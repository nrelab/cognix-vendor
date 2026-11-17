//! `cognix-vendor discover`.

use anyhow::Result;
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf};

use crate::{
    cli::ReportFormat,
    commands::{emit, resolve_output, Context},
    config::PathOverrides,
    discovery::{self, MetadataOutputs},
    paths,
};

#[derive(Debug, Serialize)]
struct DiscoverSummary {
    consumer: String,
    manifest_path: String,
    lockfile_sha256: Option<String>,
    package_count: usize,
    source_counts: BTreeMap<String, usize>,
    workspace_members: usize,
    git_sources: usize,
    packages_file: String,
}

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    packages_output: Option<PathBuf>,
    format: ReportFormat,
    report_output: Option<PathBuf>,
    offline: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let result = discovery::discover(&consumer.manifest_path, offline)?;
    let outputs = MetadataOutputs::for_consumer(&consumer);
    let packages_path = match packages_output {
        Some(path) => paths::resolve_against(&context.current_dir, &path),
        None => consumer.packages_path(),
    };
    discovery::write_metadata(&result, &outputs, &packages_path, None)?;

    let mut source_counts: BTreeMap<String, usize> = BTreeMap::new();
    for package in &result.snapshot.packages {
        *source_counts
            .entry(package.source_kind.label().to_owned())
            .or_default() += 1;
    }
    let git_sources = result
        .snapshot
        .packages
        .iter()
        .filter_map(|package| package.git.as_ref().map(|git| git.url.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let summary = DiscoverSummary {
        consumer: result.snapshot.consumer.clone(),
        manifest_path: result.snapshot.manifest_path.clone(),
        lockfile_sha256: result.snapshot.lockfile_sha256.clone(),
        package_count: result.snapshot.package_count,
        source_counts,
        workspace_members: result
            .snapshot
            .packages
            .iter()
            .filter(|package| package.is_workspace_member)
            .count(),
        git_sources,
        packages_file: packages_path.display().to_string(),
    };

    let text = format!(
        "Discovered {} package(s) for {}.\nLockfile SHA-256: {}\nGit sources: {}\nMetadata: {}\nPackages: {}\n",
        summary.package_count,
        summary.consumer,
        summary.lockfile_sha256.as_deref().unwrap_or("unknown"),
        summary.git_sources,
        consumer.metadata_dir.display(),
        packages_path.display()
    );
    emit(
        format,
        &summary,
        text,
        resolve_output(context, report_output.as_ref())?.as_deref(),
    )
}
