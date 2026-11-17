//! Safe cleanup of generated vendor and metadata output.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::config::ResolvedConsumer;

/// Clean options.
#[derive(Debug, Clone)]
pub struct CleanOptions {
    /// Resolved consumer.
    pub consumer: ResolvedConsumer,
    /// Confirm destructive removal.
    pub yes: bool,
    /// Report actions without changing anything.
    pub dry_run: bool,
    /// Keep generated metadata.
    pub keep_metadata: bool,
    /// Keep the vendor directory.
    pub keep_vendor: bool,
}

/// Clean result.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanReport {
    /// Paths that were removed (or would be removed in a dry run).
    pub removed: Vec<String>,
    /// Paths intentionally skipped.
    pub skipped: Vec<String>,
    /// True when this was a dry run.
    pub dry_run: bool,
}

/// Remove generated outputs with explicit confirmation.
pub fn clean(options: &CleanOptions) -> Result<CleanReport> {
    if !options.yes && !options.dry_run {
        bail!("refusing to remove generated files without --yes (or use --dry-run)");
    }
    let consumer = &options.consumer;
    let mut report = CleanReport {
        dry_run: options.dry_run,
        ..CleanReport::default()
    };

    if !options.keep_vendor {
        remove_path(&consumer.vendor_dir, consumer, options.dry_run, &mut report)?;
    } else {
        report
            .skipped
            .push(consumer.vendor_dir.display().to_string());
    }

    if !options.keep_metadata {
        for artifact in [
            consumer.packages_path(),
            consumer.git_sources_path(),
            consumer.provenance_path(),
            consumer.lockfile_checksum_path(),
            consumer.sbom_path(),
        ] {
            remove_file(&artifact, consumer, options.dry_run, &mut report)?;
        }
        // Only remove the metadata directory if it is empty. Policy files and
        // user documents are never deleted.
        if !options.dry_run {
            let _ = fs::remove_dir(&consumer.metadata_dir);
        }
    } else {
        report
            .skipped
            .push(consumer.metadata_dir.display().to_string());
    }

    remove_file(
        &consumer.config_output,
        consumer,
        options.dry_run,
        &mut report,
    )?;

    Ok(report)
}

fn remove_path(
    path: &Path,
    consumer: &ResolvedConsumer,
    dry_run: bool,
    report: &mut CleanReport,
) -> Result<()> {
    guard_path(path, consumer)?;
    if !path.exists() {
        return Ok(());
    }
    if !path.is_dir() {
        return remove_file(path, consumer, dry_run, report);
    }
    if dry_run {
        report.removed.push(path.display().to_string());
        return Ok(());
    }
    fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))?;
    report.removed.push(path.display().to_string());
    Ok(())
}

fn remove_file(
    path: &Path,
    consumer: &ResolvedConsumer,
    dry_run: bool,
    report: &mut CleanReport,
) -> Result<()> {
    guard_path(path, consumer)?;
    if !path.exists() {
        return Ok(());
    }
    if dry_run {
        report.removed.push(path.display().to_string());
        return Ok(());
    }
    fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    report.removed.push(path.display().to_string());
    Ok(())
}

fn guard_path(path: &Path, consumer: &ResolvedConsumer) -> Result<()> {
    if path == Path::new("/") {
        bail!("refusing to remove the filesystem root");
    }
    if path == consumer.root {
        bail!("refusing to remove the repository root {}", path.display());
    }
    if consumer.root.starts_with(path) {
        bail!(
            "refusing to remove {} because it contains the repository root",
            path.display()
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        if path == Path::new(&home) {
            bail!("refusing to remove the home directory");
        }
    }
    // Metadata and configuration files live inside the repository. Vendor
    // output may be outside it, but must still be an absolute, explicit path.
    if path.as_os_str().is_empty() {
        bail!("refusing to remove an empty path");
    }
    Ok(())
}

/// Render a cleanup summary.
pub fn render_text(report: &CleanReport) -> String {
    let mut output = String::new();
    if report.removed.is_empty() {
        output.push_str("Nothing to remove.\n");
    } else {
        output.push_str(if report.dry_run {
            "Would remove:\n"
        } else {
            "Removed:\n"
        });
        for path in &report.removed {
            output.push_str(&format!("  {path}\n"));
        }
    }
    if !report.skipped.is_empty() {
        output.push_str("Skipped:\n");
        for path in &report.skipped {
            output.push_str(&format!("  {path}\n"));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn consumer(root: &Path) -> ResolvedConsumer {
        ResolvedConsumer {
            name: "demo".to_owned(),
            root: root.to_path_buf(),
            manifest_path: root.join("../demo/Cargo.toml"),
            metadata_dir: root.join("metadata/demo"),
            vendor_dir: root.join("vendor"),
            config_output: root.join("config/demo.toml"),
            policy_dir: root.join("metadata/policies"),
        }
    }

    #[test]
    fn dry_run_removes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let consumer = consumer(dir.path());
        fs::create_dir_all(&consumer.vendor_dir).expect("vendor");
        let report = clean(&CleanOptions {
            consumer,
            yes: false,
            dry_run: true,
            keep_metadata: false,
            keep_vendor: false,
        })
        .expect("clean");
        assert!(dir.path().join("vendor").exists());
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn requires_confirmation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = clean(&CleanOptions {
            consumer: consumer(dir.path()),
            yes: false,
            dry_run: false,
            keep_metadata: false,
            keep_vendor: false,
        })
        .expect_err("must fail");
        assert!(error.to_string().contains("--yes"));
    }

    #[test]
    fn preserves_policy_files_in_shared_metadata_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut consumer = consumer(dir.path());
        consumer.metadata_dir = dir.path().join("metadata");
        consumer.policy_dir = consumer.metadata_dir.join("policies");
        fs::create_dir_all(&consumer.policy_dir).expect("policy dir");
        fs::write(consumer.policy_dir.join("licenses.toml"), "allowed = []\n").expect("policy");
        fs::write(consumer.packages_path(), "{}").expect("metadata");

        clean(&CleanOptions {
            consumer: consumer.clone(),
            yes: true,
            dry_run: false,
            keep_metadata: false,
            keep_vendor: false,
        })
        .expect("clean");
        assert!(consumer.policy_dir.join("licenses.toml").exists());
        assert!(!consumer.packages_path().exists());
    }

    #[test]
    fn refuses_to_remove_repository_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut consumer = consumer(dir.path());
        consumer.vendor_dir = PathBuf::from(dir.path());
        let error = clean(&CleanOptions {
            consumer,
            yes: true,
            dry_run: false,
            keep_metadata: true,
            keep_vendor: false,
        })
        .expect_err("must fail");
        assert!(error.to_string().contains("repository root"));
    }
}
