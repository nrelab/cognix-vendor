//! Idempotent, rollback-safe Cargo vendor synchronization.
//!
//! Synchronization stages `cargo vendor` output in a sibling directory, verifies
//! every staged package, then swaps it into place. A failed run leaves the
//! previous vendor tree and metadata untouched whenever the filesystem permits
//! an atomic rename.

use anyhow::{bail, Context, Result};
use std::{ffi::OsString, fs, path::Path};

use crate::process::Command;

use crate::{
    config::ResolvedConsumer,
    diff::SnapshotDiff,
    discovery::{self, DiscoveryResult, MetadataOutputs},
    model::{DependencySnapshot, VendorProvenance},
    paths,
    verify::{render_text, VerificationReport},
};

/// Current sync report schema.
pub const SYNC_SCHEMA_VERSION: u32 = 1;

/// Synchronization inputs.
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// Resolved consumer paths.
    pub consumer: ResolvedConsumer,
    /// Pass `--offline` to Cargo.
    pub offline: bool,
    /// Replace an existing vendor directory that does not look Cargo-generated.
    pub force: bool,
}

/// Result of a successful synchronization.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Resolved consumer.
    pub consumer: ResolvedConsumer,
    /// New snapshot.
    pub snapshot: DependencySnapshot,
    /// Changes compared with the previous approved snapshot.
    pub diff: SnapshotDiff,
    /// Number of checksum files verified in the staged tree.
    pub verified_packages: usize,
    /// Number of files verified in the staged tree.
    pub verified_files: usize,
}

impl SyncReport {
    /// Render a terminal summary.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Synchronized {} package(s) into {}.\n",
            self.snapshot.vendorable_packages().count(),
            self.consumer.vendor_dir.display()
        ));
        output.push_str(&format!(
            "Verified {} package(s) and {} file checksum(s).\n",
            self.verified_packages, self.verified_files
        ));
        output.push_str(&format!(
            "Source configuration: {}\n",
            self.consumer.config_output.display()
        ));
        output.push_str(&format!(
            "Metadata: {}\n",
            self.consumer.metadata_dir.display()
        ));
        if self.diff.has_changes {
            output.push_str("\nDependency changes:\n");
            output.push_str(&self.diff.render_text());
        } else {
            output.push_str("Dependency snapshot unchanged.\n");
        }
        output
    }

    /// Render a JSON-friendly summary.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": SYNC_SCHEMA_VERSION,
            "consumer": self.snapshot.consumer,
            "vendor_dir": self.consumer.vendor_dir,
            "metadata_dir": self.consumer.metadata_dir,
            "config_output": self.consumer.config_output,
            "package_count": self.snapshot.vendorable_packages().count(),
            "verified_packages": self.verified_packages,
            "verified_files": self.verified_files,
            "diff": self.diff,
        })
    }
}

/// Synchronize vendored sources for a consumer.
pub fn sync(options: &SyncOptions) -> Result<SyncReport> {
    let consumer = &options.consumer;
    if !consumer.manifest_path.is_file() {
        bail!(
            "Cargo manifest does not exist: {} (pass --manifest-path)",
            consumer.manifest_path.display()
        );
    }

    let previous_snapshot = match DependencySnapshot::read(&consumer.packages_path()) {
        Ok(snapshot) => Some(snapshot),
        Err(error) if consumer.packages_path().is_file() => {
            tracing::warn!(
                "existing package metadata could not be read; synchronization will replace it: {error:#}"
            );
            None
        }
        Err(_) => None,
    };

    let discovery = discovery::discover(&consumer.manifest_path, options.offline)?;
    ensure_safe_vendor_target(consumer, &discovery, options.force)?;

    let previous_config = match fs::read(&consumer.config_output) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading {}", consumer.config_output.display()))
        }
    };

    let staging = paths::sibling_temp_path(&consumer.vendor_dir, "staging")?;
    if staging.exists() {
        bail!(
            "staging directory already exists: {}; remove it and retry",
            staging.display()
        );
    }

    let run_result = run_cargo_vendor(
        &consumer.manifest_path,
        &staging,
        options.offline,
        &consumer.root,
    )
    .and_then(|output| {
        let config = rewrite_source_configuration(&output.stdout, &consumer.vendor_dir)?;
        if !staging.exists() {
            fs::create_dir_all(&staging)
                .with_context(|| format!("creating {}", staging.display()))?;
        }
        Ok(config)
    });

    let source_config = match run_result {
        Ok(config) => config,
        Err(error) => {
            remove_dir_if_exists(&staging)?;
            return Err(error);
        }
    };

    let verification = match crate::verify::verify_snapshot(&staging, &discovery.snapshot) {
        Ok(verification) => verification,
        Err(error) => {
            remove_dir_if_exists(&staging)?;
            return Err(error).context("verifying staged vendor output");
        }
    };
    if !verification.ok {
        remove_dir_if_exists(&staging)?;
        bail!(
            "staged vendor output failed integrity verification; original vendor tree was not changed\n{}",
            render_text(&verification)
        );
    }

    let commit_result = commit(
        consumer,
        &discovery,
        &staging,
        &source_config,
        previous_config.as_deref(),
    );
    match commit_result {
        Ok(()) => {}
        Err(error) => {
            remove_dir_if_exists(&staging)?;
            return Err(error);
        }
    }

    let diff = previous_snapshot
        .as_ref()
        .map(|previous| SnapshotDiff::between(previous, &discovery.snapshot))
        .unwrap_or_else(|| {
            SnapshotDiff::between(&empty_snapshot(&discovery.snapshot), &discovery.snapshot)
        });

    Ok(SyncReport {
        consumer: consumer.clone(),
        snapshot: discovery.snapshot,
        diff,
        verified_packages: verification.package_count,
        verified_files: verification.file_count,
    })
}

fn commit(
    consumer: &ResolvedConsumer,
    discovery: &DiscoveryResult,
    staging: &Path,
    source_config: &str,
    previous_config: Option<&[u8]>,
) -> Result<()> {
    let backup = if consumer.vendor_dir.exists() {
        let backup = paths::sibling_temp_path(&consumer.vendor_dir, "backup")?;
        fs::rename(&consumer.vendor_dir, &backup).with_context(|| {
            format!(
                "moving existing vendor directory {} to {}",
                consumer.vendor_dir.display(),
                backup.display()
            )
        })?;
        Some(backup)
    } else {
        None
    };

    let swap_result = fs::rename(staging, &consumer.vendor_dir).with_context(|| {
        format!(
            "moving staged vendor tree {} to {}",
            staging.display(),
            consumer.vendor_dir.display()
        )
    });
    if let Err(error) = swap_result {
        if let Some(backup) = &backup {
            let _ = fs::rename(backup, &consumer.vendor_dir);
        }
        return Err(error);
    }

    let write_result = write_outputs(consumer, discovery, source_config);
    if let Err(error) = write_result {
        let _ = remove_dir_if_exists(&consumer.vendor_dir);
        if let Some(backup) = &backup {
            let _ = fs::rename(backup, &consumer.vendor_dir);
        }
        restore_config(&consumer.config_output, previous_config)?;
        return Err(error);
    }

    if let Some(backup) = backup {
        if let Err(error) = remove_dir_if_exists(&backup) {
            tracing::warn!(
                "synchronization succeeded but the previous vendor backup could not be removed at {}: {error:#}",
                backup.display()
            );
        }
    }
    Ok(())
}

fn write_outputs(
    consumer: &ResolvedConsumer,
    discovery: &DiscoveryResult,
    source_config: &str,
) -> Result<()> {
    paths::atomic_write(&consumer.config_output, source_config.as_bytes())
        .with_context(|| format!("writing {}", consumer.config_output.display()))?;

    let outputs = MetadataOutputs::for_consumer(consumer);
    let vendor = VendorProvenance {
        directory: display_relative(&consumer.root, &consumer.vendor_dir),
        source_configuration: display_relative(&consumer.root, &consumer.config_output),
        package_count: discovery.snapshot.vendorable_packages().count(),
        verified: true,
    };
    discovery::write_metadata(discovery, &outputs, &consumer.packages_path(), Some(vendor))
}

fn restore_config(path: &Path, previous: Option<&[u8]>) -> Result<()> {
    match previous {
        Some(bytes) => paths::atomic_write(path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
        },
    }
}

fn run_cargo_vendor(
    manifest_path: &Path,
    vendor_dir: &Path,
    offline: bool,
    current_dir: &Path,
) -> Result<std::process::Output> {
    let mut args: Vec<OsString> = vec![
        "vendor".into(),
        "--locked".into(),
        "--versioned-dirs".into(),
        "--manifest-path".into(),
        manifest_path.as_os_str().to_owned(),
    ];
    if offline {
        args.push("--offline".into());
    }
    args.push(vendor_dir.as_os_str().to_owned());

    tracing::info!(
        "running `cargo vendor --locked --versioned-dirs{}`",
        if offline { " --offline" } else { "" }
    );
    let output = Command::new(paths::cargo_program())
        .args(&args)
        .current_dir(current_dir)
        .output()
        .context("failed to execute `cargo vendor`; ensure Cargo is installed")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`cargo vendor` failed with {}:\n{}",
            output.status,
            stderr.trim_end()
        );
    }
    if !output.stderr.is_empty() {
        tracing::debug!("cargo vendor: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(output)
}

/// Rewrite only the vendored-sources directory in Cargo's generated
/// configuration. All generated source replacement blocks, including Git
/// entries, are preserved.
fn rewrite_source_configuration(stdout: &[u8], final_vendor_dir: &Path) -> Result<String> {
    let generated =
        String::from_utf8(stdout.to_vec()).context("cargo vendor output is not UTF-8")?;
    if generated.trim().is_empty() {
        // Cargo emits no configuration when there is nothing to vendor.
        return Ok("# No dependencies required vendoring.\n".to_owned());
    }
    let mut document: toml::Value = toml::from_str(&generated)
        .context("cargo vendor emitted source configuration that is not valid TOML")?;
    let source = document
        .get_mut("source")
        .and_then(toml::Value::as_table_mut)
        .context("cargo vendor output has no [source] table")?;
    let vendored = source
        .get_mut("vendored-sources")
        .and_then(toml::Value::as_table_mut)
        .context("cargo vendor output has no [source.vendored-sources] table")?;
    vendored.insert(
        "directory".to_owned(),
        toml::Value::String(final_vendor_dir.to_string_lossy().replace('\\', "/")),
    );
    let mut rendered =
        toml::to_string_pretty(&document).context("re-serializing Cargo source configuration")?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

fn ensure_safe_vendor_target(
    consumer: &ResolvedConsumer,
    discovery: &DiscoveryResult,
    force: bool,
) -> Result<()> {
    let vendor = &consumer.vendor_dir;
    if vendor == Path::new("/") {
        bail!("refusing to use the filesystem root as a vendor directory");
    }
    if vendor == &consumer.root {
        bail!(
            "refusing to use the repository root {} as the vendor directory",
            vendor.display()
        );
    }
    if vendor == &discovery.workspace_root || discovery.workspace_root.starts_with(vendor) {
        bail!(
            "vendor directory {} contains the consumer workspace; choose a dedicated vendor directory",
            vendor.display()
        );
    }
    if consumer.manifest_path.starts_with(vendor) {
        bail!(
            "vendor directory {} contains the consumer manifest; choose a dedicated vendor directory",
            vendor.display()
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        if vendor == Path::new(&home) {
            bail!("refusing to use the home directory as a vendor directory");
        }
    }

    match fs::symlink_metadata(vendor) {
        Ok(metadata) if metadata.file_type().is_symlink() => bail!(
            "vendor path {} is a symbolic link; replace it with a real directory",
            vendor.display()
        ),
        Ok(metadata) if !metadata.is_dir() => bail!(
            "vendor path {} exists and is not a directory",
            vendor.display()
        ),
        Ok(_) => {
            if !force && !looks_like_cargo_vendor(vendor)? {
                bail!(
                    "{} is not empty and does not look like a Cargo vendor directory; pass --force to replace it",
                    vendor.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", vendor.display()))
        }
    }
    Ok(())
}

fn looks_like_cargo_vendor(vendor: &Path) -> Result<bool> {
    let mut entries = 0usize;
    for entry in fs::read_dir(vendor).with_context(|| format!("reading {}", vendor.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".gitkeep" {
            continue;
        }
        entries += 1;
        if entry.file_type()?.is_dir() && entry.path().join(".cargo-checksum.json").is_file() {
            return Ok(true);
        }
    }
    Ok(entries == 0)
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn display_relative(root: &Path, path: &Path) -> String {
    if paths::is_within(path, root) {
        paths::relative_to(root, path)
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        path.to_string_lossy().replace('\\', "/")
    }
}

fn empty_snapshot(new: &DependencySnapshot) -> DependencySnapshot {
    DependencySnapshot {
        schema_version: new.schema_version,
        consumer: new.consumer.clone(),
        manifest_path: new.manifest_path.clone(),
        lockfile_path: new.lockfile_path.clone(),
        lockfile_sha256: Some(String::new()),
        package_count: 0,
        packages: Vec::new(),
    }
}

/// Convenience wrapper used by tests and callers that want verification output.
pub fn verified_staging_report(report: &VerificationReport) -> String {
    render_text(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedConsumer;
    use std::path::PathBuf;

    fn consumer(root: &Path, manifest: &Path) -> ResolvedConsumer {
        ResolvedConsumer {
            name: "demo".to_owned(),
            root: root.to_path_buf(),
            manifest_path: manifest.to_path_buf(),
            metadata_dir: root.join("metadata/demo"),
            vendor_dir: root.join("vendor"),
            config_output: root.join("config/demo-source-replacement.toml"),
            policy_dir: root.join("metadata/policies"),
        }
    }

    fn write_demo_workspace(root: &Path) -> PathBuf {
        fs::create_dir_all(root.join("src")).expect("src");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), "pub fn demo() {}\n").expect("lib");
        let status = Command::new(paths::cargo_program())
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .status()
            .expect("generate lockfile");
        assert!(status.success());
        root.join("Cargo.toml")
    }

    #[test]
    fn rewrites_only_the_vendored_directory() {
        let generated = br#"[source.crates-io]
replace-with = "vendored-sources"

[source."git+https://github.com/example/repo?rev=abc"]
git = "https://github.com/example/repo"
rev = "abc"
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/tmp/staging"
"#;
        let rendered =
            rewrite_source_configuration(generated, Path::new("/repo/vendor")).expect("rewrite");
        assert!(rendered.contains("/repo/vendor"));
        assert!(rendered.contains("git+https://github.com/example/repo?rev=abc"));
        assert!(rendered.contains("rev = \"abc\""));
        assert!(!rendered.contains("/tmp/staging"));
    }

    #[test]
    fn empty_vendor_output_is_represented_as_a_comment() {
        assert_eq!(
            rewrite_source_configuration(b"", Path::new("vendor")).expect("empty"),
            "# No dependencies required vendoring.\n"
        );
    }

    #[test]
    fn rejects_configuration_without_source_tables() {
        assert!(rewrite_source_configuration(b"[other]\nx = 1\n", Path::new("vendor")).is_err());
    }

    #[test]
    fn refuses_to_vendor_into_the_repository_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let manifest = write_demo_workspace(root);
        let mut consumer = consumer(root, &manifest);
        consumer.vendor_dir = root.to_path_buf();
        let discovery = crate::discovery::discover(&manifest, true).expect("discovery");
        let error = ensure_safe_vendor_target(&consumer, &discovery, false).expect_err("unsafe");
        assert!(error.to_string().contains("repository root"));
    }

    #[test]
    fn end_to_end_sync_without_dependencies_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let manifest = write_demo_workspace(root);
        let consumer = consumer(root, &manifest);

        let first = sync(&SyncOptions {
            consumer: consumer.clone(),
            offline: true,
            force: false,
        })
        .expect("first sync");
        assert!(first.consumer.packages_path().is_file());
        assert!(consumer.vendor_dir.is_dir());
        assert!(consumer.config_output.is_file());

        let second = sync(&SyncOptions {
            consumer,
            offline: true,
            force: false,
        })
        .expect("second sync");
        assert!(!second.diff.has_changes);
    }
}
