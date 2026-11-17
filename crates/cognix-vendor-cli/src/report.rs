//! Status, diff, report, and license reporting.
//!
//! All reports are available as terminal text and JSON. Reports never modify
//! generated metadata or vendor content.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    config::{ConfigPolicy, ResolvedConsumer},
    diff::SnapshotDiff,
    discovery,
    model::DependencySnapshot,
    policy::{Policies, PolicyReport},
    verify::{verify_consumer, VerificationReport},
};

/// Current report schema.
pub const REPORT_SCHEMA_VERSION: u32 = 1;
/// Current status schema.
pub const STATUS_SCHEMA_VERSION: u32 = 1;
/// Current license report schema.
pub const LICENSES_SCHEMA_VERSION: u32 = 1;

/// Status comparison between the approved snapshot and current resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusReport {
    /// Schema version.
    pub schema_version: u32,
    /// Consumer name.
    pub consumer: String,
    /// True when the approved snapshot matches the current resolution.
    pub up_to_date: bool,
    /// Number of approved packages.
    pub approved_packages: usize,
    /// Number of currently resolved packages.
    pub current_packages: usize,
    /// Detailed changes.
    pub diff: SnapshotDiff,
    /// Vendor integrity result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<VerificationReport>,
    /// License/source policy result for the current graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyReport>,
}

impl StatusReport {
    /// Render a terminal status report.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Status: {}\n",
            if self.up_to_date {
                "up to date"
            } else {
                "OUT OF DATE"
            }
        ));
        output.push_str(&format!("Consumer: {}\n", self.consumer));
        output.push_str(&format!(
            "Approved packages: {}  Current packages: {}\n",
            self.approved_packages, self.current_packages
        ));
        if let Some(integrity) = &self.integrity {
            output.push_str(&format!(
                "Vendor integrity: {} ({} error(s), {} warning(s))\n",
                if integrity.ok { "OK" } else { "FAILED" },
                integrity.error_count,
                integrity.warning_count
            ));
        }
        if let Some(policy) = &self.policy {
            output.push_str(&format!(
                "License/source policy: {} ({} error(s), {} warning(s))\n",
                if policy.ok { "OK" } else { "FAILED" },
                policy.error_count,
                policy.warning_count
            ));
        }
        if !self.up_to_date {
            output.push('\n');
            output.push_str(&self.diff.render_text());
            output.push_str("Run `cognix-vendor sync` only after reviewing these changes.\n");
        }
        output
    }
}

/// Full dependency report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportData {
    /// Schema version.
    pub schema_version: u32,
    /// Consumer identity.
    pub consumer: String,
    /// Manifest path recorded in metadata.
    pub manifest_path: String,
    /// Lockfile SHA-256 recorded in metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile_sha256: Option<String>,
    /// Total package count.
    pub package_count: usize,
    /// Counts by source kind.
    pub source_counts: BTreeMap<String, usize>,
    /// License expression distribution.
    pub license_distribution: BTreeMap<String, usize>,
    /// Git repositories and revisions.
    pub git_sources: Vec<crate::model::GitSourceEntry>,
    /// Vendor integrity result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<VerificationReport>,
    /// Policy result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyReport>,
}

impl ReportData {
    /// Render a terminal report.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Consumer: {}\n", self.consumer));
        output.push_str(&format!("Packages: {}\n", self.package_count));
        output.push_str(&format!("Manifest: {}\n", self.manifest_path));
        output.push_str(&format!(
            "Lockfile SHA-256: {}\n",
            self.lockfile_sha256.as_deref().unwrap_or("not recorded")
        ));
        output.push_str("Sources:\n");
        for (source, count) in &self.source_counts {
            output.push_str(&format!("  {source}: {count}\n"));
        }
        output.push_str("Licenses:\n");
        for (license, count) in &self.license_distribution {
            output.push_str(&format!("  {license}: {count}\n"));
        }
        if !self.git_sources.is_empty() {
            output.push_str("Git sources:\n");
            for source in &self.git_sources {
                output.push_str(&format!(
                    "  {} ({} package(s), {})\n",
                    source.url,
                    source.packages.len(),
                    if source.pinned { "pinned" } else { "UNPINNED" }
                ));
                for revision in &source.resolved_revisions {
                    output.push_str(&format!("    {revision}\n"));
                }
            }
        }
        if let Some(integrity) = &self.integrity {
            output.push_str(&format!(
                "Vendor integrity: {} ({} error(s), {} warning(s))\n",
                if integrity.ok { "OK" } else { "FAILED" },
                integrity.error_count,
                integrity.warning_count
            ));
            for finding in integrity
                .findings
                .iter()
                .filter(|finding| finding.severity != crate::verify::Severity::Info)
                .take(50)
            {
                output.push_str(&format!(
                    "  {:?} {}: {}\n",
                    finding.severity, finding.code, finding.message
                ));
            }
        }
        if let Some(policy) = &self.policy {
            output.push_str(&policy.render_text());
        }
        output
    }
}

/// License inventory report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseReport {
    /// Schema version.
    pub schema_version: u32,
    /// Consumer name.
    pub consumer: String,
    /// License expression distribution.
    pub distribution: BTreeMap<String, usize>,
    /// Per-package license records.
    pub packages: Vec<LicenseEntry>,
    /// Policy result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyReport>,
}

/// One package's license information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseEntry {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// SPDX expression, if declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// License file name, if declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_file: Option<String>,
    /// Source category.
    pub source_kind: String,
    /// Workspace membership.
    pub is_workspace_member: bool,
}

impl LicenseReport {
    /// Render a terminal license report.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Consumer: {}\n", self.consumer));
        output.push_str(&format!("Packages: {}\n", self.packages.len()));
        output.push_str("License distribution:\n");
        for (license, count) in &self.distribution {
            output.push_str(&format!("  {license}: {count}\n"));
        }
        let unknown: Vec<&LicenseEntry> = self
            .packages
            .iter()
            .filter(|entry| entry.license.is_none())
            .collect();
        if !unknown.is_empty() {
            output.push_str("Packages without an SPDX expression:\n");
            for entry in unknown {
                output.push_str(&format!(
                    "  {} {} ({}){}\n",
                    entry.name,
                    entry.version,
                    entry.source_kind,
                    entry
                        .license_file
                        .as_ref()
                        .map(|file| format!(", license file {file}"))
                        .unwrap_or_default()
                ));
            }
        }
        if let Some(policy) = &self.policy {
            output.push_str(&policy.render_text());
        }
        output
    }
}

/// Compare the approved snapshot with current Cargo resolution.
pub fn status(
    consumer: &ResolvedConsumer,
    config_policy: &ConfigPolicy,
    offline: bool,
) -> Result<StatusReport> {
    let baseline_path = consumer.packages_path();
    if !baseline_path.is_file() {
        bail!(
            "approved package snapshot is missing at {}; run `cognix-vendor discover` first",
            baseline_path.display()
        );
    }
    let baseline = DependencySnapshot::read(&baseline_path)?;
    let discovery = discovery::discover(&consumer.manifest_path, offline)?;
    let diff = SnapshotDiff::between(&baseline, &discovery.snapshot);
    let policies = Policies::load(&consumer.policy_dir, config_policy)?;
    let policy = policies.evaluate(&discovery.snapshot);
    let integrity = if consumer.vendor_dir.is_dir() {
        Some(verify_consumer(consumer, true)?)
    } else {
        None
    };

    Ok(StatusReport {
        schema_version: STATUS_SCHEMA_VERSION,
        consumer: discovery.snapshot.consumer,
        up_to_date: !diff.has_changes,
        approved_packages: baseline.package_count,
        current_packages: discovery.snapshot.package_count,
        diff,
        integrity,
        policy: Some(policy),
    })
}

/// Build a full dependency report from generated metadata.
pub fn report(consumer: &ResolvedConsumer, config_policy: &ConfigPolicy) -> Result<ReportData> {
    let snapshot = DependencySnapshot::read(&consumer.packages_path()).with_context(|| {
        format!(
            "reading approved package snapshot {}; run `cognix-vendor discover` or `sync` first",
            consumer.packages_path().display()
        )
    })?;
    let policies = Policies::load(&consumer.policy_dir, config_policy)?;
    let policy = policies.evaluate(&snapshot);
    let integrity = if consumer.vendor_dir.is_dir() {
        Some(verify_consumer(consumer, false)?)
    } else {
        None
    };
    let git_sources = crate::model::GitSourcesFile::from_snapshot(&snapshot);

    let mut source_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut license_distribution: BTreeMap<String, usize> = BTreeMap::new();
    for package in &snapshot.packages {
        *source_counts
            .entry(package.source_kind.label().to_owned())
            .or_default() += 1;
        *license_distribution
            .entry(
                package
                    .license
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_owned()),
            )
            .or_default() += 1;
    }

    Ok(ReportData {
        schema_version: REPORT_SCHEMA_VERSION,
        consumer: snapshot.consumer,
        manifest_path: snapshot.manifest_path,
        lockfile_sha256: snapshot.lockfile_sha256,
        package_count: snapshot.package_count,
        source_counts,
        license_distribution,
        git_sources: git_sources.sources,
        integrity,
        policy: Some(policy),
    })
}

/// Build a license inventory.
pub fn licenses(
    consumer: &ResolvedConsumer,
    config_policy: &ConfigPolicy,
) -> Result<LicenseReport> {
    let snapshot = DependencySnapshot::read(&consumer.packages_path()).with_context(|| {
        format!(
            "reading approved package snapshot {}; run `cognix-vendor discover` or `sync` first",
            consumer.packages_path().display()
        )
    })?;
    let policies = Policies::load(&consumer.policy_dir, config_policy)?;
    let policy = policies.evaluate(&snapshot);
    let mut distribution: BTreeMap<String, usize> = BTreeMap::new();
    let mut packages = Vec::with_capacity(snapshot.packages.len());
    for package in &snapshot.packages {
        *distribution
            .entry(
                package
                    .license
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_owned()),
            )
            .or_default() += 1;
        packages.push(LicenseEntry {
            name: package.name.clone(),
            version: package.version.clone(),
            license: package.license.clone(),
            license_file: package.license_file.clone(),
            source_kind: package.source_kind.label().to_owned(),
            is_workspace_member: package.is_workspace_member,
        });
    }
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(LicenseReport {
        schema_version: LICENSES_SCHEMA_VERSION,
        consumer: snapshot.consumer,
        distribution,
        packages,
        policy: Some(policy),
    })
}

/// Write a rendered report to a path or stdout.
pub fn write_output(rendered: &str, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        crate::paths::atomic_write(path, rendered.as_bytes())
            .with_context(|| format!("writing report {}", path.display()))?;
        println!("Report written to {}", path.display());
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

/// Legacy helper: report from an explicit snapshot path.
pub fn report_from_path(
    path: &Path,
    config_policy: &ConfigPolicy,
    policy_dir: &Path,
) -> Result<ReportData> {
    let snapshot = DependencySnapshot::read(path)?;
    let policies = Policies::load(policy_dir, config_policy)?;
    let policy = policies.evaluate(&snapshot);
    let mut source_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut license_distribution: BTreeMap<String, usize> = BTreeMap::new();
    for package in &snapshot.packages {
        *source_counts
            .entry(package.source_kind.label().to_owned())
            .or_default() += 1;
        *license_distribution
            .entry(
                package
                    .license
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_owned()),
            )
            .or_default() += 1;
    }
    let git_sources = crate::model::GitSourcesFile::from_snapshot(&snapshot);
    Ok(ReportData {
        schema_version: REPORT_SCHEMA_VERSION,
        consumer: snapshot.consumer,
        manifest_path: snapshot.manifest_path,
        lockfile_sha256: snapshot.lockfile_sha256,
        package_count: snapshot.package_count,
        source_counts,
        license_distribution,
        git_sources: git_sources.sources,
        integrity: None,
        policy: Some(policy),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedConsumer;
    use crate::model::{PackageRecord, PACKAGES_SCHEMA_VERSION};
    use crate::source::SourceKind;
    use std::collections::BTreeMap;

    fn package(name: &str, license: Option<&str>) -> PackageRecord {
        PackageRecord {
            id: format!("id#{name}"),
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: Some("registry+https://index.crates.io".to_owned()),
            source_kind: SourceKind::Registry,
            registry: Some("https://index.crates.io".to_owned()),
            git: None,
            checksum: None,
            license: license.map(str::to_owned),
            license_file: None,
            repository: None,
            description: None,
            manifest_path: None,
            is_workspace_member: false,
            targets: Vec::new(),
            features: BTreeMap::new(),
            dependencies: Vec::new(),
            resolved_dependencies: Vec::new(),
            enabled_features: Vec::new(),
        }
    }

    fn consumer(root: &Path) -> ResolvedConsumer {
        ResolvedConsumer {
            name: "demo".to_owned(),
            root: root.to_path_buf(),
            manifest_path: root.join("Cargo.toml"),
            metadata_dir: root.join("metadata/demo"),
            vendor_dir: root.join("vendor"),
            config_output: root.join("config/demo.toml"),
            policy_dir: root.join("metadata/policies"),
        }
    }

    fn write_snapshot(consumer: &ResolvedConsumer, packages: Vec<PackageRecord>) {
        std::fs::create_dir_all(&consumer.metadata_dir).expect("metadata");
        let snapshot = DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: "Cargo.toml".to_owned(),
            lockfile_path: "Cargo.lock".to_owned(),
            lockfile_sha256: Some("aa".repeat(32)),
            package_count: packages.len(),
            packages,
        };
        crate::paths::write_json(&consumer.packages_path(), &snapshot).expect("write");
    }

    #[test]
    fn builds_report_and_license_distribution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let consumer = consumer(dir.path());
        write_snapshot(
            &consumer,
            vec![package("alpha", Some("MIT")), package("beta", Some("MIT"))],
        );
        let report = report(&consumer, &ConfigPolicy::default()).expect("report");
        assert_eq!(report.package_count, 2);
        assert_eq!(report.license_distribution.get("MIT"), Some(&2));
        assert!(report.render_text().contains("MIT: 2"));

        let licenses = licenses(&consumer, &ConfigPolicy::default()).expect("licenses");
        assert_eq!(licenses.packages.len(), 2);
        assert!(licenses.render_text().contains("License distribution"));
    }

    #[test]
    fn status_requires_baseline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let consumer = consumer(dir.path());
        let error = status(&consumer, &ConfigPolicy::default(), true).expect_err("missing");
        assert!(error
            .to_string()
            .contains("approved package snapshot is missing"));
    }
}
