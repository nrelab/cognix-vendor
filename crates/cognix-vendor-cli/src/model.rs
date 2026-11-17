//! Versioned, serializable metadata models.
//!
//! All documents written by this tool carry a `schema_version`. Readers accept
//! older versions of the package snapshot by filling in fields with defaults;
//! they reject future versions instead of silently misinterpreting them.

use crate::{paths::read_json, source::SourceKind};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current package snapshot schema.
pub const PACKAGES_SCHEMA_VERSION: u32 = 2;
/// Current Git source inventory schema.
pub const GIT_SOURCES_SCHEMA_VERSION: u32 = 1;
/// Current provenance schema.
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;

/// The resolved dependency graph of one consumer workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencySnapshot {
    /// Schema version. New fields must be additive.
    pub schema_version: u32,
    /// Consumer name, normally the workspace root directory name.
    pub consumer: String,
    /// Manifest path as supplied to the CLI. Never used for integrity checks.
    #[serde(default)]
    pub manifest_path: String,
    /// Lockfile path as displayed to the user.
    #[serde(default)]
    pub lockfile_path: String,
    /// SHA-256 of the consumer lockfile at discovery time.
    #[serde(default)]
    pub lockfile_sha256: Option<String>,
    /// Number of packages in `packages`.
    #[serde(default)]
    pub package_count: usize,
    /// Sorted resolved packages.
    #[serde(default)]
    pub packages: Vec<PackageRecord>,
}

impl DependencySnapshot {
    /// Read a snapshot and normalize older documents.
    pub fn read(path: &std::path::Path) -> Result<Self> {
        let mut snapshot: Self = read_json(path)?;
        if snapshot.schema_version > PACKAGES_SCHEMA_VERSION {
            bail!(
                "{} uses snapshot schema version {}, but this build supports at most {}",
                path.display(),
                snapshot.schema_version,
                PACKAGES_SCHEMA_VERSION
            );
        }
        snapshot.normalize();
        Ok(snapshot)
    }

    /// Sort packages and recompute derived fields.
    pub fn normalize(&mut self) {
        for package in &mut self.packages {
            if package.source_kind == SourceKind::Unknown {
                package.source_kind = package
                    .source
                    .as_deref()
                    .map(crate::source::parse_source)
                    .map(|parsed| parsed.kind())
                    .unwrap_or(if package.is_workspace_member {
                        SourceKind::Workspace
                    } else {
                        SourceKind::Unknown
                    });
            }
            if package.id.is_empty() {
                package.id = crate::source::stable_package_id(
                    &package.name,
                    &package.version,
                    package.source.as_deref(),
                    package.is_workspace_member,
                    package.manifest_path.as_deref(),
                );
            }
            package.dependencies.sort();
            package.resolved_dependencies.sort();
            package.enabled_features.sort();
            package.targets.sort();
            for features in package.features.values_mut() {
                features.sort();
            }
        }
        self.packages.sort();
        self.package_count = self.packages.len();
    }

    /// Packages that Cargo is expected to place in the vendor directory.
    pub fn vendorable_packages(&self) -> impl Iterator<Item = &PackageRecord> {
        self.packages
            .iter()
            .filter(|package| !package.is_workspace_member && package.source_kind.is_vendorable())
    }

    /// Find a package by stable identifier.
    pub fn package(&self, id: &str) -> Option<&PackageRecord> {
        self.packages.iter().find(|package| package.id == id)
    }
}

/// One package in the resolved graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageRecord {
    /// Stable identifier that does not contain machine-specific paths.
    pub id: String,
    /// Package name.
    pub name: String,
    /// Resolved version.
    pub version: String,
    /// Raw Cargo source string, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Classified source.
    #[serde(default)]
    pub source_kind: SourceKind,
    /// Registry index URL for registry packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Parsed Git source for Git packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<crate::source::GitSourceRef>,
    /// Registry package checksum from `Cargo.lock`, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// SPDX license expression from package metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// License file name recorded by Cargo, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_file: Option<String>,
    /// Upstream repository URL from package metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Upstream description from package metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Manifest path relative to the workspace for workspace members or local
    /// dependencies. Omitted for external registry and Git packages so the
    /// document stays reproducible across machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    /// True when the package belongs to the consumer workspace.
    #[serde(default)]
    pub is_workspace_member: bool,
    /// Cargo targets exposed by the package.
    #[serde(default)]
    pub targets: Vec<TargetRecord>,
    /// Feature definitions.
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
    /// Direct dependencies as declared in the package manifest.
    #[serde(default)]
    pub dependencies: Vec<DependencyRecord>,
    /// Resolved dependency package IDs from `cargo metadata`.
    #[serde(default)]
    pub resolved_dependencies: Vec<String>,
    /// Features enabled during resolution.
    #[serde(default)]
    pub enabled_features: Vec<String>,
}

impl PackageRecord {
    /// Stable identity used when comparing snapshots. Two records with the same
    /// key are the same package from the same origin.
    pub fn source_identity(&self) -> String {
        match self.source_kind {
            SourceKind::Git => self
                .git
                .as_ref()
                .map(|git| format!("git+{}", git.url))
                .unwrap_or_else(|| "git".to_owned()),
            SourceKind::Registry => {
                format!("registry+{}", self.registry.as_deref().unwrap_or("unknown"))
            }
            SourceKind::Workspace => "workspace".to_owned(),
            SourceKind::Path => format!(
                "path+{}",
                self.manifest_path.as_deref().unwrap_or("unknown")
            ),
            SourceKind::Unknown => "unknown".to_owned(),
        }
    }

    /// Reference label for Git packages, or `None` for other sources.
    pub fn git_reference(&self) -> Option<String> {
        self.git.as_ref().map(|git| git.reference_label())
    }
}

impl PartialOrd for PackageRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.name, &self.version, &self.source, &self.id).cmp(&(
            &other.name,
            &other.version,
            &other.source,
            &other.id,
        ))
    }
}

/// A Cargo target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetRecord {
    /// Target name.
    pub name: String,
    /// Target kinds, such as `lib`, `bin`, `proc-macro`, or `custom-build`.
    #[serde(default)]
    pub kind: Vec<String>,
    /// Crate types.
    #[serde(default)]
    pub crate_types: Vec<String>,
    /// Features required to build this target.
    #[serde(default)]
    pub required_features: Vec<String>,
}

/// A dependency declaration on a package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyRecord {
    /// Dependency name as written in the manifest.
    pub name: String,
    /// Version requirement.
    pub requirement: String,
    /// `normal`, `build`, or `dev`.
    #[serde(default)]
    pub kind: String,
    /// Whether the dependency is optional.
    #[serde(default)]
    pub optional: bool,
    /// Whether default features are enabled.
    #[serde(default)]
    pub uses_default_features: bool,
    /// Features explicitly enabled on the dependency.
    #[serde(default)]
    pub features: Vec<String>,
    /// Platform or target selector, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Rename applied in the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
    /// Registry index URL for registry dependencies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

/// One Git repository referenced by the resolved graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitSourceEntry {
    /// Repository URL.
    pub url: String,
    /// Repository host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Packages resolved from this repository.
    pub packages: Vec<GitPackageRecord>,
    /// True when every package from this repository declared an exact `rev`.
    #[serde(default)]
    pub pinned: bool,
    /// Distinct declared references (for example `rev abc`, `branch main`).
    #[serde(default)]
    pub references: Vec<String>,
    /// Distinct resolved commit hashes.
    #[serde(default)]
    pub resolved_revisions: Vec<String>,
}

/// A package resolved from a Git repository.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitPackageRecord {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Declared reference label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Resolved commit hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// Inventory of Git sources in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitSourcesFile {
    /// Schema version.
    pub schema_version: u32,
    /// Consumer name.
    pub consumer: String,
    /// Lockfile SHA-256 used to produce this inventory.
    #[serde(default)]
    pub lockfile_sha256: Option<String>,
    /// Number of Git repositories.
    #[serde(default)]
    pub source_count: usize,
    /// Sorted Git sources.
    pub sources: Vec<GitSourceEntry>,
}

impl GitSourcesFile {
    /// Build a Git source inventory from a snapshot.
    pub fn from_snapshot(snapshot: &DependencySnapshot) -> Self {
        let mut by_url: BTreeMap<String, GitSourceEntry> = BTreeMap::new();
        for package in &snapshot.packages {
            let Some(git) = &package.git else { continue };
            let entry = by_url
                .entry(git.url.clone())
                .or_insert_with(|| GitSourceEntry {
                    url: git.url.clone(),
                    host: git.host(),
                    packages: Vec::new(),
                    pinned: true,
                    references: Vec::new(),
                    resolved_revisions: Vec::new(),
                });
            let reference = if git.rev.is_some() || git.branch.is_some() || git.tag.is_some() {
                Some(git.reference_label())
            } else {
                None
            };
            if let Some(reference) = reference {
                if !entry.references.contains(&reference) {
                    entry.references.push(reference);
                }
            }
            if let Some(revision) = &git.resolved_revision {
                if !entry.resolved_revisions.contains(revision) {
                    entry.resolved_revisions.push(revision.clone());
                }
            }
            entry.pinned &= git.pinned;
            entry.packages.push(GitPackageRecord {
                name: package.name.clone(),
                version: package.version.clone(),
                reference: Some(git.reference_label()),
                revision: git.resolved_revision.clone(),
            });
        }

        let mut sources: Vec<GitSourceEntry> = by_url.into_values().collect();
        for source in &mut sources {
            source.packages.sort();
            source.references.sort();
            source.resolved_revisions.sort();
        }
        Self {
            schema_version: GIT_SOURCES_SCHEMA_VERSION,
            consumer: snapshot.consumer.clone(),
            lockfile_sha256: snapshot.lockfile_sha256.clone(),
            source_count: sources.len(),
            sources,
        }
    }
}

/// Provenance details for generated metadata and vendor output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceFile {
    /// Schema version.
    pub schema_version: u32,
    /// Tool identity.
    pub generator: GeneratorInfo,
    /// Consumer identity.
    pub consumer: ConsumerProvenance,
    /// Generation time in UNIX seconds. This is intentionally kept out of
    /// deterministic package metadata so CI can compare committed files.
    pub generated_at_unix: u64,
    /// Cargo version used for resolution, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_version: Option<String>,
    /// Lockfile identity.
    pub lockfile: LockfileProvenance,
    /// Vendor output details, present after `sync`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<VendorProvenance>,
    /// Sidecar metadata files written with this provenance.
    #[serde(default)]
    pub artifacts: BTreeMap<String, String>,
}

/// Tool identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratorInfo {
    /// Tool name.
    pub name: String,
    /// Tool version.
    pub version: String,
}

impl Default for GeneratorInfo {
    fn default() -> Self {
        Self {
            name: "cognix-vendor".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// Consumer workspace identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsumerProvenance {
    /// Consumer name.
    pub name: String,
    /// Manifest path as supplied by the user.
    pub manifest_path: String,
    /// Workspace root directory name and relative path marker only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root_name: Option<String>,
}

/// Lockfile identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockfileProvenance {
    /// Lockfile format version.
    pub version: u32,
    /// SHA-256 of the lockfile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// File name of the lockfile.
    pub file_name: String,
}

/// Vendor output details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VendorProvenance {
    /// Vendor directory as supplied by the user.
    pub directory: String,
    /// Cargo source-replacement configuration as supplied by the user.
    pub source_configuration: String,
    /// Number of packages expected in the vendor directory.
    pub package_count: usize,
    /// Whether the generated vendor tree passed checksum verification.
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::GitSourceRef;

    fn package(name: &str, version: &str, kind: SourceKind) -> PackageRecord {
        PackageRecord {
            id: format!("{kind:?}#{name}@{version}"),
            name: name.to_owned(),
            version: version.to_owned(),
            source: None,
            source_kind: kind,
            registry: None,
            git: None,
            checksum: None,
            license: None,
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

    #[test]
    fn snapshot_round_trip_is_stable() {
        let mut snapshot = DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: "../demo/Cargo.toml".to_owned(),
            lockfile_path: "../demo/Cargo.lock".to_owned(),
            lockfile_sha256: Some("abc".to_owned()),
            package_count: 0,
            packages: vec![
                package("zeta", "1.0.0", SourceKind::Registry),
                package("alpha", "2.0.0", SourceKind::Git),
            ],
        };
        snapshot.normalize();
        assert_eq!(snapshot.package_count, 2);
        assert_eq!(snapshot.packages[0].name, "alpha");
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let parsed: DependencySnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, snapshot);
    }

    #[test]
    fn git_sources_group_multiple_packages() {
        let mut first = package("one", "1.0.0", SourceKind::Git);
        first.git = Some(GitSourceRef {
            url: "https://github.com/example/repo".to_owned(),
            rev: Some("abc".to_owned()),
            resolved_revision: Some("abc".to_owned()),
            pinned: true,
            ..GitSourceRef::default()
        });
        let mut second = package("two", "1.0.0", SourceKind::Git);
        second.git = Some(GitSourceRef {
            url: "https://github.com/example/repo".to_owned(),
            rev: Some("abc".to_owned()),
            resolved_revision: Some("abc".to_owned()),
            pinned: true,
            ..GitSourceRef::default()
        });
        let snapshot = DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: String::new(),
            lockfile_path: String::new(),
            lockfile_sha256: None,
            package_count: 2,
            packages: vec![first, second],
        };
        let git = GitSourcesFile::from_snapshot(&snapshot);
        assert_eq!(git.source_count, 1);
        assert_eq!(git.sources[0].packages.len(), 2);
        assert!(git.sources[0].pinned);
    }
}
