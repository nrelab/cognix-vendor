//! Comparison of approved and current dependency snapshots.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{DependencySnapshot, PackageRecord};

/// Current diff schema.
pub const DIFF_SCHEMA_VERSION: u32 = 1;

/// Difference between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotDiff {
    /// Schema version.
    pub schema_version: u32,
    /// Lockfile checksum in the old snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_lockfile_sha256: Option<String>,
    /// Lockfile checksum in the new snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_lockfile_sha256: Option<String>,
    /// Whether the lockfile changed.
    pub lockfile_changed: bool,
    /// Packages added.
    pub added: Vec<PackageChange>,
    /// Packages removed.
    pub removed: Vec<PackageChange>,
    /// Packages whose available versions changed for the same source.
    pub version_changed: Vec<VersionChange>,
    /// Git packages whose resolved revision changed.
    pub git_revision_changed: Vec<GitRevisionChange>,
    /// True when any category has a change.
    pub has_changes: bool,
}

/// An added or removed package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageChange {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Source category.
    pub source_kind: String,
    /// Source identity.
    pub source: String,
    /// Resolved Git revision, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_revision: Option<String>,
}

/// A version change for one package name and source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionChange {
    /// Package name.
    pub name: String,
    /// Source identity.
    pub source: String,
    /// Old versions.
    pub old_versions: Vec<String>,
    /// New versions.
    pub new_versions: Vec<String>,
}

/// A Git revision change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitRevisionChange {
    /// Package name.
    pub name: String,
    /// Repository URL.
    pub url: String,
    /// Old revisions.
    pub old_revisions: Vec<String>,
    /// New revisions.
    pub new_revisions: Vec<String>,
}

impl SnapshotDiff {
    /// Compare two snapshots.
    pub fn between(old: &DependencySnapshot, new: &DependencySnapshot) -> Self {
        let old_packages = identity_map(old);
        let new_packages = identity_map(new);

        let mut added = new_packages
            .iter()
            .filter(|(identity, _)| !old_packages.contains_key(*identity))
            .map(|(_, package)| PackageChange {
                name: package.name.clone(),
                version: package.version.clone(),
                source_kind: package.source_kind.label().to_owned(),
                source: package.source_identity(),
                git_revision: package
                    .git
                    .as_ref()
                    .and_then(|git| git.resolved_revision.clone()),
            })
            .collect::<Vec<_>>();
        let mut removed = old_packages
            .iter()
            .filter(|(identity, _)| !new_packages.contains_key(*identity))
            .map(|(_, package)| PackageChange {
                name: package.name.clone(),
                version: package.version.clone(),
                source_kind: package.source_kind.label().to_owned(),
                source: package.source_identity(),
                git_revision: package
                    .git
                    .as_ref()
                    .and_then(|git| git.resolved_revision.clone()),
            })
            .collect::<Vec<_>>();

        let old_versions = version_map(old);
        let new_versions = version_map(new);
        let mut version_changed = Vec::new();
        for (key, old_versions) in &old_versions {
            let Some(new_versions) = new_versions.get(key) else {
                continue;
            };
            if old_versions != new_versions {
                version_changed.push(VersionChange {
                    name: key.0.clone(),
                    source: key.1.clone(),
                    old_versions: old_versions.iter().cloned().collect(),
                    new_versions: new_versions.iter().cloned().collect(),
                });
            }
        }

        let old_git = git_revision_map(old);
        let new_git = git_revision_map(new);
        let mut git_revision_changed = Vec::new();
        for (key, old_revisions) in &old_git {
            let Some(new_revisions) = new_git.get(key) else {
                continue;
            };
            if old_revisions != new_revisions {
                git_revision_changed.push(GitRevisionChange {
                    name: key.0.clone(),
                    url: key.1.clone(),
                    old_revisions: old_revisions.iter().cloned().collect(),
                    new_revisions: new_revisions.iter().cloned().collect(),
                });
            }
        }

        added.sort();
        removed.sort();
        version_changed.sort();
        git_revision_changed.sort();

        let lockfile_changed = old.lockfile_sha256 != new.lockfile_sha256;
        let has_changes = lockfile_changed
            || !added.is_empty()
            || !removed.is_empty()
            || !version_changed.is_empty()
            || !git_revision_changed.is_empty();

        Self {
            schema_version: DIFF_SCHEMA_VERSION,
            old_lockfile_sha256: old.lockfile_sha256.clone(),
            new_lockfile_sha256: new.lockfile_sha256.clone(),
            lockfile_changed,
            added,
            removed,
            version_changed,
            git_revision_changed,
            has_changes,
        }
    }

    /// Render a compact human-readable diff.
    pub fn render_text(&self) -> String {
        if !self.has_changes {
            return "No dependency changes detected.\n".to_owned();
        }
        let mut output = String::new();
        if self.lockfile_changed {
            output.push_str(&format!(
                "Cargo.lock changed: {} -> {}\n",
                self.old_lockfile_sha256
                    .as_deref()
                    .map(short_hash)
                    .unwrap_or_else(|| "none".to_owned()),
                self.new_lockfile_sha256
                    .as_deref()
                    .map(short_hash)
                    .unwrap_or_else(|| "none".to_owned())
            ));
        }
        for change in &self.added {
            output.push_str(&format!(
                "+ {} {} ({}){}\n",
                change.name,
                change.version,
                change.source,
                change
                    .git_revision
                    .as_ref()
                    .map(|revision| format!(" @ {}", short_hash(revision)))
                    .unwrap_or_default()
            ));
        }
        for change in &self.removed {
            output.push_str(&format!(
                "- {} {} ({})\n",
                change.name, change.version, change.source
            ));
        }
        for change in &self.version_changed {
            output.push_str(&format!(
                "~ {} {}: {} -> {}\n",
                change.name,
                change.source,
                change.old_versions.join(", "),
                change.new_versions.join(", ")
            ));
        }
        for change in &self.git_revision_changed {
            output.push_str(&format!(
                "~ {} git revision ({}): {} -> {}\n",
                change.name,
                change.url,
                change
                    .old_revisions
                    .iter()
                    .map(|revision| short_hash(revision))
                    .collect::<Vec<_>>()
                    .join(", "),
                change
                    .new_revisions
                    .iter()
                    .map(|revision| short_hash(revision))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        output
    }
}

fn identity_map(
    snapshot: &DependencySnapshot,
) -> BTreeMap<(String, String, String), &PackageRecord> {
    snapshot
        .packages
        .iter()
        .map(|package| {
            (
                (
                    package.name.clone(),
                    package.version.clone(),
                    package.source_identity(),
                ),
                package,
            )
        })
        .collect()
}

fn version_map(snapshot: &DependencySnapshot) -> BTreeMap<(String, String), BTreeSet<String>> {
    let mut map: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for package in &snapshot.packages {
        map.entry((package.name.clone(), package.source_identity()))
            .or_default()
            .insert(package.version.clone());
    }
    map
}

fn git_revision_map(snapshot: &DependencySnapshot) -> BTreeMap<(String, String), BTreeSet<String>> {
    let mut map: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for package in &snapshot.packages {
        if let Some(git) = &package.git {
            if let Some(revision) = &git.resolved_revision {
                map.entry((package.name.clone(), git.url.clone()))
                    .or_default()
                    .insert(revision.clone());
            }
        }
    }
    map
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PackageRecord, PACKAGES_SCHEMA_VERSION};
    use crate::source::{GitSourceRef, SourceKind};
    use std::collections::BTreeMap;

    fn package(name: &str, version: &str) -> PackageRecord {
        PackageRecord {
            id: format!("id#{name}@{version}"),
            name: name.to_owned(),
            version: version.to_owned(),
            source: Some("registry+https://index.crates.io".to_owned()),
            source_kind: SourceKind::Registry,
            registry: Some("https://index.crates.io".to_owned()),
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

    fn snapshot(packages: Vec<PackageRecord>, hash: &str) -> DependencySnapshot {
        DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: String::new(),
            lockfile_path: String::new(),
            lockfile_sha256: Some(hash.to_owned()),
            package_count: packages.len(),
            packages,
        }
    }

    #[test]
    fn detects_added_removed_and_version_changes() {
        let old = snapshot(
            vec![
                package("same", "1.0.0"),
                package("gone", "1.0.0"),
                package("bump", "1.0.0"),
            ],
            "aa",
        );
        let new = snapshot(
            vec![
                package("same", "1.0.0"),
                package("fresh", "2.0.0"),
                package("bump", "1.1.0"),
            ],
            "bb",
        );
        let diff = SnapshotDiff::between(&old, &new);
        assert!(diff.has_changes);
        assert!(diff.lockfile_changed);
        assert_eq!(diff.added.len(), 2);
        assert_eq!(diff.removed.len(), 2);
        assert_eq!(diff.version_changed.len(), 1);
        assert_eq!(diff.version_changed[0].name, "bump");
        let text = diff.render_text();
        assert!(text.contains("+ fresh 2.0.0"));
        assert!(text.contains("- gone 1.0.0"));
    }

    #[test]
    fn detects_git_revision_changes() {
        let mut old_package = package("gitdep", "1.0.0");
        old_package.source_kind = SourceKind::Git;
        old_package.registry = None;
        old_package.git = Some(GitSourceRef {
            url: "https://github.com/example/repo".to_owned(),
            rev: Some("aaaa".to_owned()),
            resolved_revision: Some("aaaa".to_owned()),
            pinned: true,
            ..GitSourceRef::default()
        });
        let mut new_package = old_package.clone();
        new_package.git.as_mut().expect("git").resolved_revision = Some("bbbb".to_owned());

        let diff = SnapshotDiff::between(
            &snapshot(vec![old_package], "aa"),
            &snapshot(vec![new_package], "aa"),
        );
        assert_eq!(diff.git_revision_changed.len(), 1);
        assert!(!diff.lockfile_changed);
        assert!(diff.has_changes);
    }

    #[test]
    fn identical_snapshots_have_no_changes() {
        let diff = SnapshotDiff::between(
            &snapshot(vec![package("same", "1.0.0")], "aa"),
            &snapshot(vec![package("same", "1.0.0")], "aa"),
        );
        assert!(!diff.has_changes);
        assert_eq!(diff.render_text(), "No dependency changes detected.\n");
    }
}
