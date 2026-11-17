//! Minimal, read-only Cargo.lock parsing.
//!
//! Cargo.lock is the approved resolution input. This module never writes a
//! lockfile; it extracts the exact versions, sources, and registry checksums
//! that Cargo already resolved.

use crate::{paths, source::parse_git_source};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

/// Parsed `Cargo.lock`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Lockfile {
    /// Lockfile format version.
    #[serde(default = "default_lockfile_version")]
    pub version: u32,
    /// Resolved packages.
    #[serde(default)]
    pub package: Vec<LockPackage>,
}

fn default_lockfile_version() -> u32 {
    1
}

/// One `[[package]]` entry.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LockPackage {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Source string, absent for workspace and path packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Registry package checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// Dependencies, either names or detailed descriptions.
    #[serde(default)]
    pub dependencies: Vec<LockDependency>,
}

/// A dependency entry in Cargo.lock.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LockDependency {
    /// A bare name, or a name with an inline version constraint.
    Name(String),
    /// A detailed lockfile dependency entry.
    Detailed {
        /// Dependency name.
        name: String,
        /// Optional version.
        #[serde(default)]
        version: Option<String>,
        /// Optional source.
        #[serde(default)]
        source: Option<String>,
    },
}

impl std::fmt::Display for LockDependency {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(value) => formatter.write_str(value),
            Self::Detailed {
                name,
                version,
                source,
            } => {
                formatter.write_str(name)?;
                if let Some(version) = version {
                    write!(formatter, " {version}")?;
                }
                if let Some(source) = source {
                    write!(formatter, " ({source})")?;
                }
                Ok(())
            }
        }
    }
}

impl Lockfile {
    /// Read and parse a lockfile.
    pub fn read(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("reading Cargo.lock at {}", path.display()))?;
        let lockfile: Self = toml::from_str(&contents)
            .with_context(|| format!("parsing Cargo.lock at {}", path.display()))?;
        if lockfile.version == 0 {
            bail!(
                "Cargo.lock at {} has an invalid format version 0",
                path.display()
            );
        }
        Ok(lockfile)
    }

    /// Parse from a string, primarily for tests.
    pub fn parse(contents: &str) -> Result<Self> {
        Ok(toml::from_str(contents)?)
    }

    /// Find a package by name, version, and exact source.
    pub fn find(&self, name: &str, version: &str, source: Option<&str>) -> Option<&LockPackage> {
        self.package.iter().find(|package| {
            package.name == name
                && package.version == version
                && package.source.as_deref() == source
        })
    }

    /// Find a package by name and version when the source is not needed.
    pub fn find_by_name_version(&self, name: &str, version: &str) -> Option<&LockPackage> {
        self.package
            .iter()
            .find(|package| package.name == name && package.version == version)
    }

    /// Map `(name, version, source)` to lockfile entries.
    pub fn keyed(&self) -> BTreeMap<(String, String, Option<String>), &LockPackage> {
        self.package
            .iter()
            .map(|package| {
                (
                    (
                        package.name.clone(),
                        package.version.clone(),
                        package.source.clone(),
                    ),
                    package,
                )
            })
            .collect()
    }

    /// Count packages by broad source category.
    pub fn counts(&self) -> LockfileCounts {
        let mut counts = LockfileCounts::default();
        for package in &self.package {
            match package.source.as_deref() {
                Some(source) if source.starts_with("git+") => counts.git += 1,
                Some(_) => counts.registry += 1,
                None => counts.path_or_workspace += 1,
            }
        }
        counts
    }

    /// Return `(name, version, repository url, resolved revision)` for each Git
    /// package in the lockfile.
    pub fn git_packages(&self) -> Vec<GitLockPackage> {
        self.package
            .iter()
            .filter_map(|package| {
                let source = package.source.as_deref()?;
                let rest = source.strip_prefix("git+")?;
                let git = parse_git_source(rest);
                let reference = git.reference_label();
                Some(GitLockPackage {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    url: git.url,
                    reference,
                    revision: git.resolved_revision,
                    pinned: git.pinned,
                })
            })
            .collect()
    }
}

/// Broad package counts from a lockfile.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockfileCounts {
    /// Packages from registries.
    pub registry: usize,
    /// Packages from Git repositories.
    pub git: usize,
    /// Local path dependencies and workspace members.
    pub path_or_workspace: usize,
}

/// Git package information derived from a lockfile source string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitLockPackage {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Repository URL.
    pub url: String,
    /// Declared reference label.
    pub reference: String,
    /// Resolved commit hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Whether an exact `rev` was declared.
    pub pinned: bool,
}

/// Write the `lockfile.sha256` sidecar in `sha256sum`-compatible form.
pub fn write_checksum_file(path: &Path, hash: &str, lockfile_name: &str) -> Result<()> {
    paths::atomic_write(path, format!("{hash}  {lockfile_name}\n").as_bytes())
}

/// Read the SHA-256 from a `lockfile.sha256` sidecar.
pub fn read_checksum_file(path: &Path) -> Result<Option<String>> {
    if !path.is_file() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading checksum file {}", path.display()))?;
    let hash = contents.split_whitespace().next().map(str::to_owned);
    if let Some(hash) = &hash {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "checksum file {} does not contain a valid SHA-256 digest",
                path.display()
            );
        }
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKFILE_V4: &str = r#"
version = 4

[[package]]
name = "local-app"
version = "0.1.0"
dependencies = [
 "serde",
 "helper",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "git-dep"
version = "0.2.0"
source = "git+https://github.com/nrelab/example.git?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "helper"
version = "0.1.0"
"#;

    #[test]
    fn parses_lockfile_packages_and_counts() {
        let lockfile = Lockfile::parse(LOCKFILE_V4).expect("parse");
        assert_eq!(lockfile.version, 4);
        assert_eq!(lockfile.package.len(), 4);
        let counts = lockfile.counts();
        assert_eq!(counts.registry, 1);
        assert_eq!(counts.git, 1);
        assert_eq!(counts.path_or_workspace, 2);

        let serde = lockfile
            .find(
                "serde",
                "1.0.200",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
            )
            .expect("serde");
        assert!(serde.checksum.is_some());
        assert_eq!(serde.dependencies.len(), 0);
    }

    #[test]
    fn extracts_git_revisions() {
        let lockfile = Lockfile::parse(LOCKFILE_V4).expect("parse");
        let git = lockfile.git_packages();
        assert_eq!(git.len(), 1);
        assert_eq!(git[0].name, "git-dep");
        assert_eq!(git[0].url, "https://github.com/nrelab/example.git");
        assert_eq!(
            git[0].revision.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert!(git[0].pinned);
    }

    #[test]
    fn parses_detailed_dependency_tables() {
        let lockfile = Lockfile::parse(
            r#"
version = 1
[[package]]
name = "root"
version = "0.1.0"
dependencies = [
 { name = "dep", version = "1.2.3", source = "registry+https://example.com/index" },
]
"#,
        )
        .expect("parse");
        assert_eq!(
            lockfile.package[0].dependencies[0].to_string(),
            "dep 1.2.3 (registry+https://example.com/index)"
        );
    }

    #[test]
    fn checksum_sidecar_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("lockfile.sha256");
        let hash = "ab".repeat(32);
        write_checksum_file(&path, &hash, "Cargo.lock").expect("write");
        assert_eq!(read_checksum_file(&path).expect("read"), Some(hash));
    }

    #[test]
    fn rejects_invalid_checksum_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("lockfile.sha256");
        std::fs::write(&path, "not-a-hash  Cargo.lock\n").expect("write");
        assert!(read_checksum_file(&path).is_err());
    }
}
