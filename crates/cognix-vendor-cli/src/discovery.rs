//! Dependency discovery through `cargo metadata` and `Cargo.lock`.
//!
//! Cargo performs all resolution. This module records what Cargo resolved,
//! enriches packages with lockfile checksums, and writes deterministic,
//! versioned metadata documents plus a CycloneDX SBOM.

use anyhow::{bail, Context, Result};
use cargo_metadata::{Metadata, MetadataCommand, PackageId};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use crate::{
    lockfile::{read_checksum_file, write_checksum_file, Lockfile},
    model::{
        ConsumerProvenance, DependencyRecord, DependencySnapshot, GeneratorInfo, GitSourcesFile,
        LockfileProvenance, PackageRecord, ProvenanceFile, TargetRecord, VendorProvenance,
        PACKAGES_SCHEMA_VERSION, PROVENANCE_SCHEMA_VERSION,
    },
    paths,
    process::Command,
    source::{parse_source, stable_package_id, ParsedSource, SourceKind},
};

/// Resolved discovery result.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Deterministic package snapshot.
    pub snapshot: DependencySnapshot,
    /// Parsed lockfile used for checksums and freshness.
    pub lockfile: Lockfile,
    /// Absolute lockfile path.
    pub lockfile_path: PathBuf,
    /// Absolute workspace root reported by Cargo.
    pub workspace_root: PathBuf,
    /// Cargo version string, when available.
    pub cargo_version: Option<String>,
}

/// Metadata output paths.
#[derive(Debug, Clone)]
pub struct MetadataOutputs {
    /// `packages.json`.
    pub packages: PathBuf,
    /// `git-sources.json`.
    pub git_sources: PathBuf,
    /// `provenance.json`.
    pub provenance: PathBuf,
    /// `lockfile.sha256`.
    pub lockfile_checksum: PathBuf,
    /// `sbom.json`.
    pub sbom: PathBuf,
}

impl MetadataOutputs {
    /// Build outputs for a resolved consumer.
    pub fn for_consumer(consumer: &crate::config::ResolvedConsumer) -> Self {
        Self {
            packages: consumer.packages_path(),
            git_sources: consumer.git_sources_path(),
            provenance: consumer.provenance_path(),
            lockfile_checksum: consumer.lockfile_checksum_path(),
            sbom: consumer.sbom_path(),
        }
    }
}

/// Discover the resolved package graph for a manifest.
pub fn discover(manifest_path: &Path, offline: bool) -> Result<DiscoveryResult> {
    let manifest = paths::absolute_path(manifest_path)?;
    if !manifest.is_file() {
        bail!(
            "Cargo manifest does not exist: {} (pass --manifest-path)",
            manifest.display()
        );
    }

    let metadata = run_cargo_metadata(&manifest, offline)?;
    let workspace_root = PathBuf::from(metadata.workspace_root.as_std_path());
    let lockfile_path = workspace_root.join("Cargo.lock");
    if !lockfile_path.is_file() {
        bail!(
            "Cargo.lock is missing at {}; generate and commit a lockfile before discovery",
            lockfile_path.display()
        );
    }
    let lockfile = Lockfile::read(&lockfile_path)?;
    let lockfile_sha256 = paths::sha256_file(&lockfile_path)?;

    let snapshot = build_snapshot(
        &metadata,
        &lockfile,
        &workspace_root,
        &manifest,
        lockfile_sha256,
    )?;
    let cargo_version = cargo_version();

    Ok(DiscoveryResult {
        snapshot,
        lockfile,
        lockfile_path,
        workspace_root,
        cargo_version,
    })
}

/// Write all metadata documents. Each document is replaced atomically.
///
/// `packages_path` may point outside the metadata directory for backward
/// compatibility with `discover --output`.
pub fn write_metadata(
    result: &DiscoveryResult,
    outputs: &MetadataOutputs,
    packages_path: &Path,
    vendor: Option<VendorProvenance>,
) -> Result<()> {
    let snapshot = &result.snapshot;
    let git_sources = GitSourcesFile::from_snapshot(snapshot);
    let sbom = crate::sbom::build_sbom(snapshot)?;

    let packages_bytes = json_bytes(&snapshot)?;
    let git_bytes = json_bytes(&git_sources)?;
    let sbom_bytes = json_bytes(&sbom)?;

    paths::atomic_write(packages_path, &packages_bytes)
        .with_context(|| format!("writing packages metadata {}", packages_path.display()))?;
    paths::atomic_write(&outputs.git_sources, &git_bytes).with_context(|| {
        format!(
            "writing Git source metadata {}",
            outputs.git_sources.display()
        )
    })?;
    paths::atomic_write(&outputs.sbom, &sbom_bytes)
        .with_context(|| format!("writing SBOM {}", outputs.sbom.display()))?;

    let lockfile_hash = snapshot.lockfile_sha256.as_deref().unwrap_or("");
    write_checksum_file(
        &outputs.lockfile_checksum,
        lockfile_hash,
        result
            .lockfile_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Cargo.lock"),
    )?;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        artifact_name(packages_path),
        paths::sha256_bytes(&packages_bytes),
    );
    artifacts.insert(
        artifact_name(&outputs.git_sources),
        paths::sha256_bytes(&git_bytes),
    );
    artifacts.insert(
        artifact_name(&outputs.sbom),
        paths::sha256_bytes(&sbom_bytes),
    );
    artifacts.insert(
        artifact_name(&outputs.lockfile_checksum),
        paths::sha256_file(&outputs.lockfile_checksum)?,
    );

    let provenance = ProvenanceFile {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        generator: GeneratorInfo::default(),
        consumer: ConsumerProvenance {
            name: snapshot.consumer.clone(),
            manifest_path: snapshot.manifest_path.clone(),
            workspace_root_name: result
                .workspace_root
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned),
        },
        generated_at_unix: paths::unix_timestamp()?,
        cargo_version: result.cargo_version.clone(),
        lockfile: LockfileProvenance {
            version: result.lockfile.version,
            sha256: snapshot.lockfile_sha256.clone(),
            file_name: result
                .lockfile_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("Cargo.lock")
                .to_owned(),
        },
        vendor,
        artifacts,
    };
    paths::write_json(&outputs.provenance, &provenance)
        .with_context(|| format!("writing provenance {}", outputs.provenance.display()))?;
    Ok(())
}

/// Check that the snapshot's recorded lockfile checksum still matches the
/// sidecar document.
pub fn verify_recorded_lockfile_checksum(
    snapshot: &DependencySnapshot,
    checksum_path: &Path,
) -> Result<()> {
    let recorded = read_checksum_file(checksum_path)?;
    match (&snapshot.lockfile_sha256, recorded) {
        (Some(snapshot_hash), Some(sidecar_hash)) if snapshot_hash != &sidecar_hash => {
            bail!(
                "lockfile.sha256 ({sidecar_hash}) does not match packages.json ({snapshot_hash})"
            );
        }
        (Some(_), None) => bail!("lockfile.sha256 is missing at {}", checksum_path.display()),
        (None, _) => bail!("packages.json does not record a lockfile checksum"),
        _ => Ok(()),
    }
}

fn run_cargo_metadata(manifest: &Path, offline: bool) -> Result<Metadata> {
    let mut options = vec!["--locked".to_owned()];
    if offline {
        options.push("--offline".to_owned());
    }
    let mut command = MetadataCommand::new();
    command.manifest_path(manifest).other_options(options);
    command.exec().with_context(|| {
        format!(
            "running `cargo metadata --locked` for {}; ensure the lockfile is current",
            manifest.display()
        )
    })
}

fn build_snapshot(
    metadata: &Metadata,
    lockfile: &Lockfile,
    workspace_root: &Path,
    manifest: &Path,
    lockfile_sha256: String,
) -> Result<DependencySnapshot> {
    let workspace_members: HashSet<&PackageId> = metadata.workspace_members.iter().collect();
    let resolve_nodes: HashMap<&PackageId, _> = metadata
        .resolve
        .as_ref()
        .map(|resolve| resolve.nodes.iter().map(|node| (&node.id, node)).collect())
        .unwrap_or_default();

    let mut raw_to_stable: HashMap<String, String> = HashMap::new();
    for package in &metadata.packages {
        let workspace_member = workspace_members.contains(&package.id);
        let source = package.source.as_ref().map(ToString::to_string);
        let manifest_relative =
            relative_manifest(workspace_root, package.manifest_path.as_std_path());
        let stable_id = stable_package_id(
            package.name.as_ref(),
            &package.version.to_string(),
            source.as_deref(),
            workspace_member,
            manifest_relative.as_deref(),
        );
        raw_to_stable.insert(package.id.to_string(), stable_id);
    }

    let mut packages = Vec::with_capacity(metadata.packages.len());
    for package in &metadata.packages {
        let raw_id = package.id.to_string();
        let stable_id = raw_to_stable
            .get(&raw_id)
            .cloned()
            .unwrap_or_else(|| raw_id.clone());
        let workspace_member = workspace_members.contains(&package.id);
        let source = package.source.as_ref().map(ToString::to_string);
        let parsed = source.as_deref().map(parse_source);
        let source_kind = if workspace_member {
            SourceKind::Workspace
        } else {
            parsed
                .as_ref()
                .map(ParsedSource::kind)
                .unwrap_or(SourceKind::Path)
        };
        let registry = match &parsed {
            Some(ParsedSource::Registry { url }) => Some(url.clone()),
            _ => None,
        };
        let git = match &parsed {
            Some(ParsedSource::Git(git)) => Some(git.clone()),
            _ => None,
        };

        let lock_package = lockfile
            .find(
                package.name.as_ref(),
                &package.version.to_string(),
                source.as_deref(),
            )
            .or_else(|| {
                lockfile.find_by_name_version(package.name.as_ref(), &package.version.to_string())
            });
        if !workspace_member && source_kind.is_vendorable() && lock_package.is_none() {
            bail!(
                "resolved package {} {} from {} is not present in Cargo.lock; refusing to invent resolution metadata",
                package.name,
                package.version,
                source.as_deref().unwrap_or("<no source>")
            );
        }
        let checksum = lock_package.and_then(|package| package.checksum.clone());

        let node = resolve_nodes.get(&package.id);
        let mut resolved_dependencies = node
            .map(|node| {
                node.deps
                    .iter()
                    .filter_map(|dependency| {
                        raw_to_stable.get(&dependency.pkg.to_string()).cloned()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        resolved_dependencies.sort();
        resolved_dependencies.dedup();
        let mut enabled_features = node
            .map(|node| {
                node.features
                    .iter()
                    .map(|feature| feature.as_ref().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        enabled_features.sort();

        let mut targets: Vec<TargetRecord> = package
            .targets
            .iter()
            .map(|target| {
                let mut kind: Vec<String> = target.kind.iter().map(ToString::to_string).collect();
                kind.sort();
                let mut crate_types: Vec<String> =
                    target.crate_types.iter().map(ToString::to_string).collect();
                crate_types.sort();
                let mut required_features = target.required_features.clone();
                required_features.sort();
                TargetRecord {
                    name: target.name.clone(),
                    kind,
                    crate_types,
                    required_features,
                }
            })
            .collect();
        targets.sort();

        let mut dependencies: Vec<DependencyRecord> = package
            .dependencies
            .iter()
            .map(|dependency| DependencyRecord {
                name: dependency.name.clone(),
                requirement: dependency.req.to_string(),
                kind: dependency.kind.to_string(),
                optional: dependency.optional,
                uses_default_features: dependency.uses_default_features,
                features: dependency.features.clone(),
                target: dependency.target.as_ref().map(ToString::to_string),
                rename: dependency.rename.clone(),
                registry: dependency.registry.clone(),
            })
            .collect();
        dependencies.sort();

        let mut features: BTreeMap<String, Vec<String>> = package
            .features
            .iter()
            .map(|(name, values)| {
                let mut values = values.clone();
                values.sort();
                (name.clone(), values)
            })
            .collect();
        for values in features.values_mut() {
            values.sort();
        }

        packages.push(PackageRecord {
            id: stable_id,
            name: package.name.to_string(),
            version: package.version.to_string(),
            source,
            source_kind,
            registry,
            git,
            checksum,
            license: package.license.clone(),
            license_file: package
                .license_file
                .as_ref()
                .and_then(|path| path.file_name())
                .map(str::to_owned),
            repository: package.repository.clone(),
            description: package.description.clone(),
            manifest_path: relative_manifest(workspace_root, package.manifest_path.as_std_path()),
            is_workspace_member: workspace_member,
            targets,
            features,
            dependencies,
            resolved_dependencies,
            enabled_features,
        });
    }

    let consumer = workspace_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("consumer")
        .to_owned();
    let manifest_display = display_path(manifest);

    let mut snapshot = DependencySnapshot {
        schema_version: PACKAGES_SCHEMA_VERSION,
        consumer,
        manifest_path: manifest_display,
        lockfile_path: "Cargo.lock".to_owned(),
        lockfile_sha256: Some(lockfile_sha256),
        package_count: packages.len(),
        packages,
    };
    snapshot.normalize();
    Ok(snapshot)
}

fn relative_manifest(workspace_root: &Path, manifest: &std::path::Path) -> Option<String> {
    if !paths::is_within(manifest, workspace_root) {
        return None;
    }
    let relative = paths::relative_to(workspace_root, manifest);
    Some(portable_path(&relative))
}

fn display_path(path: &Path) -> String {
    let current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if paths::is_within(path, &current) {
        portable_path(&paths::relative_to(&current, path))
    } else {
        portable_path(path)
    }
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn artifact_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("metadata")
        .to_owned()
}

fn json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).context("serializing metadata")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn cargo_version() -> Option<String> {
    let output = Command::new(paths::cargo_program())
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn relative_paths_are_portable() {
        assert_eq!(
            relative_manifest(
                Path::new("/work/app"),
                Path::new("/work/app/crates/one/Cargo.toml")
            )
            .as_deref(),
            Some("crates/one/Cargo.toml")
        );
        assert_eq!(
            relative_manifest(
                Path::new("/work/app"),
                Path::new("/home/user/.cargo/registry/x")
            ),
            None
        );
    }

    #[test]
    fn discovery_requires_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = discover(&dir.path().join("missing/Cargo.toml"), false).expect_err("must fail");
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn metadata_outputs_follow_consumer_layout() {
        let consumer = crate::config::ResolvedConsumer {
            name: "demo".to_owned(),
            root: PathBuf::from("/repo"),
            manifest_path: PathBuf::from("/repo/../demo/Cargo.toml"),
            metadata_dir: PathBuf::from("/repo/metadata/demo"),
            vendor_dir: PathBuf::from("/repo/vendor"),
            config_output: PathBuf::from("/repo/config/demo.toml"),
            policy_dir: PathBuf::from("/repo/metadata/policies"),
        };
        let outputs = MetadataOutputs::for_consumer(&consumer);
        assert_eq!(
            outputs.packages,
            PathBuf::from("/repo/metadata/demo/packages.json")
        );
        assert_eq!(
            outputs.lockfile_checksum,
            PathBuf::from("/repo/metadata/demo/lockfile.sha256")
        );
    }

    #[test]
    fn checksum_sidecar_mismatch_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("lockfile.sha256");
        fs::write(&path, format!("{}  Cargo.lock\n", "ab".repeat(32))).expect("write");
        let snapshot = DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: String::new(),
            lockfile_path: "Cargo.lock".to_owned(),
            lockfile_sha256: Some("cd".repeat(32)),
            package_count: 0,
            packages: Vec::new(),
        };
        assert!(verify_recorded_lockfile_checksum(&snapshot, &path).is_err());
    }
}
