//! Vendor integrity verification.
//!
//! Verification is read-only. It never repairs, rewrites, or deletes vendor
//! content, even when it finds a mismatch. Every problem is reported with a
//! stable code so CI and machines can reason about it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

use crate::{
    config::ResolvedConsumer,
    lockfile::{read_checksum_file, Lockfile},
    model::{DependencySnapshot, GitSourcesFile, PackageRecord, ProvenanceFile},
    paths,
    source::parse_source,
};

/// Current verification report schema.
pub const VERIFY_SCHEMA_VERSION: u32 = 1;

/// Verification inputs.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Directory containing generated metadata.
    pub metadata_dir: PathBuf,
    /// Cargo vendor directory.
    pub vendor_dir: PathBuf,
    /// Consumer manifest, used to detect a changed lockfile.
    pub manifest_path: Option<PathBuf>,
    /// Downgrade lockfile freshness errors to warnings. This does not relax
    /// checksum verification.
    pub allow_lockfile_change: bool,
}

impl VerifyOptions {
    /// Build options from a resolved consumer.
    pub fn for_consumer(consumer: &ResolvedConsumer, allow_lockfile_change: bool) -> Self {
        Self {
            metadata_dir: consumer.metadata_dir.clone(),
            vendor_dir: consumer.vendor_dir.clone(),
            manifest_path: Some(consumer.manifest_path.clone()),
            allow_lockfile_change,
        }
    }
}

/// Result of verifying a vendor tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    /// Schema version.
    pub schema_version: u32,
    /// Vendor directory that was checked.
    pub vendor_dir: String,
    /// Metadata directory that supplied the approved snapshot.
    pub metadata_dir: String,
    /// True when no error-severity finding was produced.
    pub ok: bool,
    /// Number of expected package directories checked.
    pub package_count: usize,
    /// Number of files whose checksums were recomputed.
    pub file_count: usize,
    /// Number of error findings.
    pub error_count: usize,
    /// Number of warning findings.
    pub warning_count: usize,
    /// Sorted findings.
    pub findings: Vec<Finding>,
}

/// Severity of a verification finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational only.
    Info,
    /// Needs review but does not fail verification by itself.
    Warning,
    /// Fails verification.
    Error,
}

/// One verification finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// Stable machine-readable code.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Package name, when the finding applies to one package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Relative path, when the finding applies to a file or directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Human-readable explanation.
    pub message: String,
}

impl Finding {
    fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Error,
            package: None,
            path: None,
            message: message.into(),
        }
    }

    fn warning(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Warning,
            package: None,
            path: None,
            message: message.into(),
        }
    }

    fn package(mut self, package: &str) -> Self {
        self.package = Some(package.to_owned());
        self
    }

    fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

#[derive(Debug, Deserialize)]
struct CargoChecksumFile {
    #[serde(default)]
    files: BTreeMap<String, String>,
    #[serde(default)]
    package: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestPackage {
    package: Option<ManifestPackageFields>,
}

#[derive(Debug, Deserialize)]
struct ManifestPackageFields {
    name: Option<String>,
    version: Option<String>,
}

/// Verify a resolved consumer's vendor tree.
pub fn verify_consumer(
    consumer: &ResolvedConsumer,
    allow_lockfile_change: bool,
) -> Result<VerificationReport> {
    verify(&VerifyOptions::for_consumer(
        consumer,
        allow_lockfile_change,
    ))
}

/// Verify a vendor tree against an approved snapshot.
pub fn verify(options: &VerifyOptions) -> Result<VerificationReport> {
    let mut report = VerificationReport {
        schema_version: VERIFY_SCHEMA_VERSION,
        vendor_dir: options.vendor_dir.display().to_string(),
        metadata_dir: options.metadata_dir.display().to_string(),
        ok: true,
        package_count: 0,
        file_count: 0,
        error_count: 0,
        warning_count: 0,
        findings: Vec::new(),
    };

    let packages_path = options.metadata_dir.join("packages.json");
    if !packages_path.is_file() {
        report.findings.push(
            Finding::error(
                "missing_metadata",
                format!(
                    "approved package snapshot is missing at {}; run `cognix-vendor discover` or `sync`",
                    packages_path.display()
                ),
            )
            .path(packages_path.display().to_string()),
        );
        verify_vendor_shape(&options.vendor_dir, &mut report);
        finalize(&mut report);
        return Ok(report);
    }

    let snapshot = DependencySnapshot::read(&packages_path)?;
    let checksum_path = options.metadata_dir.join("lockfile.sha256");
    match read_checksum_file(&checksum_path) {
        Ok(Some(sidecar_hash)) => {
            if snapshot.lockfile_sha256.as_deref() != Some(sidecar_hash.as_str()) {
                report.findings.push(Finding::error(
                    "metadata_inconsistent",
                    format!(
                        "lockfile.sha256 ({sidecar_hash}) does not match packages.json ({})",
                        snapshot.lockfile_sha256.as_deref().unwrap_or("missing")
                    ),
                ));
            }
        }
        Ok(None) => report.findings.push(Finding::error(
            "missing_metadata",
            format!(
                "lockfile.sha256 is missing at {}; regenerate metadata",
                checksum_path.display()
            ),
        )),
        Err(error) => report.findings.push(Finding::error(
            "invalid_metadata",
            format!("cannot read {}: {error:#}", checksum_path.display()),
        )),
    }

    verify_metadata_documents(&options.metadata_dir, &snapshot, &mut report)?;
    verify_current_lockfile(options, &snapshot, &mut report)?;
    verify_vendor_tree(&options.vendor_dir, &snapshot, &mut report)?;

    finalize(&mut report);
    Ok(report)
}

/// Verify only the vendor tree against an in-memory snapshot.
///
/// This is used by synchronization before committing a staged vendor tree.
/// Metadata-document checks are intentionally skipped because the staged
/// metadata does not exist yet.
pub fn verify_snapshot(
    vendor_dir: &Path,
    snapshot: &DependencySnapshot,
) -> Result<VerificationReport> {
    let mut report = VerificationReport {
        schema_version: VERIFY_SCHEMA_VERSION,
        vendor_dir: vendor_dir.display().to_string(),
        metadata_dir: String::new(),
        ok: true,
        package_count: 0,
        file_count: 0,
        error_count: 0,
        warning_count: 0,
        findings: Vec::new(),
    };
    verify_vendor_tree(vendor_dir, snapshot, &mut report)?;
    finalize(&mut report);
    Ok(report)
}

fn finalize(report: &mut VerificationReport) {
    report.findings.sort();
    report.error_count = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    report.warning_count = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    report.ok = report.error_count == 0;
}

fn verify_metadata_documents(
    metadata_dir: &Path,
    snapshot: &DependencySnapshot,
    report: &mut VerificationReport,
) -> Result<()> {
    let git_path = metadata_dir.join("git-sources.json");
    if !git_path.is_file() {
        report.findings.push(
            Finding::error(
                "missing_metadata",
                format!("{} is missing; regenerate metadata", git_path.display()),
            )
            .path(git_path.display().to_string()),
        );
    } else {
        match crate::paths::read_json::<GitSourcesFile>(&git_path) {
            Ok(git_sources) => {
                if git_sources.lockfile_sha256 != snapshot.lockfile_sha256 {
                    report.findings.push(Finding::error(
                        "metadata_inconsistent",
                        "git-sources.json was generated from a different lockfile",
                    ));
                }
                let recorded: BTreeSet<(String, String)> = git_sources
                    .sources
                    .iter()
                    .flat_map(|source| {
                        source
                            .packages
                            .iter()
                            .map(|package| (package.name.clone(), package.version.clone()))
                    })
                    .collect();
                for package in snapshot.vendorable_packages() {
                    if package.source_kind == crate::source::SourceKind::Git
                        && !recorded.contains(&(package.name.clone(), package.version.clone()))
                    {
                        report.findings.push(
                            Finding::error(
                                "metadata_inconsistent",
                                format!(
                                    "Git package {} {} is missing from git-sources.json",
                                    package.name, package.version
                                ),
                            )
                            .package(&package.name),
                        );
                    }
                }
            }
            Err(error) => report.findings.push(Finding::error(
                "invalid_metadata",
                format!("cannot parse {}: {error:#}", git_path.display()),
            )),
        }
    }

    let provenance_path = metadata_dir.join("provenance.json");
    if provenance_path.is_file() {
        match crate::paths::read_json::<ProvenanceFile>(&provenance_path) {
            Ok(provenance) => {
                if provenance.lockfile.sha256 != snapshot.lockfile_sha256 {
                    report.findings.push(Finding::warning(
                        "metadata_inconsistent",
                        "provenance.json records a different lockfile checksum",
                    ));
                }
                if let Some(vendor) = provenance.vendor {
                    if vendor.package_count != snapshot.vendorable_packages().count() {
                        report.findings.push(Finding::warning(
                            "metadata_inconsistent",
                            format!(
                                "provenance.json vendor package count {} does not match snapshot count {}",
                                vendor.package_count,
                                snapshot.vendorable_packages().count()
                            ),
                        ));
                    }
                }
            }
            Err(error) => report.findings.push(Finding::warning(
                "invalid_metadata",
                format!("cannot parse {}: {error:#}", provenance_path.display()),
            )),
        }
    } else {
        report.findings.push(Finding::warning(
            "missing_metadata",
            format!(
                "{} is missing; regenerate metadata",
                provenance_path.display()
            ),
        ));
    }

    let sbom_path = metadata_dir.join("sbom.json");
    if !sbom_path.is_file() {
        report.findings.push(Finding::warning(
            "missing_metadata",
            format!("{} is missing; regenerate metadata", sbom_path.display()),
        ));
    }
    Ok(())
}

fn verify_current_lockfile(
    options: &VerifyOptions,
    snapshot: &DependencySnapshot,
    report: &mut VerificationReport,
) -> Result<()> {
    let Some(manifest_path) = &options.manifest_path else {
        return Ok(());
    };
    let Some(lockfile_path) = find_lockfile(manifest_path) else {
        report.findings.push(Finding::warning(
            "lockfile_missing",
            format!(
                "could not locate Cargo.lock near {}",
                manifest_path.display()
            ),
        ));
        return Ok(());
    };
    let current_hash = paths::sha256_file(&lockfile_path)?;
    if snapshot.lockfile_sha256.as_deref() != Some(current_hash.as_str()) {
        let finding = Finding::error(
            "lockfile_changed",
            format!(
                "Cargo.lock at {} changed after metadata generation; approved snapshot is stale",
                lockfile_path.display()
            ),
        )
        .path(lockfile_path.display().to_string());
        if options.allow_lockfile_change {
            let mut warning = finding;
            warning.severity = Severity::Warning;
            report.findings.push(warning);
        } else {
            report.findings.push(finding);
        }
        return Ok(());
    }

    let current = Lockfile::read(&lockfile_path)?;
    for package in snapshot
        .packages
        .iter()
        .filter(|package| !package.is_workspace_member && package.source_kind.is_vendorable())
    {
        let Some(current_package) = current
            .find(&package.name, &package.version, package.source.as_deref())
            .or_else(|| current.find_by_name_version(&package.name, &package.version))
        else {
            report.findings.push(
                Finding::error(
                    "metadata_mismatch",
                    format!(
                        "package {} {} from the approved snapshot is absent from the current Cargo.lock",
                        package.name, package.version
                    ),
                )
                .package(&package.name),
            );
            continue;
        };
        if let (Some(expected), Some(actual)) = (
            package.checksum.as_deref(),
            current_package.checksum.as_deref(),
        ) {
            if expected != actual {
                report.findings.push(
                    Finding::error(
                        "checksum_mismatch",
                        format!(
                            "lockfile checksum changed for {} {}",
                            package.name, package.version
                        ),
                    )
                    .package(&package.name),
                );
            }
        }
        if let Some(git) = &package.git {
            let current_git = current_package
                .source
                .as_deref()
                .map(parse_source)
                .and_then(|parsed| match parsed {
                    crate::source::ParsedSource::Git(git) => Some(git),
                    _ => None,
                });
            if let Some(current_git) = current_git {
                if git.resolved_revision != current_git.resolved_revision {
                    report.findings.push(
                        Finding::error(
                            "git_revision_changed",
                            format!(
                                "Git revision for {} {} changed from {} to {}",
                                package.name,
                                package.version,
                                git.resolved_revision.as_deref().unwrap_or("unknown"),
                                current_git
                                    .resolved_revision
                                    .as_deref()
                                    .unwrap_or("unknown")
                            ),
                        )
                        .package(&package.name),
                    );
                }
            }
        }
    }
    Ok(())
}

fn verify_vendor_shape(vendor_dir: &Path, report: &mut VerificationReport) {
    if !vendor_dir.exists() {
        report.findings.push(
            Finding::error(
                "vendor_missing",
                format!(
                    "vendor directory does not exist: {}; run `cognix-vendor sync`",
                    vendor_dir.display()
                ),
            )
            .path(vendor_dir.display().to_string()),
        );
    } else if !vendor_dir.is_dir() {
        report.findings.push(Finding::error(
            "vendor_missing",
            format!("vendor path is not a directory: {}", vendor_dir.display()),
        ));
    }
}

fn verify_vendor_tree(
    vendor_dir: &Path,
    snapshot: &DependencySnapshot,
    report: &mut VerificationReport,
) -> Result<()> {
    if !vendor_dir.is_dir() {
        verify_vendor_shape(vendor_dir, report);
        return Ok(());
    }

    let mut directories: BTreeMap<String, PathBuf> = BTreeMap::new();
    for entry in fs::read_dir(vendor_dir)
        .with_context(|| format!("reading vendor directory {}", vendor_dir.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".gitkeep" {
            continue;
        }
        if file_type.is_symlink() {
            report.findings.push(
                Finding::error(
                    "symlink_in_vendor",
                    format!("vendor entry {name} is a symbolic link; refusing to follow it"),
                )
                .path(name),
            );
            continue;
        }
        if file_type.is_dir() {
            directories.insert(name, entry.path());
        } else {
            report.findings.push(
                Finding::error(
                    "unexpected_entry",
                    format!("unexpected non-directory entry in vendor directory: {name}"),
                )
                .path(name),
            );
        }
    }

    let mut used: BTreeSet<String> = BTreeSet::new();
    for package in snapshot.vendorable_packages() {
        let Some(directory_name) = find_package_directory(package, &directories) else {
            report.findings.push(
                Finding::error(
                    "missing_package",
                    format!(
                        "expected vendored package {} {} is missing from {}",
                        package.name,
                        package.version,
                        vendor_dir.display()
                    ),
                )
                .package(&package.name),
            );
            continue;
        };
        if used.contains(&directory_name) {
            report.findings.push(
                Finding::error(
                    "package_directory_collision",
                    format!(
                        "multiple approved packages map to vendor directory {directory_name}; refusing to reuse it"
                    ),
                )
                .package(&package.name),
            );
            continue;
        }
        used.insert(directory_name.clone());
        report.package_count += 1;
        let package_dir = directories
            .get(&directory_name)
            .expect("directory was found by name");
        verify_package(package, package_dir, &directory_name, report)?;
    }

    for name in directories.keys() {
        if !used.contains(name) {
            report.findings.push(
                Finding::error(
                    "unexpected_package",
                    format!(
                        "vendor directory {name} does not correspond to an approved registry or Git package"
                    ),
                )
                .path(name),
            );
        }
    }
    Ok(())
}

fn find_package_directory(
    package: &PackageRecord,
    directories: &BTreeMap<String, PathBuf>,
) -> Option<String> {
    let exact = format!("{}-{}", package.name, package.version);
    if directories.contains_key(&exact) {
        return Some(exact);
    }
    let prefix = format!("{exact}-");
    directories
        .keys()
        .find(|name| name.starts_with(&prefix))
        .cloned()
}

fn verify_package(
    package: &PackageRecord,
    package_dir: &Path,
    directory_name: &str,
    report: &mut VerificationReport,
) -> Result<()> {
    let checksum_path = package_dir.join(".cargo-checksum.json");
    if !checksum_path.is_file() {
        report.findings.push(
            Finding::error(
                "missing_checksum_metadata",
                format!("{directory_name}/.cargo-checksum.json is missing"),
            )
            .package(&package.name)
            .path(format!("{directory_name}/.cargo-checksum.json")),
        );
        return Ok(());
    }

    let checksum: CargoChecksumFile = match fs::read(&checksum_path)
        .with_context(|| format!("reading {}", checksum_path.display()))
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", checksum_path.display()))
        }) {
        Ok(checksum) => checksum,
        Err(error) => {
            report.findings.push(
                Finding::error(
                    "invalid_checksum_metadata",
                    format!("cannot parse {directory_name}/.cargo-checksum.json: {error:#}"),
                )
                .package(&package.name)
                .path(format!("{directory_name}/.cargo-checksum.json")),
            );
            return Ok(());
        }
    };

    if let Some(package_hash) = &checksum.package {
        if package_hash.len() != 64 || !package_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            report.findings.push(
                Finding::error(
                    "invalid_checksum_metadata",
                    format!(
                        "{directory_name}/.cargo-checksum.json has an invalid package checksum"
                    ),
                )
                .package(&package.name),
            );
        } else if let Some(expected) = &package.checksum {
            if !package_hash.eq_ignore_ascii_case(expected) {
                report.findings.push(
                    Finding::error(
                        "checksum_mismatch",
                        format!(
                            "package archive checksum for {} {} does not match Cargo.lock",
                            package.name, package.version
                        ),
                    )
                    .package(&package.name)
                    .path(format!("{directory_name}/.cargo-checksum.json")),
                );
            }
        }
    } else if package.source_kind == crate::source::SourceKind::Registry {
        report.findings.push(
            Finding::error(
                "missing_checksum_metadata",
                format!(
                    "{directory_name}/.cargo-checksum.json has no package checksum for a registry package"
                ),
            )
            .package(&package.name)
            .path(format!("{directory_name}/.cargo-checksum.json")),
        );
    }

    verify_package_manifest(package, package_dir, directory_name, report)?;

    for (relative_name, expected) in &checksum.files {
        let relative = PathBuf::from(relative_name.replace('\\', "/"));
        if !paths::is_safe_relative(&relative) {
            report.findings.push(
                Finding::error(
                    "unsafe_checksum_path",
                    format!(
                        "unsafe path in {directory_name}/.cargo-checksum.json: {relative_name}"
                    ),
                )
                .package(&package.name)
                .path(relative_name.clone()),
            );
            continue;
        }
        let file_path = package_dir.join(&relative);
        let metadata = match fs::symlink_metadata(&file_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                report.findings.push(
                    Finding::error(
                        "missing_file",
                        format!("vendored file is missing: {directory_name}/{relative_name}"),
                    )
                    .package(&package.name)
                    .path(format!("{directory_name}/{relative_name}")),
                );
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            report.findings.push(
                Finding::error(
                    "symlink_in_vendor",
                    format!("vendored file is a symbolic link: {directory_name}/{relative_name}"),
                )
                .package(&package.name)
                .path(format!("{directory_name}/{relative_name}")),
            );
            continue;
        }
        if !metadata.is_file() {
            report.findings.push(
                Finding::error(
                    "missing_file",
                    format!(
                        "vendored path is not a regular file: {directory_name}/{relative_name}"
                    ),
                )
                .package(&package.name)
                .path(format!("{directory_name}/{relative_name}")),
            );
            continue;
        }
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            report.findings.push(
                Finding::error(
                    "invalid_checksum_metadata",
                    format!(
                        "invalid SHA-256 digest for {directory_name}/{relative_name} in .cargo-checksum.json"
                    ),
                )
                .package(&package.name)
                .path(format!("{directory_name}/{relative_name}")),
            );
            continue;
        }
        let actual = match paths::sha256_file(&file_path) {
            Ok(actual) => actual,
            Err(error) => {
                report.findings.push(
                    Finding::error(
                        "unreadable_file",
                        format!("cannot read {directory_name}/{relative_name}: {error:#}"),
                    )
                    .package(&package.name)
                    .path(format!("{directory_name}/{relative_name}")),
                );
                continue;
            }
        };
        report.file_count += 1;
        if !actual.eq_ignore_ascii_case(expected) {
            report.findings.push(
                Finding::error(
                    "modified_file",
                    format!(
                        "checksum mismatch for {directory_name}/{relative_name}: expected {expected}, got {actual}"
                    ),
                )
                .package(&package.name)
                .path(format!("{directory_name}/{relative_name}")),
            );
        }
    }

    let listed: BTreeSet<String> = checksum
        .files
        .keys()
        .map(|name| name.replace('\\', "/"))
        .collect();
    for entry in WalkDir::new(package_dir).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.findings.push(
                    Finding::error(
                        "unreadable_file",
                        format!("cannot walk {directory_name}: {error}"),
                    )
                    .package(&package.name),
                );
                continue;
            }
        };
        if entry.path() == package_dir {
            continue;
        }
        let relative = match entry.path().strip_prefix(package_dir) {
            Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if relative == ".cargo-checksum.json" {
            continue;
        }
        if entry.file_type().is_symlink() {
            report.findings.push(
                Finding::error(
                    "symlink_in_vendor",
                    format!("unexpected symbolic link {directory_name}/{relative}"),
                )
                .package(&package.name)
                .path(format!("{directory_name}/{relative}")),
            );
        } else if entry.file_type().is_file() && !listed.contains(&relative) {
            report.findings.push(
                Finding::error(
                    "unexpected_file",
                    format!(
                        "file {directory_name}/{relative} is not listed in .cargo-checksum.json"
                    ),
                )
                .package(&package.name)
                .path(format!("{directory_name}/{relative}")),
            );
        }
    }
    Ok(())
}

fn verify_package_manifest(
    package: &PackageRecord,
    package_dir: &Path,
    directory_name: &str,
    report: &mut VerificationReport,
) -> Result<()> {
    let manifest_path = package_dir.join("Cargo.toml");
    let bytes = match fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            report.findings.push(
                Finding::error(
                    "missing_file",
                    format!("{directory_name}/Cargo.toml is missing"),
                )
                .package(&package.name),
            );
            return Ok(());
        }
    };
    let manifest: ManifestPackage = match toml::from_str(&String::from_utf8_lossy(&bytes)) {
        Ok(manifest) => manifest,
        Err(error) => {
            report.findings.push(
                Finding::warning(
                    "unreadable_manifest",
                    format!("cannot parse {directory_name}/Cargo.toml: {error}"),
                )
                .package(&package.name),
            );
            return Ok(());
        }
    };
    if let Some(fields) = manifest.package {
        if let Some(name) = fields.name {
            if name != package.name {
                report.findings.push(
                    Finding::error(
                        "package_identity_mismatch",
                        format!(
                            "{directory_name}/Cargo.toml declares package `{name}`, expected `{}`",
                            package.name
                        ),
                    )
                    .package(&package.name),
                );
            }
        }
        if let Some(version) = fields.version {
            if version != package.version {
                report.findings.push(
                    Finding::error(
                        "package_identity_mismatch",
                        format!(
                            "{directory_name}/Cargo.toml declares version {version}, expected {}",
                            package.version
                        ),
                    )
                    .package(&package.name),
                );
            }
        }
    }
    Ok(())
}

fn find_lockfile(manifest_path: &Path) -> Option<PathBuf> {
    let mut current = manifest_path.parent()?;
    loop {
        let candidate = current.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = current.parent()?;
    }
}

/// Render a verification report for terminals.
pub fn render_text(report: &VerificationReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("Vendor: {}\n", report.vendor_dir));
    output.push_str(&format!("Metadata: {}\n", report.metadata_dir));
    output.push_str(&format!(
        "Packages: {}  Files: {}  Errors: {}  Warnings: {}\n",
        report.package_count, report.file_count, report.error_count, report.warning_count
    ));
    if report.findings.is_empty() {
        output.push_str("Result: OK\n");
        return output;
    }
    output.push_str(&format!(
        "Result: {}\n",
        if report.ok {
            "OK with warnings"
        } else {
            "FAILED"
        }
    ));
    for finding in &report.findings {
        let location = finding
            .package
            .as_ref()
            .map(|package| format!(" [{package}]"))
            .unwrap_or_default();
        output.push_str(&format!(
            "{:?} {}{}: {}\n",
            finding.severity, finding.code, location, finding.message
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PackageRecord, PACKAGES_SCHEMA_VERSION};
    use std::collections::BTreeMap;

    fn package(name: &str, version: &str) -> PackageRecord {
        PackageRecord {
            id: format!("registry+https://index.crates.io#{name}@{version}"),
            name: name.to_owned(),
            version: version.to_owned(),
            source: Some("registry+https://index.crates.io".to_owned()),
            source_kind: crate::source::SourceKind::Registry,
            registry: Some("https://index.crates.io".to_owned()),
            git: None,
            checksum: Some("11".repeat(32)),
            license: Some("MIT".to_owned()),
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

    fn write_metadata(dir: &Path, snapshot: &DependencySnapshot) {
        fs::create_dir_all(dir).expect("metadata dir");
        crate::paths::write_json(&dir.join("packages.json"), snapshot).expect("packages");
        crate::lockfile::write_checksum_file(
            &dir.join("lockfile.sha256"),
            snapshot.lockfile_sha256.as_deref().unwrap(),
            "Cargo.lock",
        )
        .expect("checksum");
        let git = GitSourcesFile::from_snapshot(snapshot);
        crate::paths::write_json(&dir.join("git-sources.json"), &git).expect("git");
        crate::paths::write_json(
            &dir.join("provenance.json"),
            &crate::model::ProvenanceFile {
                schema_version: crate::model::PROVENANCE_SCHEMA_VERSION,
                generator: crate::model::GeneratorInfo::default(),
                consumer: crate::model::ConsumerProvenance {
                    name: snapshot.consumer.clone(),
                    manifest_path: snapshot.manifest_path.clone(),
                    workspace_root_name: None,
                },
                generated_at_unix: 0,
                cargo_version: None,
                lockfile: crate::model::LockfileProvenance {
                    version: 4,
                    sha256: snapshot.lockfile_sha256.clone(),
                    file_name: "Cargo.lock".to_owned(),
                },
                vendor: None,
                artifacts: BTreeMap::new(),
            },
        )
        .expect("provenance");
        crate::paths::write_json(&dir.join("sbom.json"), &serde_json::json!({})).expect("sbom");
    }

    fn write_vendor_package(
        vendor: &Path,
        name: &str,
        version: &str,
        contents: &str,
        extra: Option<&str>,
    ) {
        let dir = vendor.join(format!("{name}-{version}"));
        fs::create_dir_all(dir.join("src")).expect("package dir");
        fs::write(dir.join("src/lib.rs"), contents).expect("lib");
        fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
        )
        .expect("manifest");
        let mut files = BTreeMap::new();
        files.insert(
            "src/lib.rs".to_owned(),
            paths::sha256_bytes(contents.as_bytes()),
        );
        files.insert(
            "Cargo.toml".to_owned(),
            paths::sha256_bytes(
                format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n").as_bytes(),
            ),
        );
        let checksum = serde_json::json!({
            "files": files,
            "package": "11".repeat(32),
        });
        fs::write(
            dir.join(".cargo-checksum.json"),
            serde_json::to_vec(&checksum).expect("json"),
        )
        .expect("checksum");
        if let Some(extra) = extra {
            fs::write(dir.join(extra), "extra").expect("extra");
        }
    }

    fn snapshot(packages: Vec<PackageRecord>) -> DependencySnapshot {
        DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: "Cargo.toml".to_owned(),
            lockfile_path: "Cargo.lock".to_owned(),
            lockfile_sha256: Some("ab".repeat(32)),
            package_count: packages.len(),
            packages,
        }
    }

    #[test]
    fn accepts_intact_vendor_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = dir.path().join("metadata");
        let vendor = dir.path().join("vendor");
        let snapshot = snapshot(vec![package("demo-dep", "1.0.0")]);
        write_metadata(&metadata, &snapshot);
        write_vendor_package(&vendor, "demo-dep", "1.0.0", "pub fn x() {}", None);

        let report = verify(&VerifyOptions {
            metadata_dir: metadata,
            vendor_dir: vendor,
            manifest_path: None,
            allow_lockfile_change: false,
        })
        .expect("verify");
        assert!(report.ok, "{}", render_text(&report));
        assert_eq!(report.package_count, 1);
        assert_eq!(report.file_count, 2);
    }

    #[test]
    fn detects_modified_source_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = dir.path().join("metadata");
        let vendor = dir.path().join("vendor");
        let snapshot = snapshot(vec![package("demo-dep", "1.0.0")]);
        write_metadata(&metadata, &snapshot);
        write_vendor_package(&vendor, "demo-dep", "1.0.0", "pub fn x() {}", None);
        fs::write(vendor.join("demo-dep-1.0.0/src/lib.rs"), "pub fn evil() {}").expect("modify");

        let report = verify(&VerifyOptions {
            metadata_dir: metadata,
            vendor_dir: vendor,
            manifest_path: None,
            allow_lockfile_change: false,
        })
        .expect("verify");
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "modified_file"));
    }

    #[test]
    fn detects_missing_and_unexpected_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = dir.path().join("metadata");
        let vendor = dir.path().join("vendor");
        let snapshot = snapshot(vec![package("demo-dep", "1.0.0")]);
        write_metadata(&metadata, &snapshot);
        fs::create_dir_all(vendor.join("stowaway-9.9.9")).expect("stowaway");

        let report = verify(&VerifyOptions {
            metadata_dir: metadata,
            vendor_dir: vendor,
            manifest_path: None,
            allow_lockfile_change: false,
        })
        .expect("verify");
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "missing_package"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "unexpected_package"));
    }

    #[test]
    fn detects_unexpected_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = dir.path().join("metadata");
        let vendor = dir.path().join("vendor");
        let snapshot = snapshot(vec![package("demo-dep", "1.0.0")]);
        write_metadata(&metadata, &snapshot);
        write_vendor_package(
            &vendor,
            "demo-dep",
            "1.0.0",
            "pub fn x() {}",
            Some("evil.sh"),
        );

        let report = verify(&VerifyOptions {
            metadata_dir: metadata,
            vendor_dir: vendor,
            manifest_path: None,
            allow_lockfile_change: false,
        })
        .expect("verify");
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "unexpected_file"));
    }

    #[test]
    fn missing_metadata_is_reported_without_repairing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = verify(&VerifyOptions {
            metadata_dir: dir.path().join("metadata"),
            vendor_dir: dir.path().join("vendor"),
            manifest_path: None,
            allow_lockfile_change: false,
        })
        .expect("verify");
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "missing_metadata"));
        assert!(!dir.path().join("metadata").exists());
    }
}
