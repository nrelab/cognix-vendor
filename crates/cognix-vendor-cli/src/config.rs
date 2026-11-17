//! Repository configuration and path resolution.
//!
//! Relative paths in `cognix-vendor.toml` are resolved from the configuration
//! file's directory. Command-line overrides are resolved from the current
//! working directory, matching normal CLI expectations.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use crate::paths::{absolute_path, resolve_against};

/// Repository configuration, mirroring `cognix-vendor.toml`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct VendorConfig {
    /// Repository identity.
    pub repository: RepositoryConfig,
    /// Named consumer workspaces.
    pub consumer: BTreeMap<String, ConsumerConfig>,
    /// Inline policy defaults. File-based policies take precedence.
    pub policy: ConfigPolicy,
}

/// Repository identity.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct RepositoryConfig {
    /// Repository name.
    pub name: String,
    /// Configuration format version.
    pub version: u32,
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self {
            name: "cognix-vendor".to_owned(),
            version: 1,
        }
    }
}

/// Per-consumer paths.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConsumerConfig {
    /// Consumer Cargo manifest.
    pub manifest_path: Option<PathBuf>,
    /// Directory for generated metadata.
    pub metadata_dir: Option<PathBuf>,
    /// Cargo vendor output directory.
    pub vendor_dir: Option<PathBuf>,
    /// Generated Cargo source-replacement configuration.
    pub config_output: Option<PathBuf>,
    /// Directory containing policy TOML files.
    pub policy_dir: Option<PathBuf>,
}

/// Inline policy defaults from the repository configuration.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConfigPolicy {
    /// License expressions considered acceptable.
    pub allowed_licenses: Vec<String>,
    /// Whether an unknown or missing license is a violation.
    pub deny_unknown_licenses: bool,
}

impl Default for ConfigPolicy {
    fn default() -> Self {
        Self {
            allowed_licenses: vec![
                "MIT".to_owned(),
                "Apache-2.0".to_owned(),
                "BSD-2-Clause".to_owned(),
                "BSD-3-Clause".to_owned(),
                "ISC".to_owned(),
            ],
            deny_unknown_licenses: true,
        }
    }
}

/// Loaded configuration plus the directory used to resolve relative paths.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// Configuration file path (may not exist).
    pub path: PathBuf,
    /// Repository root: the configuration file's directory.
    pub root: PathBuf,
    /// Parsed configuration.
    pub config: VendorConfig,
    /// Whether the configuration file existed.
    pub exists: bool,
}

/// CLI overrides for consumer paths.
#[derive(Debug, Clone, Default)]
pub struct PathOverrides {
    /// Consumer manifest.
    pub manifest_path: Option<PathBuf>,
    /// Metadata directory.
    pub metadata_dir: Option<PathBuf>,
    /// Vendor directory.
    pub vendor_dir: Option<PathBuf>,
    /// Generated source configuration.
    pub config_output: Option<PathBuf>,
    /// Policy directory.
    pub policy_dir: Option<PathBuf>,
}

/// Fully resolved paths for one consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConsumer {
    /// Consumer name.
    pub name: String,
    /// Repository root.
    pub root: PathBuf,
    /// Consumer manifest.
    pub manifest_path: PathBuf,
    /// Metadata directory.
    pub metadata_dir: PathBuf,
    /// Vendor directory.
    pub vendor_dir: PathBuf,
    /// Generated Cargo source config.
    pub config_output: PathBuf,
    /// Policy directory.
    pub policy_dir: PathBuf,
}

impl ResolvedConsumer {
    /// `metadata/<consumer>/packages.json`.
    pub fn packages_path(&self) -> PathBuf {
        self.metadata_dir.join("packages.json")
    }

    /// `metadata/<consumer>/git-sources.json`.
    pub fn git_sources_path(&self) -> PathBuf {
        self.metadata_dir.join("git-sources.json")
    }

    /// `metadata/<consumer>/provenance.json`.
    pub fn provenance_path(&self) -> PathBuf {
        self.metadata_dir.join("provenance.json")
    }

    /// `metadata/<consumer>/lockfile.sha256`.
    pub fn lockfile_checksum_path(&self) -> PathBuf {
        self.metadata_dir.join("lockfile.sha256")
    }

    /// `metadata/<consumer>/sbom.json`.
    pub fn sbom_path(&self) -> PathBuf {
        self.metadata_dir.join("sbom.json")
    }

    /// Default licenses policy path.
    pub fn licenses_policy_path(&self) -> PathBuf {
        self.policy_dir.join("licenses.toml")
    }

    /// Default security policy path.
    pub fn security_policy_path(&self) -> PathBuf {
        self.policy_dir.join("security.toml")
    }

    /// Default sources policy path.
    pub fn sources_policy_path(&self) -> PathBuf {
        self.policy_dir.join("sources.toml")
    }
}

impl LoadedConfig {
    /// Load configuration from `path`, falling back to defaults when absent.
    pub fn load(path: &Path) -> Result<Self> {
        let path = absolute_path(path)?;
        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.clone());

        if !path.is_file() {
            return Ok(Self {
                path,
                root,
                config: VendorConfig::default(),
                exists: false,
            });
        }

        let contents = fs::read_to_string(&path)
            .with_context(|| format!("reading configuration {}", path.display()))?;
        let config: VendorConfig = toml::from_str(&contents)
            .with_context(|| format!("parsing configuration {}", path.display()))?;
        Ok(Self {
            path,
            root,
            config,
            exists: true,
        })
    }

    /// Resolve all paths for a consumer.
    pub fn resolve(
        &self,
        name: &str,
        overrides: &PathOverrides,
        current_dir: &Path,
    ) -> Result<ResolvedConsumer> {
        let consumer = self.config.consumer.get(name);
        if consumer.is_none() && !self.config.consumer.is_empty() {
            let configured = self
                .config
                .consumer
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            bail!("unknown consumer `{name}`; configured consumers: {configured}");
        }
        let consumer = consumer.cloned().unwrap_or_default();

        let manifest_path = match &overrides.manifest_path {
            Some(path) => resolve_against(current_dir, path),
            None => match consumer.manifest_path {
                Some(path) if resolve_against(&self.root, &path).is_file() => {
                    resolve_against(&self.root, &path)
                }
                Some(path) => {
                    let configured = resolve_against(&self.root, &path);
                    detect_manifest(&self.root)
                        .filter(|detected| *detected != configured)
                        .unwrap_or(configured)
                }
                None => detect_manifest(&self.root).unwrap_or_else(|| {
                    resolve_against(&self.root, Path::new("../cognix/Cargo.toml"))
                }),
            },
        };

        Ok(ResolvedConsumer {
            name: name.to_owned(),
            root: self.root.clone(),
            manifest_path,
            metadata_dir: resolve_path(
                &self.root,
                current_dir,
                overrides.metadata_dir.as_ref(),
                consumer.metadata_dir.as_ref(),
                &format!("metadata/{name}"),
            ),
            vendor_dir: resolve_path(
                &self.root,
                current_dir,
                overrides.vendor_dir.as_ref(),
                consumer.vendor_dir.as_ref(),
                "vendor",
            ),
            config_output: resolve_path(
                &self.root,
                current_dir,
                overrides.config_output.as_ref(),
                consumer.config_output.as_ref(),
                &format!("config/{name}-source-replacement.toml"),
            ),
            policy_dir: resolve_path(
                &self.root,
                current_dir,
                overrides.policy_dir.as_ref(),
                consumer.policy_dir.as_ref(),
                "metadata/policies",
            ),
        })
    }
}

fn resolve_path(
    root: &Path,
    current_dir: &Path,
    override_path: Option<&PathBuf>,
    configured: Option<&PathBuf>,
    default: &str,
) -> PathBuf {
    match (override_path, configured) {
        (Some(path), _) => resolve_against(current_dir, path),
        (None, Some(path)) => resolve_against(root, path),
        (None, None) => resolve_against(root, Path::new(default)),
    }
}

fn detect_manifest(root: &Path) -> Option<PathBuf> {
    let candidates = [
        resolve_against(root, Path::new("../cognix/Cargo.toml")),
        resolve_against(root, Path::new("../Cargo.toml")),
        resolve_against(root, Path::new("Cargo.toml")),
    ];
    candidates.into_iter().find(|candidate| candidate.is_file())
}

/// Serialize a configuration template used by `init`.
pub fn default_config_toml() -> Result<String> {
    let config = VendorConfig {
        repository: RepositoryConfig::default(),
        consumer: BTreeMap::from([(
            "cognix".to_owned(),
            ConsumerConfig {
                manifest_path: Some(PathBuf::from("../cognix/Cargo.toml")),
                metadata_dir: Some(PathBuf::from("metadata/cognix")),
                vendor_dir: Some(PathBuf::from("vendor")),
                config_output: Some(PathBuf::from("config/cognix-source-replacement.toml")),
                policy_dir: Some(PathBuf::from("metadata/policies")),
            },
        )]),
        policy: ConfigPolicy::default(),
    };
    let mut rendered = toml::to_string_pretty(&config)?;
    rendered.insert_str(
        0,
        "# Cognix Vendor repository configuration.\n\
         # Relative paths are resolved from this file's directory.\n\
         # If ../cognix/Cargo.toml does not exist, the CLI auto-detects\n\
         # ../Cargo.toml or ./Cargo.toml before reporting an error.\n\n",
    );
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_uses_defaults_and_detects_manifest() {
        let workspace = tempfile::tempdir().expect("workspace");
        let repo = workspace.path().join("cognix-vendor");
        fs::create_dir_all(&repo).expect("repo");
        fs::write(
            workspace.path().join("Cargo.toml"),
            "[workspace]\nmembers = []\n",
        )
        .expect("manifest");
        fs::create_dir_all(workspace.path().join("metadata")).expect("metadata");

        let loaded = LoadedConfig::load(&repo.join("cognix-vendor.toml")).expect("load");
        assert!(!loaded.exists);
        let resolved = loaded
            .resolve("cognix", &PathOverrides::default(), &repo)
            .expect("resolve");
        assert_eq!(resolved.manifest_path, workspace.path().join("Cargo.toml"));
        assert_eq!(resolved.metadata_dir, repo.join("metadata/cognix"));
        assert_eq!(resolved.vendor_dir, repo.join("vendor"));
    }

    #[test]
    fn parses_existing_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cognix-vendor.toml");
        fs::write(
            &path,
            r#"
[repository]
name = "test"
version = 1

[consumer.demo]
manifest_path = "../demo/Cargo.toml"
metadata_dir = "meta"
vendor_dir = "vendor"
config_output = "config.toml"

[policy]
allowed_licenses = ["MIT"]
deny_unknown_licenses = false
"#,
        )
        .expect("write");

        let loaded = LoadedConfig::load(&path).expect("load");
        assert!(loaded.exists);
        assert_eq!(loaded.config.repository.name, "test");
        let resolved = loaded
            .resolve("demo", &PathOverrides::default(), dir.path())
            .expect("resolve");
        assert_eq!(
            resolved.manifest_path,
            resolve_against(dir.path(), Path::new("../demo/Cargo.toml"))
        );
        assert_eq!(resolved.metadata_dir, dir.path().join("meta"));
        assert_eq!(resolved.config_output, dir.path().join("config.toml"));
    }

    #[test]
    fn rejects_unknown_consumer_when_others_are_configured() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cognix-vendor.toml");
        fs::write(
            &path,
            "[consumer.demo]\nmanifest_path = \"../demo/Cargo.toml\"\n",
        )
        .expect("write");
        let loaded = LoadedConfig::load(&path).expect("load");
        let error = loaded
            .resolve("other", &PathOverrides::default(), dir.path())
            .expect_err("must reject");
        assert!(error.to_string().contains("unknown consumer"));
    }

    #[test]
    fn cli_overrides_are_relative_to_current_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let loaded = LoadedConfig::load(&dir.path().join("missing.toml")).expect("load");
        let overrides = PathOverrides {
            manifest_path: Some(PathBuf::from("some/Cargo.toml")),
            ..PathOverrides::default()
        };
        let resolved = loaded
            .resolve("demo", &overrides, dir.path())
            .expect("resolve");
        assert_eq!(resolved.manifest_path, dir.path().join("some/Cargo.toml"));
    }

    #[test]
    fn template_is_valid_toml() {
        let rendered = default_config_toml().expect("render");
        let parsed: VendorConfig = toml::from_str(&rendered).expect("parse");
        assert_eq!(parsed.repository.version, 1);
        assert!(parsed.consumer.contains_key("cognix"));
    }
}
