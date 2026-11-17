//! CycloneDX SBOM generation.
//!
//! The SBOM is intentionally deterministic: it contains no generation
//! timestamp or absolute paths so it can be committed and compared in CI.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    model::{DependencySnapshot, PackageRecord},
    source::SourceKind,
};

/// Generate a CycloneDX 1.5 JSON SBOM.
pub fn build_sbom(snapshot: &DependencySnapshot) -> Result<Sbom> {
    let mut components: Vec<SbomComponent> = snapshot
        .packages
        .iter()
        .map(component_from_package)
        .collect();
    components.sort_by(|left, right| left.bom_ref.cmp(&right.bom_ref));

    Ok(Sbom {
        bom_format: "CycloneDX".to_owned(),
        spec_version: "1.5".to_owned(),
        version: 1,
        metadata: SbomMetadata {
            component: SbomComponent {
                component_type: "application".to_owned(),
                bom_ref: format!("workspace#{}", snapshot.consumer),
                name: snapshot.consumer.clone(),
                version: None,
                purl: None,
                scope: Some("required".to_owned()),
                hashes: Vec::new(),
                licenses: Vec::new(),
                external_references: Vec::new(),
            },
            tools: vec![SbomTool {
                vendor: "nrelab".to_owned(),
                name: "cognix-vendor".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }],
        },
        components,
    })
}

/// CycloneDX document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sbom {
    /// Always `CycloneDX`.
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    /// CycloneDX specification version.
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    /// Document version.
    pub version: u32,
    /// Document metadata.
    pub metadata: SbomMetadata,
    /// Package components.
    pub components: Vec<SbomComponent>,
}

/// CycloneDX metadata section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomMetadata {
    /// The consumer workspace.
    pub component: SbomComponent,
    /// Tools that produced the document.
    pub tools: Vec<SbomTool>,
}

/// Tool identity in the SBOM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomTool {
    /// Tool vendor.
    pub vendor: String,
    /// Tool name.
    pub name: String,
    /// Tool version.
    pub version: String,
}

/// CycloneDX component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomComponent {
    /// CycloneDX component type.
    #[serde(rename = "type")]
    pub component_type: String,
    /// Stable reference.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Package name.
    pub name: String,
    /// Package version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Package URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// Dependency scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Hash entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<SbomHash>,
    /// License entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<SbomLicense>,
    /// External references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "externalReferences")]
    pub external_references: Vec<SbomExternalReference>,
}

/// CycloneDX hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomHash {
    /// Hash algorithm.
    pub alg: String,
    /// Lower-case hex digest.
    pub content: String,
}

/// CycloneDX license choice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomLicense {
    /// License object.
    pub license: SbomLicenseValue,
}

/// CycloneDX license value: an expression or a named license.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomLicenseValue {
    /// SPDX expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    /// License name when no valid expression is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// CycloneDX external reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomExternalReference {
    /// Reference type.
    #[serde(rename = "type")]
    pub reference_type: String,
    /// URL.
    pub url: String,
}

fn component_from_package(package: &PackageRecord) -> SbomComponent {
    let component_type = if package.is_workspace_member {
        "application"
    } else {
        "library"
    };
    let purl = match package.source_kind {
        SourceKind::Registry => Some(format!("pkg:cargo/{}@{}", package.name, package.version)),
        SourceKind::Git => package.git.as_ref().map(|git| {
            format!(
                "pkg:cargo/{}@{}?vcs_url={}",
                package.name,
                package.version,
                percent_encode(&git.url)
            )
        }),
        _ => None,
    };
    let hashes = package
        .checksum
        .as_ref()
        .filter(|checksum| checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|checksum| {
            vec![SbomHash {
                alg: "SHA-256".to_owned(),
                content: checksum.to_ascii_lowercase(),
            }]
        })
        .unwrap_or_default();

    let licenses = package
        .license
        .as_ref()
        .map(|expression| {
            vec![SbomLicense {
                license: SbomLicenseValue {
                    expression: Some(expression.clone()),
                    name: None,
                },
            }]
        })
        .or_else(|| {
            package.license_file.as_ref().map(|file| {
                vec![SbomLicense {
                    license: SbomLicenseValue {
                        expression: None,
                        name: Some(format!("license file: {file}")),
                    },
                }]
            })
        })
        .unwrap_or_default();

    let external_references = package
        .repository
        .as_ref()
        .map(|url| {
            vec![SbomExternalReference {
                reference_type: "vcs".to_owned(),
                url: url.clone(),
            }]
        })
        .unwrap_or_default();

    SbomComponent {
        component_type: component_type.to_owned(),
        bom_ref: package.id.clone(),
        name: package.name.clone(),
        version: Some(package.version.clone()),
        purl,
        scope: (!package.is_workspace_member).then(|| "required".to_owned()),
        hashes,
        licenses,
        external_references,
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DependencySnapshot, PackageRecord, PACKAGES_SCHEMA_VERSION};
    use std::collections::BTreeMap;

    fn package(name: &str, license: Option<&str>, checksum: Option<&str>) -> PackageRecord {
        PackageRecord {
            id: format!("registry+https://index.crates.io#{name}@1.0.0"),
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: Some("registry+https://index.crates.io".to_owned()),
            source_kind: SourceKind::Registry,
            registry: Some("https://index.crates.io".to_owned()),
            git: None,
            checksum: checksum.map(str::to_owned),
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

    #[test]
    fn builds_deterministic_components() {
        let snapshot = DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: "Cargo.toml".to_owned(),
            lockfile_path: "Cargo.lock".to_owned(),
            lockfile_sha256: None,
            package_count: 2,
            packages: vec![
                package("zeta", Some("MIT"), None),
                package("alpha", Some("Apache-2.0"), Some(&"ab".repeat(32))),
            ],
        };
        let sbom = build_sbom(&snapshot).expect("sbom");
        assert_eq!(sbom.spec_version, "1.5");
        assert_eq!(sbom.components[0].name, "alpha");
        assert_eq!(sbom.components[0].hashes[0].alg, "SHA-256");
        assert_eq!(sbom.components[1].name, "zeta");
        assert!(sbom.components[1].hashes.is_empty());
        let json = serde_json::to_string(&sbom).expect("serialize");
        assert!(json.contains("\"bomFormat\":\"CycloneDX\""));
        assert!(!json.contains("generated_at"));
    }

    #[test]
    fn percent_encodes_purl_parameters() {
        assert_eq!(
            percent_encode("https://github.com/a/b"),
            "https://github.com/a/b"
        );
        assert_eq!(percent_encode("a b"), "a%20b");
    }
}
