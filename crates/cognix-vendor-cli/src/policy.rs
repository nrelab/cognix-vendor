//! License and source policy evaluation.
//!
//! Policy evaluation is local and deterministic. It never contacts a registry,
//! advisory database, or license service. `cargo audit` and `cargo deny` are
//! invoked separately by the audit command.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use crate::{
    model::{DependencySnapshot, PackageRecord},
    source::{is_crates_io, SourceKind},
    verify::Severity,
};

/// Current policy report schema.
pub const POLICY_SCHEMA_VERSION: u32 = 1;
/// Current policy file schema.
pub const POLICY_CONFIG_VERSION: u32 = 1;

/// All policy files for a repository.
#[derive(Debug, Clone, Default)]
pub struct Policies {
    /// License policy.
    pub licenses: LicensePolicy,
    /// Security/audit policy.
    pub security: SecurityPolicy,
    /// Source policy.
    pub sources: SourcePolicy,
    /// Policy files that existed and were parsed.
    pub loaded_files: Vec<PathBuf>,
}

/// License policy.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct LicensePolicy {
    /// Configuration schema version.
    pub version: u32,
    /// SPDX license identifiers or exception identifiers accepted for
    /// redistribution.
    pub allowed: Vec<String>,
    /// SPDX identifiers that are explicitly rejected.
    pub denied: Vec<String>,
    /// Reject packages without a license expression.
    pub deny_unknown: bool,
    /// Do not apply license policy to private workspace members.
    pub ignore_workspace: bool,
    /// Package names exempted from license policy, mapped to a review reason.
    pub exceptions: BTreeMap<String, String>,
}

impl Default for LicensePolicy {
    fn default() -> Self {
        Self {
            version: POLICY_CONFIG_VERSION,
            allowed: vec![
                "MIT".to_owned(),
                "Apache-2.0".to_owned(),
                "BSD-2-Clause".to_owned(),
                "BSD-3-Clause".to_owned(),
                "ISC".to_owned(),
            ],
            denied: Vec::new(),
            deny_unknown: true,
            ignore_workspace: true,
            exceptions: BTreeMap::new(),
        }
    }
}

/// Security/audit policy. This controls expectations, not audit execution.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SecurityPolicy {
    /// Configuration schema version.
    pub version: u32,
    /// Advisory-related expectations.
    pub advisories: AdvisoryPolicy,
}

/// Advisory expectations.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct AdvisoryPolicy {
    /// Whether advisory auditing is expected for this repository.
    pub enabled: bool,
    /// Whether `cargo audit` must be installed for `cognix-vendor audit`.
    pub require_cargo_audit: bool,
    /// Whether `cargo deny check` must be installed for `cognix-vendor audit`.
    pub require_cargo_deny: bool,
    /// Advisory identifiers documented as accepted risks.
    pub ignore: Vec<String>,
}

impl Default for AdvisoryPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            require_cargo_audit: false,
            require_cargo_deny: false,
            ignore: Vec::new(),
        }
    }
}

/// Source policy.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SourcePolicy {
    /// Configuration schema version.
    pub version: u32,
    /// Git source rules.
    pub git: GitPolicy,
    /// Registry source rules.
    pub registry: RegistryPolicy,
}

/// Git source rules.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct GitPolicy {
    /// Require Cargo to have recorded a resolved commit hash.
    pub require_locked_revision: bool,
    /// Allow branch, tag, or otherwise unpinned declarations.
    pub allow_unpinned: bool,
    /// Approved repository hosts. Empty means host checking is disabled.
    pub allowed_hosts: Vec<String>,
    /// Approved repository URLs. Empty means URL checking is disabled.
    pub allowed_repositories: Vec<String>,
}

impl Default for GitPolicy {
    fn default() -> Self {
        Self {
            require_locked_revision: true,
            allow_unpinned: false,
            allowed_hosts: Vec::new(),
            allowed_repositories: Vec::new(),
        }
    }
}

/// Registry source rules.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct RegistryPolicy {
    /// Allow crates.io.
    pub allow_crates_io: bool,
    /// Additional approved registry index URLs. Non-crates.io registries are
    /// rejected when this list is empty.
    pub allowed: Vec<String>,
}

impl Default for RegistryPolicy {
    fn default() -> Self {
        Self {
            allow_crates_io: true,
            allowed: Vec::new(),
        }
    }
}

/// A policy finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyFinding {
    /// Stable code.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Package name, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Explanation.
    pub message: String,
}

impl PolicyFinding {
    fn error(code: &str, package: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Error,
            package: package.map(str::to_owned),
            message: message.into(),
        }
    }

    fn warning(code: &str, package: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: Severity::Warning,
            package: package.map(str::to_owned),
            message: message.into(),
        }
    }
}

/// Results of evaluating policy against a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyReport {
    /// Schema version.
    pub schema_version: u32,
    /// Policy files loaded.
    pub loaded_files: Vec<String>,
    /// Findings, sorted.
    pub findings: Vec<PolicyFinding>,
    /// Count of license expressions.
    pub license_distribution: BTreeMap<String, usize>,
    /// Count of packages by source kind.
    pub source_distribution: BTreeMap<String, usize>,
    /// Error findings.
    pub error_count: usize,
    /// Warning findings.
    pub warning_count: usize,
    /// True when no error finding exists.
    pub ok: bool,
}

impl PolicyReport {
    /// Render a human-readable policy report.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Policy result: {}  Errors: {}  Warnings: {}\n",
            if self.ok { "OK" } else { "FAILED" },
            self.error_count,
            self.warning_count
        ));
        if !self.loaded_files.is_empty() {
            output.push_str(&format!("Policy files: {}\n", self.loaded_files.join(", ")));
        }
        for finding in &self.findings {
            let package = finding
                .package
                .as_ref()
                .map(|package| format!(" [{package}]"))
                .unwrap_or_default();
            output.push_str(&format!(
                "{:?} {}{}: {}\n",
                finding.severity, finding.code, package, finding.message
            ));
        }
        output
    }
}

impl Policies {
    /// Load policy files from `directory`, falling back to inline defaults.
    pub fn load(directory: &Path, config: &crate::config::ConfigPolicy) -> Result<Self> {
        let mut policies = Policies {
            licenses: LicensePolicy {
                allowed: config.allowed_licenses.clone(),
                deny_unknown: config.deny_unknown_licenses,
                ..LicensePolicy::default()
            },
            ..Policies::default()
        };

        let licenses_path = directory.join("licenses.toml");
        if licenses_path.is_file() {
            policies.licenses = read_policy(&licenses_path)?;
            policies.loaded_files.push(licenses_path);
        }
        let security_path = directory.join("security.toml");
        if security_path.is_file() {
            policies.security = read_policy(&security_path)?;
            policies.loaded_files.push(security_path);
        }
        let sources_path = directory.join("sources.toml");
        if sources_path.is_file() {
            policies.sources = read_policy(&sources_path)?;
            policies.loaded_files.push(sources_path);
        }
        Ok(policies)
    }

    /// Evaluate policies against a snapshot.
    pub fn evaluate(&self, snapshot: &DependencySnapshot) -> PolicyReport {
        let mut findings = Vec::new();
        let mut license_distribution: BTreeMap<String, usize> = BTreeMap::new();
        let mut source_distribution: BTreeMap<String, usize> = BTreeMap::new();

        for package in &snapshot.packages {
            *source_distribution
                .entry(package.source_kind.label().to_owned())
                .or_default() += 1;

            let license_key = package
                .license
                .clone()
                .unwrap_or_else(|| "UNKNOWN".to_owned());
            *license_distribution.entry(license_key).or_default() += 1;

            if package.is_workspace_member && self.licenses.ignore_workspace {
                continue;
            }
            if self.licenses.exceptions.contains_key(package.name.as_str()) {
                continue;
            }

            evaluate_license(&self.licenses, package, &mut findings);
            evaluate_source(&self.sources, package, &mut findings);
        }

        if self.licenses.deny_unknown {
            let unknown = snapshot
                .packages
                .iter()
                .filter(|package| {
                    !(package.is_workspace_member && self.licenses.ignore_workspace)
                        && package.license.is_none()
                        && !self.licenses.exceptions.contains_key(package.name.as_str())
                })
                .count();
            if unknown > 0 {
                findings.push(PolicyFinding::warning(
                    "license_unknown_summary",
                    None,
                    format!("{unknown} package(s) have no SPDX license expression"),
                ));
            }
        }

        if self.sources.git.allowed_hosts.is_empty() {
            findings.push(PolicyFinding::warning(
                "git_host_allowlist_empty",
                None,
                "sources.toml does not configure git.allowed_hosts; Git host allowlisting is disabled",
            ));
        }

        findings.sort();
        findings.dedup();
        let error_count = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .count();
        let warning_count = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Warning)
            .count();

        PolicyReport {
            schema_version: POLICY_SCHEMA_VERSION,
            loaded_files: self
                .loaded_files
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            findings,
            license_distribution,
            source_distribution,
            error_count,
            warning_count,
            ok: error_count == 0,
        }
    }
}

fn read_policy<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading policy {}", path.display()))?;
    toml::from_str(&contents).with_context(|| format!("parsing policy {}", path.display()))
}

fn evaluate_license(
    policy: &LicensePolicy,
    package: &PackageRecord,
    findings: &mut Vec<PolicyFinding>,
) {
    let Some(expression) = &package.license else {
        let code = if package.license_file.is_some() {
            "license_file_only"
        } else {
            "missing_license"
        };
        let message = if let Some(file) = &package.license_file {
            format!(
                "{} {} has no SPDX license expression; review license file {file} manually",
                package.name, package.version
            )
        } else {
            format!(
                "{} {} has no license metadata",
                package.name, package.version
            )
        };
        findings.push(if policy.deny_unknown {
            PolicyFinding::error(code, Some(&package.name), message)
        } else {
            PolicyFinding::warning(code, Some(&package.name), message)
        });
        return;
    };

    let alternatives = match license_alternatives(expression) {
        Ok(alternatives) => alternatives,
        Err(error) => {
            findings.push(PolicyFinding::error(
                "invalid_license_expression",
                Some(&package.name),
                format!(
                    "{} {} has an invalid SPDX license expression `{expression}`: {error}",
                    package.name, package.version
                ),
            ));
            return;
        }
    };

    let allowed_set: BTreeSet<&str> = policy
        .allowed
        .iter()
        .map(String::as_str)
        .chain(policy.exceptions.keys().map(String::as_str))
        .collect();
    let denied_set: BTreeSet<&str> = policy.denied.iter().map(String::as_str).collect();

    let mut accepted = false;
    let mut contains_denied = false;
    let mut unknown_terms: BTreeSet<String> = BTreeSet::new();

    for alternative in &alternatives {
        let mut alternative_ok = true;
        for term in alternative {
            if denied_set.contains(term.as_str()) {
                contains_denied = true;
                alternative_ok = false;
            } else if allowed_set.contains(term.as_str()) {
                // accepted
            } else {
                unknown_terms.insert(term.clone());
                if policy.deny_unknown {
                    alternative_ok = false;
                }
            }
        }
        if alternative_ok {
            accepted = true;
            break;
        }
    }

    if accepted {
        if !unknown_terms.is_empty() {
            findings.push(PolicyFinding::warning(
                "unknown_license_term",
                Some(&package.name),
                format!(
                    "{} {} includes terms not present in the allowlist: {}",
                    package.name,
                    package.version,
                    unknown_terms.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        return;
    }

    if contains_denied {
        findings.push(PolicyFinding::error(
            "license_denied",
            Some(&package.name),
            format!(
                "{} {} uses a denied license expression `{expression}`",
                package.name, package.version
            ),
        ));
    } else if !unknown_terms.is_empty() {
        findings.push(PolicyFinding::error(
            "unknown_license",
            Some(&package.name),
            format!(
                "{} {} uses license terms outside the allowlist: {}",
                package.name,
                package.version,
                unknown_terms.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    } else {
        findings.push(PolicyFinding::error(
            "license_not_allowed",
            Some(&package.name),
            format!(
                "{} {} uses license expression `{expression}`, which has no allowed alternative",
                package.name, package.version
            ),
        ));
    }
}

fn evaluate_source(
    policy: &SourcePolicy,
    package: &PackageRecord,
    findings: &mut Vec<PolicyFinding>,
) {
    match package.source_kind {
        SourceKind::Registry => {
            let registry = package.registry.as_deref().unwrap_or("");
            if is_crates_io(registry) {
                if !policy.registry.allow_crates_io {
                    findings.push(PolicyFinding::error(
                        "registry_not_allowed",
                        Some(&package.name),
                        format!(
                            "{} {} comes from crates.io, which is disabled by policy",
                            package.name, package.version
                        ),
                    ));
                }
            } else if !policy
                .registry
                .allowed
                .iter()
                .any(|allowed| allowed == registry)
            {
                findings.push(PolicyFinding::error(
                    "registry_not_allowed",
                    Some(&package.name),
                    format!(
                        "{} {} comes from unapproved registry {registry}",
                        package.name, package.version
                    ),
                ));
            }
        }
        SourceKind::Git => {
            let Some(git) = &package.git else {
                findings.push(PolicyFinding::error(
                    "git_source_missing",
                    Some(&package.name),
                    format!(
                        "{} {} is classified as a Git package but has no parsed Git source",
                        package.name, package.version
                    ),
                ));
                return;
            };
            if !policy.git.allowed_hosts.is_empty() {
                let host = git.host().unwrap_or_default();
                if !policy
                    .git
                    .allowed_hosts
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(&host))
                {
                    findings.push(PolicyFinding::error(
                        "unapproved_git_host",
                        Some(&package.name),
                        format!(
                            "{} {} comes from unapproved Git host `{host}` ({})",
                            package.name, package.version, git.url
                        ),
                    ));
                }
            }
            if !policy.git.allowed_repositories.is_empty()
                && !policy
                    .git
                    .allowed_repositories
                    .iter()
                    .any(|allowed| allowed == &git.url)
            {
                findings.push(PolicyFinding::error(
                    "unapproved_git_source",
                    Some(&package.name),
                    format!(
                        "{} {} comes from unapproved Git repository {}",
                        package.name, package.version, git.url
                    ),
                ));
            }
            if !policy.git.allow_unpinned && !git.pinned {
                findings.push(PolicyFinding::error(
                    "unpinned_git_dependency",
                    Some(&package.name),
                    format!(
                        "{} {} uses {} instead of an exact `rev`",
                        package.name,
                        package.version,
                        git.reference_label()
                    ),
                ));
            }
            if policy.git.require_locked_revision && !git.has_resolved_revision() {
                findings.push(PolicyFinding::error(
                    "unresolved_git_revision",
                    Some(&package.name),
                    format!(
                        "{} {} has no Cargo-resolved commit hash",
                        package.name, package.version
                    ),
                ));
            }
        }
        SourceKind::Workspace | SourceKind::Path | SourceKind::Unknown => {}
    }
}

/// Parse an SPDX license expression into alternative sets of required terms.
///
/// `MIT OR Apache-2.0` yields two alternatives. `MIT AND Apache-2.0` yields one
/// alternative containing both terms. `Apache-2.0 WITH LLVM-exception` yields
/// one alternative containing both the license and the exception.
pub fn license_alternatives(
    expression: &str,
) -> std::result::Result<Vec<BTreeSet<String>>, String> {
    let tokens = tokenize(expression)?;
    let mut parser = Parser {
        tokens,
        position: 0,
    };
    let alternatives = parser.parse_or()?;
    if parser.position != parser.tokens.len() {
        return Err(format!(
            "unexpected token `{}`",
            parser.tokens[parser.position].display()
        ));
    }
    if alternatives.is_empty() {
        return Err("empty expression".to_owned());
    }
    Ok(alternatives)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Identifier(String),
    And,
    Or,
    With,
    Open,
    Close,
}

impl Token {
    fn display(&self) -> String {
        match self {
            Self::Identifier(value) => value.clone(),
            Self::And => "AND".to_owned(),
            Self::Or => "OR".to_owned(),
            Self::With => "WITH".to_owned(),
            Self::Open => "(".to_owned(),
            Self::Close => ")".to_owned(),
        }
    }
}

fn tokenize(expression: &str) -> std::result::Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = expression.char_indices().peekable();
    while let Some((_, character)) = chars.peek().copied() {
        if character.is_whitespace() {
            chars.next();
            continue;
        }
        match character {
            '(' => {
                chars.next();
                tokens.push(Token::Open);
            }
            ')' => {
                chars.next();
                tokens.push(Token::Close);
            }
            _ if is_identifier_char(character) => {
                let start = chars.peek().map(|(index, _)| *index).unwrap_or(0);
                let mut end = start;
                while let Some((index, character)) = chars.peek().copied() {
                    if !is_identifier_char(character) {
                        break;
                    }
                    end = index + character.len_utf8();
                    chars.next();
                }
                let identifier = &expression[start..end];
                tokens.push(match identifier.to_ascii_uppercase().as_str() {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "WITH" => Token::With,
                    _ => Token::Identifier(identifier.to_owned()),
                });
            }
            _ => return Err(format!("invalid character `{character}`")),
        }
    }
    Ok(tokens)
}

fn is_identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+' | '_' | ':')
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn parse_or(&mut self) -> std::result::Result<Vec<BTreeSet<String>>, String> {
        let mut alternatives = self.parse_and()?;
        while self.peek() == Some(&Token::Or) {
            self.position += 1;
            alternatives.extend(self.parse_and()?);
        }
        Ok(deduplicate(alternatives))
    }

    fn parse_and(&mut self) -> std::result::Result<Vec<BTreeSet<String>>, String> {
        let mut alternatives = self.parse_factor()?;
        while self.peek() == Some(&Token::And) {
            self.position += 1;
            let right = self.parse_factor()?;
            alternatives = combine_and(alternatives, right);
        }
        Ok(alternatives)
    }

    fn parse_factor(&mut self) -> std::result::Result<Vec<BTreeSet<String>>, String> {
        let mut alternatives = match self.next() {
            Some(Token::Open) => {
                let alternatives = self.parse_or()?;
                match self.next() {
                    Some(Token::Close) => alternatives,
                    _ => return Err("missing closing parenthesis".to_owned()),
                }
            }
            Some(Token::Identifier(identifier)) => {
                vec![BTreeSet::from([identifier])]
            }
            Some(token) => return Err(format!("unexpected token `{}`", token.display())),
            None => return Err("unexpected end of expression".to_owned()),
        };

        if self.peek() == Some(&Token::With) {
            self.position += 1;
            let exception = match self.next() {
                Some(Token::Identifier(identifier)) => identifier,
                Some(token) => {
                    return Err(format!("unexpected token `{}` after WITH", token.display()))
                }
                None => return Err("missing exception after WITH".to_owned()),
            };
            for alternative in &mut alternatives {
                alternative.insert(exception.clone());
            }
        }
        Ok(alternatives)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }
}

fn combine_and(left: Vec<BTreeSet<String>>, right: Vec<BTreeSet<String>>) -> Vec<BTreeSet<String>> {
    let mut combined = Vec::new();
    for left_alternative in &left {
        for right_alternative in &right {
            let mut alternative = left_alternative.clone();
            alternative.extend(right_alternative.iter().cloned());
            combined.push(alternative);
        }
    }
    deduplicate(combined)
}

fn deduplicate(alternatives: Vec<BTreeSet<String>>) -> Vec<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    alternatives
        .into_iter()
        .filter(|alternative| seen.insert(alternative.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PackageRecord, PACKAGES_SCHEMA_VERSION};
    use crate::source::GitSourceRef;
    use std::collections::BTreeMap;

    fn package(name: &str, license: Option<&str>) -> PackageRecord {
        PackageRecord {
            id: name.to_owned(),
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

    fn snapshot(packages: Vec<PackageRecord>) -> DependencySnapshot {
        DependencySnapshot {
            schema_version: PACKAGES_SCHEMA_VERSION,
            consumer: "demo".to_owned(),
            manifest_path: String::new(),
            lockfile_path: String::new(),
            lockfile_sha256: None,
            package_count: packages.len(),
            packages,
        }
    }

    #[test]
    fn parses_or_expressions() {
        let alternatives = license_alternatives("MIT OR Apache-2.0").expect("parse");
        assert_eq!(alternatives.len(), 2);
        assert!(alternatives.contains(&BTreeSet::from(["MIT".to_owned()])));
    }

    #[test]
    fn parses_and_with_parentheses() {
        let alternatives =
            license_alternatives("(MIT AND Apache-2.0) OR BSD-3-Clause").expect("parse");
        assert_eq!(alternatives.len(), 2);
        assert!(alternatives.contains(&BTreeSet::from(["MIT".to_owned(), "Apache-2.0".to_owned()])));
    }

    #[test]
    fn parses_with_exception() {
        let alternatives = license_alternatives("Apache-2.0 WITH LLVM-exception").expect("parse");
        assert_eq!(
            alternatives[0],
            BTreeSet::from(["Apache-2.0".to_owned(), "LLVM-exception".to_owned()])
        );
    }

    #[test]
    fn rejects_malformed_expressions() {
        assert!(license_alternatives("MIT AND").is_err());
        assert!(license_alternatives("(MIT").is_err());
        assert!(license_alternatives("MIT / Apache-2.0").is_err());
    }

    #[test]
    fn or_expression_is_allowed_when_one_alternative_is_allowed() {
        let policies = Policies {
            licenses: LicensePolicy {
                allowed: vec!["MIT".to_owned()],
                ..LicensePolicy::default()
            },
            ..Policies::default()
        };
        let report = policies.evaluate(&snapshot(vec![package(
            "dual",
            Some("MIT OR GPL-3.0-only"),
        )]));
        assert!(report.ok, "{:?}", report.findings);
    }

    #[test]
    fn and_expression_requires_all_terms() {
        let policies = Policies {
            licenses: LicensePolicy {
                allowed: vec!["MIT".to_owned()],
                ..LicensePolicy::default()
            },
            ..Policies::default()
        };
        let report = policies.evaluate(&snapshot(vec![package(
            "both",
            Some("MIT AND GPL-3.0-only"),
        )]));
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "unknown_license"));
    }

    #[test]
    fn denied_license_is_reported() {
        let policies = Policies {
            licenses: LicensePolicy {
                allowed: vec!["MIT".to_owned()],
                denied: vec!["GPL-3.0-only".to_owned()],
                ..LicensePolicy::default()
            },
            ..Policies::default()
        };
        let report = policies.evaluate(&snapshot(vec![package("gpl", Some("GPL-3.0-only"))]));
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "license_denied"));
    }

    #[test]
    fn missing_license_is_reported_when_deny_unknown() {
        let policies = Policies::default();
        let report = policies.evaluate(&snapshot(vec![package("unknown", None)]));
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "missing_license"));
    }

    #[test]
    fn unpinned_git_dependency_is_reported() {
        let mut package = package("tink", Some("MIT"));
        package.source = Some("git+https://github.com/example/repo?branch=main#abc".to_owned());
        package.source_kind = SourceKind::Git;
        package.registry = None;
        package.git = Some(GitSourceRef {
            url: "https://github.com/example/repo".to_owned(),
            branch: Some("main".to_owned()),
            resolved_revision: Some("abc".to_owned()),
            pinned: false,
            ..GitSourceRef::default()
        });
        let policies = Policies::default();
        let report = policies.evaluate(&snapshot(vec![package]));
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "unpinned_git_dependency"));
    }

    #[test]
    fn unapproved_git_host_is_reported() {
        let mut package = package("dep", Some("MIT"));
        package.source_kind = SourceKind::Git;
        package.registry = None;
        package.git = Some(GitSourceRef {
            url: "https://gitlab.com/owner/repo".to_owned(),
            rev: Some("abc".to_owned()),
            resolved_revision: Some("abc".to_owned()),
            pinned: true,
            ..GitSourceRef::default()
        });
        let policies = Policies {
            sources: SourcePolicy {
                git: GitPolicy {
                    allowed_hosts: vec!["github.com".to_owned()],
                    ..GitPolicy::default()
                },
                ..SourcePolicy::default()
            },
            ..Policies::default()
        };
        let report = policies.evaluate(&snapshot(vec![package]));
        assert!(!report.ok);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "unapproved_git_host"));
    }

    #[test]
    fn policy_files_load_from_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("licenses.toml"),
            "allowed = [\"MIT\"]\ndeny_unknown = true\n",
        )
        .expect("license");
        let policies =
            Policies::load(dir.path(), &crate::config::ConfigPolicy::default()).expect("load");
        assert_eq!(policies.licenses.allowed, vec!["MIT".to_owned()]);
        assert_eq!(policies.loaded_files.len(), 1);
    }
}
