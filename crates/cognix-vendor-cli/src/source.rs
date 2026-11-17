//! Parsing of Cargo package source identifiers.
//!
//! Cargo records sources in several related forms:
//!
//! * `registry+https://github.com/rust-lang/crates.io-index`
//! * `sparse+https://index.crates.io/`
//! * `git+https://github.com/owner/repo?rev=<sha>#<resolved-sha>`
//! * `path+file:///absolute/path`
//!
//! This module turns those opaque strings into stable, serializable records.
//! It does not query registries or Git remotes.

use serde::{Deserialize, Serialize};

/// Where a resolved package came from.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A crates.io or alternative registry package.
    Registry,
    /// A Git dependency.
    Git,
    /// A local path outside the workspace.
    Path,
    /// A member of the consumer's own workspace.
    Workspace,
    /// A source form this tool does not recognize.
    #[default]
    Unknown,
}

impl SourceKind {
    /// Human-readable label for reports.
    pub fn label(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Git => "git",
            Self::Path => "path",
            Self::Workspace => "workspace",
            Self::Unknown => "unknown",
        }
    }

    /// True when Cargo vendors packages from this source into `vendor/`.
    pub fn is_vendorable(self) -> bool {
        matches!(self, Self::Registry | Self::Git)
    }
}

/// A parsed Git dependency source.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitSourceRef {
    /// Repository URL without the Cargo `git+` prefix or query/fragment.
    pub url: String,
    /// Exact revision requested with `rev = "..."` in the consumer manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    /// Branch requested with `branch = "..."` in the consumer manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Tag requested with `tag = "..."` in the consumer manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Commit hash Cargo resolved and recorded after `#` in the lockfile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_revision: Option<String>,
    /// True only when the consumer declared an exact `rev`, which is the
    /// strongest pinning mechanism available for Git dependencies.
    #[serde(default)]
    pub pinned: bool,
}

impl GitSourceRef {
    /// A short description of the declared reference, e.g. `rev abc1234`.
    pub fn reference_label(&self) -> String {
        if let Some(rev) = &self.rev {
            format!("rev {rev}")
        } else if let Some(branch) = &self.branch {
            format!("branch {branch}")
        } else if let Some(tag) = &self.tag {
            format!("tag {tag}")
        } else if let Some(rev) = &self.resolved_revision {
            format!("resolved {rev}")
        } else {
            "unpinned".to_owned()
        }
    }

    /// True when Cargo recorded a concrete commit hash.
    pub fn has_resolved_revision(&self) -> bool {
        self.resolved_revision
            .as_deref()
            .is_some_and(|revision| !revision.is_empty())
    }

    /// Host portion of the repository URL, if it can be determined.
    pub fn host(&self) -> Option<String> {
        url_host(&self.url)
    }
}

/// Result of parsing a Cargo source string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedSource {
    /// Registry source with its index URL.
    Registry { url: String },
    /// Git source.
    Git(GitSourceRef),
    /// Local path source.
    Path { url: Option<String> },
    /// Unknown or empty source.
    Unknown { raw: String },
}

impl ParsedSource {
    /// Classify the source.
    pub fn kind(&self) -> SourceKind {
        match self {
            Self::Registry { .. } => SourceKind::Registry,
            Self::Git(_) => SourceKind::Git,
            Self::Path { .. } => SourceKind::Path,
            Self::Unknown { .. } => SourceKind::Unknown,
        }
    }
}

/// Parse a Cargo `source` string.
pub fn parse_source(raw: &str) -> ParsedSource {
    let raw = raw.trim();
    if let Some(rest) = raw
        .strip_prefix("registry+")
        .or_else(|| raw.strip_prefix("sparse+"))
    {
        return ParsedSource::Registry {
            url: rest.trim_end_matches('/').to_owned(),
        };
    }
    if let Some(rest) = raw.strip_prefix("git+") {
        return ParsedSource::Git(parse_git_source(rest));
    }
    if let Some(rest) = raw.strip_prefix("path+") {
        return ParsedSource::Path {
            url: Some(rest.to_owned()),
        };
    }
    if raw.is_empty() {
        ParsedSource::Unknown { raw: String::new() }
    } else {
        ParsedSource::Unknown {
            raw: raw.to_owned(),
        }
    }
}

/// Parse the part of a Git source after `git+`.
pub fn parse_git_source(rest: &str) -> GitSourceRef {
    let (without_fragment, fragment) = match rest.split_once('#') {
        Some((left, right)) => (left, Some(right)),
        None => (rest, None),
    };
    let (url, query) = match without_fragment.split_once('?') {
        Some((left, right)) => (left, Some(right)),
        None => (without_fragment, None),
    };

    let mut git = GitSourceRef {
        url: url.trim_end_matches('/').to_owned(),
        ..GitSourceRef::default()
    };

    if let Some(query) = query {
        for pair in query.split('&') {
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, value),
                None => continue,
            };
            let value = percent_decode(value);
            match key {
                "rev" => git.rev = Some(value),
                "branch" => git.branch = Some(value),
                "tag" => git.tag = Some(value),
                _ => {}
            }
        }
    }

    if let Some(fragment) = fragment {
        let fragment = fragment.trim();
        if !fragment.is_empty() {
            git.resolved_revision = Some(fragment.to_owned());
        }
    }
    git.pinned = git.rev.is_some();
    git
}

/// Return a stable package identifier that does not contain machine-specific
/// absolute paths.
pub fn stable_package_id(
    name: &str,
    version: &str,
    source: Option<&str>,
    workspace_member: bool,
    relative_manifest_path: Option<&str>,
) -> String {
    if workspace_member {
        return format!("workspace#{name}@{version}");
    }
    match source.map(parse_source) {
        Some(ParsedSource::Registry { url }) => {
            format!("registry+{url}#{name}@{version}")
        }
        Some(ParsedSource::Git(git)) => {
            format!("git+{}#{name}@{version}", git.url)
        }
        Some(ParsedSource::Path { .. }) => match relative_manifest_path {
            Some(path) => format!("path+{path}#{name}@{version}"),
            None => format!("path#{name}@{version}"),
        },
        Some(ParsedSource::Unknown { raw }) if !raw.is_empty() => {
            format!("unknown+{raw}#{name}@{version}")
        }
        _ => match relative_manifest_path {
            Some(path) => format!("path+{path}#{name}@{version}"),
            None => format!("local#{name}@{version}"),
        },
    }
}

/// Extract the host from an HTTP(S) or SSH-style Git URL.
pub fn url_host(url: &str) -> Option<String> {
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        let authority = rest.split('/').next().unwrap_or(rest);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let host = if let Some(rest) = authority.strip_prefix('[') {
            // IPv6 literal: [::1]:443
            rest.split(']').next().unwrap_or(rest).to_owned()
        } else {
            authority.split(':').next().unwrap_or(authority).to_owned()
        };
        return (!host.is_empty()).then_some(host);
    }
    if let Some(rest) = url.strip_prefix("ssh://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let host = authority.split(':').next().unwrap_or(authority);
        return (!host.is_empty()).then_some(host.to_owned());
    }
    if let Some((user_host, _path)) = url.split_once(':') {
        if let Some((_user, host)) = user_host.rsplit_once('@') {
            return (!host.is_empty()).then_some(host.to_owned());
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hi = hex_value(bytes[index + 1]);
            let lo = hex_value(bytes[index + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                decoded.push(hi * 16 + lo);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// True when a registry URL points at crates.io (sparse or Git index).
pub fn is_crates_io(url: &str) -> bool {
    let url = url.to_ascii_lowercase();
    url.contains("crates.io") || url.contains("github.com/rust-lang/crates.io-index")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_sources() {
        let parsed = parse_source("registry+https://github.com/rust-lang/crates.io-index");
        assert_eq!(
            parsed,
            ParsedSource::Registry {
                url: "https://github.com/rust-lang/crates.io-index".to_owned()
            }
        );
        assert_eq!(parsed.kind(), SourceKind::Registry);

        let parsed = parse_source("sparse+https://index.crates.io/");
        assert_eq!(
            parsed,
            ParsedSource::Registry {
                url: "https://index.crates.io".to_owned()
            }
        );
    }

    #[test]
    fn parses_git_revision_and_resolved_fragment() {
        let parsed = parse_git_source(
            "https://github.com/nrelab/cognix-session.git?rev=a274f71f7a8afc87ccd38f6f803f2d29b694f004",
        );
        assert_eq!(parsed.url, "https://github.com/nrelab/cognix-session.git");
        assert_eq!(
            parsed.rev.as_deref(),
            Some("a274f71f7a8afc87ccd38f6f803f2d29b694f004")
        );
        assert!(parsed.pinned);
        assert_eq!(parsed.host().as_deref(), Some("github.com"));
    }

    #[test]
    fn parses_git_branch_as_unpinned() {
        let parsed = parse_git_source(
            "https://github.com/warpdotdev/tink-rust?branch=warpdotdev/main#abcdef",
        );
        assert_eq!(parsed.branch.as_deref(), Some("warpdotdev/main"));
        assert_eq!(parsed.resolved_revision.as_deref(), Some("abcdef"));
        assert!(!parsed.pinned);
    }

    #[test]
    fn decodes_percent_encoded_refs() {
        let parsed = parse_git_source("https://example.com/repo?tag=v1%2E2#deadbeef");
        assert_eq!(parsed.tag.as_deref(), Some("v1.2"));
        assert_eq!(parsed.resolved_revision.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn parses_path_and_unknown_sources() {
        assert_eq!(
            parse_source("path+file:///tmp/foo").kind(),
            SourceKind::Path
        );
        assert_eq!(parse_source("weird-source").kind(), SourceKind::Unknown);
    }

    #[test]
    fn builds_stable_ids_without_absolute_paths() {
        assert_eq!(
            stable_package_id(
                "serde",
                "1.0.0",
                Some("registry+https://index.crates.io"),
                false,
                None
            ),
            "registry+https://index.crates.io#serde@1.0.0"
        );
        assert_eq!(
            stable_package_id("app", "0.1.0", None, true, Some("app/Cargo.toml")),
            "workspace#app@0.1.0"
        );
        assert_eq!(
            stable_package_id("helper", "0.1.0", None, false, Some("helper/Cargo.toml")),
            "path+helper/Cargo.toml#helper@0.1.0"
        );
    }

    #[test]
    fn extracts_hosts_from_common_urls() {
        assert_eq!(
            url_host("https://github.com/owner/repo.git").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            url_host("ssh://git@example.com:2222/owner/repo").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            url_host("git@example.com:owner/repo").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn identifies_crates_io() {
        assert!(is_crates_io("https://index.crates.io"));
        assert!(is_crates_io("https://github.com/rust-lang/crates.io-index"));
        assert!(!is_crates_io("https://example.com/index"));
    }
}
