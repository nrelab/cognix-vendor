//! Repository initialization.

use anyhow::{Context, Result};
use std::{fs, path::Path};

use crate::config;

const LICENSES_TEMPLATE: &str = r#"# License policy for vendored third-party sources.
# This is a policy starting point, not a legal determination.
version = 1

# SPDX license identifiers accepted for redistribution.
allowed = [
  "0BSD",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BSL-1.0",
  "CC0-1.0",
  "CDLA-Permissive-2.0",
  "ISC",
  "MIT",
  "MPL-2.0",
  "Unlicense",
  "Unicode-3.0",
  "Unicode-DFS-2016",
  "Zlib",
]

# SPDX identifiers that must never be accepted.
denied = []

# Reject packages that have no SPDX license expression.
deny_unknown = true

# Private workspace members are not redistributed.
ignore_workspace = true

# Add package-specific legal review decisions here, for example:
# [exceptions]
# "some-private-git-crate" = "Private nrelab crate; license pending open sourcing."
"#;

const SECURITY_TEMPLATE: &str = r#"# Security audit expectations.
# Running an audit does not prove that a dependency is secure.
version = 1

[advisories]
enabled = true

# Require these tools to be installed for `cognix-vendor audit` in CI.
# They are not installed automatically.
require_cargo_audit = false
require_cargo_deny = false

# Advisory IDs documented as accepted risks. Prefer fixing or removing the
# dependency instead of ignoring an advisory permanently.
ignore = []
"#;

const SOURCES_TEMPLATE: &str = r#"# Dependency source policy.
version = 1

[git]
# Cargo must have recorded a resolved commit hash.
require_locked_revision = true
# Reject branch, tag, and unqualified Git declarations. Exact `rev` values are
# the only declarations treated as pinned.
allow_unpinned = false
# Hosts approved for Git dependencies. Empty disables host checking.
allowed_hosts = ["github.com"]
# Exact repository URLs approved for Git dependencies. Empty disables URL
# checking; populated lists reject every other repository.
allowed_repositories = []

[registry]
# Allow crates.io.
allow_crates_io = true
# Additional approved registry index URLs. Non-crates.io registries are
# rejected when this list is empty.
allowed = []
"#;

/// Initialize a cognix-vendor repository layout.
///
/// Existing files are preserved unless `force` is set, and `force` only
/// replaces `cognix-vendor.toml`. Generated vendor output is never touched.
pub fn init(path: &Path, force: bool) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("creating repository directory {}", path.display()))?;

    for directory in [
        "config",
        "metadata/cognix",
        "metadata/policies",
        "docs",
        "vendor",
    ] {
        let directory = path.join(directory);
        fs::create_dir_all(&directory)
            .with_context(|| format!("creating {}", directory.display()))?;
    }

    let config_path = path.join("cognix-vendor.toml");
    if config_path.exists() && !force {
        println!(
            "Configuration already exists at {}; leaving it unchanged (use --force to replace).",
            config_path.display()
        );
    } else {
        let template = config::default_config_toml()?;
        fs::write(&config_path, template)
            .with_context(|| format!("writing {}", config_path.display()))?;
        println!("Wrote {}", config_path.display());
    }

    for (relative, contents) in [
        ("metadata/policies/licenses.toml", LICENSES_TEMPLATE),
        ("metadata/policies/security.toml", SECURITY_TEMPLATE),
        ("metadata/policies/sources.toml", SOURCES_TEMPLATE),
    ] {
        let path = path.join(relative);
        if !path.exists() {
            fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
            println!("Wrote {}", path.display());
        }
    }

    let placeholder = path.join("vendor/.gitkeep");
    if !placeholder.exists() {
        fs::write(&placeholder, "")
            .with_context(|| format!("writing {}", placeholder.display()))?;
    }

    println!("Initialized cognix-vendor at {}", path.display());
    println!("Next: review metadata/policies, then run `cognix-vendor discover`.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_layout_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        init(dir.path(), false).expect("first init");
        assert!(dir.path().join("cognix-vendor.toml").is_file());
        assert!(dir.path().join("metadata/policies/licenses.toml").is_file());
        assert!(dir.path().join("metadata/policies/security.toml").is_file());
        assert!(dir.path().join("metadata/policies/sources.toml").is_file());
        assert!(dir.path().join("vendor/.gitkeep").is_file());

        fs::write(dir.path().join("cognix-vendor.toml"), "# custom\n").expect("customize");
        init(dir.path(), false).expect("second init");
        assert_eq!(
            fs::read_to_string(dir.path().join("cognix-vendor.toml")).expect("read"),
            "# custom\n"
        );
    }

    #[test]
    fn templates_are_valid_toml() {
        for template in [LICENSES_TEMPLATE, SECURITY_TEMPLATE, SOURCES_TEMPLATE] {
            toml::from_str::<toml::Value>(template).expect("valid toml");
        }
    }
}
