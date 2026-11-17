//! Export commands, including safe Cargo source-replacement configuration
//! merging.
//!
//! Export never modifies the consumer repository unless the user supplies an
//! explicit `--output` path. Existing Cargo configuration is preserved; only
//! generated `[source]` entries are merged, and conflicting values require
//! `--force`.

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    config::{ConfigPolicy, ResolvedConsumer},
    model::{DependencySnapshot, GitSourcesFile},
    paths,
    report::{self, REPORT_SCHEMA_VERSION},
};

/// Supported export formats.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ExportFormat {
    /// CycloneDX 1.5 SBOM.
    Sbom,
    /// Approved package snapshot.
    Packages,
    /// Git source inventory.
    GitSources,
    /// Human/machine dependency report.
    Report,
    /// Cargo source-replacement configuration.
    CargoConfig,
}

/// Export inputs.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Resolved consumer.
    pub consumer: ResolvedConsumer,
    /// Export format.
    pub format: ExportFormat,
    /// Destination. When omitted, output is printed to stdout.
    pub output: Option<PathBuf>,
    /// Allow overwriting conflicting configuration values.
    pub force: bool,
    /// Inline policy defaults.
    pub config_policy: ConfigPolicy,
}

/// Result of an export.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportResult {
    /// Format used.
    pub format: String,
    /// Destination, if the output was written to a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Backup created for an existing Cargo configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
}

/// Export data.
pub fn export(options: &ExportOptions) -> Result<ExportResult> {
    match options.format {
        ExportFormat::CargoConfig => export_cargo_config(options),
        ExportFormat::Sbom => {
            let snapshot = read_snapshot(&options.consumer)?;
            let sbom = crate::sbom::build_sbom(&snapshot)?;
            write_json(&sbom, options.output.as_deref())?;
            Ok(result("sbom", options.output.as_deref(), None))
        }
        ExportFormat::Packages => {
            let snapshot = read_snapshot(&options.consumer)?;
            write_json(&snapshot, options.output.as_deref())?;
            Ok(result("packages", options.output.as_deref(), None))
        }
        ExportFormat::GitSources => {
            let snapshot = read_snapshot(&options.consumer)?;
            let git = GitSourcesFile::from_snapshot(&snapshot);
            write_json(&git, options.output.as_deref())?;
            Ok(result("git-sources", options.output.as_deref(), None))
        }
        ExportFormat::Report => {
            let data = report::report(&options.consumer, &options.config_policy)?;
            if options
                .output
                .as_ref()
                .is_some_and(|path| path.extension().is_some_and(|ext| ext == "json"))
            {
                write_json(&data, options.output.as_deref())?;
            } else {
                let rendered = format!(
                    "schema_version = {REPORT_SCHEMA_VERSION}\n{}",
                    data.render_text()
                );
                report::write_output(&rendered, options.output.as_deref())?;
            }
            Ok(result("report", options.output.as_deref(), None))
        }
    }
}

fn export_cargo_config(options: &ExportOptions) -> Result<ExportResult> {
    let generated_path = &options.consumer.config_output;
    if !generated_path.is_file() {
        bail!(
            "generated source configuration is missing at {}; run `cognix-vendor sync` first",
            generated_path.display()
        );
    }
    let generated_text = fs::read_to_string(generated_path)
        .with_context(|| format!("reading {}", generated_path.display()))?;

    let Some(output) = &options.output else {
        let adjusted = adjust_configuration(
            &generated_text,
            &options.consumer.vendor_dir,
            Path::new("."),
        )?;
        print!("{adjusted}");
        if !adjusted.ends_with('\n') {
            println!();
        }
        return Ok(result("cargo-config", None, None));
    };

    let output = paths::absolute_path(output)?;
    let output_parent = output.parent().unwrap_or_else(|| Path::new("."));
    let adjusted_text =
        adjust_configuration(&generated_text, &options.consumer.vendor_dir, output_parent)?;

    let mut backup: Option<PathBuf> = None;
    let rendered = if output.is_file() {
        let existing_text = fs::read_to_string(&output).with_context(|| {
            format!("reading existing Cargo configuration {}", output.display())
        })?;
        let existing: toml::Value = toml::from_str(&existing_text).with_context(|| {
            format!("parsing existing Cargo configuration {}", output.display())
        })?;
        let generated: toml::Value = toml::from_str(&adjusted_text).with_context(|| {
            format!(
                "parsing generated Cargo configuration {}",
                generated_path.display()
            )
        })?;
        let merged = merge_toml(existing, generated, options.force)?;
        let rendered =
            toml::to_string_pretty(&merged).context("serializing merged Cargo configuration")?;
        let rendered = ensure_newline(rendered);

        let backup_path = backup_path(&output);
        fs::copy(&output, &backup_path).with_context(|| {
            format!(
                "backing up {} to {}",
                output.display(),
                backup_path.display()
            )
        })?;
        backup = Some(backup_path);
        rendered
    } else {
        ensure_newline(adjusted_text)
    };

    paths::atomic_write(&output, rendered.as_bytes())
        .with_context(|| format!("writing Cargo configuration {}", output.display()))?;
    Ok(result("cargo-config", Some(&output), backup.as_deref()))
}

fn read_snapshot(consumer: &ResolvedConsumer) -> Result<DependencySnapshot> {
    DependencySnapshot::read(&consumer.packages_path()).with_context(|| {
        format!(
            "reading package snapshot {}; run `cognix-vendor discover` or `sync` first",
            consumer.packages_path().display()
        )
    })
}

fn write_json<T: Serialize>(value: &T, output: Option<&Path>) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if let Some(path) = output {
        paths::atomic_write(path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        println!("Export written to {}", path.display());
    } else {
        use std::io::Write;
        std::io::stdout().write_all(&bytes)?;
    }
    Ok(())
}

fn result(format: &str, output: Option<&Path>, backup: Option<&Path>) -> ExportResult {
    ExportResult {
        format: format.to_owned(),
        output: output.map(|path| path.display().to_string()),
        backup: backup.map(|path| path.display().to_string()),
    }
}

/// Adjust the vendored-sources directory and validate the generated config.
fn adjust_configuration(
    generated_text: &str,
    vendor_dir: &Path,
    output_parent: &Path,
) -> Result<String> {
    if is_comment_only(generated_text) {
        return Ok("# No dependencies required vendoring.\n".to_owned());
    }
    let mut document: toml::Value = toml::from_str(generated_text)
        .context("generated Cargo source configuration is not valid TOML")?;
    let directory = paths::relative_to(output_parent, vendor_dir)
        .to_string_lossy()
        .replace('\\', "/");
    if let Some(vendored) = document
        .get_mut("source")
        .and_then(toml::Value::as_table_mut)
        .and_then(|source| source.get_mut("vendored-sources"))
        .and_then(toml::Value::as_table_mut)
    {
        vendored.insert("directory".to_owned(), toml::Value::String(directory));
    } else {
        bail!(
            "generated source configuration has no [source.vendored-sources] table; re-run `cognix-vendor sync`"
        );
    }
    let rendered =
        toml::to_string_pretty(&document).context("serializing adjusted Cargo configuration")?;
    Ok(ensure_newline(rendered))
}

fn is_comment_only(text: &str) -> bool {
    text.lines()
        .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
}

fn merge_toml(existing: toml::Value, generated: toml::Value, force: bool) -> Result<toml::Value> {
    match (existing, generated) {
        (toml::Value::Table(mut existing), toml::Value::Table(generated)) => {
            for (key, generated_value) in generated {
                match existing.remove(&key) {
                    Some(existing_value) => {
                        let merged = merge_toml(existing_value, generated_value, force)
                            .with_context(|| format!("merging configuration key `{key}`"))?;
                        existing.insert(key, merged);
                    }
                    None => {
                        existing.insert(key, generated_value);
                    }
                }
            }
            Ok(toml::Value::Table(existing))
        }
        (existing, generated) if existing == generated => Ok(existing),
        (existing, generated) if force => {
            let _ = existing;
            Ok(generated)
        }
        (_, _) => bail!(
            "existing Cargo configuration conflicts with generated source configuration; re-run with --force to overwrite conflicting values"
        ),
    }
}

fn backup_path(output: &Path) -> PathBuf {
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.toml");
    let stamp = paths::unix_timestamp().unwrap_or(0);
    output.with_file_name(format!("{file_name}.bak.{stamp}"))
}

fn ensure_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedConsumer;
    use crate::model::{PackageRecord, PACKAGES_SCHEMA_VERSION};

    fn consumer(root: &Path) -> ResolvedConsumer {
        ResolvedConsumer {
            name: "cognix".to_owned(),
            root: root.to_path_buf(),
            manifest_path: root.join("../cognix/Cargo.toml"),
            metadata_dir: root.join("metadata/cognix"),
            vendor_dir: root.join("vendor"),
            config_output: root.join("config/cognix-source-replacement.toml"),
            policy_dir: root.join("metadata/policies"),
        }
    }

    fn write_generated(consumer: &ResolvedConsumer) {
        fs::create_dir_all(consumer.config_output.parent().expect("parent")).expect("config dir");
        fs::write(
            &consumer.config_output,
            format!(
                "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"{}\"\n",
                consumer.vendor_dir.display()
            ),
        )
        .expect("config");
        fs::create_dir_all(&consumer.metadata_dir).expect("metadata");
        fs::write(
            consumer.packages_path(),
            serde_json::to_vec(&DependencySnapshot {
                schema_version: PACKAGES_SCHEMA_VERSION,
                consumer: "cognix".to_owned(),
                manifest_path: "../cognix/Cargo.toml".to_owned(),
                lockfile_path: "Cargo.lock".to_owned(),
                lockfile_sha256: None,
                package_count: 0,
                packages: Vec::<PackageRecord>::new(),
            })
            .expect("serialize"),
        )
        .expect("snapshot");
    }

    #[test]
    fn adjusts_directory_relative_to_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let consumer = consumer(dir.path());
        write_generated(&consumer);
        let output = dir.path().join("../cognix/.cargo/config.toml");
        let generated = fs::read_to_string(&consumer.config_output).expect("read");
        let adjusted = adjust_configuration(
            &generated,
            &consumer.vendor_dir,
            output.parent().expect("parent"),
        )
        .expect("adjust");
        assert!(adjusted.contains("directory = \""));
        let parsed: toml::Value = toml::from_str(&adjusted).expect("parse");
        let directory = parsed["source"]["vendored-sources"]["directory"]
            .as_str()
            .expect("directory");
        assert_eq!(
            paths::resolve_against(output.parent().expect("parent"), Path::new(directory)),
            paths::lexical_normalize(&consumer.vendor_dir)
        );
        assert!(directory.starts_with("../"));
    }

    #[test]
    fn merge_preserves_unrelated_settings() {
        let existing: toml::Value = toml::from_str(
            r#"
[env]
FOO = "bar"

[build]
rustflags = ["-C", "target-cpu=native"]

[source.crates-io]
replace-with = "vendored-sources"
"#,
        )
        .expect("existing");
        let generated: toml::Value = toml::from_str(
            r#"
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "../cognix-vendor/vendor"
"#,
        )
        .expect("generated");
        let merged = merge_toml(existing, generated, false).expect("merge");
        assert_eq!(merged["env"]["FOO"].as_str(), Some("bar"));
        assert_eq!(
            merged["source"]["vendored-sources"]["directory"].as_str(),
            Some("../cognix-vendor/vendor")
        );
    }

    #[test]
    fn conflicts_require_force() {
        let existing: toml::Value =
            toml::from_str("[source.crates-io]\nreplace-with = \"other\"\n").expect("existing");
        let generated: toml::Value =
            toml::from_str("[source.crates-io]\nreplace-with = \"vendored-sources\"\n")
                .expect("generated");
        assert!(merge_toml(existing.clone(), generated.clone(), false).is_err());
        let merged = merge_toml(existing, generated, true).expect("forced merge");
        assert_eq!(
            merged["source"]["crates-io"]["replace-with"].as_str(),
            Some("vendored-sources")
        );
    }

    #[test]
    fn comment_only_config_is_accepted() {
        assert_eq!(
            adjust_configuration(
                "# No dependencies required vendoring.\n",
                Path::new("vendor"),
                Path::new(".")
            )
            .expect("adjust"),
            "# No dependencies required vendoring.\n"
        );
    }
}
