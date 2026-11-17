//! Command dispatch and shared command context.

mod audit;
mod clean;
mod discover;
mod export;
mod init;
mod licenses;
mod report;
mod status;
mod sync;
mod verify;

use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::{
    cli::{Cli, Command, ReportFormat},
    config::{ConfigPolicy, LoadedConfig, PathOverrides, ResolvedConsumer},
};

/// Shared context for commands that operate on a consumer.
pub struct Context {
    /// Loaded repository configuration.
    pub loaded: LoadedConfig,
    /// Invocation directory, used for CLI path overrides.
    pub current_dir: PathBuf,
    /// Selected consumer name.
    pub consumer_name: String,
}

impl Context {
    /// Load configuration and capture the invocation directory.
    pub fn new(config_path: &Path, consumer_name: &str) -> Result<Self> {
        let loaded = LoadedConfig::load(config_path)?;
        let current_dir = std::env::current_dir()?;
        Ok(Self {
            loaded,
            current_dir,
            consumer_name: consumer_name.to_owned(),
        })
    }

    /// Resolve paths for the selected consumer.
    pub fn resolve(&self, overrides: &PathOverrides) -> Result<ResolvedConsumer> {
        self.loaded
            .resolve(&self.consumer_name, overrides, &self.current_dir)
    }

    /// Inline policy defaults.
    pub fn config_policy(&self) -> ConfigPolicy {
        self.loaded.config.policy.clone()
    }
}

/// Dispatch a parsed CLI.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { path, force } => init::run(&path, force),
        Command::Discover {
            manifest_path,
            metadata_dir,
            output,
            format,
            report_output,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                manifest_path,
                metadata_dir,
                ..PathOverrides::default()
            };
            discover::run(
                &context,
                &overrides,
                output,
                format,
                report_output,
                cli.offline,
            )
        }
        Command::Sync {
            manifest_path,
            vendor_dir,
            metadata_dir,
            config_output,
            force,
            format,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                manifest_path,
                vendor_dir,
                metadata_dir,
                config_output,
                policy_dir: None,
            };
            sync::run(&context, &overrides, force, format, cli.offline)
        }
        Command::Verify {
            manifest_path,
            vendor_dir,
            metadata_dir,
            allow_lockfile_change,
            format,
            output,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                manifest_path,
                vendor_dir,
                metadata_dir,
                ..PathOverrides::default()
            };
            verify::run(
                &context,
                &overrides,
                allow_lockfile_change,
                format,
                output.as_deref(),
            )
        }
        Command::Audit {
            manifest_path,
            metadata_dir,
            policy_dir,
            tools,
            allow_missing_tools,
            format,
            output,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                manifest_path,
                metadata_dir,
                policy_dir,
                ..PathOverrides::default()
            };
            audit::run(
                &context,
                &overrides,
                tools,
                allow_missing_tools,
                format,
                output.as_deref(),
                cli.offline,
            )
        }
        Command::Status {
            manifest_path,
            metadata_dir,
            vendor_dir,
            policy_dir,
            format,
            output,
            no_fail,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                manifest_path,
                metadata_dir,
                vendor_dir,
                policy_dir,
                ..PathOverrides::default()
            };
            status::run(
                &context,
                &overrides,
                format,
                output.as_deref(),
                no_fail,
                cli.offline,
                false,
            )
        }
        Command::Diff {
            manifest_path,
            metadata_dir,
            vendor_dir,
            policy_dir,
            format,
            output,
            no_fail,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                manifest_path,
                metadata_dir,
                vendor_dir,
                policy_dir,
                ..PathOverrides::default()
            };
            status::run(
                &context,
                &overrides,
                format,
                output.as_deref(),
                no_fail,
                cli.offline,
                true,
            )
        }
        Command::Report {
            metadata_dir,
            vendor_dir,
            policy_dir,
            input,
            format,
            output,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                metadata_dir,
                vendor_dir,
                policy_dir,
                ..PathOverrides::default()
            };
            report::run(&context, &overrides, input, format, output.as_deref())
        }
        Command::Licenses {
            metadata_dir,
            policy_dir,
            format,
            output,
            no_fail,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                metadata_dir,
                policy_dir,
                ..PathOverrides::default()
            };
            licenses::run(&context, &overrides, format, output.as_deref(), no_fail)
        }
        Command::Export {
            metadata_dir,
            vendor_dir,
            config_output,
            policy_dir,
            format,
            output,
            force,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                metadata_dir,
                vendor_dir,
                config_output,
                policy_dir,
                ..PathOverrides::default()
            };
            export::run(&context, &overrides, format, output, force)
        }
        Command::Clean {
            vendor_dir,
            metadata_dir,
            config_output,
            yes,
            dry_run,
            keep_metadata,
            keep_vendor,
        } => {
            let context = Context::new(&cli.config, &cli.consumer)?;
            let overrides = PathOverrides {
                vendor_dir,
                metadata_dir,
                config_output,
                ..PathOverrides::default()
            };
            clean::run(
                &context,
                &overrides,
                yes,
                dry_run,
                keep_metadata,
                keep_vendor,
            )
        }
    }
}

/// Emit text or JSON to stdout or an output file.
pub(crate) fn emit<T: Serialize>(
    format: ReportFormat,
    value: &T,
    text: String,
    output: Option<&Path>,
) -> Result<()> {
    let rendered = match format {
        ReportFormat::Json => {
            let mut rendered = serde_json::to_string_pretty(value)?;
            rendered.push('\n');
            rendered
        }
        ReportFormat::Text => text,
    };
    crate::report::write_output(&rendered, output)
}

/// Resolve a CLI output override relative to the invocation directory.
pub(crate) fn resolve_output(context: &Context, path: Option<&PathBuf>) -> Result<Option<PathBuf>> {
    match path {
        Some(path) => Ok(Some(crate::paths::resolve_against(
            &context.current_dir,
            path,
        ))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_output_override_against_current_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let context = Context {
            loaded: LoadedConfig::load(&dir.path().join("missing.toml")).expect("load"),
            current_dir: dir.path().to_path_buf(),
            consumer_name: "demo".to_owned(),
        };
        let resolved =
            resolve_output(&context, Some(&PathBuf::from("reports/out.json"))).expect("resolve");
        assert_eq!(resolved, Some(dir.path().join("reports/out.json")));
    }
}
