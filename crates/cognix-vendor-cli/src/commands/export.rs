//! `cognix-vendor export`.

use anyhow::Result;
use std::path::PathBuf;

use crate::{
    commands::Context,
    config::PathOverrides,
    export::{self, ExportFormat, ExportOptions},
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    format: ExportFormat,
    output: Option<PathBuf>,
    force: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let result = export::export(&ExportOptions {
        consumer,
        format,
        output,
        force,
        config_policy: context.config_policy(),
    })?;
    if matches!(format, ExportFormat::CargoConfig) {
        if let Some(path) = &result.output {
            println!("Cargo source configuration written to {path}");
        }
        if let Some(backup) = &result.backup {
            println!("Previous Cargo configuration backed up to {backup}");
        }
    }
    Ok(())
}
