//! `cognix-vendor verify`.

use anyhow::Result;
use std::path::Path;

use crate::{
    cli::ReportFormat,
    commands::{emit, Context},
    config::PathOverrides,
    error::CliFailure,
    verify::{self, VerifyOptions},
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    allow_lockfile_change: bool,
    format: ReportFormat,
    output: Option<&Path>,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let report = verify::verify(&VerifyOptions {
        metadata_dir: consumer.metadata_dir.clone(),
        vendor_dir: consumer.vendor_dir.clone(),
        manifest_path: Some(consumer.manifest_path.clone()),
        allow_lockfile_change,
    })?;
    emit(format, &report, verify::render_text(&report), output)?;
    if !report.ok {
        return Err(CliFailure::Verification {
            errors: report.error_count,
        }
        .into());
    }
    Ok(())
}
