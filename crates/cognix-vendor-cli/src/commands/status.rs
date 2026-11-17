//! `cognix-vendor status` and `cognix-vendor diff`.

use anyhow::Result;
use std::path::Path;

use crate::{
    cli::ReportFormat,
    commands::{emit, Context},
    config::PathOverrides,
    error::CliFailure,
    report,
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    format: ReportFormat,
    output: Option<&Path>,
    no_fail: bool,
    offline: bool,
    diff_only: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let status = report::status(&consumer, &context.config_policy(), offline)?;
    let text = if diff_only {
        status.diff.render_text()
    } else {
        status.render_text()
    };
    let up_to_date = status.up_to_date;
    if diff_only {
        emit(format, &status.diff, text, output)?;
    } else {
        emit(format, &status, text, output)?;
    }
    if !up_to_date && !no_fail {
        return Err(CliFailure::Drift.into());
    }
    Ok(())
}
