//! `cognix-vendor licenses`.

use anyhow::Result;
use std::path::Path;

use crate::{
    cli::ReportFormat,
    commands::{emit, Context},
    config::PathOverrides,
    error::CliFailure,
    report as reporting,
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    format: ReportFormat,
    output: Option<&Path>,
    no_fail: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let report = reporting::licenses(&consumer, &context.config_policy())?;
    let policy_ok = report.policy.as_ref().is_none_or(|policy| policy.ok);
    let errors = report
        .policy
        .as_ref()
        .map(|policy| policy.error_count)
        .unwrap_or(0);
    emit(format, &report, report.render_text(), output)?;
    if !policy_ok && !no_fail {
        return Err(CliFailure::Policy { errors }.into());
    }
    Ok(())
}
