//! `cognix-vendor report`.

use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::{
    cli::ReportFormat,
    commands::{emit, Context},
    config::PathOverrides,
    paths, report as reporting,
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    input: Option<PathBuf>,
    format: ReportFormat,
    output: Option<&Path>,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let config_policy = context.config_policy();
    let report = match input {
        Some(input) => {
            let input = paths::resolve_against(&context.current_dir, &input);
            reporting::report_from_path(&input, &config_policy, &consumer.policy_dir)?
        }
        None => reporting::report(&consumer, &config_policy)?,
    };
    emit(format, &report, report.render_text(), output)
}
