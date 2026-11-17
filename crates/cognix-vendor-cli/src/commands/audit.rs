//! `cognix-vendor audit`.

use anyhow::Result;
use std::path::Path;

use crate::{
    audit::{self, AuditOptions, AuditTools},
    cli::ReportFormat,
    commands::{emit, Context},
    config::PathOverrides,
    error::CliFailure,
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    tools: AuditTools,
    allow_missing_tools: bool,
    format: ReportFormat,
    output: Option<&Path>,
    offline: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let report = audit::audit(&AuditOptions {
        manifest_path: consumer.manifest_path.clone(),
        metadata_dir: consumer.metadata_dir.clone(),
        policy_dir: consumer.policy_dir.clone(),
        config_policy: context.config_policy(),
        tools,
        allow_missing_tools,
        offline,
    })?;
    emit(format, &report, report.render_text(), output)?;

    if let Some(tool) = report
        .tools
        .iter()
        .find(|tool| !tool.available && tool.required)
    {
        if !allow_missing_tools {
            return Err(CliFailure::ToolUnavailable {
                tool: tool.name.clone(),
            }
            .into());
        }
    }
    if let Some(tool) = report
        .tools
        .iter()
        .find(|tool| tool.available && !tool.success)
    {
        return Err(CliFailure::AuditFailed {
            tool: tool.name.clone(),
            status: tool.status.clone().unwrap_or_else(|| "unknown".to_owned()),
        }
        .into());
    }
    if let Some(policy) = &report.policy {
        if !policy.ok {
            return Err(CliFailure::Policy {
                errors: policy.error_count,
            }
            .into());
        }
    }
    Ok(())
}
