//! Integration with external audit tools.
//!
//! Completing `cargo audit` or `cargo deny check` is not a security guarantee.
//! This module records whether each requested tool was available, whether it
//! ran, its exit status, and a bounded output excerpt. Missing tools are never
//! reported as success.

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{
    config::ConfigPolicy,
    model::DependencySnapshot,
    paths,
    policy::{Policies, PolicyReport},
    process::Command,
};

/// Current audit report schema.
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

/// Requested audit tools.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum AuditTools {
    /// `cargo audit`.
    CargoAudit,
    /// `cargo deny check`.
    CargoDeny,
    /// Both tools.
    Both,
}

impl AuditTools {
    /// Expand a selection into concrete tools.
    pub fn selected(self) -> Vec<ToolKind> {
        match self {
            Self::CargoAudit => vec![ToolKind::CargoAudit],
            Self::CargoDeny => vec![ToolKind::CargoDeny],
            Self::Both => vec![ToolKind::CargoAudit, ToolKind::CargoDeny],
        }
    }
}

/// A concrete audit tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolKind {
    /// `cargo audit`.
    CargoAudit,
    /// `cargo deny check`.
    CargoDeny,
}

impl ToolKind {
    /// Tool name.
    pub fn name(self) -> &'static str {
        match self {
            Self::CargoAudit => "cargo-audit",
            Self::CargoDeny => "cargo-deny",
        }
    }

    /// Cargo subcommand arguments used to run the tool.
    fn run_args(self) -> &'static [&'static str] {
        match self {
            Self::CargoAudit => &["audit"],
            Self::CargoDeny => &["deny", "check"],
        }
    }

    /// Cargo subcommand arguments used to check availability.
    fn version_args(self) -> &'static [&'static str] {
        match self {
            Self::CargoAudit => &["audit", "--version"],
            Self::CargoDeny => &["deny", "--version"],
        }
    }
}

/// Audit invocation options.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Consumer manifest.
    pub manifest_path: PathBuf,
    /// Metadata directory containing the approved snapshot.
    pub metadata_dir: PathBuf,
    /// Policy directory.
    pub policy_dir: PathBuf,
    /// Inline policy defaults.
    pub config_policy: ConfigPolicy,
    /// Tools requested on the command line.
    pub tools: AuditTools,
    /// Do not fail when a tool is unavailable.
    pub allow_missing_tools: bool,
    /// Set `CARGO_NET_OFFLINE=true` for tool invocations.
    pub offline: bool,
}

/// Result of running one tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRun {
    /// Tool name.
    pub name: String,
    /// Whether the tool answered `--version`.
    pub available: bool,
    /// Whether policy or the command line requires the tool.
    pub required: bool,
    /// Exit status description, when the tool ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// True when the tool ran and exited successfully.
    #[serde(default)]
    pub success: bool,
    /// Bounded stdout excerpt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_excerpt: Option<String>,
    /// Bounded stderr excerpt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_excerpt: Option<String>,
    /// Reason the tool did not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
}

/// Combined audit report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReport {
    /// Schema version.
    pub schema_version: u32,
    /// True only when all required tools ran successfully and policy passed.
    pub complete: bool,
    /// Tool results.
    pub tools: Vec<ToolRun>,
    /// Local policy evaluation, when a snapshot was available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyReport>,
    /// Explicit limitations and notes.
    pub notes: Vec<String>,
}

impl AuditReport {
    /// Render a terminal report.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Audit checks: {} (not a security guarantee)\n",
            if self.complete {
                "complete"
            } else {
                "INCOMPLETE"
            }
        ));
        for tool in &self.tools {
            let state = if !tool.available {
                "unavailable"
            } else if tool.success {
                "passed"
            } else {
                "failed"
            };
            output.push_str(&format!(
                "- {}: {}{}{}\n",
                tool.name,
                state,
                tool.status
                    .as_ref()
                    .map(|status| format!(" ({status})"))
                    .unwrap_or_default(),
                if tool.required { " [required]" } else { "" }
            ));
            if let Some(reason) = &tool.skipped_reason {
                output.push_str(&format!("  {reason}\n"));
            }
            if let Some(excerpt) = &tool.stderr_excerpt {
                for line in excerpt.lines().take(20) {
                    output.push_str(&format!("  | {line}\n"));
                }
            }
        }
        if let Some(policy) = &self.policy {
            output.push_str(&policy.render_text());
        }
        if !self.notes.is_empty() {
            output.push_str("Notes:\n");
            for note in &self.notes {
                output.push_str(&format!("- {note}\n"));
            }
        }
        output
    }
}

/// Run requested tools and local policy checks.
pub fn audit(options: &AuditOptions) -> Result<AuditReport> {
    if !options.manifest_path.is_file() {
        anyhow::bail!(
            "Cargo manifest does not exist: {}",
            options.manifest_path.display()
        );
    }
    let workspace_dir = options
        .manifest_path
        .parent()
        .context("manifest path has no parent directory")?;

    let policies = Policies::load(&options.policy_dir, &options.config_policy)?;
    let mut requested: Vec<ToolKind> = options.tools.selected();
    if policies.security.advisories.require_cargo_audit {
        requested.push(ToolKind::CargoAudit);
    }
    if policies.security.advisories.require_cargo_deny {
        requested.push(ToolKind::CargoDeny);
    }
    requested.sort();
    requested.dedup();

    let mut tools = Vec::new();
    for tool in requested {
        let required = options.tools.selected().contains(&tool)
            || (tool == ToolKind::CargoAudit && policies.security.advisories.require_cargo_audit)
            || (tool == ToolKind::CargoDeny && policies.security.advisories.require_cargo_deny);
        tools.push(run_tool(tool, required, workspace_dir, options.offline)?);
    }

    let policy = if options.metadata_dir.join("packages.json").is_file() {
        let snapshot = DependencySnapshot::read(&options.metadata_dir.join("packages.json"))?;
        Some(policies.evaluate(&snapshot))
    } else {
        None
    };

    let all_tools_succeeded = tools.iter().all(|tool| tool.available && tool.success);
    let all_required_available = tools
        .iter()
        .filter(|tool| tool.required)
        .all(|tool| tool.available);
    let policy_ok = policy.as_ref().is_none_or(|policy| policy.ok);
    let complete = all_tools_succeeded && all_required_available && policy_ok;

    let mut notes = vec![
        "A completed audit only reports known advisory or policy findings; it does not prove that a dependency is secure."
            .to_owned(),
        "Advisory results depend on the installed tool version and the freshness of its advisory database."
            .to_owned(),
    ];
    if policy.is_none() {
        notes.push(format!(
            "No package snapshot was found at {}; local license and source policy checks were skipped.",
            options.metadata_dir.join("packages.json").display()
        ));
    }
    if !all_required_available {
        notes.push(
            "At least one required audit tool is unavailable; the audit is incomplete.".to_owned(),
        );
    }

    Ok(AuditReport {
        schema_version: AUDIT_SCHEMA_VERSION,
        complete,
        tools,
        policy,
        notes,
    })
}

fn run_tool(
    tool: ToolKind,
    required: bool,
    workspace_dir: &Path,
    offline: bool,
) -> Result<ToolRun> {
    if !tool_available(tool) {
        return Ok(ToolRun {
            name: tool.name().to_owned(),
            available: false,
            required,
            status: None,
            success: false,
            stdout_excerpt: None,
            stderr_excerpt: None,
            skipped_reason: Some(format!(
                "install it with `cargo install {} --locked`",
                tool.name()
            )),
        });
    }

    let mut command = Command::new(paths::cargo_program());
    command.args(tool.run_args()).current_dir(workspace_dir);
    if offline {
        command.env("CARGO_NET_OFFLINE", "true");
    }
    let output = command
        .output()
        .with_context(|| format!("running `cargo {}`", tool.run_args().join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(ToolRun {
        name: tool.name().to_owned(),
        available: true,
        required,
        status: Some(output.status.to_string()),
        success: output.status.success(),
        stdout_excerpt: excerpt(&stdout),
        stderr_excerpt: excerpt(&stderr),
        skipped_reason: None,
    })
}

fn tool_available(tool: ToolKind) -> bool {
    Command::new(paths::cargo_program())
        .args(tool.version_args())
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn excerpt(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut excerpt: String = trimmed
        .lines()
        .rev()
        .take(40)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    const LIMIT: usize = 8_000;
    if excerpt.len() > LIMIT {
        excerpt.truncate(LIMIT);
        excerpt.push_str("\n[output truncated]");
    }
    Some(excerpt)
}

/// Build audit options for a resolved consumer.
pub fn options_for_consumer(
    consumer: &crate::config::ResolvedConsumer,
    config_policy: ConfigPolicy,
    tools: AuditTools,
    allow_missing_tools: bool,
    offline: bool,
) -> AuditOptions {
    AuditOptions {
        manifest_path: consumer.manifest_path.clone(),
        metadata_dir: consumer.metadata_dir.clone(),
        policy_dir: consumer.policy_dir.clone(),
        config_policy,
        tools,
        allow_missing_tools,
        offline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tool_selection() {
        assert_eq!(
            AuditTools::Both.selected(),
            vec![ToolKind::CargoAudit, ToolKind::CargoDeny]
        );
        assert_eq!(AuditTools::CargoDeny.selected(), vec![ToolKind::CargoDeny]);
    }

    #[test]
    fn bounds_output_excerpts() {
        let output = (0..100)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let excerpt = excerpt(&output).expect("excerpt");
        assert!(excerpt.lines().count() <= 40);
        assert!(excerpt.contains("line 99"));
        assert!(!excerpt.contains("line 0\n"));
    }

    #[test]
    fn incomplete_report_is_not_rendered_as_success() {
        let report = AuditReport {
            schema_version: AUDIT_SCHEMA_VERSION,
            complete: false,
            tools: vec![ToolRun {
                name: "cargo-audit".to_owned(),
                available: false,
                required: true,
                status: None,
                success: false,
                stdout_excerpt: None,
                stderr_excerpt: None,
                skipped_reason: Some("install it".to_owned()),
            }],
            policy: None,
            notes: vec!["not a security guarantee".to_owned()],
        };
        let text = report.render_text();
        assert!(text.contains("INCOMPLETE"));
        assert!(text.contains("unavailable"));
        assert!(!text.contains("Audit checks: complete"));
    }
}
