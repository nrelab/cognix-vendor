//! Typed failures that map to stable process exit codes.
//!
//! Ordinary I/O and parsing failures are represented with `anyhow` so callers
//! can attach context. Expected command outcomes that require a specific exit
//! code use [`CliFailure`].

use std::process::ExitCode;

/// Exit code used when the user asked for help or provided invalid arguments.
/// Clap handles that case itself.
pub const EXIT_SUCCESS: u8 = 0;
/// Generic operational failure.
pub const EXIT_FAILURE: u8 = 1;
/// Vendor integrity verification failed.
pub const EXIT_VERIFICATION_FAILED: u8 = 2;
/// The checked-in dependency metadata is out of date.
pub const EXIT_DRIFT: u8 = 3;
/// License or source policy violations were detected.
pub const EXIT_POLICY_VIOLATION: u8 = 4;
/// An audit tool was unavailable or an audit reported a failure.
pub const EXIT_AUDIT_FAILED: u8 = 5;

/// An expected command outcome that carries a documented exit code.
#[derive(Debug, thiserror::Error)]
pub enum CliFailure {
    /// One or more integrity checks failed.
    #[error("vendor verification failed with {errors} error(s)")]
    Verification { errors: usize },

    /// The approved metadata does not match the current resolved graph.
    #[error(
        "approved dependency metadata is out of date; review the diff and run `cognix-vendor sync`"
    )]
    Drift,

    /// License or source policy was violated.
    #[error("license or source policy violations detected ({errors} error(s))")]
    Policy { errors: usize },

    /// A requested audit tool was not installed.
    #[error("required audit tool is unavailable: {tool}")]
    ToolUnavailable { tool: String },

    /// An audit tool ran and failed.
    #[error("`{tool}` reported a failure (exit status: {status})")]
    AuditFailed { tool: String, status: String },
}

impl CliFailure {
    /// Stable exit code for this failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Verification { .. } => EXIT_VERIFICATION_FAILED,
            Self::Drift => EXIT_DRIFT,
            Self::Policy { .. } => EXIT_POLICY_VIOLATION,
            Self::ToolUnavailable { .. } | Self::AuditFailed { .. } => EXIT_AUDIT_FAILED,
        }
    }
}

/// Returns the process exit code for an error, consulting [`CliFailure`] when
/// present and falling back to [`EXIT_FAILURE`].
pub fn exit_code(error: &anyhow::Error) -> ExitCode {
    if let Some(failure) = error.downcast_ref::<CliFailure>() {
        ExitCode::from(failure.exit_code())
    } else {
        ExitCode::from(EXIT_FAILURE)
    }
}

/// Returns the error text including the full `anyhow` context chain.
pub fn format_error(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_typed_failures_to_exit_codes() {
        let error: anyhow::Error = CliFailure::Drift.into();
        assert_eq!(exit_code(&error), ExitCode::from(EXIT_DRIFT));

        let error: anyhow::Error = CliFailure::Verification { errors: 2 }.into();
        assert_eq!(exit_code(&error), ExitCode::from(EXIT_VERIFICATION_FAILED));

        let error: anyhow::Error = anyhow::anyhow!("boom");
        assert_eq!(exit_code(&error), ExitCode::from(EXIT_FAILURE));
    }
}
