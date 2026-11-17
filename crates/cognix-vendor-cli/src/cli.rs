//! Command-line interface definitions.

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::audit::AuditTools;
use crate::export::ExportFormat;

/// Manage reproducible, auditable Cargo vendor snapshots for Cognix.
#[derive(Debug, Parser)]
#[command(
    name = "cognix-vendor",
    version,
    about,
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Repository configuration file.
    #[arg(
        long,
        global = true,
        default_value = "cognix-vendor.toml",
        value_name = "PATH"
    )]
    pub config: PathBuf,

    /// Consumer name from the configuration file.
    #[arg(long, global = true, default_value = "cognix", value_name = "NAME")]
    pub consumer: String,

    /// Ask Cargo to use only locally cached data.
    #[arg(long, global = true)]
    pub offline: bool,

    /// Increase log verbosity (-v = debug, -vv = trace).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-error logging.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the repository directory structure, configuration, and policy templates.
    Init {
        /// Directory in which to initialize the repository.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Replace cognix-vendor.toml if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Discover the resolved package graph and write versioned metadata.
    Discover {
        /// Consumer Cargo manifest.
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Metadata directory.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Override the packages.json destination.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Output format for the command summary.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the summary to a file.
        #[arg(long, value_name = "PATH")]
        report_output: Option<PathBuf>,
    },

    /// Run `cargo vendor --locked --versioned-dirs` and write metadata.
    Sync {
        /// Consumer Cargo manifest.
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Vendor output directory.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Metadata directory.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Generated Cargo source-replacement configuration.
        #[arg(long, value_name = "PATH")]
        config_output: Option<PathBuf>,
        /// Replace a non-Cargo vendor directory.
        #[arg(long)]
        force: bool,
        /// Output format for the command summary.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
    },

    /// Verify vendor checksums, package identity, metadata freshness, and Git revisions.
    Verify {
        /// Consumer Cargo manifest (used to detect lockfile changes).
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Vendor directory.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Metadata directory containing the approved snapshot.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Downgrade lockfile freshness errors to warnings.
        #[arg(long)]
        allow_lockfile_change: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the verification report to a file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Run installed audit tools and evaluate license/source policy.
    Audit {
        /// Consumer Cargo manifest.
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Metadata directory containing the approved snapshot.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Policy directory.
        #[arg(long, value_name = "PATH")]
        policy_dir: Option<PathBuf>,
        /// Tools to run.
        #[arg(long, value_enum, default_value = "both")]
        tools: AuditTools,
        /// Report missing tools as incomplete checks instead of failing.
        #[arg(long)]
        allow_missing_tools: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the audit report to a file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Compare the approved snapshot with the current Cargo resolution.
    Status {
        /// Consumer Cargo manifest.
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Metadata directory containing the approved snapshot.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Vendor directory, for the integrity summary.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Policy directory.
        #[arg(long, value_name = "PATH")]
        policy_dir: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the report to a file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Exit successfully even when dependencies changed.
        #[arg(long)]
        no_fail: bool,
    },

    /// Show added, removed, version-changed, and Git-revision-changed packages.
    Diff {
        /// Consumer Cargo manifest.
        #[arg(long, value_name = "PATH")]
        manifest_path: Option<PathBuf>,
        /// Metadata directory containing the approved snapshot.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Vendor directory, for the integrity summary.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Policy directory.
        #[arg(long, value_name = "PATH")]
        policy_dir: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the report to a file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Exit successfully even when dependencies changed.
        #[arg(long)]
        no_fail: bool,
    },

    /// Print a dependency report from generated metadata.
    Report {
        /// Metadata directory.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Vendor directory, for the integrity summary.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Policy directory.
        #[arg(long, value_name = "PATH")]
        policy_dir: Option<PathBuf>,
        /// Read a specific packages.json instead of the consumer metadata.
        #[arg(long, value_name = "PATH")]
        input: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the report to a file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Report the license inventory and license policy result.
    Licenses {
        /// Metadata directory.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Policy directory.
        #[arg(long, value_name = "PATH")]
        policy_dir: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        /// Write the report to a file.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Exit successfully even when policy violations are present.
        #[arg(long)]
        no_fail: bool,
    },

    /// Export SBOM, package metadata, reports, or Cargo source configuration.
    Export {
        /// Metadata directory.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Vendor directory.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Generated Cargo source configuration from `sync`.
        #[arg(long, value_name = "PATH")]
        config_output: Option<PathBuf>,
        /// Policy directory.
        #[arg(long, value_name = "PATH")]
        policy_dir: Option<PathBuf>,
        /// Export format.
        #[arg(long, value_enum)]
        format: ExportFormat,
        /// Destination. Omit to print to stdout.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Overwrite conflicting Cargo configuration values.
        #[arg(long)]
        force: bool,
    },

    /// Remove generated vendor and metadata output after explicit confirmation.
    Clean {
        /// Vendor directory.
        #[arg(long, value_name = "PATH")]
        vendor_dir: Option<PathBuf>,
        /// Metadata directory.
        #[arg(long, value_name = "PATH")]
        metadata_dir: Option<PathBuf>,
        /// Generated Cargo source configuration.
        #[arg(long, value_name = "PATH")]
        config_output: Option<PathBuf>,
        /// Confirm removal.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Print what would be removed without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Keep generated metadata.
        #[arg(long)]
        keep_metadata: bool,
        /// Keep the vendor directory.
        #[arg(long)]
        keep_vendor: bool,
    },
}

/// Report output format.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ReportFormat {
    /// Human-readable terminal output.
    Text,
    /// Pretty JSON.
    Json,
}
