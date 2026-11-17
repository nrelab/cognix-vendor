//! Binary entry point. All behavior lives in the library for testability.

use clap::Parser;
use std::process::ExitCode;

use cognix_vendor_cli::{cli::Cli, commands, error};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);
    match commands::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", error::format_error(&error));
            error::exit_code(&error)
        }
    }
}

fn init_tracing(verbose: u8, quiet: bool) {
    let default_level = if quiet {
        "error"
    } else {
        match verbose {
            0 => "warn",
            1 => "debug",
            _ => "trace",
        }
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
