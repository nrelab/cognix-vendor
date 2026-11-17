//! `cognix-vendor sync`.

use anyhow::Result;

use crate::{
    cli::ReportFormat,
    commands::{emit, Context},
    config::PathOverrides,
    vendor::{self, SyncOptions},
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    force: bool,
    format: ReportFormat,
    offline: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let report = vendor::sync(&SyncOptions {
        consumer,
        offline,
        force,
    })?;
    emit(format, &report.to_json(), report.render_text(), None)
}
