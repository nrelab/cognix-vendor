//! `cognix-vendor clean`.

use anyhow::Result;

use crate::{
    clean::{self, CleanOptions},
    commands::Context,
    config::PathOverrides,
};

pub fn run(
    context: &Context,
    overrides: &PathOverrides,
    yes: bool,
    dry_run: bool,
    keep_metadata: bool,
    keep_vendor: bool,
) -> Result<()> {
    let consumer = context.resolve(overrides)?;
    let report = clean::clean(&CleanOptions {
        consumer,
        yes,
        dry_run,
        keep_metadata,
        keep_vendor,
    })?;
    print!("{}", clean::render_text(&report));
    Ok(())
}
