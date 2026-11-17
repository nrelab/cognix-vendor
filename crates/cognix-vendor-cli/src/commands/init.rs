//! `cognix-vendor init`.

use anyhow::Result;
use std::path::Path;

pub fn run(path: &Path, force: bool) -> Result<()> {
    crate::init::init(path, force)
}
