//! cognix-vendor: reproducible and auditable Cargo vendor management.
//!
//! Cargo remains the dependency resolver and vendor generator. This crate
//! orchestrates discovery, staged synchronization, integrity verification,
//! policy evaluation, reporting, and export.
//!
//! # Exit codes
//!
//! * `0` success
//! * `1` operational failure
//! * `2` vendor verification failure
//! * `3` approved metadata is out of date
//! * `4` license or source policy violation
//! * `5` audit tool unavailable or audit failed

#![forbid(unsafe_code)]

pub mod audit;
pub mod clean;
pub mod cli;
pub mod commands;
pub mod config;
pub mod diff;
pub mod discovery;
pub mod error;
pub mod export;
pub mod init;
pub mod lockfile;
pub mod model;
pub mod paths;
pub mod policy;
pub mod process;
pub mod report;
pub mod sbom;
pub mod source;
pub mod vendor;
pub mod verify;
