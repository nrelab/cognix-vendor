#!/usr/bin/env bash
set -euo pipefail

cargo build --workspace
cargo test --workspace
cargo run -p cognix-vendor-cli -- --help
