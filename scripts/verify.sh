#!/usr/bin/env bash
set -euo pipefail

cargo run -p cognix-vendor-cli -- verify --vendor-dir vendor
