#!/usr/bin/env bash
set -euo pipefail

MANIFEST_PATH="${1:-../cognix/Cargo.toml}"

cargo run -p cognix-vendor-cli -- sync \
  --manifest-path "$MANIFEST_PATH" \
  --vendor-dir vendor \
  --metadata-dir metadata/cognix \
  --config-output config/cognix-source-replacement.toml

cargo run -p cognix-vendor-cli -- verify --vendor-dir vendor
