#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_DIR="${SOURCE_DIR:-/workspaces/cognix-dev}"

dry_run=()
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=(--dry-run)
fi

command -v rsync >/dev/null 2>&1 || { echo "rsync is required" >&2; exit 1; }
[ -d "$SOURCE_DIR" ] || { echo "source directory not found: $SOURCE_DIR" >&2; exit 1; }

rsync -a --delete "${dry_run[@]}" \
  --exclude='.git/' \
  --exclude='target/' \
  --exclude='scripts/' \
  "$SOURCE_DIR/" "$ROOT/"

python3 "$ROOT/cognix-vendor/scripts/vendor_used.py"

echo "Synced $SOURCE_DIR -> $ROOT"
