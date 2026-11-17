# cognix-vendor

A Rust CLI and repository scaffold for creating reproducible, auditable Cargo
vendor snapshots for [nrelab/cognix](https://github.com/nrelab/cognix).

**Cargo remains the dependency resolver and vendor generator.** This project
orchestrates `cargo metadata`, `cargo vendor`, checksum verification, snapshot
reporting, and optional third-party audits. It is not a Cargo registry and it
does not replace crates.io or Git repositories as upstream sources.

## Scope

- Discover resolved packages from Cognix's `Cargo.toml` and `Cargo.lock`.
- Generate a Cargo vendor tree using locked dependency versions.
- Save the complete source-replacement configuration emitted by Cargo.
- Record package metadata and the consumer lockfile SHA-256.
- Verify the per-file checksums in each `.cargo-checksum.json` file.
- Compare a current dependency graph with an approved snapshot.
- Optionally invoke `cargo audit` and `cargo deny` when installed.

The initial scaffold intentionally does not download or check in third-party
source code. Run `sync` after reviewing the upstream licenses and repository
policy. Vendor output can be large; use a separate commit for initial vendor
population.

## Requirements

- A current Rust toolchain and Cargo.
- A Cognix checkout adjacent to this repository, or an explicit manifest path.
- Network access for the first online vendor synchronization.
- Optional: `cargo-audit` and `cargo-deny` for security and license checks.

## Build

```bash
cargo build --workspace
cargo test --workspace
cargo run -p cognix-vendor-cli -- --help
```

Install locally:

```bash
cargo install --path crates/cognix-vendor-cli
```

## Quick start

From the root of this repository, assuming `../cognix` is the Cognix checkout:

```bash
# Inspect Cognix's resolved dependency graph.
cognix-vendor discover

# Generate vendor sources and the complete Cargo replacement configuration.
cognix-vendor sync

# Verify the generated vendor tree's file checksums.
cognix-vendor verify

# Inspect the checked-in package snapshot.
cognix-vendor report --format text

# Compare Cognix's current lockfile/dependency graph with the approved snapshot.
cognix-vendor status
cognix-vendor diff

# Optional tools must be installed separately.
cognix-vendor audit --tools both
```

Use `--manifest-path /path/to/cognix/Cargo.toml` when the Cognix checkout is in
a different location. See `docs/USAGE.md` for examples and command behavior.

## Repository layout

```text
crates/cognix-vendor-cli/   Rust CLI
config/                    Generated Cargo replacement config and notes
metadata/cognix/            Approved dependency snapshots and provenance
metadata/policies/          License and source policy templates
vendor/                     Cargo-generated vendor sources (not populated yet)
docs/                       Architecture and operations documentation
.github/workflows/          CI and security workflows
```

## Important safety and licensing notes

1. `Cargo.lock` in the consumer workspace is the resolution source of truth.
2. Do not edit files under `vendor/` manually. Re-run `cargo vendor` instead.
3. Preserve the entire source configuration printed by `cargo vendor`, including
   entries for Git dependencies and patched sources.
4. Review every upstream license and redistribution condition before publishing
   vendored sources. An allowlist in this repository is a policy starting point,
   not a legal determination.
5. A checksum proves that a file matches its recorded checksum; it does not
   prove that the upstream source is benign or trustworthy.
6. Vendor snapshots should be updated through reviewable commits or pull requests.

## Status

Scaffold / early MVP. The CLI is designed to be extended as Cognix's dependency
inventory and source policies are finalized. The environment used to generate
this scaffold did not have Rust/Cargo installed, so compilation and tests have
not yet been run here.

## License

The CLI scaffold is MIT-licensed. Each vendored dependency retains its own
upstream license and attribution. See `LICENSE` and the individual package
license files.
