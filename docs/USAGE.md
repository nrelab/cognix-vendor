# Usage

All commands are run from the `cognix-vendor` repository root unless noted.

## Discover

```bash
cognix-vendor discover \
  --manifest-path ../cognix/Cargo.toml \
  --output metadata/cognix/packages.json
```

This runs `cargo metadata` and records workspace members and resolved packages,
including package source, version, registry checksum (when provided by Cargo),
license metadata, dependency requirements, features, and lockfile SHA-256.

## Synchronize

```bash
cognix-vendor sync \
  --manifest-path ../cognix/Cargo.toml \
  --vendor-dir vendor \
  --metadata-dir metadata/cognix \
  --config-output config/cognix-source-replacement.toml
```

The command runs `cargo vendor --locked --versioned-dirs`. Cargo writes source
files into `vendor/` and prints the source replacement configuration to stdout;
the CLI saves that exact output. `--offline` adds Cargo's offline flag and will
fail if required package sources are not already cached.

`--locked` is intentional: synchronization must fail rather than silently
rewrite the consumer's lockfile. Update Cognix's lockfile in a separate reviewed
change first, then synchronize the vendor repository.

## Verify

```bash
cognix-vendor verify --vendor-dir vendor
```

The verifier reads every vendored package's `.cargo-checksum.json`, checks that
listed files exist, and recomputes their SHA-256 digest. This is an integrity
check against the checksum manifest, not a malware scan or provenance proof.

## Audit

Install optional tools:

```bash
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

Run:

```bash
cognix-vendor audit --manifest-path ../cognix/Cargo.toml --tools both
```

The CLI invokes the selected tool(s) from the consumer workspace directory.
The tools use their own configuration and advisory databases. Review results
and license policy decisions; the scaffold does not automatically approve or
reject a package based only on its SPDX expression.

## Status and diff

```bash
cognix-vendor status --manifest-path ../cognix/Cargo.toml
cognix-vendor diff --manifest-path ../cognix/Cargo.toml
```

The baseline is `metadata/cognix/packages.json`. Status compares package
identity/source/version and the `Cargo.lock` digest. Diff prints added, removed,
and version-changed packages. Run `sync` only after reviewing the diff.

## Report

```bash
cognix-vendor report --format json --output build/dependencies.json
cognix-vendor report --format text
```

## Cognix integration

1. Add this repository as a pinned Git submodule (or another immutable checkout)
   under Cognix, for example `third_party/cognix-vendor`.
2. Populate and review its `vendor/` directory.
3. Copy/merge the *complete* generated source-replacement configuration into
   Cognix's `.cargo/config.toml`.
4. Adjust the generated `directory` path so it resolves to
   `third_party/cognix-vendor/vendor` from the Cargo configuration context.
5. Preserve Cognix's existing build flags, environment variables, `[patch]`
   entries, and any existing source configuration.
6. Test with `cargo build --locked --offline` in a clean environment after
   ensuring all non-Cargo build prerequisites are installed.

Do not invent a single crates.io replacement block for a workspace that has
Git dependencies or patched sources: retain every mapping emitted by Cargo.
