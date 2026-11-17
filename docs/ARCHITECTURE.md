# Architecture

## Principles

- Cargo owns dependency resolution, lockfile semantics, and vendoring.
- Cognix's `Cargo.lock` is the approved dependency resolution input.
- The vendor directory is generated output and should never be hand-edited.
- Metadata is an auditable snapshot, not another package resolver.
- Source provenance, integrity, security, and license review are separate checks.

## Data flow

```text
Cognix Cargo.toml + Cargo.lock
              |
              v
        cargo metadata
              |
              v
    metadata/cognix/packages.json
              |
              +---------------------+
              |                     |
              v                     v
         cargo vendor          snapshot/provenance
              |
              v
           vendor/
              |
              v
 .cargo-checksum.json verification
              |
              v
        review + CI + PR
```

## Separation of responsibilities

- `cargo_metadata`: reads Cargo's resolved workspace metadata.
- `cargo vendor`: downloads/copies exact package sources and emits Cargo config.
- `cognix-vendor verify`: validates files against Cargo's checksum manifests.
- `cargo audit`: checks RustSec advisories.
- `cargo deny`: enforces configured license, source, and advisory policy.
- Git review: approves source and metadata changes before publishing.

## Future extensions

- Multiple consumer snapshots (`metadata/<consumer>/`).
- SBOM export in SPDX or CycloneDX format.
- Git source provenance, commit signatures, and allowlisted hosts.
- License expression policy evaluation and full license text collection.
- Signed release manifests and reproducible archive export.
- CI that regenerates a snapshot and fails on uncommitted drift.
