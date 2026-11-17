# Security model

The vendor repository is a source mirror, not a trust boundary by itself.

- Pin dependency resolution with the consumer's committed `Cargo.lock`.
- Use `cargo vendor --locked` and review all source changes.
- Preserve Cargo-generated checksum manifests and verify their listed files.
- Run `cargo audit` for RustSec advisories and `cargo deny` for policy checks.
- Prefer immutable Git revisions and review changes to `[patch]` entries.
- Treat package build scripts and procedural macros as executable code.
- Do not publish source until license and redistribution review is complete.
- Protect update workflows with required reviews and least-privilege CI tokens.

A checksum only detects a mismatch relative to its recorded value. It does not
establish who produced the source, whether the source is safe, or whether the
recorded checksum itself came from a trusted party.
