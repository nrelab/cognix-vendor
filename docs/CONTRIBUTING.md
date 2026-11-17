# Contributing

- Keep dependency resolution delegated to Cargo.
- Do not hand-edit generated `vendor/` files or checksum manifests.
- Submit vendor refreshes with the corresponding consumer `Cargo.lock` change
  or an explicit explanation of why the lockfile is unchanged.
- Include a status/diff report and audit results in the pull request.
- Preserve all upstream licenses and notices.
- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo test --workspace` before submitting.
