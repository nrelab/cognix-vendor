# Generated Cargo configuration

`cognix-vendor sync` writes the output of `cargo vendor` to
`cognix-source-replacement.toml`. Treat that file as generated output.

When integrating the vendor tree into Cognix, merge the complete generated
source-replacement sections into Cognix's `.cargo/config.toml`. Adjust the
`directory` value to point at the checked-out vendor directory from the Cargo
configuration's location. Preserve all generated Git-source replacement
sections; do not copy only the crates.io section.
