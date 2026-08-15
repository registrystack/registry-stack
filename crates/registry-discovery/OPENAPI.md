# Discovery OpenAPI

`src/openapi.rs` owns the fixed route inventory and explicit schemas for the
Discovery HTTP wire models. The service embeds and serves the committed
`openapi.json` bytes without reserializing them at runtime.

Regenerate the document from the repository root:

```bash
cargo run --locked -p registry-discovery --example openapi -- --write
```

Check for drift without writing:

```bash
cargo run --locked -p registry-discovery --example openapi -- --check
```

The Discovery product contract gate runs the check in CI. The crate test suite
also compares the generator output with the exact embedded bytes.
