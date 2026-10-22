# Examples

Use the checked-in profile fixtures as runnable examples. Run these commands from
the repository root.

Validate:

```sh
cargo run --locked -p registry-manifest-cli -- validate products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml
```

Render BRegDCAT-AP JSON-LD:

```sh
cargo run --locked -p registry-manifest-cli -- render products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml --artifact-format bregdcat-ap
```

Publish a static metadata bundle:

```sh
cargo run --locked -p registry-manifest-cli -- publish products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml --output target/metadata/public
```
