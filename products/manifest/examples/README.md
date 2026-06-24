# Examples

Use the checked-in profile fixtures as runnable examples.

Validate:

```sh
cargo run -p registry-manifest-cli -- validate profiles/example-civil-registration/fixtures/metadata.yaml
```

Render BRegDCAT-AP JSON-LD:

```sh
cargo run -p registry-manifest-cli -- render profiles/example-civil-registration/fixtures/metadata.yaml --format bregdcat-ap
```

Publish a static metadata bundle:

```sh
cargo run -p registry-manifest-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml --out target/metadata/public
```
