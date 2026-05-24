# registry-manifest-cli

Command-line validation, rendering, static publication, and profile fixture
validation for Registry Manifest.

The binary name is `registry-manifest`.

## Commands

Validate a metadata manifest:

```sh
cargo run -p registry-manifest-cli -- validate profiles/example-civil-registration/fixtures/metadata.yaml
```

Render one artifact:

```sh
cargo run -p registry-manifest-cli -- render profiles/example-civil-registration/fixtures/metadata.yaml --format catalog
```

Publish a static metadata directory:

```sh
cargo run -p registry-manifest-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml --out target/metadata/public
```

Validate all checked-in profile descriptors and fixtures:

```sh
cargo run -p registry-manifest-cli -- validate-profiles profiles
```

## Supported Render Formats

- `catalog`
- `evidence-offerings`
- `evidence-offering` with `--offering <id>`
- `policies`
- `policy` with `--dataset <id>`
- `dcat`
- `bregdcat-ap`
- `shacl`
- `json-schema` with `--dataset <id> --entity <name>`
- `ogc-records`

## Boundary

The CLI wraps `registry-manifest-core`. It reads and writes local files, but it
does not contact Registry Relay, require a running service, read secrets, or
inspect runtime data sources.

## Testing

```sh
cargo test -p registry-manifest-cli
```

## License

Apache-2.0.
