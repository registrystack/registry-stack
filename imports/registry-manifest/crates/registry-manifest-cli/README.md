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

Render a service-form JSON Schema:

```sh
cargo run -p registry-manifest-cli -- render fixtures/cpsv-ap/health-linked-child-support.metadata.yaml --format form-json-schema --form child-support-review-form
```

Publish a static metadata directory:

```sh
cargo run -p registry-manifest-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml --out target/metadata/public
```

By default, publishing writes every artifact, including `.well-known/api-catalog`
and `.well-known/registry-manifest.json`, inside the directory passed to
`--out`. Serve that directory as `/`; `/metadata/index.json` is the canonical
metadata entry point, `/.well-known/api-catalog` is the standards-facing
discovery document, and `/.well-known/registry-manifest.json` remains for
compatibility with older Registry Manifest clients.
`/metadata/index.json` includes the canonical `source_manifest_digest`, a
package-level digest, and SHA-256 digests for each indexed metadata artifact.

If the metadata bundle is a sibling of the site root rather than the site root
itself (for example, when `--out` points at `/srv/site/metadata-public/`), pass
`--site-root` so the discovery files land at the URL root:

```sh
cargo run -p registry-manifest-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml \
    --out /srv/site/metadata-public \
    --site-root /srv/site
```

With `--site-root SITE`, `.well-known/*` is written under `SITE/.well-known/`
while the metadata bundle still lands under `--out`. No files are written
outside `--out` (or `SITE`, when set).

Validate all checked-in profile descriptors and fixtures:

```sh
cargo run -p registry-manifest-cli -- validate-profiles profiles
```

Run the commons contract-kernel check, optionally with consumer manifests:

```sh
scripts/check-contract-kernel.sh ../registry-lab/config/static-metadata/metadata.yaml
```

The script runs formatting, clippy, workspace tests, checked-in profile
validation, and static publication for any passed consumer manifests.

## Supported Render Formats

- `catalog`
- `evidence-offerings`
- `evidence-offering` with `--offering <id>`
- `policies`
- `policy` with `--dataset <id>`
- `dcat`
- `bregdcat-ap`
- `cpsv-ap`
- `shacl`
- `json-schema` with `--dataset <id> --entity <name>`
- `form-json-schema` with `--form <id>`
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
