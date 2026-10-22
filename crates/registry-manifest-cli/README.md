# registry-manifest-cli

Command-line validation, rendering, static publication, and profile fixture
validation for Registry Manifest.

The binary name is `registry-manifest`.
Run the commands below from the monorepo root.

## Commands

Validate a metadata manifest:

```sh
cargo run -p registry-manifest-cli -- validate products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml
```

Render one artifact:

```sh
cargo run -p registry-manifest-cli -- render products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml --artifact-format catalog
```

Render a service-form JSON Schema:

```sh
cargo run -p registry-manifest-cli -- render products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml --artifact-format form-json-schema --form child-support-review-form
```

Publish a static metadata directory:

```sh
cargo run -p registry-manifest-cli -- publish products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml --output target/metadata/public
```

By default, publishing writes every artifact, including `.well-known/api-catalog`
and `.well-known/registry-manifest.json`, inside the directory passed to
`--output`. Serve that directory as `/`; `/metadata/index.json` is the canonical
metadata entry point, `/.well-known/api-catalog` is the standards-facing
discovery document, and `/.well-known/registry-manifest.json` remains for
compatibility with older Registry Manifest clients.
`/metadata/index.json` includes the canonical `source_manifest_digest`, a
package-level digest, and SHA-256 digests for each indexed metadata artifact.

If the metadata bundle is a sibling of the site root rather than the site root
itself (for example, when `--output` points at `/srv/site/metadata-public/`), pass
`--site-root` so the discovery files land at the URL root:

```sh
cargo run -p registry-manifest-cli -- publish products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
    --output /srv/site/metadata-public \
    --site-root /srv/site
```

With `--site-root SITE`, `.well-known/*` is written under `SITE/.well-known/`
while the metadata bundle still lands under `--output`. No files are written
outside `--output` (or `SITE`, when set).
Publishing reports in human-readable form by default. Pass `--format json` for
the versioned JSON report; artifact files still go only to `--output` and never
to standard output. The retired `--out` option is refused with `--output` named
as its replacement.

Validate all checked-in profile descriptors and fixtures:

```sh
cargo run -p registry-manifest-cli -- validate-profiles products/manifest/profiles
```

`validate` and `validate-profiles` read through `registry-platform-yaml` and
print every finding as `severity[code] file:line:column /pointer` with the fix.
Both accept `--format json` and `--deny-warnings`, and exit 0 when nothing was
refused, 1 on a refusal, 2 on a usage error, and 3 when a file cannot be read.
The retired `--json` flag is refused with `--format json` named as its
replacement. `render` writes exact artifact JSON to standard output, so it uses
`--artifact-format` and refuses report `--format`.

Regenerate the editor schemas after changing a reader type:

```sh
cargo run -p registry-manifest-cli --features schema --example manifest-schema -- --output products/manifest/schemas
```

Run the commons contract-kernel check, optionally with consumer manifests:

```sh
SOLMARA_LAB_DIR=/path/to/solmara-lab
products/manifest/scripts/check-contract-kernel.sh \
  "$SOLMARA_LAB_DIR/metadata/solmara-wave1.metadata.yaml"
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
does not contact a running service, read secrets, or
inspect runtime data sources.

## Testing

```sh
cargo test -p registry-manifest-cli
```

## License

Apache-2.0.
