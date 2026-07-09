# Manifest fuzz targets

cargo-fuzz harnesses for Registry Manifest parse and render boundaries. This
crate declares its own empty `[workspace]` table and is listed in the root
`Cargo.toml` `exclude` list, so fuzz builds do not block normal workspace
checks.

## Targets

- `metadata_manifest_yaml` exercises YAML deserialization into the real
  `MetadataManifest` type, validation, digesting, compilation, and every
  exported renderer that can be reached from a compiled manifest.
- `rendered_artifact_json` exercises JSON parsing for rendered artifacts,
  canonical JSON hashing, metadata-manifest JSON deserialization, and
  `EvidencePackMetadata` policy-hash verification.

The targets use exported `registry-manifest-core` types and functions directly.
They do not declare local mirror structs for product types.

## Running locally

```bash
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60 -rss_limit_mb=1024
```

Requires the nightly toolchain and `cargo-fuzz` (pinned to 0.13.2 in CI;
`cargo install cargo-fuzz --version 0.13.2` matches). `fuzz/Cargo.lock` pins
this crate's dependencies independently of the main workspace lockfile.

## Corpus

`fuzz/corpus/<target>/` holds hand-written seeds: valid manifests, near-valid
manifests, rendered artifact JSON, and policy fragments. The `.gitignore` here
excludes `artifacts/`, `target/`, and libFuzzer's generated 40-hex-character
corpus entries; if a generated input is worth keeping permanently, copy it into
the seed corpus under a descriptive name instead of committing the raw generated
filename.

## CI wiring

`.github/workflows/nightly-security.yml` runs a smoke pass for every committed
target when the nightly security workflow runs. The job uses the nightly
toolchain, `cargo-fuzz` 0.13.2, `-max_total_time=60`, `-rss_limit_mb=1024`, and
uploads `fuzz/artifacts/` on failure.
