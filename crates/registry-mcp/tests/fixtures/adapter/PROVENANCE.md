# Adapter compatibility fixture

The golden effective contract was emitted by the real `adapter effective-contract`
command, built from this repository's `crates/registry-adapter`.
It used this directory's `runtime.yaml` and `govstack-facilities/project.yaml`
with the `govstack-consultation` profile and `dhis2-tracker` pack from
`products/adapter`, at the profile and pack digests that project file pins.
The pinned bytes are the producer revision: a changed pack or profile changes
`artifactDeploymentDigest` and with it the contract digest.

The export uses only synthetic identifiers and secret placeholders. It opens
no listener and contacts no database, issuer, or source. The compatibility test
pins both the complete file bytes and the producer-computed contract digest.
Regenerate it only from a producer whose profile and pack bytes match the pins
in the project files, and update this record, the project pins, and the fixed
expectations in `tests/adapter_contract.rs` together after reviewing producer
drift. From the repository root, with `adapter` built and the runtime library
path prepared by `scripts/cargo-runtime-library-path.sh`:

```bash
fixtures=crates/registry-mcp/tests/fixtures/adapter
ADAPTER_FIXTURE_USERNAME=synthetic-reader \
  ADAPTER_FIXTURE_PASSWORD=synthetic-password \
  ADAPTER_FIXTURE_DATABASE=postgresql://unused.invalid/test \
  ADAPTER_FIXTURE_CURSOR_KEY='synthetic-cursor-key-0123456789!' \
  "$CARGO_TARGET_DIR/debug/adapter" effective-contract \
  --runtime-config "$fixtures/runtime.yaml" \
  --project "$fixtures/govstack-facilities" \
  --profile products/adapter/profiles/govstack-consultation/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  >"$fixtures/govstack-facilities/effective-contract.json"
```

The `breg-facilities/project.yaml` fixture proves the same non-person facility
data configuration through the second supported facade. The ignored native
tests run a separately built Adapter binary (`ADAPTER_BIN`) over the
`products/adapter` tree (`ADAPTER_FIXTURES_ROOT`) and rewrite the profile and
pack pins to those bytes, so they never link the Adapter runtime.

The `optional-pagination` fixture was emitted by the same producer revision,
with `--project "$fixtures/optional-pagination"` and
`--profile "$fixtures/optional-pagination/profile.yaml"`.
Its local profile differs only by omitting `pageSizeDefault` from the
read-only POST search, which makes the producer export its anchored
cursor-or-page-size presence schema. The fixed export exercises consumer
compatibility with that real producer shape.
