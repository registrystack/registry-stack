# OpenCRVS Consultation exact reads

This project exposes a birth-summary view through Retrieve and exact Lookup.
The reusable source route resolves one registered event by tracking ID and
returns its native data; the project script selects the public fields.
List, Search, revision history and temporal features are unavailable.

All fixtures are documented synthetic exchanges, not captures. Retrieve and
lookup were checked live against an OpenCRVS test environment in November 2026;
the OpenCRVS version could not be read, so the tested-version list remains empty.

From the checkout root, set `CARGO_TARGET_DIR` to an external build directory.
The commands validate the pinned pack, project scripts and schemas, generate
the concrete OpenAPI contract, and execute the recorded source exchanges.
No running source, database or caller token is needed for this offline journey.

```sh
cargo run --locked -p registry-adapterctl -- check products/adapter/examples/opencrvs-consultation/project.yaml \
  --pack products/adapter/packs/opencrvs-events/pack.yaml \
  --fixtures products/adapter/examples/opencrvs-consultation/fixtures/exact-reads.yaml

cargo run --locked -p registry-adapterctl -- compile products/adapter/examples/opencrvs-consultation/project.yaml \
  --pack products/adapter/packs/opencrvs-events/pack.yaml

cargo run --locked -p registry-adapterctl -- fixtures replay products/adapter/examples/opencrvs-consultation/project.yaml \
  --pack products/adapter/packs/opencrvs-events/pack.yaml \
  --fixtures products/adapter/examples/opencrvs-consultation/fixtures/exact-reads.yaml
```

The project selects the built-in protocol through `consultation`. Each
collection references one `dataSchema` in the pinned `artifacts.schemas`
inventory. `bindingTransforms` selects a project script for each enabled
operation. Use `adapterctl project lock` after reviewing changes to these
artifacts, then repeat check and replay. Standard paths and envelopes require
no authored profile file.

A serving deployment supplies its own `runtime.yaml` using the example as a
starting point. Publish the generated contract at the project's declared
version-specific HTTPS `consultation.contract` URI. Authenticated callers use
`GET /govstack/registries/v1/capabilities` to discover their enabled operations
and follow that contract for input and payload schemas. The generated OpenAPI
uses `/govstack/registries` as `servers.url`, with the `/v1/...` operation paths
relative to that base. Discovery grants no Record access.

The selected surface is a profile of an unratified GovStack draft and does not imply full GovStack conformance or certification.
