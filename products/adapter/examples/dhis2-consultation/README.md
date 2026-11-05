# DHIS2 Consultation views

This project exposes two schema-bound views of the same DHIS2 source entities.
Retrieve, exact Lookup, List and organisation-unit Search use reusable native
source routes. The project scripts select each view after acquisition; neither
view discloses source attributes. Pagination requests an explicit created-time
order with the unique tracked-entity UID as its tie-breaker.

The fixtures are documented derivatives of scrubbed DHIS2 2.43.2.1 captures.
They verify the local Adapter journey and do not establish a production deployment.

From the checkout root, set `CARGO_TARGET_DIR` to an external build directory.
The commands validate the pinned pack, project scripts and schemas, generate
the concrete OpenAPI contract, and execute the recorded source exchanges.
No running source, database or caller token is needed for this offline journey.

```sh
cargo run --locked -p registry-adapterctl -- check products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  --fixtures products/adapter/examples/dhis2-consultation/fixtures/retrieve-public.yaml

cargo run --locked -p registry-adapterctl -- compile products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml

cargo run --locked -p registry-adapterctl -- fixtures replay products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  --fixtures products/adapter/examples/dhis2-consultation/fixtures/retrieve-public.yaml
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
