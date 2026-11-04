# DHIS2 Consultation views

This project exposes three schema-bound views of the same DHIS2 source entities.
Retrieve, exact Lookup, List and organisation-unit Search use reusable native
source routes. The project scripts select each view after acquisition. The
`person-public` and `person-summary` views disclose no source attributes; the
`person-registration` view discloses exactly one, the date of birth. Pagination requests an explicit created-time
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
  --fixtures products/adapter/examples/dhis2-consultation/fixtures/retrieve-public.yaml \
  --fixtures products/adapter/examples/dhis2-consultation/fixtures/retrieve-person-registration.yaml

cargo run --locked -p registry-adapterctl -- compile products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml

cargo run --locked -p registry-adapterctl -- fixtures replay products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  --fixtures products/adapter/examples/dhis2-consultation/fixtures/retrieve-public.yaml \
  --fixtures products/adapter/examples/dhis2-consultation/fixtures/retrieve-person-registration.yaml
```

The project selects the built-in protocol through `consultation`. Each
collection references one `dataSchema` in the pinned `artifacts.schemas`
inventory. The collection `transform` selects the project script its
enabled operations follow; `bindingTransforms` overrides it for one binding. Use `adapterctl project lock` after reviewing changes to these
artifacts, then repeat check and replay. Standard paths and envelopes require
no authored profile file.

## The generated `person-registration` view

`person-registration.mapping.yaml` is an `AdapterMapping` model. It is the
source of truth for `scripts/person-registration.rhai`, which the project pins
like any other script, and it maps three source values into the closed
`schemas/person-registration.schema.json`:

| Source selection | Target | Rule |
| --- | --- | --- |
| `orgUnit` | `registration.organisationUnit` | Copy string |
| `updatedAt` | `registration.lastChangedAt` | Copy string |
| `attributes[attribute = "Dob00000001"].value` | `person.dateOfBirth` | Exactly one match; `convert: date` |

The attribute is selected by its UID from the `attributes` array. No other
attribute is read, so the second attribute in
`fixtures/retrieve-person-registration.yaml`, which holds the private canary
`PRIVATE-CANARY`, is absent from the expected body that `fixtures replay`
compares.

To change the view, edit the model (and the target schema if the output shape
changes), then regenerate, relock, and check:

```sh
cargo run --locked -p registry-adapterctl -- mapping generate products/adapter/examples/dhis2-consultation/person-registration.mapping.yaml
cargo run --locked -p registry-adapterctl -- project lock products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml
cargo run --locked -p registry-adapterctl -- compile products/adapter/examples/dhis2-consultation/project.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml
```

Hand-editing the generated script makes `adapterctl check` warn that it has
drifted from its model; edit the model instead.

`mapping preview` runs the generated script offline over source items you
supply, one bare DHIS2 tracked entity per JSON or YAML file. The synthetic
inputs in `preview/` cover an accepted entity, an entity with two
`Dob00000001` attributes, and an entity with an impossible date:

```sh
cargo run --locked -p registry-adapterctl -- mapping preview \
  products/adapter/examples/dhis2-consultation/person-registration.mapping.yaml \
  --input products/adapter/examples/dhis2-consultation/preview/accepted.json \
  --input products/adapter/examples/dhis2-consultation/preview/duplicate-date-of-birth.json \
  --input products/adapter/examples/dhis2-consultation/preview/invalid-date-of-birth.json
```

The accepted entity prints the validated result; the other two print a
categorical refusal ("the project transformation failed") that carries no
source value and does not say whether the cause was the duplicate or the date.
Runtime diagnostics are no finer than the engine provides. Pack fixtures hold
upstream exchanges rather than source items, so preview does not read them;
`fixtures replay` is the end-to-end proof over them.

The supported subset is the one in
[`VISUAL-MAPPING.md`](../../VISUAL-MAPPING.md): copy, keyed-array selection,
and `integer`, `text` and `date` conversions. A mapping does not establish
programme membership or enable an API operation; the collection, bindings and
`bindingTransforms` in `project.yaml` do.

A serving deployment supplies its own `runtime.yaml` using the example as a
starting point. Publish the generated contract at the project's declared
version-specific HTTPS `consultation.contract` URI. Authenticated callers use
`GET /govstack/registries/v1/capabilities` to discover their enabled operations
and follow that contract for input and payload schemas. The generated OpenAPI
uses `/govstack/registries` as `servers.url`, with the `/v1/...` operation paths
relative to that base. Discovery grants no Record access.

The selected surface is a profile of an unratified GovStack draft and does not imply full GovStack conformance or certification.
