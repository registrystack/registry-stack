# Registry Adapter

Use the Registry Adapter when the records a caller needs already live in a
system you do not replace, and the caller expects a standard registry API.
The Adapter is a live translation facade: it serves a declared API, such as
the `breg-records` profile, by calling the source system on each request and
translating the answer. It holds no records of its own; the source system
stays the system of record.

All system knowledge lives in configuration. A reviewed, versioned pack
declares a source's endpoints and route templates, with field mapping in
Rhai scripts beside it; a project binds a pack to a profile's operations; a
runtime config supplies origins, credentials, and the facade's issuer. The
engine is a bounded port of Apache Camel's route model, so packs use Camel's
EIP names and semantics. A new source system is a new pack, not a Rust
change.

The [product concept](CONCEPT.md) is the contract: artifact model, engine,
exchange contract, failure semantics, authorization, audit, configuration
formats, verification, and the recorded decisions. The
[effective operation contract](EFFECTIVE-CONTRACT.md) describes what one
loaded Adapter process exposes to an external gateway.

## Status

Unreleased and pre-1.0. The configuration formats are `v1alpha1` and may
change without migration. The engine serves the read operations of the
`breg-records` profile over the compiled contract; `CONCEPT.md` section 8.10
carries the status of each ported Camel concept, and section 14 the
increments still to land.

## Crates

| Crate | Owns |
|---|---|
| `crates/registry-adapter-core` | Source-neutral model, wire DTOs, `adapter.*` problem codes, and the pure authoring checks; no I/O |
| `crates/registry-adapter` | The `adapter` binary: the governed facade, the Camel-port engine, the audit journal, and the idempotency store |
| `crates/registry-adapterctl` | The `adapterctl` binary: `check`, `compile`, `fixtures replay`, `verify --live`, and `schemas` |

## Layout

| Path | Holds |
|---|---|
| `schemas/` | Generated JSON Schemas for the six formats (profile, pack, project, runtime, fixture, effective contract) |
| `profiles/` | Facade profiles: `breg-records`, plus `case-api` and `govstack-consultation`, which prove the exposed API is configuration |
| `packs/` | Maintained packs: `dhis2-tracker` and `opencrvs-events` |
| `examples/` | Example projects that bind the packs to profiles, and the registered format examples |
| `fixtures/` | Recorded or documented upstream exchanges for the maintained packs, the bad-authoring `corpus/`, and `source-shapes/` |
| `fixtures/source-shapes/` | Authored packs over five upstream API shapes (FHIR R4 search and conditional create, Relay GraphQL, JSON:API behind mTLS, and a second target profile); each README states what the shape proves and the gaps it records |
| `scripts/` | Product gates and helpers |

## Check the product

Every cargo build runs in an explicit target directory outside the source
tree; the contract gate refuses to guess one.

```sh
export CARGO_TARGET_DIR=/path/to/your/target
products/adapter/scripts/check-contracts.sh
```

`check-contracts.sh` formats, lints, and tests the three adapter crates,
holds the generated schemas and the effective-contract example to their
generators, runs the platform configuration-format lint and
`check-port-table.py`, checks and replays the examples, holds each source
shape to its committed contract and fixtures, and runs the bad-authoring
corpus. `products/adapter/scripts/test-postgres.sh` runs the
PostgreSQL-gated suites; without `ADAPTER_TEST_DATABASE_URL` it starts and
removes its own loopback PostgreSQL container.

To check one project by hand:

```sh
adapterctl check products/adapter/examples/dhis2-tracker/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml
```
