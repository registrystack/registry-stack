# Base Registry Engine

Base Registry Engine is a small PostgreSQL system of record whose data model and
REST surface are compiled from governed configuration. It is intended for
institutional registries that need reliable writes, history, access control,
and a safe way to evolve their schema without building a bespoke service.

Start with the [standalone examples](examples/README.md) for the current
Record type, Action, and Proposal model and its runnable PostgreSQL journeys.
The canonical projects include their local clients, journeys, and resumable scenarios.

The runtime has no built-in business, facility, authority, permit, or asset model.
A Record type, relationship, route, field, access profile, and event exists only
when an active Registry package declares it. For example, an establishment's
assignment to its operating business is an ordinary configured relationship.

BReg authoring uses `recordTypes` and `recordType`; `manifestProjection.entities`
keeps Registry Manifest vocabulary, and the record envelope carries the same
Record type as `recordTypeIdentifier` in the independent Registry Record contract.

The product starts with two executables:

- `breg` loads one verified package and serves its configured REST
  API against PostgreSQL.
- `bregctl` is deterministic tooling for authoring, checking,
  packaging, applying, and verifying Registry configuration.

AI-assisted authoring remains outside the production authority boundary. It
may propose configuration and run deterministic checks, but it cannot bypass
package review or the separate migration database role.

## Start a development run

With Docker running, create and start a small directory registry.

```sh
bregctl init ./directory
rstack dev start ./directory
```

Copy the run ID to stop the run with `rstack dev stop RUN`.

## First-hour local quickstart

Use the adopter guides for authoring, local evaluation, and operation.

- [Build a registry with Base Registry Engine](../../docs/site/src/content/docs/explanation/configuration-defined-registry.mdx)
- [Create and query your first registry](../../docs/site/src/content/docs/tutorials/first-breg.mdx)
- [Change a registry with an Action](../../docs/site/src/content/docs/tutorials/change-a-registry-with-an-action.mdx)
- [Query a spatial registry from QGIS](https://docs.registrystack.org/configure/breg-spatial-queries/)
- [Author a registry project](../../docs/site/src/content/docs/configure/breg.mdx)
- [Deploy and operate a registry](../../docs/site/src/content/docs/operate/breg.mdx)
- [Modeling patterns for registries](../../docs/site/src/content/docs/explanation/registry-modeling-patterns.mdx)
- [Base Registry Engine configuration reference](../../docs/site/src/content/docs/reference/breg-configuration.mdx)
- [Base Registry Engine API reference](../../docs/site/src/content/docs/reference/breg-api.mdx)

For a generic, domain-neutral local path, run:

```bash
products/breg/quickstart/run.sh
```

Pass `--installed` to use released `breg` and `bregctl` binaries from `PATH`
instead of building them from this checkout with Cargo.

The quickstart uses `bregctl init` to create a small generic
Registry project, replaces its package identity with a local one for the
disposable package, checks it, starts disposable PostgreSQL and the pinned stock
ThunderID issuer on loopback, activates an unsigned local package, obtains a
short-lived token, POSTs one record, and GETs that record back. Generated
configuration, keys, tokens, package artifacts, logs, and database URLs stay under
`products/breg/quickstart/.run/`, which is ignored by Git and
created owner-only.

Leave the quickstart terminal running, then use the printed record id in a
second terminal:

```bash
products/breg/quickstart/query.sh get <record-id>
```

The query helper reads the bearer token from an owner-only token file. It does
not put the token on the command line or print it. For a non-interactive local
smoke, run:

```bash
products/breg/quickstart/run.sh --smoke
```

To verify only the checked quickstart structure without Docker or network, run:

```bash
products/breg/quickstart/self-test.sh
```

This route is intentionally local-only: a run-scoped test issuer, loopback HTTP, disposable PostgreSQL, and an unsigned local package.
It is the first-hour learning path, not a shortcut around production package
review, operated database roles, TLS, migration review, or secret custody.

For a disposable local run that needs no checkout, Python launcher, or shell
script, `rstack dev` starts a project against installed binaries and Docker
PostgreSQL from a `dev.yaml` plan. [Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/)
describes it, and [examples/minimal](examples/minimal/README.md) shows a plan
for a BReg project.

`bregctl init <destination>` writes the complete [minimal directory](examples/minimal/README.md).
Use `--template facility-registry` for the complete [facility project](examples/facility/README.md).
Both are ordinary authored projects. A project's scenarios are requests in a
scenario file that its `dev.yaml` names, and `rstack dev start` sends them once
the registry is running. `bregctl init <destination> --from publicschema` derives
a new project from the PublicSchema reference model snapshot pinned in
`crates/registry-linkml`, either from the shipped `household` starter
selection (`--starter household`) or from an authored selection document
(`--selection <file>`); without either flag the command asks which concepts
and properties to select at the terminal. [Register and transfer a
facility](https://docs.registrystack.org/configure/breg/#register-and-transfer-a-facility), [Native persisted field
patterns](https://docs.registrystack.org/configure/breg-native-patterns/), and [Current membership
access](https://docs.registrystack.org/configure/breg-access/) describe modeling patterns a derived or starter
project can build on. An action handler can also be a WebAssembly module:
[WASM action handlers](https://docs.registrystack.org/configure/breg-wasm-action-handlers/) covers what ships, the
server-compatibility contract, operator configuration, and the upgrade and
rollback paths.
For institution-facing record numbers and codes, [Generated business
identifiers](https://docs.registrystack.org/configure/breg/#generate-business-identifiers) explains sequences, random codes,
uniqueness scopes, and migration from retained values.

## Build, run, and test

BReg is part of the Registry Stack Cargo workspace. Build both executables
from the repository root:

```bash
cargo build --locked -p registry-breg -p registry-bregctl --bins
```

Run the deterministic contract checks and the Rust tests:

```bash
products/breg/scripts/check-contracts.sh
cargo test --locked -p registry-breg -p registry-bregctl
```

Tests that reach SQL, migrations, revisions, or authorization need a real
PostgreSQL database; `AGENTS.md` lists the commands for each kind of change.
The operator lifecycle (check, test, package, plan, apply, serve) is documented
in [Deploy and operate a registry](https://docs.registrystack.org/operate/breg/), and the
authoring side in [Author a registry project](https://docs.registrystack.org/configure/breg/).

Base Registry Engine owns typed configured storage, generated REST contracts,
authorization, record revisions, audit ordering, idempotency, outbox creation,
and governed migrations. It does not provide a UI, GraphQL, workflow,
eligibility, payment, identity matching, SQLite support, a multi-registry
control plane, or runtime code plugins. PostgreSQL is the sole Version 1
database, and the administrator installs `btree_gist`.

## Directory map

- `acceptance/`: authored projects that exercise the compiler and binary
  against real PostgreSQL.
- `contracts/`: the machine-readable delivery catalog.
- `evidence/`: the reviewed registry, starter project, and proof for the
  Evidence lookup export.
- `examples/`: the canonical standalone projects, `bregctl init` starters, and
  the webhook receiver.
- `fixtures/`: compiler and runtime test fixtures.
- `generated/`: committed generated schemas and fixture outputs; regenerate,
  never hand-edit.
- `loadtest/`: load-test projects and scale notes.
- `quickstart/`: the scripted first-hour local path.
- `scripts/`: contract, generation, and PostgreSQL test scripts.
- `wasm-handler-sdk/`: the SDK for WebAssembly Action handlers.

## Guides on the docs site

- [Corrections and historical queries](https://docs.registrystack.org/configure/breg-history/)
- [Subject-facing access logs](https://docs.registrystack.org/operate/breg-access-log/)
- [Events and hooks](https://docs.registrystack.org/operate/breg-webhooks/)
- [Point queries and QGIS](https://docs.registrystack.org/configure/breg-spatial-queries/)
- [Immediate Actions](https://docs.registrystack.org/configure/breg-actions/)
- [Record timers](https://docs.registrystack.org/configure/breg-record-timers/)
- [Proposal configuration](https://docs.registrystack.org/configure/breg-proposals/)
- [Consent-gated reads](https://docs.registrystack.org/configure/breg-consent/)
- [Membership access](https://docs.registrystack.org/configure/breg-access/)
- [Statistical datasets](https://docs.registrystack.org/configure/breg-statistics/)
- [Task grants for governed writes](https://docs.registrystack.org/reference/breg-task-grants/)
- [Citizen MCP gateway](https://docs.registrystack.org/configure/breg-mcp/)
- [Event records](https://docs.registrystack.org/configure/breg-event-records/)
- [Portable metadata contract](https://docs.registrystack.org/reference/breg-api/)
- [Evidence lookup exporter](https://docs.registrystack.org/configure/breg-evidence/)
- [ODRL export](https://docs.registrystack.org/reference/breg-odrl-export/)
- [Security model](https://docs.registrystack.org/security/breg/)
- [Record timers and the future-activation example](examples/future-activation/README.md)

## Product contracts

The files in `contracts/` are the authoritative machine-readable delivery
catalog. They deliberately distinguish a `planned` invariant from an
`enforced` one. A planned row records a concrete threat and future refusal but
does not pretend that a test exists. The implementation change that enforces
it must add one resolving negative executable test in the same patch.

The projects under `acceptance/` are authored configuration inputs for the same
compiler and binary. The five baseline fixtures cover asset/site placement,
business establishments, facility inspections, environmental facilities, and
legal-entity registrations. The canonical [native projects](examples/README.md) exercise generated
CRUD, immediate multi-record Actions, and reviewed or no-review Proposals. These are not generated output or implicit
runtime models. The real-PostgreSQL pilot test executes the baseline fixtures,
while the public-binary adopter workflow proves activation, authenticated
data access, an additive upgrade, failure recovery, and unchanged server bytes
for the asset project. See [Proposal configuration](https://docs.registrystack.org/configure/breg-proposals/)
for the approval workflows.
For bounded institutional-agent authority and current-status checks, see
[task grants for governed writes](https://docs.registrystack.org/reference/breg-task-grants/).
For a chat assistant that reads a citizen's own data and prepares a
Proposal draft the citizen submits themselves, see the
[citizen MCP gateway](https://docs.registrystack.org/configure/breg-mcp/).
The separate `household-history` fixture proves correction batches and retained
snapshot answers through the same compiler and runtime.
The additional `spatial-service-sites` project covers governed Point queries
and the QGIS installation-client path described in
[Point queries and QGIS](https://docs.registrystack.org/configure/breg-spatial-queries/).
The [person-registration-rhai project](acceptance/person-registration-rhai/README.md)
combines a persisted native identifier pattern with an input-only immediate Rhai
handler, declared business refusal, coordinated creates and an optional patch.
See [native string patterns](https://docs.registrystack.org/configure/breg-native-patterns/) for stored integrity rules.
Its synthetic CLI cases assert computed effects and its PostgreSQL journeys
verify stored values and existing action authority and concurrency contracts.
For current native Proposal context pairing and independent application authority,
use the [canonical Casework review](../casework/examples/canonical-review/README.md).
The status service and human context reader have separate purpose-specific grants.
The [committed product events](../coordinator/examples/product-events/README.md)
journey shows record and Action effects starting independently authorized
Coordinator work through the shared signed event contract.

Run the current deterministic contract checks with:

```bash
products/breg/scripts/check-contracts.sh
```

Run the durable receiver's independent behavioral tests with:

```bash
python3 products/breg/examples/webhook-receiver/test_receiver.py -v
```

The [receiver example](examples/webhook-receiver/README.md) provisions no registry
or issuer. It demonstrates durable acceptance independently of BReg deployment.

