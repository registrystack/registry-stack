# Registry Adapter

Use the Registry Adapter to expose existing records through a standard
registry API or ingest them into a registry workflow.
The Adapter runs reviewed integration routes over that source. Its facade
serves a declared API, such as the `breg-records` profile, by translating each
request. Its ingestion job reads bounded source pages and delivers their
reviewed projection either to a BReg Action or to a Coordinator workflow.
The facade holds no records; the job stores item identity and progress, never
source payloads. The institution's registry remains the system of record.

The optional [typed payment host](examples/payment-collections/README.md)
shares the listener and PostgreSQL infrastructure while keeping payment
attempts outside generic record routes. Coordinator uses dedicated payment
steps. A collection reads an authoritative BReg fee bill; a disbursement
reads an authoritative [BReg instruction](../breg/examples/g2p-disbursement/README.md).
Operator configuration binds restricted registry Actions and an exact provider
pack. The host fixes credentials, origins and mutation methods while the pack
maps the provider's wire shape. The simulator remains synthetic. The Mifos
Payment Hub EE disbursement host signs exact retained Bulk requests through a
pinned Transit RSA key and verifies the released body-only Bulk response
signature with a separate pinned public key. Status reads use a distinct
operator-owned bearer credential against the configured HTTPS Operations
origin. Released Operations v1.17.1 does not enable route authorization by
default, so the deployment must enable and verify bearer authorization or
enforce it at a trusted gateway. Its unsigned status body remains a provider
report: the host independently compares its correlation, amount, currency,
funding party and recipient with the authoritative BReg instruction before
reporting confirmation. A missing Bulk response leaves the original send held
for operator or provider reconciliation because no accepted batch reference
exists for an Operations lookup; the host never submits it again. Mifos
Operations completion does not authorize a paid fee-bill receipt.

The Transit Unix socket must be an absolute local path protected by deployment
ACLs and a trusted proxy policy. Adapter pins the mount, key name, version and
SPKI SHA-256 digest for separate signing and response-verification keys.
Full Linux CI exercises `/none` with `prehashed: true` through OpenBao Transit
and its Unix proxy. The test uses a synthetic provider.

For a provider pack upgrade, repeat `--payment-provider-pack` with the current
pack and every retained pack still needed by an unfinished attempt. The host
selects each attempt's exact saved pin for sends and status reads; a missing
retained pack holds that attempt before provider I/O.

Source-system knowledge and deployment mappings live in reviewed configuration. A reviewed, versioned pack
declares a source's endpoints and route templates, with field mapping in
Rhai scripts beside it; a project binds a pack to a profile's operations; a
runtime config supplies origins, credentials, and the facade's issuer. The
engine is a bounded port of Apache Camel's route model, so packs use Camel's
EIP names and semantics. A new source system is a new pack, not a Rust
change.

The [GovStack facade specification](https://docs.registrystack.org/configure/adapter-consultation/) defines the built-in
Read and direct Write target, reusable source-pack boundary, project-owned
input/output transformations and schemas, and caller capability discovery.
The built-in target is mounted at `/govstack/registries`; its generated
OpenAPI contract uses that mount as `servers.url` and keeps `/v1/...` paths
relative to it.
It implements a profile of the unratified GovStack Digital Registries draft;
its selected capabilities do not imply general GovStack conformance or
certification.
Use the [DHIS2 Consultation example](examples/dhis2-consultation/README.md)
for two public views over the same native source routes, or the
[OpenCRVS exact-read example](examples/opencrvs-consultation/README.md) for
schema-bound Retrieve and Lookup. These projects omit `--profile`; the
GovStack protocol is built in. Source access remains in the reusable pack.
The [BReg HTTP Write example](examples/breg-govstack/README.md) selects
source-assigned Create and strong conditional Update with separate domain
input schemas and transformations. DHIS2 Write remains unavailable until
its source can preserve those guarantees.

An embedding host such as BReg can run a [reviewed projection
operation](https://docs.registrystack.org/configure/adapter/#external-projection-acquisition) for an exact read,
key batch or complete list for one parent. The host owns grants, disclosure
and any retention. See the [synthetic licensing
pack](examples/external-projections/README.md) for authoring and replay.

The [Adapter configuration page](https://docs.registrystack.org/configure/adapter/) states the contract: artifact model,
exchange contract, failure semantics, authorization, audit, configuration
formats, and verification. The
[effective operation contract](https://docs.registrystack.org/reference/adapter-effective-contract/) describes what one
loaded Adapter process exposes to an external gateway.

## Status

Released from Registry Stack 0.46.0, pre-1.0. The configuration formats are
`v1alpha1` and may change without migration. The
[route language](https://docs.registrystack.org/configure/adapter-routes/) page describes the ported
Camel concepts, and the [ingestion jobs](https://docs.registrystack.org/configure/adapter-jobs/) page owns the
ingestion contract and its declared limits.

## Install and operate

The `adapter` runtime and the `adapterctl` author tool are published with each
Registry Stack release. The install paths, the runtime database grants, and the
operation of ingestion jobs, SFTP and RabbitMQ sources, and held items are on
the docs site: [Operate the Adapter](https://docs.registrystack.org/operate/adapter/).
The job source settings are in
[Ingestion job sources](https://docs.registrystack.org/configure/adapter-ingestion-jobs/),
and the maintained KoboToolbox and ODK Central packs are in
[Adapter job packs](https://docs.registrystack.org/configure/adapter-packs/).
`adapter-job`, the governed-ingestion job host, is built from this repository
with `cargo build --release --locked -p registry-adapter-job --bin adapter-job`,
adding the features for the sources (`job-file`, `job-postgres`, `job-sftp`,
`job-rabbitmq`) and destinations (`direct-breg`, `signed-coordinator-event`) you
need; a default build delivers nowhere.
The [ingestion jobs](https://docs.registrystack.org/configure/adapter-jobs/) page records what the job host serves.

## Credit and licensing

The exchange model, the route and route-template model, the YAML DSL shape, the
enterprise integration pattern processors, the contract-first REST DSL, the error
handler, redelivery, and exception-clause semantics, the event notifier, and the
endpoint-interception testing idiom follow Apache Camel (Apache License 2.0), and
the pattern vocabulary follows the Enterprise Integration Patterns book of Hohpe
and Woolf. Circuit breaker semantics and defaults follow resilience4j (Apache
License 2.0) as Camel uses it. The config-first facade over legacy health systems
follows the OpenHIE interoperability layer tradition; connector manifest
versioning follows the Airbyte and Singer practice. The Rust precedent consulted
is rust-camel (Apache License 2.0, pre-release): its Tower-native rendering of EIP
patterns, its retry policy shape, and its error dispositions informed the route
engine. It is not a dependency: it is a general-purpose route framework with
code-first components, where the Adapter is a bounded facade whose system
knowledge is configuration.

No Camel code is copied (Camel is Java). The route language documentation cites
Camel's documentation rather than reproducing it. If documentation text or tables
are ever lifted, the Camel LICENSE and NOTICE ship beside them, and the product
documentation credits Camel and the EIP book regardless.

## Crates

| Crate | Owns |
|---|---|
| `crates/registry-adapter-core` | Source-neutral model, wire DTOs, `adapter.*` problem codes, and the pure authoring checks; no I/O |
| `crates/registry-adapter-engine` | Listener-free route compilation, execution, components and replay shared by the facade, job host and Evidence |
| `crates/registry-adapter` | The `adapter` binary: the governed facade, audit journal and idempotency store |
| `crates/registry-adapter-job` | The source-build `adapter-job` binary: bounded ingestion, item progress, scheduling and explicit destination delivery |
| `crates/registry-adapter-connectors` | BReg client integration reachable only through the job host's default-off `direct-breg` feature |
| `crates/registry-adapterctl` | The `adapterctl` binary: `check`, `compile`, `fixtures replay`, `verify --live`, and `schemas` |

## Layout

| Path | Holds |
|---|---|
| `schemas/` | Generated JSON Schemas for ten formats (profile, pack, project, runtime, job, job runtime, fixture, effective contract, mapping, preview expectations) |
| `profiles/` | Facade profiles: `breg-records`, plus `case-api`, which proves the exposed API is configuration. The GovStack Consultation and Write protocol is built in and needs no profile file |
| `packs/` | Maintained facade and ingestion packs: `dhis2-tracker`, `opencrvs-events`, `breg-records`, `kobotoolbox` and `odk-central` |
| `examples/` | Example projects that bind the packs to profiles, and the registered format examples |
| `fixtures/` | Recorded or documented upstream exchanges for the maintained packs, the bad-authoring `corpus/`, and `source-shapes/` |
| `fixtures/source-shapes/` | Authored packs over five upstream API shapes (FHIR R4 search and conditional create, Relay GraphQL, JSON:API behind mTLS, and a second target profile); each README states what the shape proves and the gaps it records |
| `scripts/` | Product gates and helpers |

## Try an example

These steps run `adapterctl` from a checkout. Release archives carry it
from 0.46.0. From the repository root, with `CARGO_TARGET_DIR` set to a
directory outside the repository, check, compile and replay the
[facade recovery example](examples/facade-recovery/README.md) offline. No
source, database or token is needed:

```sh
cargo run --locked -p registry-adapterctl -- check \
  products/adapter/examples/facade-recovery/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/examples/facade-recovery/pack.yaml \
  --runtime products/adapter/examples/facade-recovery/runtime.example.yaml

cargo run --locked -p registry-adapterctl -- compile \
  products/adapter/examples/facade-recovery/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/examples/facade-recovery/pack.yaml \
  --output /tmp/facade-recovery-openapi.json

cargo run --locked -p registry-adapterctl -- fixtures replay \
  products/adapter/examples/facade-recovery/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/examples/facade-recovery/pack.yaml \
  --fixtures products/adapter/examples/facade-recovery/fixture.yaml
```

`check` validates the project against its pinned profile and pack, and the
runtime configuration against both. `compile` writes the OpenAPI contract the
facade serves. `fixtures replay` runs the routes through the real engine
against the recorded source exchanges. The `dhis2-tracker`
and `opencrvs-events` facade examples take the same commands with their own
profile, pack and fixtures; `scripts/check-contracts.sh` runs each one. The
job examples use `adapterctl job check` instead; `kobotoolbox-job`,
`odk-central-job` and `postgres-source` give the command in their README or
`job.yaml` header.

## Recover a multi-effect facade write

Use the [facade recovery example](examples/facade-recovery/README.md) when a
source process is one fixed sequence of provider-idempotent HTTP operations.
It shows identifier-only checkpoints, same-body and same-key recovery at the
first unfinished step, the artifact and lease fences, and the authoring shapes
the Adapter refuses because skipped source-response state is not
reconstructible in this closed subset. Later reads from the digest-bound,
resupplied caller record are not supported, though they would not inherently
depend on stored payloads.

## Read a PostgreSQL view

A job can page a read-only query over a PostgreSQL view and register each row in
BReg. The [`postgres-source` example](examples/postgres-source/README.md) ships
the view SQL, the paged query, the pack, the job and the runtime binding, and
says how to adapt them to your own table.

The [QField PostGIS example](examples/qfield-postgis/README.md) reads a completed
offline submission from its original collection database and maps its point,
polygon and repeated rows into a BReg Action or Proposal.

## Check the product

Every cargo build runs in an explicit target directory outside the source
tree; the contract gate refuses to guess one.

```sh
export CARGO_TARGET_DIR=/path/to/your/target
products/adapter/scripts/check-contracts.sh
```

`check-contracts.sh` formats, lints and tests the facade, core, engine, job,
connector and authoring crates, including the declared feature lanes. It
holds the generated schemas and the effective-contract example to their
generators, runs the platform configuration-format lint and
`check-port-table.py`, checks and replays the examples, holds each source
shape to its committed contract and fixtures, and runs the bad-authoring
corpus. `products/adapter/scripts/test-postgres.sh` runs the
PostgreSQL-gated suites; without `ADAPTER_TEST_DATABASE_URL` it starts and
removes its own loopback PostgreSQL container. Docker is also required for the
real BReg-backed GovStack Write journey: the gate builds matching `breg` and
`bregctl` binaries and tests Create, conditional Update and uncertain-send
recovery through the real services. Its BReg development fixtures are stopped
and retained. To run only that journey against an existing test database, use
`products/adapter/scripts/test-govstack-breg-write.sh` with
`ADAPTER_TEST_DATABASE_URL` and `CARGO_TARGET_DIR` set.

`products/adapter/scripts/test-job-postgres.sh` also builds BReg and
Coordinator together from the current checkout and runs the ignored direct
BReg and signed Coordinator-event job proofs against their real binaries and
PostgreSQL. Set `CARGO_TARGET_DIR` explicitly and provide Docker; the wrapper
owns its pinned loopback PostgreSQL fixture and removes it on success or
failure. To run only those destination proofs against a caller-owned
disposable loopback database:

```sh
CARGO_TARGET_DIR=/path/to/your/target \
ADAPTER_TEST_DATABASE_URL=postgresql://user:password@127.0.0.1:5432/adapter \
python3 products/adapter/scripts/test-connector-native.py --suite job-destinations
```

This is native fixture evidence for destination admission, recovery, and
changed-item holds. It is not a controlled Kobo, review-provider, and
application deployment drill, and a named test is not a claim that a
controlled deployment has passed.

To check one project by hand:

```sh
adapterctl check products/adapter/examples/dhis2-tracker/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml
```
