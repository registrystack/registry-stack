# Registry Adapter

Use the Registry Adapter to expose existing records through a standard
registry API or ingest them into a registry workflow.
The Adapter runs reviewed integration routes over that source. Its facade
serves a declared API, such as the `breg-records` profile, by translating each
request. Its ingestion job reads bounded source pages and delivers their
reviewed projection either to a BReg Action or to a Coordinator workflow.
The facade holds no records; the job stores item identity and progress, never
source payloads. The institution's registry remains the system of record.

Source-system knowledge and deployment mappings live in reviewed configuration. A reviewed, versioned pack
declares a source's endpoints and route templates, with field mapping in
Rhai scripts beside it; a project binds a pack to a profile's operations; a
runtime config supplies origins, credentials, and the facade's issuer. The
engine is a bounded port of Apache Camel's route model, so packs use Camel's
EIP names and semantics. A new source system is a new pack, not a Rust
change.

The [GovStack facade specification](CONSULTATION.md) defines the built-in
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

The [product concept](CONCEPT.md) is the contract: artifact model, engine,
exchange contract, failure semantics, authorization, audit, configuration
formats, and verification. The
[effective operation contract](EFFECTIVE-CONTRACT.md) describes what one
loaded Adapter process exposes to an external gateway.

## Status

Released from Registry Stack 0.45.1, pre-1.0. The configuration formats are
`v1alpha1` and may change without migration. `CONCEPT.md` section 8.10
records each ported concept and its evidence. Section 17 owns the ingestion
contract and its declared limits.

## Install

From 0.45.1, each Registry Stack release publishes the `adapter` runtime and
the `adapterctl` author tool for Linux amd64, Linux arm64, and macOS arm64 on the
[release page](https://github.com/registrystack/registry-stack/releases),
checked against the release `SHA256SUMS`. Linux assets are executables named
`<binary>-<tag>-linux-<arch>`; macOS assets are `.tar.gz` bundles with the
executable, its AWS-LC-FIPS libraries, and notices. There is no Adapter
container image; build one from this repository if you need it.

Authenticate the checksum bundle as
[`release/VERIFY.md`](../../release/VERIFY.md) describes, then install the
binaries with the release-pinned installer or as an `rstack` component:

```sh
bash adapter-vX.Y.Z-install.sh
adapterctl --version

rstack install adapter
rstack adapter check --help
```

The installer puts the two binaries in `~/.local/bin`; set
`ADAPTER_INSTALL_DIR` to change that. `rstack install adapter` installs the
same two binaries into an `rstack` generation, and `rstack adapter` runs
`adapterctl`. Neither path needs a Rust toolchain.

`adapter-job`, the governed-ingestion job host, is not yet released. Build it
from this repository with `cargo build --release --locked -p
registry-adapter-job --bin adapter-job`, adding the features for the sources
(`job-file`, `job-postgres`) and destinations (`direct-breg`,
`signed-coordinator-event`) you need; a default build delivers nowhere.
[`CONCEPT.md`](CONCEPT.md) section 17 records what the job host serves.

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
| `schemas/` | Generated JSON Schemas for eight formats (profile, pack, project, runtime, job, job runtime, fixture, effective contract) |
| `profiles/` | Facade profiles: `breg-records`, plus `case-api`, which proves the exposed API is configuration. The GovStack Consultation and Write protocol is built in and needs no profile file |
| `packs/` | Maintained facade and ingestion packs: `dhis2-tracker`, `opencrvs-events`, `breg-records`, `kobotoolbox` and `odk-central` |
| `examples/` | Example projects that bind the packs to profiles, and the registered format examples |
| `fixtures/` | Recorded or documented upstream exchanges for the maintained packs, the bad-authoring `corpus/`, and `source-shapes/` |
| `fixtures/source-shapes/` | Authored packs over five upstream API shapes (FHIR R4 search and conditional create, Relay GraphQL, JSON:API behind mTLS, and a second target profile); each README states what the shape proves and the gaps it records |
| `scripts/` | Product gates and helpers |

## Try an example

The Adapter is unreleased, so run `adapterctl` from a checkout. From the
repository root, with `CARGO_TARGET_DIR` set to a directory outside the
repository, check, compile and replay the
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

## Grant the runtime database role

Serving needs TLS to PostgreSQL, even on loopback: `database.testOnlyPlaintext`
is refused outside test builds. Without a configured root the system roots
verify the server; when the certificate comes from a private CA, name that CA
with `database.trustedRootCertificateRef`.

`adapter serve` migrates through `database.migrationUrlRef` and serves through
`database.runtimeUrlRef`. The migration role owns the tables. Give the runtime
role only the grants its deployment uses; it is refused at startup, naming each
missing grant and table, before it listens. With `adapter` standing for the
schema on the runtime role's search path and `runtime` for that role:

```sql
-- Every deployment: append journal events, run audit.retentionDays, report readiness.
GRANT USAGE ON SCHEMA adapter TO runtime;
GRANT INSERT, SELECT, DELETE ON adapter_journal_events TO runtime;
GRANT SELECT ON adapter_schema_migrations TO runtime;

-- A deployment that serves any write: idempotent claims, response custody and the expiry sweep.
GRANT SELECT, INSERT, UPDATE, DELETE
  ON adapter_idempotency_entries, adapter_idempotency_resumes TO runtime;

-- A deployment that declares asyncCompletion or a resumable write: the artifact fence.
GRANT SELECT, INSERT, UPDATE ON adapter_idempotency_async_artifacts TO runtime;

-- A deployment that declares a resumable write: its checkpointed identifiers.
GRANT SELECT, INSERT ON adapter_idempotency_resume_bindings TO runtime;
```

The runtime role needs no grant on `adapter_idempotency_schema_migrations`;
only the migration role reads it.

## Recover a multi-effect facade write

Use the [facade recovery example](examples/facade-recovery/README.md) when a
source process is one fixed sequence of provider-idempotent HTTP operations.
It shows identifier-only checkpoints, same-body and same-key recovery at the
first unfinished step, the artifact and lease fences, and the authoring shapes
the Adapter refuses because skipped source-response state is not
reconstructible in this closed subset. Later reads from the digest-bound,
resupplied caller record are not supported, though they would not inherently
depend on stored payloads.

## Operate an SFTP job source

The default-off `job-sftp` host is read-only. Give it a dedicated source
account whose server-side authorization confines that account to the configured
`baseDirectory`, using a chroot or an equivalent SFTP-server policy. SFTP v3
has no portable atomic `open-beneath` or no-follow operation: client symlink and
canonical-path checks are defense in depth, not the confinement boundary.

Choose exactly one completed-file protocol:

- `completed-name` means the producer writes under another name, closes it,
  then atomically renames the complete bytes into the final candidate name.
- `done-file` means the producer removes any stale marker before replacing a
  same-name file, writes under another name, closes it, atomically renames the
  complete bytes into place, then publishes the marker last. This read-only consumer
  never removes markers. Leaving an old marker while overwriting in place is an
  unsupported producer protocol and cannot be made safe by size, timestamp, or
  marker rechecks.

Pin one complete OpenSSH Ed25519 or P-256 public key and use only secret
references for the password or private key. The maintained
[`sftp-source` example](examples/sftp-source/README.md) shows the runtime shape
and producer lifecycle.

Each page downloads the whole file, up to `maximumFileBytes`, within the
`pollEnrich` step's `timeoutMilliseconds`. Size that timeout to at least the file
size divided by the link bandwidth, and keep the number of pages per file low
(a larger `maximumRowsPerPage` means fewer pages). Otherwise the pass stops with
`adapter.job.read-timeout` and the next pass starts the same page again.

## Read a PostgreSQL view

A job can page a read-only query over a PostgreSQL view and register each row in
BReg. The [`postgres-source` example](examples/postgres-source/README.md) ships
the view SQL, the paged query, the pack, the job and the runtime binding, and
says how to adapt them to your own table.

## Operate a RabbitMQ job source

The default-off `job-rabbitmq` host reads one message at a time with the
explicit `rabbitmq-json` profile and manual source-owned settlement. Production
builds require AMQPS with system roots or an operator-captured private CA.
Plain AMQP exists only behind the named loopback fixture feature and is not a
production runtime option.

Publish immutable events with a unique, stable AMQP `message-id`. The job key
combines the configured namespace with that identity. Its stored digest
domain-separates the raw-message revision from the declared projection digest,
so neither a changed body nor a reviewed normalization change can silently
skip. Reuse of one identity for changed event bytes or projection is retained
as `adapter.job.rabbitmq-event-changed` and held for an operator; it is not
delivered or acknowledged automatically.

Publishers must also set `delivery_mode=2` and wait for publisher confirms.
The host rejects a delivery without mode 2 to the configured DLQ under
`adapter.job.rabbitmq-delivery-mode`; it cannot tell whether the producer
received a publisher confirm. The dedicated source principal needs only the
resource-scoped configure/write/read regexes in the maintained example, not a
broker administrative tag.

An acknowledged destination outcome is written to PostgreSQL before the broker
delivery is acknowledged. An item-scoped refusal is written before the
delivery is rejected without requeue, so the configured durable DLX and DLQ
receive it. Pending, stopped, crashed, and held deliveries remain unsettled and
requeue when their channel closes. A held message can therefore remain at the
head of a queue and delay later messages; use operational queue partitioning
where head blocking is unacceptable. The job stores identity, digest, state,
and destination references only, never message payloads or broker credentials.
Settlement uses the poll operation's finite deadline. A timeout is uncertain,
keeps source position safe, and reconnects on a later bounded read; the host
does not leave Lapin's detached automatic-recovery loop running.

This source uses AMQP `basic.get`, which is not governed by broker prefetch.
`maximumOutstandingDeliveries` is a local semaphore bound over unsettled
deliveries. Lapin has already assembled a body before the job can apply its
retained-message ceiling, so every authenticated institutional broker must set
RabbitMQ's hard `max_message_size` no higher than the deployment ceiling. This
client does not claim to attest that broker setting. Queue `--dry-run` refuses
before broker acquisition because AMQP 0-9-1 has no side-effect-free peek and
even requeueing can consume a delivery attempt.

The [`rabbitmq-source` example](examples/rabbitmq-source/README.md) shows the
authored endpoint, strict decoder, runtime TLS and dead-letter bindings, and
the broker-side requirement.

## Resolve held job items

`adapter-job status` reports aggregate `holdGuidance` by code. Use
`adapter-job inspect` for the item-level `hold`, including the stored
`destinationReference` when one exists, the `actionOwner`, and the static
`nextAction`. These reports are observational: the Adapter has no generic
unhold, retry, accept, or acknowledge mutation. A held row remains held, and
an unchanged held item is skipped by ordinary passes and rescans. Resolve a
BReg outcome in BReg, or a Coordinator Run and linked review in their owning
products.

A refusal the destination answered is stored as
`adapter.job.breg.<word>` or `adapter.job.coordinator.<word>`, where `<word>`
is the destination's own refusal word. The prefix says which product to ask;
the word is the one its documentation uses.

For `adapter.job.rabbitmq-event-changed`, first establish any possible
destination outcome. The broker operator then resolves the old unsettled
delivery under approved broker policy. Only after that does the source
operator correct immutable-identity and version handling for legitimate
later messages. Publishing a new message ID does not clear the old held row or
acknowledge its delivery; that delivery can continue to block the queue head.

A pass that stops as `adapter.job.projection-flat-dotted-name` read a row
whose flat member is named like a dotted `projection.fields` entry, such as a
CSV column headed `household.size`. A dotted field reads a nested object, so
the projection would hand the destination a `null`; the pass stops before
staging the page instead, and nothing on it is delivered. Group the columns
into a nested object in the route (a `setBody` that builds
`{"household": {"size": ...}}`), or read a source that delivers the nested
object, then run the job again.

A pass that stops as `adapter.job.identity-migration-required` found stored
file or SFTP items that predate the job's item-identity binding (store
schema 103), including a legacy raw decoder whose authored semantics did not
change. This is a stop, not a held item. HTTP and PostgreSQL jobs do not
receive it. Confirm the job definition is the one you intend to run, stop any
running pass or loop, then run
`adapter-job rebind-identity <job.yaml> --pack <pack> --runtime <runtime>`
once. It records the job's current identity and keeps the stored items and
cursor, so the next pass reads source rows as new and may deliver them
again. The host never infers identity from stored keys, rewrites rows, or
resets the cursor automatically. To keep the old identity instead, restore the
previous job definition. `pass --dry-run` shows the same stop before reading a
page. The [Kobo job operations guide](examples/kobotoolbox-job/OPERATIONS.md)
describes the receipt and the audit line. The job store keeps no audit row for
the rebind; the stderr line and the stdout receipt are the record, so keep both
in your log pipeline.

A pass that stops with `adapter.job.page-bytes-bound` built a page larger than
`profile.maximumPageBytes`. The cursor does not move, so every later pass
stops at the same place until you change the profile. Lower
`profile.read.maximumRowsPerPage` (or the file source's `maxMessagesPerPoll`) so
a page fits, or raise `profile.maximumPageBytes`, which cannot exceed
`profile.maximumResponseBytes`. Then run the job again.

`profile.maximumPageBytes` is checked after a page is built, not while it is
built: a file or PostgreSQL source reads up to `maximumRowsPerPage` rows
before the check runs, so a page can be larger than the bound in memory before
the pass stops. The real memory ceiling is therefore
`maximumRowsPerPage * maximumRowBytes`; size those two members, not only
`maximumPageBytes`, to the memory you can spare. The stop report prints the
same fix as its `next` step.

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
application deployment drill; `CONCEPT.md` section 17.7 states that a named
test is not a claim that a controlled deployment has passed.

To check one project by hand:

```sh
adapterctl check products/adapter/examples/dhis2-tracker/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml
```
