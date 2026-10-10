# Registry Messaging

PostgreSQL 17 or newer is required for package activation and runtime startup.

Registry Messaging delivers operational messages, SMS and email, on behalf of
authorized callers. The caller decides why and when to send and who the
recipient is; Messaging owns rendering from reviewed templates, delivery
through operator-configured providers, and an accountable record of each
attempt. It is a native Rust runtime over PostgreSQL with no broker.

## Status

Not yet released. Messaging builds from source in this repository and now
uses the shared platform activation ledger. Registry Stack 0.38.0 is planned
to be the first release carrying its binaries, container image, and clients.

Pre-1.0 and under construction. This version is the product skeleton:

- the `messaging` runtime with `serve`, the converged runtime
  configuration, and the package's access profiles;
- OIDC bearer authentication, access-profile resolution, and the per-process audit
  journal, which records the runtime start and every template preview;
- the package: providers, sender profiles, and versioned templates rendered
  with bounded, loader-free Jinja, a JSON Schema per version, exact locales,
  and SMS segment counting;
- the shared activation ledger: the runtime serves only the configured
  database identity and package digest `messagingctl apply` recorded;
- the unauthenticated `/health` and `/ready` routes, the authenticated
  message submission, status, cancel, and template preview routes, the
  provider callback routes each provider's verifier authenticates, and
  `/metrics` on a separate private listener;
- message submission under a caller-scoped `Idempotency-Key`, rendered from
  the active package at acceptance and recorded with its dispatch job and
  dispatch state in one transaction, with direct request/response audit;
- the dispatch worker on the platform PostgreSQL dispatch substrate: leased
  claims whose outcome writes are fenced by the lease, retries bounded by the
  sender profile's dispatch policy, quarantine of a message whose send may
  have happened, and direct audit outcomes that distinguish attempted work from established
  commits;
- SMTP and HTTP provider delivery through the connections the runtime
  configuration gives the package's providers, and verified provider
  delivery callbacks whose receipts move a message's delivery report only
  forward;
- each access profile's request rate per caller and daily limit, and each
  provider's send rate;
- retention: payloads and records erased their configured periods after a
  message reached a terminal state, by the runtime's hourly sweep or on
  demand;
- `messagingctl init`, `package`, `check`, `preview`, `plan`, `apply`,
  `status`, `messages list`, `show`, `retry`, `settle`, and `cancel`,
  `retention erase-expired`, and `dev` with `dev token` for a local session;
- the Rust client for health, readiness, submit, status, cancel, and template
  preview, with Node.js and Python bindings;
- the security invariant matrix, the problem catalog, and the generated
  OpenAPI and runtime schema.

A provider the runtime configuration gives no connection is not activated, so the worker
fails its messages with the attempt failure code `provider-unconfigured`,
without a send, and startup logs a warning.

## Provider support

| Provider | Implemented boundary |
| --- | --- |
| SMTP relay | Built-in email transport |
| Twilio SMS | `examples/providers/form-sms-gateway`, with signed callbacks |
| AWS End User Messaging SMS | `examples/providers/aws-sms`, with SigV4-authenticated `SendTextMessage`; acceptance only, no delivery-event ingestion |
| Other HTTP gateways | Reviewed request/response scripts over configured HTTP connections |
| Mailpit and mock SMS | Local development transports |

The AWS example has offline and local wire-contract tests. A configured AWS
account, approved origination identity, and real destination are needed to
verify actual carrier delivery. See the [AWS provider guide](examples/providers/aws-sms/README.md).

## Product boundary

Messaging does not own why or when to send, recipient identity or contact
directories, consent to be contacted, or any registry mutation. Those stay
with the caller's source of record.

- No Messaging crate depends on a Base Registry Engine, Casework, Scheduling,
  Evidence, or Relay crate, and no crate of those products depends on the
  Messaging runtime or its tooling. Products reach Messaging over its public
  HTTP contract, like any external caller.
  `scripts/check_dependency_direction.py` enforces this on the forward
  closure of Cargo's resolved graph.
- Messaging inherits no authorization from a caller product. Being allowed to
  act on a Casework item does not make a caller allowed to send; the
  Messaging access profile decides.
- Messaging never writes to another product's database.

## Crates

| Crate | Owns |
|---|---|
| `registry-messaging-core` | Access profiles and their decisions, the package manifest, template checking and rendering, SMS segment counting, message visibility, the problem vocabulary, wire names and DTOs. No I/O. |
| `registry-messaging` | The runtime and the `messaging` binary: configuration, the package loader and digest, authentication, HTTP, metrics, the PostgreSQL store and shared activation ledger, and the audit journal. |
| `registry-messagingctl` | Adopter and local operator tooling, the `messagingctl` binary. |
| `registry-messaging-client` | The bounded Rust client over the runtime's HTTP contract. |

## Running locally

`messagingctl dev` runs a package end to end on one machine. It needs Docker:

```bash
messagingctl init ./notices
messagingctl dev ./notices
# in another terminal
messagingctl dev token case-system ./notices
curl -X POST http://127.0.0.1:8107/v1/messages \
  -H @./notices/.messaging/dev/tokens/case-system.header \
  -H 'content-type: application/json' -H 'Idempotency-Key: first' \
  --data '{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"}}'
```

The session runs in the foreground until Ctrl-C or SIGTERM and owns
everything it starts: a pinned PostgreSQL container serving TLS with a
certificate the session generates, a pinned Mailpit container every `smtp`
provider sends to, a mock gateway every `http` provider sends to, and the
Messaging runtime itself, in the `messagingctl` process, on a
`development-loopback` listener at `--port` (8107) with metrics at
`--metrics-port` (9107). Both containers publish on 127.0.0.1 only and are
removed with their volumes when the session stops, so nothing a session sent
or recorded outlives it. The mock gateway speaks the example provider under
`examples/providers/mock`: it answers each send after `--mock-latency-ms`
(200) and then posts a delivery report, signed with the session's callback
key, to the runtime's callback route, so an SMS reaches `delivered` and an
email reaches `submitted` with its message in Mailpit.

The session's secrets, generated `runtime.yaml`, audit journal, and JSON log
live in the project's private `.messaging/dev` directory (mode 0700, files
0600, ignored by git through `.messaging/.gitignore`), and the next start in
the project replaces it. A second start in the same project is refused while
the first runs. `messagingctl dev token CLIENT` signs a one-hour bearer token
for a client one access profile names, carrying that profile's scopes and
actor kind, with the key the running session's runtime trusts, and writes it
as a header file under `.messaging/dev/tokens/`. The tokens and the key are
for this session only; nothing about the session is a production posture.
`products/messaging/scripts/test-dev.sh` is the automated run of the same
path.

`.messaging/dev/session.json` is the session's record. It is written when the
session starts, as each container starts, and when the session is ready, and
holds `owner`, the value of the `org.registrystack.messagingctl.dev-owner`
label on every container the session started; `state`, `starting` or `ready`;
`containers`, the containers started so far; and `detail`, empty while
starting and the ready report once ready. Mailpit publishes on a port Docker
picks, so `detail.mailpit` is where a script reads the Mailpit address;
`detail.api`, `detail.metrics`, and `detail.mockGateway` name the other
endpoints. The next start in the project reads `owner` to remove the
containers an interrupted session left.

To run the runtime yourself, `messagingctl init DIRECTORY` creates an editable
project with `messaging.yaml`, `providers/`, and `templates/`. Check that
project, then use `messagingctl package` to write a separate installed package
with the shared checksum envelope. Keep the runtime configuration and secrets
outside the installed package. Copy `runtime.example.yaml`, set `package.root`
to the installed directory, and configure explicit listener addresses and
secret references:

```bash
messagingctl init ./notices
messagingctl check --project ./notices
messagingctl package ./notices --output ./notices-installed
messagingctl check --package ./notices-installed
messagingctl check --runtime-config /abs/path/runtime.yaml
messagingctl preview --runtime-config /abs/path/runtime.yaml \
  appointment-reminder 1 --locale fr \
  --data ./notices/templates/appointment-reminder/1/sample.json
messagingctl plan --runtime-config /abs/path/runtime.yaml
messagingctl apply --runtime-config /abs/path/runtime.yaml
messagingctl status --runtime-config /abs/path/runtime.yaml
messaging --runtime-config /abs/path/runtime.yaml serve
```

`--data` names a JSON file, read relative to the directory the command runs
in like any other relative path; each template version's `sample.json`
serves. `messagingctl plan` and `status` use the runtime credential in
read-only transactions. `messagingctl apply` uses the migration credential to
apply pending migrations, grant a separate runtime role only the required
runtime access, and append the activation in one locked transaction. `serve`
refuses an unknown schema, a different database identity or package, stale
runtime grants, or a weakened split-role boundary. A package change takes
effect on restart after `apply`. Every
`messagingctl` command takes `--format human|json` and exits 0 on success, 1
on a refusal, 2 on a usage error, and 3 when a file, secret, or database could
not be reached. A human failure is one `error[CODE] PATH: MESSAGE` line on
standard error with a `next:` line after it. A `--format json` report opens with
`ok`, `command`, and `status`, then names its format: `apiVersion` is
`id.registrystack.org/formats/messaging/ctl-report/v1alpha1` and `kind` is
`MessagingCtlReport`. A failure lists `diagnostics`; a successful
`preview` is the exception and prints the HTTP preview's body unwrapped.
`examples/formats/ctl-report.json` is the report `check` writes for the
starter project.
`MESSAGING_LOG` accepts `error`, `warn`, or `info` and nothing else.

`messagingctl messages list` and `show` report messages with the recipient
masked, each with its derived status and its dispatch state. `retry`
requeues a message whose dispatch failed as a new generation,
`settle --outcome sent|not-sent` resolves a message whose outcome is
unknown, and `cancel` cancels a queued one; each is decided on the dispatch
state, so a submitted message the provider reported undelivered is not
retried. Each action previews without
`--apply`, and an applied action uses its own request/response audit stream. A failed audit
response after commit reports unavailable while the database effect stays
authoritative. After recovery, inspect or retry according to the action
contract rather than assuming rollback. `RUNTIME-CONFIG.md` documents every key.

## HTTP contract

`generated/registry-messaging.openapi.json` is the contract; it is generated,
never hand-edited.

| Route | Authentication | Answer |
|---|---|---|
| `GET /health` | none | `200` with an empty body while the process serves |
| `GET /ready` | none | `200` when the database carries every expected migration, its activation ledger names the configured database identity and served package active under the current runtime role, and its audit writer is healthy, `503 service.unavailable` otherwise |
| `POST /v1/messages` | bearer, an access profile listing the sender profile and template, and an `Idempotency-Key` header | `202` with the message receipt; the same key and request answer the stored receipt again; `429 rate-limit.exceeded` past the caller's rate and `429 quota.exceeded` past the profile's daily limit, both with `Retry-After` |
| `GET /v1/messages/{message_id}` | bearer, the submitting principal (the same issuer and subject) or an operator | `200` with the status derived from the dispatch state and the delivery report, both of those, the recipient's channel with the value `redacted`, and the attempts; `404 message.not-visible` for any other message |
| `POST /v1/messages/{message_id}/cancel` | bearer, the submitting principal (the same issuer and subject) or an operator | `200` with the cancelled status; `409 message.dispatch-started` once dispatch started, `409 message.terminal` once it is final |
| `POST /v1/templates/{template_id}/versions/{version}/preview` | bearer, a sender profile listing the template | `200` with the rendered parts and the SMS segment count; persists nothing |
| `POST /v1/provider-callbacks/{provider_id}` and `POST /v1/provider-callbacks/{provider_id}/{token}` | the provider's configured callback verifier, no bearer | `204` once the receipt is read; `403 callback.unverified` for any callback that does not verify, `422 callback.unreadable` for one the receipt script cannot read; `429 rate-limit.exceeded` with `Retry-After`, before verification, past the provider's fixed callback rate |
| `GET /metrics` | metrics listener only | Prometheus text; never served on the public listener |

Every response carries a `traceparent` header. Problems are
`application/problem+json` with a type under
`https://id.registrystack.org/problems/registry-messaging/`:

| Code | Status |
|---|---|
| `request.invalid` | 400 |
| `authentication.refused` | 401 |
| `operation.not-authorized` | 403 |
| `profile.not-authorized` | 403 |
| `message.not-visible` | 404 |
| `request.not-found` | 404 |
| `request.method-not-allowed` | 405 |
| `idempotency.key-reused` | 409 |
| `message.dispatch-started` | 409 |
| `message.terminal` | 409 |
| `idempotency.expired` | 410 |
| `request.body-too-large` | 413 |
| `request.unsupported-media-type` | 415 |
| `request.unprocessable` | 422 |
| `callback.unverified` | 403 |
| `callback.unreadable` | 422 |
| `rate-limit.exceeded` | 429 |
| `quota.exceeded` | 429 |
| `template.not-found` | 404 |
| `template.data-invalid` | 422 |
| `template.locale-unavailable` | 422 |
| `template.render-refused` | 422 |
| `content.invalid` | 422 |
| `content.too-large` | 422 |
| `content.too-many-segments` | 422 |
| `service.unavailable` | 503 |

The preview body is `{"locale": "fr", "data": {...}}`. Its answer is the same
bytes `messagingctl --format json preview` prints for the same package,
template, locale, and data, less the final newline. The audit journal records
the caller's pseudonym, the template reference, and the outcome of each
preview, never the data or the rendered text.

## Throughput

`products/messaging/scripts/measure-throughput.sh` measures SMS dispatch on
one replica against the mock gateway of `messagingctl dev`, which answers
every request after 200 ms and signs a delivered callback 500 ms later. It
builds `messagingctl` in release, raises the sender's request rate so
admission is not the bound, submits 600 SMS from 32 concurrent callers, and
samples `messaging_provider_attempts_total{outcome="accepted"}` on the
metrics listener every 50 ms. The steady rate is the one between 10 and 90
percent of the messages. PostgreSQL runs in Docker on the same machine.

Measured on 2026-09-25 on an Apple M5 Max (18 logical CPUs, macOS,
PostgreSQL 17 in OrbStack), three runs:

| Run | Submission | All accepted by the provider | Steady dispatch |
|---|---|---|---|
| 1 | 600 in 0.56 s | 22.92 s | 26.3 SMS per second |
| 2 | 600 in 0.44 s | 27.16 s | 21.3 SMS per second |
| 3 | 600 in 2.00 s | 26.34 s | 23.2 SMS per second |

The worker runs eight lanes, each claiming, sending, and recording one
message at a time, so a 200 ms provider caps one replica at 40 SMS per
second. The rest of each lane's cycle, about 100 to 180 ms by the same
arithmetic, is spent outside the provider call. Every run met the target of
20 SMS per second per replica, the slowest by a small margin. The numbers
hold for this machine only; a slower database or a slower provider lowers
them.

## Verification

```bash
cargo build --locked -p registry-messagingctl
products/messaging/scripts/check-checkpoint.sh
products/messaging/scripts/check-contracts.sh
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_migrate
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_package
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_messages
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_dispatch
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_callbacks
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_retention
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messagingctl --features postgres-test --test postgres_messages_cli
products/messaging/scripts/test-dev.sh
```

The checkpoint runs the database-free checks: dependency direction,
database-suite isolation, the contract validator and its tests, the generated
artifact drift test, `messagingctl init` against the published starter,
`messagingctl check` over the starter, a pinned digest, and five refusals,
`messagingctl preview` byte stability, and `messagingctl messages` refusing a
malformed id and an unreachable database. `test-dev.sh` needs Docker: it
starts `messagingctl dev` on a starter whose SMS provider is the example mock
provider, sends one email and one SMS, requires the SMS to be `delivered`
through one applied signed callback and the email to be `submitted` with one
message in Mailpit, and requires the stopped session to leave no container.
Each PostgreSQL suite works in its own schema inside the database the
URL names and fails, rather than skipping, when the URL is absent. A test
binary that skips because its database is absent is not database
verification.

Regenerate the committed artifacts with:

```bash
cargo run -p registry-messaging --features schema --example runtime-schema -- \
  --output products/messaging/generated/runtime
cargo run -p registry-messaging --features schema --example openapi -- \
  --output products/messaging/generated
```
