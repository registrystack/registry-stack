# Registry Messaging

Registry Messaging delivers operational messages, SMS and email, on behalf of
authorized callers. The caller decides why and when to send and who the
recipient is; Messaging owns rendering from reviewed templates, delivery
through operator-configured providers, and an accountable record of each
attempt. It is a native Rust runtime over PostgreSQL with no broker.

## Status

Pre-1.0 and under construction. This version is the product skeleton:

- the `messaging` runtime with `migrate` and `serve`, the converged runtime
  configuration, and the package's access profiles;
- OIDC bearer authentication, access-profile resolution, and the keyed audit
  journal, which records the runtime start and every template preview;
- the package: providers, sender profiles, and versioned templates rendered
  with bounded, loader-free Jinja, a JSON Schema per version, exact locales,
  and SMS segment counting;
- the package ledger: the runtime serves only the package digest
  `messagingctl apply` recorded, and a change applies on restart;
- the unauthenticated `/health` and `/ready` routes, the authenticated
  message submission, status, cancel, and template preview routes, the
  provider callback routes each provider's verifier authenticates, and
  `/metrics` on a separate private listener;
- message submission under a caller-scoped `Idempotency-Key`, rendered from
  the active package at acceptance and recorded with its dispatch job and
  acceptance audit in one transaction;
- the dispatch worker on the platform PostgreSQL dispatch substrate: leased
  claims whose outcome writes are fenced by the lease, retries bounded by the
  sender profile's dispatch policy, quarantine of a message whose send may
  have happened, and audit records written through an outbox the runtime
  publishes to the journal;
- SMTP and HTTP provider delivery through the connections the runtime
  configuration gives the package's providers, and verified provider
  delivery callbacks whose receipts move a message's delivery report only
  forward;
- `messagingctl init`, `check`, `preview`, `apply`, and `messages list`,
  `show`, `retry`, `settle`, and `cancel`;
- the Rust client for health and readiness;
- the security invariant matrix, the problem catalog, and the generated
  OpenAPI and runtime schema.

Quotas and the retention sweep arrive in later slices. A provider the
runtime configuration gives no connection is not activated, so the worker
fails its messages with the attempt failure code `provider-unconfigured`,
without a send, and startup logs a warning.

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
| `registry-messaging` | The runtime and the `messaging` binary: configuration, the package loader and digest, authentication, HTTP, metrics, the PostgreSQL store and package ledger, and the audit journal. |
| `registry-messagingctl` | Adopter and local operator tooling, the `messagingctl` binary. |
| `registry-messaging-client` | The bounded Rust client over the runtime's HTTP contract. |

## Running locally

The starter under `examples/starter/` is a runtime configuration and a package
with an email and an SMS sender profile, an email template in English and
French, an SMS template, a sender access profile, and an operator access
profile. `messagingctl init DIRECTORY` writes a copy. Copy
`runtime.example.yaml`, set its absolute paths and secret references, then:

```bash
messagingctl check --runtime-config /abs/path/runtime.yaml
messagingctl preview --runtime-config /abs/path/runtime.yaml \
  appointment-reminder 1 --locale fr --data sample.json
messaging --runtime-config /abs/path/runtime.yaml migrate
messagingctl apply --runtime-config /abs/path/runtime.yaml --apply
messaging --runtime-config /abs/path/runtime.yaml serve
```

`migrate` uses the migration connection and is safe to run from several
processes at once. `messagingctl apply` without `--apply` reports whether the
package differs from the one the ledger names active; with `--apply` it
records it. `serve` refuses to start against a database whose applied schema
it does not recognize, or whose ledger does not name the package on disk, so
a package change takes effect on restart after `apply --apply`. Every
`messagingctl` command takes `--format human|json` and exits 0 on success, 1
on a refusal, 2 on a usage error, and 3 when a file, secret, or database could
not be reached. `MESSAGING_LOG` accepts `error`, `warn`, or
`info` and nothing else.

`messagingctl messages list` and `show` report messages with the recipient
masked. `retry` requeues a failed message as a new generation,
`settle --outcome sent|not-sent` resolves a message whose outcome is
unknown, and `cancel` cancels a queued one. Each action previews without
`--apply`, and an applied action writes its audit record into the outbox the
running runtime publishes. `RUNTIME-CONFIG.md` documents every key.

## HTTP contract

`generated/registry-messaging.openapi.json` is the contract; it is generated,
never hand-edited.

| Route | Authentication | Answer |
|---|---|---|
| `GET /health` | none | `200` with an empty body while the process serves |
| `GET /ready` | none | `200` when the database carries every expected migration, `503 service.unavailable` otherwise |
| `POST /v1/messages` | bearer, an access profile listing the sender profile and template, and an `Idempotency-Key` header | `202` with the message receipt; the same key and request answer the stored receipt again |
| `GET /v1/messages/{message_id}` | bearer, the submitting profile or an operator | `200` with the status, the masked recipient, and the attempts; `404 message.not-visible` for any other message |
| `POST /v1/messages/{message_id}/cancel` | bearer, the submitting profile or an operator | `200` with the cancelled status; `409 message.dispatch-started` once dispatch started, `409 message.terminal` once it is final |
| `POST /v1/templates/{template_id}/versions/{version}/preview` | bearer, a sender profile listing the template | `200` with the rendered parts and the SMS segment count; persists nothing |
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
  -p registry-messagingctl --features postgres-test --test postgres_messages_cli
```

The checkpoint runs the database-free checks: dependency direction,
database-suite isolation, the contract validator and its tests, the generated
artifact drift test, `messagingctl init` against the published starter,
`messagingctl check` over the starter, a pinned digest, and five refusals,
`messagingctl preview` byte stability, and `messagingctl messages` refusing a
malformed id and an unreachable database. Each PostgreSQL suite works in its own schema inside the database the
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
