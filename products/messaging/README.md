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
  journal, which records the runtime start;
- the unauthenticated `/health` and `/ready` routes, the authenticated
  message status route, and `/metrics` on a separate private listener;
- `messagingctl check`, which loads a runtime configuration and its package
  offline exactly as `serve` would;
- the Rust client for health and readiness;
- the security invariant matrix, the problem catalog, and the generated
  OpenAPI and runtime schema.

Submission, templates, providers, dispatch, callbacks, quotas, and retention
arrive in later slices. Until the message store lands, the status route
answers `message.not-visible` to every authenticated caller, which is the
same answer it gives for a message the caller may not see.

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
| `registry-messaging-core` | Access profiles and their decisions, message visibility, the problem vocabulary, wire names and DTOs. No I/O. |
| `registry-messaging` | The runtime and the `messaging` binary: configuration, authentication, HTTP, metrics, the PostgreSQL store, and the audit journal. |
| `registry-messagingctl` | Adopter and local operator tooling, the `messagingctl` binary. |
| `registry-messaging-client` | The bounded Rust client over the runtime's HTTP contract. |

## Running locally

The starter under `examples/starter/` is a runtime configuration and a package
with one sender profile and one operator profile. Copy
`runtime.example.yaml`, set its absolute paths and secret references, then:

```bash
messagingctl check --runtime-config /abs/path/runtime.yaml
messaging --runtime-config /abs/path/runtime.yaml migrate
messaging --runtime-config /abs/path/runtime.yaml serve
```

`migrate` uses the migration connection and is safe to run from several
processes at once. `serve` refuses to start against a database whose applied
schema it does not recognize. `MESSAGING_LOG` accepts `error`, `warn`, or
`info` and nothing else. `RUNTIME-CONFIG.md` documents every key.

## HTTP contract

`generated/registry-messaging.openapi.json` is the contract; it is generated,
never hand-edited.

| Route | Authentication | Answer |
|---|---|---|
| `GET /health` | none | `200` with an empty body while the process serves |
| `GET /ready` | none | `200` when the database carries every expected migration, `503 service.unavailable` otherwise |
| `GET /v1/messages/{message_id}` | bearer | `404 message.not-visible` |
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
| `idempotency.expired` | 410 |
| `request.body-too-large` | 413 |
| `request.unsupported-media-type` | 415 |
| `request.unprocessable` | 422 |
| `service.unavailable` | 503 |

## Verification

```bash
cargo build --locked -p registry-messagingctl
products/messaging/scripts/check-checkpoint.sh
products/messaging/scripts/check-contracts.sh
MESSAGING_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-messaging --features postgres-test --test postgres_migrate
```

The checkpoint runs the database-free checks: dependency direction,
database-suite isolation, the contract validator and its tests, the generated
artifact drift test, and `messagingctl check` over the starter and five
refusals. The PostgreSQL suite works in its own schema inside the database the
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
