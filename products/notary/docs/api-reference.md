# Registry Notary API reference

The committed OpenAPI document and the running service's `/openapi.json`
response are authoritative for routes and schemas. This page records the
product boundaries that clients must preserve.

## Main surfaces

| Surface | Purpose |
| --- | --- |
| `GET /healthz`, `GET /ready` | Liveness and dependency readiness |
| `GET /.well-known/evidence-service` | Protected evidence-service discovery |
| `GET /v1/claims`, `GET /v1/claims/{id}` | Claim discovery |
| `POST /v1/evaluations` | Purpose-bound claim evaluation |
| `POST /v1/batch-evaluations` | Bounded independently authorized evaluations |
| `POST /v1/evaluations/{id}/render` | Render an evaluation in an allowed format |
| `POST /v1/credentials` | Issue an allowed credential |
| OID4VCI routes | Wallet-facing issuance profile |
| `POST /federation/v1/evaluations` | Signed static-peer delegated evaluation |
| `/admin/v1/*`, `/metrics` | Restricted operator surfaces |

Notary exposes no registry-source, adapter, or sidecar API. Relay consultations
are private product-to-product calls governed by compiler-produced contracts.

## Bounded batch evaluation

`POST /v1/batch-evaluations` repeats one claim set over an ordered list of
targets. It is the only batch surface. Notary does not expose Relay batch,
batch credential issuance, or OID4VCI batch credential routes.

The hard platform ceiling is 100 items. Operators may lower it globally with
`evidence.inline_batch_limit` and per selected claim with
`operations.batch_evaluate.max_subjects`. The effective limit is the lowest of
100 and every applicable configured limit. A larger request returns HTTP 413
with `batch.too_large` before quota, idempotency, Relay, source, or retained
state changes.

Processing has two phases. Notary first validates and plans every item without
side effects. An authorization, purpose, identity, format, claim, or
consultation-planning error rejects the whole request. After admission, items
execute with bounded concurrency and return an ordered HTTP 200 response. Each
item is independently `succeeded` or `failed`, and failures contain only closed
value-free errors.

Registry-backed batches require a caller-scoped `Idempotency-Key`. If a request
is cancelled or its response is lost, retry the identical body with the same
key. Cancellation returns no partial response and retains no partial
evaluations, although Relay may have observed work already dispatched. A
completed replay returns the stored response without another source dispatch.

The 100-item limit composes with the 1 MiB inbound request limit, 64 KiB
per-Relay-result limit, 256 consultation-group limit, 25 second Relay deadline,
30 second default outer deadline, default concurrency of 16 items and 8 Relay
operations, and the Rust client's 16 MiB response-read limit. Use smaller
batches for large member results. There is no separate aggregate Relay byte
counter.

Each member preserves the authorization, purpose, consent, minimization,
provenance, and value-free audit rules of single evaluation. A successful
member may be used only through the normal one-evaluation issuance flow.

## Client behavior

Use the Rust, Python, or Node client for bounded response reads, problem
decoding, route-aware retries, and credential verification. Map policy on the
stable Problem Details `code`, not on human-readable prose. Safe log fields
are `status`, `code`, `title`, `retryable`, and `request_id`.

Never log subject identifiers, authorization details, Relay consultation
inputs or outputs, credential material, or raw upstream errors.

## Problem categories

The API uses closed problem codes grouped by category, including:

- `auth.*`, `purpose.*`, and `request.*` for admission;
- `requester.*`, `target.*`, and `relationship.*` for evidence context;
- `delegated.*` for delegated authorization or proof;
- `claim.*`, `evaluation.*`, and `evidence.*` for evaluation;
- `credential.*`, `holder_binding.*`, and `signature.*` for issuance;
- `idempotency.*`, `batch.*`, and `replay.*` for request state; and
- `consultation.*` for invalid Relay consultation inputs; and
- `evidence.*` for unavailable evidence, including Relay consultation failures.

An internal Relay failure does not become a claim result or `no_match`.
Unknown codes must be handled conservatively by category.

## Discovery privacy

Evidence-service and claim discovery may expose bounded target-input metadata
for form construction. It must not expose Relay origins, profile credentials,
source product configuration, registry field names, scripts, or private
environment bindings.
