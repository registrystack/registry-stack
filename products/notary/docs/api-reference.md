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
- `source.*`, `verification.*`, `contract.*`, and `availability.*` for
  internal Relay consultation failures.

An internal Relay failure does not become a claim result or `no_match`.
Unknown codes must be handled conservatively by category.

## Discovery privacy

Evidence-service and claim discovery may expose bounded target-input metadata
for form construction. It must not expose Relay origins, profile credentials,
source product configuration, registry field names, scripts, or private
environment bindings.
