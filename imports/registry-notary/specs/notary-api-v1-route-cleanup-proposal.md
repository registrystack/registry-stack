# Registry Notary API V1 Route Cleanup Design Record

## Summary

Status: implemented in the current route surface. This document remains as the
design record for the breaking route cleanup and intentionally names legacy
routes in the comparison tables below.

Registry Notary is still pre-real-adoption, so we should take the opportunity to
make the HTTP API more consistent before external clients depend on it. The
current API is understandable, but several routes are action-oriented or
inconsistently versioned. This proposal moves the public application API under
`/v1`, keeps protocol-defined discovery routes where standards expect them, and
renames action routes into resource-oriented routes.

## Goals

- Establish a stable `/v1` application API before real integrations start.
- Replace action-style routes such as `/claims/evaluate` and
  `/credentials/issue` with resource-style routes.
- Keep standards-driven routes such as `.well-known` and OID4VCI endpoints
  compatible with wallet/client expectations.
- Keep operations/admin routes visibly separate from application routes.
- Update the Rust/Python/Node client method matrix to match the cleaned API.

## Non-Goals

- No compatibility layer for production users. There are no real users yet.
- No semantic behavior changes to evaluation, rendering, issuance, federation,
  OID4VCI, auth, audit, retry, or error handling.
- No signature-verification feature in this cleanup. That is tracked separately
  in issue #77.
- No change to request or response JSON shapes unless a route rename requires an
  OpenAPI operation-id cleanup.

## Current Issues

The pre-cleanup server routes mostly made sense, but they mixed styles:

- Core application routes are unversioned while federation uses
  `/federation/v1/...`.
- Several routes encode verbs in the path:
  - `POST /claims/evaluate`
  - `POST /claims/batch-evaluate`
  - `POST /evidence/render`
  - `POST /credentials/issue`
- Credential status routes put `status` before the credential id:
  - `GET /credentials/status/{credential_id}`
  - `POST /admin/credentials/status/{credential_id}`
- Operations routes are mixed with application routes at the root.

These are not fatal, but they make the API look less deliberate than it can be
while the surface is still easy to change.

## Implemented Route Surface

### Stable Public And Operational Routes

These routes should stay unversioned because they are conventional or
operational:

| Legacy route | Current route | Rationale |
| --- | --- | --- |
| `GET /healthz` | keep | Infrastructure convention. |
| `GET /ready` | keep | Infrastructure convention. |
| `GET /metrics` | keep | Prometheus convention. |
| `GET /openapi.json` | keep, but documents v1 routes | Common discovery endpoint. |
| `GET /.well-known/evidence-service` | keep | Discovery convention. |
| `GET /.well-known/evidence/jwks.json` | keep | JWKS discovery convention. |
| `GET /.well-known/openid-credential-issuer` | keep | OID4VCI metadata convention. |
| `GET /oid4vci/credential-offer` | keep | OID4VCI wallet-facing endpoint. |
| `POST /oid4vci/nonce` | keep | OID4VCI wallet-facing endpoint. |
| `POST /oid4vci/credential` | keep | OID4VCI wallet-facing endpoint. |

### Versioned Application API

Move Notary-specific application routes under `/v1`:

| Legacy route | Current route | Notes |
| --- | --- | --- |
| `GET /claims` | `GET /v1/claims` | Same response shape. |
| `GET /claims/{claim_id}` | `GET /v1/claims/{claim_id}` | Same response shape. |
| `GET /formats` | `GET /v1/formats` | Same response shape. |
| `POST /claims/evaluate` | `POST /v1/evaluations` | Creates an evaluation result from target plus claims. |
| `POST /claims/batch-evaluate` | `POST /v1/batch-evaluations` | Creates a batch evaluation job/result. |
| `POST /evidence/render` | `POST /v1/evaluations/{evaluation_id}/render` | Renders stored evaluation evidence. |
| `POST /credentials/issue` | `POST /v1/credentials` | Issues a credential. |
| `GET /credentials/status/{credential_id}` | `GET /v1/credentials/{credential_id}/status` | Credential id is the resource anchor. |

### Admin API

Keep admin routes separate and versioned:

| Legacy route | Current route | Notes |
| --- | --- | --- |
| `POST /admin/reload` | `POST /admin/v1/reload` | Explicit admin API version. |
| `POST /admin/credentials/status/{credential_id}` | `POST /admin/v1/credentials/{credential_id}/status` | Same body, clearer hierarchy. |

### Federation API

Federation already has a reasonable versioned shape:

| Route | Current route | Notes |
| --- | --- | --- |
| `POST /federation/v1/evaluations` | keep | Already versioned and resource-oriented. |

## Client API Impact

The public client method names should remain workflow-oriented and should not
mirror every path segment:

| Workflow | Rust method | Python method | Node method |
| --- | --- | --- | --- |
| Evaluate via builder | `evaluate(...).send()` | `evaluate(...)`, `aevaluate(...)` | `evaluate(...)` |
| Evaluate with raw request | `evaluate_request(...)` | `evaluate_request(...)`, `aevaluate_request(...)` | `evaluateRequest(...)` |
| Batch evaluate | `batch_evaluate_request(...)` | `batch_evaluate_request(...)`, `abatch_evaluate_request(...)` | `batchEvaluateRequest(...)` |
| Render evidence | `render_request(...)` | `render_request(...)`, `arender_request(...)` | `renderRequest(...)` |
| Issue credential | `issue_credential_request(...)` | `issue_credential_request(...)`, `aissue_credential_request(...)` | `issueCredentialRequest(...)` |
| Credential status | `credential_status(...)` | `credential_status(...)` | `credentialStatus(...)` |
| Admin reload | `admin_reload(...)` | not exposed initially | not exposed initially |

The client should update route constants internally. Public method names do not
need to expose `/v1`.

## Compatibility Position

Because there are no real users yet, the preferred implementation is a breaking
route cleanup:

- Do not mount legacy aliases by default.
- Do not document legacy routes.
- Update labs, smoke tests, OpenAPI, examples, and clients in the same change.
- If maintainers want a safety net, add legacy aliases only behind a
  `compat_legacy_routes` test/dev feature and remove it before release.

## Implementation Checklist

- [x] Update `registry-notary-server` route mounting in `api.rs`.
- [x] Update standalone routing/auth allowlists for the new paths.
- [x] Update OpenAPI paths, operation ids, examples, and route coverage tests.
- [x] Update client route constants/calls for Rust.
- [x] Update Python and Node wrappers if they own route strings.
- [x] Update docs and tutorials to use `/v1` application routes.
- [ ] Update registry-lab vendored/client usage and smoke scripts.
- [x] Update federation docs only to confirm no route change.
- [x] Run a route grep to prove old application routes are gone from source
  docs/tests, except in this proposal, dated audit artifacts, demo audit logs,
  or intentional changelog notes.

## Definition Of Done

- [x] `rg "/claims/evaluate|/claims/batch-evaluate|/evidence/render|/credentials/issue|/credentials/status/|/admin/reload|/admin/credentials/status" crates docs bindings` returns no stale route usage outside this proposal, dated audit artifacts, demo audit logs, or intentional changelog notes.
- [ ] `cargo test -p registry-notary-server` passes.
- [ ] `cargo test -p registry-notary-client` passes.
- [ ] `cargo test -p registry-notary-client --features json-facade,oid4vci,federation` passes.
- [ ] `cargo doc -p registry-notary-client --no-deps --all-features` passes.
- [ ] Python binding tests pass.
- [ ] Node binding tests and type checks pass.
- [ ] Registry lab smoke/e2e flows pass against the new route surface.
- [x] OpenAPI route coverage test asserts only the current route set.

## Review Checkpoints

1. Route-design review before implementation:
   - Confirm `/v1` placement.
   - Confirm OID4VCI and `.well-known` routes remain unversioned.
   - Confirm no default legacy aliases.
2. Server review:
   - Route mounting, auth, body limits, OpenAPI, tests.
3. Client/bindings review:
   - Rust/Python/Node route mapping, errors, docs, smoke usage.
4. Lab/release review:
   - Tutorials, lab flows, release notes, old-route grep, CI.

## Decisions

- Render uses `POST /v1/evaluations/{evaluation_id}/render`; the path carries
  `evaluation_id`, while the request body carries format and optional claim
  selection.
- Batch evaluation uses `POST /v1/batch-evaluations`.
- Admin routes use `/admin/v1/...` because it keeps administrative APIs
  visually separate from application APIs.
