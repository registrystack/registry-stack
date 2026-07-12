# Registry Notary API reference

> **Page type:** Reference · **Product:** Registry Notary · **Layer:** consultation, evaluation, credential, administration · **Audience:** integrator

This reference covers the route-to-client-method matrix, the source adapter
sidecar API, and the stable problem-code registry. For the complete OpenAPI
specification, fetch `GET /openapi.json` from any running Notary, or read the
[Registry Notary API reference](https://docs.registrystack.org/api/registry-notary.html).

The Problem code registry section is a curated, stable subset for policy mapping;
it does not list every code the server can emit. Match an unrecognized `code`
value on its category prefix. The server emits categories beyond those tabled
here, such as `credential.*` (issuance and holder-proof errors) and
`evaluation.*` (lookup and binding errors).

## Route to client method matrix

This matrix maps each server route to the client methods that call it, per
runtime. "not exposed" means the runtime does not surface a public helper for
that route.

| Route | Rust | Python | Node |
| --- | --- | --- | --- |
| `GET /healthz` | `health` | not exposed | not exposed |
| `GET /ready` | `ready` | not exposed | not exposed |
| `GET /docs` | not exposed | not exposed | not exposed |
| `GET /docs/scalar.js` | not exposed | not exposed | not exposed |
| `GET /admin/v1/capabilities` | not exposed | not exposed | not exposed |
| `GET /admin/v1/posture` | not exposed | not exposed | not exposed |
| `POST /admin/v1/reload` | `admin_reload` | not exposed | not exposed |
| `GET /openapi.json` | `openapi_json` | not exposed | not exposed |
| `GET /.well-known/evidence-service` | `service_document` | `service_document` | `serviceDocument` |
| `GET /.well-known/evidence/jwks.json` | `issuer_jwks`, `refresh_jwks`, `raw_issuer_jwks` | `issuer_jwks`, `refresh_jwks`, `raw_issuer_jwks` | `issuerJwks`, `refreshJwks`, `rawIssuerJwks` |
| local SD-JWT VC verification | `verify_sd_jwt_vc`, `verify_credential_response`, `verify_oid4vci_credential` with `verifier` | not exposed | not exposed |
| `GET /metrics` | `metrics` | not exposed | not exposed |
| `GET /v1/claims` | `list_claims` | `list_claims` | `listClaims` |
| `GET /v1/claims/{id}` | `get_claim` | `get_claim` | `getClaim` |
| `GET /v1/formats` | `list_formats` | not exposed | not exposed |
| `POST /v1/evaluations` | `evaluate`, `evaluate_request` | `evaluate`, `evaluate_request`, `aevaluate`, `aevaluate_request` | `evaluate`, `evaluateRequest` |
| `POST /v1/batch-evaluations` | `batch_evaluate_request` | `batch_evaluate_request`, `abatch_evaluate_request` | `batchEvaluate`, `batchEvaluateRequest` |
| `POST /v1/evaluations/{evaluation_id}/render` | `render_request` | `render_request`, `arender_request` | `renderRequest` |
| `POST /v1/credentials` | `issue_credential_request` | `issue_credential_request`, `aissue_credential_request` | `issueCredentialRequest` |
| `GET /v1/credentials/{id}/status` | `credential_status` | `credential_status` | `credentialStatus` |
| `POST /admin/v1/credentials/{id}/status` | `update_credential_status` | not exposed | not exposed |
| `GET /.well-known/openid-credential-issuer` | `oid4vci_issuer_metadata` | `oid4vci_issuer_metadata` | `oid4vciIssuerMetadata` |
| `GET /.well-known/vct/{*vct_path}` | not exposed | not exposed | not exposed |
| `GET /credentials/{vct_path}` | not exposed | not exposed | not exposed |
| `GET /oid4vci/credential-offer` | `oid4vci_credential_offer` | `oid4vci_credential_offer` | `oid4vciCredentialOffer` |
| `GET /oid4vci/offer/start` | not exposed | not exposed | not exposed |
| `GET /oid4vci/offer/callback` | not exposed | not exposed | not exposed |
| `POST /oid4vci/token` | not exposed | not exposed | not exposed |
| `POST /oid4vci/nonce` | `oid4vci_nonce` | `oid4vci_nonce` | `oid4vciNonce` |
| `POST /oid4vci/credential` | `oid4vci_credential` | `oid4vci_credential` | `oid4vciCredential` |
| `POST /federation/v1/evaluations` | `federation_evaluate_jws` | `federation_evaluate_jws` | `federationEvaluateJws` |

Registry Notary does not expose admin config verify, dry-run, or apply routes.
Signed config bundles are local directories verified with the node CLI
`config verify-bundle` and activated by placing the bundle on the node and
restarting the service.

`/.well-known/evidence-service` is discovery metadata, but it is protected
discovery metadata. Callers must send the configured API key, bearer token, or
OIDC credential. The unauthenticated well-known exceptions are the public issuer
JWKS, OID4VCI issuer metadata, and SD-JWT VC type-metadata routes documented in
the security allowlist.

## Claim discovery target inputs

`GET /v1/claims` and `GET /v1/claims/{claim_id}` may include `target_inputs`
when a claim has configured target matching. This block is request-contract
metadata for clients that build evaluation forms. It is separate from the Core
Criterion and Core Evidence Vocabulary (CCCEV) and the EU Once-Only Technical
System (OOTS): those describe evidence semantics and interoperability context, while
`target_inputs` describes the target-side request paths a Notary evaluation can
accept.

Each entry contains a matching method label, optional policy id, target type,
confidence label, and OR-of-AND input groups. A client should collect one full
group and submit only those target paths. For example, one group may contain
`target.identifiers.national_id`, while another may contain
`target.attributes.given_name`, `target.attributes.family_name`, and
`target.attributes.birthdate`.

The block is intentionally minimized. It can expose target-side paths and
friendly labels, but it does not expose connector names, connection ids,
dataset/entity names, source field names, or raw source binding configuration.

## Source adapter sidecar API

This section documents the private sidecar API that Registry Notary calls when a
source binding uses the source-adapter connector value
`connector: source_adapter_sidecar`. It is not a caller-facing Registry Notary route.
The sidecar can run the built-in `http_json`, `http_flow`, and `fhir` engines,
or another governed adapter implementation. It must run on localhost or a private pod network
and must not be publicly exposed.

Single reads use the Registry Data API-shaped source route:

```text
GET /v1/datasets/{dataset}/entities/{entity}/records?{lookup_field}={lookup_value}&fields=a,b&limit=2
Authorization: Bearer <notary-to-sidecar-token>
Data-Purpose: <purpose>
```

Sidecar batch matching uses this stable route and an explicit POST body.
It is semantically equivalent to running the same source binding as single reads
for each request item.

```text
POST /v1/datasets/{dataset}/entities/{entity}/records:batchMatch
Authorization: Bearer <notary-to-sidecar-token>
Data-Purpose: <purpose>
Content-Type: application/json
```

Request body:

```json
{
  "fields": ["national_id", "birth_date"],
  "query_signature": [
    { "field": "given_name", "op": "eq" },
    { "field": "family_name", "op": "eq" },
    { "field": "birthdate", "op": "eq" }
  ],
  "items": [
    { "id": "0", "values": ["Amina", "Diallo", "1990-01-01"] }
  ]
}
```

Successful response body:

```json
{
  "items": [
    {
      "id": "0",
      "data": [
        {
          "national_id": "12345",
          "birth_date": "1990-01-01"
        }
      ]
    }
  ]
}
```

Contract rules:

- `Authorization`, `Data-Purpose`, `fields`, `query_signature`, and `items` are
  required.
- The v1 `query_signature` supports `op: eq` only.
- Every item in a batch uses the same ordered `query_signature`; each
  `items[].values` array must have the same length as that signature.
- The request does not include full Notary target, requester, relationship,
  assurance, claim config, disclosure config, or unrelated request attributes.
- Response item ids must correspond exactly to request item ids.
- A duplicate response item id rejects the whole sidecar response as invalid
  output.
- A missing response item maps to `source.unavailable` for that item.
- `data: []` maps to source not found, `data: [record]` maps to a successful
  source match, and `data` with two records maps to source ambiguous.
- If the worker returns more than two records for an item, the sidecar
  normalizes the result to two records before returning it to Notary, preserving
  the same cardinality rule used for single reads.
- Returned records are projected to the requested `fields`; extra worker output
  fields are not returned to Notary.
- Documented per-item sidecar error codes are `source.target_auth` and
  `source.target_rate_limit`. The sidecar's classifier also accepts the
  unprefixed `target_auth`/`target_rate_limit` forms from custom worker code
  and treats them the same as their `source.`-prefixed counterparts. Unknown
  per-item error codes map to source unavailable.
- Adapter execution failures, invalid output, oversized output, worker crashes,
  and timeouts are not retried for the same batch request.

The sidecar rejects missing or malformed bearer tokens with `401` and a
`WWW-Authenticate: Bearer` header, rejected tokens with `403`, missing
`Data-Purpose` with `400`, unknown source routes with `404`, unsupported query
operations with `400`, sidecar capacity saturation with `503` plus
`Retry-After`, timeout with `504`, and invalid adapter execution/output with
`502`.

## Problem code registry

These application problem `code` values are part of the stable client contract
for policy mapping. Map on `code`, not on prose. Safe fields for logs are
`status`, `code`, `title`, `retryable`, and `request_id`.

| Code | Category |
| --- | --- |
| `request.invalid` | Request |
| `purpose.not_allowed` | Purpose |
| `profile.unsupported` | Profile |
| `evidence.not_available` | Evidence |
| `requester.reauthentication_required` | Requester |
| `requester.matching_policy_rejected` | Requester |
| `requester.not_found` | Requester |
| `requester.match_ambiguous` | Requester |
| `requester.identifier_missing` | Requester |
| `requester.attributes_insufficient` | Requester |
| `target.not_found` | Target |
| `target.match_ambiguous` | Target |
| `target.identifier_missing` | Target |
| `target.match_low_confidence` | Target |
| `target.attributes_insufficient` | Target |
| `target.not_in_valid_state` | Target |
| `target.matching_policy_rejected` | Target |
| `relationship.not_established` | Relationship |
| `relationship.match_ambiguous` | Relationship |
| `relationship.attributes_insufficient` | Relationship |
| `relationship.policy_rejected` | Relationship |
| `relationship.purpose_not_allowed` | Relationship |
| `source.unavailable` | Source |
| `claim.not_found` | Claim |
| `claim.version_not_found` | Claim |
| `claim.format_not_supported` | Claim |
| `auth.purpose_required` | Auth |
| `auth.missing_credential` | Auth |
| `self_attestation.denied` | Self-attestation |
| `idempotency.conflict` | Idempotency |
| `batch.too_large` | Batch |
| `jwks.unavailable` | Verifier |
| `key.missing` | Verifier |
| `key.unknown` | Verifier |
| `algorithm.disallowed` | Verifier |
| `algorithm.key_mismatch` | Verifier |
| `header.typ_mismatch` | Verifier |
| `header.untrusted_key_reference` | Verifier |
| `signature.invalid` | Verifier |
| `claim.issuer_mismatch` | Verifier |
| `claim.vct_mismatch` | Verifier |
| `claim.time_invalid` | Verifier |
| `disclosure.digest_mismatch` | Verifier |
| `holder_binding.required` | Verifier |
| `holder_binding.invalid` | Verifier |
| `holder_binding.kid_mismatch` | Verifier |
| `holder_binding.proof_invalid` | Verifier |

Profiles may collapse granular matching outcomes to public
`evidence.not_available` when revealing cardinality, state, or relationship
policy would create an oracle. Operators can still inspect the granular audit
code in the server audit trail.

### Matching outcomes

These codes report how a request resolved to a source record. The model behind
them, including the cardinality rule and the collapse behavior, is described in
[identity and record matching](identity-and-record-matching.md).

| Code | When it is returned |
| --- | --- |
| `target.not_found` | The source returned no record for the target |
| `target.match_ambiguous` | The source returned more than one record |
| `target.identifier_missing` | A required target identifier was not supplied |
| `target.attributes_insufficient` | The target attributes did not satisfy the binding's required input set |
| `target.matching_policy_rejected` | The request shape is outside the binding's matching policy |
| `target.match_low_confidence` | The source reported a match it considers too weak |
| `target.not_in_valid_state` | The matched target is in a state the source rejects |

The `requester` codes (`requester.not_found`, `requester.match_ambiguous`,
`requester.identifier_missing`, `requester.attributes_insufficient`,
`requester.matching_policy_rejected`, `requester.reauthentication_required`) and the
`relationship` codes (`relationship.not_established`, `relationship.match_ambiguous`,
`relationship.attributes_insufficient`, `relationship.policy_rejected`,
`relationship.purpose_not_allowed`) report the same outcomes for the requester and
relationship contexts. `relationship.purpose_not_allowed` means the relationship
type is valid but not for the declared purpose. A successful match returns
`target_ref` and `matching` metadata instead of a problem code.

`matching.confidence` is a policy-asserted label configured for the source
binding and matching method. It is returned verbatim for successful matches
against that binding, so it does not measure the quality of an individual match.
Additional fields may appear alongside it; its meaning will not change.

### Self-attestation denial reasons

Self-attestation policy denials return the public problem code
`self_attestation.denied`. The audit trail and internal denial context preserve
the granular reason so operators can distinguish policy failures without giving
callers an identifier oracle.

Direct self-attestation reasons include `self_attestation.disabled`,
`self_attestation.operation_denied`, `self_attestation.claim_denied`,
`self_attestation.disclosure_denied`, `self_attestation.format_denied`,
`self_attestation.profile_denied`, `self_attestation.subject_claim_missing`,
`self_attestation.subject_mismatch`, `self_attestation.rate_limited`,
`self_attestation.invalid_token`, `self_attestation.assurance_denied`, and
`self_attestation.batch_denied`.

The temporary pre-v1 internal taxonomy retains these delegated denial reasons
for closed legacy paths. It creates no supported/configurable surface or
compatibility guarantee: enabling delegated self-attestation fails validation.
The retained reasons include
`delegated.relationship_unproven`, `delegated.relationship_not_allowed`,
`delegated.claim_denied`, `delegated.subject_not_permitted`, and
`delegated.proof_denied`.
