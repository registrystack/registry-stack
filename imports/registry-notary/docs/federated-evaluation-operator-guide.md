# Federated Evaluation MVP Operator Guide

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** federation · **Audience:** operator

This guide shows the minimum static-peer setup for the delegated evaluation MVP.
It is intentionally narrower than the broader federation roadmap.

## What This Enables

One trusted Notary can call another trusted Notary:

```text
Agency B -> signed request JWT -> Agency A /federation/v1/evaluations
Agency B <- signed response JWT <- Agency A
```

The serving Notary verifies the request, enforces local peer policy, reads its
own source only after policy passes, emits audit, and returns a signed result.

```mermaid
sequenceDiagram
  participant B as Agency B (requesting Notary)
  participant A as Agency A (serving Notary)
  participant Src as Source registry
  participant Audit as Audit sink

  B->>A: POST /federation/v1/evaluations (signed request JWT)
  A->>A: Verify signature, audience, time window, profile, purpose, replay, denylist, body limit
  A->>Src: Source read, only after policy passes
  Src-->>A: Source facts
  A->>Audit: Chained audit record
  A-->>B: Signed response JWT, or signed error, or Problem Details denial
```

*The delegated evaluation exchange. Every check runs before any source read, and
an audit write failure prevents a successful signed response.*

## Required Environment

Set these before starting the serving Notary:

```bash
export REGISTRY_NOTARY_AUDIT_HASH_SECRET='change-me-audit-hash-secret'
export REGISTRY_NOTARY_FEDERATION_RESPONSE_JWK='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","alg":"EdDSA"}'
export REGISTRY_NOTARY_PAIRWISE_SUBJECT_HASH_SECRET='change-me-pairwise-secret'
export EVIDENCE_SOURCE_TOKEN='source-token-issued-by-the-registry'
```

Do not reuse the pairwise subject hash secret for audit hashing, cookies,
source tokens, credential signing, or federation response signing. Federation
response signing references a named key from `evidence.signing_keys`, so the
same local JWK and PKCS#11 providers are used for evidence and federation
signatures.

## Minimal Config Shape

```yaml
evidence:
  signing_keys:
    federation-response:
      provider: local_jwk_env
      alg: EdDSA
      kid: agency-a-fed-1
      status: active
      private_jwk_env: REGISTRY_NOTARY_FEDERATION_RESPONSE_JWK

federation:
  enabled: true
  node_id: did:web:agency-a.example.gov
  issuer: https://agency-a.example.gov
  jwks_uri: https://agency-a.example.gov/federation/jwks.json
  federation_api: https://agency-a.example.gov/federation/v1
  supported_protocol_versions:
    - registry-notary-federation/v0.1
  inbound_body_limit_bytes: 16384
  max_request_lifetime_seconds: 300
  clock_leeway_seconds: 60
  signing:
    signing_key: federation-response
  pairwise_subject_hash:
    secret_env: REGISTRY_NOTARY_PAIRWISE_SUBJECT_HASH_SECRET
  response_shaping:
    minimum_denial_latency_ms: 250
  emergency_denylist:
    node_ids: []
    kids: []
  peers:
    - node_id: did:web:agency-b.example.gov
      issuer: https://agency-b.example.gov
      jwks_uri: https://agency-b.example.gov/.well-known/jwks.json
      # Local Compose demos may use allow_insecure_private_network: true with
      # an HTTP service URL. Production peer JWKS URLs must use HTTPS.
      allowed_protocol_versions:
        - registry-notary-federation/v0.1
      allowed_purposes:
        - https://purpose.example.gov/social-protection/service-delivery
      allowed_profiles:
        - disability_status_predicate
      source_scopes:
        - disability_registry:evidence_verification
  evaluation_profiles:
    - id: disability_status_predicate
      ruleset: disability-status-v1
      claim_id: disability_status
      subject_id_type: national_id
      max_source_observed_age_seconds: 3600
```

The local `peers` block is authoritative. Manifest metadata helps partners
configure each other, but it does not grant access.

`allow_insecure_private_network` is a development and lab escape hatch for
private Compose networks. It allows HTTP peer JWKS fetches through the shared
bounded-fetch policy while still blocking cloud metadata targets. Do not enable
it for production federation.

## Request Requirements

Send `POST /federation/v1/evaluations` with:

- `Content-Type: application/jwt`
- compact JWS serialization
- protected header `typ = registry-notary-request+jwt`
- `alg = EdDSA`
- `kid` present in the configured peer JWKS
- payload claims `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `protocol`,
  `action`, `profile`, `purpose`, and `request`

The serving Notary rejects the request before source reads when signature,
audience, time window, profile, purpose, replay, emergency denylist, or body
limit checks fail.

## Response Requirements

Successful responses are compact signed JWTs with:

- protected header `typ = registry-notary-response+jwt`
- `iss` and `sub` for the serving Notary
- `aud` for the requesting peer node id
- `request_jti` copied from the request
- `result.subject_ref.hash` as a pairwise `hmac-sha256:` handle

Stale source observations return HTTP 200 with a signed top-level `error`
object. Transport denials use RFC 9457 Problem Details JSON and do not prove whether the
subject exists.

## Replay Store

Replay protection is selected by the top-level `replay` block. The default
`in_memory` store is acceptable for local development, single-process pilots,
and tests:

```yaml
replay:
  storage: in_memory
```

Do not run active-active federation with this store. Multiple serving Notary
instances need a shared replay store before privileged federation traffic is
enabled. For the full Redis replay configuration block, see the
[Replay Store section of the configuration reference](operator-config-reference.md).

`federation.replay.storage` is retained only for legacy configuration shape. If
it is set to `redis`, startup validation requires top-level
`replay.storage = redis` so the configured backend is unambiguous.

## Verification Checklist

To run the test suite, see [Verification in the workspace README](../README.md#verification).

Also confirm:

- federation routes are absent when `federation.enabled` is false;
- the peer JWKS contains the request signing `kid`;
- source tokens and raw subject identifiers do not appear in audit JSONL;
- audit write failure prevents a successful signed response;
- replaying the same request `jti` returns a denial.
