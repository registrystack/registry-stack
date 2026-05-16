# Wave 3: Data Provenance

Wave 3 lets `data_gate` return W3C Verifiable Credentials (VCs), signed
as compact JWS, for three response families:

- `GET /datasets/{dataset_id}/{entity}/verify` -> `VerifyResult`
- `GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}` -> `AggregateResult`
- `GET /datasets/{dataset_id}/{entity}/{id}` -> `EntityRecord`

The feature is opt-in twice over: by the operator (config flag) and by
the caller (Accept header). When either says no, responses are
byte-for-byte identical to a wave-2 build.

For the full design rationale and decision log, see
[`decisions/wave-3-data-provenance.md`](../decisions/wave-3-data-provenance.md).
This document describes the runtime contract: configuration, wire
shapes, endpoints, audit events, and key management.

## Why Verifiable Credentials

Consumers of `data_gate` increasingly need to relay government data to
downstream parties (cross-ministry workflows, EU-level dataspaces,
audit reviewers). Plain JSON gives them no cryptographic way to prove
"this came from data_gate at time T under DID D". A VC-JWT does:
issuer DID, signing key, claim type, subject URI, and validity window
are all signed under one envelope that any verifier with the issuer's
DID Document can check.

The choice of W3C VCDM 2.0 + JWT binding (rather than COSE or
SD-JWT-VC) is documented in the wave-3 decision file; the runtime
contract here is stable regardless of the encoding evolution.

## Enabling Provenance

Add a `provenance:` block to your config (see
[`config/example.yaml`](../config/example.yaml) for the canonical
template). Minimum gateway-mode shape:

```yaml
provenance:
  enabled: true
  schema_base_url: https://data.example.gov/schemas
  context_base_url: https://data.example.gov/contexts
  claim_validity:
    verify_result:    5m
    aggregate_result: 1h
    entity_record:    24h
  issuer:
    mode: gateway
    did: did:web:data.example.gov
    verification_method_id: did:web:data.example.gov#issuance
    signer:
      kind: software
      jwk_env: DATAGATE_PROVENANCE_JWK
      signing_algorithm: EdDSA
```

The private JWK comes from an environment variable (never from the
YAML). The env value is a JSON-encoded private JWK, e.g.:

```json
{"kty":"OKP","crv":"Ed25519","d":"<base64url>","x":"<base64url>","alg":"EdDSA"}
```

Use 1Password, AWS Secrets Manager, or your platform's secret store to
inject it. Do not echo, log, or commit this value.

When `enabled: false` (or the block is omitted entirely), the
gateway behaves exactly as in wave 2.

## Issuer Modes

`gateway` mode: the gateway holds the signing key, publishes its DID
Document at `/.well-known/did.json`, and self-issues VCs under that
DID.

`delegated` mode: the gateway signs under a ministry's DID. The
ministry hosts its own DID Document at `<ministry-did>/.well-known/did.json`
and references the gateway's signing key as one of its
`verificationMethod` entries. In delegated mode the gateway does NOT
serve `/.well-known/did.json`; the ministry owns that surface.

Both modes use the same `signer:` shape. Switching modes requires a
config change and a process restart.

## Caller Opt-In: Accept Negotiation

The handler returns a signed VC only when the caller asks for one:

```http
GET /datasets/social_registry/individual/verify?id=ind-123 HTTP/1.1
Accept: application/vc+jwt
```

Without that header (or when the header lists only types the operator
did not configure), the response stays plain JSON with the wave-2
content-type and body. Cache validators (`ETag`, `If-None-Match`,
`304 Not Modified`) still apply on the plain branch; they are
intentionally bypassed when a signed VC is issued, because each VC has
its own `iat` and `jti`.

The accepted media types are configurable
(`provenance.accepted_media_types`); the default is:

```yaml
accepted_media_types:
  - application/vc+jwt
  - application/jwt
```

The response carries `Content-Type: application/vc+jwt` regardless of
which alias the caller used.

## Wire Shape: VC-JWT Compact Serialization

The response body is a compact JWS: `base64url(header).base64url(payload).base64url(signature)`.

JOSE header:

```json
{"alg":"EdDSA","typ":"vc+jwt","cty":"vc","kid":"did:web:data.example.gov#issuance"}
```

Payload (top-level VCDM 2.0; no nested `vc` claim):

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2",
               "https://data.example.gov/contexts/provenance/v1.jsonld"],
  "type": ["VerifiableCredential", "VerifyResult"],
  "id": "urn:uuid:01J5K8M0...",
  "issuer": "did:web:data.example.gov",
  "validFrom": "2026-05-16T09:30:00Z",
  "validUntil": "2026-05-16T09:35:00Z",
  "credentialSchema": {
    "id": "https://data.example.gov/schemas/verify-result/v1.json",
    "type": "JsonSchema"
  },
  "credentialSubject": { "id": "<subject-uri>", "predicate": "exists", "value": true },
  "iss": "did:web:data.example.gov",
  "sub": "<subject-uri>",
  "iat": 1747387800,
  "nbf": 1747387800,
  "exp": 1747388100,
  "jti": "urn:uuid:01J5K8M0..."
}
```

`type[1]` is one of `VerifyResult`, `AggregateResult`, `EntityRecord`.
Subject URIs follow `<catalog.base_url>/datasets/<dataset>/<entity>/<id>`
for entity / verify claims and
`<catalog.base_url>/datasets/<dataset>/<entity>/aggregates/<aggregate_id>`
for aggregates.

## Supporting Endpoints

When provenance is enabled in `gateway` mode, the data plane serves
three additional endpoints, all unauthenticated and content-cacheable:

- `GET /.well-known/did.json` returns the gateway's DID Document. It
  lists every active and retired `verificationMethod` so existing VCs
  signed under a rotated-out key still verify.
- `GET /schemas/{claim_type}/{version}` returns the JSON Schema (draft
  2020-12) describing the `credentialSubject` shape for that claim
  type. Paths: `verify-result/v1.json`, `aggregate-result/v1.json`,
  `entity-record/v1.json`.
- `GET /contexts/{vocab}/{version}` returns the JSON-LD context
  referenced from VC `@context`.

In `delegated` mode the gateway does NOT serve `/.well-known/did.json`;
the ministry hosts it. The `/schemas` and `/contexts` routes still
serve from the gateway because the schema URIs in issued VCs point at
the gateway base URL.

## Audit Trail

When a VC is issued, the audit envelope for the request grows a
`provenance` block alongside the regular fields:

```jsonl
{"ts":"2026-05-16T09:30:00.123Z","request_id":"01J5K8...","path":"/datasets/social_registry/individual/verify","status_code":200,"provenance":{"event":"provenance.vc.issued","iss":"did:web:data.example.gov","kid":"did:web:data.example.gov#issuance","jti":"urn:uuid:01J5K8M0...","claim_type":"VerifyResult","subject":"https://data.example.gov/datasets/social_registry/individual/ind-123","validity":{"iat":1747387800,"nbf":1747387800,"exp":1747388100}}}
```

The `claim_type` field tracks `type[1]` of the VC. `kid` matches the
JOSE `kid` header. `jti` matches the VC's `id` and JWT `jti`. The
record never contains the private JWK or the compact JWS body.

Plain-JSON responses (no Accept opt-in, or `provenance.enabled: false`)
omit the `provenance` block entirely.

## Key Rotation

The signing key is referenced indirectly: the config names an env var,
the env var holds the JWK. To rotate:

1. Mint a new keypair (Ed25519 or P-256, matching `signing_algorithm`).
2. Add the new public JWK to the DID Document under a new
   `verificationMethod` id (gateway mode: edit the source the DID
   Document handler reads; delegated mode: coordinate with the
   ministry).
3. Move the previously active key to `provenance.issuer.retired_keys`
   so the DID Document keeps publishing it until every VC it signed
   has expired (cutoff = `retired_after` + the longest
   `claim_validity` window).
4. Update `verification_method_id` to the new id.
5. Update the env var holding the private JWK.
6. Restart or roll the gateway. The keyring is loaded once at process
   start, so rotation is a restart-driven operation in V1.
7. Once the retirement cutoff has passed, drop the entry from
   `retired_keys` and remove the public JWK from the DID Document on
   the next rolling deploy.

Never check a private JWK into git, into config, or into a container
image. Never log it, never include it in error messages, and never
embed it in a PR description.

## KMS Backend

The config model accepts `signer.kind: kms`, but the in-tree V1 KMS
backend is a test mock. Production-grade AWS KMS signing is reserved
for a follow-up wave; do not deploy with `provider: aws_kms`. The
`mock` provider is intentionally inaccessible to production configs
through validation.

## Verifying a VC Externally

Any standard JOSE library plus a DID Web resolver can verify these
VCs. Minimum verification recipe:

1. Split the compact JWS, decode the header.
2. Resolve `header.kid` via the DID Web resolution rules: fetch
   `https://<host>/.well-known/did.json`, find the matching
   `verificationMethod`, extract its public JWK.
3. Verify the signature over `base64url(header).base64url(payload)`
   using the JWK's algorithm.
4. Decode the payload, then check:
   - `iss` matches the issuer DID (and the issuer DID resolves to
     the same DID Document that supplied the verifying key);
   - `nbf <= now < exp`;
   - `credentialSchema.id` matches the schema you expected for this
     claim type;
   - `type[1]` matches the expected claim family;
   - the `credentialSubject` shape conforms to that schema.

Treat any failure as a hard reject.
