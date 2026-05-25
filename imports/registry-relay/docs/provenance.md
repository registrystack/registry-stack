# Data Provenance

`registry-relay` can return W3C Verifiable Credentials (VCs), signed as
compact JWS, for two response families:

- `GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}` -> `AggregateResult`
- `GET /datasets/{dataset_id}/{entity}/{id}` -> `EntityRecord`

Evidence verification uses a separate server-to-server JWT receipt media type,
documented in [evidence-verification.md](evidence-verification.md), because it is not
a holder-presentable VC.

The feature is opt-in twice over: by the operator (config flag) and by
the caller (Accept header). When either says no, responses remain plain
JSON.

This document describes the runtime contract: configuration, wire
shapes, endpoints, audit events, and key management.

## Why Verifiable Credentials

Consumers of `registry-relay` increasingly need to relay government data to
downstream parties (cross-ministry workflows, EU-level dataspaces,
audit reviewers). Plain JSON gives them no cryptographic way to prove
"this came from registry-relay at time T under DID D". A VC-JWT does:
issuer DID, signing key, claim type, subject URI, and validity window
are all signed under one envelope that any verifier with the issuer's
DID Document can check.

The current encoding is W3C VCDM 2.0 + JWT binding rather than COSE or
SD-JWT-VC. The runtime contract here is stable regardless of future
encoding evolution.

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
    aggregate_result: 1h
    entity_record:    24h
  issuer:
    mode: gateway
    did: did:web:data.example.gov
    verification_method_id: did:web:data.example.gov#issuance
    signer:
      kind: software
      jwk_env: REGISTRY_RELAY_PROVENANCE_JWK
      signing_algorithm: EdDSA
```

The private JWK comes from an environment variable (never from the
YAML). The env value is a JSON-encoded private JWK, e.g.:

```json
{"kty":"OKP","crv":"Ed25519","d":"<base64url>","x":"<base64url>","alg":"EdDSA"}
```

Use 1Password, AWS Secrets Manager, or your platform's secret store to
inject it. Do not echo, log, or commit this value.

For local smoke tests, generate a throwaway Ed25519 JWK into ignored
build output and inject it into the environment:

```sh
mkdir -p target/provenance
node -e 'const crypto=require("node:crypto"); const {privateKey}=crypto.generateKeyPairSync("ed25519"); process.stdout.write(JSON.stringify({...privateKey.export({format:"jwk"}), alg:"EdDSA"}));' \
  > target/provenance/ed25519-private.jwk
export REGISTRY_RELAY_PROVENANCE_JWK="$(cat target/provenance/ed25519-private.jwk)"
```

This command is only for local testing. In production, mint the key in
the platform secret-management workflow and inject the env var without
writing private material to disk.

When `enabled: false` (or the block is omitted entirely), the gateway
behaves as a plain JSON service.

## Production Hardening Checklist

Treat the signing key as a production credential with the same handling
standard as an API root key:

1. Inject `REGISTRY_RELAY_PROVENANCE_JWK` from the platform secret store at
   process start. Do not place it in the YAML config, image layers,
   shell history, crash reports, issue trackers, or deployment logs.
2. Run the gateway under a dedicated service account with least
   privilege on the secret, config, source-data, cache, and audit paths.
3. Disable process core dumps and memory diagnostics that could capture
   environment variables or heap contents holding signer material.
4. Restrict interactive shell access on hosts that can read the signer
   env var. Prefer short-lived break-glass sessions with recorded
   access.
5. Keep source-data mounts read-only and keep audit sinks append-only
   from the gateway process where the platform supports it.
6. Alert on startup failures with `provenance.config.*`,
   `provenance.signer_unavailable`, and `provenance.issuance_failed`.
7. Exercise key rotation in a staging deployment before production:
   issue a VC with the old key, rotate, confirm the old `kid` remains
   in `/.well-known/did.json`, verify the old VC, and confirm the old
   key disappears only after the longest validity window has elapsed.
8. Publish the `/schemas/...` and `/contexts/...` URLs behind the same
   externally reachable base URL used in issued credentials, otherwise
   downstream verifiers cannot resolve the contract named in
   `credentialSchema.id` and `@context`.

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
GET /datasets/social_registry/individual/ind-123 HTTP/1.1
Accept: application/vc+jwt
```

Without that header (or when the header lists only types the operator
did not configure), the response stays plain JSON with the normal
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
  "type": ["VerifiableCredential", "EntityRecord"],
  "id": "urn:uuid:01J5K8M0...",
  "issuer": "did:web:data.example.gov",
  "validFrom": "2026-05-16T09:30:00Z",
  "validUntil": "2026-05-16T09:35:00Z",
  "credentialSchema": {
    "id": "https://data.example.gov/schemas/entity-record/v1.json",
    "type": "JsonSchema"
  },
  "credentialSubject": {
    "id": "<subject-uri>",
    "dataset": "social_registry",
    "entity": "individual",
    "fields": { "id": "ind-123" }
  },
  "iss": "did:web:data.example.gov",
  "sub": "<subject-uri>",
  "iat": 1747387800,
  "nbf": 1747387800,
  "exp": 1747388100,
  "jti": "urn:uuid:01J5K8M0..."
}
```

`type[1]` is one of `AggregateResult` or `EntityRecord`.
Subject URIs follow `<catalog.base_url>/datasets/<dataset>/<entity>/<id>`
for entity claims and
`<catalog.base_url>/datasets/<dataset>/<entity>/aggregates/<aggregate_id>`
for aggregates.

## PublicSchema.org Entity Credentials

When the binary is built with the optional `publicschema-cel` Cargo
feature, an entity can declare a PublicSchema.org mapping for its
entity-record VC. The plain JSON API stays unchanged. Only callers that
request `Accept: application/vc+jwt` receive the mapped PublicSchema
credential.

```yaml
entities:
  - name: individual
    table: individuals_table
    fields:
      - name: id
        from: individual_id
      - name: first_name
      - name: last_name
      - name: dob
      - name: sex_code
    access: { ... }
    api: { default_limit: 100, max_limit: 1000 }
    publicschema:
      target: Person
      mapping_path: mappings/individual-person.publicschema.yaml
      schema_validation_path: ../publicschema.org/dist/schemas/Person.schema.json
```

`mapping_path` points to a PublicSchema CEL mapping document. Its source
record is the projected entity JSON, not the private storage row, so
mapping rules should refer to public field names such as `/id` or
`/first_name`. At startup the gateway compiles every declared mapping;
an unreadable or invalid mapping fails startup.

During evaluation the gateway passes a CEL context object with
`ctx.subject_uri`, `ctx.dataset`, and `ctx.entity`. Mapping files should
use `ctx.subject_uri` for `/id`; the gateway rejects issuance if the
mapped `credentialSubject.id` differs from the canonical entity URI.
This keeps the VC `sub` and subject identifier anchored to the gateway
route even when mappings are reused across deployments.

`schema_validation_path` is optional but recommended. When present, the
gateway compiles the local JSON Schema at startup and validates every
mapped `credentialSubject` before signing. Validation failures abort VC
issuance with `provenance.issuance_failed`, so a bad mapping cannot
produce a signed credential.

By default the issued VC uses:

- `type[1]`: the configured `target`, for example `Person`
- `@context[1]`: `https://publicschema.org/ctx/draft.jsonld`
- `credentialSchema.id`:
  `https://publicschema.org/schemas/{target}.schema.json`

Operators may override those defaults with `context_url`, `schema_url`,
and `credential_type` under the same `publicschema:` block.

The mapper dependency is pinned to the public
`https://github.com/PublicSchema/cel-mapping` repository in
`Cargo.toml`, so release builds do not depend on a sibling checkout.
Profile overrides do not bypass provenance audit: PublicSchema issuance
still attaches the `provenance.vc.issued` block, with `claim_type`
recording the overridden VC type such as `Person`.

Build and verify the optional path with:

```sh
cargo test --features publicschema-cel --test publicschema_cel_feature
```

A binary built without `publicschema-cel` rejects configs that declare
`entities[].publicschema`, using
`publicschema.config.feature_disabled`. This prevents accidental
fallback to the native `EntityRecord` VC when the operator expected a
PublicSchema credential.

## Supporting Endpoints

When provenance is enabled in `gateway` mode, the data plane serves
three additional endpoints, all unauthenticated and content-cacheable:

- `GET /.well-known/did.json` returns the gateway's DID Document. It
  lists every active and retired `verificationMethod` so existing VCs
  signed under a rotated-out key still verify.
- `GET /schemas/{claim_type}/{version}` returns the JSON Schema (draft
  2020-12) describing the `credentialSubject` shape for that claim
  type. Paths: `aggregate-result/v1.json`, `entity-record/v1.json`, and the
  legacy `verify-result/v1.json` schema kept for old verifier fixtures.
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
{"ts":"2026-05-16T09:30:00.123Z","request_id":"01J5K8...","path":"/datasets/social_registry/individual/ind-123","status_code":200,"provenance":{"event":"provenance.vc.issued","iss":"did:web:data.example.gov","kid":"did:web:data.example.gov#issuance","jti":"urn:uuid:01J5K8M0...","claim_type":"EntityRecord","subject":"https://data.example.gov/datasets/social_registry/individual/ind-123","validity":{"iat":1747387800,"nbf":1747387800,"exp":1747388100}}}
```

The `claim_type` field tracks `type[1]` of the VC. `kid` matches the
JOSE `kid` header. `jti` matches the VC's `id` and JWT `jti`. The
record never contains the private JWK or the compact JWS body.

Plain-JSON responses (no Accept opt-in, or `provenance.enabled: false`)
omit the `provenance` block entirely.

## Key Rotation

The signing key is referenced indirectly: the config names an env var,
the env var holds the JWK. To rotate:

1. Mint a new Ed25519 keypair. V1 production signing supports local
   software EdDSA only; P-256 (`ES256`) is reserved for a future signer
   backend.
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

Gateway-mode rotation config should keep the previous public key in
`retired_keys` until every credential signed by it has expired:

```yaml
provenance:
  enabled: true
  schema_base_url: https://data.example.gov/schemas
  context_base_url: https://data.example.gov/contexts
  claim_validity:
    aggregate_result: 1h
    entity_record: 24h
  issuer:
    mode: gateway
    did: did:web:data.example.gov
    verification_method_id: did:web:data.example.gov#issuance-2026-06
    signer:
      kind: software
      jwk_env: REGISTRY_RELAY_PROVENANCE_JWK
      signing_algorithm: EdDSA
    retired_keys:
      - verification_method_id: did:web:data.example.gov#issuance-2026-05
        jwk_env: REGISTRY_RELAY_RETIRED_2026_05_PUBLIC_JWK
        retired_after: "2026-06-01T00:00:00Z"
```

`REGISTRY_RELAY_RETIRED_2026_05_PUBLIC_JWK` must contain only the
public JWK. If an operator accidentally supplies a full keypair, the
gateway strips `d` before publishing the DID Document, but secret-store
policy should still keep retired private keys out of public config.

## Delegated Mode Runbook

Delegated mode signs under the ministry DID while the gateway continues
to host schemas and contexts. The ministry, not the gateway, must host
the DID Document:

```yaml
provenance:
  enabled: true
  schema_base_url: https://relay.example.gov/schemas
  context_base_url: https://relay.example.gov/contexts
  claim_validity:
    aggregate_result: 1h
    entity_record: 24h
  issuer:
    mode: delegated
    ministry_did: did:web:ministry.example.gov
    verification_method_id: did:web:ministry.example.gov#registry-relay
    signer:
      kind: software
      jwk_env: REGISTRY_RELAY_PROVENANCE_JWK
      signing_algorithm: EdDSA
```

Before enabling delegated mode in production:

1. Confirm `https://ministry.example.gov/.well-known/did.json`
   contains `verificationMethod[].id:
   did:web:ministry.example.gov#registry-relay`.
2. Confirm that method's `publicKeyJwk.x` matches the gateway signing
   key's public key and does not contain `d`.
3. Confirm the gateway returns `404 provenance.did_document_unavailable`
   for `GET /.well-known/did.json`.
4. Issue a VC from the gateway and verify it with the ministry-hosted
   DID Document plus the gateway-hosted schema.

## Future Signer Backends

V1 production deployments support only the local software Ed25519 path:

```yaml
signer:
  kind: software
  jwk_env: REGISTRY_RELAY_PROVENANCE_JWK
  signing_algorithm: EdDSA
```

The software signer, public JWK export, DID validation, and SD-JWT
holder-proof helpers are delegated to the shared `registry-platform`
crypto and SD-JWT crates. This keeps Relay's provenance behavior aligned
with the platform verifier rules, including `aud`, `exp > iat`, maximum
300-second holder-proof lifetime, bound evaluation/profile/disclosure
claims, sorted `_sd` digests, and `jti == credential_id` issuance
parity.

`signer.kind: kms` is reserved for future remote signing backends and
is rejected by config validation today. The internal signer trait is
kept narrow so an AWS KMS, GCP KMS, HSM, or out-of-process signer can
be added later without changing the VC-JWT envelope, DID Web behavior,
or issuer-mode model.

The production acceptance bar for any future remote signer backend is:

- The gateway never receives or logs private key material.
- Startup can resolve the configured key id to a public JWK suitable
  for `/.well-known/did.json`.
- Runtime signing returns compact JWS output with the same JOSE header
  and VCDM 2.0 payload shape as the software Ed25519 path.
- Key-disabled, access-denied, throttling, and regional outage failures
  map to `provenance.signer_unavailable` without leaking request
  payloads or secret identifiers beyond operator-safe key ids.
- Integration tests verify issued VCs with a third-party JOSE library
  using only the DID-published public JWK.

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

The repository includes an operator-facing verifier that performs this
flow using only public artifacts:

```sh
node scripts/verify_vc_jwt.mjs \
  --jwt-file target/provenance/vc.jwt \
  --did-document target/provenance/did.json \
  --issuer did:web:data.example.gov \
  --claim-type EntityRecord \
  --schema-id https://data.example.gov/schemas/entity-record/v1.json \
  --schema target/provenance/entity-record.schema.json
```

The verifier accepts local paths, `file://` URLs, and `http(s)` URLs
for DID Documents and schemas. For deterministic fixture checks, pass
`--now <unix-or-rfc3339>`.

### Production Smoke Checklist

Use this checklist after every production deployment that uses the local
software Ed25519 signer:

1. Start the gateway with `REGISTRY_RELAY_PROVENANCE_JWK` injected from
   the secret store, not from a shell prompt or config file. Confirm
   startup succeeds and readiness is green:

```sh
curl -fsS "https://data.example.gov/ready"
```

2. Fetch the public contract artifacts from the same externally
   reachable host named by issued credentials:

```sh
mkdir -p target/provenance

curl -fsS \
  "https://data.example.gov/.well-known/did.json" \
  -o target/provenance/did.json

curl -fsS \
  "https://data.example.gov/schemas/entity-record/v1.json" \
  -o target/provenance/entity-record.schema.json
```

3. Issue one entity-record VC with the lowest-privilege row-read API key:

```sh
curl -fsS \
  -H "Authorization: Bearer ${ROW_READ_API_KEY}" \
  -H "Accept: application/vc+jwt" \
  "https://data.example.gov/datasets/social_registry/individual/ind-123" \
  -o target/provenance/vc.jwt
```

4. Verify the VC with the repository verifier using only public
   artifacts:

```sh
node scripts/verify_vc_jwt.mjs \
  --jwt-file target/provenance/vc.jwt \
  --did-document target/provenance/did.json \
  --issuer did:web:data.example.gov \
  --claim-type EntityRecord \
  --schema-id https://data.example.gov/schemas/entity-record/v1.json \
  --schema target/provenance/entity-record.schema.json
```

For delegated mode, replace `--did-document` with the ministry-hosted
DID Document and keep `--schema` pointed at the gateway-hosted schema:

```sh
curl -fsS \
  "https://ministry.example.gov/.well-known/did.json" \
  -o target/provenance/ministry.did.json

node scripts/verify_vc_jwt.mjs \
  --jwt-file target/provenance/vc.jwt \
  --did-document target/provenance/ministry.did.json \
  --issuer did:web:ministry.example.gov \
  --claim-type EntityRecord \
  --schema-id https://relay.example.gov/schemas/entity-record/v1.json \
  --schema target/provenance/entity-record.schema.json
```

5. For rotation smoke, run the same issuance and verifier steps once
   before rotation and save the old VC. After rolling the new
   `verification_method_id` and new private JWK, fetch
   `/.well-known/did.json` again, confirm it publishes both old and new
   verification methods, issue a new VC, and verify both JWT files. The
   old VC must verify through the retired public key until the longest
   configured `claim_validity` window has elapsed. After that window,
   remove the retired key and repeat the DID fetch to confirm the old
   `kid` is no longer published.

### Fixture Corpus

`tests/fixtures/vc/verify-result-v1/` contains a static VC-JWT, decoded
payload, DID Document, and JSON Schema. It is signed outside
`registry_relay` and verified by `tests/vc_external_verifier.rs` through
the Node verifier. Add a new fixture directory whenever the public VC
wire contract changes or a new claim type/version is introduced.
