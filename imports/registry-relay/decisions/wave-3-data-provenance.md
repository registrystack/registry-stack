# Wave 3: Data Provenance (Signed Claims)

Status: proposed for V2. Not yet committed. Supersedes the trust-and-discovery framing in `wave-3-dataspace-trust-and-catalog.md` (kept on disk as a rejected alternative; that wave answered the wrong question for our actual goal).

This wave makes data_gate an **issuer** of Verifiable Credentials. Specifically, it lets consumers receive `/verify` and `/aggregate` responses as W3C Verifiable Credentials signed by the gateway, so a consumer can re-present those answers to a third party (regulator, downstream agency, statistical office) and have the answer cryptographically verified without contacting data_gate.

The wave does *not* introduce VC-based **authentication of consumers**. The wave-0 API-key model continues unchanged. Trust flows outward only.

---

## 1. Decision Log

| # | Decision | Rationale |
|---|---|---|
| D1 | **Scope is issuer-side data-provenance VCs.** No incoming VC/VP verification, no DSP, no DCP, no consumer-auth changes. | This is the smallest slice with sharp, demonstrable value: signed claims that travel further than the original consumer. The auth direction stays out (see rejected alternative wave-3-dataspace-trust-and-catalog). |
| D2 | **Granularity: `/verify`, `/aggregate`, and single-entity `/datasets/.../{entity}/{id}` reads.** No collection (array) responses, no catalog signing, no audit signing. | All three return small, third-party-meaningful records with a single subject. Collection responses (arrays of records) are a different feature pattern (response envelopes) and are deferred. Single-entity reads with `?expand=` include the projected expansion data in the VC; the wave-2 projection still hides unexposed fields. |
| D3 | **V1 signature format: VC-JWT (W3C VC Data Model 2.0, JWT encoding).** Format is configurable; the signer/encoder lives behind a trait so SD-JWT-VC, JAdES, and Data Integrity Proofs can be added later. | VC-JWT has the narrowest crypto surface, the broadest library support, and the cleanest path to SD-JWT-VC (EUDI-aligned) when needed. JAdES is overkill for V1; SD-JWT-VC is forward work. |
| D4 | **Issuer identity is configurable: `gateway` or `delegated`.** The binary supports both modes; each deployment selects exactly one at startup. Same code path; only the DID, verification method, and key custody differ. Per-claim issuer selection (some claims gateway-issued, some delegated, in one deployment) is deferred to a follow-up wave. | Most deployments will eventually want gateway-self for technical claims and ministry-issued for substantive legal claims. V1 picks one per deployment; richer selection comes later. |
| D5 | **DID method for the issuer is `did:web`.** Single method, single resolution path, no blockchain dependency. | Government posture, plain HTTPS, no operational tail. Ministries already operate authoritative HTTPS domains; this is the lowest-friction issuer DID method. |
| D6 | **Key custody is pluggable: software signer in-tree, KMS adapter optional.** V1 ships a `SoftwareSigner` (private JWK in env var or file) and a `Signer` trait. A KMS adapter (`AwsKmsSigner` or PKCS#11) is implementable behind the same trait but is *not* required for V1 exit. | KMS is the right production posture but adds operational dependencies that not all deployments will have on day one. The trait keeps both options first-class. |
| D7 | **VCs are short-lived with `exp` and no in-band revocation.** Default validity windows: `VerifyResult` 24h, `EntityRecord` 12h, `AggregateResult` 30d, all configurable. No BitstringStatusList in V1. | A VC issued by data_gate is a point-in-time attestation. "True as of T, valid until T+window" is the natural contract. Adding revocation later is additive; building it now adds infra for no current benefit. |
| D8 | **VC issuance is opt-in per request via the `Accept` header.** Only an explicit `Accept` mentioning a configured provenance media type (default `application/vc+jwt`, alias `application/jwt`) returns a signed VC. `application/json`, `*/*`, missing `Accept`, and unmatched `Accept` all preserve the wave-0/2 plain JSON response verbatim. When `provenance.enabled` is `false`, the wave is invisible: no Accept negotiation runs, no new content type is advertised, no wave-specific status code is emitted. | Backward compatible; no caller is forced into a new contract, no global default flips signing on. Existing API-key clients can adopt VCs at their own pace. |
| D9 | **VC subject identifiers are the canonical entity URLs**, e.g. `https://gw.example.gov/datasets/social_registry/individual/P-1234`. Aggregate subjects use the aggregate URL. | Subjects are dereferenceable. No invented URI scheme. Wave-2 entity URLs remain the public stable handles. |
| D10 | **Claim schemas and the JSON-LD context are versioned, in-tree, and self-published.** Three V1 claim types: `VerifyResult`, `AggregateResult`, `EntityRecord`. Each has a JSON Schema served at a stable `schema_base_url`. One JSON-LD context (`provenance/v1.jsonld`) covers all three claim types, served at a stable `context_base_url`. JSON-LD context ≠ JSON Schema (see §8). | Schemas and contexts are part of the cryptographic contract. They must be stable, addressable, and versioned. Hosting them via data_gate keeps them aligned with the issuer's lifecycle. |
| D11 | **The wave is verifier-agnostic.** data_gate does not host a verification endpoint. Consumers verify out-of-band with any W3C VC-JWT library. | This is the whole point of VCs. A verification endpoint would defeat the property. |
| D12 | **Signing is synchronous in the request path.** No batched signing, no async issuance queue. | The added latency is small (single-digit ms for software, ~20ms for KMS). Async issuance is a different operational model. |
| D13 | **No additional durable state.** Signing keys come from config / env / KMS. Validity windows come from config. There is no per-issuance database. | Issuance is stateless. Audit captures every issuance; the audit chain is the durable record. |
| D14 | **Audit gains `provenance.vc.issued` events.** Every signed response produces an audit event including `iss`, `kid`, `jti`, claim type, and subject URI. | Operationally and legally, "what did we sign and when" is the most important question this wave creates. |

---

## 2. Scope and Non-Goals

### In scope

- VC-JWT issuance for `/verify` responses (`VerifyResult` claim).
- VC-JWT issuance for single-aggregate responses `/aggregates/{aggregate_id}` (`AggregateResult` claim).
- VC-JWT issuance for single-entity reads `/{entity}/{id}` (`EntityRecord` claim), including `?expand=` data.
- `Accept: application/vc+jwt` content negotiation.
- `did:web` document hosting at `/.well-known/did.json` (gateway mode).
- Pluggable `Signer` trait with `SoftwareSigner` shipping in-tree.
- KMS adapter interface (reference implementation optional in V1).
- Issuer config: gateway mode, delegated mode (binary supports both; deployment picks one).
- Claim schemas (`VerifyResult` v1, `AggregateResult` v1, `EntityRecord` v1) + JSON Schemas served at `/schemas/...`.
- A pinned data-provenance JSON-LD context served at `/contexts/provenance/{version}.jsonld`.
- Audit events for every issuance.
- Operational and security documentation for key custody and rotation.

### Out of scope (deferred to later waves)

- Collection-response signing (signing arrays of records returned by `/{entity}` listings).
- Aggregate-listing signing (`/aggregates` index response).
- Catalog / dataset entry signing.
- Audit-log entry signing.
- SD-JWT-VC (selective disclosure). Forward-compatible, not implemented.
- LD-Proofs / Data Integrity Proofs.
- JAdES.
- Status list revocation (BitstringStatusList).
- Multi-active-key sets and automated key rotation.
- Incoming VC / VP verification (entire wave-3-A direction; rejected).
- DSP, DCP, IDS protocols.
- mDoc / EUDI Wallet protocols (OpenID4VCI, OpenID4VP).
- `/.well-known/openid-credential-issuer` and other wallet-issuance endpoints.

---

## 3. File Ownership

```
src/
  provenance/                # new
    mod.rs                   # public types, Signer trait, IssuanceContext
    issuer.rs                # IssuerConfig, IssuerMode, key resolution
    jwt_vc.rs                # VC-JWT encoder (header + payload + JWS)
    signer.rs                # Signer trait
    signers/
      software.rs            # SoftwareSigner (PKCS8 / JWK from env or file)
      kms.rs                 # KmsSigner trait + AwsKmsSigner (optional)
    claim/
      mod.rs                 # Claim trait, type registry
      verify_result.rs       # VerifyResult model + schema
      aggregate_result.rs    # AggregateResult model + schema
      entity_record.rs       # EntityRecord model + schema
    did_web.rs               # build /.well-known/did.json for gateway mode
  api/
    verify.rs                # touched: Accept negotiation; call provenance::issue
    aggregates.rs            # touched: Accept negotiation; call provenance::issue
    entity.rs                # touched: Accept negotiation for /{entity}/{id}
    did.rs                   # new: GET /.well-known/did.json
    schemas.rs               # new: GET /schemas/{type}/{version}.json
    contexts.rs              # new: GET /contexts/provenance/{version}.jsonld
    mod.rs                   # touched: mount new routes
  config/
    provenance.rs            # new
    mod.rs                   # touched: ProvenanceConfig in Config
  audit/
    mod.rs                   # touched: provenance.vc.issued event variant
resources/
  jsonld/                    # new
    vc/v2/credentials.jsonld # pinned W3C VC v2 context (vendored copy)
    provenance/v1/context.jsonld # data_gate-defined claim terms (VerifyResult, AggregateResult, EntityRecord)
  schemas/                   # new
    verify-result/v1.json
    aggregate-result/v1.json
    entity-record/v1.json
tests/
  provenance_verify.rs       # new
  provenance_aggregate.rs    # new
  provenance_entity_record.rs # new
  did_web_document.rs        # new
  third_party_verification.rs # use ssi or jose to verify our output
  signer_trait.rs            # new (with mock signer)
fixtures/
  provenance/                # new: test JWKs, expected VC fixtures
docs/
  provenance.md              # new: operator playbook
```

Tracks (no two write the same file concurrently):

| Track | Owns | Notes |
|---|---|---|
| Issuer config + key resolution | `src/provenance/issuer.rs`, `src/config/provenance.rs` | Validation, env-var handling, secret hygiene. |
| Signing + signers | `src/provenance/signer.rs`, `src/provenance/signers/**` | Heavy implementer. JWS algorithm support, KMS interface. |
| VC encoding + schemas | `src/provenance/jwt_vc.rs`, `src/provenance/claim/**`, `resources/schemas/**` | JSON Schema authoring, VC-JWT compliance. |
| HTTP integration | `src/api/verify.rs`, `src/api/aggregates.rs`, `src/api/did.rs`, `src/api/schemas.rs` | Accept negotiation, route mounting. |
| Audit | `src/audit/mod.rs` | New event variant; must not break the existing chain. |
| Tests + third-party verification | `tests/**`, `fixtures/provenance/**` | The third-party-verification test is the spec's main interop gate. |

---

## 4. Public Surface

### Touched endpoints

```
GET /datasets/{dataset}/{entity}/verify
GET /datasets/{dataset}/{entity}/aggregates/{aggregate_id}
GET /datasets/{dataset}/{entity}/{id}
GET /datasets/{dataset}/{entity}/{id}?expand=<relationship>
```

`/aggregates` (the listing endpoint) is **not** touched in V1: it returns an index of aggregate definitions, not a third-party-meaningful single answer. Collection responses (`/{entity}` listings) are out of scope.

Behaviour:

- `Accept: application/json` (or anything not matching a configured provenance media type): unchanged. Wave-0/2 plain JSON.
- `Accept: application/vc+jwt`: response body is a compact-serialized JWT (the VC). `Content-Type: application/vc+jwt`. Status codes unchanged.
- `Accept: application/jwt`: same as `application/vc+jwt` (alias for tooling that does not know the VC media type yet).
- `Accept: */*`: same as `application/json` (default to backward-compatible).
- Missing `Accept` header: same as `application/json`.
- Multiple accepted media types: q-value resolution per RFC 9110; ties resolve in favour of `application/json` (preserves wave-0/2 default).
- When `provenance.enabled` is `false`: the new media types are not advertised and no wave-specific status code is produced. An `Accept` header that does not match anything we serve falls through to the standard RFC 9110 path (`406 Not Acceptable` with the gateway's normal error envelope, if and only if the runtime cannot offer any representation).
- When `provenance.enabled` is `true` but the caller's `Accept` explicitly requests *only* a provenance media type and the deployment cannot sign (signer unavailable): `503 provenance.signer_unavailable`.

### New endpoints

```
GET /.well-known/did.json
  unauthenticated, public; serves the gateway DID Document.
  Returns 404 when issuer.mode = delegated and no gateway DID is configured.

GET /schemas/{claim_type}/{version}.json
  unauthenticated, public; serves the JSON Schema for a claim type.
  CORS: Access-Control-Allow-Origin: *

GET /contexts/provenance/{version}.jsonld
  unauthenticated, public; serves the data_gate-defined JSON-LD context
  that names the VerifyResult / AggregateResult / EntityRecord terms.
  Distinct from the JSON Schema: the JSON-LD context provides @id / @type
  mappings; the JSON Schema validates the credentialSubject value shape.
  CORS: Access-Control-Allow-Origin: *
```

All three new endpoints are mounted on the public data-plane listener. They are explicitly public and unauthenticated.

### Removed

Nothing. API-key auth is unchanged; existing JSON responses are unchanged.

---

## 5. Config Shape

Extends the top-level config with a new `provenance` section. Wave-0 `auth` block is untouched.

```yaml
provenance:
  enabled: true
  accepted_media_types:
    - application/vc+jwt
    - application/jwt
  schema_base_url: https://gw.example.gov/schemas
  context_base_url: https://gw.example.gov/contexts
  claim_validity:
    verify_result: 24h
    aggregate_result: 30d
    entity_record: 12h
  issuer:
    mode: gateway                # gateway | delegated
    gateway:
      did: did:web:gw.example.gov
      verification_method_id: did:web:gw.example.gov#key-1
      signer:
        kind: software           # software | kms
        # software:
        jwk_env: DATAGATE_SIGNING_JWK
        # kms (alternative):
        # provider: aws_kms
        # key_id: arn:aws:kms:eu-west-3:111:key/abcd-...
        # signing_algorithm: EdDSA
    delegated:
      ministry_did: did:web:finance.example.gov
      verification_method_id: did:web:finance.example.gov#datagate-eu-west
      signer:
        kind: kms
        provider: aws_kms
        key_id: arn:aws:kms:eu-west-3:111:key/...
        signing_algorithm: EdDSA
```

Validation rules:

* exactly one issuer mode (`gateway` or `delegated`) is required when `enabled: true`.
* in `gateway` mode, `did` resolves to `did:web:<deployment-host>` matching the deployed `/.well-known/did.json`; mismatch fails startup.
* `verification_method_id` is a fragment-suffixed form of the issuer DID.
* `signer.kind: software` requires `jwk_env` to be set in the environment at startup and to contain a parseable JWK with a private key part.
* `signer.kind: kms` requires `key_id` and `signing_algorithm`; the key reachability check runs at startup.
* `signing_algorithm` is one of `EdDSA`, `ES256`. Anything else fails validation.
* `schema_base_url` resolves to the gateway's own `/schemas/` namespace by default. External hosting is allowed but warned.
* `context_base_url` resolves to the gateway's own `/contexts/` namespace by default. External hosting is allowed but warned. The configured value plus `provenance/<version>.jsonld` must match the URL the gateway will embed in `@context` arrays.
* `claim_validity.*` parses as a duration; minimum 1 minute, maximum 365 days. Required keys: `verify_result`, `aggregate_result`, `entity_record`.

Secrets handling:

- Private JWK material comes from `jwk_env` only. Never inline in YAML. Never logged. Never echoed in config dumps.
- KMS key ARNs may be logged at startup; private key material never leaves the KMS.

---

## 6. Issuer Identity Model

Two modes, same code path, different config.

### Gateway mode

data_gate is the issuer. The deployment's domain hosts the DID Document at `/.well-known/did.json`. data_gate signs every VC with its own private key.

```
issuer DID:                did:web:gw.example.gov
verification method:       did:web:gw.example.gov#key-1
key custody:               software or KMS, in data_gate's environment
DID document hosting:      data_gate serves it
legal weight:              "the gateway operator says so"
```

Typical use: technical claims, operational attestations, low-stakes consultation responses.

### Delegated mode

A ministry is the issuer. The ministry hosts its own `did:web` DID Document, and that document includes a `verificationMethod` entry naming a key that data_gate controls. data_gate signs on the ministry's behalf using that key.

```
issuer DID:                did:web:finance.example.gov
verification method:       did:web:finance.example.gov#datagate-eu-west
key custody:               KMS (recommended) or software, in data_gate's environment
DID document hosting:      ministry serves it (data_gate does NOT)
legal weight:              "the ministry says so"
```

Typical use: substantive legal claims that need ministry-level attribution (eligibility, benefit status, demographic facts).

Both modes use the same signing pipeline. The only difference is which `iss`, `kid`, and private key are loaded.

### Why both, configurable

Real deployments will need both. A ministry might delegate `VerifyResult` claims (signed under its DID) while keeping `AggregateResult` claims under the gateway's DID for operational separation. The config does not enforce a per-claim split today (it picks one mode at startup); that is a deferred enhancement (§14).

---

## 7. Signing Pipeline

### Signer trait

```rust
pub struct SigningInput<'a> {
    pub jws_header: JwsHeader<'a>,   // alg, typ, kid, cty
    pub payload: &'a [u8],            // the JWT payload bytes
}

pub struct SigningOutput {
    pub jws_compact: String,          // header.payload.signature
}

#[async_trait]
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> SigningAlgorithm;
    fn verification_method_id(&self) -> &str;
    async fn sign(&self, input: SigningInput<'_>) -> Result<SigningOutput, SignerError>;
}
```

### SoftwareSigner

- Reads a private JWK from `jwk_env` at startup.
- Validates the JWK has a private component and matches `signing_algorithm`.
- Holds the key in-memory; never written to disk; zeroized on drop where the crypto crate supports it.
- Signing is local, blocking-free, ~200µs–1ms depending on algorithm.

### KmsSigner (interface; reference impl optional)

- `AwsKmsSigner` (behind `--features kms-aws`) calls `kms:Sign` per VC.
- Caches the public key fetched once at startup for the DID document.
- Signing latency: 10–50ms typical, region-dependent.
- Returns `SignerError::Unavailable` on KMS outage; the request fails 503 with `provenance.signer_unavailable`.

### Algorithm support in V1

- `EdDSA` (Ed25519) (recommended default).
- `ES256` (NIST P-256).

ES256K, PS256, RS256 are not in V1. Adding them is a config + dependency change, not an architectural one.

### Key rotation in V1

Single **active** signing key per deployment, but the DID Document retains **retired** keys until VCs signed by them have expired.

Mechanics:

- Operators add a new key (`key-2`) to config; data_gate starts signing with `key-2`.
- The previous key (`key-1`) becomes "retired": it stays in the DID Document's `verificationMethod` array (so consumers can still resolve `kid` to a public key) but is removed from `assertionMethod` (so it is no longer a credential-signing identity going forward).
- A retired key is fully removed from the DID Document only after `now > issued_at_of_last_signed_vc + max(claim_validity.*) + clock_skew_grace` (default grace: 5 minutes).
- The retirement timestamp for each key is recorded in config (`retired_after`); data_gate computes the removal eligibility deterministically.
- Until then, retired keys are present-but-not-assertion-eligible. Any consumer that fetched a VC during the previous key's active window can still verify it.

Config addition (per signer):

```yaml
issuer:
  gateway:
    signer:
      kind: software
      jwk_env: DATAGATE_SIGNING_JWK
      retired_keys:
        - verification_method_id: did:web:gw.example.gov#key-0
          jwk_env: DATAGATE_RETIRED_KEY_0_JWK_PUBLIC   # public part only, for DID Doc
          retired_after: 2026-05-01T00:00:00Z
```

V2 will add overlapping active keys (multiple `assertionMethod` entries usable for signing) and automated rotation orchestration.

---

## 8. Claim Schemas

Two layers are involved, and they are not the same thing:

- **JSON-LD context** (`/contexts/provenance/{version}.jsonld`): maps claim-type names and field names to absolute IRIs so the VC is a well-formed RDF graph. Referenced from the VC's `@context` array.
- **JSON Schema** (`/schemas/{claim-type}/{version}.json`): validates the *value shape* of `credentialSubject` for one claim type. Referenced from the VC's `credentialSchema.id`.

A consumer that only does cryptographic verification can ignore both. A consumer that wants strict structural validation fetches the JSON Schema. A consumer that wants graph processing follows the JSON-LD context.

The JSON-LD context URL is **not** a JSON Schema URL and vice versa. Confusing the two breaks JSON-LD processors.

### `VerifyResult` v1

Conceptual model:

```
VerifyResult {
  dataset:    string       // e.g. "social_registry"
  entity:     string       // e.g. "individual"
  subjectId:  string       // e.g. "P-1234"
  predicate:  string       // e.g. "isHouseholdHead", "isEnrolledIn:program-X"
  value:      bool | string | number | null
  asOf:       string (RFC 3339 timestamp)
}
```

JSON Schema: `<schema_base_url>/verify-result/v1.json`.

### `AggregateResult` v1

Mirrors the wave-2 aggregate response (one row per declared `group_by` value bucket, multiple measures per row, plus disclosure-control bookkeeping). The credential captures the actual answer, not a single measurement.

Conceptual model:

```
AggregateResult {
  dataset:         string
  entity:          string
  aggregateId:     string                       // wave-2 aggregate identifier (URL-safe form)
  aggregateUrl:    string                       // canonical URL: <gw>/datasets/{dataset}/{entity}/aggregates/{aggregateId}
  groupBy:         [string]                     // declared group-by fields, in declaration order; empty = global
  measures:        [string]                     // declared measure ids, in declaration order
  rows: [
    {
      group: { <groupBy[i]>: <scalar value> }, // empty object for global aggregate
      values: { <measure_id>: number | null }  // null when disclosure control suppressed this measure for this row
    }
  ],
  suppressedGroups: integer,                    // count of rows hidden by min_group_size; matches wave-2 response
  minGroupSize:    integer,                     // disclosure-control threshold applied
  computedAt:      string (RFC 3339 timestamp), // wave-2 computed_at
  asOf:            string (RFC 3339 timestamp)  // equal to computedAt unless the aggregate was cached
}
```

JSON Schema: `<schema_base_url>/aggregate-result/v1.json`. The schema requires `rows` to be non-empty unless `suppressedGroups > 0` and the entire result was suppressed (in which case `rows` is `[]` and the VC still asserts "as of this time, all groups were suppressed").

`/aggregates/{aggregate_id}` is the only aggregate endpoint that returns `AggregateResult` VCs. `/aggregates` (the listing/index) is not signed in V1.

### `EntityRecord` v1

Captures the public projection of a single entity, including any requested `?expand=` relationship data, exactly as the wave-2 plain-JSON `/datasets/{dataset}/{entity}/{id}` response would have returned it.

Conceptual model:

```
EntityRecord {
  dataset:    string
  entity:     string
  subjectId:  string                  // primary-key field value for this entity
  fields:     { <projected_field>: <scalar | null> },  // wave-2 projection rules apply
  expanded:   { <relationship>: <expansion payload> }, // present when ?expand= was used; same shape wave-2 returns
  asOf:       string (RFC 3339 timestamp)
}
```

Notes:
- `fields` reflects the entity projection only. Unexposed columns never appear in `fields` even if they exist on the backing table.
- `expanded` is omitted entirely when the request did not include `?expand=`.
- The credential subject identifier is the canonical entity URL (D9), e.g. `https://gw.example.gov/datasets/social_registry/individual/P-1234`.
- `EntityRecord` VCs carry more PII than `VerifyResult` VCs; the operator playbook (`docs/provenance.md`) explicitly calls this out (see R12).

JSON Schema: `<schema_base_url>/entity-record/v1.json`. The schema validates the shape, not the field set (which is driven by per-dataset projection config and is not statically known).

### JSON-LD context

`<context_base_url>/provenance/v1.jsonld` defines the IRIs for `VerifyResult`, `AggregateResult`, `EntityRecord`, and their first-class fields. Every VC embeds two entries in its `@context` array:

1. `https://www.w3.org/ns/credentials/v2`
2. `<context_base_url>/provenance/v1.jsonld`

### Versioning

- JSON-LD context URLs are stable; v1 stays v1 forever once published.
- JSON Schema URLs are stable; v1 stays v1 forever once published.
- New claim shapes go to v2 (new URLs for both context and schema).
- The VC embeds `credentialSchema.id` pointing at the exact JSON Schema version URL.
- The VC embeds the matching context URL in `@context`.
- Files in `resources/jsonld/` and `resources/schemas/` are immutable once shipped; CI verifies sha256.

---

## 9. VC-JWT Envelope (VCDM 2.0)

V1 follows the W3C *Securing Verifiable Credentials using JOSE and COSE* Recommendation: the VCDM 2.0 credential is the JWT payload directly. There is **no legacy nested `vc` claim** (that pattern is VCDM 1.1 only).

### JWS header

```
{
  "alg": "EdDSA",                  // or ES256
  "typ": "vc+jwt",
  "cty": "vc",
  "kid": "did:web:gw.example.gov#key-1"
}
```

`cty: vc` is the Recommendation-mandated content type. `typ: vc+jwt` identifies the envelope. `kid` is the absolute `verificationMethod` URI of the signing key.

### JWT payload (VCDM 2.0 credential, top-level)

The credential's standard members are top-level JWT claims. JWT-registered timestamp claims are *the* validity timestamps; the VCDM `validFrom` / `validUntil` are also emitted for VCDM-aware consumers and must equal the JWT `nbf` / `exp` (in RFC 3339 form).

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://gw.example.gov/contexts/provenance/v1.jsonld"
  ],
  "type": ["VerifiableCredential", "VerifyResult"],
  "id":         "urn:uuid:b94e...3a1f",
  "issuer":     "did:web:gw.example.gov",
  "validFrom":  "2026-05-16T12:00:00Z",
  "validUntil": "2026-05-17T12:00:00Z",
  "credentialSubject": {
    "id":        "https://gw.example.gov/datasets/social_registry/individual/P-1234",
    "dataset":   "social_registry",
    "entity":    "individual",
    "predicate": "isHouseholdHead",
    "value":     true,
    "asOf":      "2026-05-16T12:00:00Z"
  },
  "credentialSchema": {
    "id":   "https://gw.example.gov/schemas/verify-result/v1.json",
    "type": "JsonSchema"
  },

  "iss": "did:web:gw.example.gov",
  "sub": "https://gw.example.gov/datasets/social_registry/individual/P-1234",
  "jti": "urn:uuid:b94e...3a1f",
  "iat": 1747600000,
  "nbf": 1747600000,
  "exp": 1747686400
}
```

Conformance rules:

- `@context[0]` is exactly `https://www.w3.org/ns/credentials/v2`.
- `@context[1]` is exactly `<context_base_url>/provenance/v1.jsonld`.
- `type[0]` is exactly `"VerifiableCredential"`.
- `type[1]` is exactly the claim-type name (`VerifyResult`, `AggregateResult`, or `EntityRecord`).
- `id` and `jti` are the **same** UUID urn for the credential; one of them is redundant under the Recommendation, both are emitted to be friendly to consumers that only inspect one.
- `issuer` and `iss` are the **same** DID; same rationale.
- `validFrom` equals `nbf` (RFC 3339 form of the same instant). `validUntil` equals `exp`.
- `validUntil` and `exp` are derived from `claim_validity.<type>` in config.
- No `vc` claim. No `vp` claim.

The wire format is the compact JWS serialisation: `base64url(header) "." base64url(payload) "." base64url(signature)`.

### Why VCDM 2.0 and not the VCDM 1.1 nested-`vc` form

The W3C VC JOSE/COSE Recommendation (2025) explicitly secures VCDM 2.0 credentials as top-level JWT payloads. The nested `vc` claim was a workaround for VCDM 1.1 alignment with RFC 7519's registered claim set. Modern verifiers (Spruce `ssi` ≥ 0.9, `did-jwt-vc` ≥ 4.x, EUDI reference verifiers) expect the top-level form for `typ: vc+jwt`.

### Why VC-JWT and not LD-Proofs

- VC-JWT canonicalisation is well-defined (JSON serialisation; no LD canonicalisation).
- Library support is broad in every relevant language (Rust `ssi` / `jsonwebtoken`, JavaScript `jose`, Java `nimbus-jose-jwt`, Python `joserfc`).
- The signature surface is small; no graph canonicalisation, no URDNA2015.
- SD-JWT-VC is a strict extension of VC-JWT; the V1 envelope migrates with minimal disruption.

---

## 10. Verification Path for Consumers

data_gate does not provide a verification endpoint. Consumers verify out-of-band.

Reference flow:

1. Receive the compact JWS in the response body.
2. Decode the JWS header. Read `iss` from the payload (peek) and `kid` from the header.
3. Resolve `iss` to a DID Document via `did:web` (`https://{host}/.well-known/did.json` for the host encoded in the DID).
4. Find the `verificationMethod` whose `id` matches `kid`.
5. Verify the JWS signature using the public key from that verification method.
6. Verify `iat`, `nbf`, `exp` against the verifier's clock. Optionally cross-check `validFrom`/`validUntil` for equality with `nbf`/`exp`.
7. Compare `credentialSchema.id` (top-level) against the expected schema URL for the claim type indicated in `type[1]`.
8. Optionally fetch the JSON Schema from `credentialSchema.id` and validate `credentialSubject`.

The `tests/third_party_verification.rs` test exercises this flow against produced VCs using both the Rust `ssi` crate and the JavaScript `jose` library (invoked via a small Node sidecar in CI).

---

## 11. Observability and Audit

### New audit event

```
provenance.vc.issued {
  timestamp,
  request_id,
  iss:          <issuer DID>,
  kid:          <verification method id>,
  jti:          <JWT id>,
  claim_type:   "VerifyResult" | "AggregateResult" | "EntityRecord",
  subject:      <subject URI>,
  validity:     { iat, nbf, exp },
  caller:       <api-key principal>      // from wave-0 auth context
}
```

This event lands in the existing audit chain (Spec.md §13). Consumers can later request `?jti=<id>` lookups against an operator's audit logs to confirm issuance (this lookup endpoint is deferred to a follow-up wave).

### Metrics

- `provenance_vc_issued_total{claim_type, outcome}`
- `provenance_signing_duration_seconds{signer_kind}` (histogram)
- `provenance_signer_errors_total{kind}`
- `provenance_did_document_fetches_total` (counter on `/.well-known/did.json`)

### Logs

- Never log private key material.
- Never log full JWS payload bodies. Log `jti`, `iss`, `kid`, claim type, subject URI.
- KMS key ARN may be logged at startup once.

---

## 12. Testing Strategy

### Unit

- `tests/signer_trait.rs`: signer contract; mock signer verifies trait behaviour.
- VC-JWT header / payload construction is golden-tested against fixtures.
- Schema validation: claim payloads round-trip through their JSON Schema.

### Integration

- `tests/provenance_verify.rs`: end-to-end `/verify` with `Accept: application/vc+jwt`. Signature verifies. Schema fetched from `/schemas/verify-result/v1.json` validates the credentialSubject. Plain JSON path is unaffected.
- `tests/provenance_aggregate.rs`: same for `/aggregates/{id}`. Disclosure control (wave-2 `min_group_size`) still applies; the VC's `rows` / `suppressedGroups` / `computedAt` exactly mirror the plain-JSON response.
- `tests/provenance_entity_record.rs`: same for `/{entity}/{id}`. Includes a case with `?expand=<relationship>` showing the expansion data lands in `credentialSubject.expanded` and a case proving unexposed fields never appear.
- `tests/did_web_document.rs`: `/.well-known/did.json` is a valid W3C DID Document, its assertion method matches the configured `verification_method_id`, and the public key matches the signing key.
- Backward-compat tests: every existing `/verify`, `/aggregates/{id}`, and `/{entity}/{id}` test still passes with `provenance.enabled: false`, and with `provenance.enabled: true` but no provenance-aware `Accept` header.

### Third-party verification (the main interop gate)

- `tests/third_party_verification.rs`:
  - The Rust `ssi` crate verifies a produced VC.
  - A small Node script using `jose` verifies the same VC (executed via `std::process::Command` in CI).
  - Both must verify identically.

### Negative tests

- Tampered JWS rejected.
- Expired VC rejected by clock-checking step.
- Wrong-issuer VC rejected.
- KMS unavailable: `/verify` with `Accept: application/vc+jwt` returns 503; plain JSON still works.
- Software signer with missing `jwk_env`: startup fails with stable error code.

### Property tests

- For every wave-0 `/verify` and `/aggregate` response shape, the signed equivalent embeds exactly the public-visible fields and nothing else. No leakage of internal table IDs or hidden fields.

### Schema-fixture invariants

- `MANIFEST.toml` in `resources/schemas/` is verified by CI: every served schema matches the committed bytes.

---

## 13. Exit Criteria

1. `/verify` with `Accept: application/vc+jwt` returns a valid VC-JWT signed by the configured key; plain JSON path is unchanged.
2. `/aggregates/{aggregate_id}` behaves the same and embeds the full wave-2 result shape (rows, multiple measures, `computedAt`, `suppressedGroups`, `minGroupSize`).
3. `/{entity}/{id}` (including `?expand=`) with `Accept: application/vc+jwt` returns an `EntityRecord` VC that contains exactly the wave-2 projection plus any requested expansion data; no hidden fields leak.
4. `/.well-known/did.json` serves a valid W3C DID Document in gateway mode and returns 404 in delegated mode. Retired keys remain in `verificationMethod` until their last-issued VC has expired.
5. `/schemas/verify-result/v1.json`, `/schemas/aggregate-result/v1.json`, and `/schemas/entity-record/v1.json` are served, CORS-enabled, and match the in-tree files.
6. `/contexts/provenance/v1.jsonld` is served, CORS-enabled, parses as valid JSON-LD 1.1, and matches the in-tree file.
7. Every produced VC conforms to W3C VC JOSE/COSE for VCDM 2.0: top-level `@context`/`type`/`issuer`/`validFrom`/`validUntil`/`credentialSubject`/`credentialSchema`, no nested `vc` claim, `validFrom == nbf`, `validUntil == exp`.
8. Third-party verification passes: both `ssi` (Rust, VCDM 2.0 path) and `jose` (JS, generic JWS) verify produced VCs end-to-end including DID Document resolution.
9. Audit chain records `provenance.vc.issued` for every signed response, with the correct `claim_type` for VerifyResult / AggregateResult / EntityRecord.
10. Both gateway and delegated issuer modes are exercised in CI with the software signer; the same code path produces VCs differing only in `iss` / `kid` / signing key.
11. KMS signer trait is implemented; a mock `Signer` proves the trait works; an `AwsKmsSigner` reference implementation is either present or explicitly deferred to a follow-up with a tracking note.
12. `provenance.enabled: false` makes the wave fully invisible: no new routes mounted, no Accept negotiation runs, no provenance-specific status codes emitted, no startup secrets required. Behaviour is byte-identical to a build without the wave-3 code path (modulo response headers).
13. Operational documentation in `docs/provenance.md` covers: key generation, JWK format, rotation procedure (including retired-keys retention), KMS setup, did:web hosting, schema and JSON-LD context versioning, GDPR notes (R6, R7, R12).
14. Wave-2 invariants preserved: no public URL exposes raw table IDs; entity-grain disclosure control still applies inside VCs.
15. All wave-0 and wave-2 tests pass unchanged.

---

## 14. Deferred / Future Waves

| Item | Plausible wave |
|---|---|
| Collection-response signing (`/{entity}` listings, `/aggregates` index) | Wave 4 |
| Server-pushed "default to signed" mode (operator-forced VC issuance regardless of `Accept`) | Wave 4 |
| Response-envelope signing (the whole HTTP response as a JWS, distinct from per-claim VCs) | Wave 4 |
| Catalog entry signing (DCAT-AP `Dataset` as a VC) | Wave 5 |
| Audit-chain entry signing | Wave 5 |
| SD-JWT-VC (selective disclosure) | When EUDI / OOTS becomes a hard requirement |
| LD-Proofs / Data Integrity Proofs | When a partner requires them |
| JAdES / eIDAS-qualified signatures | When legal context requires |
| Status list revocation (BitstringStatusList) | When long-lived VCs become a use case |
| Overlapping active signing keys + automated rotation | Wave 4 |
| `jti` lookup endpoint (`GET /provenance/issuances/{jti}`) for after-the-fact verification | Wave 4 |
| OpenID4VCI / OpenID4VP (wallet issuance/presentation) | Out of charter until EUDI is firm |
| Per-claim issuer-mode mix (some claims gateway-issued, some delegated) | Wave 4 |
| Issuance from a ministry's external system via a delegation header | Out of charter |

Every deferred item has a slot in this wave's design (signer trait, claim trait, audit envelope, config shape), so future waves do not refactor the foundations.

---

## 15. Risks and Open Questions

| # | Risk | Mitigation |
|---|---|---|
| R1 | Signing latency spikes (KMS regional outage, network blips). | KMS signer documents the latency budget; circuit breaker returns 503 fast; software signer remains available for non-KMS deployments. |
| R2 | Software signer key custody is a high-value secret in process memory. | Document that production deployments should use KMS. Zeroize on drop. Never log. Env-var only. |
| R3 | `did:web` document availability becomes the verification ceiling. | Cache-Control + CORS configured for long lifetimes; consumers cache; document the operational coupling. |
| R4 | Schema URL stability. If `schema_base_url` ever moves, in-flight VCs fail validation. | Document that the schema base URL is part of the cryptographic contract and must not move without coordinated rotation. |
| R5 | Replay risk. A signed VC is portable; once leaked, anyone can present it. | `exp` is the primary mitigation. `asOf` records the point-in-time semantics. Document the property explicitly to consumers. |
| R6 | Privacy. A signed VC about an individual is a portable attestation. GDPR consequences for downstream holders. | Document predicate-only design: VCs assert facts about subjects but minimise embedded PII. `VerifyResult` answers boolean / categorical questions, not raw record dumps. Operator playbook in `docs/provenance.md` covers data minimisation. |
| R7 | Delegated mode requires ministry-side governance. | Document the delegation handshake: ministry must publish `did:web` with the gateway's key in `verificationMethod`. Startup check warns if the ministry's DID Document is unreachable or missing the configured `kid`. |
| R8 | Algorithm agility. `EdDSA` and `ES256` only. | Trait-level abstraction makes adding algorithms additive. Operators choose at deploy time. |
| R9 | Schema evolution. v1 → v2 migration. | New URLs, never edit shipped schemas. Operators bump claim-type version explicitly. |
| R10 | `jwk_env` containing a private key violates the wave-0 secret-handling posture in spirit (no inline secrets). | Document that JWK env-vars must come from a secret manager (Vault, AWS Secrets Manager, 1Password injection) and never from a `.env` file. KMS mode avoids the issue entirely. |
| R11 | A consumer caches a VC and refuses to refresh after key rotation. | Document the rotation policy: validity windows are short by default (24h for `VerifyResult`, 12h for `EntityRecord`, 30d for `AggregateResult`); retired keys remain in the DID Document until `max(claim_validity.*)` has elapsed, so cached VCs verify through one full rotation cycle. |
| R12 | `EntityRecord` VCs are signed, portable PII bundles. A leaked credential is a leaked record. | Operator playbook explicitly flags this. Per-deployment policy decides whether `EntityRecord` issuance is enabled at all (planned config: `provenance.claim_types.entity_record.enabled`). `claim_validity.entity_record` defaults to 12h. The operator playbook recommends restricting `EntityRecord` to dataset scopes that already permit row-level access, so signing does not broaden disclosure. |

### Open questions

1. Should `Accept: application/vc+jwt` also be supported on the wave-2 DCAT-AP catalog endpoint? (For "signed catalog" lite.) Current answer: no; that's a different feature pattern (D2 in this wave) and lands in a later wave.
2. For delegated mode, should data_gate validate at startup that the ministry's `did:web` document actually lists the configured `verification_method_id`? Yes for warning; no for failure (the ministry might bring it online later; we shouldn't block startup on an external dependency).
3. Should the `jti` be deterministic (hash of request) or random? Current answer: random (UUIDv4). Deterministic invites replay-detection patterns we are not building in V1.
4. Should `VerifyResult.predicate` be a free string or a registered enum? Current answer: free string with a recommended naming convention (`namespace:term`); registry deferred.
5. Should `nbf` ever differ from `iat`? Current answer: no, they are equal in V1. `nbf` exists for forward-compatibility with claims about future moments.

---

## 16. Estimated Effort

For one experienced Rust engineer comfortable with web crypto and HTTP integration:

| Block | Estimate |
|---|---|
| Provenance config + issuer resolution + secret hygiene + retired-keys plumbing | 1 wk |
| `Signer` trait, `SoftwareSigner`, key validation | 1 wk |
| `KmsSigner` trait + mock + (optional) AWS KMS impl | 3–5 days |
| VC-JWT encoder + JWS signing + VCDM 2.0 envelope assembly | 4 days |
| Claim modules (VerifyResult, AggregateResult, EntityRecord) + JSON Schemas + JSON-LD context + serving | 4 days |
| `/.well-known/did.json` builder + retired-keys logic + serving | 2 days |
| `/verify`, `/aggregates/{id}`, and `/{entity}/{id}` integration + Accept negotiation | 1.5 wk |
| Audit integration + observability + log hygiene | 3 days |
| Tests, fixtures, third-party-verification harness (ssi + jose) | 1 wk |
| Operational documentation (key rotation, KMS, GDPR for EntityRecord) | 3 days |
| **Total** | **7–9 wk** |

Plus ~20% buffer for KMS integration friction, VCDM 2.0 interop debugging, and `EntityRecord` projection edge cases: realistic landing 8–11 weeks for a wave-3 cut that meets all exit criteria. Without KMS reference implementation: 6–8 weeks.

---

## 17. Acceptance and Sign-off

This wave is considered done when:

1. All exit criteria in §13 pass on `main`.
2. `docs/provenance.md` operator playbook is published (key generation, rotation, KMS setup, GDPR notes, delegated-mode coordination with a ministry).
3. The wave-3 changes are reviewed under the same security-review cadence used by waves 0–2 (`docs/security-review-2026-05-16.md` template). Special focus: secret handling for `jwk_env`, KMS error paths, log hygiene.
4. At least one end-to-end demo: a consumer fetches a signed `VerifyResult`, verifies it with `ssi`, then a third party re-verifies it from cold (no contact with data_gate other than fetching the DID Document and the schema).
