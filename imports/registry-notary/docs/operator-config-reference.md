# Operator Configuration Reference

This guide explains how to assemble a deployable Registry Notary configuration.
It is written for teams adopting the service, not for contributors changing the
implementation.

Registry Notary is config driven. The YAML file describes which claims can be
evaluated, which upstream registries are contacted, how callers authenticate,
how credentials are signed, and which operational stores are used. Secrets
should stay in environment variables or a secret manager; config fields name the
environment variable to read.

## Adoption Decisions

Before editing YAML, decide these items:

| Decision | Use this when | Main config |
| --- | --- | --- |
| Machine-to-machine API | A backend service calls Notary for evaluation or issuance | `auth.mode: api_key` |
| Citizen or wallet flows | A user-held OIDC token identifies the subject | `auth.mode: oidc`, `self_attestation` |
| SD-JWT VC issuance | Notary signs credentials from evaluated claims | `evidence.signing_keys`, `evidence.credential_profiles` |
| OID4VCI wallet facade | A wallet requests credentials directly | `oid4vci`, `self_attestation` |
| Multi-instance deployment | More than one Notary process serves traffic | `replay.storage: redis`, usually `credential_status.storage: redis` |
| Credential suspension or revocation | Verifiers need a live status URL | `credential_status.enabled: true` |
| Audit retention | Operators need traceability without raw personal data | `audit` |

Start with one narrow claim, one source connection, one signing key, and one
credential profile. Add federation, wallet issuance, and batch evaluation after
the basic path passes `doctor`.

## Top-Level Shape

| Block | Purpose | Required for startup |
| --- | --- | --- |
| `server` | Bind address and process HTTP settings | No, defaults are present |
| `auth` | Caller authentication and scope mapping | Yes |
| `audit` | Redacted audit envelope sink and HMAC secret | Recommended for every deployable environment |
| `evidence` | Claims, sources, rules, formats, signing keys, and credential profiles | Yes |
| `replay` | One-time-use store for federation request JWTs, OID4VCI nonces, and holder proof JWTs | Defaults to in-process memory |
| `credential_status` | Optional storage-backed lifecycle status URL for issued credentials | No |
| `self_attestation` | OIDC-bound citizen request policy | Only for citizen or wallet flows |
| `oid4vci` | Wallet-facing OpenID4VCI facade | Only for wallet flows |
| `federation` | Static-peer delegated evaluation | Only for federation |

Unknown fields are rejected. That is intentional: a misspelled field should fail
at config validation instead of becoming an accidental open policy.

## Secret Handling

Config files should contain names, not secret values.

| Need | Config field | Environment value |
| --- | --- | --- |
| API key or bearer-token auth | `auth.api_keys[].hash_env`, `auth.bearer_tokens[].hash_env` | `sha256:<hex>` hash |
| Static upstream source token | `evidence.source_connections.<id>.token_env` | Raw upstream bearer token |
| OAuth2 client credential source auth | `source_auth.client_id_env`, `source_auth.client_secret_env` | OAuth client id and secret |
| Local JWK signing key | `evidence.signing_keys.<id>.private_jwk_env` | Private Ed25519 JWK JSON |
| Publish-only JWK | `evidence.signing_keys.<id>.public_jwk_env` | Public JWK JSON |
| PKCS#11 PIN | `evidence.signing_keys.<id>.pin_env` | HSM token PIN |
| Audit hashing | `audit.hash_secret_env` | Stable high-entropy HMAC secret |
| Redis stores | `replay.redis.url_env`, `credential_status.redis.url_env` | Redis connection URL |

Use `registry-notary hash-api-key --print-secret` to generate a local API key
and its hash. Store only the hash in the environment variable referenced by
config; give the plaintext key only to the caller.

For local development, the binary accepts `--env-file`. For shared
environments, prefer the platform secret store and avoid checking dotenv files
into the repository.

## Minimal Machine Config

This is the smallest useful shape for a backend caller that evaluates one claim
from one DCI source and can later issue a credential from that claim.

```yaml
server:
  bind: 127.0.0.1:4255

auth:
  mode: api_key
  api_keys:
    - id: verifier-service
      hash_env: REGISTRY_NOTARY_API_KEY_HASH
      scopes:
        - civil_registry:evidence_verification
        - registry_notary:credential_issue

audit:
  sink: stdout
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET

evidence:
  enabled: true
  service_id: civil.registry-notary
  api_base_url: https://notary.example.gov
  source_connections:
    civil_registry:
      base_url: https://registry.example.gov
      token_env: CIVIL_REGISTRY_TOKEN
      dci:
        search_path: /registry/sync/search
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          birth_date: /birth_date
  signing_keys:
    issuer-2026-05:
      provider: local_jwk_env
      private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
      alg: EdDSA
      kid: did:web:notary.example.gov#issuer-2026-05
      status: active
  credential_profiles:
    birth_record_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:notary.example.gov
      signing_key: issuer-2026-05
      vct: https://notary.example.gov/credentials/birth-record/v1
      validity_seconds: 600
      allowed_claims:
        - birth-record-exists
      holder_binding:
        mode: did
        proof_of_possession: required
        allowed_did_methods:
          - did:jwk
      disclosure:
        allowed:
          - value
          - redacted
  claims:
    - id: birth-record-exists
      title: Birth record exists
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      inputs:
        - name: target.identifiers.national_id
          type: string
      source_bindings:
        birth_record:
          connector: dci
          connection: civil_registry
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: birth_registration
          lookup:
            input: target.identifiers.national_id
            field: UIN
            op: eq
            cardinality: one
      rule:
        type: exists
        source: birth_record
      formats:
        - application/vnd.registry-notary.claim-result+json
      credential_profiles:
        - birth_record_sd_jwt
```

## Authentication

`auth.mode: api_key` is for backend integrations. Configure at least one API key
or bearer token. Each entry has an `id`, a `hash_env`, and scopes. Use the
smallest scope set each caller needs. Admin functions, including metrics and
credential status mutation, require `registry_notary:admin`.

`auth.mode: oidc` is for citizen and wallet flows. When OIDC is selected,
`auth.api_keys` and `auth.bearer_tokens` must be empty. Configure:

- `issuer`: expected token issuer.
- `jwks_uri`: HTTPS JWKS URL, or HTTP loopback only with
  `allow_insecure_localhost: true`.
- `audiences`: accepted access-token audiences.
- `allowed_clients`: optional client allow-list.
- `allowed_algorithms`: explicit token signing algorithms accepted from the
  identity provider. Match the provider and do not mix unrelated algorithm
  families in one deployment.
- `scope_claim`, `scope_separator`, and `scope_map`: how external token scopes
  map to Registry Notary scopes.
- `principal_claim`: claim used for audit principal identity. The default is
  `sub`.

For citizen self-attestation, the OIDC token must also carry a binding claim
that Registry Notary uses to derive the requester and target context.

## Source Connections

Every source binding references one `source_connections` entry. A source
connection defines the upstream base URL, the authentication method used to
contact it, and connector-specific settings.

Use exactly one source authentication mechanism:

- `token_env` for a static bearer token.
- `source_auth.type: oauth2_client_credentials` for OAuth2 client credentials.

The OAuth2 client-credentials shape is:

```yaml
source_auth:
  type: oauth2_client_credentials
  token_url: https://registry.example.gov/oauth2/client/token
  client_id_env: DCI_CLIENT_ID
  client_secret_env: DCI_CLIENT_SECRET
  request_format: json
  scope: registry.search
```

`request_format` is `form` by default and may be set to `json` for sources such
as the OpenCRVS DCI demo endpoint.

For DCI sources, check these fields carefully:

- `search_path`: path appended to `base_url`.
- `sender_id`, `receiver_id`, `registry_type`, `registry_event_type`, and
  `record_type`: envelope values expected by the upstream DCI implementation.
- `query_type`: currently the common value is `idtype-value`.
- `records_path`: JSON Pointer to the records array in a single response.
- `field_paths`: JSON Pointers for fields that the claim rule reads.
- `bulk_mode`: leave `none` until the source contract has been tested. Use
  `dci_batched_search` or `rda_in_filter` only when the upstream supports that
  access pattern.

For production, leave `allow_insecure_localhost` and
`allow_insecure_private_network` false unless the deployment review explicitly
accepts the private network source. Local demos may use them for loopback or
Docker Compose style setups.

## Claims

A claim is a public capability. It should describe one thing Notary can evaluate
or issue, such as "birth record exists" or "farmer under four hectares".

Important fields:

- `id`: stable machine id used by clients and credential profiles.
- `title`, `version`, `subject_type`, and `value`: operator and verifier
  metadata.
- `inputs`: request lookup paths. Supported paths include `target.id`,
  `target.identifiers.<scheme>`, `target.attributes.<name>`, `requester.id`,
  `requester.identifiers.<scheme>`, `requester.attributes.<name>`, and
  `relationship.attributes.<name>`.
- `source_bindings`: upstream reads, lookup fields, required caller scope, and
  extracted source fields.
- `rule`: `exists`, `extract`, or `cel`.
- `depends_on`: prerequisite claims for CEL rules that reuse earlier results.
- `operations`: enable or cap `evaluate` and `batch_evaluate`.
- `disclosure`: default and allowed response disclosure modes.
- `formats`: response formats the claim can render.
- `credential_profiles`: profiles allowed to issue from this claim.

Avoid broad source bindings. A claim should read only the fields needed to
evaluate that claim. If two credentials need different fields, prefer two claims
or a small dependency graph over one over-broad claim.

## Credential Profiles

Credential profiles control SD-JWT VC issuance.

Required fields:

- `format: application/dc+sd-jwt`.
- `issuer`: DID issuer for the credential.
- `signing_key`: key id from `evidence.signing_keys`.
- `vct`: credential type URL.
- `allowed_claims`: explicit allow-list. Empty allow-lists are rejected.
- `holder_binding`: currently implemented holder binding is `did:jwk`.
- `disclosure.allowed`: disclosure modes the profile may carry.

`validity_seconds` defaults to 600 and must be between 1 and
`evidence.max_credential_validity_seconds`. The top-level maximum is also capped
at 600 seconds. This is a deliberate beta posture: credentials are short-lived
by default, and live credential status is optional.

Signing keys are covered in detail in
[`signing-key-provider.md`](signing-key-provider.md).

## Replay Store

`replay.storage: in_memory` is acceptable for a single process in local
development. It is not acceptable for active-active serving because two
processes cannot see the same nonce or proof replay decisions.

Use Redis for multi-instance deployments:

```yaml
replay:
  storage: redis
  redis:
    url_env: REGISTRY_NOTARY_REPLAY_REDIS_URL
    key_prefix: registry-notary
    connect_timeout_ms: 1000
    operation_timeout_ms: 500
```

The router fails to build when the named Redis URL environment variable is
missing. `/ready` fails closed when the replay backend is unavailable.

## Credential Status

Credential status is disabled by default. Enable it only when verifiers need
live suspension or revocation for issued credentials.

```yaml
credential_status:
  enabled: true
  base_url: https://notary.example.gov
  storage: redis
  retention_seconds: 86400
  redis:
    url_env: REGISTRY_NOTARY_STATUS_REDIS_URL
    key_prefix: registry-notary
```

Use Redis for deployable multi-process status. In-memory status is suitable only
for lab flows because records disappear on restart and are not shared across
instances.

See [`credential-lifecycle-status.md`](credential-lifecycle-status.md) for
status semantics and rollout guidance.

## Self-Attestation

Self-attestation lets a citizen use their own OIDC token to evaluate or issue
only for the subject bound to that token. It requires `auth.mode: oidc`.

The main controls are:

- `subject_binding`: exact comparison between a token claim and the request
  field. `normalize` must be `exact`. Using `sub` as a civil identifier requires
  `allow_sub_as_civil_id: true`.
- `citizen_clients`: allowed OIDC clients or audiences. Audiences must also be
  accepted by `auth.oidc.audiences`.
- `token_policy`: assurance, auth age, access-token lifetime, evaluation age,
  credential validity, and clock leeway ceilings.
- `allowed_operations`: v1 may enable `evaluate`, `render`, and
  `issue_credential`; `batch_evaluate` must remain false.
- `allowed_purposes`, `allowed_claims`, `allowed_formats`,
  `allowed_disclosures`, and `credential_profiles`: explicit allow-lists.
- `scope_policy` and `required_scopes`: citizen token scope requirements.
- `allowed_wallet_origins`: exact HTTPS origins for browser wallet flows. Do
  not use wildcards.
- `rate_limits`: in-process guardrails. Put gateway or identity-provider rate
  limits in front of public deployments as well.

Self-attestation credential profiles must use DID holder binding with proof of
possession and `did:jwk`.

## OID4VCI Wallet Facade

OID4VCI depends on self-attestation. Enable it when a wallet should retrieve
Notary-issued credentials through OpenID4VCI-style metadata, offers, nonces,
and credential requests.

Minimum shape:

```yaml
oid4vci:
  enabled: true
  credential_issuer: https://notary.example.gov
  authorization_servers:
    - https://idp.example.gov
  accepted_token_audiences:
    - registry-notary-wallet
  credential_endpoint: https://notary.example.gov/oid4vci/credential
  offer_endpoint: https://notary.example.gov/oid4vci/credential-offer
  nonce_endpoint: https://notary.example.gov/oid4vci/nonce
  nonce:
    enabled: true
    ttl_seconds: 300
  credential_configurations:
    birth_record_sd_jwt:
      claim_id: birth-record-exists
      credential_profile: birth_record_sd_jwt
      format: dc+sd-jwt
      scope: birth_record
      vct: https://notary.example.gov/credentials/birth-record/v1
      display_name: Birth record attestation
```

Public URLs must use HTTPS except for loopback development. Endpoint URLs must
live under `credential_issuer`, include a path, and have no query string.

See [`oid4vci-wallet-interop.md`](oid4vci-wallet-interop.md) for wallet flow
and compatibility notes.

## Validation Workflow

Run config checks before exposing the service:

```sh
registry-notary explain-config --config registry-notary.yaml --env-file .env.local
registry-notary doctor --config registry-notary.yaml --env-file .env.local
registry-notary doctor --config registry-notary.yaml --env-file .env.local --live
```

Use `--live` only against a test target or a controlled integration
environment. When live lookup values are supplied, the doctor output redacts
target ids and tokens, but the upstream source still receives a real lookup.

For local VC smoke tests:

```sh
registry-notary doctor \
  --config registry-notary.yaml \
  --env-file .env.local \
  --issue-demo-vc
```

## Rollout Checklist

- Each caller has only the scopes required for its claims and operations.
- Every source connection has exactly one auth method.
- Insecure source or JWKS allowances are absent outside local demos.
- Claims read only required upstream fields.
- Credential profiles list explicit `allowed_claims`.
- Signing keys are active only when they may sign; old public keys are
  `publish_only` until verifiers no longer need them.
- Multi-instance deployments use Redis replay storage.
- Credential status, if enabled, uses the externally reachable issuer base URL
  and a shared store.
- Audit has a stable high-entropy `hash_secret_env` value and off-host
  retention.
- `/metrics` is scraped with an admin credential and normal network controls.
- `doctor` passes without `--live`, then passes with a controlled live subject.
