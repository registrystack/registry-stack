# Operator Configuration Reference

> **Page type:** Reference · **Product:** Registry Notary · **Layer:** all · **Audience:** operator

This reference describes how to assemble a deployable Registry Notary configuration.
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
| OpenFn sidecar reads | A target system needs pinned adaptor execution or normalization outside Notary | `connector: openfn_sidecar`, `retry_on_5xx: false` |
| OpenFn sidecar assurance | Notary must fail closed unless it is talking to the approved sidecar runtime | `source_connections.<id>.expected_sidecar` |
| OpenFn batch matching | Batch evaluation should share one OpenFn sidecar read across compatible items | `bulk_mode: openfn_sidecar_batch`, binding `query_fields` |

Start with one narrow claim, one source connection, one signing key, and one
credential profile. Add federation, wallet issuance, and batch evaluation after
the basic path passes `doctor`.

## Top-Level Shape

| Block | Purpose | Required for startup |
| --- | --- | --- |
| `server` | Bind address and process HTTP settings | No, defaults are present |
| `auth` | Caller authentication and scope mapping | Yes |
| `deployment` | Operator-declared deployment profile and gate waivers | No, an undeclared profile binds no gates |
| `audit` | Redacted audit envelope sink and HMAC secret | Recommended for every deployable environment |
| `config_trust` | Durable local state for governed config apply | No, only for signed governed config |
| `evidence` | Claims, sources, rules, formats, signing keys, and credential profiles | Yes |
| `cel` | Optional CEL worker policy, limits, and regex posture | Defaults are present |
| `replay` | One-time-use store for federation request JWTs, OID4VCI nonces, and holder proof JWTs | Defaults to in-process memory |
| `credential_status` | Optional storage-backed lifecycle status URL for issued credentials | No |
| `self_attestation` | OIDC-bound citizen request policy | Only for citizen or wallet flows |
| `oid4vci` | Wallet-facing OpenID4VCI facade | Only for wallet flows |
| `federation` | Static-peer delegated evaluation | Only for federation |

Unknown fields are rejected. That is intentional: a misspelled field should fail
at config validation instead of becoming an accidental open policy.

## Deployment Profile and Gates

The `deployment` block lets an operator declare the assurance shape of a
deployment. The profile is always declared by the operator and is never inferred
from environment name, hostname, or network position.

```yaml
deployment:
  profile: production      # local | hosted_lab | production | evidence_grade
  multi_instance: true     # declares this instance shares a workload with others
  waivers:
    - finding: notary.source.private_network_escape
      reason: "approved internal source for partner pilot, ticket OPS-123"
      expires: 2026-09-30
```

| Field | Purpose |
| --- | --- |
| `profile` | The declared assurance shape. Absent means undeclared. |
| `multi_instance` | Operator declaration that this instance runs active-active with peers, which makes shared, durable replay storage mandatory. |
| `waivers` | Per-finding suppressions, each with a mandatory reason and expiry. |

Profiles:

| Profile | Use |
| --- | --- |
| `local` | Development, demos, tests, local pilots. Binds no gates. |
| `hosted_lab` | Shared demos, partner evaluations, hosted validation. |
| `production` | Real integrations handling sensitive or operational data. |
| `evidence_grade` | Deployments where the evidence trail is itself part of the assurance claim. |

An **undeclared** profile binds no gates and keeps current behavior. The posture
report then carries a single `deployment.profile_undeclared` warning so the gap
is visible without breaking the deployment. An **invalid** profile value fails
startup, so a typo cannot silently disable enforcement.

Each gate evaluates to one of four severities under the declared profile:

| Severity | Effect |
| --- | --- |
| `startup_fail` | The process refuses to start. Never waivable. |
| `readiness_fail` | The readiness endpoint reports not-ready; the process runs. |
| `finding_error` | A posture finding, error class. |
| `finding_warn` | A posture finding, warn class. |

The gates bound for Registry Notary:

| Finding id | Condition | hosted_lab | production | evidence_grade |
| --- | --- | --- | --- | --- |
| `notary.replay.in_memory_high_risk` | In-memory replay while federation, OID4VCI pre-authorized code, holder proof, wallet traffic, or `multi_instance` is declared | error | readiness_fail | startup_fail |
| `notary.audit.sink_missing` | No durable, retained audit sink | error | startup_fail | startup_fail |
| `notary.source.insecure_url` | Source connection over a plain `http://` URL with no localhost or private-network allowance | error | readiness_fail | startup_fail |
| `notary.source.private_network_escape` | A source enables the private-network escape hatch | warn | error | error |
| `notary.sidecar.expected_sidecar_missing` | An OpenFn source omits `expected_sidecar` | warn | error | readiness_fail |
| `notary.admin.shared_exposure` | The admin surface shares the public listener | error | readiness_fail | startup_fail |
| `notary.openapi.public` | OpenAPI is served without authentication | warn | error | error |
| `notary.config.unsigned` | Local YAML config rather than signed governed config | warn | error | startup_fail |

### Waivers

A waiver names exactly one finding id, a free-text reason, and a mandatory
`expires` date (`YYYY-MM-DD`). While active, a waiver changes a triggered
finding's status to `waived` in posture instead of applying its severity effect.

- `startup_fail` gates are never waivable. A waiver for one is rejected at config
  load, because running at all would falsify the declared profile.
- An expired waiver stops suppressing its finding and additionally raises
  `deployment.waiver_expired` in posture, so lapsed approvals surface rather than
  silently persisting.
- Waiver reasons appear in the restricted-tier posture for review. Never put a
  secret in a reason.

Active waivers and gate findings appear in the admin posture document under the
`deployment` object, and the eight-field audit assurance vocabulary appears under
the top-level `audit` object. See `docs/security-assurance.md` for the assurance
vocabulary.

## Secret Handling

Config files should contain names, not secret values.

| Need | Config field | Environment value |
| --- | --- | --- |
| API key or bearer-token auth | `auth.api_keys[].fingerprint`, `auth.bearer_tokens[].fingerprint` | `sha256:<hex>` fingerprint |
| Static upstream source token | `evidence.source_connections.<id>.token_env` | Raw upstream bearer token |
| OAuth2 client credential source auth | `source_auth.client_id_env`, `source_auth.client_secret_env` | OAuth client id and secret |
| Local JWK signing key | `evidence.signing_keys.<id>.private_jwk_env` | Private Ed25519 JWK JSON |
| Watched local JWK signing key | `evidence.signing_keys.<id>.path` with `provider: file_watch` | Private Ed25519 JWK JSON in a host-local file |
| Publish-only JWK | `evidence.signing_keys.<id>.public_jwk_env` | Public JWK JSON |
| Publish-only deadline | `evidence.signing_keys.<id>.publish_until_unix_seconds` | Optional public metadata, not a secret |
| PKCS#11 PIN | `evidence.signing_keys.<id>.pin_env` | HSM token PIN |
| Audit hashing | `audit.hash_secret_env` | Stable high-entropy HMAC secret |
| Redis stores | `replay.redis.url_env`, `credential_status.redis.url_env` | Redis connection URL |

Use `registry-notary hash-api-key --print-secret` to generate a local API key
and its hash. Store only the hash in the environment variable referenced by
config; give the plaintext key only to the caller.

`registry-notary doctor --config <path>` validates active PKCS#11 signing keys
by loading the configured module, opening the token, checking the private-key
lookup, and running the startup self-test. Run `registry-notary build-info` on
the deployed artifact to confirm the `pkcs11` capability is compiled in before
debugging token or vendor module configuration.

For local no-restart key material refresh, use `provider: file_watch` with a
host-local private JWK file path. The file is read at startup and re-read on
signing use. A valid replacement with the same configured `kid`, `alg`, and
public JWK identity is picked up without process restart; a malformed, missing,
or different-public-key replacement marks the key degraded and keeps the last
good signer serving. Use a new `kid` and governed config change for real key
rotation.

For local development, the binary accepts `--env-file`. For shared
environments, prefer the platform secret store and avoid checking dotenv files
into the repository.

## Governed Config Apply

Most deployments can skip this section. `config_trust` is optional; it governs
signed, threshold-approved config changes for high-assurance deployments. Simple
local deployments omit it and keep using the local YAML loaded at startup.

This governed example is syntactically valid but illustrative. Generate the
`tuf_root_sha256` and targets-role signer key IDs from your own trusted TUF
repository before using governed apply in an environment.

```yaml
config_trust:
  antirollback_state_path: /var/lib/registry-notary/config-antirollback.json
  local_approval_state_path: /var/lib/registry-notary/config-local-approvals.json
  break_glass_rate_limit:
    max_accepted: 1
    window_seconds: 3600
  required_approver_count:
    emergency.break_glass: 2
  remote_tuf_repositories:
    - root_path: /etc/registry-notary/tuf/metadata/1.root.json
      metadata_base_url: https://config.example.gov/metadata
      targets_base_url: https://config.example.gov/targets
      datastore_dir: /var/lib/registry-notary/tuf
      allow_dev_insecure_fetch_urls: false
  accepted_roots:
    - root_id: ops-root
      production: false
      tuf_root_sha256: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      valid_from_unix_seconds: 1770000000
      valid_until_unix_seconds: 1772592000
      signers:
        "1111111111111111111111111111111111111111111111111111111111111111":
          kid: "1111111111111111111111111111111111111111111111111111111111111111"
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids: ["1111111111111111111111111111111111111111111111111111111111111111"]
          allowed_change_classes: [public_metadata, root_transition]
```

`config_trust` is optional. Simple local deployments omit it and keep using the
local YAML loaded at startup. Governed config apply requires
`antirollback_state_path` and `local_approval_state_path`, which must point to
durable local state such as a mounted volume. `break_glass_rate_limit` is the
trusted local rolling-window policy for break-glass apply requests; when omitted
it defaults to one accepted request per rate-limit identity per hour.
`required_approver_count` is an optional per-emergency-change-class map for
stored break-glass approval records. Counts default to `1`; values must be
greater than zero.
`accepted_roots` uses the shared Registry trust-root shape.
Standalone Registry Notary verifies local or remote signed TUF config targets
against `accepted_roots` when the admin request provides a `tuf` source.
Verified TUF targets-role signature key IDs, not target-declared custom
metadata, satisfy the role threshold. Inline YAML remains available for
verify/dry-run diagnostics. Local TUF sources use `root_path`, `metadata_dir`,
`targets_dir`, `datastore_dir`, and `target_name`. Remote TUF sources keep the
same `root_path`, `datastore_dir`, and `target_name`, and replace local
repository directories with `metadata_base_url` and `targets_base_url`. Remote
sources are recorded as `signed_bundle_endpoint`; local repository sources are
recorded as `signed_bundle_file`.

`remote_tuf_repositories` is an operator-controlled allowlist of remote TUF
sources that may be submitted in admin apply requests. An apply request whose
remote TUF source does not exactly match one of the listed entries (comparing
`root_path`, `metadata_base_url`, `targets_base_url`, and `datastore_dir`) is
rejected before any TUF fetch is attempted. This prevents an attacker who can
POST to the admin endpoint from directing the Notary to an arbitrary TUF server.
When omitted the list is empty and all remote TUF apply requests are rejected.
Each entry carries its own `allow_dev_insecure_fetch_urls` flag; the flag from
the matching allowlist entry is always used, never the value in the incoming
request. HTTP loopback remote repositories require `allow_dev_insecure_fetch_urls:
true` and are intended only for tests and local development. Production entries
must use HTTPS URLs and must set `allow_dev_insecure_fetch_urls: false`.

Governed bundle metadata may set `previous_config_hash` as either bare lowercase
SHA-256 hex or `sha256:<64 lowercase hex>`. Notary normalizes both forms at the
product boundary before anti-rollback comparison. The canonical form in
verification reports, admin API responses, audit events, docs, and mismatch
errors is `sha256:<64 lowercase hex>`. On a true chain mismatch, the error detail
includes the expected canonical hash and the received value's detected format.

### TUF root transition

For TUF root transition, apply a signed local TUF bundle whose target metadata
includes `root_transition`, changes only `config_trust.accepted_roots`, keeps
the antirollback and local approval paths unchanged, retains existing roots
unchanged, and references a matching unexpired local approval. Add the new
final `tuf_root_sha256` as another local `accepted_roots` entry before applying
bundles that verify through the rotated root. `valid_from_unix_seconds` and
`valid_until_unix_seconds` are optional local bounds for overlap windows;
expired or not-yet-valid roots fail authorization even when TUF verification
and signer quorum otherwise succeed.

### Hot-apply and reload

`POST /admin/v1/config/apply` can hot-apply governed signed signing-key
rotations for credential issuer, pre-authorized access-token, eSignet
(an OpenID Connect identity service) client-assertion, and federation response
signing paths after TUF verification,
trust-root authorization, and local anti-rollback acceptance. It can also
hot-apply `signing_key_cleanup` for expired publish-only keys that are no longer
active signing references. Inline config candidates are accepted only by verify
and dry-run; apply rejects them with
`registry.admin.config.inline_apply_rejected`. Other signed changes continue to
reject with `rejected_restart_required`, so rejected signed targets do not
advance anti-rollback state or change active posture provenance. This
restart-required apply result is distinct from unsupported live reload: it means
the signed candidate is valid but cannot be hot-applied.
Use `GET /admin/v1/capabilities` with `registry_notary:ops_read` before
automation invokes governed config or reload operations. Standalone Notary does
not support resource, table, or runtime config reload; the mounted
`POST /admin/v1/reload` route returns `501
registry.admin.capability.not_supported`.

### Break-glass apply

Break-glass apply is
available only for signed targets whose target metadata includes the local
approval's `emergency_change_class`. Inline `break_glass_approval` remains the
single-approver path. Multi-approver policies write a verifier-owned approval
record to `local_approval_state_path` and send only
`break_glass_approval_reference` in the request. The rolling-window policy comes
from local `config_trust.break_glass_rate_limit`; requests that include
`break_glass_rate_limit` are rejected. The audit record stores the approval
reference, emergency change class, expiry, rate-limit identity, and hashes of
approver identity and reason text; it does not store raw approver identity or
raw reason text.

## Minimal Machine Config

This is the smallest useful shape for a backend caller that evaluates one claim
from one DCI source and can later issue a credential from that claim.

```yaml
server:
  bind: 127.0.0.1:8081
  openapi_requires_auth: true
  request_timeout: 30s
  request_body_timeout: 10s
  http1_header_read_timeout: 10s
  max_connections: 1024

auth:
  mode: api_key
  api_keys:
    - id: verifier-service
      fingerprint:
        provider: env
        name: REGISTRY_NOTARY_API_KEY_HASH
        commitment: sha256:0000000000000000000000000000000000000000000000000000000000000000
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
    issuer-file-watch:
      provider: file_watch
      path: /run/secrets/registry-notary/issuer.jwk
      alg: EdDSA
      kid: did:web:notary.example.gov#issuer-file-watch
      status: active
  credential_profiles:
    birth_record_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:notary.example.gov
      signing_key: issuer-2026-05
      vct: https://notary.example.gov/credentials/birth-record/v1
      validity_seconds: 31536000
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

`server.openapi_requires_auth` defaults to `true`. Set it to `false` only for local testing or controlled tooling environments that need unauthenticated access to `/openapi.json`.

## Authentication

`auth.mode: api_key` is for backend integrations. Configure at least one API key
or bearer token. Each entry has an `id`, a committed `fingerprint`, and scopes.
Use the smallest scope set each caller needs. Admin functions, including metrics
and credential status mutation, require `registry_notary:admin`.

`auth.mode: oidc` is for citizen and wallet flows. When OIDC is selected,
`auth.api_keys` and `auth.bearer_tokens` must be empty. Configure:

OIDC field names follow the shared Registry service runtime configuration conventions.
Removed pre-convention names are rejected before deserialization with an error
naming the replacement field.

- `issuer`: expected token issuer.
- `jwks_url`: HTTPS JWKS URL, or HTTP loopback only with
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
- `query_type`: `idtype-value` for one identifier lookup, or `expression` when
  the upstream supports fielded query expressions.
- `records_path`: JSON Pointer to the records array in a single response.
- `field_paths`: JSON Pointers for fields that the claim rule reads.
- `bulk_mode`: leave `none` until the source contract has been tested. Use
  `dci_batched_search` or `rda_in_filter` only when the upstream supports that
  access pattern.

For any source binding, `query_fields` can replace the single-field `lookup`
wire query when the source supports multi-field lookup. `registry_data_api`
sends them as query parameters, and DCI `expression` sends them inside the DCI
query envelope. For `openfn_sidecar`, Notary sends single reads through the
sidecar's Registry Data API-shaped read endpoint, and sends batch reads through
the sidecar's `records:batchMatch` endpoint. Leave `query_fields` empty for the
legacy single-field lookup.

For production, leave `allow_insecure_localhost` and
`allow_insecure_private_network` false unless the deployment review explicitly
accepts the private network source. Local demos may use them for loopback or
Docker Compose style setups.

### OpenFn Sidecar Source Connections

Use `connector: openfn_sidecar` when a target system needs OpenFn adaptor
execution, target credential handling, or output normalization outside Notary.
The source connection must use static sidecar bearer auth through `token_env`.
Do not configure target-service credentials in Notary; keep them in the sidecar
environment or secret store.

For high-assurance deployments, pin the sidecar runtime that Notary is allowed
to use with `expected_sidecar`. Notary reads the private sidecar assurance
endpoint before source reads and fails closed when the product identity,
environment, stream, `config_hash`, expression-hash verification, runtime
verification, or smoke-check state does not match the pin.

Single-read OpenFn sidecar example:

```yaml
evidence:
  source_connections:
    openfn_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: OPENFN_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: none
      expected_sidecar:
        product: registry-notary-openfn-sidecar
        instance_id: civil-registry-sidecar
        environment: production
        stream_id: openfn-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-06
      subject_type: person
      value:
        type: date
      inputs:
        - name: target.identifiers.national_id
          type: string
      source_bindings:
        crvs:
          connector: openfn_sidecar
          connection: openfn_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.identifiers.national_id
            field: national_id
            op: eq
            cardinality: one
          fields:
            birth_date:
              field: birth_date
              type: date
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
```

OpenFn sidecar batch matching example with `query_fields`:

```yaml
evidence:
  source_connections:
    openfn_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: OPENFN_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: openfn_sidecar_batch
      bulk_timeout_max_ms: 30000
      expected_sidecar:
        product: registry-notary-openfn-sidecar
        instance_id: civil-registry-sidecar
        environment: production
        stream_id: openfn-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
  claims:
    - id: birth-record-exists
      title: Birth record exists
      version: 2026-06
      subject_type: person
      value:
        type: boolean
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 100
      inputs:
        - name: target.attributes.given_name
          type: string
        - name: target.attributes.family_name
          type: string
        - name: target.attributes.birthdate
          type: date
      source_bindings:
        crvs:
          connector: openfn_sidecar
          connection: openfn_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.attributes.birthdate
            field: birthdate
            op: eq
            cardinality: one
          query_fields:
            - input: target.attributes.given_name
              field: given_name
              op: eq
            - input: target.attributes.family_name
              field: family_name
              op: eq
            - input: target.attributes.birthdate
              field: birthdate
              op: eq
          matching:
            policy_id: civil-person-name-birthdate-v1
            method: exact_name_birthdate
            target_type: Person
            allowed_purposes:
              - benefit_eligibility_check
            sufficient_target_inputs:
              - [target.attributes.given_name, target.attributes.family_name, target.attributes.birthdate]
            allowed_target_inputs:
              - target.attributes.given_name
              - target.attributes.family_name
              - target.attributes.birthdate
            collapse_matching_errors: true
            confidence: high
          fields:
            national_id:
              field: national_id
              type: string
              required: true
            birth_date:
              field: birth_date
              type: date
              required: true
      rule:
        type: exists
        source: crvs
```

For OpenFn sidecar connections:

- Set `retry_on_5xx: false`. Notary does not retry OpenFn worker execution
  failures.
- Use `bulk_mode: openfn_sidecar_batch` only after sidecar contract tests cover
  per-item not found, exact match, ambiguous match, missing response item,
  duplicate response item id, worker timeout, worker failure, and output
  projection.
- In governed environments, set `expected_sidecar` on every OpenFn sidecar
  connection. Local demos may omit it only when the assurance boundary is not
  part of the test.

See the [deployment hardening runbook](https://github.com/jeremi/registry-notary/blob/f182385a5065873aac030c41d9fe020704afc4e2/docs/deployment-hardening-runbook.md) for
network isolation requirements, responsibility boundaries between Notary and
the sidecar, and deployment security expectations.

## CEL Runtime

CEL rules are evaluated out of process when the binary is built with
`registry-notary-cel`. The default posture is production-oriented: worker mode,
no queueing, bounded worker count, bounded frames, and regex disabled.

```yaml
cel:
  mode: worker
  worker_count: 2
  eval_timeout_ms: 2000
  queue_max: 0
  allow_regex: false
  max_expression_bytes: 8192
  max_binding_json_bytes: 65536
  max_result_json_bytes: 16384
  max_string_bytes: 16384
  max_list_items: 1024
  max_object_depth: 16
  max_object_keys: 256
  worker_memory_bytes: 134217728
  worker_stderr_bytes: 1024
```

Set `mode: disabled` only when no configured claim uses `rule.type: cel`.
`queue_max` must stay `0`; saturation fails fast so callers can retry or shed
load explicitly. Keep `allow_regex: false` unless the deployment has a reviewed
reason to permit regex-capable CEL helpers such as `matches`,
`text.regex_extract`, `text.regex_replace`, or `validate.matches`.

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

## Matching Policy

Each source binding has an optional `matching` block that gates and shapes how the
request is resolved to a source record before the read runs. The block is the
operator control behind [identity and record
matching](identity-and-record-matching.md); read that page for the concepts and the
outcome model. With no `matching` block, a binding falls back to unrestricted,
identifier-only behavior.

```yaml
source_bindings:
  person_record:
    connector: registry_data_api
    connection: civil_registry
    dataset: people
    entity: person
    lookup:
      input: target.attributes.birthdate
      field: birthdate
    matching:
      policy_id: person-name-birthdate-v1
      method: exact_name_birthdate
      target_type: Person
      allowed_purposes:
        - benefit_eligibility_check
      allowed_relationships:
        - self
        - guardian
      relationship_purpose_scopes:
        guardian:
          - benefit_eligibility_check
      sufficient_target_inputs:
        - [target.attributes.given_name, target.attributes.family_name, target.attributes.birthdate]
      allowed_target_inputs:
        - target.attributes.given_name
        - target.attributes.family_name
        - target.attributes.birthdate
      confidence: high
```

Fields:

| Field | Purpose | Default |
| --- | --- | --- |
| `policy_id` | Stable label for this policy, returned in the response and audit trail | none |
| `method` | Stable label for the matching method, returned in the response and audit trail | none |
| `target_type` | If set, the request `target.type` must equal this value | unenforced |
| `requester_type` | If set, the request `requester.type` must equal this value | unenforced |
| `allowed_purposes` | Purposes this binding may be used for; empty means no purpose restriction here | empty |
| `allowed_relationships` | Relationship types this binding accepts | empty |
| `relationship_purpose_scopes` | Per-relationship purpose allow-list; a scoped relationship used for any other purpose is rejected with granular code `relationship.purpose_not_allowed` | empty |
| `sufficient_target_inputs` | OR-of-AND groups of target paths; the request must satisfy at least one full group | empty |
| `allowed_target_inputs` | Allow-list of target paths the binding may read; empty means unrestricted | empty |
| `allowed_requester_inputs` | Allow-list of requester paths the binding may read; empty means unrestricted | empty |
| `collapse_matching_errors` | Map every matching error to public `evidence.not_available`, keeping the granular reason in audit | `true` |
| `require_requester_reauthentication` | Require the requester to reauthenticate before this binding reads | `false` |
| `confidence` | Confidence label returned with a successful match | none |

Notes:

- `sufficient_target_inputs` is an OR of ANDs. Each inner list is a complete set of
  paths that, when all present, is enough to match; the request needs to satisfy any
  one group. For example, `[[national_id], [given_name, family_name, birthdate]]`
  accepts either a national id alone or the full name-and-birthdate triple.
- `allowed_target_inputs` and `allowed_requester_inputs` are minimization controls.
  A request that supplies a path outside the allow-list is rejected, so a binding
  cannot over-collect by accident. Leave them empty only for identifier-only
  bindings that need no attribute minimization.
- `relationship_purpose_scopes` narrows named relationships to specific
  purposes after the flat `allowed_purposes` and `allowed_relationships` checks.
  Each scoped relationship must also appear in `allowed_relationships`.
  Relationships with no entry in the map keep the unscoped behavior. When
  `collapse_matching_errors` is on, callers see `evidence.not_available` and the
  granular code is retained for audit.
- `collapse_matching_errors` defaults to on. Turn it off only in a controlled
  environment where exposing not-found versus ambiguous versus rejected to the
  caller is acceptable, because those differences can be used as an existence
  oracle.
- `confidence` is a fixed label for the source and method. It is returned verbatim
  on every successful match and does not measure how strong an individual match was.
- Config validation rejects blank values: `policy_id`, `method`, `target_type`, and
  `requester_type` must be non-empty when present, and the purpose, relationship,
  relationship purpose scope, and input-path lists must not contain blank entries.

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
`evidence.max_credential_validity_seconds`. Keep token, proof, offer, and
evidence freshness windows short; set credential validity to the period the
issuing agency wants verifiers to treat the wallet-held VC as fresh. For
long-lived credentials, enable credential status or another revocation and
lifecycle surface.

Signing keys are covered in detail in
[`signing-key-provider.md`](signing-key-provider.md).

## Replay Store

`replay.storage: in_memory` is acceptable for a single process in local
development. It is not acceptable for active-active serving because two
processes cannot see the same nonce or proof replay decisions.
When the in-memory backend is selected, `/ready` returns HTTP 503 with
`status: degraded` so operators do not miss the single-process replay posture.

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

Key fields: `storage` is `in_memory` or `redis`. `redis.url_env` names the
environment variable containing the Redis connection URL. `redis.key_prefix`
scopes keys for shared clusters. `connect_timeout_ms` and
`operation_timeout_ms` must both be greater than zero when Redis is
configured. Notary fails to start when the named Redis URL environment
variable is missing. `/ready` fails closed when the Redis replay backend is
unavailable.

See [deployment-hardening-runbook.md](deployment-hardening-runbook.md) for
operational expectations, alerting guidance, and when to prefer Redis over
in-memory.

## Credential Status

Credential status tracks the lifecycle of individual issued credentials so
verifiers can check suspension or revocation after issuance. It is disabled by
default. Enable it only when verifiers need a live status check beyond
credential expiry. `base_url` must be the public HTTPS issuer origin verifiers
can reach; `retention_seconds` should cover maximum credential validity plus
verifier tolerance. Use Redis for any deployment where more than one process
can issue credentials or where status records must survive a restart.

See [`credential-lifecycle-status.md`](credential-lifecycle-status.md) for
status semantics, the full config block with all Redis fields, the status
payload shape, lifecycle state transitions, privacy boundary, and rollout
checklist.

## Self-Attestation

Self-attestation lets a citizen use their own OIDC token to evaluate or issue
only the claims that policy allows for the subject bound to that token. It
requires `auth.mode: oidc`. The subject binding is derived from a token claim
at request time; conflicting caller-supplied identity context is rejected
before any source read. All operations, claims, formats, disclosures, and
credential profiles are explicit allow-lists. Batch evaluation is not
supported. Credential profiles must use DID holder binding with proof of
possession and `did:jwk`. In-process rate limits are guardrails; public
deployments need gateway and identity-provider controls as well.

The config keys unique to this page are: `subject_binding.token_claim`,
`subject_binding.normalize` (must be `exact`),
`subject_binding.allow_sub_as_civil_id`, `citizen_clients`,
`token_policy` ceilings, `allowed_operations`, `allowed_purposes`,
`allowed_claims`, `allowed_formats`, `allowed_disclosures`,
`credential_profiles`, `scope_policy`, `required_scopes`,
`allowed_wallet_origins`, and `rate_limits`.

See the [self-attestation operator guide](https://github.com/jeremi/registry-notary/blob/f182385a5065873aac030c41d9fe020704afc4e2/docs/self-attestation-operator-guide.md)
for the full config blocks, identity-provider requirements, scope policy,
wallet origin controls, rate-limit fields, and rollout checklist.

## OID4VCI Wallet Facade

OID4VCI depends on self-attestation. Enable it when a wallet should retrieve
Notary-issued credentials through OpenID4VCI-style metadata, offers, nonces,
and credential requests. The facade is narrow: credential format is `dc+sd-jwt`,
proof type is JWT with EdDSA, holder binding is `did:jwk`, and issuance is
backed by self-attestation policy.

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
  authorization:
    require_pkce_method: S256
  proof:
    max_age_seconds: 300
    max_clock_skew_seconds: 60
  pre_authorized_code:
    enabled: true
    pre_authorized_code_ttl_seconds: 300
    tx_code:
      required: true
      input_mode: numeric
      length: 6
    esignet:
      client_id: registry-notary-rp
      client_signing_key_id: esignet-rp-key
      redirect_uri: https://notary.example.gov/oid4vci/offer/callback
      authorize_url: https://idp.example.gov/authorize
      token_url: https://idp.example.gov/oauth/v2/token
      issuer: https://idp.example.gov
      jwks_uri: https://idp.example.gov/.well-known/jwks.json
      scopes:
        - openid
      login_state_ttl_seconds: 300
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
Each `vct` must also be a public HTTPS URL and must match the referenced
credential profile `vct`.

`authorization.require_pkce_method` pins the PKCE challenge method wallets must
use. `proof.max_age_seconds` bounds how fresh a holder proof JWT must be, and
`proof.max_clock_skew_seconds` is the only clock difference tolerated when
checking that freshness.

`pre_authorized_code.tx_code.required` defaults to `true`. Set it to `false`
only for wallets that cannot send a transaction code. That compatibility mode
is reported as `bearer_offer` in admin posture and validates only when
`pre_authorized_code_ttl_seconds` is at most `300`, because the offer URI is
then sufficient to redeem the code.

Each `credential_configurations` entry must be consistent with both the claim
and the credential profile it references:

- `claim_id` exists in `evidence.claims`.
- `claim_id` is allowed by `self_attestation.allowed_claims`.
- `credential_profile` exists in `evidence.credential_profiles`.
- `credential_profile` is allowed by `self_attestation.credential_profiles`.
- The claim references the credential profile.
- The profile allows the claim.
- `format` is `dc+sd-jwt`.
- `vct` matches the credential profile `vct`.

See the [OID4VCI wallet interop guide](https://github.com/jeremi/registry-notary/blob/f182385a5065873aac030c41d9fe020704afc4e2/docs/oid4vci-wallet-interop.md) for the wallet
flow sequence, authenticated pre-authorized-code flow details, nonce policy,
Type Metadata serving, compatibility checklist, and troubleshooting.

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
  `publish_only` until their configured publication window ends or verifiers no
  longer need them.
- Multi-instance deployments use Redis replay storage.
- Credential status, if enabled, uses the externally reachable issuer base URL
  and a shared store.
- Audit has a stable high-entropy `hash_secret_env` value and off-host
  retention.
- `/metrics` is scraped with a `registry_notary:metrics_read` credential and
  normal network controls.
- `doctor` passes without `--live`, then passes with a controlled live subject.
