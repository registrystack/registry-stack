# Operator configuration reference

> **Page type:** Reference · **Product:** Registry Notary · **Layer:** all · **Audience:** operator

This reference describes how to assemble a deployable Registry Notary configuration.
It is written for teams adopting the service, not for contributors changing the
implementation.

Registry Notary is config driven. The YAML file describes which claims can be
evaluated, whether evidence comes through Registry Relay or is source-free, how
callers authenticate, how credentials are signed, and which operational stores
are used. Secrets should stay in environment variables, owner-readable secret
files, or a secret manager; config fields contain only references to them.

## Adoption decisions

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
| Registry-backed evaluation | A claim must consult a source registry | `evidence.relay`, `evidence_mode.type: registry_backed` |
| Source-free evaluation | A claim is derived without contacting Relay or a source | `evidence_mode.type: self_attested` |
| Existing direct-source migration | A pre-convergence deployment still reads a source or source adapter directly | `evidence_mode.type: transitional_direct` |

For a new registry integration, start with one narrow claim and one pinned Relay
consultation profile. Add credential issuance, federation, and wallet flows only
after the evaluation path passes `doctor` and a controlled end-to-end test.

## Top-level shape

| Block | Purpose | Required for startup |
| --- | --- | --- |
| `server` | Bind address and process HTTP settings | No, defaults are present |
| `auth` | Caller authentication and scope mapping | Yes |
| `deployment` | Operator-declared deployment profile and gate waivers | Yes, `deployment.profile` is required |
| `audit` | Redacted audit envelope sink and HMAC secret | Recommended for every deployable environment |
| `config_trust` | Signed bundle boot trust, anti-rollback state, and optional local override path | No, only for signed bundle startup |
| `evidence` | Claims, Relay or migration sources, rules, formats, signing keys, and credential profiles | Yes |
| `cel` | Optional CEL (Common Expression Language) worker policy, limits, and regex posture | Defaults are present |
| `replay` | One-time-use store for federation request JWTs, OID4VCI nonces, and holder proof JWTs | Defaults to in-process memory |
| `credential_status` | Optional storage-backed lifecycle status URL for issued credentials | No |
| `self_attestation` | OIDC-bound citizen request policy | Only for citizen or wallet flows |
| `oid4vci` | Wallet-facing OpenID4VCI facade | Only for wallet flows |
| `federation` | Static-peer delegated evaluation | Only for federation |

Unknown fields are rejected. That is intentional: a misspelled field should fail
at config validation instead of becoming an accidental open policy.

## Deployment profile and gates

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
  evidence:
    audit_offhost_shipping: true   # declares audit events are shipped off-host
    audit_ack_cursor_path: /var/lib/registry-notary/audit-ack-cursor.json # local state file the shipper updates
    audit_ack_max_age_secs: 900    # how old acked_at may get before the cursor reads as stale
    signer_custody_approved: true  # explicit approval for all configured signing roles
```

| Field | Purpose |
| --- | --- |
| `profile` | The declared assurance shape. Absent means startup refuses to boot. |
| `multi_instance` | Operator declaration that this instance runs active-active with peers, which makes shared, durable replay storage mandatory. |
| `waivers` | Per-finding suppressions, each with a mandatory reason and expiry. |
| `evidence` | Operator-asserted assurance evidence for conditions the runtime cannot observe for itself. Each flag defaults to `false`. |

`evidence` fields:

| Field | Purpose |
| --- | --- |
| `audit_offhost_shipping` | Operator asserts audit log events are shipped off-host (for example to a log aggregator or SIEM), so a local file sink does not cap retention. |
| `audit_ack_cursor_path` | Path to the regular, non-symlink state file a trusted off-host shipper atomically replaces after each successful hand-off (the `registry.audit.ack_cursor.v1` contract: `acked_at`, `last_acked_hash`, optional `writer`; maximum 16 KiB). Mount it read-only for Notary and keep it on local storage. Runtime health is `ok` only when the timestamp is fresh and the watermark equals the live keyed chain tail. Readiness and posture use one blocking worker with a 500 ms deadline. Setting the path without `audit_offhost_shipping` declared on a local file sink fails config load. |
| `audit_ack_max_age_secs` | How old the cursor's `acked_at` may get before it reads as stale. Defaults to 900 seconds. Setting it without `audit_ack_cursor_path` fails config load. |
| `signer_custody_approved` | Operator asserts a production review has approved custody for every key used by credential issuance, access-token issuance, or federation signing. Defaults to `false`. Provider kind alone is never treated as approval. |

Profiles:

| Profile | Use |
| --- | --- |
| `local` | Development, demos, tests, local pilots. Binds no gates. |
| `hosted_lab` | Shared demos, partner evaluations, hosted validation. |
| `production` | Real integrations handling sensitive or operational data. |
| `evidence_grade` | Deployments where the evidence trail is itself part of the assurance claim. |

An undeclared profile fails startup. Use `local` as the explicit development
opt-out, or declare `hosted_lab`, `production`, or `evidence_grade` for deployed
environments. An invalid profile value fails startup, so a typo cannot silently
disable enforcement.

Each gate evaluates to one of four severities under the declared profile:

| Severity | Effect |
| --- | --- |
| `startup_fail` | The process refuses to start. Never waivable. |
| `readiness_fail` | The readiness endpoint reports not-ready; the process runs. Never waivable. |
| `finding_error` | A posture finding, error class. |
| `finding_warn` | A posture finding, warn class. |

The gates bound for Registry Notary:

| Finding id | Condition | hosted_lab | production | evidence_grade |
| --- | --- | --- | --- | --- |
| `notary.replay.in_memory_high_risk` | In-memory replay while federation, OID4VCI pre-authorized code, holder proof, wallet traffic, or `multi_instance` is declared | error | readiness_fail | startup_fail |
| `notary.audit.sink_missing` | No durable, retained audit sink | error | startup_fail | startup_fail |
| `notary.audit.retention_local_only` | Audit sink is `file` or `jsonl` and `deployment.evidence.audit_offhost_shipping` is not declared. `stdout` and `syslog` are exempt. | n/a | warn | startup_fail |
| `notary.audit.shipping_unverified` | A shipping target (`stdout`, `syslog`, or an attested `file`/`jsonl` sink) has no `deployment.evidence.audit_ack_cursor_path`. | n/a | warn | startup_fail |
| `notary.audit.shipping_stale` | A cursor is configured but is missing, unsafe to read, malformed, too old, or its `last_acked_hash` differs from the live keyed audit-chain tail. | n/a | error | readiness_fail |
| `notary.source.insecure_url` | Source connection over a plain `http://` URL with no localhost or private-network allowance | error | readiness_fail | startup_fail |
| `notary.source.private_network_escape` | A source enables the private-network escape hatch | warn | error | error |
| `notary.sidecar.expected_sidecar_missing` | A source-adapter source omits `expected_sidecar` | warn | error | readiness_fail |
| `notary.admin.shared_exposure` | The admin surface shares the public listener | error | readiness_fail | startup_fail |
| `notary.openapi.public` | OpenAPI is served without authentication | warn | error | error |
| `notary.config.unsigned` | Local YAML config rather than signed bundle startup | warn | error | startup_fail |
| `notary.source_binding.no_matching_policy` | A claim source binding declares no matching policy (no `policy_id`, no context constraints), so resolution falls back to unrestricted, identifier-only matching | - | warn | error |
| `notary.assisted_access.transaction_token_anchor_missing` | `self_attestation.enabled` is true (citizen or wallet flows) while `auth.access_token_signing` is not enabled | error | readiness_fail | startup_fail |
| `notary.assisted_access.sender_constraint_missing` | `auth.access_token_signing` is enabled but the issued transaction token is not sender-constrained | warn | error | readiness_fail |
| `notary.signer_custody.unapproved` | A key used by credential issuance, access-token issuance, or federation signing is configured without `deployment.evidence.signer_custody_approved` | - | readiness_fail | startup_fail |

`notary.assisted_access.sender_constraint_missing` currently triggers whenever
its anchor condition is met: DPoP or mTLS proof validation for transaction
tokens is not yet implemented, so no config makes a transaction token
sender-constrained today. Enabling `auth.access_token_signing` for citizen or
wallet flows always leaves this finding active under `production` and
`evidence_grade`.

`notary.signer_custody.unapproved` is not a waiver. It is cleared only when the
operator declares `deployment.evidence.signer_custody_approved: true` after a
production review of every custody-relevant key. `pkcs11` identifies an
interface, not a hardware guarantee: the configured module can use an HSM or a
software token such as SoftHSM, so Registry Notary never treats provider kind as
approval.

The public `/ready` response reports whether custody approval is required and
declared, active provider-kind counts, local JWK/file provider counts, total
unapproved signer counts, and per-surface counts for credential issuance,
access-token issuance, and federation. It does not expose the deployment profile,
the complete deployment-finding list, environment variable names, file paths,
token labels, module paths, or key ids. Detailed findings remain available from
authenticated operator posture and `registry-notary doctor`.

### Waivers

A waiver names exactly one finding id, a free-text reason, and a mandatory
`expires` date (`YYYY-MM-DD`). While active, a waiver changes a triggered
finding's status to `waived` in posture instead of applying its severity effect.

- `startup_fail` and `readiness_fail` gates are never waivable. A waiver for one
  is rejected at config load, because running (or reporting ready) would falsify
  the declared profile.
- An expired waiver stops suppressing its finding and additionally raises
  `deployment.waiver_expired` in posture, so lapsed approvals surface rather than
  silently persisting.
- Waiver reasons appear in the restricted-tier posture for review. Never put a
  secret in a reason.

Active waivers and gate findings appear in the admin posture document under the
`deployment` object, and audit assurance fields appear under the top-level
`audit` object; see [security assurance](security-assurance.md).

## Secret handling

Config files should contain names, not secret values.

| Need | Config field | Secret source |
| --- | --- | --- |
| API key or bearer-token auth | `auth.api_keys[].fingerprint`, `auth.bearer_tokens[].fingerprint` | `sha256:<hex>` fingerprint |
| Registry Relay workload token | `evidence.relay.token_file` | Absolute path to a file containing the current workload JWT |
| Transitional direct upstream token | `evidence.source_connections.<id>.token_env` | Raw upstream bearer token |
| OAuth2 client credential source auth | `source_auth.client_id_env`, `source_auth.client_secret_env` | OAuth client id and secret |
| Local JWK signing key | `evidence.signing_keys.<id>.private_jwk_env` | Private JWK JSON matching the configured `alg` |
| Watched local JWK signing key | `evidence.signing_keys.<id>.path` with `provider: file_watch` | Private JWK JSON matching the configured `alg` in a host-local file |
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

RS256 is reserved for the eSignet RP client assertion key. Its private RSA JWK
must use a 2048-8192-bit modulus and include `n`, `e`, `d`, `p`, `q`, `dp`,
`dq`, and `qi`; keys outside that size range or missing CRT parameters are
rejected before use.

For local development, the binary accepts `--env-file`. For shared
environments, prefer the platform secret store and avoid checking dotenv files
into the repository.

## Config Bundle Trust

Most deployments can skip this section. `config_trust` is optional; it makes
startup config come from a signed, local config bundle. Simple local deployments
omit it and keep using the local YAML loaded at startup.

This example is syntactically valid but illustrative. Generate the trust anchor
and signed bundle with `registryctl anchor` and `registryctl bundle` before using
it in an environment.

```yaml
config_trust:
  trust_anchor_path: /etc/registry-notary/config/trust-anchor.json
  bundle_path: /etc/registry-notary/config/bundle
  antirollback_state_path: /var/lib/registry-notary/config-antirollback.json
  break_glass_override_path: /run/registry-notary/config-override.json
```

Config bundle trust is boot-time only. Notary reads no remote metadata, exposes
no admin config apply endpoint, and does not hot-apply runtime config. At boot it
verifies the anchor permissions, the bundle manifest and signature, product and
environment binding, bundle file closure, anti-rollback sequence, and full
Notary config validation. The accepted bundle is audited before the
anti-rollback state is advanced.

`antirollback_state_path` must point to durable local state such as a mounted
volume. `break_glass_override_path` is optional and points to a root-owned
one-shot override file. Rollback overrides may accept the exact signed bundle
hash named by the file. `accept_unsigned` overrides may pin an absolute local
config path and hash for emergency startup; signature, binding, and sequence
checks are skipped, but file permissions, hash pinning, and Notary config
validation still run.

Standalone Notary does not support resource, table, or runtime config reload;
the mounted `POST /admin/v1/reload` route returns `501
registry.admin.capability.not_supported`.

## Registry-backed Relay journey

Every claim must declare one sealed `evidence_mode`:

- `registry_backed` obtains evidence through Relay. Use it for new source-system
  integrations.
- `self_attested` is source-free. It permits a CEL rule but no consultation or
  `source_bindings`, and its dependency closure must also be source-free.
- `transitional_direct` keeps the old `source_connections` and source-binding
  runtime available only while an existing deployment migrates to Relay.

`transitional_direct` is intermediate-PR scaffolding, not a replacement-beta
compatibility promise. Its presence blocks the replacement beta and 1.0
release, and new integrations must not use it.

The claim evidence mode describes provenance. It is separate from the
`self_attestation` access block that configures OIDC-bound citizen and wallet
flows. Do not mark a registry-derived fact `self_attested` to avoid configuring
Relay.

Use `evidence_mode.type: registry_backed` for new claims that consult a source
system. Notary authenticates the caller, checks the claim purpose and scopes,
and sends the request's `target.id` to one reviewed Relay consultation profile.
Relay is the sole verifier of the Notary workload token and the sole component
that authenticates to and interprets the source system. Do not copy target
credentials or `source_connections` into Notary for this journey.

The initial configuration is deliberately narrow:

- `evidence.relay` describes one Relay origin and one reloadable token file.
- Each Registry-backed claim names exactly one consultation and one hash-pinned
  profile version.
- The consultation maps exactly one profile-defined input name to `target.id`.
- All Registry-backed claims in one Notary configuration share that profile,
  purpose, input name, and string output. At least one `extract` claim pins the
  shared output; an `exists` claim may reuse the same consultation.
- Rules are limited to `extract` and `exists`. Registry-backed batch evaluation
  is not supported.

This example evaluates one string result through Relay:

```yaml
evidence:
  enabled: true
  allowed_purposes: [program-enrollment-verification]
  relay:
    base_url: https://relay.example.gov
    token_file: /run/secrets/registry-notary/relay.jwt
    # Add only when this exact reviewed private range is required.
    allowed_private_cidrs: [10.42.7.12/32]
  claims:
    - id: enrollment-status
      title: Enrollment status
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile:
              id: dhis2.tracker.enrollment-status.exact
              version: "1"
              # Replace with the exact hash from the reviewed Relay contract.
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs:
              tracked_entity: target.id
      purpose: program-enrollment-verification
      required_scopes: [registry:evidence:dhis2-enrollment-status]
      value:
        type: string
      rule:
        type: extract
        source: enrollment
        field: status
      formats: [application/vnd.registry-notary.claim-result+json]
```

`evidence.relay` accepts only these fields:

| Field | Operator action |
| --- | --- |
| `base_url` | Use the Relay HTTPS root origin. Plain HTTP is accepted only for an IP loopback origin when both `allow_insecure_localhost: true` and `deployment.profile: local` are set. |
| `token_file` | Mount the current Relay-issued workload JWT at an absolute canonical path readable by the Notary process. |
| `allowed_private_cidrs` | Omit for a public Relay. For an internal Relay, list only the exact reviewed private CIDRs needed by its resolved addresses. |
| `allow_insecure_localhost` | Enable only for local loopback development. It is not a private-network or production escape hatch. |

Do not add token issuer, audience, subject, client, or Relay `max_in_flight`
fields. Unknown fields are rejected. Relay verifies token semantics on every
request, and the verified consultation profile supplies the concurrency bound.

Relay profiles may spend up to 20 seconds inside one total source fence, while
each individual data or credential exchange remains capped at 10 seconds.
Notary gives the complete internal service hop one fixed, non-configurable
25-second absolute deadline. Waiting for the profile-derived semaphore,
reloading the workload-token file, sending and reading the Relay response,
strict decoding, and final result acceptance all consume that same deadline.
There is no operator timeout field, retry, redirect, proxy, or result cache. For
a Registry-backed configuration, Notary rejects `server.request_timeout` below
30 seconds, creating a configured five-second listener margin around the
service hop. A consultation-enabled Relay separately requires its outer request
timeout to be greater than 25 seconds. The unchanged 30-second defaults satisfy
both guards.

### Startup and credential rotation

Before opening its listeners, Notary authenticates to Relay and verifies the
profile id, version, contract hash, purpose, input, and output contract. A
missing token, rejected credential, unreachable Relay, or mismatched profile
fails startup. The Relay origin, token-file path, and profile pin are
restart-only configuration.

The token value is different: Notary reopens the file for every Relay metadata
or execution operation. Rotate it without restarting Notary by atomically
replacing the configured path, or by using the atomic symlink switch provided
by a secret-volume implementation. Prepare the replacement on the same
filesystem, make it a regular file owned by the Notary service account with
owner-only permissions such as mode `0600`, then rename it over the old file.
Never rewrite the active file in place. A missing, malformed, or rejected
replacement fails closed; a later valid replacement recovers without restart.

### Validation, readiness, and audit

Use the existing operator commands in increasing order of network effect:

```sh
registry-notary explain-config --config registry-notary.yaml
registry-notary doctor --config registry-notary.yaml
registry-notary doctor --config registry-notary.yaml --live
```

`explain-config` reports the reload mode, offline file status, private-CIDR
count, and consultation pins without printing the token or token-file path.
`doctor` validates the configuration and checks that the token path resolves to
a non-empty regular file. `doctor --live` authenticates to Relay and verifies
the pinned profile metadata; run it only against an approved integration
environment. A controlled evaluation is still required to test the source
system end to end.

For a running Registry-backed deployment, `/ready` rechecks the current token
and pinned Relay profile and returns `503` when that dependency is not ready.
This readiness operation has its own 5-second outer bound, fetches only the
protected profile metadata, and makes zero source calls. It does not consume the
10-second DHIS2 source budget or execute a consultation.
The bounded `checks.relay` counts distinguish that dependency from signing or
other readiness failures without exposing its origin, profile, credential, or
error detail. Keep `/ready` on the normal orchestrator probe path and alert on
sustained failure. The default in-memory replay store still makes the overall
response degraded as documented under [Replay store](#replay-store); use the
Relay subcheck to distinguish that expected local posture from a Relay failure.

A single-subject evaluation may request several claims that use the same
Registry-backed profile, purpose, target input, and required scope set. Notary
coalesces those claims into one request-scoped Relay consultation. This is not a
cross-request cache: the next evaluation performs a new consultation. Do not
use the batch-evaluation endpoint for Registry-backed claims.

Notary forwards its evaluation id to Relay and stores every consultation id
returned before the evaluation closes only in the restricted audit event field
`relay_consultation_ids`, including failures that occur after Relay responds.
It also seals `forwarded: true` as a conservative dispatch-attempt marker before
permit acquisition, credential loading, or network I/O. The value means the
operation may have reached Relay, not that Relay received it. This placement
prevents cancellation from creating a false negative. If an early sibling
failure or client cancellation closes the Notary audit before detached Relay
work finishes, the event intentionally has no later mutation; use its
evaluation id to look for a late completion in Relay's audit. No matching Relay
event can legitimately mean the local attempt failed before network dispatch.
Relay consultation identifiers are deliberately absent from public claim
results, provenance, and debug output. Restrict access to both audit sinks.

## Transitional direct machine config

This compatibility shape is for an existing deployment that still evaluates a
claim by contacting a DCI (Social Protection Digital Convergence Initiative)
source directly. Keep it only while migrating the source integration to Relay;
do not use it for a new integration.

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
          observed_at: "$response:/message/search_response/0/timestamp"
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
      evidence_mode:
        type: transitional_direct
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
This switch does not affect `/.well-known/evidence-service`; that route remains
authenticated because it exposes configured Notary capability metadata. Hosted
lab and demo deployments returning `401` for unauthenticated discovery are
therefore aligned with the default policy.

## Authentication

`auth.mode: api_key` is for backend integrations. Configure at least one API key
or bearer token. Each entry has an `id`, a `fingerprint` reference, and scopes.
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
  RS256 JWKS keys must use a 2048-8192-bit RSA modulus.
- `scope_claim`, `scope_separator`, and `scope_map`: how external token scopes
  map to Registry Notary scopes.
- `principal_claim`: claim used for audit principal identity. The default is
  `sub`.

For citizen self-attestation, the OIDC token must also carry a binding claim
that Registry Notary uses to derive the requester and target context.

### Machine Evaluation Quota

`evidence.machine_quota` is a per-principal quota for `evaluate` and
`batch_evaluate` calls from machine credentials (API keys, bearer tokens, and
OIDC principals that are not classified as self-attestation). It is separate
from, and does not affect, the self-attestation rate limiters or the
per-request `max_subjects` batch-size cap: it bounds work over time, not the
shape of a single request.

```yaml
evidence:
  machine_quota:
    enabled: true
    subjects_per_minute: 6000
```

| Field | Purpose | Default |
| --- | --- | --- |
| `enabled` | Turns the quota on. | `false` |
| `subjects_per_minute` | Budget per principal, in subjects, over a fixed one-minute window. A single `evaluate` call costs 1; a `batch_evaluate` call costs `items.len()`. Must be greater than 0 when `enabled: true`. | `6000` |

The budget is a fixed window keyed by `principal_id`: for `auth.mode: api_key`
this is the configured key `id`; for `auth.mode: oidc` it is the JWT `sub` (or
whichever claim `principal_claim` names). A request whose cost would exceed
the remaining budget is rejected in full, so a rejected batch never partially
consumes the window. Exhaustion returns `429` with the stable error code
`evaluation.quota_exceeded` and a `Retry-After` header giving the number of
seconds until the window rolls over. The quota is disabled by default; enable
it and size `subjects_per_minute` to the traffic pattern of your machine
callers before relying on it in production.

The counters are held in an in-memory map, and each Notary process builds its
own limiter, so this quota is enforced per instance, not cluster-wide. With N
replicas behind a load balancer, a single caller can spend up to N times
`subjects_per_minute` across the deployment. Size the per-instance value with
replica count in mind, or front the fleet with a shared limiter if you need a
global ceiling.

## Source connections

`source_connections` is the pre-convergence direct-source model and is valid
only for claims with `evidence_mode.type: transitional_direct`. Every source
binding references one entry, which defines the upstream base URL,
authentication method, and connector-specific settings. Keep these connections
only while migrating an existing integration to Relay.

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
as the OpenCRVS demo endpoint.

For DCI sources, check these fields carefully:

- `search_path`: path appended to `base_url`.
- `sender_id`, `receiver_id`, `registry_type`, `registry_event_type`, and
  `record_type`: envelope values expected by the upstream DCI implementation.
- `query_type`: `idtype-value` for one identifier lookup, or `expression` when
  the upstream supports fielded query expressions.
- `records_path`: JSON Pointer to the records array in a single response.
- `field_paths`: JSON Pointers for fields that the claim rule reads. Paths are
  record-relative by default. Prefix a path with `$response:` when a binding
  needs source metadata from the full DCI response envelope, for example
  `observed_at: "$response:/message/search_response/0/timestamp"` for
  OpenCRVS response freshness.
- `bulk_mode`: leave `none` until the source contract has been tested. Use
  `dci_batched_search` or `rda_in_filter` only when the upstream supports that
  access pattern.

For any source binding, `query_fields` can replace the single-field `lookup`
wire query when the source supports multi-field lookup. `registry_data_api`
sends them as query parameters, and DCI `expression` sends them inside the DCI
query envelope. For `source_adapter_sidecar`, Notary sends single reads through the
sidecar's Registry Data API-shaped read endpoint, and sends batch reads through
the sidecar's `records:batchMatch` endpoint. Leave `query_fields` empty for the
legacy single-field lookup.

For production, leave `allow_insecure_localhost` and
`allow_insecure_private_network` false unless the deployment review explicitly
accepts the private network source. Local demos may use them for loopback or
Docker Compose style setups.

### Source adapter sidecar source connections

Use `connector: source_adapter_sidecar` when a target system needs governed HTTP JSON
mapping, a short dependent HTTP JSON flow, FHIR mapping, target credential
handling, or output normalization outside Notary. The sidecar source chooses
`engine: http_json`, `engine: http_flow`, `engine: fhir`, or
`engine: script_rhai` (a sandboxed, orchestration-only Rhai script for sources
that need a little branching across a few governed source calls, such as a JSON
POST search followed by a GET, or a visible-404 fallback; see the
[Script (Rhai) source adapter guide](script-rhai-source-adapter-guide.md))
in its own signed manifest. The source connection must use static sidecar bearer auth through
`token_env`. Do not configure target-service credentials in Notary; keep them
in the sidecar environment or secret store. Configure performance and
target-protection controls in the sidecar manifest: per-source `max_in_flight`,
optional request rate and burst, `Retry-After` backoff handling, built-in
adapter sequential or parallel lookup mode, `http_json` native batch mode where
the upstream has a real bulk endpoint, and any explicit TTL-bound result cache.
Treat cache settings as evidence freshness policy, not only performance tuning.
Sidecar result caches are bounded by `cache.max_entries`, defaulting to 10000
entries per source.

For high-assurance deployments, pin the sidecar runtime that Notary is allowed
to use with `expected_sidecar`. Notary reads the private sidecar assurance
endpoint before source reads and fails closed when the product identity,
environment, stream, `config_hash`, expression-hash verification, runtime
verification, or smoke-check state does not match the pin.

Single-read sidecar example:

```yaml
evidence:
  source_connections:
    source_adapter_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: SOURCE_ADAPTER_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: none
      expected_sidecar:
        product: registry-notary-source-adapter-sidecar
        instance_id: civil-registry-sidecar
        environment: production
        stream_id: source-adapter-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-06
      subject_type: person
      evidence_mode:
        type: transitional_direct
      value:
        type: date
      semantics:
        concept: https://publicschema.org/Person
        property: https://publicschema.org/date_of_birth
        value_mapping: publicschema
      inputs:
        - name: target.identifiers.national_id
          type: string
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
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
              semantic_term: https://publicschema.org/date_of_birth
      rule:
        type: extract
        source: crvs
        field: birth_date
```

Sidecar batch matching example with `query_fields`:

```yaml
evidence:
  source_connections:
    source_adapter_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: SOURCE_ADAPTER_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
      bulk_timeout_max_ms: 30000
      expected_sidecar:
        product: registry-notary-source-adapter-sidecar
        instance_id: civil-registry-sidecar
        environment: production
        stream_id: source-adapter-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
  claims:
    - id: birth-record-exists
      title: Birth record exists
      version: 2026-06
      subject_type: person
      evidence_mode:
        type: transitional_direct
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
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
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

For sidecar connections:

- Set `retry_on_5xx: false`. Notary does not retry sidecar adapter execution
  failures.
- Use `bulk_mode: source_adapter_sidecar_batch` only after sidecar contract tests cover
  per-item not found, exact match, ambiguous match, missing response item,
  duplicate response item id, adapter timeout, adapter failure, and output
  projection.
- In governed environments, set `expected_sidecar` on every sidecar
  connection. Local demos may omit it only when the assurance boundary is not
  part of the test.

See the [deployment hardening runbook](deployment-hardening-runbook.md) for
network isolation requirements, responsibility boundaries between Notary and
the sidecar, and deployment security expectations.

## CEL runtime

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
- `evidence_mode`: required provenance boundary: `registry_backed`, source-free
  `self_attested`, or migration-only `transitional_direct`.
- `purpose` and `required_scopes`: explicit pre-consultation gates required for
  Registry-backed claims.
- `semantics`: optional external vocabulary binding for the claim output. Use it
  to label raw values with PublicSchema properties or derived booleans with a
  local predicate plus `derived_from` PublicSchema inputs.
- `inputs`: request lookup paths. Supported paths include `target.id`,
  `target.identifiers.<scheme>`, `target.attributes.<name>`, `requester.id`,
  `requester.identifiers.<scheme>`, `requester.attributes.<name>`, and
  `relationship.attributes.<name>`.
- `source_bindings`: direct upstream reads used only by `transitional_direct`
  claims.
- `rule`: `exists`, `extract`, or `cel`.
- `depends_on`: prerequisite claims for CEL rules that reuse earlier results.
- `operations`: enable or cap `evaluate` and `batch_evaluate`.
- `disclosure`: default and allowed response disclosure modes.
- `formats`: response formats the claim can render.
- `credential_profiles`: profiles allowed to issue from this claim.

`semantics` is metadata, not a new credential shape. It helps clients understand
and compare Notary claims across systems, for example by mapping `date-of-birth`
to `https://publicschema.org/date_of_birth`. It does not turn a Notary claim
result into a full PublicSchema `IdentityCredential` or `EnrollmentCredential`.
For derived predicates, do not map the predicate as if it were the raw property;
use `predicate` and `derived_from` instead.

```yaml
semantics:
  concept: https://publicschema.org/Person
  property: https://publicschema.org/date_of_birth
  value_mapping: publicschema
```

```yaml
semantics:
  concept: https://publicschema.org/Person
  predicate: urn:registry-notary:predicate:age-at-least-18
  derived_from:
    - https://publicschema.org/date_of_birth
```

Avoid broad source bindings. A claim should read only the fields needed to
evaluate that claim. If two credentials need different fields, prefer two claims
or a small dependency graph over one over-broad claim.

### Dependent source lookups

This compatibility feature applies only to `transitional_direct` claims. When
one source row contains the identifier needed to read another source, set
the later binding's `lookup.input` or `query_fields[].input` to
`sources.<binding>.<field_path>`. Notary loads the referenced binding first,
extracts the scalar field value from its row, and uses that value as the later
lookup input. Use the plural `sources.` form in new config; the singular
`source.` form is accepted as a compatibility alias.

```yaml
source_bindings:
  birth_event:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: birth_events
    lookup:
      input: target.identifiers.registration_number
      field: registration_number
      op: eq
      cardinality: one
  child_person:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: persons
    lookup:
      input: sources.birth_event.child_person_id
      field: person_id
      op: eq
      cardinality: one
  mother_person:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: persons
    lookup:
      input: sources.birth_event.mother_person_id
      field: person_id
      op: eq
      cardinality: one
```

Dependent lookups are resolved in dependency order. A missing prior binding,
missing field, null field, or empty prior result is treated as source not found.
Multiple prior rows are treated as source ambiguous. The referenced value must be
a string, number, or boolean; arrays and objects are rejected as invalid request
input. Cycles between source bindings fail claim evaluation.

## Matching policy

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
| `allowed_assurance` | Allow-list of asserted requester assurance labels (for example `substantial`); the read is denied if the request's assurance is absent or not in this list | empty |
| `minimum_assurance` | Minimum required assurance rank the request's asserted assurance must meet or exceed; enforced alongside `allowed_assurance` when both are set | none |
| `permitted_jurisdictions` | Allow-list of jurisdictions permitted to read this binding; the read is denied if the request's jurisdiction is absent or not listed | empty |
| `max_source_age_seconds` | Maximum age, in seconds, of the source record's observed-at timestamp before the read is treated as stale evidence; requires `source_observed_at_field` to be set | none |
| `source_observed_at_field` | Path into the source row holding an RFC 3339 timestamp used for the freshness check; required when `max_source_age_seconds` is set | none |
| `require_legal_basis` | Reject the request unless a legal basis reference is present in context | `false` |
| `require_consent` | Reject the request unless a consent reference is present in context | `false` |
| `allowed_legal_basis_refs` | Allow-list of accepted legal basis references; a request with a legal basis outside the list is rejected | empty |
| `allowed_consent_refs` | Allow-list of accepted consent references; a request with a consent reference outside the list is rejected | empty |
| `redaction_fields` | Field paths redacted from the evaluation result on an otherwise-permitted read | empty |
| `ecosystem_binding` | Selects an evidence-pack policy (`policy_id` and `policy_hash`, optionally `id`, `profile`, `pack_id`, `pack_version`, `unsupported_odrl_terms`) that supplies this binding's audited policy identity in place of the binding's own `policy_id` | none |
| `context_constraints` | Nested alternate syntax for `legal_basis`, `consent`, `jurisdiction`, `assurance`, and `source_freshness`; merges into the corresponding flattened fields at config load and fails validation if the two forms disagree | none |
| `allowed_relationships` | Relationship types this binding accepts | empty |
| `relationship_purpose_scopes` | Per-relationship purpose allow-list; a scoped relationship used for any other purpose is rejected with granular code `relationship.purpose_not_allowed` | empty |
| `sufficient_target_inputs` | OR-of-AND groups of target paths; the request must satisfy at least one full group | empty |
| `allowed_target_inputs` | Allow-list of target paths the binding may read; empty means unrestricted | empty |
| `allowed_requester_inputs` | Allow-list of requester paths the binding may read; empty means unrestricted | empty |
| `collapse_matching_errors` | Map every matching error to public `evidence.not_available`, keeping the granular reason in audit | `true` |
| `require_requester_reauthentication` | Require the requester to reauthenticate before this binding reads | `false` |
| `confidence` | Confidence label returned with a successful match | none |

Notes:

- For example, `[[national_id], [given_name, family_name, birthdate]]` accepts
  either a national id alone or the full name-and-birthdate triple.
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
- `allowed_assurance`, `minimum_assurance`, `permitted_jurisdictions`,
  `max_source_age_seconds`, `require_legal_basis`, `require_consent`,
  `allowed_legal_basis_refs`, `allowed_consent_refs`, and `redaction_fields` are
  enforced by the same policy decision point (PDP) that evaluates target,
  requester, and relationship gates. A request that fails any configured
  constraint is denied before the source read runs; `redaction_fields` instead
  redacts the listed paths from an otherwise-permitted result.
- `context_constraints` is a nested, source-adjacent way to write
  `require_legal_basis`/`allowed_legal_basis_refs`, `require_consent`/
  `allowed_consent_refs`, `permitted_jurisdictions`, `allowed_assurance`/
  `minimum_assurance`, and `max_source_age_seconds`. Use either the flattened
  fields or `context_constraints`, not conflicting values in both; config
  loading rejects a nested value that disagrees with its flattened counterpart.
- `ecosystem_binding` points a binding at an evidence-pack policy's `policy_id`
  and `policy_hash` for audit identity. Supplying `policy_id` and `policy_hash`
  directly on the selector requires a supported `profile` and a well-formed
  policy hash; see the ecosystem binding entries under `evidence` for how packs
  are declared.
- Config validation rejects blank values: `policy_id`, `method`, `target_type`, and
  `requester_type` must be non-empty when present, and the purpose, assurance,
  jurisdiction, legal-basis, consent, redaction, relationship, relationship
  purpose scope, and input-path lists must not contain blank entries.
  `source_observed_at_field` is required whenever `max_source_age_seconds` is
  set, and both must be non-empty when present.

## Credential profiles

Credential profiles control SD-JWT VC issuance.

Profile fields:

- `format: application/dc+sd-jwt`.
- `issuer`: DID issuer for the credential.
- `signing_key`: key id from `evidence.signing_keys`.
- `vct`: credential type URL.
- `allowed_claims`: explicit allow-list. Empty allow-lists are rejected.
- `holder_binding`: defaults to `mode: did` with `did:jwk` as the allowed
  method. Set `mode: none` only for an explicit bearer-style credential profile;
  `registry-notary doctor` reports a warning for unbound profiles.
- `disclosure.allowed`: disclosure modes the profile may carry.

`validity_seconds` defaults to 600 and must be between 1 and
`evidence.max_credential_validity_seconds`. Keep token, proof, offer, and
evidence freshness windows short; set credential validity to the period the
issuing agency wants verifiers to treat the wallet-held VC as fresh. For
long-lived credentials, enable credential status or another revocation and
lifecycle surface.

Signing keys are covered in detail in
[`signing-key-provider.md`](signing-key-provider.md).

## Replay store

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

## Credential status

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

## Self-attestation

Self-attestation lets a citizen use their own OIDC token to evaluate or issue
only the claims that policy allows for the subject bound to that token. It
requires `auth.mode: oidc`. The subject binding is derived from a token claim
at request time; conflicting caller-supplied identity context is rejected
before any source read. All operations, claims, formats, disclosures, and
credential profiles are explicit allow-lists. Batch evaluation is not
supported. Credential profiles must use DID holder binding with proof of
possession and `did:jwk`. In-process rate limits are guardrails; public
deployments need gateway and identity-provider controls as well.

The `self_attestation` block's keys are: `subject_binding.token_claim`,
`subject_binding.normalize` (must be `exact`),
`subject_binding.allow_sub_as_civil_id`, `citizen_clients`,
`token_policy` ceilings, `allowed_operations`, `allowed_purposes`,
`allowed_claims`, `allowed_formats`, `allowed_disclosures`,
`credential_profiles`, `scope_policy`, `required_scopes`,
`allowed_wallet_origins`, `delegation`, and `rate_limits`.

Delegated self-attestation is unavailable in v1. Keep
`self_attestation.delegation.enabled: false` and `allowed_relationships: []`.
Enabling it fails configuration validation until a separately reviewed
Relay-bound subject and relationship assertion design exists.

See the [self-attestation operator guide](self-attestation-operator-guide.md)
for the full config blocks, identity-provider requirements, scope policy,
wallet origin controls, rate-limit fields, and rollout checklist.

## OID4VCI wallet facade

OID4VCI depends on self-attestation. Enable it when a wallet should retrieve
Notary-issued credentials through OpenID4VCI-style metadata, offers, nonces,
and credential requests. The facade is narrow: credential format is `dc+sd-jwt`,
proof type is JWT with EdDSA, holder binding is `did:jwk`, and issuance is
backed by direct self-attestation policy. Delegated transaction tokens and
delegation configuration are rejected in this version.

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

See the [OID4VCI wallet interop guide](oid4vci-wallet-interop.md) for the wallet
flow sequence, authenticated pre-authorized-code flow details, nonce policy,
Type Metadata serving, compatibility checklist, and troubleshooting.

## Validation workflow

Run config checks before exposing the service:

```sh
registry-notary explain-config --config registry-notary.yaml --env-file .env.local
registry-notary doctor --config registry-notary.yaml --env-file .env.local
registry-notary doctor --config registry-notary.yaml --env-file .env.local --live
```

Use `--live` only against a test target or a controlled integration
environment. For Registry-backed claims it verifies the Relay credential and
pinned profile metadata but does not execute a consultation; follow it with a
controlled evaluation to test the source end to end. For transitional direct
claims, live lookup values cause a real upstream lookup. Doctor output redacts
target ids and tokens, but the source still receives that lookup.

For local VC smoke tests:

```sh
registry-notary doctor \
  --config registry-notary.yaml \
  --env-file .env.local \
  --issue-demo-vc
```

## Rollout checklist

- Each caller has only the scopes required for its claims and operations.
- Registry-backed claims share the reviewed Relay profile pin, purpose, input,
  and output expected by the deployed Relay contract.
- The Relay token file is owner-readable only and has an atomic rotation path.
- `allowed_private_cidrs` contains only reviewed Relay destination ranges.
- Every remaining transitional source connection has exactly one auth method
  and an explicit migration owner.
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
- `doctor` passes without `--live`, then passes with `--live` in a controlled
  environment. Registry-backed rollout also includes one controlled end-to-end
  evaluation.
