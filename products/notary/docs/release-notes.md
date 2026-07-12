# Release Notes

## Unreleased

- BREAKING: every claim now declares an explicit evidence mode. New
  source-backed claims use a hash-pinned Relay consultation; source-free claims
  use `self_attested`. Existing direct/source-adapter claims must be labeled
  `transitional_direct` only during the unreleased migration window, and that
  mode blocks the replacement beta and 1.0 release.
- Registry-backed Notary verifies its Relay profile before serving, reloads a
  mounted workload JWT for each operation, exposes Relay readiness and live
  doctor checks, and keeps Relay correlation in restricted audit only. Set
  Notary `server.request_timeout` to at least 30 seconds and restrict the token
  file to the Notary service account.
- New country configurations can map one verified Relay consultation into
  Boolean, bounded String, exact Integer, full-date, Presence, and nullable
  facts, then reuse that fact map across direct claims and CEL derivations.
  Declare any full-date evaluation inputs under `evidence.variables` and send
  them in `request.variables`; undeclared or missing inputs are rejected before
  Notary contacts Relay or a source. Existing legacy projected-string and
  presence consultations remain supported during migration.
- Country fixture evaluation now reuses Notary's production authentication,
  policy, consultation, disclosure, and isolated CEL paths. The co-shipped
  internal CEL protocol also preserves multiline expressions and successful
  null results through a tagged response; old and new worker binaries remain
  intentionally version-aligned and mixed versions fail closed.
- Registry-backed batch evaluation requires a caller-supplied
  `Idempotency-Key` and authorizes the complete batch before source access.
  Notary preserves ordered per-item results while running bounded independent
  single-subject Relay consultations. Exact retries reuse private durable child
  identities without repeating completed source work; Notary does not send a
  multi-subject Relay consultation or claim native upstream bulk optimization.

## 0.9.0

- Production and evidence-grade deployments now fail closed until signer custody
  is explicitly approved for credential, access-token, and federation signing
  roles. `/ready` exposes typed, non-secret custody facts, while detailed
  deployment findings remain on authenticated operator surfaces. Review each
  role's custody and retain the evidence before setting
  `deployment.evidence.signer_custody_approved: true`; the attestation is not a
  gate bypass.
- BREAKING: `deployment.profile` is required and must be one of `local`,
  `hosted_lab`, `production`, or `evidence_grade`. Notary refuses startup when
  it is absent instead of inferring a profile.
- BREAKING: claim configuration is validated at load time. Duplicate claim ids,
  invalid default disclosure modes, and rules referring to undeclared source
  bindings must be corrected before Notary starts.
- BREAKING: the TUF-era `/admin/v1/config/verify`,
  `/admin/v1/config/dry-run`, and `/admin/v1/config/apply` endpoints are
  removed, as is the CLI `config apply-bundle` command. First run
  `registryctl bundle verify` for stateless signature and binding verification,
  then place the signed Registry Config Bundle v1 on the Notary node. For a
  genuinely absent, version-specific antirollback state path, start Notary with
  `--initialize-state`; that boot verifies the bundle and initializes state.
  Notary's read-only `config verify-bundle` command remains, but it requires
  accepted state to exist, so use it only for later candidate validation and
  restarts. Replace retired TUF-era fields inside `config_trust` with current
  Config Bundle v1 trust fields because strict parsing rejects the old schema.
  Hot apply is not supported. Back up the durable
  `config_trust.antirollback_state_path` state and keep release-specific
  restore sets. Restore the state belonging to the release during rollback;
  never delete or reinitialize it to force an older bundle to load.
- BREAKING: source-adapter sidecar configuration now rejects unknown keys.
  Remove misspelled, retired, or wrapper-only fields before upgrading.
- Evidence-grade deployments using audit shipping must configure a fresh
  acknowledgement cursor. Local-only file retention is a hard gate and cannot
  be waived.
- Federation denials after request verification now preserve available redacted
  peer, source-scope, profile, purpose, JTI, claim, and subject context in audit
  records, including response-signing failures.
- Added per-principal machine evaluation quotas and live audit-shipping health
  in readiness, posture, and doctor output.

## 0.8.4

- BREAKING: Static API-key and bearer-token config no longer accepts
  `fingerprint.commitment`.
  Remove that field from Notary YAML.
  Keep `fingerprint.provider` with `fingerprint.name` or `fingerprint.path`; the
  referenced value must contain `sha256:<64 lowercase hex chars>`.
- Static credential rotation is now either a secret-plane update plus restart,
  or a signed config bundle change to a new immutable or versioned fingerprint
  reference, placed on the node and activated by restart.
  OIDC remains the preferred production model for citizen and wallet flows.

## 0.6.2

- Fixed federated evaluation policy-context handling so federation profiles can
  satisfy source matching gates for legal basis, consent, jurisdiction, and
  assurance without being treated as scoped transaction authorization details.
- Restores delegated federation evaluations that use governed source-policy
  gates.

## 0.6.1

- Fixed static credential policy-context compatibility for source matching:
  static credentials can again carry configured legal basis, consent,
  jurisdiction, and assurance context for PDP gates without being treated as
  exact per-transaction authorization scopes.
- Kept OIDC/RAR authorization details fail-closed unless transaction scope
  fields are present.

## 0.6.0

- Added delegated self-attestation support with explicit requester-side target
  binding, canonicalized delegated targets, and claim-lookup validation.
- Bound delegated authorization details to the requested identifier type so a
  delegated attestation cannot drift across supported identity forms.
- Hardened authorization-details handling before batch prefetch, credential
  issuance, render, evaluate, pre-authorization, status-list, and data-route
  audit paths.
- Added cache compare-and-set support for credential status transitions and
  status-list signing so concurrent updates fail closed.
- Refreshed the Registry Platform pin to the beta-4 platform release.

## 0.3.0

- Added citizen self-attestation flows, including bearer-token subject binding,
  rate limiting, denial audit metadata, and SD-JWT VC issuance.
- Added OpenID4VCI issuer primitives and HTTP routes for credential issuer
  metadata, SD-JWT VC Type Metadata at configured `vct` URLs, credential offers,
  nonce creation, and credential issuance.
- Added the source adapter sidecar path for private source reads, including
  built-in `http_json`, `http_flow`, and `fhir` engines, source concurrency
  controls, target rate limits, `Retry-After`
  backoff handling, bounded result caching, and DHIS2 canary smoke scripts.
- Kept CEL out of default builds while adding an opt-in CEL production image
  profile with hardened worker execution, startup expression preflight,
  declared result-type enforcement, and policy-hash worker protocol checks.
- Added named SD-JWT VC signing keys under `evidence.signing_keys`, including
  local JWK signing, publish-only rotation keys with optional bounded
  publication windows, disabled keys, and optional PKCS#11-backed Ed25519
  signing.
- Historical note: 0.3.0 introduced the first governed config prototype with
  signed TUF bundles, `config verify-bundle`, `config apply-bundle`, and
  `config_trust`.
  Current releases use Registry Config Bundle v1 instead: a local directory with
  `manifest.json`, `manifest.sig.json`, and `config/...`. Before a first boot,
  `registryctl bundle verify` checks signatures and bindings without product
  antirollback state. The first boot with genuinely absent state uses
  `--initialize-state`; after state exists, the read-only product
  `config verify-bundle` command supports later candidate validation and
  restarts.
  There is no current `apply-bundle` command and no hot apply.
- Added `server.admin_listener` to split admin and public HTTP topology. The
  `dedicated` mode serves `/admin/v1/*` and `/metrics` on a separate admin bind,
  `shared_with_public` serves them on the public listener, and `disabled` drops
  the admin listener entirely. Governed `config_trust` requires `dedicated`.
- Changed the default `server.admin_listener.mode` from `shared_with_public` to
  `disabled`; local deployments that intentionally need the old shared topology
  must set `server.admin_listener.mode: shared_with_public` explicitly.
- Added bounded HTTP serve defaults: `server.request_timeout: 30s`,
  `server.request_body_timeout: 10s`, `server.http1_header_read_timeout: 10s`,
  and `server.max_connections: 1024`. The source adapter sidecar mirrors the same
  limits with millisecond-suffixed config keys.
- Changed `auth.api_keys[]` and `auth.bearer_tokens[]` to a committed
  `fingerprint` reference (`provider`, `name`, `commitment`) in place of
  `hash_env`, so a signed config bundle can govern caller-credential rotation
  after restart.
- Renamed OIDC config fields to the shared Registry service convention:
  `auth.oidc.jwks_url`, `auth.oidc.leeway`, and
  `auth.oidc.allowed_token_types`. Legacy aliases fail config load with an error
  naming the replacement. `auth.oidc.leeway` now uses humantime strings such as
  `30s`; self-attestation
  `token_policy.max_clock_leeway_seconds` still bounds the resolved duration.
- Removed `server.cors.allow_credentials`; Registry Notary now always disables
  credentialed CORS on the operator-configured server CORS layer. Remove the
  field from config rather than setting it to `false`.
- Renamed `audit.max_size_bytes` to `audit.max_size_mb` and aligned the default
  active-file rotation to 100 MB with 14 retained files.
- Added `REGISTRY_NOTARY_LOG_FORMAT=text|json`; the default log filter is plain
  `info`.
- Product binaries and container images now compile the PKCS#11 provider by
  default, while vendor modules, token state, labels, and PIN handling remain
  operator-supplied runtime configuration.
- Hardened SD-JWT VC conformance for `dc+sd-jwt`, holder binding, proof
  validation, and OpenAPI documentation.
- Replaced fake Problem Details type URLs with
  `https://id.registrystack.org/problems/registry-notary/...`.
- Changed self-attestation subject-binding hashes to keyed HMAC values and
  stopped recording raw query strings in request spans or audit paths.
- Known limitations: this release is `dc+sd-jwt` only, does not serve
  `/.well-known/jwt-vc-issuer`, does not implement PKCS#12 issuer keys, does
  not certify a vendor HSM, and leaves retention/erasure workflows to the
  operator.

## 0.2.1

- Added `evidence.source_connections[].allow_insecure_private_network` for
  Docker Compose and private-network demos that need HTTP source registries.
  The escape hatch is opt-in, keeps cloud metadata endpoints blocked, and
  leaves the strict HTTPS policy as the default.

## 0.2.0 (rename)

- Renamed: `evidence-server` → `registry-notary`. No backward compatibility; no aliases.
  - Crates: `evidence-core` → `registry-notary-core`, `evidence-server` → `registry-notary-server`,
    `evidence-server-bin` → `registry-notary-bin`.
  - Binary: `evidence-server` → `registry-notary`.
  - Media type: `application/vnd.evidence-server.claim-result+json` → `application/vnd.registry-notary.claim-result+json`.
  - Default audience: `"evidence-server"` → `"registry-notary"`.
  - Cargo feature: `evidence-server-cel` → `registry-notary-cel`.
  - Project-labeled env vars: `EVIDENCE_SERVER_API_KEY`, `EVIDENCE_SERVER_BEARER_TOKEN`,
    `EVIDENCE_SERVER_ISSUER_JWK` → `REGISTRY_NOTARY_API_KEY_HASH`,
    `REGISTRY_NOTARY_BEARER_TOKEN_HASH`, `REGISTRY_NOTARY_ISSUER_JWK`. The
    renamed auth variables hold `sha256:<64 hex>` fingerprints, not plaintext
    tokens.
  - Demo config: `demo/config/evidence-server.yaml` → `demo/config/registry-notary.yaml`.

## 0.1.0

- Initial Evidence Server repository cut from `registry_relay`.
- Preserves `evidence-core` and `evidence-server` crate behavior as an
  independent Cargo workspace.
- Adds `evidence-server-bin` for standalone config loading, binding, tracing,
  shutdown, fail-closed API key and bearer-token auth, and redacted audit event
  output.
- Adds HTTP Registry Data API and DCI source connectors so claim evaluation can
  use external source registries without linking Registry Relay.
- Keeps CEL enabled by default through `cel-mapper-core`, pinned to
  `PublicSchema/cel-mapping` tag `cel-mapper-core-v0.1.0`.
- Adds a `cargo run -p evidence-server-bin -- openapi` command for owned
  Evidence Server OpenAPI output.

Known non-goals for this cut:

- 0.1.0 does not include OIDC/JWKS discovery; the standalone binary supports API keys and
  static bearer tokens.
