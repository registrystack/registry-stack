# Release Notes

## Unreleased

## 0.12.2

- Registry Notary has no new product features relative to v0.12.1. This
  release fixes forward from the incomplete v0.12.1 publication with a
  canonical reproducible release-build path for the Notary binary, CEL worker,
  and runtime image.

## 0.12.1

- Registry Notary has no new product features relative to v0.12.0. The release
  reviews the three non-fixable Debian 13 `libc6` findings and binds that
  time-bounded accepted risk to the ordered runtime root filesystem layer
  digest. Fixable, expired, mismatched, and unreviewed findings fail the image
  advisory gate.

## 0.12.0

- BREAKING: The 1.0 wallet facade supports only issuer-initiated
  pre-authorized code backed by a stored registry transaction. The former
  credential-offer and public nonce routes are removed, and the credential
  response has no next nonce. Start with `/oid4vci/offer/start`, complete the
  identity-provider callback, redeem the rendered offer at `/oid4vci/token`,
  and use its transaction-bound proof nonce. The identity provider's
  authorization code is never a wallet grant.
- OID4VCI source tests now cover complete issuance and client verification for
  EdDSA and ES256 issuer keys with an EdDSA `did:jwk` holder. Metadata
  advertises the exact configured issuer algorithm and only the supported
  holder profile.
- `tx_code` remains enabled by default. A no-PIN wallet profile must opt out
  explicitly and use a pre-authorized-code TTL no longer than 300 seconds. The
  offer is bearer credential material until its single use, so operators must
  prevent disclosure and retain redemption rate limits.
- Source-free claims remain evaluation-only. OID4VCI issuance reloads the
  registry transaction and exact Relay-backed evaluation provenance before
  signer access.
- Status-bearing credentials are verified fail closed from the configured
  exact HTTPS status origin. The reserved top-level status claim cannot be
  selectively disclosable.
- External wallet, verifier, OIDF, EUDI, or HAIP evidence remains
  candidate-only until recorded against a frozen release artifact.
- Batch evaluation now has a fixed 100-member platform ceiling with lower
  operator limits and pre-side-effect `batch.too_large` rejection.
- Registry Notary publishes a generated Draft 2020-12 runtime configuration
  schema derived from the production deserialization graph.
- Maintained Notary runtime images now use Debian 13 distroless. Release checks
  enforce the expected base and vulnerability policy before publication.

## 0.11.0

- BREAKING: Direct and OID4VCI credential issuance now require a fresh,
  non-delegated stored evaluation with an exact compiler pin for every claim in
  each selected root's registry-backed dependency closure and one normalized
  record per unique Relay execution. Source-free and delegated claims are
  evaluation-only and cannot be configured for credential issuance. Existing
  evaluations remain readable and renderable but must be re-evaluated before
  issuance. See the
  [credential issuance trust-boundary migration](credential-issuance-migration.md).
- BREAKING: Configuration `${VAR}` expansion now rejects environment variables
  that are unset or empty. `${VAR:-fallback}` uses its fallback for either
  state, `${VAR:-}` explicitly expands to empty, and `${VAR:?message}` reports
  its message for either state. Whitespace-only values remain non-empty.
- Registry Notary now verifies the retained audit chain during activation and
  reports confirmed integrity failures as `audit.chain.inconsistent` on
  `/ready` without exposing audit contents. Stop the process and use
  `registry-notary audit quarantine` with the deployed configuration to retain
  the corrupt files and open a tamper-evident break segment. The single-writer
  lock prevents online recovery, and signed-bundle acceptance audit failures
  still prevent bundle persistence and serving.
- Presenting multiple primary credential channels now returns the generic
  `auth.multiple_credentials` failure before any candidate is parsed or
  validated. The result does not reveal whether either candidate was valid.
- Omitted claim `formats` now defaults to canonical claim-result JSON. Explicit
  empty, unknown, CCCEV-only, and SD-JWT evaluation-format lists fail
  configuration validation; SD-JWT remains a credential issuance format.
- Registry-backed Relay consultations may bind bounded string, boolean, and
  integer inputs from `request.target.attributes.<stable-name>`. These values
  remain caller-supplied request context and cannot satisfy authenticated
  target-identifier requirements for delegated subject access.
- The local registryctl Notary tutorial evaluates one registry-backed claim
  through an exact Relay compiler pin. It does not exercise issuance, a
  wallet, credential presentation, or OID4VCI interoperability.

## 0.10.0

- BREAKING: Notary now has one deployable correctness-state backend: typed,
  Notary-owned PostgreSQL configured under `state`. Redis and per-domain
  backend selectors are removed without compatibility aliases. Use explicit
  `in_memory` only for single-process local development.
- Operators install and verify the schema with `registry-notary state install`
  and `registry-notary state doctor`. Startup and readiness verify PostgreSQL
  version, writability, schema fingerprint, role boundaries, and fixed
  transaction functions before traffic is admitted.
- Replay, nonce, evaluation, idempotency, credential status, quota, and
  preauthorization decisions now survive restart and coordinate identical
  active-active instances. The operations guide covers PostgreSQL 16 through
  18, backup and restore, stale-restore quarantine, upgrades, and the clean
  pre-1.0 cutover.
- Redeemed pre-authorized codes use stable replay identity bound to the
  verified Notary issuer, so sensitive-state key rotation and unrelated
  service configuration changes cannot reopen a live no-PIN code.
- BREAKING: Registry-backed evidence now uses only authenticated,
  compiler-pinned Registry Relay consultations. Notary no longer accepts
  direct registry connections, DCI/FHIR connectors, source adapter sidecars,
  source credentials, or transitional evidence modes.
- Notary independently validates the full Relay consultation semantics and
  `contract_hash` before serving and at readiness. Mismatched purpose, inputs,
  outcomes, outputs, provenance, runtime requirements, or hash fail before
  source access.
- Relay consultation outcomes and typed outputs remain distinct from Notary
  claims. One consultation may supply several direct and CEL claims;
  `no_match` is explicit, while ambiguity and failures abort the consultation
  group and never become claim values.
- Relay-only, self-attested Notary-only, and combined project deployments are
  modeled separately. A combined project has one logical Relay connection and
  Notary receives no registry destination or source credential.
- BREAKING: authentication has no mode selector, and `auth.mode` is rejected.
  API keys and OIDC may coexist for distinct service and citizen or wallet
  callers, but each request presents exactly one credential type. Static
  bearer tokens and OIDC remain mutually exclusive because both use
  `Authorization: Bearer`.
- Combined projects keep the Relay's public catalog origin separate from the
  internal Notary connection URL. An explicitly enabled literal IP-loopback
  HTTP origin is allowed only for the paired Relay inside a shared network
  namespace; remote HTTP remains invalid and public origins still require
  HTTPS.
- Registry-backed claim rules now use `consultation_output` and
  `consultation_matched` with explicit `consultation` and `output` fields.
  The unreleased source-named rule forms are rejected without aliases.
- Claim provenance moves atomically to
  `registry-notary-claim-provenance/v2`, exposing only
  `relay_consultation_count`; audit records use the same terminology.
- Federation configuration and signed results use evaluation and claim-result
  terminology: configure `evaluation_scopes` and
  `max_claim_result_age_seconds`, and consume `claim_result_issued_at` plus
  `federation.stale_claim_result`. Federation profiles remain source-free in
  this version, and Relay-backed federation remains deferred pending
  cross-service audit correlation.
- Release distributions include the standalone Linux amd64
  `registry-notary-cel-worker`. CEL-enabled binary installations must place it
  beside `registry-notary` under that exact name. The Notary image includes the
  same isolated worker and `cel.worker_memory_bytes` remains the bounded
  operator control.
- The retired sidecar container, listener inventory, direct-source demo
  configurations, OpenFn caller demo, and direct DCI performance harness are
  removed.

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
