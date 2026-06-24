# Release Notes

## 0.7.0

- Added the `script_rhai` source-adapter engine with governed/runtime
  validation, bounded helper functions, batch-match coverage, and operator
  documentation.
- Added OID4VCI SD-JWT field projection so claim policies can disclose selected
  fields without widening the configured credential boundary.
- Adopted shared compliance context constraints for legal basis, consent,
  jurisdiction, assurance, and retention policy checks.
- Renamed the current source-adapter sidecar surfaces from the retired OpenFn
  sidecar naming to `source_adapter_sidecar`, including config connector values,
  batch mode values, Dockerfile naming, metrics, security inventories, and
  operator docs. Operators must update configs and monitoring that reference the
  old names.
- Removed the ignored source-adapter sidecar `--jobs-root` compatibility flag.
- Hardened source-adapter request-header validation, Rhai POST/OAuth target
  authentication, and OAuth token-refresh coalescing.
- Refreshed the Registry Platform pin to the beta-5 `0.3.3` release prep.

## 0.6.2

- Fixed federated evaluation policy-context handling so federation profiles can
  satisfy source matching gates for legal basis, consent, jurisdiction, and
  assurance without being treated as scoped transaction authorization details.
- Restores beta-4 lab delegated federation evaluations that use governed
  source-policy gates.

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
- Added governed config apply for signed TUF bundles, including
  `config verify-bundle`, `config apply-bundle`, and the `config_trust`
  operator block for trust roots, local approvals, and anti-rollback state.
  Governed signed apply can hot-apply signing-key rotations for the credential
  issuer, pre-authorized access-token, eSignet client-assertion, and federation
  response signing paths, and can clean up expired publish-only keys with the
  `signing_key_cleanup` change class; other changes remain restart-required.
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
  `hash_env`, so signed config apply can govern caller-credential rotation.
- Renamed OIDC config fields to the shared Registry service convention:
  `auth.oidc.jwks_uri` -> `auth.oidc.jwks_url`,
  `auth.oidc.leeway_seconds` -> `auth.oidc.leeway`, and
  `auth.oidc.allowed_typ` -> `auth.oidc.allowed_token_types`. Old names fail
  config load with an error naming the replacement. `auth.oidc.leeway` now uses
  humantime strings such as `30s`; self-attestation
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
  `https://docs.registry-notary.dev/problems/...`.
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
