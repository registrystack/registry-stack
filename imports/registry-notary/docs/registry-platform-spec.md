# Registry Platform Spec

## Purpose

Define a shared crate workspace, `registry-platform`, that hosts the security and operational primitives currently duplicated (or absent) across `registry-relay` and `registry-witness`. The May 2026 security pass landed the same fixes independently in both apps in some places, missed them entirely in others. A shared library forces the question "is this fixed everywhere?" to have a single answer.

This document was revised after three parallel staff-engineer reviews surfaced 10 blockers, 13 should-fix items, and 2 scope expansions: (1) witness gains relay's tamper-evident audit chain, (2) the lib expands to host JWK/DID/JCS primitives and a test-fixtures crate, since both are duplicated across the apps today. The third review tightened the SD-JWT issuer surface (`vct`, holder `cnf.kid`, signing `kid`), separated holder-proof replay-nonce semantics from credential-id semantics, removed `sub` from OIDC allowlist matching, gave `JwksFetcher` an explicit cache policy, locked the static-auth schema, and pinned `FetchUrlPolicy::dev` behaviour.

## Background

Two services, both fronting registry/evidence flows, both with overlapping primitives:

- **Outbound HTTP.** Both fetch from external sources, both added 1 MiB body caps and redirect-deny in May 2026 (`e5ba396` in witness, `2d7dfb6` in relay). Relay also has a `validate_fetch_url` policy that blocks RFC1918, link-local, IPv4-mapped loopback, and cloud-metadata targets; witness has only a partial DCI path-check.
- **`Authorization: Bearer` parsing.** Both made it case-insensitive in May 2026, in different files, with subtly different whitespace policies (witness accepts tab, relay's parser expects single SP).
- **VC issuance.** Both apps issue SD-JWT credentials (witness `sd_jwt.rs`, relay `provenance_issuance.rs` + `SoftwareSigner`). Witness's holder-proof validator binds `sub` + `evaluation_id` + `credential_profile` + `disclosure` + `claims` + `jti`; relay's issuance path has weaker discipline.
- **Audit logging.** Relay has ~2000 lines of audit machinery including a tamper-evident `prev_hash`/`record_hash` chain (`audit/chain.rs`) and an async `AuditSink::write(AuditEnvelope)` trait. Witness has a sync JSONL sink only, no chaining.
- **OIDC.** Relay has full discovery + JWKS + verifier with ~995 LoC of policy (algorithm allowlist, `typ` allowlist, scope mapping, `allowed_clients` matched against `azp` preferred over `client_id`); witness has none.
- **API keys at rest.** Relay and witness store SHA-256 fingerprints via `hash_env`; witness upstream source connections still load outbound source tokens from `token_env`.
- **JWK types.** Both define their own `PrivateJwk` / `PublicJwk` (witness `sd_jwt.rs`, relay `software.rs` + `auth/oidc/jwks.rs`). Two parallel implementations of the same shape.
- **DID validation.** Both consume DIDs. Witness validates DID methods at config load (`4aa4746`); relay has `provenance/did_web.rs` and `api/did.rs` with its own DID handling. Parallel implementations.
- **JSON canonicalization.** Both need byte-equal payloads for crypto. No shared canonicalizer.
- **Test fixtures.** Both apps need mock OIDC IdPs and mock HTTP upstreams. Witness uses `wiremock` ad-hoc; relay has its own fixtures. No shared harness.
- **Workspace hygiene.** Witness is missing `clippy.toml` and `rustfmt.toml`; relay has both. Lint/format rules have already drifted.

Independent rediscovery and selective application are both symptoms of having no shared dependency.

## Goals

- Single source of truth for HTTP outbound posture, URL SSRF policy, Bearer parsing, OIDC token verification, CORS/CSP/CORP middleware, inbound body limits, RFC 7807 Problem Details, HMAC audit-key hashing, tamper-evident audit chaining, SD-JWT issuance, JWK types, DID method validation, JCS canonicalization, and shared test fixtures.
- Single source of truth for the principles those primitives encode (`docs/SECURITY_PRINCIPLES.md` in the platform repo).
- Both consumer apps end the migration at **functional parity on the shared surface**. Witness gains: OIDC, hashed API keys, `/admin/reload`, `/healthz` + `/ready`, CORS/CSP, audit HMAC, tamper-evident audit chain, inbound body limit, RFC 7807 errors. Relay gains: SD-JWT issuance discipline (holder-proof binding, `_sd` digest sort, `jti` parity).
- Single set of workspace-hygiene files (clippy, rustfmt, deny) shared between consumers via canonical templates in the platform repo, verified by CI.
- Future security fixes land in one PR, propagate via a coordinated tag bump.

## Non-Goals

- Backward compatibility. Per operator direction, no app is in production; a big-bang migration is acceptable.
- Sharing domain types (`EvidencePrincipal`, `ResolvedCredential`, `EvidenceAuditEvent`). The lib hosts primitives; apps keep their own domain models and config schemas.
- Sharing axum extractors or HTTP handlers. The lib provides building blocks; routing stays in apps.
- Sharing source-fetcher modules (DCI / registry-data-api in witness, dataset loaders in relay). Too domain-specific.
- Pulling CEL evaluation guards into the lib. Only witness uses CEL today.
- Per-principal rate limiting / token-bucket (`EvidenceVerificationLimiter` in relay). Single-consumer surface; revisit when a second consumer needs it.
- Telemetry conventions (structured-log field names, request-ID propagation rules). Defer to v0.2.0; v0.1.0 documents the convention in `SECURITY_PRINCIPLES.md` but does not ship a crate.

## Repo Layout

Follows the `registry-manifest` precedent: new repo, sibling to consumers under `apps/`, consumed via git tag.

```
apps/registry-platform/                       (workspace root)
  Cargo.toml                                  workspace + workspace.dependencies
  CHANGELOG.md
  LICENSE                                     Apache-2.0
  README.md
  rustfmt.toml                                canonical (also used by lib itself)
  clippy.toml                                 canonical
  deny.toml                                   canonical
  rust-toolchain.toml                         MSRV pin
  .github/workflows/ci.yml
  docs/
    SECURITY_PRINCIPLES.md                    house rules
    versioning.md                             tag cadence, semver policy
    config-drift-inventory.md                 every config file that breaks during big-bang
  templates/                                  canonical workspace-hygiene files
    clippy.toml
    rustfmt.toml
    deny.toml
  scripts/
    check-hygiene-alignment.sh                consumers run this in CI
    audit-configs.sh                          enumerates consumer config files for the drift inventory
  crates/
    registry-platform-httputil/
    registry-platform-authcommon/
    registry-platform-audit/
    registry-platform-oidc/
    registry-platform-httpsec/
    registry-platform-sdjwt/
    registry-platform-crypto/                 new: JWK + DID + JCS
    registry-platform-testing/                new: mock IdP + mock HTTP upstream (dev-dep)
```

GitHub: `github.com/jeremi/registry-platform`. Tag scheme: `vMAJOR.MINOR.PATCH`. Initial release: `v0.1.0`.

## Crate Inventory

Eight crates, each with a narrow purpose. Public API sketches are illustrative; final signatures land during scaffold but the **shapes below are load-bearing** (closures vs structs, sync vs async, owned vs borrowed) and were chosen to survive reviewer scrutiny.

### `registry-platform-httputil`

**Purpose.** Outbound HTTP client builder, bounded-body reader, URL builder helpers, and **SSRF URL policy validator**. The smallest surface that closes the outbound-HTTP attack surface end-to-end.

**Public API.**

```rust
pub struct OutboundClientBuilder { /* timeout, redirect_policy, user_agent, ... */ }
impl OutboundClientBuilder {
    pub fn new() -> Self;                    // defaults: 30s timeout, no redirects, no proxies
    pub fn timeout(self, d: Duration) -> Self;
    pub fn user_agent(self, ua: &str) -> Self;
    pub fn build(self) -> reqwest::Client;
}

pub async fn read_bounded(resp: reqwest::Response, max_bytes: u64) -> Result<Vec<u8>, BoundedReadError>;

pub mod url {
    pub fn append_path_segments(base: &reqwest::Url, segments: &[&str]) -> Result<reqwest::Url, UrlError>;
}

pub struct FetchUrlPolicy {
    pub allowed_schemes: Vec<String>,
    pub allow_localhost: bool,
    pub deny_private_ranges: bool,
    pub deny_cloud_metadata: bool,
}
impl FetchUrlPolicy {
    /// Production default: `["https"]`, no localhost, deny RFC1918 +
    /// link-local + IPv4-mapped loopback + 169.254.169.254 / fd00:ec2::254.
    pub fn strict() -> Self;
    /// Development preset: `["http", "https"]`, `allow_localhost = true`
    /// (literal `127.0.0.0/8`, `::1`, host `localhost`), still denies
    /// non-loopback private ranges and cloud metadata. Plain `http://` is
    /// only permitted when the host resolves to a loopback address.
    pub fn dev() -> Self;
    /// `deny_private_ranges` operates on IP literals in the URL host *and*
    /// on the resolved A/AAAA records of DNS hostnames (rebinding-safe).
    /// `validate` performs the DNS lookup itself; callers must not bypass
    /// it by feeding a pre-resolved socket address to the HTTP client.
    pub fn validate(&self, url: &reqwest::Url) -> Result<(), FetchUrlError>;
}
```

**Replaces.** Witness `standalone.rs` HTTP client + `read_source_json` body cap + DCI path checks. Relay `auth/oidc/fetcher.rs` HTTP client + size-capped decode + loopback allowlist (F1 in `3dde7bf`).

**Deps.** `reqwest` (rustls), `url`, `thiserror`, `ipnet`.

### `registry-platform-authcommon`

**Purpose.** Auth primitives that don't depend on a specific identity provider. **No Argon2.**

**Public API.**

```rust
pub fn parse_bearer_token(header: &str) -> Result<&str, BearerParseError>;
// RFC 6750 §2.1: case-insensitive scheme, single-SP separator, no extras.

pub fn fingerprint_api_key(plaintext: &str) -> String;        // "sha256:<64 hex>"
pub fn verify_api_key(plaintext: &str, fingerprint: &str) -> Result<bool, FingerprintFormatError>;
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32], FingerprintFormatError>;

pub const MIN_API_KEY_ENTROPY_BYTES: usize = 32;  // 256 bits
pub fn validate_api_key_entropy(plaintext: &str) -> Result<(), EntropyError>;
```

**Replaces.** Witness `standalone.rs::bearer_auth_token`. Relay `auth/api_key.rs::{token_fingerprint, parse_token_fingerprint}`.

**Deps.** `sha2`, `subtle`, `zeroize`.

### `registry-platform-audit`

**Purpose.** Tamper-evident audit envelopes with `prev_hash` / `record_hash` chaining, async sinks, and HMAC primary-key redaction.

**Public API.**

```rust
pub struct AuditEnvelope {
    pub envelope_id: String,                 // ULID
    pub timestamp_unix_ms: i64,
    pub prev_hash: Option<[u8; 32]>,
    pub record: serde_json::Value,
    pub record_hash: [u8; 32],
}

pub struct ChainState { /* Mutex<Option<[u8; 32]>> */ }
impl ChainState {
    pub fn new() -> Self;
    pub async fn bootstrap(sink: &dyn AuditSink) -> Result<Self, AuditError>;
    pub async fn append<T: serde::Serialize>(&self, sink: &dyn AuditSink, record: T) -> Result<AuditEnvelope, AuditError>;
}

#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError>;
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError>;
}

pub struct JsonlFileSink { /* path, rotation, async mutex */ }
pub struct JsonlStdoutSink;
pub struct SyslogSink { /* unix domain, RFC 5424 */ }

pub struct AuditHashSecret(std::sync::Arc<[u8]>);
pub enum AuditKeyHasher {
    Keyed(AuditHashSecret),
    UnkeyedDevOnly,
}
impl AuditKeyHasher {
    pub fn from_env(env_var_name: &str) -> Result<Self, AuditError>;
    pub fn unkeyed_dev_only() -> Self;
    pub fn hash(&self, raw: &str) -> String;
}

pub mod redact {
    pub fn email(s: &str) -> String;
    pub fn phone(s: &str) -> String;
    pub struct QueryRedactor { /* ... */ }
}
```

**Replaces.** Witness `standalone.rs::AuditSink`. Relay `audit/{mod,chain,redact,file,syslog,stdout}.rs` entirely.

**Why `serde_json::Value` in the envelope?** `serde::Serialize` is not object-safe, so `&dyn AuditEvent` cannot be passed to a serializer. The chain serializes the record to `Value` before envelope construction; sinks then serialize the whole envelope. Sidesteps object-safety while letting consumers keep typed event structs.

**Deps.** `hmac`, `sha2`, `subtle`, `zeroize`, `serde`, `serde_json`, `async-trait`, `tokio`, `ulid`.

### `registry-platform-oidc`

**Purpose.** OIDC discovery, JWKS fetch, and **full token verification with policy**.

**Public API.**

```rust
pub struct OidcDiscoveryConfig {
    pub issuer: String,
    pub jwks_uri_override: Option<String>,
    pub discovery_timeout: Duration,
    pub max_doc_bytes: u64,
}

pub struct DiscoveryDocument { /* issuer, jwks_uri, ... */ }
pub async fn fetch_discovery(cfg: &OidcDiscoveryConfig) -> Result<DiscoveryDocument, OidcError>;

pub struct JwksFetcherConfig {
    pub cache_ttl: Duration,                 // default 600s; keys served from cache until expired
    pub negative_cache_ttl: Duration,        // default 60s; how long to remember "kid not found"
    pub refresh_cooldown: Duration,          // default 30s; min interval between forced refreshes on unknown-kid
    pub max_doc_bytes: u64,                  // default 1 MiB
    pub request_timeout: Duration,           // default 5s
}
impl JwksFetcherConfig {
    pub fn defaults() -> Self;
}

pub struct JwksFetcher { /* DCL cache, refresh cooldown, byte cap */ }
impl JwksFetcher {
    pub fn new(jwks_uri: String, client: reqwest::Client, config: JwksFetcherConfig) -> Self;
    pub async fn key_for_kid(&self, kid: &str) -> Result<jsonwebtoken::DecodingKey, OidcError>;
}

pub struct TokenVerifierConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub allowed_algorithms: Vec<jsonwebtoken::Algorithm>,
    pub allowed_typ: Vec<String>,
    pub scope_claim: String,
    pub scope_separator: char,
    pub scope_map: Option<std::collections::HashMap<String, Vec<String>>>,
    pub allowed_clients: Vec<String>,
    pub leeway: Duration,
}

pub struct VerifiedToken {
    pub claims: Claims,
    pub matched_client: Option<String>,
    pub scopes: Vec<String>,
}

pub struct TokenVerifier { /* config + fetcher */ }
impl TokenVerifier {
    pub fn new(config: TokenVerifierConfig, fetcher: std::sync::Arc<JwksFetcher>) -> Self;
    pub async fn verify(&self, token: &str) -> Result<VerifiedToken, OidcError>;
}
```

**`allowed_clients` semantics.** The allowlist is matched against `azp` if the token
carries it; otherwise against `client_id`. The `sub` claim is **never** consulted for
allowlist matching. `matched_client` on `VerifiedToken` records which claim was used
(`Some("azp:...")` or `Some("client_id:...")`); it is `None` only when the allowlist
is empty (any-client mode).

Consumers map `VerifiedToken` to their own `Principal` after `verify()` returns.
Principal derivation from `sub` (or any other claim) is a consumer concern; it does
not influence the platform's authentication decision.

**Replaces.** Relay `auth/oidc/{fetcher,jwks,mod,provider}.rs`. ~1100 lines collapsed into one crate.

**Deps.** `jsonwebtoken`, `serde`, `tokio`, `async-trait`, `registry-platform-httputil`, `registry-platform-crypto`.

### `registry-platform-httpsec`

**Purpose.** Tower middleware for browser-reachable HTTP, **inbound body limit, and RFC 7807 Problem Details**.

**Public API.**

```rust
pub struct CorsPolicy { /* ... */ }
impl CorsPolicy {
    pub fn validate(&self) -> Result<(), CorsValidationError>;
    pub fn layer(&self) -> tower_http::cors::CorsLayer;
}

pub struct CspBuilder { /* ... */ }
impl CspBuilder {
    pub fn restrictive() -> Self;
    pub fn header_value(&self) -> http::HeaderValue;
}

pub fn corp_conditional<S>() -> impl tower::Layer<S, Service = impl tower::Service<...>> + Clone;
pub fn security_headers<S>(csp: CspBuilder) -> impl tower::Layer<S, Service = impl tower::Service<...>> + Clone;
pub fn request_body_limit<S>(max_bytes: usize) -> tower_http::limit::RequestBodyLimitLayer;

pub mod problem {
    pub struct Problem {
        pub type_uri: String,
        pub title: String,
        pub status: http::StatusCode,
        pub detail: Option<String>,
        pub instance: Option<String>,
        pub extra: std::collections::BTreeMap<String, serde_json::Value>,
    }
    impl Problem {
        pub fn new(type_uri: &str, title: &str, status: http::StatusCode) -> Self;
        pub fn into_response(self) -> axum::response::Response;
    }
}
```

**Replaces.** Relay `src/server.rs` middleware + RFC 7807 helpers used at 26+ sites.

**Deps.** `tower`, `tower-http`, `axum`, `http`, `serde`, `serde_json`.

### `registry-platform-sdjwt`

**Purpose.** SD-JWT issuance + holder-proof verification helpers.

**Public API.**

```rust
pub struct SdJwtIssuer { /* signer wrapper; manual Debug omits keys */ }
impl SdJwtIssuer {
    pub fn from_jwk(jwk: registry_platform_crypto::PrivateJwk) -> Result<Self, SdJwtError>;
    pub fn issue(&self, input: SdJwtIssuanceInput) -> Result<SignedSdJwt, SdJwtError>;
}

pub struct HolderConfirmation {
    pub jwk: registry_platform_crypto::PublicJwk,    // becomes `cnf.jwk`
    pub kid: Option<String>,                         // becomes `cnf.kid` when set
}

pub struct SdJwtIssuanceInput {
    pub iss: String,
    pub sub_ref: String,
    pub iat: i64,
    pub exp: i64,
    pub vct: String,                          // SD-JWT VC type URI (required)
    pub signing_kid: String,                  // becomes JWS header `kid` (required)
    pub cnf: Option<HolderConfirmation>,      // holder binding; None for unbound credentials
    pub disclosures: Vec<Disclosure>,
}

pub struct SignedSdJwt {
    pub credential_id: String,
    pub jti: String,                         // == credential_id
    pub jwt: String,
}

pub fn sort_sd_digests(digests: &mut Vec<String>);

pub struct HolderProofPolicy {
    pub audience: String,
    pub max_lifetime: Duration,              // default 300s
}

pub struct HolderProofBindings<'a> {
    pub expected_sub: &'a str,
    pub evaluation_id: &'a str,
    pub credential_profile: &'a str,
    pub disclosure_hash: &'a [u8],
    pub claim_set: &'a [String],
}

pub struct HolderProofClaims {
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,           // opaque holder-chosen replay nonce; NOT the credential id
    pub raw: serde_json::Value,
}

// Validates JWS signature, audience, lifetime (exp > iat, exp - iat <= max_lifetime),
// and every binding in `HolderProofBindings`. Returns the parsed claims so the caller
// can use `claims.jti` to build a replay-detection key (e.g. by hashing it with the
// holder sub or credential id). The function itself does NOT enforce uniqueness of
// the jti; replay detection is a caller concern, intentionally kept out of the
// platform crate because it requires consumer-owned state.
pub fn validate_holder_proof(
    proof_jwt: &str,
    holder_jwk: &registry_platform_crypto::PublicJwk,
    bindings: &HolderProofBindings,
    policy: &HolderProofPolicy,
    now: i64,
) -> Result<HolderProofClaims, SdJwtError>;
```

**Replaces.** Witness `sd_jwt.rs` issuance + zeroize + `_sd` sort + JTI parity, `api.rs::validate_holder_proof_payload`.

**Reverse-ports to relay.** Relay `provenance_issuance.rs` + `SoftwareSigner` consume this.

**Deps.** `jsonwebtoken`, `ed25519-dalek`, `sha2`, `serde`, `registry-platform-crypto`.

### `registry-platform-crypto`

**Purpose.** JWK types, DID method validation, JCS canonicalization, and fail-closed signature helpers. Foundation crate consumed by `oidc` and `sdjwt`.

**Public API.**

```rust
// JWK types. Debug redacts private fields; Drop zeroizes.
pub struct PrivateJwk { /* kty, kid, alg, d, x, ... */ }
impl Drop for PrivateJwk { /* zeroize d */ }

pub struct PublicJwk { /* kty, kid, alg, x, ... */ }

pub enum SigningAlgorithm { EdDsa }

impl PrivateJwk {
    pub fn parse(json: &str) -> Result<Self, JwkError>;
    pub fn public(&self) -> PublicJwk;
    pub fn algorithm(&self) -> Result<SigningAlgorithm, JwkError>;
}

impl PublicJwk {
    pub fn parse(json: &str) -> Result<Self, JwkError>;
    pub fn jkt(&self) -> String;             // RFC 7638 JWK thumbprint
}

// DID validation.
pub enum DidMethod { Web, Key }

pub struct ValidatedDid {
    pub method: DidMethod,
    pub identifier: String,
    pub fragment: Option<String>,
}

pub fn validate_did(s: &str, allowed_methods: &[DidMethod]) -> Result<ValidatedDid, DidError>;
pub fn validate_did_web(s: &str) -> Result<(), DidError>;
// Enforces hostname (no IPs, no localhost, no metadata-target embeddings),
// rejects path traversal, optional pattern allowlist.

// JCS (RFC 8785). Stable byte representation for crypto-bound payloads.
pub fn canonicalize_json(value: &serde_json::Value) -> Result<Vec<u8>, JcsError>;

// Signature helpers. v0.1.0 supports EdDSA/Ed25519 only; unsupported algorithms return an error.
pub fn sign(payload: &[u8], jwk: &PrivateJwk) -> Result<Vec<u8>, CryptoError>;
pub fn verify(payload: &[u8], signature: &[u8], jwk: &PublicJwk) -> Result<(), CryptoError>;
```

**Algorithm scope.** `v0.1.0` intentionally supports EdDSA/Ed25519 only. ES256, RS256, PS256, and other JWK algorithms must fail closed with `UnsupportedAlgorithm` until a production consumer needs them.

**Replaces.** Witness `sd_jwt.rs` JWK types. Relay `provenance/signers/software.rs` JWK parsing + `auth/oidc/jwks.rs` JWK types + `api/did.rs` + `provenance/did_web.rs` DID handling. Witness `config.rs` DID-method validation (`4aa4746`).

**Deps.** `serde`, `serde_json`, `ed25519-dalek`, `sha2`, `subtle`, `zeroize`, `base64`, `url`.

### `registry-platform-testing`

**Purpose.** Test fixtures, mock servers, and assertions for downstream consumers. **Dev-dep only.**

**Public API.**

```rust
pub struct MockIdp { /* axum app on random port; signs tokens with embedded JWK */ }
impl MockIdp {
    pub async fn start() -> Self;
    pub fn issuer(&self) -> String;
    pub fn discovery_url(&self) -> String;
    pub fn jwks_uri(&self) -> String;
    pub fn mint_token(&self, claims: serde_json::Value) -> String;
    pub fn rotate_key(&self);
    pub async fn stop(self);
}

pub struct MockHttpUpstream { /* wiremock wrapper with body-size tracking */ }
impl MockHttpUpstream {
    pub async fn start() -> Self;
    pub fn url(&self) -> String;
    pub fn expect(&self, method: &str, path: &str) -> MockExpectation;
    pub fn assert_max_request_bytes(&self, n: u64);
}

pub mod fixtures {
    pub fn ed25519_pair() -> (registry_platform_crypto::PrivateJwk, registry_platform_crypto::PublicJwk);
}

pub fn assert_chain_integrity(envelopes: &[registry_platform_audit::AuditEnvelope]) -> Result<(), ChainAssertionError>;
```

**Replaces.** Ad-hoc test fixtures in both apps. Both consumers add as `dev-dependencies`, not runtime deps.

**Deps.** `axum`, `tokio`, `wiremock`, `registry-platform-crypto`, `registry-platform-audit`, `registry-platform-oidc`.

## Witness Gap-Fill (Capabilities Added in the Big Bang)

Beyond consuming the lib, witness gains the following operator-facing capabilities during the migration PR.

1. **OIDC auth mode** alongside the existing static-credential mode. `auth.mode = "oidc" | "api_key"`. Uses `TokenVerifier`.
2. **Hashed API keys at rest.** Replace `auth.api_keys[].token_env` and `auth.bearer_tokens[].token_env` with `*.hash_env` (env var holding the `sha256:<64 hex>` fingerprint). Uses `fingerprint_api_key`. **No backward compat path.** Witness keeps the two lists distinct (`api_keys[]` for admin scopes, `bearer_tokens[]` for evidence submitter scopes) rather than collapsing into relay's single `api_keys[]` shape: they map to different principal kinds in witness, and merging would force every entry to carry a `kind` discriminator without saving config surface. Both lists share the same `{name, hash_env, scopes}` shape and the same fingerprint verifier from `authcommon`.
3. **`POST /admin/reload` endpoint** behind an admin scope. 401/403 before reaching handler.
4. **`/healthz` and `/ready` endpoints.** `/ready` 503 body uses opaque counters, never names datasets / connections / evaluations.
5. **CORS + CSP + CORP middleware** on the `/openapi.json` + docs surface. Uses `registry-platform-httpsec`.
6. **Tamper-evident audit chain.** `EvidenceAuditEvent` becomes the record body of `AuditEnvelope`; `ChainState` bootstraps from sink tail on startup.
7. **HMAC-keyed audit primary-key hashing.** `audit.hash_secret_env` config field. PII-bearing identifiers in audit events hashed before envelope construction.
8. **Inbound request body limit.** 1 MiB default via `request_body_limit`.
9. **RFC 7807 Problem Details** for all error responses (replaces ad-hoc shapes in `api.rs`).

### Refactors During Migration (not new capabilities)

- Witness's existing JWK types in `sd_jwt.rs` replaced by `registry-platform-crypto::{PrivateJwk, PublicJwk}`.
- Witness's existing DID-method validation in `config.rs` replaced by `validate_did`.
- Witness adopts canonical `clippy.toml` and `rustfmt.toml` from `registry-platform/templates/`.
- Witness test fixtures consolidated onto `registry-platform-testing::MockIdp` and `MockHttpUpstream`.

## Relay Reverse-Port (Fixes Replayed from Witness)

1. **Holder-proof binding context.** Use `validate_holder_proof` with full `HolderProofBindings`. `exp > iat`, `exp - iat <= 300s`, dynamic `aud`.
2. **`_sd` digest array sorting** for deterministic re-issuance.
3. **`jti == credential_id` parity** guaranteed by `SdJwtIssuer::issue`.
4. **Credential profile bypass audit.** Audit `provenance_issuance.rs` for the "caller chooses profile" pattern witness's `43096ae` closed. Port the fix if present.

### Refactors During Migration

- Relay's existing JWK types in `software.rs` and `auth/oidc/jwks.rs` replaced by `registry-platform-crypto`.
- Relay's DID handling (`api/did.rs`, `provenance/did_web.rs`) consolidated on `registry-platform-crypto::validate_did_web`.
- Relay verifies its existing `clippy.toml` / `rustfmt.toml` / `deny.toml` match the canonical templates; any drift is resolved in the migration PR.

## `SECURITY_PRINCIPLES.md` Outline

1. **Fail-closed defaults.** Empty allow-lists deny everything. `AuditKeyHasher::from_env` returns `Result`; no silent fallback.
2. **Debug-redact secrets.** Manual `Debug` for any struct holding key material or tokens.
3. **Zeroize in-memory key material.** `PrivateJwk` zeroizes on drop. Exception: `AuditHashSecret` is `Arc<[u8]>` with documented rationale.
4. **Size-cap untrusted I/O.** All inbound + outbound bodies have explicit byte caps.
5. **Deterministic crypto payloads.** Sort sets; JCS-canonicalize where byte equality matters; issuer-generated `id` / `jti` / `sub_ref`.
6. **Deny outbound redirects.** Validate URLs against `FetchUrlPolicy` before every fetch.
7. **Percent-encode URL inputs.** Never string-concatenate; use `url::append_path_segments`.
8. **Bounded crypto/eval workers.** Long-running CPU work runs on `spawn_blocking` with a wall-clock timeout.
9. **Tamper-evident audit.** Every security-relevant event lands in a chained envelope.
10. **Canonical workspace hygiene.** `clippy.toml`, `rustfmt.toml`, `deny.toml` come from `registry-platform/templates/`; CI fails on drift.

## Sequencing

Big-bang, three concurrent tracks once the lib lands. Each track has a sharp DoD; nothing is "done" until every bullet is green.

### Track 0: Stand up `registry-platform v0.1.0` (week 1-2)

**Scope.**
- Create the repo, scaffold the workspace, port all eight crates from existing relay + witness code.
- Lock the `TokenVerifier` shape by porting relay's `auth/oidc/provider.rs` verbatim, then refactoring to the new struct.
- Lock the audit envelope + chain types by porting relay's `audit/{mod,chain}.rs`.
- Lock the JWK/DID/JCS shape via `registry-platform-crypto`.
- Land canonical `templates/{clippy,rustfmt,deny}.toml`, `scripts/check-hygiene-alignment.sh`, `scripts/audit-configs.sh`.
- Land `docs/{SECURITY_PRINCIPLES,versioning,config-drift-inventory}.md`.

**Definition of Done.** All of the following green:
- `cargo build --workspace --all-targets --all-features`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo deny check` (advisories, bans, licenses, sources)
- `cargo test --workspace --all-features`, including property tests on parsers/validators
- Per-crate line coverage >= 80% via `cargo llvm-cov`
- Cross-crate integration test green: sample axum app wires every middleware/layer; `TokenVerifier` resolves a token from `MockIdp`; audit chain bootstrap + append + tamper-detect passes
- Named library tests pass for the third-review fixes:
  - `sd_jwt_issuance_writes_vct_cnf_jwk_cnf_kid_and_header_kid`
  - `sd_jwt_issuance_omits_cnf_when_unbound`
  - `holder_proof_returns_jti_for_caller_replay_detection`
  - `holder_proof_rejects_when_credential_id_substituted_for_proof_jti`
  - `oidc_allowed_clients_matches_azp_then_client_id_never_sub`
  - `jwks_fetcher_caches_keys_until_ttl`
  - `jwks_fetcher_force_refresh_is_rate_limited_by_cooldown`
  - `jwks_fetcher_negative_cache_remembers_unknown_kid`
  - `fetch_url_policy_dev_allows_http_only_for_loopback_hosts`
  - `fetch_url_policy_blocks_dns_rebinding_to_private_range`
- `TokenVerifier`, `AuditEnvelope`/`ChainState`, and crypto API shapes ratified by a second-pair review
- `rust-toolchain.toml` MSRV pin merged
- Git tag `v0.1.0` pushed

### Track 1: Relay migration (week 2-3, parallel with Track 2)

**Scope.**
- Replace relay's `auth/oidc/`, `auth/api_key.rs`, `audit/`, JWK types, DID handling, HTTP client construction, and middleware with platform-crate consumption.
- Add SD-JWT reverse-port fixes via `SdJwtIssuer` and `validate_holder_proof`.
- Audit `provenance_issuance.rs` for credential-profile bypass; port witness's fix if present.

**Definition of Done.** All of the following green:
- Relay `Cargo.toml` pins `registry-platform = { git = "https://github.com/jeremi/registry-platform", tag = "v0.1.0" }`
- `git grep` of relay shows zero matches for: `auth/oidc/{fetcher,jwks,mod,provider}.rs` file presence, `auth/api_key.rs::token_fingerprint`, `audit/{chain,redact,file,syslog,stdout}.rs` file presence, manual `reqwest::ClientBuilder` calls outside the lib, hand-rolled RFC 7807 helpers, in-tree `PrivateJwk` / `PublicJwk` definitions, in-tree DID validation in `api/did.rs` / `provenance/did_web.rs`
- All existing relay unit + integration + perf-smoke tests pass
- New tests assert: holder proof `exp > iat`, `exp - iat <= 300s`, `aud == service_id`, full `HolderProofBindings` enforcement
- Credential-profile bypass audit: either documented as "not present" or fix landed with regression test
- Relay's `clippy.toml`, `rustfmt.toml`, `deny.toml` match `registry-platform/templates/*` byte-for-byte (verified by `check-hygiene-alignment.sh`)
- New entry in `docs/security-reviews/security-review-2026-XX-XX.md` describes the platform migration

### Track 2: Witness migration + gap-fill (week 2-4, parallel with Track 1)

**Scope.**
- Consume the lib for HTTP, Bearer, SD-JWT, audit, JWK, DID primitives.
- Add all 9 gap-fill capabilities.
- Update witness config schema; update every fixture per `config-drift-inventory.md`.
- Adopt canonical workspace-hygiene files.

**Definition of Done.** All of the following green:
- Witness `Cargo.toml` pins `registry-platform = { git = "...", tag = "v0.1.0" }`
- One named test per gap-fill item passes:
  - `oidc_mode_verifies_token_from_fixture_idp`
  - `api_key_plaintext_is_never_loaded_only_fingerprint`
  - `admin_reload_401_unauth_403_wrong_scope_200_admin`
  - `healthz_ready_opaque_counters_in_503_body`
  - `cors_csp_corp_headers_present_and_corp_conditional`
  - `audit_chain_bootstraps_from_sink_tail`
  - `audit_chain_detects_inserted_envelope`
  - `audit_hasher_from_env_returns_err_when_unset`
  - `request_body_limit_returns_413_above_threshold`
  - `error_responses_match_rfc_7807_shape`
- `git grep` of witness shows zero matches for: hand-rolled bearer parser, plaintext API key compare, sync `AuditSink`, in-tree `PrivateJwk` / `PublicJwk` definitions, in-tree DID-method validation
- `config-drift-inventory.md` checklist fully ticked: demo configs, perf configs, every fixture under `crates/registry-witness-server/tests/` updated atomically
- Witness `clippy.toml`, `rustfmt.toml`, `deny.toml` exist and match templates (new files, since witness lacks them today)
- New `docs/security-reviews/security-review-2026-XX-XX.md` exists with the migration entry
- Witness test fixtures use `registry-platform-testing::{MockIdp, MockHttpUpstream}`; no remaining ad-hoc `wiremock` setups outside that dep

### Cross-Track DoD (the whole effort is "done")

- CI alignment check green in both consumer repos: pinned `registry-platform` tag matches
- Interop smoke test: if witness and relay interoperate at the VC layer, a credential issued by one verifies via the other through `validate_holder_proof`. (Track 0 confirms whether this test is in scope; if the two apps don't interoperate today, this DoD item is dropped explicitly.)
- Each consumer PR description cites the principle from `SECURITY_PRINCIPLES.md` that motivates each gap-fill / reverse-port item

## Config Schema Drift Inventory (Track 0 Deliverable)

`apps/registry-platform/docs/config-drift-inventory.md` lists every config file across both apps that breaks during the big-bang:

- **Witness field renames.** `auth.api_keys[].token_env` → `hash_env`; `auth.bearer_tokens[].token_env` → `hash_env`; new `audit.hash_secret_env`; new `auth.mode`; new `admin` block.
- **Witness fixtures.** Every file under `apps/registry-witness/crates/registry-witness-server/tests/`, `apps/registry-witness/demo/config/`, `apps/registry-witness/perf/config/`.
- **Relay.** No schema renames expected; the OIDC verifier moves from internal type to lib type, so test fixtures that construct verifiers directly need updating.

The inventory is generated by `scripts/audit-configs.sh`, not free-form.

## Versioning Policy

Pre-1.0: MINOR bumps are potentially breaking, PATCH compatible. Tag the workspace at `vX.Y.Z`; consumers pin to the tag, not individual crate versions. After v1.0, standard semver per crate.

Consumers verify alignment via a CI check: both `Cargo.toml` files reference the same `registry-platform` tag. Drift fails CI.

## Testing Strategy

- **Per-crate unit tests** with parity to the original implementations.
- **Property tests** for parsers and validators: `parse_bearer_token`, `append_path_segments`, `parse_fingerprint`, `FetchUrlPolicy::validate`, `validate_did`, JCS canonicalization round-trip.
- **Cross-crate integration test** in `registry-platform/tests/`: sample axum app wiring every middleware/layer with `MockIdp`-backed OIDC.
- **Chain-integrity test**: write N envelopes, mutate one, verify detection via `assert_chain_integrity`.
- **Consumer migration tests**: each app's existing test suite must pass on the lib without semantics drift.

## Decisions Locked In

- Repo: new GitHub repo, `jeremi/registry-platform`. Same pattern as `registry-manifest`.
- **Eight crates** (was six), granular, no meta-crate. New: `crypto` (JWK + DID + JCS) and `testing` (dev-dep mock IdP / mock HTTP).
- No backward-compatibility shims. Big-bang migration. Config schemas change in both apps.
- OIDC ships as a `TokenVerifier` struct owning the full verification policy. Consumers map `VerifiedToken` to their Principal after `verify()`. `allowed_clients` matches `azp` preferred over `client_id`; `sub` is never consulted for the allowlist (principal derivation from `sub` is a consumer concern).
- `JwksFetcherConfig` exposes `cache_ttl` (default 600s), `negative_cache_ttl` (60s), `refresh_cooldown` (30s), `max_doc_bytes` (1 MiB), `request_timeout` (5s). Forced refresh on unknown-kid is rate-limited by `refresh_cooldown`.
- Static-auth schema: witness keeps `auth.api_keys[]` and `auth.bearer_tokens[]` distinct (different principal kinds). Both adopt `hash_env` and use `authcommon::verify_api_key`.
- `FetchUrlPolicy::dev()` permits plain `http://` only for hosts resolving to loopback addresses; `deny_private_ranges` enforcement covers both URL-literal IPs and resolved DNS A/AAAA records (rebinding-safe).
- Audit chain (`AuditEnvelope`, `ChainState`, `AuditSink`) lives in `registry-platform-audit`. Both apps consume it.
- Audit HMAC fails closed: `AuditKeyHasher::from_env` returns `Result`; unkeyed mode requires explicit `unkeyed_dev_only()`.
- SD-JWT issuer guarantees `jti == credential_id` as an internal invariant.
- Holder-proof validator accepts full `HolderProofBindings`.
- `FetchUrlPolicy` lives in `httputil`.
- Bearer parser pinned to RFC 6750 §2.1.
- No Argon2 in v0.1.0.
- Problem Details folded into `httpsec`.
- JWK + DID + JCS live in `registry-platform-crypto`; `oidc` and `sdjwt` depend on it.
- Mock IdP + mock HTTP upstream live in `registry-platform-testing` as dev-dep only.
- Canonical `clippy.toml` / `rustfmt.toml` / `deny.toml` in `registry-platform/templates/`, verified by `scripts/check-hygiene-alignment.sh` in each consumer CI.
- Telemetry conventions documented in `SECURITY_PRINCIPLES.md` but no telemetry crate in v0.1.0.
- Per-principal rate limiting out of scope.
- Pre-1.0 workspace-wide tag versioning.

## Open Questions

1. **Audit sink async runtime.** `AuditSink::write` is `async`. Both consumers are tokio. Pin tokio for `JsonlFileSink` I/O; leave the trait runtime-agnostic. Confirm during scaffold.
2. **JwksFetcher ownership.** `TokenVerifier::new` takes `Arc<JwksFetcher>`. Confirm during scaffold this matches relay's existing call sites.
3. **Credential-profile bypass parity in relay.** Witness's `43096ae` fix closes a profile-vs-claim bypass. Audit relay's issuance path during Track 1.
4. **Audit chain rotation policy.** `JsonlFileSink` needs rotation (size or time). Default: lift relay's policy verbatim.
5. **JCS implementation.** Use an existing crate (e.g., `serde_jcs`) or roll our own from RFC 8785? Default: use `serde_jcs` if it exists and is maintained; otherwise vendor a minimal implementation.
6. **Crypto algorithm coverage.** `v0.1.0` supports EdDSA/Ed25519 only. Add ES256, RS256, PS256, or other algorithms later only when a production consumer needs them.
7. **`MockIdp` realism.** Should it implement OAuth 2.0 client_credentials / authorization_code flows, or only mint tokens directly? Default: direct minting in v0.1.0 (enough to exercise `TokenVerifier`); add real flows in v0.2.0 if needed.
8. **Interop smoke test scope.** Confirm during Track 0 whether witness and relay interoperate at the VC layer today; if so, the cross-track DoD includes an interop test.
9. **License**: Apache-2.0 to match consumers.

## Implementation Waves And Review Plan

This work is executed as coordinated parallel lanes, with one owner per lane and explicit handoff points. The parent agent stays responsible for orchestration, integration, final review, and release readiness; worker agents own bounded slices and report files inspected, files changed, tests added, commands run, blockers, and residual risks.

### Worker Lanes

- **Platform scaffold worker.** Owns repo bootstrap, workspace metadata, CI, templates, deny/rustfmt/clippy policy, versioning docs, and config-drift inventory.
- **HTTP/auth worker.** Owns `registry-platform-httputil`, `registry-platform-authcommon`, URL policy, Bearer parsing, API-key fingerprinting, and related property tests.
- **OIDC/testing worker.** Owns `registry-platform-oidc`, `registry-platform-testing::MockIdp`, JWKS cache behavior, allowed-client semantics, and verifier integration tests.
- **Audit worker.** Owns `registry-platform-audit`, HMAC hashing, chain bootstrap, chain verification, file/stdout/syslog sinks, and tamper tests.
- **Crypto/SD-JWT worker.** Owns `registry-platform-crypto`, `registry-platform-sdjwt`, DID/JWK/JCS helpers, issuance invariants, holder-proof validation, and replay-binding tests.
- **HTTP service worker.** Owns `registry-platform-httpsec`, Problem Details, body limits, CORS/CSP/CORP, and sample axum integration tests.
- **Relay migration worker.** Owns relay replacement work after `v0.1.0` API freeze. Does not touch witness files.
- **Witness migration worker.** Owns witness replacement and gap-fill work after `v0.1.0` API freeze. Does not touch relay files.
- **Review and verification worker.** Runs independent diff review, checks the DoD evidence, verifies grep-based removal criteria, and reruns the broadest practical commands before merge.

### Waves

1. **Wave 0: Discovery freeze.** Confirm repo-local instructions, current dirty worktrees, source-of-truth code paths, and config inventory. No implementation starts until the open questions that affect public API shape are resolved or explicitly deferred in this doc.
2. **Wave 1: Platform foundation.** Scaffold `registry-platform`, CI, templates, docs, and empty crate shells. Review gate: scaffold PR reviewed before any ported security logic lands.
3. **Wave 2: Primitive extraction.** Parallel workers port the platform crates, preserving source behavior first, then refactoring to the documented APIs. Review gate: each crate gets a focused PR with unit/property tests and a second-pair code review.
4. **Wave 3: Cross-crate integration.** Wire sample axum app, MockIdp, audit chain verification, and config-drift scripts. Review gate: API freeze review for `TokenVerifier`, `AuditEnvelope`/`ChainState`, `FetchUrlPolicy`, crypto, and SD-JWT types.
5. **Wave 4: Tag `v0.1.0`.** Only after all Track 0 DoD bullets are green, CI is green, and release notes identify every breaking consumer change. No consumer migration may pin a moving branch.
6. **Wave 5: Consumer migrations in parallel.** Relay and witness workers migrate their repos in separate PRs pinned to `v0.1.0`. Review gate: each consumer PR has focused tests for every replacement and gap-fill item, plus grep evidence that duplicate primitives were removed.
7. **Wave 6: End-to-end validation.** Run cross-track alignment checks, consumer suites, security-review docs, and interop smoke test if applicable. Review gate: final reviewer signs off against the Cross-Track DoD.

### Review Cadence

- Every worker PR gets one implementation review and one security-focused review before merge.
- API-shape reviews happen at the end of Waves 2 and 3. A crate API cannot be treated as frozen until both reviews pass.
- Consumer migrations get review in three passes: mechanical replacement, behavior/security parity, then final DoD evidence.
- The review and verification worker audits the final diff after all lanes merge and before any "done" report.

### Unambiguous Done Rule

The effort is done only when every Track 0, Track 1, Track 2, and Cross-Track DoD bullet in this document is satisfied with linked evidence from commands, tests, grep output, docs, or reviewer sign-off. A feature is not done if it is wired only in one consumer, covered only by mocks when an integration test is required, missing migration docs, missing negative tests, or still has duplicate in-tree security logic that the platform crate is meant to replace.
