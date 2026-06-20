# Changelog

## Unreleased

### Security

- (AUDIT-03) `registry-platform-audit` now derives independent, domain-separated
  sub-keys for the audit chain HMAC and the identifier HMAC from the master
  environment secret using an internal HKDF-Expand (RFC 5869) over SHA-256, with
  distinct per-purpose `info` labels (`registry-platform-audit/chain-key/v1` and
  `registry-platform-audit/identifier-key/v1`). Previously both HMACs used the
  identical raw env material, so a leak of one key exposed the other. **This
  changes persisted chain and identifier hash values**; acceptable pre-beta
  (crate is `version 0.3.0`, `publish = false`) and only affects legacy
  pre-beta logs, which were already unkeyed/dev-only. Explicit `keyed(secret)`
  construction is unchanged (caller-owned key material).
- (AUDIT-02) `AuditHashSecret` now holds its HMAC key behind a
  `Zeroize`/`ZeroizeOnDrop` newtype so the raw key bytes are scrubbed when the
  last shared reference is dropped.
- (AUDIT-05) The query-redaction secret-parameter denylist now covers OAuth /
  OIDC and generic credential parameter names (`access_token`, `refresh_token`,
  `id_token`, `client_secret`, `client_assertion`, `assertion`, `bearer`,
  `code`, `private_key`, `credential`, `credentials`, `passwd`, `pwd`,
  `session_token`).
- (AUDIT-01 / AUDIT-06) The unkeyed verification and tail-hash convenience paths
  (`verify_jsonl_lines`, `AuditSink::tail_hash`) are now `#[deprecated]` and
  carry prominent warnings; production callers must use the keyed
  `*_with_hasher` variants with an explicit `AuditChainHasher`.
  `AuditSink::tail_hash_with_hasher` now fails closed by default so legacy custom
  tailable sinks cannot silently ignore the supplied keyed hasher through an
  unkeyed trait fallback.
- (REPORT-01) `registry-config-report` now exposes `ConfigExplanation::resolved_config`
  as a `RedactedConfig` newtype that can only be constructed via
  `RedactedConfig::redacted(..)` (which runs redaction internally), making
  redaction unbypassable at the type level for producers. Deserializing
  `RedactedConfig` now treats the input as untrusted and collapses it to
  `REDACTED_VALUE`; consumers that need to inspect rendered report JSON can use
  the wire-only `ConfigExplanationDocument` type. The wire format is unchanged
  (`#[serde(transparent)]`).
- (REPORT-03) `RequiredEnvVar` is documented as operator-sensitive (it enumerates
  secret env-var names and presence) and now offers `RequiredEnvVar::public_safe()`,
  a compatibility projection that collapses non-public entries to a generic
  not-checked placeholder. `RequiredEnvVar::public_safe_entries(..)` omits
  non-public entries entirely for public-facing lists so names, presence, and
  sensitive-entry counts are not disclosed.
- (OIDC-01) `registry-platform-oidc` `fetch_discovery_with_policy` now fails closed
  with `OidcError::MissingIssuer` when `jwks_uri_override` is set but `issuer` is
  empty, preserving an issuer binding when discovery is skipped.
- (HTTPSEC-01) `registry-platform-httpsec` `security_headers` now emits
  `Strict-Transport-Security` (`max-age=63072000; includeSubDomains`) by default,
  with `SecurityHeadersLayer::without_hsts()` / `with_hsts(..)` opt-outs.
- (HTTPSEC-02) `CorsPolicy::layer()` (which panics on an invalid policy) is now
  `#[deprecated]` in favor of the fallible `CorsPolicy::try_layer()`.

## v0.3.0 — 2026-06-13

### Added

- Posture profile gate vocabulary in `registry-platform-ops` (#55, PR #58): shared
  `DeploymentProfile`, `GateSeverity`, `DeploymentFinding`, `DeploymentWaiver`,
  `DeploymentFindingWaiver`, and `AuditAssurance` types plus the
  `registry.ops.posture.v1` finding and waiver shapes consumed by the Notary and
  Relay deployment-profile gates.
- Parser fuzz regression jobs (#51, PR #57): CI fuzz coverage for platform parsers.
- Emergency posture schema (#61, PR #62): adds the six `configuration.emergency`
  posture leaves to the default-tier allowlist and break-glass approval metadata
  shapes; contract tests pin schema validation, default-tier filtering, the
  change-class grammar, and the no-reason / no-approver-identity rule.
- STS bridge in `registry-platform` (PR #64): security-token-service bridge that
  backs Assisted Access token exchange.

## v0.2.1 — 2026-06-12

### Fixed

- (Issue #50) `authcommon::parse_bearer_token` now byte-compares the `Bearer `
  scheme prefix before calling `split_at(6)`, preventing a panic when a
  multibyte UTF-8 character straddles the scheme boundary.

## v0.2.0

### Security

- (F-P3-1) `crypto::sign` now wraps the decoded Ed25519 seed in
  `Zeroizing<[u8; 32]>` so key material is zeroed on drop.
- (F-P2-1) `AuditHashSecret` `Debug` impl confirmed to emit `<redacted>`,
  never the raw bytes; regression test added.
- (F-P2-2) `SdJwtIssuer` `Debug` impl confirmed to redact the private
  scalar; regression test added.
- (F-P6-1) `OidcDiscoveryConfig::jwks_uri_override` now carries a doc
  comment warning that setting it bypasses issuer-to-key-endpoint binding.

### Changed

- (Issue #10) Added provider-backed EdDSA signing via
  `SigningProvider`/`LocalJwkSigner`; SD-JWT issuance is now async and uses the
  provider `kid` as the JWT header source of truth.
- Added `registry-platform-ops` with the public
  `registry.ops.posture.v1` JSON Schema, Relay and Notary examples, shared
  finding/artifact/audit summary shapes, and sensitivity-tier redaction
  fixtures. Runtime services currently emit default posture; restricted posture
  is a contract tier for future/admin-gated surfaces, not runtime-emitted yet.
- (F-oid4vci-1) Remove `pub const PKCE_METHOD_S256`. Callers use the
  literal `"S256"`; the constant added no value and implied ownership of
  the PKCE method name.

### Fixed

- (F-P10-1) `getrandom = "0.4"` hoisted from `sdjwt/Cargo.toml` into
  `[workspace.dependencies]`; all consumers now share one pin.
- (F-testing-1) Sibling path-dep versions aligned to `"0.1.2"` across
  `testing`, `sdjwt`, `oid4vci`, and `oidc` `Cargo.toml` files
  (previously pinned at stale `"0.1.0"`).
- (F-crypto-2) `jsonwebtoken` removed from `crypto/Cargo.toml`; it was
  never referenced in source.

### Tests

- (F-P4-1) Integration test proves `RequestBodyLimitLayer` rejects a
  body 1 byte over 1 MiB with 413, and `body_limit_problem_response`
  returns the full RFC 7807 shape.
- (F-httpsec-2) Integration test asserts non-allowlisted Origin does not
  receive `Access-Control-Allow-Origin`.
- (F-httpsec-3) Unit test for `Problem` JSON serialisation shape
  (`type`/`title`/`status`/`detail`); cross-crate integration test
  extended with same assertions.
- (F-crypto-3) Unit tests for all three `DidError` variants: missing
  prefix, method not allowed, unsupported method.
- (F-sdjwt-2) `validate_holder_proof` rejects structurally malformed
  compact JWTs (no dots, two segments, four segments, invalid
  base64url characters).
- (F-oid4vci-2) Test confirms `validate_proof_jwt` does not track nonce
  reuse across calls (caller responsibility documented).
- (F-oid4vci-3) Serialisation round-trip tests for
  `CredentialConfigurationMetadata` (SD-JWT VC) and `CredentialOffer`
  (authorization_code flow).
- (F-P8-1) `#[ignore]` micro-benchmarks added for EdDSA sign and verify;
  doc comments cite measured µs/op on M5 Max (release mode).
- Focused posture contract tests validate the Relay and Notary examples, reject
  malformed posture documents including missing `posture.audit` and invalid
  artifact SHA-256 references, and prove the default redaction fixture omits
  secrets, subject ids, raw rows, claim values, SD-JWT disclosures, token hashes,
  private key material, private source URLs, and restricted topology while the
  restricted fixture may include restricted-only contract fields.

### Docs

- (F-oid4vci-4) `crates/registry-platform-oid4vci/README.md` created.
- (F-testing-2) `crates/registry-platform-testing/README.md` rewritten
  to document all public items.
- Added pre-release review report at `docs/release-review-0.1.2.md`.
- `docs/SECURITY_PRINCIPLES.md` §9 clarified: platform crates surface
  outcomes as `Result` types; consumer applications own audit wiring.
- `README.md`: toolchain pins and `cargo-deny` install hint added.

## v0.1.2

- Hardened OIDC verifier policy against mixed symmetric/asymmetric algorithm
  allowlists, JWK/header algorithm mismatches, and multi-audience ID-token
  `azp` gaps.
- Tightened OID4VCI proof validation, SD-JWT holder-proof headers, and JWK
  thumbprint construction.
- Added OpenID4VCI metadata primitives consumed by Registry Notary.

## v0.1.1

- Hardened shared security primitives for registry consumers, including
  outbound fetch validation, auth helpers, audit handling, and credential key
  utilities.

## v0.1.0

- Initial registry-platform workspace with eight crates: audit, authcommon,
  crypto, httpsec, httputil, oidc, sdjwt, and testing.
- Adds fail-closed Bearer/API-key parsing, outbound SSRF policy, bounded body
  reads, OIDC discovery/JWKS/token verification, tamper-evident audit chaining,
  RFC 7807 Problem Details, HTTP security middleware, Ed25519 JWK helpers,
  SD-JWT issuance/holder-proof validation, and shared test fixtures.
- Supports EdDSA/Ed25519 for platform-owned signing and verification in
  v0.1.0. Other JWK algorithms are rejected as unsupported until a consumer
  requires them.
- Ships canonical `clippy.toml`, `rustfmt.toml`, `deny.toml`, hygiene checks,
  versioning docs, and security principles for consumer alignment.
