# Changelog

## [Unreleased]

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
- Added OpenID4VCI metadata primitives consumed by Registry Witness.

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
