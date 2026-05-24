# Changelog

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
