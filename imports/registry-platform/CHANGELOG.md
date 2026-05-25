# Changelog

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
