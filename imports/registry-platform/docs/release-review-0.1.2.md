# Pre-Release Review: registry-platform 0.1.2

Date: 2026-05-25
Scope: pre-release review of the 9-crate workspace.

> **Decisions made after review (2026-05-25):**
> - **Distribution model for 0.1.x: git tag.** The crates.io publish decision is deferred to 0.2 once the API has settled. Several P0s in §6 only matter if publishing (Cargo metadata, path-dep versions, crate naming, workspace-vs-per-crate versioning); they are deferred accordingly.
> - **The authoritative ship-blocker list for 0.1.3 is §8.4 (staff-engineer re-prioritization), not §6.** §6 is preserved for traceability of the lane-by-lane findings.

> **Mechanical fixes executed (2026-05-27) — PR #8:**
>
> A follow-up session executed all 15 in-scope mechanical items from §8.3. Implementation was TDD (failing test first, then fix). A staff-engineer Opus review ran post-implementation and found one P2 (see below); the fix is included in the same PR.
>
> | Item | Status | Notes |
> |------|--------|-------|
> | F-P10-1 | Closed | `getrandom` hoisted to `[workspace.dependencies]` |
> | F-testing-1 | Closed | Sibling path-dep versions aligned to `"0.1.2"` |
> | F-crypto-2 | Closed | Unused `jsonwebtoken` removed from `crypto/Cargo.toml` |
> | F-oid4vci-4 | Closed | `oid4vci/README.md` created |
> | F-P2-1 | Closed | `AuditHashSecret` Debug redaction regression test |
> | F-P2-2 | Closed | `SdJwtIssuer` Debug redaction regression test |
> | F-P3-1 | Closed | Ed25519 seed wrapped in `Zeroizing<[u8; 32]>` |
> | F-P4-1 | Closed | Integration test wires `body_limit_problem_response` end-to-end (see P2 below) |
> | F-P6-1 | Closed | `jwks_uri_override` doc comment with security warning |
> | F-P8-1 | Closed | `sign`/`verify` doc comments + `#[ignore]` micro-benchmarks |
> | F-crypto-3 | Closed | Unit tests for all three `DidError` variants |
> | F-httpsec-2 | Closed | Integration test: non-allowlisted Origin gets no ACAO |
> | F-httpsec-3 | Closed | Problem JSON serialisation shape test |
> | F-oid4vci-1 | Closed | `PKCE_METHOD_S256` constant removed |
> | F-oid4vci-2 | Closed | Nonce-replay contract documented and tested |
> | F-oid4vci-3 | Closed | Serialisation round-trip tests for `CredentialConfigurationMetadata` and `CredentialOffer` |
> | F-sdjwt-2 | Closed | Malformed compact JWT rejection test |
> | F-testing-2 | Closed | `testing/README.md` rewritten to cover all public items |
> | F-P1-1 | Deferred | Not in scope for this pass |
> | F-crypto-1 | Deferred | Not in scope for this pass |
> | F-httputil-1 | Deferred | Not in scope for this pass |
> | F-sdjwt-1 | Deferred | Not in scope for this pass |
> | F-httpsec-6 | Deferred | Not in scope for this pass |
>
> **Staff-engineer post-implementation review (Opus, 2026-05-27):** One P2 was found. The original F-P4-1 tests checked the 413 status and the RFC 9457 Problem Details JSON shape in isolation: the layer rejected the body and the helper produced the JSON, but they were never connected in a single request path. Fixed: both integration tests (`httpsec/tests/integration.rs` and `testing/tests/cross_crate_integration.rs`) now wire `body_limit_problem_response` in the handler error branch and assert the full end-to-end response (status, `Content-Type: application/problem+json`, type/title/status/detail) from a single oversized request. All other items were cleared with no findings.

Five expert subagents reviewed independently:

1. **Security & cryptography** (opus)
2. **Standards compliance** (opus): OIDC, OAuth/PKCE, JWT/JWS/JWK/JWA, OID4VCI, SD-JWT, DPoP, RFC 8414
3. **Public API & Rust idioms** (sonnet)
4. **Supply chain & dependencies** (sonnet)
5. **Documentation & DX** (sonnet)

A sixth pass by a **staff-engineer reviewer** (opus) weighed value vs. cost across the consolidated findings and is captured in §8.

All reviews were read-only. This document consolidates findings and proposes a prioritized action list.

---

## Executive summary

The workspace is in solid shape from a *security correctness* standpoint: `unsafe_code = "forbid"` is enforced workspace-wide, the SSRF gate in `httputil` is comprehensive (DNS pinning, cloud-metadata blocks, IPv4-mapped normalization), ed25519 uses `verify_strict`, `none` alg is structurally rejected, `subtle::ConstantTimeEq` is used for secret comparisons, and `PrivateJwk` zeroizes on drop. The hard cryptographic primitives are right.

The workspace is **not** ready for a crates.io release for the following load-bearing reasons:

- **Every crate has `publish = false`.** Nothing publishes as-is.
- **Every error and config enum lacks `#[non_exhaustive]`.** Once 0.1.x is out, every new variant is a breaking change.
- **Path-deps pin sibling crates at stale `0.1.0` while the workspace is `0.1.2`.**
- **All crates are missing `description`, `keywords`, `categories`, `documentation`** in `Cargo.toml`; `cargo publish` will warn / crates.io will display poorly.
- **Zero rustdoc on the public surface across the workspace** (combined ~407 missing-docs errors). No doctests exist anywhere.
- **One P0 security finding** (alg-confusion via operator-mixable allowed_algorithms) and **two protocol P0 findings** (OID4VCI proof `iss` not validated; OIDC ID-token `azp` not enforced on multi-aud).
- **Two SHOULD-NOT-clone secret-bearing types** (`PrivateJwk`, `SdJwtIssuer`) derive `Clone`.
- **CHANGELOG is stuck at 0.1.0**, doesn't cover 0.1.1 or 0.1.2, and isn't in Keep-a-Changelog format.

There is a clear path forward. Most of the gaps are mechanical (manifests, docs, `#[non_exhaustive]`); the protocol-level fixes are localized.

---

## Cross-cutting themes (issues raised by multiple reviewers)

These should be addressed first because each fix closes findings across multiple lanes.

| Theme | Raised by | Severity |
|---|---|---|
| `publish = false` everywhere | API, Supply chain, Docs | P0 (release-blocker) |
| Path-dep version is `0.1.0`, workspace is `0.1.2` | API, Supply chain | P0 |
| Missing `description`/`keywords`/`categories`/`documentation` in every Cargo.toml | API, Supply chain, Docs | P0 (publish warns, crates.io page is bare) |
| No `rust-version` MSRV declared anywhere | API, Supply chain, Docs | P1 |
| `PrivateJwk` derives `Clone` over zeroize-on-drop intent; transitively `SdJwtIssuer` too | Security, API | P0 |
| No rustdoc / no doctests / no examples directory | Docs, API | P0/P1 |
| `JwksFetcher._client` dead field that's part of the public constructor | Security (P2-7), API (P1) | P1 |
| `PublicJwk::jkt()` builds JSON via raw `format!` instead of canonical JSON serialization | Security (P1-5), Standards (RFC 7638 P1) | P1 |

---

## 1. Security & cryptography findings

### Executive summary (security reviewer)

> The workspace is in solid shape for a first crates.io release: `unsafe_code = "forbid"` is workspace-wide and no overrides exist; ed25519 verification uses `verify_strict`, defeating malleability; OIDC discovery and JWKS fetches are funneled through a DNS-pinned `ValidatedFetchUrl` that closes the DNS-rebinding gap; the `none` algorithm is structurally rejected because jsonwebtoken v10 dropped the `None` variant; `PrivateJwk` zeroizes the `d` field on drop and redacts `d`/`n` in `Debug`; `subtle::ConstantTimeEq` is used for API-key digest comparison and audit hash comparison. Tests are thorough on the SSRF guard, JWKS rotation, negative caching, and chain tamper detection.

### P0

**SEC-P0-1.** **Alg-confusion via operator-mixable `allowed_algorithms`.** `crates/registry-platform-oidc/src/lib.rs:312` (`validate_jwk`) only enforces an RSA modulus floor; it does not reject `kty: "oct"`. `verify_access_token` (line 425) and `verify_id_token` (line 470) set `validation.algorithms = vec![header.alg]`, so the attacker picks the algorithm from `allowed_algorithms`. A caller that whitelists both `RS256` and `HS256` (e.g. two IdPs) hands an attacker the classic RS256-as-HS256 confusion: sign with HS256 using the RSA modulus bytes as MAC secret. **Fix:** assert in `TokenVerifier::new` that `allowed_algorithms` is fully symmetric or fully asymmetric, and have `validate_jwk` reject `kty=oct` when configured algorithms are asymmetric (and inverse).

### P1

**SEC-P1-1.** ID-token verifier doesn't enforce `azp` on multi-audience tokens. `crates/registry-platform-oidc/src/lib.rs:470-503`. OIDC Core 1.0 §3.1.3.7(3-4) requires `azp` to be present and match the client when `aud` is multi-valued. Currently `match_client` is best-effort (`.ok().flatten()`).

**SEC-P1-2.** SD-JWT holder proof doesn't enforce `typ: "kb+jwt"`. `crates/registry-platform-sdjwt/src/lib.rs:177-185`. Only `alg == "EdDSA"` is checked. Without `typ` enforcement, an attacker may substitute another holder-signed JWT (e.g. an ID token) for a key-binding JWT. Also should reject `crit`, `jku`, `jwk`, `x5u`, `x5c` like `oid4vci` does at line 309.

**SEC-P1-3.** OID4VCI proof JWT `iss` claim is not validated. `crates/registry-platform-oid4vci/src/lib.rs:239-300`. OID4VCI 1.0 §7.2.1.1 requires `iss` = wallet `client_id` for authorization-code flow. A proof from client B can be accepted on a session authorized to client A. Add optional `expected_iss: Option<&str>` to `ProofValidationPolicy` and enforce when set.

**SEC-P1-4.** JWK `alg` not cross-checked against header `alg` after kid lookup. `crates/registry-platform-oidc/src/lib.rs:443-446`. Combined with SEC-P0-1, this is the lever for alg confusion. After `key_for_kid`, require strict equality between the JWK's `alg`/`kty/crv`-inferred algorithm and `header.alg` before calling `decode`.

**SEC-P1-5.** `PublicJwk::jkt()` builds JSON via raw `format!` without escaping. `crates/registry-platform-crypto/src/lib.rs:137-158`. Fields are `pub`, so a consumer can build a `PublicJwk` with `x: Some(r#"a","x":"b"#.into())` and compute a colliding thumbprint. Build the payload via `serde_json` (or escape per-field) and consider keeping the fields `pub(crate)` with constructors.

**SEC-P1-6.** OIDC `issuer` concatenated to discovery URL by `push_str` rather than `Url::join`. `crates/registry-platform-oidc/src/lib.rs:63-65`. Validate `cfg.issuer` is a plain origin (no query/fragment, no userinfo) or use `Url::join`.

**SEC-P1-7.** OID4VCI `validate_proof_jwt` allows missing `exp` and only bounds `iat` against `max_lifetime`. `crates/registry-platform-oid4vci/src/lib.rs:269-355`. Widens the replay window if the c_nonce store doesn't enforce single-use. Optionally allow the policy to require `exp`, or explicitly document the c_nonce-store assumption.

### P2

**SEC-P2-1.** `Audience::One`/`Many` is `Deserialize(untagged)`; could accept numeric or boolean. `crates/registry-platform-oidc/src/lib.rs:378-383`. Consider explicit deserializer that rejects non-string.

**SEC-P2-2.** `OutboundClientBuilder::build` uses `.expect(...)`. `crates/registry-platform-httputil/src/lib.rs:63`. Safe today; brittle if features change. Consider `Result`.

**SEC-P2-3.** `getrandom = "0.4.2"` direct pin in sdjwt; ecosystem moving. Not a bug; tracking note.

**SEC-P2-4.** `SdJwtIssuer` derives `Clone` while wrapping a `PrivateJwk`. `crates/registry-platform-sdjwt/src/lib.rs:14-26`. Wrap key in `Arc` to avoid duplicating secret bytes on clone.

**SEC-P2-5.** `validate_did_web` blocks `localhost`/metadata literally; IDN punycode not normalized. `crates/registry-platform-crypto/src/lib.rs:388-410`. Low priority because httputil's SSRF gate is the real defense.

**SEC-P2-6.** `OidcError::IssuerMismatch { actual }` surfaces attacker-controlled `iss` claim into logs. `crates/registry-platform-oidc/src/lib.rs:716-717`. Bounded by JWT size; consider truncation.

**SEC-P2-7.** `JwksFetcher._client` field is unused. `crates/registry-platform-oidc/src/lib.rs:134`. Remove from constructor signature (also flagged by API reviewer as P1).

**SEC-P2-8.** `validate_proof_jwt` accepts matching pair of `kid` and `jwk` headers; spec-compliant but consider requiring exactly one. `crates/registry-platform-oid4vci/src/lib.rs:320-332, 276-289`.

### Cleared areas

- `registry-platform-httputil` SSRF gate (DNS pinning, ipv4-mapped normalization, cloud-metadata IPv4/IPv6 coverage, link-local/unspecified rejection, validated-fetch DNS evidence carried through, redirects disabled, proxy ignored).
- `registry-platform-authcommon`: 256-bit raw-key floor, canonical fingerprint format, `subtle::ConstantTimeEq` digest comparison, `Zeroizing` of plaintext bytes, strict bearer parsing.
- `registry-platform-crypto`: `verify_strict` for ed25519, `Drop`+`zeroize` on `PrivateJwk::d`, `Debug` redaction, strict 32-byte length on `x`/`d`, JCS canonicalization with NaN rejection, `did:jwk` round-trip rejects private members.
- `registry-platform-audit`: HMAC-SHA256 keyed mode 32-byte secret requirement, env-var fail-closed, `unkeyed_dev_only` requires explicit opt-in, chain hash uses `ct_eq`, JSONL parser rejects PrevHashMismatch from index 1, anchored verification rejects full-rewrite, `AuditEnvelope` Debug redacts `record`.
- `registry-platform-httpsec`: CORS wildcard rejection, credentialed CORS requires explicit headers, loopback-only HTTP origin allowance, security headers (CSP/X-CTO/Referrer-Policy/X-Frame-Options/CORP), `application/problem+json`, request-body limit layer.
- `registry-platform-oidc`: `none` alg structurally unrepresentable (jsonwebtoken v10), kid length cap (1024 bytes), negative-cache size cap (1024), force-refresh cooldown, single-flight refresh lock, `nbf`/`exp`/`iat` enforced via `Validation`, `required_spec_claims` set explicitly, leeway plumbed.
- `registry-platform-sdjwt`: 128-bit salt, sha-256 disclosure digest, `_sd` array sorted, `cnf.jwk` written without `d`, holder-proof rejects JTI shaped like `urn:ulid:`, audience match with array support, `exp > iat`, `exp <= iat + max_lifetime`, `exp <= now` rejected.
- No `unsafe` blocks, no `#[allow(unsafe_code)]` overrides.
- TLS posture: `rustls-tls` default; `native-tls` is opt-in.

---

## 2. Standards-compliance findings

### Overall posture

The workspace's identity surface is narrower than typical OIDC/OID4VCI stacks: only the **token-verification** side of OIDC, an **issuer-side facade** for OID4VCI, and an **SD-JWT VC issuer + bespoke "holder proof" validator** are implemented. No authorization endpoint, no client-side OAuth code, no PKCE/redirect_uri flow, no DPoP, no AS metadata (RFC 8414). Most OAuth 2.x/OIDC AuthZ specs are correctly **out of scope** rather than non-compliant.

### Per-spec findings

**OIDC Core 1.0** (targeting final). Hard MUSTs (iss, aud, exp, sig, alg) are enforced.
- P1: `nonce`/`at_hash`/`c_hash` not validated. Acceptable for a resource-server verifier; document the scope.
- P1: `iat` REQUIRED in ID Token per Core; not in `required_spec_claims`.
- P1: `verify_userinfo_jwt_with_claims_policy` clears `required_spec_claims` entirely. UserInfo signed responses are JWTs (Core 5.3.2) but lifetime is unbounded; consider requiring `iat`.

**OAuth 2.0/2.1, RFC 6749/8252/7636 (PKCE)** — N/A. Only `PKCE_METHOD_S256` constant exists. Correctly out of scope for v0.1.

**RFC 7519/7515/7517/7518 (JWT/JWS/JWK/JWA)**. None alg correctly blocked.
- P1: `PublicJwk::jkt()` doesn't validate required members are present (RFC 7638 §3.1) and uses raw `format!` (same as SEC-P1-5).
- Acceptable: only EdDSA in `registry-platform-crypto`; RSA-modulus floor at 2048 is right.

**OID4VCI 1.0 (final, Feb 2025)**. Targeting confirmed via `dc+sd-jwt` format, `openid4vci-proof+jwt` typ, `nonce_endpoint` metadata.
- **P0:** `validate_proof_jwt` does not enforce `iss` claim (§7.2.1.1 MUST). Same as SEC-P1-3.
- P1: Pre-authorized code grant not implemented. Optional in 1.0 but a known gap; document.
- P1: `CredentialOffer::authorization_code` serializes `authorization_server: null` when None. Fix: `#[serde(skip_serializing_if = "Option::is_none")]`.
- P1: `ProofValidationPolicy::expected_nonce` is `Option<&str>`; when None, no nonce enforced. Should be explicit: `NoncePolicy::{Required(&str), AllowAbsent}`.
- P1: `aud` accepted as string OR array. §8.2 specifies singular; restrict to string.
- P2: No batch / deferred / notification endpoints (1.0 §9-11). Document the scope.

**SD-JWT (draft 11+) and SD-JWT VC (`dc+sd-jwt` era)**. Issuance path is clean.
- **P0/P1 ambiguity:** `validate_holder_proof` is **not** a spec KB-JWT validator. It demands custom claims (`evaluation_id`, `credential_profile`, `disclosure`, `claims`) that aren't in the SD-JWT spec, and accepts `typ: "JWT"` instead of `kb+jwt`. **Action:** either rename to `validate_presentation_envelope`, or add a KB-JWT validator alongside.
- P1: Document that the SD-JWT crate is issuer-side only; no `iss` verification surface.

**RFC 9449 (DPoP)** — N/A.

**RFC 8414 (AS metadata)** — out of scope (only OIDC discovery via `/.well-known/openid-configuration` implemented; issuer match enforced correctly at `oidc/src/lib.rs:81-86`).

### Per-crate spec table

| Crate | Spec-clean? |
|---|---|
| `registry-platform-crypto` | Y (within EdDSA-only scope; minor jkt edge case) |
| `registry-platform-authcommon` | Y |
| `registry-platform-httpsec` | Y (not an identity spec) |
| `registry-platform-oidc` | Partial (no nonce/at_hash; iat not required; verifier-only scope undocumented) |
| `registry-platform-oid4vci` | N (proof `iss` not validated; pre-auth grant missing; null serialization in CredentialOffer) |
| `registry-platform-sdjwt` | Partial (issuance clean; "holder proof" is not KB-JWT and must be explicit) |

---

## 3. Public API & Rust idioms findings

### P0

**API-P0-1.** **Every public enum lacks `#[non_exhaustive]`.** Once at 0.1.x on crates.io, adding a variant is breaking. Apply to:

Errors:
- `crates/registry-platform-audit/src/lib.rs:133` `AuditError`
- `crates/registry-platform-audit/src/lib.rs:607` `ChainVerificationError`
- `crates/registry-platform-audit/src/lib.rs:550` `redact::QueryRedactionError`
- `crates/registry-platform-authcommon/src/lib.rs:22` `BearerParseError`
- `crates/registry-platform-authcommon/src/lib.rs:77` `FingerprintFormatError`
- `crates/registry-platform-authcommon/src/lib.rs:127` `EntropyError`
- `crates/registry-platform-crypto/src/lib.rs:179` `JwkError`
- `crates/registry-platform-crypto/src/lib.rs:188` `CryptoError`
- `crates/registry-platform-crypto/src/lib.rs:212` `DidError`
- `crates/registry-platform-crypto/src/lib.rs:316` `JcsError`
- `crates/registry-platform-httpsec/src/lib.rs:79` `CorsValidationError`
- `crates/registry-platform-httputil/src/lib.rs:69` `BoundedReadError`
- `crates/registry-platform-httputil/src/lib.rs:121` `url::UrlError`
- `crates/registry-platform-httputil/src/lib.rs:381` `FetchUrlError`
- `crates/registry-platform-oid4vci/src/lib.rs:219` `ProofError`
- `crates/registry-platform-oidc/src/lib.rs:702` `OidcError`
- `crates/registry-platform-sdjwt/src/lib.rs:228` `SdJwtError`

Growable config/data structs:
- `crates/registry-platform-audit/src/lib.rs:563` `ChainVerification`
- `crates/registry-platform-audit/src/lib.rs:576` `ChainVerificationAnchors`
- `crates/registry-platform-oid4vci/src/lib.rs:21` `CredentialIssuerMetadata`
- `crates/registry-platform-oid4vci/src/lib.rs:50` `CredentialConfigurationMetadata`
- `crates/registry-platform-oid4vci/src/lib.rs:96` `DisplayMetadata`
- `crates/registry-platform-oid4vci/src/lib.rs:103` `ProofTypeMetadata`
- `crates/registry-platform-oid4vci/src/lib.rs:109` `CredentialOffer`
- `crates/registry-platform-oid4vci/src/lib.rs:208` `ValidatedProof`
- `crates/registry-platform-oidc/src/lib.rs:22` `OidcDiscoveryConfig`
- `crates/registry-platform-oidc/src/lib.rs:94` `JwksFetcherConfig`
- `crates/registry-platform-oidc/src/lib.rs:343` `TokenVerifierConfig`

**API-P0-2.** `publish = false` on every crate. Remove from public crates; keep on `registry-platform-testing` (test fixtures embed private JWKs) if that's intentional.

**API-P0-3.** Path-deps pin sibling versions at `"0.1.0"` while workspace is `0.1.2`. Files: `crates/registry-platform-oid4vci/Cargo.toml:12`, `crates/registry-platform-oidc/Cargo.toml:13-14`, `crates/registry-platform-sdjwt/Cargo.toml:14`, `crates/registry-platform-testing/Cargo.toml:16-20`. Use `version.workspace = true`.

**API-P0-4.** `PrivateJwk` derives `Clone`. `crates/registry-platform-crypto/src/lib.rs:25`. Allows duplicating private key material into separate heap locations, against zeroize-on-drop intent. Remove `Clone` and wrap in `Arc<PrivateJwk>` if sharing is needed.

**API-P0-5.** `AuditHashSecret` derives `Clone` publicly. `crates/registry-platform-audit/src/lib.rs:347`. Internally `Arc<[u8]>`, so cheap, but the public `Clone` on a "secret"-named type invites misuse. Document or remove.

**API-P0-6.** `SdJwtIssuer` derives `Clone` (wraps `PrivateJwk`). `crates/registry-platform-sdjwt/src/lib.rs:14`. Compounds API-P0-4.

### P1

**API-P1-1.** `JwksFetcher._client` is a dead field that's part of the public constructor (`crates/registry-platform-oidc/src/lib.rs:134`). The `_` prefix masks the warning. `refresh` builds its own one-shot client. Remove now (non-breaking); breaking after publish.

**API-P1-2.** `CorsPolicy` has public fields with no construction-time validation. `crates/registry-platform-httpsec/src/lib.rs:17`. `validate()` is a separate step and `layer()` panics on invalid policy. Add a constructor that validates.

**API-P1-3.** `FetchUrlPolicy` has public mutable fields. `crates/registry-platform-httputil/src/lib.rs:166`. Caller can construct an insecure-by-default policy. Use a builder; keep `strict()`/`dev()`.

**API-P1-4.** `HolderProofPolicy::default()` produces empty audience. `crates/registry-platform-sdjwt/src/lib.rs:140`. Silently rejects everything. Either remove `Default` impl, or panic, or document explicitly.

**API-P1-5.** `sort_sd_digests` is `pub` with `#[allow(clippy::ptr_arg)]`. `crates/registry-platform-sdjwt/src/lib.rs:129`. Internal utility; should be `pub(crate)`.

**API-P1-6.** `AuditKeyHasher` is `pub` and not `#[non_exhaustive]` with `UnkeyedDevOnly` variant. `crates/registry-platform-audit/src/lib.rs:392`. Apply `#[non_exhaustive]`; consider sealing.

**API-P1-7.** `async-trait` used throughout while MSRV is undeclared. If MSRV is 1.75+, drop `async-trait` for native async-in-traits. If lower, fine as-is.

### P2

**API-P2-1.** No `rust-version` declared anywhere. Add at workspace level.

**API-P2-2.** Missing per-crate `description`/`keywords`/`categories`/`documentation` (cross-cut with Docs lane; consolidated in §5).

**API-P2-3.** `getrandom = "0.4"` is a direct dep in sdjwt not pulled from workspace. `crates/registry-platform-sdjwt/Cargo.toml:12`.

**API-P2-4.** `PrivateJwk.validate_private()` / `PublicJwk.validate_public()` are correctly `pub(crate)`. No action.

**API-P2-5.** `httpsec::problem` module re-exports only `Problem`, redundant. `crates/registry-platform-httpsec/src/lib.rs:324`. Either expand or remove.

---

## 4. Supply chain & dependency findings

### Tool outputs

- `cargo audit`: 1 advisory triggered (already documented + ignored in `deny.toml`):
  - **RUSTSEC-2023-0071** (`rsa v0.9.10`, medium): Marvin Attack timing side-channel. No patched version. Pulled transitively via `jsonwebtoken` -> `rsa`. Rationale documented.
- `cargo deny check` (0.19.7): all four subchecks pass (advisories, bans, licenses, sources).
- Warnings (non-blocking, but worth cleanup):
  - 3 ignored advisories (`RUSTSEC-2023-0089`, `RUSTSEC-2024-0436`, `RUSTSEC-2025-0068`) reference crates not in the lockfile (`atomic-polyfill`, `paste`, `serde_yml`). Pre-emptive consumer-facing ignores belong in a separate file.
  - 4 license allow entries unused (`CC0-1.0`, `Unicode-DFS-2016`, `Zlib`, `bzip2-1.0.6`).
  - 2 `allow-git` entries unmatched (`PublicSchema/cel-mapping`, `jeremi/registry-manifest`).

### P0

None.

### P1

**SUP-P1-A.** `publish = false` on every crate (cross-cut).

**SUP-P1-B.** `httputil` exposes `native-tls` feature; CI runs `--all-features`, dragging `openssl-sys` into the build. `deny.toml`'s `[graph]` also has `all-features = true` but no `deny = [{ name = "openssl-sys" }]`. Either remove the `native-tls` feature, or add explicit bans in `[bans]`:

```toml
deny = [
    { name = "openssl-sys", reason = "workspace mandates rustls" },
    { name = "openssl",     reason = "workspace mandates rustls" },
    { name = "native-tls",  reason = "workspace mandates rustls" },
]
```

**SUP-P1-C.** `jsonwebtoken`'s `rust_crypto` feature pulls `rsa`, `p256`, `p384`, `rand v0.8` even though only EdDSA is used. Dead algorithm surface; source of the RUSTSEC. No per-alg feature toggle exists upstream. Consider whether `jsonwebtoken` is the right abstraction long-term given EdDSA-only signing.

**SUP-P1-D.** Path-dep version pins are stale (`0.1.0` vs workspace `0.1.2`) — same as API-P0-3.

### P2

**SUP-P2-A.** `sha2 = "0.11"` and `hmac = "0.13"` are stable RustCrypto releases (not pre-releases, despite sub-1.0). However, `sha2 v0.10.9` is also in the lockfile (pulled by `ed25519-dalek` and `jsonwebtoken`). Two sha2 generations coexist — structural, not directly resolvable. Document in `deny.toml`.

**SUP-P2-B.** `getrandom = "0.4"` direct dep in sdjwt should move to `[workspace.dependencies]`. `getrandom 0.2`, `0.3`, and `0.4` are all in the lockfile via transitive deps; the direct pin in sdjwt is unusual since `ulid`'s rand 0.9 (using getrandom 0.3) is already available.

**SUP-P2-C.** No MSRV declared; CI tests `stable` only.

**SUP-P2-D.** Three stale `[advisories]` ignores produce permanent CI warnings.

**SUP-P2-E.** Two stale `allow-git` entries in `[sources]`.

**SUP-P2-F.** Local `cargo-deny` is 0.14.2 (uv-installed); CI is 0.19.7. Local `check` fails with hard error on unknown `[graph]` block. Use `~/.cargo/bin/cargo-deny` (0.19.7) or reinstall.

---

## 5. Documentation & DX findings

### Per-crate readiness

| Crate | Status | Missing-docs errors |
|---|---|---|
| `registry-platform-authcommon` | needs-doc-work | 2 |
| `registry-platform-audit` | needs-doc-work | 57 |
| `registry-platform-crypto` | needs-doc-work | 60 |
| `registry-platform-httpsec` | needs-doc-work | 36 (no crate-level `//!`) |
| `registry-platform-httputil` | needs-doc-work | 15 |
| `registry-platform-oid4vci` | **not-ready** | 79 (referenced README file missing) |
| `registry-platform-oidc` | **not-ready** | 81 (no crate-level `//!`) |
| `registry-platform-sdjwt` | needs-doc-work | 48 |
| `registry-platform-testing` | needs-doc-work | 29 |

Total: ~407 missing-docs errors across the workspace. Zero doctests anywhere.

### P0

**DOC-P0-1.** **Zero doctests** across the entire workspace. `cargo test --doc --workspace` runs 0 tests. No compiled usage examples for any API. Highest misuse risk on crypto-sensitive entry points (`SdJwtIssuer::issue`, `validate_holder_proof`, `TokenVerifier::verify`, `validate_proof_jwt`, `FetchUrlPolicy::strict()`).

**DOC-P0-2.** `registry-platform-httpsec/src/lib.rs:1` — no crate-level `//!` doc.

**DOC-P0-3.** `registry-platform-oidc/src/lib.rs:1` — no crate-level `//!` doc.

**DOC-P0-4.** `registry-platform-oid4vci` — no per-crate README (referenced in Cargo.toml but file is absent), every exported constant undocumented.

**DOC-P0-5.** CHANGELOG only covers v0.1.0; v0.1.1 and v0.1.2 are unrecorded. Not Keep-a-Changelog format. Commits `d112946` (security hardening) and `ce5fb6e` (OID4VCI primitives) are not documented.

### P1 (key APIs undocumented)

**DOC-P1-1.** `sdjwt`: `SdJwtIssuer` (line 15), `SdJwtIssuer::from_jwk` (29), `SdJwtIssuer::issue` (34), `SdJwtIssuanceInput` + 8 fields (97-105), `HolderConfirmation` (85), `Disclosure` (91), `SignedSdJwt` (123), `HolderProofPolicy` (135), `HolderProofBindings` (150), `HolderProofClaims` (159), `validate_holder_proof` (168), `sort_sd_digests` (130).

**DOC-P1-2.** `crypto`: `PrivateJwk` + 9 fields (26-43), `PublicJwk` + 8 fields (69-88), `SigningAlgorithm` (17), `JwkError` (178), `CryptoError` (188), `DidMethod` (198), `ValidatedDid` (205), `DidError` (212), `JcsError` (316), `validate_did` (230), `parse_did_jwk` (270), `did_jwk_from_public_jwk` (287), `validate_did_web` (293), `canonicalize_json` (324), `sign` (330), `verify` (338). `sign`/`verify` are the most dangerous items to leave undocumented.

**DOC-P1-3.** `oidc`: `OidcDiscoveryConfig` (22-26), `DiscoveryDocument` (31-36), `JwksFetcherConfig` (95-100), `JwksFetcher::new`/`new_with_fetch_url_policy`/`key_for_kid` (143/148/164), `TokenVerifierConfig` + 9 fields (344-353), `Claims` (357-375), `VerifiedToken`/`TokenVerifier`/`new`/`verify`/`verify_related_token` (385-421), `OidcError` (702). Security-critical: `allowed_algorithms` carries no security warning in rustdoc.

**DOC-P1-4.** `audit`: `AuditSink::write`/`tail_hash` (128-129), `AuditError` + variants (133), `AuditKeyHasher` (433), `ChainVerificationError`, `verify_chain`, `verify_chain_with_anchors`, `redact::QueryRedactor::redact_query`/`try_redact_query` (505, 516).

**DOC-P1-5.** `httpsec`: `CorsPolicy` + 4 fields (17-21), `CorsPolicy::validate`/`layer` (25, 51), `CspBuilder`/`restrictive`/`header_value` (90, 100, 110), `SecurityHeadersLayer`/`Service`, `CorpConditionalLayer`/`Service` (130, 146, 207, 218), `security_headers`/`corp_conditional`/`apply_conditional_corp`/`request_body_limit` (123, 202, 247, 262), `Problem` (267).

**DOC-P1-6.** `httputil`: `FetchUrlPolicy` 5 fields (167-171). `ValidatedFetchUrl` and `immediate_get` lack top-level docs.

**DOC-P1-7.** `oid4vci`: 7 string constants (13-19), `CredentialIssuerMetadata` + 5 fields (22-33), `CredentialConfigurationMetadata` + 7 fields (51-68), `DisplayMetadata`, `ProofTypeMetadata`, `CredentialOffer`, `NonceRequest`, `NonceResponse`, `CredentialRequest`, `CredentialRequestProof`, `CredentialResponse`, `WireError`, `ProofValidationPolicy`, `ValidatedProof`, `ProofError`, `validate_proof_jwt` (239).

**DOC-P1-8.** `testing`: `ED25519_PRIVATE_JWK`, `ED25519_ROTATED_PRIVATE_JWK` (350-351) carry literal private-key material. Must have doc comment stating test-only, never-deploy, public `d` values.

### P2

**DOC-P2-1.** No `examples/` directory anywhere. Add at least: `sdjwt_issue_verify` (crypto + sdjwt), `oidc_verify_token` (httputil + oidc), `httpsec_axum_app` (security_headers + cors layer).

**DOC-P2-2.** No spec references in OID4VCI / SD-JWT rustdoc. Link to draft sections (e.g. `/// See [OID4VCI §7.2.1](https://openid.net/specs/...)`).

**DOC-P2-3.** `FetchUrlPolicy::validate` carries a TOCTOU warning in prose (line 203-208) but not in a rustdoc `# Caution` section.

**DOC-P2-4.** `TokenVerifierConfig::allowed_algorithms` has no doc warning about HS256/RS256 risk.

**DOC-P2-5.** Workspace `[workspace.package]` and per-crate Cargo.toml both missing `description`/`keywords`/`categories`/`documentation`. Workspace inheritance does not fall through for these fields. See §6 for proposed values.

**DOC-P2-6.** SECURITY.md has no threat-model section. Procedure is well-documented; scope of guarantees is not.

**DOC-P2-7.** `CorsPolicy::layer()` panics on invalid policy with no `# Panics` rustdoc section. `crates/registry-platform-httpsec/src/lib.rs:52-53`.

**DOC-P2-8.** `OutboundClientBuilder::build()` uses `.expect()` with no `# Panics` section. `crates/registry-platform-httputil/src/lib.rs:62-64`.

**DOC-P2-9.** `registry-platform-audit` crate-level `//!` is a single sentence. Expand to 3-4 sentences (chain model, setup).

**DOC-P2-10.** No `[Unreleased]` section in CHANGELOG; no versioning policy. NOTICE file likely not required (no Apache-2.0 deps with their own NOTICE), to be confirmed during publish checklist.

### Suggested Cargo metadata (needs sign-off)

Workspace `[workspace.package]` cannot inherit `description`/`keywords`/`categories`/`documentation` automatically; each crate needs its own. Proposed:

| Crate | description | keywords | categories |
|---|---|---|---|
| audit | "Tamper-evident HMAC-chained audit envelopes and JSONL sinks" | audit, hmac, jsonl, tamper-evident | cryptography, web-programming |
| authcommon | "Bearer token parsing and API-key fingerprinting helpers" | bearer, api-key, authentication, jwt | authentication, web-programming |
| crypto | "Ed25519 JWK signing, DID validation, and JSON canonicalization" | ed25519, jwk, did, eddsa, jcs | cryptography, authentication |
| httpsec | "Axum/Tower HTTP security middleware and RFC 9457 Problem Details responses" | cors, csp, axum, http-security | web-programming, authentication |
| httputil | "SSRF-resistant outbound HTTP client and bounded response reads" | ssrf, reqwest, http, fetch | web-programming, network-programming |
| oid4vci | "OpenID4VCI protocol types and proof validation helpers" | oid4vci, openid, verifiable-credentials, sd-jwt | authentication, cryptography |
| oidc | "OIDC discovery, JWKS caching, and JWT token verification" | oidc, jwt, jwks, openid-connect | authentication, web-programming |
| sdjwt | "SD-JWT VC issuance and holder-proof validation" | sd-jwt, verifiable-credentials, eddsa, jwt | cryptography, authentication |
| testing | "Mock IdP, HTTP upstreams, and key fixtures for registry-platform tests" | testing, mock, fixtures, oidc | development-tools::testing |

### Suggested root README opening (precedes the existing crate table)

```
# Registry Platform

`registry-platform` is a set of Rust primitives for building identity- and
credential-aware services: SSRF-resistant outbound HTTP, OIDC token
verification, SD-JWT VC issuance, tamper-evident audit chains, and browser
HTTP security middleware. The crates are designed to compose: a service
handling OID4VCI credential requests typically pulls in `httputil`, `oidc`,
`oid4vci`, and `sdjwt` together.

All signing uses EdDSA/Ed25519 (`OKP` JWKs). OIDC JWT verification is
caller-configurable for provider compatibility; keep `allowed_algorithms` as
narrow as your provider supports.
```

---

## 6. Proposed release-blocking action list

Ordered for execution. Each item closes one or more findings.

### Must do before 0.1.3 (release candidate)

1. **Fix protocol P0s.**
   - SEC-P0-1 / SEC-P1-4: gate algorithm mixing in `TokenVerifier::new`; cross-check JWK alg vs. header alg.
   - SEC-P1-3 / OID4VCI MUST: enforce `iss` in `validate_proof_jwt` (add `expected_iss` to policy).
   - SEC-P1-1: enforce `azp` on multi-audience ID tokens.
   - SEC-P1-2: enforce `typ: "kb+jwt"` on SD-JWT holder proof, or rename helper.

2. **Secret-handling: remove `Clone` from `PrivateJwk` and `SdJwtIssuer`** (or wrap in `Arc`). API-P0-4, API-P0-6.

3. **Apply `#[non_exhaustive]` to every public enum and growable config struct** listed in API-P0-1.

4. **Fix path-dep versions** to `version.workspace = true` in all four affected manifests. API-P0-3 / SUP-P1-D.

5. **Remove `_client` dead field** from `JwksFetcher` (still non-breaking). API-P1-1 / SEC-P2-7.

6. **Tighten `PublicJwk::jkt()`** to use canonical JSON serialization and validate required members per RFC 7638. SEC-P1-5 / Standards P1.

7. **Fix `CredentialOffer::authorization_code`** to use `skip_serializing_if = "Option::is_none"`. Add `pre_authorized_code` constructor or document its absence.

8. **Crate-level docs and `description`/`keywords`/`categories`/`documentation` per crate.** DOC-P0-2/3/4, DOC-P2-5.

9. **Update CHANGELOG** to Keep-a-Changelog format, covering 0.1.1 and 0.1.2.

10. **Threat model in SECURITY.md** describing what each crate does and doesn't guarantee.

11. **Add MSRV** (`rust-version`) to `[workspace.package]` and a CI job that tests it.

12. **Decide TLS policy:** either remove `httputil`'s `native-tls` feature, or add explicit bans in `deny.toml`. SUP-P1-B.

### Should do before 0.1.3

13. Document the verifier-side scope of `registry-platform-oidc` (no nonce/at_hash/c_hash; resource-server use only).
14. Add at least one runnable example per public crate (`examples/`).
15. Add doctests on the top-of-funnel API of each crate (`SdJwtIssuer::issue`, `TokenVerifier::verify`, `validate_proof_jwt`, `FetchUrlPolicy::strict`, etc.).
16. Tighten `FetchUrlPolicy` and `CorsPolicy` construction (builder or validating `new`). API-P1-2, API-P1-3.
17. `HolderProofPolicy::default()`: remove or document. API-P1-4.
18. Move `sort_sd_digests` to `pub(crate)`. API-P1-5.
19. Apply `#[non_exhaustive]` to `AuditKeyHasher`. API-P1-6.
20. Tighten OID4VCI proof `aud` to string-only; explicit `NoncePolicy` enum. Standards.

### Polish (after 0.1.3, or batched)

21. Trim stale `deny.toml` entries (3 advisory ignores, 4 license allow entries, 2 allow-git entries). SUP-P2-D/E.
22. Move `getrandom = "0.4"` from sdjwt direct dep to workspace deps. SUP-P2-B.
23. All P2 doc additions (`# Panics`, `# Caution`, spec references, security warnings).
24. Reconsider `jsonwebtoken` long-term: thin Ed25519-only wrapper over `ed25519-dalek` would drop the `rsa` (RUSTSEC-bearing) and EC curve transitive deps. SUP-P1-C.

### Out-of-scope for v0.1 (document deferral)

- Pre-authorized code grant for OID4VCI.
- Batch / deferred / notification endpoints in OID4VCI.
- Decoy digests / array-element disclosures / recursive disclosure in SD-JWT.
- DPoP (RFC 9449), RFC 8414 AS metadata.
- Client-side OAuth/PKCE.

---

## 8. Staff-engineer re-prioritization

A staff-engineer pass (opus) read the lane-by-lane audit above and weighed value (impact) vs. cost (implementation effort + API friction + ongoing maintenance tax). The lane reviewers each had a narrow lens; this is the first whole-picture pass.

### 8.0 Headline

The lane audit silently assumed a crates.io release. `README.md:37,51` and every Cargo.toml's `publish = false` say the **current intended distribution is git tags**. Roughly a third of the §6 P0s only matter if you actually publish, and the audit never asks whether you should. The protocol bugs are real and worth fixing now (SEC-P0-1, SEC-P1-3, SEC-P1-1, SEC-P1-5, SEC-P1-2). The `#[non_exhaustive]` carpet-bombing and the ~407 missing-docs sweep are over-engineered for a 0.1.x git-consumed library where every minor bump is allowed to break.

**Per the decision at the top of this document, 0.1.3 ships on git tags; crates.io is deferred to 0.2.**

### 8.1 Scored table

Value (V) and Cost (C) are 1-5. Verdicts: Keep / Downgrade / Defer / Reject.

#### Audit §6 "must-do" items

| # | Item | V | C | Verdict | Reason |
|---|---|---|---|---|---|
| 1a | SEC-P0-1 alg-mixing gate | 5 | 1 | Keep | Textbook alg-confusion; few lines in `TokenVerifier::new`. |
| 1b | SEC-P1-4 JWK alg vs header alg cross-check | 5 | 1 | Keep | Same finding, same fix; do together. |
| 1c | SEC-P1-3 OID4VCI proof `iss` | 5 | 1 | Keep | OID4VCI §7.2.1.1 MUST; trivial. |
| 1d | SEC-P1-1 `azp` multi-aud enforcement | 4 | 1 | Keep | OIDC Core MUST; trivial. |
| 1e | SEC-P1-2 SD-JWT `typ: "kb+jwt"` + `crit/jku/jwk/x5*` rejection | 4 | 1 | Keep | Cheap; prevents proof substitution. |
| 2 | Remove `Clone` on `PrivateJwk` + `SdJwtIssuer` | 3 | 3 | Downgrade | Right intent, wrong fix; see §8.2. |
| 3 | `#[non_exhaustive]` on **every** public enum + config struct | 2 | 4 | Downgrade | Apply to error enums + clearly-growable configs only; see §8.2. |
| 4 | Path-dep versions to `version.workspace = true` | 2 | 1 | Defer | Only matters if publishing. Trivial when needed. |
| 5 | Remove `_client` dead field from `JwksFetcher` | 3 | 1 | Keep | Misleading constructor param. |
| 6 | `jkt()` canonical JSON + RFC 7638 member check | 4 | 2 | Keep | SEC-P1-5 is real (raw `format!` on attacker-controllable values). |
| 7 | `CredentialOffer::authorization_code` `skip_serializing_if` | 3 | 1 | Keep | One line; wire compliance. |
| 8 | Crate-level docs + Cargo metadata | 2 | 2 | Keep partial | Crate-level `//!` yes (§8.4 #7); `keywords/categories` deferred (no publish). |
| 9 | CHANGELOG to Keep-a-Changelog format covering 0.1.1/0.1.2 | 2 | 1 | Downgrade | Append entries; the format ceremony is cosmetic. |
| 10 | Threat model in SECURITY.md | 2 | 3 | Defer | Useful eventually; not 0.1.3-blocking. |
| 11 | MSRV declaration + CI | 2 | 2 | Downgrade | Pick `rust-version = "1.80"`, skip the MSRV CI job for now. |
| 12 | Decide TLS policy (`native-tls` feature) | 3 | 1 | Keep as deletion | Delete the feature; see §8.2. |

#### Audit §6 "should-do" items

| # | Item | V | C | Verdict | Reason |
|---|---|---|---|---|---|
| 13 | Document OIDC verifier-side scope | 3 | 1 | Keep | One paragraph in `//!`. |
| 14 | Examples per crate | 2 | 4 | Defer | 9 examples is real work; one end-to-end example covering oidc+httputil+sdjwt is enough for v0.1. |
| 15 | Doctests on top-of-funnel APIs | 3 | 3 | Downgrade | 2-3 per high-risk crate (oidc, sdjwt, oid4vci, httputil). Not all crates. |
| 16 | Builder for `FetchUrlPolicy` / `CorsPolicy` | 2 | 3 | Reject builder; keep `pub(crate)` + named ctors | See §8.2. |
| 17 | `HolderProofPolicy::default()` removal | 4 | 1 | Keep | Empty audience silently rejects everything; that's a footgun. |
| 18 | `sort_sd_digests` to `pub(crate)` | 3 | 1 | Keep | Pure internal helper. |
| 19 | `#[non_exhaustive]` on `AuditKeyHasher` | 2 | 2 | Keep | Algorithm enums genuinely grow. |
| 20 | OID4VCI `aud` string-only, explicit `NoncePolicy` enum | 3 | 2 | Keep | Aligns with spec; removes a silent-bypass. |

#### Audit §6 "polish" items

| # | Item | V | C | Verdict | Reason |
|---|---|---|---|---|---|
| 21 | Trim stale `deny.toml` entries | 1 | 1 | Keep | Five-minute cleanup; stale warnings hide real ones. |
| 22 | `getrandom` to workspace deps | 1 | 1 | Keep | One line. |
| 23 | All P2 doc additions (`# Panics`, `# Caution`, spec refs) | 1 | 4 | Defer | Open-ended; pick off opportunistically. |
| 24 | Replace `jsonwebtoken` with thin Ed25519 wrapper | 3 | 5 | Reject for 0.1.3 | See §8.2. Track for 0.2. |

### 8.2 Pushback on specific items

**`#[non_exhaustive]` everywhere → just on the 13 error enums.** At 0.1.x your semver convention (every minor break allowed) already does this work for you. `#[non_exhaustive]` is mainly there to let you add variants in a *patch* without breaking, and it imposes a permanent tax on users (every `match` on `OidcError` or `CorsValidationError` now needs `_ =>`, forever). Apply to the error enums (13 of them) and to clearly-growable configs (`TokenVerifierConfig`, `CredentialIssuerMetadata`, `ProofValidationPolicy`). Skip it on `Audience`, `SigningAlgorithm`, `DidMethod` — the variant set *is* the spec; non-exhaustive there promises less than you can deliver. Skip on small data structs like `Disclosure`, `HolderProofClaims` where adding fields *should* be a break. Audit's list of 17 + 11 = 28 is roughly half what's actually warranted.

**~407 missing-docs → 40-60 docs.** Right v0.1 bar: crate-level `//!` on every crate (only `httpsec` and `oidc` are missing per DOC-P0-2/3, that's the real bug), doc the dangerous entry points with `# Security` blocks (`TokenVerifier::verify` and `allowed_algorithms`, `validate_holder_proof`, `validate_proof_jwt`, `sign`/`verify` in crypto, `FetchUrlPolicy::strict`), and 1-2 doctests on issuance + verification flows. Forcing `#![deny(missing_docs)]` workspace-wide now generates boilerplate comments like "The kid field" that *reduce* signal. The rest fills in iteratively.

**`FetchUrlPolicy` / `CorsPolicy` builders → `pub(crate)` fields + named constructors.** Change the `pub` fields to `pub(crate)`, keep `FetchUrlPolicy::strict()` / `FetchUrlPolicy::dev()` / `CorsPolicy::new(origins).with_credentials(...)`. Smaller, no builder type to maintain, and the only "loss" is the ability for a caller to mutate a strict policy into something insecure, which is exactly what we want to lose.

**`native-tls` feature → just delete it.** No code path in the workspace asks for it (`rg native-tls --type rust` over `src/` returns nothing). The README claim that it serves "consumer flexibility" isn't backed by any callsite. Deletion is the simpler win than committing to it via `deny.toml` bans.

**`jsonwebtoken` deprecation → reject for 0.1.3.** Writing a thin Ed25519-only JWT (sign/verify, header parse, base64url, no `none`) is a security-sensitive rewrite. `crypto::sign`/`verify` already uses `ed25519-dalek` directly; only the `decode`/`decode_header`/`Validation` plumbing in `oidc/lib.rs:9,425-454` depends on `jsonwebtoken`. Tracking issue for 0.2.x. The RUSTSEC is already documented and the algorithm gate is asymmetric.

**`verify_holder_proof` rename → doc-comment banner.** The signature already shows it's a registry-specific envelope, not a generic KB-JWT validator (the `evaluation_id` / `credential_profile` / `disclosure_hash` bindings at `sdjwt/lib.rs:150-156` make that obvious). A `# Note` banner stating "this is not an SD-JWT KB-JWT validator; see [SD-JWT §X]" is sufficient. Renaming forces every caller to change. Doc banner now, rename in 0.2 if at all.

**`Clone` on `PrivateJwk` → keep `Clone`, switch `SdJwtIssuer` to `Arc<PrivateJwk>`.** Removing `Clone` outright breaks `SdJwtIssuer::from_jwk(jwk)` and forces fixture-based tests to clone manually elsewhere. The right answer is `Arc<PrivateJwk>` in `SdJwtIssuer` (`sdjwt/lib.rs:14-17`); the `Clone` derive on `PrivateJwk` can then stay, because callers wanting shared ownership use the `Arc`, and accidental deep clones become rare. Cost: ~20 LoC, one round of test breakage.

### 8.3 What the 5 lane reviewers missed

1. **The publish decision itself.** Five reviewers wrote a 460-line audit assuming crates.io. None noticed that `README.md:37,51` and every Cargo.toml's `publish = false` say the current intended distribution is git tags. If git tags is the model, half the P0s collapse: path-dep versions don't matter; crates.io metadata doesn't matter; `#[non_exhaustive]` matters much less because consumers pin a SHA. **This document's top-of-page decision (git tag through 0.1.x, defer crates.io to 0.2) settles the question.**

2. **9 crates is probably too many for v0.1.** `audit`, `authcommon`, `httpsec`, `crypto`, `httputil` are all leaf crates with no inter-platform deps. Every separate crate is API surface, a Cargo.toml, a README, a publish workflow, and a CHANGELOG burden you pay forever. Consider: collapse `audit` + `authcommon` into `registry-platform-auth`, and a single `registry-platform-vc` umbrella over `crypto` + `oid4vci` + `sdjwt`. Not blocking 0.1.3, but **decide before you publish**; merging crates post-publish is a breaking change.

3. **Crate naming is the wrong shape for a public release.** `registry-platform-*` reads as "internal to project 204" to outside eyes. Nothing in the names hints at OIDC, SD-JWT, SSRF. If you ever publish, names like `ssrf-fetch`, `oidc-verify`, `sd-jwt-vc` serve external readers better; `registry-platform` can be a meta-crate that re-exports. Cheaper now than post-publish.

4. **Workspace-version coupling.** Single workspace version means an SD-JWT spec change forces a bump on `httpsec`. Independent per-crate versioning is the norm in serious crates.io workspaces (tokio family, tower family). If you publish, switch; if you stay on git tags, the coupling doesn't matter.

5. **`registry-platform-testing` should remain `publish = false` permanently.** It ships private JWK material (`testing/lib.rs:350-351`). The audit notes the doc-comment gap; the harder question is whether it should be a crate at all vs. a `[dev-dependencies]` path-only fixture set. Recommendation: keep it as a workspace crate but never include it in any publish plan. Per DOC-P1-8, also add a clear "test only, never deploy" doc on the fixture constants.

6. **No `cargo semver-checks` in CI.** That's the actual tool for the problem `#[non_exhaustive]` is trying to solve. Add it as a CI job and gain real protection rather than the blanket non-exhaustivity tax.

7. **Hidden coupling: `OidcError` and `httputil` errors.** `oidc` wraps `reqwest` errors directly in `OidcError`. If you ever switch HTTP libraries or split the crate, that's a break. Worth thinking about for 0.2 (not 0.1.3).

### 8.4 Tightened "ship-blocking for 0.1.3" list

Given the git-tag distribution decision, the actual blockers are:

1. **Protocol fixes (one PR, all related):** SEC-P0-1 alg-mixing gate + SEC-P1-4 JWK/header alg cross-check, SEC-P1-3 OID4VCI `iss` enforcement, SEC-P1-1 `azp` enforcement, SEC-P1-2 SD-JWT `typ` / `crit` / `jku` / `jwk` / `x5*` rejection.
2. **`jkt()` correctness** (SEC-P1-5): build via `serde_json`, validate required RFC 7638 members.
3. **Drop `HolderProofPolicy::Default`**: silent-reject footgun.
4. **`CredentialOffer::authorization_code` `skip_serializing_if`**: wire compliance.
5. **`Arc<PrivateJwk>` in `SdJwtIssuer`**: intent match without breaking tests.
6. **Remove `_client` dead field from `JwksFetcher`** (still non-breaking).
7. **Crate-level `//!` on `httpsec` and `oidc`** (the only two missing).
8. **CHANGELOG entries for 0.1.1 + 0.1.2**: plain bullets are fine; full Keep-a-Changelog ceremony deferred.
9. **`#[non_exhaustive]` on the 13 error enums only**: skip the config-struct sweep and the spec-derived enums.
10. **Delete the `native-tls` feature from `httputil`**: unused; deletion is the simpler win than enforcing rustls-only via `deny.toml` bans.

Deferred to 0.2 (or whenever crates.io publish is decided): per-crate `description`/`keywords`/`categories`/`documentation`, path-dep workspace versioning, crate-naming reconsideration, crate-count consolidation, full CHANGELOG format, MSRV CI job, threat model in SECURITY.md, doctest sweep, examples directory, `jsonwebtoken` replacement, semver-checks CI, all P2 docs.

---

## 9. Appendix: spec versions targeted

- **OIDC Core 1.0 final**
- **RFC 7519 / 7515 / 7517 / 7518** (JWT/JWS/JWK/JWA, final)
- **OpenID for Verifiable Credential Issuance 1.0 (Feb 2025 final)** — confirmed via `dc+sd-jwt`, `openid4vci-proof+jwt` typ, `nonce_endpoint`
- **SD-JWT IETF draft 11+** with **SD-JWT VC** (`dc+sd-jwt` era, post Nov 2024 rename)
- **Ed25519/EdDSA** signing only; **RSA modulus floor 2048** for any RS* JWKs encountered
