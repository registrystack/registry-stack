# Registry Platform Beta Release Security Remediation Spec

- **Date:** 2026-05-30
- **Source audit:** `internal/security-reviews/beta-security-audit-2026-05-30.md`
- **Target release:** first beta tag after `v0.1.2-13-gc549768`
- **Decision rule:** do not tag beta until every P0 item is implemented, tested, documented, and consumed by Registry Notary and Registry Relay where applicable.

## Goals

1. Make the obvious platform API path safe for persistent services.
2. Remove or loudly rename public API paths that are secure only with undocumented caller work.
3. Preserve the strong surfaces already verified by the audit: EdDSA-only platform signing, strict OIDC algorithm selection, DNS-pinned outbound fetches, atomic replay primitives, and bounded HTTP bodies.
4. Provide focused tests that prove the exploit condition from the audit is closed, not just that the happy path still works.

## Non-Goals

- Do not redesign consumer authorization, tenant isolation, or business policy in this repo.
- Do not add broad refactors unrelated to the audited security surfaces.
- Do not make consumer-only config choices in this repo, except for compatibility notes and release-gate checks.
- Do not attempt general RFC 8785 number canonicalization unless a P0 fix introduces number-bearing canonical input.

## Release Gates

The beta tag is blocked until:

1. `cargo fmt --check` passes.
2. `cargo build --workspace --all-targets --all-features` passes.
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
4. `cargo test --workspace --all-targets --all-features` passes.
5. `cargo deny check` passes, with advisory ignore rationale updated.
6. `gitleaks dir --no-banner --redact --verbose --timeout 120 .` passes with the existing `target/` allowlist.
7. Registry Notary and Registry Relay build and test against the new platform tag or local path override for every changed public API they use.

## P0 Remediation Work

### P0.1 Audit Chain Integrity And File Privacy

**Findings:** M1, L1, L2, L3

**Crate:** `registry-platform-audit`

**Problem:**

- `ChainState` and `AuditEnvelope` hash records with unkeyed SHA-256.
- `verify_chain` validates internal consistency but cannot detect a full retained-log rewrite.
- `JsonlFileSink` creates logs and directories with process umask defaults, commonly `0644` files and `0755` directories.
- Rustdoc and README wording can overstate the guarantee of an unanchored chain.
- `ChainState::bootstrap` over non-tailable sinks such as stdout or syslog silently starts from genesis on every process restart.

**Required behavior:**

1. Replace the default chain-construction path with an explicit chain hash mode.
2. Provide a keyed production chain mode using HMAC-SHA256 over the existing `HashInput`.
3. Keep an explicitly named unkeyed mode only for tests and local fixtures, for example `AuditChainHasher::unkeyed_dev_only()`.
4. Remove `Default` from production-facing chain state if it would produce an unkeyed chain.
5. Verification APIs must make hash mode explicit:
   - keyed verification must require the same secret or chain hasher.
   - unkeyed verification must use an explicitly named dev-only function or hasher.
   - anchored verification remains supported because anchors still detect truncation, replacement by actors with the key, and retained-set substitution.
6. File sink creation must use restrictive permissions on Unix:
   - audit files: `0600`
   - parent directories created by the sink: `0700`
   - non-Unix platforms keep current behavior behind `cfg(not(unix))` and document the limitation.
7. Documentation must say:
   - unanchored verification proves internal consistency over retained records only.
   - keyed chains protect against a file writer that lacks the HMAC secret.
   - off-host anchors are still required for stronger continuity evidence.
8. Bootstrapping over a non-tailable sink must be explicit. Either return a typed error from production bootstrap, or require the caller to provide an external anchor or an explicit dev-only genesis restart mode.

**Implementation notes:**

- Prefer reusing `AuditHashSecret` as the secret carrier, but avoid confusing the redaction hasher with the chain hasher. A distinct type such as `AuditChainHasher` is acceptable.
- Include domain separation in the keyed MAC input or key context, for example `"registry-platform-audit-chain-v1"`.
- Preserve `AuditEnvelope.record_hash` as 32 bytes unless a format-version field is required for compatibility.
- If supporting legacy unkeyed verification, name it as legacy or dev-only and make tests assert the name is intentional.
- Existing unkeyed pre-beta JSONL chains are not required to verify under the keyed verifier. If legacy verification is retained, it must be opt-in by name and documented as a migration-only path.

**Tests:**

- A full rewrite of keyed JSONL records fails verification when the attacker does not know the secret.
- Keyed verification succeeds for records produced with the same secret.
- Keyed verification fails with the wrong secret.
- Unkeyed/dev verification remains available only through the explicit dev-only path.
- `JsonlFileSink` creates a new file with mode `0600` on Unix.
- `JsonlFileSink` creates missing parent directories with mode `0700` on Unix.
- Production bootstrap over `JsonlStdoutSink` and `SyslogSink` does not silently restart from genesis.
- Rustdoc examples use the keyed or anchored path for persistent deployments.

**Consumer rollout:**

- Relay and Notary must pass an audit chain secret or use the new anchored production path before the beta tag.
- Existing demo/test fixtures may opt into the dev-only unkeyed mode by name.

### P0.2 Replay Store Defaults And Durability Signaling

**Findings:** M2, M3

**Crates:** `registry-platform-replay`, `registry-platform-cache`

**Problem:**

- `InMemoryReplayStore::new()` is zero-arg, implements `Default`, and creates an unbounded `InMemoryCacheStore`.
- Redis support is feature-gated off by default, making the ephemeral store the only backend in a default dependency build.
- The type name does not make non-durability and single-process scope hard to miss.

**Required behavior:**

1. Bound the in-memory one-time replay store by default.
2. Add a constructor that lets tests and small deployments choose a custom cap, for example `with_max_entries(max_entries)`.
3. Choose a default cap aligned with `InMemoryConsumableNonceStore` unless evidence supports a different value.
4. Remove or deprecate `Default` if it hides the cap and durability caveat.
5. Rename, alias, or document the in-memory store so the call site says it is ephemeral and single-process. A breaking rename is acceptable before beta if consumer migration is done in the same release.
6. Keep Redis behind a feature if desired, but expose a compile-time or builder-level backend choice that makes production callers consciously select durable or ephemeral behavior.

**Implementation notes:**

- A minimal safe change is `InMemoryReplayStore::new()` returning a capped store and `InMemoryReplayStore::with_max_entries(...)` for explicit sizing.
- A stronger API change is `EphemeralSingleProcessReplayStore` with a type alias only for one release.
- Do not silently evict unexpired replay keys on overflow. Return a store-full error so callers fail closed.
- The in-memory cap is a dev/test backstop, not a production-grade DoS defense. A full cap still lets an attacker deny legitimate replay-checked work at the cap; production deployments must use a durable shared backend such as Redis.

**Tests:**

- Default in-memory replay rejects the `(cap + 1)`th distinct unexpired replay key.
- Expired entries are purged before capacity is enforced.
- `with_max_entries(1)` rejects a second live key.
- Redis-backed `insert_once` behavior remains atomic under concurrent calls.
- Notary integration tests still deny repeated proof `jti` values.

**Consumer rollout:**

- Notary must refuse production readiness when configured with the ephemeral store, or mark readiness degraded in a way operators cannot miss.
- Relay currently does not depend on replay, but its build must remain unaffected.

### P0.3 OID4VCI Proof Freshness And Single-Use Nonces

**Findings:** M4, M5, I3

**Crate:** `registry-platform-oid4vci`

**Problem:**

- `ProofValidationPolicy.expected_nonce: Option<&str>` lets callers pass `None`, which disables server-challenge freshness.
- `validate_proof_jwt` returns the same success shape whether or not nonce replay protection is wired.
- The crate documents replay as caller responsibility but does not provide a safe integrated path.
- The policy has no issuer-key or forbidden-key input, so it cannot reject a proof where the holder key equals an issuer verification key.

**Required behavior:**

1. Make the challenged proof path the default and ergonomic API.
2. Add a function or policy shape that requires an expected nonce for production proof validation.
3. Integrate nonce consumption with `registry-platform-replay`, or accept a small trait that can consume a nonce atomically.
4. Return a success type that proves the nonce was checked and consumed, or a distinct type for intentionally unchallenged proofs.
5. Keep any no-nonce validation behind an explicitly named method such as `validate_proof_jwt_without_nonce_dev_only` or `validate_unchallenged_proof_jwt`.
6. Reject proofs with missing `exp` on the unchallenged path. For challenged proofs, keep `iat` plus `max_lifetime` only if the nonce is single-use and freshly issued.
7. Add an optional forbidden-key input, or equivalent policy hook, that rejects holder keys matching issuer keys when the caller has issuer keys available.

**Implementation notes:**

- The replay crate already has `ConsumableNonceStore`. Prefer using that primitive rather than adding a second nonce store abstraction.
- Avoid making `oid4vci` depend on Redis directly. Depend on the trait, not the backend.
- Keep test fixtures explicit so they reveal when they are intentionally not using freshness.

**Tests:**

- Production validation fails when the expected nonce is absent.
- Production validation fails when the proof omits the nonce.
- Production validation fails when the nonce was already consumed.
- The same proof cannot validate twice with the integrated nonce consumer.
- A proof whose holder key matches a configured forbidden issuer key is rejected.
- Any intentionally unchallenged validation path has a test name that includes "unchallenged" or "dev".

**Consumer rollout:**

- Wave 0 must confirm whether Notary `/oid4vci/credential` still passes `expected_nonce: None`; if present, that production call site must migrate.
- Notary must consume issued OID4VCI nonces atomically before credential issuance succeeds.

### P0.4 SD-JWT Holder Binding And Conditional Presentation Verification

**Findings:** M6, M7, L7, L8

**Crate:** `registry-platform-sdjwt`

**Problem:**

- The crate issues SD-JWTs and validates KB-JWT holder proofs, but it does not verify SD-JWT presentations.
- `validate_holder_proof` trusts caller-supplied `holder_jwk`, `disclosure_hash`, and `claim_set`.
- The crate does not compute the canonical SD-JWT `sd_hash` over the presented issuer JWT and disclosures.
- Issuance accepts disclosure names that collide with protected claims.

**Required behavior:**

1. Wave 0 must confirm whether Relay or Notary accepts SD-JWT presentations. If either consumer does, presentation verification is beta-blocking under this P0. If neither does, the full presentation verifier moves to P1, but the holder-binding and issuance-collision fixes in this section remain P0.
2. Add a presentation verifier when presentation acceptance is in scope. It must:
   - parse compact SD-JWT presentation strings.
   - verify the issuer JWT signature against an issuer public JWK or trusted key resolver.
   - require the `typ` emitted by `SdJwtIssuer::issue` and any explicitly supported legacy/project-approved SD-JWT VC type.
   - require `_sd_alg = sha-256`.
   - recompute every disclosure digest as `base64url(SHA-256(encoded_disclosure_bytes))`.
   - reject disclosures whose digest is absent from `_sd`.
   - reject duplicate disclosure names unless the SD-JWT VC profile explicitly allows them.
   - return verified issuer claims, verified disclosures, holder `cnf.jwk`, and canonical presentation bytes needed for KB-JWT binding.
3. Add a helper that computes the holder-binding hash from the actual presentation bytes. Do not require consumers to invent `disclosure_hash`.
4. Add a high-level validation function that verifies presentation plus holder proof together when presentations are in scope:
   - `holder_jwk` must come from the issuer-signed `cnf.jwk`.
   - KB-JWT signature must verify with that key.
   - KB-JWT binding must match the computed presentation hash.
   - `aud`, `iat`, `exp`, `jti`, evaluation id, credential profile, and claim set checks remain enforced.
5. If full presentation verification is deferred because no consumer accepts presentations, still provide a platform-owned binding helper for existing holder-proof users so `disclosure_hash` and `holder_jwk` are not caller-invented.
6. Reject issuance inputs whose disclosure names collide with protected claims:
   - `_sd`
   - `_sd_alg`
   - `cnf`
   - `iss`
   - `sub`
   - `iat`
   - `exp`
   - `vct`
   - `id`
   - `jti`
   - `status`
7. Reject duplicate disclosure names at issuance.

**Implementation notes:**

- Keep `validate_holder_proof` as a low-level primitive only if it is clearly documented as requiring a verified `cnf.jwk` and a platform-computed presentation hash.
- Prefer a high-level `verify_presentation_with_holder_proof` API for consumers when presentation acceptance exists.
- Be explicit about the exact byte input to the holder-binding hash in rustdoc and tests.
- Add a round-trip test proving the verifier accepts the exact `typ` and wire format emitted by `SdJwtIssuer::issue`.

**Tests:**

- A forged disclosure appended to a valid SD-JWT presentation is rejected.
- A disclosure with a digest not present in `_sd` is rejected.
- Issuer signature tampering is rejected.
- A KB-JWT signed by a key not matching issuer-signed `cnf.jwk` is rejected.
- A KB-JWT bound to a different presentation hash is rejected.
- A round-trip SD-JWT issued by this crate verifies under the presentation verifier if that verifier is P0.
- Disclosure names colliding with protected claims are rejected at issuance.
- Duplicate disclosure names are rejected at issuance.

**Consumer rollout:**

- Wave 0 must confirm whether Relay or Notary accept SD-JWT presentations. Any confirmed presentation-acceptance path must migrate to the new high-level presentation verification path.
- Tests using synthetic `disclosure_hash` values must be rewritten to use the platform hash helper.

### P0.5 OIDC Token Type Binding

**Findings:** M8, L5, L6

**Crate:** `registry-platform-oidc`

**Problem:**

- Access-token verification skips `typ` binding when `allowed_typ` is empty.
- ID-token verification accepts missing `typ` and ignores `allowed_typ`.
- UserInfo JWT verification clears required spec claims, allowing no-`exp` UserInfo JWTs.

**Required behavior:**

1. Access-token verification must fail closed when no access-token type policy is provided.
2. Provide safe constructors or config helpers for common token classes:
   - access tokens default to `at+jwt`.
   - ID tokens default to `JWT` and `id_token`, with missing `typ` rejected unless explicitly allowed.
   - UserInfo JWTs have a documented policy for optional `exp`, with an opt-in requirement mode.
3. Do not use one `allowed_typ` vector ambiguously across access, ID, and UserInfo unless the semantics are documented and safe for all three.
4. Keep algorithm, issuer, audience, `exp`, `nbf`, client, and `azp` checks unchanged unless tests prove an intentional behavior change.

**Implementation notes:**

- A clean shape is a `TokenTypePolicy` with separate access, id, and userinfo fields.
- If API churn must be smaller, reject empty `allowed_typ` on `verify_access_token` and add a constructor that fills `at+jwt`.
- Treat UserInfo `exp` as configurable because OIDC UserInfo responses may not always carry it.

**Tests:**

- Access verification rejects a token when access `typ` policy is empty.
- Access verification rejects an ID-token-shaped JWT even when issuer and audience overlap.
- ID-token verification rejects missing `typ` by default.
- ID-token verification accepts configured valid types.
- UserInfo without `exp` follows the configured policy and stays subject-bound to the paired access token.

**Consumer rollout:**

- Wave 0 must confirm whether Relay still has an `allowed_typ: Vec::new()` access-verifier call site; if present, it must migrate before beta.
- Wave 0 must confirm Notary's current OIDC token-type defaults and decide whether access-token endpoints should use `at+jwt` or an explicit compatibility list.

### P0.6 Canonical `did:jwk` Holder Identity

**Findings:** M9

**Crate:** `registry-platform-crypto`

**Problem:**

- `parse_did_jwk` accepts non-canonical JSON encodings.
- The same public key can produce many raw DID strings, which destabilizes `holder_id` in `registry-platform-oid4vci`.

**Required behavior:**

1. `parse_did_jwk` must reject any identifier that does not equal `did_jwk_from_public_jwk(parsed_jwk)`.
2. The comparison must ignore only an allowed fragment after `#`, not differences in the encoded JWK identifier.
3. Unknown public JWK fields must either be rejected or excluded only if canonical re-encoding proves the exact same DID identifier.
4. The implementation must deliberately choose one interoperability policy:
   - minimal-only: reject `use`, `key_ops`, `alg`, `kid`, and other non-thumbprint members in `did:jwk` identifiers.
   - known-safe stripping: accept a documented safe member set only after deriving and comparing a stable canonical holder identity.

**Tests:**

- Canonical `did:jwk` parses.
- Reordered JSON member encoding is rejected unless it exactly matches platform canonical output.
- Whitespace-variant encoding is rejected.
- Extra ignored public members are rejected.
- Representative wallet-emitted `did:jwk` values with `use`, `key_ops`, `alg`, or `kid` are covered by compatibility tests that assert the chosen policy.
- `oid4vci::ValidatedProof.holder_id` is canonical for `did:jwk` proofs.

**Consumer rollout:**

- Consumers storing holder IDs must expect canonical DID strings after the platform tag bump.

### P0.7 SSRF-Safe Fetch API Shape

**Findings:** M10, L10, I6

**Crate:** `registry-platform-httputil`

**Problem:**

- `FetchUrlPolicy::validate()` resolves DNS and discards the pin.
- A caller can accidentally validate with one DNS answer and fetch with another.
- HTTP clients use a total timeout but no connect timeout.
- `OutboundClientBuilder::build()` can be mistaken for an SSRF guard.

**Required behavior:**

1. Deprecate, remove, or rename `FetchUrlPolicy::validate()` so the name no longer implies SSRF safety.
2. Make the DNS-pinned path the ergonomic path:
   - `validate_for_immediate_fetch_with_timeout`
   - `ValidatedFetchUrl::immediate_get_with_timeout`
3. Add `connect_timeout` to outbound clients and validated immediate clients.
4. Document clearly that `OutboundClientBuilder::build()` does not validate target URLs.

**Implementation notes:**

- If keeping compatibility, use `#[deprecated(note = "...")]` and rename the helper to `validate_shape_only` or `validate_without_fetch_pin`.
- Keep tests that assert the secure path uses `resolve_to_addrs`.

**Tests:**

- Compilation emits a deprecation warning for old `validate()` call sites if the method remains.
- Rustdoc for `build()` links to `FetchUrlPolicy`.
- Immediate fetch uses pinned addrs.
- Client builders set both total timeout and connect timeout.

**Consumer rollout:**

- Audit Relay and Notary for `FetchUrlPolicy::validate()` and migrate any runtime fetch guard to `ValidatedFetchUrl`.

### P0.8 Testing Crate Production Gating

**Findings:** M11

**Crate:** `registry-platform-testing`

**Problem:**

- The testing crate is a normal library and exports fixture private JWK material and token-minting helpers.
- Today consumers keep it under dev dependencies, but the platform provides no compile-time guard.

**Required behavior:**

1. Gate the crate behind an explicit feature, for example `test-utils`.
2. The crate must fail to compile in normal dependency mode with a clear message unless `test-utils` is enabled.
3. Fixture private JWK constants must not be exported unless the gate is active.
4. README and rustdoc must say the crate is for tests only and must not be used in production dependencies.
5. Consider removing `registry-platform-testing` from consumer `[workspace.dependencies]` declarations if that makes accidental promotion less likely.

**Implementation notes:**

- Pick one non-all-features behavior deliberately: either `compile_error!` without `test-utils` for a clear message, or an empty crate for plain workspace builds with documented unresolved-import behavior. The release gate uses `--all-features`, so add a focused check for the chosen non-all-features behavior.
- Keep `publish = false`.

**Tests:**

- `cargo build -p registry-platform-testing --features test-utils` succeeds.
- A compile-fail or CI check proves the crate cannot be used without the feature.
- Workspace tests that need fixtures enable the feature explicitly.

**Consumer rollout:**

- Notary dev-dependency usage must enable `features = ["test-utils"]`.
- Relay currently does not depend on the testing crate.

## P1 Same-Release Hardening

These should land in the same beta release if they are small after P0 work is in review. They may be deferred only with an explicit release note and issue.

1. **Replay consume wrapper (L4):** add `require_consume_once` mirroring `require_insert_once`.
2. **PrivateJwk serialization (L9):** remove `Serialize` from `PrivateJwk` or manually serialize without private members.
3. **HTTP security defaults (L11-L14, I8):**
   - narrow empty CORS allowed headers or require explicit wildcard opt-in.
   - add optional HSTS with a production helper.
   - add COOP and COEP helpers with escape hatches.
   - add `request_body_limit_default()` at 1 MiB.
   - add `CorsPolicy::try_layer() -> Result<_, CorsValidationError>`.
   - document that `Problem::detail` and `with_extra` must receive user-safe strings, or add a builder that separates public detail from server-logged cause (I7).
4. **Discovery host binding (I2):** add an optional same-host or same-site `jwks_uri` policy.
5. **Advisory rationale (I1):** update `deny.toml` comments for RUSTSEC-2023-0071 and mark consumer-preemptive ignores.
6. **API key entropy (I9):** document ASCII input or reject non-ASCII API key material.
7. **SD-JWT presentation verifier (M6, if Wave 0 confirms no presentation acceptance):** build the full verifier after beta with the same tests listed in P0.4, rather than rushing a new verifier into the beta gate when no consumer uses it.

## Explicit Accepted Risks

These findings are accounted for but are not implementation work before beta unless new evidence appears:

1. **I4 PrivateJwk expanded-key zeroization:** accepted risk. `d` is zeroized directly, `sign` uses a `Zeroizing` seed buffer, and expanded-key clearing relies on the `ed25519-dalek` v2 zeroization behavior. Action before beta: add a source comment or rustdoc note if the implementation touches this code.
2. **I5 canonicalize_json float formatting:** accepted risk. Current public DID/JWK canonicalization inputs are string/object material, not floats. Action before beta: keep the Non-Goal and narrow docs if the canonicalizer is not intended as a general RFC 8785 implementation.

## Finding Disposition Map

Every audit finding is assigned before implementation starts:

| Finding(s) | Disposition |
| --- | --- |
| M1, L1, L2, L3 | P0.1 |
| M2, M3 | P0.2 |
| M4, M5, I3 | P0.3 |
| M6 | Conditional P0.4 if Wave 0 confirms presentation acceptance; otherwise P1 design/build |
| M7, L7, L8 | P0.4 |
| M8, L5, L6 | P0.5 |
| M9 | P0.6 |
| M10, L10, I6 | P0.7 |
| M11 | P0.8 |
| L4 | P1 replay consume wrapper |
| L9 | P1 private JWK serialization |
| L11, L12, L13, L14, I7, I8 | P1 HTTP security defaults |
| I1 | P1 advisory rationale |
| I2 | P1 discovery host binding |
| I9 | P1 API key entropy |
| I4, I5 | Accepted risk |

## Compatibility And Migration Policy

1. This is pre-1.0 and pre-beta, so breaking API changes are allowed when they make unsafe states unrepresentable.
2. Prefer safe constructors over `Default` for security-sensitive types.
3. Deprecated APIs may remain for one tag only if they:
   - emit compiler warnings.
   - are not used by Relay or Notary at the beta tag.
   - have rustdoc naming the safe replacement.
4. Consumer migrations must be part of the release checklist for any changed API.

## Consumer Release Checklist

Before tagging beta:

1. Registry Notary builds against the platform change.
2. Registry Relay builds against the platform change.
3. If Wave 0 confirms the call site exists, Notary no longer passes `expected_nonce: None` on production OID4VCI issuance.
4. Notary production readiness refuses or clearly degrades on ephemeral replay storage.
5. If Wave 0 confirms the call site exists, Relay no longer creates OIDC access verifiers with an empty access-token type policy.
6. Relay and Notary use the new SD-JWT presentation verifier for any confirmed presentation acceptance path.
7. Relay and Notary use keyed or anchored audit chains for persistent audit sinks.
8. No release dependency includes `registry-platform-testing` without the explicit test-utils feature and dev-only scope.

## Definition Of Done

The remediation is complete only when every item below is true and recorded in the release PR or release checklist:

1. **P0 implementation closure:** P0.1 through P0.8 each have code changes merged in the named crate(s), or an explicit written exception approved before beta. No P0 item may be marked complete by documentation alone.
2. **Regression proof:** each P0 item has at least one focused automated regression test that demonstrates the audited exploit condition is closed. For every P0 item, the test name, file path, and command that runs it are listed in the release checklist.
3. **Negative and positive coverage:** each changed verifier or guard has both an accepting test for the intended safe path and a rejecting test for the unsafe path named in the audit.
4. **No hidden unsafe default:** no production-facing public constructor, `Default` impl, or zero-arg helper can produce the unsafe P0 behavior. Any retained compatibility path is named `legacy`, `dev_only`, `unchallenged`, `ephemeral`, or equivalent, has rustdoc warning text, and is unused by Relay and Notary production code.
5. **Public API documentation:** every changed public type, function, feature flag, or constructor has rustdoc, and every affected crate README shows the production-safe path. Documentation examples compile or are covered by tests.
6. **Platform verification commands:** these commands pass from the `registry-platform` root with no local-only environment assumptions:
   - `cargo fmt --check`
   - `cargo build --workspace --all-targets --all-features`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-targets --all-features`
   - `cargo deny check`
   - `gitleaks dir --no-banner --redact --verbose --timeout 120 .`
7. **Consumer compile verification:** Registry Notary and Registry Relay both build against the remediated platform revision by tag or local path override. The exact consumer commit, platform revision, command, and result are recorded.
8. **Consumer behavior verification:** focused consumer tests or grep-backed review prove all of the following:
   - Notary production OID4VCI issuance does not pass `expected_nonce: None`.
   - Notary production readiness fails or reports degraded status for ephemeral replay storage.
   - Relay does not construct an access-token verifier with an empty access-token type policy.
   - Relay and Notary presentation-acceptance paths use the platform SD-JWT presentation verifier rather than caller-invented `disclosure_hash` binding.
   - Relay and Notary persistent audit sinks use keyed or anchored audit verification.
   - No release dependency includes `registry-platform-testing` outside dev/test scope or without the explicit test feature.
9. **Release notes:** release notes name every operator-visible migration: audit chain secret or anchor requirement, replay backend expectations, OID4VCI nonce requirement, SD-JWT presentation verification behavior, OIDC token type policy requirement, and testing-crate feature gating.
10. **Audit status update:** `internal/security-reviews/beta-security-audit-2026-05-30.md` has a final status section listing all 34 findings as `fixed`, `deferred`, or `accepted risk`, with the commit or PR reference for fixed items.
11. **Review sign-off:** a final code-review pass records no open P0 defects, no untested P0 behavior changes, and no unrelated dirty-file changes mixed into the remediation.

## Implementation Plan

### Wave 0 - Baseline And Work Split

- Assign independent workers:
  - Worker A: audit chain and file permissions.
  - Worker B: replay/cache and OID4VCI nonce integration.
  - Worker C: SD-JWT presentation and holder binding.
  - Worker D: OIDC token type policy, `did:jwk`, httputil, and testing crate gating.
  - Worker E: consumer call-site inventory and final review.
- Capture current failing or missing regression tests for each P0 item before implementation.
- Record baseline platform revision and consumer revisions.
- Confirm whether consumer call sites named in this spec still exist, including Notary `expected_nonce: None`, Relay empty access-token type policy, Notary OIDC token-type defaults, and any Relay/Notary SD-JWT presentation-acceptance path.

**Wave 0 DoD:**

- A checklist maps P0.1 through P0.8 to an owner, crate paths, planned tests, and consumer touchpoints.
- The checklist records all 34 findings with a disposition from the Finding Disposition Map.
- Baseline commands attempted: `cargo test --workspace --all-targets --all-features` in platform, plus focused consumer grep for impacted call sites.
- Consumer call-site facts are marked `confirmed present`, `confirmed absent`, or `needs source review`; none remain as unverified assumptions.
- No code is marked fixed in the audit.

**Review checkpoint:** parent review confirms the work split has no overlapping write ownership except documented integration files.

### Wave 1 - Platform Unsafe Defaults

- Worker A implements P0.1.
- Worker B implements P0.2.
- Worker D implements P0.6, P0.7, and P0.8.
- Workers run focused crate tests before handing off.

**Wave 1 DoD:**

- P0.1, P0.2, P0.6, P0.7, and P0.8 have focused positive and negative tests.
- `cargo test -p` passes for `audit`, `replay`, `cache`, `crypto`, `httputil`, and `testing`.
- Deprecated or renamed APIs have rustdoc replacements.
- No Relay or Notary production call site still uses the old unsafe API where the platform API changed.

**Review checkpoint:** code review verifies API shape, migration burden, test names, and docs before Wave 2 starts. Findings cannot be marked fixed until consumer compile impact is known.

### Wave 2 - Protocol Verification Paths

- Worker B implements P0.3.
- Worker C implements P0.4 holder-binding and issuance-collision fixes; full presentation verification is included only if Wave 0 confirms a presentation-acceptance path, otherwise Worker C records the P1 design/build follow-up.
- Worker D implements P0.5.
- Worker E prepares consumer migration patches or explicit compatibility notes for changed APIs.

**Wave 2 DoD:**

- OID4VCI proof validation requires and consumes a nonce on the production path.
- SD-JWT holder proof verification rejects wrong `cnf.jwk` and wrong presentation binding; if presentation acceptance is confirmed, presentation verification also rejects forged disclosures.
- OIDC access verification rejects empty access-token type policy and rejects token-type confusion.
- Focused crate tests pass for `oid4vci`, `sdjwt`, `oidc`, `replay`, and `crypto`.
- All changed APIs have README and rustdoc examples for the safe path, and the M6 disposition is recorded as P0 fixed or P1 deferred based on Wave 0 evidence.

**Review checkpoint:** security review traces each protocol exploit from the audit to a failing pre-fix test and passing post-fix test. No protocol item is marked done without that trace.

### Wave 3 - Consumer Migration And Full Verification

- Worker E migrates or verifies Relay and Notary call sites.
- Workers A-D handle breakages in their owned platform crates.
- Run platform release gates and focused consumer checks.

**Wave 3 DoD:**

- All platform release-gate commands in the Definition Of Done pass.
- Relay and Notary build against the remediated platform revision.
- Focused consumer tests or grep-backed review prove every item in Definition Of Done item 8.
- Release notes and the audit status section are updated.

**Review checkpoint:** final code-review pass checks platform diff, consumer migration evidence, command output, and audit status. Beta is not taggable until every P0 row is `fixed` or has an approved written exception.
