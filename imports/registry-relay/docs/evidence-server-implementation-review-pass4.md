# Evidence Server Implementation Review, Pass 4

Date: 2026-05-22
Reviewers: 4 parallel sub-agents (DoD conformance, security/disclosure, CEL/sources/connector, code quality)
Claim under review: "95%+ ready now."
Verdict: **NOT 95%. Closer to 77-82% DONE on DoD, with clippy still failing, one regression introduced since pass-3, and a small set of hard MISSING items.**

This pass re-evaluates the work against `docs/evidence-server-spec.md` (lines
2026-2198 are the Definition of Done) and against the pass-3 findings in
`docs/evidence-server-implementation-review-pass3.md`. All paths are absolute.
All citations are reproducible against the working tree at the review date.

## Executive Summary

Verifiable, hard facts first:

| Check | Pass-3 Result | Pass-4 Result |
| --- | --- | --- |
| `cargo check --workspace --all-features` | PASS | PASS |
| `cargo fmt --check` | PASS (nightly-only directive warnings) | PASS (same warnings) |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | FAIL (2 `too_many_arguments`) | **FAIL (6 errors)** |
| `cargo test --test evidence_api` (default parallel) | FAIL (0/23, env race) | **PASS (24/24)** |
| `cargo test --workspace --all-features` | not measured in pass-3 | **FAIL (1 test panic in `tests/config_loader.rs`)** |
| Required Capabilities (36) | 28 DONE, 7 PARTIAL, 1 MISSING | **29 DONE, 6 PARTIAL, 1 MISSING** |
| Required Tests (37) | 22 DONE, 11 PARTIAL, 4 MISSING (+1 failing) | **23 DONE, 10 PARTIAL, 4 MISSING** |
| Not Done If (17) | 17 OK | 17 OK |
| DoD totals (90) | 67 DONE (74%), 18 PARTIAL (20%), 5 MISSING (6%) | **69 DONE (77%), 16 PARTIAL (18%), 5 MISSING (6%)** |

Net progress since pass-3: roughly +3 percentage points on DoD coverage, plus
two material security fixes (CEL allowlist, PoP replay). The clippy regression
moves CI further from green than it was at pass-3 (6 errors vs 2). One new
atomicity bug was introduced in the credential-issuance path.

## Build, Test, And Lint Verification

### 1. `cargo check --workspace --all-features`

PASS.

### 2. `cargo fmt --check`

PASS. Same 20 nightly-only `imports_granularity = Crate` warnings as pass-3.

### 3. `cargo clippy --workspace --all-features --all-targets -- -D warnings`

**FAIL with 6 errors:**

| Error | Location |
| --- | --- |
| `useless_conversion` (`Error::from(error)` on same type) | `src/api/evidence.rs:58` |
| `useless_conversion` | `src/api/evidence.rs:69` |
| `useless_conversion` | `src/api/evidence.rs:97` |
| `useless_conversion` | `src/api/evidence.rs:342` |
| `too_many_arguments` (8/7) on `fn validate_evidence_bound_field` | `src/config/validate.rs:708` |
| `derivable_impls` on `Default for EvidenceVerificationConfig` | `src/config/mod.rs:101` |

Pass-3's `too_many_arguments` errors in `crates/evidence-server/src/runtime.rs`
are fixed (bundled into request structs). New lint failures were introduced
during refactor. Net regression.

### 4. `cargo test --test evidence_api`

PASS. **24/24 in default parallel mode**, including the pass-3 race-condition
victim (`discovery_filters_claims_by_caller_authorization`) and the new
`credential_issue_rejects_replayed_holder_proof`. The env-race that broke
parallel testing in pass-3 no longer reproduces in practice on this machine,
but the underlying cause (per-test `env::set_var` on a global) is unaddressed.
See `tests/evidence_api.rs:62` and Code-Quality Issue Q1 below.

### 5. `cargo test --workspace --all-features`

**FAIL.** `tests/config_loader.rs:1071`
`evidence_dci_source_bindings_must_reference_named_spdci_registry` panics:

```
DCI evidence binding with named SP DCI registry loads: Config(ValidationError)
```

`tests/config_loader.rs:71 passed; 1 failed`. The test expects a *valid* DCI
evidence binding with a named SP DCI registry to load cleanly; instead the
config layer rejects it with a validation error. This is a real regression in
the DCI binding code path and contradicts Capability #6 ("date-of-birth via DCI
or CRVS-profiled DCI connector"). The pass-3 review only ran
`cargo test --test evidence_api` and `cargo test --package evidence-{core,server}`
and missed this failure. Library-crate tests in `evidence-core` remain 2 (only
`sd_jwt::tests`); `evidence-server` library crate still has zero unit tests.

## DoD Conformance Walk

Subtotals: **29/36 capabilities, 23/37 tests, 17/17 negative clauses.**

### Items Closed Since Pass-3

| # | Item | Pass-3 -> Pass-4 | Evidence |
| --- | --- | --- | --- |
| Cap. #10 | CEL feature allowlist | PARTIAL -> DONE | `runtime.rs:644-697` `expression_violates_cel_policy` is now an AST walk over `cel::common::ast::IdedExpr`, with a positive function-name allowlist and `Expr::Comprehension(_) => true` to block comprehensions. |
| Test #22 | CEL rejection for regex matching | PARTIAL -> DONE | `tests/evidence_api.rs:863-874` exercises both `value.matches('.*')` and `text_matches(...)` and asserts 400 `request.invalid`. |
| Test #21 | CEL rejection for disallowed functions | MISSING -> PARTIAL | The AST walk blocks disallowed functions; undeclared variable/field references still fall through to runtime-evaluation failure rather than a clean `request.invalid`. No test for undeclared fields. |
| Sec. H1 | Holder PoP replay | OPEN -> FIXED | `evidence.rs:554-582` extracts `jti`, enforces `iat` skew (-120s/+30s), and builds a scoped `replay_key = client_id:evaluation_id:profile_id:holder_id:jti`. `runtime.rs:150-166` `record_holder_proof` uses `Mutex<HashMap>` with `records.retain(...)` to evict expired entries on every write. New test `credential_issue_rejects_replayed_holder_proof` (`tests/evidence_api.rs:1235-1275`) covers it. |
| Sec. H4 | Idempotency hash non-canonical | OPEN -> SUFFICIENT | `hash_json` (`runtime.rs:888-891`) still uses `serde_json::to_vec`, but the inputs are derive-Serialize structs with stable field order, scoped by `principal_id + sha256(client_key)`. Adequate for the v0 contract. |
| Sec. H5 | CEL allowlist substring scan | OPEN -> FIXED | Same evidence as Cap. #10 above. |
| Sec. M1 | Render audit `claim_hash` | OPEN -> FIXED | `evidence.rs:308-315` now derives consistently from `requested_claims.as_deref().unwrap_or(&[])`. |

### Items That Remain PARTIAL or MISSING

| # | Item | Status | Evidence |
| --- | --- | --- | --- |
| Cap. #6 | DCI vs CRVS-profiled DCI fixture | PARTIAL | `src/evidence/registry_relay.rs` has distinct `read_dci_one` and `read_registry_data_api_one`, but both converge on local `EntityQueryEngine`. No DCI Search wire client. Defensible under spec's "CRVS-profiled DCI fixture" wording (line 663), and discovery correctly advertises `"production_mapper": false` (`runtime.rs:193`). |
| Cap. #17 | Idempotency window / TTL | PARTIAL | `IdempotencyRecord` (`runtime.rs:58-62`) has no `expires_at`. `insert_idempotent_batch` (`runtime.rs:132-148`) never sets an expiry, never sweeps. Spec line 2063 says "within the configured window". There is no configured window. |
| Cap. #27 | Authentication gates discovery | PARTIAL | `service_document` (`evidence.rs:52-61`), `issuer_jwks` (`evidence.rs:63-79`), and `list_formats` (`evidence.rs:138-153`) accept `Option<Extension<Principal>>` and return 200 to unauthenticated callers. Spec line 2089: "Authentication gates discovery, evaluation, batch, rendering, and credential issuance." |
| Cap. #30 | Metadata conflict signal | PARTIAL | `src/config/validate.rs:708-762` fails the whole config load with `RuntimeBindingError::FieldMissing`. Same code path covers both genuinely missing fields and type/unit mismatches; operator cannot distinguish. `tracing::error!` emits `claim_id` and `field` but not `conflict_reason` or `source_version`. |
| Cap. #31 | Audit on render / authz-fail / source-error | PARTIAL | Audit is attached only on render success (`evidence.rs:308-314`). Failure paths return early with `Error::from(error).into_response()` and never call `attach_evidence_audit`. No test asserts audit on `/evidence/render` or on authz/source-error paths. |
| Cap. #33 | External JSON does not expose internal fields | PARTIAL | `ClaimResultView` excludes `source_versions`, `requester_id`, alt subject ids by shape, but no negative test asserts the absence in response bodies. |
| Cap. #34 | ID Mapper boundary roundtrip | MISSING | `SourceReader::map_subject` (`runtime.rs:24-30`) is a no-op default. `RegistryRelaySourceReader` never overrides it. `id_type` (`crates/evidence-core/src/model.rs:80`) is accepted at the request boundary, threaded into `SubjectRequest`, then silently ignored in `lookup_value` (`registry_relay.rs:153-157`). No demo mapper, no roundtrip test. |
| Test #2 | Issuer-missing state in format discovery | PARTIAL | `runtime.rs:511-528` computes SD-JWT VC status from `!config.credential_profiles.is_empty()`. No test toggles the issuer-missing state and asserts the disabled response. |
| Test #8 | Per-item `evaluation_id` in batch | PARTIAL | `tests/evidence_api.rs:894-911` asserts ordering by status, never asserts the `evaluation_id` field on successful items. |
| Test #15 | Omitted purpose header | PARTIAL | Blank/whitespace purpose tested (`evidence_api.rs:780-792`). Header-absent case not tested. Different code path (`None` from `purpose_header(&headers)` vs trim-check). |
| Test #18 | Metadata conflict at route level | MISSING | Only `tests/config_metadata_bindings.rs:310-343` covers this at config-load level. No Evidence Server route test confirms a claim is disabled or rejected via a route. |
| Test #20 | `meta` CEL binding semantics | PARTIAL | `runtime.rs:741` still emits `("meta".to_string(), json!({}))`. Empty in every evaluation. No test reads from `meta`. Either populate or formally declare empty-for-v0 with a contract test. |
| Test #21 | CEL rejection for undeclared fields | PARTIAL (functions blocked, fields not) | The AST walk does not cross-reference `source.<alias>.<field>` against declared `source_bindings.fields`. Undeclared field references reach runtime and return `RuleEvaluationFailed`, not `request.invalid`. |
| Test #24 | CCCEV structural rendering assertions | PARTIAL | The test only asserts `@graph` is an array (`evidence_api.rs:993-1001`). No assertion on `cccev:` keys. |
| Test #27 | Disclosure downgrade to `default` / `redacted` | MISSING | `runtime.rs:757-797` supports `DisclosureDowngrade::{Default, Redacted, Deny}`. All fixtures use `Deny` (the config default). No test exercises a successful downgrade. |
| Test #28 | Disclosure denial where downgrade is `deny` | PARTIAL | Credential-issuance path tested (`evidence_api.rs:1277-1305`). The evaluate path with a disallowed-but-known profile and downgrade=`deny` is not specifically tested. |
| Test #31 | Purpose / requester mismatch on credential | PARTIAL | Format mismatch and claims mismatch tested (`evidence_api.rs:1337-1378`). Different-purpose and different-requester cases not tested. |
| Test #32 | `jwk` holder binding mode | PARTIAL | Only `did:jwk` exercised. The implementation only resolves `did:jwk:` in `holder_jwk` (`evidence.rs:585-594`). See Security H2 and H3 below. |
| Test #34 | ID Mapper demo roundtrip | MISSING | Same as Cap. #34. |
| Test #36 | Deferred routes stable not-supported errors | PARTIAL | No dedicated test. Test at `evidence_api.rs:932-943` exercises `claim.operation_unsupported`, but that is a per-claim disabled operation, not a server-level deferred feature. |
| Test #37 | Audit assertions on render / authz-fail / source-error | PARTIAL | Strong audit assertions on evaluate, batch, credential issuance. None on `/evidence/render`, none on authz-failure paths, none on source-error paths. |

### Not Done If (17 negative clauses)

All 17 pass on read-only review, unchanged from pass-3.

## Security And Disclosure Review

### Fixed Since Pass-3

- **H1 (PoP replay).** Real fix, real test. See evidence in DoD table above.
- **H4 (idempotency hash).** Acceptable for the v0 scope: structs with derived `Serialize` produce stable field order, and the key is principal-scoped (`runtime.rs:313-319`). Document the boundary.
- **H5 (CEL allowlist).** AST walk with positive allowlist (`runtime.rs:644-697`), `text_matches` and `validate_matches` are blocked, regression test covers both.
- **M1 (render audit hash).** Consistent (`evidence.rs:308-315`).

### Not Fixed Since Pass-3

- **H2. Only `did:jwk:` actually works.** `holder_jwk` (`evidence.rs:585-594`) still hard-requires the `did:jwk:` prefix. A profile configured to allow `did:web` or `did:key` via `allowed_did_methods` (`crates/evidence-core/src/config.rs:299`) will accept the holder id at validation time, then fail PoP with a generic error. Operational foot-gun.
- **M2. Discovery routes unauthenticated.** `service_document`, `issuer_jwks`, `list_formats` are all reachable without a principal. Spec line 2089 says discovery is gated. JWKS being public is fine (public keys); the other two leak service identity, claims URL, batch limit, format catalog.
- **CEL `meta` binding.** Still `json!({})` at `runtime.rs:741`. Latent accuracy bug for any expression that reads from `meta.*`.

### Partial

- **H3. `cnf` always emits `kid`, not `jwk`, regardless of binding mode** (`crates/evidence-core/src/sd_jwt.rs:141-143`). Correct for `did:jwk` (the key is recoverable from the DID). Wrong for the documented `mode: "jwk"` binding (`config.rs:293`) if anyone ever configures it: the credential would be unverifiable by KB-JWT verifiers.
- **H6. Mixed-disclosure evaluations cannot be issued.** `stored_disclosure` (`runtime.rs:874-886`) returns the literal `"mixed"` when claim results span profiles, which fails the binding check at issuance time and cannot be requested by a caller. Multi-claim evaluations across disclosure profiles are functionally dead at issuance. No error surfaced at evaluate time.
- **H7. `EvidenceStore` maps grow unbounded.** `holder_proofs` map self-prunes via `retain` on every write (good). `evaluations` map TTL-checks on `get` but never evicts. `idempotency` map has no expiry field at all. Both leak over time.
- **M3. `holder_jwk` does not reject JWKs with private fields** (`evidence.rs:585-594`). Low exploitability (caller harms themselves), but the holder_id (which is logged and audited as a string) would carry the private key.

### New Since Pass-3

- **NEW-1 (HIGH). `record_holder_proof` is called before `sd_jwt::issue`.** `evidence.rs:418-426` records the holder PoP `jti` as consumed, then attempts to sign the SD-JWT VC. If signing fails for any reason (key misconfigured, RNG error, transient panic in signer), the `jti` is permanently spent and the holder cannot retry without generating a new proof. This is a TOCTOU-style atomicity bug. Fix: attempt issuance first, record proof on success only, or wrap in a transaction.
- **NEW-2 (LOW). Test helper uses `vk.to_bytes()` as `jti`.** `tests/evidence_api.rs:99` derives `jti` from the verifying key bytes. Stable per holder identity. Not a production bug; a test-quality issue that would silently break replay-detection coverage if helpers are reused across test cases.

### Production-Blocking Concerns (Security Angle)

| Severity | Issue | Where |
| --- | --- | --- |
| High | NEW-1: holder PoP `jti` is consumed before issuance succeeds | `src/api/evidence.rs:418-426` |
| High | H2: only `did:jwk:` works, other DID methods silently fail PoP | `src/api/evidence.rs:585-594` |
| Medium | M2: discovery routes unauthenticated | `src/api/evidence.rs:52-61, 138-153` |
| Medium | H7 (partial): `evaluations` and `idempotency` maps unbounded | `crates/evidence-server/src/runtime.rs:92-110, 113-148` |
| Medium | H6: mixed-disclosure evaluations cannot be issued | `crates/evidence-server/src/runtime.rs:874-886` |
| Low | H3: `cnf` always `kid`, not `jwk`, for `mode: "jwk"` | `crates/evidence-core/src/sd_jwt.rs:141-143` |
| Low | M3: holder JWK private-field check missing | `src/api/evidence.rs:585-594` |

## CEL And Source Connector Review

### CEL Allowlist

FIXED. `expression_violates_cel_policy` (`crates/evidence-server/src/runtime.rs:644-697`) replaces the substring scan with an AST walk over `cel::common::ast::IdedExpr`. Positive allowlist of operator/function names (`runtime.rs:649-670`). `Expr::Comprehension(_) => true` blocks comprehensions. Test fixture and assertions: `tests/evidence_api.rs:293-308, 863-874`.

### CEL `meta` Binding

NOT FIXED. `runtime.rs:741` still emits `("meta".to_string(), json!({}))`. Spec lines 2140-2141 require alignment with `cel-mapping` semantics, which includes `meta` as a root binding. Two acceptable resolutions: (a) populate with `service_id`, `api_version`, request time, and field-level type/unit info from `SourceFieldConfig`; or (b) formally declare `meta` as intentionally empty for v0 and add a contract test asserting the empty-object shape.

### CEL Undeclared-Field Rejection

NOT IMPLEMENTED, NOT TESTED. The AST walk does not cross-reference `source.<alias>.<field>` and `claims.<id>` against the declared bindings. An undeclared reference reaches CEL runtime, which returns `RuleEvaluationFailed` rather than a clean `request.invalid`. Spec line 2142 explicitly requires rejection of undeclared fields.

### DCI vs Registry Data API

PARTIAL. `src/evidence/registry_relay.rs:36-44` has distinct `SourceConnectorKind::Dci` and `SourceConnectorKind::RegistryDataApi` branches that route to `read_dci_one` and `read_registry_data_api_one`. Both ultimately call `read_entity_one` against the local `EntityQueryEngine`. The DCI path resolves identifier aliases through `spdci.registries` but does not speak to a remote DCI Search API. Service document correctly flags this with `"production_mapper": false` (`runtime.rs:193`). Defensible under spec line 663, which allows "a generic DCI sync lookup binding" when CRVS DCI wire is unavailable.

### Idempotency TTL

NOT IMPLEMENTED. `IdempotencyRecord` (`runtime.rs:58-62`) has no expiry field; `insert_idempotent_batch` never sets one. Compare with `HolderProofRecord` (`runtime.rs:64-67`), which does carry `expires_at` and is swept on write. Idempotency entries accumulate until process restart.

### Metadata Conflict Handling

PARTIAL. `validate_evidence_bound_field` (`src/config/validate.rs:708-762`) correctly catches type/unit mismatches. However:

1. Behavior is "fail entire config load," not "disable the affected claim." Spec line 2094-2095 says "disables or rejects the affected claim and emits an operator-visible signal." Both readings ("disable specifically" or "reject and refuse to start") are arguably defensible, but the implementation chooses the strongest interpretation without making it visible.
2. Error code is the same (`runtime.binding.field_missing`) for genuinely missing fields and for type/unit mismatches. Operators cannot tell them apart from logs.
3. No route-level test in `tests/evidence_api.rs` (spec required test #18).

### ID Mapper Boundary

MISSING. `SourceReader::map_subject` (`runtime.rs:24-30`) is a no-op default. `RegistryRelaySourceReader` does not override it. No demo mapper, no demo roundtrip test. The `id_type` field on `SubjectRequest` (`crates/evidence-core/src/model.rs:80`) is parsed but never used by the source adapter (`registry_relay.rs:153-157`). Spec required test #34 cannot be satisfied without implementing the boundary.

## Code Quality Review

### Architecture

Mostly clean. `evidence-core` contains only domain types, config, the SD-JWT issuer, and error taxonomy. No HTTP/Axum dependencies. `evidence-server` is a proper library crate, correctly re-exported from `src/evidence/mod.rs`. `src/api/evidence.rs` is a thin HTTP adapter that delegates to `EvidenceRuntime`.

**One architectural boundary violation:** `crates/evidence-core/src/sd_jwt.rs:41` calls `std::env::var` to load the issuer private key by name at request time (via `EvidenceIssuer::from_profile`). Environment-variable reads are infrastructure-layer I/O. They belong at startup/config-load, not inside the domain crate. This is the direct cause of test issue Q1 below.

### Top Code-Quality Issues

| # | Issue | Where |
| --- | --- | --- |
| Q1 | `env::set_var("EVIDENCE_SERVER_TEST_JWK", ...)` per test, not serialized | `tests/evidence_api.rs:62`. Each `#[tokio::test]` writes a fresh random key into a global env var. Tests happen to pass today but only because the timing is incidentally compatible. The pass-3 race-condition root cause is unaddressed. |
| Q2 | Inconsistent error-wrapping convention across handlers | `src/api/evidence.rs:58, 69, 97, 342` (the 4x `useless_conversion`). Some handlers return `error.into_response()` directly; others wrap in `Error::from(error).into_response()`. Symptom: clippy fails. Root cause: the file was written incrementally without a single agreed pattern. |
| Q3 | Vacuous test in `evidence-core` | `crates/evidence-core/src/sd_jwt.rs:236-238`: `assert_eq!("EdDSA", "EdDSA")`. Passes regardless of any change. Wastes a test slot. |
| Q4 | `id_type` accepted but silently ignored | `crates/evidence-core/src/model.rs:80` and `src/evidence/registry_relay.rs:153-157`. See ID Mapper section above. If the mapper is ever wired in, all existing clients sending `id_type: "common_subject_id"` will continue to work; clients sending anything else will silently be treated as raw `subject.id`. Data integrity hazard. |
| Q5 | `EvidenceStore` in-process, in-memory, single Arc per process | `crates/evidence-server/src/runtime.rs:70-74`. Not documented anywhere visible. Restart loses every outstanding `evaluation_id`. Idempotency window is "until process restart". |

### Panics / Unwraps In Request Path

None bare in `src/api/evidence.rs` or hot paths of `crates/evidence-server/src/runtime.rs`. The `expect("is not poisoned")` calls on mutex locks (`runtime.rs:95, 103, 121, 140, 159`) are conventional and correct: a poisoned mutex implies a prior thread panic, and propagating is the right behavior. One `expect("OffsetDateTime within supported RFC3339 range")` at `runtime.rs:866` is technically reachable only on time overflow, which is not a realistic concern.

### Clippy Errors: Isolated Or Symptomatic?

Localized. The 4x `useless_conversion` are concentrated in `src/api/evidence.rs`; the other two are in `src/config/` and reflect housekeeping debt, not Evidence Server logic. The codebase is not broadly sloppy. But the failing build is still a hard CI gate.

## Net Verdict

**The "95%+ ready" claim does not hold.** All four reviewers converge on a band of 75-85% across DoD, security, and code-quality angles. The most rigorous count (DoD line items) places it at **77% DONE, 18% PARTIAL, 6% MISSING.**

Real progress since pass-3:

1. CEL allowlist is a real fix (AST walk replacing substring scan). Two security findings closed in one stroke.
2. Holder PoP replay is a real fix (server-side `jti` ledger plus iat skew plus scoped replay key). New test covers it.
3. Render audit `claim_hash` is now consistent.
4. Integration tests pass cleanly in parallel where pass-3 had a 0/23 race.

Real regressions or new issues:

1. Clippy errors went from 2 to 6 (different files, but a worse total).
2. **NEW-1 (HIGH)**: holder PoP `jti` is consumed before issuance is attempted; any signing failure permanently locks out the holder until they regenerate the proof.
3. **NEW-2 (HIGH)**: `tests/config_loader.rs:1071` `evidence_dci_source_bindings_must_reference_named_spdci_registry` fails. A valid DCI evidence binding with a named SP DCI registry is being rejected at config-load with `Config(ValidationError)`. The pass-3 review only ran the `evidence_api` integration suite and missed this failure. Either the test or the validator is wrong; either way `cargo test --workspace` is red.
4. Test parallelism passes incidentally; root cause (env-var-based key loading) is unaddressed.

Still open from pass-3 (not regressions, but not closed either):

1. CEL `meta` root binding is empty (`runtime.rs:741`).
2. CEL undeclared-field rejection is unimplemented and untested.
3. Idempotency map has no TTL or window.
4. ID Mapper boundary is a no-op default; demo and roundtrip test are absent (spec required test #34).
5. Discovery routes are unauthenticated (spec line 2089).
6. Metadata conflict is whole-config rejection with the same error code as a missing field; no route test.
7. Audit context is not attached on render-failure, authz-failure, or source-error paths.
8. PoP only works for `did:jwk:` (H2); other DID methods silently fail.
9. `cnf` is always `kid`, never `jwk`, regardless of binding mode (H3).
10. Mixed-disclosure evaluations cannot be issued (H6).
11. `EvidenceStore` `evaluations` map has no eviction-on-write (H7 partial).
12. Five Required Tests are MISSING entirely: #18, #27, #34, plus the two from pass-3 that remain.

## Shortest Path To A Defensible "Ready"

Fix in this order, smallest blast radius first:

1. **Fix the 6 clippy errors.** Standardize error wrapping in `src/api/evidence.rs`; bundle args or `#[allow]` with reason on `validate_evidence_bound_field`; replace the manual `Default` impl in `src/config/mod.rs` with `#[derive(Default)]`. Re-run `cargo clippy --workspace --all-features --all-targets -- -D warnings` until green. (< 1 hour.)
2. **Fix the failing config-loader test.** `tests/config_loader.rs:1071`. Determine whether `dci_evidence_body()` + `dci_standards_body()` are constructing a valid binding that the validator wrongly rejects, or whether the test expects too much. Either way, `cargo test --workspace` must be green. (NEW-2.)
3. **Swap call order in `issue_credential`.** `evidence.rs:418-426`: attempt `sd_jwt::issue` first, call `record_holder_proof` only after success. Add a regression test for the failure path. (NEW-1.)
4. **Either authenticate discovery or document the policy.** If discovery is intentionally public, write that into the spec; otherwise add Principal extraction to `service_document` and `list_formats`. Add a route test asserting 401. (Cap. #27 / M2.)
5. **Add idempotency TTL.** Add `expires_at` to `IdempotencyRecord`, sweep in `insert_idempotent_batch` matching the `record_holder_proof` pattern. Add a configurable window. (Cap. #17 / H7 partial.)
6. **Move issuer-key loading out of `evidence-core`.** Resolve `EVIDENCE_SERVER_TEST_JWK` (and prod equivalent) at startup, pass bytes into `EvidenceIssuer`. Remove `env::var` from `sd_jwt.rs`. Drop the per-test `env::set_var` in favor of explicit fixture injection. (Q1, architectural cleanup.)
7. **Implement the ID Mapper demo and roundtrip test.** Override `map_subject` in `RegistryRelaySourceReader` with an explicit `common_subject_id` identity mapper; thread `id_type` through. Add a route test. (Cap. #34 / Test #34, closes the only MISSING capability item.)
8. **Add Required Tests #18, #27, plus the partial-fill tests.** Metadata conflict at route level (#18); disclosure downgrade to `default`/`redacted` (#27); per-item `evaluation_id` assertion (#8); omitted purpose header (#15); purpose/requester mismatch on credential (#31); render audit assertion (#37); deferred-feature stable not-supported (#36); issuer-missing format discovery (#2).
9. **Populate or formally empty `meta`.** Either populate with `service_id`, `api_version`, and field-level type/unit metadata, or write a contract test that asserts the empty-for-v0 shape and add a spec line explicitly stating that. (Test #20.)
10. **Implement undeclared-field rejection in CEL.** Extend `expression_violates_cel_policy` to verify each `source.<alias>.<field>` and `claims.<id>` against the declared bindings; return `InvalidRequest`. Add a test fixture with an undeclared field reference. (Test #21.)
11. **Resolve non-`did:jwk:` DID methods or reject at config-load.** Either implement DID resolution for the methods configured in `allowed_did_methods`, or fail config-load when `allowed_did_methods` contains anything other than `did:jwk:`. (H2.)

That list is eleven items. Most are roughly half-day each. A genuinely "ready" v0 is one focused week of work away. Calling it 95% ready today is not defensible.

## Reproducibility

All commands run from `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/` against the working tree at the review date. Reviewer reports were independent and produced in parallel; this document is the synthesis. File paths and line numbers are exact at review time and will drift as the codebase moves.
