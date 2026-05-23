# Evidence Server Implementation Review, Pass 3

Date: 2026-05-22
Reviewers: 4 parallel agents (DoD conformance, security/disclosure, CEL/sources, build/test verification)
Claim under review: "95%+ ready"
Verdict: **NOT 95%. Closer to 80-85%, with hard CI-breakers and at least three Required-Test bullets unfilled.**

This report consolidates four independent reviews of the Evidence Server
implementation against `docs/evidence-server-spec.md`. All file paths are
absolute. All counts and citations are reproducible against the working tree at
the review date.

## Executive Summary

Verifiable, hard facts first:

| Check | Result |
| --- | --- |
| `cargo check --workspace --all-features` | PASS (12.89s, no warnings) |
| `cargo fmt --check` | PASS (stable-channel `imports_granularity` warning only) |
| `cargo clippy --all-targets -- -D warnings` | **FAIL.** Two `clippy::too_many_arguments` errors in `crates/evidence-server/src/runtime.rs:260` (`batch_evaluate`, 8 args) and `:358` (`evaluate_claim`, 9 args). Could not compile `evidence-server`. |
| `cargo test --test evidence_api` (default parallel) | **FAIL.** 0/23 pass. Every test panics at `tests/evidence_api.rs:477:49: config loads: Config(ValidationError)` because the harness calls `env::set_var("EVIDENCE_SERVER_TEST_JWK", ...)` per-test without serialization, and `config::load` races other threads. |
| `cargo test --test evidence_api -- --test-threads=1` | 22/23 pass. The failing test is `discovery_filters_claims_by_caller_authorization` (assertion: `left=0, right=1`). Discovery filters out the claim the principal should see. Real bug, not a flake. |
| `cargo test --package evidence-core --package evidence-server` | 2 passed, 0 failed (only `sd_jwt::tests` in `evidence-core`). `evidence-server` has no library unit tests. |

Spec conformance verdict (90 line items checked across "Required Capabilities",
"Required Tests", and "Not Done If" clauses): **67 DONE (74%), 18 PARTIAL (20%),
5 MISSING (6%).**

The dev's "95%+ ready" claim does not hold. The shortest path to a defensible
"ready" is listed at the end of this document.

## Build, Test, And Lint Verification

### 1. `cargo check --workspace --all-features`

PASS. Finished cleanly in 12.89s. No errors, no warnings.

### 2. `cargo test --package evidence-core --package evidence-server`

Note: the feature flag `evidence-server-cel` does not exist as written; the
correct form is `--features evidence-server/cel` or the package-feature long
form. Running without extra features:

- `evidence-core`: 2 passed (`sd_jwt::tests::signing_algorithm_header_value_is_stable`, `sd_jwt::tests::disclosure_digest_is_over_encoded_disclosure`)
- `evidence-server`: 0 tests (no unit tests in `lib.rs`)
- Doc-tests: 0 in each crate.

Total: 2 passed, 0 failed.

### 3. `cargo test --test evidence_api`

Default parallelism: 0 passed, 23 failed. Cause: per-test
`env::set_var("EVIDENCE_SERVER_TEST_JWK", ...)` calls race against `config::load`
in parallel threads. Every test panics at:

```
tests/evidence_api.rs:477:49:
config loads: Config(ValidationError)
```

With `--test-threads=1`: 22 passed, 1 failed, 0 ignored. The remaining failure
is `discovery_filters_claims_by_caller_authorization`:

```
thread 'discovery_filters_claims_by_caller_authorization' panicked at tests/evidence_api.rs:616:5:
assertion `left == right` failed
  left: 0
 right: 1
```

The test gives the principal only the `crvs:rows` scope and asserts that
`GET /claims` returns exactly one claim (`date-of-birth`). The actual result is
zero claims, meaning `principal_can_see_claim` (in `runtime.rs:441-450`)
filters out every claim whose required scopes are not held by the principal,
including the one the test expects to be visible. Either the fixture scopes are
wrong or `RegistryRelaySourceReader::required_scopes` resolves the wrong set.
Either way, the assertion is a real regression.

Full list of 23 tests (alphabetical):

1. `batch_evaluate_emits_redacted_partial_failure_audit_record`
2. `batch_idempotency_replays_same_request_and_rejects_conflict`
3. `batch_rejects_too_large_and_unsupported_operation`
4. `batch_returns_per_subject_partial_failure`
5. `credential_issue_emits_redacted_audit_record`
6. `credential_issue_enforces_profile_disclosure_policy`
7. `credential_issue_rejects_format_and_claim_binding_mismatch`
8. `credential_issue_rejects_unsigned_holder_proof`
9. `credential_issue_returns_issuer_not_configured_for_claim_without_profile`
10. `credential_issue_signs_sd_jwt_from_existing_evaluation`
11. `discovery_filters_claims_by_caller_authorization` (FAILING)
12. `discovery_lists_claims_and_formats`
13. `evaluate_computes_cel_claim_from_registry_data`
14. `evaluate_computes_exists_and_cel_source_ctx_vars_claims`
15. `evaluate_emits_useful_redacted_audit_record`
16. `evaluate_enforces_source_evidence_scope`
17. `evaluate_reads_date_of_birth_through_dci_crvs_binding`
18. `evaluate_rejects_minimal_alias_blank_purpose_and_unsupported_format`
19. `evaluate_rejects_unknown_claim_and_disallowed_cel_regex`
20. `evaluate_reports_source_ambiguity`
21. `issuer_jwks_publishes_public_key_only`
22. `render_is_bound_to_original_disclosure`
23. `render_returns_canonical_json_for_scalar_and_boolean_claims`

### 4. `cargo clippy --package evidence-core --package evidence-server --all-targets -- -D warnings`

FAIL. Two errors:

```
error: this function has too many arguments (8/7)
   --> crates/evidence-server/src/runtime.rs:260:5
    |
260 | /     pub async fn batch_evaluate<R: SourceReader>(
    = note: `-D clippy::too-many-arguments` implied by `-D warnings`

error: this function has too many arguments (9/7)
   --> crates/evidence-server/src/runtime.rs:358:5
    |
358 | /     fn evaluate_claim<'a, R: SourceReader>(
```

Both are `clippy::too_many_arguments` on `EvidenceRuntime::batch_evaluate`
(8 args) and `EvidenceRuntime::evaluate_claim` (9 args). The build fails with
"could not compile `evidence-server`". Either bundle the request arguments into
a struct or add `#[allow(clippy::too_many_arguments)]` with a reason.

### 5. `cargo fmt --package evidence-core --package evidence-server -- --check`

PASS. Exit code 0. Two non-fatal warnings:

```
Warning: can't set `imports_granularity = Crate`, unstable features are only available in nightly channel.
```

## DoD v0 Conformance Walk

### Required Capabilities (36 items)

| # | Capability | Status | Evidence |
| --- | --- | --- | --- |
| 1 | `/.well-known/evidence-service` advertises identity, version, ops, formats URL, claim URL, batch limit | DONE | `runtime.rs:139-158`, route `evidence.rs:38` |
| 2 | Discovery advertises `common_subject_id` and `production_mapper: false` | DONE | `runtime.rs:152-155`, test `evidence_api.rs:574-575` |
| 3 | `GET /claims` and `/claims/{claim_id}` filter by authz | DONE | `runtime.rs:160-184`, `registry_relay.rs:441-450`, test `evidence_api.rs:603-618` |
| 4 | `GET /formats` returns JSON, CCCEV, SD-JWT VC status | DONE | `runtime.rs:186-188, 487-503`, test `evidence_api.rs:593-601` |
| 5 | `POST /claims/evaluate` computes `date-of-birth`, `farmed-land-size`, `farmer-under-4ha` | DONE | `runtime.rs:190-258`; fixtures `evidence_api.rs:172-270` |
| 6 | `date-of-birth` via DCI or CRVS-profiled DCI connector | PARTIAL | `SourceConnectorKind::Dci` exists (`config.rs:115`), routed via `read_dci_one` (`registry_relay.rs:76-110`), but the "DCI" path resolves only identifier aliases through `spdci.registries` and then reads from the same local `EntityQueryEngine` as the Registry Data API connector. No DCI Search API client. Defensible if the spec's "CRVS-profiled DCI fixture" wording covers it, but a strict reader will flag this. |
| 7 | `farmed-land-size` via Registry Data API connector | DONE | `registry_relay.rs:60-74`, claim def `evidence_api.rs:203-233` |
| 8 | `farmer-under-4ha` CEL claim derived from `farmed-land-size` | DONE | `evidence_api.rs:234-270`, test `evidence_api.rs:671-693` |
| 9 | `extract`, `exists`, `cel` rule paths implemented | DONE | `runtime.rs:393-410`; tests `evidence_api.rs:695-723, 725-742` |
| 10 | CEL reuses `cel-mapping`/`cel-mapper-core` standalone evaluation with v0 feature allowlist | PARTIAL | Uses `cel-mapper-core` standalone API behind `evidence-server-cel` feature (`runtime.rs:606-656`). However, the only allowlist check inside Evidence Server is a string `expression.contains("matches")` (`runtime.rs:592`), which is fragile (a claim id or string literal containing "matches" would be falsely rejected). Trust for the rest of the allowlist is delegated implicitly to `cel-mapper-core`; no test asserts rejection of disallowed functions other than `matches`. |
| 11 | Every successful evaluation creates `ClaimResult` then `ClaimResultView` before renderer/issuer | DONE | `runtime.rs:45-56, 411-427, 658-711`; renderer takes `&[ClaimResultView]` (`runtime.rs:713`) |
| 12 | `POST /claims/batch-evaluate` inline only | DONE | `runtime.rs:260-321`; no async/job route exists |
| 13 | Batch computes `farmer-under-4ha` for multiple subjects | DONE | `runtime.rs:291-315`; tests `evidence_api.rs:855-872, 932-972` |
| 14 | Batch preserves input order, one item per subject, per-item `evaluation_id` | DONE | `runtime.rs:291-316` (loop appends in order); `BatchItemResponse::Ok { evaluation_id, .. }`. Test `evidence_api.rs:855-872`. |
| 15 | One subject failure does not hide successes | DONE | `runtime.rs:303-314` (matches per subject, never short-circuits). Test `evidence_api.rs:855-872`. |
| 16 | Requests above configured inline limit return `batch.too_large` | DONE | `runtime.rs:273-276`; test `evidence_api.rs:874-892` |
| 17 | `Idempotency-Key` dedup within window | PARTIAL | Dedup implemented (`runtime.rs:92-127, 277-289, 316-319`) and tested for replay and conflict (`evidence_api.rs:932-972`). No expiry/TTL on `IdempotencyRecord`: entries live until process restart. "Within the configured window" is not actually configurable. |
| 18 | Canonical JSON renders for one scalar and one boolean claim | DONE | `runtime.rs:713-720`; test `evidence_api.rs:1014-1064` |
| 19 | CCCEV JSON-LD renders from same `ClaimResultView` | DONE | `runtime.rs:722-745`; exercised via `evidence_api.rs:974-1012` |
| 20 | `POST /evidence/render` renders only from existing `evaluation_id` | DONE | `evidence.rs:263-314`, `runtime.rs:323-356` reads store, errors `EvaluationNotFound` if absent |
| 21 | Render enforces original binding (disclosure, claims, purpose, requester, format) | DONE | `runtime.rs:332-354`; test `evidence_api.rs:974-1012`. Requester check is `evaluation.client_id != principal.principal_id`. |
| 22 | `POST /credentials/issue` signs SD-JWT VC from existing `evaluation_id` | DONE | `evidence.rs:316-436`, `sd_jwt.rs:116-174`; test `evidence_api.rs:1066-1134` |
| 23 | Issuance signs only authorized `ClaimResultView`, cannot recompute | DONE | `evidence.rs:339-352` requires existing evaluation; `sd_jwt::issue` takes `&[ClaimResultView]` |
| 24 | Returns `credential.issuer_not_configured` when missing | DONE | `runtime.rs:747-768`, `sd_jwt.rs:36-45`; test `evidence_api.rs:1226-1253` |
| 25 | SD-JWT VC issuer config includes key ref, vct, allowed claims, validity, holder binding, disclosure | DONE | `config.rs:268-321`; fixture `evidence_api.rs:144-170` |
| 26 | SD-JWT VC constructs `_sd_alg`, `_sd`, salted disclosures, `typ:"dc+sd-jwt"`, `kid`, `vct`, holder binding | DONE | `sd_jwt.rs:128-167`; test `evidence_api.rs:1110-1133` |
| 27 | Authn gates discovery, eval, batch, render, issuance | PARTIAL | Routes extract `Principal` (`evidence.rs:89, 113, 169, 224, 279, 332`) returning 401 if missing. But `service_document`, `issuer_jwks`, and `list_formats` (`evidence.rs:49, 60, 135`) do not require Principal extension. Spec line 2086 says "Authentication gates discovery". |
| 28 | Authz is claim-aware, purpose-aware, format-aware, disclosure-aware | DONE | claim/format/disclosure: `runtime.rs:202-213, 515-525, 528-542, 660-687`; purpose: `runtime.rs:505-513` |
| 29 | Source metadata validates `farmed-land-size` field type and unit | DONE | `validate.rs:764-803`; loaded at config-load |
| 30 | Metadata conflict disables or rejects affected claim with operator-visible signal | PARTIAL | Mismatch causes whole config to fail loading with `RuntimeBindingError::FieldMissing` and a `tracing::error!` with code `runtime.binding.field_missing` (`validate.rs:775-801`). That is "rejects" plus operator signal, but it rejects the entire service rather than the specific claim. The error code is the same as a genuinely missing field, so the operator cannot distinguish. No focused test in `evidence_api.rs`; coverage lives in `tests/config_metadata_bindings.rs:310-343`. |
| 31 | Audit records emitted for eval, batch, render, issuance, source errors, authz failures, partial failures | PARTIAL | Routes attach `AuditContextExt` for evaluate/batch/render/issued (`evidence.rs:194-202, 250-256, 303-310, 428-434`). Tests assert presence for `/claims/evaluate`, `/claims/batch-evaluate`, `/credentials/issue` (`evidence_api.rs:620-656, 907-930, 1136-1194`). Missing: no test asserts an audit record on authorization-failed or source-error or render paths; render audit context is attached only on success. |
| 32 | Audit records pseudonymize subjects, never leak secrets/tokens/credentials/source rows/forbidden values | DONE (within tested scope) | `subject_ref` SHA-256 (`runtime.rs:776-779`). Tests `assert_no_audit_leaks` for `person-1`, raw DOB, `3.5`, `total_farmed_area`, env name, holder proof, holder id, credential (`evidence_api.rs:646-655, 928-929, 1184-1193`). Strong coverage. |
| 33 | External canonical JSON does not expose internal source refs, alt subject IDs, requester IDs, audit-only purpose | PARTIAL | `ClaimResultView` does not include populated `source_versions` (left empty in `runtime.rs:421-422`), no `requester_id`, no alt subject id. Subject ref is the pseudonym. However there is no negative test asserting this absence. |
| 34 | ID Mapper boundary exists, exercised by demo/test mapper | MISSING | `SourceReader::map_subject` has a default `Ok(subject.clone())` no-op (`runtime.rs:23-30`). `RegistryRelaySourceReader` never overrides it. No demo mapper, no demo mapper roundtrip test. The boundary is an unused trait method. |
| 35 | OOTS profile fields declared in config and surfaced in discovery without OOTS wire claim | DONE | `config.rs:330-347`, `claim_summary` emits `oots` (`runtime.rs:482`); test `evidence_api.rs:587-591` |
| 36 | Search, BG jobs, plugins, federation, prod ID mapping, OOTS EDM, revocation not exposed as v0 | DONE | No such routes in `evidence.rs:33-47`; `RuleConfig::Plugin` returns `OperationUnsupported` (`runtime.rs:409`) |

Subtotals: 28 DONE, 7 PARTIAL, 1 MISSING. **78% DONE, 19% PARTIAL, 3% MISSING.**

### Required Tests (37 bullets)

| # | Required test | Status | Evidence |
| --- | --- | --- | --- |
| 1 | discovery filtering by caller authz | EXISTS BUT FAILS | `evidence_api.rs:603-618` returns `left=0 right=1`. Real bug. |
| 2 | format discovery with SD-JWT VC enabled and issuer-missing states | PARTIAL | Enabled state tested (`evidence_api.rs:596-600`). No test toggles the issuer-missing state for `/formats`. |
| 3 | successful `date-of-birth` via DCI or CRVS-profiled DCI | DONE | `evidence_api.rs:725-742` |
| 4 | successful `farmed-land-size` via Registry Data API | DONE | implicit in `evidence_api.rs:671-693, 855-872`; also `:765-806` via the unsupported-format negative path |
| 5 | successful `farmer-under-4ha` CEL | DONE | `evidence_api.rs:671-693` |
| 6 | successful inline batch | DONE | `evidence_api.rs:855-872, 932-972` |
| 7 | partial batch failure | DONE | `evidence_api.rs:855-872` |
| 8 | batch input order and per-item `evaluation_id` | PARTIAL | Test asserts items[0]=ok and items[1]=error, establishing order indirectly. No explicit assertion of `evaluation_id` per ok item. |
| 9 | batch too large returns `batch.too_large` | DONE | `evidence_api.rs:874-892` |
| 10 | batch idempotency | DONE | `evidence_api.rs:932-972` |
| 11 | unknown or hidden claim | DONE | `evidence_api.rs:809-822, 616-617` |
| 12 | unsupported operation | DONE | `evidence_api.rs:893-905` |
| 13 | unauthorized claim evaluation | DONE | `evidence_api.rs:744-762` |
| 14 | forbidden disclosure profile | DONE | `evidence_api.rs:765-806` (the "minimal" alias path returns `request.invalid`); credential issue path `:1196-1224` returns `claim.disclosure_not_allowed`. Failure mode for evaluate is "invalid request" rather than "disclosure denied", which is acceptable but worth noting. |
| 15 | missing or invalid purpose when required | PARTIAL | Blank-purpose test exists (`evidence_api.rs:780-792`). No test omits the header entirely. |
| 16 | source record not found | DONE | `evidence_api.rs:855-872` (subject "missing" returns `source.not_found`) |
| 17 | source ambiguity | DONE | `evidence_api.rs:838-853` |
| 18 | metadata conflict disabling or failing a claim | MISSING | Capability exists at config-validation level (tests in `tests/config_metadata_bindings.rs:310-343`), but no Evidence Server route test exercises a metadata conflict and confirms the affected claim is disabled. |
| 19 | CEL expression validation and execution | DONE | `evidence_api.rs:695-723` |
| 20 | CEL root bindings (source, claims, ctx, vars, meta) | PARTIAL | `source`, `claims`, `ctx.subject.id`, `vars.limit` covered (`evidence_api.rs:309-337, 695-723`). `meta` root is wired (`runtime.rs:648`) but no test reads from `meta`. |
| 21 | CEL rejection for undeclared fields or disallowed functions | MISSING | Only `matches` is tested. No test for undeclared field reference or other disallowed CEL function. |
| 22 | CEL rejection for regex matching | DONE | `evidence_api.rs:824-836`. Note: the check is substring-only and `text_matches`/`validate_matches` would bypass it; see "Security" section. |
| 23 | canonical JSON rendering | DONE | `evidence_api.rs:1014-1064` |
| 24 | CCCEV rendering from a view | PARTIAL | A render against the CCCEV format is performed (`evidence_api.rs:974-1012` line 993-1001), but the test only checks `@graph` is an array. No deeper structural assertion on `cccev:` keys. |
| 25 | render binding denial for broader disclosure | DONE | `evidence_api.rs:1003-1011` |
| 26 | render positive for authorized format | DONE | `evidence_api.rs:991-1001, 1014-1064` |
| 27 | disclosure downgrade to default or redacted where configured | MISSING | Runtime supports `DisclosureDowngrade::{Default, Redacted, Deny}` (`runtime.rs:671-687`). All fixtures use `downgrade: deny` (default in `config.rs:264`). No test exercises a successful downgrade to `default` or `redacted`. |
| 28 | disclosure denial where downgrade is `deny` | PARTIAL | `request.invalid` is returned for unknown profile `minimal` (`evidence_api.rs:765-779`), and `claim.disclosure_not_allowed` for credential issuance (`:1196-1224`). The straight evaluate-with-disallowed-but-known-profile path is not tested. |
| 29 | credential issuance from existing evaluation | DONE | `evidence_api.rs:1066-1134` |
| 30 | credential issuance denial when issuer missing | DONE | `evidence_api.rs:1226-1253` |
| 31 | credential issuance denial when claims/format/purpose/requester/disclosure exceed evaluation binding | PARTIAL | Format mismatch and claims mismatch tested (`evidence_api.rs:1255-1297`); profile-disclosure mismatch tested (`:1196-1224`). No tests for purpose-mismatch or requester-mismatch on the credential route. |
| 32 | PoP enforcement when binding is jwk or did | PARTIAL | `did` path tested (positive `evidence_api.rs:1066-1134`, negative `:1299-1349`). The implementation only allows `did` (`evidence.rs:451-465`); `jwk` mode is not exercised, and `validate_holder_proof_payload` only strips `did:jwk:` (`evidence.rs:540`). |
| 33 | credential artifact does NOT contain `evaluation_id` | DONE | `evidence_api.rs:1123` asserts `!payload.to_string().contains(evaluation_id)`. Implementation: `sd_jwt.rs:128-160` builds payload without `evaluation_id`. |
| 34 | ID Mapper demo roundtrip | MISSING | See capability #34. No mapper, no test. |
| 35 | OOTS metadata surfaced in discovery without OOTS wire claim | DONE | `evidence_api.rs:587-591` |
| 36 | deferred routes hidden or stable not-supported errors | PARTIAL | No routes exist for search/federation/plugins/jobs (implicit). No focused test asserts a stable "not_supported" error for any deferred feature. `RuleConfig::Plugin` returns `OperationUnsupported` but is not surfaced via a route. |
| 37 | audit content assertions (caller, purpose, claim ids, source connectors, pseudonymized subject, no secrets, no source records) | PARTIAL | Strong negative assertions for evaluate, batch, issue. MISSING: no assertion of "source connector" identifiers and no audit assertion on the render route, on authz-failure, or on source-not-found. |

Subtotals: 22 DONE, 11 PARTIAL, 4 MISSING (plus 1 EXISTS-BUT-FAILS). **59% DONE, 30% PARTIAL, 11% MISSING.**

### "Not Done If" Clauses (17 clauses)

All 17 clauses pass on read-only review:

1. CCCEV/SD-JWT VC/OOTS is the internal model: OK. Internal is `ClaimResultInternal` to `ClaimResultView` (`runtime.rs:46, 658-711`).
2. A renderer recomputes claims: OK. `render` reads stored view (`runtime.rs:323-356`).
3. External canonical JSON exposes internal source refs / alt subject ids / requester ids / audit-only purpose: OK. No negative test, but `ClaimResultView` shape excludes those fields.
4. Render broadens disclosure/claims/purpose/format: OK. `runtime.rs:332-354` denies.
5. Downstream registry creds let caller see more than disclosure permits: OK within scope. Profile-disclosure enforcement at `evidence.rs:386-394`.
6. Search/BG jobs/plugins/federation/prod matching/OOTS EDM exposed: OK. Not routed.
7. Unsupported search silently scans registry: OK. No search route.
8. Search presented as OOTS Common Services: OK. N/A.
9. OOTS compatibility implied without adapter: OK. Discovery surfaces only `oots:` metadata under each claim.
10. Batch fails the whole request when one subject fails: OK. `runtime.rs:303-314`, tested.
11. Source metadata conflicts ignored or silently coerced: OK. `validate.rs:764-803` rejects.
12. Audit logs contain raw secrets/tokens/credentials/unrestricted source rows: OK within tested scope.
13. Any v0 deferred item described as implemented without API/config/docs/tests: OK on read-only review. No deferred item is plumbed in.
14. Complex computation required from a plugin to satisfy a v0 claim: OK. All fixture claims use `extract`, `exists`, `cel`.
15. Issuance recomputes claims: OK. `evidence.rs:339-352` requires existing eval.
16. SD-JWT VC advertised as enabled but cannot sign required fixture credential: OK. Tested (`evidence_api.rs:1066-1134`).
17. Issued SD-JWT VC omits `_sd_alg`/`_sd`/disclosures/`typ:"dc+sd-jwt"`/`kid`/`vct`: OK. All fields asserted (`evidence_api.rs:1110-1133`).

Subtotals: 17 OK.

## Security And Disclosure Review

Severity reflects production-blocking risk. All paths absolute.

### High

#### H1. Holder PoP signature is structurally verified but no nonce or `jti` ledger exists. Captured proofs are reusable until `exp`.

File: `src/api/evidence.rs:477-536`

The PoP JWT is bound to `evaluation_id`, `credential_profile`, `disclosure`,
`claims`, audience `evidence-server`, and `sub == holder_id`, but there is no
server-issued nonce and no `iat` skew bound. `jsonwebtoken::Validation` with
`set_audience` enforces `exp` (default 60s leeway) but does not require `nbf`
or bound `iat`. An attacker who once intercepts a holder's proof (TLS-terminating
proxy, log capture, compromised relying-party) can replay it against
`/credentials/issue` for the same `evaluation_id` until `exp`. There is also no
`jti` uniqueness check.

Impact: holder PoP becomes "bearer-of-proof" rather than proof-of-possession
within the proof's lifetime; cross-session replay against the same evaluation
succeeds.

Fix: issue a server-side `cnf_nonce` on evaluate the holder must echo, persist
`jti` in `EvidenceStore` for the proof's lifetime and reject reuse, enforce a
tight `iat` window (around 120s past, 30s future).

#### H2. Holder PoP only actually works for `did:jwk:`; other allowed DID methods silently fail.

File: `src/api/evidence.rs:454-510, 538-547`

`validate_holder_request` accepts any allowed DID method prefix from
`profile.holder_binding.allowed_did_methods` (line 458-466), yet
`validate_holder_proof_payload` calls `holder_jwk` which only succeeds with
`did:jwk:` prefix (line 540). A profile configured to allow `did:web` or
`did:key` will accept the holder id but always fail PoP verification.

Impact: foot-gun causing 100% PoP failures for non-jwk DIDs. Not a bypass, but a
silent operational dead end.

Fix: either reject non-`did:jwk:` methods at config load time, or implement DID
resolution before claiming support.

#### H3. `cnf` uses `kid` only; the holder JWK is not embedded in the SD-JWT VC.

File: `crates/evidence-core/src/sd_jwt.rs:141-143`

When `binding=jwk`, the SD-JWT VC should include `cnf.jwk` (the actual key) so
a verifier can validate KB-JWTs without out-of-band resolution. The code only
emits `{ "cnf": { "kid": holder_id } }` regardless of binding mode.

For `did:jwk`, `kid` is recoverable because the DID encodes the key. For
`binding=jwk` (per profile), the verifier has no way to retrieve the public key.

Impact: high for any profile with `holder_binding.mode == "jwk"`. Holder key is
unresolvable downstream, breaking KB-JWT verification at the verifier.

Fix: when `binding == "jwk"`, require `holder.jwk` and emit
`cnf: { jwk: <holder_jwk> }`. When `binding == "did"`, emit
`cnf: { kid: <did_url> }` plus optionally embed the resolved JWK.

#### H4. Idempotency `request_hash` is computed over `serde_json::to_vec(request)` which is non-canonical.

File: `crates/evidence-server/src/runtime.rs:277, 795-798`

`hash_json` uses `serde_json::to_vec` which is not canonical: HashMap field
ordering and floating-point representation are implementation-dependent. Two
semantically identical requests can hash differently, causing spurious
`IdempotencyConflict` errors that look like the cache was poisoned. Principal
scoping (`{principal_id}:/claims/batch-evaluate:{sha256(key)}`) is good and
blocks cross-caller poisoning, but within a single caller idempotency is
unreliable.

Impact: medium. Operational/correctness issue, not a bypass. Reliability problem
under retry.

Fix: canonical JSON serialization (sort map keys, normalize numbers) before
hashing, or hash the structured fields explicitly.

#### H5. CEL allowlist is a substring scan; trivially bypassed.

File: `crates/evidence-server/src/runtime.rs:584-594`

```rust
if expression.contains("matches") {
    return Err(EvidenceError::InvalidRequest);
}
```

Problems:

1. False positives on any identifier or string literal containing `matches`
   (e.g. `source.bank.matches_pattern`, `m["matches"]`, the literal `"matches"`).
2. False negatives on every other potentially expensive or regex-capable CEL
   function exposed by `cel-mapper-core`. The `cel-mapper-core` stdlib registers
   `text_matches` and `validate_matches` (per
   `apps/cel-mapping/crates/cel-mapper-core/src/security.rs` and related builtin
   registration). Neither contains the standalone token `matches` and both are
   regex calls. Expression like `text_matches(source.farmer.name, ".*")` clears
   the guard.
3. `cel-mapper-core` itself has no function allowlist (no `allowlist`,
   `denylist`, `forbidden`, or `banned` in any `.rs` file in that crate).

Impact: high if claim configs are not fully trusted. Medium if claim configs are
operator-only. Either way, the spec's "CEL rejection for regex matching in
version 0" is not actually enforced for stdlib regex functions.

Fix: replace substring matching with an AST walk. Either scan the compiled CEL
AST for call nodes whose function names are in a v0 deny-set, or call into a
`cel-mapper-core` API that already enforces an allowlist. The current guard is
security theater.

#### H6. Mixed-disclosure evaluations cannot be issued as credentials.

File: `src/api/evidence.rs:358-362` vs. `crates/evidence-server/src/runtime.rs:338-344, 781-793`

`stored_disclosure` returns `"mixed"` (`runtime.rs:791-793`) when the evaluation's
results span more than one disclosure profile. The PoP validator at
`evidence.rs:524-530` compares the JWT's `disclosure` claim against
`Some("mixed")`. A holder cannot reasonably know to sign over `"mixed"` ahead of
time.

Impact: medium. Mixed-disclosure evaluations are functionally dead at the
issuance step. Not a bypass.

Fix: either reject `"mixed"` at evaluate time when the claim set would require
issuance, or document that mixed evaluations are not issuable and surface a
distinct error code.

#### H7. `EvidenceStore` maps grow unbounded.

File: `crates/evidence-server/src/runtime.rs:78-90, 92-109`

`get()` checks `expires_at` at read time and returns `None`. The expired entry
remains in the HashMap until the same `evaluation_id` is reinserted (collision
probability negligible for ULID). Idempotency records have no expiry check at
all. Both maps grow unbounded.

Impact: medium. Memory exhaustion over time.

Fix: background sweeper or LRU cap. TTL the idempotency map.

### Medium

#### M1. Audit `claim_hash` inconsistent across render request shapes.

File: `src/api/evidence.rs:307`

`render` passes `requested_claims.as_deref().unwrap_or(&[])` and then
`attach_evidence_audit` hashes only if non-empty. When the caller omits claims
(legitimate per render policy), the audit row has no claim hash. When they pass
claims (which must equal `evaluation.claim_ids`), the audit row has a hash.
Audit retrieval by claim hash becomes inconsistent for the same evaluation
depending on caller behavior.

Impact: low-medium. Audit quality, not security.

Fix: derive the claim list from `evaluation.claim_ids` for audit hashing, not
from `request.claims`.

#### M2. `service_document` and `issuer_jwks` do not require authentication.

File: `src/api/evidence.rs:49-76`

These routes do not require `principal`. JWKS exposure is fine (public keys by
definition). The service document leaks `service_id`, `claims_url`,
`inline_batch_limit`, and the list of formats including which are enabled.
Reconnaissance value is low but non-zero. Spec line 2086 says "Authentication
gates discovery".

Impact: low to medium depending on policy.

Fix: confirm the policy. If discovery should be authenticated, add Principal
extraction.

#### M3. `holder_jwk` accepts a JWK that contains private fields.

File: `src/api/evidence.rs:538-547`

`serde_json::from_slice` into `jsonwebtoken::jwk::Jwk` happily parses a JWK that
includes `d`, `p`, `q`, etc. The library's `DecodingKey::from_jwk` likely only
uses public parts, but the holder_id itself would contain the private key in
plaintext, transmitted on every call. There is no validation that private
fields are absent.

Impact: medium. If a holder client constructs `did:jwk:<base64(private JWK)>` by
mistake (easy bug), the server logs and audits the holder_id containing the
private key.

Fix: after parsing, reject if any private field is present.

### Confirmed OK

- JWKS `d` leakage: `public_jwk` in `sd_jwt.rs:79-85` only constructs
  `{kty, crv, x, alg, kid}`. No `d`. Clean.
- Cross-caller idempotency poisoning: principal_id is prefixed. Clean.
- `did:jwk` parsing panic: `holder_jwk` uses `strip_prefix`, base64 decode with
  `.map_err`, and `serde_json::from_slice` with `.map_err`. No `unwrap`, no
  panic path. Clean.
- SD-JWT mandatory fields: `_sd_alg`, `_sd`, `typ: dc+sd-jwt`, `kid`, `vct` all
  present in `sd_jwt.rs:138-166`. Clean. `cnf` issues are H3 above.
- Issuance recomputation: `issue_credential` only reads from `evaluation.results`,
  no re-evaluation path. Clean.
- Credential artifact contains `evaluation_id`: the SD-JWT payload does NOT
  contain `evaluation_id`; only the HTTP response envelope does. The compact
  credential string (`signed.compact`) excludes it. Clean.
- `render` widens disclosure: `render` re-checks `client_id`, `format`,
  `disclosure`, `claims`, `purpose` against the stored evaluation. Cannot
  widen. Clean.
- No bearer tokens or connector credentials in audit emission paths in these
  four files. `attach_evidence_audit` writes only `verification_id`, `decision`,
  `claim_hash`, `row_count`. Clean within tested scope.
- No raw source records or subject PII in error paths in `runtime.rs`.
  `EvidenceError` variants are coded; `subject_ref` is hashed. Clean.

## CEL And Source Connector Review

### High

#### CEL-1. `matches` check is a substring scan that can be trivially bypassed

File: `crates/evidence-server/src/runtime.rs:592-594`

See H5 above for the full analysis. Repeated here because it surfaces in two
reviewer reports independently.

Fix: AST-level check or a positive allowlist of permitted function names. The
current guard does not block `text_matches` or `validate_matches` and is
security theater.

#### CEL-2. `meta` binding is always an empty object.

File: `crates/evidence-server/src/runtime.rs:648`

```rust
("meta".to_string(), json!({})),
```

The spec (lines 2043-2046) lists `meta` as one of the five root bindings, and
the required test bullet at line 2114 explicitly requires alignment with
`cel-mapping` semantics including `meta`. `meta` is passed as an
unconditionally empty object at every evaluation. If a CEL expression tries to
use `meta` to access source field metadata (e.g.,
`meta.farmer.total_farmed_area.unit`), it gets null silently, which can yield
wrong evaluation results without any error. There is no test that verifies
`meta` has usable content.

Fix: populate `meta` with at minimum the field-level type and unit information
from `SourceFieldConfig` for each bound source, or document that `meta` is
intentionally empty for v0 and add a test asserting that contract. An empty
binding that silently returns null is a latent accuracy bug.

#### CEL-3. Metadata conflict signal is ambiguous.

File: `src/config/validate.rs:764-804`

See capability #30 above for the full analysis. Repeated here because two
reviewers flagged it. The error code logged is the same for "field missing" and
"field type/unit conflict", and the validation only runs at startup; runtime
re-validation in `load_sources` (`runtime.rs:556-574`) only checks `required`.

Fix: distinct error code and `RuntimeBindingError` variant for type/unit
conflicts. Either re-validate at evaluation time or explicitly document the
startup-only contract.

### Medium

#### CEL-4. `Plugin` rule is not filtered from discovery.

File: `crates/evidence-server/src/runtime.rs:409`

`list_claims` filters by `principal_can_see_claim` (scopes only). `claim_summary`
emits `"evaluate": claim.operations.evaluate.enabled`. For a plugin claim with
`enabled: true` (default), this advertises the claim as evaluable. A caller who
tries to evaluate gets `claim.operation_unsupported` with no prior indication.
No config-time validation rejects a `plugin`-rule claim with
`evaluate.enabled: true`.

Fix: reject `plugin`-rule claims in `validate_evidence_server_config`, or force
`operations.evaluate.enabled = false` for plugin claims before exposing them.

#### CEL-5. No test covers undeclared field access or disallowed functions other than `matches`.

File: `tests/evidence_api.rs`

Required test bullet at spec line 2114 is split:

- `evaluate_rejects_unknown_claim_and_disallowed_cel_regex` (line 809) covers
  `matches` rejection.
- No test for `text_matches` or `validate_matches`.
- No test for accessing a variable name outside `{source, claims, ctx, vars, meta}`.
- `vars` exercised indirectly via `farmer-under-variable-limit`. `meta` has
  zero test coverage.

#### CEL-6. `satisfied` is null for non-boolean dependency values.

File: `crates/evidence-server/src/runtime.rs:624-625`

```rust
"satisfied": result.value.as_bool(),
```

`as_bool()` returns `None` for any non-boolean JSON value. The CEL binding
`claims.farmed_land_size.satisfied` would be null, not a meaningful boolean. For
scalar claims the semantics are undefined. There is no test asserting what a
caller gets when a scalar claim dependency's `.satisfied` is used in CEL.

#### CEL-7. `source` binding does not expose `root` alias.

File: `crates/evidence-server/src/runtime.rs:631-636`

The standard `StandaloneExpressionInput::from_source_context` helper in
`cel-mapper-core` inserts both `"source"` and `"root"` pointing to the same
value. The evidence-server only inserts `"source"`. Any expression that uses a
`cel-mapping` idiom relying on `root` as an alias will fail silently rather
than loudly.

Impact: low. Worth a code comment documenting the intentional omission.

## Spec Required Tests vs. Actual Test Names

37 spec bullets mapped against 23 implemented test names. Items with no
matching test:

1. batch input order and per-item `evaluation_id` (no dedicated assertion)
2. source record not found (no dedicated test name)
3. metadata conflict disabling or failing a claim (only config-level test exists)
4. disclosure denial where downgrade is `deny` (negative path on evaluate)
5. credential artifact does NOT contain `evaluation_id` (asserted inline but no named test)
6. ID Mapper demo roundtrip (boundary is a no-op default)
7. deferred routes or features hidden / stable not-supported errors (implicit, no test)

A further set of bullets is covered partially by tests that bundle multiple
concerns:

- format discovery with SD-JWT VC enabled and issuer-missing states
- successful `farmed-land-size` evaluation through Registry Data API
- successful `farmer-under-4ha` CEL evaluation
- successful inline batch evaluation
- forbidden disclosure profile
- missing or invalid purpose when required
- CEL root binding semantics (`meta` not exercised)
- CEL rejection for undeclared fields or disallowed functions (`matches` only)
- CCCEV rendering from a `ClaimResultView` (`@graph` only)
- disclosure downgrade to `default` or `redacted` (no fixture exercises non-`deny` downgrade)
- credential issuance denial when purpose or requester exceed binding
- PoP enforcement when binding is `jwk` (only `did` exercised)
- OOTS metadata surfaced in discovery (bundled with discovery_lists_claims_and_formats)
- audit content assertions (no "source connector" identifier assertion)

## Aggregate Rollup

Combining 36 Required Capabilities + 37 Required Tests + 17 Not Done If clauses:

- Total: 90 line items.
- 67 DONE (74%).
- 18 PARTIAL (20%).
- 5 MISSING (6%).

Adjusting for the actually failing test (item #1 in Required Tests is "exists
but fails") and the clippy break:

- 1 spec gate currently broken on green-build CI.
- 1 test harness defect (env race) blocks parallel runs.
- 2 hard lints (`too_many_arguments`) prevent `cargo clippy -D warnings`.

These three items alone disqualify "95% ready" by any reasonable interpretation.

## Load-Bearing Gaps

Ship-blockers, in priority order, that the dev's "95%" claim must address before
any pilot release:

1. **Failing test** `discovery_filters_claims_by_caller_authorization` returns
   0 claims where the spec test asserts 1. Required Test #1. Fix the filter or
   the fixture scope mapping. `runtime.rs:441-450` and
   `evidence_api.rs:603-618`.
2. **Clippy break** prevents CI green. `runtime.rs:260, 358`.
3. **Test env-race**: `env::set_var("EVIDENCE_SERVER_TEST_JWK", ...)` across
   parallel tests poisons `config::load`. Either serialize with a static mutex
   or use the `serial_test` crate, or set the JWK at process start.
4. **CEL allowlist** is `expression.contains("matches")` (`runtime.rs:592`).
   Trivially bypassable through `text_matches` and `validate_matches` from
   `cel-mapper-core` stdlib. Replace with an AST-level deny-set or a positive
   allowlist.
5. **Holder PoP has no replay protection**: no server nonce, no `jti` dedup, no
   `iat` skew bound. Captured proofs are reusable until `exp`.
6. **`cnf.jwk` never embedded** for `binding=jwk` (`sd_jwt.rs:141-143`).
   Downstream verifiers cannot validate KB-JWTs.

Required v0 items still missing:

7. **ID Mapper demo roundtrip** (capability #34, test #34). `map_subject`
   default `Ok(subject.clone())` is the only impl.
8. **Disclosure downgrade `default` and `redacted` paths**: code supports them
   (`runtime.rs:671-687`), all fixtures use `deny`. Test #27 missing.
9. **`meta` CEL root binding always `{}`** (`runtime.rs:648`). Test #20 partial.
10. **Metadata conflict signal**: rejects entire service load rather than
    disabling the affected claim. Error code `runtime.binding.field_missing` is
    same as a genuinely missing field. Test #18 missing at route level.
11. **Discovery routes unauthenticated**: `/.well-known/evidence-service`,
    `/.well-known/evidence/jwks.json` (intentional for JWKS, ambiguous for
    service_document), `/formats`. Spec line 2086.
12. **DCI connector** is a CRVS-profiled binding over local DataFusion engine.
    No separate DCI Search wire client. Defensible only if the spec's
    "CRVS-profiled DCI fixture" wording is honoured.

Required tests with no matching test name (7 bullets):

13. Batch input order + per-item `evaluation_id` assertion.
14. Source record not found (no dedicated test).
15. Metadata conflict at Evidence Server route level.
16. Disclosure denial where downgrade is `deny` (negative path on evaluate).
17. Credential artifact does NOT contain `evaluation_id` (asserted inline, no
    named test).
18. ID Mapper demo roundtrip.
19. Deferred routes/features stable not-supported errors.
20. `jwk` holder binding mode (only `did:jwk` is exercised; other `did:`
    methods silently fail in `holder_jwk`).

Operational hygiene (not blockers):

21. Idempotency map has no TTL/LRU; `EvidenceStore` evaluations never sweep
    expired entries.
22. `hash_json` uses non-canonical `serde_json::to_vec`. Spurious
    `IdempotencyConflict` possible under retry.
23. `holder_jwk` accepts a JWK containing private fields (`d`, `p`, `q`, ...)
    without rejecting.
24. `Plugin` rule with `evaluate.enabled: true` is advertised in discovery but
    always returns `OperationUnsupported`. Config validation should reject it.

## Shortest Path To A Defensible "Ready"

1. Fix the failing discovery filter test (real bug in `principal_can_see_claim`
   or in the fixture's scope mapping).
2. Fix the clippy errors (refactor request bundles into structs or add
   `#[allow]` with a reason).
3. Serialize env mutation in the test harness with `OnceLock<Mutex<()>>` or
   adopt the `serial_test` crate, or shift the JWK into a per-process setup.
4. Replace the CEL `matches` substring guard with an AST-level allowlist driven
   through `cel-mapper-core`. Add tests for `text_matches`, `validate_matches`,
   and an undeclared-field reference.
5. Add the missing tests: ID Mapper roundtrip, downgrade-to-default,
   downgrade-to-redacted, deferred-feature stable not-supported responses.
6. Add a server-issued nonce plus a `jti` ledger for holder PoP, with a tight
   `iat` window.
7. Either embed `cnf.jwk` for `binding=jwk` or remove `jwk` from supported
   modes and document the constraint.

Optional hardening after the above:

- Canonicalize JSON before hashing for idempotency.
- Add TTL/LRU sweep for `EvidenceStore.evaluations` and `idempotency` maps.
- Reject private JWK fields in `holder_jwk`.
- Reject `plugin`-rule claims at config-load time.

## Files Referenced

- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/docs/evidence-server-spec.md` (lines 2005-2195, 2268-2370)
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/crates/evidence-core/src/config.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/crates/evidence-core/src/sd_jwt.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/crates/evidence-core/src/model.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/crates/evidence-core/src/error.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/crates/evidence-server/src/runtime.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/src/api/evidence.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/src/evidence/registry_relay.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/src/config/validate.rs` (lines 658-816)
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/tests/evidence_api.rs`
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/registry_relay/tests/config_metadata_bindings.rs` (only metadata-conflict coverage)
- `/Users/jeremi/Projects/204-programs-delivery-commons/apps/cel-mapping/crates/cel-mapper-core/src/security.rs` (external; governs CEL allowlist enforcement claim)

## Bottom Line

The implementation has made decisive progress against the Pass 2 review. Wave 0
crate split, Wave 2 authorization, Wave 3 issuer/PoP/JWKS, and idempotency are
substantially closed. However:

- Clippy is failing.
- A required spec test is failing.
- The test harness has an env race that masks the failure under default
  parallelism.
- At least three Required-Test bullets have no implementation at all.
- The CEL allowlist is trivially bypassable through the `cel-mapper-core`
  stdlib.
- Holder PoP has no replay protection.

Realistic completion is in the **80-85%** range, not 95%. The gaps are concrete
and the fixes are scoped. The shortest path above is achievable in a focused
push, but until those items land the "95% ready" claim is not defensible.
