# Evidence Server Spec Review

Status: draft review of `evidence-server-spec.md` (2026-05-22)

This report synthesizes findings from five parallel reviewers covering API design, security and privacy, standards positioning (CCCEV/OOTS/SD-JWT VC/DCI), the Rust implementation plan, and internal spec consistency. Items flagged by more than one reviewer are marked **[converged]**. All line numbers refer to the version of `evidence-server-spec.md` reviewed on 2026-05-22.

## Critical

### 1. `ClaimResultFragment` is a phantom type [converged: impl, consistency]

Line 355 declares the plugin ABI return type and line 387 references "claim fragments". The term is never defined anywhere else. Wave 1 Worker B has nothing to implement against, and Worker A (single-subject evaluation) needs the merge contract to consume fragments.

**Fix.** Define the type in Core Concepts alongside `ClaimResult`, enumerate its fields, and specify how the host promotes a fragment into a full `ClaimResult`. Recommended split: host owns `subject`, `audit`, `identity_mapping`, `disclosure`; plugin owns `value`, `value_type`, `derived_from`, `sources` selections, and `diagnostics`. Make the definition a Wave 0 deliverable.

### 2. Disclosure downgrade in the example is unexplained [consistency]

The single-subject evaluate request asks for `disclosure: "predicate"` (line 643). The `farmed-land-size` result returns `disclosure: "redacted"`, `value: null` (lines 657-665). The `farmed-land-size` claim definition allows `predicate` (line 252), so the downgrade is not forced by config. The example is either a per-claim authorization downgrade demonstration or wrong.

**Fix.** State the rule. Recommended wording: each claim is evaluated at the requested disclosure profile unless authorization denies that profile for that claim, in which case the server downgrades to the claim's default and includes a per-claim disclosure indicator. Then update the example to show that indicator, or fix the example so `farmed-land-size` is returned with `disclosure: "predicate"`.

### 3. `search.cardinality_suppressed` is 200-or-403 [converged: api, consistency]

Line 1356 in the status table says "200 or 403". Line 875 says "return `search.cardinality_suppressed` or an empty result according to claim policy". Empty 200 looks like no matches; 403 says matches exist but are hidden. These are observably different client contracts.

**Fix.** Bind the choice to claim-definition policy, e.g., `cardinality_suppression_mode: empty | error`, so the contract is deterministic per claim. Remove "or" from the status table.

### 4. `POST /evidence/render` response body is never specified [api]

Lines 880-912 describe inputs and rebind rules but show no response body. Line 912 requires "the rendered artifact hash or equivalent binding metadata", which cannot be implemented from prose. `GET /.well-known/evidence-service` and `GET /formats` have the same gap (lines 609-616).

**Fix.** Add minimal example responses for each, showing at least `artifact_hash`, `format`, `evaluation_id`, and the artifact (inline or as a reference) for render; and the top-level field set for the well-known document and formats endpoint.

### 5. `POST /credentials/issue` has no request or response shape [api]

Lines 916-930 describe lifecycle concerns and mount the route but provide zero shape. For comparison, `POST /claims/evaluate` has full examples.

**Fix.** Either provide a skeleton (marked "informative, v0 deferred") or remove the route from the operations table until the issuance wave is in scope.

### 6. CCCEV mapping: `ClaimDefinition` → `InformationConcept` is wrong [standards, confidence 95]

The mapping table at line 1185 maps `ClaimDefinition` to `InformationConcept`, `Criterion`, or `Constraint`. In CCCEV 2.1.0, `InformationConcept` is a data-shape descriptor, not a Requirement subclass. The class designed for "requested data that is to be proven by Evidence" is `InformationRequirement`. Using `InformationConcept` in the cell will produce non-conformant CCCEV output and mislead implementers.

**Fix.** Replace `InformationConcept` with `InformationRequirement` in the table (keep `Criterion` for threshold claims), and add a note that a `ClaimDefinition` may *reference* an `InformationConcept` for value-shape and semantic binding without *being* one.

### 7. CCEV vs CCCEV typo [converged: impl, consistency, confidence 100]

Lines 1429 and 1431 say "CCEV". Every other occurrence is "CCCEV". Trivial to fix, flagged twice.

### 8. Plugin sandbox honesty [security, confidence 95]

Lines 347-384 list determinism, no network, no filesystem, no clock, no random, no process spawning as plugin obligations. The ABI is an in-process Rust trait, which provides zero runtime isolation: a buggy or malicious plugin can read heap memory (including source records for other subjects), call libc directly, exfiltrate via panic messages, or exhaust stack and heap.

**Fix.** Explicitly state that v0 plugin isolation is compilation-time review only, no OS-level sandbox, and that the v0 threat model treats plugin code as trusted host code. Name what v1+ must add (Wasm runtime, seccomp, or process isolation) so operators do not over-trust the v0 listing of plugin "must not" rules.

### 9. Selective disclosure has no enforceable invariant [security]

Lines 433, 979, and 984 put the obligation on renderers ("must never expand beyond that profile", "may omit or transform fields according to disclosure policy"). The internal `ClaimResult` (line 933) carries the full value alongside the disclosure profile, so a buggy renderer has no structural barrier.

**Fix.** State the invariant that the host constructs a disclosure-filtered `ClaimResultView` before calling any renderer, and that renderers never receive the raw `ClaimResult`. Disclosing more than the profile permits is then a host contract violation, not a renderer discretion.

## Important

### API consistency

**Field name drift across endpoints** [api, consistency]. `claims` (evaluate request, render request) vs `claim_ids` (batch response, line 742) vs `claim` (search criterion, line 810). Pick one canonical name for "list of claim IDs being operated on" and use singular only where genuinely singular.

**`provenance` (external) vs `sources` (internal) mapping undefined** [consistency, confidence 90]. Line 660 shows `provenance: {source_count, computed_by}` externally; line 954 shows `sources: [{connector, registry, record_ref, source_version, retrieved_at}]` internally. The `farmer-under-4ha` result at line 666 has no provenance block at all. State that `provenance` is the external projection of `sources`, enumerate its allowed fields, and state when it is required vs optional.

**`derived_from` type inconsistency** [consistency]. Claim ID strings locally (lines 672, 952); structured objects with `ref`, `issuer`, `claim`, `version` in federation (line 1124). The spec never specifies how `derived_from` renders in a federated external response. Specify both forms and add a federated external example.

**`evaluation_id` lifecycle** [converged: consistency, api]. Bound to "expiration time" (line 904) which is never defined. Batch returns `batch_id`, not per-item `evaluation_id`, but render takes `evaluation_id` (line 887). Specify: default expiration policy (recommend "configurable, default 24 hours from `computed_at`"); whether batch items produce individual `evaluation_id` values or whether `batch_id` is the render handle. Update the batch response example to show this.

**Content negotiation precedence** [api]. `Accept` header (line 628), body `format` field (line 888), and claim definition `formats` list have no stated precedence rule. Specify: body field wins, both must be in the claim's `formats` list, `Accept: */*` falls back to the claim default, mismatch returns 406 / `claim.format_not_supported`.

**API versioning strategy absent** [api]. No URL prefix, no Accept-versioning. Even one sentence ("v0 uses no path prefix; breaking changes use `/v1/`") prevents ambiguity.

**No idempotency keys on batch submission** [api]. A timed-out POST to `/claims/batch-evaluate` leaves the client unable to tell whether the job was created. Define an optional `Idempotency-Key` header and specify the dedup window.

**Inline-vs-job threshold for batch is undefined** [api]. Lines 720-728 leave shape selection to the server with no client hint. Add a `prefer: inline|async` request field and expose the deployment threshold in discovery.

**`subject_ref` syntax undefined** [converged: api, consistency]. `request.subjects[0]` is shown (lines 748-749) but never defined. State the exact form ("always `request.subjects[N]` where N is `input_index`") or define the expression syntax formally.

**`claim.not_found` in batch items leaks existence** [api, confidence 80]. Discovery hides claims from unauthorized callers (line 607), but a batch item can probe for `claim.not_found` vs `claim.operation_not_supported`. State that batch items must not distinguish "not configured" from "hidden from caller" and must return a uniform code for both.

### Security and privacy

**Release authorization token: no audience or replay window** [security]. Lines 900-912 bind the token to many fields but never require an `aud` claim equal to the current caller, nor a maximum replay window. A forwarded token could be replayed if the server only checks `evaluation_id` equality. Require an explicit audience bound to the issuing Evidence Server URL and the original requester's client ID; require fail-closed when audience does not match the current caller; require token expiration within the evaluation's own freshness window.

**Federation: no revocation or key rotation path** [converged: security, standards]. Lines 1117-1163 require `signature_required` and `trust_policy` but no key rotation or revocation mechanism. With `freshness: P30D`, results signed by a compromised key remain valid for 30 days. Require `trust_policy` URLs to resolve to a document specifying JWKS endpoint, key max-age, rotation protocol, and revocation status check. Specify fail-closed behavior when the trust policy is unreachable. Specify what signature format federation uses (JWS, JAdES, or COSE); the spec currently says nothing.

**Audit defaults are not safe for subject IDs** [security]. The audit record (line 973) carries the raw subject ID and is not classified as sensitive. Line 1382 uses "should be redacted or hashed", not "must". Salted-hash logging (line 1641) does not specify salt scope. Classify subject IDs as PII requiring at minimum pseudonymization, define salt scope (per-deployment minimum, rotated on a documented schedule), and change "should" to "must" for subject identifiers unless operator policy explicitly opts into plaintext with documented legal basis.

**Purpose binding is decorative** [security]. The `Data-Purpose` header (line 1048) and body `purpose` (line 1068) are self-attested. Nothing technically binds downstream use to the declared purpose. Add a clarifying note that purpose binding is an accountability and audit-trail mechanism, not technical enforcement. Require that purpose URIs resolve to a documented data-use description, and require the server to reject unknown URIs (do not implicitly accept new purposes).

**Anti-enumeration timing side channels** [security]. Rate limits (line 862) and cardinality suppression (line 866-877) do not address timing-based inference. Repeated narrowing queries leak population sizes even when each response is suppressed. Specify a constant-time response floor for suppressed results, or a configurable noise delay below the suppression threshold. Apply rate limits to unique criteria combinations per caller, not just request counts.

**Cross-registry linkage from a single shared subject ID** [security]. V0 uses one common ID across all registries. A compromised connector or audit observer can trivially link the subject across farmer, tax, CRVS, and business registries. Without a v0 mitigation, require audit to log all registries queried for a given `evaluation_id` and require operator policy to cap claims-per-subject-per-window.

**Drift detection silent disable** [security]. Line 533 says "fail validation or disable the affected claim" with no notification obligation. Require a structured audit event with `conflict_reason`, `affected_claim_id`, and the field or semantic that diverged. Require operator-observable monitoring (metrics or health endpoint listing disabled claims).

### Standards positioning

**`AuthenticationLevelOfAssurance` canonical name** [standards, confidence 85]. Line 1272 lists "level of assurance" as an OOTS profile field. The OOTS DSD Information Data Model v1.1.2 (May 2025) calls this field `AuthenticationLevelOfAssurance`. Use the canonical name or annotate with `(OOTS: AuthenticationLevelOfAssurance)`.

**SD-JWT VC "claim allowlist" is not a defined concept** [standards, confidence 82]. Lines 1297 and 1645 use "claim allowlist" as a configuration field. SD-JWT VC draft-16 governs selective disclosure through per-claim `sd` properties (`always`/`allowed`/`never`) in the credential type (`vct`) definition, not through a flat allowlist in issuer metadata. Either map this to the `claims` object in vct metadata or label "claim allowlist" as an application-layer policy on top of the SD-JWT VC type definition.

**`ConformsTo` IRIs must come from OOTS Semantic Repository** [standards, confidence 80]. The OOTS TDD requires `ConformsTo` values to be persistent URLs assigned through the DSD LCM process in the OOTS Semantic Repository registry. Lines 1194-1213 use placeholder `example.gov` URIs throughout. Add a note that for OOTS deployments, `ConformsTo` values are governance-gated registry-assigned IRIs, not invented.

### Implementation plan and code location

**`src/api/evidence_offerings.rs` does not exist in the repo** [impl, confidence 100]. Line 1696 warns "Claim computation code should not be added to `src/api/evidence_offerings.rs`", but that file does not exist in the current source tree. Workspace `Cargo.toml` at the root also has no `evidence-core` or `evidence-server` members yet. Either drop the warning or note this as a file that doesn't exist. Add the workspace `members` update as an explicit Wave 0 prerequisite.

**Crate split tension** [impl, confidence 85]. Source connector trait lives in `evidence-core` (line 1598+); DCI and Registry Data API implementations live in `evidence-server` (line 1610+). Registry Relay's migration adapter (line 1621) cannot reuse connector implementations without depending on `evidence-server` (which drags in Axum and full wiring) unless `evidence-server` is also a library. Clarify: is `evidence-server` library + binary, or should shared connector logic move to `evidence-core`?

**Wave 1 surfaces are not disjoint** [impl]. Worker A produces `ClaimResult`, B contributes fragments through `ClaimResultFragment`, C reads it, D audits it. Without `ClaimResultFragment` defined in Wave 0, A and B collide on the interface mid-wave. Make the fragment definition a Wave 0 done-gate item.

**DoD "at least one" criteria are trivially meetable** [impl, confidence 85]. Lines 1482-1524 list "at least one" of multiple kinds of artifact. Each item should name a specific test fixture or test function that Wave 5 Worker D checks off, not just "at least one X". The "Not Done If" anti-checklist (lines 1551-1573) requires running an end-to-end configured test, not code review; the Wave 5 done gate should reference a test command, not just "passes focused tests".

**Missing required tests** [impl, confidence 85]. The required-tests list (lines 1527-1548) omits: federation roundtrip, drift detection on connector metadata mismatch (line 1498 requires the capability), render-by-evaluation-id positive binding (line 1545 covers only the denial case), ID Mapper roundtrip (line 1500-1501 requires the capability), and audit record content assertion (line 1548 requires emission, not content).

**Deferred ID Mapper and OOTS record-matching are load-bearing for production** [impl, confidence 80]. Lines 1463-1467. A real DCI deployment cannot function with the v0 demo mapper. Add a "Production Readiness Note" under Version 0 Scope stating that v0 is not production-deployable without a production ID Mapper and record-matching adapter.

**`evidence-server` deployment artifact is unspecified** [impl, confidence 80]. Lines 1610-1619 describe what the crate owns but never state whether it is a separate binary, a sidecar to `registry-relay`, or a feature flag. This affects Dockerfile, config schema, health routes, and auth wiring. State explicitly that `evidence-server` has its own `[[bin]]` target, and note whether it shares `registry-relay`'s runtime config or has its own.

**Migration story needs one worked example** [impl, confidence 80]. Lines 1405-1431 are prose. Add one concrete Registry Relay evidence offering mapped to a `ClaimDefinition` config entry as a canonical reference so Wave 0 Worker C (sample configs) has a starting point.

### Definition consistency

**`subject_type` enum not defined** [consistency, confidence 85]. Only `person` is shown in examples (lines 226, 268, 806, 1119). Specify the v0 enumeration (`person` only? `business` reserved?) and where additional types are registered.

**`version` format not specified** [consistency, confidence 85]. Every example uses `2026-05` but the spec never says whether this is `YYYY-MM`, semver, or free string. Range syntax (line 1163) is mentioned but undefined. Specify (recommend `YYYY-MM`) and define version range syntax if ranges are allowed.

**`rule.type` values not enumerated** [consistency, confidence 85]. Examples show `plugin` (line 239) and `predicate` (line 278). The Rule Types section (line 333+) mentions "source field selection" and aggregation. Add a table of valid `rule.type` values (recommended for v0: `field_select`, `predicate`, `plugin`; `aggregate` reserved).

**Federation `ref` dotted namespace** [consistency, confidence 80]. `crvs.age-over-18`, `farmer.farmer-under-4ha`, `tax.tax-compliant-for-year` (lines 1124-1138) look like `namespace.claim-id` pairs. Define `ref` as a locally scoped alias unique within the claim definition's `depends_on` list, used only for referencing within the rule, not a global namespace.

**`Plugin` definition vs ABI tension** [consistency, confidence 80]. Line 131 says "configured code module"; the ABI section (line 347+) says compile-time Rust trait. "Module" implies dynamic loading. Update the Core Concepts definition to "a named, versioned computation unit implemented as a compiled Rust component and bound to a claim definition in configuration".

**Capitalization drift**. `OOTSProfile` (line 146) vs `oots:` YAML key (line 259). `identity_mapping` field (line 963) vs "ID Mapper" prose (line 547+). `Registry Data API` (concept, line 124+) vs `registry_data_api` (connector id, line 237). Pick conventions and apply consistently.

**Plugin diagnostics shape undefined** [consistency, confidence 80]. Line 374 lists "diagnostics allowed for internal audit" as a plugin output; line 384 says plugins must "never bypass disclosure policy or write audit records directly". These are not contradictory but the diagnostics shape is undefined. Define diagnostics as a structured key-value with no claim values, state the host owns writing diagnostics to audit, and state plugins must not include sensitive field values in diagnostics.

## What looked correct under scrutiny

- The CCCEV mapping `ClaimResult` → `Evidence` + `SupportedValue` is correct.
- The OOTS architecture characterization (Evidence Broker, Data Service Directory, Semantic Repository, eDelivery, preview journey, record-matching) is accurate per the OOTS TDD.
- The OOTS adapter boundary claim, that `/claims/evaluate` is not the OOTS wire and an adapter is required, is correct.
- DCI / SP DCI naming maps to the public DCI standards site (`standards.spdci.org`).
- The separation between `value`/`predicate`/`redacted` profiles and SD-JWT VC's own selective disclosure is consistent; they operate at different layers.
- Deferring SD-JWT VC credential status and revocation is reasonable under draft-16, which marks `status` as optional.

## Suggested next moves

1. Fix the convergence-flagged items first: `ClaimResultFragment`, the disclosure example, `search.cardinality_suppressed`, the CCCEV mapping correction, and the CCEV typo. Cheap, high-leverage.
2. Add the missing response bodies for render, issue, well-known, and formats.
3. Promote the disclosure-filtered view invariant, audit pseudonymization rule, and `evaluation_id` lifecycle to explicit normative sections before Wave 0 closes.
4. Add a "Production Readiness Note" so the v0 deferral list is not misread as "v0 ships to prod".

## Sources consulted by reviewers

- CCCEV 2.1.0 Specification: https://semiceu.github.io/CCCEV/releases/2.1.0/
- OOTS Architecture: https://ec.europa.eu/digital-building-blocks/sites/display/OOTS/Architecture
- OOTS Information Data Model v1.1.2 (May 2025): https://ec.europa.eu/digital-building-blocks/sites/spaces/TDD/pages/900013359/
- OOTS EDM XML Examples (September 2024): https://ec.europa.eu/digital-building-blocks/sites/spaces/TDD/pages/797081702/
- SD-JWT VC draft-ietf-oauth-sd-jwt-vc-16: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- DCI Standards (SP DCI Disability Registry, API.DR.06): https://standards.spdci.org/standards/wip-disability-registry/
