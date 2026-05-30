# Evidence Offering Refactor Spec: Consolidated Review

> **Note:** the external crate is now published as `registry-manifest-core`. This document was written when it was called `registry-metadata-core`; the old name is preserved in the body for historical accuracy.

Status: review notes (2026-05-21)

Review of [`evidence-offering-refactor-spec.md`](evidence-offering-refactor-spec.md) by five domain reviewers:

- **STD** — EU semantic standards (CCCEV, DCAT-AP, CPSV-AP, ODRL, JSON-LD hygiene)
- **REST** — REST/HTTP contract design against the existing API surface
- **IMPL** — Implementation feasibility against the actual codebase
- **SEC** — Security, privacy, and authorization
- **OOTS** — Focused follow-up against the OOTS Technical Design Documents

Each finding has a stable ID (e.g., `STD-3`, `IMPL-1`) for PR and issue referencing.

## Executive Summary

Overall: the spec's direction is sound. The shift to evidence-offering-first discovery, the standards anchor, and the careful boundary drawing ("not an EB, DSD, or eDelivery") all hold up under expert review. There are no findings that would force a redesign.

What needs attention before implementation starts:

- **4 blockers** (REST-2, REST-4, REST-8, IMPL-1). Three are missing HTTP-contract details that the spec must pin (status codes, error shape, content negotiation). One is a load-order constraint in the manifest deserializer that controls how the demo files are migrated.
- **18 should-fix items.** Split roughly evenly across standards correctness, security/privacy posture, codebase fit, and REST contract polish.
- **High-severity privacy issues** (SEC-1 through SEC-4) deserve a dedicated pass with a DPO or security-aware reviewer before any code lands. The verification endpoint is a registry oracle for citizen PII, and the spec's current mitigations are insufficient against an authorized-but-malicious caller.

Severity counts: **4 blockers, 18 should-fix, 13 nice-to-have**.

## How to read this document

Each finding lists:

- **What the spec says** (the section under review, often with a line reference).
- **The issue** (what's wrong, missing, or ambiguous).
- **Recommended fix** (often a concrete sentence or paragraph the author can drop in).
- **Severity**: blocker / should-fix / nice-to-have. For SEC findings, blocker maps to "critical/high" and should-fix to "medium".
- **Source**: which reviewer flagged it.

## Blockers

### REST-2: Verification response status code unspecified

**Spec:** §"Verification Endpoint" → "Response". Shows a JSON body including `verification_id` but never names an HTTP status.

**Issue:** The existing `POST .../claim-verifications` returns `200 OK`, not `201`. If the new endpoint is treated as resource-creation (201) then a `GET /verifications/{id}` is implied, which contradicts `Cache-Control: no-store` and the spec's intent that verifications are events, not stored resources.

**Fix:** Add to the Response section: "HTTP 200 OK. The `verification_id` is an opaque correlation handle for audit and receipt matching; no GET retrieval endpoint is provided."

**Source:** REST.

### REST-4: Error model not specified

**Spec:** §"Authorization And Privacy" ("unknown, hidden, and unauthorized offering IDs should return the same public error shape after authentication").

**Issue:** The "public error shape" is undefined. The codebase already standardizes on RFC 9457 `application/problem+json` (see `src/error.rs:1-40`), with a stable `code` extension field (pattern `schema.unknown_dataset`, `schema.unknown_resource`). The spec doesn't reference this.

**Fix:** Specify:
- Status `404 Not Found` for all three cases (unknown, hidden, unauthorized) post-authentication. Indistinguishable on purpose.
- Content-Type `application/problem+json`.
- New error code `offering.not_found` following the existing naming convention.
- The `detail` string must not vary between the three cases.

**Source:** REST, with SEC-8 reinforcing.

### REST-8: Signed receipt content negotiation unspecified

**Spec:** §"Signed Receipts". Names the media type (`application/vnd.registry-relay.evidence-verification+jwt`) but doesn't say how a caller requests it.

**Issue:** The existing `claim-verifications` endpoint uses `Accept` header on the POST (see `CLAIM_VERIFICATION_JWT` in `src/api/entity.rs:47`, and `maybe_issue_claim_verification_receipt`). The spec needs to commit to this pattern and define the fallback behavior.

**Fix:** Specify: same POST endpoint; caller sends `Accept: application/vnd.registry-relay.evidence-verification+jwt`; server responds with the JWT body. If the signer is unavailable and the caller strictly requested the JWT type, return `406 Not Acceptable` (or `503 Service Unavailable` if the signer is down rather than absent). If the caller did not strictly request the JWT type, fall back to the plain JSON response.

**Source:** REST.

### IMPL-1: `deny_unknown_fields` forces lockstep manifest migration

**Spec:** §"Implementation Plan" steps 1, 10.

**Issue:** Every manifest struct in `crates/registry-metadata-core/src/lib.rs` carries `#[serde(deny_unknown_fields)]`, including `MetadataManifest` (line 15) and `DatasetManifest` (line 104). Adding `requirements`, `evidence_types`, and nested `evidence_offerings` to demo YAML files before the structs accept those fields will hard-fail `demo_configs_load`. The reverse (adding struct fields without updating YAML) is fine.

**Fix:** Sequence the work explicitly:
1. Add structs and field deserializers first.
2. Wire validators.
3. Regenerate all five demo `*.metadata.yaml` files in the same change.
4. Run `cargo test --test demo_configs_load` before any PR merges.

Document this as a step in the implementation plan, not as a footnote.

**Source:** IMPL.

## Should-fix

### STD-1: `EvidenceProvider` is not a CCCEV class

**Spec:** §"Public Concepts" → `EvidenceProvider`.

**Issue:** CCCEV 2.x has no `EvidenceProvider` class. Provider-side agency is expressed via three properties on `cccev:Evidence`: `isCreatedBy`, `isIssuedBy`, `isProvidedBy`, all typed to `foaf:Agent` or `org:Organization`. The spec calls the concept "CCCEV-compatible" by association, which it isn't.

**Fix:** Either (a) rename to `Issuer` / `IssuingAuthority` and bind to `cccev:Evidence isIssuedBy` with `org:Organization`, or (b) keep `EvidenceProvider` and explicitly state it is a Relay extension term emitted under a configured vocabulary prefix.

**Source:** STD.

### STD-2: Call out `EvidenceOffering` as a Relay extension explicitly

**Spec:** §"Public Concepts" → `EvidenceOffering`. Currently hedged ("CCCEV-compatible where the chosen version supports them").

**Issue:** Neither CCCEV 2.0/2.1, CPSV-AP 3.2.0, nor OOTS defines an "Evidence Offering" class. OOTS represents provider-specific capability through DSD registration tuples, not as a vocabulary class. The hedging risks SEMIC reviewers reading the term as standards-defined.

**Fix:** Add a sentence: "`EvidenceOffering` is a Registry Relay extension term. It is not a CCCEV, DCAT, CPSV-AP, or OOTS class. It is emitted under a configured Relay vocabulary prefix."

**Source:** STD.

### STD-3 / OOTS-1: `procedure_contexts` is loosely bound

**Spec:** §"Portable Metadata Manifest" example, lines 150–151, 183–184. Uses `procedure_contexts: [agricultural-subsidy-application]` as a free string list.

**Issue:** Two converging problems:
- CPSV-AP 3.2.0 has no `procedureContext` predicate. The CPSV-AP path is `cpsv:PublicService` → `cpsv:holdsRequirement` → `cccev:Requirement`. The spec's manifest field never wires through to a `cpsv:PublicService` IRI.
- OOTS *does* use "procedure context" but as a singular `procedure-id` input on the EB `get-requirements` query, drawn from the EU-level **Procedures-CodeList** (SDG Regulation Annex II), hosted in the OOTS Semantic Repository (`https://sr.oots.tech.ec.europa.eu/`). The spec's plural string list does not align with that.

**Fix:** Add to §"Portable Metadata Manifest" after the example:

> `procedure_contexts` is a Relay-local advisory hint, not an OOTS field. OOTS's analog is a single `procedure-id` from the EU-level Procedures-CodeList in the Semantic Repository. Manifest values SHOULD be IRIs or codes from that codelist when the offering maps onto an SDG Annex II procedure, and MAY be free identifiers for non-SDG or Relay-only procedures. On CPSV-AP-aware JSON-LD output, link offerings to `cpsv:PublicService` IRIs via `cpsv:holdsRequirement` rather than emitting a Relay-invented `procedureContext` predicate.

**Source:** STD, sharpened by OOTS.

### STD-4 / OOTS-2: DSD-style separation of legal authority from access endpoint

**Spec:** §"Public Concepts" → `EvidenceProvider`, `AccessRoute`. §"Portable Metadata Manifest" example lines 173–186.

**Issue:** OOTS DSD `find-data-services` returns records that explicitly distinguish `sdg:Publisher` (legal authority) from `sdg:AccessService` (technical endpoint). The DSD record also carries `sdg:AuthenticationLevelOfAssurance` (eIDAS-aligned: low/substantial/high) and `sdg:ConformsTo`. The spec collapses these.

**Fix:** Document the split, mirror the LoA field:

> `EvidenceProvider` is the legal authority responsible for the evidence (analogous to OOTS DSD `sdg:Publisher`). `AccessRoute` is the technical endpoint that serves the evidence (analogous to OOTS DSD `sdg:AccessService`). A single legal authority MAY publish multiple access routes.
>
> An offering SHOULD declare a `level_of_assurance` field with one of `low | substantial | high` (eIDAS-aligned, mirroring DSD `sdg:AuthenticationLevelOfAssurance`) when an LoA can be asserted. The field is optional; absence means "not declared."

Add to the example:

```yaml
        level_of_assurance: substantial
        access:
          kind: registry-relay-verification
          conforms_to: registry-relay-verification:v1
          ruleset: farmer-status-match-v1
```

**Source:** STD, sharpened by OOTS.

### STD-5: Requirement to EvidenceType linkage skips `EvidenceTypeList`

**Spec:** §"Portable Metadata Manifest" example, `proves: [requirement-id]`.

**Issue:** CCCEV does not link a Requirement directly to an EvidenceType. The path is via `cccev:EvidenceTypeList` (property `hasEvidenceTypeList`). The manifest's `proves` is a reverse shortcut that does not round-trip cleanly.

**Fix:** Either (a) acknowledge in the spec that `proves` is a Relay convenience that maps to `cccev:EvidenceTypeList` on output, or (b) model an explicit `evidence_type_list` step in the manifest. Without this, SHACL conformance checks on CCCEV shapes will catch the missing intermediate class.

**Source:** STD.

### STD-6: JSON-LD term hygiene contradicts validation rule

**Spec:** §"Validation" rejects "unresolved compact IRIs in concept, purpose, provider, legislation, policy, and profile fields." §"Portable Metadata Manifest" example uses bare strings (`farmer-status-requirement`, `ministry-agriculture`, `farmer-registration-evidence-offering`) for `id` fields and `provider.id`.

**Issue:** Either bare strings are unresolved compact IRIs that the validator should reject, or they are local identifiers that get minted into IRIs on JSON-LD output. The spec rules and the example contradict. SHACL `sh:nodeKind sh:IRI` checks will fail on bare strings.

**Fix:** Pick one of:
- Require every `id` to be an absolute IRI or a compact IRI under a configured manifest prefix, validated identically to `concept_uri`.
- Document the local-ID → IRI mint rule explicitly (e.g., `{relay-base}/requirements/{id}`) and treat the local string as a Relay-internal handle rewritten on JSON-LD output.

Either way, also fix the receipt payload (currently uses bare strings for `requirement`, `evidence_type`, etc.). A signed attestation referring to `"requirement": "farmer-status-requirement"` is not dereferenceable.

**Source:** STD.

### OOTS-3: Receipt should carry OOTS-shaped optional metadata

**Spec:** §"Signed Receipts" payload fields.

**Issue:** The receipt is correctly not claiming OOTS conformance, but adding two OOTS-shaped optional fields makes it round-trip-compatible without overclaiming.

**Fix:** Add to the receipt payload as optional fields:
- `jurisdiction`: ISO 3166-1 alpha-2 `country` plus optional `admin_unit_level_1`, mirroring DSD `sdg:Jurisdiction`.
- `level_of_assurance`: `low | substantial | high`, mirroring the offering's LoA.

Append to the section: "The Relay decisions (`match | mismatch | ambiguous`) describe the matching outcome inside the offering's binding. They do not map onto the OOTS Evidence Error codelist (e.g., the DSD `DSDErrorCodes` codelist hosted in the OOTS Semantic Repository). A future OOTS bridge would translate Relay decisions and operational failures into the appropriate OOTS exception codes; the current contract intentionally does not."

**Source:** OOTS.

### OOTS-4: Discovery filters look like DSD/EB queries — disclaim explicitly

**Spec:** §"Public Metadata Output" → `GET /metadata/evidence-offerings`.

**Issue:** A `?evidence_type=Y&country=Z` filter structurally mirrors DSD `find-data-services`. A `?procedure_context=X` filter loosely mirrors EB `get-requirements`. Don't drop the filters (they're useful) but make the non-conformance explicit.

**Fix:** Insert before the `GET /metadata/evidence-offerings` block:

> `GET /metadata/evidence-offerings` MAY accept query-string filters such as `procedure_context`, `evidence_type`, and `country`. The output shape and these filters intentionally resemble discovery primitives exposed by the OOTS Evidence Broker (`get-requirements`, `get-evidence-types`) and the OOTS Data Service Directory (`find-data-services`), so that an OOTS-aware Atlas can reason about Relay offerings using familiar concepts. However, Registry Relay is not an EB or a DSD: it lists only the offerings published by the calling Relay tenant under the caller's metadata scope, it does not federate across providers, and it does not implement the ebRS/RegRep transport. Consumers MUST NOT treat this endpoint as an OOTS Common Service.

**Source:** OOTS.

### OOTS-5: Cite concrete TDDs in the Standards Anchor

**Spec:** §"Standards Anchor". Currently anchors only the OOTS API hub root and the architecture page.

**Issue:** Reviewers cannot trace specific spec claims back to specific normative OOTS documents.

**Fix:** Replace with:

- OOTS Technical Design Documents (hub): `https://ec.europa.eu/digital-building-blocks/sites/spaces/OOTS/pages/617087010/Technical+Design+Documents`
- OOTS TDD Chapter 1, Introduction & High-Level Architecture: `https://ec.europa.eu/digital-building-blocks/sites/x/MIvFO`
- OOTS TDD Chapter 3, Common Services: `https://ec.europa.eu/digital-building-blocks/sites/x/K4vFO`
- OOTS TDD Chapter 4, Evidence Exchange: `https://ec.europa.eu/digital-building-blocks/sites/x/L4vFO`
- OOTS TDD Chapter 5, Data Models: `https://ec.europa.eu/digital-building-blocks/sites/x/LYvFO`
- OOTS API Hub: `https://oots.pages.code.europa.eu/tdd/apidoc/`
- EB `get-requirements`: `https://oots.pages.code.europa.eu/tdd/apidoc/evidence-broker/latest/get-requirements/`
- EB `get-evidence-types`: `https://oots.pages.code.europa.eu/tdd/apidoc/evidence-broker/latest/get-evidence-types/`
- DSD `find-data-services`: `https://oots.pages.code.europa.eu/tdd/apidoc/data-services-directory/latest/find-data-services/`
- SR `get-asset-metadata`: `https://oots.pages.code.europa.eu/tdd/apidoc/semantic-repository/latest/get-asset-metadata/`
- SR content root: `https://sr.oots.tech.ec.europa.eu/`
- OOTS Evidence Explorer: `https://oots.pages.code.europa.eu/evidence-explorer/ee-app/#/home`

**Source:** OOTS.

### REST-1: URL namespace split between reads and actions

**Spec:** §"Core Decision" and §"Verification Endpoint".

**Issue:** Reads live under `/metadata/evidence-offerings[/{id}]`; the action lives at top-level `/evidence-offerings/{id}/verifications`. The existing precedent (`POST /datasets/{id}/{entity}/claim-verifications` co-located with its reads) is the opposite pattern. A client cannot derive the rule from one example.

**Fix:** Pick one and document it:
- **Option A** (matches existing pattern): `POST /metadata/evidence-offerings/{id}/verifications`. Acknowledges `/metadata` is not strictly read-only.
- **Option B** (clean split): `GET /evidence-offerings`, `GET /evidence-offerings/{id}`, `POST /evidence-offerings/{id}/verifications`. Drop the `/metadata` prefix entirely on offering routes.

**Source:** REST.

### REST-3: Idempotency story for the verification event

**Spec:** §"Verification Endpoint". No mention of idempotency.

**Issue:** Two identical retried requests produce two `verification_id`s, two `claim_hash`es, and two signed JWTs with different `jti`. Surprising on retry unless documented.

**Fix:** State explicitly: "Repeat POSTs create independent verification events. Callers needing retry-safety must implement deduplication outside Relay." Or, if support is desired, specify `Idempotency-Key` header semantics (key format, scope, TTL).

**Source:** REST.

### REST-5: Metadata GET endpoints lack `Cache-Control` and `Vary`

**Spec:** §"Public Metadata Output". Only the verification POST is required to emit `Cache-Control: no-store` and `Vary: Authorization, Accept`.

**Issue:** The new metadata GET endpoints are authorization-filtered. The existing metadata routes (`src/api/metadata.rs`) emit content-hash ETags but **no `Cache-Control` and no `Vary`**. A shared cache could serve one caller's authorization-filtered metadata to another caller.

**Fix:** Require on `GET /metadata/evidence-offerings` and `GET /metadata/evidence-offerings/{id}` (and recommend retrofitting to other authorization-filtered `/metadata/*` routes):

```http
Cache-Control: private
Vary: Authorization
```

The existing-routes retrofit is out of scope for this refactor but the spec should flag it so the gap isn't propagated forward.

**Source:** REST, with SEC-7 reinforcing for renderer parity.

### REST-9: Request schema discovery field is underspecified

**Spec:** §"Public Metadata Output" → `GET /metadata/evidence-offerings` lists "accepted verification request schema" as an offering field.

**Issue:** No statement of whether the field value is a URL, an inline JSON Schema, or an OpenAPI `$ref`. The existing OpenAPI generator (`src/api/openapi.rs:295`) builds per-entity claim-verification request schemas as component refs.

**Fix:** Specify the field value is a URL referencing the entity schema document (e.g., `GET /metadata/schema/{dataset_id}/{entity}/schema.json`), aligned with the existing schema-document convention. Not an inline blob.

**Source:** REST.

### REST-10: `offering_id` character set conflicts with existing validator

**Spec:** §"Portable Metadata Manifest" example uses `farmer-registration-evidence-offering` (hyphens) as an offering ID.

**Issue:** The existing `is_valid_id` in `src/config/validate.rs:851-857` enforces `^[a-z][a-z0-9_]*$` for `DatasetId` and `ResourceId` (no hyphens). Either the example will fail validation, or offering IDs need a different validator.

**Fix:** Decide and document. Two defensible choices:
- Constrain offering IDs to the existing pattern `^[a-z][a-z0-9_]*$` and rewrite the example to `farmer_registration_evidence_offering`.
- Introduce a separate offering-ID validator allowing `^[a-z][a-z0-9_-]*$` (hyphens permitted for CCCEV-style readability). Confirm the URL segment in `POST /evidence-offerings/{offering_id}/verifications` accepts hyphens without escaping.

**Source:** REST.

### IMPL-2: `CompiledMetadata.filter()` has no offering awareness

**Spec:** §"Authorization And Privacy" ("metadata visibility follows existing metadata-scope filtering").

**Issue:** The existing `filter()` method in `crates/registry-metadata-core/src/lib.rs:550-580` takes a `Fn(&CompiledDataset, &CompiledEntity) -> bool` and strips datasets where no visible entity remains. It does not know about offerings. After filtering, an offering whose backing entity was hidden can survive in the filtered result.

**Fix:** Extend `filter()` (or add a sibling) to also strip offerings whose `entity` was filtered out, before checking dataset emptiness. Add to the implementation plan as a sub-step of step 2.

**Source:** IMPL.

### IMPL-3: Runtime/metadata separation check belongs in two places

**Spec:** §"Validation" lists rules that mix metadata-only checks ("duplicate offering IDs") with runtime-pointer checks ("a ruleset binding that does not exist on the referenced entity").

**Issue:** `validate_manifest` in `registry-metadata-core` cannot see runtime config. The ruleset-existence check can only run in `src/config/validate.rs::validate_runtime_bindings` after both sides are loaded. The spec's flat list hides this split.

**Fix:** Split step 3 of the implementation plan into:
- **3a:** Pure structural rules in `validate_manifest` (cross-references inside the manifest, duplicate IDs, missing entity references inside the dataset, unresolved compact IRIs).
- **3b:** Cross-boundary rules in `validate_runtime_bindings` (ruleset existence on the referenced entity, scope-name allowlist updates).

Without the split, a standalone metadata manifest will validate clean and the server will only crash at startup when runtime config is missing the named ruleset.

**Source:** IMPL.

### IMPL-4: `validate_scope_name` allowlist is hardcoded

**Spec:** §"Endpoint Removal And Deprecation" suggests `evidence_verification_scope` as a new scope name.

**Issue:** `src/config/validate.rs:1265` accepts only `"metadata" | "aggregate" | "rows" | "verify" | "claim_verification"`. Introducing `evidence_verification` (or any new offering-bound scope level) will fail validation on otherwise valid runtime configs.

**Fix:** Add to the implementation plan: update the `validate_scope_name` allowlist when introducing the new scope level, before changing demo configs that use it.

**Source:** IMPL.

### IMPL-5: OpenAPI generator is hand-written Rust, not config-driven

**Spec:** §"Implementation Plan" step 9 ("Remove or hide low-level verification and ruleset discovery endpoints from public OpenAPI and docs").

**Issue:** `src/api/openapi.rs` (~500 lines) emits the four old verify/ruleset paths explicitly (lines 423–528). Step 9 is more than a flag flip; it's a substantive edit to a Rust builder.

**Fix:** Promote OpenAPI generator updates to a first-class plan step. Include adding the new evidence-offering paths and removing the four legacy paths in the same change.

**Source:** IMPL.

### IMPL-6: Inline-config users have no path to declare offerings

**Spec:** §"Portable Metadata Manifest" assumes offerings live in the portable `*.metadata.yaml`.

**Issue:** Users on the inline-config path (no split manifest) get `MetadataManifest` synthesized from runtime config via `manifest_from_runtime` in `core_adapter.rs`. That synthesizer has no concept of offerings.

**Fix:** Either (a) say explicitly that evidence offerings require the split-manifest path, and migrate all three demo scenarios to split manifests, or (b) extend `manifest_from_runtime` to synthesize offerings from runtime config (adds scope, probably not worth it for v1).

The spec should pick one and document it. The split-manifest-only path is simpler and aligned with the "portable metadata" framing.

**Source:** IMPL.

### IMPL-7: JWT receipt signing path needs a new constant and code path

**Spec:** §"Signed Receipts" introduces `application/vnd.registry-relay.evidence-verification+jwt`.

**Issue:** The existing receipt path lives in `src/provenance/jwt_receipt.rs` and uses `CLAIM_VERIFICATION_RECEIPT_MEDIA_TYPE`. The new media type means a new constant, a new signing path entry, and tests in `tests/claim_verification_jwt_receipt.rs` (which is load-bearing for the current receipt semantics).

**Fix:** Add an explicit plan step for "Add `EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE` constant and a sibling signing path in `provenance/jwt_receipt.rs`; extend or copy `claim_verification_jwt_receipt.rs` tests." The current step 11 ("Update tests, golden fixtures, ...") buries this.

**Source:** IMPL.

### IMPL-8: Bruno collection surgery is non-trivial

**Spec:** §"Endpoint Removal And Deprecation" implies a quick removal.

**Issue:** 15 Bruno files reference `verify`/`claim-verif`/`ruleset`. Of those:
- 4 are direct calls to `GET /datasets/.../verify` that must be rewritten to the new offering endpoint (Benefits 04, Education 05, Cross-Demo 11, Auth Boundaries 15).
- 10 are scope-boundary tests checking that a `verify`-scoped key cannot read rows/schema/aggregates; these should survive but need a scope-name audit (see IMPL-4).
- 1 is a Subject Registry test.

**Fix:** Add to the implementation plan: "Audit and rewrite Bruno collection: 4 direct call sites need new endpoint targets; 10 scope-boundary tests need scope-name confirmation." Don't treat this as a sweeping `rg -i verify | xargs sed` job; the scope-boundary tests are intentional.

**Source:** IMPL.

### IMPL-9: Test rewrites larger than the spec implies

**Spec:** §"Definition Of Done" → "Tests are updated so old endpoint coverage does not preserve the old product model by accident."

**Issue:** Three test files encode the old product contract:
- `tests/entity_routes.rs` (verify and claim-verification route tests)
- `tests/claim_verification_jwt_receipt.rs` (receipt semantics, load-bearing)
- `tests/third_party_verification.rs` (third-party verify semantics)

These are not cosmetic; they need substantive rewrites, not deletion, to maintain equivalent coverage under the new endpoint shape.

**Fix:** Acknowledge in the plan that test rewrites are a discrete chunk, not a side effect of step 11.

**Source:** IMPL.

### SEC-1: No rate limiting on the verification oracle (HIGH)

**Spec:** §"Authorization And Privacy".

**Issue:** Any bearer with an offering's verification scope can submit unlimited `(national_id, name)` tuples. `Cache-Control: no-store` and HMAC hashes do nothing to stop an authorized-but-malicious caller (compromised service account, insider) enumerating the registry.

**Fix:** Add a normative requirement:

- Per-caller rate limiting at the offering level, configurable burst and sustained rate.
- Audit log capturing caller identity, offering ID, and timestamp per call (not just hashes), so anomaly detection is possible.
- Deployments that need stronger integrity for PII-adjacent verification events must send audit records to an append-only external store or independently anchor retained-log tail hashes.

**Source:** SEC.

### SEC-2: `ambiguous` decision is an information-bearing oracle (HIGH)

**Spec:** §"Verification Endpoint" decision table.

**Issue:** "More than one candidate matched and the offering permits disclosure" confirms that the submitted partial claims are shared by ≥ 2 registered individuals. Significant disclosure. The spec doesn't say who controls the disclosure knob, what the default is, or whether it can be set per-field.

**Fix:** Default `ambiguous` to suppressed: return `mismatch` with no disambiguation signal unless the offering's config explicitly enables ambiguity disclosure. Document the enabling condition as a governance decision requiring DPO review, not a developer config flag. State the default in the spec.

**Source:** SEC.

### SEC-3: HMAC key scoping and rotation unspecified (HIGH)

**Spec:** §"Authorization And Privacy" ("treat claim and evidence hashes as sensitive correlation identifiers").

**Issue:** If the HMAC key is per-deployment static, the hash is a stable pseudonymous identifier correlatable across callers and across time. If the key is per-offering but shared across callers, same problem. National IDs are short and easily brute-forceable from a known-key HMAC if the key leaks.

**Fix:**
- Specify key scoping explicitly. Minimum: per-offering. Preferred: per-caller-per-offering (different caller, different key, different hash for the same subject).
- Require a documented key rotation cadence.
- For short-value fields like `national_id`, require a per-request salt included in the hash and returned in the response, so the hash is not deterministically recomputable from the field value alone even on key leak.

**Source:** SEC.

### SEC-4: Receipt `sub` undefined; transferable bearer attestation risk (HIGH)

**Spec:** §"Signed Receipts".

**Issue:** The receipt JWT requires `sub` but never says what it's bound to. If `sub` is the citizen subject, the JWT is a PII-bearing artifact. If `aud` is not bound to the original caller, the receipt is forwardable to a third party as a factual assertion about a citizen, bypassing Relay's authorization entirely. The vendor media type alone (correctly avoiding `application/vc+jwt`) does not prevent this misuse structurally.

**Fix:**
- Pin `sub` semantics: either Relay's service identity, or an opaque non-reversible per-verification token. Not the citizen subject identifier.
- Bind `aud` to the caller's client ID. Receipt is invalid when presented to any other relying party.
- Add a normative statement: "Receipts must not be forwarded to parties not listed in `aud`."
- Make signed receipts opt-in (disabled by default; per-offering toggle).
- Add a `receipt_type` constant value (e.g., `"relay-verification-receipt"`) and a `disclaimer` claim stating: "This token records that a verification check was executed. It does not attest that the subject holds any status or right."

**Source:** SEC.

### SEC-5: Error messages may leak raw PII (MEDIUM)

**Spec:** §"Authorization And Privacy" ("do not echo full submitted claims in responses").

**Issue:** Validation errors are an obvious leak surface and the spec doesn't address them. A naive implementation might return `"national_id 'FR-ABC123' is not a valid format"`.

**Fix:** Add: "Validation and error responses must not include raw claim values. Error messages may reference field names and error types only."

**Source:** SEC.

### SEC-6: Hash logging boundary unstated (MEDIUM)

**Spec:** §"Authorization And Privacy".

**Issue:** Claim hashes called "sensitive correlation identifiers" but the spec is silent on where they may or may not appear. A hash in an observability backend creates a correlation surface. Two calls from different callers with the same `national_id` produce the same hash if the key is shared.

**Fix:** Add: "Claim and evidence hashes must not be emitted to structured logs, distributed traces, or error outputs unless the log store is access-controlled to the same authorization level as the verification endpoint. Hashes must not be forwarded to third-party observability vendors without explicit data processing agreements."

**Source:** SEC.

### SEC-7: Catalog renderers not explicitly auth-filtered

**Spec:** §"Public Metadata Output" requires `/metadata/catalog` and `/metadata/dcat/bregdcat-ap` to include evidence offerings, but the explicit auth-filter statement only attaches to the dedicated `/metadata/evidence-offerings` endpoints.

**Issue:** An unauthenticated read of `/metadata/dcat/bregdcat-ap` could enumerate all configured offerings via JSON-LD.

**Fix:** State explicitly that catalog and BRegDCAT-AP renderers apply the same offering-level visibility filter as the dedicated offering endpoints. Add to the Definition of Done as a validation criterion.

**Source:** SEC, reinforced by IMPL-2.

### SEC-8: Unknown-offering status code not pinned (MEDIUM)

**Spec:** §"Authorization And Privacy" ("unknown, hidden, and unauthorized offering IDs should return the same public error shape after authentication"). See also REST-4.

**Issue:** The spec doesn't pin the status. 404 for unknown + 403 for unauthorized leaks existence; 404 for all three is the only safe choice.

**Fix:** Pin: `404 Not Found` for all three cases (unknown, hidden, unauthorized) post-authentication. Add a test asserting that an authorized caller receives 404 for a valid-but-unauthorized offering, not 403.

**Source:** SEC + REST.

### SEC-9: `Data-Purpose` value not constrained (MEDIUM)

**Spec:** §"Authorization And Privacy".

**Issue:** `Data-Purpose` is required when the offering or entity requires purpose tracking and included in the hash and signed receipt. The spec doesn't say whether the value is an IRI, free text, or validated against a configured allowlist. If free text, the audit trail is meaningless.

**Fix:** Require `Data-Purpose` values to be IRIs. When purpose tracking is mandatory, the offering config must declare an allowlist of acceptable purpose IRIs; submissions outside that list are rejected with a documented error code.

**Source:** SEC.

## Nice-to-have

### STD-7: ODRL out of receipt is correct, but document the choice

**Spec:** §"Signed Receipts" omits ODRL.

**Fix:** One-line note: "The receipt does not assert ODRL duty discharge. ODRL fulfilment semantics are out of scope for v1." Pre-empts the obvious SEMIC question.

**Source:** STD.

### STD-8: Forward-reference eIDAS eSeal and OOTS Evidence Response envelope

**Spec:** §"Signed Receipts".

**Fix:** Add: "Future versions may issue this receipt as a JAdES-signed eSeal under eIDAS Regulation (EU) 910/2014; v1 uses a plain JWT. This receipt is not an OOTS Evidence Response; OOTS responses are delivered via eDelivery in ebRS/Regrep envelopes."

**Source:** STD.

### STD-9: `cccev:Requirement` vs `cccev:Criterion`

**Spec:** §"Standards Anchor" lists "criterion" in the CCCEV scope.

**Issue:** `cccev:Criterion` is a subclass of `cccev:Requirement`. If the manifest's "requirements" can include things that aren't strictly criteria (e.g., information requirements), use `cccev:Requirement` not `cccev:Criterion` on JSON-LD output.

**Fix:** State the chosen rdf:type explicitly in the spec.

**Source:** STD.

### STD-10: Prefer `@graph` over `@included`

**Spec:** §"Public Metadata Output" → BRegDCAT-AP allows either.

**Fix:** Default to `@graph`; treat `@included` as opt-in. JSON-LD 1.1 `@included` is poorly handled by some SHACL validators.

**Source:** STD (medium confidence).

### STD-11: `dcatap:applicableLegislation` shape

**Spec:** §"Public Metadata Output" → "`dcatap:applicableLegislation` only when explicitly configured."

**Fix:** Confirm renderer emits `eli:LegalResource`-typed objects (per DCAT-AP 3.0 guidance), not bare IRI strings.

**Source:** STD.

### REST-6: Removed routes return 404

**Spec:** §"Endpoint Removal And Deprecation".

**Fix:** State: "Removed routes return 404; no `Sunset` or `Deprecation` header shim. (Codebase has no soft-deprecation pattern to follow.)"

**Source:** REST.

### REST-7: Pagination on offerings list

**Spec:** §"Public Metadata Output" → `GET /metadata/evidence-offerings`.

**Fix:** Add: "This endpoint returns the full filtered set without pagination, matching the existing `/metadata/*` list endpoints. If offering counts grow substantially, cursor-based pagination matching the entity collection pattern should be added."

**Source:** REST.

### SEC-10: Demo `national_id` collision risk (LOW)

**Spec:** Demo example uses `national_id: DEMO-123`.

**Fix:** Add: "Demo national IDs must use a prefix or structure that is formally invalid in all EU member states' national ID formats and must never be derived from or resemble real identifiers." The `DEMO-` prefix appears safe but should be asserted, not assumed.

**Source:** SEC.

### SEC-11: `jti` replay enforcement (LOW)

**Spec:** §"Signed Receipts" lists `jti`.

**Fix:** Either specify Relay maintains a short-lived `jti` issuance log to detect replay, or state explicitly that replay prevention is the relying party's responsibility, and document a short `exp` window (e.g., 5 minutes).

**Source:** SEC.

### SEC-12: Make receipt semantics survive forwarding (LOW)

**Spec:** §"Signed Receipts".

**Fix:** See SEC-4. Adding a `receipt_type` constant and a `disclaimer` claim makes the "we checked" vs "subject is registered" distinction structural, not just media-type-dependent.

**Source:** SEC.

### IMPL-10: Catalog renderer extension is mechanical

**Spec:** §"Implementation Plan" step 4.

**Note:** `render_catalog` in `crates/registry-metadata-core/src/lib.rs:819` builds a `json!({...})` literal. Adding `requirements`, `evidence_types` top-level and `evidence_offerings` per-dataset is additive. `render_breg_dcat_ap` (line 893) uses `append_included_nodes`; CCCEV nodes follow the same pattern with one prefix added to the context. No invasive refactor needed.

**Source:** IMPL (positive confirmation, not a finding to address).

### IMPL-11: Authorization model migration is small

**Spec:** §"Authorization And Privacy".

**Note:** Scope check is `require_scope(principal, scope_string)` called inline per handler (`src/auth/scopes.rs`). Migration to offering-scoped auth reads the scope string from offering config instead of `EntityConfig.access`. No middleware refactor needed. Combined with IMPL-4 (validator allowlist), the change is small.

**Source:** IMPL (positive confirmation).

## Reviewer Roster

- **STD** (EU semantic standards): CCCEV 2.x, DCAT-AP / BRegDCAT-AP, CPSV-AP 3.2.0, ODRL 2.2, JSON-LD hygiene.
- **REST** (HTTP contract): URL design, status codes, content negotiation, error model, caching, idempotency, schema discovery, against existing codebase patterns.
- **IMPL** (codebase fit): Manifest structs, validators, claim-verification engine reuse, renderers, OpenAPI generator, demo migration, Bruno collection, test coverage continuity.
- **SEC** (security/privacy): Verification oracle, HMAC scoping and rotation, signed receipt semantics, PII boundaries in logs/errors, auth filter parity, status code disclosure.
- **OOTS** (OOTS TDD follow-up): Procedures-CodeList alignment, DSD record shape, eIDAS LoA, evidence response envelope, exception model, specific TDD URLs.

## Caveats and Gaps

- The OOTS reviewer could not retrieve the verbatim **Evidence Response payload schema** (Chapter 4 sub-pages gated behind EU Login) or the full **`DSDErrorCodes` codelist contents** (per-operation `/README` pages 404 to WebFetch). Both would require offline retrieval: clone `https://code.europa.eu/oots/tdd`, or open the gated Confluence pages in a browser with EU Login. If the spec ends up needing field-by-field alignment with the Evidence Response or with specific exception codes, plan a follow-up pass.
- The standards review confirmed CCCEV 2.0 and 2.1 terminology. CCCEV releases sometimes evolve quickly; before submission to any SEMIC review, re-confirm against the version pinned by the deployment.
- The security review's HIGH-severity items (SEC-1 through SEC-4) deserve a focused privacy/DPO review before code lands. They are not the kind of issue that can be smoke-tested away in integration.

## Suggested Order of Operations

1. **Resolve blockers** (REST-2, REST-4, REST-8, IMPL-1): edit the spec to pin status codes, error model, content negotiation, and document the manifest-migration load order.
2. **Address standards should-fixes that affect on-disk shapes** (STD-1 through STD-6, OOTS-1 through OOTS-5): these change the manifest schema and the JSON-LD output. Better to fix in the spec than to migrate twice.
3. **Address security HIGH items** (SEC-1 through SEC-4): these may change config schema (rate-limit knobs, ambiguity defaults, key scope) and the receipt payload shape. Resolve before implementation.
4. **Expand the implementation plan** to cover IMPL-3 through IMPL-9: split validators, OpenAPI generator surgery, scope-allowlist update, Bruno audit, test-file rewrites, JWT receipt path.
5. **Begin implementation** with the spec updated and the plan expanded.
6. **Nice-to-haves** can fold into the same implementation pass or follow up later, depending on bandwidth.
