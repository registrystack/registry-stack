# Evidence Offering Refactor: Implementation Review

Status: review notes (2026-05-21)

Implementation review of the uncommitted work on `main` against
[`evidence-offering-refactor-spec.md`](evidence-offering-refactor-spec.md). The
spec itself was reviewed in
[`evidence-offering-refactor-spec-review.md`](evidence-offering-refactor-spec-review.md);
this document checks how the code matches the resulting spec.

Six parallel reviewers covered disjoint slices of the codebase:

- **MODEL**: manifest structs and validation (`registry-metadata-core`,
  `src/config/validate.rs`).
- **READ**: read-side metadata endpoints, BRegDCAT-AP JSON-LD, visibility
  filter, cache headers.
- **VERIFY**: `POST /evidence-offerings/{id}/verifications` shape, headers,
  body limit, ambiguity gating.
- **PRIV**: signed receipts, HMAC scoping/salt, `Data-Purpose`, rate limits,
  audit logging.
- **REMOVE**: legacy route removal, OpenAPI, Bruno, docs, scope renaming.
- **DEMO**: farmer/disability/false-positive scenarios + the spec's named
  `cargo` checks.

Each finding has a stream-prefixed stable ID (`MODEL-1`, `READ-1`, etc.) for PR
and issue referencing.

## Executive Summary

The core data model and the offering execution path are largely in place:
manifest structs and compiled metadata exist, the catalog and BRegDCAT-AP
emitters carry the new evidence nodes, `POST
/evidence-offerings/{offering_id}/verifications` is wired and tested for the
happy path, signed receipts use a correct media type and claim set, demo
manifests declare the farmer, disability, and false-positive scenarios, and the
spec's five named `cargo` checks all pass cleanly.

What is missing is sharper than the size of the refactor suggests:

- **13 blockers**. The biggest groups: a security gap (no rate limiting, no
  per-request salt, `aud == sub` in the receipt), three docs/config surfaces
  still using the legacy `verify_scope` / `claim-verification` vocabulary, and
  two demo gaps (no farmer scenario in the demo script, lookup-key mismatch in
  the farmer ruleset).
- **19 should-fix**.
- **2 nice-to-have**.

The work is close to done in the model and HTTP-shape sense, but the privacy
posture and the "remove the old surface" hygiene need a focused second pass
before the Definition of Done holds.

Severity counts: **13 blockers, 19 should-fix, 2 nice-to-have** (after
de-duplication across streams).

## Verification Commands

All five spec-named `cargo` checks were executed in this review:

| Command | Result | Notes |
| --- | --- | --- |
| `cargo fmt --check` | PASS | Two nightly-only `imports_granularity` warnings; not a failure. |
| `cargo test -p registry-metadata-core` | PASS | 14 tests in `metadata_core.rs` pass. No new offering-specific tests yet (see MODEL-4). |
| `cargo test --test demo_configs_load` | PASS | 1 test passing. Covers all demo configs including SP DCI farmer/disability under the `spdci-api-standards` feature. |
| `cargo test --test catalog_entity` | PASS | 39 tests pass. |
| `cargo test --test config_metadata_bindings` | PASS | 6 tests pass. |

Full `cargo test` was not run in this review (out of scope for the named DoD
checks, and high time cost). The DoD also lists it; run it before declaring the
refactor complete.

External SEMIC/SHACL validator: not run. Not detected in PATH; record as
skipped per the spec's instruction.

## Blockers

### MODEL-1: Duplicate offering IDs are only rejected per-dataset

**Spec**: §Validation, "duplicate evidence offering IDs, globally or within a
dataset".

**File**: `crates/registry-metadata-core/src/lib.rs:1618`.

`validate_evidence_offerings` allocates `seen_ids: BTreeSet` per call, and the
call site at lines 963–969 is inside the per-dataset loop in
`validate_manifest`. A duplicate offering ID across two datasets is silently
accepted; the lookup in `evidence_offering()` (line 715) then linearly returns
whichever the iterator hits first. The spec requires global rejection.

**Fix**: accumulate offering IDs in a manifest-wide `BTreeSet` before the
per-dataset loop, or thread that set through `validate_evidence_offerings`.

**Source**: MODEL.

### READ-1: `verification_request_schema_url` is not emitted anywhere

**Spec**: §"Public Metadata Output / GET /metadata/evidence-offerings".

**File**: `crates/registry-metadata-core/src/lib.rs:544`, `1103`, `1109`,
`2409`.

The spec requires each offering item to include
`verification_request_schema_url`, "a URL to the existing schema-document
convention such as `/metadata/schema/{dataset_id}/{entity}/schema.json`, not an
inline schema blob." `grep` across the codebase returns matches only in the
spec file. `CompiledEvidenceOffering`, `render_evidence_offerings`,
`render_evidence_offering`, and `catalog_dataset_json` all omit it. Atlas can't
reach the verification request schema from offering metadata as written.

**Fix**: add the field to `CompiledEvidenceOffering` (built from
`base_url + /metadata/schema/{dataset_id}/{entity}/schema.json`) and emit from
both renderers and the catalog.

**Source**: READ.

### READ-2: BRegDCAT-AP renderer still emits `dspace:participantId`

**Spec**: §"Public Metadata Output", explicit "Do not emit" list (no Dataspace
Protocol contract negotiation or transfer process claims).

**File**: `crates/registry-metadata-core/src/lib.rs:1143`, JSON-LD context at
line 3342, golden fixture `example-civil-registration.breg-dcat-ap.json:39,288`.

`dspace:participantId` is unconditionally emitted in the BRegDCAT-AP catalog
node, and the `dspace` prefix is declared in the JSON-LD context. This is a DSP
term; the spec's "do not emit" list bans it and the DoD reiterates that "OOTS
terms are used only as architecture guidance unless the implementation actually
conforms to the relevant OOTS interface." The behavior predates this refactor,
but the spec explicitly makes the refactor the right time to drop it.

**Fix**: remove `catalog["dspace:participantId"]` from `render_breg_dcat_ap`,
drop the `dspace` prefix from `jsonld_context`, and regenerate the golden
fixture.

**Source**: READ.

### VERIFY-1 / PRIV-2: Rate limiting is entirely absent

**Spec**: §"Authorization And Privacy"; §"Definition Of Done / Verification
Output".

**File**: no file. `rg rate_limit RateLimit governor tower_governor leaky_bucket`
returns nothing.

The spec requires verification execution to be "rate-limited per caller and
offering, with configurable burst and sustained limits", and the DoD lists it
as a Verification Output requirement. There is no middleware, no config, and no
validation for rate limits. An authenticated caller can flood the endpoint
without restriction.

**Fix**: add a per-offering `rate_limit` config block (burst + sustained +
window), wire a `tower_governor`-style or in-process bucket per
`(principal_id, offering_id)`, return `429` + `Retry-After` on exhaustion, and
validate the config in `validate_runtime_bindings`.

**Sources**: VERIFY, PRIV (independent identification, same root cause).

### VERIFY-2 / PRIV-1: Signed-receipt `aud` equals `sub`, both set to caller's principal ID

**Spec**: §"Signed Receipts".

**File**: `src/api/evidence_offerings.rs:447`, `462–463`.

Both `subject` and `audience` are set to
`format!("client:{}", principal.principal_id)`. The spec says `sub` "must not
be the citizen subject identifier" (satisfied), but must be "Relay's service
identity or an opaque non-reversible per-verification token" (not satisfied:
`principal_id` is a stable caller correlation handle). The spec also says `aud`
must be bound to the original caller's client ID and that receipts must not be
forwarded to parties not listed in `aud`. With `aud == sub`, the audience
binding is meaningless: there is no party for whom the receipt is intended that
the receipt itself attests to.

**Fix**: set `subject` to the Relay service DID (available as
`state.config().issuer_did` or a sibling), set `audience` to the OAuth2
`client_id` / API-key entry ID associated with the principal, and confirm the
two values are distinct.

**Sources**: VERIFY, PRIV (same line, same root cause).

### REMOVE-1: Canonical `config/*.yaml` examples still carry `verify_scope`

**Spec**: §"Endpoint Removal" — old scope names removed from demos, docs, and
public examples.

**Files**: `config/example.yaml:144,183`, `config/example.oidc.yaml:176,214`,
`config/spdci_disability_registry.example.yaml:147`.

All three operator-facing example configs declare `verify_scope:
<dataset>:verify`. `src/config/mod.rs:979` still declares
`pub verify_scope: String` as required, which is why the field can't simply be
deleted from the examples. The retention may exist to support SP DCI
(REMOVE-8), but that needs an explicit PR justification per the spec.

**Fix**: decide whether `verify_scope` is being kept as an internal-only field
(then namespace it that way and remove from public examples), or migrate SP DCI
off it and drop the field. Either way, public example configs must not advertise
it.

**Source**: REMOVE.

### REMOVE-2: Demo configs still emit `verify_scope` / `claim_verification_scope`

**Spec**: §"Endpoint Removal".

**Files**: `demo/config/all_demos.yaml` (many lines), `benefits_casework.yaml`,
`clinic_capacity.yaml`, `education_registry.yaml`,
`public_works_projects.yaml`, `subject_registry.yaml`,
`disability_registry.yaml`, `all_standards.yaml`. `claim_verification_scope`
remains in `all_standards.yaml:2340` and `disability_registry.yaml:320`.

Every demo entity still carries `verify_scope`; `evidence_verification_scope`
has been added alongside rather than replacing it. The spec requires the old
names to disappear from demos.

**Fix**: remove `verify_scope` and `claim_verification_scope` from every demo
runtime config. Coordinate with REMOVE-1: the Rust struct may need to accept
the field as optional or drop it before the YAML lines can go.

**Source**: REMOVE.

### REMOVE-3: `docs/api.md` references the legacy `claim-verification.md` filename

**Spec**: §"Implementation Plan" item 15, §"Removed Or Hidden Surfaces".

**Files**: `docs/api.md:236`; cross-references in `README.md:30`,
`docs/development.md:3,189`, `docs/provenance.md:10`.

`docs/api.md` line 236 links to `claim-verification.md` from the Evidence
Verification section. The document itself has been updated content-wise, but
its filename still labels the old product model and four other docs link to it
by the old name. Anyone arriving at the file via these links sees "claim
verification" in the URL/title and may infer the old surface is still
canonical.

**Fix**: rename `docs/claim-verification.md` to `docs/evidence-verification.md`
(or another offering-first name) and update the five callers.

**Source**: REMOVE.

### REMOVE-4: `docs/development.md` instructs contributors to keep `docs/claim-verification.md` current

**Spec**: §"Implementation Plan" item 17.

**File**: `docs/development.md:189`.

The line "Keep `README.md`, `docs/api.md`, `docs/configuration.md`,
`docs/claim-verification.md`, and `docs/ops.md` operationally current." bakes
the legacy filename into developer-facing guidance. It will be re-cited by
anyone running the same checklist.

**Fix**: update the developer-facing list to the renamed file from REMOVE-3.

**Source**: REMOVE.

### REMOVE-5: Agent-skill reference docs still describe the legacy verify model

**Spec**: §"Removed Or Hidden Surfaces".

**Files**: `agent-skills/registry-relay-config-review/references/v1-config-contract.md`
(lines 172, 211, 382, 392, 395, 587, 722); `…/SKILL.md` (lines 54, 57);
`agent-skills/registry-relay-config-author/SKILL.md` (lines 75, 76, 118, 127);
the matching `v1-config-contract.md` in the author skill.

Both AI-agent skill packs require `verify_scope` on every entity, validate
`claim_verification` scopes as live, and list `GET
/datasets/{dataset_id}/{entity}/verify` as a public route. Agent reviewers will
flag correct new configs as broken and rubber-stamp configs that retain the
removed fields.

**Fix**: update both skill packs: replace `verify_scope` with
`evidence_verification_scope`, remove the legacy `/verify` route, replace
`claim_verification` references with the offering equivalent. If the skills are
explicitly internal-only, downgrade to should-fix and label them as such.

**Source**: REMOVE.

### DEMO-1: No farmer scenario in `evidence_offerings_demo.py`

**Spec**: §"Demo Requirements / Farmer Subsidy Happy Path", §"Demo Acceptance".

**File**: `demo/scripts/evidence_offerings_demo.py:41–86`.

`SCENARIOS` contains only `benefits` and `education`. The farmer offering is
declared in `disability_registry.metadata.yaml` /
`all_standards.metadata.yaml`, but the script never exercises it. The spec
requires a farmer-subsidy happy path exercising `farmer_registry.farmer`,
lookup `national_id`, procedure `agricultural-subsidy-application`.

**Fix**: add a `farmer` scenario targeting
`farmer_status_evidence_offering`, with a `DEMO-` or
`DEMO-FR-` prefixed `national_id` and matching `row_path`.

**Source**: DEMO.

### DEMO-2: No disability scenario in `evidence_offerings_demo.py`

**Spec**: §"Demo Requirements / Disability Benefit Federated Or Ambiguous
Path".

**File**: `demo/scripts/evidence_offerings_demo.py:41–86`.

Same gap as DEMO-1 for the disability path. The offering exists in metadata
and runtime, but the demo script has no scenario, so the
provider-selection / missing-region story is never visible.

**Fix**: add a `disability` scenario with a `DR-MEMBER-` (or `DEMO-`) prefixed
identifier, and enable `expose_ambiguous: true` on the disability ruleset or
add a second region offering to demonstrate the ambiguity story the spec asks
for.

**Source**: DEMO.

### DEMO-3: Farmer ruleset uses `id`, but the offering advertises `national_id`

**Spec**: §"Demo Requirements / Farmer Subsidy Happy Path"; manifest declares
`lookup_keys: [national_id]`.

**Files**: `demo/config/disability_registry.yaml:767–773`,
`demo/config/all_standards.yaml:2787–2793`.

The farmer offering metadata says callers verify by `national_id`. The
`farmer-status-v1` ruleset in both runtime configs uses `required_claims: [id]`,
`candidate_lookup: [id]`, `match_fields: {id: id}`. A caller following the
offering and submitting `national_id` will get a `mismatch` because the
ruleset resolves candidates by the internal primary key. The happy path is
broken at the runtime/metadata boundary.

**Fix**: update `farmer-status-v1` to use `national_id` for
`required_claims`, `candidate_lookup`, and `match_fields`. Confirm the farmer
fixture rows include `national_id` values aligned with whatever the demo
script submits.

**Source**: DEMO.

## Should-fix

### MODEL-2: Empty `issuing_authority.country` is not rejected

**Spec**: §"Validation".

**File**: `crates/registry-metadata-core/src/lib.rs:1650–1665`; field declared
at line 284 as `country: Option<String>`.

Validation calls `validate_id` on `issuing_authority.id` and `validate_non_empty`
on `name`, but never checks `country`. `country: ""` deserializes to
`Some("")` and passes. The spec explicitly lists "an empty issuing authority
ID, name, or country".

**Fix**: add a `validate_non_empty` on `country.as_deref().unwrap_or("")`, or
make the field required (`String`) since the example always supplies it.

**Source**: MODEL.

### MODEL-3: `evidence_verification_scope` not checked against the runtime scope allowlist

**Spec**: §"Implementation Plan" item 4.

**File**: `src/config/validate.rs:226–235`.

The cross-boundary check rejects an empty `evidence_verification_scope` but
doesn't verify the value appears in the configured auth scope allowlist. Other
entity scopes are checked by `validate_scopes` in `validate::run`; the offering
scope isn't fed through that. The error variant chosen is `FieldMissing`,
which is also semantically off for this case.

**Fix**: feed the offering scope through the same allowlist check used for
other entity scopes, and add a `ScopeMissing` (or similar) variant for
clarity.

**Source**: MODEL.

### MODEL-4: No tests for the new offering validation rules

**Spec**: §"Definition Of Done / Validation".

**File**: `crates/registry-metadata-core/tests/metadata_core.rs`.

Existing tests cover pre-existing validation paths. There is no
`validation_rejects_offering_errors` (or equivalent) test exercising the new
rejection rules: duplicate offering IDs, bad `evidence_type` reference, bad
`entity` reference, bad `lookup_keys` reference, empty
`issuing_authority.country`, unsupported access kind, empty ruleset. The DoD
requires deterministic validation errors for these cases.

**Fix**: extend the `fixture("example-civil-registration")` test pattern with
an `evidence_offerings` section, then add a test that exercises each rejection
path.

**Source**: MODEL.

### READ-3: BRegDCAT-AP evidence nodes go to `@included`, not `@graph`

**Spec**: §"Public Metadata Output / GET /metadata/dcat/bregdcat-ap".

**File**: `crates/registry-metadata-core/src/lib.rs:1165` (calls
`append_included_nodes`).

The spec says evidence nodes belong in `@graph` by default; `@included` should
be used only when a downstream validator requires it. The renderer puts them in
`@included` unconditionally.

**Fix**: move evidence nodes (requirements, evidence types, offerings) to the
`@graph` key; keep `@included` for range-typed reference nodes that genuinely
need it.

**Source**: READ.

### READ-4: No golden fixtures cover the new evidence-offering output

**Spec**: §"Definition Of Done / Metadata Output".

**File**: `crates/registry-metadata-core/tests/fixtures/golden/`.

Existing fixtures cover `example-civil-registration` for catalog / SHACL /
BRegDCAT-AP, but none include `evidence_offerings`. Silent regressions in the
JSON-LD term selection will not be caught.

**Fix**: add at least one manifest fixture with requirements + evidence types +
an offering, and add golden assertions for `render_breg_dcat_ap`,
`render_catalog`, `render_evidence_offerings`, `render_evidence_offering`.

**Source**: READ.

### READ-5: No integration tests for `GET /metadata/evidence-offerings[/{id}]`

**Spec**: §"Public Metadata Output", §"Definition Of Done / Metadata Output".

**Files**: `tests/catalog_entity.rs`, `tests/entity_routes.rs`.

Neither endpoint has tests covering: `Cache-Control: private` + `Vary:
Authorization` headers; `offering.not_found` 404 with invariant `detail`;
indistinguishable behavior across unknown / hidden / unauthorized; visibility
consistency with `/metadata/catalog` and `/metadata/dcat/bregdcat-ap`.

**Fix**: add tests for both metadata offering endpoints covering header
emission, the 404 path, and scope-filtered visibility against the catalog and
BRegDCAT-AP endpoints (READ-5 is also a regression guard for the visibility
filter the DoD calls out explicitly).

**Source**: READ.

### READ-6: `cpsv:holdsRequirement` is never emitted

**Spec**: §"Portable Metadata Manifest".

**File**: `crates/registry-metadata-core/src/lib.rs:2705` (`public_service_node`).

Public service nodes emit `cpsv:produces` only. The spec says CPSV-AP-aware
output should link services to requirements via `cpsv:holdsRequirement` where
the selected profile supports it. BRegDCAT-AP is the current CPSV-aware
profile.

**Fix**: emit `cpsv:holdsRequirement` from `public_service_node` referencing
requirement IRIs whose `procedure_contexts` overlap with the service's
dataset, or document why it is deferred.

**Source**: READ.

### VERIFY-3: `requirement` is `skip_serializing_if = "Option::is_none"`

**Spec**: §"Verification Endpoint / Response", §"Definition Of Done /
Verification Output".

**File**: `src/api/evidence_offerings.rs:294–296`, `243`.

The spec sample shows `requirement` as a top-level non-optional string. The
implementation skips it when `offering.requirement_iris` is empty. A consumer
relying on the field will silently see it absent. Same pattern on
`ingest_version`: serialized as `null` rather than skipped, which may differ
from the sample's intent.

**Fix**: validate at compile or runtime-binding time that every
`registry-relay-verification` offering has at least one requirement IRI; emit
`requirement` as a non-optional string. Decide on `ingest_version` policy
(skip when None vs document as nullable).

**Source**: VERIFY.

### VERIFY-4: No test that an authenticated-but-unauthorized caller gets `offering.not_found`

**Spec**: §"Authorization And Privacy".

**Files**: `tests/entity_routes.rs` (no such test).

The handler does return `offering_not_found()` on a scope check failure
(`src/api/evidence_offerings.rs:106–107`), but there is no test asserting that
a principal without `evidence_verification_scope` for a known offering
receives the same `404 + offering.not_found` as for an unknown offering. The
invariant is the core anti-enumeration guarantee.

**Fix**: add an integration test where a valid principal lacks the scope for a
known offering and assert `404` + `code == "offering.not_found"` + the same
`detail` string as the unknown case.

**Source**: VERIFY.

### PRIV-3: `Data-Purpose` is not parsed as IRI; no purpose allowlist enforcement

**Spec**: §"Authorization And Privacy".

**File**: `src/api/evidence_offerings.rs:395–405`; config in
`src/config/mod.rs` has `require_purpose_header: bool` only.

`Data-Purpose` is accepted as any non-empty string. The spec requires values
to be IRIs and, when an allowlist is declared, rejection of values outside it
with a documented Problem Details code.

**Fix**: parse the header as a `url::Url`-style absolute IRI, add a
`purpose_allowlist: Vec<String>` field (per offering or per entity), and
reject with a stable Problem Details code on failure.

**Source**: PRIV.

### PRIV-4: No per-request salt on the claim HMAC; no salt returned to caller

**Spec**: §"Authorization And Privacy".

**File**: `src/api/evidence_offerings.rs:205–220`.

`claim_hash` is computed over canonical JSON that includes `verification_id`
(unique per request, but not surfaced as a verifiable salt). The spec
requires short-value fields (national IDs) to be bound with a per-request
salt included in the HMAC material and returned in the response so the caller
can reproduce the hash.

**Fix**: generate a random salt per request, include it in the HMAC material,
return it as `claim_salt` in the JSON response (and in the receipt when
signed).

**Source**: PRIV.

### PRIV-5: HMAC key is global, not per-offering

**Spec**: §"Authorization And Privacy".

**Files**: `src/config/mod.rs:76–87`, `src/claim_verification.rs:24–59`.

A single `binding_key_id` / `binding_key_env` pair backs every verification.
The spec requires keys to be scoped at least per offering and preferably
per-caller-per-offering, so identical claim values from different callers (or
different offerings) don't collide on the same hash.

**Fix**: derive per-offering subkeys via HKDF from the master key using the
offering IRI as context, or add explicit per-offering key configuration. The
HKDF approach is the smaller change and avoids new operator config.

**Source**: PRIV.

### PRIV-6: `AuditContextExt` does not carry `offering_id` for verification events

**Spec**: §"Authorization And Privacy" (audit must capture offering ID).

**File**: `src/audit/mod.rs:196–215`.

Audit context carries `dataset_id`, `entity_name`, `table_id`, but not
`offering_id`. The spec requires the audit stream to capture offering ID,
caller identity, timestamp, decision, purpose, and operational status. Without
`offering_id`, a downstream auditor cannot tie an event to the offering that
was checked.

**Fix**: add `offering_id: Option<String>` to `AuditContextExt`, populate it
in `verify_evidence_offering`.

**Source**: PRIV.

### PRIV-7: `strict_evidence_jwt_requested` doesn't honor Accept `q` values

**Spec**: §"Signed Receipts".

**File**: `src/api/evidence_offerings.rs:413–420`.

The current implementation does a substring scan against the `Accept` header
without parsing quality values. `Accept: application/vnd.registry-relay.…+jwt;q=0.1,
application/json;q=1.0` would be treated as a strict JWT request when the
client clearly prefers JSON. Probably rare in practice but the negotiation
contract is fragile.

**Fix**: parse Accept with q values (or use an existing content-negotiation
helper); fall back to JSON when JSON has higher q than the JWT type.

**Source**: PRIV.

### REMOVE-6: `tests/entity_routes.rs` baseline principal carries legacy scopes

**Spec**: §"Implementation Plan" item 14.

**File**: `tests/entity_routes.rs:136–138, 316–318, 344–346`.

The `ENTITY_ROUTE_SCOPES` constant still includes `"social_registry:verify"`
and `"social_registry:claim_verification"`. Test config fixtures still set
`verify_scope` and `claim_verification_scope`. Future tests written against
this constant will silently exercise legacy scopes as if they're current.

**Fix**: remove the two legacy scope strings from `ENTITY_ROUTE_SCOPES`. Drop
the legacy scope fields from the fixture blocks once the Rust struct allows
it.

**Source**: REMOVE.

### REMOVE-7: `claim_verification.ruleset_not_allowed` code leaks through the offering endpoint

**Spec**: §"Implementation Plan" item 14, §"Verification Endpoint" (error codes
should not expose internal-engine vocabulary).

**File**: `tests/entity_routes.rs:1195` asserts this code on what is now the
offering endpoint path.

The legacy claim-verification error code surfaces as the visible
`application/problem+json` code on the new offering endpoint. External callers
reading the error code see the old product vocabulary.

**Fix**: audit `src/api/evidence_offerings.rs` for any legacy `claim_verification.*`
codes; replace with offering-scoped equivalents (e.g.
`offering.access_denied`, `offering.input_invalid`). Update the test
assertion accordingly.

**Source**: REMOVE.

### REMOVE-8: SP DCI handler still uses `verify_scope` as its gate

**Spec**: §"Endpoint Removal" (concrete internal-caller justification required
to keep legacy fields).

**File**: `src/api/spdci.rs:143`.

`run_disabled_status` calls `require_scope_for(principal,
&route.entity.access.verify_scope)`. If `verify_scope` is being retained as a
required struct field solely to keep SP DCI working, the spec requires that
rationale to be explicit in the implementation PR. It isn't documented as
such.

**Fix**: either migrate SP DCI to a dedicated SP DCI scope (or
`evidence_verification_scope`), or document the retention with a comment in
both the config struct and the PR description, and namespace the field as
internal in public examples.

**Source**: REMOVE.

### DEMO-4: Farmer scenario, when added, must use `DEMO-` prefix identifiers

**Spec**: §"Demo Requirements" — national IDs must be synthetic and not
resemble real EU formats.

**Files**: `demo/scripts/evidence_offerings_demo.py:46–84` (current claim values
are internal primary keys, not national IDs); future farmer scenario.

The current `per-2001` / `stu-2001` identifiers are internal primary keys, not
national IDs, so the rule isn't violated by what's in the file today. It
becomes load-bearing when DEMO-1's farmer scenario is added, since the farmer
offering uses `national_id`.

**Fix**: when adding the farmer scenario, use `DEMO-FR-001` (or similar
explicit-synthetic) values, not `FR-MEMBER-001`-style strings that can pass
for real.

**Source**: DEMO.

### DEMO-5: False-positive boundary is not exercised by the demo script

**Spec**: §"Demo Requirements / False Positive Dataset" — "Atlas and Relay
metadata must not classify it as an evidence provider for disability status."

**Files**: `demo/scripts/evidence_offerings_demo.py`.

The false-positive datasets (education and benefits, with `disability_status`
fields but no disability offering) are structurally correct. But the demo
script has no narrated step demonstrating the boundary: nothing calls
`GET /metadata/evidence-offerings?evidence_type=disability_status_evidence`
and asserts that `education_registry` does not appear.

**Fix**: add a `false_positive` (or `boundary`) step to the demo script that
queries the filtered offerings list and prints the absence of the social/edu
datasets.

**Source**: DEMO.

### DEMO-6: Disability offering lacks `admin_unit_level_1` / multi-provider modeling

**Spec**: §"Demo Requirements / Disability Benefit Federated Or Ambiguous
Path".

**File**: `demo/config/disability_registry.metadata.yaml:94–117`.

The offering declares only `jurisdiction: {country: ZZ}`. The spec wants the
demo to show "either multiple possible providers or an explicit missing
selection attribute such as region." Neither is in the manifest.

**Fix**: add a commented-out `admin_unit_level_1` placeholder to model a
missing selection attribute, or declare a second regional disability
offering to demonstrate provider ambiguity.

**Source**: DEMO.

## Nice-to-have

### READ-7: `registry_relay:provesRequirement` on the evidence-type node is redundant

**Spec**: §"Definition Of Done / Standards Compliance".

**File**: `crates/registry-metadata-core/src/lib.rs:2745`.

The requirement-to-evidence-type direction is already correctly handled via
`cccev:hasEvidenceTypeList` + `cccev:specifiesEvidenceType`. The reverse
direction also emits `registry_relay:provesRequirement` on the evidence-type
node. It's technically allowed (Relay namespace), but it's redundant with the
declared CCCEV chain and may confuse consumers.

**Fix**: consider dropping the predicate or documenting it explicitly as a
Relay-only denormalization.

**Source**: READ.

### PRIV-8: No documented key-rotation cadence

**Spec**: §"Authorization And Privacy" — "Operators must document key rotation
cadence and key-retirement behavior."

**Files**: `src/provenance/mod.rs` (rotation mechanics present but
undocumented).

The implementation supports retired keys correctly. The spec also asks for
operator-visible documentation of rotation cadence and retirement behavior,
which is missing.

**Fix**: add a section to `docs/ops.md` (or `docs/provenance.md`) covering
cadence and retirement; add a runtime check that a retired key's
`retired_after` is in the past.

**Source**: PRIV.

## How to read severity

- **Blocker**: Definition of Done cannot hold; either a security gap or a
  user-visible contract bug.
- **Should-fix**: spec requirement is not met but DoD might still pass
  pragmatically; fix before the refactor PR lands.
- **Nice-to-have**: spec preference or future hardening; can defer.

For SEC findings (PRIV-1..PRIV-6), blocker maps to "high/critical" and
should-fix to "medium" per the spec-review document's convention.

## Open questions for the implementation PR

These were flagged by reviewers and need a product decision (not a code
change) before the implementation PR closes.

1. **`dspace:participantId` retention** (READ-2): is there a profile validator
   downstream that requires this field? If yes, the spec's "do not emit DSP
   claims" rule needs an explicit carve-out.
2. **`@included` vs `@graph` for evidence nodes** (READ-3): is there a known
   BRegDCAT-AP SHACL or DCAT-AP validator that requires `@included`? If yes,
   the current behavior is justified and the spec text should reflect it.
3. **`verify_scope` retention** (REMOVE-1, REMOVE-8): is the field being kept
   for SP DCI? Document the rationale or migrate.
4. **`agent-skills/` scope** (REMOVE-5): are these AI agent skill docs
   "public" for DoD purposes, or internal? Decision changes the severity.
5. **Per-request salt placement** (PRIV-4): salt in JSON response only, or
   also in the receipt JWT as a separate claim?
6. **Hash audit-store boundary** (PRIV-6): is there a planned controlled
   audit store, or is the current local sink the long-term home?
7. **Demo runner config** (DEMO open question): farmer/disability scenarios
   target `disability_registry.yaml` / `all_standards.yaml`, not
   `all_demos.yaml`. The README narrated demo refers only to `all_demos.yaml`,
   so demo runners may need a separate command path or a merged config.
