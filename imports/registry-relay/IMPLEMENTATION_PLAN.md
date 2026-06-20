# Registry Relay — Identity Attribute Release: Implementation Plan

Status: ready for implementation
Scope: `registry-relay` repository only
Branch: `claude/zealous-planck-gq10an`
Source spec: "Registry Relay identity attribute release implementation brief" (handoff)

> This is an internal engineering plan. It is a working artifact — keep it out of
> the focused product PR if the PR is meant to be minimal (e.g. place under an
> internal/ path, gitignore it, or strip before merge). Do not reference it from
> public product docs.

---

## 1. Objective

Add a governed **identity attribute release** capability to Registry Relay: a
purpose-bound, projection-limited, exactly-one-subject lookup that returns only
the attributes approved for a named release profile, mapped into OIDC/UserInfo-style
claims. The immediate downstream consumer is an eSignet Authenticator plugin
(separate repo, **not** built here). Relay must answer with a minimized claim
bundle, never a raw registry row, and a caller holding the release scope must
still be unable to enumerate or read ordinary rows.

Disclosure ladder (attribute release sits below projected-row, above verification):

```
No disclosure → Metadata → Aggregate → Verification/claim result
  → Attribute release bundle → Projected row
```

## 2. Verdict / feasibility

**Feasible, no blockers.** Every slice is greenfield within its module with a
clean in-repo precedent. The single gating risk — evaluating CEL predicates and
scalar expressions from inside `registry-relay` without editing the sibling
`crosswalk` repo — is resolved: the crosswalk mapping runtime already evaluates
CEL booleans over `source` (`emit: "present(source.id)"` in
`demo/mappings/spdci/crvs-person.yaml:8`) and scalar/compound expressions, so a
thin one-field-document adapter reusing `MappingRuntime`/`compile_mapping`/`evaluate`
covers both `deceased == false` and `given_name + ' ' + surname`.

## 3. Decisions (locked)

| Topic | Decision |
|---|---|
| Profile attachment | Attach `attribute_release_profiles` to **entities** (enables source-field validation). Discovery walks all entities' profiles. |
| Profile identity | Globally unique `(profile_id, version)` across all datasets/entities, enforced at config load. No silent "latest" — version is a required path segment. |
| Release scope | Distinct per-dataset scope (e.g. `<dataset_id>:identity_release`); `release_scope != read_scope`. |
| API path | `POST /v1/attribute-releases/{profile_id}/versions/{version}/resolve`; discovery `GET /v1/attribute-releases`. |
| Media type | `application/json` only in v1. No proprietary `vnd.*` type. |
| `claims` field | absent ⇒ profile default set; `[]` ⇒ 400; unknown requested claim ⇒ **deny**. |
| Public denial collapse | not-found / ambiguous / release-condition-denied / required-claim-missing ⇒ single public `release.subject_denied` (403); distinct **internal** audit outcomes preserved. |
| `profile_not_found` | 404 generic not-found (does not confirm enumeration). |
| Internal-outcome audit seam | dedicated `ar_internal_outcome` field on `AuditContextExt`/`AuditRecord`; value sourced from `ReleaseError::audit_code()`. |
| Subject hash | **keyed** hash via Relay's audit hasher, profile-scoped field domain; **never** raw value, **never** an unkeyed public hash, **never** in the public response body. |
| Signing | Do not sign in v1 (eSignet signs). If ever needed, reuse provenance/VC-JWT envelope. |
| Discovery visibility | Authenticated-only (every metadata route requires a principal). Scope strings and sensitivity labels are never exposed on any anonymous surface. |
| Expressions | CEL for release conditions and computed claims, reusing the existing crosswalk runtime via a Relay-owned one-field-document adapter. No new expression language. |
| **CEL build topology** | **CEL is in the Cargo `default` feature set.** A bare `cargo build` includes crosswalk-runtime + CEL + the endpoint. (See §6.) |

## 4. Cross-slice reconciliations (rationale)

- **Entity attachment over root `Config`:** validation must check that subject and
  claim `source_field`s exist on the backing entity, which requires the entity in
  scope. Discovery iterates all entities' profiles; global `(id,version)` uniqueness
  is hoisted into `validate_ids_and_uniqueness` (mirrors the `datafusion_table_names`
  accumulator).
- **`ar_internal_outcome` over reusing `pdp_stable_problem_code`:** the latter has a
  PDP-decision meaning; overloading it is confusing. The error slice's `audit_code()`
  is the *source* of the distinct label; the handler writes it into
  `ctx.ar_internal_outcome`. Public collapse stays in `ReleaseError::code()`.
- **Cardinality:** the query engine silently truncates, so the handler must read with
  `limit: Some(2)` to detect a duplicate; `>1` maps to `SubjectAmbiguous`
  (collapsed to `release.subject_denied`).
- **Endpoint prefix:** plural `/v1/attribute-releases`; `classify_endpoint` uses
  `path.starts_with("/v1/attribute-releases")`, correctly covering both discovery
  and resolve.

---

## 5. Component design (file-anchored)

### 5.1 Config & validation
Files: `src/config/mod.rs`, `src/config/validate.rs`, `config/example.yaml`,
`tests/config_entities.rs`, `src/config/test_support.rs`

New serde structs near `EntityConfig` (`mod.rs:996`), all `#[serde(deny_unknown_fields)]`:
`AttributeReleaseProfile`, `ReleaseSubjectConfig`, `ReleaseConditionsConfig`,
`ReleaseExpressionConfig`, `ReleaseClaimConfig`, `ReleaseResponseConfig`; enums
`SubjectCardinality { One, Many }`, `ClaimSensitivity { DirectIdentifier, Personal,
Public, Pseudonymous }` (a **separate** closed enum, not the dataset-level
`Sensitivity`). Attach to `EntityConfig`:
```rust
#[serde(default)]
pub attribute_release_profiles: Vec<AttributeReleaseProfile>,
```
Claim model: `name`, `source_field` XOR `expression.cel`, `required: bool`,
optional `sensitivity`/`format`/`locale`, `shareable: bool` (default true).

Validation:
- New `validate_entity_release_profiles(dataset, entity, &exposed_fields, governed_policy)`
  called from `validate_entities` (`validate.rs:2776`) after `exposed_fields` is built.
- Subject `source_field` and each claim `source_field` must be in `exposed_fields`
  (reuse the `validate_entity_filters` membership pattern, `validate.rs:3312`).
- `release_scope`: reuse `validate_entity_scope(..., required=true)` for dataset-binding
  + reserved-namespace rejection; additionally assert `release_scope != read_scope`.
- Purpose: when the entity's `governed_policy.permitted_purposes` is non-empty, the
  profile `purpose` must be `Some` and a member of that list.
- `id`/`version` non-empty; claims non-empty; at least one `required` claim; duplicate
  claim names rejected (`config.duplicate_id`); `source_field` XOR `expression.cel`.
- Global `(id,version)` uniqueness: accumulator hoisted into
  `validate_ids_and_uniqueness` (`validate.rs:1442`) before the dataset loop.
- CEL compile validation hook: mirror `validate.rs:854`
  (`crosswalk_core::MappingRuntime::new(RuntimeOptions::default()).compile_mapping(...)`),
  feature-gated; invalid CEL ⇒ `ConfigError::ValidationError` at load.

**Known auth touch-point:** `is_valid_scope_level` (`validate.rs:2013`) hard-codes
grantable API-key suffixes (`metadata|aggregate|rows|verify|evidence_verification`).
Add `identity_release` so a key can actually be granted the release scope.

### 5.2 Error taxonomy & outcome model
Files: `src/error.rs`, `tests/error_taxonomy.rs`, `src/audit/mod.rs` (seam only)

New `ReleaseError` sub-enum wired into top-level `Error` via `#[from]`. The public
collapse lives in a `|`-joined `code()` arm:

| Internal | Public code | Status |
|---|---|---|
| `ProfileNotFound` | `release.profile_not_found` | 404 |
| `SubjectInvalid` | `release.subject_invalid` | 400 |
| `SubjectNotFound` / `SubjectAmbiguous` / `SubjectReleaseDenied` / `ClaimUnavailable` | `release.subject_denied` | 403 |
| `SourceUnavailable` | `release.source_unavailable` | 503 |

The four collapsed variants must render **byte-identical** (status, `code`, `title`,
`detail`, `type` URI). Add `ReleaseError::audit_code() -> &'static str` returning the
distinct internal labels (`release.subject_not_found`, `…ambiguous`,
`…subject_release_denied`, `release.claim_unavailable`); non-collapsed variants
return their `code()` string. Reuse `auth.scope_denied` / `auth.purpose_required`
(400) / `auth.purpose_denied` unchanged. Detail strings must never embed profile id,
subject value, or source host (use the existing `sanitise_operator_string`/`truncate`
caps if any operator string is embedded). Update the `error_taxonomy.rs` contract
test: variant+expected tables, a "collapsed variants render identically" test, an
"audit_code differs from public code" test, and `into_response` code-extension entries.

### 5.3 CEL adapter
Files: `src/attribute_release/` (new module), validation hook in `src/config/validate.rs`

Relay-owned thin adapter (no edits to `crosswalk`):
- Predicate (`deceased == false`) and scalar (`given_name + ' ' + surname`) are each
  evaluated by synthesizing a single-field SPDCI-shape mapping doc carrying the
  expression, `compile_mapping` at config load (fail-closed on invalid CEL),
  `evaluate(EvaluationInput { source, context })` at request time, then reading the
  single field back (`bool` for predicates, scalar `Value` for computed claims).
- Missing field / eval error ⇒ **fail-closed** (deny / load-error), never silently
  allow, never drop a computed claim. PII-free diagnostics (reuse the
  `mapping_issue_diagnostics` discipline from `spdci.rs:354`).
- **Implementer must verify against the pinned `CROSSWALK_REF` before finalizing the
  doc string:** (a) the `version:"0.1"` source-binding grammar (`deceased` vs
  `source.deceased`); (b) whether a false predicate yields zero records vs a
  false-valued record; (c) that scalars round-trip as a raw `Value`; (d) whether a
  non-document scalar/predicate entrypoint already exists (prefer it if so). If a
  needed string/date helper is absent in crosswalk-core, the claim must degrade
  explicitly, never silently.

### 5.4 API surface
Files: `src/api/attribute_release.rs` (new), `src/api/mod.rs`, `src/server.rs`

Router merged into the auth-gated `protected` surface (`server.rs:223-239`), mirroring
`merge_spdci_routes`. Reuse the `RouteDeps` extractor and `RouteState::resolve`
pattern from `spdci.rs`. `ResolveRunError { error, pdp_audit }` so denials still
carry audit context.

Load-bearing gate order (each returns before the next; scope/purpose deny **before**
any source read):
1. Authenticate (`Option<Extension<Principal>>`; `None` ⇒ `MissingCredential`).
2. `require_scope(principal, release_scope)`.
3 & 4. `require_governed_read_access(...)` — Data-Purpose (`DATA_PURPOSE_HEADER`,
   `governed.rs:23`) + ODRL policy **atomically**, with
   `route_identity = "registry-relay.attribute-release"`,
   `GovernedRedactionProjection::DeferredOutput`.
5. Validate `subject.id_type`/`value` (precedent `filters_from_idtype_query`,
   `spdci.rs:768`); a mismatched/blank id_type or a non-scalar/blank value ⇒
   `release.subject_invalid` (400) — a request-shape error, distinct from the
   collapsed `release.subject_denied`, that reveals nothing about subject
   existence.
6. Exact lookup: `read_collection` with `fields: Some(profile source fields)`,
   `limit: Some(2)`, filters = `[subject_eq]` (+ profile-bound trusted filters). First
   projection enforcement of "only configured source fields."
7. Cardinality: `0` ⇒ `SubjectNotFound`; `>1` ⇒ `SubjectAmbiguous`.
8. Release-condition predicate (CEL adapter); fail ⇒ `SubjectReleaseDenied`.
9. Project to claim names (second layer): resolve claim set (absent ⇒ default; `[]` ⇒
   400; unknown ⇒ deny); drop governed `redaction_fields`; build response field-by-field
   with `json!` so source fields cannot leak and the raw subject value never appears
   outside released claims. The `source` block (profile metadata only) is emitted
   only when `response.include_source_metadata` is set (default off).
10. Audit (attach `AuditContextExt`; `attach_pdp_audit`).

Response echoes resolved `profile_id` + `profile_version`. JSON-only; `Content-Type`
mismatch ⇒ 415 (axum `Json`); malformed body ⇒ 400; no `vnd.*`. POST keeps the subject
identifier out of URLs/access logs.

### 5.5 Audit & observability
Files: `src/audit/mod.rs`, `src/audit/redact.rs`, `tests/audit_record.rs`

- Add `EndpointKind::AttributeRelease` (`mod.rs:206`) and a `classify_endpoint`
  (`mod.rs:1187`) arm `path.starts_with("/v1/attribute-releases")` **before** the
  `Other` catch-all.
- Add `ar_*` fields to `AuditContextExt` and `AuditRecord` (all
  `skip_serializing_if = Option::is_none`, so the field-shape contract test is
  unaffected): `ar_profile_id`, `ar_profile_version`, `ar_subject_id_type`,
  `ar_subject_id_raw` (context only — **never** serialized to the record),
  `ar_requested_claims`, `ar_released_claims`, `ar_internal_outcome`,
  `ar_source_cardinality_outcome`, `ar_source_availability_class`; plus
  `ar_subject_id_hash` on the record only.
- Middleware hashes `ar_subject_id_raw` via `sensitive_value_hash_keyed(hasher,
  "ar_subject_id:{profile_id}:{id_type}", raw)` → `ar_subject_id_hash`
  (`hmac-sha256:`/`sha256:` prefixed). Profile-scoped field domain prevents
  cross-profile collisions.
- `purpose`, `principal_id`, `duration_ms`, `pdp_policy_id/_hash` reuse existing
  fields/seams (`attach_pdp_audit`). `AuditOutcome` bucket stays status-derived;
  `ar_internal_outcome` carries the fine-grained label for denied-through-collapse.
- Wrap `ar_subject_id_raw` in a `Sensitive<String>` newtype whose `Debug` prints
  `[REDACTED]` to defend the `derive(Debug)` leak path. The handler must never
  `tracing`-log the raw subject.

Never log: raw subject identifiers, released claim **values**, bearer tokens, API
keys, full request bodies, private source rows.

### 5.6 Metadata & OpenAPI
Files: `src/api/metadata.rs`, `src/api/openapi.rs`, `tests/attribute_release_routes.rs`

- `GET /v1/attribute-releases` (authenticated): per visible profile — id, version,
  title, description, purpose, accepted subject id types, claim names, required claims,
  `response_media_type: "application/json"`, and `release_scope` (authenticated-only).
  Per-profile metadata visibility gating mirrors `visible_metadata_entity_ids`. Apply
  the private metadata headers (`Cache-Control: private, no-store`, `Vary: Authorization`).
- OpenAPI: add `attribute_releases_configured(config)` predicate; gate path + schema
  insertion on it (mirror `spdci_configured` at `openapi.rs:1333`). Do **not** add to
  `ensure_static_release_paths` (so an unconfigured build omits it).
- Never expose private source table ids, paths, secret names, or policy internals.

---

## 6. Build topology (CEL in `default`)

- `Cargo.toml`: keep a named feature `attribute-release = ["crosswalk-runtime"]` for
  `#[cfg(...)]` gating, **and** add it to `default` → `default = ["attribute-release"]`.
  A bare `cargo build` now compiles crosswalk-core + CEL adapter + endpoint.
- Regenerate and commit `Cargo.lock` against the pinned `CROSSWALK_REF`.
- The lean-default CI guard is intentionally retired: `just test-default`/`lint-default`
  (`justfile:28-38`) and the default-shape jobs now exercise CEL by design. Update
  `scripts/check_docker_build_contract.py` — the "default cargo build path" assertion
  (~:107) and the release-feature string (~:173) — in lockstep.
- `deny.toml:22-27`: the RUSTSEC-2023-0089 (`atomic-polyfill`) review trigger — *"before
  making CEL mapping part of a hardened default runtime"* — is now tripped. Discharge it
  with an explicit reviewed rationale (unmaintained-crate advisory, non-exploitable path
  here) or pin/patch the transitive dep. Requires reviewer sign-off in the PR.
- Keep the `attribute-release`-off feature-disabled load-time rejection (mirror
  `SpdciMappingFeatureDisabled`) so `--no-default-features` errors cleanly and the
  negative path stays tested.
- Run `just ci-preflight` before the PR (features + lock + Docker + workflows change).

---

## 7. Execution waves

Each wave = focused diff(s) on `claude/zealous-planck-gq10an`, reviewed against this
plan and the privacy invariants before the next wave.

1. **Wave 1 (parallel, no inter-deps):** config+validation · error taxonomy
   (`ReleaseError`) · CEL adapter + feature flag (+ `default` wiring). Higher effort on
   config and CEL.
2. **Wave 2:** API handler+router (consumes config/errors/CEL) · audit fields+classifier
   (consumes the internal-outcome label).
3. **Wave 3:** metadata discovery + OpenAPI · self-contained demo fixtures · example.yaml
   profile.
4. **Wave 4:** full test matrix green → `just ci-preflight` → regenerate `Cargo.lock` →
   update `check_docker_build_contract.py` + `deny.toml` in lockstep → PR notes
   (how an eSignet plugin consumes the endpoint).

---

## 8. Test matrix

**Config validation:** subject/claim source_field existence; non-empty id+version;
global `(id,version)` uniqueness; `release_scope` required + dataset-bound + distinct
from read scope; purpose permitted when governed; required claims non-empty; duplicate
claim names rejected; `source_field` XOR `expression.cel`; invalid CEL rejected;
expression-bearing profiles load in the (default-on) build.

**API:** success returns only configured claims; no raw subject echo except via released
claims; no unkeyed public subject hash; unknown requested claim denied; missing scope /
missing purpose deny **before** source read; 0 rows → safe denial; 2 rows → safe
ambiguous denial; deceased/condition-denied row denies before projection; missing
required claim denies; optional missing claim omitted; row-read scope alone does **not**
authorize release; release scope alone does **not** authorize row reads; content
negotiation = `application/json`, unsupported media rejected; collapsed variants render
identically.

**Metadata/OpenAPI:** profiles appear for authorized callers; source internals not
leaked; OpenAPI includes route+schemas only when configured; private headers set.

**Audit:** success emits profile id/version, purpose, keyed subject hash, requested +
released claim names; no raw subject; no claim values; denied outcomes audited without
leaking rows; route classified `attribute_release` not `Other`; keyed-hash field-domain
separation across profiles; denied/claim-unavailable internal outcomes auditable through
the public collapse.

---

## 9. Residual risks (track during build)

- CEL source-binding grammar unverifiable until read at `CROSSWALK_REF` — first CEL task.
- `deny.toml` RUSTSEC-2023-0089 now in the hardened default — needs reviewed sign-off.
- Post-auth timing oracle (0-rows vs exists) inherent to resolve; mitigate by running
  expensive gates before the read; document residual in PR notes.
- Brute-force on enumerable national IDs — preserve velocity-monitoring audit signals;
  rate-limiting stays operator-asserted deployment evidence; document residual.
- `is_valid_scope_level` allowlist must include `identity_release` or grants fail.

---

## 10. Acceptance criteria (Relay PR)

- Configured attribute release profiles supported; dedicated endpoint resolves one
  subject and returns only configured claims.
- Release scope distinct from generic row reads; purpose + governed policy checks apply
  before source projection.
- Public errors create no obvious subject-existence oracle; metadata/OpenAPI expose the
  feature without leaking source internals.
- Audit captures release decisions without raw identifiers or claim values, and classifies
  the route as attribute release (not `Other`).
- Tests cover success, denial, ambiguity, release conditions, projection, metadata,
  content negotiation, CEL expressions, and audit.
- `just ci-preflight` run; `Cargo.lock` regenerated against pinned refs; `deny.toml`
  re-justified.
- PR notes explain how an eSignet Authenticator plugin consumes the endpoint.

---

## 11. Hard constraints (do not violate)

- Work in `registry-relay` only. Do **not** edit `registry-lab`, `registry-notary`,
  `registry-internal`, the `crosswalk` sibling repo, or `esignet-relay-authenticator`.
- Do **not** log raw subject identifiers, released claim values, bearer tokens, API keys,
  full request bodies, or private source rows.
- Audit uses a **keyed** subject hash (Relay's audit hasher), not raw and not an unkeyed
  public hash. The public response carries no subject hash.
- Keep the change focused; do not opportunistically refactor unrelated routes/config.
- Follow existing Relay conventions for config shape, error taxonomy, media types, tests,
  and audit.
