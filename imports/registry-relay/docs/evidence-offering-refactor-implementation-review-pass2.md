# Evidence Offering Refactor: Implementation Review (Pass 2)

Status: review notes (2026-05-21)

Second-pass review of the work on `main` after the pass-1 findings in
[`evidence-offering-refactor-implementation-review.md`](evidence-offering-refactor-implementation-review.md)
were addressed. Same spec ([`evidence-offering-refactor-spec.md`](evidence-offering-refactor-spec.md)),
same six parallel reviewers (MODEL / READ / VERIFY / PRIV / REMOVE / DEMO),
same stream-prefixed ID convention. New findings in this pass continue the
numbering from pass 1 (e.g. `READ-8`, `VERIFY-5`).

## Executive Summary

Most of pass 1 was addressed. Of the 37 pass-1 findings (13 blockers, 19
should-fix, 2 nice-to-have):

- **24 FIXED** (including 12 of 13 blockers).
- **8 PARTIAL**: the headline change landed but a residual surface remains.
- **5 OPEN**.

The remaining gaps cluster into three areas:

1. **Privacy posture is still not finished.** Receipts can be issued for up to
   the full `claim_validity.verify_result` window (up to 365 days, per config
   schema), instead of the spec's "≤ 5 minutes" hard cap. Audit records embed
   `claim_hash` and `evidence_hash` that then flow to whatever audit sink the
   operator configures, with no boundary redaction. Subject and audience now
   differ in production, but every JWT receipt test fixture still has
   `sub == aud`, so the production behavior is untested.

2. **Rate limiting is half-built.** The fixed-window burst limiter caps the
   per-second spike but does nothing for sustained pressure; the spec calls
   out sustained rate limiting as a requirement, not a future enhancement.
   Tests do not exercise burst recovery, ordering, or the HashMap growth path
   (one entry per remote IP, never evicted).

3. **Legacy-scope cleanup is incomplete.** `verify_scope` is gone from
   production demo configs but still present in roughly 20 test fixtures, the
   `perf/` README, an orphaned `docs/claim-verification-spec.md`, and
   `claim_verification_scope` still appears in two demo YAMLs. The internal
   engine continues to read these names; the spec said both names must
   disappear from operator-visible surfaces by DoD.

Pass-2 new findings: **4 blockers, 15 should-fix, 1 nice-to-have** (after
de-duplication). Combined open posture (still-open pass-1 + new pass-2):
**5 blockers, ~23 should-fix, 1-2 nice-to-have**.

The work is close. With one focused privacy/receipt fix, the rate-limit
upgrade, and a sweep through the residual `verify_scope` / `claim-verification`
strings, the Definition of Done holds.

## Verification Commands

The spec's five named `cargo` checks were re-run for pass 2:

| Command | Result | Notes |
| --- | --- | --- |
| `cargo fmt --check` | PASS | Same nightly-only `imports_granularity` warnings as pass 1. |
| `cargo test -p registry-metadata-core` | PASS | 16 tests in `registry-metadata-core` pass (was 14 in pass 1; +2 covers new validation paths). |
| `cargo test --test demo_configs_load` | PASS | 1 test passing. |
| `cargo test --test catalog_entity` | PASS | 39 tests pass. |
| `cargo test --test config_metadata_bindings` | PASS | 6 tests pass. |

Full `cargo test` was again not run; it remains a DoD prerequisite. External
SEMIC/SHACL validator: still not in PATH, still skipped per the spec.

## Pass-1 Status Table

`F` = FIXED, `P` = PARTIAL (headline addressed, residue remains), `O` = OPEN.

### MODEL stream

| ID | Severity | Pass-1 finding | Pass-2 status | Evidence |
| --- | --- | --- | --- | --- |
| MODEL-1 | blocker | Duplicate offering IDs only rejected per-dataset | F | Global uniqueness check at `crates/registry-metadata-core/src/lib.rs:908-909,969`. |
| MODEL-2 | should-fix | `verification_request_schema_url` not validated | P | Field is now declared at `lib.rs:550` and surfaced at `:2168-2170`; no validation rule yet. |
| MODEL-3 | should-fix | Country code field accepts arbitrary strings | F | ISO 3166-1 alpha-2 check at `lib.rs:1685-1695`. |
| MODEL-4 | nice-to-have | No unit tests on offering manifest parsing | F | New tests in `crates/registry-metadata-core/src/lib.rs` (test count went 14 → 16). |

### READ stream

| ID | Severity | Pass-1 finding | Pass-2 status | Evidence |
| --- | --- | --- | --- | --- |
| READ-1 | blocker | Detail handler returned 500 on missing offering | F | Returns 404 RFC 9457 problem now. |
| READ-2 | blocker | Content negotiation missed `q=` ordering | F | q-value parser; `tests/entity_routes.rs` covers the precedence cases. |
| READ-3 | should-fix | `Vary` missing on detail | F | Header emitted in detail handler. |
| READ-4 | should-fix | BRegDCAT-AP emitter dropped `dct:conformsTo` for offerings | O | Still missing in emitter; no test in `tests/entity_routes.rs` references it. |
| READ-5 | should-fix | Visibility filter applied only on list | P | Detail handler now filters; metadata bindings endpoint still leaks suppressed offerings (gap behind `READ-11`). |
| READ-6 | should-fix | `Cache-Control: private` missing on offering responses | F | Header present on both list and detail. |
| READ-7 | nice-to-have | No golden JSON-LD fixtures for offering listings | O | No fixtures in `tests/fixtures/`. |

### VERIFY stream

| ID | Severity | Pass-1 finding | Pass-2 status | Evidence |
| --- | --- | --- | --- | --- |
| VERIFY-1 | blocker | No rate limiting on POST | P (now F-burst, O-sustained) | Fixed-window burst limiter at `src/api/evidence_offerings.rs:38-92,151-154`; sustained limit still missing (see VERIFY-5). |
| VERIFY-2 | blocker | Receipt `aud == sub` | F | Subject = issuer DID, audience = `client:{principal_id}` at `:576-577`. |
| VERIFY-3 | should-fix | Body limit not enforced | P | Limit honored via tower limit layer, but no test exercises the 413 path. |
| VERIFY-4 | should-fix | Ambiguity gate (multiple matching offerings) | O | Behavior under multi-match still falls through to first match. |

### PRIV stream

| ID | Severity | Pass-1 finding | Pass-2 status | Evidence |
| --- | --- | --- | --- | --- |
| PRIV-1 | blocker | `aud == sub` in receipts | F | Same fix as VERIFY-2. |
| PRIV-2 | blocker | No rate limiting | F (burst) | Same as VERIFY-1; sustained gap moved to VERIFY-5/PRIV-12. |
| PRIV-3 | blocker | No per-request salt in HMAC | F | Salt added at `src/api/evidence_offerings.rs:276-279,297,320,350,606`. |
| PRIV-4 | should-fix | Per-offering subkey derivation | F | `hmac_hex_for_offering` at `src/claim_verification.rs:56-67`. |
| PRIV-5 | should-fix | `Data-Purpose` IRI not validated | F | Allowlist check at `src/api/evidence_offerings.rs:176-193`. |
| PRIV-6 | should-fix | Audit context lost `offering_id` | F | `offering_id: Option<String>` at `src/audit/mod.rs:83`. |
| PRIV-7 | should-fix | `dspace:participantId` redundant in audit | F | Removed. |
| PRIV-8 | should-fix | Receipt media type not asserted in tests | O | Still no assertion. |

### REMOVE stream

| ID | Severity | Pass-1 finding | Pass-2 status | Evidence |
| --- | --- | --- | --- | --- |
| REMOVE-1 | blocker | `verify_scope` in production configs | F | Gone from `config/example.yaml`, `config/example.oidc.yaml`, `config/spdci_disability_registry.example.yaml`. |
| REMOVE-2 | blocker | Both legacy scope names removed from demos | P | `verify_scope` removed; `claim_verification_scope` still at `demo/config/all_standards.yaml:2306`, `demo/config/disability_registry.yaml:311` (broken out as REMOVE-13). |
| REMOVE-3 | should-fix | `docs/claim-verification.md` renamed | F | Renamed to `docs/evidence-verification.md`; cross-refs updated. |
| REMOVE-4 | should-fix | `docs/development.md` doc-currency list | F | `docs/development.md:189` lists `evidence-verification.md`. |
| REMOVE-5 | should-fix | Agent skills still mentioned legacy routes | F | `agent-skills/` clean. |
| REMOVE-6 | should-fix | Test scope names hardcoded as legacy | O | `tests/entity_routes.rs:141-143` `ENTITY_ROUTE_SCOPES` still uses `"social_registry:verify"` and `"social_registry:claim_verification"`; many fixtures follow (see REMOVE-9). |
| REMOVE-7 | should-fix | Error variants renamed | F | `evidence_verification.ruleset_not_allowed` at `src/api/evidence_offerings.rs:718`. |
| REMOVE-8 | should-fix | SP DCI scope migration | P | Reads `evidence_verification_scope` first at `src/api/spdci.rs:143-147` but falls back to `verify_scope`; fallback undocumented. |

### DEMO stream

| ID | Severity | Pass-1 finding | Pass-2 status | Evidence |
| --- | --- | --- | --- | --- |
| DEMO-1 | blocker | Farmer scenario missing from demo script | F | Present at `demo/scripts/evidence_offerings_demo.py:105-125`. |
| DEMO-2 | blocker | Farmer ruleset used wrong lookup key | F | Uses `national_id` correctly at `demo/config/all_standards.yaml:2750-2758`, `demo/config/disability_registry.yaml:755-763`. |
| DEMO-3 | should-fix | Demo IDs not prefixed | F | `FAKE-830001` etc. used as semi-prefix. |
| DEMO-4 | should-fix | Disability scenario missing config evidence | P | Scenario at `demo/scripts/evidence_offerings_demo.py:86-104`; one fixture remains incomplete (see DEMO-10). |
| DEMO-5 | should-fix | Bruno collection lacks SP DCI examples | O | No new requests under `bruno/spdci/`. |
| DEMO-6 | nice-to-have | False-positive subject not labelled in demo | P | Subject is referenced; demo step 4 does not assert false-positive absence (see DEMO-9). |

## Pass-2 New Findings

### Blockers

#### VERIFY-5 / PRIV-12: No sustained rate limit (only burst is enforced)

**Spec**: §Privacy, §Operational, "POST endpoint must rate-limit per principal
and per remote address, both burst and sustained".

**Code**: `src/api/evidence_offerings.rs:38-92` implements a fixed-window
counter that resets each tick. A client that paces exactly with the window
boundary can sustain N×60 requests per minute against an N-per-second limit.

**Why it matters**: Receipts and HMAC operations are CPU-bound; the offering
endpoint is the only entry point to issue receipts. Without a sustained limit,
a single principal can degrade service to all others. The pass-1 review caught
the burst gap; the burst-only fix is not the spec's requirement.

**Recommended fix**: Add a sliding window (e.g. token bucket with refill rate
+ burst capacity) or stack a second limiter at a longer interval. Add tests
that pace at window-boundary granularity to confirm the sustained rate.

#### PRIV-9: Audit records flow `claim_hash` and `evidence_hash` to uncontrolled audit sinks

**Spec**: §Privacy, "audit logging records hash-only references; never raw
claim or evidence bodies".

**Code**: `src/audit/mod.rs:204-206, 587-589` stores `claim_hash` and
`evidence_hash` directly on `AuditRecord`. Audit sinks (file, syslog, optional
remote forwarder) receive the record verbatim. There is no boundary scrubbing
distinguishing fields that are safe to forward externally vs. fields that must
stay process-local.

**Why it matters**: A hash is not raw data, but it is a stable identifier that
binds a specific claim/evidence pair across systems. Once a hash leaves the
process boundary into a remote audit aggregator, it can be correlated with
other systems' logs (or with a known plaintext if the input space is small,
e.g. a national ID). The spec's privacy posture relies on hashes staying
internal.

**Recommended fix**: Either (a) classify the hash fields as "internal-only" in
the audit record and strip them in the boundary serializer for remote sinks,
or (b) replace them with HMAC'd versions keyed on a per-deployment secret so
external correlation requires the key.

#### PRIV-10: Receipt expiry tied to `claim_validity.verify_result`, not the spec's 5-minute cap

**Spec**: §Receipts, "verification receipts MUST expire within 5 minutes of
issuance".

**Code**: `src/provenance/mod.rs:326-336` reads `cfg.claim_validity.verify_result`
for the `exp` claim. That config value is a `Duration` with no upper bound in
the schema; production configs (e.g. `config/example.yaml`) set it to days or
weeks. A deployment can issue receipts with `exp - iat = 365 days` while still
being "spec-compliant" per the YAML.

**Why it matters**: The receipt is presented to relying parties as proof of a
recent verification. A 365-day window means a stale receipt can be replayed
long after the underlying claim has changed.

**Recommended fix**: Clamp the receipt expiry to `min(cfg.claim_validity.verify_result,
Duration::from_secs(300))` in the issuer, and add a config-validation rule
warning if the configured value exceeds 5 minutes.

#### DEMO-7: README "Narrated demo" section missing farmer and disability scenarios

**Spec**: §Demo, "the narrated demo in `demo/README.md` must cover all three
scenarios (false-positive subject, farmer status, disability status)".

**Code**: `demo/README.md:297-341` contains the narrated walkthrough for the
false-positive scenario only. The farmer and disability scenarios exist in
`demo/scripts/evidence_offerings_demo.py:86-125` but have no corresponding
walkthrough block in the README. A developer following the README will not
exercise them.

**Recommended fix**: Add two sibling sections (`### Farmer status`,
`### Disability status`) under "Narrated demo" with the exact `curl` /
`evidence_offerings_demo.py --scenario farmer` commands and expected output
excerpts.

### Should-fix

#### MODEL-5: `registry_relay:servesEntity` IRI has a double fragment

**Code**: `crates/registry-metadata-core/src/lib.rs:2803`. The emitted IRI is
of the form `<vocab>#servesEntity#<entity_id>`. The second `#` makes the
fragment ambiguous under RFC 3986; downstream RDF parsers may either reject
the IRI or coerce the second `#` to `%23` and produce a stable but unintended
identifier.

**Recommended fix**: Use a single fragment delimiter and an in-fragment
separator (e.g. `<vocab>#servesEntity-<entity_id>` or move the entity id into
a query-style suffix on a path IRI).

#### MODEL-6: `evidence_verification.ruleset_not_allowed` error not raised in cross-boundary path

**Code**: `src/config/validate.rs:273,286` declares the variant but the scope
allowlist check at `:1318-1327` returns the generic config error. The
offering-endpoint path at `src/api/evidence_offerings.rs:718` does raise the
specific variant. The validation path and the runtime path are out of sync.

**Recommended fix**: Route the validation path through the same variant so a
config that lists a disallowed ruleset surfaces the same problem URI as a
runtime rejection.

#### READ-8: No test asserts `Vary: Accept` on the offering detail handler

**Code**: `tests/entity_routes.rs:1177-1180`. The list handler test asserts
`Vary`; the detail handler test does not. Pass-1 READ-3 was closed on the
basis that the header is emitted, but the regression net is incomplete.

**Recommended fix**: Add an `assert_eq!` on the `Vary` header value to the
existing detail handler test.

#### READ-9: No golden BRegDCAT-AP JSON-LD fixtures contain offerings

**Code**: The fixtures under `tests/fixtures/` predate the offering nodes. No
file in the offering-emitter test suite asserts against a frozen byte-for-byte
JSON-LD reference. A future emitter change can silently regress the SEMIC
shape; the SHACL validator is not in CI.

**Recommended fix**: Add at least one fixture file pinning the catalog +
offering output for a single dataset.

#### READ-11: Visibility consistency across endpoints is not tested

**Code**: The visibility filter is applied independently in
`src/api/evidence_offerings.rs` (list, detail) and in the metadata-bindings
emitter. A suppressed offering must be invisible everywhere, but no test
asserts the invariant across all three surfaces in one run.

**Recommended fix**: Add a single test that creates a hidden offering and
asserts it is absent from each of: list, detail (404), catalog metadata, and
metadata-bindings dump.

#### VERIFY-6: Rate limit returns 429 with `Retry-After` but its `WWW-Authenticate` ordering enumerates valid principals

**Code**: `src/api/evidence_offerings.rs:151-154`. When the limit is hit
before authentication completes for an unknown principal, the response
ordering can reveal whether a principal exists in the registry by timing /
header presence. Low-blast-radius but a hardening miss.

**Recommended fix**: Always run authentication before the rate-limit check, or
ensure the rate-limit response is identical for known and unknown principals.

#### VERIFY-7: `ingest_version` is allowed to be null on offering manifests

**Code**: `crates/registry-metadata-core/src/lib.rs` allows
`ingest_version: None`. Downstream emitters then emit `null` or omit the
field. The spec calls for ingest provenance on every offering for replay
debugging.

**Recommended fix**: Make `ingest_version` required at the manifest level,
defaulting to the empty string only when explicitly missing (and warning in
validation).

#### VERIFY-8 / PRIV-11: Every JWT receipt test fixture has `sub == aud`

**Code**: `tests/claim_verification_jwt_receipt.rs:78-79, 122-123, 197-198`.
Pass-1 VERIFY-2/PRIV-1 closed on the basis that production code now sets
subject = issuer DID and audience = `client:{principal_id}`. The fixtures
were not updated to match; every assertion in this test file checks
`payload["sub"] == payload["aud"]`, which is now production-incorrect.

**Recommended fix**: Rewrite the fixtures to compare `sub` and `aud` against
distinct expected values. Add one new test that explicitly fails if a fix
regresses `aud` back to the issuer.

#### VERIFY-9: Rate-limit `HashMap<IpAddr, _>` grows without eviction

**Code**: `src/api/evidence_offerings.rs:38-92`. The per-IP counter map has no
TTL or LRU eviction. A scanner hitting one request per source IP can fill
memory.

**Recommended fix**: Switch to a bounded structure (e.g. `lru::LruCache` with
a sane cap) or evict entries whose window has expired on each insertion.

#### DEMO-8: Bruno collection has no SP DCI offering-verification requests

**Code**: `bruno/spdci/` has the legacy `claim-verifications` requests but no
`POST /evidence-offerings/{id}/verifications` request. The narrated demo
points to the script; the Bruno collection is the recommended manual
verification path and currently can't drive the new endpoint.

**Recommended fix**: Add `verify-farmer-status.bru`,
`verify-disability-status.bru`, and `verify-false-positive.bru` requests under
`bruno/spdci/`.

#### DEMO-9: Step 4 of the demo script does not assert false-positive absence

**Code**: `demo/scripts/evidence_offerings_demo.py` runs the false-positive
scenario through to a successful response but does not assert that the
receipt's claim was `evidence_present=false`. The whole point of the scenario
is to demonstrate the system declining the inferred match.

**Recommended fix**: After step 4, parse the receipt body and assert
`claim.evidence_present == false`, exit non-zero otherwise.

#### DEMO-10: Farmer ruleset `row_path` not consistent across the two demo configs

**Code**: `demo/config/all_standards.yaml:2750-2758` and
`demo/config/disability_registry.yaml:755-763` both reference farmer status
but use slightly different `row_path` selectors. A subject that matches in one
config will not match in the other.

**Recommended fix**: Align the two configs on a single canonical selector and
add a `demo_configs_load` assertion that both produce identical farmer rule
behavior on the shared fixture subject.

#### REMOVE-9: `verify_scope` still in ~20 test fixtures and 2 internal source files

**Code**: see the REMOVE pass-2 reviewer summary above for the full file list.
Highlights: `tests/entity_routes.rs:141-143,358,386,1051,1717,1736`,
`tests/third_party_verification.rs:213`, `src/metadata/core_adapter.rs:489`,
`src/query/aggregates.rs:627`, `benches/query_bench.rs:78`,
`benches/registry_bench.rs:78`.

The fixtures parse because the field is `Option<String>` with
`#[serde(default)]`, but the spec treats `verify_scope` as removed from the
documented contract. Test YAML is reference material for operators.

**Recommended fix**: Sweep the legacy field from every fixture. For the
explicit "scope is denied" test at `entity_routes.rs:1072`, substitute the new
scope name. Depends on the disposition question for `EntityAccessConfig.verify_scope`
(see Open Questions).

#### REMOVE-10: `perf/README.md` documents the wrong endpoint URL

**Code**: `perf/README.md:138` says
`POST /datasets/{dataset_id}/{entity}/evidence-verifications`. Correct path:
`POST /evidence-offerings/{offering_id}/verifications`. Section header at
`:135` still reads "Claim Verification Scenario"; k6 threshold key at `:150`
and bench filename at `:186` follow the same legacy name.

**Recommended fix**: Update section header, URL, and threshold key. Bench
filename is internal but ideally renamed for grep-ability.

#### REMOVE-11: `demo/scripts/generate_demo_keys.py` user-visible output still says "claim-verification"

**Code**: `demo/scripts/generate_demo_keys.py:11,158`. Operator runs this and
sees "claim-verification HMAC binding key" in stdout. The key is the
evidence-verification HMAC key.

**Recommended fix**: Rename the user-visible label in both the docstring
(`:11`) and the printed message (`:158`).

#### REMOVE-12: Orphan `docs/claim-verification-spec.md` still in docs tree

**Code**: `docs/claim-verification-spec.md` documents the removed routes
(`/verify`, `/claim-verifications`, `/claim-verification-rulesets`) as live
public APIs. Nothing links to it, but it sits alongside `docs/api.md` and
`docs/evidence-verification.md` and shows up in any in-tree doc search.

**Recommended fix**: Delete it. If any content is worth preserving, move to
`docs/archive/` (or equivalent) with an "archived" banner.

#### REMOVE-13: `claim_verification_scope` still present in `demo/config/all_standards.yaml:2306` and `demo/config/disability_registry.yaml:311`

This is the residue of REMOVE-2 broken out for clarity: `verify_scope` is gone
from these files, `claim_verification_scope` is not. Spec required both
legacy scope names out of demo configs.

**Recommended fix**: Remove the `claim_verification_scope:` line from both
files. Coordinates with REMOVE-8 disposition (if SP DCI fallback is removed
entirely, the engine no longer reads the field and the struct member can be
dropped).

### Nice-to-have

#### MODEL-2 follow-through: `verification_request_schema_url` should be validated as a fetchable URL at deploy time

The field is declared and surfaced but never validated. A deployment can ship
a typo and discover it only when a relying party tries to validate a request
body. Pass-1 should-fix is now PARTIAL; a deploy-time HEAD request to the URL
would close it.

## Open Questions

1. **`EntityAccessConfig.verify_scope` field disposition.** Field is now
   `Option<String>` and silently accepted. REMOVE-9 says it appears in ~20
   test files and 2 internal source files. Two options: (a) `#[deprecated]`
   attribute that fails compilation in call sites; (b) delete from struct
   entirely now that SP DCI reads `evidence_verification_scope` first. Choice
   determines REMOVE-9's fix size.

2. **`claim_verification_scope` field retention.** Internal claim-verification
   engine still reads this via `claim_verification_required_scope()` for
   hidden-ruleset scope gating (e.g. `social_registry:claim_verification:hidden`
   at `entity_routes.rs:414`). If hidden-ruleset gating migrates to a different
   mechanism, the field can go; otherwise it stays as an internal-only config
   knob that just isn't in demo files.

3. **Receipt expiry source of truth.** PRIV-10 proposes clamping to 5 minutes
   at the issuer. Confirm this is the right boundary vs. a config-validation
   error vs. removing `claim_validity.verify_result` from the schema entirely
   and hard-coding the limit.

4. **Audit hash redaction strategy.** PRIV-9 offers two paths (boundary strip
   vs. per-deployment HMAC). Pick one before sweep.

5. **`perf/k6` scenario script alignment.** REMOVE-10 fixes the README URL.
   Confirm the k6 scenario script itself targets the new path, or update both
   together.
