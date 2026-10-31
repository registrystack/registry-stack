# Adapter current-checkpoint final audit

Date: 2026-10-31

Status: **current Adapter checkpoint PASS; full delivery program HOLD**.

This is the required honest current-checkpoint review, not a declaration that
the full `CONCEPT.md` definition of done is complete. Increment 0 and Increment
1 are accepted. The port-table milestone remains at Increment 1: 35 of 37 rows
(94.6 percent) are delivered with evidence. GraphQL and Idempotent Consumer
remain pending, and the Increment 2 and Increment 3 checklists are not
accepted.

## Evidence basis and review limits

This review inspected the Adapter contract, delivery plan, current source and
tests, the Increment 1 integration and staff reviews, the named final gate
logs, and the public safe live-verification summary. It did not run a build or
test, access credentials, or read the lead's private harness, environment,
logs, or recovery material.

The source and owning-gate conclusions below are independently read back. The
DHIS2 and HAPI execution results are supplied by the lead against one immutable
feature-enabled Adapter executable and its matching CLI/runtime library. The
review used only the allowed aggregate counts and artifact-hash status from the
safe summary. The lead separately reports zero sensitive-output hits and
confirmed cleanup of both owned records.

An independent PUT and security review reported PASS. Its reviewed invariants
were native PUT admission and closed input, exact response-identity custody,
fail-closed handling of an actual upstream 202, and the named anonymous-HTTPS
acknowledgement without weakening TLS, facade authentication, or header
filtering.

## Current checkpoint verdicts

| Boundary | Verdict | Evidence |
|---|---|---|
| Adapter source and architecture | PASS | No new product coupling or source-specific Rust model found; source interpretation remains in reviewed pack scripts and artifacts |
| Complete Adapter contract gate | PASS | 960 passed, 0 failed, 0 ignored |
| Complete Adapter PostgreSQL gate | PASS | 645 passed, 0 failed, 0 ignored; owned PostgreSQL container removed |
| Workspace check | PASS | Locked workspace, all targets |
| Workspace Clippy | PASS | Locked workspace, all targets, warnings denied |
| CLI catalog | PASS | 24 unit and 3 snapshot tests |
| Port-table milestone | PASS for Increment 1 | 37 rows, 35 delivered with evidence, 2 pending |
| Strict workspace configuration conformance | PASS with two recorded expected failures | 5,657 cells: 4,227 pass, 2 expected failures, 0 fail, 0 stale, 0 blocked, 1,428 not applicable; no Adapter failure |
| Dependency advisory gate | PASS | `cargo deny check` clean on the current base |
| Latest MCP/gateway read pairing | PASS | 6 native Adapter/PostgreSQL cases passed, zero failed or ignored; four artifact hashes stable and committed fixture archive reproduced |
| Full program definition of done | HOLD | Later port rows, increments, real OpenCRVS, and workspace debt remain open |

The two expected failures are the `evidence/bundle` and `coordinator/runtime`
cells of the `unique-list-sweep` case this branch adds. Their owning readers
refuse the duplicate but wrap the expected `config.duplicate-item` diagnostic
in a domain diagnostic. No Adapter cell failed. Both cells are digest-pinned in
`products/platform/conformance/yaml/expected-failures.yaml` until those readers
conform; they are not a fix to either product.

The recorded expected failures are sufficient for the accepted Increment 1
checkpoint under its inherited acceptance rule. They are not a full-program
PASS: `CONCEPT.md` section 14 item 4 requires every gate to be green.

## Current served behavior

The accepted read engine serves the profile-defined read surface with OIDC,
client admission, operation and record-type scopes, closed request and response
schemas, bounded source access, profile-owned problems, opaque continuations,
and a value-free PostgreSQL journal.

The native facade now also serves synchronous POST create and PUT update. The
current focused evidence includes six native PUT tests, four DHIS2 pack-write
tests, eight served response-custody tests, and nine CLI TLS tests. The PUT
boundary authenticates and authorizes before body or source access, checks the
effective-contract pin, binds path identity to the closed input, replays exact
response bytes and the original response ID, refuses a changed body without a
new send, and does not repeat an uncertain effect. An actual upstream 202 is
retained as an exact failed response rather than being presented as completed
or resent.

Credential-free public HTTPS is admitted only by the matching `none` pair and
the named `anonymousHttps: operator-approved` acknowledgement on a fixed HTTPS
binding. TLS certificate verification and facade authentication still apply.
No source credential, caller token, or forbidden header is sent. Omission,
wrong authentication pairing, plain HTTP, or an untrusted certificate remains
closed, and a failed credential never falls back to anonymous access.

## Lead-reported immutable-artifact journeys

- DHIS2 read: 264 of 264 checks passed.
- DHIS2 synchronous create and attribute update: 25 of 25 checks passed,
  including exact body replay with the original response ID in header and
  body, changed-body mismatch without another send, readback, and
  ownership-verified cleanup.
- `verify --live`: one request executed, zero waits, zero diagnostics.
- HAPI: 18 recorded checks passed for one synthetic Patient, covering setup
  and authentication, conditional create 201, read and search 200, exact
  replay, mismatch 422, one source POST, owned delete 200, and readback 410.
- Sensitive-output scan: zero hits.

These journeys establish the named paths only. They do not establish personal
delegation, row-level or field-level disclosure authority, MCP writes, typed
non-record commands, a maintained FHIR pack, or the full delivery program.
No personal or sensitive values are reproduced in this report.

## Fixture and source evidence

Maintained fixtures outside the refusal corpus total 7 captured and 23
documented: DHIS2 tracker has 7 captured and 4 documented, GovStack has 4
documented, OpenCRVS has 10 documented, and the experiments have 5 documented.
The HAPI live journey does not change the provenance of the documented FHIR
experiment fixtures.

The OpenCRVS pack remains offline evidence. Its 10 maintained fixtures are
documented, `testedVersions` is empty, and no real OpenCRVS system was reached.
The required client is unavailable. No OpenCRVS read or write is accepted as
live proof.

The latest immutable Adapter v3 artifact passed all six matching MCP/gateway
native PostgreSQL cases, with zero failures or ignored cases. The lead verified
the raw log hash and all four artifact hashes, and reproduced the fixture
archive from committed source. The gateway's later two-file inventory and
regression-test follow-up changes no runtime. The first attempt failed at
fixture digest-pin preparation before any runtime journey; the repaired
harness prepares temporary projects with exact supplied profile and pack pins.
This establishes bounded reads with synthetic issuers and sources and real
product runtimes and PostgreSQL. Native Adapter writes remain excluded from
the external gateway contract.

## Open items before full program acceptance

1. Deliver and accept the Idempotent Consumer port-table row, including the
   currently refused nondefault `eager: false` and `completionEager: true`
   behavior, or record a reviewed contract divergence.
2. Implement and verify D16's two accepted-but-incomplete write modes: a 202
   status link and a bounded wait, including expiry and timeout outcomes.
3. Complete the remaining Increment 2 write properties and conformance record.
   Synchronous create and update are useful slices, not acceptance of the
   increment.
4. Deliver and accept write resume for multi-step writes. Until then a write
   route with more than one non-safe send remains refused.
5. Deliver and accept the GraphQL port-table row under the increment that has
   a real source need, or revise the plan under the two-system rule.
6. Obtain a real OpenCRVS client and prove the maintained pack against a
   running source. Its current fixtures remain documented and offline only.
7. Complete the remaining Increment 3 obligations, including real OpenCRVS
   reads and writes, the applicable source protocol decision, and the planned
   facade-contract work.
8. Make the `evidence/bundle` and `coordinator/runtime` readers report
   duplicate set items as `config.duplicate-item`, and remove their two
   entries from the expected-failures register.
9. Publish the Adapter problem inventory in the identifier catalog. Its type
   base is reserved by one `planned-resolution` exclusion until the inventory
   has titles, descriptions, and a settled URI form.
10. Keep personal delegation, record-level and field-level authorization,
    MCP writes, and typed non-record commands behind their separate contracts
    and acceptance gates.
11. Execute the prepared one-PR Adapter publication under Jeremi's authority.
    The latest matching read proof is complete; Adapter integration precedes
    MCP integration. No push, merge, tag, release, or production deployment is
    claimed here.

Until these items close, this file is a current-checkpoint audit under the
planned `final.md` path, not the final full-program PASS required by
`CONCEPT.md` section 14.
