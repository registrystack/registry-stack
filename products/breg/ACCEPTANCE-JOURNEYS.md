# Acceptance journeys

Base Registry Engine proves that the same binary and compiler profile serve five
configuration projects. Their contract identifiers and delivery state are in
`contracts/acceptance-scenario-matrix.yaml`. Ten further projects under
`acceptance/` each prove one governed surface, and are listed at the end of this
page.

| Project | Example | Coverage |
| --- | --- | --- |
| `business-establishments` | Businesses, establishments, and operating assignments | Dated relationships, exact selectors, related reads, derived counts, claim-bound access, and the local webhook demo |
| `business` | Legal entities, filings, and officer appointments | Registration identifiers, public and protected projections, create-only filings, and effective time |
| `facility` | Environmental facilities, permits, installations, and discharge reports | Coordinates, quantities and units, administrative row boundaries, and resumable imports |
| `inspection` | Public authorities, facility inspections, observations, and permit records | Protected structured metadata, bounded finding grades, create-only records, and corrections retaining the original effective period |
| `asset-site-placement` | Equipment assigned to sites | Non-overlapping placements and an additive signed upgrade with unchanged server bytes |

All five pass the Production compiler and the same real-PostgreSQL pilot test,
`postgres_pilot_acceptance.rs`, which the postgres lane of `scripts/test-postgres.sh`
runs. The test loads their module source, rederives the package, and executes
configured behavior without domain-specific runtime concepts. The facility project
also carries its own real-PostgreSQL data journey, `postgres_data_facility.rs`, in
the same lane.

The business-establishments demo creates North Quay Engineering, Central
Fabrication, and South Harbour Logistics, with eight establishments in total.
Central has a suspended depot; South Harbour supplies separate control records
for row and relationship isolation. The live summary counts establishments by
role, kind, and operating status using only currently effective assignments.
An operator can query the whole registry. A separate viewer is bound by verified
claims to one business and cannot list businesses or traverse their establishments.

Permit records reference their issuing public authority. A correction appends a new
record for the original effective period and retains the prior record unchanged. The
application chooses the applicable correction; the example does not mark old records
inactive automatically.

The local concept URIs are synthetic mappings, not an external-standard conformance
claim. These fixtures record registration and permit facts; they do not implement
incorporation, inspection case management, or permit approval workflows.

The asset project also passes the public-binary adopter workflow.
That workflow builds the two executables once, tests a candidate in an isolated
database, packages it for external signing, proves that an author without the
migration secret cannot initialize production state, applies it with the
operator role, and performs authenticated data access through a static JWKS.
It then adds one optional restricted field by configuration, tests and signs
the successor in a second isolated database, records a deliberately blocked
migration as durable failed maintenance, applies the exact fix-forward package,
and restarts the byte-identical server binary. The original data survives and
the restricted field remains outside the selected response projection.

A pinned migration can also be recovered with `migration reconcile`, which
assesses it and either completes or abandons the pinned target without
building a new package. That path is proven by its own CLI-authority test,
not by this journey.

The machine-readable matrix binds each journey to its exact executable proof.
Compiler-only evidence is not used to claim the unchanged-binary upgrade or
the author-versus-production authority boundary.

## Single-surface acceptance projects

The five projects above are the ones bound to a `fixture` in
`contracts/acceptance-scenario-matrix.yaml`. The remaining projects under
`acceptance/` are narrower: each authors the smallest configuration that proves
one governed surface, and each is executed by the test or script named beside it.

| Project | Journey it proves | Run by |
| --- | --- | --- |
| `asset-site-placement-change-requests` | Reviewed change requests over the asset registry, with workspace metadata and the record profile contract | `postgres_record_profile_conformance.rs` and `postgres_workspace_metadata.rs` in the postgres lane, and the committed-tree baseline in `scripts/check-generated.sh` |
| `publicschema-household` | A household project derived from the pinned offline reference model | `demo/support/test_demo.py` under `scripts/check-contracts.sh` holds it as the explicit household fixture; the local `demo/run.sh` executes it end to end |
| `publicschema-household-change-requests` | Reviewed change requests over that derived household project | the committed-tree baseline in `scripts/check-generated.sh`, and the local `scripts/test-change-request-examples.sh` end to end |
| `person-name-change-rhai` | Bounded Rhai planning inside a reviewed change request | `compiler_rhai_planner.rs` in the workspace test run and `postgres_rhai_planner.rs` in the postgres lane |
| `person-registration-rhai` | Governed action handlers under `registry.action-handler/v1`, including their declared refusals | `postgres_action_handlers.rs` and `fixture_tooling.rs`, both in the postgres lane |
| `farmer-landholding-evidence` | A governed action resolving a declared Evidence capability under the trial `registry.action-handler/v2` ABI | `action_evidence_compiler.rs` and `action_evidence_handler.rs` in the workspace test run, then `postgres_action_evidence.rs`, `postgres_action_evidence_targets.rs`, and `postgres_action_evidence_retention.rs` against a real `evidence` binary in the postgres lane |
| `spatial-service-sites` | Bounding-box read permissions over spatial rows | `postgres_fixture_journeys.rs` in the postgres lane, and `quickstart/run.sh --spatial --smoke`, whose contract `test_quickstart.py` holds under `scripts/check-contracts.sh` |
| `registry-record-conformance` | The HTTP record contract across every configured record profile | `postgres_record_profile_conformance.rs` in the postgres lane |
| `household-history` | Historical households loaded and queried across effective periods | `scripts/test-historical-workflow.sh` only, which no continuous integration job selects |
| `issuer-portability` | An authority cutover from Registry Mint to a second issuer, with the old issuer rejected | the ignored `issuer_portability.rs` test, driven by `scripts/test-issuer-portability.py` only, which no continuous integration job selects |

The last two rows are run by local scripts alone. They are maintained
acceptance projects with executable proof, but nothing in
`.github/workflows/ci.yml` selects that proof, so a regression in either one
surfaces only when an operator runs its script.
