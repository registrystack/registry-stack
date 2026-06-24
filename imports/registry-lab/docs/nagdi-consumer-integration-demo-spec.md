# NAgDI Consumer Integration Demo Improvement Spec

## Purpose

Extend the agricultural registry demo so it shows how real consuming systems use
Registry Relay and Registry Notary. The current demo proves that XLSX-backed
agricultural registries can publish governed metadata, protected rows,
aggregates, evidence, and credentials. This improvement should prove what a
program MIS, an animal-health MIS, a GIS/planning user, and a semantic
interoperability consumer would actually do with those surfaces.

The demo should keep the core NAgDI message: authorities keep their source
systems, consumers discover what is available, access is purpose-bound, and raw
registry rows are not copied into a central data lake.

## Design Thesis

Different consumers need different surfaces:

- A program MIS needs case workflow facts and evidence.
- A permit MIS needs bounded decision support and reason codes.
- QGIS and planning users need spatial or aggregate layers, not personal rows.
- Interoperability consumers need semantic mappings, not source workbook
  rewrites.

Registry Relay answers: what facts or aggregate views may this system consult?
Registry Notary answers: what evidence, predicate, reason, or credential can
be issued from governed registry facts?

## Scope

Build four consumer stories around the existing agricultural registry profile:

- `voucher-mis`: a climate-smart input voucher program MIS.
- `qgis-planner`: a GIS or planning analyst using aggregate or spatially safe
  layers over Philippines demo geography.
- `publicschema-integrator`: an interoperability consumer validating semantic
  mappings from operational workbook fields to PublicSchema-shaped concepts.
- `wallet-holder`: a holder-bound credential and lightweight OID4VCI/wallet
  probe for successful voucher evidence.

The core implementation should keep `voucher-mis`, `qgis-planner`, planning
fixtures, `publicschema-integrator`, and wallet/OID4VCI. A separate
`animal-health-mis` client is useful later, but livestock movement can remain in
the existing narrated smoke path until the core demo is crisp.

## Non-Goals

- Do not replace the source XLSX workbooks with PublicSchema-shaped workbooks.
- Do not add writes to Registry Relay.
- Do not imply automatic voucher entitlement or automatic permit issuance.
- Do not expose farmer lists, animal-owner lists, parcel rows, or exact
  household locations to planning users.
- Do not build a full production MIS frontend unless the demo specifically
  needs one. A scripted MIS client with clear artifacts is enough for the first
  wave.
- Do not require QGIS desktop automation in CI. The smoke path must produce and
  validate the same Philippines GeoJSON or OGC-compatible aggregate layer that a
  presenter can load manually in QGIS.

## Existing Inputs

The improvement builds on the current agriculture profile:

- XLSX workbooks under `data/agriculture/`
- Registry Relay config at `config/relay/agri-registry-relay.yaml`
- portable metadata at `config/relay/agri-registry-relay.metadata.yaml`
- Registry Notary config at `config/notary/nagdi-agriculture-notary.yaml`
- generated fixtures from `scripts/generate-agri-fixtures.py`
- smoke checks from `scripts/smoke-agri.sh`
- narrated flow from `scripts/demo-agri-flow.py`

This is an extension of the implemented demo, not a replacement. The current
voucher eligibility, livestock movement, aggregate suppression, metadata
discovery, denial controls, and credential issuance flows should stay intact.
The consumer stories should reuse those surfaces and produce clearer
role-specific artifacts around them.

The existing golden subjects stay valid:

- `FARMER-1001`: voucher eligible.
- `FARMER-1002`: not eligible because parcel status is not active.
- `FARMER-1003`: not eligible because voucher was already redeemed.
- `FARMER-1004`: not eligible because farmer registration is not active.
- `FARMER-1005`: manual review because of data-quality controls.
- `HERD-2001`: livestock movement eligible.
- `HERD-2002`: livestock movement denied because vaccination is expired.
- `HERD-2003`: livestock movement denied because origin is quarantined.

## Fixture Scale Model

The demo needs two fixture scales because evidence testing and planning maps
have different needs.

### Golden Fixtures

Golden fixtures are small, hand-curated, and deterministic. They are the default
source for Notary, MIS, denial-control, and credential tests.

Rules:

- Preserve the existing golden subject IDs and outcomes.
- Keep row counts small enough that eligibility failures are easy to inspect.
- Do not let generated planning rows change the expected outcomes for
  `FARMER-1001` through `FARMER-1005` or `HERD-2001` through `HERD-2003`.
- Keep negative cases intentional: inactive parcel, redeemed voucher, inactive
  registration, manual review, expired vaccination, and quarantine.

### Planning Fixtures

Planning fixtures are larger deterministic synthetic data used for aggregate,
QGIS, and planning demos. They should make aggregate layers visible even when
minimum-cell suppression is enabled.

Recommended scale:

- 250 to 1,000 synthetic farmers.
- 4 to 8 Philippines demo geographies, modeled as provinces or municipalities
  with stable PSGC-like synthetic codes.
- 2 to 4 crop types.
- multiple risk bands and input packages.
- enough livestock holdings and herds to show species and production-system
  aggregates.
- several rare district/crop/risk/species combinations below the configured
  threshold to prove suppression.

Rules:

- Planning rows use distinct ID ranges such as `FARMER-P-0001`,
  `HOLDING-P-0001`, `PARCEL-P-0001`, `HERD-P-0001`, and `CELL-P-0001`.
- Planning rows use Philippines place names and coarse administrative geometry,
  but never real farmer, parcel, household, animal-owner, or beneficiary data.
- Planning rows avoid realistic personal data. Names may be bland synthetic
  values, or omitted from planning-only aggregate sources.
- Planning fixtures may feed pre-materialized aggregate sheets directly when
  that better matches the current Relay capability.
- Planning fixtures must still satisfy the XLSX readiness contract: stable
  sheets, unique IDs, resolvable references, parseable types, declared local
  codes, and deterministic generation.

### Generation Interface

The default command should remain stable for the core evidence demo:

```text
just agri-generate
```

Add a planning-scale generation path:

```text
just agri-generate-planning
```

or:

```text
AGRI_FIXTURE_SCALE=planning just agri-generate
```

The planning mode must preserve golden records and append or materialize
planning rows in a way that does not make the MIS and Notary smoke tests
brittle.

## Consumer Stories

### Story 1: `voucher-mis`

`voucher-mis` represents a separate climate-smart input voucher program. It is a
consumer of NAgDI registry evidence, not the owner of the farmer registry,
holding registry, parcel registry, climate registry, or redemption records.

User journey:

1. A caseworker enters or imports `FARMER-1001` for season `2026A`.
2. The MIS starts from static metadata or Relay metadata discovery.
3. The MIS finds the climate-smart input voucher evidence offering.
4. The MIS calls Registry Notary for
   `eligible-for-climate-smart-input-voucher`.
5. Notary returns an eligible outcome with minimized evidence.
6. The MIS records an internal case decision of `ready_for_program_review`.
7. The MIS requests a holder-bound credential only after a successful
   evaluation.

Negative controls:

- `FARMER-1002` returns `not_eligible` with
  `parcel.status:not_active`.
- `FARMER-1003` returns `not_eligible` with
  `voucher.redemption:already_redeemed`.
- `FARMER-1004` returns `not_eligible` with
  `farmer.registration_status:not_active`.
- `FARMER-1005` returns manual review, not automatic eligibility.
- The MIS evidence credential cannot read Relay rows directly.
- If the MIS tries to call Relay for a sensitive row without `Data-Purpose`, it
  is denied.

Optional authorized drill-down:

- The MIS may call Relay for a minimized farmer or holding row only with the
  correct row scope and purpose.
- The drill-down should be framed as case review support, not the normal path
  for eligibility.

Artifacts:

- `voucher-mis-discovery.json`
- `voucher-mis-case-FARMER-1001.json`
- `voucher-mis-case-FARMER-1002.json`
- `voucher-mis-case-FARMER-1003.json`
- `voucher-mis-case-FARMER-1004.json`
- `voucher-mis-case-FARMER-1005.json`
- `voucher-mis-row-denial.json`
- `voucher-mis-credential.json`
- `voucher-mis-summary.json`

### Story 2: `animal-health-mis`

`animal-health-mis` represents a livestock movement permit workflow. It uses
Notary to evaluate herd and movement readiness, then records an internal
permit-review state.

User journey:

1. A permit officer enters `farmer_id` plus `herd_id`.
2. The MIS discovers the livestock movement permit evidence offering.
3. The MIS calls Registry Notary for livestock movement evidence.
4. The MIS receives an eligible, denied, or manual-review result with stable
   reason codes.
5. The MIS does not receive full animal rows, owner records, or quarantine
   workbook exports.

Negative controls:

- `HERD-2002` fails on vaccination.
- `HERD-2003` fails on quarantine.
- Aggregate-only credentials cannot read herd, animal, movement permit, or
  movement event rows.

Artifacts:

- `animal-health-mis-discovery.json`
- `animal-health-mis-case-HERD-2001.json`
- `animal-health-mis-case-HERD-2002.json`
- `animal-health-mis-case-HERD-2003.json`
- `animal-health-mis-summary.json`

### Story 3: `qgis-planner`

`qgis-planner` represents a Philippines district, provincial, or program
planner using QGIS or another GIS client. The user should see safe planning
layers and aggregates, not personal registry records.

QGIS-facing surfaces:

- voucher opportunity aggregates by district, crop, risk band, and input
  package
- livestock herd planning aggregates by district and species
- district climate risk features
- optional service coverage or extension-visit aggregates
- planning-scale cells generated from deterministic synthetic source records
- Philippines administrative features with stable non-personal feature IDs

Recommended formats:

- GeoJSON artifact for the first smokeable implementation.
- OGC API Features where the Relay profile supports it.
- CSV or XLSX export only as a secondary human artifact, not the primary GIS
  story.

Privacy boundary:

- Planning layers must not contain farmer names, national IDs, phone numbers,
  exact addresses, individual animal IDs, or raw parcel ownership records.
- Planning layers should use Philippines province or municipality geometry, not
  exact farm or household geometry.
- Rare cells are suppressed or omitted.
- Village-level or exact-coordinate layers are internal-government only and
  require a separate purpose and credential.

Demo journey:

1. The planner discovers planning offerings from static metadata or Relay
   metadata.
2. The planner uses the planning-scale fixture set so at least some district
   and crop cells are above the minimum-cell threshold.
3. The planner loads the Philippines aggregate GeoJSON in QGIS, or the demo
   validates the same layer as GeoJSON in CI.
4. The planner can filter by district, crop, risk band, species, or production
   system within configured bounds.
5. A rare-cell query is suppressed.
6. A row-level farmer query with the planner credential is denied.

Artifacts:

- `qgis-planner-layer-catalog.json`
- `qgis-planner-voucher-opportunities.geojson`
- `qgis-planner-livestock-herds.geojson`
- `qgis-planner-suppressed-cell.json`
- `qgis-planner-row-denial.json`
- `qgis-planner-summary.json`

### Story 4: `publicschema-integrator`

`publicschema-integrator` represents a system integrator, procurement evaluator,
or data exchange partner who needs to understand what the source records mean.

This story should show semantic mapping, not source migration.

Target mappings:

- `Farmers` to `Person`
- `FarmerIdentifiers` to `Identifier`
- `Holdings` to `Farm`
- `FarmerGroups` and farm operator links to `GroupMembership`
- `AdminAreas`, villages, and premises to `Location`

Rules:

- Source workbooks remain authority-owned and operationally shaped.
- Mappings live in configuration and execute through `crosswalk`, using
  `crosswalk-publicschema` where PublicSchema property mappings are needed.
- Any generated PublicSchema-shaped export is an output artifact, not a source
  registry.
- Relay metadata should use PublicSchema concept URIs only where the semantic
  fit is strong. Domain-specific concepts stay in the NAgDI namespace.

Artifacts:

- `publicschema-mapping-index.json`
- `publicschema-crosswalk-diagnostics.json`
- `publicschema-person-sample.json`
- `publicschema-farm-sample.json`
- `publicschema-group-membership-sample.json`
- `publicschema-projection-summary.json`

### Story 5: `wallet-holder`

`wallet-holder` represents a farmer or applicant receiving holder-bound
credential evidence after a successful voucher evaluation.

Rules:

- Credential issuance is downstream of Notary evaluation and never substitutes
  for it.
- The demo keeps the existing holder-bound SD-JWT VC path.
- The OID4VCI or wallet probe should be lightweight and scripted. It should
  prove discovery and issuance wiring, not a full production wallet ceremony.
- Failed or not-ready voucher cases do not issue credentials.
- Credential payloads do not contain raw source workbook rows.

Artifacts:

- `wallet-holder-credential-offer.json`
- `wallet-holder-credential.json`
- `wallet-holder-negative-control.json`
- `wallet-holder-summary.json`

## Consumer Access Model

Add separate demo credentials for consumer roles:

- `voucher_mis_evidence_client`: can discover metadata and call voucher Notary
  evidence.
- `voucher_mis_case_reviewer`: can read minimized farmer and holding rows with
  the correct purpose.
- `animal_health_mis_evidence_client`: can discover metadata and call livestock
  Notary evidence.
- `qgis_planner_aggregate_client`: can discover metadata and read aggregate or
  spatial planning views only.
- `publicschema_integrator_metadata_client`: can read metadata and mapping
  artifacts, but not personal rows.
- `wallet_holder_client`: can receive credential issuance artifacts only after a
  successful Notary evaluation.

Each role must have at least one positive check and one denial check.

## MIS Behavior Contract

The MIS clients should behave like external systems:

- no source data mount
- no direct workbook reads
- no shared in-process code with fixture generation
- starts from metadata or a configured service URL
- sends `x-request-id`
- sends `Data-Purpose` where required
- stores output artifacts without raw tokens
- records internal case state separately from registry evidence
- treats Notary results as evidence for review, not automatic legal decisions

Recommended `voucher-mis` case states:

- `ready_for_program_review`
- `not_ready_for_program_review`
- `manual_review_required`
- `registry_access_denied`

## QGIS Layer Contract

GIS-facing layers should satisfy these rules:

- each feature has a stable non-personal feature id
- geometry is Philippines province or municipality level, or otherwise coarse
  enough for the configured purpose
- properties contain aggregate counts, area, risk band, crop, species, or
  program-planning fields
- properties do not contain direct identifiers
- small cells are suppressed or omitted
- the layer can be fetched by a client without source workbook access
- the same layer can be inspected as a saved artifact in CI

## PublicSchema Projection Contract

PublicSchema alignment should be demonstrated as a projection:

- `crosswalk` mapping specs define the transformation
- `crosswalk-publicschema` is used when the mapping shape is PublicSchema v0.2
  `property_mappings`
- sample projection artifacts are generated from source data
- source workbook names and operational fields remain visible in the demo
- projection outputs have stable row counts and stable IDs
- projection outputs preserve links between `Person`, `Identifier`, `Farm`, and
  `GroupMembership`
- no projection artifact becomes an authoritative source file

## Wallet/OID4VCI Contract

Wallet-facing artifacts should satisfy these rules:

- credentials issue only after a successful `FARMER-1001` voucher evaluation
- negative or manual-review voucher cases do not issue credentials
- holder binding is present in the credential request or issued artifact
- credential payloads contain bounded evidence, not raw source rows
- OID4VCI or wallet interop checks may be scripted and local, but must produce a
  replayable summary artifact

## Implementation Shape

Prefer scripted clients before full UI services:

- add `scripts/demo-voucher-mis.py`
- add `scripts/demo-qgis-planner.py`
- add `scripts/demo-publicschema-integrator.py`
- add or reuse a scripted wallet/OID4VCI probe for the agriculture credential
- later add `scripts/demo-animal-health-mis.py`

Add `just` recipes:

```text
just agri-generate-planning
just agri-voucher-mis
just agri-qgis-planner
just agri-crosswalk-python
just agri-publicschema-integrator
just agri-publicschema-integrator-strict
just agri-wallet
just agri-consumers
just agri-consumers-strict
just agri-verify-consumer-artifacts
just agri-verify-consumer-artifacts-strict
```

Future optional recipe:

```text
just agri-animal-health-mis
```

The first wave can run these scripts from the host against the existing agri
Compose profile. A later wave can package them as Compose client containers if
that makes the demo easier to present.

## Definition Of Done

This work is complete only when every core criterion below is true in a clean
checkout after `just agri-down`.

Core command gate:

- `just agri-generate` exits 0.
- `just agri-up` exits 0.
- `just agri-smoke` exits 0.
- `just agri-generate-planning` exits 0.
- `just agri-voucher-mis` exits 0.
- `just agri-qgis-planner` exits 0.
- `just agri-crosswalk-python` exits 0 and its Python binding tests pass.
- `just agri-publicschema-integrator` exits 0.
- `just agri-publicschema-integrator-strict` exits 0.
- `just agri-wallet` exits 0.
- `just agri-consumers` exits 0 and runs the implemented consumer scripts.
- `just agri-consumers-strict` exits 0 and requires Crosswalk-backed
  PublicSchema output.
- `just agri-verify-consumer-artifacts-strict` exits 0.

Fixture and source-data gate:

- `just agri-generate` produces exactly the expected agriculture source
  workbooks, including `nagdi-evidence-snapshots.xlsx`.
- Two consecutive `just agri-generate-planning` runs produce identical
  checksums for `data/agriculture/*.xlsx`.
- Golden outcomes remain unchanged for `FARMER-1001` through `FARMER-1005`.
- Planning rows use distinct `*-P-*` IDs.
- Planning rows use Philippines province or municipality geography.
- Generated workbook validation proves primary keys, required foreign keys,
  code lists, date parsing, and visible plus suppressed aggregate cells.

Consumer safety gate:

- Consumer scripts do not import `openpyxl`.
- Consumer scripts do not read `data/agriculture/`.
- Consumer containers, if added, do not mount source workbooks.
- Every consumer request includes `x-request-id`.
- Every sensitive Relay row request includes `Data-Purpose`.
- Artifacts under `output/agri-*` contain no raw API keys, bearer tokens,
  credential hashes, private keys, or `.env` values.

`voucher-mis` gate:

- `output/agri-voucher-mis/voucher-mis-summary.json` exists.
- `FARMER-1001` records `ready_for_program_review`.
- `FARMER-1002` records `not_ready_for_program_review` and
  `parcel.status:not_active`.
- `FARMER-1003` records `not_ready_for_program_review` and
  `voucher.redemption:already_redeemed`.
- `FARMER-1004` records `not_ready_for_program_review` and
  `farmer.registration_status:not_active`.
- `FARMER-1005` records `manual_review_required`.
- Evidence-only row-read and missing-purpose row-read attempts produce denial
  artifacts.

`qgis-planner` gate:

- `output/agri-qgis-planner/qgis-planner-summary.json` exists.
- `qgis-planner-summary.json` records `voucher_feature_count >= 1`.
- `qgis-planner-summary.json` records `livestock_feature_count >= 1`.
- `qgis-planner-summary.json` records `suppressed_or_denied_cell_count >= 1`.
- `qgis-planner-voucher-opportunities.geojson` exists.
- `qgis-planner-livestock-herds.geojson` exists.
- `qgis-planner-project.qgs` exists and parses as XML.
- `qgis-planner-package.json` exists, points to both GeoJSON layers, and records
  `contains_direct_identifiers = false`.
- GeoJSON features use Philippines province or municipality geometry.
- GeoJSON artifacts contain no farmer names, national IDs, phone numbers,
  individual animal IDs, or raw parcel ownership rows.
- Planner row-level farmer access is denied.

`publicschema-integrator` gate:

- `output/agri-publicschema-integrator/publicschema-projection-summary.json`
  exists.
- `output/agri-publicschema-integrator/publicschema-crosswalk-diagnostics.json`
  exists and contains no blocking mapping errors.
- Strict mode records `mapping_adapter = crosswalk-python`,
  `compiled_mapping_count = 5`, and no diagnostics warnings.
- Mapping specs live outside source workbooks.
- Projection artifacts are generated outputs, not source registry files.
- Projection summary records stable row counts and IDs for `Person`,
  `Identifier`, `Farm`, `GroupMembership`, and `Location`.
- `Person`, `Identifier`, `Farm`, and `GroupMembership` links resolve.

`wallet-holder` gate:

- `output/agri-wallet/wallet-holder-summary.json` exists.
- `FARMER-1001` voucher evidence produces a holder-bound credential.
- Negative and manual-review voucher cases do not produce credentials.
- Wallet or OID4VCI artifacts contain no raw source workbook rows.

Review and regression gate:

- Each wave has a named staff-engineer reviewer approval recorded before the
  next wave starts.
- Each wave has domain, privacy, or security review recorded when its scope
  touches workflow realism, row minimization, disclosure, or credentials.
- Review findings are resolved or explicitly deferred with a named reason.
- `git diff --name-only main...HEAD` is reviewed at each wave. If shared
  surfaces such as `justfile`, `compose.yaml`, Dockerfiles, source generation,
  static metadata, or secret generation changed, baseline `just smoke` and
  `just release-fast` run or the skipped command and reason are recorded.
- Final diff contains no unrelated file changes.

## Implementation Plan Checklist

Use this checklist as the implementation plan. Workers run in parallel only
when their file ownership is disjoint. One infrastructure owner per wave owns
shared files such as `justfile`, `compose.yaml`, README updates, and secret or
metadata publication wiring.

### Wave 1: Fixture Scale And Philippines Geography

Parallel work:

- Worker A: update `scripts/generate-agri-fixtures.py` for golden and
  planning-scale generation.
- Worker B: add `just agri-generate-planning` and generation environment
  plumbing.
- Worker C: add fixture validation for keys, references, code lists, dates,
  Philippines geography, visible aggregate cells, and suppressed cells.
- Infrastructure owner: coordinates `justfile`, README, and static metadata
  wiring.

Done when:

- `just agri-generate` exits 0.
- `just agri-generate-planning` exits 0 twice with identical workbook checksums.
- Golden farmer outcomes remain unchanged.
- Planning rows use `*-P-*` IDs and Philippines province or municipality
  geography.
- Visible and suppressed aggregate cells are both present.
- `just agri-smoke` exits 0.
- Staff-engineer and domain reviews are recorded with no unresolved blocking
  findings.

### Wave 2: `voucher-mis`

Parallel work:

- Worker A: implement `scripts/demo-voucher-mis.py`.
- Worker B: add voucher MIS consumer credentials and scopes.
- Worker C: add `just agri-voucher-mis` plus assertions for case states and
  denial artifacts.
- Infrastructure owner: coordinates shared recipe and documentation edits.

Done when:

- `just agri-voucher-mis` exits 0.
- `voucher-mis-summary.json` contains the five expected case states and exact
  reason codes.
- Evidence-only and missing-purpose row-read denials are captured.
- Consumer artifacts contain no raw tokens or raw source rows.
- `just agri-smoke` exits 0.
- Staff-engineer and privacy reviews are recorded with no unresolved blocking
  findings.

### Wave 3: `qgis-planner`

Parallel work:

- Worker A: implement `scripts/demo-qgis-planner.py`.
- Worker B: add or adjust aggregate, GeoJSON, OGC-compatible, or metadata
  surfaces needed for the planner layer.
- Worker C: add `just agri-qgis-planner` plus assertions for feature counts,
  suppressed cells, row denial, and identifier absence.
- Infrastructure owner: coordinates shared recipe and documentation edits.

Done when:

- `just agri-qgis-planner` exits 0 after planning fixtures are generated.
- Voucher and livestock GeoJSON artifacts exist.
- Summary records voucher and livestock feature counts of at least 1.
- Summary records suppressed or denied cell count of at least 1.
- GeoJSON uses Philippines province or municipality geometry.
- GeoJSON contains no direct personal, animal, or parcel identifiers.
- Planner row-level farmer access is denied.
- `just agri-smoke` exits 0 against golden fixtures.
- Staff-engineer and privacy reviews are recorded with no unresolved blocking
  findings.

### Wave 4: PublicSchema Projection With `crosswalk`

Parallel work:

- Worker A: add `crosswalk` or `crosswalk-publicschema` mapping specs under demo
  config.
- Worker B: implement `scripts/demo-publicschema-integrator.py`.
- Worker C: add `just agri-publicschema-integrator` plus diagnostics, row-count,
  ID, and link assertions.
- Infrastructure owner: coordinates shared recipe and documentation edits.

Done when:

- `just agri-publicschema-integrator` exits 0.
- `just agri-publicschema-integrator-strict` exits 0 after
  `just agri-crosswalk-python`.
- Mapping specs live outside source workbooks.
- Generated projection artifacts exist for `Person`, `Identifier`, `Farm`,
  `GroupMembership`, and `Location`.
- `publicschema-crosswalk-diagnostics.json` has no blocking mapping errors.
- Strict diagnostics show `adapter = crosswalk-python`, five compiled mappings,
  and no warnings.
- Projection summary records stable row counts and IDs.
- Links between `Person`, `Identifier`, `Farm`, and `GroupMembership` resolve.
- `just agri-smoke` exits 0.
- Staff-engineer and domain reviews are recorded with no unresolved blocking
  findings.

### Wave 5: Wallet/OID4VCI

Parallel work:

- Worker A: wire or reuse agriculture credential issuance for the wallet path.
- Worker B: add `just agri-wallet` plus negative controls for denied and
  manual-review voucher cases.
- Worker C: add holder-binding, OID4VCI or wallet artifact, and no-raw-row
  assertions.
- Infrastructure owner: coordinates shared recipe and documentation edits.

Done when:

- `just agri-wallet` exits 0.
- `wallet-holder-summary.json` records holder-bound credential issuance for
  `FARMER-1001`.
- Negative and manual-review voucher cases do not issue credentials.
- Wallet or OID4VCI artifacts contain no raw source rows or secrets.
- `just agri-smoke` exits 0.
- Staff-engineer and security reviews are recorded with no unresolved blocking
  findings.

### Final Integration Gate

- `just agri-generate`
- `just agri-up`
- `just agri-smoke`
- `just agri-generate-planning`
- `just agri-voucher-mis`
- `just agri-qgis-planner`
- `just agri-crosswalk-python`
- `just agri-publicschema-integrator`
- `just agri-publicschema-integrator-strict`
- `just agri-wallet`
- `just agri-consumers`
- `just agri-consumers-strict`
- `just agri-verify-consumer-artifacts-strict`

The work is complete only when every command above exits 0, every expected
summary artifact exists, all review findings are resolved or explicitly
deferred with a named reason, and the final diff contains no unrelated file
changes.
