# Social Protection Attestation Demo Refresh Spec

Page type: implementation spec
Product: Registry Lab
Layer: hosted and local demo UX, fixtures, Relay, Notary, credentials, and docs
Audience: maintainers, demo operators, and implementers

## Goal

Refresh Registry Lab so the social protection demos look like realistic
government evidence exchange, not a catalogue of toy API checks.

The demo should show a Social Protection MIS building a benefit case file. The
MIS does not fetch source rows. It requests narrowly scoped attestations from
authoritative registries. Each attestation contains minimized claims, matching
metadata, source freshness, PublicSchema anchors, and proof metadata.

This spec supersedes the older scenario naming in
`guided-demo-scenarios-and-data-plan.md` where it conflicts with this document.
That older plan still describes useful UI mechanics, route structure, and
verification practices.

## Current Implementation Status

Status date: 2026-06-14

This section records the current implementation state of the worktree. The
target-state requirements in the rest of this document still apply.

### Done And Verified

- Public attestation metadata exists in
  `scripts/lab_homepage_scenarios/attestations.py` and hides internal
  compatibility claim ids from returned public metadata.
- Static metadata has been refreshed so public evidence offerings use
  attestation-facing ids and rulesets, for example
  `household-composition-attestation`,
  `caregiver-link-attestation`, `disability-determination-attestation`, and
  `functioning-assessment-attestation`.
- The social protection Notary exposes these new runnable claims:
  `household-composition`, `caregiver-link`, `disability-determination`, and
  `functioning-assessment`.
- Social protection fixtures now include lightweight functioning profile and
  disability determination data, with national-id lookup fields available to
  Relay and Notary.
- Hosted configuration includes a `social-protection-notary` service and
  hosted metadata points social protection offerings at the hosted social
  Notary endpoint.
- Public static metadata no longer exposes `compatibility_claim_ids`.
- Atlas is no longer part of the demo framing or supported scenario set.

Verification completed:

- `uv run scripts/test_generate_fixtures.py`
- `python3 scripts/test_lab_homepage_server.py`
- `python3 scripts/test_validate_hosted_deploy.py`
- `bash -n scripts/smoke.sh`
- `REGISTRY_MANIFEST_REPO=../products/manifest scripts/smoke.sh`
- static metadata scan for `compatibility_claim_ids` and the old first-level
  raw ids
- hosted social Relay config sanity check in Docker

### Available Systems

| System | Demo role | Current status |
| --- | --- | --- |
| Civil Registry | CRVS-style source for date of birth, age, life stage, and vital status | Local and hosted-capable |
| OpenCRVS DCI Notary | Birth registration and demographic birth lookup source | Local and hosted-capable |
| OpenFn Civil sidecar | Civil lookup through an OpenFn path | Local path available |
| Social Protection Registry / SP MIS | Programme, household, caregiver, welfare, disability, and functioning source | Local verified; hosted config added |
| DHIS2 Health Notary | Health programme participation source | Local and hosted-capable |
| Shared Eligibility Notary | SP MIS-local composition layer for combined support checks | Local |
| NAgDI Agriculture Notary | Agriculture entitlement, voucher, livestock, and market-sizing source | Local advanced story |
| Citizen Civil Notary | Wallet and citizen credential flow | Local and hosted-capable |

### Public Attestations To Use In Demo Language

Use these public names in scenario copy, chooser cards, and presentation
narrative:

| Public attestation | Current backing claim ids |
| --- | --- |
| Vital Status Attestation | `person-is-alive` |
| Birth Registration Attestation | `opencrvs-birth-record-exists`, `opencrvs-birth-record-exists-by-demographics` |
| Age Eligibility Attestation | `age-band`, `opencrvs-age-band` |
| Program Enrollment Attestation | `program-enrollment-status`, `beneficiary-active`, `social-program-active` |
| Welfare Classification Attestation | `household-eligibility-band` |
| Household Composition Attestation | `household-composition` |
| Parent Or Guardian Link Attestation | `caregiver-link` |
| Disability Determination Attestation | `disability-determination` |
| Functioning Assessment Attestation | `functioning-assessment` |
| Health Programme Participation Attestation | `dhis2-child-program-active`, `dhis2-maternal-pnc-active`, `dhis2-child-health-visit-recorded`, `dhis2-tb-program-active` |
| Service Availability Attestation | `health-service-available` |
| Combined Support Eligibility Attestation | `eligible-for-combined-support` |
| Agricultural Entitlement Attestation | `eligible-for-climate-smart-input-voucher`, `voucher-entitlement-current` |
| Benefit Conflict Attestation | `voucher-eligibility-reason-code`, `voucher-not-redeemed`, `no-conflicting-open-movement-permit` |

The raw ids are still valid Registry Notary claim ids and may appear in raw API
payloads or compatibility tests. They should not be used as the first-level
public story.

### Current Claim Inventory

| System | Claims currently available |
| --- | --- |
| Civil Registry | `date-of-birth`, `life-stage`, `age-band`, `person-is-alive` |
| OpenCRVS DCI | `opencrvs-birth-record-exists`, `opencrvs-date-of-birth`, `opencrvs-sex`, `opencrvs-age-band`, `opencrvs-birth-record-exists-by-demographics`, `opencrvs-child-given-name`, `opencrvs-child-family-name`, `opencrvs-child-date-of-birth`, `opencrvs-child-place-of-birth` |
| OpenFn Civil | `date-of-birth` |
| Social Protection | `program-enrollment-status`, `household-eligibility-band`, `beneficiary-active`, `household-composition`, `caregiver-link`, `disability-determination`, `functioning-assessment` |
| DHIS2 Health | `dhis2-tracked-entity-first-name`, `dhis2-tracked-entity-last-name`, `dhis2-child-program-active`, `dhis2-child-age-band`, `dhis2-programme-code`, `dhis2-reconciliation-ref`, `dhis2-maternal-pnc-active`, `dhis2-child-health-visit-recorded`, `dhis2-tb-program-active` |
| Shared Eligibility | `civil-record-present`, `social-program-active`, `health-service-available`, `eligible-for-combined-support` |
| NAgDI Agriculture | `farmer-registered`, `data-use-authorized-for-purpose`, `active-smallholder-farmer`, `active-farm-parcel`, `crop-declared-for-season`, `district-climate-risk-active`, `voucher-entitlement-current`, `voucher-not-redeemed`, `supplier-license-active`, `voucher-eligibility-reason-code`, `no-manual-review-required`, `eligible-for-climate-smart-input-voucher`, `voucher-redemption-authorized`, `market-sizing-aggregate-controls`, `registered-livestock-holder`, `registered-herd`, `herd-vaccination-current`, `origin-district-not-quarantined`, `destination-district-open`, `no-conflicting-open-movement-permit`, `livestock-movement-reason-code`, `eligible-for-livestock-movement-permit` |

### Partially Done

- The new social protection attestations are implemented as conservative
  primitive claims:
  household size as an integer, caregiver link as a boolean, disability support
  category as a string, and functioning threshold as a boolean. Rich object
  attestations remain a future improvement.
- PublicSchema grounding is present as metadata anchors, but source records are
  still practical demo fixtures rather than fully PublicSchema-native records.
- Hosted social protection Notary configuration exists, but the full hosted
  user-facing flow still needs an end-to-end deployed rehearsal.
- The scenario catalogue and homepage metadata use public attestation names,
  but the complete case-file UX described later in this spec is not fully
  implemented for every scenario.

### Still Needed For 95 Percent Demo Confidence

- Run a real hosted rehearsal of the social protection Notary path, not only
  local smoke and hosted config validation.
- Polish one primary OpenSPP demo path so it reads as a case-file assembly
  flow: requirement, requested attestations, matched source authority,
  minimized claims, non-disclosure, proof metadata, and final SP MIS decision.
- Add or verify negative controls in the public scenario experience, especially
  for caregiver link failure, inactive programme enrollment, non-qualifying
  disability assessment, and ambiguous demographic birth lookup.
- Decide whether agriculture remains local-only or gets promoted to hosted.
- Clean small config hygiene issues before a public branch is finalized,
  including the duplicate `lookup:` key currently tolerated in the social
  protection Notary config.

## Definition Of Done

This refresh is complete only when every criterion below is true and verified in
the implementation change set.

- `docs/README.md` and the root `README.md` link this spec, and no other
  public Registry Lab doc contradicts the terms Evidence, Attestation, Claim,
  Credential, and Proof.
- A machine-readable attestation catalogue, or equivalent scenario metadata,
  defines every implemented public attestation with `offering_id`,
  `display_name`, source authority, lookup profiles, PublicSchema anchors,
  disclosure profile, freshness fields, and compatibility claim aliases.
- A static check fails if first-level public scenario labels, route titles, or
  chooser cards expose raw compatibility ids such as `person-is-alive`,
  `beneficiary-active`, or `health-service-available`.
- Generated fixtures contain deterministic civil records, birth events, death
  events, certificates, relationships, household memberships,
  socio-economic profiles, scoring events, enrollments, entitlements, payment
  events, and health service or programme records needed by the implemented
  scenarios.
- Fixture invariant tests name the exact persona ids, source rows, expected
  positive outcomes, expected negative outcomes, ambiguous-match controls,
  stale or expired controls, and policy-denied controls for every implemented
  scenario.
- Every implemented attestation response includes `attestation_id`,
  `display_name`, `source_authority`, `jurisdiction`, `publicschema_anchor`,
  `subject`, `match_method`, `as_of`, `source_observed_at`,
  `disclosure_profile`, `claims`, and `proof`; `valid_until` is present when
  the source fact has validity.
- Each implemented lookup profile has a positive test and at least one failure
  test for `not_found`, `ambiguous_match`, `policy_denied`, or the relevant
  domain failure.
- Hosted scenario chooser entries are accurate: runnable hosted scenarios call
  real hosted endpoints, local-only scenarios are disabled before execution,
  and planned scenarios cannot be run.
- Child Benefit Application and Health-Linked Support are runnable in hosted
  mode, or the pull request explicitly marks them incomplete and does not claim
  the refresh is complete.
- Death-Triggered Benefit Review is runnable only after hosted social registry
  attestations exist; until then it is visibly blocked in hosted mode with a
  tested local path or disabled state.
- Disability Top-Up is runnable only after the disability or functioning source
  exists; until then it is visibly blocked and omitted from completion claims.
- Agriculture Voucher is either runnable against hosted agriculture services or
  marked local-only before execution, with local positive and negative controls
  passing.
- Scenario pages show the SP MIS requirement, requested attestations, subject
  and requester context, lookup profile, friendly result, minimized claims,
  data not disclosed, proof metadata, raw request drawer, raw response drawer,
  copy-as-curl, and final case-file receipt.
- No scenario response or UI drawer exposes runtime secrets, private holder key
  material, raw source connector tokens, or unapproved full source rows.
- Automated verification passes for fixture generation, fixture invariants,
  scenario payloads, token display policy, attestation label checks, hosted
  deployment validation for hosted config changes, and smoke clients updated
  for renamed or aliased offerings.
- Desktop and mobile browser verification has been completed for every
  implemented scenario in local mode and for every hosted scenario in hosted
  mode.
- `scripts/release-check.sh` passes before the refresh is marked complete, or
  the final change record lists the exact skipped checks with reasons and the
  feature remains explicitly incomplete.

## Background

The current lab already has strong pieces:

- hosted civil Notary and Relay;
- hosted OpenCRVS DCI Notary;
- hosted citizen OID4VCI flow;
- hosted DHIS2 Notary;
- local social protection Notary and Relay;
- local shared eligibility Notary;
- local NAgDI agriculture Notary with richer domain logic.

The weak parts are credibility and framing:

- public labels still center technical claims such as `person-is-alive`;
- some source models are too thin for the DCI webinar use cases;
- health data can look like a facility registry keyed by `national_id`;
- social protection data collapses enrollment, entitlement, and payment;
- hosted scenarios do not yet show enough realistic cross-registry casework;
- PublicSchema is not yet visible as the vocabulary bridge.

## Terminology

Use these terms consistently in Registry Lab UI and docs.

| Term | Meaning in the demo |
| --- | --- |
| Evidence | What the SP MIS receives and uses to satisfy a benefit requirement. This is the CCCEV-facing term. |
| Attestation | A source-backed package produced by Registry Notary. This is the public demo term for offerings. |
| Claim | A single machine statement inside an attestation. Registry Notary configs may still call these `claims`. |
| Credential | A portable signed artifact, when the attestation is issued as VC or SD-JWT VC. |
| Proof | Signature, issuer metadata, holder binding, audit receipt, or other verification material. |

Recommended public sentence:

> The SP MIS requests evidence from the source authority. Registry Notary
> returns a signed attestation containing minimized claims and proof metadata.

## Non-Goals

- Do not model MOSIP, eSignet, or FranceConnect login as evidence. Login is
  requester context, not a reusable eligibility fact.
- Do not build a universal eligibility engine inside every source Notary. The
  SP MIS owns the benefit decision.
- Do not expose full household rosters, diagnosis details, exact income, exact
  dates of birth, or full payment history unless a scenario explicitly needs
  that disclosure.
- Do not wait for perfect PublicSchema-shaped source files before improving the
  demo. Use adapter metadata where source fixtures remain pragmatic.

## Product Principle

Registry Lab should show **case-file assembly**.

Each scenario starts with an SP MIS requirement, then shows which source
attestations satisfy that requirement. The friendly result should answer:

- what the SP MIS needed;
- which source authority answered;
- how the subject was matched;
- what minimized claim was returned;
- what was deliberately not disclosed;
- whether the result is fresh enough for the decision.

## PublicSchema Grounding

Every new or refreshed attestation offering must declare a PublicSchema anchor
in metadata and scenario copy. The fixture can still be CSV, XLSX, Parquet, or a
live sidecar response.

| Demo area | PublicSchema anchors |
| --- | --- |
| Civil events | `CivilStatusRecord`, `Birth`, `Death`, `Certificate`, `CivilStatusAnnotation` |
| Identity and matching | `Person`, `Identifier` |
| Relationships | `Relationship`, `Family`, `GroupMembership` |
| Household targeting | `Household`, `SocioEconomicProfile`, `ScoringEvent` |
| Program lifecycle | `Program`, `EligibilityDecision`, `Enrollment`, `Entitlement`, `PaymentEvent` |
| Disability and functioning | `FunctioningProfile`, `ScoringEvent` |
| Health service and programmes | `HealthFacility`, `Location`, `Program`, `Enrollment` |
| Agriculture | `Person`, `Identifier`, `Location`, `Program`, `Entitlement`, `PaymentEvent` |

Each attestation response should include:

- `attestation_id`;
- `display_name`;
- `source_authority`;
- `jurisdiction`;
- `publicschema_anchor`;
- `subject`;
- `match_method`;
- `matched_record_ref` as a hash or non-sensitive source reference;
- `as_of`;
- `source_observed_at`;
- `valid_until` when applicable;
- `disclosure_profile`;
- `claims`;
- `proof`.

## Hosted And Local Availability

The demo must be honest about what runs in hosted Registry Lab.

| Capability | Hosted target | Local target | Notes |
| --- | --- | --- | --- |
| Civil vital status | Available | Available | Rename public story from alive proof to Vital Status Attestation. |
| OpenCRVS birth data | Available | Available | Use for Birth Registration and Age Eligibility. |
| Citizen OID4VCI | Available | Available | Keep adult persona unless explicitly showing a guardian flow. |
| DHIS2 programme participation | Available | Available with profile | Use for Health Programme Participation. |
| Social registry attestations | Should become hosted | Already local | Required for serious SP MIS scenarios. |
| Shared eligibility composition | Optional hosted | Already local | Useful, but must be framed as SP MIS-local composition. |
| Agriculture attestations | Prefer hosted if operationally cheap | Already local | Mark local-only until hosted validation exists. |
| Disability or functioning assessment | Add as new lightweight source | Add as new lightweight source | Needed for the widow/disability use case. |
| Education | Defer unless time permits | Optional local | Good extension after core suite is credible. |

Local-only scenarios must be visible but disabled or clearly labeled in the
hosted UI before the user tries to run them.

## Attestation Catalogue

Registry Notary may continue to expose low-level `claims` internally. Public
metadata, scenario copy, and wallet display names should use attestation names.

| Public attestation | Offering id | Source systems | Inner claim examples |
| --- | --- | --- | --- |
| Birth Registration Attestation | `birth-registration-attestation` | OpenCRVS, civil registry, population registry | `birth_registered`, `record_status`, `certificate_reference_present` |
| Age Eligibility Attestation | `age-eligibility-attestation` | CRVS, population registry, education registry | `age_threshold_met`, `threshold`, `as_of` |
| Vital Status Attestation | `vital-status-attestation` | CRVS, population registry, pension registry | `vital_status` |
| Death Registration Attestation | `death-registration-attestation` | CRVS, population registry | `death_registered`, `registration_status` |
| Parent Or Guardian Link Attestation | `caregiver-link-attestation` | CRVS, family registry, social registry | `relationship_established`, `relationship_type` |
| Household Membership Attestation | `household-membership-attestation` | social registry, SP MIS, municipality | `membership_status`, `as_of` |
| Household Composition Attestation | `household-composition-attestation` | social registry, CAF/MSA-like source, municipality | `member_count`, `child_count`, `elderly_count`, `disabled_member_count` |
| Welfare Classification Attestation | `welfare-classification-attestation` | social registry, assessment registry | `classification_scheme`, `classification_band`, `assessment_date` |
| Program Enrollment Attestation | `program-enrollment-attestation` | program MIS, IBR, OpenSPP, openIMIS | `program_code`, `enrollment_status` |
| Entitlement Attestation | `entitlement-attestation` | program MIS, IBR, OpenSPP | `entitlement_status`, `benefit_modality`, `coverage_period` |
| Payment Status Attestation | `payment-status-attestation` | payment system, program MIS | `payment_status`, `cycle`, `delivery_channel` |
| Benefit Conflict Attestation | `benefit-conflict-attestation` | IBR, program federation | `conflict_rule`, `conflict_found` |
| Disability Determination Attestation | `disability-determination-attestation` | disability registry, program MIS | `determination_status`, `support_category`, `review_status` |
| Functioning Assessment Attestation | `functioning-assessment-attestation` | assessment registry, survey system | `instrument`, `cutoff_rule`, `identifier_met` |
| Health Programme Participation Attestation | `health-programme-participation-attestation` | DHIS2, openIMIS, health MIS | `program_code`, `participation_status` |
| Service Availability Attestation | `service-availability-attestation` | health facility/service registry | `service_type`, `location`, `available` |
| Farmer Registration Attestation | `farmer-registration-attestation` | farmer registry, agriculture MIS | `farmer_status`, `registry_scheme` |
| Agricultural Entitlement Attestation | `agricultural-entitlement-attestation` | agriculture MIS, voucher system | `entitlement_status`, `season`, `voucher_status` |

### Compatibility Aliases

Keep existing low-level claim ids as aliases where needed for stability, but
hide them from the first-level demo language.

| Current id | Public replacement |
| --- | --- |
| `person-is-alive` | `vital-status-attestation` |
| `opencrvs-birth-record-exists` | `birth-registration-attestation` |
| `opencrvs-date-of-birth` | `age-eligibility-attestation` or a raw attribute drawer only |
| `opencrvs-age-band` | `age-eligibility-attestation` |
| `beneficiary-active` | `program-enrollment-attestation` |
| `program-enrollment-status` | `program-enrollment-attestation` |
| `household-eligibility-band` | `welfare-classification-attestation` |
| `health-service-available` | `service-availability-attestation` |
| `dhis2-child-program-active` | `health-programme-participation-attestation` |
| `eligible-for-climate-smart-input-voucher` | `agricultural-entitlement-attestation` plus SP MIS decision receipt |

## Matching Profiles

Each attestation offering must publish accepted lookup profiles. Do not silently
forward extra identifiers or demographics to the source.

Required profiles:

- `by-national-id`: target has a stable NID or UIN.
- `by-source-record-id`: target has a source-specific person, event, household,
  enrollment, farmer, or tracked-entity id.
- `by-certificate-number`: target has a certificate number plus issuer or
  record type.
- `by-household-id`: household-level social registry lookup.
- `by-program-case-id`: program, enrollment, entitlement, or beneficiary lookup.
- `by-two-person-identifiers`: relationship lookup using requester and target
  identifiers.
- `by-demographics`: name, date of birth, place of birth, and at least one
  disambiguating field such as parent name or district.

Standard match outcomes:

- `matched`;
- `not_found`;
- `ambiguous_match`;
- `relationship_not_established`;
- `stale`;
- `expired`;
- `conflict`;
- `policy_denied`.

Demographic matching must never collapse `ambiguous_match` into a negative
attestation.

## Data Model Refresh

### Civil Registry

Current `civil-persons.csv` is too thin for serious CRVS scenarios. Split or
extend civil fixtures so they can represent the legal record, the event, and
certificate references.

Required source concepts:

- `persons`: `national_id`, names, birth date, sex, district, life stage,
  optional death date.
- `identifiers`: scheme, value, subject, status.
- `civil_status_records`: record id, record type, registration number, person,
  event id, authority, registration status, registration date.
- `birth_events`: event id, child, mother, father or second parent, place of
  birth, date of birth, sex at birth, attendant or place type if available.
- `death_events`: event id, deceased, date of death, place of death,
  registration date, authority. Cause of death is not needed for the SP demo.
- `certificates`: certificate number, record id, issue date, issuing office,
  certificate type.
- `relationships`: subject, related person, relationship type, source record,
  effective dates.

Minimum positive personas:

- Miguel Santos, child applicant subject.
- Maria Santos, adult caregiver and wallet subject.
- A deceased spouse or household member for death-triggered review.

Minimum controls:

- same name and date of birth with different place of birth for ambiguous
  demographic matching;
- deceased person for vital status negative control;
- child with no established caregiver link.

### Social Registry

The social registry should model household evidence separately from program
benefit state.

Required workbook sheets or source datasets:

- `Households`: household id, location, address summary, household status.
- `GroupMemberships`: household id, person id, relationship type, start date,
  end date, membership status.
- `SocioEconomicProfiles`: profile id, household id, observation date,
  instrument, collected by, source version.
- `ScoringEvents`: scoring id, profile id, scoring rule, scoring version,
  score band, validity period.
- `Programs`: program code, display name, authority, benefit type.
- `Enrollments`: enrollment id, beneficiary person or household, program code,
  status, enrollment date, exit date, jurisdiction.
- `Entitlements`: entitlement id, enrollment id, benefit modality, amount band
  or exact synthetic amount, currency, coverage period, entitlement status.
- `PaymentEvents`: payment id, entitlement id, cycle, status, delivery channel,
  payment date, reconciled flag.

The public demo should not expose full household rosters by default. It should
show `Household Composition Attestation` as counts and bands.

### Disability And Assessment Registry

Add a lightweight assessment source. It can be CSV or a sheet inside the social
workbook for the first implementation, but public metadata should describe it
as an assessment or disability authority.

Required concepts:

- `FunctioningProfiles`: profile id, person id, instrument code, administration
  date, respondent relationship, selected domain severities, source version.
- `ScoringEvents`: profile id, cutoff rule, disability identifier met, domains
  triggering the identifier.
- `DisabilityDeterminations`: determination id, person id, authority,
  determination status, support category, valid from, valid until, review due.

The demo must distinguish:

- a legal disability determination, suitable for a benefit rule;
- a Washington Group-style functioning assessment, suitable for statistics or
  an assessment-driven scenario but not automatically a legal certificate.

### Health Registry

Do not present a normal facility registry as keyed by `national_id`.

Use two separate patterns:

- DHIS2 or health MIS programme participation by tracked entity or reconciled
  participant id.
- Service availability by district, facility, or service type.

For local fixtures, replace or reframe `health-facilities.parquet` so the
normal source shape is:

- `HealthFacilities`: facility id, name, district, facility type, level,
  operational status, license status.
- `ServiceAvailability`: facility id or district, service type, available,
  valid from, valid until.
- optional `ProgrammeParticipation`: participant id, person id or reconciled
  identifier, programme code, participation status, last visit date.

If an applicant-keyed projection remains for short-term compatibility, label it
as `ApplicantServiceAvailabilityProjection` in docs and UI.

### Agriculture Registry

Keep the NAgDI agriculture model. It is the strongest non-SP demo domain.

Refresh public labels so the scenario speaks in attestations:

- Farmer Registration Attestation;
- Farm Activity or Farm Holding Attestation;
- Agricultural Entitlement Attestation;
- Benefit Conflict Attestation where a voucher is already redeemed or a permit
  is already open.

Hosted visibility depends on operational cost. If agriculture remains
local-only, the hosted scenario chooser must say so before execution.

### Education Registry

Defer education unless the core suite is finished.

If added, keep it small:

- `Students`: student id, person id, school id.
- `Schools`: school id, district, operational status.
- `Enrollments`: student id, academic year, grade, status.
- `AttendanceSummaries`: student id, period, attendance percentage band,
  threshold met.

Education gives a good conditional cash transfer scenario, but it should not
displace CRVS, social registry, disability, health, or agriculture work.

## Scenario Suite

### Scenario 1: Child Benefit Application

Availability target: hosted.

User story: an SP MIS needs to enroll a child for support without reading CRVS
or social registry rows.

Attestations:

- Birth Registration Attestation;
- Age Eligibility Attestation;
- Parent Or Guardian Link Attestation;
- Household Membership Attestation;
- Welfare Classification Attestation;
- optional Program Enrollment Attestation to check existing enrollment.

Required result:

- friendly case-file receipt;
- per-attestation source authority and match method;
- final SP MIS-local decision shown separately from source attestations.

### Scenario 2: Death-Triggered Benefit Review

Availability target: hosted after social registry Notary is hosted.

User story: an SP MIS receives evidence that a household member or spouse has
died and recalculates entitlement without repeatedly visiting the household.

Attestations:

- Vital Status Attestation or Death Registration Attestation;
- Household Composition Attestation;
- Program Enrollment Attestation;
- Entitlement Attestation.

Required result:

- before and after case summary;
- no cause of death disclosure;
- clear explanation that the SP MIS decides benefit recalculation.

### Scenario 3: Disability Top-Up

Availability target: hosted if the new assessment source is lightweight enough;
otherwise local with visible hosted disabled state.

User story: a benefit programme needs to add or review a disability top-up.

Attestations:

- Disability Determination Attestation;
- or Functioning Assessment Attestation with explicit caveat;
- Welfare Classification Attestation;
- Program Enrollment Attestation.

Required result:

- no diagnosis details;
- review due or validity shown;
- legal determination and functioning assessment clearly distinguished.

### Scenario 4: Health-Linked Support

Availability target: hosted.

User story: a programme checks health programme participation or service
availability without retrieving clinical records.

Attestations:

- Health Programme Participation Attestation from DHIS2 or health MIS;
- or Service Availability Attestation from facility/service source;
- Household Membership Attestation when the benefit is household-targeted.

Required result:

- no diagnosis disclosure;
- no misleading person-keyed facility registry copy;
- negative control for inactive programme participation.

### Scenario 5: Climate-Smart Farmer Voucher

Availability target: local first, hosted if operationally cheap.

User story: an agriculture or social protection service checks whether a farmer
can redeem a climate-smart input voucher.

Attestations:

- Farmer Registration Attestation;
- Farm Activity or Farm Holding Attestation;
- Agricultural Entitlement Attestation;
- Benefit Conflict Attestation for redeemed voucher or conflicting permit.

Required result:

- positive and negative controls;
- reason code or contributing facts;
- optional wallet credential preview.

### Scenario 6: Education-Linked Transfer

Availability target: deferred.

User story: a conditional cash transfer programme checks school enrollment and
attendance threshold.

Attestations:

- School Enrollment Attestation;
- Attendance Threshold Attestation;
- Age Eligibility Attestation;
- Parent Or Guardian Link Attestation.

This scenario should wait until the five scenarios above are credible.

## UX Requirements

Reuse the route and step model from `guided-demo-scenarios-and-data-plan.md`,
but change the narrative.

Every scenario page must show:

- SP MIS requirement;
- requested attestations;
- subject and requester context;
- lookup profile used;
- friendly result first;
- minimized claims;
- data not disclosed;
- proof metadata;
- raw request and response drawers;
- copy-as-curl;
- final SP MIS case-file receipt.

The scenario chooser at `/scenarios` must distinguish:

- hosted and runnable;
- local-only;
- planned;
- temporarily disabled because a source is not deployed.

## Implementation Plan

### Phase 0: Baseline And Naming Contract

- Add this spec and link it from `docs/README.md` and the root documentation
  map.
- Add a test or static check that public scenario labels use attestation names,
  not raw compatibility claim ids.
- Add a machine-readable attestation catalogue file if that is simpler than
  embedding labels in Python scenario modules.

Definition of done:

- docs linked;
- attestation terms visible in scenario metadata;
- no public first-level label says `person-is-alive`.

### Phase 1: Fixture Model Refresh

- Extend civil fixtures with civil records, birth events, death events,
  certificates, and relationships.
- Split social protection data into household membership, socio-economic
  profile, scoring event, enrollment, entitlement, and payment event.
- Reframe or remodel health service availability so source shape is not keyed
  by person.
- Add lightweight disability and functioning assessment data.
- Keep deterministic fixture generation.

Definition of done:

- fixture invariant tests cover positive, negative, ambiguous, stale, expired,
  and policy-denied personas;
- generated fixtures are deterministic;
- data model docs or inline fixture comments map source fields to PublicSchema
  anchors.

### Phase 2: Notary And Metadata Refresh

- Add or alias attestation offerings in civil, OpenCRVS, social protection,
  DHIS2, shared eligibility, and agriculture Notary configs.
- Include PublicSchema anchors and lookup profiles in public metadata.
- Keep existing claim ids as compatibility aliases where client scripts depend
  on them.
- Update service-first discovery so the user sees attestation offerings.

Definition of done:

- hosted metadata exposes serious attestation names;
- compatibility smoke checks still pass or are intentionally updated;
- each offering documents accepted lookup profiles.

### Phase 3: Hosted Core Scenarios

Implement hosted-ready scenarios first:

1. Child Benefit Application.
2. Health-Linked Support.
3. Citizen credential explorer with adult persona.

Then promote once social Notary is hosted:

4. Death-Triggered Benefit Review.
5. Disability Top-Up, if the new source is hosted.

Definition of done:

- all hosted scenarios call real hosted endpoints;
- local-only steps are disabled before execution;
- browser verification covers desktop and mobile.

### Phase 4: Local And Advanced Scenarios

- Implement agriculture voucher as local first unless hosted deployment is
  ready.
- Add education only after the main suite is stable.
- Keep shared eligibility composition as an SP MIS-local decision receipt, not
  as a source-owned truth.

Definition of done:

- local-only scenario label is accurate;
- positive and negative controls match fixtures;
- optional wallet preview does not expose private holder material.

## Verification

Run the closest practical verification for the implementation slice.

Required automated checks:

- fixture generation;
- fixture invariant tests;
- hosted deployment validation for hosted config changes;
- scenario payload tests;
- token and secret display policy tests;
- smoke client updates for renamed or aliased offerings;
- static check for public attestation labels.

Required manual checks:

- local browser run for every implemented scenario;
- hosted browser run for every hosted scenario;
- raw JSON drawers do not reveal runtime secrets;
- friendly output is understandable without reading JSON;
- unavailable hosted scenarios are visibly disabled or marked local-only.

Before marking the refresh complete, run `scripts/release-check.sh` or document
the exact skipped steps and reasons.

## Open Questions

- Should Notary configs support first-class `attestations`, or should Registry
  Lab maintain a public label/catalogue layer over existing `claims` until
  Registry Notary changes?
- Should the disability source be a separate Relay authority or a sheet inside
  the social registry workbook for the first demo?
- Should agriculture be promoted to hosted for UN OS Week, or kept as a strong
  local advanced story?
- Should `Family Quotient Attestation` be added as a France-like demonstration,
  or would that distract from the DCI/LMIC social registry story?

## Delivery Waves

Use parallel workers only for independent file or module areas. Workers must
not edit the same files at the same time, and each wave ends with a code-review
checkpoint before the next wave starts.

### Wave 0: Contract And Baseline

Parallel work:

- Worker A adds or updates docs links and confirms the terminology is
  consistent across public docs touched by this refresh.
- Worker B defines the attestation catalogue shape and static public-label
  check.
- Worker C records the current hosted and local scenario availability matrix.

Definition of done:

- `README.md` and `docs/README.md` link this spec.
- The static label check fails on at least one seeded raw id fixture or test
  case.
- The availability matrix names each scenario as hosted, local-only, planned,
  or blocked.

Code-review checkpoint:

- Review the catalogue fields, blocked-scenario labels, and static check before
  any fixture or scenario implementation begins.

### Wave 1: Fixture Model Refresh

Parallel work:

- Worker A owns civil fixtures: persons, identifiers, civil records, birth
  events, death events, certificates, and relationships.
- Worker B owns social fixtures: households, group memberships,
  socio-economic profiles, scoring events, programs, enrollments,
  entitlements, and payment events.
- Worker C owns health and disability fixtures: service availability or
  programme participation, functioning profiles, scoring events, and disability
  determinations.

Definition of done:

- `just generate` or the repo-equivalent fixture generation command produces
  deterministic outputs with no unrelated generated files committed.
- Fixture invariant tests pass for named positive, negative, ambiguous, stale,
  expired, and policy-denied personas.
- Health fixtures no longer present a normal facility registry as keyed by
  `national_id`; any compatibility projection is named
  `ApplicantServiceAvailabilityProjection`.

Code-review checkpoint:

- Review fixture diffs and invariant tests. Reject the wave if any scenario
  outcome depends on undocumented fixture assumptions.

### Wave 2: Attestation Metadata And Notary Configs

Parallel work:

- Worker A owns civil and OpenCRVS attestation aliases and PublicSchema
  metadata.
- Worker B owns social, shared eligibility, and programme lifecycle
  attestation aliases.
- Worker C owns DHIS2, health, disability, and agriculture attestation aliases.

Definition of done:

- Every implemented offering exposes display name, lookup profiles,
  PublicSchema anchors, disclosure profile, freshness fields, and compatibility
  aliases.
- Smoke tests or focused Notary tests pass for old compatibility ids and new
  public attestation labels.
- Service-first discovery returns attestation-facing metadata for implemented
  offerings.

Code-review checkpoint:

- Review metadata output and compatibility behavior before scenario UI work.
  No old client may break unless the diff updates its tests and docs.

### Wave 3: Hosted Core Scenarios

Parallel work:

- Worker A implements Child Benefit Application.
- Worker B implements Health-Linked Support.
- Worker C updates the citizen credential explorer labels and proof display to
  match the attestation vocabulary.

Definition of done:

- Hosted steps call real hosted endpoints and have mocked unit tests.
- Each scenario page shows requirement, attestations, lookup profile, minimized
  claims, non-disclosure statement, proof metadata, raw drawers, curl, and
  case-file receipt.
- Desktop and mobile browser checks pass for each hosted scenario.

Code-review checkpoint:

- Review browser evidence, friendly copy, raw drawers, and secret redaction.
  No scenario is marked runnable until hosted execution succeeds.

### Wave 4: Cross-Registry And Local Advanced Scenarios

Parallel work:

- Worker A implements Death-Triggered Benefit Review after hosted social
  attestations are available.
- Worker B implements Disability Top-Up after the disability or functioning
  source exists.
- Worker C implements Agriculture Voucher as hosted or clearly local-only.

Definition of done:

- Blocked prerequisites are enforced in the scenario chooser before execution.
- Positive and negative controls pass for each implemented scenario.
- Death review separates vital status, household composition, enrollment, and
  entitlement.
- Disability top-up separates legal determination from functioning assessment.
- Agriculture is either hosted-runnable or local-only with tested local flow.

Code-review checkpoint:

- Review source authority boundaries and SP MIS-local decision receipts. No
  composed eligibility result is presented as a source-owned fact.

### Wave 5: End-To-End Hardening

Parallel work:

- Worker A runs automated verification and fixes test-only gaps.
- Worker B performs local desktop and mobile browser verification.
- Worker C performs hosted browser verification and hosted deployment
  validation.

Definition of done:

- Required automated checks in this spec pass.
- Browser verification records exist for every implemented local and hosted
  scenario.
- Local-only, planned, and blocked scenarios are accurately labeled in hosted
  mode.
- `scripts/release-check.sh` passes, or the final report lists exact skipped
  commands and the refresh remains incomplete.

Code-review checkpoint:

- Final review compares the diff against the top-level Definition Of Done.
  Remove or disable any feature that lacks tests, browser verification, or
  accurate hosted availability labeling.
