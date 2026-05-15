# data_gate Demo Pack Spec

## Purpose

Create a small set of realistic government demo datasets that show `data_gate` as a controlled data reuse gateway, not an open-data portal and not a generic spreadsheet API.

The demos should help a reviewer understand:

- how private storage tables become public domain entities;
- how row, metadata, aggregate, verify, and admin scopes stay independent (`bulk_export` is a reserved future scope and is not emitted in V1 demo configs);
- how sensitive fields can exist in source spreadsheets without being exposed through public entity projections;
- how purpose headers, relationship expansion, verify-only lookups, required-filter entities, and disclosure-controlled aggregates work;
- how cross-dataset personal-data reuse is coordinated through a subject registry that holds opaque canonical ids and per-dataset aliases without centralizing personal data;
- how a Bruno collection can exercise expected and denied flows without requiring custom scripts.

## Deliverables

Add a demo pack under the repository root:

```text
demo/
  README.md
  config/
    all_demos.yaml
    benefits_casework.yaml
    clinic_capacity.yaml
    public_works_projects.yaml
    education_registry.yaml
    subject_registry.yaml
  data/
    benefits_casework.xlsx
    clinic_capacity.xlsx
    public_works_projects.xlsx
    education_registry.xlsx
    subject_registry.xlsx
  scripts/
    generate_demo_data.py
    generate_demo_keys.py
bruno/
  data_gate_demo/
    bruno.json
    environments/
      local.bru
    Health/
    Catalog/
    Datasets/
    Benefits Casework/
    Clinic Capacity/
    Public Works Projects/
    Education Registry/
    Subject Registry/
    Cross-Demo Workflows/
    Auth Boundaries/
```

The exact Bruno folder spelling may follow Bruno conventions, but the collection should remain grouped by capability and dataset.

## Global Demo Conventions

- All source data must be synthetic and safe to commit.
- Synthetic records must not contain real names, real national identifiers, real addresses, real phone numbers, real emails, or data copied from production systems.
- Use obviously fake stable identifiers such as `hh-1001`, `per-2001`, `stu-2001`, `gua-2501`, `sch-3001`, `fac-4001`, `prj-5001`, and `sub-9001`.
- Use a shared fictional geography across all demos so they can be read together: `north`, `central`, `riverbend`, `highlands`, `coast`, and `south`.
- Use shared reporting periods where useful: school year `2026`, fiscal year `FY2026`, and monthly periods such as `2026-01`.
- Each workbook should contain 50 to 300 rows per primary sheet. Keep files small enough for fast local startup and easy review.
- Each config should use `source.type: file`, `refresh.mode: manual`, and `audit.sink: stdout`. The combined config may route `subject_registry` audit to a file sink so linkage calls are visibly logged during the demo walkthrough.
- Every dataset should declare strict schemas and public entity field projections.
- Sensitive source columns may be present in workbook sheets, but must be omitted from public `entities[].fields` unless explicitly needed for a controlled demo flow.
- Row or verify endpoints for personal data must set `require_purpose_header: true`. The same applies to row endpoints on `subject_registry`.
- Aggregates must declare disclosure control explicitly, and each dataset's `min_group_size` choice must carry a one-line rationale in the config (a YAML comment is fine) so the per-dataset value is defensible at review time.
- The generator uses a single seeded RNG and asserts that the produced data exercises disclosure control visibly: every cross-tab aggregate must produce at least one suppressed and one shown group, and at least one masked measure where masking is configured. This is what makes the disclosure-control demo deterministic instead of accidentally clean.
- Config examples must use placeholder `hash_env` names only. Do not commit API keys or Argon2 PHC hashes. A `demo/scripts/generate_demo_keys.py` helper must exist that emits the env vars a reviewer needs for a local run; without it, first-time setup gets stuck on key hashing.
- `<dataset>:bulk_export` is a contract-reserved scope. Each entity must declare a `bulk_export_scope` string per the platform schema (it's a required field), but no key in any V1 demo config's access block should be granted that scope. The Bruno collection does not include any bulk-export request; the README documents the absence.

## Required Filters

Some entities must not be listable without a discriminating filter. Their `entities[].filters` block declares a `required_any_of` set; a row read that supplies none of those filters returns `400` with the error code `entity.filter_required`. This prevents bulk enumeration of sensitive entities where unfiltered list would defeat governance.

Required-filter applies to:

- `subject_registry.subject`: at least one of `canonical_id`, `benefits_person_alias`, `benefits_household_alias`, `education_student_alias`, `education_guardian_alias`.
- `benefits_casework.person`: at least one of `id`, `household_id`, or `eligibility_status`.
- `education_registry.student`: at least one of `id`, `school_id`, or `home_district`.

This is a data_gate platform prerequisite, not a demo-only feature. If `required_any_of` does not yet exist in the entity filter spec, the subject-registry section is blocked on adding it. The semantics are simple and useful beyond the demos.

## Imperfect Data Rules

The demos should feel like real government administrative data: useful, governed, and a bit uneven. Do not make the synthetic world too clean.

The source files may include:

- nullable optional fields such as `closed_on`, `paid_on`, `exited_on`, `completed_on`, and `assessment_date`;
- stale statuses such as an `active` enrollment with no recent attendance summary;
- old district labels in hidden notes while public fields use normalized district codes;
- orphan-like operational records that are valid rows but no longer line up with current business state, for example a closed project with one pending disbursement;
- uneven group sizes so disclosure control visibly suppresses or masks some aggregate groups;
- missing optional relationship rows, for example a student with no current support need or a facility with no stockout event;
- duplicate human-readable names across different entities, while identifiers remain unique.

The files must still satisfy strict schema validation. Messiness should be domain messiness, not broken headers, invalid dates, unsupported types, or malformed workbooks.

## Shared Demo Universe

The four demos should be independently runnable, but they should also tell one joined-up government reuse story. V1 relationships are scoped to entities inside one dataset, so cross-dataset reuse is demonstrated through client-side workflows in Bruno rather than config-level foreign keys.

Shared concepts:

| Concept | Used by |
| --- | --- |
| District codes | All datasets |
| School ids such as `sch-3001` | Education registry and public works school projects |
| Facility ids such as `fac-4001` | Clinic capacity and public works clinic projects |
| Reporting periods | Benefits payments, clinic capacity, public works disbursements, attendance summaries |
| Program support categories | Benefits cases and education support needs |
| Subject canonical ids such as `sub-9001` and per-dataset aliases | Subject registry, benefits casework, education registry |

Cross-demo Bruno scenarios:

- District planning: run benefits poverty aggregates, education enrollment aggregates, clinic capacity aggregates, and public works project status aggregates for the same district.
- School construction follow-up: read a public works project with `asset_type=school` and `asset_ref=sch-3001`, then read the matching education `school` record and enrollment aggregate. Note: `asset_ref` is a client-side soft pointer, not a system-enforced foreign key; the subject registry below is what makes person-level cross-dataset reuse safe.
- Clinic rehabilitation follow-up: read a public works project with `asset_type=facility` and `asset_ref=fac-4001`, then read the matching clinic `facility` and service capacity records.
- Scholarship eligibility with subject linkage: verify a student in `education_registry`, then read one subject row from `subject_registry` filtered by the student alias to obtain the matching benefits household alias, then read that household and run district-level benefits aggregates. Demonstrates that linkage is itself a controlled scope, separate from reading either underlying dataset.
- Emergency planning: combine clinic stockout aggregates, district-level benefits household counts, and public works road or facility project status for one district.

These flows should be explicit in Bruno request descriptions. They are allowed to be a little manual: the point is to show how controlled APIs compose in the real world, where one consumer often makes several scoped calls instead of receiving one giant joined extract. The subject registry is the only place where personal-data identifiers from two datasets are knowingly tied together, and it is gated by a dedicated key persona.

## Shared API Keys And Scopes

Each demo config should include key entries that show least-privilege consumers:

| Key id | Intended scopes |
| --- | --- |
| `catalog_viewer` | Metadata scopes only |
| `planning_analyst` | Metadata and aggregate scopes |
| `casework_system` | Metadata, row, verify, and selected aggregate scopes for personal datasets, plus row scopes on non-personal operational datasets (clinic capacity, public works) where cross-demo follow-ups need them. Explicitly no `subject_registry:rows`: the registry stays linkage-service only. |
| `verification_service` | Verify scopes only |
| `linkage_service` | `subject_registry:metadata`, `subject_registry:rows`, `subject_registry:aggregate` only. The sole persona authorized to resolve cross-dataset subject linkages. No row access to benefits or education. |
| `operations_admin` | `admin` only, plus metadata only if a demo request needs dataset discovery |

Use dataset-specific scope names:

```text
<dataset>:metadata
<dataset>:aggregate
<dataset>:rows
<dataset>:verify
```

`<dataset>:bulk_export` is contract-reserved for a future version. Each entity must still declare a `bulk_export_scope` string per the platform schema (it's a required field), but no key in V1 demo configs should be granted that scope. The Bruno collection contains no bulk-export request; the README documents that the surface is unimplemented in V1.

## Demo 1: Benefits Casework

### Reuse Story

A social protection ministry owns household, person, benefit case, and payment data. Other government systems need controlled access for eligibility checks, grievance follow-up, reconciliation, and planning aggregates.

This demo is intentionally personal and relationship-rich.

### Dataset

- Dataset id: `benefits_casework`
- Sensitivity: `personal`
- Access rights: `restricted`
- Update frequency: `monthly`
- Source file: `demo/data/benefits_casework.xlsx`

### Workbook Sheets

`Households`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `household_id` | string | yes | primary key |
| `district` | string | yes | stable filter |
| `municipality` | string | yes | stable filter |
| `household_size` | number | yes | aggregate-safe |
| `poverty_band` | string | yes | codelist |
| `enrollment_status` | string | yes | codelist |
| `enrolled_on` | date | yes | range filter |
| `address_line` | string | no | sensitive |
| `case_notes` | string | no | sensitive free text |

`Persons`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `person_id` | string | yes | primary key |
| `household_id` | string | yes | foreign key |
| `age_band` | string | yes | avoid exact age in demo output |
| `sex` | string | yes | codelist |
| `disability_status` | string | yes | controlled categorical field |
| `benefit_role` | string | yes | applicant, member, payee |
| `eligibility_status` | string | yes | verify and filter use case |
| `full_name` | string | no | sensitive |
| `national_id` | string | no | sensitive |
| `phone` | string | no | sensitive |

`Cases`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `case_id` | string | yes | primary key |
| `household_id` | string | yes | foreign key |
| `case_type` | string | yes | appeal, recertification, grievance |
| `case_status` | string | yes | codelist |
| `opened_on` | date | yes | range filter |
| `closed_on` | date | yes | nullable |
| `priority` | string | yes | codelist |
| `caseworker_notes` | string | no | sensitive free text |

`Payments`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `payment_id` | string | yes | primary key |
| `household_id` | string | yes | foreign key |
| `cycle` | string | yes | month or period |
| `payment_status` | string | yes | codelist |
| `amount` | number | yes | unit `USD` or neutral demo currency |
| `paid_on` | date | yes | nullable |
| `payment_channel` | string | yes | codelist |
| `bank_account_hint` | string | no | sensitive |

### Public Entities

- `household`
  - Relationships: `members` has many `person`, `cases` has many `case`, `payments` has many `payment`
  - Filters: `id`, `district`, `municipality`, `poverty_band`, `enrollment_status`, `enrolled_on`
- `person`
  - Relationships: `household` belongs to `household`
  - Filters: `id`, `household_id`, `age_band`, `sex`, `disability_status`, `eligibility_status`
  - Purpose header required
- `case`
  - Relationships: `household` belongs to `household`
  - Filters: `id`, `household_id`, `case_type`, `case_status`, `opened_on`, `priority`
  - Purpose header required
- `payment`
  - Relationships: `household` belongs to `household`
  - Filters: `id`, `household_id`, `cycle`, `payment_status`, `paid_on`
  - Purpose header required

### Aggregates

- `person.by_district_age_band`: count persons by household district and age band, joined through household.
- `case.by_status_priority`: count cases by status and priority.
- `payment.by_district_cycle`: sum and average payment amount by district and cycle, joined through household.
- `household.by_poverty_band`: count households by district and poverty band.

Use `min_group_size: 5`. Use `omit` for person and case counts, and `mask` for payment measures.

### Bruno Requests

- list visible datasets with a metadata key;
- read `household/schema`;
- filter households by `district`;
- read one household with `expand=members`;
- verify `person?id=per-2001` with `X-Data-Purpose`;
- run `payment/aggregates/by_district_cycle`;
- demonstrate that a verify-only key cannot read `person/schema` or `person` rows;
- demonstrate that missing `X-Data-Purpose` fails for `person/verify`.

## Demo 2: Clinic Capacity

### Reuse Story

A health ministry publishes restricted operational data about facilities, services, stock events, and monthly capacity. Emergency planners and supply teams need reuse without patient-level data.

This demo is operational rather than personal.

### Dataset

- Dataset id: `clinic_capacity`
- Sensitivity: `confidential`
- Access rights: `restricted`
- Update frequency: `weekly`
- Source file: `demo/data/clinic_capacity.xlsx`

### Workbook Sheets

`Facilities`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `facility_id` | string | yes | primary key |
| `facility_name` | string | yes | synthetic facility names |
| `district` | string | yes | filter |
| `facility_type` | string | yes | clinic, hospital, health_post |
| `ownership` | string | yes | public, private, mission |
| `service_level` | string | yes | codelist |
| `latitude_band` | string | yes | coarse location only |
| `longitude_band` | string | yes | coarse location only |
| `exact_latitude` | number | no | operationally sensitive |
| `exact_longitude` | number | no | operationally sensitive |

`ServiceCapacity`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `capacity_id` | string | yes | primary key |
| `facility_id` | string | yes | foreign key |
| `service_type` | string | yes | maternal, emergency, vaccination |
| `month` | string | yes | reporting period |
| `beds_available` | number | yes | aggregate |
| `staff_on_roster` | number | yes | aggregate |
| `open_days` | number | yes | aggregate |
| `internal_roster_notes` | string | no | sensitive |

`StockEvents`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `stock_event_id` | string | yes | primary key |
| `facility_id` | string | yes | foreign key |
| `medicine_code` | string | yes | codelist |
| `event_month` | string | yes | filter |
| `stock_status` | string | yes | in_stock, low_stock, stockout |
| `days_stocked_out` | number | yes | aggregate |
| `supplier_comment` | string | no | sensitive |

### Public Entities

- `facility`
  - Relationships: `service_capacity` has many `service_capacity`, `stock_events` has many `stock_event`
  - Filters: `id`, `district`, `facility_type`, `ownership`, `service_level`
- `service_capacity`
  - Relationships: `facility` belongs to `facility`
  - Filters: `id`, `facility_id`, `service_type`, `month`
- `stock_event`
  - Relationships: `facility` belongs to `facility`
  - Filters: `id`, `facility_id`, `medicine_code`, `event_month`, `stock_status`

### Aggregates

- `facility.by_district_type`: count facilities by district and type.
- `service_capacity.by_district_service`: sum beds and staff by district and service type.
- `stock_event.by_medicine_status`: count events and sum stockout days by medicine and status.

Use `min_group_size: 3`. This dataset does not require purpose headers for rows because it has no person-level records.

### Bruno Requests

- read catalog and DCAT metadata;
- filter facilities by `district`;
- read one facility with `expand=service_capacity`;
- run service capacity aggregate by district and service;
- run stock event aggregate by medicine and status;
- demonstrate aggregate-only key cannot read facility rows.

## Demo 3: Public Works Projects

### Reuse Story

A delivery unit tracks infrastructure projects, contracts, milestones, and disbursements. Finance, planning, audit, and local government users need controlled consultation and aggregate oversight.

This demo is non-personal but politically and commercially sensitive.

### Dataset

- Dataset id: `public_works_projects`
- Sensitivity: `confidential`
- Access rights: `non_public`
- Update frequency: `monthly`
- Source file: `demo/data/public_works_projects.xlsx`

### Workbook Sheets

`Projects`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `project_id` | string | yes | primary key |
| `project_name` | string | yes | synthetic |
| `sector` | string | yes | roads, water, schools, clinics |
| `district` | string | yes | filter |
| `asset_type` | string | yes | school, facility, road, water_point, admin_building |
| `asset_ref` | string | yes | may match `school.id` or `facility.id` in another demo |
| `implementing_agency` | string | yes | synthetic |
| `project_status` | string | yes | codelist |
| `start_date` | date | yes | range filter |
| `planned_end_date` | date | yes | range filter |
| `risk_rating` | string | yes | codelist |
| `internal_risk_notes` | string | no | sensitive free text |

`Contracts`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `contract_id` | string | yes | primary key |
| `project_id` | string | yes | foreign key |
| `contractor_ref` | string | yes | stable synthetic reference |
| `procurement_method` | string | yes | codelist |
| `contract_status` | string | yes | codelist |
| `contract_value` | number | yes | aggregate |
| `signed_on` | date | yes | filter |
| `contractor_bank_ref` | string | no | sensitive |

`Milestones`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `milestone_id` | string | yes | primary key |
| `project_id` | string | yes | foreign key |
| `milestone_name` | string | yes | synthetic |
| `milestone_status` | string | yes | codelist |
| `due_date` | date | yes | range filter |
| `completed_on` | date | yes | nullable |
| `delay_reason` | string | yes | controlled codelist |
| `site_observation_notes` | string | no | sensitive free text |

`Disbursements`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `disbursement_id` | string | yes | primary key |
| `project_id` | string | yes | foreign key |
| `contract_id` | string | yes | foreign key |
| `fiscal_year` | string | yes | filter |
| `quarter` | string | yes | filter |
| `amount` | number | yes | aggregate |
| `payment_status` | string | yes | codelist |
| `invoice_ref` | string | no | commercially sensitive |

### Public Entities

- `project`
  - Relationships: `contracts`, `milestones`, `disbursements`
  - Filters: `id`, `sector`, `district`, `asset_type`, `asset_ref`, `project_status`, `risk_rating`, `start_date`, `planned_end_date`
- `contract`
  - Relationships: `project`
  - Filters: `id`, `project_id`, `procurement_method`, `contract_status`, `signed_on`
- `milestone`
  - Relationships: `project`
  - Filters: `id`, `project_id`, `milestone_status`, `due_date`, `delay_reason`
- `disbursement`
  - Relationships: `project`, `contract`
  - Filters: `id`, `project_id`, `contract_id`, `fiscal_year`, `quarter`, `payment_status`

### Aggregates

- `project.by_sector_status`: count projects by sector and status.
- `contract.by_district_procurement`: count contracts and sum contract value by project district and procurement method.
- `milestone.by_status_delay_reason`: count milestones by status and delay reason.
- `disbursement.by_fiscal_year_quarter`: sum and average disbursement amount by fiscal year and quarter.

Use `min_group_size: 2` for this demo so small synthetic groups still show results. Use `mask` for money measures and `omit` for status counts.

### Bruno Requests

- filter projects by sector and status;
- filter projects by `asset_type=school` or `asset_ref=sch-3001`, then follow the cross-demo scenario in the Education Registry folder;
- read one project with `expand=milestones`;
- run contract aggregate joined to project district;
- run disbursement aggregate by fiscal period;
- demonstrate metadata-only access to schema without row access.

## Demo 4: Education Student Registry

### Reuse Story

An education ministry operates a student registry. Scholarship, school meals, transport, identity, and district planning systems need controlled reuse. The demo should show student-level personal data governance while still being useful for aggregate education planning.

This demo should be a student registry, but not a raw exposure of all student data.

### Dataset

- Dataset id: `education_registry`
- Sensitivity: `personal`
- Access rights: `restricted`
- Update frequency: `termly`
- Source file: `demo/data/education_registry.xlsx`

### Workbook Sheets

`Students`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `student_id` | string | yes | primary key |
| `school_id` | string | yes | foreign key |
| `current_enrollment_id` | string | yes | foreign key |
| `date_of_birth` | date | no | use `age_band` publicly |
| `age_band` | string | yes | public substitute for date of birth |
| `sex` | string | yes | codelist |
| `grade_level` | string | yes | filter |
| `enrollment_status` | string | yes | filter and verify use case |
| `home_district` | string | yes | filter |
| `language_group` | string | yes | aggregate |
| `disability_status` | string | yes | controlled categorical field |
| `scholarship_eligible` | boolean | yes | verify and filter use case |
| `student_name` | string | no | sensitive |
| `national_id` | string | no | sensitive |
| `home_address` | string | no | sensitive |
| `guardian_phone` | string | no | sensitive |
| `student_notes` | string | no | sensitive free text |

`Guardians`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `guardian_id` | string | yes | primary key |
| `student_id` | string | yes | foreign key |
| `relationship` | string | yes | parent, caregiver, other |
| `contact_verified` | boolean | yes | controlled reuse |
| `guardian_name` | string | no | sensitive |
| `phone` | string | no | sensitive |
| `email` | string | no | sensitive |
| `address` | string | no | sensitive |

`Schools`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `school_id` | string | yes | primary key |
| `school_name` | string | yes | synthetic |
| `district` | string | yes | filter |
| `school_type` | string | yes | public, private, community |
| `education_level` | string | yes | primary, lower_secondary, upper_secondary |
| `has_meal_program` | boolean | yes | planning field |
| `has_accessibility_support` | boolean | yes | planning field |

`Enrollments`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `enrollment_id` | string | yes | primary key |
| `student_id` | string | yes | foreign key |
| `school_id` | string | yes | foreign key |
| `school_year` | string | yes | filter |
| `grade_level` | string | yes | filter |
| `status` | string | yes | active, transferred, completed, withdrawn |
| `enrolled_on` | date | yes | range filter |
| `exited_on` | date | yes | nullable |

`SupportNeeds`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `support_need_id` | string | yes | primary key |
| `student_id` | string | yes | foreign key |
| `support_type` | string | yes | scholarship, transport, assistive_device, meals |
| `eligibility_status` | string | yes | pending, eligible, not_eligible |
| `assessment_date` | date | yes | range filter |
| `active` | boolean | yes | filter |
| `assessment_notes` | string | no | sensitive free text |

`AttendanceSummary`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `attendance_id` | string | yes | primary key |
| `student_id` | string | yes | foreign key |
| `school_year` | string | yes | filter |
| `term` | string | yes | filter |
| `attendance_rate` | number | yes | aggregate |
| `chronic_absence_flag` | boolean | yes | aggregate and filter |

### Public Entities

- `student`
  - Relationships: `school` belongs to `school`, `guardians` has many `guardian`, `enrollments` has many `enrollment`, `support_needs` has many `support_need`, `attendance_summaries` has many `attendance_summary`
  - Filters: `id`, `school_id`, `grade_level`, `enrollment_status`, `home_district`, `scholarship_eligible`
  - Purpose header required
- `guardian`
  - Relationships: `student` belongs to `student`
  - Filters: `id`, `student_id`, `relationship`, `contact_verified`
  - Purpose header required
- `school`
  - Relationships: `students`, `enrollments`
  - Filters: `id`, `district`, `school_type`, `education_level`, `has_meal_program`
- `enrollment`
  - Relationships: `student`, `school`
  - Filters: `id`, `student_id`, `school_id`, `school_year`, `grade_level`, `status`, `enrolled_on`
  - Purpose header required
- `support_need`
  - Relationships: `student`
  - Filters: `id`, `student_id`, `support_type`, `eligibility_status`, `assessment_date`, `active`
  - Purpose header required
- `attendance_summary`
  - Relationships: `student`
  - Filters: `id`, `student_id`, `school_year`, `term`, `chronic_absence_flag`
  - Purpose header required

### Aggregates

- `student.by_school_grade_status`: count students by school, grade, and enrollment status.
- `student.by_district_language`: count students by home district and language group.
- `support_need.by_type_district`: count support needs by support type and student home district.
- `attendance_summary.by_school_term`: average attendance rate and count chronic absence flags by school and term, joined through student.
- `school.by_district_meal_program`: count schools by district and meal program status.

Use `min_group_size: 5`. Use `omit` for student and support counts, and `mask` for attendance measures.

### Bruno Requests

- read `student/schema`;
- filter students by `school_id` and `grade_level` with `X-Data-Purpose`;
- read one student with `expand=school`;
- read one student guardians relationship;
- verify `student?id=stu-2001` with `X-Data-Purpose`;
- run `student/aggregates/by_school_grade_status`;
- run `support_need/aggregates/by_type_district`;
- demonstrate that a planning aggregate key cannot read student rows;
- demonstrate that a verify-only key cannot read schema, rows, or aggregates.

## Demo 5: Subject Registry

### Reuse Story

A government identity coordination function holds the canonical mapping between subject identifiers used by different administrative datasets. The registry contains no personal data: only opaque canonical ids (`sub-9001`) and the per-dataset aliases that point to the same human. Authorized linkage callers can ask "given alias X in dataset Y, what is the canonical id and what aliases does the same human have in other datasets?", scoped, purpose-tagged, and audited per call.

The dataset's whole sensitivity is the linkage itself: a holder of `subject_registry:rows` who can list every row holds the full join table between benefits and education subjects. The `subject` entity therefore declares required filters: any row read must filter by canonical id or by at least one alias, so the caller must already hold one identifier to learn the others. Unfiltered list is not permitted.

This demo demonstrates centralized linkage without centralized personal data, and shows linkage governance as a first-class API scope rather than an implicit join inside a downstream consumer's database.

### Dataset

- Dataset id: `subject_registry`
- Sensitivity: `confidential` (no PII, but the linkage is sensitive)
- Access rights: `restricted`
- Update frequency: `as_needed`
- Source file: `demo/data/subject_registry.xlsx`

### Workbook Sheets

`Subjects`

| Column | Type | Public? | Notes |
| --- | --- | --- | --- |
| `canonical_id` | string | yes | primary key, opaque, e.g. `sub-9001` |
| `benefits_person_alias` | string | yes | nullable, e.g. `per-2001` |
| `benefits_household_alias` | string | yes | nullable, e.g. `hh-1001` |
| `education_student_alias` | string | yes | nullable, e.g. `stu-2001` |
| `education_guardian_alias` | string | yes | nullable, e.g. `gua-2501` |
| `linkage_method` | string | yes | codelist: deterministic, probabilistic, manual |
| `linkage_confidence` | string | yes | codelist: high, medium, low |
| `linked_on` | date | yes | when linkage was asserted |
| `internal_match_score` | number | no | sensitive raw match score |
| `match_notes` | string | no | sensitive free-text reviewer notes |

Most rows have non-null aliases for one or two datasets, not all four. Realistic overlap is approximately one third of benefits persons matched to an education student; the remainder appear in one dataset only. This is enforced by the generator, not left to chance.

### Public Entities

- `subject`
  - Relationships: none. The registry deliberately does not expand into personal datasets; cross-dataset composition stays client-side and audited per call.
  - Filters: `canonical_id`, `benefits_person_alias`, `benefits_household_alias`, `education_student_alias`, `education_guardian_alias`, `linkage_method`, `linkage_confidence`
  - Required filters (`required_any_of`): `canonical_id`, `benefits_person_alias`, `benefits_household_alias`, `education_student_alias`, `education_guardian_alias`
  - Purpose header required

### Aggregates

- `subject.by_linkage_method_confidence`: count subjects by linkage method and confidence band. Aggregate output exposes only governance metadata about the linkage process, not population characteristics.

Use `min_group_size: 5`. Rationale: the linkage table is the most sensitive surface in the demo pack; small groups even in procedural aggregates risk pinpointing individuals across datasets.

### Bruno Requests

- read `subject/schema` with the linkage key;
- attempt to read `subject` with no filters using the linkage key and expect `400 entity.filter_required`;
- read one `subject` filtered by `?education_student_alias={{studentAlias}}` with `X-Data-Purpose` and observe the matching benefits aliases in the row body;
- read one `subject` filtered by `?canonical_id={{canonicalId}}` and confirm the same row is returned;
- run `subject/aggregates/by_linkage_method_confidence` with the planning key;
- demonstrate that `casework_system` cannot read `subject` rows (missing `subject_registry:rows` scope returns 403);
- demonstrate that missing `X-Data-Purpose` on a `subject` row read returns `auth.purpose_required`;
- demonstrate that a verify-only key cannot read `subject` rows, schema, or aggregates.

## Bruno Collection Requirements

The Bruno collection should be usable against a local server started from any one single-dataset demo config. The `Cross-Demo Workflows` folder should target `demo/config/all_demos.yaml`, where all four datasets are loaded together.

Environment variables:

| Variable | Purpose |
| --- | --- |
| `baseUrl` | default `http://127.0.0.1:4242` |
| `metadataKey` | raw key for metadata-only calls |
| `aggregateKey` | raw key for aggregate calls |
| `rowsKey` | raw key for row and relationship calls |
| `verifyKey` | raw key for verify-only calls |
| `linkageKey` | raw key for the `linkage_service` persona, used to read `subject_registry` rows |
| `adminKey` | raw key for admin reload calls |
| `purpose` | default demo purpose, for example `demo-review` |
| `district` | default shared district, for example `riverbend` |
| `schoolId` | default cross-demo school id, for example `sch-3001` |
| `facilityId` | default cross-demo facility id, for example `fac-4001` |
| `studentAlias` | default cross-demo student alias, for example `stu-2001` |
| `benefitsPersonAlias` | default cross-demo benefits person alias, for example `per-2001` |
| `canonicalId` | default cross-demo subject canonical id, for example `sub-9001` |

Each protected request should set either:

```http
Authorization: Bearer {{rowsKey}}
```

or the correct least-privilege equivalent for the scenario.

Requests that touch personal row or verify endpoints should include:

```http
X-Data-Purpose: {{purpose}}
```

The `Auth Boundaries` folder should include negative checks for:

- missing credential returns 401;
- wrong scope returns 403;
- missing purpose header returns `auth.purpose_required`;
- verify-only key can call verify but cannot read rows, schema, or aggregates;
- aggregate-only key can run aggregates but cannot read rows;
- linkage key can read `subject_registry` rows but cannot read benefits or education rows;
- `casework_system` cannot read `subject_registry` rows;
- unfiltered row read on `subject_registry.subject`, `benefits_casework.person`, or `education_registry.student` returns `400 entity.filter_required`.

The `Cross-Demo Workflows` folder should include request sequences for:

- district planning across all four operational datasets using the same `district` value;
- school construction follow-up using public works `asset_ref={{schoolId}}` and education `school/{{schoolId}}`, with a note that `asset_ref` is a client-side soft pointer and not a system-enforced foreign key;
- clinic rehabilitation follow-up using public works `asset_ref={{facilityId}}` and clinic `facility/{{facilityId}}`;
- scholarship eligibility with subject linkage: verify `student?id={{studentAlias}}`, then `subject_registry/subject?education_student_alias={{studentAlias}}` to obtain the matching `benefits_household_alias`, then read that household and run benefits district aggregates. Each call uses a different key persona; all three audit entries are visible in the file sink configured for the combined config.
- emergency planning: clinic `stock_event/aggregates/by_medicine_status` with the planning key, then benefits `person/aggregates/by_district_age_band` to size the affected population per district, then public works `project?district={{district}}&project_status=delayed` with the rows key to surface road or facility projects that compound the emergency. Three personas, three audit entries, one composite picture, no single key with broad access.

## README Requirements

`demo/README.md` should explain:

- what each demo dataset represents, including the subject registry's role as a linkage governance surface;
- how to generate or refresh synthetic spreadsheets, and how the generator coordinates aliases across datasets so registry rows resolve to real rows in benefits and education;
- how to set `DATAGATE_CONFIG` or pass `--config`;
- how to run `demo/scripts/generate_demo_keys.py` to produce the env vars (Argon2 PHC hashes plus raw keys) the reviewer needs for a local run, including a separate `linkageKey`;
- how to open the Bruno collection and choose the local environment;
- how to walk through the scholarship eligibility cross-demo flow end-to-end and where to find the audit entries in the configured file sink;
- which current V1 surfaces are intentionally unavailable, especially bulk export and registry-wide admin reload.

The README must not include real API keys, PHC hashes, secrets, or production-looking personal data.

## Acceptance Criteria

- Five demo configs load successfully with `config::load` and pass validator checks: the four domain demos plus `subject_registry.yaml`.
- The combined `all_demos.yaml` config loads successfully with all five datasets and routes `subject_registry` audit to a file sink.
- Five source workbooks are generated deterministically by `demo/scripts/generate_demo_data.py` from a single seeded RNG, and the generator asserts that disclosure-control aggregates produce a mix of suppressed, masked, and shown groups.
- The generator coordinates aliases across files: every non-null alias column in `subject_registry.Subjects` resolves to an existing row in the referenced demo's primary sheet, and overlap is realistic (not full join).
- Public entity fields never expose columns marked non-public in this spec.
- Personal-data row and verify endpoints require `X-Data-Purpose`; `subject_registry` row reads do too.
- Required filters are enforced on `subject_registry.subject`, `benefits_casework.person`, and `education_registry.student`; unfiltered reads return `400 entity.filter_required`.
- Each dataset's `min_group_size` choice has a one-line rationale documented in its config.
- `<dataset>:bulk_export` does not appear in any V1 config's key access blocks.
- At least one request per dataset demonstrates a relationship expansion or nested relationship endpoint (`subject_registry` is exempt: it intentionally has no relationships).
- At least one aggregate per dataset uses a relationship join (`subject_registry` is exempt for the same reason).
- At least three Bruno requests demonstrate cross-dataset reuse through shared district, school, facility, or reporting-period values, and at least one cross-demo flow uses `subject_registry` to compose benefits and education for the same human.
- `casework_system` cannot read `subject_registry` rows; `linkage_service` cannot read benefits or education rows. Both negative cases are exercised in Bruno.
- Demo data includes realistic domain messiness while still passing strict schema validation.
- Bruno has positive and negative requests for scope boundaries.
- `demo/scripts/generate_demo_keys.py` produces a working set of env vars; the demo README provides a complete local run path without requiring hidden setup.
- Verification includes a focused config loading check and the relevant project test command available at implementation time.

## Open Implementation Decisions

- Whether to generate XLSX only, or generate CSV copies for easier diff review. Recommendation: XLSX as the primary source because it exercises multi-table workbook ingest; optional CSV exports can be generated but should not be used by config unless there is a specific test need.
- Whether the combined config should be hand-authored or generated from the five individual configs. Recommendation: hand-author `all_demos.yaml` first for clarity, and avoid clever merging until the example shape settles.
- Whether `required_any_of` filter semantics already exist in data_gate. If yes, this is configuration only. If no, it is a small platform feature to add as a prerequisite for the subject registry section, and worth adopting for personal-data row endpoints generally.
- Whether the `subject_registry` workbook should also carry a `LinkageEvents` sheet recording each historical linkage assertion, separate from the current `Subjects` snapshot. Recommendation: keep V1 to `Subjects` only; revisit if the demo grows an audit-history story.
