# NAgDI Agricultural Registries Demo Spec

## Purpose

Create a Registry Lab demo that shows how National Agricultural Data
Infrastructure can be built over the registry practices people use today:
spreadsheet registers, exported workbooks, district-level lists, program
tracking sheets, and operational records maintained by different authorities.

The demo should not imply that NAgDI requires one national agricultural
database. It should show a governed consultation and evidence layer across
existing systems.

The demo evidence should be framed as evidence for eligibility review, permit
review, program integrity, or planning. It should not imply automatic
entitlement, automatic permit issuance, or private-sector right to identify
farmers.

## Design Thesis

Many agricultural data systems begin as XLSX workbooks or spreadsheet exports.
Those workbooks are often good enough to run programs, but not good enough to
support trusted, purpose-bound, interoperable data use across ministries,
service providers, insurers, buyers, banks, and development programs.

Registry Relay can expose those workbooks as protected, read-only,
domain-oriented APIs. Registry Notary can combine facts from multiple Relay
authorities and return bounded evidence, predicates, or credentials without
copying raw registry rows into a central data lake.

## NAgDI Ideas To Make Visible

- Existing systems stay with their authorities.
- Data exchange is decentralized and secure.
- Metadata advertises datasets, evidence offerings, policies, and public
  service requirements.
- Access is scoped by purpose and capability.
- Evidence can be computed without exposing full source records.
- Aggregates can support market sizing and planning without individual-level
  disclosure.
- Governance is represented as policy metadata, audit evidence, and explicit
  denied controls.
- Lawful data exchange may be based on consent, public task, legal mandate,
  contract, permit condition, program rules, vital/public interest, or another
  country-specific basis.

## Demo Home

The demo belongs in `registry-lab`.

Recommended first implementation shape:

- Keep the current civil, social protection, and health demo intact.
- Add the agricultural scenario under a Compose profile and parallel
  `just agri-*` recipe set.
- Prefer XLSX-backed Relays for the first pass, because spreadsheet realism is
  central to the story.
- Reuse existing lab patterns for fixture generation, secret generation,
  static metadata publication, smoke scripts, and narrated client output.

Recommended local service names and ports:

```text
agri-registry-relay             4341
nagdi-agriculture-notary       4342
agri-static-metadata-publisher  4343
```

Recommended recipes:

```text
just agri-generate
just agri-generate-planning
just agri-build
just agri-up
just agri-smoke
just agri-client
just agri-down
```

Phase 0 and Phase 1 should use one combined `agri-registry-relay` unless the
story explicitly needs separate live Relay services. The workbooks still remain
separate authority-owned source files.

Host-side smoke and narrated client orchestration should use these defaults so
they can run against the agricultural Compose profile without reading fixtures:

```text
AGRI_RELAY_URL=http://127.0.0.1:4341
AGRI_WITNESS_URL=http://127.0.0.1:4342
AGRI_STATIC_METADATA_URL=http://127.0.0.1:4343
AGRI_DATA_PURPOSE=https://demo.example.gov/purpose/nagdi/climate-smart-input-support
AGRI_MARKET_DATA_PURPOSE=https://demo.example.gov/purpose/nagdi/agricultural-market-sizing
AGRI_FARMER_DATASET=agri_registry
AGRI_FARMER_ENTITY=farmer
AGRI_INPUT_VOUCHER_CLAIM=eligible-for-climate-smart-input-voucher
AGRI_MARKET_SIZING_PATH=/v1/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input
AGRI_SUPPRESSED_AGGREGATE_PATH=/v1/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input?district_code=D-WEST
```

The scripts should consume only `AGRI_*` credentials from `.env` and must not
print raw token values in terminal output or artifacts.

`just agri-generate` must write agricultural XLSX fixtures, agricultural demo
secrets, and static metadata needed by `just agri-smoke`. Shared baseline
secrets, including `REGISTRY_NOTARY_ISSUER_JWK`, must exist before Wave 0
validation starts.

`just agri-down` may stop the named agricultural services rather than the full
Compose profile so it does not disturb the baseline lab. Keep that deviation
documented in the README and smoke instructions if the recipe remains
service-name based.

## Actors

- Farmer or livestock keeper: beneficiary, applicant, or permit requester.
- Agricultural registry authority: maintains farmer and holding records.
- Land or farm services authority: maintains parcel and crop declaration data.
- Program authority: manages input vouchers, subsidies, extension activity, and
  redemption records.
- Agroclimate or market information unit: publishes district-level climate,
  crop calendar, and market price data.
- Animal health authority: maintains herd, vaccination, quarantine, and
  movement permit data.
- Service provider: requests bounded evidence or aggregates for a lawful
  agricultural service.
- NAgDI governance body: publishes metadata, policies, evidence offerings, and
  rules for purpose-bound consultation.

## Identity And Time Contract

The demo must not imply that all authorities share a universal agricultural
identifier in production. For the synthetic lab, shared IDs are deliberate test
keys used to make the flow reproducible.

Subject identifiers:

- External request subject: `farmer_id`, for example `FARMER-1001`.
- Farmer registry lookup: `farmer_id`.
- Holding and program lookup: `farmer_id`.
- Livestock lookup: `farmer_id` plus `herd_id` for herd-specific claims.
- Livestock movement snapshot lookup: `movement_snapshot_id`, which must equal
  `herd_id` in the fixture rows used by Notary.
- Synthetic national identifiers may exist in `FarmerIdentifiers`, but should
  not be required for the main demo path and should not be exposed in ordinary
  evidence outputs.

Deterministic evaluation date:

```text
evaluation_as_of = 2026-05-01
season = 2026A
```

All freshness, entitlement, redemption, vaccination, permit, and quarantine
checks should be evaluated against this date so smoke tests remain
deterministic.

Administrative codes:

- `district_code` in operational sheets equals `AdminAreas.admin_code` where
  `admin_level = district`.
- `village_code` in operational sheets equals `AdminAreas.admin_code` where
  `admin_level = village`.
- `season` values such as `2026A` must exist in the `Seasons` reference sheet.

## Workbook Set

Use separate workbooks per authority. This preserves the decentralized story
and mirrors how registries are often maintained today.

### `farmer-registry.xlsx`

Owner: agricultural registry authority.

Sheets:

- `Farmers`
- `FarmerIdentifiers`
- `FarmerGroups`
- `DataUseAuthorizations`
- `ChangeLog`

`Farmers` columns:

```text
farmer_id
national_id
given_name
family_name
sex
birth_date
district
district_code
village
village_code
phone_present
registration_status
registered_on
smallholder_status
household_id
role_in_household
age_band
youth_status
disability_status
vulnerability_category
producer_type
contactable_by_sms
preferred_language
data_quality_status
source_submission_id
last_verified_on
source_office
```

`FarmerIdentifiers` columns:

```text
identifier_id
farmer_id
identifier_type
identifier_value
issuing_authority
active
recorded_on
```

`FarmerGroups` columns:

```text
membership_id
farmer_id
group_id
group_name
group_type
registration_number
role
active
joined_on
```

`DataUseAuthorizations` columns:

```text
authorization_id
subject_id
subject_type
subject_scope
purpose_code
lawful_basis_code
legal_instrument_reference
grantee_type
disclosure_mode
status
valid_from
valid_until
captured_by
withdrawal_allowed
```

`ChangeLog` columns:

```text
change_id
sheet_name
record_id
change_type
changed_on
changed_by_office
note
```

Realism notes:

- Include inconsistent operational labels such as `active`, `inactive`,
  `pending_verification`, and `deceased_reported`, then normalize them only in
  Relay or Notary rules where needed.
- Include phone presence as a boolean, not phone numbers, so the demo avoids
  unnecessary personal data.
- Include one stale verification date to show that eligibility may fail on data
  freshness.
- Use `DataUseAuthorizations` for consent, public task, legal mandate,
  program-rule, and permit-condition cases. Consent is one possible basis, not
  the default for government eligibility and animal-health controls.
- `subject_scope` must be one of `individual`, `program`, or `universal`.
  Individual consent or authorization rows use `individual`; program-level legal
  mandates or public-task authorizations use `program` or `universal` so the
  Notary rule can establish lawful basis without requiring a per-farmer consent
  row.

### `farm-holdings-registry.xlsx`

Owner: land, extension, or farm services authority.

Sheets:

- `Holdings`
- `Parcels`
- `CropDeclarations`
- `TenureClaims`
- `ChangeLog`

`Holdings` columns:

```text
holding_id
farmer_id
district
district_code
village
village_code
holding_status
total_area_ha
primary_livelihood
last_verified_on
data_quality_status
source_submission_id
```

`Parcels` columns:

```text
parcel_id
holding_id
plot_reference
district
district_code
area_ha
irrigation_type
soil_zone
geometry_wkt
active
last_surveyed_on
```

`CropDeclarations` columns:

```text
crop_declaration_id
parcel_id
season
crop
planted_area_ha
declared_on
declaration_status
```

`TenureClaims` columns:

```text
tenure_id
parcel_id
tenure_type
verified_status
claim_source
claim_confidence
adjudication_status
dispute_flag
document_type
valid_from
valid_until
issuing_office
```

Realism notes:

- Use `geometry_wkt` for simple polygons or centroids, because workbooks often
  carry geometry as copied text rather than a native geospatial type.
- Treat `geometry_wkt` as `sensitive_location`. Ordinary row projections should
  omit raw parcel WKT unless the credential, purpose, and audience explicitly
  allow holding-level location access.
- Include duplicate or retired parcel references only if Relay config can
  safely avoid using them as primary keys.
- Prefer `parcel_id` and `holding_id` as stable synthetic keys.
- Treat tenure as eligibility evidence, not cadastral title. The workbook does
  not represent legally determinative land tenure unless backed by a real land
  authority in a deployment.

### `agri-program-registry.xlsx`

Owner: agricultural programs, subsidy, or extension authority.

Sheets:

- `Programs`
- `VoucherEntitlements`
- `VoucherRedemptions`
- `ExtensionVisits`
- `Suppliers`
- `ProgramRules`
- `InputPackages`
- `BudgetAllocations`
- `RedemptionReconciliation`
- `Grievances`
- `Sanctions`
- `ChangeLog`

`Programs` columns:

```text
program_code
program_name
season
input_type
district_scope
status
starts_on
ends_on
```

`ProgramRules` columns:

```text
rule_id
program_code
season
target_crop
target_risk_level
max_area_ha
household_cap
package_code
active
```

`InputPackages` columns:

```text
package_code
input_type
package_name
quantity_limit
unit
max_value
currency
active
```

`VoucherEntitlements` columns:

```text
entitlement_id
farmer_id
program_code
season
entitlement_status
approval_status
approved_by_office
eligible_input_type
package_code
max_value
currency
valid_from
issued_on
expires_on
```

`VoucherRedemptions` columns:

```text
redemption_id
entitlement_id
farmer_id
supplier_id
redemption_location
redeemed_on
redeemed_value
currency
redemption_status
```

`RedemptionReconciliation` columns:

```text
reconciliation_id
redemption_id
payment_batch_id
reconciliation_status
reconciled_on
exception_reason
```

`BudgetAllocations` columns:

```text
allocation_id
program_code
season
district_code
package_code
allocated_quantity
allocated_value
currency
allocation_status
```

`Grievances` columns:

```text
grievance_id
farmer_id
program_code
season
grievance_type
status
opened_on
closed_on
resolution_code
```

`Sanctions` columns:

```text
sanction_id
farmer_id
program_code
sanction_type
status
effective_from
effective_until
issuing_office
```

`ExtensionVisits` columns:

```text
visit_id
farmer_id
parcel_id
extension_officer_id
visit_date
advisory_topic
recommendation_code
follow_up_required
```

`Suppliers` columns:

```text
supplier_id
supplier_name
district
district_code
license_status
last_verified_on
```

Realism notes:

- Include a farmer with a valid entitlement but an expired supplier license to
  demonstrate that eligibility can fail outside the farmer record.
- Include one duplicate redemption attempt to show fraud-prevention evidence.
- Include one reconciliation exception and one grievance/appeal row to show
  that program decisions may require human review.
- Keep supplier names synthetic but human-readable for walkthrough clarity.

### `agroclimate-market-registry.xlsx`

Owner: agroclimate, meteorological, statistics, or market information unit.

Sheets:

- `DistrictClimateRisk`
- `RainfallObservations`
- `MarketPrices`
- `CropCalendar`
- `AdvisoryRules`
- `VoucherMarketSizingCells`

`DistrictClimateRisk` columns:

```text
risk_id
district
district_code
season
drought_risk_level
flood_risk_level
rainfall_percentile
recommended_input_type
updated_on
```

`RainfallObservations` columns:

```text
observation_id
district
district_code
station_id
observed_on
rainfall_mm
source_quality
```

`MarketPrices` columns:

```text
price_id
district
district_code
market_name
commodity
price_date
unit
price
currency
```

`CropCalendar` columns:

```text
calendar_id
district
district_code
crop
season
planting_window_start
planting_window_end
harvest_window_start
harvest_window_end
```

`AdvisoryRules` columns:

```text
rule_id
district
district_code
season
crop
risk_level
recommended_input_type
advisory_text_code
active
```

`VoucherMarketSizingCells` columns:

```text
cell_id
district_code
district
village_code
crop
risk_band
input_type
season
eligible_count
minimum_cell_count
suppression_status
suppression_reason
recipient_type
purpose_code
```

Realism notes:

- District and season are natural join dimensions for aggregate and advisory
  decisions.
- Market prices should be aggregate/public or restricted-low sensitivity, while
  farmer and parcel records remain personal or sensitive.
- Market-sizing outputs should enforce minimum cell counts, geography floors,
  rare-category suppression, and recipient/purpose checks.
- Pre-materialized market-sizing cells should be designed to avoid simple
  differencing attacks. Do not publish paired totals and complements that allow
  a suppressed cell to be recovered by subtraction.

### `livestock-registry.xlsx`

Owner: animal health or livestock authority.

Sheets:

- `LivestockHoldings`
- `Premises`
- `Herds`
- `Animals`
- `Vaccinations`
- `QuarantineZones`
- `MovementApplications`
- `MovementPermits`
- `MovementEvents`
- `ChangeLog`

`LivestockHoldings` columns:

```text
livestock_holding_id
farmer_id
district
district_code
village
village_code
holding_status
premises_code
last_verified_on
```

`Premises` columns:

```text
premises_code
district_code
village_code
premises_type
registration_status
last_verified_on
```

`Herds` columns:

```text
herd_id
farmer_id
livestock_holding_id
species
count
production_system
registration_status
updated_on
```

`Animals` columns:

```text
animal_id
herd_id
tag_id
species
breed
sex
birth_date
status
```

`Vaccinations` columns:

```text
vaccination_id
herd_id
animal_id
vaccine_code
vaccinated_on
valid_until
administered_by_office
status
```

`QuarantineZones` columns:

```text
zone_id
district
district_code
disease_code
status
effective_from
effective_until
declared_by_office
district_code
```

`MovementPermits` columns:

```text
permit_id
application_id
herd_id
origin_premises_code
destination_premises_code
origin_district_code
destination_district_code
permit_status
issued_on
valid_until
revoked_on
```

`MovementApplications` columns:

```text
application_id
herd_id
origin_premises_code
destination_premises_code
species
animal_count
requested_movement_date
movement_purpose
application_status
```

`MovementEvents` columns:

```text
movement_event_id
permit_id
origin_premises_code
destination_premises_code
moved_on
animal_count
transporter_id
confirmed_by_office
```

Realism notes:

- Keep the main story herd-level. Add a few animal-level rows only for
  traceability and tag examples.
- Make vaccination valid at herd level for most rows and individual-animal
  level for a small traceability edge case.
- Include one active quarantine zone and one expired quarantine zone.
- Movement permits must link back to `MovementApplications.application_id`.
- Movement eligibility should consider origin premises, destination premises,
  species-specific disease rules, requested movement date, animal count, and
  conflicting open permits.
- Quarantine checks are species-aware. The fixture should include at least one
  quarantine disease affecting the requested species and one disease that does
  not affect it, so `origin-district-not-quarantined-for-species` can be tested.
- `MovementEvents` is a traceability record for post-permit movement
  confirmation. It is not part of the default movement permit eligibility claim
  unless a later wave adds a `movement-confirmed-at-destination` claim.

### `nagdi-reference-data.xlsx`

Owner: NAgDI governance or standards unit.

Sheets:

- `AdminAreas`
- `Seasons`
- `CropCodes`
- `CommodityCodes`
- `InputCatalog`
- `DiseaseCodes`
- `VaccineCodes`
- `ServiceProviders`
- `PurposePolicies`
- `SourceSubmissions`
- `ValidationIssues`
- `DuplicateCandidates`
- `CorrectionRequests`

`AdminAreas` columns:

```text
admin_code
admin_level
admin_name
parent_admin_code
active
valid_from
valid_until
```

`Seasons` columns:

```text
season
season_name
starts_on
ends_on
active
```

`CropCodes` columns:

```text
crop_code
crop_name
active
```

`CommodityCodes` columns:

```text
commodity_code
commodity_name
unit
active
```

`InputCatalog` columns:

```text
input_code
input_name
unit
active
```

`DiseaseCodes` columns:

```text
disease_code
disease_name
species
active
```

`VaccineCodes` columns:

```text
vaccine_code
disease_code
validity_days
active
```

`SourceSubmissions` columns:

```text
source_submission_id
source_office
submitted_by_role
submitted_on
source_file_label
record_count
validation_status
```

`ValidationIssues` columns:

```text
issue_id
source_submission_id
sheet_name
record_id
issue_type
severity
status
detected_on
```

`PurposePolicies` columns:

```text
purpose_code
public_service_code
lawful_basis_code
allowed_recipient_types
allowed_disclosure_modes
retention_days
minimum_cell_count
geography_floor
suppression_policy
rare_category_suppression
onward_sharing_allowed
automated_decision_allowed
appeal_contact
audit_required
published_by_authority
approval_status
```

`DuplicateCandidates` columns:

```text
candidate_id
source_submission_id
farmer_id
matched_farmer_id
match_basis
match_score
status
```

`CorrectionRequests` columns:

```text
correction_request_id
issue_id
requested_from_office
requested_on
status
resolution_note
```

Realism notes:

- Keep district and village labels in operational sheets, but use admin codes
  for deterministic joins and policy rules.
- Include one unresolved duplicate or validation issue that produces a
  `manual_review` outcome rather than a clean yes/no eligibility result.
- Include one `PurposePolicies` row with `approval_status = pending_approval`
  to show that policies are governed records, not only static lookup values.
- `ChangeLog` sheets use the same schema in every workbook. `ChangeLog` records
  manual edits or publication events, while `ValidationIssues` records detected
  data quality problems that may block or route a case to manual review.

### `nagdi-evidence-snapshots.xlsx`

Owner: NAgDI governance or evidence orchestration unit.

Sheets:

- `VoucherEligibilitySnapshots`
- `LivestockMovementSnapshots`
- `MarketSizingCells`

`VoucherEligibilitySnapshots` columns:

```text
farmer_id
season
purpose_code
farmer_registered
lawful_basis_established
active_smallholder_farmer
active_farm_parcel
crop_declared_for_season
district_climate_risk_active
voucher_entitlement_current
voucher_not_redeemed
supplier_license_active
manual_review_required
reason_code
evaluation_as_of
```

`LivestockMovementSnapshots` columns:

```text
movement_snapshot_id
farmer_id
herd_id
registered_livestock_holder
registered_herd
herd_vaccination_current
origin_district_not_quarantined_for_species
destination_district_open
no_conflicting_open_movement_permit
manual_review_required
reason_code
evaluation_as_of
```

`MarketSizingCells` columns:

```text
cell_id
district
district_code
season
crop
risk_band
input_type
eligible_opportunity_count
estimated_area_ha
cell_farmer_count
recipient_authorization_required
geography_floor
```

Realism notes:

- This workbook contains materialized evidence and aggregate projections used to
  keep the first demo inside currently proven Relay and Notary patterns.
- Snapshot rows are generated outputs. They are not authoritative source
  registry records.
- `MarketSizingCells` is the preferred source for aggregate planning evidence
  until cross-workbook Relay aggregates are explicitly validated.

## Registry Relay Surface

Each workbook should back one Relay authority, or one Relay authority can expose
multiple workbook-backed datasets if that keeps the lab lighter.

Recommended datasets:

- `farmer_registry`
- `farm_holdings_registry`
- `agri_program_registry`
- `agroclimate_market_registry`
- `livestock_registry`
- `nagdi_reference_data`
- `nagdi_evidence_snapshots`

Recommended entities:

- `farmer`
- `data_use_authorization`
- `holding`
- `parcel`
- `crop_declaration`
- `voucher_entitlement`
- `voucher_redemption`
- `extension_visit`
- `district_climate_risk`
- `market_price`
- `livestock_holding`
- `herd`
- `animal`
- `vaccination`
- `quarantine_zone`
- `movement_application`
- `movement_permit`
- `movement_event`
- `voucher_eligibility_snapshot`
- `livestock_movement_snapshot`
- `market_sizing_cell`
- `admin_area`
- `purpose_policy`

Recommended aggregates:

- farmers by district and registration status
- active parcels by crop, district, and season
- eligible voucher entitlements by district and input type
- redemptions by supplier and status
- drought-risk districts by season
- pre-materialized livestock herd counts by species and district
- vaccination coverage by species and district
- pre-materialized voucher market-sizing cells by district, crop, risk band,
  and input type

Aggregate ids must be unique across dataset-level and entity-level aggregate
configuration. Define `voucher_opportunities_by_district_crop_risk_input` in
one place only, preferably on the pre-materialized market-sizing source used by
the smoke path.

Access model:

- `metadata` scope can discover datasets and evidence offerings.
- `rows` scope can read allowed personal or operational rows.
- `aggregate` scope can read configured aggregates without row access.
- `evidence_verification` scope is used by Notary source connections.
- All personal or holding-level entities should require `Data-Purpose`.

Entity implementation contract:

Each Relay entity added for the demo must specify:

- source workbook and sheet
- primary key
- lookup fields and allowed filters
- nullable fields
- status domains used by Notary rules
- sensitivity classification
- whether `Data-Purpose` is required
- whether the entity can be used by aggregate-only clients

Phase 0 should use materialized one-row evidence projections where needed.
For example, `voucher_eligibility_snapshot` can summarize whether the farmer is
registered, has an established lawful basis for the purpose, has an active
parcel, has a current entitlement, and has a recorded redemption. Later phases
can replace this with multi-source Notary bindings if product support and demo
complexity justify it.

Do not make the first herd aggregate depend on a cross-table Relay join unless
the wave explicitly validates that feature. Prefer a pre-materialized
district-level herd planning snapshot for the demo path.

## Registry Notary Surface

### Crop And Input Voucher Claims

Claims:

- `farmer-registered`
- `lawful-basis-established-for-purpose`
- `active-smallholder-farmer`
- `active-farm-parcel`
- `crop-declared-for-season`
- `district-climate-risk-active`
- `voucher-entitlement-current`
- `voucher-not-redeemed`
- `supplier-license-active`
- `eligible-for-climate-smart-input-voucher`

Composite rule:

```text
eligible-for-climate-smart-input-voucher =
  farmer-registered
  and lawful-basis-established-for-purpose
  and active-smallholder-farmer
  and active-farm-parcel
  and crop-declared-for-season
  and district-climate-risk-active
  and voucher-entitlement-current
  and voucher-not-redeemed
```

Optional supplier rule:

```text
voucher-redemption-authorized =
  eligible-for-climate-smart-input-voucher
  and supplier-license-active
```

### Livestock Movement Claims

Claims:

- `registered-livestock-holder`
- `registered-herd`
- `herd-vaccination-current`
- `origin-district-not-quarantined-for-species`
- `destination-district-open`
- `no-conflicting-open-movement-permit`
- `eligible-for-livestock-movement-permit`

Composite rule:

```text
eligible-for-livestock-movement-permit =
  registered-livestock-holder
  and registered-herd
  and herd-vaccination-current
  and origin-district-not-quarantined-for-species
  and destination-district-open
  and no-conflicting-open-movement-permit
```

Notary lookup design:

- Phase 0 uses `cardinality: one` source bindings against materialized snapshot
  entities to stay inside the current lab pattern.
- Phase 1 may use `cardinality: one` for direct registry facts and
  pre-materialized absence checks such as `voucher_not_redeemed`.
- Collection and absence predicates such as no redemption, no active
  quarantine, and no conflicting permit must be represented either as
  materialized evidence rows or explicitly called out as product work before
  implementation.

### Disclosure Modes

Minimum supported outputs:

- Predicate result for eligibility.
- Redacted result with reason codes.
- Optional value result for operational debug claims.
- Optional SD-JWT VC for a successful eligibility result.

Reason code examples:

- `farmer.registration_status:not_active`
- `lawful_basis:missing_or_expired`
- `parcel.status:not_active`
- `climate.risk:not_targeted`
- `voucher.redemption:already_redeemed`
- `livestock.vaccination:expired`
- `quarantine.origin:active`
- `data_quality:manual_review_required`

## Golden Demo Subjects

Seed deterministic rows so the walkthrough has clear positive and negative
controls.

### Crop/Input Voucher

`FARMER-1001`

- registered farmer
- valid lawful basis established for the purpose
- active smallholder
- active maize parcel in drought-risk district
- current voucher entitlement
- no redemption
- expected result: eligible

`FARMER-1002`

- registered farmer
- no verified active parcel
- expected result: not eligible

`FARMER-1003`

- registered farmer
- active parcel
- voucher already redeemed
- expected result: not eligible

`FARMER-1004`

- pending farmer registration
- expected result: not eligible

`FARMER-1006` (optional if the fixture needs a separate freshness control)

- active farmer registration but stale verification
- expected result: not eligible with a freshness reason code

`FARMER-1005`

- unresolved duplicate or parcel conflict
- expected result: manual review

### Livestock Movement

`FARMER-2001`, `HERD-2001`

- registered livestock holder
- registered cattle herd
- vaccination current
- origin district clear
- destination district open
- no active permit
- expected result: eligible

`FARMER-2002`, `HERD-2002`

- vaccination expired
- expected result: not eligible

`FARMER-2003`, `HERD-2003`

- origin district under active quarantine
- expected result: not eligible

## Narrated Demo Flow

### Story 1: Climate-Smart Input Voucher

1. Client discovers static NAgDI metadata.
2. Client finds the public service for climate-smart input voucher eligibility.
3. Client follows evidence offerings to the agriculture Notary.
4. Notary discovers required source connections and calls the relevant Relays.
5. Relays enforce scope, purpose, row projection, and audit.
6. Notary returns a predicate and reason codes.
7. Demo client writes artifacts showing discovery, evaluation, denials, and
   audit evidence.

Required controls:

- Evidence-only client cannot read farmer rows.
- Aggregate-only client cannot read farmer rows.
- Row-reader client cannot read aggregates unless it has aggregate scope.
- Missing `Data-Purpose` is denied for sensitive row reads.
- Already-redeemed farmer returns a negative eligibility result.
- Unresolved data-quality issue returns no automatic eligibility plus a
  manual-review reason code.

### Story 2: Market Sizing Without Raw Farmer Data

1. A service provider asks for aggregate opportunity sizing.
2. Registry Relay returns counts by district, crop, risk band, or input type
   through the aggregate endpoint, not through Registry Notary.
3. The provider cannot retrieve individual farmers with the aggregate
   credential.
4. Static metadata and policy describe the aggregate offering.

Initial Phase 1b question:

```text
How many eligible voucher opportunities are present by district, crop, risk
band, and input type after suppression rules are applied?
```

This should start as a pre-materialized aggregate entity or a simple aggregate
over one source entity. Do not make Phase 1 depend on Relay joining farmer,
parcel, climate, entitlement, and redemption data across authorities.

Required aggregate controls:

- minimum cell count
- geography floor
- rare category suppression
- recipient license or authorization
- no row export for private-sector market sizing
- denial artifact for a suppressed village-level or rare-crop request

### Story 3: Livestock Movement Permit

1. Client discovers livestock movement evidence requirements.
2. Notary checks livestock holder registration, herd registration,
   vaccination, origin and destination restrictions, requested movement date,
   animal count, quarantine, and conflicting permit status.
3. Notary returns eligibility for movement permit review.
4. Negative controls show expired vaccination and active quarantine.

This should be optional in the first implementation if the crop/input story is
not yet crisp.

## Static Metadata

Add NAgDI-oriented metadata to the static publisher.

Public services:

- `climate_smart_input_voucher`
- `livestock_movement_permit`
- optional `agricultural_market_sizing`

Requirements:

- farmer identity and registration requirement
- lawful-basis requirement
- active parcel requirement
- crop declaration requirement
- climate-risk targeting requirement
- voucher redemption exclusion requirement
- livestock holding requirement
- vaccination requirement
- quarantine clearance requirement

Evidence types:

- farmer registration evidence
- active farm parcel evidence
- climate-risk district evidence
- voucher redemption status evidence
- livestock vaccination evidence
- quarantine clearance evidence
- movement permit status evidence
- composed input voucher eligibility evidence
- composed livestock movement eligibility evidence

Policy metadata should explicitly identify purposes such as:

- `climate-smart-input-support`
- `livestock-movement-permit-review`
- `agricultural-market-sizing`
- `program-integrity-audit`

Policy metadata should also include:

- data steward
- sensitivity classification
- lawful basis
- permitted recipient types
- minimum disclosure mode
- retention
- minimum cell count for aggregates
- geography floor for aggregates
- audit obligations
- appeal or contact route
- whether automated decisions are allowed

Recommended purpose IRIs:

```text
https://demo.example.gov/purpose/nagdi/climate-smart-input-support
https://demo.example.gov/purpose/nagdi/livestock-movement-permit-review
https://demo.example.gov/purpose/nagdi/agricultural-market-sizing
https://demo.example.gov/purpose/nagdi/program-integrity-audit
```

## Access Matrix

Phase 0 and Phase 1 should define these client classes.

```text
metadata_client:
  scopes: agri_registry:metadata
  allowed: metadata, catalog, evidence offerings
  denied: rows, aggregates, Notary evaluation

agri_evidence_source:
  scopes: agri_registry:metadata, agri_registry:rows, agri_registry:evidence_verification
  allowed: Notary source row lookups
  denied: direct aggregate-only market sizing unless aggregate scope is added

row_reader:
  scopes: agri_registry:metadata, agri_registry:rows
  allowed: authorized row reads with Data-Purpose
  denied: aggregates and Notary-only evidence routes

aggregate_reader:
  scopes: agri_registry:metadata, agri_registry:aggregate
  allowed: configured aggregates with Data-Purpose
  denied: personal rows and holding-level records

evidence_client:
  scopes: agri_registry:evidence_verification
  allowed: Notary claim evaluation
  denied: direct Relay row reads
```

Expected denial controls:

- missing or wrong scope returns `auth.scope_denied`
- missing purpose on sensitive row read returns the Relay purpose error used by
  the implementation
- suppressed aggregate returns a stable problem code and artifact
- unauthorized private-sector row export returns `auth.scope_denied`

## XLSX Realism Rules

Use spreadsheet features and imperfections carefully:

- Use separate sheets with stable identifiers rather than one normalized
  database-like table.
- Keep human-readable operational names alongside stable IDs.
- Include status fields with realistic values and a few stale records.
- Include `ChangeLog` sheets to acknowledge manual maintenance.
- Include source offices and verification dates.
- Avoid formulas as source-of-truth for Relay ingestion unless explicitly
  tested. Prefer materialized values in fixture sheets.
- Avoid sensitive values that are not needed for the demo, such as full phone
  numbers, exact addresses, or real-like identifiers.
- Keep date formats consistent after fixture generation.
- Make all generated workbooks deterministic.

## Implementation Phases

Consumer-facing MIS, GIS, and semantic projection improvements are specified in
[`nagdi-consumer-integration-demo-spec.md`](nagdi-consumer-integration-demo-spec.md).

### Phase 0: Feasibility Slice

Build:

- one combined `agri-registry-relay`
- one `nagdi-agriculture-notary`
- the minimum generated XLSX workbook set, including
  `nagdi-evidence-snapshots.xlsx` when materialized snapshot entities are used
- materialized one-row evidence snapshot for input voucher review
- one positive subject and one negative subject
- one static metadata offering
- one smoke script

Done when:

- `FARMER-1001` evaluates eligible.
- one negative farmer evaluates not eligible.
- a row-read denial artifact is captured under `output/agri-smoke/`.
- a Notary evaluation success artifact is captured under `output/agri-smoke/`.
- one audit artifact for an evaluation or denial is captured under
  `output/agri-smoke/`.
- fixture generation validates primary keys and references.

### Phase 1: Crop/Input Voucher Bounded Slice

Build:

- farmer, holdings, program, and agroclimate workbooks
- one combined agriculture Relay unless multi-Relay separation is required for
  a specific walkthrough
- agriculture Notary with input voucher claims
- static metadata for the input voucher service
- smoke script and narrated client flow

Done when:

- `FARMER-1001` evaluates eligible.
- `FARMER-1002`, `FARMER-1003`, and `FARMER-1004` evaluate not eligible with
  clear reason codes.
- metadata discovery leads to the Notary endpoint for eligibility evidence.
- the evidence-only row-read denial, aggregate-only row-read denial,
  row-reader aggregate denial, and missing-purpose row-read denial all pass.
- `FARMER-1005` returns manual review and is not auto-eligible.

### Phase 1b: Market-Sizing Controls

Build:

- pre-materialized aggregate entity or one-source aggregate for opportunity
  sizing
- suppression policy fixture rows
- one allowed aggregate query
- one denied or suppressed rare-cell query

Done when:

- aggregate-only access cannot read farmer, parcel, entitlement, or redemption
  rows.
- suppressed cells are not emitted.
- the suppressed-cell artifact is captured under
  `output/agri-smoke/agri-suppressed-aggregate.json` or the narrated client
  equivalent under `output/agri-client/`.
- the narrated client explains that private actors receive planning evidence,
  not farmer lists.

### Phase 2: Livestock Movement

Build:

- livestock workbook
- livestock Relay config
- livestock Notary claims
- static metadata for livestock movement permit service
- narrated flow and smoke controls

Done when:

- `HERD-2001` evaluates eligible.
- `HERD-2002` fails on vaccination.
- `HERD-2003` fails on quarantine.
- a pre-materialized or explicitly validated herd aggregate is available
  without individual animal row access.

### Phase 3: Credential And Wallet Story

Keep this in the core demo as a lightweight credential and OID4VCI/wallet
probe. The demo should prove holder-bound credential issuance after successful
voucher evidence, without expanding into a full production wallet ceremony.

Build:

- SD-JWT VC profile for successful input voucher eligibility.
- Optional SD-JWT VC profile for livestock movement eligibility.
- Lightweight OID4VCI or wallet interop probe for the agriculture credential.

Done when:

- a successful evaluation can issue a credential with holder binding.
- credential issuance does not require exposing raw source rows.

## Non-Goals

- No write-back into source registries.
- No claim that spreadsheet registries are ideal long-term systems.
- No real OpenCRVS, OpenSPP, livestock, land, meteorological, or market system
  integration.
- No production identity proofing.
- No real farmer, animal, supplier, parcel, or location data.
- No central agricultural data warehouse.

## Risks And Open Questions

- Multi-workbook joins may be easier to demonstrate in Notary than in Relay
  aggregates. Keep the first aggregate simple if needed.
- Consent should be represented as one possible data-use basis. Real
  deployments may use lawful basis, public task, consent, permit condition,
  contract, or mandate depending on country policy.
- Livestock traceability can become too detailed. Keep herd-level movement as
  the first livestock story.
- Spreadsheet messiness is useful for realism, but primary keys must remain
  deterministic and valid for Relay ingest.
- The demo should avoid implying that market actors can discover farmers
  directly. Market sizing should be aggregate-first.
- Current Relay aggregates are single-source. Cross-authority opportunity
  sizing should be pre-materialized or deferred until the product supports the
  needed query shape.
- Current Notary examples mostly use one-row lookups. Collection and absence
  predicates should use materialized projections unless explicit product work is
  planned.

## Verification Plan

Agricultural demo verification should include:

- fixture generation for XLSX workbooks
- primary-key uniqueness checks
- referential-integrity checks across synthetic IDs
- deterministic date checks using `evaluation_as_of`
- static metadata publication and validation
- Relay readiness checks
- Relay OpenAPI fetch
- Notary discovery and OpenAPI fetch
- positive and negative Notary evaluations
- manual-review evaluation for a data-quality issue
- access-denial controls for rows, aggregates, and missing purpose
- aggregate suppression control
- audit log assertion for at least one evaluation and one denial
- narrated client artifact assertions

## Definition Of Done

The NAgDI agricultural registries demo is complete only when every item required
by the implemented wave is true. A wave is not complete if any item is only
partly implemented, hidden behind manual data edits, or dependent on
undocumented setup.

Current completion stance: the near-term 95% demo target is Phases 1, 1b, 2,
and a lightweight Phase 3 with deterministic fixtures, Registry Notary voucher
and livestock evidence, Registry Relay aggregate market sizing, denial
artifacts, narrated client artifacts, holder-bound voucher credential issuance,
and a scripted OID4VCI or wallet probe. Full production wallet ceremonies remain
out of scope.

Functional acceptance:

- `just agri-generate` creates deterministic XLSX workbooks under the
  agricultural demo data directory.
- Fixture generation validates primary keys, required references, status
  domains, date windows, and golden-subject coverage before writing success.
- Generated workbooks include the authority-owned sheets required by the wave,
  and no generated source file contains real personal, farm, supplier, animal,
  parcel, or location data.
- `just agri-build` builds the agricultural Relay and Notary services without
  changing the baseline civil, social protection, and health demo.
- `just agri-up` starts the agricultural Compose profile on the documented
  ports.
- Relay readiness, Relay OpenAPI, Notary discovery, and Notary OpenAPI checks
  pass.
- Relay exposes scoped metadata, row, and aggregate routes for every entity
  required by the wave.
- Static metadata advertises the agricultural public service, requirements,
  evidence types, evidence offerings, policies, purpose IRIs, and access
  services required by the wave.
- The narrated client starts from metadata discovery and does not hard-code a
  Notary route that should have been discovered from metadata.

Evidence acceptance:

- `FARMER-1001` evaluates as eligible for climate-smart input voucher review.
- `FARMER-1002`, `FARMER-1003`, and `FARMER-1004` evaluate as not eligible with
  stable reason codes once Phase 1 is in scope.
- `FARMER-1005` returns no automatic eligibility and a
  `data_quality:manual_review_required` reason once data-quality controls are
  in scope.
- Phase 1b proves aggregate-only market sizing without personal row access and
  proves at least one suppressed or denied rare-cell aggregate.
- Phase 2 proves `HERD-2001` eligible, `HERD-2002` denied for vaccination, and
  `HERD-2003` denied for quarantine.
- Demo-grade credential issuance issues only from a successful prior evaluation,
  uses holder binding, and does not expose raw source rows.

Security, governance, and privacy acceptance:

- Missing or wrong scopes produce stable denial artifacts.
- Missing `Data-Purpose` on sensitive row reads is denied.
- Aggregate credentials cannot read farmer, parcel, entitlement, redemption,
  herd, animal, or permit rows.
- Evidence clients cannot directly read Relay rows.
- Market-sizing outputs apply minimum cell count, geography floor, and
  rare-category suppression rules.
- Audit evidence is captured for at least one successful evaluation and one
  denial.
- Outputs are framed as evidence for review, planning, or program integrity,
  not automatic entitlement, automatic permit issuance, or private-sector right
  to identify farmers.

Artifact acceptance:

- `just agri-smoke` writes replayable smoke artifacts under `output/`.
- `just agri-client` writes a narrated transcript, scenario summary, metadata
  discovery artifacts, evaluation artifacts, denial artifacts, and aggregate
  artifacts under `output/`.
- Artifacts do not print or commit raw secrets.
- The README or demo docs name the agricultural recipes, ports, source files,
  and expected golden subjects.

Verification acceptance:

- The closest focused generator checks pass.
- `just agri-smoke` passes.
- `just agri-client` passes.
- `git diff --name-only main...HEAD` is reviewed for every wave. If the diff
  touches `justfile`, `compose.yaml`, `scripts/generate-*`,
  `static-metadata/`, Dockerfiles, or shared secret generation, baseline
  `just smoke` and `just release-fast` are run, or the skipped command and
  reason are recorded in the review.
- Any skipped check is documented with the exact reason and residual risk.

Review acceptance:

- Each implementation wave receives named staff-engineer and domain or privacy
  review before the next wave starts.
- Review findings are resolved or explicitly moved to a later wave with a
  named reason.
- No wave is marked done until the named reviewer approval and the validation
  command output are recorded in the PR, change note, or review artifact.
- The final self-review confirms no unrelated dirty files were reverted,
  reformatted, or mixed into the change.
- No "partially implemented" item remains in the completed wave.

## Parallel Implementation Plan

Implement the demo in waves. Workers run in parallel only when their write
scopes are disjoint, and every wave ends with integration review, smoke
evidence, and a short retrospective before the next wave begins.

Each wave has exactly one infrastructure owner for shared files such as
`justfile`, `compose.yaml`, README files, Dockerfiles, `.env` generation, and
static metadata publication wiring. Other workers may propose interface
requirements, but they do not edit those shared files directly.

### Wave 0: Feasibility Slice

Goal: prove the smallest end-to-end agricultural loop.

Parallel worker ownership:

- Worker A owns fixture generation for the minimal XLSX source and golden
  subjects.
- Worker B owns the combined `agri-registry-relay` config, metadata manifest,
  scopes, and purpose requirements.
- Worker C owns `nagdi-agriculture-notary` claims for one eligible and one
  denied input-voucher subject.
- Worker D is the infrastructure owner and owns `just agri-*` recipes, Compose
  profile wiring, README updates, and smoke script scaffolding.

Review gate:

- Staff engineer review checks Relay/Notary feasibility, strict XLSX schema
  compatibility, scope boundaries, and smoke reliability.
- Agricultural domain review checks that the workbook shape still resembles
  realistic spreadsheet-era government operations.

Validation gate:

- `just agri-generate`
- `just agri-build`
- `just agri-up`
- `just agri-smoke`

Wave 0 is done only when metadata discovery, one positive evaluation, one
negative evaluation, one row-read denial, and one audit artifact are all
captured under `output/agri-smoke/`, and named reviewer approval is recorded.

### Wave 1: Crop And Input Voucher Demo

Goal: implement the full climate-smart input voucher review story.

Parallel worker ownership:

- Worker A owns farmer, holdings, program, agroclimate, and reference-data XLSX
  generation plus referential-integrity checks.
- Worker B owns Relay entity configs, allowed filters, schemas, sensitivity
  labels, and purpose requirements.
- Worker C owns Notary claim rules, reason codes, materialized absence checks,
  and manual-review behavior.
- Worker D owns static metadata for services, requirements, evidence types,
  policies, purpose IRIs, and access services.
- Worker E is the infrastructure owner and owns narrated client artifacts,
  smoke assertions, README/demo documentation, and any `justfile` or Compose
  edits needed by the wave.

Review gate:

- Code review verifies each worker stayed inside its owned files and did not
  change baseline demo behavior unnecessarily.
- Staff engineer review checks no cross-authority aggregate or Notary lookup
  exceeds current product capability unless it is explicitly materialized.
- Domain review checks lawful-basis wording, targetability, program realism,
  data-quality handling, and non-automatic decision framing.

Validation gate:

- `just agri-generate`
- `just agri-smoke`
- `just agri-client`
- baseline smoke or release-fast checks if shared surfaces changed

Wave 1 is done only when `FARMER-1001` is eligible, `FARMER-1002`,
`FARMER-1003`, and `FARMER-1004` are denied with stable reason codes,
`FARMER-1005` returns manual review, evidence-only row denial,
aggregate-only row denial, row-reader aggregate denial, and missing-purpose
row denial all pass, and named reviewer approval is recorded.

### Wave 1b: Market-Sizing Controls

Goal: add aggregate planning evidence without farmer discovery.

Parallel worker ownership:

- Worker A owns pre-materialized aggregate fixture rows and suppression cases.
- Worker B owns Relay aggregate config and aggregate-only access controls.
- Worker C owns static metadata and policy descriptions for market-sizing
  recipients, disclosure modes, and suppression rules.
- Worker D is the infrastructure owner and owns smoke and narrated client
  assertions for allowed and suppressed aggregates plus any shared recipe or
  README updates.

Review gate:

- Staff engineer review checks the aggregate is single-source or
  pre-materialized, not an accidental unsupported join.
- Domain review checks minimum cell count, geography floor, rare-category
  suppression, recipient limits, and no-row-export framing.

Validation gate:

- `just agri-generate`
- `just agri-smoke`
- `just agri-client`

Wave 1b is done only when aggregate-only clients cannot read personal rows,
allowed aggregate outputs pass, and a rare-cell or village-level aggregate is
suppressed or denied with a stable artifact under `output/agri-smoke/` or
`output/agri-client/`, and named reviewer approval is recorded.

### Wave 2: Livestock Movement Permit

Goal: add the herd-level animal-health and movement-permit story.

Parallel worker ownership:

- Worker A owns livestock XLSX generation for premises, herds, animals,
  vaccinations, quarantine zones, movement applications, permits, and events.
- Worker B owns livestock Relay entities, filters, purpose requirements, and
  aggregate routes.
- Worker C owns livestock Notary claims, species/date checks, quarantine
  checks, and conflicting-permit checks.
- Worker D is the infrastructure owner and owns livestock static metadata,
  narrated client flow, smoke checks, docs, and any shared recipe updates.

Review gate:

- Staff engineer review checks collection and absence predicates are
  materialized or implemented with supported Notary behavior.
- Domain review checks premises, disease/vaccine codes, origin and destination
  restrictions, requested movement date, animal count, and permit wording.

Validation gate:

- `just agri-generate`
- `just agri-smoke`
- `just agri-client`

Wave 2 is done only when `HERD-2001` evaluates eligible, `HERD-2002` fails for
vaccination, `HERD-2003` fails for species-aware quarantine, and a
pre-materialized or explicitly validated herd aggregate is available without
individual animal row access, and named reviewer approval is recorded.

### Wave 3: Credential And Wallet Story

Goal: keep demo-grade credential issuance proven and add a lightweight wallet or
OID4VCI probe after the evidence flows are stable.

Parallel worker ownership:

- Worker A owns credential profile config and issuer material wiring.
- Worker B owns holder-binding smoke and negative controls.
- Worker C is the infrastructure owner and owns narrated client credential
  artifacts, docs, and shared recipe updates.

Review gate:

- Security review checks holder binding, disclosure mode, source-row minimization,
  and no secret leakage.
- Staff engineer review checks credential issuance uses a successful prior
  evaluation and does not bypass Notary policy.

Validation gate:

- `just agri-smoke`
- `just agri-client`
- any existing credential or OID4VCI probe if that surface is touched

Wave 3 is done for the current demo when a successful evaluation can issue a
bound credential, the lightweight wallet or OID4VCI probe passes, raw source
rows remain out of credential outputs, and wallet/OID4VCI negative controls
fail closed.
