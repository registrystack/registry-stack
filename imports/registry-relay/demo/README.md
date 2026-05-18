<!-- SPDX-License-Identifier: Apache-2.0 -->

# registry-relay demo pack

Five core synthetic government datasets show `registry-relay` as a controlled
data reuse gateway: per-persona scopes, purpose-tagged reads,
disclosure-controlled aggregates, and cross-dataset composition that stays
client-side and audited. The pack also includes an optional Social Protection
Digital Convergence Initiative (SP DCI) Disability Registry demo, enabled with
the `spdci-api-standards` feature.

This pack is intended for local review. Nothing in `demo/data/` is real, all
identifiers are synthetic (`fake.*@example.invalid`, `FAKE-NNNNNN` national
ids, `555-0xxx` phones, `*** Fake St` addresses), and no key in any V1 config
holds the contract-reserved `bulk_export` scope.

## The core demos

| Dataset | Sensitivity | What it covers | Persona that owns row access |
| --- | --- | --- | --- |
| `benefits_casework` | personal | Households, persons, benefit cases, payments. Eligibility, grievance follow-up, reconciliation. | `casework_system` |
| `clinic_capacity` | confidential | Health facilities, monthly service capacity, medicine stock events. Emergency planning and supply. No patient data. | `casework_system` for operational follow-up |
| `public_works_projects` | confidential | Infrastructure projects, contracts, milestones, disbursements. Non-personal but commercially and politically sensitive. | `casework_system` for operational follow-up |
| `education_registry` | personal | Students, guardians, schools, enrolments, support needs, attendance. Scholarship, transport, meals, planning. | `casework_system` |
| `subject_registry` | confidential | Canonical subject identifiers and per-dataset aliases that point to the same human. Contains no personal fields; only ids. | `linkage_service` only |

## Optional Social Protection Digital Convergence Initiative (SP DCI) registries

| Dataset | Sensitivity | What it covers | Persona that owns row access |
| --- | --- | --- | --- |
| `disability_registry` | personal | Disabled-person status, details, support fields, plus small synthetic SR, CRVS, and FR sync-search records exposed through the SP DCI adapter. | `casework_system` |

This demo is separate from `all_demos.yaml` because it requires the optional
`spdci-api-standards` feature and, for response shaping, the optional CEL
mapping feature. The sample workbook includes `DR-MEMBER-001` through
`DR-MEMBER-080`, `SR-GROUP-001` through `SR-GROUP-080`, `FAKE-810001` through
`FAKE-810080` for CRVS, and `FR-MEMBER-001` through `FR-MEMBER-080`;
`DR-MEMBER-001` has an approved disability status and is useful for quick sync
API checks.

The subject registry is the only place where personal-data identifiers from
two datasets are knowingly tied together. Reading its rows is scoped to a
single persona (`linkage_service`), requires `Data-Purpose`, and audits per
call. The registry has no relationships into personal datasets; cross-dataset
composition happens client-side, with separate audited calls per dataset.

## Personas

| Key id | Scopes (across all five demos) |
| --- | --- |
| `catalog_viewer` | `<dataset>:metadata` only, for every dataset |
| `planning_analyst` | `metadata` + `aggregate` on every dataset |
| `casework_system` | `metadata` + `rows` + selected `verify`/`aggregate` on personal datasets (benefits, education) plus row scopes on operational non-personal datasets (clinic, public works) where cross-demo follow-ups need them. Explicitly **no** `subject_registry:rows`. |
| `verification_service` | `<dataset>:verify` only, for every dataset |
| `linkage_service` | `subject_registry:metadata` + `subject_registry:rows` + `subject_registry:aggregate` only. The sole persona authorised to resolve cross-dataset aliases. **No** row access to benefits or education. |
| `operations_admin` | `admin` plus `metadata` on every dataset |

The single Bruno environment maps the raw keys to friendly variable names so
each request only carries the persona it claims to be:

| Bruno variable | Persona |
| --- | --- |
| `metadataKey` | `catalog_viewer` |
| `aggregateKey` | `planning_analyst` |
| `rowsKey` | `casework_system` |
| `verifyKey` | `verification_service` |
| `linkageKey` | `linkage_service` |
| `adminKey` | `operations_admin` |

## Refreshing the synthetic data

The XLSX workbooks under `demo/data/` are generated, not edited by hand:

```bash
uv run demo/scripts/generate_demo_data.py
```

The generator is deterministic: a single `random.Random(42)` threads through
every draw, and the writer canonicalises the XLSX zip (sorted entries, pinned
timestamps, normalised `docProps/core.xml`) so re-runs are byte-identical.

Cross-dataset alias coordination is enforced in the generator, not left to
chance:

- household ids (`hh-1001+`) are shared between benefits and the subject
  registry's `benefits_household_alias`;
- person ids (`per-2001+`) flow from benefits into the registry's
  `benefits_person_alias`;
- student ids (`stu-2001+`) flow from education into the registry's
  `education_student_alias`;
- guardian ids (`gua-2501+`) flow from education into the registry's
  `education_guardian_alias`;
- public works `asset_ref` for projects in the `schools` or `clinics` sector
  draws from real `sch-3001+` or `fac-4001+` ids, so the cross-demo
  school-construction and clinic-rehabilitation flows resolve to real rows;
- about one third of benefits persons in the registry sample are matched to
  an education student, mirroring a realistic partial-overlap population.
- the optional SP DCI workbook is generated in the same run and uses
  deterministic demo identifiers for DR, SR, CRVS, and FR sync request examples.

The registry is a sample, not a universe: it covers a subset of subjects in
each dataset (currently ~263 rows for the seed). This keeps the primary sheet
under the 50-300 row spec cap and matches the operational reality that not
every administrative record is promoted to the cross-dataset linkage surface.

The generator runs disclosure-control distribution assertions for all 17
aggregates declared across the configs. Each aggregate has at least one
group below `min_group_size` (so suppression triggers) and at least one
group at or above it (so visible output exists). The script aborts before
writing if any assertion fails.

## Generating local keys

A separate script produces fresh SHA-256 key fingerprints for the configs and the
matching raw keys for Bruno:

```bash
just demo-keys
```

This writes two files in one go (both gitignored):

- `demo/.env.local` with `export <PERSONA>_HASH` and `export <PERSONA>_RAW`
  lines per persona. The `_HASH` values feed each config's `hash_env:` fields;
  the `_RAW` values are what Bruno sends as `Bearer` tokens.
- `bruno/registry-relay-demo/.env` with one `<PERSONA>_RAW=<value>` per persona,
  read by Bruno at collection load. The Bruno environment file at
  `bruno/registry-relay-demo/environments/local.bru` references these via
  `{{process.env.<NAME>}}`, so no raw keys are ever stored in the
  committed `local.bru` file.

Re-running the script always rotates both files together: there is no
persistence between runs.

If you want to inspect what would land in the Bruno `.env` without rewriting
either file, run:

```bash
uv run demo/scripts/generate_demo_keys.py --bruno
```

The script verifies every (raw, hash) pair before emitting anything, so
broken output never reaches a config or environment file.

To choose the right key for an API call, list the demo personas with the same
operation words used by the OpenAPI document:

```bash
just demo-keys-list
```

The compact listing shows the key id, Bruno variable, raw bearer key, and the
OpenAPI-style operations it unlocks, such as `List datasets`, `Get record`,
`Run aggregate`, `Verify record exists`, and `Create claim verification`.

After rotation, Bruno needs to re-read its collection `.env`. The simplest
way is to close and reopen the collection in the Bruno UI (right-click the
collection → close, then File → Open Collection → pick
`bruno/registry-relay-demo/`), or restart Bruno.

## Running a local server

Pick a config and source the env file before starting the server:

```bash
just demo-run demo/config/benefits_casework.yaml
```

For the cross-demo workflows, use the combined config which loads all five
datasets together:

```bash
just demo-run
```

`just demo-run` creates `demo/.env.local` first when it is missing, then
starts the server with `demo/config/all_demos.yaml`. Build the demo binary
shape without starting the server with:

```bash
just demo-build
```

To exercise the OGC API Features demo surface over the clinic facilities
collection, enable the feature flag:

```bash
just demo-run demo/config/all_demos.yaml ogcapi-features
```

The same works with `demo/config/clinic_capacity.yaml` if you only want the
clinic dataset. The OGC surface uses generalized public map points for
facilities; exact operational coordinates remain unprojected.

For the optional SP DCI sync demos, use the feature-gated config:

```bash
just demo-run demo/config/disability_registry.yaml spdci-api-standards,standards-cel-mapping
```

Example sync status request:

```bash
curl -sS -X POST http://127.0.0.1:4242/dci/dr/registry/sync/disabled \
  -H "Authorization: Bearer $VERIFICATION_SERVICE_RAW" \
  -H "Content-Type: application/json" \
  -d '{"message":{"transaction_id":"demo-dr-001","disabled_criteria":{"query":{"personal_details.member_identifier":{"eq":"DR-MEMBER-001"}}}}}'
```

For disability details and support, call
`/dci/dr/registry/sync/get-disability-details` and
`/dci/dr/registry/sync/get-disability-support` with `$CASEWORK_SYSTEM_RAW`.

The same config exposes generic DCI sync search under named registry routes.
All examples use `casework_system` because sync search requires the entity read
scope.

Disability Registry (`dr`):

```bash
curl -sS -X POST http://127.0.0.1:4242/dci/dr/registry/sync/search \
  -H "Authorization: Bearer $CASEWORK_SYSTEM_RAW" \
  -H "Content-Type: application/json" \
  -d '{"message":{"transaction_id":"demo-search-001","search_request":[{"reference_id":"ref-demo-search-001","timestamp":"2026-01-01T00:00:00Z","search_criteria":{"query_type":"idtype-value","query":{"type":"DISABILITY_ID","value":"DR-MEMBER-001"}}}]}}}'
```

Social Registry (`sr`):

```bash
curl -sS -X POST http://127.0.0.1:4242/dci/sr/registry/sync/search \
  -H "Authorization: Bearer $CASEWORK_SYSTEM_RAW" \
  -H "Content-Type: application/json" \
  -d '{"message":{"transaction_id":"demo-sr-search-001","search_request":[{"reference_id":"ref-demo-sr-search-001","timestamp":"2026-01-01T00:00:00Z","search_criteria":{"query_type":"idtype-value","query":{"type":"GROUP_ID","value":"SR-GROUP-001"}}}]}}}'
```

Civil Registration and Vital Statistics (`crvs`):

```bash
curl -sS -X POST http://127.0.0.1:4242/dci/crvs/registry/sync/search \
  -H "Authorization: Bearer $CASEWORK_SYSTEM_RAW" \
  -H "Content-Type: application/json" \
  -d '{"message":{"transaction_id":"demo-crvs-search-001","search_request":[{"reference_id":"ref-demo-crvs-search-001","timestamp":"2026-01-01T00:00:00Z","search_criteria":{"query_type":"idtype-value","query":{"type":"UIN","value":"FAKE-810001"}}}]}}}'
```

Farmer Registry (`fr`):

```bash
curl -sS -X POST http://127.0.0.1:4242/dci/fr/registry/sync/search \
  -H "Authorization: Bearer $CASEWORK_SYSTEM_RAW" \
  -H "Content-Type: application/json" \
  -d '{"message":{"transaction_id":"demo-fr-search-001","search_request":[{"reference_id":"ref-demo-fr-search-001","timestamp":"2026-01-01T00:00:00Z","search_criteria":{"query_type":"idtype-value","query":{"type":"FARMER_ID","value":"FR-MEMBER-001"}}}]}}}'
```

You can also point to a config via env var instead of `--config`:

```bash
export REGISTRY_RELAY_CONFIG=demo/config/all_demos.yaml
cargo run
```

`all_demos.yaml` routes the audit log to a file sink at
`demo/var/audit.jsonl` (rotated at 50 MB, 5 files retained). Single-dataset
configs keep audit on stdout so the running terminal shows the trail. The
file sink path is created at startup if missing; the `demo/var/` directory
is gitignored.

Operational logs stay on stderr as readable text during local demo runs. Set
`REGISTRY_RELAY_LOG_FORMAT=json` when you want those logs as JSONL for
collection or a redirected file.

## Bruno collection

Open `bruno/registry-relay-demo/` in Bruno, then pick the **local** environment.
The environment file pre-fills the cross-demo defaults the requests reference:

| Variable | Default | Purpose |
| --- | --- | --- |
| `baseUrl` | `http://127.0.0.1:4242` | Server bind in every config |
| `purpose` | a short identifier | `Data-Purpose` value used by personal-data reads |
| `district` | `riverbend` | Shared district id used by district-planning flow |
| `clinicBbox` | `38.5,10.5,39.5,11.5` | CRS84 bbox around the demo riverbend clinic map points |
| `schoolId` | `sch-3001` | School id used by school-construction flow |
| `facilityId` | `fac-4001` | Facility id used by clinic-rehab flow |
| `studentAlias` | `stu-2001` | Student id used by scholarship + subject lookups |
| `benefitsPersonAlias` | `per-2001` | Benefits person id used by verify and subject lookups |
| `canonicalId` | `sub-9001` | Canonical subject id used by registry lookups |
| `metadataKey` / `aggregateKey` / `rowsKey` / `verifyKey` / `linkageKey` / `adminKey` | from the keygen output | Per-persona raw bearer tokens |

The collection is grouped by capability and dataset:

- per-dataset folders (`Benefits Casework`, `Clinic Capacity`,
  `Public Works Projects`, `Education Registry`, `Subject Registry`) contain
  positive flows plus the spec-listed dataset-local negative checks;
- `Auth Boundaries` is the canonical cross-cutting suite of denial cases
  (401, 403, 400 `auth.purpose_required`, 400 `entity.filter_required`);
- `OGC API Features` exercises the feature-gated `/ogc/v1` surface over
  `clinic_capacity.facilities`;
- `Cross-Demo Workflows` contains the four spec-required sequences plus
  emergency planning, and assumes `all_demos.yaml` is running.

## Walking the scholarship eligibility flow

This is the canonical cross-dataset story the demo pack is designed to
exercise. It is intentionally split across personas so the audit trail
shows three different consumers each making one scoped call, instead of one
caller pulling a giant joined extract.

Start the server with the combined config:

```bash
set -a; source demo/.env.local; set +a
cargo run -- --config demo/config/all_demos.yaml
```

In Bruno, run the `Cross-Demo Workflows` folder requests 11 through 14
in order:

1. **`11-scholarship-verify-student.bru`** uses `verifyKey`
   (`verification_service`) to call `GET /datasets/education_registry/student/verify?id={{studentAlias}}`.
   Returns 200 (existence confirmed) without giving back any row content.
2. **`12-scholarship-subject-lookup.bru`** uses `linkageKey`
   (`linkage_service`) to call `GET /datasets/subject_registry/subject?education_student_alias={{studentAlias}}`.
   This is the only call in the flow that returns the cross-dataset alias
   mapping. The response carries the matching `benefits_household_alias`.
3. **`13-scholarship-read-household.bru`** uses `rowsKey`
   (`casework_system`) with the alias from step 2 to call
   `GET /datasets/benefits_casework/household?id=<benefits_household_alias>`.
4. **`14-scholarship-benefits-district-aggregate.bru`** uses `aggregateKey`
   (`planning_analyst`) to run a benefits aggregate that gives the
   district-level eligibility picture without enumerating households.

After the four calls finish, tail the audit log to see all four entries:

```bash
tail -n 20 demo/var/audit.jsonl | jq .
```

You should see one record per call, each tagged with the requesting persona,
the dataset and entity, the purpose header, the response code, and a
correlation id. Crucially, no single persona has the union of scopes used
across the four calls: the audit trail is what makes the composite read
visible.

## Cross-demo flows at a glance

The `Cross-Demo Workflows` folder also contains:

- **District planning (requests 01-04)**: same `district` value across
  benefits, education, clinic, and public works aggregates. Single persona
  (`aggregateKey`) because these are all aggregate reads.
- **School construction follow-up (05-07)**: public works project with
  `asset_ref={{schoolId}}` → education school record → enrolment aggregate.
  `asset_ref` is a client-side soft pointer, not a system-enforced foreign
  key.
- **Clinic rehabilitation follow-up (08-10)**: public works project with
  `asset_ref={{facilityId}}` → clinic facility record → service capacity.
- **Scholarship eligibility (11-14)**: the four-step flow described above.
- **Emergency planning (15-17)**: clinic stockout aggregate → benefits
  district aggregate → public works delayed projects in district. Three
  personas, three audit entries, one composite situational picture.

## What's intentionally unavailable in V1

- **Bulk export.** Every entity declares a `bulk_export_scope` string (it's
  a required field in the platform schema), but no key in any V1 demo
  config is granted that scope. The Bruno collection contains no
  bulk-export request. The surface is contract-reserved for a future
  version.
- **Registry-wide admin reload.** The `operations_admin` persona carries
  `admin` plus per-dataset `metadata` scopes for dataset discovery, but
  there is no Bruno request that exercises a reload endpoint. Operational
  reload is out of scope for the demo pack.
- **Cross-dataset relationships at config level.** V1 relationships are
  scoped to entities inside one dataset. Cross-dataset reuse is
  demonstrated through client-side Bruno workflows, not through declared
  foreign keys.
- **Streaming or push delivery.** Every endpoint is request/response. The
  audit file sink is the only durable artifact produced by a request flow.

## Layout

```
demo/
  README.md
  .env.local            # gitignored; produced by generate_demo_keys.py
  config/
    benefits_casework.yaml
    clinic_capacity.yaml
    public_works_projects.yaml
    education_registry.yaml
    subject_registry.yaml
    disability_registry.yaml # optional; requires spdci-api-standards
    all_demos.yaml      # combined config, used by Cross-Demo Workflows
  data/
    *.xlsx              # synthetic, regenerated by generate_demo_data.py
  scripts/
    generate_demo_data.py
    generate_demo_keys.py
  var/                  # gitignored; audit.jsonl lands here under all_demos
```
