<!-- SPDX-License-Identifier: Apache-2.0 -->
# DHIS2 Health Source Parity Gate

The built-in `http_json` DHIS2 health-programme source
([`examples/dhis2-health-sidecar.yaml`](../examples/dhis2-health-sidecar.yaml))
replaces the OpenFn job `dhis2-health-lookup.js` (in registry-lab, at
`config/openfn/jobs/dhis2-health-lookup.js`). The two paths MUST produce
identical Registry Data API (RDA) records for the same tracked entity. This
note describes the parity gate that proves it.

This gate is **CI / live-DHIS2 bound**. It cannot run in an environment that
cannot reach a live DHIS2 instance, and it is not exercised by `cargo test`.

## What "parity" means here

For a fixed set of tracked entity ids on the DHIS2 play instance
(`https://play.im.dhis2.org/stable-2-43-0`), the RDA record returned by the
built-in source must equal, field for field, the record the OpenFn job would
return. The fields are:

```
tracked_entity, org_unit, first_name, last_name,
child_program_code, child_program_status, child_program_active,
child_age_band, reconciliation_ref,
maternal_pnc_status, maternal_pnc_active,
child_health_visit_recorded, child_health_visit_count,
tb_program_status, tb_program_active
```

## DHIS2 query-shape assumptions (must be confirmed by the live smoke)

The OpenFn job fetched a single tracked entity via
`GET /api/tracker/trackedEntities/{id}`, whose JSON root *is* the entity. The
built-in `http_json` engine uses LITERAL paths, so the id cannot go in the
path. The built-in source instead queries the tracker **collection** endpoint:

```
GET /api/tracker/trackedEntities?trackedEntities={id}&orgUnitMode=ALL&fields=...
```

and the response CEL reads element `[0]` of the `trackedEntities` array.

Two things MUST be confirmed by the live smoke
([`scripts/smoke-http-json-dhis2-health-sidecar.sh`](../scripts/smoke-http-json-dhis2-health-sidecar.sh)):

1. **Request parameter name.** DHIS2 docs are inconsistent between
   `trackedEntities` (plural, used in the request-parameter table and response
   examples) and `trackedEntity` (singular, used in one prose example). The
   built-in source uses `trackedEntities`. If the live server rejects it, the
   manifest query key and the smoke script must switch to `trackedEntity`.
2. **Response root key.** The built-in source reads `body.trackedEntities`.
   Confirm the live collection response uses that root key (not `instances`).

The collection endpoint also requires either an explicit `orgUnit` or
`orgUnitMode=ALL`/`ACCESSIBLE` when filtering by explicit UID; the source sends
`orgUnitMode=ALL`.

## CEL ↔ JS field mapping

| RDA field | OpenFn JS | Built-in CEL (crosswalk-core 0.2.x macros) |
| --- | --- | --- |
| `tracked_entity` | `trackedEntity.trackedEntity` | `body.trackedEntities[0].trackedEntity` |
| `org_unit` | `trackedEntity.orgUnit` | `body.trackedEntities[0].orgUnit` |
| `first_name` | `attributeValue('w75KJ2mc4zz')` | `filter(a, a.attribute=='w75KJ2mc4zz')` + size guard + `[0].value` |
| `last_name` | `attributeValue('zDhUuAYrxNC')` | same pattern for `zDhUuAYrxNC` |
| `child_program_code` | constant `DHIS2_CHILD_PROGRAM` | literal `"DHIS2_CHILD_PROGRAM"` |
| `child_program_status` | `childEnrollment?.status ?? null` | filter `IpHINAT79UW` + size guard + `[0].status` |
| `child_program_active` | `isActive(CHILD_PROGRAM)` | `exists(e, e.program=='IpHINAT79UW' && e.status=='ACTIVE')` |
| `child_age_band` | `childEnrollment ? '5_to_17' : 'unknown'` | `exists(e, e.program=='IpHINAT79UW') ? '5_to_17' : 'unknown'` |
| `reconciliation_ref` | `` `${PREFIX}${trackedEntity}` `` | `'dhis2:tracked-entity:' + body.trackedEntities[0].trackedEntity` |
| `maternal_pnc_status` | `enrollment('uy2gU8kT1jF')?.status ?? null` | filter + size guard + `[0].status` |
| `maternal_pnc_active` | `isActive('uy2gU8kT1jF')` | `exists(e, e.program=='uy2gU8kT1jF' && e.status=='ACTIVE')` |
| `child_health_visit_recorded` | `childEvents.some(COMPLETED && stage in [birth,postnatal])` | nested `exists(e, e.program=='IpHINAT79UW' && e.events.exists(ev, ev.status=='COMPLETED' && (ev.programStage=='A03MvHHogjR' || ev.programStage=='ZzYYXq4fJie')))` |
| `child_health_visit_count` | `childEvents.length` (all events across child enrollments) | `size(first child enrollment's events)` — see assumption below |
| `tb_program_status` | `enrollment('ur1Edk5Oe2n')?.status ?? null` | filter + size guard + `[0].status` |
| `tb_program_active` | `isActive('ur1Edk5Oe2n')` | `exists(e, e.program=='ur1Edk5Oe2n' && e.status=='ACTIVE')` |

### `child_health_visit_count` assumption

The JS counts events across *all* child-program enrollments
(`enrollments.filter(program==CHILD).flatMap(events).length`). DHIS2 normally
allows at most one enrollment per program per tracked entity, and the JS
`enrollment()` helper uses `.find` (first match). CEL's macro set
(`filter`/`map`/`exists`/`exists_one`/`all`) has **no fold/sum**, so a true
cross-enrollment sum is not expressible in `http_json`. The built-in source
therefore counts the events of the *first* child-program enrollment, which
matches the OpenFn output for every real play-instance entity (single child
enrollment). If a tracked entity ever carried multiple child enrollments, this
single field would need an `http_flow` multi-step exception variant
(targeted enrollment/event filter, then `size()`); that exception is not needed
for the play instance and is intentionally deferred.

## How to run the gate

1. Capture the OpenFn job's RDA output for the fixed tracked entity ids (run the
   retained OpenFn-as-caller / lab pipeline, or the historical capture stored by
   CI) into a golden file.
2. Run the built-in source against the same live instance and tracked entities
   via [`scripts/smoke-http-json-dhis2-health-sidecar.sh`](../scripts/smoke-http-json-dhis2-health-sidecar.sh)
   (set `HTTP_JSON_DHIS2_HEALTH_PASSWORD`, optionally override
   `HTTP_JSON_DHIS2_HEALTH_TRACKED_ENTITY`).
3. Assert the two RDA records are byte-for-byte equal after canonical JSON
   ordering. The smoke script already asserts the derived-field invariants for
   the default tracked entity `PQfMcpmXeFE`; the full golden compare is the CI
   parity step.

## Things CI must verify (none verified locally)

- The DHIS2 collection query shape (parameter name, root key, `orgUnitMode`).
- That the CEL collection macros (`filter`/`map`/`exists`/`exists_one`/`all`)
  are available in the linked `crosswalk-core` 0.2.x release.
- Byte-for-byte parity of the built-in source vs the OpenFn job for the fixed
  tracked entity ids.
