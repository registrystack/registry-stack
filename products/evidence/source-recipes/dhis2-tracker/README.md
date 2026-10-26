# DHIS2 Tracker source recipe

This recipe represents the sanitized DHIS2 Tracker 2.43 collection contract
already exercised by Registry Stack's reference adapter. It performs an exact
lookup by tracked-entity identifier, asks for page 1 with a page size of 2,
checks pager consistency, distinguishes no match from ambiguity, and extracts a
configured status attribute plus the returned record identity.

Extraction receives the same minimized authorized selector used for request
preparation. A unique response becomes a match only when its `trackedEntity` is
the same scalar type and exact value as the requested `record_reference`.
Missing, wrongly typed, or different returned identity is a source protocol
error before facts, assertion derivation, or signing. Business derivations do
not need to repeat this reusable source-identity check.

It assumes the selected DHIS2 deployment supports:

- `GET /api/tracker/trackedEntities`;
- the `program`, `orgUnits`, `trackedEntities`, `fields`, `pageSize`, `page`, and
  `totalPages` query parameters as used in Tracker 2.43;
- the projected `pager` and `trackedEntities[].attributes[]` response shape;
- exact tracked-entity identifiers and the configured program, organisation
  unit, and status-attribute UIDs.

Those assumptions are pinned recipe inputs, not a general claim about DHIS2.
Review the provider's documentation and run a read-only compatibility exercise
against the exact deployment and version. The recipe contains no server origin
or Basic-auth credential. Bind both in the target-owned `connections` entry.

The `fixture-validation/` project is the seed used by the maintained integration
gate. The gate imports the recipe first, then adds the separately reviewed
synthetic assertion definitions, because a source export must never supply
assertion meaning. Its cases cover success, no match, ambiguity, an inconsistent
pager, and returned tracked-entity value and scalar-type mismatches. Run it from
the Registry Stack source tree or the downloaded catalog with matching installed
binaries:

```sh
bash ../run-fixtures.sh
```
