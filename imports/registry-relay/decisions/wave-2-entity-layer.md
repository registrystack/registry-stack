# Wave 2 Entity Layer Kickoff

Status: locked for the entity-layer track before Wave 2 query API work. Spec: `Spec.md` with the 2026-05-15 entity-layer amendment.

This note turns the household/individual discussion into an implementation contract. The public API is entity-shaped. Storage tables remain private.

---

## 1. Decision Log

| # | Decision | Rationale |
|---|---|---|
| E1 | **Public unit is `entity`, storage unit is `table`.** `resource` is retired from the public V1 surface. | Avoids the API looking like a spreadsheet wrapper and removes ambiguity between REST resources, RDF resources, and tabular backing files. |
| E2 | **Each entity is backed by exactly one table in V1.** | Covers the social-registry XLSX case without introducing SQL views or materialized projections before a concrete consumer needs them. |
| E3 | **Relationships are declared in config.** Supported kinds: `belongs_to`, `has_many`, `has_one`. | Enough for household/individual traversal while keeping M:N join-table design deferred until there is a real case. |
| E4 | **Routes are dataset-scoped and entity-shaped.** Examples: `/datasets/social_registry/household`, `/datasets/social_registry/household/HH-42`, `/datasets/social_registry/household/HH-42/members`. | Preserves dataset-level auth and keeps entity names from colliding across datasets. |
| E5 | **Traversal surface is nested endpoints plus `?expand=`.** Filter-on-related is out of V1. | Handles natural client calls without opening a broad query language. |
| E6 | **Cross-entity aggregates are in V1.** Aggregates may group by directly related fields, e.g. `individual` grouped by `household.region`. | This is the first useful analytic payoff of relationships and should be designed in while the query layer is still unshipped. |
| E7 | **Expansion does not add a new disclosure-control system.** It requires row read scope on every expanded entity and never emits totals or counts. | Expansion only saves round trips for data a caller could already read. Counts remain aggregate-like and go through aggregate disclosure control. |
| E8 | **Catalog is entity-grain.** DCAT-AP describes datasets and entity distributions; SHACL node shapes describe entity schemas and relationships. CSVW is optional compatibility output. | Consumers should discover the domain model, not the backing workbook/sheet layout. |

---

## 2. Config Shape

The config has two layers under each dataset:

```yaml
tables:
  - id: households_table
    format:
      xlsx:
        sheet: Households
    primary_key: household_id
    schema: ...

entities:
  - name: household
    table: households_table
    fields:
      - name: id
        from: household_id
    relationships:
      - name: members
        kind: has_many
        target: individual
        foreign_key: household_id
```

Validation rules:

* entity names are unique within a dataset and do not collide with reserved route segments;
* every entity `table` exists;
* every projected `from` column exists on the backing table;
* exactly one exposed entity field maps to the backing table primary key;
* relationship targets exist in the same dataset;
* relationship foreign keys exist on the correct table for the relationship kind;
* FK physical type matches the target entity primary-key physical type;
* `has_one` warns when uniqueness cannot be statically verified;
* `allowed_filters`, `allowed_expansions`, aggregate `group_by`, and aggregate measure columns reference exposed entity fields or declared relationship-prefixed fields.

---

## 3. File Ownership

| Track | Owns | Notes |
|---|---|---|
| Entity config + validation | `src/config/**`, `src/entity/mod.rs` | Heavy implementer. Keep config structs serializable and validation errors stable. |
| Projection | `src/entity/projection.rs` | Maps table columns to entity fields and hides unlisted columns from all public schema/output paths. |
| Relationships | `src/entity/relationship.rs`, `src/query/joins.rs` | Heavy implementer. Produces typed join plans but does not execute arbitrary SQL from clients. |
| Readiness integration | `src/api/health.rs`, `src/ingest/mod.rs` | `/ready` reports failed table ingests and unresolved entities separately. |
| Fixtures/config | `config/example.yaml`, `fixtures/**`, focused integration tests | Migrate synthetic social registry to `household` + `individual`. |

No two tracks should write the same file concurrently.

---

## 4. Query Integration

The query layer consumes an `EntityRegistry` built after ingest config validation. It must never resolve a public request directly to a table ID.

Read paths:

* collection: entity projection + allowed base-field filters;
* single record: primary-key lookup on the exposed entity primary-key field;
* nested relationship: host primary-key lookup, relationship join, target projection;
* expansion: same join logic as nested relationship, capped at target `default_limit` for `has_many`, no total count.

Aggregate paths:

* single-entity aggregates read the base entity projection;
* cross-entity aggregates follow declared direct relationships only;
* `min_group_size` is computed over distinct base-entity rows after joins.

---

## 5. Exit Criteria

* The config validator rejects every invalid case listed in §2 with stable error codes.
* The fixture workbook exposes `household` and `individual` entities from separate sheets.
* `/ready` can distinguish failed table ingest from unresolved entity mapping.
* No public URL path contains `/resources/{resource_id}/rows`.
* Cross-entity aggregate planning supports `individual` grouped by `household.region`.
* Metadata planning targets entity-grain DCAT-AP + SHACL, with CSVW explicitly optional.

---

## 6. Deferred

* `has_many_through` and other M:N relationship forms.
* Filter-on-related syntax such as `/individual?household.region=...`.
* Multi-hop relationship paths in aggregates.
* Configured views or entities backed by multiple tables.
* Computed fields.
