---
name: registry-relay-config-author
description: Use when a user has a CSV, XLSX, or Parquet file and wants to expose it with registry-relay, or when creating/modifying registry-relay V1 YAML configuration for datasets, private tables, entities, relationships, scopes, filters, aggregates, semantic URIs, audit, or server settings.
---

# Registry Relay Config Author

Use this skill to turn a user's CSV, XLSX, or Parquet file into a `registry-relay` V1 config that exposes protected, read-only, domain-oriented REST APIs.

## Bundled Contract

This skill is self-contained. Do not assume access to the `registry-relay` repository or Rust source code.

Before drafting a non-trivial config, read:

- `references/v1-config-contract.md`

Use that bundled reference as the source of truth for V1 syntax, constraints, routes, security posture, and review checks.

For file inspection, use:

- `scripts/inspect_tabular.py`

The script emits JSON describing CSV columns, XLSX sheets, or Parquet schema when optional Parquet libraries are available. It redacts sample values by default.

## Authoring Workflow

1. Inspect the user's file.
   - If the user gave a local file path, run `scripts/inspect_tabular.py <path>`.
   - For XLSX, identify candidate sheets and whether each sheet is a clean rectangle.
   - For CSV, identify delimiter, headers, sample rows, and likely column types.
   - For Parquet, inspect the schema if `pyarrow` or `duckdb` is available; otherwise ask the user for schema or a sample.
   - Keep sample values redacted unless the user explicitly says the file is synthetic or safe to inspect with `--show-samples`.
   - Do not print sensitive sample values in the final answer. Use them only to infer types and relationships.

2. Identify the dataset and source file.
   - V1 source type is `file`.
   - Supported formats are CSV, XLSX, and Parquet.
   - For XLSX, declare one private `tables` entry per sheet.
   - Use `header_row` or `data_range` only when the sheet has surrounding noise.

3. Ask only for decisions the file cannot reveal.
   - Dataset title, owner, publisher/base URL, and update cadence if unknown.
   - Which columns are identifiers, foreign keys, sensitive fields, and fields safe to expose.
   - Which domain entities the file represents. Infer obvious candidates, but do not pretend a sheet name is automatically the public entity model.
   - Which consumers need metadata, aggregate, row, verify, bulk export, or admin scopes.
   - Which filters, expansions, and aggregates are safe and useful.

4. Declare catalog and dataset metadata.
   - Include `id`, `title`, `description`, `owner`, `sensitivity`, `access_rights`, and `update_frequency`.
   - Use lower-snake identifiers that start with a letter.
   - Add `vocabularies` and `conforms_to` when semantic alignment is known.

5. Model storage first.
   - Put physical file/table details under `datasets[].tables`.
   - Every table that backs an entity needs a `primary_key`.
   - Prefer `schema.strict: true` for sensitive administrative data.
   - Declare physical field `type`, `nullable`, and useful `codelist`, `unit`, `language`, or `concept_uri` annotations.
   - Do not expose table IDs as public route concepts.

6. Model public entities second.
   - Put public REST resources under `datasets[].entities`.
   - Each V1 entity is backed by exactly one table.
   - Use `fields` to project and rename the wire shape. When `fields` is present, unlisted columns are hidden from schema, rows, aggregates, catalog, and docs.
   - Ensure exactly one exposed field maps to the backing table primary key.
   - Use entity names and exposed field names in public API settings, not storage column names, unless they intentionally match.

7. Add relationships deliberately.
   - `belongs_to`: `foreign_key` is on this entity's table.
   - `has_many` and `has_one`: `foreign_key` is on the target entity's table.
   - Relationships only target entities in the same dataset in V1.
   - Only list relationships in `api.allowed_expansions` when clients may use `?expand=`.

8. Assign scopes independently.
   - Declare `metadata_scope`, `aggregate_scope`, `read_scope`, `verify_scope`, and `bulk_export_scope` on each entity.
   - Common default strings are `<dataset>:metadata`, `<dataset>:aggregate`, `<dataset>:rows`, `<dataset>:verify`, and `<dataset>:bulk_export`.
   - Do not assume aggregate or verify access implies row access.
   - Use an `admin` scope only for `/admin/reload`.
   - `auth.api_keys[].hash_env` names an environment variable containing an Argon2id PHC hash. Never put raw keys or hashes directly in comments, examples, logs, or final answers.

9. Keep query access narrow.
   - Add `allowed_filters` only for fields consumers genuinely need.
   - Supported ops are `eq`, `in`, `gte`, `lte`, and `between`.
   - Use `default_limit` and `max_limit` to cap row responses.
   - Set `require_purpose_header: true` for row or verify access to personal data unless the deployment explicitly does not require purpose logging.

10. Add aggregates with disclosure control.
   - Aggregates live on entities, not storage tables, for V1 public APIs.
   - Supported functions are `count`, `sum`, `avg`, `min`, `max`; current config also accepts `median`, `count_distinct`, and `stddev`.
   - For cross-entity aggregates, add `joins` and use direct relationship prefixes such as `household.region`.
   - Set `disclosure_control.min_group_size` and `suppression`. Defaults are `5` and `omit`, but writing them explicitly is clearer for sensitive data.

11. Choose audit and server settings.
   - `audit.sink: stdout` is the default container-friendly path.
   - Use `file` with rotation for VM deployments when required.
   - Default CORS is deny. Add `server.cors.allowed_origins` only for known client origins.
   - Use `server.admin_bind` when the deployment separates admin traffic.

## File-To-Config Defaults

When the user wants a first draft and has not answered every modeling question:

- Use the file stem as the dataset id after converting to lower-snake.
- For a single CSV or Parquet, create one private table and one public entity unless the user describes multiple domain objects.
- For XLSX, create one private table per relevant sheet. Create public entities only for sheets that represent domain objects, not lookup/helper sheets unless the user wants them exposed.
- Prefer exposing identifier, status, geography, date, and operational reference fields. Hide direct personal identifiers, free-text notes, raw addresses, phone numbers, email, national IDs, and other high-sensitivity columns unless the user explicitly needs row-level access to them.
- Add metadata and aggregate keys before row keys. Add verify-only keys only when there is a clear existence-check use case.
- Start with `allowed_filters` on primary key and stable geography/status/date fields. Do not add filters for every column.
- Start with no row-level aggregates unless the aggregate is useful and disclosure-safe.
- Use placeholder `hash_env` names such as `<CONSUMER>_API_KEY_HASH`, not secret values.

## Validation Loop

After drafting a config:

1. Check the YAML against the skeleton and field tables in `references/v1-config-contract.md`.
2. Confirm every storage table, entity, relationship, scope, filter, and aggregate reference resolves.
3. Confirm verify-only, aggregate-only, row, metadata, bulk-export, and admin scopes remain independent.
4. Confirm hidden storage columns are not used as public filters, aggregate columns, verify parameters, or documentation fields.
5. If the user supplies loader errors or validation logs from a `registry-relay` deployment, map them back to the bundled contract and revise the YAML. Do not require repository access to complete the config draft.
6. If env-backed API keys appear in examples, use placeholder environment variable names only. Do not print real secrets.

## Gotchas

- `tables` are private storage. Public URLs are built from `entities[].name`.
- If `fields` is present, every filter, aggregate group, aggregate measure, and verify primary-key parameter must use exposed entity field names.
- Verify-only keys must not be able to call catalog, schema, rows, aggregate, or bulk-export endpoints.
- Collection and expansion responses must not include total counts.
- `?expand=` requires read scope, and required purpose headers, for both the host entity and every expanded target.
- `resources` is an older alias still accepted by the code. Prefer `tables` for V1 configs.
- The current validator rejects relationship names `aggregates`, `schema`, `verify`, and `exports`. Avoid those names unless the implementation is changed to match the spec wording.
- Config hot reload is out of scope for V1. Changes to `config.yaml` require restart.
- Do not add unsupported source types, computed fields, arbitrary SQL, row-level write APIs, or UI settings to V1 config.
