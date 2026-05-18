---
name: registry-relay-config-review
description: Use when reviewing or troubleshooting registry-relay V1 YAML configuration for spec compliance, security, disclosure control, schema/entity validation, scope isolation, relationships, aggregates, audit settings, or readiness failures.
---

# Registry Relay Config Review

Use this skill to review `registry-relay` V1 configs before deployment or when `/ready`, config loading, entity routing, or disclosure behavior is wrong.

## Bundled Contract

This skill is self-contained. Do not assume access to the `registry-relay` repository or Rust source code.

Before reviewing a config, read:

- `references/v1-config-contract.md`

Use that bundled reference as the source of truth for V1 syntax, constraints, routes, security posture, and review checks.

## Review Workflow

1. Establish the target surface.
   - List each dataset.
   - List private storage tables.
   - List public entities and their backing tables.
   - Confirm no public-facing route, name, doc, or catalog field treats a storage table as the REST resource.

2. Validate identifiers and reserved words.
   - Dataset, table, entity, field, relationship, aggregate, and API-key IDs should be lower-snake and start with a letter.
   - Entity names must not collide with `catalog`, `admin`, `health`, `ready`, or `openapi.json`.
   - Current code also rejects relationship names `aggregates`, `schema`, `verify`, and `exports`.

3. Check storage schemas.
   - Sensitive administrative data should normally use `schema.strict: true`.
   - Every entity backing table must declare a `primary_key`.
   - Physical field types must match source data and relationship foreign keys.
   - XLSX configs should identify the correct sheet and avoid merged-cell or multi-table sheets unless `header_row` or `data_range` isolates a clean rectangle.

4. Check entity projections.
   - If `fields` is present, hidden columns must not appear in schema, row output, filters, aggregates, catalog output, OpenAPI, or SHACL.
   - Exactly one exposed entity field must map to the backing table primary key.
   - Exposed field names, not hidden storage names, should drive public filters, aggregate columns, and verify parameters.
   - Semantic annotations should be declarative only: URI expansion is allowed, URI fetching or inference is not part of V1.

5. Check relationships.
   - Targets must exist in the same dataset.
   - For `belongs_to`, the FK is on the source entity's table.
   - For `has_many` and `has_one`, the FK is on the target entity's table.
   - FK and target primary-key physical types must match.
   - `api.allowed_expansions` may include only declared relationships and should be intentionally narrow.
   - Cross-dataset and multi-hop relationships are out of scope for V1.

6. Check access isolation.
   - Each entity must have `metadata_scope`, `aggregate_scope`, `read_scope`, and `verify_scope`.
   - API keys should have the minimum scopes needed by their consumer.
   - Aggregate-only keys must not read rows.
   - Verify-only keys must not access catalog, schema, rows, aggregates, or claim verification.
   - `admin` should be separate from data scopes and used only for reload.
   - If personal data is exposed, prefer `require_purpose_header: true` for entities with row or verify access.

7. Check query controls.
   - Filters must be explicit allowlists.
   - Unknown fields and unsupported operators should fail closed.
   - `limit` must be bounded by `default_limit` and `max_limit`.
   - There must be no offset pagination, arbitrary SQL, total counts, or CSV streaming endpoint in V1.

8. Check aggregates and disclosure.
   - Every aggregate needs a disclosure-control policy, even if it relies on defaults.
   - `min_group_size` must be at least 1; use 5 or higher for personal data unless explicitly justified.
   - `suppression` must be `omit` or `mask`.
   - Cross-entity aggregates must follow declared direct relationships and compute suppression over distinct base-entity rows after the join.
   - Aggregate response shapes must report `suppressed_groups` and must not leak row-level values through small groups.

9. Check audit and deployment posture.
   - Audit records must never include raw API keys, raw hashes, secrets, or row-level personal data.
   - Sensitive filter values should be hashed deterministically when audit lookup still needs to work.
   - `stdout` audit sink is fine for containers; `file` requires rotation settings; `syslog` is for local forwarding.
   - `/admin/*` should be isolated by `server.admin_bind` or network policy.
   - Default CORS should remain deny unless client origins are known.

## Validation

Perform a structural review against `references/v1-config-contract.md`. Do not require repository access to complete the review.

If the user supplies loader errors, readiness output, audit samples, or validation logs from a `registry-relay` deployment, map them back to the bundled contract and include them in the findings. Never ask for production secrets or full environment dumps.

## Review Output

Lead with actionable findings, ordered by severity. Include file and line references when reviewing a concrete config.

Use this shape:

```markdown
Findings
- [Severity] file:line - What is wrong, why it violates V1, and the concrete fix.

Open Questions
- Only include questions that block correctness or deployment safety.

Verification
- Structural checks performed.
- Supplied runtime evidence reviewed, if any.
```

If there are no findings, say that clearly and still name the checks that ran and any residual risk.

## Common Failure Patterns

- Entity `allowed_filters` references a storage column hidden by projection.
- Entity primary key column is hidden or exposed twice.
- `has_many` FK is checked on the wrong table.
- Verify-only API key accidentally also receives metadata or row scopes.
- Aggregate groups by a related field without declaring `joins`.
- Aggregate measure references `household.region`; V1 measures must be base-entity exposed fields.
- Config example drifts from the bundled V1 contract.
- The config loads, but the public model still looks like a spreadsheet wrapper rather than domain entities.
