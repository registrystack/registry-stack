# registry-relay V1 Config Contract

This reference is self-contained. Use it when reviewing `registry-relay` V1 YAML without access to the app repository or implementation spec.

## Product Shape

`registry-relay` is a config-driven Rust service that exposes sensitive tabular files as protected, read-only, domain-oriented REST APIs.

V1 has two layers under one binary:

- Storage layer: private `tables` read CSV, XLSX, or Parquet from a local file source and normalize them into internal tables.
- Entity layer: public `entities` map tables into domain REST resources with projected fields, relationships, access scopes, filters, expansions, aggregates, and semantic annotations.

Do not model the public API as spreadsheet rows. Public URLs are built from entity names, not table IDs.

V1 is:

- No UI.
- Read-only.
- REST-only.
- Config-file driven.
- Secure by default.
- API-key authenticated.
- Designed for future OIDC/JWT, dataspace tokens, data-space connectors, and richer sources, but those are not V1 config features.

## Canonical YAML Skeleton

```yaml
server:
  bind: 0.0.0.0:8080
  # admin_bind: 127.0.0.1:8081
  # cache_dir: ./cache
  # xlsx_max_file_bytes: 268435456
  # request_timeout: 30s
  # cors:
  #   allowed_origins:
  #     - https://client.example.gov
  # trust_proxy:
  #   enabled: true
  #   trusted_proxies:
  #     - 10.0.0.0/8

catalog:
  title: Internal Government Registry Relay
  base_url: https://data.example.gov
  publisher: Ministry of Digital Government

vocabularies:
  psc: https://publicschema.org/
  m8g: http://data.europa.eu/m8g/
  schema: https://schema.org/
  dct: http://purl.org/dc/terms/
  sdmx: http://purl.org/linked-data/sdmx/2009/concept#

auth:
  mode: api_key
  api_keys:
    - id: statistics_office
      hash_env: STATS_OFFICE_API_KEY_HASH
      scopes:
        - social_registry:metadata
        - social_registry:aggregate
    - id: program_system
      hash_env: PROGRAM_SYSTEM_API_KEY_HASH
      scopes:
        - social_registry:metadata
        - social_registry:aggregate
        - social_registry:rows
    - id: verification_service
      hash_env: VERIFICATION_SERVICE_API_KEY_HASH
      scopes:
        - social_registry:verify
    - id: operations_admin
      hash_env: OPERATIONS_ADMIN_API_KEY_HASH
      scopes:
        - admin

datasets:
  - id: social_registry
    title: Social Registry
    description: Registry of households participating in Program X
    owner: Ministry of Social Affairs
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    conforms_to:
      - psc:concepts/Person
      - psc:concepts/Enrollment
      - m8g:CorePerson

    source:
      type: file
      path: ./data/social_registry.xlsx
      # header_row: 1
      # data_range: A1:Z5000

    refresh:
      mode: mtime
      interval: 1h
      # Other modes:
      # mode: manual
      # mode: interval
      # interval: 1h

    tables:
      - id: households_table
        format:
          xlsx:
            sheet: Households
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
            - name: region_code
              type: string
              nullable: true
            - name: enrollment_date
              type: date
              nullable: true

      - id: individuals_table
        format:
          xlsx:
            sheet: Individuals
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
            - name: household_id
              type: string
              nullable: false
            - name: municipality_code
              type: string
              nullable: true
              codelist: https://www.insee.fr/codes/cog
            - name: payment_amount
              type: number
              nullable: true
              unit: EUR

    entities:
      - name: household
        title: Household
        description: A household participating in Program X
        table: households_table
        concept_uri: psc:concepts/Household
        fields:
          - name: id
            from: household_id
            concept_uri: psc:properties/householdIdentifier
          - name: region
            from: region_code
            concept_uri: m8g:Location
          - name: enrolled_on
            from: enrollment_date
            concept_uri: psc:properties/enrollmentDate
        relationships:
          - name: members
            kind: has_many
            target: individual
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: false
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: region
              ops: [eq, in]
          allowed_expansions: [members]

      - name: individual
        title: Individual
        description: A person enrolled in Program X
        table: individuals_table
        concept_uri: psc:concepts/Person
        fields:
          - name: id
            from: individual_id
            concept_uri: psc:properties/personIdentifier
          - name: household_id
            from: household_id
            concept_uri: psc:properties/householdIdentifier
          - name: municipality_code
            from: municipality_code
            concept_uri: m8g:Location
          - name: payment_amount
            from: payment_amount
            concept_uri: psc:properties/paymentAmount
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: true
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: household_id
              ops: [eq, in]
            - field: municipality_code
              ops: [eq, in]
          allowed_expansions: [household]
        aggregates:
          - id: by_municipality
            description: Number of individuals by municipality
            group_by:
              - municipality_code
            measures:
              - name: individual_count
                function: count
                column: id
            disclosure_control:
              min_group_size: 5
              suppression: omit
          - id: payments_by_municipality
            description: Total and average payments by municipality
            group_by:
              - municipality_code
            measures:
              - name: total_payment
                function: sum
                column: payment_amount
              - name: average_payment
                function: avg
                column: payment_amount
            disclosure_control:
              min_group_size: 5
              suppression: mask
          - id: by_household_region
            description: Number of individuals by household region
            joins:
              - relationship: household
            group_by:
              - household.region
            measures:
              - name: individual_count
                function: count
                column: id
            disclosure_control:
              min_group_size: 5
              suppression: omit

audit:
  sink: stdout
  format: jsonl
  # chain: false
  # include_health: false
  # For file sink:
  # sink: file
  # path: /var/log/registry-relay/audit.jsonl
  # rotate:
  #   max_size_mb: 100
  #   max_files: 14
```

## Top-Level Sections

Required top-level keys:

- `server`
- `catalog`
- `auth`
- `datasets`
- `audit`

Optional top-level key:

- `vocabularies`

Unknown fields should be treated as invalid.

## Identifier Rules

Use lower-snake identifiers starting with a lowercase ASCII letter:

- Valid: `social_registry`, `household`, `individual_2026`
- Invalid: `SocialRegistry`, `1_registry`, `social-registry`, `social registry`

Reserved entity names at `/datasets/{dataset_id}/...`:

- `catalog`
- `admin`
- `health`
- `ready`
- `openapi.json`

Reserved collection subroute words after an entity:

- `aggregates`
- `schema`
- `verify`
- `exports`

Avoid those as relationship names too, because some implementations reject them even though nested relationship paths include a concrete record ID.

## Server

`server.bind` is the public listener address.

Optional settings:

- `admin_bind`: separate admin listener for `/admin/*`.
- `cache_dir`: local cache directory.
- `xlsx_max_file_bytes`: size cap for XLSX ingestion.
- `request_timeout`: human duration such as `30s`.
- `cors.allowed_origins`: explicit allowlist. Empty or missing means default-deny.
- `trust_proxy.enabled`: whether proxy headers are trusted.
- `trust_proxy.trusted_proxies`: IP or CIDR values.

Admin routes should be isolated by `admin_bind` or network policy.

## Catalog

Fields:

- `title`
- `base_url`
- `publisher`

Catalog metadata is visible to authenticated metadata consumers and must not embed protected row data.

## Vocabularies And Semantic Alignment

`vocabularies` maps prefixes to URI bases. Any URI is accepted when it is absolute or uses a configured prefix.

Attachment points:

- `datasets[].conforms_to`
- `entities[].concept_uri`
- `entities[].fields[].concept_uri`
- `entities[].relationships[].concept_uri`
- table field annotations: `concept_uri`, `codelist`, `unit`, `language`
- entity field annotations: `concept_uri`, `codelist`, `unit`, `language`

V1 declares URIs only. It does not fetch, resolve, infer, validate codelist values, or reason over semantic URIs.

## Auth And Scopes

V1 auth mode:

```yaml
auth:
  mode: api_key
```

Each API key has:

- `id`: lower-snake identifier.
- `hash_env`: environment variable name containing an Argon2id PHC hash.
- `scopes`: list of granted scopes.

Never place raw keys or hash values in YAML.

Scope forms:

- `admin`
- `<dataset>:metadata`
- `<dataset>:aggregate`
- `<dataset>:rows`
- `<dataset>:verify`
- `<dataset>:bulk_export`

Deployments may use finer strings such as `<dataset>:<entity>:read` if every configured scope and key grant matches, but dataset-grained strings are the V1 default.

Scope meanings:

- `metadata`: catalog, dataset details, schema.
- `aggregate`: configured aggregate endpoints only.
- `rows`: collection, single-record, nested relationship, and expansion row reads.
- `verify`: one-bit existence check only.
- `bulk_export`: reserved contract for V1.x bulk export.
- `admin`: reload and future admin operations.

Scopes are independent. Aggregate access does not imply row access. Verify access does not imply metadata, aggregate, row, bulk-export, or admin access.

## Dataset

Required fields:

- `id`
- `title`
- `description`
- `owner`
- `sensitivity`
- `access_rights`
- `update_frequency`
- `source`
- `refresh`
- `tables`
- `entities`

Common enum values:

- `sensitivity`: `public`, `internal`, `personal`, `confidential`, `secret`
- `access_rights`: `public`, `restricted`, `non_public`
- `update_frequency`: `continuous`, `daily`, `weekly`, `monthly`, `quarterly`, `annual`, `irregular`, `unknown`

## Source

V1 supports only local files:

```yaml
source:
  type: file
  path: ./data/source.xlsx
```

Optional for noisy spreadsheets:

- `header_row`
- `data_range`

Future source types such as HTTP, S3, SharePoint, Google Drive, Nextcloud, and database tables are not V1.

## Refresh

Modes:

```yaml
refresh:
  mode: mtime
  interval: 60s
```

```yaml
refresh:
  mode: interval
  interval: 1h
```

```yaml
refresh:
  mode: manual
```

Config reload is restart-only in V1. Data reload can be driven by source mtime, interval, or `POST /admin/reload`.

## Tables

Tables are private storage declarations. One backing table per CSV file, XLSX sheet, or Parquet file.

Required fields:

- `id`
- `primary_key` when the table backs an entity
- `schema`

Optional `format`:

```yaml
format:
  csv:
    delimiter: 44
    quote: 34
```

```yaml
format:
  xlsx:
    sheet: Individuals
```

```yaml
format:
  parquet: {}
```

Exactly one format should be declared when `format` is present. If omitted, implementations may infer from the source file extension.

Schema:

```yaml
schema:
  strict: true
  fields:
    - name: field_name
      type: string
      nullable: false
```

Field types:

- `string`
- `number`
- `integer`
- `boolean`
- `date`
- `timestamp`

Use `strict: true` for sensitive data so missing columns, unexpected columns, or wrong physical types refuse table registration.

## Entities

Entities are the public REST resources.

Required fields:

- `name`
- `table`
- `access`
- `api`

Recommended fields:

- `title`
- `description`
- `concept_uri`
- `fields`
- `relationships`
- `aggregates`

Each V1 entity is backed by exactly one table. Views over multiple tables and computed fields are not V1.

Field projection:

- If `fields` is omitted, every backing table column is exposed under its physical name.
- If `fields` is present, only listed fields are exposed.
- `from` maps an exposed field name to a storage column.
- Missing `from` means the exposed field name is also the storage column name.
- Exactly one exposed field must map to the table `primary_key`.

Example:

```yaml
fields:
  - name: id
    from: individual_id
  - name: municipality_code
```

If a column is not exposed, it must not appear in public schema, row output, filters, aggregate group-by or measures, catalog output, OpenAPI, or SHACL. It can still be used internally for relationship joins.

## Relationships

Supported kinds:

- `belongs_to`: FK lives on this entity's table.
- `has_many`: FK lives on the target entity's table.
- `has_one`: FK lives on the target entity's table.

Fields:

- `name`
- `kind`
- `target`
- `foreign_key`
- optional `concept_uri`

Rules:

- `target` must be another entity in the same dataset.
- `foreign_key` must exist on the appropriate table for the relationship kind.
- FK physical type must match the target/source primary-key physical type.
- `has_one` should be unique on the target side. If uniqueness cannot be proven statically, treat it as a deployment risk.
- Cross-dataset, multi-hop, and many-to-many-through relationships are not V1.

## Entity Access

Every entity declares:

```yaml
access:
  metadata_scope: social_registry:metadata
  aggregate_scope: social_registry:aggregate
  read_scope: social_registry:rows
  verify_scope: social_registry:verify
  bulk_export_scope: social_registry:bulk_export
```

Use distinct scopes unless there is a deliberate deployment reason not to. Keep verify-only and aggregate-only consumers isolated.

## Entity API

Fields:

- `default_limit`
- `max_limit`
- `require_purpose_header`
- `allowed_filters`
- `allowed_expansions`

Example:

```yaml
api:
  default_limit: 100
  max_limit: 1000
  require_purpose_header: true
  allowed_filters:
    - field: id
      ops: [eq, in]
    - field: payment_amount
      ops: [gte, lte, between]
  allowed_expansions: [household]
```

Allowed filter operators:

- `eq`
- `in`
- `gte`
- `lte`
- `between`

Query syntax:

- `field=value` for `eq`
- `field.in=a,b,c`
- `field.gte=2026-01-01`
- `field.lte=2026-12-31`
- `field.between=2026-01-01,2026-12-31`

Unknown query parameters, unknown filter fields, and unallowed operators should fail with a 400-style problem response.

Use `require_purpose_header: true` for personal row or verify access unless the deployment explicitly does not require purpose logging. Purpose header value is opaque and logged for accountability.

## Aggregates

Aggregates are configured per entity.

Fields:

- `id`
- `description`
- optional `joins`
- `group_by`
- `measures`
- `disclosure_control`

Functions:

- `count`
- `sum`
- `avg`
- `min`
- `max`
- optional/currently accepted in some builds: `median`, `count_distinct`, `stddev`

Disclosure control:

```yaml
disclosure_control:
  min_group_size: 5
  suppression: omit
```

`suppression` values:

- `omit`: remove groups below the threshold.
- `mask`: preserve group keys, return null measures.

Rules:

- Personal data should normally use `min_group_size: 5` or higher.
- Aggregate responses must include `suppressed_groups`.
- Aggregate responses must not expose row-level data for small groups.
- Measures must reference exposed base-entity fields.
- Cross-entity group-by may reference joined fields with `relationship.field`.
- Cross-entity aggregates must declare direct relationship joins.
- Filters remain base-entity only in V1.
- Multi-hop joins are not V1.

## Audit

Audit config:

```yaml
audit:
  sink: stdout
  format: jsonl
```

Sinks:

- `stdout`: default for containers.
- `file`: include `path` and optional `rotate`.
- `syslog`: local syslog forwarding.

Optional:

- `chain`: tamper-evident hash chaining, V1.x style.
- `include_health`: whether health checks appear in audit.

Audit records should include request id, API key id, endpoint kind, dataset, entity, internal table id when applicable, relationship, aggregate id, scopes used, redacted query params, purpose, status, row/group counts, suppressed group count, duration, and error code.

Audit records must never include raw API keys, raw hashes, secrets, or row-level personal data. Sensitive filter values should be hashed deterministically when subject-keyed audit lookup will be needed later.

## Public Routes

Public entity-oriented routes:

- `GET /health`
- `GET /ready`
- `GET /catalog`
- `GET /catalog/dcat-ap.jsonld`
- `GET /datasets`
- `GET /datasets/{dataset_id}`
- `GET /datasets/{dataset_id}/{entity}/schema`
- `GET /datasets/{dataset_id}/{entity}`
- `GET /datasets/{dataset_id}/{entity}/{id}`
- `GET /datasets/{dataset_id}/{entity}/{id}/{relationship}`
- `GET /datasets/{dataset_id}/{entity}/verify`
- `GET /datasets/{dataset_id}/{entity}/aggregates`
- `GET /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}`
- `POST /admin/reload`
- `GET /openapi.json`

Bulk export route contract is reserved for V1.x:

- `POST /datasets/{dataset_id}/{entity}/exports`
- `GET /admin/jobs/{job_id}`

Do not add public table-ID routes.

## Response And Disclosure Rules

- Collection responses use `{data, pagination, meta}`.
- Single record responses are top-level objects, no `data` wrapper.
- Pagination is cursor-based, not offset-based.
- Do not return exact total counts.
- `?expand=` must enumerate relationships. `expand=*` is not V1.
- Nested expansion such as `members.household` is not V1.
- A failed auth or purpose check for any expansion rejects the whole request with 403. Do not silently omit embeds.
- `has_many` expansions may include up to the entity `default_limit`; if truncated, set an `_expansion` truncated flag.
- Nested relationship endpoints paginate collections and do not return totals.
- Verify returns only `{exists, ingest_version}`.

## Error And HTTP Conventions

- Success JSON: `application/json`.
- Error JSON: `application/problem+json` using RFC 9457 Problem Details.
- DCAT output: `application/ld+json`.
- Stable `code` should be present in problem responses and audit logs.
- Use `X-Request-Id` response header.
- Use `ETag`, `Last-Modified`, `Cache-Control`, and conditional GETs where applicable.

Status map:

- `200`: success with body.
- `204`: admin reload acknowledged.
- `304`: not modified.
- `400`: malformed request or unallowed filter/operator/query parameter.
- `401`: missing or invalid key.
- `403`: scope denied.
- `404`: unknown dataset, entity, relationship, primary key, or aggregate.
- `409`: reload in progress or stale cursor.
- `413`: too many values, such as a large `in` list.
- `422`: semantically invalid filter value.
- `429`: rate limited.
- `500`: scrubbed internal error.
- `503`: not ready.

## V1 Non-Goals

Do not configure or imply:

- UI.
- Open anonymous public access.
- Data editing or write-back.
- Raw SQL API.
- Row-level security rules per user.
- Automatic PII detection.
- Complex transformations.
- Computed fields.
- Config hot reload.
- Full GIS.
- Data-space connector.
- Access request or manual approval workflow.
- Inline CSV streaming download.
- Async messaging or file-batch transport.
- Data-subject audit query API.

## Self-Review Checklist

Before approving a config:

- Every referenced table, entity, relationship, field, scope, aggregate, and vocabulary prefix resolves.
- Public names are entity-oriented and do not leak storage table IDs.
- Every entity has exactly one exposed primary-key field.
- Hidden storage columns do not appear in public filters, aggregate measures, aggregate groups, schemas, docs, or verify parameters.
- Verify-only scope grants only verify.
- Aggregate-only scope grants only aggregates.
- Personal row or verify access requires purpose headers unless explicitly waived.
- Aggregates have disclosure control and no small-group leaks.
- No total counts or offset pagination are introduced.
- Audit sink is configured and will not log secrets or row-level personal data.
- Admin scope and admin network exposure are separated from data access.
