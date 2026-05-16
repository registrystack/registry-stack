# registry-relay Configuration Guide

`registry-relay` is configured by one YAML document. The binary chooses the first available source:

1. `--config <path>`
2. `REGISTRY_RELAY_CONFIG`
3. `./config/example.yaml`

The canonical sample is [config/example.yaml](../config/example.yaml). Keep examples aligned with this guide and the API and operations documentation.

## Root Shape

```yaml
server: {}
catalog: {}
vocabularies: {}
auth: {}
datasets: []
audit: {}
provenance: {} # optional
standards: {}  # optional, feature-gated adapters
```

Unknown fields are rejected for most blocks. Config validation runs after YAML parsing and checks ids, scopes, table/entity references, filter references, aggregate references, env var presence, and vocabulary prefixes.

## Server

```yaml
server:
  bind: 0.0.0.0:8080
  admin_bind: 127.0.0.1:8081
  cache_dir: ./cache
  max_source_file_bytes: 268435456
  xlsx_max_file_bytes: 268435456
  request_timeout: 30s
  cors:
    allowed_origins:
      - https://portal.example.gov
  trust_proxy:
    enabled: false
    trusted_proxies: []
```

`bind` is the public data-plane listener. `admin_bind` is optional and should be private. `cache_dir` must be writable by the process. Source data should be mounted read-only.

The default CORS policy is deny by omission. Add explicit trusted origins only.

## Catalog And Vocabularies

```yaml
catalog:
  title: Internal Government Registry Relay
  base_url: https://data.example.gov
  publisher: Ministry of Digital Government
  participant_id: did:web:data.example.gov

vocabularies:
  psc: https://publicschema.org/
  m8g: http://data.europa.eu/m8g/
```

`base_url` is used in generated catalog links, OpenAPI servers, and provenance subject URIs. `participant_id` is optional and defaults from the catalog base URL when omitted.

Vocabulary prefixes let entity fields and dataset metadata use compact semantic references such as `psc:concepts/Person`.

## Optional SPD CI Sync Adapter

Build with `--features spdci-api-standards` to enable the optional SPD CI Disability Registry sync adapter. Without that feature, any `standards.spdci` config is rejected with `spdci.config.feature_disabled`.

The adapter does not add new storage semantics. Configure a normal Registry Relay entity, often backed by an XLSX worksheet, then bind the SPD CI sync routes to it:

```yaml
standards:
  spdci:
    disability_registry:
      dataset: disability_registry
      entity: disabled_person
      query_key: member.member_identifier
      query_field: id
      disabled_status_field: disability_status
      disabled_positive_values: [approved, yes]
```

When enabled and configured, Registry Relay serves these SPD CI sync endpoints on the protected data-plane listener:

```text
POST /registry/sync/disabled
POST /registry/sync/get-disability-details
POST /registry/sync/get-disability-support
```

`query_key` is read from `message.disabled_criteria.query` in the SPD CI request envelope. It may be represented as a literal dotted JSON key (`"member.member_identifier"`) or as nested objects (`{"member": {"member_identifier": ...}}`). `query_field` must be an allowed entity filter because the adapter delegates reads to the normal entity query engine.

For `/registry/sync/disabled`, the caller needs the configured entity `verify_scope`; details and support need the entity `read_scope`. API-key authentication is still Registry Relay's normal auth layer.

## API Keys

```yaml
auth:
  mode: api_key
  api_keys:
    - id: program_system
      hash_env: PROGRAM_SYSTEM_API_KEY_HASH
      scopes:
        - social_registry:metadata
        - social_registry:rows
```

The YAML stores env var names, never raw API keys. Each env var value must be:

```text
sha256:<64 lowercase hex chars>
```

Generate a fingerprint without printing the raw key:

```sh
RAW_KEY="$(openssl rand -base64 32)"
printf 'sha256:%s\n' "$(printf '%s' "$RAW_KEY" | shasum -a 256 | awk '{print $1}')"
```

Store the fingerprint in the platform secret store under the configured `hash_env` name. Give the raw key only to the authorized client.

## Audit

```yaml
audit:
  sink: stdout
  format: jsonl
  chain: false
  include_health: false
```

Supported sinks:

```yaml
audit:
  sink: stdout
  format: jsonl
```

```yaml
audit:
  sink: file
  format: jsonl
  path: /var/log/registry-relay/audit.jsonl
  rotate:
    max_size_mb: 100
    max_files: 14
```

```yaml
audit:
  sink: syslog
  format: jsonl
```

`chain: true` wraps audit records with hash-chain fields for tamper evidence. Audit records are separate from operational logs, which go to stderr as structured JSON.

## Datasets

Each dataset combines private storage tables with public entities:

```yaml
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
    defaults:
      materialization: snapshot
    tables: []
    entities: []
```

`sensitivity`, `access_rights`, and `update_frequency` are catalog metadata. They also make review conversations concrete; do not leave them vague in production configs.

`defaults` is optional. It may provide `materialization` and `refresh` defaults for tables in the same dataset. Source configuration stays table-level.

### Sources

Sources are configured on each private table. File sources read CSV, XLSX, or Parquet data:

```yaml
source:
  type: file
  path: ./data/social_registry.xlsx
  format:
    xlsx:
      sheet: Individuals
      header_row: 1
      data_range: A1:E100000
```

For XLSX files, `header_row` and `data_range` can be used when a worksheet has notes or title rows around the rectangular table. Existing configs with dataset-level `source` and table-level `format` are still accepted during the datasource refactor, but new configs should use `tables[].source.format`.

Postgres snapshot and live table sources are supported. Credentials are never stored in YAML:

```yaml
source:
  type: postgres
  connection_env: SOCIAL_REGISTRY_DATABASE_URL
  table:
    schema: public
    name: individuals
  change_token_sql: "select max(updated_at)::text from public.individuals"
```

`connection_env` is the environment variable name containing the connection string. Validation and logs may mention the env var name but must not read or print its value. Use read-only database credentials. Registry Relay also marks Postgres connector sessions as read-only, but credentials should enforce the same boundary at the database. `table` and `query` are mutually exclusive; prefer structured `table` configs for production.

Snapshot ingest reads Postgres through `COPY (SELECT ...) TO STDOUT WITH CSV HEADER`, then applies the same declared-schema coercion and validation as CSV files. The exported snapshot is bounded by `server.max_source_file_bytes`. For `table` sources, Registry Relay projects the declared schema fields from the table and casts them to CSV-friendly values. Extra database columns are ignored. For `query` sources, write a single `SELECT` or `WITH` statement without semicolons; public request input is never interpolated into SQL.

Live materialization is supported for structured `table` sources only. Each DataFusion scan opens a read-only Postgres session, exports the declared columns from the configured table, and lets DataFusion apply query filters and projection locally. This keeps the live path bounded and safe, but it does not yet push predicates, projections, joins, or limits into Postgres. Live row responses do not advertise snapshot-style strong validators or cursor version tokens, because upstream rows can change between requests without a Registry Relay ingest event. Live exports are also bounded by `server.max_source_file_bytes`. Use `connect_timeout`, `query_timeout`, and `live_max_connections` to bound upstream behavior:

```yaml
source:
  type: postgres
  connection_env: SOCIAL_REGISTRY_DATABASE_URL
  table:
    schema: public
    name: individuals
  connect_timeout: 5s
  query_timeout: 30s
  live_max_connections: 8
```

Supported Postgres field mappings are:

```text
string -> text
integer -> bigint
number -> double precision
boolean -> boolean
date -> date
timestamp -> timestamptz rendered as RFC 3339 UTC text
```

### Refresh

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

`mtime` reloads when the source change token changes. It is supported for file sources and for Postgres snapshot sources only when `change_token_sql` is configured. `interval` reloads on every interval. `manual` reloads only through the admin listener's table reload route.

## Tables

Tables are private storage resources. Their ids do not appear in public URLs.

```yaml
tables:
  - id: individuals_table
    materialization: snapshot
    source:
      type: file
      path: ./data/social_registry.xlsx
      format:
        xlsx:
          sheet: Individuals
    refresh:
      mode: mtime
      interval: 1h
    primary_key: individual_id
    schema:
      strict: true
      fields:
        - name: individual_id
          type: string
          nullable: false
        - name: payment_amount
          type: number
          nullable: true
          unit: EUR
```

Supported formats are `csv`, `xlsx`, and `parquet`. If `format` is omitted, the loader infers from the source file extension where possible.

`materialization` may be `snapshot` or `live`. File sources support `snapshot`. Postgres sources support `snapshot`; Postgres structured table sources also support `live`.

Field types:

```text
string, number, integer, boolean, date, timestamp
```

Use `sensitive: true` on source or entity fields whose query values should be redacted in audit records.

## Entities

Entities are the public REST resources:

```yaml
entities:
  - name: individual
    title: Individual
    description: A person enrolled in Program X
    table: individuals_table
    concept_uri: psc:concepts/Person
    fields:
      - name: id
        from: individual_id
        sensitive: true
      - name: payment_amount
        from: payment_amount
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
      required_filters:
        - id
      allowed_filters:
        - field: id
          ops: [eq, in]
      allowed_expansions:
        - household
    publicschema:
      target: Person
      mapping_path: mappings/individual-person.publicschema.yaml
      schema_validation_path: ../publicschema.org/dist/schemas/Person.schema.json
```

When `fields` is present, only listed fields are exposed. When it is omitted, every table column is exposed. For sensitive datasets, prefer an explicit field list.

Relationships are dataset-local in V1. Cross-dataset workflows should compose client-side with separate scoped calls and separate audit records.

`publicschema` is optional and requires a binary built with
`--features publicschema-cel`. When present, entity-record VC issuance
uses the mapping file to transform the public entity JSON into a
PublicSchema.org subject. The plain JSON route is unchanged. Defaults
are `context_url: https://publicschema.org/ctx/draft.jsonld`,
`schema_url: https://publicschema.org/schemas/{target}.schema.json`,
and `credential_type: {target}`. `schema_validation_path` is optional
but recommended; when set, every mapped VC subject is validated before
signing. Mapping CEL expressions receive `ctx.subject_uri`, `ctx.dataset`,
and `ctx.entity`; use `ctx.subject_uri` for the PublicSchema subject
`/id` so the mapped credential stays bound to the canonical gateway
entity URI.

## Aggregates

Aggregates are declared on entities:

```yaml
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
```

Supported measure functions include the configured V1 set used by tests and examples, such as `count`, `sum`, and `avg`. Keep disclosure thresholds explicit and reviewable.

## Provenance

The `provenance` block is optional. When absent or `enabled: false`, the gateway behaves as a plain JSON service. When enabled, callers can opt in to signed VC-JWT responses with `Accept: application/vc+jwt`.

See [provenance.md](provenance.md) for the full signer, DID, schema, context, and rotation contract.

## Production Checklist

- Source files are read-only to the process.
- `cache_dir` is writable and on a filesystem with enough space.
- Every `hash_env` exists in the runtime environment.
- No raw key, fingerprint, private JWK, or full environment dump is logged.
- Admin listener, if enabled, is private.
- CORS origins are explicit.
- Personal-data entities use explicit field projections.
- Row and verify routes that need purpose tracking set `require_purpose_header: true`.
- Sensitive identifier fields are marked `sensitive: true` where audit redaction is required.
- Audit sink and retention match the deployment's governance requirements.
