# registry-relay Configuration Guide

`registry-relay` is configured by one YAML document. The binary chooses the first available source:

1. `--config <path>`
2. `REGISTRY_RELAY_CONFIG`
3. `./config/example.yaml`

The canonical sample is [config/example.yaml](../config/example.yaml). Keep examples aligned with this guide and the API and operations documentation.

## Root Shape

```yaml
server: {}
metadata: {}   # optional split portable metadata manifest
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

## Split Metadata Manifest

```yaml
metadata:
  manifest_path: ./metadata.yaml
```

`manifest_path` points at a portable metadata manifest. Relative paths are
resolved from the runtime config file. At startup, Registry Relay compiles the
manifest and validates that runtime datasets, entities, fields, filters, and
relationships are present in the metadata model.

Keep operational details in this runtime config: sources, tables, physical
columns, scopes, filters, aggregates, standards adapters, ingest, and refresh.
Keep standard-facing meaning in the manifest: catalog, datasets, entities,
fields, constraints, vocabularies, codelists, profiles, conformance claims, and
descriptive ODRL policy metadata.

See [metadata.md](metadata.md) for the manifest schema, static publication, and
the `metadata.manifest.*` / `runtime.binding.*` startup error codes.

ODRL policy belongs in the portable metadata manifest, not in runtime dataset
bindings. A dataset `policy` block is published as an `odrl:Offer` for discovery
and review evidence only. It does not change API-key scopes, OIDC authorization,
row filtering, evidence verification, SP DCI behavior, or any other runtime access
decision.

```yaml
metadata:
  manifest_path: ./disability_registry.metadata.yaml

# In disability_registry.metadata.yaml:
datasets:
  - id: disability_registry
    policy:
      uid: https://demo.example.gov/datasets/disability_registry#illustrative-offer
      assigner: did:web:social-affairs.demo.example.gov
      permissions:
        - action: odrl:use
          constraints:
            - left_operand: odrl:purpose
              operator: odrl:isA
              right_operand:
                iri: https://demo.example.gov/purpose/disability-benefit-eligibility
          duties:
            - action: odrl:attribute
      prohibitions:
        - action: odrl:sell
```

The demo policy IRIs under `demo.example.gov` are hypothetical examples for
catalog consumers. They are not official policy, legal advice, or a declaration
that a client has been approved to use the data.

## Optional Social Protection Digital Convergence Initiative (SP DCI) Sync Adapter

Build with `--features spdci-api-standards` to enable the optional SP DCI sync adapters. Without that feature, any `standards.spdci` config is rejected with `spdci.config.feature_disabled`.

The adapter does not add new storage semantics. Configure a normal Registry Relay entity, often backed by an XLSX worksheet, then bind the SP DCI sync routes to it:

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
    registries:
      dr:
        dataset: disability_registry
        entity: disabled_person
        registry_type: ns:org:RegistryType:DR
        record_type: spdci-extensions-dci:DisabledPerson
        identifiers:
          DISABILITY_ID: id
          MEMBER_ID: id
        expression_fields:
          disability_status: disability_status
          disability_details.impairment_type: impairment_type
```

When enabled and configured, Registry Relay serves these SP DCI sync endpoints on the protected data-plane listener:

```text
POST /dci/{registry}/registry/sync/search
POST /dci/{registry}/registry/sync/disabled
POST /dci/{registry}/registry/sync/get-disability-details
POST /dci/{registry}/registry/sync/get-disability-support
```

The `{registry}` segment selects a named `standards.spdci.registries` entry such as `dr`, which lets one listener host multiple DCI registry APIs without path ambiguity. The async `/registry/search`, subscribe, callback, and transaction-status APIs are intentionally not implemented by this sync adapter.

For generic sync search, `identifiers` maps DCI `idtype-value` query types to entity fields. `expression_fields` maps DCI expression or predicate attribute names to entity fields. Mapped fields must be exposed entity fields and allowed filters. The adapter currently supports `idtype-value`, expression `$and` with `eq`, `in`, `ge`, and `le`, and predicate conditions joined with `and`.

`query_key` is read from `message.disabled_criteria.query` in the SP DCI request envelope. It may be represented as a literal dotted JSON key (`"member.member_identifier"`) or as nested objects (`{"member": {"member_identifier": ...}}`). `query_field` must be an allowed entity filter because the adapter delegates reads to the normal entity query engine.

For `/dci/{registry}/registry/sync/disabled`, the caller needs the configured entity DCI status-check scope; generic search, details, and support need the entity `read_scope`. API-key authentication is still Registry Relay's normal auth layer.

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

## OIDC (OAuth2)

Set `auth.mode: oidc` to verify bearer JWTs against an external OpenID Connect / OAuth2 IdP. The relay is a resource server: it validates inbound tokens against the IdP's JWKS but never mints, refreshes, or stores tokens. A given deployment runs in exactly one auth mode at a time; mixed-mode operation is not supported.

```yaml
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.gov
    audience:
      - registry-relay
    discovery_url: https://idp.example.gov/.well-known/openid-configuration
    algorithms:
      - RS256
    jwks_cache_ttl: 10m
    leeway: 60s
    scope_claim: scope
    scope_map:
      "role:social-registry-reader": "social_registry:rows"
    allowed_clients: []
    token_types:
      - JWT
      - at+jwt
```

A full drop-in alternative to `config/example.yaml` lives at `config/example.oidc.yaml`. It targets a local Zitadel instance and is what the integration test consumes.

| Field             | Purpose                                                                                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`          | Compared verbatim against the JWT `iss` claim. Must match the IdP's published issuer URL.                                                                     |
| `audience`        | One or more accepted `aud` values. Tokens whose `aud` does not intersect this list are rejected.                                                              |
| `jwks_url`        | Explicit JWKS endpoint. Exactly one of `jwks_url` and `discovery_url` must be set; the validator rejects configs that supply both or neither.                 |
| `discovery_url`   | OIDC discovery document (`.well-known/openid-configuration`). The JWKS URL is resolved from `jwks_uri` at startup.                                            |
| `algorithms`      | Signature algorithms accepted by the verifier. RS256, ES256, EdDSA. HS\* and `none` are intentionally absent.                                                 |
| `jwks_cache_ttl`  | Steady-state JWKS cache TTL. The cache also refreshes on unknown `kid` (rate-limited), so this is the rotation pickup latency, not the upper bound.           |
| `leeway`          | Clock skew tolerance on `exp` and `nbf`. Bounded at 5 minutes by validation.                                                                                  |
| `scope_claim`     | Name of the JWT claim to read scopes from (the config field itself is always a single string; defaults to `scope`). The claim's *value* in the token may be a space-separated string (RFC 8693 / RFC 9068), a JSON array of strings, or a JSON object whose keys are the scope names (Zitadel's `urn:zitadel:iam:org:project:roles`); all three shapes are accepted at verify time. |
| `scope_map`       | Optional rename map applied before scope-based access checks. Adapt IdP role names to the relay's `<dataset_id>:<level>` shape.                               |
| `allowed_clients` | Optional allowlist matched against the token's `azp` (preferred) or `client_id`. Empty list means any client is accepted.                                     |
| `token_types`     | Accepted JOSE `typ` header values. Defaults to `JWT` and `at+jwt` (RFC 9068). ID tokens (`id+jwt`) are intentionally rejected by default.                     |

### Discovery vs explicit JWKS

`discovery_url` triggers a single discovery fetch at startup to resolve `jwks_uri`; a failure here aborts the binary so an operator sees the IdP wiring problem instead of a process that runs but silently rejects every token. The JWKS document itself is fetched lazily on first verify, so a transient JWKS outage at boot does not block startup.

### Resource-server semantics

The relay never mints or refreshes tokens. Operators are responsible for provisioning OIDC applications, machine users, and grant types on the IdP. The Principal's `principal_id` is taken from the token's `sub` (preferred), then `client_id`, then `azp`; `auth_mode=oidc` is recorded on every audit record.

### Granular failure codes

Token verification failures map to specific `auth.*` codes so audit pipelines can distinguish IdP outages from bad tokens from policy denials:

| Code                            | HTTP | Meaning                                                       |
| ------------------------------- | ---- | ------------------------------------------------------------- |
| `auth.missing_credential`       | 401  | No `Authorization` header                                     |
| `auth.malformed_credential`     | 401  | Wrong scheme, empty bearer, or unparseable JWT structure      |
| `auth.token_expired`            | 401  | `exp` claim is in the past (after `leeway`)                   |
| `auth.token_not_yet_valid`      | 401  | `nbf` claim is in the future (after `leeway`)                 |
| `auth.token_signature_invalid`  | 401  | JWKS key found but signature did not verify                   |
| `auth.issuer_mismatch`          | 401  | `iss` claim does not match `oidc.issuer`                      |
| `auth.audience_mismatch`        | 401  | `aud` claim does not intersect `oidc.audience`                |
| `auth.kid_unknown`              | 401  | Header `kid` is absent from the JWKS even after one refresh   |
| `auth.algorithm_not_allowed`    | 401  | Header `alg` is not in the configured allowlist               |
| `auth.client_not_allowed`       | 403  | `azp` / `client_id` is not in the configured `allowed_clients`|
| `auth.invalid_credential`       | 401  | JWT decode failure not covered by a more specific variant      |
| `auth.jwks_unavailable`         | 503  | JWKS fetch failed; the relay cannot verify any token          |

### Running against a local IdP

The publicschema.com dev compose stack provisions a Zitadel organisation, project, OIDC application, test user, machine service account, and the relay-facing project roles on first boot. See `apps/publicschema.com/compose/seed/zitadel-bootstrap.md` for the resources created, the env-file shape, and the claim that carries roles in minted access tokens.

**Prerequisites.** The bootstrap must have completed against a current Zitadel volume so the `publicschema-api` machine user has `accessTokenType: JWT` and a generated client secret (Section 7b of `compose/seed/zitadel-init.sh`). Token minting uses the SA's `client_credentials` grant rather than the `workbench-dev` OIDC app's, because Zitadel WEB-typed OIDC applications silently drop the `client_credentials` grant at write time. If you are pointing at an older snapshot of the stack that predates the SA hardening, re-run `docker compose -f compose/dev.compose.yaml up zitadel-init` against the publicschema.com stack to regenerate the SA credentials and refresh `compose/seed/zitadel.env`; otherwise the token mint will fail with `invalid_grant` or produce an opaque bearer that the relay cannot verify.

To exercise the relay end-to-end:

```sh
# 1. Bring up Zitadel from the sibling stack.
cd ../publicschema.com
docker compose -f compose/dev.compose.yaml up -d zitadel zitadel-init

# 2. Mint a test access token.
cd ../registry_relay
TOKEN="$(./scripts/mint-zitadel-token.sh)"

# 3. Run the relay against the OIDC example.
cargo run -- --config config/example.oidc.yaml

# 4. Hit a protected endpoint with the minted bearer.
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/metadata/catalog
```

The `tests/oidc_zitadel.rs` integration test exercises the same path and asserts the granular failure modes above. The test reads `OIDC_ISSUER`, `OIDC_SA_CLIENT_ID`, and `OIDC_SA_CLIENT_SECRET` from the environment, so source the bootstrap env file first:

```sh
source ../publicschema.com/compose/seed/zitadel.env
cargo test --test oidc_zitadel -- --ignored --nocapture
```

The integration test verifies the auth wiring (signature, issuer, audience, principal extraction, granular `auth.*` codes) using a token minted by the bootstrap. Asserting RBAC against specific resource scopes requires either roles in the token that match `oidc.scope_map`'s keys, or aligning `oidc.scope_claim` with the IdP's role-bearing claim; the example `config/example.oidc.yaml` ships with the values the bootstrap emits.

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

`chain: true` wraps audit records with hash-chain fields for tamper evidence. Audit records are separate from operational logs, which go to stderr as readable text by default. Set `REGISTRY_RELAY_LOG_FORMAT=json` or `REGISTRY_RELAY_LOG_FORMAT=jsonl` when operational logs should be emitted as JSON Lines for collection or redirected files.

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

For CSV files, set `format.csv.header_row: 1` when the first row contains column names. For XLSX files, `header_row` and `data_range` can be used when a worksheet has notes or title rows around the rectangular table. Source configuration is table-local: put file/database settings and format hints under each `tables[].source`.

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

Live materialization is supported for structured `table` sources only. Each DataFusion scan opens a read-only Postgres session and exports data from the configured table. Simple column projection is pushed into the generated `COPY` query only when the scan has no filters; filtered scans, joins, and limits remain gateway-side. This keeps the live path bounded and safe without accepting caller-controlled SQL. Live row responses do not advertise snapshot-style strong validators or cursor version tokens, because upstream rows can change between requests without a Registry Relay ingest event. Live exports are also bounded by `server.max_source_file_bytes`. Use `connect_timeout`, `query_timeout`, and `live_max_connections` to bound upstream behavior.

For production live sources, keep the contract deliberately narrow:

```yaml
tables:
  - id: individuals_table
    materialization: live
    primary_key: individual_id
    refresh:
      mode: manual
    schema:
      strict: true
      fields:
        - name: individual_id
          type: string
          nullable: false
        - name: household_id
          type: string
          nullable: false
        - name: updated_at
          type: timestamp
          nullable: true
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

The connection string should point to a read-only database role that can `SELECT` only the configured table or view. Do not use `query` sources, `change_token_sql`, or `refresh.mode: mtime` with live materialization; those are snapshot-only controls. Declared schema fields are the exported contract, and extra database columns are ignored unless an entity query needs a full local scan to evaluate filters.

Minimal source-only form:

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

### Datasource Capability Matrix

Registry Relay derives datasource capabilities from `source.type` and `materialization`. Operators do not configure these flags directly.

| Source | Materialization | Filters | Projection | Limit | Validators and cursors | Provenance |
| --- | --- | --- | --- | --- | --- | --- |
| `file` | `snapshot` | gateway-side | gateway-side | gateway-side | strong snapshot tokens | snapshot-backed |
| `postgres` `table` or `query` | `snapshot` | gateway-side | gateway-side | gateway-side | strong snapshot tokens | snapshot-backed |
| `postgres` `table` | `live` | gateway-side | Postgres column pushdown for filter-free scans, otherwise gateway-side | gateway-side | no strong snapshot tokens | not snapshot-backed |

Unsupported combinations are rejected at config load: file `live`, Postgres `live` with a configured `query`, and `live` with `mtime` refresh. Postgres `query` sources stay snapshot-only so operator SQL is executed only during controlled ingest or refresh, never per public request. Future datasource connectors should follow the same convention: only generated SQL over structured table metadata may receive pushdown, and unsupported operations must fall back to gateway-side execution or be rejected explicitly.

At startup, Registry Relay logs one `ingest.datasource_capabilities` event per configured table. For Postgres live scans, the admin listener's `/metrics` route also exports low-cardinality live scan metrics for scan duration, concurrency wait time, exported rows, and exported bytes. These metrics intentionally do not include dataset ids, table names, SQL, env vars, request ids, or row values.

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
      evidence_verification_scope: social_registry:evidence_verification
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

### Evidence Verification

Evidence verification exposes declared metadata offerings and an offering-bound verification endpoint:

```http
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
POST /evidence-offerings/{offering_id}/verifications
```

The portable metadata manifest declares the public offering, while runtime entity access declares the scope required to execute the offering's verification binding. The expected runtime shape is:

```yaml
claim_verification:
  binding_key_id: social-registry-v1
  binding_key_env: CLAIM_VERIFICATION_BINDING_KEY

evidence_verification:
  rate_limit:
    enabled: true
    burst: 120
    window_seconds: 60

access:
  evidence_verification_scope: social_registry:evidence_verification

claim_verification:
  rulesets:
    identity-match-v1:
      mode: normalized_exact
      required_claims: [given_name, family_name, date_of_birth]
      candidate_lookup: [family_name, date_of_birth]
      match_fields:
        given_name: given_name
        family_name: family_name
        date_of_birth: date_of_birth
      allow_subject_id_targeting: false
      diagnostics: false
      expose_ambiguous: false
      scope: social_registry:evidence_verification
```

V1 supports `normalized_exact` only. `binding_key_env` must point at a stable high-entropy secret encoded as `hex:<64-or-more-lowercase-hex-chars>`, where the decoded key is at least 32 bytes. For example, generate it with `printf 'hex:%s\n' "$(openssl rand -hex 32)"`. Registry Relay derives offering-scoped HMAC keys from that secret, and the same decoded key must remain available after process restarts so `claim_hash` and `evidence_hash` remain interpretable. The endpoint defaults to JSON. Signed JWT receipts use `application/vnd.registry-relay.evidence-verification+jwt` when provenance is enabled and that media type is listed in `provenance.accepted_media_types`; otherwise strict receipt requests return `406`. Header names are case-insensitive, so `Data-Purpose` and `data-purpose` are equivalent; values must be absolute IRIs and must match `policy.purpose` when an offering declares one. The built-in rate limiter is per principal and offering. See [evidence-verification.md](evidence-verification.md) for request and response examples.

`example-person-schema` is optional and requires a binary built with
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

The `provenance` block is optional. When absent or `enabled: false`, the gateway behaves as a plain JSON service. When enabled, callers can opt in to signed VC-JWT responses with `Accept: application/vc+jwt`. Evidence-verification receipts use the same signer but are not VC-JWTs; add `application/vnd.registry-relay.evidence-verification+jwt` to `provenance.accepted_media_types` only for deployments that want that receipt profile.

See [provenance.md](provenance.md) for the full signer, DID, schema, context, and rotation contract.

## Production Checklist

- Source files are read-only to the process.
- `cache_dir` is writable and on a filesystem with enough space.
- Every `hash_env` exists in the runtime environment.
- No raw key, fingerprint, private JWK, or full environment dump is logged.
- Admin listener, if enabled, is private.
- CORS origins are explicit.
- Personal-data entities use explicit field projections.
- Row and evidence-verification routes that need purpose tracking set `require_purpose_header: true`.
- Sensitive identifier fields are marked `sensitive: true` where audit redaction is required.
- Audit sink and retention match the deployment's governance requirements.
- For Postgres live tables, scrape `/metrics` from the admin listener and alert on live scan timeout/error growth, exported bytes, and concurrency wait time.
