# Wave 0 Architecture Decisions

Status: locked for Wave 0 execution. Architect: code-architect (opus). Spec: `Spec.md` (V1).

This note is the contract Wave 0's six tracks build against. It is abstract by design: trait shapes, file ownership, integration seams, and exit criteria. It is not code.

---

## 1. Decisions on Section 17 Open Clarifications

| # | Item | Decision | Rationale |
|---|---|---|---|
| 1 | Deployment target | **Container first** (OCI image), VM-capable via the same binary. | Spec recommends container; audit default `stdout` and 12-factor secret delivery both presume it. VM is reachable by toggling audit sink to `file` plus an `op run`-style env injector; no code path differs. |
| 2 | OS / libc target | **`x86_64-unknown-linux-gnu`** as primary; **add `x86_64-unknown-linux-musl`** in CI from Wave 0 so we never discover a glibc dependency late. | Two CI targets cost nothing now and avoid an "oh no, OpenSSL" rebuild during hardened-VM rollout. Skip Apple Silicon as a release target; dev-only. |
| 3 | First real dataset | **Synthetic XLSX fixture required.** Two sheets, header row 1, ~1k rows, columns mirroring the `social_registry` example (`beneficiary_id`, `household_id`, `municipality_code`, `enrollment_date`, `payment_amount`). Wave 0 unblocked without it; **Wave 1 blocked**. | Section 17 item 3 calls this out. Source-trait design only needs the shape; ingestion tests need real bytes. Flag: **needs Jeremi's input** (or authorization to generate synthetically in Wave 1's fixtures track). |
| 4 | Config format | **YAML.** | Comments, anchors, multi-line strings, and the example in Section 4 is already YAML. TOML's table-array ergonomics are worse for nested `datasets[].resources[].schema.fields[]`. |
| 5 | Error response format | **RFC 9457 Problem Details** (`application/problem+json`). | Industry standard, plays well with OpenAPI tooling, and aligns naturally with our stable error-code taxonomy (mapped to `type` URI + `code` extension). RFC 9457 obsoletes RFC 7807 (2023); wire shape is identical. Locked in Spec §7.bis.6. |
| 6 | OpenAPI generator | **`utoipa`**. | Stronger axum integration via `utoipa-axum`, derive-based, smaller surface than `aide`. Dynamic per-dataset paths get hand-augmented after generation (best-effort per spec Section 7). |
| 7 | CORS policy | **Default deny; allowlist origins in config** (`server.cors.allowed_origins: []`). | "Secure by default" is a stated principle. An allowlist is one line of config when needed. |
| 8 | Rate limiting | **Delegate to reverse proxy in V1**; expose `X-Request-Id` and `api_key_id` upstream-readable so the proxy can shape per-key. Add in-process token bucket as a V1.x toggle. | Avoids leaking rate-limit state into stateful request handling now. Operators already need a proxy for TLS termination. |
| 9 | Tracing / metrics | **`tracing` + structured JSON logs to stderr only** in V1. OpenTelemetry export is V1.x behind a feature flag. | Spec recommends logs-only. Keeps dependency tree small. Audit log is the load-bearing observability surface, not tracing. |
| 10 | License / OSS posture | **Apache-2.0**, SPDX header on every source file. `cargo-deny` advisory + license allowlist (Apache-2.0, MIT, BSD-2/3, ISC, Zlib, Unicode-DFS-2016) gated in CI. | Permissive, government-friendly, mirrors most of the dataspace ecosystem. Avoids GPL/LGPL contamination in the dependency tree. |
| 11 | Vocabulary version pinning | **Accept both versioned and canonical URIs verbatim**; do not canonicalize. The catalog surfaces what config says. | V1 is declaration-only. Rewriting URIs would be a surprise. Per-deployment policy lives in the config file. |
| 12 | Admin bind topology | **Single binary, second optional bind address.** `server.admin_bind` if present produces a separate `TcpListener` running an axum router scoped to `/admin/*`. If absent, `/admin/*` is mounted on the main router behind the `admin` scope check only. | One binary, one config, two listeners. Network policy isolation is a deployment concern, not a binary concern. |

**Items confirmed by Jeremi:**
- Item 3: synthetic XLSX fixture authorized. Wave 1 fixtures track generates `fixtures/social_registry.xlsx` (~1k rows, PII-free).
- Item 10: Apache-2.0 only (no MIT dual license).

---

## 2. Crate-Level Decisions

**Layout: confirmed single-crate per Section 18.1.** No workspace until a second crate earns its keep. Module hierarchy as specified; `src/audit/chain.rs` deferred to Wave 4 but the module slot is reserved.

**Dependencies proposed for `Cargo.toml`** (do not write the file in Wave 0 beyond what the Repo+CI track needs; this is the inventory):

Runtime:
- `tokio` (full features): async runtime, signal handling, graceful shutdown.
- `axum` (~0.7): HTTP server; matches `utoipa-axum` integration.
- `tower`, `tower-http` (`trace`, `request-id`, `cors`, `timeout`, `limit`, `set-header`): middleware stack composition.
- `hyper` (transitively pinned via axum): no direct dep unless we need a custom listener for `admin_bind`.

Data:
- `datafusion` (latest stable, pin minor): query engine. Heavy; gate to `query`/`ingest` modules.
- `arrow` (re-exported by datafusion; do not add a second arrow version).
- `calamine`: XLSX reader. Wave 1.
- `parquet` (via datafusion re-export).
- `csv-async` or `csv`: CSV reader. Decide in Wave 1; default `csv` for simplicity.

Serialization / config:
- `serde`, `serde_derive`: pervasive.
- `serde_yaml` (or `serde_yml` fork if maintenance is a concern; verify in Wave 0): config loader.
- `serde_json`: API responses, audit JSONL, OpenAPI.
- `humantime-serde`: `interval: 1h` parsing in refresh config.

Auth / crypto:
- `argon2`: Argon2id verification, Wave 4 introduces hashing; Wave 0 only verifies.
- `subtle`: constant-time comparisons where Argon2 isn't appropriate.
- `zeroize`: drop guarantees on key material in memory.

Time / IDs:
- `time` (with `serde`, `formatting`, `parsing`, `macros`): ISO-8601 with millisecond precision, no chrono. Single timestamp lib; do not mix with chrono.
- `ulid`: request IDs (`X-Request-Id`).

Observability:
- `tracing`, `tracing-subscriber` (`fmt`, `json`, `env-filter`): operational logs to stderr.
- `tracing-error`: error context capture without backtraces leaking to clients.

Errors / problem details:
- `thiserror`: internal error enums.
- **`http-api-problem`** for RFC 9457 representation (lighter than `problemdetails`; serde-friendly). Wire shape is identical to RFC 7807; the crate is unchanged. Verify maintenance in Wave 0; fall back to a hand-rolled struct if stale.

OpenAPI:
- `utoipa`, `utoipa-axum`, `utoipa-swagger-ui` (dev/optional): generation.

Dev / test:
- `tokio-test`, `axum-test` (or `tower::ServiceExt::oneshot`): handler tests.
- `assert-json-diff`: audit-record assertions.
- `proptest`: property tests for filter parser (Wave 2) and redaction (Wave 4); included from Wave 0 so it's in lockfile.
- `tempfile`: integration tests with file sinks.
- `insta`: snapshot tests for DCAT-AP/CSVW JSON-LD (Wave 3).

Version constraints / flags:
- Pin `datafusion` to a specific minor version; track its arrow version. Do not bring in a second arrow.
- `serde_yaml` is unmaintained upstream; pick a fork in Wave 0 (`serde_yml` is the current community fork). Decision is reversible.
- Enable `tokio` "rt-multi-thread", "signal", "fs", "net", "macros", "time"; skip "process".
- `MSRV` policy: track stable, no MSRV pin in Wave 0.

---

## 3. Trait Signatures

Signatures and doc comments only; no bodies. All four live in module scope as defined in Section 18.1.

### 3.1 `AuthProvider` (`src/auth/mod.rs`)

```rust
/// Authenticates an inbound request and produces a [`Principal`].
///
/// V1 implementation: `ApiKeyAuth`, reading `Authorization: Bearer <key>`
/// or `X-Api-Key: <key>` and verifying against Argon2id hashes loaded
/// from environment variables named by `auth.api_keys[].hash_env`.
///
/// Forward compatibility:
/// - V2 OIDC/JWT: a `JwtAuth` impl validates a Bearer JWT and projects
///   claims into `Principal::scopes` via a configured mapping.
/// - V2 Dataspace (DAT/IDSA): a `DspAuth` impl wraps the dataspace
///   verification SDK; `Principal` gains an opaque `extensions` map
///   (see below) for connector context; the trait itself does not change.
///
/// The trait is intentionally synchronous in its hot path inputs
/// (header map + remote addr) but `async fn` so JWT verification, JWKS
/// fetches, and token-introspection round-trips fit without breaking
/// callers.
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync + 'static {
    /// Authenticate a request from its headers and peer address.
    /// Returns `Ok(Principal)` on success, `Err(AuthError)` otherwise.
    /// Implementations must never log or surface the raw credential.
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        remote_addr: std::net::IpAddr,
    ) -> Result<Principal, AuthError>;
}

/// Result of successful authentication. Carried in request extensions.
///
/// Extension point: `extensions` is a typed map for future auth modes
/// (e.g. JWT claims, dataspace DAT metadata) without breaking handlers.
pub struct Principal {
    pub api_key_id: String,          // stable identifier; never the secret
    pub scopes: ScopeSet,            // resolved scopes for authorization
    pub auth_mode: AuthMode,         // ApiKey | Jwt | Dataspace
    pub extensions: Extensions,      // typed map for forward compat
}
```

`AuthError` is part of the error taxonomy (Section 4 of this note) and maps to `auth.*` codes.

### 3.2 `AuditSink` (`src/audit/mod.rs`)

```rust
/// Destination for audit records. Errors here must never break the
/// request path: the caller logs the failure to the operational log
/// and continues serving. The trait returns `Result` so implementations
/// can surface the failure; the audit pipeline decides policy.
///
/// V1 impls: `StdoutSink` (Wave 0). `FileSink` with in-process rotation
/// and `SyslogSink` arrive in Wave 4.
///
/// Forward compatibility:
/// - Tamper-evident chaining (Wave 4) is a *wrapping* sink
///   (`ChainingSink<S: AuditSink>`) that injects `prev_hash` and
///   `record_hash` envelope fields before delegating; the trait
///   doesn't change.
/// - Multi-sink fanout uses a `TeeSink` wrapper for the same reason.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync + 'static {
    /// Write a single audit record. Implementations should be
    /// non-blocking on the request path; long-running I/O belongs
    /// behind an internal channel.
    async fn write(&self, record: AuditRecord) -> Result<(), AuditError>;

    /// Best-effort flush on graceful shutdown. Must be idempotent.
    async fn flush(&self) -> Result<(), AuditError>;
}
```

### 3.3 `ConfigSchema` (`src/config/mod.rs`)

Top-level config struct shape; serde derives only, no validation logic here. Validation lives in `src/config/validate.rs` and runs after deserialization.

```rust
/// Root config. Parsed from `config.yaml` at startup.
/// Hot reload is out of scope; restart-only per spec Section 6.1.
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub catalog: CatalogConfig,
    #[serde(default)]
    pub vocabularies: BTreeMap<String, String>, // prefix -> base URI
    pub auth: AuthConfig,
    pub audit: AuditConfig,
    pub datasets: Vec<DatasetConfig>,
}

pub struct ServerConfig {
    pub bind: SocketAddr,
    pub admin_bind: Option<SocketAddr>,         // see decision #12
    pub trust_proxy: TrustProxyConfig,          // X-Forwarded-For policy
    #[serde(default)]
    pub cors: CorsConfig,                       // default deny
    #[serde(default)]
    pub request_timeout: HumanDuration,         // default 30s
}

pub struct CatalogConfig {
    pub title: String,
    pub base_url: Url,
    pub publisher: String,
}

pub struct AuthConfig {
    pub mode: AuthMode,                         // api_key (V1)
    pub api_keys: Vec<ApiKeyConfig>,
}

pub struct ApiKeyConfig {
    pub id: String,
    pub hash_env: String,                       // env var name, not the hash
    pub scopes: BTreeSet<String>,
}

pub struct AuditConfig {
    pub sink: AuditSinkConfig,                  // Stdout | File { path, rotate } | Syslog
    #[serde(default = "default_audit_format")]
    pub format: AuditFormat,                    // Jsonl
    #[serde(default)]
    pub chain: bool,                            // V1.x: tamper-evident chaining
    #[serde(default)]
    pub redact: RedactionConfig,                // per-field hash-or-omit rules
}

pub struct DatasetConfig {
    pub id: DatasetId,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub sensitivity: Sensitivity,
    pub access_rights: AccessRights,
    pub update_frequency: UpdateFrequency,
    #[serde(default)]
    pub conforms_to: Vec<String>,               // URIs, expanded via vocabularies
    pub source: SourceConfig,                   // tagged enum: file | (future) http | s3
    pub refresh: RefreshConfig,                 // mtime | interval | manual
    pub resources: Vec<ResourceConfig>,
}

pub struct ResourceConfig {
    pub id: ResourceId,
    pub sheet: Option<String>,                  // XLSX only
    pub primary_key: Option<String>,
    pub schema: SchemaConfig,
    pub access: ResourceAccessConfig,           // metadata/aggregate/row scopes
    pub api: ResourceApiConfig,                 // limits, filters, purpose hdr
    #[serde(default)]
    pub aggregates: Vec<AggregateConfig>,
}
```

Extension points called out: `SourceConfig` is `#[serde(tag = "type")]` so HTTP/S3 variants are additive; `AuthMode` enum is non-exhaustive; `AuditSinkConfig` is tagged so the chaining wrapper attaches via a sibling `chain` flag, not a new sink type.

### 3.4 `Source` (`src/source/mod.rs`)

```rust
/// A configured data source. V1 impls: `FileSource` dispatching on
/// extension/MIME to CSV/XLSX/Parquet readers.
///
/// Forward compatibility:
/// - HTTP/S3/SharePoint: implement `Source` over a `Box<dyn AsyncRead>`
///   produced by a fetcher; the trait surface does not change.
/// - Database: a `JdbcSource` would return batches directly without an
///   intermediate file; the trait permits this because `read` returns
///   a stream of `RecordBatch`, not bytes.
#[async_trait::async_trait]
pub trait Source: Send + Sync + 'static {
    /// Stable identifier for this source instance, for logging/audit.
    fn descriptor(&self) -> SourceDescriptor;

    /// A change token used by refresh: file mtime, ETag, version, etc.
    /// `None` means "I cannot detect change"; refresh policy falls back
    /// to interval or manual.
    async fn change_token(&self) -> Result<Option<ChangeToken>, SourceError>;

    /// Read the source into an Arrow `RecordBatch` stream.
    /// Implementations apply `header_row` / `data_range` / sheet
    /// selection per `SourceConfig`. Schema is *not* validated here;
    /// that is `ingest`'s job.
    async fn read(&self)
        -> Result<futures::stream::BoxStream<'static, Result<arrow::record_batch::RecordBatch, SourceError>>, SourceError>;
}
```

---

## 4. Error Taxonomy

Stable codes. They appear verbatim in audit `error_code` and in the `code` extension field of RFC 9457 Problem Details. Names are namespaced; the namespace is the audit `endpoint_kind` family or the subsystem.

### `auth.*`

| Code | HTTP | Meaning |
|---|---|---|
| `auth.missing_credential` | 401 | No `Authorization` / `X-Api-Key` header present. |
| `auth.invalid_credential` | 401 | Credential present but does not match any configured key/hash. |
| `auth.malformed_credential` | 401 | Header present but not parseable (wrong scheme, empty). |
| `auth.scope_denied` | 403 | Authenticated, but principal lacks the required scope. |
| `auth.purpose_required` | 400 | `X-Data-Purpose` header required by config but missing/empty. |
| `auth.admin_required` | 403 | `/admin/*` reached without `admin` scope. |

### `filter.*`

| Code | HTTP | Meaning |
|---|---|---|
| `filter.unknown_field` | 400 | Query parameter references a field not in the resource schema. |
| `filter.not_allowed` | 400 | Field exists but is not in the resource's `allowed_filters`. |
| `filter.unsupported_op` | 400 | Operator not allowed for this field. |
| `filter.invalid_value` | 400 | Value does not parse for the field's physical type. |
| `filter.too_many_values` | 413 | `in` list exceeds 100 entries. (Spec §7.bis.5.) |
| `filter.invalid_range` | 400 | `between` `from > to`, or `gte`/`lte` inverted. |
| `filter.limit_out_of_range` | 400 | `limit` exceeds `max_limit` or is non-positive. |

### `schema.*`

| Code | HTTP | Meaning |
|---|---|---|
| `schema.unknown_dataset` | 404 | Dataset id not registered. |
| `schema.unknown_resource` | 404 | Resource id not registered under dataset. |
| `schema.unknown_aggregate` | 404 | Aggregate id not declared for resource. |
| `schema.resource_unavailable` | 503 | Resource exists in config but failed ingest or is mid-reload. |

### `ingest.*` (not directly client-facing; appears in `/ready` 503 body and operational logs)

| Code | HTTP | Meaning |
|---|---|---|
| `ingest.source_not_found` | n/a | Source file path missing or unreadable. |
| `ingest.source_unreadable` | n/a | I/O or parser error reading source. |
| `ingest.schema_mismatch` | n/a | Declared schema does not match observed columns/types. |
| `ingest.strict_extra_column` | n/a | Source has columns absent from a `strict: true` schema. |
| `ingest.cache_write_failed` | n/a | Parquet cache could not be written. |
| `ingest.registration_failed` | n/a | DataFusion `register_table` failed. |

### `aggregate.*`

| Code | HTTP | Meaning |
|---|---|---|
| `aggregate.execution_failed` | 500 | DataFusion returned an execution error. |
| `aggregate.measure_unsupported` | 500 | Configured measure references a function not implemented. |
| `aggregate.disclosure_violation` | 500 | Internal: disclosure-control invariant broken before response; never reaches client without scrubbing. |

### `admin.*`

| Code | HTTP | Meaning |
|---|---|---|
| `admin.reload_failed` | 500 | One or more resources failed to reload. Body lists per-resource codes. |
| `admin.unknown_resource` | 404 | Reload target id not found. |

### `config.*` (startup-only; surfaced via process exit code and stderr, never HTTP)

| Code | HTTP | Meaning |
|---|---|---|
| `config.parse_error` | n/a | YAML did not deserialize. |
| `config.validation_error` | n/a | Cross-field validation failed (e.g. dangling scope, missing env var). |
| `config.missing_secret` | n/a | A `hash_env` env var is unset. |
| `config.duplicate_id` | n/a | Two datasets/resources/aggregates share an id. |

### `internal.*`

| Code | HTTP | Meaning |
|---|---|---|
| `internal.timeout` | 504 | Request exceeded `server.request_timeout`. |
| `internal.payload_too_large` | 413 | Request body or response cardinality exceeds configured caps. |
| `internal.unhandled` | 500 | Catch-all; mapped from any error not otherwise classified. Never includes stack trace in response. |

---

## 5. AuditRecord JSON Lines Schema

One record per authenticated request, written **after** response (per spec 13.1). One JSON object per line, no trailing comma, UTF-8, LF-terminated.

| Field | Type | Required | Notes |
|---|---|---|---|
| `ts` | string | yes | ISO-8601 UTC with millisecond precision and `Z` suffix, e.g. `2026-05-15T10:00:00.123Z`. Generated server-side at record emit. |
| `request_id` | string | yes | ULID, 26 chars, Crockford Base32; identical to `X-Request-Id` returned to client. Monotonic per process. |
| `api_key_id` | string \| null | yes | Stable id from `auth.api_keys[].id`. `null` only when auth failed before identification (e.g. `auth.missing_credential`). Never the raw key, never the hash. |
| `auth_mode` | string | yes | `api_key` in V1; future `jwt`, `dataspace`. |
| `remote_addr` | string | yes | Client IP after applying `server.trust_proxy` policy. IPv4 or IPv6 textual form. |
| `method` | string | yes | `GET` or `POST`. |
| `path` | string | yes | Request path; query string excluded (see `query_params`). |
| `endpoint_kind` | string | yes | One of: `health`, `ready`, `catalog`, `dataset`, `schema`, `rows`, `aggregate_list`, `aggregate`, `admin`, `openapi`. (`health`/`ready` records are only emitted when `audit.include_health: true`; default false to avoid noise.) |
| `dataset_id` | string \| null | conditional | Set on `dataset`, `schema`, `rows`, `aggregate_list`, `aggregate`. |
| `resource_id` | string \| null | conditional | Set when path includes a resource. |
| `aggregate_id` | string \| null | conditional | Set on `aggregate` only. |
| `scopes_used` | string[] | yes | Scopes actually checked on this request (post-authz), in declaration order. Empty for `health`/`ready`. |
| `query_params` | object | yes | Redacted parameter inventory; see below. `{}` when none. |
| `purpose` | string \| null | yes | Verbatim `X-Data-Purpose` header value when `require_purpose_header: true`. Opaque to the gateway. `null` otherwise. |
| `status_code` | integer | yes | HTTP status returned. |
| `row_count` | integer \| null | conditional | Rows on `rows`, group count on `aggregate`. `null` elsewhere. |
| `suppressed_groups` | integer \| null | conditional | Groups removed/masked by disclosure control. `null` outside aggregate. |
| `duration_ms` | integer | yes | Server-side handling time, milliseconds, integer (sub-millisecond rounds down). |
| `error_code` | string \| null | yes | Stable taxonomy code on 4xx/5xx; `null` on 2xx/3xx. |
| `prev_hash` | string \| null | optional | Hex SHA-256 of the previous record's canonical JSON. Present only when `audit.chain: true` (Wave 4). |
| `record_hash` | string \| null | optional | Hex SHA-256 of this record's canonical JSON minus the `record_hash` field. Present only when `audit.chain: true`. |

### `query_params` shape

Default-off-by-value redaction. Each entry describes which filter was applied, not what value was matched:

```jsonc
{
  "municipality_code": { "op": "eq" },
  "enrollment_date":    { "op": "between" },
  "limit":              { "op": "eq" }
}
```

When a field is configured with `audit.redact.fields.<name>.mode: hash`, the entry carries a salted-hash `value_hash` instead of being value-omitted. The salt is per-process and never logged. Wave 4 introduces the salt machinery; Wave 0 emits value-omitted entries only.

Unknown / rejected query parameters are recorded as `{ "op": "rejected" }` so that audit shows the attempted filter without disclosing the value.

### Constraints

- Audit records MUST NOT contain raw secrets, raw API keys, request bodies, or row-level data.
- On audit-write failure, the request still succeeds; the operational logger emits `audit.write_failed` to stderr.
- One record per request. Streaming endpoints emit one record after the stream completes.

---

## 6. Wave 0 File Ownership

Six tracks, disjoint files. The middleware-stack overlap between Auth and HTTP scaffold is resolved by giving HTTP scaffold ownership of `src/server.rs` (the wiring) while Auth owns the middleware *factories* in `src/auth/middleware.rs`. The server calls into auth; the file boundary holds.

Tests live alongside production code via `#[cfg(test)] mod tests` and in `tests/` for integration. Integration tests are owned by the track whose feature is under test in Wave 0; Wave 5 consolidates.

### Track 1: Repo + CI (Implementer, sonnet)

Owns:
- `apps/data_gate/Cargo.toml`
- `apps/data_gate/.github/workflows/ci.yml`
- `apps/data_gate/rustfmt.toml`
- `apps/data_gate/clippy.toml`
- `apps/data_gate/justfile`
- `apps/data_gate/.gitignore`
- `apps/data_gate/deny.toml` (cargo-deny licenses + advisories)
- `apps/data_gate/.mise.toml` (Rust toolchain pin)
- `apps/data_gate/LICENSE`
- `apps/data_gate/README.md` (skeleton only; Wave 5 owns content)

### Track 2: Config (Heavy Implementer, opus)

Owns:
- `apps/data_gate/src/config/mod.rs` (struct tree per Section 3.3)
- `apps/data_gate/src/config/loader.rs` (file read + serde_yaml)
- `apps/data_gate/src/config/validate.rs` (cross-field invariants: scope refs, env var presence, unique ids, vocabulary prefix expansion check)
- `apps/data_gate/src/config/vocabularies.rs` (prefix registry + URI expansion helper; Wave 3 consumes)
- `apps/data_gate/config/example.yaml` (canonical example from Spec Section 4)
- `apps/data_gate/tests/config_loader.rs` (integration tests against `config/example.yaml` and minimal/invalid fixtures)
- `apps/data_gate/tests/fixtures/config/` (config-only fixtures; data fixtures owned by Wave 1)

### Track 3: Error Model (Heavy Implementer, opus)

Owns:
- `apps/data_gate/src/error.rs` (error enum tree, stable codes per Section 4 of this note, RFC 9457 mapping; Wave 2 adds `request_id` + `instance` extension members per Spec §7.bis.6; Wave 4 extends response-side scrubbing)
- `apps/data_gate/tests/error_taxonomy.rs` (snapshot test asserting every code is emitted with the right HTTP status and Problem Details `type` URI)

### Track 4: Auth Trait + API Key (Heavy Implementer, opus)

Owns:
- `apps/data_gate/src/auth/mod.rs` (`AuthProvider` trait, `Principal`, `AuthMode`, `ScopeSet`, `Extensions`)
- `apps/data_gate/src/auth/api_key.rs` (`ApiKeyAuth` impl; Wave 0 verifies env-loaded Argon2id hashes; rotation deferred to Wave 4)
- `apps/data_gate/src/auth/middleware.rs` (tower middleware factories; consumed by `server.rs`, owned here)
- `apps/data_gate/src/auth/scopes.rs` (scope parser, `requires_scope` axum extractor)
- `apps/data_gate/tests/auth_flow.rs` (integration: anonymous denied, valid key admitted, scope-denied returns 403 with `auth.scope_denied`)

### Track 5: Audit Core + Stdout Sink (Heavy Implementer, opus)

Owns:
- `apps/data_gate/src/audit/mod.rs` (`AuditSink` trait, `AuditRecord` struct per Section 5 of this note, canonical JSON serialization, builder)
- `apps/data_gate/src/audit/stdout.rs` (stdout JSONL sink with internal mpsc + writer task)
- `apps/data_gate/src/audit/middleware.rs` (tower layer that captures `request_id`, timing, status, error_code, and emits one record per request; depends on `Principal` from auth)
- `apps/data_gate/tests/audit_record.rs` (asserts record shape on `/health` with `include_health: true`, on an authenticated request, on an auth-failure request)
- Reserved (empty) module slots: `src/audit/file.rs`, `src/audit/syslog.rs`, `src/audit/chain.rs`, `src/audit/redact.rs` (created in Wave 4)

### Track 6: HTTP Scaffold + Health/Ready (Implementer, sonnet)

Owns:
- `apps/data_gate/src/main.rs` (binary entry, CLI flag parsing, signal handling, graceful shutdown)
- `apps/data_gate/src/lib.rs` (public re-exports)
- `apps/data_gate/src/server.rs` (axum app builder; composes middleware from auth and audit; sets up main + optional admin listener)
- `apps/data_gate/src/api/mod.rs` (router assembly; placeholder handlers for data endpoints return `501 not_implemented` until Wave 2)
- `apps/data_gate/src/api/health.rs` (`GET /health`, `GET /ready`; `/ready` consults an `AppState` readiness handle that Wave 1 will populate; Wave 0 reports 200 once startup completes)
- `apps/data_gate/tests/e2e_health.rs` (integration: spin up the binary, hit `/health` and `/ready`, assert audit record emitted, assert `X-Request-Id` header present)

### Overlap resolution log

- `src/auth/middleware.rs` vs `src/server.rs`: Auth owns the factories; HTTP scaffold owns composition. Server calls `auth::middleware::layer(provider)`, never authors middleware itself.
- `src/audit/middleware.rs` vs `src/server.rs`: same pattern. Audit owns the layer; server installs it.
- `src/error.rs` vs everything: Error track owns the file. Other tracks add variants by PR-into-error within Wave 0 only via the architect note's taxonomy; coordination via the taxonomy table, not concurrent edits. Error track lands first.

---

## 7. Integration Points Between Wave 0 Tracks

**Config to Auth, Audit, Server.** Config track exposes a single parsed `Config` value via `config::load(path)`. Auth consumes `Config.auth` to build the `ApiKeyAuth` provider, resolving each `hash_env` to a verified Argon2id PHC string at startup; missing env vars are `config.missing_secret` and abort the process. Audit consumes `Config.audit` to instantiate the sink. Server consumes `Config.server` for binds, timeouts, CORS. Config is read once, owned by `AppState`, never mutated post-startup.

**Auth produces `Principal` consumed by Audit and future handlers.** The auth middleware verifies credentials, builds a `Principal`, and inserts it into request extensions (`Extension<Principal>`). The audit middleware reads `Principal` from extensions when present, projecting `api_key_id`, `auth_mode`, and `scopes_used` into the `AuditRecord`. On auth failure, the auth middleware short-circuits with the appropriate `auth.*` Problem Details response and annotates the request extension with the error code so the audit middleware can still emit a record (`api_key_id: null`). Future handlers extract `Principal` and call `scopes::require(&principal, "social_registry:rows")` which returns `Err(auth.scope_denied)` on miss.

**Audit invocation from middleware.** The audit layer wraps the entire router. It captures start time on request enter, generates a `request_id` (ULID), stores it in extensions and as response header `X-Request-Id`, awaits the inner service, then emits exactly one `AuditRecord` after the response future resolves (per spec Section 13.1: "after the response is sent or after the request is rejected"). The sink's `write` returns immediately by pushing onto an mpsc; an internal task drains to stdout. Drop guard on the writer task flushes on shutdown. Health/ready records are gated by `audit.include_health` (default false) to avoid load-balancer probe noise.

---

## 8. Wave 0 Exit Criteria Checklist

Copied from Spec Section 18.4 and made testable. Each line names the command and the expected observable.

- [ ] **`cargo run -- --config config/example.yaml` starts and serves `/health` and `/ready`.**
  - Command: `cargo run -- --config config/example.yaml &; sleep 2; curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/health`
  - Expected: process binds within 2s; `/health` returns `200`; `/ready` returns `200` in Wave 0 (no datasets registered yet, so the readiness handle is trivially ready; Wave 1 makes it dataset-gated).
- [ ] **An authenticated request produces one well-formed audit record on stdout.**
  - Setup: export `STATS_OFFICE_API_KEY_HASH` to a known Argon2id PHC string whose plaintext is in a test env var.
  - Command: `curl -sS -H "Authorization: Bearer $TEST_KEY" -H "X-Data-Purpose: ci-smoke" http://127.0.0.1:8080/datasets`
  - Expected: stdout contains exactly one JSON line; `jq -e '.api_key_id == "statistics_office" and .request_id | test("^[0-9A-HJKMNP-TV-Z]{26}$")'` exits 0; `.scopes_used` is a non-empty array; no field contains the raw key.
- [ ] **`/ready` returns 503 with JSON body when readiness handle is not ready.**
  - Test asserts via in-process integration test (`tests/e2e_health.rs`) that flipping the readiness handle to "not ready" produces `503` with `application/problem+json` and `code: schema.resource_unavailable` in the response.
- [ ] **CI green: `cargo test`.**
  - Command: `cargo test --all-features --workspace`
  - Expected: all tests pass; stderr is clean of warnings; test log capture asserts on audit records, not just status codes.
- [ ] **CI green: `cargo clippy -D warnings`.**
  - Command: `cargo clippy --all-targets --all-features -- -D warnings`
  - Expected: zero warnings, zero errors.
- [ ] **CI green: `cargo fmt --check`.**
  - Command: `cargo fmt --all -- --check`
  - Expected: exit 0, no diff.
- [ ] **CI green: `cargo deny check`.**
  - Command: `cargo deny check licenses advisories bans`
  - Expected: exit 0; license allowlist matches decision #10.
- [ ] **Startup with missing `hash_env` aborts with `config.missing_secret`.**
  - Command: unset all `*_API_KEY_HASH`, run `cargo run -- --config config/example.yaml`
  - Expected: exit code non-zero within 1s; stderr contains a single JSON line with `event: "config.missing_secret"`; no listener bound.
- [ ] **Two listeners when `server.admin_bind` is configured.**
  - Test: integration test boots with `admin_bind: 127.0.0.1:0`; asserts `/admin/reload` returns `403 auth.admin_required` on main bind and `401` (no creds) on admin bind, and that audit records carry `endpoint_kind: "admin"`.
- [ ] **`X-Request-Id` echoed on every response.**
  - Command: `curl -sS -D - http://127.0.0.1:8080/health | grep -i x-request-id`
  - Expected: header present; value is a valid ULID; identical to the record_id in the audit record for that request.

---

## 9. Risks and Open Questions Affecting Wave 1+

1. **DataFusion / arrow version coupling.** Picking `datafusion` minor pins arrow. Wave 1's `Source` returns `RecordBatch` from that arrow; Wave 3's CSVW type mapping depends on the same arrow type system. Bumping later means re-typing the trait. *Mitigation:* lock the minor in Wave 0's `Cargo.toml`, bump only at wave boundaries.
2. **`serde_yaml` maintenance.** Upstream is archived. Choosing `serde_yml` or another fork in Wave 0 is reversible but every config change touches it; flag for re-evaluation before Wave 3.
3. **XLSX fixture availability (Section 17 item 3).** Wave 1 cannot finish without a representative file. Either Jeremi supplies one or we generate a synthetic registry in Wave 1's fixtures track. Architect's recommendation: synthetic, committed to `fixtures/`, with a README documenting the shape.
4. **Disclosure control semantics for non-count measures (Wave 2).** When a group's `count` exceeds `min_group_size` but a `sum`/`avg` measure is computed over a sparse column, is the group still "safe"? Spec says yes (threshold is on group size, not measure cardinality). Architect agrees; Wave 2 must encode this explicitly in `disclosure.rs` and test it.
5. **Combined-query disclosure attack (Wave 2 staff focus).** A `count` aggregate plus a subsequent `sum` aggregate on the same group-by can leak a single row even with `min_group_size: 5`. V1's defense is operator policy (do not configure both), not algorithmic. Document this explicitly in `decisions/wave-2.md`.
6. **CSVW + DCAT-AP JSON-LD context strategy (Wave 3).** Inline `@context` is simpler but bloats every response; hosted context requires a stable public URL. Architect leans inline for V1 (zero hosting requirements), revisit in V1.x.
7. **Admin bind topology vs middleware composition.** A second listener means two router instances share auth/audit middleware factories but not state. Trivial in axum but a foot-gun if someone wires `AppState` once. Wave 4's admin track must assert this via test.
8. **Audit chain rotation (Wave 4).** Tamper-evident chaining and file rotation interact: a new file segment must carry the prior file's tail hash in its header record, or chain verification breaks at rotation boundaries. Worth a sentence in Wave 4's note now so the file-sink author and chain author don't ship incompatible designs.
9. **Argon2id parameters (Wave 4).** OWASP 2026 guidance must be re-read at Wave 4 kickoff; pin parameters in `auth::api_key` config, not as hard-coded constants, so we can bump without recompiling.

---

## 10. Addendum (2026-05-15): integration with Spec §7.bis API Conventions

Spec §7.bis was added after Wave 0 shipped. The wire-shape change is small (RFC 9457 obsoletes 7807, identical payload); the new constraints are concentrated in Waves 1, 2, and 4.

### Applied retroactively in Wave 0
- Doc strings and decision text updated from RFC 7807 to RFC 9457 (cosmetic; the `http-api-problem` crate output is unchanged).
- `filter.too_many_values` status changed from 400 to 413 per §7.bis.5. Both `tests/error_taxonomy.rs` and the taxonomy table in this note updated.

### Carried forward to Wave 1 (architect brief)
- `IngestPlan` carries a per-resource `ingest_ulid: Ulid`, rotated on every successful re-ingest. Used in Wave 2 as the ETag validator (`"ingest-<ULID>"`, §7.bis.4) and as the seed encoded into pagination cursors (§7.bis.3); reload-rotated cursors then surface as `pagination.cursor_invalidated` (409).

### Carried forward to Wave 2 (architect deliverables expand)
- Response envelope `{ data, pagination: { next_cursor, has_more }, meta: { request_id, computed_at } }` for collection endpoints; singletons stay top-level.
- Cursor encoding/decoding (opaque, encodes primary key + filter set + ingest ULID). New taxonomy entry: `pagination.cursor_invalidated` (409).
- ETag + `If-None-Match` → 304; `Cache-Control` + `Last-Modified` + `Link` (RFC 8288) headers.
- Error response body gains `request_id` and `instance` extension members per §7.bis.6 (no production path emits these today; the auth layer wraps an empty sub-router).
- Content-Type negotiation: `application/json` for success, `application/problem+json` for errors, `application/ld+json` for DCAT-AP (Wave 3).
- Possibly add `filter.invalid_value_semantic` (422) per §7.bis.5 when a real case appears; current `filter.invalid_value` (400) stays for parse errors.

### Carried forward to Wave 4 (audit schema extension)
- `AuditRecord` gains `cached: bool`, set on 304 cache-hit responses (§7.bis.4). Cleaner than overloading `endpoint_kind`. Default false.

### Carried forward to Wave 5
- End-to-end coverage: cursor pagination round-trip, ETag/304 revalidation, content-type negotiation across success and error paths.

---

End of Wave 0 architect note.
