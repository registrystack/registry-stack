# Wave 1 Architecture Decisions

Status: locked for Wave 1 execution. Architect: code-architect (opus). Spec: `Spec.md` (V1, with §7.bis 2026-05-15). Builds on `decisions/wave-0.md` and incorporates findings from `decisions/wave-0-review.md`.

This note is the contract Wave 1's seven tracks build against. It is abstract by design: trait shapes, file ownership, integration seams, exit criteria. It is not code.

The single load-bearing decision is splitting **Source** (byte production) from **Format** (byte decoding). Wave 0 §3.4 sketched a `Source` trait that conflated the two; this note unfolds the split, justifies it, restates file layout, and rebuilds the seven tracks around it.

Terminology addendum after the 2026-05-15 entity-layer amendment: this note was drafted before the public `resource` term was retired. Inside Wave 1, any `resource_id`, `ResourceConfig`, "configured resource", or cache path segment should now be read as the private storage-layer `table_id` / `TableConfig`. The Source/Format split, cache lifecycle, DataFusion registration, and readiness semantics are unchanged; the public entity layer is specified separately in `Spec.md` §6.bis and `decisions/wave-2-entity-layer.md`.

---

## 1. Decisions Log

| # | Decision | Rationale |
|---|---|---|
| W1-1 | **Source/Format split.** A `Source` produces bytes plus a change token; a `Format` decodes those bytes into Arrow `RecordBatch` streams. Combinations are free. | DataFusion separates `ObjectStore` (bytes) from `FileFormat` (decode); we match that shape. New byte producers (HTTP, S3, SharePoint, Nextcloud) ship without touching decoders; new decoders (JSONL, fixed-width, Avro) ship without touching producers. Wave 0 §3.4's single `Source::read -> Stream<RecordBatch>` would force every byte producer to know every decoder. |
| W1-2 | **Naming: `Source` and `Format`.** `Format` over `Decoder` because the surface area covers both decoding (input) and (later, V2) encoding metadata; "Format" is also the DataFusion term and the spec's own term in §5. | Keep names short and aligned with the larger ecosystem. |
| W1-3 | **Layout deviation from Spec §18.1.** Spec puts `csv.rs`, `xlsx.rs`, `parquet.rs` under `src/source/`. With the split, byte producers live in `src/source/`, decoders live in `src/format/`. | The published tree's layout pre-supposes the conflated trait. Splitting source/format and leaving the files under one directory would create two unrelated layers in the same module. Flagged: Spec §18.1 needs a follow-up edit. Justification recorded here so Wave 2 and Wave 3 reviewers see the precedent. |
| W1-4 | **Ingest pipeline file split.** `src/ingest.rs` would have three concurrent editors under the Spec §18.5 table. Replace with a module: `src/ingest/mod.rs` (public `IngestPlan` + `IngestRegistry`), `src/ingest/validation.rs`, `src/ingest/cache.rs`, `src/ingest/refresh.rs`. | Disjoint files restore the wave-coordination model. The public API stays in `mod.rs`; submodules are implementation. |
| W1-5 | **`Format` trait skeleton landed up front by Architect as a precondition file, not by a track.** A single ~40-line stub in `src/format/mod.rs` declaring the trait, the input/output types, and the registry signature. Tracks 1-3 implement against it. | Avoids the "Track 1 owns both `Source` and `Format` skeletons" coordination smell; lets the three decoder tracks start in parallel. |
| W1-6 | **`IngestPlan.ingest_ulid: Ulid` rotated atomically with table swap.** Old ULID remains observable until DataFusion `register_table` replaces the old table; if registration fails, the old ULID stays and the previous successful registration keeps serving. | This is the load-bearing carry-forward from Wave 0 §10 addendum: Wave 2 reads `ingest_ulid` for ETags (`"ingest-<ULID>"`) and cursor encoding. Rotation atomicity = cursor invalidation guarantee. |
| W1-7 | **Cache file naming: `cache/<dataset_id>/<resource_id>/<ingest_ulid>.parquet`.** Content-addressed by ULID; survives process restart; admin GC pass deletes old files. | Atomic rename within the same directory works on all V1 target filesystems (ext4, xfs, APFS, container overlay-fs). Cross-mount rename is out of scope; cache dir must live on one filesystem. |
| W1-8 | **DataFusion table backed by `ListingTable` over the single Parquet file.** Atomic swap is `SessionContext::register_table(name, Arc<dyn TableProvider>)` which replaces the previous registration; outstanding query handles against the old `Arc` keep working until dropped. | Simplest atomic swap that DataFusion natively supports. No partitioning gymnastics in V1. |
| W1-9 | **XLSX is buffered to memory.** `calamine` is non-streaming. Cap via `RequestBodyLimitLayer` does not apply here (this is file input); enforce a `xlsx.max_file_bytes` config knob (default 256 MiB), reject larger files with `ingest.source_unreadable`. | Honest about the cost. Memory bound is documented; the alternative (custom XLSX streamer) is out of scope. |
| W1-10 | **CSV: streaming via the `csv` crate** wrapped in a Tokio `spawn_blocking` for the parse step. Header row + data range honoured via per-resource config. | `csv-async` was an option in Wave 0's inventory; the sync `csv` crate plus `spawn_blocking` is simpler, faster on `RecordBatch`-sized chunks, and avoids the async-bytestream-to-Arrow conversion boilerplate. |
| W1-11 | **Parquet: native `parquet` reader (re-exported by DataFusion); no double dependency.** Parquet is already Arrow-native, so the `Format` impl is mostly a passthrough that fixes up Arrow schema and yields `RecordBatch`es. | Matches Wave 0's "do not bring in a second arrow" rule. |
| W1-12 | **Format dispatch: explicit `format:` discriminant on `ResourceConfig`, additive to existing `SourceConfig::File`.** Additive only; default = infer from path extension when omitted. | The Wave 0 `SourceConfig::File` variant carries only `path / header_row / data_range`. Add `ResourceConfig.format: Option<ResourceFormat>` where `ResourceFormat = Csv { delimiter?, quote? } | Xlsx { sheet } | Parquet`. `sheet` migrates off `ResourceConfig.sheet` (deprecated alias, kept for one wave). |
| W1-13 | **Readiness state lives in `AppState` as `Arc<tokio::sync::watch::Sender<ReadinessSnapshot>>`.** Health handler reads `.borrow()`. Pure watch channel, not `RwLock<HashMap>`: lock-free reads, single writer = the ingest task. | Avoids ergonomic friction in the `/ready` handler; gives Wave 4's admin endpoint a free "wait for ready" primitive (`watch::Receiver::changed`). |
| W1-14 | **Per-refresh exponential backoff** on read/parse failures: 30s → 60s → 120s → 240s → cap 600s, reset on success. State is per-resource. | The refresh loop must not pound a flaky file source. Same cap regardless of policy. |
| W1-15 | **Schema mismatch policy.** Mid-refresh: previous successful registration stays serving; new attempt logs `ingest.schema_mismatch` and is surfaced in `/ready` only if no prior successful ingest existed. At startup: resource registers as `Failed`; `/ready` returns 503 listing failed resources. | Spec §6 step 3: "refuse to register the resource ... continue serving previously-loaded resources." Codified here. |

Items confirmed by Jeremi (carry-forward from Wave 0):
- Synthetic fixtures are authorized for Wave 1's fixtures track to generate.

---

## 2. Trait Signatures

Signatures and docstrings only; no bodies. The four module files (`src/source/mod.rs`, `src/format/mod.rs`, `src/ingest/mod.rs`, plus the readiness type in `src/api/health.rs`) carry these contracts.

### 2.1 `Source` (`src/source/mod.rs`)

```rust
/// A byte producer for ingestion.
///
/// Implementations open a logical resource (local file path, future HTTP URL,
/// future S3 key) and yield a byte stream plus a change token. They are
/// agnostic to the decoded format; pairing with a [`Format`] happens in
/// `IngestPlan`.
///
/// V1 impl: `LocalFileSource` (`src/source/local_file.rs`).
/// V1.x targets: HTTP, S3, SharePoint, Nextcloud. Each is a new struct
/// implementing this trait; no other code in the gateway changes.
///
/// Forward compatibility:
/// - Streaming sources (Kafka, CDC): add `async fn subscribe()
///   -> Result<BoxStream<'static, ChangeEvent>>` in V2. Not in V1.
/// - Pre-fetch sizing / range reads: a `range()` method may join the
///   trait in V1.x; current shape does not preclude it.
pub trait Source: Send + Sync + 'static {
    /// Stable identifier for this source instance, for logging and
    /// audit. Never includes secrets; for `LocalFileSource` this is the
    /// canonical path string.
    fn descriptor(&self) -> SourceDescriptor;

    /// Open the source for reading. Returns a boxed `AsyncRead` plus a
    /// `SourceMetadata` snapshot captured at open time (mtime, size,
    /// content-type hint). The reader yields raw bytes; decoding is the
    /// caller's job. `Format::decode` consumes the reader exactly once.
    fn open<'a>(&'a self) -> SourceFuture<'a, OpenedSource>;

    /// Sample the source's change token without reading the body. Used
    /// by the refresh loop's `mtime` policy. Returns `None` when the
    /// source has no detectable change token (refresh degrades to
    /// `interval` or `manual`).
    fn metadata<'a>(&'a self) -> SourceFuture<'a, SourceMetadata>;
}

/// Boxed `AsyncRead` plus the metadata captured at open time. The
/// metadata is the value the change-token comparison MUST use for this
/// read; sampling `metadata()` again later would race against an
/// in-flight refresh.
pub struct OpenedSource {
    pub reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    pub metadata: SourceMetadata,
}

/// Snapshot of source-level change-detection inputs.
#[derive(Clone, Debug)]
pub struct SourceMetadata {
    /// File mtime (local-file source). `None` for sources that don't
    /// expose mtime (future HTTP without `Last-Modified`).
    pub mtime: Option<OffsetDateTime>,
    /// Byte size when known (skipped for streaming sources).
    pub size_bytes: Option<u64>,
    /// `ETag` or equivalent strong validator. Local-file source returns
    /// a `dev:inode:mtime_ns:size` fingerprint so refresh can detect
    /// rename-in-place or atomic-replace mutations the mtime alone
    /// might miss.
    pub etag: Option<String>,
    /// Content-type hint from the producer. Local-file source returns
    /// `None` (extension-based dispatch happens in the format layer).
    pub content_type: Option<String>,
}

/// Stable identifier for an open source instance.
#[derive(Clone, Debug)]
pub struct SourceDescriptor {
    /// Scheme: `file`, `http`, `s3`, ... Matches `SourceConfig` tag.
    pub scheme: &'static str,
    /// Human-readable target (path, URL minus credentials, S3 key).
    pub target: String,
}

/// Manually-typed future to match the project's existing
/// non-`async_trait` convention (`AuthProvider`, `AuditSink`).
pub type SourceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SourceError>> + Send + 'a>>;

/// Errors raised by a `Source` impl. Mapped to `ingest.*` taxonomy
/// codes in `IngestPlan`.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source not found")]
    NotFound,
    #[error("source unreadable: {0}")]
    Unreadable(String),
    #[error("source I/O error")]
    Io(#[source] std::io::Error),
}
```

### 2.2 `Format` (`src/format/mod.rs`)

```rust
/// A decoder from a byte stream into Arrow `RecordBatch`es.
///
/// Implementations are stateless. Per-resource hints (header row, data
/// range, sheet name, declared schema) arrive as `FormatHints` so the
/// same decoder serves every resource of its format.
///
/// V1 impls: `CsvFormat`, `XlsxFormat`, `ParquetFormat`.
/// V1.x targets: `JsonlFormat`, `AvroFormat`, `ArrowIpcFormat`. Each is
/// a new struct implementing this trait plus one line in the registry.
///
/// XLSX note: `calamine` is non-streaming. `XlsxFormat::decode` reads
/// the entire workbook into memory before yielding the first batch.
/// `IngestPlan` enforces a max-file-bytes guard before calling this
/// trait; `XlsxFormat` does not enforce it itself.
pub trait Format: Send + Sync + 'static {
    /// Canonical name (`"csv"`, `"xlsx"`, `"parquet"`); used in audit
    /// and operational logs.
    fn name(&self) -> &'static str;

    /// Decode a byte stream into a `RecordBatch` stream.
    ///
    /// Implementations consume `reader` exactly once. `hints` carries
    /// per-resource configuration (sheet, header row, delimiter,
    /// declared schema for type coercion). Schema *validation* is not
    /// the format's job; it returns observed Arrow types and lets
    /// `ingest::validation` decide whether to accept.
    fn decode<'a>(
        &'a self,
        reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
        hints: FormatHints,
    ) -> FormatFuture<'a, DecodedStream>;
}

/// `RecordBatch` stream plus the schema as observed at decode time.
/// `IngestPlan` uses the observed schema for validation against the
/// declared schema in config.
pub struct DecodedStream {
    pub observed_schema: arrow::datatypes::SchemaRef,
    pub batches:
        BoxStream<'static, Result<arrow::record_batch::RecordBatch, FormatError>>,
}

/// Per-resource decoding configuration. Built by `IngestPlan` from the
/// `ResourceConfig`; never reaches back into `Config` from inside a
/// `Format` impl.
#[derive(Clone, Debug)]
pub struct FormatHints {
    pub sheet: Option<String>,        // XLSX
    pub header_row: Option<u32>,      // CSV / XLSX (1-indexed in config)
    pub data_range: Option<String>,   // XLSX, e.g. "A2:E100000"
    pub delimiter: Option<u8>,        // CSV
    pub quote: Option<u8>,            // CSV
    /// Declared field types from the config. Decoders MAY use this for
    /// type coercion (e.g. CSV string-to-date parsing). `None` for any
    /// field means "let the decoder infer".
    pub declared: Arc<DeclaredSchema>,
}

/// Errors raised by a `Format` impl. Mapped to `ingest.*` taxonomy
/// codes in `IngestPlan`.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("format parse error: {0}")]
    Parse(String),
    #[error("format I/O error")]
    Io(#[source] std::io::Error),
    #[error("format limit exceeded: {0}")]
    LimitExceeded(String),
}

pub type FormatFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FormatError>> + Send + 'a>>;

/// Registry of available formats, looked up by name. V1 registers
/// CSV/XLSX/Parquet at startup. The registry is `Arc<dyn>` so it lives
/// in `AppState` and the ingest task holds a clone.
pub struct FormatRegistry { /* private */ }

impl FormatRegistry {
    pub fn with_v1_defaults() -> Self { /* ... */ }
    pub fn get(&self, name: &str) -> Option<Arc<dyn Format>>;
    pub fn register(&mut self, name: &'static str, format: Arc<dyn Format>);
}
```

### 2.3 `IngestPlan` (`src/ingest/mod.rs`)

```rust
/// Per-resource ingestion lifecycle. One `IngestPlan` per
/// `(dataset_id, resource_id)`.
///
/// Holds:
/// - The `Source` instance (boxed dyn for trait-object dispatch).
/// - The `Format` instance (looked up from `FormatRegistry`).
/// - The declared `SchemaConfig` (immutable; read-only after build).
/// - The current `ingest_ulid` and `ResourceReadiness` (mutable, behind
///   internal sync).
/// - The current `CacheLocation` (path to the cached Parquet).
///
/// Lifecycle:
/// 1. `IngestPlan::new(...)` constructs the plan. No I/O.
/// 2. `IngestPlan::initial_ingest()` runs once at startup. Drives the
///    Source -> Format -> validation -> cache -> register pipeline.
///    On success, sets `Ready { ingest_ulid, schema, registered_at }`;
///    on failure, sets `Failed { code, since }`.
/// 3. `IngestPlan::refresh()` is called by the refresh loop (mtime or
///    interval) or by the admin endpoint. Same pipeline, but the
///    previous registration stays serving if anything fails before the
///    final table swap.
/// 4. `IngestPlan::readiness()` returns the current state for `/ready`.
pub struct IngestPlan { /* private */ }

impl IngestPlan {
    pub fn new(
        dataset_id: DatasetId,
        resource_id: ResourceId,
        source: Arc<dyn Source>,
        format: Arc<dyn Format>,
        schema: SchemaConfig,
        cache_root: Arc<Path>,
        df_ctx: Arc<datafusion::execution::context::SessionContext>,
    ) -> Self;

    /// Run the first ingest. Idempotent across retries.
    pub async fn initial_ingest(&self) -> Result<(), IngestError>;

    /// Re-run the pipeline. On success, rotates `ingest_ulid` and
    /// atomically swaps the DataFusion table. On failure, leaves prior
    /// state intact.
    pub async fn refresh(&self) -> Result<(), IngestError>;

    /// Current readiness state. Cheap; reads from an internal arc-swap.
    pub fn readiness(&self) -> ResourceReadiness;

    /// Stable composite identifier used by the cache path and audit.
    pub fn descriptor(&self) -> (&DatasetId, &ResourceId);
}

/// Per-resource readiness state. Owned by `IngestPlan`, observed
/// through `AppState`'s readiness watch channel.
#[derive(Clone, Debug)]
pub enum ResourceReadiness {
    /// Not yet attempted, or in progress.
    NotReady,
    /// Last attempt succeeded; the DataFusion table named
    /// `<dataset_id>__<resource_id>` is registered with this ULID.
    Ready {
        ingest_ulid: ulid::Ulid,
        schema: arrow::datatypes::SchemaRef,
        registered_at: OffsetDateTime,
    },
    /// Last attempt failed. Carries the stable `ingest.*` code and the
    /// timestamp of the first failure (not the most recent).
    Failed {
        code: &'static str,
        since: OffsetDateTime,
    },
}

/// Top-level registry of every configured resource's `IngestPlan`.
/// Held in `AppState`. Drives startup, refresh, and reload.
pub struct IngestRegistry { /* private */ }

impl IngestRegistry {
    pub fn from_config(
        config: &Config,
        formats: Arc<FormatRegistry>,
        cache_root: Arc<Path>,
        df_ctx: Arc<datafusion::execution::context::SessionContext>,
    ) -> Result<Self, IngestError>;

    /// Walk every plan, calling `initial_ingest`. Updates the readiness
    /// watch channel after each plan completes. Returns once every plan
    /// is in `Ready` or `Failed` state.
    pub async fn run_initial_ingest(
        &self,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
    );

    /// Spawn the per-plan refresh tasks. Returns the join set so the
    /// process can await them on shutdown.
    pub fn spawn_refresh_tasks(
        self: Arc<Self>,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
    ) -> JoinSet<()>;

    /// Trigger a reload of a single resource (Wave 4 admin endpoint).
    pub async fn reload(
        &self,
        dataset: &DatasetId,
        resource: &ResourceId,
    ) -> Result<(), IngestError>;
}

/// Aggregate readiness across every resource. The `/ready` handler
/// returns 200 iff `failed.is_empty() && not_ready.is_empty()`.
#[derive(Clone, Debug, Default)]
pub struct ReadinessSnapshot {
    pub ready: BTreeMap<(DatasetId, ResourceId), ulid::Ulid>,
    pub not_ready: BTreeSet<(DatasetId, ResourceId)>,
    pub failed: BTreeMap<(DatasetId, ResourceId), &'static str>,
}
```

---

## 3. Refresh State Machine

States are per-`IngestPlan`. Transitions are driven by the refresh loop, the admin endpoint, or the initial-ingest pass.

```
                           +-------------------+
                           |       Idle        |<--+
                           +-------------------+   |
                                |                  |
       tick OR mtime change OR  |                  | success: swap done
       admin reload triggered   |                  | ULID rotated
                                v                  |
                           +-------------------+   |
                +--------->|     Polling       |   |
                |          +-------------------+   |
                |              |                   |
                |   no change  |                   |
                |              v                   |
                |          +-------------------+   |
                |          |     Reading       |   |
                |          +-------------------+   |
                |              |                   |
                |              v                   |
                |          +-------------------+   |
                |          |    Validating     |---+----> [hard fail]
                |          +-------------------+        Failed{code, since}
                |              |
                |              v
                |          +-------------------+
                |          |     Caching       |---+----> [hard fail]
                |          +-------------------+        Failed
                |              |
                |              v
                |          +-------------------+
                |          |   Registering     |---+----> [hard fail]
                |          +-------------------+        Failed
                |              |
                |              v swap atomic
                |          +-------------------+
                +----------|       Idle        |
                           +-------------------+
                                ^
                                |
            +-------------------+-------------------+
            |                                       |
            |             [retryable fail]          |
            |   Backoff{attempt, next_at} ----------+
            |                                       |
            +---------------------------------------+
                  refresh loop sleeps until next_at
```

Atomicity guarantees:

1. **Cache write is atomic.** Decoder writes to `cache/<ds>/<rs>/.tmp-<ULID>.parquet`, then `std::fs::rename` to `cache/<ds>/<rs>/<ULID>.parquet`. POSIX rename is atomic within a filesystem; cross-filesystem rename is rejected at startup (cache_root validation).
2. **DataFusion table swap is atomic.** `SessionContext::register_table(name, new_provider)` replaces the previous registration in a single critical section. Outstanding `RecordBatchStream`s holding an `Arc<dyn TableProvider>` keep their pre-swap view; new queries see the new ULID.
3. **`ingest_ulid` rotation happens after both above succeed.** The plan's internal `ArcSwap<ResourceReadiness>` is updated in one store. Wave 2's ETag and cursor encoding read this atomically.
4. **Schema mismatch never causes a partial swap.** If validation fails, the pipeline aborts before the cache write; if the cache write fails, registration is not attempted; if registration fails, no ULID rotates. The previous `Ready` state remains the observable truth.
5. **Backoff is per-plan, not global.** A flaky resource does not stall sibling refresh tasks.

---

## 4. Schema Validation Rules

Validation runs against the observed Arrow schema from `Format::decode` and the declared `SchemaConfig` from config. Every rule maps to a Wave 0 `ingest.*` code; no new codes are required for V1.

| Failure mode | Behaviour | Mapped code |
|---|---|---|
| Declared column missing from observed schema | Hard fail; refuse to register | `ingest.schema_mismatch` |
| Observed column not in declared schema, `strict: true` | Hard fail; refuse to register | `ingest.strict_extra_column` |
| Observed column not in declared schema, `strict: false` | Warn in operational log; project away the column before caching | (no code; logged) |
| Declared `string` vs observed `Utf8` | Accept | n/a |
| Declared `number` vs observed `Float64` / `Int64` / `Decimal128` | Accept; cast `Int*` to `Float64` if measure operations need it (deferred to query layer) | n/a |
| Declared `integer` vs observed `Int64` / `Int32` | Accept; cast to `Int64` | n/a |
| Declared `boolean` vs observed `Boolean` | Accept | n/a |
| Declared `date` vs observed `Date32` | Accept | n/a |
| Declared `date` vs observed `Utf8` (CSV/XLSX) | Try to parse with `time::Date::parse` using RFC 3339 / ISO 8601; on failure for any non-null row, hard fail | `ingest.schema_mismatch` |
| Declared `timestamp` vs observed `Timestamp(_, _)` | Accept; normalise to `Timestamp(Millisecond, "UTC")` | n/a |
| Declared `timestamp` vs observed `Utf8` | Parse RFC 3339; otherwise hard fail | `ingest.schema_mismatch` |
| Declared non-null column has null rows | Hard fail | `ingest.schema_mismatch` |
| Declared `primary_key` field is missing or non-unique | Hard fail | `ingest.schema_mismatch` |
| Declared type cannot be cast to observed (e.g. declared `integer`, observed `Utf8` of non-numeric text) | Hard fail | `ingest.schema_mismatch` |
| Source returns zero rows | Warn; register the empty table | (no code; logged) |
| Field name case mismatch (declared `MunicipalityCode`, observed `municipality_code`) | Hard fail | `ingest.schema_mismatch` |

Validation runs once per ingest, before the cache write. The validator emits a structured `ingest.schema_mismatch` log record carrying:

```
event: ingest.schema_mismatch
dataset_id: <id>
resource_id: <id>
declared: [ { name, type, nullable }, ... ]
observed: [ { name, type, nullable }, ... ]
diff: [ "missing: foo", "type_mismatch: bar (declared date, observed Utf8)", ... ]
```

Field-level details DO appear in the operational log because they are operator-visible, not client-visible. The `/ready` response surfaces only `dataset_id`, `resource_id`, and the stable `code`; never the diff itself (spec §13 scrubbing).

---

## 5. Cache and Registration Design

### Layout

```
cache/
  <dataset_id>/
    <resource_id>/
      <ingest_ulid>.parquet      # currently-registered (or just-swapped)
      <prev_ingest_ulid>.parquet # one previous, kept for rollback
      .tmp-<ingest_ulid>.parquet # in-flight; never registered
```

The cache root is configured via `server.cache_dir` (new config field, additive; default `./cache`). Validated at startup: must exist, be writable, and live on a single filesystem (rename atomicity).

### Write path

1. Decoder yields `RecordBatch` stream.
2. Validation projects/casts/rejects per §4.
3. Writer opens `.tmp-<ULID>.parquet`, streams batches through `parquet::arrow::AsyncArrowWriter`, closes, fsyncs.
4. `rename(.tmp-<ULID>.parquet, <ULID>.parquet)`.
5. `register_table(<dataset_id>__<resource_id>, ListingTable::new([<ULID>.parquet]))`.
6. ULID rotates in `IngestPlan::readiness`; readiness watch channel publishes.
7. Garbage-collect: delete files older than the two most recent ULIDs (keep current + previous for rollback diagnosis).

### Failure semantics

- Step 3 fails: `ingest.cache_write_failed`; `.tmp-*` may exist and is reaped on next refresh.
- Step 4 fails (rename): `ingest.cache_write_failed`; previous `<ULID>.parquet` still in place.
- Step 5 fails: `ingest.registration_failed`; new Parquet file exists on disk but is not registered. Next refresh attempt overwrites with a fresh ULID; the orphan is GC'd.
- After step 7 GC: a single previous Parquet remains for at most one refresh cycle. Operators can disable GC via `server.cache_retention: keep_all` (V1.x knob; deferred).

### Cross-process / restart behaviour

The cache directory survives process restart. On boot, `IngestRegistry::from_config` does not pre-trust existing cache files; every resource starts in `NotReady` and `initial_ingest` runs the full pipeline. Wave 5 may add a cache-warm-start optimisation; not in scope here.

---

## 6. File Ownership for the 7 Tracks

Architect-laid precondition files (committed before tracks start):
- `src/format/mod.rs` (trait skeleton + registry signature; ~40 LOC).
- `src/source/mod.rs` (trait skeleton; ~30 LOC).
- `src/ingest/mod.rs` (`IngestPlan`, `IngestRegistry`, `ResourceReadiness`, `ReadinessSnapshot` signatures; ~60 LOC). Empty submodules.

Why precondition: lets all seven tracks start in parallel without contention over the shared trait surface. The Architect lands these stubs in a single commit so reviewers can lock the interface before Wave 1 fans out.

### Track 1: Source trait + Local-file source (Implementer, sonnet)

Owns:
- `apps/data_gate/src/source/mod.rs` (final, beyond the precondition stub: `SourceError`, `SourceMetadata`, `OpenedSource`, `SourceDescriptor`)
- `apps/data_gate/src/source/local_file.rs` (`LocalFileSource` impl; mtime + fingerprint ETag)
- `apps/data_gate/tests/source_local_file.rs` (open, metadata, change-token rotation)

### Track 2: CSV format (Implementer, sonnet)

Owns:
- `apps/data_gate/src/format/mod.rs` (final, beyond precondition: `FormatError`, `FormatHints`, `DecodedStream`, `FormatRegistry`)
- `apps/data_gate/src/format/csv.rs` (`CsvFormat` impl; `csv` crate + `spawn_blocking`)
- `apps/data_gate/tests/format_csv.rs` (well-formed CSV, malformed CSV from fixtures, header_row honour)

### Track 3: XLSX format (Implementer, sonnet)

Owns:
- `apps/data_gate/src/format/xlsx.rs` (`XlsxFormat` impl; `calamine`)
- `apps/data_gate/tests/format_xlsx.rs` (well-formed XLSX, sheet selection, data_range, max-file-bytes guard)

### Track 4: Parquet format (Implementer, sonnet)

Owns:
- `apps/data_gate/src/format/parquet.rs` (`ParquetFormat` impl; `parquet::arrow::async_reader`)
- `apps/data_gate/tests/format_parquet.rs` (well-formed Parquet, schema-mismatched Parquet)

### Track 5: Schema validation (Heavy Implementer, opus)

Owns:
- `apps/data_gate/src/ingest/validation.rs` (the §4 rule table in code; `validate(declared, observed) -> Result<ProjectionPlan, IngestError>`)
- `apps/data_gate/src/ingest/declared_schema.rs` (compiled `DeclaredSchema` from `SchemaConfig`; declared-to-Arrow type mapping)
- `apps/data_gate/tests/ingest_validation.rs` (every row of the §4 table as a unit test)

### Track 6: Parquet cache + DataFusion registration + Refresh loop (Implementer, sonnet)

Track 6 owns the full ingest plumbing. Splitting cache/refresh into two tracks would create concurrent edits on `IngestPlan::refresh()`; keeping them together avoids that and matches the size of the work.

Owns:
- `apps/data_gate/src/ingest/mod.rs` (final, beyond precondition: `IngestPlan`, `IngestRegistry`, `ResourceReadiness`, `ReadinessSnapshot`, the orchestration logic)
- `apps/data_gate/src/ingest/cache.rs` (write `.tmp-*.parquet`, rename, GC)
- `apps/data_gate/src/ingest/refresh.rs` (per-plan refresh task, backoff, mtime polling)
- `apps/data_gate/src/api/health.rs` (extension: `/ready` consults the readiness watch channel; replaces the trivial 200)
- `apps/data_gate/tests/ingest_refresh.rs` (mtime poll re-ingests; backoff on repeated failure; admin reload path stub)
- `apps/data_gate/tests/ingest_register.rs` (atomic swap; outstanding handles survive; readiness watch publishes)

This track depends on Tracks 1-5; it starts after the precondition lands and consumes their outputs once they reach merge.

### Track 7: Synthetic fixtures (Implementer, haiku)

Owns:
- `apps/data_gate/fixtures/social_registry.xlsx` (~1k rows, two sheets per Wave 0 §1 item 3; PII-free synthetic data)
- `apps/data_gate/fixtures/social_registry.csv` (same data; matches XLSX shape)
- `apps/data_gate/fixtures/social_registry.parquet` (same data; built from CSV via Arrow)
- `apps/data_gate/fixtures/malformed_csv_truncated.csv` (mid-row EOF; for `format_csv` malformed test)
- `apps/data_gate/fixtures/xlsx_type_mismatch.xlsx` (declared date column has free-text rows; for `ingest_validation` test)
- `apps/data_gate/fixtures/parquet_schema_mismatch.parquet` (extra column not in declared schema; for `format_parquet` test)
- `apps/data_gate/fixtures/README.md` (documents shape and generation method)
- `apps/data_gate/scripts/generate_fixtures.sh` (regenerates from a seed; bash, `#!/usr/bin/env bash` + `set -euo pipefail`)

This track has no Rust source ownership; it produces test data and a regeneration script. It can start day 1 and is a dependency for Tracks 2-5 integration tests.

### Coordination notes

- The Architect's precondition commit lands first. After it merges, all seven tracks start in parallel.
- Track 5 depends on Tracks 2-4 only for their fixtures, not their source. Track 5 can write its rule table against a hand-crafted `arrow::Schema` independently.
- Track 6 is the integration point. It is the last track to converge; the other six should be at "tests green in isolation" before Track 6's integration tests can run end-to-end.
- The shared file `src/api/health.rs` is touched by Track 6 only. Wave 0 review HIGH-2 (the `/healthz` vs `/health` deviation) was addressed in the post-review fix; Wave 1 only extends the readiness handler to consult the watch channel. No other track edits this file.

---

## 7. Integration Points with Wave 0 Modules

### Config (`src/config/mod.rs`)

Wave 1 reads `Config.datasets[].source / refresh`, `Config.datasets[].resources[].schema / primary_key`.

Additive config changes (no breaking changes to Wave 0):

1. `ResourceConfig.format: Option<ResourceFormat>` (new enum `Csv { delimiter?, quote? } | Xlsx { sheet } | Parquet`). When `None`, dispatch is by file extension on `SourceConfig::File.path`. `ResourceConfig.sheet` becomes a deprecated alias for `ResourceFormat::Xlsx.sheet`; the validator emits a one-shot warning and copies it forward. Removal targeted for V1.x.
2. `ServerConfig.cache_dir: PathBuf` (default `./cache`). Validated at startup as writable + single-filesystem.
3. `ServerConfig.xlsx_max_file_bytes: ByteSize` (default 256 MiB). Bound for the W1-9 memory cap.

Spec §18.1 follow-up: edit the published Spec to (a) put `csv.rs`, `xlsx.rs`, `parquet.rs` under `src/format/`, (b) add `cache_dir` and `xlsx_max_file_bytes` to the example config.

### Error (`src/error.rs`)

The Wave 0 `IngestError` enum (lines 128-142) already covers every Wave 1 failure mode:
- `SourceNotFound` (path missing)
- `SourceUnreadable` (I/O, parse, format limit exceeded)
- `SchemaMismatch` (any §4 hard fail except strict-extra-column)
- `StrictExtraColumn` (§4 strict extra column rule)
- `CacheWriteFailed` (cache write, rename, fsync)
- `RegistrationFailed` (DataFusion `register_table` error)

No new error codes are required for Wave 1. The mapping from `SourceError` / `FormatError` to `IngestError` happens in `src/ingest/mod.rs`:

```text
SourceError::NotFound        -> IngestError::SourceNotFound
SourceError::Unreadable      -> IngestError::SourceUnreadable
SourceError::Io              -> IngestError::SourceUnreadable
FormatError::Parse           -> IngestError::SourceUnreadable
FormatError::Io              -> IngestError::SourceUnreadable
FormatError::LimitExceeded   -> IngestError::SourceUnreadable
```

Per Spec §7.bis these codes appear in the `/ready` 503 body and in audit; never in a client error response from a data endpoint (no Wave 1 code path renders an `IngestError` to a non-`/ready` client).

### Audit (`src/audit/mod.rs`)

Wave 1 does not emit audit records itself (handlers do, Wave 2 introduces them). It DOES consume the audit module in one place: the `/ready` 503 body shape.

`/ready` 503 response body, Problem Details (`application/problem+json`):

```jsonc
{
  "type":   "https://data.example.gov/problems/schema/resource_unavailable",
  "title":  "Resource unavailable",
  "status": 503,
  "detail": "one or more configured resources failed ingest",
  "code":   "schema.resource_unavailable",
  "failed_resources": [
    {
      "dataset_id":  "social_registry",
      "resource_id": "beneficiaries",
      "code":        "ingest.schema_mismatch"
    }
  ]
}
```

The `failed_resources` extension member is a new addition (not currently in `http_api_problem`'s default fields). `Error::to_problem` already supports `.value("...", &json!(...))` for extensions; we add `failed_resources` only on this one path. No `request_id` for `/ready` because `/ready` is unauthenticated and outside the audit middleware's authenticated-only emission policy.

The audit middleware's `dataset_id`, `resource_id`, `aggregate_id`, `row_count`, `suppressed_groups` fields stay `None` in Wave 1; Wave 2's `RequestAuditExt` (flagged in Wave 0 review §6) is the seam.

### Server / `/ready` (`src/server.rs`, `src/api/health.rs`)

Wave 1 introduces `AppState`:

```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub readiness: watch::Receiver<ReadinessSnapshot>,
    pub df_ctx: Arc<datafusion::execution::context::SessionContext>,
    pub ingest: Arc<IngestRegistry>,
}
```

`server::build_app` signature extends to accept an `AppState` (replacing the current `Arc<Config>` parameter). The readiness handler reads `state.readiness.borrow()`; aggregates a `ReadinessSnapshot`; returns 200 with `{ "status": "ok", "resources": <ulid map> }` when fully ready, 503 with the Problem Details body above when any resource is `NotReady` or `Failed`.

The binary (`src/main.rs`) builds `IngestRegistry` after config validation, drives `run_initial_ingest`, then calls `spawn_refresh_tasks`. Initial-ingest is awaited fully before the listener binds. Spec §6: "On startup, the service should ingest all configured datasets immediately. Lazy ingestion is out of scope for V1."

---

## 8. Wave 1 Exit Criteria Checklist

Each item is a command and an expected observable.

- [ ] **CSV fixture ingests and registers.**
  - Command: `cargo test --test ingest_register -- csv_fixture_registers`
  - Expected: test passes; DataFusion `SessionContext::table_exist("social_registry__beneficiaries_csv")` returns true; `readiness_snapshot.ready` contains the resource with a 26-char ULID.

- [ ] **XLSX fixture ingests and registers.**
  - Command: `cargo test --test ingest_register -- xlsx_fixture_registers`
  - Expected: same as CSV, against `fixtures/social_registry.xlsx`.

- [ ] **Parquet fixture ingests and registers.**
  - Command: `cargo test --test ingest_register -- parquet_fixture_registers`
  - Expected: same as CSV, against `fixtures/social_registry.parquet`.

- [ ] **Schema mismatch refuses to register and surfaces via `/ready`.**
  - Command: `cargo test --test ingest_validation -- xlsx_type_mismatch_refuses_register`
  - Expected: ingest fails with `IngestError::SchemaMismatch`; operational log carries `event: ingest.schema_mismatch` with the declared/observed diff; readiness snapshot lists the resource as `Failed`; `/ready` returns 503 with `code: schema.resource_unavailable` and `failed_resources[].code: ingest.schema_mismatch`.

- [ ] **Strict-extra-column refuses to register.**
  - Command: `cargo test --test ingest_validation -- strict_extra_column_refuses`
  - Expected: ingest fails with `IngestError::StrictExtraColumn`; `failed_resources[].code: ingest.strict_extra_column` in `/ready` body.

- [ ] **mtime refresh re-ingests on file change within one poll interval.**
  - Command: `cargo test --test ingest_refresh -- mtime_re_ingests_on_change`
  - Expected: test writes fixture A, ingests; mutates fixture in place; sleeps `2 * interval`; asserts `ingest_ulid` has rotated; asserts `SessionContext::table` returns the new content.

- [ ] **`ingest_ulid` rotation is atomic with table swap.**
  - Command: `cargo test --test ingest_register -- ulid_rotates_with_table_swap`
  - Expected: spawn a query stream against the old ULID's table; trigger refresh; assert the old stream completes successfully against the pre-swap data while a fresh query sees post-swap data.

- [ ] **Backoff on repeated read failures.**
  - Command: `cargo test --test ingest_refresh -- backoff_on_repeated_failure`
  - Expected: simulate four consecutive `SourceError::Unreadable`; assert refresh task sleeps for 30s, 60s, 120s, 240s between attempts (via mocked clock); asserts plan state never flips to `Ready`; assert one operational log per attempt.

- [ ] **Format / Source split: direct unit test.**
  - Command: `cargo test --test source_format_decoupling -- local_file_into_each_format`
  - Expected: test instantiates `LocalFileSource` against each fixture; calls `.open().await`; feeds the resulting `AsyncRead` into `CsvFormat::decode`, `XlsxFormat::decode`, `ParquetFormat::decode` respectively; asserts each yields a non-empty `RecordBatch` stream. No `IngestPlan` involved. This is the proof-of-decoupling exit criterion.

- [ ] **`/ready` aggregation returns 200 when all resources are Ready.**
  - Command: `cargo test --test e2e_health -- ready_200_when_all_resources_registered`
  - Expected: end-to-end test starts the binary with the example config and synthetic fixtures; polls `/ready` until 200; asserts response body contains the resource map with ULIDs.

- [ ] **`/ready` returns 503 with `failed_resources` body when any resource is Failed.**
  - Command: `cargo test --test e2e_health -- ready_503_lists_failed_resources`
  - Expected: end-to-end test starts the binary against a config pointing to a deliberately mismatched fixture; asserts `/ready` returns 503 `application/problem+json` with `code: schema.resource_unavailable` and `failed_resources[0]` carrying `dataset_id`, `resource_id`, and `ingest.schema_mismatch`.

- [ ] **CI green.**
  - `cargo test --all-features --workspace`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo fmt --all -- --check`
  - `cargo deny check licenses advisories bans`
  - Expected: all four exit 0.

---

## 9. Risks and Open Questions Affecting Wave 2+

1. **XLSX buffering memory cost.** `calamine` reads the whole workbook into RAM before yielding rows. The W1-9 cap (`xlsx_max_file_bytes`, default 256 MiB) is a soft mitigation. If real deployments push past this we either (a) chase a streaming XLSX reader (none currently exist in Rust for the OOXML container), or (b) document a hard "preprocess large XLSX to Parquet" runbook. Decision deferred to V1.x; the cap surfaces the cost cleanly today.

2. **DataFusion / arrow version coupling (carry-over from Wave 0 risk #1, now load-bearing).** Wave 1 is the first wave that actually compiles DataFusion code. The `datafusion = 53.1` pin from Wave 0 must hold across all of Wave 1; bumping mid-wave changes Arrow types in every decoder. The architect's recommendation: a Day-1 smoke test (`use datafusion::prelude::*; use parquet::arrow::AsyncArrowWriter;`) in Track 6 before any decoder lands, so version friction shows up immediately.

3. **Refresh atomicity on multi-mount cache directories.** POSIX rename is atomic only within a filesystem. Containerised deployments often mount a separate volume at `/var/cache/data_gate`; if `cache_dir` is on that volume, the in-flight `.tmp-*` file must be on the same volume (it is, by construction; both are under `cache_root`). The risk is the cache_root being a *symlink* or a *bind mount* that aliases two filesystems. Mitigation: at startup, write-and-rename a probe file in `cache_root`; abort with `config.validation_error` if it fails.

4. **Cache directory survival across process restart.** Wave 1 always re-ingests on startup, so a stale cache is harmless. But an admin GC pass could delete the currently-registered Parquet from disk while it is held open by DataFusion; on Linux this is safe (file lives until handle closed), but on Windows-style filesystems the file would be unlinkable. Wave 5 deployments are Linux-only per Wave 0 decision #2; flag for V1.x Windows support.

5. **Streaming sources (Kafka / CDC) and the snapshot refresh model.** Spec §6.1 explicitly excludes streaming; V1 is snapshot-only. The `Source` trait surface ships without a `subscribe()` method. When V2 wants streaming, the additive shape is:
   - New trait method `async fn subscribe(&self) -> Result<BoxStream<'static, ChangeEvent>, SourceError>;` with a default `Err(SourceError::Unsupported)` impl so V1 byte-only sources don't need to implement it.
   - `IngestPlan` gains a streaming variant of the refresh state machine.
   - The cache + DataFusion-swap model becomes per-batch instead of per-snapshot.
   This is a Wave 7+ concern; today the trait shape does not preclude it.

6. **`serde_yml` maintenance (carry-over from Wave 0 risk #2).** Two RUSTSEC advisories already ignored in `deny.toml`. Wave 0 reviewer flagged this for Wave 1 kickoff re-evaluation. The Architect's recommendation: keep `serde_yml` through Wave 1 (no config-shape changes that depend on it beyond additive fields); re-evaluate at Wave 2 kickoff alongside the §7.bis-driven cursor encoding.

7. **DataFusion table naming collision.** The naming scheme `<dataset_id>__<resource_id>` assumes neither id contains a literal `__`. Wave 0's id regex (lower-snake, starts with letter) currently does not forbid double-underscore. Tighten the validator in Track 5 or Track 6 to reject ids containing `__`. (Surgical config-validator change; not a breaking schema change.)

8. **Format auto-detection vs explicit `format:` discriminant (W1-12).** The deprecated `ResourceConfig.sheet` alias path is a one-wave concession. Wave 2 should remove it; flag for the Wave 2 architect note.

9. **Concept-URI surfacing for Wave 3.** Wave 1's `DeclaredSchema` should retain the `concept_uri / codelist / unit / language` fields from `FieldConfig` even though they don't drive any V1 behaviour. Wave 3's CSVW renderer reads them straight off `ResourceReadiness::Ready.schema`-adjacent metadata. Track 5 owns this carry-through.

10. **Open question for V2 (deferred):** the `Source::subscribe` shape for streaming sources, and whether `IngestRegistry::reload` (Wave 4 admin) should accept a `Source` override for ad-hoc data-quality replays. Both are V2 concerns; the trait surface as designed does not preclude them.

---

End of Wave 1 architect note.
