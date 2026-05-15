// SPDX-License-Identifier: Apache-2.0
//! Per-resource ingestion lifecycle, registry, and readiness model.
//!
//! Trait shapes and lifecycle are pinned in `decisions/wave-1.md`
//! Section 2.3. Track 6 (cache + register + refresh, sonnet) owns the
//! orchestration logic and the submodules [`cache`], [`refresh`], and
//! the rest of [`validation`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::listing::{
    ListingOptions, ListingTable, ListingTableConfig, ListingTableUrl,
};
use datafusion::execution::context::SessionContext;
use futures::stream;
use futures::StreamExt as _;
use time::OffsetDateTime;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use ulid::Ulid;

use crate::config::{
    Config, DatasetId, RefreshConfig, ResourceConfig, ResourceId, SchemaConfig, SourceConfig,
};
use crate::error::IngestError;
use crate::format::{Format, FormatHints, FormatRegistry};
use crate::ingest::cache::CacheLayout;
use crate::ingest::declared_schema::DeclaredSchema;
use crate::ingest::refresh::{run_refresh_loop, RefreshPolicy};
use crate::ingest::validation::validate;
use crate::source::{Source, SourceError};

pub mod cache;
pub mod declared_schema;
pub mod refresh;
pub mod validation;

/// Default number of sample rows forwarded to validation for the
/// not-null and primary-key uniqueness checks.
const DEFAULT_SAMPLE_ROWS: usize = 1_000;

/// Per-resource ingestion lifecycle. One `IngestPlan` per
/// `(dataset_id, resource_id)`.
///
/// Lifecycle:
/// 1. [`IngestPlan::new`] constructs the plan. No I/O.
/// 2. [`IngestPlan::initial_ingest`] runs once at startup.
/// 3. [`IngestPlan::refresh`] is called by the refresh loop or admin endpoint.
/// 4. [`IngestPlan::readiness`] returns the current state for `/ready`.
pub struct IngestPlan {
    dataset_id: DatasetId,
    resource_id: ResourceId,
    source: Arc<dyn Source>,
    format: Arc<dyn Format>,
    declared: Arc<DeclaredSchema>,
    primary_key: Option<String>,
    hints: FormatHints,
    cache_layout: Arc<CacheLayout>,
    df_ctx: Arc<SessionContext>,
    readiness: Arc<ArcSwap<ResourceReadiness>>,
    /// Serialises concurrent refresh attempts so they don't pile up.
    refresh_lock: Mutex<()>,
}

impl IngestPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dataset_id: DatasetId,
        resource_id: ResourceId,
        source: Arc<dyn Source>,
        format: Arc<dyn Format>,
        schema: SchemaConfig,
        cache_root: Arc<Path>,
        df_ctx: Arc<SessionContext>,
    ) -> Self {
        let declared = Arc::new(DeclaredSchema::from(&schema));
        let hints = FormatHints {
            sheet: None,
            header_row: None,
            data_range: None,
            delimiter: None,
            quote: None,
            declared: Arc::clone(&declared),
        };
        Self {
            dataset_id,
            resource_id,
            source,
            format,
            declared,
            primary_key: None,
            hints,
            cache_layout: Arc::new(CacheLayout::new(cache_root)),
            df_ctx,
            readiness: Arc::new(ArcSwap::from_pointee(ResourceReadiness::NotReady)),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Constructor with full resource-level config (primary key, hints).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_resource_config(
        dataset_id: DatasetId,
        resource_id: ResourceId,
        source: Arc<dyn Source>,
        format: Arc<dyn Format>,
        resource_cfg: &ResourceConfig,
        dataset_source: &SourceConfig,
        cache_root: Arc<Path>,
        df_ctx: Arc<SessionContext>,
    ) -> Self {
        let declared = Arc::new(DeclaredSchema::from(&resource_cfg.schema));
        let hints = hints_from_config(Arc::clone(&declared), resource_cfg, dataset_source);
        Self {
            dataset_id,
            resource_id,
            source,
            format,
            declared,
            primary_key: resource_cfg.primary_key.clone(),
            hints,
            cache_layout: Arc::new(CacheLayout::new(cache_root)),
            df_ctx,
            readiness: Arc::new(ArcSwap::from_pointee(ResourceReadiness::NotReady)),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Run the first ingest. Idempotent across retries.
    pub async fn initial_ingest(&self) -> Result<(), IngestError> {
        let _guard = self.refresh_lock.lock().await;
        let result = self.run_pipeline().await;
        if let Err(ref e) = result {
            let code = ingest_error_code(e);
            let prior = self.readiness.load();
            // Only set Failed if we aren't already Ready (shouldn't happen on initial, but defensive).
            if !matches!(prior.as_ref(), ResourceReadiness::Ready { .. }) {
                self.readiness.store(Arc::new(ResourceReadiness::Failed {
                    code,
                    since: OffsetDateTime::now_utc(),
                }));
            }
        }
        result
    }

    /// Re-run the pipeline. On success, rotates `ingest_ulid` and
    /// atomically swaps the DataFusion table. On failure, leaves the
    /// previous `Ready` state intact so it keeps serving.
    pub async fn refresh(&self) -> Result<(), IngestError> {
        let _guard = self.refresh_lock.lock().await;
        let prior = self.readiness.load_full();
        let result = self.run_pipeline().await;
        if let Err(ref e) = result {
            let code = ingest_error_code(e);
            // Preserve prior Ready state on refresh failure (W1-15).
            if !matches!(prior.as_ref(), ResourceReadiness::Ready { .. }) {
                self.readiness.store(Arc::new(ResourceReadiness::Failed {
                    code,
                    since: OffsetDateTime::now_utc(),
                }));
            }
            // If we were already Ready, leave it unchanged so queries
            // keep serving the last good data.
        }
        result
    }

    /// Current readiness state. Cheap arc-swap load.
    pub fn readiness(&self) -> ResourceReadiness {
        self.readiness.load_full().as_ref().clone()
    }

    /// Stable composite identifier used by the cache path and audit.
    pub fn descriptor(&self) -> (&DatasetId, &ResourceId) {
        (&self.dataset_id, &self.resource_id)
    }

    /// Expose dataset_id for the refresh loop.
    pub(crate) fn dataset_id(&self) -> &DatasetId {
        &self.dataset_id
    }

    /// Expose resource_id for the refresh loop.
    pub(crate) fn resource_id(&self) -> &ResourceId {
        &self.resource_id
    }

    /// Sample source metadata for mtime-policy polling.
    pub(crate) async fn source_metadata(
        &self,
    ) -> Result<crate::source::SourceMetadata, SourceError> {
        self.source.metadata().await
    }

    // ── Inner pipeline ────────────────────────────────────────────────────────

    async fn run_pipeline(&self) -> Result<(), IngestError> {
        let dataset_id = &self.dataset_id;
        let resource_id = &self.resource_id;

        // Step 1: open source.
        let opened = self.source.open().await.map_err(|e| {
            let code = match &e {
                SourceError::NotFound => "ingest.source_not_found",
                _ => "ingest.source_unreadable",
            };
            tracing::error!(
                event = code,
                dataset_id = %dataset_id,
                resource_id = %resource_id,
                error = %e,
            );
            match e {
                SourceError::NotFound => IngestError::SourceNotFound,
                _ => IngestError::SourceUnreadable,
            }
        })?;

        // Step 2: decode.
        let decoded = self
            .format
            .decode(opened.reader, self.hints.clone())
            .await
            .map_err(|e| {
                tracing::error!(
                    event = "ingest.source_unreadable",
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    error = %e,
                );
                IngestError::SourceUnreadable
            })?;

        // Step 3: materialise all batches and build a sample.
        // V1: full materialisation in memory. Wave 5 targets streaming.
        let observed_schema = decoded.observed_schema;
        let mut all_batches: Vec<RecordBatch> = Vec::new();
        let mut batch_stream = decoded.batches;
        while let Some(result) = batch_stream.next().await {
            let batch = result.map_err(|e| {
                tracing::error!(
                    event = "ingest.source_unreadable",
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    error = %e,
                );
                IngestError::SourceUnreadable
            })?;
            all_batches.push(batch);
        }

        // Build the sample batch for validation (concatenate first N rows).
        let sample = build_sample(&all_batches, DEFAULT_SAMPLE_ROWS, &observed_schema);

        // Step 4: validate schema and build projection plan.
        let projection_plan = validate(
            dataset_id,
            resource_id,
            &self.declared,
            &observed_schema,
            self.primary_key.as_deref(),
            sample.as_ref(),
        )?;

        let output_schema = projection_plan.output_schema();

        // Step 5: project every batch.
        let projected: Result<Vec<RecordBatch>, IngestError> = all_batches
            .iter()
            .map(|b| projection_plan.apply(b))
            .collect();
        let projected = projected?;

        // Step 6: mint ULID for this ingest.
        let ingest_ulid = Ulid::new();

        // Step 7: write to cache atomically.
        let batch_stream = stream::iter(projected.into_iter().map(Ok::<RecordBatch, IngestError>));
        let final_path = cache::write_atomic(
            &self.cache_layout,
            dataset_id,
            resource_id,
            ingest_ulid,
            Arc::clone(&output_schema),
            batch_stream,
        )
        .await?;

        // Step 8: register (or replace) the DataFusion table.
        let table_name = table_name(dataset_id, resource_id);
        self.register_table(&table_name, &final_path, Arc::clone(&output_schema))
            .await?;

        // Step 9: rotate readiness and GC stale files.
        self.readiness.store(Arc::new(ResourceReadiness::Ready {
            ingest_ulid,
            schema: output_schema,
            registered_at: OffsetDateTime::now_utc(),
        }));

        cache::gc_resource(&self.cache_layout, dataset_id, resource_id, ingest_ulid).await;

        tracing::info!(
            event = "ingest.complete",
            dataset_id = %dataset_id,
            resource_id = %resource_id,
            ingest_ulid = %ingest_ulid,
            path = %final_path.display(),
        );

        Ok(())
    }

    /// Register the parquet file as a DataFusion table, replacing any
    /// prior registration atomically via deregister + register.
    async fn register_table(
        &self,
        table_name: &str,
        parquet_path: &std::path::Path,
        schema: SchemaRef,
    ) -> Result<(), IngestError> {
        use datafusion::datasource::file_format::parquet::ParquetFormat as DFParquetFormat;

        let url_str = format!("file://{}", parquet_path.display());
        let table_url = ListingTableUrl::parse(&url_str).map_err(|e| {
            tracing::error!(
                event = "ingest.registration_failed",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                error = %e,
            );
            IngestError::RegistrationFailed
        })?;

        let options = ListingOptions::new(Arc::new(DFParquetFormat::default()))
            .with_file_extension(".parquet");

        let config = ListingTableConfig::new(table_url)
            .with_listing_options(options)
            .with_schema(schema);

        let table = ListingTable::try_new(config).map_err(|e| {
            tracing::error!(
                event = "ingest.registration_failed",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                error = %e,
            );
            IngestError::RegistrationFailed
        })?;

        // Deregister any prior version so register_table doesn't error
        // on "table already exists". Outstanding Arc<dyn TableProvider>
        // handles from running queries keep the old provider alive until
        // their streams complete (W1-8 atomicity guarantee).
        if self.df_ctx.table_exist(table_name).map_err(|e| {
            tracing::error!(
                event = "ingest.registration_failed",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                error = %e,
            );
            IngestError::RegistrationFailed
        })? {
            self.df_ctx.deregister_table(table_name).map_err(|e| {
                tracing::error!(
                    event = "ingest.registration_failed",
                    dataset_id = %self.dataset_id,
                    resource_id = %self.resource_id,
                    error = %e,
                );
                IngestError::RegistrationFailed
            })?;
        }

        self.df_ctx
            .register_table(table_name, Arc::new(table))
            .map_err(|e| {
                tracing::error!(
                    event = "ingest.registration_failed",
                    dataset_id = %self.dataset_id,
                    resource_id = %self.resource_id,
                    error = %e,
                );
                IngestError::RegistrationFailed
            })?;

        Ok(())
    }
}

// ── Per-resource readiness state ──────────────────────────────────────────────

/// Per-resource readiness state. Owned by [`IngestPlan`], observed
/// through `AppState`'s readiness watch channel.
#[derive(Clone, Debug)]
pub enum ResourceReadiness {
    /// Not yet attempted, or in progress.
    NotReady,
    /// Last attempt succeeded; the DataFusion table named
    /// `<dataset_id>__<resource_id>` is registered with this ULID.
    Ready {
        ingest_ulid: Ulid,
        schema: SchemaRef,
        registered_at: OffsetDateTime,
    },
    /// Last attempt failed. Carries the stable `ingest.*` code and the
    /// timestamp of the first failure (not the most recent).
    Failed {
        code: &'static str,
        since: OffsetDateTime,
    },
}

// ── IngestRegistry ────────────────────────────────────────────────────────────

/// Top-level registry of every configured resource's [`IngestPlan`].
/// Held in `AppState`. Drives startup, refresh, and reload.
pub struct IngestRegistry {
    plans: BTreeMap<(DatasetId, ResourceId), Arc<IngestPlan>>,
}

impl IngestRegistry {
    pub fn from_config(
        config: &Config,
        formats: Arc<FormatRegistry>,
        cache_root: Arc<Path>,
        df_ctx: Arc<SessionContext>,
    ) -> Result<Self, IngestError> {
        let mut plans: BTreeMap<(DatasetId, ResourceId), Arc<IngestPlan>> = BTreeMap::new();

        for dataset in &config.datasets {
            for resource in dataset.table_configs() {
                let source = build_source(&dataset.source).map_err(|e| {
                    tracing::error!(
                        event = "ingest.source_not_found",
                        dataset_id = %dataset.id,
                        resource_id = %resource.id,
                        error = %e,
                    );
                    IngestError::SourceNotFound
                })?;

                // Derive format name from file extension when not explicit.
                // V1 resources don't have a `format` field; infer from path.
                let format_name = resource
                    .format_name()
                    .unwrap_or_else(|| infer_format(&dataset.source));
                let format = formats.get(format_name).ok_or_else(|| {
                    tracing::error!(
                        event = "ingest.source_unreadable",
                        dataset_id = %dataset.id,
                        resource_id = %resource.id,
                        format = format_name,
                        "unknown format",
                    );
                    IngestError::SourceUnreadable
                })?;

                let plan = IngestPlan::from_resource_config(
                    dataset.id.clone(),
                    resource.id.clone(),
                    source,
                    format,
                    resource,
                    &dataset.source,
                    Arc::clone(&cache_root),
                    Arc::clone(&df_ctx),
                );

                plans.insert((dataset.id.clone(), resource.id.clone()), Arc::new(plan));
            }
        }

        Ok(Self { plans })
    }

    /// Walk every plan, calling `initial_ingest`. Updates the readiness
    /// watch channel after each plan completes. Returns once every plan
    /// is in `Ready` or `Failed` state.
    pub async fn run_initial_ingest(&self, readiness_tx: watch::Sender<ReadinessSnapshot>) {
        let mut set: JoinSet<(DatasetId, ResourceId, Result<(), IngestError>)> = JoinSet::new();

        for ((ds, rs), plan) in &self.plans {
            let plan = Arc::clone(plan);
            let ds = ds.clone();
            let rs = rs.clone();
            set.spawn(async move {
                let result = plan.initial_ingest().await;
                (ds, rs, result)
            });
        }

        while let Some(outcome) = set.join_next().await {
            match outcome {
                Ok((_ds, _rs, _result)) => {
                    // Rebuild snapshot from all current plan states.
                    let snapshot = self.snapshot();
                    // Ignore send error (receiver may have dropped if shutting down).
                    let _ = readiness_tx.send(snapshot);
                }
                Err(join_err) => {
                    tracing::error!(
                        event = "ingest.initial_ingest_panicked",
                        error = %join_err,
                    );
                }
            }
        }

        // Final send to ensure the watch channel is up to date.
        let _ = readiness_tx.send(self.snapshot());
    }

    /// Spawn the per-plan refresh tasks. Returns the join set so the
    /// process can await them on shutdown.
    pub fn spawn_refresh_tasks(
        self: Arc<Self>,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
    ) -> (JoinSet<()>, CancellationToken) {
        self.spawn_refresh_tasks_with_policy(|_| RefreshPolicy::Manual, readiness_tx)
    }

    /// Spawn refresh tasks using the provided config for policy lookup.
    pub fn spawn_refresh_tasks_with_config(
        self: Arc<Self>,
        config: &Config,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
    ) -> (JoinSet<()>, CancellationToken) {
        let ds_configs: BTreeMap<&DatasetId, &crate::config::DatasetConfig> =
            config.datasets.iter().map(|d| (&d.id, d)).collect();
        self.spawn_refresh_tasks_with_policy(
            |ds_id| {
                ds_configs
                    .get(ds_id)
                    .map(|d| refresh_policy_from_config(&d.refresh))
                    .unwrap_or(RefreshPolicy::Manual)
            },
            readiness_tx,
        )
    }

    fn spawn_refresh_tasks_with_policy(
        self: Arc<Self>,
        policy_for_dataset: impl Fn(&DatasetId) -> RefreshPolicy,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
    ) -> (JoinSet<()>, CancellationToken) {
        let mut set: JoinSet<()> = JoinSet::new();
        let shutdown = CancellationToken::new();

        for ((ds_id, rs_id), plan) in &self.plans {
            let plan = Arc::clone(plan);
            let tx = readiness_tx.clone();
            let registry = Arc::clone(&self);
            let shutdown_clone = shutdown.clone();
            let policy = policy_for_dataset(ds_id);

            set.spawn(async move {
                run_refresh_loop(plan.clone(), policy, shutdown_clone).await;
                // After the loop ends (shutdown), send a final snapshot.
                let snapshot = registry.snapshot();
                let _ = tx.send(snapshot);
            });

            let _ = (ds_id, rs_id); // suppress unused warning
        }

        (set, shutdown)
    }

    /// Trigger a reload of a single resource (Wave 4 admin endpoint).
    pub async fn reload(
        &self,
        dataset: &DatasetId,
        resource: &ResourceId,
    ) -> Result<(), IngestError> {
        let key = (dataset.clone(), resource.clone());
        let plan = self.plans.get(&key).ok_or(IngestError::SourceNotFound)?;
        plan.refresh().await
    }

    /// Aggregate readiness snapshot across all plans.
    pub fn snapshot(&self) -> ReadinessSnapshot {
        let mut snapshot = ReadinessSnapshot::default();
        for ((ds, rs), plan) in &self.plans {
            match plan.readiness() {
                ResourceReadiness::Ready { ingest_ulid, .. } => {
                    snapshot.ready.insert((ds.clone(), rs.clone()), ingest_ulid);
                }
                ResourceReadiness::NotReady => {
                    snapshot.not_ready.insert((ds.clone(), rs.clone()));
                }
                ResourceReadiness::Failed { code, .. } => {
                    snapshot.failed.insert((ds.clone(), rs.clone()), code);
                }
            }
        }
        snapshot
    }
}

// ── ReadinessSnapshot ─────────────────────────────────────────────────────────

/// Aggregate readiness across every resource. The `/ready` handler
/// returns 200 iff `failed.is_empty() && not_ready.is_empty()`.
#[derive(Clone, Debug, Default)]
pub struct ReadinessSnapshot {
    pub ready: BTreeMap<(DatasetId, ResourceId), Ulid>,
    pub not_ready: BTreeSet<(DatasetId, ResourceId)>,
    pub failed: BTreeMap<(DatasetId, ResourceId), &'static str>,
}

impl ReadinessSnapshot {
    /// True iff every resource is in `Ready` state.
    pub fn fully_ready(&self) -> bool {
        self.not_ready.is_empty() && self.failed.is_empty()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// DataFusion table name for a resource.
pub fn table_name(dataset: &DatasetId, resource: &ResourceId) -> String {
    format!("{}__{}", dataset.as_str(), resource.as_str())
}

/// Build a sample `RecordBatch` from the first `n` rows across batches.
fn build_sample(batches: &[RecordBatch], n: usize, schema: &SchemaRef) -> Option<RecordBatch> {
    let total: usize = batches.iter().map(|b| b.num_rows()).sum();
    if total == 0 {
        return Some(RecordBatch::new_empty(Arc::clone(schema)));
    }

    // Collect up to n rows from the front.
    let mut remaining = n;
    let mut slices: Vec<RecordBatch> = Vec::new();
    for batch in batches {
        if remaining == 0 {
            break;
        }
        let take = batch.num_rows().min(remaining);
        slices.push(batch.slice(0, take));
        remaining -= take;
    }

    if slices.is_empty() {
        return None;
    }
    if slices.len() == 1 {
        return Some(slices.remove(0));
    }

    // Concatenate slices.
    use datafusion::arrow::compute::concat_batches;
    concat_batches(schema, &slices).ok()
}

/// Build a `Source` from a `SourceConfig`. Only `File` is supported in V1.
fn build_source(source_cfg: &SourceConfig) -> Result<Arc<dyn Source>, std::io::Error> {
    match source_cfg {
        SourceConfig::File { path, .. } => {
            use crate::source::local_file::LocalFileSource;
            let src = LocalFileSource::new(path)?;
            Ok(Arc::new(src))
        }
    }
}

/// Infer format name from file extension.
fn infer_format(source_cfg: &SourceConfig) -> &'static str {
    match source_cfg {
        SourceConfig::File { path, .. } => {
            match path.extension().and_then(|e| e.to_str()) {
                Some("csv") => "csv",
                Some("xlsx") | Some("xls") => "xlsx",
                Some("parquet") => "parquet",
                _ => "csv", // Safe default for unknown extensions.
            }
        }
    }
}

/// Build `FormatHints` from resource and dataset source config.
fn hints_from_config(
    declared: Arc<DeclaredSchema>,
    resource_cfg: &ResourceConfig,
    dataset_source: &SourceConfig,
) -> FormatHints {
    let (header_row, data_range) = match dataset_source {
        SourceConfig::File {
            header_row,
            data_range,
            ..
        } => (*header_row, data_range.clone()),
    };
    FormatHints {
        sheet: resource_cfg.xlsx_sheet(),
        header_row,
        data_range,
        delimiter: resource_cfg.csv_delimiter(),
        quote: resource_cfg.csv_quote(),
        declared,
    }
}

/// Map an `IngestError` to its stable `&'static str` code.
fn ingest_error_code(e: &IngestError) -> &'static str {
    match e {
        IngestError::SourceNotFound => "ingest.source_not_found",
        IngestError::SourceUnreadable => "ingest.source_unreadable",
        IngestError::SchemaMismatch => "ingest.schema_mismatch",
        IngestError::StrictExtraColumn => "ingest.strict_extra_column",
        IngestError::CacheWriteFailed => "ingest.cache_write_failed",
        IngestError::RegistrationFailed => "ingest.registration_failed",
    }
}

/// Convert `RefreshConfig` to `RefreshPolicy`.
fn refresh_policy_from_config(cfg: &RefreshConfig) -> RefreshPolicy {
    match cfg {
        RefreshConfig::Mtime { interval } => RefreshPolicy::Mtime {
            interval: *interval,
        },
        RefreshConfig::Interval { interval } => RefreshPolicy::Interval {
            interval: *interval,
        },
        RefreshConfig::Manual {} => RefreshPolicy::Manual,
    }
}
