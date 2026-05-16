// SPDX-License-Identifier: Apache-2.0
//! Per-resource ingestion lifecycle, registry, and readiness model.
//!
//! This module owns the flow from configured resources to registered
//! DataFusion tables: source open, format decode, schema validation,
//! Parquet cache write, table registration, refresh, and readiness.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::TableProvider;
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

use crate::config::capabilities::source_capabilities;
use crate::config::{
    Config, DatasetId, MaterializationMode, RefreshConfig, ResourceConfig, ResourceId,
    SchemaConfig, SourceConfig,
};
use crate::connector::{
    ConnectorError, ConnectorMetadata, FileConnector, PostgresConnector, TableConnector,
};
use crate::error::IngestError;
use crate::format::{Format, FormatHints, FormatRegistry};
use crate::ingest::cache::CacheLayout;
use crate::ingest::declared_schema::DeclaredSchema;
use crate::ingest::refresh::{run_refresh_loop, RefreshPolicy};
use crate::ingest::validation::validate;
use crate::source::Source;
use crate::table_provider::register_or_replace_versioned_table;

pub use crate::table_provider::{register_versioned_table, table_name};

pub mod cache;
pub mod declared_schema;
pub mod refresh;
pub mod validation;

/// Default number of sample rows forwarded to validation for the
/// not-null and primary-key uniqueness checks.
const DEFAULT_SAMPLE_ROWS: usize = 1_000;
const DEFAULT_XLSX_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_SOURCE_FILE_BYTES: u64 = 256 * 1024 * 1024;

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
    connector: Arc<dyn TableConnector>,
    materialization: MaterializationMode,
    declared: Arc<DeclaredSchema>,
    primary_key: Option<String>,
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
        let connector = Arc::new(FileConnector::new(
            source,
            format,
            hints,
            DEFAULT_XLSX_MAX_FILE_BYTES,
            DEFAULT_MAX_SOURCE_FILE_BYTES,
        ));
        Self::new_with_connector(
            dataset_id,
            resource_id,
            connector,
            MaterializationMode::Snapshot,
            schema,
            None,
            cache_root,
            df_ctx,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_connector(
        dataset_id: DatasetId,
        resource_id: ResourceId,
        connector: Arc<dyn TableConnector>,
        materialization: MaterializationMode,
        schema: SchemaConfig,
        primary_key: Option<String>,
        cache_root: Arc<Path>,
        df_ctx: Arc<SessionContext>,
    ) -> Self {
        let declared = Arc::new(DeclaredSchema::from(&schema));
        Self {
            dataset_id,
            resource_id,
            connector,
            materialization,
            declared,
            primary_key,
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
            let prior = self.readiness.load_full();
            // Only set Failed if we aren't already Ready (shouldn't happen on initial, but defensive).
            if !matches!(prior.as_ref(), ResourceReadiness::Ready { .. }) {
                self.store_failed(code, prior.as_ref());
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
                self.store_failed(code, prior.as_ref());
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

    fn store_failed(&self, code: &'static str, prior: &ResourceReadiness) {
        let since = match prior {
            ResourceReadiness::Failed { since, .. } => *since,
            _ => OffsetDateTime::now_utc(),
        };
        self.readiness
            .store(Arc::new(ResourceReadiness::Failed { code, since }));
    }

    /// Expose dataset_id for the refresh loop.
    pub(crate) fn dataset_id(&self) -> &DatasetId {
        &self.dataset_id
    }

    /// Expose resource_id for the refresh loop.
    pub(crate) fn resource_id(&self) -> &ResourceId {
        &self.resource_id
    }

    /// Sample connector metadata for mtime-policy polling.
    pub(crate) async fn connector_metadata(&self) -> Result<ConnectorMetadata, ConnectorError> {
        self.connector.metadata().await
    }

    // ── Inner pipeline ────────────────────────────────────────────────────────

    async fn run_pipeline(&self) -> Result<(), IngestError> {
        match self.materialization {
            MaterializationMode::Snapshot => self.run_snapshot_pipeline().await,
            MaterializationMode::Live => self.run_live_registration().await,
        }
    }

    async fn run_snapshot_pipeline(&self) -> Result<(), IngestError> {
        let dataset_id = &self.dataset_id;
        let resource_id = &self.resource_id;

        // Step 1: get a connector snapshot.
        let snapshot = self.connector.snapshot().await.map_err(|e| {
            let code = connector_error_code(&e);
            tracing::error!(
                event = code,
                dataset_id = %dataset_id,
                resource_id = %resource_id,
                error = %e,
            );
            ingest_error_from_connector(e)
        })?;

        // Step 2: materialise all batches and build a sample.
        // Current implementation: full materialisation in memory.
        // Streaming ingest can replace this path later.
        let observed_schema = snapshot.observed_schema;
        let mut all_batches: Vec<RecordBatch> = Vec::new();
        let mut batch_stream = snapshot.batches;
        while let Some(result) = batch_stream.next().await {
            let batch = result.map_err(|e| {
                let code = connector_error_code(&e);
                tracing::error!(
                    event = code,
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    error = %e,
                );
                ingest_error_from_connector(e)
            })?;
            all_batches.push(batch);
        }

        // Build the sample batch for validation (concatenate first N rows).
        let sample = build_sample(&all_batches, DEFAULT_SAMPLE_ROWS, &observed_schema);

        // Step 3: validate schema and build projection plan.
        let projection_plan = validate(
            dataset_id,
            resource_id,
            &self.declared,
            &observed_schema,
            self.primary_key.as_deref(),
            sample.as_ref(),
        )?;

        let output_schema = projection_plan.output_schema();

        // Step 4: project every batch.
        let projected: Result<Vec<RecordBatch>, IngestError> = all_batches
            .iter()
            .map(|b| projection_plan.apply(b))
            .collect();
        let projected = projected?;

        // Step 5: mint ULID for this ingest.
        let ingest_ulid = Ulid::new();

        // Step 6: write to cache atomically.
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

        // Step 7: register (or replace) the DataFusion table.
        let table_name = table_name(dataset_id, resource_id);
        self.register_table(
            &table_name,
            &final_path,
            Arc::clone(&output_schema),
            ingest_ulid,
        )
        .await?;

        // Step 8: rotate readiness and GC stale files.
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

    async fn run_live_registration(&self) -> Result<(), IngestError> {
        let dataset_id = &self.dataset_id;
        let resource_id = &self.resource_id;

        let provider = self
            .connector
            .live_provider()
            .await
            .map_err(|e| {
                let code = connector_error_code(&e);
                tracing::error!(
                    event = code,
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    error = %e,
                );
                ingest_error_from_connector(e)
            })?
            .ok_or_else(|| {
                tracing::error!(
                    event = "ingest.source_unreadable",
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    "connector does not support live materialization",
                );
                IngestError::SourceUnreadable
            })?;

        let observed_schema = provider.schema();
        let projection_plan = validate(
            dataset_id,
            resource_id,
            &self.declared,
            &observed_schema,
            self.primary_key.as_deref(),
            None,
        )?;
        let output_schema = projection_plan.output_schema();

        if output_schema.as_ref() != observed_schema.as_ref() {
            tracing::error!(
                event = "ingest.schema_mismatch",
                dataset_id = %dataset_id,
                resource_id = %resource_id,
                "live connector output must already match declared schema",
            );
            return Err(IngestError::SchemaMismatch);
        }

        let ingest_ulid = Ulid::new();
        let table_name = table_name(dataset_id, resource_id);
        self.register_live_provider(&table_name, provider).await?;

        self.readiness.store(Arc::new(ResourceReadiness::Ready {
            ingest_ulid,
            schema: output_schema,
            registered_at: OffsetDateTime::now_utc(),
        }));

        tracing::info!(
            event = "ingest.complete",
            dataset_id = %dataset_id,
            resource_id = %resource_id,
            ingest_ulid = %ingest_ulid,
            materialization = "live",
        );

        Ok(())
    }

    /// Register the parquet file as a DataFusion table, replacing any
    /// prior provider atomically inside a stable table registration.
    async fn register_table(
        &self,
        table_name: &str,
        parquet_path: &std::path::Path,
        schema: SchemaRef,
        ingest_ulid: Ulid,
    ) -> Result<(), IngestError> {
        use datafusion::datasource::file_format::parquet::ParquetFormat as DFParquetFormat;

        let parquet_path = tokio::fs::canonicalize(parquet_path).await.map_err(|e| {
            tracing::error!(
                event = "ingest.registration_failed",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                path = %parquet_path.display(),
                error = %e,
            );
            IngestError::RegistrationFailed
        })?;
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

        self.register_provider(table_name, Arc::new(table), ingest_ulid)
            .await
    }

    async fn register_provider(
        &self,
        table_name: &str,
        table: Arc<dyn TableProvider>,
        ingest_ulid: Ulid,
    ) -> Result<(), IngestError> {
        register_or_replace_versioned_table(&self.df_ctx, table_name, Some(ingest_ulid), table)
            .await
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

    async fn register_live_provider(
        &self,
        table_name: &str,
        table: Arc<dyn TableProvider>,
    ) -> Result<(), IngestError> {
        register_or_replace_versioned_table(&self.df_ctx, table_name, None, table)
            .await
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
                let source_cfg = resource
                    .effective_source(dataset)
                    .ok_or(IngestError::SourceNotFound)?;
                let materialization = resource.effective_materialization(dataset);
                let capabilities = source_capabilities(source_cfg, materialization);
                tracing::info!(
                    event = "ingest.datasource_capabilities",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    source = source_kind_label(source_cfg),
                    materialization = materialization_label(materialization),
                    filter_pushdown = capabilities.filter_pushdown.as_str(),
                    projection_pushdown = capabilities.projection_pushdown.as_str(),
                    limit_pushdown = capabilities.limit_pushdown.as_str(),
                    strong_validators = capabilities.strong_validators,
                    snapshot_provenance = capabilities.snapshot_provenance,
                    live_query_source = capabilities.live_query_source,
                    mtime_refresh = capabilities.mtime_refresh,
                );
                let declared = Arc::new(DeclaredSchema::from(&resource.schema));
                let connector: Arc<dyn TableConnector> = match source_cfg {
                    SourceConfig::File { .. } => {
                        let source = build_source(source_cfg).map_err(|e| {
                            tracing::error!(
                                event = "ingest.source_not_found",
                                dataset_id = %dataset.id,
                                resource_id = %resource.id,
                                error = %e,
                            );
                            IngestError::SourceNotFound
                        })?;

                        // Derive format name from resource/source config, then file extension.
                        let format_name = resource
                            .format_name()
                            .or_else(|| format_name_from_source(source_cfg))
                            .unwrap_or_else(|| infer_format(source_cfg));
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

                        let hints = hints_from_config(Arc::clone(&declared), resource, source_cfg);
                        Arc::new(FileConnector::new(
                            source,
                            format,
                            hints,
                            config.server.xlsx_max_file_bytes,
                            config.server.max_source_file_bytes,
                        ))
                    }
                    SourceConfig::Postgres {
                        connection_env,
                        table,
                        query,
                        change_token_sql,
                        connect_timeout,
                        query_timeout,
                        live_max_connections,
                    } => Arc::new(PostgresConnector::new(
                        connection_env.clone(),
                        table.clone(),
                        query.clone(),
                        change_token_sql.clone(),
                        Arc::clone(&declared),
                        config.server.max_source_file_bytes,
                        *connect_timeout,
                        *query_timeout,
                        *live_max_connections,
                    )),
                };

                let plan = IngestPlan::new_with_connector(
                    dataset.id.clone(),
                    resource.id.clone(),
                    connector,
                    materialization,
                    resource.schema.clone(),
                    resource.primary_key.clone(),
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
        self.spawn_refresh_tasks_with_policy(|_, _| RefreshPolicy::Manual, readiness_tx)
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
            |ds_id, rs_id| {
                ds_configs
                    .get(ds_id)
                    .and_then(|d| {
                        d.table_configs()
                            .find(|resource| &resource.id == rs_id)
                            .and_then(|resource| resource.effective_refresh(d))
                    })
                    .map(refresh_policy_from_config)
                    .unwrap_or(RefreshPolicy::Manual)
            },
            readiness_tx,
        )
    }

    fn spawn_refresh_tasks_with_policy(
        self: Arc<Self>,
        policy_for_resource: impl Fn(&DatasetId, &ResourceId) -> RefreshPolicy,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
    ) -> (JoinSet<()>, CancellationToken) {
        let mut set: JoinSet<()> = JoinSet::new();
        let shutdown = CancellationToken::new();

        for ((ds_id, rs_id), plan) in &self.plans {
            let plan = Arc::clone(plan);
            let tx = readiness_tx.clone();
            let registry = Arc::clone(&self);
            let shutdown_clone = shutdown.clone();
            let policy = policy_for_resource(ds_id, rs_id);

            set.spawn(async move {
                let publish_registry = Arc::clone(&registry);
                let publish_tx = tx.clone();
                let publish = Arc::new(move || {
                    let snapshot = publish_registry.snapshot();
                    let _ = publish_tx.send(snapshot);
                });
                run_refresh_loop(plan.clone(), policy, shutdown_clone, publish).await;
                // After the loop ends (shutdown), send a final snapshot.
                let snapshot = registry.snapshot();
                let _ = tx.send(snapshot);
            });

            let _ = (ds_id, rs_id); // suppress unused warning
        }

        (set, shutdown)
    }

    /// Trigger a reload of a single resource through the admin endpoint.
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
                ResourceReadiness::Ready {
                    ingest_ulid,
                    registered_at,
                    ..
                } => {
                    snapshot.ready.insert(
                        (ds.clone(), rs.clone()),
                        ReadyResource {
                            ingest_ulid,
                            registered_at,
                        },
                    );
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

/// One row of [`ReadinessSnapshot::ready`]. Carries enough to identify
/// the current ingest (the `ingest_ulid`) and to derive an `as_of`
/// timestamp for downstream consumers such as aggregate VC builders.
#[derive(Clone, Debug)]
pub struct ReadyResource {
    pub ingest_ulid: Ulid,
    /// Wall-clock time at which the underlying DataFusion table was
    /// registered with the session context. The `/ready` and aggregate
    /// handlers treat this as the resource's `as_of`.
    pub registered_at: OffsetDateTime,
}

/// Aggregate readiness across every resource. The `/ready` handler
/// returns 200 iff `failed.is_empty() && not_ready.is_empty()`.
#[derive(Clone, Debug, Default)]
pub struct ReadinessSnapshot {
    pub ready: BTreeMap<(DatasetId, ResourceId), ReadyResource>,
    pub not_ready: BTreeSet<(DatasetId, ResourceId)>,
    pub failed: BTreeMap<(DatasetId, ResourceId), &'static str>,
    pub unresolved_entities: BTreeSet<(DatasetId, String)>,
}

impl ReadinessSnapshot {
    /// True iff every resource is in `Ready` state.
    pub fn fully_ready(&self) -> bool {
        self.not_ready.is_empty() && self.failed.is_empty() && self.unresolved_entities.is_empty()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn source_kind_label(source: &SourceConfig) -> &'static str {
    match source {
        SourceConfig::File { .. } => "file",
        SourceConfig::Postgres { .. } => "postgres",
    }
}

fn materialization_label(materialization: MaterializationMode) -> &'static str {
    match materialization {
        MaterializationMode::Snapshot => "snapshot",
        MaterializationMode::Live => "live",
    }
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

/// Build a byte-oriented `Source` from a `SourceConfig`.
fn build_source(source_cfg: &SourceConfig) -> Result<Arc<dyn Source>, std::io::Error> {
    match source_cfg {
        SourceConfig::File { path, .. } => {
            use crate::source::local_file::LocalFileSource;
            let src = LocalFileSource::new(path)?;
            Ok(Arc::new(src))
        }
        SourceConfig::Postgres { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "postgres sources are table connectors, not byte sources",
        )),
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
        SourceConfig::Postgres { .. } => "parquet",
    }
}

fn format_name_from_source(source_cfg: &SourceConfig) -> Option<&'static str> {
    let format = source_cfg.format()?;
    if format.csv.is_some() {
        Some("csv")
    } else if format.xlsx.is_some() {
        Some("xlsx")
    } else if format.parquet.is_some() {
        Some("parquet")
    } else {
        None
    }
}

/// Build `FormatHints` from resource and dataset source config.
fn hints_from_config(
    declared: Arc<DeclaredSchema>,
    resource_cfg: &ResourceConfig,
    dataset_source: &SourceConfig,
) -> FormatHints {
    let (dataset_header_row, dataset_data_range) = match dataset_source {
        SourceConfig::File {
            header_row,
            data_range,
            ..
        } => (*header_row, data_range.clone()),
        SourceConfig::Postgres { .. } => (None, None),
    };
    FormatHints {
        sheet: resource_cfg.xlsx_sheet(),
        header_row: resource_cfg.xlsx_header_row().or(dataset_header_row),
        data_range: resource_cfg.xlsx_data_range().or(dataset_data_range),
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

fn connector_error_code(e: &ConnectorError) -> &'static str {
    match e {
        ConnectorError::SourceNotFound => "ingest.source_not_found",
        ConnectorError::SourceUnreadable(_) | ConnectorError::LiveUnsupported => {
            "ingest.source_unreadable"
        }
    }
}

fn ingest_error_from_connector(e: ConnectorError) -> IngestError {
    match e {
        ConnectorError::SourceNotFound => IngestError::SourceNotFound,
        ConnectorError::SourceUnreadable(_) | ConnectorError::LiveUnsupported => {
            IngestError::SourceUnreadable
        }
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

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;
    use tokio::sync::Notify;
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::config::{FieldConfig, FieldType};
    use crate::format::{DecodedStream, FormatError, FormatFuture};
    use crate::source::{OpenedSource, SourceDescriptor, SourceFuture, SourceMetadata};

    fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
        serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
    }

    struct EmptySource;

    impl Source for EmptySource {
        fn descriptor(&self) -> SourceDescriptor {
            SourceDescriptor {
                scheme: "test",
                target: "empty".to_string(),
            }
        }

        fn open<'a>(&'a self) -> SourceFuture<'a, OpenedSource> {
            Box::pin(async {
                Ok(OpenedSource {
                    reader: Box::pin(tokio::io::empty()),
                    metadata: SourceMetadata {
                        size_bytes: Some(0),
                        ..SourceMetadata::default()
                    },
                })
            })
        }

        fn metadata<'a>(&'a self) -> SourceFuture<'a, SourceMetadata> {
            Box::pin(async { Ok(SourceMetadata::default()) })
        }
    }

    #[derive(Debug)]
    struct FailingFormat;

    impl Format for FailingFormat {
        fn name(&self) -> &'static str {
            "test"
        }

        fn decode<'a>(
            &'a self,
            _reader: Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
            _hints: FormatHints,
        ) -> FormatFuture<'a, DecodedStream> {
            Box::pin(async { Err(FormatError::Parse("boom".to_string())) })
        }
    }

    fn schema_config() -> SchemaConfig {
        SchemaConfig {
            strict: false,
            fields: vec![FieldConfig {
                name: "id".to_string(),
                r#type: FieldType::Integer,
                nullable: true,
                sensitive: false,
                concept_uri: None,
                codelist: None,
                unit: None,
                language: None,
            }],
        }
    }

    fn test_plan(format: Arc<dyn Format>) -> IngestPlan {
        let tmp = TempDir::new().expect("tempdir");
        IngestPlan::new(
            id("dataset"),
            id("resource"),
            Arc::new(EmptySource),
            format,
            schema_config(),
            Arc::from(tmp.path()),
            Arc::new(SessionContext::new()),
        )
    }

    #[tokio::test]
    async fn repeated_failures_preserve_failed_since_until_success() {
        let plan = test_plan(Arc::new(FailingFormat));

        let first = plan.initial_ingest().await.expect_err("first failure");
        assert!(matches!(first, IngestError::SourceUnreadable));
        let first_since = match plan.readiness() {
            ResourceReadiness::Failed { since, .. } => since,
            other => panic!("expected failed readiness, got {other:?}"),
        };

        tokio::time::sleep(Duration::from_millis(2)).await;
        plan.initial_ingest().await.expect_err("second failure");
        let second_since = match plan.readiness() {
            ResourceReadiness::Failed { since, .. } => since,
            other => panic!("expected failed readiness, got {other:?}"),
        };

        assert_eq!(first_since, second_since);
    }

    #[tokio::test]
    async fn refresh_loop_publishes_readiness_after_runtime_failure() {
        let plan = Arc::new(test_plan(Arc::new(FailingFormat)));
        let notified = Arc::new(Notify::new());
        let publish_count = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();
        let publish = {
            let notified = Arc::clone(&notified);
            let publish_count = Arc::clone(&publish_count);
            Arc::new(move || {
                publish_count.fetch_add(1, Ordering::SeqCst);
                notified.notify_one();
            })
        };

        let task = tokio::spawn(run_refresh_loop(
            plan,
            RefreshPolicy::Interval {
                interval: Duration::from_millis(1),
            },
            shutdown.clone(),
            publish,
        ));

        timeout(Duration::from_secs(1), notified.notified())
            .await
            .expect("refresh loop published readiness");
        shutdown.cancel();
        task.await.expect("refresh loop task joins");

        assert!(publish_count.load(Ordering::SeqCst) >= 1);
    }
}
