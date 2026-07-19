// SPDX-License-Identifier: Apache-2.0
//! Per-resource ingestion lifecycle, registry, and readiness model.
//!
//! This module owns the flow from configured resources to registered
//! DataFusion tables: source open, format decode, schema validation,
//! Parquet cache write, table registration, refresh, and readiness.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

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
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{watch, Mutex, MutexGuard};
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
use crate::source_backend::{SnapshotMaterializationCandidate, SnapshotMaterializationCoordinator};
use crate::table_provider::{
    mark_versioned_table_unavailable, publication_write_guard, register_or_replace_versioned_table,
    restore_versioned_table, table_snapshot, TableSnapshot,
};

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
    /// Consecutive refresh or refresh-metadata failures while a last-good
    /// table remains ready. This is separate from readiness so availability
    /// does not hide refresh health.
    consecutive_refresh_failures: AtomicU64,
    materializations: OnceLock<Arc<SnapshotMaterializationCoordinator>>,
    /// Serialises concurrent refresh attempts so they don't pile up.
    refresh_lock: Mutex<()>,
}

struct PreparedIngest {
    table_name: String,
    provider_ingest_ulid: Option<Ulid>,
    readiness_ingest_ulid: Ulid,
    schema: SchemaRef,
    provider: Arc<dyn TableProvider>,
    cache_path: Option<PathBuf>,
    row_count: u64,
    byte_count: u64,
    digest: [u8; 32],
    source_revision: Option<String>,
    source_observed_at_unix_ms: Option<i64>,
}

impl PreparedIngest {
    fn materialization_candidate(&self) -> SnapshotMaterializationCandidate {
        SnapshotMaterializationCandidate {
            generation: self.readiness_ingest_ulid,
            digest: self.digest,
            source_revision: self.source_revision.clone(),
            source_observed_at_unix_ms: self.source_observed_at_unix_ms,
            row_count: self.row_count,
            byte_count: self.byte_count,
            provider: Arc::clone(&self.provider),
        }
    }
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
            consecutive_refresh_failures: AtomicU64::new(0),
            materializations: OnceLock::new(),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Run the first ingest. Idempotent across retries.
    pub async fn initial_ingest(&self) -> Result<(), IngestError> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_unlocked().await
    }

    /// Re-run the pipeline. On success, rotates `ingest_ulid` and
    /// atomically swaps the DataFusion table. On failure, leaves the
    /// previous `Ready` state intact so it keeps serving.
    pub async fn refresh(&self) -> Result<(), IngestError> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_unlocked().await
    }

    async fn refresh_unlocked(&self) -> Result<(), IngestError> {
        let prior = self.readiness.load_full();
        let result = if let Some(coordinator) = self.materializations.get() {
            self.refresh_snapshot_exact(coordinator, prior.as_ref())
                .await
        } else {
            match self.prepare_pipeline().await {
                Ok(prepared) => {
                    let result = {
                        let _publication_guard = publication_write_guard().await;
                        self.commit_prepared(&prepared).await
                    };
                    if result.is_ok() {
                        self.finalize_prepared(&prepared).await;
                    }
                    result
                }
                Err(error) => Err(error),
            }
        };
        if let Err(ref e) = result {
            let code = ingest_error_code(e);
            // Preserve prior Ready state on refresh failure (W1-15).
            if matches!(prior.as_ref(), ResourceReadiness::Ready { .. }) {
                self.record_refresh_failure();
            } else {
                self.store_failed(code, prior.as_ref());
            }
            // If we were already Ready, keep the last-good table and its
            // registration timestamp while surfacing the refresh failure.
        }
        result
    }

    async fn refresh_snapshot_exact(
        &self,
        coordinator: &Arc<SnapshotMaterializationCoordinator>,
        prior: &ResourceReadiness,
    ) -> Result<(), IngestError> {
        let provider_id = table_name(&self.dataset_id, &self.resource_id);

        if matches!(prior, ResourceReadiness::NotReady) {
            if let Some(active) = coordinator
                .active_candidate(&provider_id)
                .await
                .map_err(|_| IngestError::MaterializationFailed)?
            {
                return self.reconcile_snapshot_exact(coordinator, active).await;
            }
        }

        let attempt = coordinator
            .begin(&provider_id, self.connector.descriptor().kind)
            .await
            .map_err(|_| IngestError::MaterializationFailed)?;
        let footprint_limits = coordinator
            .footprint_limits(&provider_id)
            .ok_or(IngestError::MaterializationFailed)?;
        let prepared = match self.prepare_snapshot_pipeline(Some(footprint_limits)).await {
            Ok(prepared) => prepared,
            Err(error) => {
                if coordinator
                    .fail(attempt, ingest_error_code(&error))
                    .await
                    .is_err()
                {
                    tracing::error!(
                        event = "ingest.materialization_failure_audit_failed",
                        dataset_id = %self.dataset_id,
                        resource_id = %self.resource_id,
                    );
                }
                return Err(error);
            }
        };
        let pending = match coordinator
            .publish(attempt, prepared.materialization_candidate())
            .await
        {
            Ok(pending) => pending,
            Err(_) => {
                self.discard_prepared(&prepared).await;
                return Err(IngestError::MaterializationFailed);
            }
        };
        let result = {
            let _publication_guard = publication_write_guard().await;
            self.commit_prepared(&prepared).await
        };
        match result {
            Ok(()) => {
                pending.finish();
                self.finalize_prepared(&prepared).await;
                Ok(())
            }
            Err(error) => {
                self.discard_prepared(&prepared).await;
                Err(error)
            }
        }
    }

    async fn reconcile_snapshot_exact(
        &self,
        coordinator: &Arc<SnapshotMaterializationCoordinator>,
        active: crate::source_backend::ActiveSnapshotCandidate,
    ) -> Result<(), IngestError> {
        let provider_id = table_name(&self.dataset_id, &self.resource_id);
        let path =
            self.cache_layout
                .final_path(&self.dataset_id, &self.resource_id, active.generation);
        let digest = sha256_file(&path).await?;
        if digest != active.digest {
            return Err(IngestError::MaterializationFailed);
        }
        let schema = self.declared.to_arrow_schema();
        let provider = self
            .snapshot_table_provider(&path, Arc::clone(&schema))
            .await?;
        let byte_count = tokio::fs::metadata(&path)
            .await
            .map_err(|_| IngestError::MaterializationFailed)?
            .len();
        let pending = coordinator
            .reconcile(
                &provider_id,
                SnapshotMaterializationCandidate {
                    generation: active.generation,
                    digest,
                    source_revision: active.source_revision,
                    source_observed_at_unix_ms: active.source_observed_at_unix_ms,
                    row_count: 0,
                    byte_count,
                    provider: Arc::clone(&provider),
                },
            )
            .await
            .map_err(|_| IngestError::MaterializationFailed)?;
        let prepared = PreparedIngest {
            table_name: provider_id,
            provider_ingest_ulid: Some(active.generation),
            readiness_ingest_ulid: active.generation,
            schema,
            provider,
            cache_path: Some(path),
            row_count: 0,
            byte_count,
            digest,
            source_revision: None,
            source_observed_at_unix_ms: None,
        };
        self.commit_prepared(&prepared).await?;
        pending.finish();
        self.finalize_prepared(&prepared).await;
        Ok(())
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
        self.consecutive_refresh_failures
            .store(0, Ordering::Relaxed);
        let since = match prior {
            ResourceReadiness::Failed { since, .. } => *since,
            _ => OffsetDateTime::now_utc(),
        };
        self.readiness
            .store(Arc::new(ResourceReadiness::Failed { code, since }));
    }

    fn record_refresh_failure(&self) {
        if matches!(self.readiness(), ResourceReadiness::Ready { .. }) {
            let _ = self.consecutive_refresh_failures.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |count| Some(count.saturating_add(1)),
            );
        }
    }

    pub(crate) fn record_unchanged_metadata_success(&self) {
        if matches!(self.readiness(), ResourceReadiness::Ready { .. }) {
            self.consecutive_refresh_failures
                .store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn loaded_source_revision(&self) -> Option<String> {
        match self.readiness() {
            ResourceReadiness::Ready {
                source_revision, ..
            } => source_revision,
            ResourceReadiness::NotReady | ResourceReadiness::Failed { .. } => None,
        }
    }

    fn refresh_failure_count(&self) -> u64 {
        self.consecutive_refresh_failures.load(Ordering::Relaxed)
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
        let result = if self.materializations.get().is_some() {
            Err(ConnectorError::source_unreadable(
                "snapshot-exact metadata polling requires an audited materialization attempt",
            ))
        } else {
            self.connector.metadata().await
        };
        if result.is_err() {
            self.record_refresh_failure();
        }
        result
    }

    // ── Inner pipeline ────────────────────────────────────────────────────────

    async fn prepare_pipeline(&self) -> Result<PreparedIngest, IngestError> {
        self.prepare_snapshot_pipeline(None).await
    }

    async fn prepare_snapshot_pipeline(
        &self,
        footprint_limits: Option<(u64, u64)>,
    ) -> Result<PreparedIngest, IngestError> {
        let dataset_id = &self.dataset_id;
        let resource_id = &self.resource_id;

        // Step 1: get a connector snapshot.
        let snapshot_result = match footprint_limits {
            Some((max_source_records, max_source_bytes)) => {
                self.connector
                    .snapshot_bounded(max_source_bytes, max_source_records)
                    .await
            }
            None => self.connector.snapshot().await,
        };
        let snapshot = snapshot_result.map_err(|e| {
            let code = connector_error_code(&e);
            if self.materializations.get().is_some() {
                tracing::error!(
                    event = code,
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    "snapshot acquisition failed with redacted diagnostics",
                );
            } else {
                tracing::error!(
                    event = code,
                    dataset_id = %dataset_id,
                    resource_id = %resource_id,
                    error = %e,
                );
            }
            ingest_error_from_connector(e)
        })?;

        // Step 2: materialise all batches and build a sample.
        // Current implementation: full materialisation in memory.
        // Streaming ingest can replace this path later.
        let source_byte_count = snapshot.metadata.size_bytes;
        if footprint_limits.is_some()
            && source_byte_count
                .is_none_or(|bytes| bytes > footprint_limits.expect("checked as present").1)
        {
            return Err(IngestError::MaterializationFailed);
        }
        let observed_schema = snapshot.observed_schema;
        let source_revision = restricted_source_revision(&snapshot.metadata);
        let source_observed_at_unix_ms = snapshot.metadata.mtime.and_then(offset_datetime_unix_ms);
        let mut all_batches: Vec<RecordBatch> = Vec::new();
        let mut source_row_count = 0_u64;
        let mut batch_stream = snapshot.batches;
        while let Some(result) = batch_stream.next().await {
            let batch = result.map_err(|e| {
                let code = connector_error_code(&e);
                if self.materializations.get().is_some() {
                    tracing::error!(
                        event = code,
                        dataset_id = %dataset_id,
                        resource_id = %resource_id,
                        "snapshot decode failed with redacted diagnostics",
                    );
                } else {
                    tracing::error!(
                        event = code,
                        dataset_id = %dataset_id,
                        resource_id = %resource_id,
                        error = %e,
                    );
                }
                ingest_error_from_connector(e)
            })?;
            source_row_count = source_row_count
                .checked_add(batch.num_rows() as u64)
                .ok_or(IngestError::MaterializationFailed)?;
            if footprint_limits
                .is_some_and(|(max_source_records, _)| source_row_count > max_source_records)
            {
                return Err(IngestError::MaterializationFailed);
            }
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
        let row_count = source_row_count;

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

        // Step 7: construct the DataFusion table provider. Registration is
        // delayed until commit so multi-table reloads can publish as a unit.
        let table_name = table_name(dataset_id, resource_id);
        let provider = self
            .snapshot_table_provider(&final_path, Arc::clone(&output_schema))
            .await?;
        let byte_count = match source_byte_count {
            Some(byte_count) => byte_count,
            None => tokio::fs::metadata(&final_path)
                .await
                .map_err(|_| IngestError::CacheWriteFailed)?
                .len(),
        };
        let digest = sha256_file(&final_path).await?;

        Ok(PreparedIngest {
            table_name,
            provider_ingest_ulid: Some(ingest_ulid),
            readiness_ingest_ulid: ingest_ulid,
            schema: output_schema,
            provider,
            cache_path: Some(final_path),
            row_count,
            byte_count,
            digest,
            source_revision,
            source_observed_at_unix_ms,
        })
    }

    /// Build the parquet-backed DataFusion table provider without
    /// registering it. Registration happens in `commit_prepared`.
    async fn snapshot_table_provider(
        &self,
        parquet_path: &std::path::Path,
        schema: SchemaRef,
    ) -> Result<Arc<dyn TableProvider>, IngestError> {
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

        Ok(Arc::new(table))
    }

    async fn commit_prepared(&self, prepared: &PreparedIngest) -> Result<(), IngestError> {
        register_or_replace_versioned_table(
            &self.df_ctx,
            &prepared.table_name,
            prepared.provider_ingest_ulid,
            Arc::clone(&prepared.provider),
        )
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

        self.consecutive_refresh_failures
            .store(0, Ordering::Relaxed);
        self.readiness.store(Arc::new(ResourceReadiness::Ready {
            ingest_ulid: prepared.readiness_ingest_ulid,
            schema: Arc::clone(&prepared.schema),
            registered_at: OffsetDateTime::now_utc(),
            source_revision: prepared.source_revision.clone(),
        }));

        Ok(())
    }

    async fn finalize_prepared(&self, prepared: &PreparedIngest) {
        if prepared.cache_path.is_some() {
            cache::gc_resource_with_retention(
                &self.cache_layout,
                &self.dataset_id,
                &self.resource_id,
                prepared.readiness_ingest_ulid,
                self.materializations
                    .get()
                    .and_then(|coordinator| coordinator.retention_generations(&prepared.table_name))
                    .unwrap_or(2),
            )
            .await;
        }

        if let Some(path) = &prepared.cache_path {
            tracing::info!(
                event = "ingest.complete",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                ingest_ulid = %prepared.readiness_ingest_ulid,
                materialization = materialization_label(self.materialization),
                path = %path.display(),
            );
        } else {
            tracing::info!(
                event = "ingest.complete",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                ingest_ulid = %prepared.readiness_ingest_ulid,
                materialization = materialization_label(self.materialization),
            );
        }
    }

    async fn discard_prepared(&self, prepared: &PreparedIngest) {
        let Some(path) = &prepared.cache_path else {
            return;
        };
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                tracing::debug!(
                    event = "ingest.prepared_cache_discarded",
                    dataset_id = %self.dataset_id,
                    resource_id = %self.resource_id,
                    ingest_ulid = %prepared.readiness_ingest_ulid,
                    path = %path.display(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    event = "ingest.prepared_cache_cleanup_failed",
                    dataset_id = %self.dataset_id,
                    resource_id = %self.resource_id,
                    ingest_ulid = %prepared.readiness_ingest_ulid,
                    path = %path.display(),
                    error = %error,
                );
            }
        }
    }

    async fn current_table_snapshot(
        &self,
        table_name: &str,
    ) -> Result<Option<TableSnapshot>, IngestError> {
        let exists = self.df_ctx.table_exist(table_name).map_err(|e| {
            tracing::error!(
                event = "ingest.registration_failed",
                dataset_id = %self.dataset_id,
                resource_id = %self.resource_id,
                error = %e,
            );
            IngestError::RegistrationFailed
        })?;
        if !exists {
            return Ok(None);
        }

        table_snapshot(&self.df_ctx, table_name)
            .await
            .map(Some)
            .map_err(|e| {
                tracing::error!(
                    event = "ingest.registration_failed",
                    dataset_id = %self.dataset_id,
                    resource_id = %self.resource_id,
                    error = %e,
                );
                IngestError::RegistrationFailed
            })
    }

    fn restore_readiness(&self, readiness: ResourceReadiness) {
        self.readiness.store(Arc::new(readiness));
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
        /// Non-reversible digest of the connector token captured with this
        /// loaded generation. Raw ETags and source timestamps are not retained
        /// in this public, debug-printable state.
        source_revision: Option<String>,
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

#[derive(Debug)]
pub struct RegistryReloadReport {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub resources: Vec<ResourceReloadResult>,
}

#[derive(Debug)]
pub struct ResourceReloadResult {
    pub dataset_id: DatasetId,
    pub resource_id: ResourceId,
    pub status: &'static str,
    pub error_code: Option<&'static str>,
}

struct PreparedReloadResource {
    dataset_id: DatasetId,
    resource_id: ResourceId,
    plan: Arc<IngestPlan>,
    prior_readiness: ResourceReadiness,
    prior_refresh_failures: u64,
    prior_table: Option<TableSnapshot>,
    prepared: PreparedIngest,
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
                let source_cfg = &resource.source;
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
                    mtime_refresh = capabilities.mtime_refresh,
                );
                let declared = Arc::new(DeclaredSchema::from(&resource.schema));
                let connector: Arc<dyn TableConnector> = match source_cfg {
                    SourceConfig::File { .. } => {
                        let source = build_source(source_cfg, config.server.max_source_file_bytes)
                            .map_err(|e| {
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

                        let hints = hints_from_config(Arc::clone(&declared), resource);
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
                    } => Arc::new(PostgresConnector::new(
                        connection_env.clone(),
                        table.clone(),
                        query.clone(),
                        change_token_sql.clone(),
                        Arc::clone(&declared),
                        config.server.max_source_file_bytes,
                        *connect_timeout,
                        *query_timeout,
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

    pub(crate) fn bind_snapshot_materialization(
        &self,
        coordinator: Arc<SnapshotMaterializationCoordinator>,
    ) -> Result<(), IngestError> {
        for provider in coordinator.providers() {
            let plan = self
                .plans
                .values()
                .find(|plan| table_name(&plan.dataset_id, &plan.resource_id) == provider)
                .ok_or(IngestError::MaterializationFailed)?;
            if !coordinator.validates_declared_schema(provider, &plan.declared) {
                return Err(IngestError::MaterializationFailed);
            }
            plan.materializations
                .set(Arc::clone(&coordinator))
                .map_err(|_| IngestError::MaterializationFailed)?;
        }
        Ok(())
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
        self.spawn_refresh_tasks_with_policy(|_, _| RefreshPolicy::Manual, readiness_tx, None)
    }

    /// Spawn refresh tasks using the provided config for policy lookup.
    pub fn spawn_refresh_tasks_with_config(
        self: Arc<Self>,
        config: &Config,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
        audit_sink: Arc<crate::audit::AuditPipeline>,
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
            Some(audit_sink),
        )
    }

    fn spawn_refresh_tasks_with_policy(
        self: Arc<Self>,
        policy_for_resource: impl Fn(&DatasetId, &ResourceId) -> RefreshPolicy,
        readiness_tx: watch::Sender<ReadinessSnapshot>,
        audit_sink: Option<Arc<crate::audit::AuditPipeline>>,
    ) -> (JoinSet<()>, CancellationToken) {
        let mut set: JoinSet<()> = JoinSet::new();
        let shutdown = CancellationToken::new();

        for ((ds_id, rs_id), plan) in &self.plans {
            let plan = Arc::clone(plan);
            let tx = readiness_tx.clone();
            let registry = Arc::clone(&self);
            let shutdown_clone = shutdown.clone();
            let policy = match policy_for_resource(ds_id, rs_id) {
                // SnapshotExact cannot poll even source metadata before its
                // durable materialization attempt. Preserve the operator's
                // interval while performing the bounded refresh acquisition
                // under the audited path.
                RefreshPolicy::Mtime { interval } if plan.materializations.get().is_some() => {
                    RefreshPolicy::Interval { interval }
                }
                policy => policy,
            };
            let audit_sink = audit_sink.clone();

            set.spawn(async move {
                let publish_registry = Arc::clone(&registry);
                let publish_tx = tx.clone();
                let publish = Arc::new(move || {
                    let snapshot = publish_registry.snapshot();
                    let _ = publish_tx.send(snapshot);
                });
                run_refresh_loop(plan.clone(), policy, shutdown_clone, publish, audit_sink).await;
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

    /// Trigger a reload of every configured resource through the admin endpoint.
    pub async fn reload_all(&self) -> RegistryReloadReport {
        if self
            .plans
            .values()
            .any(|plan| plan.materializations.get().is_some())
        {
            return RegistryReloadReport {
                total: self.plans.len(),
                succeeded: 0,
                failed: self.plans.len(),
                resources: self
                    .plans
                    .keys()
                    .map(|(dataset_id, resource_id)| ResourceReloadResult {
                        dataset_id: dataset_id.clone(),
                        resource_id: resource_id.clone(),
                        status: "failed",
                        error_code: Some("ingest.materialization_failed"),
                    })
                    .collect(),
            };
        }
        let _guards = self.lock_all_plans().await;
        let total = self.plans.len();
        let mut prepared = Vec::with_capacity(total);
        let mut resources = BTreeMap::new();
        let mut prepare_failed = false;

        for ((dataset_id, resource_id), plan) in &self.plans {
            let prior_readiness = plan.readiness();
            match plan.prepare_pipeline().await {
                Ok(prepared_ingest) => {
                    prepared.push(PreparedReloadResource {
                        dataset_id: dataset_id.clone(),
                        resource_id: resource_id.clone(),
                        plan: Arc::clone(plan),
                        prior_readiness,
                        prior_refresh_failures: plan.refresh_failure_count(),
                        prior_table: None,
                        prepared: prepared_ingest,
                    });
                }
                Err(error) => {
                    prepare_failed = true;
                    if matches!(prior_readiness, ResourceReadiness::Ready { .. }) {
                        plan.record_refresh_failure();
                    } else {
                        plan.store_failed(ingest_error_code(&error), &prior_readiness);
                    }
                    resources.insert(
                        (dataset_id.clone(), resource_id.clone()),
                        ResourceReloadResult {
                            dataset_id: dataset_id.clone(),
                            resource_id: resource_id.clone(),
                            status: "failed",
                            error_code: Some(ingest_error_code(&error)),
                        },
                    );
                }
            }
        }

        if prepare_failed {
            self.discard_prepared_reload(&prepared).await;
            for resource in prepared {
                resources.insert(
                    (resource.dataset_id.clone(), resource.resource_id.clone()),
                    ResourceReloadResult {
                        dataset_id: resource.dataset_id,
                        resource_id: resource.resource_id,
                        status: "skipped",
                        error_code: None,
                    },
                );
            }
            return atomic_reload_failed_report(total, resources.into_values().collect());
        }

        for resource in &mut prepared {
            match resource
                .plan
                .current_table_snapshot(&resource.prepared.table_name)
                .await
            {
                Ok(prior_table) => {
                    resource.prior_table = prior_table;
                }
                Err(error) => {
                    resource.plan.record_refresh_failure();
                    resources.insert(
                        (resource.dataset_id.clone(), resource.resource_id.clone()),
                        ResourceReloadResult {
                            dataset_id: resource.dataset_id.clone(),
                            resource_id: resource.resource_id.clone(),
                            status: "failed",
                            error_code: Some(ingest_error_code(&error)),
                        },
                    );
                    for resource in &prepared {
                        resources
                            .entry((resource.dataset_id.clone(), resource.resource_id.clone()))
                            .or_insert(ResourceReloadResult {
                                dataset_id: resource.dataset_id.clone(),
                                resource_id: resource.resource_id.clone(),
                                status: "skipped",
                                error_code: None,
                            });
                    }
                    self.discard_prepared_reload(&prepared).await;
                    return atomic_reload_failed_report(total, resources.into_values().collect());
                }
            }
        }

        let publication_guard = publication_write_guard().await;
        for (idx, resource) in prepared.iter().enumerate() {
            if let Err(error) = resource.plan.commit_prepared(&resource.prepared).await {
                self.rollback_committed_reload(&prepared[..idx]).await;
                if matches!(resource.prior_readiness, ResourceReadiness::Ready { .. }) {
                    resource.plan.record_refresh_failure();
                } else {
                    resource
                        .plan
                        .store_failed(ingest_error_code(&error), &resource.prior_readiness);
                }
                resources.insert(
                    (resource.dataset_id.clone(), resource.resource_id.clone()),
                    ResourceReloadResult {
                        dataset_id: resource.dataset_id.clone(),
                        resource_id: resource.resource_id.clone(),
                        status: "failed",
                        error_code: Some(ingest_error_code(&error)),
                    },
                );
                for resource in &prepared {
                    resources
                        .entry((resource.dataset_id.clone(), resource.resource_id.clone()))
                        .or_insert(ResourceReloadResult {
                            dataset_id: resource.dataset_id.clone(),
                            resource_id: resource.resource_id.clone(),
                            status: "skipped",
                            error_code: None,
                        });
                }
                drop(publication_guard);
                self.discard_prepared_reload(&prepared).await;
                return atomic_reload_failed_report(total, resources.into_values().collect());
            }
        }
        drop(publication_guard);

        for resource in &prepared {
            resource.plan.finalize_prepared(&resource.prepared).await;
            resources.insert(
                (resource.dataset_id.clone(), resource.resource_id.clone()),
                ResourceReloadResult {
                    dataset_id: resource.dataset_id.clone(),
                    resource_id: resource.resource_id.clone(),
                    status: "ok",
                    error_code: None,
                },
            );
        }

        RegistryReloadReport {
            total,
            succeeded: total,
            failed: 0,
            resources: resources.into_values().collect(),
        }
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
                            consecutive_refresh_failures: plan.refresh_failure_count(),
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

    async fn lock_all_plans(&self) -> Vec<MutexGuard<'_, ()>> {
        let mut guards = Vec::with_capacity(self.plans.len());
        for plan in self.plans.values() {
            guards.push(plan.refresh_lock.lock().await);
        }
        guards
    }

    async fn rollback_committed_reload(&self, committed: &[PreparedReloadResource]) {
        for resource in committed.iter().rev() {
            match restore_versioned_table(
                &resource.plan.df_ctx,
                &resource.prepared.table_name,
                resource.prior_table.clone(),
            )
            .await
            {
                Ok(()) => {
                    resource
                        .plan
                        .restore_readiness(resource.prior_readiness.clone());
                    resource
                        .plan
                        .consecutive_refresh_failures
                        .store(resource.prior_refresh_failures, Ordering::Relaxed);
                }
                Err(error) => {
                    tracing::error!(
                        event = "ingest.reload_rollback_failed",
                        dataset_id = %resource.dataset_id,
                        resource_id = %resource.resource_id,
                        error = %error,
                    );
                    resource
                        .plan
                        .store_failed("ingest.reload_rollback_failed", &resource.prior_readiness);
                    if let Err(mark_error) = mark_versioned_table_unavailable(
                        &resource.plan.df_ctx,
                        &resource.prepared.table_name,
                        "ingest.reload_rollback_failed",
                    )
                    .await
                    {
                        tracing::error!(
                            event = "ingest.reload_fail_closed_failed",
                            dataset_id = %resource.dataset_id,
                            resource_id = %resource.resource_id,
                            error = %mark_error,
                        );
                    }
                }
            }
        }
    }

    async fn discard_prepared_reload(&self, prepared: &[PreparedReloadResource]) {
        for resource in prepared {
            resource.plan.discard_prepared(&resource.prepared).await;
        }
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
    /// Number of consecutive refresh or metadata-poll failures after this
    /// last-good table was registered.
    pub consecutive_refresh_failures: u64,
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
    }
}

fn atomic_reload_failed_report(
    total: usize,
    resources: Vec<ResourceReloadResult>,
) -> RegistryReloadReport {
    RegistryReloadReport {
        total,
        succeeded: 0,
        failed: total,
        resources,
    }
}

fn restricted_source_revision(metadata: &crate::source::SourceMetadata) -> Option<String> {
    let change_token = metadata
        .etag
        .as_deref()
        .map(str::to_owned)
        .or_else(|| metadata.mtime.map(|mtime| mtime.to_string()));
    restricted_change_token_revision(change_token.as_deref())
}

pub(super) fn restricted_change_token_revision(change_token: Option<&str>) -> Option<String> {
    change_token.map(|value| {
        format!(
            "sha256:{}",
            encode_sha256(Sha256::digest(value.as_bytes()).into())
        )
    })
}

fn offset_datetime_unix_ms(value: OffsetDateTime) -> Option<i64> {
    i64::try_from(value.unix_timestamp_nanos().checked_div(1_000_000)?).ok()
}

async fn sha256_file(path: &Path) -> Result<[u8; 32], IngestError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| IngestError::MaterializationFailed)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|_| IngestError::MaterializationFailed)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

fn encode_sha256(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
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
fn build_source(
    source_cfg: &SourceConfig,
    max_source_file_bytes: u64,
) -> Result<Arc<dyn Source>, std::io::Error> {
    match source_cfg {
        SourceConfig::File { path, .. } => {
            use crate::source::local_file::LocalFileSource;
            let src = LocalFileSource::new_with_content_digest_limit(path, max_source_file_bytes)?;
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

/// Build `FormatHints` from the table source config.
fn hints_from_config(declared: Arc<DeclaredSchema>, resource_cfg: &ResourceConfig) -> FormatHints {
    FormatHints {
        sheet: resource_cfg.xlsx_sheet(),
        header_row: resource_cfg.header_row(),
        data_range: resource_cfg.xlsx_data_range(),
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
        IngestError::MaterializationFailed => "ingest.materialization_failed",
    }
}

fn connector_error_code(e: &ConnectorError) -> &'static str {
    match e {
        ConnectorError::SourceNotFound => "ingest.source_not_found",
        ConnectorError::SourceUnreadable(_) => "ingest.source_unreadable",
    }
}

fn ingest_error_from_connector(e: ConnectorError) -> IngestError {
    match e {
        ConnectorError::SourceNotFound => IngestError::SourceNotFound,
        ConnectorError::SourceUnreadable(_) => IngestError::SourceUnreadable,
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tempfile::TempDir;
    use tokio::sync::Notify;
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::config::{FieldConfig, FieldType};
    use crate::format::csv::CsvFormat;
    use crate::format::{DecodedStream, FormatError, FormatFuture};
    use crate::source::{
        OpenedSource, SourceDescriptor, SourceError, SourceFuture, SourceMetadata,
    };

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

    struct ToggleSource {
        target: String,
        open_count: AtomicUsize,
        fail_open: AtomicBool,
        fail_metadata: AtomicBool,
    }

    impl ToggleSource {
        fn new(target: &str) -> Arc<Self> {
            Arc::new(Self {
                target: target.to_string(),
                open_count: AtomicUsize::new(0),
                fail_open: AtomicBool::new(false),
                fail_metadata: AtomicBool::new(false),
            })
        }
    }

    impl Source for ToggleSource {
        fn descriptor(&self) -> SourceDescriptor {
            SourceDescriptor {
                scheme: "test",
                target: self.target.clone(),
            }
        }

        fn open<'a>(&'a self) -> SourceFuture<'a, OpenedSource> {
            Box::pin(async move {
                self.open_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_open.load(Ordering::SeqCst) {
                    return Err(SourceError::Unreadable(
                        "synthetic open failure".to_string(),
                    ));
                }
                let bytes = b"id\n1\n".to_vec();
                Ok(OpenedSource {
                    reader: Box::pin(std::io::Cursor::new(bytes.clone())),
                    metadata: SourceMetadata {
                        size_bytes: Some(bytes.len() as u64),
                        etag: Some("revision-1".to_string()),
                        ..SourceMetadata::default()
                    },
                })
            })
        }

        fn metadata<'a>(&'a self) -> SourceFuture<'a, SourceMetadata> {
            Box::pin(async move {
                if self.fail_metadata.load(Ordering::SeqCst) {
                    return Err(SourceError::Unreadable(
                        "synthetic metadata failure".to_string(),
                    ));
                }
                Ok(SourceMetadata {
                    size_bytes: Some(5),
                    etag: Some("revision-1".to_string()),
                    ..SourceMetadata::default()
                })
            })
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

    fn csv_schema_config() -> SchemaConfig {
        SchemaConfig {
            strict: false,
            fields: vec![FieldConfig {
                name: "c0".to_string(),
                r#type: FieldType::String,
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

    fn successful_plan(
        dataset: &str,
        resource: &str,
        source: Arc<ToggleSource>,
        cache_root: Arc<Path>,
        df_ctx: Arc<SessionContext>,
    ) -> Arc<IngestPlan> {
        Arc::new(IngestPlan::new(
            id(dataset),
            id(resource),
            source,
            Arc::new(CsvFormat::new()),
            csv_schema_config(),
            cache_root,
            df_ctx,
        ))
    }

    fn readiness_details(plan: &IngestPlan) -> (Ulid, OffsetDateTime) {
        match plan.readiness() {
            ResourceReadiness::Ready {
                ingest_ulid,
                registered_at,
                ..
            } => (ingest_ulid, registered_at),
            other => panic!("expected ready resource, got {other:?}"),
        }
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
    async fn failed_manual_refresh_preserves_last_good_readiness_and_recovers() {
        let tmp = TempDir::new().expect("tempdir");
        let source = ToggleSource::new("resource");
        let plan = successful_plan(
            "dataset",
            "resource",
            Arc::clone(&source),
            Arc::from(tmp.path()),
            Arc::new(SessionContext::new()),
        );
        plan.initial_ingest()
            .await
            .expect("initial ingest succeeds");
        let (initial_ulid, initial_registered_at) = readiness_details(&plan);

        source.fail_open.store(true, Ordering::SeqCst);
        plan.refresh().await.expect_err("refresh fails");
        let (failed_refresh_ulid, failed_refresh_registered_at) = readiness_details(&plan);
        assert_eq!(failed_refresh_ulid, initial_ulid);
        assert_eq!(failed_refresh_registered_at, initial_registered_at);
        assert_eq!(plan.refresh_failure_count(), 1);

        let registry = IngestRegistry {
            plans: BTreeMap::from([((id("dataset"), id("resource")), Arc::clone(&plan))]),
        };
        let snapshot = registry.snapshot();
        assert!(snapshot.fully_ready(), "last-good data remains ready");
        assert_eq!(
            snapshot
                .ready
                .get(&(id("dataset"), id("resource")))
                .expect("ready resource")
                .consecutive_refresh_failures,
            1
        );

        source.fail_open.store(false, Ordering::SeqCst);
        plan.refresh().await.expect("refresh recovers");
        let (recovered_ulid, _) = readiness_details(&plan);
        assert_ne!(recovered_ulid, initial_ulid);
        assert_eq!(plan.refresh_failure_count(), 0);
    }

    #[tokio::test]
    async fn mtime_first_poll_uses_loaded_token_and_recovers_health_without_reingest() {
        let tmp = TempDir::new().expect("tempdir");
        let source = ToggleSource::new("resource");
        let plan = successful_plan(
            "dataset",
            "resource",
            Arc::clone(&source),
            Arc::from(tmp.path()),
            Arc::new(SessionContext::new()),
        );
        plan.initial_ingest()
            .await
            .expect("initial ingest succeeds");
        let (initial_ulid, initial_registered_at) = readiness_details(&plan);
        let readiness_debug = format!("{:?}", plan.readiness());
        assert!(
            !readiness_debug.contains("revision-1"),
            "raw connector tokens must not enter public readiness state"
        );
        assert!(
            plan.loaded_source_revision()
                .is_some_and(|revision| revision.starts_with("sha256:")),
            "the loaded generation retains only a non-reversible token digest"
        );

        source.fail_metadata.store(true, Ordering::SeqCst);
        plan.connector_metadata()
            .await
            .expect_err("metadata poll fails");
        assert_eq!(plan.refresh_failure_count(), 1);

        source.fail_metadata.store(false, Ordering::SeqCst);
        let notified = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let publish = {
            let notified = Arc::clone(&notified);
            Arc::new(move || notified.notify_one())
        };
        let task = tokio::spawn(run_refresh_loop(
            Arc::clone(&plan),
            RefreshPolicy::Mtime {
                interval: Duration::from_millis(1),
            },
            shutdown.clone(),
            publish,
            None,
        ));
        timeout(Duration::from_secs(1), notified.notified())
            .await
            .expect("unchanged first poll publishes readiness");
        shutdown.cancel();
        task.await.expect("mtime refresh loop joins");

        assert_eq!(plan.refresh_failure_count(), 0);
        assert_eq!(
            source.open_count.load(Ordering::SeqCst),
            1,
            "the unchanged first poll must reuse the startup-loaded generation"
        );
        assert_eq!(
            readiness_details(&plan),
            (initial_ulid, initial_registered_at),
            "an unchanged metadata poll must not advance the last data-load timestamp"
        );
    }

    #[tokio::test]
    async fn refresh_failure_count_saturates() {
        let tmp = TempDir::new().expect("tempdir");
        let source = ToggleSource::new("resource");
        let plan = successful_plan(
            "dataset",
            "resource",
            source,
            Arc::from(tmp.path()),
            Arc::new(SessionContext::new()),
        );
        plan.initial_ingest()
            .await
            .expect("initial ingest succeeds");
        plan.consecutive_refresh_failures
            .store(u64::MAX, Ordering::Relaxed);
        plan.record_refresh_failure();
        assert_eq!(plan.refresh_failure_count(), u64::MAX);
    }

    #[tokio::test]
    async fn atomic_reload_marks_only_the_resource_that_actually_failed() {
        let tmp = TempDir::new().expect("tempdir");
        let df_ctx = Arc::new(SessionContext::new());
        let healthy_source = ToggleSource::new("healthy");
        let failing_source = ToggleSource::new("failing");
        let healthy = successful_plan(
            "dataset",
            "a_healthy",
            Arc::clone(&healthy_source),
            Arc::from(tmp.path()),
            Arc::clone(&df_ctx),
        );
        let failing = successful_plan(
            "dataset",
            "b_failing",
            Arc::clone(&failing_source),
            Arc::from(tmp.path()),
            df_ctx,
        );
        healthy
            .initial_ingest()
            .await
            .expect("healthy initial ingest");
        failing
            .initial_ingest()
            .await
            .expect("failing initial ingest");
        let registry = IngestRegistry {
            plans: BTreeMap::from([
                ((id("dataset"), id("a_healthy")), Arc::clone(&healthy)),
                ((id("dataset"), id("b_failing")), Arc::clone(&failing)),
            ]),
        };

        failing_source.fail_open.store(true, Ordering::SeqCst);
        let report = registry.reload_all().await;
        assert_eq!(report.succeeded, 0);
        assert_eq!(
            report.failed, 2,
            "atomic reload reports the whole batch failed"
        );
        assert_eq!(
            healthy.refresh_failure_count(),
            0,
            "prepared peer was skipped"
        );
        assert_eq!(
            failing.refresh_failure_count(),
            1,
            "actual failure is marked"
        );
        assert!(
            registry.snapshot().fully_ready(),
            "both last-good tables remain ready"
        );
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
            None,
        ));

        timeout(Duration::from_secs(1), notified.notified())
            .await
            .expect("refresh loop published readiness");
        shutdown.cancel();
        task.await.expect("refresh loop task joins");

        assert!(publish_count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn refresh_loop_writes_audit_event_after_runtime_failure() {
        let plan = Arc::new(test_plan(Arc::new(FailingFormat)));
        let notified = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let audit_sink = crate::audit::InMemorySink::new();
        let audit_pipeline = crate::audit::AuditPipeline::from_sink(audit_sink.clone());
        let publish = {
            let notified = Arc::clone(&notified);
            Arc::new(move || {
                notified.notify_one();
            })
        };

        let task = tokio::spawn(run_refresh_loop(
            Arc::clone(&plan),
            RefreshPolicy::Interval {
                interval: Duration::from_millis(1),
            },
            shutdown.clone(),
            publish,
            Some(audit_pipeline),
        ));

        timeout(Duration::from_secs(1), notified.notified())
            .await
            .expect("refresh loop published readiness");
        shutdown.cancel();
        task.await.expect("refresh loop task joins");

        let records = audit_sink.snapshot();
        assert!(
            records.iter().any(|line| {
                let envelope: serde_json::Value =
                    serde_json::from_str(line.trim_end()).expect("audit envelope JSON");
                let record = &envelope["record"];
                record["path"] == "/__events/ingest.refresh_failed"
                    && record["method"] == "BACKGROUND"
                    && record["error_code"] == "ingest.refresh_failed"
                    && record["dataset_id"] == "dataset"
                    && record["table_id_hash"].is_null()
            }),
            "missing refresh failure audit event: {records:?}"
        );
    }
}
