// SPDX-License-Identifier: Apache-2.0
//! Versioned DataFusion table providers shared by ingest and query planning.

use std::any::Any;
use std::fmt;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{Result as DataFusionResult, Statistics};
use datafusion::execution::context::SessionContext;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown, TableType};
use datafusion::physical_plan::ExecutionPlan;
use ulid::Ulid;

use crate::config::{DatasetId, ResourceId};

/// DataFusion table name for a private storage table.
pub fn table_name(dataset: &DatasetId, resource: &ResourceId) -> String {
    format!("{}__{}", dataset.as_str(), resource.as_str())
}

#[derive(Clone)]
pub(crate) struct TableSnapshot {
    pub(crate) ingest_ulid: Option<Ulid>,
    pub(crate) provider: Arc<dyn TableProvider>,
}

pub(crate) async fn table_snapshot(
    ctx: &SessionContext,
    table_name: &str,
) -> DataFusionResult<TableSnapshot> {
    let provider = ctx.table_provider(table_name).await?;
    if let Some(swappable) = provider.as_any().downcast_ref::<SwappableTableProvider>() {
        return Ok(swappable.snapshot());
    }
    Ok(TableSnapshot {
        ingest_ulid: None,
        provider,
    })
}

pub fn register_versioned_table(
    ctx: &SessionContext,
    table_name: String,
    ingest_ulid: Ulid,
    provider: Arc<dyn TableProvider>,
) -> DataFusionResult<Option<Arc<dyn TableProvider>>> {
    ctx.register_table(
        table_name,
        Arc::new(SwappableTableProvider::new(Some(ingest_ulid), provider)),
    )
}

pub(crate) async fn register_or_replace_versioned_table(
    ctx: &SessionContext,
    table_name: &str,
    ingest_ulid: Option<Ulid>,
    provider: Arc<dyn TableProvider>,
) -> DataFusionResult<()> {
    if ctx.table_exist(table_name)? {
        let existing = ctx.table_provider(table_name).await?;
        if let Some(swappable) = existing.as_any().downcast_ref::<SwappableTableProvider>() {
            swappable.replace(ingest_ulid, provider);
            return Ok(());
        }
    }

    ctx.register_table(
        table_name.to_string(),
        Arc::new(SwappableTableProvider::new(ingest_ulid, provider)),
    )?;
    Ok(())
}

#[derive(Clone)]
struct VersionedTableProvider {
    ingest_ulid: Option<Ulid>,
    inner: Arc<dyn TableProvider>,
}

pub(crate) struct SwappableTableProvider {
    inner: RwLock<VersionedTableProvider>,
}

impl SwappableTableProvider {
    fn new(ingest_ulid: Option<Ulid>, inner: Arc<dyn TableProvider>) -> Self {
        Self {
            inner: RwLock::new(VersionedTableProvider { ingest_ulid, inner }),
        }
    }

    fn replace(&self, ingest_ulid: Option<Ulid>, inner: Arc<dyn TableProvider>) {
        *self.inner.write().expect("table provider lock poisoned") =
            VersionedTableProvider { ingest_ulid, inner };
    }

    fn snapshot(&self) -> TableSnapshot {
        let inner = self.inner.read().expect("table provider lock poisoned");
        TableSnapshot {
            ingest_ulid: inner.ingest_ulid,
            provider: Arc::clone(&inner.inner),
        }
    }

    fn inner(&self) -> Arc<dyn TableProvider> {
        self.snapshot().provider
    }
}

impl fmt::Debug for SwappableTableProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwappableTableProvider")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TableProvider for SwappableTableProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.inner().schema()
    }

    fn table_type(&self) -> TableType {
        self.inner().table_type()
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        self.inner().scan(state, projection, filters, limit).await
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DataFusionResult<Vec<TableProviderFilterPushDown>> {
        self.inner().supports_filters_pushdown(filters)
    }

    fn statistics(&self) -> Option<Statistics> {
        self.inner().statistics()
    }
}
