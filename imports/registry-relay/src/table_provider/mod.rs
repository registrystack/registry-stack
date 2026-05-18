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

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::arrow::array::{ArrayRef, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;

    fn ingest_ulid(value: &str) -> Ulid {
        Ulid::from_string(value).expect("valid ulid")
    }

    fn mem_table(values: &[&str]) -> Arc<dyn TableProvider> {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(StringArray::from(values.to_vec())) as ArrayRef],
        )
        .expect("record batch");
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("mem table"))
    }

    async fn query_values(ctx: &SessionContext, table_name: &str) -> Vec<String> {
        let batches = ctx
            .sql(&format!("select value from {table_name} order by value"))
            .await
            .expect("sql plans")
            .collect()
            .await
            .expect("sql executes");
        assert_eq!(batches.len(), 1);
        batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("value array")
            .iter()
            .map(|value| value.expect("non-null value").to_string())
            .collect()
    }

    #[tokio::test]
    async fn register_or_replace_versioned_table_queries_replacement_provider() {
        let ctx = SessionContext::new();
        let table = "replacement_query";

        register_or_replace_versioned_table(
            &ctx,
            table,
            Some(ingest_ulid("01J5K8M0000000000000000000")),
            mem_table(&["old-a", "old-b"]),
        )
        .await
        .expect("register old table");
        assert_eq!(query_values(&ctx, table).await, vec!["old-a", "old-b"]);

        register_or_replace_versioned_table(
            &ctx,
            table,
            Some(ingest_ulid("01J5K8M0000000000000000001")),
            mem_table(&["new-a"]),
        )
        .await
        .expect("replace table");

        assert_eq!(query_values(&ctx, table).await, vec!["new-a"]);
    }

    #[tokio::test]
    async fn table_snapshot_reports_current_ingest_ulid_after_replacement() {
        let ctx = SessionContext::new();
        let table = "snapshot_version";
        let previous = ingest_ulid("01J5K8M0000000000000000000");
        let current = ingest_ulid("01J5K8M0000000000000000001");

        register_or_replace_versioned_table(&ctx, table, Some(previous), mem_table(&["previous"]))
            .await
            .expect("register previous table");
        let previous_snapshot = table_snapshot(&ctx, table)
            .await
            .expect("previous snapshot");
        assert_eq!(previous_snapshot.ingest_ulid, Some(previous));

        register_or_replace_versioned_table(&ctx, table, Some(current), mem_table(&["current"]))
            .await
            .expect("replace table");
        let current_snapshot = table_snapshot(&ctx, table).await.expect("current snapshot");

        assert_eq!(current_snapshot.ingest_ulid, Some(current));
        assert_eq!(query_values(&ctx, table).await, vec!["current"]);
    }
}
