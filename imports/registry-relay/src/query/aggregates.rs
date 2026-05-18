// SPDX-License-Identifier: Apache-2.0
//! Configured aggregate query execution over entity-shaped DataFusion plans.

use std::collections::BTreeSet;
use std::sync::Arc;

use datafusion::execution::context::SessionContext;
use datafusion::functions_aggregate::expr_fn::{avg, count, count_distinct, max, min, sum};
use datafusion::prelude::{col, JoinType};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{
    AggregateConfig, AggregateFunction, Config, DatasetConfig, EntityConfig, RelationshipKind,
    Suppression,
};
use crate::entity::{EntityField, EntityModel, EntityRegistry};
use crate::error::{AggregateError, Error, FilterError, SchemaError};
use crate::table_provider::table_snapshot;

use super::{batches_to_json_rows, table_name_str};

const BASE_PK_ALIAS: &str = "__dg_base_pk";
const GROUP_SIZE_ALIAS: &str = "__dg_group_size";

#[derive(Clone)]
pub struct AggregateQueryEngine {
    ctx: Arc<SessionContext>,
    registry: Arc<EntityRegistry>,
    config: Arc<Config>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateListItem {
    pub aggregate_id: String,
    pub description: String,
    pub group_by: Vec<String>,
    pub measures: Vec<AggregateMeasureItem>,
    pub min_group_size: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateMeasureItem {
    pub name: String,
    pub function: &'static str,
    pub column: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateRows {
    pub rows: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateResult {
    pub dataset_id: String,
    pub entity: String,
    pub aggregate_id: String,
    pub computed_at: String,
    pub min_group_size: u32,
    pub suppressed_groups: usize,
    /// Group-by columns declared for this aggregate. Echoed verbatim
    /// on the wire so consumers can validate row shape without a
    /// second roundtrip; also used when building aggregate provenance
    /// claims.
    pub group_by: Vec<String>,
    /// Measure names declared for this aggregate. Same rationale as
    /// `group_by`.
    pub measures: Vec<String>,
    pub rows: Vec<Value>,
}

impl AggregateQueryEngine {
    pub fn new(
        ctx: Arc<SessionContext>,
        registry: Arc<EntityRegistry>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            ctx,
            registry,
            config,
        }
    }

    pub fn list_aggregates(
        &self,
        dataset_id: &str,
        entity_name: &str,
    ) -> Result<Vec<AggregateListItem>, Error> {
        let (_, entity_config) = self.entity_config(dataset_id, entity_name)?;
        Ok(entity_config
            .aggregates
            .iter()
            .map(|aggregate| AggregateListItem {
                aggregate_id: aggregate.id.to_string(),
                description: aggregate.description.clone(),
                group_by: aggregate.group_by.clone(),
                measures: aggregate
                    .measures
                    .iter()
                    .map(|measure| AggregateMeasureItem {
                        name: measure.name.clone(),
                        function: aggregate_function_name(measure.function),
                        column: measure.column.clone(),
                    })
                    .collect(),
                min_group_size: aggregate.disclosure_control.min_group_size,
            })
            .collect())
    }

    pub async fn execute_aggregate(
        &self,
        dataset_id: &str,
        entity_name: &str,
        aggregate_id: &str,
    ) -> Result<AggregateResult, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        let (_, entity_config) = self.entity_config(dataset_id, entity_name)?;
        let aggregate = entity_config
            .aggregates
            .iter()
            .find(|aggregate| aggregate.id.as_str() == aggregate_id)
            .ok_or_else(|| Error::from(SchemaError::UnknownAggregate))?;

        let plan =
            AggregatePlan::build(dataset_id, entity, aggregate, &self.registry, &self.ctx).await?;
        let rows = plan.execute(aggregate).await?;

        Ok(AggregateResult {
            dataset_id: dataset_id.to_string(),
            entity: entity_name.to_string(),
            aggregate_id: aggregate_id.to_string(),
            computed_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|_| Error::from(AggregateError::ExecutionFailed))?,
            min_group_size: aggregate.disclosure_control.min_group_size,
            suppressed_groups: rows.suppressed_groups,
            group_by: aggregate.group_by.clone(),
            measures: aggregate
                .measures
                .iter()
                .map(|measure| measure.name.clone())
                .collect(),
            rows: rows.rows,
        })
    }

    fn entity<'a>(&'a self, dataset_id: &str, entity_name: &str) -> Result<&'a EntityModel, Error> {
        let dataset = self
            .registry
            .dataset(dataset_id)
            .ok_or(SchemaError::UnknownDataset)?;
        dataset
            .entity(entity_name)
            .ok_or_else(|| SchemaError::UnknownResource.into())
    }

    fn entity_config<'a>(
        &'a self,
        dataset_id: &str,
        entity_name: &str,
    ) -> Result<(&'a DatasetConfig, &'a EntityConfig), Error> {
        let dataset = self
            .config
            .datasets
            .iter()
            .find(|dataset| dataset.id.as_str() == dataset_id)
            .ok_or(SchemaError::UnknownDataset)?;
        let entity = dataset
            .entities
            .iter()
            .find(|entity| entity.name == entity_name)
            .ok_or_else(|| Error::from(SchemaError::UnknownResource))?;
        Ok((dataset, entity))
    }
}

struct AggregatePlan {
    df: datafusion::prelude::DataFrame,
    group_keys: Vec<(String, String)>,
    measure_columns: Vec<(String, String)>,
}

struct ExecutedAggregateRows {
    suppressed_groups: usize,
    rows: Vec<Value>,
}

impl AggregatePlan {
    async fn build(
        dataset_id: &str,
        entity: &EntityModel,
        aggregate: &AggregateConfig,
        registry: &EntityRegistry,
        ctx: &SessionContext,
    ) -> Result<Self, Error> {
        let mut base_aliases = BTreeSet::new();
        base_aliases.insert(entity.primary_key.table_column.clone());
        for measure in &aggregate.measures {
            let field = entity_field(entity, &measure.column)?;
            base_aliases.insert(field.table_column.clone());
        }
        for group in &aggregate.group_by {
            if !group.contains('.') {
                let field = entity_field(entity, group)?;
                base_aliases.insert(field.table_column.clone());
            }
        }
        for join in &aggregate.joins {
            let relationship = entity
                .relationships
                .get(&join.relationship)
                .ok_or_else(|| Error::from(FilterError::UnknownField))?;
            if relationship.kind == RelationshipKind::BelongsTo {
                base_aliases.insert(relationship.foreign_key.clone());
            }
        }

        let base_table = table_name_str(dataset_id, &entity.table_id);
        let mut base_select = Vec::new();
        for table_column in base_aliases {
            base_select
                .push(col(table_column.as_str()).alias(base_field_alias(entity, &table_column)));
        }
        let mut df = snapshot_table(ctx, dataset_id, &entity.name, &base_table)
            .await?
            .select(base_select)
            .map_err(aggregate_execution_failed)?;

        let joined_relationships = aggregate
            .joins
            .iter()
            .map(|join| join.relationship.as_str())
            .collect::<BTreeSet<_>>();
        for group in &aggregate.group_by {
            if let Some((relationship, _)) = group.split_once('.') {
                if !joined_relationships.contains(relationship) {
                    return Err(FilterError::NotAllowed.into());
                }
            }
        }
        let group_keys = aggregate
            .group_by
            .iter()
            .map(|field| group_key(dataset_id, entity, field, registry))
            .collect::<Result<Vec<_>, _>>()?;

        for relationship_name in joined_relationships {
            let relationship = entity
                .relationships
                .get(relationship_name)
                .ok_or_else(|| Error::from(FilterError::UnknownField))?;
            let dataset = registry
                .dataset(dataset_id)
                .ok_or(SchemaError::UnknownDataset)?;
            let target = dataset
                .entity(&relationship.target)
                .ok_or_else(|| Error::from(SchemaError::UnknownResource))?;

            let related_groups = aggregate
                .group_by
                .iter()
                .filter_map(|field| field.split_once('.'))
                .filter(|(prefix, _)| prefix == &relationship.name)
                .map(|(_, related_field)| related_field)
                .collect::<BTreeSet<_>>();
            let target_table = table_name_str(dataset_id, &target.table_id);
            let mut target_select = Vec::new();
            let (left_on, right_on) = match relationship.kind {
                RelationshipKind::BelongsTo => {
                    target_select.push(
                        col(target.primary_key.table_column.as_str())
                            .alias(related_pk_alias(&relationship.name)),
                    );
                    (
                        base_alias(&relationship.foreign_key),
                        related_pk_alias(&relationship.name),
                    )
                }
                RelationshipKind::HasMany | RelationshipKind::HasOne => {
                    target_select.push(
                        col(relationship.foreign_key.as_str())
                            .alias(related_fk_alias(&relationship.name)),
                    );
                    (
                        base_alias(&entity.primary_key.table_column),
                        related_fk_alias(&relationship.name),
                    )
                }
            };
            for related_field_name in related_groups {
                let field = entity_field(target, related_field_name)?;
                target_select.push(
                    col(field.table_column.as_str())
                        .alias(related_field_alias(&relationship.name, &field.name)),
                );
            }

            let target_df = snapshot_table(ctx, dataset_id, &target.name, &target_table)
                .await?
                .select(target_select)
                .map_err(aggregate_execution_failed)?;
            df = df
                .join(
                    target_df,
                    JoinType::Inner,
                    &[left_on.as_str()],
                    &[right_on.as_str()],
                    None,
                )
                .map_err(aggregate_execution_failed)?;
        }

        let measure_columns = aggregate
            .measures
            .iter()
            .map(|measure| {
                let field = entity_field(entity, &measure.column)?;
                Ok((
                    measure.name.clone(),
                    base_field_alias(entity, &field.table_column),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Self {
            df,
            group_keys,
            measure_columns,
        })
    }

    async fn execute(self, aggregate: &AggregateConfig) -> Result<ExecutedAggregateRows, Error> {
        let group_exprs = self
            .group_keys
            .iter()
            .map(|(_, alias)| col(alias.as_str()))
            .collect::<Vec<_>>();
        let mut aggregate_exprs = aggregate
            .measures
            .iter()
            .zip(self.measure_columns.iter())
            .map(|measure| {
                let (measure, (_, column)) = measure;
                measure_expr(measure.function, column).map(|expr| expr.alias(measure.name.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        aggregate_exprs.push(count_distinct(col(BASE_PK_ALIAS)).alias(GROUP_SIZE_ALIAS));

        let batches = self
            .df
            .aggregate(group_exprs, aggregate_exprs)
            .map_err(aggregate_execution_failed)?
            .collect()
            .await
            .map_err(aggregate_execution_failed)?;
        let rows = batches_to_json_rows(&batches)?;
        apply_disclosure_control(rows, aggregate, &self.group_keys)
    }
}

fn apply_disclosure_control(
    rows: Vec<Value>,
    aggregate: &AggregateConfig,
    group_keys: &[(String, String)],
) -> Result<ExecutedAggregateRows, Error> {
    let mut suppressed_groups = 0;
    let mut returned = Vec::new();

    for row in rows {
        let Value::Object(mut object) = row else {
            return Err(AggregateError::DisclosureViolation.into());
        };
        let group_size = object
            .remove(GROUP_SIZE_ALIAS)
            .and_then(|value| value.as_u64())
            .ok_or(AggregateError::DisclosureViolation)?;
        let suppressed = group_size < aggregate.disclosure_control.min_group_size as u64;
        if suppressed {
            suppressed_groups += 1;
            if aggregate.disclosure_control.suppression == Suppression::Omit {
                continue;
            }
            for measure in &aggregate.measures {
                object.insert(measure.name.clone(), Value::Null);
            }
        }
        for (public_name, alias) in group_keys {
            if let Some(value) = object.remove(alias) {
                object.insert(public_name.clone(), value);
            }
        }
        returned.push(Value::Object(object));
    }

    Ok(ExecutedAggregateRows {
        suppressed_groups,
        rows: returned,
    })
}

fn group_key(
    dataset_id: &str,
    entity: &EntityModel,
    name: &str,
    registry: &EntityRegistry,
) -> Result<(String, String), Error> {
    if let Some((relationship_name, field_name)) = name.split_once('.') {
        let relationship = entity
            .relationships
            .get(relationship_name)
            .ok_or_else(|| Error::from(FilterError::UnknownField))?;
        let target = registry
            .dataset(dataset_id)
            .ok_or(SchemaError::UnknownDataset)?
            .entity(&relationship.target)
            .ok_or_else(|| Error::from(SchemaError::UnknownResource))?;
        let field = entity_field(target, field_name)?;
        return Ok((
            name.to_string(),
            related_field_alias(relationship_name, &field.name),
        ));
    }
    let field = entity_field(entity, name)?;
    Ok((
        field.name.clone(),
        base_field_alias(entity, &field.table_column),
    ))
}

fn entity_field<'a>(entity: &'a EntityModel, name: &str) -> Result<&'a EntityField, Error> {
    entity
        .fields
        .iter()
        .find(|field| field.name == name)
        .ok_or_else(|| FilterError::UnknownField.into())
}

fn measure_expr(
    function: AggregateFunction,
    column: &str,
) -> Result<datafusion::prelude::Expr, Error> {
    match function {
        AggregateFunction::Count => Ok(count(col(column))),
        AggregateFunction::Sum => Ok(sum(col(column))),
        AggregateFunction::Avg => Ok(avg(col(column))),
        AggregateFunction::Min => Ok(min(col(column))),
        AggregateFunction::Max => Ok(max(col(column))),
        AggregateFunction::Median
        | AggregateFunction::CountDistinct
        | AggregateFunction::Stddev => Err(AggregateError::MeasureUnsupported.into()),
    }
}

fn aggregate_function_name(function: AggregateFunction) -> &'static str {
    match function {
        AggregateFunction::Count => "count",
        AggregateFunction::Sum => "sum",
        AggregateFunction::Avg => "avg",
        AggregateFunction::Min => "min",
        AggregateFunction::Max => "max",
        AggregateFunction::Median => "median",
        AggregateFunction::CountDistinct => "count_distinct",
        AggregateFunction::Stddev => "stddev",
    }
}

fn base_alias(column: &str) -> String {
    format!("__dg_base_{column}")
}

fn base_field_alias(entity: &EntityModel, column: &str) -> String {
    if column == entity.primary_key.table_column {
        BASE_PK_ALIAS.to_string()
    } else {
        base_alias(column)
    }
}

fn related_pk_alias(relationship: &str) -> String {
    format!("__dg_rel_{relationship}_pk")
}

fn related_fk_alias(relationship: &str) -> String {
    format!("__dg_rel_{relationship}_fk")
}

fn related_field_alias(relationship: &str, field: &str) -> String {
    format!("__dg_rel_{relationship}_{field}")
}

async fn snapshot_table(
    ctx: &SessionContext,
    dataset_id: &str,
    entity: &str,
    table: &str,
) -> Result<datafusion::prelude::DataFrame, Error> {
    let snapshot = table_snapshot(ctx, table)
        .await
        .map_err(|err| table_unavailable(dataset_id, entity, table, err))?;
    ctx.read_table(Arc::clone(&snapshot.provider))
        .map_err(aggregate_execution_failed)
}

fn table_unavailable(
    dataset_id: &str,
    entity: &str,
    table: &str,
    err: impl std::fmt::Display,
) -> Error {
    tracing::error!(
        event = "query.aggregate_table_unavailable",
        dataset_id,
        entity,
        table,
        error = %err,
    );
    SchemaError::ResourceUnavailable.into()
}

fn aggregate_execution_failed(err: impl std::fmt::Display) -> Error {
    tracing::error!(
        event = "query.aggregate_execution_failed",
        error = %err,
    );
    AggregateError::ExecutionFailed.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use datafusion::arrow::array::StringArray;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use tempfile::TempDir;
    use ulid::Ulid;

    use crate::config::{self, DatasetId, ResourceId};
    use crate::entity::EntityRegistry;
    use crate::table_provider::{register_or_replace_versioned_table, table_name};

    fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
        serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
    }

    fn mem_table(group: &str) -> Arc<MemTable> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("item_id", DataType::Utf8, false),
            Field::new("group_code", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(StringArray::from(vec!["item-1"])),
                Arc::new(StringArray::from(vec![group])),
            ],
        )
        .expect("record batch");
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("mem table"))
    }

    fn aggregate_config() -> Arc<Config> {
        let tmp = TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("aggregate_snapshot.yaml");
        std::fs::write(
            &config_path,
            r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: fixtures/social_registry.csv
    refresh:
      mode: manual
    tables:
      - id: items_table
        primary_key: item_id
        schema:
          strict: true
          fields:
            - name: item_id
              type: string
              nullable: false
            - name: group_code
              type: string
              nullable: true
    entities:
      - name: item
        table: items_table
        fields:
          - name: id
            from: item_id
          - name: group
            from: group_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
        api:
          default_limit: 100
          max_limit: 1000
        aggregates:
          - id: by_group
            description: Number of items by group
            group_by:
              - group
            measures:
              - name: item_count
                function: count
                column: id
            disclosure_control:
              min_group_size: 1
              suppression: omit

audit:
  sink: stdout
  format: jsonl
"#,
        )
        .expect("write config");
        Arc::new(config::load(&config_path).expect("config loads"))
    }

    #[tokio::test]
    async fn aggregate_plan_uses_captured_table_snapshot_after_provider_swap() {
        let cfg = aggregate_config();
        let registry = EntityRegistry::from_config(&cfg).expect("registry");
        let entity = registry
            .dataset("social_registry")
            .expect("dataset")
            .entity("item")
            .expect("entity");
        let aggregate = cfg.datasets[0].entities[0]
            .aggregates
            .iter()
            .find(|aggregate| aggregate.id.as_str() == "by_group")
            .expect("aggregate");

        let ctx = SessionContext::new();
        let dataset: DatasetId = id("social_registry");
        let resource: ResourceId = id("items_table");
        let table_name = table_name(&dataset, &resource);
        register_or_replace_versioned_table(&ctx, &table_name, Some(Ulid::new()), mem_table("old"))
            .await
            .expect("register old table");

        let plan =
            AggregatePlan::build("social_registry", entity, aggregate, &registry, &ctx).await;
        let plan = plan.expect("aggregate plan");

        register_or_replace_versioned_table(&ctx, &table_name, Some(Ulid::new()), mem_table("new"))
            .await
            .expect("swap table");

        let rows = plan.execute(aggregate).await.expect("execute aggregate");

        assert_eq!(
            rows.rows,
            vec![serde_json::json!({
                "group": "old",
                "item_count": 1
            })]
        );
    }
}
