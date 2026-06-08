// SPDX-License-Identifier: Apache-2.0
//! Dataset-scoped aggregate query execution over entity-shaped DataFusion plans.

use std::collections::BTreeSet;
use std::sync::Arc;

use datafusion::execution::context::SessionContext;
use datafusion::functions_aggregate::expr_fn::{avg, count, count_distinct, max, min, sum};
use datafusion::prelude::{col, lit, Expr, JoinType};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use serde::Serialize;

use crate::config::{
    AggregateConfig, AggregateDimensionConfig, AggregateFunction, AggregateIndicatorConfig, Config,
    DatasetConfig, RelationshipKind, Sensitivity, Suppression,
};
use crate::entity::{EntityField, EntityModel, EntityRegistry};
use crate::error::{AggregateError, Error, FilterError, SchemaError};
use crate::table_provider::table_snapshot;

use super::{batches_to_json_rows, table_name_str};

const BASE_PK_ALIAS: &str = "__dg_base_pk";
const GROUP_SIZE_ALIAS: &str = "__dg_group_size";
const DEFAULT_MAX_RESULT_ROWS: usize = 10_000;

#[derive(Clone)]
pub struct AggregateQueryEngine {
    ctx: Arc<SessionContext>,
    registry: Arc<EntityRegistry>,
    config: Arc<Config>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateListItem {
    pub aggregate_id: String,
    pub title: Option<String>,
    pub description: String,
    pub metadata_scope: String,
    pub source_entity_metadata_scope: Option<String>,
    pub dimensions: Vec<AggregateDimensionItem>,
    pub indicators: Vec<AggregateIndicatorItem>,
    pub default_group_by: Vec<String>,
    pub temporal_field: Option<String>,
    pub min_cell_size: u32,
    pub collection_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AggregateDimensionItem {
    pub id: String,
    pub label: String,
    pub field: String,
    pub codelist: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AggregateIndicatorItem {
    pub id: String,
    pub label: String,
    pub function: &'static str,
    pub column: String,
    pub unit_measure: String,
    pub unit_mult: Option<i32>,
    pub decimals: Option<u32>,
    pub frequency: Option<String>,
    pub definition_uri: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AggregateQueryRequest {
    pub indicators: Option<Vec<String>>,
    pub group_by: Option<Vec<String>>,
    pub filters: Vec<AggregateFilter>,
    pub max_rows: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateFilter {
    pub field: String,
    pub op: AggregateFilterOp,
    pub value: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateFilterOp {
    Eq,
    In,
    Gte,
    Lte,
    Between,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateResult {
    pub dataset_id: String,
    pub aggregate_id: String,
    pub computed_at: String,
    pub data: Vec<Value>,
    pub schema: AggregateSchema,
    pub disclosure_control: AggregateDisclosure,
    pub group_by: Vec<String>,
    pub indicators: Vec<String>,
    pub source_tables: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateSchema {
    pub dimensions: Vec<AggregateDimensionItem>,
    pub indicators: Vec<AggregateIndicatorItem>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateDisclosure {
    pub method: Vec<String>,
    pub min_cell_size: u32,
    pub suppression: &'static str,
    pub suppressed_rows: Option<u64>,
    pub tracked_query_budget: bool,
    pub query_budget_scope: &'static str,
}

struct AggregatePlan {
    df: datafusion::prelude::DataFrame,
    group_keys: Vec<(String, String)>,
    indicator_columns: Vec<(String, String)>,
    source_tables: BTreeSet<String>,
}

struct ExecutedAggregateRows {
    suppressed_groups: usize,
    rows: Vec<Value>,
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

    pub fn list_aggregates(&self, dataset_id: &str) -> Result<Vec<AggregateListItem>, Error> {
        let dataset = self.dataset_config(dataset_id)?;
        Ok(dataset
            .aggregates
            .iter()
            .map(|aggregate| aggregate_list_item(dataset, aggregate))
            .collect())
    }

    pub fn aggregate_config<'a>(
        &'a self,
        dataset_id: &str,
        aggregate_id: &str,
    ) -> Result<(&'a DatasetConfig, &'a AggregateConfig), Error> {
        let dataset = self.dataset_config(dataset_id)?;
        let aggregate = dataset
            .aggregates
            .iter()
            .find(|aggregate| aggregate.id.as_str() == aggregate_id)
            .ok_or_else(|| Error::from(SchemaError::UnknownAggregate))?;
        Ok((dataset, aggregate))
    }

    pub async fn execute_aggregate(
        &self,
        dataset_id: &str,
        aggregate_id: &str,
        request: AggregateQueryRequest,
    ) -> Result<AggregateResult, Error> {
        let (dataset, aggregate) = self.aggregate_config(dataset_id, aggregate_id)?;
        let source_entity = aggregate
            .source_entity
            .as_deref()
            .ok_or_else(|| Error::from(SchemaError::UnknownAggregate))?;
        let entity = self.entity(dataset_id, source_entity)?;
        let indicators = selected_indicators(aggregate, request.indicators.as_deref())?;
        let group_by = selected_group_by(aggregate, request.group_by.as_deref())?;
        validate_query_limits(&indicators, &group_by, &request.filters)?;
        enforce_required_filters(aggregate, &request.filters)?;

        let plan = AggregatePlan::build(
            dataset_id,
            entity,
            aggregate,
            &indicators,
            &group_by,
            &request.filters,
            self,
        )
        .await?;
        let max_rows = request.max_rows.unwrap_or(DEFAULT_MAX_RESULT_ROWS);
        let source_tables = plan.source_tables.clone();
        let rows = plan.execute(aggregate, &indicators, max_rows).await?;

        let hidden_suppression_count = dataset.sensitivity == Sensitivity::Personal
            && !aggregate.disclosure_control.report_suppressed_rows;
        let suppressed_rows = if hidden_suppression_count {
            None
        } else {
            Some(rows.suppressed_groups as u64)
        };
        let schema = AggregateSchema {
            dimensions: group_by
                .iter()
                .map(|dimension| dimension_item(dimension))
                .collect(),
            indicators: indicators
                .iter()
                .map(|indicator| indicator_item(indicator))
                .collect(),
        };
        let indicator_ids = indicators
            .iter()
            .map(|indicator| indicator.id.clone())
            .collect::<Vec<_>>();
        Ok(AggregateResult {
            dataset_id: dataset_id.to_string(),
            aggregate_id: aggregate_id.to_string(),
            computed_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|_| Error::from(AggregateError::ExecutionFailed))?,
            data: rows.rows,
            schema,
            disclosure_control: AggregateDisclosure {
                method: aggregate.disclosure_control.method.clone(),
                min_cell_size: aggregate.disclosure_control.effective_min_cell_size(),
                suppression: suppression_wire(aggregate.disclosure_control.suppression),
                suppressed_rows,
                tracked_query_budget: false,
                query_budget_scope: "none",
            },
            group_by: group_by
                .iter()
                .map(|dimension| dimension.id.clone())
                .collect(),
            indicators: indicator_ids,
            source_tables: source_tables.into_iter().collect(),
        })
    }

    fn dataset_config<'a>(&'a self, dataset_id: &str) -> Result<&'a DatasetConfig, Error> {
        self.config
            .datasets
            .iter()
            .find(|dataset| dataset.id.as_str() == dataset_id)
            .ok_or(SchemaError::UnknownDataset.into())
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
}

impl AggregatePlan {
    async fn build(
        dataset_id: &str,
        entity: &EntityModel,
        aggregate: &AggregateConfig,
        indicators: &[&AggregateIndicatorConfig],
        group_by: &[&AggregateDimensionConfig],
        filters: &[AggregateFilter],
        engine: &AggregateQueryEngine,
    ) -> Result<Self, Error> {
        let registry = engine.registry.as_ref();
        let ctx = engine.ctx.as_ref();
        let mut base_aliases = BTreeSet::new();
        base_aliases.insert(entity.primary_key.table_column.clone());
        for indicator in indicators {
            let field = entity_field(entity, &indicator.column)?;
            base_aliases.insert(field.table_column.clone());
        }
        for dimension in group_by {
            if !dimension.field.contains('.') {
                let field = entity_field(entity, &dimension.field)?;
                base_aliases.insert(field.table_column.clone());
            }
        }
        for filter in filters {
            let field_name = filter_source_field(aggregate, &filter.field)?;
            if !field_name.contains('.') {
                let field = entity_field(entity, &field_name)?;
                base_aliases.insert(field.table_column.clone());
            }
        }
        let joined_relationships = group_by
            .iter()
            .filter_map(|dimension| dimension.field.split_once('.').map(|(rel, _)| rel))
            .collect::<BTreeSet<_>>();
        for relationship_name in &joined_relationships {
            let relationship = entity
                .relationships
                .get(*relationship_name)
                .ok_or_else(|| Error::from(FilterError::UnknownField))?;
            if relationship.kind != RelationshipKind::BelongsTo {
                return Err(FilterError::NotAllowed.into());
            }
            base_aliases.insert(relationship.foreign_key.clone());
        }

        let base_table = table_name_str(dataset_id, &entity.table_id);
        let mut source_tables = BTreeSet::from([entity.table_id.clone()]);
        let mut base_select = Vec::new();
        for table_column in base_aliases {
            base_select
                .push(col(table_column.as_str()).alias(base_field_alias(entity, &table_column)));
        }
        let mut df = snapshot_table(ctx, dataset_id, &entity.name, &base_table)
            .await?
            .select(base_select)
            .map_err(aggregate_execution_failed)?;

        for filter in filters {
            let field_name = filter_source_field(aggregate, &filter.field)?;
            if field_name.contains('.') {
                return Err(FilterError::NotAllowed.into());
            }
            let field = entity_field(entity, &field_name)?;
            let alias = base_field_alias(entity, &field.table_column);
            df = apply_filter(df, &alias, filter)?;
        }

        let group_keys = group_by
            .iter()
            .map(|dimension| group_key(dataset_id, entity, dimension, registry))
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
            source_tables.insert(target.table_id.clone());
            let related_groups = group_by
                .iter()
                .filter_map(|dimension| dimension.field.split_once('.'))
                .filter(|(prefix, _)| prefix == &relationship.name)
                .map(|(_, related_field)| related_field)
                .collect::<BTreeSet<_>>();
            let target_table = table_name_str(dataset_id, &target.table_id);
            let mut target_select = vec![col(target.primary_key.table_column.as_str())
                .alias(related_pk_alias(&relationship.name))];
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
                    &[base_alias(&relationship.foreign_key).as_str()],
                    &[related_pk_alias(&relationship.name).as_str()],
                    None,
                )
                .map_err(aggregate_execution_failed)?;
        }

        let indicator_columns = indicators
            .iter()
            .map(|indicator| {
                let field = entity_field(entity, &indicator.column)?;
                Ok((
                    indicator.id.clone(),
                    base_field_alias(entity, &field.table_column),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Self {
            df,
            group_keys,
            indicator_columns,
            source_tables,
        })
    }

    async fn execute(
        self,
        aggregate: &AggregateConfig,
        indicators: &[&AggregateIndicatorConfig],
        max_rows: usize,
    ) -> Result<ExecutedAggregateRows, Error> {
        let group_exprs = self
            .group_keys
            .iter()
            .map(|(_, alias)| col(alias.as_str()))
            .collect::<Vec<_>>();
        let mut aggregate_exprs = indicators
            .iter()
            .zip(self.indicator_columns.iter())
            .map(|(indicator, (_, column))| {
                indicator_expr(indicator.function, column)
                    .map(|expr| expr.alias(indicator.id.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        aggregate_exprs.push(count_distinct(col(BASE_PK_ALIAS)).alias(GROUP_SIZE_ALIAS));

        let batches = self
            .df
            .aggregate(group_exprs, aggregate_exprs)
            .map_err(aggregate_execution_failed)?
            .limit(0, Some(max_rows.saturating_add(1)))
            .map_err(aggregate_execution_failed)?
            .collect()
            .await
            .map_err(aggregate_execution_failed)?;
        let rows = batches_to_json_rows(&batches)?;
        if rows.len() > max_rows {
            return Err(FilterError::LimitOutOfRange.into());
        }
        apply_disclosure_control(rows, aggregate, indicators, &self.group_keys)
    }
}

fn enforce_required_filters(
    aggregate: &AggregateConfig,
    filters: &[AggregateFilter],
) -> Result<(), Error> {
    if aggregate.required_filters.is_empty() {
        return Ok(());
    }
    let satisfied = filters.iter().any(|filter| {
        aggregate
            .required_filters
            .iter()
            .any(|required| required == &filter.field)
    });
    if satisfied {
        Ok(())
    } else {
        Err(AggregateError::FilterRequired {
            required: aggregate.required_filters.clone(),
        }
        .into())
    }
}

fn selected_indicators<'a>(
    aggregate: &'a AggregateConfig,
    requested: Option<&[String]>,
) -> Result<Vec<&'a AggregateIndicatorConfig>, Error> {
    let requested = requested
        .filter(|requested| !requested.is_empty())
        .map(|requested| requested.to_vec())
        .unwrap_or_else(|| {
            aggregate
                .indicators
                .iter()
                .map(|indicator| indicator.id.clone())
                .collect()
        });
    requested
        .iter()
        .map(|id| {
            aggregate
                .indicators
                .iter()
                .find(|indicator| indicator.id == *id)
                .ok_or_else(|| Error::from(SchemaError::UnknownAggregate))
        })
        .collect()
}

fn selected_group_by<'a>(
    aggregate: &'a AggregateConfig,
    requested: Option<&[String]>,
) -> Result<Vec<&'a AggregateDimensionConfig>, Error> {
    let requested = requested
        .map(|requested| requested.to_vec())
        .unwrap_or_else(|| aggregate.default_group_by.clone());
    requested
        .iter()
        .map(|id| {
            aggregate
                .dimensions
                .iter()
                .find(|dimension| dimension.id == *id)
                .ok_or_else(|| Error::from(FilterError::UnknownField))
        })
        .collect()
}

fn validate_query_limits(
    indicators: &[&AggregateIndicatorConfig],
    group_by: &[&AggregateDimensionConfig],
    filters: &[AggregateFilter],
) -> Result<(), Error> {
    if indicators.is_empty() || indicators.len() > 20 {
        return Err(FilterError::LimitOutOfRange.into());
    }
    if group_by.len() > 5 {
        return Err(FilterError::LimitOutOfRange.into());
    }
    if filters.len() > 20 {
        return Err(FilterError::TooManyFilters.into());
    }
    Ok(())
}

fn apply_filter(
    df: datafusion::prelude::DataFrame,
    column: &str,
    filter: &AggregateFilter,
) -> Result<datafusion::prelude::DataFrame, Error> {
    let column = col(column);
    let expr = match filter.op {
        AggregateFilterOp::Eq => column.eq(literal_value(&filter.value)?),
        AggregateFilterOp::In => column.in_list(literal_list(&filter.value)?, false),
        AggregateFilterOp::Gte => column.gt_eq(literal_value(&filter.value)?),
        AggregateFilterOp::Lte => column.lt_eq(literal_value(&filter.value)?),
        AggregateFilterOp::Between => {
            let (lower, upper) = literal_range(&filter.value)?;
            column.clone().gt_eq(lower).and(column.lt_eq(upper))
        }
    };
    df.filter(expr).map_err(aggregate_execution_failed)
}

fn filter_source_field(aggregate: &AggregateConfig, field: &str) -> Result<String, Error> {
    let allowed = aggregate
        .allowed_filters
        .iter()
        .find(|allowed| allowed.field == field);
    let Some(allowed) = allowed else {
        return Err(FilterError::NotAllowed.into());
    };
    let _ = allowed;
    Ok(aggregate
        .dimensions
        .iter()
        .find(|dimension| dimension.id == field)
        .map(|dimension| dimension.field.clone())
        .unwrap_or_else(|| field.to_string()))
}

fn apply_disclosure_control(
    rows: Vec<Value>,
    aggregate: &AggregateConfig,
    indicators: &[&AggregateIndicatorConfig],
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
        let suppressed = group_size < aggregate.disclosure_control.effective_min_cell_size() as u64;
        if suppressed {
            suppressed_groups += 1;
            if aggregate.disclosure_control.suppression == Suppression::Omit {
                continue;
            }
            let mut attributes = Map::new();
            for indicator in indicators {
                object.insert(indicator.id.clone(), Value::Null);
                attributes.insert(format!("{}$status", indicator.id), json!("S"));
            }
            object.insert("attributes".to_string(), Value::Object(attributes));
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
    dimension: &AggregateDimensionConfig,
    registry: &EntityRegistry,
) -> Result<(String, String), Error> {
    if let Some((relationship_name, field_name)) = dimension.field.split_once('.') {
        let relationship = entity
            .relationships
            .get(relationship_name)
            .ok_or_else(|| Error::from(FilterError::UnknownField))?;
        if relationship.kind != RelationshipKind::BelongsTo {
            return Err(FilterError::NotAllowed.into());
        }
        let target = registry
            .dataset(dataset_id)
            .ok_or(SchemaError::UnknownDataset)?
            .entity(&relationship.target)
            .ok_or_else(|| Error::from(SchemaError::UnknownResource))?;
        let field = entity_field(target, field_name)?;
        return Ok((
            dimension.id.clone(),
            related_field_alias(relationship_name, &field.name),
        ));
    }
    let field = entity_field(entity, &dimension.field)?;
    Ok((
        dimension.id.clone(),
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

fn indicator_expr(function: AggregateFunction, column: &str) -> Result<Expr, Error> {
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

fn aggregate_list_item(dataset: &DatasetConfig, aggregate: &AggregateConfig) -> AggregateListItem {
    AggregateListItem {
        aggregate_id: aggregate.id.to_string(),
        title: aggregate.title.clone(),
        description: aggregate.description.clone(),
        metadata_scope: aggregate
            .access
            .as_ref()
            .and_then(|access| access.metadata_scope.clone())
            .unwrap_or_else(|| format!("{}:metadata", dataset.id)),
        source_entity_metadata_scope: aggregate
            .source_entity
            .as_deref()
            .and_then(|name| dataset.entities.iter().find(|entity| entity.name == name))
            .map(|entity| entity.access.metadata_scope.clone()),
        dimensions: aggregate.dimensions.iter().map(dimension_item).collect(),
        indicators: aggregate.indicators.iter().map(indicator_item).collect(),
        default_group_by: aggregate.default_group_by.clone(),
        temporal_field: aggregate.temporal_field.clone(),
        min_cell_size: aggregate.disclosure_control.effective_min_cell_size(),
        collection_id: aggregate_edr_collection_id(dataset, aggregate),
    }
}

pub fn aggregate_edr_collection_id(
    dataset: &DatasetConfig,
    aggregate: &AggregateConfig,
) -> Option<String> {
    match aggregate.spatial.as_ref()? {
        crate::config::AggregateSpatialConfig::AdminArea { collection_id, .. } => collection_id
            .clone()
            .or_else(|| Some(format!("{}_{}", dataset.id, aggregate.id))),
    }
}

fn dimension_item(dimension: &AggregateDimensionConfig) -> AggregateDimensionItem {
    AggregateDimensionItem {
        id: dimension.id.clone(),
        label: dimension.label.clone(),
        field: dimension.field.clone(),
        codelist: dimension.codelist.clone(),
    }
}

fn indicator_item(indicator: &AggregateIndicatorConfig) -> AggregateIndicatorItem {
    AggregateIndicatorItem {
        id: indicator.id.clone(),
        label: indicator.label.clone(),
        function: aggregate_function_name(indicator.function),
        column: indicator.column.clone(),
        unit_measure: indicator.unit_measure.clone(),
        unit_mult: indicator.unit_mult,
        decimals: indicator.decimals,
        frequency: indicator.frequency.clone(),
        definition_uri: indicator.definition_uri.clone(),
    }
}

fn suppression_wire(suppression: Suppression) -> &'static str {
    match suppression {
        Suppression::Omit => "omit",
        Suppression::Mask | Suppression::Null => "null",
    }
}

fn literal_value(value: &Value) -> Result<Expr, Error> {
    match value {
        Value::String(value) => Ok(lit(value.as_str())),
        Value::Bool(value) => Ok(lit(*value)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(lit(value))
            } else if let Some(value) = value.as_u64() {
                Ok(lit(value))
            } else if let Some(value) = value.as_f64() {
                Ok(lit(value))
            } else {
                Err(FilterError::InvalidValue.into())
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => Err(FilterError::InvalidValue.into()),
    }
}

fn literal_list(value: &Value) -> Result<Vec<Expr>, Error> {
    let values = match value {
        Value::Array(values) => values,
        _ => return Err(FilterError::InvalidValue.into()),
    };
    if values.is_empty() || values.len() > 100 {
        return Err(FilterError::InvalidValue.into());
    }
    values.iter().map(literal_value).collect()
}

fn literal_range(value: &Value) -> Result<(Expr, Expr), Error> {
    let values = match value {
        Value::Array(values) if values.len() == 2 => values,
        _ => return Err(FilterError::InvalidRange.into()),
    };
    Ok((literal_value(&values[0])?, literal_value(&values[1])?))
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
