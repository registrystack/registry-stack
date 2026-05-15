// SPDX-License-Identifier: Apache-2.0
//! Entity query API over Wave 1 DataFusion table registrations.

use std::sync::Arc;

use datafusion::arrow::json::writer::{JsonArray, WriterBuilder};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::execution::context::SessionContext;
use datafusion::prelude::{col, lit};
use serde_json::Value;

use crate::config::{FilterOp, RelationshipKind};
use crate::entity::{EntityField, EntityModel, EntityRegistry};
use crate::error::{Error, FilterError, InternalError, SchemaError};
use crate::ingest::table_name;

pub mod aggregates;
pub use aggregates::{AggregateListItem, AggregateQueryEngine, AggregateResult, AggregateRows};

/// Executes public entity reads against private DataFusion tables.
#[derive(Clone)]
pub struct EntityQueryEngine {
    ctx: Arc<SessionContext>,
    registry: Arc<EntityRegistry>,
}

/// Collection read options.
#[derive(Clone, Debug, Default)]
pub struct EntityCollectionQuery {
    pub fields: Option<Vec<String>>,
    pub limit: Option<usize>,
    pub filters: Vec<EntityFilter>,
    pub expansions: Vec<String>,
}

/// Single base-field filter.
#[derive(Clone, Debug)]
pub struct EntityFilter {
    pub field: String,
    pub op: EntityFilterOp,
    pub value: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntityFilterOp {
    Eq,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntityRows {
    pub rows: Vec<Value>,
}

impl EntityQueryEngine {
    pub fn new(ctx: Arc<SessionContext>, registry: Arc<EntityRegistry>) -> Self {
        Self { ctx, registry }
    }

    pub async fn read_collection(
        &self,
        dataset_id: &str,
        entity_name: &str,
        query: EntityCollectionQuery,
    ) -> Result<EntityRows, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        validate_allowed_expansions(entity, &query.expansions)?;
        let requested_fields = query.fields.clone();
        let mut projected_fields = projected_fields(entity, requested_fields.as_deref())?;
        let strip_fields =
            add_expansion_source_fields(entity, &query.expansions, &mut projected_fields)?;
        let limit = match query.limit {
            Some(limit) if limit == 0 || limit > entity.api.max_limit as usize => {
                return Err(FilterError::LimitOutOfRange.into());
            }
            Some(limit) => Some(limit),
            None => Some(entity.api.default_limit as usize),
        };
        validate_allowed_filters(entity, &query.filters)?;
        let mut rows = self
            .execute_entity_query(dataset_id, entity, &projected_fields, query.filters, limit)
            .await?;
        self.expand_rows(dataset_id, entity, &mut rows, &query.expansions)
            .await?;
        strip_projection_fields(&mut rows, &strip_fields);
        Ok(EntityRows { rows })
    }

    pub async fn read_record(
        &self,
        dataset_id: &str,
        entity_name: &str,
        primary_key: Value,
        fields: Option<Vec<String>>,
        expansions: Vec<String>,
    ) -> Result<Option<Value>, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        validate_allowed_expansions(entity, &expansions)?;
        let mut projected_fields = projected_fields(entity, fields.as_deref())?;
        let strip_fields = add_expansion_source_fields(entity, &expansions, &mut projected_fields)?;
        let filter = EntityFilter::eq(entity.primary_key.name.clone(), primary_key);
        let mut rows = self
            .execute_entity_query(dataset_id, entity, &projected_fields, vec![filter], Some(1))
            .await?;
        self.expand_rows(dataset_id, entity, &mut rows, &expansions)
            .await?;
        strip_projection_fields(&mut rows, &strip_fields);
        Ok(rows.into_iter().next())
    }

    pub async fn read_relationship(
        &self,
        dataset_id: &str,
        entity_name: &str,
        primary_key: Value,
        relationship_name: &str,
    ) -> Result<Value, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        let Some(relationship) = entity.relationships.get(relationship_name) else {
            return Err(SchemaError::UnknownResource.into());
        };
        let mut rows = self
            .execute_entity_query(
                dataset_id,
                entity,
                &entity.fields.iter().collect::<Vec<_>>(),
                vec![EntityFilter::eq(
                    entity.primary_key.name.clone(),
                    primary_key,
                )],
                Some(1),
            )
            .await?;
        let Some(row) = rows.pop() else {
            return Err(SchemaError::UnknownResource.into());
        };
        self.expand_relationship(dataset_id, entity, &row, relationship_name, relationship)
            .await
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

    async fn execute_entity_query(
        &self,
        dataset_id: &str,
        entity: &EntityModel,
        projected_fields: &[&EntityField],
        filters: Vec<EntityFilter>,
        limit: Option<usize>,
    ) -> Result<Vec<Value>, Error> {
        if matches!(limit, Some(0)) {
            return Err(FilterError::LimitOutOfRange.into());
        }

        let table = table_name_str(dataset_id, &entity.table_id);
        let mut df = self.ctx.table(table.as_str()).await.map_err(|err| {
            tracing::error!(
                event = "query.entity_table_unavailable",
                dataset_id,
                entity = %entity.name,
                table = %table,
                error = %err,
            );
            Error::from(SchemaError::ResourceUnavailable)
        })?;

        for filter in filters {
            let field = entity_field(entity, &filter.field)?;
            let value = literal_value(&filter.value)?;
            match filter.op {
                EntityFilterOp::Eq => {
                    df = df
                        .filter(col(field.table_column.as_str()).eq(value))
                        .map_err(execution_failed)?;
                }
            }
        }

        let exprs = projected_fields
            .iter()
            .map(|field| col(field.table_column.as_str()).alias(field.name.clone()));
        df = df.select(exprs).map_err(execution_failed)?;

        if let Some(limit) = limit {
            df = df.limit(0, Some(limit)).map_err(execution_failed)?;
        }

        let batches = df.collect().await.map_err(execution_failed)?;
        batches_to_json_rows(&batches)
    }

    async fn expand_rows(
        &self,
        dataset_id: &str,
        entity: &EntityModel,
        rows: &mut [Value],
        expansions: &[String],
    ) -> Result<(), Error> {
        for expansion in expansions {
            let relationship = entity
                .relationships
                .get(expansion)
                .ok_or(FilterError::NotAllowed)?;
            for row in rows.iter_mut() {
                let expanded = self
                    .expand_relationship(dataset_id, entity, row, expansion, relationship)
                    .await?;
                if let Value::Object(object) = row {
                    object.insert(expansion.clone(), expanded);
                }
            }
        }
        Ok(())
    }

    async fn expand_relationship(
        &self,
        dataset_id: &str,
        entity: &EntityModel,
        row: &Value,
        relationship_name: &str,
        relationship: &crate::config::EntityRelationshipConfig,
    ) -> Result<Value, Error> {
        let target = self.entity(dataset_id, &relationship.target)?;
        let (filter_field, filter_value, limit) = match relationship.kind {
            RelationshipKind::BelongsTo => {
                let source_fk = entity_field_by_table_column(entity, &relationship.foreign_key)?;
                let Some(value) = row.get(&source_fk.name) else {
                    return Err(SchemaError::ResourceUnavailable.into());
                };
                (target.primary_key.name.clone(), value.clone(), Some(1))
            }
            RelationshipKind::HasOne => {
                let Some(value) = row.get(&entity.primary_key.name) else {
                    return Err(SchemaError::ResourceUnavailable.into());
                };
                let target_fk = entity_field_by_table_column(target, &relationship.foreign_key)?;
                (target_fk.name.clone(), value.clone(), Some(1))
            }
            RelationshipKind::HasMany => {
                let Some(value) = row.get(&entity.primary_key.name) else {
                    return Err(SchemaError::ResourceUnavailable.into());
                };
                let target_fk = entity_field_by_table_column(target, &relationship.foreign_key)?;
                (
                    target_fk.name.clone(),
                    value.clone(),
                    Some(target.api.default_limit as usize),
                )
            }
        };
        let target_fields = target.fields.iter().collect::<Vec<_>>();
        let mut rows = self
            .execute_entity_query(
                dataset_id,
                target,
                &target_fields,
                vec![EntityFilter::eq(filter_field, filter_value)],
                limit,
            )
            .await?;
        match relationship.kind {
            RelationshipKind::HasMany => Ok(Value::Array(rows)),
            RelationshipKind::BelongsTo | RelationshipKind::HasOne => {
                Ok(rows.pop().unwrap_or(Value::Null))
            }
        }
        .map_err(|error| {
            tracing::error!(
                event = "query.entity_relationship_expansion_failed",
                dataset_id,
                entity = %entity.name,
                relationship = relationship_name,
                target = %target.name,
                error = %error,
            );
            error
        })
    }
}

impl EntityCollectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_fields(mut self, fields: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.fields = Some(fields.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_filter(mut self, filter: EntityFilter) -> Self {
        self.filters.push(filter);
        self
    }

    pub fn with_expansions(
        mut self,
        expansions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.expansions = expansions.into_iter().map(Into::into).collect();
        self
    }
}

impl EntityFilter {
    pub fn eq(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self {
            field: field.into(),
            op: EntityFilterOp::Eq,
            value: value.into(),
        }
    }
}

fn projected_fields<'a>(
    entity: &'a EntityModel,
    fields: Option<&[String]>,
) -> Result<Vec<&'a EntityField>, Error> {
    match fields {
        Some(fields) if !fields.is_empty() => fields
            .iter()
            .map(|name| entity_field(entity, name))
            .collect(),
        _ => Ok(entity.fields.iter().collect()),
    }
}

fn add_expansion_source_fields<'a>(
    entity: &'a EntityModel,
    expansions: &[String],
    projected_fields: &mut Vec<&'a EntityField>,
) -> Result<Vec<String>, Error> {
    let mut strip_fields = Vec::new();
    for expansion in expansions {
        let relationship = entity
            .relationships
            .get(expansion)
            .ok_or(FilterError::NotAllowed)?;
        let source_field = match relationship.kind {
            RelationshipKind::BelongsTo => {
                entity_field_by_table_column(entity, &relationship.foreign_key)?
            }
            RelationshipKind::HasMany | RelationshipKind::HasOne => &entity.primary_key,
        };
        if !projected_fields
            .iter()
            .any(|field| field.name == source_field.name)
        {
            projected_fields.push(source_field);
            strip_fields.push(source_field.name.clone());
        }
    }
    Ok(strip_fields)
}

fn strip_projection_fields(rows: &mut [Value], field_names: &[String]) {
    for row in rows {
        let Value::Object(object) = row else {
            continue;
        };
        for field_name in field_names {
            object.remove(field_name);
        }
    }
}

fn entity_field<'a>(entity: &'a EntityModel, name: &str) -> Result<&'a EntityField, Error> {
    entity
        .fields
        .iter()
        .find(|field| field.name == name)
        .ok_or_else(|| FilterError::UnknownField.into())
}

fn entity_field_by_table_column<'a>(
    entity: &'a EntityModel,
    table_column: &str,
) -> Result<&'a EntityField, Error> {
    entity
        .fields
        .iter()
        .find(|field| field.table_column == table_column)
        .ok_or_else(|| FilterError::UnknownField.into())
}

fn validate_allowed_filters(entity: &EntityModel, filters: &[EntityFilter]) -> Result<(), Error> {
    for filter in filters {
        let allowed =
            entity.api.allowed_filters.iter().any(|allowed| {
                allowed.field == filter.field && allowed.ops.contains(&FilterOp::Eq)
            });
        if !allowed {
            return Err(FilterError::NotAllowed.into());
        }
    }
    Ok(())
}

fn validate_allowed_expansions(entity: &EntityModel, expansions: &[String]) -> Result<(), Error> {
    for expansion in expansions {
        if expansion == "*" || expansion.contains('.') {
            return Err(FilterError::UnsupportedOp.into());
        }
        let declared = entity.relationships.contains_key(expansion);
        let allowed = entity
            .api
            .allowed_expansions
            .iter()
            .any(|allowed| allowed == expansion);
        if !declared || !allowed {
            return Err(FilterError::NotAllowed.into());
        }
    }
    Ok(())
}

fn literal_value(value: &Value) -> Result<datafusion::prelude::Expr, Error> {
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

fn batches_to_json_rows(batches: &[RecordBatch]) -> Result<Vec<Value>, Error> {
    let mut bytes = Vec::new();
    {
        let mut writer = WriterBuilder::new()
            .with_explicit_nulls(true)
            .build::<_, JsonArray>(&mut bytes);
        let refs: Vec<&RecordBatch> = batches.iter().collect();
        writer.write_batches(&refs).map_err(execution_failed)?;
        writer.finish().map_err(execution_failed)?;
    }
    serde_json::from_slice(&bytes).map_err(|err| {
        tracing::error!(
            event = "query.entity_json_serialization_failed",
            error = %err,
        );
        Error::from(InternalError::Unhandled)
    })
}

fn execution_failed(err: impl std::fmt::Display) -> Error {
    tracing::error!(
        event = "query.entity_execution_failed",
        error = %err,
    );
    InternalError::Unhandled.into()
}

fn table_name_str(dataset_id: &str, resource_id: &str) -> String {
    let dataset = serde_json::from_str(&format!(r#""{dataset_id}""#));
    let resource = serde_json::from_str(&format!(r#""{resource_id}""#));
    match (dataset, resource) {
        (Ok(dataset), Ok(resource)) => table_name(&dataset, &resource),
        _ => format!("{dataset_id}__{resource_id}"),
    }
}
