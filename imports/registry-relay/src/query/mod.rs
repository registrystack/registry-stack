// SPDX-License-Identifier: Apache-2.0
//! Entity query API over DataFusion table registrations.

use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::json::writer::{JsonArray, WriterBuilder};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::execution::context::SessionContext;
use datafusion::prelude::{col, lit};
use serde_json::Value;

use crate::config::{FilterOp, RelationshipKind};
use crate::entity::{EntityField, EntityModel, EntityRegistry};
use crate::error::{Error, FilterError, InternalError, SchemaError};
use crate::table_provider::{table_name, table_snapshot};

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
    pub after_primary_key: Option<Value>,
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
    In,
    Gte,
    Lte,
    Between,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntityRows {
    pub rows: Vec<Value>,
    pub next_primary_key: Option<Value>,
    pub cursor_ingest_version: Option<String>,
    pub validator_ingest_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntityRecord {
    pub value: Value,
    pub validator_ingest_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityExists {
    pub exists: bool,
    pub ingest_version: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RelationshipPageQuery {
    pub limit: Option<usize>,
    pub after_primary_key: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntityRelationshipPage {
    pub value: Value,
    pub next_primary_key: Option<Value>,
    pub cursor_ingest_version: Option<String>,
    pub validator_ingest_version: Option<String>,
}

impl EntityQueryEngine {
    pub fn new(ctx: Arc<SessionContext>, registry: Arc<EntityRegistry>) -> Self {
        Self { ctx, registry }
    }

    pub fn validate_collection_query(
        &self,
        dataset_id: &str,
        entity_name: &str,
        query: &EntityCollectionQuery,
    ) -> Result<(), Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        validate_allowed_expansions(entity, &query.expansions)?;
        projected_fields(entity, query.fields.as_deref())?;
        match query.limit {
            Some(limit) if limit == 0 || limit > entity.api.max_limit as usize => {
                return Err(FilterError::LimitOutOfRange.into());
            }
            _ => {}
        }
        validate_allowed_filters(entity, &query.filters)?;
        Ok(())
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
        let strip_primary_key = add_pagination_primary_key_field(
            entity,
            requested_fields.as_deref(),
            &mut projected_fields,
        );
        let limit = match query.limit {
            Some(limit) if limit == 0 || limit > entity.api.max_limit as usize => {
                return Err(FilterError::LimitOutOfRange.into());
            }
            Some(limit) => Some(limit),
            None => Some(entity.api.default_limit as usize),
        };
        validate_allowed_filters(entity, &query.filters)?;
        let mut result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &projected_fields,
                query.filters,
                limit.map(|limit| limit.saturating_add(1)),
                query.after_primary_key,
            )
            .await?;
        let cursor_ingest_version = table_version(&result.versions, &entity.table_id);
        let next_primary_key = truncate_page(&mut result.rows, limit, &entity.primary_key.name);
        merge_versions(
            &mut result.versions,
            self.expand_rows(dataset_id, entity, &mut result.rows, &query.expansions)
                .await?,
        );
        strip_projection_fields(&mut result.rows, &strip_fields);
        if strip_primary_key {
            strip_projection_fields(
                &mut result.rows,
                std::slice::from_ref(&entity.primary_key.name),
            );
        }
        Ok(EntityRows {
            validator_ingest_version: versions_token(&result.versions),
            rows: result.rows,
            next_primary_key,
            cursor_ingest_version,
        })
    }

    pub async fn read_record(
        &self,
        dataset_id: &str,
        entity_name: &str,
        primary_key: Value,
        fields: Option<Vec<String>>,
        expansions: Vec<String>,
    ) -> Result<Option<EntityRecord>, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        validate_allowed_expansions(entity, &expansions)?;
        let mut projected_fields = projected_fields(entity, fields.as_deref())?;
        let strip_fields = add_expansion_source_fields(entity, &expansions, &mut projected_fields)?;
        let filter = EntityFilter::eq(entity.primary_key.name.clone(), primary_key);
        let mut result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &projected_fields,
                vec![filter],
                Some(1),
                None,
            )
            .await?;
        merge_versions(
            &mut result.versions,
            self.expand_rows(dataset_id, entity, &mut result.rows, &expansions)
                .await?,
        );
        strip_projection_fields(&mut result.rows, &strip_fields);
        Ok(result.rows.into_iter().next().map(|value| EntityRecord {
            value,
            validator_ingest_version: versions_token(&result.versions),
        }))
    }

    pub async fn verify_exists(
        &self,
        dataset_id: &str,
        entity_name: &str,
        primary_key: Value,
    ) -> Result<EntityExists, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        let projected_fields = vec![&entity.primary_key];
        let filter = EntityFilter::eq(entity.primary_key.name.clone(), primary_key);
        let result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &projected_fields,
                vec![filter],
                Some(1),
                None,
            )
            .await?;
        Ok(EntityExists {
            exists: !result.rows.is_empty(),
            ingest_version: table_version(&result.versions, &entity.table_id),
        })
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
        let mut result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &entity.fields.iter().collect::<Vec<_>>(),
                vec![EntityFilter::eq(
                    entity.primary_key.name.clone(),
                    primary_key,
                )],
                Some(1),
                None,
            )
            .await?;
        let Some(row) = result.rows.pop() else {
            return Err(SchemaError::UnknownResource.into());
        };
        let expanded = self
            .expand_relationship(dataset_id, entity, &row, relationship_name, relationship)
            .await?;
        if relationship.kind == RelationshipKind::BelongsTo && expanded.value.is_null() {
            return Err(SchemaError::UnknownResource.into());
        }
        Ok(expanded.value)
    }

    pub async fn read_relationship_page(
        &self,
        dataset_id: &str,
        entity_name: &str,
        primary_key: Value,
        relationship_name: &str,
        page: RelationshipPageQuery,
    ) -> Result<EntityRelationshipPage, Error> {
        let entity = self.entity(dataset_id, entity_name)?;
        let Some(relationship) = entity.relationships.get(relationship_name) else {
            return Err(SchemaError::UnknownResource.into());
        };
        let mut host_result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &entity.fields.iter().collect::<Vec<_>>(),
                vec![EntityFilter::eq(
                    entity.primary_key.name.clone(),
                    primary_key,
                )],
                Some(1),
                None,
            )
            .await?;
        let Some(row) = host_result.rows.pop() else {
            return Err(SchemaError::UnknownResource.into());
        };
        if relationship.kind != RelationshipKind::HasMany {
            let expanded = self
                .expand_relationship(dataset_id, entity, &row, relationship_name, relationship)
                .await?;
            if relationship.kind == RelationshipKind::BelongsTo && expanded.value.is_null() {
                return Err(SchemaError::UnknownResource.into());
            }
            merge_versions(&mut host_result.versions, expanded.versions);
            return Ok(EntityRelationshipPage {
                value: expanded.value,
                next_primary_key: None,
                cursor_ingest_version: None,
                validator_ingest_version: versions_token(&host_result.versions),
            });
        }

        let target = self.entity(dataset_id, &relationship.target)?;
        let Some(value) = row.get(&entity.primary_key.name) else {
            return Err(SchemaError::ResourceUnavailable.into());
        };
        let target_fk = entity_field_by_table_column(target, &relationship.foreign_key)?;
        let limit = match page.limit {
            Some(limit) if limit == 0 || limit > target.api.max_limit as usize => {
                return Err(FilterError::LimitOutOfRange.into());
            }
            Some(limit) => limit,
            None => target.api.default_limit as usize,
        };
        let target_fields = target.fields.iter().collect::<Vec<_>>();
        let mut target_result = self
            .execute_entity_query(
                dataset_id,
                target,
                &target_fields,
                vec![EntityFilter::eq(target_fk.name.clone(), value.clone())],
                Some(limit.saturating_add(1)),
                page.after_primary_key,
            )
            .await?;
        let cursor_ingest_version = table_version(&target_result.versions, &target.table_id);
        let next_primary_key = truncate_page(
            &mut target_result.rows,
            Some(limit),
            &target.primary_key.name,
        );
        merge_versions(&mut host_result.versions, target_result.versions);
        Ok(EntityRelationshipPage {
            value: Value::Array(target_result.rows),
            next_primary_key,
            cursor_ingest_version,
            validator_ingest_version: versions_token(&host_result.versions),
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

    async fn execute_entity_query(
        &self,
        dataset_id: &str,
        entity: &EntityModel,
        projected_fields: &[&EntityField],
        filters: Vec<EntityFilter>,
        limit: Option<usize>,
        after_primary_key: Option<Value>,
    ) -> Result<VersionedRows, Error> {
        if matches!(limit, Some(0)) {
            return Err(FilterError::LimitOutOfRange.into());
        }

        let table = table_name_str(dataset_id, &entity.table_id);
        let snapshot = table_snapshot(&self.ctx, table.as_str())
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "query.entity_table_unavailable",
                    dataset_id,
                    entity = %entity.name,
                    table = %table,
                    error = %err,
                );
                Error::from(SchemaError::ResourceUnavailable)
            })?;
        let mut df = self
            .ctx
            .read_table(Arc::clone(&snapshot.provider))
            .map_err(execution_failed)?;

        for filter in filters {
            let field = entity_field(entity, &filter.field)?;
            let column = col(field.table_column.as_str());
            match filter.op {
                EntityFilterOp::Eq => {
                    df = df
                        .filter(column.eq(literal_value(&filter.value)?))
                        .map_err(execution_failed)?;
                }
                EntityFilterOp::In => {
                    let values = literal_list(&filter.value)?;
                    df = df
                        .filter(column.in_list(values, false))
                        .map_err(execution_failed)?;
                }
                EntityFilterOp::Gte => {
                    df = df
                        .filter(column.gt_eq(literal_value(&filter.value)?))
                        .map_err(execution_failed)?;
                }
                EntityFilterOp::Lte => {
                    df = df
                        .filter(column.lt_eq(literal_value(&filter.value)?))
                        .map_err(execution_failed)?;
                }
                EntityFilterOp::Between => {
                    let (lower, upper) = literal_range(&filter.value)?;
                    df = df
                        .filter(column.clone().gt_eq(lower).and(column.lt_eq(upper)))
                        .map_err(execution_failed)?;
                }
            }
        }

        if let Some(after_primary_key) = after_primary_key {
            df = df
                .filter(
                    col(entity.primary_key.table_column.as_str())
                        .gt(literal_value(&after_primary_key)?),
                )
                .map_err(execution_failed)?;
        }

        df = df
            .sort(vec![
                col(entity.primary_key.table_column.as_str()).sort(true, false)
            ])
            .map_err(execution_failed)?;

        let exprs = projected_fields
            .iter()
            .map(|field| col(field.table_column.as_str()).alias(field.name.clone()));
        df = df.select(exprs).map_err(execution_failed)?;

        if let Some(limit) = limit {
            df = df.limit(0, Some(limit)).map_err(execution_failed)?;
        }

        let batches = df.collect().await.map_err(execution_failed)?;
        let rows = batches_to_json_rows(&batches)?;
        let mut versions = BTreeMap::new();
        if let Some(ingest_ulid) = snapshot.ingest_ulid {
            versions.insert(entity.table_id.clone(), ingest_ulid.to_string());
        }
        Ok(VersionedRows { rows, versions })
    }

    async fn expand_rows(
        &self,
        dataset_id: &str,
        entity: &EntityModel,
        rows: &mut [Value],
        expansions: &[String],
    ) -> Result<VersionMap, Error> {
        let mut versions = BTreeMap::new();
        for expansion in expansions {
            let relationship = entity
                .relationships
                .get(expansion)
                .ok_or(FilterError::NotAllowed)?;
            for row in rows.iter_mut() {
                let expanded = self
                    .expand_relationship(dataset_id, entity, row, expansion, relationship)
                    .await?;
                merge_versions(&mut versions, expanded.versions.clone());
                if let Value::Object(object) = row {
                    object.insert(expansion.clone(), expanded.value);
                    if expanded.truncated {
                        mark_expansion_truncated(object, expansion);
                    }
                }
            }
        }
        Ok(versions)
    }

    async fn expand_relationship(
        &self,
        dataset_id: &str,
        entity: &EntityModel,
        row: &Value,
        relationship_name: &str,
        relationship: &crate::config::EntityRelationshipConfig,
    ) -> Result<ExpandedRelationship, Error> {
        let target = self.entity(dataset_id, &relationship.target)?;
        let (filter_field, filter_value, limit) = match relationship.kind {
            RelationshipKind::BelongsTo => {
                let source_fk = entity_field_by_table_column(entity, &relationship.foreign_key)?;
                let Some(value) = row.get(&source_fk.name) else {
                    return Err(SchemaError::ResourceUnavailable.into());
                };
                if value.is_null() {
                    return Ok(ExpandedRelationship::untruncated(
                        Value::Null,
                        BTreeMap::new(),
                    ));
                }
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
                let default_limit = target.api.default_limit as usize;
                (
                    target_fk.name.clone(),
                    value.clone(),
                    Some(default_limit.saturating_add(1)),
                )
            }
        };
        let target_fields = target.fields.iter().collect::<Vec<_>>();
        let mut result = self
            .execute_entity_query(
                dataset_id,
                target,
                &target_fields,
                vec![EntityFilter::eq(filter_field, filter_value)],
                limit,
                None,
            )
            .await?;
        match relationship.kind {
            RelationshipKind::HasMany => {
                let default_limit = target.api.default_limit as usize;
                let truncated = result.rows.len() > default_limit;
                result.rows.truncate(default_limit);
                Ok(ExpandedRelationship {
                    value: Value::Array(result.rows),
                    truncated,
                    versions: result.versions,
                })
            }
            RelationshipKind::BelongsTo | RelationshipKind::HasOne => {
                Ok(ExpandedRelationship::untruncated(
                    result.rows.pop().unwrap_or(Value::Null),
                    result.versions,
                ))
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

struct ExpandedRelationship {
    value: Value,
    truncated: bool,
    versions: VersionMap,
}

impl ExpandedRelationship {
    fn untruncated(value: Value, versions: VersionMap) -> Self {
        Self {
            value,
            truncated: false,
            versions,
        }
    }
}

type VersionMap = BTreeMap<String, String>;

struct VersionedRows {
    rows: Vec<Value>,
    versions: VersionMap,
}

fn merge_versions(target: &mut VersionMap, source: VersionMap) {
    target.extend(source);
}

fn table_version(versions: &VersionMap, table_id: &str) -> Option<String> {
    versions.get(table_id).cloned()
}

fn versions_token(versions: &VersionMap) -> Option<String> {
    if versions.is_empty() {
        return None;
    }
    Some(
        versions
            .iter()
            .map(|(table, version)| format!("{table}={version}"))
            .collect::<Vec<_>>()
            .join(";"),
    )
}

impl EntityCollectionQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_after_primary_key(mut self, primary_key: impl Into<Value>) -> Self {
        self.after_primary_key = Some(primary_key.into());
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

impl RelationshipPageQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_after_primary_key(mut self, primary_key: impl Into<Value>) -> Self {
        self.after_primary_key = Some(primary_key.into());
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

    pub fn with_op(field: impl Into<String>, op: EntityFilterOp, value: impl Into<Value>) -> Self {
        Self {
            field: field.into(),
            op,
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

fn add_pagination_primary_key_field<'a>(
    entity: &'a EntityModel,
    requested_fields: Option<&[String]>,
    projected_fields: &mut Vec<&'a EntityField>,
) -> bool {
    let should_strip = requested_fields
        .filter(|fields| !fields.is_empty())
        .is_some_and(|fields| !fields.iter().any(|field| field == &entity.primary_key.name));
    if should_strip
        && !projected_fields
            .iter()
            .any(|field| field.name == entity.primary_key.name)
    {
        projected_fields.push(&entity.primary_key);
    }
    should_strip
}

fn truncate_page(
    rows: &mut Vec<Value>,
    limit: Option<usize>,
    primary_key_name: &str,
) -> Option<Value> {
    let limit = limit?;
    if rows.len() <= limit {
        return None;
    }
    rows.truncate(limit);
    rows.last()?.get(primary_key_name).cloned()
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

fn mark_expansion_truncated(object: &mut serde_json::Map<String, Value>, relationship: &str) {
    let expansion = object
        .entry("_expansion")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Value::Object(expansion) = expansion else {
        return;
    };
    expansion.insert(
        relationship.to_string(),
        json_object([("truncated", Value::Bool(true))]),
    );
}

fn json_object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
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
        let allowed = entity.api.allowed_filters.iter().any(|allowed| {
            allowed.field == filter.field && allowed.ops.contains(&filter_op_config(filter.op))
        });
        if !allowed {
            return Err(FilterError::NotAllowed.into());
        }
    }
    Ok(())
}

fn filter_op_config(op: EntityFilterOp) -> FilterOp {
    match op {
        EntityFilterOp::Eq => FilterOp::Eq,
        EntityFilterOp::In => FilterOp::In,
        EntityFilterOp::Gte => FilterOp::Gte,
        EntityFilterOp::Lte => FilterOp::Lte,
        EntityFilterOp::Between => FilterOp::Between,
    }
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

fn literal_list(value: &Value) -> Result<Vec<datafusion::prelude::Expr>, Error> {
    let values = match value {
        Value::Array(values) => values,
        _ => return Err(FilterError::InvalidValue.into()),
    };
    if values.is_empty() {
        return Err(FilterError::InvalidValue.into());
    }
    if values.len() > 100 {
        return Err(FilterError::TooManyValues.into());
    }
    values.iter().map(literal_value).collect()
}

fn literal_range(
    value: &Value,
) -> Result<(datafusion::prelude::Expr, datafusion::prelude::Expr), Error> {
    let values = match value {
        Value::Array(values) if values.len() == 2 => values,
        _ => return Err(FilterError::InvalidRange.into()),
    };
    validate_range_order(&values[0], &values[1])?;
    Ok((literal_value(&values[0])?, literal_value(&values[1])?))
}

fn validate_range_order(lower: &Value, upper: &Value) -> Result<(), Error> {
    let valid = match (lower, upper) {
        (Value::String(lower), Value::String(upper)) => lower <= upper,
        (Value::Number(lower), Value::Number(upper)) => match (lower.as_f64(), upper.as_f64()) {
            (Some(lower), Some(upper)) => lower <= upper,
            _ => false,
        },
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(FilterError::InvalidRange.into())
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
