// SPDX-License-Identifier: Apache-2.0
//! Entity query API over DataFusion table registrations.

use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::json::writer::{JsonArray, WriterBuilder};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::execution::context::SessionContext;
use datafusion::prelude::{col, lit};
use serde_json::Value;

use crate::config::{
    FilterOp, RelationshipKind, RequiredFilterBindingConfig, RequiredFilterBindingSource,
};
use crate::entity::{EntityField, EntityModel, EntityRegistry};
use crate::error::{EntityError, Error, FilterError, InternalError, SchemaError};
use crate::table_provider::{publication_read_guard, table_name, table_snapshot};

pub mod aggregates;
pub use aggregates::{
    principal_bound_aggregate_filters, AggregateFilter, AggregateFilterOp, AggregateListItem,
    AggregateQueryEngine, AggregateQueryRequest, AggregateResult,
};

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
    /// Gateway-owned filters derived from trusted route semantics rather
    /// than caller-controlled entity filters. OGC uses this for spatial
    /// bbox predicates and primary-key item lookup while still applying
    /// `allowed_filters` to normal query parameters.
    pub trusted_filters: Vec<EntityFilter>,
    /// Gateway-owned filters derived from authenticated principal data. This
    /// lane is the only one that can satisfy `required_filters` security gates.
    pub principal_bound_filters: Vec<EntityFilter>,
    /// Principal-bound filters for relationship expansion targets, keyed by
    /// expansion name.
    pub expansion_principal_bound_filters: BTreeMap<String, Vec<EntityFilter>>,
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

pub fn satisfies_required_filter(required_filters: &[String], filter: &EntityFilter) -> bool {
    required_filters
        .iter()
        .any(|required| required == &filter.field)
        && filter.op == EntityFilterOp::Eq
        && is_single_scalar_filter_value(&filter.value)
}

pub fn required_filters_are_satisfied(
    required_filters: &[String],
    filters: &[EntityFilter],
) -> bool {
    filters
        .iter()
        .any(|filter| satisfies_required_filter(required_filters, filter))
}

pub fn principal_bound_required_filters(
    required_filters: &[String],
    bindings: &[RequiredFilterBindingConfig],
    principal_id: Option<&str>,
) -> Result<Vec<EntityFilter>, Error> {
    if required_filters.is_empty() {
        return Ok(Vec::new());
    }
    let mut filters = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let value = match binding.source {
            RequiredFilterBindingSource::PrincipalId => {
                principal_id.ok_or_else(|| EntityError::FilterRequired {
                    required: required_filters.to_vec(),
                })?
            }
        };
        filters.push(EntityFilter::eq(binding.field.clone(), value.to_string()));
    }
    Ok(filters)
}

pub fn bind_principal_required_filters(
    required_filters: &[String],
    bindings: &[RequiredFilterBindingConfig],
    principal_id: Option<&str>,
    query: &mut EntityCollectionQuery,
) -> Result<(), Error> {
    query
        .principal_bound_filters
        .extend(principal_bound_required_filters(
            required_filters,
            bindings,
            principal_id,
        )?);
    Ok(())
}

fn validate_required_filter_gate(
    entity: &EntityModel,
    _caller_filters: &[EntityFilter],
    _trusted_filters: &[EntityFilter],
    principal_bound_filters: &[EntityFilter],
) -> Result<(), Error> {
    let required_filters = &entity.api.required_filters;
    if required_filters.is_empty() {
        return Ok(());
    }
    if required_filters_are_satisfied(required_filters, principal_bound_filters) {
        return Ok(());
    }
    Err(EntityError::FilterRequired {
        required: required_filters.clone(),
    }
    .into())
}

pub(super) fn is_single_scalar_filter_value(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Number(_) | Value::Bool(_) => true,
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    }
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
    pub host_principal_bound_filters: Vec<EntityFilter>,
    pub target_principal_bound_filters: Vec<EntityFilter>,
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
        validate_expansion_principal_bound_filters(
            self,
            dataset_id,
            entity,
            &query.expansion_principal_bound_filters,
        )?;
        projected_fields(entity, query.fields.as_deref())?;
        match query.limit {
            Some(limit) if limit == 0 || limit > entity.api.max_limit as usize => {
                return Err(FilterError::LimitOutOfRange.into());
            }
            _ => {}
        }
        validate_allowed_filters(entity, &query.filters)?;
        validate_filter_fields_exist(entity, &query.trusted_filters)?;
        validate_filter_fields_exist(entity, &query.principal_bound_filters)?;
        validate_required_filter_gate(
            entity,
            &query.filters,
            &query.trusted_filters,
            &query.principal_bound_filters,
        )?;
        Ok(())
    }

    pub async fn read_collection(
        &self,
        dataset_id: &str,
        entity_name: &str,
        query: EntityCollectionQuery,
    ) -> Result<EntityRows, Error> {
        let _publication_guard = publication_read_guard().await;
        let entity = self.entity(dataset_id, entity_name)?;
        validate_allowed_expansions(entity, &query.expansions)?;
        validate_expansion_principal_bound_filters(
            self,
            dataset_id,
            entity,
            &query.expansion_principal_bound_filters,
        )?;
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
        validate_filter_fields_exist(entity, &query.trusted_filters)?;
        validate_filter_fields_exist(entity, &query.principal_bound_filters)?;
        validate_required_filter_gate(
            entity,
            &query.filters,
            &query.trusted_filters,
            &query.principal_bound_filters,
        )?;
        let mut filters = query.filters;
        filters.extend(query.trusted_filters);
        filters.extend(query.principal_bound_filters);
        let mut result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &projected_fields,
                filters,
                limit.map(|limit| limit.saturating_add(1)),
                query.after_primary_key,
            )
            .await?;
        let cursor_ingest_version = table_version(&result.versions, &entity.table_id);
        let next_primary_key = truncate_page(&mut result.rows, limit, &entity.primary_key.name);
        merge_versions(
            &mut result.versions,
            self.expand_rows(
                dataset_id,
                entity,
                &mut result.rows,
                &query.expansions,
                &query.expansion_principal_bound_filters,
            )
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

    #[allow(clippy::too_many_arguments)]
    pub async fn read_record(
        &self,
        dataset_id: &str,
        entity_name: &str,
        primary_key: Value,
        fields: Option<Vec<String>>,
        expansions: Vec<String>,
        expansion_principal_bound_filters: BTreeMap<String, Vec<EntityFilter>>,
        principal_bound_filters: Vec<EntityFilter>,
    ) -> Result<Option<EntityRecord>, Error> {
        let _publication_guard = publication_read_guard().await;
        let entity = self.entity(dataset_id, entity_name)?;
        validate_allowed_expansions(entity, &expansions)?;
        validate_expansion_principal_bound_filters(
            self,
            dataset_id,
            entity,
            &expansion_principal_bound_filters,
        )?;
        validate_filter_fields_exist(entity, &principal_bound_filters)?;
        let mut projected_fields = projected_fields(entity, fields.as_deref())?;
        let strip_fields = add_expansion_source_fields(entity, &expansions, &mut projected_fields)?;
        let filter = EntityFilter::eq(entity.primary_key.name.clone(), primary_key);
        validate_required_filter_gate(
            entity,
            &[],
            std::slice::from_ref(&filter),
            &principal_bound_filters,
        )?;
        let mut filters = vec![filter];
        filters.extend(principal_bound_filters);
        let mut result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &projected_fields,
                filters,
                Some(1),
                None,
            )
            .await?;
        merge_versions(
            &mut result.versions,
            self.expand_rows(
                dataset_id,
                entity,
                &mut result.rows,
                &expansions,
                &expansion_principal_bound_filters,
            )
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
        let _publication_guard = publication_read_guard().await;
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
        host_principal_bound_filters: Vec<EntityFilter>,
    ) -> Result<Value, Error> {
        let _publication_guard = publication_read_guard().await;
        let entity = self.entity(dataset_id, entity_name)?;
        let Some(relationship) = entity.relationships.get(relationship_name) else {
            return Err(SchemaError::UnknownResource.into());
        };
        validate_filter_fields_exist(entity, &host_principal_bound_filters)?;
        let host_filter = EntityFilter::eq(entity.primary_key.name.clone(), primary_key);
        validate_required_filter_gate(
            entity,
            &[],
            std::slice::from_ref(&host_filter),
            &host_principal_bound_filters,
        )?;
        let mut host_filters = vec![host_filter];
        host_filters.extend(host_principal_bound_filters);
        let mut result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &entity.fields.iter().collect::<Vec<_>>(),
                host_filters,
                Some(1),
                None,
            )
            .await?;
        let Some(row) = result.rows.pop() else {
            return Err(SchemaError::UnknownResource.into());
        };
        let expanded = self
            .expand_relationship(
                dataset_id,
                entity,
                &row,
                relationship_name,
                relationship,
                &[],
            )
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
        let _publication_guard = publication_read_guard().await;
        let entity = self.entity(dataset_id, entity_name)?;
        let Some(relationship) = entity.relationships.get(relationship_name) else {
            return Err(SchemaError::UnknownResource.into());
        };
        validate_filter_fields_exist(entity, &page.host_principal_bound_filters)?;
        let host_filter = EntityFilter::eq(entity.primary_key.name.clone(), primary_key);
        validate_required_filter_gate(
            entity,
            &[],
            std::slice::from_ref(&host_filter),
            &page.host_principal_bound_filters,
        )?;
        let mut host_filters = vec![host_filter];
        host_filters.extend(page.host_principal_bound_filters.clone());
        let mut host_result = self
            .execute_entity_query(
                dataset_id,
                entity,
                &entity.fields.iter().collect::<Vec<_>>(),
                host_filters,
                Some(1),
                None,
            )
            .await?;
        let Some(row) = host_result.rows.pop() else {
            return Err(SchemaError::UnknownResource.into());
        };
        if relationship.kind != RelationshipKind::HasMany {
            let expanded = self
                .expand_relationship(
                    dataset_id,
                    entity,
                    &row,
                    relationship_name,
                    relationship,
                    &page.target_principal_bound_filters,
                )
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
        validate_filter_fields_exist(target, &page.target_principal_bound_filters)?;
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
        let target_filter = EntityFilter::eq(target_fk.name.clone(), value.clone());
        validate_required_filter_gate(
            target,
            &[],
            std::slice::from_ref(&target_filter),
            &page.target_principal_bound_filters,
        )?;
        let mut target_filters = vec![target_filter];
        target_filters.extend(page.target_principal_bound_filters);
        let mut target_result = self
            .execute_entity_query(
                dataset_id,
                target,
                &target_fields,
                target_filters,
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
        expansion_principal_bound_filters: &BTreeMap<String, Vec<EntityFilter>>,
    ) -> Result<VersionMap, Error> {
        let mut versions = BTreeMap::new();
        for expansion in expansions {
            let relationship = entity
                .relationships
                .get(expansion)
                .ok_or(FilterError::NotAllowed)?;
            let target_principal_bound_filters = expansion_principal_bound_filters
                .get(expansion)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for row in rows.iter_mut() {
                let expanded = self
                    .expand_relationship(
                        dataset_id,
                        entity,
                        row,
                        expansion,
                        relationship,
                        target_principal_bound_filters,
                    )
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
        target_principal_bound_filters: &[EntityFilter],
    ) -> Result<ExpandedRelationship, Error> {
        let target = self.entity(dataset_id, &relationship.target)?;
        validate_filter_fields_exist(target, target_principal_bound_filters)?;
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
        let target_filter = EntityFilter::eq(filter_field, filter_value);
        validate_required_filter_gate(
            target,
            &[],
            std::slice::from_ref(&target_filter),
            target_principal_bound_filters,
        )?;
        let mut target_filters = vec![target_filter];
        target_filters.extend(target_principal_bound_filters.iter().cloned());
        let mut result = self
            .execute_entity_query(
                dataset_id,
                target,
                &target_fields,
                target_filters,
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

    pub fn with_trusted_filter(mut self, filter: EntityFilter) -> Self {
        self.trusted_filters.push(filter);
        self
    }

    pub fn with_principal_bound_filter(mut self, filter: EntityFilter) -> Self {
        self.principal_bound_filters.push(filter);
        self
    }

    pub fn with_expansions(
        mut self,
        expansions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.expansions = expansions.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_expansion_principal_bound_filters(
        mut self,
        filters: BTreeMap<String, Vec<EntityFilter>>,
    ) -> Self {
        self.expansion_principal_bound_filters = filters;
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

    pub fn with_host_principal_bound_filters(
        mut self,
        filters: impl IntoIterator<Item = EntityFilter>,
    ) -> Self {
        self.host_principal_bound_filters = filters.into_iter().collect();
        self
    }

    pub fn with_target_principal_bound_filters(
        mut self,
        filters: impl IntoIterator<Item = EntityFilter>,
    ) -> Self {
        self.target_principal_bound_filters = filters.into_iter().collect();
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

fn validate_filter_fields_exist(
    entity: &EntityModel,
    filters: &[EntityFilter],
) -> Result<(), Error> {
    for filter in filters {
        entity_field(entity, &filter.field)?;
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

fn validate_expansion_principal_bound_filters(
    query: &EntityQueryEngine,
    dataset_id: &str,
    entity: &EntityModel,
    filters: &BTreeMap<String, Vec<EntityFilter>>,
) -> Result<(), Error> {
    for (expansion, principal_filters) in filters {
        let Some(relationship) = entity.relationships.get(expansion) else {
            return Err(FilterError::NotAllowed.into());
        };
        let target = query.entity(dataset_id, &relationship.target)?;
        validate_filter_fields_exist(target, principal_filters)?;
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

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use datafusion::arrow::array::{ArrayRef, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::catalog::{Session, TableProvider};
    use datafusion::common::{Result as DataFusionResult, Statistics};
    use datafusion::datasource::MemTable;
    use datafusion::execution::context::SessionContext;
    use datafusion::logical_expr::{Expr, TableProviderFilterPushDown, TableType};
    use datafusion::physical_plan::ExecutionPlan;
    use serde_json::json;
    use tokio::sync::Notify;
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::config::Config;
    use crate::entity::EntityRegistry;
    use crate::table_provider::publication_write_guard;

    #[derive(Debug)]
    struct BlockingTableProvider {
        inner: Arc<dyn TableProvider>,
        started: Arc<Notify>,
        release: Arc<Notify>,
        blocked: AtomicBool,
    }

    impl BlockingTableProvider {
        fn new(inner: Arc<dyn TableProvider>, started: Arc<Notify>, release: Arc<Notify>) -> Self {
            Self {
                inner,
                started,
                release,
                blocked: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl TableProvider for BlockingTableProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn schema(&self) -> SchemaRef {
            self.inner.schema()
        }

        fn table_type(&self) -> TableType {
            self.inner.table_type()
        }

        async fn scan(
            &self,
            state: &dyn Session,
            projection: Option<&Vec<usize>>,
            filters: &[Expr],
            limit: Option<usize>,
        ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
            if !self.blocked.swap(true, Ordering::SeqCst) {
                self.started.notify_one();
                self.release.notified().await;
            }
            self.inner.scan(state, projection, filters, limit).await
        }

        fn supports_filters_pushdown(
            &self,
            filters: &[&Expr],
        ) -> DataFusionResult<Vec<TableProviderFilterPushDown>> {
            self.inner.supports_filters_pushdown(filters)
        }

        fn statistics(&self) -> Option<Statistics> {
            self.inner.statistics()
        }
    }

    fn query_test_config() -> Config {
        serde_saphyr::from_str(
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
    tables:
      - id: households_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
            - name: region_code
              type: string
              nullable: false
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
            - name: household_id
              type: string
              nullable: false
            - name: given_name
              type: string
              nullable: false
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: given_name
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
          allowed_expansions: [household]

audit:
  sink: stdout
  format: jsonl
"#,
        )
        .expect("query test config parses")
    }

    fn mem_table(schema: SchemaRef, columns: Vec<ArrayRef>) -> Arc<dyn TableProvider> {
        let batch = RecordBatch::try_new(Arc::clone(&schema), columns).expect("record batch");
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("mem table"))
    }

    fn household_table() -> Arc<dyn TableProvider> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("household_id", DataType::Utf8, false),
            Field::new("region_code", DataType::Utf8, false),
        ]));
        mem_table(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["hh-1"])) as ArrayRef,
                Arc::new(StringArray::from(vec!["north"])) as ArrayRef,
            ],
        )
    }

    fn individual_table() -> Arc<dyn TableProvider> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("individual_id", DataType::Utf8, false),
            Field::new("household_id", DataType::Utf8, false),
            Field::new("given_name", DataType::Utf8, false),
        ]));
        mem_table(
            schema,
            vec![
                Arc::new(StringArray::from(vec!["p-1"])) as ArrayRef,
                Arc::new(StringArray::from(vec!["hh-1"])) as ArrayRef,
                Arc::new(StringArray::from(vec!["Ada"])) as ArrayRef,
            ],
        )
    }

    #[tokio::test]
    async fn public_collection_read_holds_publication_guard_until_expansions_finish() {
        let cfg = query_test_config();
        let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));
        let ctx = Arc::new(SessionContext::new());

        ctx.register_table(
            table_name_str("social_registry", "households_table"),
            household_table(),
        )
        .expect("register households table");

        let scan_started = Arc::new(Notify::new());
        let release_scan = Arc::new(Notify::new());
        let blocking_individuals: Arc<dyn TableProvider> = Arc::new(BlockingTableProvider::new(
            individual_table(),
            Arc::clone(&scan_started),
            Arc::clone(&release_scan),
        ));
        ctx.register_table(
            table_name_str("social_registry", "individuals_table"),
            blocking_individuals,
        )
        .expect("register individuals table");

        let engine = EntityQueryEngine::new(ctx, registry);
        let read_task = tokio::spawn(async move {
            engine
                .read_collection(
                    "social_registry",
                    "individual",
                    EntityCollectionQuery::new().with_expansions(["household"]),
                )
                .await
        });

        timeout(Duration::from_secs(1), scan_started.notified())
            .await
            .expect("base table scan started");

        let mut publication_write = Box::pin(publication_write_guard());
        assert!(
            timeout(Duration::from_millis(50), &mut publication_write)
                .await
                .is_err(),
            "publication write guard acquired while public read was still in flight"
        );

        release_scan.notify_one();
        let rows = timeout(Duration::from_secs(1), read_task)
            .await
            .expect("public read finishes")
            .expect("public read task joins")
            .expect("public read succeeds")
            .rows;
        assert_eq!(
            rows,
            vec![json!({
                "id": "p-1",
                "household_id": "hh-1",
                "given_name": "Ada",
                "household": {"id": "hh-1", "region": "north"}
            })]
        );

        let _publication_guard = timeout(Duration::from_secs(1), &mut publication_write)
            .await
            .expect("publication write unblocks after public read");
    }
}
