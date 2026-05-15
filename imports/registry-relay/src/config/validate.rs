// SPDX-License-Identifier: Apache-2.0
//! Cross-field validation for the parsed [`Config`].
//!
//! Each check returns the most specific [`ConfigError`] variant from
//! the taxonomy; operator-visible context (offending dataset / resource
//! / field id, env var name, etc.) is emitted to `tracing` at error
//! level so the operator sees what failed in their logs while the
//! response/audit detail strings stay scrubbed.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::net::IpAddr;

use crate::error::{ConfigError, Error};

use super::{
    AggregateConfig, AllowedFilter, AuthMode, Config, DatasetConfig, EntityConfig,
    EntityRelationshipConfig, FieldConfig, RelationshipKind, ResourceConfig, SourceConfig,
};

/// Prefix for the special `admin` scope. Spec.md Section 8.
const ADMIN_SCOPE: &str = "admin";

/// Run every cross-field check on a freshly deserialised [`Config`].
///
/// # Errors
///
/// Returns the corresponding [`ConfigError`] variant on the first
/// failure. Multiple failures are not aggregated in V1 to keep the
/// error type unit-shaped; the operator log line names the offending
/// field.
pub fn run(config: &Config) -> Result<(), Error> {
    super::vocabularies::validate_registry(&config.vocabularies).map_err(Error::from)?;
    validate_server(config).map_err(Error::from)?;
    validate_ids_and_uniqueness(config).map_err(Error::from)?;
    validate_scopes(config).map_err(Error::from)?;
    validate_env_vars_and_hashes(config).map_err(Error::from)?;
    validate_resources(config).map_err(Error::from)?;
    Ok(())
}

/// Match `^[a-z][a-z0-9_]*$` without pulling in a regex crate.
fn is_valid_id(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn validate_server(config: &Config) -> Result<(), ConfigError> {
    for cidr in &config.server.trust_proxy.trusted_proxies {
        if !is_trusted_proxy_spec(cidr) {
            tracing::error!(
                code = "config.validation_error",
                trusted_proxy = %cidr,
                "trusted_proxies entry must be an IP address or CIDR range"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn is_trusted_proxy_spec(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((addr, prefix)) = trimmed.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let Ok(bits) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => bits <= 32,
        IpAddr::V6(_) => bits <= 128,
    }
}

fn validate_ids_and_uniqueness(config: &Config) -> Result<(), ConfigError> {
    let mut dataset_ids: HashSet<&str> = HashSet::new();
    for dataset in &config.datasets {
        if !is_valid_id(dataset.id.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                "dataset id does not match ^[a-z][a-z0-9_]*$"
            );
            return Err(ConfigError::ValidationError);
        }
        if !dataset_ids.insert(dataset.id.as_str()) {
            tracing::error!(
                code = "config.duplicate_id",
                dataset_id = %dataset.id,
                "duplicate dataset id"
            );
            return Err(ConfigError::DuplicateId);
        }

        let mut resource_ids: HashSet<&str> = HashSet::new();
        for resource in dataset.table_configs() {
            if !is_valid_id(resource.id.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    "resource id does not match ^[a-z][a-z0-9_]*$"
                );
                return Err(ConfigError::ValidationError);
            }
            if !resource_ids.insert(resource.id.as_str()) {
                tracing::error!(
                    code = "config.duplicate_id",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    "duplicate resource id within dataset"
                );
                return Err(ConfigError::DuplicateId);
            }

            let mut aggregate_ids: HashSet<&str> = HashSet::new();
            for aggregate in &resource.aggregates {
                if !is_valid_id(aggregate.id.as_str()) {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        resource_id = %resource.id,
                        aggregate_id = %aggregate.id,
                        "aggregate id does not match ^[a-z][a-z0-9_]*$"
                    );
                    return Err(ConfigError::ValidationError);
                }
                if !aggregate_ids.insert(aggregate.id.as_str()) {
                    tracing::error!(
                        code = "config.duplicate_id",
                        dataset_id = %dataset.id,
                        resource_id = %resource.id,
                        aggregate_id = %aggregate.id,
                        "duplicate aggregate id within resource"
                    );
                    return Err(ConfigError::DuplicateId);
                }
            }
        }

        let mut entity_names: HashSet<&str> = HashSet::new();
        for entity in &dataset.entities {
            if !is_valid_id(&entity.name) || is_reserved_entity_segment(&entity.name) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "entity name is invalid or reserved"
                );
                return Err(ConfigError::ValidationError);
            }
            if !entity_names.insert(&entity.name) {
                tracing::error!(
                    code = "config.duplicate_id",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "duplicate entity name within dataset"
                );
                return Err(ConfigError::DuplicateId);
            }
        }
    }
    Ok(())
}

fn validate_scopes(config: &Config) -> Result<(), ConfigError> {
    let dataset_ids: HashSet<&str> = config.datasets.iter().map(|d| d.id.as_str()).collect();

    for key in &config.auth.api_keys {
        if !is_valid_id(&key.id) {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                "api key id does not match ^[a-z][a-z0-9_]*$"
            );
            return Err(ConfigError::ValidationError);
        }
        for scope in &key.scopes {
            validate_scope(scope, &dataset_ids, &key.id)?;
        }
    }
    Ok(())
}

fn validate_scope(
    scope: &str,
    dataset_ids: &HashSet<&str>,
    api_key_id: &str,
) -> Result<(), ConfigError> {
    if scope == ADMIN_SCOPE {
        return Ok(());
    }
    let (dataset, level) = scope.split_once(':').ok_or_else(|| {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %api_key_id,
            scope = %scope,
            "scope must be 'admin' or '<dataset_id>:<metadata|aggregate|rows|verify|bulk_export>'"
        );
        ConfigError::ValidationError
    })?;

    match level {
        "metadata" | "aggregate" | "rows" | "verify" | "bulk_export" => {}
        _ => {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %api_key_id,
                scope = %scope,
                "unknown scope level (allowed: metadata, aggregate, rows, verify, bulk_export)"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    if !dataset_ids.contains(dataset) {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %api_key_id,
            scope = %scope,
            dataset_id = %dataset,
            "scope references unknown dataset"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_env_vars_and_hashes(config: &Config) -> Result<(), ConfigError> {
    if config.auth.mode != AuthMode::ApiKey {
        return Ok(());
    }
    for key in &config.auth.api_keys {
        if key.hash_env.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                "hash_env must be a non-empty environment variable name"
            );
            return Err(ConfigError::ValidationError);
        }
        let value = match env::var(&key.hash_env) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!(
                    code = "config.missing_secret",
                    api_key_id = %key.id,
                    hash_env = %key.hash_env,
                    "hash_env environment variable is not set"
                );
                return Err(ConfigError::MissingSecret);
            }
        };
        if !is_argon2id_phc(&value) {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                hash_env = %key.hash_env,
                "hash_env value is not an Argon2id PHC string"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

/// Cheap structural check for an Argon2id PHC string. We deliberately
/// avoid pulling Argon2 verification into config validation: that is
/// done at request time by the auth layer. Here we only confirm the
/// value *looks like* a PHC string for the right algorithm.
fn is_argon2id_phc(s: &str) -> bool {
    // PHC format: `$argon2id$v=...$m=...,t=...,p=...$<salt>$<hash>`.
    // Five `$`-separated segments after the leading `$`. We accept any
    // value that starts with the algorithm marker and has at least
    // four further segments; the auth layer parses it strictly.
    if !s.starts_with("$argon2id$") {
        return false;
    }
    s.split('$').filter(|seg| !seg.is_empty()).count() >= 5
}

fn validate_resources(config: &Config) -> Result<(), ConfigError> {
    for dataset in &config.datasets {
        validate_dataset_uris(&config.vocabularies, dataset)?;
        validate_source(dataset)?;
        validate_format_overrides(dataset)?;
        for resource in dataset.table_configs() {
            validate_schema_uris(&config.vocabularies, dataset, resource)?;
            validate_allowed_filters(dataset, resource)?;
            for aggregate in &resource.aggregates {
                validate_aggregate(dataset, resource, aggregate)?;
            }
        }
        validate_entities(&config.vocabularies, dataset)?;
    }
    Ok(())
}

fn validate_format_overrides(dataset: &DatasetConfig) -> Result<(), ConfigError> {
    for resource in dataset.table_configs() {
        let Some(format) = &resource.format else {
            continue;
        };
        let count = usize::from(format.csv.is_some())
            + usize::from(format.xlsx.is_some())
            + usize::from(format.parquet.is_some());
        if count != 1 {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "resource.format must declare exactly one of csv, xlsx, parquet"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_dataset_uris(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
) -> Result<(), ConfigError> {
    for uri in &dataset.conforms_to {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                uri = %uri,
                "conforms_to URI uses an unregistered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_source(dataset: &DatasetConfig) -> Result<(), ConfigError> {
    match &dataset.source {
        SourceConfig::File { path, .. } => {
            if path.as_os_str().is_empty() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    "source.path is empty"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn validate_schema_uris(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
) -> Result<(), ConfigError> {
    for field in &resource.schema.fields {
        if let Some(uri) = &field.concept_uri {
            if super::vocabularies::expand(uri, registry).is_none() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    field = %field.name,
                    uri = %uri,
                    "field.concept_uri uses an unregistered vocabulary prefix"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn validate_allowed_filters(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
) -> Result<(), ConfigError> {
    let field_names: HashSet<&str> = field_names_of(resource);
    for filter in &resource.api.allowed_filters {
        validate_filter(dataset, resource, filter, &field_names)?;
    }
    Ok(())
}

/// Project the schema's field name set; reused by aggregate validation.
fn field_names_of(resource: &ResourceConfig) -> HashSet<&str> {
    resource
        .schema
        .fields
        .iter()
        .map(|f: &FieldConfig| f.name.as_str())
        .collect()
}

fn validate_filter(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    filter: &AllowedFilter,
    field_names: &HashSet<&str>,
) -> Result<(), ConfigError> {
    if !field_names.contains(filter.field.as_str()) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            field = %filter.field,
            "allowed_filters references a field not in the resource schema"
        );
        return Err(ConfigError::ValidationError);
    }
    if filter.ops.is_empty() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            field = %filter.field,
            "allowed_filters entry must declare at least one op"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_aggregate(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    aggregate: &AggregateConfig,
) -> Result<(), ConfigError> {
    let field_names: HashSet<&str> = field_names_of(resource);

    if aggregate.disclosure_control.min_group_size < 1 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            aggregate_id = %aggregate.id,
            "disclosure_control.min_group_size must be >= 1"
        );
        return Err(ConfigError::ValidationError);
    }

    for column in &aggregate.group_by {
        if !field_names.contains(column.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                aggregate_id = %aggregate.id,
                column = %column,
                "aggregate group_by references a field not in the resource schema"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    for measure in &aggregate.measures {
        if !field_names.contains(measure.column.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                aggregate_id = %aggregate.id,
                measure = %measure.name,
                column = %measure.column,
                "aggregate measure references a field not in the resource schema"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_entities(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
) -> Result<(), ConfigError> {
    if dataset.entities.is_empty() {
        return Ok(());
    }

    let tables: BTreeMap<&str, &ResourceConfig> = dataset
        .table_configs()
        .map(|table| (table.id.as_str(), table))
        .collect();
    let entities: BTreeMap<&str, &EntityConfig> = dataset
        .entities
        .iter()
        .map(|entity| (entity.name.as_str(), entity))
        .collect();

    for entity in &dataset.entities {
        validate_entity_uris(registry, dataset, entity)?;
        let table = tables.get(entity.table.as_str()).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                table_id = %entity.table,
                "entity references an unknown backing table"
            );
            ConfigError::ValidationError
        })?;

        let exposed_fields = exposed_entity_fields(entity, table)?;
        validate_entity_primary_key(dataset, entity, table, &exposed_fields)?;
        validate_entity_filters(dataset, entity, &exposed_fields)?;
        validate_entity_aggregates(dataset, entity, &exposed_fields)?;
        validate_entity_relationships(dataset, entity, table, &tables, &entities)?;
    }

    Ok(())
}

fn validate_entity_uris(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
    entity: &EntityConfig,
) -> Result<(), ConfigError> {
    if let Some(uri) = &entity.concept_uri {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                uri = %uri,
                "entity concept_uri uses an unregistered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    for field in &entity.fields {
        if let Some(uri) = &field.concept_uri {
            if super::vocabularies::expand(uri, registry).is_none() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    field = %field.name,
                    uri = %uri,
                    "entity field concept_uri uses an unregistered vocabulary prefix"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    for relationship in &entity.relationships {
        if let Some(uri) = &relationship.concept_uri {
            if super::vocabularies::expand(uri, registry).is_none() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    relationship = %relationship.name,
                    uri = %uri,
                    "entity relationship concept_uri uses an unregistered vocabulary prefix"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn exposed_entity_fields(
    entity: &EntityConfig,
    table: &ResourceConfig,
) -> Result<BTreeMap<String, String>, ConfigError> {
    let table_fields = field_names_of(table);
    if entity.fields.is_empty() {
        return Ok(table
            .schema
            .fields
            .iter()
            .map(|field| (field.name.clone(), field.name.clone()))
            .collect());
    }

    let mut exposed = BTreeMap::new();
    for field in &entity.fields {
        if !is_valid_id(&field.name) {
            tracing::error!(
                code = "config.validation_error",
                entity = %entity.name,
                field = %field.name,
                "entity field name is not a valid lower-snake id"
            );
            return Err(ConfigError::ValidationError);
        }
        let source = field.from.as_deref().unwrap_or(&field.name);
        if !table_fields.contains(source) {
            tracing::error!(
                code = "config.validation_error",
                entity = %entity.name,
                field = %field.name,
                from = %source,
                table_id = %table.id,
                "entity field projection references a missing table column"
            );
            return Err(ConfigError::ValidationError);
        }
        if exposed
            .insert(field.name.clone(), source.to_string())
            .is_some()
        {
            tracing::error!(
                code = "config.duplicate_id",
                entity = %entity.name,
                field = %field.name,
                "duplicate entity field"
            );
            return Err(ConfigError::DuplicateId);
        }
    }
    Ok(exposed)
}

fn validate_entity_primary_key(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let Some(primary_key) = table.primary_key.as_deref() else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            table_id = %table.id,
            "entity backing table must declare primary_key"
        );
        return Err(ConfigError::ValidationError);
    };
    let pk_exposures = exposed_fields
        .values()
        .filter(|from| from.as_str() == primary_key)
        .count();
    if pk_exposures != 1 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            table_id = %table.id,
            primary_key = %primary_key,
            exposures = pk_exposures,
            "exactly one entity field must expose the backing table primary key"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_entity_filters(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let allowed_filter_fields: HashSet<&str> = entity
        .api
        .allowed_filters
        .iter()
        .map(|f| f.field.as_str())
        .collect();

    for filter in &entity.api.allowed_filters {
        if !exposed_fields.contains_key(&filter.field) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %filter.field,
                "entity allowed_filters references a non-exposed field"
            );
            return Err(ConfigError::ValidationError);
        }
        if filter.ops.is_empty() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %filter.field,
                "entity allowed_filters entry must declare at least one op"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    for field in &entity.api.required_filters {
        if !allowed_filter_fields.contains(field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %field,
                "entity required_filters entry is not present in allowed_filters"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    Ok(())
}

fn validate_entity_aggregates(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for aggregate in &entity.aggregates {
        let join_names: HashSet<&str> = aggregate
            .joins
            .iter()
            .map(|join| join.relationship.as_str())
            .collect();
        for join in &aggregate.joins {
            if !entity
                .relationships
                .iter()
                .any(|rel| rel.name == join.relationship)
            {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    aggregate_id = %aggregate.id,
                    relationship = %join.relationship,
                    "entity aggregate join references an unknown relationship"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        if aggregate.disclosure_control.min_group_size < 1 {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                aggregate_id = %aggregate.id,
                "entity aggregate min_group_size must be >= 1"
            );
            return Err(ConfigError::ValidationError);
        }
        for field in &aggregate.group_by {
            if let Some((relationship, related_field)) = field.split_once('.') {
                if !join_names.contains(relationship) || related_field.is_empty() {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        aggregate_id = %aggregate.id,
                        field = %field,
                        "relationship-prefixed aggregate group_by must reference a declared aggregate join"
                    );
                    return Err(ConfigError::ValidationError);
                }
            } else if !exposed_fields.contains_key(field) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    aggregate_id = %aggregate.id,
                    field = %field,
                    "entity aggregate group_by references a non-exposed field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        for measure in &aggregate.measures {
            if !exposed_fields.contains_key(&measure.column) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    aggregate_id = %aggregate.id,
                    column = %measure.column,
                    "entity aggregate measure references a non-exposed field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn validate_entity_relationships(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    tables: &BTreeMap<&str, &ResourceConfig>,
    entities: &BTreeMap<&str, &EntityConfig>,
) -> Result<(), ConfigError> {
    let mut names = HashSet::new();
    if !entity.api.allowed_expansions.is_empty()
        && !entity
            .api
            .allowed_expansions
            .iter()
            .all(|name| entity.relationships.iter().any(|rel| &rel.name == name))
    {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            "allowed_expansions references an unknown relationship"
        );
        return Err(ConfigError::ValidationError);
    }

    for relationship in &entity.relationships {
        if !is_valid_id(&relationship.name)
            || is_reserved_relationship_segment(&relationship.name)
            || !names.insert(relationship.name.as_str())
        {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                relationship = %relationship.name,
                "relationship name is invalid, reserved, or duplicated"
            );
            return Err(ConfigError::ValidationError);
        }
        let target = entities.get(relationship.target.as_str()).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                relationship = %relationship.name,
                target = %relationship.target,
                "relationship target entity does not exist"
            );
            ConfigError::ValidationError
        })?;
        let target_table = tables
            .get(target.table.as_str())
            .expect("target entity table was validated earlier or will be validated in same pass");
        validate_relationship_fk(dataset, entity, table, relationship, target, target_table)?;
    }
    Ok(())
}

fn validate_relationship_fk(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    relationship: &EntityRelationshipConfig,
    target: &EntityConfig,
    target_table: &ResourceConfig,
) -> Result<(), ConfigError> {
    let (fk_table, pk_table) = match relationship.kind {
        RelationshipKind::BelongsTo => (table, target_table),
        RelationshipKind::HasMany | RelationshipKind::HasOne => (target_table, table),
    };
    let Some(fk_field) = field_by_name(fk_table, &relationship.foreign_key) else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            foreign_key = %relationship.foreign_key,
            "relationship foreign_key is missing on the expected table"
        );
        return Err(ConfigError::ValidationError);
    };
    let Some(pk_name) = pk_table.primary_key.as_deref() else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            target = %target.name,
            "relationship target/source table lacks primary_key"
        );
        return Err(ConfigError::ValidationError);
    };
    let Some(pk_field) = field_by_name(pk_table, pk_name) else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            primary_key = %pk_name,
            "relationship primary key column is missing"
        );
        return Err(ConfigError::ValidationError);
    };
    if fk_field.r#type != pk_field.r#type {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            foreign_key = %relationship.foreign_key,
            "relationship foreign_key type does not match primary key type"
        );
        return Err(ConfigError::ValidationError);
    }
    if relationship.kind == RelationshipKind::HasOne {
        tracing::warn!(
            code = "config.validation_warning",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            "has_one uniqueness cannot be statically proven from config"
        );
    }
    Ok(())
}

fn field_by_name<'a>(resource: &'a ResourceConfig, name: &str) -> Option<&'a FieldConfig> {
    resource
        .schema
        .fields
        .iter()
        .find(|field| field.name == name)
}

fn is_reserved_entity_segment(name: &str) -> bool {
    matches!(
        name,
        "catalog" | "admin" | "health" | "ready" | "openapi.json"
    )
}

fn is_reserved_relationship_segment(name: &str) -> bool {
    matches!(name, "aggregates" | "schema" | "verify" | "exports")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_regex_accepts_canonical() {
        assert!(is_valid_id("social_registry"));
        assert!(is_valid_id("a"));
        assert!(is_valid_id("a1_b2"));
    }

    #[test]
    fn id_regex_rejects_uppercase_or_leading_digit_or_dash() {
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("Social_registry"));
        assert!(!is_valid_id("1_social"));
        assert!(!is_valid_id("social-registry"));
        assert!(!is_valid_id("social registry"));
    }

    #[test]
    fn argon_phc_check_accepts_canonical_shape() {
        let sample = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHkxc2FsdA$Pv5b/uIqg+Z3KCJ7eqlEYUx8j7Rq3oKZxV/JTM6oRiE";
        assert!(is_argon2id_phc(sample));
    }

    #[test]
    fn argon_phc_check_rejects_other_algos_and_plain_text() {
        assert!(!is_argon2id_phc("not_an_argon_phc"));
        assert!(!is_argon2id_phc("$argon2i$..."));
        assert!(!is_argon2id_phc(""));
    }

    #[test]
    fn trusted_proxy_specs_accept_ips_and_cidrs() {
        assert!(is_trusted_proxy_spec("127.0.0.1"));
        assert!(is_trusted_proxy_spec("10.0.0.0/8"));
        assert!(is_trusted_proxy_spec("::1"));
        assert!(is_trusted_proxy_spec("2001:db8::/32"));
    }

    #[test]
    fn trusted_proxy_specs_reject_bad_values() {
        assert!(!is_trusted_proxy_spec(""));
        assert!(!is_trusted_proxy_spec("not-an-ip"));
        assert!(!is_trusted_proxy_spec("10.0.0.0/99"));
        assert!(!is_trusted_proxy_spec("2001:db8::/129"));
    }
}
