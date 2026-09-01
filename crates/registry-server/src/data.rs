// SPDX-License-Identifier: Apache-2.0

//! Structural data import and export planning against compiled authority.
//!
//! Planning and checkpoints do no I/O. Execution emits closed requests to a
//! caller-supplied authenticated HTTP transport, so imports and exports reuse
//! the ordinary API instead of inventing a second data-access path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime};
use uuid::Uuid;

use crate::contract::{
    valid_crs84_point, valid_decimal_value, valid_structured_value, FieldTypeSource, MutationMode,
    Operation,
};
use crate::model::{
    CompiledEntity, CompiledQueryKind, CompiledRegistry, CompiledStoredField, HttpMethod,
};

const DATA_API_VERSION: &str = "registry.registrystack.org/v1alpha1";
const IMPORT_CHECKPOINT_KIND: &str = "RegistryDataImportCheckpoint";
const EXPORT_CHECKPOINT_KIND: &str = "RegistryDataExportCheckpoint";
const CHUNK_ALGORITHM_VERSION: &str = "greedy-canonical-http-batch-v1";
const IDEMPOTENCY_DOMAIN: &str = "registry-data-import-chunk-v1";
const MAX_BINDING_BYTES: usize = 256;
const MAX_CURSOR_BYTES: usize = 16 * 1024;
/// Maximum canonical JSONL bytes accepted by one import plan.
pub const MAX_DATA_IMPORT_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_INPUT_ITEMS: usize = 1_000_000;
const MAX_PATCH_OPERATIONS: usize = 128;
/// Maximum response-body bytes accepted from one Registry data HTTP exchange.
pub const MAX_DATA_HTTP_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataHttpMethod {
    Get,
    Post,
}

/// One closed request for the ordinary Registry HTTP surface.
///
/// Authentication remains transport-owned so bearer material is never stored
/// in a data plan, checkpoint, error, or debug representation.
pub struct DataHttpRequest {
    method: DataHttpMethod,
    path_and_query: String,
    content_type: Option<&'static str>,
    idempotency_key: Option<String>,
    body: Vec<u8>,
}

impl fmt::Debug for DataHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataHttpRequest")
            .field("method", &self.method)
            .field("content_type", &self.content_type)
            .field("idempotency_key_present", &self.idempotency_key.is_some())
            .field("body_length", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl DataHttpRequest {
    pub fn method(&self) -> DataHttpMethod {
        self.method
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub fn content_type(&self) -> Option<&'static str> {
        self.content_type
    }

    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Bounded response returned by the transport after normal HTTP
/// authentication and authorization have completed.
pub struct DataHttpResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl fmt::Debug for DataHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataHttpResponse")
            .field("status", &self.status)
            .field("content_type_present", &self.content_type.is_some())
            .field("body_length", &self.body.len())
            .finish()
    }
}

impl DataHttpResponse {
    pub fn new(
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    ) -> Result<Self, DataError> {
        if !(100..=599).contains(&status)
            || body.len() > MAX_DATA_HTTP_RESPONSE_BYTES
            || content_type.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_BINDING_BYTES
                    || !value.is_ascii()
                    || value.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(DataError::InvalidResponse);
        }
        Ok(Self {
            status,
            content_type,
            body,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FieldValue<'a> {
    Json(&'a Value),
    #[cfg(feature = "runtime")]
    Text(&'a str),
}

/// The single no-I/O value/type rule used by import validation, mutations,
/// and PostgreSQL claim-boundary construction.
pub(crate) fn validate_field_value(value: FieldValue<'_>, field_type: &FieldTypeSource) -> bool {
    match value {
        FieldValue::Json(value) => validate_json_field_value(value, field_type),
        #[cfg(feature = "runtime")]
        FieldValue::Text(value) => validate_text_field_value(value, field_type),
    }
}

fn validate_json_field_value(value: &Value, field_type: &FieldTypeSource) -> bool {
    match field_type {
        FieldTypeSource::Boolean => value.is_boolean(),
        FieldTypeSource::Int64 => value.as_i64().is_some(),
        FieldTypeSource::Crs84Point { precision, bbox } => {
            valid_crs84_point(value, *precision, bbox.as_ref())
        }
        FieldTypeSource::Structured { max_bytes, schema } => {
            valid_structured_value(value, *max_bytes, schema)
        }
        _ => value
            .as_str()
            .is_some_and(|value| validate_text_field_value(value, field_type)),
    }
}

fn validate_text_field_value(value: &str, field_type: &FieldTypeSource) -> bool {
    match field_type {
        FieldTypeSource::Boolean => matches!(value, "true" | "false"),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => {
            let length = value.chars().count();
            length >= *min_length as usize && length <= *max_length as usize
        }
        FieldTypeSource::Text { max_length } => value.chars().count() <= *max_length as usize,
        FieldTypeSource::Int64 => value
            .parse::<i64>()
            .is_ok_and(|parsed| parsed.to_string() == value),
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } => valid_decimal_value(
            value,
            *precision,
            *scale,
            minimum.as_deref(),
            maximum.as_deref(),
        ),
        FieldTypeSource::Date => valid_iso_date(value),
        FieldTypeSource::Timestamp => OffsetDateTime::parse(value, &Rfc3339).is_ok(),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => valid_uuid(value),
        FieldTypeSource::VocabularyCode { values, .. } => {
            values.iter().any(|allowed| allowed == value)
        }
        FieldTypeSource::Crs84Point { precision, bbox } => parse_json_strict(value.as_bytes())
            .is_ok_and(|parsed| valid_crs84_point(&parsed, *precision, bbox.as_ref())),
        FieldTypeSource::Structured { max_bytes, schema } => parse_json_strict(value.as_bytes())
            .is_ok_and(|parsed| valid_structured_value(&parsed, *max_bytes, schema)),
    }
}

fn valid_iso_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<i32>() else {
        return false;
    };
    let Some(month) = value[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|month| Month::try_from(month).ok())
    else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    (1..=9999).contains(&year) && Date::from_calendar_date(year, month, day).is_ok()
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

fn valid_import_uuid(value: &str) -> bool {
    valid_uuid(value)
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.get_version_num() == 4)
}

fn valid_strong_etag(value: &str) -> bool {
    value.len() > 5
        && value.len() <= MAX_BINDING_BYTES
        && value.starts_with("\"rs-")
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataImportOperation {
    Create,
    Patch,
}

impl DataImportOperation {
    fn compiled(self) -> Operation {
        match self {
            Self::Create => Operation::Create,
            Self::Patch => Operation::Patch,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DataError {
    #[error("data authority binding is invalid")]
    InvalidBinding,
    #[error("data input is invalid")]
    InvalidInput,
    #[error("data item is invalid")]
    InvalidItem,
    #[error("one data item exceeds the compiled batch byte bound")]
    ItemTooLarge,
    #[error("data checkpoint does not match the active binding")]
    CheckpointMismatch,
    #[error("the Registry data transport is unavailable")]
    TransportUnavailable,
    #[error("the Registry data operation was refused")]
    OperationRefused,
    #[error("the Registry data response is invalid")]
    InvalidResponse,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DataChunk {
    index: u64,
    start_item: u64,
    end_item: u64,
    next_byte_offset: u64,
    canonical_body: Vec<u8>,
    digest: String,
    prefix_digest: String,
}

impl fmt::Debug for DataChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataChunk")
            .field("index", &self.index)
            .field("start_item", &self.start_item)
            .field("end_item", &self.end_item)
            .field("next_byte_offset", &self.next_byte_offset)
            .field("body_length", &self.canonical_body.len())
            .field("digest", &self.digest)
            .finish()
    }
}

impl DataChunk {
    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn item_range(&self) -> std::ops::Range<u64> {
        self.start_item..self.end_item
    }

    pub fn next_byte_offset(&self) -> u64 {
        self.next_byte_offset
    }

    /// Exact canonical body for the compiled HTTP batch operation.
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DataImportPlan {
    entity_id: String,
    operation: DataImportOperation,
    profile_id: String,
    input_digest: String,
    input_length: u64,
    item_count: u64,
    maximum_items: u16,
    maximum_bytes: u32,
    chunks: Vec<DataChunk>,
    route_path: String,
    response_fields: BTreeMap<String, (FieldTypeSource, bool)>,
}

impl fmt::Debug for DataImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataImportPlan")
            .field("operation", &self.operation)
            .field("input_length", &self.input_length)
            .field("item_count", &self.item_count)
            .field("maximum_items", &self.maximum_items)
            .field("maximum_bytes", &self.maximum_bytes)
            .field("chunk_count", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

impl DataImportPlan {
    pub fn from_jsonl(
        registry: &CompiledRegistry,
        entity_id: &str,
        operation: DataImportOperation,
        profile_id: &str,
        input: &[u8],
    ) -> Result<Self, DataError> {
        let (entity, maximum_items, maximum_bytes, route_path) =
            resolve_import_binding(registry, entity_id, operation, profile_id)?;
        if input.is_empty() || input.len() > MAX_DATA_IMPORT_INPUT_BYTES {
            return Err(DataError::InvalidInput);
        }
        let mut parsed = Vec::new();
        let mut offset = 0usize;
        for raw_line in input.split_inclusive(|byte| *byte == b'\n') {
            offset = offset
                .checked_add(raw_line.len())
                .ok_or(DataError::InvalidInput)?;
            let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() || parsed.len() >= MAX_INPUT_ITEMS {
                return Err(DataError::InvalidInput);
            }
            let value = parse_json_strict(line).map_err(|_| DataError::InvalidItem)?;
            let canonical_item = validate_item(entity, operation, profile_id, value)?;
            parsed.push((canonical_item, offset));
        }
        if parsed.is_empty() {
            return Err(DataError::InvalidInput);
        }
        let chunks = plan_chunks(input, &parsed, maximum_items, maximum_bytes)?;
        Ok(Self {
            entity_id: entity_id.to_owned(),
            operation,
            profile_id: profile_id.to_owned(),
            input_digest: sha256_hex(input),
            input_length: input.len() as u64,
            item_count: parsed.len() as u64,
            maximum_items,
            maximum_bytes,
            chunks,
            route_path,
            response_fields: entity.access_profiles[profile_id]
                .readable_fields
                .iter()
                .filter_map(|field_id| {
                    let stored = stored_field_by_id(entity, field_id)?;
                    let field = entity.fields.get(field_id)?;
                    Some((
                        stored.logical.api_name.clone(),
                        (field.field_type.clone(), field.required),
                    ))
                })
                .collect(),
        })
    }

    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn operation(&self) -> DataImportOperation {
        self.operation
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    pub fn input_length(&self) -> u64 {
        self.input_length
    }

    pub fn item_count(&self) -> u64 {
        self.item_count
    }

    pub fn maximum_items(&self) -> u16 {
        self.maximum_items
    }

    pub fn maximum_bytes(&self) -> u32 {
        self.maximum_bytes
    }

    pub fn chunks(&self) -> &[DataChunk] {
        &self.chunks
    }
}

fn resolve_import_binding<'a>(
    registry: &'a CompiledRegistry,
    entity_id: &str,
    operation: DataImportOperation,
    profile_id: &str,
) -> Result<(&'a CompiledEntity, u16, u32, String), DataError> {
    if !valid_binding(entity_id) || !valid_binding(profile_id) {
        return Err(DataError::InvalidBinding);
    }
    let entity = registry
        .entities()
        .get(entity_id)
        .ok_or(DataError::InvalidBinding)?;
    let batch = entity.batch.as_ref().ok_or(DataError::InvalidBinding)?;
    let profile = entity
        .access_profiles
        .get(profile_id)
        .ok_or(DataError::InvalidBinding)?;
    let operation = operation.compiled();
    let access_matches = |candidate: Operation| {
        registry.access().entries.iter().any(|entry| {
            entry.entity_id == entity_id
                && entry.operation == candidate
                && entry.profile_ids.contains(profile_id)
        })
    };
    let batch_route = registry.routes().routes.iter().find(|route| {
        route.entity_id == entity_id
            && route.operation == Operation::Batch
            && route.method == HttpMethod::Post
            && route.access_profiles.iter().any(|id| id == profile_id)
    });
    let item_route_matches = registry.routes().routes.iter().any(|route| {
        route.entity_id == entity_id
            && route.operation == operation
            && route.access_profiles.iter().any(|id| id == profile_id)
            && matches!(
                (operation, route.method),
                (Operation::Create, HttpMethod::Post) | (Operation::Patch, HttpMethod::Patch)
            )
    });
    if profile.anonymous
        || !profile.operations.contains(&Operation::Batch)
        || !profile.operations.contains(&operation)
        || !access_matches(Operation::Batch)
        || !access_matches(operation)
        || batch_route.is_none()
        || !item_route_matches
        || operation == Operation::Patch && entity.mutation_mode != MutationMode::Mutable
        || batch.maximum_items == 0
        || batch.maximum_bytes == 0
    {
        return Err(DataError::InvalidBinding);
    }
    Ok((
        entity,
        batch.maximum_items,
        batch.maximum_bytes,
        batch_route.expect("checked batch route").path.clone(),
    ))
}

fn validate_item(
    entity: &CompiledEntity,
    operation: DataImportOperation,
    profile_id: &str,
    value: Value,
) -> Result<Value, DataError> {
    let object = value.as_object().ok_or(DataError::InvalidItem)?;
    let profile = entity
        .access_profiles
        .get(profile_id)
        .ok_or(DataError::InvalidBinding)?;
    match operation {
        DataImportOperation::Create => {
            require_exact_keys(object, &["operation", "data"])?;
            if object.get("operation").and_then(Value::as_str) != Some("create") {
                return Err(DataError::InvalidItem);
            }
            let data = object
                .get("data")
                .and_then(Value::as_object)
                .ok_or(DataError::InvalidItem)?;
            validate_create_data(entity, profile_id, data)?;
        }
        DataImportOperation::Patch => {
            require_exact_keys(object, &["operation", "recordId", "ifMatch", "patch"])?;
            if object.get("operation").and_then(Value::as_str) != Some("patch")
                || !object
                    .get("recordId")
                    .and_then(Value::as_str)
                    .is_some_and(valid_uuid)
                || !object
                    .get("ifMatch")
                    .and_then(Value::as_str)
                    .is_some_and(valid_strong_etag)
            {
                return Err(DataError::InvalidItem);
            }
            let patch = object
                .get("patch")
                .and_then(Value::as_array)
                .ok_or(DataError::InvalidItem)?;
            validate_patch(entity, profile, patch)?;
        }
    }
    Ok(value)
}

fn validate_create_data(
    entity: &CompiledEntity,
    profile_id: &str,
    data: &Map<String, Value>,
) -> Result<(), DataError> {
    let profile = &entity.access_profiles[profile_id];
    if entity
        .stored_fields
        .iter()
        .any(|field| field.required && !data.contains_key(&field.logical.api_name))
    {
        return Err(DataError::InvalidItem);
    }
    for (api_name, value) in data {
        let stored = stored_field_by_api_name(entity, api_name).ok_or(DataError::InvalidItem)?;
        let field = entity
            .fields
            .get(&stored.logical.id)
            .ok_or(DataError::InvalidItem)?;
        if !profile.writable_fields.contains(&stored.logical.id)
            || value.is_null() && field.required
            || !value.is_null() && !validate_field_value(FieldValue::Json(value), &field.field_type)
        {
            return Err(DataError::InvalidItem);
        }
    }
    Ok(())
}

fn validate_patch(
    entity: &CompiledEntity,
    profile: &crate::contract::AccessProfileSource,
    patch: &[Value],
) -> Result<(), DataError> {
    if patch.is_empty() || patch.len() > MAX_PATCH_OPERATIONS {
        return Err(DataError::InvalidItem);
    }
    let mut mutated = false;
    for operation in patch {
        let operation = operation.as_object().ok_or(DataError::InvalidItem)?;
        let name = operation
            .get("op")
            .and_then(Value::as_str)
            .ok_or(DataError::InvalidItem)?;
        let path = operation
            .get("path")
            .and_then(Value::as_str)
            .ok_or(DataError::InvalidItem)?;
        let api_name = patch_field(path)?;
        let stored = stored_field_by_api_name(entity, &api_name).ok_or(DataError::InvalidItem)?;
        let field_id = &stored.logical.id;
        let field = entity.fields.get(field_id).ok_or(DataError::InvalidItem)?;
        match name {
            "add" | "replace" => {
                require_exact_keys(operation, &["op", "path", "value"])?;
                let value = &operation["value"];
                if !profile.writable_fields.contains(field_id)
                    || value.is_null() && field.required
                    || !value.is_null()
                        && !validate_field_value(FieldValue::Json(value), &field.field_type)
                {
                    return Err(DataError::InvalidItem);
                }
                mutated = true;
            }
            "remove" => {
                require_exact_keys(operation, &["op", "path"])?;
                if field.required || !profile.writable_fields.contains(field_id) {
                    return Err(DataError::InvalidItem);
                }
                mutated = true;
            }
            "test" => {
                require_exact_keys(operation, &["op", "path", "value"])?;
                let value = &operation["value"];
                if !profile.readable_fields.contains(field_id)
                    || !value.is_null()
                        && !validate_field_value(FieldValue::Json(value), &field.field_type)
                {
                    return Err(DataError::InvalidItem);
                }
            }
            _ => return Err(DataError::InvalidItem),
        }
    }
    if !mutated {
        return Err(DataError::InvalidItem);
    }
    Ok(())
}

fn patch_field(path: &str) -> Result<String, DataError> {
    let encoded = path.strip_prefix("/data/").ok_or(DataError::InvalidItem)?;
    if encoded.is_empty() || encoded.contains('/') {
        return Err(DataError::InvalidItem);
    }
    let mut decoded = String::new();
    let mut chars = encoded.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return Err(DataError::InvalidItem),
        }
    }
    if !valid_binding(&decoded) {
        return Err(DataError::InvalidItem);
    }
    Ok(decoded)
}

fn stored_field_by_api_name<'a>(
    entity: &'a CompiledEntity,
    api_name: &str,
) -> Option<&'a CompiledStoredField> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.api_name == api_name)
}

fn stored_field_by_id<'a>(
    entity: &'a CompiledEntity,
    field_id: &str,
) -> Option<&'a CompiledStoredField> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<(), DataError> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(DataError::InvalidItem);
    }
    Ok(())
}

fn plan_chunks(
    input: &[u8],
    parsed: &[(Value, usize)],
    maximum_items: u16,
    maximum_bytes: u32,
) -> Result<Vec<DataChunk>, DataError> {
    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < parsed.len() {
        let maximum_end = parsed
            .len()
            .min(start.saturating_add(maximum_items as usize));
        let mut accepted = None;
        for end in start + 1..=maximum_end {
            let items = parsed[start..end]
                .iter()
                .map(|(item, _)| item.clone())
                .collect::<Vec<_>>();
            let body =
                canonicalize_json(&json!({"items": items})).map_err(|_| DataError::InvalidItem)?;
            if body.len() > maximum_bytes as usize {
                break;
            }
            accepted = Some((end, body));
        }
        let Some((end, body)) = accepted else {
            return Err(DataError::ItemTooLarge);
        };
        let next_byte_offset = parsed[end - 1].1;
        chunks.push(DataChunk {
            index: chunks.len() as u64,
            start_item: start as u64,
            end_item: end as u64,
            next_byte_offset: next_byte_offset as u64,
            digest: sha256_hex(&body),
            prefix_digest: sha256_hex(&input[..next_byte_offset]),
            canonical_body: body,
        });
        start = end;
    }
    Ok(chunks)
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataImportCheckpoint {
    api_version: String,
    kind: String,
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    operation: DataImportOperation,
    profile_id: String,
    input_digest: String,
    input_length: u64,
    item_count: u64,
    chunk_algorithm_version: String,
    maximum_items: u16,
    maximum_bytes: u32,
    import_id: String,
    next_item_index: u64,
    next_byte_offset: u64,
    committed_prefix_digest: String,
    completed_chunk_count: u64,
    complete: bool,
}

impl fmt::Debug for DataImportCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataImportCheckpoint")
            .field("operation", &self.operation)
            .field("input_length", &self.input_length)
            .field("item_count", &self.item_count)
            .field("next_item_index", &self.next_item_index)
            .field("next_byte_offset", &self.next_byte_offset)
            .field("completed_chunk_count", &self.completed_chunk_count)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl DataImportCheckpoint {
    pub fn start(
        plan: &DataImportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
    ) -> Result<Self, DataError> {
        validate_checkpoint_binding(package_revision, schema_fingerprint)?;
        Ok(Self {
            api_version: DATA_API_VERSION.to_owned(),
            kind: IMPORT_CHECKPOINT_KIND.to_owned(),
            package_revision: package_revision.to_owned(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            entity_id: plan.entity_id.clone(),
            operation: plan.operation,
            profile_id: plan.profile_id.clone(),
            input_digest: plan.input_digest.clone(),
            input_length: plan.input_length,
            item_count: plan.item_count,
            chunk_algorithm_version: CHUNK_ALGORITHM_VERSION.to_owned(),
            maximum_items: plan.maximum_items,
            maximum_bytes: plan.maximum_bytes,
            import_id: Uuid::new_v4().to_string(),
            next_item_index: 0,
            next_byte_offset: 0,
            committed_prefix_digest: sha256_hex(&[]),
            completed_chunk_count: 0,
            complete: false,
        })
    }

    /// Restores a checkpoint only when its random import identity matches the
    /// identity retained by the executor for this import.
    pub fn from_json(
        bytes: &[u8],
        plan: &DataImportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
        expected_import_id: &str,
    ) -> Result<Self, DataError> {
        let value = parse_json_strict(bytes).map_err(|_| DataError::CheckpointMismatch)?;
        let checkpoint: Self =
            serde_json::from_value(value).map_err(|_| DataError::CheckpointMismatch)?;
        checkpoint.validate_resume(
            plan,
            package_revision,
            schema_fingerprint,
            expected_import_id,
        )?;
        Ok(checkpoint)
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, DataError> {
        canonicalize_json(&serde_json::to_value(self).map_err(|_| DataError::CheckpointMismatch)?)
            .map_err(|_| DataError::CheckpointMismatch)
    }

    /// Checks every import binding against the plan and executor-held import
    /// identity.
    pub fn validate_resume(
        &self,
        plan: &DataImportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
        expected_import_id: &str,
    ) -> Result<(), DataError> {
        validate_checkpoint_binding(package_revision, schema_fingerprint)
            .map_err(|_| DataError::CheckpointMismatch)?;
        if self.api_version != DATA_API_VERSION
            || self.kind != IMPORT_CHECKPOINT_KIND
            || self.package_revision != package_revision
            || self.schema_fingerprint != schema_fingerprint
            || self.entity_id != plan.entity_id
            || self.operation != plan.operation
            || self.profile_id != plan.profile_id
            || self.input_digest != plan.input_digest
            || self.input_length != plan.input_length
            || self.item_count != plan.item_count
            || self.chunk_algorithm_version != CHUNK_ALGORITHM_VERSION
            || self.maximum_items != plan.maximum_items
            || self.maximum_bytes != plan.maximum_bytes
            || !valid_import_uuid(&self.import_id)
            || self.import_id != expected_import_id
        {
            return Err(DataError::CheckpointMismatch);
        }
        let completed = usize::try_from(self.completed_chunk_count)
            .map_err(|_| DataError::CheckpointMismatch)?;
        if completed > plan.chunks.len() {
            return Err(DataError::CheckpointMismatch);
        }
        let (next_item_index, next_byte_offset, committed_prefix_digest) = if completed == 0 {
            (0, 0, sha256_hex(&[]))
        } else {
            let chunk = &plan.chunks[completed - 1];
            (
                chunk.end_item,
                chunk.next_byte_offset,
                chunk.prefix_digest.clone(),
            )
        };
        let complete = completed == plan.chunks.len();
        if self.next_item_index != next_item_index
            || self.next_byte_offset != next_byte_offset
            || self.committed_prefix_digest != committed_prefix_digest
            || self.complete != complete
        {
            return Err(DataError::CheckpointMismatch);
        }
        Ok(())
    }

    pub fn idempotency_key(
        &self,
        plan: &DataImportPlan,
        chunk_index: u64,
        package_revision: &str,
        schema_fingerprint: &str,
        expected_import_id: &str,
    ) -> Result<String, DataError> {
        self.validate_resume(
            plan,
            package_revision,
            schema_fingerprint,
            expected_import_id,
        )?;
        let chunk = plan
            .chunks
            .get(usize::try_from(chunk_index).map_err(|_| DataError::InvalidBinding)?)
            .ok_or(DataError::InvalidBinding)?;
        let binding = canonicalize_json(&json!({
            "domain": IDEMPOTENCY_DOMAIN,
            "importId": self.import_id,
            "inputDigest": self.input_digest,
            "chunkIndex": chunk_index,
            "chunkDigest": chunk.digest,
        }))
        .map_err(|_| DataError::InvalidBinding)?;
        Ok(format!("rs-data-v1-{}", sha256_hex(&binding)))
    }

    pub fn commit_chunk(
        &mut self,
        plan: &DataImportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
        chunk_index: u64,
        expected_import_id: &str,
    ) -> Result<(), DataError> {
        self.validate_resume(
            plan,
            package_revision,
            schema_fingerprint,
            expected_import_id,
        )?;
        if self.complete || chunk_index != self.completed_chunk_count {
            return Err(DataError::CheckpointMismatch);
        }
        let chunk = plan
            .chunks
            .get(usize::try_from(chunk_index).map_err(|_| DataError::CheckpointMismatch)?)
            .ok_or(DataError::CheckpointMismatch)?;
        self.next_item_index = chunk.end_item;
        self.next_byte_offset = chunk.next_byte_offset;
        self.committed_prefix_digest
            .clone_from(&chunk.prefix_digest);
        self.completed_chunk_count += 1;
        self.complete = self.completed_chunk_count == plan.chunks.len() as u64;
        Ok(())
    }

    pub fn next_item_index(&self) -> u64 {
        self.next_item_index
    }

    pub fn next_byte_offset(&self) -> u64 {
        self.next_byte_offset
    }

    pub fn completed_chunk_count(&self) -> u64 {
        self.completed_chunk_count
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn import_id(&self) -> &str {
        &self.import_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataImportProgress {
    chunk_index: u64,
    committed_items: u64,
    complete: bool,
}

impl DataImportProgress {
    pub fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    pub fn committed_items(&self) -> u64 {
        self.committed_items
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Execute exactly one bounded import chunk through the compiled HTTP batch
/// route. The dispatcher owns bearer admission and must send this request to
/// the ordinary authenticated Registry router.
pub async fn execute_import_chunk<Dispatch, DispatchFuture, DispatchError>(
    plan: &DataImportPlan,
    checkpoint: &mut DataImportCheckpoint,
    package_revision: &str,
    schema_fingerprint: &str,
    expected_import_id: &str,
    mut dispatch: Dispatch,
) -> Result<Option<DataImportProgress>, DataError>
where
    Dispatch: FnMut(DataHttpRequest) -> DispatchFuture,
    DispatchFuture: Future<Output = Result<DataHttpResponse, DispatchError>>,
{
    checkpoint.validate_resume(
        plan,
        package_revision,
        schema_fingerprint,
        expected_import_id,
    )?;
    if checkpoint.is_complete() {
        return Ok(None);
    }
    let chunk_index = checkpoint.completed_chunk_count();
    let chunk = plan
        .chunks
        .get(usize::try_from(chunk_index).map_err(|_| DataError::CheckpointMismatch)?)
        .ok_or(DataError::CheckpointMismatch)?;
    let idempotency_key = checkpoint.idempotency_key(
        plan,
        chunk_index,
        package_revision,
        schema_fingerprint,
        expected_import_id,
    )?;
    let request = DataHttpRequest {
        method: DataHttpMethod::Post,
        path_and_query: query_path(
            &plan.route_path,
            &[("accessProfile", plan.profile_id.as_str())],
        ),
        content_type: Some("application/json"),
        idempotency_key: Some(idempotency_key),
        body: chunk.canonical_body.clone(),
    };
    let response = dispatch(request)
        .await
        .map_err(|_| DataError::TransportUnavailable)?;
    validate_import_response(&response, plan, chunk)?;
    checkpoint.commit_chunk(
        plan,
        package_revision,
        schema_fingerprint,
        chunk_index,
        expected_import_id,
    )?;
    Ok(Some(DataImportProgress {
        chunk_index,
        committed_items: chunk.end_item - chunk.start_item,
        complete: checkpoint.is_complete(),
    }))
}

#[derive(Clone, Eq, PartialEq)]
pub struct DataExportPlan {
    entity_id: String,
    profile_id: String,
    requested_fields: Vec<String>,
    route_path: String,
    maximum_page_size: u16,
    response_fields: BTreeMap<String, (FieldTypeSource, bool)>,
}

impl fmt::Debug for DataExportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataExportPlan")
            .field("field_count", &self.requested_fields.len())
            .finish_non_exhaustive()
    }
}

impl DataExportPlan {
    pub fn from_compiled<I, S>(
        registry: &CompiledRegistry,
        entity_id: &str,
        profile_id: &str,
        requested_fields: I,
    ) -> Result<Self, DataError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if !valid_binding(entity_id) || !valid_binding(profile_id) {
            return Err(DataError::InvalidBinding);
        }
        let entity = registry
            .entities()
            .get(entity_id)
            .ok_or(DataError::InvalidBinding)?;
        let profile = entity
            .access_profiles
            .get(profile_id)
            .ok_or(DataError::InvalidBinding)?;
        let fields = requested_fields
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        if fields.is_empty()
            || fields.iter().any(|field| !valid_binding(field))
            || fields.iter().collect::<BTreeSet<_>>().len() != fields.len()
        {
            return Err(DataError::InvalidBinding);
        }
        let requested_api_names = fields.iter().cloned().collect::<BTreeSet<_>>();
        let requested = requested_api_names
            .iter()
            .map(|api_name| {
                entity
                    .stored_fields
                    .iter()
                    .map(|field| &field.logical)
                    .chain(entity.derived_fields.values().map(|field| &field.logical))
                    .find(|field| field.api_name == *api_name)
                    .map(|field| field.id.clone())
                    .ok_or(DataError::InvalidBinding)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_projection = profile.readable_fields.iter().cloned().collect::<Vec<_>>();
        let access_matches = registry.access().entries.iter().any(|entry| {
            entry.entity_id == entity_id
                && entry.operation == Operation::List
                && entry.profile_ids.contains(profile_id)
        });
        let route = registry.routes().routes.iter().find(|route| {
            route.entity_id == entity_id
                && route.operation == Operation::List
                && route.method == HttpMethod::Get
                && route.query_kind == Some(CompiledQueryKind::List)
                && route.access_profiles.iter().any(|id| id == profile_id)
        });
        let query = route.and_then(|route| {
            registry.queries().operations.iter().find(|query| {
                query.entity_id == entity_id
                    && query.profile_id == profile_id
                    && query.kind == CompiledQueryKind::List
                    && query.route_id == route.id
                    && query.projection_fields == expected_projection
                    && requested
                        .iter()
                        .all(|field| query.projection_fields.contains(field))
            })
        });
        if profile.anonymous
            || !profile.allow_data_export
            || !profile.operations.contains(&Operation::List)
            || profile.readable_fields.is_empty()
            || !requested.is_subset(&profile.readable_fields)
            || !access_matches
            || query.is_none()
        {
            return Err(DataError::InvalidBinding);
        }
        let response_fields = requested_api_names
            .iter()
            .map(|api_name| {
                if let Some(field) = stored_field_by_api_name(entity, api_name) {
                    return (
                        api_name.clone(),
                        (field.logical.field_type.clone(), field.required),
                    );
                }
                let field = entity
                    .derived_fields
                    .values()
                    .find(|field| field.logical.api_name == *api_name)
                    .expect("requested fields were resolved against compiled data fields");
                (api_name.clone(), (field.logical.field_type.clone(), false))
            })
            .collect();
        Ok(Self {
            entity_id: entity_id.to_owned(),
            profile_id: profile_id.to_owned(),
            requested_fields: requested_api_names.into_iter().collect(),
            route_path: route.expect("checked list route").path.clone(),
            maximum_page_size: query.expect("checked list query").max_page_size,
            response_fields,
        })
    }

    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn requested_fields(&self) -> &[String] {
        &self.requested_fields
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataExportCheckpoint {
    api_version: String,
    kind: String,
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    operation: Operation,
    profile_id: String,
    requested_fields: Vec<String>,
    output_length: u64,
    output_prefix_digest: String,
    record_count: u64,
    completed_page_count: u64,
    next_cursor: Option<String>,
    complete: bool,
}

struct DataExportPage<'a> {
    prior_output_prefix: &'a [u8],
    output_prefix: &'a [u8],
    added_record_count: u64,
    next_cursor: Option<String>,
}

impl fmt::Debug for DataExportPage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataExportPage")
            .field("prior_output_length", &self.prior_output_prefix.len())
            .field("output_length", &self.output_prefix.len())
            .field("added_record_count", &self.added_record_count)
            .field("cursor_present", &self.next_cursor.is_some())
            .finish()
    }
}

impl<'a> DataExportPage<'a> {
    fn new(
        prior_output_prefix: &'a [u8],
        output_prefix: &'a [u8],
        added_record_count: u64,
        next_cursor: Option<String>,
    ) -> Result<Self, DataError> {
        let prior_record_count = canonical_jsonl_record_count(prior_output_prefix)?;
        let output_record_count = canonical_jsonl_record_count(output_prefix)?;
        if !output_prefix.starts_with(prior_output_prefix)
            || output_record_count
                != prior_record_count
                    .checked_add(added_record_count)
                    .ok_or(DataError::CheckpointMismatch)?
            || invalid_cursor(next_cursor.as_deref())
        {
            return Err(DataError::CheckpointMismatch);
        }
        Ok(Self {
            prior_output_prefix,
            output_prefix,
            added_record_count,
            next_cursor,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
enum DataExportContinuation {
    Initial,
    Next(String),
    Complete,
}

/// Executor-held proof of the last HTTP page observed for an export.
///
/// Fields and constructors are private. A checkpoint file alone therefore
/// cannot create continuation or terminal authority by deleting its cursor or
/// changing `complete`.
#[derive(Clone, Eq, PartialEq)]
pub struct DataExportResumeState {
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    profile_id: String,
    requested_fields: Vec<String>,
    output_length: u64,
    output_prefix_digest: String,
    record_count: u64,
    completed_page_count: u64,
    continuation: DataExportContinuation,
}

impl fmt::Debug for DataExportResumeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataExportResumeState")
            .field("output_length", &self.output_length)
            .field("record_count", &self.record_count)
            .field("completed_page_count", &self.completed_page_count)
            .field(
                "continuation",
                &match &self.continuation {
                    DataExportContinuation::Initial => "initial",
                    DataExportContinuation::Next(_) => "next",
                    DataExportContinuation::Complete => "complete",
                },
            )
            .finish_non_exhaustive()
    }
}

impl DataExportResumeState {
    fn initial(plan: &DataExportPlan, package_revision: &str, schema_fingerprint: &str) -> Self {
        Self {
            package_revision: package_revision.to_owned(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            entity_id: plan.entity_id.clone(),
            profile_id: plan.profile_id.clone(),
            requested_fields: plan.requested_fields.clone(),
            output_length: 0,
            output_prefix_digest: sha256_hex(&[]),
            record_count: 0,
            completed_page_count: 0,
            continuation: DataExportContinuation::Initial,
        }
    }

    fn next(
        &self,
        output_prefix: &[u8],
        record_count: u64,
        completed_page_count: u64,
        next_cursor: Option<String>,
    ) -> Self {
        Self {
            package_revision: self.package_revision.clone(),
            schema_fingerprint: self.schema_fingerprint.clone(),
            entity_id: self.entity_id.clone(),
            profile_id: self.profile_id.clone(),
            requested_fields: self.requested_fields.clone(),
            output_length: output_prefix.len() as u64,
            output_prefix_digest: sha256_hex(output_prefix),
            record_count,
            completed_page_count,
            continuation: match next_cursor {
                Some(cursor) => DataExportContinuation::Next(cursor),
                None => DataExportContinuation::Complete,
            },
        }
    }

    fn next_cursor(&self) -> Option<&str> {
        match &self.continuation {
            DataExportContinuation::Next(cursor) => Some(cursor),
            DataExportContinuation::Initial | DataExportContinuation::Complete => None,
        }
    }

    fn is_complete(&self) -> bool {
        self.continuation == DataExportContinuation::Complete
    }
}

impl fmt::Debug for DataExportCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataExportCheckpoint")
            .field("operation", &self.operation)
            .field("field_count", &self.requested_fields.len())
            .field("output_length", &self.output_length)
            .field("record_count", &self.record_count)
            .field("cursor_present", &self.next_cursor.is_some())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl DataExportCheckpoint {
    pub fn start(
        plan: &DataExportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
    ) -> Result<(Self, DataExportResumeState), DataError> {
        validate_checkpoint_binding(package_revision, schema_fingerprint)?;
        let checkpoint = Self {
            api_version: DATA_API_VERSION.to_owned(),
            kind: EXPORT_CHECKPOINT_KIND.to_owned(),
            package_revision: package_revision.to_owned(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            entity_id: plan.entity_id.clone(),
            operation: Operation::List,
            profile_id: plan.profile_id.clone(),
            requested_fields: plan.requested_fields.clone(),
            output_length: 0,
            output_prefix_digest: sha256_hex(&[]),
            record_count: 0,
            completed_page_count: 0,
            next_cursor: None,
            complete: false,
        };
        Ok((
            checkpoint,
            DataExportResumeState::initial(plan, package_revision, schema_fingerprint),
        ))
    }

    /// Restores a checkpoint only when its complete state matches the opaque
    /// state produced by the executor after the last observed HTTP page.
    pub fn from_json(
        bytes: &[u8],
        plan: &DataExportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
        output_prefix: &[u8],
        resume_state: &DataExportResumeState,
    ) -> Result<Self, DataError> {
        let value = parse_json_strict(bytes).map_err(|_| DataError::CheckpointMismatch)?;
        let checkpoint: Self =
            serde_json::from_value(value).map_err(|_| DataError::CheckpointMismatch)?;
        checkpoint.validate_resume(
            plan,
            package_revision,
            schema_fingerprint,
            output_prefix,
            resume_state,
        )?;
        Ok(checkpoint)
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, DataError> {
        canonicalize_json(&serde_json::to_value(self).map_err(|_| DataError::CheckpointMismatch)?)
            .map_err(|_| DataError::CheckpointMismatch)
    }

    /// Checks filesystem output structurally and binds cursor and terminal
    /// state to the last executor-observed HTTP response.
    pub fn validate_resume(
        &self,
        plan: &DataExportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
        output_prefix: &[u8],
        resume_state: &DataExportResumeState,
    ) -> Result<(), DataError> {
        validate_checkpoint_binding(package_revision, schema_fingerprint)
            .map_err(|_| DataError::CheckpointMismatch)?;
        let record_count = canonical_jsonl_record_count(output_prefix)?;
        if self.api_version != DATA_API_VERSION
            || self.kind != EXPORT_CHECKPOINT_KIND
            || self.package_revision != package_revision
            || self.schema_fingerprint != schema_fingerprint
            || self.entity_id != plan.entity_id
            || self.operation != Operation::List
            || self.profile_id != plan.profile_id
            || self.requested_fields != plan.requested_fields
            || self.output_length != output_prefix.len() as u64
            || self.output_prefix_digest != sha256_hex(output_prefix)
            || self.record_count != record_count
            || self.completed_page_count != resume_state.completed_page_count
            || resume_state.package_revision != package_revision
            || resume_state.schema_fingerprint != schema_fingerprint
            || resume_state.entity_id != plan.entity_id
            || resume_state.profile_id != plan.profile_id
            || resume_state.requested_fields != plan.requested_fields
            || resume_state.output_length != output_prefix.len() as u64
            || resume_state.output_prefix_digest != sha256_hex(output_prefix)
            || resume_state.record_count != record_count
            || self.next_cursor.as_deref() != resume_state.next_cursor()
            || self.complete != resume_state.is_complete()
            || matches!(&resume_state.continuation, DataExportContinuation::Initial)
                && (self.output_length != 0
                    || self.record_count != 0
                    || self.completed_page_count != 0
                    || self.next_cursor.is_some()
                    || self.complete)
            || !matches!(&resume_state.continuation, DataExportContinuation::Initial)
                && self.completed_page_count == 0
            || self.complete && self.next_cursor.is_some()
            || invalid_cursor(self.next_cursor.as_deref())
            || invalid_cursor(resume_state.next_cursor())
        {
            return Err(DataError::CheckpointMismatch);
        }
        Ok(())
    }

    /// Records a page only after the executor checked the HTTP response.
    fn record_page(
        &mut self,
        plan: &DataExportPlan,
        package_revision: &str,
        schema_fingerprint: &str,
        resume_state: &DataExportResumeState,
        page: DataExportPage<'_>,
    ) -> Result<DataExportResumeState, DataError> {
        self.validate_resume(
            plan,
            package_revision,
            schema_fingerprint,
            page.prior_output_prefix,
            resume_state,
        )?;
        let record_count = canonical_jsonl_record_count(page.output_prefix)?;
        if self.complete || invalid_cursor(page.next_cursor.as_deref()) {
            return Err(DataError::CheckpointMismatch);
        }
        self.output_length = page.output_prefix.len() as u64;
        self.output_prefix_digest = sha256_hex(page.output_prefix);
        self.record_count = record_count;
        self.completed_page_count = self
            .completed_page_count
            .checked_add(1)
            .ok_or(DataError::CheckpointMismatch)?;
        self.complete = page.next_cursor.is_none();
        self.next_cursor.clone_from(&page.next_cursor);
        Ok(resume_state.next(
            page.output_prefix,
            record_count,
            self.completed_page_count,
            page.next_cursor,
        ))
    }

    pub fn output_length(&self) -> u64 {
        self.output_length
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

pub struct DataExportProgress {
    output_prefix: Vec<u8>,
    resume_state: DataExportResumeState,
    added_record_count: u64,
    complete: bool,
}

impl fmt::Debug for DataExportProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataExportProgress")
            .field("output_length", &self.output_prefix.len())
            .field("cursor_present", &self.resume_state.next_cursor().is_some())
            .field("added_record_count", &self.added_record_count)
            .field("complete", &self.complete)
            .finish()
    }
}

impl DataExportProgress {
    pub fn output_prefix(&self) -> &[u8] {
        &self.output_prefix
    }

    pub fn trusted_next_cursor(&self) -> Option<&str> {
        self.resume_state.next_cursor()
    }

    pub fn resume_state(&self) -> &DataExportResumeState {
        &self.resume_state
    }

    pub fn added_record_count(&self) -> u64 {
        self.added_record_count
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn into_parts(self) -> (Vec<u8>, DataExportResumeState) {
        (self.output_prefix, self.resume_state)
    }
}

/// Execute exactly one bounded export page through the compiled HTTP list
/// route. Continuation and terminal state come only from the opaque state
/// produced after the last executor-observed response.
pub async fn execute_export_page<Dispatch, DispatchFuture, DispatchError>(
    plan: &DataExportPlan,
    checkpoint: &mut DataExportCheckpoint,
    package_revision: &str,
    schema_fingerprint: &str,
    prior_output_prefix: &[u8],
    resume_state: &DataExportResumeState,
    mut dispatch: Dispatch,
) -> Result<Option<DataExportProgress>, DataError>
where
    Dispatch: FnMut(DataHttpRequest) -> DispatchFuture,
    DispatchFuture: Future<Output = Result<DataHttpResponse, DispatchError>>,
{
    checkpoint.validate_resume(
        plan,
        package_revision,
        schema_fingerprint,
        prior_output_prefix,
        resume_state,
    )?;
    if checkpoint.is_complete() {
        return Err(DataError::CheckpointMismatch);
    }
    let fields = plan.requested_fields.join(",");
    let page_size = plan.maximum_page_size.to_string();
    let path_and_query = if let Some(cursor) = resume_state.next_cursor() {
        query_path(
            &plan.route_path,
            &[
                ("accessProfile", plan.profile_id.as_str()),
                ("$skiptoken", cursor),
            ],
        )
    } else {
        query_path(
            &plan.route_path,
            &[
                ("accessProfile", plan.profile_id.as_str()),
                ("$select", fields.as_str()),
                ("$top", page_size.as_str()),
            ],
        )
    };
    let response = dispatch(DataHttpRequest {
        method: DataHttpMethod::Get,
        path_and_query,
        content_type: None,
        idempotency_key: None,
        body: Vec::new(),
    })
    .await
    .map_err(|_| DataError::TransportUnavailable)?;
    let (records, next_cursor) = validate_export_response(&response, plan)?;
    if resume_state
        .next_cursor()
        .is_some_and(|prior| next_cursor.as_deref() == Some(prior))
    {
        return Err(DataError::InvalidResponse);
    }
    let mut output_prefix = Vec::with_capacity(
        prior_output_prefix
            .len()
            .checked_add(response.body.len())
            .ok_or(DataError::InvalidResponse)?,
    );
    output_prefix.extend_from_slice(prior_output_prefix);
    for record in &records {
        output_prefix
            .extend_from_slice(&canonicalize_json(record).map_err(|_| DataError::InvalidResponse)?);
        output_prefix.push(b'\n');
    }
    let added_record_count =
        u64::try_from(records.len()).map_err(|_| DataError::InvalidResponse)?;
    let page = DataExportPage::new(
        prior_output_prefix,
        &output_prefix,
        added_record_count,
        next_cursor.clone(),
    )?;
    let resume_state = checkpoint.record_page(
        plan,
        package_revision,
        schema_fingerprint,
        resume_state,
        page,
    )?;
    Ok(Some(DataExportProgress {
        output_prefix,
        resume_state,
        added_record_count,
        complete: checkpoint.is_complete(),
    }))
}

fn validate_import_response(
    response: &DataHttpResponse,
    plan: &DataImportPlan,
    chunk: &DataChunk,
) -> Result<(), DataError> {
    require_success_json(response)?;
    let value = parse_canonical_response(&response.body)?;
    let object = value.as_object().ok_or(DataError::InvalidResponse)?;
    require_exact_keys(object, &["results", "snapshot"]).map_err(|_| DataError::InvalidResponse)?;
    crate::history_reference::SnapshotReference::parse(
        object["snapshot"]
            .as_str()
            .ok_or(DataError::InvalidResponse)?,
    )
    .map_err(|_| DataError::InvalidResponse)?;
    let results = object["results"]
        .as_array()
        .ok_or(DataError::InvalidResponse)?;
    let submitted = parse_json_strict(&chunk.canonical_body)
        .map_err(|_| DataError::InvalidResponse)?["items"]
        .as_array()
        .ok_or(DataError::InvalidResponse)?
        .clone();
    if results.len() != submitted.len() || results.len() > usize::from(plan.maximum_items) {
        return Err(DataError::InvalidResponse);
    }
    for (result, submitted) in results.iter().zip(&submitted) {
        let result = result.as_object().ok_or(DataError::InvalidResponse)?;
        require_exact_keys(result, &["operation", "id", "revision", "etag", "data"])
            .map_err(|_| DataError::InvalidResponse)?;
        let expected_operation = submitted["operation"]
            .as_str()
            .ok_or(DataError::InvalidResponse)?;
        if result["operation"].as_str() != Some(expected_operation)
            || !result["id"].as_str().is_some_and(valid_uuid)
            || result["revision"].as_u64().is_none_or(|value| value == 0)
            || !result["etag"].as_str().is_some_and(valid_strong_etag)
        {
            return Err(DataError::InvalidResponse);
        }
        if expected_operation == "patch" && result["id"].as_str() != submitted["recordId"].as_str()
        {
            return Err(DataError::InvalidResponse);
        }
        let data = result["data"]
            .as_object()
            .ok_or(DataError::InvalidResponse)?;
        if !valid_response_data(data, &plan.response_fields) {
            return Err(DataError::InvalidResponse);
        }
    }
    Ok(())
}

fn validate_export_response(
    response: &DataHttpResponse,
    plan: &DataExportPlan,
) -> Result<(Vec<Value>, Option<String>), DataError> {
    require_success_json(response)?;
    let value = parse_canonical_response(&response.body)?;
    let object = value.as_object().ok_or(DataError::InvalidResponse)?;
    if !(object.len() == 2 || object.len() == 3)
        || !object.contains_key("items")
        || !object.contains_key("pageInfo")
        || (object.len() == 3 && !object.contains_key("count"))
    {
        return Err(DataError::InvalidResponse);
    }
    let items = object["items"]
        .as_array()
        .ok_or(DataError::InvalidResponse)?;
    if items.len() > usize::from(plan.maximum_page_size) {
        return Err(DataError::InvalidResponse);
    }
    if object.get("count").is_some_and(|count| {
        count
            .as_u64()
            .is_none_or(|count| count < items.len() as u64)
    }) {
        return Err(DataError::InvalidResponse);
    }
    let page_info = object["pageInfo"]
        .as_object()
        .ok_or(DataError::InvalidResponse)?;
    require_exact_keys(page_info, &["nextCursor"]).map_err(|_| DataError::InvalidResponse)?;
    let next_cursor = match &page_info["nextCursor"] {
        Value::Null => None,
        Value::String(value) if !invalid_cursor(Some(value)) => Some(value.clone()),
        _ => return Err(DataError::InvalidResponse),
    };
    if items.is_empty() && next_cursor.is_some() {
        return Err(DataError::InvalidResponse);
    }
    for item in items {
        let item = item.as_object().ok_or(DataError::InvalidResponse)?;
        require_exact_keys(item, &["id", "revision", "data"])
            .map_err(|_| DataError::InvalidResponse)?;
        if !item["id"].as_str().is_some_and(valid_uuid)
            || item["revision"].as_u64().is_none_or(|value| value == 0)
        {
            return Err(DataError::InvalidResponse);
        }
        let data = item["data"].as_object().ok_or(DataError::InvalidResponse)?;
        if !valid_response_data(data, &plan.response_fields) {
            return Err(DataError::InvalidResponse);
        }
    }
    Ok((items.clone(), next_cursor))
}

fn valid_response_data(
    data: &Map<String, Value>,
    fields: &BTreeMap<String, (FieldTypeSource, bool)>,
) -> bool {
    data.len() == fields.len()
        && fields.iter().all(|(field_id, (field_type, required))| {
            data.get(field_id).is_some_and(|value| {
                if value.is_null() {
                    !required
                } else {
                    validate_field_value(FieldValue::Json(value), field_type)
                }
            })
        })
}

fn require_success_json(response: &DataHttpResponse) -> Result<(), DataError> {
    if response.status != 200 {
        return Err(DataError::OperationRefused);
    }
    if response.content_type.as_deref() != Some("application/json") {
        return Err(DataError::InvalidResponse);
    }
    Ok(())
}

fn parse_canonical_response(bytes: &[u8]) -> Result<Value, DataError> {
    let value = parse_json_strict(bytes).map_err(|_| DataError::InvalidResponse)?;
    if canonicalize_json(&value).map_err(|_| DataError::InvalidResponse)? != bytes {
        return Err(DataError::InvalidResponse);
    }
    Ok(value)
}

fn query_path(path: &str, parameters: &[(&str, &str)]) -> String {
    let mut result = String::with_capacity(path.len() + 64);
    result.push_str(path);
    for (index, (name, value)) in parameters.iter().enumerate() {
        result.push(if index == 0 { '?' } else { '&' });
        result.push_str(name);
        result.push('=');
        percent_encode_query_value(value, &mut result);
    }
    result
}

fn percent_encode_query_value(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn validate_checkpoint_binding(
    package_revision: &str,
    schema_fingerprint: &str,
) -> Result<(), DataError> {
    if !valid_binding(package_revision) || !valid_binding(schema_fingerprint) {
        return Err(DataError::InvalidBinding);
    }
    Ok(())
}

fn invalid_cursor(cursor: Option<&str>) -> bool {
    cursor.is_some_and(|cursor| {
        cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control)
    })
}

fn canonical_jsonl_record_count(bytes: &[u8]) -> Result<u64, DataError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if !bytes.ends_with(b"\n") {
        return Err(DataError::CheckpointMismatch);
    }
    let mut record_count = 0u64;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() || line.ends_with(b"\r") {
            return Err(DataError::CheckpointMismatch);
        }
        let record = parse_json_strict(line).map_err(|_| DataError::CheckpointMismatch)?;
        if !record.is_object()
            || canonicalize_json(&record).map_err(|_| DataError::CheckpointMismatch)? != line
        {
            return Err(DataError::CheckpointMismatch);
        }
        record_count = record_count
            .checked_add(1)
            .ok_or(DataError::CheckpointMismatch)?;
    }
    Ok(record_count)
}

fn valid_binding(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_BINDING_BYTES && !value.chars().any(char::is_control)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
