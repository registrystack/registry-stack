//! Open Registry Record v1 response types shared across Registry products.
//!
//! Decoding is deliberately representation-aware. Context identifiers are
//! validated as inert strings and are never resolved, fetched, or interpreted
//! as authority.

mod strict_json;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use url::Url;

/// The stable Registry Record v1 profile identifier.
pub const REGISTRY_RECORD_PROFILE_IDENTIFIER: &str =
    "https://id.registrystack.org/profiles/registry-record/v1";

/// The stable Registry Record v1 schema identifier.
pub const REGISTRY_RECORD_SCHEMA_IDENTIFIER: &str =
    "https://id.registrystack.org/schemas/registry-record/v1";

/// The locally pinned shared JSON-LD context identifier.
pub const REGISTRY_RECORD_CONTEXT_IDENTIFIER: &str =
    "https://id.registrystack.org/contexts/registry-record/v1";

const INFRASTRUCTURE_MEMBERS: &[&str] = &[
    "data",
    "items",
    "pageInfo",
    "meta",
    "registryIdentifier",
    "datasetIdentifier",
    "entityTypeIdentifier",
    "recordIdentifier",
    "revisionIdentifier",
    "domainData",
    "nextCursor",
];

/// The expected wire representation for a Registry Record v1 response.
///
/// The distinction between the two JSON-LD variants keeps an exact shared
/// context response, as emitted by Registry Server, separate from a product
/// composition, as emitted by Registry Relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryRecordRepresentation {
    /// `application/json`, which must not contain `@context`.
    Json,
    /// `application/ld+json` with the exact scalar shared context identifier.
    JsonLdSharedContext,
    /// `application/ld+json` with the shared context first and one or more
    /// unique absolute HTTPS product context identifiers after it.
    JsonLdProductComposition,
}

/// A validated Registry Record JSON-LD context.
///
/// An empty `product_contexts` list represents the exact scalar shared
/// context. A non-empty list represents the ordered product composition. The
/// fields remain private so an invalid context cannot be manufactured through
/// this type's public API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryRecordJsonLdContext {
    product_contexts: Vec<String>,
}

impl RegistryRecordJsonLdContext {
    /// Returns `true` for the exact scalar shared context form.
    #[must_use]
    pub fn is_shared_only(&self) -> bool {
        self.product_contexts.is_empty()
    }

    /// Returns the ordered product context identifiers following the shared
    /// context. The shared identifier itself is available as
    /// [`REGISTRY_RECORD_CONTEXT_IDENTIFIER`].
    #[must_use]
    pub fn product_contexts(&self) -> &[String] {
        &self.product_contexts
    }
}

impl Serialize for RegistryRecordJsonLdContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.product_contexts.is_empty() {
            return serializer.serialize_str(REGISTRY_RECORD_CONTEXT_IDENTIFIER);
        }

        let contexts = std::iter::once(REGISTRY_RECORD_CONTEXT_IDENTIFIER)
            .chain(self.product_contexts.iter().map(String::as_str))
            .collect::<Vec<_>>();
        contexts.serialize(serializer)
    }
}

/// One Registry Record v1 member.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecord {
    pub record_identifier: String,
    pub revision_identifier: String,
    pub domain_data: BTreeMap<String, Value>,
    /// Product-owned record members, retained without interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// The homogeneous Registry, primary dataset, and entity context shared by a
/// single response or every member of a collection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecordMeta {
    pub registry_identifier: String,
    pub dataset_identifier: String,
    pub entity_type_identifier: String,
    /// Product-owned response metadata, retained without interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Cursor state for one Registry Record v1 collection.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecordPageInfo {
    pub next_cursor: Option<String>,
    /// Product-owned collection pagination members, retained without
    /// interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One Registry Record v1 single-response envelope.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecordSingleResponse {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub json_ld_context: Option<RegistryRecordJsonLdContext>,
    pub data: RegistryRecord,
    pub meta: RegistryRecordMeta,
    /// Product-owned response members, retained without interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One homogeneous Registry Record v1 collection-response envelope.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecordCollectionResponse {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub json_ld_context: Option<RegistryRecordJsonLdContext>,
    pub items: Vec<RegistryRecord>,
    pub page_info: RegistryRecordPageInfo,
    pub meta: RegistryRecordMeta,
    /// Product-owned collection response members, retained without
    /// interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// A validated single or homogeneous collection Registry Record v1 response.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RegistryRecordResponse {
    Single(RegistryRecordSingleResponse),
    Collection(RegistryRecordCollectionResponse),
}

impl RegistryRecordResponse {
    /// Decodes a response from JSON bytes under an explicit representation
    /// contract.
    ///
    /// This function performs no context resolution or other I/O.
    pub fn from_slice(
        bytes: &[u8],
        representation: RegistryRecordRepresentation,
    ) -> Result<Self, RegistryRecordDecodeError> {
        let value =
            crate::strict_json::from_slice(bytes).map_err(|_| RegistryRecordDecodeError::Json)?;
        Self::from_value(value, representation)
    }

    /// Decodes an already parsed JSON value under an explicit representation
    /// contract.
    ///
    /// Product extensions are retained as inert [`Value`] members. They may
    /// not introduce nested JSON-LD contexts or relocate profile
    /// infrastructure.
    pub fn from_value(
        value: Value,
        representation: RegistryRecordRepresentation,
    ) -> Result<Self, RegistryRecordDecodeError> {
        let mut response = require_object(value, "response")?;
        let context = decode_context(response.remove("@context"), representation)?;
        reject_nested_context_in_map(&response, "response")?;

        let is_single = response.contains_key("data");
        let is_collection = response.contains_key("items") || response.contains_key("pageInfo");
        if is_single == is_collection {
            return Err(invalid(
                "response must use exactly one Registry Record v1 envelope",
            ));
        }

        if is_single {
            reject_misplaced_infrastructure(&response, &["data", "meta"], "response")?;
            let data = decode_record(take_required(&mut response, "data", "response")?, "data")?;
            let meta = decode_meta(take_required(&mut response, "meta", "response")?)?;
            return Ok(Self::Single(RegistryRecordSingleResponse {
                json_ld_context: context,
                data,
                meta,
                extensions: into_extensions(response),
            }));
        }

        reject_misplaced_infrastructure(&response, &["items", "pageInfo", "meta"], "response")?;
        let items = match take_required(&mut response, "items", "response")? {
            Value::Array(items) => items,
            _ => return Err(invalid("response.items must be an array")),
        };
        let items = items
            .into_iter()
            .enumerate()
            .map(|(index, item)| decode_record(item, &format!("items[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let page_info = decode_page_info(take_required(&mut response, "pageInfo", "response")?)?;
        let meta = decode_meta(take_required(&mut response, "meta", "response")?)?;
        Ok(Self::Collection(RegistryRecordCollectionResponse {
            json_ld_context: context,
            items,
            page_info,
            meta,
            extensions: into_extensions(response),
        }))
    }

    /// Returns the response's JSON-LD context, when the representation has
    /// one.
    #[must_use]
    pub fn json_ld_context(&self) -> Option<&RegistryRecordJsonLdContext> {
        match self {
            Self::Single(response) => response.json_ld_context.as_ref(),
            Self::Collection(response) => response.json_ld_context.as_ref(),
        }
    }

    /// Returns the response-level homogeneous Registry Record context.
    #[must_use]
    pub fn meta(&self) -> &RegistryRecordMeta {
        match self {
            Self::Single(response) => &response.meta,
            Self::Collection(response) => &response.meta,
        }
    }
}

/// A value-free Registry Record profile decoding failure.
///
/// The variants deliberately omit parser messages, member names, paths, and
/// response values so callers can safely log the error at a trust boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistryRecordDecodeError {
    #[error("Registry Record response is not valid JSON")]
    Json,
    #[error("Registry Record response does not conform")]
    Profile,
}

fn decode_context(
    value: Option<Value>,
    representation: RegistryRecordRepresentation,
) -> Result<Option<RegistryRecordJsonLdContext>, RegistryRecordDecodeError> {
    match representation {
        RegistryRecordRepresentation::Json => {
            if value.is_some() {
                return Err(invalid("ordinary JSON must not contain @context"));
            }
            Ok(None)
        }
        RegistryRecordRepresentation::JsonLdSharedContext => {
            if value.as_ref().and_then(Value::as_str) != Some(REGISTRY_RECORD_CONTEXT_IDENTIFIER) {
                return Err(invalid(
                    "shared-context JSON-LD must use the exact scalar Registry Record context",
                ));
            }
            Ok(Some(RegistryRecordJsonLdContext {
                product_contexts: Vec::new(),
            }))
        }
        RegistryRecordRepresentation::JsonLdProductComposition => {
            let Some(Value::Array(values)) = value else {
                return Err(invalid(
                    "product JSON-LD must use an ordered Registry Record context composition",
                ));
            };
            if values.len() < 2 {
                return Err(invalid(
                    "product JSON-LD context composition requires a product context",
                ));
            }
            if values.first().and_then(Value::as_str) != Some(REGISTRY_RECORD_CONTEXT_IDENTIFIER) {
                return Err(invalid(
                    "product JSON-LD context composition must start with the Registry Record context",
                ));
            }

            let mut seen = BTreeSet::new();
            seen.insert(REGISTRY_RECORD_CONTEXT_IDENTIFIER.to_owned());
            let mut product_contexts = Vec::with_capacity(values.len() - 1);
            for (index, value) in values.into_iter().enumerate().skip(1) {
                let Value::String(context) = value else {
                    return Err(invalid(format!(
                        "@context[{index}] must be a non-empty absolute HTTPS IRI"
                    )));
                };
                validate_product_context(&context, index)?;
                if !seen.insert(context.clone()) {
                    return Err(invalid("JSON-LD context entries must be unique"));
                }
                product_contexts.push(context);
            }
            Ok(Some(RegistryRecordJsonLdContext { product_contexts }))
        }
    }
}

fn validate_product_context(context: &str, index: usize) -> Result<(), RegistryRecordDecodeError> {
    if context.is_empty()
        || context
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid(format!(
            "@context[{index}] must be a non-empty absolute HTTPS IRI"
        )));
    }
    let parsed = Url::parse(context).map_err(|_| {
        invalid(format!(
            "@context[{index}] must be a non-empty absolute HTTPS IRI"
        ))
    })?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(invalid(format!(
            "@context[{index}] must be a non-empty absolute HTTPS IRI"
        )));
    }
    Ok(())
}

fn decode_record(value: Value, path: &str) -> Result<RegistryRecord, RegistryRecordDecodeError> {
    let mut record = require_object(value, path)?;
    reject_misplaced_infrastructure(
        &record,
        &["recordIdentifier", "revisionIdentifier", "domainData"],
        path,
    )?;
    let record_identifier = take_identifier(&mut record, "recordIdentifier", path)?;
    let revision_identifier = take_identifier(&mut record, "revisionIdentifier", path)?;
    let domain_data_path = format!("{path}.domainData");
    let domain_data = require_object(
        take_required(&mut record, "domainData", path)?,
        &domain_data_path,
    )?;
    reject_misplaced_infrastructure(&domain_data, &[], &domain_data_path)?;
    Ok(RegistryRecord {
        record_identifier,
        revision_identifier,
        domain_data: into_extensions(domain_data),
        extensions: into_extensions(record),
    })
}

fn decode_meta(value: Value) -> Result<RegistryRecordMeta, RegistryRecordDecodeError> {
    let mut meta = require_object(value, "meta")?;
    reject_misplaced_infrastructure(
        &meta,
        &[
            "registryIdentifier",
            "datasetIdentifier",
            "entityTypeIdentifier",
        ],
        "meta",
    )?;
    let registry_identifier = take_identifier(&mut meta, "registryIdentifier", "meta")?;
    let dataset_identifier = take_identifier(&mut meta, "datasetIdentifier", "meta")?;
    let entity_type_identifier = take_identifier(&mut meta, "entityTypeIdentifier", "meta")?;
    Ok(RegistryRecordMeta {
        registry_identifier,
        dataset_identifier,
        entity_type_identifier,
        extensions: into_extensions(meta),
    })
}

fn decode_page_info(value: Value) -> Result<RegistryRecordPageInfo, RegistryRecordDecodeError> {
    let mut page_info = require_object(value, "pageInfo")?;
    reject_misplaced_infrastructure(&page_info, &["nextCursor"], "pageInfo")?;
    let next_cursor = match take_required(&mut page_info, "nextCursor", "pageInfo")? {
        Value::Null => None,
        Value::String(cursor) if !cursor.is_empty() => Some(cursor),
        _ => {
            return Err(invalid(
                "pageInfo.nextCursor must be null or a non-empty string",
            ))
        }
    };
    Ok(RegistryRecordPageInfo {
        next_cursor,
        extensions: into_extensions(page_info),
    })
}

fn take_identifier(
    object: &mut Map<String, Value>,
    member: &str,
    path: &str,
) -> Result<String, RegistryRecordDecodeError> {
    match take_required(object, member, path)? {
        Value::String(identifier) if !identifier.is_empty() => Ok(identifier),
        _ => Err(invalid(format!(
            "{path}.{member} must be an opaque non-empty string"
        ))),
    }
}

fn take_required(
    object: &mut Map<String, Value>,
    member: &str,
    path: &str,
) -> Result<Value, RegistryRecordDecodeError> {
    object
        .remove(member)
        .ok_or_else(|| invalid(format!("{path}.{member} is required")))
}

fn require_object(
    value: Value,
    path: &str,
) -> Result<Map<String, Value>, RegistryRecordDecodeError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(invalid(format!("{path} must be an object"))),
    }
}

fn reject_nested_context_in_map(
    object: &Map<String, Value>,
    path: &str,
) -> Result<(), RegistryRecordDecodeError> {
    for (member, value) in object {
        if member == "@context" {
            return Err(invalid(format!(
                "{path} contains a nested or inline @context"
            )));
        }
        reject_nested_context(value, &format!("{path}.{member}"))?;
    }
    Ok(())
}

fn reject_nested_context(value: &Value, path: &str) -> Result<(), RegistryRecordDecodeError> {
    match value {
        Value::Object(object) => reject_nested_context_in_map(object, path),
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_nested_context(value, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reject_misplaced_infrastructure(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), RegistryRecordDecodeError> {
    if let Some(member) = object.keys().find(|member| {
        INFRASTRUCTURE_MEMBERS.contains(&member.as_str()) && !allowed.contains(&member.as_str())
    }) {
        return Err(invalid(format!(
            "{path}.{member} is a misplaced Registry Record infrastructure member"
        )));
    }
    Ok(())
}

fn into_extensions(object: Map<String, Value>) -> BTreeMap<String, Value> {
    object.into_iter().collect()
}

fn invalid(_message: impl Into<String>) -> RegistryRecordDecodeError {
    RegistryRecordDecodeError::Profile
}
