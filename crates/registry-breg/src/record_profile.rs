// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine's closed adoption of the shared Registry Record profile.
//!
//! The selected compiled record operation is the governed publication
//! decision for the structural Registry, dataset, and entity-type identifiers.
//! They are not caller-selectable domain fields and are never inferred from a
//! route, host header, storage relation, or deployment origin.

use serde_json::{Map, Value};

use crate::model::CompiledEntity;

pub const PROFILE_IDENTIFIER: &str = "https://id.registrystack.org/profiles/registry-record/v1";
pub const SCHEMA_IDENTIFIER: &str = "https://id.registrystack.org/schemas/registry-record/v1";
pub const CONTEXT_IDENTIFIER: &str = "https://id.registrystack.org/contexts/registry-record/v1";

const RESERVED_DOMAIN_MEMBERS: &[&str] = &[
    "@context",
    "@id",
    "@type",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordRepresentation {
    Json,
    JsonLd,
}

impl RecordRepresentation {
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::JsonLd => "application/ld+json",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordProfileError {
    InvalidContext,
    InvalidMember,
}

pub fn link_header_value(entity: &CompiledEntity) -> Result<String, RecordProfileError> {
    if entity.id.is_empty() || entity.id.chars().any(char::is_control) {
        return Err(RecordProfileError::InvalidContext);
    }
    Ok(format!(
        "<{PROFILE_IDENTIFIER}>; rel=\"profile\", </v1/schemas/{}>; rel=\"describedby\"",
        entity.id
    ))
}

pub fn record_member(
    record_identifier: String,
    revision_identifier: String,
    domain_data: Map<String, Value>,
    extensions: Map<String, Value>,
) -> Result<Value, RecordProfileError> {
    if record_identifier.is_empty()
        || revision_identifier.is_empty()
        || domain_data
            .keys()
            .any(|name| RESERVED_DOMAIN_MEMBERS.contains(&name.as_str()))
        || extensions.keys().any(|name| {
            RESERVED_DOMAIN_MEMBERS.contains(&name.as_str())
                || name == "recordIdentifier"
                || name == "revisionIdentifier"
                || name == "domainData"
        })
        || domain_data.values().any(contains_inline_context)
        || extensions.values().any(contains_inline_context)
    {
        return Err(RecordProfileError::InvalidMember);
    }
    let mut member = Map::from_iter([
        (
            "recordIdentifier".to_owned(),
            Value::String(record_identifier),
        ),
        (
            "revisionIdentifier".to_owned(),
            Value::String(revision_identifier),
        ),
        ("domainData".to_owned(), Value::Object(domain_data)),
    ]);
    member.extend(extensions);
    Ok(Value::Object(member))
}

pub fn single_response(
    registry_identifier: &str,
    entity: &CompiledEntity,
    data: Value,
    representation: RecordRepresentation,
) -> Result<Value, RecordProfileError> {
    validate_member(&data)?;
    let mut response = response_prefix(representation);
    response.insert("data".to_owned(), data);
    response.insert(
        "meta".to_owned(),
        response_meta(registry_identifier, entity)?,
    );
    Ok(Value::Object(response))
}

pub fn collection_response(
    registry_identifier: &str,
    entity: &CompiledEntity,
    items: Vec<Value>,
    next_cursor: Option<String>,
    extensions: Map<String, Value>,
    representation: RecordRepresentation,
) -> Result<Value, RecordProfileError> {
    if items.iter().any(|item| validate_member(item).is_err())
        || next_cursor.as_deref().is_some_and(str::is_empty)
        || extensions
            .keys()
            .any(|name| matches!(name.as_str(), "@context" | "items" | "pageInfo" | "meta"))
        || extensions.values().any(contains_inline_context)
    {
        return Err(RecordProfileError::InvalidMember);
    }
    let mut response = response_prefix(representation);
    response.insert("items".to_owned(), Value::Array(items));
    response.insert(
        "pageInfo".to_owned(),
        Value::Object(Map::from_iter([(
            "nextCursor".to_owned(),
            next_cursor.map_or(Value::Null, Value::String),
        )])),
    );
    response.insert(
        "meta".to_owned(),
        response_meta(registry_identifier, entity)?,
    );
    response.extend(extensions);
    Ok(Value::Object(response))
}

fn response_prefix(representation: RecordRepresentation) -> Map<String, Value> {
    match representation {
        RecordRepresentation::Json => Map::new(),
        RecordRepresentation::JsonLd => Map::from_iter([(
            "@context".to_owned(),
            Value::String(CONTEXT_IDENTIFIER.to_owned()),
        )]),
    }
}

fn response_meta(
    registry_identifier: &str,
    entity: &CompiledEntity,
) -> Result<Value, RecordProfileError> {
    let dataset_identifier = entity
        .primary_dataset
        .as_deref()
        .filter(|identifier| !identifier.is_empty())
        .ok_or(RecordProfileError::InvalidContext)?;
    if registry_identifier.is_empty() || entity.id.is_empty() {
        return Err(RecordProfileError::InvalidContext);
    }
    Ok(Value::Object(Map::from_iter([
        (
            "registryIdentifier".to_owned(),
            Value::String(registry_identifier.to_owned()),
        ),
        (
            "datasetIdentifier".to_owned(),
            Value::String(dataset_identifier.to_owned()),
        ),
        (
            "entityTypeIdentifier".to_owned(),
            Value::String(entity.id.clone()),
        ),
    ])))
}

fn validate_member(value: &Value) -> Result<(), RecordProfileError> {
    let object = value.as_object().ok_or(RecordProfileError::InvalidMember)?;
    if object
        .get("recordIdentifier")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || object
            .get("revisionIdentifier")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !object.get("domainData").is_some_and(Value::is_object)
        || contains_inline_context(value)
    {
        return Err(RecordProfileError::InvalidMember);
    }
    Ok(())
}

fn contains_inline_context(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_inline_context),
        Value::Object(values) => {
            values.contains_key("@context") || values.values().any(contains_inline_context)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_data_refuses_every_profile_infrastructure_member() {
        for reserved in RESERVED_DOMAIN_MEMBERS {
            let result = record_member(
                "record".to_owned(),
                "1".to_owned(),
                Map::from_iter([(reserved.to_string(), Value::Null)]),
                Map::new(),
            );
            assert_eq!(result, Err(RecordProfileError::InvalidMember), "{reserved}");
        }
    }

    #[test]
    fn nested_json_ld_identity_and_type_members_are_valid_domain_data() {
        let result = record_member(
            "record".to_owned(),
            "1".to_owned(),
            Map::from_iter([(
                "structured".to_owned(),
                Value::Object(Map::from_iter([
                    (
                        "@id".to_owned(),
                        Value::String("urn:example:item".to_owned()),
                    ),
                    ("@type".to_owned(), Value::String("ExampleItem".to_owned())),
                ])),
            )]),
            Map::new(),
        );
        let member = result.expect("structured JSON-LD identity and type are domain values");
        assert_eq!(validate_member(&member), Ok(()));
    }

    #[test]
    fn nested_json_ld_context_is_never_domain_data() {
        let result = record_member(
            "record".to_owned(),
            "1".to_owned(),
            Map::from_iter([(
                "structured".to_owned(),
                Value::Object(Map::from_iter([(
                    "@context".to_owned(),
                    Value::String("https://example.test/context".to_owned()),
                )])),
            )]),
            Map::new(),
        );
        assert_eq!(result, Err(RecordProfileError::InvalidMember));
    }
}
