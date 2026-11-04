// SPDX-License-Identifier: Apache-2.0

//! Bounded project-owned public JSON Schemas. Runtime compilation resolves no
//! filesystem or network references: a schema is one digest-pinned document,
//! and every reference remains inside that document.

use std::sync::Arc;

use jsonschema::{Draft, JSONSchema, SchemaResolver, SchemaResolverError};
use serde_json::Value;
use thiserror::Error;
use url::Url;

const MAXIMUM_SCHEMA_BYTES: usize = 256 * 1024;
const MAXIMUM_SCHEMA_DEPTH: usize = 64;
const MAXIMUM_SCHEMA_NODES: usize = 8_192;
const MAXIMUM_ARRAY_ITEMS: u64 = 100_000;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PublicSchemaError {
    #[error("the schema exceeds its byte, depth, or node bound")]
    Bound,
    #[error("the schema root must be a closed object")]
    RootNotClosed,
    #[error("the schema must carry a versioned absolute HTTPS $id")]
    Identity,
    #[error("every object schema must refuse undeclared properties")]
    ObjectNotClosed,
    #[error("every array schema must declare a finite maxItems within the supported bound")]
    ArrayNotBounded,
    #[error("the schema may use local JSON Pointer references only")]
    ExternalReference,
    #[error("the schema is not valid JSON Schema 2020-12")]
    Invalid,
}

/// A checked project schema and its public identity.
pub struct CheckedPublicSchema {
    identity: String,
    value: Value,
    validator: JSONSchema,
}

impl std::fmt::Debug for CheckedPublicSchema {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedPublicSchema")
            .field("identity", &self.identity)
            .field("value", &"<schema>")
            .finish()
    }
}

impl CheckedPublicSchema {
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.value
    }

    #[must_use]
    pub fn validates(&self, value: &Value) -> bool {
        self.validator.is_valid(value)
    }

    /// Return this schema ready to insert under `#/$defs/<definition>` in a
    /// generated wrapper. Local references are rebased to that location and
    /// the nested `$id` is removed, so `#/$defs/...` keeps naming this
    /// schema's definitions rather than the wrapper's root.
    #[must_use]
    pub fn for_definition(&self, definition: &str) -> Value {
        let escaped = definition.replace('~', "~0").replace('/', "~1");
        self.rebased(&format!("#/$defs/{escaped}"))
    }

    /// Return this schema ready to insert under an OpenAPI 3.1
    /// `components.schemas` member. Local JSON Schema references stay local
    /// to the embedded component and no nested identity changes their base.
    #[must_use]
    pub fn for_component(&self, component: &str) -> Value {
        let escaped = component.replace('~', "~0").replace('/', "~1");
        self.rebased(&format!("#/components/schemas/{escaped}"))
    }

    fn rebased(&self, base: &str) -> Value {
        let mut value = self.value.clone();
        if let Some(root) = value.as_object_mut() {
            root.remove("$id");
        }
        rebase_references(&mut value, base);
        value
    }
}

#[derive(Debug)]
struct NoExternalSchemaResolver;

impl SchemaResolver for NoExternalSchemaResolver {
    fn resolve(
        &self,
        _root_schema: &Value,
        _url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "external public schema resolution is disabled",
        )
        .into())
    }
}

/// Compile one complete project schema without external resolution.
pub fn check_public_schema(schema: Value) -> Result<CheckedPublicSchema, PublicSchemaError> {
    if serde_json::to_vec(&schema).map_or(true, |bytes| bytes.len() > MAXIMUM_SCHEMA_BYTES) {
        return Err(PublicSchemaError::Bound);
    }
    let Some(root) = schema.as_object() else {
        return Err(PublicSchemaError::RootNotClosed);
    };
    if root.get("type") != Some(&Value::String("object".to_owned()))
        || root.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err(PublicSchemaError::RootNotClosed);
    }
    let identity = root
        .get("$id")
        .and_then(Value::as_str)
        .filter(|identity| versioned_https_identity(identity))
        .ok_or(PublicSchemaError::Identity)?
        .to_owned();
    let mut nodes = 0;
    check_bounds(&schema, 0, &mut nodes)?;
    check_schema(&schema, true)?;

    let mut options = JSONSchema::options();
    options
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_resolver(NoExternalSchemaResolver);
    let validator = options
        .compile(&schema)
        .map_err(|_| PublicSchemaError::Invalid)?;
    Ok(CheckedPublicSchema {
        identity,
        value: schema,
        validator,
    })
}

fn versioned_https_identity(identity: &str) -> bool {
    if identity.len() > 2_048
        || identity
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return false;
    }
    let Ok(url) = Url::parse(identity) else {
        return false;
    };
    let authority_has_userinfo = identity
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|authority| authority.contains('@'));
    if url.scheme() != "https"
        || url.host_str().is_none()
        || authority_has_userinfo
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    url.path_segments().is_some_and(|segments| {
        segments
            .filter(|segment| !segment.is_empty())
            .any(|segment| {
                let version = segment.strip_prefix('v').unwrap_or(segment);
                version.starts_with(|character: char| character.is_ascii_digit())
            })
    })
}

fn check_bounds(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), PublicSchemaError> {
    if depth > MAXIMUM_SCHEMA_DEPTH || *nodes >= MAXIMUM_SCHEMA_NODES {
        return Err(PublicSchemaError::Bound);
    }
    *nodes += 1;
    match value {
        Value::Array(items) => {
            for item in items {
                check_bounds(item, depth + 1, nodes)?;
            }
        }
        Value::Object(object) => {
            for member in object.values() {
                check_bounds(member, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_schema(schema: &Value, root: bool) -> Result<(), PublicSchemaError> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    if (has_type(object, "object")
        || object.contains_key("properties")
        || object.contains_key("patternProperties"))
        && object.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err(PublicSchemaError::ObjectNotClosed);
    }
    if has_type(object, "array") {
        let bounded = object
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| maximum <= MAXIMUM_ARRAY_ITEMS);
        if !bounded {
            return Err(PublicSchemaError::ArrayNotBounded);
        }
    }
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if object.get(keyword).is_some_and(|reference| {
            !reference
                .as_str()
                .is_some_and(|text| text == "#" || text.starts_with("#/"))
        }) {
            return Err(PublicSchemaError::ExternalReference);
        }
    }
    if !root && object.contains_key("$id") {
        return Err(PublicSchemaError::ExternalReference);
    }
    visit_subschemas(object, |subschema| check_schema(subschema, false))
}

fn has_type(object: &serde_json::Map<String, Value>, expected: &str) -> bool {
    match object.get("type") {
        Some(Value::String(actual)) => actual == expected,
        Some(Value::Array(actual)) => actual.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn visit_subschemas<E>(
    object: &serde_json::Map<String, Value>,
    mut visit: impl FnMut(&Value) -> Result<(), E>,
) -> Result<(), E> {
    for keyword in [
        "additionalProperties",
        "unevaluatedProperties",
        "propertyNames",
        "contains",
        "items",
        "unevaluatedItems",
        "if",
        "then",
        "else",
        "not",
        "contentSchema",
    ] {
        if let Some(subschema) = object.get(keyword) {
            visit(subschema)?;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(subschemas) = object.get(keyword).and_then(Value::as_array) {
            for subschema in subschemas {
                visit(subschema)?;
            }
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
    ] {
        if let Some(subschemas) = object.get(keyword).and_then(Value::as_object) {
            for subschema in subschemas.values() {
                visit(subschema)?;
            }
        }
    }
    Ok(())
}

fn rebase_references(value: &mut Value, base: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if let Some(reference) = object.get_mut(keyword) {
            if let Some(local) = reference.as_str() {
                *reference = Value::String(if local == "#" {
                    base.to_owned()
                } else {
                    format!("{base}{}", local.trim_start_matches('#'))
                });
            }
        }
    }
    visit_subschemas_mut(object, |subschema| {
        rebase_references(subschema, base);
    });
}

fn visit_subschemas_mut(
    object: &mut serde_json::Map<String, Value>,
    mut visit: impl FnMut(&mut Value),
) {
    for keyword in [
        "additionalProperties",
        "unevaluatedProperties",
        "propertyNames",
        "contains",
        "items",
        "unevaluatedItems",
        "if",
        "then",
        "else",
        "not",
        "contentSchema",
    ] {
        if let Some(subschema) = object.get_mut(keyword) {
            visit(subschema);
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(subschemas) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for subschema in subschemas {
                visit(subschema);
            }
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
    ] {
        if let Some(subschemas) = object.get_mut(keyword).and_then(Value::as_object_mut) {
            for subschema in subschemas.values_mut() {
                visit(subschema);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nested_schema() -> Value {
        json!({
            "$id": "https://registry.example/schemas/person-public/1.0.0",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["household"],
            "properties": {
                "household": {"$ref": "#/$defs/household"}
            },
            "$defs": {
                "household": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["members"],
                    "properties": {
                        "members": {
                            "type": "array",
                            "maxItems": 16,
                            "items": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["name"],
                                "properties": {"name": {"type": "string"}}
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn nested_objects_bounded_arrays_and_local_references_are_checked() {
        let checked = check_public_schema(nested_schema()).expect("checked");
        assert!(checked.validates(&json!({"household":{"members":[{"name":"Ada"}]}})));
        assert!(
            !checked.validates(&json!({"household":{"members":[{"name":"Ada","private":true}]}}))
        );
    }

    #[test]
    fn embedding_rebases_local_definitions_without_remote_resolution() {
        let checked = check_public_schema(nested_schema()).expect("checked");
        let embedded = checked.for_definition("person/public");
        assert!(embedded.get("$id").is_none());
        assert_eq!(
            embedded["properties"]["household"]["$ref"],
            json!("#/$defs/person~1public/$defs/household")
        );
    }

    #[test]
    fn openapi_component_embedding_rebases_nested_local_definitions() {
        let checked = check_public_schema(nested_schema()).expect("checked");
        let embedded = checked.for_component("person/public");
        assert!(embedded.get("$id").is_none());
        assert_eq!(
            embedded["properties"]["household"]["$ref"],
            json!("#/components/schemas/person~1public/$defs/household")
        );
    }

    #[test]
    fn unbounded_arrays_and_external_references_are_refused() {
        let mut unbounded = nested_schema();
        unbounded["$defs"]["household"]["properties"]["members"]
            .as_object_mut()
            .expect("array schema")
            .remove("maxItems");
        assert_eq!(
            check_public_schema(unbounded).unwrap_err(),
            PublicSchemaError::ArrayNotBounded
        );

        let mut external = nested_schema();
        external["properties"]["household"]["$ref"] = json!("https://schemas.example/household");
        assert_eq!(
            check_public_schema(external).unwrap_err(),
            PublicSchemaError::ExternalReference
        );

        let mut anchor = nested_schema();
        anchor["properties"]["household"]["$ref"] = json!("#household");
        assert_eq!(
            check_public_schema(anchor).unwrap_err(),
            PublicSchemaError::ExternalReference
        );
    }

    #[test]
    fn nullable_objects_and_arrays_keep_the_disclosure_bounds() {
        let mut open_object = nested_schema();
        open_object["properties"]["household"]["type"] = json!(["object", "null"]);
        open_object["properties"]["household"]
            .as_object_mut()
            .unwrap()
            .remove("$ref");
        open_object["properties"]["household"]["properties"] = json!({"name":{"type":"string"}});
        assert_eq!(
            check_public_schema(open_object).unwrap_err(),
            PublicSchemaError::ObjectNotClosed
        );

        let mut unbounded_array = nested_schema();
        unbounded_array["$defs"]["household"]["properties"]["members"]["type"] =
            json!(["array", "null"]);
        unbounded_array["$defs"]["household"]["properties"]["members"]
            .as_object_mut()
            .unwrap()
            .remove("maxItems");
        assert_eq!(
            check_public_schema(unbounded_array).unwrap_err(),
            PublicSchemaError::ArrayNotBounded
        );
    }

    #[test]
    fn literal_schema_keyword_names_in_data_are_not_interpreted_or_rewritten() {
        let mut schema = nested_schema();
        schema["properties"]["annotation"] = json!({
            "const": {
                "$ref": "literal-not-a-schema-reference",
                "$id": "literal-not-a-schema-identity",
                "type": "object",
                "properties": {"private": true}
            },
            "examples": [{"$ref":"also-literal"}]
        });
        let checked = check_public_schema(schema).expect("literal data is accepted");
        let embedded = checked.for_definition("person");
        assert_eq!(
            embedded["properties"]["annotation"]["const"]["$ref"],
            json!("literal-not-a-schema-reference")
        );
        assert_eq!(
            embedded["properties"]["annotation"]["const"]["$id"],
            json!("literal-not-a-schema-identity")
        );
        assert_eq!(
            embedded["properties"]["annotation"]["examples"][0]["$ref"],
            json!("also-literal")
        );
    }

    #[test]
    fn schema_identity_refuses_credentials_query_whitespace_and_excessive_length() {
        for identity in [
            "https://user:password@registry.example/schemas/person/1.0.0",
            "https://registry.example/schemas/person/1.0.0?token=private",
            "https://registry.example/schemas/person/1.0.0#fragment",
            "https://registry.example/schemas/person/1.0.0 bad",
        ] {
            let mut schema = nested_schema();
            schema["$id"] = json!(identity);
            assert_eq!(
                check_public_schema(schema).unwrap_err(),
                PublicSchemaError::Identity,
                "{identity}"
            );
        }
        let mut schema = nested_schema();
        schema["$id"] = json!(format!(
            "https://registry.example/schemas/{}/1.0.0",
            "x".repeat(2_048)
        ));
        assert_eq!(
            check_public_schema(schema).unwrap_err(),
            PublicSchemaError::Identity
        );
    }

    #[test]
    fn an_empty_only_array_is_still_finitely_bounded() {
        let mut schema = nested_schema();
        schema["$defs"]["household"]["properties"]["members"]["maxItems"] = json!(0);
        assert!(check_public_schema(schema).is_ok());
    }
}
