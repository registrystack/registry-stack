//! Byte-only admission of project-owned source-facts schemas.
//!
//! Keep authoring and runtime admission aligned: closed bounded values, a
//! versioned public identity, and document-local JSON Pointer references.
use serde_json::Value;
use std::sync::Arc;
use url::Url;

const MAXIMUM_SCHEMA_DEPTH: usize = 64;
const MAXIMUM_SCHEMA_NODES: usize = 8_192;
const MAXIMUM_ARRAY_ITEMS: u64 = 100_000;

#[derive(Debug)]
struct NoExternalResolver;
impl jsonschema::SchemaResolver for NoExternalResolver {
    fn resolve(
        &self,
        _root: &Value,
        _url: &Url,
        _reference: &str,
    ) -> Result<Arc<Value>, jsonschema::SchemaResolverError> {
        Err(anyhow::anyhow!(
            "external source projection schema resolution is disabled"
        ))
    }
}

pub(crate) fn schema_is_admissible(schema: &Value) -> bool {
    if schema.get("type").and_then(Value::as_str) != Some("object")
        || schema.get("additionalProperties") != Some(&Value::Bool(false))
        || !schema
            .get("$id")
            .and_then(Value::as_str)
            .is_some_and(versioned_https_identity)
        || serde_json::to_vec(schema).map_or(true, |bytes| bytes.len() > 256 * 1024)
    {
        return false;
    }
    let mut nodes = 0;
    if check_bounds(schema, 0, &mut nodes).is_err() || check_schema(schema, true).is_err() {
        return false;
    }
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .with_resolver(NoExternalResolver)
        .compile(schema)
        .is_ok()
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

fn check_bounds(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), ()> {
    if depth > MAXIMUM_SCHEMA_DEPTH || *nodes >= MAXIMUM_SCHEMA_NODES {
        return Err(());
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

fn check_schema(schema: &Value, root: bool) -> Result<(), ()> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    if (has_type(object, "object")
        || object.contains_key("properties")
        || object.contains_key("patternProperties"))
        && object.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err(());
    }
    if has_type(object, "array") {
        let bounded = object
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| maximum <= MAXIMUM_ARRAY_ITEMS);
        if !bounded {
            return Err(());
        }
    }
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if object.get(keyword).is_some_and(|reference| {
            !reference
                .as_str()
                .is_some_and(|text| text == "#" || text.starts_with("#/"))
        }) {
            return Err(());
        }
    }
    if !root && object.contains_key("$id") {
        return Err(());
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
