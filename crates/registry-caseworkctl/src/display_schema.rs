// SPDX-License-Identifier: Apache-2.0
//! What a source-context review kind's `displaySchema` provably cannot show.
//!
//! A reviewer's source read discloses each projected request field the reader
//! may see, under its API name, with a value the field's source schema admits.
//! The runtime validates that disclosure against the kind's `displaySchema`
//! and hides the task from every reviewer when it is rejected. The imported
//! source description carries each field's exact source schema, so authoring
//! can refuse the part of that failure the two schemas prove:
//!
//! - a projected field the closed schema does not declare, where no
//!   `patternProperties` entry could admit it;
//! - a declared property whose `type` shares no JSON type with the source
//!   field's;
//! - a value the source schema itself enumerates (an `enum` or `const`
//!   member, `null`, or a Boolean, alone or as the item of an array) that the
//!   source schema admits and the declared property rejects.
//!
//! Every reported value is validated against the source schema first, so a
//! refusal names a value the source can really hold. Constraints that need an
//! invented value to disprove (lengths, patterns, formats, numeric bounds) and
//! properties that use `$ref` are not analysed; the runtime check still
//! applies to them.

use anyhow::{bail, Result};
use jsonschema::{Draft, JSONSchema};
use registry_casework_core::{CaseworkProject, ReviewContextStrategy, SourcePolicy};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const MAXIMUM_SCHEMA_DEPTH: usize = 16;

/// Refuse a described request whose bound source-context review kind cannot
/// display what the request's projected fields disclose. A request that
/// requires no review, names no declared kind, or binds a kind that is not
/// source-context is left to the checks that refuse those bindings.
pub(crate) fn check_described_request(
    policy: &CaseworkProject,
    source: &SourcePolicy,
    description: &Path,
    request: &Value,
) -> Result<()> {
    let Some(policy_id) = request.pointer("/review/policyId").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(kind) = policy
        .review_kinds
        .iter()
        .find(|kind| kind.id == policy_id)
        .filter(|kind| kind.context_strategy == ReviewContextStrategy::Source)
    else {
        return Ok(());
    };
    let entity = request["requestEntity"].as_str().unwrap_or_default();
    let Some(declared) = source
        .requests
        .iter()
        .find(|declared| declared.entity == entity)
    else {
        return Ok(());
    };
    let mismatches =
        display_mismatches(&kind.display_schema, request, &declared.context_projection);
    if mismatches.is_empty() {
        return Ok(());
    }
    bail!(
        "review kind {kind_id} displaySchema rejects what source {source_id} request entity {entity} in {description} can disclose to a reviewer, so Casework would hide those review tasks from every reviewer: {mismatches}; make the displaySchema of reviewKinds entry {kind_id} admit each projected field's source schema under its API name, as `bregctl explain change-requests` reports it",
        kind_id = kind.id,
        source_id = source.id,
        description = description.display(),
        mismatches = mismatches.join("; "),
    )
}

/// Apply [`check_described_request`] to every request a source description
/// lists, in description order.
pub(crate) fn check_description(
    policy: &CaseworkProject,
    source: &SourcePolicy,
    path: &Path,
    description: &Value,
) -> Result<()> {
    let described = match description.get("requests").and_then(Value::as_array) {
        Some(requests) => requests.iter().collect::<Vec<_>>(),
        None => vec![&description["request"]],
    };
    for request in described {
        check_described_request(policy, source, path, request)?;
    }
    Ok(())
}

fn display_mismatches(display: &Value, request: &Value, projection: &[String]) -> Vec<String> {
    let Some(fields) = request["fields"].as_array() else {
        return Vec::new();
    };
    let properties = display.get("properties").and_then(Value::as_object);
    // additionalProperties is evaluated against its sibling properties and
    // patternProperties only, so an undeclared name is refused whatever other
    // keywords the root carries, unless a pattern could still admit it.
    let closed = display.get("additionalProperties") == Some(&Value::Bool(false))
        && display.get("patternProperties").is_none();
    let mut mismatches = Vec::new();
    for logical in projection {
        let Some(field) = fields.iter().find(|field| field["field"] == *logical) else {
            continue;
        };
        let (Some(api_name), source) = (field["apiName"].as_str(), &field["schema"]) else {
            continue;
        };
        match properties.and_then(|properties| properties.get(api_name)) {
            None if closed => mismatches.push(format!(
                "property {api_name} (source field {logical}) is not declared, and additionalProperties: false rejects every disclosure that carries it; the source describes it as {source}"
            )),
            None => {}
            Some(property) => {
                if let Some(mismatch) = property_mismatch(api_name, logical, property, source) {
                    mismatches.push(mismatch);
                }
            }
        }
    }
    mismatches
}

fn property_mismatch(
    api_name: &str,
    logical: &str,
    property: &Value,
    source: &Value,
) -> Option<String> {
    if contains_reference(property, 0) {
        return None;
    }
    let displayed = compile(property)?;
    let admitted = compile(source)?;
    if property == &Value::Bool(false) {
        return Some(format!(
            "property {api_name} (source field {logical}) admits no value"
        ));
    }
    if let (Some(displayed_types), Some(source_types)) =
        (json_types(property), source_json_types(source, 0))
    {
        if !source_types.iter().any(|source| {
            displayed_types
                .iter()
                .any(|shown| types_overlap(source, shown))
        }) {
            return Some(format!(
                "property {api_name} accepts type {}, but source field {logical} is {}",
                render_types(&displayed_types),
                render_types(&source_types),
            ));
        }
    }
    let maximum_bytes = source.get("x-registry-maxBytes").and_then(Value::as_u64);
    let mut rejected = Vec::new();
    for (value, label) in witnesses(source, 0) {
        if admitted.is_valid(&value)
            && maximum_bytes.is_none_or(|maximum| encoded_len(&value) <= maximum)
            && !displayed.is_valid(&value)
            && !rejected.contains(&label)
        {
            rejected.push(label);
        }
    }
    if rejected.is_empty() {
        return None;
    }
    Some(format!(
        "property {api_name} rejects {} that source field {logical} admits",
        rejected
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn compile(schema: &Value) -> Option<JSONSchema> {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .ok()
}

fn contains_reference(schema: &Value, depth: usize) -> bool {
    if depth > MAXIMUM_SCHEMA_DEPTH {
        return true;
    }
    match schema {
        Value::Object(object) => object.iter().any(|(keyword, value)| {
            matches!(keyword.as_str(), "$ref" | "$dynamicRef")
                || contains_reference(value, depth + 1)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_reference(value, depth + 1)),
        _ => false,
    }
}

/// The JSON types a schema's own `type` keyword admits.
fn json_types(schema: &Value) -> Option<BTreeSet<String>> {
    match schema.get("type")? {
        Value::String(name) => Some(BTreeSet::from([name.clone()])),
        Value::Array(names) => names
            .iter()
            .map(|name| name.as_str().map(str::to_owned))
            .collect(),
        _ => None,
    }
}

/// The JSON types every value of a source schema has, from its `type`
/// keyword or, without one, from every `anyOf` or `oneOf` branch.
fn source_json_types(schema: &Value, depth: usize) -> Option<BTreeSet<String>> {
    if depth > MAXIMUM_SCHEMA_DEPTH {
        return None;
    }
    if schema.get("type").is_some() {
        return json_types(schema);
    }
    let branches = ["anyOf", "oneOf"]
        .iter()
        .find_map(|keyword| schema.get(*keyword).and_then(Value::as_array))?;
    let mut types = BTreeSet::new();
    for branch in branches {
        types.extend(source_json_types(branch, depth + 1)?);
    }
    Some(types)
}

fn types_overlap(source: &str, shown: &str) -> bool {
    source == shown
        || (source == "integer" && shown == "number")
        || (source == "number" && shown == "integer")
}

fn render_types(types: &BTreeSet<String>) -> String {
    match types.iter().collect::<Vec<_>>().as_slice() {
        [single] => (*single).clone(),
        several => format!(
            "[{}]",
            several
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn encoded_len(value: &Value) -> u64 {
    serde_json::to_vec(value).map_or(u64::MAX, |bytes| bytes.len() as u64)
}

/// Values the source schema itself names, each paired with the value a
/// refusal reports: the value, or for an array witness the item it carries.
/// Callers still validate every witness against the whole source schema.
fn witnesses(schema: &Value, depth: usize) -> Vec<(Value, Value)> {
    if depth > MAXIMUM_SCHEMA_DEPTH {
        return Vec::new();
    }
    let mut scalars = Vec::new();
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        scalars.extend(values.iter().cloned());
    }
    if let Some(value) = schema.get("const") {
        scalars.push(value.clone());
    }
    let types = json_types(schema).unwrap_or_default();
    if types.contains("null") {
        scalars.push(Value::Null);
    }
    if types.contains("boolean") {
        scalars.extend([Value::Bool(false), Value::Bool(true)]);
    }
    let maximum_bytes = schema.get("x-registry-maxBytes").and_then(Value::as_u64);
    let mut witnesses = scalars
        .into_iter()
        .filter(|value| maximum_bytes.is_none_or(|maximum| encoded_len(value) <= maximum))
        .map(|value| (value.clone(), value))
        .collect::<Vec<_>>();
    if let Some(items) = schema.get("items").filter(|items| items.is_object()) {
        let item_values = witnesses_of(items, depth + 1);
        let minimum = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
        for item in &item_values {
            if minimum <= 1 {
                witnesses.push((Value::Array(vec![item.clone()]), item.clone()));
                continue;
            }
            let mut array = vec![item.clone()];
            array.extend(
                item_values
                    .iter()
                    .filter(|other| *other != item)
                    .take(minimum as usize - 1)
                    .cloned(),
            );
            if array.len() as u64 == minimum {
                let array = Value::Array(array);
                witnesses.push((array.clone(), array));
            }
        }
    }
    for keyword in ["anyOf", "oneOf"] {
        for branch in schema
            .get(keyword)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            witnesses.extend(self::witnesses(branch, depth + 1));
        }
    }
    witnesses
}

fn witnesses_of(schema: &Value, depth: usize) -> Vec<Value> {
    let admitted = compile(schema);
    let mut values = Vec::new();
    for (value, _) in witnesses(schema, depth) {
        if admitted
            .as_ref()
            .is_some_and(|admitted| admitted.is_valid(&value))
            && !values.contains(&value)
        {
            values.push(value);
        }
    }
    values
}
