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
//! - a declared property, or a `patternProperties` entry proven to match the
//!   disclosed name, whose `type` shares no JSON type with the source
//!   field's;
//! - a value the source schema itself enumerates (an `enum` or `const`
//!   member, `null`, or a Boolean, alone or as the item of an array) that the
//!   source schema admits and the declared property, or a matching
//!   `patternProperties` entry, rejects.
//!
//! Every reported value is validated against the source schema first, so a
//! refusal names a value the source can really hold. Constraints that need an
//! invented value to disprove (lengths, patterns, formats, numeric bounds) and
//! properties that use `$ref` are not analysed; the runtime check still
//! applies to them.
//!
//! `allOf` requires every branch to validate the whole display object, so
//! each root `allOf` branch's own `properties`, `patternProperties`, and
//! `additionalProperties: false` provably apply too, and the same analysis
//! above is applied to each one in turn (bounded by `MAXIMUM_SCHEMA_DEPTH`),
//! with its mismatches labelled by the branch that proved them. `anyOf`,
//! `oneOf`, `not`, `if`/`then`/`else`, and `$ref` are not analysed this way,
//! since only one branch of those needs to hold; the runtime check still
//! applies to them.

use anyhow::{bail, Result};
use jsonschema::{Draft, Validator};
use registry_casework_core::{CaseworkProject, ReviewContextStrategy, SourcePolicy};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const MAXIMUM_SCHEMA_DEPTH: usize = 16;
/// The longest array witness built. A source's minItems is an unbounded
/// number, so an array it requires to be longer is left to the runtime check
/// rather than materialized here.
const MAXIMUM_WITNESS_ITEMS: u64 = 64;

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
    let mut mismatches = schema_mismatches(display, fields, projection, None);
    mismatches.extend(allof_branch_mismatches(display, fields, projection, 0));
    mismatches
}

/// The mismatches one object schema proves against the projected fields:
/// either the root display schema (`label_prefix` is `None`), or one `allOf`
/// branch of it (`label_prefix` names the branch, e.g. `allOf branch 1`).
fn schema_mismatches(
    schema: &Value,
    fields: &[Value],
    projection: &[String],
    label_prefix: Option<&str>,
) -> Vec<String> {
    let properties = schema.get("properties").and_then(Value::as_object);
    // additionalProperties is evaluated against its sibling properties and
    // patternProperties only, so an undeclared name is refused whatever other
    // keywords this schema carries, unless some patternProperties entry
    // admits it, or might: JSON Schema applies every patternProperties
    // schema whose pattern matches a name alongside the properties schema,
    // so a name no pattern can be proven to match is still refused, and a
    // name a pattern does match is checked against that pattern's schema
    // too.
    let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
    let prefix = label_prefix.map_or_else(String::new, |prefix| format!("{prefix}: "));
    let mut mismatches = Vec::new();
    for logical in projection {
        let Some(field) = fields.iter().find(|field| field["field"] == *logical) else {
            continue;
        };
        let (Some(api_name), source) = (field["apiName"].as_str(), &field["schema"]) else {
            continue;
        };
        let declared = properties.and_then(|properties| properties.get(api_name));
        let patterns = pattern_matches(schema, api_name);
        if declared.is_none() && closed && !patterns.admits {
            mismatches.push(format!(
                "{prefix}property {api_name} (source field {logical}) is not declared, and additionalProperties: false rejects every disclosure that carries it; the source describes it as {source}"
            ));
            continue;
        }
        if let Some(property) = declared {
            let label = format!("{prefix}property {api_name}");
            if let Some(mismatch) = property_mismatch(&label, logical, property, source) {
                mismatches.push(mismatch);
            }
        }
        for (pattern, pattern_schema) in patterns.definite {
            let label =
                format!("{prefix}patternProperties pattern {pattern} matching property {api_name}");
            if let Some(mismatch) = property_mismatch(&label, logical, pattern_schema, source) {
                mismatches.push(mismatch);
            }
        }
    }
    mismatches
}

/// The mismatches proved through each `allOf` branch of `schema`, recursing
/// into a branch's own `allOf` the same way, bounded by
/// `MAXIMUM_SCHEMA_DEPTH`. `allOf` requires every branch to validate the
/// whole display object, so a branch's own `properties`, `patternProperties`,
/// and `additionalProperties: false` provably apply, the same as the root
/// schema's do. A branch that is not an object schema contributes nothing,
/// except a `false` branch: it admits no instance at all, so it provably
/// rejects every disclosure of every projected field.
fn allof_branch_mismatches(
    schema: &Value,
    fields: &[Value],
    projection: &[String],
    depth: usize,
) -> Vec<String> {
    if depth > MAXIMUM_SCHEMA_DEPTH {
        return Vec::new();
    }
    let mut mismatches = Vec::new();
    for (index, branch) in schema
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let label = format!("allOf branch {}", index + 1);
        if branch == &Value::Bool(false) {
            for logical in projection {
                let Some(field) = fields.iter().find(|field| field["field"] == *logical) else {
                    continue;
                };
                let Some(api_name) = field["apiName"].as_str() else {
                    continue;
                };
                mismatches.push(format!(
                    "{label}: property {api_name} (source field {logical}) admits no value"
                ));
            }
            continue;
        }
        if !branch.is_object() {
            continue;
        }
        mismatches.extend(schema_mismatches(branch, fields, projection, Some(&label)));
        mismatches.extend(allof_branch_mismatches(
            branch,
            fields,
            projection,
            depth + 1,
        ));
    }
    mismatches
}

/// The `patternProperties` entries that bear on one disclosed API name.
struct PatternMatches<'a> {
    /// Whether some entry admits the name, or might: a pattern this crate's
    /// regex engine cannot compile is not disproved, so it counts here even
    /// though its schema is left to the runtime check, never applied by
    /// `definite`.
    admits: bool,
    /// The entries proven to match the name, each with its schema, so both
    /// can be checked the same way a declared property is.
    definite: Vec<(&'a str, &'a Value)>,
}

/// `patternProperties` patterns are ECMA-262 and matched unanchored (a
/// substring match is a match). This crate checks them with the `regex`
/// crate, which is not the same engine: syntax such as a lookaround
/// assertion is valid ECMA-262 but fails to compile here. A pattern this
/// engine cannot compile is not proof it cannot match, so it is treated as
/// possibly matching and left to the runtime check rather than false-refused
/// or force-applied.
fn pattern_matches<'a>(display: &'a Value, api_name: &str) -> PatternMatches<'a> {
    let mut admits = false;
    let mut definite = Vec::new();
    for (pattern, schema) in display
        .get("patternProperties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        match regex::Regex::new(pattern) {
            Ok(regex) if regex.is_match(api_name) => {
                admits = true;
                definite.push((pattern.as_str(), schema));
            }
            Ok(_) => {}
            Err(_) => admits = true,
        }
    }
    PatternMatches { admits, definite }
}

fn property_mismatch(
    label: &str,
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
        return Some(format!("{label} (source field {logical}) admits no value"));
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
                "{label} accepts type {}, but source field {logical} is {}",
                render_types(&displayed_types),
                render_types(&source_types),
            ));
        }
    }
    let maximum_bytes = source.get("x-registry-maxBytes").and_then(Value::as_u64);
    let mut rejected = Vec::new();
    for (value, witness_label) in witnesses(source, 0) {
        if admitted.is_valid(&value)
            && maximum_bytes.is_none_or(|maximum| encoded_len(&value) <= maximum)
            && !displayed.is_valid(&value)
            && !rejected.contains(&witness_label)
        {
            rejected.push(witness_label);
        }
    }
    if rejected.is_empty() {
        return None;
    }
    Some(format!(
        "{label} rejects {} that source field {logical} admits",
        rejected
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn compile(schema: &Value) -> Option<Validator> {
    Validator::options()
        .with_draft(Draft::Draft202012)
        .build(schema)
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
        let maximum = schema.get("maxItems").and_then(Value::as_u64);
        let unique = schema.get("uniqueItems") == Some(&Value::Bool(true));
        for item in &item_values {
            if minimum <= 1 {
                witnesses.push((Value::Array(vec![item.clone()]), item.clone()));
                continue;
            }
            if minimum > MAXIMUM_WITNESS_ITEMS || maximum.is_some_and(|maximum| minimum > maximum) {
                continue;
            }
            let mut array = vec![item.clone()];
            if unique {
                // Distinct items only: a length the source's own item
                // witnesses cannot fill distinctly is not provable, so it is
                // left unreported below rather than invented.
                array.extend(
                    item_values
                        .iter()
                        .filter(|other| *other != item)
                        .take(minimum as usize - 1)
                        .cloned(),
                );
            } else {
                // uniqueItems is not true, so the source can repeat this item
                // to reach minItems.
                array.extend(std::iter::repeat_n(item.clone(), minimum as usize - 1));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A source description's minItems is an unbounded number, so a witness
    // that repeats an item to reach it must not be materialized past a small
    // bound: a description with a huge minItems would otherwise exhaust
    // memory before the witness is ever checked.
    #[test]
    fn a_repeated_array_witness_is_not_built_past_the_witness_bound() {
        let schema =
            json!({"type":"array","items":{"type":"string","enum":["example"]},"minItems":100_000});

        let longest = witnesses(&schema, 0)
            .into_iter()
            .filter_map(|(value, _)| value.as_array().map(Vec::len))
            .max();

        assert_eq!(longest, None);
    }
}
