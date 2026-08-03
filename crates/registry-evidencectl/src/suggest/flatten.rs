//! Flattens a fully-resolved response schema into candidate projection
//! leaves.
//!
//! Every leaf pointer is in the extended projection form ADAPTER-API.md
//! defines: RFC 6901 segments (`~0`/`~1` escaped) for object members and the
//! reserved segment `*` for "every array element". Constructs the closed
//! schema subset cannot express as a selectable leaf (a real union via
//! `oneOf`/`anyOf`, an `allOf` merging more than one schema, an
//! `additionalProperties` schema, an untyped node, a pointer past the depth
//! limit) are skipped with a warning rather than failing the whole spec: one
//! exotic node should not block drafting from the rest of the operation.

use serde_json::Value;

use super::types::{CandidateLeaf, ResolvedSchema};

/// The extended-pointer form shares `get_path`'s 16-segment ceiling (see
/// `primitive-library.yaml`), so a projection pointer this stage produces
/// never needs truncating again once `*` is substituted for a numeric index.
const MAX_POINTER_SEGMENTS: usize = 16;

/// Flattens `schema` into its selectable leaves plus warnings for any
/// skipped, unsupported node. A leaf's `pointer` selects one scalar value
/// (or, through a `*` segment, every occurrence of one scalar value inside
/// an array); containers (objects, arrays) are never themselves leaves.
pub fn candidate_leaves(schema: &ResolvedSchema) -> (Vec<CandidateLeaf>, Vec<String>) {
    let mut leaves = Vec::new();
    let mut warnings = Vec::new();
    walk(&schema.0, String::new(), 0, &mut leaves, &mut warnings);
    (leaves, warnings)
}

fn walk(
    node: &Value,
    pointer: String,
    depth: usize,
    leaves: &mut Vec<CandidateLeaf>,
    warnings: &mut Vec<String>,
) {
    let Some(object) = node.as_object() else {
        warnings.push(format!(
            "schema at `{}` is not an object node; skipped",
            display_pointer(&pointer)
        ));
        return;
    };

    if object.contains_key("oneOf") || object.contains_key("anyOf") {
        warnings.push(format!(
            "unsupported oneOf/anyOf union at `{}`; skipped",
            display_pointer(&pointer)
        ));
        return;
    }
    if let Some(members) = object.get("allOf").and_then(Value::as_array) {
        // A single-member allOf is the common code-generation idiom for
        // attaching shared metadata via $ref (already inlined by this
        // point); it is equivalent to its one member. Anything wider is a
        // real merge this stage does not attempt to compute.
        return if members.len() == 1 {
            walk(&members[0], pointer, depth, leaves, warnings)
        } else {
            warnings.push(format!(
                "unsupported allOf with {} members at `{}`; skipped",
                members.len(),
                display_pointer(&pointer)
            ));
        };
    }

    let Some((base_type, nullable)) = resolve_type(object) else {
        warnings.push(format!(
            "schema at `{}` has no single supported type (missing `type`, or a multi-type union beyond `[T, \"null\"]`); skipped",
            display_pointer(&pointer)
        ));
        return;
    };

    match base_type.as_str() {
        "object" => walk_object(object, &pointer, depth, leaves, warnings),
        "array" => walk_array(object, &pointer, depth, leaves, warnings),
        scalar => leaves.push(CandidateLeaf {
            pointer,
            type_label: type_label(scalar, object),
            nullable,
            description: object
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string),
        }),
    }
}

fn walk_object(
    object: &serde_json::Map<String, Value>,
    pointer: &str,
    depth: usize,
    leaves: &mut Vec<CandidateLeaf>,
    warnings: &mut Vec<String>,
) {
    if object
        .get("additionalProperties")
        .is_some_and(Value::is_object)
    {
        warnings.push(format!(
            "unsupported additionalProperties schema at `{}`; unnamed extra members cannot be named as projection pointers",
            display_pointer(pointer)
        ));
    }
    if object.contains_key("patternProperties") {
        warnings.push(format!(
            "unsupported patternProperties at `{}`; skipped",
            display_pointer(pointer)
        ));
    }
    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        warnings.push(format!(
            "object at `{}` has no declared properties; nothing to select",
            display_pointer(pointer)
        ));
        return;
    };
    if depth >= MAX_POINTER_SEGMENTS {
        warnings.push(format!(
            "pointer depth limit ({MAX_POINTER_SEGMENTS} segments) reached at `{}`; not descending further",
            display_pointer(pointer)
        ));
        return;
    }
    for (member_name, member_schema) in properties {
        let child_pointer = format!("{pointer}/{}", escape_pointer_segment(member_name));
        walk(member_schema, child_pointer, depth + 1, leaves, warnings);
    }
}

fn walk_array(
    object: &serde_json::Map<String, Value>,
    pointer: &str,
    depth: usize,
    leaves: &mut Vec<CandidateLeaf>,
    warnings: &mut Vec<String>,
) {
    let Some(items) = object.get("items") else {
        warnings.push(format!(
            "array at `{}` has no `items` schema; skipped",
            display_pointer(pointer)
        ));
        return;
    };
    if depth >= MAX_POINTER_SEGMENTS {
        warnings.push(format!(
            "pointer depth limit ({MAX_POINTER_SEGMENTS} segments) reached at `{}`; not descending further",
            display_pointer(pointer)
        ));
        return;
    }
    walk(items, format!("{pointer}/*"), depth + 1, leaves, warnings);
}

/// Resolves a schema node's JSON Schema `type` to `(base type, nullable)`.
/// Accepts a bare string type, or the closed subset's only admitted union:
/// an array pairing exactly one non-`null` type with `"null"`. Any other
/// shape (missing `type`, or a genuine multi-type union) is not represented
/// and yields `None`.
fn resolve_type(object: &serde_json::Map<String, Value>) -> Option<(String, bool)> {
    match object.get("type") {
        Some(Value::String(type_name)) => Some((type_name.clone(), false)),
        Some(Value::Array(type_names)) => {
            let mut non_null = Vec::new();
            let mut has_null = false;
            for entry in type_names {
                match entry.as_str()? {
                    "null" => has_null = true,
                    other => non_null.push(other),
                }
            }
            if non_null.len() == 1 {
                Some((non_null[0].to_string(), has_null))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A human label for a leaf's type: `string (date)` when a string carries a
/// `format`, otherwise the bare JSON Schema type name.
fn type_label(base_type: &str, object: &serde_json::Map<String, Value>) -> String {
    if base_type == "string" {
        if let Some(format) = object.get("format").and_then(Value::as_str) {
            return format!("string ({format})");
        }
    }
    base_type.to_string()
}

/// Escapes an object member name into one RFC 6901 pointer segment: `~` and
/// `/` are escaped in that order (escaping `/` first would double-escape a
/// `~` produced by escaping a literal `~`).
fn escape_pointer_segment(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

fn display_pointer(pointer: &str) -> &str {
    if pointer.is_empty() {
        "(root)"
    } else {
        pointer
    }
}
