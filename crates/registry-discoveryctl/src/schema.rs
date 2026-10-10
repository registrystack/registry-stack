// SPDX-License-Identifier: Apache-2.0

//! Generated JSON Schemas for the Discovery origins, evidence mapping, and
//! runtime files.
//!
//! Each schema is derived from the types `discoveryctl check` and
//! `discovery serve` read, never written by hand. Regenerate the committed
//! documents in `products/discovery/schemas` with:
//!
//! ```bash
//! cargo run -p registry-discoveryctl --features schema --example discovery-schema -- \
//!   --output products/discovery/schemas
//! ```
//!
//! The index schema beside them is written by hand: the index is generated
//! by `discoveryctl package`, and the schema contract test holds its schema to
//! the parser.

use std::collections::BTreeMap;

use registry_discovery::{RuntimeConfig, RUNTIME_API_VERSION, RUNTIME_KIND};
use serde_json::{json, Map, Value};

use crate::project::{
    AuthoredEvidenceMapping, OriginsFile, MAPPING_API_VERSION, MAPPING_KIND, ORIGINS_API_VERSION,
    ORIGINS_KIND,
};

/// The `$id` of the origins schema.
pub const ORIGINS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/discovery/origins/origins.v1alpha1.schema.json";
/// The `$id` of the evidence mapping schema.
pub const MAPPING_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/discovery/evidence-mapping/evidence-mapping.v1alpha1.schema.json";
/// The `$id` of the runtime schema.
pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/discovery/runtime/runtime.v1alpha1.schema.json";

pub const ORIGINS_SCHEMA_FILE: &str = "origins.schema.json";
pub const MAPPING_SCHEMA_FILE: &str = "evidence-mapping.schema.json";
pub const RUNTIME_SCHEMA_FILE: &str = "runtime.schema.json";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut origins = serde_json::to_value(schemars::schema_for!(OriginsFile))?;
    set_const(&mut origins, "apiVersion", ORIGINS_API_VERSION);
    set_const(&mut origins, "kind", ORIGINS_KIND);
    let mut mapping = serde_json::to_value(schemars::schema_for!(AuthoredEvidenceMapping))?;
    set_const(&mut mapping, "apiVersion", MAPPING_API_VERSION);
    set_const(&mut mapping, "kind", MAPPING_KIND);
    let mut runtime = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    install_runtime_constraints(&mut runtime);
    Ok([
        (
            ORIGINS_SCHEMA_FILE,
            render(
                origins,
                ORIGINS_SCHEMA_ID,
                "Registry Discovery approved origins",
            )?,
        ),
        (
            MAPPING_SCHEMA_FILE,
            render(
                mapping,
                MAPPING_SCHEMA_ID,
                "Registry Discovery requirement-to-evidence-type mapping",
            )?,
        ),
        (
            RUNTIME_SCHEMA_FILE,
            render(
                runtime,
                RUNTIME_SCHEMA_ID,
                "Registry Discovery runtime configuration",
            )?,
        ),
    ]
    .into())
}

/// The derived schema with its `$schema`, `$id`, and `title`, pretty printed
/// with a final newline.
fn render(derived: Value, id: &str, title: &str) -> Result<String, serde_json::Error> {
    let Value::Object(mut object) = derived else {
        unreachable!("schemars derives a schema object for a struct")
    };
    object.insert("$schema".to_owned(), Value::String(DRAFT.to_owned()));
    object.insert("$id".to_owned(), Value::String(id.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok(rendered)
}

/// State in the schema what the runtime enforces beyond its types: the
/// envelope values, a listener address the runtime can bind, and a package
/// root with no `.` or `..` segment. The `RuntimeListener` and shared
/// `PackageConfig` definitions stay unchanged; an `allOf` branch beside each
/// reference narrows the block where the Discovery runtime uses it.
fn install_runtime_constraints(schema: &mut Value) {
    set_const(schema, "apiVersion", RUNTIME_API_VERSION);
    set_const(schema, "kind", RUNTIME_KIND);
    narrow(
        schema,
        "listener",
        json!({
            "bind": {
                "allOf": [
                    {"$ref": "#/$defs/socketPort"},
                    {"anyOf": [
                        {"$ref": "#/$defs/ipv4SocketHost"},
                        {"$ref": "#/$defs/ipv6HexSocketHost"},
                        {"$ref": "#/$defs/ipv6MixedSocketHost"}
                    ]}
                ]
            }
        }),
    );
    narrow(
        schema,
        "package",
        json!({"root": {"not": {"pattern": "(^|/)\\.{1,2}(/|$)"}}}),
    );
    if let Some(definitions) = schema.get_mut("$defs").and_then(Value::as_object_mut) {
        definitions.extend(socket_definitions());
    }
}

/// Narrow the members of the shared block at `property` with one `allOf`
/// branch, leaving the referenced definition unchanged.
fn narrow(schema: &mut Value, property: &str, members: Value) {
    if let Some(member) = schema
        .pointer_mut(&format!("/properties/{property}"))
        .and_then(Value::as_object_mut)
    {
        member.insert("allOf".to_owned(), json!([{ "properties": members }]));
    }
}

/// The address grammar Rust's `SocketAddr` parser accepts: an IPv4 or
/// bracketed IPv6 literal and a decimal port.
const SOCKET_DEFINITIONS: &str = r#"{
    "socketPort": {
        "description": "A decimal u16 port, including zero and Rust-compatible leading zeroes.",
        "pattern": ":0*(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
    },
    "ipv4SocketHost": {
        "description": "Four canonical decimal IPv4 octets followed by a decimal port.",
        "pattern": "^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0):[0-9]+$"
    },
    "ipv6HexSocketHost": {
        "description": "A bracketed hexadecimal IPv6 literal, including every RFC 3986 compression position, followed by a decimal port.",
        "pattern": "^\\[(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))\\]:[0-9]+$"
    },
    "ipv6MixedSocketHost": {
        "description": "A bracketed IPv6 literal whose final 32 bits use canonical dotted-decimal IPv4 notation, followed by a decimal port.",
        "pattern": "^\\[(?:(?:[0-9A-Fa-f]{1,4}:){6}|::(?:[0-9A-Fa-f]{1,4}:){5}|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}|(?:(?:[0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}|(?:(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}|(?:(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:|(?:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})?::)(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)\\]:[0-9]+$"
    }
}"#;

fn socket_definitions() -> Map<String, Value> {
    serde_json::from_str(SOCKET_DEFINITIONS).expect("the socket definitions are a JSON object")
}

fn set_const(schema: &mut Value, property: &str, value: &str) {
    if let Some(member) = schema
        .pointer_mut(&format!("/properties/{property}"))
        .and_then(Value::as_object_mut)
    {
        member.insert("const".to_owned(), Value::String(value.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMAS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/discovery/schemas"
    );

    #[test]
    fn committed_schemas_match_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(std::path::Path::new(SCHEMAS).join(name))
                .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted from its generator; regenerate it with \
                 `cargo run -p registry-discoveryctl --features schema --example \
                 discovery-schema -- --output products/discovery/schemas`"
            );
        }
    }

    #[test]
    fn shared_blocks_are_embedded_unchanged() {
        let canonical: Value = serde_json::from_str(include_str!(
            "../../../products/platform/generated/runtime-config-blocks.schema.json"
        ))
        .unwrap();
        for (name, document) in schema_documents().unwrap() {
            let document: Value = serde_json::from_str(&document).unwrap();
            for (definition, schema) in document["$defs"].as_object().unwrap() {
                if let Some(shared) = canonical["$defs"].get(definition) {
                    assert_eq!(schema, shared, "{name} changed shared block {definition}");
                }
            }
        }
    }
}
