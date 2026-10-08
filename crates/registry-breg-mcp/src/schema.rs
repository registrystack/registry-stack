// SPDX-License-Identifier: Apache-2.0

//! The generated JSON Schema for the gateway runtime file.
//!
//! The schema is derived from the types `breg-mcp check` and `breg-mcp serve`
//! read, never written by hand. Regenerate the committed document with:
//!
//! ```bash
//! cargo run -p registry-breg-mcp --features schema --example mcp-runtime-schema -- \
//!   --output products/breg/generated/mcp-runtime
//! ```

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::{RuntimeConfig, RUNTIME_API_VERSION, RUNTIME_KIND};

/// The `$id` of the runtime schema.
pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/breg/mcp-runtime/mcp-runtime.v1alpha1.schema.json";
/// The file name of the committed runtime schema.
pub const RUNTIME_SCHEMA_FILE: &str = "mcp-runtime.schema.json";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut runtime = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut runtime, "apiVersion", RUNTIME_API_VERSION);
    set_const(&mut runtime, "kind", RUNTIME_KIND);
    set_audit_destination_constraints(&mut runtime);
    Ok([(
        RUNTIME_SCHEMA_FILE,
        render(
            runtime,
            RUNTIME_SCHEMA_ID,
            "Base Registry Engine MCP gateway runtime configuration",
        )?,
    )]
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

/// State the shape `AuditConfig::destination` requires: a `file`
/// destination, the default, names an absolute `path`, and `stdout` takes
/// none of the file-only settings. The rotation and retention bounds are
/// the platform writer's and come from the member types.
fn set_audit_destination_constraints(schema: &mut Value) {
    if let Some(member) = schema
        .pointer_mut("/$defs/AuditConfig/properties/path")
        .and_then(Value::as_object_mut)
    {
        member.insert(
            "pattern".to_owned(),
            Value::String(registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN.to_owned()),
        );
    }
    if let Some(audit) = schema
        .pointer_mut("/$defs/AuditConfig")
        .and_then(Value::as_object_mut)
    {
        audit.insert(
            "if".to_owned(),
            json!({
                "required": ["destination"],
                "properties": {"destination": {"const": "stdout"}}
            }),
        );
        audit.insert(
            "then".to_owned(),
            json!({
                "not": {"anyOf": [
                    {"required": ["path"]},
                    {"required": ["rotateBytes"]},
                    {"required": ["retentionDays"]}
                ]}
            }),
        );
        audit.insert("else".to_owned(), json!({"required": ["path"]}));
    }
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
    use std::path::Path;

    use jsonschema::{Draft, JSONSchema};
    use registry_platform_yaml::Reader;

    use super::*;
    use crate::config::{check_runtime, tests::document};

    const PRODUCT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/breg");

    fn validator() -> JSONSchema {
        let schema: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("the schema compiles as Draft 2020-12: {error}"))
    }

    fn as_json(bytes: &[u8]) -> Value {
        Reader::new("runtime.yaml")
            .scan(bytes)
            .expect("the file is YAML")
            .expect("the file is not empty")
            .to_json_value()
    }

    /// Whether the reader accepts `text`, offline and with every expression
    /// substituted.
    fn reader_accepts(text: &str) -> bool {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        check_runtime(&path, true).diagnostics.is_empty()
    }

    #[test]
    fn committed_schemas_match_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(
                Path::new(PRODUCT).join("generated/mcp-runtime").join(name),
            )
            .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted from its generator; regenerate it with \
                 `cargo run -p registry-breg-mcp --features schema --example mcp-runtime-schema \
                 -- --output products/breg/generated/mcp-runtime`"
            );
        }
    }

    #[test]
    fn shared_blocks_are_embedded_unchanged() {
        let canonical: Value = serde_json::from_str(include_str!(
            "../../../products/platform/generated/runtime-config-blocks.schema.json"
        ))
        .unwrap();
        let document: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        let definitions = document["$defs"].as_object().unwrap();
        let mut shared = 0;
        for (definition, schema) in definitions {
            if let Some(platform) = canonical["$defs"].get(definition) {
                assert_eq!(schema, platform, "changed shared block {definition}");
                shared += 1;
            }
        }
        assert!(shared > 0, "the runtime schema embeds the shared blocks");
    }

    #[test]
    fn the_committed_example_is_accepted_by_schema_and_reader() {
        let example = Path::new(PRODUCT).join("examples/mcp-runtime/runtime.yaml");
        let check = check_runtime(&example.canonicalize().unwrap(), false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
        let bytes = std::fs::read(&example).unwrap();
        assert!(validator().is_valid(&as_json(&bytes)));
        assert!(validator().is_valid(&as_json(document().as_bytes())));
    }

    #[test]
    fn runtime_members_are_judged_alike_by_schema_and_reader() {
        let validator = validator();
        for (from, to, accepted) in [
            ("algorithms: [EdDSA, ES256]", "algorithms: []", false),
            ("algorithms: [EdDSA, ES256]", "algorithms: [HS256]", false),
            (
                "allowedClients: [chat-host]",
                "allowedClients: [chat-host, chat-host]",
                false,
            ),
            (
                "requiredScopes: [address-correction:self]",
                "requiredScopes: ['address correction']",
                false,
            ),
            ("burst: 10", "burst: 0", false),
            ("burst: 10", "burst: 1000000", true),
            ("burst: 10", "burst: 1000001", false),
            (
                "accessProfile: citizen-agent",
                "accessProfile: Citizen",
                false,
            ),
            (
                "audience: urn:breg:citizen-address-correction",
                "audience: 'urn:breg:a b'",
                false,
            ),
            ("name: Address correction", "name: ' '", false),
            ("destination: file", "destination: stdout", false),
            (
                "path: /var/lib/breg-mcp/audit/audit.jsonl",
                "path: audit.jsonl",
                false,
            ),
            (
                "hashKeyRef: secret:file/audit-key",
                "hashKeyRef: inline",
                false,
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            assert_eq!(reader_accepts(&text), accepted, "reader: {to}");
            assert_eq!(
                validator.is_valid(&as_json(text.as_bytes())),
                accepted,
                "schema: {to}"
            );
        }
    }
}
