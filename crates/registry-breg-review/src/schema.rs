// SPDX-License-Identifier: Apache-2.0

//! The generated JSON Schema for the review page runtime file.
//!
//! The schema is derived from the types `breg-review check` and
//! `breg-review serve` read, never written by hand. Regenerate the committed
//! document with:
//!
//! ```bash
//! cargo run -p registry-breg-review --features schema --example review-runtime-schema -- \
//!   --output products/breg/generated/review-runtime
//! ```

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::{RuntimeConfig, RUNTIME_API_VERSION, RUNTIME_KIND};

/// The `$id` of the runtime schema.
pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/breg/review-runtime/review-runtime.v1alpha1.schema.json";
/// The file name of the committed runtime schema.
pub const RUNTIME_SCHEMA_FILE: &str = "review-runtime.schema.json";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut runtime = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut runtime, "apiVersion", RUNTIME_API_VERSION);
    set_const(&mut runtime, "kind", RUNTIME_KIND);
    set_audit_destination_constraints(&mut runtime);
    set_scope_constraints(&mut runtime);
    Ok([(
        RUNTIME_SCHEMA_FILE,
        render(
            runtime,
            RUNTIME_SCHEMA_ID,
            "Base Registry Engine citizen review page runtime configuration",
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

/// The page requests `openid` on every sign-in, so `signIn.scopes` never
/// names it.
fn set_scope_constraints(schema: &mut Value) {
    if let Some(scopes) = schema
        .pointer_mut("/$defs/SignInConfig/properties/scopes")
        .and_then(Value::as_object_mut)
    {
        scopes.insert("not".to_owned(), json!({"contains": {"const": "openid"}}));
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
                Path::new(PRODUCT)
                    .join("generated/review-runtime")
                    .join(name),
            )
            .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted from its generator; regenerate it with \
                 `cargo run -p registry-breg-review --features schema --example \
                 review-runtime-schema -- --output products/breg/generated/review-runtime`"
            );
        }
    }

    /// The reader refuses `null` in every member this crate defines, so the
    /// schema never offers it as a value or a default there: an omitted member
    /// is described instead. The shared platform blocks are the platform's,
    /// embedded unchanged, so their shape is checked where they are generated.
    #[test]
    fn no_member_accepts_or_defaults_to_null() {
        fn visit(node: &Value, at: &str) {
            match node {
                Value::Object(object) => {
                    assert_ne!(
                        object.get("default"),
                        Some(&Value::Null),
                        "default null at {at}"
                    );
                    assert_ne!(
                        object.get("type"),
                        Some(&json!("null")),
                        "null type at {at}"
                    );
                    if let Some(Value::Array(types)) = object.get("type") {
                        assert!(!types.contains(&json!("null")), "nullable type at {at}");
                    }
                    for (key, value) in object {
                        visit(value, &format!("{at}/{key}"));
                    }
                }
                Value::Array(items) => {
                    for (index, value) in items.iter().enumerate() {
                        visit(value, &format!("{at}/{index}"));
                    }
                }
                _ => {}
            }
        }
        let canonical: Value = serde_json::from_str(include_str!(
            "../../../products/platform/generated/runtime-config-blocks.schema.json"
        ))
        .unwrap();
        let mut document: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        let definitions = document["$defs"].as_object_mut().unwrap();
        definitions.retain(|definition, _| canonical["$defs"].get(definition).is_none());
        assert!(!definitions.is_empty(), "the crate defines its own members");
        visit(&document, "");
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
        let example = Path::new(PRODUCT).join("examples/review-runtime/runtime.yaml");
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
            (
                "scopes: [address-correction:self]",
                "scopes: []",
                false,
            ),
            (
                "scopes: [address-correction:self]",
                "scopes: [address-correction:self, address-correction:self]",
                false,
            ),
            (
                "scopes: [address-correction:self]",
                "scopes: ['address correction']",
                false,
            ),
            (
                "scopes: [address-correction:self]",
                "scopes: [address-correction:self, openid]",
                false,
            ),
            (
                "clientId: citizen-review-page",
                "clientId: ''",
                false,
            ),
            ("targetField: address", "targetField: Address", false),
            (
                "resource: https://registry.example/base",
                "resource: 'urn:a b'",
                false,
            ),
            (
                "publicOrigin: https://review.example",
                "publicOrigin: review.example",
                false,
            ),
            (
                "path: /var/lib/breg-review/audit.jsonl",
                "path: audit.jsonl",
                false,
            ),
            (
                "hashKeyRef: secret:env/BREG_REVIEW_AUDIT_KEY",
                "hashKeyRef: inline",
                false,
            ),
            (
                "path: /var/lib/breg-review/audit.jsonl\n",
                "path: /var/lib/breg-review/audit.jsonl\nrateLimits:\n  perCitizen: { requestsPerMinute: 1000000, burst: 1 }\n",
                true,
            ),
            (
                "path: /var/lib/breg-review/audit.jsonl\n",
                "path: /var/lib/breg-review/audit.jsonl\nrateLimits:\n  perCitizen: { requestsPerMinute: 1000001, burst: 1 }\n",
                false,
            ),
            (
                "path: /var/lib/breg-review/audit.jsonl\n",
                "path: /var/lib/breg-review/audit.jsonl\nsession:\n  signInLifetimeSeconds: 59\n",
                false,
            ),
            (
                "path: /var/lib/breg-review/audit.jsonl\n",
                "path: /var/lib/breg-review/audit.jsonl\nsession:\n  maximumLifetimeSeconds: 86400\n",
                true,
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
