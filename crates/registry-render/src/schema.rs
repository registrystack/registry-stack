//! Generated JSON Schemas for the Render bundle manifest, label tables, and
//! runtime file.
//!
//! Each schema is derived from the types `registry-render check` and
//! `registry-render serve` read, never written by hand. Regenerate the
//! committed documents in `products/render/schemas` with:
//!
//! ```bash
//! cargo run -p registry-render --features schema --example render-schema -- \
//!   --output products/render/schemas
//! ```

use std::collections::BTreeMap;

use registry_platform_yaml::LocalId;
use schemars::JsonSchema as _;
use serde_json::{json, Map, Value};

use crate::labels::{LabelsFile, LABELS_API_VERSION, LABELS_KIND};
use crate::manifest::{ManifestFile, MANIFEST_API_VERSION, MANIFEST_KIND};
use crate::runtime::{RenderRuntime, RUNTIME_API_VERSION, RUNTIME_KIND};

/// The `$id` of the bundle manifest schema.
pub const BUNDLE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/render/bundle/bundle.v1alpha1.schema.json";
/// The `$id` of the label table schema.
pub const LABELS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/render/labels/labels.v1alpha1.schema.json";
/// The `$id` of the runtime schema.
pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/render/runtime/runtime.v1alpha1.schema.json";

pub const BUNDLE_SCHEMA_FILE: &str = "bundle.schema.json";
pub const LABELS_SCHEMA_FILE: &str = "labels.schema.json";
pub const RUNTIME_SCHEMA_FILE: &str = "runtime.schema.json";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut bundle = serde_json::to_value(schemars::schema_for!(ManifestFile))?;
    install_bundle_constraints(&mut bundle);
    let mut labels = serde_json::to_value(schemars::schema_for!(LabelsFile))?;
    install_labels_constraints(&mut labels)?;
    let mut runtime = serde_json::to_value(schemars::schema_for!(RenderRuntime))?;
    install_runtime_constraints(&mut runtime);
    Ok([
        (
            BUNDLE_SCHEMA_FILE,
            render(bundle, BUNDLE_SCHEMA_ID, "Registry Render bundle manifest")?,
        ),
        (
            LABELS_SCHEMA_FILE,
            render(labels, LABELS_SCHEMA_ID, "Registry Render label table")?,
        ),
        (
            RUNTIME_SCHEMA_FILE,
            render(
                runtime,
                RUNTIME_SCHEMA_ID,
                "Registry Render runtime configuration",
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

/// State in the schema what `read_manifest` enforces beyond the types: the
/// envelope values, and an entry and a schema file that are relative paths
/// inside the bundle with the right suffix.
fn install_bundle_constraints(schema: &mut Value) {
    set_const(schema, "apiVersion", MANIFEST_API_VERSION);
    set_const(schema, "kind", MANIFEST_KIND);
    for (property, suffix) in [("entryFile", "\\.typ$"), ("schemaFile", "\\.json$")] {
        set_definition_property(
            schema,
            "DocumentFile",
            property,
            "pattern",
            Value::String(suffix.to_owned()),
        );
        set_definition_property(
            schema,
            "DocumentFile",
            property,
            "not",
            json!({"pattern": "^/|\\.\\."}),
        );
    }
}

/// State in the schema what `read_labels` enforces beyond the types: the
/// envelope values, and label keys that are local identifiers. The derived
/// schema inlines the key pattern; the key type is named instead, so the
/// table reads as a map keyed by `LocalId` like every other keyed map.
fn install_labels_constraints(schema: &mut Value) -> Result<(), serde_json::Error> {
    set_const(schema, "apiVersion", LABELS_API_VERSION);
    set_const(schema, "kind", LABELS_KIND);
    let local_id = serde_json::to_value(LocalId::json_schema(
        &mut schemars::SchemaGenerator::default(),
    ))?;
    if let Some(labels) = schema
        .pointer_mut("/properties/labels")
        .and_then(Value::as_object_mut)
    {
        labels.remove("patternProperties");
        labels.insert(
            "propertyNames".to_owned(),
            json!({"$ref": "#/$defs/LocalId"}),
        );
        labels.insert("additionalProperties".to_owned(), json!({"type": "string"}));
    }
    if let Value::Object(object) = schema {
        object
            .entry("$defs")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("$defs is an object")
            .insert("LocalId".to_owned(), local_id);
    }
    Ok(())
}

/// State in the schema what the runtime enforces beyond its types: the
/// envelope values, a listener address the runtime can bind, a package root
/// with no `.` or `..` segment, and the audit destination shape. The shared
/// `PackageConfig` definition stays unchanged; an `allOf` branch beside its
/// reference narrows the block where Render uses it.
fn install_runtime_constraints(schema: &mut Value) {
    set_const(schema, "apiVersion", RUNTIME_API_VERSION);
    set_const(schema, "kind", RUNTIME_KIND);
    set_definition_property(
        schema,
        "ListenerRuntime",
        "bind",
        "allOf",
        json!([
            {"$ref": "#/$defs/socketPort"},
            {"anyOf": [
                {"$ref": "#/$defs/ipv4SocketHost"},
                {"$ref": "#/$defs/ipv6HexSocketHost"},
                {"$ref": "#/$defs/ipv6MixedSocketHost"}
            ]}
        ]),
    );
    if let Some(member) = schema
        .pointer_mut("/properties/package")
        .and_then(Value::as_object_mut)
    {
        member.insert(
            "allOf".to_owned(),
            json!([{"properties": {"root": {"not": {"pattern": "(^|/)\\.{1,2}(/|$)"}}}}]),
        );
    }
    set_audit_destination_constraints(schema);
    if let Some(definitions) = schema.get_mut("$defs").and_then(Value::as_object_mut) {
        definitions.extend(socket_definitions());
    }
}

/// State the shape `AuditRuntime::destination` requires: a `file`
/// destination, the default, names an absolute `path`, and `stdout` takes
/// none of the file-only settings. The rotation and retention bounds are
/// the platform writer's and come from the member types.
fn set_audit_destination_constraints(schema: &mut Value) {
    set_definition_property(
        schema,
        "AuditRuntime",
        "path",
        "pattern",
        Value::String(registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN.to_owned()),
    );
    if let Some(audit) = schema
        .pointer_mut("/$defs/AuditRuntime")
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

fn set_definition_property(
    schema: &mut Value,
    definition: &str,
    property: &str,
    keyword: &str,
    value: Value,
) {
    if let Some(member) = schema
        .pointer_mut(&format!("/$defs/{definition}/properties/{property}"))
        .and_then(Value::as_object_mut)
    {
        member.insert(keyword.to_owned(), value);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use jsonschema::{Draft, JSONSchema};
    use registry_platform_yaml::Reader;

    use super::*;
    use crate::labels::read_labels;
    use crate::manifest::read_manifest;
    use crate::runtime::check_runtime;

    const PRODUCT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/render");

    fn validator(file: &str) -> JSONSchema {
        let schema: Value = serde_json::from_str(&schema_documents().unwrap()[file]).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{file} compiles as Draft 2020-12: {error}"))
    }

    fn as_json(file: &str, bytes: &[u8]) -> Value {
        Reader::new(file)
            .scan(bytes)
            .expect("the file is YAML")
            .expect("the file is not empty")
            .to_json_value()
    }

    /// Replace the member at `pointer`, or remove it when `value` is none.
    fn with(document: &Value, pointer: &str, value: Option<Value>) -> Value {
        let mut document = document.clone();
        let (parent, member) = pointer.rsplit_once('/').unwrap();
        let parent = document
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap();
        match value {
            Some(value) => parent.insert(member.to_owned(), value),
            None => parent.remove(member),
        };
        document
    }

    #[test]
    fn committed_schemas_match_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(Path::new(PRODUCT).join("schemas").join(name))
                .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted from its generator; regenerate it with \
                 `cargo run -p registry-render --features schema --example render-schema -- \
                 --output products/render/schemas`"
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
            let Some(definitions) = document["$defs"].as_object() else {
                continue;
            };
            for (definition, schema) in definitions {
                if let Some(shared) = canonical["$defs"].get(definition) {
                    assert_eq!(schema, shared, "{name} changed shared block {definition}");
                }
            }
        }
    }

    #[test]
    fn every_committed_bundle_file_and_example_is_accepted_by_schema_and_reader() {
        let bundle = validator(BUNDLE_SCHEMA_FILE);
        let labels = validator(LABELS_SCHEMA_FILE);
        let mut checked = 0;
        for entry in std::fs::read_dir(Path::new(PRODUCT).join("bundles")).unwrap() {
            let root = entry.unwrap().path();
            let manifest = std::fs::read(root.join("manifest.yaml")).unwrap();
            read_manifest("manifest.yaml", &manifest).expect("the reader accepts the manifest");
            assert!(
                bundle.is_valid(&as_json("manifest.yaml", &manifest)),
                "{}",
                root.display()
            );
            for table in std::fs::read_dir(root.join("labels")).unwrap() {
                let table = table.unwrap().path();
                let bytes = std::fs::read(&table).unwrap();
                read_labels("labels.yaml", &bytes).expect("the reader accepts the table");
                assert!(
                    labels.is_valid(&as_json("labels.yaml", &bytes)),
                    "{}",
                    table.display()
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "the bundles carry label tables");

        let example = Path::new(PRODUCT).join("examples/runtime.yaml");
        let check = check_runtime(&example.canonicalize().unwrap(), false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
        let bytes = std::fs::read(&example).unwrap();
        assert!(validator(RUNTIME_SCHEMA_FILE).is_valid(&as_json("runtime.yaml", &bytes)));
    }

    #[test]
    fn bundle_file_paths_are_judged_alike_by_schema_and_reader() {
        let validator = validator(BUNDLE_SCHEMA_FILE);
        let manifest = |member: &str, path: &str| {
            json!({
                "apiVersion": MANIFEST_API_VERSION,
                "kind": MANIFEST_KIND,
                "bundleVersion": 1,
                "documents": [{"id": "letter", "version": 1, "entryFile": "templates/letter.typ",
                    member: path}]
            })
        };
        for (member, path, accepted) in [
            ("entryFile", "templates/letter.typ", true),
            ("entryFile", ".typ", true),
            ("entryFile", "templates/letter.txt", false),
            ("entryFile", "/templates/letter.typ", false),
            ("entryFile", "../letter.typ", false),
            ("entryFile", "templates/a..b.typ", false),
            ("schemaFile", "schemas/letter.schema.json", true),
            ("schemaFile", "schemas/letter.yaml", false),
            ("schemaFile", "/schemas/letter.json", false),
            ("schemaFile", "../letter.json", false),
        ] {
            let document = manifest(member, path);
            let text = serde_json::to_string(&document).unwrap();
            assert_eq!(
                read_manifest("manifest.yaml", text.as_bytes()).is_ok(),
                accepted,
                "reader, {member}: {path}"
            );
            assert_eq!(
                validator.is_valid(&document),
                accepted,
                "schema, {member}: {path}"
            );
        }
    }

    #[test]
    fn versions_are_judged_alike_by_schema_and_reader() {
        let validator = validator(BUNDLE_SCHEMA_FILE);
        for (bundle_version, version, accepted) in [
            (json!(1), json!(1), true),
            (json!(u32::MAX), json!(u32::MAX), true),
            (json!(0), json!(1), false),
            (json!(1), json!(0), false),
            (json!(u64::from(u32::MAX) + 1), json!(1), false),
            (json!(1), json!("1"), false),
        ] {
            let document = json!({
                "apiVersion": MANIFEST_API_VERSION,
                "kind": MANIFEST_KIND,
                "bundleVersion": bundle_version,
                "documents": [{"id": "letter", "version": version,
                    "entryFile": "templates/letter.typ"}]
            });
            let text = serde_json::to_string(&document).unwrap();
            assert_eq!(
                read_manifest("manifest.yaml", text.as_bytes()).is_ok(),
                accepted,
                "reader: {bundle_version}, {version}"
            );
            assert_eq!(
                validator.is_valid(&document),
                accepted,
                "schema: {bundle_version}, {version}"
            );
        }
    }

    #[test]
    fn label_keys_and_text_are_judged_alike_by_schema_and_reader() {
        let validator = validator(LABELS_SCHEMA_FILE);
        let longest = format!("a{}", "b".repeat(63));
        let too_long = format!("a{}", "b".repeat(64));
        for (labels, accepted) in [
            (json!({"title": "Receipt", "call-center": "Call us"}), true),
            (json!({longest: "Text"}), true),
            (json!({too_long: "Text"}), false),
            (json!({"Title": "Receipt"}), false),
            (json!({"count": 3}), false),
        ] {
            let document = json!({
                "apiVersion": LABELS_API_VERSION,
                "kind": LABELS_KIND,
                "labels": labels
            });
            let text = serde_json::to_string(&document).unwrap();
            assert_eq!(
                read_labels("labels.yaml", text.as_bytes()).is_ok(),
                accepted,
                "reader: {labels}"
            );
            assert_eq!(validator.is_valid(&document), accepted, "schema: {labels}");
        }
    }

    #[test]
    fn runtime_members_are_judged_alike_by_schema_and_reader() {
        let validator = validator(RUNTIME_SCHEMA_FILE);
        let example_path = Path::new(PRODUCT).join("examples/runtime.yaml");
        let example = as_json("runtime.yaml", &std::fs::read(example_path).unwrap());
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        let stdout = with(&example, "/audit/destination", Some(json!("stdout")));
        let stdout = with(&stdout, "/audit/path", None);
        let cases = [
            ("/listener/bind", Some(json!("[::1]:8080")), true),
            ("/listener/bind", Some(json!("10.0.0.5:0")), true),
            ("/listener/bind", Some(json!("localhost:8080")), false),
            ("/listener/bind", Some(json!("127.0.0.1")), false),
            (
                "/listener/shutdownGraceMilliseconds",
                Some(json!(1_000)),
                true,
            ),
            (
                "/listener/shutdownGraceMilliseconds",
                Some(json!(999)),
                false,
            ),
            (
                "/listener/shutdownGraceMilliseconds",
                Some(json!(3_600_001)),
                false,
            ),
            ("/listener/extra", Some(json!(1)), false),
            ("/package/root", Some(json!("package")), false),
            ("/package/root", Some(json!("/var/../package")), false),
            ("/package/expectedDigest", Some(json!("sha256:abc")), false),
            ("/auth/apiKeyRef", Some(json!("secret:vault/key")), false),
            (
                "/limits",
                Some(json!({"renderTimeoutSeconds": 3_600})),
                true,
            ),
            ("/limits", Some(json!({"renderTimeoutSeconds": 0})), false),
            (
                "/limits",
                Some(json!({"maximumOutputBytes": 8_388_609})),
                false,
            ),
            (
                "/limits",
                Some(json!({"maximumConcurrentRenders": 65})),
                false,
            ),
            ("/audit/path", Some(json!("audit.jsonl")), false),
            (
                "/audit/path",
                Some(json!("/var/audit/../render.jsonl")),
                false,
            ),
            ("/audit/path", None, false),
            ("/audit/rotateBytes", Some(json!(1_048_576)), true),
            ("/audit/rotateBytes", Some(json!(1_048_575)), false),
            ("/audit/retentionDays", Some(json!(36_500)), true),
            ("/audit/retentionDays", Some(json!(0)), false),
            ("/audit/retentionDays", Some(json!(36_501)), false),
            ("/audit/retainDays", Some(json!(90)), false),
        ];
        let stdout_cases = [
            ("/audit/destination", Some(json!("stdout")), true),
            ("/audit/path", Some(json!("/var/audit/render.jsonl")), false),
            ("/audit/rotateBytes", Some(json!(1_048_576)), false),
            ("/audit/retentionDays", Some(json!(90)), false),
        ];
        let documents = cases
            .into_iter()
            .map(|(pointer, value, accepted)| (with(&example, pointer, value), accepted))
            .chain(
                stdout_cases
                    .into_iter()
                    .map(|(pointer, value, accepted)| (with(&stdout, pointer, value), accepted)),
            );
        for (document, accepted) in documents {
            std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
            let check = check_runtime(&path, false);
            assert_eq!(
                check.diagnostics.is_empty(),
                accepted,
                "reader: {document}\n{:?}",
                check.diagnostics
            );
            assert_eq!(
                validator.is_valid(&document),
                accepted,
                "schema: {document}"
            );
        }
    }

    /// The rules a schema cannot state are left to the reader, and the
    /// member's description names them (CFG-SCHEMA-9).
    #[test]
    fn a_public_bind_and_an_undeclared_provider_are_refused_by_the_reader_alone() {
        let validator = validator(RUNTIME_SCHEMA_FILE);
        let example_path = Path::new(PRODUCT).join("examples/runtime.yaml");
        let example = as_json("runtime.yaml", &std::fs::read(example_path).unwrap());
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        for (pointer, value, code) in [
            (
                "/listener/bind",
                "0.0.0.0:8080",
                "render.runtime.public-bind",
            ),
            (
                "/listener/bind",
                "203.0.113.7:8080",
                "render.runtime.public-bind",
            ),
            (
                "/auth/apiKeyRef",
                "secret:env/RENDER_API_KEY",
                "render.runtime.undeclared-secret-provider",
            ),
        ] {
            let document = with(&example, pointer, Some(json!(value)));
            assert!(validator.is_valid(&document), "schema: {document}");
            std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
            let codes = check_runtime(&path, false)
                .diagnostics
                .into_iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>();
            assert_eq!(codes, [code], "{pointer}: {value}");
        }
        let documents = schema_documents().unwrap();
        let runtime: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let description = |definition: &str, property: &str| {
            runtime["$defs"][definition]["properties"][property]["description"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let bind = description("ListenerRuntime", "bind");
        assert!(
            bind.contains("public or all-interfaces bind is refused"),
            "{bind}"
        );
        let key = description("AuthRuntime", "apiKeyRef");
        assert!(key.contains("under a declared provider"), "{key}");
    }
}
