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

use registry_platform_yaml::{DisplayText, LocalId};
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
/// envelope values, label keys that are local identifiers, and safe display
/// text values. The derived schema inlines the key pattern; the key type is
/// named instead, so the table reads as a map keyed by `LocalId` like every
/// other keyed map.
fn install_labels_constraints(schema: &mut Value) -> Result<(), serde_json::Error> {
    set_const(schema, "apiVersion", LABELS_API_VERSION);
    set_const(schema, "kind", LABELS_KIND);
    let local_id = serde_json::to_value(LocalId::json_schema(
        &mut schemars::SchemaGenerator::default(),
    ))?;
    let display_text = serde_json::to_value(DisplayText::json_schema(
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
        labels.insert(
            "additionalProperties".to_owned(),
            json!({"$ref": "#/$defs/DisplayText"}),
        );
    }
    if let Value::Object(object) = schema {
        object
            .entry("$defs")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("$defs is an object")
            .extend([
                ("DisplayText".to_owned(), display_text),
                ("LocalId".to_owned(), local_id),
            ]);
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
    if let Some(auth) = schema
        .pointer_mut("/$defs/AuthenticationRuntime")
        .and_then(Value::as_object_mut)
    {
        auth.insert(
            "oneOf".to_owned(),
            json!([
                {"required":["oidc"], "not":{"required":["apiKeyRef"]}},
                {"required":["apiKeyRef"], "not":{"required":["oidc"]}}
            ]),
        );
    }
    // Absence is described by the optional members, not by null or an empty
    // object that the referenced schemas reject as an explicit value.
    for pointer in [
        "/$defs/AuthenticationRuntime/properties/apiKeyRef",
        "/properties/secretProviders",
    ] {
        schema
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("derived optional runtime member exists")
            .remove("default");
    }
    set_audit_destination_constraints(schema);
    set_signing_constraints(schema);
    if let Some(definitions) = schema.get_mut("$defs").and_then(Value::as_object_mut) {
        definitions.extend(socket_definitions());
    }
}

/// State the rules of the `signing` block that the types alone do not:
/// the block is an object and never null, the seals are keyed by local
/// identifiers and number at least one, the certificate chain file is an
/// absolute path with no `.` or `..` segment, a seal has exactly one
/// timestamp policy, its clients are named (no wildcard, no `unrestricted`),
/// and a timestamp authority is `https`, or `http` on a loopback host.
/// Rules that need another member (every client is admitted by
/// `authentication.oidc.allowedClients`, the secret provider is declared, OIDC is
/// configured) are left to the reader and stated in the member descriptions.
fn set_signing_constraints(schema: &mut Value) {
    if let Some(member) = schema
        .pointer_mut("/properties/signing")
        .and_then(Value::as_object_mut)
    {
        member.remove("anyOf");
        member.insert("$ref".to_owned(), json!("#/$defs/SigningRuntime"));
    }
    if let Some(seals) = schema
        .pointer_mut("/$defs/SigningRuntime/properties/seals")
        .and_then(Value::as_object_mut)
    {
        seals.remove("patternProperties");
        seals.insert(
            "propertyNames".to_owned(),
            json!({"$ref": "#/$defs/LocalId"}),
        );
        seals.insert(
            "additionalProperties".to_owned(),
            json!({"$ref": "#/$defs/SealRuntime"}),
        );
        seals.insert("minProperties".to_owned(), json!(1));
    }
    if let Some(Value::Object(object)) = schema.get_mut("$defs") {
        let local_id = serde_json::to_value(LocalId::json_schema(
            &mut schemars::SchemaGenerator::default(),
        ))
        .expect("the local identifier schema is JSON");
        object.insert("LocalId".to_owned(), local_id);
    }
    set_definition_property(
        schema,
        "SealRuntime",
        "allowedClients",
        "minItems",
        json!(1),
    );
    set_definition_property(
        schema,
        "SealRuntime",
        "allowedClients",
        "items",
        json!({
            "$ref": "#/$defs/ExternalId",
            "not": {"anyOf": [{"const": "unrestricted"}, {"pattern": "\\*"}]}
        }),
    );
    set_definition_property(
        schema,
        "SealRuntime",
        "certificateChainFile",
        "pattern",
        json!("^/(?:[^/]+/)*[^/]+$"),
    );
    set_definition_property(
        schema,
        "SealRuntime",
        "certificateChainFile",
        "not",
        json!({"pattern": "(^|/)\\.{1,2}(/|$)"}),
    );
    if let Some(seal) = schema
        .pointer_mut("/$defs/SealRuntime")
        .and_then(Value::as_object_mut)
    {
        seal.insert(
            "oneOf".to_owned(),
            json!([
                {"required": ["timestampAuthority"], "not": {"required": ["withoutTimestamp"]}},
                {"required": ["withoutTimestamp"], "not": {"required": ["timestampAuthority"]}}
            ]),
        );
    }
    // The profile decides the signer: `local` signs with a key file,
    // `production` through Transit. A runtime that declares a seal states it.
    if let Some(root) = schema.as_object_mut() {
        let signer_is = |profile: &str, signer: &str| {
            json!({
                "if": {"properties": {"assuranceProfile": {"const": profile}}, "required": ["assuranceProfile"]},
                "then": {"properties": {"signing": {"properties": {"seals": {"additionalProperties": {
                    "properties": {"signer": {"properties": {"type": {"const": signer}}}}
                }}}}}}
            })
        };
        root.insert(
            "allOf".to_owned(),
            json!([
                {
                    "if": {"properties": {"signing": {"properties": {"seals": {"minProperties": 1}}, "required": ["seals"]}}, "required": ["signing"]},
                    "then": {"required": ["assuranceProfile"]}
                },
                signer_is("local", "local-jwk"),
                signer_is("production", "transit")
            ]),
        );
    }
    if let Some(Value::Array(variants)) = schema.pointer_mut("/$defs/SealSignerRuntime/oneOf") {
        let socket = variants
            .iter_mut()
            .filter(|variant| variant.pointer("/properties/type/const") == Some(&json!("transit")))
            .find_map(|variant| variant.pointer_mut("/properties/unixSocketPath"))
            .and_then(Value::as_object_mut);
        if let Some(socket) = socket {
            socket.insert("pattern".to_owned(), json!("^/(?:[^/]+/)*[^/]+$"));
            socket.insert("not".to_owned(), json!({"pattern": "(^|/)\\.{1,2}(/|$)"}));
        }
    }
    set_definition_property(
        schema,
        "TimestampAuthorityRuntime",
        "url",
        "allOf",
        json!([{"pattern": LOOPBACK_OR_HTTPS_PATTERN}]),
    );
}

/// An `https` URL, or an `http` URL whose host is `localhost`, an IPv4
/// loopback address, or `[::1]`.
const LOOPBACK_OR_HTTPS_PATTERN: &str = "^(?:[Hh][Tt][Tt][Pp][Ss]://|[Hh][Tt][Tt][Pp]://(?:[Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt]|127(?:\\.[0-9]{1,3}){3}|\\[::1\\])(?:[:/?#]|$))";

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

    #[test]
    fn optional_auth_metadata_does_not_advertise_invalid_defaults() {
        let documents = schema_documents().unwrap();
        let runtime: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        for pointer in [
            "/$defs/AuthenticationRuntime/properties/apiKeyRef",
            "/properties/secretProviders",
        ] {
            let member = runtime.pointer(pointer).unwrap().as_object().unwrap();
            assert!(!member.contains_key("default"), "{pointer}: {member:?}");
            let description = member.get("description").and_then(Value::as_str).unwrap();
            assert!(description.contains("Omit"), "{pointer}: {description}");
        }
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
        let check = check_runtime(&example.canonicalize().unwrap(), false, None);
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
            (json!({"title": "العربية \u{200f}Latin"}), true),
            (json!({longest: "Text"}), true),
            (json!({too_long: "Text"}), false),
            (json!({"Title": "Receipt"}), false),
            (json!({"count": 3}), false),
            (json!({"title": "Receipt\u{202e}hidden"}), false),
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
            (
                "/authentication/apiKeyRef",
                Some(json!("secret:vault/key")),
                false,
            ),
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
            let check = check_runtime(&path, false, None);
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

    fn signing_runtime_document() -> Value {
        json!({
            "apiVersion": RUNTIME_API_VERSION,
            "kind": RUNTIME_KIND,
            "listener": {"bind": "127.0.0.1:8080"},
            "package": {"root": "/srv/render/package"},
            "secretProviders": {"file": {"root": "/run/secrets"}},
            "authentication": {"oidc": {
                "issuer": "https://issuer.example.test",
                "audience": "https://render.example.test",
                "allowedClients": ["portal", "records-service"]
            }},
            "audit": {"path": "/var/lib/render/audit/render.jsonl"},
            "assuranceProfile": "local",
            "signing": {"seals": {"ministry": {
                "signer": {"type": "local-jwk", "privateKeyRef": "secret:file/seal.jwk"},
                "certificateChainFile": "/etc/render/seal/chain.pem",
                "timestampAuthority": {"url": "https://tsa.example.test/tsr"},
                "allowedClients": ["records-service"]
            }}}
        })
    }

    #[test]
    fn signing_members_are_judged_alike_by_schema_and_reader() {
        let validator = validator(RUNTIME_SCHEMA_FILE);
        let base = signing_runtime_document();
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        let seal = "/signing/seals/ministry";
        let authority = format!("{seal}/timestampAuthority");
        let without = json!("seal-stops-validating-when-certificate-expires");
        let no_authority = with(&base, &authority, None);
        let transit = with(
            &with(&base, "/assuranceProfile", Some(json!("production"))),
            &format!("{seal}/signer"),
            Some(json!({
                "type": "transit",
                "unixSocketPath": "/run/render/transit.sock",
                "mount": "transit",
                "keyName": "render-seal",
                "keyVersion": 3,
                "attemptTimeoutMilliseconds": 2000
            })),
        );
        let no_seals = with(&with(&base, "/signing", None), "/assuranceProfile", None);
        let signer = format!("{seal}/signer");
        let cases = [
            (&transit, "/assuranceProfile", Some(json!("local")), false),
            (&transit, "/assuranceProfile", None, false),
            (
                &transit,
                &format!("{signer}/unixSocketPath"),
                Some(json!("run/render/transit.sock")),
                false,
            ),
            (
                &transit,
                &format!("{signer}/unixSocketPath"),
                Some(json!("/run/../transit.sock")),
                false,
            ),
            (
                &transit,
                &format!("{signer}/unixSocketPath"),
                Some(json!("/run/render/")),
                false,
            ),
            (
                &transit,
                &format!("{signer}/mount"),
                Some(json!("transit/render")),
                false,
            ),
            (
                &transit,
                &format!("{signer}/keyName"),
                Some(json!("Render.Seal")),
                false,
            ),
            (
                &transit,
                &format!("{signer}/keyVersion"),
                Some(json!(0)),
                false,
            ),
            (
                &transit,
                &format!("{signer}/attemptTimeoutMilliseconds"),
                Some(json!(30_000)),
                true,
            ),
            (
                &transit,
                &format!("{signer}/attemptTimeoutMilliseconds"),
                Some(json!(30_001)),
                false,
            ),
            (
                &transit,
                &format!("{signer}/attemptTimeoutMilliseconds"),
                Some(json!(0)),
                false,
            ),
            (
                &transit,
                &format!("{signer}/attemptTimeoutMilliseconds"),
                None,
                false,
            ),
            (
                &transit,
                &format!("{signer}/privateKeyRef"),
                Some(json!("secret:file/seal.jwk")),
                false,
            ),
            (&base, "/assuranceProfile", None, false),
            (&base, "/assuranceProfile", Some(json!("production")), false),
            (
                &base,
                "/assuranceProfile",
                Some(json!("evidence-grade")),
                false,
            ),
            (
                &base,
                &format!("{seal}/trust"),
                Some(json!("test-only")),
                false,
            ),
            (&no_seals, "/assuranceProfile", Some(json!("local")), true),
            (
                &base,
                &format!("{authority}/url"),
                Some(json!("http://tsa.example.test/")),
                false,
            ),
            (
                &base,
                &format!("{authority}/url"),
                Some(json!("http://localhost:3161/")),
                true,
            ),
            (
                &base,
                &format!("{authority}/url"),
                Some(json!("http://127.0.0.1:3161/tsr")),
                true,
            ),
            (
                &base,
                &format!("{authority}/url"),
                Some(json!("http://[::1]:3161/")),
                true,
            ),
            (
                &base,
                &format!("{authority}/url"),
                Some(json!("http://localhost.example.test/")),
                false,
            ),
            (
                &base,
                &format!("{authority}/attemptTimeoutMilliseconds"),
                Some(json!(999)),
                false,
            ),
            (
                &base,
                &format!("{authority}/attemptTimeoutMilliseconds"),
                Some(json!(1_000)),
                true,
            ),
            (
                &base,
                &format!("{authority}/attemptTimeoutMilliseconds"),
                Some(json!(60_000)),
                true,
            ),
            (
                &base,
                &format!("{authority}/attemptTimeoutMilliseconds"),
                Some(json!(60_001)),
                false,
            ),
            (
                &base,
                &format!("{authority}/attemptTimeoutMilliseconds"),
                Some(json!("5000")),
                false,
            ),
            (
                &base,
                &format!("{authority}/retries"),
                Some(json!(3)),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!([])),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!("unrestricted")),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!(["*"])),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!(["unrestricted"])),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!(["records-*"])),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!(["portal", "portal"])),
                false,
            ),
            (
                &base,
                &format!("{seal}/allowedClients"),
                Some(json!(["portal", "records-service"])),
                true,
            ),
            (&base, &format!("{seal}/allowedClients"), None, false),
            (
                &base,
                &format!("{seal}/certificateChainFile"),
                Some(json!("chain.pem")),
                false,
            ),
            (
                &base,
                &format!("{seal}/certificateChainFile"),
                Some(json!("/etc/../chain.pem")),
                false,
            ),
            (
                &base,
                &format!("{seal}/certificateChainFile"),
                Some(json!("/etc//chain.pem")),
                false,
            ),
            (
                &base,
                &format!("{seal}/certificateChainFile"),
                Some(json!("/etc/seal/")),
                false,
            ),
            (
                &base,
                &format!("{seal}/signer/privateKeyRef"),
                Some(json!("/etc/seal.jwk")),
                false,
            ),
            (&base, &format!("{seal}/signer/privateKeyRef"), None, false),
            (&base, &format!("{seal}/signer"), None, false),
            (
                &base,
                &format!("{seal}/signer/type"),
                Some(json!("pkcs11")),
                false,
            ),
            (
                &base,
                &format!("{seal}/privateKeyRef"),
                Some(json!("secret:file/seal.jwk")),
                false,
            ),
            (
                &base,
                &format!("{seal}/keyFile"),
                Some(json!("/etc/seal.jwk")),
                false,
            ),
            (
                &no_authority,
                &format!("{seal}/withoutTimestamp"),
                Some(without.clone()),
                true,
            ),
            (
                &no_authority,
                &format!("{seal}/withoutTimestamp"),
                Some(json!(true)),
                false,
            ),
            (
                &no_authority,
                &format!("{seal}/withoutTimestamp"),
                Some(json!("without-timestamp")),
                false,
            ),
            (
                &base,
                &format!("{seal}/withoutTimestamp"),
                Some(without),
                false,
            ),
            (
                &no_authority,
                &format!("{seal}/withoutTimestamp"),
                None,
                false,
            ),
            (&base, "/signing/seals", Some(json!({})), false),
            (&base, "/signing", Some(Value::Null), false),
            (&base, "/signing/extra", Some(json!(1)), false),
        ];
        let renamed = {
            let mut document = base.clone();
            let seals = document["signing"]["seals"].as_object_mut().unwrap();
            let seal = seals.remove("ministry").unwrap();
            seals.insert("Ministry".to_owned(), seal);
            document
        };
        let documents = cases
            .into_iter()
            .map(|(document, pointer, value, accepted)| (with(document, pointer, value), accepted))
            .chain([
                (base.clone(), true),
                (transit.clone(), true),
                (no_seals.clone(), true),
                (renamed, false),
            ]);
        for (document, accepted) in documents {
            std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
            let check = check_runtime(&path, false, None);
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

    /// The rules that span members are the reader's alone, and the member
    /// descriptions name them (CFG-SCHEMA-9).
    #[test]
    fn signing_rules_across_members_are_refused_by_the_reader_alone() {
        let validator = validator(RUNTIME_SCHEMA_FILE);
        let base = signing_runtime_document();
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        let key_mode = {
            let document = with(&base, "/authentication/oidc", None);
            with(
                &document,
                "/authentication/apiKeyRef",
                Some(json!("secret:file/api.key")),
            )
        };
        for (document, code) in [
            (
                with(
                    &base,
                    "/signing/seals/ministry/allowedClients",
                    Some(json!(["batch-job"])),
                ),
                "render.runtime.seal-client-not-admitted",
            ),
            (
                with(
                    &base,
                    "/signing/seals/ministry/signer/privateKeyRef",
                    Some(json!("secret:env/SEAL_KEY")),
                ),
                "render.runtime.seal-key-requires-file-provider",
            ),
            (key_mode, "render.runtime.signing-requires-oidc"),
        ] {
            assert!(validator.is_valid(&document), "schema: {document}");
            std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
            let codes = check_runtime(&path, false, None)
                .diagnostics
                .into_iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>();
            assert_eq!(codes, [code], "{document}");
        }
        let documents = schema_documents().unwrap();
        let runtime: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let clients = runtime["$defs"]["SealRuntime"]["properties"]["allowedClients"]
            ["description"]
            .as_str()
            .unwrap();
        assert!(
            clients.contains("authentication.oidc.allowedClients"),
            "the cross-member rule is stated: {clients}"
        );
    }

    #[test]
    fn a_document_type_names_its_seal_by_local_identifier_in_schema_and_reader() {
        let validator = validator(BUNDLE_SCHEMA_FILE);
        for (seal, accepted) in [
            (json!("ministry"), true),
            (json!("seal_2"), true),
            (json!("Ministry"), false),
            (json!("9seal"), false),
            (json!(7), false),
            (json!(null), false),
        ] {
            let document = json!({
                "apiVersion": MANIFEST_API_VERSION,
                "kind": MANIFEST_KIND,
                "bundleVersion": 1,
                "documents": [{"id": "licence", "version": 1,
                    "entryFile": "templates/licence.typ", "seal": seal}]
            });
            let text = serde_json::to_string(&document).unwrap();
            assert_eq!(
                read_manifest("manifest.yaml", text.as_bytes()).is_ok(),
                accepted,
                "reader: {seal}"
            );
            assert_eq!(validator.is_valid(&document), accepted, "schema: {seal}");
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
                "/authentication/apiKeyRef",
                "secret:env/RENDER_API_KEY",
                "render.runtime.undeclared-secret-provider",
            ),
        ] {
            let document = with(&example, pointer, Some(json!(value)));
            assert!(validator.is_valid(&document), "schema: {document}");
            std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
            let codes = check_runtime(&path, false, None)
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
        let key = description("AuthenticationRuntime", "apiKeyRef");
        assert!(key.contains("under a declared provider"), "{key}");
    }
}
