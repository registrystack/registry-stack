// SPDX-License-Identifier: Apache-2.0

//! Generated JSON Schema for the configurable MCP runtime file.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::{RuntimeConfig, API_VERSION, KIND};

pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/mcp-runtime/mcp-runtime.v1alpha1.schema.json";
pub const RUNTIME_SCHEMA_FILE: &str = "mcp-runtime.schema.json";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const TOOL_NAME_PATTERN: &str = "^[A-Za-z0-9_.-]{1,256}$";

/// Every generated schema, by file name and committed bytes.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut runtime = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut runtime, "apiVersion", API_VERSION);
    set_const(&mut runtime, "kind", KIND);
    set_audit_destination_constraints(&mut runtime);
    constrain_named_members(&mut runtime);
    Ok([(
        RUNTIME_SCHEMA_FILE,
        render(
            runtime,
            RUNTIME_SCHEMA_ID,
            "Registry Stack configurable MCP gateway runtime configuration",
        )?,
    )]
    .into())
}

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

fn set_const(schema: &mut Value, property: &str, value: &str) {
    if let Some(member) = schema
        .pointer_mut(&format!("/properties/{property}"))
        .and_then(Value::as_object_mut)
    {
        member.insert("const".to_owned(), Value::String(value.to_owned()));
    }
}

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

/// Schemars describes the container types. These constraints describe the
/// product-neutral identifiers whose Rust representation remains `String`.
fn constrain_named_members(schema: &mut Value) {
    visit_objects(schema, &mut |object| {
        let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) else {
            return;
        };
        if let Some(tools) = properties.get_mut("tools").and_then(Value::as_object_mut) {
            if let Some(items) = tools.get_mut("items").and_then(Value::as_object_mut) {
                items.insert(
                    "pattern".to_owned(),
                    Value::String(TOOL_NAME_PATTERN.to_owned()),
                );
            }
        }
        if let Some(path) = properties
            .get_mut("contractFile")
            .and_then(Value::as_object_mut)
        {
            path.insert("pattern".to_owned(), Value::String("^/".to_owned()));
        }
        if let Some(operations) = properties
            .get_mut("operations")
            .and_then(Value::as_object_mut)
        {
            operations.insert("minProperties".to_owned(), json!(1));
            operations.insert("maxProperties".to_owned(), json!(128));
            operations.insert(
                "propertyNames".to_owned(),
                json!({
                    "$ref": "#/$defs/ExternalId",
                    "pattern": TOOL_NAME_PATTERN
                }),
            );
        }
    });
}

fn visit_objects(
    schema: &mut Value,
    visitor: &mut impl FnMut(&mut serde_json::Map<String, Value>),
) {
    match schema {
        Value::Object(object) => {
            visitor(object);
            for value in object.values_mut() {
                visit_objects(value, visitor);
            }
        }
        Value::Array(items) => {
            for value in items {
                visit_objects(value, visitor);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use jsonschema::{Draft, JSONSchema};
    use registry_platform_yaml::Reader;

    use super::*;

    const PLATFORM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/platform");

    fn validator() -> JSONSchema {
        let schema: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("the schema compiles as Draft 2020-12: {error}"))
    }

    fn example() -> String {
        std::fs::read_to_string(
            Path::new(PLATFORM).join("examples/mcp-runtime/runtime.example.yaml"),
        )
        .unwrap()
    }

    fn as_json(bytes: &[u8]) -> Value {
        Reader::new("runtime.yaml")
            .scan(bytes)
            .expect("the file is YAML")
            .expect("the file is not empty")
            .to_json_value()
    }

    fn reader_accepts(text: &str) -> bool {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("runtime.yaml");
        std::fs::write(&path, text).unwrap();
        !crate::config::RuntimeConfig::check(&path, false).has_errors()
    }

    #[test]
    fn committed_schema_matches_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(
                Path::new(PLATFORM).join("generated/mcp-runtime").join(name),
            )
            .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted; regenerate it with `cargo run -p registry-mcp --features schema \
                 --example runtime-schema -- --output products/platform/generated/mcp-runtime`"
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
        assert!(
            shared > 0,
            "the runtime schema embeds shared platform blocks"
        );
    }

    #[test]
    fn committed_example_is_accepted_by_schema_and_reader() {
        let text = example();
        assert!(reader_accepts(&text));
        assert!(validator().is_valid(&as_json(text.as_bytes())));
    }

    #[test]
    fn offline_check_preserves_unavailable_file_status() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("missing-runtime.yaml");
        let (report, unavailable) = crate::config::RuntimeConfig::check_status(&path, false);
        assert!(unavailable);
        assert!(report.has_errors());
    }

    #[test]
    fn schema_and_reader_agree_on_local_runtime_constraints() {
        let validator = validator();
        for (from, to, accepted) in [
            ("name: Citizen registry assistant", "name: ''", false),
            ("tools: [get_my_details]", "tools: []", false),
            ("tools: [get_my_details]", "tools: [not/a/tool]", false),
            ("requestsPerMinute: 30", "requestsPerMinute: 0", false),
            ("burst: 10", "burst: 1000000", true),
            ("burst: 10", "burst: 1000001", false),
        ] {
            let source = example();
            let text = source.replacen(from, to, 1);
            assert_ne!(text, source, "the fixture carries {from}");
            assert_eq!(reader_accepts(&text), accepted, "reader: {to}");
            assert_eq!(
                validator.is_valid(&as_json(text.as_bytes())),
                accepted,
                "schema: {to}"
            );
        }
    }

    #[test]
    fn offline_check_loads_the_exact_adapter_contract_and_operation_map() {
        const PUBLIC_TOOL: &str = "Adapter.Record_Read";
        const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
        let empty = json!({"type":"object","additionalProperties":false,"properties":{}});
        let protocol_problem = |code: &str, status: u16, title: &str| {
            json!({
                "type":"object",
                "properties":{
                    "code":{"const":code},
                    "status":{"const":status},
                    "title":{"const":title},
                    "requestId":{
                        "type":"string",
                        "minLength":32,
                        "maxLength":32,
                        "pattern":"^[0-9a-f]{32}$"
                    }
                },
                "required":["code","status","title","requestId"],
                "additionalProperties":false
            })
        };
        let contract = json!({
            "schemaDialect":SCHEMA_DIALECT,
            "project":{"id":"fixture","version":"1"},
            "profileVersion":"1",
            "artifactDeploymentDigest":format!("sha256:{}", "a".repeat(64)),
            "authentication":{"scheme":"bearer","audience":"urn:example:adapter","clientAdmission":"allowlist"},
            "authority":{
                "callerMode":"trusted-machine",
                "representedSubject":"unsupported",
                "personalDelegation":"unsupported",
                "targetBinding":"unsupported",
                "rowDisclosureAuthority":"not-granted",
                "fieldDisclosureAuthority":"not-granted"
            },
            "operations":[{
                "id":"records.list","version":"1","bindingId":"read",
                "profileOperationId":"list","method":"GET","path":"/records",
                "support":"served","effect":"read","successStatus":200,
                "input":{"path":empty.clone(),"query":empty.clone()},
                "output":empty.clone(),"access":{"anyOf":[{"allScopes":["read"]}]}
            }],
            "unserved":[],"problemSchema":empty,
            "protocolProblems":{
                "schema":{"$schema":SCHEMA_DIALECT,"oneOf":[
                    protocol_problem(
                        "adapter.contract.precondition-failed",
                        412,
                        "Effective contract precondition failed"
                    ),
                    protocol_problem(
                        "adapter.contract.unavailable",
                        503,
                        "Effective contract unavailable"
                    )
                ]},
                "problems":[
                    {"code":"adapter.contract.precondition-failed","status":412,"title":"Effective contract precondition failed"},
                    {"code":"adapter.contract.unavailable","status":503,"title":"Effective contract unavailable"}
                ]
            }
        });
        let digest = crate::adapter::contract_digest(&contract).unwrap();
        let document = json!({
            "apiVersion":"id.registrystack.org/formats/adapter/effective-contract/v1alpha1",
            "kind":"AdapterEffectiveContract","digest":digest,"contract":contract
        });
        let directory = tempfile::tempdir().unwrap();
        let contract_file = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("effective.json");
        std::fs::write(&contract_file, serde_json::to_vec(&document).unwrap()).unwrap();

        let mut runtime = as_json(example().as_bytes());
        runtime["bindings"][0]["tools"] = json!([PUBLIC_TOOL]);
        runtime["bindings"][0]["provider"] = json!({
            "type":"adapter",
            "baseUrl":"http://127.0.0.1:8114/",
            "contractFile":contract_file,
            "contractDigest":document["digest"],
            "dataClass":"non-personal",
            "audience":"urn:example:adapter",
            "machineTokenRef":"secret:env/MCP_ADAPTER_TOKEN",
            "operations":{(PUBLIC_TOOL):"records.list"}
        });
        let runtime_file = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("runtime.json");
        std::fs::write(&runtime_file, serde_json::to_vec(&runtime).unwrap()).unwrap();
        let report = crate::config::RuntimeConfig::check(&runtime_file, false);
        assert!(!report.has_errors(), "{}", report.render_human());
        assert!(validator().is_valid(&runtime));

        runtime["bindings"][0]["provider"]["operations"][PUBLIC_TOOL] = json!("records.missing");
        std::fs::write(&runtime_file, serde_json::to_vec(&runtime).unwrap()).unwrap();
        let report = crate::config::RuntimeConfig::check(&runtime_file, false);
        assert!(
            report.has_errors(),
            "an operation absent from the pin was accepted"
        );
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic.path == "/bindings/0/provider"
                && diagnostic.code == "platform.mcp-runtime.invalid-binding"
        }));
    }

    #[test]
    fn casework_shape_requires_the_explicit_delegated_read_contract() {
        let mut runtime = as_json(example().as_bytes());
        runtime["bindings"][0]["tools"] = json!(["list_my_review_tasks"]);
        runtime["bindings"][0]["provider"] = json!({
            "type":"casework","authority":"delegated-staff-read","baseUrl":"http://127.0.0.1:8120/",
            "readerPolicy":"reviewer","sourceProfile":"reviewer-source","pageSize":20,
            "authorization":{
                "exchange":{"tokenEndpoint":"http://127.0.0.1:8111/token","clientId":"staff-gateway","privateKeyRef":"secret:env/MCP_EXCHANGE_PRIVATE_KEY"},
                "audience":"urn:example:casework","scopes":["casework:staff"]
            }
        });
        assert!(
            validator().is_valid(&runtime),
            "the explicit delegated-read shape is documentable"
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("runtime.json");
        std::fs::write(&path, serde_json::to_vec(&runtime).unwrap()).unwrap();
        let report = crate::config::RuntimeConfig::check(&path, false);
        assert!(!report.has_errors(), "{}", report.render_human());
        runtime["bindings"][0]["provider"]
            .as_object_mut()
            .unwrap()
            .remove("authority");
        assert!(!validator().is_valid(&runtime));
    }
}
