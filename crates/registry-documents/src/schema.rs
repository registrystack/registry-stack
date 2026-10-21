// SPDX-License-Identifier: Apache-2.0

//! Generated documents: the JSON Schemas for the Document Store runtime
//! configuration and the authored project file, and the OpenAPI description
//! of the HTTP surface.
//!
//! Every one is derived, never written by hand. The schemas come from the
//! strict reader types; the OpenAPI document comes from the same route and
//! problem vocabulary the router serves. Regenerate the committed documents
//! with:
//!
//! ```bash
//! cargo run -p registry-documents --features schema --example runtime-schema -- \
//!   --output products/documents/generated/runtime
//! cargo run -p registry-documents --features schema --example project-schema -- \
//!   --output products/documents/generated/project
//! cargo run -p registry-documents --features schema --example openapi -- \
//!   --output products/documents/generated
//! ```

use std::collections::{BTreeMap, BTreeSet};

use registry_documents_core::{
    type_uri, DocumentsProject, ProblemCode, DOCUMENTS_PROJECT_API_VERSION, DOCUMENTS_PROJECT_KIND,
    DOCUMENTS_PROJECT_SCHEMA_ID, DOCUMENTS_RUNTIME_API_VERSION, DOCUMENTS_RUNTIME_KIND,
    DOCUMENTS_RUNTIME_SCHEMA_ID, HEALTH_PATH, PROJECT_SCHEMA_FILE, RUNTIME_SCHEMA_FILE,
};
use serde_json::{json, Map, Value};

use crate::config::RuntimeConfig;

/// File name of the generated OpenAPI document.
pub const OPENAPI_FILE: &str = "registry-documents.openapi.json";

/// One operation the public listener serves.
pub struct Operation {
    pub method: &'static str,
    pub path: &'static str,
    pub operation_id: &'static str,
    pub summary: &'static str,
    pub problems: &'static [ProblemCode],
}

/// Every operation the public listener serves. Every other route answers
/// `request.not-found`.
pub const OPERATIONS: &[Operation] = &[Operation {
    method: "get",
    path: HEALTH_PATH,
    operation_id: "health",
    summary: "Report that the process is serving.",
    problems: &[ProblemCode::RequestMethodNotAllowed],
}];

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    refuse_null_outside_shared_blocks(&mut derived)?;
    set_const(&mut derived, "apiVersion", DOCUMENTS_RUNTIME_API_VERSION);
    set_const(&mut derived, "kind", DOCUMENTS_RUNTIME_KIND);
    install_runtime_constraints(&mut derived);
    Ok([(
        RUNTIME_SCHEMA_FILE,
        render(&with_header(
            derived,
            DOCUMENTS_RUNTIME_SCHEMA_ID,
            "Registry Stack Document Store runtime configuration",
        ))?,
    )]
    .into())
}

/// The schema of the authored project file, `documents.yaml`.
pub fn project_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(DocumentsProject))?;
    // The reader refuses `null` in every authored member (CFG-EMPTY-1).
    refuse_null(&mut derived);
    set_const(&mut derived, "apiVersion", DOCUMENTS_PROJECT_API_VERSION);
    set_const(&mut derived, "kind", DOCUMENTS_PROJECT_KIND);
    Ok([(
        PROJECT_SCHEMA_FILE,
        render(&with_header(
            derived,
            DOCUMENTS_PROJECT_SCHEMA_ID,
            "Registry Stack Document Store project",
        ))?,
    )]
    .into())
}

/// The OpenAPI 3.1 description of every operation the public listener
/// serves, with the problem each can answer.
pub fn openapi_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut paths = Map::new();
    for operation in OPERATIONS {
        let mut responses = Map::new();
        responses.insert(
            "200".to_owned(),
            json!({"description": "The operation succeeded. The body is empty."}),
        );
        let mut by_status: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
        for problem in operation.problems {
            by_status
                .entry(problem.http_status())
                .or_default()
                .push(problem.code());
        }
        for (status, codes) in by_status {
            let mut response = json!({
                "description": format!("A problem: {}.", codes.join(", ")),
                "content": {"application/problem+json": {"schema": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Problem"},
                        {"properties": {"code": {"enum": codes}}}
                    ]
                }}}
            });
            if status == 503 {
                response["headers"] = retry_after();
            }
            responses.insert(status.to_string(), response);
        }
        paths
            .entry(operation.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("every path item is an object")
            .insert(
                operation.method.to_owned(),
                json!({
                    "operationId": operation.operation_id,
                    "summary": operation.summary,
                    "security": [],
                    "responses": responses,
                }),
            );
    }
    let problem_types: Vec<String> = ProblemCode::ALL
        .iter()
        .map(|problem| type_uri(problem.code()))
        .collect();
    let codes: Vec<&str> = ProblemCode::ALL
        .iter()
        .map(|problem| problem.code())
        .collect();
    let document = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Stack Document Store API",
            "version": "v1alpha1",
            "license": {"identifier": "Apache-2.0", "name": "Apache-2.0"},
            "description": "Registry Stack Document Store HTTP contract. Every refusal is one \
                            application/problem+json document from the closed vocabulary."
        },
        "paths": paths,
        "components": {
            "schemas": {
                "Problem": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "title", "status", "detail", "code", "traceId"],
                    "properties": {
                        "type": {"type": "string", "enum": problem_types},
                        "title": {"type": "string"},
                        "status": {"type": "integer"},
                        "detail": {"type": "string"},
                        "code": {"type": "string", "enum": codes},
                        "traceId": {"type": "string"}
                    }
                }
            }
        }
    });
    Ok([(OPENAPI_FILE, render(&document)?)].into())
}

fn retry_after() -> Value {
    json!({"Retry-After": {
        "description": "Whole seconds to wait before trying again.",
        "required": true,
        "schema": {"type": "integer", "minimum": 1}
    }})
}

/// Write the documents `generate` returns into the directory named by
/// `--output`, the only argument.
pub fn write_documents(
    name: &str,
    generate: fn() -> Result<BTreeMap<&'static str, String>, serde_json::Error>,
) -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let output = match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(flag), Some(output), None) if flag == "--output" => std::path::PathBuf::from(output),
        _ => {
            eprintln!("usage: {name} --output <directory>");
            return std::process::ExitCode::from(2);
        }
    };
    let written = generate()
        .map_err(|error| error.to_string())
        .and_then(|documents| {
            std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
            documents.into_iter().try_for_each(|(file, contents)| {
                std::fs::write(output.join(file), contents).map_err(|error| error.to_string())
            })
        });
    match written {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{name} generation failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn with_header(derived: Value, identifier: &str, title: &str) -> Value {
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for a struct"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(identifier.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    Value::Object(object)
}

fn render(document: &Value) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(document)?;
    rendered.push('\n');
    Ok(rendered)
}

/// Refuse `null` in every member this product defines. The shared blocks
/// keep the definitions the platform publishes for them.
fn refuse_null_outside_shared_blocks(schema: &mut Value) -> Result<(), serde_json::Error> {
    let shared: Value =
        serde_json::from_str(&registry_platform_config::schema::shared_blocks_document()?)?;
    let shared: BTreeSet<String> = shared
        .get("$defs")
        .and_then(Value::as_object)
        .map(|definitions| definitions.keys().cloned().collect())
        .unwrap_or_default();
    let Some(object) = schema.as_object_mut() else {
        return Ok(());
    };
    for (key, member) in object.iter_mut() {
        if key != "$defs" {
            refuse_null(member);
            continue;
        }
        if let Some(definitions) = member.as_object_mut() {
            for (name, definition) in definitions.iter_mut() {
                if !shared.contains(name) {
                    refuse_null(definition);
                }
            }
        }
    }
    Ok(())
}

/// Drop the `null` schemars adds to each optional member: the shared reader
/// refuses `null` in every member (CFG-EMPTY-1), so a schema that admitted
/// it would accept a document the runtime refuses.
fn refuse_null(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if let [only] = types.as_slice() {
                    let only = only.clone();
                    object.insert("type".to_owned(), only);
                }
            }
            if let Some(Value::Array(branches)) = object.get_mut("anyOf") {
                branches.retain(|branch| branch.get("type") != Some(&Value::from("null")));
                if let [only] = branches.as_slice() {
                    let only = only.clone();
                    object.remove("anyOf");
                    if let Value::Object(only) = only {
                        object.extend(only);
                    }
                }
            }
            for member in object.values_mut() {
                refuse_null(member);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(refuse_null),
        _ => {}
    }
}

fn install_runtime_constraints(schema: &mut Value) {
    // `identity` is optional in the Rust type only so that a missing block
    // gets a refusal naming the key to add; the document requires it.
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        if !required.contains(&json!("identity")) {
            required.push(json!("identity"));
        }
    }
    for (definition, property) in [
        ("PackageConfig", "root"),
        ("FileSecretProviderConfig", "root"),
        ("AuditConfig", "path"),
    ] {
        set_definition_property(schema, definition, property, "pattern", json!("^/"));
    }
    // Every access profile resolves its caller from the matched client, so
    // a Document Store deployment always lists the clients it admits. The
    // shared block also admits the keyword `unrestricted`, which this
    // runtime refuses in every mode, so the member is restated as the list
    // alone and the shared definition is dropped.
    if let Some(clients) = schema.pointer_mut("/$defs/OidcConfig/properties/allowedClients") {
        *clients = json!({
            "description": "Client identifiers whose access tokens are admitted. Required in every\nfile; an omitted or empty list, an empty or repeated client, and\n`unrestricted` are refused.",
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
            "uniqueItems": true,
        });
    }
    if let Some(definitions) = schema.pointer_mut("/$defs").and_then(Value::as_object_mut) {
        definitions.remove("OidcAllowedClients");
    }
    if let Some(providers) = schema
        .pointer_mut("/$defs/SecretProvidersConfig")
        .and_then(Value::as_object_mut)
    {
        providers.insert(
            "anyOf".to_owned(),
            json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ]),
        );
    }
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "allOf".to_owned(),
            registry_platform_config::schema::jwks_document_provider_requirements(),
        );
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

fn set_const(schema: &mut Value, property: &str, expected: &str) {
    if let Some(member) = schema
        .pointer_mut(&format!("/properties/{property}"))
        .and_then(Value::as_object_mut)
    {
        member.insert("const".to_owned(), json!(expected));
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests parse the committed examples to prove the schema accepts them"
    )]

    use super::*;

    fn product() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/documents")
    }

    fn schema(documents: &BTreeMap<&'static str, String>, file: &str) -> Value {
        serde_json::from_str(&documents[file]).unwrap()
    }

    fn example(relative: &str) -> Value {
        let text = std::fs::read_to_string(product().join(relative)).unwrap();
        serde_norway::from_str(&text).unwrap()
    }

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        assert_eq!(first, runtime_documents().unwrap());
        let document = schema(&first, RUNTIME_SCHEMA_FILE);
        assert_eq!(document["$id"], DOCUMENTS_RUNTIME_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            DOCUMENTS_RUNTIME_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            DOCUMENTS_RUNTIME_KIND
        );
        let required = document["required"].as_array().unwrap();
        assert_eq!(
            required
                .iter()
                .filter(|member| *member == "identity")
                .count(),
            1
        );
    }

    #[test]
    fn the_runtime_schema_states_the_bounds_the_runtime_enforces() {
        let document = schema(&runtime_documents().unwrap(), RUNTIME_SCHEMA_FILE);
        for (definition, property) in [
            ("PackageConfig", "root"),
            ("FileSecretProviderConfig", "root"),
            ("AuditConfig", "path"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"], "^/",
                "{definition}.{property} must be absolute"
            );
        }
        let clients = &document["$defs"]["OidcConfig"]["properties"]["allowedClients"];
        assert_eq!(clients["type"], "array");
        assert_eq!(clients["minItems"], 1);
        assert!(document["$defs"].get("OidcAllowedClients").is_none());
    }

    #[test]
    fn project_schema_is_deterministic_and_versioned() {
        let first = project_documents().unwrap();
        assert_eq!(first, project_documents().unwrap());
        let document = schema(&first, PROJECT_SCHEMA_FILE);
        assert_eq!(document["$id"], DOCUMENTS_PROJECT_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            DOCUMENTS_PROJECT_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            DOCUMENTS_PROJECT_KIND
        );
    }

    #[test]
    fn the_starter_examples_satisfy_their_schemas() {
        for (documents, file, example_path) in [
            (
                runtime_documents().unwrap(),
                RUNTIME_SCHEMA_FILE,
                "examples/starter/runtime.example.yaml",
            ),
            (
                project_documents().unwrap(),
                PROJECT_SCHEMA_FILE,
                "examples/starter/documents.yaml",
            ),
        ] {
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema(&documents, file))
                .unwrap_or_else(|error| panic!("{file} compiles: {error}"));
            let instance = example(example_path);
            let errors: Vec<String> = match validator.validate(&instance) {
                Ok(()) => Vec::new(),
                Err(errors) => errors
                    .map(|error| format!("{error} at {}", error.instance_path))
                    .collect(),
            };
            assert!(errors.is_empty(), "{example_path}: {errors:#?}");
        }
    }

    #[test]
    fn openapi_lists_every_operation_and_only_catalogued_problems() {
        let documents = openapi_documents().unwrap();
        assert_eq!(documents, openapi_documents().unwrap());
        let document = schema(&documents, OPENAPI_FILE);
        for operation in OPERATIONS {
            let entry = &document["paths"][operation.path][operation.method];
            assert_eq!(entry["operationId"], operation.operation_id);
        }
        let codes: Vec<&str> = document["components"]["schemas"]["Problem"]["properties"]["code"]
            ["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect();
        let catalogued: Vec<&str> = ProblemCode::ALL
            .iter()
            .map(|problem| problem.code())
            .collect();
        assert_eq!(codes, catalogued);
    }

    #[test]
    fn committed_documents_match_generated_bytes() {
        let generated = product().join("generated");
        for (directory, documents, example) in [
            (
                generated.join("runtime"),
                runtime_documents().unwrap(),
                "runtime-schema",
            ),
            (
                generated.join("project"),
                project_documents().unwrap(),
                "project-schema",
            ),
            (generated.clone(), openapi_documents().unwrap(), "openapi"),
        ] {
            for (file, contents) in documents {
                assert_eq!(
                    std::fs::read_to_string(directory.join(file))
                        .unwrap_or_else(|_| panic!("the committed {file}")),
                    contents,
                    "regenerate with the {example} example"
                );
            }
        }
    }
}
