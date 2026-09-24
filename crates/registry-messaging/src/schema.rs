// SPDX-License-Identifier: Apache-2.0

//! Generated documents: the JSON Schema for the Messaging runtime
//! configuration and the OpenAPI description of the HTTP surface.
//!
//! Both are derived, never written by hand. The runtime schema comes from the
//! strict `RuntimeConfig` types; the OpenAPI document comes from the same
//! operation table the router serves. Regenerate the committed documents
//! with:
//!
//! ```bash
//! cargo run -p registry-messaging --features schema --example runtime-schema -- \
//!   --output products/messaging/generated/runtime
//! cargo run -p registry-messaging --features schema --example openapi -- \
//!   --output products/messaging/generated
//! ```
//!
//! The derived schema states the bounds `RuntimeConfig::check` enforces, so
//! a document an operator's editor accepts is one the runtime starts on.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use registry_messaging_core::{
    type_uri, ProblemCode, MESSAGING_RUNTIME_API_VERSION, MESSAGING_RUNTIME_KIND,
    MESSAGING_RUNTIME_SCHEMA_ID, RUNTIME_SCHEMA_FILE,
};

use crate::config::{
    RuntimeConfig, MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT, MAXIMUM_ASSERTION_ISSUER_BYTES,
    MAXIMUM_ASSERTION_ISSUER_CLIENTS, MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES, MAXIMUM_PAYLOAD_DAYS,
    MAXIMUM_RECORD_DAYS,
};
use crate::http::OPERATIONS;

/// File name of the generated OpenAPI document.
pub const OPENAPI_FILE: &str = "registry-messaging.openapi.json";

const SECRET_REFERENCE_SCHEMA_PATTERN: &str =
    "^(?:secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$";

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut derived, "apiVersion", MESSAGING_RUNTIME_API_VERSION);
    set_const(&mut derived, "kind", MESSAGING_RUNTIME_KIND);
    install_runtime_constraints(&mut derived);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for RuntimeConfig"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(MESSAGING_RUNTIME_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Registry Messaging runtime configuration".to_owned()),
    );
    Ok([(RUNTIME_SCHEMA_FILE, render(&Value::Object(object))?)].into())
}

/// The OpenAPI 3.1 description of every operation the public listener
/// serves, with the problem each can answer.
pub fn openapi_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut paths = Map::new();
    for operation in OPERATIONS {
        let mut responses = Map::new();
        responses.insert(
            operation.success_status.to_string(),
            json!({"description": "The operation succeeded. The body is empty."}),
        );
        let mut by_status: BTreeMap<u16, Vec<ProblemCode>> = BTreeMap::new();
        for problem in operation.problems {
            by_status
                .entry(problem.http_status())
                .or_default()
                .push(*problem);
        }
        for (status, problems) in by_status {
            let codes: Vec<&str> = problems.iter().map(|problem| problem.code()).collect();
            responses.insert(
                status.to_string(),
                json!({
                    "description": format!("A problem: {}.", codes.join(", ")),
                    "content": {"application/problem+json": {"schema": {
                        "allOf": [
                            {"$ref": "#/components/schemas/Problem"},
                            {"properties": {"code": {"enum": codes}}}
                        ]
                    }}}
                }),
            );
        }
        let mut entry = json!({
            "operationId": operation.operation_id,
            "summary": operation.summary,
            "responses": responses,
        });
        if operation.path.contains('{') {
            entry["parameters"] = json!([{
                "name": "message_id",
                "in": "path",
                "required": true,
                "schema": {"type": "string", "minLength": 1}
            }]);
        }
        entry["security"] = if operation.authenticated {
            json!([{"bearer": []}])
        } else {
            json!([])
        };
        paths
            .entry(operation.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("every path item is an object")
            .insert(operation.method.to_owned(), entry);
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
            "title": "Registry Messaging API",
            "version": "v1alpha1",
            "license": {"identifier": "Apache-2.0", "name": "Apache-2.0"},
            "description": "Registry Messaging HTTP contract. Every refusal is one \
                            application/problem+json document from the closed vocabulary."
        },
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            },
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

/// The generator examples' shared entry point: parse `--output <directory>`
/// and write every document `generate` returns into it.
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

fn render(document: &Value) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(document)?;
    rendered.push('\n');
    Ok(rendered)
}

/// State in the schema the bounds `RuntimeConfig::check` enforces at load.
fn install_runtime_constraints(schema: &mut Value) {
    for (definition, property) in [
        ("RuntimePackageConfig", "root"),
        ("FileSecretProviderConfig", "root"),
        ("AuditConfig", "path"),
    ] {
        set_definition_property(schema, definition, property, "pattern", json!("^/"));
    }
    for (definition, property) in [
        ("DatabaseConfig", "runtimeUrlRef"),
        ("DatabaseConfig", "migrationUrlRef"),
        ("DatabaseConfig", "trustedRootCertificateRef"),
        ("AuditConfig", "hashKeyRef"),
    ] {
        set_definition_property(
            schema,
            definition,
            property,
            "pattern",
            json!("^secret:(?:env|file)/"),
        );
    }
    for (property, minimum, maximum) in [
        ("payloadDays", 1, MAXIMUM_PAYLOAD_DAYS),
        ("recordDays", 1, MAXIMUM_RECORD_DAYS),
        ("submissionReceiptDays", 1, MAXIMUM_RECORD_DAYS),
    ] {
        set_definition_property(
            schema,
            "RetentionConfig",
            property,
            "minimum",
            json!(minimum),
        );
        set_definition_property(
            schema,
            "RetentionConfig",
            property,
            "maximum",
            json!(maximum),
        );
    }
    set_definition_property(schema, "OidcConfig", "allowedClients", "minItems", json!(1));
    set_definition_property(
        schema,
        "OidcConfig",
        "allowedClients",
        "uniqueItems",
        json!(true),
    );
    if let Some(variants) = schema
        .pointer_mut("/$defs/OidcJwksSource/oneOf")
        .and_then(Value::as_array_mut)
    {
        for variant in variants {
            if let Some(document_reference) = variant
                .pointer_mut("/properties/documentRef")
                .and_then(Value::as_object_mut)
            {
                document_reference
                    .insert("pattern".to_owned(), json!(SECRET_REFERENCE_SCHEMA_PATTERN));
            }
        }
    }
    if let Some(property) = schema
        .pointer_mut("/$defs/OidcConfig/properties/assertionIssuers")
        .and_then(Value::as_object_mut)
    {
        property.insert(
            "maxProperties".to_owned(),
            json!(MAXIMUM_ASSERTION_ISSUER_CLIENTS),
        );
        property.insert(
            "propertyNames".to_owned(),
            json!({"minLength": 1, "maxLength": MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES}),
        );
        property.insert(
            "additionalProperties".to_owned(),
            json!({
                "type": "array",
                "minItems": 1,
                "maxItems": MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT,
                "uniqueItems": true,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAXIMUM_ASSERTION_ISSUER_BYTES
                }
            }),
        );
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
    use super::*;

    fn product_generated() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/generated")
    }

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        assert_eq!(first, runtime_documents().unwrap());
        let document: Value = serde_json::from_str(&first[RUNTIME_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], MESSAGING_RUNTIME_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            MESSAGING_RUNTIME_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            MESSAGING_RUNTIME_KIND
        );
    }

    #[test]
    fn the_schema_states_the_bounds_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        for (definition, property) in [
            ("RuntimePackageConfig", "root"),
            ("FileSecretProviderConfig", "root"),
            ("AuditConfig", "path"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"], "^/",
                "{definition}.{property} must be absolute"
            );
        }
        for (definition, property) in [
            ("DatabaseConfig", "runtimeUrlRef"),
            ("DatabaseConfig", "migrationUrlRef"),
            ("DatabaseConfig", "trustedRootCertificateRef"),
            ("AuditConfig", "hashKeyRef"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"],
                "^secret:(?:env|file)/",
                "{definition}.{property} must be a secret reference"
            );
        }
        assert_eq!(
            document["$defs"]["RetentionConfig"]["properties"]["payloadDays"]["maximum"],
            MAXIMUM_PAYLOAD_DAYS
        );
        assert_eq!(
            document["$defs"]["OidcConfig"]["properties"]["allowedClients"]["minItems"],
            1
        );
        assert_eq!(
            document["$defs"]["OidcConfig"]["additionalProperties"], false,
            "unknown keys are refused"
        );
        assert!(document["$defs"]["MetricsListenerConfig"].is_object());
    }

    #[test]
    fn openapi_lists_every_operation_and_only_catalogued_problems() {
        let documents = openapi_documents().unwrap();
        assert_eq!(documents, openapi_documents().unwrap());
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        for operation in OPERATIONS {
            let entry = &document["paths"][operation.path][operation.method];
            assert_eq!(entry["operationId"], operation.operation_id);
        }
        assert!(
            document["paths"].get("/metrics").is_none(),
            "the metrics listener is not part of the public contract"
        );
        let message = &document["paths"]["/v1/messages/{message_id}"]["get"];
        assert_eq!(message["security"], json!([{"bearer": []}]));
        assert!(message["responses"]["404"].is_object());
        assert!(message["responses"]["401"].is_object());
    }

    #[test]
    fn committed_documents_match_generated_bytes() {
        let generated = runtime_documents().unwrap();
        assert_eq!(
            std::fs::read_to_string(
                product_generated()
                    .join("runtime")
                    .join(RUNTIME_SCHEMA_FILE)
            )
            .expect("the committed runtime schema"),
            generated[RUNTIME_SCHEMA_FILE],
            "regenerate with the runtime-schema example"
        );
        let generated = openapi_documents().unwrap();
        assert_eq!(
            std::fs::read_to_string(product_generated().join(OPENAPI_FILE))
                .expect("the committed OpenAPI document"),
            generated[OPENAPI_FILE],
            "regenerate with the openapi example"
        );
    }
}
