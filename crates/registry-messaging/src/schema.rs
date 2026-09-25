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
    type_uri, MessageDispatch, MessageStatus, ProblemCode, IDEMPOTENCY_KEY_HEADER,
    MAXIMUM_CALLBACK_HEADER_BYTES, MAXIMUM_CALLBACK_URL_BYTES, MAXIMUM_CORRELATION_ID_BYTES,
    MAXIMUM_IDEMPOTENCY_KEY_BYTES, MAXIMUM_SENDER_BYTES, MESSAGING_RUNTIME_API_VERSION,
    MESSAGING_RUNTIME_KIND, MESSAGING_RUNTIME_SCHEMA_ID, RUNTIME_SCHEMA_FILE,
};

use crate::config::{
    RuntimeConfig, MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT, MAXIMUM_ASSERTION_ISSUER_BYTES,
    MAXIMUM_ASSERTION_ISSUER_CLIENTS, MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES, MAXIMUM_PAYLOAD_DAYS,
    MAXIMUM_RECORD_DAYS,
};
use crate::http::{RequestBody, OPERATIONS};
use crate::messages::MASKED_CONTACT;

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
            match operation.response_body {
                Some(schema) => json!({
                    "description": "The operation succeeded.",
                    "content": {"application/json": {"schema": {
                        "$ref": format!("#/components/schemas/{schema}")
                    }}}
                }),
                None => json!({"description": "The operation succeeded. The body is empty."}),
            },
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
        let mut parameters: Vec<Value> = path_parameters(operation.path)
            .map(|name| {
                json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": {"type": "string", "minLength": 1}
                })
            })
            .collect();
        if operation.idempotency_key {
            parameters.push(json!({
                "name": IDEMPOTENCY_KEY_HEADER,
                "in": "header",
                "required": true,
                "description": "Scopes a retry to the caller: the same key and request answer \
                                the stored receipt again.",
                "schema": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAXIMUM_IDEMPOTENCY_KEY_BYTES,
                    "pattern": "^[\\x21-\\x7e]+$"
                }
            }));
        }
        if !parameters.is_empty() {
            entry["parameters"] = Value::Array(parameters);
        }
        match operation.request_body {
            RequestBody::None => {}
            RequestBody::Json(schema) => {
                entry["requestBody"] = json!({
                    "required": true,
                    "content": {"application/json": {"schema": {
                        "$ref": format!("#/components/schemas/{schema}")
                    }}}
                });
            }
            RequestBody::ProviderCallback => {
                entry["requestBody"] = json!({
                    "required": false,
                    "description": "The body the provider sends, JSON or form-encoded, read \
                                    only by the provider package's receipt script after the \
                                    callback verified.",
                    "content": {
                        "application/json": {"schema": {}},
                        "application/x-www-form-urlencoded": {"schema": {"type": "object"}}
                    }
                });
            }
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
    let statuses: Vec<&str> = [
        MessageStatus::Queued,
        MessageStatus::Sending,
        MessageStatus::Submitted,
        MessageStatus::Delivered,
        MessageStatus::Failed,
        MessageStatus::Expired,
        MessageStatus::Cancelled,
        MessageStatus::Unknown,
    ]
    .iter()
    .map(|status| status.as_str())
    .collect();
    let dispatch_states: Vec<&str> = MessageDispatch::ALL
        .iter()
        .map(|dispatch| dispatch.as_str())
        .collect();
    let outcomes = [
        "in-progress",
        "accepted",
        "transient",
        "permanent",
        "maybe-sent",
        "interrupted",
    ];
    // The message view and its state vocabularies are built apart from the
    // document, which would otherwise exceed the `json!` macro's recursion
    // limit.
    let message_status = json!({
        "type": "string",
        "enum": statuses,
        "description": "Derived from dispatch and report: the dispatch state, except that a \
                        submitted message whose report is delivered is delivered, and one \
                        whose report is undelivered is failed."
    });
    let message_dispatch = json!({
        "type": "string",
        "enum": dispatch_states,
        "description": "What the dispatch worker did. submitted means the provider accepted \
                        the message, never that it was delivered."
    });
    let message_report = json!({
        "type": "string",
        "enum": ["none", "sent", "delivered", "undelivered", "unavailable"],
        "description": "What the provider's delivery receipts reported. It only moves \
                        forward, none then sent then delivered or undelivered, and a final \
                        report is never replaced. unavailable: the message's provider \
                        reports no delivery receipts, so submitted is the last status."
    });
    let message_view = json!({
        "type": "object",
        "additionalProperties": false,
        "description": "A message's status and metadata. The recipient is masked, \
                        and no part or template data is returned.",
        "required": [
            "id", "status", "dispatch", "report", "channel", "senderProfile",
            "to", "acceptedAt", "expiresAt", "updatedAt", "attempts", "links"
        ],
        "properties": {
            "id": {"type": "string", "format": "uuid"},
            "status": {"$ref": "#/components/schemas/MessageStatus"},
            "dispatch": {"$ref": "#/components/schemas/MessageDispatch"},
            "report": {"$ref": "#/components/schemas/MessageReport"},
            "reportedAt": {
                "type": "string",
                "format": "date-time",
                "description": "When the report last moved. Absent while it is \
                                none or unavailable."
            },
            "channel": {"type": "string", "enum": ["email", "sms"]},
            "senderProfile": {"type": "string"},
            "to": {"$ref": "#/components/schemas/MaskedRecipient"},
            "template": {"$ref": "#/components/schemas/TemplateReference"},
            "correlationId": {"type": "string"},
            "acceptedAt": {"type": "string", "format": "date-time"},
            "notBefore": {"type": "string", "format": "date-time"},
            "expiresAt": {"type": "string", "format": "date-time"},
            "updatedAt": {"type": "string", "format": "date-time"},
            "attempts": {
                "type": "array",
                "items": {"$ref": "#/components/schemas/AttemptSummary"}
            },
            "links": {"$ref": "#/components/schemas/MessageLinks"}
        }
    });
    let mut document = json!({
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
                },
                "Recipient": {
                    "description": "Exactly one contact, typed by the channel that carries it: \
                                    an email address, or an E.164 phone number.",
                    "oneOf": [
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["email"],
                            "properties": {"email": {"type": "string", "minLength": 3, "maxLength": MAXIMUM_SENDER_BYTES}}
                        },
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["phone"],
                            "properties": {"phone": {"type": "string", "pattern": "^\\+[1-9][0-9]{1,14}$"}}
                        }
                    ]
                },
                "MaskedRecipient": {
                    "description": "The recipient's kind, with its contact masked.",
                    "oneOf": [
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["email"],
                            "properties": {"email": {"const": MASKED_CONTACT}}
                        },
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["phone"],
                            "properties": {"phone": {"const": MASKED_CONTACT}}
                        }
                    ]
                },
                "TemplateReference": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "version"],
                    "properties": {
                        "id": {"type": "string"},
                        "version": {"type": "string"}
                    }
                },
                "SubmitMessageRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "description": "One message: a template version with its locale and data, \
                                    or direct content where the access profile allows it, never \
                                    both. Every endpoint, credential, and script is bound by \
                                    the operator; no member chooses one.",
                    "required": ["senderProfile", "to"],
                    "properties": {
                        "senderProfile": {
                            "type": "string",
                            "description": "A sender profile the caller's access profile lists."
                        },
                        "to": {"$ref": "#/components/schemas/Recipient"},
                        "template": {"$ref": "#/components/schemas/TemplateReference"},
                        "locale": {
                            "type": "string",
                            "description": "A locale the template version declares; required \
                                            with `template`."
                        },
                        "data": {
                            "description": "The template data, validated against the template \
                                            version's schema; required with `template`. It is \
                                            rendered at acceptance and never stored."
                        },
                        "content": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["text"],
                            "description": "Direct content, instead of `template`.",
                            "properties": {
                                "subject": {"type": "string"},
                                "text": {"type": "string"}
                            }
                        },
                        "notBefore": {
                            "type": "string",
                            "format": "date-time",
                            "description": "The earliest instant the message may be sent."
                        },
                        "expiresAt": {
                            "type": "string",
                            "format": "date-time",
                            "description": "The instant an unsent message expires. It must lie \
                                            within `retention.payloadDays` of acceptance, and \
                                            defaults to the sender profile's expiry."
                        },
                        "correlationId": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAXIMUM_CORRELATION_ID_BYTES,
                            "description": "An opaque caller reference, stored, returned, and \
                                            audited, never interpreted."
                        }
                    }
                },
                "MessageStatus": message_status,
                "MessageLinks": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["self", "cancel"],
                    "properties": {
                        "self": {"type": "string"},
                        "cancel": {"type": "string"}
                    }
                },
                "MessageReceipt": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "status", "links"],
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "status": {"$ref": "#/components/schemas/MessageStatus"},
                        "links": {"$ref": "#/components/schemas/MessageLinks"}
                    }
                },
                "AttemptSummary": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["generation", "attempt", "outcome", "startedAt", "providerReference"],
                    "properties": {
                        "generation": {"type": "integer", "minimum": 1},
                        "attempt": {"type": "integer", "minimum": 1},
                        "outcome": {"type": "string", "enum": outcomes},
                        "startedAt": {"type": "string", "format": "date-time"},
                        "finishedAt": {"type": "string", "format": "date-time"},
                        "providerReference": {
                            "type": "boolean",
                            "description": "Whether the provider returned a reference. The \
                                            reference itself is not returned."
                        }
                    }
                },
                "MessageView": message_view,
                "TemplatePreviewRequest": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["locale", "data"],
                    "properties": {
                        "locale": {
                            "type": "string",
                            "description": "A locale the template version declares."
                        },
                        "data": {
                            "description": "The template data, validated against the template \
                                            version's schema before rendering."
                        }
                    }
                },
                "TemplatePreview": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["template", "locale", "channel", "packageDigest", "parts"],
                    "properties": {
                        "template": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["id", "version"],
                            "properties": {
                                "id": {"type": "string"},
                                "version": {"type": "string"}
                            }
                        },
                        "locale": {"type": "string"},
                        "channel": {"type": "string", "enum": ["email", "sms"]},
                        "packageDigest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                        "parts": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["text"],
                            "properties": {
                                "subject": {"type": "string"},
                                "text": {"type": "string"},
                                "html": {"type": "string"}
                            }
                        },
                        "sms": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["encoding", "units", "segments"],
                            "description": "The segment count, for an SMS template only.",
                            "properties": {
                                "encoding": {"type": "string", "enum": ["gsm7", "ucs2"]},
                                "units": {"type": "integer", "minimum": 0},
                                "segments": {"type": "integer", "minimum": 1}
                            }
                        }
                    }
                }
            }
        }
    });
    let schemas = document["components"]["schemas"]
        .as_object_mut()
        .expect("the components hold a schema map");
    schemas.insert("MessageDispatch".to_owned(), message_dispatch);
    schemas.insert("MessageReport".to_owned(), message_report);
    Ok([(OPENAPI_FILE, render(&document)?)].into())
}

/// The `{name}` segments of a route template, in order.
fn path_parameters(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter_map(|segment| {
        segment
            .strip_prefix('{')
            .and_then(|segment| segment.strip_suffix('}'))
    })
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
    install_callback_verifier(schema);
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

/// The callback verifier is decoded by the core's closed type, which the
/// schema feature does not derive; publish its three kinds precisely in
/// place of the open object the settings type declares.
fn install_callback_verifier(schema: &mut Value) {
    let header = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAXIMUM_CALLBACK_HEADER_BYTES,
        "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
    });
    let reference = json!({"type": "string", "pattern": SECRET_REFERENCE_SCHEMA_PATTERN});
    let verifier = json!({
        "description": "How the provider's delivery callbacks are authenticated, from a closed \
                        set of algorithms. Required exactly when the package declares \
                        `receipts: callback`; there is no unauthenticated kind.",
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "description": "HMAC-SHA1 over `url` and the request's query, followed by the \
                                form parameters sorted by name, base64 in `header`.",
                "required": ["kind", "url", "header", "secretRef"],
                "properties": {
                    "kind": {"type": "string", "const": "hmac-sha1-url-form"},
                    "url": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAXIMUM_CALLBACK_URL_BYTES,
                        "pattern": "^https?://[^?#]+$",
                        "description": "The external callback URL the provider was given and \
                                        signs, exactly as given, without a query or fragment."
                    },
                    "header": header,
                    "secretRef": reference
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "description": "HMAC-SHA256 over the raw request body, in `header` as `encoding`.",
                "required": ["kind", "header", "encoding", "secretRef"],
                "properties": {
                    "kind": {"type": "string", "const": "hmac-sha256-body"},
                    "header": header,
                    "encoding": {"type": "string", "enum": ["hex", "base64"]},
                    "secretRef": reference
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "description": "A secret random token as the last segment of the callback path.",
                "required": ["kind", "tokenRef"],
                "properties": {
                    "kind": {"type": "string", "const": "path-token"},
                    "tokenRef": reference
                }
            }
        ]
    });
    if let Some(definitions) = schema.pointer_mut("/$defs").and_then(Value::as_object_mut) {
        definitions.insert("CallbackVerifierConfig".to_owned(), verifier);
    }
    if let Some(variants) = schema
        .pointer_mut("/$defs/ProviderConnection/oneOf")
        .and_then(Value::as_array_mut)
    {
        for variant in variants {
            if let Some(member) = variant.pointer_mut("/properties/callbackVerifier") {
                *member = json!({
                    "anyOf": [{"$ref": "#/$defs/CallbackVerifierConfig"}, {"type": "null"}]
                });
            }
        }
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
    fn the_runtime_schema_publishes_the_closed_callback_verifier_kinds() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        let kinds: Vec<&str> = document["$defs"]["CallbackVerifierConfig"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| variant["properties"]["kind"]["const"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            ["hmac-sha1-url-form", "hmac-sha256-body", "path-token"]
        );
        let referenced = document["$defs"]["ProviderConnection"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|variant| {
                variant["properties"]["callbackVerifier"]["anyOf"][0]["$ref"]
                    == "#/$defs/CallbackVerifierConfig"
            })
            .count();
        assert_eq!(referenced, 1, "only the http connection names a verifier");
    }

    #[test]
    fn the_callback_operations_take_no_bearer_and_any_provider_body() {
        let documents = openapi_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        for path in [
            registry_messaging_core::PROVIDER_CALLBACK_PATH,
            registry_messaging_core::PROVIDER_CALLBACK_TOKEN_PATH,
        ] {
            let callback = &document["paths"][path]["post"];
            assert_eq!(callback["security"], json!([]));
            assert!(callback["responses"]["204"].is_object());
            assert!(callback["responses"]["401"].is_null());
            assert_eq!(
                callback["responses"]["403"]["content"]["application/problem+json"]["schema"]
                    ["allOf"][1]["properties"]["code"]["enum"],
                json!(["callback.unverified"])
            );
            assert_eq!(
                callback["responses"]["422"]["content"]["application/problem+json"]["schema"]
                    ["allOf"][1]["properties"]["code"]["enum"],
                json!(["callback.unreadable"])
            );
            let content = &callback["requestBody"]["content"];
            assert!(content["application/json"].is_object());
            assert!(content["application/x-www-form-urlencoded"].is_object());
        }
    }

    #[test]
    fn the_preview_operation_publishes_its_path_parameters_and_bodies() {
        let documents = openapi_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        let preview = &document["paths"][registry_messaging_core::TEMPLATE_PREVIEW_PATH]["post"];
        let names: Vec<&str> = preview["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["template_id", "version"]);
        assert_eq!(
            preview["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TemplatePreviewRequest"
        );
        assert_eq!(
            preview["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TemplatePreview"
        );
        let message = &document["paths"]["/v1/messages/{message_id}"]["get"];
        assert_eq!(message["parameters"][0]["name"], "message_id");
        assert!(message.get("requestBody").is_none());
    }

    /// The published preview schemas are written out by hand, since the core
    /// types carry no schema derive; this holds them to what the core
    /// serializes, member for member.
    #[test]
    fn the_published_preview_schemas_name_exactly_the_serialized_members() {
        let documents = openapi_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        let schemas = &document["components"]["schemas"];
        let package = crate::package::load_package(&crate::package::tests::starter_root())
            .unwrap()
            .package;
        let request = registry_messaging_core::TemplatePreviewRequest {
            locale: "en".to_owned(),
            data: json!({"name": "Ada", "day": "2026-10-01", "office": "Office"}),
        };
        let email = package
            .preview("appointment-reminder", "1", &request)
            .unwrap();
        let sms = package
            .preview("appointment-reminder-sms", "1", &request)
            .unwrap();
        fn members(value: &Value) -> Vec<String> {
            let mut members: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
            members.sort();
            members
        }
        let email = serde_json::to_value(email).unwrap();
        let sms = serde_json::to_value(sms).unwrap();
        let preview = &schemas["TemplatePreview"];
        assert_eq!(members(&sms), members(&preview["properties"]));
        assert_eq!(
            members(&email["parts"]),
            members(&preview["properties"]["parts"]["properties"])
        );
        assert_eq!(
            members(&sms["sms"]),
            members(&preview["properties"]["sms"]["properties"])
        );
        assert_eq!(
            members(&email["template"]),
            members(&preview["properties"]["template"]["properties"])
        );
        assert_eq!(
            members(&serde_json::to_value(&request).unwrap()),
            members(&schemas["TemplatePreviewRequest"]["properties"])
        );
        let encoding = sms["sms"]["encoding"].clone();
        assert!(
            preview["properties"]["sms"]["properties"]["encoding"]["enum"]
                .as_array()
                .unwrap()
                .contains(&encoding)
        );
    }

    /// The message schemas are written out by hand too; this holds them to
    /// what the core serializes and parses, member for member.
    #[test]
    fn the_published_message_schemas_name_exactly_the_serialized_members() {
        use registry_messaging_core::{
            AttemptOutcome, AttemptSummary, Channel, DeliveryReport, MessageLinks, MessageReceipt,
            MessageReport, MessageView, Recipient, SubmitMessageRequest, TemplateReference,
        };
        let documents = openapi_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        let schemas = &document["components"]["schemas"];
        fn members(value: &Value) -> Vec<String> {
            let mut members: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
            members.sort();
            members
        }
        let request: SubmitMessageRequest = serde_json::from_value(json!({
            "senderProfile": "p",
            "to": {"email": "a@example.org"},
            "template": {"id": "t", "version": "1"},
            "locale": "en",
            "data": {},
            "content": {"subject": "s", "text": "t"},
            "notBefore": "2026-10-01T00:00:00Z",
            "expiresAt": "2026-10-02T00:00:00Z",
            "correlationId": "c"
        }))
        .unwrap();
        assert_eq!(
            members(&serde_json::to_value(&request).unwrap()),
            members(&schemas["SubmitMessageRequest"]["properties"])
        );
        let view = MessageView {
            id: "m".to_owned(),
            status: MessageStatus::Delivered,
            dispatch: MessageDispatch::Submitted,
            report: MessageReport::Delivered,
            reported_at: Some("r".to_owned()),
            channel: Channel::Email,
            sender_profile: "p".to_owned(),
            to: Recipient::Email(MASKED_CONTACT.to_owned()),
            template: Some(TemplateReference {
                id: "t".to_owned(),
                version: "1".to_owned(),
            }),
            correlation_id: Some("c".to_owned()),
            accepted_at: "a".to_owned(),
            not_before: Some("n".to_owned()),
            expires_at: "e".to_owned(),
            updated_at: "u".to_owned(),
            attempts: vec![AttemptSummary {
                generation: 1,
                attempt: 1,
                outcome: AttemptOutcome::MaybeSent,
                started_at: "s".to_owned(),
                finished_at: Some("f".to_owned()),
                provider_reference: false,
            }],
            links: MessageLinks::for_message("m"),
        };
        let serialized = serde_json::to_value(&view).unwrap();
        let published = &schemas["MessageView"];
        assert_eq!(members(&serialized), members(&published["properties"]));
        assert_eq!(
            members(&serialized["attempts"][0]),
            members(&schemas["AttemptSummary"]["properties"])
        );
        assert_eq!(
            members(&serialized["links"]),
            members(&schemas["MessageLinks"]["properties"])
        );
        assert!(schemas["AttemptSummary"]["properties"]["outcome"]["enum"]
            .as_array()
            .unwrap()
            .contains(&serialized["attempts"][0]["outcome"]));
        let published_reports: Vec<Value> = [MessageReport::None, MessageReport::Unavailable]
            .into_iter()
            .chain(DeliveryReport::ALL.into_iter().map(MessageReport::from))
            .map(|report| serde_json::to_value(report).unwrap())
            .collect();
        let mut enumerated = schemas["MessageReport"]["enum"].as_array().unwrap().clone();
        let mut expected = published_reports;
        enumerated.sort_by_key(ToString::to_string);
        expected.sort_by_key(ToString::to_string);
        assert_eq!(enumerated, expected);
        let receipt = MessageReceipt {
            id: "m".to_owned(),
            status: MessageStatus::Queued,
            links: MessageLinks::for_message("m"),
        };
        assert_eq!(
            members(&serde_json::to_value(&receipt).unwrap()),
            members(&schemas["MessageReceipt"]["properties"])
        );
        let submit = &document["paths"][registry_messaging_core::MESSAGES_PATH]["post"];
        assert_eq!(submit["parameters"][0]["name"], IDEMPOTENCY_KEY_HEADER);
        assert_eq!(submit["parameters"][0]["in"], "header");
        assert!(submit["responses"]["202"].is_object());
        assert!(submit["responses"]["409"].is_object());
        assert!(submit["responses"]["410"].is_object());
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
