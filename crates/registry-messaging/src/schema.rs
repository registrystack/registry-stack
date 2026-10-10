// SPDX-License-Identifier: Apache-2.0

//! Generated documents: the JSON Schemas for the Messaging runtime
//! configuration and the authored project, template, and provider files,
//! and the OpenAPI description of the HTTP surface.
//!
//! Every one is derived, never written by hand. The schemas come from the
//! strict reader types; the OpenAPI document comes from the same operation
//! table the router serves. Regenerate the committed documents with:
//!
//! ```bash
//! cargo run -p registry-messaging --features schema --example runtime-schema -- \
//!   --output products/messaging/generated/runtime
//! cargo run -p registry-messaging --features schema --example authoring-schema -- \
//!   --output products/messaging/generated/authoring
//! cargo run -p registry-messaging --features schema --example openapi -- \
//!   --output products/messaging/generated
//! ```
//!
//! The derived schema states the bounds `RuntimeConfig::check` enforces, so
//! a document an operator's editor accepts is one the runtime starts on.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use registry_messaging_core::typed::refuse_null;
use registry_messaging_core::{
    type_uri, MessageDispatch, MessageStatus, MessagingProject, ProblemCode, TemplateDocument,
    IDEMPOTENCY_KEY_HEADER, MAXIMUM_CORRELATION_ID_BYTES, MAXIMUM_IDEMPOTENCY_KEY_BYTES,
    MAXIMUM_SENDER_BYTES, MESSAGING_PROJECT_API_VERSION, MESSAGING_PROJECT_KIND,
    MESSAGING_PROJECT_SCHEMA_ID, MESSAGING_PROVIDER_API_VERSION, MESSAGING_PROVIDER_KIND,
    MESSAGING_PROVIDER_SCHEMA_ID, MESSAGING_RUNTIME_API_VERSION, MESSAGING_RUNTIME_KIND,
    MESSAGING_RUNTIME_SCHEMA_ID, MESSAGING_TEMPLATE_API_VERSION, MESSAGING_TEMPLATE_KIND,
    MESSAGING_TEMPLATE_SCHEMA_ID, PROJECT_SCHEMA_FILE, PROVIDER_SCHEMA_FILE, RUNTIME_SCHEMA_FILE,
    TEMPLATE_SCHEMA_FILE,
};

use crate::config::{RuntimeConfig, MAXIMUM_TLS_TRUST_PROFILES};
use crate::http::{RequestBody, OPERATIONS};
use crate::http_provider::HttpProviderPackage;
use crate::messages::MASKED_CONTACT;

/// File name of the generated OpenAPI document.
pub const OPENAPI_FILE: &str = "registry-messaging.openapi.json";

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    refuse_null_outside_shared_blocks(&mut derived)?;
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

/// The schemas of the three authored files a package holds: the project
/// `messaging.yaml`, each version's `template.yaml`, and each HTTP
/// provider's `provider.yaml`.
pub fn authoring_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [
        (
            PROJECT_SCHEMA_FILE,
            serde_json::to_value(schemars::schema_for!(MessagingProject))?,
            "Registry Messaging project",
            MESSAGING_PROJECT_SCHEMA_ID,
            MESSAGING_PROJECT_API_VERSION,
            MESSAGING_PROJECT_KIND,
        ),
        (
            TEMPLATE_SCHEMA_FILE,
            serde_json::to_value(schemars::schema_for!(TemplateDocument))?,
            "Registry Messaging template version",
            MESSAGING_TEMPLATE_SCHEMA_ID,
            MESSAGING_TEMPLATE_API_VERSION,
            MESSAGING_TEMPLATE_KIND,
        ),
        (
            PROVIDER_SCHEMA_FILE,
            serde_json::to_value(schemars::schema_for!(HttpProviderPackage))?,
            "Registry Messaging HTTP provider package",
            MESSAGING_PROVIDER_SCHEMA_ID,
            MESSAGING_PROVIDER_API_VERSION,
            MESSAGING_PROVIDER_KIND,
        ),
    ];
    entries
        .into_iter()
        .map(
            |(file, mut derived, title, identifier, api_version, kind)| {
                // The reader refuses `null` in every authored member (CFG-EMPTY-1).
                refuse_null(&mut derived);
                set_const(&mut derived, "apiVersion", api_version);
                set_const(&mut derived, "kind", kind);
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
                Ok((file, render(&Value::Object(object))?))
            },
        )
        .collect()
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
            let mut response = json!({
                "description": format!("A problem: {}.", codes.join(", ")),
                "content": {"application/problem+json": {"schema": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Problem"},
                        {"properties": {"code": {"enum": codes}}}
                    ]
                }}}
            });
            if let Some(headers) = problem_headers(status) {
                response["headers"] = headers;
            }
            responses.insert(status.to_string(), response);
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
                "description": "Scopes a retry to the caller's issuer and subject: the same \
                                key and request answer the stored receipt again, across an \
                                audit key rotation too. A retry is authorized and rendered \
                                again before its key is looked up, so a 403 or 422 answer to \
                                an exact retry does not mean the first attempt failed.",
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
                            "properties": {"email": {
                                "type": "string",
                                "minLength": 3,
                                "maxLength": MAXIMUM_SENDER_BYTES,
                                "pattern": "^[\\x21-\\x7e]+$",
                                "description": "One address, local@domain, of visible ASCII, \
                                                so its bound counts bytes and characters \
                                                alike."
                            }}
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
                                            within `retention.payloadRetentionDays` of acceptance, and \
                                            defaults to the sender profile's expiry."
                        },
                        "correlationId": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAXIMUM_CORRELATION_ID_BYTES,
                            "pattern": "^[^\\x00-\\x1f\\x7f-\\x9f]+$",
                            "description": format!(
                                "An opaque caller reference, stored, returned, and audited, \
                                 never interpreted. The runtime bounds it at \
                                 {MAXIMUM_CORRELATION_ID_BYTES} UTF-8 bytes, not characters, \
                                 and refuses control characters."
                            )
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
/// The headers every problem answered with `status` carries.
fn problem_headers(status: u16) -> Option<Value> {
    match status {
        401 => Some(json!({"WWW-Authenticate": {
            "description": "The bearer challenge.",
            "required": true,
            "schema": {"type": "string", "const": "Bearer"}
        }})),
        429 | 503 => Some(json!({"Retry-After": {
            "description": "Whole seconds to wait before trying again.",
            "required": true,
            "schema": {"type": "integer", "minimum": 1}
        }})),
        _ => None,
    }
}

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

/// The reader refuses `null` in every member (CFG-EMPTY-1), so drop the
/// `null` schemars adds to each optional Messaging member. The shared blocks
/// are embedded exactly as the platform publishes them.
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

/// State in the schema the rules `RuntimeConfig::check` enforces at load
/// beyond the reader types and the shared blocks, which carry their own.
fn install_runtime_constraints(schema: &mut Value) {
    // `identity` is optional in the Rust type only so that a missing block
    // gets a refusal naming the key to add; the document requires it.
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.push(json!("identity"));
    }
    for (definition, property) in [
        ("PackageConfig", "root"),
        ("FileSecretProviderConfig", "root"),
    ] {
        set_definition_property(schema, definition, property, "pattern", json!("^/"));
    }
    // Every access profile resolves its caller from the matched client, so
    // a Messaging deployment always lists the clients it admits. The shared
    // block requires the member and also admits the keyword `unrestricted`,
    // which this runtime refuses in every mode, so the member is restated
    // as the list alone and the shared definition is dropped.
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
    if let Some(profiles) = schema
        .pointer_mut("/properties/tlsTrustProfiles")
        .and_then(Value::as_object_mut)
    {
        profiles.insert(
            "maxProperties".to_owned(),
            json!(MAXIMUM_TLS_TRUST_PROFILES),
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
    use super::*;
    use crate::config::MAXIMUM_PAYLOAD_RETENTION_DAYS;

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
            ("PackageConfig", "root"),
            ("FileSecretProviderConfig", "root"),
            ("AuditConfig", "path"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"], "^/",
                "{definition}.{property} must be absolute"
            );
        }
        for property in [
            "runtimeUrlRef",
            "migrationUrlRef",
            "trustedRootCertificateRef",
        ] {
            assert_eq!(
                document["$defs"]["DatabaseConfig"]["properties"][property]["$ref"],
                "#/$defs/SecretReference",
                "DatabaseConfig.{property} must be a secret reference"
            );
        }
        assert_eq!(
            document["$defs"]["AuditConfig"]["properties"]["hashKeyRef"]["$ref"],
            "#/$defs/SecretReference",
            "AuditConfig.hashKeyRef must be a secret reference"
        );
        assert_eq!(
            document["$defs"]["PackageConfig"]["properties"]["expectedDigest"]["$ref"],
            "#/$defs/Digest",
            "package.expectedDigest must be a lowercase SHA-256 label"
        );
        assert_eq!(
            document["$defs"]["RetentionConfig"]["properties"]["payloadRetentionDays"]["maximum"],
            MAXIMUM_PAYLOAD_RETENTION_DAYS
        );
        // `allowedClients` is decided in every file, and only as a list:
        // the runtime refuses `unrestricted` in every mode.
        let oidc = &document["$defs"]["OidcConfig"];
        assert_eq!(
            oidc["required"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|member| *member == "allowedClients")
                .count(),
            1
        );
        let clients = &oidc["properties"]["allowedClients"];
        assert!(clients.get("default").is_none());
        assert!(clients.get("$ref").is_none(), "{clients}");
        assert_eq!(clients["type"], "array");
        assert_eq!(clients["minItems"], 1);
        assert_eq!(clients["uniqueItems"], true);
        assert_eq!(clients["items"]["minLength"], 1);
        assert!(document["$defs"].get("OidcAllowedClients").is_none());
        assert_eq!(
            document["$defs"]["OidcConfig"]["additionalProperties"], false,
            "unknown keys are refused"
        );
        for definition in ["ListenerConfig", "PrivateListenerConfig"] {
            assert!(
                document["$defs"][definition].is_object(),
                "{definition} must be present"
            );
            assert_eq!(
                document["$defs"][definition]["additionalProperties"], false,
                "{definition} must refuse unknown keys"
            );
        }
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
            .map(|variant| variant["properties"]["type"]["const"].as_str().unwrap())
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
                variant["properties"]["callbackVerifier"]["$ref"]
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
        let package = crate::package::load_project(&crate::package::tests::starter_root())
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
    fn openapi_publishes_the_headers_a_refusal_carries() {
        let documents = openapi_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        for operation in OPERATIONS {
            let responses = &document["paths"][operation.path][operation.method]["responses"];
            for problem in operation.problems {
                let status = problem.http_status();
                let headers = &responses[status.to_string()]["headers"];
                match status {
                    401 => assert_eq!(
                        headers["WWW-Authenticate"]["schema"]["const"], "Bearer",
                        "{}",
                        operation.operation_id
                    ),
                    429 | 503 => {
                        let schema = &headers["Retry-After"]["schema"];
                        assert_eq!(schema["type"], "integer", "{}", operation.operation_id);
                        assert_eq!(schema["minimum"], 1, "{}", operation.operation_id);
                    }
                    _ => assert!(headers.is_null(), "{}", operation.operation_id),
                }
            }
        }
    }

    #[test]
    fn openapi_states_contact_and_correlation_bounds_in_bytes() {
        let documents = openapi_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[OPENAPI_FILE]).unwrap();
        let schemas = &document["components"]["schemas"];
        let correlation = &schemas["SubmitMessageRequest"]["properties"]["correlationId"];
        assert_eq!(correlation["pattern"], "^[^\\x00-\\x1f\\x7f-\\x9f]+$");
        assert!(correlation["description"]
            .as_str()
            .unwrap()
            .contains("UTF-8 bytes"));
        let email = &schemas["Recipient"]["oneOf"][0]["properties"]["email"];
        assert_eq!(email["pattern"], "^[\\x21-\\x7e]+$");
        assert!(email["description"].as_str().unwrap().contains("bytes"));
    }

    #[test]
    fn the_shipped_examples_satisfy_the_authoring_schemas() {
        use registry_messaging_core::{MESSAGING_PROJECT_FORMAT, MESSAGING_TEMPLATE_FORMAT};
        use registry_platform_yaml::{Expect, Reader};

        use crate::http_provider::MESSAGING_PROVIDER_FORMAT;

        let documents = authoring_documents().unwrap();
        let examples = product_generated().join("../examples");
        for (schema_file, format, example) in [
            (
                PROJECT_SCHEMA_FILE,
                &MESSAGING_PROJECT_FORMAT,
                "starter/messaging.yaml",
            ),
            (
                TEMPLATE_SCHEMA_FILE,
                &MESSAGING_TEMPLATE_FORMAT,
                "starter/templates/appointment-reminder/1/template.yaml",
            ),
            (
                TEMPLATE_SCHEMA_FILE,
                &MESSAGING_TEMPLATE_FORMAT,
                "starter/templates/appointment-reminder-sms/1/template.yaml",
            ),
            (
                PROVIDER_SCHEMA_FILE,
                &MESSAGING_PROVIDER_FORMAT,
                "starter/providers/sms-gateway/provider.yaml",
            ),
            (
                PROVIDER_SCHEMA_FILE,
                &MESSAGING_PROVIDER_FORMAT,
                "providers/aws-sms/provider.yaml",
            ),
            (
                PROVIDER_SCHEMA_FILE,
                &MESSAGING_PROVIDER_FORMAT,
                "providers/form-sms-gateway/provider.yaml",
            ),
            (
                PROVIDER_SCHEMA_FILE,
                &MESSAGING_PROVIDER_FORMAT,
                "providers/mock/provider.yaml",
            ),
        ] {
            let schema: Value = serde_json::from_str(&documents[schema_file]).unwrap();
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema)
                .unwrap_or_else(|error| panic!("{schema_file} compiles: {error}"));
            let bytes = std::fs::read(examples.join(example)).unwrap();
            let instance = Reader::new(example)
                .read(&bytes, &Expect::one(format))
                .unwrap_or_else(|report| panic!("{example} reads: {report:?}"))
                .to_json_value();
            let errors: Vec<String> = match validator.validate(&instance) {
                Ok(()) => Vec::new(),
                Err(errors) => errors
                    .map(|error| format!("{}: {error}", error.instance_path))
                    .collect(),
            };
            assert!(
                errors.is_empty(),
                "{example} does not satisfy {schema_file}: {errors:?}"
            );
        }
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
        for (file, contents) in authoring_documents().unwrap() {
            assert_eq!(
                std::fs::read_to_string(product_generated().join("authoring").join(file))
                    .expect("the committed authoring schema"),
                contents,
                "regenerate with the authoring-schema example"
            );
        }
        let generated = openapi_documents().unwrap();
        assert_eq!(
            std::fs::read_to_string(product_generated().join(OPENAPI_FILE))
                .expect("the committed OpenAPI document"),
            generated[OPENAPI_FILE],
            "regenerate with the openapi example"
        );
    }
}
