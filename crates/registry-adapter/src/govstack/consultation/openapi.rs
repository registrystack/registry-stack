// SPDX-License-Identifier: Apache-2.0

//! Fixed OpenAPI 3.1 assembly for the unified GovStack target.

use std::collections::{BTreeMap, BTreeSet};

use registry_adapter_core::{AdapterProject, HttpMethod};
use serde_json::{json, Map, Value};

use super::{ConsultationCapability, CAPABILITIES_PATH, MOUNT_PATH};

#[derive(Clone, Debug)]
pub struct OpenApiSchema {
    pub identity: String,
    pub component: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiError {
    pub code: &'static str,
    pub message: &'static str,
}

fn refusal(code: &'static str, message: &'static str) -> OpenApiError {
    OpenApiError { code, message }
}

pub fn assemble_openapi(
    project: &AdapterProject,
    schemas: &BTreeMap<String, OpenApiSchema>,
) -> Result<Value, Vec<OpenApiError>> {
    if project.consultation.is_none() && project.write.is_none() {
        return Err(vec![refusal(
            "adapterctl.compile.consultation-missing",
            "the project does not select the built-in GovStack facade",
        )]);
    }
    let target = project.consultation.as_ref();
    let mut findings = Vec::new();
    let mut paths = Map::new();
    let mut operation_ids = BTreeSet::new();
    for binding in project.bindings.iter() {
        let Some(capability) =
            ConsultationCapability::from_binding_operation(binding.operation.as_str())
        else {
            continue;
        };
        if !super::valid_collection_id(binding.record_type.as_str()) {
            findings.push(refusal(
                "adapterctl.compile.govstack-collection-id",
                "a GovStack collection id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
            ));
            continue;
        }
        let Some(collection) =
            target.and_then(|target| target.collections.get(binding.record_type.as_str()))
        else {
            findings.push(refusal(
                "adapterctl.compile.consultation-collection",
                "a Consultation binding has no collection metadata",
            ));
            continue;
        };
        if !super::valid_view_id(collection.view.as_str()) {
            findings.push(refusal(
                "adapterctl.compile.govstack-view-id",
                "a GovStack view id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
            ));
            continue;
        }
        if !schemas.contains_key(collection.data_schema.as_str()) {
            findings.push(refusal(
                "adapterctl.compile.consultation-schema",
                "a Consultation collection data schema has no loaded versioned identity",
            ));
            continue;
        }
        let request_schema = match capability {
            ConsultationCapability::Lookup => collection.lookup.as_ref().and_then(|lookup| {
                schemas.contains_key(lookup.input_schema.as_str()).then(|| {
                    super::lookup_request_schema(
                        lookup.selector.as_str(),
                        &component_reference(lookup.input_schema.as_str()),
                    )
                })
            }),
            ConsultationCapability::Search => collection.search.as_ref().and_then(|search| {
                schemas.contains_key(search.input_schema.as_str()).then(|| {
                    super::search_request_schema(
                        search.search.as_str(),
                        &component_reference(search.input_schema.as_str()),
                    )
                })
            }),
            ConsultationCapability::Retrieve | ConsultationCapability::List => None,
        };
        if matches!(
            capability,
            ConsultationCapability::Lookup | ConsultationCapability::Search
        ) && request_schema.is_none()
        {
            findings.push(refusal(
                "adapterctl.compile.consultation-input-schema",
                "a named Consultation input has no loaded versioned schema identity",
            ));
            continue;
        }
        let success_schema = match capability {
            ConsultationCapability::Retrieve | ConsultationCapability::Lookup => {
                super::record_schema(&component_reference(collection.data_schema.as_str()))
            }
            ConsultationCapability::List | ConsultationCapability::Search => {
                super::record_page_schema(&component_reference(collection.data_schema.as_str()))
            }
        };
        let path = capability
            .path()
            .replace("{collectionId}", binding.record_type.as_str());
        let operation_id = capability.operation_id(binding.record_type.as_str());
        if !operation_ids.insert(operation_id.clone()) {
            findings.push(refusal(
                "adapterctl.compile.consultation-operation-id-collision",
                "two Consultation collections normalize to the same caller-visible operationId",
            ));
            continue;
        }
        let method = match capability.method() {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put | HttpMethod::Patch => unreachable!("Consultation is read only"),
        };
        let mut operation = json!({
            "operationId": operation_id,
            "x-govstack-digital-registries": {"registry": collection.registry, "collection": binding.record_type.as_str(), "capability": capability, "view": collection.view.as_str()},
            "responses": problem_responses(capability),
            "security": [{"bearerAuth": []}],
        });
        let mut parameters = vec![traceparent_parameter()];
        match capability {
            ConsultationCapability::Retrieve => {
                parameters.insert(0, json!({"name": "recordId", "in": "path", "required": true, "schema": {"type": "string", "minLength": 1, "maxLength": 256}}));
            }
            ConsultationCapability::List => {
                parameters.splice(
                    0..0,
                    [
                        json!({"name": "pageSize", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}),
                        json!({"name": "cursor", "in": "query", "required": false, "schema": crate::engine::effective_contract::cursor_schema()}),
                    ],
                );
            }
            ConsultationCapability::Lookup | ConsultationCapability::Search => {}
        }
        operation["parameters"] = Value::Array(parameters);
        if let Some(schema) = request_schema {
            operation["requestBody"] =
                json!({"required": true, "content": {"application/json": {"schema": schema}}});
        }
        let mut success_headers = response_headers("200");
        if capability == ConsultationCapability::Retrieve
            && is_write_update_companion(project, binding.id.as_str())
        {
            success_headers["ETag"] = strong_etag_header();
        }
        operation["responses"]["200"] = json!({"description": "The operation's response envelope for the bound record type.", "headers": success_headers, "content": {"application/json": {"schema": success_schema}}});
        paths.entry(path).or_insert_with(|| json!({}))[method] = operation;
    }
    if let Some(write) = project.write.as_ref() {
        for collection in write
            .collections
            .iter()
            .filter(|collection| collection.update.is_some())
        {
            let update = collection
                .update
                .as_ref()
                .expect("the filtered Write collection has Update metadata");
            let Some(binding) = update
                .companion_read
                .as_deref()
                .and_then(|id| project.bindings.get(id))
            else {
                continue;
            };
            if binding.record_type != collection.record_type
                || binding.operation.as_str() != "writable-read"
            {
                continue;
            }
            if !super::valid_collection_id(binding.record_type.as_str()) {
                findings.push(refusal(
                    "adapterctl.compile.govstack-collection-id",
                    "a GovStack collection id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
                ));
                continue;
            }
            let metadata = match crate::govstack::write::metadata::collection_metadata(
                project,
                binding.record_type.as_str(),
            ) {
                Ok(metadata) => metadata,
                Err(_) => {
                    findings.push(refusal(
                        "adapterctl.compile.write-companion-read",
                        "a guarded Write operation has incomplete companion read metadata",
                    ));
                    continue;
                }
            };
            let (Some(view), Some(data_schema)) = (metadata.view, metadata.read_data_schema) else {
                findings.push(refusal(
                    "adapterctl.compile.write-companion-read",
                    "a guarded Write operation has incomplete companion read metadata",
                ));
                continue;
            };
            if !super::valid_view_id(view) {
                findings.push(refusal(
                    "adapterctl.compile.govstack-view-id",
                    "a GovStack view id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
                ));
                continue;
            }
            if !schemas.contains_key(data_schema) {
                findings.push(refusal(
                    "adapterctl.compile.write-companion-read",
                    "a guarded Write companion read schema has no loaded versioned identity",
                ));
                continue;
            }
            let operation_id =
                ConsultationCapability::Retrieve.operation_id(binding.record_type.as_str());
            if !operation_ids.insert(operation_id.clone()) {
                findings.push(refusal(
                    "adapterctl.compile.consultation-operation-id-collision",
                    "two Consultation collections normalize to the same caller-visible operationId",
                ));
                continue;
            }
            let path = ConsultationCapability::Retrieve
                .path()
                .replace("{collectionId}", binding.record_type.as_str());
            let mut responses = problem_responses(ConsultationCapability::Retrieve);
            let mut success_headers = response_headers("200");
            success_headers["ETag"] = strong_etag_header();
            responses["200"] = json!({
                "description": "The operation's response envelope for the bound record type.",
                "headers": success_headers,
                "content": {"application/json": {"schema": super::record_schema(
                    &component_reference(data_schema)
                )}}
            });
            paths.entry(path).or_insert_with(|| json!({}))["get"] = json!({
                "operationId": operation_id,
                "x-govstack-digital-registries": {
                    "registry": metadata.registry,
                    "collection": binding.record_type.as_str(),
                    "capability": ConsultationCapability::Retrieve,
                    "view": view
                },
                "parameters": [
                    {"name": "recordId", "in": "path", "required": true, "schema": {
                        "type": "string", "minLength": 1, "maxLength": 256
                    }},
                    traceparent_parameter()
                ],
                "responses": responses,
                "security": [{"bearerAuth": []}]
            });
        }
        for binding in project.bindings.iter() {
            let Some(capability) =
                crate::govstack::write::attachment::WriteCapability::from_binding_operation(
                    binding.operation.as_str(),
                )
            else {
                continue;
            };
            if !super::valid_collection_id(binding.record_type.as_str()) {
                findings.push(refusal(
                    "adapterctl.compile.govstack-collection-id",
                    "a GovStack collection id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
                ));
                continue;
            }
            let Some(collection) = write.collections.get(binding.record_type.as_str()) else {
                continue;
            };
            if capability == crate::govstack::write::attachment::WriteCapability::Update {
                let companion_view = collection.view.as_deref().or_else(|| {
                    target
                        .and_then(|target| target.collections.get(binding.record_type.as_str()))
                        .map(|collection| collection.view.as_str())
                });
                if companion_view.is_some_and(|view| !super::valid_view_id(view)) {
                    findings.push(refusal(
                        "adapterctl.compile.govstack-view-id",
                        "a GovStack view id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
                    ));
                    continue;
                }
            }
            let input_schema = match capability {
                crate::govstack::write::attachment::WriteCapability::Create => collection
                    .create
                    .as_ref()
                    .map(|operation| operation.input_schema.as_str()),
                crate::govstack::write::attachment::WriteCapability::Update => collection
                    .update
                    .as_ref()
                    .map(|operation| operation.input_schema.as_str()),
            };
            let Some(input_schema) = input_schema else {
                continue;
            };
            if !schemas.contains_key(input_schema) {
                findings.push(refusal(
                    "adapterctl.compile.write-input-schema",
                    "a direct Write input has no loaded versioned schema identity",
                ));
                continue;
            }
            let operation_id = capability.operation_id(binding.record_type.as_str());
            if !operation_ids.insert(operation_id.clone()) {
                findings.push(refusal(
                    "adapterctl.compile.write-operation-id-collision",
                    "two Write collections normalize to the same caller-visible operationId",
                ));
                continue;
            }
            let metadata = match crate::govstack::write::metadata::collection_metadata(
                project,
                binding.record_type.as_str(),
            ) {
                Ok(metadata) => metadata,
                Err(_) => {
                    findings.push(refusal(
                        "adapterctl.compile.write-collection",
                        "a direct Write binding has incomplete collection metadata",
                    ));
                    continue;
                }
            };
            let mut extension = json!({
                "registry": metadata.registry,
                "collection": binding.record_type.as_str(),
                "capability": capability,
                "inputSchema": component_reference(input_schema),
            });
            if capability == crate::govstack::write::attachment::WriteCapability::Update {
                let view = metadata.view.ok_or_else(|| {
                    vec![refusal(
                        "adapterctl.compile.write-companion-read",
                        "a guarded Write operation has no companion read view",
                    )]
                })?;
                if !super::valid_view_id(view) {
                    findings.push(refusal(
                        "adapterctl.compile.govstack-view-id",
                        "a GovStack view id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters",
                    ));
                    continue;
                }
                extension["inputMediaType"] = json!("application/merge-patch+json");
                extension["companionRead"] = json!({
                    "operationId": ConsultationCapability::Retrieve.operation_id(binding.record_type.as_str()),
                    "view": view,
                });
            }
            let path = capability
                .path()
                .replace("{collectionId}", binding.record_type.as_str());
            let mut parameters = vec![traceparent_parameter(), idempotency_key_parameter()];
            if capability == crate::govstack::write::attachment::WriteCapability::Update {
                parameters.insert(0, record_id_parameter());
                parameters.push(if_match_parameter());
            }
            let media_type =
                if capability == crate::govstack::write::attachment::WriteCapability::Create {
                    "application/json"
                } else {
                    "application/merge-patch+json"
                };
            let mut content = Map::new();
            content.insert(
                media_type.to_owned(),
                json!({"schema": write_request_schema(input_schema)}),
            );
            let mut operation = json!({
                "operationId": operation_id,
                "x-govstack-digital-registries-write": extension,
                "parameters": parameters,
                "requestBody": {"required": true, "content": content},
                "responses": write_problem_responses(capability),
                "security": [{"bearerAuth": []}],
            });
            let success_status = capability.success_status().to_string();
            match capability {
                crate::govstack::write::attachment::WriteCapability::Create => {
                    operation["responses"][success_status.as_str()] = json!({
                        "description": "The Record was authoritatively created.",
                        "headers": write_success_headers(true),
                        "content": {"application/json": {"schema": write_result_schema()}},
                    });
                }
                crate::govstack::write::attachment::WriteCapability::Update => {
                    operation["responses"][success_status.as_str()] = json!({
                        "description": "The Record was authoritatively updated.",
                        "headers": write_success_headers(false),
                    });
                }
            }
            let method = match capability.method() {
                HttpMethod::Post => "post",
                HttpMethod::Patch => "patch",
                HttpMethod::Get | HttpMethod::Put => unreachable!("Write is POST or PATCH"),
            };
            paths.entry(path).or_insert_with(|| json!({}))[method] = operation;
        }
    }
    paths.insert(CAPABILITIES_PATH.to_owned(), capabilities_operation());
    if !findings.is_empty() {
        return Err(findings);
    }
    let mut component_schemas = Map::new();
    component_schemas.insert("Problem".to_owned(), problem_schema(false));
    component_schemas.insert("ValidationProblem".to_owned(), problem_schema(true));
    component_schemas.insert(
        "UnprocessableContentProblem".to_owned(),
        write_unprocessable_content_schema(),
    );
    for (id, schema) in schemas {
        let mut component = schema.component.clone();
        if let Some(object) = component.as_object_mut() {
            object.insert(
                "x-public-schema-id".to_owned(),
                Value::String(schema.identity.clone()),
            );
        }
        component_schemas.insert(id.clone(), component);
    }
    Ok(json!({
        "openapi": "3.1.0",
        "info": {"title": project.project.id.as_str(), "version": project.project.version},
        "servers": [{"url": MOUNT_PATH}],
        "paths": paths,
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}, "schemas": component_schemas},
    }))
}

fn component_reference(id: &str) -> String {
    format!("#/components/schemas/{id}")
}
fn traceparent_parameter() -> Value {
    json!({
        "name": "traceparent",
        "in": "header",
        "required": false,
        "description": "W3C Trace Context. A valid context is propagated; absent or invalid context is replaced.",
        "schema": {"type": "string"},
    })
}

pub(super) fn is_write_update_companion(project: &AdapterProject, binding: &str) -> bool {
    project.write.as_ref().is_some_and(|write| {
        write.collections.iter().any(|collection| {
            collection
                .update
                .as_ref()
                .is_some_and(|update| update.companion_read.as_deref() == Some(binding))
        })
    })
}

fn strong_etag_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 3,
        "maxLength": 258,
        "pattern": r#"^"[\x21\x23-\x7E]{1,256}"(?![\s\S])"#
    })
}

fn strong_etag_header() -> Value {
    json!({
        "description": "Strong opaque validator suitable for If-Match; weak validators are forbidden.",
        "required": true,
        "schema": strong_etag_schema()
    })
}

fn response_headers(status: &str) -> Value {
    let mut headers = json!({
        "Cache-Control": {
            "description": "Protected reads and errors are not stored.",
            "schema": {"type": "string", "const": "no-store"},
        },
    });
    if status == "401" {
        headers["WWW-Authenticate"] = json!({
            "description": "Bearer authentication challenge with no record-specific facts.",
            "schema": {"type": "string"},
        });
    }
    if matches!(status, "429" | "503") {
        headers["Retry-After"] = json!({
            "description": "Optional delay in seconds or HTTP-date before retrying.",
            "schema": {"type": "string"},
        });
    }
    headers
}

fn problem_response(status: &str, description: &str, schema: &str) -> Value {
    json!({"description": description, "headers": response_headers(status), "content": {"application/problem+json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}})
}

fn problem_responses(capability: ConsultationCapability) -> Value {
    let mut responses = json!({
        "400": problem_response("400", "The request is not valid.", "Problem"),
        "401": problem_response("401", "The caller was not authenticated.", "Problem"),
        "403": problem_response("403", "The caller is not authorized.", "Problem"),
        "404": problem_response("404", "The collection or record is not available.", "Problem"),
        "406": problem_response("406", "The response media type is not acceptable.", "Problem"),
        "413": problem_response("413", "The request body is too large.", "Problem"),
        "415": problem_response("415", "The request media type is not supported.", "Problem"),
        "422": problem_response("422", "A request field is not valid.", "ValidationProblem"),
        "429": problem_response("429", "The source is throttling requests.", "Problem"),
        "500": problem_response("500", "The request could not be served.", "Problem"),
        "502": problem_response("502", "The source answered with an error.", "Problem"),
        "503": problem_response("503", "The service is unavailable.", "Problem"),
        "504": problem_response("504", "The source did not answer in time.", "Problem")
    });
    if matches!(
        capability,
        ConsultationCapability::Retrieve | ConsultationCapability::List
    ) {
        let object = responses
            .as_object_mut()
            .expect("the maintained problem catalogue is an object");
        object.remove("413");
        object.remove("415");
        object.remove("422");
    }
    responses
}

fn capabilities_operation() -> Value {
    let headers = response_headers("200");
    json!({"get": {"operationId": "getCallerCapabilities", "responses": {
        "200": {"description": "Bounded caller-filtered capability document.", "headers": headers, "content": {"application/json": {"schema": capabilities_schema()}}},
        "401": problem_response("401", "The caller was not authenticated.", "Problem"),
        "403": problem_response("403", "The caller is not authorized.", "Problem"),
        "406": problem_response("406", "The response media type is not acceptable.", "Problem"),
        "500": problem_response("500", "The request could not be served.", "Problem"),
        "503": problem_response("503", "The service is unavailable.", "Problem")
    }, "parameters": [traceparent_parameter()], "security": [{"bearerAuth": []}]}})
}

fn record_id_parameter() -> Value {
    json!({"name": "recordId", "in": "path", "required": true, "schema": {
        "type": "string", "minLength": 1, "maxLength": 256
    }})
}

fn idempotency_key_parameter() -> Value {
    json!({
        "name": "Idempotency-Key", "in": "header", "required": true,
        "description": "Quoted Structured Field String identifying one exact write request.",
        "schema": {"type": "string", "minLength": 3, "maxLength": 202}
    })
}

fn if_match_parameter() -> Value {
    json!({
        "name": "If-Match", "in": "header", "required": true,
        "description": "The strong validator returned by the exact companion read.",
        "schema": strong_etag_schema()
    })
}

fn write_request_schema(input_schema: &str) -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["data"],
        "properties": {"data": {"$ref": component_reference(input_schema)}}
    })
}

fn write_result_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["collectionId", "recordId", "etag"],
        "properties": {
            "collectionId": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9-]{0,127}$"},
            "recordId": {"type": "string", "minLength": 1, "maxLength": 256},
            "etag": strong_etag_schema()
        }
    })
}

fn write_success_headers(create: bool) -> Value {
    let mut headers = response_headers("200");
    headers["ETag"] = strong_etag_header();
    if create {
        headers["Location"] = json!({
            "description": "URI of the created Record.",
            "required": true,
            "schema": {"type": "string", "format": "uri-reference", "minLength": 1, "maxLength": 2048}
        });
    }
    headers
}

fn write_problem_responses(
    capability: crate::govstack::write::attachment::WriteCapability,
) -> Value {
    let mut responses = json!({
        "400": write_problem_response("400", "The write request is not valid.", "Problem"),
        "401": write_problem_response("401", "The caller was not authenticated.", "Problem"),
        "403": write_problem_response("403", "The caller is not authorized.", "Problem"),
        "404": write_problem_response("404", "The collection or record is not available.", "Problem"),
        "409": write_problem_response("409", "The write conflicts with another operation.", "Problem"),
        "415": write_problem_response("415", "The request media type is not supported.", "Problem"),
        "422": write_problem_response("422", "The write content is not valid.", "UnprocessableContentProblem"),
        "429": write_problem_response("429", "The source is throttling requests.", "Problem"),
        "500": write_problem_response("500", "The write could not be served.", "Problem"),
        "502": write_problem_response("502", "The source answered with an error.", "Problem"),
        "503": write_problem_response("503", "The service is unavailable.", "Problem")
    });
    if capability == crate::govstack::write::attachment::WriteCapability::Update {
        responses["412"] = write_problem_response(
            "412",
            "The supplied strong validator no longer matches.",
            "Problem",
        );
        responses["428"] = write_problem_response(
            "428",
            "A strong validator is required for this write.",
            "Problem",
        );
    }
    responses
}

fn write_problem_response(status: &str, description: &str, schema: &str) -> Value {
    json!({
        "description": description,
        "headers": response_headers(status),
        "content": {"application/problem+json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}},
    })
}

fn problem_schema(validation: bool) -> Value {
    let mut schema = json!({"type": "object", "additionalProperties": false, "required": ["type", "title", "status", "traceId"], "properties": {
        "type": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 512, "pattern": "^https://govstack\\.global/problems/[a-z][a-z0-9-]{1,30}/[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"}, "title": {"type": "string", "minLength": 1, "maxLength": 512},
        "status": {"type": "integer", "minimum": 400, "maximum": 599}, "detail": {"type": "string", "minLength": 1, "maxLength": 2048}, "traceId": {"type": "string", "pattern": "^(?!0{32}$)[\\da-f]{32}$"},
        "errors": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"type": "object", "additionalProperties": false, "required": ["pointer", "message"], "properties": {"pointer": {"type": "string", "format": "json-pointer", "minLength": 1, "maxLength": 512}, "message": {"type": "string", "minLength": 1, "maxLength": 512}}}}
    }});
    if validation {
        schema["required"] = json!(["type", "title", "status", "traceId", "errors"]);
    }
    schema
}

fn write_unprocessable_content_schema() -> Value {
    json!({
        "description": "Semantic body validation failure or idempotency fingerprint mismatch.",
        "required": ["type", "title", "status", "traceId"],
        "oneOf": [
            {
                "allOf": [
                    {"$ref": "#/components/schemas/ValidationProblem"},
                    {
                        "type": "object",
                        "description": "Bind semantic field validation failure to its 422 identity.",
                        "required": ["type", "title", "status", "traceId"],
                        "properties": {
                            "type": {"const": "https://govstack.global/problems/digital-registries/invalid-content"},
                            "status": {"const": 422}
                        }
                    }
                ]
            },
            {
                "allOf": [
                    {"$ref": "#/components/schemas/Problem"},
                    {
                        "type": "object",
                        "description": "Bind idempotency fingerprint mismatch to its distinct 422 identity.",
                        "required": ["type", "title", "status", "traceId"],
                        "properties": {
                            "type": {"const": "https://govstack.global/problems/digital-registries/idempotency-fingerprint-mismatch"},
                            "status": {"const": 422}
                        },
                        "not": {"required": ["errors"]}
                    }
                ]
            }
        ]
    })
}

fn capabilities_schema() -> Value {
    let operation = json!({
        "type": "object", "additionalProperties": false,
        "required": ["operationId", "contract", "capability", "family"],
        "properties": {
            "operationId": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9]*$", "maxLength": 128},
            "contract": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 2048, "pattern": "^https://\\S+$"},
            "family": {"type": "string", "enum": ["consultation", "write"]},
            "capability": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9-]{0,127}$", "x-extensible-enum": ["retrieve", "lookup", "list", "search", "create", "update"]},
            "view": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9-]{0,127}$"},
            "write": {"type": "object", "additionalProperties": false, "required": ["idempotencyReplayWindow"], "properties": {
                "idempotencyReplayWindow": {"type": "integer", "minimum": 1, "maximum": 31_536_000, "description": "Seconds a reused Idempotency-Key still replays its exact terminal response; the deployment's response retention."},
                "companionRead": {"type": "object", "additionalProperties": false, "required": ["operationId", "view"], "properties": {
                    "operationId": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9]*$", "maxLength": 128},
                    "view": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9-]{0,127}$"}
                }}
            }},
            "selectors": named_inputs(),
            "searches": named_inputs()
        }
    });
    json!({
        "type": "object", "additionalProperties": false, "required": ["collections"],
        "properties": {
            "collections": {"type": "array", "maxItems": 64, "uniqueItems": true, "items": {
                "type": "object", "additionalProperties": false,
                "required": ["collectionId", "registry", "operations"],
                "properties": {
                    "collectionId": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9-]{0,127}$"},
                    "registry": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 2048},
                    "operations": {"type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": operation}
                }
            }},
            "operations": {"type": "array", "maxItems": 64, "uniqueItems": true}
        }
    })
}

fn named_inputs() -> Value {
    json!({"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,127}$"}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_contract() -> Value {
        let project: AdapterProject = serde_json::from_value(json!({
            "project": {"id": "consultation-metadata", "version": "1"},
            "consultation": {
                "contract": "https://registry.example/contracts/1/openapi.json",
                "collections": [{
                    "recordType": "people",
                    "registry": "https://registry.example/registries/people",
                    "view": "public",
                    "dataSchema": "person",
                    "lookup": {"selector": "by-id", "inputSchema": "identifier"},
                    "search": {"search": "by-status", "inputSchema": "criteria"}
                }]
            },
            "pack": {
                "id": "source",
                "version": "1",
                "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"
            },
            "recordTypes": [{"name": "people", "fields": []}],
            "bindings": [
                {"id": "retrieve", "operation": "retrieve", "recordType": "people", "route": "read", "maximumUpstreamCalls": 1},
                {"id": "lookup", "operation": "lookup", "recordType": "people", "route": "read", "maximumUpstreamCalls": 1},
                {"id": "list", "operation": "list", "recordType": "people", "route": "page", "maximumUpstreamCalls": 1},
                {"id": "search", "operation": "search", "recordType": "people", "route": "page", "maximumUpstreamCalls": 1}
            ]
        }))
        .expect("minimal Consultation project");
        let schemas = [
            ("person", "https://schemas.example/person/1"),
            ("identifier", "https://schemas.example/identifier/1"),
            ("criteria", "https://schemas.example/criteria/1"),
        ]
        .into_iter()
        .map(|(id, identity)| {
            (
                id.to_owned(),
                OpenApiSchema {
                    identity: identity.to_owned(),
                    component: json!({"type": "object", "additionalProperties": false}),
                },
            )
        })
        .collect();
        assemble_openapi(&project, &schemas).expect("generated Consultation contract")
    }

    fn operation<'a>(contract: &'a Value, path: &str, method: &str) -> &'a Value {
        &contract["paths"][path][method]
    }

    fn generated_write_contract() -> Value {
        let project: AdapterProject = serde_json::from_value(json!({
            "project": {"id": "unified-metadata", "version": "1"},
            "consultation": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "registry": "https://registry.example/registries/people",
                "view": "person-public", "dataSchema": "person-public"
            }]},
            "write": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "create": {"inputSchema": "person-create"},
                "update": {"inputSchema": "person-update", "companionRead": "retrieve"}
            }]},
            "pack": {"id": "source", "version": "1", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": [{"name": "people", "fields": []}],
            "bindings": [
                {"id": "retrieve", "operation": "retrieve", "recordType": "people", "route": "read", "maximumUpstreamCalls": 1},
                {"id": "create", "operation": "create", "recordType": "people", "route": "create", "maximumUpstreamCalls": 1},
                {"id": "update", "operation": "update", "recordType": "people", "route": "update", "maximumUpstreamCalls": 1}
            ]
        })).expect("minimal unified project");
        let schemas = ["person-public", "person-create", "person-update"]
            .into_iter()
            .map(|id| {
                (
                    id.to_owned(),
                    OpenApiSchema {
                        identity: format!("https://schemas.example/{id}/1"),
                        component: json!({"type": "object", "additionalProperties": false}),
                    },
                )
            })
            .collect();
        assemble_openapi(&project, &schemas).expect("generated unified contract")
    }

    fn parameter<'a>(operation: &'a Value, name: &str) -> &'a Value {
        operation["parameters"]
            .as_array()
            .expect("operation parameters")
            .iter()
            .find(|parameter| parameter["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} parameter"))
    }

    #[test]
    fn generated_operations_publish_trace_and_protected_response_headers() {
        let contract = generated_contract();
        for (path, method) in [
            ("/v1/collections/people/records/{recordId}", "get"),
            ("/v1/collections/people/lookup", "post"),
            ("/v1/collections/people/records", "get"),
            ("/v1/collections/people/search", "post"),
            (CAPABILITIES_PATH, "get"),
        ] {
            let operation = operation(&contract, path, method);
            let traceparent = parameter(operation, "traceparent");
            assert_eq!(traceparent["in"], "header", "{method} {path}");
            assert_eq!(traceparent["required"], false, "{method} {path}");
            for (status, response) in operation["responses"]
                .as_object()
                .expect("operation responses")
            {
                assert_eq!(
                    response["headers"]["Cache-Control"]["schema"]["const"], "no-store",
                    "{method} {path} response {status}"
                );
            }
            assert_eq!(
                operation["responses"]["401"]["headers"]["WWW-Authenticate"]["schema"]["type"],
                "string",
                "{method} {path}"
            );
            for status in ["429", "503"] {
                if operation["responses"].get(status).is_some() {
                    assert_eq!(
                        operation["responses"][status]["headers"]["Retry-After"]["schema"]["type"],
                        "string",
                        "{method} {path} response {status}"
                    );
                }
            }
        }
    }

    #[test]
    fn generated_problem_catalogue_matches_each_request_shape() {
        let contract = generated_contract();
        for path in [
            "/v1/collections/people/records/{recordId}",
            "/v1/collections/people/records",
        ] {
            let operation = operation(&contract, path, "get");
            for body_only_status in ["413", "415", "422"] {
                assert!(
                    operation["responses"].get(body_only_status).is_none(),
                    "GET {path} advertised body-only response {body_only_status}"
                );
            }
        }
        assert!(
            contract["paths"]["/v1/collections/people/records/{recordId}"]["get"]["responses"]
                ["200"]["headers"]
                .get("ETag")
                .is_none()
        );
        for path in [
            "/v1/collections/people/lookup",
            "/v1/collections/people/search",
        ] {
            let operation = operation(&contract, path, "post");
            for body_status in ["413", "415", "422"] {
                assert!(
                    operation["responses"].get(body_status).is_some(),
                    "POST {path} omitted response {body_status}"
                );
            }
        }
    }

    #[test]
    fn generated_trace_ids_and_cursors_use_the_runtime_constraints() {
        let contract = generated_contract();
        assert_eq!(
            contract["components"]["schemas"]["Problem"]["properties"]["type"]["pattern"],
            "^https://govstack\\.global/problems/[a-z][a-z0-9-]{1,30}/[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"
        );
        assert_eq!(
            contract["components"]["schemas"]["Problem"]["properties"]["traceId"]["pattern"],
            "^(?!0{32}$)[\\da-f]{32}$"
        );
        assert_eq!(
            contract["components"]["schemas"]["ValidationProblem"]["properties"]["errors"]["items"]
                ["properties"]["pointer"]["format"],
            "json-pointer"
        );
        let cursor = crate::engine::effective_contract::cursor_schema();
        assert_eq!(
            parameter(
                operation(&contract, "/v1/collections/people/records", "get"),
                "cursor"
            )["schema"],
            cursor
        );
        assert_eq!(
            operation(&contract, "/v1/collections/people/search", "post")["requestBody"]["content"]
                ["application/json"]["schema"]["properties"]["cursor"],
            cursor
        );
        assert_eq!(
            contract["paths"]["/v1/collections/people/records"]["get"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["properties"]["pageInfo"]["properties"]
                ["nextCursor"]["anyOf"][0],
            cursor
        );
    }

    #[test]
    fn generated_write_contract_fixes_create_update_and_companion_metadata() {
        let contract = generated_write_contract();
        let create = operation(&contract, "/v1/collections/people/records", "post");
        assert!(create["responses"].get("201").is_some());
        assert!(create["responses"].get("202").is_none());
        assert!(create["responses"].get("502").is_some());
        assert_eq!(
            create["requestBody"]["content"]["application/json"]["schema"]["properties"]["data"]
                ["$ref"],
            "#/components/schemas/person-create"
        );
        let update = operation(
            &contract,
            "/v1/collections/people/records/{recordId}",
            "patch",
        );
        assert!(update["responses"].get("204").is_some());
        assert!(update["responses"].get("412").is_some());
        assert!(update["responses"].get("428").is_some());
        let strong_pattern = r#"^"[\x21\x23-\x7E]{1,256}"(?![\s\S])"#;
        assert_eq!(
            create["responses"]["201"]["content"]["application/json"]["schema"]["properties"]
                ["etag"]["pattern"],
            strong_pattern
        );
        for success in [&create["responses"]["201"], &update["responses"]["204"]] {
            assert_eq!(success["headers"]["ETag"]["required"], true);
            assert_eq!(
                success["headers"]["ETag"]["schema"]["pattern"],
                strong_pattern
            );
        }
        assert_eq!(
            create["responses"]["201"]["headers"]["Location"]["required"],
            true
        );
        let companion = &contract["paths"]["/v1/collections/people/records/{recordId}"]["get"];
        assert_eq!(
            companion["responses"]["200"]["headers"]["ETag"]["required"],
            true
        );
        assert_eq!(
            companion["responses"]["200"]["headers"]["ETag"]["schema"]["pattern"],
            strong_pattern
        );
        assert_eq!(
            create["responses"]["422"]["content"]["application/problem+json"]["schema"]["$ref"],
            "#/components/schemas/UnprocessableContentProblem"
        );
        let unprocessable = &contract["components"]["schemas"]["UnprocessableContentProblem"];
        assert_eq!(
            unprocessable["oneOf"][0]["allOf"][1]["properties"]["type"]["const"],
            "https://govstack.global/problems/digital-registries/invalid-content"
        );
        assert_eq!(
            unprocessable["oneOf"][1]["allOf"][1]["properties"]["type"]["const"],
            "https://govstack.global/problems/digital-registries/idempotency-fingerprint-mismatch"
        );
        assert_eq!(
            unprocessable["oneOf"][1]["allOf"][1]["not"]["required"],
            json!(["errors"])
        );
        assert_eq!(
            update["x-govstack-digital-registries-write"]["companionRead"],
            json!({"operationId": "retrievePeople", "view": "person-public"})
        );
        for operation in [create, update] {
            for response in operation["responses"]
                .as_object()
                .expect("Write response catalogue")
                .values()
            {
                assert!(
                    response["headers"]
                        .as_object()
                        .expect("response headers")
                        .keys()
                        .all(|name| !name.to_ascii_lowercase().contains("replay-window")),
                    "the replay window is published in capabilities, not as a header"
                );
            }
        }
        let write_member = &contract["paths"][CAPABILITIES_PATH]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["properties"]["collections"]["items"]
            ["properties"]["operations"]["items"]["properties"]["write"];
        assert_eq!(write_member["required"], json!(["idempotencyReplayWindow"]));
        assert_eq!(
            write_member["properties"]["idempotencyReplayWindow"]["maximum"],
            31_536_000
        );
        for collection_id in [
            &create["responses"]["201"]["content"]["application/json"]["schema"]["properties"]
                ["collectionId"],
            &contract["paths"][CAPABILITIES_PATH]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["properties"]["collections"]["items"]["properties"]
                ["collectionId"],
        ] {
            assert_eq!(collection_id["maxLength"], 128);
            assert_eq!(collection_id["pattern"], "^[a-z][a-z0-9-]{0,127}$");
        }
    }

    #[test]
    fn generated_contract_refuses_noncanonical_public_view_ids() {
        let project: AdapterProject = serde_json::from_value(json!({
            "project": {"id": "invalid-view", "version": "1"},
            "consultation": {"contract": "https://registry.example/contracts/1/openapi.json", "collections": [{
                "recordType": "people", "registry": "https://registry.example/registries/people",
                "view": "person_public", "dataSchema": "person"
            }]},
            "pack": {"id": "source", "version": "1", "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "recordTypes": [{"name": "people", "fields": []}],
            "bindings": [{"id": "retrieve", "operation": "retrieve", "recordType": "people", "route": "read", "maximumUpstreamCalls": 1}]
        }))
        .expect("the broader authoring grammar admits the view");
        let schemas = [(
            "person".to_owned(),
            OpenApiSchema {
                identity: "https://schemas.example/person/1".to_owned(),
                component: json!({"type": "object"}),
            },
        )]
        .into_iter()
        .collect();

        let findings = assemble_openapi(&project, &schemas)
            .expect_err("the fixed contract refuses a noncanonical public view");
        assert!(findings
            .iter()
            .any(|finding| { finding.code == "adapterctl.compile.govstack-view-id" }));
    }
}
