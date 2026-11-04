// SPDX-License-Identifier: Apache-2.0

//! Fixed OpenAPI 3.1 assembly for the GovStack Consultation target.

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
    let Some(target) = project.consultation.as_ref() else {
        return Err(vec![refusal(
            "adapterctl.compile.consultation-missing",
            "the project does not select the built-in Consultation facade",
        )]);
    };
    let mut findings = Vec::new();
    let mut paths = Map::new();
    let mut operation_ids = BTreeSet::new();
    for binding in project.bindings.iter() {
        let Some(capability) =
            ConsultationCapability::from_binding_operation(binding.operation.as_str())
        else {
            findings.push(refusal(
                "adapterctl.compile.consultation-capability",
                "a Consultation binding names an unsupported capability",
            ));
            continue;
        };
        let Some(collection) = target.collections.get(binding.record_type.as_str()) else {
            findings.push(refusal(
                "adapterctl.compile.consultation-collection",
                "a Consultation binding has no collection metadata",
            ));
            continue;
        };
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
            "responses": problem_responses(),
            "security": [{"bearerAuth": []}],
        });
        match capability {
            ConsultationCapability::Retrieve => {
                operation["parameters"] = json!([{"name": "recordId", "in": "path", "required": true, "schema": {"type": "string", "minLength": 1, "maxLength": 256}}])
            }
            ConsultationCapability::List => {
                operation["parameters"] = json!([
                    {"name": "pageSize", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
                    {"name": "cursor", "in": "query", "required": false, "schema": {"type": "string", "minLength": 1}}
                ])
            }
            ConsultationCapability::Lookup | ConsultationCapability::Search => {}
        }
        if let Some(schema) = request_schema {
            operation["requestBody"] =
                json!({"required": true, "content": {"application/json": {"schema": schema}}});
        }
        operation["responses"]["200"] = json!({"description": "The operation's response envelope for the bound record type.", "content": {"application/json": {"schema": success_schema}}});
        paths.entry(path).or_insert_with(|| json!({}))[method] = operation;
    }
    paths.insert(CAPABILITIES_PATH.to_owned(), capabilities_operation());
    if !findings.is_empty() {
        return Err(findings);
    }
    let mut component_schemas = Map::new();
    component_schemas.insert("Problem".to_owned(), problem_schema(false));
    component_schemas.insert("ValidationProblem".to_owned(), problem_schema(true));
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
fn problem_response(description: &str, schema: &str) -> Value {
    json!({"description": description, "content": {"application/problem+json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}})
}

fn problem_responses() -> Value {
    json!({
        "400": problem_response("The request is not valid.", "Problem"),
        "401": problem_response("The caller was not authenticated.", "Problem"),
        "403": problem_response("The caller is not authorized.", "Problem"),
        "404": problem_response("The collection or record is not available.", "Problem"),
        "406": problem_response("The response media type is not acceptable.", "Problem"),
        "413": problem_response("The request body is too large.", "Problem"),
        "415": problem_response("The request media type is not supported.", "Problem"),
        "422": problem_response("A request field is not valid.", "ValidationProblem"),
        "429": problem_response("The source is throttling requests.", "Problem"),
        "500": problem_response("The request could not be served.", "Problem"),
        "502": problem_response("The source answered with an error.", "Problem"),
        "503": problem_response("The service is unavailable.", "Problem"),
        "504": problem_response("The source did not answer in time.", "Problem")
    })
}

fn capabilities_operation() -> Value {
    json!({"get": {"operationId": "getCallerCapabilities", "responses": {
        "200": {"description": "Bounded caller-filtered capability document.", "headers": {"Cache-Control": {"schema": {"const": "no-store"}}}, "content": {"application/json": {"schema": capabilities_schema()}}},
        "401": problem_response("The caller was not authenticated.", "Problem"),
        "403": problem_response("The caller is not authorized.", "Problem"),
        "406": problem_response("The response media type is not acceptable.", "Problem"),
        "500": problem_response("The request could not be served.", "Problem"),
        "503": problem_response("The service is unavailable.", "Problem")
    }, "security": [{"bearerAuth": []}]}})
}

fn problem_schema(validation: bool) -> Value {
    let mut schema = json!({"type": "object", "additionalProperties": false, "required": ["type", "title", "status", "traceId"], "properties": {
        "type": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 512}, "title": {"type": "string", "minLength": 1, "maxLength": 512},
        "status": {"type": "integer", "minimum": 400, "maximum": 599}, "detail": {"type": "string", "minLength": 1, "maxLength": 2048}, "traceId": {"type": "string", "minLength": 1, "maxLength": 128},
        "errors": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"type": "object", "additionalProperties": false, "required": ["pointer", "message"], "properties": {"pointer": {"type": "string", "minLength": 1, "maxLength": 512}, "message": {"type": "string", "minLength": 1, "maxLength": 512}}}}
    }});
    if validation {
        schema["required"] = json!(["type", "title", "status", "traceId", "errors"]);
    }
    schema
}

fn capabilities_schema() -> Value {
    json!({"type": "object", "additionalProperties": false, "required": ["collections"], "properties": {"collections": {"type": "array", "maxItems": 64, "uniqueItems": true, "items": {"type": "object", "additionalProperties": false, "required": ["collectionId", "registry", "operations"], "properties": {
        "collectionId": {"type": "string", "minLength": 1, "maxLength": 64}, "registry": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 2048},
        "operations": {"type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": {"type": "object", "additionalProperties": false, "required": ["operationId", "contract", "capability", "view"], "properties": {
            "operationId": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9]*$", "maxLength": 128}, "contract": {"type": "string", "format": "uri", "minLength": 1, "maxLength": 2048, "pattern": "^https://\\S+$"},
            "capability": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9-]{0,127}$", "x-extensible-enum": ["retrieve", "lookup", "list", "search"]}, "view": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z][a-z0-9_-]{0,127}$"},
            "selectors": named_inputs(), "searches": named_inputs()
        }}}
    }}}}})
}

fn named_inputs() -> Value {
    json!({"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,127}$"}})
}
