// SPDX-License-Identifier: Apache-2.0

//! The compiled contract document: the concrete OpenAPI 3.1 description of
//! one deployment's facade, assembled from the bound pairs of a checked
//! workspace (`products/adapter/CONCEPT.md` sections 7 and 8.11.1). One
//! concrete operation per bound (profile operation, record type) pair, the
//! record type substituted into its path parameter, and nothing for an
//! operation no binding binds. Assembly is pure over the parsed profile and
//! project: no clocks, no host values, no file paths, so the same authored
//! bytes always compile to the same document bytes and the file's diff is
//! the contract review.

use registry_adapter_core::{
    derive_binding_result_schema, derive_operation_request_schema, derive_problem_envelope_schema,
    AdapterProfile, AdapterProject, Binding, HttpMethod, ParameterizedPart, Problem,
    ProfileOperation, RecordField,
};
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Map, Value};

/// The OpenAPI version every compiled contract declares.
const OPENAPI_VERSION: &str = "3.1.0";

/// The one security scheme a compiled contract names: a bearer token, the
/// shape the Base Registry Engine's generated contracts serve. No scopes
/// are enumerated in v1.
fn bearer_scheme() -> Value {
    json!({
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    })
}

/// The description every success response carries. The response's schema is
/// the profile's envelope for the bound record type; the text stays generic
/// because the schema already says exactly what the body is.
const SUCCESS_DESCRIPTION: &str = "The operation's response envelope for the bound record type.";

/// Assemble the deployment's concrete OpenAPI document. Errors are
/// value-free findings; the caller refuses the compile on any of them
/// instead of writing a document.
pub(crate) fn assemble(
    profile: &AdapterProfile,
    project: &AdapterProject,
) -> Result<Value, Vec<Diagnostic>> {
    let parts: Vec<ParameterizedPart> = profile.parameterized_parts.iter().cloned().collect();
    let mut findings = Vec::new();
    let mut paths = Map::new();
    for binding in project.bindings.iter() {
        let Some(operation) = profile.operations.get(binding.operation.as_str()) else {
            findings.push(assembly_refusal(
                "adapterctl.compile.operation-missing",
                &format!(
                    "the binding names operation {}, which the profile does not declare",
                    binding.operation.as_str()
                ),
            ));
            continue;
        };
        let record_type = binding.record_type.as_str();
        let substituted = record_type_parameter(operation);
        let concrete = concrete_path(&operation.path, substituted, record_type);
        let method = openapi_method(operation.method);
        let path_item = paths
            .entry(concrete.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if path_item.get(&method).is_some() {
            findings.push(assembly_refusal(
                "adapterctl.compile.path-collision",
                &format!("two bound operations compile to {method} {concrete}"),
            ));
            continue;
        }
        let mut response = match derive_binding_result_schema(profile, project, binding) {
            Ok(schema) => schema,
            Err(reason) => {
                findings.push(derivation_refusal(binding, &reason));
                continue;
            }
        };
        unpin_parameterized_parts(&mut response, &parts);
        let fields: &[RecordField] = &project
            .record_types
            .get(record_type)
            .expect("the derivation resolved the binding's record type")
            .fields;
        let mut members = Map::new();
        members.insert(
            "operationId".to_owned(),
            json!(format!("{}.{}", operation.id.as_str(), record_type)),
        );
        members.insert(
            "parameters".to_owned(),
            Value::Array(operation_parameters(
                operation,
                binding,
                fields,
                substituted,
            )),
        );
        if operation.request_envelope.is_some() {
            match derive_operation_request_schema(profile, project, binding) {
                Ok(mut request) => {
                    unpin_parameterized_parts(&mut request, &parts);
                    members.insert(
                        "requestBody".to_owned(),
                        json!({
                            "content": {"application/json": {"schema": request}},
                            "required": true,
                        }),
                    );
                }
                Err(reason) => {
                    findings.push(derivation_refusal(binding, &reason));
                    continue;
                }
            }
        }
        let mut responses = Map::new();
        responses.insert(
            success_status(operation).to_string(),
            json!({
                "description": SUCCESS_DESCRIPTION,
                "content": {"application/json": {"schema": response}},
            }),
        );
        for (status, error) in problem_responses(&profile.problems) {
            responses.entry(status).or_insert(error);
        }
        members.insert("responses".to_owned(), Value::Object(responses));
        members.insert("security".to_owned(), json!([{"bearerAuth": []}]));
        let Some(path_object) = path_item.as_object_mut() else {
            unreachable!("the path item was inserted as an object");
        };
        path_object.insert(method, Value::Object(members));
    }

    let mut schemas = Map::new();
    match derive_problem_envelope_schema(profile) {
        Ok(mut problem) => {
            unpin_parameterized_parts(&mut problem, &parts);
            schemas.insert("Problem".to_owned(), problem);
        }
        Err(reason) => findings.push(assembly_refusal(
            "adapterctl.compile.derivation-failed",
            &format!("the problem envelope cannot be derived: {reason}"),
        )),
    }

    if !findings.is_empty() {
        return Err(findings);
    }
    Ok(json!({
        "components": {
            "schemas": Value::Object(schemas),
            "securitySchemes": {"bearerAuth": bearer_scheme()},
        },
        "info": {
            "title": project.project.id.as_str(),
            "version": project.project.version,
        },
        "openapi": OPENAPI_VERSION,
        "paths": Value::Object(paths),
    }))
}

/// The document's bytes: pretty JSON with sorted keys and a trailing
/// newline, so the file's diff is the contract review.
pub(crate) fn render(document: &Value) -> String {
    let mut rendered =
        serde_json::to_string_pretty(&sorted_keys(document)).expect("a Value serializes");
    rendered.push('\n');
    rendered
}

/// Recursively sort an object's members by key, so the rendered bytes are
/// the same whatever iteration order the in-memory maps carry: a build
/// with `serde_json/preserve_order` enabled anywhere in its graph inserts
/// members in construction order, while the default stores them sorted.
/// Arrays keep their order; only member names sort.
fn sorted_keys(value: &Value) -> Value {
    match value {
        Value::Object(members) => {
            let mut sorted: Vec<(String, Value)> = members
                .iter()
                .map(|(key, member)| (key.clone(), sorted_keys(member)))
                .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted_keys).collect()),
        scalar => scalar.clone(),
    }
}

/// The path parameter the bound record type substitutes into: the
/// operation's declared `recordTypeParameter`, which the profile checks
/// require to be one of its `pathParameters`. The concrete path carries the
/// record type in that parameter's place and the remaining declared
/// parameters stay templated.
fn record_type_parameter(operation: &ProfileOperation) -> Option<&str> {
    operation
        .path_parameters
        .iter()
        .find(|name| name.as_str() == operation.record_type_parameter.as_str())
        .map(|name| name.as_str())
}

/// The success status the compiled contract answers with: the operation's
/// declared `successStatus`, two hundreds only (CFG-QTY-4).
fn success_status(operation: &ProfileOperation) -> u32 {
    operation.success_status.get()
}

/// The OpenAPI method name of a facade method.
fn openapi_method(method: HttpMethod) -> String {
    // The wire form is uppercase (`GET`); OpenAPI path item keys are
    // lowercase.
    match method {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Patch => "patch",
    }
    .to_owned()
}

/// The concrete path of one bound operation: the record type substituted
/// into the record-type parameter's whole segment, every other segment
/// kept as declared.
fn concrete_path(path: &str, parameter: Option<&str>, record_type: &str) -> String {
    let Some(parameter) = parameter else {
        return path.to_owned();
    };
    let template = format!("{{{parameter}}}");
    path.split('/')
        .map(|segment| {
            if segment == template {
                record_type.to_owned()
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The operation's OpenAPI parameters: the remaining declared path
/// parameters in their declared order, then the query parameters — the
/// binding's declared filters beside the profile's pagination — sorted by
/// name. The record-type parameter is substituted into the path, so it
/// emits no parameter.
fn operation_parameters(
    operation: &ProfileOperation,
    binding: &Binding,
    fields: &[RecordField],
    substituted: Option<&str>,
) -> Vec<Value> {
    let mut parameters = Vec::new();
    for name in operation.path_parameters.iter() {
        if Some(name.as_str()) == substituted {
            continue;
        }
        parameters.push(json!({
            "name": name.as_str(),
            "in": "path",
            "required": true,
            "schema": {"type": "string"},
        }));
    }
    let mut query = Vec::new();
    if let Some(pagination) = &operation.pagination {
        query.push(json!({
            "name": pagination.cursor_parameter.as_str(),
            "in": "query",
            "required": false,
            "schema": {"type": "string"},
        }));
        query.push(json!({
            "name": pagination.page_size_parameter.as_str(),
            "in": "query",
            "required": false,
            "schema": {
                "type": "integer",
                "minimum": pagination.page_size_minimum.get(),
                "maximum": pagination.page_size_maximum.get(),
            },
        }));
    }
    // A declared filter names a declared field (the project checks require
    // it), so the field's declared type types the parameter; fields with no
    // declared filter stay out of the contract.
    let declared: Vec<&RecordField> = fields
        .iter()
        .filter(|field| binding.filters.iter().any(|name| name == &field.name))
        .collect();
    query.extend(filter_parameters(&declared));
    query.sort_by_key(|parameter| parameter["name"].as_str().unwrap_or_default().to_owned());
    parameters.extend(query);
    parameters
}

/// The typed equality query parameters of a search binding's declared
/// filter fields: one optional parameter per field, typed by the field's
/// declared type, in the record type's declared field order.
fn filter_parameters(fields: &[&RecordField]) -> Vec<Value> {
    fields
        .iter()
        .map(|field| {
            json!({
                "name": field.name.as_str(),
                "in": "query",
                "required": false,
                "schema": field_schema(field.r#type),
            })
        })
        .collect()
}

/// The OpenAPI schema of one declared record field. The closed mapping of
/// the declared field types; core owns the envelope-side twin of this
/// table, which the derived schemas already carry.
fn field_schema(field_type: registry_adapter_core::RecordFieldType) -> Value {
    match field_type {
        registry_adapter_core::RecordFieldType::String => json!({"type": "string"}),
        registry_adapter_core::RecordFieldType::Integer => json!({"type": "integer"}),
        registry_adapter_core::RecordFieldType::Decimal => json!({"type": "number"}),
        registry_adapter_core::RecordFieldType::Boolean => json!({"type": "boolean"}),
        registry_adapter_core::RecordFieldType::Date => json!({"type": "string", "format": "date"}),
        registry_adapter_core::RecordFieldType::DateTime => {
            json!({"type": "string", "format": "date-time"})
        }
    }
}

/// The error responses of a profile's problems list: one response per
/// distinct status, each answering the shared problem schema and described
/// by the first problem carrying that status (`products/adapter/CONCEPT.md`
/// section 8.11.6). The statuses, not the codes, key the responses: two
/// problems answering with the same status share one response.
fn problem_responses(problems: &[Problem]) -> Map<String, Value> {
    let mut responses = Map::new();
    for problem in problems {
        responses
            .entry(problem.status.get().to_string())
            .or_insert_with(|| {
                json!({
                    "description": problem.title,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Problem"}}
                    },
                })
            });
    }
    responses
}

/// Type a parameterized part's member as a plain string, recursively.
///
/// A part member (`parameterizedParts`, e.g. `meta.registryIdentifier`)
/// carries the part name itself as stand-in literal text in the envelope
/// template, which the core derivation renders as a string const. The
/// compiled contract cannot know the deployment's value, so the const is
/// dropped and the member stays a string. That core emits the const at all
/// is a reported core gap; this walk is the interim correction.
fn unpin_parameterized_parts(schema: &mut Value, parts: &[ParameterizedPart]) {
    let Some(object) = schema.as_object_mut() else {
        if let Value::Array(items) = schema {
            for item in items {
                unpin_parameterized_parts(item, parts);
            }
        }
        return;
    };
    for (key, member) in object.iter_mut() {
        if key == "properties" {
            let Some(properties) = member.as_object_mut() else {
                continue;
            };
            for (name, property) in properties.iter_mut() {
                let is_part = parts.iter().any(|part| part.name.as_str() == name);
                if is_part {
                    if let Some(property_object) = property.as_object_mut() {
                        if property_object.get("type") == Some(&Value::from("string")) {
                            property_object.remove("const");
                        }
                    }
                }
                unpin_parameterized_parts(property, parts);
            }
        } else {
            unpin_parameterized_parts(member, parts);
        }
    }
}

/// One assembly refusal finding.
fn assembly_refusal(code: &str, message: &str) -> Diagnostic {
    Diagnostic::error(
        code,
        "/paths",
        message.to_owned(),
        "Repair the authored profile and project, then compile again.",
    )
}

/// One derivation refusal finding for a binding.
fn derivation_refusal(binding: &Binding, reason: &str) -> Diagnostic {
    Diagnostic::error(
        "adapterctl.compile.derivation-failed",
        format!("/bindings/{}", binding.id.as_str()),
        format!("the binding's envelope schema cannot be derived: {reason}"),
        "Repair the envelope templates in the pinned profile, then compile again.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::RecordType;
    use serde_json::json;

    const GET_ENVELOPE: &str =
        r#"{"case": {{record}}, "meta": {"registryIdentifier": "registryIdentifier"}}"#;
    const FIND_ENVELOPE: &str = r#"{"cases": {{records}}}"#;
    const FIND_REQUEST: &str = r#"{"query": {{record}}}"#;
    const PROBLEM_ENVELOPE: &str = r#"{"family": "{{problemCode}}"}"#;
    const PINNED_DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// One profile with a read, a paginated search, and no parts beyond
    /// the one the envelope exercises.
    fn profile() -> AdapterProfile {
        serde_json::from_value(profile_value()).expect("the profile decodes")
    }

    /// The JSON of [`profile`], for tests that vary one declared field.
    fn profile_value() -> Value {
        json!({
            "id": "case-api",
            "version": "1",
            "operations": [
                {
                    "id": "cases-get",
                    "method": "GET",
                    "path": "/v2/cases/{type}/{case_id}",
                    "pathParameters": ["type", "case_id"],
                    "recordTypeParameter": "type",
                    "recordIdParameter": "case_id",
                    "responseEnvelope": GET_ENVELOPE,
                },
                {
                    "id": "cases-find",
                    "method": "POST",
                    "path": "/v2/cases/{type}",
                    "pathParameters": ["type"],
                    "recordTypeParameter": "type",
                    "requestEnvelope": FIND_REQUEST,
                    "responseEnvelope": FIND_ENVELOPE,
                    "pagination": {
                        "cursorParameter": "pageStateToken",
                        "pageSizeParameter": "maxResults",
                        "pageSizeMinimum": 10,
                        "pageSizeMaximum": 500,
                    },
                },
            ],
            "problems": [
                {
                    "code": "cases.missing",
                    "status": 404,
                    "title": "No case answers the request.",
                    "classes": ["outcome.not-found"],
                },
                {
                    "code": "cases.changed",
                    "status": 409,
                    "title": "The case changed since it was read.",
                    "classes": ["outcome.conflict"],
                },
                {
                    "code": "cases.gone",
                    "status": 404,
                    "title": "A second code with the same status.",
                    "classes": ["facade.not-found"],
                },
            ],
            "problemEnvelope": PROBLEM_ENVELOPE,
            "parameterizedParts": [
                {
                    "name": "registryIdentifier",
                    "description": "the registry this deployment serves",
                },
            ],
        })
    }

    /// One project over that profile, with the given bindings.
    fn project(bindings: Value) -> AdapterProject {
        serde_json::from_value(json!({
            "project": {"id": "case-deployment", "version": "1"},
            "profile": {"id": "case-api", "version": "1", "digest": PINNED_DIGEST},
            "pack": {"id": "case-api-pack", "version": "1", "digest": PINNED_DIGEST},
            "recordTypes": [
                {
                    "name": "case",
                    "fields": [
                        {"name": "case_type", "type": "string", "required": true},
                        {"name": "severity", "type": "integer"},
                        {"name": "opened_on", "type": "date"},
                    ],
                },
            ],
            "templatedRoutes": [],
            "bindings": bindings,
            "accessProfiles": [],
        }))
        .expect("the project decodes")
    }

    fn both_bindings() -> Value {
        json!([
            {
                "id": "case-get",
                "operation": "cases-get",
                "recordType": "case",
                "route": "case-find",
                "maximumUpstreamCalls": 4,
            },
            {
                "id": "case-find",
                "operation": "cases-find",
                "recordType": "case",
                "route": "case-find",
                "maximumUpstreamCalls": 11,
            },
        ])
    }

    /// The bound pairs compile to concrete operations: the record type
    /// substituted into the first path parameter's segment, the remaining
    /// declared parameters kept, the operationId names the pair, and the
    /// write carries its request body.
    #[test]
    fn bound_pairs_compile_to_concrete_operations() {
        let document = assemble(&profile(), &project(both_bindings())).expect("the assembly runs");
        let get = &document["paths"]["/v2/cases/case/{case_id}"]["get"];
        assert_eq!(get["operationId"], "cases-get.case");
        assert_eq!(
            get["parameters"],
            json!([{
                "name": "case_id",
                "in": "path",
                "required": true,
                "schema": {"type": "string"},
            }])
        );
        assert_eq!(get["responses"]["200"]["description"], SUCCESS_DESCRIPTION);
        assert_eq!(
            get["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["case"]
                ["properties"]["case_type"],
            json!({"type": "string"})
        );
        assert_eq!(get["security"], json!([{"bearerAuth": []}]));
        assert!(get.get("requestBody").is_none());

        let find = &document["paths"]["/v2/cases/case"]["post"];
        assert_eq!(find["operationId"], "cases-find.case");
        assert_eq!(
            find["requestBody"]["content"]["application/json"]["schema"]["properties"]["query"]
                ["properties"]["case_type"],
            json!({"type": "string"})
        );
        assert_eq!(find["requestBody"]["required"], json!(true));
        assert_eq!(
            find["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
                ["cases"]["items"]["properties"]["severity"],
            json!({"type": "integer"})
        );
        assert_eq!(document["openapi"], OPENAPI_VERSION);
        assert_eq!(
            document["info"],
            json!({"title": "case-deployment", "version": "1"})
        );
        assert_eq!(
            document["components"]["securitySchemes"]["bearerAuth"],
            bearer_scheme()
        );
        assert_eq!(
            document["components"]["schemas"]["Problem"],
            json!({
                "type": "object",
                "properties": {"family": {"type": "string"}},
                "required": ["family"],
                "additionalProperties": false,
            })
        );
    }

    /// The pagination parameters carry the profile's names and bounds, in
    /// name order beside the path parameters.
    #[test]
    fn pagination_parameters_carry_the_profile_names_and_bounds() {
        let document = assemble(&profile(), &project(both_bindings())).expect("the assembly runs");
        let parameters = &document["paths"]["/v2/cases/case"]["post"]["parameters"];
        assert_eq!(
            parameters,
            &json!([
                {
                    "name": "maxResults",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "integer", "minimum": 10, "maximum": 500},
                },
                {
                    "name": "pageStateToken",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string"},
                },
            ]),
            "the query parameters sort by name"
        );
    }

    /// A write operation answers with its declared `successStatus`, not a
    /// uniform 200: a records-create style write answers 201.
    #[test]
    fn a_write_answers_its_declared_success_status() {
        let mut value = profile_value();
        let write = value["operations"]
            .as_array_mut()
            .expect("the operations are a list")
            .iter_mut()
            .find(|operation| operation["id"] == "cases-find")
            .expect("the profile declares the write");
        write["successStatus"] = json!(201);
        let declared: AdapterProfile = serde_json::from_value(value).expect("the profile decodes");
        let document = assemble(&declared, &project(both_bindings())).expect("the assembly runs");
        let find = &document["paths"]["/v2/cases/case"]["post"];
        assert!(
            find["responses"].get("201").is_some(),
            "the declared success status answers: {}",
            find["responses"]
        );
        assert!(
            find["responses"].get("200").is_none(),
            "no uniform 200 shadows the declared status: {}",
            find["responses"]
        );
    }

    /// A search binding's declared filters appear as typed equality query
    /// parameters, sorted by name beside the profile's pagination
    /// parameters.
    #[test]
    fn filters_become_typed_equality_query_parameters() {
        let document = assemble(
            &profile(),
            &project(json!([{
                "id": "case-find",
                "operation": "cases-find",
                "recordType": "case",
                "route": "case-find",
                "filters": ["opened_on", "case_type"],
                "maximumUpstreamCalls": 11,
            }])),
        )
        .expect("the assembly runs");
        let parameters = &document["paths"]["/v2/cases/case"]["post"]["parameters"];
        assert_eq!(
            parameters,
            &json!([
                {
                    "name": "case_type",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string"},
                },
                {
                    "name": "maxResults",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "integer", "minimum": 10, "maximum": 500},
                },
                {
                    "name": "opened_on",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string", "format": "date"},
                },
                {
                    "name": "pageStateToken",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string"},
                },
            ]),
            "the binding's filters join the pagination parameters in name order"
        );
    }

    /// Every binding of one operation resolves through its own record type:
    /// the same operation bound to two record types compiles two concrete
    /// operations, each envelope schema carrying its own record type's
    /// fields.
    #[test]
    fn every_binding_of_an_operation_resolves_through_its_own_record_type() {
        let two_types = serde_json::from_value(json!({
            "project": {"id": "case-deployment", "version": "1"},
            "profile": {"id": "case-api", "version": "1", "digest": PINNED_DIGEST},
            "pack": {"id": "case-api-pack", "version": "1", "digest": PINNED_DIGEST},
            "recordTypes": [
                {
                    "name": "case",
                    "fields": [{"name": "case_type", "type": "string", "required": true}],
                },
                {
                    "name": "incident",
                    "fields": [{"name": "incident_kind", "type": "string", "required": true}],
                },
            ],
            "templatedRoutes": [],
            "bindings": [
                {
                    "id": "case-get",
                    "operation": "cases-get",
                    "recordType": "case",
                    "route": "case-find",
                    "maximumUpstreamCalls": 4,
                },
                {
                    "id": "incident-get",
                    "operation": "cases-get",
                    "recordType": "incident",
                    "route": "case-find",
                    "maximumUpstreamCalls": 4,
                },
            ],
            "accessProfiles": [],
        }))
        .expect("the project decodes");
        let document = assemble(&profile(), &two_types).expect("the assembly runs");
        let case = &document["paths"]["/v2/cases/case/{case_id}"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["properties"]["case"]["properties"];
        assert_eq!(case["case_type"], json!({"type": "string"}));
        assert!(case.get("incident_kind").is_none());
        let incident = &document["paths"]["/v2/cases/incident/{case_id}"]["get"]["responses"]
            ["200"]["content"]["application/json"]["schema"]["properties"]["case"]["properties"];
        assert_eq!(incident["incident_kind"], json!({"type": "string"}));
        assert!(incident.get("case_type").is_none());
    }

    /// A parameterized part member keeps its string type and loses the
    /// stand-in const; a literal that names no part keeps its const.
    #[test]
    fn parameterized_parts_lose_their_const() {
        let document = assemble(&profile(), &project(both_bindings())).expect("the assembly runs");
        let meta = &document["paths"]["/v2/cases/case/{case_id}"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["properties"]["meta"]["properties"];
        assert_eq!(meta["registryIdentifier"], json!({"type": "string"}));

        let with_literal = serde_json::from_value(json!({
            "id": "case-api",
            "version": "1",
            "operations": [{
                "id": "cases-get",
                "method": "GET",
                "path": "/v2/cases/{type}",
                "pathParameters": ["type"],
                "recordTypeParameter": "type",
                "responseEnvelope": r#"{"kind": "case", "meta": {"registryIdentifier": "registryIdentifier"}}"#,
            }],
            "problems": [
                {
                    "code": "cases.missing",
                    "status": 404,
                    "title": "No case answers the request.",
                    "classes": ["outcome.not-found"],
                },
            ],
            "problemEnvelope": PROBLEM_ENVELOPE,
            "parameterizedParts": [
                {"name": "registryIdentifier", "description": "the registry"},
            ],
        }))
        .expect("the profile decodes");
        let document = assemble(
            &with_literal,
            &project(json!([{
                "id": "case-get",
                "operation": "cases-get",
                "recordType": "case",
                "route": "case-find",
                "maximumUpstreamCalls": 4,
            }])),
        )
        .expect("the assembly runs");
        let properties = &document["paths"]["/v2/cases/case"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"];
        assert_eq!(
            properties["kind"],
            json!({"type": "string", "const": "case"})
        );
        assert_eq!(
            properties["meta"]["properties"]["registryIdentifier"],
            json!({"type": "string"})
        );
    }

    /// An operation no binding binds emits no path, and a project with no
    /// bindings compiles to an empty paths object.
    #[test]
    fn an_unbound_operation_emits_no_path() {
        let document = assemble(&profile(), &project(json!([]))).expect("the assembly runs");
        assert_eq!(document["paths"], json!({}));
    }

    /// Two bindings whose concrete paths collide refuse the assembly with
    /// the collision finding.
    #[test]
    fn colliding_concrete_paths_refuse() {
        let findings = assemble(
            &profile(),
            &project(json!([
                {
                    "id": "case-get",
                    "operation": "cases-get",
                    "recordType": "case",
                    "route": "case-find",
                    "maximumUpstreamCalls": 4,
                },
                {
                    "id": "case-get-again",
                    "operation": "cases-get",
                    "recordType": "case",
                    "route": "case-find",
                    "maximumUpstreamCalls": 4,
                },
            ])),
        )
        .expect_err("the collision refuses");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "adapterctl.compile.path-collision");
    }

    /// The same authored bytes compile to the same rendered bytes.
    #[test]
    fn the_document_is_deterministic() {
        let first = render(&assemble(&profile(), &project(both_bindings())).expect("assembles"));
        let second = render(&assemble(&profile(), &project(both_bindings())).expect("assembles"));
        assert_eq!(first, second);
        assert!(first.ends_with("}\n"));
    }

    /// The sorted walk changes no member: the rendered bytes parse back to
    /// exactly the document. Under the default map implementation the
    /// members already iterate sorted, so the walk is unobservable here; a
    /// `preserve_order` build renders these same bytes through it.
    #[test]
    fn the_rendered_bytes_round_trip_the_document() {
        let document = assemble(&profile(), &project(both_bindings())).expect("assembles");
        let text = render(&document);
        let parsed: Value = serde_json::from_str(&text).expect("the rendered bytes parse");
        assert_eq!(parsed, document);
    }

    /// The filter assembler offers one optional typed equality parameter
    /// per declared field, in the record type's declared order.
    #[test]
    fn filter_parameters_are_typed_equality_parameters() {
        let record_type: RecordType = serde_json::from_value(json!({
            "name": "case",
            "fields": [
                {"name": "case_type", "type": "string", "required": true},
                {"name": "severity", "type": "integer"},
                {"name": "opened_on", "type": "date"},
            ],
        }))
        .expect("the record type decodes");
        assert_eq!(
            filter_parameters(&record_type.fields.iter().collect::<Vec<_>>()),
            vec![
                json!({
                    "name": "case_type",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string"},
                }),
                json!({
                    "name": "severity",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "integer"},
                }),
                json!({
                    "name": "opened_on",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string", "format": "date"},
                }),
            ]
        );
    }

    /// The problem assembler answers one response per distinct status, each
    /// referencing the shared problem schema; the first problem carrying a
    /// status describes its response.
    #[test]
    fn problem_responses_are_keyed_by_status() {
        let responses = problem_responses(&profile().problems);
        assert_eq!(responses.len(), 2);
        assert_eq!(
            responses["404"]["description"],
            "No case answers the request."
        );
        assert_eq!(
            responses["409"]["content"]["application/json"]["schema"],
            json!({"$ref": "#/components/schemas/Problem"})
        );
    }

    /// Every compiled operation answers the profile's problems beside its
    /// success response: one error response per distinct status, described
    /// by the first problem carrying that status.
    #[test]
    fn error_responses_follow_the_problems_list() {
        let document = assemble(&profile(), &project(both_bindings())).expect("the assembly runs");
        for (path, method) in [
            ("/v2/cases/case/{case_id}", "get"),
            ("/v2/cases/case", "post"),
        ] {
            let responses = &document["paths"][path][method]["responses"];
            let keys: Vec<&str> = responses
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, ["200", "404", "409"], "{path} {method}");
            assert_eq!(
                responses["404"],
                json!({
                    "description": "No case answers the request.",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Problem"}
                        }
                    },
                })
            );
        }
    }
}
