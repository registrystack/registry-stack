// SPDX-License-Identifier: Apache-2.0

//! Generated documents: the JSON Schemas for the Document Store runtime
//! configuration, the authored project file, and the data of each event
//! family an observer receives, and the OpenAPI description of the HTTP
//! surface.
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
//! cargo run -p registry-documents --features schema --example event-schemas -- \
//!   --output products/documents/generated/events
//! cargo run -p registry-documents --features schema --example openapi -- \
//!   --output products/documents/generated
//! ```

use std::collections::{BTreeMap, BTreeSet};

use registry_documents_core::{
    type_uri, DocumentsProject, HookTrigger, ProblemCode, DOCUMENTS_PROJECT_API_VERSION,
    DOCUMENTS_PROJECT_KIND, DOCUMENTS_PROJECT_SCHEMA_ID, DOCUMENTS_RUNTIME_API_VERSION,
    DOCUMENTS_RUNTIME_KIND, DOCUMENTS_RUNTIME_SCHEMA_ID, HEALTH_PATH, PROJECT_SCHEMA_FILE,
    RUNTIME_SCHEMA_FILE,
};
use serde_json::{json, Map, Value};

use crate::config::RuntimeConfig;
use crate::http::{
    DOCUMENTS_PATH, DOCUMENT_CONTENT_PATH, DOCUMENT_ERASURE_PATH, DOCUMENT_GRANTS_PATH,
    DOCUMENT_PATH, GRANTS_PATH, GRANT_PATH, MAXIMUM_IDEMPOTENCY_KEY_BYTES, POLICIES_PATH,
    UPLOAD_CONTENT_PATH,
};
use crate::service::MAXIMUM_CURSOR_BYTES;
use registry_documents_core::{DEFAULT_PAGE_SIZE, MAXIMUM_PAGE_SIZE};

/// File name of the generated OpenAPI document.
pub const OPENAPI_FILE: &str = "registry-documents.openapi.json";

/// What one side of an operation carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Payload {
    /// No body.
    Empty,
    /// A JSON document of the named component schema.
    Json(&'static str),
    /// Document content of the reserved media type, as raw bytes.
    Content,
}

/// One operation the public listener serves.
pub struct Operation {
    pub method: &'static str,
    pub path: &'static str,
    pub operation_id: &'static str,
    pub summary: &'static str,
    /// What the summary leaves out that a client needs, if anything.
    pub description: Option<&'static str>,
    /// Whether the caller must present a bearer access token.
    pub authenticated: bool,
    /// Whether the request carries a required `Idempotency-Key` header.
    pub idempotent: bool,
    /// Whether the operation pages by `cursor` and `limit`.
    pub paged: bool,
    pub request: Payload,
    pub success: u16,
    pub response: Payload,
    pub problems: &'static [ProblemCode],
}

/// Every problem an authenticated operation can answer before it reads
/// anything of the request but its credential.
const CALLER: [ProblemCode; 4] = [
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::RequestMethodNotAllowed,
    ProblemCode::ServiceUnavailable,
];

/// Every problem reading a JSON request body can answer.
const JSON_BODY: [ProblemCode; 4] = [
    ProblemCode::RequestBodyTooLarge,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
];

const fn join<const A: usize, const B: usize, const C: usize, const N: usize>(
    first: [ProblemCode; A],
    second: [ProblemCode; B],
    third: [ProblemCode; C],
) -> [ProblemCode; N] {
    assert!(A + B + C == N, "the joined length is the sum of the parts");
    let mut joined = [ProblemCode::ServiceUnavailable; N];
    let mut index = 0;
    while index < A {
        joined[index] = first[index];
        index += 1;
    }
    while index < A + B {
        joined[index] = second[index - A];
        index += 1;
    }
    while index < N {
        joined[index] = third[index - A - B];
        index += 1;
    }
    joined
}

const RESERVE_PROBLEMS: [ProblemCode; 15] = join(
    CALLER,
    JSON_BODY,
    [
        ProblemCode::CustodyNotPermitted,
        ProblemCode::CustodyQuotaExceeded,
        ProblemCode::DocumentContentTypeNotAllowed,
        ProblemCode::DocumentPolicyUnknown,
        ProblemCode::DocumentTooLarge,
        ProblemCode::IdempotencyExpired,
        ProblemCode::IdempotencyKeyReused,
    ],
);
const LIST_PROBLEMS: [ProblemCode; 5] = join(CALLER, [ProblemCode::RequestInvalid], []);
const READ_PROBLEMS: [ProblemCode; 5] = join(CALLER, [ProblemCode::ResourceNotFound], []);
const DOWNLOAD_PROBLEMS: [ProblemCode; 6] = join(
    CALLER,
    [
        ProblemCode::DocumentVersionNotReleasable,
        ProblemCode::ResourceNotFound,
    ],
    [],
);
const UPLOAD_PROBLEMS: [ProblemCode; 13] = join(
    CALLER,
    [
        ProblemCode::RequestBodyTooLarge,
        ProblemCode::RequestInvalid,
        ProblemCode::ResourceNotFound,
    ],
    [
        ProblemCode::UploadContentTypeMismatch,
        ProblemCode::UploadDigestMismatch,
        ProblemCode::UploadExpired,
        ProblemCode::UploadFinalized,
        ProblemCode::UploadLengthMismatch,
        ProblemCode::CustodyQuotaExceeded,
    ],
);
const ISSUE_GRANT_PROBLEMS: [ProblemCode; 11] = join(
    CALLER,
    JSON_BODY,
    [
        ProblemCode::DocumentVersionNotReleasable,
        ProblemCode::IdempotencyKeyReused,
        ProblemCode::ResourceNotFound,
    ],
);
const LIST_GRANTS_PROBLEMS: [ProblemCode; 6] = join(
    CALLER,
    [ProblemCode::RequestInvalid, ProblemCode::ResourceNotFound],
    [],
);

/// Every operation the public listener serves. Every other route answers
/// `request.not-found`.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        method: "get",
        path: HEALTH_PATH,
        operation_id: "health",
        summary: "Report that the process is serving.",
        description: None,
        authenticated: false,
        idempotent: false,
        paged: false,
        request: Payload::Empty,
        success: 200,
        response: Payload::Empty,
        problems: &[ProblemCode::RequestMethodNotAllowed],
    },
    Operation {
        method: "post",
        path: DOCUMENTS_PATH,
        operation_id: "reserveDocument",
        summary: "Reserve a document under a policy and receive its upload path.",
        description: None,
        authenticated: true,
        idempotent: true,
        paged: false,
        request: Payload::Json("ReserveDocumentRequest"),
        success: 201,
        response: Payload::Json("ReservationView"),
        problems: &RESERVE_PROBLEMS,
    },
    Operation {
        method: "get",
        path: DOCUMENTS_PATH,
        operation_id: "listDocuments",
        summary: "List the documents the caller holds in custody or reserved.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: true,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentPage"),
        problems: &LIST_PROBLEMS,
    },
    Operation {
        method: "get",
        path: DOCUMENT_PATH,
        operation_id: "readDocument",
        summary: "Read one document's metadata and the actions the caller may take.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: false,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentView"),
        problems: &READ_PROBLEMS,
    },
    Operation {
        method: "get",
        path: DOCUMENT_CONTENT_PATH,
        operation_id: "downloadDocumentVersion",
        summary: "Download one releasable document version, as the custodian or a grant holder.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: false,
        request: Payload::Empty,
        success: 200,
        response: Payload::Content,
        problems: &DOWNLOAD_PROBLEMS,
    },
    Operation {
        method: "put",
        path: UPLOAD_CONTENT_PATH,
        operation_id: "uploadDocumentContent",
        summary: "Send the reserved content; a repeat of the same content answers the same view.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: false,
        request: Payload::Content,
        success: 200,
        response: Payload::Json("DocumentView"),
        problems: &UPLOAD_PROBLEMS,
    },
    Operation {
        method: "post",
        path: DOCUMENT_GRANTS_PATH,
        operation_id: "issueDocumentGrant",
        summary: "Grant one named recipient one exact document version until a fixed expiry.",
        description: None,
        authenticated: true,
        idempotent: true,
        paged: false,
        request: Payload::Json("IssueGrantRequest"),
        success: 201,
        response: Payload::Json("DocumentGrantView"),
        problems: &ISSUE_GRANT_PROBLEMS,
    },
    Operation {
        method: "get",
        path: DOCUMENT_GRANTS_PATH,
        operation_id: "listDocumentGrants",
        summary: "List every grant on one document, in any state.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: true,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentGrantPage"),
        problems: &LIST_GRANTS_PROBLEMS,
    },
    Operation {
        method: "get",
        path: GRANTS_PATH,
        operation_id: "listReceivedGrants",
        summary: "List the active grants that name the caller.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: true,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentGrantPage"),
        problems: &LIST_PROBLEMS,
    },
    Operation {
        method: "delete",
        path: GRANT_PATH,
        operation_id: "revokeDocumentGrant",
        summary: "Revoke one grant; revoking a revoked grant answers the same view.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: false,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentGrantView"),
        problems: &READ_PROBLEMS,
    },
    Operation {
        method: "post",
        path: DOCUMENT_ERASURE_PATH,
        operation_id: "requestDocumentErasure",
        summary: "Ask, as the custodian, for a document's erasure; release stops at once.",
        description: Some(
            "Takes no `Idempotency-Key`: the request is repeat-safe by construction. \
             The first request moves the version to erasure; a repeat moves nothing, \
             revokes nothing, keeps the first due time, and answers the document as \
             it stands, so a client that lost the answer may simply send it again.",
        ),
        authenticated: true,
        idempotent: false,
        paged: false,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentView"),
        problems: &READ_PROBLEMS,
    },
    Operation {
        method: "get",
        path: POLICIES_PATH,
        operation_id: "listDocumentPolicies",
        summary: "List the policies the caller may place documents under, with their bounds.",
        description: None,
        authenticated: true,
        idempotent: false,
        paged: false,
        request: Payload::Empty,
        success: 200,
        response: Payload::Json("DocumentPolicyList"),
        problems: &CALLER,
    },
];

/// The JSON Schema of every body the operations name, keyed by component
/// name, with each type's own definitions hoisted beside it.
fn component_schemas() -> Result<Map<String, Value>, serde_json::Error> {
    use registry_documents_core::{
        DocumentGrantPage, DocumentGrantView, DocumentPage, DocumentPolicyList, DocumentView,
        IssueGrantRequest, ReservationView, ReserveDocumentRequest,
    };
    let derived = [
        (
            "ReserveDocumentRequest",
            schemars::schema_for!(ReserveDocumentRequest),
        ),
        ("ReservationView", schemars::schema_for!(ReservationView)),
        ("DocumentView", schemars::schema_for!(DocumentView)),
        ("DocumentPage", schemars::schema_for!(DocumentPage)),
        (
            "IssueGrantRequest",
            schemars::schema_for!(IssueGrantRequest),
        ),
        (
            "DocumentGrantView",
            schemars::schema_for!(DocumentGrantView),
        ),
        (
            "DocumentGrantPage",
            schemars::schema_for!(DocumentGrantPage),
        ),
        (
            "DocumentPolicyList",
            schemars::schema_for!(DocumentPolicyList),
        ),
    ];
    let mut components = Map::new();
    for (name, schema) in derived {
        let mut schema = serde_json::to_value(schema)?;
        refuse_null(&mut schema);
        retarget_references(&mut schema);
        let Value::Object(mut object) = schema else {
            unreachable!("schemars derives a schema object for a struct")
        };
        object.remove("$schema");
        object.remove("title");
        if let Some(Value::Object(definitions)) = object.remove("$defs") {
            components.extend(definitions);
        }
        components.insert(name.to_owned(), Value::Object(object));
    }
    Ok(components)
}

/// Point every `#/$defs/` reference at the OpenAPI components.
fn retarget_references(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref") {
                if let Some(name) = reference.strip_prefix("#/$defs/") {
                    *reference = format!("#/components/schemas/{name}");
                }
            }
            object.values_mut().for_each(retarget_references);
        }
        Value::Array(items) => items.iter_mut().for_each(retarget_references),
        _ => {}
    }
}

fn payload_content(payload: Payload) -> Option<Value> {
    match payload {
        Payload::Empty => None,
        Payload::Json(schema) => Some(json!({"application/json": {
            "schema": {"$ref": format!("#/components/schemas/{schema}")}
        }})),
        Payload::Content => Some(json!({"*/*": {
            "schema": {"type": "string", "contentMediaType": "application/octet-stream"}
        }})),
    }
}

/// The parameters of `operation`: its path identifiers, its paging query,
/// and its idempotency key.
fn parameters(operation: &Operation) -> Vec<Value> {
    let mut parameters: Vec<Value> = operation
        .path
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| {
            json!({
                "name": name,
                "in": "path",
                "required": true,
                "schema": {"type": "string", "format": "uuid"}
            })
        })
        .collect();
    if operation.paged {
        parameters.push(json!({
            "name": "cursor",
            "in": "query",
            "required": false,
            "description": "The opaque cursor a previous page returned as `nextCursor`.",
            "schema": {"type": "string", "maxLength": MAXIMUM_CURSOR_BYTES}
        }));
        parameters.push(json!({
            "name": "limit",
            "in": "query",
            "required": false,
            "description": "Items per page.",
            "schema": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAXIMUM_PAGE_SIZE,
                "default": DEFAULT_PAGE_SIZE
            }
        }));
    }
    if operation.idempotent {
        parameters.push(json!({
            "name": "Idempotency-Key",
            "in": "header",
            "required": true,
            "description": "The caller's key for this request. A retry with the same key and body answers the first outcome; another body under the key is refused.",
            "schema": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_IDEMPOTENCY_KEY_BYTES, "pattern": "^[!-~]+$"}
        }));
    }
    parameters
}

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

/// The data schema of each event family, one closed object per trigger.
pub fn event_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    HookTrigger::ALL
        .into_iter()
        .map(|trigger| {
            Ok((
                trigger.data_schema_file(),
                render(&crate::hooks::event_data_schema(trigger))?,
            ))
        })
        .collect()
}

/// The OpenAPI 3.1 description of every operation the public listener
/// serves, with the problem each can answer.
pub fn openapi_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut paths = Map::new();
    for operation in OPERATIONS {
        let mut responses = Map::new();
        let mut success = json!({"description": match operation.response {
            Payload::Empty => "The operation succeeded. The body is empty.",
            Payload::Json(_) => "The operation succeeded.",
            Payload::Content => "The document version's content, exactly as reserved and verified.",
        }});
        if let Some(content) = payload_content(operation.response) {
            success["content"] = content;
        }
        if operation.success == 201 {
            success["headers"] = json!({"Location": {
                "description": "The path of the created resource.",
                "required": true,
                "schema": {"type": "string"}
            }});
        }
        responses.insert(operation.success.to_string(), success);
        let mut by_status: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
        for problem in operation.problems {
            by_status
                .entry(problem.http_status())
                .or_default()
                .push(problem.code());
        }
        for (status, mut codes) in by_status {
            codes.sort_unstable();
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
            if status == 401 {
                response["headers"] = json!({"WWW-Authenticate": {
                    "description": "The bearer challenge.",
                    "required": true,
                    "schema": {"type": "string", "const": "Bearer"}
                }});
            }
            responses.insert(status.to_string(), response);
        }
        let mut entry = json!({
            "operationId": operation.operation_id,
            "summary": operation.summary,
            "security": if operation.authenticated { json!([{"bearer": []}]) } else { json!([]) },
            "responses": responses,
        });
        if let Some(description) = operation.description {
            entry["description"] = json!(description);
        }
        let parameters = parameters(operation);
        if !parameters.is_empty() {
            entry["parameters"] = Value::Array(parameters);
        }
        if let Some(content) = payload_content(operation.request) {
            entry["requestBody"] = json!({"required": true, "content": content});
        }
        paths
            .entry(operation.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("every path item is an object")
            .insert(operation.method.to_owned(), entry);
    }
    let mut schemas = component_schemas()?;
    let problem_types: Vec<String> = ProblemCode::ALL
        .iter()
        .map(|problem| type_uri(problem.code()))
        .collect();
    let codes: Vec<&str> = ProblemCode::ALL
        .iter()
        .map(|problem| problem.code())
        .collect();
    schemas.insert(
        "Problem".to_owned(),
        json!({
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
        }),
    );
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
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            },
            "schemas": schemas
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
    fn openapi_states_bearer_security_and_resolves_every_reference() {
        let document = schema(&openapi_documents().unwrap(), OPENAPI_FILE);
        assert_eq!(
            document["components"]["securitySchemes"]["bearer"]["scheme"],
            "bearer"
        );
        for operation in OPERATIONS {
            let entry = &document["paths"][operation.path][operation.method];
            let expected = if operation.authenticated {
                json!([{"bearer": []}])
            } else {
                json!([])
            };
            assert_eq!(entry["security"], expected, "{}", operation.operation_id);
            assert_eq!(
                entry["responses"].get("401").is_some(),
                operation.authenticated,
                "{}",
                operation.operation_id
            );
        }
        let mut references = Vec::new();
        collect_references(&document, &mut references);
        assert!(!references.is_empty());
        for reference in references {
            let name = reference
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("{reference} points outside the components"));
            assert!(
                document["components"]["schemas"].get(name).is_some(),
                "{reference} does not resolve"
            );
        }
    }

    fn collect_references(value: &Value, references: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                if let Some(Value::String(reference)) = object.get("$ref") {
                    references.push(reference.clone());
                }
                object
                    .values()
                    .for_each(|value| collect_references(value, references));
            }
            Value::Array(items) => items
                .iter()
                .for_each(|value| collect_references(value, references)),
            _ => {}
        }
    }

    #[test]
    fn the_erasure_route_states_why_it_takes_no_idempotency_key() {
        let openapi = schema(&openapi_documents().unwrap(), OPENAPI_FILE);
        let operation = &openapi["paths"][DOCUMENT_ERASURE_PATH]["post"];
        let description = operation["description"].as_str().unwrap();
        assert!(description.contains("Idempotency-Key"), "{description}");
        assert!(description.contains("repeat"), "{description}");
        let parameters = operation["parameters"].as_array().unwrap();
        assert!(!parameters
            .iter()
            .any(|parameter| parameter["name"] == "Idempotency-Key"));
    }

    #[test]
    fn openapi_describes_exactly_the_routes_the_listener_serves() {
        let source = include_str!("http.rs");
        let served: std::collections::BTreeSet<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix(".route("))
            .filter_map(|rest| rest.split(',').next())
            .collect();
        let described: std::collections::BTreeSet<&str> = OPERATIONS
            .iter()
            .map(|operation| match operation.path {
                HEALTH_PATH => "HEALTH_PATH",
                DOCUMENTS_PATH => "DOCUMENTS_PATH",
                DOCUMENT_PATH => "DOCUMENT_PATH",
                DOCUMENT_CONTENT_PATH => "DOCUMENT_CONTENT_PATH",
                DOCUMENT_GRANTS_PATH => "DOCUMENT_GRANTS_PATH",
                GRANTS_PATH => "GRANTS_PATH",
                GRANT_PATH => "GRANT_PATH",
                DOCUMENT_ERASURE_PATH => "DOCUMENT_ERASURE_PATH",
                POLICIES_PATH => "POLICIES_PATH",
                UPLOAD_CONTENT_PATH => "UPLOAD_CONTENT_PATH",
                other => panic!("{other} is not a served path"),
            })
            .collect();
        assert_eq!(served, described);
    }

    #[test]
    fn event_schemas_are_deterministic_closed_and_one_per_trigger() {
        let first = event_documents().unwrap();
        assert_eq!(first, event_documents().unwrap());
        assert_eq!(first.len(), HookTrigger::ALL.len());
        for trigger in HookTrigger::ALL {
            let document = schema(&first, trigger.data_schema_file());
            assert_eq!(document["$id"], trigger.data_schema_id());
            assert_eq!(document["additionalProperties"], false);
            let mut published = document["properties"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            published.sort();
            let mut fields = trigger
                .fields()
                .iter()
                .map(|field| (*field).to_owned())
                .collect::<Vec<_>>();
            fields.sort();
            assert_eq!(published, fields, "{}", trigger.as_str());
        }
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
            (
                generated.join("events"),
                event_documents().unwrap(),
                "event-schemas",
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
