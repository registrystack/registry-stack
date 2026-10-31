// SPDX-License-Identifier: Apache-2.0

//! The effective operation contract exported from the runtime's loaded plan.
//!
//! Authored profiles describe candidates. This contract contains only the
//! read operations [`crate::load::load`] compiled for serving under the
//! operator's runtime binding. It embeds the same closed schemas the facade
//! derives and validates, and binds the versioned contract with an RFC 8785
//! digest. It does not implement MCP or grant personal disclosure authority.

use registry_adapter_core::{
    decode_slot, derive_binding_result_schema, derive_operation_request_schema,
    derive_problem_envelope_schema, parse_envelope_template, HttpMethod, RecordFieldType, SlotForm,
    SLOT_RECORDS,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::sha256_uri;
use serde::Serialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::component::{
    http::uri::CONTRACT_PATH_SEGMENT_DISALLOWED_PATTERN,
    rest::continuation::CURSOR_MAXIMUM_TOKEN_BYTES,
};
use crate::load::{Loaded, ServedOperation};

pub const API_VERSION: &str = "id.registrystack.org/formats/adapter/effective-contract/v1alpha1";
pub const KIND: &str = "AdapterEffectiveContract";
pub const WELL_KNOWN_PATH: &str = "/.well-known/registry-adapter/effective-contract";
pub const PIN_HEADER: &str = "x-registry-adapter-contract";
pub const DIGEST_DOMAIN: &str = "registry-adapter/effective-contract/v1alpha1";
pub const JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
pub const PIN_PROBLEM_CODE: &str = "adapter.contract.precondition-failed";
pub const UNAVAILABLE_PROBLEM_CODE: &str = "adapter.contract.unavailable";
pub const REQUEST_ID_PATTERN: &str = "^[0-9a-f]{32}$";

// Powers of two are exactly representable under RFC 8785's binary64 number
// model. Exclusive upper bounds therefore describe the runtime's complete
// signed and unsigned integer domains without placing an unhashable i64::MAX
// or u64::MAX value inside the effective contract.
const SIGNED_INTEGER_EXCLUSIVE_MAXIMUM: u64 = 1_u64 << 63;
const JSON_INTEGER_EXCLUSIVE_MAXIMUM: f64 = 18_446_744_073_709_551_616.0;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("the loaded operation {0} has no authored binding")]
    MissingBinding(String),
    #[error("the loaded operation {0} has no profile declaration")]
    MissingOperation(String),
    #[error("the effective operation schema could not be derived: {0}")]
    Schema(String),
    #[error("the effective contract could not be serialized")]
    Serialize,
    #[error("the effective contract could not be canonicalized")]
    Canonicalize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveContract {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub digest: String,
    pub contract: EffectiveContractBody,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveContractBody {
    pub schema_dialect: &'static str,
    pub project: ProjectIdentity,
    pub profile_version: String,
    pub artifact_deployment_digest: String,
    pub authentication: AuthenticationRequirement,
    pub authority: AuthorityBoundary,
    pub operations: Vec<EffectiveOperation>,
    pub unserved: Vec<UnservedOperation>,
    pub problem_schema: Value,
    pub protocol_problems: ProtocolProblems,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectIdentity {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRequirement {
    pub scheme: &'static str,
    pub audience: String,
    pub client_admission: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityBoundary {
    pub caller_mode: &'static str,
    pub represented_subject: &'static str,
    pub personal_delegation: &'static str,
    pub target_binding: &'static str,
    pub row_disclosure_authority: &'static str,
    pub field_disclosure_authority: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProtocolProblems {
    pub schema: Value,
    pub problems: Vec<ProtocolProblem>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProtocolProblem {
    pub code: &'static str,
    pub status: u16,
    pub title: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveOperation {
    pub id: String,
    pub version: String,
    pub binding_id: String,
    pub profile_operation_id: String,
    pub method: &'static str,
    pub path: String,
    pub support: &'static str,
    pub effect: &'static str,
    pub success_status: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_maximum_bytes: Option<usize>,
    pub input: OperationInput,
    pub output: Value,
    pub access: AccessRequirement,
}

#[derive(Clone, Debug, Serialize)]
pub struct OperationInput {
    pub path: Value,
    pub query: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRequirement {
    pub any_of: Vec<ScopeSet>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeSet {
    pub all_scopes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnservedOperation {
    pub operation_id: String,
    pub version: String,
    pub binding_id: String,
    pub profile_operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
    pub support: &'static str,
    pub effect: &'static str,
    pub reason_code: String,
    pub reason: String,
}

impl EffectiveContract {
    pub fn from_loaded(loaded: &Loaded) -> Result<Self, ContractError> {
        let mut operations = Vec::new();
        let mut unserved = loaded
            .unserved
            .iter()
            .map(|entry| {
                let binding = loaded
                    .project
                    .bindings
                    .get(&entry.binding)
                    .ok_or_else(|| ContractError::MissingBinding(entry.binding.clone()))?;
                let profile_operation_id = binding.operation.as_str().to_owned();
                let profile_operation = loaded.profile.operations.get(&profile_operation_id);
                Ok(UnservedOperation {
                    operation_id: operation_id(
                        binding.operation.as_str(),
                        binding.record_type.as_str(),
                    ),
                    version: loaded.profile.version.clone(),
                    binding_id: entry.binding.clone(),
                    profile_operation_id,
                    method: profile_operation.map(|operation| method_name(operation.method)),
                    support: "unserved",
                    effect: unserved_effect(profile_operation),
                    reason_code: entry.reason_code.to_owned(),
                    reason: public_unserved_reason(entry.reason_code).to_owned(),
                })
            })
            .collect::<Result<Vec<_>, ContractError>>()?;

        for served in &loaded.served {
            let profile = loaded
                .profile
                .operations
                .get(&served.operation)
                .ok_or_else(|| ContractError::MissingOperation(served.operation.clone()))?;
            if !profile.is_read() {
                unserved.push(UnservedOperation {
                    operation_id: operation_id(&served.operation, &served.record_type),
                    version: loaded.profile.version.clone(),
                    binding_id: served.binding.clone(),
                    profile_operation_id: served.operation.clone(),
                    method: Some(method_name(profile.method)),
                    support: "unserved",
                    effect: "write",
                    reason_code: "adapter.operation.gateway-write-disabled".to_owned(),
                    reason: "the external gateway contract does not expose write operations"
                        .to_owned(),
                });
                continue;
            }
            let access = access_requirement(loaded, served);
            if access.any_of.is_empty() {
                unserved.push(UnservedOperation {
                    operation_id: operation_id(&served.operation, &served.record_type),
                    version: loaded.profile.version.clone(),
                    binding_id: served.binding.clone(),
                    profile_operation_id: served.operation.clone(),
                    method: Some(method_name(profile.method)),
                    support: "unserved",
                    effect: operation_effect(profile.method, profile.read_only),
                    reason_code: "adapter.operation.no-access-profile".to_owned(),
                    reason: "no non-empty access profile admits the operation and record type"
                        .to_owned(),
                });
                continue;
            }
            operations.push(effective_operation(loaded, served, access)?);
        }

        let problem_schema =
            derive_problem_envelope_schema(&loaded.profile).map_err(ContractError::Schema)?;
        let body = EffectiveContractBody {
            schema_dialect: JSON_SCHEMA_DIALECT,
            project: ProjectIdentity {
                id: loaded.project.project.id.as_str().to_owned(),
                version: loaded.project.project.version.clone(),
            },
            profile_version: loaded.profile.version.clone(),
            artifact_deployment_digest: loaded.deployment.clone(),
            authentication: AuthenticationRequirement {
                scheme: "bearer",
                audience: loaded.runtime.oidc.audience.clone(),
                client_admission: "allowlist",
            },
            authority: AuthorityBoundary {
                caller_mode: "trusted-machine",
                represented_subject: "unsupported",
                personal_delegation: "unsupported",
                target_binding: "unsupported",
                row_disclosure_authority: "not-granted",
                field_disclosure_authority: "not-granted",
            },
            operations,
            unserved,
            problem_schema,
            protocol_problems: protocol_problems(),
        };
        let digest = contract_digest(&body)?;
        Ok(Self {
            api_version: API_VERSION,
            kind: KIND,
            digest,
            contract: body,
        })
    }

    pub fn to_pretty_json(&self) -> Result<String, ContractError> {
        serde_json::to_string_pretty(self)
            .map(|mut document| {
                document.push('\n');
                document
            })
            .map_err(|_| ContractError::Serialize)
    }
}

fn contract_digest(contract: &EffectiveContractBody) -> Result<String, ContractError> {
    let value = json!({
        "domain": DIGEST_DOMAIN,
        "apiVersion": API_VERSION,
        "kind": KIND,
        "contract": contract,
    });
    let canonical = canonicalize_json(&value).map_err(|_| ContractError::Canonicalize)?;
    Ok(sha256_uri(&canonical))
}

fn effective_operation(
    loaded: &Loaded,
    served: &ServedOperation,
    access: AccessRequirement,
) -> Result<EffectiveOperation, ContractError> {
    let binding = loaded
        .project
        .bindings
        .get(&served.binding)
        .ok_or_else(|| ContractError::MissingBinding(served.binding.clone()))?;
    let profile = loaded
        .profile
        .operations
        .get(&served.operation)
        .ok_or_else(|| ContractError::MissingOperation(served.operation.clone()))?;
    let concrete_path = served.method_path.replace(
        &format!("{{{}}}", served.record_type_parameter),
        &served.record_type,
    );
    let mut body = served
        .request_template
        .as_ref()
        .map(|_| derive_operation_request_schema(&loaded.profile, &loaded.project, binding))
        .transpose()
        .map_err(ContractError::Schema)?;
    if let (Some(schema), Some(template)) = (&mut body, profile.request_envelope.as_ref()) {
        let template = parse_envelope_template(template.text()).map_err(ContractError::Schema)?;
        apply_exact_array_lengths(schema, &template);
        if let Some(pagination) = &served.pagination {
            refine_slot_schema(schema, &template, "pageSize", &|member| {
                *member = json!({
                    "type": "integer",
                    "minimum": pagination.page_size_minimum,
                    "maximum": pagination.page_size_maximum,
                });
                if let Some(default) = pagination.page_size_default {
                    member["default"] = json!(default);
                }
            });
            refine_slot_schema(schema, &template, "cursor", &apply_cursor_contract);
            if pagination.page_size_default.is_none() {
                require_cursor_or_page_size(schema, &template);
            }
        }
        refine_slot_schema(schema, &template, "recordId", &apply_path_segment_contract);
        refine_slot_schema(schema, &template, "filters", &|member| {
            apply_filter_integer_bounds(member, &served.filters);
        });
    }
    let mut output = derive_binding_result_schema(&loaded.profile, &loaded.project, binding)
        .map_err(ContractError::Schema)?;
    if let Some(pagination) = &served.pagination {
        apply_records_array_maximum(
            &mut output,
            profile.response_envelope.text(),
            pagination.page_size_maximum,
        )?;
    }

    Ok(EffectiveOperation {
        id: operation_id(&served.operation, &served.record_type),
        version: loaded.profile.version.clone(),
        binding_id: served.binding.clone(),
        profile_operation_id: served.operation.clone(),
        method: method_name(served.method),
        path: concrete_path,
        support: "served",
        effect: operation_effect(profile.method, profile.read_only),
        success_status: profile.success_status.get(),
        request_maximum_bytes: served
            .request_template
            .as_ref()
            .map(|_| served.request_maximum_bytes),
        input: OperationInput {
            path: path_schema(profile, served),
            query: query_schema(served),
            body,
        },
        output,
        access,
    })
}

fn operation_id(operation: &str, record_type: &str) -> String {
    format!("{operation}.{record_type}")
}

fn public_unserved_reason(code: &str) -> &'static str {
    match code {
        "adapter.operation.profile-operation-missing" => {
            "the binding has no loaded profile operation"
        }
        "adapter.operation.method-unsupported" => "the facade method is not served by this runtime",
        "adapter.operation.write-async-unsupported" => {
            "a write success status of 202 needs asynchronous completion recovery"
        }
        "adapter.operation.request-body-unsupported" => {
            "the operation declares a request body form this runtime does not serve"
        }
        "adapter.operation.request-envelope-missing" => {
            "the operation needs a request envelope before it can be served"
        }
        "adapter.operation.pagination-declaration-missing" => {
            "the request envelope needs a matching pagination declaration"
        }
        "adapter.operation.record-type-missing" => "the binding has no loaded record type",
        "adapter.operation.filter-field-missing" => {
            "the binding has a filter with no loaded record field"
        }
        "adapter.operation.route-instantiation-refused" => {
            "the binding route could not be instantiated"
        }
        "adapter.operation.route-missing" => "the binding has no loaded route",
        "adapter.operation.reserved-facade-path" => {
            "the facade path is reserved for the Adapter effective-contract route"
        }
        "adapter.operation.cursor-key-missing" => {
            "the paginated operation has no configured cursor key"
        }
        "adapter.operation.route-unsupported" => {
            "the route contains behavior this runtime does not serve"
        }
        "adapter.operation.write-idempotency-missing" => {
            "the write route does not provide the required idempotency boundary"
        }
        "adapter.operation.direct-route-missing" => {
            "the route calls a direct route that is not loaded"
        }
        "adapter.operation.source-authentication-unsupported" => {
            "the source authentication mode is not served by this runtime"
        }
        "adapter.operation.source-component-mismatch" => {
            "the source component does not match the route call"
        }
        "adapter.operation.source-unbound" => {
            "the route calls a source that is not bound by the runtime"
        }
        "adapter.operation.record-schema-unavailable" => {
            "the binding record schema could not be derived"
        }
        _ => "the operation is not served by this runtime",
    }
}

/// Classify the facade effect from the profile semantics, not from the HTTP
/// method alone. The only method override is the profile's reviewed
/// read-only POST form. PUT and PATCH remain writes even if a malformed
/// in-memory profile were to carry `readOnly`; the profile checks refuse that
/// combination before loading, and the exporter still fails closed here.
fn operation_effect(method: HttpMethod, read_only: bool) -> &'static str {
    match (method, read_only) {
        (HttpMethod::Get, _) | (HttpMethod::Post, true) => "read",
        (HttpMethod::Post, false) | (HttpMethod::Put, _) | (HttpMethod::Patch, _) => "write",
    }
}

fn unserved_effect(operation: Option<&registry_adapter_core::ProfileOperation>) -> &'static str {
    operation.map_or("unknown", |operation| {
        operation_effect(operation.method, operation.read_only)
    })
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
    }
}

fn closed_object(properties: Map<String, Value>, mut required: Vec<String>) -> Value {
    required.sort();
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn path_schema(
    profile: &registry_adapter_core::ProfileOperation,
    served: &ServedOperation,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for parameter in &profile.path_parameters {
        if parameter.as_str() == served.record_type_parameter {
            continue;
        }
        properties.insert(parameter.as_str().to_owned(), path_segment_schema());
        required.push(parameter.as_str().to_owned());
    }
    closed_object(properties, required)
}

fn query_schema(served: &ServedOperation) -> Value {
    if served.method == HttpMethod::Post {
        return closed_object(Map::new(), Vec::new());
    }
    let mut properties = Map::new();
    let mut required = Vec::new();
    if let Some(pagination) = &served.pagination {
        properties.insert(pagination.cursor_parameter.clone(), cursor_schema());
        let mut page_size = json!({
            "type": "integer",
            "minimum": pagination.page_size_minimum,
            "maximum": pagination.page_size_maximum,
        });
        if let Some(default) = pagination.page_size_default {
            page_size["default"] = json!(default);
        }
        properties.insert(pagination.page_size_parameter.clone(), page_size);
    }
    for filter in &served.filters {
        properties.insert(filter.name.clone(), field_schema(filter.field_type));
        required.push(filter.name.clone());
    }
    let mut schema = closed_object(properties, required);
    if served
        .pagination
        .as_ref()
        .is_some_and(|pagination| pagination.page_size_default.is_none())
    {
        let pagination = served.pagination.as_ref().expect("pagination exists");
        append_constraint(
            &mut schema,
            json!({
                "anyOf": [
                    {"required": [pagination.cursor_parameter.clone()]},
                    {"required": [pagination.page_size_parameter.clone()]},
                ]
            }),
        );
    }
    schema
}

fn field_schema(field_type: RecordFieldType) -> Value {
    match field_type {
        RecordFieldType::String => json!({"type": "string"}),
        RecordFieldType::Integer => json!({
            "type": "integer",
            "minimum": i64::MIN,
            "exclusiveMaximum": SIGNED_INTEGER_EXCLUSIVE_MAXIMUM,
        }),
        RecordFieldType::Decimal => json!({"type": "number"}),
        RecordFieldType::Boolean => json!({"type": "boolean"}),
        RecordFieldType::Date => json!({"type": "string", "format": "date"}),
        RecordFieldType::DateTime => json!({"type": "string", "format": "date-time"}),
    }
}

fn access_requirement(loaded: &Loaded, operation: &ServedOperation) -> AccessRequirement {
    let mut any_of = Vec::new();
    for profile in &loaded.project.access_profiles {
        let applies = !profile.scopes.is_empty()
            && profile
                .operations
                .iter()
                .any(|id| id.as_str() == operation.operation)
            && profile
                .record_types
                .iter()
                .any(|name| name.as_str() == operation.record_type);
        if !applies {
            continue;
        }
        let mut all_scopes = profile
            .scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect::<Vec<_>>();
        all_scopes.sort();
        let set = ScopeSet { all_scopes };
        if !any_of.contains(&set) {
            any_of.push(set);
        }
    }
    AccessRequirement { any_of }
}

fn path_segment_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "not": {"anyOf": [
            {"enum": [".", ".."]},
            {"pattern": CONTRACT_PATH_SEGMENT_DISALLOWED_PATTERN},
        ]},
    })
}

fn apply_path_segment_contract(schema: &mut Value) {
    *schema = path_segment_schema();
}

fn cursor_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": CURSOR_MAXIMUM_TOKEN_BYTES,
        "pattern": "^[A-Za-z0-9_-]+$",
        "x-registry-runtime-validation": "The Adapter verifies authenticated cursor bytes and their caller, operation, deployment, filter, and expiry bindings.",
    })
}

fn apply_cursor_contract(schema: &mut Value) {
    *schema = cursor_schema();
}

fn apply_filter_integer_bounds(schema: &mut Value, filters: &[crate::read_request::ServedFilter]) {
    remove_nullable_wrapper(schema);
    let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    for filter in filters {
        if filter.field_type == RecordFieldType::Integer {
            if let Some(member) = properties.get_mut(&filter.name) {
                member["minimum"] = json!(i64::MIN);
                member["exclusiveMaximum"] = json!(JSON_INTEGER_EXCLUSIVE_MAXIMUM);
            }
        }
    }
}

fn remove_nullable_wrapper(schema: &mut Value) {
    let replacement = schema
        .get("anyOf")
        .and_then(Value::as_array)
        .and_then(|members| {
            members
                .iter()
                .find(|member| member.get("type").and_then(Value::as_str) != Some("null"))
        })
        .cloned();
    if let Some(replacement) = replacement {
        *schema = replacement;
    }
}

#[derive(Clone, Debug)]
enum TemplateStep {
    Member(String),
    Index(usize),
}

fn require_cursor_or_page_size(schema: &mut Value, template: &Value) {
    let mut optional_paths = Vec::new();
    let mut already_required = false;
    collect_slot_paths(template, &mut Vec::new(), &mut |path, name, form| {
        if !matches!(name, "cursor" | "pageSize") {
            return;
        }
        if form == SlotForm::Optional {
            optional_paths.push(path.to_vec());
        } else {
            already_required = true;
        }
    });
    if already_required {
        return;
    }
    let alternatives = optional_paths
        .iter()
        .map(|path| presence_schema(path))
        .collect::<Vec<_>>();
    let constraint = if alternatives.is_empty() {
        // The runtime cannot open a first page without a default, a cursor,
        // or a supplied page size. Preserve that fact instead of advertising
        // a request body the facade will always refuse.
        json!({"not": {}})
    } else {
        json!({"anyOf": alternatives})
    };
    append_constraint(schema, constraint);
}

fn collect_slot_paths<F>(template: &Value, path: &mut Vec<TemplateStep>, visit: &mut F)
where
    F: FnMut(&[TemplateStep], &str, SlotForm),
{
    match template {
        Value::String(text) => {
            if let Some((name, form)) = decode_slot(text) {
                visit(path, name, form);
            }
        }
        Value::Object(members) => {
            for (name, member) in members {
                path.push(TemplateStep::Member(name.clone()));
                collect_slot_paths(member, path, visit);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(TemplateStep::Index(index));
                collect_slot_paths(item, path, visit);
                path.pop();
            }
        }
        _ => {}
    }
}

fn presence_schema(path: &[TemplateStep]) -> Value {
    let Some((step, rest)) = path.split_first() else {
        return json!({});
    };
    match step {
        TemplateStep::Member(name) => json!({
            "type": "object",
            "required": [name],
            "properties": {(name.clone()): presence_schema(rest)},
        }),
        TemplateStep::Index(index) => {
            let mut prefix = vec![json!({}); *index + 1];
            prefix[*index] = presence_schema(rest);
            json!({
                "type": "array",
                "minItems": *index + 1,
                "prefixItems": prefix,
            })
        }
    }
}

fn append_constraint(schema: &mut Value, constraint: Value) {
    let object = schema
        .as_object_mut()
        .expect("derived request schemas are JSON Schema objects");
    object
        .entry("allOf")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("the exporter alone writes allOf")
        .push(constraint);
}

fn apply_exact_array_lengths(schema: &mut Value, template: &Value) {
    match template {
        Value::Object(template_members) => {
            let Some(schema_members) = schema.get_mut("properties").and_then(Value::as_object_mut)
            else {
                return;
            };
            for (name, template_member) in template_members {
                if let Some(schema_member) = schema_members.get_mut(name) {
                    apply_exact_array_lengths(schema_member, template_member);
                }
            }
        }
        Value::Array(template_items) => {
            schema["minItems"] = json!(template_items.len());
            schema["maxItems"] = json!(template_items.len());
            let Some(schema_items) = schema.get_mut("items") else {
                return;
            };
            for template_item in template_items {
                apply_exact_array_lengths(schema_items, template_item);
            }
        }
        _ => {}
    }
}

fn refine_slot_schema<F>(schema: &mut Value, template: &Value, slot: &str, refine: &F)
where
    F: Fn(&mut Value),
{
    if template
        .as_str()
        .and_then(decode_slot)
        .is_some_and(|(name, _)| name == slot)
    {
        refine(schema);
        return;
    }
    match template {
        Value::Object(template_members) => {
            let Some(schema_members) = schema.get_mut("properties").and_then(Value::as_object_mut)
            else {
                return;
            };
            for (name, template_member) in template_members {
                if let Some(schema_member) = schema_members.get_mut(name) {
                    refine_slot_schema(schema_member, template_member, slot, refine);
                }
            }
        }
        Value::Array(template_items) => {
            let Some(schema_items) = schema.get_mut("items") else {
                return;
            };
            for template_item in template_items {
                refine_slot_schema(schema_items, template_item, slot, refine);
            }
        }
        _ => {}
    }
}

fn apply_records_array_maximum(
    schema: &mut Value,
    response_envelope: &str,
    maximum: u64,
) -> Result<(), ContractError> {
    let template = parse_envelope_template(response_envelope).map_err(ContractError::Schema)?;
    bound_records_slots(schema, &template, maximum);
    Ok(())
}

fn bound_records_slots(schema: &mut Value, template: &Value, maximum: u64) {
    match template {
        Value::String(text)
            if decode_slot(text).is_some_and(|(name, _)| name == SLOT_RECORDS)
                && schema.get("type").and_then(Value::as_str) == Some("array") =>
        {
            schema["maxItems"] = json!(maximum);
        }
        Value::Object(template) => {
            let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut)
            else {
                return;
            };
            for (name, member) in template {
                if let Some(member_schema) = properties.get_mut(name) {
                    bound_records_slots(member_schema, member, maximum);
                }
            }
        }
        Value::Array(template) => {
            let Some(item_schema) = schema.get_mut("items") else {
                return;
            };
            for member in template {
                bound_records_slots(item_schema, member, maximum);
            }
        }
        _ => {}
    }
}

fn protocol_problems() -> ProtocolProblems {
    ProtocolProblems {
        schema: json!({
            "$schema": JSON_SCHEMA_DIALECT,
            "oneOf": [
                protocol_problem_schema(
                    PIN_PROBLEM_CODE,
                    412,
                    "Effective contract precondition failed",
                ),
                protocol_problem_schema(
                    UNAVAILABLE_PROBLEM_CODE,
                    503,
                    "Effective contract unavailable",
                ),
            ],
        }),
        problems: vec![
            ProtocolProblem {
                code: PIN_PROBLEM_CODE,
                status: 412,
                title: "Effective contract precondition failed",
            },
            ProtocolProblem {
                code: UNAVAILABLE_PROBLEM_CODE,
                status: 503,
                title: "Effective contract unavailable",
            },
        ],
    }
}

fn protocol_problem_schema(code: &str, status: u16, title: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "code": {"const": code},
            "status": {"const": status},
            "title": {"const": title},
            "requestId": {
                "type": "string",
                "minLength": 32,
                "maxLength": 32,
                "pattern": REQUEST_ID_PATTERN,
            },
        },
        "required": ["code", "status", "title", "requestId"],
        "additionalProperties": false,
    })
}

#[cfg(test)]
mod contract_schema_tests {
    use super::*;

    #[test]
    fn effect_classification_is_explicit_and_conservative() {
        assert_eq!(operation_effect(HttpMethod::Get, false), "read");
        assert_eq!(operation_effect(HttpMethod::Post, true), "read");
        assert_eq!(operation_effect(HttpMethod::Post, false), "write");
        assert_eq!(operation_effect(HttpMethod::Put, true), "write");
        assert_eq!(operation_effect(HttpMethod::Patch, true), "write");
        assert_eq!(unserved_effect(None), "unknown");
    }

    #[test]
    fn integer_filter_bounds_are_exact_and_rfc8785_hashable() {
        let get = field_schema(RecordFieldType::Integer);
        assert_eq!(get["minimum"], i64::MIN);
        assert_eq!(get["exclusiveMaximum"], SIGNED_INTEGER_EXCLUSIVE_MAXIMUM);
        canonicalize_json(&get).expect("signed integer bounds canonicalize");

        let mut body = json!({
            "type": "object",
            "properties": {"count": {"type": "integer"}},
            "additionalProperties": false,
        });
        apply_filter_integer_bounds(
            &mut body,
            &[crate::read_request::ServedFilter {
                name: "count".to_owned(),
                field_type: RecordFieldType::Integer,
            }],
        );
        assert_eq!(body["properties"]["count"]["minimum"], i64::MIN);
        assert_eq!(
            body["properties"]["count"]["exclusiveMaximum"],
            JSON_INTEGER_EXCLUSIVE_MAXIMUM
        );
        canonicalize_json(&body).expect("full JSON integer bounds canonicalize");
    }

    #[test]
    fn pagination_bounds_only_the_records_projection() {
        let mut schema = json!({
            "type":"object",
            "properties":{
                "items":{"type":"array","items":{"type":"object"}},
                "fixed":{"type":"array","items":{"type":"string"}}
            }
        });
        apply_records_array_maximum(
            &mut schema,
            r#"{"items": {{records}}, "fixed": ["a", "b", "c"]}"#,
            2,
        )
        .expect("the envelope parses");
        assert_eq!(schema["properties"]["items"]["maxItems"], 2);
        assert!(schema["properties"]["fixed"].get("maxItems").is_none());
    }

    #[test]
    fn request_slot_refinement_follows_the_template_position() {
        let template =
            parse_envelope_template(r#"{"paging":{"size":"{{pageSize}}"},"pageSize":"literal"}"#)
                .expect("template");
        let mut schema = json!({
            "type":"object",
            "properties":{
                "paging":{"type":"object","properties":{"size":{"type":"integer"}}},
                "pageSize":{"type":"string","const":"literal"}
            }
        });
        refine_slot_schema(&mut schema, &template, "pageSize", &|member| {
            member["minimum"] = json!(1);
            member["maximum"] = json!(100);
        });
        assert_eq!(
            schema["properties"]["paging"]["properties"]["size"]["minimum"],
            1
        );
        assert!(schema["properties"]["pageSize"].get("minimum").is_none());
    }

    #[test]
    fn request_arrays_and_non_default_pagination_match_runtime_admission() {
        let template = parse_envelope_template(
            r#"{"wrapper":[{"cursor":"{{?cursor}}","limit":"{{?pageSize}}"}]}"#,
        )
        .expect("template");
        let mut schema = json!({
            "type": "object",
            "properties": {
                "wrapper": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cursor": {"type": "string"},
                            "limit": {"type": "integer"}
                        },
                        "required": [],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["wrapper"],
            "additionalProperties": false
        });
        apply_exact_array_lengths(&mut schema, &template);
        require_cursor_or_page_size(&mut schema, &template);
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("schema");

        assert_eq!(schema["properties"]["wrapper"]["minItems"], 1);
        assert_eq!(schema["properties"]["wrapper"]["maxItems"], 1);
        assert!(!validator.is_valid(&json!({"wrapper": [{}]})));
        assert!(!validator.is_valid(&json!({"wrapper": []})));
        assert!(validator.is_valid(&json!({"wrapper": [{"cursor": "sealed"}]})));
        assert!(validator.is_valid(&json!({"wrapper": [{"limit": 10}]})));
    }

    #[test]
    fn protocol_problem_schema_is_closed_and_status_specific() {
        let problems = protocol_problems();
        assert_eq!(problems.problems[0].code, PIN_PROBLEM_CODE);
        assert_eq!(problems.problems[0].status, 412);
        assert_eq!(problems.problems[1].code, UNAVAILABLE_PROBLEM_CODE);
        assert_eq!(problems.problems[1].status, 503);
        assert_eq!(
            problems.schema["oneOf"][0]["properties"]["code"]["const"],
            PIN_PROBLEM_CODE
        );
        assert_eq!(
            problems.schema["oneOf"][0]["properties"]["status"]["const"],
            412
        );
        assert_eq!(
            problems.schema["oneOf"][1]["properties"]["code"]["const"],
            UNAVAILABLE_PROBLEM_CODE
        );
        assert_eq!(
            problems.schema["oneOf"][1]["properties"]["status"]["const"],
            503
        );
        assert_eq!(
            problems.schema["oneOf"][0]["properties"]["requestId"]["pattern"],
            REQUEST_ID_PATTERN
        );
    }
}

/// The closed schema of the exported file and protected runtime readback.
/// `adapterctl schemas` writes this projection to the registered schema file.
#[must_use]
pub fn schema() -> Value {
    json!(
    {
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "https://id.registrystack.org/schemas/adapter/effective-contract/effective-contract.v1alpha1.schema.json",
      "title": "Registry Adapter effective contract",
      "type": "object",
      "properties": {
        "apiVersion": {
          "const": "id.registrystack.org/formats/adapter/effective-contract/v1alpha1"
        },
        "kind": {
          "const": "AdapterEffectiveContract"
        },
        "digest": {
          "$ref": "#/$defs/Digest"
        },
        "contract": {
          "$ref": "#/$defs/contract"
        },
        "readiness": {
          "$ref": "#/$defs/readiness"
        }
      },
      "required": [
        "apiVersion",
        "kind",
        "digest",
        "contract"
      ],
      "additionalProperties": false,
      "$defs": {
        "Digest": {
          "description": "A SHA-256 digest: `sha256:` followed by 64 lowercase hex digits.",
          "type": "string",
          "pattern": "^sha256:[0-9a-f]{64}$"
        },
        "DerivedId": {
          "description": "An identifier the runtime derives from local identifiers: two or more local identifiers joined by `.`. It is never authored.",
          "type": "string",
          "pattern": "^[a-z][a-z0-9_-]{0,63}(\\.[a-z][a-z0-9_-]{0,63})+$"
        },
        "LocalId": {
          "description": "A local identifier: a lowercase letter, then up to 63 lowercase letters, digits, `_`, or `-`.",
          "type": "string",
          "pattern": "^[a-z][a-z0-9_-]{0,63}$"
        },
        "nonEmptyText": {
          "type": "string",
          "minLength": 1
        },
        "jsonSchema": {
          "type": "object",
          "x-registry-passthrough": "The embedded JSON Schema document is governed by JSON Schema 2020-12."
        },
        "project": {
          "type": "object",
          "properties": {
            "id": {
              "$ref": "#/$defs/LocalId"
            },
            "version": {
              "type": "string"
            }
          },
          "required": [
            "id",
            "version"
          ],
          "additionalProperties": false
        },
        "authentication": {
          "type": "object",
          "properties": {
            "scheme": {
              "const": "bearer"
            },
            "audience": {
              "$ref": "#/$defs/nonEmptyText"
            },
            "clientAdmission": {
              "const": "allowlist"
            }
          },
          "required": [
            "scheme",
            "audience",
            "clientAdmission"
          ],
          "additionalProperties": false
        },
        "authority": {
          "type": "object",
          "properties": {
            "callerMode": {
              "const": "trusted-machine"
            },
            "representedSubject": {
              "const": "unsupported"
            },
            "personalDelegation": {
              "const": "unsupported"
            },
            "targetBinding": {
              "const": "unsupported"
            },
            "rowDisclosureAuthority": {
              "const": "not-granted"
            },
            "fieldDisclosureAuthority": {
              "const": "not-granted"
            }
          },
          "required": [
            "callerMode",
            "representedSubject",
            "personalDelegation",
            "targetBinding",
            "rowDisclosureAuthority",
            "fieldDisclosureAuthority"
          ],
          "additionalProperties": false
        },
        "scopeSet": {
          "type": "object",
          "properties": {
            "allScopes": {
              "type": "array",
              "items": {
                "$ref": "#/$defs/nonEmptyText"
              },
              "minItems": 1,
              "uniqueItems": true
            }
          },
          "required": [
            "allScopes"
          ],
          "additionalProperties": false
        },
        "access": {
          "type": "object",
          "properties": {
            "anyOf": {
              "type": "array",
              "items": {
                "$ref": "#/$defs/scopeSet"
              },
              "minItems": 1,
              "uniqueItems": true
            }
          },
          "required": [
            "anyOf"
          ],
          "additionalProperties": false
        },
        "input": {
          "type": "object",
          "properties": {
            "path": {
              "$ref": "#/$defs/jsonSchema"
            },
            "query": {
              "$ref": "#/$defs/jsonSchema"
            },
            "body": {
              "$ref": "#/$defs/jsonSchema"
            }
          },
          "required": [
            "path",
            "query"
          ],
          "additionalProperties": false
        },
        "operation": {
          "type": "object",
          "properties": {
            "id": {
              "$ref": "#/$defs/DerivedId"
            },
            "version": {
              "type": "string"
            },
            "bindingId": {
              "$ref": "#/$defs/LocalId"
            },
            "profileOperationId": {
              "$ref": "#/$defs/LocalId"
            },
            "method": {
              "type": "string",
              "pattern": "^(GET|POST)$"
            },
            "path": {
              "type": "string",
              "pattern": "^/"
            },
            "support": {
              "const": "served"
            },
            "effect": {
              "const": "read"
            },
            "successStatus": {
              "type": "integer",
              "minimum": 200,
              "maximum": 299
            },
            "requestMaximumBytes": {
              "type": "integer",
              "minimum": 1,
              "maximum": 1048576
            },
            "input": {
              "$ref": "#/$defs/input"
            },
            "output": {
              "$ref": "#/$defs/jsonSchema"
            },
            "access": {
              "$ref": "#/$defs/access"
            }
          },
          "required": [
            "id",
            "version",
            "bindingId",
            "profileOperationId",
            "method",
            "path",
            "support",
            "effect",
            "successStatus",
            "input",
            "output",
            "access"
          ],
          "additionalProperties": false
        },
        "unserved": {
          "type": "object",
          "properties": {
            "operationId": {
              "$ref": "#/$defs/nonEmptyText"
            },
            "version": {
              "type": "string"
            },
            "bindingId": {
              "$ref": "#/$defs/LocalId"
            },
            "profileOperationId": {
              "$ref": "#/$defs/LocalId"
            },
            "method": {
              "type": "string",
              "description": "A case-sensitive HTTP method token from RFC 9110.",
              "pattern": "^(GET|POST|PUT|PATCH)$"
            },
            "support": {
              "const": "unserved"
            },
            "effect": {
              "enum": [
                "read",
                "write",
                "unknown"
              ]
            },
            "reasonCode": {
              "type": "string",
              "pattern": "^adapter\\.[a-z0-9.-]+$"
            },
            "reason": {
              "$ref": "#/$defs/nonEmptyText"
            }
          },
          "required": [
            "operationId",
            "version",
            "bindingId",
            "profileOperationId",
            "support",
            "effect",
            "reasonCode",
            "reason"
          ],
          "additionalProperties": false
        },
        "contract": {
          "type": "object",
          "properties": {
            "schemaDialect": {
              "const": "https://json-schema.org/draft/2020-12/schema"
            },
            "project": {
              "$ref": "#/$defs/project"
            },
            "profileVersion": {
              "type": "string"
            },
            "artifactDeploymentDigest": {
              "$ref": "#/$defs/Digest"
            },
            "authentication": {
              "$ref": "#/$defs/authentication"
            },
            "authority": {
              "$ref": "#/$defs/authority"
            },
            "operations": {
              "type": "array",
              "items": {
                "$ref": "#/$defs/operation"
              }
            },
            "unserved": {
              "type": "array",
              "items": {
                "$ref": "#/$defs/unserved"
              }
            },
            "problemSchema": {
              "$ref": "#/$defs/jsonSchema"
            },
            "protocolProblems": {
              "$ref": "#/$defs/protocolProblems"
            }
          },
          "required": [
            "schemaDialect",
            "project",
            "profileVersion",
            "artifactDeploymentDigest",
            "authentication",
            "authority",
            "operations",
            "unserved",
            "problemSchema",
            "protocolProblems"
          ],
          "additionalProperties": false
        },
        "protocolProblems": {
          "type": "object",
          "properties": {
            "schema": {
              "$ref": "#/$defs/jsonSchema"
            },
            "problems": {
              "type": "array",
              "prefixItems": [
                {
                  "type": "object",
                  "properties": {
                    "code": {
                      "const": "adapter.contract.precondition-failed"
                    },
                    "status": {
                      "const": 412
                    },
                    "title": {
                      "const": "Effective contract precondition failed"
                    }
                  },
                  "required": ["code", "status", "title"],
                  "additionalProperties": false
                },
                {
                  "type": "object",
                  "properties": {
                    "code": {
                      "const": "adapter.contract.unavailable"
                    },
                    "status": {
                      "const": 503
                    },
                    "title": {
                      "const": "Effective contract unavailable"
                    }
                  },
                  "required": ["code", "status", "title"],
                  "additionalProperties": false
                }
              ],
              "items": false,
              "minItems": 2,
              "maxItems": 2,
              "uniqueItems": true
            }
          },
          "required": [
            "schema",
            "problems"
          ],
          "additionalProperties": false
        },
        "readiness": {
          "type": "object",
          "properties": {
            "ready": {
              "const": true
            },
            "configuration": {
              "const": "ready"
            },
            "journal": {
              "const": "ready"
            }
          },
          "required": [
            "ready",
            "configuration",
            "journal"
          ],
          "additionalProperties": false
        }
      }
    }
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeContractResponse<'a> {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub digest: &'a str,
    pub contract: &'a EffectiveContractBody,
    pub readiness: RuntimeReadiness,
}

#[derive(Serialize)]
pub struct RuntimeReadiness {
    pub ready: bool,
    pub configuration: &'static str,
    pub journal: &'static str,
}

impl<'a> RuntimeContractResponse<'a> {
    pub fn ready(contract: &'a EffectiveContract) -> Self {
        Self {
            api_version: contract.api_version,
            kind: contract.kind,
            digest: &contract.digest,
            contract: &contract.contract,
            readiness: RuntimeReadiness {
                ready: true,
                configuration: "ready",
                journal: "ready",
            },
        }
    }
}
