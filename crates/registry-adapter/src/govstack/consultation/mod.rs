// SPDX-License-Identifier: Apache-2.0

//! Fixed protocol catalogue for the built-in GovStack Digital Registries
//! Consultation facade. Deployment projects supply Registry, collection,
//! view, schemas and source bindings; these definitions own the wire names.

use registry_adapter_core::{
    AdapterPack, AdapterProfile, AdapterProject, HttpMethod, SourceReadSupport,
    MAXIMUM_ITEM_KEY_BYTES,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

mod openapi;
pub use openapi::{assemble_openapi, OpenApiError, OpenApiSchema};

pub const MOUNT_PATH: &str = "/govstack/registries";
pub const CAPABILITIES_PATH: &str = "/v1/capabilities";
pub const SERVICE_UNAVAILABLE_PROBLEM_CODE: &str =
    "https://govstack.global/problems/digital-registries/service-unavailable";
pub const MAX_COLLECTIONS: usize = 64;
pub const MAX_OPERATIONS_PER_COLLECTION: usize = 16;
pub const MAXIMUM_RECORD_ID_CHARACTERS: usize = 256;
pub const PROFILE_ID: &str = "govstack-consultation";
pub const PROFILE_VERSION: &str = "1.0.0-draft";

#[must_use]
pub fn valid_collection_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[must_use]
pub(crate) fn valid_view_id(value: &str) -> bool {
    valid_collection_id(value)
}

/// The internal profile used only to reuse the existing facade execution,
/// admission, problem, cursor and journal machinery. Deployments never pin
/// or author these standard paths and envelopes.
#[must_use]
pub fn built_in_profile() -> AdapterProfile {
    serde_json::from_value(json!({
        "id": PROFILE_ID,
        "version": PROFILE_VERSION,
        "operations": [
            {"id":"retrieve","method":"GET","path":"/v1/collections/{collection_id}/records/{record_id}","pathParameters":["collection_id","record_id"],"recordTypeParameter":"collection_id","recordIdParameter":"record_id","itemEnvelope":r#"{"recordId":"{{recordId}}","data":{{record}}}"#,"responseEnvelope":"{{record}}"},
            {"id":"lookup","method":"POST","readOnly":true,"path":"/v1/collections/{collection_id}/lookup","pathParameters":["collection_id"],"recordTypeParameter":"collection_id","requestEnvelope":r#"{"selector":"project-selected","values":{{filters}}}"#,"itemEnvelope":r#"{"recordId":"{{recordId}}","data":{{record}}}"#,"responseEnvelope":"{{record}}"},
            {"id":"list","method":"GET","path":"/v1/collections/{collection_id}/records","pathParameters":["collection_id"],"recordTypeParameter":"collection_id","itemEnvelope":r#"{"recordId":"{{recordId}}","data":{{record}}}"#,"responseEnvelope":r#"{"items":{{records}},"pageInfo":{"nextCursor":{{??nextCursor}}}}"#,"pagination":{"cursorParameter":"cursor","pageSizeParameter":"pageSize","pageSizeMinimum":1,"pageSizeMaximum":100,"pageSizeDefault":20}},
            {"id":"search","method":"POST","readOnly":true,"path":"/v1/collections/{collection_id}/search","pathParameters":["collection_id"],"recordTypeParameter":"collection_id","requestEnvelope":r#"{"search":"project-selected","criteria":{{filters}},"pageSize":{{?pageSize}},"cursor":{{?cursor}}}"#,"itemEnvelope":r#"{"recordId":"{{recordId}}","data":{{record}}}"#,"responseEnvelope":r#"{"items":{{records}},"pageInfo":{"nextCursor":{{??nextCursor}}}}"#,"pagination":{"cursorParameter":"cursor","pageSizeParameter":"pageSize","pageSizeMinimum":1,"pageSizeMaximum":100,"pageSizeDefault":20}}
        ],
        "problems": [
            {"code":"https://govstack.global/problems/digital-registries/bad-request","status":400,"title":"the request is not valid","classes":["outcome.conflict","outcome.rejected","facade.invalid-request","facade.method-not-allowed","facade.conflict","facade.idempotency-mismatch"]},
            {"code":"https://govstack.global/problems/digital-registries/unauthorized","status":401,"title":"the request carries no valid credential","classes":["facade.unauthenticated"]},
            {"code":"https://govstack.global/problems/digital-registries/forbidden","status":403,"title":"the caller may not make this request","classes":["facade.forbidden"]},
            {"code":"https://govstack.global/problems/digital-registries/collection-not-available","status":404,"title":"the collection is not available","classes":["facade.not-found"]},
            {"code":"https://govstack.global/problems/digital-registries/record-not-available","status":404,"title":"the record is not available","classes":["outcome.not-found"]},
            {"code":"https://govstack.global/problems/digital-registries/not-acceptable","status":406,"title":"the reply cannot be given in an accepted media type","classes":["facade.not-acceptable"]},
            {"code":"https://govstack.global/problems/digital-registries/content-too-large","status":413,"title":"the request body is too large","classes":["facade.payload-too-large"]},
            {"code":"https://govstack.global/problems/digital-registries/unsupported-media-type","status":415,"title":"the request body is not in a supported media type","classes":["facade.unsupported-media-type"]},
            {"code":"https://govstack.global/problems/digital-registries/invalid-field","status":422,"title":"a request field is not valid","classes":["outcome","outcome.invalid-request","facade.invalid-field"]},
            {"code":"https://govstack.global/problems/digital-registries/invalid-cursor","status":400,"title":"the cursor is not valid","classes":["facade.invalid-cursor"]},
            {"code":"https://govstack.global/problems/digital-registries/too-many-requests","status":429,"title":"the source is throttling requests","classes":["throttle.rejected"]},
            {"code":"https://govstack.global/problems/digital-registries/internal-error","status":500,"title":"the request could not be served","classes":["facade","loop.maximum-iterations-reached","validation","conversion.unmapped","aggregation.duplicate","script","script.budget-exceeded","budget.exhausted","credential.rejected","disclosure.violation","egress.refused"]},
            {"code":"https://govstack.global/problems/digital-registries/bad-gateway","status":502,"title":"the source answered with an error","classes":["upstream"]},
            {"code":"https://govstack.global/problems/digital-registries/service-unavailable","status":503,"title":"the circuit protecting the source is open","classes":["breaker.open"]},
            {"code":"https://govstack.global/problems/digital-registries/gateway-timeout","status":504,"title":"the source did not answer in time","classes":["upstream.timeout"]}
        ],
        "problemEnvelope": r#"{"type":"{{problemCode}}","title":"{{problemTitle}}","status":{{status}},"detail":"{{?problemDetail}}","traceId":"{{requestId}}","errors":{{?problemErrors}}}"#,
        "parameterizedParts": []
    }))
    .expect("the maintained Consultation profile is valid")
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsultationCapability {
    Retrieve,
    Lookup,
    List,
    Search,
}

impl ConsultationCapability {
    #[must_use]
    pub const fn binding_operation(self) -> &'static str {
        match self {
            Self::Retrieve => "retrieve",
            Self::Lookup => "lookup",
            Self::List => "list",
            Self::Search => "search",
        }
    }

    #[must_use]
    pub const fn method(self) -> HttpMethod {
        match self {
            Self::Retrieve | Self::List => HttpMethod::Get,
            Self::Lookup | Self::Search => HttpMethod::Post,
        }
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Retrieve => "/v1/collections/{collectionId}/records/{recordId}",
            Self::Lookup => "/v1/collections/{collectionId}/lookup",
            Self::List => "/v1/collections/{collectionId}/records",
            Self::Search => "/v1/collections/{collectionId}/search",
        }
    }

    /// Equivalent router template using Adapter's internal local-id
    /// parameter spelling. Placeholder names are not wire path segments;
    /// generated OpenAPI uses [`Self::path`] with canonical GovStack names.
    #[must_use]
    pub const fn runtime_path(self) -> &'static str {
        match self {
            Self::Retrieve => "/v1/collections/{collection_id}/records/{record_id}",
            Self::Lookup => "/v1/collections/{collection_id}/lookup",
            Self::List => "/v1/collections/{collection_id}/records",
            Self::Search => "/v1/collections/{collection_id}/search",
        }
    }

    #[must_use]
    pub fn from_binding_operation(operation: &str) -> Option<Self> {
        match operation {
            "retrieve" => Some(Self::Retrieve),
            "lookup" => Some(Self::Lookup),
            "list" => Some(Self::List),
            "search" => Some(Self::Search),
            _ => None,
        }
    }

    #[must_use]
    pub fn operation_id(self, collection: &str) -> String {
        let mut id = self.binding_operation().to_owned();
        for part in collection.split(['-', '_']).filter(|part| !part.is_empty()) {
            let mut characters = part.chars();
            if let Some(first) = characters.next() {
                id.extend(first.to_uppercase());
                id.extend(characters);
            }
        }
        id
    }
}

/// The per-collection request template compiled into the served operation.
/// Named inputs are literals owned by the project; values and criteria use
/// the existing bounded filter capture until the initial scalar-equality
/// input surface grows deliberately.
#[must_use]
pub fn request_envelope(
    capability: ConsultationCapability,
    selector_or_search: Option<&str>,
) -> Option<String> {
    match capability {
        ConsultationCapability::Retrieve | ConsultationCapability::List => None,
        ConsultationCapability::Lookup => selector_or_search
            .map(|selector| json!({"selector": selector, "values": "{{filters}}"}).to_string()),
        ConsultationCapability::Search => selector_or_search.map(|search| {
            json!({
                "search": search,
                "criteria": "{{filters}}",
                "pageSize": "{{?pageSize}}",
                "cursor": "{{?cursor}}"
            })
            .to_string()
        }),
    }
}

/// Fixed GovStack Record schema around one project-owned data schema.
#[must_use]
pub fn record_schema(data_schema_reference: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordId", "data"],
        "properties": {
            "recordId": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAXIMUM_RECORD_ID_CHARACTERS,
            },
            "data": {"$ref": data_schema_reference},
        },
    })
}

/// Fixed GovStack RecordPage schema using the same Record view.
#[must_use]
pub fn record_page_schema(data_schema_reference: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["items", "pageInfo"],
        "properties": {
            "items": {
                "type": "array",
                "maxItems": 100,
                "items": record_schema(data_schema_reference),
            },
            "pageInfo": {
                "type": "object",
                "additionalProperties": false,
                "required": ["nextCursor"],
                "properties": {
                    "nextCursor": {
                        "anyOf": [
                            crate::engine::effective_contract::cursor_schema(),
                            {"type": "null"},
                        ],
                    },
                },
            },
        },
    })
}

/// Fixed exact-Lookup request around one project-owned scalar input schema.
#[must_use]
pub fn lookup_request_schema(selector: &str, input_schema_reference: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["selector", "values"],
        "properties": {
            "selector": {"const": selector},
            "values": {"$ref": input_schema_reference},
        },
    })
}

/// Fixed named-Search request around one project-owned scalar-equality
/// criteria schema. Pagination controls remain host owned.
#[must_use]
pub fn search_request_schema(search: &str, input_schema_reference: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["search", "criteria"],
        "properties": {
            "search": {"const": search},
            "criteria": {"$ref": input_schema_reference},
            "pageSize": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            "cursor": crate::engine::effective_contract::cursor_schema(),
        },
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallerCapabilities {
    pub collections: Vec<CapabilityCollection>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityCollection {
    pub collection_id: String,
    pub registry: String,
    pub operations: Vec<CapabilityOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityOperation {
    pub operation_id: String,
    pub contract: String,
    pub family: CapabilityFamily,
    pub capability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<DiscoveredWriteMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub searches: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityFamily {
    Consultation,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredWriteMetadata {
    pub companion_read: CompanionReadIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanionReadIdentity {
    pub operation_id: String,
    pub view: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CapabilityError {
    #[error("the caller-visible capability document exceeds its collection bound")]
    TooManyCollections,
    #[error("one caller-visible collection exceeds its operation bound")]
    TooManyOperations,
    #[error("caller-visible capability metadata is contradictory")]
    Contradictory,
}

pub fn validate_capabilities(document: &CallerCapabilities) -> Result<(), CapabilityError> {
    if document.collections.len() > MAX_COLLECTIONS {
        return Err(CapabilityError::TooManyCollections);
    }
    let mut collections = BTreeSet::new();
    let mut operations = BTreeSet::new();
    for collection in &document.collections {
        if !valid_collection_id(&collection.collection_id)
            || !collections.insert(collection.collection_id.as_str())
        {
            return Err(CapabilityError::Contradictory);
        }
        if collection.operations.is_empty()
            || collection.operations.len() > MAX_OPERATIONS_PER_COLLECTION
        {
            return Err(CapabilityError::TooManyOperations);
        }
        let mut capabilities = BTreeSet::new();
        for operation in &collection.operations {
            let expected_operation = discovered_operation_id(
                operation.capability.as_str(),
                collection.collection_id.as_str(),
            );
            if expected_operation.as_deref() != Some(operation.operation_id.as_str())
                || !capabilities.insert(operation.capability.as_str())
                || !operations.insert(operation.operation_id.as_str())
            {
                return Err(CapabilityError::Contradictory);
            }
            let named_input_is_consistent = match operation.capability.as_str() {
                "lookup" => operation.selectors.len() == 1 && operation.searches.is_empty(),
                "search" => operation.searches.len() == 1 && operation.selectors.is_empty(),
                "retrieve" | "list" | "create" | "update" => {
                    operation.selectors.is_empty() && operation.searches.is_empty()
                }
                _ => false,
            };
            let annotations_are_consistent = match operation.family {
                CapabilityFamily::Consultation => {
                    operation.view.as_deref().is_some_and(valid_view_id)
                        && operation.write.is_none()
                }
                CapabilityFamily::Write if operation.capability == "update" => operation
                    .write
                    .as_ref()
                    .is_some_and(|write| valid_view_id(&write.companion_read.view)),
                CapabilityFamily::Write => operation.view.is_none() && operation.write.is_none(),
            };
            if !named_input_is_consistent || !annotations_are_consistent {
                return Err(CapabilityError::Contradictory);
            }
        }
    }
    Ok(())
}

/// Derive the bounded caller-visible capability document. The facade host
/// supplies the current authorization decision for each already-served
/// operation; this target owns all protocol names and annotations.
pub fn caller_capabilities(
    project: &AdapterProject,
    served_operations: &[crate::engine::load::ServedOperation],
    mut admitted: impl FnMut(&crate::engine::load::ServedOperation) -> bool,
) -> Result<CallerCapabilities, CapabilityError> {
    if project.consultation.is_none() && project.write.is_none() {
        return Ok(CallerCapabilities {
            collections: Vec::new(),
            operations: Vec::new(),
        });
    }
    let consultation = project.consultation.as_ref();
    let write = project.write.as_ref();
    let record_types: BTreeSet<&str> = consultation
        .into_iter()
        .flat_map(|target| {
            target
                .collections
                .iter()
                .map(|entry| entry.record_type.as_str())
        })
        .chain(write.into_iter().flat_map(|target| {
            target
                .collections
                .iter()
                .map(|entry| entry.record_type.as_str())
        }))
        .collect();
    let mut collections = Vec::new();
    for record_type in record_types {
        let declared = consultation.and_then(|target| target.collections.get(record_type));
        let write_collection = write.and_then(|target| target.collections.get(record_type));
        let resolved = write_collection.and_then(|_| {
            crate::govstack::write::metadata::collection_metadata(project, record_type).ok()
        });
        let registry = declared
            .map(|collection| collection.registry.as_str())
            .or_else(|| resolved.as_ref().map(|metadata| metadata.registry))
            .ok_or(CapabilityError::Contradictory)?;
        let mut operations = Vec::new();
        for served in served_operations
            .iter()
            .filter(|served| served.record_type == record_type)
        {
            if !admitted(served) {
                continue;
            }
            if let Some(capability) =
                ConsultationCapability::from_binding_operation(&served.operation).or_else(|| {
                    (served.operation == "writable-read")
                        .then_some(ConsultationCapability::Retrieve)
                })
            {
                let view = declared
                    .map(|collection| collection.view.as_str())
                    .or_else(|| resolved.as_ref().and_then(|metadata| metadata.view))
                    .ok_or(CapabilityError::Contradictory)?;
                let (selectors, searches) = match capability {
                    ConsultationCapability::Lookup => (
                        declared
                            .and_then(|collection| collection.lookup.as_ref())
                            .map(|lookup| vec![lookup.selector.as_str().to_owned()])
                            .unwrap_or_default(),
                        Vec::new(),
                    ),
                    ConsultationCapability::Search => (
                        Vec::new(),
                        declared
                            .and_then(|collection| collection.search.as_ref())
                            .map(|search| vec![search.search.as_str().to_owned()])
                            .unwrap_or_default(),
                    ),
                    ConsultationCapability::Retrieve | ConsultationCapability::List => {
                        (Vec::new(), Vec::new())
                    }
                };
                operations.push(CapabilityOperation {
                    operation_id: capability.operation_id(record_type),
                    contract: if served.operation == "writable-read" {
                        resolved.as_ref().map(|metadata| metadata.contract)
                    } else {
                        consultation.map(|target| target.contract.as_str())
                    }
                    .ok_or(CapabilityError::Contradictory)?
                    .to_owned(),
                    family: CapabilityFamily::Consultation,
                    capability: capability.binding_operation().to_owned(),
                    view: Some(view.to_owned()),
                    write: None,
                    selectors,
                    searches,
                });
                continue;
            }
            let Some(capability) =
                crate::govstack::write::attachment::WriteCapability::from_binding_operation(
                    &served.operation,
                )
            else {
                continue;
            };
            let selected = match capability {
                crate::govstack::write::attachment::WriteCapability::Create => {
                    write_collection.is_some_and(|collection| collection.create.is_some())
                }
                crate::govstack::write::attachment::WriteCapability::Update => {
                    write_collection.is_some_and(|collection| collection.update.is_some())
                }
            };
            if !selected {
                continue;
            }
            let write_metadata = if capability
                == crate::govstack::write::attachment::WriteCapability::Update
            {
                let view = resolved
                    .as_ref()
                    .and_then(|metadata| metadata.view)
                    .ok_or(CapabilityError::Contradictory)?;
                Some(DiscoveredWriteMetadata {
                    companion_read: CompanionReadIdentity {
                        operation_id: ConsultationCapability::Retrieve.operation_id(record_type),
                        view: view.to_owned(),
                    },
                })
            } else {
                None
            };
            operations.push(CapabilityOperation {
                operation_id: capability.operation_id(record_type),
                contract: resolved
                    .as_ref()
                    .map(|metadata| metadata.contract.to_owned())
                    .ok_or(CapabilityError::Contradictory)?,
                family: CapabilityFamily::Write,
                capability: capability.binding_operation().to_owned(),
                view: None,
                write: write_metadata,
                selectors: Vec::new(),
                searches: Vec::new(),
            });
        }
        if !operations.is_empty() {
            collections.push(CapabilityCollection {
                collection_id: record_type.to_owned(),
                registry: registry.to_owned(),
                operations,
            });
        }
    }
    let document = CallerCapabilities {
        collections,
        operations: Vec::new(),
    };
    validate_capabilities(&document)?;
    Ok(document)
}

fn discovered_operation_id(capability: &str, collection: &str) -> Option<String> {
    ConsultationCapability::from_binding_operation(capability)
        .map(|capability| capability.operation_id(collection))
        .or_else(|| {
            crate::govstack::write::attachment::WriteCapability::from_binding_operation(capability)
                .map(|capability| capability.operation_id(collection))
        })
}

#[must_use]
pub fn validation_pointer(operation: &str) -> &'static str {
    match operation {
        "lookup" => "/values",
        "search" => "/criteria",
        "create" | "update" => "/data",
        _ => "/request",
    }
}

#[must_use]
pub fn service_unavailable_problem(request_id: &str) -> Value {
    json!({
        "type": SERVICE_UNAVAILABLE_PROBLEM_CODE,
        "title": "the service is unavailable",
        "status": 503,
        "traceId": request_id,
    })
}

/// Compile the fixed target against the exact project and pack the generic
/// engine will load. Every operation receives explicit input, projection and
/// effective-contract metadata before it can be served.
pub fn target_attachment(
    project: &AdapterProject,
    pack: &AdapterPack,
    project_directory: &Path,
) -> Result<crate::engine::target::TargetAttachment, crate::engine::load::LoadError> {
    if project.consultation.is_none() && project.write.is_none() {
        return Err(crate::engine::load::LoadError::Runtime(
            "the GovStack target metadata is unavailable".to_owned(),
        ));
    }
    let consultation = project.consultation.as_ref();
    let profile = crate::govstack::built_in_profile(project);
    let mut operations = BTreeMap::new();
    for binding in project.bindings.iter() {
        let ordinary_capability =
            ConsultationCapability::from_binding_operation(&binding.operation);
        let capability = match ordinary_capability {
            Some(capability) => capability,
            None if binding.operation.as_str() == "writable-read" => {
                ConsultationCapability::Retrieve
            }
            None => continue,
        };
        if !valid_collection_id(binding.record_type.as_str()) {
            return Err(crate::engine::load::LoadError::Runtime(
                "a GovStack collection id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters"
                    .to_owned(),
            ));
        }
        let consultation_collection =
            consultation.and_then(|target| target.collections.get(binding.record_type.as_str()));
        let view = consultation_collection
            .map(|collection| collection.view.as_str())
            .or_else(|| {
                project
                    .write
                    .as_ref()
                    .and_then(|target| target.collections.get(binding.record_type.as_str()))
                    .and_then(|collection| collection.view.as_deref())
            })
            .ok_or_else(|| {
                crate::engine::load::LoadError::Runtime(
                    "the GovStack public view metadata is unavailable".to_owned(),
                )
            })?;
        if !valid_view_id(view) {
            return Err(crate::engine::load::LoadError::Runtime(
                "a GovStack view id must start with a lowercase letter and contain only lowercase letters, digits, and hyphens, with at most 128 characters"
                    .to_owned(),
            ));
        }
        let data_schema = if ordinary_capability.is_some() {
            consultation_collection
                .map(|collection| collection.data_schema.as_str())
                .ok_or_else(|| {
                    crate::engine::load::LoadError::Runtime(format!(
                        "binding {} names no GovStack Consultation collection",
                        binding.id
                    ))
                })?
        } else {
            crate::govstack::write::metadata::collection_metadata(
                project,
                binding.record_type.as_str(),
            )
            .ok()
            .and_then(|metadata| metadata.read_data_schema)
            .ok_or_else(|| {
                crate::engine::load::LoadError::Runtime(format!(
                    "binding {} has no writable companion-read schema",
                    binding.id
                ))
            })?
        };
        let templated = project
            .templated_routes
            .get(binding.route.as_str())
            .ok_or_else(|| {
                crate::engine::load::LoadError::Runtime(format!(
                    "binding {} must select an instantiated route template",
                    binding.id
                ))
            })?;
        let template = pack
            .route_templates
            .get(templated.route_template.as_str())
            .ok_or_else(|| {
                crate::engine::load::LoadError::Runtime(format!(
                    "binding {} names no reusable source route template",
                    binding.id
                ))
            })?;
        let support = template.read_support.clone().ok_or_else(|| {
            crate::engine::load::LoadError::Runtime(format!(
                "binding {} selects a route template with no declared read support",
                binding.id
            ))
        })?;
        let source_input = source_input(capability, &support).ok_or_else(|| {
            crate::engine::load::LoadError::Runtime(format!(
                "binding {} selects incompatible source read support",
                binding.id
            ))
        })?;
        let (selected_input, input_schema_id, input_shape) = match capability {
            ConsultationCapability::Lookup => {
                let lookup = consultation_collection
                    .and_then(|collection| collection.lookup.as_ref())
                    .ok_or_else(|| {
                        crate::engine::load::LoadError::Runtime(format!(
                            "binding {} has no Consultation Lookup metadata",
                            binding.id
                        ))
                    })?;
                (
                    Some(lookup.selector.as_str()),
                    Some(lookup.input_schema.as_str()),
                    Some(crate::engine::load::TargetInputShape::ReadOne),
                )
            }
            ConsultationCapability::Search => {
                let search = consultation_collection
                    .and_then(|collection| collection.search.as_ref())
                    .ok_or_else(|| {
                        crate::engine::load::LoadError::Runtime(format!(
                            "binding {} has no Consultation Search metadata",
                            binding.id
                        ))
                    })?;
                (
                    Some(search.search.as_str()),
                    Some(search.input_schema.as_str()),
                    Some(crate::engine::load::TargetInputShape::ReadPageEquality),
                )
            }
            ConsultationCapability::Retrieve | ConsultationCapability::List => (None, None, None),
        };
        let (filters, project_input_schema) = match (input_schema_id, input_shape) {
            (Some(schema_id), Some(shape)) => {
                let (filters, schema) = crate::engine::load::compile_target_input_filters(
                    project,
                    schema_id,
                    &support,
                    shape,
                    project_directory,
                )
                .map_err(|_| {
                    crate::engine::load::LoadError::Runtime(format!(
                        "binding {} Consultation input schema was refused",
                        binding.id
                    ))
                })?;
                (filters, Some(schema))
            }
            (None, None) => (Vec::new(), None),
            _ => unreachable!("a named input carries its schema and shape together"),
        };
        let request_template = request_envelope(capability, selected_input)
            .map(|template| crate::engine::read_request::ReadRequestTemplate::compile(&template))
            .transpose()
            .map_err(|_| {
                crate::engine::load::LoadError::Runtime(format!(
                    "binding {} has an unusable Consultation request contract",
                    binding.id
                ))
            })?;
        let transform = Arc::new(
            crate::engine::project_transform::CompiledProjectTransform::compile_from_directory(
                project,
                binding.id.as_str(),
                data_schema,
                project_directory,
            )
            .map_err(|_| {
                crate::engine::load::LoadError::Runtime(format!(
                    "binding {} project transformation was refused",
                    binding.id
                ))
            })?,
        );
        let declared = profile
            .operations
            .get(binding.operation.as_str())
            .expect("the fixed capability has a fixed profile operation");
        let pagination =
            declared
                .pagination
                .as_ref()
                .map(|pagination| crate::engine::load::ServedPagination {
                    cursor_parameter: pagination.cursor_parameter.as_str().to_owned(),
                    page_size_parameter: pagination.page_size_parameter.as_str().to_owned(),
                    page_size_minimum: pagination.page_size_minimum.get(),
                    page_size_maximum: pagination.page_size_maximum.get(),
                    page_size_default: pagination.page_size_default.map(|value| value.get()),
                });
        let request_body = effective_request_schema(
            capability,
            selected_input,
            project_input_schema.as_deref(),
            pagination.as_ref(),
        )?;
        let response_body =
            effective_response_schema(capability, transform.schema(), pagination.as_ref())?;
        let path = format!(
            "{}{}",
            MOUNT_PATH,
            capability
                .path()
                .replace("{collectionId}", binding.record_type.as_str())
        );
        let path_parameters = match capability {
            ConsultationCapability::Retrieve => {
                let mut record_id = crate::engine::effective_contract::path_segment_schema();
                record_id["maxLength"] = json!(MAXIMUM_RECORD_ID_CHARACTERS);
                json!({
                    "type": "object",
                    "properties": {"recordId": record_id},
                    "required": ["recordId"],
                    "additionalProperties": false
                })
            }
            ConsultationCapability::Lookup
            | ConsultationCapability::List
            | ConsultationCapability::Search => json!({
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": false
            }),
        };
        let operation = crate::engine::target::TargetOperation::Read(Box::new(
            crate::engine::target::TargetReadOperation {
                filters,
                request_template,
                project_input_schema,
                project_transform: transform,
                read_support: support,
                source_input,
                item_projection: crate::engine::target::ItemProjection {
                    record_id_member: "recordIdentifier".to_owned(),
                    value_member: "domainData".to_owned(),
                    revision_member: Some("revisionIdentifier".to_owned()),
                    maximum_record_id_bytes: MAXIMUM_ITEM_KEY_BYTES,
                    maximum_record_id_characters: MAXIMUM_RECORD_ID_CHARACTERS,
                },
                effective_contract: crate::engine::target::EffectiveContractOperation {
                    path,
                    path_parameters,
                    request_body,
                    response_body,
                },
            },
        ));
        if operations
            .insert(binding.id.as_str().to_owned(), operation)
            .is_some()
        {
            return Err(crate::engine::load::LoadError::Runtime(format!(
                "duplicate target attachment for binding {}",
                binding.id
            )));
        }
    }
    let identity = target_identity(&profile, &operations)?;
    Ok(crate::engine::target::TargetAttachment {
        profile,
        identity,
        operations,
    })
}

fn target_identity(
    profile: &AdapterProfile,
    operations: &BTreeMap<String, crate::engine::target::TargetOperation>,
) -> Result<Vec<u8>, crate::engine::load::LoadError> {
    let mut identity_operations = Vec::with_capacity(operations.len());
    for (binding, operation) in operations {
        let crate::engine::target::TargetOperation::Read(operation) = operation else {
            return Err(crate::engine::load::LoadError::Runtime(
                "the Consultation target identity accepts read operations only".to_owned(),
            ));
        };
        identity_operations.push(json!({
            "binding": binding,
            "sourceInput": operation.source_input,
            "itemProjection": operation.item_projection,
            "readSupport": operation.read_support,
            "inputSchema": operation
                .project_input_schema
                .as_ref()
                .map(|schema| schema.as_value()),
            "outputSchema": operation.project_transform.schema().as_value(),
            "effectivePath": operation.effective_contract.path,
            "effectivePathParameters": operation.effective_contract.path_parameters,
            "effectiveRequest": operation.effective_contract.request_body,
            "effectiveResponse": operation.effective_contract.response_body,
        }));
    }
    let identity_value = json!({
        "domain": "registry-adapter:host-target:v1",
        "mount": MOUNT_PATH,
        "profile": profile,
        "operations": identity_operations,
    });
    registry_platform_canonical_json::canonicalize_json(&identity_value).map_err(|_| {
        crate::engine::load::LoadError::Runtime(
            "the fixed target identity could not be serialized".to_owned(),
        )
    })
}

#[must_use]
pub fn source_input(
    capability: ConsultationCapability,
    support: &SourceReadSupport,
) -> Option<crate::engine::target::SourceInput> {
    let input = match (capability, support) {
        (ConsultationCapability::Retrieve, SourceReadSupport::ReadOne { inputs })
            if inputs.len() == 1 =>
        {
            crate::engine::target::SourceInput::RecordId {
                header: "recordId".to_owned(),
                source_input: inputs[0].as_str().to_owned(),
            }
        }
        (ConsultationCapability::Lookup, SourceReadSupport::ReadOne { .. })
        | (ConsultationCapability::Search, SourceReadSupport::ReadPage { .. }) => {
            crate::engine::target::SourceInput::Filters
        }
        (ConsultationCapability::List, SourceReadSupport::ReadPage { inputs, .. })
            if inputs.is_empty() =>
        {
            crate::engine::target::SourceInput::EmptyObject
        }
        _ => {
            return None;
        }
    };
    Some(input)
}

fn effective_request_schema(
    capability: ConsultationCapability,
    selected: Option<&str>,
    input: Option<&crate::engine::public_schema::CheckedPublicSchema>,
    pagination: Option<&crate::engine::load::ServedPagination>,
) -> Result<Option<Value>, crate::engine::load::LoadError> {
    let Some(selected) = selected else {
        return Ok(None);
    };
    let input = input.ok_or_else(|| {
        crate::engine::load::LoadError::Runtime(
            "a named target input has no checked schema".to_owned(),
        )
    })?;
    let reference = "#/$defs/projectInput";
    let mut schema = match capability {
        ConsultationCapability::Lookup => lookup_request_schema(selected, reference),
        ConsultationCapability::Search => {
            let pagination = pagination.ok_or_else(|| {
                crate::engine::load::LoadError::Runtime(
                    "the target Search contract has no pagination declaration".to_owned(),
                )
            })?;
            let mut schema = search_request_schema(selected, reference);
            schema["properties"]["pageSize"] = json!({
                "type": "integer",
                "minimum": pagination.page_size_minimum,
                "maximum": pagination.page_size_maximum,
            });
            if let Some(default) = pagination.page_size_default {
                schema["properties"]["pageSize"]["default"] = json!(default);
            }
            schema["properties"]["cursor"] = crate::engine::effective_contract::cursor_schema();
            schema
        }
        ConsultationCapability::Retrieve | ConsultationCapability::List => return Ok(None),
    };
    embed_definition(&mut schema, "projectInput", input)?;
    Ok(Some(schema))
}

fn effective_response_schema(
    capability: ConsultationCapability,
    data: &crate::engine::public_schema::CheckedPublicSchema,
    pagination: Option<&crate::engine::load::ServedPagination>,
) -> Result<Value, crate::engine::load::LoadError> {
    let reference = "#/$defs/projectData";
    let mut schema = match capability {
        ConsultationCapability::Retrieve | ConsultationCapability::Lookup => {
            record_schema(reference)
        }
        ConsultationCapability::List | ConsultationCapability::Search => {
            let maximum = pagination
                .map(|value| value.page_size_maximum)
                .ok_or_else(|| {
                    crate::engine::load::LoadError::Runtime(
                        "the target page contract has no pagination declaration".to_owned(),
                    )
                })?;
            let mut schema = record_page_schema(reference);
            schema["properties"]["items"]["maxItems"] = json!(maximum);
            schema
        }
    };
    embed_definition(&mut schema, "projectData", data)?;
    Ok(schema)
}

fn embed_definition(
    schema: &mut Value,
    name: &str,
    project: &crate::engine::public_schema::CheckedPublicSchema,
) -> Result<(), crate::engine::load::LoadError> {
    let root = schema.as_object_mut().ok_or_else(|| {
        crate::engine::load::LoadError::Runtime(
            "the fixed target schema is not an object".to_owned(),
        )
    })?;
    let definitions = root
        .entry("$defs")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            crate::engine::load::LoadError::Runtime(
                "the fixed target schema has invalid definitions".to_owned(),
            )
        })?;
    definitions.insert(name.to_owned(), project.for_definition(name));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maintained_inputs() -> (
        AdapterProject,
        AdapterPack,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let project_path = root.join("products/adapter/examples/dhis2-consultation/project.yaml");
        let pack_path = root.join("products/adapter/packs/dhis2-tracker/pack.yaml");
        let (project, _): (AdapterProject, _) = crate::engine::load::read_artifact(
            &project_path,
            registry_adapter_core::ADAPTER_PROJECT_KIND,
            registry_adapter_core::ADAPTER_PROJECT_API_VERSION,
        )
        .expect("the maintained Consultation project reads");
        let (pack, _): (AdapterPack, _) = crate::engine::load::read_artifact(
            &pack_path,
            registry_adapter_core::ADAPTER_PACK_KIND,
            registry_adapter_core::ADAPTER_PACK_API_VERSION,
        )
        .expect("the maintained source pack reads");
        (project, pack, project_path, pack_path)
    }

    fn maintained_attachment() -> crate::engine::target::TargetAttachment {
        let (project, pack, project_path, _) = maintained_inputs();
        target_attachment(
            &project,
            &pack,
            project_path.parent().expect("project directory"),
        )
        .expect("the maintained target attaches")
    }

    fn maintained_unserved_authoring(
        project: &AdapterProject,
        pack: &AdapterPack,
        pack_path: &Path,
    ) -> crate::engine::load::CompiledAuthoring {
        crate::engine::load::compile_authored_with(
            project,
            &built_in_profile(),
            pack,
            pack_path.parent().expect("pack directory"),
            "test-deployment",
            true,
            |_| Ok(crate::engine::load::EndpointCompilation::Absent),
        )
        .expect("the source-unbound authoring compiles")
    }

    #[test]
    fn fixed_catalogue_has_only_the_selected_baseline() {
        let expected = [
            (
                ConsultationCapability::Retrieve,
                "retrieve",
                HttpMethod::Get,
                "/v1/collections/{collectionId}/records/{recordId}",
            ),
            (
                ConsultationCapability::Lookup,
                "lookup",
                HttpMethod::Post,
                "/v1/collections/{collectionId}/lookup",
            ),
            (
                ConsultationCapability::List,
                "list",
                HttpMethod::Get,
                "/v1/collections/{collectionId}/records",
            ),
            (
                ConsultationCapability::Search,
                "search",
                HttpMethod::Post,
                "/v1/collections/{collectionId}/search",
            ),
        ];
        for (capability, operation, method, path) in expected {
            assert_eq!(capability.binding_operation(), operation);
            assert_eq!(capability.method(), method);
            assert_eq!(capability.path(), path);
            assert_eq!(
                ConsultationCapability::from_binding_operation(operation),
                Some(capability)
            );
        }
        for unsupported in ["revision-list", "revision-retrieve", "history", "snapshot"] {
            assert_eq!(
                ConsultationCapability::from_binding_operation(unsupported),
                None
            );
        }
    }

    #[test]
    fn built_in_profile_owns_standard_paths_envelopes_and_problems() {
        let profile = built_in_profile();
        assert_eq!(profile.id.as_str(), PROFILE_ID);
        assert_eq!(profile.operations.len(), 4);
        for capability in [
            ConsultationCapability::Retrieve,
            ConsultationCapability::Lookup,
            ConsultationCapability::List,
            ConsultationCapability::Search,
        ] {
            assert_eq!(
                profile
                    .operations
                    .get(capability.binding_operation())
                    .unwrap()
                    .path,
                capability.runtime_path()
            );
        }
        assert!(profile.operations.get("revision-list").is_none());
    }

    #[test]
    fn operation_ids_are_alphanumeric_and_collection_specific() {
        assert_eq!(
            ConsultationCapability::Retrieve.operation_id("birth-registrations"),
            "retrieveBirthRegistrations"
        );
        assert_eq!(
            ConsultationCapability::Search.operation_id("people"),
            "searchPeople"
        );
        assert_eq!(
            ConsultationCapability::Retrieve.operation_id("people_summary"),
            "retrievePeopleSummary"
        );
        assert!(ConsultationCapability::Retrieve
            .operation_id("people_summary")
            .chars()
            .all(|character| character.is_ascii_alphanumeric()));
    }

    #[test]
    fn normalized_collection_operation_id_collisions_are_refused() {
        let document = CallerCapabilities {
            collections: vec![
                CapabilityCollection {
                    collection_id: "people-summary".to_owned(),
                    registry: "https://registry.example/people".to_owned(),
                    operations: vec![operation(
                        "retrievePeopleSummary",
                        ConsultationCapability::Retrieve,
                    )],
                },
                CapabilityCollection {
                    collection_id: "people_summary".to_owned(),
                    registry: "https://registry.example/people".to_owned(),
                    operations: vec![operation(
                        "retrievePeopleSummary",
                        ConsultationCapability::Retrieve,
                    )],
                },
            ],
            operations: Vec::new(),
        };
        assert_eq!(
            validate_capabilities(&document),
            Err(CapabilityError::Contradictory)
        );
    }

    #[test]
    fn per_collection_named_input_templates_keep_standard_shape_host_owned() {
        assert_eq!(
            request_envelope(ConsultationCapability::Lookup, Some("by-national-id")),
            Some(r#"{"selector":"by-national-id","values":"{{filters}}"}"#.to_owned())
        );
        assert_eq!(
            request_envelope(ConsultationCapability::Retrieve, None),
            None
        );
    }

    #[test]
    fn schema_helpers_wrap_project_schemas_without_authored_envelopes() {
        let record = record_schema("https://registry.example/schemas/person/1");
        assert_eq!(
            record["properties"]["data"]["$ref"],
            "https://registry.example/schemas/person/1"
        );
        let lookup = lookup_request_schema(
            "by-national-id",
            "https://registry.example/schemas/national-id/1",
        );
        assert_eq!(lookup["properties"]["selector"]["const"], "by-national-id");
        let search =
            search_request_schema("by-criteria", "https://registry.example/schemas/criteria/1");
        assert_eq!(search["properties"]["pageSize"]["maximum"], 100);
    }

    fn operation(id: &str, capability: ConsultationCapability) -> CapabilityOperation {
        CapabilityOperation {
            operation_id: id.to_owned(),
            contract: "https://registry.example/contracts/1/openapi.yaml".to_owned(),
            family: CapabilityFamily::Consultation,
            capability: capability.binding_operation().to_owned(),
            view: Some("public".to_owned()),
            write: None,
            selectors: Vec::new(),
            searches: Vec::new(),
        }
    }

    #[test]
    fn contradictory_duplicates_are_refused_not_merged() {
        let document = CallerCapabilities {
            collections: vec![
                CapabilityCollection {
                    collection_id: "people".to_owned(),
                    registry: "https://registry.example/people".to_owned(),
                    operations: vec![operation(
                        "retrievePeople",
                        ConsultationCapability::Retrieve,
                    )],
                },
                CapabilityCollection {
                    collection_id: "people".to_owned(),
                    registry: "https://other.example/people".to_owned(),
                    operations: vec![operation(
                        "retrievePeople",
                        ConsultationCapability::Retrieve,
                    )],
                },
            ],
            operations: Vec::new(),
        };
        assert_eq!(
            validate_capabilities(&document),
            Err(CapabilityError::Contradictory)
        );
    }

    #[test]
    fn named_inputs_are_present_only_on_their_capability() {
        let mut lookup = operation("lookupPeople", ConsultationCapability::Lookup);
        lookup.selectors.push("byNationalId".to_owned());
        let document = CallerCapabilities {
            collections: vec![CapabilityCollection {
                collection_id: "people".to_owned(),
                registry: "https://registry.example/people".to_owned(),
                operations: vec![lookup],
            }],
            operations: Vec::new(),
        };
        assert_eq!(validate_capabilities(&document), Ok(()));
    }

    #[test]
    fn guarded_write_discovery_has_closed_companion_read_metadata() {
        let update = CapabilityOperation {
            operation_id: "updatePeople".to_owned(),
            contract: "https://registry.example/contracts/1/openapi.yaml".to_owned(),
            family: CapabilityFamily::Write,
            capability: "update".to_owned(),
            view: None,
            write: Some(DiscoveredWriteMetadata {
                companion_read: CompanionReadIdentity {
                    operation_id: "retrievePeople".to_owned(),
                    view: "person-public".to_owned(),
                },
            }),
            selectors: Vec::new(),
            searches: Vec::new(),
        };
        let document = CallerCapabilities {
            collections: vec![CapabilityCollection {
                collection_id: "people".to_owned(),
                registry: "https://registry.example/people".to_owned(),
                operations: vec![update],
            }],
            operations: Vec::new(),
        };
        assert_eq!(validate_capabilities(&document), Ok(()));
        assert_eq!(
            serde_json::to_value(document).unwrap()["collections"][0]["operations"][0],
            json!({
                "operationId": "updatePeople",
                "contract": "https://registry.example/contracts/1/openapi.yaml",
                "family": "write",
                "capability": "update",
                "write": {"companionRead": {"operationId": "retrievePeople", "view": "person-public"}}
            })
        );
    }

    #[test]
    fn caller_visible_read_and_companion_views_use_the_canonical_hyphen_grammar() {
        let mut read = operation("retrievePeople", ConsultationCapability::Retrieve);
        read.view = Some("person_public".to_owned());
        let mut update = CapabilityOperation {
            operation_id: "updatePeople".to_owned(),
            contract: "https://registry.example/contracts/1/openapi.yaml".to_owned(),
            family: CapabilityFamily::Write,
            capability: "update".to_owned(),
            view: None,
            write: Some(DiscoveredWriteMetadata {
                companion_read: CompanionReadIdentity {
                    operation_id: "retrievePeople".to_owned(),
                    view: "person-public".to_owned(),
                },
            }),
            selectors: Vec::new(),
            searches: Vec::new(),
        };
        let document = |operation| CallerCapabilities {
            collections: vec![CapabilityCollection {
                collection_id: "people".to_owned(),
                registry: "https://registry.example/people".to_owned(),
                operations: vec![operation],
            }],
            operations: Vec::new(),
        };
        assert_eq!(
            validate_capabilities(&document(read)),
            Err(CapabilityError::Contradictory)
        );

        update
            .write
            .as_mut()
            .expect("Write metadata")
            .companion_read
            .view = "person_public".to_owned();
        assert_eq!(
            validate_capabilities(&document(update)),
            Err(CapabilityError::Contradictory)
        );
    }

    #[test]
    fn bounds_fail_instead_of_truncating() {
        let document = CallerCapabilities {
            collections: (0..=MAX_COLLECTIONS)
                .map(|index| CapabilityCollection {
                    collection_id: format!("collection-{index}"),
                    registry: format!("https://registry.example/{index}"),
                    operations: vec![],
                })
                .collect(),
            operations: Vec::new(),
        };
        assert_eq!(
            validate_capabilities(&document),
            Err(CapabilityError::TooManyCollections)
        );
    }

    #[test]
    fn source_support_is_validated_for_every_capability() {
        let one: SourceReadSupport = serde_json::from_value(json!({
            "type": "read-one", "inputs": ["record-id"]
        }))
        .expect("read one");
        let two: SourceReadSupport = serde_json::from_value(json!({
            "type": "read-one", "inputs": ["record-id", "tenant-id"]
        }))
        .expect("read one with two inputs");
        let page: SourceReadSupport = serde_json::from_value(json!({
            "type": "read-page", "inputs": [],
            "order": [{"name": "record-id", "direction": "ascending"}],
            "uniqueTieBreaker": "record-id"
        }))
        .expect("read page");
        assert!(source_input(ConsultationCapability::Retrieve, &one).is_some());
        assert!(source_input(ConsultationCapability::Retrieve, &two).is_none());
        assert!(source_input(ConsultationCapability::List, &page).is_some());
        assert!(source_input(ConsultationCapability::List, &one).is_none());
    }

    #[test]
    fn target_application_allows_known_unserved_entries_and_refuses_unknown_entries() {
        let (project, pack, project_path, pack_path) = maintained_inputs();
        let attachment = target_attachment(
            &project,
            &pack,
            project_path.parent().expect("project directory"),
        )
        .expect("target attachment");
        let mut authored = maintained_unserved_authoring(&project, &pack, &pack_path);
        assert!(authored.served.is_empty());
        assert_eq!(authored.unserved.len(), project.bindings.len());
        attachment
            .apply(&mut authored, &pack)
            .expect("known unserved attachment entries remain valid");

        let mut attachment = target_attachment(
            &project,
            &pack,
            project_path.parent().expect("project directory"),
        )
        .expect("target attachment");
        let operation = attachment
            .operations
            .remove("people-retrieve")
            .expect("retrieve attachment");
        attachment
            .operations
            .insert("unknown-binding".to_owned(), operation);
        let mut authored = maintained_unserved_authoring(&project, &pack, &pack_path);
        let failure = attachment
            .apply(&mut authored, &pack)
            .expect_err("an unknown attachment entry is refused");
        assert!(failure.to_string().contains("unknown-binding"));
    }

    #[test]
    fn target_identity_changes_with_projection_and_contract_metadata() {
        let mut attachment = maintained_attachment();
        let baseline = attachment.identity.clone();
        let serialized: Value =
            serde_json::from_slice(&baseline).expect("canonical target identity");
        let operation = serialized["operations"]
            .as_array()
            .expect("identity operations")
            .iter()
            .find(|operation| operation["binding"] == "people-retrieve")
            .expect("retrieve identity");
        assert_eq!(operation["itemProjection"]["valueMember"], "domainData");
        assert_eq!(
            operation["effectivePath"],
            "/govstack/registries/v1/collections/people/records/{recordId}"
        );
        assert!(operation["outputSchema"].is_object());

        let operation = attachment
            .operations
            .get_mut("people-retrieve")
            .expect("retrieve attachment");
        let crate::engine::target::TargetOperation::Read(operation) = operation else {
            panic!("the Consultation retrieve attachment is a read");
        };
        operation.item_projection.value_member = "publicData".to_owned();
        let projection = target_identity(&attachment.profile, &attachment.operations)
            .expect("projection identity");
        assert_ne!(baseline, projection);

        let mut attachment = maintained_attachment();
        let operation = attachment
            .operations
            .get_mut("people-retrieve")
            .expect("retrieve attachment");
        let crate::engine::target::TargetOperation::Read(operation) = operation else {
            panic!("the Consultation retrieve attachment is a read");
        };
        operation.effective_contract.response_body["properties"]["recordId"]["maxLength"] =
            json!(128);
        let schema =
            target_identity(&attachment.profile, &attachment.operations).expect("schema identity");
        assert_ne!(baseline, schema);

        let mut attachment = maintained_attachment();
        let operation = attachment
            .operations
            .get_mut("people-retrieve")
            .expect("retrieve attachment");
        let crate::engine::target::TargetOperation::Read(operation) = operation else {
            panic!("the Consultation retrieve attachment is a read");
        };
        operation.effective_contract.path.push_str("/changed");
        let path =
            target_identity(&attachment.profile, &attachment.operations).expect("path identity");
        assert_ne!(baseline, path);
    }

    #[test]
    fn consultation_identity_refuses_write_operations_without_values() {
        let mut attachment = maintained_attachment();
        let operation = attachment
            .operations
            .remove("people-search")
            .expect("Search attachment");
        let crate::engine::target::TargetOperation::Read(operation) = operation else {
            panic!("the Consultation Search attachment is a read");
        };
        let source = br#"fn prepare(source) { #{person: #{name: source.name}} }"#;
        let script = registry_adapter_core::ProjectScript {
            id: registry_platform_yaml::LocalId::new("write-input").expect("script id"),
            file: "scripts/write-input.rhai".to_owned(),
            digest: registry_platform_yaml::Digest::new(registry_platform_config::sha256_uri(
                source,
            ))
            .expect("script digest"),
        };
        let transform = registry_adapter_core::BindingTransform {
            script: script.id.clone(),
            entrypoint: "prepare".to_owned(),
        };
        let artifacts = crate::engine::artifacts::ProjectArtifactBytes::new([(
            script.file.clone(),
            source.to_vec(),
        )]);
        let input_transform =
            crate::engine::inbound_transform::CompiledProjectInputTransform::compile_parts(
                "write-identity",
                &script,
                &transform,
                &artifacts,
            )
            .expect("input transform compiles");
        let write_support = serde_json::from_value(json!({
            "type": "create-one",
            "identity": "source-assigned",
            "replay": {"type": "exact-keyed", "replayWindowSeconds": 300}
        }))
        .expect("write support");
        attachment.operations.insert(
            "people-search".to_owned(),
            crate::engine::target::TargetOperation::Write(
                crate::engine::target::TargetWriteOperation {
                    project_input_schema: operation
                        .project_input_schema
                        .expect("Search has an input schema"),
                    project_input_transform: std::sync::Arc::new(input_transform),
                    write_support,
                    native_replay:
                        crate::engine::target::SourceNativeReplayPlan::ExactKeyedSinglePost,
                    effective_contract: operation.effective_contract,
                },
            ),
        );

        let error = target_identity(&attachment.profile, &attachment.operations)
            .expect_err("Consultation identity is read-only");
        assert_eq!(
            error.to_string(),
            "the Consultation target identity accepts read operations only"
        );
    }

    #[test]
    fn effective_schemas_preserve_cursor_and_path_segment_bounds() {
        let attachment = maintained_attachment();
        let crate::engine::target::TargetOperation::Read(search) =
            &attachment.operations["people-search"]
        else {
            panic!("the Consultation Search attachment is a read");
        };
        let cursor = &search
            .effective_contract
            .request_body
            .as_ref()
            .expect("Search request contract")["properties"]["cursor"];
        assert_eq!(
            cursor["maxLength"],
            crate::engine::component::rest::continuation::CURSOR_MAXIMUM_TOKEN_BYTES
        );
        assert_eq!(cursor["pattern"], "^[A-Za-z0-9_-]+$");
        let crate::engine::target::TargetOperation::Read(retrieve) =
            &attachment.operations["people-retrieve"]
        else {
            panic!("the Consultation Retrieve attachment is a read");
        };
        let segment = &retrieve.effective_contract.path_parameters["properties"]["recordId"];
        assert_eq!(segment["maxLength"], MAXIMUM_RECORD_ID_CHARACTERS);
        assert!(segment["not"]["anyOf"].is_array());
    }
}
