// SPDX-License-Identifier: Apache-2.0

//! Fixed protocol catalogue for the built-in GovStack Digital Registries
//! Consultation facade. Deployment projects supply Registry, collection,
//! view, schemas and source bindings; these definitions own the wire names.

use registry_adapter_core::{AdapterProfile, HttpMethod};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use thiserror::Error;

pub const CAPABILITIES_PATH: &str = "/v1/capabilities";
pub const SERVICE_UNAVAILABLE_PROBLEM_CODE: &str =
    "https://govstack.global/problems/digital-registries/service-unavailable";
pub const MAX_COLLECTIONS: usize = 64;
pub const MAX_OPERATIONS_PER_COLLECTION: usize = 16;
pub const PROFILE_ID: &str = "govstack-consultation";
pub const PROFILE_VERSION: &str = "1.0.0-draft";

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
            "recordId": {"type": "string", "minLength": 1, "maxLength": 256},
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
                    "nextCursor": {"type": ["string", "null"]},
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
            "cursor": {"type": "string", "minLength": 1},
        },
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallerCapabilities {
    pub collections: Vec<CapabilityCollection>,
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
    pub capability: ConsultationCapability,
    pub view: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub searches: Vec<String>,
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
        if !collections.insert(collection.collection_id.as_str()) {
            return Err(CapabilityError::Contradictory);
        }
        if collection.operations.is_empty()
            || collection.operations.len() > MAX_OPERATIONS_PER_COLLECTION
        {
            return Err(CapabilityError::TooManyOperations);
        }
        let mut capabilities = BTreeSet::new();
        for operation in &collection.operations {
            if operation.operation_id
                != operation.capability.operation_id(&collection.collection_id)
                || !capabilities.insert(operation.capability)
                || !operations.insert(operation.operation_id.as_str())
            {
                return Err(CapabilityError::Contradictory);
            }
            let named_input_is_consistent = match operation.capability {
                ConsultationCapability::Lookup => {
                    operation.selectors.len() == 1 && operation.searches.is_empty()
                }
                ConsultationCapability::Search => {
                    operation.searches.len() == 1 && operation.selectors.is_empty()
                }
                ConsultationCapability::Retrieve | ConsultationCapability::List => {
                    operation.selectors.is_empty() && operation.searches.is_empty()
                }
            };
            if !named_input_is_consistent {
                return Err(CapabilityError::Contradictory);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            capability,
            view: "public".to_owned(),
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
        };
        assert_eq!(validate_capabilities(&document), Ok(()));
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
        };
        assert_eq!(
            validate_capabilities(&document),
            Err(CapabilityError::TooManyCollections)
        );
    }
}
