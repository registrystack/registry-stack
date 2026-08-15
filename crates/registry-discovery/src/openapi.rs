// SPDX-License-Identifier: Apache-2.0
//! Deterministic OpenAPI contract for the fixed Discovery HTTP surface.

use std::marker::PhantomData;

use serde_json::{json, Map, Value};

use crate::model::{
    EvidenceTypeResolveRequest, EvidenceTypeResolveResponse, ResolvedAlternative, ServiceRecord,
    ServiceSearchResponse, MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE, MAXIMUM_FILTER_VALUES,
    MAXIMUM_IDENTIFIER_CHARACTERS, MAXIMUM_QUERY_BYTES, MAXIMUM_QUERY_VALUE_CHARACTERS,
    MAXIMUM_RESULT_ALTERNATIVES, MAXIMUM_RESULT_RECORDS, MAXIMUM_TEXT_CHARACTERS,
    MAXIMUM_VALUES_PER_FIELD, MINIMUM_HTTP_RESPONSE_BYTES,
};
use crate::problem::ProblemCode;

pub const HEALTH_ROUTE: &str = "/health";
pub const READY_ROUTE: &str = "/ready";
pub const OPENAPI_ROUTE: &str = "/openapi.json";
pub const SERVICES_ROUTE: &str = "/v1/services";
pub const EVIDENCE_TYPES_ROUTE: &str = "/v1/evidence-types/resolve";
pub const OPENAPI_BYTES: &[u8] = include_bytes!("../openapi.json");
const _: () = assert!(OPENAPI_BYTES.len() <= MINIMUM_HTTP_RESPONSE_BYTES);

const JSON: &str = "application/json";
const PROBLEM_JSON: &str = "application/problem+json";
const DIGEST_LENGTH: usize = 71;
const DIGEST_PATTERN: &str = "^sha256:[0-9a-f]{64}$";
const IDENTIFIER_PATTERN: &str =
    "^[^\\s\\u0000-\\u001f\\u007f](?:[^\\u0000-\\u001f\\u007f]*[^\\s\\u0000-\\u001f\\u007f])?$";
const PUBLIC_URL_PATTERN: &str =
    "^(?:https://[^\\s\\u0000-\\u001f\\u007f-\\u009f/?#@]+|http://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?)(?!.*//)(?:/[^\\s\\u0000-\\u001f\\u007f-\\u009f?#]*)?$";
const TEXT_PATTERN: &str = "^[^\\u0000-\\u001f\\u007f-\\u009f]+$";
const URI_IDENTIFIER_PATTERN: &str = "^[A-Za-z][A-Za-z0-9+.-]*:";

trait WireSchema {
    const NAME: &'static str;

    fn schema() -> Value;
}

struct SchemaRef<T>(PhantomData<T>);

impl<T: WireSchema> SchemaRef<T> {
    fn value() -> Value {
        json!({"$ref": format!("#/components/schemas/{}", T::NAME)})
    }
}

impl WireSchema for EvidenceTypeResolveRequest {
    const NAME: &'static str = "EvidenceTypeResolveRequest";

    fn schema() -> Value {
        object_schema(
            &["requirementId"],
            &[
                ("requirementId", uri_identifier_schema()),
                ("jurisdiction", uri_identifier_schema()),
            ],
        )
    }
}

impl WireSchema for ResolvedAlternative {
    const NAME: &'static str = "ResolvedAlternative";

    fn schema() -> Value {
        object_schema(
            &[
                "evidenceTypeListId",
                "evidenceTypeIds",
                "mappingId",
                "mappingAuthorityId",
            ],
            &[
                ("evidenceTypeListId", uri_identifier_schema()),
                (
                    "evidenceTypeIds",
                    bounded_array_schema(
                        uri_identifier_schema(),
                        1,
                        MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE,
                        true,
                    ),
                ),
                ("mappingId", uri_identifier_schema()),
                ("mappingAuthorityId", uri_identifier_schema()),
            ],
        )
    }
}

impl WireSchema for EvidenceTypeResolveResponse {
    const NAME: &'static str = "EvidenceTypeResolveResponse";

    fn schema() -> Value {
        object_schema(
            &["requirementId", "mappingRevision", "alternatives"],
            &[
                ("requirementId", uri_identifier_schema()),
                ("jurisdiction", uri_identifier_schema()),
                ("mappingRevision", digest_schema()),
                (
                    "alternatives",
                    bounded_array_schema(
                        SchemaRef::<ResolvedAlternative>::value(),
                        0,
                        MAXIMUM_RESULT_ALTERNATIVES,
                        false,
                    ),
                ),
            ],
        )
    }
}

impl WireSchema for ServiceRecord {
    const NAME: &'static str = "ServiceRecord";

    fn schema() -> Value {
        object_schema(
            &[
                "recordId",
                "bindingId",
                "serviceId",
                "serviceKind",
                "title",
                "description",
                "endpointUrl",
                "jurisdictions",
                "conformsTo",
                "evidenceTypeIds",
                "semanticClassIds",
                "operationFamilyIds",
                "originId",
                "originUrl",
                "originContentDigest",
                "originFetchedAt",
            ],
            &[
                ("recordId", identifier_schema()),
                ("bindingId", uri_identifier_schema()),
                ("serviceId", uri_identifier_schema()),
                (
                    "serviceKind",
                    json!({"type": "string", "enum": ["evidence", "relay"]}),
                ),
                ("title", text_schema()),
                ("description", text_schema()),
                ("endpointUrl", public_url_schema()),
                ("publisherId", uri_identifier_schema()),
                ("operatorId", uri_identifier_schema()),
                ("registryAuthorityId", uri_identifier_schema()),
                ("legalIssuerId", uri_identifier_schema()),
                ("technicalProviderId", uri_identifier_schema()),
                ("jurisdictions", service_identifier_list_schema(1)),
                ("conformsTo", service_identifier_list_schema(1)),
                ("evidenceTypeIds", service_identifier_list_schema(0)),
                ("semanticClassIds", service_identifier_list_schema(0)),
                ("operationFamilyIds", service_identifier_list_schema(0)),
                ("originId", identifier_schema()),
                ("originUrl", public_url_schema()),
                ("originContentDigest", digest_schema()),
                ("originFetchedAt", timestamp_schema()),
            ],
        )
    }
}

impl WireSchema for ServiceSearchResponse {
    const NAME: &'static str = "ServiceSearchResponse";

    fn schema() -> Value {
        object_schema(
            &["catalogRevision", "items"],
            &[
                ("catalogRevision", digest_schema()),
                (
                    "items",
                    bounded_array_schema(
                        SchemaRef::<ServiceRecord>::value(),
                        0,
                        MAXIMUM_RESULT_RECORDS,
                        false,
                    ),
                ),
            ],
        )
    }
}

/// Generate the committed OpenAPI bytes. Object keys are serialized in stable
/// lexical order by `serde_json`, and the trailing newline is part of the
/// served contract.
pub fn generated_bytes() -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(&document())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn document() -> Value {
    let mut paths = Map::new();
    paths.insert(
        HEALTH_ROUTE.into(),
        json!({"get": probe_operation("Process is live")}),
    );
    paths.insert(
        OPENAPI_ROUTE.into(),
        json!({"get": probe_operation("Exact OpenAPI document")}),
    );
    paths.insert(
        READY_ROUTE.into(),
        json!({"get": probe_operation("Immutable index is loaded")}),
    );
    paths.insert(
        EVIDENCE_TYPES_ROUTE.into(),
        json!({"post": {
            "requestBody": {
                "required": true,
                "content": {
                    (JSON): {"schema": SchemaRef::<EvidenceTypeResolveRequest>::value()}
                }
            },
            "responses": dynamic_responses(
                "Complete exact mapping result",
                SchemaRef::<EvidenceTypeResolveResponse>::value(),
            )
        }}),
    );
    paths.insert(
        SERVICES_ROUTE.into(),
        json!({"get": {
            "description": format!(
                "Exact unranked search. The encoded query is limited to {MAXIMUM_QUERY_BYTES} bytes and all decoded values share one aggregate limit of {MAXIMUM_QUERY_VALUE_CHARACTERS} Unicode scalar values. Individual field maxima do not imply that their aggregate is accepted."
            ),
            "x-registry-maximum-query-bytes": MAXIMUM_QUERY_BYTES,
            "x-registry-maximum-decoded-query-value-characters": MAXIMUM_QUERY_VALUE_CHARACTERS,
            "parameters": service_parameters(),
            "responses": dynamic_responses(
                "Complete exact search result",
                SchemaRef::<ServiceSearchResponse>::value(),
            )
        }}),
    );

    let mut schemas = Map::new();
    insert_schema::<EvidenceTypeResolveRequest>(&mut schemas);
    insert_schema::<EvidenceTypeResolveResponse>(&mut schemas);
    insert_schema::<ResolvedAlternative>(&mut schemas);
    insert_schema::<ServiceRecord>(&mut schemas);
    insert_schema::<ServiceSearchResponse>(&mut schemas);
    schemas.insert("Problem".into(), problem_schema());

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Discovery",
            "version": "v1alpha1"
        },
        "paths": paths,
        "components": {
            "responses": problem_responses(),
            "schemas": schemas
        }
    })
}

fn insert_schema<T: WireSchema>(schemas: &mut Map<String, Value>) {
    schemas.insert(T::NAME.into(), T::schema());
}

fn probe_operation(description: &str) -> Value {
    json!({
        "responses": {
            "200": {"description": description},
            "400": response_ref("InvalidRequest"),
            "503": response_ref("Unavailable")
        }
    })
}

fn dynamic_responses(description: &str, schema: Value) -> Value {
    json!({
        "200": {
            "description": description,
            "content": {(JSON): {"schema": schema}}
        },
        "400": response_ref("InvalidRequest"),
        "422": response_ref("ResultBoundExceeded"),
        "503": response_ref("Unavailable")
    })
}

fn response_ref(name: &str) -> Value {
    json!({"$ref": format!("#/components/responses/{name}")})
}

fn problem_responses() -> Value {
    json!({
        "InvalidRequest": problem_response(
            "Invalid request or request body exceeds the configured bound",
        ),
        "ResultBoundExceeded": problem_response(
            "Complete result exceeds the configured bound",
        ),
        "Unavailable": problem_response(
            "Request exceeded the configured time limit or the response could not be produced",
        )
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            (PROBLEM_JSON): {
                "schema": {"$ref": "#/components/schemas/Problem"}
            }
        }
    })
}

fn service_parameters() -> Value {
    Value::Array(
        [
            ("recordId", identifier_schema(), MAXIMUM_FILTER_VALUES),
            ("serviceId", uri_identifier_schema(), MAXIMUM_FILTER_VALUES),
            (
                "serviceKind",
                json!({"type": "string", "enum": ["evidence", "relay"]}),
                2,
            ),
            (
                "jurisdiction",
                uri_identifier_schema(),
                MAXIMUM_FILTER_VALUES,
            ),
            ("conformsTo", uri_identifier_schema(), MAXIMUM_FILTER_VALUES),
            (
                "evidenceType",
                uri_identifier_schema(),
                MAXIMUM_FILTER_VALUES,
            ),
            (
                "semanticClass",
                uri_identifier_schema(),
                MAXIMUM_FILTER_VALUES,
            ),
            (
                "operationFamily",
                uri_identifier_schema(),
                MAXIMUM_FILTER_VALUES,
            ),
        ]
        .into_iter()
        .map(|(name, items, maximum_items)| {
            json!({
                "name": name,
                "in": "query",
                "description": format!(
                    "Repeated exact-match values sharing the operation-wide aggregate limit of {MAXIMUM_QUERY_VALUE_CHARACTERS} decoded Unicode scalar values."
                ),
                "style": "form",
                "explode": true,
                "schema": bounded_array_schema(
                    items,
                    1,
                    maximum_items,
                    name == "serviceKind",
                )
            })
        })
        .collect(),
    )
}

fn object_schema(required: &[&str], properties: &[(&str, Value)]) -> Value {
    let properties = properties
        .iter()
        .map(|(name, schema)| ((*name).to_owned(), schema.clone()))
        .collect::<Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn identifier_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAXIMUM_IDENTIFIER_CHARACTERS,
        "pattern": IDENTIFIER_PATTERN
    })
}

fn uri_identifier_schema() -> Value {
    json!({
        "type": "string",
        "format": "uri",
        "minLength": 1,
        "maxLength": MAXIMUM_IDENTIFIER_CHARACTERS,
        "pattern": URI_IDENTIFIER_PATTERN
    })
}

fn public_url_schema() -> Value {
    json!({
        "type": "string",
        "format": "uri",
        "minLength": 1,
        "maxLength": MAXIMUM_IDENTIFIER_CHARACTERS,
        "pattern": PUBLIC_URL_PATTERN
    })
}

fn text_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAXIMUM_TEXT_CHARACTERS,
        "pattern": TEXT_PATTERN
    })
}

fn digest_schema() -> Value {
    json!({
        "type": "string",
        "minLength": DIGEST_LENGTH,
        "maxLength": DIGEST_LENGTH,
        "pattern": DIGEST_PATTERN
    })
}

fn timestamp_schema() -> Value {
    json!({
        "type": "string",
        "format": "date-time",
        "maxLength": 64
    })
}

fn service_identifier_list_schema(minimum_items: usize) -> Value {
    bounded_array_schema(
        uri_identifier_schema(),
        minimum_items,
        MAXIMUM_VALUES_PER_FIELD,
        true,
    )
}

fn bounded_array_schema(
    items: Value,
    minimum_items: usize,
    maximum_items: usize,
    unique_items: bool,
) -> Value {
    json!({
        "type": "array",
        "items": items,
        "minItems": minimum_items,
        "maxItems": maximum_items,
        "uniqueItems": unique_items
    })
}

fn problem_schema() -> Value {
    let variants = ProblemCode::ALL
        .into_iter()
        .map(|problem| {
            object_schema(
                &["type", "title", "status"],
                &[
                    (
                        "type",
                        json!({"type": "string", "format": "uri", "const": problem.type_uri()}),
                    ),
                    ("title", json!({"type": "string", "const": problem.title()})),
                    (
                        "status",
                        json!({"type": "integer", "const": problem.status().as_u16()}),
                    ),
                ],
            )
        })
        .collect::<Vec<_>>();
    json!({"oneOf": variants})
}

#[cfg(test)]
mod tests {
    use registry_discovery_profile::ServiceKind;
    use serde::Serialize;

    use super::*;

    #[test]
    fn committed_openapi_is_the_deterministic_generator_output() {
        assert_eq!(generated_bytes().unwrap(), OPENAPI_BYTES);
    }

    #[test]
    fn component_property_names_match_the_serialized_wire_models() {
        assert_wire_properties(&EvidenceTypeResolveRequest {
            requirement_id: "urn:example:requirement".into(),
            jurisdiction: Some("urn:example:jurisdiction".into()),
        });
        assert_wire_properties(&ResolvedAlternative {
            evidence_type_list_id: "urn:example:list".into(),
            evidence_type_ids: vec!["urn:example:type".into()],
            mapping_id: "mapping".into(),
            mapping_authority_id: "urn:example:authority".into(),
        });
        assert_wire_properties(&EvidenceTypeResolveResponse {
            requirement_id: "urn:example:requirement".into(),
            jurisdiction: Some("urn:example:jurisdiction".into()),
            mapping_revision: "sha256:revision".into(),
            alternatives: Vec::new(),
        });
        assert_wire_properties(&ServiceRecord {
            record_id: "record".into(),
            binding_id: "binding".into(),
            service_id: "urn:example:service".into(),
            service_kind: ServiceKind::Evidence,
            title: "Service".into(),
            description: "Description".into(),
            endpoint_url: "https://service.example.invalid".into(),
            publisher_id: Some("urn:example:publisher".into()),
            operator_id: Some("urn:example:operator".into()),
            registry_authority_id: Some("urn:example:registry".into()),
            legal_issuer_id: Some("urn:example:issuer".into()),
            technical_provider_id: Some("urn:example:provider".into()),
            jurisdictions: vec!["urn:example:jurisdiction".into()],
            conforms_to: vec!["urn:example:profile".into()],
            evidence_type_ids: vec!["urn:example:type".into()],
            semantic_class_ids: Vec::new(),
            operation_family_ids: Vec::new(),
            origin_id: "origin".into(),
            origin_url: "https://origin.example.invalid/catalog.jsonld".into(),
            origin_content_digest: "sha256:digest".into(),
            origin_fetched_at: "2026-08-14T00:00:00Z".into(),
        });
        assert_wire_properties(&ServiceSearchResponse {
            catalog_revision: "sha256:revision".into(),
            items: Vec::new(),
        });
    }

    #[test]
    fn openapi_publishes_the_compiled_query_and_wire_bounds() {
        let document = document();
        let operation = &document["paths"][SERVICES_ROUTE]["get"];
        assert_eq!(
            operation["x-registry-maximum-query-bytes"],
            MAXIMUM_QUERY_BYTES
        );
        assert_eq!(
            operation["x-registry-maximum-decoded-query-value-characters"],
            MAXIMUM_QUERY_VALUE_CHARACTERS
        );
        assert!(operation["description"]
            .as_str()
            .is_some_and(|description| description.contains("Individual field maxima")));
        let parameters = operation["parameters"].as_array().unwrap();
        for parameter in parameters {
            let name = parameter["name"].as_str().unwrap();
            let expected = if name == "serviceKind" {
                2
            } else {
                MAXIMUM_FILTER_VALUES
            };
            assert_eq!(parameter["schema"]["minItems"], 1);
            assert_eq!(parameter["schema"]["maxItems"], expected);
            assert_eq!(parameter["schema"]["uniqueItems"], name == "serviceKind");
            assert!(parameter["description"].as_str().is_some_and(
                |description| description.contains(&MAXIMUM_QUERY_VALUE_CHARACTERS.to_string())
            ));
        }
        let parameter = |name: &str| {
            parameters
                .iter()
                .find(|parameter| parameter["name"] == name)
                .unwrap()
        };
        assert_eq!(
            parameter("recordId")["schema"]["items"]["maxLength"],
            MAXIMUM_IDENTIFIER_CHARACTERS
        );
        assert_eq!(
            parameter("recordId")["schema"]["items"]["pattern"],
            IDENTIFIER_PATTERN
        );
        assert_eq!(parameter("serviceId")["schema"]["items"]["format"], "uri");
        assert_eq!(
            parameter("serviceId")["schema"]["items"]["pattern"],
            URI_IDENTIFIER_PATTERN
        );

        let schemas = &document["components"]["schemas"];
        assert_eq!(
            schemas[ServiceSearchResponse::NAME]["properties"]["items"]["maxItems"],
            MAXIMUM_RESULT_RECORDS
        );
        assert_eq!(
            schemas[EvidenceTypeResolveResponse::NAME]["properties"]["alternatives"]["maxItems"],
            MAXIMUM_RESULT_ALTERNATIVES
        );
        assert_eq!(
            schemas[ResolvedAlternative::NAME]["properties"]["evidenceTypeIds"]["maxItems"],
            MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE
        );
        assert_eq!(
            schemas[ServiceRecord::NAME]["properties"]["jurisdictions"]["maxItems"],
            MAXIMUM_VALUES_PER_FIELD
        );
        assert_eq!(
            schemas[ServiceRecord::NAME]["properties"]["title"]["maxLength"],
            MAXIMUM_TEXT_CHARACTERS
        );
        assert_eq!(
            schemas[ServiceRecord::NAME]["properties"]["endpointUrl"]["format"],
            "uri"
        );
        assert_eq!(
            schemas[ServiceRecord::NAME]["properties"]["endpointUrl"]["pattern"],
            PUBLIC_URL_PATTERN
        );
        assert!(PUBLIC_URL_PATTERN.contains("(?!.*//)"));
        assert_eq!(
            schemas[ServiceRecord::NAME]["properties"]["originContentDigest"]["maxLength"],
            DIGEST_LENGTH
        );
        assert_eq!(
            schemas[ServiceRecord::NAME]["properties"]["originContentDigest"]["pattern"],
            DIGEST_PATTERN
        );
        assert_eq!(
            schemas[EvidenceTypeResolveRequest::NAME]["properties"]["requirementId"]["maxLength"],
            MAXIMUM_IDENTIFIER_CHARACTERS
        );
        let problems = schemas["Problem"]["oneOf"].as_array().unwrap();
        assert_eq!(problems.len(), ProblemCode::ALL.len());
        for (schema, problem) in problems.iter().zip(ProblemCode::ALL) {
            assert_eq!(schema["properties"]["type"]["const"], problem.type_uri());
            assert_eq!(schema["properties"]["title"]["const"], problem.title());
            assert_eq!(
                schema["properties"]["status"]["const"],
                problem.status().as_u16()
            );
        }
    }

    fn assert_wire_properties<T: Serialize + WireSchema>(value: &T) {
        let serialized = serde_json::to_value(value).unwrap();
        let serialized = serialized.as_object().unwrap().keys().collect::<Vec<_>>();
        let schema = T::schema();
        let properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>();
        assert_eq!(serialized, properties, "{}", T::NAME);
    }
}
