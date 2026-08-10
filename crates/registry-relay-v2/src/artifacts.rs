// SPDX-License-Identifier: Apache-2.0
//! Repeatable artifacts generated only from the immutable compiled Registry.

use std::collections::BTreeSet;

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contract::Visibility;
use crate::model::{
    CompiledAccess, CompiledOperation, CompiledRegistry, CompiledResource, ConsultationPattern,
    OperationKind, RepresentationProfile,
};
use crate::semantics::{
    full_record_schema, full_record_shacl, json_ld_context, local_vocabulary,
    representation_schema, representation_shacl,
};

const CRS84_URI: &str = "http://www.opengis.net/def/crs/OGC/0/CRS84";
const RFC7946_PROFILE_URI: &str = "http://www.opengis.net/def/profile/OGC/0/rfc7946";
const JSON_FG_PROFILE_URI: &str = "http://www.opengis.net/def/profile/OGC/0/jsonfg";
const JSON_FG_CORE_CONFORMANCE: &str = "http://www.opengis.net/spec/json-fg-1/1.0/conf/core";
const JSON_FG_TYPES_CONFORMANCE: &str =
    "http://www.opengis.net/spec/json-fg-1/1.0/conf/types-schemas";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSet {
    pub contract_revision: String,
    pub artifacts: Vec<GeneratedArtifact>,
    pub operation_bindings: Vec<OperationArtifactBindings>,
}

impl ArtifactSet {
    pub fn get(&self, path: &str) -> Option<&GeneratedArtifact> {
        self.artifacts.iter().find(|artifact| artifact.path == path)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedArtifact {
    pub id: String,
    pub path: String,
    pub media_type: String,
    pub visibility: Visibility,
    /// Present only for operation-bound artifacts. The HTTP layer must mount
    /// the artifact behind this exact compiled operation's static access gate.
    pub operation_identifier: Option<String>,
    /// Present with `operation_identifier` when an operation-bound artifact
    /// belongs to one exact finite representation.
    pub representation_identifier: Option<String>,
    pub sha256: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperationArtifactBindings {
    pub operation_identifier: String,
    pub representation_identifier: String,
    pub vocabulary_path: String,
    pub context_path: String,
    pub representation_schema_path: String,
    pub representation_shacl_path: String,
    pub classification_path: String,
    pub processing_path: String,
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("generated JSON could not be canonicalized")]
    CanonicalJson,
    #[error("a compiled operation refers to a missing disclosure profile")]
    MissingDisclosure,
}

pub fn generate_artifacts(registry: &CompiledRegistry) -> Result<ArtifactSet, ArtifactError> {
    let mut artifacts = Vec::new();
    let mut bindings = Vec::new();

    push_json(
        &mut artifacts,
        "openapi-full",
        "openapi.full.yaml",
        "application/yaml",
        Visibility::OperatorOnly,
        None,
        &openapi(registry, false),
    )?;
    push_json(
        &mut artifacts,
        "openapi-public",
        "openapi.public.json",
        "application/json",
        Visibility::Public,
        None,
        &openapi(registry, true),
    )?;
    push_json(
        &mut artifacts,
        "capability-inventory",
        "artifacts/capabilities.json",
        "application/json",
        Visibility::Public,
        None,
        &capability_inventory(registry, CapabilityProjection::Public),
    )?;
    push_json(
        &mut artifacts,
        "capability-inventory-full",
        "artifacts/capabilities.full.json",
        "application/json",
        Visibility::OperatorOnly,
        None,
        &capability_inventory(registry, CapabilityProjection::Full),
    )?;
    push_json(
        &mut artifacts,
        "audit-event-schema",
        "artifacts/audit-event.schema.json",
        "application/schema+json",
        Visibility::OperatorOnly,
        None,
        &audit_event_schema(),
    )?;

    for resource in &registry.resources {
        let all_properties = resource
            .properties
            .iter()
            .map(|property| property.name.clone())
            .chain(
                resource
                    .primary_geometry
                    .iter()
                    .map(|geometry| geometry.name.clone()),
            )
            .collect::<Vec<_>>();
        push_json(
            &mut artifacts,
            &format!("{}-full-schema", resource.id),
            &format!("artifacts/{}.full.schema.json", resource.id),
            "application/schema+json",
            Visibility::OperatorOnly,
            None,
            &full_record_schema(registry, resource),
        )?;
        push_text(
            &mut artifacts,
            &format!("{}-full-shacl", resource.id),
            &format!("artifacts/{}.full.shacl.ttl", resource.id),
            "text/turtle",
            Visibility::OperatorOnly,
            None,
            full_record_shacl(registry, resource).into_bytes(),
        );
        push_json(
            &mut artifacts,
            &format!("{}-full-vocabulary", resource.id),
            &format!("artifacts/{}.full.vocabulary.jsonld", resource.id),
            "application/ld+json",
            Visibility::OperatorOnly,
            None,
            &local_vocabulary(registry, resource, &all_properties),
        )?;
        push_json(
            &mut artifacts,
            &format!("{}-classification", resource.id),
            &format!("artifacts/{}.classifications.json", resource.id),
            "application/json",
            // This resource-wide inventory includes hidden source columns and
            // every operation's properties. Only operation-specific safe
            // projections may ever cross an operation gate.
            Visibility::OperatorOnly,
            None,
            &json!({
                "resource": resource.id,
                "properties": resource.properties.iter().map(|property| json!({
                    "property": property.name,
                    "classification": property.classification,
                })).chain(resource.primary_geometry.iter().map(|geometry| json!({
                    "property": geometry.name,
                    "classification": geometry.classification,
                    "geometryType": "Point",
                    "crs": geometry.crs,
                }))).collect::<Vec<_>>(),
                "columns": resource.column_accounting,
            }),
        )?;
        push_json(
            &mut artifacts,
            &format!("{}-processing-full", resource.id),
            &format!("artifacts/{}.processing.full.json", resource.id),
            "application/json",
            Visibility::OperatorOnly,
            None,
            &json!({
                "resourceIdentifier": resource.id,
                "descriptions": resource.processing_descriptions,
            }),
        )?;

        for operation in &resource.operations {
            for representation in &operation.representations {
                let disclosure = resource
                    .disclosure_profiles
                    .iter()
                    .find(|profile| profile.id == representation.disclosure_profile)
                    .ok_or(ArtifactError::MissingDisclosure)?;
                let suffix =
                    representation_artifact_stem(&resource.id, &operation.kind, &representation.id);
                if matches!(&representation.access, CompiledAccess::Protected { .. }) {
                    push_representation_json(
                        &mut artifacts,
                        &format!("{suffix}-capability"),
                        &format!("artifacts/{suffix}.capability.json"),
                        "application/json",
                        Visibility::OperationBound,
                        &operation.identifier,
                        &representation.id,
                        &capability_inventory(
                            registry,
                            CapabilityProjection::Representation(
                                &operation.identifier,
                                &representation.id,
                            ),
                        ),
                    )?;
                }
                let semantic_visibility = projection_visibility(
                    registry.metadata_visibility.semantics,
                    &representation.access,
                );
                let vocabulary_path = format!("artifacts/{suffix}.vocabulary.jsonld");
                let context_path = format!("artifacts/{suffix}.context.jsonld");
                let schema_path = format!("artifacts/{suffix}.schema.json");
                let shacl_path = format!("artifacts/{suffix}.shacl.ttl");
                let classification_path = format!("artifacts/{suffix}.classifications.json");
                let processing_path = format!("artifacts/{suffix}.processing.json");
                push_representation_json(
                    &mut artifacts,
                    &format!("{suffix}-vocabulary"),
                    &vocabulary_path,
                    "application/ld+json",
                    semantic_visibility,
                    &operation.identifier,
                    &representation.id,
                    &local_vocabulary(registry, resource, &disclosure.properties),
                )?;
                push_representation_json(
                    &mut artifacts,
                    &format!("{suffix}-context"),
                    &context_path,
                    "application/ld+json",
                    semantic_visibility,
                    &operation.identifier,
                    &representation.id,
                    &json_ld_context(registry, resource, &disclosure.properties),
                )?;
                push_representation_json(
                    &mut artifacts,
                    &format!("{suffix}-schema"),
                    &schema_path,
                    "application/schema+json",
                    semantic_visibility,
                    &operation.identifier,
                    &representation.id,
                    &representation_schema(
                        registry,
                        resource,
                        &disclosure.properties,
                        &representation.schema_reference,
                        &representation.semantic_model_reference,
                    ),
                )?;
                if supports_geojson(resource, representation) {
                    push_representation_json(
                        &mut artifacts,
                        &format!("{suffix}-geojson-schema"),
                        &format!("artifacts/{suffix}.geojson.schema.json"),
                        "application/schema+json",
                        semantic_visibility,
                        &operation.identifier,
                        &representation.id,
                        &geojson_response_schema(
                            registry,
                            operation,
                            representation,
                            resource,
                            true,
                        ),
                    )?;
                }
                push_representation_text(
                    &mut artifacts,
                    &format!("{suffix}-shacl"),
                    &shacl_path,
                    "text/turtle",
                    semantic_visibility,
                    &operation.identifier,
                    &representation.id,
                    representation_shacl(registry, resource, &disclosure.properties).into_bytes(),
                );
                let classification_visibility = projection_visibility(
                    registry.metadata_visibility.classifications,
                    &representation.access,
                );
                push_representation_json(
                    &mut artifacts,
                    &format!("{suffix}-classifications"),
                    &classification_path,
                    "application/json",
                    classification_visibility,
                    &operation.identifier,
                    &representation.id,
                    &json!({
                        "resourceIdentifier": resource.id,
                        "operationIdentifier": operation.identifier,
                        "representationIdentifier": representation.id,
                        "disclosureProfile": representation.disclosure_profile,
                        "processingHandling": representation.processing_handling,
                        "disclosureHandling": representation.disclosure_handling,
                        "transformIdentifiers": representation.transform_inventory,
                        "properties": resource.properties.iter()
                            .filter(|property| disclosure.properties.contains(&property.name))
                            .map(|property| json!({
                                "property": property.name,
                                "classification": property.classification,
                                "transform": property.transform,
                            })).chain(resource.primary_geometry.iter()
                                .filter(|geometry| disclosure.properties.contains(&geometry.name))
                                .map(|geometry| json!({
                                    "property": geometry.name,
                                    "classification": geometry.classification,
                                    "geometryType": "Point",
                                    "crs": geometry.crs,
                                })))
                            .collect::<Vec<_>>(),
                    }),
                )?;
                let processing_visibility = projection_visibility(
                    registry.metadata_visibility.processing,
                    &representation.access,
                );
                let operation_ref = operation_contract_reference(&operation.kind);
                push_representation_json(
                    &mut artifacts,
                    &format!("{suffix}-processing"),
                    &processing_path,
                    "application/json",
                    processing_visibility,
                    &operation.identifier,
                    &representation.id,
                    &json!({
                        "resourceIdentifier": resource.id,
                        "operationIdentifier": operation.identifier,
                        "representationIdentifier": representation.id,
                        "processingHandling": representation.processing_handling,
                        "disclosureHandling": representation.disclosure_handling,
                        "transformIdentifiers": representation.transform_inventory,
                        "descriptions": resource.processing_descriptions.iter()
                            .filter(|description| description.operation_refs.contains(&operation_ref))
                            .collect::<Vec<_>>(),
                    }),
                )?;
                bindings.push(OperationArtifactBindings {
                    operation_identifier: operation.identifier.clone(),
                    representation_identifier: representation.id.clone(),
                    vocabulary_path,
                    context_path,
                    representation_schema_path: schema_path,
                    representation_shacl_path: shacl_path,
                    classification_path,
                    processing_path,
                });
            }
        }

        let codelists = resource
            .properties
            .iter()
            .filter_map(|property| property.codelist.as_ref())
            .chain(std::iter::once(
                &resource.record_context.lifecycle_state_codelist,
            ))
            .cloned()
            .collect::<BTreeSet<_>>();
        for (index, codelist) in codelists.into_iter().enumerate() {
            push_json(
                &mut artifacts,
                &format!("{}-codelist-{index}", resource.id),
                &format!("artifacts/{}.codelist-{index}.schema.json", resource.id),
                "application/schema+json",
                Visibility::OperatorOnly,
                None,
                &json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "title": "Governed controlled-code source",
                    "type": "string",
                    "x-registry-codelist": codelist,
                }),
            )?;
        }
    }

    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    bindings.sort_by(|left, right| {
        left.operation_identifier
            .cmp(&right.operation_identifier)
            .then(
                left.representation_identifier
                    .cmp(&right.representation_identifier),
            )
    });
    Ok(ArtifactSet {
        contract_revision: registry.contract_revision.clone(),
        artifacts,
        operation_bindings: bindings,
    })
}

fn projection_visibility(configured: Visibility, access: &CompiledAccess) -> Visibility {
    match configured {
        Visibility::OperatorOnly => Visibility::OperatorOnly,
        Visibility::Public | Visibility::OperationBound => match access {
            CompiledAccess::Public => Visibility::Public,
            CompiledAccess::Protected { .. } => Visibility::OperationBound,
        },
    }
}

fn operation_contract_reference(kind: &OperationKind) -> String {
    match kind {
        OperationKind::List => "list".into(),
        OperationKind::Read => "read".into(),
        OperationKind::Lookup { name } => format!("lookup:{name}"),
    }
}

fn operation_artifact_stem(resource: &str, kind: &OperationKind) -> String {
    match kind {
        OperationKind::List => format!("{resource}--list"),
        OperationKind::Read => format!("{resource}--read"),
        OperationKind::Lookup { name } => format!("{resource}--lookup-{name}"),
    }
}

fn representation_artifact_stem(
    resource: &str,
    kind: &OperationKind,
    representation: &str,
) -> String {
    format!(
        "{}--representation-{representation}",
        operation_artifact_stem(resource, kind)
    )
}

#[allow(clippy::too_many_arguments)]
fn push_json(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: Option<String>,
    value: &Value,
) -> Result<(), ArtifactError> {
    let bytes = canonicalize_json(value).map_err(|_| ArtifactError::CanonicalJson)?;
    push_text(
        artifacts,
        id,
        path,
        media_type,
        visibility,
        operation_identifier,
        bytes,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_representation_json(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: &str,
    representation_identifier: &str,
    value: &Value,
) -> Result<(), ArtifactError> {
    let bound = visibility == Visibility::OperationBound;
    push_json(
        artifacts,
        id,
        path,
        media_type,
        visibility,
        bound.then(|| operation_identifier.to_owned()),
        value,
    )?;
    artifacts
        .last_mut()
        .expect("a representation artifact was appended")
        .representation_identifier = bound.then(|| representation_identifier.to_owned());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_representation_text(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: &str,
    representation_identifier: &str,
    content: Vec<u8>,
) {
    let bound = visibility == Visibility::OperationBound;
    push_text(
        artifacts,
        id,
        path,
        media_type,
        visibility,
        bound.then(|| operation_identifier.to_owned()),
        content,
    );
    artifacts
        .last_mut()
        .expect("a representation artifact was appended")
        .representation_identifier = bound.then(|| representation_identifier.to_owned());
}

#[allow(clippy::too_many_arguments)]
fn push_text(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: Option<String>,
    content: Vec<u8>,
) {
    artifacts.push(GeneratedArtifact {
        id: id.into(),
        path: path.into(),
        media_type: media_type.into(),
        visibility,
        operation_identifier,
        representation_identifier: None,
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(&content))),
        content,
    });
}

fn openapi(registry: &CompiledRegistry, public_only: bool) -> Value {
    let mut paths = Map::new();
    for (path, operation_id, description) in [
        ("/health", "relay.health", "Relay process liveness"),
        ("/ready", "relay.ready", "Compiled Registry readiness"),
        (
            "/openapi.json",
            "relay.openapi.public",
            "Safe public OpenAPI projection",
        ),
        (
            "/v2",
            "relay.registry.metadata",
            "Registry service metadata",
        ),
    ] {
        paths.insert(
            path.into(),
            json!({"get": {
                "operationId": operation_id,
                "description": description,
                "security": [],
                "responses": {"200": {"description": "Successful response"}, "default": {"$ref": "#/components/responses/Problem"}}
            }}),
        );
    }
    if !public_only || registry.metadata_visibility.resources == Visibility::Public {
        paths.insert(
            "/v2/resources".into(),
            json!({"get": {
                "operationId": "relay.resources.list",
                "security": [],
                "responses": {"200": {"description": "Visible Registry resources"}, "default": {"$ref": "#/components/responses/Problem"}}
            }}),
        );
        paths.insert(
            "/v2/resources/{resource}".into(),
            json!({"get": {
                "operationId": "relay.resources.retrieve",
                "security": if registry.metadata_visibility.resources == Visibility::Public {
                    json!([])
                } else {
                    json!([{"bearerAuth": []}])
                },
                "parameters": [{
                    "name": "resource", "in": "path", "required": true,
                    "schema": {"type": "string", "minLength": 1}
                }],
                "responses": {"200": {"description": "Visible Registry resource metadata"}, "default": {"$ref": "#/components/responses/Problem"}}
            }}),
        );
    }
    for resource in &registry.resources {
        for operation in &resource.operations {
            let visible_representations = operation
                .representations
                .iter()
                .filter(|representation| {
                    !public_only || matches!(&representation.access, CompiledAccess::Public)
                })
                .collect::<Vec<_>>();
            if visible_representations.is_empty() {
                continue;
            }
            let (method, path) = match &operation.kind {
                OperationKind::List => ("get", format!("/v2/resources/{}/records", resource.id)),
                OperationKind::Read => (
                    "get",
                    format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id),
                ),
                OperationKind::Lookup { name } => (
                    "post",
                    format!("/v2/resources/{}/lookups/{name}", resource.id),
                ),
            };
            let has_public = visible_representations
                .iter()
                .any(|representation| matches!(&representation.access, CompiledAccess::Public));
            let has_protected = visible_representations.iter().any(|representation| {
                matches!(&representation.access, CompiledAccess::Protected { .. })
            });
            let security = match (has_public, has_protected) {
                (true, true) => json!([{}, {"bearerAuth": []}]),
                (true, false) => json!([]),
                (false, true) => json!([{"bearerAuth": []}]),
                (false, false) => unreachable!("a visible representation exists"),
            };
            let visible_identifiers = visible_representations
                .iter()
                .map(|representation| representation.id.clone())
                .collect::<Vec<_>>();
            let visible_default = visible_identifiers
                .contains(&operation.default_representation)
                .then(|| operation.default_representation.clone());
            let mut representation_schema = json!({
                "type": "string",
                "enum": visible_identifiers,
            });
            if let Some(default) = &visible_default {
                representation_schema
                    .as_object_mut()
                    .expect("representation schema object")
                    .insert("default".into(), json!(default));
            }
            let mut parameters = vec![
                json!({
                    "name": "representation",
                    "in": "query",
                    "required": false,
                    "schema": representation_schema,
                    "description": "One finite compiled representation. Absence selects the declared default."
                }),
                json!({
                    "name": "fields",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string", "minLength": 1},
                    "description": "Duplicate-free comma-separated subset of the selected representation"
                }),
            ];
            let has_geojson = visible_representations
                .iter()
                .any(|representation| supports_geojson(resource, representation));
            if has_geojson {
                parameters.push(json!({
                    "name": "profile",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string", "enum": ["rfc7946", "jsonfg"], "default": "rfc7946"},
                    "description": "GeoJSON profile. Valid only with Accept: application/geo+json."
                }));
            }
            match &operation.kind {
                OperationKind::List => {
                    let pagination = operation
                        .query
                        .pagination
                        .as_ref()
                        .expect("compiled list pagination");
                    parameters.push(json!({"name": "pageSize", "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1, "maximum": pagination.maximum_page_size, "default": pagination.default_page_size}}));
                    parameters.push(json!({"name": "cursor", "in": "query", "required": false, "schema": {"type": "string", "minLength": 1}}));
                    for filter in &operation.query.filters {
                        parameters.push(json!({
                            "name": filter.parameter,
                            "in": "query",
                            "required": false,
                            "schema": openapi_type(filter.data_type),
                            "x-registry-exact-equality": true,
                        }));
                    }
                    if let Some(bbox) = &operation.query.spatial_bbox {
                        parameters.push(json!({
                            "name": "bbox",
                            "in": "query",
                            "required": false,
                            "style": "form",
                            "explode": false,
                            "schema": {
                                "type": "array",
                                "items": {"type": "number"},
                                "minItems": 4,
                                "maxItems": 4
                            },
                            "description": "Inclusive CRS84 point bounds: west,south,east,north",
                            "x-registry-spatial-predicate": "exact-point-intersection",
                            "x-registry-crs": CRS84_URI,
                            "x-registry-maximum-longitude-span-degrees": bbox.maximum_longitude_span_degrees,
                            "x-registry-maximum-latitude-span-degrees": bbox.maximum_latitude_span_degrees,
                        }));
                    }
                }
                OperationKind::Read => parameters.push(json!({
                    "name": "recordIdentifier", "in": "path", "required": true,
                    "schema": {"type": "string", "minLength": 1}
                })),
                OperationKind::Lookup { .. } => {}
            }
            let mut success_response = json!({
                "description": "A validated minimum-disclosure Registry response",
                "content": operation_response_content(
                    registry,
                    operation,
                    resource,
                    &visible_representations,
                )
            });
            if has_geojson {
                success_response
                    .as_object_mut()
                    .expect("response object")
                    .insert(
                        "headers".into(),
                        json!({
                            "Link": {
                                "description": "Selected RFC 7946 or JSON-FG profile link for GeoJSON responses",
                                "schema": {"type": "string"}
                            }
                        }),
                    );
            }
            let mut operation_value = json!({
                "operationId": operation.identifier,
                "x-registry-family": "consultation",
                "x-registry-pattern": consultation_pattern(operation.pattern),
                "x-registry-representations": visible_representations.iter().map(|representation| json!({
                    "identifier": representation.id,
                    "default": operation.default_representation == representation.id,
                    "disclosureProfile": representation.disclosure_profile,
                    "processingHandling": representation.processing_handling,
                    "disclosureHandling": representation.disclosure_handling,
                    "transformIdentifiers": representation.transform_inventory,
                    "schemaReference": representation.schema_reference,
                    "semanticModelReference": representation.semantic_model_reference,
                    "contextReference": representation.context_reference,
                    "formats": response_format_documents(resource, representation),
                })).collect::<Vec<_>>(),
                "security": security,
                "parameters": parameters,
                "responses": {
                    "200": success_response,
                    "default": {"$ref": "#/components/responses/Problem"}
                }
            });
            let required_scopes = visible_representations
                .iter()
                .filter_map(|representation| match &representation.access {
                    CompiledAccess::Public => None,
                    CompiledAccess::Protected { scope, .. } => Some(json!({
                        "representation": representation.id,
                        "scope": scope,
                    })),
                })
                .collect::<Vec<_>>();
            if !required_scopes.is_empty() {
                operation_value
                    .as_object_mut()
                    .expect("operation object")
                    .insert("x-registry-required-scopes".into(), json!(required_scopes));
            }
            if matches!(&operation.kind, OperationKind::Lookup { .. }) {
                let mut selector_properties = Map::new();
                for selector in &operation.query.selectors {
                    let mut schema = openapi_type(selector.data_type);
                    if let Value::Object(schema) = &mut schema {
                        if let Some(minimum) = selector.minimum_bytes {
                            schema.insert("minLength".into(), json!(minimum));
                        }
                        if let Some(maximum) = selector.maximum_bytes {
                            schema.insert("maxLength".into(), json!(maximum));
                        }
                    }
                    selector_properties.insert(selector.name.clone(), schema);
                }
                operation_value
                    .as_object_mut()
                    .expect("operation object")
                    .insert(
                        "requestBody".into(),
                        json!({
                            "required": true,
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": operation.query.selectors.iter().map(|selector| selector.name.clone()).collect::<Vec<_>>(),
                                "properties": selector_properties,
                            }}}
                        }),
                    );
            }
            paths
                .entry(path)
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .expect("path item object")
                .insert(method.into(), operation_value);
        }
    }
    paths.insert(
        "/v2/artifacts/{artifactIdentifier}".into(),
        json!({"get": {
            "operationId": "relay.artifacts.retrieve",
            "description": "Retrieve a visibility-appropriate generated Registry artifact",
            "security": [{}, {"bearerAuth": []}],
            "parameters": [{
                "name": "artifactIdentifier", "in": "path", "required": true,
                "schema": {"type": "string", "minLength": 1}
            }],
            "responses": {"200": {"description": "Generated artifact"}, "default": {"$ref": "#/components/responses/Problem"}}
        }}),
    );
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": registry.registry_name,
            "version": registry.contract_version,
            "description": "Generated Registry Relay Consultation API. This document makes no conformance or certification claim."
        },
        "servers": [{"url": registry.base_uri}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            },
            "schemas": {
                "Problem": {
                    "type": "object", "additionalProperties": false,
                    "required": ["type", "title", "status", "code", "traceId"],
                    "properties": {
                        "type": {"type": "string", "format": "uri"},
                        "title": {"type": "string"},
                        "status": {"type": "integer"},
                        "detail": {"type": "string"},
                        "code": {"type": "string"},
                        "traceId": {"type": "string", "pattern": "^[0-9a-f]{32}$"}
                    }
                }
            },
            "responses": {
                "Problem": {
                    "description": "Registry Stack problem",
                    "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
                }
            }
        }
    })
}

fn operation_response_schema(
    operation: &crate::model::CompiledOperation,
    representations: &[&crate::model::CompiledRepresentation],
) -> Value {
    let meta = json!({"type": "object"});
    let record = if representations.len() == 1 {
        json!({"$ref": representations[0].schema_reference})
    } else {
        json!({
            "oneOf": representations.iter().map(|representation| {
                json!({"$ref": representation.schema_reference})
            }).collect::<Vec<_>>()
        })
    };
    match &operation.kind {
        OperationKind::List => json!({
            "type": "object", "additionalProperties": false,
            "required": ["items", "pageInfo", "meta"],
            "properties": {
                "items": {"type": "array", "items": record},
                "pageInfo": {
                    "type": "object", "additionalProperties": false,
                    "required": ["nextCursor"],
                    "properties": {"nextCursor": {"type": ["string", "null"]}}
                },
                "meta": meta
            }
        }),
        OperationKind::Read | OperationKind::Lookup { .. } => json!({
            "type": "object", "additionalProperties": false,
            "required": ["data", "meta"],
            "properties": {
                "data": record,
                "meta": meta
            }
        }),
    }
}

fn operation_response_content(
    registry: &CompiledRegistry,
    operation: &CompiledOperation,
    resource: &CompiledResource,
    representations: &[&crate::model::CompiledRepresentation],
) -> Value {
    let ordinary = operation_response_schema(operation, representations);
    let mut content = Map::from_iter([
        (
            "application/json".into(),
            json!({"schema": ordinary.clone()}),
        ),
        ("application/ld+json".into(), json!({"schema": ordinary})),
    ]);
    let spatial = representations
        .iter()
        .filter(|representation| supports_geojson(resource, representation))
        .map(|representation| {
            geojson_response_schema(registry, operation, representation, resource, false)
        })
        .collect::<Vec<_>>();
    if !spatial.is_empty() {
        let schema = if spatial.len() == 1 {
            spatial.into_iter().next().expect("one spatial schema")
        } else {
            json!({"oneOf": spatial})
        };
        content.insert("application/geo+json".into(), json!({"schema": schema}));
    }
    Value::Object(content)
}

fn geojson_response_schema(
    registry: &CompiledRegistry,
    operation: &CompiledOperation,
    representation: &crate::model::CompiledRepresentation,
    resource: &CompiledResource,
    include_identity: bool,
) -> Value {
    let mut schema = match &operation.kind {
        OperationKind::List => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["type", "features", "pageInfo", "meta"],
            "properties": {
                "type": {"type": "string", "enum": ["FeatureCollection"]},
                "features": {
                    "type": "array",
                    "items": geojson_feature_schema(registry, representation, resource, false)
                },
                "pageInfo": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["nextCursor"],
                    "properties": {"nextCursor": {"type": ["string", "null"]}}
                },
                "meta": {"type": "object"},
                "conformsTo": json_fg_conforms_to_schema(),
                "featureType": {"type": "string", "enum": [resource.id]}
            },
            "dependentRequired": {
                "conformsTo": ["featureType"],
                "featureType": ["conformsTo"]
            }
        }),
        OperationKind::Read | OperationKind::Lookup { .. } => {
            geojson_feature_schema(registry, representation, resource, true)
        }
    };
    if include_identity {
        schema
            .as_object_mut()
            .expect("GeoJSON schema object")
            .insert(
                "$schema".into(),
                json!("https://json-schema.org/draft/2020-12/schema"),
            );
        schema
            .as_object_mut()
            .expect("GeoJSON schema object")
            .insert(
                "$id".into(),
                json!(representation
                    .schema_reference
                    .strip_suffix("-schema")
                    .map(|base| format!("{base}-geojson-schema"))
                    .unwrap_or_else(|| format!("{}-geojson", representation.schema_reference))),
            );
    }
    schema
}

fn geojson_feature_schema(
    registry: &CompiledRegistry,
    representation: &crate::model::CompiledRepresentation,
    resource: &CompiledResource,
    require_meta: bool,
) -> Value {
    let mut required = vec![
        json!("type"),
        json!("id"),
        json!("geometry"),
        json!("properties"),
    ];
    if require_meta {
        required.push(json!("meta"));
    }
    let mut properties = json!({
        "type": {"type": "string", "enum": ["Feature"]},
        "id": {"type": "string", "minLength": 1},
        "geometry": {
            "oneOf": [point_geometry_schema(), {"type": "null"}]
        },
        "properties": geojson_record_properties_schema(registry, representation, resource)
    });
    if require_meta {
        let properties = properties
            .as_object_mut()
            .expect("Feature properties schema is an object");
        properties.insert("meta".into(), json!({"type": "object"}));
        properties.insert("conformsTo".into(), json_fg_conforms_to_schema());
        properties.insert(
            "featureType".into(),
            json!({"type": "string", "enum": [resource.id]}),
        );
    }
    let mut schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    });
    if require_meta {
        schema
            .as_object_mut()
            .expect("Feature schema is an object")
            .insert(
                "dependentRequired".into(),
                json!({
                    "conformsTo": ["featureType"],
                    "featureType": ["conformsTo"]
                }),
            );
    }
    schema
}

fn geojson_record_properties_schema(
    registry: &CompiledRegistry,
    representation: &crate::model::CompiledRepresentation,
    resource: &CompiledResource,
) -> Value {
    let geometry_name = resource
        .primary_geometry
        .as_ref()
        .map(|geometry| geometry.name.as_str());
    let selected = representation
        .selectable_properties
        .iter()
        .filter(|property| Some(property.as_str()) != geometry_name)
        .cloned()
        .collect::<Vec<_>>();
    let mut schema = representation_schema(
        registry,
        resource,
        &selected,
        &representation.schema_reference,
        &representation.semantic_model_reference,
    );
    let object = schema
        .as_object_mut()
        .expect("Registry Record schema is an object");
    object.remove("$schema");
    object.remove("$id");
    schema
}

fn point_geometry_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "coordinates"],
        "properties": {
            "type": {"type": "string", "enum": ["Point"]},
            "coordinates": {
                "type": "array",
                "prefixItems": [
                    {"type": "number", "minimum": -180, "maximum": 180},
                    {"type": "number", "minimum": -90, "maximum": 90}
                ],
                "items": false,
                "minItems": 2,
                "maxItems": 2
            }
        }
    })
}

fn json_fg_conforms_to_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "string",
            "enum": [JSON_FG_CORE_CONFORMANCE, JSON_FG_TYPES_CONFORMANCE]
        },
        "minItems": 2,
        "maxItems": 2,
        "uniqueItems": true
    })
}

fn consultation_pattern(pattern: ConsultationPattern) -> &'static str {
    match pattern {
        ConsultationPattern::List => "list",
        ConsultationPattern::Retrieve => "retrieve",
        ConsultationPattern::Search => "search",
    }
}

fn supports_geojson(
    resource: &CompiledResource,
    representation: &crate::model::CompiledRepresentation,
) -> bool {
    resource.primary_geometry.as_ref().is_some_and(|geometry| {
        representation
            .selectable_properties
            .iter()
            .any(|property| property == &geometry.name)
    })
}

fn response_format_documents(
    resource: &CompiledResource,
    representation: &crate::model::CompiledRepresentation,
) -> Vec<Value> {
    let mut formats = vec![
        json!({"id": "json", "mediaType": "application/json", "profiles": []}),
        json!({"id": "json-ld", "mediaType": "application/ld+json", "profiles": []}),
    ];
    if supports_geojson(resource, representation) {
        formats.push(json!({
            "id": "geojson",
            "mediaType": "application/geo+json",
            "profiles": [
                representation_profile(RepresentationProfile::Rfc7946),
                representation_profile(RepresentationProfile::JsonFg),
            ],
        }));
    }
    formats
}

fn representation_profile(profile: RepresentationProfile) -> Value {
    match profile {
        RepresentationProfile::Rfc7946 => json!({
            "id": "rfc7946",
            "uri": RFC7946_PROFILE_URI,
            "crs": CRS84_URI,
        }),
        RepresentationProfile::JsonFg => json!({
            "id": "jsonfg",
            "uri": JSON_FG_PROFILE_URI,
            "crs": CRS84_URI,
            "conformsTo": [JSON_FG_CORE_CONFORMANCE, JSON_FG_TYPES_CONFORMANCE],
        }),
    }
}

fn openapi_type(data_type: crate::contract::DataType) -> Value {
    use crate::contract::DataType;
    match data_type {
        DataType::String | DataType::ControlledCode => json!({"type": "string"}),
        DataType::Boolean => json!({"type": "boolean"}),
        DataType::Integer => json!({"type": "integer"}),
        DataType::Date => json!({"type": "string", "format": "date"}),
        DataType::DateTime => json!({"type": "string", "format": "date-time"}),
        DataType::Year => json!({
            "type": "string",
            "pattern": "^[0-9]{4}$",
            "x-registry-datatype": "year"
        }),
        DataType::YearMonth => json!({
            "type": "string",
            "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])$",
            "x-registry-datatype": "year-month"
        }),
    }
}

#[derive(Clone, Copy)]
enum CapabilityProjection<'a> {
    Public,
    Full,
    Representation(&'a str, &'a str),
}

fn capability_inventory(
    registry: &CompiledRegistry,
    projection: CapabilityProjection<'_>,
) -> Value {
    let capabilities = registry
        .resources
        .iter()
        .flat_map(|resource| {
            resource.operations.iter().flat_map(move |operation| {
                operation.representations.iter().filter_map(move |representation| {
                    let include = match projection {
                        CapabilityProjection::Public => {
                            matches!(&representation.access, CompiledAccess::Public)
                        }
                        CapabilityProjection::Full => true,
                        CapabilityProjection::Representation(
                            operation_identifier,
                            representation_identifier,
                        ) => {
                            operation.identifier == operation_identifier
                                && representation.id == representation_identifier
                        }
                    };
                    if !include {
                        return None;
                    }
                    let pattern = match &operation.kind {
                        OperationKind::List => "list",
                        OperationKind::Read => "retrieve",
                        OperationKind::Lookup { .. } => "search",
                    };
                    Some(json!({
                        "resource": resource.id,
                        "operationIdentifier": operation.identifier,
                        "representationIdentifier": representation.id,
                        "defaultRepresentation": operation.default_representation == representation.id,
                        "family": "consultation",
                        "pattern": pattern,
                        "profile": if matches!(&operation.kind, OperationKind::Lookup { .. }) { Value::String("exact".into()) } else { Value::Null },
                        "schemaReference": representation.schema_reference,
                        "semanticModelReference": representation.semantic_model_reference,
                        "contextReference": representation.context_reference,
                        "formats": response_format_documents(resource, representation),
                        "spatialQuery": operation.query.spatial_bbox.as_ref().map(|spatial| json!({
                            "bbox": {
                                "crs": CRS84_URI,
                                "predicate": "exact-point-intersection",
                                "maximumLongitudeSpanDegrees": spatial.maximum_longitude_span_degrees,
                                "maximumLatitudeSpanDegrees": spatial.maximum_latitude_span_degrees,
                            }
                        })),
                    }))
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "registryIdentifier": registry.registry_identifier,
        "authorityIdentifier": registry.authority_identifier,
        "contractRevision": registry.contract_revision,
        "apiBinding": {"name": "registry-relay", "version": "v2alpha1"},
        "alignmentTargets": registry.alignment_targets,
        "metadataVisibility": registry.metadata_visibility,
        "capabilities": capabilities,
        "unsupportedFamilies": ["provisioning", "evidence", "write", "notification", "aggregate-data", "access-transparency", "identity-federation"]
    })
}

fn audit_event_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://id.registrystack.org/schemas/registry-relay/audit-event/v2alpha1",
        "title": "Registry Relay value-free consultation audit event",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema", "phase", "operationId", "traceId", "registryIdentifier",
            "rowBoundaryKind", "processingDescriptionIdentifiers", "selectedProperties",
            "transformIdentifiers", "contractRevision", "principalKind"
        ],
        "properties": {
            "schema": {"const": crate::audit::AUDIT_SCHEMA},
            "phase": {"enum": ["attempt", "refusal", "terminal"]},
            "operationId": {"type": "string", "minLength": 1},
            "traceId": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
            "registryIdentifier": {"type": "string", "minLength": 1},
            "resourceIdentifier": {"type": "string", "minLength": 1},
            "operationIdentifier": {"type": "string", "minLength": 1},
            "accessRuleRevision": {"type": "string", "minLength": 1},
            "purpose": {"type": "string", "minLength": 1},
            "rowBoundaryKind": {"enum": ["none", "principal", "verified-claim", "unknown"]},
            "representation": {"type": "string", "minLength": 1},
            "disclosureProfile": {"type": "string", "minLength": 1},
            "processingDescriptionIdentifiers": {"type": "array", "items": {"type": "string", "minLength": 1}, "uniqueItems": true},
            "selectedProperties": {"type": "array", "items": {"type": "string", "minLength": 1}, "uniqueItems": true},
            "processingHandling": {"enum": ["public", "internal", "confidential", "restricted"]},
            "disclosureHandling": {"enum": ["public", "internal", "confidential", "restricted"]},
            "transformIdentifiers": {"type": "array", "items": {"type": "string", "minLength": 1}, "uniqueItems": true},
            "contractRevision": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "sourceRevision": {
                "type": "object",
                "additionalProperties": false,
                "required": ["profile", "status", "value"],
                "properties": {
                    "profile": {"enum": ["snapshot", "live"]},
                    "status": {"enum": ["versioned", "unversioned"]},
                    "value": {"type": ["string", "null"]}
                }
            },
            "principalKind": {"enum": ["anonymous", "authenticated", "unknown"]},
            "outcome": {"enum": [
                "released", "not-modified", "unresolved", "invalid-request",
                "missing-credential", "invalid-credential", "denied", "rate-limited",
                "timed-out", "source-failed", "internal-failed", "not-found"
            ]}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_contract_with_governed_files, tests as compiler_tests};
    use crate::contract::RegistryContract;
    use crate::model::{CompileProfile, CompiledRegistry};

    #[test]
    fn generated_inventory_covers_required_v1_artifact_classes_only() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        let paths = generated
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect::<BTreeSet<_>>();

        for required in [
            "openapi.full.yaml",
            "openapi.public.json",
            "artifacts/audit-event.schema.json",
            "artifacts/capabilities.json",
            "artifacts/capabilities.full.json",
            "artifacts/record.full.schema.json",
            "artifacts/record.full.shacl.ttl",
            "artifacts/record.full.vocabulary.jsonld",
            "artifacts/record--read--representation-public.schema.json",
            "artifacts/record--read--representation-public.shacl.ttl",
            "artifacts/record--read--representation-public.context.jsonld",
            "artifacts/record--read--representation-public.vocabulary.jsonld",
        ] {
            assert!(paths.contains(required), "missing {required}");
        }
        for deferred in [
            "artifacts/registry-manifest.yaml",
            "artifacts/standards-alignment.json",
            "artifacts/safeguards-matrix.yaml",
        ] {
            assert!(!paths.contains(deferred), "deferred artifact {deferred}");
        }
    }

    #[test]
    fn generated_openapi_covers_router_paths_and_public_is_a_full_subset() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        let full: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI is JSON-compatible YAML");
        let public: Value = serde_json::from_slice(
            &generated
                .get("openapi.public.json")
                .expect("public OpenAPI")
                .content,
        )
        .expect("public OpenAPI JSON");
        serde_json::from_slice::<utoipa::openapi::OpenApi>(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI conforms to the maintained OpenAPI model");
        serde_json::from_slice::<utoipa::openapi::OpenApi>(
            &generated
                .get("openapi.public.json")
                .expect("public OpenAPI")
                .content,
        )
        .expect("public OpenAPI conforms to the maintained OpenAPI model");

        for path in [
            "/health",
            "/ready",
            "/openapi.json",
            "/v2",
            "/v2/resources",
            "/v2/resources/{resource}",
            "/v2/resources/record/records/{recordIdentifier}",
            "/v2/artifacts/{artifactIdentifier}",
        ] {
            assert!(full["paths"].get(path).is_some(), "missing {path}");
        }
        for (path, definition) in public["paths"].as_object().expect("public paths") {
            assert_eq!(
                full["paths"].get(path),
                Some(definition),
                "public path {path} must be byte-semantically identical in full OpenAPI"
            );
        }
        assert_eq!(
            full["components"]["securitySchemes"]["bearerAuth"]["type"],
            "http"
        );
        assert!(full["components"]["securitySchemes"]
            .get("oauth2")
            .is_none());
    }

    #[test]
    fn configured_metadata_visibility_drives_safe_operation_projections() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.resources[0].operations[0].representations[0].access = CompiledAccess::Protected {
            scope: "records:read".into(),
            purpose: None,
            row_binding: None,
        };
        registry.metadata_visibility.semantics = Visibility::OperationBound;
        registry.metadata_visibility.classifications = Visibility::OperationBound;
        registry.metadata_visibility.processing = Visibility::OperationBound;
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        for id in [
            "record--read--representation-public-vocabulary",
            "record--read--representation-public-context",
            "record--read--representation-public-schema",
            "record--read--representation-public-shacl",
            "record--read--representation-public-classifications",
            "record--read--representation-public-processing",
        ] {
            let artifact = generated
                .artifacts
                .iter()
                .find(|artifact| artifact.id == id)
                .unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(artifact.visibility, Visibility::OperationBound);
            assert_eq!(
                artifact.operation_identifier.as_deref(),
                Some("record.read")
            );
            assert_eq!(
                artifact.representation_identifier.as_deref(),
                Some("public")
            );
        }

        registry.metadata_visibility.semantics = Visibility::Public;
        registry.metadata_visibility.classifications = Visibility::OperatorOnly;
        registry.metadata_visibility.processing = Visibility::OperatorOnly;
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        assert_eq!(
            generated
                .artifacts
                .iter()
                .find(|artifact| {
                    artifact.id == "record--read--representation-public-vocabulary"
                })
                .expect("semantic projection")
                .visibility,
            Visibility::OperationBound
        );
        for id in [
            "record--read--representation-public-classifications",
            "record--read--representation-public-processing",
        ] {
            assert_eq!(
                generated
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.id == id)
                    .unwrap_or_else(|| panic!("missing {id}"))
                    .visibility,
                Visibility::OperatorOnly
            );
        }
    }

    #[test]
    fn spatial_artifacts_are_deterministic_bounded_and_carrier_free() {
        let registry = spatial_registry(CompiledAccess::Public);
        let generated = generate_artifacts(&registry).expect("spatial artifacts generate");
        assert_eq!(
            generated,
            generate_artifacts(&registry).expect("repeat generation")
        );

        let geojson_schema = generated
            .get("artifacts/record--list--representation-public.geojson.schema.json")
            .expect("GeoJSON wrapper schema");
        let schema: Value = serde_json::from_slice(&geojson_schema.content).expect("schema JSON");
        assert_eq!(schema["properties"]["type"]["enum"][0], "FeatureCollection");
        assert_eq!(
            schema["properties"]["features"]["items"]["properties"]["geometry"]["oneOf"][0]
                ["properties"]["type"]["enum"][0],
            "Point"
        );
        let coordinates = &schema["properties"]["features"]["items"]["properties"]["geometry"]
            ["oneOf"][0]["properties"]["coordinates"];
        assert_eq!(coordinates["prefixItems"][0]["minimum"], -180);
        assert_eq!(coordinates["prefixItems"][0]["maximum"], 180);
        assert_eq!(coordinates["prefixItems"][1]["minimum"], -90);
        assert_eq!(coordinates["prefixItems"][1]["maximum"], 90);
        assert_eq!(coordinates["items"], false);

        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("generated GeoJSON schema compiles");
        let resource = &registry.resources[0];
        let operation = &resource.operations[0];
        let representation = &operation.representations[0];
        let lifecycle = registry.codelists[0].values[0].clone();
        let point = json!({"type": "Point", "coordinates": [100.0, 13.0]});
        let record = json!({
            "registryIdentifier": registry.registry_identifier,
            "recordIdentifier": "record-1",
            "revisionIdentifier": "revision-1",
            "lifecycleState": lifecycle,
            "schemaReference": representation.schema_reference,
            "semanticModelReference": representation.semantic_model_reference,
            "authorityIdentifier": registry.authority_identifier,
            "recordedAt": "2026-08-10T00:00:00Z",
            "domainData": {"name": "Example"}
        });
        let feature = json!({
            "type": "Feature",
            "id": "https://example.invalid/records/record-1",
            "geometry": point,
            "properties": record
        });
        let rfc_response = json!({
            "type": "FeatureCollection",
            "features": [feature],
            "pageInfo": {"nextCursor": null},
            "meta": {}
        });
        assert!(validator.is_valid(&rfc_response));

        let mut json_fg_response = rfc_response.clone();
        json_fg_response["conformsTo"] =
            json!([JSON_FG_CORE_CONFORMANCE, JSON_FG_TYPES_CONFORMANCE]);
        json_fg_response["featureType"] = json!(resource.id);
        assert!(validator.is_valid(&json_fg_response));

        let mut nested_json_fg_metadata = json_fg_response.clone();
        nested_json_fg_metadata["features"][0]["conformsTo"] =
            json!([JSON_FG_CORE_CONFORMANCE, JSON_FG_TYPES_CONFORMANCE]);
        nested_json_fg_metadata["features"][0]["featureType"] = json!(resource.id);
        assert!(
            !validator.is_valid(&nested_json_fg_metadata),
            "JSON-FG conformance metadata is permitted only on the root object"
        );

        let mut duplicate_geometry = rfc_response;
        duplicate_geometry["features"][0]["properties"]["domainData"]["location"] =
            json!({"type": "Point", "coordinates": [101.0, 14.0]});
        assert!(
            !validator.is_valid(&duplicate_geometry),
            "Feature geometry cannot be repeated or contradicted in properties.domainData"
        );

        let openapi: Value = serde_json::from_slice(
            &generated
                .get("openapi.public.json")
                .expect("public OpenAPI")
                .content,
        )
        .expect("OpenAPI JSON");
        serde_json::from_value::<utoipa::openapi::OpenApi>(openapi.clone())
            .expect("spatial OpenAPI conforms to the maintained OpenAPI model");
        let operation = &openapi["paths"]["/v2/resources/record/records"]["get"];
        assert_eq!(operation["x-registry-pattern"], "search");
        assert!(operation["responses"]["200"]["content"]
            .get("application/geo+json")
            .is_some());
        let bbox = operation["parameters"]
            .as_array()
            .expect("parameters")
            .iter()
            .find(|parameter| parameter["name"] == "bbox")
            .expect("bbox parameter");
        assert_eq!(bbox["schema"]["minItems"], 4);
        assert_eq!(bbox["explode"], false);

        let capabilities = generated
            .get("artifacts/capabilities.json")
            .expect("public capabilities");
        let encoded = String::from_utf8(capabilities.content.clone()).expect("UTF-8 capability");
        assert!(encoded.contains("exact-point-intersection"));
        assert!(encoded.contains(JSON_FG_PROFILE_URI));
        assert!(!encoded.contains("longitude_col"));
        assert!(!encoded.contains("latitude_col"));
        assert!(!encoded.to_ascii_lowercase().contains("spatialite"));
        assert!(!encoded.to_ascii_lowercase().contains("geopackage"));
        assert!(!encoded.contains("ogcapi-features"));
    }

    #[test]
    fn public_projection_does_not_reveal_protected_spatial_capability() {
        let registry = spatial_registry(CompiledAccess::Protected {
            scope: "registry:spatial:read".into(),
            purpose: None,
            row_binding: None,
        });
        let generated = generate_artifacts(&registry).expect("spatial artifacts generate");
        let public_openapi = String::from_utf8(
            generated
                .get("openapi.public.json")
                .expect("public OpenAPI")
                .content
                .clone(),
        )
        .expect("UTF-8 OpenAPI");
        let public_capabilities = String::from_utf8(
            generated
                .get("artifacts/capabilities.json")
                .expect("public capabilities")
                .content
                .clone(),
        )
        .expect("UTF-8 capabilities");
        assert!(!public_openapi.contains("application/geo+json"));
        assert!(!public_openapi.contains("exact-point-intersection"));
        assert!(!public_capabilities.contains("application/geo+json"));
        assert!(!public_capabilities.contains("exact-point-intersection"));

        let operation_capability = generated
            .get("artifacts/record--list--representation-public.capability.json")
            .expect("operation-bound capability");
        assert_eq!(operation_capability.visibility, Visibility::OperationBound);
        assert_eq!(
            operation_capability.operation_identifier.as_deref(),
            Some("record.list")
        );
        let encoded = String::from_utf8(operation_capability.content.clone())
            .expect("UTF-8 operation capability");
        assert!(encoded.contains("application/geo+json"));
        assert!(!encoded.contains("longitude_col"));
        assert!(!encoded.contains("latitude_col"));
    }

    fn spatial_registry(access: CompiledAccess) -> CompiledRegistry {
        let contract = compiler_tests::spatial_contract(true);
        let governed_files = compiler_tests::governed_files_for(&contract);
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::spatial_observed_schema()],
            CompileProfile::Production,
            &governed_files,
        )
        .expect("contract compiles");
        registry.resources[0].operations[0].representations[0].access = access;
        registry
    }
}
