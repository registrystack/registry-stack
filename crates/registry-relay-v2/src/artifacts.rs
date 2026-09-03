// SPDX-License-Identifier: Apache-2.0
//! Repeatable artifacts generated only from the immutable compiled Registry.

use std::collections::BTreeSet;

use registry_discovery_profile::{
    render_description, DiscoveryDescription, ServiceDescription, ServiceKind, ServiceRoles,
    MEDIA_TYPE as DISCOVERY_MEDIA_TYPE,
};
use registry_platform_canonical_json::canonicalize_json;
use registry_relay_http_contract::{routes, PROBLEM_MEDIA_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contract::Visibility;
use crate::format_capabilities::{
    response_format_capabilities, supports_geojson, CRS84_URI, JSON_FG_CORE_CONFORMANCE,
    JSON_FG_TYPES_CONFORMANCE,
};
use crate::model::{CompiledAccess, CompiledRegistry, CompiledResource, OperationKind};
use crate::sdmx::{
    serialize_structure_json, StructureKind, DATA_CSV_MEDIA_TYPE, DATA_JSON_MEDIA_TYPE,
    STRUCTURE_JSON_MEDIA_TYPE,
};
use crate::semantics::{
    access_profile_schema, access_profile_shacl, full_record_schema, full_record_shacl,
    json_ld_context, local_vocabulary,
};

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
    /// Present for operation-bound Record artifacts and every statistical
    /// structure artifact. The HTTP layer uses the latter ownership link to
    /// prove it serves bytes generated for the exact parent capability.
    pub operation_identifier: Option<String>,
    /// Records bind to one finite access profile when operation-bound;
    /// statistical structures always bind to their dataset's fixed operation.
    pub access_binding: Option<ArtifactAccessBinding>,
    pub sha256: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ArtifactAccessBinding {
    AccessProfile { identifier: String },
    FixedOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperationArtifactBindings {
    pub operation_identifier: String,
    pub access_profile_identifier: String,
    pub vocabulary_path: String,
    pub context_path: String,
    pub access_profile_schema_path: String,
    pub access_profile_shacl_path: String,
    pub classification_path: String,
    pub processing_path: String,
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("generated JSON could not be canonicalized")]
    CanonicalJson,
    #[error("a compiled operation refers to a missing disclosure profile")]
    MissingDisclosure,
    #[error("a compiled statistical structure could not be serialized")]
    StatisticalStructure,
    #[error("the compiled public discovery description is invalid")]
    DiscoveryDescription,
}

pub fn generate_artifacts(registry: &CompiledRegistry) -> Result<ArtifactSet, ArtifactError> {
    let mut artifacts = Vec::new();
    let mut bindings = Vec::new();

    if let Some(publication) = &registry.publication {
        push_text(
            &mut artifacts,
            "discovery-description",
            "artifacts/discovery.jsonld",
            DISCOVERY_MEDIA_TYPE,
            Visibility::Public,
            None,
            discovery_description(registry, &publication.jurisdictions)?,
        );
    }

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
                })).collect::<Vec<_>>(),
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
            for access_profile in &operation.access_profiles {
                let disclosure = resource
                    .disclosure_profiles
                    .iter()
                    .find(|profile| profile.id == access_profile.disclosure_profile)
                    .ok_or(ArtifactError::MissingDisclosure)?;
                let suffix =
                    access_profile_artifact_stem(&resource.id, &operation.kind, &access_profile.id);
                if matches!(&access_profile.access, CompiledAccess::Protected { .. }) {
                    push_access_profile_json(
                        &mut artifacts,
                        &format!("{suffix}-capability"),
                        &format!("artifacts/{suffix}.capability.json"),
                        "application/json",
                        Visibility::OperationBound,
                        &operation.identifier,
                        &access_profile.id,
                        &capability_inventory(
                            registry,
                            CapabilityProjection::AccessProfile(
                                &operation.identifier,
                                &access_profile.id,
                            ),
                        ),
                    )?;
                }
                let semantic_visibility = projection_visibility(
                    registry.metadata_visibility.semantics,
                    &access_profile.access,
                );
                let vocabulary_path = format!("artifacts/{suffix}.vocabulary.jsonld");
                let context_path = format!("artifacts/{suffix}.context.jsonld");
                let schema_path = format!("artifacts/{suffix}.schema.json");
                let shacl_path = format!("artifacts/{suffix}.shacl.ttl");
                let classification_path = format!("artifacts/{suffix}.classifications.json");
                let processing_path = format!("artifacts/{suffix}.processing.json");
                push_access_profile_json(
                    &mut artifacts,
                    &format!("{suffix}-vocabulary"),
                    &vocabulary_path,
                    "application/ld+json",
                    semantic_visibility,
                    &operation.identifier,
                    &access_profile.id,
                    &local_vocabulary(registry, resource, &disclosure.properties),
                )?;
                push_access_profile_json(
                    &mut artifacts,
                    &format!("{suffix}-context"),
                    &context_path,
                    "application/ld+json",
                    semantic_visibility,
                    &operation.identifier,
                    &access_profile.id,
                    &json_ld_context(registry, resource, &disclosure.properties),
                )?;
                push_access_profile_json(
                    &mut artifacts,
                    &format!("{suffix}-schema"),
                    &schema_path,
                    "application/schema+json",
                    semantic_visibility,
                    &operation.identifier,
                    &access_profile.id,
                    &access_profile_schema(
                        registry,
                        resource,
                        &disclosure.properties,
                        &access_profile.schema_reference,
                        &access_profile.semantic_model_reference,
                    ),
                )?;
                if supports_geojson(resource, access_profile) {
                    push_access_profile_json(
                        &mut artifacts,
                        &format!("{suffix}-geojson-schema"),
                        &format!("artifacts/{suffix}.geojson.schema.json"),
                        "application/schema+json",
                        semantic_visibility,
                        &operation.identifier,
                        &access_profile.id,
                        &geojson_response_schema(
                            registry,
                            operation,
                            access_profile,
                            resource,
                            true,
                        ),
                    )?;
                }
                push_access_profile_text(
                    &mut artifacts,
                    &format!("{suffix}-shacl"),
                    &shacl_path,
                    "text/turtle",
                    semantic_visibility,
                    &operation.identifier,
                    &access_profile.id,
                    access_profile_shacl(registry, resource, &disclosure.properties).into_bytes(),
                );
                let classification_visibility = projection_visibility(
                    registry.metadata_visibility.classifications,
                    &access_profile.access,
                );
                push_access_profile_json(
                    &mut artifacts,
                    &format!("{suffix}-classifications"),
                    &classification_path,
                    "application/json",
                    classification_visibility,
                    &operation.identifier,
                    &access_profile.id,
                    &json!({
                        "resourceIdentifier": resource.id,
                        "operationIdentifier": operation.identifier,
                        "accessProfileIdentifier": access_profile.id,
                        "disclosureProfile": access_profile.disclosure_profile,
                        "processingHandling": access_profile.processing_handling,
                        "disclosureHandling": access_profile.disclosure_handling,
                        "transformIdentifiers": access_profile.transform_inventory,
                        "properties": resource.properties.iter()
                            .filter(|property| disclosure.properties.contains(&property.name))
                            .map(|property| json!({
                                "property": property.name,
                                "classification": property.classification,
                                "transform": property.scalar_binding()
                                    .and_then(|binding| binding.transform.as_ref()),
                            }))
                            .collect::<Vec<_>>(),
                    }),
                )?;
                let processing_visibility = projection_visibility(
                    registry.metadata_visibility.processing,
                    &access_profile.access,
                );
                let operation_ref = operation_contract_reference(&operation.kind);
                push_access_profile_json(
                    &mut artifacts,
                    &format!("{suffix}-processing"),
                    &processing_path,
                    "application/json",
                    processing_visibility,
                    &operation.identifier,
                    &access_profile.id,
                    &json!({
                        "resourceIdentifier": resource.id,
                        "operationIdentifier": operation.identifier,
                        "accessProfileIdentifier": access_profile.id,
                        "processingHandling": access_profile.processing_handling,
                        "disclosureHandling": access_profile.disclosure_handling,
                        "transformIdentifiers": access_profile.transform_inventory,
                        "descriptions": resource.processing_descriptions.iter()
                            .filter(|description| description.operation_refs.contains(&operation_ref))
                            .collect::<Vec<_>>(),
                    }),
                )?;
                bindings.push(OperationArtifactBindings {
                    operation_identifier: operation.identifier.clone(),
                    access_profile_identifier: access_profile.id.clone(),
                    vocabulary_path,
                    context_path,
                    access_profile_schema_path: schema_path,
                    access_profile_shacl_path: shacl_path,
                    classification_path,
                    processing_path,
                });
            }
        }

        let codelists = resource
            .properties
            .iter()
            .filter_map(|property| {
                property
                    .scalar_binding()
                    .and_then(|binding| binding.codelist.as_deref())
            })
            .chain(std::iter::once(
                resource.record_context.lifecycle_state_codelist.as_str(),
            ))
            .map(str::to_owned)
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

    for dataset in &registry.statistical_datasets {
        let visibility = projection_visibility(
            registry
                .metadata_visibility
                .statistical_datasets
                .unwrap_or(Visibility::OperatorOnly),
            &dataset.access,
        );
        let operation_identifier = dataset.operation_identifier();
        for (kind, id_suffix, path_suffix) in [
            (StructureKind::Dataflow, "dataflow", "sdmx.dataflow.json"),
            (
                StructureKind::DataStructure,
                "datastructure",
                "sdmx.datastructure.json",
            ),
        ] {
            let content = serialize_structure_json(dataset, kind)
                .map_err(|_| ArtifactError::StatisticalStructure)?;
            push_fixed_operation_text(
                &mut artifacts,
                &format!("{}-sdmx-{id_suffix}-structure", dataset.id),
                &format!("artifacts/{}.{path_suffix}", dataset.id),
                STRUCTURE_JSON_MEDIA_TYPE,
                visibility,
                &operation_identifier,
                content,
            );
        }
    }

    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    bindings.sort_by(|left, right| {
        left.operation_identifier
            .cmp(&right.operation_identifier)
            .then(
                left.access_profile_identifier
                    .cmp(&right.access_profile_identifier),
            )
    });
    Ok(ArtifactSet {
        contract_revision: registry.contract_revision.clone(),
        artifacts,
        operation_bindings: bindings,
    })
}

/// Product-owned identifier for the Relay response compatibility line that
/// adopts the shared Registry Record profile.
pub const RELAY_PROFILE_ID: &str = "https://registrystack.org/relay/profile/v3";
pub const REGISTRY_RECORD_PROFILE_ID: &str =
    "https://id.registrystack.org/profiles/registry-record/v1";
pub const REGISTRY_RECORD_CONTEXT_ID: &str =
    "https://id.registrystack.org/contexts/registry-record/v1";
const CONSULTATION_LIST_FAMILY: &str =
    "https://registrystack.org/discovery/operation-family/relay-v2/consultation-list";
const CONSULTATION_RETRIEVE_FAMILY: &str =
    "https://registrystack.org/discovery/operation-family/relay-v2/consultation-retrieve";
const CONSULTATION_SEARCH_FAMILY: &str =
    "https://registrystack.org/discovery/operation-family/relay-v2/consultation-search";
const AGGREGATE_DATA_STATISTICAL_DATAFLOW_FAMILY: &str =
    "https://registrystack.org/discovery/operation-family/relay-v2/statistical-dataflow";

pub(crate) fn discovery_description(
    registry: &CompiledRegistry,
    jurisdictions: &[String],
) -> Result<Vec<u8>, ArtifactError> {
    let mut bindings: BTreeSet<(Vec<String>, Vec<String>)> = BTreeSet::new();
    if registry.metadata_visibility.resources != Visibility::OperatorOnly {
        for resource in &registry.resources {
            for operation in &resource.operations {
                if operation
                    .access_profiles
                    .iter()
                    .any(|profile| matches!(profile.access, CompiledAccess::Public))
                {
                    bindings.insert((
                        vec![resource.semantic_class.clone()],
                        vec![operation_family(operation.pattern).to_owned()],
                    ));
                }
            }
        }
    }
    if registry.statistical_datasets.iter().any(|dataset| {
        projection_visibility(
            registry
                .metadata_visibility
                .statistical_datasets
                .unwrap_or(Visibility::OperatorOnly),
            &dataset.access,
        ) == Visibility::Public
    }) {
        bindings.insert((
            Vec::new(),
            vec![AGGREGATE_DATA_STATISTICAL_DATAFLOW_FAMILY.to_owned()],
        ));
    }
    let roles = ServiceRoles {
        publisher_id: Some(registry.publisher_identifier.clone()),
        operator_id: registry.operator_identifier.clone(),
        registry_authority_id: Some(registry.authority_identifier.clone()),
        legal_issuer_id: None,
        technical_provider_id: None,
    };
    let exact_bindings = if bindings.is_empty() {
        vec![(Vec::new(), Vec::new())]
    } else {
        bindings.into_iter().collect()
    };
    let services = exact_bindings
        .into_iter()
        .map(|(semantic_class_ids, operation_family_ids)| {
            ServiceDescription::new(
                registry.registry_identifier.clone(),
                ServiceKind::Relay,
                registry.registry_name.clone(),
                registry.authoritative_scope.clone(),
                registry.base_uri.clone(),
                roles.clone(),
                jurisdictions.to_vec(),
                vec![
                    REGISTRY_RECORD_PROFILE_ID.to_owned(),
                    RELAY_PROFILE_ID.to_owned(),
                ],
                Vec::new(),
                semantic_class_ids,
                operation_family_ids,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ArtifactError::DiscoveryDescription)?;
    render_description(
        &DiscoveryDescription::new(services).map_err(|_| ArtifactError::DiscoveryDescription)?,
    )
    .map_err(|_| ArtifactError::DiscoveryDescription)
}

const fn operation_family(pattern: crate::model::ConsultationPattern) -> &'static str {
    match pattern {
        crate::model::ConsultationPattern::List => CONSULTATION_LIST_FAMILY,
        crate::model::ConsultationPattern::Retrieve => CONSULTATION_RETRIEVE_FAMILY,
        crate::model::ConsultationPattern::Search => CONSULTATION_SEARCH_FAMILY,
    }
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
        OperationKind::Search { name } => format!("search:{name}"),
    }
}

fn operation_artifact_stem(resource: &str, kind: &OperationKind) -> String {
    match kind {
        OperationKind::List => format!("{resource}--list"),
        OperationKind::Read => format!("{resource}--read"),
        OperationKind::Lookup { name } => format!("{resource}--lookup-{name}"),
        OperationKind::Search { name } => format!("{resource}--search-{name}"),
    }
}

fn access_profile_artifact_stem(
    resource: &str,
    kind: &OperationKind,
    access_profile: &str,
) -> String {
    format!(
        "{}--access-profile-{access_profile}",
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
fn push_access_profile_json(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: &str,
    access_profile_identifier: &str,
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
        .expect("an access-profile artifact was appended")
        .access_binding = bound.then(|| ArtifactAccessBinding::AccessProfile {
        identifier: access_profile_identifier.to_owned(),
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_access_profile_text(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: &str,
    access_profile_identifier: &str,
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
        .expect("an access-profile artifact was appended")
        .access_binding = bound.then(|| ArtifactAccessBinding::AccessProfile {
        identifier: access_profile_identifier.to_owned(),
    });
}

#[allow(clippy::too_many_arguments)]
fn push_fixed_operation_text(
    artifacts: &mut Vec<GeneratedArtifact>,
    id: &str,
    path: &str,
    media_type: &str,
    visibility: Visibility,
    operation_identifier: &str,
    content: Vec<u8>,
) {
    push_text(
        artifacts,
        id,
        path,
        media_type,
        visibility,
        Some(operation_identifier.to_owned()),
        content,
    );
    artifacts
        .last_mut()
        .expect("a fixed-operation artifact was appended")
        .access_binding = Some(ArtifactAccessBinding::FixedOperation);
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
        access_binding: None,
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(&content))),
        content,
    });
}

fn openapi(registry: &CompiledRegistry, public_only: bool) -> Value {
    let mut paths = Map::new();
    for (path, operation_id, description) in [
        (routes::HEALTH, "relay.health", "Relay process liveness"),
        (routes::READY, "relay.ready", "Compiled Registry readiness"),
        (
            routes::OPENAPI,
            "relay.openapi.public",
            "Safe public OpenAPI projection",
        ),
        (
            routes::SERVICE,
            "relay.registry.metadata",
            "Registry service metadata",
        ),
    ] {
        let cacheable = path == routes::OPENAPI
            || (path == routes::SERVICE
                && registry.metadata_visibility.resources == Visibility::Public);
        let schema = match path {
            routes::HEALTH | routes::READY => json!({"$ref": "#/components/schemas/Status"}),
            routes::SERVICE => json!({"$ref": "#/components/schemas/ServiceMetadata"}),
            routes::OPENAPI => json!({"type": "object"}),
            _ => unreachable!("fixed OpenAPI path"),
        };
        let mut responses = json!({
            "200": {
                "description": "Successful response",
                "content": {"application/json": {"schema": schema}}
            },
            "default": {"$ref": "#/components/responses/Problem"}
        });
        if cacheable {
            add_not_modified_response(&mut responses);
        }
        paths.insert(
            path.into(),
            json!({"get": {
                "operationId": operation_id,
                "description": description,
                "security": [],
                "responses": responses
            }}),
        );
    }
    if !public_only || registry.metadata_visibility.resources == Visibility::Public {
        let mut list_responses = json!({
            "200": {"description": "Visible Registry resources"},
            "default": {"$ref": "#/components/responses/Problem"}
        });
        let mut retrieve_responses = json!({
            "200": {"description": "Visible Registry resource metadata"},
            "default": {"$ref": "#/components/responses/Problem"}
        });
        if registry.metadata_visibility.resources == Visibility::Public {
            add_not_modified_response(&mut list_responses);
            add_not_modified_response(&mut retrieve_responses);
        }
        paths.insert(
            routes::RESOURCES.into(),
            json!({"get": {
                "operationId": "relay.resources.list",
                "security": if registry.metadata_visibility.resources == Visibility::Public {
                    json!([])
                } else {
                    json!([{"bearerAuth": []}])
                },
                "parameters": [
                    {
                        "name": "pageSize", "in": "query", "required": false,
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50}
                    },
                    {
                        "name": "cursor", "in": "query", "required": false,
                        "schema": {"type": "string", "minLength": 1}
                    }
                ],
                "responses": list_responses
            }}),
        );
        paths.insert(
            routes::RESOURCE.into(),
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
                "responses": retrieve_responses
            }}),
        );
    }
    for resource in &registry.resources {
        for operation in &resource.operations {
            let visible_access_profiles = operation
                .access_profiles
                .iter()
                .filter(|access_profile| {
                    !public_only || matches!(&access_profile.access, CompiledAccess::Public)
                })
                .collect::<Vec<_>>();
            if visible_access_profiles.is_empty() {
                continue;
            }
            let (method, path, pattern) = match &operation.kind {
                OperationKind::List => (
                    "get",
                    format!("/v2/resources/{}/records", resource.id),
                    "list",
                ),
                OperationKind::Read => (
                    "get",
                    format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id),
                    "retrieve",
                ),
                OperationKind::Lookup { name } => (
                    "post",
                    format!("/v2/resources/{}/lookups/{name}", resource.id),
                    "search",
                ),
                OperationKind::Search { name } => (
                    "get",
                    format!("/v2/resources/{}/searches/{name}", resource.id),
                    "search",
                ),
            };
            let has_public = visible_access_profiles
                .iter()
                .any(|access_profile| matches!(&access_profile.access, CompiledAccess::Public));
            let has_protected = visible_access_profiles.iter().any(|access_profile| {
                matches!(&access_profile.access, CompiledAccess::Protected { .. })
            });
            let security = match (has_public, has_protected) {
                (true, true) => json!([{}, {"bearerAuth": []}]),
                (true, false) => json!([]),
                (false, true) => json!([{"bearerAuth": []}]),
                (false, false) => unreachable!("a visible access profile exists"),
            };
            let visible_identifiers = visible_access_profiles
                .iter()
                .map(|access_profile| access_profile.id.clone())
                .collect::<Vec<_>>();
            let visible_default = visible_identifiers
                .contains(&operation.default_access_profile)
                .then(|| operation.default_access_profile.clone());
            let mut access_profile_schema = json!({
                "type": "string",
                "enum": visible_identifiers,
            });
            if let Some(default) = &visible_default {
                access_profile_schema
                    .as_object_mut()
                    .expect("access profile schema object")
                    .insert("default".into(), json!(default));
            }
            let mut parameters = vec![
                json!({
                    "name": "accessProfile",
                    "in": "query",
                    "required": false,
                    "schema": access_profile_schema,
                    "description": "One finite compiled access profile. Absence selects the declared default."
                }),
                json!({
                    "name": "fields",
                    "in": "query",
                    "required": false,
                    "schema": {"type": "string", "minLength": 1},
                    "description": "Duplicate-free comma-separated subset of the selected access profile"
                }),
            ];
            let has_geojson = visible_access_profiles
                .iter()
                .any(|access_profile| supports_geojson(resource, access_profile));
            if has_geojson {
                parameters.push(json!({
                    "name": "formatProfile", "in": "query", "required": false,
                    "schema": {"type": "string", "enum": ["rfc7946", "jsonfg"]},
                    "description": "GeoJSON response profile; valid only when application/geo+json is selected"
                }));
            }
            match &operation.kind {
                OperationKind::List | OperationKind::Search { .. } => {
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
                    if let Some(spatial) = &operation.query.spatial_bbox {
                        parameters.push(json!({
                            "name": "bbox", "in": "query", "required": false,
                            "schema": {"type": "string", "minLength": 7, "maxLength": 256},
                            "description": format!(
                                "Required on the first page and mutually exclusive with cursor. CRS84 west,south,east,north bounds with maximum spans {} by {} degrees",
                                spatial.maximum_longitude_span_degrees,
                                spatial.maximum_latitude_span_degrees,
                            ),
                            "x-registry-crs": CRS84_URI,
                            "x-registry-inclusive": true,
                            "x-registry-required-on-first-page": true,
                            "x-registry-mutually-exclusive-with": "cursor",
                        }));
                    }
                }
                OperationKind::Read => parameters.push(json!({
                    "name": "recordIdentifier", "in": "path", "required": true,
                    "schema": {"type": "string", "minLength": 1}
                })),
                OperationKind::Lookup { .. } => {}
            }
            let mut operation_value = json!({
                "operationId": operation.identifier,
                "x-registry-responseProfile": REGISTRY_RECORD_PROFILE_ID,
                "x-registry-family": "consultation",
                "x-registry-pattern": pattern,
                "x-registry-access-profiles": visible_access_profiles.iter().map(|access_profile| json!({
                    "accessProfileIdentifier": access_profile.id,
                    "isDefault": operation.default_access_profile == access_profile.id,
                    "disclosureProfile": access_profile.disclosure_profile,
                    "processingHandling": access_profile.processing_handling,
                    "disclosureHandling": access_profile.disclosure_handling,
                    "transformIdentifiers": access_profile.transform_inventory,
                    "schemaReference": access_profile.schema_reference,
                    "semanticModelReference": access_profile.semantic_model_reference,
                    "contextReference": access_profile.context_reference,
                    "wireFormats": response_format_capabilities(resource, access_profile),
                })).collect::<Vec<_>>(),
                "security": security,
                "parameters": parameters,
                "responses": {
                    "200": {
                        "description": "A validated minimum-disclosure Registry response",
                        "content": {
                            "application/json": {"schema": operation_response_schema(registry, resource, operation, &visible_access_profiles, false)},
                            "application/ld+json": {"schema": operation_response_schema(registry, resource, operation, &visible_access_profiles, true)}
                        }
                    },
                    "default": {"$ref": "#/components/responses/Problem"}
                }
            });
            if has_geojson {
                let schemas = visible_access_profiles
                    .iter()
                    .filter(|access_profile| supports_geojson(resource, access_profile))
                    .map(|access_profile| {
                        geojson_response_schema(
                            registry,
                            operation,
                            access_profile,
                            resource,
                            false,
                        )
                    })
                    .collect::<Vec<_>>();
                let schema = if schemas.len() == 1 {
                    schemas.into_iter().next().expect("one GeoJSON schema")
                } else {
                    json!({"anyOf": schemas})
                };
                operation_value["responses"]["200"]["content"]
                    .as_object_mut()
                    .expect("OpenAPI response content object")
                    .insert("application/geo+json".into(), json!({"schema": schema}));
            }
            let source_is_snapshot = registry
                .sources
                .iter()
                .find(|source| source.id == operation.query.source)
                .is_some_and(|source| source.profile == crate::contract::SourceProfile::Snapshot);
            let has_cacheable_access_profile =
                visible_access_profiles.iter().any(|access_profile| {
                    matches!(&access_profile.access, CompiledAccess::Public)
                        && access_profile.processing_handling == crate::contract::Handling::Public
                });
            if method == "get" && source_is_snapshot && has_cacheable_access_profile {
                add_not_modified_response(&mut operation_value["responses"]);
            }
            let required_scopes = visible_access_profiles
                .iter()
                .filter_map(|access_profile| match &access_profile.access {
                    CompiledAccess::Public => None,
                    CompiledAccess::Protected { scope, .. } => Some(json!({
                        "accessProfileIdentifier": access_profile.id,
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
                            schema.insert("x-registry-minimum-bytes".into(), json!(minimum));
                        }
                        if let Some(maximum) = selector.maximum_bytes {
                            schema.insert("x-registry-maximum-bytes".into(), json!(maximum));
                        }
                        if selector.minimum_bytes.is_some() || selector.maximum_bytes.is_some() {
                            schema.insert(
                                "description".into(),
                                json!("Selector bounds are measured over its UTF-8 encoded bytes, not Unicode code points."),
                            );
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
                                "required": ["selectors"],
                                "properties": {
                                    "selectors": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": operation.query.selectors.iter().map(|selector| selector.name.clone()).collect::<Vec<_>>(),
                                        "properties": selector_properties,
                                    }
                                },
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
    add_statistical_openapi_paths(registry, public_only, &mut paths);
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
            "responses": {
                "200": {"description": "Generated artifact"},
                "304": {"$ref": "#/components/responses/NotModified"},
                "default": {"$ref": "#/components/responses/Problem"}
            }
        }}),
    );
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": registry.registry_name,
            "version": registry.contract_version,
            "description": "Generated Registry Relay read API. Its SDMX routes are a bounded aligned subset and make no conformance or certification claim."
        },
        "servers": [{"url": registry.base_uri}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            },
            "schemas": {
                "Status": {
                    "type": "object", "additionalProperties": false,
                    "required": ["status"],
                    "properties": {"status": {"type": "string", "enum": ["ok", "ready"]}}
                },
                "ServiceMetadata": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "registryIdentifier", "name", "authority", "operator",
                        "authoritativeScope", "product", "apiBinding", "alignmentTargets",
                        "capabilities", "links"
                    ],
                    "properties": {
                        "registryIdentifier": {"type": "string", "minLength": 1},
                        "name": {"type": "string", "minLength": 1},
                        "authority": {
                            "type": "object", "additionalProperties": false,
                            "required": ["identifier", "name"],
                            "properties": {
                                "identifier": {"type": "string", "minLength": 1},
                                "name": {"type": "string", "minLength": 1}
                            }
                        },
                        "operator": {
                            "type": ["object", "null"],
                            "additionalProperties": false,
                            "required": ["identifier", "name"],
                            "properties": {
                                "identifier": {"type": "string", "minLength": 1},
                                "name": {"type": "string", "minLength": 1}
                            }
                        },
                        "authoritativeScope": {"type": "string", "minLength": 1},
                        "product": {
                            "type": "object", "additionalProperties": false,
                            "required": ["name", "version"],
                            "properties": {
                                "name": {"type": "string", "minLength": 1},
                                "version": {"type": "string", "minLength": 1}
                            }
                        },
                        "apiBinding": {
                            "type": "object", "additionalProperties": false,
                            "required": ["name", "version"],
                            "properties": {
                                "name": {"type": "string", "minLength": 1},
                                "version": {"type": "string", "minLength": 1}
                            }
                        },
                        "alignmentTargets": {
                            "type": "array",
                            "items": {
                                "type": "object", "additionalProperties": false,
                                "required": ["name", "version", "status", "cfrTarget"],
                                "properties": {
                                    "name": {"type": "string", "minLength": 1},
                                    "version": {"type": "string", "minLength": 1},
                                    "status": {"type": "string", "minLength": 1},
                                    "cfrTarget": {"type": ["string", "null"]}
                                }
                            }
                        },
                        "capabilities": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["family", "pattern", "operationIdentifier", "href"],
                                "properties": {
                                    "family": {"type": "string", "minLength": 1},
                                    "pattern": {"type": "string", "minLength": 1},
                                    "operationIdentifier": {"type": "string", "minLength": 1},
                                    "href": {"type": "string", "format": "uri"}
                                }
                            }
                        },
                        "links": {
                            "type": "object", "additionalProperties": false,
                            "required": ["self", "resources", "openapi"],
                            "properties": {
                                "self": {"type": "string", "format": "uri"},
                                "resources": {"type": "string", "format": "uri"},
                                "openapi": {"type": "string", "format": "uri"}
                            }
                        }
                    }
                },
                "Problem": {
                    "type": "object", "additionalProperties": false,
                    "required": ["type", "title", "status", "detail", "code", "traceId"],
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
                "NotModified": {
                    "description": "Not modified; the response body is empty",
                    "headers": {
                        "Cache-Control": {
                            "schema": {"type": "string", "const": "public, no-cache"}
                        },
                        "ETag": {
                            "schema": {"type": "string", "pattern": "^\"[0-9a-f]{64}\"$"}
                        },
                        "Vary": {
                            "schema": {"type": "string", "const": "Accept, Authorization"}
                        }
                    }
                },
                "Problem": {
                    "description": "Registry Stack problem",
                    "content": {(PROBLEM_MEDIA_TYPE): {"schema": {"$ref": "#/components/schemas/Problem"}}}
                }
            }
        }
    })
}

fn add_statistical_openapi_paths(
    registry: &CompiledRegistry,
    public_only: bool,
    paths: &mut Map<String, Value>,
) {
    for dataset in &registry.statistical_datasets {
        let visibility = projection_visibility(
            registry
                .metadata_visibility
                .statistical_datasets
                .unwrap_or(Visibility::OperatorOnly),
            &dataset.access,
        );
        if public_only && visibility != Visibility::Public {
            continue;
        }

        let parent_operation = dataset.operation_identifier();
        let security = if matches!(&dataset.access, CompiledAccess::Public) {
            json!([])
        } else {
            json!([{"bearerAuth": []}])
        };
        let mut data_parameters = vec![
            json!({
                "name": "offset", "in": "query", "required": false,
                "schema": {"type": "integer", "minimum": 0, "maximum": dataset.maximum_offset, "default": 0}
            }),
            json!({
                "name": "limit", "in": "query", "required": false,
                "schema": {"type": "integer", "minimum": 1, "maximum": dataset.maximum_observations, "default": dataset.maximum_observations}
            }),
            json!({
                "name": "dimensionAtObservation", "in": "query", "required": false,
                "schema": {"type": "string", "enum": [dataset.time.id, "AllDimensions"], "default": dataset.time.id}
            }),
        ];
        data_parameters.extend(dataset.dimensions.iter().map(|dimension| {
            json!({
                "name": format!("c[{}]", dimension.id), "in": "query", "required": false,
                "schema": {"type": "string", "minLength": 1}
            })
        }));
        data_parameters.push(json!({
            "name": format!("c[{}]", dataset.time.id), "in": "query", "required": false,
            "schema": {"type": "string", "minLength": 1}
        }));

        let data_base = format!(
            "/sdmx/v2/data/dataflow/{}/{}/{}",
            dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
        );
        for (path, suffix, keyed) in [
            (format!("{data_base}/{{key}}"), "data.keyed", true),
            (data_base, "data.omitted-key", false),
        ] {
            let mut parameters = data_parameters.clone();
            if keyed {
                parameters.insert(
                    0,
                    json!({
                        "name": "key", "in": "path", "required": true,
                        "schema": {"type": "string", "minLength": 1}
                    }),
                );
            }
            let mut responses = statistical_data_responses();
            if visibility == Visibility::Public {
                add_not_modified_response(&mut responses);
            }
            let mut operation = json!({
                "operationId": format!("{parent_operation}.{suffix}"),
                "description": "Read bounded snapshot observations through the aligned SDMX REST subset",
                "x-registry-family": "aggregate-data",
                "x-registry-pattern": "statistical-dataflow",
                "x-registry-capability-operation": parent_operation,
                "security": security,
                "parameters": parameters,
                "responses": responses,
            });
            add_statistical_scope(&mut operation, &dataset.access);
            paths.insert(path, json!({"get": operation}));
        }

        for (path, suffix, description) in [
            (
                format!(
                    "/sdmx/v2/structure/dataflow/{}/{}/{}",
                    dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
                ),
                "structure.dataflow",
                "Read the generated SDMX dataflow structure",
            ),
            (
                format!(
                    "/sdmx/v2/structure/datastructure/{}/{}/{}",
                    dataset.sdmx.agency_id, dataset.sdmx.data_structure_id, dataset.sdmx.version
                ),
                "structure.datastructure",
                "Read the generated SDMX data structure definition",
            ),
        ] {
            let mut responses = statistical_structure_responses();
            if visibility == Visibility::Public {
                add_not_modified_response(&mut responses);
            }
            let mut operation = json!({
                "operationId": format!("{parent_operation}.{suffix}"),
                "description": description,
                "x-registry-family": "aggregate-data",
                "x-registry-pattern": "statistical-dataflow",
                "x-registry-capability-operation": parent_operation,
                "security": security,
                "parameters": [{
                    "name": "references", "in": "query", "required": false,
                    "schema": {"type": "string", "const": "none", "default": "none"}
                }],
                "responses": responses,
            });
            add_statistical_scope(&mut operation, &dataset.access);
            paths.insert(path, json!({"get": operation}));
        }
    }
}

fn add_statistical_scope(operation: &mut Value, access: &CompiledAccess) {
    if let CompiledAccess::Protected { scope, .. } = access {
        operation
            .as_object_mut()
            .expect("statistical OpenAPI operation object")
            .insert("x-registry-required-scope".into(), json!(scope));
    }
}

fn statistical_data_responses() -> Value {
    let mut content = Map::new();
    content.insert(
        DATA_JSON_MEDIA_TYPE.into(),
        json!({"schema": {"type": "object"}}),
    );
    content.insert(
        DATA_CSV_MEDIA_TYPE.into(),
        json!({"schema": {"type": "string"}}),
    );
    json!({
        "200": {
            "description": "A bounded SDMX data message",
            "content": content,
        },
        "default": {"$ref": "#/components/responses/Problem"}
    })
}

fn statistical_structure_responses() -> Value {
    let mut content = Map::new();
    content.insert(
        STRUCTURE_JSON_MEDIA_TYPE.into(),
        json!({"schema": {"type": "object"}}),
    );
    json!({
        "200": {
            "description": "A generated SDMX structure message",
            "content": content,
        },
        "default": {"$ref": "#/components/responses/Problem"}
    })
}

fn add_not_modified_response(responses: &mut Value) {
    responses
        .as_object_mut()
        .expect("OpenAPI responses object")
        .insert(
            "304".into(),
            json!({"$ref": "#/components/responses/NotModified"}),
        );
}

fn operation_response_schema(
    registry: &CompiledRegistry,
    resource: &CompiledResource,
    operation: &crate::model::CompiledOperation,
    access_profiles: &[&crate::model::CompiledAccessProfile],
    json_ld: bool,
) -> Value {
    let meta = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "registryIdentifier", "datasetIdentifier", "entityTypeIdentifier",
            "operationIdentifier", "accessProfile", "family", "pattern",
            "disclosureProfile", "contractRevision", "sourceRevision",
            "selectedFields", "links"
        ],
        "properties": {
            "registryIdentifier": {"type": "string", "const": registry.registry_identifier},
            "datasetIdentifier": {"type": "string", "const": resource.dataset_identifier},
            "entityTypeIdentifier": {"type": "string", "const": resource.entity_type_identifier},
            "operationIdentifier": {"type": "string", "const": operation.identifier},
            "accessProfile": {"type": "string", "enum": access_profiles.iter().map(|profile| profile.id.clone()).collect::<Vec<_>>()},
            "family": {"type": "string", "const": "consultation"},
            "pattern": {"type": "string", "const": match &operation.kind {
                OperationKind::List => "list",
                OperationKind::Read => "retrieve",
                OperationKind::Lookup { .. } | OperationKind::Search { .. } => "search",
            }},
            "disclosureProfile": {"type": "string", "enum": access_profiles.iter().map(|profile| profile.disclosure_profile.clone()).collect::<BTreeSet<_>>()},
            "contractRevision": {"type": "string", "const": registry.contract_revision},
            "sourceRevision": {
                "oneOf": [
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["profile", "status", "value"],
                        "properties": {
                            "profile": {"type": "string", "const": "snapshot"},
                            "status": {"type": "string", "const": "versioned"},
                            "value": {"type": "string", "minLength": 1}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["profile", "status", "value"],
                        "properties": {
                            "profile": {"type": "string", "const": "live"},
                            "status": {"type": "string", "const": "unversioned"},
                            "value": {"type": "null"}
                        }
                    }
                ]
            },
            "selectedFields": {
                "type": "array", "uniqueItems": true,
                "items": {"type": "string", "enum": access_profiles.iter().flat_map(|profile| profile.selectable_properties.iter().cloned()).collect::<BTreeSet<_>>()}
            },
            "links": {
                "type": "object", "additionalProperties": false,
                "required": ["self", "context", "schema", "semanticModel"],
                "properties": {
                    "self": {"type": "string", "format": "uri"},
                    "context": {"type": "string", "enum": access_profiles.iter().map(|profile| profile.context_reference.clone()).collect::<BTreeSet<_>>()},
                    "schema": {"type": "string", "enum": access_profiles.iter().map(|profile| profile.schema_reference.clone()).collect::<BTreeSet<_>>()},
                    "semanticModel": {"type": "string", "enum": access_profiles.iter().map(|profile| profile.semantic_model_reference.clone()).collect::<BTreeSet<_>>()}
                }
            }
        }
    });
    let exact_record_schema = |access_profile: &crate::model::CompiledAccessProfile| {
        // Every OpenAPI subschema states its own `type`; the maintained OpenAPI
        // model reads a schema object only when it does. The record referenced
        // beside this constraint is an object, so stating it here narrows
        // nothing the composed schema did not already require.
        let representation_constraint = if json_ld {
            json!({"type": "object", "required": ["@id", "@type"]})
        } else {
            json!({
                "type": "object",
                "not": {
                    "anyOf": [
                        {"required": ["@id"]},
                        {"required": ["@type"]}
                    ]
                }
            })
        };
        json!({
            "allOf": [
                {"$ref": access_profile.schema_reference},
                representation_constraint
            ]
        })
    };
    let record = if access_profiles.len() == 1 {
        exact_record_schema(access_profiles[0])
    } else {
        json!({
            "oneOf": access_profiles.iter().map(|access_profile| {
                exact_record_schema(access_profile)
            }).collect::<Vec<_>>()
        })
    };
    let mut schema = match &operation.kind {
        OperationKind::List | OperationKind::Search { .. } => json!({
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
    };
    if json_ld {
        let context_references = access_profiles
            .iter()
            .map(|access_profile| access_profile.context_reference.clone())
            .collect::<BTreeSet<_>>();
        let context_schema = json!({
            "oneOf": context_references.into_iter().map(|reference| json!({
                "type": "array",
                "prefixItems": [
                    {"type": "string", "const": REGISTRY_RECORD_CONTEXT_ID},
                    {"type": "string", "const": reference}
                ],
                "items": false,
                "minItems": 2,
                "maxItems": 2
            })).collect::<Vec<_>>()
        });
        schema["required"]
            .as_array_mut()
            .expect("response required array")
            .push(json!("@context"));
        schema["properties"]
            .as_object_mut()
            .expect("response properties object")
            .insert("@context".into(), context_schema);
    }
    schema
}

fn geojson_response_schema(
    registry: &CompiledRegistry,
    operation: &crate::model::CompiledOperation,
    access_profile: &crate::model::CompiledAccessProfile,
    resource: &crate::model::CompiledResource,
    include_identity: bool,
) -> Value {
    let mut schema = match &operation.kind {
        OperationKind::List | OperationKind::Search { .. } => json!({
            "type": "object", "additionalProperties": false,
            "required": ["type", "features", "pageInfo", "meta"],
            "properties": {
                "type": {"type": "string", "const": "FeatureCollection"},
                "features": {"type": "array", "items": geojson_feature_schema(registry, access_profile, resource, false)},
                "pageInfo": {"type": "object", "additionalProperties": false, "required": ["nextCursor"], "properties": {"nextCursor": {"type": ["string", "null"]}}},
                "meta": {"type": "object"},
                "conformsTo": json_fg_conforms_to_schema(),
                "featureType": {"type": "string", "const": resource.id},
                "coordRefSys": {"type": "string", "const": CRS84_URI}
            },
            "dependentRequired": {
                "conformsTo": ["featureType", "coordRefSys"],
                "featureType": ["conformsTo", "coordRefSys"],
                "coordRefSys": ["conformsTo", "featureType"]
            }
        }),
        OperationKind::Read | OperationKind::Lookup { .. } => {
            geojson_feature_schema(registry, access_profile, resource, true)
        }
    };
    if include_identity {
        let object = schema.as_object_mut().expect("GeoJSON schema object");
        object.insert(
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        );
        object.insert(
            "$id".into(),
            json!(access_profile
                .schema_reference
                .strip_suffix("-schema")
                .map(|base| format!("{base}-geojson-schema"))
                .unwrap_or_else(|| format!("{}-geojson", access_profile.schema_reference))),
        );
    }
    schema
}

fn geojson_feature_schema(
    registry: &CompiledRegistry,
    access_profile: &crate::model::CompiledAccessProfile,
    resource: &crate::model::CompiledResource,
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
        "type": {"type": "string", "const": "Feature"},
        "id": {"type": "string", "minLength": 1},
        "geometry": {"oneOf": [point_geometry_schema(), {"type": "null"}]},
        "properties": geojson_record_properties_schema(registry, access_profile, resource)
    });
    if require_meta {
        let object = properties
            .as_object_mut()
            .expect("Feature properties schema");
        object.insert("meta".into(), json!({"type": "object"}));
        object.insert("conformsTo".into(), json_fg_conforms_to_schema());
        object.insert(
            "featureType".into(),
            json!({"type": "string", "const": resource.id}),
        );
        object.insert(
            "coordRefSys".into(),
            json!({"type": "string", "const": CRS84_URI}),
        );
    }
    let mut schema = json!({
        "type": "object", "additionalProperties": false,
        "required": required,
        "properties": properties
    });
    if require_meta {
        schema["dependentRequired"] = json!({
            "conformsTo": ["featureType", "coordRefSys"],
            "featureType": ["conformsTo", "coordRefSys"],
            "coordRefSys": ["conformsTo", "featureType"]
        });
    }
    schema
}

fn geojson_record_properties_schema(
    registry: &CompiledRegistry,
    access_profile: &crate::model::CompiledAccessProfile,
    resource: &crate::model::CompiledResource,
) -> Value {
    let selected = access_profile
        .selectable_properties
        .iter()
        .filter(|property| resource.primary_geometry.as_ref() != Some(*property))
        .cloned()
        .collect::<Vec<_>>();
    let mut schema = access_profile_schema(
        registry,
        resource,
        &selected,
        &access_profile.schema_reference,
        &access_profile.semantic_model_reference,
    );
    let object = schema
        .as_object_mut()
        .expect("Registry Record schema object");
    object.remove("$schema");
    object.remove("$id");
    object["required"]
        .as_array_mut()
        .expect("record required members")
        .insert(0, json!("registryIdentifier"));
    object["properties"]
        .as_object_mut()
        .expect("record properties")
        .insert(
            "registryIdentifier".into(),
            json!({"type": "string", "const": registry.registry_identifier}),
        );
    schema
}

fn point_geometry_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["type", "coordinates"],
        "properties": {
            "type": {"type": "string", "const": "Point"},
            "coordinates": {
                "type": "array",
                "prefixItems": [
                    {"type": "number", "minimum": -180, "maximum": 180},
                    {"type": "number", "minimum": -90, "maximum": 90}
                ],
                "items": false, "minItems": 2, "maxItems": 2
            }
        }
    })
}

fn json_fg_conforms_to_schema() -> Value {
    json!({
        "type": "array",
        "items": {"type": "string", "enum": [JSON_FG_CORE_CONFORMANCE, JSON_FG_TYPES_CONFORMANCE]},
        "minItems": 2, "maxItems": 2, "uniqueItems": true
    })
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
    AccessProfile(&'a str, &'a str),
}

fn capability_inventory(
    registry: &CompiledRegistry,
    projection: CapabilityProjection<'_>,
) -> Value {
    let mut capabilities = registry
        .resources
        .iter()
        .flat_map(|resource| {
            resource.operations.iter().flat_map(move |operation| {
                operation.access_profiles.iter().filter_map(move |access_profile| {
                    let include = match projection {
                        CapabilityProjection::Public => {
                            matches!(&access_profile.access, CompiledAccess::Public)
                        }
                        CapabilityProjection::Full => true,
                        CapabilityProjection::AccessProfile(
                            operation_identifier,
                            access_profile_identifier,
                        ) => {
                            operation.identifier == operation_identifier
                                && access_profile.id == access_profile_identifier
                        }
                    };
                    if !include {
                        return None;
                    }
                    let pattern = match &operation.kind {
                        OperationKind::List => "list",
                        OperationKind::Read => "retrieve",
                        OperationKind::Lookup { .. } => "search",
                        OperationKind::Search { .. } => "search",
                    };
                    let href = match &operation.kind {
                        OperationKind::List => {
                            format!("/v2/resources/{}/records", resource.id)
                        }
                        OperationKind::Read => {
                            format!("/v2/resources/{}/records/{{recordIdentifier}}", resource.id)
                        }
                        OperationKind::Lookup { name } => {
                            format!("/v2/resources/{}/lookups/{name}", resource.id)
                        }
                        OperationKind::Search { name } => {
                            format!("/v2/resources/{}/searches/{name}", resource.id)
                        }
                    };
                    Some(json!({
                        "resource": resource.id,
                        "operationIdentifier": operation.identifier,
                        "accessProfileIdentifier": access_profile.id,
                        "isDefault": operation.default_access_profile == access_profile.id,
                        "family": "consultation",
                        "pattern": pattern,
                        "profile": if matches!(&operation.kind, OperationKind::Lookup { .. }) { Value::String("exact".into()) } else { Value::Null },
                        "href": absolute(&registry.base_uri, &href),
                        "schemaReference": access_profile.schema_reference,
                        "semanticModelReference": access_profile.semantic_model_reference,
                        "contextReference": access_profile.context_reference,
                        "wireFormats": response_format_capabilities(resource, access_profile),
                    }))
                })
            })
        })
        .collect::<Vec<_>>();
    capabilities.extend(registry.statistical_datasets.iter().filter_map(|dataset| {
        let visibility = projection_visibility(
            registry
                .metadata_visibility
                .statistical_datasets
                .unwrap_or(Visibility::OperatorOnly),
            &dataset.access,
        );
        let include = match projection {
            CapabilityProjection::Public => visibility == Visibility::Public,
            CapabilityProjection::Full => true,
            CapabilityProjection::AccessProfile(_, _) => false,
        };
        include.then(|| {
            let data = format!(
                "/sdmx/v2/data/dataflow/{}/{}/{}",
                dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
            );
            json!({
                "statisticalDatasetIdentifier": dataset.id,
                "operationIdentifier": dataset.operation_identifier(),
                "family": "aggregate-data",
                "pattern": "statistical-dataflow",
                "profile": {
                    "sdmxRestVersion": dataset.sdmx.rest_version,
                    "sdmxDataJsonVersion": dataset.sdmx.data_json_version,
                    "sdmxDataCsvVersion": dataset.sdmx.data_csv_version,
                    "sdmxStructureJsonVersion": dataset.sdmx.structure_json_version,
                },
                "wireFormats": [
                    {"id": "sdmx-json", "mediaType": DATA_JSON_MEDIA_TYPE},
                    {"id": "sdmx-csv", "mediaType": DATA_CSV_MEDIA_TYPE},
                    {"id": "sdmx-structure-json", "mediaType": STRUCTURE_JSON_MEDIA_TYPE},
                ],
                "href": absolute(&registry.base_uri, &data),
                "structureLinks": {
                    "dataflow": absolute(&registry.base_uri, &format!(
                        "/sdmx/v2/structure/dataflow/{}/{}/{}",
                        dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
                    )),
                    "datastructure": absolute(&registry.base_uri, &format!(
                        "/sdmx/v2/structure/datastructure/{}/{}/{}",
                        dataset.sdmx.agency_id,
                        dataset.sdmx.data_structure_id,
                        dataset.sdmx.version
                    )),
                },
            })
        })
    }));
    let mut unsupported_families = vec![
        "provisioning",
        "evidence",
        "write",
        "notification",
        "access-transparency",
        "identity-federation",
    ];
    if registry.statistical_datasets.is_empty() {
        unsupported_families.insert(4, "aggregate-data");
    }
    json!({
        "registryIdentifier": registry.registry_identifier,
        "authorityIdentifier": registry.authority_identifier,
        "contractRevision": registry.contract_revision,
        "apiBinding": {"name": "registry-relay", "version": "v2alpha1"},
        "alignmentTargets": registry.alignment_targets,
        "metadataVisibility": registry.metadata_visibility,
        "capabilities": capabilities,
        "unsupportedFamilies": unsupported_families
    })
}

fn absolute(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

/// Return the fixed value-free audit event JSON Schema published in packages.
#[must_use]
pub fn audit_event_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://id.registrystack.org/schemas/registry-relay/audit-event/v2alpha1",
        "title": "Registry Relay value-free audit event",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema", "phase", "operationId", "traceId", "registryIdentifier",
            "operationSurface",
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
            "operationSurface": {"enum": [
                "record-list", "record-read", "record-lookup", "record-search",
                "sdmx-data", "sdmx-dataflow-structure",
                "sdmx-datastructure-structure", "unknown"
            ]},
            "queryShape": {"enum": [
                "sdmx-keyed-time-period", "sdmx-keyed-all-dimensions",
                "sdmx-omitted-key-time-period", "sdmx-omitted-key-all-dimensions"
            ]},
            "accessRuleRevision": {"type": "string", "minLength": 1},
            "purpose": {"type": "string", "minLength": 1},
            "rowBoundaryKind": {"enum": ["none", "principal", "verified-claim", "unknown"]},
            "accessProfile": {"type": "string", "minLength": 1},
            "disclosureProfile": {"type": "string", "minLength": 1},
            "wireFormat": {"enum": [
                "json", "json-ld", "geojson",
                "sdmx-json", "sdmx-csv", "sdmx-structure-json"
            ]},
            "formatProfile": {"enum": ["rfc7946", "jsonfg"]},
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
    use crate::model::CompileProfile;

    fn compiled_statistical_registry() -> CompiledRegistry {
        let contract = RegistryContract::parse_yaml(compiler_tests::statistical_contract())
            .expect("statistical contract parses");
        compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::statistical_observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files_for(&contract),
        )
        .expect("statistical contract compiles")
    }

    #[test]
    fn provider_discovery_description_is_deterministic_and_exactly_regenerated() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.publication = Some(crate::model::CompiledPublication {
            jurisdictions: vec!["urn:example:jurisdiction:acceptance".into()],
        });

        let first = generate_artifacts(&registry).expect("description generates");
        let second = generate_artifacts(&registry).expect("description regenerates");
        let first = first
            .get("artifacts/discovery.jsonld")
            .expect("description artifact exists");
        let second = second
            .get("artifacts/discovery.jsonld")
            .expect("regenerated description exists");
        assert_eq!(first.content, second.content);
        assert_eq!(first.media_type, DISCOVERY_MEDIA_TYPE);
        assert_eq!(first.visibility, Visibility::Public);
        assert_eq!(first.operation_identifier, None);
        assert_eq!(first.access_binding, None);
        let parsed = registry_discovery_profile::parse_description(&first.content)
            .expect("generated description satisfies the shared profile");
        for service in parsed.services() {
            assert_eq!(
                service.conforms_to(),
                [REGISTRY_RECORD_PROFILE_ID, RELAY_PROFILE_ID]
            );
            assert!(service.semantic_class_ids().len() <= 1);
            assert!(service.operation_family_ids().len() <= 1);
            assert_eq!(
                service.endpoint_url(),
                registry.base_uri,
                "the publication endpoint is the native Relay client base"
            );
        }
    }

    #[test]
    fn provider_discovery_description_preserves_semantic_class_operation_family_correlation() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.publication = Some(crate::model::CompiledPublication {
            jurisdictions: vec!["urn:example:jurisdiction:acceptance".into()],
        });
        let mut first = registry.resources[0].clone();
        first.semantic_class = "urn:example:semantic-class:first".into();
        first.operations.truncate(1);
        first.operations[0].pattern = crate::model::ConsultationPattern::List;
        first.operations[0].access_profiles[0].access = CompiledAccess::Public;
        let mut second = first.clone();
        second.semantic_class = "urn:example:semantic-class:second".into();
        second.operations[0].pattern = crate::model::ConsultationPattern::Search;
        registry.resources = vec![first, second];

        let generated = generate_artifacts(&registry).expect("description generates");
        let artifact = generated
            .get("artifacts/discovery.jsonld")
            .expect("description artifact exists");
        let description = registry_discovery_profile::parse_description(&artifact.content)
            .expect("description satisfies profile");
        assert_eq!(description.services().len(), 2);
        assert!(description.services().iter().all(|service| {
            service.semantic_class_ids().len() == 1 && service.operation_family_ids().len() == 1
        }));
        assert!(description.services().iter().any(|service| {
            service.semantic_class_ids() == ["urn:example:semantic-class:first"]
                && service.operation_family_ids() == [CONSULTATION_LIST_FAMILY]
        }));
        assert!(description.services().iter().any(|service| {
            service.semantic_class_ids() == ["urn:example:semantic-class:second"]
                && service.operation_family_ids() == [CONSULTATION_SEARCH_FAMILY]
        }));
        assert!(!description.services().iter().any(|service| {
            service.semantic_class_ids() == ["urn:example:semantic-class:first"]
                && service.operation_family_ids() == [CONSULTATION_SEARCH_FAMILY]
        }));
        assert!(!description.services().iter().any(|service| {
            service.semantic_class_ids() == ["urn:example:semantic-class:second"]
                && service.operation_family_ids() == [CONSULTATION_LIST_FAMILY]
        }));
    }

    #[test]
    fn provider_discovery_description_deduplicates_public_statistical_dataflow_without_semantic_class(
    ) {
        let mut registry = compiled_statistical_registry();
        let mut second_public = registry.statistical_datasets[0].clone();
        second_public.id = "second-public-statistical-dataset".into();
        registry.statistical_datasets.push(second_public);

        let bytes =
            discovery_description(&registry, &["urn:example:jurisdiction:acceptance".into()])
                .expect("public statistical description renders");
        let description = registry_discovery_profile::parse_description(&bytes)
            .expect("public statistical description satisfies the shared profile");
        let statistical = description
            .services()
            .iter()
            .filter(|service| {
                service.operation_family_ids() == [AGGREGATE_DATA_STATISTICAL_DATAFLOW_FAMILY]
            })
            .collect::<Vec<_>>();
        assert_eq!(statistical.len(), 1, "the operation family is deduplicated");
        assert!(
            statistical[0].semantic_class_ids().is_empty(),
            "Relay must not invent a statistical semantic class"
        );
    }

    #[test]
    fn provider_discovery_description_excludes_protected_and_operator_only_statistical_dataflows() {
        let jurisdictions = ["urn:example:jurisdiction:acceptance".into()];
        let mut registry = compiled_statistical_registry();
        registry.statistical_datasets[0].access = CompiledAccess::Protected {
            scope: "statistics:protected:read".into(),
            purpose: None,
            row_binding: None,
        };
        let protected = discovery_description(&registry, &jurisdictions)
            .expect("protected statistical description renders");
        let protected = registry_discovery_profile::parse_description(&protected)
            .expect("protected statistical description satisfies the shared profile");
        assert!(protected.services().iter().all(|service| {
            service.operation_family_ids() != [AGGREGATE_DATA_STATISTICAL_DATAFLOW_FAMILY]
        }));

        registry.statistical_datasets[0].access = CompiledAccess::Public;
        registry.metadata_visibility.statistical_datasets = Some(Visibility::OperatorOnly);
        let operator_only = discovery_description(&registry, &jurisdictions)
            .expect("operator-only statistical description renders");
        let operator_only = registry_discovery_profile::parse_description(&operator_only)
            .expect("operator-only statistical description satisfies the shared profile");
        assert!(operator_only.services().iter().all(|service| {
            service.operation_family_ids() != [AGGREGATE_DATA_STATISTICAL_DATAFLOW_FAMILY]
        }));
    }

    #[test]
    fn provider_discovery_description_excludes_operator_only_resource_bindings() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.publication = Some(crate::model::CompiledPublication {
            jurisdictions: vec!["urn:example:jurisdiction:acceptance".into()],
        });
        registry.metadata_visibility.resources = Visibility::OperatorOnly;
        registry.resources[0].operations[0].access_profiles[0].access = CompiledAccess::Public;

        let bytes =
            discovery_description(&registry, &["urn:example:jurisdiction:acceptance".into()])
                .expect("operator-only resource description renders");
        let description = registry_discovery_profile::parse_description(&bytes)
            .expect("operator-only resource description satisfies the profile");
        assert!(description.services().iter().all(|service| {
            service.semantic_class_ids().is_empty() && service.operation_family_ids().is_empty()
        }));
    }

    #[test]
    fn provider_discovery_description_excludes_protected_and_internal_contract_fields() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.publication = Some(crate::model::CompiledPublication {
            jurisdictions: vec!["urn:example:jurisdiction:acceptance".into()],
        });
        let operation = &mut registry.resources[0].operations[0];
        operation.identifier = "canary.protected.operation".into();
        operation.access_profiles[0].id = "canary-private-profile".into();
        operation.access_profiles[0].access = CompiledAccess::Protected {
            scope: "canary:private:scope".into(),
            purpose: None,
            row_binding: None,
        };
        registry.sources[0].id = "canary-internal-source".into();
        registry.resources[0].source = "canary-internal-source".into();
        registry.resources[0].view = "canary_internal_view".into();
        registry.resources[0].properties[0].binding = crate::model::CompiledPropertyBinding::Scalar(
            crate::model::CompiledScalarPropertyBinding {
                source_column: "canary_private_column".into(),
                ..registry.resources[0].properties[0]
                    .scalar_binding()
                    .expect("scalar property")
                    .clone()
            },
        );

        let generated = generate_artifacts(&registry).expect("description generates");
        let artifact = generated
            .get("artifacts/discovery.jsonld")
            .expect("description artifact exists");
        let text = std::str::from_utf8(&artifact.content).expect("description is UTF-8");
        for canary in [
            "canary.protected.operation",
            "canary-private-profile",
            "canary:private:scope",
            "canary-internal-source",
            "canary_internal_view",
            "canary_private_column",
        ] {
            assert!(!text.contains(canary), "public projection leaked {canary}");
        }
        let description = registry_discovery_profile::parse_description(&artifact.content)
            .expect("description satisfies profile");
        let service = &description.services()[0];
        assert!(service.semantic_class_ids().is_empty());
        assert!(service.operation_family_ids().is_empty());
    }

    #[test]
    fn generated_sdmx_dataflow_and_dsd_artifacts_are_canonical_and_route_identical() {
        let mut registry = compiled_statistical_registry();
        registry.base_uri = "https://statistics.example.invalid/registry/".into();
        let dataset = &registry.statistical_datasets[0];
        let operation_identifier = dataset.operation_identifier();
        let generated = generate_artifacts(&registry).expect("statistical artifacts generate");
        assert_eq!(
            generated,
            generate_artifacts(&registry).expect("statistical artifacts repeat")
        );

        for (id, path, kind) in [
            (
                format!("{}-sdmx-dataflow-structure", dataset.id),
                format!("artifacts/{}.sdmx.dataflow.json", dataset.id),
                StructureKind::Dataflow,
            ),
            (
                format!("{}-sdmx-datastructure-structure", dataset.id),
                format!("artifacts/{}.sdmx.datastructure.json", dataset.id),
                StructureKind::DataStructure,
            ),
        ] {
            let artifact = generated
                .get(&path)
                .unwrap_or_else(|| panic!("missing {path}"));
            assert_eq!(artifact.id, id);
            assert_eq!(artifact.media_type, STRUCTURE_JSON_MEDIA_TYPE);
            assert_eq!(artifact.visibility, Visibility::Public);
            assert_eq!(
                artifact.operation_identifier.as_deref(),
                Some(operation_identifier.as_str())
            );
            assert_eq!(
                artifact.access_binding,
                Some(ArtifactAccessBinding::FixedOperation)
            );
            assert_eq!(
                artifact.content,
                serialize_structure_json(dataset, kind).expect("route serializer bytes")
            );
            let value: Value =
                serde_json::from_slice(&artifact.content).expect("structure artifact is JSON");
            assert_eq!(
                artifact.content,
                canonicalize_json(&value).expect("structure artifact canonicalizes")
            );
        }

        let full_openapi: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI parses");
        let public_openapi: Value = serde_json::from_slice(
            &generated
                .get("openapi.public.json")
                .expect("public OpenAPI")
                .content,
        )
        .expect("public OpenAPI parses");
        let data_base = format!(
            "/sdmx/v2/data/dataflow/{}/{}/{}",
            dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
        );
        let paths = [
            (format!("{data_base}/{{key}}"), "data.keyed"),
            (data_base, "data.omitted-key"),
            (
                format!(
                    "/sdmx/v2/structure/dataflow/{}/{}/{}",
                    dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
                ),
                "structure.dataflow",
            ),
            (
                format!(
                    "/sdmx/v2/structure/datastructure/{}/{}/{}",
                    dataset.sdmx.agency_id, dataset.sdmx.data_structure_id, dataset.sdmx.version
                ),
                "structure.datastructure",
            ),
        ];
        for (path, suffix) in &paths {
            let operation = &full_openapi["paths"][path.as_str()]["get"];
            assert_eq!(
                operation["operationId"],
                format!("{operation_identifier}.{suffix}")
            );
            assert_eq!(
                operation["x-registry-capability-operation"],
                operation_identifier
            );
            assert_eq!(operation["x-registry-family"], "aggregate-data");
            assert_eq!(operation["x-registry-pattern"], "statistical-dataflow");
            assert_eq!(
                public_openapi["paths"].get(path.as_str()),
                full_openapi["paths"].get(path.as_str())
            );
        }
        assert!(
            full_openapi["paths"][paths[0].0.as_str()]["get"]["responses"]["200"]["content"]
                .get(DATA_JSON_MEDIA_TYPE)
                .is_some()
        );
        assert!(
            full_openapi["paths"][paths[0].0.as_str()]["get"]["responses"]["200"]["content"]
                .get(DATA_CSV_MEDIA_TYPE)
                .is_some()
        );
        assert!(
            full_openapi["paths"][paths[2].0.as_str()]["get"]["responses"]["200"]["content"]
                .get(STRUCTURE_JSON_MEDIA_TYPE)
                .is_some()
        );
        assert!(full_openapi["paths"]
            .as_object()
            .expect("OpenAPI paths")
            .keys()
            .all(|path| !path.contains("/schema") && !path.contains("/availability")));

        let capabilities: Value = serde_json::from_slice(
            &generated
                .get("artifacts/capabilities.json")
                .expect("public capabilities")
                .content,
        )
        .expect("public capabilities parse");
        assert_eq!(
            capabilities["alignmentTargets"],
            json!(registry.alignment_targets)
        );
        assert!(capabilities["capabilities"]
            .as_array()
            .expect("capabilities")
            .iter()
            .any(|capability| {
                capability["operationIdentifier"] == operation_identifier
                    && capability["family"] == "aggregate-data"
                    && capability["pattern"] == "statistical-dataflow"
            }));
        let capability = capabilities["capabilities"]
            .as_array()
            .expect("capabilities")
            .iter()
            .find(|capability| capability["operationIdentifier"] == operation_identifier)
            .expect("statistical capability");
        assert_eq!(
            capability["href"],
            format!(
                "https://statistics.example.invalid/registry/sdmx/v2/data/dataflow/{}/{}/{}",
                dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
            )
        );
        assert_eq!(
            capability["structureLinks"]["dataflow"],
            format!(
                "https://statistics.example.invalid/registry/sdmx/v2/structure/dataflow/{}/{}/{}",
                dataset.sdmx.agency_id, dataset.sdmx.dataflow_id, dataset.sdmx.version
            )
        );
        assert_eq!(
            capability["structureLinks"]["datastructure"],
            format!(
                "https://statistics.example.invalid/registry/sdmx/v2/structure/datastructure/{}/{}/{}",
                dataset.sdmx.agency_id, dataset.sdmx.data_structure_id, dataset.sdmx.version
            )
        );
        assert!(!capabilities["unsupportedFamilies"]
            .as_array()
            .expect("unsupported families")
            .contains(&json!("aggregate-data")));

        let audit: Value = serde_json::from_slice(
            &generated
                .get("artifacts/audit-event.schema.json")
                .expect("audit schema")
                .content,
        )
        .expect("audit schema parses");
        let wire_formats = audit["properties"]["wireFormat"]["enum"]
            .as_array()
            .expect("wire-format enum");
        for wire_format in [
            "json",
            "json-ld",
            "geojson",
            "sdmx-json",
            "sdmx-csv",
            "sdmx-structure-json",
        ] {
            assert!(wire_formats.contains(&json!(wire_format)));
        }

        let mut protected = registry.clone();
        protected.metadata_visibility.statistical_datasets = Some(Visibility::OperationBound);
        protected.statistical_datasets[0].access = CompiledAccess::Protected {
            scope: "statistics:read".into(),
            purpose: None,
            row_binding: None,
        };
        let protected_generated =
            generate_artifacts(&protected).expect("protected statistical artifacts");
        for path in [
            format!("artifacts/{}.sdmx.dataflow.json", dataset.id),
            format!("artifacts/{}.sdmx.datastructure.json", dataset.id),
        ] {
            let artifact = protected_generated.get(&path).expect("protected artifact");
            assert_eq!(artifact.visibility, Visibility::OperationBound);
            assert_eq!(
                artifact.operation_identifier.as_deref(),
                Some(operation_identifier.as_str())
            );
            assert_eq!(
                artifact.access_binding,
                Some(ArtifactAccessBinding::FixedOperation)
            );
        }
        let protected_public: Value = serde_json::from_slice(
            &protected_generated
                .get("openapi.public.json")
                .expect("protected public OpenAPI")
                .content,
        )
        .expect("protected public OpenAPI parses");
        assert!(paths
            .iter()
            .all(|(path, _)| protected_public["paths"].get(path.as_str()).is_none()));
        let protected_full: Value = serde_json::from_slice(
            &protected_generated
                .get("openapi.full.yaml")
                .expect("protected full OpenAPI")
                .content,
        )
        .expect("protected full OpenAPI parses");
        for (path, _) in &paths {
            let operation = &protected_full["paths"][path.as_str()]["get"];
            assert_eq!(operation["security"], json!([{"bearerAuth": []}]));
            assert_eq!(operation["x-registry-required-scope"], "statistics:read");
        }
        let protected_capabilities: Value = serde_json::from_slice(
            &protected_generated
                .get("artifacts/capabilities.json")
                .expect("protected public capabilities")
                .content,
        )
        .expect("protected public capabilities parse");
        assert!(protected_capabilities["capabilities"]
            .as_array()
            .expect("protected public capabilities")
            .iter()
            .all(|capability| capability["operationIdentifier"] != operation_identifier));

        let mut operator_only = protected;
        operator_only.metadata_visibility.statistical_datasets = Some(Visibility::OperatorOnly);
        let operator_generated =
            generate_artifacts(&operator_only).expect("operator-only statistical artifacts");
        let artifact = operator_generated
            .get(&format!("artifacts/{}.sdmx.dataflow.json", dataset.id))
            .expect("operator-only artifact");
        assert_eq!(artifact.visibility, Visibility::OperatorOnly);
        assert_eq!(
            artifact.operation_identifier.as_deref(),
            Some(operation_identifier.as_str())
        );
        assert_eq!(
            artifact.access_binding,
            Some(ArtifactAccessBinding::FixedOperation)
        );
    }

    #[test]
    fn spatial_artifacts_are_deterministic_bounded_and_carrier_free() {
        let contract = compiler_tests::spatial_contract();
        let registry = crate::compiler::compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::point_observed_schema("INTEGER", "REAL")],
            CompileProfile::Production,
            &compiler_tests::governed_files_for(&contract),
        )
        .expect("spatial contract compiles");
        let generated = generate_artifacts(&registry).expect("spatial artifacts generate");
        assert_eq!(
            generated,
            generate_artifacts(&registry).expect("spatial artifacts repeat")
        );
        assert!(generated
            .artifacts
            .iter()
            .all(|artifact| artifact.content.len() <= 8 * 1024 * 1024));
        for artifact in generated.artifacts.iter().filter(|artifact| {
            artifact.path.ends_with(".schema.json")
                || artifact.path.ends_with(".context.jsonld")
                || artifact.path.ends_with(".vocabulary.jsonld")
                || artifact.path.ends_with(".shacl.ttl")
        }) {
            let text = String::from_utf8_lossy(&artifact.content);
            assert!(
                !text.contains("longitude"),
                "{} leaked a carrier",
                artifact.path
            );
            assert!(
                !text.contains("latitude"),
                "{} leaked a carrier",
                artifact.path
            );
        }
        let geojson_schema: Value = serde_json::from_slice(
            &generated
                .get("artifacts/record--search-within-bbox--access-profile-public.geojson.schema.json")
                .expect("GeoJSON schema")
                .content,
        )
        .expect("GeoJSON schema parses");
        let coordinates = &geojson_schema["properties"]["features"]["items"]["properties"]
            ["geometry"]["oneOf"][0]["properties"]["coordinates"];
        assert_eq!(coordinates["prefixItems"][0]["minimum"], -180);
        assert_eq!(coordinates["prefixItems"][0]["maximum"], 180);
        assert_eq!(coordinates["prefixItems"][1]["minimum"], -90);
        assert_eq!(coordinates["prefixItems"][1]["maximum"], 90);
        assert_eq!(coordinates["items"], false);
        let document: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("OpenAPI JSON");
        let operation = &document["paths"]["/v2/resources/record/searches/within-bbox"]["get"];
        let bbox = operation["parameters"]
            .as_array()
            .expect("parameters")
            .iter()
            .find(|parameter| parameter["name"] == "bbox")
            .expect("bbox parameter");
        assert_eq!(bbox["required"], false);
        assert_eq!(bbox["x-registry-required-on-first-page"], true);
        assert_eq!(bbox["x-registry-mutually-exclusive-with"], "cursor");
        let format_profile = operation["parameters"]
            .as_array()
            .expect("parameters")
            .iter()
            .find(|parameter| parameter["name"] == "formatProfile")
            .expect("formatProfile parameter");
        assert_eq!(format_profile["required"], false);
        assert_eq!(
            format_profile["schema"],
            json!({"type": "string", "enum": ["rfc7946", "jsonfg"]})
        );
        let response_content = operation["responses"]["200"]["content"]
            .as_object()
            .expect("response media types");
        for media_type in [
            "application/json",
            "application/ld+json",
            "application/geo+json",
        ] {
            assert!(response_content.contains_key(media_type));
        }
    }

    #[test]
    fn generated_inventory_covers_required_v1_artifact_classes_only() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.base_uri = "https://registry.example.invalid/registry/".into();
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
            "artifacts/record--read--access-profile-public.schema.json",
            "artifacts/record--read--access-profile-public.shacl.ttl",
            "artifacts/record--read--access-profile-public.context.jsonld",
            "artifacts/record--read--access-profile-public.vocabulary.jsonld",
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
        let capabilities: Value = serde_json::from_slice(
            &generated
                .get("artifacts/capabilities.json")
                .expect("public capabilities")
                .content,
        )
        .expect("public capabilities parse");
        assert!(capabilities["unsupportedFamilies"]
            .as_array()
            .expect("unsupported families")
            .contains(&json!("aggregate-data")));
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
        assert_eq!(
            full["paths"]["/v2/resources"]["get"]["parameters"],
            json!([
                {
                    "name": "pageSize", "in": "query", "required": false,
                    "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50}
                },
                {
                    "name": "cursor", "in": "query", "required": false,
                    "schema": {"type": "string", "minLength": 1}
                }
            ])
        );
        for path in ["/health", "/ready", "/openapi.json", "/v2"] {
            assert!(
                full["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]
                    .is_object(),
                "{path} must describe its JSON success body"
            );
        }
        let service_metadata = &full["components"]["schemas"]["ServiceMetadata"];
        for property in ["registryIdentifier", "authority", "capabilities", "links"] {
            assert!(
                service_metadata["properties"].get(property).is_some(),
                "ServiceMetadata must expose {property} to generated clients"
            );
        }
        assert_eq!(
            service_metadata["properties"]["links"]["required"],
            json!(["self", "resources", "openapi"])
        );
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
        let not_modified = &full["components"]["responses"]["NotModified"];
        assert_eq!(
            not_modified,
            &json!({
                "description": "Not modified; the response body is empty",
                "headers": {
                    "Cache-Control": {
                        "schema": {"type": "string", "const": "public, no-cache"}
                    },
                    "ETag": {
                        "schema": {"type": "string", "pattern": "^\"[0-9a-f]{64}\"$"}
                    },
                    "Vary": {
                        "schema": {"type": "string", "const": "Accept, Authorization"}
                    }
                }
            })
        );
        assert!(not_modified.get("content").is_none());
        for path in [
            "/openapi.json",
            "/v2",
            "/v2/resources",
            "/v2/resources/{resource}",
            "/v2/resources/record/records/{recordIdentifier}",
            "/v2/artifacts/{artifactIdentifier}",
        ] {
            assert_eq!(
                full["paths"][path]["get"]["responses"]["304"],
                json!({"$ref": "#/components/responses/NotModified"}),
                "cacheable GET {path} must document its empty 304 response"
            );
        }
        for path in ["/health", "/ready"] {
            assert!(
                full["paths"][path]["get"]["responses"].get("304").is_none(),
                "non-cacheable GET {path} must not document 304"
            );
        }
        let json_schema = &full["paths"]["/v2/resources/record/records/{recordIdentifier}"]["get"]
            ["responses"]["200"]["content"]["application/json"]["schema"];
        let json_ld_schema = &full["paths"]["/v2/resources/record/records/{recordIdentifier}"]
            ["get"]["responses"]["200"]["content"]["application/ld+json"]["schema"];
        assert_eq!(
            full["paths"]["/v2/resources/record/records/{recordIdentifier}"]["get"]
                ["x-registry-responseProfile"],
            REGISTRY_RECORD_PROFILE_ID
        );
        assert!(!json_schema["required"]
            .as_array()
            .expect("ordinary JSON required array")
            .contains(&json!("@context")));

        let capabilities: Value = serde_json::from_slice(
            &generated
                .get("artifacts/capabilities.json")
                .expect("public capabilities")
                .content,
        )
        .expect("public capabilities parse");
        assert!(capabilities["capabilities"]
            .as_array()
            .expect("capabilities")
            .iter()
            .any(|capability| {
                capability["href"].as_str().is_some_and(|href| {
                    href.starts_with(
                        "https://registry.example.invalid/registry/v2/resources/record/",
                    )
                })
            }));
        assert!(json_schema["properties"].get("@context").is_none());
        assert!(json_ld_schema["required"]
            .as_array()
            .expect("JSON-LD required array")
            .contains(&json!("@context")));
        assert_eq!(
            json_ld_schema["properties"]["@context"]["oneOf"][0]["prefixItems"],
            json!([
                {"type": "string", "const": REGISTRY_RECORD_CONTEXT_ID},
                {
                    "type": "string",
                    "const": registry.resources[0].operations[0].access_profiles[0].context_reference
                }
            ])
        );
    }

    #[test]
    fn exact_operation_schema_rejects_wrong_registry_record_context_constants() {
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
        let openapi: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI parses");
        let operation_schema = &openapi["paths"]["/v2/resources/record/records/{recordIdentifier}"]
            ["get"]["responses"]["200"]["content"]["application/json"]["schema"];
        let json_ld_operation_schema = &openapi["paths"]
            ["/v2/resources/record/records/{recordIdentifier}"]["get"]["responses"]["200"]
            ["content"]["application/ld+json"]["schema"];

        let mut options = jsonschema::JSONSchema::options();
        options.with_draft(jsonschema::Draft::Draft202012);
        for artifact in generated
            .artifacts
            .iter()
            .filter(|artifact| artifact.media_type == "application/schema+json")
        {
            let schema: Value =
                serde_json::from_slice(&artifact.content).expect("generated schema parses");
            if let Some(identifier) = schema.get("$id").and_then(Value::as_str) {
                options.with_document(identifier.to_owned(), schema);
            }
        }
        let validator = options
            .compile(operation_schema)
            .expect("the exact operation schema compiles with generated references");
        let json_ld_validator = options
            .compile(json_ld_operation_schema)
            .expect("the exact JSON-LD operation schema compiles with generated references");
        let operation = &registry.resources[0].operations[0];
        let access_profile = &operation.access_profiles[0];
        let intended = json!({
            "data": {
                "recordIdentifier": "record-1",
                "revisionIdentifier": "revision-1",
                "lifecycleState": "ACTIVE",
                "schemaReference": access_profile.schema_reference,
                "semanticModelReference": access_profile.semantic_model_reference,
                "authorityIdentifier": registry.authority_identifier,
                "recordedAt": "2026-08-10T00:00:00Z",
                "domainData": {"name": "Example"}
            },
            "meta": {
                "registryIdentifier": registry.registry_identifier,
                "datasetIdentifier": registry.resources[0].dataset_identifier,
                "entityTypeIdentifier": registry.resources[0].entity_type_identifier,
                "operationIdentifier": operation.identifier,
                "accessProfile": access_profile.id,
                "family": "consultation",
                "pattern": "retrieve",
                "disclosureProfile": access_profile.disclosure_profile,
                "contractRevision": registry.contract_revision,
                "sourceRevision": {
                    "profile": "snapshot",
                    "status": "versioned",
                    "value": "sha256:source"
                },
                "selectedFields": ["name"],
                "links": {
                    "self": "https://registry.example.invalid/registry/v2/resources/record/records/record-1",
                    "context": access_profile.context_reference,
                    "schema": access_profile.schema_reference,
                    "semanticModel": access_profile.semantic_model_reference
                }
            }
        });
        assert!(validator.is_valid(&intended));
        let mut intended_json_ld = intended.clone();
        intended_json_ld["data"]["@id"] =
            json!("https://registry.example.invalid/registry/v2/resources/record/records/record-1");
        intended_json_ld["data"]["@type"] = json!(registry.resources[0].semantic_class);
        intended_json_ld["@context"] =
            json!([REGISTRY_RECORD_CONTEXT_ID, access_profile.context_reference]);
        assert!(json_ld_validator.is_valid(&intended_json_ld));

        for (label, invalid_context) in [
            (
                "reordered",
                json!([access_profile.context_reference, REGISTRY_RECORD_CONTEXT_ID]),
            ),
            (
                "extra",
                json!([
                    REGISTRY_RECORD_CONTEXT_ID,
                    access_profile.context_reference,
                    "https://example.invalid/extra-context"
                ]),
            ),
            (
                "inline",
                json!([
                    REGISTRY_RECORD_CONTEXT_ID,
                    {"registryIdentifier": "https://example.invalid/hostile"}
                ]),
            ),
            (
                "wrong shared value",
                json!([
                    "https://example.invalid/wrong-shared-context",
                    access_profile.context_reference
                ]),
            ),
            (
                "wrong governed value",
                json!([
                    REGISTRY_RECORD_CONTEXT_ID,
                    "https://example.invalid/wrong-operation-context"
                ]),
            ),
            ("scalar", json!(REGISTRY_RECORD_CONTEXT_ID)),
        ] {
            let mut invalid = intended_json_ld.clone();
            invalid["@context"] = invalid_context;
            assert!(
                !json_ld_validator.is_valid(&invalid),
                "the exact JSON-LD operation schema must reject a {label} context"
            );
        }
        let mut missing_context = intended_json_ld.clone();
        missing_context
            .as_object_mut()
            .expect("response is an object")
            .remove("@context");
        assert!(!json_ld_validator.is_valid(&missing_context));

        let mut context_in_json = intended.clone();
        context_in_json["@context"] =
            json!([REGISTRY_RECORD_CONTEXT_ID, access_profile.context_reference]);
        assert!(
            !validator.is_valid(&context_in_json),
            "the exact JSON operation schema must reject every @context value"
        );

        for (field, wrong) in [
            ("registryIdentifier", "urn:example:registry:wrong"),
            ("datasetIdentifier", "wrong-dataset"),
            ("entityTypeIdentifier", "wrong-entity-type"),
        ] {
            let mut invalid = intended.clone();
            invalid["meta"][field] = Value::String(wrong.into());
            assert!(
                !validator.is_valid(&invalid),
                "the exact operation schema must reject the wrong {field} constant"
            );
        }
    }

    #[test]
    fn exact_operation_schemas_pin_media_specific_record_identity() {
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
        let resource = &registry.resources[0];
        let read_operation = &resource.operations[0];
        let mut list_operation = read_operation.clone();
        list_operation.identifier = "record.list".into();
        list_operation.kind = OperationKind::List;

        let mut options = jsonschema::JSONSchema::options();
        options.with_draft(jsonschema::Draft::Draft202012);
        for artifact in generated
            .artifacts
            .iter()
            .filter(|artifact| artifact.media_type == "application/schema+json")
        {
            let schema: Value =
                serde_json::from_slice(&artifact.content).expect("generated schema parses");
            if let Some(identifier) = schema.get("$id").and_then(Value::as_str) {
                options.with_document(identifier.to_owned(), schema);
            }
        }

        for (shape, operation) in [("single", read_operation), ("collection", &list_operation)] {
            let access_profile = &operation.access_profiles[0];
            let access_profiles = [access_profile];
            let json_schema =
                operation_response_schema(&registry, resource, operation, &access_profiles, false);
            let json_ld_schema =
                operation_response_schema(&registry, resource, operation, &access_profiles, true);
            let validator = options
                .compile(&json_schema)
                .expect("the exact JSON operation schema compiles");
            let json_ld_validator = options
                .compile(&json_ld_schema)
                .expect("the exact JSON-LD operation schema compiles");
            let record = json!({
                "recordIdentifier": "record-1",
                "revisionIdentifier": "revision-1",
                "lifecycleState": "ACTIVE",
                "schemaReference": access_profile.schema_reference,
                "semanticModelReference": access_profile.semantic_model_reference,
                "authorityIdentifier": registry.authority_identifier,
                "recordedAt": "2026-08-10T00:00:00Z",
                "domainData": {"name": "Example"}
            });
            let meta = json!({
                "registryIdentifier": registry.registry_identifier,
                "datasetIdentifier": resource.dataset_identifier,
                "entityTypeIdentifier": resource.entity_type_identifier,
                "operationIdentifier": operation.identifier,
                "accessProfile": access_profile.id,
                "family": "consultation",
                "pattern": if matches!(&operation.kind, OperationKind::List) {
                    "list"
                } else {
                    "retrieve"
                },
                "disclosureProfile": access_profile.disclosure_profile,
                "contractRevision": registry.contract_revision,
                "sourceRevision": {
                    "profile": "snapshot",
                    "status": "versioned",
                    "value": "sha256:source"
                },
                "selectedFields": ["name"],
                "links": {
                    "self": "https://registry.example.invalid/registry/v2/resources/record/records/record-1",
                    "context": access_profile.context_reference,
                    "schema": access_profile.schema_reference,
                    "semanticModel": access_profile.semantic_model_reference
                }
            });
            let intended_json = if matches!(&operation.kind, OperationKind::List) {
                json!({
                    "items": [record.clone(), record],
                    "pageInfo": {"nextCursor": null},
                    "meta": meta
                })
            } else {
                json!({"data": record, "meta": meta})
            };
            assert!(
                validator.is_valid(&intended_json),
                "the exact {shape} JSON schema accepts a Registry Record"
            );

            for identity_member in ["@id", "@type"] {
                let mut invalid = intended_json.clone();
                let target = if shape == "collection" {
                    &mut invalid["items"][1]
                } else {
                    &mut invalid["data"]
                };
                target[identity_member] = if identity_member == "@id" {
                    json!("https://registry.example.invalid/records/record-1")
                } else {
                    json!(resource.semantic_class)
                };
                assert!(
                    !validator.is_valid(&invalid),
                    "the exact {shape} JSON schema must reject {identity_member}"
                );
            }

            let mut intended_json_ld = intended_json;
            if shape == "collection" {
                for item in intended_json_ld["items"]
                    .as_array_mut()
                    .expect("collection items")
                {
                    item["@id"] =
                        json!("https://registry.example.invalid/registry/v2/resources/record/records/record-1");
                    item["@type"] = json!(resource.semantic_class);
                }
            } else {
                intended_json_ld["data"]["@id"] =
                    json!("https://registry.example.invalid/registry/v2/resources/record/records/record-1");
                intended_json_ld["data"]["@type"] = json!(resource.semantic_class);
            }
            intended_json_ld["@context"] =
                json!([REGISTRY_RECORD_CONTEXT_ID, access_profile.context_reference]);
            assert!(
                json_ld_validator.is_valid(&intended_json_ld),
                "the exact {shape} JSON-LD schema accepts complete record identities"
            );

            for identity_member in ["@id", "@type"] {
                let mut invalid = intended_json_ld.clone();
                let target = if shape == "collection" {
                    &mut invalid["items"][1]
                } else {
                    &mut invalid["data"]
                };
                target
                    .as_object_mut()
                    .expect("record is an object")
                    .remove(identity_member);
                assert!(
                    !json_ld_validator.is_valid(&invalid),
                    "the exact {shape} JSON-LD schema must reject a missing {identity_member}"
                );
            }
        }
    }

    #[test]
    fn operation_bound_resource_metadata_requires_bearer_in_the_full_contract() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        registry.metadata_visibility.resources = Visibility::OperationBound;

        let generated = generate_artifacts(&registry).expect("artifacts generate");
        let full: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI parses");
        let public: Value = serde_json::from_slice(
            &generated
                .get("openapi.public.json")
                .expect("public OpenAPI")
                .content,
        )
        .expect("public OpenAPI parses");

        assert_eq!(
            full["paths"]["/v2/resources"]["get"]["security"],
            json!([{"bearerAuth": []}])
        );
        assert_eq!(
            full["paths"]["/v2/resources/{resource}"]["get"]["security"],
            json!([{"bearerAuth": []}])
        );
        for path in ["/v2", "/v2/resources", "/v2/resources/{resource}"] {
            assert!(
                full["paths"][path]["get"]["responses"].get("304").is_none(),
                "non-public metadata GET {path} must not document 304"
            );
        }
        assert!(public["paths"].get("/v2/resources").is_none());
        assert!(public["paths"].get("/v2/resources/{resource}").is_none());
    }

    #[test]
    fn non_cacheable_consultation_get_omits_not_modified_response() {
        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");

        registry.sources[0].profile = crate::contract::SourceProfile::LiveReadOnly;
        let generated = generate_artifacts(&registry).expect("live artifacts generate");
        let full: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI parses");
        let operation = &full["paths"]["/v2/resources/record/records/{recordIdentifier}"]["get"];
        assert!(operation["responses"].get("304").is_none());
        assert_eq!(operation["security"], json!([]));

        registry.sources[0].profile = crate::contract::SourceProfile::Snapshot;
        registry.resources[0].operations[0].access_profiles[0].access = CompiledAccess::Protected {
            scope: "records:read".into(),
            purpose: None,
            row_binding: None,
        };
        let generated = generate_artifacts(&registry).expect("protected artifacts generate");
        let full: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI parses");
        let operation = &full["paths"]["/v2/resources/record/records/{recordIdentifier}"]["get"];
        assert!(operation["responses"].get("304").is_none());
        assert_eq!(operation["security"], json!([{"bearerAuth": []}]));
    }

    #[test]
    fn lookup_openapi_matches_the_nested_body_and_utf8_byte_bounds() {
        use crate::model::CompiledSelector;

        let contract = RegistryContract::parse_yaml(compiler_tests::valid_contract())
            .expect("contract parses");
        let mut registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files(),
        )
        .expect("contract compiles");
        let operation = &mut registry.resources[0].operations[0];
        operation.identifier = "record.lookup.by-name".into();
        operation.kind = OperationKind::Lookup {
            name: "by-name".into(),
        };
        operation.query.selectors = vec![CompiledSelector {
            name: "name".into(),
            source_column: "name".into(),
            data_type: crate::contract::DataType::String,
            minimum_bytes: Some(2),
            maximum_bytes: Some(32),
            codelist: None,
        }];
        operation.query.maximum_request_body_bytes = Some(128);

        let generated = generate_artifacts(&registry).expect("artifacts generate");
        let full: Value = serde_json::from_slice(
            &generated
                .get("openapi.full.yaml")
                .expect("full OpenAPI")
                .content,
        )
        .expect("full OpenAPI parses");
        assert!(
            full["paths"]["/v2/resources/record/lookups/by-name"]["post"]["responses"]
                .get("304")
                .is_none()
        );
        let body = &full["paths"]["/v2/resources/record/lookups/by-name"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"];
        assert_eq!(body["required"], json!(["selectors"]));
        assert!(body["properties"].get("name").is_none());
        let selectors = &body["properties"]["selectors"];
        assert_eq!(selectors["required"], json!(["name"]));
        assert_eq!(selectors["additionalProperties"], false);
        let name = &selectors["properties"]["name"];
        assert_eq!(name["type"], "string");
        assert_eq!(name["x-registry-minimum-bytes"], 2);
        assert_eq!(name["x-registry-maximum-bytes"], 32);
        assert!(name["description"]
            .as_str()
            .expect("byte-bound description")
            .contains("UTF-8"));
        assert!(name.get("minLength").is_none());
        assert!(name.get("maxLength").is_none());
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
        registry.resources[0].operations[0].access_profiles[0].access = CompiledAccess::Protected {
            scope: "records:read".into(),
            purpose: None,
            row_binding: None,
        };
        registry.metadata_visibility.semantics = Visibility::OperationBound;
        registry.metadata_visibility.classifications = Visibility::OperationBound;
        registry.metadata_visibility.processing = Visibility::OperationBound;
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        for id in [
            "record--read--access-profile-public-vocabulary",
            "record--read--access-profile-public-context",
            "record--read--access-profile-public-schema",
            "record--read--access-profile-public-shacl",
            "record--read--access-profile-public-classifications",
            "record--read--access-profile-public-processing",
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
                artifact.access_binding,
                Some(ArtifactAccessBinding::AccessProfile {
                    identifier: "public".into()
                })
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
                    artifact.id == "record--read--access-profile-public-vocabulary"
                })
                .expect("semantic projection")
                .visibility,
            Visibility::OperationBound
        );
        for id in [
            "record--read--access-profile-public-classifications",
            "record--read--access-profile-public-processing",
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
}
