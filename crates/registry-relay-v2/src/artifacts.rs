// SPDX-License-Identifier: Apache-2.0
//! Repeatable artifacts generated only from the immutable compiled Registry.

use std::collections::BTreeSet;

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contract::Visibility;
use crate::model::{CompiledAccess, CompiledRegistry, OperationKind};
use crate::semantics::{
    full_record_schema, full_record_shacl, json_ld_context, local_vocabulary,
    representation_schema, representation_shacl,
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
    /// Present only for operation-bound artifacts. The HTTP layer must mount
    /// the artifact behind this exact compiled operation's static access gate.
    pub operation_identifier: Option<String>,
    pub sha256: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperationArtifactBindings {
    pub operation_identifier: String,
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
            if matches!(&operation.access, CompiledAccess::Protected { .. }) {
                let visibility = Visibility::OperationBound;
                push_json(
                    &mut artifacts,
                    &format!("{}-capability", operation.identifier),
                    &format!(
                        "artifacts/{}.capability.json",
                        operation_artifact_stem(&resource.id, &operation.kind)
                    ),
                    "application/json",
                    visibility,
                    (visibility == Visibility::OperationBound)
                        .then(|| operation.identifier.clone()),
                    &capability_inventory(
                        registry,
                        CapabilityProjection::Operation(&operation.identifier),
                    ),
                )?;
            }
            let disclosure = resource
                .disclosure_profiles
                .iter()
                .find(|profile| profile.id == operation.disclosure_profile)
                .ok_or(ArtifactError::MissingDisclosure)?;
            let semantic_visibility =
                projection_visibility(registry.metadata_visibility.semantics, &operation.access);
            let semantic_operation_identifier = (semantic_visibility == Visibility::OperationBound)
                .then(|| operation.identifier.clone());
            let suffix = operation_artifact_stem(&resource.id, &operation.kind);
            let vocabulary_path = format!("artifacts/{suffix}.vocabulary.jsonld");
            let context_path = format!("artifacts/{suffix}.context.jsonld");
            let schema_path = format!("artifacts/{suffix}.schema.json");
            let shacl_path = format!("artifacts/{suffix}.shacl.ttl");
            let classification_path = format!("artifacts/{suffix}.classifications.json");
            let processing_path = format!("artifacts/{suffix}.processing.json");
            push_json(
                &mut artifacts,
                &format!("{suffix}-vocabulary"),
                &vocabulary_path,
                "application/ld+json",
                semantic_visibility,
                semantic_operation_identifier.clone(),
                &local_vocabulary(registry, resource, &disclosure.properties),
            )?;
            push_json(
                &mut artifacts,
                &format!("{suffix}-context"),
                &context_path,
                "application/ld+json",
                semantic_visibility,
                semantic_operation_identifier.clone(),
                &json_ld_context(registry, resource, &disclosure.properties),
            )?;
            push_json(
                &mut artifacts,
                &format!("{suffix}-schema"),
                &schema_path,
                "application/schema+json",
                semantic_visibility,
                semantic_operation_identifier.clone(),
                &representation_schema(
                    registry,
                    resource,
                    &disclosure.properties,
                    &operation.schema_reference,
                    &operation.semantic_model_reference,
                ),
            )?;
            push_text(
                &mut artifacts,
                &format!("{suffix}-shacl"),
                &shacl_path,
                "text/turtle",
                semantic_visibility,
                semantic_operation_identifier,
                representation_shacl(registry, resource, &disclosure.properties).into_bytes(),
            );
            let classification_visibility = projection_visibility(
                registry.metadata_visibility.classifications,
                &operation.access,
            );
            push_json(
                &mut artifacts,
                &format!("{suffix}-classifications"),
                &classification_path,
                "application/json",
                classification_visibility,
                (classification_visibility == Visibility::OperationBound)
                    .then(|| operation.identifier.clone()),
                &json!({
                    "resourceIdentifier": resource.id,
                    "operationIdentifier": operation.identifier,
                    "properties": resource.properties.iter()
                        .filter(|property| disclosure.properties.contains(&property.name))
                        .map(|property| json!({
                            "property": property.name,
                            "classification": property.classification,
                        }))
                        .collect::<Vec<_>>(),
                }),
            )?;
            let processing_visibility =
                projection_visibility(registry.metadata_visibility.processing, &operation.access);
            let operation_ref = operation_contract_reference(&operation.kind);
            push_json(
                &mut artifacts,
                &format!("{suffix}-processing"),
                &processing_path,
                "application/json",
                processing_visibility,
                (processing_visibility == Visibility::OperationBound)
                    .then(|| operation.identifier.clone()),
                &json!({
                    "resourceIdentifier": resource.id,
                    "operationIdentifier": operation.identifier,
                    "descriptions": resource.processing_descriptions.iter()
                        .filter(|description| description.operation_refs.contains(&operation_ref))
                        .collect::<Vec<_>>(),
                }),
            )?;
            bindings.push(OperationArtifactBindings {
                operation_identifier: operation.identifier.clone(),
                vocabulary_path,
                context_path,
                representation_schema_path: schema_path,
                representation_shacl_path: shacl_path,
                classification_path,
                processing_path,
            });
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
    bindings.sort_by(|left, right| left.operation_identifier.cmp(&right.operation_identifier));
    Ok(ArtifactSet {
        contract_revision: registry.contract_revision.clone(),
        artifacts,
        operation_bindings: bindings,
    })
}

fn projection_visibility(configured: Visibility, access: &CompiledAccess) -> Visibility {
    match configured {
        Visibility::Public => Visibility::Public,
        Visibility::OperatorOnly => Visibility::OperatorOnly,
        Visibility::OperationBound => match access {
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
            if public_only && !matches!(operation.access, CompiledAccess::Public) {
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
            };
            let security = match &operation.access {
                CompiledAccess::Public => json!([]),
                CompiledAccess::Protected { .. } => {
                    json!([{"bearerAuth": []}])
                }
            };
            let mut parameters = vec![json!({
                "name": "fields",
                "in": "query",
                "required": false,
                "schema": {"type": "string", "minLength": 1},
                "description": "Duplicate-free comma-separated subset of the operation disclosure profile"
            })];
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
                }
                OperationKind::Read => parameters.push(json!({
                    "name": "recordIdentifier", "in": "path", "required": true,
                    "schema": {"type": "string", "minLength": 1}
                })),
                OperationKind::Lookup { .. } => {}
            }
            let mut operation_value = json!({
                "operationId": operation.identifier,
                "x-registry-family": "consultation",
                "x-registry-pattern": pattern,
                "x-registry-disclosure-profile": operation.disclosure_profile,
                "security": security,
                "parameters": parameters,
                "responses": {
                    "200": {
                        "description": "A validated minimum-disclosure Registry response",
                        "content": {
                            "application/json": {"schema": operation_response_schema(operation)},
                            "application/ld+json": {"schema": operation_response_schema(operation)}
                        }
                    },
                    "default": {"$ref": "#/components/responses/Problem"}
                }
            });
            if let CompiledAccess::Protected { scope, .. } = &operation.access {
                operation_value
                    .as_object_mut()
                    .expect("operation object")
                    .insert("x-registry-required-scope".into(), json!(scope));
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

fn operation_response_schema(operation: &crate::model::CompiledOperation) -> Value {
    let meta = json!({"type": "object"});
    match &operation.kind {
        OperationKind::List => json!({
            "type": "object", "additionalProperties": false,
            "required": ["items", "pageInfo", "meta"],
            "properties": {
                "items": {"type": "array", "items": {"$ref": operation.schema_reference}},
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
                "data": {"$ref": operation.schema_reference},
                "meta": meta
            }
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
    }
}

#[derive(Clone, Copy)]
enum CapabilityProjection<'a> {
    Public,
    Full,
    Operation(&'a str),
}

fn capability_inventory(
    registry: &CompiledRegistry,
    projection: CapabilityProjection<'_>,
) -> Value {
    let capabilities = registry
        .resources
        .iter()
        .flat_map(|resource| {
            resource.operations.iter().filter_map(move |operation| {
                let include = match projection {
                    CapabilityProjection::Public => {
                        matches!(&operation.access, CompiledAccess::Public)
                    }
                    CapabilityProjection::Full => true,
                    CapabilityProjection::Operation(identifier) => {
                        operation.identifier == identifier
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
                    "family": "consultation",
                    "pattern": pattern,
                    "profile": if matches!(&operation.kind, OperationKind::Lookup { .. }) { Value::String("exact".into()) } else { Value::Null },
                    "schemaReference": operation.schema_reference,
                    "semanticModelReference": operation.semantic_model_reference,
                    "contextReference": operation.context_reference,
                }))
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
            "contractRevision", "principalKind"
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
            "disclosureProfile": {"type": "string", "minLength": 1},
            "processingDescriptionIdentifiers": {"type": "array", "items": {"type": "string", "minLength": 1}, "uniqueItems": true},
            "selectedProperties": {"type": "array", "items": {"type": "string", "minLength": 1}, "uniqueItems": true},
            "maximumHandling": {"enum": ["public", "internal", "confidential", "restricted"]},
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
            "artifacts/record--read.schema.json",
            "artifacts/record--read.shacl.ttl",
            "artifacts/record--read.context.jsonld",
            "artifacts/record--read.vocabulary.jsonld",
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
        registry.resources[0].operations[0].access = CompiledAccess::Protected {
            scope: "records:read".into(),
            purpose: None,
            row_binding: None,
        };
        registry.metadata_visibility.semantics = Visibility::OperationBound;
        registry.metadata_visibility.classifications = Visibility::OperationBound;
        registry.metadata_visibility.processing = Visibility::OperationBound;
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        for id in [
            "record--read-vocabulary",
            "record--read-context",
            "record--read-schema",
            "record--read-shacl",
            "record--read-classifications",
            "record--read-processing",
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
        }

        registry.metadata_visibility.semantics = Visibility::Public;
        registry.metadata_visibility.classifications = Visibility::OperatorOnly;
        registry.metadata_visibility.processing = Visibility::OperatorOnly;
        let generated = generate_artifacts(&registry).expect("artifacts generate");
        assert_eq!(
            generated
                .artifacts
                .iter()
                .find(|artifact| artifact.id == "record--read-vocabulary")
                .expect("semantic projection")
                .visibility,
            Visibility::Public
        );
        for id in ["record--read-classifications", "record--read-processing"] {
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
