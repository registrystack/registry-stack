// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::contract::{
    EventSource, EventTrigger, FieldTypeSource, MutationMode, Operation, PackageIdentitySource,
    ProvenanceFieldSource,
};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::DdlInventory;
use crate::manifest_adapter::project_manifest_artifacts;
use crate::model::{
    ActionRouteKind, CompiledAccessInventory, CompiledAction, CompiledActionInput,
    CompiledActionInventory, CompiledActionRoute, CompiledActionTargetUseSource,
    CompiledChangeRequestApplication, CompiledChangeRequestApplicationMode,
    CompiledChangeRequestDisposition, CompiledChangeRequestMutation, CompiledChangeRequestPlanner,
    CompiledChangeRequestRetentionMode, CompiledChangeRequestReviewMode,
    CompiledChangeRequestTargetBinding, CompiledChangeRequestValue, CompiledEntity,
    CompiledEventDeliveryInventory, CompiledManifestProjection, CompiledMetadataInventory,
    CompiledModuleIdentity, CompiledQueryInventory, CompiledQueryKind, CompiledQueryOperation,
    CompiledQueryTemporalValueKind, CompiledRevisionKind, CompiledRoute, CompiledRouteInventory,
    HttpMethod,
};
use crate::physical_names::{hex_prefix, PhysicalNameInventory};
use crate::record_profile::{link_header_value, CONTEXT_IDENTIFIER, PROFILE_IDENTIFIER};

pub const REGISTRY_METADATA_ARTIFACT_PATH: &str = "generated/metadata/registry.json";

pub(crate) struct EventDataSchemaBinding {
    pub schema: Value,
    pub fingerprint: String,
    pub data_schema: String,
    pub artifact_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeneratedArtifact {
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GeneratedArtifacts {
    artifacts: BTreeMap<String, GeneratedArtifact>,
}

impl GeneratedArtifacts {
    pub fn entries(&self) -> &BTreeMap<String, GeneratedArtifact> {
        &self.artifacts
    }

    pub fn get(&self, path: &str) -> Option<&GeneratedArtifact> {
        self.artifacts.get(path)
    }

    pub fn canonical_inventory_bytes(&self) -> Result<Vec<u8>, Diagnostic> {
        let value = serde_json::to_value(self).map_err(|_| canonicalization_error())?;
        canonicalize_json(&value).map_err(|_| canonicalization_error())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EffectiveModel<'a> {
    pub registry_id: &'a str,
    pub version: &'a str,
    pub default_language: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<&'a PackageIdentitySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_projection: Option<&'a CompiledManifestProjection>,
    pub module_order: &'a [String],
    pub module_closure: &'a [CompiledModuleIdentity],
    pub entities: &'a BTreeMap<String, CompiledEntity>,
    pub physical_names: &'a PhysicalNameInventory,
    #[serde(skip_serializing_if = "CompiledActionInventory::is_empty")]
    pub action_inventory: &'a CompiledActionInventory,
    pub metadata_inventory: &'a CompiledMetadataInventory,
    pub query_inventory: &'a CompiledQueryInventory,
    pub event_delivery_inventory: &'a CompiledEventDeliveryInventory,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_artifacts(
    registry_id: &str,
    version: &str,
    default_language: &str,
    package: Option<&PackageIdentitySource>,
    manifest_projection: Option<&CompiledManifestProjection>,
    module_order: &[String],
    module_closure: &[CompiledModuleIdentity],
    entities: &BTreeMap<String, CompiledEntity>,
    physical_names: &PhysicalNameInventory,
    actions: &CompiledActionInventory,
    routes: &CompiledRouteInventory,
    access: &CompiledAccessInventory,
    metadata: &CompiledMetadataInventory,
    query: &CompiledQueryInventory,
    event_deliveries: &CompiledEventDeliveryInventory,
    ddl: &DdlInventory,
) -> Result<GeneratedArtifacts, Diagnostic> {
    let mut artifacts = BTreeMap::new();
    let effective_model = EffectiveModel {
        registry_id,
        version,
        default_language,
        package,
        manifest_projection,
        module_order,
        module_closure,
        entities,
        physical_names,
        action_inventory: actions,
        metadata_inventory: metadata,
        query_inventory: query,
        event_delivery_inventory: event_deliveries,
    };
    insert_json_value(
        &mut artifacts,
        "compiled/effective-model.json",
        &sanitized_effective_model(&effective_model)?,
    )?;
    insert_json(&mut artifacts, "compiled/modules.json", &module_closure)?;
    if !actions.is_empty() {
        insert_json(&mut artifacts, "compiled/actions.json", actions)?;
    }
    insert_json(&mut artifacts, "compiled/routes.json", routes)?;
    insert_json(&mut artifacts, "compiled/access.json", access)?;
    insert_json(&mut artifacts, "compiled/metadata-inventory.json", metadata)?;
    insert_json(&mut artifacts, "compiled/query-inventory.json", query)?;
    insert_json(
        &mut artifacts,
        "compiled/event-deliveries.json",
        event_deliveries,
    )?;
    if actions.is_empty() {
        insert_json(&mut artifacts, REGISTRY_METADATA_ARTIFACT_PATH, metadata)?;
    } else {
        insert_json_value(
            &mut artifacts,
            REGISTRY_METADATA_ARTIFACT_PATH,
            &registry_metadata_artifact(metadata, actions),
        )?;
    }
    insert_bytes(
        &mut artifacts,
        "generated/postgres/schema.sql",
        "application/sql",
        ddl.script().into_bytes(),
    );

    let mut schemas = BTreeMap::new();
    for entity in entities.values() {
        let schema = entity_schema(entity, entities);
        let path = format!("generated/schemas/{}.schema.json", entity.id);
        insert_json_value(&mut artifacts, &path, &schema)?;
        schemas.insert(entity.id.clone(), schema);
    }
    for delivery in &event_deliveries.deliveries {
        let entity = entities
            .get(&delivery.entity_id)
            .expect("compiled event delivery refers to a compiled entity");
        let event = entity
            .events
            .get(&delivery.event_id)
            .expect("compiled event delivery refers to a compiled event");
        let binding = event_data_schema_binding(registry_id, entity, event)?;
        debug_assert_eq!(delivery.data_schema, binding.data_schema);
        debug_assert_eq!(delivery.data_schema_fingerprint, binding.fingerprint);
        debug_assert_eq!(delivery.data_schema_artifact_path, binding.artifact_path);
        insert_json_value(&mut artifacts, &binding.artifact_path, &binding.schema)?;
    }
    for action in &actions.actions {
        insert_json_value(
            &mut artifacts,
            &format!(
                "generated/action-schemas/{}.invoke.input.schema.json",
                action.id
            ),
            &openapi_action_input_schema(action),
        )?;
        insert_json_value(
            &mut artifacts,
            &format!(
                "generated/action-schemas/{}.invoke.response.schema.json",
                action.id
            ),
            &openapi_action_response_schema(action, None),
        )?;
        if action.condition_route.is_some() {
            insert_json_value(
                &mut artifacts,
                &format!(
                    "generated/action-schemas/{}.target-conditions.input.schema.json",
                    action.id
                ),
                &openapi_action_condition_request_schema(action),
            )?;
            insert_json_value(
                &mut artifacts,
                &format!(
                    "generated/action-schemas/{}.target-conditions.response.schema.json",
                    action.id
                ),
                &openapi_action_condition_response_schema(action),
            )?;
        }
    }
    let openapi = openapi_document(
        registry_id,
        version,
        entities,
        routes,
        actions,
        query,
        &schemas,
    );
    insert_json_value(&mut artifacts, "generated/openapi.json", &openapi)?;
    if let Some(projection) = manifest_projection {
        let projected = project_manifest_artifacts(registry_id, projection, entities)?;
        insert_bytes(
            &mut artifacts,
            "generated/manifest/registry-manifest.json",
            "application/json",
            projected.manifest,
        );
        insert_bytes(
            &mut artifacts,
            "generated/manifest/dcat.jsonld",
            "application/ld+json",
            projected.dcat,
        );
    }
    Ok(GeneratedArtifacts { artifacts })
}

/// The effective model is a generated operator artifact, not planner runtime
/// input. Planner executable bytes and relative storage location remain inside
/// the sealed package capture. The artifact retains a source-safe digest and
/// coarse declaring origin for operator explanation.
fn sanitized_effective_model(model: &EffectiveModel<'_>) -> Result<Value, Diagnostic> {
    let mut value = serde_json::to_value(model).map_err(|_| canonicalization_error())?;
    sanitize_effective_model_planners(&mut value);
    Ok(value)
}

fn sanitize_effective_model_planners(value: &mut Value) {
    let Some(entities) = value
        .as_object_mut()
        .and_then(|model| model.get_mut("entities"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for entity in entities.values_mut() {
        let Some(planner) = entity
            .as_object_mut()
            .and_then(|entity| entity.get_mut("changeRequest"))
            .and_then(Value::as_object_mut)
            .and_then(|request| request.get_mut("planner"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        planner.remove("scriptBytes");
        planner.remove("scriptPath");
        let declaring_origin = match planner.remove("sourceModule") {
            Some(Value::String(identifier)) => json!({"kind": "module", "id": identifier}),
            Some(Value::Null) | None => json!({"kind": "project"}),
            Some(_) => return,
        };
        planner.insert("declaringOrigin".to_owned(), declaring_origin);
    }
}

pub(crate) fn event_data_schema_binding(
    registry_id: &str,
    entity: &CompiledEntity,
    event: &EventSource,
) -> Result<EventDataSchemaBinding, Diagnostic> {
    let mut value_properties = Map::new();
    for field_id in &event.projection {
        let field = entity
            .fields
            .get(field_id)
            .expect("validated event projection refers to a compiled field");
        let schema = field_schema(&field.field_type);
        let schema = if field.required {
            schema
        } else {
            json!({"anyOf": [schema, {"type": "null"}]})
        };
        value_properties.insert(field_id.clone(), schema);
    }
    let trigger = match event.trigger {
        EventTrigger::Created => "created",
        EventTrigger::Patched => "patched",
        EventTrigger::Tombstoned => "tombstoned",
        EventTrigger::RequestLifecycle => "request_lifecycle",
    };
    let mut properties = Map::new();
    properties.insert("entity".to_owned(), json!({"const": entity.id}));
    properties.insert(
        "recordId".to_owned(),
        json!({"type": "string", "format": "uuid"}),
    );
    properties.insert(
        "revision".to_owned(),
        json!({"type": "integer", "format": "int64", "minimum": 1}),
    );
    properties.insert("trigger".to_owned(), json!({"const": trigger}));
    properties.insert("packageRevision".to_owned(), json!({"type": "string"}));
    if event.trigger == EventTrigger::RequestLifecycle {
        properties.insert(
            "request".to_owned(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "proposalVersion": {"type": "integer", "minimum": 1},
                    "workflowRevision": {"type": "integer", "minimum": 1},
                    "transition": {"type": "string"},
                    "fromState": {"type": "string"},
                    "toState": {"type": "string"},
                    "stage": {"type": ["string", "null"]},
                    "effectDigest": {"type": ["string", "null"]},
                    "deduplicationKey": {"type": "string"}
                },
                "required": [
                    "proposalVersion",
                    "workflowRevision",
                    "transition",
                    "fromState",
                    "toState",
                    "stage",
                    "effectDigest",
                    "deduplicationKey"
                ]
            }),
        );
    }
    properties.insert(
        "values".to_owned(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": value_properties,
            "required": event.projection,
        }),
    );
    let required = if event.trigger == EventTrigger::RequestLifecycle {
        vec![
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "request",
            "values",
        ]
    } else {
        vec![
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "values",
        ]
    };
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required
    });
    let bytes = canonicalize_json(&schema).map_err(|_| canonicalization_error())?;
    let digest = Sha256::digest(&bytes);
    let fingerprint = format!("sha256:{}", hex_prefix(&digest, digest.len()));
    let data_schema = format!(
        "urn:breg:event-schema:{registry_id}:{}:{}:{fingerprint}",
        entity.id, event.id
    );
    let artifact_path = format!(
        "generated/event-schemas/{}.{}.schema.json",
        entity.id, event.id
    );
    Ok(EventDataSchemaBinding {
        schema,
        fingerprint,
        data_schema,
        artifact_path,
    })
}

fn entity_schema(entity: &CompiledEntity, entities: &BTreeMap<String, CompiledEntity>) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.stored_fields {
        properties.insert(
            field.logical.api_name.clone(),
            field_value_schema(&field.logical.field_type, !field.required),
        );
        if field.required {
            required.push(Value::String(field.logical.api_name.clone()));
        }
    }
    for field in entity.derived_fields.values() {
        let mut schema = field_value_schema(&field.logical.field_type, true);
        schema
            .as_object_mut()
            .expect("field schemas are objects")
            .insert("readOnly".to_owned(), Value::Bool(true));
        properties.insert(field.logical.api_name.clone(), schema);
    }
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:entity:{}", entity.id),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-registry-mutationMode": match entity.mutation_mode {
            MutationMode::Mutable => "mutable",
            MutationMode::CreateOnly => "create_only",
        }
    });
    let object = schema.as_object_mut().expect("entity schema is an object");
    if entity.change_control.is_some() {
        object.insert(
            "x-registry-changeControl".to_owned(),
            render_change_control(entity, entities),
        );
    }
    if entity.change_request.is_some() {
        object.insert(
            "x-registry-changeRequest".to_owned(),
            render_change_request(entity, entities),
        );
    }
    schema
}

pub(crate) fn openapi_input_schema_id(entity_id: &str, operation: Operation) -> String {
    format!("{entity_id}-{}-input", operation_name(operation))
}

pub(crate) fn openapi_entity_input_schema(
    entity: &CompiledEntity,
    writable_fields: Option<&BTreeSet<String>>,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.stored_fields {
        if writable_fields.is_some_and(|fields| !fields.contains(&field.logical.id)) {
            continue;
        }
        properties.insert(
            field.logical.api_name.clone(),
            field_value_schema(&field.logical.field_type, !field.required),
        );
        if field.required {
            required.push(Value::String(field.logical.api_name.clone()));
        }
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:entity:{}:input", entity.id),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-registry-mutationMode": match entity.mutation_mode {
            MutationMode::Mutable => "mutable",
            MutationMode::CreateOnly => "create_only",
        }
    })
}

pub(crate) fn openapi_request_action_input_schema(operation: Operation) -> Value {
    let proposal_binding = json!({
        "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
        "effectDigest": {
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
            "description": "Digest of the immutable proposal effects displayed to the actor."
        }
    });
    match operation {
        Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ApplyRequest => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["proposalVersion", "effectDigest"],
            "properties": proposal_binding,
        }),
        Operation::ReviseRequest => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "required": ["rebase"],
            "properties": {
                "rebase": {"type": "boolean"}
            }
        }),
        _ => json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
    }
}

fn render_change_control(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Value {
    let controlled_operations = entity
        .change_control
        .as_ref()
        .map(|control| {
            control
                .required_for
                .iter()
                .map(|operation| operation_name(*operation))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let eligible_request_types = entities
        .values()
        .filter_map(|request_entity| {
            let request = request_entity.change_request.as_ref()?;
            let operations = request
                .effects
                .iter()
                .filter(|effect| effect.target.entity_id == entity.id)
                .map(|effect| operation_name(effect.operation))
                .chain(
                    request
                        .planner
                        .iter()
                        .flat_map(|planner| planner.writes.iter())
                        .filter(|write| write.target_entity_id == entity.id)
                        .map(|write| operation_name(write.operation)),
                )
                .collect::<BTreeSet<_>>();
            (!operations.is_empty()).then(|| {
                json!({
                    "requestEntity": request_entity.id,
                    "requestRoute": request_entity.route,
                    "operations": operations.into_iter().collect::<Vec<_>>(),
                    "contractFingerprint": request.contract_fingerprint,
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "requiredFor": controlled_operations,
        "directWriteRestriction": "controlled_operations_require_compiled_change_request_application",
        "eligibleRequestTypes": eligible_request_types,
    })
}

fn render_change_request(
    entity: &CompiledEntity,
    entities: &BTreeMap<String, CompiledEntity>,
) -> Value {
    let request = entity
        .change_request
        .as_ref()
        .expect("caller checked change request presence");
    json!({
        "requestEntity": request.request_entity_id,
        "contractFingerprint": request.contract_fingerprint,
        "planner": render_request_planner(request.planner.as_ref(), request),
        "reviewMode": render_request_review_mode(request.review_mode),
        "application": render_request_application(&request.application),
        "retention": render_request_retention(request.retention_mode),
        "bounds": {
            "maximumTargets": request.maximum_targets,
            "maximumFieldMutations": request.maximum_field_mutations,
            "maximumSnapshotBytes": request.maximum_snapshot_bytes,
        },
        "stateEnvelope": {
            "states": ["draft", "submitted", "approved", "needs_changes", "rejected", "canceled", "applied"],
            "proposalBinding": ["proposalVersion", "effectDigest", "contractFingerprint"],
            "actionAvailability": "advisory_rechecked_on_use",
        },
        "effects": request.effects.iter().map(|effect| {
            let target = entities.get(&effect.target.entity_id);
            json!({
                "id": effect.id,
                "operation": operation_name(effect.operation),
                "target": {
                    "entity": effect.target.entity_id,
                    "binding": render_target_binding(&effect.target.binding),
                },
                "mutations": effect.mutations.iter().map(|mutation| {
                    render_request_mutation(mutation, target)
                }).collect::<Vec<_>>(),
                "dependsOn": effect.depends_on.iter().collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
        "stages": request.stages,
        "actions": request.actions.iter().map(|action| json!({
            "operation": operation_name(action.operation.access_operation()),
            "stage": action.review_stage,
            "method": "POST",
            "requiresIdempotencyKey": true,
            "requiresRecordPrecondition": true,
            "inputSchema": openapi_input_schema_id(&entity.id, action.operation.access_operation()),
            "responseSchema": "ChangeRequestActionResponse",
        })).collect::<Vec<_>>(),
        "reviewGrants": request.review_grants,
        "applyGrants": request.apply_grants,
        "presenceGrants": request.presence_grants,
        "targetEntities": request.target_entities,
    })
}

/// Source-free change-request capability projection for caller-filtered
/// Registry metadata. It intentionally omits effects, grants, targets and all
/// planner provenance, so this descriptive surface cannot manufacture action
/// authority or disclose hidden configuration.
#[allow(dead_code)] // Called by the production /v1/registry metadata route.
pub(crate) fn request_capability_metadata(
    request: &crate::model::CompiledChangeRequest,
    _visible_fields: &BTreeSet<String>,
) -> Value {
    let planner = match request.planner.as_ref() {
        None => json!({"kind": "declarative"}),
        Some(planner) => {
            let operations = planner
                .writes
                .iter()
                .map(|write| operation_name(write.operation))
                .collect::<BTreeSet<_>>();
            json!({
                "kind": "rhai",
                "abi": planner.abi,
                "limits": render_request_planner(Some(planner), request)["limits"],
                "possibleWriteCount": planner.writes.len(),
                "possibleWriteOperations": operations,
            })
        }
    };
    json!({
        "planner": planner,
        "reviewMode": render_request_review_mode(request.review_mode),
        "application": render_request_application(&request.application),
    })
}

fn render_request_planner(
    planner: Option<&CompiledChangeRequestPlanner>,
    request: &crate::model::CompiledChangeRequest,
) -> Value {
    match planner {
        None => json!({"kind": "declarative"}),
        Some(planner) => json!({
            "kind": "rhai",
            "abi": planner.abi,
            "limits": {
                "maximumTargets": request.maximum_targets,
                "maximumFieldMutations": request.maximum_field_mutations,
                "maximumSnapshotBytes": request.maximum_snapshot_bytes,
                "maximumSourceBytes": planner.limits.maximum_source_bytes,
                "maximumOperations": planner.limits.maximum_operations,
                "maximumCallDepth": planner.limits.maximum_call_depth,
                "maximumExpressionDepth": planner.limits.maximum_expression_depth,
                "maximumStringBytes": planner.limits.maximum_string_bytes,
                "maximumArrayItems": planner.limits.maximum_array_items,
                "maximumMapEntries": planner.limits.maximum_map_entries,
                "maximumModules": planner.limits.maximum_modules,
            },
            "possibleWrites": planner.writes.iter().map(|write| {
                let target = match &write.target_from_field {
                    Some(field) => json!({"fromField": field}),
                    None => json!({"entity": write.target_entity_id}),
                };
                json!({
                    "target": target,
                    "operation": operation_name(write.operation),
                    "fields": write.fields,
                })
            }).collect::<Vec<_>>(),
        }),
    }
}

fn render_request_review_mode(mode: CompiledChangeRequestReviewMode) -> &'static str {
    match mode {
        CompiledChangeRequestReviewMode::None => "none",
        CompiledChangeRequestReviewMode::Stages => "staged",
    }
}

fn render_request_application(application: &CompiledChangeRequestApplication) -> Value {
    let mode = match application.mode {
        CompiledChangeRequestApplicationMode::Manual => "manual",
        CompiledChangeRequestApplicationMode::Automatic => "automatic",
        CompiledChangeRequestApplicationMode::Planner => "planner",
    };
    let allowed_dispositions = match application.mode {
        CompiledChangeRequestApplicationMode::Manual => vec!["queue"],
        CompiledChangeRequestApplicationMode::Automatic => vec!["apply"],
        CompiledChangeRequestApplicationMode::Planner => application
            .allowed_dispositions
            .iter()
            .map(|disposition| match disposition {
                CompiledChangeRequestDisposition::Apply => "apply",
                CompiledChangeRequestDisposition::Queue => "queue",
            })
            .collect::<Vec<_>>(),
    };
    let queue_reasons = application
        .queue_reasons
        .iter()
        .map(|(code, label)| json!({"code": code, "label": label}))
        .collect::<Vec<_>>();
    json!({
        "mode": mode,
        "allowedDispositions": allowed_dispositions,
        "queueReasons": queue_reasons,
    })
}

fn render_request_retention(mode: CompiledChangeRequestRetentionMode) -> Value {
    let mode = match mode {
        CompiledChangeRequestRetentionMode::Retain => "retain",
        CompiledChangeRequestRetentionMode::OperatorErase => "operator_erase",
    };
    json!({
        "mode": mode,
        "effectivePolicy": {
            "payloadSnapshots": match mode {
                "retain" => "retained_until_package_or_operator_policy_changes",
                "operator_erase" => "operator_erasable_after_terminal_state",
                _ => unreachable!("closed retention mode"),
            },
            "provenanceStub": "retained_while_target_revisions_reference_request",
            "erasedDetailMarker": "request.detailErased",
        }
    })
}

fn render_target_binding(binding: &CompiledChangeRequestTargetBinding) -> Value {
    match binding {
        CompiledChangeRequestTargetBinding::Existing { from_field } => {
            json!({"kind": "existing", "fromField": from_field})
        }
        CompiledChangeRequestTargetBinding::ReservedCreate { effect } => {
            json!({"kind": "reserved_create", "effect": effect})
        }
    }
}

fn render_request_mutation(
    mutation: &CompiledChangeRequestMutation,
    target: Option<&CompiledEntity>,
) -> Value {
    match mutation {
        CompiledChangeRequestMutation::Set { field, value } => json!({
            "kind": "set",
            "field": field,
            "apiName": target.and_then(|entity| api_field_name(entity, field)),
            "value": render_request_value(value),
        }),
        CompiledChangeRequestMutation::Clear { field } => json!({
            "kind": "clear",
            "field": field,
            "apiName": target.and_then(|entity| api_field_name(entity, field)),
        }),
    }
}

fn render_request_value(value: &CompiledChangeRequestValue) -> Value {
    match value {
        CompiledChangeRequestValue::FromField { field } => {
            json!({"kind": "from_field", "field": field})
        }
        CompiledChangeRequestValue::FromEffect {
            effect,
            target_entity_id,
        } => json!({
            "kind": "from_effect",
            "effect": effect,
            "targetEntity": target_entity_id,
        }),
    }
}

pub(crate) fn openapi_action_input_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-invoke-input")
}

pub(crate) fn openapi_action_condition_request_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-target-conditions-input")
}

pub(crate) fn openapi_action_condition_response_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-target-conditions-response")
}

pub(crate) fn openapi_action_response_schema_id(action_id: &str) -> String {
    format!("action-{action_id}-invoke-response")
}

pub(crate) fn openapi_action_input_schema(action: &CompiledAction) -> Value {
    let input_schema = action_input_properties_schema(action.inputs.iter());
    let condition_inputs = action_condition_inputs(action);
    let mut properties = Map::from_iter([("input".to_owned(), input_schema)]);
    if !condition_inputs.is_empty() {
        properties.insert(
            "preconditions".to_owned(),
            action_preconditions_schema(condition_inputs.iter().copied()),
        );
    }
    let mut required = vec![Value::String("input".to_owned())];
    if !condition_inputs.is_empty() {
        required.push(Value::String("preconditions".to_owned()));
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:invoke-input", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
        "x-registry-action": action.id,
        "x-registry-requiredConditionKeys": condition_inputs
            .iter()
            .map(|input| input.api_name.as_str())
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn openapi_action_condition_request_schema(action: &CompiledAction) -> Value {
    let condition_inputs = action_condition_inputs(action);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:target-conditions-input", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["input"],
        "properties": {
            "input": action_condition_input_properties_schema(condition_inputs.iter().copied()),
        },
        "x-registry-action": action.id,
        "x-registry-requiredConditionKeys": condition_inputs
            .iter()
            .map(|input| input.api_name.as_str())
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn openapi_action_condition_response_schema(action: &CompiledAction) -> Value {
    let condition_inputs = action_condition_inputs(action);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:target-conditions-response", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["preconditions"],
        "properties": {
            "preconditions": action_preconditions_schema(condition_inputs.iter().copied()),
        },
        "x-registry-action": action.id,
    })
}

pub(crate) fn openapi_action_response_schema(
    action: &CompiledAction,
    selected_result_effects: Option<&BTreeSet<String>>,
) -> Value {
    let result_shapes = action_response_result_shapes(action, selected_result_effects);
    let results_schema = match result_shapes.as_slice() {
        [shape] => action_results_schema(action, shape),
        shapes => json!({
            "oneOf": shapes
                .iter()
                .map(|shape| action_results_schema(action, shape))
                .collect::<Vec<_>>()
        }),
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("urn:breg:action:{}:invoke-response", action.id),
        "type": "object",
        "additionalProperties": false,
        "required": ["action", "applicationId", "results"],
        "properties": {
            "action": {"const": action.id},
            "applicationId": {"type": "string", "format": "uuid"},
            "results": results_schema
        }
    })
}

fn action_response_result_shapes(
    action: &CompiledAction,
    selected_result_effects: Option<&BTreeSet<String>>,
) -> Vec<BTreeSet<String>> {
    if let Some(results) = selected_result_effects {
        return vec![known_action_result_effects(action, results)];
    }
    let mut shapes = action
        .grants
        .iter()
        .map(|grant| known_action_result_effects(action, &grant.results))
        .collect::<BTreeSet<_>>();
    if shapes.is_empty() {
        shapes.insert(known_action_result_effects(action, &action.result_effects));
    }
    shapes.into_iter().collect()
}

fn known_action_result_effects(
    action: &CompiledAction,
    results: &BTreeSet<String>,
) -> BTreeSet<String> {
    action
        .effects
        .iter()
        .filter(|effect| results.contains(&effect.id))
        .map(|effect| effect.id.clone())
        .collect()
}

fn action_results_schema(action: &CompiledAction, effect_ids: &BTreeSet<String>) -> Value {
    let result_properties = action
        .effects
        .iter()
        .filter(|effect| effect_ids.contains(&effect.id))
        .map(|effect| {
            (
                effect.id.clone(),
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["entity", "recordId", "revision"],
                    "properties": {
                        "entity": {"const": effect.target.entity_id},
                        "recordId": {"type": "string", "format": "uuid"},
                        "revision": {"type": "integer", "format": "int64", "minimum": 1}
                    }
                }),
            )
        })
        .collect::<Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": effect_ids.iter().cloned().collect::<Vec<_>>(),
        "properties": result_properties,
    })
}

pub(crate) fn openapi_action_operation(
    route: &CompiledActionRoute,
    action: &CompiledAction,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Value {
    let mut operation = Map::from_iter([
        ("operationId".to_owned(), json!(route.id)),
        (
            "x-registry-action".to_owned(),
            public_action_metadata_entry(
                action,
                selected_profile_from_access_profiles(access_profiles),
            ),
        ),
        (
            "x-registry-operation".to_owned(),
            json!(operation_name(route.operation)),
        ),
        (
            "x-registry-routeKind".to_owned(),
            json!(action_route_kind_name(route.kind)),
        ),
        (
            "security".to_owned(),
            action_operation_security(action, route, access_profiles),
        ),
    ]);
    match access_profiles {
        OpenApiAccessProfiles::All => {
            operation.insert(
                "x-registry-accessProfiles".to_owned(),
                json!(route.access_profiles),
            );
            operation.insert(
                "x-registry-defaultAccessProfile".to_owned(),
                json!(route.default_access_profile),
            );
        }
        OpenApiAccessProfiles::Selected(profile) => {
            operation.insert("x-registry-accessProfile".to_owned(), json!(profile));
        }
    }
    let mut parameters = vec![
        header_parameter(
            "traceparent",
            false,
            traceparent_schema(),
            "Optional W3C trace context. Responses carry Registry trace context for the request.",
        ),
        access_profile_parameter(),
    ];
    if route.kind == ActionRouteKind::Invoke {
        parameters.push(header_parameter(
            "Idempotency-Key",
            true,
            json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"}),
            "Idempotency key bound to the action route, selected profile, package revision, normalized action input, preconditions, and granted result contract.",
        ));
    }
    operation.insert("parameters".to_owned(), Value::Array(parameters));
    operation.insert(
        "requestBody".to_owned(),
        json_request_body(json!({"$ref": format!(
            "#/components/schemas/{}",
            match route.kind {
                ActionRouteKind::Invoke => openapi_action_input_schema_id(&action.id),
                ActionRouteKind::TargetConditions => {
                    openapi_action_condition_request_schema_id(&action.id)
                }
            }
        )})),
    );
    operation.insert(
        "responses".to_owned(),
        action_operation_responses(route, action),
    );
    Value::Object(operation)
}

pub(crate) fn public_action_metadata(actions: &CompiledActionInventory) -> Value {
    json!({
        "actions": actions
            .actions
            .iter()
            .map(|action| public_action_metadata_entry(action, None))
            .collect::<Vec<_>>()
    })
}

fn registry_metadata_artifact(
    metadata: &CompiledMetadataInventory,
    actions: &CompiledActionInventory,
) -> Value {
    let mut value = serde_json::to_value(metadata).expect("compiled metadata serializes");
    let object = value
        .as_object_mut()
        .expect("compiled metadata serializes as object");
    object.insert(
        "actions".to_owned(),
        public_action_metadata(actions)["actions"].clone(),
    );
    value
}

pub(crate) fn public_action_metadata_entry(
    action: &CompiledAction,
    selected_profile: Option<&str>,
) -> Value {
    let condition_inputs = action_condition_inputs(action);
    let selected_result_effects = action_selected_result_effects(action, selected_profile);
    let access = match selected_profile {
        Some(profile) => json!({"selectedProfile": profile}),
        None => json!({"accessProfiles": action_profile_ids(action)}),
    };
    json!({
        "id": action.id,
        "route": action.route,
        "conditionRoute": action.condition_route,
        "contractFingerprint": action.contract_fingerprint,
        "inputs": action.inputs.iter().map(action_input_metadata).collect::<Vec<_>>(),
        "referenceInputs": action.inputs.iter().filter_map(reference_input_metadata).collect::<Vec<_>>(),
        "requiredConditionKeys": condition_inputs
            .iter()
            .map(|input| input.api_name.as_str())
            .collect::<Vec<_>>(),
        "resultEffects": action.effects.iter()
            .filter(|effect| selected_result_effects.contains(&effect.id))
            .map(|effect| json!({
                "effect": effect.id,
                "entity": effect.target.entity_id,
                "operation": operation_name(effect.operation),
            }))
            .collect::<Vec<_>>(),
        "access": access,
        "routes": {
            "invoke": {
                "method": "POST",
                "path": action.route,
                "operationId": format!("actions.{}.invoke", action.id),
                "requiresIdempotencyKey": true,
                "inputSchema": openapi_action_input_schema_id(&action.id),
                "responseSchema": openapi_action_response_schema_id(&action.id),
            },
            "targetConditions": action.condition_route.as_ref().map(|path| json!({
                "method": "POST",
                "path": path,
                "operationId": format!("actions.{}.target_conditions", action.id),
                "requiresIdempotencyKey": false,
                "inputSchema": openapi_action_condition_request_schema_id(&action.id),
                "responseSchema": openapi_action_condition_response_schema_id(&action.id),
            })),
        },
        "bounds": {
            "maximumTargets": action.maximum_targets,
            "maximumFieldMutations": action.maximum_field_mutations,
            "maximumSnapshotBytes": action.maximum_snapshot_bytes,
        }
    })
}

fn action_input_metadata(input: &CompiledActionInput) -> Value {
    json!({
        "id": input.id,
        "apiName": input.api_name,
        "fieldType": input.field_type,
        "required": input.required,
        "classification": input.classification,
    })
}

fn selected_profile_from_access_profiles(
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Option<&str> {
    match access_profiles {
        OpenApiAccessProfiles::All => None,
        OpenApiAccessProfiles::Selected(profile) => Some(profile),
    }
}

fn action_profile_ids(action: &CompiledAction) -> Vec<String> {
    action
        .grants
        .iter()
        .map(|grant| grant.profile_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn action_selected_result_effects(
    action: &CompiledAction,
    selected_profile: Option<&str>,
) -> BTreeSet<String> {
    match selected_profile {
        Some(profile) => action
            .grants
            .iter()
            .filter(|grant| grant.profile_id == profile)
            .flat_map(|grant| grant.results.iter().cloned())
            .collect(),
        None => action.result_effects.clone(),
    }
}

fn reference_input_metadata(input: &CompiledActionInput) -> Option<Value> {
    let FieldTypeSource::Reference { target, .. } = &input.field_type else {
        return None;
    };
    Some(json!({
        "input": input.id,
        "apiName": input.api_name,
        "targetEntity": target,
    }))
}

fn action_input_properties_schema<'a>(
    inputs: impl IntoIterator<Item = &'a CompiledActionInput>,
) -> Value {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let properties = inputs
        .iter()
        .map(|input| (input.api_name.clone(), field_schema(&input.field_type)))
        .collect::<Map<_, _>>();
    let required = inputs
        .iter()
        .filter(|input| input.required)
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn action_condition_input_properties_schema<'a>(
    inputs: impl IntoIterator<Item = &'a CompiledActionInput>,
) -> Value {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let properties = inputs
        .iter()
        .map(|input| (input.api_name.clone(), field_schema(&input.field_type)))
        .collect::<Map<_, _>>();
    let required = inputs
        .iter()
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn action_preconditions_schema<'a>(
    inputs: impl IntoIterator<Item = &'a CompiledActionInput>,
) -> Value {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let properties = inputs
        .iter()
        .map(|input| {
            (
                input.api_name.clone(),
                immediate_action_precondition_schema(),
            )
        })
        .collect::<Map<_, _>>();
    let required = inputs
        .iter()
        .map(|input| Value::String(input.api_name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn action_condition_inputs(action: &CompiledAction) -> Vec<&CompiledActionInput> {
    let condition_input_ids = action
        .target_uses
        .iter()
        .filter(|use_| use_.condition_required)
        .filter_map(|use_| match &use_.source {
            CompiledActionTargetUseSource::Input { input } => Some(input.as_str()),
            CompiledActionTargetUseSource::Effect { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    action
        .inputs
        .iter()
        .filter(|input| condition_input_ids.contains(input.id.as_str()))
        .collect()
}

fn immediate_action_precondition_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["ifMatch"],
        "properties": {
            "ifMatch": {"type": "string", "minLength": 3, "maxLength": 256, "pattern": "^\\\"[\\x21\\x23-\\x7E]+\\\"$"}
        }
    })
}

fn immediate_action_result_reference_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["entity", "recordId", "revision"],
        "properties": {
            "entity": {"type": "string"},
            "recordId": {"type": "string", "format": "uuid"},
            "revision": {"type": "integer", "format": "int64", "minimum": 1}
        }
    })
}

fn action_operation_security(
    action: &CompiledAction,
    route: &CompiledActionRoute,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Value {
    let profiles = match access_profiles {
        OpenApiAccessProfiles::All => route.access_profiles.clone(),
        OpenApiAccessProfiles::Selected(profile) => vec![profile.to_owned()],
    };
    let mut allows_anonymous = false;
    let mut requires_bearer = false;
    for profile in &profiles {
        let Some(grant) = action
            .grants
            .iter()
            .find(|grant| grant.profile_id == *profile)
        else {
            continue;
        };
        if grant.anonymous {
            allows_anonymous = true;
        } else {
            requires_bearer = true;
        }
    }
    let mut alternatives = Vec::new();
    if allows_anonymous {
        alternatives.push(json!({}));
    }
    if requires_bearer {
        alternatives.push(json!({"bearerAuth": []}));
    }
    if alternatives.is_empty() {
        alternatives.push(json!({"bearerAuth": []}));
    }
    Value::Array(alternatives)
}

fn action_operation_responses(route: &CompiledActionRoute, action: &CompiledAction) -> Value {
    let success = match route.kind {
        ActionRouteKind::Invoke => success_response(
            "Immediate action committed",
            StatusResponseHeaders::ActionMutation,
            json!({"$ref": format!("#/components/schemas/{}", openapi_action_response_schema_id(&action.id))}),
        ),
        ActionRouteKind::TargetConditions => success_response(
            "Action target conditions returned",
            StatusResponseHeaders::NoStore,
            json!({"$ref": format!(
                "#/components/schemas/{}",
                openapi_action_condition_response_schema_id(&action.id)
            )}),
        ),
    };
    let mut responses = Map::from_iter([("200".to_owned(), success)]);
    for (status, problems) in action_problem_responses(route.kind) {
        let examples = problems
            .iter()
            .map(|problem| {
                (
                    problem.code.to_owned(),
                    json!({"value": problem_example(status, problem.code, problem.detail)}),
                )
            })
            .collect::<Map<_, _>>();
        responses.insert(
            status.to_owned(),
            json!({
                "description": "Problem response",
                "headers": {
                    "traceparent": traceparent_header("Trace context for this problem response."),
                    "Cache-Control": no_store_header()
                },
                "content": {
                    "application/problem+json": {
                        "schema": {"$ref": "#/components/schemas/Problem"},
                        "examples": examples
                    }
                }
            }),
        );
    }
    Value::Object(responses)
}

fn action_problem_responses(kind: ActionRouteKind) -> BTreeMap<&'static str, Vec<ProblemExample>> {
    let mut responses = BTreeMap::from([
        (
            "400",
            vec![ProblemExample {
                code: "request.invalid",
                detail: "The request is invalid.",
            }],
        ),
        (
            "401",
            vec![ProblemExample {
                code: "authentication.refused",
                detail: "The bearer credential is missing or refused.",
            }],
        ),
        (
            "404",
            vec![ProblemExample {
                code: "resource.not_found",
                detail: "The requested resource was not found.",
            }],
        ),
        (
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        ),
        (
            "503",
            vec![ProblemExample {
                code: "service.unavailable",
                detail: "The Registry mutation service is unavailable.",
            }],
        ),
        (
            "504",
            vec![ProblemExample {
                code: "request.timeout",
                detail: "The request timed out.",
            }],
        ),
    ]);
    if kind == ActionRouteKind::Invoke {
        responses.insert(
            "409",
            vec![
                ProblemExample {
                    code: "mutation.conflict",
                    detail: "The mutation conflicts with current state.",
                },
                ProblemExample {
                    code: "idempotency.conflict",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "412",
            vec![ProblemExample {
                code: "precondition.failed",
                detail: "The mutation precondition failed.",
            }],
        );
    }
    responses
}

fn action_route_kind_name(kind: ActionRouteKind) -> &'static str {
    match kind {
        ActionRouteKind::Invoke => "invoke",
        ActionRouteKind::TargetConditions => "target_conditions",
    }
}

pub(crate) fn field_value_schema(field_type: &FieldTypeSource, nullable: bool) -> Value {
    let schema = field_schema(field_type);
    if nullable {
        json!({"anyOf": [schema, {"type": "null"}]})
    } else {
        schema
    }
}

pub(crate) fn field_schema(field_type: &FieldTypeSource) -> Value {
    match field_type {
        FieldTypeSource::Boolean => json!({"type": "boolean"}),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => json!({
            "type": "string",
            "minLength": min_length,
            "maxLength": max_length,
        }),
        FieldTypeSource::Text { max_length } => json!({
            "type": "string",
            "maxLength": max_length,
        }),
        FieldTypeSource::Int64 => json!({
            "type": "integer",
            "format": "int64",
        }),
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } => {
            let mut schema = json!({
                "type": "string",
                "pattern": decimal_pattern(*precision, *scale),
                "x-registry-decimalPrecision": precision,
                "x-registry-decimalScale": scale,
            });
            let object = schema.as_object_mut().expect("decimal schema is an object");
            if let Some(minimum) = minimum {
                object.insert(
                    "x-registry-decimalMinimum".to_owned(),
                    Value::String(minimum.clone()),
                );
            }
            if let Some(maximum) = maximum {
                object.insert(
                    "x-registry-decimalMaximum".to_owned(),
                    Value::String(maximum.clone()),
                );
            }
            schema
        }
        FieldTypeSource::Date => json!({"type": "string", "format": "date"}),
        FieldTypeSource::Timestamp => json!({"type": "string", "format": "date-time"}),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
            json!({"type": "string", "format": "uuid"})
        }
        FieldTypeSource::VocabularyCode { vocabulary, values } => json!({
            "type": "string",
            "enum": values,
            "x-registry-vocabulary": vocabulary,
        }),
        FieldTypeSource::Crs84Point { precision, bbox } => {
            let mut schema = json!({
                "type": "object",
                "description": "CRS84 GeoJSON Point with coordinates in [longitude, latitude] order.",
                "additionalProperties": false,
                "properties": {
                    "type": {"const": "Point"},
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
                },
                "required": ["type", "coordinates"],
                "x-registry-coordinateReferenceSystem": "CRS84",
                "x-registry-coordinatePrecision": precision,
            });
            if let Some(bbox) = bbox {
                schema
                    .as_object_mut()
                    .expect("point schema is an object")
                    .insert("x-registry-bbox".to_owned(), json!(bbox));
            }
            schema
        }
        FieldTypeSource::Structured { max_bytes, schema } => {
            let mut schema = schema.clone();
            schema
                .as_object_mut()
                .expect("validated structured schema is an object")
                .insert("x-registry-maxBytes".to_owned(), json!(max_bytes));
            schema
        }
    }
}

pub(crate) fn decimal_pattern(precision: u8, scale: u8) -> String {
    let integer_digits = precision - scale;
    let integer = if integer_digits == 0 {
        "0".to_owned()
    } else {
        format!("(0|[1-9][0-9]{{0,{}}})", integer_digits - 1)
    };
    if scale == 0 {
        format!("^-?{integer}$")
    } else {
        format!("^-?{integer}\\.[0-9]{{{scale}}}$")
    }
}

fn openapi_document(
    registry_id: &str,
    version: &str,
    entities: &BTreeMap<String, CompiledEntity>,
    routes: &CompiledRouteInventory,
    actions: &CompiledActionInventory,
    query: &CompiledQueryInventory,
    schemas: &BTreeMap<String, Value>,
) -> Value {
    let mut paths = Map::new();
    let mut input_schemas = Map::new();
    for route in &routes.routes {
        let entity = entities
            .get(&route.entity_id)
            .expect("compiled route refers to a compiled entity");
        let response_entity = response_entity_for_route(route, entities);
        let path_entry = paths
            .entry(route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(operations) = path_entry else {
            unreachable!("OpenAPI path entries are objects")
        };
        let request_schema_ref = openapi_input_schema_id(&entity.id, route.operation);
        if matches!(route.operation, Operation::Create | Operation::Batch) {
            let writable_fields = writable_fields_for_route(route, entity);
            input_schemas.insert(
                request_schema_ref.clone(),
                openapi_entity_input_schema(entity, Some(&writable_fields)),
            );
        } else if is_request_action(route.operation) {
            input_schemas.insert(
                request_schema_ref.clone(),
                openapi_request_action_input_schema(route.operation),
            );
        }
        operations.insert(
            method_name(route.method).to_owned(),
            openapi_operation(OpenApiOperationSpec {
                registry_identifier: registry_id,
                route,
                entity,
                response_entity,
                query,
                schema_ref: &response_entity.id,
                request_schema_ref: &request_schema_ref,
                readable_fields: None,
                access_profiles: OpenApiAccessProfiles::All,
            }),
        );
    }
    let mut has_immediate_actions = false;
    for action in &actions.actions {
        has_immediate_actions = true;
        input_schemas.insert(
            openapi_action_input_schema_id(&action.id),
            openapi_action_input_schema(action),
        );
        if action.condition_route.is_some() {
            input_schemas.insert(
                openapi_action_condition_request_schema_id(&action.id),
                openapi_action_condition_request_schema(action),
            );
            input_schemas.insert(
                openapi_action_condition_response_schema_id(&action.id),
                openapi_action_condition_response_schema(action),
            );
        }
        input_schemas.insert(
            openapi_action_response_schema_id(&action.id),
            openapi_action_response_schema(action, None),
        );
    }
    for route in &actions.routes {
        let action = actions
            .actions
            .iter()
            .find(|action| action.id == route.action_id)
            .expect("compiled action route refers to a compiled action");
        let path_entry = paths
            .entry(route.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(operations) = path_entry else {
            unreachable!("OpenAPI path entries are objects")
        };
        operations.insert(
            method_name(route.method).to_owned(),
            openapi_action_operation(route, action, OpenApiAccessProfiles::All),
        );
    }
    let mut component_schemas: Map<String, Value> = schemas
        .iter()
        .map(|(id, schema)| (id.clone(), schema.clone()))
        .collect();
    component_schemas.extend(input_schemas);
    let has_request_actions = routes
        .routes
        .iter()
        .any(|route| is_request_action(route.operation));
    json!({
        "openapi": "3.1.0",
        "info": {"title": registry_id, "version": version},
        "paths": paths,
        "components": openapi_components(component_schemas, has_request_actions, has_immediate_actions)
    })
}

#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "runtime"), allow(dead_code))]
pub(crate) enum OpenApiAccessProfiles<'a> {
    All,
    Selected(&'a str),
}

#[derive(Clone, Copy)]
pub(crate) struct OpenApiOperationSpec<'a> {
    pub registry_identifier: &'a str,
    pub route: &'a CompiledRoute,
    pub entity: &'a CompiledEntity,
    pub response_entity: &'a CompiledEntity,
    pub query: &'a CompiledQueryInventory,
    pub schema_ref: &'a str,
    pub request_schema_ref: &'a str,
    pub readable_fields: Option<&'a BTreeSet<String>>,
    pub access_profiles: OpenApiAccessProfiles<'a>,
}

const OPENAPI_EXAMPLE_TRACE_ID: &str = "11111111111111111111111111111111";
const OPENAPI_EXAMPLE_TRACEPARENT: &str = "00-11111111111111111111111111111111-2222222222222222-01";

pub(crate) fn openapi_components(
    mut schemas: Map<String, Value>,
    has_request_actions: bool,
    has_immediate_actions: bool,
) -> Value {
    schemas.insert("Problem".to_owned(), problem_schema());
    if has_request_actions {
        schemas.insert(
            "ChangeRequestActionResponse".to_owned(),
            request_action_response_schema(),
        );
    }
    if has_immediate_actions {
        schemas.insert(
            "ImmediateActionResultReference".to_owned(),
            immediate_action_result_reference_schema(),
        );
        schemas.insert(
            "ImmediateActionPrecondition".to_owned(),
            immediate_action_precondition_schema(),
        );
    }
    json!({
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        },
        "schemas": schemas
    })
}

pub(crate) fn openapi_operation(spec: OpenApiOperationSpec<'_>) -> Value {
    let geojson_profiles = geojson_profiles(spec);
    let mut operation = Map::from_iter([
        ("operationId".to_owned(), json!(spec.route.id)),
        ("x-registry-entity".to_owned(), json!(spec.route.entity_id)),
        (
            "x-registry-responseEntity".to_owned(),
            json!(spec.response_entity.id),
        ),
        (
            "x-registry-operation".to_owned(),
            json!(operation_name(spec.route.operation)),
        ),
        ("security".to_owned(), operation_security(spec)),
    ]);
    if geojson_profiles.is_empty() {
        operation.insert(
            "x-registry-responseShape".to_owned(),
            json!(operation_response_shape(spec)),
        );
    } else {
        operation.insert(
            "x-registry-responseShapes".to_owned(),
            json!({
                "application/json": operation_response_shape(spec),
                "application/ld+json": operation_response_shape(spec),
                "application/geo+json": geojson_operation_response_shape(spec),
            }),
        );
    }
    if is_registry_record_response(spec) {
        operation.insert(
            "x-registry-responseProfile".to_owned(),
            json!(PROFILE_IDENTIFIER),
        );
    }
    match spec.access_profiles {
        OpenApiAccessProfiles::All => {
            operation.insert(
                "x-registry-accessProfiles".to_owned(),
                json!(spec.route.access_profiles),
            );
        }
        OpenApiAccessProfiles::Selected(profile) => {
            operation.insert("x-registry-accessProfile".to_owned(), json!(profile));
        }
    }
    if let Some(kind) = spec.route.query_kind {
        operation.insert(
            "x-registry-queryKind".to_owned(),
            Value::String(query_kind_name(kind).to_owned()),
        );
    }
    if let Some(kind) = spec.route.revision_kind {
        operation.insert(
            "x-registry-revisionKind".to_owned(),
            Value::String(revision_kind_name(kind).to_owned()),
        );
        operation.insert(
            "x-registry-maximumRecords".to_owned(),
            json!(spec.route.maximum_records),
        );
    }
    if spec.route.operation == Operation::Batch {
        let batch = spec
            .entity
            .batch
            .as_ref()
            .expect("batch routes require compiled bounds");
        operation.insert(
            "x-registry-maximumItems".to_owned(),
            json!(batch.maximum_items),
        );
        operation.insert(
            "x-registry-maximumBytes".to_owned(),
            json!(batch.maximum_bytes),
        );
    }
    if is_request_action(spec.route.operation) {
        operation.insert(
            "x-registry-requestAction".to_owned(),
            render_request_action(spec),
        );
    }
    if let Some(query_profile) = query_profile_extension(spec) {
        operation.insert(query_profile.0, query_profile.1);
    }
    let mut parameters = operation_parameters(
        spec.route,
        spec.response_entity,
        spec.query,
        spec.access_profiles,
    );
    if !geojson_profiles.is_empty() {
        if let Some(select) = parameters
            .iter_mut()
            .find(|parameter| parameter["name"] == "$select")
        {
            select["examples"] = geojson_selection_examples(spec, &geojson_profiles);
        }
        operation.insert(
            "x-registry-geojsonProfiles".to_owned(),
            json!(geojson_profiles),
        );
    }
    if is_registry_record_response(spec) {
        let mut media_types = vec!["application/json", "application/ld+json"];
        if !geojson_profiles.is_empty() {
            media_types.push("application/geo+json");
        }
        parameters.push(header_parameter(
            "Accept",
            false,
            json!({"type": "string", "enum": media_types}),
            if geojson_profiles.is_empty() {
                "Choose the ordinary JSON or JSON-LD Registry Record representation."
            } else {
                "Choose ordinary JSON, JSON-LD, or GeoJSON. Selecting fields without the primary Point returns null geometry; include that Point in $select to display a map feature."
            },
        ));
    }
    if !parameters.is_empty() {
        operation.insert("parameters".to_owned(), Value::Array(parameters));
    }
    if let Some(request_body) = operation_request_body(spec) {
        operation.insert("requestBody".to_owned(), request_body);
    }
    operation.insert("responses".to_owned(), operation_responses(spec));
    Value::Object(operation)
}

fn is_registry_record_response(spec: OpenApiOperationSpec<'_>) -> bool {
    matches!(
        spec.route.operation,
        Operation::Create
            | Operation::Get
            | Operation::Lookup
            | Operation::List
            | Operation::Snapshot
            | Operation::Patch
            | Operation::Tombstone
            | Operation::Revisions
    )
}

fn operation_response_shape(spec: OpenApiOperationSpec<'_>) -> &'static str {
    match spec.route.operation {
        Operation::Create
        | Operation::Get
        | Operation::Lookup
        | Operation::Patch
        | Operation::Tombstone => "RegistryRecordSingleV1",
        Operation::List => "RegistryRecordCollectionV1",
        Operation::Snapshot => "BRegSnapshotCollectionV1",
        Operation::Revisions if spec.route.revision_kind == Some(CompiledRevisionKind::Detail) => {
            "BRegRevisionRecordV1"
        }
        Operation::Revisions => "BRegRevisionCollectionV1",
        Operation::Batch => "BRegAtomicBatchMutationResponseV1",
        Operation::Invoke => "BRegImmediateActionResponseV1",
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => "BRegChangeRequestActionResponseV1",
    }
}

fn geojson_operation_response_shape(spec: OpenApiOperationSpec<'_>) -> &'static str {
    match spec.route.operation {
        Operation::Get => "BRegGeoJsonFeatureV1",
        Operation::List => "BRegGeoJsonFeatureCollectionV1",
        _ => unreachable!("only record get and list routes expose GeoJSON"),
    }
}

fn render_request_action(spec: OpenApiOperationSpec<'_>) -> Value {
    json!({
        "operation": operation_name(spec.route.operation),
        "stage": spec.route.request_stage,
        "method": method_name(spec.route.method),
        "path": spec.route.path,
        "requestEntity": spec.route.entity_id,
        "requiredPreconditions": request_action_preconditions(spec.route.operation),
        "inputSchema": openapi_input_schema_id(&spec.entity.id, spec.route.operation),
        "responseSchema": "ChangeRequestActionResponse",
        "proposalBinding": {
            "versionField": "proposalVersion",
            "digestField": "effectDigest",
            "recordPrecondition": "If-Match",
            "idempotencyHeader": "Idempotency-Key",
        },
        "targetEntities": request_action_target_entities(spec),
    })
}

fn request_action_target_entities(spec: OpenApiOperationSpec<'_>) -> Vec<String> {
    let Some(request) = spec.entity.change_request.as_ref() else {
        return Vec::new();
    };
    match spec.access_profiles {
        OpenApiAccessProfiles::All => request.target_entities.iter().cloned().collect(),
        OpenApiAccessProfiles::Selected(profile) => {
            let mut targets = BTreeSet::new();
            match spec.route.operation {
                Operation::ApproveRequest
                | Operation::RejectRequest
                | Operation::RequestRevision => {
                    if let Some(stage) = spec.route.request_stage.as_deref() {
                        targets.extend(
                            request
                                .review_grants
                                .iter()
                                .filter(|grant| grant.profile_id == profile && grant.stage == stage)
                                .map(|grant| grant.target_entity_id.clone()),
                        );
                    }
                }
                Operation::ApplyRequest => {
                    targets.extend(
                        request
                            .apply_grants
                            .iter()
                            .filter(|grant| grant.profile_id == profile)
                            .map(|grant| grant.target_entity_id.clone()),
                    );
                }
                Operation::SubmitRequest
                | Operation::ReviseRequest
                | Operation::CancelRequest
                | Operation::Create
                | Operation::Get
                | Operation::List
                | Operation::Patch
                | Operation::Tombstone
                | Operation::Batch
                | Operation::Lookup
                | Operation::Revisions
                | Operation::Snapshot => {}
                Operation::Invoke => {}
            }
            targets.into_iter().collect()
        }
    }
}

fn request_action_preconditions(operation: Operation) -> Vec<&'static str> {
    let mut preconditions = vec!["Idempotency-Key", "If-Match"];
    if matches!(
        operation,
        Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ApplyRequest
    ) {
        preconditions.push("proposalVersion");
        preconditions.push("effectDigest");
    }
    preconditions
}

fn operation_security(spec: OpenApiOperationSpec<'_>) -> Value {
    let profiles = match spec.access_profiles {
        OpenApiAccessProfiles::All => spec.route.access_profiles.clone(),
        OpenApiAccessProfiles::Selected(profile) => vec![profile.to_owned()],
    };
    let mut allows_anonymous = false;
    let mut requires_bearer = false;
    for profile_id in profiles {
        let Some(profile) = spec.entity.access_profiles.get(&profile_id) else {
            continue;
        };
        if profile.anonymous {
            allows_anonymous = true;
        } else {
            requires_bearer = true;
        }
    }
    let mut alternatives = Vec::new();
    if allows_anonymous {
        alternatives.push(json!({}));
    }
    if requires_bearer {
        alternatives.push(json!({"bearerAuth": []}));
    }
    if alternatives.is_empty() {
        alternatives.push(json!({"bearerAuth": []}));
    }
    Value::Array(alternatives)
}

fn operation_parameters(
    route: &CompiledRoute,
    entity: &CompiledEntity,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Vec<Value> {
    let mut parameters = Vec::new();
    if route.path.contains("{record_id}") {
        parameters.push(path_parameter(
            "record_id",
            json!({"type": "string", "format": "uuid"}),
            "Canonical record UUID.",
        ));
    }
    if route.path.contains("{revision}") {
        parameters.push(path_parameter(
            "revision",
            json!({"type": "integer", "format": "int64", "minimum": 1}),
            "Exact positive record revision.",
        ));
    }
    parameters.push(header_parameter(
        "traceparent",
        false,
        traceparent_schema(),
        "Optional W3C trace context. Responses carry Registry trace context for the request.",
    ));
    parameters.push(access_profile_parameter());
    match route.operation {
        Operation::Get => {
            parameters.push(query_parameter(
                "$select",
                false,
                false,
                json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
                "Comma-separated subset of readable API property names.",
            ));
            if entity.change_request.is_some() && route.query_kind.is_none() {
                parameters.push(query_parameter(
                    "requestHistoryAfterProposalVersion",
                    false,
                    false,
                    json!({"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX}),
                    "Positive proposal-version cursor for the request history page returned with this request record.",
                ));
            }
        }
        Operation::List => {
            parameters.extend(read_query_parameters(route, query, access_profiles));
        }
        Operation::Snapshot => {
            parameters.extend(read_query_parameters(route, query, access_profiles));
            parameters.push(query_parameter(
                "snapshot",
                false,
                false,
                json!({"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES}),
                "Opaque Registry history snapshot reference. Omit to capture the latest committed position.",
            ));
            if let Some(schema) = snapshot_valid_at_schema(route, query, access_profiles) {
                parameters.push(query_parameter(
                    "validAt",
                    false,
                    false,
                    schema,
                    "Effective-validity value evaluated within the selected historical snapshot.",
                ));
            }
        }
        Operation::Lookup => parameters.push(query_parameter(
            "$select",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
            "Comma-separated subset of readable API property names.",
        )),
        Operation::Create | Operation::Patch | Operation::Tombstone | Operation::Batch => {
            parameters.push(header_parameter(
                "Idempotency-Key",
                true,
                json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"}),
                "Idempotency key bound to method, route, caller, target record, package revision, request body, and response field set.",
            ));
            if matches!(route.operation, Operation::Patch | Operation::Tombstone) {
                parameters.push(header_parameter(
                    "If-Match",
                    true,
                    json!({"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"}),
                    "Strong Registry ETag for the currently visible record representation.",
                ));
            }
        }
        Operation::Revisions => {}
        Operation::Invoke => {}
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => {
            parameters.push(header_parameter(
                "Idempotency-Key",
                true,
                json!({"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"}),
                "Idempotency key bound to method, route, caller, request record, package revision, action body, and response field set.",
            ));
            parameters.push(header_parameter(
                "If-Match",
                true,
                json!({"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"}),
                "Strong Registry ETag for the currently visible request record representation.",
            ));
        }
    }
    parameters
}

fn read_query_parameters(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Vec<Value> {
    let mut parameters = vec![
        query_parameter(
            "$select",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
            "Comma-separated subset of readable API property names.",
        ),
        query_parameter(
            "$filter",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_QUERY_PAYLOAD_BYTES}),
            "Strict Registry read filter expression over compiled filterable API properties.",
        ),
        query_parameter(
            "$orderby",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES}),
            "One compiled sortable property, ascending only.",
        ),
        query_parameter(
            "$top",
            false,
            false,
            json!({"type": "integer", "minimum": 1, "maximum": max_page_size(route, query, access_profiles)}),
            "Bounded page size.",
        ),
        query_parameter(
            "$count",
            false,
            false,
            json!({"type": "boolean"}),
            "Request count when the selected compiled query profile allows it.",
        ),
        query_parameter(
            "$skiptoken",
            false,
            false,
            json!({"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES}),
            "Opaque continuation cursor for the next page.",
        ),
    ];
    if route.query_kind == Some(CompiledQueryKind::AsOf) {
        parameters.push(query_parameter(
            "asOf",
            true,
            false,
            json!({"type": "string", "format": "date-time"}),
            "Strict UTC RFC3339 instant for the as-of temporal query.",
        ));
    }
    if query_profiles_for_route(route, query, access_profiles)
        .iter()
        .any(|profile| {
            profile
                .spatial
                .as_ref()
                .and_then(|spatial| spatial.bbox.as_ref())
                .is_some()
        })
    {
        parameters.push(query_parameter(
            "bbox",
            false,
            false,
            json!({"type": "string", "maxLength": 256, "example": "100.4,13.6,100.6,13.8"}),
            "Inclusive west,south,east,north CRS84 bounds within the selected profile's maximum spans. Finite decimal or exponent coordinates only; zero spans are valid. No crossing, 3D, alternate CRS or temporal queries. ANDed with $filter. Continuations carry only $skiptoken and routing/profile context.",
        ));
    }
    parameters
}

fn snapshot_valid_at_schema(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Option<Value> {
    let kind = query_profiles_for_route(route, query, access_profiles)
        .into_iter()
        .filter_map(|operation| {
            operation
                .temporal
                .as_ref()
                .map(|temporal| temporal.value_kind)
        })
        .max()?;
    Some(match kind {
        CompiledQueryTemporalValueKind::Date => json!({"type": "string", "format": "date"}),
        CompiledQueryTemporalValueKind::Timestamp => {
            json!({"type": "string", "format": "date-time"})
        }
    })
}

fn query_parameter(
    name: &str,
    required: bool,
    repeatable: bool,
    schema: Value,
    description: &str,
) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": required,
        "description": description,
        "schema": schema,
        "explode": repeatable,
    })
}

fn access_profile_parameter() -> Value {
    query_parameter(
        "accessProfile",
        false,
        false,
        json!({"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES}),
        "Select one compiled access profile. Omit to use the route default.",
    )
}

fn header_parameter(name: &str, required: bool, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "header",
        "required": required,
        "description": description,
        "schema": schema,
    })
}

fn path_parameter(name: &str, schema: Value, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": schema,
    })
}

fn operation_request_body(spec: OpenApiOperationSpec<'_>) -> Option<Value> {
    match spec.route.operation {
        Operation::Create => Some(json_request_body(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["data"],
            "properties": {
                "data": {"$ref": format!("#/components/schemas/{}", spec.request_schema_ref)}
            }
        }))),
        Operation::Patch => Some(json_patch_request_body()),
        Operation::Lookup => Some(json_request_body(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["selector"],
            "properties": {
                "selector": {"type": "string", "maxLength": crate::query::MAX_IDENTIFIER_BYTES},
                "values": {
                    "type": "object",
                    "maxProperties": 16,
                    "additionalProperties": {
                        "oneOf": [
                            {"type": "string", "maxLength": crate::query::MAX_LITERAL_BYTES},
                            {"type": "integer", "format": "int64"},
                            {"type": "boolean"}
                        ]
                    }
                }
            }
        }))),
        Operation::Batch => {
            let batch = spec
                .entity
                .batch
                .as_ref()
                .expect("batch routes require compiled bounds");
            let (allow_create, allow_patch) = batch_permissions(spec);
            Some(batch_request_body(
                spec.request_schema_ref,
                batch.maximum_items,
                allow_create,
                allow_patch,
            ))
        }
        Operation::Get
        | Operation::List
        | Operation::Tombstone
        | Operation::Revisions
        | Operation::Snapshot => None,
        Operation::Invoke => None,
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => Some(json_request_body(json!({
            "$ref": format!("#/components/schemas/{}", spec.request_schema_ref)
        }))),
    }
}

fn json_request_body(schema: Value) -> Value {
    json!({
        "required": true,
        "content": {"application/json": {"schema": schema}}
    })
}

fn json_patch_request_body() -> Value {
    json!({
        "required": true,
        "content": {"application/json-patch+json": {"schema": json_patch_array_schema()}}
    })
}

fn batch_request_body(
    schema_ref: &str,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    let mut item_schemas = Vec::new();
    if allow_create {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "data"],
            "properties": {
                "operation": {"const": "create"},
                "data": {"$ref": format!("#/components/schemas/{schema_ref}")},
            }
        }));
    }
    if allow_patch {
        item_schemas.push(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "recordId", "ifMatch", "patch"],
            "properties": {
                "operation": {"const": "patch"},
                "recordId": {"type": "string", "format": "uuid"},
                "ifMatch": {"type": "string", "minLength": 6, "maxLength": 256, "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"},
                "patch": json_patch_array_schema(),
            }
        }));
    }
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["items"],
                    "properties": {
                        "changeContext": change_context_request_schema(),
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": maximum_items,
                            "items": {"oneOf": item_schemas}
                        }
                    }
                }
            }
        }
    })
}

fn change_context_request_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "x-registry-maxCanonicalBytes": 16 * 1024,
        "properties": {
            "kind": {"type": "string", "enum": ["change", "correction"]},
            "reasonCode": bounded_nonempty_text_schema(64),
            "reasonText": bounded_text_schema(4 * 1024),
            "sourceReferences": {
                "type": "array",
                "maxItems": 16,
                "items": bounded_text_schema(256)
            }
        },
        "allOf": [{
            "if": {
                "required": ["kind"],
                "properties": {"kind": {"const": "correction"}}
            },
            "then": {"required": ["reasonCode"]}
        }]
    })
}

fn bounded_nonempty_text_schema(max_bytes: usize) -> Value {
    let mut schema = bounded_text_schema(max_bytes);
    schema
        .as_object_mut()
        .expect("bounded text schema is an object")
        .insert("minLength".to_owned(), json!(1));
    schema
}

fn bounded_text_schema(max_bytes: usize) -> Value {
    json!({
        "type": "string",
        "maxLength": max_bytes,
        "x-registry-maxBytes": max_bytes
    })
}

pub(crate) fn json_patch_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 128,
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["op", "path"],
            "properties": {
                "op": {"type": "string", "enum": ["add", "replace", "remove", "test"]},
                "path": {"type": "string"},
                "value": true
            },
            "if": {"properties": {"op": {"const": "remove"}}},
            "then": {"not": {"required": ["value"]}},
            "else": {"required": ["value"]}
        }
    })
}

fn operation_responses(spec: OpenApiOperationSpec<'_>) -> Value {
    let mut success = match spec.route.operation {
        Operation::Create => registry_record_success_response(
            spec,
            "Record created",
            StatusResponseHeaders::MutationCreate,
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), false),
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), true),
        ),
        Operation::Get => registry_record_success_response(
            spec,
            "Record returned",
            StatusResponseHeaders::ReadDetail,
            single_response_schema(spec, record_member_schema(spec), false),
            single_response_schema(spec, record_member_schema(spec), true),
        ),
        Operation::Lookup => registry_record_success_response(
            spec,
            "Lookup resolved to one record",
            StatusResponseHeaders::NoStore,
            single_response_schema(spec, record_member_schema(spec), false),
            single_response_schema(spec, record_member_schema(spec), true),
        ),
        Operation::List => registry_record_success_response(
            spec,
            "Records returned",
            StatusResponseHeaders::NoStore,
            list_response_schema(spec, false),
            list_response_schema(spec, true),
        ),
        Operation::Snapshot => registry_record_success_response(
            spec,
            "Historical records returned",
            StatusResponseHeaders::NoStore,
            snapshot_response_schema(spec, false),
            snapshot_response_schema(spec, true),
        ),
        Operation::Patch => registry_record_success_response(
            spec,
            "Record patched",
            StatusResponseHeaders::Mutation,
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), false),
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), true),
        ),
        Operation::Tombstone => registry_record_success_response(
            spec,
            "Record tombstoned",
            StatusResponseHeaders::Mutation,
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), false),
            single_response_schema(spec, mutation_record_member_schema(spec.schema_ref), true),
        ),
        Operation::Batch => {
            let batch = spec
                .entity
                .batch
                .as_ref()
                .expect("batch routes require compiled bounds");
            let (allow_create, allow_patch) = batch_permissions(spec);
            success_response(
                "Atomic batch committed",
                StatusResponseHeaders::Mutation,
                batch_response_schema(
                    spec.schema_ref,
                    batch.maximum_items,
                    allow_create,
                    allow_patch,
                ),
            )
        }
        Operation::Revisions => registry_record_success_response(
            spec,
            "Record revisions returned",
            StatusResponseHeaders::NoStore,
            revision_response_schema(spec, false),
            revision_response_schema(spec, true),
        ),
        Operation::Invoke => success_response(
            "Action accepted",
            StatusResponseHeaders::ActionMutation,
            json!({"type": "object"}),
        ),
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => success_response(
            "Request action accepted",
            StatusResponseHeaders::ActionMutation,
            json!({"$ref": "#/components/schemas/ChangeRequestActionResponse"}),
        ),
    };
    if let Some(schema) = geojson_response_schema(spec) {
        success["content"]["application/geo+json"] = json!({"schema": schema});
        success["headers"]["Vary"] = json!({
            "description": "Responses vary by authorization and negotiated representation.",
            "schema": {"type": "string"}
        });
        if spec.route.operation == Operation::Get {
            success["headers"]["ETag"]["description"] = json!(
                "Strong Registry mutation precondition for JSON and JSON-LD only. GeoJSON does not return this validator."
            );
            success["headers"]["Cache-Control"] = json!({
                "description": "Protected GeoJSON responses are not stored.",
                "schema": {"type": "string"}
            });
        }
    }
    let success_status = if spec.route.operation == Operation::Create {
        "201"
    } else {
        "200"
    };
    let mut responses = Map::from_iter([(success_status.to_owned(), success)]);
    for (status, problems) in problem_responses(spec.route.operation) {
        let examples = problems
            .iter()
            .map(|problem| {
                (
                    problem.code.to_owned(),
                    json!({"value": problem_example(status, problem.code, problem.detail)}),
                )
            })
            .collect::<Map<_, _>>();
        responses.insert(
            status.to_owned(),
            json!({
                "description": "Problem response",
                "headers": {
                    "traceparent": traceparent_header("Trace context for this problem response."),
                    "Cache-Control": no_store_header()
                },
                "content": {
                    "application/problem+json": {
                        "schema": {"$ref": "#/components/schemas/Problem"},
                        "examples": examples
                    }
                }
            }),
        );
    }
    Value::Object(responses)
}

#[derive(Clone, Copy)]
enum StatusResponseHeaders {
    ReadDetail,
    NoStore,
    Mutation,
    MutationCreate,
    ActionMutation,
}

fn success_response(description: &str, headers: StatusResponseHeaders, schema: Value) -> Value {
    let mut response = Map::from_iter([
        ("description".to_owned(), json!(description)),
        (
            "content".to_owned(),
            json!({"application/json": {"schema": schema}}),
        ),
    ]);
    let mut header_map = match headers {
        StatusResponseHeaders::ReadDetail => json!({
            "ETag": etag_header(),
        }),
        StatusResponseHeaders::NoStore => json!({
            "Cache-Control": no_store_header(),
        }),
        StatusResponseHeaders::Mutation => json!({
            "ETag": etag_header(),
        }),
        StatusResponseHeaders::MutationCreate => json!({
            "ETag": etag_header(),
            "Location": {"description": "Relative URL of the created record.", "schema": {"type": "string"}},
        }),
        StatusResponseHeaders::ActionMutation => json!({}),
    };
    header_map
        .as_object_mut()
        .expect("response headers are objects")
        .insert(
            "traceparent".to_owned(),
            traceparent_header("Trace context for this response."),
        );
    header_map
        .as_object_mut()
        .expect("response headers are objects")
        .insert("Cache-Control".to_owned(), no_store_header());
    response.insert("headers".to_owned(), header_map);
    Value::Object(response)
}

fn registry_record_success_response(
    spec: OpenApiOperationSpec<'_>,
    description: &str,
    headers: StatusResponseHeaders,
    json_schema: Value,
    json_ld_schema: Value,
) -> Value {
    let mut response = success_response(description, headers, json_schema);
    response["content"]["application/ld+json"] = json!({"schema": json_ld_schema});
    response["headers"]["Link"] = json!({
        "description": "Emitted only for application/json and application/ld+json Registry Record responses and omitted for application/geo+json. Carries the Registry Record profile and caller-visible entity schema. The describedby target includes the configured deployment prefix and is never derived from Host or forwarded headers.",
        "schema": {
            "type": "string",
            "example": link_header_value(spec.response_entity, "")
                .expect("compiled entity identifiers are safe response-header components")
        }
    });
    response["headers"]["Vary"] = json!({
        "description": "Responses vary by authorization and negotiated representation.",
        "schema": {"type": "string"}
    });
    response
}

fn no_store_header() -> Value {
    json!({"description": "Caller-dependent responses must not be stored.", "schema": {"const": "no-store"}})
}

fn etag_header() -> Value {
    json!({
        "description": "Strong Registry ETag bound to the record, package revision, caller profile, and response field set.",
        "schema": {"type": "string", "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"}
    })
}

fn traceparent_header(description: &str) -> Value {
    json!({
        "description": description,
        "schema": traceparent_schema(),
        "example": OPENAPI_EXAMPLE_TRACEPARENT,
    })
}

fn traceparent_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 55,
        "maxLength": 55,
        "pattern": "^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
    })
}

fn record_member_schema(spec: OpenApiOperationSpec<'_>) -> Value {
    let entity = spec.response_entity;
    let schema_ref = spec.schema_ref;
    let mut properties = Map::from_iter([
        (
            "recordIdentifier".to_owned(),
            json!({"type": "string", "format": "uuid"}),
        ),
        (
            "revisionIdentifier".to_owned(),
            json!({"type": "string", "pattern": "^[1-9][0-9]*$"}),
        ),
        ("domainData".to_owned(), json!({"type": "object"})),
    ]);
    if entity.change_request.is_some() {
        properties.insert("request".to_owned(), request_record_metadata_schema());
    }
    if entity
        .access_profiles
        .values()
        .any(|profile| !profile.request_presence.is_empty())
    {
        properties.insert(
            "requestPresence".to_owned(),
            request_presence_metadata_schema(),
        );
    }
    let mut schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordIdentifier", "revisionIdentifier", "domainData"],
        "properties": properties,
        "allOf": [{
            "if": {
                "required": ["request"],
                "properties": {
                    "request": {
                        "type": "object",
                        "required": ["detailErased"],
                        "properties": {
                            "detailErased": {"const": true}
                        }
                    }
                }
            },
            "then": {
                "properties": {
                    "domainData": {
                        "type": "object",
                        "additionalProperties": false,
                        "maxProperties": 0
                    }
                }
            },
            "else": {
                "properties": {
                    "domainData": {"$ref": format!("#/components/schemas/{schema_ref}")}
                }
            }
        }]
    });
    if entity.change_request.is_none() {
        schema
            .as_object_mut()
            .expect("record schema is object")
            .remove("allOf");
        schema["properties"]["domainData"] =
            json!({"$ref": format!("#/components/schemas/{schema_ref}")});
    }
    schema
}

fn mutation_record_member_schema(schema_ref: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordIdentifier", "revisionIdentifier", "domainData", "snapshot"],
        "properties": {
            "recordIdentifier": {"type": "string", "format": "uuid"},
            "revisionIdentifier": {"type": "string", "pattern": "^[1-9][0-9]*$"},
            "snapshot": snapshot_reference_schema(),
            "domainData": {"$ref": format!("#/components/schemas/{schema_ref}")},
        }
    })
}

fn snapshot_reference_schema() -> Value {
    json!({"type": "string", "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES})
}

fn response_meta_schema(spec: OpenApiOperationSpec<'_>) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["registryIdentifier", "datasetIdentifier", "entityTypeIdentifier"],
        "properties": {
            "registryIdentifier": {"const": spec.registry_identifier},
            "datasetIdentifier": {
                "const": spec.response_entity.primary_dataset.as_deref()
                    .expect("served entities have a compiled primary dataset")
            },
            "entityTypeIdentifier": {"const": spec.response_entity.id}
        }
    })
}

fn single_response_schema(
    spec: OpenApiOperationSpec<'_>,
    member_schema: Value,
    json_ld: bool,
) -> Value {
    let mut required = vec!["data", "meta"];
    let mut properties = Map::from_iter([
        ("data".to_owned(), member_schema),
        ("meta".to_owned(), response_meta_schema(spec)),
    ]);
    if json_ld {
        required.push("@context");
        properties.insert("@context".to_owned(), json!({"const": CONTEXT_IDENTIFIER}));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn collection_response_schema(
    spec: OpenApiOperationSpec<'_>,
    member_schema: Value,
    mut extensions: Map<String, Value>,
    required_extensions: &[&'static str],
    json_ld: bool,
) -> Value {
    let mut required = vec!["items", "pageInfo", "meta"];
    required.extend_from_slice(required_extensions);
    let mut properties = Map::from_iter([
        (
            "items".to_owned(),
            json!({"type": "array", "items": member_schema}),
        ),
        (
            "pageInfo".to_owned(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["nextCursor"],
                "properties": {
                    "nextCursor": {"type": ["string", "null"], "maxLength": crate::query::MAX_OPAQUE_VALUE_BYTES}
                }
            }),
        ),
        ("meta".to_owned(), response_meta_schema(spec)),
    ]);
    properties.append(&mut extensions);
    if json_ld {
        required.push("@context");
        properties.insert("@context".to_owned(), json!({"const": CONTEXT_IDENTIFIER}));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn list_response_schema(spec: OpenApiOperationSpec<'_>, json_ld: bool) -> Value {
    collection_response_schema(
        spec,
        record_member_schema(spec),
        Map::from_iter([(
            "count".to_owned(),
            json!({"type": "integer", "format": "int64", "minimum": 0}),
        )]),
        &[],
        json_ld,
    )
}

fn request_record_metadata_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["bregState", "proposalVersion", "editable"],
        "properties": {
            "bregState": request_state_schema(),
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": nullable_effect_digest_schema(),
            "proposal": request_proposal_schema(),
            "editable": {"type": "boolean"},
            "detailErased": {"const": true},
            "actions": {
                "type": "array",
                "maxItems": 64,
                "items": request_action_link_schema(),
            },
            "application": request_application_metadata_schema(false),
            "history": retained_request_history_schema(),
        }
    })
}

fn request_action_link_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["operation", "method", "href", "ifMatch"],
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["submit_request", "approve_request", "reject_request", "request_revision", "revise_request", "cancel_request", "apply_request"]
            },
            "method": {"const": "POST"},
            "href": {"type": "string", "maxLength": 2048},
            "ifMatch": {"type": "string", "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"},
            "stage": {"type": "string", "minLength": 1},
            "rebase": {"type": "boolean"},
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": effect_digest_schema(),
            "review": {
                "type": "object",
                "additionalProperties": false,
                "required": ["targets"],
                "properties": {
                    "targets": {
                        "type": "array",
                        "maxItems": 16,
                        "items": request_review_target_schema(),
                    }
                }
            }
        }
    })
}

fn request_review_target_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["entityId", "recordId", "operation", "baseRevision", "before", "after"],
        "properties": {
            "entityId": {"type": "string"},
            "recordId": {"type": "string", "format": "uuid"},
            "operation": {"type": "string", "enum": ["create", "patch"]},
            "baseRevision": {"type": ["integer", "null"], "format": "int64", "minimum": 1},
            "before": {
                "type": ["object", "null"],
                "maxProperties": 128,
                "additionalProperties": true,
            },
            "after": {
                "type": "object",
                "maxProperties": 128,
                "additionalProperties": true,
            }
        }
    })
}

fn request_application_metadata_schema(require_receipt_fields: bool) -> Value {
    let required = if require_receipt_fields {
        json!([
            "applicationId",
            "proposalVersion",
            "effectDigest",
            "appliedAt"
        ])
    } else {
        json!(["applicationId", "proposalVersion"])
    };
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": required,
        "properties": {
            "applicationId": {"type": "string", "format": "uuid"},
            "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
            "effectDigest": effect_digest_schema(),
            "appliedAt": {"type": "string", "format": "date-time"}
        }
    })
}

fn retained_request_history_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["proposals", "nextAfterProposalVersion"],
        "properties": {
            "proposals": {
                "type": "array",
                "maxItems": 50,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "requestEntityId",
                        "requestId",
                        "proposalVersion",
                        "bregState",
                        "current",
                        "contractFingerprint",
                        "detailErased",
                        "applicationId",
                        "resultLinkCount",
                        "resultLinks"
                    ],
                    "properties": {
                        "requestEntityId": {"type": "string"},
                        "requestId": {"type": "string", "format": "uuid"},
                        "proposalVersion": {"type": "integer", "format": "int64", "minimum": 1, "maximum": u32::MAX},
                        "bregState": request_state_schema(),
                        "current": {"type": "boolean"},
                        "contractFingerprint": {"type": "string"},
                        "detailErased": {"type": "boolean"},
                        "applicationId": {"type": ["string", "null"], "format": "uuid"},
                        "resultLinkCount": {"type": "integer", "minimum": 0, "maximum": 16},
                        "resultLinks": {
                            "type": "array",
                            "maxItems": 16,
                            "items": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["targetEntityId", "targetRecordId", "targetRevision"],
                                "properties": {
                                    "targetEntityId": {"type": "string"},
                                    "targetRecordId": {"type": "string", "format": "uuid"},
                                    "targetRevision": {"type": "integer", "format": "int64", "minimum": 1}
                                }
                            }
                        },
                        "effectDigest": effect_digest_schema()
                    }
                }
            },
            "nextAfterProposalVersion": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": u32::MAX}
        }
    })
}

fn request_presence_metadata_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["requests"],
        "properties": {
            "requests": {
                "type": "array",
                "maxItems": 64,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["requestType", "pending"],
                    "properties": {
                        "requestType": {"type": "string"},
                        "pending": {"type": "boolean"}
                    }
                }
            }
        }
    })
}

fn request_state_schema() -> Value {
    json!({"type": "string", "enum": ["draft", "submitted", "approved", "needs_changes", "rejected", "canceled", "applied"]})
}

fn effect_digest_schema() -> Value {
    json!({"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"})
}

fn nullable_effect_digest_schema() -> Value {
    json!({"type": ["string", "null"], "pattern": "^sha256:[0-9a-f]{64}$"})
}

fn snapshot_response_schema(spec: OpenApiOperationSpec<'_>, json_ld: bool) -> Value {
    let mut extensions = Map::from_iter([
        ("snapshot".to_owned(), snapshot_reference_schema()),
        (
            "count".to_owned(),
            json!({"type": "integer", "format": "int64", "minimum": 0}),
        ),
    ]);
    if let Some(valid_at) = snapshot_valid_at_schema(spec.route, spec.query, spec.access_profiles) {
        extensions.insert("validAt".to_owned(), valid_at);
    }
    collection_response_schema(
        spec,
        record_member_schema(spec),
        extensions,
        &["snapshot"],
        json_ld,
    )
}

fn geojson_profiles<'a>(spec: OpenApiOperationSpec<'a>) -> Vec<&'a str> {
    let Some(binding) = &spec.response_entity.geojson else {
        return Vec::new();
    };
    if spec.route.revision_kind.is_some()
        || spec.entity.id != spec.response_entity.id
        || read_path_for_route(spec.route, spec.entity).is_some()
        || !matches!(
            (spec.route.operation, spec.route.query_kind),
            (Operation::Get, None) | (Operation::List, Some(CompiledQueryKind::List))
        )
    {
        return Vec::new();
    }
    spec.route
        .access_profiles
        .iter()
        .filter(|profile_id| match spec.access_profiles {
            OpenApiAccessProfiles::All => true,
            OpenApiAccessProfiles::Selected(selected) => profile_id.as_str() == selected,
        })
        .filter(|profile_id| {
            spec.entity
                .access_profiles
                .get(profile_id.as_str())
                .is_some_and(|profile| profile.readable_fields.contains(&binding.geometry_field))
        })
        .map(String::as_str)
        .collect()
}

fn geojson_response_schema(spec: OpenApiOperationSpec<'_>) -> Option<Value> {
    let profiles = geojson_profiles(spec);
    if profiles.is_empty() {
        return None;
    }
    let entity = spec.response_entity;
    let binding = entity.geojson.as_ref()?;
    let geometry = entity.fields.get(&binding.geometry_field)?;
    let fields: BTreeSet<_> = profiles
        .iter()
        .flat_map(|profile| selectable_fields_for_profile(spec, profile))
        .collect();
    let mut properties = Map::new();
    for field in &entity.stored_fields {
        if fields.contains(&field.logical.id) && field.logical.id != binding.geometry_field {
            let schema = field_schema(&field.logical.field_type);
            properties.insert(
                field.logical.api_name.clone(),
                if field.required {
                    schema
                } else {
                    json!({"anyOf": [schema, {"type": "null"}]})
                },
            );
        }
    }
    for field in entity.derived_fields.values() {
        if fields.contains(&field.logical.id) {
            properties.insert(
                field.logical.api_name.clone(),
                json!({
                    "anyOf": [field_schema(&field.logical.field_type), {"type": "null"}]
                }),
            );
        }
    }
    let feature = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "id", "geometry", "properties", "registry"],
        "properties": {
            "type": {"const": "Feature"},
            "id": {"type": "string", "format": "uuid"},
            "geometry": {"anyOf": [field_schema(&geometry.field_type), {"type": "null"}]},
            "properties": {"type": "object", "additionalProperties": false, "properties": properties},
            "registry": {
                "type": "object",
                "additionalProperties": false,
                "required": ["revision"],
                "properties": {"revision": {"type": "integer", "format": "int64", "minimum": 1}}
            }
        },
        "description": "Selected logical fields use their API names. The primary Point appears only as geometry. Omitting it from $select returns null geometry. Registry record metadata is in the registry foreign member."
    });
    if spec.route.operation == Operation::Get {
        return Some(feature);
    }
    let collection = list_response_schema(spec, false);
    Some(json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "features", "registry"],
        "properties": {
            "type": {"const": "FeatureCollection"},
            "features": {"type": "array", "items": feature},
            "registry": {
                "type": "object",
                "additionalProperties": false,
                "required": ["pageInfo"],
                "properties": {
                    "pageInfo": collection["properties"]["pageInfo"],
                    "count": collection["properties"]["count"]
                }
            }
        },
        "description": "Live authorized collection. Follow registry.pageInfo.nextCursor with the same representation and authority. A refresh starts a fresh traversal; concurrent edits can change membership. Count is present only when requested and permitted."
    }))
}

fn geojson_selection_examples(spec: OpenApiOperationSpec<'_>, profiles: &[&str]) -> Value {
    let binding = spec
        .response_entity
        .geojson
        .as_ref()
        .expect("GeoJSON profiles have a binding");
    let geometry = api_field_name(spec.response_entity, &binding.geometry_field)
        .expect("compiled GeoJSON binding has an API field");
    let attributes: BTreeSet<_> = profiles
        .iter()
        .flat_map(|profile| selectable_fields_for_profile(spec, profile))
        .filter(|field| field != &binding.geometry_field)
        .filter_map(|field| api_field_name(spec.response_entity, &field).map(str::to_owned))
        .collect();
    let attributes: Vec<_> = attributes.into_iter().take(2).collect();
    let mut with_geometry = attributes.clone();
    with_geometry.push(geometry.to_owned());
    let mut examples = Map::from_iter([(
        "withGeometry".to_owned(),
        json!({
            "summary": "Include the Point to render a map feature",
            "value": with_geometry.join(",")
        }),
    )]);
    if !attributes.is_empty() {
        examples.insert(
            "withoutGeometry".to_owned(),
            json!({
                "summary": "Select attributes only; GeoJSON geometry is null",
                "value": attributes.join(",")
            }),
        );
    }
    Value::Object(examples)
}

fn batch_response_schema(
    schema_ref: &str,
    maximum_items: u16,
    allow_create: bool,
    allow_patch: bool,
) -> Value {
    let operations = [
        allow_create.then_some("create"),
        allow_patch.then_some("patch"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["snapshot", "results"],
        "properties": {
            "snapshot": snapshot_reference_schema(),
            "results": {
                "type": "array",
                "minItems": 1,
                "maxItems": maximum_items,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["operation", "id", "revision", "etag", "data"],
                    "properties": {
                        "operation": {"enum": operations},
                        "id": {"type": "string", "format": "uuid"},
                        "revision": {"type": "integer", "format": "int64", "minimum": 1},
                        "etag": {"type": "string", "pattern": "^\\\"breg-[\\x21\\x23-\\x7E]+\\\"$"},
                        "data": {"$ref": format!("#/components/schemas/{schema_ref}")},
                    }
                }
            }
        }
    })
}

fn revision_response_schema(spec: OpenApiOperationSpec<'_>, json_ld: bool) -> Value {
    let mut properties = Map::from_iter([
        (
            "recordIdentifier".to_owned(),
            json!({"type": "string", "format": "uuid"}),
        ),
        (
            "revisionIdentifier".to_owned(),
            json!({"type": "string", "pattern": "^[1-9][0-9]*$"}),
        ),
        (
            "predecessorRevision".to_owned(),
            json!({"type": ["integer", "null"], "format": "int64", "minimum": 1}),
        ),
        (
            "lifecycle".to_owned(),
            json!({"type": "string", "enum": ["active", "tombstoned"]}),
        ),
        (
            "mutationKind".to_owned(),
            json!({"type": "string", "enum": ["create", "patch", "tombstone", "migration"]}),
        ),
        ("packageRevision".to_owned(), json!({"type": "string"})),
        ("operationIdentifier".to_owned(), json!({"type": "string"})),
        ("actorReference".to_owned(), json!({"type": "string"})),
        ("requestReference".to_owned(), json!({"type": "string"})),
        (
            "createdAt".to_owned(),
            json!({"type": "string", "format": "date-time"}),
        ),
        (
            "domainData".to_owned(),
            json!({"$ref": format!("#/components/schemas/{}", spec.schema_ref)}),
        ),
    ]);
    if let Some(change_context) = revision_change_context_schema(spec) {
        properties.insert("changeContext".to_owned(), change_context);
    }
    let item = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "recordIdentifier",
            "revisionIdentifier",
            "predecessorRevision",
            "lifecycle",
            "packageRevision",
            "operationIdentifier",
            "mutationKind",
            "actorReference",
            "requestReference",
            "createdAt",
            "domainData"
        ],
        "properties": properties
    });
    if spec.route.revision_kind == Some(CompiledRevisionKind::Detail) {
        single_response_schema(spec, item, json_ld)
    } else {
        let mut collection = collection_response_schema(spec, item, Map::new(), &[], json_ld);
        collection["properties"]["items"]["maxItems"] =
            json!(crate::model::MAX_REVISION_HISTORY_RECORDS);
        collection
    }
}

fn request_action_response_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "revision", "snapshot", "request"],
        "properties": {
            "id": {"type": "string", "format": "uuid"},
            "revision": {"type": "integer", "format": "int64", "minimum": 1},
            "snapshot": snapshot_reference_schema(),
            "request": {
                "type": "object",
                "additionalProperties": false,
                "required": ["bregState", "proposalVersion", "effectDigest", "application"],
                "properties": {
                    "bregState": request_state_schema(),
                    "proposalVersion": {"type": ["integer", "null"], "format": "int64", "minimum": 1, "maximum": u32::MAX},
                    "effectDigest": nullable_effect_digest_schema(),
                    "proposal": request_proposal_schema(),
                    "application": request_application_metadata_schema(true)
                }
            }
        }
    })
}

fn request_proposal_schema() -> Value {
    json!({
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["reviewMode", "applicationDisposition"],
                "properties": {
                    "reviewMode": {"type": "string", "enum": ["none", "staged"]},
                    "applicationDisposition": {"const": "apply"}
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["reviewMode", "applicationDisposition"],
                "properties": {
                    "reviewMode": {"type": "string", "enum": ["none", "staged"]},
                    "applicationDisposition": {"const": "queue"},
                    "queueReason": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["code", "label"],
                        "properties": {
                            "code": {"type": "string", "maxLength": 128},
                            "label": {"type": "string", "minLength": 1, "maxLength": 160}
                        }
                    }
                }
            },
            {"type": "null"}
        ]
    })
}

fn revision_change_context_schema(spec: OpenApiOperationSpec<'_>) -> Option<Value> {
    let mut fields = Vec::new();
    match spec.access_profiles {
        OpenApiAccessProfiles::All => {
            for profile_id in &spec.route.access_profiles {
                let Some(profile) = spec.entity.access_profiles.get(profile_id) else {
                    continue;
                };
                for field in &profile.provenance_fields {
                    if !fields.contains(field) {
                        fields.push(*field);
                    }
                }
            }
        }
        OpenApiAccessProfiles::Selected(profile_id) => {
            let profile = spec.entity.access_profiles.get(profile_id)?;
            fields.extend(profile.provenance_fields.iter().copied());
        }
    }
    change_context_response_schema(&fields)
}

fn change_context_response_schema(fields: &[ProvenanceFieldSource]) -> Option<Value> {
    if fields.is_empty() {
        return None;
    }
    let mut properties = Map::new();
    for field in fields {
        match field {
            ProvenanceFieldSource::Kind => {
                properties.insert(
                    "kind".to_owned(),
                    json!({"type": "string", "enum": ["change", "correction"]}),
                );
            }
            ProvenanceFieldSource::ReasonCode => {
                properties.insert("reasonCode".to_owned(), bounded_nonempty_text_schema(64));
            }
            ProvenanceFieldSource::ReasonText => {
                properties.insert("reasonText".to_owned(), bounded_text_schema(4 * 1024));
            }
            ProvenanceFieldSource::SourceReferences => {
                properties.insert(
                    "sourceReferences".to_owned(),
                    json!({
                        "type": "array",
                        "maxItems": 16,
                        "items": bounded_text_schema(256)
                    }),
                );
            }
        }
    }
    Some(Value::Object(Map::from_iter([
        ("type".to_owned(), json!("object")),
        ("additionalProperties".to_owned(), json!(false)),
        ("properties".to_owned(), Value::Object(properties)),
    ])))
}

#[cfg(test)]
#[path = "tests/artifacts_response_schema_tests.rs"]
mod artifacts_response_schema_tests;

#[derive(Clone, Copy)]
struct ProblemExample {
    code: &'static str,
    detail: &'static str,
}

fn problem_responses(operation: Operation) -> BTreeMap<&'static str, Vec<ProblemExample>> {
    let mut responses = BTreeMap::from([
        (
            "400",
            vec![ProblemExample {
                code: "request.invalid",
                detail: "The request is invalid.",
            }],
        ),
        (
            "401",
            vec![ProblemExample {
                code: "authentication.refused",
                detail: "The bearer credential is missing or refused.",
            }],
        ),
        (
            "404",
            vec![ProblemExample {
                code: "resource.not_found",
                detail: "The requested resource was not found.",
            }],
        ),
        (
            "503",
            vec![ProblemExample {
                code: "source.unavailable",
                detail: "The Registry data service is unavailable.",
            }],
        ),
        (
            "504",
            vec![ProblemExample {
                code: "request.timeout",
                detail: "The request timed out.",
            }],
        ),
    ]);
    if matches!(
        operation,
        Operation::List | Operation::Lookup | Operation::Snapshot
    ) {
        responses.entry("400").or_default().extend([
            ProblemExample {
                code: "query.invalid",
                detail: "The query request is invalid.",
            },
            ProblemExample {
                code: "query.cursor_invalid",
                detail: "The query cursor is invalid.",
            },
        ]);
    }
    if operation == Operation::Lookup {
        responses.entry("404").or_default().push(ProblemExample {
            code: "lookup.unresolved",
            detail: "The lookup did not resolve exactly one record.",
        });
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        );
    }
    if matches!(
        operation,
        Operation::Create | Operation::Patch | Operation::Tombstone | Operation::Batch
    ) {
        responses.insert(
            "503",
            vec![ProblemExample {
                code: "service.unavailable",
                detail: "The Registry mutation service is unavailable.",
            }],
        );
        responses.insert(
            "409",
            vec![
                ProblemExample {
                    code: "mutation.conflict",
                    detail: "The mutation conflicts with current state.",
                },
                ProblemExample {
                    code: "idempotency.conflict",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        );
    }
    if matches!(operation, Operation::Patch | Operation::Tombstone) {
        responses.insert(
            "412",
            vec![ProblemExample {
                code: "precondition.failed",
                detail: "The mutation precondition failed.",
            }],
        );
        responses.insert(
            "428",
            vec![ProblemExample {
                code: "precondition.required",
                detail: "The mutation precondition is required.",
            }],
        );
    }
    if is_request_action(operation) {
        if operation == Operation::SubmitRequest {
            // The bounded planner runs at submit, so submit is the only action
            // that can refuse for a plan the planner would not produce.
            responses.entry("400").or_default().push(ProblemExample {
                code: "request.plan_refused",
                detail:
                    "The change-request planner refused the submission: change_request.planner.execution.",
            });
        }
        responses.insert(
            "503",
            vec![ProblemExample {
                code: "service.unavailable",
                detail: "The Registry mutation service is unavailable.",
            }],
        );
        responses.insert(
            "409",
            vec![
                ProblemExample {
                    code: "mutation.conflict",
                    detail: "The mutation conflicts with current state.",
                },
                ProblemExample {
                    code: "idempotency.conflict",
                    detail: "The idempotency key is bound to another request.",
                },
            ],
        );
        responses.insert(
            "412",
            vec![ProblemExample {
                code: "precondition.failed",
                detail: "The mutation precondition failed.",
            }],
        );
        responses.insert(
            "415",
            vec![ProblemExample {
                code: "unsupported.media_type",
                detail: "The request media type is not supported.",
            }],
        );
        responses.insert(
            "428",
            vec![ProblemExample {
                code: "precondition.required",
                detail: "The mutation precondition is required.",
            }],
        );
    }
    responses
}

fn problem_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "title", "status", "detail", "code", "traceId"],
        "properties": {
            "type": {"type": "string", "format": "uri", "maxLength": 256},
            "title": {"type": "string", "maxLength": 128},
            "status": {"type": "integer", "minimum": 400, "maximum": 599},
            "detail": {"type": "string", "maxLength": 256},
            "traceId": {"type": "string", "minLength": 32, "maxLength": 32, "pattern": "^[0-9a-f]{32}$"},
            "fieldPath": {"type": "string", "maxLength": 256},
            "code": {
                "type": "string",
                "enum": [
                    "authentication.refused",
                    "idempotency.conflict",
                    "lookup.unresolved",
                    "mutation.conflict",
                    "precondition.failed",
                    "precondition.required",
                    "query.cursor_invalid",
                    "query.invalid",
                    "request.invalid",
                    "request.plan_refused",
                    "request.timeout",
                    "resource.not_found",
                    "service.unavailable",
                    "source.unavailable",
                    "unsupported.media_type"
                ]
            }
        }
    })
}

fn problem_example(status: &str, code: &str, detail: &str) -> Value {
    json!({
        "type": format!("urn:breg:problem:{code}"),
        "title": match status {
            "400" => "Bad Request",
            "401" => "Unauthorized",
            "404" => "Not Found",
            "409" => "Conflict",
            "412" => "Precondition Failed",
            "415" => "Unsupported Media Type",
            "428" => "Precondition Required",
            "503" => "Service Unavailable",
            "504" => "Gateway Timeout",
            _ => "Request failed",
        },
        "status": status.parse::<u16>().expect("problem status is numeric"),
        "detail": detail,
        "code": code,
        "traceId": OPENAPI_EXAMPLE_TRACE_ID,
    })
}

fn batch_permissions(spec: OpenApiOperationSpec<'_>) -> (bool, bool) {
    match spec.access_profiles {
        OpenApiAccessProfiles::All => (
            spec.route.access_profiles.iter().any(|profile_id| {
                spec.entity.access_profiles[profile_id]
                    .operations
                    .contains(&Operation::Create)
            }),
            spec.route.access_profiles.iter().any(|profile_id| {
                spec.entity.access_profiles[profile_id]
                    .operations
                    .contains(&Operation::Patch)
            }),
        ),
        OpenApiAccessProfiles::Selected(profile_id) => {
            let profile = &spec.entity.access_profiles[profile_id];
            (
                profile.operations.contains(&Operation::Create),
                profile.operations.contains(&Operation::Patch),
            )
        }
    }
}

fn writable_fields_for_route(route: &CompiledRoute, entity: &CompiledEntity) -> BTreeSet<String> {
    route
        .access_profiles
        .iter()
        .filter_map(|profile_id| entity.access_profiles.get(profile_id))
        .flat_map(|profile| profile.writable_fields.iter().cloned())
        .collect()
}

fn query_profile_extension(spec: OpenApiOperationSpec<'_>) -> Option<(String, Value)> {
    if spec.route.query_kind.is_none() && spec.route.operation != Operation::Lookup {
        return None;
    }
    let profiles = query_profiles_for_route(spec.route, spec.query, spec.access_profiles);
    if profiles.is_empty() {
        return None;
    }
    match spec.access_profiles {
        OpenApiAccessProfiles::Selected(_) => Some((
            "x-registry-queryProfile".to_owned(),
            render_query_profile(
                spec.response_entity,
                profiles[0],
                selectable_fields_for_profile(spec, &profiles[0].profile_id),
            ),
        )),
        OpenApiAccessProfiles::All => Some((
            "x-registry-queryProfiles".to_owned(),
            Value::Object(
                profiles
                    .into_iter()
                    .map(|profile| {
                        (
                            profile.profile_id.clone(),
                            render_query_profile(
                                spec.response_entity,
                                profile,
                                selectable_fields_for_profile(spec, &profile.profile_id),
                            ),
                        )
                    })
                    .collect(),
            ),
        )),
    }
}

fn query_profiles_for_route<'a>(
    route: &CompiledRoute,
    query: &'a CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> Vec<&'a CompiledQueryOperation> {
    let mut profiles = query
        .operations
        .iter()
        .filter(|operation| operation.route_id == route.id)
        .filter(|operation| match access_profiles {
            OpenApiAccessProfiles::All => route
                .access_profiles
                .iter()
                .any(|profile| profile == &operation.profile_id),
            OpenApiAccessProfiles::Selected(profile) => operation.profile_id == profile,
        })
        .collect::<Vec<_>>();
    profiles.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    profiles
}

fn render_query_profile(
    entity: &CompiledEntity,
    operation: &CompiledQueryOperation,
    selectable_fields: BTreeSet<String>,
) -> Value {
    let mut rendered = json!({
        "profile": operation.profile_id,
        "kind": query_kind_name(operation.kind),
        "maxPageSize": operation.max_page_size,
        "allowCount": operation.allow_count,
        "selectableProperties": api_field_names(entity, &selectable_fields),
        "filterableProperties": operation.filter_fields.iter().map(|field| {
            json!({
                "property": api_field_name(entity, &field.field).unwrap_or(field.field.as_str()),
                "operators": field.operators.iter().map(|operator| query_filter_operator_name(*operator)).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>(),
        "sortableProperties": operation.sort_fields.iter().map(|field| {
            json!({
                "property": api_field_name(entity, &field.field).unwrap_or(field.field.as_str()),
                "directions": field.directions.iter().map(|direction| match direction {
                    crate::model::CompiledQuerySortDirection::Asc => "asc",
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>(),
        "selectorProperties": api_field_names(entity, &operation.selector_fields),
        "temporal": operation.temporal.as_ref().map(|temporal| json!({
            "startProperty": api_field_name(entity, &temporal.start_field).unwrap_or(temporal.start_field.as_str()),
            "endProperty": api_field_name(entity, &temporal.end_field).unwrap_or(temporal.end_field.as_str()),
            "valueKind": match temporal.value_kind {
                CompiledQueryTemporalValueKind::Date => "date",
                CompiledQueryTemporalValueKind::Timestamp => "timestamp",
            },
            "semantics": "start_inclusive_end_exclusive",
        }))
    });
    if let Some(bbox) = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
    {
        rendered["spatialQueries"] = json!({"bbox": {
            "geometryProperty": api_field_name(entity, &bbox.geometry_field).unwrap_or(&bbox.geometry_field),
            "maximumLongitudeSpanDegrees": bbox.maximum_longitude_span_degrees,
            "maximumLatitudeSpanDegrees": bbox.maximum_latitude_span_degrees,
            "coordinateReferenceSystem": "CRS84",
            "semantics": "inclusive_2d_non_crossing"
        }});
    }
    rendered
}

fn query_filter_operator_name(operator: crate::model::CompiledQueryFilterOperator) -> &'static str {
    match operator {
        crate::model::CompiledQueryFilterOperator::Equals => "equals",
        crate::model::CompiledQueryFilterOperator::In => "in",
        crate::model::CompiledQueryFilterOperator::Range => "range",
        crate::model::CompiledQueryFilterOperator::IsNull => "is_null",
        crate::model::CompiledQueryFilterOperator::IsNotNull => "is_not_null",
        crate::model::CompiledQueryFilterOperator::Prefix => "prefix",
        crate::model::CompiledQueryFilterOperator::Contains => "contains",
    }
}

fn selectable_fields_for_profile(
    spec: OpenApiOperationSpec<'_>,
    profile_id: &str,
) -> BTreeSet<String> {
    if let Some(readable_fields) = spec.readable_fields {
        return readable_fields.clone();
    }
    if let Some(read_path) = read_path_for_route(spec.route, spec.entity) {
        return spec
            .entity
            .access_profiles
            .get(profile_id)
            .and_then(|profile| {
                profile
                    .read_paths
                    .iter()
                    .find(|grant| grant.path == read_path.id)
            })
            .map(|grant| grant.readable_fields.clone())
            .unwrap_or_default();
    }
    spec.entity
        .access_profiles
        .get(profile_id)
        .map(|profile| profile.readable_fields.clone())
        .unwrap_or_default()
}

fn api_field_names<'a>(
    entity: &CompiledEntity,
    fields: impl IntoIterator<Item = &'a String>,
) -> Vec<String> {
    fields
        .into_iter()
        .filter_map(|field| api_field_name(entity, field).map(str::to_owned))
        .collect()
}

fn api_field_name<'a>(entity: &'a CompiledEntity, field_id: &str) -> Option<&'a str> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| field.logical.api_name.as_str())
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .map(|field| field.logical.api_name.as_str())
        })
        .or_else(|| {
            (entity.canonical_id.id == field_id).then_some(entity.canonical_id.api_name.as_str())
        })
}

fn max_page_size(
    route: &CompiledRoute,
    query: &CompiledQueryInventory,
    access_profiles: OpenApiAccessProfiles<'_>,
) -> u16 {
    query_profiles_for_route(route, query, access_profiles)
        .into_iter()
        .map(|operation| operation.max_page_size)
        .max()
        .unwrap_or(crate::query::MAX_TOP as u16)
}

fn response_entity_for_route<'a>(
    route: &CompiledRoute,
    entities: &'a BTreeMap<String, CompiledEntity>,
) -> &'a CompiledEntity {
    let entity = entities
        .get(&route.entity_id)
        .expect("compiled route refers to a compiled entity");
    if route.operation == Operation::List && route.id.contains(".path.") {
        if let Some(path) = read_path_for_route(route, entity) {
            return entities
                .get(&path.to)
                .expect("compiled read path refers to a compiled entity");
        }
    }
    entity
}

fn read_path_for_route<'a>(
    route: &CompiledRoute,
    entity: &'a CompiledEntity,
) -> Option<&'a crate::model::CompiledReadPath> {
    entity
        .read_paths
        .values()
        .find(|path| route.id == format!("records.{}.path.{}", entity.id, path.id))
}

fn revision_kind_name(kind: CompiledRevisionKind) -> &'static str {
    match kind {
        CompiledRevisionKind::List => "list",
        CompiledRevisionKind::Detail => "detail",
    }
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "delete",
        HttpMethod::Get => "get",
        HttpMethod::Patch => "patch",
        HttpMethod::Post => "post",
    }
}

fn query_kind_name(kind: CompiledQueryKind) -> &'static str {
    match kind {
        CompiledQueryKind::List => "list",
        CompiledQueryKind::Current => "current",
        CompiledQueryKind::AsOf => "as_of",
        CompiledQueryKind::Snapshot => "snapshot",
    }
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Get => "get",
        Operation::Lookup => "lookup",
        Operation::List => "list",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
        Operation::Snapshot => "snapshot",
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        Operation::Invoke => "invoke",
    }
}

fn is_request_action(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::SubmitRequest
            | Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ReviseRequest
            | Operation::CancelRequest
            | Operation::ApplyRequest
    )
}

fn insert_json<T: Serialize>(
    artifacts: &mut BTreeMap<String, GeneratedArtifact>,
    path: &str,
    value: &T,
) -> Result<(), Diagnostic> {
    let value = serde_json::to_value(value).map_err(|_| canonicalization_error())?;
    insert_json_value(artifacts, path, &value)
}

fn insert_json_value(
    artifacts: &mut BTreeMap<String, GeneratedArtifact>,
    path: &str,
    value: &Value,
) -> Result<(), Diagnostic> {
    let bytes = canonicalize_json(value).map_err(|_| canonicalization_error())?;
    insert_bytes(artifacts, path, "application/json", bytes);
    Ok(())
}

fn insert_bytes(
    artifacts: &mut BTreeMap<String, GeneratedArtifact>,
    path: &str,
    media_type: &str,
    bytes: Vec<u8>,
) {
    let digest = Sha256::digest(&bytes);
    artifacts.insert(
        path.to_owned(),
        GeneratedArtifact {
            path: path.to_owned(),
            media_type: media_type.to_owned(),
            sha256: format!("sha256:{}", hex_prefix(&digest, digest.len())),
            bytes,
        },
    );
}

fn canonicalization_error() -> Diagnostic {
    Diagnostic::error(
        "artifact.canonicalization_failed",
        "artifacts",
        "the generated artifact could not be canonicalized",
    )
}

#[cfg(test)]
mod spatial_tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use crate::model::CompiledRegistry;

    fn registry() -> CompiledRegistry {
        let project = parse_project_json(br#"{
            "apiVersion":"registry.registrystack.org/v1alpha1",
            "kind":"RegistryProject",
            "registry":{"id":"spatial-artifacts","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://spatial-artifacts.example.test"},
            "entities":[{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
                "geojson":{"geometryField":"location"},
                "fields":[
                    {"id":"code","type":"string","maxLength":32,"classification":"internal"},
                    {"id":"label","type":"string","maxLength":64,"classification":"internal"},
                    {"id":"location","apiName":"position","type":"crs84-point","precision":9,"classification":"internal"}
                ]
            }],
            "accessProfiles":[
                {"id":"map","default":true,"principalClaim":"principal","grants":[{"entity":"site","operations":["get","list"],"readableFields":["code","label","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.5,"maximumLatitudeSpanDegrees":0.25}}}]},
                {"id":"plain","principalClaim":"principal","grants":[{"entity":"site","operations":["get","list"],"readableFields":["code"]}]},
                {"id":"geometry-only","principalClaim":"principal","grants":[{"entity":"site","operations":["get","list"],"readableFields":["location"]}]}
            ]
        }"#).expect("spatial artifact fixture parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("spatial artifact fixture compiles")
    }

    fn operation(registry: &CompiledRegistry, method: Operation, profile: &str) -> Value {
        let entity = &registry.entities()["site"];
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.operation == method)
            .expect("fixture route exists");
        openapi_operation(OpenApiOperationSpec {
            registry_identifier: registry.registry_id(),
            route,
            entity,
            response_entity: entity,
            query: registry.queries(),
            schema_ref: "site",
            request_schema_ref: "site",
            readable_fields: None,
            access_profiles: OpenApiAccessProfiles::Selected(profile),
        })
    }

    #[test]
    fn selected_profile_controls_bbox_and_geojson_advertisement() {
        let registry = registry();
        let map = operation(&registry, Operation::List, "map");
        assert!(map["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "bbox"));
        assert_eq!(
            map["x-registry-queryProfile"]["spatialQueries"]["bbox"]["geometryProperty"],
            "position"
        );
        assert_eq!(
            map["x-registry-queryProfile"]["spatialQueries"]["bbox"]["maximumLatitudeSpanDegrees"],
            0.25
        );
        assert!(map.get("x-registry-responseShape").is_none());
        assert_eq!(
            map["x-registry-responseShapes"],
            json!({
                "application/json": "RegistryRecordCollectionV1",
                "application/ld+json": "RegistryRecordCollectionV1",
                "application/geo+json": "BRegGeoJsonFeatureCollectionV1",
            })
        );
        assert_eq!(
            map["x-registry-responseProfile"], PROFILE_IDENTIFIER,
            "the stable profile marker governs only the JSON and JSON-LD shapes in the media map"
        );
        let feature = &map["responses"]["200"]["content"]["application/geo+json"]["schema"]
            ["properties"]["features"]["items"];
        assert!(feature["properties"]["properties"]["properties"]["code"].is_object());
        assert!(feature["properties"]["properties"]["properties"]
            .get("position")
            .is_none());
        assert_eq!(
            feature["properties"]["geometry"]["anyOf"][1]["type"],
            "null"
        );
        assert_eq!(
            feature["properties"]["registry"]["required"],
            json!(["revision"])
        );
        let select = map["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "$select")
            .unwrap();
        assert_eq!(select["examples"]["withoutGeometry"]["value"], "code,label");
        assert_eq!(
            select["examples"]["withGeometry"]["value"],
            "code,label,position"
        );

        let plain = operation(&registry, Operation::List, "plain");
        assert!(!plain["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "bbox"));
        assert!(plain["responses"]["200"]["content"]
            .get("application/geo+json")
            .is_none());
        assert_eq!(
            plain["x-registry-responseShape"],
            "RegistryRecordCollectionV1"
        );
        assert_eq!(plain["x-registry-responseProfile"], PROFILE_IDENTIFIER);
        assert!(plain.get("x-registry-responseShapes").is_none());
        assert!(plain.get("x-registry-geojsonProfiles").is_none());
        assert!(plain["x-registry-queryProfile"]
            .get("spatialQueries")
            .is_none());
    }

    #[test]
    fn geojson_without_bbox_does_not_widen_properties() {
        let registry = registry();
        let get = operation(&registry, Operation::Get, "geometry-only");
        let content = &get["responses"]["200"]["content"];
        assert!(content["application/json"].is_object());
        assert_eq!(
            get["x-registry-responseShapes"]["application/geo+json"],
            "BRegGeoJsonFeatureV1"
        );
        assert_eq!(
            get["x-registry-responseShapes"]["application/json"],
            "RegistryRecordSingleV1"
        );
        let schema = &content["application/geo+json"]["schema"];
        assert_eq!(schema["properties"]["type"]["const"], "Feature");
        assert_eq!(schema["properties"]["properties"]["properties"], json!({}));
        assert!(!get["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "bbox"));
    }

    #[test]
    fn effective_model_keeps_only_safe_planner_provenance() {
        let mut value = json!({
            "entities": {
                "request": {
                    "changeRequest": {
                        "planner": {
                            "sourceModule": null,
                            "scriptPath": "modules/private/plan.rhai",
                            "scriptBytes": [1, 2, 3],
                            "scriptSha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                            "limits": {"maximumOperations": 100}
                        }
                    }
                },
                "module-request": {
                    "changeRequest": {
                        "planner": {
                            "sourceModule": "request-module",
                            "scriptPath": "private.rhai",
                            "scriptBytes": [4],
                            "scriptSha256": "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                            "limits": {"maximumOperations": 200}
                        }
                    }
                }
            }
        });
        sanitize_effective_model_planners(&mut value);

        let project = &value["entities"]["request"]["changeRequest"]["planner"];
        assert_eq!(project["declaringOrigin"], json!({"kind": "project"}));
        assert!(project.get("scriptPath").is_none());
        assert!(project.get("scriptBytes").is_none());
        assert!(project["scriptSha256"].is_string());
        assert_eq!(project["limits"]["maximumOperations"], 100);

        let module = &value["entities"]["module-request"]["changeRequest"]["planner"];
        assert_eq!(
            module["declaringOrigin"],
            json!({"kind": "module", "id": "request-module"})
        );
        assert!(module.get("scriptPath").is_none());
        assert!(module.get("scriptBytes").is_none());
    }
}
