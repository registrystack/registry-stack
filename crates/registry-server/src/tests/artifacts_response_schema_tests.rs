// SPDX-License-Identifier: Apache-2.0

use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};

use crate::compiler::{compile_project, CompileProfile};
use crate::contract::{parse_project_json, Operation};
use crate::model::{CompiledRegistry, HttpMethod};

#[test]
fn request_get_schema_accepts_runtime_annotations_and_erased_terminal_data() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let schema = response_validator(
        &openapi,
        route_path(&registry, "placement-correction-request", Operation::Get),
        "get",
        "200",
    );
    let digest = effect_digest();
    let request_id = "00000000-0000-4000-8000-000000000001";
    let placement_id = "00000000-0000-4000-8000-000000000010";
    let site_id = "00000000-0000-4000-8000-000000000020";
    let replacement_site_id = "00000000-0000-4000-8000-000000000021";

    assert_valid(
        &schema,
        &json!({
            "id": request_id,
            "revision": 4,
            "data": {
                "placement": placement_id,
                "proposedSite": replacement_site_id
            },
            "request": {
                "serverState": "submitted",
                "proposalVersion": 2,
                "effectDigest": digest,
                "editable": false,
                "actions": [{
                    "operation": "approve_request",
                    "method": "POST",
                    "href": "/v1/records/placement-correction-requests/00000000-0000-4000-8000-000000000001/actions/stages/review/approve?accessProfile=request-reviewer",
                    "ifMatch": "\"rs-action\"",
                    "stage": "review",
                    "proposalVersion": 2,
                    "effectDigest": digest,
                    "review": {
                        "targets": [{
                            "entityId": "placement",
                            "recordId": placement_id,
                            "operation": "patch",
                            "baseRevision": 7,
                            "before": {"site": site_id},
                            "after": {"site": replacement_site_id}
                        }]
                    }
                }],
                "application": {
                    "applicationId": "00000000-0000-4000-8000-0000000000aa",
                    "proposalVersion": 2,
                    "effectDigest": digest,
                    "appliedAt": "2026-08-31T01:02:03.700350Z"
                },
                "history": {
                    "proposals": [{
                        "requestEntityId": "placement-correction-request",
                        "requestId": request_id,
                        "proposalVersion": 2,
                        "serverState": "submitted",
                        "current": true,
                        "contractFingerprint": "sha256:contract",
                        "detailErased": false,
                        "applicationId": null,
                        "resultLinkCount": 0,
                        "resultLinks": [],
                        "effectDigest": digest
                    }],
                    "nextAfterProposalVersion": null
                }
            }
        }),
    );

    assert_valid(
        &schema,
        &json!({
            "id": request_id,
            "revision": 9,
            "data": {},
            "request": {
                "serverState": "applied",
                "proposalVersion": 2,
                "detailErased": true,
                "editable": false,
                "effectDigest": digest,
                "application": {
                    "applicationId": "00000000-0000-4000-8000-0000000000aa",
                    "proposalVersion": 2
                },
                "history": {
                    "proposals": [{
                        "requestEntityId": "placement-correction-request",
                        "requestId": request_id,
                        "proposalVersion": 2,
                        "serverState": "applied",
                        "current": true,
                        "contractFingerprint": "sha256:contract",
                        "detailErased": true,
                        "applicationId": "00000000-0000-4000-8000-0000000000aa",
                        "resultLinkCount": 1,
                        "resultLinks": [{
                            "targetEntityId": "placement",
                            "targetRecordId": placement_id,
                            "targetRevision": 8
                        }],
                        "effectDigest": digest
                    }],
                    "nextAfterProposalVersion": null
                }
            }
        }),
    );

    assert_invalid(
        &schema,
        &json!({
            "id": request_id,
            "revision": 9,
            "data": {},
            "request": {
                "serverState": "applied",
                "proposalVersion": 2,
                "editable": false
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "id": request_id,
            "revision": 4,
            "data": {
                "placement": placement_id,
                "proposedSite": replacement_site_id
            },
            "request": {
                "serverState": "submitted",
                "proposalVersion": 2,
                "editable": false,
                "operatorSecret": "must-not-be-modeled"
            }
        }),
    );
}

#[test]
fn served_field_projection_keeps_response_data_strict_but_subsettable() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let path = route_path(&registry, "placement-correction-request", Operation::Get);
    let response_schema =
        &openapi["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"];
    let schema = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/response",
            "$defs": {"response": response_schema},
            "components": {
                "schemas": {
                    "placement-correction-request": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["placement"],
                        "properties": {
                            "placement": {"type": "string", "format": "uuid"}
                        }
                    }
                }
            }
        }))
        .expect("served response schema compiles");

    assert_valid(
        &schema,
        &json!({
            "id": "00000000-0000-4000-8000-000000000001",
            "revision": 4,
            "data": {
                "placement": "00000000-0000-4000-8000-000000000010"
            },
            "request": {
                "serverState": "submitted",
                "proposalVersion": 2,
                "editable": false
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "id": "00000000-0000-4000-8000-000000000001",
            "revision": 4,
            "data": {
                "placement": "00000000-0000-4000-8000-000000000010",
                "proposedSite": "00000000-0000-4000-8000-000000000021"
            },
            "request": {
                "serverState": "submitted",
                "proposalVersion": 2,
                "editable": false
            }
        }),
    );
}

#[test]
fn target_get_schema_accepts_bounded_request_presence_annotations() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let schema = response_validator(
        &openapi,
        route_path(&registry, "placement", Operation::Get),
        "get",
        "200",
    );
    let record = json!({
        "id": "00000000-0000-4000-8000-000000000010",
        "revision": 8,
        "data": {
            "site": "00000000-0000-4000-8000-000000000020"
        },
        "requestPresence": {
            "requests": [{
                "requestType": "placement-correction-request",
                "pending": true
            }]
        }
    });
    assert_valid(&schema, &record);

    let mut widened = record;
    widened["requestPresence"]["requests"][0]["effectDigest"] = json!(effect_digest());
    assert_invalid(&schema, &widened);
}

#[test]
fn action_response_schema_matches_application_receipt_shape() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let component = &openapi["components"]["schemas"]["ChangeRequestActionResponse"];
    assert!(component["required"]
        .as_array()
        .expect("action response required properties render")
        .contains(&json!("snapshot")));
    assert_eq!(
        component["properties"]["snapshot"]["maxLength"],
        crate::query::MAX_OPAQUE_VALUE_BYTES
    );
    let schema = component_validator(&openapi, "ChangeRequestActionResponse");
    let digest = effect_digest();

    assert_valid(
        &schema,
        &json!({
            "id": "00000000-0000-4000-8000-000000000001",
            "revision": 10,
            "snapshot": snapshot_reference(),
            "request": {
                "serverState": "applied",
                "proposalVersion": 2,
                "effectDigest": digest,
                "application": {
                    "applicationId": "00000000-0000-4000-8000-0000000000aa",
                    "proposalVersion": 2,
                    "effectDigest": digest,
                    "appliedAt": "2026-08-31T01:02:03.700350Z"
                }
            }
        }),
    );

    assert_invalid(
        &schema,
        &json!({
            "id": "00000000-0000-4000-8000-000000000001",
            "revision": 10,
            "request": {
                "serverState": "applied",
                "proposalVersion": 2,
                "effectDigest": digest,
                "application": {
                    "applicationId": "00000000-0000-4000-8000-0000000000aa",
                    "proposalVersion": 2,
                    "effectDigest": digest,
                    "appliedAt": "2026-08-31T01:02:03.700350Z"
                }
            }
        }),
    );

    assert_invalid(
        &schema,
        &json!({
            "id": "00000000-0000-4000-8000-000000000001",
            "revision": 10,
            "snapshot": snapshot_reference(),
            "request": {
                "serverState": "applied",
                "proposalVersion": 2,
                "effectDigest": digest,
                "application": {
                    "id": "00000000-0000-4000-8000-0000000000aa",
                    "proposalVersion": 2,
                    "effectDigest": digest
                }
            }
        }),
    );
}

#[test]
fn generated_request_metadata_exposes_effective_retention_policy() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let request = &openapi["components"]["schemas"]["placement-correction-request"]
        ["x-registry-changeRequest"];
    assert_eq!(request["retention"]["mode"], "operator_erase");
    assert_eq!(
        request["retention"]["effectivePolicy"]["erasedDetailMarker"],
        "request.detailErased"
    );
}

fn response_validator(openapi: &Value, path: &str, method: &str, status: &str) -> JSONSchema {
    let response_schema = &openapi["paths"][path][method]["responses"][status]["content"]
        ["application/json"]["schema"];
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/response",
            "$defs": {"response": response_schema},
            "components": openapi["components"].clone()
        }))
        .expect("response schema compiles")
}

fn component_validator(openapi: &Value, component: &str) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("#/components/schemas/{component}"),
            "components": openapi["components"].clone()
        }))
        .expect("component schema compiles")
}

fn assert_valid(schema: &JSONSchema, value: &Value) {
    if let Err(errors) = schema.validate(value) {
        panic!(
            "expected value to satisfy schema:\n{}",
            errors
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn assert_invalid(schema: &JSONSchema, value: &Value) {
    assert!(
        schema.validate(value).is_err(),
        "expected value to be rejected by schema: {value}"
    );
}

fn generated_openapi(registry: &CompiledRegistry) -> Value {
    let artifact = registry
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI artifact exists");
    serde_json::from_slice(&artifact.bytes).expect("OpenAPI parses")
}

fn route_path<'a>(
    registry: &'a CompiledRegistry,
    entity_id: &str,
    operation: Operation,
) -> &'a str {
    registry
        .routes()
        .routes
        .iter()
        .find(|route| {
            route.entity_id == entity_id
                && route.operation == operation
                && route.method == HttpMethod::Get
                && route.query_kind.is_none()
        })
        .map(|route| route.path.as_str())
        .expect("route exists")
}

fn effect_digest() -> &'static str {
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

fn snapshot_reference() -> &'static str {
    "rs1_018feaa0-68f9-4a45-b9e3-58436df07af7"
}

fn compiled_registry() -> CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-openapi","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"site","route":"sites","mutationMode":"create_only",
            "fields":[{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}]
          },{
            "id":"placement","route":"placements","mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
              {"id":"site","type":"reference","target":"site","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":64,"classification":"internal"}
            ]
          },{
            "id":"placement-correction-request","route":"placement-correction-requests","mutationMode":"mutable",
            "fields":[
              {"id":"placement","type":"reference","target":"placement","required":true,"classification":"internal"},
              {"id":"proposed-site","apiName":"proposedSite","type":"reference","target":"site","required":true,"classification":"internal"}
            ],
            "changeRequest":{
              "retention":{"mode":"operator_erase"},
              "effects":[{
                "target":{"fromField":"placement"},
                "operation":"patch",
                "set":{"site":{"fromField":"proposed-site"}}
              }],
              "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
            }
          }],
          "accessProfiles":[{
            "id":"request-reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","approve_request","reject_request","request_revision"],
              "readableFields":["placement","proposed-site"],
              "reviewStages":[{
                "stage":"review",
                "targets":[{
                  "entity":"placement",
                  "readableFields":["site"],
                  "rowBoundaries":[{"field":"site","claim":"site_claim","operator":"equals"}]
                }]
              }]
            }]
          },{
            "id":"request-submitter","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","create","patch","submit_request"],
              "readableFields":["placement","proposed-site"],
              "writableFields":["placement","proposed-site"]
            }]
          },{
            "id":"request-applier","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request",
              "operations":["get","apply_request"],
              "readableFields":["placement"],
              "applyTargets":[{"entity":"placement"}]
            }]
          },{
            "id":"placement-viewer","principalClaim":"principal","grants":[{
              "entity":"placement",
              "operations":["get"],
              "readableFields":["site"],
              "requestPresence":[{
                "requestType":"placement-correction-request",
                "rowBoundaries":[{"field":"placement","claim":"placement_claim","operator":"equals"}]
              }]
            }]
          }]
        }"#,
    )
    .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
