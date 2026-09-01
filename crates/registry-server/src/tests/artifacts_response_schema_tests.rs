// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

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
            "data": {
                "recordIdentifier": request_id,
                "revisionIdentifier": "4",
                "domainData": {
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
            },
            },
            "meta": {
                "registryIdentifier": "change-request-openapi",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": "placement-correction-request"
            }
        }),
    );

    assert_valid(
        &schema,
        &json!({
            "data": {
                "recordIdentifier": request_id,
                "revisionIdentifier": "9",
                "domainData": {},
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
            },
            },
            "meta": {
                "registryIdentifier": "change-request-openapi",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": "placement-correction-request"
            }
        }),
    );

    assert_invalid(
        &schema,
        &json!({
            "data": {
                "recordIdentifier": request_id,
                "revisionIdentifier": "9",
                "domainData": {},
                "request": {
                    "serverState": "applied",
                    "proposalVersion": 2,
                    "editable": false
                }
            },
            "meta": {
                "registryIdentifier": "change-request-openapi",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": "placement-correction-request"
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "data": {
                "recordIdentifier": request_id,
                "revisionIdentifier": "4",
                "domainData": {
                    "placement": placement_id,
                    "proposedSite": replacement_site_id
                },
                "request": {
                    "serverState": "submitted",
                    "proposalVersion": 2,
                    "editable": false,
                    "operatorSecret": "must-not-be-modeled"
                }
            },
            "meta": {
                "registryIdentifier": "change-request-openapi",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": "placement-correction-request"
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
            "data": {
                "recordIdentifier": "00000000-0000-4000-8000-000000000001",
                "revisionIdentifier": "4",
                "domainData": {
                    "placement": "00000000-0000-4000-8000-000000000010"
                },
                "request": {
                    "serverState": "submitted",
                    "proposalVersion": 2,
                    "editable": false
                }
            },
            "meta": {
                "registryIdentifier": "change-request-openapi",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": "placement-correction-request"
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "data": {
                "recordIdentifier": "00000000-0000-4000-8000-000000000001",
                "revisionIdentifier": "4",
                "domainData": {
                    "placement": "00000000-0000-4000-8000-000000000010",
                    "proposedSite": "00000000-0000-4000-8000-000000000021"
                },
                "request": {
                    "serverState": "submitted",
                    "proposalVersion": 2,
                    "editable": false
                }
            },
            "meta": {
                "registryIdentifier": "change-request-openapi",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": "placement-correction-request"
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
        "data": {
            "recordIdentifier": "00000000-0000-4000-8000-000000000010",
            "revisionIdentifier": "8",
            "domainData": {
                "site": "00000000-0000-4000-8000-000000000020"
            },
            "requestPresence": {
                "requests": [{
                    "requestType": "placement-correction-request",
                    "pending": true
                }]
            }
        },
        "meta": {
            "registryIdentifier": "change-request-openapi",
            "datasetIdentifier": "test-dataset",
            "entityTypeIdentifier": "placement"
        }
    });
    assert_valid(&schema, &record);

    let mut widened = record;
    widened["data"]["requestPresence"]["requests"][0]["effectDigest"] = json!(effect_digest());
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

#[test]
fn immediate_action_response_schema_filters_results_by_selected_profile() {
    let registry = compiled_action_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-household-contact")
        .expect("compiled action exists");
    let selected = BTreeSet::from(["household".to_owned()]);
    let schema = inline_validator(&super::openapi_action_response_schema(
        action,
        Some(&selected),
    ));

    assert_valid(
        &schema,
        &json!({
            "action": "register-household-contact",
            "applicationId": "00000000-0000-4000-8000-000000000200",
            "results": {
                "household": {
                    "entity": "household",
                    "recordId": "00000000-0000-4000-8000-000000000100",
                    "revision": 13
                }
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "action": "register-household-contact",
            "applicationId": "00000000-0000-4000-8000-000000000200",
            "results": {
                "person": {
                    "entity": "person",
                    "recordId": "00000000-0000-4000-8000-000000000201",
                    "revision": 1
                }
            }
        }),
    );
}

#[test]
fn immediate_action_all_profile_response_schema_preserves_grant_result_shapes() {
    let registry = compiled_action_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-household-contact")
        .expect("compiled action exists");
    let schema_value = super::openapi_action_response_schema(action, None);
    let result_shapes = schema_value["properties"]["results"]["oneOf"]
        .as_array()
        .expect("different grant result sets are represented as oneOf");
    assert_eq!(result_shapes.len(), 2);
    let schema = inline_validator(&schema_value);

    assert_valid(
        &schema,
        &json!({
            "action": "register-household-contact",
            "applicationId": "00000000-0000-4000-8000-000000000200",
            "results": {
                "household": {
                    "entity": "household",
                    "recordId": "00000000-0000-4000-8000-000000000100",
                    "revision": 13
                }
            }
        }),
    );
    assert_valid(
        &schema,
        &json!({
            "action": "register-household-contact",
            "applicationId": "00000000-0000-4000-8000-000000000200",
            "results": {
                "person": {
                    "entity": "person",
                    "recordId": "00000000-0000-4000-8000-000000000201",
                    "revision": 1
                },
                "membership": {
                    "entity": "group-membership",
                    "recordId": "00000000-0000-4000-8000-000000000202",
                    "revision": 1
                },
                "household": {
                    "entity": "household",
                    "recordId": "00000000-0000-4000-8000-000000000100",
                    "revision": 14
                }
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "action": "register-household-contact",
            "applicationId": "00000000-0000-4000-8000-000000000200",
            "results": {
                "person": {
                    "entity": "person",
                    "recordId": "00000000-0000-4000-8000-000000000201",
                    "revision": 1
                },
                "household": {
                    "entity": "household",
                    "recordId": "00000000-0000-4000-8000-000000000100",
                    "revision": 14
                }
            }
        }),
    );
}

#[test]
fn immediate_action_all_profile_response_schema_allows_exact_sole_grant_results() {
    let registry = compiled_asset_result_action_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-asset")
        .expect("compiled action exists");
    let schema_value = super::openapi_action_response_schema(action, None);
    assert!(schema_value["properties"]["results"].get("oneOf").is_none());
    let schema = inline_validator(&schema_value);

    assert_valid(
        &schema,
        &json!({
            "action": "register-asset",
            "applicationId": "00000000-0000-4000-8000-000000000300",
            "results": {
                "asset": {
                    "entity": "asset",
                    "recordId": "00000000-0000-4000-8000-000000000301",
                    "revision": 1
                }
            }
        }),
    );
    assert_invalid(
        &schema,
        &json!({
            "action": "register-asset",
            "applicationId": "00000000-0000-4000-8000-000000000300",
            "results": {
                "asset": {
                    "entity": "asset",
                    "recordId": "00000000-0000-4000-8000-000000000301",
                    "revision": 1
                },
                "initial-inspection": {
                    "entity": "inspection",
                    "recordId": "00000000-0000-4000-8000-000000000302",
                    "revision": 1
                }
            }
        }),
    );
}

#[test]
fn immediate_action_metadata_and_operation_filter_selected_profile() {
    let registry = compiled_action_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-household-contact")
        .expect("compiled action exists");
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.id == "actions.register-household-contact.invoke")
        .expect("compiled invoke route exists");

    let metadata = super::public_action_metadata_entry(action, Some("contact-auditor"));
    assert_eq!(
        metadata["access"],
        json!({"selectedProfile": "contact-auditor"})
    );
    assert_eq!(
        metadata["resultEffects"],
        json!([{
            "effect": "household",
            "entity": "household",
            "operation": "patch"
        }])
    );
    let operation = super::openapi_action_operation(
        route,
        action,
        super::OpenApiAccessProfiles::Selected("contact-auditor"),
    );
    assert_eq!(operation["x-registry-accessProfile"], "contact-auditor");
    assert!(operation.get("x-registry-accessProfiles").is_none());
    let rendered = serde_json::to_string(&operation).expect("operation serializes");
    assert!(!rendered.contains("private_claim_name"));
    assert!(!rendered.contains("other_private_claim"));
    assert!(!rendered.contains("rowBoundaries"));
    assert!(!rendered.contains("contact-registrar"));
}

#[test]
fn immediate_action_input_and_condition_schemas_are_strict_envelopes() {
    let registry = compiled_action_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-household-contact")
        .expect("compiled action exists");
    let invoke = inline_validator(&super::openapi_action_input_schema(action));
    let condition_read = inline_validator(&super::openapi_action_condition_request_schema(action));
    let condition_response =
        inline_validator(&super::openapi_action_condition_response_schema(action));

    assert_valid(
        &invoke,
        &json!({
            "input": {
                "householdId": "00000000-0000-4000-8000-000000000100",
                "personCode": "P-001",
                "legalName": "Alex Example"
            },
            "preconditions": {
                "householdId": {"ifMatch": "\"rsac-0123456789abcdef\""}
            }
        }),
    );
    assert_valid(
        &condition_response,
        &json!({
            "preconditions": {
                "householdId": {"ifMatch": "\"rsac-0123456789abcdef\""}
            }
        }),
    );
    for condition in ["W/\"rsac-weak\"", "*", "rsac-unquoted"] {
        assert_invalid(
            &invoke,
            &json!({
                "input": {
                    "householdId": "00000000-0000-4000-8000-000000000100",
                    "personCode": "P-001",
                    "legalName": "Alex Example"
                },
                "preconditions": {
                    "householdId": {"ifMatch": condition}
                }
            }),
        );
        assert_invalid(
            &condition_response,
            &json!({
                "preconditions": {
                    "householdId": {"ifMatch": condition}
                }
            }),
        );
    }
    assert_invalid(
        &invoke,
        &json!({
            "input": {
                "householdId": "00000000-0000-4000-8000-000000000100",
                "personCode": "P-001",
                "legalName": "Alex Example"
            },
            "preconditions": {}
        }),
    );
    assert_valid(
        &condition_read,
        &json!({
            "input": {
                "householdId": "00000000-0000-4000-8000-000000000100"
            }
        }),
    );
    assert_invalid(
        &condition_read,
        &json!({
            "input": {
                "householdId": "00000000-0000-4000-8000-000000000100",
                "personCode": "P-001"
            }
        }),
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

fn inline_validator(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .expect("schema compiles")
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
          "registry":{"id":"change-request-openapi","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://change-request-openapi.example.test"},
          "entities":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only",
            "fields":[{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}]
          },{
            "id":"placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
              {"id":"site","type":"reference","target":"site","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":64,"classification":"internal"}
            ]
          },{
            "id":"placement-correction-request","primaryDataset":"test-dataset","route":"placement-correction-requests","mutationMode":"mutable",
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

fn compiled_action_registry() -> CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"action-openapi","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://action-openapi.example.test"},
          "entities":[{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","apiName":"householdCode","type":"string","maxLength":64,"required":true,"classification":"internal"},
              {"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"}
            ]
          },{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
            "fields":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ]
          },{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"create_only",
            "fields":[
              {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"},
              {"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"}
            ]
          }],
          "actions":[{
            "id":"register-household-contact",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ],
            "effects":[{
              "id":"person",
              "target":{"entity":"person"},
              "operation":"create",
              "set":{
                "person-code":{"fromField":"person-code"},
                "legal-name":{"fromField":"legal-name"}
              }
            },{
              "id":"membership",
              "target":{"entity":"group-membership"},
              "operation":"create",
              "set":{
                "person":{"fromEffect":"person"},
                "household":{"fromField":"household"}
              }
            },{
              "id":"household",
              "target":{"fromField":"household"},
              "operation":"patch",
              "set":{"contact-person":{"fromEffect":"person"}}
            }]
          }],
          "accessProfiles":[{
            "id":"contact-registrar",
            "default":true,
            "principalClaim":"private_claim_name",
            "requiredScopes":["registry:contact:register"],
            "requiredPurposes":["contact-registration"],
            "grants":[{
              "action":"register-household-contact",
              "operations":["invoke"],
              "targets":[
                {"entity":"household"},
                {"entity":"person"},
                {"entity":"group-membership"}
              ],
              "results":["person","membership","household"]
            }]
          },{
            "id":"contact-auditor",
            "principalClaim":"other_private_claim",
            "requiredScopes":["registry:contact:audit"],
            "requiredPurposes":["contact-audit"],
            "grants":[{
              "action":"register-household-contact",
              "operations":["invoke"],
              "targets":[
                {"entity":"household"},
                {"entity":"person"},
                {"entity":"group-membership"}
              ],
              "results":["household"]
            }]
          }]
        }"#,
    )
    .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

fn compiled_asset_result_action_registry() -> CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"asset-action-openapi","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://asset-action-openapi.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"create_only",
            "fields":[
              {"id":"asset-code","apiName":"assetCode","type":"string","maxLength":64,"required":true,"classification":"internal"}
            ]
          },{
            "id":"inspection","primaryDataset":"test-dataset","route":"inspections","mutationMode":"create_only",
            "fields":[
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"}
            ]
          }],
          "actions":[{
            "id":"register-asset",
            "inputs":[
              {"id":"asset-code","apiName":"assetCode","type":"string","maxLength":64,"required":true,"classification":"internal"}
            ],
            "effects":[{
              "id":"asset",
              "target":{"entity":"asset"},
              "operation":"create",
              "set":{"asset-code":{"fromField":"asset-code"}}
            },{
              "id":"initial-inspection",
              "target":{"entity":"inspection"},
              "operation":"create",
              "set":{"asset":{"fromEffect":"asset"}}
            }]
          }],
          "accessProfiles":[{
            "id":"asset-registrar",
            "default":true,
            "principalClaim":"principal",
            "requiredScopes":["registry:asset:register"],
            "grants":[{
              "action":"register-asset",
              "operations":["invoke"],
              "targets":[
                {"entity":"asset"},
                {"entity":"inspection"}
              ],
              "results":["asset"]
            }]
          }]
        }"#,
    )
    .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
