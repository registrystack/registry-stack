// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};

use crate::compiler::{compile_project, CompileProfile};
use crate::contract::{parse_project_json, Operation};
use crate::model::{CompiledRegistry, HttpMethod};

#[test]
fn unconditioned_action_schema_accepts_only_empty_optional_preconditions() {
    let registry = compiled_asset_result_action_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-asset")
        .unwrap();
    assert!(crate::plan::condition_inputs(action).is_empty());
    let schema = inline_validator(&super::openapi_action_input_schema(action));
    assert_valid(&schema, &json!({"input":{"assetCode":"ASSET-1"}}));
    assert_valid(
        &schema,
        &json!({"input":{"assetCode":"ASSET-1"},"preconditions":{}}),
    );
    assert_invalid(
        &schema,
        &json!({"input":{"assetCode":"ASSET-1"},"preconditions":{"assetCode":{"ifMatch":"\"opaque\""}}}),
    );
    assert_invalid(
        &schema,
        &json!({"input":{"assetCode":"ASSET-1"},"preconditions":null}),
    );
}

#[test]
fn prospective_row_boundary_refusal_is_documented_only_where_it_can_apply() {
    for operation in [Operation::Create, Operation::Patch, Operation::Batch] {
        assert!(super::problem_responses(operation, true, false).contains_key("403"));
        assert!(!super::problem_responses(operation, false, false).contains_key("403"));
    }
    assert!(!super::problem_responses(Operation::Create, true, false).contains_key("412"));
    assert!(super::problem_responses(Operation::Batch, true, false).contains_key("412"));
    assert!(super::problem_responses(Operation::Patch, false, false).contains_key("412"));
    let example = super::problem_example(
        "403",
        "write.outside-boundary",
        "The write falls outside what the selected access profile may write: its row boundary or a disclosure condition.",
    );
    assert_eq!(example["title"], "Forbidden");
}

#[test]
fn write_outside_boundary_problem_is_exact_and_does_not_narrow_located_problems() {
    let schema = inline_validator(&super::problem_schema());
    let boundary = crate::problem::ProblemCode::WriteOutsideBoundary;
    let exact = json!({
        "type": boundary.type_uri(),
        "title": boundary.title(),
        "status": boundary.status(),
        "detail": boundary.description(),
        "code": boundary.code(),
        "traceId": "11111111111111111111111111111111"
    });
    assert_valid(&schema, &exact);

    for (member, value) in [
        ("fieldPath", json!("/data/jurisdiction")),
        ("refusalCode", json!("outside-boundary")),
        ("guardReason", json!("outside-boundary")),
        ("reasonCode", json!("disclosure-risk")),
        ("recordType", json!("contact")),
        ("fieldId", json!("jurisdiction")),
        ("constraintId", json!("row-boundary")),
        ("constraintKind", json!("vocabulary")),
        ("left", json!("jurisdiction")),
        ("right", json!("selected-jurisdiction")),
        ("field", json!("jurisdiction")),
    ] {
        let mut extended = exact.clone();
        extended[member] = value;
        assert_invalid(&schema, &extended);
    }

    for (member, value) in [
        (
            "type",
            json!(crate::problem::ProblemCode::PreconditionFailed.type_uri()),
        ),
        ("title", json!("Precondition Failed")),
        ("status", json!(412)),
        ("detail", json!("The mutation precondition failed.")),
    ] {
        let mut altered = exact.clone();
        altered[member] = value;
        assert_invalid(&schema, &altered);
    }

    let query = crate::problem::ProblemCode::QueryInvalid;
    let located_query = json!({
        "type": query.type_uri(),
        "title": query.title(),
        "status": query.status(),
        "detail": query.description(),
        "code": query.code(),
        "traceId": "22222222222222222222222222222222",
        "fieldPath": "$filter"
    });
    assert_valid(&schema, &located_query);
}

#[test]
fn change_context_request_schema_rejects_present_empty_text() {
    let schema = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&super::change_context_request_schema())
        .expect("generated ChangeContext request schema compiles");
    assert!(schema
        .validate(&json!({"reasonText": "why", "sourceReferences": ["case-1"]}))
        .is_ok());
    assert!(schema.validate(&json!({"reasonText": ""})).is_err());
    assert!(schema.validate(&json!({"sourceReferences": [""]})).is_err());
}

#[test]
fn served_field_projection_keeps_response_data_strict_but_subsettable() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let schema = response_validator(
        &openapi,
        route_path(&registry, "contact", Operation::Get),
        "get",
        "200",
    );
    let mut record = json!({"data":{"recordIdentifier":"00000000-0000-4000-8000-000000000001", "revisionIdentifier":"1", "domainData":{"name":"Example"}}, "meta":{"registryIdentifier":"local-directory", "datasetIdentifier":"directory", "recordTypeIdentifier":"contact"}});
    assert_valid(&schema, &record);
    record["data"]["domainData"]["undeclared"] = json!("refused");
    assert_invalid(&schema, &record);
    record["data"]["domainData"]
        .as_object_mut()
        .unwrap()
        .remove("undeclared");
    record["data"]["request"] = json!({"bregState":"submitted"});
    assert_invalid(&schema, &record);
}

#[test]
fn record_response_schema_uses_only_record_type_identifier_in_meta() {
    let registry = compiled_registry();
    let openapi = generated_openapi(&registry);
    let schema = response_validator(
        &openapi,
        route_path(&registry, "contact", Operation::Get),
        "get",
        "200",
    );
    let canonical = json!({
        "data": {
            "recordIdentifier": "00000000-0000-4000-8000-000000000001",
            "revisionIdentifier": "1",
            "domainData": {"name": "Example"}
        },
        "meta": {
            "registryIdentifier": "local-directory",
            "datasetIdentifier": "directory",
            "recordTypeIdentifier": "contact"
        }
    });
    assert_valid(&schema, &canonical);

    let retired: Value = serde_json::from_str(include_str!(
        "../../../../products/registry-record/fixtures/negative/retired-record-type-member.json"
    ))
    .expect("retired fixture parses");
    assert_invalid(&schema, &retired);
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
                    "recordType": "household",
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
                    "recordType": "person",
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
                    "recordType": "household",
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
                    "recordType": "person",
                    "recordId": "00000000-0000-4000-8000-000000000201",
                    "revision": 1
                },
                "membership": {
                    "recordType": "group-membership",
                    "recordId": "00000000-0000-4000-8000-000000000202",
                    "revision": 1
                },
                "household": {
                    "recordType": "household",
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
                    "recordType": "person",
                    "recordId": "00000000-0000-4000-8000-000000000201",
                    "revision": 1
                },
                "household": {
                    "recordType": "household",
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
                    "recordType": "asset",
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
                    "recordType": "asset",
                    "recordId": "00000000-0000-4000-8000-000000000301",
                    "revision": 1
                },
                "initial-inspection": {
                    "recordType": "inspection",
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
            "recordType": "household",
            "operation": "patch"
        }])
    );
    assert_eq!(metadata["inputMode"], "fixed");
    assert!(metadata["maximumInputStringBytes"].is_null());
    assert!(metadata["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|input| input["nullable"] == false));
    let operation = super::openapi_action_operation(
        route,
        action,
        registry.entities(),
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
fn action_metadata_execution_names_review_and_application_only_for_proposals() {
    let facility = compiled_facility_registry();
    let minimal = compiled_registry();
    for (registry, action_id, execution) in [
        (
            &facility,
            "correct-address",
            json!({"mode": "proposal", "review": "required", "application": "automatic"}),
        ),
        (
            &facility,
            "deactivate-facility",
            json!({"mode": "proposal", "review": "none", "application": "manual"}),
        ),
        (
            &minimal,
            "register-contact",
            json!({"mode": "proposal", "review": "none", "application": "automatic"}),
        ),
        (&facility, "register-facility", json!({"mode": "immediate"})),
        (
            &minimal,
            "update-contact-email",
            json!({"mode": "immediate"}),
        ),
    ] {
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == action_id)
            .expect("compiled action exists");
        let profiles = super::action_profile_ids(action);
        for selected_profile in [None, profiles.first().map(String::as_str)] {
            let metadata = super::public_action_metadata_entry(action, selected_profile);
            assert_eq!(metadata["execution"], execution, "{action_id}");
        }
    }
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

fn compiled_registry() -> CompiledRegistry {
    let project = crate::contract::parse_project_yaml(include_bytes!(
        "../../../../products/breg/examples/minimal/registry.yaml"
    ))
    .unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

fn compiled_facility_registry() -> CompiledRegistry {
    let project = crate::contract::parse_project_yaml(include_bytes!(
        "../../../../products/breg/examples/facility/registry.yaml"
    ))
    .unwrap();
    crate::compiler::compile_project_with_assets(
        &project,
        &[],
        &[crate::contract::ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../../products/breg/examples/facility/plans/correct-address.rhai"
            )
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn compiled_action_registry() -> CompiledRegistry {
    let project = parse_project_json(
        br#"{
  "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
  "kind": "BRegProject",
  "project": {
    "id": "action-openapi",
    "version": "1",
    "defaultLanguage": "en",
    "canonicalBaseIri": "https://action-openapi.example.test"
  },
  "actions": {
    "register-household-contact": {
      "inputs": [
        {
          "id": "household",
          "apiName": "householdId",
          "type": "reference",
          "target": "household",
          "required": true,
          "classification": "restricted"
        },
        {
          "id": "person-code",
          "apiName": "personCode",
          "type": "string",
          "maximumLength": 64,
          "required": true,
          "classification": "restricted"
        },
        {
          "id": "legal-name",
          "apiName": "legalName",
          "type": "string",
          "maximumLength": 160,
          "required": true,
          "classification": "restricted"
        }
      ],
      "execution": {
        "mode": "immediate"
      },
      "plan": {
        "type": "fixed",
        "effects": [
          {
            "id": "person",
            "target": {
              "recordType": "person"
            },
            "operation": "create",
            "set": {
              "person-code": {
                "fromInput": "person-code"
              },
              "legal-name": {
                "fromInput": "legal-name"
              }
            }
          },
          {
            "id": "membership",
            "target": {
              "recordType": "group-membership"
            },
            "operation": "create",
            "set": {
              "person": {
                "fromEffect": "person"
              },
              "household": {
                "fromInput": "household"
              }
            }
          },
          {
            "id": "household",
            "target": {
              "fromInput": "household"
            },
            "operation": "patch",
            "set": {
              "contact-person": {
                "fromEffect": "person"
              }
            }
          }
        ]
      }
    }
  },
  "accessProfiles": {
    "contact-registrar": {
      "default": true,
      "principalClaim": "private_claim_name",
      "requiredScopes": [
        "registry:contact:register"
      ],
      "requiredPurposes": [
        "contact-registration"
      ],
      "permissions": {
        "actions": [
          {
            "action": "register-household-contact",
            "operations": [
              "invoke"
            ],
            "targets": [
              {
                "rowBoundaries": "unrestricted",
                "recordType": "household"
              },
              {
                "rowBoundaries": "unrestricted",
                "recordType": "person"
              },
              {
                "rowBoundaries": "unrestricted",
                "recordType": "group-membership"
              }
            ],
            "results": [
              "person",
              "membership",
              "household"
            ]
          }
        ]
      }
    },
    "contact-auditor": {
      "principalClaim": "other_private_claim",
      "requiredScopes": [
        "registry:contact:audit"
      ],
      "requiredPurposes": [
        "contact-audit"
      ],
      "permissions": {
        "actions": [
          {
            "action": "register-household-contact",
            "operations": [
              "invoke"
            ],
            "targets": [
              {
                "rowBoundaries": "unrestricted",
                "recordType": "household"
              },
              {
                "rowBoundaries": "unrestricted",
                "recordType": "person"
              },
              {
                "rowBoundaries": "unrestricted",
                "recordType": "group-membership"
              }
            ],
            "results": [
              "household"
            ]
          }
        ]
      }
    }
  },
  "recordTypes": {
    "household": {
      "primaryDataset": "test-dataset",
      "route": "households",
      "mutationMode": "mutable",
      "fields": [
        {
          "id": "household-code",
          "apiName": "householdCode",
          "type": "string",
          "maximumLength": 64,
          "required": true,
          "classification": "internal"
        },
        {
          "id": "contact-person",
          "apiName": "contactPerson",
          "type": "reference",
          "target": "person",
          "classification": "restricted"
        }
      ]
    },
    "person": {
      "primaryDataset": "test-dataset",
      "route": "people",
      "mutationMode": "mutable",
      "fields": [
        {
          "id": "person-code",
          "apiName": "personCode",
          "type": "string",
          "maximumLength": 64,
          "required": true,
          "classification": "restricted"
        },
        {
          "id": "legal-name",
          "apiName": "legalName",
          "type": "string",
          "maximumLength": 160,
          "required": true,
          "classification": "restricted"
        }
      ]
    },
    "group-membership": {
      "primaryDataset": "test-dataset",
      "route": "group-memberships",
      "mutationMode": "create-only",
      "fields": [
        {
          "id": "person",
          "type": "reference",
          "target": "person",
          "required": true,
          "classification": "restricted"
        },
        {
          "id": "household",
          "type": "reference",
          "target": "household",
          "required": true,
          "classification": "restricted"
        }
      ]
    }
  },
  "datasets": {"test-dataset": {}}
}"#,
    )
    .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

fn compiled_asset_result_action_registry() -> CompiledRegistry {
    let project = parse_project_json(
        br#"{
  "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
  "kind": "BRegProject",
  "project": {
    "id": "asset-action-openapi",
    "version": "1",
    "defaultLanguage": "en",
    "canonicalBaseIri": "https://asset-action-openapi.example.test"
  },
  "actions": {
    "register-asset": {
      "inputs": [
        {
          "id": "asset-code",
          "apiName": "assetCode",
          "type": "string",
          "maximumLength": 64,
          "required": true,
          "classification": "internal"
        }
      ],
      "execution": {
        "mode": "immediate"
      },
      "plan": {
        "type": "fixed",
        "effects": [
          {
            "id": "asset",
            "target": {
              "recordType": "asset"
            },
            "operation": "create",
            "set": {
              "asset-code": {
                "fromInput": "asset-code"
              }
            }
          },
          {
            "id": "initial-inspection",
            "target": {
              "recordType": "inspection"
            },
            "operation": "create",
            "set": {
              "asset": {
                "fromEffect": "asset"
              }
            }
          }
        ]
      }
    }
  },
  "accessProfiles": {
    "asset-registrar": {
      "default": true,
      "principalClaim": "principal",
      "requiredScopes": [
        "registry:asset:register"
      ],
      "permissions": {
        "actions": [
          {
            "action": "register-asset",
            "operations": [
              "invoke"
            ],
            "targets": [
              {
                "rowBoundaries": "unrestricted",
                "recordType": "asset"
              },
              {
                "rowBoundaries": "unrestricted",
                "recordType": "inspection"
              }
            ],
            "results": [
              "asset"
            ]
          }
        ]
      }
    }
  },
  "recordTypes": {
    "asset": {
      "primaryDataset": "test-dataset",
      "route": "assets",
      "mutationMode": "create-only",
      "fields": [
        {
          "id": "asset-code",
          "apiName": "assetCode",
          "type": "string",
          "maximumLength": 64,
          "required": true,
          "classification": "internal"
        }
      ]
    },
    "inspection": {
      "primaryDataset": "test-dataset",
      "route": "inspections",
      "mutationMode": "create-only",
      "fields": [
        {
          "id": "asset",
          "type": "reference",
          "target": "asset",
          "required": true,
          "classification": "internal"
        }
      ]
    }
  },
  "datasets": {"test-dataset": {}}
}"#,
    )
    .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

#[test]
fn a_caller_document_declares_the_workflow_write_refusal_only_to_a_bound_writer() {
    let registry = compiled_bound_writer_registry();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "set-person-phone")
        .expect("compiled action exists");
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.id == "actions.set-person-phone.invoke")
        .expect("compiled invoke route exists");
    for (profile, declared) in [("registrar", true), ("officer", false)] {
        let operation = super::openapi_action_operation(
            route,
            action,
            registry.entities(),
            super::OpenApiAccessProfiles::Selected(profile),
        );
        assert_eq!(
            operation["responses"]["403"].is_object(),
            declared,
            "{profile} invoke"
        );
        let visible = BTreeSet::from([(
            "propose-person-phone".to_owned(),
            profile.to_owned(),
            crate::model::ProposalOperation::Apply,
        )]);
        let mut paths = serde_json::Map::new();
        super::append_proposal_openapi(
            &mut paths,
            registry.actions(),
            registry.entities(),
            Some(&visible),
        );
        assert_eq!(
            paths["/v1/proposals/{proposal_id}/apply"]["post"]["responses"]["403"].is_object(),
            declared,
            "{profile} apply"
        );
    }
}

/// `registrar` and `officer` both set the phone number through an immediate
/// Action and apply a manual Proposal that sets it. A condition withholds the
/// number of a protected person from every profile but `officer`.
fn compiled_bound_writer_registry() -> CompiledRegistry {
    let inputs = json!([
        {"id": "person", "apiName": "personId", "type": "reference", "target": "person",
         "required": true, "classification": "internal"},
        {"id": "phone", "apiName": "phone", "type": "string", "maximumLength": 32,
         "required": true, "classification": "internal"}]);
    let plan = json!({"type": "fixed", "effects": [
        {"id": "contact", "target": {"fromInput": "person"}, "operation": "patch",
         "set": {"phone": {"fromInput": "phone"}}}]});
    let targets = json!([{"recordType": "person", "rowBoundaries": "unrestricted"}]);
    let profile = |id: &str, default: bool| {
        json!({"default": default, "principalClaim": "registry_principal",
            "requiredScopes": [format!("registry.{id}")],
            "permissions": {
                "records": [{"recordType": "person", "operations": ["get", "list"],
                    "rowBoundaries": "unrestricted",
                    "readableFields": ["family-name", "protected", "phone"]}],
                "actions": [
                    {"action": "set-person-phone", "operations": ["invoke"], "targets": targets},
                    {"action": "propose-person-phone", "operations": ["start"], "targets": targets}],
                "proposals": [{"action": "propose-person-phone", "ownership": "caller",
                    "operations": ["get", "list", "edit", "submit", "cancel", "apply"],
                    "targets": targets}]}})
    };
    let source = json!({"datasets": {"test-dataset": {}},
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1", "kind": "BRegProject",
        "project": {"id": "bound-writer", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://bound-writer.example.test"},
        "recordTypes": {"person": {"primaryDataset": "test-dataset", "route": "people",
            "mutationMode": "mutable", "classification": "internal",
            "fields": [
                {"id": "family-name", "type": "string", "maximumLength": 64, "classification": "internal"},
                {"id": "protected", "type": "boolean", "classification": "internal"},
                {"id": "phone", "type": "string", "maximumLength": 32, "classification": "internal"}],
            "disclosureConditions": {"hide-phone": {"when": [{"type": "field-equals", "field": "protected", "value": true}],
                "withhold": "fields", "fields": ["phone"], "exemptProfiles": ["officer"]}}}},
        "actions": {
            "set-person-phone": {"inputs": inputs, "plan": plan,
             "execution": {"mode": "immediate"}},
            "propose-person-phone": {"inputs": inputs, "plan": plan,
             "commitGuards": {"targets": [{"input": "person", "revision": "unchanged"}]},
             "execution": {"mode": "proposal", "proposal": {"review": {"type": "none"},
                 "application": {"mode": "manual"}, "retention": {"mode": "operator-erase"}}}}},
        "accessProfiles": {"registrar": profile("registrar", true), "officer": profile("officer", false)}
    });
    let project =
        parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

#[test]
fn a_caller_document_declares_a_record_condition_write_refusal_to_a_bound_writer() {
    for effect in ["patch", "create"] {
        let registry = compiled_record_condition_writer_registry(effect);
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == "write-person")
            .expect("compiled action exists");
        let route = registry
            .actions()
            .routes
            .iter()
            .find(|route| route.id == "actions.write-person.invoke")
            .expect("compiled invoke route exists");
        for (profile, declared) in [("registrar", true), ("officer", false)] {
            let operation = super::openapi_action_operation(
                route,
                action,
                registry.entities(),
                super::OpenApiAccessProfiles::Selected(profile),
            );
            assert_eq!(
                operation["responses"]["403"].is_object(),
                declared,
                "{profile} invoke of a {effect}"
            );
            let visible = BTreeSet::from([(
                "propose-person".to_owned(),
                profile.to_owned(),
                crate::model::ProposalOperation::Apply,
            )]);
            let mut paths = serde_json::Map::new();
            super::append_proposal_openapi(
                &mut paths,
                registry.actions(),
                registry.entities(),
                Some(&visible),
            );
            assert_eq!(
                paths["/v1/proposals/{proposal_id}/apply"]["post"]["responses"]["403"].is_object(),
                declared,
                "{profile} apply of a {effect}"
            );
        }
    }
}

/// `registrar` and `officer` both write a person through an immediate Action
/// and apply a manual Proposal whose plan runs one `effect`, `patch` or
/// `create`. A `record` condition withholds a protected person from every
/// profile but `officer`.
fn compiled_record_condition_writer_registry(effect: &str) -> CompiledRegistry {
    let phone = json!({"id": "phone", "apiName": "phone", "type": "string",
        "maximumLength": 32, "required": true, "classification": "internal"});
    let targets = json!([{"recordType": "person", "rowBoundaries": "unrestricted"}]);
    let (inputs, plan, commit_guards) = if effect == "patch" {
        (
            json!([{"id": "person", "apiName": "personId", "type": "reference",
                "target": "person", "required": true, "classification": "internal"}, phone]),
            json!({"type": "fixed", "effects": [
                {"id": "contact", "target": {"fromInput": "person"}, "operation": "patch",
                 "set": {"phone": {"fromInput": "phone"}}}]}),
            json!({"targets": [{"input": "person", "revision": "unchanged"}]}),
        )
    } else {
        (
            json!([phone]),
            json!({"type": "fixed", "effects": [
                {"id": "contact", "target": {"recordType": "person"}, "operation": "create",
                 "set": {"phone": {"fromInput": "phone"}}}]}),
            json!({}),
        )
    };
    let profile = |id: &str, default: bool| {
        json!({"default": default, "principalClaim": "registry_principal",
            "requiredScopes": [format!("registry.{id}")],
            "permissions": {
                "records": [{"recordType": "person", "operations": ["get", "list"],
                    "rowBoundaries": "unrestricted",
                    "readableFields": ["family-name", "protected", "phone"]}],
                "actions": [
                    {"action": "write-person", "operations": ["invoke"], "targets": targets},
                    {"action": "propose-person", "operations": ["start"], "targets": targets}],
                "proposals": [{"action": "propose-person", "ownership": "caller",
                    "operations": ["get", "list", "edit", "submit", "cancel", "apply"],
                    "targets": targets}]}})
    };
    let source = json!({"datasets": {"test-dataset": {}},
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1", "kind": "BRegProject",
        "project": {"id": "record-condition-writer", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://record-condition-writer.example.test"},
        "recordTypes": {"person": {"primaryDataset": "test-dataset", "route": "people",
            "mutationMode": "mutable", "classification": "internal",
            "fields": [
                {"id": "family-name", "type": "string", "maximumLength": 64, "classification": "internal"},
                {"id": "protected", "type": "boolean", "classification": "internal"},
                {"id": "phone", "type": "string", "maximumLength": 32, "classification": "internal"}],
            "disclosureConditions": {"hide-protected": {"when": [{"type": "field-equals", "field": "protected", "value": true}],
                "withhold": "record", "exemptProfiles": ["officer"]}}}},
        "actions": {
            "write-person": {"inputs": inputs, "plan": plan,
             "execution": {"mode": "immediate"}},
            "propose-person": {"inputs": inputs, "plan": plan,
             "commitGuards": commit_guards,
             "execution": {"mode": "proposal", "proposal": {"review": {"type": "none"},
                 "application": {"mode": "manual"}, "retention": {"mode": "operator-erase"}}}}},
        "accessProfiles": {"registrar": profile("registrar", true), "officer": profile("officer", false)}
    });
    let project =
        parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}

#[test]
fn the_required_filter_refusal_is_documented_only_where_a_profile_requires_a_filter() {
    let declares = |responses: &Value| {
        responses["400"]["content"]["application/problem+json"]["examples"]
            .get("query.filter_required")
            .is_some()
    };
    let static_list = |registry: &CompiledRegistry| {
        let openapi: Value = serde_json::from_slice(
            &registry
                .artifacts()
                .get("generated/openapi.json")
                .expect("OpenAPI is generated")
                .bytes,
        )
        .unwrap();
        openapi["paths"]["/v1/records/people"]["get"]["responses"].clone()
    };

    let registry = compiled_required_filter_registry(true);
    assert!(declares(&static_list(&registry)));
    let route = registry
        .routes()
        .routes
        .iter()
        .find(|route| route.entity_id == "person" && route.operation == Operation::List)
        .expect("compiled list route exists");
    let entity = &registry.entities()["person"];
    for (profile, declared) in [("registrar", true), ("clerk", false)] {
        let operation = super::openapi_operation(super::OpenApiOperationSpec {
            registry_identifier: registry.registry_id(),
            route,
            entity,
            response_entity: entity,
            query: registry.queries(),
            schema_ref: "person",
            request_schema_ref: "person",
            readable_fields: None,
            access_profiles: super::OpenApiAccessProfiles::Selected(profile),
        });
        assert_eq!(declares(&operation["responses"]), declared, "{profile}");
    }

    assert!(!declares(&static_list(&compiled_required_filter_registry(
        false
    ))));
}

/// `registrar` and `clerk` both list `person`. With `required`, the registrar
/// must filter its list by the national identifier.
fn compiled_required_filter_registry(required: bool) -> CompiledRegistry {
    let grant = json!({"recordType": "person", "operations": ["get", "list"],
        "rowBoundaries": "unrestricted", "readableFields": ["national-id", "family-name"],
        "filterableFields": ["national-id"]});
    let mut registrar = grant.clone();
    if required {
        registrar["requiredFilters"] = json!([{"fields": ["national-id"]}]);
    }
    let source = json!({"datasets": {"test-dataset": {}},
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1", "kind": "BRegProject",
        "project": {"id": "required-filter", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://required-filter.example.test"},
        "recordTypes": {"person": {"primaryDataset": "test-dataset", "route": "people",
            "mutationMode": "mutable", "classification": "internal",
            "fields": [
                {"id": "national-id", "type": "string", "maximumLength": 32, "classification": "internal"},
                {"id": "family-name", "type": "string", "maximumLength": 64, "classification": "internal"}]}},
        "accessProfiles": {
            "registrar": {"default": true, "principalClaim": "registry_principal",
             "requiredScopes": ["registry.registrar"], "permissions": {"records": [registrar]}},
            "clerk": {"principalClaim": "registry_principal",
             "requiredScopes": ["registry.clerk"], "permissions": {"records": [grant]}}}
    });
    let project =
        parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
