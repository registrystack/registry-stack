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
        assert!(super::problem_responses(operation, true).contains_key("403"));
        assert!(!super::problem_responses(operation, false).contains_key("403"));
    }
    assert!(!super::problem_responses(Operation::Create, true).contains_key("412"));
    assert!(super::problem_responses(Operation::Batch, true).contains_key("412"));
    assert!(super::problem_responses(Operation::Patch, false).contains_key("412"));
    let example = super::problem_example(
        "403",
        "write.outside-boundary",
        "The resulting record falls outside the selected access profile's row boundary.",
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

    let mut retired = canonical;
    let meta = retired["meta"]
        .as_object_mut()
        .expect("record meta is an object");
    let record_type = meta
        .remove("recordTypeIdentifier")
        .expect("canonical record type exists");
    meta.insert("entityTypeIdentifier".to_owned(), record_type);
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
  "actions": [
    {
      "id": "register-household-contact",
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
  ],
  "accessProfiles": [
    {
      "id": "contact-registrar",
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
    {
      "id": "contact-auditor",
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
  ],
  "recordTypes": [
    {
      "id": "household",
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
    {
      "id": "person",
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
    {
      "id": "group-membership",
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
  ],
  "datasets": [
    {
      "id": "test-dataset"
    }
  ]
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
  "actions": [
    {
      "id": "register-asset",
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
  ],
  "accessProfiles": [
    {
      "id": "asset-registrar",
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
  ],
  "recordTypes": [
    {
      "id": "asset",
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
    {
      "id": "inspection",
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
  ],
  "datasets": [
    {
      "id": "test-dataset"
    }
  ]
}"#,
    )
    .expect("fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
