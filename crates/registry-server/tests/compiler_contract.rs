// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use registry_manifest_core::{compile_manifest, AccessRights, FieldType, MetadataManifest};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_server::artifacts::REGISTRY_METADATA_ARTIFACT_PATH;
use registry_server::compiler::{
    compile_project, compile_project_with_assets, module_digest, module_digest_with_assets,
    CompileProfile,
};
use registry_server::contract::{
    parse_module_json, parse_module_yaml, parse_project_json, parse_project_yaml,
    AccessGrantSource, BoundaryOperator, Classification, ComparisonOperator, ConstraintSource,
    FieldTypeSource, ModuleAssetSource, Operation, PackageIdentitySource,
    ProjectAccessProfileSource, ReferenceDelete, RegistryModule, RowBoundarySource,
    UniqueWhenPredicate,
};
use registry_server::diagnostics::CompileFailure;
use registry_server::generated_ddl::DdlStatementKind;
use registry_server::model::{
    ChangeRequestOperation, CompiledChangeRequestMutation, CompiledChangeRequestTargetBinding,
    CompiledChangeRequestValue, CompiledMetadataInventory, CompiledQueryFilterOperator,
    CompiledQueryKind, CompiledQuerySortDirection, CompiledQueryTemporalSemantics,
    CompiledRevisionKind, HttpMethod, MAX_REVISION_HISTORY_RECORDS,
    REQUEST_EFFECT_DIGEST_QUERY_FIELD, REQUEST_PROPOSAL_VERSION_QUERY_FIELD,
    REQUEST_SERVER_STATE_QUERY_FIELD,
};
use serde_json::{json, Value};

fn asset_project() -> registry_server::contract::RegistryProject {
    acceptance_project("asset-site-placement")
}

fn asset_modules() -> Vec<RegistryModule> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/asset-site-placement/modules")
        .join("asset-site-placement-core/module.yaml");
    let bytes = fs::read(path).expect("committed acceptance module is readable");
    vec![parse_module_yaml(&bytes).expect("acceptance module follows the authoring contract")]
}

fn acceptance_project(domain: &str) -> registry_server::contract::RegistryProject {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance")
        .join(domain)
        .join("registry.yaml");
    let bytes = fs::read(path).expect("committed acceptance fixture is readable");
    parse_project_yaml(&bytes).expect("acceptance fixture follows the authoring contract")
}

fn compile_json(source: &[u8]) -> Result<registry_server::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(source).expect("source shape parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn compile_json_with_assets(
    source: &[u8],
    assets: Vec<ModuleAssetSource>,
) -> Result<registry_server::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(source).expect("source shape parses");
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
}

fn derived_sql_asset(path: &str, sql: &str) -> ModuleAssetSource {
    ModuleAssetSource {
        module: None,
        path: path.to_owned(),
        bytes: sql.as_bytes().to_vec(),
    }
}

fn add_retention_mode(mut source: Vec<u8>, mode: &str) -> Vec<u8> {
    let text = String::from_utf8(source).expect("fixture is UTF-8");
    source = text
        .replacen(
            r#""changeRequest":{"#,
            &format!(r#""changeRequest":{{"retention":{{"mode":"{mode}"}},"#),
            1,
        )
        .into_bytes();
    source
}

#[allow(clippy::too_many_arguments)]
fn change_request_correction_project(
    registry_id: &str,
    package_entry: &str,
    extra_entity: &str,
    request_reason_classification: &str,
    target_label_classification: &str,
    review_boundaries: &str,
    apply_boundaries: &str,
    reviewer_scopes: &str,
) -> Vec<u8> {
    let extra_entity = if extra_entity.is_empty() {
        String::new()
    } else {
        format!(",{}", extra_entity)
    };
    format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"{registry_id}","version":"1","defaultLanguage":"en"}}{package_entry},
          "entities":[{{
            "id":"site","route":"sites","mutationMode":"create_only",
            "fields":[{{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}}]
          }},{{
            "id":"placement","route":"placements","mutationMode":"mutable",
            "changeControl":{{"requiredFor":["patch"]}},
            "fields":[
              {{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}},
              {{"id":"label","type":"string","maxLength":64,"classification":"{target_label_classification}"}}
            ]
          }},{{
            "id":"placement-correction-request","route":"placement-correction-requests","mutationMode":"mutable",
            "fields":[
              {{"id":"placement","type":"reference","target":"placement","required":true,"classification":"internal"}},
              {{"id":"proposed-site","type":"reference","target":"site","required":true,"classification":"internal"}},
              {{"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"{request_reason_classification}"}}
            ],
            "changeRequest":{{
              "effects":[{{
                "target":{{"fromField":"placement"}},
                "operation":"patch",
                "set":{{"site":{{"fromField":"proposed-site"}}}},
                "clear":["label"]
              }}],
              "review":{{"stages":[{{"id":"review","approvals":1,"excludeSubmitter":true}}]}}
            }}
          }}{extra_entity}],
          "accessProfiles":[{{
            "id":"placement-reader","principalClaim":"principal","grants":[{{
              "entity":"placement","operations":["get","list"],"readableFields":["site","label"],
              "requestPresence":[{{"requestType":"placement-correction-request"}}]
            }}]
          }},{{
            "id":"request-reviewer","default":true,"principalClaim":"principal","requiredScopes":{reviewer_scopes},"grants":[{{
              "entity":"placement-correction-request","operations":["get","list","submit_request","approve_request","reject_request","request_revision"],"readableFields":["placement","proposed-site","reason"],
              "reviewStages":[{{"stage":"review","targets":[{{"entity":"placement","readableFields":["site","label"],"rowBoundaries":{review_boundaries}}}]}}]
            }}]
          }},{{
            "id":"request-applier","principalClaim":"principal","grants":[{{
              "entity":"placement-correction-request","operations":["get","apply_request"],"readableFields":["placement"],
              "applyTargets":[{{"entity":"placement","rowBoundaries":{apply_boundaries}}}]
            }}]
          }}]
        }}"#
    )
    .into_bytes()
}

#[test]
fn anonymous_request_presence_processes_only_public_existence_and_linkage() {
    let bytes = change_request_correction_project(
        "public-request-presence",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[]",
        "[]",
    );
    let mut project: Value = serde_json::from_slice(&bytes).unwrap();
    for entity in project["entities"].as_array_mut().unwrap() {
        entity["classification"] = json!("public");
        for field in entity["fields"].as_array_mut().unwrap() {
            field["classification"] = json!("public");
        }
    }
    // Presence does not process the proposed value or the request's reason.
    project["entities"][2]["fields"][1]["classification"] = json!("internal");
    project["entities"][2]["fields"][2]["classification"] = json!("restricted");
    let reader = project["accessProfiles"][0].as_object_mut().unwrap();
    reader.remove("principalClaim");
    reader.insert("anonymous".to_owned(), json!(true));
    project["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id":"request-public", "anonymous":true,
        "grants":[{"entity":"placement-correction-request","operations":["get","list"],"readableFields":["placement"]}]
    }));
    let registry = compile_json(&serde_json::to_vec(&project).unwrap())
        .expect("public existence and linkage may be disclosed without private intake detail");
    let public_queue = registry
        .queries()
        .operations
        .iter()
        .find(|operation| {
            operation.profile_id == "request-public" && operation.kind == CompiledQueryKind::List
        })
        .expect("anonymous polling remains available");
    assert!(public_queue
        .filter_fields
        .iter()
        .any(|field| field.field == REQUEST_SERVER_STATE_QUERY_FIELD));
    assert!(public_queue
        .filter_fields
        .iter()
        .any(|field| field.field == REQUEST_PROPOSAL_VERSION_QUERY_FIELD));
    assert!(!public_queue
        .filter_fields
        .iter()
        .any(|field| field.field == REQUEST_EFFECT_DIGEST_QUERY_FIELD));
    assert!(!public_queue
        .sort_fields
        .iter()
        .any(|field| field.field == REQUEST_EFFECT_DIGEST_QUERY_FIELD));

    let mut private_type = project.clone();
    private_type["entities"][2]["classification"] = json!("internal");
    let mut private_link = project.clone();
    private_link["entities"][2]["fields"][0]["classification"] = json!("restricted");
    for mut invalid in [private_type, private_link] {
        // Exercise the separate presence grant without an ordinary request
        // GET grant failing its own public-field validation first.
        invalid["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .retain(|profile| profile["id"] != "request-public");
        let failure = compile_json(&serde_json::to_vec(&invalid).unwrap())
            .expect_err("an existence-only response still processes classified request linkage");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "change_request.presence.anonymous_non_public"
        }));
    }

    project["accessProfiles"][0]["grants"][0]["requestPresence"][0]["rowBoundaries"] =
        json!([{"field":"placement","claim":"placement","operator":"equals"}]);
    let failure = compile_json(&serde_json::to_vec(&project).unwrap())
        .expect_err("an anonymous presence grant cannot acquire verified claim authority");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "change_request.presence.anonymous_claim_boundary"
    }));
}

#[test]
fn change_request_correction_compiles_to_immutable_plan_and_scoped_grants() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-correction","version":"1","defaultLanguage":"en"},
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
              {"id":"proposed-site","type":"reference","target":"site","required":true,"classification":"internal"},
              {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
            ],
            "changeRequest":{
              "effects":[{
                "target":{"fromField":"placement"},
                "operation":"patch",
                "set":{"site":{"fromField":"proposed-site"}},
                "clear":["label"]
              }],
              "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
            }
          }],
          "accessProfiles":[{
            "id":"placement-reader","principalClaim":"principal","grants":[{
              "entity":"placement","operations":["get","list"],"readableFields":["site","label"],
              "requestPresence":[{"requestType":"placement-correction-request"}]
            }]
          },{
            "id":"request-reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"placement-correction-request","operations":["get","list","submit_request","approve_request","reject_request","request_revision"],"readableFields":["placement","proposed-site","reason"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"placement","readableFields":["site","label"],"rowBoundaries":[]}]}]
            }]
          },{
            "id":"request-applier","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request","operations":["get","apply_request"],"readableFields":["placement"],
              "applyTargets":[{"entity":"placement","rowBoundaries":[]}]
            }]
          }]
        }"#,
    )
    .expect("typed correction request compiles");

    let request = compiled.entities()["placement-correction-request"]
        .change_request
        .as_ref()
        .expect("request plan is compiled");
    assert_eq!(request.effects.len(), 1);
    assert!(request.contract_fingerprint.starts_with("sha256:"));
    assert_eq!(
        request.target_entities,
        BTreeSet::from(["placement".to_owned()])
    );
    assert_eq!(request.maximum_targets, 16);
    assert_eq!(request.maximum_field_mutations, 128);
    assert_eq!(request.maximum_snapshot_bytes, 2_097_152);
    assert!(request.actions.iter().any(|action| {
        action.operation == ChangeRequestOperation::ApproveRequest
            && action.review_stage.as_deref() == Some("review")
    }));
    assert!(request.actions.iter().any(|action| {
        action.operation == ChangeRequestOperation::ApplyRequest && action.review_stage.is_none()
    }));
    let effect = &request.effects[0];
    assert!(matches!(
        effect.target.binding,
        CompiledChangeRequestTargetBinding::Existing { ref from_field }
            if from_field == "placement"
    ));
    assert!(effect.mutations.iter().any(|mutation| matches!(
        mutation,
        CompiledChangeRequestMutation::Set {
            field,
            value: CompiledChangeRequestValue::FromField { field: source }
        } if field == "site" && source == "proposed-site"
    )));
    assert!(effect.mutations.iter().any(|mutation| matches!(
        mutation,
        CompiledChangeRequestMutation::Clear { field } if field == "label"
    )));
    assert!(request.review_grants.iter().any(|grant| {
        grant.profile_id == "request-reviewer"
            && grant.stage == "review"
            && grant.target_entity_id == "placement"
            && grant.readable_fields == BTreeSet::from(["site".to_owned(), "label".to_owned()])
    }));
    assert!(request.apply_grants.iter().any(|grant| {
        grant.profile_id == "request-applier" && grant.target_entity_id == "placement"
    }));
    assert!(request.presence_grants.iter().any(|grant| {
        grant.profile_id == "placement-reader" && grant.target_entity_id == "placement"
    }));
}

#[test]
fn change_request_routes_compile_to_finite_action_inventory() {
    let compiled = compile_json(&change_request_correction_project(
        "change-request-routes",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[]",
        "[]",
    ))
    .expect("change-request routes compile");

    let route = |id: &str| {
        compiled
            .routes()
            .routes
            .iter()
            .find(|route| route.id == id)
            .unwrap_or_else(|| panic!("route {id} exists"))
    };
    let submit = route("records.placement-correction-request.request.submit");
    assert_eq!(submit.method, HttpMethod::Post);
    assert_eq!(submit.operation, Operation::SubmitRequest);
    assert_eq!(submit.request_stage, None);
    assert_eq!(
        submit.path,
        "/v1/records/placement-correction-requests/{record_id}/actions/submit"
    );
    assert_eq!(submit.access_profiles, vec!["request-reviewer".to_owned()]);

    let approve = route("records.placement-correction-request.request.stages.review.approve");
    assert_eq!(approve.operation, Operation::ApproveRequest);
    assert_eq!(approve.request_stage.as_deref(), Some("review"));
    assert_eq!(
        approve.path,
        "/v1/records/placement-correction-requests/{record_id}/actions/stages/review/approve"
    );
    assert_eq!(approve.access_profiles, vec!["request-reviewer".to_owned()]);

    let reject = route("records.placement-correction-request.request.stages.review.reject");
    assert_eq!(reject.operation, Operation::RejectRequest);
    assert_eq!(reject.request_stage.as_deref(), Some("review"));

    let revision =
        route("records.placement-correction-request.request.stages.review.request_revision");
    assert_eq!(revision.operation, Operation::RequestRevision);
    assert_eq!(
        revision.path,
        "/v1/records/placement-correction-requests/{record_id}/actions/stages/review/request-revision"
    );

    let apply = route("records.placement-correction-request.request.apply");
    assert_eq!(apply.operation, Operation::ApplyRequest);
    assert_eq!(apply.request_stage, None);
    assert_eq!(apply.access_profiles, vec!["request-applier".to_owned()]);

    let access = compiled
        .access()
        .entries
        .iter()
        .find(|entry| entry.route_id == "records.placement-correction-request.request.apply")
        .expect("apply route has exact access entry");
    assert_eq!(access.operation, Operation::ApplyRequest);
    assert_eq!(
        access.profile_ids,
        BTreeSet::from(["request-applier".to_owned()])
    );
}

#[test]
fn change_request_openapi_exposes_finite_action_contract_and_request_metadata() {
    let compiled = compile_json(
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
              {"id":"proposed-site","type":"reference","target":"site","required":true,"classification":"internal"},
              {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
            ],
            "changeRequest":{
              "effects":[{
                "target":{"fromField":"placement"},
                "operation":"patch",
                "set":{"site":{"fromField":"proposed-site"}},
                "clear":["label"]
              }],
              "review":{"stages":[
                {"id":"review","approvals":1,"excludeSubmitter":true},
                {"id":"final-approval","approvals":1,"excludeSubmitter":true}
              ]}
            }
          }],
          "accessProfiles":[{
            "id":"placement-reader","principalClaim":"principal","grants":[{
              "entity":"placement","operations":["get","list"],"readableFields":["site","label"],
              "requestPresence":[{"requestType":"placement-correction-request"}]
            }]
          },{
            "id":"submitter","default":true,"principalClaim":"principal","grants":[{
              "entity":"placement-correction-request","operations":["create","patch","submit_request","revise_request","cancel_request"],"readableFields":["placement","proposed-site","reason"],"writableFields":["placement","proposed-site","reason"]
            }]
          },{
            "id":"reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"placement-correction-request","operations":["get","list","approve_request","reject_request","request_revision"],"readableFields":["placement","proposed-site","reason"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"placement","readableFields":["site","label"],"rowBoundaries":[]}]}]
            }]
          },{
            "id":"supervisor","principalClaim":"principal","grants":[{
              "entity":"placement-correction-request","operations":["approve_request","reject_request","request_revision"],"readableFields":["placement","proposed-site","reason"],
              "reviewStages":[{"stage":"final-approval","targets":[{"entity":"placement","readableFields":["site","label"],"rowBoundaries":[]}]}]
            }]
          },{
            "id":"applier","default":true,"principalClaim":"principal","grants":[{
              "entity":"placement-correction-request","operations":["apply_request"],"readableFields":["placement"],
              "applyTargets":[{"entity":"placement","rowBoundaries":[]}]
            }]
          }]
        }"#,
    )
    .expect("change request OpenAPI fixture compiles");

    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let value = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    let submit_request = &value["paths"]
        ["/v1/records/placement-correction-requests/{record_id}/actions/submit"]["post"];
    assert_eq!(
        query_parameter_names(&submit_request["parameters"]),
        [
            "Idempotency-Key",
            "If-Match",
            "accessProfile",
            "record_id",
            "traceparent"
        ]
    );
    assert_eq!(
        submit_request["x-registry-requestAction"],
        json!({
            "operation": "submit_request",
            "stage": null,
            "method": "post",
            "path": "/v1/records/placement-correction-requests/{record_id}/actions/submit",
            "requestEntity": "placement-correction-request",
            "requiredPreconditions": ["Idempotency-Key", "If-Match"],
            "inputSchema": "placement-correction-request-submit_request-input",
            "responseSchema": "ChangeRequestActionResponse",
            "proposalBinding": {
                "versionField": "proposalVersion",
                "digestField": "effectDigest",
                "recordPrecondition": "If-Match",
                "idempotencyHeader": "Idempotency-Key"
            },
            "targetEntities": ["placement"]
        })
    );
    assert_eq!(
        submit_request["requestBody"]["content"]["application/json"]["schema"],
        json!({"$ref": "#/components/schemas/placement-correction-request-submit_request-input"})
    );
    assert_eq!(
        submit_request["responses"]["200"]["content"]["application/json"]["schema"],
        json!({"$ref": "#/components/schemas/ChangeRequestActionResponse"})
    );
    assert_eq!(
        submit_request["responses"]["409"]["content"]["application/problem+json"]["examples"]
            ["request.conflict"]["value"]["code"],
        "request.conflict"
    );

    let approve_request = &value["paths"]
        ["/v1/records/placement-correction-requests/{record_id}/actions/stages/review/approve"]
        ["post"];
    assert_eq!(
        approve_request["x-registry-requestAction"]["requiredPreconditions"],
        json!([
            "Idempotency-Key",
            "If-Match",
            "proposalVersion",
            "effectDigest"
        ])
    );
    let approve_input =
        &value["components"]["schemas"]["placement-correction-request-approve_request-input"];
    assert_eq!(approve_input["additionalProperties"], false);
    assert_eq!(
        approve_input["required"],
        json!(["proposalVersion", "effectDigest"])
    );
    assert_eq!(
        approve_input["properties"]["proposalVersion"]["maximum"],
        u32::MAX
    );
    assert_eq!(
        approve_input["properties"]["effectDigest"]["pattern"],
        "^sha256:[0-9a-f]{64}$"
    );
    let revise_input =
        &value["components"]["schemas"]["placement-correction-request-revise_request-input"];
    assert_eq!(revise_input["required"], json!(["rebase"]));
    assert_eq!(revise_input["properties"]["rebase"]["type"], "boolean");
    assert_eq!(
        value["components"]["schemas"]["ChangeRequestActionResponse"]["properties"]["request"]
            ["properties"]["effectDigest"]["pattern"],
        "^sha256:[0-9a-f]{64}$"
    );
    assert_eq!(
        value["components"]["schemas"]["placement"]["x-registry-changeControl"]
            ["directWriteRestriction"],
        "controlled_operations_require_compiled_change_request_application"
    );
    assert_eq!(
        value["components"]["schemas"]["placement-correction-request"]["x-registry-changeRequest"]
            ["bounds"]["maximumTargets"],
        16
    );
    assert_eq!(
        value["components"]["schemas"]["placement-correction-request"]["x-registry-changeRequest"]
            ["stages"][1]["id"],
        "final-approval"
    );
}

#[test]
fn change_request_fingerprint_tracks_relevant_contract_closure_only() {
    let compiled_request = |source: Vec<u8>| {
        let compiled = compile_json(&source).expect("project compiles");
        compiled.entities()["placement-correction-request"]
            .change_request
            .as_ref()
            .expect("request plan exists")
            .clone()
    };
    let base_request = compiled_request(change_request_correction_project(
        "change-request-fingerprint",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[]",
        "[]",
    ));
    let base = base_request.contract_fingerprint;
    assert_eq!(
        base_request.retention_mode,
        registry_server::model::CompiledChangeRequestRetentionMode::Retain
    );
    let unrelated = compiled_request(change_request_correction_project(
        "change-request-fingerprint",
        ",\"package\":{\"environment\":\"local\",\"instanceId\":\"local\",\"sequence\":7,\"sourceRevision\":\"unrelated\"}",
        r#"{"id":"audit-note","route":"audit-notes","mutationMode":"create_only","fields":[{"id":"label","type":"string","maxLength":16,"classification":"internal"}]}"#,
        "internal",
        "internal",
        "[]",
        "[]",
        "[]",
    ))
    .contract_fingerprint;
    assert_eq!(base, unrelated);

    let operator_erase = compiled_request(add_retention_mode(
        change_request_correction_project(
            "change-request-fingerprint",
            "",
            "",
            "internal",
            "internal",
            "[]",
            "[]",
            "[]",
        ),
        "operator_erase",
    ));
    assert_eq!(
        operator_erase.retention_mode,
        registry_server::model::CompiledChangeRequestRetentionMode::OperatorErase
    );
    assert_eq!(
        base, operator_erase.contract_fingerprint,
        "manual retention policy does not reinterpret frozen proposal effects"
    );

    let request_schema_changed = compiled_request(change_request_correction_project(
        "change-request-fingerprint",
        "",
        "",
        "restricted",
        "internal",
        "[]",
        "[]",
        "[]",
    ))
    .contract_fingerprint;
    assert_ne!(base, request_schema_changed);

    let target_schema_changed = compiled_request(change_request_correction_project(
        "change-request-fingerprint",
        "",
        "",
        "internal",
        "restricted",
        "[]",
        "[]",
        "[]",
    ))
    .contract_fingerprint;
    assert_ne!(base, target_schema_changed);

    let review_authority_changed = compiled_request(change_request_correction_project(
        "change-request-fingerprint",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[]",
        "[\"change-review\"]",
    ))
    .contract_fingerprint;
    assert_ne!(base, review_authority_changed);

    let apply_boundary_changed = compiled_request(change_request_correction_project(
        "change-request-fingerprint",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[{\"field\":\"site\",\"claim\":\"site\",\"operator\":\"equals\"}]",
        "[]",
    ))
    .contract_fingerprint;
    assert_ne!(base, apply_boundary_changed);
}

#[test]
fn change_request_retention_mode_is_a_strict_enum() {
    let failure = parse_project_json(&add_retention_mode(
        change_request_correction_project(
            "change-request-retention-enum",
            "",
            "",
            "internal",
            "internal",
            "[]",
            "[]",
            "[]",
        ),
        "ttl",
    ))
    .expect_err("unknown retention mode is refused");

    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.path.contains("changeRequest")));
}

fn correction_with_target_access_requirements() -> serde_json::Value {
    let mut source: serde_json::Value = serde_json::from_slice(&change_request_correction_project(
        "request-target-requirements",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[]",
        "[]",
    ))
    .unwrap();
    let boundary = serde_json::json!({"field":"site","claim":"allowed_sites","operator":"in"});
    source["entities"][1]["accessRequirements"] = serde_json::json!({
        "requiredScopes":["target:manage"],
        "allowedPurposes":["target-management"],
        "rowBoundaries":[boundary.clone()]
    });
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        profile["requiredScopes"] = serde_json::json!(["target:manage"]);
        profile["requiredPurposes"] = serde_json::json!(["target-management"]);
    }
    source["accessProfiles"][0]["grants"][0]["rowBoundaries"] =
        serde_json::json!([boundary.clone()]);
    source["accessProfiles"][1]["grants"][0]["reviewStages"][0]["targets"][0]["rowBoundaries"] =
        serde_json::json!([boundary.clone()]);
    source["accessProfiles"][2]["grants"][0]["applyTargets"][0]["rowBoundaries"] =
        serde_json::json!([boundary]);
    source
}

#[test]
fn change_request_review_and_apply_cannot_omit_target_access_requirements() {
    let source = correction_with_target_access_requirements();
    compile_json(&serde_json::to_vec(&source).unwrap())
        .expect("explicit requirements are satisfied");
    for (profile_index, target_path, surface) in [
        (
            1,
            "/grants/0/reviewStages/0/targets/0/rowBoundaries",
            "reviewStages",
        ),
        (2, "/grants/0/applyTargets/0/rowBoundaries", "applyTargets"),
    ] {
        for (path, replacement, code) in [
            (
                "/requiredScopes",
                serde_json::json!([]),
                "access.requirements.scope_missing",
            ),
            (
                "/requiredPurposes",
                serde_json::json!([]),
                "access.requirements.purpose_widened",
            ),
            (
                "/requiredPurposes",
                serde_json::json!(["unrelated"]),
                "access.requirements.purpose_widened",
            ),
            (
                target_path,
                serde_json::json!([]),
                "access.requirements.row_boundary_missing",
            ),
            (
                target_path,
                serde_json::json!([{"field":"site","claim":"different_sites","operator":"in"}]),
                "access.requirements.row_boundary_missing",
            ),
        ] {
            let mut changed = source.clone();
            *changed["accessProfiles"][profile_index]
                .pointer_mut(path)
                .unwrap() = replacement;
            let failure = compile_json(&serde_json::to_vec(&changed).unwrap())
                .expect_err("request target grants cannot weaken mandatory entity requirements");
            assert!(
                failure
                    .diagnostics()
                    .iter()
                    .any(|d| d.code == code && d.path.contains(surface)),
                "{surface} {path}: {failure:?}"
            );
        }
    }
}

#[test]
fn change_request_fingerprint_covers_request_and_target_access_requirements() {
    let fingerprint = |source: &serde_json::Value| {
        compile_json(&serde_json::to_vec(source).unwrap())
            .unwrap()
            .entities()["placement-correction-request"]
            .change_request
            .as_ref()
            .unwrap()
            .contract_fingerprint
            .clone()
    };
    let mut source = correction_with_target_access_requirements();
    source["entities"][1]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    let base = fingerprint(&source);
    for entity_index in [1, 2] {
        let mut changed = source.clone();
        changed["entities"][entity_index]["accessRequirements"] =
            serde_json::json!({"requiredScopes":["target:manage"]});
        assert_ne!(
            base,
            fingerprint(&changed),
            "relevant requirements change the proposal contract"
        );
    }
    source["entities"][0]["accessRequirements"] =
        serde_json::json!({"requiredScopes":["site:read"]});
    assert_eq!(
        base,
        fingerprint(&source),
        "unaffected entity requirements do not reinterpret effects"
    );
}

#[test]
fn change_request_presence_cannot_omit_request_access_requirements() {
    let mut source = correction_with_target_access_requirements();
    let boundary =
        serde_json::json!({"field":"placement","claim":"allowed_placements","operator":"in"});
    source["entities"][1]["accessRequirements"]["allowedPurposes"] =
        serde_json::json!(["target-management", "non-review"]);
    source["entities"][2]["accessRequirements"] = serde_json::json!({
        "requiredScopes":["request:read"],
        "allowedPurposes":["target-management"],
        "rowBoundaries":[boundary.clone()]
    });
    for (index, profile) in source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        profile["requiredScopes"] = serde_json::json!(["target:manage", "request:read"]);
        if index > 0 {
            profile["grants"][0]["rowBoundaries"] = serde_json::json!([boundary.clone()]);
        }
    }
    source["accessProfiles"][0]["grants"][0]["requestPresence"][0]["rowBoundaries"] =
        serde_json::json!([boundary]);
    compile_json(&serde_json::to_vec(&source).unwrap())
        .expect("presence explicitly satisfies request requirements");
    for (path, replacement, code) in [
        (
            "/requiredScopes",
            serde_json::json!(["target:manage"]),
            "access.requirements.scope_missing",
        ),
        (
            "/requiredPurposes",
            serde_json::json!(["non-review"]),
            "access.requirements.purpose_widened",
        ),
        (
            "/grants/0/requestPresence/0/rowBoundaries",
            serde_json::json!([]),
            "access.requirements.row_boundary_missing",
        ),
        (
            "/grants/0/requestPresence/0/rowBoundaries",
            serde_json::json!([{"field":"placement","claim":"different_placements","operator":"in"}]),
            "access.requirements.row_boundary_missing",
        ),
    ] {
        let mut changed = source.clone();
        *changed["accessProfiles"][0].pointer_mut(path).unwrap() = replacement;
        let failure = compile_json(&serde_json::to_vec(&changed).unwrap())
            .expect_err("target admission alone cannot authorize protected request existence");
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|d| d.code == code && d.path.contains("requestPresence")),
            "{path}: {failure:?}"
        );
    }
}

#[test]
fn change_request_multi_record_create_and_patch_orders_reserved_references() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-registration","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"person","route":"people","mutationMode":"mutable","changeControl":{"requiredFor":["create"]},
            "fields":[{"id":"display-name","type":"string","maxLength":200,"required":true,"classification":"internal"}]
          },{
            "id":"membership","route":"memberships","mutationMode":"mutable","changeControl":{"requiredFor":["create"]},
            "fields":[
              {"id":"person","type":"reference","target":"person","required":true,"classification":"internal"},
              {"id":"household","type":"reference","target":"household","required":true,"classification":"internal"}
            ]
          },{
            "id":"household","route":"households","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"contact-person","type":"reference","target":"person","classification":"internal"}]
          },{
            "id":"registration-request","route":"registration-requests","mutationMode":"mutable",
            "fields":[
              {"id":"household","type":"reference","target":"household","required":true,"classification":"internal"},
              {"id":"name","type":"string","maxLength":200,"required":true,"classification":"internal"}
            ],
            "changeRequest":{
              "effects":[
                {"id":"person","target":{"entity":"person"},"operation":"create","set":{"display-name":{"fromField":"name"}}},
                {"id":"membership","target":{"entity":"membership"},"operation":"create","set":{"person":{"fromEffect":"person"},"household":{"fromField":"household"}}},
                {"target":{"fromField":"household"},"operation":"patch","set":{"contact-person":{"fromEffect":"person"}}}
              ],
              "review":{"stages":[{"id":"review","approvals":1}]}
            }
          }],
          "accessProfiles":[{
            "id":"reviewer","default":true,"principalClaim":"principal","grants":[{
              "entity":"registration-request","operations":["get","list","submit_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["household","name"],
              "reviewStages":[{"stage":"review","targets":[
                {"entity":"person","readableFields":["display-name"]},
                {"entity":"membership","readableFields":["person","household"]},
                {"entity":"household","readableFields":["contact-person"]}
              ]}],
              "applyTargets":[{"entity":"person"},{"entity":"membership"},{"entity":"household"}]
            }]
          }]
        }"#,
    )
    .expect("multi-record request compiles");

    let request = compiled.entities()["registration-request"]
        .change_request
        .as_ref()
        .expect("request plan is compiled");
    assert_eq!(
        request
            .effects
            .iter()
            .map(|effect| effect.id.as_str())
            .collect::<Vec<_>>(),
        vec!["person", "effect-3", "membership"],
        "reserved person identity is compiled before dependent writes"
    );
    assert!(request
        .effects
        .iter()
        .find(|effect| effect.id == "membership")
        .expect("membership create exists")
        .depends_on
        .contains("person"));
    assert!(matches!(
        request.effects[0].target.binding,
        CompiledChangeRequestTargetBinding::ReservedCreate { ref effect } if effect == "person"
    ));
    assert_eq!(
        request.target_entities,
        [
            "household".to_owned(),
            "membership".to_owned(),
            "person".to_owned()
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn change_request_compile_refuses_direct_write_bypass_and_incomplete_grants() {
    let source = |grant_ops: &str, review_fields: &str, apply_targets: &str| {
        format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"change-request-refusals","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"site","route":"sites","mutationMode":"create_only",
                "fields":[{{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}}]
              }},{{
                "id":"placement","route":"placements","mutationMode":"mutable","changeControl":{{"requiredFor":["patch"]}},
                "fields":[{{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}}]
              }},{{
                "id":"correction-request","route":"correction-requests","mutationMode":"mutable",
                "fields":[
                  {{"id":"placement","type":"reference","target":"placement","required":true,"classification":"internal"}},
                  {{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}}
                ],
                "changeRequest":{{"effects":[{{"target":{{"fromField":"placement"}},"operation":"patch","set":{{"site":{{"fromField":"site"}}}}}}],
                  "review":{{"stages":[{{"id":"review","approvals":1}}]}}}}
              }}],
              "accessProfiles":[{{
                "id":"target-writer","principalClaim":"principal","grants":[{{"entity":"placement","operations":{grant_ops},"readableFields":["site"],"writableFields":["site"]}}]
              }},{{
                "id":"reviewer","default":true,"principalClaim":"principal","grants":[{{"entity":"correction-request","operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["placement","site"],
                  "reviewStages":[{{"stage":"review","targets":[{{"entity":"placement","readableFields":{review_fields}}}]}}],
                  "applyTargets":{apply_targets}
                }}]
              }}]
            }}"#
        )
    };

    let direct = compile_json(
        source(
            r#"["get","patch"]"#,
            r#"["site"]"#,
            r#"[{"entity":"placement"}]"#,
        )
        .as_bytes(),
    )
    .expect_err("controlled targets cannot retain direct patch access");
    assert!(direct
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_control.direct_write_grant"));

    let blind =
        compile_json(source(r#"["get"]"#, r#"[]"#, r#"[{"entity":"placement"}]"#).as_bytes())
            .expect_err("review grants must cover changed fields");
    assert!(blind
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.review_projection.incomplete"));

    let partial_apply = compile_json(source(r#"["get"]"#, r#"["site"]"#, r#"[]"#).as_bytes())
        .expect_err("apply grants must cover every target entity");
    assert!(partial_apply
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.apply_targets.incomplete"));
}

#[test]
fn change_request_compile_refuses_ambiguous_references_cycles_overlaps_and_null_misuse() {
    let base = |effect: &str, request_fields: &str, target_fields: &str| {
        format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"change-request-negative","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"record","route":"records","mutationMode":"mutable","changeControl":{{"requiredFor":["patch","create"]}},
                "fields":[{target_fields}]
              }},{{
                "id":"request","route":"requests","mutationMode":"mutable",
                "fields":[{request_fields}],
                "changeRequest":{{"effects":[{effect}],"review":{{"stages":[{{"id":"review","approvals":1}}]}}}}
              }}],
              "accessProfiles":[{{
                "id":"operator","default":true,"principalClaim":"principal","grants":[{{
                  "entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["target","value","optional-value"],
                  "reviewStages":[{{"stage":"review","targets":[{{"entity":"record","readableFields":["label","parent"]}}]}}],
                  "applyTargets":[{{"entity":"record"}}]
                }}]
              }}]
            }}"#
        )
    };
    let request_fields = r#"
      {"id":"target","type":"reference","target":"record","required":true,"classification":"internal"},
      {"id":"value","type":"string","maxLength":32,"required":true,"classification":"internal"},
      {"id":"optional-value","type":"string","maxLength":32,"classification":"internal"}
    "#;
    let target_fields = r#"
      {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"},
      {"id":"parent","type":"reference","target":"record","classification":"internal"}
    "#;

    let ambiguous_target = compile_json(
        base(
            r#"{"target":{"entity":"record","fromField":"target"},"operation":"patch","set":{"label":{"fromField":"value"}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("effect targets must be unambiguous");
    assert!(ambiguous_target
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.target.invalid"));

    let nullable_set = compile_json(
        base(
            r#"{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"optional-value"}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("nullable set source is refused");
    assert!(nullable_set
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.value_nullable"));

    let missing_set_source = compile_json(
        base(
            r#"{"target":{"fromField":"target"},"operation":"patch","set":{"label":{}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("set mappings must declare an explicit source");
    assert!(missing_set_source
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.value.invalid"));

    let ambiguous_set_source = compile_json(
        base(
            r#"{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"value","fromEffect":"created"}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("set mappings cannot declare multiple sources");
    assert!(ambiguous_set_source
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.value.invalid"));

    let clear_required = compile_json(
        base(
            r#"{"target":{"fromField":"target"},"operation":"patch","clear":["label"]}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("required target fields cannot be cleared");
    assert!(clear_required
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.clear_required"));

    let overlap = compile_json(
        base(
            r#"{"id":"first","target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"value"}}},
               {"id":"second","target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"value"}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("overlapping target writes are refused");
    assert!(overlap
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.overlapping_write"));

    let cycle = compile_json(
        base(
            r#"{"id":"first","target":{"entity":"record"},"operation":"create","set":{"parent":{"fromEffect":"second"}}},
               {"id":"second","target":{"entity":"record"},"operation":"create","set":{"parent":{"fromEffect":"first"}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("reserved-create dependency cycles are refused");
    assert!(cycle
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.dependency_cycle"));

    let wrong_reserved_type = compile_json(
        base(
            r#"{"id":"created","target":{"entity":"record"},"operation":"create","set":{"label":{"fromEffect":"created"}}}"#,
            request_fields,
            target_fields,
        )
        .as_bytes(),
    )
    .expect_err("reserved ids can populate only reference fields");
    assert!(wrong_reserved_type
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.value_reference_required"));
}

#[test]
fn change_request_compile_refuses_uncontrolled_targets_tombstone_requests_and_plan_bounds() {
    let uncontrolled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"uncontrolled-request","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"target","route":"targets","mutationMode":"mutable",
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"request","route":"requests","mutationMode":"mutable",
            "fields":[
              {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
              "entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["target","label"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["label"]}]}],
              "applyTargets":[{"entity":"target"}]
            }]
          }]
        }"#,
    )
    .expect_err("change requests cannot claim uncontrolled target mutations");
    assert!(uncontrolled
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.uncontrolled_target"));

    let tombstone_request = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"request-tombstone","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"target","route":"targets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"request","route":"requests","mutationMode":"mutable","tombstone":true,
            "fields":[
              {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
              "entity":"request","operations":["get","tombstone","submit_request","approve_request","apply_request"],"readableFields":["target","label"],
              "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["label"]}]}],
              "applyTargets":[{"entity":"target"}]
            }]
          }]
        }"#,
    )
    .expect_err("request entities cannot expose ordinary tombstone");
    assert!(tombstone_request
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.tombstone_forbidden"));

    let mut effects = Vec::new();
    let mut target_fields = Vec::new();
    let mut request_fields = Vec::new();
    let mut review_fields = Vec::new();
    for index in 0..129 {
        let id = format!("field-{index}");
        target_fields.push(format!(
            r#"{{"id":"{id}","type":"string","maxLength":8,"classification":"internal"}}"#
        ));
        request_fields.push(format!(
            r#"{{"id":"{id}","type":"string","maxLength":8,"required":true,"classification":"internal"}}"#
        ));
        review_fields.push(format!(r#""{id}""#));
    }
    request_fields.push(
        r#"{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"}"#
            .to_owned(),
    );
    effects.push(format!(
        r#"{{"target":{{"fromField":"target"}},"operation":"patch","set":{{{}}}}}"#,
        (0..129)
            .map(|index| format!(r#""field-{index}":{{"fromField":"field-{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
    ));
    let bounded = format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"request-bounds","version":"1","defaultLanguage":"en"}},
          "entities":[{{"id":"target","route":"targets","mutationMode":"mutable","changeControl":{{"requiredFor":["patch"]}},
            "fields":[{}]}},{{"id":"request","route":"requests","mutationMode":"mutable",
            "fields":[{}],
            "changeRequest":{{"effects":[{}],"review":{{"stages":[{{"id":"review","approvals":1}}]}}}}
          }}],
          "accessProfiles":[{{"id":"operator","default":true,"principalClaim":"principal","grants":[{{"entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["target"],
            "reviewStages":[{{"stage":"review","targets":[{{"entity":"target","readableFields":[{}]}}]}}],
            "applyTargets":[{{"entity":"target"}}]}}]}}]
        }}"#,
        target_fields.join(","),
        request_fields.join(","),
        effects.join(","),
        review_fields.join(",")
    );
    let too_many_fields = compile_json(bounded.as_bytes())
        .expect_err("field-mutation ceiling is enforced at compile time");
    assert!(too_many_fields
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.bounds.field_mutations"));
}

#[test]
fn change_request_compile_refuses_invalid_lifecycle_surface_bounds_and_controls() {
    let misplaced_lifecycle = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"misplaced-lifecycle","version":"1","defaultLanguage":"en"},
          "entities":[{"id":"record","route":"records","mutationMode":"create_only",
            "fields":[{"id":"label","type":"string","maxLength":32,"classification":"internal"}]}],
          "accessProfiles":[{"id":"operator","principalClaim":"principal","grants":[{"entity":"record","operations":["get","submit_request"],"readableFields":["label"]}]}]
        }"#,
    )
    .expect_err("request lifecycle operations are available only on request entities");
    assert!(misplaced_lifecycle
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.operation.unavailable"));

    let unsupported_control = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"unsupported-control","version":"1","defaultLanguage":"en"},
          "entities":[{"id":"record","route":"records","mutationMode":"mutable","changeControl":{"requiredFor":["tombstone"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"classification":"internal"}]}],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","grants":[{"entity":"record","operations":["get"],"readableFields":["label"]}]}]
        }"#,
    )
    .expect_err("change control is bounded to create and patch operations");
    assert!(unsupported_control
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_control.operation.unsupported"));

    let self_controlled_request = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"self-controlled-request","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"target","route":"targets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"request","route":"requests","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[
              {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","grants":[{"entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["target","label"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["label"]}]}],
            "applyTargets":[{"entity":"target"}]}]}]
        }"#,
    )
    .expect_err("request entities cannot also be target-controlled entities");
    assert!(self_controlled_request
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.change_control_conflict"));

    let nested_request_target = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"nested-request-target","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"target","route":"targets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          },{
            "id":"inner-request","route":"inner-requests","mutationMode":"mutable",
            "fields":[
              {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"target":{"fromField":"target"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          },{
            "id":"outer-request","route":"outer-requests","mutationMode":"mutable",
            "fields":[
              {"id":"inner","type":"reference","target":"inner-request","required":true,"classification":"internal"},
              {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":[{"target":{"fromField":"inner"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"stages":[{"id":"review","approvals":1}]}}
          }],
          "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","grants":[{
            "entity":"inner-request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["target","label"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["label"]}]}],
            "applyTargets":[{"entity":"target"}]
          },{
            "entity":"outer-request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["inner","label"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"inner-request","readableFields":["label"]}]}],
            "applyTargets":[{"entity":"inner-request"}]
          }]}]
        }"#,
    )
    .expect_err("request effects cannot target nested request entities");
    assert!(nested_request_target
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.effect.nested_request_target"));

    let stages = (0..33)
        .map(|index| format!(r#"{{"id":"stage-{index}","approvals":1}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let too_many_stages = format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"too-many-stages","version":"1","defaultLanguage":"en"}},
          "entities":[{{"id":"target","route":"targets","mutationMode":"mutable","changeControl":{{"requiredFor":["patch"]}},
            "fields":[{{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}}]
          }},{{"id":"request","route":"requests","mutationMode":"mutable",
            "fields":[
              {{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"}},
              {{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}}
            ],
            "changeRequest":{{"effects":[{{"target":{{"fromField":"target"}},"operation":"patch","set":{{"label":{{"fromField":"label"}}}}}}],
              "review":{{"stages":[{stages}]}}}}
          }}],
          "accessProfiles":[{{"id":"operator","default":true,"principalClaim":"principal","grants":[{{"entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["target","label"],
            "reviewStages":[{{"stage":"stage-0","targets":[{{"entity":"target","readableFields":["label"]}}]}}],
            "applyTargets":[{{"entity":"target"}}]}}]}}]
        }}"#
    );
    let too_many_stages =
        compile_json(too_many_stages.as_bytes()).expect_err("stage count is finite and bounded");
    assert!(too_many_stages
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.review.stage_count"));
}

#[test]
fn derived_fields_selectors_and_read_paths_compile_to_route_specific_inventories() {
    let project = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"household-demo","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"household","route":"households","mutationMode":"mutable",
        "fields":[
          {"id":"household-code","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"administrative-area","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"local-household-number","type":"string","maxLength":32,"required":true,"classification":"internal"}
        ],
        "derived":[{
          "id":"demographics","sql":"sql/household-demographics.sql","key":"id","execution":"live",
          "fields":[
            {"id":"child-count","type":"int64","classification":"restricted"},
            {"id":"single-headed","type":"boolean","classification":"restricted"},
            {"id":"registry-derived-key-cardinality","type":"int64","classification":"restricted"}
          ]
        }],
        "selectorProfiles":[
          {"id":"by-local-reference","fields":["administrative-area","local-household-number"]}
        ],
        "readPaths":[{"id":"people","through":"group-membership","to":"person","route":"people"}]
      },{
        "id":"person","route":"people","mutationMode":"mutable",
        "fields":[
          {"id":"legal-name","type":"string","maxLength":80,"classification":"internal"},
          {"id":"date-of-birth","type":"date","classification":"internal"}
        ]
      },{
        "id":"group-membership","route":"memberships","mutationMode":"mutable",
        "fields":[
          {"id":"household","type":"reference","target":"household","classification":"internal"},
          {"id":"person","type":"reference","target":"person","classification":"internal"}
        ]
      }],
      "accessProfiles":[{
        "id":"operator","default":true,"principalClaim":"sub","grants":[{
          "entity":"household","operations":["get","lookup","list"],
          "readableFields":["household-code","child-count","single-headed"],
          "filterableFields":["child-count","single-headed"],
          "sortableFields":["child-count"],
          "allowCount":true,
          "lookups":[{"selector":"by-local-reference","valueOrigin":"request"}],
          "readPaths":[{
            "path":"people",
            "readableFields":["legal-name","date-of-birth"],
            "filterableFields":["date-of-birth"],
            "sortableFields":["date-of-birth"],
            "allowCount":true
          }]
        }]
      }]
    }"#;
    let sql = "SELECT h.id AS id, count(p.id)::bigint AS child_count, false AS single_headed, 1::bigint AS registry_derived_key_cardinality FROM registry_source.household h LEFT JOIN registry_source.group_membership gm ON gm.household = h.id LEFT JOIN registry_source.person p ON p.id = gm.person GROUP BY h.id";
    let compiled = compile_json_with_assets(
        project,
        vec![derived_sql_asset("sql/household-demographics.sql", sql)],
    )
    .expect("derived fields and relationship reads compile");

    let household = &compiled.entities()["household"];
    assert_eq!(
        household
            .stored_fields
            .iter()
            .map(|field| field.logical.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "household-code",
            "administrative-area",
            "local-household-number"
        ],
        "stored field authoring order is preserved for DDL/query workers"
    );
    assert_eq!(household.canonical_id.id, "id");
    assert!(!household.fields.contains_key("id"));
    let person = &compiled.entities()["person"];
    let path_policy = compiled
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "person")
        .and_then(|table| table.policies.first())
        .and_then(|policy| policy.using_expression.as_deref())
        .expect("target read-path RLS policy is compiled");
    assert!(path_policy.contains(&format!("\"{}\".\"record_id\"", person.physical_table)));
    let child_count = &household.derived_fields["child-count"].logical;
    assert_eq!(child_count.api_name, "childCount");
    assert_eq!(child_count.sql_name, "child_count");
    assert_eq!(
        household.derived_relations["demographics"].sql_bytes,
        sql.as_bytes()
    );
    let last_source_view = compiled
        .ddl()
        .statements
        .iter()
        .rposition(|statement| statement.id.ends_with(".source-view"))
        .expect("source views are generated");
    let first_derived_view = compiled
        .ddl()
        .statements
        .iter()
        .position(|statement| statement.id.contains(".derived."))
        .expect("derived view is generated");
    assert!(
        last_source_view < first_derived_view,
        "all source views must exist before cross-entity derived SQL is installed"
    );
    let derived_view = &compiled.ddl().statements[first_derived_view].sql;
    assert!(derived_view
        .contains("count(*) OVER (PARTITION BY canonical_derived.\"__registry$derived$key\")"));
    assert!(derived_view.contains("\"__registry$derived$cardinality\""));
    assert!(derived_view.contains("\"registry_derived_key_cardinality\"::bigint"));
    assert!(compiled
        .routes()
        .routes
        .iter()
        .any(|route| route.id == "records.household.lookup"
            && route.path == "/v1/records/households:lookup"));
    assert!(compiled
        .routes()
        .routes
        .iter()
        .any(|route| route.id == "records.household.path.people"
            && route.path == "/v1/records/households/{record_id}/people"));
    assert!(compiled
        .access()
        .entries
        .iter()
        .any(|entry| entry.route_id == "records.household.path.people"
            && entry.profile_ids.contains("operator")));
    let lookup = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.household.operator.lookup")
        .expect("lookup selector operation is compiled");
    assert_eq!(
        lookup.selector_fields,
        vec!["administrative-area", "local-household-number"]
    );
    let path = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.household.operator.path.people")
        .expect("read-path operation is compiled");
    assert_eq!(path.read_path.as_deref(), Some("people"));
    assert!(path.allow_count);
    assert!(path.processing_fields.contains(&"household".to_owned()));
    assert!(path.processing_fields.contains(&"person".to_owned()));
}

#[test]
fn canonical_id_row_boundary_targets_the_physical_record_id_column() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"canonical-id-boundary","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"household","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","type":"string","maxLength":32,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"viewer","principalClaim":"sub","grants":[{
              "entity":"household","operations":["get"],
              "readableFields":["household-code"],
              "rowBoundaries":[{"field":"id","claim":"household_id","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("the canonical id is a valid governed row boundary");

    let policy = compiled
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "household")
        .and_then(|table| {
            table
                .policies
                .iter()
                .find(|policy| policy.access_profile == "viewer")
        })
        .expect("viewer RLS policy is compiled");
    let expression = policy
        .using_expression
        .as_deref()
        .expect("viewer SELECT policy has a USING expression");
    assert!(expression.contains("\"record_id\" ="));
    assert!(
        !expression.contains("\"id\" ="),
        "logical aliases must not cross into physical table policies"
    );
}

#[test]
fn derived_sql_is_asset_backed_value_free_and_validates_output_aliases() {
    let project = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"derived-demo","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"household","route":"households","mutationMode":"mutable",
        "fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"}],
        "derived":[{
          "id":"demographics","sql":"sql/demographics.sql","key":"id",
          "fields":[{"id":"child-count","type":"int64","classification":"internal"}]
        }]
      }]
    }"#;

    let missing = compile_json_with_assets(project, vec![])
        .expect_err("derived SQL must be supplied as an explicit asset");
    assert!(missing
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "derived.sql.asset_missing"
            && !diagnostic.message.contains("SELECT")));

    let wrong_alias = compile_json_with_assets(
        project,
        vec![derived_sql_asset(
            "sql/demographics.sql",
            "SELECT h.id AS id, 0::bigint AS childCount FROM registry_source.household h",
        )],
    )
    .expect_err("SQL output aliases must use stable SQL field names");
    assert!(wrong_alias
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "derived.sql.invalid"
            && diagnostic.path == "entities[household].derived[demographics].sql"
            && !diagnostic.message.contains("childCount")));

    let wildcard = compile_json_with_assets(
        project,
        vec![derived_sql_asset(
            "sql/demographics.sql",
            "SELECT * FROM registry_source.household",
        )],
    )
    .expect_err("derived SQL cannot use wildcard projection");
    assert!(wildcard
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "derived.sql.invalid"));

    compile_json_with_assets(
        project,
        vec![derived_sql_asset(
            "sql/demographics.sql",
            "WITH counts AS (SELECT h.id AS id, count(*) AS child_count FROM registry_source.household h GROUP BY h.id) SELECT c.id AS id, c.child_count AS child_count FROM counts c",
        )],
    )
    .expect("a bounded non-recursive CTE over registry_source is accepted");
}

#[test]
fn anonymous_access_cannot_process_selector_path_or_derived_private_fields() {
    let source = |extra: &str| {
        format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"public-demo","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"household","route":"households","mutationMode":"mutable","classification":"public",
                "fields":[{{"id":"public-code","type":"string","maxLength":32,"classification":"public"}},
                  {{"id":"private-code","type":"string","maxLength":32,"classification":"restricted"}}],
                "derived":[{{"id":"flags","sql":"sql/flags.sql","key":"id","fields":[{{"id":"risk-flag","type":"boolean","classification":"public"}}]}}],
                "selectorProfiles":[{{"id":"by-private-code","fields":["private-code"]}}]
              }}],
              "accessProfiles":[{{"id":"anon","anonymous":true,"grants":[{{"entity":"household","operations":["lookup"],{extra}}}]}}]
            }}"#
        )
    };

    let selector = compile_json_with_assets(
        source(r#""readableFields":["public-code"],"lookups":[{"selector":"by-private-code","valueOrigin":"request"}]"#).as_bytes(),
        vec![derived_sql_asset(
            "sql/flags.sql",
            "SELECT h.id AS id, false AS risk_flag FROM registry_source.household h",
        )],
    )
    .expect_err("anonymous lookup cannot process restricted selector fields");
    assert!(selector
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.public.processing_non_public"));

    let derived = compile_json_with_assets(
        source(r#""readableFields":["risk-flag"],"filterableFields":["risk-flag"]"#).as_bytes(),
        vec![derived_sql_asset(
            "sql/flags.sql",
            "SELECT h.id AS id, false AS risk_flag FROM registry_source.household h",
        )],
    )
    .expect_err("anonymous access cannot process derived fields until lineage exists");
    assert!(derived
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.public.processing_non_public"));
}

#[test]
fn module_digest_can_bind_explicit_sql_assets() {
    let module = parse_module_json(
        br#"{"id":"core","version":"1","entities":[{"id":"record","route":"records","mutationMode":"mutable","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}]}]}"#,
    )
    .expect("module parses");
    let yaml_only = module_digest(&module);
    let with_asset = module_digest_with_assets(
        &module,
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/derived.sql".to_owned(),
            bytes: b"SELECT r.id AS id FROM registry_source.record r".to_vec(),
        }],
    );
    assert_ne!(yaml_only, with_asset);
    assert_eq!(yaml_only, module_digest_with_assets(&module, &[]));
    assert_eq!(
        yaml_only,
        module_digest_with_assets(
            &module,
            &[ModuleAssetSource {
                module: Some("another-module".to_owned()),
                path: "sql/derived.sql".to_owned(),
                bytes: b"SELECT 1".to_vec(),
            }],
        ),
        "assets owned by another module do not change this module's lock digest"
    );
}

#[test]
fn batch_route_requires_explicit_bounds_and_compiles_bounded_openapi() {
    let source = |batch: &str, operations: &str| {
        format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"batch-contract","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"record","route":"records","mutationMode":"mutable"{batch},
                "fields":[{{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}}]
              }}],
              "accessProfiles":[{{
                "id":"writer","principalClaim":"principal","grants":[{{
                  "entity":"record","operations":{operations},
                  "readableFields":["label"],"writableFields":["label"]
                }}]
              }}]
            }}"#
        )
    };

    let missing = compile_json(source("", r#"["create","batch"]"#).as_bytes())
        .expect_err("Batch grants require explicit entity-local bounds");
    assert!(missing
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "entity.batch.required"));

    for batch in [
        r#", "batch":{"maximumItems":0,"maximumBytes":1}"#,
        r#", "batch":{"maximumItems":101,"maximumBytes":1}"#,
        r#", "batch":{"maximumItems":1,"maximumBytes":0}"#,
        r#", "batch":{"maximumItems":1,"maximumBytes":2097153}"#,
    ] {
        let failure = compile_json(source(batch, r#"["create","batch"]"#).as_bytes())
            .expect_err("out-of-range Batch bounds are refused");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "entity.batch.bounds_invalid"));
    }

    let configured = compile_json(
        source(
            r#", "batch":{"maximumItems":37,"maximumBytes":65536}"#,
            r#"["create","patch","batch"]"#,
        )
        .as_bytes(),
    )
    .expect("bounded Batch contract compiles");
    let route = configured
        .routes()
        .routes
        .iter()
        .find(|route| route.operation == Operation::Batch)
        .expect("one Batch route is generated");
    assert_eq!(route.id, "records.record.batch");
    assert_eq!(route.path, "/v1/records/records:batch");
    let openapi = parse_json_strict(
        &configured
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated")
            .bytes,
    )
    .expect("OpenAPI is strict JSON");
    let batch_operation = &openapi["paths"]["/v1/records/records:batch"]["post"];
    assert_eq!(batch_operation["x-registry-maximumItems"], 37);
    assert_eq!(batch_operation["x-registry-maximumBytes"], 65536);
    assert_eq!(
        batch_operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
            ["items"]["maxItems"],
        37
    );
    assert_eq!(
        batch_operation["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["results"]["maxItems"],
        37
    );

    let configured_but_ungranted = compile_json(
        source(
            r#", "batch":{"maximumItems":10,"maximumBytes":4096}"#,
            r#"["create"]"#,
        )
        .as_bytes(),
    )
    .expect("unused valid bounds do not create authority");
    assert!(configured_but_ungranted
        .routes()
        .routes
        .iter()
        .all(|route| route.operation != Operation::Batch));

    let create_only = source(
        r#", "batch":{"maximumItems":10,"maximumBytes":4096}"#,
        r#"["create","batch"]"#,
    )
    .replace(
        r#""mutationMode":"mutable""#,
        r#""mutationMode":"create_only""#,
    );
    let create_only = compile_json(create_only.as_bytes())
        .expect("create-only entities may expose bounded batch create");
    assert!(create_only
        .routes()
        .routes
        .iter()
        .any(|route| route.operation == Operation::Batch));

    let create_only_patch = source(
        r#", "batch":{"maximumItems":10,"maximumBytes":4096}"#,
        r#"["create","patch","batch"]"#,
    )
    .replace(
        r#""mutationMode":"mutable""#,
        r#""mutationMode":"create_only""#,
    );
    let unavailable = compile_json(create_only_patch.as_bytes())
        .expect_err("create-only Batch profiles can never grant patch");
    assert!(unavailable
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.operation.unavailable"));
}

#[test]
fn public_asset_fixture_compiles_to_coherent_deterministic_inventories() {
    let project = asset_project();
    let modules = asset_modules();
    let first = compile_project(&project, &modules, CompileProfile::Production)
        .expect("the closed asset fixture compiles in production mode");
    let second = compile_project(&project, &modules, CompileProfile::Production)
        .expect("the same source compiles twice");

    assert_eq!(first, second);
    assert_eq!(first.entities().len(), 4);
    assert!(first.ddl().requires_btree_gist);
    assert!(first.ddl().script().contains("EXCLUDE USING gist"));
    assert!(first.artifacts().get("generated/openapi.json").is_some());
    assert!(first
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .is_some());
    assert!(first
        .artifacts()
        .get("generated/schemas/asset-placement.schema.json")
        .is_some());

    let inspection_routes: Vec<_> = first
        .routes()
        .routes
        .iter()
        .filter(|route| route.entity_id == "inspection-event")
        .collect();
    assert!(inspection_routes
        .iter()
        .all(|route| !matches!(route.operation, Operation::Patch | Operation::Tombstone)));
    assert!(first.findings().iter().all(|d| matches!(
        d.code.as_str(),
        "access.profile.no_required_scope" | "access.profile.unrestricted_collection"
    )));
}

#[test]
fn production_refuses_incomplete_authoring_closure() {
    let mut incomplete = asset_project();
    incomplete.package = None;
    incomplete.modules[0].digest = None;
    let failure = compile_project(&incomplete, &asset_modules(), CompileProfile::Production)
        .expect_err("the authoring fixture is not a production package");
    let codes: Vec<_> = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert!(codes.contains(&"package.identity.required"));
    assert!(codes.contains(&"module.lock.digest_required"));
    assert!(!codes.contains(&"manifest_projection.required"));
}

#[test]
fn production_allows_missing_manifest_projection_and_emits_no_manifest_artifacts() {
    let compiled = compile_project(
        &parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
              "package":{"environment":"local","instanceId":"local-instance","sequence":1,"sourceRevision":"source"},
              "entities":[{
                "id":"record","route":"records","mutationMode":"create_only",
                "fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"}]
              }],
              "accessProfiles":[{
                "id":"reader",
                "principalClaim":"principal",
                "grants":[{
                  "entity":"record",
                  "operations":["get"],
                  "readableFields":["code"]
                }]
              }]
            }"#,
        )
        .expect("source parses"),
        &[],
        CompileProfile::Production,
    )
    .expect("production compilation does not require a manifest projection");

    assert!(compiled.manifest_projection().is_none());
    assert!(compiled
        .artifacts()
        .entries()
        .keys()
        .all(|path| !path.starts_with("generated/manifest/")));
    assert_eq!(
        compiled
            .findings()
            .iter()
            .map(|d| d.code.as_str())
            .collect::<Vec<_>>(),
        vec!["access.profile.no_required_scope"]
    );
}

#[test]
fn project_access_profiles_use_the_entity_access_vocabulary() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case-file","route":"case-files","mutationMode":"mutable",
            "fields":[
              {"id":"case-code","type":"string","maxLength":32,"classification":"internal"},
              {"id":"status","type":"string","maxLength":32,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator",
            "default":true,
            "principalClaim":"sub",
            "requiredScopes":["records.read"],
            "requiredPurposes":["case-management"],
            "grants":[{
              "entity":"case-file",
              "operations":["get","list"],
              "readableFields":["case-code","status"],
              "filterableFields":["status"],
              "allowCount":true
            }]
          }]
        }"#,
    )
    .expect("canonical top-level profile source parses");

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("canonical top-level profile source compiles");
    let profile = compiled
        .entities()
        .get("case-file")
        .and_then(|entity| entity.access_profiles.get("operator"))
        .expect("top-level profile is expanded onto its granted entity");

    assert_eq!(profile.principal_claim.as_deref(), Some("sub"));
    assert_eq!(
        profile.required_scopes,
        ["records.read".to_owned()].into_iter().collect()
    );
    assert_eq!(
        profile.required_purposes,
        ["case-management".to_owned()].into_iter().collect()
    );
    assert_eq!(
        profile.operations,
        [Operation::Get, Operation::List].into_iter().collect()
    );
    assert!(profile.allow_count);
    assert!(compiled.access().entries.iter().any(|entry| {
        entry.entity_id == "case-file"
            && entry.operation == Operation::List
            && entry.profile_ids == ["operator".to_owned()].into_iter().collect()
            && entry.default_profile_id == "operator"
    }));
}

#[test]
fn root_project_entity_access_profiles_are_compile_time_errors() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case-file","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}],
            "accessProfiles":[{
              "id":"entity-local-reader",
              "principalClaim":"sub",
              "operations":["get"],
              "readableFields":["case-code"]
            }]
          }]
        }"#,
    )
    .expect("the shared parser still accepts the internal/module profile field");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("root project entity-local profiles match the public schema refusal");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "access_profile.project_entity_local.forbidden")
        .expect("root entity-local profile refusal is reported");
    assert_eq!(diagnostic.path, "project.entities[].accessProfiles");
}

#[test]
fn module_entity_access_profiles_remain_supported_for_module_composition() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"module-profile","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case-file","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}]
          }],
          "modules":[{"id":"core","version":"1"}]
        }"#,
    )
    .expect("project parses");
    let module = parse_module_json(
        br#"{
          "id":"core",
          "version":"1",
          "entities":[{
            "id":"module-record","route":"module-records","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}],
            "accessProfiles":[{
              "id":"module-reader",
              "principalClaim":"sub",
              "operations":["get"],
              "readableFields":["case-code"]
            }]
          }],
          "extendEntities":[{
            "entity":"case-file",
            "accessProfiles":[{
              "id":"extension-reader",
              "principalClaim":"sub",
              "operations":["get"],
              "readableFields":["case-code"]
            }]
          }]
        }"#,
    )
    .expect("module parses");

    let compiled = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect("module-local access profiles remain module composition input");
    assert!(compiled.entities()["module-record"]
        .access_profiles
        .contains_key("module-reader"));
    assert!(compiled.entities()["case-file"]
        .access_profiles
        .contains_key("extension-reader"));
}

#[test]
fn anonymous_project_access_profiles_expand_without_authenticated_claims() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"anonymous-profile","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"public-record","route":"public-records","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"classification":"public"},
              {"id":"name","type":"string","maxLength":80,"classification":"public"}
            ]
          }],
          "accessProfiles":[{
            "id":"public-reader",
            "default":true,
            "anonymous":true,
            "grants":[{
              "entity":"public-record",
              "operations":["get","list"],
              "readableFields":["code","name"],
              "filterableFields":["code"]
            }]
          }]
        }"#,
    )
    .expect("anonymous project profile source parses");

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("anonymous project profile compiles");
    let profile = compiled
        .entities()
        .get("public-record")
        .and_then(|entity| entity.access_profiles.get("public-reader"))
        .expect("anonymous top-level profile is expanded onto its granted entity");

    assert!(profile.anonymous);
    assert_eq!(profile.principal_claim, None);
    assert!(profile.required_scopes.is_empty());
    assert!(profile.required_purposes.is_empty());
    assert_eq!(
        profile.operations,
        [Operation::Get, Operation::List].into_iter().collect()
    );
}

#[test]
fn anonymous_project_access_profiles_cannot_require_authenticated_claims() {
    let source = |extra: &str| {
        format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"anonymous-profile","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"public-record","route":"public-records","mutationMode":"mutable","classification":"public",
                "fields":[{{"id":"code","type":"string","maxLength":32,"classification":"public"}}]
              }}],
              "accessProfiles":[{{
                "id":"public-reader",
                "anonymous":true,
                {extra}
                "grants":[{{"entity":"public-record","operations":["get"],"readableFields":["code"]}}]
              }}]
            }}"#
        )
    };

    for (source, code, path) in [
        (
            source(r#""principalClaim":"sub","#),
            "access_profile.principal_claim.forbidden",
            "project.accessProfiles[].principalClaim",
        ),
        (
            source(r#""requiredScopes":["records.read"],"#),
            "access_profile.anonymous.claim_requirements_forbidden",
            "project.accessProfiles[]",
        ),
        (
            source(r#""requiredPurposes":["case-management"],"#),
            "access_profile.anonymous.claim_requirements_forbidden",
            "project.accessProfiles[]",
        ),
    ] {
        let project = parse_project_json(source.as_bytes()).expect("project source parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("anonymous profiles cannot require authenticated claims");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code && diagnostic.path == path));
    }
}

#[test]
fn project_access_profiles_reject_the_legacy_purpose_vocabulary() {
    let failure = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case-file","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator",
            "principalClaim":"sub",
            "purposes":["case-management"],
            "grants":[{"entity":"case-file","operations":["get"],"readableFields":["case-code"]}]
          }]
        }"#,
    )
    .expect_err("legacy purposes key is no longer part of the authoring contract");

    let diagnostic = &failure.diagnostics()[0];
    assert_eq!(diagnostic.code, "source.shape.invalid");
    assert_eq!(diagnostic.path, "project.accessProfiles[0].purposes");
}

#[test]
fn project_access_grants_reject_the_legacy_action_vocabulary() {
    let failure = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case-file","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator",
            "principalClaim":"sub",
            "requiredPurposes":["case-management"],
            "grants":[{"entity":"case-file","actions":["get"],"readableFields":["case-code"]}]
          }]
        }"#,
    )
    .expect_err("legacy actions key is no longer part of the authoring contract");

    let diagnostic = &failure.diagnostics()[0];
    assert_eq!(diagnostic.code, "source.shape.invalid");
    assert_eq!(
        diagnostic.path,
        "project.accessProfiles[0].grants[0].actions"
    );
}

#[test]
fn entity_access_grants_reject_action_target_and_result_fields() {
    for extra in [
        r#","targets":[{"entity":"case-file","rowBoundaries":[]}]"#,
        r#","results":["created"]"#,
    ] {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"profile-vocabulary","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"case-file","route":"case-files","mutationMode":"mutable",
                "fields":[{{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}}]
              }}],
              "accessProfiles":[{{
                "id":"operator",
                "principalClaim":"sub",
                "grants":[{{
                  "entity":"case-file",
                  "operations":["get"],
                  "readableFields":["case-code"]{extra}
                }}]
              }}]
            }}"#
        );
        let failure = compile_json(source.as_bytes())
            .expect_err("entity grants cannot carry action-only fields");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "access_profile.grant.action_fields_forbidden"
                && diagnostic.path == "project.accessProfiles[].grants[]"
        }));
    }
}

#[test]
fn project_access_grants_reject_mixed_entity_and_action_targets() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case-file","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}]
          }],
          "actions":[{
            "id":"create-case-file",
            "inputs":[{"id":"case-code","type":"string","maxLength":32,"classification":"internal"}],
            "effects":[{"id":"case","target":{"entity":"case-file"},"operation":"create","set":{"case-code":{"fromField":"case-code"}}}]
          }],
          "accessProfiles":[{
            "id":"operator",
            "principalClaim":"sub",
            "grants":[{
              "entity":"case-file",
              "action":"create-case-file",
              "operations":["invoke"],
              "targets":[{"entity":"case-file","rowBoundaries":[]}]
            }]
          }]
        }"#,
    )
    .expect_err("grants cannot name both an entity and an action");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "access_profile.grant.target_exclusive"
            && diagnostic.path == "project.accessProfiles[].grants[]"
    }));
}

#[test]
fn manifest_projection_unknown_nested_keys_are_rejected_without_values() {
    let failure = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"internal",
            "catalog":{
              "baseUrl":"https://registry.example.test",
              "title":"Registry Catalog",
              "publisher":{"name":"Publisher","privateKey":"do-not-echo"}
            },
            "dataset":{"title":"Registry Dataset"}
          }
        }"#,
    )
    .expect_err("unknown projection members are refused");

    assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
    assert_eq!(
        failure.diagnostics()[0].path,
        "project.manifestProjection.catalog.publisher.privateKey"
    );
    assert!(!serde_json::to_string(&failure)
        .expect("diagnostic serializes")
        .contains("do-not-echo"));
}

#[test]
fn manifest_projection_compiles_to_deterministic_valid_manifest_core() {
    let compiled = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let value = parse_json_strict(&artifact.bytes).expect("Manifest projection is strict JSON");
    assert_eq!(
        canonicalize_json(&value).expect("Manifest projection canonicalizes"),
        artifact.bytes
    );
    let manifest: MetadataManifest =
        serde_json::from_value(value).expect("generated Manifest source parses");
    let first = compile_manifest(&manifest).expect("generated Manifest compiles");
    let second = compile_manifest(&manifest).expect("generated Manifest compiles twice");
    assert_eq!(first, second);

    let dataset = first
        .dataset("asset-site-placement")
        .expect("stable dataset id is preserved");
    assert_eq!(dataset.access_rights, AccessRights::Restricted);
    assert_eq!(dataset.entities.len(), 4);
    assert!(dataset
        .entities
        .get("asset-placement")
        .expect("placement entity is projected")
        .relationships
        .iter()
        .any(|relationship| relationship.name == "asset" && relationship.target == "asset-item"));
}

#[test]
fn all_acceptance_fixtures_compile_manifest_projection_under_production() {
    for domain in [
        "asset-site-placement",
        "business-establishments",
        "facility",
        "inspection",
        "business",
    ] {
        let mut project = acceptance_project(domain);
        assert!(
            project.manifest_projection.is_some(),
            "{domain} declares explicit projection metadata"
        );
        project
            .package
            .get_or_insert_with(|| PackageIdentitySource {
                environment: "local".to_owned(),
                instance_id: format!("{domain}-instance"),
                sequence: 1,
                source_revision: "acceptance-fixture-source".to_owned(),
            });
        let mut modules = Vec::new();
        let mut assets = Vec::new();
        for lock in &mut project.modules {
            let module_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/registry-server/acceptance")
                .join(domain)
                .join("modules")
                .join(&lock.id);
            let module_path = module_root.join("module.yaml");
            let module = if module_path.is_file() {
                let bytes = fs::read(module_path).expect("locked acceptance module is readable");
                let module = parse_module_yaml(&bytes).expect("locked acceptance module parses");
                let mut module_assets = Vec::new();
                for derived in module
                    .entities
                    .iter()
                    .flat_map(|entity| &entity.derived)
                    .chain(
                        module
                            .extend_entities
                            .iter()
                            .flat_map(|extension| &extension.derived),
                    )
                {
                    module_assets.push(ModuleAssetSource {
                        module: Some(module.id.clone()),
                        path: derived.sql.clone(),
                        bytes: fs::read(module_root.join(&derived.sql))
                            .expect("locked derived SQL asset is readable"),
                    });
                }
                lock.digest = Some(module_digest_with_assets(&module, &module_assets));
                assets.extend(module_assets);
                module
            } else {
                let module = RegistryModule {
                    id: lock.id.clone(),
                    version: lock.version.clone(),
                    dependencies: Vec::new(),
                    entities: Vec::new(),
                    extend_entities: Vec::new(),
                    actions: Vec::new(),
                };
                lock.digest = Some(module_digest(&module));
                module
            };
            modules.push(module);
        }

        let compiled =
            compile_project_with_assets(&project, &modules, &assets, CompileProfile::Production)
                .unwrap_or_else(|failure| {
                    panic!("{domain} production compile failed: {failure:?}")
                });
        let artifact = compiled
            .artifacts()
            .get("generated/manifest/registry-manifest.json")
            .unwrap_or_else(|| panic!("{domain} Manifest projection is generated"));
        let manifest: MetadataManifest = serde_json::from_slice(&artifact.bytes)
            .unwrap_or_else(|error| panic!("{domain} Manifest projection parses: {error}"));
        let manifest = compile_manifest(&manifest)
            .unwrap_or_else(|error| panic!("{domain} Manifest projection compiles: {error:?}"));
        let dcat = compiled
            .artifacts()
            .get("generated/manifest/dcat.jsonld")
            .unwrap_or_else(|| panic!("{domain} DCAT projection is generated"));
        let dcat = parse_json_strict(&dcat.bytes)
            .unwrap_or_else(|error| panic!("{domain} DCAT projection parses: {error}"));

        if domain == "business-establishments" {
            let dataset = manifest
                .dataset("business-registry")
                .expect("configured dataset id is preserved");
            assert_eq!(
                dataset.entities["establishment"].concept_uri.as_deref(),
                Some("https://business-establishments.example.gov/model/establishment")
            );
            assert_eq!(
                dataset.entities["operator-assignment"]
                    .relationships
                    .iter()
                    .find(|relationship| relationship.name == "business")
                    .expect("operator relationship is projected")
                    .concept_uri
                    .as_deref(),
                Some("https://business-establishments.example.gov/model/business")
            );
            assert_eq!(manifest.data_services().count(), 1);
            assert!(manifest
                .codelists()
                .any(|codelist| codelist.id == "establishment-role"));
            assert_eq!(
                dcat["dcat:service"][0]["dcat:endpointURL"],
                "https://business-establishments.example.gov/v1"
            );
        }
    }
}

#[test]
fn manifest_projection_filters_by_selected_profile_and_classification_ceiling() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"public-slice","version":"1","defaultLanguage":"en"},
          "manifestProjection":{
            "accessProfile":"operator",
            "classificationCeiling":"public",
            "catalog":{"baseUrl":"https://public-slice.example.test","title":"Public Slice","publisher":{"name":"Publisher"}},
            "dataset":{"title":"Public Slice Dataset","status":"active"}
          },
          "entities":[
            {"id":"visible-target","route":"visible-targets","mutationMode":"create_only","classification":"public",
             "fields":[{"id":"label","type":"string","maxLength":64,"classification":"public"}]},
            {"id":"hidden-target","route":"hidden-targets","mutationMode":"create_only","classification":"restricted",
             "fields":[{"id":"label","type":"string","maxLength":64,"classification":"restricted"}]},
            {"id":"link","route":"links","mutationMode":"create_only","classification":"public",
             "fields":[
               {"id":"name","type":"string","maxLength":64,"classification":"public"},
               {"id":"operator-note","type":"string","maxLength":64,"classification":"internal"},
               {"id":"visible-ref","type":"reference","target":"visible-target","classification":"public"},
               {"id":"hidden-ref","type":"reference","target":"hidden-target","classification":"public"}
             ]}
          ],
          "accessProfiles":[{
            "id":"operator","principalClaim":"principal","grants":[
              {"entity":"visible-target","operations":["get"],"readableFields":["label"]},
              {"entity":"hidden-target","operations":["get"],"readableFields":["label"]},
              {"entity":"link","operations":["get"],"readableFields":["name","operator-note","visible-ref","hidden-ref"]}
            ]
          }]
        }"#,
    )
    .expect("project parses");
    let compiled =
        compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let manifest: MetadataManifest =
        serde_json::from_slice(&artifact.bytes).expect("generated Manifest projection parses");
    let projected = compile_manifest(&manifest).expect("generated Manifest projection compiles");
    let dataset = projected
        .dataset("public-slice")
        .expect("dataset id is stable");

    assert_eq!(dataset.access_rights, AccessRights::Restricted);
    assert!(dataset.entities.contains_key("visible-target"));
    assert!(dataset.entities.contains_key("link"));
    assert!(!dataset.entities.contains_key("hidden-target"));
    let link = dataset.entities.get("link").expect("link is visible");
    assert!(link.fields.contains_key("name"));
    assert_eq!(link.fields["name"].field_type, FieldType::String);
    assert!(!link.fields.contains_key("operator-note"));
    assert!(link
        .relationships
        .iter()
        .any(|relationship| relationship.name == "visible-ref"
            && relationship.target == "visible-target"));
    assert!(!link
        .relationships
        .iter()
        .any(|relationship| relationship.name == "hidden-ref"));
}

#[test]
fn manifest_projection_metadata_cannot_describe_hidden_entities_or_fields() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"public-slice","version":"1","defaultLanguage":"en"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"restricted",
            "catalog":{"baseUrl":"https://public-slice.example.test","title":"Public Slice","publisher":{"name":"Publisher"}},
            "dataset":{"title":"Public Slice Dataset"},
            "entities":[
              {"id":"record","fields":[
                {"id":"secret-note","concepts":["https://example.test/secret-note"]},
                {"id":"profile","concepts":["https://example.test/Profile"]}
              ]},
              {"id":"secret-record","conceptUri":"https://example.test/SecretRecord"}
            ]
          },
          "entities":[
            {"id":"record","route":"records","mutationMode":"create_only","classification":"public",
             "fields":[
               {"id":"name","type":"string","maxLength":64,"classification":"public"},
               {"id":"secret-note","type":"string","maxLength":64,"classification":"restricted"},
               {"id":"profile","type":"structured","maxBytes":1024,"schema":{"type":"object","additionalProperties":false},"classification":"public"}
             ]},
            {"id":"secret-record","route":"secret-records","mutationMode":"create_only","classification":"restricted",
             "fields":[{"id":"name","type":"string","maxLength":64,"classification":"restricted"}]}
          ],
          "accessProfiles":[
            {"id":"reader","principalClaim":"principal","grants":[{"entity":"record","operations":["get"],"readableFields":["name","profile"]}]},
            {"id":"other-reader","principalClaim":"principal","grants":[{"entity":"secret-record","operations":["get"],"readableFields":["name"]}]}
          ]
        }"#,
    )
    .expect("project parses");
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("metadata outside the projected disclosure slice is refused");
    let codes = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<BTreeSet<_>>();

    assert!(codes.contains("manifest_projection.field.not_visible"));
    assert!(codes.contains("manifest_projection.field.not_representable"));
    assert!(codes.contains("manifest_projection.entity.not_visible"));
}

#[test]
fn manifest_projection_omits_physical_runtime_and_security_terms() {
    let compiled = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let rendered = std::str::from_utf8(&artifact.bytes).expect("Manifest is UTF-8");

    for forbidden in [
        "postgres",
        "physical",
        "runtime",
        "secret",
        "authorization",
        "migration",
        "revision",
        "rls",
    ] {
        assert!(!rendered.to_ascii_lowercase().contains(forbidden));
    }
}

#[test]
fn independent_additive_modules_are_order_independent() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"neutral-registry","version":"1","defaultLanguage":"en"},
          "modules":[
            {"id":"core","version":"1"},
            {"id":"alpha","version":"1"},
            {"id":"beta","version":"1"}
          ],
          "entities":[{
            "id":"object","route":"objects","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal","grants":[{
              "entity":"object","operations":["create","get","list","patch"],
              "readableFields":["code"],"writableFields":["code"]
            }]
          }]
        }"#,
    )
    .expect("project parses");
    let alpha = parse_module_json(
        br#"{
          "id":"alpha","version":"1","dependencies":["core"],
          "extendEntities":[{"entity":"object","fields":[
            {"id":"alpha-field","type":"boolean","classification":"internal"}
          ]}]
        }"#,
    )
    .expect("alpha module parses");
    let beta = parse_module_json(
        br#"{
          "id":"beta","version":"1","dependencies":["core"],
          "extendEntities":[{"entity":"object","fields":[
            {"id":"beta-field","type":"int64","classification":"internal"}
          ]}]
        }"#,
    )
    .expect("beta module parses");

    let left = compile_project(
        &project,
        &[alpha.clone(), beta.clone()],
        CompileProfile::Authoring,
    )
    .expect("first order compiles");
    let right = compile_project(&project, &[beta, alpha], CompileProfile::Authoring)
        .expect("reverse order compiles");
    assert_eq!(left, right);
    assert_eq!(left.module_order(), ["core", "alpha", "beta"]);
}

#[test]
fn project_access_profile_required_scopes_compile_into_each_grant() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"scope-bound-registry","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"record","route":"records","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator","principalClaim":"registry_principal",
            "requiredScopes":["registry:record:operate"],
            "grants":[{
              "entity":"record","operations":["get"],"readableFields":["code"]
            }]
          }]
        }"#,
    )
    .expect("scope-bound project parses");

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("scope-bound project compiles");
    let profile = compiled.entities()["record"]
        .access_profiles
        .get("operator")
        .expect("project profile is compiled onto the grant");
    assert_eq!(
        profile.required_scopes,
        BTreeSet::from(["registry:record:operate".to_owned()])
    );
}

#[test]
fn strict_parse_refuses_unknown_and_duplicate_members_without_echoing_values() {
    let unknown = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en","secretField":"do-not-echo"}
        }"#,
    )
    .expect_err("unknown member is refused");
    assert_eq!(unknown.diagnostics()[0].code, "source.shape.invalid");
    assert!(unknown.diagnostics()[0]
        .path
        .starts_with("project.registry"));
    let rendered = serde_json::to_string(&unknown).expect("diagnostic serializes");
    assert!(!rendered.contains("do-not-echo"));
    assert!(unknown.diagnostics()[0].path.ends_with("secretField"));

    let duplicate = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "kind":"Other",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"}
        }"#,
    )
    .expect_err("duplicate member is refused");
    assert_eq!(duplicate.diagnostics()[0].code, "source.json.invalid");
    assert_eq!(duplicate.diagnostics()[0].path, "project");
}

#[test]
fn deferred_query_features_are_strictly_unknown_key_rejected() {
    for (key, member, canary) in [
        (
            "joins",
            r#""joins":[{"source":"join-source-canary"}]"#,
            "join-source-canary",
        ),
        (
            "transforms",
            r#""transforms":[{"source":"transform-source-canary"}]"#,
            "transform-source-canary",
        ),
        (
            "countSources",
            r#""countSources":[{"source":"count-source-canary"}]"#,
            "count-source-canary",
        ),
        (
            "namedQueries",
            r#""namedQueries":[{"source":"named-query-canary"}]"#,
            "named-query-canary",
        ),
        (
            "spatialPredicates",
            r#""spatialPredicates":[{"source":"spatial-predicate-canary"}]"#,
            "spatial-predicate-canary",
        ),
    ] {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"closed-query-grammar","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"record","route":"records","mutationMode":"create_only",
                {member}
              }}]
            }}"#
        );
        let failure = parse_project_json(source.as_bytes())
            .expect_err("deferred query features remain outside the strict authoring grammar");
        assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
        assert!(failure.diagnostics()[0].path.ends_with(key));
        let rendered = format!(
            "{failure:?}\n{failure}\n{}",
            serde_json::to_string(&failure).expect("diagnostic serializes")
        );
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn strict_yaml_parse_refuses_duplicate_members() {
    let failure = parse_project_yaml(
        br#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
kind: AnotherKind
registry:
  id: neutral
  version: "1"
  defaultLanguage: en
"#,
    )
    .expect_err("duplicate YAML member is refused");
    assert_eq!(failure.diagnostics()[0].code, "source.yaml.invalid");
}

#[test]
fn generic_decimal_crs84_point_and_structured_fields_compile_to_deterministic_ddl_and_schema() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"generic-scalars","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"reading","route":"readings","mutationMode":"mutable",
            "fields":[
              {"id":"amount","type":"decimal","precision":6,"scale":2,"minimum":"-10.00","maximum":"9999.99","classification":"internal"},
              {"id":"location","type":"crs84-point","precision":4,"bbox":{"west":"100.0000","south":"10.0000","east":"110.0000","north":"20.0000"},"classification":"internal"},
              {"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object",
                "additionalProperties":false,
                "properties":{"batch":{"type":"string","maxLength":32}},
                "required":["batch"]
              }}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
              "entity":"reading","operations":["create","get","list","patch"],
              "readableFields":["amount","location","payload"],
              "writableFields":["amount","location","payload"]
            }]
          }]
        }"#,
    )
    .expect("generic scalar source parses");
    let first =
        compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles");
    let second =
        compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles twice");
    assert_eq!(first, second);

    let ddl = first.ddl().script();
    assert!(ddl.contains("numeric(6,2)"));
    assert!(ddl.contains("jsonb_typeof"));
    assert!(ddl.contains("octet_length"));
    assert!(ddl.contains("^-?(0|[1-9]|[1-8][0-9]|90)(\\.[0-9]{1,4})?$"));
    let lower = ddl.to_ascii_lowercase();
    assert!(!lower.contains("postgis"));
    assert!(!lower.contains("geometry"));
    assert!(!lower.contains("geography"));

    let schema = first
        .artifacts()
        .get("generated/schemas/reading.schema.json")
        .expect("entity schema generated");
    let schema: Value = parse_json_strict(&schema.bytes).expect("schema is strict JSON");
    assert_eq!(schema["properties"]["amount"]["type"], "string");
    assert_eq!(schema["properties"]["amount"]["x-registry-decimalScale"], 2);
    assert_eq!(
        schema["properties"]["location"]["description"],
        "CRS84 GeoJSON Point with coordinates in [longitude, latitude] order."
    );
    assert_eq!(
        schema["properties"]["payload"]["properties"]["batch"]["type"],
        "string"
    );
    assert_eq!(schema["properties"]["payload"]["x-registry-maxBytes"], 256);
}

#[test]
fn scalar_field_sources_reject_incompatible_type_options_during_strict_parse() {
    let failure = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"generic-scalars","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"reading","route":"readings","mutationMode":"mutable",
            "fields":[{"id":"flag","type":"boolean","precision":2,"classification":"internal"}]
          }]
        }"#,
    )
    .expect_err("type-incompatible option is refused during parse");
    assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
}

#[test]
fn scalar_grammar_is_exactly_the_typed_allowlist_and_rejects_json_or_reference_lists() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"scalar-allowlist","version":"1","defaultLanguage":"en"},
          "entities":[
            {"id":"target","route":"targets","mutationMode":"create_only"},
            {
              "id":"record","route":"records","mutationMode":"create_only",
              "fields":[
                {"id":"flag","type":"boolean","classification":"internal"},
                {"id":"code","type":"string","maxLength":32,"classification":"internal"},
                {"id":"notes","type":"text","maxLength":1024,"classification":"internal"},
                {"id":"count","type":"int64","classification":"internal"},
                {"id":"amount","type":"decimal","precision":6,"scale":2,"classification":"internal"},
                {"id":"day","type":"date","classification":"internal"},
                {"id":"observed-at","type":"timestamp","classification":"internal"},
                {"id":"external-id","type":"uuid","classification":"internal"},
                {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"internal"},
                {"id":"target","type":"reference","target":"target","classification":"internal"},
                {"id":"location","type":"crs84-point","precision":4,"classification":"internal"},
                {"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{"type":"object","additionalProperties":false}}
              ]
            }
          ],
          "vocabularies":[{"id":"status","values":["active","closed"]}]
        }"#,
    )
    .expect("every approved scalar form parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("every approved scalar form compiles");

    let approved: Vec<_> = project.entities[1]
        .fields
        .iter()
        .map(|field| match &field.field_type {
            FieldTypeSource::Boolean => "boolean",
            FieldTypeSource::String { .. } => "string",
            FieldTypeSource::Text { .. } => "text",
            FieldTypeSource::Int64 => "int64",
            FieldTypeSource::Decimal { .. } => "decimal",
            FieldTypeSource::Date => "date",
            FieldTypeSource::Timestamp => "timestamp",
            FieldTypeSource::Uuid => "uuid",
            FieldTypeSource::VocabularyCode { .. } => "vocabulary-code",
            FieldTypeSource::Reference { .. } => "reference",
            FieldTypeSource::Crs84Point { .. } => "crs84-point",
            FieldTypeSource::Structured { .. } => "structured",
        })
        .collect();
    assert_eq!(
        approved,
        [
            "boolean",
            "string",
            "text",
            "int64",
            "decimal",
            "date",
            "timestamp",
            "uuid",
            "vocabulary-code",
            "reference",
            "crs84-point",
            "structured",
        ]
    );

    let refused = [
        (
            r#"{"id":"unvalidated-json-canary","type":"json","classification":"internal"}"#,
            "unvalidated-json-canary",
        ),
        (
            r#"{"id":"reference-list-canary","type":"reference-list","target":"target","classification":"internal"}"#,
            "reference-list-canary",
        ),
        (
            r#"{"id":"reference-target-list-canary","type":"reference","target":["target"],"classification":"internal"}"#,
            "reference-target-list-canary",
        ),
    ];
    for (field, canary) in refused {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"scalar-allowlist","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"record","route":"records","mutationMode":"create_only",
                "fields":[{field}]
              }}]
            }}"#
        );
        let failure = parse_project_json(source.as_bytes())
            .expect_err("unapproved scalar or reference-list forms fail strict parsing");
        assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
        let rendered = format!(
            "{failure:?}\n{failure}\n{}",
            serde_json::to_string(&failure).expect("diagnostic serializes")
        );
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn generic_scalar_option_and_schema_negatives_fail_before_ddl_generation() {
    let cases = [
        (
            r#"{"id":"amount","type":"decimal","precision":39,"scale":2,"classification":"internal"}"#,
            "field.decimal.bounds_invalid",
        ),
        (
            r#"{"id":"amount","type":"decimal","precision":4,"scale":2,"minimum":"01.00","classification":"internal"}"#,
            "field.decimal.bounds_invalid",
        ),
        (
            r#"{"id":"location","type":"crs84-point","precision":10,"classification":"internal"}"#,
            "field.crs84_point.bounds_invalid",
        ),
        (
            r#"{"id":"location","type":"crs84-point","precision":4,"bbox":{"west":"110.0000","south":"10.0000","east":"100.0000","north":"20.0000"},"classification":"internal"}"#,
            "field.crs84_point.bounds_invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maxBytes":0,"classification":"internal","schema":{"type":"object","additionalProperties":false}}"#,
            "field.structured.schema_invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{"type":"object","properties":{"code":{"type":"string"}}}}"#,
            "field.structured.schema_invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{}}"#,
            "field.structured.schema_invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{"$ref":"https://schema.example.invalid/payload"}}"#,
            "field.structured.schema_invalid",
        ),
    ];

    for (field, code) in cases {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"generic-scalars","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"reading","route":"readings","mutationMode":"mutable",
                "fields":[{field}]
              }}],
              "accessProfiles":[{{"id":"operator","default":true,"principalClaim":"principal","grants":[{{"entity":"reading","operations":["get"],"readableFields":["{}"]}}]}}]
            }}"#,
            if field.contains("\"amount\"") {
                "amount"
            } else if field.contains("\"location\"") {
                "location"
            } else {
                "payload"
            }
        );
        let project = parse_project_json(source.as_bytes()).expect("source shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("invalid generic scalar configuration fails compilation");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn crs84_point_and_structured_fields_cannot_be_row_boundaries_until_equality_is_defined() {
    for field in [
        r#"{"id":"location","type":"crs84-point","precision":4,"classification":"internal"}"#,
        r#"{"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{"type":"object","additionalProperties":false}}"#,
    ] {
        let field_id = if field.contains("\"location\"") {
            "location"
        } else {
            "payload"
        };
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"generic-scalars","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"reading","route":"readings","mutationMode":"mutable",
                "fields":[{field}]
              }}],
              "accessProfiles":[{{
                "id":"operator","default":true,"principalClaim":"principal","grants":[{{
                  "entity":"reading","operations":["get"],
                  "readableFields":["{field_id}"],
                  "rowBoundaries":[{{"field":"{field_id}","claim":"claim","operator":"equals"}}]
                }}]
              }}]
            }}"#
        );
        let project = parse_project_json(source.as_bytes()).expect("source shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("unsupported row-boundary field type fails compilation");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "access_profile.row_boundary.type_unsupported"
        }));
    }
}

#[test]
fn closed_constraint_grammar_compiles_typed_checks_and_refuses_expression_escape_hatches() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"constraint-matrix","version":"1","defaultLanguage":"en"},
          "entities":[
            {"id":"parent","route":"parents","mutationMode":"create_only"},
            {
              "id":"record","route":"records","mutationMode":"create_only",
              "fields":[
                {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"internal"},
                {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
                {"id":"revoked-at","type":"timestamp","classification":"internal"},
                {"id":"status","type":"vocabulary-code","vocabulary":"status","required":true,"classification":"internal"},
                {"id":"count","type":"int64","required":true,"classification":"internal"},
                {"id":"capacity","type":"int64","required":true,"classification":"internal"},
                {"id":"floor","type":"int64","required":true,"classification":"internal"},
                {"id":"ceiling","type":"int64","required":true,"classification":"internal"},
                {"id":"starts-on","type":"date","required":true,"classification":"internal"},
                {"id":"ends-on","type":"date","required":true,"classification":"internal"},
                {"id":"observed-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"expires-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"quantity","type":"int64","required":true,"classification":"internal"},
                {"id":"amount","type":"decimal","precision":8,"scale":2,"minimum":"-100.00","maximum":"100.00","classification":"internal"},
                {"id":"parent","type":"reference","target":"parent","onDelete":"restrict","required":true,"classification":"internal"},
                {"id":"alternate-parent","type":"reference","target":"parent","onDelete":"restrict","classification":"internal"},
                {"id":"scope","type":"string","maxLength":32,"required":true,"classification":"internal"},
                {"id":"valid-from","type":"timestamp","validTimeRole":"valid_from","required":true,"classification":"internal"},
                {"id":"valid-to","type":"timestamp","validTimeRole":"valid_to","classification":"internal"}
              ],
              "temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["scope"]},
              "constraints":[
                {"id":"composite-key","kind":"unique","fields":["jurisdiction","code"]},
                {"id":"active-code","kind":"unique","fields":["code"],"when":[
                  {"kind":"field_equals","field":"status","value":"active"},
                  {"kind":"field_is_null","field":"revoked-at"},
                  {"kind":"active_lifecycle"}
                ]},
                {"id":"int-less","kind":"compare","left":"count","operator":"less_than","right":"capacity"},
                {"id":"date-less-or-equal","kind":"compare","left":"starts-on","operator":"less_than_or_equal","right":"ends-on"},
                {"id":"timestamp-greater","kind":"compare","left":"expires-at","operator":"greater_than","right":"observed-at"},
                {"id":"int-greater-or-equal","kind":"compare","left":"ceiling","operator":"greater_than_or_equal","right":"floor"},
                {"id":"quantity-range","kind":"int_range","field":"quantity","minimum":0,"maximum":100},
                {"id":"status-membership","kind":"vocabulary","field":"status","values":["active","paused"]},
                {"id":"scope-time","kind":"temporal-non-overlap","scopeFields":["scope"],"startField":"valid-from","endField":"valid-to"}
              ]
            }
          ],
          "vocabularies":[{"id":"status","values":["active","paused","closed"]}]
        }"#,
    )
    .expect("the closed typed constraint matrix parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("the closed typed constraint matrix compiles");
    let record = &compiled.entities()["record"];

    let kinds = record
        .constraints
        .values()
        .map(|constraint| match constraint {
            ConstraintSource::Unique { when: None, .. } => "composite-unique",
            ConstraintSource::Unique { when: Some(_), .. } => "partial-unique",
            ConstraintSource::Compare { .. } => "compare",
            ConstraintSource::IntRange { .. } => "int-range",
            ConstraintSource::Vocabulary { .. } => "vocabulary",
            ConstraintSource::TemporalNonOverlap { .. } => "temporal-non-overlap",
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        kinds,
        [
            "compare",
            "composite-unique",
            "int-range",
            "partial-unique",
            "temporal-non-overlap",
            "vocabulary",
        ]
        .into_iter()
        .collect()
    );
    assert!(matches!(
        &record.constraints["composite-key"],
        ConstraintSource::Unique { fields, when: None, .. }
            if fields == &["jurisdiction".to_owned(), "code".to_owned()]
    ));
    assert!(matches!(
        &record.constraints["active-code"],
        ConstraintSource::Unique { fields, when: Some(when), .. }
            if fields == &["code".to_owned()] && when.len() == 3
    ));

    let comparison_operators = record
        .constraints
        .values()
        .filter_map(|constraint| match constraint {
            ConstraintSource::Compare { operator, .. } => Some(match operator {
                ComparisonOperator::LessThan => "less_than",
                ComparisonOperator::LessThanOrEqual => "less_than_or_equal",
                ComparisonOperator::GreaterThan => "greater_than",
                ComparisonOperator::GreaterThanOrEqual => "greater_than_or_equal",
            }),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        comparison_operators,
        [
            "greater_than",
            "greater_than_or_equal",
            "less_than",
            "less_than_or_equal",
        ]
        .into_iter()
        .collect()
    );

    for (field, required) in [("parent", true), ("alternate-parent", false)] {
        let compiled_field = &record.fields[field];
        assert_eq!(compiled_field.required, required);
        assert!(matches!(
            &compiled_field.field_type,
            FieldTypeSource::Reference {
                target,
                on_delete: ReferenceDelete::Restrict,
            } if target == "parent"
        ));
        let reference = compiled
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.id == format!("entity.record.field.{field}.reference"))
            .expect("each reference has compiler-owned DDL");
        assert_eq!(reference.kind, DdlStatementKind::Reference);
        assert!(reference.sql.ends_with("ON DELETE RESTRICT"));
    }

    let table = compiled
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.record.table")
        .expect("record table DDL exists");
    let optional_reference = &record.fields["alternate-parent"].physical_name;
    assert!(table
        .sql
        .contains(&format!("\"{optional_reference}\" uuid")));
    assert!(!table
        .sql
        .contains(&format!("\"{optional_reference}\" uuid NOT NULL")));
    let amount = &record.fields["amount"].physical_name;
    assert!(table.sql.contains(&format!(
        "\"{amount}\" numeric(8,2) CHECK (\"{amount}\" >= -100.00 AND \"{amount}\" <= 100.00)"
    )));

    let statement = |id: &str| {
        compiled
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.id == format!("entity.record.constraint.{id}"))
            .unwrap_or_else(|| panic!("constraint DDL exists for {id}"))
    };
    assert!(statement("composite-key").sql.contains(" UNIQUE ("));
    assert!(statement("active-code")
        .sql
        .starts_with("CREATE UNIQUE INDEX "));
    for id in [
        "int-less",
        "date-less-or-equal",
        "timestamp-greater",
        "int-greater-or-equal",
        "quantity-range",
        "status-membership",
    ] {
        assert!(statement(id).sql.contains(" CHECK ("));
    }
    assert!(statement("quantity-range").sql.contains(" >= 0 AND "));
    assert!(statement("quantity-range").sql.contains(" <= 100"));
    assert!(statement("status-membership")
        .sql
        .contains(" IN ('active', 'paused')"));
    assert!(statement("scope-time").sql.contains("EXCLUDE USING gist"));
    assert!(statement("scope-time").sql.contains("tstzrange"));
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.id == "entity.record.constraint.temporal-order"
            && statement.sql.contains(" IS NULL OR ")
            && statement.sql.contains(" < ")
    }));

    for (constraint, canary) in [
        (
            r#"{"kind":"check","expression":"sql-expression-canary"}"#,
            "sql-expression-canary",
        ),
        (
            r#"{"kind":"compare","left":"left","operator":"less_than","right":"right","sql":"sql-fragment-canary"}"#,
            "sql-fragment-canary",
        ),
        (
            r#"{"kind":"int_range","field":"left","minimum":0,"expression":"general-expression-canary"}"#,
            "general-expression-canary",
        ),
    ] {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"constraint-matrix","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"record","route":"records","mutationMode":"create_only",
                "fields":[
                  {{"id":"left","type":"int64","classification":"internal"}},
                  {{"id":"right","type":"int64","classification":"internal"}}
                ],
                "constraints":[{constraint}]
              }}]
            }}"#
        );
        let failure = parse_project_json(source.as_bytes())
            .expect_err("SQL and general expression forms fail strict parsing");
        assert_eq!(failure.diagnostics()[0].code, "source.shape.invalid");
        let rendered = format!(
            "{failure:?}\n{failure}\n{}",
            serde_json::to_string(&failure).expect("diagnostic serializes")
        );
        assert!(!rendered.contains(canary));
    }

    let cascade = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"constraint-matrix","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"record","route":"records","mutationMode":"create_only",
            "fields":[{"id":"cascade-reference-canary","type":"reference","target":"record","onDelete":"cascade","classification":"internal"}]
          }]
        }"#,
    )
    .expect_err("reference deletion behavior is closed to restrict");
    assert_eq!(cascade.diagnostics()[0].code, "source.shape.invalid");
    let rendered = format!(
        "{cascade:?}\n{cascade}\n{}",
        serde_json::to_string(&cascade).expect("diagnostic serializes")
    );
    assert!(!rendered.contains("cascade-reference-canary"));
}

#[test]
fn partial_unique_when_predicates_are_strictly_tagged_and_closed() {
    let unknown_member = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"entry","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
              {"id":"status","type":"vocabulary-code","vocabulary":"status","required":true,"classification":"internal"}
            ],
            "constraints":[{
              "kind":"unique","fields":["code"],
              "when":[{"kind":"field_equals","field":"status","value":"active","sql":"record_lifecycle = 'active'"}]
            }]
          }],
          "vocabularies":[{"id":"status","values":["active","closed"]}]
        }"#,
    )
    .expect_err("predicate members are closed");
    assert_eq!(unknown_member.diagnostics()[0].code, "source.shape.invalid");
    assert!(!serde_json::to_string(&unknown_member)
        .expect("diagnostic serializes")
        .contains("record_lifecycle"));

    let arbitrary_lifecycle = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"entry","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"}],
            "constraints":[{
              "kind":"unique","fields":["code"],
              "when":[{"kind":"active_lifecycle","value":"tombstoned"}]
            }]
          }]
        }"#,
    )
    .expect_err("lifecycle predicates have no caller-provided value");
    assert_eq!(
        arbitrary_lifecycle.diagnostics()[0].code,
        "source.shape.invalid"
    );
}

#[test]
fn partial_unique_typed_literals_are_canonical_for_each_supported_field_type() {
    let source = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"entry","route":"entries","mutationMode":"mutable",
        "fields":[
          {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"flag","type":"boolean","classification":"internal"},
          {"id":"count","type":"int64","classification":"internal"},
          {"id":"amount","type":"decimal","precision":6,"scale":2,"minimum":"0.00","maximum":"9999.99","classification":"internal"},
          {"id":"day","type":"date","classification":"internal"},
          {"id":"seen-at","type":"timestamp","classification":"internal"},
          {"id":"owner","type":"uuid","classification":"internal"},
          {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"internal"}
        ],
        "constraints":[{
          "kind":"unique","fields":["code"],
          "when":[
            {"kind":"field_equals","field":"flag","value":true},
            {"kind":"field_equals","field":"count","value":42},
            {"kind":"field_equals","field":"amount","value":"12.30"},
            {"kind":"field_equals","field":"day","value":"2026-08-29"},
            {"kind":"field_equals","field":"seen-at","value":"2026-08-29T10:20:30Z"},
            {"kind":"field_equals","field":"owner","value":"123e4567-e89b-12d3-a456-426614174000"},
            {"kind":"field_equals","field":"status","value":"active"}
          ]
        }]
      }],
      "vocabularies":[{"id":"status","values":["active","closed"]}]
    }"#;
    let compiled = compile_json(source).expect("canonical literals compile");
    let ddl = compiled.ddl().script();
    assert!(ddl.contains("'true'::boolean"));
    assert!(ddl.contains("'42'::bigint"));
    assert!(ddl.contains("'12.30'::numeric(6,2)"));
    assert!(ddl.contains("'2026-08-29'::date"));
    assert!(ddl.contains("'2026-08-29T10:20:30Z'::timestamptz"));
    assert!(ddl.contains("'123e4567-e89b-12d3-a456-426614174000'::uuid"));
}

#[test]
fn partial_unique_rejects_invalid_literals_and_json_predicate_fields() {
    let cases = [
        (
            r#"{"id":"amount","type":"decimal","precision":6,"scale":2,"classification":"internal"}"#,
            r#"{"kind":"field_equals","field":"amount","value":"1.2"}"#,
            "constraint.unique.when.literal_invalid",
        ),
        (
            r#"{"id":"seen-at","type":"timestamp","classification":"internal"}"#,
            r#"{"kind":"field_equals","field":"seen-at","value":"2026-08-29T10:20:30+00:00"}"#,
            "constraint.unique.when.literal_invalid",
        ),
        (
            r#"{"id":"owner","type":"uuid","classification":"internal"}"#,
            r#"{"kind":"field_equals","field":"owner","value":"123E4567-E89B-12D3-A456-426614174000"}"#,
            "constraint.unique.when.literal_invalid",
        ),
        (
            r#"{"id":"shape","type":"crs84-point","precision":4,"classification":"internal"}"#,
            r#"{"kind":"field_is_not_null","field":"shape"}"#,
            "constraint.unique.when.field_unsupported",
        ),
        (
            r#"{"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{"type":"object","additionalProperties":false}}"#,
            r#"{"kind":"field_equals","field":"payload","value":{}}"#,
            "constraint.unique.when.field_unsupported",
        ),
    ];

    for (field, predicate, code) in cases {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"partial-unique","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"entry","route":"entries","mutationMode":"mutable",
                "fields":[
                  {{"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"}},
                  {field}
                ],
                "constraints":[{{"kind":"unique","fields":["code"],"when":[{predicate}]}}]
              }}]
            }}"#
        );
        let failure = compile_json(source.as_bytes()).expect_err("invalid partial predicate fails");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn partial_unique_rejects_empty_unknown_duplicate_and_contradictory_when_predicates() {
    let cases = [
        ("[]", "constraint.unique.when.empty"),
        (
            r#"[{"kind":"active_lifecycle"},{"kind":"active_lifecycle"}]"#,
            "constraint.unique.when.duplicate",
        ),
        (
            r#"[{"kind":"field_is_null","field":"optional"},{"kind":"field_is_not_null","field":"optional"}]"#,
            "constraint.unique.when.contradiction",
        ),
        (
            r#"[{"kind":"field_equals","field":"optional","value":"one"},{"kind":"field_equals","field":"optional","value":"two"}]"#,
            "constraint.unique.when.contradiction",
        ),
        (
            r#"[{"kind":"field_is_not_null","field":"required"}]"#,
            "constraint.unique.when.null_invalid",
        ),
        (
            r#"[{"kind":"field_equals","field":"missing","value":"one"}]"#,
            "constraint.unique.when.field_unknown",
        ),
    ];

    for (when, code) in cases {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"partial-unique","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"entry","route":"entries","mutationMode":"mutable",
                "fields":[
                  {{"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"}},
                  {{"id":"required","type":"string","maxLength":32,"required":true,"classification":"internal"}},
                  {{"id":"optional","type":"string","maxLength":32,"classification":"internal"}}
                ],
                "constraints":[{{"kind":"unique","fields":["code"],"when":{when}}}]
              }}]
            }}"#
        );
        let failure = compile_json(source.as_bytes()).expect_err("invalid when fails");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn partial_unique_ddl_is_quoted_and_deterministic_across_predicate_order() {
    let left = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"entry","route":"entries","mutationMode":"mutable",
        "fields":[
          {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"ended-on","type":"date","classification":"internal"},
          {"id":"marker","type":"string","maxLength":96,"classification":"internal"}
        ],
        "constraints":[{
          "kind":"unique","fields":["code"],
          "when":[
            {"kind":"active_lifecycle"},
            {"kind":"field_equals","field":"marker","value":"O'Hare'); DROP TABLE registry_data.x; --"},
            {"kind":"field_is_null","field":"ended-on"}
          ]
        }]
      }]
    }"#;
    let right = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"entry","route":"entries","mutationMode":"mutable",
        "fields":[
          {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"ended-on","type":"date","classification":"internal"},
          {"id":"marker","type":"string","maxLength":96,"classification":"internal"}
        ],
        "constraints":[{
          "kind":"unique","fields":["code"],
          "when":[
            {"kind":"field_is_null","field":"ended-on"},
            {"kind":"field_equals","field":"marker","value":"O'Hare'); DROP TABLE registry_data.x; --"},
            {"kind":"active_lifecycle"}
          ]
        }]
      }]
    }"#;

    let left = compile_json(left).expect("left order compiles");
    let right = compile_json(right).expect("right order compiles");
    assert_eq!(left, right);
    let statement = left
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.kind == DdlStatementKind::Index)
        .expect("partial unique renders as an index");
    assert!(statement.sql.starts_with("CREATE UNIQUE INDEX "));
    assert!(statement.sql.contains(" WHERE "));
    assert!(statement
        .sql
        .contains("'O''Hare''); DROP TABLE registry_data.x; --'"));
    assert!(statement.sql.contains(" IS NULL"));
    assert!(statement.sql.ends_with("record_lifecycle = 'active'"));
}

#[test]
fn equivalent_partial_unique_extension_constraints_merge_deterministically() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
          "modules":[{"id":"a","version":"1"},{"id":"b","version":"1"}],
          "entities":[{"id":"entry","route":"entries","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
            {"id":"ended-on","type":"date","classification":"internal"}
          ]}]
        }"#,
    )
    .expect("project parses");
    let a = parse_module_json(
        br#"{"id":"a","version":"1","extendEntities":[{"entity":"entry","constraints":[{
          "kind":"unique","fields":["code"],"when":[{"kind":"active_lifecycle"},{"kind":"field_is_null","field":"ended-on"}]
        }]}]}"#,
    )
    .expect("module parses");
    let b = parse_module_json(
        br#"{"id":"b","version":"1","extendEntities":[{"entity":"entry","constraints":[{
          "kind":"unique","fields":["code"],"when":[{"kind":"field_is_null","field":"ended-on"},{"kind":"active_lifecycle"}]
        }]}]}"#,
    )
    .expect("module parses");

    for modules in [vec![a.clone(), b.clone()], vec![b, a]] {
        let failure = compile_project(&project, &modules, CompileProfile::Authoring)
            .expect_err("equivalent partial unique extensions are duplicates");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "extension.constraint.duplicate"));
    }
}

#[test]
fn anonymous_profiles_cannot_inherit_partial_unique_processing_over_non_public_fields() {
    let source = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"entry","route":"entries","mutationMode":"mutable","classification":"public",
        "fields":[
          {"id":"code","type":"string","maxLength":32,"required":true,"classification":"public"},
          {"id":"protected-marker","type":"string","maxLength":32,"classification":"restricted"}
        ],
        "constraints":[{
          "kind":"unique","fields":["code"],
          "when":[{"kind":"field_is_not_null","field":"protected-marker"}]
        }]
      }],
      "accessProfiles":[{
        "id":"public-reader","anonymous":true,"default":true,"grants":[{
          "entity":"entry","operations":["get"],"readableFields":["code"]
        }]
      }]
    }"#;

    let failure = compile_json(source)
        .expect_err("anonymous profile cannot inherit hidden non-public predicate processing");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "access_profile.public.processing_non_public"
            && diagnostic.path == "entities[].constraints[]"
    }));
}

#[test]
fn anonymous_public_surface_rejects_every_non_public_constraint_field() {
    let source = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"constraint-processing","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"record","route":"records","mutationMode":"mutable","classification":"public",
        "fields":[
          {"id":"label","type":"string","maxLength":32,"required":true,"classification":"public"},
          {"id":"unique-field","type":"string","maxLength":32,"required":true,"classification":"public"},
          {"id":"partial-field","type":"string","maxLength":32,"required":true,"classification":"public"},
          {"id":"predicate-field","type":"string","maxLength":32,"classification":"public"},
          {"id":"compare-left","type":"int64","required":true,"classification":"public"},
          {"id":"compare-right","type":"int64","required":true,"classification":"public"},
          {"id":"range-field","type":"int64","classification":"public"},
          {"id":"vocabulary-field","type":"vocabulary-code","vocabulary":"status","classification":"public"},
          {"id":"temporal-start","type":"date","required":true,"classification":"public"},
          {"id":"temporal-end","type":"date","classification":"public"},
          {"id":"temporal-scope","type":"string","maxLength":32,"required":true,"classification":"public"}
        ],
        "temporal":{"startField":"temporal-start","endField":"temporal-end","scopeFields":["temporal-scope"]},
        "constraints":[
          {"kind":"unique","fields":["unique-field"]},
          {"kind":"unique","fields":["partial-field"],"when":[{"kind":"field_is_not_null","field":"predicate-field"}]},
          {"kind":"compare","left":"compare-left","operator":"less_than","right":"compare-right"},
          {"kind":"int_range","field":"range-field","minimum":0,"maximum":10},
          {"kind":"vocabulary","field":"vocabulary-field","values":["active"]},
          {"kind":"temporal-non-overlap","scopeFields":["temporal-scope"],"startField":"temporal-start","endField":"temporal-end"}
        ]
      }],
      "accessProfiles":[{
        "id":"public-reader","anonymous":true,"default":true,"grants":[{
          "entity":"record","operations":["get"],"readableFields":["label"]
        }]
      }],
      "vocabularies":[{"id":"status","values":["active","inactive"]}]
    }"#;
    let base = parse_project_json(source).expect("closed constraint processing fixture parses");
    compile_project(&base, &[], CompileProfile::Authoring)
        .expect("an anonymous profile may process public constraint fields");

    let cases = [
        ("full unique tuple", "unique-field"),
        ("partial unique tuple", "partial-field"),
        ("partial unique predicate", "predicate-field"),
        ("compare left operand", "compare-left"),
        ("compare right operand", "compare-right"),
        ("integer range", "range-field"),
        ("vocabulary", "vocabulary-field"),
        ("temporal start", "temporal-start"),
        ("temporal end", "temporal-end"),
        ("temporal scope", "temporal-scope"),
    ];
    for (case, field_id) in cases {
        let mut project = base.clone();
        project.entities[0]
            .fields
            .iter_mut()
            .find(|field| field.id == field_id)
            .expect("constraint field exists")
            .classification = Classification::Restricted;

        let failure = compile_project(&project, &[], CompileProfile::Authoring).expect_err(
            "the anonymous public surface cannot process a non-public constraint field",
        );
        let diagnostics = failure
            .diagnostics()
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "access_profile.public.processing_non_public"
                    && diagnostic.path == "entities[].constraints[]"
            })
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1, "missing exact negative for {case}");
        assert_eq!(
            diagnostics[0].message,
            "an anonymous profile is a public surface and may process only public constraint fields"
        );
        assert!(!serde_json::to_string(diagnostics[0])
            .expect("diagnostic serializes")
            .contains(field_id));
    }

    let mut authenticated = base;
    let profile = &mut authenticated.access_profiles[0];
    profile.anonymous = false;
    profile.principal_claim = Some("principal".to_owned());
    for (_, field_id) in cases {
        authenticated.entities[0]
            .fields
            .iter_mut()
            .find(|field| field.id == field_id)
            .expect("constraint field exists")
            .classification = Classification::Restricted;
    }
    compile_project(&authenticated, &[], CompileProfile::Authoring)
        .expect("authenticated entities may process governed non-public constraint fields");
}

#[test]
fn compiled_partial_unique_constraint_keeps_closed_predicates_in_the_model() {
    let source = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en"},
      "entities":[{
        "id":"entry","route":"entries","mutationMode":"mutable","classification":"public",
        "fields":[
          {"id":"code","type":"string","maxLength":32,"required":true,"classification":"public"},
          {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"public"}
        ],
        "constraints":[{
          "kind":"unique","fields":["code"],
          "when":[{"kind":"active_lifecycle"},{"kind":"field_equals","field":"status","value":"active"}]
        }]
      }],
      "accessProfiles":[{
        "id":"public-reader","anonymous":true,"default":true,"grants":[{
          "entity":"entry","operations":["get"],"readableFields":["code","status"],"filterableFields":["status"]
        }]
      }],
      "vocabularies":[{"id":"status","values":["active","closed"]}]
    }"#;

    let compiled = compile_json(source).expect("public partial unique compiles");
    let constraint = compiled
        .entities()
        .get("entry")
        .expect("entity compiled")
        .constraints
        .values()
        .find(|constraint| matches!(constraint, ConstraintSource::Unique { .. }))
        .expect("unique constraint compiled");
    assert!(matches!(
        constraint,
        ConstraintSource::Unique {
            when: Some(when),
            ..
        } if when == &[
            UniqueWhenPredicate::FieldEquals {
                field: "status".to_owned(),
                value: Value::String("active".to_owned()),
            },
            UniqueWhenPredicate::ActiveLifecycle {},
        ]
    ));
}

#[test]
fn create_only_operation_conflict_fails_before_artifact_generation() {
    let mut project = asset_project();
    let profile = project
        .access_profiles
        .first_mut()
        .expect("fixture has an access profile");
    let grant = profile
        .grants
        .iter_mut()
        .find(|grant| grant.entity == "inspection-event")
        .expect("fixture grants the create-only entity");
    grant.operations.insert(Operation::Patch);

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("create-only patch is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "access_profile.operation.unavailable"));
}

#[test]
fn generated_openapi_routes_and_physical_names_share_one_compiled_inventory() {
    let compiled = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let value = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    assert_eq!(
        canonicalize_json(&value).expect("OpenAPI canonicalizes"),
        openapi.bytes
    );
    let generated_operation_count: usize = value["paths"]
        .as_object()
        .expect("paths is an object")
        .values()
        .map(|entry| entry.as_object().expect("path item is an object").len())
        .sum();
    assert_eq!(generated_operation_count, compiled.routes().routes.len());
    assert_eq!(
        value["components"]["securitySchemes"]["bearerAuth"],
        json!({"type": "http", "scheme": "bearer", "bearerFormat": "JWT"})
    );
    assert_eq!(
        value["components"]["schemas"]["Problem"]["properties"]["code"]["enum"],
        json!([
            "authentication.refused",
            "idempotency.conflict",
            "lookup.unresolved",
            "mutation.conflict",
            "precondition.failed",
            "precondition.required",
            "query.cursor_invalid",
            "query.invalid",
            "request.conflict",
            "request.invalid",
            "request.timeout",
            "resource.not_found",
            "service.unavailable",
            "source.unavailable",
            "unsupported.media_type"
        ])
    );
    assert_eq!(
        value["components"]["schemas"]["Problem"]["required"],
        json!(["type", "title", "status", "detail", "code", "traceId"])
    );
    assert_eq!(
        value["components"]["schemas"]["Problem"]["properties"]["traceId"]["pattern"],
        "^[0-9a-f]{32}$"
    );

    let list = &value["paths"]["/v1/records/assets"]["get"];
    assert_eq!(list["security"], json!([{"bearerAuth": []}]));
    assert!(list["responses"]["200"]["headers"]
        .get("traceparent")
        .is_some());
    assert!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["required"]
            .as_array()
            .expect("list response required members")
            .contains(&json!("pageInfo"))
    );
    assert!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            .get("count")
            .is_some()
    );
    assert!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            .get("totalCount")
            .is_none()
    );
    assert_eq!(
        list["x-registry-queryProfiles"]["asset-operator"]["selectableProperties"],
        json!(["assetClass", "assetCode", "label"])
    );
    assert_eq!(
        list["x-registry-queryProfiles"]["site-planner"]["selectableProperties"],
        json!(["assetCode", "label"])
    );
    assert!(list["x-registry-queryProfiles"]["asset-operator"]["filterableProperties"].is_array());

    let detail = &value["paths"]["/v1/records/assets/{record_id}"]["get"];
    assert_eq!(
        query_parameter_names(&detail["parameters"]),
        ["$select", "accessProfile", "record_id", "traceparent"]
    );
    assert!(detail["responses"]["200"]["headers"].get("ETag").is_some());
    assert!(detail["responses"]["200"]["headers"]
        .get("traceparent")
        .is_some());
    assert!(detail["responses"]["504"]["headers"]
        .get("traceparent")
        .is_some());
    assert_eq!(
        detail["responses"]["504"]["content"]["application/problem+json"]["examples"]
            ["request.timeout"]["value"]["traceId"],
        "11111111111111111111111111111111"
    );
    assert_eq!(
        detail["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["data"],
        json!({"$ref": "#/components/schemas/asset-item"})
    );

    let create = &value["paths"]["/v1/records/assets"]["post"];
    assert_eq!(
        query_parameter_names(&create["parameters"]),
        ["Idempotency-Key", "accessProfile", "traceparent"]
    );
    assert!(create["responses"]["201"]["headers"].get("ETag").is_some());
    assert!(create["responses"]["201"]["headers"]
        .get("Location")
        .is_some());
    assert!(create["responses"]["201"]["headers"]
        .get("traceparent")
        .is_some());
    assert_eq!(
        create["requestBody"]["content"]["application/json"]["schema"]["properties"]["data"],
        json!({"$ref": "#/components/schemas/asset-item-create-input"})
    );

    let patch = &value["paths"]["/v1/records/assets/{record_id}"]["patch"];
    assert_eq!(
        query_parameter_names(&patch["parameters"]),
        [
            "Idempotency-Key",
            "If-Match",
            "accessProfile",
            "record_id",
            "traceparent"
        ]
    );
    assert!(patch["requestBody"]["content"]
        .get("application/json-patch+json")
        .is_some());
    assert!(patch["responses"]["428"]["headers"]
        .get("traceparent")
        .is_some());
    assert!(
        patch["responses"]["428"]["content"]["application/problem+json"]["schema"]
            .get("$ref")
            .is_some()
    );

    for names in compiled.physical_names().entities.values() {
        let all = std::iter::once(&names.table)
            .chain(names.fields.values())
            .chain(names.constraints.values())
            .chain(names.indexes.values())
            .chain(names.policies.values());
        for name in all {
            assert!(name.len() <= 63);
            assert!(name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
        }
    }
}

#[test]
fn generated_openapi_separates_security_and_mutation_input_from_read_schema() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"business-contract","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"business-record","route":"business-records","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"code","type":"string","required":true,"maxLength":32,"classification":"public"},
              {"id":"business-note","apiName":"businessNote","type":"string","maxLength":80,"classification":"public"},
              {"id":"draft-note","apiName":"draftNote","type":"string","maxLength":80,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"public",
            "default":true,
            "anonymous":true,
            "grants":[{
              "entity":"business-record",
              "operations":["get","list"],
              "readableFields":["code","business-note"]
            }]
          },{
            "id":"business",
            "principalClaim":"registry_principal",
            "requiredPurposes":["business"],
            "grants":[{
              "entity":"business-record",
              "operations":["create","get"],
              "readableFields":["code","business-note"],
              "writableFields":["code","draft-note"]
            }]
          }]
        }"#,
    )
    .expect("business contract compiles");
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");

    assert_eq!(
        openapi["paths"]["/v1/records/business-records/{record_id}"]["get"]["security"],
        json!([{}, {"bearerAuth": []}])
    );
    assert_eq!(
        openapi["paths"]["/v1/records/business-records"]["post"]["security"],
        json!([{"bearerAuth": []}])
    );
    assert_eq!(
        openapi["paths"]["/v1/records/business-records"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["data"],
        json!({"$ref": "#/components/schemas/business-record-create-input"})
    );
    assert_eq!(
        openapi["paths"]["/v1/records/business-records"]["post"]["responses"]["201"]["content"]
            ["application/json"]["schema"]["properties"]["data"],
        json!({"$ref": "#/components/schemas/business-record"})
    );
    assert_eq!(
        openapi["components"]["schemas"]["business-record-create-input"]["properties"],
        json!({
            "code": {"type": "string", "minLength": 0, "maxLength": 32},
            "draftNote": {"type": "string", "minLength": 0, "maxLength": 80}
        })
    );
    assert_eq!(
        openapi["components"]["schemas"]["business-record-create-input"]["required"],
        json!(["code"])
    );
    assert!(
        openapi["components"]["schemas"]["business-record"]["properties"]
            .get("businessNote")
            .is_some()
    );
    assert_ne!(
        openapi["components"]["schemas"]["business-record-create-input"]["properties"],
        openapi["components"]["schemas"]["business-record"]["properties"]
    );
}

#[test]
fn entity_schema_uses_compiled_api_names_and_preserves_field_contracts() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"logical-schema","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"household","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","type":"string","required":true,"maxLength":64,"classification":"restricted"},
              {"id":"household-kind-code","apiName":"householdKind","type":"vocabulary-code","vocabulary":"household-kind","required":true,"classification":"restricted"},
              {"id":"case-note","apiName":"caseNoteText","type":"text","maxLength":200,"classification":"restricted"}
            ]
          }],
          "vocabularies":[{"id":"household-kind","values":["single","extended"]}]
        }"#,
    )
    .expect("logical field names compile");
    let artifact = compiled
        .artifacts()
        .get("generated/schemas/household.schema.json")
        .expect("entity schema is generated");
    let schema: Value = parse_json_strict(&artifact.bytes).expect("entity schema is strict JSON");

    assert_eq!(
        schema["properties"],
        json!({
            "caseNoteText": {"type": "string", "maxLength": 200},
            "householdCode": {"type": "string", "minLength": 0, "maxLength": 64},
            "householdKind": {
                "type": "string",
                "enum": ["single", "extended"],
                "x-registry-vocabulary": "household-kind"
            }
        })
    );
    assert_eq!(
        schema["required"],
        json!(["householdCode", "householdKind"])
    );
    for internal_id in ["household-code", "household-kind-code", "case-note"] {
        assert!(schema["properties"].get(internal_id).is_none());
    }
}

#[test]
fn compiled_metadata_inventory_is_bijective_canonical_schema_bound_and_deterministic() {
    let first = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let second = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles twice");

    assert_eq!(first.metadata(), second.metadata());
    let expected_route_profiles = first
        .routes()
        .routes
        .iter()
        .flat_map(|route| {
            route
                .access_profiles
                .iter()
                .map(move |profile| (route.id.clone(), profile.clone()))
        })
        .collect::<BTreeSet<_>>();
    let actual_route_profiles = first
        .metadata()
        .entities
        .iter()
        .flat_map(|entity| {
            entity
                .entries
                .iter()
                .map(|entry| (entry.route_id.clone(), entry.access_profile.clone()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_route_profiles, expected_route_profiles,
        "metadata entries must be in bijection with compiled route/profile pairs"
    );

    for metadata_entity in &first.metadata().entities {
        let entity = first
            .entities()
            .get(&metadata_entity.id)
            .expect("metadata entity refers to a compiled entity");
        assert_eq!(metadata_entity.route, entity.route);
        assert_eq!(
            metadata_entity.schema_path,
            format!("/v1/schemas/{}", metadata_entity.id)
        );
        assert!(first
            .artifacts()
            .get(&format!(
                "generated/schemas/{}.schema.json",
                metadata_entity.id
            ))
            .is_some());
        for entry in &metadata_entity.entries {
            let route = first
                .routes()
                .routes
                .iter()
                .find(|route| route.id == entry.route_id)
                .expect("metadata route id refers to a compiled route");
            assert_eq!(route.entity_id, metadata_entity.id);
            assert_eq!(route.operation, entry.operation);
            assert!(route.access_profiles.contains(&entry.access_profile));
            let profile = entity
                .access_profiles
                .get(&entry.access_profile)
                .expect("metadata access profile refers to a compiled profile");
            assert!(entry.readable_fields.is_subset(&profile.readable_fields));
            if profile.anonymous {
                assert!(entry.readable_fields.iter().all(|field| {
                    entity
                        .fields
                        .get(field)
                        .is_some_and(|field| field.classification == Classification::Public)
                }));
            }
        }
    }

    for path in [
        "compiled/metadata-inventory.json",
        REGISTRY_METADATA_ARTIFACT_PATH,
    ] {
        let first_artifact = first
            .artifacts()
            .get(path)
            .expect("metadata artifact exists");
        let second_artifact = second
            .artifacts()
            .get(path)
            .expect("metadata artifact exists on recompilation");
        assert_eq!(first_artifact.bytes, second_artifact.bytes);
        let value = parse_json_strict(&first_artifact.bytes).expect("metadata is strict JSON");
        assert_eq!(
            canonicalize_json(&value).expect("metadata canonicalizes"),
            first_artifact.bytes
        );
        assert!(value.get("revision").is_none());
        let parsed: CompiledMetadataInventory =
            serde_json::from_value(value).expect("metadata artifact has the typed schema");
        assert_eq!(&parsed, first.metadata());
    }
}

#[test]
fn compiler_produces_both_revision_routes_when_explicitly_configured() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"revision-surface","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"entry","route":"entries","mutationMode":"create_only","classification":"internal",
            "fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"auditor","default":true,"principalClaim":"principal","grants":[{
              "entity":"entry","operations":["revisions"],"revisionAccess":true,"readableFields":["code"]
            }]
          }]
        }"#,
    )
    .expect("explicit authenticated revision access compiles");
    let routes = compiled
        .routes()
        .routes
        .iter()
        .filter(|route| route.operation == Operation::Revisions)
        .collect::<Vec<_>>();
    assert_eq!(routes.len(), 2);
    let list = routes
        .iter()
        .find(|route| route.revision_kind == Some(CompiledRevisionKind::List))
        .expect("revision list route exists");
    assert_eq!(list.id, "records.entry.revisions.list");
    assert_eq!(list.path, "/v1/records/entries/{record_id}/revisions");
    assert_eq!(list.maximum_records, Some(MAX_REVISION_HISTORY_RECORDS));
    let detail = routes
        .iter()
        .find(|route| route.revision_kind == Some(CompiledRevisionKind::Detail))
        .expect("revision detail route exists");
    assert_eq!(detail.id, "records.entry.revisions.detail");
    assert_eq!(
        detail.path,
        "/v1/records/entries/{record_id}/revisions/{revision}"
    );
    assert_eq!(detail.maximum_records, Some(1));

    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    assert_eq!(
        openapi["paths"]["/v1/records/entries/{record_id}/revisions"]["get"]["operationId"],
        "records.entry.revisions.list"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/entries/{record_id}/revisions/{revision}"]["get"]
            ["operationId"],
        "records.entry.revisions.detail"
    );
    assert_eq!(
        query_parameter_names(
            &openapi["paths"]["/v1/records/entries/{record_id}/revisions"]["get"]["parameters"]
        ),
        ["accessProfile", "record_id", "traceparent"]
    );
}

#[test]
fn compiler_omits_revision_routes_when_not_configured_or_revision_access_is_false() {
    for (operations, revision_access, anonymous, principal_claim) in [
        (
            r#"["get"]"#,
            "true",
            "false",
            r#""principalClaim":"principal","#,
        ),
        (
            r#"["revisions"]"#,
            "false",
            "false",
            r#""principalClaim":"principal","#,
        ),
        (r#"["revisions"]"#, "true", "true", ""),
    ] {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"revision-surface","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"entry","route":"entries","mutationMode":"create_only","classification":"public",
                "fields":[{{"id":"code","type":"string","maxLength":32,"classification":"public"}}]
              }}],
              "accessProfiles":[{{
                "id":"reader","default":true,"anonymous":{anonymous},{principal_claim}"grants":[{{
                  "entity":"entry","operations":{operations},"revisionAccess":{revision_access},"readableFields":["code"]
                }}]
              }}]
            }}"#
        );
        let compiled = compile_json(source.as_bytes()).expect("fixture compiles");
        assert!(compiled
            .routes()
            .routes
            .iter()
            .all(|route| route.operation != Operation::Revisions));
        let openapi = compiled
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated");
        let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
        assert!(openapi["paths"]
            .as_object()
            .expect("paths object")
            .keys()
            .all(|path| !path.contains("revisions")));
    }
}

#[test]
fn public_profile_cannot_process_an_internal_field() {
    let mut project = asset_project();
    project.access_profiles[0].default = true;
    let entity = project
        .entities
        .iter()
        .find(|entity| entity.id == "asset-item")
        .expect("asset entity exists");
    assert!(entity.fields.iter().any(|field| field.id == "asset-code"));
    project.access_profiles.push(ProjectAccessProfileSource {
        id: "public-reader".to_owned(),
        default: false,
        anonymous: true,
        principal_claim: None,
        required_scopes: Default::default(),
        required_purposes: Default::default(),
        grants: vec![AccessGrantSource {
            entity: "asset-item".to_owned(),
            action: None,
            operations: [Operation::Get].into_iter().collect(),
            readable_fields: ["asset-code".to_owned()].into_iter().collect(),
            writable_fields: Default::default(),
            filterable_fields: Default::default(),
            sortable_fields: Default::default(),
            row_boundaries: vec![RowBoundarySource {
                field: "asset-code".to_owned(),
                claim: "asset_code".to_owned(),
                operator: BoundaryOperator::Equals,
            }],
            lookups: Vec::new(),
            read_paths: Vec::new(),
            review_stages: Vec::new(),
            apply_targets: Vec::new(),
            request_presence: Vec::new(),
            targets: Vec::new(),
            results: Default::default(),
            allow_count: false,
            allow_data_export: false,
            revision_access: false,
        }],
    });

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("anonymous processing of internal data is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "access_profile.public.processing_non_public" }));
}

#[test]
fn anonymous_public_profile_cannot_filter_a_non_public_field() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"public-filter","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"entry","route":"entries","mutationMode":"create_only","classification":"public",
            "fields":[
              {"id":"label","type":"string","maxLength":32,"classification":"public"},
              {"id":"hidden-filter-canary","type":"string","maxLength":32,"classification":"restricted"}
            ]
          }],
          "accessProfiles":[{
            "id":"public-reader","anonymous":true,"default":true,"grants":[{
              "entity":"entry","operations":["list"],"readableFields":["label"],
              "filterableFields":["hidden-filter-canary"]
            }]
          }]
        }"#,
    )
    .expect_err("an anonymous filter cannot process a non-public field");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "access_profile.public.processing_non_public"
            && diagnostic.path == "entities[].accessProfiles[]"
    }));
    let rendered = serde_json::to_string(&failure).expect("diagnostics serialize");
    assert!(!rendered.contains("hidden-filter-canary"));
}

#[test]
fn unresolved_reference_is_value_free_and_fails_before_ddl() {
    let mut project = asset_project();
    let field = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "inspection-event")
        .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
        .expect("reference field exists");
    if let registry_server::contract::FieldTypeSource::Reference { target, .. } =
        &mut field.field_type
    {
        *target = "classified-target-name".to_owned();
    } else {
        panic!("fixture field is a reference");
    }
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("unresolved reference fails compilation");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "field.reference.target_unknown"));
    assert!(!serde_json::to_string(&failure)
        .expect("diagnostics serialize")
        .contains("classified-target-name"));
}

#[test]
fn additive_module_conflicts_fail_instead_of_using_input_precedence() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
          "modules":[{"id":"core","version":"1"},{"id":"a","version":"1"},{"id":"b","version":"1"}],
          "entities":[{"id":"object","route":"objects","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","maxLength":8,"classification":"internal"}
          ]}],
          "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","grants":[{"entity":"object","operations":["get"],"readableFields":["code"]}]}]
        }"#,
    )
    .expect("project parses");
    let a = parse_module_json(
        br#"{"id":"a","version":"1","dependencies":["core"],"extendEntities":[{"entity":"object","fields":[{"id":"collision","type":"boolean","classification":"internal"}]}]}"#,
    )
    .expect("module parses");
    let b = parse_module_json(
        br#"{"id":"b","version":"1","dependencies":["core"],"extendEntities":[{"entity":"object","fields":[{"id":"collision","type":"int64","classification":"internal"}]}]}"#,
    )
    .expect("module parses");
    for modules in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
        let failure = compile_project(&project, &modules, CompileProfile::Authoring)
            .expect_err("conflicting additive extensions fail");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "extension.field.duplicate"));
    }
}

#[test]
fn operation_ids_preserve_distinct_valid_entity_ids_without_collisions() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
          "entities":[
            {"id":"case-file","route":"case-files","mutationMode":"create_only","fields":[
              {"id":"code","type":"string","maxLength":8,"classification":"internal"}
            ]},
            {"id":"case_file","route":"case_file_records","mutationMode":"create_only","fields":[
              {"id":"code","type":"string","maxLength":8,"classification":"internal"}
            ]}
          ],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","grants":[
            {"entity":"case-file","operations":["get"],"readableFields":["code"]},
            {"entity":"case_file","operations":["get"],"readableFields":["code"]}
          ]}]
        }"#,
    )
    .expect("project parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("both valid entity identifiers compile");
    let operation_ids: Vec<_> = compiled
        .routes()
        .routes
        .iter()
        .map(|route| route.id.as_str())
        .collect();
    let unique: std::collections::BTreeSet<_> = operation_ids.iter().copied().collect();

    assert_eq!(unique.len(), operation_ids.len());
    assert!(unique.contains("records.case-file.get"));
    assert!(unique.contains("records.case_file.get"));
}

#[test]
fn temporal_non_overlap_refuses_a_nullable_scope_field() {
    let mut project = asset_project();
    let scope = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "asset-placement")
        .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
        .expect("temporal scope field exists");
    scope.required = false;

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("nullable temporal scope is refused before DDL generation");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "constraint.temporal.scope_nullable")
        .expect("nullable temporal scope has a stable diagnostic");
    assert_eq!(diagnostic.path, "entities[].constraints[].scopeFields");
    assert!(!serde_json::to_string(diagnostic)
        .expect("diagnostic serializes")
        .contains("asset-placement"));
}

#[test]
fn temporal_non_overlap_refuses_structured_and_crs84_point_scope_fields() {
    let unsupported = [
        FieldTypeSource::Structured {
            max_bytes: 128,
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "scope-canary": {"type": "string"}
                }
            }),
        },
        FieldTypeSource::Crs84Point {
            precision: 4,
            bbox: None,
        },
    ];

    for field_type in unsupported {
        let mut project = asset_project();
        let scope = project
            .entities
            .iter_mut()
            .find(|entity| entity.id == "asset-placement")
            .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
            .expect("temporal scope field exists");
        scope.field_type = field_type;

        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("jsonb temporal scopes are refused before DDL generation");
        let diagnostics = failure
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "constraint.temporal.scope_type_unsupported")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = diagnostics[0];
        assert_eq!(diagnostic.path, "entities[].constraints[].scopeFields");
        assert_eq!(
            diagnostic.message,
            "a temporal non-overlap scope field must use a supported scalar type"
        );
        let serialized = serde_json::to_string(diagnostic).expect("diagnostic serializes");
        for value in ["asset-placement", "asset-item", "scope-canary"] {
            assert!(!serialized.contains(value));
        }
    }
}

#[test]
fn temporal_non_overlap_accepts_every_btree_gist_equality_scalar_scope_type() {
    let supported = [
        FieldTypeSource::Boolean,
        FieldTypeSource::String {
            min_length: 0,
            max_length: 32,
        },
        FieldTypeSource::Text { max_length: 32 },
        FieldTypeSource::Int64,
        FieldTypeSource::Decimal {
            precision: 8,
            scale: 2,
            minimum: None,
            maximum: None,
        },
        FieldTypeSource::Date,
        FieldTypeSource::Timestamp,
        FieldTypeSource::Uuid,
        FieldTypeSource::VocabularyCode {
            vocabulary: "asset-classification".to_owned(),
            values: Vec::new(),
        },
        FieldTypeSource::Reference {
            target: "asset-item".to_owned(),
            on_delete: ReferenceDelete::Restrict,
        },
    ];

    for field_type in supported {
        let mut project = asset_project();
        let scope = project
            .entities
            .iter_mut()
            .find(|entity| entity.id == "asset-placement")
            .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
            .expect("temporal scope field exists");
        scope.field_type = field_type;

        let compiled = compile_project(&project, &[], CompileProfile::Authoring)
            .expect("every btree_gist equality scalar compiles as a temporal scope");
        assert!(compiled.ddl().script().contains("EXCLUDE USING gist"));
    }
}

#[test]
fn compiled_query_inventory_is_profile_scoped_bounded_and_temporal() {
    let mut project = asset_project();
    let grant = project
        .access_profiles
        .first_mut()
        .expect("fixture has an access profile")
        .grants
        .iter_mut()
        .find(|grant| grant.entity == "asset-placement")
        .expect("fixture grants placement access");
    grant.filterable_fields = ["asset".to_owned(), "valid-from".to_owned()]
        .into_iter()
        .collect();
    grant.sortable_fields = ["valid-from".to_owned()].into_iter().collect();

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("temporal list fixture compiles");
    let temporal = compiled
        .entities()
        .get("asset-placement")
        .expect("placement entity compiled")
        .temporal
        .as_ref()
        .expect("temporal declaration is preserved in the compiled model");
    assert_eq!(temporal.start_field, "valid-from");
    assert_eq!(temporal.end_field, "valid-to");

    let operations = &compiled.queries().operations;
    let route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.asset-placement.list")
        .expect("base list route is compiled");
    assert_eq!(route.path, "/v1/records/placements");
    assert_eq!(route.query_kind, Some(CompiledQueryKind::List));
    let current_route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.asset-placement.current")
        .expect("current temporal route is compiled");
    assert_eq!(current_route.path, "/v1/records/placements:current");
    assert_eq!(current_route.query_kind, Some(CompiledQueryKind::Current));
    let as_of_route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.asset-placement.as-of")
        .expect("as-of temporal route is compiled");
    assert_eq!(as_of_route.path, "/v1/records/placements:as-of");
    assert_eq!(as_of_route.query_kind, Some(CompiledQueryKind::AsOf));
    assert!(compiled.routes().routes.iter().all(|route| {
        !matches!(
            route.entity_id.as_str(),
            "asset-item" | "asset-site" | "inspection-event"
        ) || route.query_kind != Some(CompiledQueryKind::Current)
            && route.query_kind != Some(CompiledQueryKind::AsOf)
    }));

    let base = operations
        .iter()
        .find(|operation| operation.id == "records.asset-placement.asset-operator.list")
        .expect("base list query is compiled");
    assert_eq!(base.kind, CompiledQueryKind::List);
    assert_eq!(base.route_id, "records.asset-placement.list");
    assert_eq!(base.profile_id, "asset-operator");
    assert_eq!(base.max_page_size, 100);
    assert_eq!(base.stable_tie_breaker, "record_id");
    assert_eq!(
        base.projection_fields,
        ["asset", "site", "valid-from", "valid-to"]
    );
    assert!(base.temporal.is_none());
    assert_eq!(base.sort_fields.len(), 1);
    assert_eq!(base.sort_fields[0].field, "valid-from");
    assert_eq!(
        base.sort_fields[0].directions,
        [CompiledQuerySortDirection::Asc]
    );
    let valid_from_filter = base
        .filter_fields
        .iter()
        .find(|field| field.field == "valid-from")
        .expect("configured date filter is present");
    assert!(valid_from_filter
        .operators
        .contains(&CompiledQueryFilterOperator::Range));
    let asset_filter = base
        .filter_fields
        .iter()
        .find(|field| field.field == "asset")
        .expect("configured reference filter is present");
    assert!(asset_filter
        .operators
        .contains(&CompiledQueryFilterOperator::Equals));
    assert!(!asset_filter
        .operators
        .contains(&CompiledQueryFilterOperator::Prefix));

    let current = operations
        .iter()
        .find(|operation| operation.id == "records.asset-placement.asset-operator.current")
        .expect("current temporal query is compiled");
    let as_of = operations
        .iter()
        .find(|operation| operation.id == "records.asset-placement.asset-operator.as-of")
        .expect("as-of temporal query is compiled");
    assert_eq!(current.kind, CompiledQueryKind::Current);
    assert_eq!(as_of.kind, CompiledQueryKind::AsOf);
    assert_eq!(current.route_id, "records.asset-placement.current");
    assert_eq!(as_of.route_id, "records.asset-placement.as-of");
    for operation in [current, as_of] {
        let binding = operation
            .temporal
            .as_ref()
            .expect("temporal query carries a fixed temporal binding");
        assert_eq!(binding.start_field, "valid-from");
        assert_eq!(binding.end_field, "valid-to");
        assert_eq!(binding.scope_fields, ["asset"]);
        assert_eq!(
            binding.semantics,
            CompiledQueryTemporalSemantics::StartInclusiveEndExclusive
        );
    }

    assert!(compiled
        .artifacts()
        .get("compiled/query-inventory.json")
        .is_some());
    let effective = compiled
        .artifacts()
        .get("compiled/effective-model.json")
        .expect("effective model generated");
    let value = parse_json_strict(&effective.bytes).expect("effective model is strict JSON");
    assert_eq!(
        value["queryInventory"]["operations"]
            .as_array()
            .expect("query operations are rendered")
            .len(),
        compiled.queries().operations.len()
    );
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    assert_eq!(
        openapi["paths"]["/v1/records/placements"]["get"]["x-registry-queryKind"],
        "list"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/placements:current"]["get"]["x-registry-queryKind"],
        "current"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/placements:as-of"]["get"]["x-registry-queryKind"],
        "as_of"
    );
    let list_parameter_names =
        query_parameter_names(&openapi["paths"]["/v1/records/placements"]["get"]["parameters"]);
    assert_eq!(
        list_parameter_names,
        [
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "accessProfile",
            "traceparent",
        ]
    );
    let as_of_parameter_names = query_parameter_names(
        &openapi["paths"]["/v1/records/placements:as-of"]["get"]["parameters"],
    );
    assert_eq!(
        as_of_parameter_names,
        [
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "accessProfile",
            "asOf",
            "traceparent",
        ]
    );
    let as_of_parameters = openapi["paths"]["/v1/records/placements:as-of"]["get"]["parameters"]
        .as_array()
        .expect("as-of parameters are rendered");
    let as_of = as_of_parameters
        .iter()
        .find(|parameter| parameter["name"] == "asOf")
        .expect("asOf parameter is rendered");
    assert_eq!(as_of["required"], true);
    assert_eq!(
        as_of["schema"],
        json!({"type": "string", "format": "date-time"})
    );
    let page_size = as_of_parameters
        .iter()
        .find(|parameter| parameter["name"] == "$top")
        .expect("$top parameter is rendered");
    assert_eq!(
        page_size["schema"],
        json!({"type": "integer", "minimum": 1, "maximum": 100})
    );
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.id == "entity.asset-placement.constraint.temporal-order"
            && statement.sql.contains(" IS NULL OR ")
            && statement.sql.contains(" < ")
    }));
}

#[test]
fn change_request_entity_fields_cannot_shadow_server_owned_query_state_api_names() {
    for reserved_field in [
        r#"{"id":"server-state","type":"string","maxLength":32,"required":true,"classification":"internal"}"#,
        r#"{"id":"proposal-version","type":"int64","required":true,"classification":"internal"}"#,
        r#"{"id":"digest","apiName":"effectDigest","type":"string","maxLength":71,"classification":"internal"}"#,
    ] {
        let project = change_request_correction_project(
            "change-request-reserved-query-name",
            "",
            "",
            "internal",
            "internal",
            "[]",
            "[]",
            "[]",
        );
        let mut source = String::from_utf8(project).expect("fixture is UTF-8");
        source = source.replace(
            r#"{"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}"#,
            &format!(
                r#"{{"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}},{}"#,
                reserved_field
            ),
        );
        let failure = compile_json(source.as_bytes())
            .expect_err("server-owned request query field names are reserved");
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == "change_request.field.api_name_reserved"),
            "diagnostics: {:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn change_request_list_queries_gain_server_state_filters_without_business_field_duplication() {
    let compiled = compile_json(&change_request_correction_project(
        "change-request-work-queue",
        "",
        "",
        "internal",
        "internal",
        "[]",
        "[]",
        "[]",
    ))
    .expect("change-request queue fixture compiles");

    let request_list = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| {
            operation.id == "records.placement-correction-request.request-reviewer.list"
        })
        .expect("request reviewer list query compiles");
    assert_eq!(request_list.kind, CompiledQueryKind::List);
    assert_eq!(
        request_list.projection_fields,
        ["placement", "proposed-site", "reason"],
        "server-owned state is not duplicated into business projection fields"
    );
    assert!(request_list.filter_fields.iter().any(|field| {
        field.field == REQUEST_SERVER_STATE_QUERY_FIELD
            && field
                .operators
                .contains(&CompiledQueryFilterOperator::Equals)
            && field.operators.contains(&CompiledQueryFilterOperator::In)
    }));
    assert!(request_list.filter_fields.iter().any(|field| {
        field.field == REQUEST_PROPOSAL_VERSION_QUERY_FIELD
            && field
                .operators
                .contains(&CompiledQueryFilterOperator::Range)
    }));
    assert!(request_list.filter_fields.iter().any(|field| {
        field.field == REQUEST_EFFECT_DIGEST_QUERY_FIELD
            && field
                .operators
                .contains(&CompiledQueryFilterOperator::IsNull)
            && field
                .operators
                .contains(&CompiledQueryFilterOperator::IsNotNull)
    }));
    assert!(request_list
        .sort_fields
        .iter()
        .any(|field| field.field == REQUEST_SERVER_STATE_QUERY_FIELD));
    assert!(request_list
        .sort_fields
        .iter()
        .any(|field| field.field == REQUEST_PROPOSAL_VERSION_QUERY_FIELD));
    assert!(request_list
        .sort_fields
        .iter()
        .any(|field| field.field == REQUEST_EFFECT_DIGEST_QUERY_FIELD));

    let target_list = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.placement.placement-reader.list")
        .expect("target list query compiles");
    assert!(!target_list
        .filter_fields
        .iter()
        .any(|field| field.field == REQUEST_SERVER_STATE_QUERY_FIELD));
    assert!(!target_list
        .sort_fields
        .iter()
        .any(|field| field.field == REQUEST_SERVER_STATE_QUERY_FIELD));
}

fn query_parameter_names(parameters: &Value) -> Vec<String> {
    let mut names = parameters
        .as_array()
        .expect("parameters are an array")
        .iter()
        .map(|parameter| {
            parameter["name"]
                .as_str()
                .expect("parameter has a name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn query_inventory_rejects_unsupported_filter_and_sort_field_types() {
    for (member, code) in [
        (
            r#""filterableFields":["payload"]"#,
            "query.filter.field_type_unsupported",
        ),
        (
            r#""sortableFields":["payload"]"#,
            "query.sort.field_type_unsupported",
        ),
    ] {
        let source = format!(
            r#"{{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{{"id":"query-shape","version":"1","defaultLanguage":"en"}},
              "entities":[{{
                "id":"entry","route":"entries","mutationMode":"mutable",
                "fields":[
                  {{"id":"payload","type":"structured","maxBytes":256,"classification":"internal","schema":{{"type":"object","additionalProperties":false}}}}
                ]
              }}],
              "accessProfiles":[{{
                "id":"operator","default":true,"principalClaim":"principal","grants":[{{
                  "entity":"entry","operations":["list"],"readableFields":["payload"],{member}
                }}]
              }}]
            }}"#
        );
        let project = parse_project_json(source.as_bytes()).expect("project shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("unsupported query field type is refused");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn temporal_queries_require_profile_readable_boundary_fields() {
    let mut project = asset_project();
    let grant = project
        .access_profiles
        .first_mut()
        .expect("fixture has an access profile")
        .grants
        .iter_mut()
        .find(|grant| grant.entity == "asset-placement")
        .expect("fixture grants placement access");
    grant.readable_fields.remove("valid-to");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("temporal query cannot process hidden boundary fields");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "query.temporal.field_not_readable"
            && diagnostic.path == "entities[].accessProfiles[].readableFields"
    }));
}

#[test]
fn reordered_stored_field_authoring_changes_revision_but_not_query_inventory() {
    let left = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"query-shape","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"entry","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"classification":"internal"},
              {"id":"count","type":"int64","classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
              "entity":"entry","operations":["list"],
              "readableFields":["code","count"],"filterableFields":["count","code"],"sortableFields":["count","code"]
            }]
          }]
        }"#,
    )
    .expect("left source parses");
    let right = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"query-shape","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"entry","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"count","type":"int64","classification":"internal"},
              {"id":"code","type":"string","maxLength":32,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
              "entity":"entry","operations":["list"],
              "readableFields":["count","code"],"filterableFields":["code","count"],"sortableFields":["code","count"]
            }]
          }]
        }"#,
    )
    .expect("right source parses");

    let left =
        compile_project(&left, &[], CompileProfile::Authoring).expect("left query source compiles");
    let right = compile_project(&right, &[], CompileProfile::Authoring)
        .expect("right query source compiles");
    assert_eq!(left.queries(), right.queries());
    assert_ne!(
        left.revision(),
        right.revision(),
        "stored field authoring order is now part of the compiled model"
    );
}

#[test]
fn duplicate_routes_fail_before_artifact_generation() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
          "entities":[
            {"id":"first-record","route":"hidden-route-value","mutationMode":"create_only","fields":[
              {"id":"code","type":"string","maxLength":8,"classification":"internal"}
            ]},
            {"id":"second-record","route":"hidden-route-value","mutationMode":"create_only","fields":[
              {"id":"code","type":"string","maxLength":8,"classification":"internal"}
            ]}
          ],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","grants":[
            {"entity":"first-record","operations":["get"],"readableFields":["code"]},
            {"entity":"second-record","operations":["get"],"readableFields":["code"]}
          ]}]
        }"#,
    )
    .expect("project parses");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("duplicate routes fail before artifact generation");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "entity.route.duplicate")
        .expect("duplicate route has a stable diagnostic");
    assert_eq!(diagnostic.path, "entities[].route");
    let rendered = serde_json::to_string(&failure).expect("failure serializes");
    for authored_value in ["hidden-route-value", "first-record", "second-record"] {
        assert!(!rendered.contains(authored_value));
    }
}

#[test]
fn anonymous_profiles_cannot_grant_mutation_operations() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"public-entry","route":"public-entries","mutationMode":"mutable","classification":"public",
            "fields":[{"id":"label","type":"string","maxLength":32,"classification":"public"}]
          }],
          "accessProfiles":[{
            "id":"anonymous-writer","anonymous":true,"default":true,"grants":[{
              "entity":"public-entry","operations":["create","patch"],"readableFields":["label"],"writableFields":["label"]
            }]
          }]
        }"#,
    )
    .expect("anonymous mutation fixture parses");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("anonymous mutation authority is refused at compilation");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "access_profile.anonymous.mutation_forbidden")
        .expect("anonymous mutation has a stable diagnostic");
    assert_eq!(diagnostic.path, "entities[].accessProfiles[].operations");
    assert!(!serde_json::to_string(diagnostic)
        .expect("diagnostic serializes")
        .contains("anonymous-writer"));
}

#[test]
fn production_refuses_a_digest_present_lock_without_module_source() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
          "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
          "package":{"environment":"production","instanceId":"neutral-instance","sequence":1,"sourceRevision":"revision-1"},
          "modules":[{"id":"missing-module","version":"1","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],
          "entities":[{"id":"object","route":"objects","mutationMode":"create_only","fields":[
            {"id":"code","type":"string","maxLength":8,"classification":"internal"}
          ]}],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","grants":[{"entity":"object","operations":["get"],"readableFields":["code"]}]}]
        }"#,
    )
    .expect("project parses");

    let failure = compile_project(&project, &[], CompileProfile::Production)
        .expect_err("a lock digest cannot substitute for loaded module source");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "module.source.required")
        .expect("missing source has a stable production diagnostic");
    assert_eq!(diagnostic.path, "project.modules[].id");
    let rendered = serde_json::to_string(&failure).expect("failure serializes");
    for authored_value in ["missing-module", "sha256:000000"] {
        assert!(!rendered.contains(authored_value));
    }
}

#[test]
fn verified_module_digest_changes_compiled_closure_artifact_and_revision() {
    let project_source = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject",
      "registry":{"id":"neutral","version":"1","defaultLanguage":"en"},
      "package":{"environment":"production","instanceId":"neutral-instance","sequence":1,"sourceRevision":"revision-1"},
      "manifestProjection":{"accessProfile":"reader","classificationCeiling":"internal","catalog":{"baseUrl":"https://neutral.example.test","title":"Neutral Catalog","publisher":{"name":"Neutral Publisher"}},"dataset":{"title":"Neutral Dataset"}},
      "modules":[{"id":"core","version":"1","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]
    }"#;
    let module_source = br#"{
      "id":"core","version":"1","entities":[
        {"id":"alpha-record","route":"alpha-records","mutationMode":"create_only","fields":[
          {"id":"code","type":"string","maxLength":8,"classification":"internal"}
        ],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get"],"readableFields":["code"]}]},
        {"id":"beta-record","route":"beta-records","mutationMode":"create_only","fields":[
          {"id":"code","type":"string","maxLength":8,"classification":"internal"}
        ],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get"],"readableFields":["code"]}]}
      ]
    }"#;
    let first_module = parse_module_json(module_source).expect("module parses");
    let mut second_module = first_module.clone();
    second_module.entities.reverse();
    let first_digest = module_digest(&first_module);
    let second_digest = module_digest(&second_module);
    assert_ne!(first_digest, second_digest);

    let mut first_project = parse_project_json(project_source).expect("project parses");
    first_project.modules[0].digest = Some(first_digest);
    let mut second_project = first_project.clone();
    second_project.modules[0].digest = Some(second_digest);

    let first = compile_project(&first_project, &[first_module], CompileProfile::Production)
        .expect("first verified closure compiles");
    let second = compile_project(
        &second_project,
        &[second_module],
        CompileProfile::Production,
    )
    .expect("second verified closure compiles");

    assert_ne!(first.module_closure(), second.module_closure());
    assert_ne!(
        first
            .artifacts()
            .get("compiled/modules.json")
            .expect("module closure artifact exists")
            .bytes,
        second
            .artifacts()
            .get("compiled/modules.json")
            .expect("module closure artifact exists")
            .bytes
    );
    assert_ne!(first.revision(), second.revision());
}
