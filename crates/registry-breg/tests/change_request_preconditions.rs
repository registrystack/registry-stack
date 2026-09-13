// SPDX-License-Identifier: Apache-2.0

use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
    model::{
        CompiledChangeRequestEvidenceExpected, CompiledChangeRequestPredicateExpected,
        CompiledChangeRequestSelector,
    },
};
use serde_json::{json, Value};

fn contracts() -> Value {
    json!({
        "schema": "registry.evidence-client-contracts/v1",
        "assuranceProfile": "local",
        "audience": "urn:example:seed-registry",
        "issuedBy": "urn:example:laboratory",
        "providedBy": "urn:example:evidence-service",
        "definitions": [{
            "handle": "lot-release",
            "requirement": "urn:example:requirement:lot-release:v1",
            "configurationRevision": format!("sha256:{}", "0".repeat(64)),
            "kind": "criterion",
            "evidenceType": "urn:example:evidence:lot-release:v1",
            "purpose": "lot-release",
            "responseFormats": ["signed-jws"],
            "referenceFrameworks": ["urn:example:framework:seed:v1"],
            "subjects": [{
                "role": "subject", "cardinality": "one",
                "selector": {
                    "profile": "lot-owner-v1", "valueOrigin": "request",
                    "fields": [
                        {"type":"string", "name":"lot-reference", "minimumBytes":1, "maximumBytes":64},
                        {"type":"string", "name":"owner-reference", "minimumBytes":1, "maximumBytes":64}
                    ]
                }
            }],
            "concepts": [
                {"handle":"report-reference", "concept":"urn:example:concept:report", "required":true, "form":"string"},
                {"handle":"germination", "concept":"urn:example:concept:germination", "required":true, "form":"integer"}
            ]
        }]
    })
}

fn project() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"request-preconditions", "version":"1", "defaultLanguage":"en", "canonicalBaseIri":"https://example.test"},
        "evidenceProviders":[{"id":"laboratory", "contracts":"evidence/contracts.json", "subjectResolution":"trusted-provider-exact-selector"}],
        "entities":[{
            "id":"lot", "primaryDataset":"test-dataset", "route":"lots", "mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
                {"id":"owner-reference", "type":"string", "maxLength":64, "required":true, "classification":"restricted"},
                {"id":"lot-reference", "type":"string", "maxLength":64, "required":true, "classification":"restricted"},
                {"id":"active", "type":"boolean", "required":true, "classification":"restricted"},
                {"id":"release-state", "type":"string", "maxLength":16, "required":true, "classification":"restricted"}
            ]
        },{
            "id":"release-request", "primaryDataset":"test-dataset", "route":"release-requests", "mutationMode":"mutable",
            "fields":[
                {"id":"lot", "type":"reference", "target":"lot", "required":true, "classification":"restricted"},
                {"id":"owner-reference", "type":"string", "maxLength":64, "required":true, "classification":"restricted"},
                {"id":"report-reference", "type":"string", "maxLength":64, "required":true, "classification":"restricted"},
                {"id":"release-state", "type":"string", "maxLength":16, "required":true, "classification":"restricted"},
                {"id":"valid-from", "type":"date", "required":true, "classification":"restricted"},
                {"id":"valid-through", "type":"date", "required":true, "classification":"restricted"}
            ],
            "changeRequest":{
                "effects":[{"id":"release", "target":{"fromField":"lot"}, "operation":"patch", "set":{"release-state":{"fromField":"release-state"}}}],
                "review":{"stages":[{"id":"review", "approvals":1}]},
                "application":{"mode":"manual", "preconditions":{
                    "request":[
                        {"field":"valid-from", "currentDate":"on_or_before"},
                        {"field":"valid-through", "currentDate":"on_or_after"}
                    ],
                    "targets":[{"id":"lot", "entity":"lot", "fromField":"lot", "requires":[
                        {"field":"owner-reference", "equalsFromRequestField":"owner-reference"},
                        {"field":"active", "equals":true}
                    ]}],
                    "evidence":[{
                        "id":"release-check", "provider":"laboratory", "requirement":"urn:example:requirement:lot-release:v1",
                        "subjects":{"subject":{"profile":"lot-owner-v1", "selectors":{
                            "lot-reference":{"source":"target_field", "target":"lot", "field":"lot-reference"},
                            "owner-reference":{"source":"request_field", "field":"owner-reference"}
                        }}},
                        "requires":[
                            {"output":"report-reference", "equalsFromRequestField":"report-reference"},
                            {"output":"germination", "atLeast":9000}
                        ],
                        "maximumObservationAgeSeconds":300
                    }]
                }}
            }
        }],
        "accessProfiles":[{"id":"reviewer", "default":true, "principalClaim":"principal", "permissions":[{
            "entity":"release-request",
            "operations":["get","submit_request","approve_request","reject_request","request_revision","apply_request"],
            "readableFields":["lot","owner-reference","report-reference","release-state","valid-from","valid-through"],
            "reviewStages":[{"stage":"review", "targets":[{"entity":"lot", "readableFields":["release-state"], "rowBoundaries":[]}]}],
            "applyTargets":[{"entity":"lot", "rowBoundaries":[]}], "rowBoundaries":[]
        }]}]
    })
}

fn compile(
    source: Value,
) -> Result<registry_breg::CompiledRegistry, registry_breg::CompileFailure> {
    let source = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "evidence/contracts.json".into(),
            bytes: serde_json::to_vec(&contracts()).unwrap(),
        }],
        CompileProfile::Authoring,
    )
}

#[test]
fn reviewed_manual_application_compiles_closed_digest_bound_preconditions() {
    let registry = compile(project()).unwrap();
    let plan = registry.entities()["release-request"]
        .change_request
        .as_ref()
        .unwrap();
    let preconditions = &plan.application.preconditions;
    assert_eq!(preconditions.request.len(), 2);
    assert!(matches!(
        preconditions.request[0].expected,
        CompiledChangeRequestPredicateExpected::CurrentDate { .. }
    ));
    assert_eq!(preconditions.targets.len(), 1);
    assert_eq!(preconditions.evidence.len(), 1);
    assert_eq!(
        preconditions.evidence[0].subjects["subject"]
            .selectors
            .len(),
        2
    );
    assert!(matches!(
        preconditions.evidence[0].subjects["subject"].selectors["lot-reference"],
        CompiledChangeRequestSelector::TargetField { .. }
    ));
    assert!(matches!(
        preconditions.evidence[0].requires[0].expected,
        CompiledChangeRequestEvidenceExpected::AtLeast { value: 9000 }
            | CompiledChangeRequestEvidenceExpected::RequestField { .. }
    ));
    assert_eq!(
        plan.target_entities,
        ["lot".to_owned()].into_iter().collect()
    );
    assert!(plan.contract_fingerprint.starts_with("sha256:"));
}

#[test]
fn preconditions_refuse_automatic_apply_incomplete_profiles_and_wrong_types() {
    for change in [
        "automatic",
        "planner",
        "missing-selector",
        "wrong-output-type",
        "wrong-date",
        "effect-id-collision",
    ] {
        let mut source = project();
        match change {
            "automatic" => {
                source["entities"][1]["changeRequest"]["application"]["mode"] = json!("automatic")
            }
            "planner" => {
                source["entities"][1]["changeRequest"]
                    .as_object_mut()
                    .unwrap()
                    .remove("effects");
                source["entities"][1]["changeRequest"]["planner"] = json!({
                    "kind":"rhai", "script":"planner.rhai",
                    "abi":"registry.change-request-plan/v1",
                    "requestFields":["lot", "release-state"],
                    "writes":[{"target":{"fromField":"lot"}, "operation":"patch", "fields":["release-state"]}]
                });
            }
            "missing-selector" => {
                source["entities"][1]["changeRequest"]["application"]["preconditions"]["evidence"]
                    [0]["subjects"]["subject"]["selectors"]
                    .as_object_mut()
                    .unwrap()
                    .remove("owner-reference");
            }
            "wrong-output-type" => {
                source["entities"][1]["changeRequest"]["application"]["preconditions"]
                    ["evidence"][0]["requires"][0]["equalsFromRequestField"] = json!("valid-from");
            }
            "wrong-date" => {
                source["entities"][1]["changeRequest"]["application"]["preconditions"]["request"]
                    [0]["field"] = json!("owner-reference");
            }
            "effect-id-collision" => {
                source["entities"][1]["changeRequest"]["application"]["preconditions"]["targets"]
                    [0]["id"] = json!("release");
            }
            _ => unreachable!(),
        }
        let failure = compile(source).unwrap_err();
        let report = format!("{failure:?}");
        assert!(
            report.contains(match change {
                "automatic" => "change_request.application.preconditions_manual_only",
                "planner" => "change_request.application.preconditions_manual_only",
                "missing-selector" => "change_request.preconditions.selector_fields_invalid",
                "wrong-output-type" => "change_request.preconditions.evidence_requirement_invalid",
                "wrong-date" => "change_request.preconditions.predicate_current_date_invalid",
                "effect-id-collision" => {
                    "change_request.preconditions.target_effect_collision"
                }
                _ => unreachable!(),
            }),
            "{change}: {report}"
        );
    }
}

#[test]
fn changing_any_guard_or_selector_binding_changes_the_request_contract_fingerprint() {
    let baseline = compile(project()).unwrap().entities()["release-request"]
        .change_request
        .as_ref()
        .unwrap()
        .contract_fingerprint
        .clone();
    let mut changed = project();
    changed["entities"][1]["changeRequest"]["application"]["preconditions"]["evidence"][0]
        ["maximumObservationAgeSeconds"] = json!(120);
    let changed = compile(changed).unwrap().entities()["release-request"]
        .change_request
        .as_ref()
        .unwrap()
        .contract_fingerprint
        .clone();
    assert_ne!(baseline, changed);
}

#[test]
fn request_fields_can_narrow_a_target_vocabulary_for_effects_and_guards() {
    let mut source = project();
    source["entities"][0]["fields"][3] = json!({
        "id":"release-state", "type":"vocabulary-code", "vocabulary":"release-state",
        "values":["draft","released"], "required":true, "classification":"restricted"
    });
    source["entities"][1]["fields"][3] = json!({
        "id":"release-state", "type":"vocabulary-code", "vocabulary":"release-state",
        "values":["released"], "required":true, "classification":"restricted"
    });
    source["entities"][1]["changeRequest"]["application"]["preconditions"]["targets"][0]
        ["requires"]
        .as_array_mut()
        .unwrap()
        .push(json!({"field":"release-state", "equalsFromRequestField":"release-state"}));
    compile(source).unwrap();
}

#[test]
fn request_predicates_distinguish_explicit_null_from_an_absent_equality() {
    let mut source = project();
    source["entities"][1]["fields"].as_array_mut().unwrap().push(json!({
        "id":"optional-note", "type":"string", "maxLength":32, "required":false, "classification":"restricted"
    }));
    source["entities"][1]["changeRequest"]["application"]["preconditions"]["request"]
        .as_array_mut()
        .unwrap()
        .push(json!({"field":"optional-note", "equals":null}));
    let registry = compile(source.clone()).unwrap();
    let preconditions = &registry.entities()["release-request"]
        .change_request
        .as_ref()
        .unwrap()
        .application
        .preconditions;
    assert!(preconditions.request.iter().any(|p| p.field == "optional-note" && matches!(&p.expected, CompiledChangeRequestPredicateExpected::Literal { value } if value.is_null())));
    source["entities"][1]["changeRequest"]["application"]["preconditions"]["request"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("equals");
    assert!(format!("{:?}", compile(source).unwrap_err())
        .contains("change_request.preconditions.predicate_operator_invalid"));
}

#[test]
fn frozen_guard_values_are_counted_with_the_original_proposal_snapshot() {
    let mut source = project();
    let field = source["entities"][1]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|field| field["id"] == "report-reference")
        .unwrap();
    field["maxLength"] = json!(200_000);
    let failure = format!("{:?}", compile(source).unwrap_err());
    assert!(
        failure.contains("change_request.preconditions.bounds"),
        "{failure}"
    );
}

#[test]
fn duplicated_reviewed_evidence_definitions_count_toward_the_snapshot_ceiling() {
    let mut source = project();
    source["entities"][1]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|field| field["id"] == "report-reference")
        .unwrap()["maxLength"] = json!(174_350);
    compile(source.clone()).unwrap();

    let mut second = source["entities"][1]["changeRequest"]["application"]["preconditions"]
        ["evidence"][0]
        .clone();
    second["id"] = json!("release-check-again");
    source["entities"][1]["changeRequest"]["application"]["preconditions"]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let failure = format!("{:?}", compile(source).unwrap_err());
    assert!(
        failure.contains("change_request.preconditions.bounds"),
        "{failure}"
    );
}
