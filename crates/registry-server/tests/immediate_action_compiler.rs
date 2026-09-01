// SPDX-License-Identifier: Apache-2.0

use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::{parse_project_json, Operation};
use registry_server::model::{
    ActionRouteKind, CompiledActionTargetBinding, CompiledActionTargetUseSource,
    CompiledActionValue,
};

fn compile_json(
    source: &[u8],
) -> Result<registry_server::CompiledRegistry, registry_server::CompileFailure> {
    let project = parse_project_json(source).expect("source shape parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn household_contact_project(extra: &str) -> String {
    r#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"immediate-actions","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
            "fields":[
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}
            ]
          },{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"}
            ]
          },{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"mutable",
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
            "effects":[
              {"id":"person","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"}}},
              {"id":"membership","target":{"entity":"group-membership"},"operation":"create",
                "set":{"person":{"fromEffect":"person"},"household":{"fromField":"household"}}},
              {"id":"household","target":{"fromField":"household"},"operation":"patch",
                "set":{"contact-person":{"fromEffect":"person"}}}
            ]
          }],
          "accessProfiles":[{
            "id":"contact-registrar",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredScopes":["registry:contact:register"],
            "requiredPurposes":["contact-registration"],
            "grants":[{
              "action":"register-household-contact",
              "operations":["invoke"],
              "targets":[
                {"entity":"household","rowBoundaries":[]},
                {"entity":"person","rowBoundaries":[]},
                {"entity":"group-membership","rowBoundaries":[]}
              ],
              "results":["person","membership","household"]
            }]
          }]
          __EXTRA__
        }"#
    .replace("__EXTRA__", extra)
}

#[test]
fn household_contact_action_compiles_routes_effects_and_authority() {
    let compiled = compile_json(household_contact_project("").as_bytes())
        .expect("household contact action compiles");
    assert!(
        compiled.routes().routes.is_empty(),
        "no CRUD route is granted"
    );

    let inventory = compiled.actions();
    assert_eq!(inventory.actions.len(), 1);
    let action = &inventory.actions[0];
    assert_eq!(action.id, "register-household-contact");
    assert_eq!(action.route, "/v1/actions/register-household-contact");
    assert_eq!(
        action.condition_route.as_deref(),
        Some("/v1/actions/register-household-contact/target-conditions")
    );
    assert_eq!(action.maximum_targets, 16);
    assert_eq!(action.maximum_field_mutations, 128);
    assert_eq!(action.maximum_snapshot_bytes, 2_097_152);
    assert!(action.contract_fingerprint.starts_with("sha256:"));

    assert_eq!(
        action
            .inputs
            .iter()
            .map(|input| (input.id.as_str(), input.api_name.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("household", "householdId"),
            ("person-code", "personCode"),
            ("legal-name", "legalName")
        ]
    );
    let effect_ids = action
        .effects
        .iter()
        .map(|effect| effect.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(effect_ids.len(), 3);
    let person_position = effect_ids
        .iter()
        .position(|id| *id == "person")
        .expect("person effect is present");
    let membership_position = effect_ids
        .iter()
        .position(|id| *id == "membership")
        .expect("membership effect is present");
    let household_position = effect_ids
        .iter()
        .position(|id| *id == "household")
        .expect("household effect is present");
    assert!(person_position < membership_position);
    assert!(person_position < household_position);

    let person_effect = action
        .effects
        .iter()
        .find(|effect| effect.id == "person")
        .expect("person effect compiled");
    let membership_effect = action
        .effects
        .iter()
        .find(|effect| effect.id == "membership")
        .expect("membership effect compiled");
    let household_effect = action
        .effects
        .iter()
        .find(|effect| effect.id == "household")
        .expect("household effect compiled");
    assert!(matches!(
        person_effect.target.binding,
        CompiledActionTargetBinding::Create
    ));
    assert!(matches!(
        household_effect.target.binding,
        CompiledActionTargetBinding::Existing { ref input } if input == "household"
    ));
    assert!(membership_effect.mutations.iter().any(|mutation| matches!(
        mutation,
        registry_server::model::CompiledActionMutation::Set {
            field,
            value: CompiledActionValue::FromEffect { effect, target_entity_id }
        } if field == "person" && effect == "person" && target_entity_id == "person"
    )));

    let household_use = action
        .target_uses
        .iter()
        .find(|use_| {
            use_.entity_id == "household"
                && matches!(
                    use_.source,
                    CompiledActionTargetUseSource::Input { ref input } if input == "household"
                )
        })
        .expect("household reference input is a derived target use");
    assert_eq!(household_use.operation, Operation::Patch);
    assert!(household_use.condition_required);
    assert_eq!(
        household_use.fields.iter().cloned().collect::<Vec<_>>(),
        vec!["contact-person".to_owned()]
    );

    assert_eq!(action.grants.len(), 1);
    let grant = &action.grants[0];
    assert_eq!(grant.profile_id, "contact-registrar");
    assert!(grant.default);
    assert_eq!(grant.principal_claim.as_deref(), Some("registry_principal"));
    assert_eq!(grant.operations, [Operation::Invoke].into_iter().collect());
    assert_eq!(
        grant.results.iter().cloned().collect::<Vec<_>>(),
        vec![
            "household".to_owned(),
            "membership".to_owned(),
            "person".to_owned()
        ]
    );
    assert_eq!(inventory.routes.len(), 2);
    assert!(inventory.routes.iter().any(|route| {
        route.kind == ActionRouteKind::Invoke
            && route.path == "/v1/actions/register-household-contact"
            && route.access_profiles == vec!["contact-registrar".to_owned()]
            && route.default_access_profile == "contact-registrar"
    }));
    assert!(inventory.routes.iter().any(|route| {
        route.kind == ActionRouteKind::TargetConditions
            && route.path == "/v1/actions/register-household-contact/target-conditions"
    }));
    assert_eq!(inventory.access.len(), 2);
}

#[test]
fn action_grants_must_cover_every_derived_target_and_result() {
    let source = household_contact_project("").replace(
        r#""targets":[
                {"entity":"household","rowBoundaries":[]},
                {"entity":"person","rowBoundaries":[]},
                {"entity":"group-membership","rowBoundaries":[]}
              ],
              "results":["person","membership","household"]"#,
        r#""targets":[{"entity":"household","rowBoundaries":[]}],
              "results":["person","missing"]"#,
    );

    let failure = compile_json(source.as_bytes())
        .expect_err("partial target authority and unknown results are refused");
    let codes = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"action.grant.targets.incomplete"));
    assert!(codes.contains(&"action.grant.result_unknown"));
}

#[test]
fn immediate_actions_preserve_review_control_and_request_lifecycle_boundaries() {
    let controlled = household_contact_project("").replace(
        r#""id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","#,
        r#""id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},"#,
    );
    let failure =
        compile_json(controlled.as_bytes()).expect_err("controlled target patches are refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.controlled_target"));

    let request_target = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"request-target-action","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[{
        "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable",
        "changeControl":{"requiredFor":["patch"]},
        "fields":[{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}]
      },{
        "id":"record-change","primaryDataset":"test-dataset","route":"record-changes","mutationMode":"mutable",
        "fields":[
          {"id":"record","type":"reference","target":"record","required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}
        ],
        "changeRequest":{
          "effects":[{"target":{"fromField":"record"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
          "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
        }
      }],
      "actions":[{
        "id":"create-record-change-directly",
        "inputs":[
          {"id":"record","type":"reference","target":"record","required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}
        ],
        "effects":[{"id":"request","target":{"entity":"record-change"},"operation":"create","set":{"record":{"fromField":"record"},"label":{"fromField":"label"}}}]
      }],
      "accessProfiles":[{
        "id":"operator","default":true,"principalClaim":"principal",
        "grants":[{
          "entity":"record-change",
          "operations":["get","submit_request","approve_request","apply_request"],
          "readableFields":["record","label"],
          "reviewStages":[{"stage":"review","targets":[{"entity":"record","readableFields":["label"],"rowBoundaries":[]}]}],
          "applyTargets":[{"entity":"record","rowBoundaries":[]}]
        },{
          "action":"create-record-change-directly",
          "operations":["invoke"],
          "targets":[{"entity":"record-change","rowBoundaries":[]}]
        }]
      }]
    }"#;
    let failure =
        compile_json(request_target).expect_err("request entities are not action targets");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.request_target"));
}

#[test]
fn action_effect_graph_rejects_invalid_sources_cycles_and_overlaps() {
    let nullable_required = household_contact_project("").replace(
        r#""inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},"#,
        r#""inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"classification":"restricted"},"#,
    );
    let failure = compile_json(nullable_required.as_bytes())
        .expect_err("nullable inputs cannot populate required fields");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.value_nullable"));

    let overlap = household_contact_project("").replace(
        r#""set":{"contact-person":{"fromEffect":"person"}}"#,
        r#""set":{"contact-person":{"fromEffect":"person"}},"clear":["contact-person"]"#,
    );
    let failure = compile_json(overlap.as_bytes()).expect_err("overlapping writes are refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.overlapping_write"));

    let cycle = br#"{
      "apiVersion":"registry.registrystack.org/v1alpha1",
      "kind":"RegistryProject",
      "registry":{"id":"action-cycle","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "entities":[{
        "id":"alpha","primaryDataset":"test-dataset","route":"alphas","mutationMode":"mutable",
        "fields":[
          {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"beta","type":"reference","target":"beta","classification":"internal"}
        ]
      },{
        "id":"beta","primaryDataset":"test-dataset","route":"betas","mutationMode":"mutable",
        "fields":[
          {"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"},
          {"id":"alpha","type":"reference","target":"alpha","classification":"internal"}
        ]
      }],
      "actions":[{
        "id":"make-cycle",
        "inputs":[{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}],
        "effects":[{
          "id":"alpha",
          "target":{"entity":"alpha"},
          "operation":"create",
          "set":{"label":{"fromField":"label"},"beta":{"fromEffect":"beta"}}
        },{
          "id":"beta",
          "target":{"entity":"beta"},
          "operation":"create",
          "set":{"label":{"fromField":"label"},"alpha":{"fromEffect":"alpha"}}
        }]
      }],
      "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","grants":[{
        "action":"make-cycle",
        "operations":["invoke"],
        "targets":[{"entity":"alpha","rowBoundaries":[]},{"entity":"beta","rowBoundaries":[]}]
      }]}]
    }"#;
    let failure = compile_json(cycle).expect_err("create dependencies cannot cycle");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.effect.dependency_cycle"));
}

#[test]
fn action_inputs_resolve_project_vocabulary_values_for_type_compatibility() {
    let compiled = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"action-vocabulary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "vocabularies":[{"id":"asset-type","values":["bridge","road"]}],
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable",
            "fields":[{"id":"kind","type":"vocabulary-code","vocabulary":"asset-type","required":true,"classification":"internal"}]
          }],
          "actions":[{
            "id":"create-asset",
            "inputs":[{"id":"kind","type":"vocabulary-code","vocabulary":"asset-type","required":true,"classification":"internal"}],
            "effects":[{"id":"asset","target":{"entity":"asset"},"operation":"create","set":{"kind":{"fromField":"kind"}}}]
          }],
          "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","grants":[{
            "action":"create-asset",
            "operations":["invoke"],
            "targets":[{"entity":"asset","rowBoundaries":[]}],
            "results":["asset"]
          }]}]
        }"#,
    )
    .expect("action input vocabulary values resolve from project vocabularies");
    let input_type = &compiled.actions().actions[0].inputs[0].field_type;
    assert!(matches!(
        input_type,
        registry_server::contract::FieldTypeSource::VocabularyCode { vocabulary, values }
            if vocabulary == "asset-type" && values == &vec!["bridge".to_owned(), "road".to_owned()]
    ));
}

#[test]
fn action_inputs_reject_unknown_project_vocabulary_references() {
    let failure = compile_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"action-vocabulary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"asset","primaryDataset":"test-dataset","route":"assets","mutationMode":"mutable",
            "fields":[{"id":"kind","type":"string","maxLength":32,"required":true,"classification":"internal"}]
          }],
          "actions":[{
            "id":"create-asset",
            "inputs":[{"id":"kind","type":"vocabulary-code","vocabulary":"asset-type","required":true,"classification":"internal"}],
            "effects":[{"id":"asset","target":{"entity":"asset"},"operation":"create","set":{"kind":{"fromField":"kind"}}}]
          }],
          "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","grants":[{
            "action":"create-asset",
            "operations":["invoke"],
            "targets":[{"entity":"asset","rowBoundaries":[]}]
          }]}]
        }"#,
    )
    .expect_err("unknown action input vocabularies are refused");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "action.input.vocabulary.unknown"
            && diagnostic.path == "actions[].inputs[].vocabulary"
    }));
}

#[test]
fn action_bounds_apply_before_runtime_target_work() {
    let mut inputs = Vec::new();
    let mut effects = Vec::new();
    let mut targets = Vec::new();
    for index in 0..17 {
        let input = format!("target-{index}");
        inputs.push(format!(
            r#"{{"id":"{input}","type":"reference","target":"record","required":true,"classification":"internal"}}"#
        ));
        effects.push(format!(
            r#"{{"target":{{"fromField":"{input}"}},"operation":"patch","set":{{"label":{{"fromField":"label"}}}}}}"#
        ));
        targets.push(r#"{"entity":"record","rowBoundaries":[]}"#.to_owned());
    }
    inputs.push(
        r#"{"id":"label","type":"string","maxLength":32,"required":true,"classification":"internal"}"#
            .to_owned(),
    );
    let source = format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"action-bounds","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "entities":[{{"id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable",
            "fields":[{{"id":"label","type":"string","maxLength":32,"classification":"internal"}}]}}],
          "actions":[{{"id":"bulk-fix","inputs":[{}],"effects":[{}]}}],
          "accessProfiles":[{{"id":"operator","default":true,"principalClaim":"principal",
            "grants":[{{"action":"bulk-fix","operations":["invoke"],"targets":[{}]}}]}}]
        }}"#,
        inputs.join(","),
        effects.join(","),
        targets.join(",")
    );

    let failure = compile_json(source.as_bytes()).expect_err("target ceiling is enforced");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "action.bounds.targets"));
}

#[test]
fn action_field_and_snapshot_ceilings_refuse_otherwise_valid_plans() {
    use serde_json::{json, Map, Value};

    for (field_count, field_type, expected_code) in [
        (
            129,
            json!({"type": "boolean"}),
            "action.bounds.field_mutations",
        ),
        (
            1,
            json!({"type": "string", "maxLength": 1_000_000}),
            "action.bounds.snapshot_bytes",
        ),
    ] {
        let mut fields = Vec::new();
        let mut assignments = Map::new();
        for index in 0..field_count {
            let id = format!("field-{index}");
            let mut field = json!({"id": id, "classification": "internal"});
            field
                .as_object_mut()
                .unwrap()
                .extend(field_type.as_object().unwrap().clone());
            fields.push(field);
            assignments.insert(id, json!({"fromField": "value"}));
        }
        let mut input = json!({"id": "value", "required": true, "classification": "internal"});
        input
            .as_object_mut()
            .unwrap()
            .extend(field_type.as_object().unwrap().clone());
        let project = json!({
            "apiVersion": "registry.registrystack.org/v1alpha1",
            "kind": "RegistryProject",
            "registry": {"id": "action-size-bounds", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://authoring.example.test"},
            "entities": [{
                "id": "bounded-record", "primaryDataset": "test-dataset", "route": "bounded-records", "mutationMode": "mutable",
                "fields": fields
            }],
            "actions": [{
                "id": "create-bounded-record", "inputs": [input],
                "effects": [{
                    "id": "created-record", "target": {"entity": "bounded-record"},
                    "operation": "create", "set": Value::Object(assignments)
                }]
            }],
            "accessProfiles": [{
                "id": "operator", "default": true, "principalClaim": "principal",
                "grants": [{
                    "action": "create-bounded-record", "operations": ["invoke"],
                    "targets": [{"entity": "bounded-record", "rowBoundaries": []}]
                }]
            }]
        });
        let failure = compile_json(&serde_json::to_vec(&project).unwrap())
            .expect_err("over-budget action plans are refused before runtime");
        assert_eq!(
            failure
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            vec![expected_code]
        );
    }
}
