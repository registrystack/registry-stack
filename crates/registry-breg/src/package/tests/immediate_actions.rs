// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::contract::{ModuleAssetSource, Operation};
use crate::model::ActionRouteKind;
use crate::{compile_project, compile_project_with_assets, parse_project_json, CompileProfile};
use serde_json::json;

fn source() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"action-package", "version":"1", "defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "datasets":[{"id":"test-dataset"}],"recordTypes":[{"id":"item", "primaryDataset":"test-dataset", "route":"items", "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maximumLength":40, "required":true, "classification":"internal"}]}],
        "actions":[{"id":"rename-item", "execution":{"mode":"immediate"}, "inputs":[
            {"id":"item", "apiName":"itemId", "type":"reference", "target":"item", "required":true, "classification":"internal"},
            {"id":"label", "apiName":"newLabel", "type":"string", "maximumLength":40, "required":true, "classification":"internal"}
        ], "plan":{"type":"fixed","effects":[{"id":"renamed", "target":{"fromInput":"item"}, "operation":"patch", "set":{"label":{"fromInput":"label"}}}]}}],
        "accessProfiles":[{"id":"operator", "default":true, "principalClaim":"principal", "requiredScopes":["item.rename"],
            "permissions":{"actions":[{"action":"rename-item", "operations":["invoke"], "targets":[{"recordType":"item", "rowBoundaries":"unrestricted"}], "results":["renamed"]}]}}]
    })
}

fn compile(value: &Value) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

fn compile_with_assets(value: &Value, assets: &[ModuleAssetSource]) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap();
    compile_project_with_assets(&project, &[], assets, CompileProfile::Authoring).unwrap()
}

fn source_without_actions() -> Value {
    let mut value = source();
    value["actions"] = json!([]);
    value["accessProfiles"] = json!([]);
    value
}

fn ordinary_policy_source(auditor_operations: Option<&[&str]>) -> Value {
    let mut source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"policy-package", "version":"1", "defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "datasets":[{"id":"test-dataset"}],"recordTypes":[{"id":"person", "primaryDataset":"test-dataset", "route":"people", "mutationMode":"mutable",
            "fields":[
                {"id":"person-code", "type":"string", "maximumLength":40, "required":true, "classification":"internal"},
                {"id":"sensitive-note", "type":"string", "maximumLength":120, "classification":"internal"}
            ]}],
        "accessProfiles":[{"id":"operator", "default":true, "principalClaim":"principal","requiredScopes":"unrestricted",
            "permissions":{"records":[{"recordType":"person", "operations":["create","get","list"],
                "readableFields":["person-code","sensitive-note"],
                "writableFields":["person-code","sensitive-note"], "rowBoundaries":"unrestricted"}]}}]
    });
    if let Some(operations) = auditor_operations {
        let mut permission = json!({
            "recordType":"person", "operations":operations, "rowBoundaries":"unrestricted"
        });
        if operations
            .iter()
            .any(|operation| matches!(*operation, "get" | "list"))
        {
            permission["readableFields"] = json!(["person-code", "sensitive-note"]);
        }
        if operations.contains(&"create") {
            permission["writableFields"] = json!(["person-code", "sensitive-note"]);
        }
        source["accessProfiles"]
            .as_array_mut()
            .expect("accessProfiles is an array")
            .push(json!({
                "id":"auditor", "principalClaim":"principal",
                "requiredScopes":["registry.audit"], "permissions":{"records":[permission]}
            }));
    }
    source
}

fn assert_complete_person_policy_drops(
    before: &CompiledRegistry,
    after: &CompiledRegistry,
    plan: &MigrationPlan,
) {
    let before = before
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "person")
        .expect("predecessor person table is compiled")
        .policies
        .iter()
        .map(|policy| (policy.name.as_str(), policy))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "person")
        .expect("candidate person table is compiled")
        .policies
        .iter()
        .map(|policy| (policy.name.as_str(), policy))
        .collect::<BTreeMap<_, _>>();
    let expected_drops = before
        .iter()
        .filter(|(name, policy)| after.get(*name) != Some(policy))
        .map(|(name, _)| format!("entity.person.policy.{name}.drop"))
        .collect::<BTreeSet<_>>();
    let actual_drop_ids = plan
        .statements
        .iter()
        .filter(|statement| statement.sql.starts_with("DROP POLICY "))
        .map(|statement| statement.id.clone())
        .collect::<Vec<_>>();
    let actual_drops = actual_drop_ids.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual_drop_ids.len(), actual_drops.len());
    assert_eq!(actual_drops, expected_drops);
    assert!(plan
        .statements
        .iter()
        .all(|statement| !statement.sql.starts_with("CREATE POLICY ")));
}

#[test]
fn compiler_successor_drops_every_policy_for_removed_read_profile() {
    let before = compile(&ordinary_policy_source(Some(&["get", "list"])));
    let after = compile(&ordinary_policy_source(None));
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("ordinary profile removal is compiler-applicable");

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::AccessProfileRemoved));
    assert_complete_person_policy_drops(&before, &after, &plan);
    assert!(drop_policy_sql(&plan)
        .iter()
        .any(|statement| statement.contains("registry_rls_select_")));
}

#[test]
fn compiler_successor_drops_create_returning_policy_for_removed_create_profile() {
    let before = compile(&ordinary_policy_source(Some(&["create"])));
    let after = compile(&ordinary_policy_source(None));
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("create-only profile removal is compiler-applicable");

    assert_complete_person_policy_drops(&before, &after, &plan);
    let drops = drop_policy_sql(&plan);
    assert!(drops
        .iter()
        .any(|statement| statement.contains("registry_rls_insert_")));
    assert!(drops
        .iter()
        .any(|statement| statement.contains("registry_create_returning_rls_")));
}

#[test]
fn compiler_successor_replaces_complete_policy_set_when_profile_is_narrowed() {
    let before = compile(&ordinary_policy_source(Some(&["get", "list"])));
    let after = compile(&ordinary_policy_source(Some(&["create"])));
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("ordinary profile narrowing is compiler-applicable");

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::AccessProfileChanged));
    assert_complete_person_policy_drops(&before, &after, &plan);
    let drops = drop_policy_sql(&plan);
    assert!(drops
        .iter()
        .any(|statement| statement.contains("registry_rls_select_")));
    assert_eq!(create_policy_sql(&plan), Vec::<String>::new());
}

#[test]
fn reviewed_successor_uses_the_same_complete_ordinary_policy_drops() {
    let before = compile(&ordinary_policy_source(Some(&["get", "list"])));
    let after = compile(&ordinary_policy_source(None));
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::AccessProfileRemoved));
    assert_complete_person_policy_drops(&before, &after, &plan);
}

#[test]
fn action_configuration_and_disclosure_changes_are_visible_in_package_diffs() {
    let value = source();
    let before = compile(&value);
    let mut renamed = value.clone();
    renamed["actions"][0]["inputs"][0]["apiName"] = json!("selectedItem");
    let mut scoped = value.clone();
    scoped["accessProfiles"][0]["requiredScopes"] = json!(["item.rename.restricted"]);
    let mut no_results = value;
    no_results["accessProfiles"][0]["permissions"]["actions"][0]["results"] = json!([]);
    for variant in [renamed, scoped, no_results] {
        let after = compile(&variant);
        let changes = compiled_registry_change_set(&before, &after, "prior-package");
        assert_eq!(changes.changes.len(), 1);
        let change = &changes.changes[0];
        assert_eq!(change.code, CompiledRegistryChangeCode::ActionChanged);
        assert_eq!(
            change.class,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        );
        assert_eq!(change.target.kind, CompiledRegistryChangeTargetKind::Action);
        assert_eq!(change.target.entity_id, None);
        assert_eq!(change.target.member_id.as_deref(), Some("rename-item"));
        assert!(change_set_to_applicable_migration_plan(&changes).is_err());
    }
}

#[test]
fn action_schemas_and_authority_inventory_are_in_the_rederived_package_closure() {
    let compiled = compile(&source());
    let mut files = BTreeMap::new();
    add_compiled_artifacts(&compiled, &initial_migration_plan(&compiled), &mut files).unwrap();
    assert_eq!(
        package_role_for_path("inventories/actions.json").unwrap(),
        PackageFileRole::ActionInventory
    );
    let inventory: Value = serde_json::from_slice(&files["inventories/actions.json"]).unwrap();
    assert_eq!(inventory["actions"][0]["id"], "rename-item");
    for suffix in [
        "availability.input",
        "availability.response",
        "invoke.input",
        "invoke.response",
        "target-conditions.input",
        "target-conditions.response",
    ] {
        let path = format!("action-schemas/rename-item.{suffix}.schema.json");
        assert_eq!(
            package_role_for_path(&path).unwrap(),
            PackageFileRole::ActionJsonSchema
        );
        assert_eq!(
            files[&path],
            compiled
                .artifacts()
                .get(&format!("generated/{path}"))
                .unwrap()
                .bytes
        );
    }
    let baseline = CompiledRegistryMigrationBaseline::from_compiled("prior-package", &compiled);
    let serialized = serde_json::to_value(&baseline).unwrap();
    assert_eq!(serialized["actions"], inventory);
    let decoded: CompiledRegistryMigrationBaseline = serde_json::from_value(serialized).unwrap();
    assert_eq!(decoded.actions, *compiled.actions());
}

#[test]
fn reference_target_actions_publish_bounded_availability_contracts() {
    let compiled = compile(&source());
    let action = &compiled.actions().actions[0];
    let route = compiled
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Availability)
        .expect("the immediate action has a reference target");
    assert_eq!(route.id, "actions.rename-item.availability");
    assert_eq!(route.path, "/v1/actions/rename-item/availability");
    assert_eq!(route.operation, Operation::Invoke);
    assert_eq!(route.access_profiles, vec!["operator"]);

    let metadata: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/metadata/registry.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(
        metadata["actions"][0]["routes"]["availability"],
        json!({
            "method": "POST",
            "path": "/v1/actions/rename-item/availability",
            "operationId": "actions.rename-item.availability",
            "requiresIdempotencyKey": false,
            "inputSchema": "action-rename-item-availability-input",
            "responseSchema": "action-rename-item-availability-response",
        })
    );

    let openapi: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let availability_examples = &openapi["paths"][&route.path]["post"]["responses"]["503"]
        ["content"]["application/problem+json"]["examples"];
    assert_eq!(
        availability_examples["runtime.field_encryption.unavailable"]["value"],
        json!({
            "type": "https://id.registrystack.org/problems/registry-breg/runtime/field_encryption/unavailable",
            "title": "Service Unavailable",
            "status": 503,
            "detail": "The Registry field-encryption service is unavailable.",
            "code": "runtime.field_encryption.unavailable",
            "traceId": "11111111111111111111111111111111",
        })
    );
    assert!(availability_examples["service.unavailable"].is_object());
    assert!(openapi["paths"][&route.path]["post"]["responses"]
        .get("412")
        .is_none());

    let invoke = compiled
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let invoke_examples = &openapi["paths"][&invoke.path]["post"]["responses"]["503"]["content"]
        ["application/problem+json"]["examples"];
    assert!(invoke_examples["runtime.field_encryption.unavailable"].is_object());
    assert_eq!(
        openapi["paths"][&invoke.path]["post"]["responses"]["412"]["content"]
            ["application/problem+json"]["examples"]["action.guard_failed"]["value"],
        json!({
            "type": "https://id.registrystack.org/problems/registry-breg/action/guard_failed",
            "title": "Precondition Failed",
            "status": 412,
            "detail": "The action guard was not satisfied.",
            "code": "action.guard_failed",
            "traceId": "11111111111111111111111111111111",
        })
    );

    let target_conditions = compiled
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::TargetConditions)
        .unwrap();
    let target_condition_examples = &openapi["paths"][&target_conditions.path]["post"]["responses"]
        ["503"]["content"]["application/problem+json"]["examples"];
    assert!(target_condition_examples
        .get("runtime.field_encryption.unavailable")
        .is_none());
    assert!(
        openapi["paths"][&target_conditions.path]["post"]["responses"]
            .get("412")
            .is_none()
    );

    let proposal = compile(&proposal_source(
        &["get", "edit", "submit", "cancel", "apply"],
        &["item", "label"],
    ));
    let proposal_route = proposal
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let proposal_openapi: Value = serde_json::from_slice(
        &proposal
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(
        proposal_openapi["paths"][&proposal_route.path]["post"]["responses"]["503"]["content"]
            ["application/problem+json"]["examples"]
            .get("runtime.field_encryption.unavailable")
            .is_none()
    );
    let proposal_precondition_examples = &proposal_openapi["paths"][&proposal_route.path]["post"]
        ["responses"]["412"]["content"]["application/problem+json"]["examples"];
    assert!(proposal_precondition_examples["precondition.failed"].is_object());
    assert!(proposal_precondition_examples
        .get("action.guard_failed")
        .is_none());
    let proposal_responses = &proposal_openapi["paths"][&proposal_route.path]["post"]["responses"];
    assert!(proposal_responses.get("200").is_none());
    assert_eq!(proposal_responses["201"]["description"], "Proposal created");
    assert_eq!(
        proposal_responses["201"]["content"]["application/json"]["schema"],
        json!({"$ref": "#/components/schemas/action-rename-item-invoke-response"})
    );
    assert_eq!(
        proposal_openapi["components"]["schemas"]["action-rename-item-invoke-response"],
        crate::artifacts::proposal_schema()
    );
    assert_eq!(
        proposal_responses["201"]["headers"]["ETag"]["description"],
        "Strong Registry ETag for the created Proposal."
    );
    assert_eq!(
        proposal_responses["201"]["headers"]["Location"]["description"],
        "Relative URL of the created Proposal."
    );
    assert!(proposal_responses["201"]["headers"]["traceparent"].is_object());
    assert_eq!(
        proposal_responses["201"]["headers"]["Cache-Control"]["schema"]["const"],
        "no-store"
    );

    let request_schema: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/action-schemas/rename-item.availability.input.schema.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let request_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&request_schema)
        .unwrap();
    assert!(request_validator
        .validate(&json!({"targetInput":"itemId", "input":{"itemId":"00000000-0000-0000-0000-000000000001"}}))
        .is_ok());
    assert!(request_validator
        .validate(&json!({"targetInput":"itemId", "input":{"newLabel":"renamed"}}))
        .is_err());

    let response_schema: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/action-schemas/rename-item.availability.response.schema.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let response_validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&response_schema)
        .unwrap();
    for response in [
        json!({"availability":{"available":true,"observedRevision":3}}),
        json!({"availability":{"available":false,"observedRevision":3,"reason":"guard-not-satisfied","recovery":"none"}}),
        json!({"availability":{"available":null,"observedRevision":3,"reason":"input-required","recovery":"correct-input","missingInputs":["newLabel"]}}),
        json!({"availability":{"available":null,"observedRevision":null,"reason":"not-disclosed","recovery":"none"}}),
    ] {
        assert!(response_validator.validate(&response).is_ok(), "{response}");
    }
    assert!(response_validator
        .validate(&json!({"availability":{"available":false,"observedRevision":3,"reason":"guard-not-satisfied","recovery":"correct-input"}}))
        .is_err());

    assert!(!action.execution.is_proposal());
}

#[test]
fn reviewed_successor_adds_action_policies_for_existing_entity() {
    let before = compile(&source_without_actions());
    let after = compile(&source());
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionAdded));
    assert!(
        change_set_to_applicable_migration_plan(&CompiledRegistryChangeSet {
            from_package_digest: format!("sha256:{}", "a".repeat(64)),
            changes: plan.changes.clone(),
            migration_plan: None,
        })
        .is_err(),
        "action authority changes still require reviewed activation"
    );
    assert!(
        plan.statements
            .iter()
            .all(|statement| statement.kind == DdlStatementKind::Policy),
        "action-only review adds no table or view DDL"
    );
    assert_eq!(drop_policy_sql(&plan), Vec::<String>::new());
    assert_eq!(
        sorted(create_policy_sql(&plan)),
        sorted(action_policy_sql(&after))
    );
}

#[test]
fn reviewed_successor_does_not_duplicate_action_policies_for_new_entity() {
    let before = compile(&source_without_actions());
    let mut candidate = source_without_actions();
    candidate["recordTypes"]
        .as_array_mut()
        .expect("entities are an array")
        .push(json!({
            "id":"task",
            "primaryDataset":"test-dataset",
            "route":"tasks",
            "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maximumLength":40, "required":true, "classification":"internal"}]
        }));
    candidate["actions"] = json!([{
        "id":"create-task", "execution":{"mode":"immediate"},
        "inputs":[{"id":"label", "apiName":"label", "type":"string", "maximumLength":40, "required":true, "classification":"internal"}],
        "plan":{"type":"fixed","effects":[{"id":"task", "target":{"recordType":"task"}, "operation":"create", "set":{"label":{"fromInput":"label"}}}]}
    }]);
    candidate["accessProfiles"] = json!([{
        "id":"task-operator",
        "default":true,
        "principalClaim":"principal",
        "requiredScopes":"unrestricted",
        "permissions":{"actions":[{"action":"create-task", "operations":["invoke"], "targets":[{"recordType":"task", "rowBoundaries":"unrestricted"}], "results":["task"]}]}
    }]);
    let after = compile(&candidate);
    let plan = reviewed_plan(&before, &after);
    let creates = create_policy_sql(&plan);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionAdded));
    assert_eq!(sorted(creates.clone()), sorted(action_policy_sql(&after)));
    assert_eq!(
        creates
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        creates.len(),
        "new-entity additive DDL must not duplicate action policies"
    );
}

#[test]
fn reviewed_successor_replaces_action_policies_when_contract_changes() {
    let before = compile(&source());
    let mut changed = source();
    changed["accessProfiles"][0]["permissions"]["actions"][0]["targets"][0]["rowBoundaries"] =
        json!([{"field":"label","claim":"itemLabel","operator":"equals"}]);
    let after = compile(&changed);
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionChanged));
    let drops = drop_policy_sql(&plan);
    let creates = create_policy_sql(&plan);
    assert_eq!(drops.len(), action_policy_sql(&before).len());
    assert_eq!(sorted(creates.clone()), sorted(action_policy_sql(&after)));
    for create in creates {
        assert!(
            create.contains(&after.actions().actions[0].definition_revision),
            "candidate policy must bind the new action contract fingerprint"
        );
    }
}

#[test]
fn reviewed_successor_drops_removed_action_policies_for_existing_entity() {
    let before = compile(&source());
    let after = compile(&source_without_actions());
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionRemoved));
    assert_eq!(
        drop_policy_sql(&plan).len(),
        action_policy_sql(&before).len()
    );
    assert_eq!(create_policy_sql(&plan), Vec::<String>::new());
}

#[test]
fn reviewed_successor_tracks_link_only_reference_policies() {
    let mut without_action = source_without_actions();
    without_action["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"group", "primaryDataset":"test-dataset", "route":"groups", "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maximumLength":40,
                "required":true, "classification":"internal"}]
        }));
    without_action["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"group", "type":"reference", "target":"group", "classification":"internal"
        }));
    let mut with_action = without_action.clone();
    with_action["actions"] = source()["actions"].clone();
    with_action["accessProfiles"] = source()["accessProfiles"].clone();
    with_action["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"group", "apiName":"groupId", "type":"reference", "target":"group",
            "required":true, "classification":"internal"
        }));
    with_action["actions"][0]["plan"]["effects"][0]["set"]["group"] = json!({"fromInput":"group"});
    with_action["accessProfiles"][0]["permissions"]["actions"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"group", "rowBoundaries":"unrestricted"
        }));
    let before = compile(&without_action);
    let after = compile(&with_action);
    let links = after
        .ddl()
        .tables
        .iter()
        .flat_map(|table| &table.policies)
        .filter(|policy| policy.name.starts_with("registry_action_link_rls_"))
        .map(|policy| policy.name.clone())
        .collect::<Vec<_>>();
    assert!(
        !links.is_empty(),
        "a link-only input needs its own row authority"
    );
    let added = reviewed_plan(&before, &after);
    let removed = reviewed_plan(&after, &before);
    for name in &links {
        assert!(create_policy_sql(&added)
            .iter()
            .any(|sql| sql.contains(name)));
        assert!(drop_policy_sql(&removed)
            .iter()
            .any(|sql| sql.contains(name)));
    }
    with_action["accessProfiles"][0]["permissions"]["actions"][0]["targets"][1]["rowBoundaries"] =
        json!([{"field":"label","claim":"groupLabel","operator":"equals"}]);
    let changed = compile(&with_action);
    let replaced = reviewed_plan(&after, &changed);
    for name in links {
        assert!(drop_policy_sql(&replaced)
            .iter()
            .any(|sql| sql.contains(&name)));
        assert!(create_policy_sql(&replaced)
            .iter()
            .any(|sql| sql.contains(&name)
                && sql.contains(&changed.actions().actions[0].definition_revision)));
    }
}

#[test]
fn reviewed_successor_does_not_drop_action_policies_for_absent_entity_table() {
    let before = compile(&source());
    let mut removed_entity = source_without_actions();
    removed_entity["recordTypes"] = json!([{
        "id":"other",
        "primaryDataset":"test-dataset",
        "route":"others",
        "mutationMode":"mutable",
        "fields":[{"id":"label", "type":"string", "maximumLength":40, "required":true, "classification":"internal"}]
    }]);
    removed_entity["accessProfiles"] = json!([]);
    let after = compile(&removed_entity);
    let plan = reviewed_plan(&before, &after);

    assert!(plan
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::EntityRemoved));
    assert_eq!(drop_policy_sql(&plan), Vec::<String>::new());
    assert_eq!(create_policy_sql(&plan), Vec::<String>::new());
}

fn proposal_source(operations: &[&str], readable_inputs: &[&str]) -> Value {
    let mut value = source();
    value["recordTypes"][0]["mutationPolicy"] = json!({"patch":"proposal-required"});
    value["actions"][0]["execution"] = json!({"mode":"proposal","proposal":{
        "review":{"type":"none"}, "application":{"mode":"manual"}, "retention":{"mode":"retain"}
    }});
    value["accessProfiles"][0]["permissions"]["actions"][0]["operations"] = json!(["start"]);
    value["accessProfiles"][0]["permissions"]["proposals"] = json!([{
        "action":"rename-item", "operations":operations, "readableInputs":readable_inputs,
        "targets":[{"recordType":"item","rowBoundaries":"unrestricted"}]
    }]);
    value
}

#[test]
fn proposal_draft_schema_omits_required_presence_without_changing_non_null_fixed_inputs() {
    let registry = compile(&proposal_source(
        &["get", "edit", "submit"],
        &["item", "label"],
    ));
    let action = &registry.actions().actions[0];
    assert!(action.inputs.iter().all(|input| input.required));
    let draft = crate::artifacts::openapi_action_input_schema(action);
    assert_eq!(draft["properties"]["input"]["required"], json!([]));
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&draft)
        .unwrap();
    assert!(validator.is_valid(&json!({"input":{}})));
    assert!(!validator.is_valid(&json!({"input":{"newLabel":null}})));
    assert!(!validator.is_valid(&json!({"input":{"newLabel":42}})));
    let immediate = compile(&source());
    let schema = crate::artifacts::openapi_action_input_schema(&immediate.actions().actions[0]);
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(!validator.is_valid(&json!({"input":{}})));
}

fn compile_diagnostics(value: &Value) -> String {
    let project = parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap();
    format!(
        "{:?}",
        compile_project(&project, &[], CompileProfile::Authoring).unwrap_err()
    )
}

fn proposal_permission(registry: &CompiledRegistry) -> crate::model::CompiledProposalPermission {
    let crate::model::CompiledActionExecution::Proposal { proposal } =
        &registry.actions().actions[0].execution
    else {
        panic!("proposal action");
    };
    proposal.permissions[0].clone()
}

#[test]
fn proposal_task_context_requires_service_authority_and_a_declared_field_subset() {
    let mut value = proposal_source(&["get-task-grant-context"], &[]);
    value["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"booking-context",
        "fields":{"applicationId":{"type":"input","input":"label"}}
    });
    value["accessProfiles"][0]["actorKind"] = json!("service");
    value["accessProfiles"][0]["requesterClients"] = json!(["casework-service"]);
    value["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["applicationId"]);
    let permission = proposal_permission(&compile(&value));
    assert!(permission
        .operations
        .contains(&crate::model::ProposalOperation::GetTaskGrantContext));
    assert_eq!(
        permission.readable_context_fields,
        std::collections::BTreeSet::from(["applicationId".to_owned()])
    );

    for invalid in [
        {
            let mut invalid = value.clone();
            invalid["accessProfiles"][0]["actorKind"] = json!("human");
            invalid
        },
        {
            let mut invalid = value.clone();
            invalid["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
                json!([]);
            invalid
        },
        {
            let mut invalid = value.clone();
            invalid["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
                json!(["missing"]);
            invalid
        },
    ] {
        let diagnostics = compile_diagnostics(&invalid);
        assert!(
            diagnostics.contains("breg.proposal.task-context-grant-invalid")
                || diagnostics.contains("breg.proposal.context-field-unknown"),
            "{diagnostics}"
        );
    }
}

#[test]
fn proposal_writable_inputs_compile_to_the_named_input_ids() {
    let mut value = proposal_source(&["get", "edit", "submit"], &["item", "label"]);
    value["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] = json!(["label"]);
    let permission = proposal_permission(&compile(&value));
    assert_eq!(
        permission.writable_inputs,
        Some(std::collections::BTreeSet::from(["label".to_owned()]))
    );
    let compiled = serde_json::to_value(&permission).unwrap();
    assert_eq!(compiled["writableInputs"], json!(["label"]));
}

#[test]
fn proposal_grant_without_writable_inputs_compiles_without_the_field() {
    let value = proposal_source(&["get", "edit", "submit"], &["item", "label"]);
    let permission = proposal_permission(&compile(&value));
    assert_eq!(permission.writable_inputs, None);
    let compiled = serde_json::to_value(&permission).unwrap();
    assert!(compiled.get("writableInputs").is_none());
}

#[test]
fn proposal_writable_inputs_refuse_invalid_grants() {
    let unknown = {
        let mut value = proposal_source(&["get", "edit"], &["item", "label"]);
        value["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] =
            json!(["missing"]);
        value
    };
    let no_write_authority = {
        let mut value = proposal_source(&["get", "submit"], &["item", "label"]);
        value["accessProfiles"][0]["permissions"]["actions"] = json!([]);
        value["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] =
            json!(["label"]);
        value
    };
    let unreadable_fixed_input = {
        let mut value = proposal_source(&["get", "edit"], &["label"]);
        value["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] =
            json!(["label"]);
        value
    };
    for value in [unknown, no_write_authority, unreadable_fixed_input] {
        let diagnostics = compile_diagnostics(&value);
        assert!(
            diagnostics.contains("breg.proposal.input-grant-invalid")
                && diagnostics.contains("writableInputs"),
            "{diagnostics}"
        );
    }
}

#[test]
fn proposal_writable_inputs_accept_start_only_or_fully_writable_grants() {
    let mut start_only = proposal_source(&["get", "submit"], &[]);
    start_only["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] =
        json!(["item", "label"]);
    assert!(proposal_permission(&compile(&start_only))
        .writable_inputs
        .is_some());
    let mut edit_without_get = proposal_source(&["edit", "submit"], &[]);
    edit_without_get["accessProfiles"][0]["permissions"]["proposals"][0]["writableInputs"] =
        json!(["item", "label"]);
    assert!(proposal_permission(&compile(&edit_without_get))
        .writable_inputs
        .is_some());
}

fn evidence_contract_asset() -> ModuleAssetSource {
    ModuleAssetSource {
        module: None,
        path: "evidence/contracts.json".into(),
        bytes: include_bytes!(
            "../../../../../products/breg/acceptance/farmer-landholding-evidence/evidence/farmer-contracts.json"
        )
        .to_vec(),
    }
}

fn proposal_handler_evidence_source() -> Value {
    let mut value = proposal_source(
        &["get", "edit", "submit", "cancel", "apply"],
        &["item", "label"],
    );
    value["functions"] = json!([{
        "id": "rename-plan",
        "runtime": "rhai",
        "source": "handlers/rename.rhai",
        "entrypoint": "plan",
        "abi": "registry.action-plan/v1",
    }]);
    value["evidenceProviders"] = json!([{
        "id": "provider",
        "contracts": "evidence/contracts.json",
        "subjectResolution": "trusted-provider-exact-selector",
    }]);
    value["recordTypes"][0]["fields"][0]["minimumLength"] = json!(3);
    value["actions"][0]["inputs"][1]["minimumLength"] = json!(3);
    value["actions"][0]["commitGuards"] = json!({"evidence": [{
        "id": "commit-status",
        "provider": "provider",
        "requirement": "urn:example:farmer:status-v1",
        "subjects": {"farmer": {
            "profile": "farmer-number-v1",
            "selectors": {"farmer-number": {"type": "input", "input": "label"}},
        }},
        "requires": [{"output": "active", "equals": true}],
        "maximumObservationAgeSeconds": 60,
    }]});
    value["actions"][0]["plan"] = json!({
        "type": "function",
        "function": "rename-plan",
        "inputs": ["item", "label"],
        "refusals": [{"code": "rename-refused", "label": "The rename was refused."}],
        "writes": [{
            "id": "renamed",
            "target": {"fromInput": "item"},
            "operation": "patch",
            "fields": ["label"],
        }],
    });
    value
}

fn commit_evidence_source() -> Value {
    let mut value = source();
    value["evidenceProviders"] = json!([{
        "id": "provider",
        "contracts": "evidence/contracts.json",
        "subjectResolution": "trusted-provider-exact-selector",
    }]);
    value["recordTypes"][0]["fields"][0]["minimumLength"] = json!(3);
    value["actions"][0]["inputs"][1]["minimumLength"] = json!(3);
    value["actions"][0]["commitGuards"] = json!({"evidence": [{
        "id": "commit-status",
        "provider": "provider",
        "requirement": "urn:example:farmer:status-v1",
        "subjects": {"farmer": {
            "profile": "farmer-number-v1",
            "selectors": {"farmer-number": {"type": "input", "input": "label"}},
        }},
        "requires": [{"output": "active", "equals": true}],
        "maximumObservationAgeSeconds": 60,
    }]});
    value
}

#[test]
fn action_problem_examples_follow_the_execution_that_can_emit_them() {
    let proposal_assets = vec![
        ModuleAssetSource {
            module: None,
            path: "handlers/rename.rhai".into(),
            bytes: b"fn plan(ctx) { #{effects: []} }".to_vec(),
        },
        evidence_contract_asset(),
    ];
    let proposal = compile_with_assets(&proposal_handler_evidence_source(), &proposal_assets);
    let proposal_route = proposal
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let proposal_openapi: Value = serde_json::from_slice(
        &proposal
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let proposal_responses = &proposal_openapi["paths"][&proposal_route.path]["post"]["responses"];
    assert!(proposal_responses.get("500").is_none());
    assert!(proposal_responses.get("422").is_none());
    assert!(
        proposal_responses["503"]["content"]["application/problem+json"]["examples"]
            .get("action.evidence_failed")
            .is_none()
    );

    let commit_evidence =
        compile_with_assets(&commit_evidence_source(), &[evidence_contract_asset()]);
    let action = &commit_evidence.actions().actions[0];
    assert!(action.handler.is_none());
    assert!(action.evidence.is_empty());
    assert_eq!(action.commit_evidence.len(), 1);
    let invoke = commit_evidence
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let openapi: Value = serde_json::from_slice(
        &commit_evidence
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(
        openapi["paths"][&invoke.path]["post"]["responses"]["503"]["content"]
            ["application/problem+json"]["examples"]["action.evidence_failed"]
            .is_object()
    );
}

#[test]
fn reviewed_successor_drops_removed_proposal_preparation_and_application_policies() {
    let before = compile(&proposal_source(
        &["get", "edit", "submit", "cancel", "apply"],
        &["item", "label"],
    ));
    let after = compile(&proposal_source(&["get", "cancel"], &["item", "label"]));
    assert_eq!(
        before.actions().actions[0].definition_revision,
        after.actions().actions[0].definition_revision
    );
    let plan = reviewed_plan(&before, &after);
    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionChanged));
    let drops = drop_policy_sql(&plan);
    assert!(
        !drops.is_empty(),
        "revoked Proposal target policies must be removed"
    );
    assert!(drops.iter().all(|sql| !sql.contains("registry_cr_")));
}

#[test]
fn proposal_input_disclosure_change_is_reported_without_changing_frozen_execution() {
    let before = compile(&proposal_source(&["get", "cancel"], &["item", "label"]));
    let after = compile(&proposal_source(&["get", "cancel"], &["item"]));
    assert_eq!(
        before.actions().actions[0].definition_revision,
        after.actions().actions[0].definition_revision
    );
    let plan = reviewed_plan(&before, &after);
    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionChanged));
}

#[test]
fn action_only_claim_change_is_a_reviewable_successor() {
    let before = compile(&source());
    let mut changed = source();
    changed["accessProfiles"][0]["requiredScopes"] = json!(["item.rename.restricted"]);
    let after = compile(&changed);
    assert_eq!(
        before.actions().actions[0].definition_revision,
        after.actions().actions[0].definition_revision
    );
    let plan = reviewed_plan(&before, &after);
    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionChanged));
}

#[test]
fn target_record_type_changes_are_reviewed_by_record_type_rules_not_as_action_changes() {
    let value = source();
    let before = compile(&value);

    let mut reclassified = value.clone();
    reclassified["recordTypes"][0]["fields"][0]["classification"] = json!("restricted");
    let mut constrained = value;
    constrained["recordTypes"][0]["constraints"] =
        json!([{"id":"label-unique", "type":"unique", "fields":["label"]}]);

    for (variant, expected) in [
        (
            reclassified,
            CompiledRegistryChangeCode::FieldClassificationChanged,
        ),
        (constrained, CompiledRegistryChangeCode::ConstraintAdded),
    ] {
        let after = compile(&variant);
        assert_ne!(
            before.actions().actions[0].definition_revision,
            after.actions().actions[0].definition_revision,
            "the Action definition revision tracks its target record type"
        );
        assert_eq!(
            crate::immediate_actions::migration_review_revision(&before.actions().actions[0]),
            crate::immediate_actions::migration_review_revision(&after.actions().actions[0]),
            "the migration review revision ignores the target record type"
        );
        let changes = compiled_registry_change_set(&before, &after, "prior-package");
        let codes = changes
            .changes
            .iter()
            .map(|change| change.code)
            .collect::<Vec<_>>();
        assert!(
            codes.contains(&expected),
            "{expected:?} missing from {codes:?}"
        );
        assert!(
            !codes.contains(&CompiledRegistryChangeCode::ActionChanged),
            "{codes:?}"
        );
    }
}

fn reviewed_plan(before: &CompiledRegistry, after: &CompiledRegistry) -> MigrationPlan {
    let change_set = compiled_registry_change_set(before, after, "prior-package");
    let baseline = CompiledRegistryMigrationBaseline::from_compiled("prior-package", before);
    reviewed_successor_migration_plan(
        &baseline,
        after,
        &change_set,
        vec!["modules/core/migrations/action-policy/descriptor.json".to_owned()],
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    )
    .expect("reviewed successor migration plan is derived")
}

fn change_codes(plan: &MigrationPlan) -> Vec<CompiledRegistryChangeCode> {
    plan.changes.iter().map(|change| change.code).collect()
}

fn action_policy_sql(registry: &CompiledRegistry) -> Vec<String> {
    registry
        .ddl()
        .statements
        .iter()
        .filter(|statement| {
            statement.kind == DdlStatementKind::Policy
                && statement
                    .sql
                    .contains("CREATE POLICY \"registry_action_rls_")
        })
        .map(|statement| statement.sql.clone())
        .collect()
}

fn create_policy_sql(plan: &MigrationPlan) -> Vec<String> {
    plan.statements
        .iter()
        .filter(|statement| statement.sql.starts_with("CREATE POLICY "))
        .map(|statement| statement.sql.clone())
        .collect()
}

fn drop_policy_sql(plan: &MigrationPlan) -> Vec<String> {
    plan.statements
        .iter()
        .filter(|statement| statement.sql.starts_with("DROP POLICY "))
        .map(|statement| statement.sql.clone())
        .collect()
}

fn sorted(mut statements: Vec<String>) -> Vec<String> {
    statements.sort();
    statements
}

#[test]
fn reviewed_successor_installs_added_proposal_operation_policies() {
    let before = compile(&proposal_source(&["get", "cancel"], &[]));
    let after = compile(&proposal_source(
        &["get", "cancel", "edit", "submit", "apply"],
        &[],
    ));
    let plan = reviewed_plan(&before, &after);
    let before_sql = before
        .ddl()
        .statements
        .iter()
        .filter(|s| s.kind == DdlStatementKind::Policy)
        .map(|s| s.sql.clone())
        .collect::<BTreeSet<_>>();
    let expected = after
        .ddl()
        .statements
        .iter()
        .filter(|s| {
            s.kind == DdlStatementKind::Policy
                && s.sql.contains("registry_proposal_")
                && !before_sql.contains(&s.sql)
        })
        .map(|s| s.sql.clone())
        .collect::<BTreeSet<_>>();
    assert!(!expected.is_empty());
    let actual = create_policy_sql(&plan)
        .into_iter()
        .filter(|s| s.contains("registry_proposal_"))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}
