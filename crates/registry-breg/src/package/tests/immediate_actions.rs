// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{compile_project, parse_project_json, CompileProfile};
use serde_json::json;

fn source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"action-package", "version":"1", "defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{"id":"item", "primaryDataset":"test-dataset", "route":"items", "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maxLength":40, "required":true, "classification":"internal"}]}],
        "actions":[{"id":"rename-item", "inputs":[
            {"id":"item", "apiName":"itemId", "type":"reference", "target":"item", "required":true, "classification":"internal"},
            {"id":"label", "apiName":"newLabel", "type":"string", "maxLength":40, "required":true, "classification":"internal"}
        ], "effects":[{"id":"renamed", "target":{"fromField":"item"}, "operation":"patch", "set":{"label":{"fromField":"label"}}}]}],
        "accessProfiles":[{"id":"operator", "default":true, "principalClaim":"principal", "requiredScopes":["item.rename"],
            "permissions":[{"action":"rename-item", "operations":["invoke"], "targets":[{"entity":"item", "rowBoundaries":[]}], "results":["renamed"]}]}]
    })
}

fn compile(value: &Value) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

fn source_without_actions() -> Value {
    let mut value = source();
    value["actions"] = json!([]);
    value["accessProfiles"] = json!([]);
    value
}

fn ordinary_policy_source(auditor_operations: Option<&[&str]>) -> Value {
    let mut source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"policy-package", "version":"1", "defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{"id":"person", "primaryDataset":"test-dataset", "route":"people", "mutationMode":"mutable",
            "fields":[
                {"id":"person-code", "type":"string", "maxLength":40, "required":true, "classification":"internal"},
                {"id":"sensitive-note", "type":"string", "maxLength":120, "classification":"internal"}
            ]}],
        "accessProfiles":[{"id":"operator", "default":true, "principalClaim":"principal",
            "permissions":[{"entity":"person", "operations":["create","get","list"],
                "readableFields":["person-code","sensitive-note"],
                "writableFields":["person-code","sensitive-note"], "rowBoundaries":[]}]}]
    });
    if let Some(operations) = auditor_operations {
        let mut permission = json!({
            "entity":"person", "operations":operations, "rowBoundaries":[]
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
                "requiredScopes":["registry.audit"], "permissions":[permission]
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
    no_results["accessProfiles"][0]["permissions"][0]["results"] = json!([]);
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
fn reviewed_successor_adds_action_policies_for_existing_entity() {
    let before = compile(&source_without_actions());
    let after = compile(&source());
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionAdded));
    assert!(
        change_set_to_applicable_migration_plan(&CompiledRegistryChangeSet {
            from_revision: "prior-package".to_owned(),
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
    candidate["entities"]
        .as_array_mut()
        .expect("entities are an array")
        .push(json!({
            "id":"task",
            "primaryDataset":"test-dataset",
            "route":"tasks",
            "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maxLength":40, "required":true, "classification":"internal"}]
        }));
    candidate["actions"] = json!([{
        "id":"create-task",
        "inputs":[{"id":"label", "apiName":"label", "type":"string", "maxLength":40, "required":true, "classification":"internal"}],
        "effects":[{"id":"task", "target":{"entity":"task"}, "operation":"create", "set":{"label":{"fromField":"label"}}}]
    }]);
    candidate["accessProfiles"] = json!([{
        "id":"task-operator",
        "default":true,
        "principalClaim":"principal",
        "permissions":[{"action":"create-task", "operations":["invoke"], "targets":[{"entity":"task", "rowBoundaries":[]}], "results":["task"]}]
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
    changed["accessProfiles"][0]["requiredScopes"] = json!(["item.rename.restricted"]);
    let after = compile(&changed);
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::ActionChanged));
    let drops = drop_policy_sql(&plan);
    let creates = create_policy_sql(&plan);
    assert_eq!(drops.len(), action_policy_sql(&before).len());
    assert_eq!(sorted(creates.clone()), sorted(action_policy_sql(&after)));
    for create in creates {
        assert!(
            create.contains(&after.actions().actions[0].contract_fingerprint),
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
    without_action["entities"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"group", "primaryDataset":"test-dataset", "route":"groups", "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maxLength":40,
                "required":true, "classification":"internal"}]
        }));
    without_action["entities"][0]["fields"]
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
    with_action["actions"][0]["effects"][0]["set"]["group"] = json!({"fromField":"group"});
    with_action["accessProfiles"][0]["permissions"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "entity":"group", "rowBoundaries":[]
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
    with_action["accessProfiles"][0]["requiredScopes"] = json!(["item.rename.changed"]);
    let changed = compile(&with_action);
    let replaced = reviewed_plan(&after, &changed);
    for name in links {
        assert!(drop_policy_sql(&replaced)
            .iter()
            .any(|sql| sql.contains(&name)));
        assert!(create_policy_sql(&replaced)
            .iter()
            .any(|sql| sql.contains(&name)
                && sql.contains(&changed.actions().actions[0].contract_fingerprint)));
    }
}

#[test]
fn reviewed_successor_does_not_drop_action_policies_for_absent_entity_table() {
    let before = compile(&source());
    let mut removed_entity = source_without_actions();
    removed_entity["entities"] = json!([{
        "id":"other",
        "primaryDataset":"test-dataset",
        "route":"others",
        "mutationMode":"mutable",
        "fields":[{"id":"label", "type":"string", "maxLength":40, "required":true, "classification":"internal"}]
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

fn change_request_source(operator_operations: &[&str]) -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"change-request-package", "version":"1", "defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{
            "id":"asset", "primaryDataset":"test-dataset", "route":"assets", "mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[{"id":"label", "type":"string", "maxLength":40, "required":true, "classification":"internal"}]
        },{
            "id":"asset-request", "primaryDataset":"test-dataset", "route":"asset-requests", "mutationMode":"mutable",
            "fields":[
                {"id":"asset", "type":"reference", "target":"asset", "required":true, "classification":"internal"},
                {"id":"label", "type":"string", "maxLength":40, "required":true, "classification":"internal"}
            ],
            "changeRequest":{
                "effects":[{"id":"apply-label","target":{"fromField":"asset"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
                "review":{"authority":"casework-main","policyId":"request-review"},
                "onApproved":{"mode":"manual"}
            }
        }],
        "accessProfiles":[{
            "id":"operator", "default":true, "principalClaim":"principal",
            "permissions":[{
                "entity":"asset-request", "operations": operator_operations,
                "readableFields":["asset","label"], "writableFields":["asset","label"],
                "applyTargets":[{"entity":"asset", "rowBoundaries":[]}],
                "rowBoundaries":[]
            }]
        }]
    })
}

/// A change-request action grant (`submit_request`, `revise_request`,
/// `cancel_request`, `apply_request`) compiles to a `registry_cr_action_rls_`
/// policy on the request entity's own table. Removing the grant must drop
/// that policy in the reviewed successor plan, the same way removing an
/// immediate-action grant drops its `registry_action_rls_` policy.
#[test]
fn reviewed_successor_drops_change_request_action_policy_when_grant_is_removed() {
    let before = compile(&change_request_source(&[
        "get",
        "list",
        "submit_request",
        "cancel_request",
        "apply_request",
    ]));
    let after = compile(&change_request_source(&[
        "get",
        "list",
        "submit_request",
        "apply_request",
    ]));
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::AccessProfileChanged));
    let drops = drop_policy_sql(&plan);
    assert!(
        drops
            .iter()
            .any(|sql| sql.contains("registry_cr_action_rls_")),
        "removing the cancel_request grant must drop its registry_cr_action_rls_ policy, got: {drops:?}"
    );
}

fn change_request_source_with_reviewer_profile(reviewer_operations: &[&str]) -> Value {
    let mut source = change_request_source(&["get", "list", "submit_request", "apply_request"]);
    source["accessProfiles"]
        .as_array_mut()
        .expect("accessProfiles array")
        .push(json!({
            "id":"reviewer-extra", "principalClaim":"principal",
            "permissions":[{
                "entity":"asset-request", "operations": reviewer_operations,
                "readableFields":["asset","label"], "writableFields":["asset","label"],
                "rowBoundaries":[]
            }]
        }));
    source
}

/// The same stale-policy gap applies to the change-request target "prepare"
/// policies (`registry_cr_rls_`), generated per profile holding submit or
/// revise authority on the request entity. Removing a second profile's
/// `submit_request` grant must drop its stale policy in the reviewed
/// successor plan, while `operator` keeps the type's only apply coverage
/// unchanged so the plan compiles on both sides.
#[test]
fn reviewed_successor_drops_change_request_target_policy_when_submit_grant_is_removed() {
    let before = compile(&change_request_source_with_reviewer_profile(&[
        "get",
        "list",
        "submit_request",
    ]));
    let after = compile(&change_request_source_with_reviewer_profile(&[
        "get", "list",
    ]));
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::AccessProfileChanged));
    let drops = drop_policy_sql(&plan);
    assert!(
        drops.iter().any(|sql| sql.contains("registry_cr_rls_")),
        "removing the reviewer profile's submit_request grant must drop its registry_cr_rls_ target policy, got: {drops:?}"
    );
}

fn change_request_source_with_presence_profile(include_presence: bool) -> Value {
    let mut source = change_request_source(&["get", "list", "submit_request", "apply_request"]);
    let mut viewer_permission = json!({
        "entity":"asset", "operations":["get"],
        "readableFields":["label"], "writableFields":[],
        "rowBoundaries":[]
    });
    if include_presence {
        viewer_permission["requestPresence"] =
            json!([{"requestType":"asset-request","rowBoundaries":[]}]);
    }
    source["accessProfiles"]
        .as_array_mut()
        .expect("accessProfiles array")
        .push(json!({
            "id":"asset-viewer", "principalClaim":"principal",
            "permissions":[viewer_permission]
        }));
    source
}

/// Change-request presence policies (`registry_cr_presence_rls_`) come from a
/// `requestPresence` grant on the target entity's own profile, independent of
/// the request entity's submit or apply authority. Removing that grant must
/// drop its stale presence policy in the reviewed successor plan.
#[test]
fn reviewed_successor_drops_change_request_presence_policy_when_grant_is_removed() {
    let before = compile(&change_request_source_with_presence_profile(true));
    let after = compile(&change_request_source_with_presence_profile(false));
    let plan = reviewed_plan(&before, &after);

    assert!(change_codes(&plan).contains(&CompiledRegistryChangeCode::AccessProfileChanged));
    let drops = drop_policy_sql(&plan);
    assert!(
        drops
            .iter()
            .any(|sql| sql.contains("registry_cr_presence_rls_")),
        "removing the requestPresence grant must drop its registry_cr_presence_rls_ policy, got: {drops:?}"
    );
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
