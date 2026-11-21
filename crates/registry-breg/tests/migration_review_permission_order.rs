// SPDX-License-Identifier: Apache-2.0

//! The migration review revision ignores the order of an Action's grants.
//! Grants are keyed by profile id, so a reorder alone carries no meaning, while
//! a changed default flag or operation set still changes the revision.

use registry_breg::immediate_actions::migration_review_revision;
use registry_breg::model::{CompiledAction, CompiledActionExecution};
use registry_breg::{compile_project, parse_project_json, CompileFailure, CompileProfile};
use serde_json::{json, Value};

fn proposal_grant(operations: Value, client: &str) -> Value {
    json!({
        "principalClaim":"registry_principal","requiredScopes":"unrestricted","actorKind":"human",
        "requesterClients":[client],
        "permissions":{"records":[
            {"recordType":"case","operations":["get","list"],"readableFields":["label"],"rowBoundaries":"unrestricted"}],
            "proposals":[{"action":"correct-case","operations":operations,"ownership":"caller",
                "targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]}
    })
}

/// Two human profiles named `first` and `second`, both default, granting the
/// given operations on `correct-case`. The `first` profile also holds Start.
fn project(first: Value, second: Value) -> Value {
    let mut first = proposal_grant(first, "first-client");
    first["default"] = json!(true);
    first["permissions"]["actions"] = json!([
        {"action":"correct-case","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]);
    let mut second = proposal_grant(second, "second-client");
    second["default"] = json!(true);
    // Only `first` holds Record grants, so the Record default rule stays out of play.
    second["permissions"]["records"] = json!([]);
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"default-grants","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://default-grants.example.test"},
        "datasets":[{"id":"test-dataset"}],
        "recordTypes":{
            "case": {"route":"cases","primaryDataset":"test-dataset","mutationMode":"mutable","classification":"internal",
                "batch":{"maximumItems":3,"maximumBytes":8192},"mutationPolicy":{"patch":"proposal-required"},
                "fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":"internal"}]}},
        "actions":{
            "correct-case": {"execution":{"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"retain"}}},"inputs":[
                {"id":"case-ref","type":"reference","target":"case","required":true,"classification":"internal"},
                {"id":"new-label","type":"string","maximumLength":32,"required":true,"classification":"internal"}],
                "plan":{"type":"fixed","effects":[{"id":"corrected","target":{"fromInput":"case-ref"},"operation":"patch","set":{"label":{"fromInput":"new-label"}}}]}}},
        "accessProfiles":{"first": first, "second": second}
    })
}

fn compile(value: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(value).expect("project serializes"))
        .expect("project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn compile_action(value: &Value) -> CompiledAction {
    compile(value).expect("project compiles").actions().actions[0].clone()
}

fn reversed(action: &CompiledAction) -> CompiledAction {
    let mut action = action.clone();
    action.permissions.reverse();
    if let CompiledActionExecution::Proposal { proposal } = &mut action.execution {
        proposal.permissions.reverse();
    }
    action
}

#[test]
fn reordering_grants_keeps_the_migration_review_revision() {
    let action = compile_action(&project(json!(["edit"]), json!(["get"])));
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal")
    };
    assert_eq!(proposal.permissions.len(), 2);
    let flipped = reversed(&action);
    let CompiledActionExecution::Proposal { proposal } = &flipped.execution else {
        panic!("Proposal")
    };
    assert_eq!(proposal.permissions[0].profile_id, "second");
    assert_eq!(
        migration_review_revision(&action),
        migration_review_revision(&flipped)
    );
}

#[test]
fn reordering_start_grants_keeps_the_migration_review_revision() {
    let mut value = project(json!(["edit"]), json!(["get"]));
    value["accessProfiles"]["second"]["default"] = json!(false);
    value["accessProfiles"]["second"]["permissions"]["actions"] = json!([
        {"action":"correct-case","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]);
    let action = compile_action(&value);
    assert_eq!(action.permissions.len(), 2);
    assert_eq!(
        migration_review_revision(&action),
        migration_review_revision(&reversed(&action))
    );
}

#[test]
fn a_changed_default_flag_or_operation_still_changes_the_revision() {
    let base = project(json!(["edit"]), json!(["get"]));
    let before = migration_review_revision(&compile_action(&base));

    let mut no_default = base.clone();
    no_default["accessProfiles"]["second"]["default"] = json!(false);
    assert_ne!(
        before,
        migration_review_revision(&compile_action(&no_default))
    );

    let mut other_operation = base;
    other_operation["accessProfiles"]["second"]["permissions"]["proposals"][0]["operations"] =
        json!(["list"]);
    assert_ne!(
        before,
        migration_review_revision(&compile_action(&other_operation))
    );
}
