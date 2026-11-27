// SPDX-License-Identifier: Apache-2.0

//! Two default profiles may not grant the same operation on one Proposal
//! action, so default grant selection never depends on profile id order.

use registry_breg::model::{CompiledActionExecution, ProposalOperation};
use registry_breg::{compile_project, parse_project_json, CompileFailure, CompileProfile};
use serde_json::{json, Value};

const DEFAULT_MULTIPLE: &str = "breg.proposal.default-multiple";

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
        "datasets":{"test-dataset": {}},
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

#[test]
fn overlapping_default_proposal_grants_are_refused_naming_both_profiles() {
    let Err(failure) = compile(&project(json!(["get", "edit"]), json!(["get"]))) else {
        panic!("overlapping defaults on get compiled")
    };
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == DEFAULT_MULTIPLE)
        .expect("default-multiple diagnostic");
    assert!(diagnostic.message.contains("first"), "{diagnostic:?}");
    assert!(diagnostic.message.contains("second"), "{diagnostic:?}");
    assert!(diagnostic.message.contains("get"), "{diagnostic:?}");
}

#[test]
fn default_proposal_grants_with_disjoint_operations_compile() {
    compile(&project(json!(["submit"]), json!(["get"])))
        .expect("disjoint default operations are legal");
}

/// The single default for `get` is the same profile whatever the ids sort as.
#[test]
fn the_one_default_grant_compiles_whichever_profile_id_sorts_first() {
    for (default_id, other_id) in [("alpha", "omega"), ("omega", "alpha")] {
        let mut value = project(json!(["get"]), json!(["get"]));
        let mut profiles = value["accessProfiles"].take();
        let mut default = profiles["first"].take();
        default["default"] = json!(true);
        let mut other = profiles["second"].take();
        other["default"] = json!(false);
        value["accessProfiles"] = json!({ default_id: default, other_id: other });
        let registry = compile(&value).expect("one default compiles");
        let action = &registry.actions().actions[0];
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            panic!("Proposal")
        };
        let selected = proposal
            .permissions
            .iter()
            .filter(|grant| grant.default && grant.operations.contains(&ProposalOperation::Get))
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].profile_id, default_id);
        assert!(selected[0].requester_clients.contains("first-client"));
    }
}
