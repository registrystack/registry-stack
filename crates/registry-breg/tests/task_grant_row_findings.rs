// SPDX-License-Identifier: Apache-2.0

//! A task-grant profile pins rows to the grant only where it authors a row
//! boundary. The compiler flags a profile, Action target, or Proposal target
//! that binds no rows, even when the profile requires scopes and purposes.

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

const UNBOUND: &str = "breg.access-profile.task-grant-rows-unbound";

fn boundary() -> Value {
    json!({"field":"tenant","claim":"tenant_claim","operator":"equals"})
}

fn project(rows: Value, classification: &str) -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"task-rows","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://task-rows.example.test"},
        "datasets":[{"id":"test-dataset"}],
        "recordTypes":[
            {"id":"case","route":"cases","primaryDataset":"test-dataset","mutationMode":"mutable","classification":classification,
                "mutationPolicy":{"patch":"proposal-required"},
                "fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":classification},
                          {"id":"tenant","type":"string","maximumLength":32,"required":true,"classification":classification}]},
            {"id":"note","route":"notes","primaryDataset":"test-dataset","mutationMode":"mutable","classification":classification,
                "fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":classification},
                          {"id":"tenant","type":"string","maximumLength":32,"required":true,"classification":classification}]}
        ],
        "actions":[
            {"id":"relabel-note","execution":{"mode":"immediate"},"inputs":[
                {"id":"note-ref","apiName":"noteId","type":"reference","target":"note","required":true,"classification":classification},
                {"id":"new-label","apiName":"newLabel","type":"string","maximumLength":32,"required":true,"classification":classification}],
                "plan":{"type":"fixed","effects":[{"id":"relabelled","target":{"fromInput":"note-ref"},"operation":"patch","set":{"label":{"fromInput":"new-label"}}}]}},
            {"id":"correct-case","execution":{"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"retain"},"reviewContext":{"id":"case-review","fields":{"currentLabel":{"type":"record","input":"case-ref","field":"label"},"proposedLabel":{"type":"input","input":"new-label"}}}}},"inputs":[
                {"id":"case-ref","type":"reference","target":"case","required":true,"classification":classification},
                {"id":"new-label","type":"string","maximumLength":32,"required":true,"classification":classification}],
                "plan":{"type":"fixed","effects":[{"id":"corrected","target":{"fromInput":"case-ref"},"operation":"patch","set":{"label":{"fromInput":"new-label"}}}]}}
        ],
        "accessProfiles":[
            {"id":"delegated","principalClaim":"registry_principal","requiredScopes":["registry.read"],
                "requiredPurposes":["correction-review"],"actorKind":"agent","requesterClients":["task-agent"],
                "taskGrant":{"sourceIssuer":"https://casework.example"},
                "permissions":{
                    "records":[{"recordType":"case","operations":["get"],"readableFields":["label"],"rowBoundaries":rows.clone()}],
                    "actions":[
                        {"action":"relabel-note","operations":["invoke"],"targets":[{"recordType":"note","rowBoundaries":rows.clone()}],"results":["relabelled"]},
                        {"action":"correct-case","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":rows.clone()}]}],
                    "proposals":[{"action":"correct-case","operations":["get","edit"],"ownership":"caller","targets":[{"recordType":"case","rowBoundaries":rows}]}]}}
        ]
    })
}

fn compile(value: &Value) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(value).expect("project serializes"))
        .expect("project parses");
    compile_project(&project, &[], CompileProfile::Authoring).unwrap_or_else(|failure| {
        panic!(
            "project did not compile: {:?}",
            failure
                .diagnostics()
                .iter()
                .map(|d| (&d.code, &d.path))
                .collect::<Vec<_>>()
        )
    })
}

fn unbound_paths(registry: &CompiledRegistry) -> Vec<String> {
    let mut paths = registry
        .findings()
        .iter()
        .filter(|finding| finding.code == UNBOUND)
        .map(|finding| finding.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[test]
fn scoped_task_grant_profile_without_row_boundaries_is_flagged_everywhere() {
    let registry = compile(&project(json!("unrestricted"), "internal"));
    assert_eq!(
        unbound_paths(&registry),
        [
            "actions[id=correct-case].execution.proposal.permissions[profile=delegated].targets[recordType=case].rowBoundaries",
            "actions[id=correct-case].permissions[profile=delegated].targets[recordType=case].rowBoundaries",
            "actions[id=relabel-note].permissions[profile=delegated].targets[recordType=note].rowBoundaries",
            "recordTypes[id=case].accessProfiles[id=delegated].rowBoundaries",
        ]
    );
}

#[test]
fn task_grant_profile_with_row_boundaries_draws_no_finding() {
    let registry = compile(&project(json!([boundary()]), "internal"));
    assert_eq!(unbound_paths(&registry), Vec::<String>::new());
}

#[test]
fn public_record_types_and_standing_profiles_draw_no_finding() {
    let registry = compile(&project(json!("unrestricted"), "public"));
    assert_eq!(unbound_paths(&registry), Vec::<String>::new());

    let mut standing = project(json!("unrestricted"), "internal");
    standing["accessProfiles"][0]
        .as_object_mut()
        .expect("profile object")
        .remove("taskGrant");
    // A standing agent holds no immediate Action and only drafts Proposals.
    standing["actions"]
        .as_array_mut()
        .expect("actions array")
        .remove(0);
    let permissions = standing["accessProfiles"][0]["permissions"]
        .as_object_mut()
        .expect("permissions object");
    permissions["actions"]
        .as_array_mut()
        .expect("action permissions")
        .remove(0);
    permissions["proposals"][0]["operations"] = json!(["edit"]);
    let registry = compile(&standing);
    assert_eq!(unbound_paths(&registry), Vec::<String>::new());
}
