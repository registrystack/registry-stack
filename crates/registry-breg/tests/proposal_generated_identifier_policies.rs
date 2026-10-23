// SPDX-License-Identifier: Apache-2.0

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::generated_ddl::PolicyCommand;
use serde_json::{json, Value};

fn project() -> Value {
    json!({
        "datasets": [{"id": "test-dataset"}],
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "generated-only-proposal-policy",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://proposal-policy.example.test"
        },
        "recordTypes": [{
            "id": "registration",
            "primaryDataset": "test-dataset",
            "route": "registrations",
            "mutationMode": "mutable",
            "fields": [{
                "id": "number",
                "type": "string",
                "minimumLength": 1,
                "maximumLength": 32,
                "required": true,
                "classification": "internal",
                "generate": {"type": "sequence", "minimumDigits": 1}
            }]
        }],
        "actions": [{
            "id": "register",
            "inputs": [{
                "id": "confirmed",
                "type": "boolean",
                "required": true,
                "classification": "internal"
            }],
            "execution": {
                "mode": "proposal",
                "proposal": {
                    "review": {"type": "none"},
                    "application": {"mode": "manual"},
                    "retention": {"mode": "retain"}
                }
            },
            "plan": {"type": "fixed", "effects": [{
                "id": "registration",
                "target": {"recordType": "registration"},
                "operation": "create",
                "set": {}
            }]}
        }],
        "accessProfiles": [{
            "id": "operator",
            "default": true,
            "principalClaim": "principal",
            "requiredScopes": "unrestricted",
            "permissions": {
                "actions": [{
                    "action": "register",
                    "operations": ["start"],
                    "targets": [{
                        "recordType": "registration",
                        "rowBoundaries": "unrestricted"
                    }]
                }],
                "proposals": [{
                    "action": "register",
                    "operations": ["apply"],
                    "ownership": "caller",
                    "targets": [{
                        "recordType": "registration",
                        "rowBoundaries": "unrestricted"
                    }]
                }]
            }
        }]
    })
}

fn compile(project: &Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(project).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("Proposal project compiles")
}

fn registration_policies(
    registry: &registry_breg::CompiledRegistry,
) -> &[registry_breg::generated_ddl::DdlPolicy] {
    let table = registry
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "registration")
        .expect("registration table");
    &table.policies
}

#[test]
fn manual_proposal_generated_only_create_emits_insert_policy() {
    let registry = compile(&project());
    let policy = registration_policies(&registry)
        .iter()
        .find(|policy| {
            policy.access_profile == "operator" && policy.command == PolicyCommand::Insert
        })
        .expect("manual Proposal application has an INSERT policy");

    assert!(
        policy
            .check_expression
            .as_deref()
            .is_some_and(|expression| expression.contains("'[\"number\"]'::jsonb")),
        "generated identifier is included in the INSERT field ceiling: {policy:?}"
    );
}

#[test]
fn patch_only_proposal_does_not_gain_generated_identifier_insert_policy() {
    let mut project = project();
    project["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "label",
            "type": "string",
            "maximumLength": 32,
            "classification": "internal"
        }));
    project["actions"][0]["inputs"] = json!([
        {
            "id": "registration",
            "type": "reference",
            "target": "registration",
            "required": true,
            "classification": "internal"
        },
        {
            "id": "label",
            "type": "string",
            "maximumLength": 32,
            "required": true,
            "classification": "internal"
        }
    ]);
    project["actions"][0]["plan"]["effects"][0] = json!({
        "id": "registration",
        "target": {"fromInput": "registration"},
        "operation": "patch",
        "set": {"label": {"fromInput": "label"}}
    });

    let registry = compile(&project);
    assert!(registration_policies(&registry).iter().all(|policy| {
        policy.access_profile != "operator" || policy.command != PolicyCommand::Insert
    }));
}
