// SPDX-License-Identifier: Apache-2.0

//! A standing agent profile (`actorKind: agent` without a `taskGrant`) may
//! read and author change-request drafts. It carries no human approval, so it
//! can neither move a request through its lifecycle nor write target records
//! directly: a human submits.

use std::collections::BTreeSet;

use registry_breg::contract::{parse_module_json, Operation};
use registry_breg::{compile_project, parse_project_json, CompileFailure, CompileProfile};
use serde_json::{json, Value};

const OPERATION_FORBIDDEN: &str = "access_profile.standing_agent.operation_forbidden";
const DIRECT_MUTATION_FORBIDDEN: &str = "access_profile.standing_agent.direct_mutation_forbidden";

fn project() -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {"id": "standing-agent-ceiling", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://standing-agent.example.test"},
        "entities": [
            {
                "id": "case", "primaryDataset": "test-dataset", "route": "cases",
                "mutationMode": "mutable", "classification": "internal",
                "changeControl": {"requiredFor": ["patch"]},
                "fields": [{"id": "label", "type": "string", "maxLength": 32, "required": true, "classification": "internal"}]
            },
            {
                "id": "note", "primaryDataset": "test-dataset", "route": "notes",
                "mutationMode": "mutable", "tombstone": true, "classification": "internal",
                "batch": {"maximumItems": 3, "maximumBytes": 8192},
                "fields": [{"id": "label", "type": "string", "maxLength": 32, "required": true, "classification": "internal"}]
            },
            {
                "id": "correction", "primaryDataset": "test-dataset", "route": "corrections",
                "mutationMode": "mutable", "classification": "internal",
                "fields": [
                    {"id": "case", "type": "reference", "target": "case", "required": true, "classification": "internal"},
                    {"id": "label", "type": "string", "maxLength": 32, "required": true, "classification": "internal"}
                ],
                "changeRequest": {
                    "effects": [{"id": "relabel", "target": {"fromField": "case"}, "operation": "patch", "set": {"label": {"fromField": "label"}}}],
                    "review": {"authority": "casework-main", "policyId": "correction-review"},
                    "onApproved": {"mode": "manual"}
                }
            }
        ],
        "accessProfiles": [
            {
                "id": "clerk", "default": true, "principalClaim": "registry_principal",
                "actorKind": "human", "requesterClients": ["clerk-portal"],
                "permissions": [
                    {
                        "entity": "case",
                        "operations": ["create", "get", "list"],
                        "readableFields": ["label"], "writableFields": ["label"], "rowBoundaries": []
                    },
                    {
                        "entity": "correction",
                        "operations": ["create", "get", "list", "patch", "submit_request", "revise_request", "cancel_request", "apply_request"],
                        "readableFields": ["case", "label"], "writableFields": ["case", "label"], "rowBoundaries": [],
                        "applyTargets": [{"entity": "case", "rowBoundaries": []}]
                    },
                    {
                        "entity": "note",
                        "operations": ["create", "get", "list", "patch", "tombstone", "batch"],
                        "readableFields": ["label"], "writableFields": ["label"], "rowBoundaries": []
                    }
                ]
            },
            {
                "id": "assistant", "principalClaim": "registry_principal",
                "actorKind": "agent", "requesterClients": ["assistant-client"],
                "permissions": [
                    {"entity": "case", "operations": ["get", "list"], "readableFields": ["label"], "rowBoundaries": []},
                    {
                        "entity": "correction",
                        "operations": ["create", "get", "list", "patch"],
                        "readableFields": ["case", "label"], "writableFields": ["case", "label"], "rowBoundaries": []
                    },
                    {"entity": "note", "operations": ["get", "list"], "readableFields": ["label"], "writableFields": ["label"], "rowBoundaries": []}
                ]
            }
        ]
    })
}

fn compile(value: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(value).expect("project serializes"))
        .expect("project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn codes(failure: &CompileFailure) -> Vec<&str> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

/// Compiles a project expected to be refused, without printing the compiled
/// registry when it is not.
fn refused(
    result: Result<registry_breg::CompiledRegistry, CompileFailure>,
    case: &str,
) -> CompileFailure {
    match result {
        Ok(_) => panic!("{case} compiled"),
        Err(failure) => failure,
    }
}

/// Profile index 1 is the standing agent. Its permission 0 is the
/// change-controlled target, 1 the change-request entity, and 2 an entity
/// without change control.
fn with_assistant_operation(permission: usize, operation: &str) -> Value {
    let mut value = project();
    value["accessProfiles"][1]["permissions"][permission]["operations"]
        .as_array_mut()
        .expect("operations array")
        .push(json!(operation));
    value
}

#[test]
fn standing_agent_may_read_and_author_change_request_drafts() {
    let registry = compile(&project()).expect("reads and draft authoring compile");
    let draft = &registry.entities()["correction"].access_profiles["assistant"];
    assert_eq!(
        draft.operations,
        BTreeSet::from([
            Operation::Create,
            Operation::Get,
            Operation::List,
            Operation::Patch
        ])
    );
}

#[test]
fn standing_agent_cannot_hold_a_request_lifecycle_operation() {
    for operation in [
        "submit_request",
        "revise_request",
        "cancel_request",
        "apply_request",
    ] {
        let failure = refused(
            compile(&with_assistant_operation(1, operation)),
            "a standing agent cannot move a request through its lifecycle",
        );
        let codes = codes(&failure);
        assert!(
            codes.contains(&OPERATION_FORBIDDEN),
            "{operation} was not refused: {codes:?}"
        );
        assert!(
            !codes.contains(&DIRECT_MUTATION_FORBIDDEN),
            "{operation} is not a direct mutation: {codes:?}"
        );
    }
}

#[test]
fn standing_agent_cannot_hold_a_direct_target_mutation() {
    for (permission, operation) in [
        (0, "create"),
        (2, "create"),
        (2, "patch"),
        (2, "tombstone"),
        (2, "batch"),
    ] {
        let failure = refused(
            compile(&with_assistant_operation(permission, operation)),
            "a standing agent cannot write a target record directly",
        );
        let codes = codes(&failure);
        assert!(
            codes.contains(&DIRECT_MUTATION_FORBIDDEN),
            "{operation} was not refused: {codes:?}"
        );
        assert!(
            !codes.contains(&OPERATION_FORBIDDEN),
            "{operation} is not a lifecycle operation: {codes:?}"
        );
    }
}

#[test]
fn standing_agent_cannot_batch_change_request_drafts() {
    let mut value = with_assistant_operation(1, "batch");
    value["entities"][2]["batch"] = json!({"maximumItems": 3, "maximumBytes": 8192});
    let failure = refused(compile(&value), "only draft create and patch are allowed");
    assert!(
        codes(&failure).contains(&DIRECT_MUTATION_FORBIDDEN),
        "batch on a draft was not refused: {:?}",
        codes(&failure)
    );
}

#[test]
fn module_contributed_standing_agent_profiles_meet_the_same_ceiling() {
    let mut value = project();
    value["modules"] = json!([{"id": "assistant-extension", "version": "1"}]);
    let project = parse_project_json(&serde_json::to_vec(&value).expect("project serializes"))
        .expect("project parses");
    for (entity, operation, code) in [
        ("correction", "submit_request", OPERATION_FORBIDDEN),
        ("note", "patch", DIRECT_MUTATION_FORBIDDEN),
    ] {
        let module = parse_module_json(
            &serde_json::to_vec(&json!({
                "id": "assistant-extension", "version": "1",
                "extendEntities": [{
                    "entity": entity,
                    "accessProfiles": [{
                        "id": "module-assistant", "principalClaim": "registry_principal",
                        "actorKind": "agent", "requesterClients": ["assistant-client"],
                        "operations": ["get", operation],
                        "readableFields": ["label"], "writableFields": ["label"], "rowBoundaries": []
                    }]
                }]
            }))
            .expect("module serializes"),
        )
        .expect("module parses");
        let failure = refused(
            compile_project(
                &project,
                std::slice::from_ref(&module),
                CompileProfile::Authoring,
            ),
            "a module cannot contribute a wider standing agent",
        );
        assert!(
            codes(&failure).contains(&code),
            "module {operation} on {entity} was not refused: {:?}",
            codes(&failure)
        );
    }
}

#[test]
fn task_grant_and_human_profiles_keep_their_ceilings() {
    // The human profile in the base project holds every lifecycle and direct
    // write operation.
    compile(&project()).expect("a human profile keeps lifecycle and direct writes");

    let mut delegated = project();
    delegated["accessProfiles"][1]["requiredPurposes"] = json!(["correction-review"]);
    delegated["accessProfiles"][1]["taskGrant"] =
        json!({"sourceIssuer": "https://casework.example"});
    delegated["accessProfiles"][1]["permissions"][1]["operations"] = json!([
        "create",
        "get",
        "list",
        "patch",
        "submit_request",
        "revise_request",
        "cancel_request"
    ]);
    compile(&delegated).expect("a task grant keeps submit, revise and cancel");

    let mut delegated_apply = delegated.clone();
    delegated_apply["accessProfiles"][1]["permissions"][1]["operations"]
        .as_array_mut()
        .expect("operations array")
        .push(json!("apply_request"));
    let failure = refused(compile(&delegated_apply), "a task grant still cannot apply");
    let apply_codes = codes(&failure);
    assert!(apply_codes.contains(&"access_profile.task_grant.operation_forbidden"));
    assert!(!apply_codes.contains(&OPERATION_FORBIDDEN));

    let mut delegated_direct = delegated;
    delegated_direct["accessProfiles"][1]["permissions"][2]["operations"] =
        json!(["get", "list", "patch"]);
    let failure = refused(
        compile(&delegated_direct),
        "a task grant still cannot write directly",
    );
    let direct_codes = codes(&failure);
    assert!(direct_codes.contains(&"access_profile.task_grant.direct_mutation_forbidden"));
    assert!(!direct_codes.contains(&DIRECT_MUTATION_FORBIDDEN));
}
