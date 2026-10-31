// SPDX-License-Identifier: Apache-2.0

//! A standing agent profile (`actorKind: agent` without a `taskGrant`) may
//! read, author caller-owned Proposal drafts, and disclose an explicitly bounded
//! review context for a delegated staff subject. It carries no human approval,
//! so it can neither move a request through its lifecycle, write target records
//! directly, import records, invoke an immediate action, nor publish or
//! withdraw a statistical release: lifecycle decisions require explicit human
//! or task-grant authority.

use std::collections::BTreeSet;

use registry_breg::contract::{parse_module_json, Operation};
use registry_breg::{compile_project, parse_project_json, CompileFailure, CompileProfile};
use serde_json::{json, Value};

const OPERATION_FORBIDDEN: &str = "breg.proposal.standing-agent-operation-forbidden";
const REVIEW_CLIENT_REQUIRED: &str = "breg.proposal.standing-agent-review-client-required";
const DIRECT_MUTATION_FORBIDDEN: &str =
    "breg.access-profile.standing-agent-direct-mutation-forbidden";
const ACTION_FORBIDDEN: &str = "breg.access-profile.standing-agent-action-forbidden";
const PUBLISH_FORBIDDEN: &str = "breg.access-profile.standing-agent-publish-forbidden";
const PUBLISHER_CALLER_DEPENDENT: &str = "breg.statistical-dataset.publisher-caller-dependent";
const MODULE_TASK_GRANT_FORBIDDEN: &str = "breg.access-profile.task-grant-module-forbidden";

fn project() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"standing-agent-ceiling","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://standing-agent.example.test"},
        "datasets":[{"id":"test-dataset"}],
        "recordTypes":[
            {"id":"case","route":"cases","primaryDataset":"test-dataset","mutationMode":"mutable","classification":"internal",
                "batch":{"maximumItems":3,"maximumBytes":8192},"mutationPolicy":{"patch":"proposal-required"},
                "fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":"internal"}]},
            {"id":"note","route":"notes","primaryDataset":"test-dataset","mutationMode":"mutable","tombstone":true,"classification":"internal",
                "batch":{"maximumItems":3,"maximumBytes":8192},"fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":"internal"}]},
            {"id":"memo","route":"memos","primaryDataset":"test-dataset","mutationMode":"mutable","classification":"internal",
                "batch":{"maximumItems":3,"maximumBytes":8192},"fields":[{"id":"label","type":"string","maximumLength":32,"required":true,"classification":"internal"}]}
        ],
        "actions":[
            {"id":"relabel-note","execution":{"mode":"immediate"},"inputs":[
                {"id":"note-ref","apiName":"noteId","type":"reference","target":"note","required":true,"classification":"internal"},
                {"id":"new-label","apiName":"newLabel","type":"string","maximumLength":32,"required":true,"classification":"internal"}],
                "plan":{"type":"fixed","effects":[{"id":"relabelled","target":{"fromInput":"note-ref"},"operation":"patch","set":{"label":{"fromInput":"new-label"}}}]}},
            {"id":"correct-case","execution":{"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"retain"},"reviewContext":{"id":"case-review","fields":{"currentLabel":{"type":"record","input":"case-ref","field":"label"},"proposedLabel":{"type":"input","input":"new-label"}}}}},"inputs":[
                {"id":"case-ref","type":"reference","target":"case","required":true,"classification":"internal"},
                {"id":"new-label","type":"string","maximumLength":32,"required":true,"classification":"internal"}],
                "plan":{"type":"fixed","effects":[{"id":"corrected","target":{"fromInput":"case-ref"},"operation":"patch","set":{"label":{"fromInput":"new-label"}}}]}}
        ],
        "accessProfiles":[
            {"id":"clerk","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","actorKind":"human","requesterClients":["clerk-portal"],
                "permissions":{"records":[
                    {"recordType":"case","operations":["create","get","list","import"],"readableFields":["label"],"writableFields":["label"],"rowBoundaries":"unrestricted"},
                    {"recordType":"memo","operations":["create","get","list","patch"],"readableFields":["label"],"writableFields":["label"],"rowBoundaries":"unrestricted"},
                    {"recordType":"note","operations":["create","get","list","patch","tombstone","batch"],"readableFields":["label"],"writableFields":["label"],"rowBoundaries":"unrestricted"}],
                    "actions":[
                        {"action":"relabel-note","operations":["invoke"],"targets":[{"recordType":"note","rowBoundaries":"unrestricted"}],"results":["relabelled"]},
                        {"action":"correct-case","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}],
                    "proposals":[{"action":"correct-case","operations":["get","list","edit","submit","revise","cancel","apply","rebase","retry","get-review-status"],"ownership":"caller","targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]}},
            {"id":"assistant","principalClaim":"registry_principal","requiredScopes":"unrestricted","actorKind":"agent","requesterClients":["assistant-client"],
                "permissions":{"records":[
                    {"recordType":"case","operations":["get","list"],"readableFields":["label"],"rowBoundaries":"unrestricted"},
                    {"recordType":"memo","operations":["get","list"],"readableFields":["label"],"writableFields":["label"],"rowBoundaries":"unrestricted"},
                    {"recordType":"note","operations":["get","list"],"readableFields":["label"],"writableFields":["label"],"rowBoundaries":"unrestricted"}],
                    "actions":[{"action":"correct-case","operations":["start"],"targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}],
                    "proposals":[{"action":"correct-case","operations":["edit"],"ownership":"caller","targets":[{"recordType":"case","rowBoundaries":"unrestricted"}]}]}}
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
/// proposal-required target, 1 another native Record, and 2 a Record
/// without change control.
fn with_assistant_operation(permission: usize, operation: &str) -> Value {
    let mut value = project();
    value["accessProfiles"][1]["permissions"]["records"][permission]["operations"]
        .as_array_mut()
        .expect("operations array")
        .push(json!(operation));
    value
}

#[test]
fn standing_agent_may_read_and_author_caller_owned_proposal_drafts() {
    use registry_breg::model::{CompiledActionExecution, ProposalOperation};
    let registry = compile(&project()).expect("reads and caller-owned draft authoring compile");
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-case")
        .unwrap();
    assert!(action.permissions.iter().any(
        |grant| grant.profile_id == "assistant" && grant.operations.contains(&Operation::Start)
    ));
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal")
    };
    let draft = proposal
        .permissions
        .iter()
        .find(|grant| grant.profile_id == "assistant")
        .unwrap();
    assert_eq!(draft.operations, BTreeSet::from([ProposalOperation::Edit]));
}

#[test]
fn standing_agent_may_hold_only_bounded_review_context_disclosure() {
    use registry_breg::model::{CompiledActionExecution, ProposalOperation};

    let mut value = project();
    value["accessProfiles"][1]["permissions"]["actions"] = json!([]);
    value["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] =
        json!(["get-review-context"]);
    value["accessProfiles"][1]["permissions"]["proposals"][0]
        .as_object_mut()
        .expect("proposal permission")
        .remove("ownership");
    value["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["currentLabel", "proposedLabel"]);

    let registry = compile(&value).expect("bounded standing-agent context read compiles");
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-case")
        .expect("compiled proposal action");
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal")
    };
    let permission = proposal
        .permissions
        .iter()
        .find(|permission| permission.profile_id == "assistant")
        .expect("standing-agent review permission");
    assert_eq!(
        permission.operations,
        BTreeSet::from([ProposalOperation::GetReviewContext])
    );
    assert!(action
        .permissions
        .iter()
        .all(|permission| permission.profile_id != "assistant"));
}

#[test]
fn standing_agent_review_context_requires_an_exact_requester_client() {
    let mut value = project();
    value["accessProfiles"][1]["permissions"]["actions"] = json!([]);
    value["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] =
        json!(["get-review-context"]);
    value["accessProfiles"][1]["permissions"]["proposals"][0]
        .as_object_mut()
        .expect("proposal permission")
        .remove("ownership");
    value["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["currentLabel", "proposedLabel"]);
    value["accessProfiles"][1]
        .as_object_mut()
        .expect("standing agent profile")
        .remove("requesterClients");

    let failure = refused(
        compile(&value),
        "a standing-agent review disclosure without an exact client",
    );
    assert!(codes(&failure).contains(&REVIEW_CLIENT_REQUIRED));
}

#[test]
fn standing_agent_review_context_refuses_an_authored_empty_requester_client_list() {
    let mut value = project();
    value["accessProfiles"][1]["permissions"]["actions"] = json!([]);
    value["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] =
        json!(["get-review-context"]);
    value["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["currentLabel", "proposedLabel"]);
    value["accessProfiles"][1]["requesterClients"] = json!([]);
    let failure = parse_project_json(&serde_json::to_vec(&value).expect("project serializes"))
        .expect_err("an authored empty requesterClients list is invalid configuration");
    assert!(codes(&failure).contains(&"config.invalid-value"));
}

#[test]
fn human_profile_may_import_records() {
    let registry = compile(&project()).expect("a human profile keeps import authority");
    let target = &registry.entities()["case"].access_profiles["clerk"];
    assert!(target.operations.contains(&Operation::Import));
}

#[test]
fn standing_agent_cannot_hold_a_proposal_lifecycle_decision() {
    for operation in [
        "get",
        "list",
        "submit",
        "revise",
        "cancel",
        "apply",
        "rebase",
        "retry",
        "get-review-status",
    ] {
        let mut value = project();
        value["accessProfiles"][1]["permissions"]["proposals"][0]["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!(operation));
        let failure = refused(
            compile(&value),
            "a standing agent cannot decide a Proposal lifecycle operation",
        );
        assert!(
            codes(&failure).contains(&OPERATION_FORBIDDEN),
            "{operation}: {:?}",
            codes(&failure)
        );
        assert!(!codes(&failure).contains(&DIRECT_MUTATION_FORBIDDEN));
    }
    let mut value = project();
    value["accessProfiles"][1]["permissions"]["proposals"][0]["ownership"] = json!("any");
    assert!(
        parse_project_json(&serde_json::to_vec(&value).unwrap()).is_err(),
        "ownership has no any-caller escape"
    );
}

#[test]
fn standing_agent_cannot_hold_a_direct_target_mutation() {
    for (permission, operation) in [
        (0, "create"),
        (2, "create"),
        (2, "patch"),
        (2, "tombstone"),
        (2, "batch"),
        (0, "import"),
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
fn standing_agent_cannot_batch_record_writes() {
    let mut value = with_assistant_operation(1, "batch");
    value["recordTypes"][2]["batch"] = json!({"maximumItems": 3, "maximumBytes": 8192});
    let failure = refused(
        compile(&value),
        "batch does not create Proposal draft authority",
    );
    assert!(
        codes(&failure).contains(&DIRECT_MUTATION_FORBIDDEN),
        "native batch was not refused: {:?}",
        codes(&failure)
    );
}

/// An immediate action commits its effects at once, with no draft for a human
/// to confirm, so a standing agent may not hold one.
fn with_assistant_action(value: &mut Value) {
    value["accessProfiles"][1]["permissions"]["actions"] = json!([{
        "action": "relabel-note", "operations": ["invoke"],
        "targets": [{"recordType": "note", "rowBoundaries": "unrestricted"}], "results": ["relabelled"]
    }]);
}

#[test]
fn standing_agent_cannot_hold_an_immediate_action() {
    let mut value = project();
    with_assistant_action(&mut value);
    let failure = refused(
        compile(&value),
        "a standing agent cannot invoke an immediate action",
    );
    let codes = codes(&failure);
    assert!(
        codes.contains(&ACTION_FORBIDDEN),
        "invoke was not refused: {codes:?}"
    );
    assert!(
        !codes.contains(&OPERATION_FORBIDDEN) && !codes.contains(&DIRECT_MUTATION_FORBIDDEN),
        "invoke is neither a lifecycle operation nor a record write: {codes:?}"
    );
}

#[test]
fn human_profiles_keep_immediate_actions() {
    // The human profile in the base project invokes the action; a human
    // profile bound to the agent's client keeps it too.
    let mut value = project();
    value["accessProfiles"][1]["actorKind"] = json!("human");
    with_assistant_action(&mut value);
    let registry = compile(&value).expect("human profiles keep immediate actions");
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "relabel-note")
        .expect("the action compiles");
    let profiles: BTreeSet<&str> = action
        .permissions
        .iter()
        .map(|grant| grant.profile_id.as_str())
        .collect();
    assert_eq!(profiles, BTreeSet::from(["assistant", "clerk"]));
}

/// The base project with a statistical dataset counting notes, and the
/// operations the human profile and the standing agent hold on it. Publishing
/// and withdrawing a release commit at once, with no draft for a human to
/// confirm.
fn with_dataset(clerk: &[&str], assistant: &[&str]) -> Value {
    let mut value = project();
    value["recordTypes"][1]["fields"]
        .as_array_mut()
        .expect("fields array")
        .extend([
            json!({"id": "open", "type": "boolean", "required": true, "classification": "internal"}),
            json!({"id": "filed", "type": "date", "required": true, "classification": "internal"}),
        ]);
    value["project"]["timezone"] = json!("UTC");
    value["statisticalDatasets"] = json!([{
        "id": "notes-by-status", "unit": "note", "population": "open eq true",
        "period": {"type": "flow", "field": "filed", "granularity": "month", "firstPeriod": "2025-01"},
        "dimensions": ["open"],
        "disclosure": {"minimumCount": 5, "roundingBase": 5}
    }]);
    for (profile, operations) in [(0, clerk), (1, assistant)] {
        let permissions = &mut value["accessProfiles"][profile]["permissions"];
        let note = &mut permissions["records"][2];
        note["readableFields"] = json!(["label", "open", "filed"]);
        note["filterableFields"] = json!(["open", "filed"]);
        note["allowCount"] = json!(true);
        if !operations.is_empty() {
            permissions["datasets"] =
                json!([{"dataset": "notes-by-status", "operations": operations}]);
        }
    }
    value
}

fn publisher(registry: &registry_breg::CompiledRegistry) -> &str {
    registry.statistical_datasets()["notes-by-status"]
        .releases
        .as_ref()
        .expect("the dataset has a publisher")
        .publisher
        .as_str()
}

/// The dataset project whose publisher `statistician` is a project profile
/// granting nothing on the unit entity, compiled with a module that
/// contributes the unit entity profile of the same id and the given actor
/// kind.
fn compile_with_module_unit_profile(
    actor_kind: &str,
) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let mut value = with_dataset(&[], &[]);
    value["modules"] = json!([{"id": "assistant-extension", "version": "1"}]);
    value["accessProfiles"]
        .as_array_mut()
        .expect("profiles array")
        .push(json!({
            "id": "statistician", "principalClaim": "registry_principal", "requiredScopes": "unrestricted",
            "permissions": {"datasets": [{"dataset": "notes-by-status", "operations": ["publish", "read-releases"]}]}
        }));
    let project = parse_project_json(&serde_json::to_vec(&value).expect("project serializes"))
        .expect("project parses");
    let module = parse_module_json(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id": "assistant-extension", "version": "1",
            "extendRecordTypes": [{
                "recordType": "note",
                "accessProfiles": [{
                    "id": "statistician", "principalClaim": "registry_principal",
                    "actorKind": actor_kind, "requesterClients": ["assistant-client"],
                    "operations": ["list"], "allowCount": true,
                    "readableFields": ["label", "open", "filed"], "filterableFields": ["open", "filed"],
                    "requiredScopes": "unrestricted", "rowBoundaries": "unrestricted"
                }]
            }]
        }))
        .expect("module serializes"),
    )
    .expect("module parses");
    compile_project(
        &project,
        std::slice::from_ref(&module),
        CompileProfile::Authoring,
    )
}

#[test]
fn standing_agent_cannot_publish_a_statistical_release() {
    for clerk in [&[][..], &["read-live", "read-releases"]] {
        let failure = refused(
            compile(&with_dataset(clerk, &["publish", "read-releases"])),
            "a standing agent cannot publish or withdraw a statistical release",
        );
        let codes = codes(&failure);
        assert!(
            codes.contains(&PUBLISH_FORBIDDEN),
            "publish was not refused: {codes:?}"
        );
        assert!(
            failure.diagnostics().iter().any(|diagnostic| {
                diagnostic.code == PUBLISH_FORBIDDEN
                    && diagnostic.path
                        == "project.accessProfiles[id=assistant].permissions.datasets[dataset=notes-by-status].operations"
            }),
            "the refusal does not name the permission: {:?}",
            failure.diagnostics()
        );
        assert!(
            !codes.contains(&OPERATION_FORBIDDEN)
                && !codes.contains(&DIRECT_MUTATION_FORBIDDEN)
                && !codes.contains(&ACTION_FORBIDDEN),
            "publish is neither a lifecycle operation, a record write, nor an action: {codes:?}"
        );
    }

    // Publishing and withdrawing authorize through the publisher's profile on
    // the unit entity, so a module-contributed standing agent is refused
    // there, and the same profile declared human publishes.
    let failure = refused(
        compile_with_module_unit_profile("agent"),
        "a module cannot contribute a standing agent that publishes",
    );
    let refusal = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == PUBLISH_FORBIDDEN)
        .unwrap_or_else(|| panic!("module publisher was not refused: {:?}", codes(&failure)));
    assert_eq!(
        refusal.path,
        "recordTypes[id=note].accessProfiles[id=statistician]"
    );

    let registry =
        compile_with_module_unit_profile("human").expect("a human unit profile publishes");
    assert_eq!(publisher(&registry), "statistician");
}

#[test]
fn standing_agent_may_read_statistical_counts_and_releases() {
    let registry = compile(&with_dataset(
        &["publish", "read-releases"],
        &["read-live", "read-releases"],
    ))
    .expect("a standing agent keeps live counts and releases");
    let dataset = &registry.statistical_datasets()["notes-by-status"];
    assert!(dataset.live_profiles.contains("assistant"));
    assert_eq!(publisher(&registry), "clerk");

    let registry = compile(&with_dataset(
        &["publish", "read-releases"],
        &["read-releases"],
    ))
    .expect("a standing agent keeps releases alone");
    let releases = registry.statistical_datasets()["notes-by-status"]
        .releases
        .as_ref()
        .expect("the dataset has a publisher");
    assert!(releases.readers.contains("assistant"));
}

#[test]
fn human_service_and_unspecified_profiles_keep_publish() {
    // The same profile publishes once it is no longer an agent: bound to the
    // agent's client as a human or as a service, and with no actor kind at all.
    for actor_kind in ["human", "service"] {
        let mut direct = with_dataset(&[], &["publish", "read-releases"]);
        direct["accessProfiles"][1]["actorKind"] = json!(actor_kind);
        let registry = compile(&direct).unwrap_or_else(|failure| {
            panic!("a {actor_kind} profile lost publish: {:?}", codes(&failure))
        });
        assert_eq!(publisher(&registry), "assistant");
    }

    let mut unspecified = with_dataset(&[], &["publish", "read-releases"]);
    let profile = unspecified["accessProfiles"][1]
        .as_object_mut()
        .expect("profile object");
    profile.remove("actorKind");
    profile.remove("requesterClients");
    let registry = compile(&unspecified).expect("a profile with no actor kind keeps publish");
    assert_eq!(publisher(&registry), "assistant");
}

#[test]
fn task_grant_profile_cannot_be_a_dataset_publisher() {
    // A task-grant profile declares requiredPurposes, and a publisher's
    // authority admits none, so the publisher rules refuse it.
    let mut delegated = with_dataset(&[], &["publish", "read-releases"]);
    delegated["accessProfiles"][1]["requiredPurposes"] = json!(["correction-review"]);
    delegated["accessProfiles"][1]["taskGrant"] =
        json!({"sourceIssuer": "https://casework.example"});
    let failure = refused(
        compile(&delegated),
        "a task-grant profile cannot publish a statistical release",
    );
    let codes = codes(&failure);
    assert!(
        codes.contains(&PUBLISHER_CALLER_DEPENDENT),
        "a task-grant publisher was not refused: {codes:?}"
    );
    assert!(!codes.contains(&PUBLISH_FORBIDDEN));
}

#[test]
fn module_contributed_standing_agent_profiles_meet_the_same_ceiling() {
    let mut value = project();
    value["modules"] = json!([{"id": "assistant-extension", "version": "1"}]);
    let project = parse_project_json(&serde_json::to_vec(&value).expect("project serializes"))
        .expect("project parses");
    for (entity, operation, code) in [
        ("memo", "create", DIRECT_MUTATION_FORBIDDEN),
        ("note", "patch", DIRECT_MUTATION_FORBIDDEN),
        ("case", "import", DIRECT_MUTATION_FORBIDDEN),
    ] {
        let module = parse_module_json(
            &serde_json::to_vec(&json!({
                "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
                "id": "assistant-extension", "version": "1",
                "extendRecordTypes": [{
                    "recordType": entity,
                    "accessProfiles": [{
                        "id": "module-assistant", "principalClaim": "registry_principal",
                        "actorKind": "agent", "requesterClients": ["assistant-client"],
                        "operations": ["get", operation],
                        "readableFields": ["label"], "writableFields": ["label"],
                        "requiredScopes": "unrestricted", "rowBoundaries": "unrestricted"
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
    compile(&project()).expect("a human keeps lifecycle and direct writes");
    let mut delegated = project();
    delegated["accessProfiles"][1]["requiredPurposes"] = json!(["correction-review"]);
    delegated["accessProfiles"][1]["taskGrant"] =
        json!({"sourceIssuer":"https://casework.example"});
    delegated["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] = json!([
        "get",
        "list",
        "edit",
        "submit",
        "revise",
        "cancel",
        "apply",
        "rebase",
        "retry",
        "get-review-status"
    ]);
    compile(&delegated).expect("explicit task grants retain bounded Proposal lifecycle operations");
    let mut delegated_action = delegated.clone();
    with_assistant_action(&mut delegated_action);
    compile(&delegated_action).expect("an explicit task-grant profile can invoke a named Action");
    for (index, operation) in [
        (2, "patch"),
        (0, "import"),
        (2, "create"),
        (2, "batch"),
        (2, "tombstone"),
    ] {
        let mut direct = delegated.clone();
        direct["accessProfiles"][1]["permissions"]["records"][index]["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!(operation));
        let failure = refused(
            compile(&direct),
            "task grants cannot authorize native Record mutations",
        );
        assert!(
            codes(&failure).contains(&"breg.access-profile.task-grant-direct-mutation-forbidden")
        );
        assert!(!codes(&failure).contains(&DIRECT_MUTATION_FORBIDDEN));
    }
}

#[test]
fn module_contributed_profiles_cannot_declare_a_task_grant() {
    // A task grant is authored only in project accessProfiles, where its
    // ceiling is checked. A module profile declaring one would otherwise
    // escape the standing-agent ceiling and meet no task-grant ceiling.
    let mut value = project();
    value["modules"] = json!([{"id": "assistant-extension", "version": "1"}]);
    let project = parse_project_json(&serde_json::to_vec(&value).expect("project serializes"))
        .expect("project parses");
    let delegated_profile = json!({
        "id": "module-assistant", "principalClaim": "registry_principal",
        "actorKind": "agent", "requesterClients": ["assistant-client"],
        "taskGrant": {"sourceIssuer": "http://not-https.example", "permissions": []},
        "operations": ["get", "list", "patch"],
        "readableFields": ["label"], "writableFields": ["label"],
                        "requiredScopes": "unrestricted", "rowBoundaries": "unrestricted"
    });
    for module in [
        json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id": "assistant-extension", "version": "1",
            "extendRecordTypes": [{"recordType": "note", "accessProfiles": [delegated_profile.clone()]}]
        }),
        json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id": "assistant-extension", "version": "1",
            "recordTypes": [{
                "id": "archive", "primaryDataset": "test-dataset", "route": "archives",
                "mutationMode": "mutable", "classification": "internal",
                "fields": [{"id": "label", "type": "string", "maximumLength": 32, "required": true, "classification": "internal"}],
                "accessProfiles": [delegated_profile.clone()]
            }]
        }),
    ] {
        let module = parse_module_json(&serde_json::to_vec(&module).expect("module serializes"))
            .expect("module parses");
        let failure = refused(
            compile_project(
                &project,
                std::slice::from_ref(&module),
                CompileProfile::Authoring,
            ),
            "a module cannot contribute a task-grant profile",
        );
        assert!(
            codes(&failure).contains(&MODULE_TASK_GRANT_FORBIDDEN),
            "module task grant was not refused: {:?}",
            codes(&failure)
        );
    }
}
