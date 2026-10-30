// SPDX-License-Identifier: Apache-2.0
//! A run follows a BReg Proposal to an outcome. Each Proposal operation pins
//! one Proposal Action, declares the host-owned `proposal` completion, and
//! returns only the outcomes its follow can observe. A run cancels only a
//! Proposal it started or submitted.
use registry_coordinator::{authoring, definition::Definition, scenarios};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const ACTION: &str = "correct-address";
const REVISION: &str = "sha256:1e2b7f1e425c009616e0ffd8123583f9a8c3f95ebb8a001679dd96c7521c6120";
const PROPOSAL: &str = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";

/// A project that calls `uses` with `correct-address`, waits on its
/// `proposal` completion and chooses on the outcome with `cases`.
fn project(uses: &str, cases: &[&str]) -> Value {
    let mut steps = json!({
        "call": {"type": "call", "operation": "follow", "input": {"type": "input"}, "next": "await"},
        "await": {"type": "wait-for", "completion": {"step": "call", "name": "proposal"},
            "timeoutSeconds": 86400, "next": "decide", "onTimeout": "late"},
        "decide": {"type": "choose", "choose": {"type": "step", "step": "await", "path": "/outcome"},
            "cases": {}},
        "late": {"type": "finish", "outcome": "late"}
    });
    for case in cases {
        steps["decide"]["cases"][case] = json!(case);
        steps[case] = json!({"type": "finish", "outcome": case,
            "output": {"type": "step", "step": "await", "path": "/proposalId"}});
    }
    let mut outcomes = json!({"late": {"type": "null"}});
    for case in cases {
        outcomes[case] = json!({"type": "string", "format": "uuid"});
    }
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "proposal-follow", "version": "1"},
        "contracts": {"facilities": {"type": "breg", "source": "facilities.json"}},
        "operations": {"follow": {"uses": uses, "connection": "facilities",
            "action": {"contract": "facilities", "id": ACTION}}},
        "workflow": {"input": {"operationInput": "follow"}, "deadlineSeconds": 2_592_000,
            "start": "call", "steps": steps, "outcomes": outcomes}
    })
}

fn write(root: &Path, project: &Value) {
    fs::write(root.join("workflow.yaml"), project.to_string()).unwrap();
    fs::write(
        root.join("facilities.json"),
        include_str!("fixtures/breg-contracts/facilities.contract.json"),
    )
    .unwrap();
}

fn cli(root: &Path, command: &str) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", command, "--project"])
        .arg(root)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), report)
}

fn check(project: &Value) -> (i32, Value) {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), project);
    cli(root.path(), "check")
}

fn codes(report: &Value) -> Vec<(String, String)> {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["code"].as_str().unwrap().to_owned(),
                item["path"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[test]
fn each_proposal_follow_names_exactly_the_outcomes_its_operation_returns() {
    let three = ["applied", "rejected", "cancelled"];
    let four = ["applied", "rejected", "cancelled", "returned"];
    for (uses, own, other) in [
        ("breg.read-proposal/v1", &three[..], &four[..]),
        ("breg.start-proposal/v1", &three[..], &four[..]),
        ("breg.submit-proposal/v1", &four[..], &three[..]),
    ] {
        let (exit, report) = check(&project(uses, own));
        assert_eq!(exit, 0, "{uses}: {report}");
        let (exit, report) = check(&project(uses, other));
        assert_eq!(exit, 1, "{uses}: {report}");
        let found = codes(&report);
        assert_eq!(found.len(), 1, "{uses}: {report}");
        assert_eq!(found[0].0, "coordinator.mapping.cases", "{uses}: {report}");
        assert!(
            found[0].1.starts_with("/workflow/steps/decide/cases"),
            "{uses}: {report}"
        );
    }
}

#[test]
fn the_proposal_completion_is_host_owned_and_follows_the_pinned_action() {
    for uses in [
        "breg.read-proposal/v1",
        "breg.start-proposal/v1",
        "breg.submit-proposal/v1",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut cases = vec!["applied", "rejected", "cancelled"];
        if uses == "breg.submit-proposal/v1" {
            cases.push("returned");
        }
        write(root.path(), &project(uses, &cases));
        let definition = Definition::load(root.path()).unwrap();
        let operation = &definition.workflow.operations["follow"];
        let action = operation.action.as_ref().unwrap();
        assert_eq!(action.action_id, ACTION);
        assert_eq!(action.action_revision, REVISION);
        let completion = &operation.completions["proposal"];
        assert_eq!(
            serde_json::to_value(&completion.kind).unwrap(),
            json!({"type": "breg-proposal"})
        );
        assert_eq!(
            completion.output["properties"]["outcome"]["enum"],
            json!(cases),
            "{uses}"
        );
        // The settled input names the Action's members, none required:
        // BReg discloses only what the connection profile may read.
        let input = &completion.output["properties"]["input"];
        assert!(input["properties"]["addressLine"].is_object(), "{input}");
        assert!(input.get("required").is_none(), "{input}");
        let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
        assert_eq!(restored.digest, definition.digest);

        let mut replaced = project(uses, &cases);
        replaced["operations"]["follow"]["completions"] = json!({"proposal": {
            "type": "bounded-poll", "interpret": "anything", "intervalSeconds": 60}});
        let (exit, report) = check(&replaced);
        assert_eq!(exit, 1, "{report}");
        assert!(
            codes(&report)
                .iter()
                .any(|(_, path)| path == "/operations/follow/completions/proposal"),
            "{report}"
        );
    }
}

#[test]
fn proposal_operations_take_only_proposal_actions_and_invoke_keeps_refusing_them() {
    for uses in [
        "breg.read-proposal/v1",
        "breg.start-proposal/v1",
        "breg.submit-proposal/v1",
        "breg.cancel-proposal/v1",
    ] {
        let mut immediate = project(uses, &["applied", "rejected", "cancelled"]);
        immediate["operations"]["follow"]["action"]["id"] = json!("register-facility");
        let (exit, report) = check(&immediate);
        assert_eq!(exit, 1, "{uses}: {report}");
        assert!(
            codes(&report)
                .iter()
                .any(|(code, _)| code == "coordinator.operation.contract-invalid"),
            "{uses}: {report}"
        );
        let mut unpinned = project(uses, &["applied", "rejected", "cancelled"]);
        unpinned["operations"]["follow"]
            .as_object_mut()
            .unwrap()
            .remove("action");
        let (exit, report) = check(&unpinned);
        assert_eq!(exit, 1, "{uses}: {report}");
    }
    let mut invoke = project("breg.invoke-action/v1", &[]);
    invoke["workflow"]["steps"] = json!({
        "call": {"type": "call", "operation": "follow", "input": {"type": "input"}, "next": "late"},
        "late": {"type": "finish", "outcome": "late"}});
    let (exit, report) = check(&invoke);
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        codes(&report)[0].0,
        "coordinator.operation.proposal-action",
        "{report}"
    );
}

/// Start a Proposal, follow it, and cancel it when no decision comes in
/// time, with the cancel's `proposalId` taken from `source`.
fn cancelling(source: Value) -> Value {
    let mut project = project(
        "breg.start-proposal/v1",
        &["applied", "rejected", "cancelled"],
    );
    project["operations"]["withdraw"] = json!({"uses": "breg.cancel-proposal/v1",
        "connection": "facilities", "action": {"contract": "facilities", "id": ACTION}});
    project["workflow"]["steps"]["await"]["onTimeout"] = json!("withdraw");
    project["workflow"]["steps"]["withdraw"] = json!({"type": "call", "operation": "withdraw",
        "input": {"type": "fields", "fields": {"proposalId": source}}, "next": "late"});
    project
}

#[test]
fn a_run_cancels_only_a_proposal_it_started_or_submitted() {
    let (exit, report) = check(&cancelling(
        json!({"type": "step", "step": "call", "path": "/proposalId"}),
    ));
    assert_eq!(exit, 0, "{report}");
    let mut submitted = cancelling(json!({"type": "step", "step": "call", "path": "/proposalId"}));
    submitted["operations"]["follow"]["uses"] = json!("breg.submit-proposal/v1");
    submitted["workflow"]["steps"]["decide"]["cases"]["returned"] = json!("returned");
    submitted["workflow"]["steps"]["returned"] = json!({"type": "finish", "outcome": "late"});
    let (exit, report) = check(&submitted);
    assert_eq!(exit, 0, "{report}");

    let mut read = cancelling(json!({"type": "step", "step": "call", "path": "/proposalId"}));
    read["operations"]["follow"]["uses"] = json!("breg.read-proposal/v1");
    for project in [
        cancelling(json!({"type": "input", "path": "/input/facilityId"})),
        cancelling(json!({"type": "literal", "value": PROPOSAL})),
        cancelling(json!({"type": "step", "step": "call", "path": "/actionId"})),
        read,
    ] {
        let (exit, report) = check(&project);
        assert_eq!(exit, 1, "{report}");
        let found = codes(&report);
        let refusal = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["code"] == "coordinator.definition.proposal-not-run-owned")
            .unwrap_or_else(|| panic!("{found:?}"));
        assert_eq!(
            refusal["path"], "/workflow/steps/withdraw/input",
            "{report}"
        );
        assert_eq!(
            refusal["message"],
            "Cancel only a request this run started or submitted: map proposalId from that step's output."
        );
    }
}

/// `check` with extra arguments, run over `project`.
fn check_with(project: &Value, args: &[&str]) -> (i32, Value) {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), project);
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "check", "--project"])
        .arg(root.path())
        .args(args)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), report)
}

#[test]
fn check_warns_when_a_proposal_wait_is_long_or_its_timeout_has_no_route() {
    let cases = ["applied", "rejected", "cancelled"];
    let (exit, report) = check_with(
        &project("breg.read-proposal/v1", &cases),
        &["--deny-warnings"],
    );
    assert_eq!(exit, 0, "a 1-day routed wait is quiet: {report}");

    let mut long = project("breg.read-proposal/v1", &cases);
    long["workflow"]["deadlineSeconds"] = json!(31_536_000);
    long["workflow"]["steps"]["await"]["timeoutSeconds"] = json!(7_776_001);
    long["workflow"]["steps"]["await"]
        .as_object_mut()
        .unwrap()
        .remove("onTimeout");
    long["workflow"]["steps"]
        .as_object_mut()
        .unwrap()
        .remove("late");
    long["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("late");
    let (exit, report) = check_with(&long, &[]);
    assert_eq!(exit, 0, "warnings alone pass check: {report}");
    let warnings = report["diagnostics"].as_array().unwrap();
    let found = |code: &str| {
        warnings
            .iter()
            .find(|item| item["code"] == code)
            .unwrap_or_else(|| panic!("{code}: {report}"))
            .clone()
    };
    let long_warning = found("coordinator.follow.long");
    assert_eq!(long_warning["severity"], "warning", "{report}");
    assert_eq!(long_warning["path"], "/workflow/steps/await/timeoutSeconds");
    assert_eq!(
        long_warning["message"],
        "This wait follows a request for more than 90 days. Long waits delay drain-based upgrades; shorten the time limit or route the timeout."
    );
    let unrouted = found("coordinator.follow.timeout-unrouted");
    assert_eq!(unrouted["severity"], "warning", "{report}");
    assert_eq!(unrouted["path"], "/workflow/steps/await");
    assert_eq!(
        unrouted["message"],
        "This wait has no route for a request that gets no decision in time, so the run fails with wait-timed-out. Add onTimeout."
    );
    assert_eq!(warnings.len(), 2, "{report}");
    let (exit, report) = check_with(&long, &["--deny-warnings"]);
    assert_eq!(exit, 1, "{report}");

    // Exactly 90 days is not more than 90 days.
    let mut ninety = project("breg.read-proposal/v1", &cases);
    ninety["workflow"]["deadlineSeconds"] = json!(31_536_000);
    ninety["workflow"]["steps"]["await"]["timeoutSeconds"] = json!(7_776_000);
    let (exit, report) = check_with(&ninety, &["--deny-warnings"]);
    assert_eq!(exit, 0, "{report}");
}

fn receipt(state: &str) -> Value {
    json!({"proposalId": PROPOSAL, "actionId": ACTION, "actionRevision": REVISION,
        "submissionVersion": 1, "state": state})
}

fn settled(outcome: &str) -> Value {
    json!({"outcome": outcome, "proposalId": PROPOSAL, "submissionVersion": 1,
        "actionRevision": REVISION,
        "decision": {"status": "approved", "decidedAt": "2026-10-20T10:00:00Z"},
        "input": {"facilityId": "c8e1f0a2-3b4c-4d5e-8f60-7a8b9c0d1e2f", "city": "Lyon"}})
}

fn start_input() -> Value {
    json!({"input": {"facilityId": "c8e1f0a2-3b4c-4d5e-8f60-7a8b9c0d1e2f",
        "addressLine": "1 rue de la Paix", "city": "Lyon", "postalCode": "69001"}})
}

/// A second wait on the same completion, reached when the first times out.
fn second_follow() -> Value {
    let mut project = project(
        "breg.start-proposal/v1",
        &["applied", "rejected", "cancelled"],
    );
    project["workflow"]["steps"]["await"]["onTimeout"] = json!("await-again");
    project["workflow"]["steps"]["await-again"] = json!({"type": "wait-for",
        "completion": {"step": "call", "name": "proposal"}, "timeoutSeconds": 86400,
        "next": "decide-again", "onTimeout": "late"});
    project["workflow"]["steps"]["decide-again"] = json!({"type": "choose",
        "choose": {"type": "step", "step": "await-again", "path": "/outcome"},
        "cases": {"applied": "late", "rejected": "late", "cancelled": "late"}});
    project
}

fn scenario(root: &Path, waits: Value, path: Value, outcome: &str) {
    let cases = json!({
        "apiVersion": scenarios::API_VERSION, "kind": scenarios::KIND,
        "cases": [{"id": "followed", "admittedAt": "2026-10-09T09:00:00Z", "input": start_input(),
            "replies": {"call": [{"type": "success", "value": receipt("draft")}]},
            "waits": waits,
            "expect": {"path": path, "state": "completed",
                "outcome": {"type": "named", "value": outcome}}}]
    });
    fs::write(root.join("scenarios.yaml"), cases.to_string()).unwrap();
}

#[test]
fn a_second_wait_follows_the_same_proposal_after_the_first_timed_out() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), &second_follow());
    scenario(
        root.path(),
        json!({"await": {"type": "timeout"}, "await-again": {"type": "event", "value": settled("applied")}}),
        json!(["call", "await", "await-again", "decide-again", "late"]),
        "late",
    );
    let (exit, report) = cli(root.path(), "test");
    assert_eq!(exit, 0, "{report}");
}

#[test]
fn a_stated_outcome_belongs_to_the_proposal_the_run_followed() {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        &project(
            "breg.start-proposal/v1",
            &["applied", "rejected", "cancelled"],
        ),
    );
    let mut other = settled("applied");
    other["proposalId"] = json!("1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d");
    scenario(
        root.path(),
        json!({"await": {"type": "event", "value": other}}),
        json!(["call", "await", "decide", "applied"]),
        "applied",
    );
    let (exit, report) = cli(root.path(), "test");
    assert_eq!(exit, 1, "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "coordinator.scenario.wait-event"
    );
    scenario(
        root.path(),
        json!({"await": {"type": "event", "value": settled("applied")}}),
        json!(["call", "await", "decide", "applied"]),
        "applied",
    );
    let (exit, report) = cli(root.path(), "test");
    assert_eq!(exit, 0, "{report}");
}
