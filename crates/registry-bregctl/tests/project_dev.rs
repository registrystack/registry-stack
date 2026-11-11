// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn project(root: &std::path::Path, extra: &str) {
    fs::write(
        root.join("registry.yaml"),
        include_str!(
            "../../../products/platform/conformance/projects/breg-project-dev/registry/registry.yaml"
        ),
    )
    .unwrap();
    fs::write(
        root.join("dev.yaml"),
        format!(
            "# yaml-language-server: $schema=https://id.registrystack.org/schemas/breg/project-dev/project-dev.v1alpha1.schema.json\n\
apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n\
kind: BRegProjectDev\n\
issuer: https://issuer.example.invalid\n\
products:\n  - {{product: breg, project: ., audience: registry}}\n\
people:\n  operator:\n    subject: operator\n    client: operator-client\n    grants:\n      breg: {{profile: operator, scopes: []}}\n\
journey:\n  id: smoke\n  steps:\n    - {{id: read, product: breg, as: operator, method: GET, path: /v1/records, expect: {{status: 200}}}}\n\
{extra}"
        ),
    )
    .unwrap();
}

const RUN_ID: &str = "0123456789abcdef0123456789abcdef";

/// Validates a helper failure against the documented error schema and checks
/// its class.
fn assert_error_envelope(report: &serde_json::Value, class: &str) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../products/platform/schemas/rstack-dev-error.v1.schema.json"
    ))
    .unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    if let Err(errors) = schema.validate(report) {
        let errors: Vec<_> = errors.map(|error| error.to_string()).collect();
        panic!("{report} violates the error schema: {errors:?}");
    }
    assert_eq!(report["error"]["class"], class, "{report}");
}

fn helper(request: serde_json::Value, state: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap()
}

/// A run directory whose supervisor is gone: its lock file exists, unlocked.
fn lost_run(state: &std::path::Path) -> std::path::PathBuf {
    let root = state.join(RUN_ID);
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("worker.lock"), "").unwrap();
    root
}

#[test]
fn every_helper_failure_prints_the_error_envelope() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    lost_run(&state);
    let missing_project = scratch.path().join("missing");
    let other_run = "fedcba9876543210fedcba9876543210";
    let cases = [
        (
            "start of a missing project",
            serde_json::json!({"action": "start", "project": missing_project, "json": true}),
            "domain",
            1,
        ),
        (
            "start with a bad ttl",
            serde_json::json!({"action": "start", "project": scratch.path(), "ttl": "9", "json": true}),
            "usage",
            2,
        ),
        (
            "status with a malformed run ID",
            serde_json::json!({"action": "status", "run_id": "../x", "json": true}),
            "usage",
            2,
        ),
        (
            "token with a malformed person",
            serde_json::json!({"action": "token", "run_id": other_run, "person": "../x", "json": true}),
            "usage",
            2,
        ),
        (
            "token for a run that is not ready",
            serde_json::json!({"action": "token", "run_id": other_run, "person": "operator", "json": true}),
            "domain",
            1,
        ),
        (
            "stop with a malformed run ID",
            serde_json::json!({"action": "stop", "run_id": "../x", "json": true}),
            "usage",
            2,
        ),
        (
            "recover with a malformed run ID",
            serde_json::json!({"action": "stop", "run_id": "../x", "json": true, "recover": true}),
            "usage",
            2,
        ),
        (
            "status of a run whose supervisor is lost",
            serde_json::json!({"action": "status", "run_id": RUN_ID, "json": true}),
            "operational",
            3,
        ),
        (
            "stop of a run whose supervisor is lost",
            serde_json::json!({"action": "stop", "run_id": RUN_ID, "json": true}),
            "operational",
            3,
        ),
    ];
    for (name, request, class, exit) in cases {
        let output = helper(request, &state);
        assert_eq!(output.status.code(), Some(exit), "{name}: {output:?}");
        assert!(output.stderr.is_empty(), "{name}: {output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{name}: {error}: {output:?}"));
        assert_error_envelope(&report, class);
        if class == "operational" {
            assert_eq!(report["run_id"], RUN_ID, "{name}");
            assert_eq!(report["recovery"]["kind"], "lost-supervisor", "{name}");
        } else {
            assert!(report.get("run_id").is_none(), "{name}: {report}");
        }
    }
}

#[test]
fn a_helper_failure_without_json_prints_one_line_and_the_same_exit_class() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    lost_run(&state);
    let output = helper(
        serde_json::json!({"action": "status", "run_id": RUN_ID, "json": false}),
        &state,
    );
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.starts_with("rstack dev: run "), "{text}");
    assert!(text.contains("lost its supervisor"), "{text}");
}

fn recover(state: &std::path::Path, run_id: &str) -> std::process::Output {
    helper(
        serde_json::json!({"action": "stop", "run_id": run_id, "json": true, "recover": true}),
        state,
    )
}

#[test]
fn recover_of_an_absent_run_reports_it_stopped() {
    let scratch = tempfile::tempdir().unwrap();
    let output = recover(&scratch.path().join("state"), RUN_ID);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "stopped");
}

#[test]
fn recover_refuses_a_run_with_a_running_supervisor() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let root = lost_run(&state);
    let lock = fs::File::open(root.join("worker.lock")).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();

    let output = recover(&state, RUN_ID);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    let message = report["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("still has a running supervisor"),
        "{message}"
    );
    assert!(root.exists());
}

#[test]
fn recover_refuses_a_run_without_a_supervisor_lock() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let root = lost_run(&state);
    fs::remove_file(root.join("worker.lock")).unwrap();

    let output = recover(&state, RUN_ID);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    assert!(root.exists());
}

#[test]
fn recover_that_cannot_proceed_reports_the_facts_and_changes_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let root = lost_run(&state);

    let output = recover(&state, RUN_ID);

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_error_envelope(&report, "operational");
    assert_eq!(report["run_id"], RUN_ID);
    assert_eq!(report["recovery"]["kind"], "lost-supervisor");
    assert!(report["recovery"]["run_directory"]
        .as_str()
        .unwrap()
        .ends_with(RUN_ID));
    let message = report["error"]["message"].as_str().unwrap();
    assert!(message.contains("could not be recovered"), "{message}");
    assert!(root.exists());
}

fn semantic_project(root: &std::path::Path, grant: &str, step_extra: &str) {
    fs::write(root.join("registry.yaml"), "fixture\n").unwrap();
    fs::write(
        root.join("dev.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n\
kind: BRegProjectDev\n\
issuer: https://issuer.example.invalid\n\
products:\n  - {{product: breg, project: ., audience: private-audience-marker}}\n\
people:\n  operator:\n    subject: private-subject-marker\n    client: private-client-marker\n    grants:\n      {grant}: {{profile: private-profile-marker, scopes: []}}\n\
journey:\n  id: smoke\n  steps:\n    - id: read\n      product: breg\n      as: operator\n      method: GET\n      path: /v1/records\n      expect: {{status: 200}}\n{step_extra}"
        ),
    )
    .unwrap();
}

fn fixture_project(root: &std::path::Path, extra: &str) {
    project(root, extra);
    fs::create_dir(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/journeys.yaml"),
        concat!(
            "apiVersion: id.registrystack.org/formats/breg/journeys/v1\n",
            "kind: BRegJourneys\n",
            "journeys:\n",
            "  - id: real-journey\n",
            "    steps:\n",
            "      - id: real-step\n",
            "        recordType: record\n",
            "        accessProfile: operator\n",
            "        claims: {principal: fixture-operator}\n",
            "        request: {type: list}\n",
            "        expect: {outcome: success, status: 200, count: 0}\n",
        ),
    )
    .unwrap();
}

fn check(root: &std::path::Path, state: &std::path::Path, json: bool) -> std::process::Output {
    let request = serde_json::json!({
        "action": "check", "project": root, "deny_warnings": true, "json": json,
    });
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap()
}

fn start(root: &std::path::Path, state: &std::path::Path) -> std::process::Output {
    let request = serde_json::json!({
        "action": "start", "project": root, "json": true,
    });
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap()
}

fn check_with_casework_tool(
    root: &std::path::Path,
    state: &std::path::Path,
    tool: &std::path::Path,
) -> std::process::Output {
    let request = serde_json::json!({
        "action": "check", "project": root, "deny_warnings": true, "json": true,
    });
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env("RSTACK_CASEWORKCTL_BIN", tool)
        .env_remove("RSTACK_CASEWORK_BIN")
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap()
}

fn start_with_casework_tool(
    root: &std::path::Path,
    state: &std::path::Path,
    tool: &std::path::Path,
) -> std::process::Output {
    let request = serde_json::json!({
        "action": "start", "project": root, "json": true,
    });
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env("RSTACK_CASEWORKCTL_BIN", tool)
        .env_remove("RSTACK_CASEWORK_BIN")
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap()
}

fn fake_casework_tool(root: &std::path::Path) -> std::path::PathBuf {
    fake_casework_tool_with_status_profile(root, "operator")
}

/// A `caseworkctl` whose `proposal-context` provider names `status_profile`
/// for the `service-status` capability. Its `check` refuses a runtime file
/// whose context provider resource is `registry`, as Casework does.
fn fake_casework_tool_with_status_profile(
    root: &std::path::Path,
    status_profile: &str,
) -> std::path::PathBuf {
    let tool = root.join("caseworkctl");
    fs::write(
        &tool,
        concat!(
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n",
            "[[ $1 == --format && $2 == json && -f $4/casework.yaml ]]\n",
            "if [[ $3 == check ]]; then\n",
            "  [[ $# -eq 6 && $5 == --runtime-config && -f $6 ]]\n",
            "  if grep -q '\"resource\":\"registry\"' \"$6\"; then\n",
            "    printf '%s\\n' '",
            "{\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"command\":\"check\",\"status\":\"domain-refusal\",\"ok\":false,",
            "\"diagnostics\":[{\"severity\":\"error\",\"code\":\"casework.runtime.invalid-context-provider\",",
            "\"artifact\":\"CaseworkRuntimeConfig\",\"path\":\"/contextProviders/proposal-context/resource\",",
            "\"message\":\"contextProviders.proposal-context.resource: the resource must be one absolute URI without a fragment or userinfo\",",
            "\"suggestedAction\":\"Correct the context provider member so it meets the rule the message names.\"}]}'\n",
            "    exit 1\n",
            "  fi\n",
            "  printf '%s\\n' '",
            "{\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"command\":\"check\",\"status\":\"complete\",\"ok\":true,",
            "\"diagnostics\":[]}'\n",
            "  exit 0\n",
            "fi\n",
            "[[ $# -eq 4 && $3 == explain ]]\n",
            "printf '%s\\n' '",
            "{\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"command\":\"explain\",\"status\":\"complete\",\"ok\":true,",
            "\"accessProfiles\":[{\"id\":\"reviewer\",\"principalClaim\":\"sub\"}],",
            "\"reviewPolicies\":[{\"dependencies\":{\"accessProfiles\":[{\"id\":\"reviewer\",\"principalClaim\":\"sub\"}]}}],",
            "\"trustedProducers\":[{\"id\":\"review-producer\"}],",
            "\"contextProviders\":[{\"id\":\"proposal-context\",",
            "\"serviceProfiles\":{\"service-status\":\"",
        )
        .to_owned()
            + status_profile
            + "\"}}]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&tool).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&tool, permissions).unwrap();
    tool
}

fn casework_reference_project(
    root: &std::path::Path,
    casework_profile: &str,
    bindings: &str,
) -> std::path::PathBuf {
    fs::write(
        root.join("registry.yaml"),
        include_str!(
            "../../../products/platform/conformance/projects/breg-project-dev/registry/registry.yaml"
        ),
    )
    .unwrap();
    fs::create_dir(root.join("casework")).unwrap();
    fs::write(root.join("casework/casework.yaml"), "fixture\n").unwrap();
    fs::create_dir(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/journeys.yaml"),
        concat!(
            "apiVersion: id.registrystack.org/formats/breg/journeys/v1\n",
            "kind: BRegJourneys\n",
            "journeys:\n",
            "  - id: real-journey\n",
            "    steps:\n",
            "      - id: real-step\n",
            "        recordType: record\n",
            "        accessProfile: operator\n",
            "        claims: {principal: fixture-operator}\n",
            "        request: {type: list}\n",
            "        expect: {outcome: success, status: 200, count: 0}\n",
        ),
    )
    .unwrap();
    fs::write(
        root.join("dev.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n\
kind: BRegProjectDev\n\
issuer: https://issuer.example.invalid\n\
products:\n  - {{product: breg, project: ., audience: \"urn:example:registry\"}}\n  - {{product: casework, project: casework, audience: \"urn:example:review\"}}\n\
people:\n  operator:\n    subject: operator\n    client: operator-client\n    grants:\n      breg: {{profile: operator, scopes: [registry:read]}}\n  reviewer:\n    subject: reviewer\n    client: reviewer-client\n    grants:\n      casework: {{profile: {casework_profile}, scopes: [casework:review]}}\n\
journey:\n  id: smoke\n  steps:\n    - {{id: read, product: breg, as: operator, method: GET, path: /v1/records, expect: {{status: 200}}}}\n\
{bindings}"
        ),
    )
    .unwrap();
    fake_casework_tool(root)
}

fn assert_dangling_schema_assignment(
    extra: &str,
    path: &str,
    message: &str,
    suggested_action: &str,
) {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fixture_project(scratch.path(), extra);

    let checked = check(scratch.path(), &state, true);

    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(report["kind"], "BRegCtlReport");
    assert_eq!(report["command"], "dev-check");
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "breg.project-dev.invalid-plan");
    assert_eq!(diagnostic["path"], path);
    assert_eq!(diagnostic["message"], message);
    assert_eq!(diagnostic["suggestedAction"], suggested_action);
    assert!(!state.exists());

    let started = start(scratch.path(), &state);

    assert_eq!(started.status.code(), Some(1), "{started:?}");
    let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(error.contains(path), "{error}");
    assert!(error.contains(message), "{error}");
    assert!(error.contains(suggested_action), "{error}");
    assert!(!state.exists());
}

#[test]
fn check_validates_the_closed_plan_without_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "");

    let result = check(scratch.path(), &state, true);

    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["kind"], "BRegCtlReport");
    assert_eq!(report["command"], "dev-check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["ok"], true);
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert!(!state.exists());
}

#[test]
fn check_accepts_a_project_with_encrypted_fields_without_allocating_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "");
    let registry = scratch.path().join("registry.yaml");
    let source = fs::read_to_string(&registry).unwrap();
    let encrypted = source
        .replacen(
            "mutationMode: mutable\n    display: {label: Record",
            "mutationMode: mutable\n    classification: restricted\n    display: {label: Record",
            1,
        )
        .replacen(
            "- {id: name, type: string, required: true, minimumLength: 1, maximumLength: 100, classification: internal}\n      - {id: owner",
            "- {id: name, type: string, required: true, minimumLength: 1, maximumLength: 100, classification: restricted, encrypted: true}\n      - {id: owner",
            1,
        );
    assert_eq!(encrypted.matches("encrypted: true").count(), 1);
    fs::write(&registry, encrypted).unwrap();

    let result = check(scratch.path(), &state, true);

    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(result.status.success(), "{report}");
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert!(!state.exists());
}

#[test]
fn check_and_start_reject_an_unknown_fixture_journey_without_allocating_state() {
    assert_dangling_schema_assignment(
        "schemaTestPeople:\n  \"private/journey~marker\":\n    real-step: operator\n",
        "/schemaTestPeople/private~1journey~0marker/real-step",
        "The schema test assignment names a BReg fixture journey that does not exist.",
        "Set the journey key to a journey defined in tests/journeys.yaml, or remove this assignment.",
    );
}

#[test]
fn check_and_start_reject_an_unknown_fixture_step_without_allocating_state() {
    assert_dangling_schema_assignment(
        "schemaTestPeople:\n  real-journey:\n    \"private/step~marker\": operator\n",
        "/schemaTestPeople/real-journey/private~1step~0marker",
        "The schema test assignment names a BReg fixture step that does not exist in the named journey.",
        "Set the step key to a step defined in that fixture journey, or remove this assignment.",
    );
}

#[test]
fn check_accepts_a_valid_explicit_fixture_assignment_without_allocating_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fixture_project(
        scratch.path(),
        "schemaTestPeople:\n  real-journey:\n    real-step: operator\n",
    );

    let result = check(scratch.path(), &state, true);

    assert!(result.status.success(), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "complete");
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert!(!state.exists());
}

#[test]
fn implicit_fixture_person_refusals_keep_the_intended_assignment_pointer() {
    for ambiguous in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let state = scratch.path().join("state");
        fixture_project(scratch.path(), "");
        let plan = fs::read_to_string(scratch.path().join("dev.yaml")).unwrap();
        let plan = if ambiguous {
            plan.replace(
                "journey:\n",
                "  second:\n    subject: second\n    client: second-client\n    grants:\n      breg: {profile: operator, scopes: []}\njourney:\n",
            )
        } else {
            plan.replace("profile: operator", "profile: other")
        };
        fs::write(scratch.path().join("dev.yaml"), plan).unwrap();

        let result = check(scratch.path(), &state, true);

        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(
            diagnostic["path"],
            "/schemaTestPeople/real-journey/real-step"
        );
        assert_eq!(
            diagnostic["message"],
            "A BReg fixture step must resolve to exactly one test person with matching profile, scopes, and purpose."
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "Add or update a matching BReg grant, or select the matching person in schemaTestPeople."
        );
        assert!(!state.exists());
    }
}

#[test]
fn check_and_start_report_an_explicit_assignment_with_no_fixture_file() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(
        scratch.path(),
        "schemaTestPeople:\n  real-journey:\n    real-step: operator\n",
    );

    let checked = check(scratch.path(), &state, true);

    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/schemaTestPeople");
    assert_eq!(
        diagnostic["message"],
        "The BReg fixture journeys file is missing, unreadable, or outside the BReg product project."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Create a readable tests/journeys.yaml inside the BReg product project, or remove schemaTestPeople."
    );
    assert!(!state.exists());

    let started = start(scratch.path(), &state);

    assert_eq!(started.status.code(), Some(1), "{started:?}");
    let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(error.contains("/schemaTestPeople"), "{error}");
    assert!(
        error.contains("fixture journeys file is missing"),
        "{error}"
    );
    assert!(
        error.contains("Create a readable tests/journeys.yaml"),
        "{error}"
    );
    assert!(!state.exists());
}

#[test]
fn check_and_start_refuse_a_fixture_symlink_outside_the_breg_project() {
    let scratch = tempfile::tempdir().unwrap();
    let sibling = tempfile::tempdir_in(scratch.path()).unwrap();
    let state = scratch.path().join("state");
    fixture_project(sibling.path(), "");
    project(scratch.path(), "");
    fs::create_dir(scratch.path().join("breg")).unwrap();
    fs::write(scratch.path().join("breg/registry.yaml"), "fixture\n").unwrap();
    let plan = fs::read_to_string(scratch.path().join("dev.yaml"))
        .unwrap()
        .replace("product: breg, project: .", "product: breg, project: breg");
    fs::write(scratch.path().join("dev.yaml"), plan).unwrap();
    fs::create_dir(scratch.path().join("breg/tests")).unwrap();
    std::os::unix::fs::symlink(
        sibling.path().join("tests/journeys.yaml"),
        scratch.path().join("breg/tests/journeys.yaml"),
    )
    .unwrap();

    let checked = check(scratch.path(), &state, true);

    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/0/project");
    assert_eq!(
        diagnostic["message"],
        "The BReg fixture journeys file must be a readable regular file inside the BReg product project."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Place tests/journeys.yaml inside the BReg product project without linking it outside that project."
    );
    assert!(!state.exists());

    let started = start(scratch.path(), &state);

    assert_eq!(started.status.code(), Some(1), "{started:?}");
    let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(error.contains("/products/0/project"), "{error}");
    assert!(error.contains("fixture journeys file must be"), "{error}");
    assert!(error.contains("without linking it outside"), "{error}");
    assert!(!state.exists());
}

#[test]
fn check_reports_an_invalid_fixture_as_an_actionable_plan_refusal() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(
        scratch.path(),
        "schemaTestPeople:\n  real-journey:\n    real-step: operator\n",
    );
    fs::create_dir(scratch.path().join("tests")).unwrap();
    fs::write(
        scratch.path().join("tests/journeys.yaml"),
        "not a fixture\n",
    )
    .unwrap();

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/schemaTestPeople");
    assert_eq!(
        diagnostic["message"],
        "The BReg fixture journeys file is not valid."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Run `rstack breg check` for authored diagnostics, then correct tests/journeys.yaml."
    );
    assert!(!state.exists());
}

#[test]
fn check_reports_an_oversized_fixture_as_an_actionable_plan_refusal() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(
        scratch.path(),
        "schemaTestPeople:\n  real-journey:\n    real-step: operator\n",
    );
    fs::create_dir(scratch.path().join("tests")).unwrap();
    fs::write(
        scratch.path().join("tests/journeys.yaml"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/schemaTestPeople");
    assert_eq!(
        diagnostic["message"],
        "The BReg fixture journeys file is unreadable or exceeds the 1 MiB limit."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Make tests/journeys.yaml readable and no larger than 1 MiB, then run the check again."
    );
    assert!(!state.exists());
}

#[test]
fn check_refuses_a_breg_project_directory_that_resolves_outside_the_project() {
    let scratch = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "");
    fs::create_dir(outside.path().join("tests")).unwrap();
    fs::write(
        outside.path().join("tests/journeys.yaml"),
        include_str!("../../../products/breg/examples/minimal/tests/journeys.yaml"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        scratch.path().join("registry.yaml"),
        outside.path().join("registry.yaml"),
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.path(), scratch.path().join("linked-breg")).unwrap();
    let plan = fs::read_to_string(scratch.path().join("dev.yaml"))
        .unwrap()
        .replace(
            "product: breg, project: .",
            "product: breg, project: linked-breg",
        );
    fs::write(scratch.path().join("dev.yaml"), plan).unwrap();

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/0/project");
    assert_eq!(
        diagnostic["message"],
        "The BReg fixture journeys file must be a readable regular file inside the BReg product project."
    );
    assert!(!state.exists());
}

#[test]
fn check_refuses_an_unknown_plan_field_without_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "unexpected: true\n");

    let result = check(scratch.path(), &state, true);

    assert!(!result.status.success(), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
    assert_eq!(report["diagnostics"][0]["path"], "/unexpected");
    assert!(!state.exists());
}

#[test]
fn check_renders_both_locations_of_a_duplicate_key() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(scratch.path(), "issuer: https://second.example.invalid\n");

    let result = check(scratch.path(), &state, false);

    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let human = String::from_utf8(result.stderr).unwrap();
    assert!(human.starts_with("error[yaml.duplicate-key] "), "{human}");
    assert!(human.contains("dev.yaml:17:1 /issuer"), "{human}");
    assert!(human.contains("dev.yaml:4:1 /issuer"), "{human}");
    assert!(
        human.contains("next: Keep one definition of the key."),
        "{human}"
    );
    assert!(!human.contains("second.example.invalid"));
    assert!(!state.exists());
}

#[test]
fn check_distinguishes_unavailable_input_from_an_invalid_plan() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.project-dev.check-unavailable"
    );
    assert!(!state.exists());
}

#[test]
fn check_reports_an_actionable_value_free_poll_relationship() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    semantic_project(
        scratch.path(),
        "breg",
        "      poll: {maximumWaitMilliseconds: 173, pollIntervalMilliseconds: 211}\n",
    );

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "breg.project-dev.invalid-plan");
    assert_eq!(
        diagnostic["path"],
        "/journey/steps/0/poll/pollIntervalMilliseconds"
    );
    assert_eq!(
        diagnostic["message"],
        "The poll interval must not exceed the maximum wait."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Set pollIntervalMilliseconds to no more than maximumWaitMilliseconds."
    );
    let output = String::from_utf8(result.stdout).unwrap();
    for supplied in [
        "173",
        "211",
        "private-audience-marker",
        "private-client-marker",
    ] {
        assert!(!output.contains(supplied), "leaked {supplied}: {output}");
    }
    assert!(!state.exists());
}

#[test]
fn semantic_diagnostic_escapes_authored_mapping_keys_only_in_its_pointer() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    project(
        scratch.path(),
        "schemaTestPeople:\n  \"private/journey~marker\":\n    \"private/step~marker\": private-person-marker\n",
    );

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["path"],
        "/schemaTestPeople/private~1journey~0marker/private~1step~0marker"
    );
    assert_eq!(
        diagnostic["message"],
        "The schema test assignment must name a person with a BReg grant."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Set this assignment to a test person that has a BReg grant."
    );
    for member in ["message", "suggestedAction"] {
        let text = diagnostic[member].as_str().unwrap();
        for supplied in [
            "private/journey~marker",
            "private/step~marker",
            "private-person-marker",
        ] {
            assert!(!text.contains(supplied), "leaked {supplied}: {text}");
        }
    }
    assert!(!state.exists());
}

#[test]
fn start_reports_an_actionable_value_free_unstarted_grant() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    semantic_project(scratch.path(), "casework", "");
    let request = serde_json::json!({
        "action": "start", "project": scratch.path(), "json": true,
    });

    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", &state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(
        error.contains("/people/operator/grants/casework"),
        "{error}"
    );
    assert!(
        error.contains("The grant names a product that is not started."),
        "{error}"
    );
    assert!(
        error.contains("Add the grant's product to products, or remove this grant."),
        "{error}"
    );
    for supplied in [
        "private-audience-marker",
        "private-subject-marker",
        "private-client-marker",
        "private-profile-marker",
    ] {
        assert!(!error.contains(supplied), "leaked {supplied}: {error}");
    }
    assert!(!state.exists());
}

#[test]
fn start_rejects_a_dangling_breg_grant_profile_before_allocating_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fs::write(
        scratch.path().join("registry.yaml"),
        include_str!("../../../products/breg/examples/minimal/registry.yaml"),
    )
    .unwrap();
    fs::create_dir(scratch.path().join("tests")).unwrap();
    fs::write(
        scratch.path().join("tests/journeys.yaml"),
        include_str!("../../../products/breg/examples/minimal/tests/journeys.yaml"),
    )
    .unwrap();
    fs::write(
        scratch.path().join("dev.yaml"),
        "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n\
kind: BRegProjectDev\n\
issuer: https://issuer.example.invalid\n\
products:\n  - {product: breg, project: ., audience: registry}\n\
people:\n  editor:\n    subject: editor\n    client: editor-client\n    grants:\n      breg:\n        profile: directory-editor\n        scopes: [registry:directory:write]\n        claims: {registry_purpose: directory-administration}\n  unused:\n    subject: unused\n    client: unused-client\n    grants:\n      breg: {profile: private-profile-marker, scopes: []}\n\
journey:\n  id: smoke\n  steps:\n    - {id: read, product: breg, as: editor, method: GET, path: /v1/records, expect: {status: 200}}\n",
    )
    .unwrap();

    let checked = check(scratch.path(), &state, true);

    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/people/unused/grants/breg/profile");
    assert_eq!(
        diagnostic["message"],
        "The BReg grant profile does not name an access profile in the BReg project."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Set profile to an access profile defined by the BReg project."
    );
    assert!(!checked
        .stdout
        .windows(22)
        .any(|value| value == b"private-profile-marker"));
    assert!(!state.exists());

    let result = start(scratch.path(), &state);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(
        error.contains("/people/unused/grants/breg/profile"),
        "{error}"
    );
    assert!(
        error.contains(
            "The BReg grant profile does not name an access profile in the BReg project."
        ),
        "{error}"
    );
    assert!(
        error.contains("Set profile to an access profile defined by the BReg project."),
        "{error}"
    );
    assert!(!error.contains("private-profile-marker"), "{error}");
    assert!(!state.exists());
}

#[test]
fn check_and_start_resolve_casework_profiles_and_bindings_with_the_owning_report() {
    for (profile, bindings, path, message, action, supplied) in [
        (
            "private-profile-marker",
            "",
            "/people/reviewer/grants/casework/profile",
            "The Casework grant profile does not name an access profile in the Casework project.",
            "Set profile to an access profile defined by the Casework project.",
            "private-profile-marker",
        ),
        (
            "reviewer",
            "bindings:\n  bregReviewAuthority: {id: local-review, producer: private-producer-marker, identity: reviewer}\n",
            "/bindings/bregReviewAuthority/producer",
            "The BReg review producer does not name a trusted producer in the Casework project.",
            "Set producer to a trusted producer defined by the Casework project.",
            "private-producer-marker",
        ),
        (
            "reviewer",
            "bindings:\n  caseworkContextProvider: {id: private-provider-marker, identity: operator, action: review-action}\n",
            "/bindings/caseworkContextProvider/id",
            "The Casework context provider ID does not name a context provider in the Casework project.",
            "Set id to a context provider defined by the Casework project.",
            "private-provider-marker",
        ),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let state = scratch.path().join("state");
        let tool = casework_reference_project(scratch.path(), profile, bindings);

        let checked = check_with_casework_tool(scratch.path(), &state, &tool);

        assert_eq!(checked.status.code(), Some(1), "{checked:?}");
        let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
        assert_eq!(report["status"], "domain-refusal");
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["path"], path);
        assert_eq!(diagnostic["message"], message);
        assert_eq!(diagnostic["suggestedAction"], action);
        assert!(!diagnostic.to_string().contains(supplied));
        assert!(!state.exists());

        let started = start_with_casework_tool(scratch.path(), &state, &tool);

        assert_eq!(started.status.code(), Some(1), "{started:?}");
        let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
        assert_error_envelope(&report, "domain");
        let error = report["error"]["message"].as_str().unwrap();
        assert!(error.contains(path), "{error}");
        assert!(error.contains(message), "{error}");
        assert!(error.contains(action), "{error}");
        assert!(!error.contains(supplied), "{error}");
        assert!(!state.exists());
    }
}

#[test]
fn check_refuses_binding_configuration_the_products_would_refuse_at_the_plan_field() {
    for (plan_edit, from, to, path, product) in [
        (
            "scope",
            "casework: {profile: reviewer, scopes: [casework:review]}",
            "casework: {profile: reviewer, scopes: ['casework:\"quoted\"']}",
            "/people/reviewer/grants/casework/scopes",
            "BReg refuses",
        ),
        (
            "audience",
            "audience: \"urn:example:registry\"",
            "audience: registry",
            "/products/0/audience",
            "Casework refuses",
        ),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let state = scratch.path().join("state");
        let tool = casework_reference_project(
            scratch.path(),
            "reviewer",
            concat!(
                "bindings:\n",
                "  bregReviewAuthority: {id: local-review, producer: review-producer, identity: reviewer}\n",
                "  caseworkContextProvider: {id: proposal-context, identity: operator, action: review-action}\n",
            ),
        );
        let dev = scratch.path().join("dev.yaml");
        let text = fs::read_to_string(&dev).unwrap();
        assert!(text.contains(from), "{plan_edit}: {text}");
        fs::write(&dev, text.replace(from, to)).unwrap();

        let checked = check_with_casework_tool(scratch.path(), &state, &tool);

        assert_eq!(checked.status.code(), Some(1), "{plan_edit}: {checked:?}");
        let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
        assert_eq!(report["status"], "domain-refusal", "{plan_edit}");
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["path"], path, "{plan_edit}: {diagnostic}");
        assert!(
            diagnostic["message"].as_str().unwrap().contains(product),
            "{plan_edit}: {diagnostic}"
        );
        assert!(!state.exists(), "{plan_edit}");
    }
}

#[test]
fn check_refuses_a_context_provider_binding_with_the_rule_caseworkctl_check_names() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let tool = casework_reference_project(
        scratch.path(),
        "reviewer",
        "bindings:\n  caseworkContextProvider: {id: proposal-context, identity: operator, action: review-action}\n",
    );
    let dev = scratch.path().join("dev.yaml");
    let text = fs::read_to_string(&dev).unwrap();
    fs::write(
        &dev,
        text.replace("audience: \"urn:example:registry\"", "audience: registry"),
    )
    .unwrap();

    let checked = check_with_casework_tool(scratch.path(), &state, &tool);

    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/0/audience");
    assert_eq!(
        diagnostic["message"],
        "Casework refuses the binding configuration the run writes from this value: \
contextProviders.proposal-context.resource: the resource must be one absolute URI without a \
fragment or userinfo."
    );
    assert!(!state.exists());

    // A helper that cannot check the configuration is unavailable, not a
    // refusal of the plan.
    fs::rename(&tool, scratch.path().join("caseworkctl-reference")).unwrap();
    fs::write(
        &tool,
        concat!(
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n",
            "if [[ $3 == check ]]; then\n",
            "  printf '%s\\n' '",
            "{\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"command\":\"check\",\"status\":\"domain-refusal\",\"ok\":false,",
            "\"diagnostics\":[{\"severity\":\"error\",\"code\":\"config.unknown-key\",",
            "\"artifact\":\"CaseworkRuntimeConfig\",\"path\":\"/listener\",",
            "\"message\":\"The key is not part of this format.\",",
            "\"suggestedAction\":\"Remove the key.\"}]}'\n",
            "  exit 1\n",
            "fi\n",
            "exec \"${0%/*}/caseworkctl-reference\" \"$@\"\n",
        ),
    )
    .unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();

    let unavailable = check_with_casework_tool(scratch.path(), &state, &tool);

    assert_eq!(unavailable.status.code(), Some(3), "{unavailable:?}");
    let report: serde_json::Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/1/project");
    assert_eq!(
        diagnostic["message"],
        "The selected `caseworkctl` helper could not check the Casework configuration the run writes."
    );
    assert!(!state.exists());
}

#[test]
fn check_refuses_a_status_profile_the_context_provider_policy_does_not_name() {
    let bindings = "bindings:\n  caseworkContextProvider: {id: proposal-context, identity: operator, action: review-action}\n";
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let tool = casework_reference_project(scratch.path(), "reviewer", bindings);
    fake_casework_tool_with_status_profile(scratch.path(), "another-status-profile");

    let checked = check_with_casework_tool(scratch.path(), &state, &tool);

    assert_eq!(checked.status.code(), Some(1), "{checked:?}");
    let report: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/people/operator/grants/breg/profile");
    assert!(!diagnostic.to_string().contains("another-status-profile"));
    assert!(!state.exists());

    let started = start_with_casework_tool(scratch.path(), &state, &tool);
    assert_eq!(started.status.code(), Some(1), "{started:?}");
    assert!(!state.exists());

    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let tool = casework_reference_project(scratch.path(), "reviewer", bindings);
    let checked = check_with_casework_tool(scratch.path(), &state, &tool);
    assert_eq!(checked.status.code(), Some(0), "{checked:?}");
}

#[test]
fn check_distinguishes_an_unavailable_casework_helper_from_an_invalid_project() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let tool = casework_reference_project(scratch.path(), "reviewer", "");
    let request = serde_json::json!({
        "action": "check", "project": scratch.path(), "deny_warnings": true, "json": true,
    });

    let unavailable = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", &state)
        .env_remove("RSTACK_CASEWORKCTL_BIN")
        .env_remove("RSTACK_CASEWORK_BIN")
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap();

    assert_eq!(unavailable.status.code(), Some(3), "{unavailable:?}");
    let report: serde_json::Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/1/project");
    assert_eq!(
        diagnostic["message"],
        "The Casework project cannot be inspected because its owning tool is unavailable."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Install the matching Casework tools or provide RSTACK_CASEWORKCTL_BIN, then run the check again."
    );
    assert!(!state.exists());

    fs::write(
        &tool,
        concat!(
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n",
            "printf '%s\\n' '",
            "{\"ok\":false,\"command\":\"explain\",\"status\":\"operational-failure\",",
            "\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"version\":\"0.46.1-dev\",",
            "\"diagnostics\":[{\"severity\":\"error\",\"code\":\"caseworkctl.operational-failure\",",
            "\"path\":\"runtime\",\"message\":\"A dependency was unavailable.\",",
            "\"suggestedAction\":\"Restore the dependency, then retry.\"}]}'\n",
            "exit 3\n",
        ),
    )
    .unwrap();
    let helper_failure = check_with_casework_tool(scratch.path(), &state, &tool);

    assert_eq!(helper_failure.status.code(), Some(3), "{helper_failure:?}");
    let report: serde_json::Value = serde_json::from_slice(&helper_failure.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/1/project");
    assert_eq!(
        diagnostic["message"],
        "The selected `caseworkctl` helper could not inspect the Casework project."
    );
    assert!(!state.exists());

    fs::write(
        &tool,
        concat!(
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n",
            "printf '%s\\n' '",
            "{\"ok\":false,\"command\":\"explain\",\"status\":\"domain-refusal\",",
            "\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"version\":\"0.46.1-dev\",",
            "\"diagnostics\":[{\"severity\":\"error\",\"code\":\"casework.project.invalid\",",
            "\"path\":\"/reviewPolicies\",\"message\":\"The authored project was refused.\",",
            "\"suggestedAction\":\"Correct the Casework project.\"}]}'\n",
            "exit 1\n",
        ),
    )
    .unwrap();
    let invalid = check_with_casework_tool(scratch.path(), &state, &tool);

    assert_eq!(invalid.status.code(), Some(1), "{invalid:?}");
    let report: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["path"], "/products/1/project");
    assert_eq!(
        diagnostic["message"],
        "The Casework project did not pass validation by its owning tool."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Run `rstack casework check` for authored diagnostics, then correct the Casework project."
    );
    assert!(!state.exists());
}

#[test]
fn a_malformed_plan_names_its_field_before_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fs::write(
        scratch.path().join("dev.yaml"),
        "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\nkind: BRegProjectDev\nissuer: https://example.test\nproducts: [{product: coordinator, project: registry, audience: test}]\npeople: {}\njourney: {id: licensing, steps: []}\n",
    )
    .unwrap();
    let request = serde_json::json!({
        "action": "start", "project": scratch.path(), "json": true,
    });
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", &state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    assert!(report.get("diagnostics").is_none());
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("/products/0/product"),
        "{report}"
    );
    assert!(!state.exists());
}

#[test]
fn a_run_id_cannot_name_a_path() {
    let scratch = tempfile::tempdir().unwrap();
    let request = serde_json::json!({
        "action": "stop", "run_id": "../other-run", "json": true,
    });
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", scratch.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["error"]["message"]
        .as_str()
        .unwrap()
        .contains("run ID"));
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

/// A system binary such as `true` or `false`, wherever this platform keeps it.
fn system_binary(name: &str) -> std::path::PathBuf {
    ["/usr/bin", "/bin"]
        .into_iter()
        .map(|directory| std::path::Path::new(directory).join(name))
        .find(|path| path.is_file())
        .unwrap()
}

/// A loopback port nothing listens on: it is reserved and released at once.
fn closed_loopback_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start a BReg run whose product tool and runtime are the given binaries and
/// whose PostgreSQL administrator URL is `database_url`.
fn start_with_breg_binaries(
    root: &std::path::Path,
    state: &std::path::Path,
    (tool, runtime): (&std::path::Path, &std::path::Path),
    database_url: &str,
) -> std::process::Output {
    let request = serde_json::json!({
        "action": "start", "project": root, "json": true,
    });
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev")
        .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
        .env("RSTACK_DEV_STATE_DIR", state)
        .env("RSTACK_DEV_DATABASE_URL", database_url)
        .env_remove("RSTACK_DEV_DATABASE_CA")
        .env("RSTACK_BREGCTL_BIN", tool)
        .env("RSTACK_BREG_BIN", runtime)
        .output()
        .unwrap()
}

/// The run directories `state` still holds; kept logs of failed runs are not
/// runs.
fn live_runs(state: &std::path::Path) -> Vec<String> {
    match fs::read_dir(state) {
        Ok(entries) => entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "failed")
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("cannot read the run state: {error}"),
    }
}

#[test]
fn worker_restores_a_valid_plan_whose_captured_input_exceeds_512_kib() {
    let scratch = tempfile::tempdir().unwrap();
    let project_root = scratch.path().join("project");
    fs::create_dir(&project_root).unwrap();
    fixture_project(&project_root, "");
    let raw = BASE64.encode(vec![b'x'; 400 * 1024]);
    // The captured input carries the plan's base64 body verbatim, so it is
    // larger than the body itself.
    assert!(raw.len() > 512 * 1024, "raw body: {}", raw.len());
    let plan = serde_json::json!({
        "apiVersion": "id.registrystack.org/formats/breg/project-dev/v1alpha1",
        "kind": "BRegProjectDev",
        "issuer": "https://issuer.example.invalid",
        "products": [{"product": "breg", "project": ".", "audience": "registry"}],
        "people": {"operator": {
            "subject": "operator", "client": "operator-client",
            "grants": {"breg": {"profile": "operator", "scopes": []}}
        }},
        "journey": {"id": "smoke", "steps": [{
            "id": "send-raw", "product": "breg", "as": "operator", "method": "POST",
            "path": "/v1/records",
            "raw": {"contentType": "application/octet-stream", "base64": raw},
            "expect": {"status": 200}
        }]}
    });
    let document = serde_json::to_vec(&plan).unwrap();
    assert!(
        document.len() <= registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES,
        "the regression fixture must remain a valid-size development plan"
    );
    fs::write(project_root.join("dev.yaml"), &document).unwrap();

    let checked = check(&project_root, &scratch.path().join("check-state"), true);
    assert!(
        checked.status.success(),
        "the substantial development plan was refused"
    );

    // The supervisor captures the plan for its worker; a refusing product tool
    // proves the worker restored that capture and reached the product check.
    let state = scratch.path().join("state");
    let false_binary = system_binary("false");
    let result = start_with_breg_binaries(
        &project_root,
        &state,
        (&false_binary, &false_binary),
        &format!("postgresql://127.0.0.1:{}/postgres", closed_loopback_port()),
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    assert_eq!(result.status.code(), Some(1), "{report}");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(error.contains("breg check failed"), "{error}");
    assert!(!error.contains("cannot restore the captured development plan"));
    assert_eq!(live_runs(&state), Vec::<String>::new());
}

#[test]
fn start_reports_an_unreachable_postgresql_server_as_operational() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fixture_project(scratch.path(), "");
    let canary = "rstack-dev-admin-password-canary";

    let result = start_with_breg_binaries(
        scratch.path(),
        &state,
        (&system_binary("true"), &system_binary("false")),
        &format!(
            "postgresql://admin:{canary}@127.0.0.1:{}/postgres",
            closed_loopback_port()
        ),
    );

    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "operational");
    assert_eq!(result.status.code(), Some(3), "{report}");
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot establish the PostgreSQL administrator session"),
        "{report}"
    );
    // The run released everything itself, so there is nothing to recover.
    assert!(report.get("run_id").is_none(), "{report}");
    assert!(report.get("recovery").is_none(), "{report}");
    assert_eq!(live_runs(&state), Vec::<String>::new());
    for output in [&result.stdout, &result.stderr] {
        assert!(!String::from_utf8_lossy(output).contains(canary));
    }
}
