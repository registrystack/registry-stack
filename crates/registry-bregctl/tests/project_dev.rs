// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::{
    fs,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct GuardFixture {
    guard: Child,
    workload: Option<rustix::process::Pid>,
}

impl Drop for GuardFixture {
    fn drop(&mut self) {
        if let Some(pid) = self.workload {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.guard.kill();
        let _ = self.guard.wait();
    }
}

#[test]
fn hidden_project_dev_guard_dispatch_reaps_workload_when_controller_closes() {
    let scratch = tempfile::tempdir().unwrap();
    let lock = scratch.path().join("guard.lock");
    let pid_file = scratch.path().join("guard.pid");
    let state_file = scratch.path().join("guard.state");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock)
        .unwrap();
    let sleep = system_binary("sleep");
    let guard = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("project-dev-guard")
        .arg("--lock")
        .arg(&lock)
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--state-file")
        .arg(&state_file)
        .arg("--")
        .arg(&sleep)
        .arg("60")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut fixture = GuardFixture {
        guard,
        workload: None,
    };

    let launch_deadline = Instant::now() + Duration::from_secs(5);
    let workload = loop {
        match fs::read_to_string(&pid_file) {
            Ok(raw) => {
                let raw: i32 = raw.trim().parse().unwrap();
                break rustix::process::Pid::from_raw(raw).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot read guard workload PID: {error}"),
        }
        assert!(
            fixture.guard.try_wait().unwrap().is_none(),
            "hidden guard exited before publishing its workload PID"
        );
        assert!(
            Instant::now() < launch_deadline,
            "hidden guard did not publish its workload PID"
        );
        thread::sleep(Duration::from_millis(10));
    };
    fixture.workload = Some(workload);
    assert_eq!(fs::read(&state_file).unwrap(), b"launching\n");

    drop(fixture.guard.stdin.take());
    let stop_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if fixture.guard.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < stop_deadline,
            "hidden guard did not stop after its controller closed"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(fs::read(&state_file).unwrap(), b"complete\n");
    assert_eq!(
        rustix::process::test_kill_process_group(workload),
        Err(rustix::io::Errno::SRCH)
    );
    fixture.workload = None;
}

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
scenarioFile: tests/scenarios.yaml\n\
{extra}"
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/scenarios.yaml"),
        "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n  - id: smoke\n    steps:\n      - {id: read, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    )
    .unwrap();
}

fn authored_scenarios(root: &std::path::Path, scenarios: &str) {
    project(root, "");
    fs::write(
        root.join("tests/scenarios.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n{scenarios}"
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
fn declared_application_requires_a_built_root_before_allocating_a_run() {
    let scratch = tempfile::tempdir().unwrap();
    project(scratch.path(), "");
    let plan_file = scratch.path().join("dev.yaml");
    let plan = fs::read_to_string(&plan_file)
        .unwrap()
        .replace("issuer: https://issuer.example.invalid", "issuer: run");
    fs::write(
        &plan_file,
        format!(
            "{plan}\napplication:\n  client: browser-client\n  callbackPath: /callback\n  healthPath: /health\n  entry: dist/main.js\n  prepare: dist/prepare.js\n  checker: dist/check.js\n  deployment: deployment.json\n  configSchema: example/host-run/v1\n  configEnvironment: HOST_CONFIG\n  prepareVersion: example-prepare 1.0\n"
        ),
    )
    .unwrap();
    fs::write(scratch.path().join("deployment.json"), "{}").unwrap();
    let state = scratch.path().join("state");
    let checked = helper(
        serde_json::json!({"action":"check", "project":scratch.path(), "deny_warnings":false, "json":true}),
        &state,
    );
    assert!(checked.status.success(), "{checked:?}");
    assert!(!state.exists());
    let result = helper(
        serde_json::json!({"action":"start", "project":scratch.path(), "json":true}),
        &state,
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    assert!(report["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--application-root"));
    assert!(!state.exists());
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
scenarioFile: tests/scenarios.yaml\n"
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/scenarios.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n  - id: smoke\n    steps:\n      - id: read\n        product: breg\n        as: operator\n        method: GET\n        path: /v1/records\n        expect: {{status: 200}}\n{step_extra}"
        ),
    )
    .unwrap();
}

fn fixture_project(root: &std::path::Path, extra: &str) {
    project(root, extra);
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

#[test]
fn authored_stack_scenarios_coexist_with_native_breg_fixture_journeys() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fixture_project(scratch.path(), "");
    let dev = fs::read_to_string(scratch.path().join("dev.yaml")).unwrap();
    let (prefix, _) = dev.split_once("scenarioFile:").unwrap();
    fs::write(
        scratch.path().join("dev.yaml"),
        format!("{prefix}scenarioFile: tests/scenarios.yaml\nschemaTestPeople:\n  real-journey:\n    real-step: operator\n"),
    )
    .unwrap();
    fs::write(
        scratch.path().join("tests/scenarios.yaml"),
        "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n  - id: read\n    steps:\n      - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    )
    .unwrap();

    let result = check(scratch.path(), &state, true);

    assert!(result.status.success(), "{result:?}");
    assert!(!state.exists());
    fs::rename(
        scratch.path().join("tests/journeys.yaml"),
        scratch.path().join("tests/journeys.saved"),
    )
    .unwrap();
    let result = check(scratch.path(), &state, true);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(!state.exists());
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
scenarioFile: tests/scenarios.yaml\n\
{bindings}"
        ),
    )
    .unwrap();
    fs::write(
        root.join("tests/scenarios.yaml"),
        "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n  - id: smoke\n    steps:\n      - {id: read, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
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
fn check_reads_authored_scenarios_without_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: read\n    steps:\n      - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n  - id: refusal\n    steps:\n      - id: submit\n        product: breg\n        as: operator\n        method: POST\n        path: /v1/actions/missing\n        body: {issuer: '{{run.issuer}}'}\n        expect: {status: 403}\n",
    );

    let result = check(scratch.path(), &state, true);

    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    assert!(!state.exists());
}

#[test]
fn check_accepts_scoped_null_assertions_but_refuses_null_native_input() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let scenario = |body: &str, expected: &str| {
        format!(
            "  - id: nullable\n    steps:\n      - id: compare\n        product: breg\n        as: operator\n        method: POST\n        path: /v1/actions/fixture\n{body}        expect: {expected}\n"
        )
    };
    let expected = "{status: 200, json: {/data: {optional: null, nested: [null, 'null', false]}}}";
    authored_scenarios(scratch.path(), &scenario("", expected));
    let accepted = check(scratch.path(), &state, true);
    assert!(accepted.status.success(), "{accepted:?}");
    assert!(!state.exists());

    for (body, expected) in [
        ("        body: {optional: null}\n", expected),
        ("        body: null\n", expected),
        ("", "{status: 200, json: null}"),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let state = scratch.path().join("state");
        authored_scenarios(scratch.path(), &scenario(body, expected));
        let refused = check(scratch.path(), &state, true);
        assert!(!refused.status.success(), "{refused:?}");
        let report: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["diagnostics"][0]["code"], "config.null-value");
        assert!(!state.exists());
    }
}

#[test]
fn check_refuses_duplicate_authored_scenarios() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: repeated\n    steps:\n      - {id: first, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n  - id: repeated\n    steps:\n      - {id: second, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    );

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report.to_string().contains("scenarios"), "{report}");
    assert!(!state.exists());
}

#[test]
fn check_refuses_a_scenario_file_outside_the_project() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: read\n    steps:\n      - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    );
    let dev = fs::read_to_string(scratch.path().join("dev.yaml")).unwrap();
    for outside in ["../scenarios.yaml", "/private/tmp/scenarios.yaml"] {
        fs::write(
            scratch.path().join("dev.yaml"),
            dev.replace("tests/scenarios.yaml", outside),
        )
        .unwrap();

        let result = check(scratch.path(), &state, true);

        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report.to_string().contains("scenarioFile"), "{report}");
        assert!(!state.exists());
    }
}

#[test]
fn check_refuses_a_scenario_file_symlink_escaping_the_project() {
    let scratch = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: read\n    steps:\n      - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    );
    let file = scratch.path().join("tests/scenarios.yaml");
    fs::rename(&file, outside.path().join("scenarios.yaml")).unwrap();
    symlink(outside.path().join("scenarios.yaml"), &file).unwrap();

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report.to_string().contains("scenarioFile"), "{report}");
    assert!(!state.exists());
}

#[cfg(unix)]
#[test]
fn check_refuses_a_backslash_in_an_existing_scenario_file_name() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: read\n    steps:\n      - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    );
    let source = scratch.path().join("tests/scenarios.yaml");
    let backslash = scratch.path().join("tests\\scenarios.yaml");
    fs::copy(&source, &backslash).unwrap();
    assert!(backslash.is_file());
    let dev = fs::read_to_string(scratch.path().join("dev.yaml")).unwrap();
    fs::write(
        scratch.path().join("dev.yaml"),
        dev.replace("tests/scenarios.yaml", "tests\\scenarios.yaml"),
    )
    .unwrap();

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report.to_string().contains("scenarioFile"), "{report}");
    assert!(!state.exists());
}

#[test]
fn check_refuses_an_inline_journey_or_a_missing_scenario_file() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: read\n    steps:\n      - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n",
    );
    let plan = scratch.path().join("dev.yaml");
    let authored = fs::read_to_string(&plan).unwrap();
    let inline = "journey:\n  id: inline\n  steps:\n    - {id: list, product: breg, as: operator, method: GET, path: /v1/records, expect: {status: 200}}\n";
    for changed in [
        format!("{authored}{inline}"),
        authored.replace("scenarioFile: tests/scenarios.yaml\n", ""),
    ] {
        fs::write(&plan, changed).unwrap();
        let result = check(scratch.path(), &state, true);
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report.to_string().contains("scenarioFile"), "{report}");
        assert!(!state.exists());
    }
}

#[test]
fn check_refuses_unknown_scenario_members_and_dynamic_references() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: submit\n    steps:\n      - {id: create, product: breg, as: operator, method: POST, path: /v1/actions/missing, body: {issuer: '{{run.issuer}}'}, expect: {status: 400}}\n",
    );
    let file = scratch.path().join("tests/scenarios.yaml");
    let authored = fs::read_to_string(&file).unwrap();
    for (changed, expected) in [
        (
            authored.replace("scenarios:\n", "unexpected: true\nscenarios:\n"),
            "unexpected",
        ),
        (
            authored.replace("run.issuer", "run.unsupported"),
            "earlier capture",
        ),
    ] {
        fs::write(&file, changed).unwrap();
        let result = check(scratch.path(), &state, true);
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report.to_string().contains(expected), "{report}");
        assert!(!state.exists());
    }
}

#[test]
fn check_reports_a_capture_union_error_in_the_authored_file() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    authored_scenarios(
        scratch.path(),
        "  - id: read\n    steps:\n      - id: list\n        product: breg\n        as: operator\n        method: GET\n        path: /v1/records\n        expect: {status: 200}\n        capture: {result: {type: pointer, pointer: /items, surprise: true}}\n",
    );

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["path"], "/scenarios/0/steps/0/capture/result/surprise",
        "{report}"
    );
    assert_eq!(diagnostic["source"]["line"], 12, "{report}");
    assert!(diagnostic["source"]["column"].as_u64().unwrap() > 0);
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
                "scenarioFile:",
                "  second:\n    subject: second\n    client: second-client\n    grants:\n      breg: {profile: operator, scopes: []}\nscenarioFile:",
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
    fs::create_dir_all(scratch.path().join("tests")).unwrap();
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
    fs::create_dir_all(scratch.path().join("tests")).unwrap();
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
    assert!(human.contains("dev.yaml:14:1 /issuer"), "{human}");
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
        "        poll: {maximumWaitMilliseconds: 173, pollIntervalMilliseconds: 211}\n",
    );

    let result = check(scratch.path(), &state, true);

    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "breg.project-dev.invalid-scenarios");
    assert_eq!(
        diagnostic["path"],
        "/scenarios/0/steps/0/poll/pollIntervalMilliseconds"
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
scenarioFile: tests/scenarios.yaml\n",
    )
    .unwrap();
    fs::write(
        scratch.path().join("tests/scenarios.yaml"),
        "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\nkind: RStackScenarios\nscenarios:\n  - id: smoke\n    steps:\n      - {id: read, product: breg, as: editor, method: GET, path: /v1/records, expect: {status: 200}}\n",
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
fn browser_run_issuer_checks_both_bindings_before_start_requires_application_root() {
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
    let plan = fs::read_to_string(&dev)
        .unwrap()
        .replace("issuer: https://issuer.example.invalid", "issuer: run");
    fs::write(&dev, format!(
        "{plan}\napplication:\n  client: browser-client\n  callbackPath: /callback\n  healthPath: /health\n  entry: dist/main.js\n  prepare: dist/prepare.js\n  checker: dist/check.js\n  deployment: deployment.json\n  configSchema: example/host-run/v1\n  configEnvironment: HOST_CONFIG\n  prepareVersion: example-prepare 1.0\n"
    )).unwrap();
    fs::write(scratch.path().join("deployment.json"), "{}").unwrap();
    // This double checks the exact runtime input delivered to the owning
    // Casework CLI; the BReg binding is checked by its real product reader.
    let script = fs::read_to_string(&tool).unwrap().replace(
        "  [[ $# -eq 6 && $5 == --runtime-config && -f $6 ]]",
        concat!(
            "  [[ $# -eq 6 && $5 == --runtime-config && -f $6 ]]\n",
            "  grep -q '\"issuer\":\"http://127.0.0.1:1\"' \"$6\"\n",
            "  grep -q '\"clientAssertionAudience\":\"http://127.0.0.1:1\"' \"$6\"",
        ),
    );
    fs::write(&tool, script).unwrap();
    let checked = check_with_casework_tool(scratch.path(), &state, &tool);
    assert!(checked.status.success(), "{checked:?}");
    assert!(!state.exists());
    let started = start_with_casework_tool(scratch.path(), &state, &tool);
    let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    assert_error_envelope(&report, "domain");
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--application-root"),
        "{report}"
    );
    assert!(!state.exists());
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
        "The selected `caseworkctl` helper could not check the Casework configuration the run writes: caseworkctl check did not report a result for the binding."
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
        "The selected `caseworkctl` helper could not inspect the Casework project: caseworkctl explain did not complete successfully."
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
        "The Casework project did not pass validation by its owning tool: /reviewPolicies: The authored project was refused."
    );
    assert_eq!(
        diagnostic["suggestedAction"],
        "Correct the Casework project where the diagnostics point."
    );
    assert!(!state.exists());
}

#[test]
fn a_malformed_plan_names_its_field_before_allocating_run_state() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    fs::write(
        scratch.path().join("dev.yaml"),
        "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\nkind: BRegProjectDev\nissuer: https://example.test\nproducts: [{product: coordinator, project: registry, audience: test}]\npeople: {}\nscenarioFile: tests/scenarios.yaml\n",
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

/// A `bregctl` stand-in that answers `explain access` and `explain model` for
/// the fixture project and does nothing else.
fn explain_only_tool(directory: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join("bregctl-explain-only");
    fs::write(
        &path,
        concat!(
            "#!/usr/bin/env bash\nset -euo pipefail\n",
            "case \"$*\" in\n",
            "  *explain\\ access*) printf '%s' '{\"ok\":true,\"explanation\":{\"claimContract\":{\"principalClaims\":[],\"purposeRequired\":false,\"requesterClients\":[\"operator-client\"]},\"consent\":null}}' ;;\n",
            "  *explain\\ model*) printf '%s' '{\"ok\":true,\"explanation\":{\"recordTypes\":[],\"requiresPostgis\":false,\"accessProfiles\":[{\"id\":\"operator\"}],\"actions\":[],\"reviewAuthorities\":[]}}' ;;\n",
            "esac\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
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
        "scenarioFile": "tests/scenarios.yaml"
    });
    let scenarios = serde_json::json!({
        "apiVersion": "id.registrystack.org/formats/rstack/scenarios/v1alpha1",
        "kind": "RStackScenarios",
        "scenarios": [{"id": "smoke", "steps": [{
            "id": "send-raw", "product": "breg", "as": "operator", "method": "POST",
            "path": "/v1/records",
            "raw": {"contentType": "application/octet-stream", "base64": raw},
            "expect": {"status": 200}
        }]}]
    });
    let document = serde_json::to_vec(&scenarios).unwrap();
    assert!(
        document.len() <= registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES,
        "the regression fixture must remain a valid-size scenarios file"
    );
    fs::write(project_root.join("tests/scenarios.yaml"), &document).unwrap();
    fs::write(
        project_root.join("dev.yaml"),
        serde_json::to_vec(&plan).unwrap(),
    )
    .unwrap();

    let checked = check(&project_root, &scratch.path().join("check-state"), true);
    assert!(
        checked.status.success(),
        "the substantial development plan was refused"
    );

    // The supervisor captures the plan for its worker; a refusing product tool
    // proves the worker restored that capture and reached the product
    // inspection.
    let state = scratch.path().join("state");
    let false_binary = system_binary("false");
    let result = start_with_breg_binaries(
        &project_root,
        &state,
        (&false_binary, &false_binary),
        &format!("postgresql://127.0.0.1:{}/postgres", closed_loopback_port()),
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_error_envelope(&report, "operational");
    assert_eq!(result.status.code(), Some(3), "{report}");
    let error = report["error"]["message"].as_str().unwrap();
    assert!(
        error.contains("`bregctl` helper could not inspect the BReg project"),
        "{error}"
    );
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
        (&explain_only_tool(scratch.path()), &system_binary("false")),
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

#[test]
#[ignore = "requires an independently built matching Casework CLI, no database"]
fn normal_check_uses_owning_casework_tool_for_exact_run_producer_chain() {
    let tool = std::path::PathBuf::from(
        std::env::var_os("RSTACK_TEST_CASEWORKCTL_BIN").expect("set matching Casework CLI"),
    );
    let scratch = tempfile::tempdir().unwrap();
    fn copy(source: &std::path::Path, dest: &std::path::Path) {
        fs::create_dir(dest).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = dest.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/reviewed-evidence-journey");
    let project = scratch.path().join("project");
    copy(&source, &project);
    let plan_path = project.join("dev.yaml");
    let mut plan = registry_platform_yaml::Reader::new("dev.yaml")
        .scan(&fs::read(&plan_path).unwrap())
        .unwrap()
        .unwrap()
        .to_json_value();
    plan["issuer"] = serde_json::json!("run");
    plan["application"] = serde_json::json!({"client":"browser-client","callbackPath":"/callback","healthPath":"/health","entry":"dist/main.js","prepare":"dist/prepare.js","checker":"dist/check.js","deployment":"deployment.json","configSchema":"example/host-run/v1","configEnvironment":"HOST_CONFIG","prepareVersion":"example-prepare 1.0"});
    plan["bindings"]["bregReviewAuthority"]["runIssuerBinding"] = serde_json::json!({"producer":{"expectedIssuer":"https://issuer.example.test","expectedProfile":"requester","expectedSubject":"producer"},"initiator":{"expectedIssuer":"https://issuer.example.test","trust":"run-test-people"}});
    fs::write(&plan_path, serde_norway::to_string(&plan).unwrap()).unwrap();
    fs::write(project.join("deployment.json"), "{}").unwrap();
    let original = fs::read(project.join("casework/casework.yaml")).unwrap();
    let state = scratch.path().join("state");
    let checked = check_with_casework_tool(&project, &state, &tool);
    assert!(checked.status.success(), "{checked:?}");
    assert!(!state.exists());
    // The downloaded product API path needs no application, host build or
    // browser client. It still reaches the same real source/actor validation.
    plan.as_object_mut().unwrap().remove("application");
    fs::write(&plan_path, serde_norway::to_string(&plan).unwrap()).unwrap();
    let product_only = check_with_casework_tool(&project, &state, &tool);
    assert!(product_only.status.success(), "{product_only:?}");
    let started = start_with_casework_tool(&project, &state, &tool);
    let start_report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    assert_eq!(started.status.code(), Some(1));
    assert!(
        start_report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("RSTACK_DEV_DATABASE_URL"),
        "{start_report}"
    );
    assert!(!start_report.to_string().contains("--application-root"));
    assert!(!state.exists());
    let extra_root = helper(
        serde_json::json!({"action":"start","project":project,"application_root":scratch.path(),"json":true}),
        &state,
    );
    let root_report: serde_json::Value = serde_json::from_slice(&extra_root.stdout).unwrap();
    assert_eq!(extra_root.status.code(), Some(1));
    assert!(root_report["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--application-root"));
    assert!(!state.exists());
    plan["people"]["producer"]["subject"] = serde_json::json!("mismatched-test-subject");
    fs::write(&plan_path, serde_norway::to_string(&plan).unwrap()).unwrap();
    let refused = check_with_casework_tool(&project, &state, &tool);
    assert_eq!(refused.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/bindings/bregReviewAuthority/runIssuerBinding"
    );
    assert!(!report.to_string().contains("mismatched-test-subject"));
    assert!(!state.exists());
    assert_eq!(
        original,
        fs::read(project.join("casework/casework.yaml")).unwrap()
    );
}

/// Match the existing BReg dev-client normalizer, not a new issuer default.
fn public_parity_client_claims(
    client: &serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut claims = client["claims"].as_object().unwrap().clone();
    claims
        .entry("registry_actor_kind".to_owned())
        .or_insert_with(|| serde_json::json!("service"));
    assert!(
        client["allowHumanFixture"].as_bool().unwrap_or(false)
            == (claims["registry_actor_kind"] == "human"),
        "human fixtures require the existing authored opt-in"
    );
    claims
}

#[test]
fn public_parity_clients_preserve_existing_machine_contract() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/minimal/dev-clients.yaml");
    let clients = registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(&fs::read(&path).unwrap())
        .unwrap()
        .unwrap()
        .to_json_value();
    for client in clients["clients"].as_array().unwrap() {
        let raw = client["claims"].as_object().unwrap();
        assert!(!raw.contains_key("registry_actor_kind"));
        let normalized = public_parity_client_claims(client);
        assert!(normalized.len() == raw.len() + 1);
        assert!(raw
            .iter()
            .all(|(key, value)| normalized.get(key) == Some(value)));
        assert!(normalized["registry_actor_kind"] == "service");
        for kind in ["agent", "service", "human"] {
            let mut explicit = client.clone();
            explicit["claims"]["registry_actor_kind"] = serde_json::json!(kind);
            explicit["allowHumanFixture"] = serde_json::json!(kind == "human");
            assert!(public_parity_client_claims(&explicit)["registry_actor_kind"] == kind);
        }
    }
}

/// A closed receipt, not a redacted copy of arbitrary native error text.
fn public_parity_start_result(
    started: &serde_json::Value,
    exit: Option<i32>,
    source_unchanged: bool,
) -> serde_json::Value {
    let (schema, status) = match (
        started["schema_version"].as_str(),
        started["status"].as_str(),
    ) {
        (Some("registry.rstack.dev.v1"), Some("ready")) => {
            (Some("registry.rstack.dev.v1"), Some("ready"))
        }
        (Some("registry.rstack.error.v1"), Some("refused")) => {
            (Some("registry.rstack.error.v1"), Some("refused"))
        }
        _ => (None, None),
    };
    let class = if status == Some("refused") {
        match started["error"]["class"].as_str() {
            Some("domain") => Some("domain"),
            Some("usage") => Some("usage"),
            Some("operational") => Some("operational"),
            _ => None,
        }
    } else {
        None
    };
    let exit = exit.filter(|code| (0..=3).contains(code));
    let valid = matches!(
        (status, class, exit),
        (Some("ready"), None, Some(0 | 1))
            | (Some("refused"), Some("domain"), Some(1))
            | (Some("refused"), Some("usage"), Some(2))
            | (Some("refused"), Some("operational"), Some(3))
    );
    // Preserve only membership of this one existing contract diagnostic.
    // Neither its surrounding text nor any prefix-derived code is copied.
    let reserved = status == Some("refused")
        && started["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("breg.registry.canonical-base-iri-reserved"));
    serde_json::json!({"phase":"native-start","startExit":exit,"schema":schema,"status":status,
        "class":class,"protocolEnvelopeValid":valid,"reservedIdentityDiagnostic":reserved,
        "sourceBytesUnchanged":source_unchanged})
}

#[test]
fn public_parity_retention_excludes_short_claim_message_and_forged_codes() {
    for canary in [
        "unallowlisted-claim-canary auth.unallowlisted-canary",
        "tiny-token-abc",
        "config.short-canary source.short-canary test.forged-canary",
    ] {
        let report = serde_json::json!({"schema_version":"registry.rstack.error.v1","status":"refused",
            "error":{"class":"domain","message":canary,"code":canary},
            "claims":{"short":canary},"boundedRedactedSummary":canary,"diagnosticCodes":[canary]});
        let result = public_parity_start_result(&report, Some(1), true);
        let encoded = result.to_string();
        for word in canary.split_whitespace() {
            assert!(!encoded.contains(word));
        }
        assert!(result.get("boundedRedactedSummary").is_none());
        assert!(result.get("diagnosticCodes").is_none());
        assert!(result.as_object().unwrap().len() == 8);
        assert!(result["protocolEnvelopeValid"] == true);
        assert!(result["reservedIdentityDiagnostic"] == false);
    }
    let report = serde_json::json!({"schema_version":"registry.rstack.error.v1","status":"refused",
        "error":{"class":"domain","message":"breg.registry.canonical-base-iri-reserved short-claim-canary auth.forged-canary"}});
    let result = public_parity_start_result(&report, Some(1), false);
    assert!(result["reservedIdentityDiagnostic"] == true);
    assert!(result["sourceBytesUnchanged"] == false);
    assert!(!result.to_string().contains("canary"));
}

#[test]
fn public_parity_retention_accepts_only_fixed_protocol_enums() {
    for (class, exit) in [("domain", 1), ("usage", 2), ("operational", 3)] {
        let report = serde_json::json!({"schema_version":"registry.rstack.error.v1","status":"refused","error":{"class":class}});
        let result = public_parity_start_result(&report, Some(exit), true);
        assert!(result["protocolEnvelopeValid"] == true);
        assert!(result["class"] == class);
        for field in ["schema_version", "status", "class"] {
            let mut forged = report.clone();
            if field == "class" {
                forged["error"][field] = serde_json::json!("short-enum-canary");
            } else {
                forged[field] = serde_json::json!("short-enum-canary");
            }
            let result = public_parity_start_result(&forged, Some(exit), true);
            assert!(!result.to_string().contains("canary"));
            assert!(result["class"].is_null());
            assert!(result["protocolEnvelopeValid"] == false);
        }
    }
    let ready = serde_json::json!({"schema_version":"registry.rstack.dev.v1","status":"ready","error":{"class":"short-enum-canary"}});
    for exit in [0, 1] {
        let result = public_parity_start_result(&ready, Some(exit), true);
        assert!(result["protocolEnvelopeValid"] == true && result["class"].is_null());
        assert!(!result.to_string().contains("canary"));
    }
    for exit in [None, Some(-1), Some(4), Some(101), Some(i32::MAX)] {
        let result = public_parity_start_result(&ready, exit, true);
        assert!(result["startExit"].is_null() && result["protocolEnvelopeValid"] == false);
    }
}

/// Public native lifecycle regression. The caller supplies a fresh owner-only
/// directory and a disposable TLS PostgreSQL, never a retained developer DB.
#[test]
#[ignore = "requires RSTACK_PARITY_ROOT, RSTACK_PARITY_DATABASE_URL_FILE, RSTACK_PARITY_DATABASE_CA, RSTACK_PARITY_RSTACK_BIN and RSTACK_PARITY_BREG_BIN"]
fn a_local_placeholder_project_runs_without_becoming_a_deployment_package() {
    use registry_breg::package::{
        load_package, load_predecessor_package, PackageError, PackageLoadContext,
    };
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    fn required(name: &str) -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("set {name}"))
    }
    fn copy(source: &Path, target: &Path) {
        fs::create_dir(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination = target.join(entry.file_name());
            assert!(!entry.file_type().unwrap().is_symlink());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).unwrap();
            }
        }
    }
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(root, &entry.path(), files);
                } else {
                    files.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }
    struct OwnedRun {
        rstack: PathBuf,
        install: PathBuf,
        state: PathBuf,
        run: Option<String>,
    }
    impl OwnedRun {
        fn command(&self, operation: &str, subject: &Path) -> Command {
            let mut command = Command::new(&self.rstack);
            command
                .args(["--install-root"])
                .arg(&self.install)
                .args(["dev", operation])
                .arg(subject)
                .arg("--json")
                .env("RSTACK_DEV_STATE_DIR", &self.state)
                .env("RSTACK_BREGCTL_BIN", env!("CARGO_BIN_EXE_bregctl"))
                .env("RSTACK_BREG_BIN", required("RSTACK_PARITY_BREG_BIN"));
            command
        }
        fn stop(&mut self) {
            if let Some(id) = self.run.clone() {
                let stopped = self.command("stop", Path::new(&id)).output().unwrap();
                assert!(stopped.status.success(), "owned normal stop failed");
                let report: serde_json::Value = serde_json::from_slice(&stopped.stdout).unwrap();
                assert!(
                    report["status"] == "stopped",
                    "owned status must be stopped"
                );
                self.run = None;
                let later = self.command("status", Path::new(&id)).output().unwrap();
                assert!(later.status.success());
                let report: serde_json::Value = serde_json::from_slice(&later.stdout).unwrap();
                assert!(
                    report["status"] == "stopped",
                    "owned status must be stopped"
                );
            }
        }
    }
    impl Drop for OwnedRun {
        fn drop(&mut self) {
            if self.run.is_some() {
                self.stop();
            }
        }
    }

    let parent = required("RSTACK_PARITY_ROOT").canonicalize().unwrap();
    let scratch = tempfile::Builder::new()
        .prefix("public-local-package-")
        .tempdir_in(&parent)
        .unwrap();
    let root = scratch.path();
    let project = root.join("project");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/minimal"),
        &project,
    );
    let source = fs::read_to_string(project.join("registry.yaml")).unwrap();
    assert_eq!(source.matches("https://directory.example.gov").count(), 1);
    fs::write(
        project.join("registry.yaml"),
        source.replace(
            "https://directory.example.gov",
            "https://directory.example.invalid",
        ),
    )
    .unwrap();

    // Derive identities and exact fixture-step assignments from the public
    // project's existing authored clients and journeys, without widening them.
    let yaml = |name: &str| -> serde_json::Value {
        let path = project.join(name);
        registry_platform_yaml::Reader::new(path.display().to_string())
            .scan(&fs::read(&path).unwrap())
            .unwrap()
            .unwrap()
            .to_json_value()
    };
    let clients = yaml("dev-clients.yaml");
    let journeys = yaml("tests/journeys.yaml");
    let mut people = serde_json::Map::new();
    for client in clients["clients"].as_array().unwrap() {
        let alias = client["id"].as_str().unwrap();
        assert_eq!(client["accessProfiles"].as_array().unwrap().len(), 1);
        let mut claims = public_parity_client_claims(client);
        let subject = claims.remove("registry_principal").unwrap();
        people.insert(alias.to_owned(), serde_json::json!({"subject":subject,"client":alias,
            "grants":{"breg":{"profile":client["accessProfiles"][0],"scopes":client["scopes"],"claims":claims}}}));
    }
    let mut assignments = serde_json::Map::new();
    for journey in journeys["journeys"].as_array().unwrap() {
        let mut steps = serde_json::Map::new();
        for step in journey["steps"].as_array().unwrap() {
            let selected: Vec<_> = clients["clients"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|client| {
                    client["claims"]["registry_principal"] == step["claims"]["principal"]
                        && client["accessProfiles"][0] == step["accessProfile"]
                        && client["scopes"] == step["claims"]["scopes"]
                        && client["claims"]["registry_purpose"] == step["claims"]["purpose"]
                })
                .collect();
            assert_eq!(
                selected.len(),
                1,
                "one existing authored client must bind each fixture step"
            );
            steps.insert(
                step["id"].as_str().unwrap().to_owned(),
                selected[0]["id"].clone(),
            );
        }
        assignments.insert(journey["id"].as_str().unwrap().to_owned(), steps.into());
    }
    fs::write(project.join("dev.yaml"), serde_json::to_vec_pretty(&serde_json::json!({
        "apiVersion":"id.registrystack.org/formats/breg/project-dev/v1alpha1","kind":"BRegProjectDev",
        "issuer":"https://issuer.example.invalid",
        "products":[{"product":"breg","project":".","audience":"registry"}],
        "people":people,"schemaTestPeople":assignments,
        "scenarioFile":"tests/scenarios.yaml"
    })).unwrap()).unwrap();
    fs::write(project.join("tests/scenarios.yaml"), serde_json::to_vec_pretty(&serde_json::json!({
        "apiVersion":"id.registrystack.org/formats/rstack/scenarios/v1alpha1","kind":"RStackScenarios",
        "scenarios":[{"id":"public-directory","steps":[{"id":"read-registry","product":"breg","as":"editor","method":"GET","path":"/v1/registry","expect":{"status":200}}]}]
    })).unwrap()).unwrap();
    let original = snapshot(&project);
    let mut owned = OwnedRun {
        rstack: required("RSTACK_PARITY_RSTACK_BIN"),
        install: root.join("install"),
        state: root.join("state"),
        run: None,
    };
    let checked = owned.command("check", &project).output().unwrap();
    assert!(
        checked.status.success(),
        "public authored project-dev check failed"
    );
    let database = fs::read_to_string(required("RSTACK_PARITY_DATABASE_URL_FILE")).unwrap();
    let output = owned
        .command("start", &project)
        .args(["--ttl", "5m"])
        .env("RSTACK_DEV_DATABASE_URL", database.trim())
        .env(
            "RSTACK_DEV_DATABASE_CA",
            required("RSTACK_PARITY_DATABASE_CA"),
        )
        .output()
        .unwrap();
    let started: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    if let Some(id) = started["run_id"].as_str() {
        owned.run = Some(id.to_owned());
    }
    fn retain_failure(root: &Path, parent: &Path) {
        if !root.is_dir() {
            return;
        }
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                retain_failure(&entry.path(), parent);
            } else if entry.file_name() == "breg-test-report.json" {
                let bytes = fs::read(entry.path()).unwrap();
                let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                use std::io::Write as _;
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(parent.join("first-failure.json"))
                    .unwrap()
                    .write_all(&bytes)
                    .unwrap();
            }
        }
    }
    retain_failure(&owned.state, &parent);
    let safe = public_parity_start_result(
        &started,
        output.status.code(),
        snapshot(&project) == original,
    );
    fs::write(
        parent.join("result.json"),
        serde_json::to_vec_pretty(&safe).unwrap(),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "public placeholder start refused; see bounded result.json"
    );
    assert!(started["status"] == "ready", "native start must be ready");
    assert!(
        started["scenarios"][0]["result"] == "passed",
        "native journey must pass"
    );
    let id = owned.run.as_deref().unwrap();
    let run_root = owned.state.join(id);
    let receipt = run_root.join("schema-test-receipt.json");
    let receipt_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert!(
        receipt_value["successfulJourneyIds"] == serde_json::json!(["directory-contact"]),
        "receipt must bind the authored journey"
    );
    fs::copy(&receipt, parent.join("schema-test-receipt.json")).unwrap();
    let package = run_root.join("breg-build/package");
    load_package(
        &package,
        &PackageLoadContext {
            database_initialization_environment: "local",
        },
    )
    .unwrap();
    assert!(matches!(
        load_package(
            &package,
            &PackageLoadContext {
                database_initialization_environment: "production"
            }
        ),
        Err(PackageError::DeploymentIdentity)
    ));
    load_predecessor_package(
        &package,
        &PackageLoadContext {
            database_initialization_environment: "production",
        },
    )
    .unwrap();
    let deployment = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("package")
        .arg(&project)
        .arg("--test-receipt")
        .arg(&receipt)
        .arg("--output")
        .arg(root.join("deployment-build"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(!deployment.status.success());
    let refused: serde_json::Value = serde_json::from_slice(&deployment.stdout).unwrap();
    assert!(refused["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == "breg.registry.canonical-base-iri-reserved"));
    assert!(!root.join("deployment-build").exists());
    let status = owned.command("status", Path::new(id)).output().unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(status["status"] == "ready", "native status must be ready");
    assert!(
        status["scenarios"] == started["scenarios"],
        "native status must match the start journey"
    );
    owned.stop();
    assert!(live_runs(&owned.state).is_empty());
    assert!(
        snapshot(&project) == original,
        "authored source must remain byte-identical"
    );
    fs::write(parent.join("result.json"), serde_json::to_vec_pretty(&serde_json::json!({"checkPassed":true,"startReady":true,"authoredNativeJourneyReceiptPassed":true,"journeyPassed":true,"localPackageAdmitted":true,"productionPackageRefused":true,"productionTargetLoadRefused":true,"predecessorRecoveryReadable":true,"statusReady":true,"stopStopped":true,"postStopStatusStopped":true,"stateEmpty":true,"sourceBytesUnchanged":true})).unwrap()).unwrap();
}

#[test]
fn local_package_public_command_keeps_reserved_identity_refusal() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let initialized = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("init")
        .arg(&project)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "normal public initialization must succeed"
    );
    let path = project.join("registry.yaml");
    let original = fs::read_to_string(&path).unwrap();
    assert!(original.matches("https://directory.example.gov").count() == 1);
    let source = original.replace(
        "https://directory.example.gov",
        "https://directory.example.invalid",
    );
    fs::write(&path, &source).unwrap();
    let output = root.path().join("deployment-build");
    let refused = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("package")
        .arg(&project)
        .arg("--schema-fingerprint")
        .arg(format!("sha256:{}", "0".repeat(64)))
        .arg("--test-receipt")
        .arg(root.path().join("missing-receipt.json"))
        .arg("--output")
        .arg(&output)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "ordinary package must refuse reserved identity"
    );
    let report: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "breg.registry.canonical-base-iri-reserved"));
    assert!(!output.exists());
    assert!(fs::read_to_string(&path).unwrap() == source);
}

#[test]
fn native_schema_test_runtime_path_refusal_has_closed_report_envelope() {
    let scratch = tempfile::tempdir().unwrap();
    fixture_project(scratch.path(), "");
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .arg("test")
        .arg(scratch.path())
        .args([
            "--runtime-config",
            "relative-private-canary",
            "--credentials",
            "relative-private-canary",
            "--output",
        ])
        .arg(scratch.path().join("receipt.json"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "test");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "test.runtime-config.path-invalid"
    );
    assert_eq!(report["diagnostics"][0]["path"], "runtimeConfig");
    assert!(!scratch.path().join("receipt.json").exists());
}

/// The reviewed-evidence acceptance project, copied beside `root` so a test
/// can edit it, and the built product binaries a full start needs. A full
/// start needs a TLS PostgreSQL server: `RSTACK_DEV_DATABASE_URL` and
/// `RSTACK_DEV_DATABASE_CA`.
struct AcceptanceRun {
    project: std::path::PathBuf,
    state: std::path::PathBuf,
    bin: std::path::PathBuf,
}

impl AcceptanceRun {
    const ISSUER_BINDING: &'static str = "bindings:\n  bregReviewAuthority: {id: casework, producer: registry, identity: producer, runIssuerBinding: {producer: {expectedIssuer: \"https://issuer.example.test\", expectedProfile: requester, expectedSubject: SUBJECT}, initiator: {expectedIssuer: \"https://issuer.example.test\", trust: run-test-people}}}\n";

    fn new(root: &std::path::Path, expected_subject: &str) -> Self {
        fn copy(source: &std::path::Path, target: &std::path::Path) {
            fs::create_dir_all(target).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let destination = target.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy(&entry.path(), &destination);
                } else {
                    fs::copy(entry.path(), destination).unwrap();
                }
            }
        }
        let project = root.join("project");
        copy(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/breg/acceptance/reviewed-evidence-journey"),
            &project,
        );
        let dev = fs::read_to_string(project.join("dev.yaml")).unwrap();
        let (_, rest) = dev
            .split_once(
                "  bregReviewAuthority: {id: casework, producer: registry, identity: producer}\n",
            )
            .expect("the acceptance dev.yaml binds the review authority");
        let head = dev
            .split("bindings:\n")
            .next()
            .unwrap()
            .replace("issuer: https://issuer.example.test", "issuer: run");
        let binding = Self::ISSUER_BINDING.replace("SUBJECT", expected_subject);
        fs::write(project.join("dev.yaml"), format!("{head}{binding}{rest}")).unwrap();
        let bin = std::path::Path::new(env!("CARGO_BIN_EXE_bregctl"))
            .parent()
            .unwrap()
            .to_owned();
        Self {
            project,
            state: root.join("state"),
            bin,
        }
    }

    /// A tool that records its arguments, then runs `real` unless `intercept`
    /// (a bash `case` pattern over all arguments) matches.
    fn wrapper(&self, name: &str, real: &str, intercept: &str, reply: &str) -> std::path::PathBuf {
        let path = self.state.with_file_name(format!("{name}-wrapper"));
        let log = self.state.with_file_name(format!("{name}-calls.log"));
        // The system shell strips DYLD_* variables, so the script restores the
        // library path Cargo gave this test.
        let library_path = std::env::var("DYLD_FALLBACK_LIBRARY_PATH").unwrap_or_default();
        fs::write(
            &path,
            format!(
                "#!/usr/bin/env bash\nset -uo pipefail\nexport DYLD_FALLBACK_LIBRARY_PATH='{library_path}'\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  {intercept}) {reply} ;;\n  *) exec '{}' \"$@\" ;;\nesac\n",
                log.display(),
                self.bin.join(real).display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn calls(&self, name: &str) -> String {
        fs::read_to_string(self.state.with_file_name(format!("{name}-calls.log")))
            .unwrap_or_default()
    }

    fn start(
        &self,
        bregctl: &std::path::Path,
        caseworkctl: &std::path::Path,
    ) -> std::process::Output {
        let request = serde_json::json!({
            "action": "start", "project": self.project, "json": true,
        });
        let variable = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| panic!("set {name} to a TLS PostgreSQL server"))
        };
        Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .arg("project-dev")
            .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
            .env("RSTACK_DEV_STATE_DIR", &self.state)
            // The runner requires a password in the URL; a trust-authenticated
            // test server ignores it.
            .env(
                "RSTACK_DEV_DATABASE_URL",
                variable("RSTACK_DEV_DATABASE_URL").replacen("postgres@", "postgres:unused@", 1),
            )
            .env("RSTACK_DEV_DATABASE_CA", variable("RSTACK_DEV_DATABASE_CA"))
            .env("RSTACK_BREGCTL_BIN", bregctl)
            .env("RSTACK_BREG_BIN", self.bin.join("breg"))
            .env("RSTACK_CASEWORKCTL_BIN", caseworkctl)
            .env("RSTACK_CASEWORK_BIN", self.bin.join("casework"))
            .output()
            .unwrap()
    }

    /// Stop a run a test left running.
    fn stop(&self, started: &serde_json::Value) {
        if let Some(run) = started["run_id"].as_str() {
            let request = serde_json::json!({"action": "stop", "run_id": run, "json": true});
            let _ = Command::new(env!("CARGO_BIN_EXE_bregctl"))
                .arg("project-dev")
                .env("RSTACK_PROJECT_DEV_REQUEST", request.to_string())
                .env("RSTACK_DEV_STATE_DIR", &self.state)
                .output();
        }
    }
}

#[test]
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built breg, casework and caseworkctl binaries"]
fn casework_run_issuer_binding_needs_no_run_source_command() {
    let scratch = tempfile::tempdir().unwrap();
    let run = AcceptanceRun::new(scratch.path(), "producer");
    let caseworkctl = run.wrapper(
        "caseworkctl",
        "caseworkctl",
        "*\"generate run-source\"*",
        "exit 97",
    );
    let output = run.start(&run.bin.join("bregctl"), &caseworkctl);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    run.stop(&report);
    let calls = run.calls("caseworkctl");
    assert!(
        !calls.contains("run-source"),
        "the runner must not call generate run-source: {calls}\n{report}"
    );
    assert!(
        calls
            .lines()
            .any(|line| line.starts_with("check ") && line.contains("casework-bound")),
        "the runner checks the bound copy with the public check: {calls}\n{report}"
    );
}

#[test]
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built breg, casework and caseworkctl binaries"]
fn casework_run_issuer_mismatch_names_the_dev_yaml_pointer() {
    let scratch = tempfile::tempdir().unwrap();
    let run = AcceptanceRun::new(scratch.path(), "not-the-producer");
    let output = run.start(&run.bin.join("bregctl"), &run.bin.join("caseworkctl"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    run.stop(&report);
    assert!(!output.status.success(), "{report}");
    assert!(
        report
            .to_string()
            .contains("/bindings/bregReviewAuthority/runIssuerBinding/producer/expectedSubject"),
        "{report}"
    );
}

#[test]
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built breg, casework and caseworkctl binaries"]
fn breg_schema_test_failure_passes_the_tool_report_through() {
    let scratch = tempfile::tempdir().unwrap();
    let run = AcceptanceRun::new(scratch.path(), "producer");
    let tool_report = r#"{"ok":false,"command":"test","status":"domain-refusal","diagnostics":[{"code":"tool-owned-canary-code","message":"tool owned message","path":"/tool/owned","severity":"error","suggestedAction":"Correct it."}]}"#;
    let bregctl = run.wrapper(
        "bregctl",
        "bregctl",
        "\"test \"*",
        &format!("printf '%s\\n' '{tool_report}'; exit 1"),
    );
    let output = run.start(&bregctl, &run.bin.join("caseworkctl"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    run.stop(&report);
    assert!(!output.status.success(), "{report}");
    fn find(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
        for entry in fs::read_dir(root).ok()? {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                if let Some(found) = find(&entry.path(), name) {
                    return Some(found);
                }
            } else if entry.file_name() == name {
                return Some(entry.path());
            }
        }
        None
    }
    let kept = find(&run.state, "breg-test-report.json")
        .unwrap_or_else(|| panic!("the failed run keeps the tool's own report: {report}"));
    let kept: serde_json::Value = serde_json::from_slice(&fs::read(kept).unwrap()).unwrap();
    assert_eq!(
        kept,
        serde_json::from_str::<serde_json::Value>(tool_report).unwrap()
    );
    assert!(
        report.to_string().contains("tool-owned-canary-code"),
        "{report}"
    );
}
