// SPDX-License-Identifier: Apache-2.0

//! `rstack dev` runs, driven through the launcher in source mode against the
//! development hosts built beside it. Cargo builds only the binaries of the
//! package under test, so build the hosts first:
//! `cargo build --locked -p registry-bregctl -p registry-caseworkctl --bins`.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::{
    fs,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// A development host CLI built beside `rstack`.
fn host(name: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_rstack")).with_file_name(name);
    assert!(
        path.is_file(),
        "{} is missing; build the development hosts first: cargo build --locked -p registry-bregctl -p registry-caseworkctl --bins",
        path.display()
    );
    path
}

/// `rstack dev` in source mode, with run state under `state` and the JSON
/// report format when `json` is set: no managed installation, the `bregctl`
/// built beside rstack as the BReg host and tool, no Casework tool, and the
/// system `false` as every product runtime, since these runs stop before a
/// service starts.
fn rstack_dev(state: &std::path::Path, json: bool) -> Command {
    let uninstalled = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("dev-run-uninstalled");
    let mut command = Command::new(env!("CARGO_BIN_EXE_rstack"));
    command
        .arg("--install-root")
        .arg(uninstalled.join("install"))
        .arg("--bin-dir")
        .arg(uninstalled.join("bin"));
    if json {
        command.args(["--format", "json"]);
    }
    command
        .arg("dev")
        .env("RSTACK_DEV_STATE_DIR", state)
        .env("RSTACK_BREGCTL_BIN", host("bregctl"))
        .env("RSTACK_BREG_BIN", system_binary("false"))
        .env_remove("RSTACK_CASEWORKCTL_BIN")
        .env("RSTACK_CASEWORK_BIN", system_binary("false"))
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .env_remove("RSTACK_DEV_DATABASE_CA");
    command
}

/// Runs `rstack --format json dev ARGUMENTS` with run state under `state`.
fn dev_json(state: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    rstack_dev(state, true).args(arguments).output().unwrap()
}

/// A path argument as UTF-8, which every test scratch path is.
fn utf8(path: &std::path::Path) -> &str {
    path.to_str().unwrap()
}

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
fn every_host_runs_the_service_guard() {
    for name in ["bregctl", "caseworkctl"] {
        hidden_guard_dispatch_reaps_workload_when_controller_closes(&host(name));
    }
}

/// The supervisor runs each service under `HOST rstack-dev guard`, where HOST
/// is the CLI that runs the supervisor.
fn hidden_guard_dispatch_reaps_workload_when_controller_closes(host: &std::path::Path) {
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
    let guard = Command::new(host)
        .args(["rstack-dev", "guard"])
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
            "{} guard exited before publishing its workload PID",
            host.display()
        );
        assert!(
            Instant::now() < launch_deadline,
            "{} guard did not publish its workload PID",
            host.display()
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
            "{} guard did not stop after its controller closed",
            host.display()
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
            vec!["start", utf8(&missing_project)],
            "domain",
            1,
        ),
        (
            "start with a bad ttl",
            vec!["start", utf8(scratch.path()), "--ttl", "9"],
            "usage",
            2,
        ),
        (
            "status with a malformed run ID",
            vec!["status", "../x"],
            "usage",
            2,
        ),
        (
            "token with a malformed person",
            vec!["token", other_run, "--as", "../x"],
            "usage",
            2,
        ),
        (
            "token for a run that is not ready",
            vec!["token", other_run, "--as", "operator"],
            "domain",
            1,
        ),
        (
            "stop with a malformed run ID",
            vec!["stop", "../x"],
            "usage",
            2,
        ),
        (
            "recover with a malformed run ID",
            vec!["stop", "../x", "--recover"],
            "usage",
            2,
        ),
        (
            "status of a run whose supervisor is lost",
            vec!["status", RUN_ID],
            "operational",
            3,
        ),
        (
            "stop of a run whose supervisor is lost",
            vec!["stop", RUN_ID],
            "operational",
            3,
        ),
    ];
    for (name, arguments, class, exit) in cases {
        let output = dev_json(&state, &arguments);
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
    let checked = dev_json(&state, &["check", utf8(scratch.path())]);
    assert!(checked.status.success(), "{checked:?}");
    assert!(!state.exists());
    let result = dev_json(&state, &["start", utf8(scratch.path())]);
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
    let output = rstack_dev(&state, false)
        .args(["status", RUN_ID])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.starts_with("rstack dev: run "), "{text}");
    assert!(text.contains("lost its supervisor"), "{text}");
}

fn recover(state: &std::path::Path, run_id: &str) -> std::process::Output {
    dev_json(state, &["stop", run_id, "--recover"])
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
    rstack_dev(state, json)
        .args(["check", utf8(root), "--deny-warnings"])
        .output()
        .unwrap()
}

fn start(root: &std::path::Path, state: &std::path::Path) -> std::process::Output {
    dev_json(state, &["start", utf8(root)])
}

fn check_with_casework_tool(
    root: &std::path::Path,
    state: &std::path::Path,
    tool: &std::path::Path,
) -> std::process::Output {
    rstack_dev(state, true)
        .args(["check", utf8(root), "--deny-warnings"])
        .env("RSTACK_CASEWORKCTL_BIN", tool)
        .output()
        .unwrap()
}

fn start_with_casework_tool(
    root: &std::path::Path,
    state: &std::path::Path,
    tool: &std::path::Path,
) -> std::process::Output {
    rstack_dev(state, true)
        .args(["start", utf8(root)])
        .env("RSTACK_CASEWORKCTL_BIN", tool)
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

    let result = start(scratch.path(), &state);

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
    for (plan_edit, from, to, path, message) in [
        (
            "scope",
            "casework: {profile: reviewer, scopes: [casework:review]}",
            "casework: {profile: reviewer, scopes: ['casework:\"quoted\"']}",
            "/people/reviewer/grants/casework/scopes",
            "scope-token",
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
            diagnostic["message"].as_str().unwrap().contains(message),
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

    // `check` needs only its host, so the launcher runs it without the
    // Casework tool and the runner reports that tool at its plan entry.
    let unavailable = check(scratch.path(), &state, true);

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
    // The plan lists no hosting product, so the first available host reports
    // the plan error.
    let result = start(scratch.path(), &state);
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
    let result = dev_json(scratch.path(), &["stop", "../other-run"]);
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
/// whose PostgreSQL administrator URL is `database_url`. The launcher would run
/// the stand-in tool as the host, so the test runs the built host directly.
fn start_with_breg_binaries(
    root: &std::path::Path,
    state: &std::path::Path,
    (tool, runtime): (&std::path::Path, &std::path::Path),
    database_url: &str,
) -> std::process::Output {
    Command::new(host("bregctl"))
        .args(["rstack-dev", "start", "--json", "--"])
        .arg(root)
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

/// A project whose plan lists only Casework: the standalone decision example
/// and one scenario that reads its review policies.
fn casework_only_project(root: &std::path::Path) {
    fs::create_dir_all(root.join("casework")).unwrap();
    fs::write(
        root.join("casework/casework.yaml"),
        include_str!("../../../products/casework/examples/standalone-decision/casework.yaml"),
    )
    .unwrap();
    fs::write(
        root.join("dev.yaml"),
        concat!(
            "apiVersion: id.registrystack.org/formats/breg/project-dev/v1alpha1\n",
            "kind: BRegProjectDev\n",
            "issuer: https://issuer.example.invalid\n",
            "products:\n",
            "  - {product: casework, project: casework, audience: \"urn:example:review\"}\n",
            "people:\n",
            "  staff:\n",
            "    subject: staff\n",
            "    client: staff-client\n",
            "    grants:\n",
            "      casework: {profile: staff, scopes: [\"casework:staff\"], claims: {registry_actor_kind: human}}\n",
            "scenarioFile: tests/scenarios.yaml\n",
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/scenarios.yaml"),
        concat!(
            "apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1\n",
            "kind: RStackScenarios\n",
            "scenarios:\n",
            "  - id: smoke\n",
            "    steps:\n",
            "      - {id: read, product: casework, as: staff, method: GET, path: /v1/review-policies, expect: {status: 200}}\n",
        ),
    )
    .unwrap();
}

/// `rstack dev` with only the Casework tools: no BReg binary is set and none
/// is installed, so the launcher runs the built `caseworkctl` as the host.
fn casework_only_dev(state: &std::path::Path) -> Command {
    let mut command = rstack_dev(state, true);
    command
        .env_remove("RSTACK_BREGCTL_BIN")
        .env_remove("RSTACK_BREG_BIN")
        .env("RSTACK_CASEWORKCTL_BIN", host("caseworkctl"));
    command
}

#[test]
fn a_casework_only_run_is_supervised_by_its_casework_host() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let project = scratch.path().join("project");
    casework_only_project(&project);

    let checked = casework_only_dev(&state)
        .args(["check", utf8(&project), "--deny-warnings"])
        .output()
        .unwrap();
    assert!(checked.status.success(), "{checked:?}");

    // The supervisor opens the PostgreSQL administrator session, so a refused
    // session proves `caseworkctl rstack-dev supervisor` ran the run.
    let result = casework_only_dev(&state)
        .args(["start", utf8(&project)])
        .env(
            "RSTACK_DEV_DATABASE_URL",
            format!(
                "postgresql://admin:unused@127.0.0.1:{}/postgres",
                closed_loopback_port()
            ),
        )
        .output()
        .unwrap();

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
    assert_eq!(live_runs(&state), Vec::<String>::new());
}

#[test]
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built caseworkctl and casework binaries"]
fn a_casework_only_run_starts_reports_and_stops_without_breg() {
    let scratch = tempfile::tempdir().unwrap();
    let state = scratch.path().join("state");
    let project = scratch.path().join("project");
    casework_only_project(&project);
    let casework = host("casework");

    let started = with_test_database(
        casework_only_dev(&state)
            .args(["start", utf8(&project)])
            .env("RSTACK_CASEWORK_BIN", &casework),
    )
    .output()
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    let run_id = report["run_id"].as_str().unwrap_or_default().to_owned();
    let stop = || dev_json(&state, &["stop", &run_id]);
    if !started.status.success() {
        stop();
        panic!("{started:?}");
    }
    assert_eq!(report["status"], "ready", "{report}");
    assert_eq!(report["scenarios"][0]["result"], "passed", "{report}");

    // Run-ID actions find a host without any BReg binary.
    let status = casework_only_dev(&state)
        .args(["status", &run_id])
        .output()
        .unwrap();
    let token = casework_only_dev(&state)
        .args(["token", &run_id, "--as", "staff"])
        .output()
        .unwrap();
    let stopped = casework_only_dev(&state)
        .args(["stop", &run_id])
        .output()
        .unwrap();
    if !stopped.status.success() {
        stop();
    }

    assert!(status.status.success(), "{status:?}");
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["status"], "ready", "{status}");
    // The token report holds a credential, so only its exit status is shown.
    assert!(token.status.success(), "{:?}", token.status);
    assert!(stopped.status.success(), "{stopped:?}");
    let stopped: serde_json::Value = serde_json::from_slice(&stopped.stdout).unwrap();
    assert_eq!(stopped["status"], "stopped", "{stopped}");
    assert_eq!(live_runs(&state), Vec::<String>::new());
}

/// Points `command` at the TLS PostgreSQL test server that
/// `RSTACK_DEV_DATABASE_URL` and `RSTACK_DEV_DATABASE_CA` name.
fn with_test_database(command: &mut Command) -> &mut Command {
    let variable = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("set {name} to a TLS PostgreSQL server"))
    };
    command
        // The runner requires a password in the URL; a trust-authenticated
        // test server ignores it.
        .env(
            "RSTACK_DEV_DATABASE_URL",
            variable("RSTACK_DEV_DATABASE_URL").replacen("postgres@", "postgres:unused@", 1),
        )
        .env("RSTACK_DEV_DATABASE_CA", variable("RSTACK_DEV_DATABASE_CA"))
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
    let extra_root = rstack_dev(&state, true)
        .args([
            "start",
            utf8(&project),
            "--application-root",
            utf8(scratch.path()),
        ])
        .env("RSTACK_CASEWORKCTL_BIN", &tool)
        .output()
        .unwrap();
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
        "/bindings/bregReviewAuthority/runIssuerBinding/producer/expectedSubject"
    );
    assert!(!report.to_string().contains("mismatched-test-subject"));
    assert!(!state.exists());
    assert_eq!(
        original,
        fs::read(project.join("casework/casework.yaml")).unwrap()
    );
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
        let bin = std::path::Path::new(env!("CARGO_BIN_EXE_rstack"))
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
        with_test_database(rstack_dev(&self.state, true).args(["start", utf8(&self.project)]))
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
            let _ = dev_json(&self.state, &["stop", run]);
        }
    }
}

#[test]
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built bregctl, breg, caseworkctl and casework binaries"]
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
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built bregctl, breg, caseworkctl and casework binaries"]
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
#[ignore = "requires RSTACK_DEV_DATABASE_URL, RSTACK_DEV_DATABASE_CA and built bregctl, breg, caseworkctl and casework binaries"]
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
