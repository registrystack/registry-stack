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
    let tool = root.join("caseworkctl");
    fs::write(
        &tool,
        concat!(
            "#!/usr/bin/env bash\n",
            "set -euo pipefail\n",
            "[[ $# -eq 4 ]]\n",
            "[[ $1 == --format && $2 == json && $3 == explain ]]\n",
            "[[ -f $4/casework.yaml ]]\n",
            "printf '%s\\n' '",
            "{\"apiVersion\":\"id.registrystack.org/formats/casework/report/v1alpha2\",",
            "\"kind\":\"CaseworkReport\",\"command\":\"explain\",\"status\":\"complete\",\"ok\":true,",
            "\"accessProfiles\":[{\"id\":\"reviewer\",\"principalClaim\":\"sub\"}],",
            "\"reviewPolicies\":[{\"dependencies\":{\"accessProfiles\":[{\"id\":\"reviewer\",\"principalClaim\":\"sub\"}]}}],",
            "\"trustedProducers\":[{\"id\":\"review-producer\"}],",
            "\"contextProviders\":[{\"id\":\"proposal-context\"}]}",
            "'\n",
        ),
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
    let error = report["error"].as_str().unwrap();
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
    let error = report["error"].as_str().unwrap();
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
    let error = report["error"].as_str().unwrap();
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
    let error = report["error"].as_str().unwrap();
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
    let error = report["error"].as_str().unwrap();
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
        let error = report["error"].as_str().unwrap();
        assert!(error.contains(path), "{error}");
        assert!(error.contains(message), "{error}");
        assert!(error.contains(action), "{error}");
        assert!(!error.contains(supplied), "{error}");
        assert!(!state.exists());
    }
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
    assert!(!result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.dev.v1");
    assert!(report.get("diagnostics").is_none());
    assert!(
        report["error"]
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
    assert!(report["error"].as_str().unwrap().contains("run ID"));
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn worker_restores_a_valid_plan_whose_captured_input_exceeds_512_kib() {
    let scratch = tempfile::tempdir().unwrap();
    let project_root = scratch.path().join("project");
    fs::create_dir(&project_root).unwrap();
    fs::write(
        project_root.join("registry.yaml"),
        include_str!(
            "../../../products/platform/conformance/projects/breg-project-dev/registry/registry.yaml"
        ),
    )
    .unwrap();
    let raw = BASE64.encode(vec![b'x'; 400 * 1024]);
    let mut plan = serde_json::json!({
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

    let members = plan.as_object_mut().unwrap();
    members.remove("apiVersion");
    members.remove("kind");
    let run_id = "0123456789abcdef0123456789abcdef";
    let state = scratch.path().join("state");
    let root = state.join(run_id);
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.canonicalize().unwrap();
    let false_binary = ["/usr/bin/false", "/bin/false"]
        .into_iter()
        .map(std::path::Path::new)
        .find(|path| path.is_file())
        .unwrap()
        .canonicalize()
        .unwrap();
    let input = serde_json::to_vec(&serde_json::json!({
        "run_id": run_id,
        "project": project_root,
        "plan": plan,
        "ttl_seconds": 1,
        "schema_people": [],
        "breg_authority": {
            "principal": "sub", "purpose": false, "requires_postgis": false,
            "named_clients": []
        },
        "casework_principals": {},
        "binaries": {"breg": {"tool": false_binary, "runtime": false_binary}}
    }))
    .unwrap();
    assert!(input.len() > 512 * 1024, "captured input: {}", input.len());
    fs::write(root.join("input.json"), input).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["project-dev", "--worker"])
        .arg(&root)
        .env("RSTACK_DEV_STATE_DIR", &state)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .output()
        .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let error = reply["error"].as_str().unwrap();
    assert!(error.contains("breg check failed"), "{error}");
    assert!(!error.contains("cannot restore the captured development plan"));
}
