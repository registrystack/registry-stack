// SPDX-License-Identifier: Apache-2.0
//! First project journey through the public executable, entirely offline.
use serde_json::Value;
use std::{fs, process::Command};

fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(arguments)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap()
}

#[test]
fn runtime_check_is_offline_until_environment_is_explicitly_requested() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().canonicalize().unwrap().join("runtime.yaml");
    let text =
        include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml")
            .replace(
                "namespace: coordinator_demo",
                "namespace: ${COORDINATOR_CHECK_NAMESPACE}",
            );
    fs::write(&file, text).unwrap();
    let arguments = [
        "--format",
        "json",
        "--runtime-config",
        file.to_str().unwrap(),
        "check",
    ];
    let unchecked = cli(&arguments);
    assert!(
        unchecked.status.success(),
        "{}",
        String::from_utf8_lossy(&unchecked.stdout)
    );
    let report: Value = serde_json::from_slice(&unchecked.stdout).unwrap();
    assert_eq!(report["kind"], "CoordinatorCtlReport");
    assert_eq!(report["ok"], true);
    // A valid stand-in permits the surrounding document to be checked.
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    let denied = cli(&[arguments.as_slice(), &["--deny-warnings"]].concat());
    assert!(denied.status.success());
    for (value, exit) in [("coordinator_example", 0), ("PRIVATE-NAMESPACE-CANARY", 1)] {
        let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(arguments)
            .arg("--environment")
            .env("COORDINATOR_CHECK_NAMESPACE", value)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-NAMESPACE-CANARY"));
    }
    // A product discriminator cannot decode its generic stand-in. The common
    // reader explicitly warns that the remainder could not be checked.
    let text = fs::read_to_string(&file)
        .unwrap()
        .replace("product: breg", "product: ${COORDINATOR_CHECK_PRODUCT}");
    fs::write(&file, text).unwrap();
    let incomplete = cli(&arguments);
    assert!(incomplete.status.success());
    let report: Value = serde_json::from_slice(&incomplete.stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["severity"], "warning");
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/connections/applications/product"
    );
    let denied = cli(&[arguments.as_slice(), &["--deny-warnings"]].concat());
    assert_eq!(denied.status.code(), Some(1));
}

#[test]
fn checking_reports_distinct_refusal_usage_and_unavailable_exits() {
    let empty = cli(&["--format", "json", "check"]);
    assert_eq!(empty.status.code(), Some(2));
    let empty: Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert_eq!(empty["diagnostics"][0]["code"], "coordinator.command.usage");
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().canonicalize().unwrap().join("missing.yaml");
    let unavailable = cli(&[
        "--format",
        "json",
        "--runtime-config",
        missing.to_str().unwrap(),
        "check",
    ]);
    assert_eq!(unavailable.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    let usage = cli(&["--format", "json", "check", "--PRIVATE-ARGUMENT-CANARY"]);
    assert_eq!(usage.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&usage.stdout).contains("PRIVATE-ARGUMENT-CANARY"));
    let invalid = root.path().canonicalize().unwrap().join("runtime.yaml");
    let text =
        include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml")
            .replace(
                "namespace: coordinator_demo",
                "namespace: coordinator_demo\nunknownRoot: PRIVATE-PRODUCT-CANARY",
            )
            .replace(
                "product: breg",
                "product: breg\n    unknownConnection: PRIVATE-PRODUCT-CANARY",
            );
    fs::write(&invalid, text).unwrap();
    let refusal = cli(&[
        "--format",
        "json",
        "--runtime-config",
        invalid.to_str().unwrap(),
        "check",
    ]);
    assert_eq!(refusal.status.code(), Some(1));
    let bytes = String::from_utf8(refusal.stdout).unwrap();
    assert!(!bytes.contains("PRIVATE-PRODUCT-CANARY"));
    let report: Value = serde_json::from_str(&bytes).unwrap();
    let findings = report["diagnostics"].as_array().unwrap();
    assert!(findings.len() >= 2);
    assert!(findings.iter().all(|finding| finding["source"]["line"]
        .as_u64()
        .is_some_and(|line| line > 0)));
}

#[test]
fn init_check_and_explain_work_without_database_or_signing_keys() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    let initialized = cli(&["--format", "json", "init", "--directory", directory]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let result: Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(result["status"], "initialized");
    assert_eq!(
        result["created"],
        serde_json::json!([
            "workflow.yaml",
            "functions.rhai",
            "runtime.yaml",
            "scenarios.yaml",
            ".gitignore"
        ])
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 5);
    // Local secrets and caches under `.coordinator/` stay out of version control.
    assert_eq!(
        fs::read_to_string(path.join(".gitignore")).unwrap(),
        ".coordinator/\n"
    );
    let tested = cli(&["--format", "json", "test", "--project", directory]);
    assert!(
        tested.status.success(),
        "{}",
        String::from_utf8_lossy(&tested.stdout)
    );
    let runtime = path.join("runtime.yaml");
    let checked = cli(&[
        "--format",
        "json",
        "--runtime-config",
        runtime.to_str().unwrap(),
        "check",
        "--project",
        directory,
    ]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let result: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(result["status"], "valid");
    assert!(result["definitionDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let explained = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        directory,
        "--explain",
    ]);
    assert!(explained.status.success());
    let result: Value = serde_json::from_slice(&explained.stdout).unwrap();
    assert_eq!(result["networkAccess"], false);
    assert_eq!(result["databaseAccess"], false);
    assert_eq!(result["secretResolution"], false);
    assert_eq!(result["limits"]["operations"], 100000);
    assert_eq!(result["steps"].as_array().unwrap().len(), 6);
    let text = cli(&["check", "--project", directory]);
    assert!(text.status.success());
    assert!(String::from_utf8(text.stdout)
        .unwrap()
        .contains("Valid workflow"));
    let refused = cli(&["--format", "json", "init", "--directory", directory]);
    assert!(!refused.status.success());
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(result["diagnostics"][0]["code"], "coordinator.project.init");
    assert!(result["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("--directory"));
}

#[test]
fn init_names_the_project_after_its_directory_and_writes_runtime_in_reading_order() {
    let root = tempfile::tempdir().unwrap();
    // A parent whose path needs YAML quoting proves the secrets root works anywhere.
    let parent = root.path().canonicalize().unwrap().join("notes #1: drafts");
    fs::create_dir(&parent).unwrap();
    let path = parent.join("claims-follow-up");
    let directory = path.to_str().unwrap();
    let initialized = cli(&["init", "--directory", directory]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let workflow = fs::read_to_string(path.join("workflow.yaml")).unwrap();
    assert!(
        workflow.contains("\n  id: claims-follow-up\n"),
        "{workflow}"
    );
    let runtime = fs::read_to_string(path.join("runtime.yaml")).unwrap();
    let keys: Vec<_> = runtime
        .lines()
        .filter(|line| line.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
        .map(|line| line.split(':').next().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "apiVersion",
            "kind",
            "secretProviders",
            "database",
            "namespace",
            "connections"
        ]
    );
    assert!(runtime.contains("# Offline check reads references"));
    let parsed = registry_platform_config::RuntimeConfigLoader::new(
        registry_platform_config::RuntimeEnvelope {
            api_version: registry_coordinator::runtime::API_VERSION,
            kind: registry_coordinator::runtime::KIND,
        },
    )
    .parse_str::<Value>(&runtime, |_| None)
    .unwrap()
    .config;
    assert_eq!(
        parsed["secretProviders"]["file"]["root"],
        path.join(".coordinator/secrets").to_str().unwrap()
    );
    let checked = cli(&[
        "--runtime-config",
        path.join("runtime.yaml").to_str().unwrap(),
        "check",
        "--project",
        directory,
    ]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
    assert!(String::from_utf8(checked.stdout)
        .unwrap()
        .contains("Valid workflow claims-follow-up version 1"));
    assert!(cli(&["test", "--project", directory]).status.success());

    let named = root.path().join("second");
    let initialized = cli(&[
        "init",
        "--directory",
        named.to_str().unwrap(),
        "--id",
        "renewal-reminder",
    ]);
    assert!(initialized.status.success());
    let workflow = fs::read_to_string(named.join("workflow.yaml")).unwrap();
    assert!(
        workflow.contains("\n  id: renewal-reminder\n"),
        "{workflow}"
    );
}

#[test]
fn a_relative_runtime_config_is_read_from_the_current_directory() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relative-flow");
    assert!(cli(&["init", "--directory", path.to_str().unwrap()])
        .status
        .success());
    for (directory, runtime) in [
        (root.path().to_path_buf(), "relative-flow/runtime.yaml"),
        (path.clone(), "./runtime.yaml"),
        (path.join(".coordinator"), "../runtime.yaml"),
    ] {
        fs::create_dir_all(&directory).unwrap();
        let checked = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args([
                "--runtime-config",
                runtime,
                "check",
                "--project",
                path.to_str().unwrap(),
            ])
            .current_dir(&directory)
            .env_remove("COORDINATOR_TEST_DATABASE_URL")
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{runtime}: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        assert!(String::from_utf8(checked.stdout)
            .unwrap()
            .contains("Valid runtime configuration"));
    }
}

#[test]
fn init_fills_an_empty_directory_and_refuses_one_with_content_or_no_project_id() {
    let root = tempfile::tempdir().unwrap();
    let empty = root.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let initialized = cli(&["init", "--directory", empty.to_str().unwrap()]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 5);

    let occupied = root.path().join("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("notes.txt"), "keep me").unwrap();
    let refused = cli(&[
        "--format",
        "json",
        "init",
        "--directory",
        occupied.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    let finding = &result["diagnostics"][0];
    assert_eq!(finding["code"], "coordinator.project.init");
    assert!(
        finding["message"].as_str().unwrap().contains("not empty"),
        "{finding}"
    );
    assert!(finding["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("new or empty directory"));
    assert_eq!(fs::read_dir(&occupied).unwrap().count(), 1);
    assert_eq!(
        fs::read_to_string(occupied.join("notes.txt")).unwrap(),
        "keep me"
    );

    let unnamed = root.path().join("My Flow");
    let refused = cli(&[
        "--format",
        "json",
        "init",
        "--directory",
        unnamed.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    let finding = &result["diagnostics"][0];
    assert!(
        finding["message"].as_str().unwrap().contains("project id"),
        "{finding}"
    );
    assert!(finding["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("--id"));
    assert!(!unnamed.exists());
    let refused = cli(&[
        "--format",
        "json",
        "init",
        "--directory",
        unnamed.to_str().unwrap(),
        "--id",
        "My Flow",
    ]);
    assert_eq!(refused.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert!(result["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("--id"));
    assert!(!unnamed.exists());
}

#[test]
fn human_output_is_the_default_and_explain_reads_the_graph_from_start() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    let initialized = cli(&["init", "--directory", directory]);
    assert!(initialized.status.success());
    let created = String::from_utf8(initialized.stdout).unwrap();
    assert!(created.starts_with("created: "), "{created}");
    assert!(created.contains("  workflow.yaml\n"), "{created}");
    assert!(created.contains("  .gitignore\n"), "{created}");
    let order = [
        "due",
        "read-application",
        "permission",
        "notify",
        "skipped",
        "accepted",
    ];
    for arguments in [
        vec!["check", "--project", directory, "--explain"],
        vec!["--format", "human", "explain", "--project", directory],
    ] {
        let explained = cli(&arguments);
        assert!(
            explained.status.success(),
            "{}",
            String::from_utf8_lossy(&explained.stderr)
        );
        let text = String::from_utf8(explained.stdout).unwrap();
        assert!(text.starts_with("Workflow "), "{text}");
        assert!(text.lines().count() <= 12, "{text}");
        let steps = text
            .lines()
            .filter_map(|line| line.strip_prefix("  "))
            .map(|line| line.split(':').next().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(steps, order, "{text}");
        assert!(text.contains("send -> notify"), "{text}");
        assert!(text.contains("notices submit-message"), "{text}");
    }
    let explained = cli(&["--format", "json", "explain", "--project", directory]);
    let result: Value = serde_json::from_slice(&explained.stdout).unwrap();
    let steps = result["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(steps, order);
    let runtime = path.join("runtime.yaml");
    let checked = cli(&["--runtime-config", runtime.to_str().unwrap(), "check"]);
    assert!(checked.status.success());
    let text = String::from_utf8(checked.stdout).unwrap();
    assert_eq!(text, "Valid runtime configuration\n");
    let output = root.path().canonicalize().unwrap().join("package");
    let packaged = cli(&[
        "package",
        "--project",
        directory,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        packaged.status.success(),
        "{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let text = String::from_utf8(packaged.stdout).unwrap();
    assert!(
        text.starts_with(&format!("created: {}\n", output.display())),
        "{text}"
    );
    assert!(text.contains("package digest: sha256:"), "{text}");
}

#[test]
fn test_without_scenarios_names_the_missing_file_and_how_to_add_it() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    assert!(cli(&["init", "--directory", directory]).status.success());
    fs::remove_file(path.join("scenarios.yaml")).unwrap();
    let refused = cli(&["--format", "json", "test", "--project", directory]);
    assert_eq!(refused.status.code(), Some(1));
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    let finding = &result["diagnostics"][0];
    assert_eq!(finding["code"], "coordinator.scenario.missing");
    assert!(finding["message"].as_str().unwrap().contains("missing"));
    assert!(finding["source"]["file"]
        .as_str()
        .unwrap()
        .ends_with("scenarios.yaml"));
    let action = finding["suggestedAction"].as_str().unwrap();
    assert!(action.contains("scenarios.yaml"), "{action}");
    assert!(action.contains("--scenarios"), "{action}");
}

#[test]
fn package_into_an_existing_directory_names_it_and_how_to_write_a_new_one() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    assert!(cli(&["init", "--directory", directory]).status.success());
    let output = root.path().canonicalize().unwrap().join("package");
    let arguments = [
        "package",
        "--project",
        directory,
        "--output",
        output.to_str().unwrap(),
    ];
    assert!(cli(&arguments).status.success());
    let refused = cli(&arguments);
    assert_eq!(refused.status.code(), Some(1));
    let text = String::from_utf8(refused.stderr).unwrap();
    assert!(
        text.contains(&format!("{} already exists", output.display())),
        "{text}"
    );
    assert!(!text.contains("deployment contract"), "{text}");
    assert!(text.contains("--output"), "{text}");
}

#[test]
fn package_runs_the_project_scenarios_and_refuses_when_one_fails() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    assert!(cli(&["init", "--directory", directory]).status.success());
    let scenarios = path.join("scenarios.yaml");
    let text = fs::read_to_string(&scenarios).unwrap();
    fs::write(
        &scenarios,
        text.replacen("state: completed", "state: refused", 1),
    )
    .unwrap();
    let output = root.path().canonicalize().unwrap().join("package");
    let refused = cli(&[
        "--format",
        "json",
        "package",
        "--project",
        directory,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(!output.exists(), "a refused package leaves no directory");
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    let findings = result["diagnostics"].as_array().unwrap();
    assert_eq!(findings[0]["code"], "coordinator.package.scenarios-failed");
    assert!(findings[0]["source"]["file"]
        .as_str()
        .unwrap()
        .ends_with("scenarios.yaml"));
    assert!(findings[0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("coordinatorctl test"));
    assert!(
        findings[1..]
            .iter()
            .any(|finding| finding["code"] == "coordinator.scenario.expectation"),
        "{findings:?}"
    );
    fs::write(&scenarios, text).unwrap();
    assert!(cli(&[
        "package",
        "--project",
        directory,
        "--output",
        output.to_str().unwrap(),
    ])
    .status
    .success());
}

#[test]
fn only_commands_that_call_the_service_take_service_arguments() {
    for command in [
        "init",
        "check",
        "explain",
        "test",
        "package",
        "plan",
        "apply",
        "deployment-status",
        "openapi",
    ] {
        let help = String::from_utf8(cli(&[command, "--help"]).stdout).unwrap();
        assert!(!help.contains("--url"), "{command}: {help}");
        assert!(!help.contains("--token-file"), "{command}: {help}");
    }
    for command in [
        "start",
        "status",
        "list",
        "inspect",
        "retry-same",
        "cancel",
        "reconcile",
        "doctor",
        "restore-hold",
        "release-restore-hold",
        "release-admission-hold",
        "complete-execution-recovery",
        "retain",
    ] {
        let help = String::from_utf8(cli(&[command, "--help"]).stdout).unwrap();
        assert!(help.contains("--url"), "{command}: {help}");
        assert!(help.contains("--token-file"), "{command}: {help}");
    }
}

#[test]
fn a_refused_command_line_names_the_argument_and_the_fix_for_that_mistake() {
    let usage = |arguments: &[&str]| {
        let output = cli(&[&["--format", "json"], arguments].concat());
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let finding = &report["diagnostics"][0];
        assert_eq!(finding["code"], "coordinator.cli.usage");
        let text = format!("{finding}");
        assert!(!text.contains("value-canary"), "{text}");
        (
            finding["message"].as_str().unwrap().to_owned(),
            finding["suggestedAction"].as_str().unwrap().to_owned(),
        )
    };
    let (message, action) = usage(&[
        "package",
        "--project",
        "value-canary",
        "--output",
        "value-canary",
        "--url",
        "https://value-canary.example.org",
    ]);
    assert!(message.contains("--url"), "{message}");
    assert!(action.contains("Remove --url"), "{action}");
    assert!(action.contains("calls no service"), "{action}");
    let (message, action) = usage(&[
        "--url",
        "https://value-canary.example.org",
        "status",
        "--run",
        "00000000-0000-4000-8000-000000000001",
    ]);
    assert!(message.contains("--url"), "{message}");
    assert!(action.contains("after status"), "{action}");
    let (message, action) = usage(&["package", "--project", "value-canary"]);
    assert!(message.contains("--output"), "{message}");
    assert!(action.contains("Add --output"), "{action}");
    assert!(action.contains("coordinatorctl package --help"), "{action}");
    let (message, action) = usage(&["status", "--run", "value-canary"]);
    assert!(message.contains("--run"), "{message}");
    assert!(action.contains("coordinatorctl status --help"), "{action}");
    let (_, action) = usage(&["pakage"]);
    assert!(action.contains("coordinatorctl package"), "{action}");
}

#[test]
fn check_locates_a_missing_binding_without_printing_configured_values() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    assert!(cli(&["init", "--directory", directory]).status.success());
    let runtime = path.join("runtime.yaml");
    let mut document: Value = registry_platform_config::RuntimeConfigLoader::new(
        registry_platform_config::RuntimeEnvelope {
            api_version: registry_coordinator::runtime::API_VERSION,
            kind: registry_coordinator::runtime::KIND,
        },
    )
    .parse_str::<Value>(&fs::read_to_string(&runtime).unwrap(), |_| None)
    .unwrap()
    .config;
    let original = document["connections"]
        .as_object_mut()
        .unwrap()
        .remove("applications")
        .unwrap();
    document["connections"]["wrong-name"] = original;
    document["connections"]["wrong-name"]["authorization"]["resource"] =
        Value::String("urn:example:configured-value-canary".into());
    fs::write(&runtime, serde_norway::to_string(&document).unwrap()).unwrap();
    let refused = cli(&[
        "--format",
        "json",
        "--runtime-config",
        runtime.to_str().unwrap(),
        "check",
        "--project",
        directory,
    ]);
    assert!(!refused.status.success());
    let report = String::from_utf8(refused.stdout).unwrap();
    assert!(!report.contains("configured-value-canary"));
    let result: Value = serde_json::from_str(&report).unwrap();
    assert_eq!(
        result["diagnostics"][0]["code"],
        "coordinator.runtime.workflow-binding"
    );
    assert_eq!(
        result["diagnostics"][0]["path"],
        "/connections/applications"
    );
    assert!(result["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("same logical name"));
}

#[path = "support/snapshot_boundary.rs"]
mod snapshot_boundary;

#[test]
fn check_and_package_refuse_oversized_canonical_snapshot_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    snapshot_boundary::project_at_snapshot_size(&project, snapshot_boundary::SNAPSHOT_BOUND + 1);
    let output = root.path().join("package");
    for arguments in [
        vec![
            "--format",
            "json",
            "check",
            "--project",
            project.to_str().unwrap(),
        ],
        vec![
            "--format",
            "json",
            "package",
            "--project",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    ] {
        let refused = cli(&arguments);
        assert!(
            !refused.status.success(),
            "oversized project must be refused"
        );
        assert!(refused.stderr.is_empty());
        let error: Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(
            error["diagnostics"][0]["code"],
            "coordinator.definition.snapshot-limit"
        );
        assert!(error["diagnostics"][0]["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("393216"));
        assert!(!output.exists());
    }
    snapshot_boundary::project_at_snapshot_size(&project, snapshot_boundary::SNAPSHOT_BOUND);
    assert!(cli(&["check", "--project", project.to_str().unwrap()])
        .status
        .success());
    let packaged = cli(&[
        "--format",
        "json",
        "package",
        "--project",
        project.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        packaged.status.success(),
        "{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let report: Value = serde_json::from_slice(&packaged.stdout).unwrap();
    assert!(report["packageDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let bytes = fs::read_to_string(output.join("definition.json")).unwrap();
    assert_eq!(bytes.len(), snapshot_boundary::SNAPSHOT_BOUND);
    registry_coordinator::definition::Definition::from_snapshot(&bytes).unwrap();
}
