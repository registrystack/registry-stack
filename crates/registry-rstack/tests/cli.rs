use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rstack"))
        .args(arguments)
        .output()
        .expect("run rstack")
}

#[test]
fn root_command_metadata_states_the_human_default() {
    let command = registry_rstack::command();
    let format = command
        .get_arguments()
        .find(|argument| argument.get_id() == "format")
        .expect("format option");
    assert_eq!(format.get_default_values(), ["human"]);
}

#[test]
fn version_matches_the_shared_build_identity() {
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        format!("rstack {}\n", registry_platform_buildinfo::DISPLAY_VERSION)
    );
}

#[test]
fn root_help_works_without_an_installation() {
    let help = run(&[]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("rstack <product> <action>"));
    assert!(text.contains("components list"));
    assert!(text.contains("breg"));
    assert!(text.contains("evidence"));
}

#[test]
fn unknown_component_and_duplicate_format_are_usage_failures() {
    let unknown = run(&["install", "bogus"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8(unknown.stderr)
        .unwrap()
        .contains("unknown component"));

    let duplicated = run(&[
        "--format",
        "human",
        "components",
        "list",
        "--format",
        "json",
    ]);
    assert_eq!(duplicated.status.code(), Some(2));
    assert!(duplicated.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&duplicated.stdout).unwrap();
    assert!(report["error"]["message"]
        .as_str()
        .unwrap()
        .contains("--format"));
}

#[test]
fn completions_refuses_an_explicit_report_format_without_emitting_a_script() {
    let before = run(&["--format", "human", "completions", "zsh"]);
    assert_eq!(before.status.code(), Some(2), "{before:?}");
    assert!(before.stdout.is_empty(), "{before:?}");
    assert!(!String::from_utf8(before.stderr)
        .unwrap()
        .contains("#compdef"));

    let after = run(&["completions", "zsh", "--format", "json"]);
    assert_eq!(after.status.code(), Some(2), "{after:?}");
    assert!(after.stderr.is_empty(), "{after:?}");
    assert!(!String::from_utf8_lossy(&after.stdout).contains("#compdef"));
    let report: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(report["error"]["class"], "usage");
}

#[test]
fn product_json_help_uses_the_public_command_tree_offline() {
    let output = run(&["help", "evidence", "--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "registry.rstack.help.v1");
    assert_eq!(value["command"]["invocation"], "rstack evidence");
    assert!(value["command"]["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["name"] == "init"));
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("evidencectl"));
}

#[test]
fn manifest_help_rewrites_the_command_without_rewriting_product_prose() {
    let output = run(&["help", "manifest", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["command"]["invocation"], "rstack manifest");
    assert_eq!(
        report["command"]["subcommands"][0]["about"],
        "Validate one Registry Manifest metadata document"
    );
}

#[test]
fn action_help_accepts_json_after_the_product_without_an_installation() {
    let output = run(&["evidence", "check", "--help", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.help.v1");
    assert_eq!(report["command"]["invocation"], "rstack evidence check");
    assert_eq!(report["command"]["name"], "check");
}

#[test]
fn evidence_junit_help_remains_offline_for_supported_commands() {
    for arguments in [
        &["--format", "junit", "evidence", "test", "--help"][..],
        &["evidence", "fixtures", "run", "--help", "--format=junit"][..],
    ] {
        let output = run(arguments);
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("rstack evidence"),
            "{arguments:?}: {stdout}"
        );
    }
}

#[test]
fn offline_help_refuses_unknown_surplus_actions_and_options() {
    for arguments in [
        &["evidence", "unknown", "--help"][..],
        &["evidence", "check", "extra", "--help"][..],
        &["evidence", "check", "--unknown", "--help"][..],
        &["evidence", "check", "--help", "--", "extra"][..],
    ] {
        let output = run(arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
        assert!(!output.stderr.is_empty(), "{arguments:?}: {output:?}");
    }

    for arguments in [
        &["evidence", "check", "extra", "--help", "--format", "json"][..],
        &["evidence", "check", "--unknown", "--help", "--format=json"][..],
    ] {
        let json = run(arguments);
        assert_eq!(json.status.code(), Some(2), "{arguments:?}: {json:?}");
        assert!(json.stderr.is_empty(), "{arguments:?}: {json:?}");
        let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(report["error"]["class"], "usage");
    }
}

#[test]
fn json_refusal_is_one_stdout_object_with_matching_exit_class() {
    let output = run(&["--format", "json", "install", "bogus"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.error.v1");
    assert_eq!(report["error"]["class"], "usage");
    assert!(report["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown component"));
    assert!(output.stdout.ends_with(b"\n"));

    let duplicated = run(&["--format", "human", "--format=json", "components", "list"]);
    assert_eq!(duplicated.status.code(), Some(2));
    assert!(duplicated.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&duplicated.stdout).unwrap();
    assert_eq!(report["error"]["class"], "usage");
}

#[test]
fn doctor_reports_absent_installation_without_creating_state() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("never-installed");
    let bin = scratch.path().join("bin");
    let output = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .arg("--install-root")
        .arg(&root)
        .arg("--bin-dir")
        .arg(&bin)
        .args(["doctor", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.doctor.v1");
    assert_eq!(report["status"], "refused");
    assert!(!report["problems"].as_array().unwrap().is_empty());
    assert!(!root.exists());
    assert!(!bin.exists());
}

#[test]
fn piped_output_keeps_the_human_default() {
    let scratch = tempfile::tempdir().unwrap();
    let output = run(&[
        "--install-root",
        scratch.path().to_str().unwrap(),
        "components",
        "list",
    ]);
    assert!(output.status.success(), "{output:?}");
    let output = String::from_utf8(output.stdout).unwrap();
    assert!(output.starts_with("No installation selected."));
    assert!(output.contains("breg: availability unknown, version unavailable, path none"));
    assert!(output.contains("coordinator: availability unknown, version unavailable, path none"));
}

#[test]
fn unselected_component_inventory_has_stable_detail_fields() {
    let scratch = tempfile::tempdir().unwrap();
    let output = run(&[
        "--install-root",
        scratch.path().join("absent").to_str().unwrap(),
        "components",
        "list",
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let components = report["components"].as_array().unwrap();
    assert_eq!(components.len(), 9);
    assert!(components.iter().all(|component| {
        component["version"].is_null()
            && component["path"].is_null()
            && component["available"].is_null()
    }));
}

#[test]
fn closed_report_output_is_an_operational_failure() {
    let scratch = tempfile::tempdir().unwrap();
    for format in ["human", "json"] {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        let writer: OwnedFd = writer.into();
        let output = Command::new(env!("CARGO_BIN_EXE_rstack"))
            .stdout(Stdio::from(writer))
            .args([
                "--install-root",
                scratch.path().to_str().unwrap(),
                "--format",
                format,
                "components",
                "list",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot write"));
    }
}
