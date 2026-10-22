use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn wallet_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let generation = tempfile::tempdir().unwrap();
    let binary = generation
        .path()
        .join("components/evidence/evidence-oid4vci/evidence-oid4vci");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::write(
        &binary,
        b"#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    (generation, binary)
}

#[test]
fn wallet_check_uses_selected_optional_binary_and_json_report_flag() {
    let (generation, binary) = wallet_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .env("RSTACK_GENERATION_DIR", generation.path())
        .env("RSTACK_RELEASE_TAG", "v0.44.0")
        .env("RSTACK_EVIDENCE_OID4VCI_BIN", binary)
        .args([
            "--format",
            "json",
            "oid4vci",
            "check",
            "--runtime-config",
            "runtime.yaml",
            "--environment",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"check\n--runtime-config\nruntime.yaml\n--format\njson\n--environment\n"
    );
}

#[test]
fn wallet_artifact_and_service_refuse_report_format_before_exec() {
    let (generation, binary) = wallet_fixture();
    for action in ["openapi", "serve"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
        command
            .env("RSTACK_GENERATION_DIR", generation.path())
            .env("RSTACK_RELEASE_TAG", "v0.44.0")
            .env("RSTACK_EVIDENCE_OID4VCI_BIN", &binary)
            .args(["oid4vci", action, "--format", "human"]);
        if action == "serve" {
            command.args(["--runtime-config", "runtime.yaml"]);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(!output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
fn wallet_helper_never_falls_back_to_path_in_managed_mode() {
    let (generation, _binary) = wallet_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .env("RSTACK_GENERATION_DIR", generation.path())
        .env("RSTACK_RELEASE_TAG", "v0.44.0")
        .env_remove("RSTACK_EVIDENCE_OID4VCI_BIN")
        .args(["oid4vci", "openapi"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("rstack"), "{diagnostic}");
}
