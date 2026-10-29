use std::{fs, os::unix::fs::PermissionsExt, process::Command};

/// A stand-in wallet-delivery binary that identifies itself as `reported` when
/// asked for its version and otherwise prints the arguments it received.
fn wallet_fixture_reporting(reported: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let generation = tempfile::tempdir().unwrap();
    let binary = generation
        .path()
        .join("components/evidence/evidence-oid4vci/evidence-oid4vci");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::write(
        &binary,
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${{1:-}}\" == --version ]]; then\n  printf '%s\\n' 'evidence-oid4vci {reported}'\n  exit 0\nfi\nprintf '%s\\n' \"$@\"\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    (generation, binary)
}

fn wallet_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    wallet_fixture_reporting(registry_platform_buildinfo::DISPLAY_VERSION)
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

#[test]
fn wallet_helper_of_another_version_is_refused_before_it_runs() {
    let (generation, binary) = wallet_fixture_reporting("0.0.1-other");
    for action in ["check", "inspect", "openapi", "serve"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
        command
            .env("RSTACK_GENERATION_DIR", generation.path())
            .env("RSTACK_RELEASE_TAG", "v0.44.0")
            .env("RSTACK_EVIDENCE_OID4VCI_BIN", &binary)
            .args(["oid4vci", action]);
        if action != "openapi" {
            command.args(["--runtime-config", "runtime.yaml"]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "{action}: {output:?}");
        assert!(
            output.stdout.is_empty(),
            "the helper must not have run for {action}: {output:?}"
        );
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(
            diagnostic.contains(binary.to_str().unwrap()),
            "{action}: {diagnostic}"
        );
        assert!(diagnostic.contains("0.0.1-other"), "{action}: {diagnostic}");
        assert!(
            diagnostic.contains(registry_platform_buildinfo::DISPLAY_VERSION),
            "{action}: {diagnostic}"
        );
    }
}
