// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REGISTRYCTL_BIN: &str = env!("CARGO_BIN_EXE_registryctl");

fn registryctl_command() -> Command {
    let mut command = Command::new(REGISTRYCTL_BIN);
    command.env("REGISTRYCTL_NO_UPDATE_CHECK", "1");
    command
}

fn run_registryctl(args: &[&str]) -> Output {
    registryctl_command()
        .args(args)
        .output()
        .expect("the exact Cargo-injected registryctl binary runs")
}

fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{action} wrote stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_no_worker_path(output: &Output) {
    let injected = Path::new(REGISTRYCTL_BIN);
    let canonical = std::fs::canonicalize(injected)
        .expect("the Cargo-injected registryctl binary has a canonical path");
    for path in [injected.to_path_buf(), canonical] {
        let path = path
            .to_str()
            .expect("the Cargo-injected registryctl binary path is UTF-8");
        for (stream, bytes) in [
            ("stdout", output.stdout.as_slice()),
            ("stderr", output.stderr.as_slice()),
        ] {
            let rendered = String::from_utf8_lossy(bytes);
            assert!(
                !rendered.contains(path),
                "{stream} exposed the fixture-worker path {path}: {rendered}"
            );
        }
    }
}

fn initialize_http_starter(parent: &Path) -> PathBuf {
    let project = parent.join("registry-project");
    let project_arg = project
        .to_str()
        .expect("temporary project path is valid UTF-8");
    let output = run_registryctl(&["init", "--from", "http", "--project-dir", project_arg]);
    assert_success(&output, "HTTP starter initialization");
    assert_no_worker_path(&output);
    project
}

fn check_http_starter(project: &Path, explain: bool) -> Output {
    let project_arg = project
        .to_str()
        .expect("temporary project path is valid UTF-8");
    let mut args = vec![
        "check",
        "--project-dir",
        project_arg,
        "--environment",
        "local",
    ];
    if explain {
        args.push("--explain");
    }
    let output = run_registryctl(&args);
    assert_success(
        &output,
        if explain {
            "expanded HTTP project check"
        } else {
            "concise HTTP project check"
        },
    );
    assert_no_worker_path(&output);
    output
}

#[test]
fn process_harness_uses_the_exact_cargo_injected_registryctl_binary() {
    let empty_path = tempfile::tempdir().expect("empty PATH directory");
    let mut command = registryctl_command();
    assert_eq!(command.get_program(), std::ffi::OsStr::new(REGISTRYCTL_BIN));
    let output = command
        .arg("--version")
        .env("PATH", empty_path.path())
        .output()
        .expect("the exact Cargo-injected registryctl binary runs without PATH lookup");

    assert_success(&output, "exact-binary identity check");
    assert_no_worker_path(&output);
}

#[test]
fn process_human_check_is_concise_and_explain_adds_review_detail() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialize_http_starter(temporary.path());

    let concise = check_http_starter(&project, false);
    let concise = String::from_utf8(concise.stdout).expect("concise output is UTF-8");
    for heading in [
        "Baseline:",
        "Semantic changes:",
        "Fixtures:",
        "Effective authority and limits:",
        "Rhai xw.v1 reference:",
    ] {
        assert!(concise.contains(heading), "missing {heading}: {concise}");
    }
    assert!(!concise.contains("Services, claims, and disclosure:"));
    assert!(concise.contains("topology: Relay + Notary"));
    assert!(concise.contains("calls=1 call (derived)"));
    assert!(concise.contains("deadline=15s (defaulted)"));
    assert!(!concise.contains("1calls"));
    assert!(!concise.contains("\"15s\"duration"));
    assert!(!concise.contains("subject mismatch not applicable:"));
    assert!(!concise.contains("request fixture:"));

    let expanded = check_http_starter(&project, true);
    let expanded = String::from_utf8(expanded.stdout).expect("expanded output is UTF-8");
    for expected in [
        "operation 1: class=data",
        "Services, claims, and disclosure:",
        "purpose: public-service-person-verification",
        "legal basis: public-service-delivery",
        "consent: not_required",
        "scopes: evidence:person:read",
        "claim person-active: class=consultation_output, disclosure=value",
        "claim person-record-exists: class=registry_backed_evaluation, disclosure=predicate",
        "Redactions:",
    ] {
        assert!(
            expanded.contains(expected),
            "missing {expected}: {expanded}"
        );
    }
    assert!(!expanded.contains("outputs:"));
}

#[test]
fn process_human_check_does_not_emit_classifier_redaction_sentinels() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialize_http_starter(temporary.path());
    let rendered = check_http_starter(&project, true);
    let rendered = String::from_utf8(rendered.stdout).expect("expanded output is UTF-8");

    for forbidden in [
        "FICTIONAL_REGISTRY_TOKEN",
        "https://citizen-registry.invalid",
        "/people/{input.person_id}",
        "/people/{person_id}",
        "/active",
        "person_record.matched",
        "active-person",
        "/run/secrets/relay-workload-token",
        "fictional-registry-notary",
        "The selected response projection contains no identifier",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "classifier-redacted sentinel leaked: {forbidden}: {rendered}"
        );
    }
}
