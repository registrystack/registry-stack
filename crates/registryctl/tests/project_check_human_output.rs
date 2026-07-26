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

#[test]
fn explicit_trusted_local_check_shows_authored_metadata_but_not_secrets_or_fixtures() {
    const METADATA_SENTINEL: &str = "https://metadata-review-sentinel.invalid";
    const SECRET_SENTINEL: &str = "TRUSTED_LOCAL_SECRET_SENTINEL";
    const ENVIRONMENT_SECRET_VALUE_SENTINEL: &str =
        "TRUSTED_LOCAL_ENVIRONMENT_SECRET_VALUE_SENTINEL";
    const FIXTURE_SENTINEL: &str = "TRUSTED_LOCAL_FIXTURE_SENTINEL";
    const PARSER_SENTINEL: &str = "TRUSTED_LOCAL_PARSER_SENTINEL";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialize_http_starter(temporary.path());
    let environment_path = project.join("environments/local.yaml");
    let environment = std::fs::read_to_string(&environment_path).expect("environment reads");
    std::fs::write(
        &environment_path,
        environment
            .replace("https://citizen-registry.invalid", METADATA_SENTINEL)
            .replace("FICTIONAL_REGISTRY_TOKEN", SECRET_SENTINEL),
    )
    .expect("environment sentinel writes");
    let fixture_path = project.join("integrations/person-record/fixtures/active.yaml");
    let fixture = std::fs::read_to_string(&fixture_path).expect("fixture reads");
    std::fs::write(
        &fixture_path,
        fixture.replace("AB-123456", FIXTURE_SENTINEL),
    )
    .expect("fixture sentinel writes");
    let project_path = project.join("registry-stack.yaml");
    let project_document = std::fs::read_to_string(&project_path).expect("project reads");
    std::fs::write(
        &project_path,
        project_document.replace(
            "cel: person_record.matched",
            &format!(
                "cel: 'person_record.matched && \"{PARSER_SENTINEL}\" == \"{PARSER_SENTINEL}\"'"
            ),
        ),
    )
    .expect("parser sentinel writes");

    let project_arg = project
        .to_str()
        .expect("temporary project path is valid UTF-8");
    let rendered = registryctl_command()
        .args([
            "check",
            "--project-dir",
            project_arg,
            "--environment",
            "local",
            "--explain",
            "--show-authored-values",
        ])
        .env(SECRET_SENTINEL, ENVIRONMENT_SECRET_VALUE_SENTINEL)
        .output()
        .expect("trusted-local HTTP project check runs");
    assert_success(&rendered, "trusted-local HTTP project check");
    assert_no_worker_path(&rendered);
    let rendered = String::from_utf8(rendered.stdout).expect("trusted-local output is UTF-8");
    assert!(rendered.contains(
        "WARNING: trusted-local authored values follow. This output includes project-sensitive metadata and must not be shared."
    ));
    for visible in [
        "fictional-citizen-registry",
        "integrations/person-record/integration.yaml",
        METADATA_SENTINEL,
        "https://relay.internal.invalid",
        "registry-relay",
    ] {
        assert!(
            rendered.contains(visible),
            "trusted-local output omitted useful authored metadata {visible}: {rendered}"
        );
    }
    let always_hidden = [
        SECRET_SENTINEL,
        ENVIRONMENT_SECRET_VALUE_SENTINEL,
        FIXTURE_SENTINEL,
        PARSER_SENTINEL,
        "REGISTRY_NOTARY_ISSUER_JWK",
        "EVIDENCE_CLIENT_TOKEN_HASH",
        "/run/secrets/relay-workload-token",
        "/people/{input.person_id}",
        "person_record.matched",
        "= \"/active\"",
    ];
    for forbidden in always_hidden {
        assert!(
            !rendered.contains(forbidden),
            "trusted-local output leaked prohibited value {forbidden}: {rendered}"
        );
    }

    for (format, extra_args) in [
        ("default human", &["--explain"][..]),
        ("portable JSON", &["--explain", "--format", "json"][..]),
    ] {
        let mut args = vec![
            "check",
            "--project-dir",
            project_arg,
            "--environment",
            "local",
        ];
        args.extend_from_slice(extra_args);
        let output = registryctl_command()
            .args(args)
            .env(SECRET_SENTINEL, ENVIRONMENT_SECRET_VALUE_SENTINEL)
            .output()
            .unwrap_or_else(|error| panic!("{format} project check runs: {error}"));
        assert_success(&output, format);
        assert_no_worker_path(&output);
        let output = String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("{format} output is UTF-8: {error}"));
        for forbidden in [METADATA_SENTINEL].into_iter().chain(always_hidden) {
            assert!(
                !output.contains(forbidden),
                "{format} output leaked redacted value {forbidden}: {output}"
            );
        }
    }
}

#[test]
fn authored_values_require_explicit_explanation_and_human_output() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialize_http_starter(temporary.path());
    let project_arg = project
        .to_str()
        .expect("temporary project path is valid UTF-8");

    let missing_explain = run_registryctl(&[
        "check",
        "--project-dir",
        project_arg,
        "--environment",
        "local",
        "--show-authored-values",
    ]);
    assert!(!missing_explain.status.success());
    assert!(String::from_utf8_lossy(&missing_explain.stderr).contains("--explain"));

    let json = run_registryctl(&[
        "check",
        "--project-dir",
        project_arg,
        "--environment",
        "local",
        "--explain",
        "--show-authored-values",
        "--format",
        "json",
    ]);
    assert!(!json.status.success());
    assert_eq!(
        String::from_utf8_lossy(&json.stderr).trim(),
        "Error: --show-authored-values requires --format human"
    );

    let portable = run_registryctl(&[
        "check",
        "--project-dir",
        project_arg,
        "--environment",
        "local",
        "--format",
        "json",
    ]);
    assert_success(&portable, "portable JSON project check");
    let portable = String::from_utf8(portable.stdout).expect("portable JSON is UTF-8");
    assert!(!portable.contains("trusted-local"));
    assert!(!portable.contains("https://citizen-registry.invalid"));
    assert!(!portable.contains("FICTIONAL_REGISTRY_TOKEN"));
    assert!(!portable.contains("AB-123456"));
}

#[test]
fn trusted_local_library_entry_point_requires_explanation() {
    let error = match registryctl::check_registry_project_with_trusted_local_authored_values(
        &registryctl::ProjectCheckOptions {
            project_directory: PathBuf::from("unused"),
            environment: "local".to_owned(),
            explain: false,
            against: None,
            anchor: None,
        },
    ) {
        Ok(_) => panic!("trusted-local library entry point must require explanation"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "trusted-local authored values require an explanation"
    );
}
