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

fn assert_strict_project_diagnostics(output: &Output) -> serde_json::Value {
    assert!(
        !output.status.success(),
        "invalid check unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "portable check failure wrote non-JSON stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("check failure emits a JSON document");
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/project-reports/registryctl.project_diagnostics.v1.schema.json"
    ))
    .expect("diagnostics schema parses");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("diagnostics schema compiles");
    if let Err(errors) = validator.validate(&report) {
        panic!(
            "check failure violates the strict diagnostics contract: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    }
    report
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
    assert!(concise.contains("Fixtures: 25/25 passed (offline synthetic)"));
    assert!(concise.contains(
        "Fixture request witnesses: 1/1 independently authored offline request-to-consultation bindings passed; 2 fixture(s) remain mapping-derived."
    ));
    assert!(concise.contains(
        "Fixture proof boundary: independently authored fixture requests exercise offline request-to-consultation bindings; mapping-derived fixtures exercise consultation and source behavior only. External/live caller compatibility is not evaluated."
    ));
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
    let diagnostics = assert_strict_project_diagnostics(&json);
    assert_eq!(diagnostics["status"], "invalid");

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
    let portable: serde_json::Value =
        serde_json::from_str(&portable).expect("portable check report is JSON");
    assert_eq!(
        portable["fixture_coverage"]["governed_request_evidence"],
        "per_consultation_authored_request_witness_evaluation"
    );
    assert_eq!(
        portable["fixture_coverage"]["live_compatibility"],
        "not_evaluated"
    );
    let binding_states = portable["fixture_coverage"]["targets"]
        .as_array()
        .expect("fixture coverage targets are an array")
        .iter()
        .flat_map(|target| {
            target["fixture_inventory"]
                .as_array()
                .expect("fixture inventory is an array")
        })
        .map(|fixture| {
            fixture["request_to_consultation_binding"]["state"]
                .as_str()
                .expect("request binding state is a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        binding_states
            .iter()
            .filter(|state| **state == "passed")
            .count(),
        1
    );
    assert_eq!(
        binding_states
            .iter()
            .filter(|state| **state == "not_authored")
            .count(),
        2
    );
}

#[test]
fn every_portable_check_failure_emits_strict_redacted_diagnostics() {
    const OUTPUT_SENTINEL: &str = "country-output-sentinel";
    const BASELINE_SENTINEL: &str = "country-baseline-path-sentinel";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = initialize_http_starter(temporary.path());
    let project_arg = project
        .to_str()
        .expect("temporary project path is valid UTF-8");
    let project_path = project.join("registry-stack.yaml");
    let authored = std::fs::read_to_string(&project_path).expect("project reads");
    assert!(authored.contains("output: person_record.active"));
    std::fs::write(
        &project_path,
        authored.replace(
            "output: person_record.active",
            &format!("output: person_record.{OUTPUT_SENTINEL}"),
        ),
    )
    .expect("unknown output writes");

    let typed = run_registryctl(&[
        "check",
        "--project-dir",
        project_arg,
        "--environment",
        "local",
        "--format",
        "json",
    ]);
    let typed = assert_strict_project_diagnostics(&typed);
    assert!(typed["diagnostics"].as_array().is_some_and(|diagnostics| {
        diagnostics.iter().any(|diagnostic| {
            diagnostic["addresses"].as_array().is_some_and(|addresses| {
                addresses.iter().any(|address| {
                    address["pointer"]
                        == "/services/person-verification/claims/person-active/output"
                })
            })
        })
    }));
    assert!(
        !typed.to_string().contains(OUTPUT_SENTINEL),
        "typed diagnostics leaked the rejected output name"
    );

    let baseline = temporary.path().join(BASELINE_SENTINEL);
    let fallback = registryctl_command()
        .args([
            "check",
            "--project-dir",
            project_arg,
            "--environment",
            "local",
            "--format",
            "json",
            "--against",
        ])
        .arg(&baseline)
        .output()
        .expect("registryctl fallback check runs");
    let fallback = assert_strict_project_diagnostics(&fallback);
    assert_eq!(
        fallback["diagnostics"][0]["cause"],
        "The offline project check could not complete safely."
    );
    assert!(
        !fallback.to_string().contains(BASELINE_SENTINEL),
        "fallback diagnostics leaked the local baseline path"
    );
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
