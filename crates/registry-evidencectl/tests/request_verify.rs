use std::{
    fs,
    net::TcpListener,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, SecondsFormat, Utc};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use registry_platform_crypto::PublicJwk;
use serde_json::{json, Value};

#[path = "support/executable.rs"]
mod executable;

const TOKEN: &str = "secret.token.canary";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const BINDING: &str = "urn:evidence:subject:v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn public_help_exposes_only_the_adopter_request_and_verify_inputs() {
    let request = command()
        .args(["request", "prepare", "--help"])
        .output()
        .expect("request help");
    assert_success(&request);
    let request = String::from_utf8_lossy(&request.stdout);
    for visible in [
        "[DEFINITION]",
        "--profile",
        "--requirement",
        "--purpose",
        "--subject",
        "--subjects-file",
        "--name",
        "--evidence-url",
        "--header",
        "--runtime-config",
        "--format",
    ] {
        assert!(request.contains(visible), "missing {visible}: {request}");
    }
    for hidden in ["--project", "--evidence-bin"] {
        assert!(!request.contains(hidden), "test seam leaked: {request}");
    }

    let verify = command()
        .args(["verify", "--help"])
        .output()
        .expect("verify help");
    assert_success(&verify);
    let verify = String::from_utf8_lossy(&verify.stdout);
    for visible in ["<RESPONSE>", "--context", "--output"] {
        assert!(verify.contains(visible), "missing {visible}: {verify}");
    }
    assert!(!verify.contains("--evidence-bin"));

    let nested_verify = command()
        .args(["request", "verify", "--help"])
        .output()
        .expect("nested verify help");
    assert_eq!(nested_verify.status.code(), Some(2));
}

#[test]
fn owner_only_subjects_file_keeps_selector_values_out_of_command_arguments() {
    let fixture = Fixture::new();
    fixture.write_procedure(&[
        "adult-status",
        "--purpose",
        "age-check",
        "--subject",
        "person_id=selector-file-canary",
    ]);
    let subjects = fixture.root.join("subjects.json");
    private_file(
        &subjects,
        br#"{"subjects":[{"role":"person","field":"person_id","value":"selector-file-canary"}]}"#,
        0o600,
    );

    let prepared = command()
        .current_dir(&fixture.root)
        .args([
            "request",
            "prepare",
            "adult-status",
            "--purpose",
            "age-check",
            "--subjects-file",
        ])
        .arg(&subjects)
        .args([
            "--name",
            "subjects-file",
            "--project",
            ".",
            "--evidence-url",
        ])
        .arg(&fixture.server.origin)
        .arg("--header")
        .arg(format!("@{}", fixture.header.display()))
        .arg("--runtime-config")
        .arg(&fixture.runtime)
        .arg("--evidence-bin")
        .arg(&fixture.evidence)
        .output()
        .expect("prepare from subjects file");
    assert_success(&prepared);
    let request: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".evidence/requests/subjects-file/request.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        request["subjects"][0]["selector"]["values"]["person_id"],
        "selector-file-canary"
    );
    assert!(!String::from_utf8_lossy(&prepared.stdout).contains("selector-file-canary"));
    assert!(!String::from_utf8_lossy(&prepared.stderr).contains("selector-file-canary"));
    assert!(
        !fs::read_to_string(fixture.evidence.with_extension("prepare.args"))
            .unwrap()
            .contains("selector-file-canary")
    );

    let unsafe_subjects = fixture.root.join("unsafe-subjects.json");
    private_file(
        &unsafe_subjects,
        br#"{"subjects":[{"role":"person","field":"person_id","value":"unsafe-selector-canary"}]}"#,
        0o644,
    );
    let refused = command()
        .current_dir(&fixture.root)
        .args([
            "request",
            "prepare",
            "adult-status",
            "--purpose",
            "age-check",
            "--subjects-file",
        ])
        .arg(&unsafe_subjects)
        .args([
            "--name",
            "unsafe-subjects-file",
            "--project",
            ".",
            "--evidence-url",
        ])
        .arg(&fixture.server.origin)
        .arg("--header")
        .arg(format!("@{}", fixture.header.display()))
        .arg("--runtime-config")
        .arg(&fixture.runtime)
        .arg("--evidence-bin")
        .arg(&fixture.evidence)
        .output()
        .expect("refuse unsafe subjects file");
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("unsafe-selector-canary"));
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("unsafe-selector-canary"));
}

#[test]
fn prepare_and_verify_delegate_exactly_and_publish_only_safe_artifacts() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare("first-assertion");
    assert_success(&prepared);
    assert_eq!(
        String::from_utf8_lossy(&prepared.stdout),
        "Prepared request: .evidence/requests/first-assertion/request.json\n\
         Prepared verification context: .evidence/requests/first-assertion/verification.json\n\
         Prepared authorization: .evidence/requests/first-assertion/authorization.curl\n"
    );

    let retained = fixture.root.join(".evidence/requests/first-assertion");
    assert_mode(&fixture.root.join(".evidence/requests"), 0o700);
    assert_mode(&retained, 0o700);
    assert_eq!(
        sorted_names(&retained),
        ["authorization.curl", "request.json", "verification.json"]
    );
    for name in ["authorization.curl", "request.json", "verification.json"] {
        assert_mode(&retained.join(name), 0o600);
    }

    let request_bytes = fs::read(retained.join("request.json")).expect("request");
    let request: Value = serde_json::from_slice(&request_bytes).expect("request JSON");
    assert_eq!(
        request,
        json!({
            "requestNonce": request["requestNonce"],
            "requirement": "urn:registrystack:evidence:local:requirement:adult-status",
            "expectedConfigurationRevision": format!("sha256:{}", "0".repeat(64)),
            "purpose": "age-check",
            "subjects": [{
                "role": "person",
                "selector": {
                    "profile": "local-subject-adult-status-v1",
                    "values": {"person_id": "person-123"}
                }
            }]
        })
    );
    let nonce = request["requestNonce"].as_str().expect("nonce");
    assert_eq!(nonce.len(), 43);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(nonce)
            .expect("canonical nonce")
            .len(),
        32
    );
    let context: Value = serde_json::from_slice(
        &fs::read(retained.join("verification.json")).expect("verification context"),
    )
    .expect("verification context JSON");
    assert_eq!(
        context["schema"],
        "registry.evidence-client.retained-verification/v1"
    );
    assert_eq!(context["responseFormat"], "signed-jws");
    assert_eq!(
        context["verificationPolicy"]["requestNonce"],
        request["requestNonce"]
    );
    assert_eq!(context["subjectExpectation"]["mode"], "pinned");
    assert_eq!(
        fs::read_to_string(retained.join("authorization.curl")).unwrap(),
        format!("header = \"Authorization: Bearer {TOKEN}\"\n")
    );

    assert!(fixture.server.request_count() >= 1);
    let evidence_args = fs::read_to_string(fixture.evidence.with_extension("prepare.args"))
        .expect("Evidence prepare argv");
    let evidence_args = evidence_args.lines().collect::<Vec<_>>();
    assert_eq!(evidence_args[0], "prepare-local-relying-procedure");
    assert_eq!(evidence_args[1], "--runtime-config");
    assert_eq!(evidence_args[3], "--input");
    assert!(evidence_args[4].ends_with("/procedure-input.json"));
    assert_eq!(&evidence_args[5..], ["--posture", "production"]);
    assert!(!evidence_args.join(" ").contains(TOKEN));
    assert_eq!(
        fs::read_to_string(fixture.evidence.with_extension("prepare.stdin")).unwrap(),
        "stdin-empty\n"
    );
    let procedure_input: Value =
        serde_json::from_slice(&fs::read(fixture.evidence.with_extension("input")).unwrap())
            .unwrap();
    assert_eq!(
        procedure_input["schema"],
        "registry.evidence.local-relying-procedure-input/v1"
    );
    assert_eq!(procedure_input["responseFormat"], "signed-jws");
    assert_eq!(
        procedure_input["audience"],
        "urn:registrystack:evidence:local:caller"
    );
    assert!(procedure_input.get("requestNonce").is_none());
    for non_secret in [
        &request_bytes,
        fs::read(retained.join("verification.json"))
            .unwrap()
            .as_slice(),
        &prepared.stdout,
        &prepared.stderr,
    ] {
        assert!(!String::from_utf8_lossy(non_secret).contains(TOKEN));
    }

    let second = fixture.prepare("second-assertion");
    assert_success(&second);
    let second: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".evidence/requests/second-assertion/request.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(request["requestNonce"], second["requestNonce"]);

    let sd_jwt = fixture.prepare_with(
        &[
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
            "--format",
            "sd-jwt-vc",
        ],
        "sd-jwt-assertion",
    );
    assert_success(&sd_jwt);
    let sd_jwt_context: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".evidence/requests/sd-jwt-assertion/verification.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(sd_jwt_context["responseFormat"], "sd-jwt-vc");

    let age = fixture.prepare_with(
        &[
            "age-bracket",
            "--purpose",
            "service-path-selection",
            "--subject",
            "person_id=person-123",
        ],
        "age-bracket",
    );
    assert_success(&age);
    let age: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".evidence/requests/age-bracket/request.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        age["requirement"],
        "urn:registrystack:evidence:local:requirement:age-bracket"
    );
    assert_eq!(age["purpose"], "service-path-selection");
    assert_eq!(
        age["subjects"][0]["selector"]["profile"],
        "local-subject-age-bracket-v1"
    );

    fixture.write_signed_adult_response();
    let verified = fixture.verify("verified.json");
    assert_success(&verified);
    assert_eq!(verified.stdout, b"VERIFIED\n");
    let verified_path = fixture.root.join("verified.json");
    assert_mode(&verified_path, 0o600);
    let verified_payload: Value =
        serde_json::from_slice(&fs::read(&verified_path).unwrap()).unwrap();
    assert_eq!(verified_payload["purpose"], "age-check");
    assert_eq!(verified_payload["supportedValues"][0]["value"], true);
    assert!(!fixture.evidence.with_extension("verify.args").exists());

    let refused = fixture.verify("verified.json");
    assert!(!refused.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&verified_path).unwrap()).unwrap(),
        verified_payload
    );
}

#[test]
fn request_prepare_forwards_flag_environment_and_default_posture() {
    let fixture = Fixture::new();
    let inputs = [
        "adult-status",
        "--purpose",
        "age-check",
        "--subject",
        "person_id=person-123",
    ];
    for (mode, expected) in [
        ("flag", "development"),
        ("environment", "development"),
        ("default", "production"),
    ] {
        let output = fixture.prepare_with_posture(&inputs, mode, mode);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let args = fs::read_to_string(fixture.evidence.with_extension("prepare.args")).unwrap();
        assert!(
            args.ends_with(&format!("--posture\n{expected}\n")),
            "{args}"
        );
    }
}

#[test]
fn request_prepare_applies_its_posture_to_marked_discovery() {
    let fixture = Fixture::new();
    fixture.server.development.store(true, Ordering::Relaxed);
    let refused = fixture.prepare("production");
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("Evidence definition discovery failed")
    );
    assert_no_request_artifacts(&fixture.root, "production");
    let accepted = fixture.prepare_with_posture(
        &[
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
        ],
        "development",
        "flag",
    );
    assert_success(&accepted);
}

#[test]
fn request_prepare_preserves_value_free_posture_refusal_from_the_runtime() {
    let fixture = Fixture::new();
    fs::write(
        fixture.evidence.with_extension("posture-refusal"),
        serde_json::json!({
            "ok": false,
            "diagnostics": [{
                "code": "evidence.posture.local-assurance",
                "severity": "error",
                "path": "/assuranceProfile",
                "message": "local assurance is accepted only in development",
                "suggestedAction": "Use rstack dev or REGISTRY_STACK_POSTURE=development."
            }]
        })
        .to_string(),
    )
    .unwrap();
    let output = fixture.prepare("refused-posture");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "evidence.posture.local-assurance",
        "/assuranceProfile",
        "REGISTRY_STACK_POSTURE=development",
    ] {
        assert!(stderr.contains(expected), "{stderr}");
    }
    assert_no_request_artifacts(&fixture.root, "refused-posture");
}

#[test]
fn request_prepare_uses_the_given_header_file() {
    let fixture = Fixture::new();
    fixture.write_procedure(&[
        "adult-status",
        "--purpose",
        "age-check",
        "--subject",
        "person_id=person-123",
    ]);
    let other = fixture.root.join("other-headers");
    private_file(
        &other,
        format!("Authorization: Bearer {TOKEN}\n").as_bytes(),
        0o600,
    );
    let prepared = command()
        .current_dir(&fixture.root)
        .args([
            "request",
            "prepare",
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
            "--name",
            "header-file",
            "--project",
            ".",
            "--evidence-url",
        ])
        .arg(&fixture.server.origin)
        .arg("--header")
        .arg(format!("@{}", other.display()))
        .arg("--runtime-config")
        .arg(&fixture.runtime)
        .arg("--evidence-bin")
        .arg(&fixture.evidence)
        .output()
        .expect("prepare with a header file");
    assert_success(&prepared);
    assert!(fixture.server.request_count() >= 1);
    assert_eq!(
        fs::read_to_string(
            fixture
                .root
                .join(".evidence/requests/header-file/authorization.curl")
        )
        .unwrap(),
        format!("header = \"Authorization: Bearer {TOKEN}\"\n")
    );

    let wrong = fixture.root.join("wrong-headers");
    private_file(&wrong, b"Authorization: Bearer some.other.token\n", 0o600);
    let refused = command()
        .current_dir(&fixture.root)
        .args([
            "request",
            "prepare",
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
            "--name",
            "wrong-header",
            "--project",
            ".",
            "--evidence-url",
        ])
        .arg(&fixture.server.origin)
        .arg("--header")
        .arg(format!("@{}", wrong.display()))
        .arg("--runtime-config")
        .arg(&fixture.runtime)
        .arg("--evidence-bin")
        .arg(&fixture.evidence)
        .output()
        .expect("prepare with a refused header");
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("some.other.token"));
    assert!(!fixture
        .root
        .join(".evidence/requests/wrong-header")
        .exists());
}

#[test]
fn failed_preparations_publish_nothing() {
    let fixture = Fixture::new();

    fixture.server.refuse();
    let refused = fixture.prepare("refused-discovery");
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stderr).contains(TOKEN));
    assert_no_request_artifacts(&fixture.root, "refused-discovery");
}

#[test]
fn a_failed_relying_procedure_cleans_staging() {
    let fixture = Fixture::new();
    fs::write(fixture.evidence.with_extension("fail-prepare"), b"").unwrap();
    let failed = fixture.prepare("failed-procedure");
    assert!(!failed.status.success());
    assert_no_request_artifacts(&fixture.root, "failed-procedure");
}

#[test]
fn the_header_must_be_an_owner_only_bearer_file() {
    let fixture = Fixture::new();
    for (name, contents, mode) in [
        ("open", format!("Authorization: Bearer {TOKEN}\n"), 0o644),
        ("other", format!("X-Token: {TOKEN}\n"), 0o600),
        (
            "two",
            format!("Authorization: Bearer {TOKEN}\nX-Extra: 1\n"),
            0o600,
        ),
        ("empty", String::new(), 0o600),
    ] {
        let path = fixture.root.join(name);
        private_file(&path, contents.as_bytes(), mode);
        let refused = command()
            .current_dir(&fixture.root)
            .args([
                "request",
                "prepare",
                "adult-status",
                "--purpose",
                "age-check",
                "--subject",
                "person_id=person-123",
                "--name",
                "refused-header",
                "--project",
                ".",
                "--evidence-url",
            ])
            .arg(&fixture.server.origin)
            .arg("--header")
            .arg(format!("@{}", path.display()))
            .arg("--runtime-config")
            .arg(&fixture.runtime)
            .output()
            .expect("prepare with an unusable header file");
        assert!(!refused.status.success(), "{name}");
        assert!(!String::from_utf8_lossy(&refused.stderr).contains(TOKEN));
        assert_no_request_artifacts(&fixture.root, "refused-header");
    }
    assert_eq!(fixture.server.request_count(), 0);

    let inline = command()
        .current_dir(&fixture.root)
        .args([
            "request",
            "prepare",
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
            "--name",
            "inline-header",
            "--evidence-url",
        ])
        .arg(&fixture.server.origin)
        .args(["--header", &format!("Authorization: Bearer {TOKEN}")])
        .arg("--runtime-config")
        .arg(&fixture.runtime)
        .output()
        .expect("prepare with an inline header");
    assert!(!inline.status.success());
    assert!(!String::from_utf8_lossy(&inline.stderr).contains(TOKEN));
}

#[test]
fn multi_subject_prepare_requires_the_exact_role_set_and_emits_declaration_order() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare_with(
        &[
            "relationship-check",
            "--purpose",
            "relationship-review",
            "--subject",
            "candidate:person_reference=person-456",
            "--subject",
            "child:child_reference=child-123",
        ],
        "relationship",
    );
    assert_success(&prepared);
    let request: Value = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join(".evidence/requests/relationship/request.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        request["subjects"],
        json!([
            {
                "role": "child",
                "selector": {
                    "profile": "child-reference-v1",
                    "values": {"child_reference": "child-123"}
                }
            },
            {
                "role": "candidate",
                "selector": {
                    "profile": "person-reference-v1",
                    "values": {"person_reference": "person-456"}
                }
            }
        ])
    );

    for (name, inputs) in [
        (
            "missing",
            vec![
                "relationship-check",
                "--purpose",
                "relationship-review",
                "--subject",
                "child:child_reference=child-123",
            ],
        ),
        (
            "duplicate",
            vec![
                "relationship-check",
                "--purpose",
                "relationship-review",
                "--subject",
                "child:child_reference=child-123",
                "--subject",
                "child:child_reference=child-456",
            ],
        ),
        (
            "wrong-field",
            vec![
                "relationship-check",
                "--purpose",
                "relationship-review",
                "--subject",
                "child:person_reference=child-123",
                "--subject",
                "candidate:child_reference=person-456",
            ],
        ),
    ] {
        let refused = fixture.prepare_with(&inputs, name);
        assert!(!refused.status.success(), "{name} role set must fail");
        assert!(!fixture.root.join(".evidence/requests").join(name).exists());
    }
}

#[test]
fn request_inputs_are_exact_and_every_failed_preparation_cleans_staging() {
    for arguments in [
        vec![
            "other",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
        ],
        vec![
            "adult-status",
            "--purpose",
            "other",
            "--subject",
            "person_id=person-123",
        ],
        vec![
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "other=person-123",
        ],
        vec![
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=",
        ],
        vec![
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=a=b",
        ],
    ] {
        let fixture = Fixture::new();
        let output = fixture.prepare_with(&arguments, "first-assertion");
        assert!(!output.status.success(), "{arguments:?}");
        assert!(!fixture
            .root
            .join(".evidence/requests/first-assertion")
            .exists());
    }

    let fixture = Fixture::new();
    fs::write(fixture.evidence.with_extension("fail-prepare"), b"").unwrap();
    let failed = fixture.prepare("first-assertion");
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains(TOKEN));
    let requests = fixture.root.join(".evidence/requests");
    assert_eq!(sorted_names(&requests), Vec::<String>::new());

    let existing = Fixture::new();
    let target = existing.root.join(".evidence/requests/first-assertion");
    fs::create_dir_all(&target).unwrap();
    fs::set_permissions(target.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(target.join("canary"), b"keep").unwrap();
    let failed = existing.prepare("first-assertion");
    assert!(!failed.status.success());
    assert_eq!(fs::read(target.join("canary")).unwrap(), b"keep");
}

#[test]
fn unsafe_request_and_verify_paths_are_refused_without_clobbering() {
    let public = Fixture::new();
    let requests = public.root.join(".evidence/requests");
    fs::create_dir(&requests).unwrap();
    fs::set_permissions(&requests, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!public.prepare("first-assertion").status.success());

    let linked = Fixture::new();
    let target = linked.root.join("request-target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target, linked.root.join(".evidence/requests")).unwrap();
    assert!(!linked.prepare("first-assertion").status.success());
    assert!(sorted_names(&target).is_empty());

    let verify = Fixture::new();
    fs::write(verify.root.join("assertion.jws.json"), b"response").unwrap();
    let destination = verify.root.join("verified.json");
    let canary = verify.root.join("canary");
    fs::write(&canary, b"keep").unwrap();
    symlink(&canary, &destination).unwrap();
    assert!(!verify.verify("verified.json").status.success());
    assert_eq!(fs::read(&canary).unwrap(), b"keep");

    fs::remove_file(destination).unwrap();
    let target = verify.root.join("output-target");
    fs::create_dir(&target).unwrap();
    let linked_parent = verify.root.join("linked-output");
    symlink(&target, &linked_parent).unwrap();
    let output = verify.verify("linked-output/verified.json");
    assert!(!output.status.success());
    assert!(sorted_names(&target).is_empty());
}

#[test]
fn failed_client_verification_removes_the_unpublished_output() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("assertion.jws.json"), b"response").unwrap();
    let output = fixture.verify("verified.json");
    assert!(!output.status.success());
    assert!(!fixture.root.join("verified.json").exists());
    assert!(sorted_names(&fixture.root)
        .iter()
        .all(|name| !name.starts_with(".verify-")));
}

/// A stand-in for a running Registry Evidence: it answers the discovery route
/// for the one bearer in the header file and refuses everything else.
struct EvidenceServer {
    origin: String,
    refuse: Arc<AtomicBool>,
    development: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct EvidenceServerState {
    refuse: Arc<AtomicBool>,
    development: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
}

impl EvidenceServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Evidence listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking Evidence listener");
        let origin = format!(
            "http://{}",
            listener.local_addr().expect("Evidence address")
        );
        let refuse = Arc::new(AtomicBool::new(false));
        let development = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let state = EvidenceServerState {
            refuse: Arc::clone(&refuse),
            development: Arc::clone(&development),
            requests: Arc::clone(&requests),
        };
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Evidence runtime")
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener)
                        .expect("async Evidence listener");
                    let app = Router::new()
                        .route("/v1/evidence-definitions", get(test_definitions))
                        .with_state(state);
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .expect("test Evidence server");
                });
        });
        Self {
            origin,
            refuse,
            development,
            requests,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    fn refuse(&self) {
        self.refuse.store(true, Ordering::Relaxed);
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

async fn test_definitions(
    State(state): State<EvidenceServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    state.requests.fetch_add(1, Ordering::Relaxed);
    if state.refuse.load(Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let expected = format!("Bearer {TOKEN}");
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(expected.as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut response =
        ([("traceparent", TRACEPARENT)], Json(definitions_document())).into_response();
    if state.development.load(Ordering::Relaxed) {
        response
            .headers_mut()
            .insert("registry-posture", "development".parse().unwrap());
    }
    response
}

impl Drop for EvidenceServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().expect("Evidence server thread");
        }
    }
}

fn definitions_document() -> Value {
    let definition = |handle: &str,
                      purpose: &str,
                      subjects: Vec<(&str, &str, &str)>,
                      concept: (&str, Value)| {
        json!({
            "handle": handle,
            "requirement": format!("urn:registrystack:evidence:local:requirement:{handle}"),
            "configurationRevision": format!("sha256:{}", "0".repeat(64)),
            "kind": "criterion",
            "evidenceType": format!("urn:registrystack:evidence:local:evidence-type:{handle}"),
            "purpose": purpose,
            "responseFormats": ["signed-jws", "sd-jwt-vc"],
            "referenceFrameworks": ["urn:registrystack:evidence:local:framework:test"],
            "subjects": subjects.into_iter().map(|(role, profile, field)| json!({
                "role": role,
                "cardinality": "one",
                "selector": {
                    "profile": profile,
                    "valueOrigin": "request",
                    "fields": [{"type": "string", "name": field, "minimumBytes": 1, "maximumBytes": 200}]
                }
            })).collect::<Vec<_>>(),
            "concepts": [{
                "handle": concept.0,
                "concept": format!("urn:registrystack:evidence:local:concept:{handle}:{}", concept.0),
                "required": true,
                "form": concept.1
            }]
        })
    };
    json!({
        "schema": "registry.evidence-definitions/v1",
        "assuranceProfile": "local",
        "audience": "urn:registrystack:evidence:local:caller",
        "issuedBy": "urn:registrystack:evidence:local:issuer",
        "providedBy": "urn:registrystack:evidence:local:provider",
        "definitions": [
            definition(
                "adult-status",
                "age-check",
                vec![("person", "local-subject-adult-status-v1", "person_id")],
                ("is_adult", json!({"type": "boolean"})),
            ),
            definition(
                "age-bracket",
                "service-path-selection",
                vec![("person", "local-subject-age-bracket-v1", "person_id")],
                ("age_bracket", json!({"type": "boolean"})),
            ),
            definition(
                "relationship-check",
                "relationship-review",
                vec![
                    ("child", "child-reference-v1", "child_reference"),
                    ("candidate", "person-reference-v1", "person_reference"),
                ],
                ("relationship_confirmed", json!({"type": "boolean"})),
            ),
        ]
    })
}

struct Fixture {
    _temporary: tempfile::TempDir,
    server: EvidenceServer,
    root: PathBuf,
    header: PathBuf,
    runtime: PathBuf,
    evidence: PathBuf,
    signing_key: SigningKey,
    signing_jwk: Value,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("project");
        private_directory(&root);
        private_directory(&root.join(".evidence"));
        let header = temporary.path().join("headers");
        private_file(
            &header,
            format!("Authorization: Bearer {TOKEN}\n").as_bytes(),
            0o600,
        );
        let runtime = temporary.path().join("evidence.yaml");
        private_file(&runtime, b"runtime", 0o400);
        let server = EvidenceServer::start();

        let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("test signing key");
        let point = signing_key.verifying_key().to_sec1_point(false);
        let mut signing_jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate")),
        });
        let public = PublicJwk::parse(&serde_json::to_string(&signing_jwk).unwrap())
            .expect("test public JWK");
        signing_jwk["kid"] = Value::String(public.jkt().expect("test key thumbprint"));
        let evidence = temporary.path().join("evidence-stub");
        executable(
            &evidence,
            b"#!/bin/sh\ncase \"$1\" in\n  prepare-local-relying-procedure)\n    printf '%s\\n' \"$@\" > \"$0.prepare.args\"\n    [ \"$2\" = '--runtime-config' ] || exit 40\n    [ \"$4\" = '--input' ] || exit 41\n    cp \"$5\" \"$0.input\" || exit 42\n    if IFS= read -r unexpected; then exit 43; fi\n    printf 'stdin-empty\\n' > \"$0.prepare.stdin\"\n    [ ! -f \"$0.fail-prepare\" ] || exit 44\n    if [ -f \"$0.posture-refusal\" ]; then cat \"$0.posture-refusal\"; exit 1; fi\n    cat \"$0.procedure\"\n    ;;\n  *) exit 45 ;;\nesac\n",
        );
        executable::wait_until_executable_with(&evidence, "probe");
        Self {
            _temporary: temporary,
            server,
            root,
            header,
            runtime,
            evidence,
            signing_key,
            signing_jwk,
        }
    }

    fn write_procedure(&self, inputs: &[&str]) {
        let question = inputs[0];
        let (requirement, purpose, evidence_type, outputs, roles) = match question {
            "adult-status" => (
                "urn:registrystack:evidence:local:requirement:adult-status",
                "age-check",
                "urn:registrystack:evidence:local:evidence-type:adult-status",
                json!([{
                    "handle": "is_adult",
                    "concept": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
                    "form": {"type": "boolean"},
                    "required": true
                }]),
                vec!["person"],
            ),
            "age-bracket" => (
                "urn:registrystack:evidence:local:requirement:age-bracket",
                "service-path-selection",
                "urn:registrystack:evidence:local:evidence-type:age-bracket",
                json!([{
                    "handle": "age_bracket",
                    "concept": "urn:registrystack:evidence:local:concept:age-bracket:age_bracket",
                    "form": {"type": "string"},
                    "required": true
                }]),
                vec!["person"],
            ),
            "relationship-check" => (
                "urn:registrystack:evidence:local:requirement:relationship-check",
                "relationship-review",
                "urn:registrystack:evidence:local:evidence-type:relationship-check",
                json!([{
                    "handle": "relationship_confirmed",
                    "concept": "urn:registrystack:evidence:local:concept:relationship-check:relationship_confirmed",
                    "form": {"type": "boolean"},
                    "required": true
                }]),
                vec!["child", "candidate"],
            ),
            _ => (
                "urn:registrystack:evidence:local:requirement:other",
                "other",
                "urn:registrystack:evidence:local:evidence-type:other",
                json!([{"handle": "other", "concept": "urn:other", "form": {"type": "boolean"}, "required": true}]),
                vec!["person"],
            ),
        };
        let audience = "urn:registrystack:evidence:local:caller".to_owned();
        let response_format = inputs
            .windows(2)
            .find(|pair| pair[0] == "--format")
            .map_or("signed-jws", |pair| pair[1]);
        let expected_subjects = roles
            .into_iter()
            .map(|role| json!({"role": role, "binding": BINDING}))
            .collect::<Vec<_>>();
        let procedure = json!({
            "schema": "registry.evidence.local-relying-procedure/v1",
            "responseFormat": response_format,
            "trustedJwks": {"keys": [self.signing_jwk.clone()]},
            "expectedAssuranceProfile": "local",
            "issuedBy": "urn:registrystack:evidence:local:issuer",
            "providedBy": "urn:registrystack:evidence:local:provider",
            "requirement": requirement,
            "evidenceType": evidence_type,
            "purpose": purpose,
            "audience": audience,
            "configurationRevision": format!("sha256:{}", "0".repeat(64)),
            "expectedSubjects": expected_subjects,
            "expectedOutputs": outputs,
            "revokedKeyIds": [],
            "maximumAssertionLifetimeSeconds": 300,
            "clockSkewSeconds": 30
        });
        fs::write(
            self.evidence.with_extension("procedure"),
            serde_json::to_vec(&procedure).unwrap(),
        )
        .unwrap();
    }

    fn prepare(&self, name: &str) -> Output {
        self.prepare_with(
            &[
                "adult-status",
                "--purpose",
                "age-check",
                "--subject",
                "person_id=person-123",
            ],
            name,
        )
    }

    fn prepare_with(&self, inputs: &[&str], name: &str) -> Output {
        self.prepare_with_posture(inputs, name, "default")
    }

    fn prepare_with_posture(&self, inputs: &[&str], name: &str, mode: &str) -> Output {
        self.write_procedure(inputs);
        let mut command = command();
        command
            .current_dir(&self.root)
            .args(["request", "prepare"])
            .args(inputs)
            .args(["--name", name, "--project", ".", "--evidence-url"])
            .arg(&self.server.origin)
            .arg("--header")
            .arg(format!("@{}", self.header.display()))
            .arg("--runtime-config")
            .arg(&self.runtime)
            .arg("--evidence-bin")
            .arg(&self.evidence);
        if mode == "flag" {
            command.args(["--posture", "development"]);
        } else if mode == "environment" {
            command.env("REGISTRY_STACK_POSTURE", "development");
        }
        command.output().expect("prepare command")
    }

    fn write_signed_adult_response(&self) {
        let request: Value = serde_json::from_slice(
            &fs::read(
                self.root
                    .join(".evidence/requests/first-assertion/request.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let issued_at = Utc::now() - Duration::seconds(5);
        let payload = json!({
            "schema": "registry.assertion-evidence/v1",
            "assuranceProfile": "local",
            "subjectBinding": "audience-scoped",
            "channel": "source",
            "requestNonce": request["requestNonce"],
            "id": "urn:registrystack:evidence:local:assertion:00000000-0000-4000-8000-000000000001",
            "type": "Evidence",
            "supportsRequirement": "urn:registrystack:evidence:local:requirement:adult-status",
            "isConformantTo": "urn:registrystack:evidence:local:evidence-type:adult-status",
            "issuedBy": "urn:registrystack:evidence:local:issuer",
            "providedBy": "urn:registrystack:evidence:local:provider",
            "issuedAt": issued_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "observedAt": issued_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            "validUntil": (issued_at + Duration::seconds(300)).to_rfc3339_opts(SecondsFormat::Secs, true),
            "purpose": "age-check",
            "audience": "urn:registrystack:evidence:local:caller",
            "configurationRevision": format!("sha256:{}", "0".repeat(64)),
            "subjects": [{"role": "person", "binding": BINDING}],
            "supportedValues": [{
                "providesValueFor": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
                "value": true
            }]
        });
        let kid = self.signing_jwk["kid"].as_str().unwrap();
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "ES256",
                "kid": kid,
                "typ": "evidence+jws",
                "cty": "application/evidence+json"
            }))
            .unwrap(),
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signature: Signature = self
            .signing_key
            .sign(format!("{protected}.{payload}").as_bytes());
        let jws = json!({
            "protected": protected,
            "payload": payload,
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes())
        });
        fs::write(
            self.root.join("assertion.jws.json"),
            serde_json::to_vec(&jws).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            self.root.join("assertion.jws.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }

    fn verify(&self, output: &str) -> Output {
        command()
            .current_dir(&self.root)
            .args([
                "verify",
                "assertion.jws.json",
                "--context",
                ".evidence/requests/first-assertion/verification.json",
                "--output",
                output,
            ])
            .output()
            .expect("verify command")
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_evidencectl"));
    command.env_remove("REGISTRY_STACK_POSTURE");
    command
}

fn private_directory(path: &Path) {
    fs::create_dir(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, contents: &[u8], mode: u32) {
    fs::write(path, contents).expect("private file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn executable(path: &Path, contents: &[u8]) {
    private_file(path, contents, 0o700);
}

fn assert_mode(path: &Path, expected: u32) {
    let mode = fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, expected, "{}", path.display());
}

fn sorted_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn assert_no_request_artifacts(project: &Path, name: &str) {
    let requests = project.join(".evidence/requests");
    assert!(!requests.join(name).exists());
    if requests.exists() {
        assert_eq!(sorted_names(&requests), Vec::<String>::new());
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
