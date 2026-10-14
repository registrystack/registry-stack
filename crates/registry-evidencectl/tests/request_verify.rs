use std::{
    fs,
    net::TcpListener,
    os::unix::{
        fs::{symlink, PermissionsExt as _},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, SecondsFormat, Utc};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use registry_platform_crypto::PublicJwk;
use serde_json::{json, Value};

const TOKEN: &str = "secret.token.canary";
const BINDING: &str = "urn:evidence:subject:v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const AGE_CHECKS_TAG: &str = "age-checks";

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
        "--client",
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
            "--evidence-bin",
        ])
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
            "--evidence-bin",
        ])
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

    assert!(fixture.token_server.request_count() >= 1);
    let evidence_args = fs::read_to_string(fixture.evidence.with_extension("prepare.args"))
        .expect("Evidence prepare argv");
    let evidence_args = evidence_args.lines().collect::<Vec<_>>();
    assert_eq!(evidence_args[0], "prepare-local-relying-procedure");
    assert_eq!(evidence_args[1], "--runtime-config");
    assert_eq!(evidence_args[3], "--input");
    assert!(evidence_args[4].ends_with("/procedure-input.json"));
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
fn named_client_prepare_uses_the_registered_identity() {
    let fixture = Fixture::new();
    fixture.add_named_client("age-checker", "active", 0o600);
    fixture.use_explicit_access();

    let prepared = fixture.prepare_as("age-checker", "named-client");
    assert_success(&prepared);
    assert!(fixture.token_server.request_count() >= 1);
    assert!(fixture
        .root
        .join(".evidence/requests/named-client/request.json")
        .is_file());

    let unentitled = fixture.prepare_with(
        &[
            "age-bracket",
            "--purpose",
            "service-path-selection",
            "--subject",
            "person_id=person-456",
            "--client",
            "age-checker",
        ],
        "unentitled-question",
    );
    assert_success(&unentitled);
    let input: Value =
        serde_json::from_slice(&fs::read(fixture.evidence.with_extension("input")).unwrap())
            .unwrap();
    assert_eq!(
        input["audience"],
        "urn:registrystack:evidence:local:client:age-checker"
    );
    assert!(fixture
        .root
        .join(".evidence/requests/unentitled-question/verification.json")
        .is_file());
}

#[test]
fn unusable_named_clients_and_issuer_refusal_publish_no_request_artifacts() {
    let unknown = Fixture::new();
    unknown.add_named_client("other-client", "active", 0o600);
    unknown.use_explicit_access();
    let output = unknown.prepare_as("unknown-client", "unknown-client");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "evidencectl: unknown or revoked active client unknown-client\n"
    );
    assert_no_request_artifacts(&unknown.root, "unknown-client");

    let revoked = Fixture::new();
    revoked.add_named_client("other-client", "active", 0o600);
    revoked.add_named_client("revoked-client", "revoked", 0o600);
    revoked.use_explicit_access();
    let output = revoked.prepare_as("revoked-client", "revoked-client");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "evidencectl: unknown or revoked active client revoked-client\n"
    );
    assert_no_request_artifacts(&revoked.root, "revoked-client");

    let unsafe_key = Fixture::new();
    unsafe_key.add_named_client("unsafe-client", "active", 0o644);
    unsafe_key.use_explicit_access();
    let output = unsafe_key.prepare_as("unsafe-client", "unsafe-client");
    assert!(!output.status.success());
    assert_no_request_artifacts(&unsafe_key.root, "unsafe-client");

    let missing_key = Fixture::new();
    missing_key.add_named_client("missing-key-client", "active", 0o600);
    missing_key.use_explicit_access();
    fs::remove_dir_all(
        missing_key
            .root
            .join(".evidence/clients/missing-key-client"),
    )
    .unwrap();
    let output = missing_key.prepare_as("missing-key-client", "missing-key-client");
    assert!(!output.status.success());
    assert_no_request_artifacts(&missing_key.root, "missing-key-client");

    let mismatched_key = Fixture::new();
    mismatched_key.add_named_client("mismatched-key-client", "active", 0o600);
    mismatched_key.use_explicit_access();
    let registration = mismatched_key
        .root
        .join("access/clients/mismatched-key-client.yaml");
    let text = fs::read_to_string(&registration).unwrap().replace(
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    fs::write(&registration, text).unwrap();
    let output = mismatched_key.prepare_as("mismatched-key-client", "mismatched-key-client");
    assert!(!output.status.success());
    assert_no_request_artifacts(&mismatched_key.root, "mismatched-key-client");

    let refused = Fixture::new();
    refused.add_named_client("refused-client", "active", 0o600);
    refused.use_explicit_access();
    refused.token_server.refuse();
    let output = refused.prepare_as("refused-client", "refused-client");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    assert!(String::from_utf8_lossy(&output.stderr).contains("local issuer declined"));
    assert_no_request_artifacts(&refused.root, "refused-client");
}

#[test]
fn selected_clients_require_an_explicit_current_authority_generation() {
    let implicit = Fixture::new();
    implicit.add_named_client("age-checker", "active", 0o600);
    let output = implicit.prepare_as("age-checker", "implicit-client");
    assert!(!output.status.success());
    assert_no_request_artifacts(&implicit.root, "implicit-client");

    let explicit = Fixture::new();
    explicit.add_named_client("age-checker", "active", 0o600);
    explicit.use_explicit_access();
    let output = explicit.prepare("missing-client");
    assert!(!output.status.success());
    assert_no_request_artifacts(&explicit.root, "missing-client");

    let authority_path = explicit.root.join("dev-authority.yaml");
    let mut authority: Value = serde_json::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
    let state: Value =
        serde_json::from_slice(&fs::read(explicit.root.join(".evidence/dev/state.json")).unwrap())
            .unwrap();
    authority["accessProfiles"]["age-checks"] = authored_profile(
        state["definitions"].as_array().unwrap(),
        &["adult-status".to_owned(), "age-bracket".to_owned()],
        AGE_CHECKS_TAG,
    );
    fs::write(&authority_path, serde_json::to_vec(&authority).unwrap()).unwrap();
    let output = explicit.prepare_as("age-checker", "drifted-authority");
    assert!(!output.status.success());
    assert_no_request_artifacts(&explicit.root, "drifted-authority");
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

struct TokenServer {
    address: std::net::SocketAddr,
    refuse: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct TokenServerState {
    refuse: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
}

impl TokenServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("token endpoint");
        listener
            .set_nonblocking(true)
            .expect("nonblocking token endpoint");
        let address = listener.local_addr().expect("token endpoint address");
        let refuse = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let state = TokenServerState {
            refuse: Arc::clone(&refuse),
            requests: Arc::clone(&requests),
        };
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("token runtime")
                .block_on(async move {
                    let listener =
                        tokio::net::TcpListener::from_std(listener).expect("async token listener");
                    let app = Router::new()
                        .route("/oauth2/token", post(test_token_endpoint))
                        .with_state(state);
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .expect("test token endpoint");
                });
        });
        Self {
            address,
            refuse,
            requests,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    fn refuse(&self) {
        self.refuse.store(true, Ordering::Relaxed);
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

async fn test_token_endpoint(State(state): State<TokenServerState>) -> impl IntoResponse {
    state.requests.fetch_add(1, Ordering::Relaxed);
    if state.refuse.load(Ordering::Relaxed) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_client"})),
        )
            .into_response();
    }
    Json(json!({
        "access_token": TOKEN,
        "token_type": "Bearer",
        "expires_in": 300
    }))
    .into_response()
}

impl Drop for TokenServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().expect("token endpoint thread");
        }
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    _listener: UnixListener,
    token_server: TokenServer,
    root: PathBuf,
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
        private_directory(&root.join(".evidence/dev"));
        private_directory(&root.join(".evidence/dev/generated"));
        private_directory(&root.join(".evidence/dev/generated/keys"));
        private_file(&root.join(".evidence/dev/runtime.yaml"), b"runtime", 0o400);
        let caller_key = root.join(".evidence/dev/generated/keys/caller-private.jwk");
        private_file(
            &caller_key,
            br#"{"kty":"OKP","crv":"Ed25519","kid":"local-tutorial-caller-key-1","alg":"EdDSA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
            0o600,
        );
        let socket = root.join(".evidence/dev/control.sock");
        let listener = UnixListener::bind(&socket).expect("control socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        let token_server = TokenServer::start();
        let issuer_origin = format!("http://{}", token_server.address());
        let state = json!({
            "apiVersion": "id.registrystack.org/formats/evidence/dev-state/v6",
            "kind": "EvidenceDevState",
            "status": "ready",
            "project": canonical,
            "runtimePath": canonical.join(".evidence/dev/runtime.yaml"),
            "evidenceOrigin": "http://127.0.0.1:8080",
            "issuerOrigin": issuer_origin,
            "issuerSessionId": "0123456789abcdef0123456789abcdef0123456789abcdef",
            "namePrefix": "evidence-dev",
            "tokenUrl": format!("{issuer_origin}/oauth2/token"),
            "accessTokenAudience": "urn:registrystack:evidence:local:gateway",
            "caller": {
                "clientId": "local-tutorial-caller",
                "privateKeyPath": canonical.join(".evidence/dev/generated/keys/caller-private.jwk"),
                "assertionAudience": issuer_origin,
                "evidenceAudience": "urn:registrystack:evidence:local:caller",
                "requesterTag": "local-caller"
            },
            "accessProfiles": [],
            "definitions": [
                {
                    "alias": "adult-status",
                    "requirementUri": "urn:registrystack:evidence:local:requirement:adult-status",
                    "purpose": "age-check",
                    "subjects": [{
                        "role": "person",
                        "selectors": [{"profile": "local-subject-adult-status-v1", "fields": ["person_id"]}]
                    }],
                    "concepts": [{
                        "alias": "is_adult",
                        "uri": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
                        "form": "boolean"
                    }]
                },
                {
                    "alias": "age-bracket",
                    "requirementUri": "urn:registrystack:evidence:local:requirement:age-bracket",
                    "purpose": "service-path-selection",
                    "subjects": [{
                        "role": "person",
                        "selectors": [{"profile": "local-subject-age-bracket-v1", "fields": ["person_id"]}]
                    }],
                    "concepts": [{
                        "alias": "age_bracket",
                        "uri": "urn:registrystack:evidence:local:concept:age-bracket:age_bracket",
                        "form": "controlled-category"
                    }]
                },
                {
                    "alias": "relationship-check",
                    "requirementUri": "urn:registrystack:evidence:local:requirement:relationship-check",
                    "purpose": "relationship-review",
                    "subjects": [
                        {
                            "role": "child",
                            "selectors": [{"profile": "child-reference-v1", "fields": ["child_reference"]}]
                        },
                        {
                            "role": "candidate",
                            "selectors": [{"profile": "person-reference-v1", "fields": ["person_reference"]}]
                        }
                    ],
                    "concepts": [{
                        "alias": "relationship_confirmed",
                        "uri": "urn:registrystack:evidence:local:concept:relationship-check:relationship_confirmed",
                        "form": "boolean"
                    }]
                }
            ]
        });
        private_file(
            &root.join(".evidence/dev/state.json"),
            &serde_json::to_vec(&state).unwrap(),
            0o600,
        );
        write_sealed_bundle(&root, &state);

        let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("test signing key");
        let point = signing_key.verifying_key().to_encoded_point(false);
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
            b"#!/bin/sh\ncase \"$1\" in\n  prepare-local-relying-procedure)\n    printf '%s\\n' \"$@\" > \"$0.prepare.args\"\n    [ \"$2\" = '--runtime-config' ] || exit 40\n    [ \"$4\" = '--input' ] || exit 41\n    cp \"$5\" \"$0.input\" || exit 42\n    if IFS= read -r unexpected; then exit 43; fi\n    printf 'stdin-empty\\n' > \"$0.prepare.stdin\"\n    [ ! -f \"$0.fail-prepare\" ] || exit 44\n    cat \"$0.procedure\"\n    ;;\n  *) exit 45 ;;\nesac\n",
        );
        Self {
            _temporary: temporary,
            _listener: listener,
            token_server,
            root,
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
        let client = inputs
            .windows(2)
            .find(|pair| pair[0] == "--client")
            .map(|pair| pair[1]);
        let audience = client.map_or_else(
            || "urn:registrystack:evidence:local:caller".to_owned(),
            |client| format!("urn:registrystack:evidence:local:client:{client}"),
        );
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
        self.write_procedure(inputs);
        command()
            .current_dir(&self.root)
            .args(["request", "prepare"])
            .args(inputs)
            .args(["--name", name, "--project", ".", "--evidence-bin"])
            .arg(&self.evidence)
            .output()
            .expect("prepare command")
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

    fn prepare_as(&self, client_id: &str, name: &str) -> Output {
        self.prepare_with(
            &[
                "adult-status",
                "--purpose",
                "age-check",
                "--subject",
                "person_id=person-123",
                "--client",
                client_id,
            ],
            name,
        )
    }

    fn add_named_client(&self, client_id: &str, status: &str, key_mode: u32) {
        let authority_path = self.root.join("dev-authority.yaml");
        let mut authority: Value =
            serde_json::from_slice(&fs::read(&authority_path).unwrap()).unwrap();
        let state: Value =
            serde_json::from_slice(&fs::read(self.root.join(".evidence/dev/state.json")).unwrap())
                .unwrap();
        authority["accessProfiles"]["age-checks"] = authored_profile(
            state["definitions"].as_array().unwrap(),
            &["adult-status".to_owned()],
            AGE_CHECKS_TAG,
        );
        fs::write(&authority_path, serde_json::to_vec(&authority).unwrap()).unwrap();
        let clients = self.root.join("access/clients");
        fs::create_dir_all(&clients).expect("editable client directory");
        private_file(
            &clients.join(format!("{client_id}.yaml")),
            format!(
                "apiVersion: id.registrystack.org/formats/evidence/access-client/v1alpha1\n\
                 kind: EvidenceAccessClient\n\
                 clientId: {client_id}\n\
                 status: {status}\n\
                 principal: urn:registrystack:evidence:local:client:{client_id}\n\
                 evidenceAudience: urn:registrystack:evidence:local:client:{client_id}\n\
                 accessProfiles: [age-checks]\n\
                 keys:\n\
                   - {{kty: OKP, crv: Ed25519, kid: {client_id}-key-1, alg: EdDSA, use: sig, x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo}}\n"
            )
            .as_bytes(),
            0o644,
        );

        let private_clients = self.root.join(".evidence/clients");
        if !private_clients.exists() {
            private_directory(&private_clients);
        }
        let private_client = private_clients.join(client_id);
        private_directory(&private_client);
        private_file(
            &private_client.join("private.jwk"),
            format!(
                "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{client_id}-key-1\",\"alg\":\"EdDSA\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"}}"
            )
            .as_bytes(),
            key_mode,
        );
    }

    fn use_explicit_access(&self) {
        let path = self.root.join(".evidence/dev/state.json");
        let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state.as_object_mut().unwrap().remove("caller");
        state["accessProfiles"] = json!([{
            "id": "age-checks",
            "requesterTags": [AGE_CHECKS_TAG],
            "definitions": ["adult-status"],
            "actorKind": "service"
        }]);
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        write_sealed_bundle(&self.root, &state);
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
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn private_directory(path: &Path) {
    fs::create_dir(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, contents: &[u8], mode: u32) {
    fs::write(path, contents).expect("private file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn authored_profile(definitions: &[Value], selected: &[String], tag: &str) -> Value {
    let grants = selected.iter().map(|id| {
        let definition = definitions.iter().find(|d| d["alias"] == id.as_str())
            .expect("profile definition exists");
        json!({
            "definition":id,"purpose":definition["purpose"],
            "audienceFrom":"authenticated-requester","representations":["signed-jws"],
            "subjectBinding":"audience-scoped",
            "subjects":definition["subjects"].as_array().unwrap().iter().map(|subject|
                json!({"role":subject["role"],"selectorProfile":subject["selectors"][0]["profile"],"valueOrigin":"request"})
            ).collect::<Vec<_>>()
        })
    }).collect::<Vec<_>>();
    json!({"authority":"organizational","actorKind":"service","requesterTags":[tag],"grants":grants})
}

/// Exercise retained frontend state against the actual pure project and
/// authority compilers. Only the child that closes relying-party trust is
/// substituted; these tests never claim to execute a source or signer.
fn write_sealed_bundle(root: &Path, state: &Value) {
    let mut state = state.clone();
    let definitions = state["definitions"]
        .as_array()
        .expect("state definitions")
        .clone();
    let mut selector_profiles = serde_json::Map::new();
    let mut source_selectors =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    let mut authored_definitions = serde_json::Map::new();
    let mut functions = vec![
        json!({"id":"extract-record","interface":"source-extract/v1","source":"functions/extract-record.rhai"}),
    ];
    let mut scripts = std::collections::BTreeMap::from([("functions/extract-record.rhai".to_owned(),
        "fn extract(response, context) { #{outcome: \"match\", facts: #{active: response.active}} }".to_owned())]);
    let mut audiences = vec!["urn:registrystack:evidence:local:caller".to_owned()];
    for client in [
        "age-checker",
        "other-client",
        "revoked-client",
        "unsafe-client",
        "missing-key-client",
        "mismatched-key-client",
        "refused-client",
    ] {
        audiences.push(format!("urn:registrystack:evidence:local:client:{client}"));
    }
    for definition in &definitions {
        let id = definition["alias"].as_str().unwrap();
        let subjects = definition["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|subject| {
                let role = subject["role"].as_str().unwrap();
                let selector = &subject["selectors"][0];
                let profile = selector["profile"].as_str().unwrap();
                let fields = selector["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|field| {
                        (
                            field.as_str().unwrap().to_owned(),
                            json!({"type":"string","minimumBytes":1,"maximumBytes":128}),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>();
                selector_profiles.insert(
                    profile.to_owned(),
                    json!({"maximumAggregateBytes":512,"fields":fields}),
                );
                source_selectors
                    .entry(role.to_owned())
                    .or_default()
                    .insert(profile.to_owned());
                json!({"role":role,"selectors":[profile]})
            })
            .collect::<Vec<_>>();
        let outputs = definition["concepts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|concept| {
                let mut output = json!({"concept":concept["uri"],"type":concept["form"]});
                if concept["form"] == "controlled-category" {
                    output["values"] = json!(["adult", "minor"]);
                }
                (concept["alias"].as_str().unwrap().to_owned(), output)
            })
            .collect::<serde_json::Map<_, _>>();
        let function_id = format!("derive-{id}");
        let path = format!("functions/{function_id}.rhai");
        let values = definition["concepts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|concept| {
                let value = if concept["form"] == "controlled-category" {
                    json!("adult")
                } else {
                    json!(true)
                };
                format!("#{{output: {}, value: {value}}}", concept["alias"])
            })
            .collect::<Vec<_>>()
            .join(", ");
        scripts.insert(
            path.clone(),
            format!("fn derive(facts, selectors, context) {{ [{values}] }}"),
        );
        functions.push(json!({"id":function_id,"interface":"assertion-derive/v1","source":path}));
        authored_definitions.insert(id.to_owned(),json!({
            "question":format!("Synthetic {id} assertion"),
            "semantics":{"requirement":definition["requirementUri"],"kind":"criterion","evidenceType":format!("urn:registrystack:evidence:local:evidence-type:{id}"),"referenceFrameworks":["urn:example:framework:request-verification"]},
            "purpose":definition["purpose"],
            "grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":audiences},
            "subjects":subjects,"acquisition":{"type":"single","source":"record"},
            "derive":{"function":function_id},"outputs":outputs,"validitySeconds":300,
            "subjectBinding":"audience-scoped","representations":["signed-jws"]
        }));
    }
    let project_document = json!({
        "apiVersion":registry_evidence_authoring::project::PROJECT_API_VERSION,
        "kind":"EvidenceProject","id":"request-verify-fixture","selectorProfiles":selector_profiles,
        "functions":functions,
        "sources":{"record":{
            "type":"http-json","connection":"synthetic-register","acquisitionPosture":"record-transformed",
            "selectors":source_selectors.iter().map(|(role,profiles)|json!({"role":role,"profiles":profiles})).collect::<Vec<_>>(),
            "request":{"method":"GET","path":"/record","fixedHeaders":[]},
            "response":{"projection":["/active"],"shape":{"type":"object","required":["active"],"properties":{"active":{"type":"boolean"}}},"maximumBytes":4096},
            "extract":{"function":"extract-record"},"facts":{"active":{"type":"boolean"}},
            "limits":{"attemptTimeoutMilliseconds":2000,"maximumConcurrency":4}
        }},"assertionDefinitions":authored_definitions
    });
    let project_bytes = serde_json::to_vec(&project_document).unwrap();
    let project =
        registry_evidence_authoring::project::read_project("evidence.yaml", &project_bytes)
            .unwrap()
            .value;
    let compiled = registry_evidence_authoring::compile::compile(&project, &scripts).unwrap();
    private_file(&root.join("evidence.yaml"), &project_bytes, 0o644);
    fs::create_dir_all(root.join("functions")).unwrap();
    for (path, text) in &scripts {
        private_file(&root.join(path), text.as_bytes(), 0o644);
    }
    let mut target = registry_platform_yaml::Reader::new("local-target.yaml")
        .scan(include_bytes!(
            "../../../products/evidence/examples/standalone/local-target.yaml"
        ))
        .unwrap()
        .expect("target document")
        .to_json_value();
    target["project"] = json!("request-verify-fixture");
    private_file(
        &root.join("local-target.yaml"),
        &serde_json::to_vec(&target).unwrap(),
        0o644,
    );
    if state["accessProfiles"].as_array().unwrap().is_empty() {
        let selected = definitions
            .iter()
            .map(|d| d["alias"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        state["accessProfiles"] = json!([{"id":"local-caller","requesterTags":["local-caller"],"definitions":selected,"actorKind":"service"}]);
    }
    let profiles = state["accessProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|profile| {
            let selected = profile["definitions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            (
                profile["id"].as_str().unwrap().to_owned(),
                authored_profile(
                    &definitions,
                    &selected,
                    profile["requesterTags"][0].as_str().unwrap(),
                ),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let authority_document = json!({"apiVersion":registry_evidence_authoring::target::AUTHORITY_API_VERSION,"kind":"EvidenceTargetAuthority","target":"local","project":"request-verify-fixture","accessProfiles":profiles});
    let authority_bytes = serde_json::to_vec(&authority_document).unwrap();
    private_file(&root.join("dev-authority.yaml"), &authority_bytes, 0o644);
    let authority = registry_evidence_authoring::target::read_authority(
        "dev-authority.yaml",
        &authority_bytes,
        &project,
    )
    .unwrap()
    .value;
    let mut document =
        registry_evidence_authoring::target::compile_authority(&authority, &project).unwrap();
    document.as_object_mut().unwrap().remove("apiVersion");
    document.as_object_mut().unwrap().remove("kind");
    for profile in state["accessProfiles"].as_array_mut().unwrap() {
        let body = &document["accessProfiles"][profile["id"].as_str().unwrap()];
        profile["digest"] = json!(registry_platform_config::sha256_uri(
            &registry_platform_crypto::canonicalize_json(body).unwrap()
        ));
    }
    private_file(
        &root.join(".evidence/dev/state.json"),
        &serde_json::to_vec(&state).unwrap(),
        0o600,
    );
    let bundle_directory = root.join(".evidence/dev/bundle");
    if bundle_directory.exists() {
        make_fixture_writable(&bundle_directory);
    } else {
        private_directory(&bundle_directory);
    }
    for (path, bytes) in &compiled.artifacts {
        let path = bundle_directory.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        private_file(&path, bytes, 0o400);
    }
    let mut bundle = compiled.model;
    bundle["authentication"] = target["authentication"].clone();
    bundle["authentication"]["oidc"]["issuer"] = state["issuerOrigin"].clone();
    bundle["authentication"]["oidc"]["audience"] = state["accessTokenAudience"].clone();
    private_file(
        &bundle_directory.join("evidence.yaml"),
        &serde_json::to_vec(&bundle).unwrap(),
        0o400,
    );
    let sum_file = bundle_directory.join(registry_platform_config::SUM_FILE);
    if sum_file.exists() {
        fs::remove_file(&sum_file).unwrap();
    }
    let package = registry_platform_config::write_sum_file(
        &bundle_directory,
        None,
        &registry_platform_config::PackageLimits {
            max_files: 1024,
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_depth: 3,
            max_path_bytes: 128,
        },
        "evidencectl package",
    )
    .unwrap();
    fs::set_permissions(sum_file, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&bundle_directory, fs::Permissions::from_mode(0o500)).unwrap();
    let authority_directory = root.join(".evidence/dev/authority");
    if !authority_directory.exists() {
        private_directory(&authority_directory);
    }
    let bytes = registry_platform_crypto::canonicalize_json(&document).unwrap();
    let activation = json!({"apiVersion":"id.registrystack.org/formats/evidence/authority-state/v1alpha1","kind":"EvidenceAuthorityState","activations":[{
        "sequence":1,"activatedAt":"2026-08-04T00:00:00Z","packageDigest":package.digest(),
        "authorityDigest":registry_platform_config::sha256_uri(&bytes),
        "authorityRevision":format!("sha256:{}",hex::encode(registry_platform_crypto::domain_separated_sha256(b"registry.evidence.target-authority/v1\0",&bytes))),"document":document
    }]});
    private_file(
        &authority_directory.join("authority-state.json"),
        &serde_json::to_vec(&activation).unwrap(),
        0o600,
    );
}

fn make_fixture_writable(root: &Path) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            make_fixture_writable(&path);
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
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
