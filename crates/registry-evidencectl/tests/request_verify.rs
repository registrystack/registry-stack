use std::{
    fs,
    os::unix::{
        fs::{symlink, PermissionsExt as _},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

const TOKEN: &str = "secret.token-canary";
const CONTEXT: &str = "{\"schema\":\"context-canary\"}\n";
const VERIFIED: &str =
    "{\"purpose\":\"age-check\",\"schema\":\"verified-canary\",\"values\":{\"is_adult\":true}}\n";
const AGE_CHECKS_TAG: &str =
    "policy-v1-bc8c04f766133dc6ffd6e395caa64f9c3b43301c1d308716668c71b8b839c0dc";

#[test]
fn public_help_exposes_only_the_adopter_request_and_verify_inputs() {
    let request = command()
        .args(["request", "prepare", "--help"])
        .output()
        .expect("request help");
    assert_success(&request);
    let request = String::from_utf8_lossy(&request.stdout);
    for visible in [
        "<QUESTION>",
        "--purpose",
        "--subject",
        "--name",
        "--client",
        "--format",
    ] {
        assert!(request.contains(visible), "missing {visible}: {request}");
    }
    for hidden in ["--project", "--evidence-bin", "--mint-bin"] {
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
    assert_eq!(
        fs::read_to_string(retained.join("verification.json")).unwrap(),
        CONTEXT
    );
    assert_eq!(
        fs::read_to_string(retained.join("authorization.curl")).unwrap(),
        format!("header = \"Authorization: Bearer {TOKEN}\"\n")
    );

    let mint_args = fs::read_to_string(fixture.mint.with_extension("args")).unwrap();
    assert_eq!(
        mint_args.lines().collect::<Vec<_>>(),
        [
            "token",
            "--url",
            "http://127.0.0.1:8081/token",
            "--client-id",
            "local-tutorial-caller",
            "--key",
            fs::canonicalize(&fixture.root)
                .unwrap()
                .join(".evidence/dev/generated/keys/caller-private.jwk")
                .to_str()
                .unwrap(),
            "--audience",
            "http://127.0.0.1:8081/token",
        ]
    );
    let evidence_args = fs::read_to_string(fixture.evidence.with_extension("prepare.args"))
        .expect("Evidence prepare argv");
    let evidence_args = evidence_args.lines().collect::<Vec<_>>();
    assert_eq!(evidence_args[0], "--runtime");
    assert_eq!(evidence_args[2], "prepare-local-verification-context");
    assert_eq!(evidence_args[3], "--request");
    assert!(evidence_args[4].ends_with("/request.json"));
    assert_eq!(&evidence_args[5..], ["--response-format", "signed-jws"]);
    assert!(!evidence_args.join(" ").contains(TOKEN));
    assert_eq!(
        fs::read_to_string(fixture.evidence.with_extension("prepare.stdin")).unwrap(),
        "stdin-ok\n"
    );
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
    let evidence_args = fs::read_to_string(fixture.evidence.with_extension("prepare.args"))
        .expect("Evidence SD-JWT prepare argv");
    assert_eq!(
        &evidence_args.lines().collect::<Vec<_>>()[5..],
        ["--response-format", "sd-jwt-vc"]
    );

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

    let response = fixture.root.join("assertion.jws.json");
    fs::write(&response, b"ordinary curl response").expect("response");
    fs::set_permissions(&response, fs::Permissions::from_mode(0o644)).expect("curl mode");
    let verified = fixture.verify("verified.json");
    assert_success(&verified);
    assert_eq!(verified.stdout, b"VERIFIED\n");
    let verified_path = fixture.root.join("verified.json");
    assert_mode(&verified_path, 0o600);
    assert_eq!(fs::read_to_string(&verified_path).unwrap(), VERIFIED);
    assert_eq!(
        fs::read_to_string(fixture.evidence.with_extension("verify.args"))
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        [
            "verify-local-response",
            "--context",
            ".evidence/requests/first-assertion/verification.json",
            "--response",
            "assertion.jws.json",
        ]
    );

    let refused = fixture.verify("verified.json");
    assert!(!refused.status.success());
    assert_eq!(fs::read_to_string(&verified_path).unwrap(), VERIFIED);
}

#[test]
fn named_client_prepare_uses_the_registered_identity() {
    let fixture = Fixture::new();
    fixture.add_named_client("age-checker", "active", 0o600);
    fixture.use_explicit_access();

    let prepared = fixture.prepare_as("age-checker", "named-client");
    assert_success(&prepared);
    let mint_args = fs::read_to_string(fixture.mint.with_extension("args")).unwrap();
    assert_eq!(
        mint_args.lines().collect::<Vec<_>>(),
        [
            "token",
            "--url",
            "http://127.0.0.1:8081/token",
            "--client-id",
            "age-checker",
            "--key",
            fs::canonicalize(&fixture.root)
                .unwrap()
                .join(".evidence/clients/age-checker/private.jwk")
                .to_str()
                .unwrap(),
            "--audience",
            "http://127.0.0.1:8081/token",
        ]
    );
    assert!(fixture
        .root
        .join(".evidence/requests/named-client/request.json")
        .is_file());
}

#[test]
fn unusable_named_clients_and_mint_refusal_publish_no_request_artifacts() {
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
    fs::write(refused.mint.with_extension("fail"), b"").unwrap();
    let output = refused.prepare_as("refused-client", "refused-client");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "evidencectl: Registry Mint refused a token for client refused-client\n"
    );
    assert_no_request_artifacts(&refused.root, "refused-client");
}

#[test]
fn selected_clients_require_an_explicit_current_policy_generation() {
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

    private_file(
        &explicit.root.join("questions/age-bracket.yaml"),
        b"id: age-bracket\n",
        0o644,
    );
    private_file(
        &explicit.root.join("access/policies/age-checks.yaml"),
        b"version: 1\nid: age-checks\nquestions: [adult-status, age-bracket]\n",
        0o644,
    );
    let output = explicit.prepare_as("age-checker", "drifted-policy");
    assert!(!output.status.success());
    assert_no_request_artifacts(&explicit.root, "drifted-policy");
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
fn failed_core_verification_removes_the_unpublished_output() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("assertion.jws.json"), b"response").unwrap();
    fs::write(fixture.evidence.with_extension("fail-verify"), b"").unwrap();
    let output = fixture.verify("verified.json");
    assert!(!output.status.success());
    assert!(!fixture.root.join("verified.json").exists());
    assert!(sorted_names(&fixture.root)
        .iter()
        .all(|name| !name.starts_with(".verify-")));
}

struct Fixture {
    _temporary: tempfile::TempDir,
    _listener: UnixListener,
    root: PathBuf,
    evidence: PathBuf,
    mint: PathBuf,
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
        private_file(&caller_key, b"{}", 0o600);
        let socket = root.join(".evidence/dev/control.sock");
        let listener = UnixListener::bind(&socket).expect("control socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        let state = json!({
            "schema": "registry.evidencectl.dev-state/v5",
            "status": "ready",
            "project": canonical,
            "runtimePath": canonical.join(".evidence/dev/runtime.yaml"),
            "evidenceOrigin": "http://127.0.0.1:8080",
            "mintOrigin": "http://127.0.0.1:8081",
            "tokenUrl": "http://127.0.0.1:8081/token",
            "accessTokenAudience": "registry-evidence-local",
            "caller": {
                "clientId": "local-tutorial-caller",
                "privateKeyPath": canonical.join(".evidence/dev/generated/keys/caller-private.jwk"),
                "assertionAudience": "http://127.0.0.1:8081/token",
                "evidenceAudience": "urn:registrystack:evidence:local:caller",
                "requesterTag": "local-caller"
            },
            "accessPolicies": [],
            "questions": [
                {
                    "alias": "adult-status",
                    "requirementUri": "urn:registrystack:evidence:local:requirement:adult-status",
                    "purpose": "age-check",
                    "subjects": [{
                        "role": "person",
                        "selectorProfile": "local-subject-adult-status-v1",
                        "selectorField": "person_id"
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
                        "selectorProfile": "local-subject-age-bracket-v1",
                        "selectorField": "person_id"
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
                            "selectorProfile": "child-reference-v1",
                            "selectorField": "child_reference"
                        },
                        {
                            "role": "candidate",
                            "selectorProfile": "person-reference-v1",
                            "selectorField": "person_reference"
                        }
                    ],
                    "concepts": [{
                        "alias": "relationship_confirmed",
                        "uri": "urn:registrystack:evidence:local:concept:relationship-check:relationship_confirmed",
                        "form": "boolean"
                    }]
                }
            ],
            "failure": null
        });
        private_file(
            &root.join(".evidence/dev/state.json"),
            &serde_json::to_vec(&state).unwrap(),
            0o600,
        );
        write_sealed_bundle(&root, &state);

        let mint = temporary.path().join("mint-stub");
        executable(
            &mint,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\n[ ! -f \"$0.fail\" ] || exit 31\nprintf '%s\\n' '{TOKEN}'\n"
            )
            .as_bytes(),
        );
        let evidence = temporary.path().join("evidence-stub");
        executable(
            &evidence,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  --runtime)\n    printf '%s\\n' \"$@\" > \"$0.prepare.args\"\n    bearer=$(dd bs=65536 count=1 2>/dev/null)\n    [ \"$bearer\" = '{TOKEN}' ] || exit 40\n    printf 'stdin-ok\\n' > \"$0.prepare.stdin\"\n    [ ! -f \"$0.fail-prepare\" ] || exit 41\n    printf '%s' '{CONTEXT}'\n    ;;\n  verify-local-response)\n    printf '%s\\n' \"$@\" > \"$0.verify.args\"\n    [ ! -f \"$0.fail-verify\" ] || exit 42\n    printf '%s' '{VERIFIED}'\n    ;;\n  *) exit 43 ;;\nesac\n"
            )
            .as_bytes(),
        );
        Self {
            _temporary: temporary,
            _listener: listener,
            root,
            evidence,
            mint,
        }
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
        command()
            .current_dir(&self.root)
            .args(["request", "prepare"])
            .args(inputs)
            .args(["--name", name, "--project", ".", "--evidence-bin"])
            .arg(&self.evidence)
            .arg("--mint-bin")
            .arg(&self.mint)
            .output()
            .expect("prepare command")
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
        let questions = self.root.join("questions");
        fs::create_dir_all(&questions).expect("authored question directory");
        private_file(
            &questions.join("adult-status.yaml"),
            b"id: adult-status\n",
            0o644,
        );
        let policies = self.root.join("access/policies");
        fs::create_dir_all(&policies).expect("editable policy directory");
        private_file(
            &policies.join("age-checks.yaml"),
            b"version: 1\nid: age-checks\nquestions: [adult-status]\n",
            0o644,
        );
        let clients = self.root.join("access/clients");
        fs::create_dir_all(&clients).expect("editable client directory");
        private_file(
            &clients.join(format!("{client_id}.yaml")),
            format!(
                "version: 1\n\
                 clientId: {client_id}\n\
                 status: {status}\n\
                 principal: urn:registrystack:evidence:local:client:{client_id}\n\
                 evidenceAudience: urn:registrystack:evidence:local:client:{client_id}\n\
                 policies: [age-checks]\n\
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
        state["caller"] = Value::Null;
        state["accessPolicies"] = json!([{
            "id": "age-checks",
            "requesterTag": AGE_CHECKS_TAG,
            "questions": ["adult-status"]
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
                "--evidence-bin",
            ])
            .arg(&self.evidence)
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

fn write_sealed_bundle(root: &Path, state: &Value) {
    let bundle_directory = root.join(".evidence/dev/bundle");
    if !bundle_directory.exists() {
        private_directory(&bundle_directory);
    }
    let questions = state["questions"].as_array().expect("state questions");
    let mut selector_profiles = serde_json::Map::new();
    let requirements = questions
        .iter()
        .map(|question| {
            let roles = question["subjects"]
                .as_array()
                .expect("question subjects")
                .iter()
                .map(|subject| {
                    let profile = subject["selectorProfile"]
                        .as_str()
                        .expect("selector profile");
                    let field = subject["selectorField"].as_str().expect("selector field");
                    selector_profiles.insert(
                        profile.to_owned(),
                        json!({"fields": {field: {"type": "string"}}}),
                    );
                    json!({"role": subject["role"], "selectorProfiles": [profile]})
                })
                .collect::<Vec<_>>();
            let concepts = question["concepts"]
                .as_array()
                .expect("question concepts")
                .iter()
                .map(|concept| json!({"id": concept["uri"], "form": concept["form"]}))
                .collect::<Vec<_>>();
            json!({
                "id": question["requirementUri"],
                "purposes": [question["purpose"].clone()],
                "subjectRoles": roles,
                "concepts": concepts,
            })
        })
        .collect::<Vec<_>>();
    let grant_for = |question: &Value| {
        let subjects = question["subjects"]
            .as_array()
            .expect("question subjects")
            .iter()
            .map(|subject| {
                json!({
                    "role": subject["role"],
                    "selectorProfile": subject["selectorProfile"],
                    "valueOrigin": "request",
                })
            })
            .collect::<Vec<_>>();
        json!({
            "requirement": question["requirementUri"],
            "purpose": question["purpose"],
            "audienceFrom": "authenticated-requester",
            "responseFormats": ["signed-jws"],
            "subjects": subjects,
        })
    };
    let access_policies = state["accessPolicies"]
        .as_array()
        .expect("state access policies");
    let authority_profiles = if access_policies.is_empty() {
        serde_json::Map::from_iter([(
            "local-caller".to_owned(),
            json!({
                "kind": "explicit-request",
                "requesterTags": ["local-caller"],
                "grants": questions.iter().map(grant_for).collect::<Vec<_>>(),
            }),
        )])
    } else {
        access_policies
            .iter()
            .map(|policy| {
                let requester_tag = policy["requesterTag"]
                    .as_str()
                    .expect("policy requester tag");
                let grants = policy["questions"]
                    .as_array()
                    .expect("policy questions")
                    .iter()
                    .map(|alias| {
                        let alias = alias.as_str().expect("question alias");
                        let question = questions
                            .iter()
                            .find(|question| question["alias"] == alias)
                            .expect("policy question exists");
                        grant_for(question)
                    })
                    .collect::<Vec<_>>();
                (
                    requester_tag.to_owned(),
                    json!({
                        "kind": "explicit-request",
                        "requesterTags": [requester_tag],
                        "grants": grants,
                    }),
                )
            })
            .collect()
    };
    let bundle = json!({
        "selectorProfiles": selector_profiles,
        "authorityProfiles": authority_profiles,
        "requirements": requirements,
    });
    let bundle_path = bundle_directory.join("evidence.yaml");
    if bundle_path.exists() {
        fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o600))
            .expect("unseal bundle fixture");
    }
    private_file(
        &bundle_path,
        serde_norway::to_string(&bundle)
            .expect("bundle renders")
            .as_bytes(),
        0o400,
    );
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
