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

#[test]
fn public_help_exposes_only_the_adopter_request_and_verify_inputs() {
    let request = command()
        .args(["request", "prepare", "--help"])
        .output()
        .expect("request help");
    assert_success(&request);
    let request = String::from_utf8_lossy(&request.stdout);
    for visible in ["<QUESTION>", "--purpose", "--subject", "--name"] {
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
                    "profile": "local-subject-v1",
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
            "schema": "registry.evidencectl.dev-state/v1",
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
                "evidenceAudience": "registry-evidence-local",
                "requesterTag": "local-caller"
            },
            "question": {
                "alias": "adult-status",
                "requirementUri": "urn:registrystack:evidence:local:requirement:adult-status",
                "purpose": "age-check",
                "subjectRole": "person",
                "selectorProfile": "local-subject-v1",
                "selectorField": "person_id",
                "conceptAlias": "is_adult",
                "conceptUri": "urn:registrystack:evidence:local:concept:adult-status:is_adult",
                "conceptForm": "boolean"
            },
            "failure": null
        });
        private_file(
            &root.join(".evidence/dev/state.json"),
            &serde_json::to_vec(&state).unwrap(),
            0o600,
        );

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

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
