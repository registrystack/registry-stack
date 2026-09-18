//! Focused local Evidence lifecycle proofs.
//!
//! Ordinary tests stop at the process and filesystem boundary. The ignored
//! gate starts the pinned stock issuer container and the real Evidence binary,
//! acquires a token through the public CLI, and verifies its typed claims.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output},
};

const OPENAPI: &str = r#"openapi: 3.1.0
info: {title: Tutorial registry, version: 1.0.0}
servers: [{url: 'http://127.0.0.1:8000'}]
paths:
  /people/{person_id}:
    get:
      operationId: getPerson
      parameters:
        - name: person_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: A person
          content:
            application/json:
              schema:
                type: object
                required: [person_id, date_of_birth]
                properties:
                  person_id: {type: string}
                  date_of_birth: {type: string, format: date}
"#;

const QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

const DERIVATION: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    #{is_adult: compare_dates(context.legal_local_date, add_calendar_years(born, 18)) >= 0}
}
"#;

#[test]
#[ignore = "exact gate: starts the pinned stock issuer container and real Evidence binary"]
fn real_issuer_lifecycle_issues_typed_service_claims_and_stops_cleanly() {
    let evidence = required_binary("EVIDENCE_BIN");
    let docker = installed_or_env("DOCKER_BIN", "docker");
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let (evidence_port, issuer_port) = unused_port_pair();

    let started = fixture.dev_start(&evidence, &docker, evidence_port, issuer_port);
    assert_success(&started, "issuer-backed dev start");
    let stdout = String::from_utf8_lossy(&started.stdout);
    assert!(
        stdout.contains(&format!(
            "Evidence ready at http://127.0.0.1:{evidence_port}"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("Issuer ready at http://127.0.0.1:{issuer_port}")),
        "{stdout}"
    );

    let state = read_json(&fixture.root.join(".evidence/dev/state.json"));
    assert_eq!(state["schema"], "registry.evidencectl.dev-state/v6");
    assert_eq!(state["status"], "ready");
    assert_eq!(
        state["issuerOrigin"],
        format!("http://127.0.0.1:{issuer_port}")
    );
    assert_eq!(
        state["tokenUrl"],
        format!("http://127.0.0.1:{issuer_port}/oauth2/token")
    );
    assert!(state.get("mintOrigin").is_none());

    let token = evidencectl()
        .args(["dev", "token", "local-tutorial-caller"])
        .arg(&fixture.root)
        .output()
        .expect("dev token");
    assert_success(&token, "dev token");
    let header_path = fixture
        .root
        .join(".evidence/dev/generated/keys/local-tutorial-caller.header");
    assert_mode(&header_path, 0o600);
    let header = fs::read_to_string(&header_path).expect("private authorization header");
    let compact = header
        .trim_end()
        .strip_prefix("Authorization: Bearer ")
        .expect("authorization header prefix");
    let claims = decode_claims(compact);
    assert_eq!(claims["registry_actor_kind"], "service");
    assert_eq!(claims["evidence_tags"], serde_json::json!(["local-caller"]));
    assert_eq!(
        claims["evidence_audience"],
        "urn:registrystack:evidence:local:caller"
    );
    assert_eq!(claims["aud"], "urn:registrystack:evidence:local:gateway");
    assert!(claims.get("registry_grant_id").is_none());

    assert_success(&fixture.dev_stop(), "dev stop");
    let stopped = read_json(&fixture.root.join(".evidence/dev/state.json"));
    assert_eq!(stopped["status"], "stopped");
    assert!(stopped["caller"].is_null());
    assert!(!fixture.root.join(".evidence/dev/control.sock").exists());
    assert_success(&fixture.dev_clean(), "dev clean");
    assert!(!fixture.root.join(".evidence/dev").exists());
}

#[test]
fn retired_mint_flags_are_refused_before_private_state_is_created() {
    for flag in ["--mint-port", "--mint-bin"] {
        let fixture = Project::new();
        let value = if flag == "--mint-port" {
            "18081"
        } else {
            "/missing/mint"
        };
        let output = evidencectl()
            .args(["dev", "--detach", flag, value, "--project"])
            .arg(&fixture.root)
            .output()
            .expect("retired Mint flag");
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("Registry Mint development flags were removed"),
            "{error}"
        );
        assert!(error.contains("--issuer-port"), "{error}");
        assert!(!fixture.root.join(".evidence").exists());
    }
}

#[test]
fn approved_grant_command_requires_connection_and_refuses_arbitrary_requirements() {
    let output = evidencectl()
        .args(["dev", "grant", "--requirement", "adult-status"])
        .output()
        .expect("approved grant command");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("evidencectl.usage"), "{error}");

    let help = evidencectl()
        .args(["dev", "--help"])
        .output()
        .expect("dev help");
    assert_success(&help, "dev help");
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("grant"),
        "approved grant acquisition must be discoverable"
    );
}

#[test]
fn equal_local_ports_fail_before_creating_private_state() {
    let fixture = Project::new();
    let output = evidencectl()
        .args([
            "dev",
            "--detach",
            "--evidence-port",
            "18080",
            "--issuer-port",
            "18080",
            "--project",
        ])
        .arg(&fixture.root)
        .output()
        .expect("equal-port start");
    assert!(!output.status.success());
    assert!(!fixture.root.join(".evidence").exists());
}

#[test]
fn each_busy_local_port_is_refused_by_name_with_its_recovery_flag() {
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let tool = fixture.tool_that_never_serves();
    let busy = TcpListener::bind("127.0.0.1:0").expect("hold a local port");
    let busy_port = busy.local_addr().expect("busy address").port();
    let (free_evidence, free_issuer) = unused_port_pair();

    for (evidence_port, issuer_port, flag) in [
        (busy_port, free_issuer, "--evidence-port"),
        (free_evidence, busy_port, "--issuer-port"),
    ] {
        let output = fixture.dev_start(&tool, &tool, evidence_port, issuer_port);
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(&busy_port.to_string()), "{error}");
        assert!(error.contains("already in use"), "{error}");
        assert!(error.contains(flag), "{error}");
        assert!(!fixture.root.join(".evidence/dev").exists());
    }
    assert!(busy.local_addr().is_ok());
}

#[test]
fn public_symlink_and_stale_state_are_never_replaced() {
    let public = Project::new();
    fs::create_dir(public.root.join(".evidence")).expect("generated root");
    fs::set_permissions(
        public.root.join(".evidence"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("public mode");
    assert!(!public.start_without_binaries().status.success());
    assert!(!public.dev_clean().status.success());

    let linked = Project::new();
    let target = linked.root.join("private-target");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("target mode");
    symlink(&target, linked.root.join(".evidence")).expect("generated symlink");
    assert!(!linked.start_without_binaries().status.success());
    assert!(linked.root.join(".evidence").is_symlink());

    let stale = Project::new();
    fs::create_dir(stale.root.join(".evidence")).expect("generated root");
    fs::set_permissions(
        stale.root.join(".evidence"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("private mode");
    fs::create_dir(stale.root.join(".evidence/dev")).expect("stale dev");
    fs::set_permissions(
        stale.root.join(".evidence/dev"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("stale mode");
    fs::write(stale.root.join(".evidence/dev/unknown"), b"keep").expect("stale entry");
    assert!(!stale.start_without_binaries().status.success());
    assert!(!stale.dev_clean().status.success());
    assert_eq!(
        fs::read(stale.root.join(".evidence/dev/unknown")).expect("preserved stale entry"),
        b"keep"
    );
}

#[test]
fn compatibility_flags_beside_a_dev_action_are_refused_naming_both_flags() {
    let fixture = Project::new();
    // The flags stay parseable next to the action so the refusal can name
    // them; both output formats must carry that cause.
    let human = evidencectl()
        .args(["dev", "--detach", "start"])
        .arg(&fixture.root)
        .output()
        .expect("compat-flag start");
    assert_eq!(human.status.code(), Some(1));
    let error = String::from_utf8_lossy(&human.stderr);
    assert!(
        error.contains("evidence.dev.compat-flags-refused"),
        "{error}"
    );
    assert!(error.contains("--detach"), "{error}");
    assert!(error.contains("--project"), "{error}");
    assert!(!fixture.root.join(".evidence").exists());

    let json = evidencectl()
        .args(["--format=json", "dev", "--project"])
        .arg(&fixture.root)
        .args(["token", "local-tutorial-caller"])
        .output()
        .expect("compat-flag token");
    assert_eq!(json.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&json.stdout).expect("JSON refusal");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidence.dev.compat-flags-refused"
    );
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .expect("message")
        .contains("--detach or --project"));
}

#[test]
fn bare_dev_without_detach_names_the_required_spelling() {
    let fixture = Project::new();
    let output = evidencectl()
        .args(["dev", "--project"])
        .arg(&fixture.root)
        .output()
        .expect("bare dev");
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("evidence.dev.detach-required"), "{error}");
    assert!(error.contains("dev start"), "{error}");
    assert!(!fixture.root.join(".evidence").exists());
}

#[test]
fn sqlite_extract_dev_start_refuses_local_serving_by_name_in_both_formats() {
    let fixture = Project::new();
    let project = fixture
        .root
        .parent()
        .expect("temporary parent")
        .join("sqlite-project");
    assert_success(
        &evidencectl()
            .args([
                "new",
                project.to_str().expect("UTF-8 project path"),
                "--transport",
                "sqlite-extract",
                "--profile",
                "local",
            ])
            .output()
            .expect("create SQLite starter"),
        "create SQLite starter",
    );
    let tool = fixture.tool_that_never_serves();
    let (evidence_port, issuer_port) = unused_port_pair();

    let human = evidencectl()
        .args(["dev", "start"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&tool)
        .args(["--evidence-port", &evidence_port.to_string()])
        .args(["--issuer-port", &issuer_port.to_string()])
        .output()
        .expect("sqlite dev start");
    assert_eq!(human.status.code(), Some(1));
    let error = String::from_utf8_lossy(&human.stderr);
    assert!(
        error.contains("evidence.dev.local-transport-refused"),
        "{error}"
    );
    assert!(error.contains("does not bind SQLite extracts"), "{error}");
    assert!(
        error.contains("sources/record-status.yaml:/transport"),
        "{error}"
    );
    assert!(error.contains("evidencectl test"), "{error}");
    assert!(!project.join(".evidence/dev/state.json").exists());

    let json = evidencectl()
        .args(["--format=json", "dev", "start"])
        .arg(&project)
        .arg("--evidence-bin")
        .arg(&tool)
        .args(["--evidence-port", &evidence_port.to_string()])
        .args(["--issuer-port", &issuer_port.to_string()])
        .output()
        .expect("sqlite dev start JSON");
    assert_eq!(json.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&json.stdout).expect("JSON refusal");
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "evidence.dev.local-transport-refused");
    assert_eq!(diagnostic["path"], "sources/record-status.yaml:/transport");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message")
        .contains("does not bind SQLite extracts"));
    assert!(diagnostic["suggestedAction"]
        .as_str()
        .expect("suggested action")
        .contains("evidencectl test"));
}

#[test]
fn dev_token_without_a_ready_session_names_the_missing_session_in_both_formats() {
    let fixture = Project::new();

    let human = evidencectl()
        .args(["dev", "token", "local-tutorial-caller"])
        .arg(&fixture.root)
        .output()
        .expect("token without session");
    assert_eq!(human.status.code(), Some(3));
    let error = String::from_utf8_lossy(&human.stderr);
    assert!(error.contains("evidence.dev.no-ready-session"), "{error}");
    assert!(
        error.contains("No ready local development session"),
        "{error}"
    );
    assert!(error.contains("dev start"), "{error}");

    let json = evidencectl()
        .args(["--format=json", "dev", "token", "local-tutorial-caller"])
        .arg(&fixture.root)
        .output()
        .expect("token without session JSON");
    assert_eq!(json.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&json.stdout).expect("JSON refusal");
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidence.dev.no-ready-session"
    );
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .expect("message")
        .contains("No ready local development session"));
}

#[test]
fn dev_stop_and_clean_without_a_session_name_what_is_missing_in_both_formats() {
    let fixture = Project::new();

    for (arguments, code, message) in [
        (
            vec!["dev", "stop"],
            "evidence.dev.no-active-session",
            "No active local development session",
        ),
        (
            vec!["dev", "clean", "--project"],
            "evidence.dev.no-stopped-session",
            "No completed stopped local development session",
        ),
    ] {
        let human = evidencectl()
            .args(&arguments)
            .arg(&fixture.root)
            .output()
            .expect("lifecycle refusal");
        assert_eq!(human.status.code(), Some(3));
        let error = String::from_utf8_lossy(&human.stderr);
        assert!(error.contains(code), "{error}");
        assert!(error.contains(message), "{error}");

        let json = evidencectl()
            .args(["--format=json"])
            .args(&arguments)
            .arg(&fixture.root)
            .output()
            .expect("lifecycle refusal JSON");
        assert_eq!(json.status.code(), Some(3));
        let report: Value = serde_json::from_slice(&json.stdout).expect("JSON refusal");
        assert_eq!(report["status"], "operational-failure");
        assert_eq!(report["diagnostics"][0]["code"], code);
        assert!(report["diagnostics"][0]["message"]
            .as_str()
            .expect("message")
            .contains("nothing was"));
    }
}

struct Project {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl Project {
    fn new() -> Self {
        // The issuer bind-mounts this state into Docker. Keep it beside the
        // built binary rather than under a host TMPDIR Docker may not share.
        let binary = Path::new(env!("CARGO_BIN_EXE_evidencectl"));
        let temporary = tempfile::Builder::new()
            .prefix("evidence-native-lifecycle-")
            .tempdir_in(binary.parent().expect("binary parent"))
            .expect("tempdir");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("tempdir mode");
        let root = temporary.path().join("tutorial");
        fs::create_dir_all(root.join("questions")).expect("questions");
        fs::create_dir(root.join("derivations")).expect("derivations");
        fs::write(root.join("source.openapi.yaml"), OPENAPI).expect("OpenAPI");
        fs::write(root.join("questions/adult-status.yaml"), QUESTION).expect("question");
        fs::write(root.join("derivations/adult-status.rhai"), DERIVATION).expect("derivation");
        Self {
            _temporary: temporary,
            root,
        }
    }

    fn generate_evidence_keys(&self) {
        let secrets = self.root.join("secrets");
        assert_success(
            &evidencectl()
                .args(["keygen", "signing", "--out-dir"])
                .arg(&secrets)
                .output()
                .expect("signing key"),
            "signing key",
        );
        for name in ["audit-hmac-key", "subject-binding-hmac-key"] {
            assert_success(
                &evidencectl()
                    .args(["keygen", "secret", "--out"])
                    .arg(secrets.join(name))
                    .output()
                    .expect("HMAC key"),
                "HMAC key",
            );
        }
    }

    fn tool_that_never_serves(&self) -> PathBuf {
        let path = self.root.join("never-serves-tool");
        fs::write(&path, "#!/bin/sh\nexit 1\n").expect("test tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("test tool mode");
        path
    }

    fn dev_start(
        &self,
        evidence: &Path,
        docker: &Path,
        evidence_port: u16,
        issuer_port: u16,
    ) -> Output {
        evidencectl()
            .args(["dev", "--detach", "--project"])
            .arg(&self.root)
            .arg("--evidence-bin")
            .arg(evidence)
            .arg("--docker-bin")
            .arg(docker)
            .args(["--evidence-port", &evidence_port.to_string()])
            .args(["--issuer-port", &issuer_port.to_string()])
            .arg("--ready-timeout-seconds")
            .arg("120")
            .output()
            .expect("dev start")
    }

    fn start_without_binaries(&self) -> Output {
        evidencectl()
            .args(["dev", "--detach", "--project"])
            .arg(&self.root)
            .output()
            .expect("dev start")
    }

    fn dev_stop(&self) -> Output {
        evidencectl()
            .args(["dev", "stop", "--project"])
            .arg(&self.root)
            .output()
            .expect("dev stop")
    }

    fn dev_clean(&self) -> Output {
        evidencectl()
            .args(["dev", "clean", "--project"])
            .arg(&self.root)
            .output()
            .expect("dev clean")
    }
}

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn required_binary(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("set {name} for the exact lifecycle gate"))
}

fn installed_or_env(variable: &str, binary: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("set {variable} for the exact lifecycle gate"))
}

fn unused_port_pair() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").expect("reserve first port");
    let second = TcpListener::bind("127.0.0.1:0").expect("reserve second port");
    let ports = (
        first.local_addr().expect("first address").port(),
        second.local_addr().expect("second address").port(),
    );
    drop((first, second));
    ports
}

fn decode_claims(compact: &str) -> Value {
    let payload = compact.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload encoding"),
    )
    .expect("JWT claims")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_mode(path: &Path, expected: u32) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));
    assert_eq!(
        metadata.mode() & 0o777,
        expected,
        "mode of {}",
        path.display()
    );
    assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
}
