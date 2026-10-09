// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` binary as an operator runs it: `check` reads the runtime
//! configuration offline, resolving no secret and opening no socket, and
//! reports every finding in the shared diagnostic shape; `serve` resolves the
//! secrets the file names before it listens. Every refusal names the field,
//! never the value.

#[path = "support/gateway.rs"]
mod gateway;
#[path = "support/mock_registry.rs"]
mod mock_registry;

use std::{os::unix::fs::PermissionsExt as _, path::Path, process::Command};

use gateway::{document, write_secrets, Document, Limits, REVIEW_BASE_URL};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use serde_json::Value;
use tempfile::TempDir;

const CANARY: &str = "canary-inline-gateway-private-key-material";

struct Project {
    directory: TempDir,
    config: std::path::PathBuf,
    key_secret: String,
}

impl Project {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("temporary directory canonicalizes");
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
        let secrets = write_secrets(&root, &key);
        let text = document(&Document {
            listen: "127.0.0.1:8110",
            resource: "http://127.0.0.1:8110/mcp",
            issuer: "http://127.0.0.1:8111",
            jwks: "http://127.0.0.1:8111/jwks.json",
            registry: "http://127.0.0.1:8112/",
            token_endpoint: "http://127.0.0.1:8111/token",
            review: REVIEW_BASE_URL,
            secrets: &secrets,
            audit: &root.join("audit").join("audit.jsonl"),
            limits: Limits::default(),
        });
        let config = root.join("runtime.yaml");
        std::fs::write(&config, text).expect("configuration writes");
        Self {
            directory,
            config,
            key_secret: key.d.clone().expect("private scalar"),
        }
    }

    fn rewrite(&self, from: &str, to: &str) {
        let text = std::fs::read_to_string(&self.config).expect("configuration reads");
        assert_eq!(text.matches(from).count(), 1, "{from}");
        std::fs::write(&self.config, text.replace(from, to)).expect("configuration writes");
    }

    fn check(&self, arguments: &[&str]) -> Outcome {
        let mut all = vec!["--runtime-config", path_text(&self.config), "check"];
        all.extend_from_slice(arguments);
        run(&all)
    }

    /// The JSON report `check --format json` writes.
    fn report(&self) -> (Option<i32>, Value) {
        let outcome = self.check(&["--format", "json"]);
        assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
        let report = serde_json::from_str(&outcome.stdout).expect("the report is JSON");
        (outcome.code, report)
    }

    /// Run `serve` with a startup that fails before the listener binds.
    fn serve_failing(&self, level: &str) -> Outcome {
        let output = Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
            .args(["--runtime-config", path_text(&self.config), "serve"])
            .env("BREG_MCP_LOG", level)
            .output()
            .expect("breg-mcp runs");
        Outcome::of(&output)
    }
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Outcome {
    fn of(output: &std::process::Output) -> Self {
        Self {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn run(arguments: &[&str]) -> Outcome {
    let output = Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
        .args(arguments)
        .env_remove("BREG_MCP_LOG")
        .output()
        .expect("breg-mcp runs");
    Outcome::of(&output)
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary paths are UTF-8")
}

fn codes(report: &Value) -> Vec<(&str, &str)> {
    report["diagnostics"]
        .as_array()
        .expect("the report lists its diagnostics")
        .iter()
        .map(|diagnostic| {
            (
                diagnostic["code"].as_str().expect("code"),
                diagnostic["path"].as_str().expect("path"),
            )
        })
        .collect()
}

#[test]
fn a_valid_configuration_checks_offline_without_reading_its_secrets() {
    let project = Project::new();
    // `check` resolves no secret, so it passes with every secret file gone.
    for name in ["gateway-key", "audit-key"] {
        std::fs::remove_file(project.directory.path().join("secrets").join(name))
            .expect("secret removes");
    }
    let outcome = project.check(&[]);
    assert_eq!(outcome.code, Some(0), "{}", outcome.output());
    assert_eq!(outcome.stdout, "0 errors, 0 warnings in 1 file\n");
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    // `check` writes nothing: the audit log is opened only by `serve`.
    assert!(!project.directory.path().join("audit").exists());

    let (code, report) = project.report();
    assert_eq!(code, Some(0));
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/breg/mcp-ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "BRegMcpCtlReport");
    assert_eq!(report["command"], "check");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["ok"], true);
    assert_eq!(report["filesChecked"], 1);
    assert!(codes(&report).is_empty(), "{report}");
}

#[test]
fn a_refused_configuration_reports_every_finding_by_code() {
    let project = Project::new();
    // Decoding stops at the first refused value; once the file decodes,
    // every semantic finding is reported together.
    project.rewrite("bind: 127.0.0.1:8110", "bind: 203.0.113.9:8110");
    project.rewrite("ownerField: owner", "ownerField: address");
    let (code, report) = project.report();
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "domain-refusal");
    assert_eq!(report["ok"], false);
    assert_eq!(
        codes(&report),
        [
            ("breg.mcp-runtime.public-bind", "/listener/bind"),
            (
                "breg.mcp-runtime.owner-field-is-target",
                "/service/application/ownerField"
            ),
        ]
    );

    let outcome = project.check(&[]);
    assert_eq!(outcome.code, Some(1));
    assert!(outcome.stdout.is_empty(), "{}", outcome.stdout);
    assert!(
        outcome
            .stderr
            .starts_with("breg-mcp check refused the input.\n"),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.ends_with("2 errors, 0 warnings in 1 file\n"),
        "{}",
        outcome.stderr
    );
}

#[test]
fn an_unreadable_runtime_file_is_an_operational_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let missing = directory
        .path()
        .canonicalize()
        .expect("temporary directory canonicalizes")
        .join("absent.yaml");
    let outcome = run(&[
        "--runtime-config",
        path_text(&missing),
        "check",
        "--format",
        "json",
    ]);
    assert_eq!(outcome.code, Some(3), "{}", outcome.output());
    let report: Value = serde_json::from_str(&outcome.stdout).expect("the report is JSON");
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        codes(&report),
        [("platform.runtime-config.unavailable", "")]
    );
}

#[test]
fn check_names_a_relative_runtime_file_as_given() {
    let project = Project::new();
    project.rewrite("accessProfile: citizen-agent", "accessProfile: Citizen");
    let output = Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
        .current_dir(project.directory.path())
        .args([
            "--runtime-config",
            "runtime.yaml",
            "check",
            "--format",
            "json",
        ])
        .output()
        .expect("breg-mcp runs");
    let report: Value = serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert_eq!(report["diagnostics"][0]["source"]["file"], "runtime.yaml");
}

#[test]
fn an_inline_credential_is_refused_without_echoing_it() {
    let project = Project::new();
    project.rewrite(
        "privateKeyRef: secret:file/gateway-key",
        &format!("privateKeyRef: {CANARY}"),
    );
    let outcome = project.check(&[]);
    assert_eq!(outcome.code, Some(1));
    assert!(
        outcome.stderr.contains("/exchange/privateKeyRef"),
        "{}",
        outcome.stderr
    );
    assert!(!outcome.output().contains(CANARY), "{}", outcome.output());
    let (_, report) = project.report();
    assert!(!report.to_string().contains(CANARY), "{report}");

    // `serve` refuses the same file before it starts, in the same shape.
    let served = project.serve_failing("info");
    assert_eq!(served.code, Some(1));
    assert!(served.stdout.is_empty(), "{}", served.stdout);
    assert!(
        served
            .stderr
            .starts_with("breg-mcp: the runtime configuration was refused\n"),
        "{}",
        served.stderr
    );
    assert!(
        served.stderr.contains("/exchange/privateKeyRef"),
        "{}",
        served.stderr
    );
    assert!(!served.stderr.contains(CANARY), "{}", served.stderr);
}

/// The single startup failure `serve` logs, as one JSON line on standard
/// output.
fn startup_failure(outcome: &Outcome) -> String {
    assert_eq!(outcome.code, Some(1), "{}", outcome.output());
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    let lines: Vec<Value> = outcome
        .stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each log line is JSON"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["level"], "ERROR");
    lines[0]["fields"]["message"]
        .as_str()
        .expect("message")
        .to_owned()
}

#[test]
fn serve_refuses_a_secret_file_others_can_read() {
    let project = Project::new();
    let key = project.directory.path().join("secrets").join("gateway-key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))
        .expect("permissions change");
    // `check` reads no secret, so only `serve` can refuse the file mode.
    assert_eq!(project.check(&[]).code, Some(0));
    let outcome = project.serve_failing("warn");
    let message = startup_failure(&outcome);
    assert!(message.contains("could not be resolved"), "{message}");
    assert!(!message.contains("secret:file/gateway-key"), "{message}");
    assert!(!outcome.output().contains(&project.key_secret));
    assert!(!project.directory.path().join("audit").exists());
}

#[test]
fn serve_names_the_member_but_not_the_reference_of_a_missing_secret() {
    let project = Project::new();
    std::fs::remove_file(project.directory.path().join("secrets").join("audit-key"))
        .expect("secret removes");
    let message = startup_failure(&project.serve_failing("error"));
    assert!(message.contains("could not be resolved"), "{message}");
    assert!(!message.contains("secret:file/audit-key"), "{message}");
}

/// `BREG_MCP_LOG` is a closed level, not a filter: `error`, `warn`, or
/// `info`, with the log as JSON lines on standard output. Anything else is
/// refused by `serve` with exit status 2 before any work, so a typo can
/// neither silence the log nor turn on a dependency's. `check` logs nothing
/// and reads no level.
#[test]
fn the_log_level_vocabulary_is_closed() {
    let project = Project::new();
    for refused in [
        "debug",
        "trace",
        "off",
        "INFO",
        "",
        "registry_breg_mcp=info",
    ] {
        let outcome = project.serve_failing(refused);
        assert_eq!(outcome.code, Some(2), "{refused:?}");
        assert!(outcome.stdout.is_empty(), "{refused:?}");
        assert_eq!(
            outcome.stderr, "breg-mcp: BREG_MCP_LOG must be one of error, warn, or info\n",
            "{refused:?}"
        );
        assert!(!project.directory.path().join("audit").exists());
    }

    let output = Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
        .args(["--runtime-config", path_text(&project.config), "check"])
        .env("BREG_MCP_LOG", "debug")
        .output()
        .expect("breg-mcp runs");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"0 errors, 0 warnings in 1 file\n");
}

#[test]
fn the_runtime_configuration_is_required() {
    let outcome = run(&["check"]);
    assert_eq!(outcome.code, Some(2));
    assert!(
        outcome.stderr.contains("--runtime-config"),
        "{}",
        outcome.stderr
    );
}

#[test]
fn the_runtime_configuration_is_named_before_the_subcommand() {
    let outcome = run(&["check", "--runtime-config", "/etc/breg-mcp/runtime.yaml"]);
    assert_eq!(outcome.code, Some(2));
    assert!(
        outcome
            .stderr
            .contains("unexpected argument '--runtime-config'"),
        "{}",
        outcome.stderr
    );
}

#[test]
fn serve_answers_health_and_stops_on_terminate() {
    use std::io::{Read as _, Write as _};

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("free port")
        .local_addr()
        .expect("port")
        .port();
    let project = Project::new();
    project.rewrite("bind: 127.0.0.1:8110", &format!("bind: 127.0.0.1:{port}"));
    project.rewrite(
        "resource: http://127.0.0.1:8110/mcp",
        &format!("resource: http://127.0.0.1:{port}/mcp"),
    );
    let child = Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
        .args(["--runtime-config", path_text(&project.config), "serve"])
        .env_remove("BREG_MCP_LOG")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("breg-mcp starts");
    // Retry until an HTTP answer arrives: under load a first connection can
    // close before the server answers it.
    let mut answer = String::new();
    for _ in 0..100 {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            answer.clear();
            let written = stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            if written.is_ok()
                && stream.read_to_string(&mut answer).is_ok()
                && answer.starts_with("HTTP/")
            {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let terminated = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(terminated.success());
    let output = child.wait_with_output().expect("breg-mcp exits");
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}\n{logs}");
    assert!(answer.contains(r#"{"status":"alive"}"#), "{answer}");
    assert!(output.status.success(), "{logs}");
    assert!(logs.contains("gateway listening"), "{logs}");
    assert!(logs.contains("shutting down"), "{logs}");
    assert!(!logs.contains(&project.key_secret));
    assert!(!logs.contains(gateway::AUDIT_KEY));
}
