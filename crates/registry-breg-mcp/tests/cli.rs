// SPDX-License-Identifier: Apache-2.0

//! The `breg-mcp` binary as an operator runs it: `check` validates a runtime
//! configuration and resolves its secrets without opening a socket, and every
//! refusal names the field, never the value.

#[path = "support/gateway.rs"]
mod gateway;
#[path = "support/mock_registry.rs"]
mod mock_registry;

use std::{os::unix::fs::PermissionsExt as _, path::Path, process::Command};

use gateway::{document, write_secrets, Document, Limits, REVIEW_BASE_URL};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
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
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
        let secrets = write_secrets(directory.path(), &key);
        let text = document(&Document {
            listen: "127.0.0.1:8110",
            resource: "http://127.0.0.1:8110/mcp",
            issuer: "http://127.0.0.1:8111",
            jwks: "http://127.0.0.1:8111/jwks.json",
            registry: "http://127.0.0.1:8112/",
            token_endpoint: "http://127.0.0.1:8111/token",
            review: REVIEW_BASE_URL,
            secrets: &secrets,
            audit: &directory.path().join("audit").join("audit.jsonl"),
            limits: Limits::default(),
        });
        let config = directory.path().join("runtime.yaml");
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

    fn check(&self) -> Outcome {
        run(&["--runtime-config", path_text(&self.config), "check"])
    }
}

struct Outcome {
    success: bool,
    output: String,
}

fn run(arguments: &[&str]) -> Outcome {
    let output = Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
        .args(arguments)
        .env_remove("BREG_MCP_LOG")
        .output()
        .expect("breg-mcp runs");
    Outcome {
        success: output.status.success(),
        output: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary paths are UTF-8")
}

#[test]
fn a_valid_configuration_checks_without_disclosing_its_secrets() {
    let project = Project::new();
    let outcome = project.check();
    assert!(outcome.success, "{}", outcome.output);
    assert!(outcome.output.contains("configuration is valid"));
    assert!(!outcome.output.contains(&project.key_secret));
    assert!(!outcome.output.contains(gateway::AUDIT_KEY));
    // `check` writes nothing: the audit log is opened only by `serve`.
    assert!(!project.directory.path().join("audit").exists());
}

fn check_with_log(project: &Project, level: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_breg-mcp"))
        .args(["--runtime-config", path_text(&project.config), "check"])
        .env("BREG_MCP_LOG", level)
        .output()
        .expect("breg-mcp runs")
}

/// `BREG_MCP_LOG` is a closed level, not a filter: `error`, `warn`, or
/// `info`, with the log as JSON lines on standard output. Anything else is
/// refused with exit status 2 before any work, so a typo can neither silence
/// the log nor turn on a dependency's.
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
        let output = check_with_log(&project, refused);
        assert_eq!(output.status.code(), Some(2), "{refused:?}");
        assert!(output.stdout.is_empty(), "{refused:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "breg-mcp: BREG_MCP_LOG must be one of error, warn, or info\n",
            "{refused:?}"
        );
    }

    let info = check_with_log(&project, "info");
    assert!(info.status.success());
    assert!(info.stderr.is_empty());
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&info.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("each log line is JSON"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["level"], "INFO");
    assert_eq!(lines[0]["fields"]["message"], "configuration is valid");

    for quiet in ["warn", "error"] {
        let output = check_with_log(&project, quiet);
        assert!(output.status.success(), "{quiet}");
        assert!(output.stdout.is_empty(), "{quiet}");
        assert!(output.stderr.is_empty(), "{quiet}");
    }
}

#[test]
fn an_inline_credential_is_refused_without_echoing_it() {
    let project = Project::new();
    project.rewrite(
        "privateKeyRef: secret:file/gateway-key",
        &format!("privateKeyRef: {CANARY}"),
    );
    let outcome = project.check();
    assert!(!outcome.success);
    assert!(
        outcome.output.contains("exchange.privateKeyRef"),
        "{}",
        outcome.output
    );
    assert!(!outcome.output.contains(CANARY), "{}", outcome.output);
}

#[test]
fn a_secret_file_others_can_read_is_refused() {
    let project = Project::new();
    let key = project.directory.path().join("secrets").join("gateway-key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))
        .expect("permissions change");
    let outcome = project.check();
    assert!(!outcome.success);
    assert!(
        outcome.output.contains("exchange.privateKeyRef"),
        "{}",
        outcome.output
    );
    assert!(!outcome.output.contains(&project.key_secret));
}

#[test]
fn a_missing_secret_names_the_field() {
    let project = Project::new();
    std::fs::remove_file(project.directory.path().join("secrets").join("audit-key"))
        .expect("secret removes");
    let outcome = project.check();
    assert!(!outcome.success);
    assert!(
        outcome.output.contains("audit.hashKeyRef"),
        "{}",
        outcome.output
    );
}

#[test]
fn the_runtime_configuration_is_required() {
    let outcome = run(&["check"]);
    assert!(!outcome.success);
    assert!(
        outcome.output.contains("--runtime-config"),
        "{}",
        outcome.output
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
