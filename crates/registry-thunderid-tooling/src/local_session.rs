//! Bounded local issuer startup shared by adopter CLIs. Only public discovery
//! and verification keys leave this module; captured command output does not,
//! except a first-run one-shot's, kept redacted in an owner-only log file.
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bootstrap::{
    Bootstrap, CommandOutcome, CommandRunner, OneShotOutcome, SCHEMA_MOUNT_POINT,
};
use crate::container::{random_urlsafe, write_owner_only, Session};
use crate::ToolingError;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const PUBLIC_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PUBLIC_RESPONSE: usize = 256 * 1024;

fn cancelled_error() -> ToolingError {
    ToolingError::CommandFailed {
        step: "local issuer startup was cancelled",
    }
}

/// The most output kept from one stream of a first-run one-shot. A longer
/// stream keeps its tail, which is where a failure is reported.
const MAX_KEPT_STREAM: usize = 256 * 1024;
/// What replaces a secret value, or a whole line carrying a credential the
/// pinned release generated itself, before kept output reaches disk.
const REDACTED: &str = "[redacted]";
/// Fragments of the lines the pinned release's `setup.sh` prints beside a
/// credential it generated: the administrator notice (printed only when no
/// password is supplied, so this guards a changed invocation) and the Direct
/// API secret it generates on a fresh state.
const GENERATED_CREDENTIAL_LINES: &[&str] = &["Password:", "Direct Auth Secret"];

#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

struct Executed {
    status: ExitStatus,
    stdout: Captured,
    stderr: Captured,
    /// The injected secret values, so kept output can be redacted.
    secrets: Vec<zeroize::Zeroizing<String>>,
}

/// Read a stream to its end, keeping at most `limit` trailing bytes.
fn drain_tail(mut stream: impl Read, limit: usize) -> Captured {
    let mut captured = Captured::default();
    let mut buffer = [0u8; 8192];
    while let Ok(n) = stream.read(&mut buffer) {
        if n == 0 {
            break;
        }
        captured.bytes.extend_from_slice(&buffer[..n]);
        if captured.bytes.len() > limit {
            captured.bytes.drain(..captured.bytes.len() - limit);
            captured.truncated = true;
        }
    }
    captured
}

/// Prepare one first-run one-shot's captured output for its owner-only log:
/// every occurrence of each injected secret value becomes [`REDACTED`], and
/// so does every whole line naming a credential the release generated. A
/// truncated capture first drops its partial leading line, which could hold
/// a fragment of a secret the value search cannot recognise.
fn redact_one_shot_output(captured: &[u8], truncated: bool, secrets: &[&str]) -> String {
    let mut text = String::from_utf8_lossy(captured).into_owned();
    if truncated {
        text = text
            .find('\n')
            .map(|end| text[end + 1..].to_owned())
            .unwrap_or_default();
    }
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        text = text.replace(secret, REDACTED);
    }
    text.split_inclusive('\n')
        .map(|line| {
            if GENERATED_CREDENTIAL_LINES
                .iter()
                .any(|fragment| line.contains(fragment))
            {
                if line.ends_with('\n') {
                    "[redacted]\n"
                } else {
                    REDACTED
                }
            } else {
                line
            }
        })
        .collect()
}

/// Write one first-run one-shot's already redacted output to a new
/// owner-only file in an owner-only directory, and return its path.
fn keep_one_shot_log(
    log_dir: &Path,
    one_shot: &str,
    redacted: &[u8],
) -> Result<PathBuf, ToolingError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    crate::container::ensure_owner_only_dir(log_dir)?;
    let suffix = random_urlsafe(12).map_err(|_| ToolingError::Filesystem {
        reason: "a one-shot log name could not be generated",
    })?;
    let path = log_dir.join(format!(
        "thunderid-{}.{suffix}.log",
        one_shot.replace(' ', "-")
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| ToolingError::Filesystem {
            reason: "a one-shot log could not be created",
        })?;
    file.write_all(redacted)
        .map_err(|_| ToolingError::Filesystem {
            reason: "a one-shot log could not be written",
        })?;
    Ok(path)
}

struct DockerRunner<'a> {
    docker: &'a Path,
    cancelled: &'a mut dyn FnMut() -> bool,
    /// Where first-run one-shot output is kept, redacted and owner-only.
    log_dir: Option<&'a Path>,
}
impl CommandRunner for DockerRunner<'_> {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
    ) -> Result<CommandOutcome, ToolingError> {
        self.run_with_timeout(program, args, secret_environment, COMMAND_TIMEOUT)
    }

    fn run_with_timeout(
        &mut self,
        _: &str,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
        timeout: Duration,
    ) -> Result<CommandOutcome, ToolingError> {
        let executed = self.execute(args, secret_environment, timeout, false)?;
        Ok(CommandOutcome {
            success: executed.status.success(),
            container_ids: String::from_utf8(executed.stdout.bytes).unwrap_or_default(),
        })
    }

    /// Keep both streams, redacted, in a new owner-only file under the log
    /// directory. `REGISTRY_THUNDERID_TOOLING_DIAGNOSTICS` keeps its meaning
    /// here: it adds a stderr tail only for a command without a secret.
    fn run_one_shot(
        &mut self,
        one_shot: &'static str,
        _: &str,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
    ) -> Result<OneShotOutcome, ToolingError> {
        let Some(log_dir) = self.log_dir else {
            let executed = self.execute(args, secret_environment, COMMAND_TIMEOUT, false)?;
            return Ok(OneShotOutcome {
                success: executed.status.success(),
                exit_code: executed.status.code(),
                log_file: None,
            });
        };
        let executed = self.execute(args, secret_environment, COMMAND_TIMEOUT, true)?;
        let secrets: Vec<&str> = executed
            .secrets
            .iter()
            .map(|value| value.as_str())
            .collect();
        let mut kept = format!(
            "{}\n\n-- stdout --\n",
            crate::container::one_shot_report(one_shot, executed.status.code(), None)
        );
        kept.push_str(&redact_one_shot_output(
            &executed.stdout.bytes,
            executed.stdout.truncated,
            &secrets,
        ));
        kept.push_str("\n-- stderr --\n");
        kept.push_str(&redact_one_shot_output(
            &executed.stderr.bytes,
            executed.stderr.truncated,
            &secrets,
        ));
        let log_file = keep_one_shot_log(log_dir, one_shot, kept.as_bytes())?;
        Ok(OneShotOutcome {
            success: executed.status.success(),
            exit_code: executed.status.code(),
            log_file: Some(log_file),
        })
    }
}

impl DockerRunner<'_> {
    /// Run one engine command. `keep` captures both streams (a bounded tail
    /// of each) for a kept one-shot; otherwise only `docker ps` output is
    /// captured. A stderr tail is printed only when diagnostics are requested
    /// for a failed command without a secret.
    fn execute(
        &mut self,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
        timeout: Duration,
        keep: bool,
    ) -> Result<Executed, ToolingError> {
        if (self.cancelled)() {
            return Err(cancelled_error());
        }
        let mut command = Command::new(self.docker);
        let mut flags = Vec::new();
        let mut secrets = Vec::new();
        for (name, file) in secret_environment {
            let metadata =
                std::fs::symlink_metadata(file).map_err(|_| ToolingError::Filesystem {
                    reason: "an issuer secret file cannot be inspected",
                })?;
            if !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.len() > 16 * 1024
            {
                return Err(ToolingError::Filesystem {
                    reason: "issuer secret files must be bounded owner-only ordinary files",
                });
            }
            let value = std::fs::read_to_string(file).map_err(|_| ToolingError::Filesystem {
                reason: "an issuer secret file cannot be read",
            })?;
            let value = zeroize::Zeroizing::new(value.trim_end_matches('\n').to_owned());
            command.env(name, value.as_str());
            secrets.push(value);
            flags.extend(["-e".to_owned(), name.clone()]);
        }
        let one_shot =
            args.first().is_some_and(|arg| arg == "run") && args.iter().any(|arg| arg == "--rm");
        let command_name = if one_shot {
            let name = format!(
                "thunderid-local-command-{}",
                random_urlsafe(16).map_err(|_| ToolingError::CommandFailed {
                    step: "local command identity generation failed"
                })?
            );
            flags.extend(["--name".into(), name.clone()]);
            Some(name)
        } else {
            None
        };
        if args.first().is_some_and(|arg| arg == "run") {
            command.arg("run").args(&flags).args(&args[1..]);
        } else {
            command.args(args);
        }
        let ids_only = args.first().is_some_and(|arg| arg == "ps");
        let diagnostics = secret_environment.is_empty()
            && std::env::var_os("REGISTRY_THUNDERID_TOOLING_DIAGNOSTICS").is_some();
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(if diagnostics || keep {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .spawn()
            .map_err(|_| ToolingError::CommandFailed {
                step: "the resolved container engine could not be executed",
            })?;
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take();
        let drain = std::thread::spawn(move || {
            if keep {
                return drain_tail(stdout, MAX_KEPT_STREAM);
            }
            let mut captured = Vec::new();
            let mut buffer = [0u8; 8192];
            while let Ok(n) = stdout.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if ids_only && captured.len() + n <= 4096 {
                    captured.extend_from_slice(&buffer[..n]);
                } else if ids_only {
                    captured.clear();
                    return Captured::default();
                }
            }
            Captured {
                bytes: captured,
                truncated: false,
            }
        });
        let stderr_limit = if keep { MAX_KEPT_STREAM } else { 4096 };
        let diagnostic_drain =
            stderr.map(|stderr| std::thread::spawn(move || drain_tail(stderr, stderr_limit)));
        let deadline = Instant::now() + timeout;
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(_) => {
                    break Err(ToolingError::CommandFailed {
                        step: "the container command status could not be read",
                    })
                }
            }
            if (self.cancelled)() {
                break Err(cancelled_error());
            }
            if Instant::now() >= deadline {
                break Err(ToolingError::CommandFailed {
                    step: "the container command exceeded its time limit",
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            // A one-shot has an unguessable name assigned by this exact run.
            // No other container is selected, and all session mounts survive.
            if let Some(name) = command_name {
                let mut cleanup = DockerRunner {
                    docker: self.docker,
                    cancelled: &mut || false,
                    log_dir: None,
                };
                let _ = cleanup.run("docker", &["rm".into(), "-f".into(), name], &[]);
            }
        }
        let stdout = drain.join().unwrap_or_default();
        let stderr = diagnostic_drain
            .and_then(|drain| drain.join().ok())
            .unwrap_or_default();
        if diagnostics && !result.as_ref().is_ok_and(|status| status.success()) {
            let bounded: String = String::from_utf8_lossy(&stderr.bytes)
                .chars()
                .rev()
                .take(600)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            eprintln!("issuer diagnostics: {bounded}");
        }
        Ok(Executed {
            status: result?,
            stdout,
            stderr,
            secrets,
        })
    }
}

/// Start already-rendered local state and return a bounded public RS256 JWKS
/// snapshot. Every restart reprovisions the authored registrations, preserves
/// retained databases/keys, and reads discovery from the exact numeric loopback
/// origin. A true cancellation callback aborts and cleans up only this session.
/// First-run one-shot output is kept, redacted, under the session state's
/// `logs` directory.
pub fn start(
    session: &Session<'_>,
    docker: &Path,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Value, ToolingError> {
    start_with_logs(session, docker, cancelled, &session.state_root.join("logs"))
}

/// [`start`], keeping each first-run one-shot's redacted output in a new
/// owner-only file under `log_dir`, a private directory the caller chooses.
pub fn start_with_logs(
    session: &Session<'_>,
    docker: &Path,
    cancelled: &mut dyn FnMut() -> bool,
    log_dir: &Path,
) -> Result<Value, ToolingError> {
    let result = start_inner(session, docker, cancelled, log_dir);
    if result.is_err() {
        let _ = stop(session, docker);
    }
    result
}

fn start_inner(
    session: &Session<'_>,
    docker: &Path,
    cancelled: &mut dyn FnMut() -> bool,
    log_dir: &Path,
) -> Result<Value, ToolingError> {
    let mut runner = DockerRunner {
        docker,
        cancelled,
        log_dir: Some(log_dir),
    };
    session.prepare(&mut runner)?;
    let password = session
        .state_root
        .join("secrets/throwaway-bootstrap-password");
    if !password.exists() {
        write_owner_only(
            &password,
            random_urlsafe(32)
                .map_err(|_| ToolingError::Filesystem {
                    reason: "bootstrap credential generation failed",
                })?
                .as_bytes(),
        )?;
    }
    let bootstrap_dir = session.state_root.join(crate::render::BOOTSTRAP_DIR);
    Bootstrap {
        runner: &mut runner,
        image: session.image,
    }
    .apply_agent_schema(
        &bootstrap_dir,
        &password,
        &[
            (
                session.state_root.join("database"),
                "/opt/thunderid/database".into(),
            ),
            (
                session.state_root.join("certs"),
                "/opt/thunderid/config/certs".into(),
            ),
            (
                session.state_root.join("secrets"),
                "/opt/thunderid/config/secrets".into(),
            ),
            (
                session.state_root.join("deployment.yaml"),
                "/opt/thunderid/deployment.yaml".into(),
            ),
            (bootstrap_dir.clone(), SCHEMA_MOUNT_POINT.into()),
            (
                session.state_root.join("resources"),
                "/opt/thunderid/config/resources".into(),
            ),
        ],
    )?;
    session.start(&mut runner)?;
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if (runner.cancelled)() {
            return Err(cancelled_error());
        }
        if let Some(snapshot) = blocking_ready_snapshot(session.port)? {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return Err(ToolingError::Unreachable {
                step: "the issuer did not answer discovery within 120 seconds",
            });
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Stop only the container whose two ownership labels and exact name match
/// this session. Missing state/containers are already stopped; retained files
/// are never removed.
pub fn stop(session: &Session<'_>, docker: &Path) -> Result<(), ToolingError> {
    session.stop(&mut DockerRunner {
        docker,
        cancelled: &mut || false,
        log_dir: None,
    })
}

async fn public_json(http: &reqwest::Client, url: &str) -> Result<Value, ToolingError> {
    let refusal = || ToolingError::Unreachable {
        step: "the local public issuer endpoint did not return bounded JSON",
    };
    let mut response = http.get(url).send().await.map_err(|_| refusal())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(refusal());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| refusal())? {
        if bytes.len() + chunk.len() > MAX_PUBLIC_RESPONSE {
            return Err(refusal());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| refusal())
}

fn public_http_client() -> Result<reqwest::Client, ToolingError> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PUBLIC_HTTP_TIMEOUT)
        .connect_timeout(PUBLIC_CONNECT_TIMEOUT)
        .build()
        .map_err(|_| ToolingError::Unreachable {
            step: "local HTTP client could not start",
        })
}

/// Read the bounded public RS256 verification-key snapshot from an existing
/// local issuer. The numeric loopback origin and both endpoint paths are fixed
/// here; this operation starts, stops, and otherwise changes no lifecycle.
pub async fn snapshot(port: u16) -> Result<serde_json::Value, ToolingError> {
    let issuer = local_issuer(port)?;
    let http = public_http_client()?;
    let discovery =
        public_json(&http, &format!("{issuer}/.well-known/openid-configuration")).await?;
    snapshot_from_discovery(&http, &issuer, &discovery).await
}

fn local_issuer(port: u16) -> Result<String, ToolingError> {
    if port == 0 {
        return Err(ToolingError::Unreachable {
            step: "the local issuer port must be nonzero",
        });
    }
    Ok(format!("http://127.0.0.1:{port}"))
}

async fn ready_snapshot(port: u16) -> Result<Option<Value>, ToolingError> {
    let issuer = local_issuer(port)?;
    let http = public_http_client()?;
    let discovery =
        match public_json(&http, &format!("{issuer}/.well-known/openid-configuration")).await {
            Ok(discovery) => discovery,
            Err(_) => return Ok(None),
        };
    snapshot_from_discovery(&http, &issuer, &discovery)
        .await
        .map(Some)
}

/// Run one asynchronous snapshot attempt on its own runtime thread. `start`
/// is synchronous and is called both outside and inside Tokio executors, so it
/// must not construct and enter a nested runtime on its caller's thread.
fn blocking_ready_snapshot(port: u16) -> Result<Option<Value>, ToolingError> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ToolingError::Unreachable {
                step: "local HTTP runtime could not start",
            })?;
        runtime.block_on(ready_snapshot(port))
    })
    .join()
    .map_err(|_| ToolingError::Unreachable {
        step: "local HTTP snapshot worker failed",
    })?
}

async fn snapshot_from_discovery(
    http: &reqwest::Client,
    issuer: &str,
    discovery: &Value,
) -> Result<Value, ToolingError> {
    let jwks_uri = format!("{issuer}/oauth2/jwks");
    if discovery["issuer"] != issuer || discovery["jwks_uri"] != jwks_uri {
        return Err(ToolingError::Unreachable {
            step: "discovery did not bind the exact local issuer and JWKS endpoint",
        });
    }
    let jwks = public_json(http, &jwks_uri).await?;
    public_rsa_keys(&jwks)
}

fn public_rsa_keys(jwks: &Value) -> Result<Value, ToolingError> {
    let refusal = || ToolingError::Unreachable {
        step: "the issuer JWKS has no bounded distinct RS256 verification key set",
    };
    let entries = jwks["keys"].as_array().ok_or_else(refusal)?;
    if entries.len() > 32 {
        return Err(refusal());
    }
    let mut ids = BTreeSet::new();
    let mut keys = Vec::new();
    for key in entries.iter().filter(|key| key["alg"] == "RS256") {
        let kid = key["kid"]
            .as_str()
            .filter(|kid| !kid.is_empty() && kid.len() <= 256)
            .ok_or_else(refusal)?;
        let verification_operations = match key.get("key_ops") {
            None => true,
            Some(Value::Array(operations)) => operations.len() == 1 && operations[0] == "verify",
            Some(_) => false,
        };
        if !ids.insert(kid)
            || key["kty"] != "RSA"
            || key["use"] != "sig"
            || !verification_operations
        {
            return Err(refusal());
        }
        registry_platform_crypto::PublicJwk::parse(&key.to_string()).map_err(|_| refusal())?;
        let public =
            json!({"kty":"RSA","kid":kid,"alg":"RS256","use":"sig","n":key["n"],"e":key["e"]});
        keys.push(public);
    }
    if keys.is_empty() || keys.len() > 16 {
        return Err(refusal());
    }
    Ok(json!({"keys":keys}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const RSA_MODULUS: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn serve(responses: Vec<Vec<u8>>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        assert!(request.len() < 32 * 1024);
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                    }
                    stream.write_all(&response).unwrap();
                    String::from_utf8(request).unwrap()
                })
                .collect()
        });
        (port, worker)
    }

    fn rsa_key() -> Value {
        json!({
            "kty":"RSA",
            "kid":"issuer-signing",
            "alg":"RS256",
            "use":"sig",
            "n":RSA_MODULUS,
            "e":"AQAB",
            "x5c":["not-returned"]
        })
    }

    #[test]
    fn a_cancelled_runner_never_executes_the_engine() {
        let mut runner = DockerRunner {
            docker: Path::new("/does-not-exist"),
            cancelled: &mut || true,
            log_dir: None,
        };
        assert!(matches!(
            runner.run("docker", &["ps".into()], &[]),
            Err(ToolingError::CommandFailed {
                step: "local issuer startup was cancelled"
            })
        ));
    }
    #[test]
    fn secret_permissions_fail_before_starting_the_engine() {
        let path = std::env::temp_dir().join(format!(
            "issuer-secret-permissions-{}",
            random_urlsafe(12).unwrap()
        ));
        std::fs::write(&path, "synthetic-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut runner = DockerRunner {
            docker: Path::new("/does-not-exist"),
            cancelled: &mut || false,
            log_dir: None,
        };
        assert!(matches!(
            runner.run(
                "docker",
                &["run".into()],
                &[("ADMIN_PASSWORD".into(), path.clone())]
            ),
            Err(ToolingError::Filesystem { .. })
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn one_shot_output_redacts_every_secret_value_and_generated_credential_line() {
        let secret = "synthetic-admin-value-never-kept";
        let output = format!(
            "start {secret} middle{secret}\n\
             Direct Auth Secret (Direct API): 0123synthetic\n  \
             Password: generated-synthetic\n\
             plain diagnostic line\n"
        );

        let kept = redact_one_shot_output(output.as_bytes(), false, &[secret]);

        for value in [secret, "0123synthetic", "generated-synthetic"] {
            assert!(!kept.contains(value), "{kept}");
        }
        assert_eq!(kept.matches("[redacted]").count(), 4, "{kept}");
        assert!(kept.contains("plain diagnostic line"), "{kept}");

        // A bounded tail can start inside a secret. Its first, partial line
        // is dropped, so no fragment the value search cannot match survives.
        let fragment = &secret[7..];
        let tail = format!("{fragment} rest\nnext line\n");
        let kept = redact_one_shot_output(tail.as_bytes(), true, &[secret]);
        assert!(!kept.contains(fragment), "{kept}");
        assert!(kept.contains("next line"), "{kept}");
    }

    #[test]
    fn a_kept_one_shot_never_writes_a_secret_to_its_owner_only_log() {
        let root = std::env::temp_dir().join(format!(
            "issuer-one-shot-log-{}",
            random_urlsafe(12).unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let secret = "synthetic-admin-value-never-kept";
        let secret_file = root.join("admin-password");
        std::fs::write(&secret_file, format!("{secret}\n")).unwrap();
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A stand-in engine that prints the injected value on both streams,
        // and a generated credential the way the pinned setup.sh does.
        let engine = root.join("engine");
        std::fs::write(
            &engine,
            "#!/bin/sh\n\
             printf 'stdout before %s after\\n' \"$ADMIN_PASSWORD\"\n\
             printf 'Direct Auth Secret (Direct API): %s\\n' generated-synthetic-secret\n\
             printf 'stderr %s tail\\n' \"$ADMIN_PASSWORD\" >&2\n\
             exit 3\n",
        )
        .unwrap();
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o700)).unwrap();
        let logs = root.join("logs");
        let mut runner = DockerRunner {
            docker: &engine,
            cancelled: &mut || false,
            log_dir: Some(&logs),
        };

        let outcome = runner
            .run_one_shot(
                "setup",
                "docker",
                &[
                    "run".into(),
                    "--rm".into(),
                    "pinned-test-image".into(),
                    "./setup.sh".into(),
                ],
                &[("ADMIN_PASSWORD".into(), secret_file.clone())],
            )
            .unwrap();

        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, Some(3));
        let log = outcome.log_file.expect("the output is kept");
        assert_eq!(log.parent(), Some(logs.as_path()));
        // A separator the URL-safe suffix never contains keeps the name
        // readable whichever character the suffix starts with.
        let name = log.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("thunderid-setup.") && name.ends_with(".log"),
            "{name}"
        );
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&log), 0o600);
        assert_eq!(mode(&logs), 0o700);
        let kept = std::fs::read_to_string(&log).unwrap();
        assert!(!kept.contains(secret), "{kept}");
        assert!(!kept.contains("generated-synthetic-secret"), "{kept}");
        for fact in ["stdout before [redacted] after", "stderr [redacted] tail"] {
            assert!(kept.contains(fact), "{fact}: {kept}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn jwks_without_the_pinned_signing_algorithm_is_refused() {
        assert!(public_rsa_keys(&json!({"keys":[]})).is_err());
        assert!(public_rsa_keys(&json!({"keys":[{"alg":"ES256"}]})).is_err());
        assert!(public_rsa_keys(
            &json!({"keys":[{"alg":"RS256","kid":"one","kty":"RSA","d":"forbidden"}]})
        )
        .is_err());
    }

    #[test]
    fn jwks_refuses_non_signing_use_and_incompatible_key_operations() {
        let mut encryption = rsa_key();
        encryption["use"] = json!("enc");
        assert!(public_rsa_keys(&json!({"keys":[encryption]})).is_err());

        for operations in [
            json!(["sign"]),
            json!(["verify", "sign"]),
            json!(["encrypt"]),
            json!("verify"),
        ] {
            let mut incompatible = rsa_key();
            incompatible["key_ops"] = operations;
            assert!(public_rsa_keys(&json!({"keys":[incompatible]})).is_err());
        }

        let mut verification = rsa_key();
        verification["key_ops"] = json!(["verify"]);
        assert!(public_rsa_keys(&json!({"keys":[verification]})).is_ok());
    }

    #[tokio::test]
    async fn snapshot_reads_only_the_exact_loopback_public_rs256_key_set() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let discovery = serde_json::to_vec(&json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/oauth2/jwks"),
        }))
        .unwrap();
        let jwks = serde_json::to_vec(&json!({
            "keys": [
                rsa_key(),
                {"kty":"EC","kid":"ignored","alg":"ES256","d":"ignored-private"}
            ]
        }))
        .unwrap();
        let worker = std::thread::spawn(move || {
            [discovery, jwks]
                .into_iter()
                .map(|body| {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                    }
                    stream
                        .write_all(&response(
                            "200 OK",
                            "Content-Type: application/json\r\n",
                            &body,
                        ))
                        .unwrap();
                    String::from_utf8(request).unwrap()
                })
                .collect::<Vec<_>>()
        });

        let keys = snapshot(port).await.unwrap();
        assert_eq!(
            keys,
            json!({"keys":[{
                "kty":"RSA",
                "kid":"issuer-signing",
                "alg":"RS256",
                "use":"sig",
                "n":RSA_MODULUS,
                "e":"AQAB"
            }]})
        );
        let requests = worker.join().unwrap();
        assert!(requests[0].starts_with("GET /.well-known/openid-configuration HTTP/1.1"));
        assert!(requests[1].starts_with("GET /oauth2/jwks HTTP/1.1"));
    }

    #[tokio::test]
    async fn snapshot_refuses_discovery_for_another_issuer_or_jwks_path() {
        let wrong_issuer = serde_json::to_vec(&json!({
            "issuer":"http://127.0.0.1:1",
            "jwks_uri":"http://127.0.0.1:1/oauth2/jwks"
        }))
        .unwrap();
        let (port, worker) = serve(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &wrong_issuer,
        )]);
        assert!(snapshot(port).await.is_err());
        worker.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let wrong_path = serde_json::to_vec(&json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/another/path")
        }))
        .unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(&response(
                    "200 OK",
                    "Content-Type: application/json\r\n",
                    &wrong_path,
                ))
                .unwrap();
        });
        assert!(snapshot(port).await.is_err());
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn snapshot_does_not_follow_redirects() {
        let (port, worker) = serve(vec![response(
            "302 Found",
            "Location: /oauth2/jwks\r\n",
            b"",
        )]);
        assert!(snapshot(port).await.is_err());
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /.well-known/openid-configuration HTTP/1.1"));
    }

    #[tokio::test]
    async fn snapshot_refuses_private_rs256_keys_and_oversized_public_json() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let discovery = serde_json::to_vec(&json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/oauth2/jwks")
        }))
        .unwrap();
        let mut private = rsa_key();
        private["d"] = json!("forbidden");
        let jwks = serde_json::to_vec(&json!({"keys":[private]})).unwrap();
        let worker = std::thread::spawn(move || {
            for body in [discovery, jwks] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).unwrap();
                stream
                    .write_all(&response(
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        &body,
                    ))
                    .unwrap();
            }
        });
        assert!(snapshot(port).await.is_err());
        worker.join().unwrap();

        let oversized = vec![b' '; MAX_PUBLIC_RESPONSE + 1];
        let (port, worker) = serve(vec![response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &oversized,
        )]);
        assert!(snapshot(port).await.is_err());
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn snapshot_refuses_port_zero_without_making_a_request() {
        assert!(matches!(
            snapshot(0).await,
            Err(ToolingError::Unreachable {
                step: "the local issuer port must be nonzero"
            })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_snapshot_is_safe_inside_a_current_thread_runtime() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let discovery = serde_json::to_vec(&json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/oauth2/jwks")
        }))
        .unwrap();
        let jwks = serde_json::to_vec(&json!({"keys":[rsa_key()]})).unwrap();
        let worker = std::thread::spawn(move || {
            for body in [discovery, jwks] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).unwrap();
                stream
                    .write_all(&response(
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        &body,
                    ))
                    .unwrap();
            }
        });
        assert!(blocking_ready_snapshot(port).is_ok_and(|keys| keys.is_some()));
        worker.join().unwrap();
    }
}
