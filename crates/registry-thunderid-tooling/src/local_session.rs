//! Bounded local issuer startup shared by adopter CLIs. Only public discovery
//! and verification keys leave this module; captured command output does not.
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::bootstrap::{Bootstrap, CommandOutcome, CommandRunner, SCHEMA_MOUNT_POINT};
use crate::container::{random_urlsafe, write_owner_only, Session};
use crate::ToolingError;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PUBLIC_RESPONSE: usize = 256 * 1024;

fn cancelled_error() -> ToolingError {
    ToolingError::CommandFailed {
        step: "local issuer startup was cancelled",
    }
}

struct DockerRunner<'a> {
    docker: &'a Path,
    cancelled: &'a mut dyn FnMut() -> bool,
}
impl CommandRunner for DockerRunner<'_> {
    fn run(
        &mut self,
        _: &str,
        args: &[String],
        secret_environment: &[(String, PathBuf)],
    ) -> Result<CommandOutcome, ToolingError> {
        if (self.cancelled)() {
            return Err(cancelled_error());
        }
        let mut command = Command::new(self.docker);
        let mut flags = Vec::new();
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
            command.env(name, value.trim_end_matches('\n'));
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
            .stderr(if diagnostics {
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
                    return Vec::new();
                }
            }
            captured
        });
        let diagnostic_drain = stderr.map(|mut stderr| {
            std::thread::spawn(move || {
                let mut captured = Vec::new();
                let mut buffer = [0u8; 2048];
                while let Ok(n) = stderr.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    captured.extend_from_slice(&buffer[..n]);
                    if captured.len() > 4096 {
                        captured.drain(..captured.len() - 4096);
                    }
                }
                captured
            })
        });
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status.success()),
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
                };
                let _ = cleanup.run("docker", &["rm".into(), "-f".into(), name], &[]);
            }
        }
        let bytes = drain.join().unwrap_or_default();
        if diagnostics && !result.as_ref().is_ok_and(|success| *success) {
            let diagnostic = diagnostic_drain
                .and_then(|drain| drain.join().ok())
                .unwrap_or_default();
            let bounded: String = String::from_utf8_lossy(&diagnostic)
                .chars()
                .rev()
                .take(600)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            eprintln!("issuer diagnostics: {bounded}");
        } else if let Some(drain) = diagnostic_drain {
            let _ = drain.join();
        }
        Ok(CommandOutcome {
            success: result?,
            container_ids: String::from_utf8(bytes).unwrap_or_default(),
        })
    }
}

/// Start already-rendered local state and return a bounded public RS256 JWKS
/// snapshot. Every restart reprovisions the authored registrations, preserves
/// retained databases/keys, and reads discovery from the exact numeric loopback
/// origin. A true cancellation callback aborts and cleans up only this session.
pub fn start(
    session: &Session<'_>,
    docker: &Path,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Value, ToolingError> {
    let result = start_inner(session, docker, cancelled);
    if result.is_err() {
        let _ = stop(session, docker);
    }
    result
}

fn start_inner(
    session: &Session<'_>,
    docker: &Path,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Value, ToolingError> {
    let mut runner = DockerRunner { docker, cancelled };
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
    let issuer = format!("http://127.0.0.1:{}", session.port);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ToolingError::Unreachable {
            step: "local HTTP runtime could not start",
        })?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| ToolingError::Unreachable {
            step: "local HTTP client could not start",
        })?;
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if (runner.cancelled)() {
            return Err(cancelled_error());
        }
        if let Ok(discovery) = runtime.block_on(public_json(
            &http,
            &format!("{issuer}/.well-known/openid-configuration"),
        )) {
            return runtime.block_on(snapshot(&http, &issuer, &discovery));
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

async fn snapshot(
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
        if !ids.insert(kid) || key["kty"] != "RSA" || key.get("d").is_some() {
            return Err(refusal());
        }
        let public =
            json!({"kty":"RSA","kid":kid,"alg":"RS256","use":"sig","n":key["n"],"e":key["e"]});
        registry_platform_crypto::PublicJwk::parse(&public.to_string()).map_err(|_| refusal())?;
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
    #[test]
    fn a_cancelled_runner_never_executes_the_engine() {
        let mut runner = DockerRunner {
            docker: Path::new("/does-not-exist"),
            cancelled: &mut || true,
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
    fn jwks_without_the_pinned_signing_algorithm_is_refused() {
        assert!(public_rsa_keys(&json!({"keys":[]})).is_err());
        assert!(public_rsa_keys(&json!({"keys":[{"alg":"ES256"}]})).is_err());
        assert!(public_rsa_keys(
            &json!({"keys":[{"alg":"RS256","kid":"one","kty":"RSA","d":"forbidden"}]})
        )
        .is_err());
    }
}
