//! One development session's retained ThunderID container.
//!
//! The lifecycle rules are fixed: deterministic ownership labels plus a
//! persisted session id, numeric loopback publishing, one-time setup before
//! any resource that references the bootstrap organization is loaded,
//! retained state across stop/start, and a destructive reset that is a
//! separate, explicitly requested operation. An unrelated occupant of the
//! configured port is reported, never stopped or adopted.

use std::path::{Path, PathBuf};

use crate::bootstrap::CommandRunner;
use crate::ToolingError;

/// The ownership label every resource this session creates carries.
pub const SESSION_LABEL: &str = "registry.stack.thunderid.session";
/// The persistent identity label: present only on this session's resources.
pub const SESSION_ID_LABEL: &str = "registry.stack.thunderid.session-id";

/// The retained state of one development session, persisted owner-only under
/// the description's state root. Completion markers are written only after
/// the step they name has succeeded, so a partially initialized session is
/// diagnosable rather than silently restarted.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SessionState {
    pub setup_complete: bool,
    pub schema_applied: Option<String>,
    pub container_name: Option<String>,
}

pub struct Session<'a> {
    pub label: &'a str,
    pub id: &'a str,
    pub port: u16,
    pub state_root: &'a Path,
    pub image: &'a str,
}

impl Session<'_> {
    pub fn state_path(&self) -> PathBuf {
        self.state_root.join("session.json")
    }

    pub fn load_state(&self) -> Result<SessionState, ToolingError> {
        let bytes = std::fs::read(self.state_path()).map_err(|_| ToolingError::InvalidState {
            reason: "the session state file does not exist; run prepare before this step",
        })?;
        serde_json::from_slice(&bytes).map_err(|_| ToolingError::InvalidState {
            reason: "the session state file is not readable",
        })
    }

    fn save_state(&self, state: &SessionState) -> Result<(), ToolingError> {
        use std::os::unix::fs::PermissionsExt;
        // Session state is mutable bookkeeping, not a rendered document: the
        // completion markers it carries are updated as steps succeed, so
        // overwriting this one file is the intended behavior.
        std::fs::write(
            self.state_path(),
            serde_json::to_vec(state).expect("state serializes"),
        )
        .map_err(|_| ToolingError::Filesystem {
            reason: "the session state could not be written",
        })?;
        std::fs::set_permissions(self.state_path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|_| ToolingError::Filesystem {
                reason: "the session state could not be made owner-only",
            })?;
        Ok(())
    }

    /// One-time upstream setup: generate a private administrator credential,
    /// write the deployment configuration, and run the image's `setup.sh`
    /// with persistent mounts but without the runtime resource mounts, since
    /// the resources reference the organization unit setup creates.
    ///
    /// Setup stdout is discarded unread: the pinned release prints the
    /// administrator credential there, and this crate already holds that
    /// credential in its private file.
    pub fn prepare(&self, runner: &mut dyn CommandRunner) -> Result<(), ToolingError> {
        ensure_owner_only_dir(&self.state_root.join("secrets"))?;
        ensure_regular_dir(&self.state_root.join("database"))?;
        ensure_regular_dir(&self.state_root.join("certs"))?;
        if self.load_state().is_ok_and(|state| state.setup_complete) {
            return Ok(());
        }
        let admin_password_file = self.state_root.join("secrets/admin-password");
        if !admin_password_file.exists() {
            let secret = random_urlsafe(32).map_err(|_| ToolingError::Filesystem {
                reason: "the administrator credential could not be generated",
            })?;
            write_owner_only(&admin_password_file, secret.as_bytes())?;
        }
        let issuer = format!("http://127.0.0.1:{}", self.port);
        let deployment = deployment_yaml(&issuer);
        let deployment_file = self.state_root.join("deployment.yaml");
        if !deployment_file.exists() {
            write_owner_only(&deployment_file, deployment.as_bytes())?;
        }
        let database = self.state_root.join("database");
        // Every bind source must exist before the engine will mount it;
        // setup.sh fills `certs` with the signing material it generates.
        // Seed the shipped schema into a fresh session's database directory.
        // The image's databases carry the table layout setup.sh's bootstrap
        // writes into; an empty directory has no tables and setup cannot
        // create them. The copy runs as root inside the container only to
        // hand ownership to the image's non-root user, exactly as upstream
        // deployment guidance does for a fresh volume.
        let database_is_empty = std::fs::read_dir(&database)
            .map(|entries| entries.count() == 0)
            .unwrap_or(false);
        if database_is_empty {
            let seed: Vec<String> = vec![
                "run".into(),
                "--rm".into(),
                "--user".into(),
                "0:0".into(),
                "--mount".into(),
                format!("type=bind,src={},dst=/seed", database.display()),
                "--entrypoint".into(),
                "sh".to_owned(),
                self.image.to_owned(),
                "-c".to_owned(),
                "cp -r /opt/thunderid/database/. /seed/ && chown -R 10001:10001 /seed".to_owned(),
            ];
            let outcome = runner.run("docker", &seed, &[])?;
            if !outcome.success {
                return Err(ToolingError::CommandFailed {
                    step: "the shipped database schema could not be seeded into the fresh session state",
                });
            }
        }

        let mut args: Vec<String> = vec!["run".into(), "--rm".into()];
        for (host, container) in self.setup_mounts() {
            args.push("--mount".into());
            args.push(format!(
                "type=bind,src={},dst={}",
                host.display(),
                container
            ));
        }
        args.push(self.image.to_owned());
        args.push("./setup.sh".into());
        let outcome = runner.run(
            "docker",
            &args,
            &[("ADMIN_PASSWORD".to_owned(), admin_password_file.clone())],
        )?;
        if !outcome.success {
            // Persist the failure shape rather than retrying destructively:
            // the state file deliberately still says setup is incomplete.
            return Err(ToolingError::CommandFailed {
                step: "upstream setup did not complete; the partial state is retained for recovery",
            });
        }
        let mut state = self.load_state().unwrap_or_default();
        state.setup_complete = true;
        self.save_state(&state)
    }

    /// Bind mounts for the setup one-shot: persistent state, but not the
    /// runtime declarative resources.
    fn setup_mounts(&self) -> Vec<(PathBuf, String)> {
        vec![
            (
                self.state_root.join("database"),
                "/opt/thunderid/database".into(),
            ),
            (
                self.state_root.join("certs"),
                "/opt/thunderid/config/certs".into(),
            ),
            (
                self.state_root.join("secrets"),
                "/opt/thunderid/config/secrets".into(),
            ),
            (
                self.state_root.join("deployment.yaml"),
                "/opt/thunderid/deployment.yaml".into(),
            ),
        ]
    }

    /// Bind mounts for normal serving: setup state plus the rendered
    /// declarative resources, each as its own explicit directory so nothing
    /// overbinds the image's shipped configuration tree.
    fn serving_mounts(&self) -> Vec<(PathBuf, String)> {
        let mut mounts = self.setup_mounts();
        mounts.push((
            self.state_root.join("resources"),
            "/opt/thunderid/config/resources".into(),
        ));
        mounts
    }

    pub fn container_name(&self) -> String {
        format!(
            "thunderid-{}-{}",
            self.label,
            &self.id[..12.min(self.id.len())]
        )
    }

    /// Find only the container carrying this session's two labels and exact
    /// Docker name. Docker's `ps -q` output is a container ID, never an
    /// untrusted container name to pass to `rm`.
    fn owned_container(
        &self,
        runner: &mut dyn CommandRunner,
    ) -> Result<Option<String>, ToolingError> {
        let listed = runner.run(
            "docker",
            &[
                "ps".into(),
                "-aq".into(),
                "--no-trunc".into(),
                "--filter".into(),
                format!("label={SESSION_LABEL}={}", self.label),
                "--filter".into(),
                format!("label={SESSION_ID_LABEL}={}", self.id),
                "--filter".into(),
                format!("name=^/{}$", self.container_name()),
            ],
            &[],
        )?;
        if !listed.success {
            return Err(ToolingError::CommandFailed {
                step: "the ownership query failed",
            });
        }
        let ids: Vec<&str> = listed.container_ids.lines().collect();
        if ids.len() > 1
            || ids
                .iter()
                .any(|id| id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(ToolingError::InvalidState {
                reason: "the owned container listing is invalid",
            });
        }
        Ok(ids.first().map(|id| (*id).to_owned()))
    }

    /// Start the serving container. Refuses when the port is already held by
    /// anything other than this session's own container: an unrelated service
    /// is reported, never stopped and never adopted.
    pub fn start(&self, runner: &mut dyn CommandRunner) -> Result<(), ToolingError> {
        let state = self.load_state()?;
        if !state.setup_complete {
            return Err(ToolingError::InvalidState {
                reason: "setup has not completed for this session; run prepare first",
            });
        }
        let name = self.container_name();
        // A previous supervisor may have died before cleanup. Recreate only
        // this exact owned container, leaving its persistent mounts intact.
        if let Some(id) = self.owned_container(runner)? {
            let removed = runner.run("docker", &["rm".into(), "-f".into(), id], &[])?;
            if !removed.success {
                return Err(ToolingError::CommandFailed {
                    step: "the stale owned container could not be removed",
                });
            }
        }
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            format!("{SESSION_LABEL}={}", self.label),
            "--label".into(),
            format!("{SESSION_ID_LABEL}={}", self.id),
            "--publish".into(),
            format!("127.0.0.1:{}:8090", self.port),
        ];
        for (host, container) in self.serving_mounts() {
            args.push("--mount".into());
            args.push(format!(
                "type=bind,src={},dst={}",
                host.display(),
                container
            ));
        }
        args.push(self.image.to_owned());
        args.push("./start.sh".into());
        let outcome = runner.run("docker", &args, &[])?;
        if !outcome.success {
            // The most common cause is an occupied port; surface it as the
            // bounded, non-destructive refusal it must remain.
            return Err(ToolingError::PortOccupied {
                detail: format!(
                    "the serving container could not start on 127.0.0.1:{}; an occupant of that port is never stopped or adopted by this session",
                    self.port
                ),
            });
        }
        let mut state = self.load_state()?;
        state.container_name = Some(name);
        self.save_state(&state)
    }

    /// Stop the serving container, retaining all state. This is the normal
    /// shutdown: the database, keys, registrations, and rendered resources
    /// all survive for the next start.
    pub fn stop(&self, runner: &mut dyn CommandRunner) -> Result<(), ToolingError> {
        let Some(id) = self.owned_container(runner)? else {
            return Ok(());
        };
        let outcome = runner.run("docker", &["rm".into(), "-f".into(), id], &[])?;
        if !outcome.success {
            return Err(ToolingError::CommandFailed {
                step: "the serving container could not be stopped",
            });
        }
        Ok(())
    }

    /// The explicitly requested destructive reset. Nothing else in this
    /// crate removes retained state.
    pub fn reset(&self, runner: &mut dyn CommandRunner) -> Result<(), ToolingError> {
        self.stop(runner)?;
        let _ = std::fs::remove_file(self.state_path());
        Ok(())
    }
}

/// The deployment configuration for one local session: one issuer URL fixed
/// for the session's life, plain HTTP on loopback only, the four SQLite
/// stores on the persistent bind, and the file-referenced signing material
/// setup.sh generated.
fn deployment_yaml(issuer: &str) -> String {
    let host_only = issuer.trim_start_matches("http://");
    format!(
        r#"server:
  http_only: true
  hostname: "0.0.0.0"
  public_url: {issuer}
  port: 8090
  security:
    direct_auth_secret: "file://config/secrets/direct_auth_secret"
tls:
  min_version: "1.3"
  cert_file: "config/certs/server.cert"
  key_file: "config/certs/server.key"
database:
  config:
    type: "sqlite"
    sqlite: {{ path: "database/configdb.db" }}
  runtime_transient:
    type: "sqlite"
    sqlite: {{ path: "database/runtime_transient.db" }}
  entity:
    type: "sqlite"
    sqlite: {{ path: "database/entitydb.db" }}
  runtime_persistent:
    type: "sqlite"
    sqlite: {{ path: "database/runtime_persistent.db" }}
crypto:
  encryption:
    key: "file://config/certs/crypto.key"
  password_hashing:
    algorithm: "PBKDF2"
  keys:
    - id: "default-key"
      cert_file: "config/certs/signing.cert"
      key_file: "config/certs/signing.key"
    - id: "ecdsa-key"
      cert_file: "config/certs/ecdsa-signing.cert"
      key_file: "config/certs/ecdsa-signing.key"
jwt:
  preferred_key_id: "default-key"
# The pinned release's serving path reads resource servers and roles from
# files only through composite stores; the mutable default ignores the
# mounted declarative resources entirely.
resource:
  store: composite
role:
  store: composite
identity_provider:
  store: declarative
passkey:
  allowed_origins:
    - "{host_only}"
"#
    )
}

pub(crate) fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), ToolingError> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        return Err(ToolingError::Filesystem {
            reason: "a private session file already exists; reset the session explicitly",
        });
    }
    std::fs::write(path, bytes).map_err(|_| ToolingError::Filesystem {
        reason: "a private session file could not be written",
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| {
        ToolingError::Filesystem {
            reason: "a private session file could not be made owner-only",
        }
    })?;
    Ok(())
}

fn ensure_owner_only_dir(path: &Path) -> Result<(), ToolingError> {
    use std::os::unix::fs::PermissionsExt;
    ensure_regular_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|_| {
        ToolingError::Filesystem {
            reason: "the private session directory could not be made owner-only",
        }
    })
}

fn ensure_regular_dir(path: &Path) -> Result<(), ToolingError> {
    std::fs::create_dir_all(path).map_err(|_| ToolingError::Filesystem {
        reason: "the private session directory could not be created",
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ToolingError::Filesystem {
        reason: "the private session directory could not be inspected",
    })?;
    if !metadata.is_dir() {
        return Err(ToolingError::Filesystem {
            reason: "the private session directory is not an ordinary directory",
        });
    }
    Ok(())
}

pub(crate) fn random_urlsafe(bytes: usize) -> Result<String, ()> {
    use base64::Engine as _;
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).map_err(|_| ())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::CommandOutcome;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Default)]
    struct Runner {
        commands: Vec<Vec<String>>,
        owned_id: Option<String>,
    }

    impl CommandRunner for Runner {
        fn run(
            &mut self,
            _: &str,
            args: &[String],
            _: &[(String, PathBuf)],
        ) -> Result<CommandOutcome, ToolingError> {
            self.commands.push(args.to_vec());
            Ok(CommandOutcome {
                success: true,
                container_ids: if args.first().is_some_and(|arg| arg == "ps") {
                    self.owned_id
                        .as_ref()
                        .map(|id| format!("{id}\n"))
                        .unwrap_or_default()
                } else {
                    String::new()
                },
            })
        }
    }

    #[test]
    fn restart_and_stop_reclaim_only_the_exact_owned_container() {
        let root = std::env::temp_dir().join(format!(
            "thunderid-session-test-{}-{}",
            std::process::id(),
            random_urlsafe(8).unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let session = Session {
            label: "owned-test",
            id: "0197aaaa-0000-7000-8000-0000000000a1",
            port: 18091,
            state_root: &root,
            image: "pinned-test-image",
        };
        session
            .save_state(&SessionState {
                setup_complete: true,
                ..SessionState::default()
            })
            .unwrap();
        let id = "a".repeat(64);
        let mut runner = Runner {
            owned_id: Some(id.clone()),
            ..Runner::default()
        };
        session.start(&mut runner).unwrap();
        assert_eq!(runner.commands[0][0], "ps");
        assert!(runner.commands[0].contains(&format!("label={SESSION_LABEL}=owned-test")));
        assert!(runner.commands[0].contains(&format!("label={SESSION_ID_LABEL}={}", session.id)));
        assert!(runner.commands[0].contains(&format!("name=^/{}$", session.container_name())));
        assert_eq!(runner.commands[1], ["rm", "-f", &id]);
        assert_eq!(runner.commands[2][0], "run");

        runner.commands.clear();
        runner.owned_id = None;
        session.stop(&mut runner).unwrap();
        assert_eq!(
            runner.commands.len(),
            1,
            "an absent owned container is already stopped"
        );
        runner.commands.clear();
        runner.owned_id = Some(id.clone());
        session.stop(&mut runner).unwrap();
        assert_eq!(runner.commands[1], ["rm", "-f", &id]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_prepare_repairs_private_secret_directory_before_reuse() {
        let root = std::env::temp_dir().join(format!(
            "thunderid-secret-dir-test-{}-{}",
            std::process::id(),
            random_urlsafe(8).unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let secrets = root.join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755)).unwrap();
        let session = Session {
            label: "owned-test",
            id: "0197aaaa-0000-7000-8000-0000000000a1",
            port: 18091,
            state_root: &root,
            image: "pinned-test-image",
        };
        session
            .save_state(&SessionState {
                setup_complete: true,
                ..SessionState::default()
            })
            .unwrap();
        let mut runner = Runner::default();
        session.prepare(&mut runner).unwrap();
        assert!(
            runner.commands.is_empty(),
            "completed setup must not run again"
        );
        assert_eq!(
            std::fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
