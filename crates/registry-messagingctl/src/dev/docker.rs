// SPDX-License-Identifier: Apache-2.0

//! The two containers a development session owns: PostgreSQL, serving TLS
//! with the session's generated certificate, and Mailpit, the local SMTP
//! relay. Both publish on 127.0.0.1 only, on ports Docker chooses, carry
//! the session's owner label, and are removed with their volumes when the
//! session stops.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{failed, interrupted, DevResult, DATABASE_NAME, MIGRATION_ROLE, RUNTIME_ROLE};

/// The pinned PostgreSQL image, the same one Casework's development
/// session runs.
pub(super) const POSTGRES_IMAGE: &str =
    "postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675";
/// The pinned Mailpit image.
pub(super) const MAILPIT_IMAGE: &str =
    "axllent/mailpit:v1.31.2@sha256:74d609a42ec279aa63c6b4622a6fa9b5408d1ad5b1d76a1c4be40a265ce0863d";
/// The label naming the session that owns a container.
pub(super) const OWNER_LABEL: &str = "org.registrystack.messagingctl.dev-owner";

/// How long one Docker command may run. Starting a container may pull its
/// image first.
const RUN_DEADLINE: Duration = Duration::from_secs(600);
const COMMAND_DEADLINE: Duration = Duration::from_secs(120);
/// How long PostgreSQL has to accept connections.
const READY_DEADLINE: Duration = Duration::from_secs(60);
/// The most of a failed command's error output a refusal repeats.
const MAXIMUM_ERROR_CHARACTERS: usize = 400;

pub(super) struct Docker {
    binary: PathBuf,
}

/// A container this session started and the loopback ports it publishes.
pub(super) struct Started {
    pub id: String,
    pub ports: Vec<u16>,
}

impl Docker {
    pub(super) fn new(binary: PathBuf) -> Self {
        Self { binary }
    }

    /// Run one Docker command, feeding `input` on standard input. The
    /// command's error output is repeated in a refusal with `secret`
    /// removed from it.
    fn command(
        &self,
        arguments: &[&str],
        input: Option<&[u8]>,
        secret: Option<&[u8]>,
        deadline: Duration,
    ) -> DevResult<Vec<u8>> {
        let step = arguments.first().copied().unwrap_or("docker");
        let mut child = Command::new(&self.binary)
            .args(arguments)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                failed(format!(
                    "Docker could not be started ({error}); install Docker or pass --docker-bin"
                ))
            })?;
        if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
            stdin
                .write_all(bytes)
                .map_err(|error| failed(format!("docker {step}: {error}")))?;
        }
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let out = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            bytes
        });
        let err = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() > deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(failed(format!(
                        "docker {step} did not finish in {} seconds",
                        deadline.as_secs()
                    )));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(error) => return Err(failed(format!("docker {step}: {error}"))),
            }
        };
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        if status.success() {
            return Ok(stdout);
        }
        let mut message = String::from_utf8_lossy(&redact(&stderr, secret)).into_owned();
        message = message
            .trim()
            .chars()
            .take(MAXIMUM_ERROR_CHARACTERS)
            .collect();
        Err(failed(format!("docker {step} failed: {message}")))
    }

    fn run(&self, arguments: &[&str]) -> DevResult<Vec<u8>> {
        self.command(arguments, None, None, COMMAND_DEADLINE)
    }

    /// Start a detached, labelled container publishing `ports` on loopback,
    /// and report the host port Docker chose for each.
    fn start(
        &self,
        name: &str,
        owner: &str,
        ports: &[u16],
        env_file: Option<&Path>,
        image: &str,
    ) -> DevResult<Started> {
        let label = format!("{OWNER_LABEL}={owner}");
        let published: Vec<String> = ports
            .iter()
            .map(|port| format!("127.0.0.1::{port}"))
            .collect();
        let env_file = env_file.map(|path| path.to_string_lossy().into_owned());
        let mut arguments = vec!["run", "--detach", "--name", name, "--label", &label];
        for port in &published {
            arguments.extend(["--publish", port.as_str()]);
        }
        if let Some(path) = &env_file {
            arguments.extend(["--env-file", path.as_str()]);
        }
        arguments.push(image);
        let created = self.command(&arguments, None, None, RUN_DEADLINE)?;
        let id = String::from_utf8_lossy(&created).trim().to_owned();
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(failed(format!(
                "Docker returned no container id for {name}"
            )));
        }
        let mut host_ports = Vec::new();
        for port in ports {
            host_ports.push(self.host_port(&id, *port)?);
        }
        Ok(Started {
            id,
            ports: host_ports,
        })
    }

    fn host_port(&self, container: &str, port: u16) -> DevResult<u16> {
        let answer = self.run(&["port", container, &format!("{port}/tcp")])?;
        String::from_utf8_lossy(&answer)
            .lines()
            .find_map(|line| line.strip_prefix("127.0.0.1:"))
            .and_then(|port| port.trim().parse().ok())
            .ok_or_else(|| failed(format!("Docker published no loopback port for {port}")))
    }

    /// The ids of every container, running or not, labelled with `owner`.
    pub(super) fn owned(&self, owner: &str) -> DevResult<Vec<String>> {
        let listed = self.run(&[
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            &format!("label={OWNER_LABEL}={owner}"),
        ])?;
        Ok(String::from_utf8_lossy(&listed)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// Remove `containers` and their anonymous volumes.
    pub(super) fn remove(&self, containers: &[String]) -> DevResult<()> {
        if containers.is_empty() {
            return Ok(());
        }
        let mut arguments = vec!["rm", "--force", "--volumes"];
        arguments.extend(containers.iter().map(String::as_str));
        self.run(&arguments).map(|_| ())
    }

    fn sql(
        &self,
        container: &str,
        database: &str,
        statements: &[u8],
        secret: Option<&[u8]>,
    ) -> DevResult<Vec<u8>> {
        self.command(
            &[
                "exec",
                "-i",
                container,
                "psql",
                "-X",
                "-A",
                "-t",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                database,
            ],
            Some(statements),
            secret,
            COMMAND_DEADLINE,
        )
    }
}

/// Remove `secret` from `bytes`, so no refusal repeats it.
fn redact(bytes: &[u8], secret: Option<&[u8]>) -> Vec<u8> {
    let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
        return bytes.to_vec();
    };
    let mut redacted = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(secret) {
            redacted.extend_from_slice(b"<redacted>");
            index += secret.len();
        } else {
            redacted.push(bytes[index]);
            index += 1;
        }
    }
    redacted
}

/// The files PostgreSQL needs, written by the caller under the session's
/// private `database/` directory.
pub(super) struct DatabaseFiles<'a> {
    pub env_file: &'a Path,
    pub pg_hba: &'a Path,
    pub server_certificate: &'a Path,
    pub server_key: &'a Path,
    pub migration_password: &'a str,
    pub runtime_password: &'a str,
}

/// Start PostgreSQL and provision it: TLS with the session certificate,
/// host connections over TLS only, the migration role owning the `public`
/// schema, and the runtime role reading and writing what the migration role
/// creates. `record` is called with the container id as soon as it exists,
/// so a failed start still removes it.
pub(super) fn postgres(
    docker: &Docker,
    name: &str,
    owner: &str,
    files: &DatabaseFiles<'_>,
    stop: &AtomicBool,
    record: &mut dyn FnMut(&str) -> DevResult<()>,
) -> DevResult<u16> {
    let started = docker.start(name, owner, &[5432], Some(files.env_file), POSTGRES_IMAGE)?;
    record(&started.id)?;
    let id = started.id.as_str();
    let deadline = Instant::now() + READY_DEADLINE;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(interrupted());
        }
        if docker
            .run(&[
                "exec",
                id,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ])
            .is_ok()
        {
            break;
        }
        if Instant::now() > deadline {
            return Err(failed(
                "PostgreSQL did not accept connections in time; run `docker logs` on the session's container".to_owned(),
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for (source, target) in [
        (files.pg_hba, "/var/lib/postgresql/data/pg_hba.conf"),
        (
            files.server_certificate,
            "/var/lib/postgresql/messaging-dev-server.pem",
        ),
        (
            files.server_key,
            "/var/lib/postgresql/messaging-dev-server.key",
        ),
    ] {
        docker.run(&["cp", &source.to_string_lossy(), &format!("{id}:{target}")])?;
    }
    docker.run(&[
        "exec",
        "--user",
        "root",
        id,
        "chown",
        "postgres:postgres",
        "/var/lib/postgresql/data/pg_hba.conf",
        "/var/lib/postgresql/messaging-dev-server.pem",
        "/var/lib/postgresql/messaging-dev-server.key",
    ])?;
    docker.run(&[
        "exec",
        "--user",
        "root",
        id,
        "chmod",
        "600",
        "/var/lib/postgresql/data/pg_hba.conf",
        "/var/lib/postgresql/messaging-dev-server.key",
    ])?;
    docker.sql(
        id,
        "postgres",
        b"ALTER SYSTEM SET ssl = 'on';\n\
          ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/messaging-dev-server.pem';\n\
          ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/messaging-dev-server.key';\n\
          SELECT pg_reload_conf();\n",
        None,
    )?;
    for (role, password) in [
        (MIGRATION_ROLE, files.migration_password),
        (RUNTIME_ROLE, files.runtime_password),
    ] {
        let statement = Zeroizing::new(format!(
            "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';\n"
        ));
        docker.sql(
            id,
            "postgres",
            statement.as_bytes(),
            Some(password.as_bytes()),
        )?;
    }
    docker.sql(
        id,
        "postgres",
        format!("CREATE DATABASE {DATABASE_NAME};\n").as_bytes(),
        None,
    )?;
    // Messaging's migrations create ordinary tables in `public` and no
    // other schema, so the migration role owns that one schema and the
    // runtime role only reads and writes through it.
    docker.sql(
        id,
        DATABASE_NAME,
        format!(
            "REVOKE ALL ON DATABASE {DATABASE_NAME} FROM PUBLIC;\n\
             GRANT CONNECT ON DATABASE {DATABASE_NAME} TO {MIGRATION_ROLE}, {RUNTIME_ROLE};\n\
             ALTER SCHEMA public OWNER TO {MIGRATION_ROLE};\n\
             REVOKE ALL ON SCHEMA public FROM PUBLIC;\n\
             GRANT USAGE ON SCHEMA public TO {RUNTIME_ROLE};\n\
             ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATION_ROLE} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {RUNTIME_ROLE};\n\
             ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATION_ROLE} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {RUNTIME_ROLE};\n"
        )
        .as_bytes(),
        None,
    )?;
    Ok(started.ports[0])
}

/// Start Mailpit and report its SMTP and web ports.
pub(super) fn mailpit(
    docker: &Docker,
    name: &str,
    owner: &str,
    record: &mut dyn FnMut(&str) -> DevResult<()>,
) -> DevResult<(u16, u16)> {
    let started = docker.start(name, owner, &[1025, 8025], None, MAILPIT_IMAGE)?;
    record(&started.id)?;
    Ok((started.ports[0], started.ports[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_never_repeats_the_secret() {
        assert_eq!(
            redact(b"ERROR: bad PASSWORD 's3cret' near s3cret", Some(b"s3cret")),
            b"ERROR: bad PASSWORD '<redacted>' near <redacted>".to_vec()
        );
        assert_eq!(redact(b"plain", None), b"plain".to_vec());
    }

    #[test]
    fn a_missing_docker_binary_is_an_operational_failure_naming_the_flag() {
        let docker = Docker::new(PathBuf::from("/nonexistent/docker"));
        let failure = docker.run(&["version"]).unwrap_err();
        assert!(
            failure.message.contains("--docker-bin"),
            "{}",
            failure.message
        );
    }
}
