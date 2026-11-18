// SPDX-License-Identifier: Apache-2.0
//! The PostgreSQL server of a managed run: one Docker container per run,
//! published on loopback only, serving verified TLS from a CA the run draws,
//! and removed by its run label when the run stops, expires or is recovered.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use super::{database, operational, write_private};

/// The label every managed run's container carries, valued with the run ID.
pub(super) const LABEL: &str = "org.registrystack.rstack.dev-run";

/// The official multi-arch PostgreSQL image.
const DEFAULT_IMAGE: &str =
    "postgres:18.7@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc";
/// The PostGIS image a run starts only when a BReg project in the plan
/// requires PostGIS. It is published for linux/amd64 only, so Apple Silicon
/// runs it under emulation.
const POSTGIS_IMAGE: &str =
    "postgis/postgis:18-3.6@sha256:4a43e3c3e5d55b9208240fc71db543b79c638766280c625a425bd0a2390989c4";
const POSTGIS_PLATFORM: &str = "linux/amd64";

/// How long the server may take to accept connections, and then to serve TLS.
const READY_DEADLINE: Duration = Duration::from_secs(60);
const READY_POLL: Duration = Duration::from_millis(250);
/// How long Docker may take to answer whether its daemon runs.
const PROBE_DEADLINE: Duration = Duration::from_secs(30);
/// How long one Docker command other than a pull may take.
const COMMAND_DEADLINE: Duration = Duration::from_secs(120);
const PULL_DEADLINE: Duration = Duration::from_secs(600);
/// Docker output a run reads, and the stderr an error repeats.
const MAXIMUM_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAXIMUM_ERROR_CHARACTERS: usize = 400;

/// Where the server's certificate and key live inside the container: the
/// image's volume, so removing the container with its volumes removes them.
const SERVER_CERTIFICATE: &str = "/var/lib/postgresql/rstack-dev-server.crt";
const SERVER_KEY: &str = "/var/lib/postgresql/rstack-dev-server.key";
/// Local connections inside the container stay trusted for the image's own
/// tooling; every TCP connection must use TLS and a password.
const PG_HBA: &[u8] = b"local all all trust\nhostssl all all all scram-sha-256\n";

/// The image a managed run starts, and the one platform it must be pulled and
/// run for when it is published for one platform only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Image {
    pub(super) reference: &'static str,
    platform: Option<&'static str>,
}

impl Image {
    pub(super) fn for_plan(requires_postgis: bool) -> Self {
        if requires_postgis {
            Self {
                reference: POSTGIS_IMAGE,
                platform: Some(POSTGIS_PLATFORM),
            }
        } else {
            Self {
                reference: DEFAULT_IMAGE,
                platform: None,
            }
        }
    }
}

/// The name of a managed run's container.
pub(super) fn container_name(run_id: &str) -> String {
    format!("rstack-dev-{run_id}")
}

/// A started server: the administrator URL the by-address path connects with
/// and the PEM of the run CA its certificate chains to.
pub(super) struct Server {
    pub(super) admin_url: Zeroizing<String>,
    pub(super) ca_pem: Vec<u8>,
}

pub(super) struct Docker {
    program: PathBuf,
    ready_deadline: Duration,
}

impl Docker {
    /// The `docker` command `PATH` names, refused unless its daemon answers.
    pub(super) fn connect() -> Result<Self> {
        Self::at(PathBuf::from("docker"), READY_DEADLINE).answering()
    }

    fn at(program: PathBuf, ready_deadline: Duration) -> Self {
        Self {
            program,
            ready_deadline,
        }
    }

    fn answering(self) -> Result<Self> {
        match self.run(&["version", "--format", "{{.Server.Version}}"], None, PROBE_DEADLINE) {
            Ok(_) => Ok(self),
            Err(error) => Err(operational(anyhow!(
                "Docker is not available to run the development PostgreSQL server ({error:#}); install Docker, or pass --database-url (or set RSTACK_DEV_DATABASE_URL) to use a TLS PostgreSQL server you run"
            ))),
        }
    }

    /// Pull `image` unless Docker already holds it.
    pub(super) fn ensure_image(&self, image: Image) -> Result<()> {
        let held = self.run(
            &["image", "inspect", "--format", "{{.Id}}", image.reference],
            None,
            COMMAND_DEADLINE,
        );
        if held.is_ok() {
            return Ok(());
        }
        let mut arguments = vec!["pull"];
        if let Some(platform) = image.platform {
            arguments.extend(["--platform", platform]);
        }
        arguments.push(image.reference);
        self.run(&arguments, None, PULL_DEADLINE)
            .with_context(|| format!("cannot pull the PostgreSQL image {}", image.reference))
            .map_err(operational)?;
        Ok(())
    }

    /// Start the run's PostgreSQL container and turn on verified TLS. A
    /// failure leaves any container started under the run's label, for the
    /// run's cleanup to remove.
    pub(super) fn start_server(&self, root: &Path, run_id: &str, image: Image) -> Result<Server> {
        self.start_labelled(root, run_id, image)
            .map_err(operational)
    }

    fn start_labelled(&self, root: &Path, run_id: &str, image: Image) -> Result<Server> {
        let name = container_name(run_id);
        let label = format!("{LABEL}={run_id}");
        // The password reaches Docker in an owner-only file, never in an
        // argument another local user could read.
        let password = database::random_password()?;
        let env_file = root.join("postgres.env");
        write_private(
            &env_file,
            Zeroizing::new(format!("POSTGRES_PASSWORD={}\n", password.as_str())).as_bytes(),
        )
        .context("cannot write the PostgreSQL container environment")?;
        let env_file = env_file
            .to_str()
            .context("the run directory is not valid UTF-8")?;
        let mut arguments = vec![
            "run",
            "--detach",
            "--name",
            &name,
            "--label",
            &label,
            "--publish",
            "127.0.0.1::5432",
            "--env-file",
            env_file,
        ];
        if let Some(platform) = image.platform {
            arguments.extend(["--platform", platform]);
        }
        arguments.push(image.reference);
        let id = self
            .run(&arguments, None, COMMAND_DEADLINE)
            .context("cannot start the PostgreSQL container")?;
        let id = id.trim().to_owned();
        ensure!(
            id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "docker run did not report the ID of container {name}"
        );

        let published = self.run(&["port", &id, "5432/tcp"], None, COMMAND_DEADLINE)?;
        let port = published
            .lines()
            .filter_map(|line| line.trim().strip_prefix("127.0.0.1:"))
            .find_map(|port| port.parse::<u16>().ok().filter(|port| *port != 0))
            .with_context(|| {
                format!(
                    "Docker did not publish the PostgreSQL port of container {name} on 127.0.0.1 (it answered {:?}); refusing to use it",
                    published.trim()
                )
            })?;

        self.await_ready(&id, &name, &label)?;
        let tls = RunTls::generate()?;
        let hba_file = self.sql(&id, "SHOW hba_file;")?;
        let hba_file = hba_file.trim();
        ensure!(
            hba_file.starts_with('/') && !hba_file.contains(char::is_whitespace),
            "the PostgreSQL server in container {name} reported no usable pg_hba.conf path"
        );
        let staged = [
            (
                "postgres-server.crt",
                tls.certificate_pem.as_slice(),
                SERVER_CERTIFICATE,
            ),
            ("postgres-server.key", tls.key_pem.as_slice(), SERVER_KEY),
            ("postgres-hba.conf", PG_HBA, hba_file),
        ];
        for (file, contents, target) in staged {
            let source = root.join(file);
            write_private(&source, contents)?;
            let source = source
                .to_str()
                .context("the run directory is not valid UTF-8")?;
            self.run(
                &["cp", source, &format!("{id}:{target}")],
                None,
                COMMAND_DEADLINE,
            )?;
        }
        let installed = [SERVER_CERTIFICATE, SERVER_KEY, hba_file];
        for change in [["chown", "postgres:postgres"], ["chmod", "600"]] {
            let mut arguments = vec!["exec", "--user", "root", &id];
            arguments.extend(change);
            arguments.extend(installed);
            self.run(&arguments, None, COMMAND_DEADLINE)?;
        }
        self.sql(
            &id,
            &format!(
                "ALTER SYSTEM SET ssl_cert_file = '{SERVER_CERTIFICATE}';\nALTER SYSTEM SET ssl_key_file = '{SERVER_KEY}';\nALTER SYSTEM SET ssl = 'on';\nSELECT pg_reload_conf();\n"
            ),
        )?;
        self.await_tls(&id, &name, &label)?;

        Ok(Server {
            admin_url: Zeroizing::new(format!(
                "postgresql://postgres:{}@127.0.0.1:{port}/postgres?sslmode=verify-full",
                password.as_str()
            )),
            ca_pem: tls.ca_pem,
        })
    }

    /// Wait until the server accepts TCP connections. The image's first-start
    /// server listens on its socket only, so this waits for the final server.
    fn await_ready(&self, id: &str, name: &str, label: &str) -> Result<()> {
        let deadline = Instant::now() + self.ready_deadline;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let error = match self.run(
                &[
                    "exec",
                    id,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-p",
                    "5432",
                    "-U",
                    "postgres",
                    "-d",
                    "postgres",
                ],
                None,
                remaining.max(READY_POLL),
            ) {
                Ok(_) => return Ok(()),
                Err(error) => error,
            };
            if Instant::now() >= deadline {
                bail!(
                    "the PostgreSQL server in container {name} (label {label}) did not accept connections within {} s: {error:#}",
                    self.ready_deadline.as_secs()
                );
            }
            thread::sleep(READY_POLL);
        }
    }

    /// Wait until the reloaded server reports TLS on. A certificate it cannot
    /// load leaves TLS off, so this fails rather than serving without it.
    fn await_tls(&self, id: &str, name: &str, label: &str) -> Result<()> {
        let deadline = Instant::now() + self.ready_deadline;
        loop {
            let answer = self.sql(id, "SHOW ssl;")?;
            if answer.trim() == "on" {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "the PostgreSQL server in container {name} (label {label}) did not turn on TLS within {} s; its log has the reason",
                    self.ready_deadline.as_secs()
                );
            }
            thread::sleep(READY_POLL);
        }
    }

    /// Run SQL in the container's own `psql` over its local socket. The SQL
    /// travels on stdin, never in an argument.
    fn sql(&self, id: &str, statements: &str) -> Result<String> {
        self.run(
            &[
                "exec",
                "-i",
                id,
                "psql",
                "-X",
                "-A",
                "-t",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                "postgres",
            ],
            Some(statements.as_bytes()),
            COMMAND_DEADLINE,
        )
    }

    /// Remove every container labelled with this run, with its anonymous
    /// volumes, and return the IDs removed.
    pub(super) fn remove(&self, run_id: &str) -> Result<Vec<String>> {
        let filter = format!("label={LABEL}={run_id}");
        let ids: Vec<String> = self
            .run(
                &["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter],
                None,
                COMMAND_DEADLINE,
            )
            .context("cannot list the run's PostgreSQL container")?
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .collect();
        if ids.is_empty() {
            return Ok(ids);
        }
        let mut arguments = vec!["rm", "--force", "--volumes"];
        arguments.extend(ids.iter().map(String::as_str));
        self.run(&arguments, None, COMMAND_DEADLINE)
            .context("cannot remove the run's PostgreSQL container")?;
        Ok(ids)
    }

    /// Run one Docker command and return its stdout. A command that exits
    /// non-zero, or outlives `deadline`, fails with its stderr.
    fn run(&self, arguments: &[&str], input: Option<&[u8]>, deadline: Duration) -> Result<String> {
        let verb = arguments.first().copied().unwrap_or_default();
        let mut child = Command::new(&self.program)
            .args(arguments)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot run docker {verb}"))?;
        let stdout = drain(child.stdout.take().context("docker stdout")?);
        let stderr = drain(child.stderr.take().context("docker stderr")?);
        // Dropping stdin after the write closes it, so the command sees the
        // end of its input.
        let written = match (input, child.stdin.take()) {
            (Some(input), Some(mut stdin)) => stdin.write_all(input),
            _ => Ok(()),
        };
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= deadline {
                let stopped = child.kill().and_then(|()| child.wait().map(drop));
                bail!(
                    "docker {verb} did not finish within {} s{}",
                    deadline.as_secs(),
                    stopped
                        .err()
                        .map(|error| format!(" and could not be stopped: {error}"))
                        .unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(20));
        };
        let stdout = stdout
            .join()
            .map_err(|_| anyhow!("cannot read docker {verb} output"))??;
        let stderr = stderr
            .join()
            .map_err(|_| anyhow!("cannot read docker {verb} errors"))??;
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            let stderr: String = stderr
                .trim()
                .chars()
                .take(MAXIMUM_ERROR_CHARACTERS)
                .collect();
            bail!("docker {verb} failed with {status}: {stderr}");
        }
        written.with_context(|| format!("cannot send input to docker {verb}"))?;
        String::from_utf8(stdout).with_context(|| format!("docker {verb} output is not UTF-8"))
    }
}

/// Read a child's stream to its end, up to the output bound, on a thread so
/// neither stream can fill and block the child.
fn drain(stream: impl Read + Send + 'static) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream
            .take(MAXIMUM_OUTPUT_BYTES)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    })
}

/// A CA drawn for one run and the server certificate it signs, for the names
/// a loopback client verifies.
struct RunTls {
    ca_pem: Vec<u8>,
    certificate_pem: Vec<u8>,
    key_pem: Zeroizing<Vec<u8>>,
}

impl RunTls {
    fn generate() -> Result<Self> {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rstack dev run PostgreSQL CA");
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = rcgen::KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;
        let server_key = rcgen::KeyPair::generate()?;
        let mut server_params =
            rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rstack dev run PostgreSQL");
        server_params.use_authority_key_identifier_extension = true;
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.signed_by(
            &server_key,
            &rcgen::Issuer::from_params(&ca_params, &ca_key),
        )?;
        Ok(Self {
            ca_pem: pem("CERTIFICATE", ca.der()).to_vec(),
            certificate_pem: pem("CERTIFICATE", server.der()).to_vec(),
            key_pem: pem("PRIVATE KEY", &Zeroizing::new(server_key.serialize_der())),
        })
    }
}

/// PEM text of `der`, in a buffer sized up front so no copy of a key is left
/// behind by a reallocation.
fn pem(label: &str, der: &[u8]) -> Zeroizing<Vec<u8>> {
    let encoded = Zeroizing::new(STANDARD.encode(der));
    let mut text = Zeroizing::new(Vec::with_capacity(
        encoded.len() + encoded.len() / 64 + 2 * label.len() + 40,
    ));
    text.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
    for chunk in encoded.as_bytes().chunks(64) {
        text.extend_from_slice(chunk);
        text.push(b'\n');
    }
    text.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    };

    const RUN_ID: &str = "0123456789abcdef0123456789abcdef";

    /// The test fake Docker CLI under the name `docker`, with its state
    /// directory beside it, and an owner-only run directory.
    struct Fake {
        scratch: tempfile::TempDir,
        docker: Docker,
    }

    impl Fake {
        fn new() -> Self {
            Self::with_state(true)
        }

        fn with_state(daemon: bool) -> Self {
            let scratch = tempfile::tempdir().unwrap();
            let bin = scratch.path().join("bin");
            fs::create_dir(&bin).unwrap();
            symlink(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake-docker.sh"),
                bin.join("docker"),
            )
            .unwrap();
            if daemon {
                fs::create_dir(bin.join("fake-docker-state")).unwrap();
            }
            fs::DirBuilder::new()
                .mode(0o700)
                .create(scratch.path().join("run"))
                .unwrap();
            let docker = Docker::at(bin.join("docker"), Duration::from_millis(500));
            Self { scratch, docker }
        }

        fn state(&self) -> PathBuf {
            self.scratch.path().join("bin/fake-docker-state")
        }

        fn root(&self) -> PathBuf {
            self.scratch.path().join("run")
        }

        fn argv(&self) -> String {
            fs::read_to_string(self.state().join("argv.log")).unwrap_or_default()
        }

        fn invocations(&self, verb: &str) -> Vec<String> {
            self.argv()
                .lines()
                .filter(|line| line.split(' ').next() == Some(verb))
                .map(str::to_owned)
                .collect()
        }

        fn containers(&self) -> Vec<String> {
            fs::read_dir(self.state().join("containers"))
                .map(|entries| {
                    entries
                        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                        .collect()
                })
                .unwrap_or_default()
        }

        fn start(&self, image: Image) -> Result<Server> {
            self.docker.start_server(&self.root(), RUN_ID, image)
        }
    }

    #[test]
    fn managed_container_binds_loopback_only() {
        let fake = Fake::new();
        fs::write(fake.state().join("port-answer"), "127.0.0.1:49153\n").unwrap();

        let server = fake.start(Image::for_plan(false)).unwrap();

        let run = fake.invocations("run");
        assert_eq!(run.len(), 1, "{run:?}");
        assert!(run[0].contains(" --publish 127.0.0.1::5432 "), "{run:?}");
        assert_eq!(run[0].matches("--publish").count(), 1, "{run:?}");
        assert!(
            run[0].contains(&format!(" --label {LABEL}={RUN_ID} ")),
            "{run:?}"
        );
        assert!(
            run[0].contains(&format!(" --name {} ", container_name(RUN_ID))),
            "{run:?}"
        );
        assert!(
            server.admin_url.starts_with("postgresql://postgres:"),
            "the URL names the administrator"
        );
        assert!(
            server
                .admin_url
                .ends_with("@127.0.0.1:49153/postgres?sslmode=verify-full"),
            "the URL names the loopback port Docker published"
        );

        // Docker publishing on any other address is refused, and the
        // container it started stays labelled for removal.
        for answer in ["0.0.0.0:49154\n[::]:49154\n", ""] {
            let fake = Fake::new();
            fs::write(fake.state().join("port-answer"), answer).unwrap();
            let error = fake.start(Image::for_plan(false)).err().unwrap();
            assert!(format!("{error:#}").contains("127.0.0.1"), "{error:#}");
            assert!(error.is::<super::super::Operational>(), "{error:#}");
            assert_eq!(fake.containers().len(), 1);
        }
    }

    #[test]
    fn the_admin_password_never_reaches_a_command_line() {
        let fake = Fake::new();

        let server = fake.start(Image::for_plan(false)).unwrap();

        let env_file = fs::read_to_string(fake.state().join("env-file")).unwrap();
        let password = env_file
            .strip_prefix("POSTGRES_PASSWORD=")
            .unwrap()
            .trim_end();
        assert!(password.len() >= 40, "the password is drawn, not fixed");
        assert!(server.admin_url.contains(&format!(":{password}@")));
        let argv = fake.argv();
        assert!(argv.contains(" --env-file "), "{argv}");
        assert!(!argv.contains(password));
        let psql = fs::read_to_string(fake.state().join("psql.log")).unwrap();
        assert!(!psql.contains(password));
        let written = fake.root().join("postgres.env");
        assert_eq!(
            fs::metadata(&written).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn tls_is_required_for_every_tcp_connection() {
        let fake = Fake::new();

        let server = fake.start(Image::for_plan(false)).unwrap();

        assert!(String::from_utf8(server.ca_pem.clone())
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----\n"));
        let hba = fs::read_to_string(fake.state().join("copied/pg_hba.conf")).unwrap();
        assert_eq!(
            hba,
            "local all all trust\nhostssl all all all scram-sha-256\n"
        );
        let key = fs::read_to_string(fake.state().join("copied/rstack-dev-server.key")).unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let exec = fake.invocations("exec");
        assert!(
            exec.iter()
                .any(|line| line.contains(" --user root ")
                    && line.contains(" chown postgres:postgres ")),
            "{exec:?}"
        );
        assert!(
            exec.iter()
                .any(|line| line.contains(" --user root ") && line.contains(" chmod 600 ")),
            "{exec:?}"
        );
        let psql = fs::read_to_string(fake.state().join("psql.log")).unwrap();
        assert!(psql.contains("ALTER SYSTEM SET ssl = 'on'"), "{psql}");
        assert!(psql.contains("SELECT pg_reload_conf()"), "{psql}");
        assert!(psql.contains("SHOW ssl"), "{psql}");
    }

    #[test]
    fn postgis_image_only_when_a_breg_project_requires_it() {
        assert_eq!(Image::for_plan(false).reference, DEFAULT_IMAGE);
        assert_eq!(Image::for_plan(true).reference, POSTGIS_IMAGE);

        let plain = Fake::new();
        plain.docker.ensure_image(Image::for_plan(false)).unwrap();
        plain.start(Image::for_plan(false)).unwrap();
        assert!(!plain.argv().contains("--platform"), "{}", plain.argv());
        assert_eq!(plain.invocations("pull"), [format!("pull {DEFAULT_IMAGE}")]);

        let spatial = Fake::new();
        spatial.docker.ensure_image(Image::for_plan(true)).unwrap();
        spatial.docker.ensure_image(Image::for_plan(true)).unwrap();
        spatial.start(Image::for_plan(true)).unwrap();
        assert_eq!(
            spatial.invocations("pull"),
            [format!("pull --platform linux/amd64 {POSTGIS_IMAGE}")],
            "a held image is not pulled again"
        );
        let run = spatial.invocations("run");
        assert!(
            run[0].ends_with(&format!(" --platform linux/amd64 {POSTGIS_IMAGE}")),
            "{run:?}"
        );
    }

    #[test]
    fn stop_removes_the_container_by_label() {
        let fake = Fake::new();
        fake.start(Image::for_plan(false)).unwrap();
        let other = "f".repeat(64);
        fs::write(
            fake.state().join("containers").join(&other),
            format!("{LABEL}=fedcba9876543210fedcba9876543210\n"),
        )
        .unwrap();
        let started = fake
            .containers()
            .into_iter()
            .find(|id| id != &other)
            .unwrap();

        let removed = fake.docker.remove(RUN_ID).unwrap();

        assert_eq!(removed, std::slice::from_ref(&started));
        assert_eq!(fake.containers(), [other]);
        assert_eq!(
            fake.invocations("ps"),
            [format!(
                "ps --all --quiet --no-trunc --filter label={LABEL}={RUN_ID}"
            )]
        );
        assert_eq!(
            fake.invocations("rm"),
            [format!("rm --force --volumes {started}")]
        );
        // Nothing left to remove is not an error, and removes nothing.
        assert_eq!(fake.docker.remove(RUN_ID).unwrap(), Vec::<String>::new());
        assert_eq!(fake.invocations("rm").len(), 1);
    }

    #[test]
    fn a_server_that_never_answers_names_its_container_label() {
        let fake = Fake::new();
        fs::write(fake.state().join("never-ready"), "").unwrap();

        let error = fake.start(Image::for_plan(false)).err().unwrap();

        assert!(error.is::<super::super::Operational>(), "{error:#}");
        let message = format!("{error:#}");
        assert!(message.contains(&format!("{LABEL}={RUN_ID}")), "{message}");
        assert_eq!(fake.containers().len(), 1, "removal is the run's cleanup");
    }

    #[test]
    fn an_unavailable_docker_names_both_ways_out() {
        let missing = Docker::at(PathBuf::from("/nonexistent/docker"), READY_DEADLINE);
        let silent = Fake::with_state(false);
        for result in [missing.answering(), silent.docker.answering()] {
            let error = result.err().unwrap();
            assert!(error.is::<super::super::Operational>(), "{error:#}");
            let message = format!("{error:#}");
            assert!(
                message.contains("install Docker, or pass --database-url"),
                "{message}"
            );
        }
    }
}
