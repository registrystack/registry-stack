// SPDX-License-Identifier: Apache-2.0

//! `messagingctl dev`: a foreground, loopback-only development session for
//! an authored package.
//!
//! One start owns everything it runs, and stopping it removes all of it:
//! a PostgreSQL container serving TLS with a certificate the session
//! generates, a Mailpit container every `smtp` provider sends to, a mock
//! HTTP gateway every `http` provider sends to, and the Messaging runtime
//! itself, run in this process on a development listener. The session's
//! secrets, generated configuration, audit journal, and log live in the
//! project's private `.messaging/dev` directory, which the next start
//! replaces. `dev token` signs a short-lived bearer token for a client an
//! access profile names, with the key the running session trusts.

mod config;
mod docker;
mod gateway;
mod private;

use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use registry_messaging::config::RuntimeConfig;
use registry_messaging::dispatch::Transports;
use registry_messaging::package::{load_package, LoadedPackage};
use registry_messaging::runtime::{
    apply_package, migrate_from_path, operational_log_level, serve_from_path,
};
use registry_messaging_core::READY_PATH;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    finish, render_human, Outcome, OutputFormat, View, OPERATIONAL_FAILURE_EXIT, REFUSAL_EXIT,
};

const DATABASE_NAME: &str = "messaging_dev";
const MIGRATION_ROLE: &str = "messaging_dev_migration";
const RUNTIME_ROLE: &str = "messaging_dev_runtime";
/// The project's private state directory and the session directory in it.
const STATE_DIRECTORY: &str = ".messaging";
const SESSION_DIRECTORY: &str = "dev";
/// The largest session record a start reads back.
const MAXIMUM_SESSION_BYTES: u64 = 64 * 1024;
/// How long Mailpit and then the runtime have to answer as ready.
const READY_DEADLINE: Duration = Duration::from_secs(45);
/// How long after accepting a send the mock gateway reports it delivered.
const CALLBACK_DELAY: Duration = Duration::from_millis(500);
/// How often the foreground session checks for a stop signal.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub(crate) struct DevArgs {
    #[command(subcommand)]
    action: Option<DevAction>,
    #[command(flatten)]
    start: StartArgs,
}

#[derive(Debug, Subcommand)]
enum DevAction {
    /// Write a bearer header file for a client an access profile names,
    /// signed with the running session's key and valid for one hour.
    Token(TokenArgs),
}

#[derive(Debug, Args)]
struct TokenArgs {
    /// A client that one access profile in messaging.yaml names.
    #[arg(value_name = "CLIENT")]
    client: String,
    /// The package directory the session runs.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
}

/// Start a session in the foreground and stop it on Ctrl-C or SIGTERM.
///
/// The session needs Docker. It pulls and runs the pinned images
/// postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675
/// and
/// axllent/mailpit:v1.31.2@sha256:74d609a42ec279aa63c6b4622a6fa9b5408d1ad5b1d76a1c4be40a265ce0863d,
/// each publishing on 127.0.0.1 only, and removes both when it stops.
#[derive(Debug, Args)]
struct StartArgs {
    /// The package directory to run, as `messagingctl init` writes it.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// The runtime's loopback port.
    #[arg(long, env = "MESSAGINGCTL_DEV_PORT", default_value_t = 8107)]
    port: u16,
    /// The runtime's loopback metrics port.
    #[arg(long, env = "MESSAGINGCTL_DEV_METRICS_PORT", default_value_t = 9107)]
    metrics_port: u16,
    /// How long the mock gateway takes to answer each send, in milliseconds.
    #[arg(long, value_name = "MILLISECONDS", default_value_t = 200)]
    mock_latency_ms: u64,
    #[arg(long, hide = true, default_value = "docker")]
    docker_bin: PathBuf,
}

/// Why a development step stopped: the exit code, a stable problem code,
/// and a message that never carries a secret.
#[derive(Debug)]
pub(crate) struct DevFailure {
    pub exit: u8,
    pub code: &'static str,
    pub message: String,
}

pub(crate) type DevResult<T> = Result<T, DevFailure>;

/// A service, file, or container could not be reached or started.
fn failed(message: String) -> DevFailure {
    DevFailure {
        exit: OPERATIONAL_FAILURE_EXIT,
        code: "dev.failed",
        message,
    }
}

/// The project or the request cannot be run as asked.
fn refused(message: String) -> DevFailure {
    DevFailure {
        exit: REFUSAL_EXIT,
        code: "dev.refused",
        message,
    }
}

fn interrupted() -> DevFailure {
    DevFailure {
        exit: OPERATIONAL_FAILURE_EXIT,
        code: "dev.interrupted",
        message: "the session was stopped before it was ready".to_owned(),
    }
}

impl DevFailure {
    fn outcome(&self) -> Outcome {
        Outcome::refused(self.exit, self.code, "/", self.message.clone())
    }
}

/// Run `messagingctl dev` or `messagingctl dev token`.
pub(crate) fn run(
    args: DevArgs,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    match args.action {
        Some(DevAction::Token(token_args)) => {
            let outcome = token(&token_args).unwrap_or_else(|failure| failure.outcome());
            finish(&outcome, format, stdout, stderr)
        }
        None => start(&args.start, format, stdout, stderr),
    }
}

fn project_directory(project: &Path) -> DevResult<PathBuf> {
    let project = fs::canonicalize(project).map_err(|error| {
        refused(format!(
            "the project {} cannot be read: {error}",
            project.display()
        ))
    })?;
    // Every string of the generated runtime configuration is substituted
    // from the environment, so a path that reads as an expression would not
    // name this project.
    if project.to_string_lossy().contains("${") {
        return Err(refused(
            "the project path contains `${`, which the runtime configuration would read as an environment expression; move the project".to_owned(),
        ));
    }
    Ok(project)
}

fn package(project: &Path) -> DevResult<LoadedPackage> {
    load_package(project).map_err(|error| {
        refused(format!(
            "the package does not pass its checks; run messagingctl check --package: {error}"
        ))
    })
}

fn session_directory(project: &Path) -> PathBuf {
    project.join(STATE_DIRECTORY).join(SESSION_DIRECTORY)
}

fn token(args: &TokenArgs) -> DevResult<Outcome> {
    let project = project_directory(&args.project)?;
    let loaded = package(&project)?;
    let root = session_directory(&project);
    private::check(&root, true).map_err(|error| {
        refused(format!(
            "no development session exists in this project ({error}); start one with messagingctl dev"
        ))
    })?;
    let signed = config::token(&root, &loaded, &args.client)?;
    let header = config::header_file(&root, &args.client, &signed)?;
    Ok(Outcome::new(
        json!({
            "ok": true,
            "client": args.client,
            "headerFile": header,
            "expiresInSeconds": 3600,
        }),
        View::DevToken,
    ))
}

/// The containers a session started, recorded as each one is created so a
/// failed or interrupted start still removes it.
struct Session {
    root: PathBuf,
    owner: String,
    containers: Vec<String>,
}

impl Session {
    fn record(&mut self, container: &str) -> DevResult<()> {
        self.containers.push(container.to_owned());
        self.write("starting", &json!({}))
    }

    fn write(&self, state: &str, detail: &Value) -> DevResult<()> {
        let record = json!({
            "owner": self.owner,
            "state": state,
            "containers": self.containers,
            "detail": detail,
        });
        private::replace(
            &self.root.join("session.json"),
            record.to_string().as_bytes(),
        )
        .map_err(|error| failed(format!("the session record could not be written: {error}")))
    }
}

/// Remove what an earlier session in this project left: its containers,
/// by the owner its record names, and its private directory.
fn clear_previous(root: &Path, docker: &docker::Docker) -> DevResult<()> {
    if fs::symlink_metadata(root).is_err() {
        return Ok(());
    }
    private::check(root, true).map_err(|error| {
        refused(format!(
            "the session directory {} is unsafe: {error}",
            root.display()
        ))
    })?;
    let record = root.join("session.json");
    if fs::symlink_metadata(&record).is_ok() {
        let bytes = private::read(&record, MAXIMUM_SESSION_BYTES).map_err(|error| {
            failed(format!(
                "the previous session record is unreadable: {error}"
            ))
        })?;
        let owner = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| value["owner"].as_str().map(str::to_owned))
            .ok_or_else(|| failed("the previous session record names no owner".to_owned()))?;
        docker.remove(&docker.owned(&owner)?)?;
    }
    fs::remove_dir_all(root).map_err(|error| {
        failed(format!(
            "the previous session could not be removed: {error}"
        ))
    })
}

fn fresh_session(project: &Path, docker: &docker::Docker) -> DevResult<(private::Lock, PathBuf)> {
    let state = project.join(STATE_DIRECTORY);
    private::directory(&state).map_err(|error| {
        refused(format!(
            "the state directory {} is unsafe: {error}",
            state.display()
        ))
    })?;
    match private::create(&state.join(".gitignore"), b"*\n") {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(failed(format!(
                "the state directory is not writable: {error}"
            )))
        }
    }
    let lock = private::lock(&state.join("dev.lock"))
        .map_err(|error| failed(format!("the session lock is unusable: {error}")))?
        .ok_or_else(|| {
            refused("another messagingctl dev session is running in this project".to_owned())
        })?;
    let root = state.join(SESSION_DIRECTORY);
    clear_previous(&root, docker)?;
    for directory in [
        root.clone(),
        root.join("secrets"),
        root.join("database"),
        root.join("issuer"),
        root.join("audit"),
        root.join("logs"),
        root.join("tokens"),
    ] {
        private::directory(&directory).map_err(|error| {
            failed(format!(
                "the session directory could not be created: {error}"
            ))
        })?;
    }
    Ok((lock, root))
}

fn start(
    args: &StartArgs,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let docker = docker::Docker::new(args.docker_bin.clone());
    let project = match project_directory(&args.project).and_then(|project| {
        let loaded = package(&project)?;
        Ok((project, loaded))
    }) {
        Ok(found) => found,
        Err(failure) => return finish(&failure.outcome(), format, stdout, stderr),
    };
    let (project, loaded) = project;
    let (_lock, root) = match fresh_session(&project, &docker) {
        Ok(session) => session,
        Err(failure) => return finish(&failure.outcome(), format, stdout, stderr),
    };
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
            let failure = failed(format!("the stop signal could not be handled: {error}"));
            return finish(&failure.outcome(), format, stdout, stderr);
        }
    }
    let mut session = Session {
        root: root.clone(),
        owner: uuid::Uuid::new_v4().simple().to_string(),
        containers: Vec::new(),
    };
    let served = run_session(
        args,
        &project,
        &loaded,
        &docker,
        &mut session,
        &stop,
        format,
        stdout,
        stderr,
    );
    let removed = docker.remove(&session.containers);
    let removed_all = removed.is_ok();
    // A container that could not be removed stays in the record, so the
    // next start in this project removes it.
    let recorded = session.write(
        if removed_all {
            "stopped"
        } else {
            "stop-failed"
        },
        &json!({}),
    );
    let failure = served.and(removed).and(recorded).err();
    if let Some(failure) = failure {
        let mut outcome = failure.outcome();
        outcome.report["containersRemoved"] = json!(removed_all);
        outcome.report["sessionDirectory"] = json!(root);
        return finish(&outcome, format, stdout, stderr);
    }
    let outcome = Outcome::new(
        json!({
            "ok": true,
            "state": "stopped",
            "sessionDirectory": root,
            "containersRemoved": true,
        }),
        View::Dev,
    );
    match print_report(&outcome, format, stdout, stderr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(OPERATIONAL_FAILURE_EXIT),
    }
}

/// Print a session report. In JSON each report is one line, so a caller
/// can read the ready report while the session keeps running.
fn print_report(
    outcome: &Outcome,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> io::Result<()> {
    match format {
        OutputFormat::Json => {
            let mut line = serde_json::to_vec(&outcome.report).map_err(io::Error::other)?;
            line.push(b'\n');
            stdout.write_all(&line)?;
        }
        OutputFormat::Human => render_human(outcome, stdout, stderr)?,
    }
    stdout.flush()
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    args: &StartArgs,
    project: &Path,
    loaded: &LoadedPackage,
    docker: &docker::Docker,
    session: &mut Session,
    stop: &AtomicBool,
    format: OutputFormat,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> DevResult<()> {
    let root = session.root.clone();
    session.write("starting", &json!({}))?;
    let passwords = config::generate(&root)?;
    let owner = session.owner.clone();
    let short = &owner[..12];
    let database_port = docker::postgres(
        docker,
        &format!("messagingctl-dev-postgres-{short}"),
        &owner,
        &docker::DatabaseFiles {
            env_file: &root.join("database/postgres.env"),
            pg_hba: &root.join("database/pg_hba.conf"),
            server_certificate: &root.join("database/server.pem"),
            server_key: &root.join("database/server.key"),
            migration_password: &passwords.migration,
            runtime_password: &passwords.runtime,
        },
        stop,
        &mut |container| session.record(container),
    )?;
    config::database_urls(&root, database_port, &passwords)?;
    drop(passwords);
    if stop.load(Ordering::SeqCst) {
        return Err(interrupted());
    }
    let (smtp_port, mailpit_port) = docker::mailpit(
        docker,
        &format!("messagingctl-dev-mailpit-{short}"),
        &owner,
        &mut |container| session.record(container),
    )?;
    initialize_logging(&root.join("logs/messaging.log"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| failed(format!("the async runtime could not start: {error}")))?;
    let result = runtime.block_on(async {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| failed(format!("the readiness client could not start: {error}")))?;
        wait_ready(
            &client,
            &format!("http://127.0.0.1:{mailpit_port}/readyz"),
            "Mailpit",
            stop,
            None,
        )
        .await?;
        let token = read_secret(&root, "gateway-token")?;
        let (gateway_address, _counts) = gateway::start(gateway::GatewaySettings {
            token: Zeroizing::new(String::from_utf8_lossy(&token).into_owned()),
            callback_key: read_secret(&root, "gateway-callback-key")?,
            runtime_origin: format!("http://127.0.0.1:{}", args.port),
            latency: Duration::from_millis(args.mock_latency_ms),
            callback_delay: CALLBACK_DELAY,
        })
        .await
        .map_err(|error| failed(format!("the mock gateway could not start: {error}")))?;
        let endpoints = config::Endpoints {
            api_port: args.port,
            metrics_port: args.metrics_port,
            smtp_port,
            gateway_port: gateway_address.port(),
        };
        let runtime_config = root.join("runtime.yaml");
        let document =
            serde_norway::to_string(&config::runtime_config(project, &root, loaded, &endpoints))
                .map_err(|error| {
                    failed(format!(
                        "the runtime configuration could not be written: {error}"
                    ))
                })?;
        private::create(&runtime_config, document.as_bytes()).map_err(|error| {
            failed(format!(
                "the runtime configuration could not be written: {error}"
            ))
        })?;
        migrate_from_path(&runtime_config)
            .await
            .map_err(|error| failed(format!("the database could not be migrated: {error}")))?;
        let checked = RuntimeConfig::load(&runtime_config).map_err(|error| {
            failed(format!(
                "the generated runtime configuration was refused: {error}"
            ))
        })?;
        apply_package(&checked, true)
            .await
            .map_err(|error| failed(format!("the package could not be applied: {error}")))?;
        let mut serve = tokio::spawn(serve_from_path(runtime_config.clone(), Transports::new()));
        let origin = format!("http://127.0.0.1:{}", args.port);
        wait_ready(
            &client,
            &format!("{origin}{READY_PATH}"),
            "the Messaging runtime",
            stop,
            Some(&mut serve),
        )
        .await?;

        let ready = json!({
            "ok": true,
            "state": "ready",
            "api": origin,
            "metrics": format!("http://127.0.0.1:{}/metrics", args.metrics_port),
            "mailpit": format!("http://127.0.0.1:{mailpit_port}"),
            "mockGateway": format!("http://{gateway_address}"),
            "mockLatencyMilliseconds": args.mock_latency_ms,
            "runtimeConfig": runtime_config,
            "log": root.join("logs/messaging.log"),
            "sessionDirectory": root,
        });
        session.write("ready", &ready)?;
        print_report(&Outcome::new(ready, View::Dev), format, stdout, stderr)
            .map_err(|error| failed(format!("the ready report could not be written: {error}")))?;

        loop {
            if stop.load(Ordering::SeqCst) {
                serve.abort();
                return Ok(());
            }
            if serve.is_finished() {
                return Err(match serve.await {
                    Ok(Err(error)) => failed(format!("the Messaging runtime stopped: {error}")),
                    Ok(Ok(())) => failed("the Messaging runtime stopped".to_owned()),
                    Err(error) => failed(format!("the Messaging runtime stopped: {error}")),
                });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

fn read_secret(root: &Path, name: &str) -> DevResult<Zeroizing<Vec<u8>>> {
    private::read(&root.join("secrets").join(name), 4096)
        .map(Zeroizing::new)
        .map_err(|error| failed(format!("the session secret {name} is unreadable: {error}")))
}

/// Poll `url` until it answers 200, the deadline passes, a stop signal
/// arrives, or the task that should answer it ends.
async fn wait_ready(
    client: &reqwest::Client,
    url: &str,
    service: &str,
    stop: &AtomicBool,
    mut task: Option<
        &mut tokio::task::JoinHandle<Result<(), registry_messaging::runtime::RuntimeError>>,
    >,
) -> DevResult<()> {
    let deadline = Instant::now() + READY_DEADLINE;
    loop {
        if stop.load(Ordering::SeqCst) {
            if let Some(task) = task {
                task.abort();
            }
            return Err(interrupted());
        }
        if let Some(handle) = task.as_mut() {
            if handle.is_finished() {
                return Err(match (&mut **handle).await {
                    Ok(Err(error)) => failed(format!("{service} did not start: {error}")),
                    Ok(Ok(())) => failed(format!("{service} stopped before it was ready")),
                    Err(error) => failed(format!("{service} did not start: {error}")),
                });
            }
        }
        if let Ok(response) = client.get(url).send().await {
            if response.status() == reqwest::StatusCode::OK {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            if let Some(task) = task {
                task.abort();
            }
            return Err(failed(format!(
                "{service} did not answer as ready in {} seconds; see the session log",
                READY_DEADLINE.as_secs()
            )));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Send the runtime's JSON log lines, and the session's own, to the
/// session's private log file, so the terminal shows only the reports.
fn initialize_logging(path: &Path) -> DevResult<()> {
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::prelude::*;

    let level = operational_log_level(std::env::var("MESSAGING_LOG").ok().as_deref())
        .map_err(|error| refused(format!("MESSAGING_LOG is refused: {error}")))?;
    let file = fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| failed(format!("the session log could not be created: {error}")))?;
    let filter = Targets::new()
        .with_target("registry_messaging", level)
        .with_target("registry_messaging_core", level)
        .with_target("registry_messagingctl", level);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(Mutex::new(file)),
        )
        .try_init()
        .map_err(|error| failed(format!("the session log could not be installed: {error}")))
}

#[cfg(test)]
mod tests;
