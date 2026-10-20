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

mod borrowed;
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
use registry_messaging::activation::ApplyRequest;
use registry_messaging::config::RuntimeConfig;
use registry_messaging::dispatch::Transports;
use registry_messaging::package::{
    load_package, load_project, package_inputs, write_package_inputs, LoadedPackage,
};
use registry_messaging::runtime::{apply_activation, operational_log_level, serve_from_path};
use registry_messaging_core::{ProviderKind, READY_PATH};
use registry_platform_yaml::{Diagnostic, Report, Severity, Source};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    completed, finish, render_human, report, Outcome, OutputFormat, View, DOMAIN_REFUSAL_EXIT,
    OPERATIONAL_FAILURE_EXIT,
};

const DATABASE_NAME: &str = "messaging_dev";
const MIGRATION_ROLE: &str = "messaging_dev_migration";
const RUNTIME_ROLE: &str = "messaging_dev_runtime";
/// The project's private state directory and the session directory in it.
const STATE_DIRECTORY: &str = ".messaging";
const SESSION_DIRECTORY: &str = "dev";
/// The largest session record a start reads back: the bound every
/// configuration file shares (CFG-YAML-6).
const MAXIMUM_SESSION_BYTES: u64 = registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64;
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
    /// using the running session's local key or borrowed issuer.
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
/// `docker::POSTGRES_IMAGE` and `docker::MAILPIT_IMAGE`, each publishing on
/// 127.0.0.1 only, and removes both when it stops.
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
    /// Borrow pre-registered clients from this Base Registry Engine (BReg) development project.
    #[arg(long, value_name = "PROJECT", requires = "resource")]
    issuer_project: Option<PathBuf>,
    /// The exact Messaging audience registered at the borrowed issuer.
    #[arg(long, value_name = "URI", requires = "issuer_project")]
    resource: Option<String>,
    #[arg(long, hide = true, default_value = "bregctl")]
    bregctl_bin: PathBuf,
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
        exit: DOMAIN_REFUSAL_EXIT,
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
    pub(super) fn outcome(&self) -> Outcome {
        Outcome::refused(self.exit, self.code, "/", self.message.clone())
    }
}

/// The subcommand path a `dev` invocation selected, as its report names it.
pub(crate) fn command_path(args: &DevArgs) -> &'static str {
    match args.action {
        Some(DevAction::Token(_)) => "dev token",
        None => "dev",
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
            finish(&outcome, "dev token", format, stdout, stderr)
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
    // The runtime configuration loader substitutes environment expressions
    // in the string values of the parsed document, so a project path in the
    // generated configuration that reads as an expression would not name
    // this project.
    if project.to_string_lossy().contains("${") {
        return Err(refused(
            "the project path contains `${`, which the runtime configuration would read as an environment expression; move the project".to_owned(),
        ));
    }
    Ok(project)
}

fn package(project: &Path) -> DevResult<LoadedPackage> {
    load_project(project).map_err(|error| {
        refused(format!(
            "the project does not pass its checks; run messagingctl check --project: {error}"
        ))
    })
}

fn install_project(project: &Path, root: &Path) -> DevResult<LoadedPackage> {
    let inputs = package_inputs(project).map_err(|error| {
        refused(format!(
            "the project does not pass its checks; run messagingctl check --project: {error}"
        ))
    })?;
    let installed = root.join("package");
    write_package_inputs(&installed, &inputs, None).map_err(|error| {
        failed(format!(
            "the development package could not be written: {error}"
        ))
    })?;
    load_package(&installed).map_err(|error| {
        failed(format!(
            "the development package could not be loaded: {error}"
        ))
    })
}

fn session_directory(project: &Path) -> PathBuf {
    project.join(STATE_DIRECTORY).join(SESSION_DIRECTORY)
}

fn token(args: &TokenArgs) -> DevResult<Outcome> {
    let project = project_directory(&args.project)?;
    let root = session_directory(&project);
    private::check(&root, true).map_err(|error| {
        refused(format!(
            "no development session exists in this project ({error}); start one with messagingctl dev"
        ))
    })?;
    let loaded = load_package(&root.join("package")).map_err(|error| {
        refused(format!(
            "the running session package is unavailable ({error}); start messagingctl dev again"
        ))
    })?;
    let record = read_session(&root)?;
    let (signed, expires) = if let Some(binding) = &record.borrowed_issuer {
        if record.state != "ready" {
            return Err(refused(
                "the borrowed development session is not ready; start messagingctl dev again"
                    .to_owned(),
            ));
        }
        borrowed::refresh(&root, &loaded, binding, &args.client)?
    } else {
        (config::token(&root, &loaded, &args.client)?, 3600)
    };
    let header = config::header_file(&root, &args.client, &signed)?;
    Ok(Outcome::new(
        json!({
            "ok": true,
            "client": args.client,
            "headerFile": header,
            "expiresInSeconds": expires,
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
    borrowed: Option<borrowed::Binding>,
}

pub(crate) const DEV_STATE_API_VERSION: &str =
    "id.registrystack.org/formats/messaging/dev-state/v1alpha1";
pub(crate) const DEV_STATE_KIND: &str = "MessagingDevState";
const DEV_STATE_FORMAT: registry_platform_yaml::FormatSpec<'static> =
    registry_platform_yaml::FormatSpec {
        kind: DEV_STATE_KIND,
        envelope: registry_platform_yaml::EnvelopeRule::ApiVersionKind {
            api_versions: &[registry_platform_yaml::ApiVersion::current(
                DEV_STATE_API_VERSION,
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };

/// Private read-back state. Keys and tokens are files, never record members.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionRecord {
    api_version: String,
    kind: String,
    owner: String,
    state: String,
    containers: Vec<String>,
    detail: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    borrowed_issuer: Option<borrowed::Binding>,
}

fn read_session(root: &Path) -> DevResult<SessionRecord> {
    let file = root.join("session.json");
    let bytes = private::read(&file, MAXIMUM_SESSION_BYTES).map_err(|_| {
        refused(
            "the development session record is unavailable; start messagingctl dev again"
                .to_owned(),
        )
    })?;
    decode_session(&file.display().to_string(), &bytes)
        .map(|(record, _)| record)
        .map_err(|_| refused("the development session record is invalid; preserve it for inspection and restart with the messagingctl version that wrote it".to_owned()))
}

fn decode_session(file: &str, bytes: &[u8]) -> Result<(SessionRecord, Report), Report> {
    let decoded = registry_platform_yaml::Reader::new(file).decode::<SessionRecord>(
        bytes,
        &registry_platform_yaml::Expect::one(&DEV_STATE_FORMAT),
    )?;
    let mut report = decoded.document.warnings();
    if uuid::Uuid::parse_str(&decoded.value.owner).is_err() {
        report.push(decoded.document.diagnostic_at_value(
            Severity::Error,
            "messaging.dev-state.invalid-owner",
            "/owner",
            "the session owner is not an identifier messagingctl writes",
            "Preserve the file for inspection, remove the development session directory after stopping its containers, and start messagingctl dev again.",
        ));
    }
    if !matches!(
        decoded.value.state.as_str(),
        "starting" | "ready" | "stopped" | "stop-failed"
    ) {
        report.push(decoded.document.diagnostic_at_value(
            Severity::Error,
            "messaging.dev-state.invalid-state",
            "/state",
            "the session state is not one messagingctl writes",
            "Preserve the file for inspection and start messagingctl dev again.",
        ));
    }
    for invalid in decoded
        .value
        .borrowed_issuer
        .iter()
        .flat_map(borrowed::Binding::invalid_members)
    {
        report.push(decoded.document.diagnostic_at_value(
            Severity::Error,
            "messaging.dev-state.invalid-borrowed-issuer",
            &format!("/borrowedIssuer/{}", invalid.member),
            invalid.message,
            invalid.suggested_action,
        ));
    }
    if report.has_errors() {
        Err(report)
    } else {
        Ok((decoded.value, report))
    }
}

#[derive(Debug)]
pub(crate) struct SessionCheckFailure {
    pub(crate) exit: u8,
    pub(crate) report: Report,
}

fn file_report(path: &Path, code: &str, message: &str, suggested_action: &str) -> Report {
    let mut diagnostic = Diagnostic::error(code, "", message, suggested_action);
    diagnostic.artifact = Some(DEV_STATE_KIND.to_owned());
    diagnostic.source = Some(Source {
        file: path.display().to_string(),
        line: None,
        column: None,
    });
    let mut report = Report::new(vec![diagnostic]);
    report.set_files_checked(1);
    report
}

/// Validate generated read-back state without accessing secrets or services.
pub(crate) fn check_session_file(path: &Path) -> Result<Report, SessionCheckFailure> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    // One byte past the bound is enough for the shared reader to refuse the
    // file as `yaml.too-large`.
    fs::File::open(path)
        .and_then(|file| file.take(MAXIMUM_SESSION_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| SessionCheckFailure {
            exit: OPERATIONAL_FAILURE_EXIT,
            report: file_report(
                path,
                "messaging.dev-state.file-unreadable",
                "the development session file could not be read",
                "Name an existing development session file that this user may read.",
            ),
        })?;
    decode_session(&path.display().to_string(), &bytes)
        .map(|(_, report)| report)
        .map_err(|report| SessionCheckFailure {
            exit: DOMAIN_REFUSAL_EXIT,
            report,
        })
}

impl Session {
    fn record(&mut self, container: &str) -> DevResult<()> {
        self.containers.push(container.to_owned());
        self.write("starting", &json!({}))
    }

    fn write(&self, state: &str, detail: &Value) -> DevResult<()> {
        let record = SessionRecord {
            api_version: DEV_STATE_API_VERSION.to_owned(),
            kind: DEV_STATE_KIND.to_owned(),
            owner: self.owner.clone(),
            state: state.to_owned(),
            containers: self.containers.clone(),
            detail: detail.clone(),
            borrowed_issuer: self.borrowed.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| failed(format!("the session record could not be written: {error}")))?;
        private::replace(&self.root.join("session.json"), &bytes)
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
        let owner = previous_owner(&record, &bytes)?;
        docker.remove(&docker.owned(&owner)?)?;
    }
    fs::remove_dir_all(root).map_err(|error| {
        failed(format!(
            "the previous session could not be removed: {error}"
        ))
    })
}

/// Read only a validated owner for cleanup. An enveloped record always goes
/// through the current typed reader. The fallback is limited to the exact
/// pre-envelope distinction, and its owner still has to be a UUID before it
/// can select Docker resources.
fn previous_owner(file: &Path, bytes: &[u8]) -> DevResult<String> {
    let invalid = || {
        failed(
            "the previous session record is invalid; preserve it for inspection and remove its containers manually"
                .to_owned(),
        )
    };
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let object = value.as_object().ok_or_else(&invalid)?;
    let owner = if object.contains_key("apiVersion") || object.contains_key("kind") {
        decode_session(&file.display().to_string(), bytes)
            .map_err(|_| invalid())?
            .0
            .owner
    } else {
        object
            .get("owner")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(&invalid)?
    };
    uuid::Uuid::parse_str(&owner).map_err(|_| invalid())?;
    Ok(owner)
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
        Err(failure) => return finish(&failure.outcome(), "dev", format, stdout, stderr),
    };
    let (project, _) = project;
    if let Some(resource) = &args.resource {
        if !registry_platform_httputil::valid_resource_uri(resource) {
            return finish(
                &refused(
                    "--resource must be an absolute resource URI without credentials or fragment"
                        .to_owned(),
                )
                .outcome(),
                "dev",
                format,
                stdout,
                stderr,
            );
        }
    }
    let (_lock, root) = match fresh_session(&project, &docker) {
        Ok(session) => session,
        Err(failure) => return finish(&failure.outcome(), "dev", format, stdout, stderr),
    };
    let loaded = match install_project(&project, &root) {
        Ok(loaded) => loaded,
        Err(failure) => return finish(&failure.outcome(), "dev", format, stdout, stderr),
    };
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        if let Err(error) = signal_hook::flag::register(signal, Arc::clone(&stop)) {
            let failure = failed(format!("the stop signal could not be handled: {error}"));
            return finish(&failure.outcome(), "dev", format, stdout, stderr);
        }
    }
    let mut session = Session {
        root: root.clone(),
        owner: uuid::Uuid::new_v4().simple().to_string(),
        containers: Vec::new(),
        borrowed: None,
    };
    let served = run_session(
        args,
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
        return finish(&outcome, "dev", format, stdout, stderr);
    }
    let outcome = Outcome::new(
        json!({
            "ok": true,
            "status": "stopped",
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
            report::write_line(&completed(&outcome.report, "dev", outcome.exit), stdout)?;
        }
        OutputFormat::Human => render_human(outcome, "dev", stdout, stderr)?,
    }
    stdout.flush()
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    args: &StartArgs,
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
    // Issuer preflight precedes owned containers and leaves the owner's
    // lifecycle entirely with bregctl.
    if let Some(project) = &args.issuer_project {
        session.borrowed = Some(borrowed::capture(
            &root,
            loaded,
            project,
            args.resource.as_deref().expect("paired options"),
            &args.bregctl_bin,
            stop,
        )?);
        session.write("starting", &json!({}))?;
    }
    let passwords = config::generate(&root, session.borrowed.is_none())?;
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
            providers: loaded
                .package
                .providers()
                .filter(|provider| provider.kind == ProviderKind::Http)
                .map(|provider| provider.id.clone())
                .collect(),
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
        let document = config::runtime_document_with_issuer(
            &root.join("package"),
            &root,
            loaded,
            &endpoints,
            session.borrowed.as_ref(),
        )
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
        let checked = RuntimeConfig::load(&runtime_config).map_err(|error| {
            failed(format!(
                "the generated runtime configuration was refused: {error}"
            ))
        })?;
        apply_activation(&checked, &ApplyRequest::default())
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
            "status": "ready",
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
mod state_tests;
#[cfg(test)]
mod tests;
