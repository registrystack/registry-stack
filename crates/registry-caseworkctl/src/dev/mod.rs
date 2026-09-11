// SPDX-License-Identifier: Apache-2.0
//! Native, retained, loopback-only Casework tutorial lifecycle.
//!
//! A resident supervisor owns the service children. The only database it may
//! start or stop is the container whose random ownership label and immutable
//! Docker ID match its private journal. There is intentionally no reset.

mod config;
mod private;
#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use config::Clients;
use registry_casework_core::CaseworkRole;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::TcpListener,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const DATABASE_NAME: &str = "casework_dev";
const MIGRATION_ROLE: &str = "casework_dev_migration";
const RUNTIME_ROLE: &str = "casework_dev_runtime";
const IMAGE: &str =
    "postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675";
const LABEL: &str = "org.registrystack.caseworkctl.dev-owner";
/// Refusal for a project that never started. Reporting a stopped session
/// would claim owned services were stopped when none were ever created.
const MISSING_SESSION: &str = "no local development session exists in this project; nothing was stopped. Check the project path, or start one with caseworkctl dev";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Longest one supervised prerequisite command may run before the supervisor
/// stops it and fails the start.
const CHILD_DEADLINE: Duration = Duration::from_secs(120);
/// Longest the supervisor waits for the owned database, and for each started
/// service, to answer as ready.
const READY_DEADLINE: Duration = Duration::from_secs(45);
/// The stop response covers two graceful child shutdowns followed by the
/// database stop. Each of those operations keeps its own tighter deadline.
const STOP_RESPONSE_DEADLINE: Duration = Duration::from_secs(8 * 60);
/// Recorded when an installed prerequisite does not report a usable version.
const UNREPORTED_VERSION: &str = "unreported";
/// Longest version line kept from a prerequisite that prints a banner.
const MAX_VERSION: usize = 200;
/// Shortest run of secret bytes that must not survive in captured output.
const SECRET_RUN: usize = 8;
/// Longest refusal carried out of a native child or out of the supervisor.
const MAX_REFUSAL: usize = 400;
/// Maximum bytes the supervisor entry point can add to its retained log when
/// it reports one bounded error plus its terminating newline.
const MAX_SUPERVISOR_ERROR_BYTES: u64 = MAX_REFUSAL as u64 * 4 + 1;
/// Bound on the journal tail `dev events` reports, in bytes and in lines.
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const MAX_JOURNAL_LINES: usize = 512;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum retained UUID-named prerequisite logs. Each file is independently
/// bounded by `MAX_BYTES`; rotating the oldest before each new command also
/// bounds diagnostics across retained starts while keeping the newest run.
const MAX_PREREQUISITE_LOGS: usize = 64;
const SUPERVISOR_RELEASE_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct DevArgs {
    #[command(subcommand)]
    action: Option<DevAction>,
    #[command(flatten)]
    start: StartArgs,
}

#[derive(Debug, Subcommand)]
enum DevAction {
    /// Start or reuse the project's retained local database and services.
    ///
    /// A resident supervisor owns this project's PostgreSQL container plus its
    /// local Registry Mint and Casework children. The database runs the pinned
    /// image
    /// postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675,
    /// which the supervisor pulls on the first start. Each supervised
    /// prerequisite command may run for 120 seconds, and the database and each
    /// started service have 45 seconds to answer as ready. A start that passes
    /// a deadline fails, stops what it acquired, and keeps its owner-only
    /// diagnostics in the project's private .casework/dev/logs directory.
    Start(StartArgs),
    /// Stop only this project's supervised services, preserving its database.
    Stop(StopArgs),
    /// Print the bounded retained runtime journal.
    Events(EventsArgs),
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Existing authored Casework project directory.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// Local clients and their directory teams (default on first start:
    /// dev-clients.yaml in the project; retained for restarts).
    #[arg(long, alias = "clients", value_name = "FILE")]
    clients_file: Option<PathBuf>,
    /// Casework loopback port on first start (default 8092; retained for restarts).
    #[arg(long, env = "CASEWORKCTL_DEV_CASEWORK_PORT")]
    casework_port: Option<u16>,
    /// Local Mint loopback port on first start (default 8093; retained for restarts).
    #[arg(long, env = "CASEWORKCTL_DEV_MINT_PORT")]
    mint_port: Option<u16>,
    /// PostgreSQL loopback port on first start (default 55433; retained for restarts).
    #[arg(long, env = "CASEWORKCTL_DEV_DATABASE_PORT")]
    database_port: Option<u16>,
    #[arg(long, hide = true, env = "CASEWORK_BIN")]
    casework_bin: Option<PathBuf>,
    #[arg(long, hide = true)]
    mint_bin: Option<PathBuf>,
    #[arg(long, hide = true)]
    docker_bin: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct StopArgs {
    /// Casework project whose owned services should stop while preserving records.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// Also remove the owned container and its data volume, discarding records.
    #[arg(long)]
    remove: bool,
    #[arg(long, hide = true)]
    docker_bin: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct EventsArgs {
    /// Casework project whose retained runtime journal should be inspected.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
}

#[derive(Debug, Args)]
pub struct SupervisorArgs {
    #[arg(long)]
    dev_root: PathBuf,
    #[arg(long)]
    casework_bin: PathBuf,
    #[arg(long)]
    mint_bin: PathBuf,
    #[arg(long)]
    docker_bin: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    version: u8,
    project: PathBuf,
    owner: String,
    status: Status,
    casework_port: u16,
    mint_port: u16,
    database_port: u16,
    clients_file: PathBuf,
    source_digest: String,
    /// Every local client with the access profile it binds and that profile's
    /// role, recorded so the report needs no second reading of the project.
    clients: Vec<ReportedClient>,
    container_id: Option<String>,
    tls_files_copied: bool,
    database_ready: bool,
    /// Whether this retained database has completed at least one migration.
    /// Migrations remain idempotent and run again on every start so an upgraded
    /// toolset cannot reuse an older schema.
    migrated: bool,
    /// Directory teams this session has already seeded, by team identifier.
    seeded: BTreeSet<String>,
    directory_revision: i64,
    directory_teams: usize,
    /// Installed prerequisites this session resolved, keyed by command name.
    #[serde(default)]
    binaries: BTreeMap<String, Binary>,
    /// Why the detached supervisor stopped, recorded so the terminal that
    /// asked for the start can report it. The supervisor writes both its
    /// streams to a private log, so this is the only path a refusal has back
    /// to the owner.
    #[serde(default)]
    failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportedClient {
    id: String,
    profile: String,
    role: CaseworkRole,
    /// The subject the runtime sees for this client, resolved from its access
    /// profile's `principalClaim`. It is a local teaching identity, never a
    /// deployment identity, and it is what the seeded directory records.
    principal: String,
}

/// One resolved prerequisite as the session found it. The path resolves
/// symlinks so a later diagnosis names the file that actually ran, which the
/// executed path deliberately does not.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binary {
    path: PathBuf,
    version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

impl State {
    fn root(&self) -> PathBuf {
        self.project.join(".casework/dev")
    }
    fn container_name(&self) -> String {
        format!("casework-dev-{}", self.owner)
    }
    /// The owned data volume carries the container's generated name; Docker
    /// keeps container and volume names in separate namespaces.
    fn volume_name(&self) -> String {
        format!("casework-dev-{}", self.owner)
    }
    fn container_id(&self) -> Result<&str> {
        self.container_id
            .as_deref()
            .context("owned Docker identity has not been recorded")
    }
    fn casework_origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.casework_port)
    }
    fn mint_origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.mint_port)
    }
    fn audience(&self) -> String {
        format!("urn:casework:dev:{}", self.owner)
    }
    fn administrator(&self) -> Result<&ReportedClient> {
        self.clients
            .iter()
            .find(|client| client.role == CaseworkRole::Administrator)
            .context("retained local clients bind no Administrator profile")
    }
    fn save(&self) -> Result<()> {
        private::replace(
            &self.root().join("state.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }
    fn report(&self) -> Value {
        let root = self.root();
        json!({"ok":true,"command":"dev","status":self.status,"project":self.project,
            "stateFile":root.join("state.json"),"operatorConfig":root.join("operator.yaml"),
            "caseworkUrl":self.casework_origin(),"tokenEndpoint":format!("{}/token",self.mint_origin()),
            "audience":self.audience(),"journal":root.join("logs/casework.log"),
            "clients":self.clients.iter().map(|client|json!({"id":client.id,"profile":client.profile,"role":client.role,
                "clientIdFile":root.join("credentials").join(&client.id).join("client-id"),
                "assertionKeyFile":root.join("credentials").join(&client.id).join("assertion-key.jwk")})).collect::<Vec<_>>(),
            "directory":{"revision":self.directory_revision,"teams":self.directory_teams}})
    }
}

pub(crate) fn run(args: DevArgs) -> Result<Value> {
    match args.action {
        Some(DevAction::Stop(args)) => stop(&args.project, args.remove, args.docker_bin.as_deref()),
        Some(DevAction::Events(args)) => events(&args.project),
        Some(DevAction::Start(args)) => start(args),
        None => start(args.start),
    }
}

fn project(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)?.is_dir() {
        bail!("project must be an ordinary existing directory");
    }
    Ok(fs::canonicalize(path)?)
}

/// The project's private `.casework` directory, ignored by version control as
/// a whole: the session directory ignores itself, and the lock beside it would
/// otherwise be the one private file a reader could commit.
fn parent_directory(project: &Path) -> Result<PathBuf> {
    let parent = project.join(".casework");
    private::directory(&parent)?;
    let ignore = parent.join(".gitignore");
    if !ignore.exists() {
        private::create(&ignore, b"*\n")?;
    }
    Ok(parent)
}

/// The clients file a start reads: the one named, else the one the retained
/// session started with, else the `dev-clients.yaml` the project carries.
fn clients_file(
    explicit: Option<&Path>,
    retained: Option<&State>,
    project: &Path,
) -> Result<PathBuf> {
    match (explicit, retained) {
        (Some(path), _) => fs::canonicalize(path).context("clients file does not exist"),
        (None, Some(state)) => Ok(state.clients_file.clone()),
        (None, None) => {
            let generated = project.join("dev-clients.yaml");
            if generated.is_file() {
                fs::canonicalize(&generated).context("clients file does not exist")
            } else {
                bail!("first start needs local clients: add dev-clients.yaml to the project, as caseworkctl init does, or name a clients file with --clients-file");
            }
        }
    }
}

fn read_state(root: &Path) -> Result<State> {
    private::check(root, true)?;
    let state: State = serde_json::from_slice(&private::read(&root.join("state.json"), MAX_BYTES)?)
        .map_err(|_| {
            anyhow::anyhow!("retained dev state is invalid; preserve it for inspection")
        })?;
    if state.version != 1
        || state.root() != root
        || uuid::Uuid::parse_str(&state.owner).is_err()
        || state.directory_revision < 0
        || state
            .container_id
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("retained dev state ownership is invalid; no resources were changed");
    }
    ports(state.casework_port, state.mint_port, state.database_port)?;
    Ok(state)
}

fn ports(casework: u16, mint: u16, database: u16) -> Result<()> {
    if casework == 0
        || mint == 0
        || database == 0
        || BTreeSet::from([casework, mint, database]).len() != 3
    {
        bail!("three distinct nonzero loopback ports are required");
    }
    Ok(())
}

fn probe(port: u16) -> Result<()> {
    TcpListener::bind(("127.0.0.1", port))
        .map(drop)
        .context("a requested local port is already occupied; stop its owner or choose other ports")
}

fn bounded(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("{label} must be one ordinary readable file"))?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        bail!("{label} must be one bounded ordinary file");
    }
    fs::read(path).with_context(|| format!("cannot read {label}"))
}

#[derive(Debug)]
/// Everything the retained session is pinned to: the authored policy the
/// supervised runtime serves, and the local clients bound to it.
struct Captured {
    clients: Clients,
    digest: String,
    reported: Vec<ReportedClient>,
}

/// Catch terminal interruption while the foreground command waits for its
/// detached supervisor. Registrations are scoped to this one start attempt so
/// later commands in the same process keep their ordinary signal behavior.
struct StartInterruption {
    requested: Arc<AtomicBool>,
    registrations: Vec<signal_hook::SigId>,
}

impl StartInterruption {
    fn install() -> Result<Self> {
        let mut interruption = Self {
            requested: Arc::new(AtomicBool::new(false)),
            registrations: Vec::new(),
        };
        for signal in [
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGHUP,
        ] {
            let registration =
                signal_hook::flag::register(signal, Arc::clone(&interruption.requested))?;
            interruption.registrations.push(registration);
        }
        Ok(interruption)
    }
}

impl Drop for StartInterruption {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn capture(project: &Path, client_bytes: &[u8]) -> Result<Captured> {
    let policy = crate::project::load_and_check_policy(project)?;
    if !policy.sources.is_empty() {
        bail!("caseworkctl dev serves a project with no declared sources, because every source binding needs a running source system and its own reader credential. Run this project against a deployed Casework runtime, or start with the standalone-decision template");
    }
    let clients = config::clients(client_bytes)?;
    let bound = config::bind(&clients, &policy)?;
    let reported = bound
        .iter()
        .map(|entry| ReportedClient {
            id: entry.client.id.clone(),
            profile: entry.client.access_profile.clone(),
            role: entry.role,
            principal: entry.principal.clone(),
        })
        .collect();
    let project_bytes = bounded(&project.join("casework.yaml"), "casework.yaml")?;
    let mut hasher = Sha256::new();
    hasher.update(b"casework-dev-source/v1\0");
    for bytes in [project_bytes.as_slice(), client_bytes] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(Captured {
        clients,
        digest: config::hex_lower(&hasher.finalize()),
        reported,
    })
}

fn start(args: StartArgs) -> Result<Value> {
    let project = project(&args.project)?;
    let parent = parent_directory(&project)?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let root = parent.join("dev");
    let existing = if root.exists() {
        Some(read_state(&root)?)
    } else {
        None
    };
    let clients_file = clients_file(args.clients_file.as_deref(), existing.as_ref(), &project)?;
    let client_bytes = bounded(&clients_file, "clients file")?;
    let Captured {
        clients,
        digest,
        reported,
    } = capture(&project, &client_bytes)?;
    // The source pin protects the records a session retains. Once `dev stop
    // --remove` has discarded them, changed inputs start a fresh session on
    // the ports and clients file the previous one used.
    let mut previous = None;
    let existing = match existing {
        Some(state)
            if digest != state.source_digest
                || args.casework_port.is_some_and(|p| p != state.casework_port)
                || args.mint_port.is_some_and(|p| p != state.mint_port)
                || args.database_port.is_some_and(|p| p != state.database_port) =>
        {
            if state.container_id.is_some() {
                bail!("the authored project, clients or ports differ from the retained development session, which still holds records; run caseworkctl dev stop --remove to discard them and start again from the edited inputs, or copy the authored files to a new project directory to keep the records");
            }
            let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
            fs::remove_dir_all(&root).context("cannot replace the owned development session")?;
            previous = Some(state);
            None
        }
        existing => existing,
    };
    let mut state = if let Some(state) = existing {
        private::validate_tree(&root.join("credentials"))?;
        private::validate_tree(&root.join("secrets"))?;
        if control(&root, "status").is_ok_and(|status| status == "ready") {
            return Ok(state.report());
        }
        // A live owner lock is conclusive even when its control socket is not ready.
        let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
        state
    } else {
        let previous = previous.as_ref();
        let state = State {
            version: 1,
            project: project.clone(),
            owner: uuid::Uuid::new_v4().to_string(),
            status: Status::Stopped,
            casework_port: args
                .casework_port
                .or(previous.map(|s| s.casework_port))
                .unwrap_or(8092),
            mint_port: args
                .mint_port
                .or(previous.map(|s| s.mint_port))
                .unwrap_or(8093),
            database_port: args
                .database_port
                .or(previous.map(|s| s.database_port))
                .unwrap_or(55433),
            clients_file,
            source_digest: digest,
            clients: reported,
            container_id: None,
            tls_files_copied: false,
            database_ready: false,
            migrated: false,
            seeded: BTreeSet::new(),
            directory_revision: 0,
            directory_teams: 0,
            binaries: BTreeMap::new(),
            failure: None,
        };
        ports(state.casework_port, state.mint_port, state.database_port)?;
        for port in [state.casework_port, state.mint_port, state.database_port] {
            probe(port)?;
        }
        initialize(&root, &state, &clients)?;
        read_state(&root)?
    };
    let casework = executable("casework", args.casework_bin.as_deref())?;
    let mint = executable("mint", args.mint_bin.as_deref())?;
    let docker = executable("docker", args.docker_bin.as_deref())?;
    // Identify the prerequisites before the session stops a container or
    // launches the supervisor: a casework or mint from another release has to
    // be named here, while the terminal that asked for the start is reading.
    state.binaries = BTreeMap::from([
        ("casework".into(), binary(&root, &casework)?),
        ("mint".into(), binary(&root, &mint)?),
        ("docker".into(), binary(&root, &docker)?),
    ]);
    matching_versions(&state.binaries)?;
    for port in [state.casework_port, state.mint_port] {
        probe(port)?;
    }
    // Verify the container before accepting a retained database port.
    if let Some(container) = inspect(&docker, &state)? {
        if container["State"]["Running"] == true {
            docker_command(
                &docker,
                &state,
                "stop-database",
                &[
                    "stop",
                    "--time",
                    "30",
                    container["Id"]
                        .as_str()
                        .context("verified container ID missing")?,
                ],
                None,
            )?;
        }
    }
    probe(state.database_port)?;
    remove_socket(&root)?;
    state.status = Status::Starting;
    state.failure = None;
    state.save()?;
    let interruption = StartInterruption::install()?;
    let log = supervisor_log(&root)?;
    let mut supervisor = Command::new(std::env::current_exe()?)
        .arg("__dev-supervisor")
        .arg("--dev-root")
        .arg(&root)
        .arg("--casework-bin")
        .arg(casework)
        .arg("--mint-bin")
        .arg(mint)
        .arg("--docker-bin")
        .arg(docker)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
        .context("cannot launch native local supervisor")?;
    wait_for_start(&root, &mut supervisor, &interruption.requested)
}

fn wait_for_start(root: &Path, supervisor: &mut Child, interrupted: &AtomicBool) -> Result<Value> {
    loop {
        if interrupted.load(Ordering::Relaxed) {
            return interrupted_start(root, supervisor);
        }
        let state = read_state(root)?;
        if matches!(state.status, Status::Ready)
            && control(root, "status").is_ok_and(|status| status == "ready")
        {
            return Ok(state.report());
        }
        let supervisor_exited = supervisor.try_wait()?.is_some();
        if supervisor_exited || matches!(state.status, Status::Failed) {
            // A failed state is durable before the supervisor finishes its
            // cleanup and releases its owner lock. Keep this foreground start
            // alive for the same bounded grace used by retry and stop.
            let _supervisor_lock = completed_supervisor_lock(root, &state.status)?;
            if !supervisor_exited {
                reap_failed_supervisor(supervisor)?;
            }
            // Read once more: a supervisor that exited between this poll's
            // read and its own last save has the recorded cause on disk.
            let mut failed = read_state(root)?;
            let cause = failed.failure.clone();
            failed.status = Status::Failed;
            failed.save()?;
            return Err(start_failure(cause.as_deref(), root));
        }
        // Each prerequisite command and readiness probe owns its documented
        // deadline. Do not put a shorter aggregate deadline over a valid slow
        // first start whose bounded phases run sequentially.
        thread::sleep(Duration::from_millis(100));
    }
}

fn reap_failed_supervisor(supervisor: &mut Child) -> Result<()> {
    let deadline = Instant::now() + SUPERVISOR_RELEASE_GRACE;
    loop {
        if supervisor.try_wait()?.is_some() {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            supervisor.kill()?;
            supervisor.wait()?;
            bail!("failed local supervisor did not exit after releasing its owner lock");
        }
        thread::sleep(Duration::from_millis(20).min(remaining));
    }
}

/// Stage the whole session beside its final path and rename it into place, so
/// an interrupted first start never leaves a half-generated session behind.
fn initialize(root: &Path, original: &State, clients: &Clients) -> Result<()> {
    let stage = root
        .parent()
        .context("dev parent missing")?
        .join(format!(".dev-{}", original.owner));
    private::directory(&stage)?;
    let result = (|| {
        private::create(&stage.join(".gitignore"), b"*\n")?;
        private::create(&stage.join("clients.json"), &serde_json::to_vec(clients)?)?;
        let mut staged = original.clone();
        staged.project = original.project.clone();
        config::prepare(&stage, original, clients)?;
        private::create(
            &stage.join("state.json"),
            &serde_json::to_vec_pretty(&staged)?,
        )?;
        fs::rename(&stage, root)?;
        Ok(())
    })();
    if result.is_err() && stage.exists() {
        fs::remove_dir_all(&stage).context("cannot clean owned incomplete initialization")?;
    }
    result
}

fn stop(project_path: &Path, remove: bool, docker_bin: Option<&Path>) -> Result<Value> {
    let project = project(project_path)?;
    let parent = project.join(".casework");
    if !parent.exists() {
        bail!(MISSING_SESSION);
    }
    private::check(&parent, true)?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let root = parent.join("dev");
    if !root.exists() {
        bail!(MISSING_SESSION);
    }
    let mut state = read_state(&root)?;
    if !matches!(state.status, Status::Stopped)
        && control(&root, "stop").is_ok_and(|status| status == "stopped")
    {
        state = read_state(&root)?;
        if !remove {
            return Ok(state.report());
        }
    }
    // No PID-based recovery: unrelated reused PIDs must never be signalled.
    let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
    if service_ports_must_be_free(&state.status) {
        for port in [state.casework_port, state.mint_port] {
            probe(port)?;
        }
    }
    let docker = executable("docker", docker_bin)?;
    // Remove mode tolerates a container already taken by hand: reclaim verifies
    // ownership of whatever is still there and forgets the rest, so skip the
    // inspection (and the stop it guards) when nothing is listed under this name.
    let container = if remove && !listed(&docker, &state)? {
        None
    } else {
        inspect(&docker, &state)?
    };
    if let Some(container) = container {
        if container["State"]["Running"] == true {
            docker_command(
                &docker,
                &state,
                "stop-database",
                &[
                    "stop",
                    "--time",
                    "30",
                    container["Id"]
                        .as_str()
                        .context("verified container ID missing")?,
                ],
                None,
            )?;
        }
    }
    remove_socket(&root)?;
    state.status = Status::Stopped;
    state.save()?;
    if remove {
        reclaim(&docker, &mut state)?;
    }
    Ok(state.report())
}

fn service_ports_must_be_free(status: &Status) -> bool {
    !matches!(status, Status::Stopped | Status::Failed)
}

/// Remove the owned container and its named data volume, then forget them in
/// the journal so the next start creates an empty database. What an earlier
/// reclamation or a manual removal already took is tolerated; ownership is
/// still verified for anything that is still there.
fn reclaim(docker: &Path, state: &mut State) -> Result<()> {
    if listed(docker, state)? {
        let container = inspect(docker, state)?.context("owned container listing changed")?;
        let id = container["Id"]
            .as_str()
            .context("verified container ID missing")?
            .to_owned();
        docker_command(
            docker,
            state,
            "remove-database",
            &["rm", "--volumes", &id],
            None,
        )?;
    }
    docker_command(
        docker,
        state,
        "remove-database-volume",
        &["volume", "rm", "--force", &state.volume_name()],
        None,
    )?;
    reclaimed(state);
    state.save()
}

/// Forget the reclaimed database while keeping the ownership identifier,
/// ports, clients and credentials the next start reuses.
fn reclaimed(state: &mut State) {
    state.container_id = None;
    state.tls_files_copied = false;
    state.database_ready = false;
    state.migrated = false;
    state.seeded.clear();
    state.directory_revision = 0;
    state.directory_teams = 0;
    state.status = Status::Stopped;
}

/// The bounded tail of the retained runtime journal. The journal survives
/// restarts, so a reader can inspect a start that has already stopped.
fn events(project_path: &Path) -> Result<Value> {
    let project = project(project_path)?;
    let root = project.join(".casework/dev");
    if !root.exists() {
        bail!(MISSING_SESSION);
    }
    private::check(&root, true)?;
    let journal = root.join("logs/casework.log");
    let (bytes, byte_truncated) = match File::open(&journal) {
        Ok(mut file) => {
            private::check_metadata(&file.metadata()?, false)?;
            let length = file.metadata()?.len();
            let start = length.saturating_sub(MAX_JOURNAL_BYTES);
            file.seek_relative(i64::try_from(start).context("sizing the retained journal tail")?)?;
            let mut bytes = Vec::new();
            file.take(MAX_JOURNAL_BYTES).read_to_end(&mut bytes)?;
            (bytes, start > 0)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (Vec::new(), false),
        Err(error) => return Err(error).context("opening the retained local journal"),
    };
    let text = String::from_utf8_lossy(&bytes);
    let lines = text.lines().collect::<Vec<_>>();
    let line_truncated = lines.len() > MAX_JOURNAL_LINES;
    let first_line = if line_truncated {
        lines.len() - MAX_JOURNAL_LINES
    } else {
        0
    };
    let events = lines.into_iter().skip(first_line).collect::<Vec<_>>();
    Ok(
        json!({"ok":true,"command":"dev events","project":project,"journal":journal,"events":events,
            "truncated":byte_truncated || line_truncated}),
    )
}

fn completed_supervisor_lock(root: &Path, status: &Status) -> Result<private::Lock> {
    let deadline = Instant::now()
        + if matches!(status, Status::Stopped | Status::Stopping | Status::Failed) {
            SUPERVISOR_RELEASE_GRACE
        } else {
            Duration::ZERO
        };
    loop {
        match private::lock(&root.join("supervisor.lock")) {
            Ok(lock) => return Ok(lock),
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(error),
        }
    }
}

fn control_directory(root: &Path) -> Result<PathBuf> {
    let state = read_state(root)?;
    Ok(fs::canonicalize("/tmp")?.join(format!("casework-dev-{}", state.owner)))
}

fn remove_socket(root: &Path) -> Result<()> {
    let directory = control_directory(root)?;
    if !directory.exists() {
        return Ok(());
    }
    private::check(&directory, true)?;
    let path = directory.join("control.sock");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            bail!("unowned control path refused");
        }
        fs::remove_file(path)?;
    }
    fs::remove_dir(directory).context(
        "private control directory contains unexpected files; preserve it for inspection",
    )?;
    Ok(())
}

fn control(root: &Path, message: &str) -> Result<String> {
    let directory = control_directory(root)?;
    private::check(&directory, true)?;
    let path = directory.join("control.sock");
    let meta = fs::symlink_metadata(&path)?;
    use std::os::unix::fs::FileTypeExt;
    if !meta.file_type().is_socket()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        bail!("unowned control path refused");
    }
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(control_response_deadline(message)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("{message}\n").as_bytes())?;
    let mut bytes = Vec::new();
    stream.take(64).read_to_end(&mut bytes)?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn control_response_deadline(message: &str) -> Duration {
    if message == "stop" {
        STOP_RESPONSE_DEADLINE
    } else {
        Duration::from_secs(2)
    }
}

pub(crate) fn run_supervisor(args: SupervisorArgs) -> Result<()> {
    run_supervisor_inner(args).map_err(|error| anyhow::anyhow!(bounded_supervisor_error(&error)))
}

fn run_supervisor_inner(args: SupervisorArgs) -> Result<()> {
    let terminate = Arc::new(AtomicBool::new(false));
    for signal in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(signal, Arc::clone(&terminate))?;
    }
    // Install cleanup signals before detaching. A terminal signal delivered in
    // the small interval between process creation and `setsid` then requests
    // owned cleanup instead of terminating the supervisor by default.
    rustix::process::setsid().context("cannot detach local supervisor")?;
    let root = fs::canonicalize(&args.dev_root)?;
    let _lock = private::lock(&root.join("supervisor.lock"))?;
    let mut state = read_state(&root)?;
    if !matches!(state.status, Status::Starting) {
        bail!("supervisor requires a pending owned start");
    }
    let clients: Clients =
        serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES)?)?;
    let mut children = Children::default();
    let result = (|| {
        ensure_active(&terminate)?;
        database(&args.docker_bin, &mut state)?;
        ensure_active(&terminate)?;
        children.mint = Some(service(
            &args.mint_bin,
            &["serve", "--config"],
            &root.join("mint/mint.yaml"),
            &[],
            &root,
            "mint",
        )?);
        ready(
            &format!("{}/ready", state.mint_origin()),
            &mut children.mint.as_mut().context("Mint child missing")?.child,
            &terminate,
        )?;
        ensure_active(&terminate)?;
        // Migrations are idempotent and guarded by an advisory lock. Run them
        // on every start so a retained database is upgraded with the binaries
        // that now own it; this is the only step using the migration credential.
        command(
            Command::new(&args.casework_bin)
                .arg("--config")
                .arg(root.join("operator.yaml"))
                .arg("migrate"),
            &root,
            "migrate",
            None,
        )?;
        grants(&args.docker_bin, &state)?;
        state.migrated = true;
        state.save()?;
        ensure_active(&terminate)?;
        children.casework = Some(service(
            &args.casework_bin,
            &["--config"],
            &root.join("operator.yaml"),
            &["serve"],
            &root,
            "casework",
        )?);
        ready(
            &format!("{}/ready", state.casework_origin()),
            &mut children
                .casework
                .as_mut()
                .context("Casework child missing")?
                .child,
            &terminate,
        )?;
        // A client token lives 300 seconds, which the child and readiness
        // deadlines of a slow first start can exhaust before the seed runs.
        // Mint the seeding tokens once Casework is ready, not before it.
        tokens(&args.mint_bin, &state, &clients)?;
        seed(&mut state, &clients)?;
        let control_root = control_directory(&root)?;
        private::directory(&control_root)?;
        let listener = UnixListener::bind(control_root.join("control.sock"))?;
        fs::set_permissions(
            control_root.join("control.sock"),
            fs::Permissions::from_mode(0o600),
        )?;
        listener.set_nonblocking(true)?;
        state.status = Status::Ready;
        state.save()?;
        let mut stop_stream = None;
        loop {
            if terminate.load(Ordering::Relaxed) {
                break;
            }
            if children.exited()? {
                bail!("a supervised local service exited; inspect private logs");
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let bytes = read_control_command(&mut stream)?;
                    if bytes == b"stop\n" {
                        stop_stream = Some(stream);
                        break;
                    }
                    if bytes == b"status\n" {
                        stream.write_all(b"ready\n")?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(error) => return Err(error.into()),
            }
        }
        state.status = Status::Stopping;
        state.save()?;
        Ok(stop_stream)
    })();
    let child_cleanup = children.stop();
    let database_cleanup = stop_database(&args.docker_bin, &state);
    let socket_cleanup = remove_socket(&root);
    if result.is_err()
        || child_cleanup.is_err()
        || database_cleanup.is_err()
        || socket_cleanup.is_err()
    {
        state.status = Status::Failed;
        // Both supervisor streams go to a private log, so record the cause in
        // the state document the waiting terminal reads.
        state.failure = [
            result.as_ref().err(),
            child_cleanup.as_ref().err(),
            database_cleanup.as_ref().err(),
            socket_cleanup.as_ref().err(),
        ]
        .into_iter()
        .flatten()
        .next()
        .map(|error| format!("{error:#}").chars().take(MAX_REFUSAL).collect());
        state.save()?;
        result?;
        child_cleanup?;
        database_cleanup?;
        socket_cleanup?;
        unreachable!("a failed cleanup returned its error");
    }
    state.status = Status::Stopped;
    state.save()?;
    if let Some(mut stream) = result? {
        stream.write_all(b"stopped\n")?;
    }
    Ok(())
}

fn bounded_supervisor_error(error: &anyhow::Error) -> String {
    format!("{error:#}").chars().take(MAX_REFUSAL).collect()
}

/// Read one client control command from `stream`, stopping at the first
/// newline, at end of stream, or after 16 bytes, whichever comes first.
fn read_control_command(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < 16 {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(bytes)
}

#[derive(Default)]
struct Children {
    casework: Option<Service>,
    mint: Option<Service>,
}
impl Children {
    fn exited(&mut self) -> Result<bool> {
        for service in [&mut self.casework, &mut self.mint].into_iter().flatten() {
            if service.child.try_wait()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn stop(&mut self) -> Result<()> {
        let mut error = None;
        for owned in [&mut self.casework, &mut self.mint] {
            if let Some(mut service) = owned.take() {
                if let Err(cause) = service.stop() {
                    error = Some(cause);
                }
            }
        }
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct Service {
    child: Child,
    pumps: Vec<thread::JoinHandle<Result<()>>>,
}

/// Own a spawned service from the first instruction after `Command::spawn`.
/// Any partial pipe-reader setup kills and reaps the child before joining the
/// readers that did start, so no failure can strand a service outside
/// `Children`.
struct StartingService {
    child: Option<Child>,
    pumps: Vec<thread::JoinHandle<Result<()>>>,
}

impl StartingService {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            pumps: Vec::new(),
        }
    }

    fn finish(mut self) -> Result<Service> {
        Ok(Service {
            child: self.child.take().context("service child missing")?,
            pumps: std::mem::take(&mut self.pumps),
        })
    }
}

impl Drop for StartingService {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Setup failed, so graceful service shutdown is neither available
            // nor useful. A forceful stop makes every owned pipe reach EOF
            // before its reader is joined.
            let _ = child.kill();
            let _ = child.wait();
        }
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
    }
}

impl Service {
    fn stop(&mut self) -> Result<()> {
        let child_result = stop_child(&mut self.child);
        let mut pump_error = None;
        for pump in self.pumps.drain(..) {
            let result = pump
                .join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("service log reader failed")));
            if pump_error.is_none() {
                pump_error = result.err();
            }
        }
        child_result?;
        match pump_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
impl Drop for Children {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn signal(child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_none() {
        let pid =
            rustix::process::Pid::from_raw(child.id() as i32).context("owned child PID invalid")?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
    }
    Ok(())
}

fn terminate_and_reap(child: &mut Child) -> Result<()> {
    signal(child)?;
    child.wait()?;
    Ok(())
}

fn interrupted_start(root: &Path, supervisor: &mut Child) -> Result<Value> {
    terminate_and_reap(supervisor)?;
    let mut state = read_state(root)?;
    if matches!(state.status, Status::Starting | Status::Stopping) {
        state.status = Status::Failed;
        state.failure = Some("local start interrupted before it became ready".to_owned());
        state.save()?;
    }
    if matches!(state.status, Status::Failed) {
        return Err(start_failure(
            state.failure.as_deref().or(Some("local start interrupted")),
            root,
        ));
    }
    bail!("local start interrupted; the owned supervisor stopped and retained data is preserved")
}

fn stop_child(child: &mut Child) -> Result<()> {
    signal(child)?;
    let deadline = Instant::now() + Duration::from_secs(35);
    while child.try_wait()?.is_none() {
        if Instant::now() > deadline {
            child.kill()?;
            child.wait()?;
            bail!(
                "owned local child required forced shutdown; inspect retained audit before reuse"
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
fn ensure_active(terminate: &AtomicBool) -> Result<()> {
    if terminate.load(Ordering::Relaxed) {
        bail!("local start interrupted; owned services are stopping");
    }
    Ok(())
}

fn executable(name: &str, explicit: Option<&Path>) -> Result<PathBuf> {
    let found = explicit
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("PATH").and_then(|value| {
                std::env::split_paths(&value)
                    .map(|p| p.join(name))
                    .find(|p| p.is_file())
            })
        })
        .with_context(|| {
            format!("install {name} and put it on PATH before starting local development")
        })?;
    // Preserve the installed command name: Docker distributions may route a
    // symlink by argv[0], so canonicalizing the executable changes behavior.
    let absolute = if found.is_absolute() {
        found
    } else {
        std::env::current_dir()?.join(found)
    };
    let path = fs::canonicalize(absolute.parent().context("executable parent missing")?)?
        .join(absolute.file_name().context("executable name missing")?);
    if !fs::metadata(&path)?.is_file() {
        bail!("installed executable must be a regular file");
    }
    Ok(path)
}

/// Identify a resolved prerequisite for the state document: the fully
/// canonical path of the file that runs, and the version it reports for
/// itself. Diagnostics stay in the owner-only log directory.
fn binary(root: &Path, path: &Path) -> Result<Binary> {
    let output = output(
        Command::new(path).arg("--version"),
        root,
        &format!(
            "version-{}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ),
        None,
    )?;
    let reported = String::from_utf8_lossy(&output.stdout);
    let reported = reported.lines().next().unwrap_or_default().trim();
    let version = if !output.success || reported.is_empty() {
        UNREPORTED_VERSION.to_string()
    } else {
        reported.chars().take(MAX_VERSION).collect()
    };
    Ok(Binary {
        path: fs::canonicalize(path)?,
        version,
    })
}

/// The version a prerequisite reported for itself. Every executable of this
/// stack answers `--version` with its own name and its version, so the second
/// word is the version. A prerequisite that reported nothing, or answered in
/// another shape, offers no version to compare rather than a guessed one.
fn reported_version(binary: &Binary) -> Option<&str> {
    if binary.version == UNREPORTED_VERSION {
        return None;
    }
    binary.version.split_whitespace().nth(1)
}

/// Refuse a session whose casework or mint comes from another release. The
/// three executables share a configuration contract, a token shape and a
/// schema, so an older casework beside this caseworkctl fails deep inside a
/// supervised phase, where the cause reads as an unrelated refusal about the
/// database. Docker belongs to no release of this stack and is never compared.
fn matching_versions(binaries: &BTreeMap<String, Binary>) -> Result<()> {
    let own = registry_platform_buildinfo::DISPLAY_VERSION;
    for name in ["casework", "mint"] {
        let Some(prerequisite) = binaries.get(name) else {
            continue;
        };
        let Some(reported) = reported_version(prerequisite) else {
            continue;
        };
        if reported != own {
            bail!(
                "the installed {name} at {} reports version {reported}, and this caseworkctl reports version {own}. A local session runs casework, mint and caseworkctl together, so install all three from the same release, or put the matching build first on PATH",
                prerequisite.path.display()
            );
        }
    }
    Ok(())
}

fn log_file(root: &Path, name: &str) -> Result<File> {
    log_file_with_rotation(root, name, || {})
}

fn log_file_with_rotation(root: &Path, name: &str, before_rotation: impl FnOnce()) -> Result<File> {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

    let directory = File::from(
        rustix::fs::open(
            root.join("logs"),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot open private prerequisite log directory")?,
    );
    private::check_metadata(&directory.metadata()?, true)?;
    let mut logs = Vec::new();
    for entry in Dir::read_from(&directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Ok(text) = std::str::from_utf8(name.to_bytes()) else {
            continue;
        };
        let Some(stem) = text.strip_suffix(".log") else {
            continue;
        };
        let stem = stem.as_bytes();
        let Some(uuid_start) = stem.len().checked_sub(36) else {
            continue;
        };
        if uuid_start == 0
            || stem[uuid_start - 1] != b'-'
            || std::str::from_utf8(&stem[uuid_start..])
                .ok()
                .is_none_or(|suffix| uuid::Uuid::parse_str(suffix).is_err())
        {
            continue;
        }
        let metadata = rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if metadata.st_uid as u32 != rustix::process::geteuid().as_raw()
            || metadata.st_mode as u32 & 0o077 != 0
            || FileType::from_raw_mode(metadata.st_mode as _) != FileType::RegularFile
            || metadata.st_nlink as u64 != 1
        {
            bail!("local state must use ordinary owner-only directories and single-link files");
        }
        logs.push((
            metadata.st_mtime as i64,
            metadata.st_mtime_nsec as i64,
            name.to_owned(),
        ));
    }
    logs.sort_by(|left, right| {
        (left.0, left.1, left.2.as_bytes()).cmp(&(right.0, right.1, right.2.as_bytes()))
    });
    let remove = logs
        .len()
        .saturating_sub(MAX_PREREQUISITE_LOGS.saturating_sub(1));
    before_rotation();
    for (_, _, name) in logs.into_iter().take(remove) {
        rustix::fs::unlinkat(&directory, &name, AtFlags::empty())
            .context("cannot rotate retained prerequisite diagnostics")?;
    }
    let filename = format!("{name}-{}.log", uuid::Uuid::new_v4());
    Ok(File::from(
        rustix::fs::openat(
            &directory,
            filename,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .context("cannot create private prerequisite log")?,
    ))
}

fn pump(mut input: impl Read, mut output: impl Write) -> Result<()> {
    let mut buffer = [0u8; 8192];
    let mut written = 0;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let kept = count.min((MAX_BYTES as usize).saturating_sub(written));
        output.write_all(&buffer[..kept])?;
        written += kept;
    }
    Ok(())
}

/// One owner-only service journal shared by both child streams. Once full it
/// compacts to its newest half before accepting more bytes, so a noisy service
/// retains its latest diagnostics without growing the file across restarts.
#[derive(Clone)]
struct RetainedJournal {
    file: Arc<Mutex<File>>,
}

impl RetainedJournal {
    fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            private::create(path, b"")?;
        }
        private::check(path, false)?;
        let before = fs::symlink_metadata(path)?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .context("cannot open the retained local journal")?;
        let opened = file.metadata()?;
        private::check_metadata(&opened, false)?;
        if before.ino() != opened.ino() || before.dev() != opened.dev() {
            bail!("local state changed while opening it");
        }
        compact_journal(&mut file, MAX_BYTES)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
}

fn supervisor_log(root: &Path) -> Result<File> {
    supervisor_log_with_open(root, || {})
}

fn supervisor_log_with_open(root: &Path, after_directory_open: impl FnOnce()) -> Result<File> {
    use rustix::{
        fs::{statat, AtFlags, Mode, OFlags},
        io::Errno,
    };

    let directory = File::from(
        rustix::fs::open(
            root.join("logs"),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot open private supervisor log directory")?,
    );
    private::check_metadata(&directory.metadata()?, true)?;
    after_directory_open();
    let name = "supervisor.log";
    let before = match statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => Some(metadata),
        Err(Errno::NOENT) => None,
        Err(error) => return Err(error.into()),
    };
    let descriptor = match before {
        Some(_) => rustix::fs::openat(
            &directory,
            name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ),
        None => rustix::fs::openat(
            &directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        ),
    }
    .context("cannot open retained supervisor journal")?;
    let mut file = File::from(descriptor);
    let opened = file.metadata()?;
    private::check_metadata(&opened, false)?;
    if before.is_some_and(|metadata| {
        metadata.st_ino != opened.ino() || metadata.st_dev as u64 != opened.dev()
    }) {
        bail!("local state changed while opening it");
    }
    compact_journal(
        &mut file,
        MAX_BYTES.saturating_sub(MAX_SUPERVISOR_ERROR_BYTES),
    )?;
    Ok(file)
}

impl Write for RetainedJournal {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("retained journal lock failed"))?;
        let maximum = MAX_BYTES as usize;
        let kept = if bytes.len() > maximum {
            &bytes[bytes.len() - maximum..]
        } else {
            bytes
        };
        let length = file.metadata()?.len() as usize;
        if length.saturating_add(kept.len()) > maximum {
            compact_journal(&mut file, (maximum - kept.len()).min(maximum / 2) as u64)?;
        }
        file.seek(SeekFrom::End(0))?;
        file.write_all(kept)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::other("retained journal lock failed"))?
            .flush()
    }
}

fn compact_journal(file: &mut File, keep: u64) -> std::io::Result<()> {
    let length = file.metadata()?.len();
    if length > keep {
        file.seek(SeekFrom::Start(length - keep))?;
        let mut tail = Vec::with_capacity(keep as usize);
        file.take(keep).read_to_end(&mut tail)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&tail)?;
        file.set_len(tail.len() as u64)?;
    }
    file.seek(SeekFrom::End(0))?;
    Ok(())
}

fn pump_retained(mut input: impl Read, mut journal: RetainedJournal) -> Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        journal.write_all(&buffer[..count])?;
    }
    Ok(())
}

/// Start one supervised service, appending both its streams to the retained
/// journal `dev events` tails.
fn service(
    binary: &Path,
    leading: &[&str],
    config: &Path,
    trailing: &[&str],
    root: &Path,
    name: &str,
) -> Result<Service> {
    // Validate and compact the retained destination before a child exists. A
    // refused journal must not leave an otherwise untracked service running.
    let journal = RetainedJournal::open(&root.join("logs").join(format!("{name}.log")))?;
    let child = Command::new(binary)
        .args(leading)
        .arg(config)
        .args(trailing)
        .env("SSL_CERT_FILE", root.join("tls/ca.pem"))
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start local service")?;
    service_with_pump_spawner(child, journal, |stream, task| {
        thread::Builder::new()
            .name(format!("casework-dev-{name}-{stream}"))
            .spawn(task)
    })
}

type PumpTask = Box<dyn FnOnce() -> Result<()> + Send + 'static>;

fn service_with_pump_spawner(
    child: Child,
    journal: RetainedJournal,
    mut spawn: impl FnMut(&str, PumpTask) -> std::io::Result<thread::JoinHandle<Result<()>>>,
) -> Result<Service> {
    let mut starting = StartingService::new(child);
    let out = starting
        .child
        .as_mut()
        .context("service child missing")?
        .stdout
        .take()
        .context("service output pipe missing")?;
    let err = starting
        .child
        .as_mut()
        .context("service child missing")?
        .stderr
        .take()
        .context("service diagnostic pipe missing")?;
    let second = journal.clone();
    starting.pumps.push(
        spawn("stdout", Box::new(move || pump_retained(out, journal)))
            .context("cannot start service output reader")?,
    );
    starting.pumps.push(
        spawn("stderr", Box::new(move || pump_retained(err, second)))
            .context("cannot start service diagnostic reader")?,
    );
    starting.finish()
}

/// Bytes written to a child's standard input, naming the secret substring the
/// child must never be able to echo back into a log, a report or an error.
struct Input<'a> {
    bytes: &'a [u8],
    secret: Option<&'a [u8]>,
}

struct NativeOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Replace every run of bytes that also occurs in `secret` with a fixed marker,
/// keeping the surrounding diagnostics readable.
fn redact(bytes: &[u8], secret: &[u8]) -> Vec<u8> {
    let run = SECRET_RUN.min(secret.len());
    if run == 0 || bytes.len() < run {
        return bytes.to_vec();
    }
    let windows: BTreeSet<&[u8]> = secret.windows(run).collect();
    let mut hidden = vec![false; bytes.len()];
    for (index, window) in bytes.windows(run).enumerate() {
        if windows.contains(window) {
            hidden[index..index + run].fill(true);
        }
    }
    let mut redacted = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if hidden[index] {
            redacted.extend_from_slice(b"[redacted]");
            while index < bytes.len() && hidden[index] {
                index += 1;
            }
        } else {
            redacted.push(bytes[index]);
            index += 1;
        }
    }
    redacted
}

/// Run one owned prerequisite, returning its bounded, redacted streams.
/// Diagnostics also stay in the owner-only log directory.
fn output(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
) -> Result<NativeOutput> {
    output_with_deadline(command, root, name, input, None)
}

/// Run a prerequisite that belongs to an already-active aggregate deadline.
/// Unlike ordinary prerequisite commands, expiry kills this probe immediately
/// so its cleanup cannot extend the aggregate readiness budget by 35 seconds.
fn output_before(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
    deadline: Instant,
) -> Result<NativeOutput> {
    output_with_deadline(command, root, name, input, Some(deadline))
}

fn output_with_deadline(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
    aggregate_deadline: Option<Instant>,
) -> Result<NativeOutput> {
    let log = log_file(root, name)?;
    let secret = input
        .as_ref()
        .and_then(|input| input.secret)
        .map(|secret| Zeroizing::new(secret.to_vec()));
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot launch native development prerequisite")?;
    let stdout = child.stdout.take().context("command output pipe missing")?;
    let stderr = child
        .stderr
        .take()
        .context("command diagnostic pipe missing")?;
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        pump(stdout, &mut bytes).map(|()| bytes)
    });
    // Capture every diagnostic stream so a failed native command can surface
    // its bounded machine-readable refusal. Redact before either returning or
    // persisting bytes that could carry a secret.
    let redacting = secret.clone();
    let err = thread::spawn(move || {
        let mut captured = Zeroizing::new(Vec::new());
        pump(stderr, &mut *captured)?;
        let persisted = match redacting {
            Some(secret) => redact(&captured, &secret),
            None => std::mem::take(&mut *captured),
        };
        let mut log = log;
        log.write_all(&persisted)?;
        Ok::<_, anyhow::Error>(persisted)
    });
    if let Some(input) = &input {
        child
            .stdin
            .take()
            .context("command input missing")?
            .write_all(input.bytes)?;
    }
    // Preserve the full per-command allowance for ordinary prerequisites.
    // An aggregate readiness deadline instead includes all probe setup time.
    let deadline = aggregate_deadline.unwrap_or_else(|| Instant::now() + CHILD_DEADLINE);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if aggregate_deadline.is_some() {
                child.kill()?;
                child.wait()?;
            } else {
                stop_child(&mut child)?;
            }
            break None;
        }
        thread::sleep(Duration::from_millis(50).min(remaining));
    };
    let mut bytes = out
        .join()
        .map_err(|_| anyhow::anyhow!("command output reader failed"))??;
    let stderr = err
        .join()
        .map_err(|_| anyhow::anyhow!("command diagnostic reader failed"))??;
    if let Some(secret) = &secret {
        let echoed = Zeroizing::new(std::mem::take(&mut bytes));
        bytes = redact(&echoed, secret);
    }
    let Some(status) = status else {
        bail!("native local prerequisite timed out; inspect private logs");
    };
    if !status.success() {
        // Native caseworkctl and casework report errors as JSON. Preserve them
        // privately as well; credentials never enter the report.
        let mut log = log_file(root, &format!("{name}-report"))?;
        log.write_all(&bytes)?;
    }
    Ok(NativeOutput {
        success: status.success(),
        stdout: bytes,
        stderr,
    })
}

/// Name the first failing check from the machine-readable report a native
/// command writes. Output in any other shape names nothing, so the caller
/// keeps the logs pointer.
fn refused_check(report: &[u8]) -> Option<String> {
    let report: Value = serde_json::from_slice(report).ok()?;
    let first = report["diagnostics"].as_array()?.first()?;
    let named = format!(
        "{}: {}",
        first["code"].as_str()?,
        first["message"].as_str()?
    );
    Some(named.chars().take(MAX_REFUSAL).collect())
}

fn command(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
) -> Result<Vec<u8>> {
    let output = output(command, root, name, input)?;
    checked_output(output, root, name)
}

fn command_before(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let output = output_before(command, root, name, input, deadline)?;
    checked_output(output, root, name)
}

fn checked_output(output: NativeOutput, root: &Path, name: &str) -> Result<Vec<u8>> {
    if !output.success {
        let logs = root.join("logs").display().to_string();
        let refusal = refused_check(&output.stderr)
            .or_else(|| refused_check(&output.stdout))
            .or_else(|| native_migration_refusal(name, &output.stderr));
        match refusal {
            Some(check) => bail!(
                "native {name} refused: {check}. The full report and owner-only diagnostics are in {logs}"
            ),
            None => bail!("native {name} failed; inspect owner-only diagnostics in {logs}"),
        }
    }
    Ok(output.stdout)
}

fn native_migration_refusal(name: &str, diagnostics: &[u8]) -> Option<String> {
    if name != "migrate" {
        return None;
    }
    let diagnostics = String::from_utf8_lossy(diagnostics);
    let line = diagnostics
        .lines()
        .find(|line| !line.trim().is_empty())?
        .trim()
        .strip_prefix("casework: ")?
        .trim();
    if line.is_empty() {
        return None;
    }
    Some(line.chars().take(MAX_REFUSAL).collect())
}

/// The refusal a failed start reports, naming the supervisor's own cause when
/// it recorded one.
fn start_failure(cause: Option<&str>, root: &Path) -> anyhow::Error {
    let logs = root.join("logs");
    let logs = logs.display().to_string();
    match cause {
        // A cause carried out of a named check already points at the retained
        // log directory, and reading the same path twice teaches nothing.
        Some(cause) if cause.contains(&logs) => anyhow::anyhow!(
            "local start failed: {cause}. Retry the same command after correcting the cause; retained data is preserved"
        ),
        Some(cause) => anyhow::anyhow!(
            "local start failed: {cause}. Private diagnostics are in {logs}. Retry the same command after correcting the cause; retained data is preserved"
        ),
        None => anyhow::anyhow!(
            "local start failed; private diagnostics are in {logs}. Retry the same command after correcting the cause; retained data is preserved"
        ),
    }
}

fn docker_command(
    docker: &Path,
    state: &State,
    name: &str,
    args: &[&str],
    input: Option<Input<'_>>,
) -> Result<Vec<u8>> {
    command(Command::new(docker).args(args), &state.root(), name, input)
}

fn docker_command_before(
    docker: &Path,
    state: &State,
    name: &str,
    args: &[&str],
    deadline: Instant,
) -> Result<Vec<u8>> {
    command_before(
        Command::new(docker).args(args),
        &state.root(),
        name,
        None,
        deadline,
    )
}

/// Listing by exact generated name distinguishes absence from a daemon failure
/// without treating arbitrary stderr as a trustworthy classifier.
fn listed(docker: &Path, state: &State) -> Result<bool> {
    let listing = docker_command(
        docker,
        state,
        "inspect-list",
        &[
            "ps",
            "--all",
            "--filter",
            &format!("name=^/{}$", state.container_name()),
            "--format",
            "{{.ID}}",
        ],
        None,
    )?;
    Ok(!listing.iter().all(u8::is_ascii_whitespace))
}

fn inspect(docker: &Path, state: &State) -> Result<Option<Value>> {
    if !listed(docker, state)? {
        if state.container_id.is_some() {
            bail!("retained database container is missing; restore its owned data or use a new project directory; no empty replacement was created");
        }
        return Ok(None);
    }
    let output = docker_command(
        docker,
        state,
        "inspect-database",
        &["inspect", &state.container_name()],
        None,
    )?;
    let values: Vec<Value> =
        serde_json::from_slice(&output).context("Docker returned invalid container inventory")?;
    let container = values
        .into_iter()
        .next()
        .context("Docker returned no exact container")?;
    if container["Name"] != format!("/{}", state.container_name())
        || container["Config"]["Labels"][LABEL] != state.owner
        || container["Config"]["Image"] != IMAGE
        || state
            .container_id
            .as_ref()
            .is_some_and(|id| container["Id"] != *id)
    {
        bail!("container ownership differs from retained local state; no resource was changed");
    }
    Ok(Some(container))
}

fn database(docker: &Path, state: &mut State) -> Result<()> {
    let root = state.root();
    if inspect(docker, state)?.is_none() {
        let created = docker_command(
            docker,
            state,
            "create-database",
            &[
                "create",
                "--name",
                &state.container_name(),
                "--label",
                &format!("{LABEL}={}", state.owner),
                "--publish",
                &format!("127.0.0.1:{}:5432", state.database_port),
                "--volume",
                &format!("{}:/var/lib/postgresql/data", state.volume_name()),
                "--env-file",
                root.join("database/postgres.env")
                    .to_str()
                    .context("dev path must be UTF-8")?,
                IMAGE,
            ],
            None,
        )?;
        let id = std::str::from_utf8(&created)?.trim();
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("Docker returned an invalid newly created container ID");
        }
        state.container_id = Some(id.to_owned());
        state.save()?;
    }
    let container = inspect(docker, state)?.context("owned database was not created")?;
    state.container_id = Some(
        container["Id"]
            .as_str()
            .context("Docker container ID missing")?
            .to_owned(),
    );
    state.save()?;
    if !state.tls_files_copied {
        for (source, target) in [
            ("database/pg_hba.conf", "pg_hba.conf"),
            ("tls/server.pem", "server.pem"),
            ("tls/server.key", "server.key"),
        ] {
            docker_command(
                docker,
                state,
                "copy-database-tls",
                &[
                    "cp",
                    root.join(source)
                        .to_str()
                        .context("dev path must be UTF-8")?,
                    &format!("{}:/tmp/casework-dev-{target}", state.container_id()?),
                ],
                None,
            )?;
        }
        state.tls_files_copied = true;
        state.save()?;
    }
    if container["State"]["Running"] != true {
        docker_command(
            docker,
            state,
            "start-database",
            &["start", state.container_id()?],
            None,
        )?;
    }
    let deadline = Instant::now() + READY_DEADLINE;
    loop {
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            bail!("owned PostgreSQL did not become ready; inspect private logs");
        }
        let result = docker_command_before(
            docker,
            state,
            "database-readiness",
            &[
                "exec",
                state.container_id()?,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ],
            deadline,
        );
        if result.is_ok() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("owned PostgreSQL did not become ready; inspect private logs");
        }
        thread::sleep(Duration::from_millis(200).min(remaining));
    }
    if !state.database_ready {
        docker_command(
            docker,
            state,
            "tls-ownership",
            &[
                "exec",
                "--user",
                "root",
                state.container_id()?,
                "chown",
                "postgres:postgres",
                "/tmp/casework-dev-server.key",
                "/tmp/casework-dev-server.pem",
                "/tmp/casework-dev-pg_hba.conf",
            ],
            None,
        )?;
        docker_command(
            docker,
            state,
            "tls-permissions",
            &[
                "exec",
                "--user",
                "root",
                state.container_id()?,
                "chmod",
                "600",
                "/tmp/casework-dev-server.key",
            ],
            None,
        )?;
        sql(docker,state,"postgres",b"ALTER SYSTEM SET hba_file = '/tmp/casework-dev-pg_hba.conf';\nALTER SYSTEM SET ssl = 'on';\nALTER SYSTEM SET ssl_cert_file = '/tmp/casework-dev-server.pem';\nALTER SYSTEM SET ssl_key_file = '/tmp/casework-dev-server.key';\nSELECT pg_reload_conf();\n",None)?;
        for (role, filename) in [
            (MIGRATION_ROLE, "migration-password"),
            (RUNTIME_ROLE, "runtime-password"),
        ] {
            let password = Zeroizing::new(String::from_utf8(private::read(
                &root.join("database").join(filename),
                64,
            )?)?);
            let statement=Zeroizing::new(format!("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{}'; END IF; END $$;",password.as_str()));
            sql(
                docker,
                state,
                "postgres",
                statement.as_bytes(),
                Some(password.as_bytes()),
            )?;
        }
        let exists = sql(
            docker,
            state,
            "postgres",
            format!("SELECT count(*) FROM pg_database WHERE datname='{DATABASE_NAME}';").as_bytes(),
            None,
        )?;
        if String::from_utf8_lossy(&exists).trim() == "0" {
            sql(
                docker,
                state,
                "postgres",
                format!("CREATE DATABASE {DATABASE_NAME};").as_bytes(),
                None,
            )?;
        }
        // Casework's migrations create ordinary tables in `public` and declare
        // no extension and no other schema, so the migration role owns that one
        // schema and the runtime role only reads and writes through it.
        sql(docker,state,DATABASE_NAME,format!("REVOKE ALL ON DATABASE {DATABASE_NAME} FROM PUBLIC; GRANT CONNECT ON DATABASE {DATABASE_NAME} TO {MIGRATION_ROLE},{RUNTIME_ROLE}; ALTER SCHEMA public OWNER TO {MIGRATION_ROLE}; REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO {RUNTIME_ROLE}; ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATION_ROLE} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {RUNTIME_ROLE}; ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATION_ROLE} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {RUNTIME_ROLE};").as_bytes(),None)?;
        state.database_ready = true;
        state.save()?;
    }
    Ok(())
}

/// Grant the runtime role what the just-applied migrations created. Default
/// privileges cover every later object; this covers the ones already there
/// when an older session's database is reused.
fn grants(docker: &Path, state: &State) -> Result<()> {
    sql(docker,state,DATABASE_NAME,format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {RUNTIME_ROLE}; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {RUNTIME_ROLE};").as_bytes(),None)?;
    Ok(())
}

fn sql(
    docker: &Path,
    state: &State,
    database: &str,
    bytes: &[u8],
    secret: Option<&[u8]>,
) -> Result<Vec<u8>> {
    docker_command(
        docker,
        state,
        "database-bootstrap",
        &[
            "exec",
            "-i",
            state.container_id()?,
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
        Some(Input { bytes, secret }),
    )
}

fn stop_database(docker: &Path, state: &State) -> Result<()> {
    if let Some(container) = inspect(docker, state)? {
        if container["State"]["Running"] == true {
            docker_command(
                docker,
                state,
                "stop-database",
                &[
                    "stop",
                    "--time",
                    "30",
                    container["Id"]
                        .as_str()
                        .context("verified container ID missing")?,
                ],
                None,
            )?;
        }
    }
    Ok(())
}

fn tokens(mint: &Path, state: &State, clients: &Clients) -> Result<()> {
    issue_tokens(state, clients, |id| token(mint, state, id))
}

fn issue_tokens(
    state: &State,
    clients: &Clients,
    mut issue: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let administrator = state.administrator()?;
    if !clients
        .clients
        .iter()
        .any(|client| client.id == administrator.id)
    {
        bail!("retained Administrator is missing from the local clients file");
    }
    for client in &clients.clients {
        if client.id != administrator.id {
            issue(&client.id)?;
        }
    }
    // This token authorizes the immediately following directory seed. Issue
    // it after every other client so a maximum-sized file cannot age it first.
    issue(&administrator.id)
}

fn token(mint: &Path, state: &State, id: &str) -> Result<()> {
    let root = state.root();
    let bytes = Zeroizing::new(command(
        Command::new(mint)
            .arg("token")
            .arg("--url")
            .arg(format!("{}/token", state.mint_origin()))
            .arg("--client-id")
            .arg(id)
            .arg("--key")
            .arg(root.join("credentials").join(id).join("assertion-key.jwk")),
        &root,
        "token",
        None,
    )?);
    let value = std::str::from_utf8(&bytes)
        .context("Mint token output must be ASCII")?
        .trim();
    if value.len() > 65536
        || value.split('.').count() != 3
        || value.chars().any(char::is_whitespace)
    {
        bail!("Mint returned an invalid compact token");
    }
    private::replace(
        &root.join("secrets").join(format!("{id}-token")),
        value.as_bytes(),
    )
}

fn http(
    method: &str,
    url: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Result<(u16, Value)> {
    http_with_timeout(method, url, token, headers, body, HTTP_TIMEOUT)
}

fn http_with_timeout(
    method: &str,
    url: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<Value>,
    timeout: Duration,
) -> Result<(u16, Value)> {
    if timeout.is_zero() {
        bail!("local HTTP prerequisite is unavailable");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()?;
        let mut request = match method {
            "POST" => client.post(url),
            _ => client.get(url),
        };
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("local HTTP prerequisite is unavailable"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > MAX_BYTES as usize {
                bail!("local HTTP response exceeded its bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    })
}

fn ready(url: &str, child: &mut Child, terminate: &AtomicBool) -> Result<()> {
    ready_before(url, child, terminate, Instant::now() + READY_DEADLINE)
}

fn ready_before(
    url: &str,
    child: &mut Child,
    terminate: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    ready_with_probe(child, terminate, deadline, |remaining| {
        matches!(
            http_with_timeout(
                "GET",
                url,
                None,
                &[],
                None,
                readiness_http_timeout(remaining),
            ),
            Ok((200, _))
        )
    })
}

fn readiness_http_timeout(remaining: Duration) -> Duration {
    HTTP_TIMEOUT.min(remaining)
}

fn ready_with_probe(
    child: &mut Child,
    terminate: &AtomicBool,
    deadline: Instant,
    mut probe: impl FnMut(Duration) -> bool,
) -> Result<()> {
    loop {
        ensure_active(terminate)?;
        if child.try_wait()?.is_some() {
            bail!("local service exited before readiness; inspect private logs");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("local service readiness timed out; inspect private logs");
        }
        if probe(remaining) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("local service readiness timed out; inspect private logs");
        }
        thread::sleep(Duration::from_millis(200).min(remaining));
    }
}

/// Seed the directory so `caseworkctl doctor` reports ready and a person can
/// open the inbox. One authored team per declared queue, created as the
/// Administrator the clients file binds. A team that already serves its queue
/// is left exactly as it is: retained records survive every restart.
fn seed(state: &mut State, clients: &Clients) -> Result<()> {
    let administrator = state.administrator()?.clone();
    let token = Zeroizing::new(String::from_utf8(private::read(
        &state
            .root()
            .join("secrets")
            .join(format!("{}-token", administrator.id)),
        65536,
    )?)?);
    let profile = administrator.profile.clone();
    let read_directory = |token: &str| -> Result<Value> {
        let (status, body) = http(
            "GET",
            &format!("{}/v1/directory", state.casework_origin()),
            Some(token),
            &[("registry-casework-profile", profile.as_str())],
            None,
        )?;
        if status != 200 {
            bail!("the local Casework directory could not be read as an Administrator (HTTP {status}); inspect private logs");
        }
        Ok(body)
    };
    let mut directory = read_directory(&token)?;
    let issuer = state.mint_origin();
    let principals: BTreeMap<&str, &str> = state
        .clients
        .iter()
        .map(|client| (client.id.as_str(), client.principal.as_str()))
        .collect();
    for team in &clients.directory {
        let serving = directory["teams"].as_array().is_some_and(|teams| {
            teams.iter().any(|record| {
                record["id"] == team.team
                    && record["servedQueues"]
                        .as_array()
                        .is_some_and(|queues| queues.iter().any(|queue| *queue == team.queue))
            })
        });
        if serving {
            state.seeded.insert(team.team.clone());
            continue;
        }
        let revision = directory["revision"]
            .as_i64()
            .context("the local Casework directory reported no revision")?;
        let members = |ids: &[String]| -> Result<Vec<Value>> {
            ids.iter()
                .map(|id| {
                    let subject = principals
                        .get(id.as_str())
                        .with_context(|| format!("directory member {id} is not a local client"))?;
                    Ok(json!({"issuer": issuer, "subject": subject}))
                })
                .collect()
        };
        let (status, body) = http(
            "POST",
            &format!("{}/v1/directory/bootstrap", state.casework_origin()),
            Some(&token),
            &[
                ("registry-casework-profile", profile.as_str()),
                ("if-match", &format!("\"{revision}\"")),
                (
                    "idempotency-key",
                    &format!("dev-{}-{}", state.owner, team.team),
                ),
            ],
            Some(json!({"teamId":team.team,"queueId":team.queue,
                "staff":members(&team.staff)?,"supervisors":members(&team.supervisors)?})),
        )?;
        if status != 200 {
            bail!("the local Casework directory refused team {} for queue {} (HTTP {status}); inspect the clients file and private logs", team.team, team.queue);
        }
        directory = body;
        state.seeded.insert(team.team.clone());
        state.save()?;
    }
    state.directory_revision = directory["revision"].as_i64().unwrap_or_default();
    state.directory_teams = directory["teams"].as_array().map_or(0, Vec::len);
    state.save()
}
