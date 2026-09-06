// SPDX-License-Identifier: Apache-2.0
//! Native, retained, loopback-only BReg tutorial lifecycle.
//!
//! A resident supervisor owns service children. The only database it may
//! start or stop is the container whose random ownership label and immutable
//! Docker ID match its private journal. There is intentionally no reset.

mod config;
mod private;
#[cfg(test)]
mod tests;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use config::Clients;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::TcpListener,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const DATABASE_ID: &str = "breg-dev-database";
const MIGRATION_ROLE: &str = "breg_dev_migration";
const RUNTIME_ROLE: &str = "breg_dev_runtime";
const IMAGE: &str =
    "postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675";
const LABEL: &str = "org.registrystack.bregctl.dev-owner";
/// Refusal for a project that never started. Reporting a stopped session
/// would claim owned services were stopped when none were ever created.
const MISSING_SESSION: &str = "no local development session exists in this project; nothing was stopped. Check --project, or start one with bregctl dev --clients-file";
const MAX_BYTES: u64 = 4 * 1024 * 1024;

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
    Start(StartArgs),
    /// Stop only this project's supervised services, preserving its database.
    Stop(StopArgs),
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Existing authored registry project. Its package environment must be local.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Explicit local clients, profile bindings, and optional seed records.
    #[arg(long, alias = "clients")]
    clients_file: Option<PathBuf>,
    /// Registry loopback port on first start (default 8090; retained for restarts).
    #[arg(long)]
    breg_port: Option<u16>,
    /// Local Mint loopback port on first start (default 8091; retained for restarts).
    #[arg(long)]
    mint_port: Option<u16>,
    /// PostgreSQL loopback port on first start (default 55432; retained for restarts).
    #[arg(long)]
    database_port: Option<u16>,
    #[arg(long, hide = true)]
    breg_bin: Option<PathBuf>,
    #[arg(long, hide = true)]
    mint_bin: Option<PathBuf>,
    #[arg(long, hide = true)]
    docker_bin: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct StopArgs {
    /// Registry project whose owned services should stop while preserving records.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Also remove the owned container and its data volume, discarding records.
    #[arg(long)]
    remove: bool,
    #[arg(long, hide = true)]
    docker_bin: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SupervisorArgs {
    #[arg(long)]
    dev_root: PathBuf,
    #[arg(long)]
    breg_bin: PathBuf,
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
    breg_port: u16,
    mint_port: u16,
    database_port: u16,
    clients_file: PathBuf,
    source_digest: String,
    instance_id: String,
    source_revision: String,
    container_id: Option<String>,
    tls_files_copied: bool,
    database_ready: bool,
    package_revision: Option<String>,
    activated: bool,
    seeded: BTreeSet<String>,
    outputs: Vec<CredentialOutput>,
    /// Installed prerequisites this session resolved, keyed by command name.
    /// A state document written by an earlier session records none.
    #[serde(default)]
    binaries: BTreeMap<String, Binary>,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialOutput {
    path: PathBuf,
    client: String,
    key: bool,
    digest: String,
}

impl State {
    fn root(&self) -> PathBuf {
        self.project.join(".breg/dev")
    }
    fn container_name(&self) -> String {
        format!("breg-dev-{}", self.owner)
    }
    /// The owned data volume carries the container's generated name; Docker
    /// keeps container and volume names in separate namespaces.
    fn volume_name(&self) -> String {
        format!("breg-dev-{}", self.owner)
    }
    fn container_id(&self) -> Result<&str> {
        self.container_id
            .as_deref()
            .context("owned Docker identity has not been recorded")
    }
    fn breg_origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.breg_port)
    }
    fn mint_origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.mint_port)
    }
    fn audience(&self) -> String {
        format!("urn:breg:dev:{}", self.owner)
    }
    fn save(&self) -> Result<()> {
        private::replace(
            &self.root().join("state.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }
    fn report(&self) -> Result<Value> {
        let clients: Clients = serde_json::from_slice(&private::read(
            &self.root().join("clients.json"),
            MAX_BYTES,
        )?)
        .map_err(|_| {
            anyhow::anyhow!(
                "retained clients are invalid; inspect the owned state before reusing credentials"
            )
        })?;
        Ok(
            json!({"ok":true,"command":"dev","status":self.status,"project":self.project,
            "stateFile":self.root().join("state.json"),"runtimeConfig":self.root().join("runtime.yaml"),
            "bregUrl":self.breg_origin(),"tokenEndpoint":format!("{}/token",self.mint_origin()),
            "audience":self.audience(),"packageRevision":self.package_revision,
            "clients":clients.clients.iter().map(|client|json!({"id":client.id,"accessProfiles":client.access_profiles,
                "clientIdFile":client.client_id_file.clone().unwrap_or_else(||self.root().join("credentials").join(&client.id).join("client-id")),
                "assertionKeyFile":client.assertion_key_file.clone().unwrap_or_else(||self.root().join("credentials").join(&client.id).join("assertion-key.jwk"))})).collect::<Vec<_>>()}),
        )
    }
}

pub fn run(args: DevArgs) -> Result<Value> {
    match args.action {
        Some(DevAction::Stop(args)) => stop(&args.project, args.remove, args.docker_bin.as_deref()),
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

fn read_state(root: &Path) -> Result<State> {
    private::check(root, true)?;
    let state: State = serde_json::from_slice(&private::read(&root.join("state.json"), MAX_BYTES)?)
        .map_err(|_| {
            anyhow::anyhow!("retained dev state is invalid; preserve it for inspection")
        })?;
    if state.version != 1
        || state.root() != root
        || uuid::Uuid::parse_str(&state.owner).is_err()
        || state
            .container_id
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("retained dev state ownership is invalid; no resources were changed");
    }
    ports(state.breg_port, state.mint_port, state.database_port)?;
    Ok(state)
}

fn ports(breg: u16, mint: u16, database: u16) -> Result<()> {
    if breg == 0 || mint == 0 || database == 0 || BTreeSet::from([breg, mint, database]).len() != 3
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

struct CapturedSource {
    files: BTreeMap<String, Vec<u8>>,
    digest: String,
    instance_id: String,
    source_revision: String,
}

fn capture(project: &Path, client_bytes: &[u8]) -> Result<CapturedSource> {
    let source = crate::capture_project_source(project).map_err(|_| {
        anyhow::anyhow!(
            "registry authoring could not be captured; run bregctl check on the project"
        )
    })?;
    let compiled = crate::compile_captured_project(&source, crate::ProfileArg::Production, "dev")
        .map_err(|_| {
        anyhow::anyhow!(
            "registry must compile for a package; run bregctl check --production on the project"
        )
    })?;
    let identity = compiled
        .package()
        .context("local development requires an authored package identity")?;
    if identity.environment != "local" || identity.sequence != 1 {
        bail!("dev initializes only package.environment: local and package.sequence: 1; edit the teaching project explicitly before first start");
    }
    let mut files = BTreeMap::from([("registry.yaml".into(), source.project_bytes)]);
    for asset in source.project_assets {
        files.insert(asset.path.trim_start_matches("source/").into(), asset.bytes);
    }
    for module in source.modules {
        files.insert(format!("modules/{}/module.yaml", module.id), module.bytes);
        for asset in module.assets {
            files.insert(format!("modules/{}/{}", module.id, asset.path), asset.bytes);
        }
    }
    let journeys = crate::read_bounded_source_file(
        &project.join("tests/journeys.yaml"),
        "dev.journeys",
        "tests/journeys.yaml",
        MAX_BYTES,
    )
    .map_err(|_| anyhow::anyhow!("local development requires bounded tests/journeys.yaml"))?;
    files.insert("tests/journeys.yaml".into(), journeys);
    let mut hasher = Sha256::new();
    hasher.update(b"breg-dev-source/v1\0");
    for (path, bytes) in &files {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.update((client_bytes.len() as u64).to_be_bytes());
    hasher.update(client_bytes);
    let digest = crate::hex_lower(&hasher.finalize());
    Ok(CapturedSource {
        files,
        digest,
        instance_id: identity.instance_id.clone(),
        source_revision: identity.source_revision.clone(),
    })
}

fn start(args: StartArgs) -> Result<Value> {
    let project = project(&args.project)?;
    let parent = project.join(".breg");
    private::directory(&parent)?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let root = parent.join("dev");
    let existing = if root.exists() {
        Some(read_state(&root)?)
    } else {
        None
    };
    let clients_file = match &args.clients_file {
        Some(path) => fs::canonicalize(path).context("clients file does not exist")?,
        None => existing
            .as_ref()
            .map(|s| s.clients_file.clone())
            .context("first start requires --clients-file with explicit local clients")?,
    };
    let client_bytes =
        crate::read_bounded_source_file(&clients_file, "dev.clients", "clients", MAX_BYTES)
            .map_err(|_| anyhow::anyhow!("clients file must be one bounded ordinary file"))?;
    let clients = config::clients(&client_bytes)?;
    let CapturedSource {
        files,
        digest,
        instance_id,
        source_revision,
    } = capture(&project, &client_bytes)?;
    let mut state = if let Some(state) = existing {
        if digest != state.source_digest
            || args.breg_port.is_some_and(|p| p != state.breg_port)
            || args.mint_port.is_some_and(|p| p != state.mint_port)
            || args.database_port.is_some_and(|p| p != state.database_port)
        {
            bail!("authored package, clients or ports differ from retained dev state; restore the original inputs to restart, or copy authored files to a new project directory for a fresh experiment. Existing records remain in the stopped container. Use the normal reviewed package lifecycle for an operated upgrade");
        }
        private::validate_tree(&root.join("credentials"))?;
        private::validate_tree(&root.join("secrets"))?;
        if control(&root, "status").is_ok_and(|status| status == "ready") {
            verify_outputs(&state)?;
            return state.report();
        }
        // A live owner lock is conclusive even when its control socket is not ready.
        let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
        state
    } else {
        let state = State {
            version: 1,
            project: project.clone(),
            owner: uuid::Uuid::new_v4().to_string(),
            status: Status::Stopped,
            breg_port: args.breg_port.unwrap_or(8090),
            mint_port: args.mint_port.unwrap_or(8091),
            database_port: args.database_port.unwrap_or(55432),
            clients_file,
            source_digest: digest,
            instance_id,
            source_revision,
            container_id: None,
            tls_files_copied: false,
            database_ready: false,
            package_revision: None,
            activated: false,
            seeded: BTreeSet::new(),
            outputs: vec![],
            binaries: BTreeMap::new(),
        };
        ports(state.breg_port, state.mint_port, state.database_port)?;
        for port in [state.breg_port, state.mint_port, state.database_port] {
            probe(port)?;
        }
        initialize(&root, &state, &clients, &files)?;
        read_state(&root)?
    };
    verify_outputs(&state)?;
    let breg = executable("breg", args.breg_bin.as_deref())?;
    let mint = executable("mint", args.mint_bin.as_deref())?;
    let docker = executable("docker", args.docker_bin.as_deref())?;
    for port in [state.breg_port, state.mint_port] {
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
    state.binaries = BTreeMap::from([
        ("breg".into(), binary(&root, &breg)?),
        ("mint".into(), binary(&root, &mint)?),
        ("docker".into(), binary(&root, &docker)?),
    ]);
    state.status = Status::Starting;
    state.save()?;
    let log = log_file(&root, "supervisor")?;
    let mut supervisor = Command::new(std::env::current_exe()?)
        .arg("__dev-supervisor")
        .arg("--dev-root")
        .arg(&root)
        .arg("--breg-bin")
        .arg(breg)
        .arg("--mint-bin")
        .arg(mint)
        .arg("--docker-bin")
        .arg(docker)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()
        .context("cannot launch native local supervisor")?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let state = read_state(&root)?;
        if matches!(state.status, Status::Ready)
            && control(&root, "status").is_ok_and(|status| status == "ready")
        {
            return state.report();
        }
        if supervisor.try_wait()?.is_some() || matches!(state.status, Status::Failed) {
            let mut failed = state;
            failed.status = Status::Failed;
            failed.save()?;
            bail!("local start failed; private diagnostics are in {}. Retry the same command after correcting the cause; retained data is preserved",root.join("logs").display());
        }
        if Instant::now() > deadline {
            signal(&mut supervisor)?;
            supervisor.wait()?;
            bail!("local start timed out; inspect private logs and retry the same command");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn initialize(
    root: &Path,
    original: &State,
    clients: &Clients,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for client in &clients.clients {
        for path in [&client.client_id_file, &client.assertion_key_file]
            .into_iter()
            .flatten()
        {
            if fs::symlink_metadata(path).is_ok() {
                bail!("credential output already exists; choose fresh pair paths, preserving existing credentials");
            }
        }
    }
    let stage = root
        .parent()
        .context("dev parent missing")?
        .join(format!(".dev-{}", original.owner));
    private::directory(&stage)?;
    let result = (|| {
        private::create(&stage.join(".gitignore"), b"*\n")?;
        config::prepare(&stage, original, clients)?;
        private::create(&stage.join("clients.json"), &serde_json::to_vec(clients)?)?;
        private::directory(&stage.join("project"))?;
        for (relative, bytes) in files {
            let path = stage.join("project").join(relative);
            let parent = path.parent().context("source parent missing")?;
            let mut cursor = stage.join("project");
            for component in parent.strip_prefix(&cursor)?.components() {
                cursor.push(component);
                private::directory(&cursor)?;
            }
            private::create(&path, bytes)?;
        }
        let mut state = original.clone();
        for client in &clients.clients {
            for (destination, key) in [
                (&client.client_id_file, false),
                (&client.assertion_key_file, true),
            ] {
                if let Some(path) = destination {
                    let source = stage.join("credentials").join(&client.id).join(if key {
                        "assertion-key.jwk"
                    } else {
                        "client-id"
                    });
                    state.outputs.push(CredentialOutput {
                        path: path.clone(),
                        client: client.id.clone(),
                        key,
                        digest: config::hash(&private::read(&source, MAX_BYTES)?),
                    });
                }
            }
        }
        private::create(
            &stage.join("state.json"),
            &serde_json::to_vec_pretty(&state)?,
        )?;
        fs::rename(&stage, root)?;
        Ok(())
    })();
    if result.is_err() && stage.exists() {
        fs::remove_dir_all(&stage).context("cannot clean owned incomplete initialization")?;
    }
    result
}

fn verify_outputs(state: &State) -> Result<()> {
    for output in &state.outputs {
        let source = state
            .root()
            .join("credentials")
            .join(&output.client)
            .join(if output.key {
                "assertion-key.jwk"
            } else {
                "client-id"
            });
        let bytes = Zeroizing::new(private::read(&source, MAX_BYTES)?);
        if config::hash(&bytes) != output.digest {
            bail!(
                "owned credential changed; preserve state and inspect the private credential pair"
            );
        }
        if fs::symlink_metadata(&output.path).is_ok() {
            if config::hash(&private::read(&output.path, MAX_BYTES)?) != output.digest {
                bail!("credential output conflicts with retained ownership; no credentials were replaced");
            }
        } else {
            private::create(&output.path, &bytes)?;
        }
    }
    Ok(())
}

fn stop(project_path: &Path, remove: bool, docker_bin: Option<&Path>) -> Result<Value> {
    let project = project(project_path)?;
    let parent = project.join(".breg");
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
            return state.report();
        }
    }
    // No PID-based recovery: unrelated reused PIDs must never be signalled.
    let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
    for port in [state.breg_port, state.mint_port] {
        probe(port)?;
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
    state.report()
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

/// Forget the reclaimed database while keeping the ownership identifier, ports,
/// clients, credentials and built package the next start reuses.
fn reclaimed(state: &mut State) {
    state.container_id = None;
    state.tls_files_copied = false;
    state.database_ready = false;
    state.activated = false;
    state.seeded.clear();
    state.status = Status::Stopped;
}

fn completed_supervisor_lock(root: &Path, status: &Status) -> Result<private::Lock> {
    let deadline = Instant::now()
        + if matches!(status, Status::Stopped | Status::Stopping) {
            Duration::from_secs(5)
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
    Ok(fs::canonicalize("/tmp")?.join(format!("breg-dev-{}", state.owner)))
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
    stream.set_read_timeout(Some(Duration::from_secs(75)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("{message}\n").as_bytes())?;
    let mut bytes = Vec::new();
    stream.take(64).read_to_end(&mut bytes)?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

pub fn run_supervisor(args: SupervisorArgs) -> Result<()> {
    rustix::process::setsid().context("cannot detach local supervisor")?;
    let root = fs::canonicalize(&args.dev_root)?;
    let _lock = private::lock(&root.join("supervisor.lock"))?;
    let mut state = read_state(&root)?;
    if !matches!(state.status, Status::Starting) {
        bail!("supervisor requires a pending owned start");
    }
    let terminate = Arc::new(AtomicBool::new(false));
    for signal in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(signal, Arc::clone(&terminate))?;
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
            &root,
            "mint",
        )?);
        ready(
            &format!("{}/ready", state.mint_origin()),
            children.mint.as_mut().context("Mint child missing")?,
            &terminate,
        )?;
        if state.package_revision.is_none() {
            // The schema-test rehearsal presents these tokens to its own
            // disposable runtime; the seed below mints its own.
            tokens(&args.mint_bin, &state, &clients)?;
            package(&args.docker_bin, &mut state, &clients)?;
        }
        ensure_active(&terminate)?;
        if !state.activated {
            // apply is the native activation/recovery authority. A retry after an
            // interrupted activation first asks doctor whether it already committed.
            let mut doctor = ctl(&state);
            doctor
                .arg("doctor")
                .arg("--runtime-config")
                .arg(root.join("runtime.yaml"));
            let (reported, report) = output(&mut doctor, &root, "doctor-before-apply", None)?;
            if activation(reported, &report)? == Activation::NotActivated {
                let mut apply = ctl(&state);
                apply
                    .arg("apply")
                    .arg("--runtime-config")
                    .arg(root.join("runtime.yaml"))
                    .arg("--package")
                    .arg(root.join("build/package"))
                    .arg("--initial");
                command(&mut apply, &root, "apply", None)?;
            }
            state.activated = true;
            state.save()?;
        }
        let mut verify = ctl(&state);
        verify
            .arg("verify")
            .arg("--runtime-config")
            .arg(root.join("runtime.yaml"));
        command(&mut verify, &root, "verify", None)?;
        children.breg = Some(service(
            &args.breg_bin,
            &["--config"],
            &root.join("runtime.yaml"),
            &root,
            "breg",
        )?);
        ready(
            &format!("{}/ready", state.breg_origin()),
            children.breg.as_mut().context("BReg child missing")?,
            &terminate,
        )?;
        // A client token lives 300 seconds, which the child and readiness
        // deadlines of a slow first start can exhaust before the seed runs.
        // Mint the seeding tokens once the registry is ready, not before it.
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

/// Read one client control command from `stream`, stopping at the first
/// newline, at end of stream, or after 16 bytes, whichever comes first. A
/// command that a client's write splits across the socket is read whole
/// here; the caller compares the returned bytes against the known commands.
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
    breg: Option<Child>,
    mint: Option<Child>,
}
impl Children {
    fn exited(&mut self) -> Result<bool> {
        for child in [&mut self.breg, &mut self.mint].into_iter().flatten() {
            if child.try_wait()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn stop(&mut self) -> Result<()> {
        let mut error = None;
        for owned in [&mut self.breg, &mut self.mint] {
            if let Some(mut child) = owned.take() {
                if let Err(cause) = stop_child(&mut child) {
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
/// Recorded when an installed prerequisite does not report a usable version.
/// A command that declines to identify itself still serves the session, and
/// losing its recorded path would cost a later diagnosis more than the
/// unknown version does.
const UNREPORTED_VERSION: &str = "unreported";
/// Longest version line kept; a prerequisite that prints a banner is bounded
/// like every other captured output.
const MAX_VERSION: usize = 200;

/// Identify a resolved prerequisite for the state document: the fully
/// canonical path of the file that runs, and the version it reports for
/// itself. Diagnostics stay in the owner-only log directory.
fn binary(root: &Path, path: &Path) -> Result<Binary> {
    let (success, bytes) = output(
        Command::new(path).arg("--version"),
        root,
        &format!(
            "version-{}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ),
        None,
    )?;
    let reported = String::from_utf8_lossy(&bytes);
    let reported = reported.lines().next().unwrap_or_default().trim();
    let version = if !success || reported.is_empty() {
        UNREPORTED_VERSION.to_string()
    } else {
        reported.chars().take(MAX_VERSION).collect()
    };
    Ok(Binary {
        path: fs::canonicalize(path)?,
        version,
    })
}
fn log_file(root: &Path, name: &str) -> Result<File> {
    let path = root
        .join("logs")
        .join(format!("{name}-{}.log", uuid::Uuid::new_v4()));
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
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
fn service(binary: &Path, args: &[&str], config: &Path, root: &Path, name: &str) -> Result<Child> {
    let mut child = Command::new(binary)
        .args(args)
        .arg(config)
        .env("SSL_CERT_FILE", root.join("tls/ca.pem"))
        .env("BREG_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start local service")?;
    let out = child.stdout.take().context("service output pipe missing")?;
    let err = child
        .stderr
        .take()
        .context("service diagnostic pipe missing")?;
    let log = log_file(root, name)?;
    let second = log.try_clone()?;
    thread::spawn(move || {
        let _ = pump(out, log);
    });
    thread::spawn(move || {
        let _ = pump(err, second);
    });
    Ok(child)
}
/// Bytes written to a child's standard input, naming the secret substring the
/// child must never be able to echo back into a log, a report or an error.
struct Input<'a> {
    bytes: &'a [u8],
    secret: Option<&'a [u8]>,
}

/// Shortest run of secret bytes that must not survive in captured output. A
/// database client echoes a window around an error position rather than the
/// whole statement, so partial runs are hidden as well as whole occurrences.
const SECRET_RUN: usize = 8;

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

/// Run one owned prerequisite, returning whether it succeeded together with
/// its captured stdout. Diagnostics stay in the owner-only log directory.
fn output(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
) -> Result<(bool, Vec<u8>)> {
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
    // Diagnostics that could carry a secret are captured and redacted before
    // they are persisted; otherwise they stream straight into the log.
    let redacting = secret.clone();
    let err = thread::spawn(move || match redacting {
        Some(secret) => {
            let mut captured = Zeroizing::new(Vec::new());
            pump(stderr, &mut *captured)?;
            let mut log = log;
            log.write_all(&redact(&captured, &secret))?;
            Ok(())
        }
        None => pump(stderr, log),
    });
    if let Some(input) = &input {
        child
            .stdin
            .take()
            .context("command input missing")?
            .write_all(input.bytes)?;
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            stop_child(&mut child)?;
            bail!("native local prerequisite timed out; inspect private logs");
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut bytes = out
        .join()
        .map_err(|_| anyhow::anyhow!("command output reader failed"))??;
    err.join()
        .map_err(|_| anyhow::anyhow!("command diagnostic reader failed"))??;
    if let Some(secret) = &secret {
        let echoed = Zeroizing::new(std::mem::take(&mut bytes));
        bytes = redact(&echoed, secret);
    }
    if !status.success() {
        // Native bregctl reports errors on stdout in JSON mode. Preserve them
        // privately as well; selectors and credentials never enter the report.
        let mut log = log_file(root, &format!("{name}-report"))?;
        log.write_all(&bytes)?;
    }
    Ok((status.success(), bytes))
}
fn command(
    command: &mut Command,
    root: &Path,
    name: &str,
    input: Option<Input<'_>>,
) -> Result<Vec<u8>> {
    let (success, bytes) = output(command, root, name, input)?;
    if !success {
        bail!(
            "native {name} failed; inspect owner-only diagnostics in {}",
            root.join("logs").display()
        );
    }
    Ok(bytes)
}
#[derive(Debug, Eq, PartialEq)]
enum Activation {
    Activated,
    NotActivated,
}

/// Classify the doctor report taken before activation. Only a database that is
/// not ready for the runtime package means activation never committed; every
/// other refusal is a real prerequisite failure and must stop the start.
fn activation(success: bool, report: &[u8]) -> Result<Activation> {
    if success {
        return Ok(Activation::Activated);
    }
    let report: Value = serde_json::from_slice(report).context(
        "doctor refused the runtime configuration without a machine-readable report; inspect private logs",
    )?;
    let diagnostics = report["diagnostics"]
        .as_array()
        .filter(|diagnostics| !diagnostics.is_empty())
        .context("doctor refused without naming a diagnostic; inspect private logs")?;
    if diagnostics
        .iter()
        .all(|entry| entry["code"] == "startup.database.unready")
    {
        return Ok(Activation::NotActivated);
    }
    bail!(
        "doctor refused before activation: {}",
        diagnostics
            .iter()
            .map(|entry| format!(
                "{} at {}: {}",
                entry["code"].as_str().unwrap_or("unknown"),
                entry["path"].as_str().unwrap_or("unknown"),
                entry["message"].as_str().unwrap_or("no message")
            ))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

fn ctl(state: &State) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current executable exists"));
    command
        .arg("--format")
        .arg("json")
        .env("SSL_CERT_FILE", state.root().join("tls/ca.pem"));
    command
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
                    &format!("{}:/tmp/breg-dev-{target}", state.container_id()?),
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
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let result = docker_command(
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
            None,
        );
        if result.is_ok() {
            break;
        }
        if Instant::now() > deadline {
            bail!("owned PostgreSQL did not become ready; inspect private logs");
        }
        thread::sleep(Duration::from_millis(200));
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
                "/tmp/breg-dev-server.key",
                "/tmp/breg-dev-server.pem",
                "/tmp/breg-dev-pg_hba.conf",
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
                "/tmp/breg-dev-server.key",
            ],
            None,
        )?;
        sql(docker,state,"postgres",b"ALTER SYSTEM SET hba_file = '/tmp/breg-dev-pg_hba.conf';\nALTER SYSTEM SET ssl = 'on';\nALTER SYSTEM SET ssl_cert_file = '/tmp/breg-dev-server.pem';\nALTER SYSTEM SET ssl_key_file = '/tmp/breg-dev-server.key';\nSELECT pg_reload_conf();\n",None)?;
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
        for database in ["breg_dev", "breg_dev_test"] {
            let exists = sql(
                docker,
                state,
                "postgres",
                format!("SELECT count(*) FROM pg_database WHERE datname='{database}';").as_bytes(),
                None,
            )?;
            if String::from_utf8_lossy(&exists).trim() == "0" {
                sql(
                    docker,
                    state,
                    "postgres",
                    format!("CREATE DATABASE {database};").as_bytes(),
                    None,
                )?;
            }
            let mut statements=format!("CREATE EXTENSION IF NOT EXISTS btree_gist; REVOKE ALL ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {MIGRATION_ROLE},{RUNTIME_ROLE};");
            for schema in [
                "registry_internal",
                "registry_data",
                "registry_source",
                "registry_derived",
                "registry_context",
            ] {
                statements.push_str(&format!("CREATE SCHEMA IF NOT EXISTS {schema} AUTHORIZATION {MIGRATION_ROLE}; REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;"));
            }
            sql(docker, state, database, statements.as_bytes(), None)?;
        }
        state.database_ready = true;
        state.save()?;
    }
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
    for client in &clients.clients {
        token(mint, state, &client.id)?;
    }
    Ok(())
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

fn package(docker: &Path, state: &mut State, clients: &Clients) -> Result<()> {
    let root = state.root();
    // The schema-test database is disposable. A failed rehearsal is rebuilt;
    // the retained runtime database is never dropped or reseeded here.
    sql(
        docker,
        state,
        "postgres",
        b"DROP DATABASE IF EXISTS breg_dev_test WITH (FORCE); CREATE DATABASE breg_dev_test;",
        None,
    )?;
    let mut initialization=format!("CREATE EXTENSION btree_gist; REVOKE ALL ON DATABASE breg_dev_test FROM PUBLIC; GRANT CONNECT ON DATABASE breg_dev_test TO {MIGRATION_ROLE},{RUNTIME_ROLE};");
    for schema in [
        "registry_internal",
        "registry_data",
        "registry_source",
        "registry_derived",
        "registry_context",
    ] {
        initialization.push_str(&format!("CREATE SCHEMA {schema} AUTHORIZATION {MIGRATION_ROLE}; REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;"));
    }
    sql(
        docker,
        state,
        "breg_dev_test",
        initialization.as_bytes(),
        None,
    )?;
    let journeys: Value = serde_norway::from_slice(&private::read(
        &root.join("project/tests/journeys.yaml"),
        MAX_BYTES,
    )?)?;
    let mut bindings = Vec::new();
    for journey in journeys["journeys"]
        .as_array()
        .context("journeys must contain an array")?
    {
        for step in journey["steps"]
            .as_array()
            .context("journey steps must be an array")?
        {
            let profile = step["accessProfile"]
                .as_str()
                .context("journey step requires an access profile")?;
            let client = clients
                .clients
                .iter()
                .find(|client| client.access_profiles.iter().any(|p| p == profile))
                .context("every schema-test profile needs an explicit local client binding")?;
            bindings.push(json!({"journeyId":journey["id"],"stepId":step["id"],"credential":{"type":"bearer","tokenRef":format!("secret:file/{}-token",client.id)}}));
        }
    }
    let credentials = json!({"apiVersion":"registry.registrystack.org/breg-schema-test-credentials/v1","kind":"SchemaTestCredentials","bindings":bindings});
    private::replace(
        &root.join("schema-test-credentials.yaml"),
        serde_norway::to_string(&credentials)?.as_bytes(),
    )?;
    // Failed, unpublished build/receipt paths belong solely to this journal.
    for path in [
        root.join("schema-test-receipt.json"),
        root.join("runtime.yaml"),
    ] {
        if path.exists() {
            private::check(&path, false)?;
            fs::remove_file(path)?;
        }
    }
    if root.join("build").exists() {
        fs::remove_dir_all(root.join("build"))?;
    }
    let mut test = ctl(state);
    test.arg("test")
        .arg(root.join("project"))
        .arg("--runtime-config")
        .arg(root.join("runtime-test.yaml"))
        .arg("--credentials")
        .arg(root.join("schema-test-credentials.yaml"))
        .arg("--database-id")
        .arg(DATABASE_ID)
        .arg("--output")
        .arg(root.join("schema-test-receipt.json"));
    let report: Value = serde_json::from_slice(&command(&mut test, &root, "schema-test", None)?)?;
    let fingerprint = report["schemaFingerprint"]
        .as_str()
        .context("schema-test report has no fingerprint")?;
    let mut package = ctl(state);
    package
        .arg("package")
        .arg(root.join("project"))
        .arg("--database-id")
        .arg(DATABASE_ID)
        .arg("--schema-fingerprint")
        .arg(fingerprint)
        .arg("--test-receipt")
        .arg(root.join("schema-test-receipt.json"))
        .arg("--output")
        .arg(root.join("build"));
    let report: Value = serde_json::from_slice(&command(&mut package, &root, "package", None)?)?;
    let revision = report["packageRevision"]
        .as_str()
        .context("package report has no revision")?;
    config::runtime(&root, state, clients, revision, false)?;
    state.package_revision = Some(revision.into());
    state.save()
}

fn http(
    url: &str,
    token: Option<&str>,
    body: Option<Value>,
    idempotency: Option<&str>,
) -> Result<(u16, Value)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        let mut request = if let Some(body) = body {
            client.post(url).json(&body)
        } else {
            client.get(url)
        };
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency {
            request = request.header("Idempotency-Key", key);
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
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        ensure_active(terminate)?;
        if child.try_wait()?.is_some() {
            bail!("local service exited before readiness; inspect private logs");
        }
        if matches!(http(url, None, None, None), Ok((200, _))) {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("local service readiness timed out; inspect private logs");
        }
        thread::sleep(Duration::from_millis(200));
    }
}
fn seed(state: &mut State, clients: &Clients) -> Result<()> {
    let compiled = crate::compile(
        &state.root().join("project"),
        crate::ProfileArg::Authoring,
        "dev",
    )
    .map_err(|_| anyhow::anyhow!("captured seed project no longer compiles"))?;
    for seed in &clients.seed {
        if state.seeded.contains(&seed.id) {
            continue;
        }
        let route = compiled
            .routes()
            .routes
            .iter()
            .find(|r| {
                r.entity_id == seed.entity
                    && r.operation == registry_breg::contract::Operation::Create
                    && r.access_profiles.contains(&seed.access_profile)
            })
            .context("seed requires an authored create route and explicit permitted profile")?;
        let mut url = reqwest::Url::parse(&state.breg_origin())?.join(&route.path)?;
        url.query_pairs_mut()
            .append_pair("accessProfile", &seed.access_profile);
        let token = Zeroizing::new(String::from_utf8(private::read(
            &state
                .root()
                .join("secrets")
                .join(format!("{}-token", seed.client)),
            65536,
        )?)?);
        let key = format!("dev-{}-{}", state.owner, seed.id);
        let (status, _) = http(
            url.as_str(),
            Some(&token),
            Some(json!({"data":seed.data})),
            Some(&key),
        )?;
        if status != 201 {
            bail!("synthetic seed was refused; inspect the authored seed/profile and retained state. Earlier completed seeds will not repeat");
        }
        state.seeded.insert(seed.id.clone());
        state.save()?;
    }
    Ok(())
}
