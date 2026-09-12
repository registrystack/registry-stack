// SPDX-License-Identifier: Apache-2.0
//! Native, retained, loopback-only BReg tutorial lifecycle.
//!
//! A resident supervisor owns service children. The only database it may
//! start or stop is the container whose random ownership label and immutable
//! Docker ID match its private journal. There is intentionally no reset.

mod config;
mod events;
pub mod examples;
mod export_client;
mod prepare_source;
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
const SPATIAL_IMAGE: &str =
    "postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6";
const LABEL: &str = "org.registrystack.bregctl.dev-owner";
/// Refusal for a project that never started. Reporting a stopped session
/// would claim owned services were stopped when none were ever created.
const MISSING_SESSION: &str = "no local development session exists in this project; nothing was stopped. Check the project path, or start one with bregctl dev";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Longest one supervised prerequisite command may run before the supervisor
/// stops it and fails the start.
const CHILD_DEADLINE: Duration = Duration::from_secs(120);
/// Longest the supervisor waits for the owned database, and for each started
/// service, to answer as ready.
const READY_DEADLINE: Duration = Duration::from_secs(45);

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
    /// A resident supervisor owns this project's PostgreSQL and ThunderID
    /// containers plus its Base Registry Engine (BReg) child. The database runs
    /// the pinned image
    /// postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675,
    /// or, when the compiled schema requires PostGIS,
    /// postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6,
    /// which the supervisor pulls on the first start. Each supervised
    /// prerequisite command may run for 120 seconds, and the database and each
    /// started service have 45 seconds to answer as ready. A start that passes
    /// a deadline fails, stops what it acquired, and keeps its owner-only
    /// diagnostics in the project's private .breg/dev/logs directory.
    Start(StartArgs),
    /// Stop only this project's supervised services, preserving its database.
    Stop(StopArgs),
    /// Show received local webhook deliveries, hiding projected values by default.
    Events(EventsArgs),
    /// Copy an explicitly selected retained local client credential pair.
    ExportClient(export_client::ExportClientArgs),
    /// Acquire a fresh local client token and report its private header-file path.
    Token(TokenArgs),
    /// Exchange an existing Casework approval using an explicit configured issuer connection.
    Grant(GrantArgs),
    /// Review or prepare a bounded lookup successor for a stopped retained registry.
    ///
    /// `evidencectl source add` drives this operation for an adopter, so the
    /// lifecycle help lists only the commands run by hand.
    #[command(hide = true)]
    PrepareSource(Box<prepare_source::PrepareSourceArgs>),
}

#[derive(Debug, Args)]
struct GrantArgs {
    /// Registered agent client ID in the owner-only connection file.
    client: String,
    /// Existing Casework-approved grant UUID; this command does not approve tasks.
    #[arg(long)]
    grant: String,
    /// Owner-only task connection v1 file with the registered agent key and fixed target.
    #[arg(long, value_name = "FILE")]
    connection: PathBuf,
    /// Existing project whose private directory receives the grant-specific header.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
}

#[derive(Debug, Args)]
struct TokenArgs {
    /// Registered local client ID.
    client: String,
    /// Ready local project (defaults to the current directory).
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Existing authored registry project. Its package environment must be local.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// Local clients, profile bindings, and optional seed records (default on
    /// first start: dev-clients.yaml in the project; retained for restarts).
    #[arg(long, alias = "clients", value_name = "FILE")]
    clients_file: Option<PathBuf>,
    /// Registry loopback port on first start (default 8090; retained for restarts).
    #[arg(long)]
    breg_port: Option<u16>,
    /// Local issuer loopback port on first start (default 8091; retained for restarts).
    #[arg(long)]
    issuer_port: Option<u16>,
    /// Immutable local candidate issuer image ID on first start; retained for restarts.
    #[arg(long, value_parser = candidate_issuer_image)]
    issuer_image: Option<String>,
    /// Retained spelling from earlier Mint-based dev sessions; refused with
    /// legacy-session guidance rather than silently ignored.
    #[arg(long)]
    mint_port: Option<u16>,
    /// Retained spelling from earlier Mint-based dev sessions; refused with
    /// legacy-session guidance rather than silently ignored.
    #[arg(long)]
    mint_bin: Option<PathBuf>,
    /// PostgreSQL loopback port on first start (default 55432; retained for restarts).
    #[arg(long)]
    database_port: Option<u16>,
    #[arg(long, hide = true)]
    breg_bin: Option<PathBuf>,
    #[arg(long, hide = true)]
    docker_bin: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct StopArgs {
    /// Registry project whose owned services should stop while preserving records.
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
    /// Local registry project whose retained deliveries should be inspected.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// Explicitly show projected values captured by the development receiver.
    #[arg(long)]
    include_payload: bool,
}

#[derive(Debug, Args)]
pub struct SupervisorArgs {
    #[arg(long)]
    dev_root: PathBuf,
    #[arg(long)]
    breg_bin: PathBuf,
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
    issuer_port: u16,
    #[serde(default)]
    issuer_image: Option<String>,
    database_port: u16,
    /// Fixed at first start from the compiled schema; retained with the database.
    #[serde(default)]
    requires_postgis: bool,
    /// Kernel-selected loopback receiver port, retained with destination bindings.
    #[serde(default)]
    webhook_port: Option<u16>,
    clients_file: PathBuf,
    source_digest: String,
    sequence: u64,
    baseline_runtime: Option<PathBuf>,
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
    /// Why the detached supervisor stopped, recorded so the terminal that
    /// asked for the start can report it. The supervisor writes both its
    /// streams to a private log, so this is the only path a refusal has back
    /// to the owner. A state document written by an earlier session, and a
    /// session that has not failed, record none.
    #[serde(default)]
    failure: Option<String>,
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
    fn database_image(&self) -> &'static str {
        if self.requires_postgis {
            SPATIAL_IMAGE
        } else {
            IMAGE
        }
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
    fn issuer_origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.issuer_port)
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
            "bregUrl":self.breg_origin(),"issuer":self.issuer_origin(),"tokenEndpoint":format!("{}/oauth2/token",self.issuer_origin()),
            "clientAssertionAudience":self.issuer_origin(),"resource":self.audience(),
            "webhookUrl":self.webhook_port.map(|port|format!("http://127.0.0.1:{port}/events")),
            "eventsFile":self.webhook_port.map(|_|self.root().join("events.jsonl")),
            "audience":self.audience(),"packageRevision":self.package_revision,"packageSequence":self.sequence,"activationPending":!self.activated,
            "clients":clients.clients.iter().map(|client|json!({"id":client.id,"accessProfiles":client.access_profiles,"scopes":client.scopes,
                "clientIdFile":client.client_id_file.clone().unwrap_or_else(||self.root().join("credentials").join(&client.id).join("client-id")),
                "assertionKeyFile":client.assertion_key_file.clone().unwrap_or_else(||self.root().join("credentials").join(&client.id).join("assertion-key.jwk"))})).collect::<Vec<_>>()}),
        )
    }
}

pub fn run(args: DevArgs) -> Result<Value> {
    match args.action {
        Some(DevAction::Stop(args)) => stop(&args.project, args.remove, args.docker_bin.as_deref()),
        Some(DevAction::Events(args)) => {
            let project = project(&args.project)?;
            private::check(&project.join(".breg"), true)?;
            let state = read_state(&project.join(".breg/dev"))?;
            events::report(&state.root(), args.include_payload)
        }
        Some(DevAction::Start(args)) => start(args),
        Some(DevAction::ExportClient(args)) => export_client::run(args),
        Some(DevAction::Token(args)) => fresh_token(&args.project, &args.client),
        Some(DevAction::Grant(args)) => approved_grant(args),
        Some(DevAction::PrepareSource(args)) => prepare_source::run(*args),
        None => start(args.start),
    }
}

fn approved_grant(args: GrantArgs) -> Result<Value> {
    let project = project(&args.project)?;
    let output = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(registry_thunderid_tooling::grant_file::acquire_to_header(
            &args.connection,
            &project.join(".breg"),
            &args.client,
            &args.grant,
        ))?;
    Ok(
        json!({"ok":true,"command":"dev grant","headerFile":output.header_file,"grantExpiresAt":output.grant_expires_at}),
    )
}

fn fresh_token(project_path: &Path, client: &str) -> Result<Value> {
    if !config::identifier(client) {
        bail!("a registered bounded local client ID is required");
    }
    let project = project(project_path)?;
    private::check(&project.join(".breg"), true)?;
    let root = project.join(".breg/dev");
    let state = read_state(&root)?;
    if !matches!(state.status, Status::Ready)
        || !control(&root, "status").is_ok_and(|status| status == "ready")
    {
        bail!("the local development session must be ready before requesting a token");
    }
    // Resolve admission before opening any caller-derived credential path.
    let clients: Clients =
        serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES)?)?;
    if !clients
        .clients
        .iter()
        .any(|configured| configured.id == client)
    {
        bail!("the local client is not registered");
    }
    token(&state, client)?;
    let credential = Zeroizing::new(private::read(
        &root.join("secrets").join(format!("{client}-token")),
        65536,
    )?);
    let mut header = Zeroizing::new(b"Authorization: Bearer ".to_vec());
    header.extend_from_slice(&credential);
    header.push(b'\n');
    let output = root.join("secrets").join(format!("{client}.header"));
    private::replace(&output, &header)?;
    Ok(json!({"ok":true,"command":"dev token","headerFile":output}))
}

fn project(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)?.is_dir() {
        bail!("project must be an ordinary existing directory");
    }
    Ok(fs::canonicalize(path)?)
}

/// The project's private `.breg` directory, ignored by version control as a
/// whole: the session directory ignores itself, and the lock beside it would
/// otherwise be the one private file a reader could commit.
fn parent_directory(project: &Path) -> Result<PathBuf> {
    let parent = project.join(".breg");
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
                bail!("first start needs local clients: add dev-clients.yaml to the project, as bregctl init does, or name a clients file with --clients-file")
            }
        }
    }
}

fn read_state(root: &Path) -> Result<State> {
    private::check(root, true)?;
    let bytes = private::read(&root.join("state.json"), MAX_BYTES)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VersionProbe {
        version: u8,
        mint_port: Option<u16>,
    }
    let invalid = || anyhow::anyhow!("retained dev state is invalid; preserve it for inspection");
    let version: VersionProbe = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if version.version == 1 && version.mint_port.is_some() {
        bail!(
            "this retained dev session still records its Mint-based issuer (state v1). \
            This build does not implement retained issuer migration; keep the \
            matching Mint-era bregctl and issuer for this session until a \
            verified migration is available. Nothing was changed"
        );
    }
    let state: State = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if state.version != 2
        || state.sequence == 0
        || state.baseline_runtime
            != (state.sequence > 1).then(|| {
                root.join(format!("baseline-{}", state.sequence - 1))
                    .join("runtime.yaml")
            })
        || state.root() != root
        || uuid::Uuid::parse_str(&state.owner).is_err()
        || state
            .container_id
            .as_ref()
            .is_some_and(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("retained dev state ownership is invalid; no resources were changed");
    }
    if let Some(image) = &state.issuer_image {
        candidate_issuer_image(image).map_err(anyhow::Error::msg)?;
    }
    ports(state.breg_port, state.issuer_port, state.database_port)?;
    if state.webhook_port.is_some_and(|port| {
        port == 0 || [state.breg_port, state.issuer_port, state.database_port].contains(&port)
    }) {
        bail!("retained webhook receiver needs a distinct nonzero loopback port");
    }
    Ok(state)
}

fn candidate_issuer_image(value: &str) -> std::result::Result<String, String> {
    if value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        Ok(value.to_owned())
    } else {
        Err("issuer image must be an immutable local sha256: image ID with 64 lowercase hexadecimal digits".into())
    }
}

fn ports(breg: u16, issuer: u16, database: u16) -> Result<()> {
    if breg == 0
        || issuer == 0
        || database == 0
        || BTreeSet::from([breg, issuer, database]).len() != 3
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

fn receiver_port(state: &State) -> Result<u16> {
    loop {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        if ![state.breg_port, state.issuer_port, state.database_port].contains(&port) {
            return Ok(port);
        }
    }
}

/// Older versions could retain a failed rehearsal with declared events but
/// no receiver binding. Repair that incomplete local setup without touching
/// its database, credentials, or captured source.
fn prepare_receiver(state: &mut State, clients: &Clients) -> Result<()> {
    if state.webhook_port.is_some() {
        return Ok(());
    }
    let root = state.root();
    let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
        .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
    if compiled.event_deliveries().deliveries.is_empty() {
        return Ok(());
    }
    if state.package_revision.is_some() || state.activated {
        bail!("an activated local event package lacks its retained receiver binding; preserve its state for inspection");
    }
    let port = receiver_port(state)?;
    let key = root.join("secrets/webhook-key");
    if fs::symlink_metadata(&key).is_ok() {
        private::check(&key, false)?;
    } else {
        config::webhook_secret(&root)?;
    }
    state.webhook_port = Some(port);
    let runtime = root.join("runtime-test.yaml");
    if runtime.exists() {
        private::check(&runtime, false)?;
        fs::remove_file(runtime)?;
    }
    config::runtime(
        &root,
        state,
        clients,
        &format!("sha256:{}", "1".repeat(64)),
        true,
    )?;
    state.save()
}

/// Name the first journey step whose access profile no local client binds.
///
/// The schema-test stage makes the same lookup, but by then the database has
/// been pulled and the issuer is serving. Refusing here, before any service starts,
/// tells the author which profile the clients file still lacks while the fix
/// is one edit away.
fn bind_journey_profiles(journeys: &[u8], clients: &Clients) -> Result<()> {
    let journeys: Value = serde_norway::from_slice(journeys)
        .context("tests/journeys.yaml must parse before local development starts")?;
    let mut used = BTreeSet::new();
    for journey in journeys["journeys"]
        .as_array()
        .context("journeys must contain an array")?
    {
        for step in journey["steps"]
            .as_array()
            .context("journey steps must be an array")?
        {
            let journey_id = journey["id"].as_str().context("journey requires an id")?;
            let step_id = step["id"].as_str().context("journey step requires an id")?;
            let profile = step["accessProfile"]
                .as_str()
                .context("journey step requires an access profile")?;
            if let Some(client) = exact_journey_client(clients, journey_id, step_id, profile)? {
                used.insert((journey_id.to_owned(), step_id.to_owned()));
                let _ = client;
                continue;
            }
            if step["claims"]
                .as_object()
                .is_some_and(|claims| claims.is_empty())
            {
                continue;
            }
            let client = journey_client(clients, journey_id, step_id, profile)?;
            if !client.test_bindings.is_empty() {
                used.insert((journey_id.to_owned(), step_id.to_owned()));
            }
        }
    }
    for client in &clients.clients {
        for binding in &client.test_bindings {
            if !used.contains(&(binding.journey_id.clone(), binding.step_id.clone())) {
                bail!(
                    "client {} testBindings names unknown or profile-mismatched journey step {}/{}",
                    client.id,
                    binding.journey_id,
                    binding.step_id
                );
            }
        }
    }
    Ok(())
}

fn journey_client<'a>(
    clients: &'a Clients,
    journey_id: &str,
    step_id: &str,
    profile: &str,
) -> Result<&'a config::Client> {
    let candidates = clients
        .clients
        .iter()
        .filter(|client| client.access_profiles.iter().any(|value| value == profile))
        .collect::<Vec<_>>();
    let exact = candidates
        .iter()
        .copied()
        .filter(|client| {
            client
                .test_bindings
                .iter()
                .any(|binding| binding.journey_id == journey_id && binding.step_id == step_id)
        })
        .collect::<Vec<_>>();
    if let [client] = exact.as_slice() {
        return Ok(*client);
    }
    let defaults = candidates
        .iter()
        .copied()
        .filter(|client| client.test_bindings.is_empty())
        .collect::<Vec<_>>();
    if exact.is_empty() {
        if let [client] = defaults.as_slice() {
            return Ok(*client);
        }
    }
    bail!(
        "journey step {step_id} of {journey_id} needs one unambiguous local client for access profile {profile}; add one default client or one exact testBindings entry"
    )
}

fn exact_journey_client<'a>(
    clients: &'a Clients,
    journey_id: &str,
    step_id: &str,
    profile: &str,
) -> Result<Option<&'a config::Client>> {
    let exact = clients
        .clients
        .iter()
        .filter(|client| client.access_profiles.iter().any(|value| value == profile))
        .filter(|client| {
            client
                .test_bindings
                .iter()
                .any(|binding| binding.journey_id == journey_id && binding.step_id == step_id)
        })
        .collect::<Vec<_>>();
    match exact.as_slice() {
        [] => Ok(None),
        [client] => Ok(Some(*client)),
        _ => bail!("journey step {step_id} of {journey_id} has ambiguous exact testBindings"),
    }
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
    if identity.environment != "local" {
        bail!("dev requires package.environment: local");
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
    let parent = parent_directory(&project)?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let root = parent.join("dev");
    let existing = if root.exists() {
        prepare_source::recover(&root)?;
        Some(read_state(&root)?)
    } else {
        None
    };
    if args.mint_port.is_some() || args.mint_bin.is_some() {
        bail!(
            "--mint-port and --mint-bin named the Mint-based issuer used by earlier dev sessions. \
            Use --issuer-port for a new owned dev issuer. A retained Mint session \
            must stay with its matching Mint-era tools until a verified migration \
            is available"
        );
    }
    let clients_file = clients_file(args.clients_file.as_deref(), existing.as_ref(), &project)?;
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
    bind_journey_profiles(&files["tests/journeys.yaml"], &clients)?;
    // The source pin protects the records a session retains. Once `dev stop
    // --remove` has discarded them, changed inputs start a fresh session on
    // the ports and clients file the previous one used.
    let mut previous = None;
    let existing = match existing {
        Some(state)
            if digest != state.source_digest
                || args.breg_port.is_some_and(|p| p != state.breg_port)
                || args.issuer_port.is_some_and(|p| p != state.issuer_port)
                || args
                    .issuer_image
                    .as_ref()
                    .is_some_and(|image| Some(image) != state.issuer_image.as_ref())
                || args.database_port.is_some_and(|p| p != state.database_port) =>
        {
            if state.container_id.is_some() {
                bail!("authored package, clients, ports or issuer image differ from the retained development session, which still holds records; run bregctl dev stop --remove to discard them and start again from the edited inputs, or copy the authored files to a new project directory to keep the records. Use the normal reviewed package lifecycle for an operated upgrade");
            }
            let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
            // A removed BREG database does not imply its separately owned
            // issuer state has been discarded. The explicit --remove path
            // clears both before a changed source can replace this directory.
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
            verify_outputs(&state)?;
            return state.report();
        }
        // A live owner lock is conclusive even when its control socket is not ready.
        let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
        state
    } else {
        let compiled = crate::compile(&project, crate::ProfileArg::Production, "dev")
            .map_err(|_| anyhow::anyhow!("project no longer compiles"))?;
        if compiled.package().context("package missing")?.sequence != 1 {
            bail!("first dev start requires package.sequence: 1");
        }
        let previous = previous.as_ref();
        let mut state = State {
            version: 2,
            project: project.clone(),
            owner: uuid::Uuid::new_v4().to_string(),
            status: Status::Stopped,
            breg_port: args
                .breg_port
                .or(previous.map(|s| s.breg_port))
                .unwrap_or(8090),
            issuer_port: args
                .issuer_port
                .or(previous.map(|s| s.issuer_port))
                .unwrap_or(8091),
            issuer_image: args
                .issuer_image
                .clone()
                .or_else(|| previous.and_then(|s| s.issuer_image.clone())),
            database_port: args
                .database_port
                .or(previous.map(|s| s.database_port))
                .unwrap_or(55432),
            requires_postgis: compiled.ddl().requires_postgis,
            webhook_port: None,
            clients_file,
            source_digest: digest,
            sequence: 1,
            baseline_runtime: None,
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
            failure: None,
        };
        ports(state.breg_port, state.issuer_port, state.database_port)?;
        for port in [state.breg_port, state.issuer_port, state.database_port] {
            probe(port)?;
        }
        if !compiled.event_deliveries().deliveries.is_empty() {
            state.webhook_port = Some(receiver_port(&state)?);
        }
        initialize(&root, &state, &clients, &files)?;
        read_state(&root)?
    };
    if state.sequence > 1 && state.container_id.is_none() {
        bail!("the retained successor database was explicitly removed; a successor package cannot initialize empty records. Create a fresh project with package.sequence: 1 before starting a new database");
    }
    prepare_receiver(&mut state, &clients)?;
    verify_outputs(&state)?;
    let breg = executable("breg", args.breg_bin.as_deref())?;
    let docker = executable("docker", args.docker_bin.as_deref())?;
    // Identify the prerequisites before the session stops a container or
    // launches the supervisor: a breg from another release has to be named
    // here, while the terminal that asked for the start is reading. The dev
    // issuer is the pinned upstream container; no token-issuer binary is
    // installed or version-locked anymore.
    state.binaries = BTreeMap::from([
        ("breg".into(), binary(&root, &breg)?),
        ("docker".into(), binary(&root, &docker)?),
    ]);
    matching_versions(&state.binaries)?;
    // A prior supervisor may have exited without reaching cleanup. Reclaim
    // only this session's issuer before testing whether its port is free.
    stop_issuer(&docker, &state)?;
    for port in [state.breg_port, state.issuer_port] {
        probe(port)?;
    }
    if let Some(port) = state.webhook_port {
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
    let log = log_file(&root, "supervisor")?;
    let mut supervisor = Command::new(std::env::current_exe()?)
        .arg("__dev-supervisor")
        .arg("--dev-root")
        .arg(&root)
        .arg("--breg-bin")
        .arg(breg)
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
            // Read once more: a supervisor that exited between this poll's
            // read and its own last save has the recorded cause on disk.
            let mut failed = read_state(&root)?;
            let cause = failed.failure.clone();
            failed.status = Status::Failed;
            failed.save()?;
            return Err(start_failure(cause.as_deref(), &root));
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
        config::prepare(&stage, original, clients)?;
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
    let docker = executable("docker", docker_bin)?;
    stop_issuer(&docker, &state)?;
    for port in [state.breg_port, state.issuer_port] {
        probe(port)?;
    }
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
    events::clear(&state.root())?;
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
        if let Some(port) = state.webhook_port {
            children.receiver = Some(events::Receiver::start(&root, port)?);
        }
        database(&args.docker_bin, &mut state)?;
        ensure_active(&terminate)?;
        // The dev issuer is the pinned upstream ThunderID container, owned by
        // this session through the shared tooling crate: setup, bootstrap
        // provisioning, serving, and readiness all live there, and its state
        // is retained across stop/start exactly like the registry's own.
        issuer(&args.docker_bin, &state, &clients)?;
        ensure_active(&terminate)?;
        if state.package_revision.is_none() {
            // The schema-test rehearsal presents these tokens to its own
            // disposable runtime; the seed below acquires its own.
            tokens(&state, &clients)?;
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
                    .arg(
                        state
                            .baseline_runtime
                            .clone()
                            .unwrap_or_else(|| root.join("runtime.yaml")),
                    )
                    .arg("--package")
                    .arg(root.join("build/package"));
                if state.sequence == 1 {
                    apply.arg("--initial");
                }
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
        tokens(&state, &clients)?;
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
    let issuer_cleanup = stop_issuer(&args.docker_bin, &state);
    let database_cleanup = stop_database(&args.docker_bin, &state);
    let socket_cleanup = remove_socket(&root);
    if result.is_err()
        || child_cleanup.is_err()
        || issuer_cleanup.is_err()
        || database_cleanup.is_err()
        || socket_cleanup.is_err()
    {
        state.status = Status::Failed;
        // Both supervisor streams go to a private log, so record the cause in
        // the state document the waiting terminal reads.
        state.failure = [
            result.as_ref().err(),
            child_cleanup.as_ref().err(),
            issuer_cleanup.as_ref().err(),
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
        issuer_cleanup?;
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
    receiver: Option<events::Receiver>,
}
impl Children {
    fn exited(&mut self) -> Result<bool> {
        if self.receiver.as_ref().is_some_and(events::Receiver::exited) {
            return Ok(true);
        }
        for child in [&mut self.breg].into_iter().flatten() {
            if child.try_wait()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn stop(&mut self) -> Result<()> {
        let mut error = None;
        for owned in [&mut self.breg] {
            if let Some(mut child) = owned.take() {
                if let Err(cause) = stop_child(&mut child) {
                    error = Some(cause);
                }
            }
        }
        // Stop the receiver only once BReg can no longer send deliveries.
        self.receiver.take();
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
/// Refuse a session whose BREG executable comes from another release. An older
/// BREG beside this bregctl fails deep inside a supervised phase, where the
/// cause reads as an unrelated refusal about the package or the database.
/// Docker and the source-pinned issuer belong to no BREG release comparison.
fn matching_versions(binaries: &BTreeMap<String, Binary>) -> Result<()> {
    let own = registry_platform_buildinfo::DISPLAY_VERSION;
    if let Some(prerequisite) = binaries.get("breg") {
        let Some(reported) = reported_version(prerequisite) else {
            return Ok(());
        };
        if reported != own {
            bail!(
                "the installed breg at {} reports version {reported}, and this bregctl reports version {own}. A local session runs breg and bregctl together, so install both from the same release, or put the matching build first on PATH",
                prerequisite.path.display()
            );
        }
    }
    Ok(())
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
    let deadline = Instant::now() + CHILD_DEADLINE;
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
/// Longest refusal carried out of a native child or out of the supervisor.
/// One named check is a sentence; a report that runs longer stays in the
/// retained log rather than filling the owner's terminal.
const MAX_REFUSAL: usize = 400;

/// Name the first failing check from the machine-readable report a native
/// command writes to stdout. The first diagnostic is the check an author
/// corrects first, and the retained report holds every later one. Output in
/// any other shape names nothing, so the caller keeps the logs pointer.
fn refused_check(report: &[u8]) -> Option<String> {
    let report: Value = serde_json::from_slice(report).ok()?;
    let first = report["diagnostics"].as_array()?.first()?;
    let named = format!(
        "{} at {}: {}",
        first["code"].as_str()?,
        first["path"].as_str()?,
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
    let (success, bytes) = output(command, root, name, input)?;
    if !success {
        let logs = root.join("logs").display().to_string();
        match refused_check(&bytes) {
            // The child named which check failed. Report it here: the schema
            // test runs inside the detached supervisor, so a refusal that
            // stays in the log never reaches the terminal that asked.
            Some(check) => bail!(
                "native {name} refused: {check}. The full report and owner-only diagnostics are in {logs}"
            ),
            None => bail!("native {name} failed; inspect owner-only diagnostics in {logs}"),
        }
    }
    Ok(bytes)
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
        || container["Config"]["Image"] != state.database_image()
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
                state.database_image(),
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
    let deadline = Instant::now() + READY_DEADLINE;
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
            if state.requires_postgis {
                statements.push_str(&spatial_prerequisites_sql());
            }
            sql(docker, state, database, statements.as_bytes(), None)?;
        }
        state.database_ready = true;
        state.save()?;
    }
    Ok(())
}
/// Same role boundary as the runtime spatial prerequisite contract: the
/// migration role may SET the no-login bbox owner; runtime is never a member.
fn spatial_prerequisites_sql() -> String {
    let bbox_role = format!("{RUNTIME_ROLE}__spatial_bbox");
    format!(
        "CREATE SCHEMA IF NOT EXISTS registry_spatial_ext; \
         REVOKE ALL ON SCHEMA registry_spatial_ext FROM PUBLIC; \
         CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA registry_spatial_ext; \
         GRANT USAGE ON SCHEMA registry_spatial_ext TO {MIGRATION_ROLE}, {RUNTIME_ROLE}; \
         DO $breg_spatial$ BEGIN \
         IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{bbox_role}') THEN \
         CREATE ROLE {bbox_role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; \
         END IF; END; $breg_spatial$; \
         GRANT {bbox_role} TO {MIGRATION_ROLE} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE; \
         GRANT USAGE ON SCHEMA registry_spatial_ext TO {bbox_role};"
    )
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

fn tokens(state: &State, clients: &Clients) -> Result<()> {
    for client in &clients.clients {
        token(state, &client.id)?;
    }
    Ok(())
}

/// One dev credential, acquired through the shared private-key-JWT provider
/// exactly as a relying client would: no token-issuer binary is spawned, the
/// assertion key never leaves the session's private credentials tree, and the
/// credential is stored owner-only for the seeding and rehearsal steps.
fn token(state: &State, id: &str) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot build the dev token runtime")?;
    runtime.block_on(token_async(state, id))
}

async fn token_async(state: &State, id: &str) -> Result<()> {
    use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};

    let root = state.root();
    let issuer = state.issuer_origin();
    let endpoint: url::Url = format!("{issuer}/oauth2/token")
        .parse()
        .context("the dev issuer token endpoint is invalid")?;
    let key_bytes = private::read(
        &root.join("credentials").join(id).join("assertion-key.jwk"),
        4096,
    )?;
    let key_text =
        String::from_utf8(key_bytes.to_vec()).context("the retained client key is unreadable")?;
    let key = registry_platform_crypto::PrivateJwk::parse(&key_text)
        .map_err(|_| anyhow::anyhow!("the retained client key is unusable"))?;
    let client: Clients =
        serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES)?)?;
    let scopes = client
        .clients
        .iter()
        .find(|client| client.id == id)
        .with_context(|| format!("the retained client {id} is not registered"))?
        .scopes
        .clone();
    let provider = PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(endpoint, id.to_owned(), key)
            // ThunderID v1.0.1 checks the assertion audience against the
            // issuer identifier, not the token endpoint.
            .with_audience(issuer.clone())
            .with_resource(state.audience())
            .with_scopes(scopes),
    )
    .map_err(|error| anyhow::anyhow!("the dev token provider is unusable: {error}"))?;
    let value = provider
        .bearer_token()
        .await
        .map_err(|error| anyhow::anyhow!("the dev issuer declined to issue a token: {error}"))?;
    let header = value.authorization_header_value();
    let text = header
        .to_str()
        .context("the issued credential is not header-safe")?
        .strip_prefix("Bearer ")
        .unwrap_or_default()
        .to_owned();
    if text.len() > 65536 || text.split('.').count() != 3 {
        bail!("the dev issuer returned an invalid compact token");
    }
    private::replace(
        &root.join("secrets").join(format!("{id}-token")),
        text.as_bytes(),
    )
}

/// Bring the session's issuer container up: one-time setup and bootstrap
/// provisioning against the rendered registration, then serving, then the
/// bounded discovery wait. The functional half of readiness is the token
/// acquisition above.
fn issuer(docker: &Path, state: &State, _clients: &Clients) -> Result<()> {
    let root = state.root();
    let pin = registry_thunderid_tooling::version::ThunderIdPin::load()?;
    let image = state.issuer_image.as_deref().unwrap_or(&pin.image);
    let state_root = root.join("issuer");
    let session = registry_thunderid_tooling::container::Session {
        label: &format!("breg-dev-{}", state.instance_id),
        id: &state.instance_id,
        port: state.issuer_port,
        state_root: &state_root,
        image,
    };
    let jwks = registry_thunderid_tooling::local::start(&session, docker, &mut || false)?;
    private::replace(
        &root.join("secrets/issuer-jwks"),
        &serde_json::to_vec(&jwks)?,
    )
}

fn stop_issuer(docker: &Path, state: &State) -> Result<()> {
    let state_root = state.root().join("issuer");
    if !state_root.join("session.json").exists() {
        return Ok(());
    }
    let pin = registry_thunderid_tooling::version::ThunderIdPin::load()?;
    let image = state.issuer_image.as_deref().unwrap_or(&pin.image);
    let session = registry_thunderid_tooling::container::Session {
        label: &format!("breg-dev-{}", state.instance_id),
        id: &state.instance_id,
        port: state.issuer_port,
        state_root: &state_root,
        image,
    };
    registry_thunderid_tooling::local::stop(&session, docker).map_err(Into::into)
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
    if state.requires_postgis {
        initialization.push_str(&spatial_prerequisites_sql());
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
            let journey_id = journey["id"].as_str().context("journey requires an id")?;
            let step_id = step["id"].as_str().context("journey step requires an id")?;
            let explicit = exact_journey_client(clients, journey_id, step_id, profile)?;
            let credential = if let Some(client) = explicit {
                json!({"type":"bearer","tokenRef":format!("secret:file/{}-token",client.id)})
            } else if step["claims"]
                .as_object()
                .is_some_and(|claims| claims.is_empty())
            {
                json!({"type":"anonymous"})
            } else {
                let client = journey_client(clients, journey_id, step_id, profile)?;
                json!({"type":"bearer","tokenRef":format!("secret:file/{}-token",client.id)})
            };
            bindings.push(json!({"journeyId":journey_id,"stepId":step_id,"credential":credential}));
        }
    }
    let credentials = json!({"apiVersion":"registry.registrystack.org/breg-schema-test-credentials/v1","kind":"SchemaTestCredentials","bindings":bindings});
    private::replace(
        &root.join("schema-test-credentials.yaml"),
        serde_norway::to_string(&credentials)?.as_bytes(),
    )?;
    clear_package_outputs(&root)?;
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
    if let Some(baseline) = &state.baseline_runtime {
        test.arg("--baseline-runtime-config").arg(baseline);
    }
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
    if let Some(baseline) = &state.baseline_runtime {
        package.arg("--baseline-runtime-config").arg(baseline);
    }
    let report: Value = serde_json::from_slice(&command(&mut package, &root, "package", None)?)?;
    let revision = report["packageRevision"]
        .as_str()
        .context("package report has no revision")?;
    config::runtime(&root, state, clients, revision, false)?;
    state.package_revision = Some(revision.into());
    state.save()
}

/// Clear only this journal's rebuild outputs, preserving predecessor packages.
/// The native schema-test receipt is a value-free public compiler artifact;
/// runtime configuration remains an owner-only deployment binding.
fn clear_package_outputs(root: &Path) -> Result<()> {
    private::check(root, true)?;
    let receipt = root.join("schema-test-receipt.json");
    match fs::symlink_metadata(&receipt) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                bail!(
                    "schema-test receipt must be an ordinary owned single-link compiler artifact"
                );
            }
            fs::remove_file(receipt)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let runtime = root.join("runtime.yaml");
    if runtime.exists() {
        private::check(&runtime, false)?;
        fs::remove_file(runtime)?;
    }
    if root.join("build").exists() {
        fs::remove_dir_all(root.join("build"))?;
    }
    Ok(())
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
    let deadline = Instant::now() + READY_DEADLINE;
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
