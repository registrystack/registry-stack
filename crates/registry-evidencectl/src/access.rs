//! Local access-policy and client authoring.
//!
//! Governed, reviewable policy and public client membership live under
//! `access/`. The only private client artifact is the locally generated key
//! under `.evidence/clients/<id>/private.jwk`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use registry_platform_crypto::{PrivateJwk, PublicJwk};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{authoring, dev, keygen};

const ACCESS_DIRECTORY: &str = "access";
const POLICIES_DIRECTORY: &str = "policies";
const CLIENTS_DIRECTORY: &str = "clients";
const PRIVATE_STATE_DIRECTORY: &str = ".evidence";
const PRIVATE_KEY_FILENAME: &str = "private.jwk";
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_POLICIES: usize = 128;
const MAX_QUESTIONS: usize = 128;
const MAX_CLIENTS: usize = 4_096;
const MAX_POLICIES_PER_CLIENT: usize = 32;
const PUBLIC_DIRECTORY_MODE: u32 = 0o755;
const PUBLIC_FILE_MODE: u32 = 0o644;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Define which authored questions a policy may request.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Register and revoke local Evidence Gateway clients.
    #[command(subcommand)]
    Client(ClientCommand),
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Add one governed access policy.
    Add(PolicyAddArgs),
    /// List governed access policies.
    List(ProjectArgs),
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Add one local client and generate its private key.
    Add(ClientAddArgs),
    /// List local clients and their policy membership.
    List(ProjectArgs),
    /// Revoke one local client.
    Revoke(ClientRevokeArgs),
}

#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

#[derive(Debug, Args)]
pub struct PolicyAddArgs {
    /// Lowercase policy identifier.
    policy: String,
    /// Authored question granted by this policy. Repeat for more than one.
    #[arg(long, required = true)]
    question: Vec<String>,
    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

#[derive(Debug, Args)]
pub struct ClientAddArgs {
    /// Lowercase client identifier.
    client: String,
    /// Access policy assigned to this client. Repeat for more than one.
    #[arg(long, required = true)]
    policy: Vec<String>,
    /// Generate an owner-only P-256 key for local client authentication.
    #[arg(long, required = true)]
    generate_local_key: bool,
    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

#[derive(Debug, Args)]
pub struct ClientRevokeArgs {
    /// Lowercase client identifier.
    client: String,
    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessPolicyDocument {
    version: u8,
    id: String,
    questions: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ClientStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientDocument {
    version: u8,
    client_id: String,
    status: ClientStatus,
    policies: Vec<String>,
    principal: String,
    evidence_audience: String,
    keys: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveClient {
    pub(crate) client_id: String,
    pub(crate) private_key_path: PathBuf,
    pub(crate) evidence_audience: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ActiveClientRegistration {
    pub(crate) client_id: String,
    pub(crate) registration: Value,
}

pub fn run(command: AccessCommand) -> Result<ExitCode> {
    match command {
        AccessCommand::Policy(PolicyCommand::Add(args)) => add_policy(&args),
        AccessCommand::Policy(PolicyCommand::List(args)) => list_policies(&args.project),
        AccessCommand::Client(ClientCommand::Add(args)) => add_client(&args),
        AccessCommand::Client(ClientCommand::List(args)) => list_clients(&args.project),
        AccessCommand::Client(ClientCommand::Revoke(args)) => revoke_client(&args),
    }
}

fn add_policy(args: &PolicyAddArgs) -> Result<ExitCode> {
    let project = canonical_project(&args.project)?;
    validate_identifier(&args.policy, "policy")?;
    let questions = sorted_unique(&args.question, "questions", MAX_QUESTIONS)?;
    for question in &questions {
        validate_identifier(question, "question")?;
    }
    let _lifecycle = dev::lock_project_lifecycle(&project)?;
    if dev::try_load_ready_state(&project)?.is_some() {
        bail!("stop the local development session before changing access policies");
    }
    for question in &questions {
        validate_authored_question(&project, question)?;
    }

    let directory = project.join(ACCESS_DIRECTORY).join(POLICIES_DIRECTORY);
    ensure_public_directory(&project.join(ACCESS_DIRECTORY))?;
    ensure_public_directory(&directory)?;
    if load_policy_documents_if_present(&project)?.len() >= MAX_POLICIES {
        bail!("a project may define at most {MAX_POLICIES} access policies");
    }
    let path = directory.join(format!("{}.yaml", args.policy));
    let document = AccessPolicyDocument {
        version: 1,
        id: args.policy.clone(),
        questions,
    };
    write_new_yaml_atomic(&path, &document, PUBLIC_FILE_MODE)?;
    println!(
        "Added access policy {} for {}.",
        document.id,
        document.questions.join(", ")
    );
    Ok(ExitCode::SUCCESS)
}

fn list_policies(project: &Path) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let policies = load_policy_documents_if_present(&project)?;
    if policies.is_empty() {
        println!("No access policies configured.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("POLICY\tQUESTIONS");
    for policy in policies.values() {
        println!("{}\t{}", policy.id, policy.questions.join(", "));
    }
    Ok(ExitCode::SUCCESS)
}

fn add_client(args: &ClientAddArgs) -> Result<ExitCode> {
    let project = canonical_project(&args.project)?;
    validate_identifier(&args.client, "client")?;
    if !args.generate_local_key {
        bail!("local client creation requires --generate-local-key");
    }
    let policy_ids = sorted_unique(&args.policy, "policies", MAX_POLICIES_PER_CLIENT)?;
    for policy_id in &policy_ids {
        validate_identifier(policy_id, "policy")?;
    }
    let _lifecycle = dev::lock_project_lifecycle(&project)?;
    let live = prepare_live_context(&project)?;
    let policies = load_policy_documents(&project)?;
    validate_client_policies(&policy_ids, &policies)?;
    let existing_clients = load_client_documents_if_present(&project)?;
    for existing in existing_clients.values() {
        validate_client_policies(&existing.policies, &policies)?;
    }
    if existing_clients.len() >= MAX_CLIENTS {
        bail!("a project may define at most {MAX_CLIENTS} clients");
    }

    let public_directory = project.join(ACCESS_DIRECTORY).join(CLIENTS_DIRECTORY);
    let private_directory = project
        .join(PRIVATE_STATE_DIRECTORY)
        .join(CLIENTS_DIRECTORY);
    ensure_public_directory(&project.join(ACCESS_DIRECTORY))?;
    ensure_public_directory(&public_directory)?;
    ensure_private_directory(&project.join(PRIVATE_STATE_DIRECTORY))?;
    ensure_private_directory(&private_directory)?;

    let public_path = public_directory.join(format!("{}.yaml", args.client));
    let private_client_path = private_directory.join(&args.client);
    reject_existing(&public_path)?;
    reject_existing(&private_client_path)?;

    let staging = tempfile::Builder::new()
        .prefix(".client-stage-")
        .tempdir_in(&private_directory)
        .context("creating private client staging directory")?;
    fs::set_permissions(
        staging.path(),
        fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
    )?;
    let public_key_path = staging.path().join("public.jwk");
    let (_, generated_public) =
        keygen::generate_dev_keypair(staging.path(), PRIVATE_KEY_FILENAME, "public.jwk")?;
    debug_assert_eq!(generated_public, public_key_path);
    let public_key = read_public_jwk(&public_key_path)?;
    fs::remove_file(&public_key_path).context("removing staged public-key copy")?;

    let document = ClientDocument {
        version: 1,
        client_id: args.client.clone(),
        status: ClientStatus::Active,
        policies: policy_ids,
        principal: format!("urn:registrystack:evidence:local:client:{}", args.client),
        evidence_audience: format!("urn:registrystack:evidence:local:client:{}", args.client),
        keys: vec![public_key],
    };

    // Publish the private directory first. The public document is the marker
    // that makes the client discoverable, and an unexpected public collision
    // rolls the newly published private directory back.
    fs::rename(staging.path(), &private_client_path)
        .context("publishing private local client key")?;
    if let Err(error) = write_new_yaml_atomic(&public_path, &document, PUBLIC_FILE_MODE) {
        let _ = fs::remove_dir_all(&private_client_path);
        return Err(error);
    }

    let reload_requested =
        if let Err(error) = synchronize_live_client(&project, &document, live.as_ref()) {
            return Err(
                error.context("client was saved, but the running local session was not reloaded")
            );
        } else {
            live.is_some()
        };
    println!(
        "Added client {} with {}.",
        document.client_id,
        joined_policies(&document.policies)
    );
    if reload_requested {
        println!("Registry Mint reload requested.");
    }
    Ok(ExitCode::SUCCESS)
}

fn list_clients(project: &Path) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let policies = load_policy_documents_if_present(&project)?;
    let clients = load_client_documents_if_present(&project)?;
    if clients.is_empty() {
        println!("No clients configured.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("CLIENT\tSTATUS\tPOLICIES");
    for client in clients.values() {
        validate_client_policies(&client.policies, &policies)?;
        let status = match client.status {
            ClientStatus::Active => "active",
            ClientStatus::Revoked => "revoked",
        };
        println!(
            "{}\t{}\t{}",
            client.client_id,
            status,
            client.policies.join(", ")
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn revoke_client(args: &ClientRevokeArgs) -> Result<ExitCode> {
    let project = canonical_project(&args.project)?;
    validate_identifier(&args.client, "client")?;
    let _lifecycle = dev::lock_project_lifecycle(&project)?;
    let live = prepare_live_context(&project)?;
    let policies = load_policy_documents(&project)?;
    let path = client_document_path(&project, &args.client);
    let mut document = read_client_document(&path)?;
    validate_client_policies(&document.policies, &policies)?;
    if document.status == ClientStatus::Revoked {
        bail!("client {} is already revoked", args.client);
    }
    if let Some(context) = &live {
        validate_path_mode(
            &context
                .generated_directory
                .join(format!("{}.yaml", document.client_id)),
            false,
            PRIVATE_FILE_MODE,
        )?;
    }
    document.status = ClientStatus::Revoked;
    replace_yaml_atomic(&path, &document, PUBLIC_FILE_MODE)?;
    let reload_requested =
        if let Err(error) = synchronize_live_revocation(&project, &document, live.as_ref()) {
            return Err(
                error.context("client was revoked, but the running local session was not reloaded")
            );
        } else {
            live.is_some()
        };
    println!("Revoked client {}.", document.client_id);
    if reload_requested {
        println!("Registry Mint reload requested.");
    }
    Ok(ExitCode::SUCCESS)
}

/// Resolve one client against the exact access-policy generation currently
/// active in local development.
pub(crate) fn resolve_ready_client(
    project: &Path,
    client_id: &str,
    policy_tags: &BTreeMap<String, String>,
) -> Result<ActiveClient> {
    validate_identifier(client_id, "client")?;
    let registration = load_active_clients(project, policy_tags)?
        .into_iter()
        .find(|registration| registration.client_id == client_id)
        .ok_or_else(|| anyhow::anyhow!("unknown or revoked active client {client_id}"))?;
    let project = canonical_project(project)?;
    let document = read_client_document(&client_document_path(&project, client_id))?;
    let private_key_path = validate_private_client_key(&project, &document)?;
    Ok(ActiveClient {
        client_id: registration.client_id,
        private_key_path,
        evidence_audience: document.evidence_audience,
    })
}

/// Load active editable clients as exact Mint registration documents.
pub(crate) fn load_active_clients(
    project: &Path,
    policy_tags: &BTreeMap<String, String>,
) -> Result<Vec<ActiveClientRegistration>> {
    let project = canonical_project(project)?;
    let policies = load_policy_documents_if_present(&project)?;
    if policy_tags.len() != policies.len() {
        bail!("compiled access policies do not match the editable project policies");
    }
    for policy in policies.values() {
        let expected = authoring::access_policy_requester_tag(&policy.id, &policy.questions)?;
        if policy_tags.get(&policy.id) != Some(&expected) {
            bail!(
                "editable access policy {} differs from the active generation",
                policy.id
            );
        }
    }
    let clients = load_client_documents_if_present(&project)?;
    let mut registrations = Vec::new();
    for document in clients.values() {
        validate_client_policies(&document.policies, &policies)?;
        if document.status == ClientStatus::Revoked {
            continue;
        }
        let requester_tags = document
            .policies
            .iter()
            .map(|id| {
                policy_tags
                    .get(id)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("client names an unknown compiled policy"))
            })
            .collect::<Result<Vec<_>>>()?;
        registrations.push(ActiveClientRegistration {
            client_id: document.client_id.clone(),
            registration: mint_registration(document, requester_tags),
        });
    }
    Ok(registrations)
}

fn mint_registration(document: &ClientDocument, requester_tags: Vec<String>) -> Value {
    json!({
        "clientId": document.client_id,
        "principal": document.principal,
        "evidenceAudience": document.evidence_audience,
        "requesterTags": requester_tags,
        "keys": document.keys,
    })
}

#[derive(Clone, Debug)]
struct LiveContext {
    policy_tags: BTreeMap<String, String>,
    generated_directory: PathBuf,
}

fn prepare_live_context(project: &Path) -> Result<Option<LiveContext>> {
    let Some(ready) = dev::try_load_ready_state(project)? else {
        return Ok(None);
    };
    if ready.access_policies.is_empty() {
        bail!(
            "the running local session uses the implicit tutorial caller; stop and restart it after defining access policies"
        );
    }
    let policy_tags = ready
        .access_policies
        .into_iter()
        .map(|policy| (policy.id, policy.requester_tag))
        .collect::<BTreeMap<_, _>>();
    // Validate the complete editable registry and exact policy generation
    // before a mutation publishes anything.
    load_active_clients(project, &policy_tags)?;
    let generated_directory = project.join(".evidence/dev/generated/clients");
    validate_path_mode(&generated_directory, true, PRIVATE_DIRECTORY_MODE)?;
    Ok(Some(LiveContext {
        policy_tags,
        generated_directory,
    }))
}

fn synchronize_live_client(
    project: &Path,
    document: &ClientDocument,
    live: Option<&LiveContext>,
) -> Result<()> {
    let Some(live) = live else {
        return Ok(());
    };
    let registration = load_active_clients(project, &live.policy_tags)?
        .into_iter()
        .find(|registration| registration.client_id == document.client_id)
        .ok_or_else(|| anyhow::anyhow!("new client is not active in the editable registry"))?;
    let generated_path = live
        .generated_directory
        .join(format!("{}.yaml", document.client_id));
    write_new_yaml_atomic(
        &generated_path,
        &registration.registration,
        PRIVATE_FILE_MODE,
    )?;
    dev::request_mint_reload(project)
}

fn synchronize_live_revocation(
    project: &Path,
    document: &ClientDocument,
    live: Option<&LiveContext>,
) -> Result<()> {
    let Some(live) = live else {
        return Ok(());
    };
    // The remaining registry must still be a valid all-or-nothing snapshot.
    load_active_clients(project, &live.policy_tags)?;
    let generated_path = live
        .generated_directory
        .join(format!("{}.yaml", document.client_id));
    validate_path_mode(&generated_path, false, PRIVATE_FILE_MODE)?;
    fs::remove_file(&generated_path)
        .with_context(|| format!("removing revoked registration {}", generated_path.display()))?;
    sync_directory(&live.generated_directory)?;
    dev::request_mint_reload(project)
}

fn validate_client_policies(
    policy_ids: &[String],
    policies: &BTreeMap<String, AccessPolicyDocument>,
) -> Result<()> {
    if policy_ids.is_empty() || policy_ids.len() > MAX_POLICIES_PER_CLIENT {
        bail!("a client must have 1..={MAX_POLICIES_PER_CLIENT} policies");
    }
    let mut covered_questions = BTreeMap::<&str, &str>::new();
    for policy_id in policy_ids {
        validate_identifier(policy_id, "policy")?;
        let policy = policies
            .get(policy_id)
            .ok_or_else(|| anyhow::anyhow!("unknown access policy {policy_id}"))?;
        for question in &policy.questions {
            if let Some(existing) = covered_questions.insert(question, policy_id) {
                bail!(
                    "policies {existing} and {policy_id} grant the same authored entitlement for question {question}"
                );
            }
        }
    }
    Ok(())
}

fn load_policy_documents(project: &Path) -> Result<BTreeMap<String, AccessPolicyDocument>> {
    let policies = load_policy_documents_if_present(project)?;
    if policies.is_empty() {
        bail!("no access policies are configured");
    }
    Ok(policies)
}

fn load_policy_documents_if_present(
    project: &Path,
) -> Result<BTreeMap<String, AccessPolicyDocument>> {
    validate_optional_access_root(project)?;
    let directory = project.join(ACCESS_DIRECTORY).join(POLICIES_DIRECTORY);
    let paths = yaml_paths_if_present(&directory, MAX_POLICIES, "access policies")?;
    let mut policies = BTreeMap::new();
    for path in paths {
        let mut document: AccessPolicyDocument = read_yaml(&path, PUBLIC_FILE_MODE)?;
        if document.version != 1 {
            bail!("access policy version must be 1");
        }
        validate_identifier(&document.id, "policy")?;
        validate_filename_id(&path, &document.id, "access policy")?;
        document.questions =
            canonical_sorted_unique(&document.questions, "questions", MAX_QUESTIONS)?;
        for question in &document.questions {
            validate_identifier(question, "question")?;
            validate_authored_question(project, question)?;
        }
        if policies.insert(document.id.clone(), document).is_some() {
            bail!("access policy ids must be unique");
        }
    }
    Ok(policies)
}

fn load_client_documents_if_present(project: &Path) -> Result<BTreeMap<String, ClientDocument>> {
    validate_optional_access_root(project)?;
    let directory = project.join(ACCESS_DIRECTORY).join(CLIENTS_DIRECTORY);
    let paths = yaml_paths_if_present(&directory, MAX_CLIENTS, "clients")?;
    let mut clients = BTreeMap::new();
    for path in paths {
        let document = read_client_document(&path)?;
        if clients
            .insert(document.client_id.clone(), document)
            .is_some()
        {
            bail!("client ids must be unique");
        }
    }
    Ok(clients)
}

fn read_client_document(path: &Path) -> Result<ClientDocument> {
    let mut document: ClientDocument = read_yaml(path, PUBLIC_FILE_MODE)?;
    if document.version != 1 {
        bail!("client document version must be 1");
    }
    validate_identifier(&document.client_id, "client")?;
    validate_filename_id(path, &document.client_id, "client")?;
    document.policies =
        canonical_sorted_unique(&document.policies, "policies", MAX_POLICIES_PER_CLIENT)?;
    if document.principal != local_client_uri(&document.client_id)
        || document.evidence_audience != local_client_uri(&document.client_id)
    {
        bail!("local client principal and evidence audience must match its client id");
    }
    if document.keys.len() != 1 {
        bail!("a local client must contain exactly one public key");
    }
    for key in &document.keys {
        if key.get("d").is_some() {
            bail!("client documents must never contain private key material");
        }
        let text = serde_json::to_string(key).context("rendering client public key")?;
        PublicJwk::parse(&text).context("client public JWK is invalid")?;
    }
    Ok(document)
}

fn validate_private_client_key(project: &Path, document: &ClientDocument) -> Result<PathBuf> {
    let private_root = project.join(PRIVATE_STATE_DIRECTORY);
    let clients_root = private_root.join(CLIENTS_DIRECTORY);
    let directory = clients_root.join(&document.client_id);
    validate_path_mode(&private_root, true, PRIVATE_DIRECTORY_MODE)?;
    validate_path_mode(&clients_root, true, PRIVATE_DIRECTORY_MODE)?;
    validate_path_mode(&directory, true, PRIVATE_DIRECTORY_MODE)?;
    let path = directory.join(PRIVATE_KEY_FILENAME);
    let text = read_bounded_file(&path, MAX_DOCUMENT_BYTES, Some(PRIVATE_FILE_MODE))?;
    let private = PrivateJwk::parse(&text).context("local client private JWK is invalid")?;
    let registered_text = serde_json::to_string(&document.keys[0])
        .context("rendering registered client public JWK")?;
    let registered =
        PublicJwk::parse(&registered_text).context("registered client public JWK is invalid")?;
    if private
        .public()
        .jkt()
        .context("deriving private-key thumbprint")?
        != registered
            .jkt()
            .context("deriving registered-key thumbprint")?
    {
        bail!("local client private key does not match its registered public key");
    }
    Ok(path)
}

fn read_public_jwk(path: &Path) -> Result<Value> {
    let text = read_bounded_file(path, MAX_DOCUMENT_BYTES, Some(PRIVATE_FILE_MODE))?;
    PublicJwk::parse(&text).context("generated public JWK is invalid")?;
    let value: Value = serde_json::from_str(&text).context("parsing generated public JWK")?;
    if value.get("d").is_some() {
        bail!("generated public JWK unexpectedly contains private material");
    }
    Ok(value)
}

fn validate_authored_question(project: &Path, question_id: &str) -> Result<()> {
    let directory = project.join("questions");
    validate_visible_directory(&directory, "questions")?;
    let path = directory.join(format!("{question_id}.yaml"));
    let value: Value = read_yaml_any_mode(&path)?;
    if value.get("id").and_then(Value::as_str) != Some(question_id) {
        bail!("question id must match its questions/<id>.yaml filename");
    }
    Ok(())
}

fn yaml_paths_if_present(directory: &Path, maximum: usize, label: &str) -> Result<Vec<PathBuf>> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("inspecting {label}")),
    };
    let parent = directory
        .parent()
        .context("access directory has no parent")?;
    validate_path_mode(parent, true, PUBLIC_DIRECTORY_MODE)?;
    validate_path_mode(directory, true, PUBLIC_DIRECTORY_MODE)?;
    let mut paths = fs::read_dir(directory)
        .with_context(|| format!("reading {label}"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    if paths.len() > maximum {
        bail!("too many {label}; maximum is {maximum}");
    }
    if paths
        .iter()
        .any(|path| path.extension().and_then(|value| value.to_str()) != Some("yaml"))
    {
        bail!("{label} may contain only <id>.yaml files");
    }
    Ok(paths)
}

fn validate_optional_access_root(project: &Path) -> Result<()> {
    let path = project.join(ACCESS_DIRECTORY);
    match fs::symlink_metadata(&path) {
        Ok(_) => validate_path_mode(&path, true, PUBLIC_DIRECTORY_MODE),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_visible_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("{label} must be held in a plain owner-controlled directory");
    }
    Ok(())
}

fn read_yaml<T: for<'de> Deserialize<'de>>(path: &Path, mode: u32) -> Result<T> {
    let text = read_bounded_file(path, MAX_DOCUMENT_BYTES, Some(mode))?;
    serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn read_yaml_any_mode(path: &Path) -> Result<Value> {
    let text = read_bounded_file(path, MAX_DOCUMENT_BYTES, None)?;
    serde_norway::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn read_bounded_file(path: &Path, maximum: u64, required_mode: Option<u32>) -> Result<String> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {} without following symlinks", path.display()))?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting open file {}", path.display()))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() > maximum
        || required_mode.is_some_and(|mode| metadata.permissions().mode() & 0o7777 != mode)
    {
        bail!(
            "{} is not a bounded owner-controlled regular file",
            path.display()
        );
    }
    let mut text = String::new();
    file.take(maximum + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    if text.len() as u64 > maximum {
        bail!("{} is too large", path.display());
    }
    Ok(text)
}

fn write_new_yaml_atomic<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    reject_existing(path)?;
    let bytes = serde_norway::to_string(value).context("rendering access document")?;
    let parent = path.parent().context("access document has no parent")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".access-write-")
        .tempfile_in(parent)
        .context("creating temporary access document")?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing {} without overwrite", path.display()))?;
    sync_directory(parent)?;
    Ok(())
}

fn replace_yaml_atomic<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    validate_path_mode(path, false, mode)?;
    let bytes = serde_norway::to_string(value).context("rendering access document")?;
    let parent = path.parent().context("access document has no parent")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".access-write-")
        .tempfile_in(parent)
        .context("creating temporary access document")?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn ensure_public_directory(path: &Path) -> Result<()> {
    ensure_directory(path, PUBLIC_DIRECTORY_MODE)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    ensure_directory(path, PRIVATE_DIRECTORY_MODE)
}

fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_path_mode(path, true, mode),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(mode)
                .create(path)
                .with_context(|| format!("creating {}", path.display()))?;
            validate_path_mode(path, true, mode)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_path_mode(path: &Path, directory: bool, mode: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != mode
    {
        bail!(
            "{} must be a plain owner-controlled {} with mode {mode:04o}",
            path.display(),
            if directory { "directory" } else { "file" }
        );
    }
    Ok(())
}

fn reject_existing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("refusing to overwrite existing {}", path.display()),
        Err(error) => Err(error.into()),
    }
}

fn validate_filename_id(path: &Path, id: &str, label: &str) -> Result<()> {
    if path.file_stem().and_then(|value| value.to_str()) != Some(id) {
        bail!("{label} id must match its <id>.yaml filename");
    }
    Ok(())
}

fn sorted_unique(values: &[String], label: &str, maximum: usize) -> Result<Vec<String>> {
    if values.is_empty() || values.len() > maximum {
        bail!("{label} must contain 1..={maximum} values");
    }
    let sorted = values.iter().cloned().collect::<BTreeSet<_>>();
    if sorted.len() != values.len() {
        bail!("{label} must be unique");
    }
    Ok(sorted.into_iter().collect())
}

fn canonical_sorted_unique(values: &[String], label: &str, maximum: usize) -> Result<Vec<String>> {
    let sorted = sorted_unique(values, label, maximum)?;
    if sorted != values {
        bail!("{label} must be sorted in canonical order");
    }
    Ok(sorted)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if !matches!(bytes.first(), Some(b'a'..=b'z'))
        || bytes.len() > 64
        || bytes[1..].iter().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        bail!("{label} id must be a lowercase local identifier (maximum 64 bytes)");
    }
    Ok(())
}

fn canonical_project(path: &Path) -> Result<PathBuf> {
    let project = fs::canonicalize(path)
        .with_context(|| format!("resolving project root {}", path.display()))?;
    let metadata = fs::symlink_metadata(&project)?;
    if !metadata.is_dir() {
        bail!("project root must be a directory");
    }
    Ok(project)
}

fn client_document_path(project: &Path, client_id: &str) -> PathBuf {
    project
        .join(ACCESS_DIRECTORY)
        .join(CLIENTS_DIRECTORY)
        .join(format!("{client_id}.yaml"))
}

fn local_client_uri(client_id: &str) -> String {
    format!("urn:registrystack:evidence:local:client:{client_id}")
}

fn joined_policies(policies: &[String]) -> String {
    if policies.len() == 1 {
        format!("policy {}", policies[0])
    } else {
        format!("policies {}", policies.join(", "))
    }
}
