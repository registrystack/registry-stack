//! Governed target access profiles and local client credentials.
//!
//! Complete access profiles live in the target authority document. Public client
//! membership lives under `access/clients/`. The only private client artifact is the locally generated key
//! under `.evidence/clients/<id>/private.jwk`; revoking a client removes that
//! directory so no private state outlives the client it authenticated.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::{Args, Subcommand};
use registry_evidence_authoring::formats::{
    decode_authored, envelope_lines, ACCESS_CLIENT, ACCESS_CLIENT_API_VERSION, ACCESS_CLIENT_KIND,
};
use registry_evidence_authoring::{project::ActorKind, target::AccessProfile};
use registry_platform_crypto::{PrivateJwk, PublicJwk};
use registry_platform_yaml::{Decoded, Report, Severity, MAXIMUM_DOCUMENT_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{authoring, dev, keygen, OutputFormat};

const ACCESS_DIRECTORY: &str = "access";
const CLIENTS_DIRECTORY: &str = "clients";
const PRIVATE_STATE_DIRECTORY: &str = ".evidence";
const PRIVATE_KEY_FILENAME: &str = "private.jwk";
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_CLIENTS: usize = 4_096;
const MAX_PROFILES_PER_CLIENT: usize = 32;
const PUBLIC_DIRECTORY_MODE: u32 = 0o755;
const PUBLIC_FILE_MODE: u32 = 0o644;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Inspect complete access profiles from the target authority.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Register and revoke local Evidence Gateway clients.
    #[command(subcommand)]
    Client(Box<ClientCommand>),
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List governed target access profiles.
    List(ProjectArgs),
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Add one local client and generate its private key.
    Add(ClientAddArgs),
    /// List local clients and their access-profile membership.
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
pub struct ClientAddArgs {
    /// Lowercase client identifier.
    client: String,
    /// Existing target access profile assigned to this client. Repeat for disjoint grants.
    #[arg(long, required = true)]
    access_profile: Vec<String>,
    /// Audience inside every selected definition ceiling. Inferred when exactly one fits.
    #[arg(long)]
    evidence_audience: Option<String>,
    /// Actor permitted by the selected profiles. Inferred when exactly one fits.
    #[arg(long, value_parser = ["human", "agent", "service"])]
    actor_kind: Option<String>,
    /// Generate an owner-only P-256 key for local client authentication.
    #[arg(long, required = true)]
    generate_local_key: bool,
    /// Use institutional task exchange with this one bootstrap scope.
    #[arg(long)]
    grant_bootstrap_scope: Option<String>,
    /// Bootstrap resource audience. Omit to use the shared issuer owner's default.
    #[arg(long, requires = "grant_bootstrap_scope")]
    grant_bootstrap_resource: Option<String>,
    /// Use a signed first-party context with this one bootstrap scope.
    #[arg(
        long,
        conflicts_with = "grant_bootstrap_scope",
        requires_all = ["first_party_bootstrap_resource", "first_party_issuer"]
    )]
    first_party_bootstrap_scope: Option<String>,
    /// Exact resource for the first-party bootstrap credential.
    #[arg(long, requires = "first_party_bootstrap_scope")]
    first_party_bootstrap_resource: Option<String>,
    /// Exact trusted issuer of the signed first-party context.
    #[arg(long, requires = "first_party_bootstrap_scope")]
    first_party_issuer: Option<String>,
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

/// The derived JSON Schema of one local access client document.
#[cfg(feature = "schema")]
pub(crate) fn client_document_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ClientDocument)).expect("a derived schema is JSON")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct TaskGrantBinding {
    pub(crate) requester_clients: Vec<String>,
    pub(crate) source_issuer: registry_platform_yaml::Url,
}

struct LoadedProfile {
    profile: AccessProfile,
    digest: String,
    audiences: BTreeSet<String>,
    actors: BTreeSet<String>,
}

pub(crate) fn profile_digest(profile: &Value) -> Result<String> {
    let bytes = registry_platform_crypto::canonicalize_json(profile)
        .context("canonicalizing the complete access profile")?;
    Ok(registry_platform_config::sha256_uri(&bytes))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
enum ClientStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientDocument {
    client_id: String,
    status: ClientStatus,
    access_profiles: Vec<String>,
    principal: String,
    evidence_audience: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_kind: Option<ActorKind>,
    keys: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exchange: Option<ActiveClientExchange>,
}

/// Local issuer wiring for a client whose Evidence authority comes from a task
/// assertion. This does not grant access or change the governed task profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActiveClientExchange {
    pub(crate) kind: ActiveClientExchangeKind,
    pub(crate) bootstrap_scope: String,
    /// None means the issuer owner's default resource, not the Evidence resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) bootstrap_resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source_issuer: Option<registry_platform_yaml::Url>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ActiveClientExchangeKind {
    InstitutionalGrant,
    FirstParty,
}

impl ActiveClientExchange {
    fn validate(&self) -> Result<()> {
        if self.bootstrap_scope.is_empty()
            || self.bootstrap_scope.len() > 128
            || !self
                .bootstrap_scope
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            bail!("grant bootstrap scope must be one bounded OAuth scope token");
        }
        if self.bootstrap_resource.as_ref().is_some_and(|resource| {
            resource.len() > 512 || !authoring::valid_local_audience(resource)
        }) {
            bail!("grant bootstrap resource must be a bounded resource URI");
        }
        match self.kind {
            ActiveClientExchangeKind::InstitutionalGrant if self.source_issuer.is_some() => {
                bail!("institutional grant issuer comes from its governed task profile")
            }
            ActiveClientExchangeKind::FirstParty
                if self.bootstrap_resource.is_none()
                    || self.source_issuer.as_ref().is_none_or(|issuer| {
                        issuer.len() > 512 || !authoring::valid_local_audience(issuer)
                    }) =>
            {
                bail!("first-party exchange needs exact bootstrap resource and source issuer")
            }
            _ => {}
        }
        Ok(())
    }
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
    pub(crate) public_jwks: String,
    pub(crate) requester_tags: Vec<String>,
    pub(crate) actor_kind: String,
    pub(crate) evidence_audience: String,
    pub(crate) exchange: Option<ActiveClientExchange>,
}

pub fn run(command: AccessCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        AccessCommand::Profile(ProfileCommand::List(args)) => {
            list_access_profiles(&args.project, format)
        }
        AccessCommand::Client(command) => match *command {
            ClientCommand::Add(args) => add_client(&args, format),
            ClientCommand::List(args) => list_clients(&args.project, format),
            ClientCommand::Revoke(args) => revoke_client(&args, format),
        },
    }
}

/// The project-relative spelling of one client's private state directory.
fn private_client_directory(client_id: &str) -> String {
    format!("{PRIVATE_STATE_DIRECTORY}/{CLIENTS_DIRECTORY}/{client_id}")
}

fn list_access_profiles(project: &Path, format: OutputFormat) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let profiles = load_access_profiles(&project)?;
    if format == OutputFormat::Human {
        println!("PROFILE\tACTOR\tDEFINITIONS");
        for (id, loaded) in &profiles {
            let definitions = loaded
                .profile
                .grants
                .iter()
                .map(|grant| grant.definition.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{id}\t{}\t{definitions}",
                loaded
                    .profile
                    .actor_kind
                    .as_ref()
                    .map_or("definition ceilings", |actor| actor.as_str())
            );
        }
    } else {
        crate::print_report(&crate::command_report(
            "access profile list",
            json!({"entries": profiles.iter()
            .map(|(id, loaded)| json!({"id":id,"actorKind":loaded.profile.actor_kind,
                "definitions":loaded.profile.grants.iter().map(|grant| &grant.definition).collect::<BTreeSet<_>>(),
                "digest":loaded.digest})).collect::<Vec<_>>()}),
        ));
    }
    Ok(ExitCode::SUCCESS)
}

fn add_client(args: &ClientAddArgs, format: OutputFormat) -> Result<ExitCode> {
    let actor_kind: Option<ActorKind> = args
        .actor_kind
        .as_ref()
        .map(|actor| serde_json::from_value(json!(actor)))
        .transpose()
        .context("client actor kind must be human, agent or service")?;
    let project = canonical_project(&args.project)?;
    validate_identifier(&args.client, "client")?;
    if !args.generate_local_key {
        bail!("local client creation requires --generate-local-key");
    }
    let exchange = if let Some(scope) = &args.grant_bootstrap_scope {
        Some(ActiveClientExchange {
            kind: ActiveClientExchangeKind::InstitutionalGrant,
            bootstrap_scope: scope.clone(),
            bootstrap_resource: args.grant_bootstrap_resource.clone(),
            source_issuer: None,
        })
    } else {
        args.first_party_bootstrap_scope
            .as_ref()
            .map(|scope| {
                let source_issuer = args
                    .first_party_issuer
                    .as_ref()
                    .map(|issuer| registry_platform_yaml::Url::new(issuer.clone()))
                    .transpose()
                    .map_err(|_| {
                        anyhow!("first-party issuer must be an absolute http or https URL")
                    })?;
                Ok::<_, anyhow::Error>(ActiveClientExchange {
                    kind: ActiveClientExchangeKind::FirstParty,
                    bootstrap_scope: scope.clone(),
                    bootstrap_resource: args.first_party_bootstrap_resource.clone(),
                    source_issuer,
                })
            })
            .transpose()?
    };
    if let Some(exchange) = &exchange {
        exchange.validate()?;
    }
    let profile_ids = sorted_unique(
        &args.access_profile,
        "access profiles",
        MAX_PROFILES_PER_CLIENT,
    )?;
    for profile_id in &profile_ids {
        validate_identifier(profile_id, "access profile")?;
    }
    let _lifecycle = dev::lock_project_lifecycle(&project)?;
    require_stopped_or_absent_session(&project)?;
    let access_profiles = load_access_profiles(&project)?;
    validate_client_profiles(&profile_ids, &access_profiles)?;
    let allowed_audiences = profile_audiences(&profile_ids, &access_profiles)?;
    let evidence_audience = match &args.evidence_audience {
        Some(audience) if allowed_audiences.contains(audience) => audience.clone(),
        Some(_) => bail!("--evidence-audience must be inside every selected definition ceiling"),
        None if allowed_audiences.len() == 1 => {
            allowed_audiences.first().expect("one audience").clone()
        }
        None => bail!(
            "choose --evidence-audience from the selected definitions' common audience ceiling"
        ),
    };
    validate_client_identity(
        &ClientDocument {
            client_id: args.client.clone(),
            status: ClientStatus::Active,
            access_profiles: profile_ids.clone(),
            principal: local_client_uri(&args.client),
            evidence_audience: evidence_audience.clone(),
            actor_kind,
            keys: Vec::new(),
            exchange: exchange.clone(),
        },
        &access_profiles,
    )?;
    let existing_clients = load_client_documents_if_present(&project)?;
    for existing in existing_clients.values() {
        validate_client_profiles(&existing.access_profiles, &access_profiles)?;
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
        client_id: args.client.clone(),
        status: ClientStatus::Active,
        access_profiles: profile_ids,
        principal: format!("urn:registrystack:evidence:local:client:{}", args.client),
        evidence_audience,
        actor_kind,
        keys: vec![public_key],
        exchange,
    };

    // Publish the private directory first. The public document is the marker
    // that makes the client discoverable, and an unexpected public collision
    // rolls the newly published private directory back.
    fs::rename(staging.path(), &private_client_path)
        .context("publishing private local client key")?;
    if let Err(error) = write_new_yaml_atomic(
        &public_path,
        &envelope_lines(ACCESS_CLIENT_API_VERSION, ACCESS_CLIENT_KIND),
        &document,
        PUBLIC_FILE_MODE,
    ) {
        let _ = fs::remove_dir_all(&private_client_path);
        return Err(error);
    }

    match format {
        OutputFormat::Human => println!(
            "Added client {} with {}.",
            document.client_id,
            joined_profiles(&document.access_profiles)
        ),
        OutputFormat::Json => {
            let kid = document.keys[0]
                .get("kid")
                .and_then(Value::as_str)
                .context("generated client public key carries no kid")?;
            crate::print_report(&crate::command_report(
                "access client add",
                json!({
                    "client": document.client_id,
                    "accessProfiles": document.access_profiles,
                    "kid": kid,
                    "files": [
                        private_client_path.join(PRIVATE_KEY_FILENAME).display().to_string(),
                        public_path.display().to_string(),
                    ],
                }),
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn list_clients(project: &Path, format: OutputFormat) -> Result<ExitCode> {
    let project = canonical_project(project)?;
    let clients = load_client_documents_if_present(&project)?;
    if clients.is_empty() {
        match format {
            OutputFormat::Human => println!("No clients configured."),
            OutputFormat::Json => crate::print_report(&crate::command_report(
                "access client list",
                json!({"entries": []}),
            )),
        }
        return Ok(ExitCode::SUCCESS);
    }
    let access_profiles = load_access_profiles(&project)?;
    if format == OutputFormat::Human {
        println!("CLIENT\tSTATUS\tACCESS PROFILES");
        for client in clients.values() {
            validate_client_profiles(&client.access_profiles, &access_profiles)?;
            let status = match client.status {
                ClientStatus::Active => "active",
                ClientStatus::Revoked => "revoked",
            };
            println!(
                "{}\t{}\t{}",
                client.client_id,
                status,
                client.access_profiles.join(", ")
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut entries = Vec::with_capacity(clients.len());
    for client in clients.values() {
        validate_client_profiles(&client.access_profiles, &access_profiles)?;
        let status = match client.status {
            ClientStatus::Active => "active",
            ClientStatus::Revoked => "revoked",
        };
        entries.push(json!({
            "id": client.client_id,
            "status": status,
            "accessProfiles": client.access_profiles,
        }));
    }
    crate::print_report(&crate::command_report(
        "access client list",
        json!({"entries": entries}),
    ));
    Ok(ExitCode::SUCCESS)
}

fn revoke_client(args: &ClientRevokeArgs, format: OutputFormat) -> Result<ExitCode> {
    let project = canonical_project(&args.project)?;
    validate_identifier(&args.client, "client")?;
    let _lifecycle = dev::lock_project_lifecycle(&project)?;
    require_stopped_or_absent_session(&project)?;
    let path = client_document_path(&project, &args.client);
    let mut document = read_client_document(&path)?;
    if document.status == ClientStatus::Revoked {
        bail!("client {} is already revoked", args.client);
    }
    // Nothing consumes a revoked client's private state, and re-adding the
    // same id is refused while its directory exists, so revocation removes
    // the directory rather than retaining key material no client can use.
    // A client admitted without a local key has no directory to remove. The
    // directory is removed before the record is marked revoked: if removal
    // fails, the record is left untouched and a rerun retries the removal.
    let private_directory = project
        .join(PRIVATE_STATE_DIRECTORY)
        .join(CLIENTS_DIRECTORY)
        .join(&args.client);
    let removed = match fs::symlink_metadata(&private_directory) {
        Ok(_) => {
            fs::remove_dir_all(&private_directory).with_context(|| {
                format!(
                    "removing revoked client state {}",
                    private_directory.display()
                )
            })?;
            Some(private_client_directory(&args.client))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting revoked client state {}",
                    private_directory.display()
                )
            })
        }
    };
    document.status = ClientStatus::Revoked;
    replace_yaml_atomic(
        &path,
        &envelope_lines(ACCESS_CLIENT_API_VERSION, ACCESS_CLIENT_KIND),
        &document,
        PUBLIC_FILE_MODE,
    )?;
    match format {
        OutputFormat::Human => match &removed {
            Some(removed) => println!(
                "Revoked client {} (removed local private key {removed}).",
                document.client_id
            ),
            None => println!("Revoked client {}.", document.client_id),
        },
        OutputFormat::Json => crate::print_report(&crate::command_report(
            "access client revoke",
            json!({
                "client": document.client_id,
                "removed": removed,
            }),
        )),
    }
    Ok(ExitCode::SUCCESS)
}

/// Resolve one client against the exact access-profile generation currently
/// active in local development.
pub(crate) fn resolve_ready_client(
    project: &Path,
    client_id: &str,
    profile_digests: &BTreeMap<String, String>,
) -> Result<ActiveClient> {
    validate_identifier(client_id, "client")?;
    let registration = load_active_clients(project, profile_digests)?
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

/// The exact client identifiers an active editable project registers, read
/// without a compiled generation. A local session needs them before it
/// compiles, to state in the bundle which clients that bundle admits.
pub(crate) fn active_client_ids(project: &Path) -> Result<Vec<String>> {
    let project = canonical_project(project)?;
    let access_profiles = load_access_profiles(&project)?;
    let mut ids = Vec::new();
    for document in load_client_documents_if_present(&project)?.values() {
        validate_client_profiles(&document.access_profiles, &access_profiles)?;
        validate_client_identity(document, &access_profiles)?;
        if document.status == ClientStatus::Revoked {
            continue;
        }
        ids.push(document.client_id.clone());
    }
    Ok(ids)
}

/// Load active editable clients as exact local issuer registrations.
pub(crate) fn load_active_clients(
    project: &Path,
    profile_digests: &BTreeMap<String, String>,
) -> Result<Vec<ActiveClientRegistration>> {
    let project = canonical_project(project)?;
    let profiles = load_access_profiles(&project)?;
    if profile_digests.len() != profiles.len()
        || profiles
            .iter()
            .any(|(id, profile)| profile_digests.get(id) != Some(&profile.digest))
    {
        bail!("target access profiles differ from the active generation; stop and restart the session");
    }
    let mut registrations = Vec::new();
    for document in load_client_documents_if_present(&project)?.values() {
        validate_client_profiles(&document.access_profiles, &profiles)?;
        validate_client_identity(document, &profiles)?;
        if document.status == ClientStatus::Revoked {
            continue;
        }
        let requester_tags = document
            .access_profiles
            .iter()
            .flat_map(|id| profiles[id].profile.requester_tags.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        registrations.push(ActiveClientRegistration {
            client_id: document.client_id.clone(),
            public_jwks: serde_json::to_string(&json!({"keys":document.keys}))?,
            requester_tags,
            actor_kind: resolved_client_actor(document, &profiles)?,
            evidence_audience: document.evidence_audience.clone(),
            exchange: document.exchange.clone(),
        });
    }
    Ok(registrations)
}

/// Public, editable client admission for local bundle compilation. Private
/// keys are checked separately when `dev` registers the issuer generation.
pub(crate) fn service_caller_profiles(project: &Path) -> Result<BTreeSet<String>> {
    Ok(load_access_profiles(project)?
        .into_iter()
        .filter_map(|(id, profile)| profile.actors.contains("service").then_some(id))
        .collect())
}

pub(crate) fn generated_caller_audience(project: &Path, profile: &str) -> Result<String> {
    let profiles = load_access_profiles(project)?;
    let allowed = profile_audiences(&[profile.to_owned()], &profiles)?;
    if allowed.len() != 1 {
        bail!("profile {profile} has multiple audiences; register an access client with --evidence-audience before dev start");
    }
    Ok(allowed.first().expect("one audience").clone())
}

fn require_stopped_or_absent_session(project: &Path) -> Result<()> {
    if dev::try_load_ready_state(project)?.is_some() {
        bail!("stop the local development session before changing clients; the next start reprovisions the complete issuer registration");
    }
    Ok(())
}

fn validate_client_profiles(
    ids: &[String],
    profiles: &BTreeMap<String, LoadedProfile>,
) -> Result<()> {
    if ids.is_empty() || ids.len() > MAX_PROFILES_PER_CLIENT {
        bail!("a client must reference 1..={MAX_PROFILES_PER_CLIENT} access profiles");
    }
    let mut shapes = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut actors: Option<BTreeSet<String>> = None;
    for id in ids {
        validate_identifier(id, "access profile")?;
        let loaded = profiles
            .get(id)
            .with_context(|| format!("unknown target access profile {id}"))?;
        actors = Some(match actors {
            None => loaded.actors.clone(),
            Some(current) => current.intersection(&loaded.actors).cloned().collect(),
        });
        tags.extend(loaded.profile.requester_tags.iter().map(String::as_str));
        for grant in &loaded.profile.grants {
            let subjects = grant
                .subjects
                .iter()
                .map(|subject| (subject.role.as_str(), subject.selector_profile.as_str()))
                .collect::<BTreeSet<_>>();
            if !shapes.insert((grant.definition.as_str(), grant.purpose.as_str(), subjects)) {
                bail!("selected access profiles contain overlapping complete grant tuples");
            }
        }
    }
    let actors = actors.unwrap_or_default();
    if actors.is_empty() {
        bail!("one local client needs a common actor kind across its access profiles");
    }
    for (id, loaded) in profiles {
        if loaded
            .profile
            .requester_tags
            .iter()
            .all(|tag| tags.contains(tag.as_str()))
            && !actors.is_disjoint(&loaded.actors)
            && !ids.contains(id)
        {
            bail!("selected profile tags also match unassigned access profile {id}; use distinct identity tags");
        }
    }
    Ok(())
}

fn profile_audiences(
    ids: &[String],
    profiles: &BTreeMap<String, LoadedProfile>,
) -> Result<BTreeSet<String>> {
    let mut audiences: Option<BTreeSet<String>> = None;
    for id in ids {
        let profile = profiles
            .get(id)
            .context("client names an unknown target access profile")?;
        audiences = Some(match audiences {
            None => profile.audiences.clone(),
            Some(current) => current.intersection(&profile.audiences).cloned().collect(),
        });
    }
    let audiences = audiences.unwrap_or_default();
    if audiences.is_empty() {
        bail!("selected access profiles have no common permitted audience");
    }
    Ok(audiences)
}

/// A local credential has one concrete actor. Optional target actor constraints
/// remain bounded by the selected profiles and per-request definition ceilings.
fn resolved_client_actor(
    document: &ClientDocument,
    profiles: &BTreeMap<String, LoadedProfile>,
) -> Result<String> {
    let mut actors: Option<BTreeSet<String>> = None;
    for id in &document.access_profiles {
        let profile = profiles
            .get(id)
            .context("client names an unknown target access profile")?;
        actors = Some(match actors {
            None => profile.actors.clone(),
            Some(current) => current.intersection(&profile.actors).cloned().collect(),
        });
    }
    let mut actors = actors.unwrap_or_default();
    actors.retain(
        |actor| match document.exchange.as_ref().map(|exchange| exchange.kind) {
            Some(ActiveClientExchangeKind::InstitutionalGrant) => actor == "agent",
            Some(ActiveClientExchangeKind::FirstParty) => {
                matches!(actor.as_str(), "human" | "service")
            }
            None => matches!(actor.as_str(), "service" | "agent"),
        },
    );
    match &document.actor_kind {
        Some(actor) if actors.contains(actor.as_str()) => Ok(actor.as_str().to_owned()),
        Some(_) => {
            bail!("client actor kind is outside a selected definition ceiling or exchange mode")
        }
        None if actors.len() == 1 => Ok(actors.first().expect("one actor").clone()),
        None if actors.is_empty() => {
            bail!("selected profiles and exchange mode have no common actor kind")
        }
        None => bail!("choose --actor-kind from the selected definitions' common actor ceiling"),
    }
}

fn validate_client_identity(
    document: &ClientDocument,
    profiles: &BTreeMap<String, LoadedProfile>,
) -> Result<()> {
    if !profile_audiences(&document.access_profiles, profiles)?
        .contains(&document.evidence_audience)
    {
        bail!("client audience is outside a selected definition ceiling");
    }
    let actor = resolved_client_actor(document, profiles)?;
    for id in &document.access_profiles {
        let profile = &profiles[id].profile;
        let task = profile.grants.iter().any(|grant| {
            grant
                .subjects
                .iter()
                .any(|subject| subject.value_origin.as_str() == "authenticated-grant")
        });
        if task
            && (profile
                .requester_clients
                .as_ref()
                .is_none_or(|clients| !clients.iter().any(|id| id == &document.client_id))
                || profile.grant_source_issuer.is_none())
        {
            bail!("task client must be explicitly named by the target profile and trusted source issuer");
        }
        match document.exchange.as_ref().map(|exchange| exchange.kind) {
            Some(ActiveClientExchangeKind::InstitutionalGrant) if !task || actor != "agent" => {
                bail!("institutional exchange requires an assigned agent task-grant profile")
            }
            Some(ActiveClientExchangeKind::FirstParty)
                if task || !matches!(actor.as_str(), "service" | "human") =>
            {
                bail!("first-party exchange cannot replace task-grant authority")
            }
            None if task || !matches!(actor.as_str(), "service" | "agent") => bail!(
                "human and task-grant profiles require their explicit signed-context exchange"
            ),
            _ => {}
        }
    }
    Ok(())
}

fn load_access_profiles(project: &Path) -> Result<BTreeMap<String, LoadedProfile>> {
    let project_path = project.join("evidence.yaml");
    let text = read_bounded_file(
        &project_path,
        registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64,
        None,
    )?;
    let project_doc = registry_evidence_authoring::project::read_project(
        &project_path.display().to_string(),
        text.as_bytes(),
    )?
    .value;
    let target_path = project.join("local-target.yaml");
    let text = read_bounded_file(
        &target_path,
        registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64,
        None,
    )?;
    let target = registry_evidence_authoring::target::read_target(
        &target_path.display().to_string(),
        text.as_bytes(),
    )?
    .value;
    if target.project != project_doc.id {
        bail!("local-target.yaml must name this EvidenceProject");
    }
    let relative = Path::new(&target.authority);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        bail!("target authority must be a project-relative file path without parent traversal");
    }
    let authority_path = project.join(relative);
    let text = read_bounded_file(
        &authority_path,
        registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64,
        None,
    )?;
    let authority = registry_evidence_authoring::target::read_authority(
        &authority_path.display().to_string(),
        text.as_bytes(),
        &project_doc,
    )?
    .value;
    if authority.target != target.id {
        bail!("target authority must name the selected local target");
    }
    let compiled = registry_evidence_authoring::target::compile_authority(&authority, &project_doc)
        .map_err(|_| {
            anyhow!("target authority must contain complete grants within every definition ceiling")
        })?;
    authority
        .access_profiles
        .into_iter()
        .map(|(id, profile)| {
            let mut audiences: Option<BTreeSet<String>> = None;
            let mut actors = BTreeSet::new();
            for grant in &profile.grants {
                let allowed = project_doc.assertion_definitions[&grant.definition]
                    .grant_ceiling
                    .audiences
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                audiences = Some(match audiences {
                    None => allowed,
                    Some(current) => current.intersection(&allowed).cloned().collect(),
                });
                let allowed_actors = project_doc.assertion_definitions[&grant.definition]
                    .grant_ceiling
                    .actor_kinds
                    .iter()
                    .map(|actor| actor.as_str().to_owned())
                    .collect::<BTreeSet<_>>();
                actors.extend(allowed_actors);
            }
            if let Some(actor) = &profile.actor_kind {
                actors.retain(|candidate| candidate == actor.as_str());
            } else if !profile.grants.iter().any(|grant| {
                grant
                    .subjects
                    .iter()
                    .any(|subject| subject.value_origin.as_str() == "authenticated-grant")
            }) {
                // Ordinary agents require an explicitly agent-bound profile;
                // task grants have their own complete signed-context profile.
                actors.remove("agent");
            }
            let digest = profile_digest(&compiled["accessProfiles"][id.as_str()])?;
            Ok((
                id.to_string(),
                LoadedProfile {
                    profile,
                    digest,
                    audiences: audiences.unwrap_or_default(),
                    actors,
                },
            ))
        })
        .collect()
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

/// Check the public registration bytes without requiring a local project,
/// filename, private key, or installed file permissions.
pub(crate) fn check_client_document(file: &str, bytes: &[u8]) -> Result<Report, Report> {
    decode_client_document(file, bytes).map(|decoded| decoded.document.warnings())
}

fn decode_client_document(file: &str, bytes: &[u8]) -> Result<Decoded<ClientDocument>, Report> {
    let mut decoded = decode_authored::<ClientDocument>(file, bytes, &ACCESS_CLIENT)?;
    if let Err((path, message, action)) = validate_client_document(&mut decoded.value) {
        return Err(Report::new(vec![decoded.document.diagnostic_at_value(
            Severity::Error,
            "evidence.access.invalid-client",
            path,
            message,
            action,
        )]));
    }
    Ok(decoded)
}

/// The same content rules apply to standalone checks and local registration.
/// Faults name only fixed fields and fixes, never a caller value or key bytes.
fn validate_client_document(
    document: &mut ClientDocument,
) -> Result<(), (&'static str, &'static str, &'static str)> {
    validate_identifier(&document.client_id, "client").map_err(|_| {
        (
            "/clientId",
            "the client id must be a bounded lowercase local identifier",
            "Write a lowercase local identifier of at most 64 bytes.",
        )
    })?;
    document.access_profiles = canonical_sorted_unique(
        &document.access_profiles,
        "access profiles",
        MAX_PROFILES_PER_CLIENT,
    )
    .map_err(|_| {
        (
            "/accessProfiles",
            "access profiles must be a nonempty bounded sorted unique list",
            "Declare between one and 32 distinct access profiles in sorted order.",
        )
    })?;
    if document.principal != local_client_uri(&document.client_id) {
        return Err((
            "/principal",
            "the local client principal must match its client id",
            "Use urn:registrystack:evidence:local:client: followed by the client id.",
        ));
    }
    if !authoring::valid_local_audience(&document.evidence_audience) {
        return Err((
            "/evidenceAudience",
            "the evidence audience must be a bounded URI",
            "Declare a bounded URI for the audience of this client's evidence.",
        ));
    }
    if document.keys.len() != 1 {
        return Err((
            "/keys",
            "a local client must contain exactly one public key",
            "Declare exactly one public JWK without private key material.",
        ));
    }
    let key = &document.keys[0];
    if key.get("d").is_some()
        || serde_json::to_string(key)
            .ok()
            .and_then(|text| PublicJwk::parse(&text).ok())
            .is_none()
    {
        return Err((
            "/keys/0",
            "the client key must be a valid public JWK without private key material",
            "Declare a valid public JWK and retain its private key outside this document.",
        ));
    }
    if document
        .exchange
        .as_ref()
        .is_some_and(|exchange| exchange.validate().is_err())
    {
        return Err(("/exchange", "the local client exchange binding is invalid",
            "Declare the bounded bootstrap scope and the resource and issuer required by its exchange kind."));
    }
    Ok(())
}

fn read_client_document(path: &Path) -> Result<ClientDocument> {
    let text = read_bounded_file(path, MAXIMUM_DOCUMENT_BYTES as u64, Some(PUBLIC_FILE_MODE))?;
    let decoded = decode_client_document(&path.display().to_string(), text.as_bytes())?;
    validate_filename_id(path, &decoded.value.client_id, "client")?;
    Ok(decoded.value)
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

/// Write one access document: its envelope lines, then its members.
fn write_new_yaml_atomic<T: Serialize>(
    path: &Path,
    envelope: &str,
    value: &T,
    mode: u32,
) -> Result<()> {
    reject_existing(path)?;
    let bytes = format!(
        "{envelope}{}",
        crate::authored::to_indented_yaml(value).context("rendering access document")?
    );
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

fn replace_yaml_atomic<T: Serialize>(
    path: &Path,
    envelope: &str,
    value: &T,
    mode: u32,
) -> Result<()> {
    validate_path_mode(path, false, mode)?;
    let bytes = format!(
        "{envelope}{}",
        crate::authored::to_indented_yaml(value).context("rendering access document")?
    );
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
            // The kernel masks the requested mode with the process umask, so
            // an operator under `umask 077` gets a 0700 public directory. Set
            // the intended mode explicitly on the directory this call created,
            // then prove it, rather than refusing a directory we just made.
            set_directory_mode_without_following(path, mode)?;
            validate_path_mode(path, true, mode)
        }
        Err(error) => Err(error.into()),
    }
}

/// Set `mode` on the directory at `path` through a descriptor opened without
/// following a final symlink.
///
/// A path-based chmod follows a symlink, so a directory swapped for one
/// between its creation and the chmod would lend this process's authority to
/// whatever the link names. Opening with `NOFOLLOW` and `DIRECTORY` refuses
/// anything but the plain directory, and the mode is applied to that very
/// directory rather than to a name resolved a second time.
fn set_directory_mode_without_following(path: &Path, mode: u32) -> Result<()> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {} as a plain directory", path.display()))?;
    File::from(descriptor)
        .set_permissions(fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of {}", path.display()))
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

fn joined_profiles(access_profiles: &[String]) -> String {
    if access_profiles.len() == 1 {
        format!("access profile {}", access_profiles[0])
    } else {
        format!("access profiles {}", access_profiles.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A directory swapped for a symlink before its mode is set must not lend
    /// the chmod to the link's target.
    #[test]
    fn setting_a_directory_mode_refuses_a_symlink_and_leaves_its_target_alone() {
        let fixture = tempfile::tempdir().expect("tempdir");
        let target = fixture.path().join("private-target");
        fs::create_dir(&target).expect("target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .expect("private target mode");
        let swapped = fixture.path().join("public");
        symlink(&target, &swapped).expect("swapped symlink");

        assert!(set_directory_mode_without_following(&swapped, PUBLIC_DIRECTORY_MODE).is_err());
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o7777,
            PRIVATE_DIRECTORY_MODE
        );

        let plain = fixture.path().join("plain");
        fs::create_dir(&plain).expect("plain directory");
        set_directory_mode_without_following(&plain, PUBLIC_DIRECTORY_MODE)
            .expect("a plain directory takes the mode");
        assert_eq!(
            fs::metadata(&plain)
                .expect("plain metadata")
                .permissions()
                .mode()
                & 0o7777,
            PUBLIC_DIRECTORY_MODE
        );
    }
}
