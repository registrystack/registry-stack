//! Governed target access profiles and the local client documents a dev session reads.
//!
//! Complete access profiles live in the target authority document. Public client
//! membership lives under `access/clients/`. The only private client artifact is
//! the key under `.evidence/clients/<id>/private.jwk`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::{Args, Subcommand};
use registry_evidence_authoring::formats::{decode_authored, ACCESS_CLIENT};
use registry_evidence_authoring::{project::ActorKind, target::AccessProfile};
use registry_platform_crypto::PublicJwk;
use registry_platform_yaml::{Decoded, Report, Severity, MAXIMUM_DOCUMENT_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{authoring, OutputFormat};

const ACCESS_DIRECTORY: &str = "access";
const CLIENTS_DIRECTORY: &str = "clients";
const MAX_CLIENTS: usize = 4_096;
const MAX_PROFILES_PER_CLIENT: usize = 32;
const PUBLIC_DIRECTORY_MODE: u32 = 0o755;
const PUBLIC_FILE_MODE: u32 = 0o644;

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Inspect complete access profiles from the target authority.
    #[command(subcommand)]
    Profile(ProfileCommand),
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List governed target access profiles.
    List(ProjectArgs),
}

#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,
}

/// The derived JSON Schema of one local access client document.
#[cfg(feature = "schema")]
pub(crate) fn client_document_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ClientDocument)).expect("a derived schema is JSON")
}

struct LoadedProfile {
    profile: AccessProfile,
    digest: String,
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

pub fn run(command: AccessCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        AccessCommand::Profile(ProfileCommand::List(args)) => {
            list_access_profiles(&args.project, format)
        }
    }
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

/// An active client that presents a task authority assertion, with the
/// access profiles it holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExchangeClient {
    pub(crate) client_id: String,
    pub(crate) access_profiles: Vec<String>,
    pub(crate) exchange: ActiveClientExchange,
}

/// The public registrations of active clients that exchange an assertion.
/// Reads `access/clients/` only; no key is returned.
pub(crate) fn active_exchange_clients(project: &Path) -> Result<Vec<ExchangeClient>> {
    let project = canonical_project(project)?;
    Ok(load_client_documents_if_present(&project)?
        .into_values()
        .filter(|document| document.status == ClientStatus::Active)
        .filter_map(|document| {
            Some(ExchangeClient {
                client_id: document.client_id,
                access_profiles: document.access_profiles,
                exchange: document.exchange?,
            })
        })
        .collect())
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
            let digest = profile_digest(&compiled["accessProfiles"][id.as_str()])?;
            Ok((id.to_string(), LoadedProfile { profile, digest }))
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

fn local_client_uri(client_id: &str) -> String {
    format!("urn:registrystack:evidence:local:client:{client_id}")
}
