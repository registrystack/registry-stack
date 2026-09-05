//! Progressive relying-party profile and contract-candidate tooling.
//!
//! Profiles contain references to authorization and trust material, never the
//! material itself. Contract catalogs are requester-scoped authoring input and
//! are deliberately distinct from the verification trust decision.

use std::{
    fs::{self, File},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{ArgGroup, Args, Subcommand};
use registry_evidence_client::{EvidenceClient, EvidenceClientProfile};
use registry_platform_crypto::canonicalize_json;
use serde::{Deserialize, Serialize};
use url::Url;

pub(crate) const CLIENT_PROFILE_SCHEMA_V1: &str = "registry.evidence-client-profile/v1";
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_CLIENT_ID_BYTES: usize = 256;

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Create and inspect relying-party client profiles.
    #[command(subcommand)]
    Profile(Box<ProfileCommand>),
    /// Fetch requester-scoped contract candidates for review.
    #[command(subcommand)]
    Contracts(ContractsCommand),
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Create a strict profile containing only references to local key material.
    Create(ProfileCreateArgs),
}

#[derive(Debug, Subcommand)]
pub enum ContractsCommand {
    /// Fetch a closed requester-scoped contract candidate.
    Fetch(ContractsFetchArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("private_key")
        .required(true)
        .args(["private_key_file", "private_key_env"])
))]
pub struct ProfileCreateArgs {
    /// Evidence Gateway base URL. HTTPS is required by default.
    #[arg(long)]
    base_url: Url,

    /// Registered OAuth client identifier.
    #[arg(long)]
    client_id: String,

    /// Safe path to a private JWK, relative to the profile file.
    #[arg(long, value_name = "PATH")]
    private_key_file: Option<PathBuf>,

    /// Environment variable holding the private JWK JSON.
    #[arg(long, value_name = "VARIABLE")]
    private_key_env: Option<String>,

    /// Permit discovery over plain HTTP only when the base URL is loopback.
    #[arg(long)]
    local_loopback_discovery: bool,

    /// Reviewed pinned JWKS file, relative to the profile file.
    #[arg(long, value_name = "PATH", conflicts_with = "local_loopback_discovery")]
    pinned_jwks: Option<PathBuf>,

    /// Reviewed contract catalog, relative to the profile file.
    #[arg(long, value_name = "PATH")]
    contracts_file: Option<PathBuf>,

    /// Maximum accepted assertion lifetime in seconds.
    #[arg(long, default_value_t = 300)]
    maximum_assertion_lifetime_seconds: u64,

    /// Accepted verifier clock skew in seconds.
    #[arg(long, default_value_t = 30)]
    clock_skew_seconds: u64,

    /// Optional expected audience override.
    #[arg(long)]
    expected_audience: Option<String>,

    /// Optional expected Evidence issuer.
    #[arg(long)]
    expected_issuer: Option<String>,

    /// Optional expected Evidence provider.
    #[arg(long)]
    expected_provider: Option<String>,

    /// New owner-only profile file.
    #[arg(long, alias = "out")]
    output: PathBuf,
}

#[derive(Debug, Args)]
pub struct ContractsFetchArgs {
    /// Owner-only client profile.
    #[arg(long)]
    pub(crate) profile: PathBuf,

    /// New owner-only contract-candidate file.
    #[arg(long, alias = "out")]
    pub(crate) output: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClientProfile {
    pub(crate) schema: String,
    pub(crate) base_url: String,
    pub(crate) client_id: String,
    pub(crate) private_key: PrivateKeyReference,
    pub(crate) trust: TrustProfile,
    pub(crate) contracts: ContractsProfile,
    pub(crate) verification: VerificationProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expected: Option<ExpectedProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PrivateKeyReference {
    File { path: PathBuf },
    Environment { variable: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TrustProfile {
    HttpsDiscovery,
    LocalLoopbackDiscovery,
    PinnedJwks { file: PathBuf },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ContractsProfile {
    Published,
    Reviewed { file: PathBuf },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VerificationProfile {
    pub(crate) maximum_assertion_lifetime_seconds: u64,
    pub(crate) clock_skew_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExpectedProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
}

pub fn run(command: ClientCommand) -> Result<ExitCode> {
    match command {
        ClientCommand::Profile(command) => match *command {
            ProfileCommand::Create(args) => create_profile(args),
        },
        ClientCommand::Contracts(ContractsCommand::Fetch(args)) => fetch_contracts(args),
    }
}

fn create_profile(args: ProfileCreateArgs) -> Result<ExitCode> {
    validate_new_output(&args.output).context("client profile output is unsafe")?;
    validate_base_url(&args.base_url, args.local_loopback_discovery)?;
    validate_bounded_identifier(&args.client_id, MAX_CLIENT_ID_BYTES, "client identifier")?;
    if !(1..=31_536_000).contains(&args.maximum_assertion_lifetime_seconds) {
        bail!("maximum assertion lifetime must be within 1..=31536000 seconds");
    }
    if args.clock_skew_seconds > 300 {
        bail!("clock skew must be within 0..=300 seconds");
    }

    let private_key = match (args.private_key_file, args.private_key_env) {
        (Some(path), None) => {
            validate_relative_reference(&path)?;
            PrivateKeyReference::File { path }
        }
        (None, Some(variable)) => {
            validate_environment_variable(&variable)?;
            PrivateKeyReference::Environment { variable }
        }
        _ => bail!("provide exactly one private key reference"),
    };
    let trust = match args.pinned_jwks {
        Some(file) => {
            validate_relative_reference(&file)?;
            TrustProfile::PinnedJwks { file }
        }
        None if args.local_loopback_discovery => TrustProfile::LocalLoopbackDiscovery,
        None => TrustProfile::HttpsDiscovery,
    };
    let contracts = match args.contracts_file {
        Some(file) => {
            validate_relative_reference(&file)?;
            ContractsProfile::Reviewed { file }
        }
        None => ContractsProfile::Published,
    };
    let expected = ExpectedProfile {
        audience: args.expected_audience,
        issuer: args.expected_issuer,
        provider: args.expected_provider,
    };
    for value in [
        expected.audience.as_deref(),
        expected.issuer.as_deref(),
        expected.provider.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_bounded_identifier(value, 512, "expected identity")?;
    }
    let expected =
        (expected.audience.is_some() || expected.issuer.is_some() || expected.provider.is_some())
            .then_some(expected);
    let profile = ClientProfile {
        schema: CLIENT_PROFILE_SCHEMA_V1.to_owned(),
        base_url: args.base_url.as_str().trim_end_matches('/').to_owned(),
        client_id: args.client_id,
        private_key,
        trust,
        contracts,
        verification: VerificationProfile {
            maximum_assertion_lifetime_seconds: args.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: args.clock_skew_seconds,
        },
        expected,
    };
    let mut bytes = canonicalize_json(&serde_json::to_value(profile)?)?;
    EvidenceClientProfile::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("generated client profile is invalid"))?;
    bytes.push(b'\n');
    write_owner_only_new(&args.output, &bytes).context("failed to write client profile")?;
    println!("Created client profile");
    Ok(ExitCode::SUCCESS)
}

fn fetch_contracts(args: ContractsFetchArgs) -> Result<ExitCode> {
    validate_new_output(&args.output).context("client contract output is unsafe")?;
    validate_owner_only_input(&args.profile)
        .context("client profile is not a safe owner-only file")?;
    let mut profile = EvidenceClientProfile::from_file(&args.profile)
        .map_err(|_| anyhow::anyhow!("client contract discovery failed"))?;
    // Fetch always asks the deployment for a new candidate. A reviewed catalog
    // in the profile remains the authority for ordinary requests, but using it
    // here would merely copy the already-reviewed file instead of discovering
    // what the deployment currently publishes.
    profile.contracts = registry_evidence_client::ContractsProfile::Published;
    let client = EvidenceClient::from_profile(profile)
        .map_err(|_| anyhow::anyhow!("client contract discovery failed"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("client contract discovery failed")?;
    let contracts = runtime
        .block_on(client.contracts_candidate())
        .map_err(|_| anyhow::anyhow!("client contract discovery failed"))?;
    let mut bytes = canonicalize_json(&serde_json::to_value(contracts)?)?;
    bytes.push(b'\n');
    write_owner_only_new(&args.output, &bytes)
        .context("failed to write client contract candidate")?;
    println!("Fetched client contract candidate");
    Ok(ExitCode::SUCCESS)
}

fn validate_base_url(url: &Url, allow_local_loopback: bool) -> Result<()> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("base URL must contain no credentials, query, or fragment");
    }
    if url.path() != "/" {
        bail!("base URL must be an origin without a path");
    }
    match url.scheme() {
        "https" if !allow_local_loopback => Ok(()),
        "http"
            if allow_local_loopback
                && url.host().is_some_and(is_loopback_host)
                && url.port().is_some_and(|port| port != 0) =>
        {
            Ok(())
        }
        "https" if allow_local_loopback => {
            bail!("local loopback discovery requires an HTTP loopback base URL")
        }
        _ if allow_local_loopback => {
            bail!("local loopback discovery requires an HTTP loopback base URL")
        }
        _ => bail!("HTTPS discovery requires an HTTPS base URL"),
    }
}

fn is_loopback_host(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(address) => address == std::net::Ipv4Addr::LOCALHOST,
        url::Host::Domain(_) | url::Host::Ipv6(_) => false,
    }
}

fn validate_relative_reference(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.components().any(|component| {
            matches!(component, Component::CurDir | Component::ParentDir)
                || (!path.is_absolute()
                    && matches!(component, Component::Prefix(_) | Component::RootDir))
        })
    {
        bail!("profile file references must be absolute or normalized relative paths");
    }
    Ok(())
}

fn validate_environment_variable(variable: &str) -> Result<()> {
    let mut bytes = variable.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        || bytes.any(|byte| byte != b'_' && !byte.is_ascii_alphanumeric())
        || variable.len() > 128
    {
        bail!("private key environment variable name is invalid");
    }
    Ok(())
}

fn validate_bounded_identifier(value: &str, maximum_bytes: usize, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        bail!("{label} must be non-empty, bounded, and contain no control characters");
    }
    Ok(())
}

fn validate_new_output(path: &Path) -> Result<()> {
    if path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("output must be a normalized path naming one new file");
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("output already exists; refusing to replace it"),
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        bail!("output directory must be owned and unsymlinked");
    }
    Ok(())
}

pub(crate) fn write_owner_only_new(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_new_output(path)?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::from_bits_truncate(PRIVATE_FILE_MODE as rustix::fs::RawMode),
    )
    .map_err(std::io::Error::from)?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() != bytes.len() as u64
    {
        bail!("owner-only output failed its file-safety checks");
    }
    Ok(())
}

pub(crate) fn validate_owner_only_input(path: &Path) -> Result<()> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.len() == 0
        || metadata.len() > 256 * 1024
    {
        bail!("input is not a bounded owner-only regular file");
    }
    Ok(())
}
