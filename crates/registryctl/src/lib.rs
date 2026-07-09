use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::ValueEnum;
use ed25519_dalek::SigningKey;
use registry_config_report::{
    ConfigDiagnostic, ConfigDiagnosticReport, ConfigSourceKind, ConfigSourceRef,
    DiagnosticSeverity, DiagnosticSummary, RegistryctlProductReport, RegistryctlProjectRef,
    RegistryctlValidationReport, ReportStatus, REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1,
};
use registry_platform_authcommon::{fingerprint_api_key, validate_api_key_entropy};
use registry_platform_config::{
    sha256_uri, verify_config_bundle, ConfigBundleFile, ConfigBundleManifest,
    ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
    ConfigTrustAnchorSigner, MAX_BUNDLE_FILE_BYTES, MAX_CONFIG_BUNDLE_SEQUENCE,
};
use registry_platform_crypto::{
    canonicalize_json, sign as sign_payload, PrivateJwk, PublicJwk, SigningAlgorithm,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub use crate::sample::Sample;

mod sample;
mod stored_zip;

const RELAY_IMAGE: &str =
    "ghcr.io/registrystack/registry-relay@sha256:da9332ef30ba252d54ba275eb2a9be443a65e95ef78c493b9b0ce30cbc391e71";
const NOTARY_IMAGE: &str =
    "ghcr.io/registrystack/registry-notary@sha256:338d3ac7ddbea55f6e76014b9c23e4ff4e7206c2c40e356452288de06a745ff3";
const NOTARY_REDIS_IMAGE: &str = "redis:7.4-alpine";
const LINUX_AMD64_PLATFORM: &str = "linux/amd64";
const RELAY_BASE_URL: &str = "http://127.0.0.1:4242";
const NOTARY_BASE_URL: &str = "http://127.0.0.1:4255";
const NOTARY_SOURCE_RELAY_SERVICE_URL: &str = "http://registry-relay:8080";
const RELAY_DOCS_PATH: &str = "/docs";
const NOTARY_DOCS_PATH: &str = "/docs";
const NOTARY_OPENAPI_PATH: &str = "/openapi.json";
const NOTARY_CLAIM_RESULT_JSON: &str = "application/vnd.registry-notary.claim-result+json";
const NOTARY_TUTORIAL_CLAIM: &str = "benefits-person-exists";
const NOTARY_DEMO_ISSUER_KEY_ID: &str = "registryctl-demo-issuer";
const NOTARY_DEMO_ISSUER_KID: &str = "did:web:localhost#registryctl-demo";
const TUTORIAL_PURPOSE: &str = "https://example.local/purpose/tutorial";
const BRUNO_COLLECTION_DIR: &str = "bruno/registry-api";
const BRUNO_GENERATED_MANIFEST: &str = "bruno/registry-api/.registryctl-generated";
const STANDALONE_SOURCE_TOKEN_PLACEHOLDER: &str = "replace-with-source-api-token";
const REGISTRY_STACK_RUNTIME_UID_ENV: &str = "REGISTRY_STACK_RUNTIME_UID";
const REGISTRY_STACK_RUNTIME_GID_ENV: &str = "REGISTRY_STACK_RUNTIME_GID";
const DEFAULT_NONROOT_CONTAINER_ID: &str = "65532";
const REGISTRYCTL_RELEASES_API: &str =
    "https://api.github.com/repos/registrystack/registry-stack/releases/latest";
const REGISTRYCTL_INSTALL_SCRIPT: &str =
    "https://raw.githubusercontent.com/registrystack/registry-stack/main/crates/registryctl/install.sh";
const UPDATE_CHECK_CACHE_SECONDS: u64 = 60 * 60 * 24;
/// The only `schema_version` `registryctl_manifest` generates today; `Project::load` rejects
/// any other value so a future/incompatible schema file fails loudly instead of half-parsing.
const PROJECT_SCHEMA_VERSION: &str = "registryctl/v1";
const CONFIG_BUNDLE_SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const CONFIG_TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum NotarySource {
    LocalRelay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum NotaryInitSourceKind {
    RegistryDataApi,
    FhirSidecar,
    OpencrvsDci,
}

impl NotaryInitSourceKind {
    /// Every `notary.source` label `from_source_label` accepts, listed for error messages.
    /// `"relay"` is an accepted alias for `RegistryDataApi`; `source_label` never emits it.
    const VALID_SOURCE_LABELS: &'static [&'static str] = &[
        "registry_data_api",
        "relay",
        "fhir_source_adapter_sidecar",
        "opencrvs_dci",
    ];

    fn from_source_label(source: &str) -> Option<Self> {
        match source {
            "registry_data_api" | "relay" => Some(Self::RegistryDataApi),
            "fhir_source_adapter_sidecar" => Some(Self::FhirSidecar),
            "opencrvs_dci" => Some(Self::OpencrvsDci),
            _ => None,
        }
    }

    fn source_label(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "registry_data_api",
            Self::FhirSidecar => "fhir_source_adapter_sidecar",
            Self::OpencrvsDci => "opencrvs_dci",
        }
    }

    fn connection_id(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "source_api",
            Self::FhirSidecar => "fhir_sidecar",
            Self::OpencrvsDci => "opencrvs_crvs",
        }
    }

    fn connector(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "registry_data_api",
            Self::FhirSidecar => "openfn_sidecar",
            Self::OpencrvsDci => "dci",
        }
    }

    fn source_binding(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "person",
            Self::FhirSidecar => "patient",
            Self::OpencrvsDci => "birth_record",
        }
    }

    pub fn default_source_url(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "https://api.example.test",
            Self::FhirSidecar => "http://host.docker.internal:4360",
            Self::OpencrvsDci => "https://opencrvs.example.test",
        }
    }

    pub fn default_source_token_env(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "EVIDENCE_SOURCE_API_TOKEN",
            Self::FhirSidecar => "FHIR_SIDECAR_TOKEN",
            Self::OpencrvsDci => "OPENCRVS_DCI_UNUSED_STATIC_TOKEN",
        }
    }

    pub fn default_source_dataset(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "benefits_casework",
            Self::FhirSidecar => "health_registry",
            Self::OpencrvsDci => "civil_registry",
        }
    }

    pub fn default_source_entity(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "person",
            Self::FhirSidecar => "patient",
            Self::OpencrvsDci => "birth_registration",
        }
    }

    pub fn default_source_lookup_field(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "id",
            Self::FhirSidecar => "national_id",
            Self::OpencrvsDci => "UIN",
        }
    }

    pub fn default_source_claim(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "benefits-person-exists",
            Self::FhirSidecar => "patient-record-exists",
            Self::OpencrvsDci => "opencrvs-birth-record-exists",
        }
    }

    pub fn default_source_claim_title(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "Benefits person exists",
            Self::FhirSidecar => "Patient record exists",
            Self::OpencrvsDci => "OpenCRVS birth record exists",
        }
    }

    pub fn default_smoke_target_id(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "per-2001",
            Self::FhirSidecar => "person-123",
            Self::OpencrvsDci => "UIN-2001",
        }
    }

    fn retry_on_5xx(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "true",
            Self::FhirSidecar => "false",
            Self::OpencrvsDci => "true",
        }
    }

    fn bulk_mode(self) -> &'static str {
        match self {
            Self::RegistryDataApi => "none",
            Self::FhirSidecar => "openfn_sidecar_batch",
            Self::OpencrvsDci => "none",
        }
    }

    fn uses_static_source_token(self) -> bool {
        !matches!(self, Self::OpencrvsDci)
    }

    fn smoke_target_json(self, smoke_target_id: &str, source_entity: &str) -> Value {
        match self {
            Self::OpencrvsDci => serde_json::json!({
                "type": "person",
                "identifiers": [
                    {
                        "scheme": "UIN",
                        "value": smoke_target_id
                    }
                ]
            }),
            Self::RegistryDataApi | Self::FhirSidecar => serde_json::json!({
                "type": source_entity,
                "id": smoke_target_id
            }),
        }
    }
}

#[derive(Debug)]
pub struct NotaryInitOptions {
    pub source_kind: NotaryInitSourceKind,
    pub source_url: String,
    pub source_token_from_env: Option<String>,
    pub source_token_env: String,
    pub source_dataset: String,
    pub source_entity: String,
    pub source_lookup_field: String,
    pub source_network: Option<String>,
    pub source_claim: String,
    pub source_claim_title: String,
    pub smoke_target_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleInspectReport {
    pub schema_version: String,
    pub manifest: ConfigBundleManifest,
    pub signature_count: usize,
    pub signature_kids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleVerifyReport {
    pub schema_version: String,
    pub product: String,
    pub environment: String,
    pub stream_id: String,
    pub instance_id: Option<String>,
    pub bundle_id: String,
    pub sequence: u64,
    pub config_path: PathBuf,
    pub config_hash: String,
    pub signer_kids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleSignReport {
    pub schema_version: String,
    pub bundle_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub signature_path: PathBuf,
    pub config_path: String,
    pub config_hash: String,
    pub kid: String,
    pub alg: String,
    pub signature_count: usize,
}

#[derive(Debug)]
pub struct BundleSignOptions {
    pub input: PathBuf,
    pub key: String,
    pub product: String,
    pub environment: String,
    pub stream_id: String,
    pub instance_id: Option<String>,
    pub sequence: u64,
    pub bundle_id: String,
    pub out: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnchorReport {
    pub schema_version: String,
    pub anchor_path: PathBuf,
    pub product: String,
    pub environment: String,
    pub stream_id: String,
    pub instance_id: String,
    pub signer_count: usize,
    pub enabled_signer_count: usize,
}

#[derive(Debug)]
pub struct OpenFnConvertOptions {
    pub input: PathBuf,
    pub workflow: Option<String>,
    pub output: PathBuf,
    pub jobs_dir: PathBuf,
    pub expression_prefix: Option<PathBuf>,
    pub source_id: String,
    pub dataset: String,
    pub entity: String,
    pub credential_env: String,
    pub allowed_base_urls: Vec<String>,
    pub smoke_field: String,
    pub smoke_value: String,
    pub smoke_fields: Option<String>,
    pub smoke_purpose: String,
    pub auth_hash_env: String,
    pub server_bind: String,
    pub cli_build_tool: String,
    pub runtime: String,
    pub worker_command: PathBuf,
    pub worker_script: PathBuf,
    pub max_workers: usize,
    pub worker_timeout_ms: u64,
    pub max_worker_memory_mb: u64,
    pub max_output_bytes: usize,
    pub max_request_bytes: usize,
    pub max_query_parameter_bytes: usize,
    pub max_batch_items: usize,
    pub batch_mode: OpenFnBatchMode,
    pub notary_snippet_output: Option<PathBuf>,
    pub sidecar_base_url: Option<String>,
    pub sidecar_token_env: String,
    pub allow_latest_adaptors: bool,
    pub allow_empty_job_bodies: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum OpenFnBatchMode {
    PerItem,
    Native,
}

impl OpenFnBatchMode {
    fn as_yaml_str(self) -> &'static str {
        match self {
            Self::PerItem => "per_item",
            Self::Native => "native",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DoctorFormat {
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum DeploymentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

impl DeploymentProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::HostedLab => "hosted_lab",
            Self::Production => "production",
            Self::EvidenceGrade => "evidence_grade",
        }
    }
}

#[derive(Debug)]
pub struct OpenFnImportOptions {
    pub input: String,
    pub openfn_token_env: String,
    pub workflow: Option<String>,
    pub output: PathBuf,
    pub jobs_dir: PathBuf,
    pub expression_prefix: PathBuf,
    pub source_id: String,
    pub dataset: String,
    pub entity: String,
    pub credential_env: String,
    pub allowed_base_urls: Vec<String>,
    pub smoke: String,
    pub smoke_fields: Option<String>,
    pub smoke_purpose: String,
    pub auth_hash_env: String,
    pub server_bind: String,
    pub cli_build_tool: String,
    pub runtime: String,
    pub worker_command: PathBuf,
    pub worker_script: PathBuf,
    pub max_workers: usize,
    pub worker_timeout_ms: u64,
    pub max_worker_memory_mb: u64,
    pub max_output_bytes: usize,
    pub max_request_bytes: usize,
    pub max_query_parameter_bytes: usize,
    pub max_batch_items: usize,
    pub batch_mode: OpenFnBatchMode,
    pub notary_snippet_output: Option<PathBuf>,
    pub sidecar_base_url: Option<String>,
    pub sidecar_token_env: String,
    pub allow_latest_adaptors: bool,
    pub allow_empty_job_bodies: bool,
}

pub fn inspect_config_bundle(bundle_dir: &Path) -> Result<BundleInspectReport> {
    let manifest_path = bundle_dir.join("manifest.json");
    let signature_path = bundle_dir.join("manifest.sig.json");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest: ConfigBundleManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
    manifest
        .validate()
        .with_context(|| format!("invalid config bundle manifest {}", manifest_path.display()))?;

    let envelope = read_signature_envelope_if_present(&signature_path)?;
    let signature_kids: Vec<String> = envelope
        .as_ref()
        .map(|envelope| {
            envelope
                .signatures
                .iter()
                .map(|signature| signature.kid.clone())
                .collect()
        })
        .unwrap_or_default();
    Ok(BundleInspectReport {
        schema_version: "registryctl.config_bundle.inspect.v1".to_string(),
        manifest,
        signature_count: signature_kids.len(),
        signature_kids,
    })
}

pub fn verify_config_bundle_cli(
    bundle_dir: &Path,
    anchor_path: &Path,
) -> Result<BundleVerifyReport> {
    let verified = verify_config_bundle(bundle_dir, anchor_path)
        .with_context(|| format!("failed to verify config bundle {}", bundle_dir.display()))?;
    Ok(BundleVerifyReport {
        schema_version: "registryctl.config_bundle.verify.v1".to_string(),
        product: verified.manifest.product,
        environment: verified.manifest.environment,
        stream_id: verified.manifest.stream_id,
        instance_id: verified.manifest.instance_id,
        bundle_id: verified.manifest.bundle_id,
        sequence: verified.manifest.sequence,
        config_path: verified.config_path,
        config_hash: verified.manifest.config_hash,
        signer_kids: verified.signer_kids,
    })
}

pub fn sign_config_bundle(options: BundleSignOptions) -> Result<BundleSignReport> {
    if options.sequence == 0 || options.sequence > MAX_CONFIG_BUNDLE_SEQUENCE {
        bail!("sequence must be in 1..={}", MAX_CONFIG_BUNDLE_SEQUENCE);
    }
    ensure_output_bundle_dir_is_empty(&options.out)?;
    let files = collect_config_bundle_input_files(&options.input)?;
    let primary_config_path = primary_config_path(&options.product, &files)?;
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format created_at")?;
    let manifest_files = files
        .iter()
        .map(|file| ConfigBundleFile {
            path: file.relative_path.clone(),
            sha256: file.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let config_hash = files
        .iter()
        .find(|file| file.relative_path == primary_config_path)
        .map(|file| file.sha256.clone())
        .expect("primary config path was selected from files");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        product: options.product,
        environment: options.environment,
        stream_id: options.stream_id,
        instance_id: options.instance_id,
        bundle_id: options.bundle_id,
        sequence: options.sequence,
        previous_config_hash: None,
        config_hash: config_hash.clone(),
        files: manifest_files,
        created_at,
    };
    manifest
        .validate()
        .context("generated manifest is invalid")?;

    for file in &files {
        let destination = options.out.join(&file.relative_path);
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        fs::write(&destination, &file.bytes)
            .with_context(|| format!("failed to write {}", destination.display()))?;
    }
    let manifest_path = options.out.join("manifest.json");
    let signature_path = options.out.join("manifest.sig.json");
    write_json_file(&manifest_path, &manifest)?;
    let manifest_value =
        serde_json::to_value(&manifest).context("failed to render manifest for signing")?;

    let private_jwk_text = read_private_jwk_text(&options.key)?;
    let private_jwk = PrivateJwk::parse(&private_jwk_text).with_context(|| {
        format!(
            "failed to parse private JWK from {}",
            key_display(&options.key)
        )
    })?;
    let public_jwk = private_jwk.public();
    let kid = public_jwk
        .jkt()
        .context("failed to compute JWK thumbprint for signing key")?;
    let alg = signing_algorithm_label(private_jwk.algorithm().context("invalid signing key alg")?);
    let canonical_manifest =
        canonicalize_json(&manifest_value).context("failed to canonicalize manifest JSON")?;
    let signature = sign_payload(&canonical_manifest, &private_jwk)
        .context("failed to sign config bundle manifest")?;

    let envelope = ConfigBundleSignatureEnvelope {
        schema: CONFIG_BUNDLE_SIGNATURE_SCHEMA.to_string(),
        signatures: vec![ConfigBundleSignature {
            kid: kid.clone(),
            alg: alg.to_string(),
            sig: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
        }],
    };
    write_json_file(&signature_path, &envelope)?;

    Ok(BundleSignReport {
        schema_version: "registryctl.config_bundle.sign.v1".to_string(),
        bundle_dir: options.out,
        manifest_path,
        signature_path,
        config_path: primary_config_path,
        config_hash,
        kid,
        alg: alg.to_string(),
        signature_count: envelope.signatures.len(),
    })
}

pub fn init_config_anchor(
    anchor_path: &Path,
    product: String,
    environment: String,
    stream_id: String,
    instance_id: String,
) -> Result<AnchorReport> {
    let anchor = ConfigTrustAnchor {
        schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
        product,
        environment,
        stream_id,
        instance_id,
        signers: Vec::new(),
    };
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

pub fn add_config_anchor_key(
    anchor_path: &Path,
    jwk_path: &Path,
    enabled: bool,
) -> Result<AnchorReport> {
    let mut anchor = read_anchor_unvalidated(anchor_path)?;
    let jwk_bytes =
        fs::read(jwk_path).with_context(|| format!("failed to read {}", jwk_path.display()))?;
    let jwk = PublicJwk::parse(
        std::str::from_utf8(&jwk_bytes)
            .with_context(|| format!("{} is not UTF-8 JSON", jwk_path.display()))?,
    )
    .with_context(|| format!("failed to parse public JWK {}", jwk_path.display()))?;
    let kid = jwk
        .jkt()
        .context("failed to compute JWK thumbprint for anchor key")?;
    if anchor.signers.iter().any(|signer| signer.kid == kid) {
        bail!("trust anchor already contains signer {kid}");
    }
    anchor
        .signers
        .push(ConfigTrustAnchorSigner { kid, jwk, enabled });
    anchor
        .validate()
        .with_context(|| format!("invalid trust anchor {}", anchor_path.display()))?;
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

pub fn remove_config_anchor_key(anchor_path: &Path, kid: &str) -> Result<AnchorReport> {
    let mut anchor = read_anchor_unvalidated(anchor_path)?;
    let before = anchor.signers.len();
    anchor.signers.retain(|signer| signer.kid != kid);
    if anchor.signers.len() == before {
        bail!("trust anchor does not contain signer {kid}");
    }
    if !anchor.signers.is_empty() {
        anchor
            .validate()
            .with_context(|| format!("invalid trust anchor {}", anchor_path.display()))?;
    }
    write_trust_anchor_file(anchor_path, &anchor)?;
    Ok(anchor_report(anchor_path, &anchor))
}

#[derive(Debug)]
struct BundleInputFile {
    relative_path: String,
    bytes: Vec<u8>,
    sha256: String,
}

fn ensure_output_bundle_dir_is_empty(out: &Path) -> Result<()> {
    if out.exists() {
        if !out.is_dir() {
            bail!(
                "bundle output path exists and is not a directory: {}",
                out.display()
            );
        }
        let mut entries =
            fs::read_dir(out).with_context(|| format!("failed to read {}", out.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!("bundle output directory must be empty: {}", out.display());
        }
    } else {
        fs::create_dir_all(out).with_context(|| format!("failed to create {}", out.display()))?;
    }
    Ok(())
}

fn collect_config_bundle_input_files(input: &Path) -> Result<Vec<BundleInputFile>> {
    if !input.is_dir() {
        bail!("bundle input path must be a directory: {}", input.display());
    }
    let mut files = Vec::new();
    collect_config_bundle_input_files_inner(input, input, &mut files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files.is_empty() {
        bail!("bundle input directory contains no regular files");
    }
    Ok(files)
}

fn collect_config_bundle_input_files_inner(
    root: &Path,
    dir: &Path,
    files: &mut Vec<BundleInputFile>,
) -> Result<()> {
    let metadata =
        fs::symlink_metadata(dir).with_context(|| format!("failed to stat {}", dir.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("bundle input symlink is not allowed: {}", dir.display());
    }
    if !metadata.is_dir() {
        bail!("bundle input path is not a directory: {}", dir.display());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("bundle input symlink is not allowed: {}", path.display());
        }
        if metadata.is_dir() {
            collect_config_bundle_input_files_inner(root, &path, files)?;
        } else if metadata.is_file() {
            if metadata.len() > MAX_BUNDLE_FILE_BYTES {
                bail!("bundle input file exceeds size cap: {}", path.display());
            }
            let relative_path = bundle_relative_path(root, &path)?;
            if matches!(
                relative_path.as_str(),
                "manifest.json" | "manifest.sig.json"
            ) {
                bail!(
                    "bundle input must not contain reserved file {}",
                    relative_path
                );
            }
            let bytes =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BUNDLE_FILE_BYTES {
                bail!("bundle input file exceeds size cap: {}", path.display());
            }
            let sha256 = sha256_uri(&bytes);
            files.push(BundleInputFile {
                relative_path,
                bytes,
                sha256,
            });
        }
    }
    Ok(())
}

fn bundle_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| anyhow!("bundle path is not valid UTF-8: {}", path.display()))?;
                if part.is_empty() || part == "." || part == ".." {
                    bail!("bundle path is not normalized: {}", path.display());
                }
                parts.push(part.to_string());
            }
            _ => bail!("bundle path is not normalized: {}", path.display()),
        }
    }
    if parts.is_empty() {
        bail!("bundle path is empty: {}", path.display());
    }
    Ok(parts.join("/"))
}

fn primary_config_path(product: &str, files: &[BundleInputFile]) -> Result<String> {
    let expected = match product {
        "registry-notary" => Some("config/notary.yaml"),
        "registry-relay" => Some("config/relay.yaml"),
        _ => None,
    };
    if let Some(expected) = expected {
        if files.iter().any(|file| file.relative_path == expected) {
            return Ok(expected.to_string());
        }
    }
    if files.len() == 1 {
        return Ok(files[0].relative_path.clone());
    }
    bail!(
        "bundle input has multiple files; expected primary config path {}",
        expected.unwrap_or("as the only regular file")
    )
}

fn read_private_jwk_text(key_ref: &str) -> Result<String> {
    if key_ref.starts_with("op://") {
        let output = Command::new("op")
            .arg("read")
            .arg(key_ref)
            .output()
            .context("failed to run op read for bundle signing key")?;
        if !output.status.success() {
            bail!("op read failed for bundle signing key reference");
        }
        return String::from_utf8(output.stdout)
            .context("private JWK returned by op read is not UTF-8 JSON");
    }
    fs::read_to_string(key_ref).with_context(|| format!("failed to read {}", key_ref))
}

fn key_display(key_ref: &str) -> &str {
    if key_ref.starts_with("op://") {
        "op://..."
    } else {
        key_ref
    }
}

fn read_signature_envelope_if_present(
    signature_path: &Path,
) -> Result<Option<ConfigBundleSignatureEnvelope>> {
    match fs::read(signature_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", signature_path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read {}", signature_path.display()))
        }
    }
}

fn read_anchor_unvalidated(anchor_path: &Path) -> Result<ConfigTrustAnchor> {
    let bytes = fs::read(anchor_path)
        .with_context(|| format!("failed to read {}", anchor_path.display()))?;
    let anchor: ConfigTrustAnchor = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", anchor_path.display()))?;
    if anchor.schema != CONFIG_TRUST_ANCHOR_SCHEMA {
        bail!("trust anchor schema is invalid");
    }
    if anchor.product.trim().is_empty()
        || anchor.environment.trim().is_empty()
        || anchor.stream_id.trim().is_empty()
        || anchor.instance_id.trim().is_empty()
    {
        bail!("trust anchor binding fields must be non-empty");
    }
    Ok(anchor)
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let json = serde_json::to_vec_pretty(value).context("failed to render JSON")?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(unix)]
fn write_trust_anchor_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let json = serde_json::to_vec_pretty(value).context("failed to render JSON")?;

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "trust anchor path must not be a symlink: {}",
                    path.display()
                );
            }
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions)
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(&json)
        .with_context(|| format!("failed to write {}", path.display()))?;

    let mut permissions = file
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn write_trust_anchor_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_json_file(path, value)
}

fn anchor_report(anchor_path: &Path, anchor: &ConfigTrustAnchor) -> AnchorReport {
    AnchorReport {
        schema_version: "registryctl.config_anchor.v1".to_string(),
        anchor_path: anchor_path.to_path_buf(),
        product: anchor.product.clone(),
        environment: anchor.environment.clone(),
        stream_id: anchor.stream_id.clone(),
        instance_id: anchor.instance_id.clone(),
        signer_count: anchor.signers.len(),
        enabled_signer_count: anchor
            .signers
            .iter()
            .filter(|signer| signer.enabled)
            .count(),
    }
}

fn signing_algorithm_label(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa => "EdDSA",
        SigningAlgorithm::Es256 => "ES256",
        SigningAlgorithm::Rs256 => "RS256",
    }
}

pub fn init_spreadsheet_api(dir: &Path, sample: Sample) -> Result<()> {
    match sample {
        Sample::Benefits => init_benefits_project(dir),
    }
}

pub fn init_notary_project(dir: &Path, options: NotaryInitOptions) -> Result<()> {
    init_standalone_notary_project(dir, options)
}

pub fn add_notary(project_dir: &Path, from: NotarySource, force: bool) -> Result<()> {
    match from {
        NotarySource::LocalRelay => add_notary_from_local_relay(project_dir, force),
    }
}

pub fn convert_openfn_project(options: OpenFnConvertOptions) -> Result<()> {
    let input = fs::read_to_string(&options.input)
        .with_context(|| format!("failed to read {}", options.input.display()))?;
    let conversion = build_openfn_sidecar_conversion(&input, &options)?;
    write_openfn_sidecar_conversion(&conversion, &options.output, &options.jobs_dir)?;
    write_openfn_notary_snippet(&conversion, &options)?;

    print_openfn_conversion_result(&conversion, &options.output, &options.jobs_dir, &options);
    Ok(())
}

pub fn import_openfn_project(options: OpenFnImportOptions) -> Result<()> {
    let (smoke_field, smoke_value) = parse_openfn_smoke(&options.smoke)?;
    let loaded = load_openfn_import_input(&options)?;
    let workflow = options.workflow.or(loaded.workflow_key);
    let convert_options = OpenFnConvertOptions {
        input: PathBuf::from(&options.input),
        workflow,
        output: options.output,
        jobs_dir: options.jobs_dir,
        expression_prefix: Some(options.expression_prefix),
        source_id: options.source_id,
        dataset: options.dataset,
        entity: options.entity,
        credential_env: options.credential_env,
        allowed_base_urls: options.allowed_base_urls,
        smoke_field,
        smoke_value,
        smoke_fields: options.smoke_fields,
        smoke_purpose: options.smoke_purpose,
        auth_hash_env: options.auth_hash_env,
        server_bind: options.server_bind,
        cli_build_tool: options.cli_build_tool,
        runtime: options.runtime,
        worker_command: options.worker_command,
        worker_script: options.worker_script,
        max_workers: options.max_workers,
        worker_timeout_ms: options.worker_timeout_ms,
        max_worker_memory_mb: options.max_worker_memory_mb,
        max_output_bytes: options.max_output_bytes,
        max_request_bytes: options.max_request_bytes,
        max_query_parameter_bytes: options.max_query_parameter_bytes,
        max_batch_items: options.max_batch_items,
        batch_mode: options.batch_mode,
        notary_snippet_output: options.notary_snippet_output,
        sidecar_base_url: options.sidecar_base_url,
        sidecar_token_env: options.sidecar_token_env,
        allow_latest_adaptors: options.allow_latest_adaptors,
        allow_empty_job_bodies: options.allow_empty_job_bodies,
    };
    let conversion = build_openfn_sidecar_conversion(&loaded.yaml, &convert_options)?;
    write_openfn_sidecar_conversion(
        &conversion,
        &convert_options.output,
        &convert_options.jobs_dir,
    )?;
    write_openfn_notary_snippet(&conversion, &convert_options)?;
    print_openfn_conversion_result(
        &conversion,
        &convert_options.output,
        &convert_options.jobs_dir,
        &convert_options,
    );
    Ok(())
}

pub fn maybe_warn_about_update(current_version: &str) {
    if update_check_disabled() {
        return;
    }
    let Some(cache_path) = update_check_cache_path() else {
        return;
    };

    let should_refresh = match read_update_check_cache(&cache_path) {
        Ok(Some(cache)) => {
            if is_newer_release(current_version, &cache.latest_tag) {
                eprintln!("{}", update_notice(current_version, &cache.latest_tag));
            }
            !cache.is_fresh
        }
        Ok(None) | Err(_) => true,
    };

    if should_refresh {
        spawn_update_check_refresh();
    }
}

pub fn update_check(current_version: &str) -> Result<()> {
    let latest_tag = fetch_latest_registryctl_release()?;
    if is_newer_release(current_version, &latest_tag) {
        println!("{}", update_notice(current_version, &latest_tag));
    } else {
        println!(
            "registryctl {} is current. Latest release: {}.",
            display_version(current_version),
            latest_tag
        );
    }

    if let Some(cache_path) = update_check_cache_path() {
        let _ = write_update_check_cache(&cache_path, &latest_tag);
    }

    Ok(())
}

pub fn refresh_update_check_cache() -> Result<()> {
    let latest_tag = fetch_latest_registryctl_release()?;
    if let Some(cache_path) = update_check_cache_path() {
        write_update_check_cache(&cache_path, &latest_tag)?;
    }
    Ok(())
}

fn spawn_update_check_refresh() {
    let Ok(current_exe) = std::env::current_exe() else {
        return;
    };
    let _ = Command::new(current_exe)
        .arg("__update-check-refresh")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

fn update_check_disabled() -> bool {
    env_flag_is_set("CI")
        || env_flag_is_set("REGISTRYCTL_NO_UPDATE_CHECK")
        || matches!(
            std::env::var("REGISTRYCTL_UPDATE_CHECK"),
            Ok(value) if value == "0" || value.eq_ignore_ascii_case("false")
        )
}

fn env_flag_is_set(name: &str) -> bool {
    matches!(
        std::env::var(name),
        Ok(value) if !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
    )
}

fn read_update_check_cache(cache_path: &Path) -> Result<Option<CachedLatestRelease>> {
    let raw = match fs::read_to_string(cache_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("failed to read registryctl update check cache"),
    };
    let cache: UpdateCheckCache =
        serde_json::from_str(&raw).context("failed to parse registryctl update check cache")?;
    let now = unix_now();
    Ok(Some(CachedLatestRelease {
        is_fresh: now.saturating_sub(cache.checked_at) <= UPDATE_CHECK_CACHE_SECONDS,
        latest_tag: cache.latest_tag,
    }))
}

fn write_update_check_cache(cache_path: &Path, latest_tag: &str) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let cache = UpdateCheckCache {
        checked_at: unix_now(),
        latest_tag: latest_tag.to_string(),
    };
    let json = serde_json::to_string(&cache).context("failed to render update check cache")?;
    fs::write(cache_path, json).with_context(|| format!("failed to write {}", cache_path.display()))
}

fn update_check_cache_path() -> Option<PathBuf> {
    let cache_home = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(cache_home.join("registryctl").join("update-check.json"))
}

fn fetch_latest_registryctl_release() -> Result<String> {
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build()
        .get(REGISTRYCTL_RELEASES_API)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "registryctl")
        .call()
        .map_err(registryctl_release_http_error)?;
    let body = response
        .into_string()
        .context("failed to read registryctl latest release response")?;
    let latest: GitHubLatestRelease = serde_json::from_str(&body)
        .context("failed to parse registryctl latest release response")?;
    if latest.tag_name.trim().is_empty() {
        bail!("registryctl latest release response did not include tag_name");
    }
    Ok(latest.tag_name)
}

fn registryctl_release_http_error(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            anyhow!(
                "GitHub returned HTTP {status} while checking registryctl releases: {}",
                body.trim()
            )
        }
        ureq::Error::Transport(error) => {
            anyhow!("failed to check registryctl releases: {error}")
        }
    }
}

fn is_newer_release(current_version: &str, latest_tag: &str) -> bool {
    let Some(current) = VersionNumber::parse(current_version) else {
        return false;
    };
    let Some(latest) = VersionNumber::parse(latest_tag) else {
        return false;
    };
    latest > current
}

fn update_notice(current_version: &str, latest_tag: &str) -> String {
    format!(
        "registryctl {latest_tag} is available. You have {}.\nUpgrade with:\n  REGISTRYCTL_VERSION={latest_tag} curl -fsSL {REGISTRYCTL_INSTALL_SCRIPT} | sh",
        display_version(current_version)
    )
}

fn display_version(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Deserialize)]
struct GitHubLatestRelease {
    tag_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateCheckCache {
    checked_at: u64,
    latest_tag: String,
}

#[derive(Debug)]
struct CachedLatestRelease {
    is_fresh: bool,
    latest_tag: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct VersionNumber {
    major: u64,
    minor: u64,
    patch: u64,
}

impl VersionNumber {
    fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim().trim_start_matches('v');
        let without_prerelease = trimmed.split_once('-').map_or(trimmed, |(base, _)| base);
        let base = without_prerelease
            .split_once('+')
            .map_or(without_prerelease, |(base, _)| base);
        let mut parts = base.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

fn write_openfn_sidecar_conversion(
    conversion: &OpenFnSidecarConversion,
    output: &Path,
    jobs_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(jobs_dir)
        .with_context(|| format!("failed to create {}", jobs_dir.display()))?;
    for job_file in &conversion.job_files {
        if let Some(parent) = job_file.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        write_text(job_file.path.clone(), &job_file.contents)?;
    }

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    write_text(output.to_path_buf(), &conversion.manifest_yaml)?;
    Ok(())
}

fn write_openfn_notary_snippet(
    conversion: &OpenFnSidecarConversion,
    options: &OpenFnConvertOptions,
) -> Result<()> {
    let Some(output) = &options.notary_snippet_output else {
        return Ok(());
    };
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    write_text(output.to_path_buf(), &conversion.notary_snippet_yaml)
}

fn print_openfn_conversion_result(
    conversion: &OpenFnSidecarConversion,
    output: &Path,
    jobs_dir: &Path,
    options: &OpenFnConvertOptions,
) {
    for warning in &conversion.warnings {
        eprintln!("WARN {warning}");
    }
    println!("OpenFn workflow: {}", conversion.workflow_key);
    println!("Sidecar manifest: {}", output.display());
    println!("Job expressions: {}", jobs_dir.display());
    println!("Batch mode: {}", options.batch_mode.as_yaml_str());
    if let Some(path) = &options.notary_snippet_output {
        println!("Notary config snippet: {}", path.display());
    }
}

pub fn start_project(project_dir: &Path) -> Result<()> {
    start_project_with_timeout(project_dir, Duration::from_secs(60))
}

fn start_project_with_timeout(project_dir: &Path, timeout: Duration) -> Result<()> {
    let project = Project::load(project_dir)?;
    validate_project_fingerprints(project_dir, &project)?;
    validate_notary_fingerprint(project_dir, &project)?;
    run_compose_for_project(project_dir, &project, &["up", "-d"])?;
    if project.relay.is_some() {
        let relay_base_url = project.relay_base_url()?;
        wait_for_ready("Relay", relay_base_url, timeout)?;
        println!("Relay API:  {relay_base_url}");
        println!("API docs:   {relay_base_url}{RELAY_DOCS_PATH}");
    }
    if project.notary.is_some() {
        let notary_base_url = project.notary_base_url()?;
        wait_for_ready("Notary", notary_base_url, timeout)?;
        println!("Notary API: {notary_base_url}");
        println!("API docs:   {notary_base_url}{NOTARY_DOCS_PATH}");
    }
    Ok(())
}

pub fn stop_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    run_compose_for_project(project_dir, &project, &["down"])?;
    Ok(())
}

/// Stops and starts the project so edits to the bind-mounted config files
/// take effect; a plain `start` leaves an already-running container as is.
pub fn restart_project(project_dir: &Path) -> Result<()> {
    stop_project(project_dir)?;
    start_project(project_dir)
}

pub fn status_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    run_compose_for_project(project_dir, &project, &["ps"])?;
    if project.relay.is_some() {
        let relay_base_url = project.relay_base_url()?;
        print_probe_status("healthz", &format!("{relay_base_url}/healthz"));
        print_probe_status("ready", &format!("{relay_base_url}/ready"));
        println!("Relay API:  {relay_base_url}");
        println!("API docs:   {relay_base_url}{RELAY_DOCS_PATH}");
    }
    if project.notary.is_some() {
        let notary_base_url = project.notary_base_url()?;
        print_probe_status("notary healthz", &format!("{notary_base_url}/healthz"));
        print_probe_status("notary ready", &format!("{notary_base_url}/ready"));
        println!("Notary API: {notary_base_url}");
        println!("API docs:   {notary_base_url}{NOTARY_DOCS_PATH}");
    }
    Ok(())
}

pub fn open_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    if project.relay.is_none() {
        return notary_open_project(project_dir);
    }
    let docs_url = format!("{}{}", project.relay_base_url()?, RELAY_DOCS_PATH);
    // Always surface the URL: `open` reports success even in headless macOS
    // sessions where nothing actually launches, so a conditional fallback would
    // silently print nothing. Then best-effort open a browser for desktops.
    for line in relay_open_lines(&docs_url) {
        println!("{line}");
    }
    let _ = Command::new("open").arg(&docs_url).status();
    Ok(())
}

fn relay_open_lines(docs_url: &str) -> Vec<String> {
    vec![docs_url.to_string()]
}

pub fn logs_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    run_compose_for_project(project_dir, &project, &["logs"])?;
    Ok(())
}

pub fn smoke_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    let relay_base_url = project.relay_base_url()?;
    validate_project_fingerprints(project_dir, &project)?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let report = run_smoke_checks(relay_base_url, &secrets);
    let output_path = project_dir
        .join(project.local.output_dir)
        .join("smoke-results.json");
    fs::create_dir_all(output_path.parent().unwrap_or(project_dir))?;
    let json =
        serde_json::to_string_pretty(&report).context("failed to render smoke result JSON")?;
    parse_smoke_report(&json)?;
    write_text(output_path, &json)?;

    for check in &report.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        println!("{status} {}", check.name);
    }

    if report.passed {
        Ok(())
    } else {
        bail!("one or more smoke checks failed")
    }
}

pub fn notary_smoke_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    validate_project_fingerprints(project_dir, &project)?;
    validate_notary_fingerprint(project_dir, &project)?;
    let notary_base_url = project.notary_base_url()?.to_string();
    let claim_id = project.notary_claim_id();
    let smoke_target = project
        .notary
        .as_ref()
        .map(|notary| notary_smoke_target_json(notary, notary_smoke_target_id(notary)))
        .unwrap_or_else(|| {
            NotaryInitSourceKind::RegistryDataApi.smoke_target_json("per-2001", "person")
        });
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let report = run_notary_smoke_checks(&notary_base_url, &secrets, &claim_id, smoke_target);
    let output_path = project_dir
        .join(&project.local.output_dir)
        .join("notary-smoke-results.json");
    fs::create_dir_all(output_path.parent().unwrap_or(project_dir))?;
    let json =
        serde_json::to_string_pretty(&report).context("failed to render notary smoke JSON")?;
    parse_smoke_report(&json)?;
    write_text(output_path, &json)?;

    for check in &report.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        println!("{status} {}", check.name);
    }

    if report.passed {
        Ok(())
    } else {
        bail!("one or more Notary smoke checks failed")
    }
}

pub fn notary_open_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    let notary_base_url = project.notary_base_url()?;
    let docs_url = format!("{notary_base_url}{NOTARY_DOCS_PATH}");
    // Always surface the URLs: `open` reports success even in headless macOS
    // sessions where nothing actually launches, so a conditional fallback would
    // silently print nothing. Then best-effort open a browser for desktops.
    for line in notary_open_lines(notary_base_url) {
        println!("{line}");
    }
    let _ = Command::new("open").arg(&docs_url).status();
    Ok(())
}

fn notary_open_lines(notary_base_url: &str) -> Vec<String> {
    vec![
        format!("Notary API docs: {notary_base_url}{NOTARY_DOCS_PATH}"),
        format!("OpenAPI JSON: {notary_base_url}{NOTARY_OPENAPI_PATH}"),
    ]
}

pub fn bruno_generate_project(project_dir: &Path, force: bool) -> Result<()> {
    let project = Project::load(project_dir)?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    let files = bruno_files(&project, &secrets)?;
    write_generated_files(project_dir, &collection_dir, files, force)?;
    println!("Bruno collection: {}", collection_dir.display());
    Ok(())
}

pub fn bruno_open_project(project_dir: &Path) -> Result<()> {
    Project::load(project_dir)?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    if !collection_dir.exists() {
        println!("Bruno collection has not been generated yet. Run `registryctl bruno generate`.");
        return Ok(());
    }

    let open_result = Command::new("open")
        .arg("-a")
        .arg("Bruno")
        .arg(&collection_dir)
        .status();
    if matches!(open_result, Ok(status) if status.success()) {
        return Ok(());
    }

    println!("Bruno collection generated at:");
    println!("  {}", collection_dir.display());
    println!("Install Bruno to open it visually:");
    println!("  https://www.usebruno.com/downloads");
    println!("The API still works without Bruno:");
    println!("  registryctl smoke");
    println!("  registryctl notary smoke");
    Ok(())
}

pub fn bruno_run_project(project_dir: &Path) -> Result<()> {
    Project::load(project_dir)?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    let env_file = collection_dir.join("environments/local.bru");
    if !collection_dir.exists() || !env_file.exists() {
        println!("Bruno collection has not been generated yet. Run `registryctl bruno generate`.");
        return Ok(());
    }

    let status = Command::new("bru")
        .arg("run")
        .arg("--env-file")
        .arg("environments/local.bru")
        .current_dir(&collection_dir)
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("bru run exited with {status}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("Bruno CLI `bru` is not installed.");
            println!("Install Bruno CLI to run the collection from the terminal:");
            println!("  https://docs.usebruno.com/bru-cli/overview");
            println!("The API still works without Bruno:");
            println!("  registryctl smoke");
            println!("  registryctl notary smoke");
            Ok(())
        }
        Err(err) => Err(err).context("failed to run bru"),
    }
}

pub fn doctor_project(
    project_dir: &Path,
    format: DoctorFormat,
    deployment_profile: Option<DeploymentProfile>,
) -> Result<()> {
    let report = run_doctor_report_with_path(project_dir, format, deployment_profile, None)?;
    let json =
        serde_json::to_string_pretty(&report).context("failed to render doctor report JSON")?;
    println!("{json}");
    ensure_doctor_report_ok(&report)
}

struct ProductDoctorInvocation {
    product: &'static str,
    binary: &'static str,
    cwd: PathBuf,
    config_path: PathBuf,
    args: Vec<String>,
}

fn run_doctor_report_with_path(
    project_dir: &Path,
    format: DoctorFormat,
    deployment_profile: Option<DeploymentProfile>,
    path: Option<&Path>,
) -> Result<DoctorReport> {
    match format {
        DoctorFormat::Json => {}
    }
    let project = Project::load(project_dir)?;
    let secrets_path = project_dir.join(&project.local.secrets_env);
    let secrets = LocalEnv::load(&secrets_path)?;
    let redactor = SecretRedactor::new(&secrets);
    let generated_at = rfc3339_now();
    let products = product_doctor_invocations(project_dir, &project, deployment_profile)?
        .into_iter()
        .map(|invocation| {
            run_product_doctor(
                invocation,
                path.map(Path::as_os_str),
                &redactor,
                &generated_at,
            )
        })
        .collect::<Vec<_>>();
    Ok(RegistryctlValidationReport {
        schema_version: REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1.to_string(),
        project: RegistryctlProjectRef {
            path: project_dir.display().to_string(),
            profile: deployment_profile
                .map_or("project", DeploymentProfile::as_str)
                .to_string(),
        },
        status: registryctl_report_status(&products),
        products,
        cross_product_diagnostics: Vec::new(),
        generated_at,
    })
}

type DoctorReport = RegistryctlValidationReport;

fn ensure_doctor_report_ok(report: &DoctorReport) -> Result<()> {
    if report
        .products
        .iter()
        .all(|product| matches!(product.status, ReportStatus::Ok | ReportStatus::Warning))
    {
        Ok(())
    } else {
        bail!("one or more product doctor checks failed")
    }
}

fn registryctl_report_status(products: &[RegistryctlProductReport]) -> ReportStatus {
    if products
        .iter()
        .any(|product| matches!(product.status, ReportStatus::Error | ReportStatus::NotRun))
    {
        ReportStatus::Error
    } else if products
        .iter()
        .any(|product| product.status == ReportStatus::Warning)
    {
        ReportStatus::Warning
    } else {
        ReportStatus::Ok
    }
}

fn rfc3339_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn product_doctor_invocations(
    project_dir: &Path,
    project: &Project,
    deployment_profile: Option<DeploymentProfile>,
) -> Result<Vec<ProductDoctorInvocation>> {
    let env_file = project_dir.join(&project.local.secrets_env);
    let mut invocations = Vec::new();
    if let Some(relay) = &project.relay {
        let config = relay_doctor_config_path(project_dir, project, relay)?;
        invocations.push(ProductDoctorInvocation {
            product: "registry-relay",
            binary: "registry-relay",
            cwd: project_dir.to_path_buf(),
            config_path: config.clone(),
            args: product_doctor_args(config, &env_file, deployment_profile),
        });
    }
    if let Some(notary) = &project.notary {
        let config = project_dir.join(&notary.config);
        invocations.push(ProductDoctorInvocation {
            product: "registry-notary",
            binary: "registry-notary",
            cwd: project_dir.to_path_buf(),
            config_path: config.clone(),
            args: product_doctor_args(config, &env_file, deployment_profile),
        });
    }
    Ok(invocations)
}

fn relay_doctor_config_path(
    project_dir: &Path,
    project: &Project,
    relay: &ProjectRelay,
) -> Result<PathBuf> {
    let config_path = project_dir.join(&relay.config);
    if relay.metadata.is_none() && relay.data.is_empty() {
        return Ok(config_path);
    }

    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    if let Some(metadata) = &relay.metadata {
        set_yaml_path_string(
            &mut value,
            &["metadata", "source", "path"],
            project_dir.join(metadata).display().to_string(),
        );
    }
    rewrite_relay_container_data_paths(&mut value, project_dir, relay);

    let output_dir = project_dir.join(&project.local.output_dir).join("doctor");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;
    let doctor_config = output_dir.join("relay.config.yaml");
    let rendered = serde_yaml::to_string(&value).context("failed to render Relay doctor config")?;
    write_text(doctor_config.clone(), &rendered)?;
    Ok(doctor_config)
}

fn set_yaml_path_string(value: &mut serde_yaml::Value, path: &[&str], replacement: String) {
    let mut current = value;
    for segment in &path[..path.len().saturating_sub(1)] {
        let serde_yaml::Value::Mapping(map) = current else {
            return;
        };
        let key = serde_yaml::Value::String((*segment).to_string());
        let Some(next) = map.get_mut(&key) else {
            return;
        };
        current = next;
    }
    let Some(last) = path.last() else {
        return;
    };
    if let serde_yaml::Value::Mapping(map) = current {
        map.insert(
            serde_yaml::Value::String((*last).to_string()),
            serde_yaml::Value::String(replacement),
        );
    }
}

fn rewrite_relay_container_data_paths(
    value: &mut serde_yaml::Value,
    project_dir: &Path,
    relay: &ProjectRelay,
) {
    match value {
        serde_yaml::Value::String(text) => {
            const PREFIX: &str = "/var/lib/registry-relay/data/";
            if let Some(relative) = text.strip_prefix(PREFIX) {
                let host_path = relay
                    .data
                    .iter()
                    .find(|path| path.ends_with(relative))
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("data").join(relative));
                *text = project_dir.join(host_path).display().to_string();
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                rewrite_relay_container_data_paths(item, project_dir, relay);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for value in map.values_mut() {
                rewrite_relay_container_data_paths(value, project_dir, relay);
            }
        }
        _ => {}
    }
}

fn product_doctor_args(
    config: PathBuf,
    env_file: &Path,
    deployment_profile: Option<DeploymentProfile>,
) -> Vec<String> {
    let mut args = vec![
        "doctor".to_string(),
        "--config".to_string(),
        config.display().to_string(),
        "--env-file".to_string(),
        env_file.display().to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if let Some(profile) = deployment_profile {
        args.push("--profile".to_string());
        args.push(profile.as_str().to_string());
    }
    args
}

fn run_product_doctor(
    invocation: ProductDoctorInvocation,
    path: Option<&OsStr>,
    redactor: &SecretRedactor,
    generated_at: &str,
) -> RegistryctlProductReport {
    let mut command = Command::new(invocation.binary);
    command.args(&invocation.args);
    command.current_dir(&invocation.cwd);
    if let Some(path) = path {
        command.env("PATH", path);
    }
    match command.output() {
        Ok(output) => product_report_from_output(invocation, output, redactor, generated_at),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => RegistryctlProductReport {
            product: invocation.product.to_string(),
            status: ReportStatus::NotRun,
            report: fallback_product_report(
                invocation.product,
                &invocation.config_path,
                ReportStatus::NotRun,
                "registryctl.product_doctor.binary_missing",
                DiagnosticSeverity::Error,
                format!(
                    "Install {} and ensure it is on PATH, then rerun `registryctl doctor --format json`.",
                    invocation.binary
                ),
                generated_at,
            ),
        },
        Err(err) => RegistryctlProductReport {
            product: invocation.product.to_string(),
            status: ReportStatus::Error,
            report: fallback_product_report(
                invocation.product,
                &invocation.config_path,
                ReportStatus::Error,
                "registryctl.product_doctor.start_failed",
                DiagnosticSeverity::Error,
                format!("failed to run {}: {err}", invocation.binary),
                generated_at,
            ),
        },
    }
}

fn product_report_from_output(
    invocation: ProductDoctorInvocation,
    output: Output,
    redactor: &SecretRedactor,
    generated_at: &str,
) -> RegistryctlProductReport {
    let stdout = redactor.redact_output(&output.stdout);
    let stderr = redactor.redact_output(&output.stderr);
    let passed = output.status.success();
    if let Some(report) = stdout.as_deref().and_then(parse_product_report) {
        let status = if passed {
            report.status
        } else {
            ReportStatus::Error
        };
        return RegistryctlProductReport {
            product: invocation.product.to_string(),
            status,
            report,
        };
    }

    let (code, message) = if passed {
        (
            "registryctl.product_doctor.report_missing",
            "product doctor exited successfully but did not emit a JSON diagnostic report"
                .to_string(),
        )
    } else {
        (
            "registryctl.product_doctor.report_missing_after_failure",
            format!(
                "product doctor exited nonzero without a JSON diagnostic report; exit_code={:?}; stdout_present={}; stderr_present={}",
                output.status.code(),
                stdout.is_some(),
                stderr.is_some()
            ),
        )
    };
    RegistryctlProductReport {
        product: invocation.product.to_string(),
        status: ReportStatus::Error,
        report: fallback_product_report(
            invocation.product,
            &invocation.config_path,
            ReportStatus::Error,
            code,
            DiagnosticSeverity::Error,
            message,
            generated_at,
        ),
    }
}

fn parse_product_report(stdout: &str) -> Option<ConfigDiagnosticReport> {
    serde_json::from_str(stdout).ok()
}

fn fallback_product_report(
    product: &str,
    config_path: &Path,
    status: ReportStatus,
    code: &str,
    severity: DiagnosticSeverity,
    message: String,
    generated_at: &str,
) -> ConfigDiagnosticReport {
    let diagnostics = vec![ConfigDiagnostic {
        code: code.to_string(),
        severity,
        path: None,
        message,
        replacement: None,
        documentation_key: None,
    }];
    ConfigDiagnosticReport {
        schema_version: "registry.config.diagnostic_report.v1".to_string(),
        product: product.to_string(),
        config_schema_version: product_config_schema_version(product).to_string(),
        source: ConfigSourceRef {
            kind: ConfigSourceKind::GeneratedFile,
            path: Some(config_path.display().to_string()),
            uri: None,
        },
        status,
        summary: diagnostic_summary(&diagnostics),
        diagnostics,
        required_env: Vec::new(),
        context_constraints: Vec::new(),
        hashes: None,
        generated_at: generated_at.to_string(),
    }
}

fn product_config_schema_version(product: &str) -> &'static str {
    match product {
        "registry-relay" => "registry.relay.config.v1",
        "registry-notary" => "registry.notary.config.v1",
        _ => "registry.config.unknown.v1",
    }
}

fn diagnostic_summary(diagnostics: &[ConfigDiagnostic]) -> DiagnosticSummary {
    DiagnosticSummary {
        error_count: diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .count() as u64,
        warning_count: diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
            .count() as u64,
    }
}

struct SecretRedactor {
    secrets: Vec<String>,
}

impl SecretRedactor {
    fn new(secrets: &LocalEnv) -> Self {
        let mut secrets = secrets
            .values
            .values()
            .filter(|value| !value.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        secrets.sort();
        secrets.dedup();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self { secrets }
    }

    fn redact_output(&self, bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }
        let mut output = String::from_utf8_lossy(bytes).into_owned();
        for secret in &self.secrets {
            output = output.replace(secret, "[REDACTED]");
        }
        Some(output)
    }
}

fn init_benefits_project(dir: &Path) -> Result<()> {
    if dir.exists() {
        let mut entries =
            fs::read_dir(dir).with_context(|| format!("failed to inspect {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "target directory already exists and is not empty: {}",
                dir.display()
            );
        }
    }

    fs::create_dir_all(dir.join("relay"))?;
    fs::create_dir_all(dir.join("data"))?;
    fs::create_dir_all(dir.join("secrets"))?;
    fs::create_dir_all(dir.join("output"))?;
    create_relay_state_dirs(dir)?;
    write_compose_runtime_env(dir)?;

    let credentials = LocalCredentials::generate()?;
    write_text(
        dir.join("registryctl.yaml"),
        &registryctl_manifest(dir, ProjectManifestKind::Relay)?,
    )?;
    write_text(dir.join("compose.yaml"), &compose_yaml(false))?;
    write_text(dir.join("README.md"), project_readme())?;
    write_text(dir.join(".gitignore"), include_str!("templates/gitignore"))?;
    write_text(dir.join("relay/config.yaml"), &relay_config(&credentials))?;
    write_text(dir.join("secrets/local.env"), &credentials.env_file())?;
    write_text(dir.join("output/.gitkeep"), "")?;
    sample::write_benefits_workbook(&dir.join("data/benefits_casework.xlsx"))?;
    bruno_generate_project(dir, false)?;
    Ok(())
}

fn init_standalone_notary_project(dir: &Path, options: NotaryInitOptions) -> Result<()> {
    if dir.exists() {
        let mut entries =
            fs::read_dir(dir).with_context(|| format!("failed to inspect {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "target directory already exists and is not empty: {}",
                dir.display()
            );
        }
    }

    fs::create_dir_all(dir.join("notary"))?;
    fs::create_dir_all(dir.join("secrets"))?;
    fs::create_dir_all(dir.join("output"))?;
    create_notary_state_dirs(dir)?;
    write_compose_runtime_env(dir)?;

    if !options.source_kind.uses_static_source_token() && options.source_token_from_env.is_some() {
        bail!(
            "--source-token-from-env is not used with --source-kind {}; configure DCI_CLIENT_ID and DCI_CLIENT_SECRET in secrets/local.env",
            options.source_kind.source_label()
        );
    }
    let source_token = if options.source_kind.uses_static_source_token() {
        match &options.source_token_from_env {
            Some(env_name) => std::env::var(env_name)
                .with_context(|| format!("failed to read source token from ${env_name}"))?,
            None => STANDALONE_SOURCE_TOKEN_PLACEHOLDER.to_string(),
        }
    } else {
        STANDALONE_SOURCE_TOKEN_PLACEHOLDER.to_string()
    };
    let notary_credentials = NotaryLocalCredentials::generate(source_token)?;

    write_text(
        dir.join("registryctl.yaml"),
        &registryctl_manifest(
            dir,
            ProjectManifestKind::StandaloneNotary { options: &options },
        )?,
    )?;
    write_text(
        dir.join("compose.yaml"),
        &compose_notary_only_yaml(options.source_network.as_deref()),
    )?;
    write_text(dir.join("README.md"), standalone_notary_readme())?;
    write_text(dir.join(".gitignore"), include_str!("templates/gitignore"))?;
    write_text(
        dir.join("notary/config.yaml"),
        &notary_config_for_source(&notary_credentials.evaluator, &options),
    )?;
    write_text(
        dir.join("secrets/local.env"),
        &standalone_notary_env_file(&notary_credentials, &options),
    )?;
    write_text(dir.join("output/.gitkeep"), "")?;
    bruno_generate_project(dir, false)?;
    Ok(())
}

fn add_notary_from_local_relay(project_dir: &Path, force: bool) -> Result<()> {
    let project = Project::load(project_dir)?;
    let notary_config_path = project_dir.join("notary/config.yaml");
    if project.notary.is_some() && !force {
        bail!("project already has a Notary section; rerun with --force to overwrite generated Notary files");
    }
    if notary_config_path.exists() && !force {
        bail!(
            "{} already exists; rerun with --force to overwrite generated Notary files",
            notary_config_path.display()
        );
    }

    let secrets_path = project_dir.join(&project.local.secrets_env);
    let secrets_contents = fs::read_to_string(&secrets_path)
        .with_context(|| format!("failed to read {}", secrets_path.display()))?;
    let secrets = LocalEnv {
        values: parse_local_env(&secrets_contents),
    };
    let relay_row_reader = secrets.required("ROW_READER_RAW").with_context(|| {
        "cannot add Notary because secrets/local.env is missing ROW_READER_RAW; recreate the Relay project or restore the generated row-reader key"
    })?;

    fs::create_dir_all(project_dir.join("notary"))?;
    create_relay_state_dirs(project_dir)?;
    create_notary_state_dirs(project_dir)?;
    write_compose_runtime_env(project_dir)?;
    ensure_gitignore_entries(project_dir, &[".env", "state/"])?;
    let notary_credentials = NotaryLocalCredentials::generate(relay_row_reader.to_string())?;
    write_text(
        notary_config_path,
        &notary_config(&notary_credentials.evaluator),
    )?;
    write_text(
        project_dir.join("registryctl.yaml"),
        &registryctl_manifest(project_dir, ProjectManifestKind::RelayWithNotary)?,
    )?;
    write_text(project_dir.join("compose.yaml"), &compose_yaml(true))?;
    write_text(
        secrets_path,
        &upsert_env_values(&secrets_contents, &notary_credentials.env_values()),
    )?;
    bruno_generate_project(project_dir, false)?;
    Ok(())
}

fn write_text(path: PathBuf, contents: &str) -> Result<()> {
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn create_relay_state_dirs(dir: &Path) -> Result<()> {
    create_state_dirs(
        dir,
        &[
            "state",
            "state/relay",
            "state/relay/cache",
            "state/relay/config-state",
            "state/relay/audit",
        ],
    )
}

fn create_notary_state_dirs(dir: &Path) -> Result<()> {
    create_state_dirs(
        dir,
        &[
            "state",
            "state/notary",
            "state/notary/config-state",
            "state/notary/audit",
        ],
    )
}

fn create_state_dirs(dir: &Path, paths: &[&str]) -> Result<()> {
    #[cfg(unix)]
    let identity = compose_runtime_identity_values(dir)?;

    for path in paths {
        let path = dir.join(path);
        create_private_dir_all(&path)?;
        #[cfg(unix)]
        ensure_private_state_owner(&path, identity)?;
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct RuntimeIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
fn compose_runtime_identity_values(dir: &Path) -> Result<RuntimeIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::metadata(dir).with_context(|| format!("failed to stat {}", dir.display()))?;
    Ok(runtime_identity_for_owner(metadata.uid(), metadata.gid()))
}

#[cfg(unix)]
fn runtime_identity_for_owner(uid: u32, gid: u32) -> RuntimeIdentity {
    let default_id = DEFAULT_NONROOT_CONTAINER_ID
        .parse()
        .expect("default nonroot container id is numeric");
    RuntimeIdentity {
        uid: if uid == 0 { default_id } else { uid },
        gid: if gid == 0 { default_id } else { gid },
    }
}

#[cfg(unix)]
fn ensure_private_state_owner(path: &Path, identity: RuntimeIdentity) -> Result<()> {
    use std::os::unix::fs::{lchown, MetadataExt};

    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.uid() == identity.uid {
        return Ok(());
    }

    lchown(path, Some(identity.uid), Some(identity.gid)).with_context(|| {
        format!(
            "failed to set owner of {} to {}:{}",
            path.display(),
            identity.uid,
            identity.gid
        )
    })?;
    Ok(())
}

fn write_compose_runtime_env(dir: &Path) -> Result<()> {
    let path = dir.join(".env");
    let values = compose_runtime_env_values(dir)?;
    let body = if path.exists() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        upsert_env_values(&contents, &values)
    } else {
        format!(
            "# Generated by registryctl. Docker Compose uses these values to run product\n\
             # containers as the project runtime owner so private state directories stay writable.\n\
             {REGISTRY_STACK_RUNTIME_UID_ENV}={}\n\
             {REGISTRY_STACK_RUNTIME_GID_ENV}={}\n",
            values[0].1, values[1].1
        )
    };
    write_text(path, &body)
}

fn ensure_gitignore_entries(dir: &Path, entries: &[&str]) -> Result<()> {
    let path = dir.join(".gitignore");
    let mut contents = if path.exists() {
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    let missing: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|entry| !contents.lines().any(|line| line.trim() == *entry))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    for entry in missing {
        contents.push_str(entry);
        contents.push('\n');
    }
    write_text(path, &contents)
}

fn compose_runtime_env_values(dir: &Path) -> Result<Vec<(String, String)>> {
    let (uid, gid) = compose_runtime_identity(dir)?;
    Ok(vec![
        (REGISTRY_STACK_RUNTIME_UID_ENV.to_string(), uid),
        (REGISTRY_STACK_RUNTIME_GID_ENV.to_string(), gid),
    ])
}

#[cfg(unix)]
fn compose_runtime_identity(dir: &Path) -> Result<(String, String)> {
    let identity = compose_runtime_identity_values(dir)?;
    Ok((identity.uid.to_string(), identity.gid.to_string()))
}

#[cfg(not(unix))]
fn compose_runtime_identity(_dir: &Path) -> Result<(String, String)> {
    Ok((
        DEFAULT_NONROOT_CONTAINER_ID.to_string(),
        DEFAULT_NONROOT_CONTAINER_ID.to_string(),
    ))
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;

    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "state directory path must not be a symlink: {}",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!(
            "state directory path must be a directory: {}",
            path.display()
        );
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn create_private_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    if !path.is_dir() {
        bail!(
            "state directory path must be a directory: {}",
            path.display()
        );
    }
    Ok(())
}

#[derive(Debug)]
struct OpenFnSidecarConversion {
    workflow_key: String,
    manifest_yaml: String,
    notary_snippet_yaml: String,
    job_files: Vec<OpenFnJobFile>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct OpenFnJobFile {
    path: PathBuf,
    contents: String,
}

#[derive(Debug)]
struct LoadedOpenFnImport {
    yaml: String,
    workflow_key: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct OpenFnWorkflowUrl {
    project_id: String,
    workflow_id: Option<String>,
    project_yaml_url: String,
    workflow_json_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenFnProjectExport {
    #[serde(default)]
    workflows: BTreeMap<String, OpenFnWorkflowExport>,
}

#[derive(Debug, Deserialize)]
struct OpenFnWorkflowExport {
    #[serde(default)]
    jobs: BTreeMap<String, OpenFnJobExport>,
    #[serde(default)]
    triggers: BTreeMap<String, OpenFnTriggerExport>,
    #[serde(default)]
    edges: BTreeMap<String, OpenFnEdgeExport>,
}

#[derive(Debug, Deserialize)]
struct OpenFnJobExport {
    #[serde(default)]
    adaptor: String,
    #[serde(default)]
    credential: Option<serde_yaml::Value>,
    #[serde(default)]
    body: String,
}

#[derive(Debug, Deserialize)]
struct OpenFnTriggerExport {
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct OpenFnEdgeExport {
    #[serde(default)]
    source_trigger: Option<String>,
    #[serde(default)]
    source_job: Option<String>,
    target_job: String,
    #[serde(default)]
    condition_type: Option<String>,
    #[serde(default)]
    condition_expression: Option<String>,
    #[serde(default)]
    condition_label: Option<String>,
    #[serde(default = "default_openfn_edge_enabled")]
    enabled: bool,
}

fn default_openfn_edge_enabled() -> bool {
    true
}

fn load_openfn_import_input(options: &OpenFnImportOptions) -> Result<LoadedOpenFnImport> {
    if let Some(openfn_url) = parse_openfn_workflow_url(&options.input)? {
        let token = std::env::var(&options.openfn_token_env).with_context(|| {
            format!(
                "failed to read OpenFn API token from ${}",
                options.openfn_token_env
            )
        })?;
        let yaml = fetch_openfn_text(&openfn_url.project_yaml_url, &token, "text/yaml")
            .with_context(|| format!("failed to fetch {}", openfn_url.project_yaml_url))?;
        let workflow_key = if options.workflow.is_some() {
            None
        } else {
            match openfn_url.workflow_json_url.as_deref() {
                Some(workflow_url) => Some(
                    fetch_openfn_workflow_key(workflow_url, &token).with_context(|| {
                        "failed to infer OpenFn workflow key from URL; pass --workflow <yaml-workflow-key> to skip workflow metadata lookup"
                    })?,
                ),
                None => None,
            }
        };
        return Ok(LoadedOpenFnImport { yaml, workflow_key });
    }

    let input = PathBuf::from(&options.input);
    let yaml = fs::read_to_string(&input)
        .with_context(|| format!("failed to read {}", input.display()))?;
    Ok(LoadedOpenFnImport {
        yaml,
        workflow_key: None,
    })
}

fn parse_openfn_workflow_url(input: &str) -> Result<Option<OpenFnWorkflowUrl>> {
    let Ok(url) = url::Url::parse(input) else {
        return Ok(None);
    };
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    if !host.ends_with("openfn.org") {
        return Ok(None);
    }
    let segments = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let Some(project_index) = segments.iter().position(|segment| *segment == "projects") else {
        return Ok(None);
    };
    let Some(project_id) = segments.get(project_index + 1) else {
        bail!("OpenFn URL is missing the project id after /projects/");
    };
    let workflow_id = segments
        .iter()
        .position(|segment| *segment == "w")
        .and_then(|index| segments.get(index + 1))
        .map(|value| (*value).to_string());

    let origin = url
        .origin()
        .ascii_serialization()
        .trim_end_matches('/')
        .to_string();
    let project_yaml_url = format!("{origin}/api/provision/{project_id}.yaml");
    let workflow_json_url = workflow_id
        .as_ref()
        .map(|workflow_id| format!("{origin}/api/workflows/{workflow_id}?project_id={project_id}"));

    Ok(Some(OpenFnWorkflowUrl {
        project_id: (*project_id).to_string(),
        workflow_id,
        project_yaml_url,
        workflow_json_url,
    }))
}

fn fetch_openfn_text(url: &str, token: &str, accept: &str) -> Result<String> {
    let response = ureq::get(url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", accept)
        .call()
        .map_err(openfn_http_error)?;
    response
        .into_string()
        .context("failed to read OpenFn response body")
}

fn fetch_openfn_workflow_key(url: &str, token: &str) -> Result<String> {
    let body = fetch_openfn_text(url, token, "application/json")
        .with_context(|| format!("failed to fetch workflow metadata from {url}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&body).context("failed to parse OpenFn workflow metadata JSON")?;
    let name = value
        .get("workflow")
        .and_then(|workflow| workflow.get("name"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("OpenFn workflow metadata did not include workflow.name"))?;
    Ok(openfn_yaml_key(name))
}

fn openfn_http_error(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            anyhow!("OpenFn returned HTTP {status}: {}", body.trim())
        }
        ureq::Error::Transport(error) => anyhow!("OpenFn request failed: {error}"),
    }
}

fn parse_openfn_smoke(value: &str) -> Result<(String, String)> {
    let Some((field, lookup_value)) = value.split_once('=') else {
        bail!("--smoke must use field=value syntax");
    };
    let field = field.trim();
    let lookup_value = lookup_value.trim();
    if field.is_empty() || lookup_value.is_empty() {
        bail!("--smoke must include a non-empty field and value");
    }
    Ok((field.to_string(), lookup_value.to_string()))
}

fn openfn_yaml_key(name: &str) -> String {
    name.replace(' ', "-")
}

#[derive(Debug, Serialize)]
struct SidecarManifest {
    server: SidecarServerConfig,
    auth: SidecarAuthConfig,
    limits: SidecarLimitConfig,
    openfn: SidecarOpenFnConfig,
    worker: SidecarWorkerConfig,
    sources: BTreeMap<String, SidecarSourceConfig>,
}

#[derive(Debug, Serialize)]
struct SidecarServerConfig {
    bind: SocketAddr,
    request_timeout_ms: u64,
    request_body_timeout_ms: u64,
    http1_header_read_timeout_ms: u64,
    max_connections: usize,
}

#[derive(Debug, Serialize)]
struct SidecarAuthConfig {
    bearer_tokens: Vec<SidecarBearerTokenConfig>,
}

#[derive(Debug, Serialize)]
struct SidecarBearerTokenConfig {
    id: String,
    hash_env: String,
}

#[derive(Debug, Serialize)]
struct SidecarLimitConfig {
    max_workers: usize,
    worker_timeout_ms: u64,
    max_worker_memory_mb: u64,
    max_output_bytes: usize,
    max_request_bytes: usize,
    max_query_parameter_bytes: usize,
    max_batch_items: usize,
    liveness_window_ms: u64,
    retry_after_seconds: u64,
}

#[derive(Debug, Serialize)]
struct SidecarOpenFnConfig {
    cli_build_tool: String,
    runtime: String,
}

#[derive(Debug, Serialize)]
struct SidecarWorkerConfig {
    command: PathBuf,
    args: Vec<String>,
    version_args: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SidecarSourceConfig {
    dataset: String,
    entity: String,
    engine: &'static str,
    workflow: SidecarWorkflowConfig,
    credential_env: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_base_urls: Vec<String>,
    smoke_lookup: SidecarSmokeLookupConfig,
}

#[derive(Debug, Serialize)]
struct SidecarWorkflowConfig {
    start: String,
    batch_mode: OpenFnBatchMode,
    steps: Vec<SidecarWorkflowStepConfig>,
}

#[derive(Clone, Debug, Serialize)]
struct SidecarWorkflowStepConfig {
    id: String,
    expression: PathBuf,
    adaptors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<BTreeMap<String, SidecarWorkflowEdgeConfig>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum SidecarWorkflowEdgeConfig {
    Enabled(bool),
    Edge(SidecarWorkflowEdgeObjectConfig),
}

#[derive(Clone, Debug, Serialize)]
struct SidecarWorkflowEdgeObjectConfig {
    condition: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct SidecarSmokeLookupConfig {
    field: String,
    value: String,
    fields: Vec<String>,
    purpose: String,
}

type SidecarNextByJob = BTreeMap<String, BTreeMap<String, SidecarWorkflowEdgeConfig>>;

fn build_openfn_sidecar_conversion(
    input: &str,
    options: &OpenFnConvertOptions,
) -> Result<OpenFnSidecarConversion> {
    let (workflow_key, workflow) = select_openfn_workflow(input, options.workflow.as_deref())?;
    validate_openfn_options(options)?;

    if workflow.jobs.is_empty() {
        bail!("OpenFn workflow {workflow_key} has no jobs");
    }

    let mut warnings = Vec::new();
    let mut credential_names = BTreeSet::new();
    let mut has_registry_notary_adaptor = false;
    for (job_key, job) in &workflow.jobs {
        validate_openfn_job(&workflow_key, job_key, job, options)?;
        if adaptor_package_name(&job.adaptor) == Some("@registry/notary-openfn") {
            has_registry_notary_adaptor = true;
        }
        if let Some(credential_name) = yaml_scalar_string(job.credential.as_ref()) {
            if !credential_name.trim().is_empty() {
                credential_names.insert(credential_name.to_string());
            }
        }
    }
    if options.batch_mode == OpenFnBatchMode::Native && !has_registry_notary_adaptor {
        bail!(
            "OpenFn workflow {workflow_key} uses --batch-mode native but does not use @registry/notary-openfn; add the Registry Notary adaptor so OpenFn authoring validates the native batch response shape"
        );
    }
    if has_registry_notary_adaptor {
        warnings.push(
            "Registry Notary OpenFn adaptor detected; lookup and batch response helpers are available in workflow jobs"
                .to_string(),
        );
    }
    if credential_names.len() > 1 {
        bail!(
            "OpenFn workflow {workflow_key} uses multiple job credentials ({:?}); the sidecar source accepts one credential_env JSON for the workflow",
            credential_names
        );
    }
    if let Some(credential_name) = credential_names.first() {
        warnings.push(format!(
            "OpenFn job credential {credential_name} is not copied; sidecar will read {} instead",
            options.credential_env
        ));
    }

    let (start, next_by_job) = convert_openfn_edges(&workflow_key, &workflow)?;
    validate_sidecar_topology(&workflow_key, &workflow.jobs, &start, &next_by_job)?;

    let expression_prefix = options
        .expression_prefix
        .clone()
        .unwrap_or_else(|| options.jobs_dir.clone());
    let mut filenames = BTreeMap::<String, usize>::new();
    let mut job_files = Vec::new();
    let mut steps = Vec::new();
    for (job_key, job) in &workflow.jobs {
        let filename = unique_openfn_job_filename(job_key, &mut filenames);
        let local_expression_path = options.jobs_dir.join(&filename);
        let manifest_expression_path = expression_prefix.join(&filename);
        job_files.push(OpenFnJobFile {
            path: local_expression_path,
            contents: ensure_trailing_newline(&job.body),
        });
        steps.push(SidecarWorkflowStepConfig {
            id: job_key.clone(),
            expression: manifest_expression_path,
            adaptors: vec![job.adaptor.clone()],
            next: next_by_job.get(job_key).cloned(),
        });
    }

    let mut sources = BTreeMap::new();
    sources.insert(
        options.source_id.clone(),
        SidecarSourceConfig {
            dataset: options.dataset.clone(),
            entity: options.entity.clone(),
            engine: "openfn",
            workflow: SidecarWorkflowConfig {
                start,
                batch_mode: options.batch_mode,
                steps,
            },
            credential_env: options.credential_env.clone(),
            allowed_base_urls: options.allowed_base_urls.clone(),
            smoke_lookup: SidecarSmokeLookupConfig {
                field: options.smoke_field.clone(),
                value: options.smoke_value.clone(),
                fields: smoke_fields(options),
                purpose: options.smoke_purpose.clone(),
            },
        },
    );

    let worker_script = options.worker_script.to_string_lossy().to_string();
    let adaptor_args = workflow
        .jobs
        .values()
        .map(|job| job.adaptor.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .flat_map(|adaptor| ["--require-adaptor".to_string(), adaptor.to_string()])
        .collect::<Vec<_>>();
    let mut version_args = vec![
        "--experimental-vm-modules".to_string(),
        worker_script.clone(),
        "--version".to_string(),
    ];
    version_args.extend(adaptor_args);

    let manifest = SidecarManifest {
        server: SidecarServerConfig {
            bind: options
                .server_bind
                .parse()
                .with_context(|| format!("invalid --server-bind {}", options.server_bind))?,
            request_timeout_ms: 30000,
            request_body_timeout_ms: 10000,
            http1_header_read_timeout_ms: 10000,
            max_connections: 1024,
        },
        auth: SidecarAuthConfig {
            bearer_tokens: vec![SidecarBearerTokenConfig {
                id: "notary".to_string(),
                hash_env: options.auth_hash_env.clone(),
            }],
        },
        limits: SidecarLimitConfig {
            max_workers: options.max_workers,
            worker_timeout_ms: options.worker_timeout_ms,
            max_worker_memory_mb: options.max_worker_memory_mb,
            max_output_bytes: options.max_output_bytes,
            max_request_bytes: options.max_request_bytes,
            max_query_parameter_bytes: options.max_query_parameter_bytes,
            max_batch_items: options.max_batch_items,
            liveness_window_ms: 30000,
            retry_after_seconds: 1,
        },
        openfn: SidecarOpenFnConfig {
            cli_build_tool: options.cli_build_tool.clone(),
            runtime: options.runtime.clone(),
        },
        worker: SidecarWorkerConfig {
            command: options.worker_command.clone(),
            args: vec!["--experimental-vm-modules".to_string(), worker_script],
            version_args,
        },
        sources,
    };

    let mut manifest_yaml =
        serde_yaml::to_string(&manifest).context("failed to render sidecar manifest")?;
    manifest_yaml.insert_str(
        0,
        "# Generated by registryctl from an OpenFn project export.\n# Production startup should render and sign a governed runtime target before deployment.\n",
    );

    let notary_snippet_yaml = openfn_notary_snippet_yaml(options)?;

    Ok(OpenFnSidecarConversion {
        workflow_key,
        manifest_yaml,
        notary_snippet_yaml,
        job_files,
        warnings,
    })
}

fn select_openfn_workflow(
    input: &str,
    requested_workflow: Option<&str>,
) -> Result<(String, OpenFnWorkflowExport)> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(input).context("failed to parse OpenFn YAML")?;
    if value.get("workflows").is_some() {
        let project: OpenFnProjectExport =
            serde_yaml::from_value(value).context("failed to parse OpenFn project YAML")?;
        if let Some(workflow_key) = requested_workflow {
            let workflow = project
                .workflows
                .into_iter()
                .find_map(|(key, workflow)| (key == workflow_key).then_some(workflow));
            return workflow
                .map(|workflow| (workflow_key.to_string(), workflow))
                .ok_or_else(|| anyhow!("OpenFn workflow {workflow_key} was not found"));
        }
        if project.workflows.len() == 1 {
            return project
                .workflows
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("OpenFn project has no workflows"));
        }
        let names = project
            .workflows
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        bail!("OpenFn project has multiple workflows; pass --workflow. Available: {names}");
    }

    if requested_workflow.is_some() {
        bail!("--workflow can only be used with an OpenFn project export that has workflows");
    }
    let workflow: OpenFnWorkflowExport =
        serde_yaml::from_value(value).context("failed to parse OpenFn workflow YAML")?;
    Ok(("workflow".to_string(), workflow))
}

fn validate_openfn_options(options: &OpenFnConvertOptions) -> Result<()> {
    if options.source_id.trim().is_empty() {
        bail!("--source-id must not be empty");
    }
    if options.dataset.trim().is_empty() {
        bail!("--dataset must not be empty");
    }
    if options.entity.trim().is_empty() {
        bail!("--entity must not be empty");
    }
    if options.credential_env.trim().is_empty() {
        bail!("--credential-env must not be empty");
    }
    if options.smoke_field.trim().is_empty() {
        bail!("--smoke-field must not be empty");
    }
    if options.smoke_value.trim().is_empty() {
        bail!("--smoke-value must not be empty");
    }
    if options.max_workers == 0
        || options.worker_timeout_ms == 0
        || options.max_worker_memory_mb == 0
        || options.max_output_bytes == 0
        || options.max_request_bytes == 0
        || options.max_query_parameter_bytes == 0
    {
        bail!("sidecar limits must be greater than zero");
    }
    Ok(())
}

fn validate_openfn_job(
    workflow_key: &str,
    job_key: &str,
    job: &OpenFnJobExport,
    options: &OpenFnConvertOptions,
) -> Result<()> {
    if job_key.trim().is_empty() {
        bail!("OpenFn workflow {workflow_key} has a job with an empty key");
    }
    if job.adaptor.trim().is_empty() {
        bail!("OpenFn workflow {workflow_key} job {job_key} is missing adaptor");
    }
    if !adaptor_has_version_pin(&job.adaptor) {
        bail!(
            "OpenFn workflow {workflow_key} job {job_key} adaptor {} must include a version pin",
            job.adaptor
        );
    }
    if !options.allow_latest_adaptors && adaptor_uses_latest(&job.adaptor) {
        bail!("OpenFn workflow {workflow_key} job {job_key} adaptor {} uses @latest; pin an exact adaptor version or rerun with --allow-latest-adaptors", job.adaptor);
    }
    if !options.allow_empty_job_bodies && job.body.trim().is_empty() {
        bail!("OpenFn workflow {workflow_key} job {job_key} has an empty body");
    }
    Ok(())
}

fn convert_openfn_edges(
    workflow_key: &str,
    workflow: &OpenFnWorkflowExport,
) -> Result<(String, SidecarNextByJob)> {
    let mut start_jobs = Vec::new();
    let mut next_by_job = BTreeMap::<String, BTreeMap<String, SidecarWorkflowEdgeConfig>>::new();

    for (edge_key, edge) in &workflow.edges {
        if !edge.enabled {
            continue;
        }
        if !workflow.jobs.contains_key(&edge.target_job) {
            bail!(
                "OpenFn workflow {workflow_key} edge {edge_key} targets missing job {}",
                edge.target_job
            );
        }
        let has_source_trigger = edge
            .source_trigger
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        let has_source_job = edge.source_job.as_deref().is_some_and(|s| !s.is_empty());
        match (has_source_trigger, has_source_job) {
            (true, false) => {
                let trigger_key = edge.source_trigger.as_deref().unwrap_or_default();
                let trigger_enabled = workflow
                    .triggers
                    .get(trigger_key)
                    .and_then(|trigger| trigger.enabled)
                    .unwrap_or(true);
                if trigger_enabled {
                    ensure_openfn_trigger_edge_is_start(workflow_key, edge_key, edge)?;
                    start_jobs.push(edge.target_job.clone());
                }
            }
            (false, true) => {
                let source_job = edge.source_job.as_deref().unwrap_or_default();
                if !workflow.jobs.contains_key(source_job) {
                    bail!(
                        "OpenFn workflow {workflow_key} edge {edge_key} sources missing job {source_job}"
                    );
                }
                let sidecar_edge = convert_openfn_job_edge(workflow_key, edge_key, edge)?;
                next_by_job
                    .entry(source_job.to_string())
                    .or_default()
                    .insert(edge.target_job.clone(), sidecar_edge);
            }
            (true, true) => {
                bail!("OpenFn workflow {workflow_key} edge {edge_key} has both source_trigger and source_job");
            }
            (false, false) => {
                bail!("OpenFn workflow {workflow_key} edge {edge_key} is missing a source");
            }
        }
    }

    let start = match start_jobs.len() {
        1 => start_jobs.remove(0),
        0 => infer_openfn_start_job(workflow_key, workflow, &next_by_job)?,
        _ => bail!(
            "OpenFn workflow {workflow_key} has multiple enabled trigger start edges ({:?}); sidecar supports one start step",
            start_jobs
        ),
    };

    Ok((start, next_by_job))
}

fn ensure_openfn_trigger_edge_is_start(
    workflow_key: &str,
    edge_key: &str,
    edge: &OpenFnEdgeExport,
) -> Result<()> {
    let condition_type = edge.condition_type.as_deref().unwrap_or("always");
    if condition_type != "always" {
        bail!("OpenFn workflow {workflow_key} trigger edge {edge_key} uses condition_type {condition_type}; sidecar start edges must be always");
    }
    Ok(())
}

fn convert_openfn_job_edge(
    workflow_key: &str,
    edge_key: &str,
    edge: &OpenFnEdgeExport,
) -> Result<SidecarWorkflowEdgeConfig> {
    let condition_type = edge.condition_type.as_deref().unwrap_or("always");
    match condition_type {
        "always" | "on_job_success" => Ok(SidecarWorkflowEdgeConfig::Enabled(true)),
        "js_expression" => {
            let condition = edge
                .condition_expression
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "OpenFn workflow {workflow_key} edge {edge_key} uses js_expression without condition_expression"
                    )
                })?;
            Ok(SidecarWorkflowEdgeConfig::Edge(
                SidecarWorkflowEdgeObjectConfig {
                    condition: condition.to_string(),
                    label: edge.condition_label.clone(),
                },
            ))
        }
        "on_job_failure" => {
            bail!("OpenFn workflow {workflow_key} edge {edge_key} uses on_job_failure; sidecar lookup workflows must return a single successful final Registry Data API state")
        }
        other => bail!(
            "OpenFn workflow {workflow_key} edge {edge_key} uses unsupported condition_type {other}"
        ),
    }
}

fn infer_openfn_start_job(
    workflow_key: &str,
    workflow: &OpenFnWorkflowExport,
    next_by_job: &SidecarNextByJob,
) -> Result<String> {
    let incoming = incoming_counts(next_by_job);
    let roots = workflow
        .jobs
        .keys()
        .filter(|job_key| !incoming.contains_key(job_key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    match roots.len() {
        1 => Ok(roots[0].clone()),
        0 => bail!("OpenFn workflow {workflow_key} has no trigger start edge and no root job"),
        _ => bail!(
            "OpenFn workflow {workflow_key} has no trigger start edge and multiple root jobs ({:?}); sidecar supports one start step",
            roots
        ),
    }
}

fn validate_sidecar_topology(
    workflow_key: &str,
    jobs: &BTreeMap<String, OpenFnJobExport>,
    start: &str,
    next_by_job: &SidecarNextByJob,
) -> Result<()> {
    if !jobs.contains_key(start) {
        bail!("OpenFn workflow {workflow_key} start job {start} is not defined");
    }
    let incoming = incoming_counts(next_by_job);
    if let Some((job_key, count)) = incoming.iter().find(|(_, count)| **count > 1) {
        bail!(
            "OpenFn workflow {workflow_key} job {job_key} has {count} incoming edges; sidecar does not support Lightning-style joins"
        );
    }
    let mut visited = BTreeSet::new();
    let mut path = BTreeSet::new();
    detect_openfn_cycle(workflow_key, start, next_by_job, &mut visited, &mut path)?;
    let unreachable = jobs
        .keys()
        .filter(|job_key| !visited.contains(job_key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unreachable.is_empty() {
        bail!(
            "OpenFn workflow {workflow_key} has jobs unreachable from start {start}: {:?}",
            unreachable
        );
    }
    Ok(())
}

fn incoming_counts(next_by_job: &SidecarNextByJob) -> BTreeMap<&str, usize> {
    let mut incoming = BTreeMap::new();
    for targets in next_by_job.values() {
        for target in targets.keys() {
            *incoming.entry(target.as_str()).or_default() += 1;
        }
    }
    incoming
}

fn detect_openfn_cycle<'a>(
    workflow_key: &str,
    current: &'a str,
    next_by_job: &'a SidecarNextByJob,
    visited: &mut BTreeSet<&'a str>,
    path: &mut BTreeSet<&'a str>,
) -> Result<()> {
    if path.contains(current) {
        bail!("OpenFn workflow {workflow_key} contains a cycle at job {current}");
    }
    if !visited.insert(current) {
        return Ok(());
    }
    path.insert(current);
    if let Some(targets) = next_by_job.get(current) {
        for target in targets.keys() {
            detect_openfn_cycle(workflow_key, target, next_by_job, visited, path)?;
        }
    }
    path.remove(current);
    Ok(())
}

fn adaptor_has_version_pin(adaptor: &str) -> bool {
    adaptor_pin(adaptor)
        .map(|version| !version.trim().is_empty())
        .unwrap_or(false)
}

fn adaptor_uses_latest(adaptor: &str) -> bool {
    adaptor_pin(adaptor).is_some_and(|version| version == "latest")
}

fn adaptor_pin(adaptor: &str) -> Option<&str> {
    let module = adaptor
        .split_once('=')
        .map_or(adaptor, |(module, _)| module);
    let (name, version) = module.rsplit_once('@')?;
    (!name.is_empty()).then_some(version)
}

fn adaptor_package_name(adaptor: &str) -> Option<&str> {
    let module = adaptor
        .split_once('=')
        .map_or(adaptor, |(module, _)| module);
    let (name, _) = module.rsplit_once('@')?;
    (!name.is_empty()).then_some(name)
}

fn smoke_fields(options: &OpenFnConvertOptions) -> Vec<String> {
    let fields = options
        .smoke_fields
        .as_deref()
        .map(|fields| {
            fields
                .split(',')
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|fields| !fields.is_empty())
        .unwrap_or_else(|| vec![options.smoke_field.clone()]);
    if fields.iter().any(|field| field == &options.smoke_field) {
        fields
    } else {
        let mut with_lookup = vec![options.smoke_field.clone()];
        with_lookup.extend(fields);
        with_lookup
    }
}

fn openfn_notary_snippet_yaml(options: &OpenFnConvertOptions) -> Result<String> {
    let sidecar_base_url = options
        .sidecar_base_url
        .clone()
        .unwrap_or_else(|| default_sidecar_base_url(&options.server_bind));
    let fields = smoke_fields(options);
    let query_fields = fields
        .iter()
        .map(|field| {
            serde_json::json!({
                "input": format!("target.identifiers.{field}"),
                "field": field,
                "op": "eq",
            })
        })
        .collect::<Vec<_>>();
    let projected_fields = fields
        .iter()
        .map(|field| {
            (
                field.clone(),
                serde_json::json!({
                    "field": field,
                    "type": "string",
                    "required": false,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let snippet = serde_json::json!({
        "evidence": {
            "source_connections": {
                options.source_id.clone(): {
                    "base_url": sidecar_base_url,
                    "allow_insecure_localhost": true,
                    "token_env": options.sidecar_token_env,
                    "retry_on_5xx": false,
                    "bulk_mode": "openfn_sidecar_batch",
                    "bulk_timeout_max_ms": 30000,
                }
            },
            "claims": [
                {
                    "id": format!("{}-lookup", options.source_id.replace('_', "-")),
                    "title": format!("{} lookup", options.source_id),
                    "version": "2026-06",
                    "subject_type": options.entity,
                    "value": { "type": "boolean" },
                    "operations": {
                        "batch_evaluate": {
                            "enabled": true,
                            "max_subjects": options.max_batch_items,
                        }
                    },
                    "source_bindings": {
                        options.source_id.clone(): {
                            "connector": "openfn_sidecar",
                            "connection": options.source_id,
                            "required_scope": "REVIEW_REQUIRED:evidence_verification",
                            "dataset": options.dataset,
                            "entity": options.entity,
                            "lookup": {
                                "input": format!("target.identifiers.{}", options.smoke_field),
                                "field": options.smoke_field,
                                "op": "eq",
                                "cardinality": "one",
                            },
                            "query_fields": query_fields,
                            "fields": projected_fields,
                        }
                    },
                    "rule": {
                        "type": "exists",
                        "source": options.source_id,
                    }
                }
            ],
        }
    });
    let mut yaml =
        serde_yaml::to_string(&snippet).context("failed to render OpenFn Notary snippet")?;
    yaml.insert_str(
        0,
        "# Generated by registryctl from an OpenFn workflow import.\n# Review claim id, scopes, matching policy, expected_sidecar, and field types before production use.\n",
    );
    Ok(yaml)
}

fn default_sidecar_base_url(server_bind: &str) -> String {
    match server_bind.parse::<SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => format!("http://127.0.0.1:{}", addr.port()),
        Ok(addr) => format!("http://{addr}"),
        Err(_) => "http://127.0.0.1:9191".to_string(),
    }
}

fn yaml_scalar_string(value: Option<&serde_yaml::Value>) -> Option<&str> {
    match value {
        Some(serde_yaml::Value::String(value)) => Some(value),
        _ => None,
    }
}

fn unique_openfn_job_filename(job_key: &str, seen: &mut BTreeMap<String, usize>) -> String {
    let base = sanitize_filename_stem(job_key);
    let count = seen.entry(base.clone()).or_default();
    *count += 1;
    if *count == 1 {
        format!("{base}.js")
    } else {
        format!("{base}-{}.js", *count)
    }
}

fn sanitize_filename_stem(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
            output.push(byte as char);
        } else {
            output.push('_');
        }
    }
    let trimmed = output.trim_matches('_');
    if trimmed.is_empty() {
        "job".to_string()
    } else {
        trimmed.to_string()
    }
}

fn ensure_trailing_newline(value: &str) -> String {
    if value.ends_with('\n') {
        value.to_string()
    } else {
        format!("{value}\n")
    }
}

#[derive(Debug)]
struct GeneratedFile {
    relative_path: String,
    contents: String,
}

fn write_generated_files(
    project_dir: &Path,
    collection_dir: &Path,
    mut files: Vec<GeneratedFile>,
    force: bool,
) -> Result<()> {
    let mut manifest_paths: Vec<_> = files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect();
    manifest_paths.push(".registryctl-generated".to_string());
    files.push(GeneratedFile {
        relative_path: ".registryctl-generated".to_string(),
        contents: generated_manifest_contents(&manifest_paths),
    });
    let known = read_generated_manifest(project_dir);

    for file in &files {
        let path = collection_dir.join(&file.relative_path);
        if path.exists() && !force && !known.contains_key(&file.relative_path) {
            bail!(
                "{} already exists and is not marked as registryctl-generated; rerun with --force to overwrite it",
                path.display()
            );
        }
    }

    for file in files {
        let path = collection_dir.join(&file.relative_path);
        fs::create_dir_all(path.parent().unwrap_or(collection_dir))?;
        write_text(path, &file.contents)?;
    }

    Ok(())
}

fn read_generated_manifest(project_dir: &Path) -> BTreeMap<String, bool> {
    let path = project_dir.join(BRUNO_GENERATED_MANIFEST);
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| (line.to_string(), true))
        .collect()
}

fn generated_manifest_contents(paths: &[String]) -> String {
    let mut paths: Vec<_> = paths.iter().map(String::as_str).collect();
    paths.sort_unstable();
    let mut output = paths.join("\n");
    output.push('\n');
    output
}

fn bruno_files(project: &Project, secrets: &LocalEnv) -> Result<Vec<GeneratedFile>> {
    let mut files = vec![
        generated_file(
            "bruno.json",
            r#"{
  "version": "1",
  "name": "Registry API",
  "type": "collection",
  "ignore": [
    "node_modules",
    ".git"
  ]
}
"#,
        ),
        generated_file(
            "collection.bru",
            "docs {\nGenerated local Registry Commons API collection.\n}\n",
        ),
    ];

    if project.relay.is_some() {
        files.extend(bruno_relay_files(project.relay_base_url()?, secrets));
    }
    if project.notary.is_some() {
        files.extend(bruno_notary_files(project, secrets)?);
    }
    files.push(generated_file(
        "environments/local.bru",
        &bruno_local_env(project, secrets)?,
    ));
    files.push(generated_file(
        "environments/local.example.bru",
        &bruno_example_env(project)?,
    ));
    Ok(files)
}

fn generated_file(path: &str, contents: &str) -> GeneratedFile {
    GeneratedFile {
        relative_path: path.to_string(),
        contents: contents.to_string(),
    }
}

fn bruno_relay_files(relay_base_url: &str, _secrets: &LocalEnv) -> Vec<GeneratedFile> {
    let application_query_body = r#"{
  "measures": ["application_count"],
  "group_by": ["program", "application_status"],
  "filters": {
    "program": "cash_transfer"
  }
}"#;

    vec![
        bruno_get(
            "Relay/Health.bru",
            "Relay health",
            1,
            "{{relay_base_url}}/healthz",
            &[],
        ),
        bruno_get("Relay/Ready.bru", "Relay ready", 2, "{{relay_base_url}}/ready", &[]),
        bruno_get(
            "Relay/OpenAPI.bru",
            "Relay OpenAPI",
            3,
            "{{relay_base_url}}/openapi.json",
            &[],
        ),
        bruno_get(
            "Relay/Unauthorized datasets.bru",
            "Unauthorized datasets",
            4,
            "{{relay_base_url}}/v1/datasets",
            &[],
        ),
        bruno_get(
            "Relay/List datasets.bru",
            "List datasets",
            5,
            "{{relay_base_url}}/v1/datasets",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Get dataset detail.bru",
            "Get dataset detail",
            6,
            "{{relay_base_url}}/v1/datasets/benefits_casework",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Metadata catalog.bru",
            "Metadata catalog",
            7,
            "{{relay_base_url}}/metadata/catalog",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Household schema.bru",
            "Household schema",
            8,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/household/schema",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Person schema.bru",
            "Person schema",
            9,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/schema",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Application schema.bru",
            "Application schema",
            10,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/application/schema",
            &[("Authorization", "Bearer {{relay_metadata_key}}")],
        ),
        bruno_get(
            "Relay/Read households by district.bru",
            "Read households by district",
            11,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/household/records?district=south",
            &[("Authorization", "Bearer {{relay_row_key}}")],
        ),
        bruno_get(
            "Relay/Read household with members.bru",
            "Read household with members",
            12,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/household/records/hh-1001?expand=members",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read sample people.bru",
            "Read sample people",
            13,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read pending people.bru",
            "Read pending people",
            14,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?eligibility_status=pending_review",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read person with household.bru",
            "Read person with household",
            15,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records/per-2001?expand=household",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read approved applications.bru",
            "Read approved applications",
            16,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/application/records?application_status=approved",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read application with applicant.bru",
            "Read application with applicant",
            17,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/application/records/app-3001?expand=applicant",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/People missing purpose.bru",
            "People missing purpose",
            18,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
            &[("Authorization", "Bearer {{relay_row_key}}")],
        ),
        bruno_get(
            "Relay/Metadata key cannot read people.bru",
            "Metadata key cannot read people",
            19,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
            &[
                ("Authorization", "Bearer {{relay_metadata_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/List aggregates.bru",
            "List aggregates",
            20,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates",
            &[("Authorization", "Bearer {{relay_aggregate_key}}")],
        ),
        bruno_get(
            "Relay/Run households by district aggregate.bru",
            "Run households by district aggregate",
            21,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/by_district",
            &[("Authorization", "Bearer {{relay_aggregate_key}}")],
        ),
        bruno_get(
            "Relay/Run applications aggregate as CSV.bru",
            "Run applications aggregate as CSV",
            22,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/applications_by_program_status?f=csv",
            &[
                ("Authorization", "Bearer {{relay_aggregate_key}}"),
                ("Data-Purpose", "{{purpose}}"),
                ("Accept", "text/csv"),
            ],
        ),
        bruno_post_json(
            "Relay/Query applications aggregate.bru",
            "Query applications aggregate",
            23,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/applications_by_program_status/query",
            &[
                ("Authorization", "Bearer {{relay_aggregate_key}}"),
                ("Data-Purpose", "{{purpose}}"),
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ],
            application_query_body,
        ),
        generated_file(
            "Relay/folder.bru",
            "meta {\n  name: Relay\n  type: folder\n  seq: 1\n}\n",
        ),
        generated_file(
            "Relay/README.md",
            &format!(
                "Relay requests use the generated local API at {relay_base_url}. Request files use Bruno variables and do not contain raw keys.\n"
            ),
        ),
    ]
}

fn bruno_notary_files(project: &Project, _secrets: &LocalEnv) -> Result<Vec<GeneratedFile>> {
    let notary = project
        .notary
        .as_ref()
        .ok_or_else(|| anyhow!("project does not have a Notary section"))?;
    let claim_id = notary
        .claims
        .first()
        .map(String::as_str)
        .unwrap_or(NOTARY_TUTORIAL_CLAIM);
    let smoke_target_id = notary_smoke_target_id(notary);
    let missing_smoke_target_id = format!("{smoke_target_id}-missing");
    let evaluate_body = bruno_notary_evaluate_body(notary, claim_id, smoke_target_id)?;
    let evaluate_missing_body =
        bruno_notary_evaluate_body(notary, claim_id, &missing_smoke_target_id)?;
    let source_url = notary
        .source_url
        .as_deref()
        .or(notary.source_relay_service_url.as_deref())
        .unwrap_or("configured source API");
    Ok(vec![
        bruno_get(
            "Notary/Health.bru",
            "Notary health",
            1,
            "{{notary_base_url}}/healthz",
            &[],
        ),
        bruno_get(
            "Notary/Ready.bru",
            "Notary ready",
            2,
            "{{notary_base_url}}/ready",
            &[],
        ),
        bruno_get(
            "Notary/Unauthorized claims.bru",
            "Unauthorized claims",
            3,
            "{{notary_base_url}}/v1/claims",
            &[],
        ),
        bruno_get(
            "Notary/List claims.bru",
            "List claims",
            4,
            "{{notary_base_url}}/v1/claims",
            &[
                ("x-api-key", "{{notary_evaluator_key}}"),
                ("Accept", "application/json"),
            ],
        ),
        bruno_post_json(
            "Notary/Evaluate person exists.bru",
            "Evaluate person exists",
            5,
            "{{notary_base_url}}/v1/evaluations",
            &[
                ("x-api-key", "{{notary_evaluator_key}}"),
                ("Content-Type", "application/json"),
                ("Accept", NOTARY_CLAIM_RESULT_JSON),
            ],
            &evaluate_body,
        ),
        bruno_post_json(
            "Notary/Evaluate missing person.bru",
            "Evaluate missing person",
            6,
            "{{notary_base_url}}/v1/evaluations",
            &[
                ("x-api-key", "{{notary_evaluator_key}}"),
                ("Content-Type", "application/json"),
                ("Accept", NOTARY_CLAIM_RESULT_JSON),
            ],
            &evaluate_missing_body,
        ),
        generated_file(
            "Notary/folder.bru",
            "meta {\n  name: Notary\n  type: folder\n  seq: 2\n}\n",
        ),
        generated_file(
            "Notary/README.md",
            &format!(
                "Notary requests call the generated local Notary API. The source connection is `{}` at {}. Source token env: {}. Starter source: dataset `{}`, entity `{}`, lookup field `{}`. Source network: {}.\n",
                notary.source,
                source_url,
                notary.source_token_env.as_deref().unwrap_or("configured in secrets/local.env"),
                notary.source_dataset.as_deref().unwrap_or("configured"),
                notary.source_entity.as_deref().unwrap_or("configured"),
                notary.source_lookup_field.as_deref().unwrap_or("configured"),
                notary.source_network.as_deref().unwrap_or("none")
            ),
        ),
    ])
}

fn bruno_notary_evaluate_body(
    notary: &ProjectNotary,
    claim_id: &str,
    smoke_target_id: &str,
) -> Result<String> {
    if notary.source_kind() == NotaryInitSourceKind::OpencrvsDci {
        return serde_json::to_string_pretty(&serde_json::json!({
            "target": notary_smoke_target_json(notary, smoke_target_id),
            "claims": [claim_id],
            "disclosure": "predicate",
            "purpose": "{{purpose}}"
        }))
        .context("failed to render OpenCRVS DCI Notary Bruno body");
    }
    let source_entity = notary.source_entity.as_deref().unwrap_or("person");
    Ok(format!(
        r#"{{
  "target": {{
    "type": "{source_entity}",
    "id": "{smoke_target_id}"
  }},
  "claims": ["{claim_id}"],
  "disclosure": "predicate",
  "purpose": "{{{{purpose}}}}"
}}"#
    ))
}

fn notary_smoke_target_id(notary: &ProjectNotary) -> &str {
    notary
        .smoke_target_id
        .as_deref()
        .unwrap_or_else(|| notary.source_kind().default_smoke_target_id())
}

fn notary_smoke_target_json(notary: &ProjectNotary, smoke_target_id: &str) -> Value {
    let source_entity = notary.source_entity.as_deref().unwrap_or("person");
    notary
        .source_kind()
        .smoke_target_json(smoke_target_id, source_entity)
}

fn bruno_get(
    path: &str,
    name: &str,
    seq: u32,
    url: &str,
    headers: &[(&str, &str)],
) -> GeneratedFile {
    let mut contents = format!(
        "meta {{\n  name: {name}\n  type: http\n  seq: {seq}\n}}\n\nget {{\n  url: {url}\n  body: none\n  auth: none\n}}\n"
    );
    contents.push_str(&bruno_headers(headers));
    generated_file(path, &contents)
}

fn bruno_post_json(
    path: &str,
    name: &str,
    seq: u32,
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> GeneratedFile {
    let mut contents = format!(
        "meta {{\n  name: {name}\n  type: http\n  seq: {seq}\n}}\n\npost {{\n  url: {url}\n  body: json\n  auth: none\n}}\n"
    );
    contents.push_str(&bruno_headers(headers));
    contents.push_str("\nbody:json {\n");
    contents.push_str(body);
    contents.push_str("\n}\n");
    generated_file(path, &contents)
}

fn bruno_headers(headers: &[(&str, &str)]) -> String {
    if headers.is_empty() {
        return String::new();
    }
    let mut contents = "\nheaders {\n".to_string();
    for (name, value) in headers {
        contents.push_str("  ");
        contents.push_str(name);
        contents.push_str(": ");
        contents.push_str(value);
        contents.push('\n');
    }
    contents.push_str("}\n");
    contents
}

fn bruno_local_env(project: &Project, secrets: &LocalEnv) -> Result<String> {
    bruno_env(project, secrets, false)
}

fn bruno_example_env(project: &Project) -> Result<String> {
    bruno_env(
        project,
        &LocalEnv {
            values: BTreeMap::new(),
        },
        true,
    )
}

fn bruno_env(project: &Project, secrets: &LocalEnv, example: bool) -> Result<String> {
    let mut values = Vec::new();
    values.push(("purpose", TUTORIAL_PURPOSE.to_string()));
    if project.relay.is_some() {
        values.push(("relay_base_url", project.relay_base_url()?.to_string()));
        values.push((
            "relay_metadata_key",
            bruno_env_value(secrets, "METADATA_READER_RAW", example),
        ));
        values.push((
            "relay_row_key",
            bruno_env_value(secrets, "ROW_READER_RAW", example),
        ));
        values.push((
            "relay_aggregate_key",
            bruno_env_value(secrets, "AGGREGATE_READER_RAW", example),
        ));
    }
    if project.notary.is_some() {
        values.push(("notary_base_url", project.notary_base_url()?.to_string()));
        values.push((
            "notary_evaluator_key",
            bruno_env_value(secrets, "REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW", example),
        ));
    }

    let mut contents = "vars {\n".to_string();
    for (name, value) in values {
        contents.push_str("  ");
        contents.push_str(name);
        contents.push_str(": ");
        contents.push_str(&value);
        contents.push('\n');
    }
    contents.push_str("}\n");
    Ok(contents)
}

fn bruno_env_value(secrets: &LocalEnv, name: &str, example: bool) -> String {
    if example {
        format!("replace-with-{}", name.to_ascii_lowercase())
    } else {
        secrets.value(name).to_string()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Project {
    // Not read anywhere today beyond load-time validation (see `deserialize_schema_version`);
    // modeled so `deny_unknown_fields` doesn't reject registryctl's own generated files
    // (see `registryctl_manifest`).
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_schema_version")]
    schema_version: String,
    #[allow(dead_code)]
    project: ProjectMeta,
    #[serde(default)]
    relay: Option<ProjectRelay>,
    #[serde(default)]
    notary: Option<ProjectNotary>,
    runtime: ProjectRuntime,
    local: ProjectLocal,
}

/// The `project:` metadata block `registryctl_manifest` writes into every generated
/// `registryctl.yaml` (see `ProjectSection`); not consumed elsewhere today, but modeled here
/// so `deny_unknown_fields` doesn't reject registryctl's own generated files.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectMeta {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    products: Vec<String>,
}

impl Project {
    fn load(project_dir: &Path) -> Result<Self> {
        let path = project_dir.join("registryctl.yaml");
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRelay {
    config: PathBuf,
    #[serde(default)]
    metadata: Option<PathBuf>,
    #[serde(default)]
    data: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectNotary {
    config: PathBuf,
    #[serde(deserialize_with = "deserialize_notary_source")]
    source: String,
    #[serde(default)]
    source_relay_service_url: Option<String>,
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    source_token_env: Option<String>,
    #[serde(default)]
    source_dataset: Option<String>,
    #[serde(default)]
    source_entity: Option<String>,
    #[serde(default)]
    source_lookup_field: Option<String>,
    #[serde(default)]
    source_network: Option<String>,
    #[serde(default)]
    claims: Vec<String>,
    #[serde(default)]
    smoke_target_id: Option<String>,
}

/// Validates `schema_version` against `PROJECT_SCHEMA_VERSION`, the only version
/// `registryctl_manifest` generates today, so a future/incompatible schema file fails project
/// load instead of half-parsing.
fn deserialize_schema_version<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let schema_version = String::deserialize(deserializer)?;
    if schema_version != PROJECT_SCHEMA_VERSION {
        return Err(D::Error::custom(format!(
            "invalid schema_version {schema_version:?}; expected {PROJECT_SCHEMA_VERSION:?}"
        )));
    }
    Ok(schema_version)
}

/// Validates `notary.source` against the labels `NotaryInitSourceKind::from_source_label`
/// accepts, so an unrecognized value fails project load instead of silently behaving as
/// `NotaryInitSourceKind::RegistryDataApi` later on.
fn deserialize_notary_source<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let source = String::deserialize(deserializer)?;
    if NotaryInitSourceKind::from_source_label(&source).is_none() {
        return Err(D::Error::custom(format!(
            "invalid notary.source {source:?}; expected one of: {}",
            NotaryInitSourceKind::VALID_SOURCE_LABELS.join(", ")
        )));
    }
    Ok(source)
}

impl ProjectNotary {
    /// The parsed source kind. `source` is validated against `NotaryInitSourceKind::from_source_label`
    /// when the project is loaded, so this always succeeds.
    fn source_kind(&self) -> NotaryInitSourceKind {
        NotaryInitSourceKind::from_source_label(&self.source)
            .expect("ProjectNotary.source is validated against known labels at load time")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRuntime {
    // Not read anywhere today (the compose engine/file are hardcoded elsewhere); modeled so
    // `deny_unknown_fields` doesn't reject registryctl's own generated files.
    #[allow(dead_code)]
    engine: String,
    #[allow(dead_code)]
    compose_file: PathBuf,
    #[serde(default)]
    relay_image: Option<String>,
    #[serde(default)]
    relay_base_url: Option<String>,
    #[serde(default)]
    notary_image: Option<String>,
    #[serde(default)]
    notary_base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectLocal {
    secrets_env: PathBuf,
    output_dir: PathBuf,
}

impl Project {
    fn relay_base_url(&self) -> Result<&str> {
        if self.relay.is_none() {
            bail!(
                "project does not have a Relay section; use `registryctl notary smoke` for standalone Notary projects"
            );
        }
        self.runtime
            .relay_base_url
            .as_deref()
            .ok_or_else(|| anyhow!("project runtime is missing relay_base_url"))
    }

    fn notary_base_url(&self) -> Result<&str> {
        if self.notary.is_none() {
            bail!("project does not have a Notary section; run `registryctl init notary <dir>` or `registryctl add notary --from local-relay` first");
        }
        self.runtime
            .notary_base_url
            .as_deref()
            .ok_or_else(|| anyhow!("project runtime is missing notary_base_url"))
    }

    fn notary_claim_id(&self) -> String {
        self.notary
            .as_ref()
            .and_then(|notary| notary.claims.first())
            .cloned()
            .unwrap_or_else(|| NOTARY_TUTORIAL_CLAIM.to_string())
    }
}

#[derive(Debug)]
struct LocalEnv {
    values: BTreeMap<String, String>,
}

impl LocalEnv {
    fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Self {
            values: parse_local_env(&contents),
        })
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("missing required local env value {name}"))
    }

    fn value(&self, name: &str) -> &str {
        self.values.get(name).map(String::as_str).unwrap_or("")
    }
}

fn parse_local_env(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn upsert_env_values(contents: &str, values: &[(String, String)]) -> String {
    let replacements: BTreeMap<&str, &str> = values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut seen = BTreeMap::new();
    let mut lines = Vec::new();

    for line in contents.lines() {
        if let Some((key, _)) = line.split_once('=') {
            if let Some(value) = replacements.get(key) {
                lines.push(format!("{key}={value}"));
                seen.insert(key.to_string(), true);
                continue;
            }
        }
        lines.push(line.to_string());
    }

    for (key, value) in values {
        if !seen.contains_key(key) {
            lines.push(format!("{key}={value}"));
        }
    }

    let mut output = lines.join("\n");
    output.push('\n');
    output
}

fn run_compose_for_project(project_dir: &Path, project: &Project, args: &[&str]) -> Result<()> {
    let explicit_platform = std::env::var("DOCKER_DEFAULT_PLATFORM").ok();
    let server_platform = should_probe_compose_platform(args)
        .then(|| docker_server_platform("docker"))
        .flatten();
    let platform_override = compose_platform_override(
        project,
        explicit_platform.as_deref(),
        server_platform.as_deref(),
    );
    run_compose_command_with_platform(project_dir, "docker", args, platform_override)
}

fn run_compose_command_with_platform(
    project_dir: &Path,
    binary: &str,
    args: &[&str],
    platform_override: Option<&str>,
) -> Result<()> {
    let command_args = compose_command_args("compose.yaml", args);
    let mut command = Command::new(binary);
    command.args(&command_args).current_dir(project_dir);
    if let Some(platform) = platform_override {
        eprintln!("Using DOCKER_DEFAULT_PLATFORM={platform} for Registry Stack release images on this Docker host.");
        command.env("DOCKER_DEFAULT_PLATFORM", platform);
    }
    let status = command
        .status()
        .with_context(|| format!("failed to run {binary} compose"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{binary} compose exited with {status}")
    }
}

fn should_probe_compose_platform(args: &[&str]) -> bool {
    args.first().is_some_and(|arg| *arg == "up")
}

fn docker_server_platform(binary: &str) -> Option<String> {
    let output = Command::new(binary)
        .args(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let platform = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!platform.is_empty()).then_some(platform)
}

fn compose_platform_override(
    project: &Project,
    explicit_platform: Option<&str>,
    docker_server_platform: Option<&str>,
) -> Option<&'static str> {
    if explicit_platform.is_some_and(|platform| !platform.trim().is_empty()) {
        return None;
    }
    if !project_uses_amd64_only_release_image(project) {
        return None;
    }
    docker_server_platform
        .filter(|platform| is_linux_arm64_platform(platform))
        .map(|_| LINUX_AMD64_PLATFORM)
}

fn project_uses_amd64_only_release_image(project: &Project) -> bool {
    project.runtime.relay_image.as_deref() == Some(RELAY_IMAGE)
        || project.runtime.notary_image.as_deref() == Some(NOTARY_IMAGE)
}

fn is_linux_arm64_platform(platform: &str) -> bool {
    let normalized = platform.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "linux/arm64" | "linux/aarch64")
        || normalized.starts_with("linux/arm64/")
}

fn compose_command_args(compose_file: &str, args: &[&str]) -> Vec<String> {
    ["compose", "-f", compose_file]
        .into_iter()
        .chain(args.iter().copied())
        .map(String::from)
        .collect()
}

fn validate_project_fingerprints(project_dir: &Path, project: &Project) -> Result<()> {
    let Some(relay) = &project.relay else {
        return Ok(());
    };
    let config_path = project_dir.join(&relay.config);
    let config = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: serde_yaml::Value = serde_yaml::from_str(&config)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let api_keys = config["auth"]["api_keys"]
        .as_sequence()
        .ok_or_else(|| anyhow!("relay config auth.api_keys must be a list"))?;

    for api_key in api_keys {
        let id = api_key["id"]
            .as_str()
            .ok_or_else(|| anyhow!("relay config api key entry is missing id"))?;
        let hash_env = api_key["fingerprint"]["name"]
            .as_str()
            .ok_or_else(|| anyhow!("relay config api key {id} is missing fingerprint env name"))?;

        let fingerprint = secrets.required(hash_env)?;
        let raw_env = raw_env_name_for(id)?;
        let raw_key = secrets.required(raw_env)?;
        let expected_fingerprint = fingerprint_api_key(raw_key);
        if fingerprint != expected_fingerprint {
            bail!("local raw key and fingerprint do not match for {id}");
        }
    }

    Ok(())
}

fn validate_notary_fingerprint(project_dir: &Path, project: &Project) -> Result<()> {
    let Some(notary) = &project.notary else {
        return Ok(());
    };
    let config_path = project_dir.join(&notary.config);
    let config = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: serde_yaml::Value = serde_yaml::from_str(&config)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let api_keys = config["auth"]["api_keys"]
        .as_sequence()
        .ok_or_else(|| anyhow!("notary config auth.api_keys must be a list"))?;

    for api_key in api_keys {
        let id = api_key["id"]
            .as_str()
            .ok_or_else(|| anyhow!("notary config api key entry is missing id"))?;
        let hash_env = api_key["fingerprint"]["name"]
            .as_str()
            .ok_or_else(|| anyhow!("notary config api key {id} is missing fingerprint env name"))?;

        let fingerprint = secrets.required(hash_env)?;
        let raw_key = secrets.required(raw_env_name_for_notary(id)?)?;
        let expected_fingerprint = fingerprint_api_key(raw_key);
        if fingerprint != expected_fingerprint {
            bail!("local raw key and fingerprint do not match for notary api key {id}");
        }
    }

    Ok(())
}

fn raw_env_name_for(id: &str) -> Result<&'static str> {
    match id {
        "metadata_reader" => Ok("METADATA_READER_RAW"),
        "row_reader" => Ok("ROW_READER_RAW"),
        "aggregate_reader" => Ok("AGGREGATE_READER_RAW"),
        _ => bail!("unknown generated api key id {id}"),
    }
}

fn raw_env_name_for_notary(id: &str) -> Result<&'static str> {
    match id {
        "tutorial_evaluator" => Ok("REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW"),
        _ => bail!("unknown generated notary api key id {id}"),
    }
}

fn wait_for_ready(label: &str, base_url: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let health = http_get(&format!("{base_url}/healthz"), &[]).ok();
        let ready = http_get(&format!("{base_url}/ready"), &[]).ok();
        if matches!(health.as_ref().map(|response| response.status), Some(200))
            && matches!(ready.as_ref().map(|response| response.status), Some(200))
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!("{label} did not become healthy and ready before timeout")
}

fn print_probe_status(name: &str, url: &str) {
    match http_get(url, &[]) {
        Ok(response) => println!("{name}: {}", response.status),
        Err(err) => println!("{name}: unavailable ({err})"),
    }
}

#[derive(Debug)]
struct LocalCredentials {
    metadata_reader: Credential,
    row_reader: Credential,
    aggregate_reader: Credential,
    audit_hash_secret: String,
}

impl LocalCredentials {
    fn generate() -> Result<Self> {
        Ok(Self {
            metadata_reader: Credential::generate("metadata_reader")?,
            row_reader: Credential::generate("row_reader")?,
            aggregate_reader: Credential::generate("aggregate_reader")?,
            audit_hash_secret: random_token(48)?,
        })
    }

    fn env_file(&self) -> String {
        format!(
            "\
METADATA_READER_RAW={metadata_raw}
METADATA_READER_HASH={metadata_hash}
ROW_READER_RAW={row_raw}
ROW_READER_HASH={row_hash}
AGGREGATE_READER_RAW={aggregate_raw}
AGGREGATE_READER_HASH={aggregate_hash}
REGISTRY_RELAY_AUDIT_HASH_SECRET={audit_hash_secret}
",
            metadata_raw = self.metadata_reader.raw,
            metadata_hash = self.metadata_reader.fingerprint,
            row_raw = self.row_reader.raw,
            row_hash = self.row_reader.fingerprint,
            aggregate_raw = self.aggregate_reader.raw,
            aggregate_hash = self.aggregate_reader.fingerprint,
            audit_hash_secret = self.audit_hash_secret,
        )
    }
}

#[derive(Debug)]
struct NotaryLocalCredentials {
    evaluator: Credential,
    audit_hash_secret: String,
    relay_source_token: String,
    issuer_jwk: String,
}

impl NotaryLocalCredentials {
    fn generate(relay_source_token: String) -> Result<Self> {
        Ok(Self {
            evaluator: Credential::generate("tutorial_evaluator")?,
            audit_hash_secret: random_token(48)?,
            relay_source_token,
            issuer_jwk: demo_issuer_jwk(NOTARY_DEMO_ISSUER_KID)?,
        })
    }

    fn env_values(&self) -> Vec<(String, String)> {
        let mut values = self.common_env_values();
        values.push((
            "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN".to_string(),
            self.relay_source_token.clone(),
        ));
        values
    }

    fn env_values_for_source(&self, options: &NotaryInitOptions) -> Vec<(String, String)> {
        let mut values = self.common_env_values();
        if options.source_kind.uses_static_source_token() {
            values.push((
                options.source_token_env.clone(),
                self.relay_source_token.clone(),
            ));
        } else {
            values.push((
                "DCI_CLIENT_ID".to_string(),
                "replace-with-dci-client-id".to_string(),
            ));
            values.push((
                "DCI_CLIENT_SECRET".to_string(),
                "replace-with-dci-client-secret".to_string(),
            ));
        }
        values
    }

    fn common_env_values(&self) -> Vec<(String, String)> {
        vec![
            (
                "REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW".to_string(),
                self.evaluator.raw.clone(),
            ),
            (
                "REGISTRY_NOTARY_TUTORIAL_EVALUATOR_HASH".to_string(),
                self.evaluator.fingerprint.clone(),
            ),
            (
                "REGISTRY_NOTARY_AUDIT_HASH_SECRET".to_string(),
                self.audit_hash_secret.clone(),
            ),
            (
                "REGISTRY_NOTARY_ISSUER_JWK".to_string(),
                self.issuer_jwk.clone(),
            ),
            (
                "REGISTRY_NOTARY_REPLAY_REDIS_URL".to_string(),
                "redis://registry-notary-redis:6379".to_string(),
            ),
        ]
    }
}

#[derive(Debug)]
struct Credential {
    id: &'static str,
    raw: String,
    fingerprint: String,
}

impl Credential {
    fn generate(id: &'static str) -> Result<Self> {
        let raw = random_token(32)?;
        validate_api_key_entropy(&raw)?;
        let fingerprint = fingerprint_api_key(&raw);
        Ok(Self {
            id,
            raw,
            fingerprint,
        })
    }
}

fn random_token(byte_len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; byte_len];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("random generation failed: {err}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn demo_issuer_jwk(kid: &str) -> Result<String> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|err| anyhow!("random generation failed: {err}"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    serde_json::to_string(&serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": kid,
        "d": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
    }))
    .context("failed to render local demo issuer JWK")
}

#[derive(Serialize)]
struct ProjectManifest<'a> {
    schema_version: &'a str,
    project: ProjectSection<'a>,
    runtime: RuntimeSection<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelaySection<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notary: Option<NotarySection<'a>>,
    local: LocalSection<'a>,
}

#[derive(Serialize)]
struct ProjectSection<'a> {
    name: String,
    kind: &'a str,
    products: Vec<&'a str>,
}

#[derive(Serialize)]
struct RuntimeSection<'a> {
    engine: &'a str,
    compose_file: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_image: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_base_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notary_image: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notary_base_url: Option<&'a str>,
}

#[derive(Serialize)]
struct RelaySection<'a> {
    config: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a str>,
    data: Vec<&'a str>,
}

#[derive(Serialize)]
struct NotarySection<'a> {
    config: &'a str,
    source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_relay_service_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_token_env: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_dataset: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_entity: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_lookup_field: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_network: Option<&'a str>,
    claims: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smoke_target_id: Option<&'a str>,
}

#[derive(Serialize)]
struct LocalSection<'a> {
    secrets_env: &'a str,
    output_dir: &'a str,
}

enum ProjectManifestKind<'a> {
    Relay,
    RelayWithNotary,
    StandaloneNotary { options: &'a NotaryInitOptions },
}

fn registryctl_manifest(dir: &Path, kind: ProjectManifestKind<'_>) -> Result<String> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("my-first-api")
        .to_string();
    let include_relay = matches!(
        kind,
        ProjectManifestKind::Relay | ProjectManifestKind::RelayWithNotary
    );
    let include_notary = matches!(
        kind,
        ProjectManifestKind::RelayWithNotary | ProjectManifestKind::StandaloneNotary { .. }
    );
    let products = match kind {
        ProjectManifestKind::Relay => vec!["registry-relay"],
        ProjectManifestKind::RelayWithNotary => vec!["registry-relay", "registry-notary"],
        ProjectManifestKind::StandaloneNotary { .. } => vec!["registry-notary"],
    };
    let project_kind = match kind {
        ProjectManifestKind::Relay | ProjectManifestKind::RelayWithNotary => "spreadsheet-api",
        ProjectManifestKind::StandaloneNotary { .. } => "notary",
    };
    let notary = match kind {
        ProjectManifestKind::RelayWithNotary => Some(NotarySection {
            config: "notary/config.yaml",
            source: "relay",
            source_relay_service_url: Some(NOTARY_SOURCE_RELAY_SERVICE_URL),
            source_url: None,
            source_token_env: Some("EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN"),
            source_dataset: Some("benefits_casework"),
            source_entity: Some("person"),
            source_lookup_field: Some("id"),
            source_network: None,
            claims: vec![NOTARY_TUTORIAL_CLAIM],
            smoke_target_id: Some("per-2001"),
        }),
        ProjectManifestKind::StandaloneNotary { options } => Some(NotarySection {
            config: "notary/config.yaml",
            source: options.source_kind.source_label(),
            source_relay_service_url: None,
            source_url: Some(&options.source_url),
            source_token_env: options
                .source_kind
                .uses_static_source_token()
                .then_some(options.source_token_env.as_str()),
            source_dataset: Some(&options.source_dataset),
            source_entity: Some(&options.source_entity),
            source_lookup_field: Some(&options.source_lookup_field),
            source_network: options.source_network.as_deref(),
            claims: vec![&options.source_claim],
            smoke_target_id: Some(&options.smoke_target_id),
        }),
        ProjectManifestKind::Relay => None,
    };
    let manifest = ProjectManifest {
        schema_version: PROJECT_SCHEMA_VERSION,
        project: ProjectSection {
            name,
            kind: project_kind,
            products,
        },
        runtime: RuntimeSection {
            engine: "docker_compose",
            compose_file: "compose.yaml",
            relay_image: include_relay.then_some(RELAY_IMAGE),
            relay_base_url: include_relay.then_some(RELAY_BASE_URL),
            notary_image: include_notary.then_some(NOTARY_IMAGE),
            notary_base_url: include_notary.then_some(NOTARY_BASE_URL),
        },
        relay: include_relay.then_some(RelaySection {
            config: "relay/config.yaml",
            metadata: None,
            data: vec!["data/benefits_casework.xlsx"],
        }),
        notary,
        local: LocalSection {
            secrets_env: "secrets/local.env",
            output_dir: "output",
        },
    };
    serde_yaml::to_string(&manifest).context("failed to render registryctl manifest")
}

fn compose_yaml(include_notary: bool) -> String {
    if include_notary {
        include_str!("templates/compose-with-notary.yaml")
            .replace("{{notary_redis_image}}", NOTARY_REDIS_IMAGE)
    } else {
        include_str!("templates/compose.yaml").to_string()
    }
}

fn compose_notary_only_yaml(source_network: Option<&str>) -> String {
    let (service_networks, networks) = match source_network {
        Some(name) => (
            "    networks:\n      - default\n      - source_api\n",
            format!("\nnetworks:\n  source_api:\n    external: true\n    name: {name}\n"),
        ),
        None => ("", String::new()),
    };
    include_str!("templates/compose-notary.yaml")
        .replace("{{notary_redis_image}}", NOTARY_REDIS_IMAGE)
        .replace("{{source_network_service}}", service_networks)
        .replace("{{source_networks}}", &networks)
}

fn project_readme() -> &'static str {
    include_str!("templates/project_readme.md")
}

fn standalone_notary_readme() -> &'static str {
    include_str!("templates/notary_project_readme.md")
}

fn relay_config(credentials: &LocalCredentials) -> String {
    include_str!("templates/relay_config.yaml.tmpl")
        .replace("{{metadata_id}}", credentials.metadata_reader.id)
        .replace("{{row_id}}", credentials.row_reader.id)
        .replace("{{aggregate_id}}", credentials.aggregate_reader.id)
}

fn notary_config(evaluator: &Credential) -> String {
    include_str!("templates/notary_config.yaml.tmpl")
        .replace("{{evaluator_id}}", evaluator.id)
        .replace("{{issuer_key_id}}", NOTARY_DEMO_ISSUER_KEY_ID)
        .replace("{{issuer_kid}}", NOTARY_DEMO_ISSUER_KID)
}

fn notary_config_for_source(evaluator: &Credential, options: &NotaryInitOptions) -> String {
    let template = if options.source_kind == NotaryInitSourceKind::OpencrvsDci {
        include_str!("templates/notary_opencrvs_dci_config.yaml.tmpl")
    } else {
        include_str!("templates/notary_standalone_config.yaml.tmpl")
    };
    template
        .replace("{{evaluator_id}}", evaluator.id)
        .replace("{{issuer_key_id}}", NOTARY_DEMO_ISSUER_KEY_ID)
        .replace("{{issuer_kid}}", NOTARY_DEMO_ISSUER_KID)
        .replace("{{source_connection}}", options.source_kind.connection_id())
        .replace("{{source_connector}}", options.source_kind.connector())
        .replace("{{source_binding}}", options.source_kind.source_binding())
        .replace("{{source_url}}", &options.source_url)
        .replace("{{source_token_env}}", &options.source_token_env)
        .replace(
            "{{source_retry_on_5xx}}",
            options.source_kind.retry_on_5xx(),
        )
        .replace("{{source_bulk_mode}}", options.source_kind.bulk_mode())
        .replace("{{source_dataset}}", &options.source_dataset)
        .replace("{{source_entity}}", &options.source_entity)
        .replace("{{source_lookup_field}}", &options.source_lookup_field)
        .replace("{{source_claim}}", &options.source_claim)
        .replace("{{source_claim_title}}", &options.source_claim_title)
}

fn standalone_notary_env_file(
    credentials: &NotaryLocalCredentials,
    options: &NotaryInitOptions,
) -> String {
    let mut env = String::new();
    for (name, value) in credentials.env_values_for_source(options) {
        env.push_str(&name);
        env.push('=');
        env.push_str(&value);
        env.push('\n');
    }
    env
}

#[derive(Debug, Deserialize, Serialize)]
struct SmokeReport {
    base_url: String,
    passed: bool,
    checks: Vec<SmokeCheck>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SmokeCheck {
    name: String,
    method: String,
    path: String,
    expected_status: u16,
    actual_status: Option<u16>,
    passed: bool,
    error: Option<String>,
}

fn run_smoke_checks(base_url: &str, secrets: &LocalEnv) -> SmokeReport {
    let mut checks = Vec::new();

    record_smoke_check(
        &mut checks,
        base_url,
        "healthz is public",
        "/healthz",
        200,
        &[],
    );
    record_smoke_check(&mut checks, base_url, "ready is public", "/ready", 200, &[]);
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous dataset request is denied",
        "/v1/datasets",
        401,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "metadata key can list datasets",
        "/v1/datasets",
        200,
        &[bearer_header(secrets.value("METADATA_READER_RAW"))],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "metadata key cannot read rows",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        403,
        &[
            bearer_header(secrets.value("METADATA_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                "https://example.local/purpose/tutorial".to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "row read without Data-Purpose returns 400",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        400,
        &[bearer_header(secrets.value("ROW_READER_RAW"))],
    );
    record_row_data_smoke_check(
        &mut checks,
        base_url,
        "row reader can read filtered records",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        &[
            bearer_header(secrets.value("ROW_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                "https://example.local/purpose/tutorial".to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous caller can fetch runtime OpenAPI",
        "/openapi.json",
        200,
        &[],
    );

    SmokeReport {
        base_url: base_url.to_string(),
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn run_notary_smoke_checks(
    base_url: &str,
    secrets: &LocalEnv,
    claim_id: &str,
    smoke_target: Value,
) -> SmokeReport {
    let mut checks = Vec::new();
    let api_key = secrets.value("REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW");
    let evaluation_body = serde_json::json!({
        "target": smoke_target,
        "claims": [claim_id],
        "disclosure": "predicate",
        "purpose": TUTORIAL_PURPOSE
    })
    .to_string();

    record_smoke_check(
        &mut checks,
        base_url,
        "notary healthz is public",
        "/healthz",
        200,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "notary ready is public",
        "/ready",
        200,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous claims request is denied",
        "/v1/claims",
        401,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous caller can open Notary API docs",
        "/docs",
        200,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous caller can fetch Notary OpenAPI",
        "/openapi.json",
        200,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "notary evaluator can list claims",
        "/v1/claims",
        200,
        &[
            api_key_header(api_key),
            ("Accept".to_string(), "application/json".to_string()),
        ],
    );
    record_notary_evaluation_check(
        &mut checks,
        base_url,
        "notary evaluator can verify starter claim",
        "/v1/evaluations",
        &[
            api_key_header(api_key),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), NOTARY_CLAIM_RESULT_JSON.to_string()),
            ("Data-Purpose".to_string(), TUTORIAL_PURPOSE.to_string()),
        ],
        &evaluation_body,
        claim_id,
    );

    SmokeReport {
        base_url: base_url.to_string(),
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn parse_smoke_report(contents: &str) -> Result<SmokeReport> {
    serde_json::from_str(contents).context("failed to parse smoke result JSON")
}

fn record_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    expected_status: u16,
    headers: &[(String, String)],
) {
    let url = format!("{base_url}{path}");
    match http_get(&url, headers) {
        Ok(response) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status,
            actual_status: Some(response.status),
            passed: response.status == expected_status,
            error: None,
        }),
        Err(err) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&err.to_string())),
        }),
    }
}

fn record_row_data_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    headers: &[(String, String)],
) {
    let url = format!("{base_url}{path}");
    match http_get(&url, headers) {
        Ok(response) => {
            let has_rows = response.status == 200
                && serde_json::from_str::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| value["data"].as_array().map(|data| !data.is_empty()))
                    .unwrap_or(false);
            checks.push(SmokeCheck {
                name: name.to_string(),
                method: "GET".to_string(),
                path: path.to_string(),
                expected_status: 200,
                actual_status: Some(response.status),
                passed: has_rows,
                error: (!has_rows)
                    .then(|| "row response did not include any sample records".to_string()),
            });
        }
        Err(err) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status: 200,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&err.to_string())),
        }),
    }
}

fn record_notary_evaluation_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    headers: &[(String, String)],
    body: &str,
    claim_id: &str,
) {
    let url = format!("{base_url}{path}");
    match http_post(&url, headers, body) {
        Ok(response) => {
            let result_ok = response.status == 200
                && serde_json::from_str::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| {
                        value["results"].as_array().map(|results| {
                            results.iter().any(|result| {
                                result["claim_id"].as_str() == Some(claim_id)
                                    && result["satisfied"].as_bool() == Some(true)
                            })
                        })
                    })
                    .unwrap_or(false);
            checks.push(SmokeCheck {
                name: name.to_string(),
                method: "POST".to_string(),
                path: path.to_string(),
                expected_status: 200,
                actual_status: Some(response.status),
                passed: result_ok,
                error: (!result_ok).then(|| {
                    "evaluation response did not include a satisfied tutorial claim".to_string()
                }),
            });
        }
        Err(err) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "POST".to_string(),
            path: path.to_string(),
            expected_status: 200,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&err.to_string())),
        }),
    }
}

fn bearer_header(raw_key: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {raw_key}"))
}

fn api_key_header(raw_key: &str) -> (String, String) {
    ("x-api-key".to_string(), raw_key.to_string())
}

fn redact_error(error: &str) -> String {
    if error.len() > 240 {
        format!("{}...", &error[..240])
    } else {
        error.to_string()
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: String,
}

fn http_get(url: &str, headers: &[(String, String)]) -> Result<HttpResponse> {
    http_request("GET", url, headers, "")
}

fn http_post(url: &str, headers: &[(String, String)], body: &str) -> Result<HttpResponse> {
    http_request("POST", url, headers, body)
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<HttpResponse> {
    let parsed = ParsedHttpUrl::parse(url)?;
    let addr = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("could not resolve {}", parsed.host))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("failed to connect to {}", parsed.authority()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    write!(
        stream,
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        parsed.path, parsed.host
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !body.is_empty() {
        write!(stream, "Content-Length: {}\r\n", body.len())?;
    }
    write!(stream, "\r\n")?;
    if !body.is_empty() {
        write!(stream, "{body}")?;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP response from {}", parsed.authority()))?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok(HttpResponse { status, body })
}

#[derive(Debug)]
struct ParsedHttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl ParsedHttpUrl {
    fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("only http:// local URLs are supported"))?;
        let (authority, path) = rest
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or_else(|| (rest, "/".to_string()));
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            let parsed_port = port
                .parse::<u16>()
                .with_context(|| format!("invalid URL port in {url}"))?;
            (host.to_string(), parsed_port)
        } else {
            (authority.to_string(), 80)
        };
        Ok(Self { host, port, path })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use registry_config_report::REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1;
    use serde_json::Value as JsonValue;
    use serde_yaml::Value;
    use tempfile::TempDir;

    use super::*;

    const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

    #[test]
    fn config_bundle_sign_anchor_and_verify_round_trip() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let bundle_dir = temp.path().join("bundle");
        fs::create_dir_all(input_dir.join("config")).unwrap();
        let config_bytes = b"server:\n  bind: 127.0.0.1:8080\n";
        fs::write(input_dir.join("config/notary.yaml"), config_bytes).unwrap();
        let config_hash = registry_platform_config::sha256_uri(config_bytes);
        let private_path = temp.path().join("private.jwk");
        fs::write(&private_path, TEST_PRIVATE_JWK).unwrap();
        let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
        let public = private.public();
        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
        let anchor_path = temp.path().join("trust_anchor.json");

        let init = init_config_anchor(
            &anchor_path,
            "registry-notary".to_string(),
            "production".to_string(),
            "civil-registry".to_string(),
            "notary-011".to_string(),
        )
        .unwrap();
        assert_eq!(init.signer_count, 0);

        let sign = sign_config_bundle(BundleSignOptions {
            input: input_dir,
            key: private_path.display().to_string(),
            product: "registry-notary".to_string(),
            environment: "production".to_string(),
            stream_id: "civil-registry".to_string(),
            instance_id: None,
            sequence: 1,
            bundle_id: "rollout-1".to_string(),
            out: bundle_dir.clone(),
        })
        .unwrap();
        assert_eq!(sign.alg, "EdDSA");
        assert_eq!(sign.signature_count, 1);
        assert_eq!(sign.config_path, "config/notary.yaml");

        let add = add_config_anchor_key(&anchor_path, &public_path, true).unwrap();
        assert_eq!(add.signer_count, 1);
        assert_eq!(add.enabled_signer_count, 1);

        let inspect = inspect_config_bundle(&bundle_dir).unwrap();
        assert_eq!(inspect.signature_count, 1);
        assert_eq!(inspect.manifest.bundle_id, "rollout-1");

        let verified = verify_config_bundle_cli(&bundle_dir, &anchor_path).unwrap();
        assert_eq!(verified.config_hash, config_hash);
        assert_eq!(verified.signer_kids, vec![public.jkt().unwrap()]);
        assert_eq!(verified.config_path, bundle_dir.join("config/notary.yaml"));
    }

    #[test]
    fn config_anchor_remove_key_updates_anchor_without_private_material() {
        let temp = TempDir::new().unwrap();
        let anchor_path = temp.path().join("trust_anchor.json");
        let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
        let public = private.public();
        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();
        init_config_anchor(
            &anchor_path,
            "registry-notary".to_string(),
            "production".to_string(),
            "civil-registry".to_string(),
            "notary-011".to_string(),
        )
        .unwrap();
        add_config_anchor_key(&anchor_path, &public_path, true).unwrap();

        let report = remove_config_anchor_key(&anchor_path, &public.jkt().unwrap()).unwrap();

        assert_eq!(report.signer_count, 0);
        let anchor = fs::read_to_string(anchor_path).unwrap();
        assert!(!anchor.contains(r#""d":"#));
        assert!(!anchor.contains(r#""d": "#));
    }

    #[cfg(unix)]
    #[test]
    fn config_anchor_writes_verifier_safe_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let anchor_path = temp.path().join("trust_anchor.json");
        let private = PrivateJwk::parse(TEST_PRIVATE_JWK).unwrap();
        let public = private.public();
        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec_pretty(&public).unwrap()).unwrap();

        init_config_anchor(
            &anchor_path,
            "registry-notary".to_string(),
            "production".to_string(),
            "civil-registry".to_string(),
            "notary-011".to_string(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut permissions = fs::metadata(&anchor_path).unwrap().permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&anchor_path, permissions).unwrap();

        add_config_anchor_key(&anchor_path, &public_path, true).unwrap();
        assert_eq!(
            fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut permissions = fs::metadata(&anchor_path).unwrap().permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&anchor_path, permissions).unwrap();

        remove_config_anchor_key(&anchor_path, &public.jkt().unwrap()).unwrap();
        assert_eq!(
            fs::metadata(&anchor_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn assert_digest_pinned_image(image: &str, repository: &str) {
        assert!(image.starts_with(&format!("{repository}@sha256:")));
        assert!(!image.contains(":snapshot"));
        assert!(!image.contains(":latest"));
    }

    fn assert_no_local_demo_external_auth_deps(label: &str, contents: &str) {
        let normalized = contents.to_ascii_lowercase();
        let boundary_normalized = normalized
            .chars()
            .map(|value| {
                if value.is_alphanumeric() || value == '-' || value == '_' || value == ' ' {
                    value
                } else {
                    ' '
                }
            })
            .collect::<String>();
        for forbidden in [
            "assisted access",
            "assisted-access",
            "assisted_access",
            "e-signet",
            "oidc",
            "oauth",
            "openid",
            "sts-url",
            "sts url",
            "security token service",
            "security-token-service",
            "security_token_service",
            "transaction-token",
            "transaction_token",
            "transaction token",
        ] {
            assert!(
                !boundary_normalized.contains(forbidden),
                "{label} should not reference external auth dependency {forbidden:?}"
            );
        }

        for word in boundary_normalized.split_whitespace() {
            assert!(
                word != "esign" && word != "sts",
                "{label} should not reference external auth dependency {word:?}"
            );
        }
    }

    #[test]
    fn registryctl_manifest_has_no_external_auth_dependencies() {
        let manifest =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
        assert_no_local_demo_external_auth_deps("registryctl Cargo.toml", &manifest);
        for forbidden_dependency in [
            "registry-platform-sts",
            "registry-assisted-access",
            "registry-platform-oidc",
        ] {
            assert!(
                !manifest.contains(forbidden_dependency),
                "registryctl must not depend on {forbidden_dependency}"
            );
        }
    }

    fn openfn_options(temp: &TempDir) -> OpenFnConvertOptions {
        OpenFnConvertOptions {
            input: temp.path().join("openfn.yaml"),
            workflow: Some("lookup".to_string()),
            output: temp.path().join("openfn-sidecar.yaml"),
            jobs_dir: temp.path().join("jobs"),
            expression_prefix: Some(PathBuf::from("/opt/openfn/jobs")),
            source_id: "openfn_crvs".to_string(),
            dataset: "civil_registry".to_string(),
            entity: "civil_person".to_string(),
            credential_env: "OPENCRVS_READER_CREDENTIAL_JSON".to_string(),
            allowed_base_urls: vec!["https://opencrvs.example.test".to_string()],
            smoke_field: "national_id".to_string(),
            smoke_value: "smoke-person".to_string(),
            smoke_fields: Some("national_id,birth_date".to_string()),
            smoke_purpose: "startup-readiness-smoke".to_string(),
            auth_hash_env: "DEV_SIDECAR_TOKEN_HASH".to_string(),
            server_bind: "127.0.0.1:9191".to_string(),
            cli_build_tool: "1.2.5".to_string(),
            runtime: "1.9.3".to_string(),
            worker_command: PathBuf::from("node"),
            worker_script: PathBuf::from("/opt/openfn/openfn_worker.mjs"),
            max_workers: 2,
            worker_timeout_ms: 10000,
            max_worker_memory_mb: 512,
            max_output_bytes: 1048576,
            max_request_bytes: 16384,
            max_query_parameter_bytes: 1024,
            max_batch_items: 100,
            batch_mode: OpenFnBatchMode::PerItem,
            notary_snippet_output: Some(temp.path().join("notary-openfn-snippet.yaml")),
            sidecar_base_url: Some("http://127.0.0.1:9191".to_string()),
            sidecar_token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
            allow_latest_adaptors: false,
            allow_empty_job_bodies: false,
        }
    }

    fn openfn_import_options(temp: &TempDir) -> OpenFnImportOptions {
        OpenFnImportOptions {
            input: temp.path().join("openfn.yaml").display().to_string(),
            openfn_token_env: "OPENFN_TOKEN".to_string(),
            workflow: Some("lookup".to_string()),
            output: temp.path().join("openfn/openfn-sidecar.yaml"),
            jobs_dir: temp.path().join("openfn/jobs"),
            expression_prefix: PathBuf::from("/opt/openfn/jobs"),
            source_id: "openfn_crvs".to_string(),
            dataset: "civil_registry".to_string(),
            entity: "civil_person".to_string(),
            credential_env: "OPENCRVS_READER_CREDENTIAL_JSON".to_string(),
            allowed_base_urls: vec!["https://opencrvs.example.test".to_string()],
            smoke: "national_id=smoke-person".to_string(),
            smoke_fields: Some("national_id,birth_date".to_string()),
            smoke_purpose: "startup-readiness-smoke".to_string(),
            auth_hash_env: "DEV_SIDECAR_TOKEN_HASH".to_string(),
            server_bind: "127.0.0.1:9191".to_string(),
            cli_build_tool: "1.2.5".to_string(),
            runtime: "1.9.3".to_string(),
            worker_command: PathBuf::from("node"),
            worker_script: PathBuf::from("/opt/openfn/openfn_worker.mjs"),
            max_workers: 2,
            worker_timeout_ms: 10000,
            max_worker_memory_mb: 512,
            max_output_bytes: 1048576,
            max_request_bytes: 16384,
            max_query_parameter_bytes: 1024,
            max_batch_items: 100,
            batch_mode: OpenFnBatchMode::PerItem,
            notary_snippet_output: Some(temp.path().join("openfn/notary-source-snippet.yaml")),
            sidecar_base_url: Some("http://127.0.0.1:9191".to_string()),
            sidecar_token_env: "OPENFN_SIDECAR_TOKEN".to_string(),
            allow_latest_adaptors: false,
            allow_empty_job_bodies: false,
        }
    }

    #[test]
    fn update_check_detects_newer_semver_tags() {
        assert!(is_newer_release("0.1.0", "v0.1.1"));
        assert!(is_newer_release("0.1.9", "v0.10.0"));
        assert!(!is_newer_release("0.1.0", "v0.1.0"));
        assert!(!is_newer_release("0.2.0", "v0.1.9"));
        assert!(!is_newer_release("not-a-version", "v0.2.0"));
    }

    #[test]
    fn update_notice_uses_pinned_installer_version() {
        let notice = update_notice("0.1.0", "v0.2.0");

        assert!(notice.contains("registryctl v0.2.0 is available"));
        assert!(notice.contains("You have v0.1.0"));
        assert!(notice.contains("REGISTRYCTL_VERSION=v0.2.0"));
        assert!(notice.contains(REGISTRYCTL_INSTALL_SCRIPT));
    }

    #[test]
    fn update_check_cache_round_trips_latest_tag() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("registryctl/update-check.json");

        write_update_check_cache(&cache_path, "v0.2.0").unwrap();

        let read = read_update_check_cache(&cache_path).unwrap().unwrap();
        assert_eq!(read.latest_tag, "v0.2.0");
        assert!(read.is_fresh);
    }

    #[test]
    fn update_check_reads_stale_cache_for_nonblocking_notice() {
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("registryctl/update-check.json");
        let cache = UpdateCheckCache {
            checked_at: 1,
            latest_tag: "v0.2.0".to_string(),
        };
        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        fs::write(&cache_path, serde_json::to_string(&cache).unwrap()).unwrap();

        let read = read_update_check_cache(&cache_path).unwrap().unwrap();

        assert_eq!(read.latest_tag, "v0.2.0");
        assert!(!read.is_fresh);
    }

    #[test]
    fn openfn_url_parser_derives_api_export_urls() {
        let parsed = parse_openfn_workflow_url(
            "https://app.openfn.org/projects/604b650e-a33a-41d2-b30b-5e7a5b773f30/w/7c90b5e8-ff4f-46a5-958a-a7150035410b",
        )
        .unwrap()
        .unwrap();

        assert_eq!(parsed.project_id, "604b650e-a33a-41d2-b30b-5e7a5b773f30");
        assert_eq!(
            parsed.workflow_id.as_deref(),
            Some("7c90b5e8-ff4f-46a5-958a-a7150035410b")
        );
        assert_eq!(
            parsed.project_yaml_url,
            "https://app.openfn.org/api/provision/604b650e-a33a-41d2-b30b-5e7a5b773f30.yaml"
        );
        assert_eq!(
            parsed.workflow_json_url.as_deref(),
            Some("https://app.openfn.org/api/workflows/7c90b5e8-ff4f-46a5-958a-a7150035410b?project_id=604b650e-a33a-41d2-b30b-5e7a5b773f30")
        );
    }

    #[test]
    fn openfn_import_from_file_uses_compact_smoke_option_and_writes_outputs() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
workflows:
  lookup:
    jobs:
      prepare_lookup:
        adaptor: "@openfn/language-common@3.2.3"
        body: |
          fn(state => state)
    triggers:
      webhook:
        type: webhook
        enabled: true
    edges:
      webhook->prepare_lookup:
        source_trigger: webhook
        target_job: prepare_lookup
        condition_type: always
        enabled: true
"#;
        fs::write(temp.path().join("openfn.yaml"), yaml).unwrap();
        let options = openfn_import_options(&temp);

        import_openfn_project(options).unwrap();

        assert!(temp.path().join("openfn/openfn-sidecar.yaml").exists());
        assert!(temp.path().join("openfn/jobs/prepare_lookup.js").exists());
        assert!(temp
            .path()
            .join("openfn/notary-source-snippet.yaml")
            .exists());
        let manifest: Value = serde_yaml::from_str(
            &fs::read_to_string(temp.path().join("openfn/openfn-sidecar.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["smoke_lookup"]["field"],
            "national_id"
        );
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["smoke_lookup"]["value"],
            "smoke-person"
        );
        assert_eq!(manifest["sources"]["openfn_crvs"]["engine"], "openfn");
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["workflow"]["batch_mode"],
            "per_item"
        );
        assert_eq!(manifest["limits"]["max_batch_items"], 100);
    }

    #[test]
    fn openfn_conversion_writes_sidecar_manifest_and_job_files() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
workflows:
  lookup:
    jobs:
      prepare_lookup:
        adaptor: "@openfn/language-common@3.2.3"
        credential: opencrvs-reader
        body: |
          fn(state => state)
      fetch_person:
        adaptor: "@openfn/language-http@7.2.0"
        credential: opencrvs-reader
        body: |
          get('/people')
    triggers:
      webhook:
        type: webhook
        enabled: true
    edges:
      webhook->prepare_lookup:
        source_trigger: webhook
        target_job: prepare_lookup
        condition_type: always
        enabled: true
      prepare_lookup->fetch_person:
        source_job: prepare_lookup
        target_job: fetch_person
        condition_type: on_job_success
        enabled: true
"#;
        let options = openfn_options(&temp);

        let conversion = build_openfn_sidecar_conversion(yaml, &options).unwrap();

        assert_eq!(conversion.workflow_key, "lookup");
        assert_eq!(conversion.job_files.len(), 2);
        assert_eq!(
            conversion.job_files[0].path,
            temp.path().join("jobs/fetch_person.js")
        );
        assert_eq!(
            conversion.job_files[1].path,
            temp.path().join("jobs/prepare_lookup.js")
        );
        let manifest: Value = serde_yaml::from_str(&conversion.manifest_yaml).unwrap();
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["workflow"]["start"],
            "prepare_lookup"
        );
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["workflow"]["batch_mode"],
            "per_item"
        );
        assert_eq!(manifest["limits"]["max_batch_items"], 100);
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["workflow"]["steps"][0]["expression"],
            "/opt/openfn/jobs/fetch_person.js"
        );
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["workflow"]["steps"][1]["next"]["fetch_person"],
            true
        );
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["smoke_lookup"]["fields"][1],
            "birth_date"
        );
        assert!(
            conversion.warnings[0].contains("sidecar will read OPENCRVS_READER_CREDENTIAL_JSON")
        );
        let snippet: Value = serde_yaml::from_str(&conversion.notary_snippet_yaml).unwrap();
        assert_eq!(
            snippet["evidence"]["source_connections"]["openfn_crvs"]["bulk_mode"],
            "openfn_sidecar_batch"
        );
        assert_eq!(
            snippet["evidence"]["claims"][0]["operations"]["batch_evaluate"]["max_subjects"],
            100
        );
    }

    #[test]
    fn openfn_native_batch_requires_registry_notary_adaptor_and_renders_mode() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
workflows:
  lookup:
    jobs:
      batch_lookup:
        adaptor: "@registry/notary-openfn@0.1.0"
        body: |
          fn(state => returnBatchItems(state, []))
    triggers:
      webhook:
        type: webhook
        enabled: true
    edges:
      webhook->batch_lookup:
        source_trigger: webhook
        target_job: batch_lookup
        condition_type: always
        enabled: true
"#;
        let mut options = openfn_options(&temp);
        options.batch_mode = OpenFnBatchMode::Native;

        let conversion = build_openfn_sidecar_conversion(yaml, &options).unwrap();

        let manifest: Value = serde_yaml::from_str(&conversion.manifest_yaml).unwrap();
        assert_eq!(
            manifest["sources"]["openfn_crvs"]["workflow"]["batch_mode"],
            "native"
        );
        assert!(conversion
            .warnings
            .iter()
            .any(|warning| warning.contains("Registry Notary OpenFn adaptor detected")));
    }

    #[test]
    fn openfn_native_batch_rejects_workflows_without_registry_notary_adaptor() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
workflows:
  lookup:
    jobs:
      batch_lookup:
        adaptor: "@openfn/language-common@3.2.3"
        body: |
          fn(state => state)
    triggers:
      webhook:
        type: webhook
        enabled: true
    edges:
      webhook->batch_lookup:
        source_trigger: webhook
        target_job: batch_lookup
        condition_type: always
        enabled: true
"#;
        let mut options = openfn_options(&temp);
        options.batch_mode = OpenFnBatchMode::Native;

        let err = build_openfn_sidecar_conversion(yaml, &options).unwrap_err();

        assert!(err.to_string().contains("@registry/notary-openfn"));
    }

    #[test]
    fn openfn_conversion_rejects_latest_adaptors_by_default() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
name: lookup
jobs:
  prepare:
    adaptor: "@openfn/language-common@latest"
    body: |
      fn(state => state)
triggers:
  webhook:
    type: webhook
    enabled: true
edges:
  webhook->prepare:
    source_trigger: webhook
    target_job: prepare
    condition_type: always
    enabled: true
"#;
        let mut options = openfn_options(&temp);
        options.workflow = None;

        let err = build_openfn_sidecar_conversion(yaml, &options).unwrap_err();

        assert!(err.to_string().contains("uses @latest"));
    }

    #[test]
    fn openfn_conversion_rejects_lightning_joins() {
        let temp = TempDir::new().unwrap();
        let yaml = r#"
workflows:
  lookup:
    jobs:
      start:
        adaptor: "@openfn/language-common@3.2.3"
        body: |
          fn(state => state)
      branch_a:
        adaptor: "@openfn/language-common@3.2.3"
        body: |
          fn(state => state)
      branch_b:
        adaptor: "@openfn/language-common@3.2.3"
        body: |
          fn(state => state)
      join:
        adaptor: "@openfn/language-common@3.2.3"
        body: |
          fn(state => state)
    triggers:
      webhook:
        type: webhook
        enabled: true
    edges:
      webhook->start:
        source_trigger: webhook
        target_job: start
        condition_type: always
        enabled: true
      start->branch_a:
        source_job: start
        target_job: branch_a
        condition_type: on_job_success
        enabled: true
      start->branch_b:
        source_job: start
        target_job: branch_b
        condition_type: on_job_success
        enabled: true
      branch_a->join:
        source_job: branch_a
        target_job: join
        condition_type: on_job_success
        enabled: true
      branch_b->join:
        source_job: branch_b
        target_job: join
        condition_type: on_job_success
        enabled: true
"#;
        let options = openfn_options(&temp);

        let err = build_openfn_sidecar_conversion(yaml, &options).unwrap_err();

        assert!(err
            .to_string()
            .contains("does not support Lightning-style joins"));
    }

    #[test]
    fn init_sample_creates_expected_project_tree() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");

        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            ".env",
            "README.md",
            ".gitignore",
            "relay/config.yaml",
            "data/benefits_casework.xlsx",
            "secrets/local.env",
            "output/.gitkeep",
            "state/relay/cache",
            "state/relay/config-state",
            "state/relay/audit",
            "bruno/registry-api/bruno.json",
            "bruno/registry-api/collection.bru",
            "bruno/registry-api/environments/local.bru",
            "bruno/registry-api/environments/local.example.bru",
            "bruno/registry-api/Relay/Health.bru",
        ] {
            assert!(project.join(path).exists(), "{path} should exist");
        }
        assert_private_state_dirs(
            &project,
            &[
                "state",
                "state/relay",
                "state/relay/cache",
                "state/relay/config-state",
                "state/relay/audit",
            ],
        );
        assert_runtime_env_matches_project_owner(&project);
        assert!(!project.join("relay/metadata.yaml").exists());

        let config_text = fs::read_to_string(project.join("relay/config.yaml")).unwrap();
        assert!(config_text.contains("# This file is the Relay contract"));
        assert!(config_text.contains("# The raw bearer keys live in secrets/local.env."));
        assert!(config_text.contains("# Tables describe the source workbook."));
        assert!(config_text.contains("# Aggregates expose predeclared grouped statistics."));
        assert!(config_text.contains("# Entities are the public API surface."));
        let config: Value = serde_yaml::from_str(&config_text).unwrap();
        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();
        assert!(config.get("metadata").is_none());
        assert!(manifest["relay"].get("metadata").is_none());
        assert!(!compose.contains("metadata.yaml"));
        assert!(compose.contains(
            "user: \"${REGISTRY_STACK_RUNTIME_UID:-65532}:${REGISTRY_STACK_RUNTIME_GID:-65532}\""
        ));
        assert!(compose.contains("./relay:/etc/registry-relay:ro"));
        assert!(compose.contains("./state/relay/cache:/var/lib/registry-relay/cache"));
        assert!(compose.contains("./state/relay/config-state:/var/lib/registry-relay/config-state"));
        assert!(compose.contains("./state/relay/audit:/var/log/registry-relay"));
        assert_eq!(
            config["datasets"][0]["aggregates"][0]["access"]["aggregate_only_execution"],
            true
        );
        assert_eq!(
            config["datasets"][0]["aggregates"][0]["disclosure_control"]["min_group_size"],
            2
        );
        assert_eq!(
            config["datasets"][0]["aggregates"][1]["access"]["aggregate_only_execution"],
            true
        );
        assert_eq!(
            config["datasets"][0]["aggregates"][1]["disclosure_control"]["min_group_size"],
            2
        );

        let readme = fs::read_to_string(project.join("README.md")).unwrap();
        assert!(readme.contains("registryctl doctor --profile local --format json"));
        assert!(readme.contains("redacts local secret values"));
        assert!(readme.contains("Back up that file before upgrades"));
        assert!(readme.contains("https://docs.registrystack.org/operate/backup-and-restore/"));
        assert!(readme
            .contains("https://docs.registrystack.org/operate/single-node-compose-behind-proxy/"));
    }

    #[test]
    fn bruno_files_for_relay_project_are_generated_and_secret_scoped() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let local_bru =
            fs::read_to_string(project.join("bruno/registry-api/environments/local.bru")).unwrap();
        let example_bru =
            fs::read_to_string(project.join("bruno/registry-api/environments/local.example.bru"))
                .unwrap();
        let request =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Read sample people.bru"))
                .unwrap();
        let aggregate_request = fs::read_to_string(
            project.join("bruno/registry-api/Relay/Run households by district aggregate.bru"),
        )
        .unwrap();
        let application_aggregate_request = fs::read_to_string(
            project.join("bruno/registry-api/Relay/Query applications aggregate.bru"),
        )
        .unwrap();
        let openapi_request =
            fs::read_to_string(project.join("bruno/registry-api/Relay/OpenAPI.bru")).unwrap();

        assert!(local_bru.contains(&env_value(&env, "METADATA_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "ROW_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "AGGREGATE_READER_RAW")));
        assert!(example_bru.contains("replace-with-metadata_reader_raw"));
        assert!(example_bru.contains("replace-with-aggregate_reader_raw"));
        assert!(!request.contains(&env_value(&env, "METADATA_READER_RAW")));
        assert!(!request.contains(&env_value(&env, "ROW_READER_RAW")));
        assert!(!aggregate_request.contains(&env_value(&env, "AGGREGATE_READER_RAW")));
        assert!(request.contains("{{relay_row_key}}"));
        assert!(aggregate_request.contains("{{relay_aggregate_key}}"));
        assert!(application_aggregate_request.contains("Data-Purpose"));
        assert!(!openapi_request.contains("Authorization"));
        assert!(!openapi_request.contains("{{relay_metadata_key}}"));
    }

    #[test]
    fn bruno_generation_after_notary_add_includes_notary_requests_without_raw_keys() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let local_bru =
            fs::read_to_string(project.join("bruno/registry-api/environments/local.bru")).unwrap();
        let list_claims =
            fs::read_to_string(project.join("bruno/registry-api/Notary/List claims.bru")).unwrap();
        let evaluate_exists = fs::read_to_string(
            project.join("bruno/registry-api/Notary/Evaluate person exists.bru"),
        )
        .unwrap();
        let evaluate_missing = fs::read_to_string(
            project.join("bruno/registry-api/Notary/Evaluate missing person.bru"),
        )
        .unwrap();
        let notary_requests = format!("{list_claims}\n{evaluate_exists}\n{evaluate_missing}");

        assert!(local_bru.contains(&env_value(&env, "REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW")));
        assert!(
            !notary_requests.contains(&env_value(&env, "REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW"))
        );
        assert!(notary_requests.contains("{{notary_evaluator_key}}"));
        assert!(notary_requests.contains("x-api-key: {{notary_evaluator_key}}"));
        assert!(!notary_requests.contains("X-Api-Key"));
    }

    #[test]
    fn bruno_generate_is_idempotent_for_generated_files() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let before =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Health.bru")).unwrap();
        bruno_generate_project(&project, false).unwrap();
        let after =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Health.bru")).unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn standalone_notary_init_creates_notary_only_project() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-notary");
        init_notary_project(
            &project,
            NotaryInitOptions {
                source_kind: NotaryInitSourceKind::RegistryDataApi,
                source_url: "http://registry-relay:8080".to_string(),
                source_token_from_env: None,
                source_token_env: "EVIDENCE_SOURCE_API_TOKEN".to_string(),
                source_dataset: "benefits_casework".to_string(),
                source_entity: "person".to_string(),
                source_lookup_field: "id".to_string(),
                source_network: Some("my-first-api_default".to_string()),
                source_claim: "benefits-person-exists".to_string(),
                source_claim_title: "Benefits person exists".to_string(),
                smoke_target_id: "per-2001".to_string(),
            },
        )
        .unwrap();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            ".env",
            "README.md",
            ".gitignore",
            "notary/config.yaml",
            "secrets/local.env",
            "output/.gitkeep",
            "state/notary/config-state",
            "state/notary/audit",
            "bruno/registry-api/Notary/Evaluate person exists.bru",
        ] {
            assert!(project.join(path).exists(), "{path} should exist");
        }
        assert_private_state_dirs(
            &project,
            &[
                "state",
                "state/notary",
                "state/notary/config-state",
                "state/notary/audit",
            ],
        );
        assert_runtime_env_matches_project_owner(&project);

        let readme = fs::read_to_string(project.join("README.md")).unwrap();
        assert!(readme.contains("registryctl doctor --profile local --format json"));
        assert!(readme.contains("calls the Notary"));
        assert!(readme.contains("validator and redacts local secret values"));
        assert!(readme.contains("Back up that file before upgrades"));
        assert!(readme.contains("https://docs.registrystack.org/operate/backup-and-restore/"));
        assert!(readme
            .contains("https://docs.registrystack.org/operate/single-node-compose-behind-proxy/"));

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        assert!(manifest.get("relay").is_none());
        assert_eq!(manifest["project"]["kind"], "notary");
        assert_eq!(manifest["runtime"]["notary_image"], NOTARY_IMAGE);
        assert_eq!(manifest["runtime"]["notary_base_url"], NOTARY_BASE_URL);
        assert_eq!(manifest["notary"]["source"], "registry_data_api");
        assert_eq!(
            manifest["notary"]["source_url"],
            "http://registry-relay:8080"
        );
        assert_eq!(manifest["notary"]["source_network"], "my-first-api_default");

        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();
        assert!(compose.contains("registry-notary:"));
        assert!(!compose.contains("registry-relay:"));
        assert!(compose.contains(
            "user: \"${REGISTRY_STACK_RUNTIME_UID:-65532}:${REGISTRY_STACK_RUNTIME_GID:-65532}\""
        ));
        assert!(compose.contains("host.docker.internal:host-gateway"));
        assert!(compose.contains("name: my-first-api_default"));
        assert!(compose.contains("- source_api"));
        assert!(compose.contains("./notary:/etc/registry-notary:ro"));
        assert!(
            compose.contains("./state/notary/config-state:/var/lib/registry-notary/config-state")
        );
        assert!(compose.contains("./state/notary/audit:/var/log/registry-notary"));
        assert!(compose.contains("command: [\"redis-server\", \"--appendonly\", \"yes\"]"));
        assert!(compose.contains("registry-notary-redis-data:/data"));

        let config = fs::read_to_string(project.join("notary/config.yaml")).unwrap();
        let config_yaml: Value = serde_yaml::from_str(&config).unwrap();
        assert_eq!(config_yaml["server"]["openapi_requires_auth"], false);
        assert!(config.contains("base_url: http://registry-relay:8080"));
        assert!(config.contains("token_env: EVIDENCE_SOURCE_API_TOKEN"));

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        assert!(env.contains(&format!(
            "EVIDENCE_SOURCE_API_TOKEN={STANDALONE_SOURCE_TOKEN_PLACEHOLDER}"
        )));
        assert!(!config.contains(STANDALONE_SOURCE_TOKEN_PLACEHOLDER));
    }

    #[test]
    fn standalone_notary_init_can_target_fhir_sidecar() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-fhir-notary");
        init_notary_project(
            &project,
            NotaryInitOptions {
                source_kind: NotaryInitSourceKind::FhirSidecar,
                source_url: "http://host.docker.internal:4360".to_string(),
                source_token_from_env: None,
                source_token_env: "FHIR_SIDECAR_TOKEN".to_string(),
                source_dataset: "health_registry".to_string(),
                source_entity: "patient".to_string(),
                source_lookup_field: "national_id".to_string(),
                source_network: None,
                source_claim: "patient-record-exists".to_string(),
                source_claim_title: "Patient record exists".to_string(),
                smoke_target_id: "person-123".to_string(),
            },
        )
        .unwrap();

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        assert_eq!(manifest["notary"]["source"], "fhir_source_adapter_sidecar");
        assert_eq!(
            manifest["notary"]["source_url"],
            "http://host.docker.internal:4360"
        );
        assert_eq!(manifest["notary"]["source_token_env"], "FHIR_SIDECAR_TOKEN");
        assert_eq!(manifest["notary"]["source_dataset"], "health_registry");
        assert_eq!(manifest["notary"]["source_entity"], "patient");
        assert_eq!(manifest["notary"]["source_lookup_field"], "national_id");
        assert_eq!(manifest["notary"]["claims"][0], "patient-record-exists");
        assert_eq!(manifest["notary"]["smoke_target_id"], "person-123");

        let config_yaml: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("notary/config.yaml")).unwrap())
                .unwrap();
        assert_eq!(
            config_yaml["evidence"]["source_connections"]["fhir_sidecar"]["base_url"],
            "http://host.docker.internal:4360"
        );
        assert_eq!(
            config_yaml["evidence"]["source_connections"]["fhir_sidecar"]["token_env"],
            "FHIR_SIDECAR_TOKEN"
        );
        assert_eq!(
            config_yaml["evidence"]["source_connections"]["fhir_sidecar"]["retry_on_5xx"],
            false
        );
        assert_eq!(
            config_yaml["evidence"]["claims"][0]["subject_type"],
            "patient"
        );
        assert_eq!(
            config_yaml["evidence"]["claims"][0]["source_bindings"]["patient"]["connector"],
            "openfn_sidecar"
        );
        assert_eq!(
            config_yaml["evidence"]["claims"][0]["source_bindings"]["patient"]["connection"],
            "fhir_sidecar"
        );
        assert_eq!(
            config_yaml["evidence"]["source_connections"]["fhir_sidecar"]["bulk_mode"],
            "openfn_sidecar_batch"
        );
        assert_eq!(
            config_yaml["evidence"]["claims"][0]["source_bindings"]["patient"]["dataset"],
            "health_registry"
        );
        assert_eq!(
            config_yaml["evidence"]["claims"][0]["source_bindings"]["patient"]["entity"],
            "patient"
        );
        assert_eq!(
            config_yaml["evidence"]["claims"][0]["source_bindings"]["patient"]["lookup"]["field"],
            "national_id"
        );

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        assert!(env.contains(&format!(
            "FHIR_SIDECAR_TOKEN={STANDALONE_SOURCE_TOKEN_PLACEHOLDER}"
        )));

        let bruno = fs::read_to_string(
            project.join("bruno/registry-api/Notary/Evaluate person exists.bru"),
        )
        .unwrap();
        assert!(bruno.contains(r#""type": "patient""#));
        assert!(bruno.contains(r#""id": "person-123""#));
        assert!(bruno.contains(r#""claims": ["patient-record-exists"]"#));
    }

    #[test]
    fn standalone_notary_init_can_target_opencrvs_dci() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-opencrvs-notary");
        init_notary_project(
            &project,
            NotaryInitOptions {
                source_kind: NotaryInitSourceKind::OpencrvsDci,
                source_url: "https://opencrvs.example.test".to_string(),
                source_token_from_env: None,
                source_token_env: "OPENCRVS_DCI_UNUSED_STATIC_TOKEN".to_string(),
                source_dataset: "civil_registry".to_string(),
                source_entity: "birth_registration".to_string(),
                source_lookup_field: "UIN".to_string(),
                source_network: None,
                source_claim: "opencrvs-birth-record-exists".to_string(),
                source_claim_title: "OpenCRVS birth record exists".to_string(),
                smoke_target_id: "UIN-2001".to_string(),
            },
        )
        .unwrap();

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        assert_eq!(manifest["notary"]["source"], "opencrvs_dci");
        assert_eq!(
            manifest["notary"]["source_url"],
            "https://opencrvs.example.test"
        );
        assert_eq!(manifest["notary"]["source_dataset"], "civil_registry");
        assert_eq!(manifest["notary"]["source_entity"], "birth_registration");
        assert_eq!(manifest["notary"]["source_lookup_field"], "UIN");
        assert!(manifest["notary"].get("source_token_env").is_none());

        let config = fs::read_to_string(project.join("notary/config.yaml")).unwrap();
        let parsed_config: registry_notary_core::StandaloneRegistryNotaryConfig =
            serde_yaml::from_str(&config).unwrap();
        parsed_config.validate().unwrap();
        let runtime_matching =
            &parsed_config.evidence.claims[0].source_bindings["birth_record"].matching;
        assert!(runtime_matching.require_legal_basis);
        assert!(runtime_matching.require_consent);
        assert_eq!(runtime_matching.permitted_jurisdictions, ["ZZ"]);
        assert_eq!(runtime_matching.allowed_assurance, ["substantial"]);
        assert_eq!(runtime_matching.max_source_age_seconds, Some(86400));
        assert_eq!(
            runtime_matching.source_observed_at_field.as_deref(),
            Some("observed_at")
        );
        assert!(runtime_matching.allowed_legal_basis_refs.is_empty());
        assert!(runtime_matching.allowed_consent_refs.is_empty());

        let config_yaml: Value = serde_yaml::from_str(&config).unwrap();
        let credential = &config_yaml["auth"]["api_keys"][0];
        assert_eq!(
            credential["authorization_details"]["legal_basis_ref"],
            "registryctl:opencrvs-dci:demo-legal-basis"
        );
        assert_eq!(
            credential["authorization_details"]["consent_ref"],
            "registryctl:opencrvs-dci:demo-consent"
        );
        assert_eq!(credential["authorization_details"]["jurisdiction"], "ZZ");
        assert_eq!(
            credential["authorization_details"]["assurance_level"],
            "substantial"
        );

        let source = &config_yaml["evidence"]["source_connections"]["opencrvs_crvs"];
        assert!(source.get("token_env").is_none());
        assert_eq!(source["source_auth"]["type"], "oauth2_client_credentials");
        assert_eq!(source["source_auth"]["client_id_env"], "DCI_CLIENT_ID");
        assert_eq!(
            source["source_auth"]["client_secret_env"],
            "DCI_CLIENT_SECRET"
        );
        assert_eq!(
            source["dci"]["field_paths"]["observed_at"],
            "$response:/message/search_response/0/timestamp"
        );

        let binding = &config_yaml["evidence"]["claims"][0]["source_bindings"]["birth_record"];
        assert_eq!(binding["connector"], "dci");
        assert_eq!(binding["lookup"]["input"], "target.identifiers.UIN");
        assert_eq!(binding["lookup"]["field"], "UIN");
        let matching = &binding["matching"];
        assert!(matching.get("require_legal_basis").is_none());
        assert!(matching.get("require_consent").is_none());
        assert!(matching.get("permitted_jurisdictions").is_none());
        assert!(matching.get("allowed_assurance").is_none());
        assert!(matching.get("max_source_age_seconds").is_none());
        assert_eq!(matching["allowed_purposes"][0], TUTORIAL_PURPOSE);
        let context_constraints = &matching["context_constraints"];
        assert_eq!(context_constraints["legal_basis"]["required"], true);
        assert!(context_constraints["legal_basis"]["allowed_refs"].is_null());
        assert_eq!(context_constraints["consent"]["required"], true);
        assert!(context_constraints["consent"]["allowed_refs"].is_null());
        assert_eq!(context_constraints["jurisdiction"]["permitted"][0], "ZZ");
        assert_eq!(
            context_constraints["assurance"]["allowed"][0],
            "substantial"
        );
        assert_eq!(
            context_constraints["source_freshness"]["max_age_seconds"],
            86400
        );
        assert_eq!(matching["source_observed_at_field"], "observed_at");
        assert_eq!(
            matching["sufficient_target_inputs"][0][0],
            "target.identifiers.UIN"
        );

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        assert!(env.contains("DCI_CLIENT_ID=replace-with-dci-client-id"));
        assert!(env.contains("DCI_CLIENT_SECRET=replace-with-dci-client-secret"));
        assert!(!env.contains("OPENCRVS_DCI_UNUSED_STATIC_TOKEN="));

        let bruno = fs::read_to_string(
            project.join("bruno/registry-api/Notary/Evaluate person exists.bru"),
        )
        .unwrap();
        assert!(bruno.contains(r#""scheme": "UIN""#));
        assert!(bruno.contains(r#""value": "UIN-2001""#));
        assert!(bruno.contains(r#""opencrvs-birth-record-exists""#));
    }

    #[test]
    fn manifest_pins_image_and_records_base_url() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();

        assert_digest_pinned_image(
            manifest["runtime"]["relay_image"].as_str().unwrap(),
            "ghcr.io/registrystack/registry-relay",
        );
        assert_eq!(manifest["runtime"]["relay_base_url"], RELAY_BASE_URL);
        assert!(manifest["relay"].get("metadata").is_none());
        assert!(compose.contains(&format!("image: {RELAY_IMAGE}")));
        assert!(!compose.contains("metadata.yaml"));
        assert!(!compose.contains("registry-relay:snapshot"));
        assert!(!compose.contains("registry-relay:latest"));
    }

    #[test]
    fn compose_platform_override_targets_amd64_for_arm64_relay_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let project = Project::load(&project_dir).unwrap();

        assert_eq!(
            compose_platform_override(&project, None, Some("linux/arm64")),
            Some(LINUX_AMD64_PLATFORM)
        );
        assert_eq!(
            compose_platform_override(&project, None, Some("linux/arm64/v8")),
            Some(LINUX_AMD64_PLATFORM)
        );
        assert_eq!(
            compose_platform_override(&project, None, Some("linux/amd64")),
            None
        );
    }

    #[test]
    fn compose_platform_override_respects_operator_platform() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let project = Project::load(&project_dir).unwrap();

        assert_eq!(
            compose_platform_override(&project, Some("linux/arm64"), Some("linux/arm64")),
            None
        );
    }

    #[test]
    fn compose_platform_override_targets_amd64_for_arm64_notary_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-notary");
        init_standalone_notary_project(&project_dir, default_notary_options()).unwrap();
        let project = Project::load(&project_dir).unwrap();

        assert_eq!(
            compose_platform_override(&project, None, Some("linux/arm64")),
            Some(LINUX_AMD64_PLATFORM)
        );
    }

    #[test]
    fn relay_only_manifest_loads_without_notary_section() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        Project::load(&project).unwrap();

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let products = manifest["project"]["products"]
            .as_sequence()
            .expect("project products should be a list");
        assert!(products
            .iter()
            .any(|product| product.as_str() == Some("registry-relay")));
        assert!(manifest.get("notary").is_none());
        assert!(manifest["runtime"].get("notary_image").is_none());
        assert!(manifest["runtime"].get("notary_base_url").is_none());
    }

    fn write_project_yaml(dir: &Path, yaml: &str) {
        fs::write(dir.join("registryctl.yaml"), yaml).unwrap();
    }

    const MINIMAL_LOCAL_BLOCK: &str =
        "local:\n  secrets_env: secrets/local.env\n  output_dir: output\n";

    // `schema_version` and `project` are required fields with no `#[serde(default)]`, so any
    // fixture exercising `deny_unknown_fields` elsewhere in the document must still supply them
    // (and a complete `runtime` block) to keep the unknown-key/invalid-value error the only
    // possible parse failure.
    const MINIMAL_SCHEMA_AND_PROJECT_BLOCK: &str = "schema_version: registryctl/v1\nproject:\n  name: my-first-api\n  kind: spreadsheet-api\n  products:\n    - registry-relay\n";

    const MINIMAL_RUNTIME_BLOCK: &str =
        "runtime:\n  engine: docker_compose\n  compose_file: compose.yaml\n";

    #[test]
    fn unknown_top_level_key_fails_to_load_naming_the_key() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}noatry:\n  config: notary/config.yaml\n  source: registry_data_api\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("noatry"),
            "error should name the offending key `noatry`: {error:#}"
        );
    }

    #[test]
    fn unknown_key_in_relay_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}relay:\n  config: relay/config.yaml\n  bogus_relay_key: nope\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_relay_key"),
            "error should name the offending key `bogus_relay_key`: {error:#}"
        );
    }

    #[test]
    fn unknown_key_in_notary_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}notary:\n  config: notary/config.yaml\n  source: registry_data_api\n  bogus_notary_key: nope\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_notary_key"),
            "error should name the offending key `bogus_notary_key`: {error:#}"
        );
    }

    #[test]
    fn unknown_key_in_runtime_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}runtime:\n  engine: docker_compose\n  compose_file: compose.yaml\n  bogus_runtime_key: nope\n{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_runtime_key"),
            "error should name the offending key `bogus_runtime_key`: {error:#}"
        );
    }

    #[test]
    fn unknown_key_in_local_section_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}runtime:\n  engine: docker_compose\n  compose_file: compose.yaml\nlocal:\n  secrets_env: secrets/local.env\n  output_dir: output\n  bogus_local_key: nope\n"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("bogus_local_key"),
            "error should name the offending key `bogus_local_key`: {error:#}"
        );
    }

    #[test]
    fn invalid_notary_source_fails_to_load_with_valid_values_listed() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}notary:\n  config: notary/config.yaml\n  source: not_a_real_source\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("not_a_real_source"),
            "error should name the offending value `not_a_real_source`: {rendered}"
        );
        for valid in [
            "registry_data_api",
            "relay",
            "fhir_source_adapter_sidecar",
            "opencrvs_dci",
        ] {
            assert!(
                rendered.contains(valid),
                "error should list valid value `{valid}`: {rendered}"
            );
        }
    }

    #[test]
    fn invalid_schema_version_fails_to_load_naming_the_value() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "schema_version: registryctl/v2\nproject:\n  name: my-first-api\n  kind: spreadsheet-api\n  products:\n    - registry-relay\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("registryctl/v2"),
            "error should name the offending value `registryctl/v2`: {rendered}"
        );
        assert!(
            rendered.contains("registryctl/v1"),
            "error should name the expected value `registryctl/v1`: {rendered}"
        );
    }

    #[test]
    fn missing_schema_version_fails_to_load() {
        let temp = TempDir::new().unwrap();
        write_project_yaml(
            temp.path(),
            &format!(
                "project:\n  name: my-first-api\n  kind: spreadsheet-api\n  products:\n    - registry-relay\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();
        let rendered = format!("{error:#}");

        assert!(
            rendered.contains("schema_version"),
            "error should name the missing field `schema_version`: {rendered}"
        );
    }

    #[test]
    fn manifest_after_notary_add_records_relay_plus_notary() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();

        assert_digest_pinned_image(
            manifest["runtime"]["notary_image"].as_str().unwrap(),
            "ghcr.io/registrystack/registry-notary",
        );
        assert_eq!(
            manifest["runtime"]["notary_base_url"],
            "http://127.0.0.1:4255"
        );
        assert_eq!(manifest["notary"]["config"], "notary/config.yaml");
        assert_eq!(manifest["notary"]["source"], "relay");
        assert_eq!(
            manifest["notary"]["source_relay_service_url"],
            "http://registry-relay:8080"
        );
        let claims = manifest["notary"]["claims"]
            .as_sequence()
            .expect("notary claims should be a list");
        assert!(claims
            .iter()
            .any(|claim| claim.as_str() == Some("benefits-person-exists")));
    }

    #[test]
    fn relay_plus_notary_local_demo_has_no_external_auth_dependencies() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            "relay/config.yaml",
            "notary/config.yaml",
            "bruno/registry-api/environments/local.bru",
            "bruno/registry-api/environments/local.example.bru",
            "bruno/registry-api/Relay/List datasets.bru",
            "bruno/registry-api/Relay/Read sample people.bru",
            "bruno/registry-api/Relay/Read approved applications.bru",
            "bruno/registry-api/Relay/List aggregates.bru",
            "bruno/registry-api/Notary/List claims.bru",
            "bruno/registry-api/Notary/Evaluate person exists.bru",
        ] {
            let contents = fs::read_to_string(project.join(path)).unwrap();
            assert_no_local_demo_external_auth_deps(path, &contents);
        }

        let relay_config: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("relay/config.yaml")).unwrap())
                .unwrap();
        let notary_config_body = fs::read_to_string(project.join("notary/config.yaml")).unwrap();
        assert!(!notary_config_body.contains("commitment:"));
        let notary_config: Value = serde_yaml::from_str(&notary_config_body).unwrap();
        assert_eq!(relay_config["auth"]["mode"], "api_key");
        assert_eq!(notary_config["auth"]["mode"], "api_key");
        assert_eq!(
            notary_config["evidence"]["source_connections"]["relay"]["base_url"],
            "http://registry-relay:8080"
        );
        assert_eq!(
            notary_config["evidence"]["source_connections"]["relay"]["token_env"],
            "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN"
        );

        let local_env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        for key in parse_local_env(&local_env).keys() {
            assert_no_local_demo_external_auth_deps("secrets/local.env key", key);
        }
    }

    #[test]
    fn add_notary_backfills_relay_state_for_older_generated_projects() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        fs::remove_dir_all(project.join("state")).unwrap();
        fs::remove_file(project.join(".env")).unwrap();
        fs::write(project.join(".gitignore"), "secrets/\ncustom-output/\n").unwrap();

        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        for path in [
            "state/relay/cache",
            "state/relay/config-state",
            "state/relay/audit",
            "state/notary/config-state",
            "state/notary/audit",
        ] {
            assert!(project.join(path).exists(), "{path} should exist");
        }
        assert_private_state_dirs(
            &project,
            &[
                "state",
                "state/relay",
                "state/relay/cache",
                "state/relay/config-state",
                "state/relay/audit",
                "state/notary",
                "state/notary/config-state",
                "state/notary/audit",
            ],
        );
        assert_runtime_env_matches_project_owner(&project);
        let gitignore = fs::read_to_string(project.join(".gitignore")).unwrap();
        assert!(gitignore.lines().any(|line| line == "secrets/"));
        assert!(gitignore.lines().any(|line| line == "custom-output/"));
        assert!(gitignore.lines().any(|line| line == ".env"));
        assert!(gitignore.lines().any(|line| line == "state/"));

        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();
        assert!(compose.contains("./state/relay/cache:/var/lib/registry-relay/cache"));
        assert!(compose.contains("./state/relay/config-state:/var/lib/registry-relay/config-state"));
        assert!(compose.contains("./state/relay/audit:/var/log/registry-relay"));
    }

    #[test]
    fn compose_after_notary_add_includes_digest_pinned_notary_service() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();

        assert!(compose.contains("registry-notary:"));
        assert!(compose.contains(&format!("image: {NOTARY_IMAGE}")));
        assert!(!compose.contains("registry-notary:snapshot"));
        assert!(!compose.contains("registry-notary:latest"));
        assert!(compose.contains("registry-notary-redis:"));
        assert!(compose.contains(&format!("image: {NOTARY_REDIS_IMAGE}")));
        assert!(!compose.contains("redis:latest"));
        assert!(compose.contains("\"4255:8080\""));
        assert!(compose.contains("./notary:/etc/registry-notary:ro"));
        assert!(
            compose.contains("./state/notary/config-state:/var/lib/registry-notary/config-state")
        );
        assert!(compose.contains("./state/notary/audit:/var/log/registry-notary"));
        assert!(compose.contains("command: [\"redis-server\", \"--appendonly\", \"yes\"]"));
        assert!(compose.contains("registry-notary-redis-data:/data"));
    }

    #[test]
    fn notary_config_after_add_uses_local_relay_registry_data_api() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        let notary_config_path = project.join("notary/config.yaml");

        assert!(
            notary_config_path.exists(),
            "add-notary generation should create notary/config.yaml"
        );
        let notary_config = fs::read_to_string(notary_config_path).unwrap();
        let notary_config_yaml: Value = serde_yaml::from_str(&notary_config).unwrap();
        assert_eq!(notary_config_yaml["server"]["openapi_requires_auth"], false);
        assert_eq!(
            notary_config_yaml["evidence"]["source_connections"]["relay"]["base_url"],
            "http://registry-relay:8080"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["source_connections"]["relay"]["token_env"],
            "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["claims"][0]["source_bindings"]["person"]["connector"],
            "registry_data_api"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["claims"][0]["id"],
            "benefits-person-exists"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["claims"][0]["source_bindings"]["person"]["dataset"],
            "benefits_casework"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["claims"][0]["source_bindings"]["person"]["entity"],
            "person"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["claims"][0]["source_bindings"]["person"]["lookup"]
                ["field"],
            "id"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["claims"][0]["rule"]["type"],
            "exists"
        );
        assert_eq!(
            notary_config_yaml["evidence"]["signing_keys"][NOTARY_DEMO_ISSUER_KEY_ID]
                ["private_jwk_env"],
            "REGISTRY_NOTARY_ISSUER_JWK"
        );
        assert_eq!(notary_config_yaml["replay"]["storage"], "redis");
        assert_eq!(
            notary_config_yaml["replay"]["redis"]["url_env"],
            "REGISTRY_NOTARY_REPLAY_REDIS_URL"
        );
    }

    #[test]
    fn relay_open_always_reports_docs_url_for_headless_fallback() {
        // On macOS `open <url>` returns success even over SSH with no display,
        // so a conditional fallback never fires. The URL must always be surfaced.
        let lines = relay_open_lines("http://127.0.0.1:4242/docs");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("http://127.0.0.1:4242/docs")),
            "relay open must always print the docs URL for headless environments; got {lines:?}"
        );
    }

    #[test]
    fn notary_open_always_reports_docs_url_for_headless_fallback() {
        let lines = notary_open_lines("http://127.0.0.1:4255");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("http://127.0.0.1:4255/docs")),
            "notary open must always print the docs URL for headless environments; got {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("http://127.0.0.1:4255/openapi.json")),
            "notary open must always print the OpenAPI URL for headless environments; got {lines:?}"
        );
    }

    #[test]
    fn local_relay_notary_config_permits_tutorial_purpose() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        let notary_config = fs::read_to_string(project.join("notary/config.yaml")).unwrap();
        let parsed_config: registry_notary_core::StandaloneRegistryNotaryConfig =
            serde_yaml::from_str(&notary_config).unwrap();
        parsed_config.validate().unwrap();

        // The source-binding PDP policy fails closed: with no purpose allow-list the
        // notary evaluate step denies every request with pdp.purpose_not_permitted
        // before any evidence lookup. The generated project must permit the same
        // tutorial purpose its smoke check and docs send.
        let matching = &parsed_config.evidence.claims[0].source_bindings["person"].matching;
        assert!(
            matching
                .allowed_purposes
                .iter()
                .any(|purpose| purpose == TUTORIAL_PURPOSE),
            "generated local-relay notary source binding must permit the tutorial purpose; \
             got allowed_purposes = {:?}",
            matching.allowed_purposes
        );
    }

    #[test]
    fn standalone_notary_config_permits_tutorial_purpose() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-notary");
        init_standalone_notary_project(&project, default_notary_options()).unwrap();

        let notary_config = fs::read_to_string(project.join("notary/config.yaml")).unwrap();
        let parsed_config: registry_notary_core::StandaloneRegistryNotaryConfig =
            serde_yaml::from_str(&notary_config).unwrap();
        parsed_config.validate().unwrap();

        // `registryctl notary smoke` sends the tutorial purpose for standalone
        // projects too, so the fail-closed source-binding policy must permit it.
        let matching = &parsed_config.evidence.claims[0].source_bindings["person"].matching;
        assert!(
            matching
                .allowed_purposes
                .iter()
                .any(|purpose| purpose == TUTORIAL_PURPOSE),
            "generated standalone notary source binding must permit the tutorial purpose; \
             got allowed_purposes = {:?}",
            matching.allowed_purposes
        );
    }

    #[test]
    fn local_env_after_notary_add_appends_notary_and_source_tokens() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        add_notary(&project, NotarySource::LocalRelay, false).unwrap();

        let local_env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let notary_config_path = project.join("notary/config.yaml");

        assert!(local_env.contains("REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW="));
        assert!(local_env.contains("REGISTRY_NOTARY_TUTORIAL_EVALUATOR_HASH="));
        assert!(local_env.contains("REGISTRY_NOTARY_AUDIT_HASH_SECRET="));
        assert!(local_env.contains("EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN="));
        assert!(local_env.contains("REGISTRY_NOTARY_ISSUER_JWK="));
        assert!(local_env.contains("REGISTRY_NOTARY_REPLAY_REDIS_URL="));

        let relay_row_reader = env_value(&local_env, "ROW_READER_RAW");
        let notary_source_token = env_value(&local_env, "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN");
        let notary_issuer_jwk = env_value(&local_env, "REGISTRY_NOTARY_ISSUER_JWK");
        let notary_config = fs::read_to_string(notary_config_path)
            .expect("add-notary generation should create notary/config.yaml");
        assert_eq!(notary_source_token, relay_row_reader);
        assert!(!notary_config.contains(&env_value(
            &local_env,
            "REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW"
        )));
        assert!(!notary_config.contains(&notary_source_token));
        assert!(!notary_config.contains(&notary_issuer_jwk));
    }

    #[test]
    fn add_notary_refuses_to_overwrite_existing_notary_files() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();
        fs::create_dir_all(project.join("notary")).unwrap();
        let marker_path = project.join("notary/config.yaml");
        fs::write(&marker_path, "user-owned notary config\n").unwrap();

        let error = add_notary(&project, NotarySource::LocalRelay, false).unwrap_err();

        assert!(
            error.to_string().contains("notary/config.yaml")
                && error.to_string().contains("overwrite"),
            "error should name the existing Notary config and overwrite refusal, got: {error}"
        );
        assert_eq!(
            fs::read_to_string(marker_path).unwrap(),
            "user-owned notary config\n"
        );
    }

    #[test]
    fn notary_smoke_project_writes_redacted_failure_report() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        add_notary(&project_dir, NotarySource::LocalRelay, false).unwrap();

        let error = notary_smoke_project(&project_dir).unwrap_err();
        assert!(error
            .to_string()
            .contains("one or more Notary smoke checks failed"));

        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let report =
            fs::read_to_string(project_dir.join("output/notary-smoke-results.json")).unwrap();
        for (_, secret) in env.lines().filter_map(|line| line.split_once('=')) {
            assert!(!report.contains(secret));
        }
        assert!(!report.contains("Alice Johnson"));
        assert!(!report.contains("NID-1001"));
        assert!(report.contains("\"passed\": false"));
    }

    #[test]
    fn generated_gitignore_excludes_local_secrets_and_output() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let gitignore = fs::read_to_string(project.join(".gitignore")).unwrap();
        assert!(gitignore.lines().any(|line| line == ".env"));
        assert!(gitignore.lines().any(|line| line == "secrets/"));
        assert!(gitignore.lines().any(|line| line == "output/"));
        assert!(gitignore.lines().any(|line| line == "state/"));
    }

    #[test]
    fn generated_credentials_reference_fingerprints_without_commitments() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let config = fs::read_to_string(project.join("relay/config.yaml")).unwrap();
        let config_yaml: Value = serde_yaml::from_str(&config).unwrap();
        assert_eq!(config_yaml["server"]["openapi_requires_auth"], false);
        assert!(!config.contains("commitment:"));

        for (id, env_name) in [
            ("metadata_reader", "METADATA_READER_HASH"),
            ("row_reader", "ROW_READER_HASH"),
            ("aggregate_reader", "AGGREGATE_READER_HASH"),
        ] {
            let fingerprint = env_value(&env, env_name);
            assert!(
                fingerprint.starts_with("sha256:"),
                "generated env should contain fingerprint for {id}"
            );
            assert!(
                config.contains(&format!("name: {env_name}")),
                "config should reference fingerprint env for {id}"
            );
        }
    }

    #[test]
    fn generated_fingerprint_preflight_passes_for_clean_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

        let project = Project::load(&project_dir).unwrap();
        validate_project_fingerprints(&project_dir, &project).unwrap();
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_changes() {
        for (env_name, id) in [
            ("METADATA_READER_HASH", "metadata_reader"),
            ("ROW_READER_HASH", "row_reader"),
            ("AGGREGATE_READER_HASH", "aggregate_reader"),
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

            let env_path = project_dir.join("secrets/local.env");
            let mut env = fs::read_to_string(&env_path).unwrap();
            let original = env_value(&env, env_name);
            env = env.replace(
                &original,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            );
            fs::write(&env_path, env).unwrap();

            let project = Project::load(&project_dir).unwrap();
            let error = validate_project_fingerprints(&project_dir, &project).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "local raw key and fingerprint do not match for {id}"
            )));
        }
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_is_missing() {
        for env_name in [
            "METADATA_READER_HASH",
            "ROW_READER_HASH",
            "AGGREGATE_READER_HASH",
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

            let env_path = project_dir.join("secrets/local.env");
            let env = fs::read_to_string(&env_path).unwrap();
            let filtered: String = env
                .lines()
                .filter(|line| !line.starts_with(&format!("{env_name}=")))
                .map(|line| format!("{line}\n"))
                .collect();
            fs::write(&env_path, filtered).unwrap();

            let project = Project::load(&project_dir).unwrap();
            let error = validate_project_fingerprints(&project_dir, &project).unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("missing required local env value {env_name}")));
        }
    }

    #[test]
    fn generated_public_files_do_not_contain_raw_keys_or_fingerprints() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let secrets: BTreeSet<_> = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(name, _)| name.ends_with("_RAW") || name.ends_with("_HASH"))
            .map(|(_, value)| value.to_string())
            .collect();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            "README.md",
            "relay/config.yaml",
        ] {
            let contents = fs::read_to_string(project.join(path)).unwrap();
            for secret in &secrets {
                assert!(
                    !contents.contains(secret),
                    "{path} should not contain generated secret/fingerprint"
                );
            }
        }
    }

    #[test]
    fn generated_workbook_is_xlsx_with_benefits_sample_sheets() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let workbook = fs::read(project.join("data/benefits_casework.xlsx")).unwrap();
        assert!(workbook.starts_with(b"PK"));
        let lossy = String::from_utf8_lossy(&workbook);
        assert!(lossy.contains("Households"));
        assert!(lossy.contains("Persons"));
        assert!(lossy.contains("Applications"));
        assert!(lossy.contains("hh-1001"));
        assert!(lossy.contains("app-3001"));
    }

    #[test]
    fn compose_command_arguments_are_stable() {
        assert_eq!(
            compose_command_args("compose.yaml", &["up", "-d"]),
            ["compose", "-f", "compose.yaml", "up", "-d"]
        );
    }

    #[test]
    fn compose_runner_surfaces_nonzero_exit() {
        let temp = TempDir::new().unwrap();

        run_compose_command_with_platform(temp.path(), "true", &["ps"], None).unwrap();
        let error =
            run_compose_command_with_platform(temp.path(), "false", &["ps"], None).unwrap_err();

        assert!(error.to_string().contains("false compose exited"));
    }

    #[test]
    fn restart_project_requires_a_project_manifest() {
        let temp = TempDir::new().unwrap();

        let error = restart_project(temp.path()).unwrap_err();

        assert!(error.to_string().contains("registryctl.yaml"));
    }

    #[test]
    fn readiness_wait_fails_after_bounded_timeout() {
        let error =
            wait_for_ready("Relay", "http://127.0.0.1:1", Duration::from_millis(1)).unwrap_err();

        assert!(error
            .to_string()
            .contains("Relay did not become healthy and ready before timeout"));
    }

    #[test]
    fn parses_local_http_urls_for_smoke_checks() {
        let parsed = ParsedHttpUrl::parse("http://127.0.0.1:4242/v1/datasets?x=y").unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 4242);
        assert_eq!(parsed.path, "/v1/datasets?x=y");

        let default_port = ParsedHttpUrl::parse("http://localhost/healthz").unwrap();
        assert_eq!(default_port.host, "localhost");
        assert_eq!(default_port.port, 80);
        assert_eq!(default_port.path, "/healthz");
    }

    #[test]
    fn smoke_report_json_does_not_include_local_keys() {
        let secrets = LocalEnv {
            values: BTreeMap::from([
                (
                    "METADATA_READER_RAW".to_string(),
                    "metadata-secret".to_string(),
                ),
                ("ROW_READER_RAW".to_string(), "row-secret".to_string()),
            ]),
        };
        let report = run_smoke_checks("http://127.0.0.1:1", &secrets);
        let json = serde_json::to_string(&report).unwrap();
        let parsed = parse_smoke_report(&json).unwrap();

        assert!(!json.contains("metadata-secret"));
        assert!(!json.contains("row-secret"));
        assert!(!report.passed);
        assert_eq!(parsed.checks.len(), 8);
    }

    #[test]
    fn smoke_project_writes_redacted_failure_report() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

        let error = smoke_project(&project_dir).unwrap_err();
        assert!(error
            .to_string()
            .contains("one or more smoke checks failed"));

        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let report = fs::read_to_string(project_dir.join("output/smoke-results.json")).unwrap();
        for (_, secret) in env.lines().filter_map(|line| line.split_once('=')) {
            assert!(!report.contains(secret));
        }
        assert!(report.contains("\"passed\": false"));
    }

    #[test]
    fn doctor_invokes_relay_product_for_relay_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("relay.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&fake_bin))
                .unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        assert_eq!(report.products.len(), 1);
        assert_eq!(report.products[0].product, "registry-relay");
        assert_eq!(report.products[0].status, ReportStatus::Ok);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["project"]["profile"], "project");
        let args = fs::read_to_string(temp.path().join("relay.args")).unwrap();
        let doctor_config = project_dir.join("output/doctor/relay.config.yaml");
        assert_eq!(
            args,
            format!(
                "doctor\n--config\n{}\n--env-file\n{}\n--format\njson\n",
                doctor_config.display(),
                project_dir.join("secrets/local.env").display(),
            )
        );
        let rendered = fs::read_to_string(&doctor_config).unwrap();
        assert!(!rendered.contains("metadata.yaml"));
        assert!(rendered.contains(
            &project_dir
                .join("data/benefits_casework.xlsx")
                .display()
                .to_string()
        ));
    }

    #[test]
    fn doctor_invokes_relay_product_with_profile_override() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("relay.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report = run_doctor_report_with_path(
            &project_dir,
            DoctorFormat::Json,
            Some(DeploymentProfile::Local),
            Some(&fake_bin),
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["project"]["profile"], "local");
        let args = fs::read_to_string(temp.path().join("relay.args")).unwrap();
        assert_eq!(
            args,
            format!(
                "doctor\n--config\n{}\n--env-file\n{}\n--format\njson\n--profile\nlocal\n",
                project_dir
                    .join("output/doctor/relay.config.yaml")
                    .display(),
                project_dir.join("secrets/local.env").display(),
            )
        );
    }

    #[test]
    fn doctor_invokes_relay_and_notary_for_combined_project_with_profile_override() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        add_notary(&project_dir, NotarySource::LocalRelay, false).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("relay.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );
        write_fake_product(
            &fake_bin.join("registry-notary"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("notary.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-notary", "ok", vec![]))
            ),
        );

        let report = run_doctor_report_with_path(
            &project_dir,
            DoctorFormat::Json,
            Some(DeploymentProfile::Local),
            Some(&fake_bin),
        )
        .unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        assert_eq!(
            report
                .products
                .iter()
                .map(|check| check.product.as_str())
                .collect::<Vec<_>>(),
            ["registry-relay", "registry-notary"]
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["project"]["profile"], "local");
        let relay_args = fs::read_to_string(temp.path().join("relay.args")).unwrap();
        let notary_args = fs::read_to_string(temp.path().join("notary.args")).unwrap();
        assert!(relay_args.contains("output/doctor/relay.config.yaml"));
        assert!(relay_args.contains("\n--profile\nlocal\n"));
        assert!(notary_args.contains("notary/config.yaml"));
        assert!(notary_args.contains("\n--profile\nlocal\n"));
    }

    #[test]
    fn doctor_invokes_only_notary_for_standalone_notary_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("notary-only");
        init_notary_project(&project_dir, default_notary_options()).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-notary"),
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&temp.path().join("notary.args").display().to_string()),
                shell_single_quoted(&fake_product_report("registry-notary", "ok", vec![]))
            ),
        );

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&fake_bin))
                .unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        assert_eq!(report.products.len(), 1);
        assert_eq!(report.products[0].product, "registry-notary");
        assert_eq!(report.products[0].status, ReportStatus::Ok);
        assert!(!temp.path().join("relay.args").exists());
    }

    #[test]
    fn doctor_reports_missing_product_binary_without_panic() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let empty_path = temp.path().join("empty-path");
        fs::create_dir_all(&empty_path).unwrap();

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&empty_path))
                .unwrap();

        assert_eq!(report.status, ReportStatus::Error);
        assert_eq!(report.products[0].status, ReportStatus::NotRun);
        assert!(report.products[0].report.diagnostics[0]
            .message
            .contains("Install registry-relay"));
    }

    #[test]
    fn doctor_reports_nonzero_product_exit_and_redacts_output() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let secrets = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(_, value)| value.to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        let secret_prints = secrets
            .iter()
            .map(|secret| {
                format!(
                    "printf 'stdout has {}\\n'\nprintf 'stderr has {}\\n' >&2\n",
                    shell_single_quoted(secret),
                    shell_single_quoted(secret)
                )
            })
            .collect::<String>();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!("{secret_prints}exit 17\n"),
        );

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&fake_bin))
                .unwrap();
        let json = serde_json::to_string(&report).unwrap();

        assert_eq!(report.status, ReportStatus::Error);
        assert_eq!(report.products[0].status, ReportStatus::Error);
        assert_eq!(
            report.products[0].report.diagnostics[0].code,
            "registryctl.product_doctor.report_missing_after_failure"
        );
        let error = ensure_doctor_report_ok(&report).unwrap_err();
        assert!(error
            .to_string()
            .contains("one or more product doctor checks failed"));
        for secret in &secrets {
            assert!(!json.contains(secret));
        }
    }

    #[test]
    fn secret_redactor_deduplicates_before_length_ordering() {
        let secrets = LocalEnv {
            values: BTreeMap::from([
                ("A".to_string(), "secret1".to_string()),
                ("B".to_string(), "another".to_string()),
                ("C".to_string(), "secret1".to_string()),
                ("D".to_string(), "longer-secret".to_string()),
            ]),
        };

        let redactor = SecretRedactor::new(&secrets);

        assert_eq!(
            redactor.secrets,
            vec![
                "longer-secret".to_string(),
                "another".to_string(),
                "secret1".to_string(),
            ]
        );
    }

    #[test]
    fn doctor_extracts_structured_product_report_and_findings_after_redaction() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let secret = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(_, value)| value)
            .find(|value| !value.is_empty())
            .unwrap();
        let product_json = serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": "registry-relay",
            "config_schema_version": "registry.relay.config.v1",
            "source": {"kind": "generated_file", "path": "relay/config.yaml"},
            "status": "error",
            "summary": {"error_count": 1, "warning_count": 0},
            "diagnostics": [
                {
                    "code": "relay.config.unsigned",
                    "severity": "error",
                    "message": format!("do not leak {secret}")
                }
            ],
            "context_constraints": [],
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' {}\nexit 1\n",
                shell_single_quoted(&product_json)
            ),
        );

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&fake_bin))
                .unwrap();
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(report.status, ReportStatus::Error);
        assert_eq!(json["products"][0]["product"], "registry-relay");
        assert_eq!(
            json["products"][0]["report"]["diagnostics"][0]["code"],
            "relay.config.unsigned"
        );
        let rendered = serde_json::to_string(&json).unwrap();
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn doctor_extracts_notary_diagnostics_as_product_findings() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("notary-only");
        init_notary_project(&project_dir, default_notary_options()).unwrap();
        let product_json = serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": "registry-notary",
            "config_schema_version": "registry.notary.config.v1",
            "source": {"kind": "generated_file", "path": "notary/config.yaml"},
            "status": "warning",
            "summary": {"error_count": 0, "warning_count": 1},
            "diagnostics": [
                {
                    "code": "deployment.profile_undeclared",
                    "severity": "warning",
                    "message": "deployment profile is not declared"
                }
            ],
            "context_constraints": [],
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-notary"),
            &format!(
                "printf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&product_json)
            ),
        );

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&fake_bin))
                .unwrap();
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(report.status, ReportStatus::Warning);
        ensure_doctor_report_ok(&report).unwrap();
        assert_eq!(json["products"][0]["product"], "registry-notary");
        assert_eq!(
            json["products"][0]["report"]["diagnostics"][0]["code"],
            "deployment.profile_undeclared"
        );
    }

    #[test]
    fn doctor_report_json_has_registryctl_schema() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report =
            run_doctor_report_with_path(&project_dir, DoctorFormat::Json, None, Some(&fake_bin))
                .unwrap();
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(
            json["schema_version"],
            REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1
        );
        assert_eq!(json["status"], "ok");
        assert_eq!(json["project"]["profile"], "project");
        assert_eq!(json["products"][0]["status"], "ok");
        let schema: JsonValue =
            serde_json::from_str(REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1).unwrap();
        let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
        let validation_errors = match compiled.validate(&json) {
            Ok(()) => Vec::new(),
            Err(errors) => errors.map(|error| error.to_string()).collect::<Vec<_>>(),
        };
        assert!(
            validation_errors.is_empty(),
            "registryctl doctor report must satisfy its schema: {validation_errors:?}"
        );
    }

    fn write_fake_product(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
        }
        fs::set_permissions(path, permissions).unwrap();
    }

    fn assert_private_state_dirs(project: &Path, paths: &[&str]) {
        for path in paths {
            assert_private_state_dir(project, path);
        }
    }

    #[cfg(unix)]
    fn assert_private_state_dir(project: &Path, path: &str) {
        use std::os::unix::fs::PermissionsExt;

        let actual_mode = fs::metadata(project.join(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(actual_mode, 0o700, "{path} should be private");
    }

    #[cfg(not(unix))]
    fn assert_private_state_dir(_project: &Path, _path: &str) {}

    #[cfg(unix)]
    #[test]
    fn runtime_identity_uses_default_nonroot_for_root_owner() {
        let identity = runtime_identity_for_owner(0, 0);

        assert_eq!(identity.uid.to_string(), DEFAULT_NONROOT_CONTAINER_ID);
        assert_eq!(identity.gid.to_string(), DEFAULT_NONROOT_CONTAINER_ID);

        let identity = runtime_identity_for_owner(1000, 0);
        assert_eq!(identity.uid, 1000);
        assert_eq!(identity.gid.to_string(), DEFAULT_NONROOT_CONTAINER_ID);
    }

    fn assert_runtime_env_matches_project_owner(project: &Path) {
        let env = fs::read_to_string(project.join(".env")).unwrap();
        let uid = env_value(&env, REGISTRY_STACK_RUNTIME_UID_ENV);
        let gid = env_value(&env, REGISTRY_STACK_RUNTIME_GID_ENV);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let metadata = fs::metadata(project).unwrap();
            let identity = runtime_identity_for_owner(metadata.uid(), metadata.gid());
            assert_eq!(uid, identity.uid.to_string());
            assert_eq!(gid, identity.gid.to_string());
        }

        #[cfg(not(unix))]
        {
            assert_eq!(uid, DEFAULT_NONROOT_CONTAINER_ID);
            assert_eq!(gid, DEFAULT_NONROOT_CONTAINER_ID);
        }
    }

    fn fake_product_report(product: &str, status: &str, diagnostics: Vec<JsonValue>) -> String {
        let error_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["severity"] == "error")
            .count();
        let warning_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic["severity"] == "warning")
            .count();
        serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": product,
            "config_schema_version": product_config_schema_version(product),
            "source": {"kind": "generated_file", "path": format!("{product}.yaml")},
            "status": status,
            "summary": {"error_count": error_count, "warning_count": warning_count},
            "diagnostics": diagnostics,
            "context_constraints": [],
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string()
    }

    fn shell_single_quoted(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn default_notary_options() -> NotaryInitOptions {
        NotaryInitOptions {
            source_kind: NotaryInitSourceKind::RegistryDataApi,
            source_url: "https://api.example.test".to_string(),
            source_token_from_env: None,
            source_token_env: "EVIDENCE_SOURCE_API_TOKEN".to_string(),
            source_dataset: "benefits_casework".to_string(),
            source_entity: "person".to_string(),
            source_lookup_field: "id".to_string(),
            source_network: None,
            source_claim: "benefits-person-exists".to_string(),
            source_claim_title: "Benefits person exists".to_string(),
            smoke_target_id: "per-2001".to_string(),
        }
    }

    fn env_value(env: &str, name: &str) -> String {
        env.lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then(|| value.to_string()))
            .unwrap_or_else(|| panic!("{name} should be present"))
    }
}
