use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::ValueEnum;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use registry_config_report::{
    ConfigDiagnostic, ConfigDiagnosticReport, ConfigSourceKind, ConfigSourceRef,
    DiagnosticSeverity, DiagnosticSummary, RegistryctlProductReport, RegistryctlProjectRef,
    RegistryctlValidationReport, ReportStatus, REGISTRYCTL_VALIDATION_REPORT_SCHEMA_VERSION_V1,
};
use registry_platform_authcommon::{fingerprint_api_key, validate_api_key_entropy};
use registry_platform_config::{
    sha256_uri, verify_config_bundle, ConfigBundleFile, ConfigBundleManifest,
    ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
    ConfigTrustAnchorSigner, MAX_BUNDLE_FILE_BYTES, MAX_CONFIG_BUNDLE_SEQUENCE, MAX_MANIFEST_BYTES,
    MAX_SIGNATURE_ENVELOPE_BYTES, MAX_TRUST_ANCHOR_BYTES,
};
use registry_platform_crypto::{
    canonicalize_json, parse_json_strict, sign as sign_payload, PrivateJwk, PublicJwk,
    SigningAlgorithm, MAX_JWK_JSON_BYTES,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

mod project_authoring;

pub use project_authoring::{
    build_registry_project, check_registry_project, init_registry_project,
    render_project_authoring_diagnostics, setup_registry_project_editor, test_registry_project,
    test_registry_project_selected, ProjectAuthoringDiagnostic, ProjectAuthoringDiagnostics,
    ProjectBuildOptions, ProjectCheckOptions, ProjectCommandReport, ProjectEditorSetupOptions,
    ProjectEditorSetupReport, ProjectInitOptions, ProjectSchemaKind, ProjectStarter,
    ProjectTestOptions, ProjectTestSelection, SemanticChange,
};

pub use crate::sample::Sample;

mod sample;
mod stored_zip;

const IMAGE_LOCK_SCHEMA_VERSION: &str = "registryctl.release_image_lock.v1";
const IMAGE_LOCK_MAX_BYTES: u64 = 16 * 1024;
const IMAGE_LOCK_PATH_ENV: &str = "REGISTRYCTL_IMAGE_LOCK";
const RELAY_IMAGE_REPOSITORY: &str = "ghcr.io/registrystack/registry-relay";
const NOTARY_IMAGE_REPOSITORY: &str = "ghcr.io/registrystack/registry-notary";
const LINUX_AMD64_PLATFORM: &str = "linux/amd64";
const RELAY_BASE_URL: &str = "http://127.0.0.1:4242";
const NOTARY_BASE_URL: &str = "http://127.0.0.1:4255";
const RELAY_DOCS_PATH: &str = "/docs";
const TUTORIAL_PURPOSE: &str = "https://example.local/purpose/tutorial";
const TUTORIAL_IDENTITY_PURPOSE: &str = "https://example.local/purpose/identity-verification";
const BRUNO_COLLECTION_DIR: &str = "bruno/registry-api";
const BRUNO_GENERATED_MANIFEST: &str = "bruno/registry-api/.registryctl-generated";
const REGISTRY_STACK_RUNTIME_UID_ENV: &str = "REGISTRY_STACK_RUNTIME_UID";
const REGISTRY_STACK_RUNTIME_GID_ENV: &str = "REGISTRY_STACK_RUNTIME_GID";
const DEFAULT_NONROOT_CONTAINER_ID: &str = "65532";
const REGISTRYCTL_RELEASES_API: &str =
    "https://api.github.com/repos/registrystack/registry-stack/releases/latest";
const REGISTRYCTL_RAW_REPOSITORY: &str =
    "https://raw.githubusercontent.com/registrystack/registry-stack";
const REGISTRYCTL_VERIFY_GUIDE: &str =
    "https://github.com/registrystack/registry-stack/blob/main/release/VERIFY.md";
const UPDATE_CHECK_CACHE_SECONDS: u64 = 60 * 60 * 24;
/// The only `schema_version` `registryctl_manifest` generates today; `Project::load` rejects
/// any other value so a future/incompatible schema file fails loudly instead of half-parsing.
const PROJECT_SCHEMA_VERSION: &str = "registryctl/v1";
const CONFIG_BUNDLE_SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const CONFIG_TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";
const INIT_REPORT_SCHEMA_VERSION: &str = "registryctl.init.v1";
const ADD_NOTARY_REPORT_SCHEMA_VERSION: &str = "registryctl.add_notary.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitProjectKind {
    RegistryProject,
    RelaySpreadsheetApi,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InitSource {
    Starter {
        id: String,
        release: String,
        content_digest: String,
        content_state: &'static str,
    },
    Sample {
        id: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct InitArtifacts {
    pub project_file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bruno_collection: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub editor_manifest: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InitReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub project: String,
    pub project_kind: InitProjectKind,
    pub output: PathBuf,
    pub source: InitSource,
    pub artifacts: InitArtifacts,
}
const NOTARY_PROJECT_DIR: &str = "notary/project";
#[cfg(test)]
const NOTARY_CONFIG_DIR: &str = "notary/project/.registry-stack/build/local/private/notary/config";
const NOTARY_CONFIG_PATH: &str =
    "notary/project/.registry-stack/build/local/private/notary/config/notary.yaml";
#[cfg(test)]
const CONSULTATION_RELAY_CONFIG_DIR: &str =
    "notary/project/.registry-stack/build/local/private/relay/config";
const CONSULTATION_RELAY_CONFIG_PATH: &str =
    "notary/project/.registry-stack/build/local/private/relay/config/relay.yaml";
const NOTARY_CLAIM_FILE: &str = "notary/project/registry-stack.yaml";
const NOTARY_RELAY_TOKEN_PATH: &str = "secrets/notary-relay.jwt";
const NOTARY_RELAY_WORKLOAD_JWK_ENV: &str = "REGISTRY_NOTARY_RELAY_WORKLOAD_JWK";
const NOTARY_RELAY_WORKLOAD_KID: &str = "registry-notary-relay-workload";
const CONSULTATION_POSTGRES_CERT_PATH: &str = "secrets/consultation-postgres.crt";
const CONSULTATION_POSTGRES_KEY_PATH: &str = "secrets/consultation-postgres.key";
const CONSULTATION_RELAY_STATE_DIR: &str = "state/relay-consultation";
const CONSULTATION_RELAY_CACHE_PATH: &str = "state/relay-consultation/cache";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryctlImageLock {
    schema_version: String,
    release_tag: String,
    manifest_source_ref: String,
    tag_target: String,
    platform: String,
    images: RegistryctlLockedImages,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RegistryctlLockedImages {
    #[serde(rename = "registry-relay")]
    registry_relay: String,
    #[serde(rename = "registry-notary")]
    registry_notary: String,
}

impl RegistryctlImageLock {
    fn relay_image(&self) -> &str {
        &self.images.registry_relay
    }

    fn notary_image(&self) -> &str {
        &self.images.registry_notary
    }
}

pub fn registryctl_image_lock_filename() -> String {
    format!("registryctl-v{}-image-lock.json", env!("CARGO_PKG_VERSION"))
}

/// Loads the release image lock located beside the running registryctl binary.
///
/// Only project-generation commands call this function. Existing projects keep
/// using the immutable image references already stored in their generated files.
pub fn load_registryctl_image_lock() -> Result<RegistryctlImageLock> {
    if let Some(path) = std::env::var_os(IMAGE_LOCK_PATH_ENV) {
        return load_registryctl_image_lock_path(&PathBuf::from(path));
    }
    let executable =
        std::env::current_exe().context("failed to locate the running registryctl binary")?;
    let directory = executable.parent().ok_or_else(|| {
        anyhow!(
            "running registryctl binary has no parent directory: {}",
            executable.display()
        )
    })?;
    load_registryctl_image_lock_path(&directory.join(registryctl_image_lock_filename()))
}

#[cfg(test)]
fn load_registryctl_image_lock_beside(executable: &Path) -> Result<RegistryctlImageLock> {
    let directory = executable.parent().ok_or_else(|| {
        anyhow!(
            "running registryctl binary has no parent directory: {}",
            executable.display()
        )
    })?;
    load_registryctl_image_lock_path(&directory.join(registryctl_image_lock_filename()))
}

fn load_registryctl_image_lock_path(path: &Path) -> Result<RegistryctlImageLock> {
    let guidance = format!(
        "reinstall registryctl v{} with its matching image lock, or set {IMAGE_LOCK_PATH_ENV} to that verified file; verify the release evidence described at {REGISTRYCTL_VERIFY_GUIDE}",
        env!("CARGO_PKG_VERSION")
    );
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "registryctl image lock is missing at {}; {guidance}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        bail!(
            "registryctl image lock must be a regular file, not a symlink or directory: {}; {guidance}",
            path.display()
        );
    }
    if metadata.len() > IMAGE_LOCK_MAX_BYTES {
        bail!(
            "registryctl image lock exceeds the {IMAGE_LOCK_MAX_BYTES}-byte limit: {}; {guidance}",
            path.display()
        );
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .with_context(|| {
            format!(
                "failed to open registryctl image lock {}; {guidance}",
                path.display()
            )
        })?
        .take(IMAGE_LOCK_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| {
            format!(
                "failed to read registryctl image lock {}; {guidance}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > IMAGE_LOCK_MAX_BYTES {
        bail!(
            "registryctl image lock exceeds the {IMAGE_LOCK_MAX_BYTES}-byte limit: {}; {guidance}",
            path.display()
        );
    }

    let image_lock: RegistryctlImageLock = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "registryctl image lock is not valid schema-v1 JSON: {}; {guidance}",
            path.display()
        )
    })?;
    validate_registryctl_image_lock(&image_lock).with_context(|| {
        format!(
            "registryctl image lock validation failed for {}; {guidance}",
            path.display()
        )
    })?;
    Ok(image_lock)
}

fn validate_registryctl_image_lock(image_lock: &RegistryctlImageLock) -> Result<()> {
    if image_lock.schema_version != IMAGE_LOCK_SCHEMA_VERSION {
        bail!(
            "schema_version must be {IMAGE_LOCK_SCHEMA_VERSION:?}, got {:?}",
            image_lock.schema_version
        );
    }
    let expected_release_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    if image_lock.release_tag != expected_release_tag {
        bail!(
            "release_tag must exactly match registryctl version {expected_release_tag:?}, got {:?}",
            image_lock.release_tag
        );
    }
    validate_lowercase_commit("manifest_source_ref", &image_lock.manifest_source_ref)?;
    validate_lowercase_commit("tag_target", &image_lock.tag_target)?;
    if image_lock.platform != LINUX_AMD64_PLATFORM {
        bail!(
            "platform must be {LINUX_AMD64_PLATFORM:?}, got {:?}",
            image_lock.platform
        );
    }
    validate_locked_image_ref(
        "images.registry-relay",
        &image_lock.images.registry_relay,
        RELAY_IMAGE_REPOSITORY,
    )?;
    validate_locked_image_ref(
        "images.registry-notary",
        &image_lock.images.registry_notary,
        NOTARY_IMAGE_REPOSITORY,
    )?;
    Ok(())
}

fn validate_lowercase_commit(field: &str, value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} must contain exactly 40 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_locked_image_ref(field: &str, value: &str, repository: &str) -> Result<()> {
    let prefix = format!("{repository}@sha256:");
    let digest = value.strip_prefix(&prefix).ok_or_else(|| {
        anyhow!("{field} must use the literal repository {repository:?} and a sha256 digest")
    })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} digest must contain exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DoctorFormat {
    Human,
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

pub fn inspect_config_bundle(bundle_dir: &Path) -> Result<BundleInspectReport> {
    let manifest_path = bundle_dir.join("manifest.json");
    let signature_path = bundle_dir.join("manifest.sig.json");
    let manifest: ConfigBundleManifest =
        read_bounded_strict_json(&manifest_path, MAX_MANIFEST_BYTES)?;
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
    let jwk_text = read_bounded_utf8_file(jwk_path, MAX_JWK_JSON_BYTES)?;
    let jwk = PublicJwk::parse(&jwk_text)
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

fn read_private_jwk_text(key_ref: &str) -> Result<Zeroizing<String>> {
    if key_ref.starts_with("op://") {
        let mut child = Command::new("op")
            .arg("read")
            .arg(key_ref)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to run op read for bundle signing key")?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            bail!("op read did not provide a stdout pipe");
        };
        let bytes = match read_bounded_zeroizing(stdout, MAX_JWK_JSON_BYTES, "op read output") {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let status = child
            .wait()
            .context("failed to wait for op read bundle signing key")?;
        if !status.success() {
            bail!("op read failed for bundle signing key reference");
        }
        return zeroizing_utf8(bytes, "private JWK returned by op read is not UTF-8 JSON");
    }
    read_bounded_utf8_file(Path::new(key_ref), MAX_JWK_JSON_BYTES)
}

fn read_bounded_utf8_file(path: &Path, max_bytes: usize) -> Result<Zeroizing<String>> {
    let file =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let label = path.display().to_string();
    let bytes = read_bounded_zeroizing(file, max_bytes, &label)?;
    zeroizing_utf8(bytes, &format!("{} is not UTF-8 JSON", path.display()))
}

fn read_bounded_zeroizing(
    reader: impl Read,
    max_bytes: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}

fn zeroizing_utf8(bytes: Zeroizing<Vec<u8>>, invalid_message: &str) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(&bytes).with_context(|| invalid_message.to_string())?;
    Ok(Zeroizing::new(text.to_owned()))
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
    match fs::File::open(signature_path) {
        Ok(file) => {
            decode_bounded_strict_json(file, signature_path, MAX_SIGNATURE_ENVELOPE_BYTES).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read {}", signature_path.display()))
        }
    }
}

fn read_anchor_unvalidated(anchor_path: &Path) -> Result<ConfigTrustAnchor> {
    let anchor: ConfigTrustAnchor = read_bounded_strict_json(anchor_path, MAX_TRUST_ANCHOR_BYTES)?;
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

fn read_bounded_strict_json<T>(path: &Path, max_bytes: u64) -> Result<T>
where
    T: DeserializeOwned,
{
    let file =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    decode_bounded_strict_json(file, path, max_bytes)
}

fn decode_bounded_strict_json<T>(reader: impl Read, path: &Path, max_bytes: u64) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut bytes = Vec::new();
    reader
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "JSON artifact exceeds the {max_bytes}-byte limit: {}",
            path.display()
        );
    }
    let value =
        parse_json_strict(&bytes).with_context(|| format!("failed to parse {}", path.display()))?;
    serde_json::from_value(value).with_context(|| format!("failed to parse {}", path.display()))
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

pub fn init_spreadsheet_api(
    dir: &Path,
    sample: Sample,
    image_lock: &RegistryctlImageLock,
) -> Result<InitReport> {
    match sample {
        Sample::Benefits => init_benefits_project(dir, image_lock),
    }
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
            if let Some(notice) = update_notice(current_version, &cache.latest_tag) {
                eprintln!("{notice}");
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
    if let Some(notice) = update_notice(current_version, &latest_tag) {
        println!("{notice}");
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
    if VersionNumber::parse_release_tag(&cache.latest_tag).is_none() {
        bail!("registryctl update check cache contains a non-canonical release tag");
    }
    let now = unix_now();
    Ok(Some(CachedLatestRelease {
        is_fresh: now.saturating_sub(cache.checked_at) <= UPDATE_CHECK_CACHE_SECONDS,
        latest_tag: cache.latest_tag,
    }))
}

fn write_update_check_cache(cache_path: &Path, latest_tag: &str) -> Result<()> {
    if VersionNumber::parse_release_tag(latest_tag).is_none() {
        bail!("refusing to cache a non-canonical registryctl release tag");
    }
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
    if VersionNumber::parse_release_tag(&latest.tag_name).is_none() {
        bail!("registryctl latest release response did not include a canonical vMAJOR.MINOR.PATCH tag");
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

fn update_notice(current_version: &str, latest_tag: &str) -> Option<String> {
    let current = VersionNumber::parse(current_version)?;
    let latest = VersionNumber::parse_release_tag(latest_tag)?;
    if latest <= current {
        return None;
    }
    let install_script = format!(
        "{REGISTRYCTL_RAW_REPOSITORY}/refs/tags/{latest_tag}/crates/registryctl/install.sh"
    );
    Some(format!(
        "registryctl {latest_tag} is available. You have {}.\nThe quick installer verifies SHA256 integrity only. For canonical release authenticity guidance, see:\n  {REGISTRYCTL_VERIFY_GUIDE}\nUpgrade with:\n  curl -fsSL {install_script} | REGISTRYCTL_VERSION={latest_tag} bash",
        display_version(current_version),
    ))
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
    fn parse_release_tag(value: &str) -> Option<Self> {
        let version = value.strip_prefix('v')?;
        if !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return None;
        }
        let parsed = Self::parse(version)?;
        if value != format!("v{}.{}.{}", parsed.major, parsed.minor, parsed.patch) {
            return None;
        }
        Some(parsed)
    }

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

pub fn start_project(project_dir: &Path) -> Result<()> {
    start_project_with_timeout(project_dir, Duration::from_secs(60))
}

fn start_project_with_timeout(project_dir: &Path, timeout: Duration) -> Result<()> {
    let mut project = Project::load(project_dir)?;
    if project.notary.is_some() {
        prepare_notary_runtime(project_dir)?;
        project = Project::load(project_dir)?;
    }
    validate_project_fingerprints(project_dir, &project)?;
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
        println!("Notary docs: {notary_base_url}{RELAY_DOCS_PATH}");
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
        println!("Notary docs: {notary_base_url}{RELAY_DOCS_PATH}");
    }
    Ok(())
}

pub fn open_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
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

pub fn bruno_generate_project(project_dir: &Path, force: bool) -> Result<PathBuf> {
    let project = Project::load(project_dir)?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let collection_dir = project_dir.join(BRUNO_COLLECTION_DIR);
    let files = bruno_files(&project, &secrets)?;
    write_generated_files(project_dir, &collection_dir, files, force)?;
    Ok(collection_dir)
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
    let report = run_doctor_report_with_path(project_dir, deployment_profile, None)?;
    match format {
        DoctorFormat::Human => println!("{}", render_doctor_report(&report)),
        DoctorFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .context("failed to render doctor report JSON")?;
            println!("{json}");
        }
    }
    ensure_doctor_report_ok(&report)
}

fn render_doctor_report(report: &DoctorReport) -> String {
    use std::fmt::Write as _;

    let mut output = format!("Registry Stack doctor: {}", report.status.as_str());
    let _ = write!(
        output,
        "\nProject: {}\nProfile: {}",
        human_line_value(&report.project.path),
        human_line_value(&report.project.profile)
    );
    for product in &report.products {
        let _ = write!(
            output,
            "\n{}: {} ({} errors, {} warnings)",
            human_line_value(&product.product),
            product.status.as_str(),
            product.report.summary.error_count,
            product.report.summary.warning_count
        );
        if let Some(path) = &product.report.source.path {
            let _ = write!(output, "\n  Config: {}", human_line_value(path));
        }
        if !product.report.required_env.is_empty() {
            let present = product
                .report
                .required_env
                .iter()
                .filter(|entry| entry.status.as_str() == "present")
                .count();
            let missing = product
                .report
                .required_env
                .iter()
                .filter(|entry| entry.status.as_str() == "missing")
                .count();
            let not_checked = product.report.required_env.len() - present - missing;
            let _ = write!(
                output,
                "\n  Required environment: {present} present, {missing} missing, {not_checked} not checked"
            );
        }
        if !product.report.context_constraints.is_empty() {
            let _ = write!(
                output,
                "\n  Context constraints: {}",
                product.report.context_constraints.len()
            );
        }
        if let Some(shipping) = &product.report.audit_shipping {
            let _ = write!(
                output,
                "\n  Audit shipping: sink={}, target={}, health={}",
                human_line_value(&shipping.sink_type),
                human_line_value(&shipping.shipping_target),
                shipping
                    .shipping_health
                    .as_deref()
                    .map_or("not observed".to_string(), human_line_value)
            );
        }
        for diagnostic in &product.report.diagnostics {
            let _ = write!(
                output,
                "\n  [{}] {}: {}",
                diagnostic.severity.as_str(),
                human_line_value(&diagnostic.code),
                human_line_value(&diagnostic.message)
            );
            if let Some(path) = &diagnostic.path {
                let _ = write!(output, " ({})", human_line_value(path));
            }
        }
    }
    if !report.cross_product_diagnostics.is_empty() {
        output.push_str("\nCross-product diagnostics:");
        for diagnostic in &report.cross_product_diagnostics {
            let _ = write!(
                output,
                "\n  [{}] {}: {}",
                diagnostic.severity.as_str(),
                human_line_value(&diagnostic.code),
                human_line_value(&diagnostic.message)
            );
        }
    }
    output
}

fn human_line_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
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
    deployment_profile: Option<DeploymentProfile>,
    path: Option<&Path>,
) -> Result<DoctorReport> {
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
    let mut value: serde_norway::Value = serde_norway::from_str(&raw)
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
    let rendered =
        serde_norway::to_string(&value).context("failed to render Relay doctor config")?;
    write_text(doctor_config.clone(), &rendered)?;
    Ok(doctor_config)
}

fn set_yaml_path_string(value: &mut serde_norway::Value, path: &[&str], replacement: String) {
    let mut current = value;
    for segment in &path[..path.len().saturating_sub(1)] {
        let serde_norway::Value::Mapping(map) = current else {
            return;
        };
        let key = serde_norway::Value::String((*segment).to_string());
        let Some(next) = map.get_mut(&key) else {
            return;
        };
        current = next;
    }
    let Some(last) = path.last() else {
        return;
    };
    if let serde_norway::Value::Mapping(map) = current {
        map.insert(
            serde_norway::Value::String((*last).to_string()),
            serde_norway::Value::String(replacement),
        );
    }
}

fn rewrite_relay_container_data_paths(
    value: &mut serde_norway::Value,
    project_dir: &Path,
    relay: &ProjectRelay,
) {
    match value {
        serde_norway::Value::String(text) => {
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
        serde_norway::Value::Sequence(items) => {
            for item in items {
                rewrite_relay_container_data_paths(item, project_dir, relay);
            }
        }
        serde_norway::Value::Mapping(map) => {
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
                    "Install {} and ensure it is on PATH, then rerun `registryctl doctor`.",
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
        audit_shipping: None,
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

#[derive(Debug, Serialize)]
pub struct AddNotaryReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub project: String,
    pub notary_url: &'static str,
    pub claim_file: &'static str,
}

/// Adds the local tutorial Notary journey to a generated spreadsheet project.
///
/// The authored files remain the source of truth. `registryctl start` rebuilds
/// the reviewed Relay and Notary inputs so edits to the claim take effect after
/// a restart.
pub fn add_notary_to_project(
    project_dir: &Path,
    image_lock: &RegistryctlImageLock,
) -> Result<AddNotaryReport> {
    let mut project = Project::load(project_dir)?;
    if project.relay.is_none() {
        bail!("add notary requires a generated Relay spreadsheet project");
    }
    if project.notary.is_some() {
        bail!("this project already has a Notary add-on");
    }
    let workbook = project_dir.join("data/benefits_casework.xlsx");
    if !workbook.is_file() {
        bail!(
            "add notary requires the benefits workbook at {}",
            workbook.display()
        );
    }
    let notary_dir = project_dir.join("notary");
    for relative in [
        "notary",
        NOTARY_RELAY_TOKEN_PATH,
        CONSULTATION_POSTGRES_CERT_PATH,
        CONSULTATION_POSTGRES_KEY_PATH,
        CONSULTATION_RELAY_STATE_DIR,
    ] {
        let path = project_dir.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!(
                "Notary destination already exists and was not modified: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stat {}", path.display()));
            }
        }
    }
    let secrets_path = project_dir.join(&project.local.secrets_env);
    let compose_path = project_dir.join("compose.yaml");
    let manifest_path = project_dir.join("registryctl.yaml");
    let original_secrets = fs::read_to_string(&secrets_path)
        .with_context(|| format!("failed to read {}", secrets_path.display()))?;
    let original_compose = fs::read_to_string(&compose_path)
        .with_context(|| format!("failed to read {}", compose_path.display()))?;
    let original_manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;

    let result = (|| {
        write_notary_addon_files(project_dir)?;
        write_local_postgres_tls(project_dir)?;
        add_notary_local_secrets(project_dir)?;
        create_notary_state_dirs(project_dir)?;
        prepare_notary_runtime(project_dir)?;
        merge_notary_compose(project_dir, image_lock)?;

        project.project.products.push("registry-notary".to_string());
        project.runtime.notary_image = Some(image_lock.notary_image().to_string());
        project.runtime.notary_base_url = Some(NOTARY_BASE_URL.to_string());
        project.notary = Some(ProjectNotary {
            project: PathBuf::from(NOTARY_PROJECT_DIR),
            config: PathBuf::from(NOTARY_CONFIG_PATH),
            consultation_relay_config: PathBuf::from(CONSULTATION_RELAY_CONFIG_PATH),
            claim_file: PathBuf::from(NOTARY_CLAIM_FILE),
            workload_token: PathBuf::from(NOTARY_RELAY_TOKEN_PATH),
        });
        let manifest = serde_norway::to_string(&project)
            .context("failed to render registryctl manifest with Notary")?;
        write_text(project_dir.join("registryctl.yaml"), &manifest)?;
        Ok(())
    })();

    if let Err(error) = result {
        let mut rollback_errors = Vec::new();
        if let Err(rollback) = fs::remove_dir_all(&notary_dir) {
            if rollback.kind() != std::io::ErrorKind::NotFound {
                rollback_errors.push(format!("remove {}: {rollback}", notary_dir.display()));
            }
        }
        let consultation_state_dir = project_dir.join(CONSULTATION_RELAY_STATE_DIR);
        if let Err(rollback) = fs::remove_dir_all(&consultation_state_dir) {
            if rollback.kind() != std::io::ErrorKind::NotFound {
                rollback_errors.push(format!(
                    "remove {}: {rollback}",
                    consultation_state_dir.display()
                ));
            }
        }
        if let Err(rollback) = write_private_text(&secrets_path, &original_secrets) {
            rollback_errors.push(format!("restore {}: {rollback:#}", secrets_path.display()));
        }
        for generated_sidecar_path in [
            NOTARY_RELAY_TOKEN_PATH,
            CONSULTATION_POSTGRES_CERT_PATH,
            CONSULTATION_POSTGRES_KEY_PATH,
        ] {
            let path = project_dir.join(generated_sidecar_path);
            if let Err(rollback) = fs::remove_file(&path) {
                if rollback.kind() != std::io::ErrorKind::NotFound {
                    rollback_errors.push(format!("remove {}: {rollback}", path.display()));
                }
            }
        }
        if let Err(rollback) = write_text(compose_path, &original_compose) {
            rollback_errors.push(format!("restore Compose file: {rollback:#}"));
        }
        if let Err(rollback) = write_text(manifest_path, &original_manifest) {
            rollback_errors.push(format!("restore project manifest: {rollback:#}"));
        }
        if !rollback_errors.is_empty() {
            bail!(
                "failed to add Notary: {error:#}; rollback also failed: {}",
                rollback_errors.join("; ")
            );
        }
        return Err(error);
    }

    Ok(AddNotaryReport {
        schema_version: ADD_NOTARY_REPORT_SCHEMA_VERSION,
        status: "added",
        project: project.project.name,
        notary_url: NOTARY_BASE_URL,
        claim_file: NOTARY_CLAIM_FILE,
    })
}

fn write_notary_addon_files(project_dir: &Path) -> Result<()> {
    let files = [
        (
            "notary/project/registry-stack.yaml",
            include_str!("templates/notary_addon/registry-stack.yaml"),
        ),
        (
            "notary/project/entities/person.yaml",
            include_str!("templates/notary_addon/entities/person.yaml"),
        ),
        (
            "notary/project/integrations/person-demographics/integration.yaml",
            include_str!(
                "templates/notary_addon/integrations/person-demographics/integration.yaml"
            ),
        ),
        (
            "notary/project/integrations/person-demographics/fixtures/match.yaml",
            include_str!(
                "templates/notary_addon/integrations/person-demographics/fixtures/match.yaml"
            ),
        ),
        (
            "notary/project/integrations/person-demographics/fixtures/pending.yaml",
            include_str!(
                "templates/notary_addon/integrations/person-demographics/fixtures/pending.yaml"
            ),
        ),
        (
            "notary/project/integrations/person-demographics/fixtures/no-match.yaml",
            include_str!(
                "templates/notary_addon/integrations/person-demographics/fixtures/no-match.yaml"
            ),
        ),
        (
            "notary/project/integrations/person-demographics/fixtures/ambiguous.yaml",
            include_str!(
                "templates/notary_addon/integrations/person-demographics/fixtures/ambiguous.yaml"
            ),
        ),
        (
            "notary/project/environments/local.yaml",
            include_str!("templates/notary_addon/environments/local.yaml"),
        ),
        (
            "notary/postgres-init.sql",
            include_str!("templates/notary_addon/postgres-init.sql"),
        ),
    ];
    for (relative, contents) in files {
        let path = project_dir.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("generated Notary path has no parent"))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        write_text(path, contents)?;
    }
    write_text(
        project_dir.join("notary/project/.gitignore"),
        ".registry-stack/\n",
    )?;
    Ok(())
}

fn add_notary_local_secrets(project_dir: &Path) -> Result<()> {
    let evaluator = Credential::generate("tutorial-evaluator")?;
    let workload_jwk = generate_ed25519_jwk(NOTARY_RELAY_WORKLOAD_KID)?;
    write_local_workload_jwks(project_dir, &workload_jwk)?;
    let env_path = project_dir.join("secrets/local.env");
    let current = fs::read_to_string(&env_path)
        .with_context(|| format!("failed to read {}", env_path.display()))?;
    let values = vec![
        ("TUTORIAL_EVALUATOR_RAW".to_string(), evaluator.raw),
        (
            "TUTORIAL_EVALUATOR_HASH".to_string(),
            evaluator.fingerprint,
        ),
        (
            "REGISTRY_NOTARY_AUDIT_HASH_SECRET".to_string(),
            random_token(48)?,
        ),
        (
            "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1".to_string(),
            random_token(48)?,
        ),
        (
            NOTARY_RELAY_WORKLOAD_JWK_ENV.to_string(),
            workload_jwk,
        ),
        (
            "REGISTRY_RELAY_CONSULTATION_DATABASE_URL".to_string(),
            "postgresql://relay_state_runtime@registry-consultation-db:5432/registry_relay?sslmode=require".to_string(),
        ),
        (
            "REGISTRY_RELAY_STATE_MIGRATION_URL".to_string(),
            "postgresql://postgres@registry-consultation-db:5432/registry_relay?sslmode=require".to_string(),
        ),
        (
            "REGISTRY_RELAY_STATE_KEYRING_MAINTENANCE_URL".to_string(),
            "postgresql://relay_state_maintenance@registry-consultation-db:5432/registry_relay?sslmode=require".to_string(),
        ),
        (
            "REGISTRY_RELAY_STATE_KEYRING_READER_URL".to_string(),
            "postgresql://relay_state_reader@registry-consultation-db:5432/registry_relay?sslmode=require".to_string(),
        ),
    ];
    write_private_text(&env_path, &upsert_env_values(&current, &values))?;
    Ok(())
}

fn write_local_workload_jwks(project_dir: &Path, private_jwk: &str) -> Result<()> {
    let mut public_jwk: serde_json::Value =
        serde_json::from_str(private_jwk).context("generated workload JWK is invalid")?;
    public_jwk
        .as_object_mut()
        .ok_or_else(|| anyhow!("generated workload JWK must be an object"))?
        .remove("d");
    let document = serde_json::to_string_pretty(&serde_json::json!({ "keys": [public_jwk] }))
        .context("failed to render local workload JWKS")?;
    write_text(
        project_dir.join("notary/jwks.json"),
        &format!("{document}\n"),
    )
}

fn write_local_postgres_tls(project_dir: &Path) -> Result<()> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["registry-consultation-db".to_string()])
            .context("failed to generate local consultation database TLS identity")?;
    let certificate_pem = pem_block("CERTIFICATE", cert.der().as_ref());
    let private_key_pem = Zeroizing::new(pem_block("PRIVATE KEY", &key_pair.serialize_der()));
    write_text(
        project_dir.join(CONSULTATION_POSTGRES_CERT_PATH),
        &certificate_pem,
    )?;
    write_private_text(
        &project_dir.join(CONSULTATION_POSTGRES_KEY_PATH),
        &private_key_pem,
    )
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 output is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn generate_ed25519_jwk(kid: &str) -> Result<String> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow!("random generation failed: {error}"))?;
    let signing_key = Ed25519SigningKey::from_bytes(&seed);
    let x = signing_key.verifying_key().to_bytes();
    serde_json::to_string(&serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed),
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        "alg": "EdDSA",
        "kid": kid,
    }))
    .context("failed to render workload JWK")
}

fn prepare_notary_runtime(project_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    let runtime_identity = Some(compose_runtime_identity_values(project_dir)?);
    #[cfg(not(unix))]
    let runtime_identity = None;
    project_authoring::build_registry_project_for_local_tutorial(
        &ProjectBuildOptions {
            project_directory: project_dir.join(NOTARY_PROJECT_DIR),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        },
        runtime_identity,
    )?;
    refresh_notary_relay_token(project_dir, runtime_identity)
}

fn refresh_notary_relay_token(
    project_dir: &Path,
    runtime_identity: Option<RuntimeIdentity>,
) -> Result<()> {
    let project = Project::load(project_dir).ok();
    let secrets_path = project
        .as_ref()
        .map(|project| project_dir.join(&project.local.secrets_env))
        .unwrap_or_else(|| project_dir.join("secrets/local.env"));
    let secrets = LocalEnv::load(&secrets_path)?;
    let private_jwk = PrivateJwk::parse(secrets.required(NOTARY_RELAY_WORKLOAD_JWK_ENV)?)
        .context("local Notary workload JWK is invalid")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "at+jwt",
        "kid": NOTARY_RELAY_WORKLOAD_KID,
    });
    let claims = serde_json::json!({
        "iss": "http://127.0.0.1:8081",
        "sub": "registry-notary",
        "client_id": "registry-notary",
        "azp": "registry-notary",
        "aud": "registry-relay",
        "scope": "registry:consult:registration-verification",
        "iat": now,
        "nbf": now.saturating_sub(5),
        "exp": now.saturating_add(3600),
        "jti": random_token(16)?,
    });
    let encoded_header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let encoded_claims =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = sign_payload(signing_input.as_bytes(), &private_jwk)
        .context("failed to sign local Relay workload token")?;
    let token = format!(
        "{signing_input}.{}\n",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    );
    write_private_runtime_text(
        &project_dir.join(NOTARY_RELAY_TOKEN_PATH),
        &token,
        runtime_identity,
    )
}

fn merge_notary_compose(project_dir: &Path, image_lock: &RegistryctlImageLock) -> Result<()> {
    let path = project_dir.join("compose.yaml");
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut compose: serde_norway::Value = serde_norway::from_str(&contents)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let fragment = include_str!("templates/notary_addon/compose-fragment.yaml.tmpl")
        .replace("{{relay_image}}", image_lock.relay_image())
        .replace("{{notary_image}}", image_lock.notary_image());
    let fragment: serde_norway::Value =
        serde_norway::from_str(&fragment).context("failed to parse Notary Compose fragment")?;
    merge_yaml_mapping(&mut compose, &fragment, "services")?;
    merge_yaml_mapping(&mut compose, &fragment, "volumes")?;
    merge_yaml_mapping(&mut compose, &fragment, "networks")?;
    let rendered = serde_norway::to_string(&compose).context("failed to render Compose file")?;
    write_text(path, &format!("# Generated by registryctl.\n{rendered}"))
}

fn merge_yaml_mapping(
    target: &mut serde_norway::Value,
    source: &serde_norway::Value,
    key: &str,
) -> Result<()> {
    let target_root = target
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("Compose document must be a mapping"))?;
    let yaml_key = serde_norway::Value::String(key.to_owned());
    if !target_root.contains_key(&yaml_key) {
        target_root.insert(
            yaml_key.clone(),
            serde_norway::Value::Mapping(serde_norway::Mapping::new()),
        );
    }
    let target_mapping = target_root
        .get_mut(&yaml_key)
        .and_then(serde_norway::Value::as_mapping_mut)
        .ok_or_else(|| anyhow!("Compose {key} must be a mapping"))?;
    let source_mapping = source[key]
        .as_mapping()
        .ok_or_else(|| anyhow!("Notary Compose {key} must be a mapping"))?;
    for (entry_key, value) in source_mapping {
        if target_mapping.contains_key(entry_key) {
            bail!("Compose {key} already contains a generated Notary entry");
        }
        target_mapping.insert(entry_key.clone(), value.clone());
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_text(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_text(path: &Path, contents: &str) -> Result<()> {
    write_text(path.to_path_buf(), contents)
}

#[cfg(unix)]
fn write_private_runtime_text(
    path: &Path,
    contents: &str,
    runtime_identity: Option<RuntimeIdentity>,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("private runtime input has no parent"))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("private runtime input name is invalid"))?;
    let mut staged = None;
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).context("failed to create private runtime input identity")?;
        let staged_path = parent.join(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged_path);
        match file {
            Ok(file) => {
                staged = Some((staged_path, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to stage {}", path.display()));
            }
        }
    }
    let (staged_path, mut file) =
        staged.ok_or_else(|| anyhow!("failed to allocate private runtime input staging file"))?;
    let staged_result = (|| {
        file.write_all(contents.as_bytes())
            .with_context(|| format!("failed to write {}", staged_path.display()))?;
        let metadata = file.metadata()?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
        if let Some(identity) = runtime_identity {
            if metadata.uid() != identity.uid || metadata.gid() != identity.gid {
                rustix::fs::fchown(
                    &file,
                    Some(rustix::fs::Uid::from_raw(identity.uid)),
                    Some(rustix::fs::Gid::from_raw(identity.gid)),
                )
                .with_context(|| {
                    format!(
                        "failed to assign staged Notary runtime input to {}:{}",
                        identity.uid, identity.gid
                    )
                })?;
            }
        }
        file.sync_all()
            .with_context(|| format!("failed to sync {}", staged_path.display()))
    })();
    drop(file);
    if let Err(error) = staged_result {
        let _ = fs::remove_file(&staged_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&staged_path, path) {
        let _ = fs::remove_file(&staged_path);
        return Err(error).with_context(|| format!("failed to publish {}", path.display()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private_runtime_text(
    path: &Path,
    contents: &str,
    _runtime_identity: Option<RuntimeIdentity>,
) -> Result<()> {
    write_private_text(path, contents)
}

fn init_benefits_project(dir: &Path, image_lock: &RegistryctlImageLock) -> Result<InitReport> {
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
        &registryctl_manifest(dir, image_lock)?,
    )?;
    write_text(dir.join("compose.yaml"), &compose_yaml(image_lock))?;
    write_text(dir.join("README.md"), project_readme())?;
    write_text(dir.join(".gitignore"), include_str!("templates/gitignore"))?;
    write_text(dir.join("relay/config.yaml"), &relay_config(&credentials))?;
    write_text(dir.join("secrets/local.env"), &credentials.env_file())?;
    write_text(dir.join("output/.gitkeep"), "")?;
    sample::write_benefits_workbook(&dir.join("data/benefits_casework.xlsx"))?;
    let bruno_collection = bruno_generate_project(dir, false)?;
    Ok(InitReport {
        schema_version: INIT_REPORT_SCHEMA_VERSION,
        status: "initialized",
        project: generated_project_name(dir),
        project_kind: InitProjectKind::RelaySpreadsheetApi,
        output: dir.to_path_buf(),
        source: InitSource::Sample {
            id: Sample::Benefits.id().to_string(),
        },
        artifacts: InitArtifacts {
            project_file: dir.join("registryctl.yaml"),
            bruno_collection: Some(bruno_collection),
            editor_manifest: None,
        },
    })
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
            CONSULTATION_RELAY_STATE_DIR,
            CONSULTATION_RELAY_CACHE_PATH,
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
pub(crate) struct RuntimeIdentity {
    uid: u32,
    gid: u32,
}

#[cfg(not(unix))]
#[derive(Clone, Copy)]
pub(crate) struct RuntimeIdentity;

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
            "docs {\nGenerated local Registry Stack API collection.\n}\n",
        ),
    ];

    if project.relay.is_some() {
        files.extend(bruno_relay_files(project.relay_base_url()?, secrets));
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
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
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
            "Read pending registrations",
            14,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person/records?registration_status=pending",
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
            "Relay/Row key cannot read identity.bru",
            "Row key cannot read identity",
            20,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person_identity/records/per-2001?expand=household_contact",
            &[
                ("Authorization", "Bearer {{relay_row_key}}"),
                ("Data-Purpose", "{{identity_purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Read restricted identity.bru",
            "Read restricted identity",
            21,
            "{{relay_base_url}}/v1/datasets/benefits_casework/entities/person_identity/records/per-2001?expand=household_contact",
            &[
                ("Authorization", "Bearer {{relay_identity_key}}"),
                ("Data-Purpose", "{{identity_purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/List aggregates.bru",
            "List aggregates",
            22,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates",
            &[("Authorization", "Bearer {{relay_aggregate_key}}")],
        ),
        bruno_get(
            "Relay/Run households by district aggregate.bru",
            "Run households by district aggregate",
            23,
            "{{relay_base_url}}/v1/datasets/benefits_casework/aggregates/by_district",
            &[
                ("Authorization", "Bearer {{relay_aggregate_key}}"),
                ("Data-Purpose", "{{purpose}}"),
            ],
        ),
        bruno_get(
            "Relay/Run applications aggregate as CSV.bru",
            "Run applications aggregate as CSV",
            24,
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
            25,
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
    values.push(("identity_purpose", TUTORIAL_IDENTITY_PURPOSE.to_string()));
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
        values.push((
            "relay_identity_key",
            bruno_env_value(secrets, "IDENTITY_READER_RAW", example),
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

#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notary: Option<ProjectNotary>,
    runtime: ProjectRuntime,
    local: ProjectLocal,
}

/// The `project:` metadata block `registryctl_manifest` writes into every generated
/// `registryctl.yaml` (see `ProjectSection`); not consumed elsewhere today, but modeled here
/// so `deny_unknown_fields` doesn't reject registryctl's own generated files.
#[derive(Debug, Deserialize, Serialize)]
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
        serde_norway::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectRelay {
    config: PathBuf,
    #[serde(default)]
    metadata: Option<PathBuf>,
    #[serde(default)]
    data: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectNotary {
    project: PathBuf,
    config: PathBuf,
    consultation_relay_config: PathBuf,
    claim_file: PathBuf,
    workload_token: PathBuf,
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

#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notary_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notary_base_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectLocal {
    secrets_env: PathBuf,
    output_dir: PathBuf,
}

impl Project {
    fn relay_base_url(&self) -> Result<&str> {
        if self.relay.is_none() {
            bail!("project does not have a Relay section");
        }
        self.runtime
            .relay_base_url
            .as_deref()
            .ok_or_else(|| anyhow!("project runtime is missing relay_base_url"))
    }

    fn notary_base_url(&self) -> Result<&str> {
        if self.notary.is_none() {
            bail!("project does not have a Notary section");
        }
        self.runtime
            .notary_base_url
            .as_deref()
            .ok_or_else(|| anyhow!("project runtime is missing notary_base_url"))
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
    let relay_is_amd64_only = project
        .runtime
        .relay_image
        .as_deref()
        .is_some_and(|image| image.starts_with(&format!("{RELAY_IMAGE_REPOSITORY}@sha256:")));
    let notary_is_amd64_only = project
        .runtime
        .notary_image
        .as_deref()
        .is_some_and(|image| image.starts_with(&format!("{NOTARY_IMAGE_REPOSITORY}@sha256:")));
    relay_is_amd64_only || notary_is_amd64_only
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
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    if let Some(relay) = &project.relay {
        validate_config_api_key_fingerprints(&project_dir.join(&relay.config), "Relay", &secrets)?;
    }
    if let Some(notary) = &project.notary {
        validate_config_api_key_fingerprints(
            &project_dir.join(&notary.config),
            "Notary",
            &secrets,
        )?;
    }
    Ok(())
}

fn validate_config_api_key_fingerprints(
    config_path: &Path,
    product: &str,
    secrets: &LocalEnv,
) -> Result<()> {
    let config = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: serde_norway::Value = serde_norway::from_str(&config)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let api_keys = config["auth"]["api_keys"]
        .as_sequence()
        .ok_or_else(|| anyhow!("{product} config auth.api_keys must be a list"))?;
    for api_key in api_keys {
        let id = api_key["id"]
            .as_str()
            .ok_or_else(|| anyhow!("{product} config api key entry is missing id"))?;
        let hash_env = api_key["fingerprint"]["name"].as_str().ok_or_else(|| {
            anyhow!("{product} config api key {id} is missing fingerprint env name")
        })?;
        let fingerprint = secrets.required(hash_env)?;
        let raw_key = secrets.required(raw_env_name_for(id)?)?;
        if fingerprint != fingerprint_api_key(raw_key) {
            bail!("local raw key and fingerprint do not match for {id}");
        }
    }
    Ok(())
}

fn raw_env_name_for(id: &str) -> Result<&'static str> {
    match id {
        "metadata_reader" => Ok("METADATA_READER_RAW"),
        "row_reader" => Ok("ROW_READER_RAW"),
        "aggregate_reader" => Ok("AGGREGATE_READER_RAW"),
        "identity_reader" => Ok("IDENTITY_READER_RAW"),
        "tutorial-evaluator" => Ok("TUTORIAL_EVALUATOR_RAW"),
        _ => bail!("unknown generated api key id {id}"),
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
    identity_reader: Credential,
    audit_hash_secret: String,
}

impl LocalCredentials {
    fn generate() -> Result<Self> {
        Ok(Self {
            metadata_reader: Credential::generate("metadata_reader")?,
            row_reader: Credential::generate("row_reader")?,
            aggregate_reader: Credential::generate("aggregate_reader")?,
            identity_reader: Credential::generate("identity_reader")?,
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
IDENTITY_READER_RAW={identity_raw}
IDENTITY_READER_HASH={identity_hash}
REGISTRY_RELAY_AUDIT_HASH_SECRET={audit_hash_secret}
",
            metadata_raw = self.metadata_reader.raw,
            metadata_hash = self.metadata_reader.fingerprint,
            row_raw = self.row_reader.raw,
            row_hash = self.row_reader.fingerprint,
            aggregate_raw = self.aggregate_reader.raw,
            aggregate_hash = self.aggregate_reader.fingerprint,
            identity_raw = self.identity_reader.raw,
            identity_hash = self.identity_reader.fingerprint,
            audit_hash_secret = self.audit_hash_secret,
        )
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

#[derive(Serialize)]
struct ProjectManifest<'a> {
    schema_version: &'a str,
    project: ProjectSection<'a>,
    runtime: RuntimeSection<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelaySection<'a>>,
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
}

#[derive(Serialize)]
struct RelaySection<'a> {
    config: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a str>,
    data: Vec<&'a str>,
}

#[derive(Serialize)]
struct LocalSection<'a> {
    secrets_env: &'a str,
    output_dir: &'a str,
}

fn registryctl_manifest(dir: &Path, image_lock: &RegistryctlImageLock) -> Result<String> {
    let name = generated_project_name(dir);
    let manifest = ProjectManifest {
        schema_version: PROJECT_SCHEMA_VERSION,
        project: ProjectSection {
            name,
            kind: "spreadsheet-api",
            products: vec!["registry-relay"],
        },
        runtime: RuntimeSection {
            engine: "docker_compose",
            compose_file: "compose.yaml",
            relay_image: Some(image_lock.relay_image()),
            relay_base_url: Some(RELAY_BASE_URL),
        },
        relay: Some(RelaySection {
            config: "relay/config.yaml",
            metadata: None,
            data: vec!["data/benefits_casework.xlsx"],
        }),
        local: LocalSection {
            secrets_env: "secrets/local.env",
            output_dir: "output",
        },
    };
    serde_norway::to_string(&manifest).context("failed to render registryctl manifest")
}

fn generated_project_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("my-first-api")
        .to_string()
}

fn compose_yaml(image_lock: &RegistryctlImageLock) -> String {
    include_str!("templates/compose.yaml").replace("{{relay_image}}", image_lock.relay_image())
}

fn project_readme() -> &'static str {
    include_str!("templates/project_readme.md")
}

fn relay_config(credentials: &LocalCredentials) -> String {
    include_str!("templates/relay_config.yaml.tmpl")
        .replace("{{metadata_id}}", credentials.metadata_reader.id)
        .replace("{{row_id}}", credentials.row_reader.id)
        .replace("{{aggregate_id}}", credentials.aggregate_reader.id)
        .replace("{{identity_id}}", credentials.identity_reader.id)
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
        "row reader cannot read restricted identity fields",
        "/v1/datasets/benefits_casework/entities/person_identity/records?id=per-2001",
        403,
        &[
            bearer_header(secrets.value("ROW_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                TUTORIAL_IDENTITY_PURPOSE.to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "identity reader with unpermitted Data-Purpose returns 403",
        "/v1/datasets/benefits_casework/entities/person_identity/records?id=per-2001",
        403,
        &[
            bearer_header(secrets.value("IDENTITY_READER_RAW")),
            ("Data-Purpose".to_string(), TUTORIAL_PURPOSE.to_string()),
        ],
    );
    record_row_data_smoke_check(
        &mut checks,
        base_url,
        "identity reader can read one restricted identity record",
        "/v1/datasets/benefits_casework/entities/person_identity/records?id=per-2001",
        &[
            bearer_header(secrets.value("IDENTITY_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                TUTORIAL_IDENTITY_PURPOSE.to_string(),
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

fn bearer_header(raw_key: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {raw_key}"))
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
    use serde_norway::Value;
    use tempfile::TempDir;

    use super::*;

    const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
    const TEST_RELAY_IMAGE: &str = "ghcr.io/registrystack/registry-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_NOTARY_IMAGE: &str = "ghcr.io/registrystack/registry-notary@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn test_image_lock() -> RegistryctlImageLock {
        RegistryctlImageLock {
            schema_version: IMAGE_LOCK_SCHEMA_VERSION.to_string(),
            release_tag: format!("v{}", env!("CARGO_PKG_VERSION")),
            manifest_source_ref: "a".repeat(40),
            tag_target: "b".repeat(40),
            platform: LINUX_AMD64_PLATFORM.to_string(),
            images: RegistryctlLockedImages {
                registry_relay: TEST_RELAY_IMAGE.to_string(),
                registry_notary: TEST_NOTARY_IMAGE.to_string(),
            },
        }
    }

    fn test_image_lock_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": IMAGE_LOCK_SCHEMA_VERSION,
            "release_tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "manifest_source_ref": "a".repeat(40),
            "tag_target": "b".repeat(40),
            "platform": LINUX_AMD64_PLATFORM,
            "images": {
                "registry-relay": TEST_RELAY_IMAGE,
                "registry-notary": TEST_NOTARY_IMAGE,
            }
        })
    }

    fn write_test_image_lock(temp: &TempDir, value: &serde_json::Value) -> PathBuf {
        let executable = temp.path().join("registryctl");
        fs::write(&executable, b"test binary").unwrap();
        fs::write(
            temp.path().join(registryctl_image_lock_filename()),
            serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
        executable
    }

    #[test]
    fn image_lock_loads_strict_versioned_file_beside_executable() {
        let temp = TempDir::new().unwrap();
        let executable = write_test_image_lock(&temp, &test_image_lock_json());

        let image_lock = load_registryctl_image_lock_beside(&executable).unwrap();

        assert_eq!(image_lock, test_image_lock());
    }

    #[test]
    fn image_lock_rejects_unknown_root_and_image_fields() {
        for (field_path, value) in [
            ("root", serde_json::json!(true)),
            ("images", serde_json::json!(true)),
        ] {
            let temp = TempDir::new().unwrap();
            let mut document = test_image_lock_json();
            if field_path == "root" {
                document["unexpected"] = value;
            } else {
                document["images"]["unexpected"] = value;
            }
            let executable = write_test_image_lock(&temp, &document);

            let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

            assert!(
                format!("{error:#}").contains("unknown field"),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn image_lock_rejects_release_identity_and_platform_mismatches() {
        for (field, invalid, expected) in [
            ("release_tag", serde_json::json!("v9.9.9"), "release_tag"),
            (
                "manifest_source_ref",
                serde_json::json!("A".repeat(40)),
                "manifest_source_ref",
            ),
            (
                "tag_target",
                serde_json::json!("b".repeat(39)),
                "tag_target",
            ),
            ("platform", serde_json::json!("linux/arm64"), "platform"),
        ] {
            let temp = TempDir::new().unwrap();
            let mut document = test_image_lock_json();
            document[field] = invalid;
            let executable = write_test_image_lock(&temp, &document);

            let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

            assert!(
                format!("{error:#}").contains(expected),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn image_lock_rejects_mutable_or_noncanonical_image_references() {
        for (field, invalid) in [
            (
                "registry-relay",
                "ghcr.io/registrystack/registry-relay:v0.8.4".to_string(),
            ),
            (
                "registry-notary",
                format!("ghcr.io/example/registry-notary@sha256:{}", "b".repeat(64)),
            ),
            (
                "registry-relay",
                format!(
                    "ghcr.io/registrystack/registry-relay@sha256:{}",
                    "A".repeat(64)
                ),
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let mut document = test_image_lock_json();
            document["images"][field] = serde_json::json!(invalid);
            let executable = write_test_image_lock(&temp, &document);

            let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

            assert!(
                format!("{error:#}").contains(&format!("images.{field}")),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn image_lock_rejects_missing_nonregular_and_oversized_files() {
        let missing = TempDir::new().unwrap();
        let missing_executable = missing.path().join("registryctl");
        fs::write(&missing_executable, b"test binary").unwrap();
        let error = load_registryctl_image_lock_beside(&missing_executable).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("image lock is missing"));
        assert!(message.contains(IMAGE_LOCK_PATH_ENV));

        let directory = TempDir::new().unwrap();
        let executable = directory.path().join("registryctl");
        fs::write(&executable, b"test binary").unwrap();
        fs::create_dir(directory.path().join(registryctl_image_lock_filename())).unwrap();
        let error = load_registryctl_image_lock_beside(&executable).unwrap_err();
        assert!(format!("{error:#}").contains("must be a regular file"));

        let oversized = TempDir::new().unwrap();
        let executable = oversized.path().join("registryctl");
        fs::write(&executable, b"test binary").unwrap();
        fs::write(
            oversized.path().join(registryctl_image_lock_filename()),
            vec![b' '; IMAGE_LOCK_MAX_BYTES as usize + 1],
        )
        .unwrap();
        let error = load_registryctl_image_lock_beside(&executable).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the 16384-byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn image_lock_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let executable = temp.path().join("registryctl");
        let target = temp.path().join("lock-target.json");
        fs::write(&executable, b"test binary").unwrap();
        fs::write(
            &target,
            serde_json::to_vec(&test_image_lock_json()).unwrap(),
        )
        .unwrap();
        symlink(&target, temp.path().join(registryctl_image_lock_filename())).unwrap();

        let error = load_registryctl_image_lock_beside(&executable).unwrap_err();

        assert!(format!("{error:#}").contains("must be a regular file"));
    }

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
    fn config_artifact_reader_rejects_duplicate_members_and_oversize_input() {
        let temp = TempDir::new().unwrap();
        let duplicate_path = temp.path().join("duplicate.json");
        fs::write(&duplicate_path, br#"{"id":1,"\u0069d":2}"#).unwrap();

        let error = read_bounded_strict_json::<Value>(&duplicate_path, 1024).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate JSON object member"));

        let oversized_path = temp.path().join("oversized.json");
        fs::write(&oversized_path, br#"{"value":"too-large"}"#).unwrap();
        let error = read_bounded_strict_json::<Value>(&oversized_path, 4).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the 4-byte limit"));

        let oversized_jwk_path = temp.path().join("oversized.jwk");
        fs::write(&oversized_jwk_path, vec![b' '; MAX_JWK_JSON_BYTES + 1]).unwrap();
        let error = read_private_jwk_text(oversized_jwk_path.to_str().unwrap()).unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("exceeds the {MAX_JWK_JSON_BYTES}-byte limit"))
        );
        let error = read_bounded_utf8_file(&oversized_jwk_path, MAX_JWK_JSON_BYTES).unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("exceeds the {MAX_JWK_JSON_BYTES}-byte limit"))
        );
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

    #[test]
    fn update_check_detects_newer_canonical_release_tags() {
        assert!(update_notice("0.1.0", "v0.1.1").is_some());
        assert!(update_notice("0.1.9", "v0.10.0").is_some());
        assert!(update_notice("0.1.0", "v0.1.0").is_none());
        assert!(update_notice("0.2.0", "v0.1.9").is_none());
        assert!(update_notice("not-a-version", "v0.2.0").is_none());
    }

    #[test]
    fn update_notice_uses_explicit_tag_ref_and_env_on_bash() {
        let notice = update_notice("0.1.0", "v0.2.0").unwrap();

        assert!(notice.contains("registryctl v0.2.0 is available"));
        assert!(notice.contains("You have v0.1.0"));
        assert_eq!(
            notice.lines().last(),
            Some(
                "  curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/refs/tags/v0.2.0/crates/registryctl/install.sh | REGISTRYCTL_VERSION=v0.2.0 bash"
            )
        );
        assert!(!notice.contains(
            "https://raw.githubusercontent.com/registrystack/registry-stack/main/crates/registryctl/install.sh"
        ));
        assert!(!notice.contains(
            "https://raw.githubusercontent.com/registrystack/registry-stack/v0.2.0/crates/registryctl/install.sh"
        ));
        assert!(!notice.contains("REGISTRYCTL_VERSION=v0.2.0 curl"));
    }

    #[test]
    fn update_notice_warns_about_checksum_only_installer_before_command() {
        let notice = update_notice("0.1.0", "v0.2.0").unwrap();
        let warning = notice
            .find("The quick installer verifies SHA256 integrity only.")
            .unwrap();
        let command = notice.find("Upgrade with:").unwrap();

        assert!(warning < command);
        assert!(notice.contains(REGISTRYCTL_VERIFY_GUIDE));
    }

    #[test]
    fn update_notice_rejects_shell_active_and_noncanonical_tags() {
        let hostile = "v999.0.0-$(touch${IFS}/tmp/registryctl-owned)";
        let temp = TempDir::new().unwrap();
        let cache_path = temp.path().join("registryctl/update-check.json");

        assert!(update_notice("0.1.0", hostile).is_none());
        assert!(VersionNumber::parse_release_tag(hostile).is_none());
        assert!(VersionNumber::parse_release_tag("999.0.0").is_none());
        assert!(VersionNumber::parse_release_tag("v01.0.0").is_none());
        assert!(write_update_check_cache(&cache_path, hostile).is_err());
        assert!(!cache_path.exists());

        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        let poisoned = UpdateCheckCache {
            checked_at: 1,
            latest_tag: hostile.to_string(),
        };
        fs::write(&cache_path, serde_json::to_string(&poisoned).unwrap()).unwrap();
        assert!(read_update_check_cache(&cache_path).is_err());
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
    fn init_sample_creates_expected_project_tree() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");

        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

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
        assert!(config_text.contains("# Entities are API projections."));
        let config: Value = serde_norway::from_str(&config_text).unwrap();
        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();
        assert!(config.get("metadata").is_none());
        assert_eq!(config["deployment"]["profile"], "local");
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

        let entities = config["datasets"][0]["entities"].as_sequence().unwrap();
        let entity = |name: &str| {
            entities
                .iter()
                .find(|entity| entity["name"] == name)
                .unwrap()
        };
        let person = entity("person");
        let person_fields = person["fields"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            person_fields,
            [
                "id",
                "household_id",
                "date_of_birth",
                "relationship_to_head",
                "registration_status"
            ]
        );
        assert_eq!(
            person["api"]["governed_policy"]["permitted_purposes"][0],
            TUTORIAL_PURPOSE
        );

        let person_identity = entity("person_identity");
        assert_eq!(
            person_identity["access"]["read_scope"],
            "benefits_casework:identity_release"
        );
        assert_eq!(person_identity["api"]["max_limit"], 1);
        assert_eq!(
            person_identity["api"]["governed_policy"]["permitted_purposes"][0],
            TUTORIAL_IDENTITY_PURPOSE
        );
        assert_eq!(
            entity("household_contact")["access"]["read_scope"],
            "benefits_casework:identity_release"
        );

        let readme = fs::read_to_string(project.join("README.md")).unwrap();
        assert!(readme.contains("registryctl doctor --profile local"));
        assert!(readme.contains("redacts local secret"));
        assert!(readme.contains("Back up that file before upgrades"));
        assert!(readme.contains("Notary evaluation state is in memory"));
        assert!(readme.contains("may contain cached source rows"));
        assert!(!readme.contains("preserve its configured PostgreSQL database"));
        assert!(readme.contains("https://docs.registrystack.org/operate/backup-and-restore/"));
        assert!(readme
            .contains("https://docs.registrystack.org/operate/single-node-compose-behind-proxy/"));
    }

    #[test]
    fn add_notary_builds_an_editable_live_tutorial_addon() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        let image_lock = test_image_lock();
        init_spreadsheet_api(&project, Sample::Benefits, &image_lock).unwrap();

        let report = add_notary_to_project(&project, &image_lock).unwrap();

        assert_eq!(report.status, "added");
        for path in [
            NOTARY_CLAIM_FILE,
            NOTARY_CONFIG_PATH,
            CONSULTATION_RELAY_CONFIG_PATH,
            NOTARY_RELAY_TOKEN_PATH,
            CONSULTATION_POSTGRES_CERT_PATH,
            CONSULTATION_POSTGRES_KEY_PATH,
            "notary/postgres-init.sql",
            "notary/jwks.json",
        ] {
            assert!(project.join(path).is_file(), "{path} should exist");
        }
        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        assert_eq!(manifest["runtime"]["notary_base_url"], NOTARY_BASE_URL);
        assert_eq!(manifest["notary"]["claim_file"], NOTARY_CLAIM_FILE);
        assert!(project.join(CONSULTATION_RELAY_CACHE_PATH).is_dir());
        assert_private_state_dirs(
            &project,
            &[
                CONSULTATION_RELAY_STATE_DIR,
                CONSULTATION_RELAY_CACHE_PATH,
                NOTARY_CONFIG_DIR,
                CONSULTATION_RELAY_CONFIG_DIR,
            ],
        );
        assert_private_file(&project, NOTARY_RELAY_TOKEN_PATH);
        assert_private_file(&project, CONSULTATION_POSTGRES_KEY_PATH);
        assert_private_file(&project, NOTARY_CONFIG_PATH);
        assert_private_file(&project, CONSULTATION_RELAY_CONFIG_PATH);
        assert_notary_runtime_input_owners_match_project(&project);
        let compose_text = fs::read_to_string(project.join("compose.yaml")).unwrap();
        let compose: Value = serde_norway::from_str(&compose_text).unwrap();
        let services = &compose["services"];
        let runtime_user =
            "${REGISTRY_STACK_RUNTIME_UID:-65532}:${REGISTRY_STACK_RUNTIME_GID:-65532}";
        for service in [
            "registry-relay-consultation-bootstrap",
            "registry-relay-consultation",
            "registry-notary",
        ] {
            assert_eq!(services[service]["user"], runtime_user);
        }
        for service in ["registry-consultation-db", "registry-notary-jwks"] {
            assert!(
                services[service].get("user").is_none(),
                "{service} must keep its image-provided runtime identity"
            );
        }
        let consultation_mounts = services["registry-relay-consultation"]["volumes"]
            .as_sequence()
            .unwrap();
        assert!(consultation_mounts.iter().any(|mount| {
            mount == "./state/relay-consultation/cache:/var/lib/registry-relay/cache"
        }));
        assert!(!compose["volumes"]
            .as_mapping()
            .unwrap()
            .contains_key("registry-consultation-cache"));
        assert_eq!(
            services["registry-notary"]["network_mode"],
            "service:registry-notary-jwks"
        );
        assert!(consultation_mounts.iter().any(|mount| {
            mount
                == "./notary/project/.registry-stack/build/local/private/relay/config:/etc/registry-relay:ro"
        }));
        assert!(services["registry-notary"]["volumes"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|mount| {
                mount
                    == "./notary/project/.registry-stack/build/local/private/notary/config:/etc/registry-notary:ro"
            }));
        assert!(!compose_text.contains("config/notary.yaml:/etc/registry-notary/notary.yaml"));
        let postgres_init = fs::read_to_string(project.join("notary/postgres-init.sql")).unwrap();
        assert!(!postgres_init.contains("GRANT relay_state_owner"));
        assert!(
            postgres_init.contains("GRANT CREATE ON DATABASE registry_relay TO relay_state_owner")
        );
        assert_eq!(services["registry-notary-jwks"]["ports"][0], "4255:8081");
        assert!(services["registry-consultation-db"]["entrypoint"][2]
            .as_str()
            .unwrap()
            .contains("ssl_cert_file=/var/lib/postgresql/tls/server.crt"));
        assert_eq!(
            compose["networks"]["registry-notary-internal"]["internal"],
            true
        );
        assert!(compose["networks"].get("registry-notary-public").is_some());
        assert_eq!(services["registry-notary"]["image"], TEST_NOTARY_IMAGE);
        let claim_source = fs::read_to_string(project.join(NOTARY_CLAIM_FILE)).unwrap();
        assert!(claim_source.contains("request.target.attributes.given_name"));
        assert!(claim_source.contains("request.target.attributes.date_of_birth"));
        assert!(claim_source.contains("person-registration-accepted"));
        assert!(claim_source.contains("enrollment.registration_status == \"active\""));
        assert!(!claim_source.contains("age_on"));
        let integration = fs::read_to_string(
            project.join("notary/project/integrations/person-demographics/integration.yaml"),
        )
        .unwrap();
        assert!(integration.contains("outputs: [registration_status]"));
        assert!(!integration.contains("outputs: [date_of_birth]"));
        assert!(!integration.contains("outputs: [national_id]"));
        let environment =
            fs::read_to_string(project.join("notary/project/environments/local.yaml")).unwrap();
        assert!(environment.contains("worker_memory_bytes: 1073741824"));
        let secrets = LocalEnv::load(&project.join("secrets/local.env")).unwrap();
        assert!(!secrets.value("TUTORIAL_EVALUATOR_RAW").is_empty());
        assert_eq!(
            secrets.required("TUTORIAL_EVALUATOR_HASH").unwrap(),
            fingerprint_api_key(secrets.required("TUTORIAL_EVALUATOR_RAW").unwrap())
        );
        let token = fs::read_to_string(project.join(NOTARY_RELAY_TOKEN_PATH)).unwrap();
        assert_eq!(token.trim().split('.').count(), 3);
        let claims = token.trim().split('.').nth(1).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(claims)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            claims["scope"],
            "registry:consult:registration-verification"
        );
        let claim_path = project.join(NOTARY_CLAIM_FILE);
        let claim = fs::read_to_string(&claim_path).unwrap().replace(
            "enrollment.registration_status == \"active\"",
            "(enrollment.registration_status == \"active\" || enrollment.registration_status == \"pending\")",
        );
        fs::write(&claim_path, claim).unwrap();
        let fixture_path =
            project.join("notary/project/integrations/person-demographics/fixtures/pending.yaml");
        let fixture = fs::read_to_string(&fixture_path).unwrap().replace(
            "claims: { person-registration-accepted: false }",
            "claims: { person-registration-accepted: true }",
        );
        fs::write(&fixture_path, fixture).unwrap();
        prepare_notary_runtime(&project).unwrap();
        assert_notary_runtime_input_owners_match_project(&project);
        let notary_config_text = fs::read_to_string(project.join(NOTARY_CONFIG_PATH)).unwrap();
        assert!(notary_config_text.contains("person-registration-accepted"));
        assert!(notary_config_text.contains("pending"));
        let notary_config: Value = serde_norway::from_str(&notary_config_text).unwrap();
        assert_eq!(notary_config["state"]["storage"], "in_memory");
        assert!(notary_config["evidence"]["credential_profiles"]
            .as_mapping()
            .is_some_and(serde_norway::Mapping::is_empty));
        let claims = notary_config["evidence"]["claims"].as_sequence().unwrap();
        assert!(!claims.is_empty());
        assert!(claims
            .iter()
            .all(|claim| claim["evidence_mode"]["type"] == "registry_backed"));
        assert!(claims.iter().all(|claim| claim["credential_profiles"]
            .as_sequence()
            .is_some_and(Vec::is_empty)));
        let signing_keys = notary_config["evidence"]["signing_keys"]
            .as_mapping()
            .unwrap();
        assert_eq!(signing_keys.len(), 1);
        assert!(signing_keys.contains_key("relay-workload"));

        let error = add_notary_to_project(&project, &image_lock).unwrap_err();
        assert!(format!("{error:#}").contains("already has a Notary"));
    }

    #[test]
    fn add_notary_rolls_back_generated_project_files_on_failure() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        let image_lock = test_image_lock();
        init_spreadsheet_api(&project, Sample::Benefits, &image_lock).unwrap();
        let compose_path = project.join("compose.yaml");
        let secrets_path = project.join("secrets/local.env");
        let manifest_path = project.join("registryctl.yaml");
        let conflicting_compose = fs::read_to_string(&compose_path)
            .unwrap()
            .replace("services:\n", "services:\n  registry-notary: {}\n");
        fs::write(&compose_path, &conflicting_compose).unwrap();
        let original_secrets = fs::read_to_string(&secrets_path).unwrap();
        let original_manifest = fs::read_to_string(&manifest_path).unwrap();

        let error = add_notary_to_project(&project, &image_lock).unwrap_err();

        assert!(format!("{error:#}").contains("already contains a generated Notary entry"));
        assert!(!project.join("notary").exists());
        for path in [
            NOTARY_RELAY_TOKEN_PATH,
            CONSULTATION_POSTGRES_CERT_PATH,
            CONSULTATION_POSTGRES_KEY_PATH,
        ] {
            assert!(!project.join(path).exists());
        }
        assert!(!project.join(CONSULTATION_RELAY_STATE_DIR).exists());
        assert_eq!(
            fs::read_to_string(compose_path).unwrap(),
            conflicting_compose
        );
        assert_eq!(fs::read_to_string(secrets_path).unwrap(), original_secrets);
        assert_eq!(
            fs::read_to_string(manifest_path).unwrap(),
            original_manifest
        );
    }

    #[test]
    fn add_notary_refuses_a_preexisting_sidecar_without_modifying_it() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        let image_lock = test_image_lock();
        init_spreadsheet_api(&project, Sample::Benefits, &image_lock).unwrap();
        let token_path = project.join(NOTARY_RELAY_TOKEN_PATH);
        fs::write(&token_path, "operator-owned\n").unwrap();

        let error = add_notary_to_project(&project, &image_lock).unwrap_err();

        assert!(format!("{error:#}").contains("destination already exists"));
        assert_eq!(fs::read_to_string(token_path).unwrap(), "operator-owned\n");
        assert!(!project.join("notary").exists());
    }

    #[test]
    fn add_notary_refuses_preexisting_consultation_state_without_modifying_it() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        let image_lock = test_image_lock();
        init_spreadsheet_api(&project, Sample::Benefits, &image_lock).unwrap();
        let state_dir = project.join(CONSULTATION_RELAY_STATE_DIR);
        fs::create_dir_all(&state_dir).unwrap();
        let marker = state_dir.join("operator-owned");
        fs::write(&marker, "keep\n").unwrap();

        let error = add_notary_to_project(&project, &image_lock).unwrap_err();

        assert!(format!("{error:#}").contains("destination already exists"));
        assert_eq!(fs::read_to_string(marker).unwrap(), "keep\n");
        assert!(!project.join("notary").exists());
    }

    #[test]
    fn bruno_files_for_relay_project_are_generated_and_secret_scoped() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

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
        let identity_request = fs::read_to_string(
            project.join("bruno/registry-api/Relay/Read restricted identity.bru"),
        )
        .unwrap();
        let openapi_request =
            fs::read_to_string(project.join("bruno/registry-api/Relay/OpenAPI.bru")).unwrap();

        assert!(local_bru.contains(&env_value(&env, "METADATA_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "ROW_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "AGGREGATE_READER_RAW")));
        assert!(local_bru.contains(&env_value(&env, "IDENTITY_READER_RAW")));
        assert!(example_bru.contains("replace-with-metadata_reader_raw"));
        assert!(example_bru.contains("replace-with-aggregate_reader_raw"));
        assert!(example_bru.contains("replace-with-identity_reader_raw"));
        assert!(!request.contains(&env_value(&env, "METADATA_READER_RAW")));
        assert!(!request.contains(&env_value(&env, "ROW_READER_RAW")));
        assert!(!aggregate_request.contains(&env_value(&env, "AGGREGATE_READER_RAW")));
        assert!(request.contains("{{relay_row_key}}"));
        assert!(aggregate_request.contains("{{relay_aggregate_key}}"));
        assert!(aggregate_request.contains("Data-Purpose"));
        assert!(application_aggregate_request.contains("Data-Purpose"));
        assert!(identity_request.contains("{{relay_identity_key}}"));
        assert!(identity_request.contains("{{identity_purpose}}"));
        assert!(!openapi_request.contains("Authorization"));
        assert!(!openapi_request.contains("{{relay_metadata_key}}"));
    }

    #[test]
    fn bruno_generate_is_idempotent_for_generated_files() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let before =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Health.bru")).unwrap();
        bruno_generate_project(&project, false).unwrap();
        let after =
            fs::read_to_string(project.join("bruno/registry-api/Relay/Health.bru")).unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn manifest_pins_image_and_records_base_url() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let compose = fs::read_to_string(project.join("compose.yaml")).unwrap();

        assert_digest_pinned_image(
            manifest["runtime"]["relay_image"].as_str().unwrap(),
            "ghcr.io/registrystack/registry-relay",
        );
        assert_eq!(manifest["runtime"]["relay_base_url"], RELAY_BASE_URL);
        assert!(manifest["relay"].get("metadata").is_none());
        assert!(compose.contains(&format!("image: {TEST_RELAY_IMAGE}")));
        assert!(!compose.contains("metadata.yaml"));
        assert!(!compose.contains("registry-relay:snapshot"));
        assert!(!compose.contains("registry-relay:latest"));
    }

    #[test]
    fn compose_platform_override_targets_amd64_for_arm64_relay_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
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
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let project = Project::load(&project_dir).unwrap();

        assert_eq!(
            compose_platform_override(&project, Some("linux/arm64"), Some("linux/arm64")),
            None
        );
    }

    #[test]
    fn relay_only_manifest_loads_without_notary_section() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        Project::load(&project).unwrap();

        let manifest: Value =
            serde_norway::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        let products = manifest["project"]["products"]
            .as_sequence()
            .expect("project products should be a list");
        assert!(products
            .iter()
            .any(|product| product.as_str() == Some("registry-relay")));
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
                "{MINIMAL_SCHEMA_AND_PROJECT_BLOCK}unknown_product:\n  config: unknown/config.yaml\n{MINIMAL_RUNTIME_BLOCK}{MINIMAL_LOCAL_BLOCK}"
            ),
        );

        let error = Project::load(temp.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("unknown_product"),
            "error should name the offending key `unknown_product`: {error:#}"
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
    fn generated_gitignore_excludes_local_secrets_and_output() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

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
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let config = fs::read_to_string(project.join("relay/config.yaml")).unwrap();
        let config_yaml: Value = serde_norway::from_str(&config).unwrap();
        assert_eq!(config_yaml["server"]["openapi_requires_auth"], false);
        assert!(!config.contains("commitment:"));

        for (id, env_name) in [
            ("metadata_reader", "METADATA_READER_HASH"),
            ("row_reader", "ROW_READER_HASH"),
            ("aggregate_reader", "AGGREGATE_READER_HASH"),
            ("identity_reader", "IDENTITY_READER_HASH"),
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
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

        let project = Project::load(&project_dir).unwrap();
        validate_project_fingerprints(&project_dir, &project).unwrap();
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_changes() {
        for (env_name, id) in [
            ("METADATA_READER_HASH", "metadata_reader"),
            ("ROW_READER_HASH", "row_reader"),
            ("AGGREGATE_READER_HASH", "aggregate_reader"),
            ("IDENTITY_READER_HASH", "identity_reader"),
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

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
            "IDENTITY_READER_HASH",
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

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
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

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
        init_spreadsheet_api(&project, Sample::Benefits, &test_image_lock()).unwrap();

        let workbook = fs::read(project.join("data/benefits_casework.xlsx")).unwrap();
        assert!(workbook.starts_with(b"PK"));
        let lossy = String::from_utf8_lossy(&workbook);
        assert!(lossy.contains("Households"));
        assert!(lossy.contains("Persons"));
        assert!(lossy.contains("Applications"));
        assert!(lossy.contains("hh-1001"));
        assert!(lossy.contains("app-3001"));
        assert!(lossy.contains("date_of_birth"));
        assert!(lossy.contains("given_name"));
        assert!(lossy.contains("national_id"));
        assert!(lossy.contains("address_line"));
        assert!(!lossy.contains("age_band"));
        assert!(!lossy.contains("eligibility_status"));
        assert!(!lossy.contains("is_primary_applicant"));
        assert!(!lossy.contains("consent_reference"));
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
                (
                    "IDENTITY_READER_RAW".to_string(),
                    "identity-secret".to_string(),
                ),
            ]),
        };
        let report = run_smoke_checks("http://127.0.0.1:1", &secrets);
        let json = serde_json::to_string(&report).unwrap();
        let parsed = parse_smoke_report(&json).unwrap();

        assert!(!json.contains("metadata-secret"));
        assert!(!json.contains("row-secret"));
        assert!(!json.contains("identity-secret"));
        assert!(!report.passed);
        assert_eq!(parsed.checks.len(), 11);
    }

    #[test]
    fn smoke_project_writes_redacted_failure_report() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();

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
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
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

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();

        assert_eq!(report.status, ReportStatus::Ok);
        assert_eq!(report.products.len(), 1);
        assert_eq!(report.products[0].product, "registry-relay");
        assert_eq!(report.products[0].status, ReportStatus::Ok);
        let human = render_doctor_report(&report);
        assert!(human.starts_with("Registry Stack doctor: ok\n"), "{human}");
        assert!(human.contains("Profile: project"), "{human}");
        assert!(
            human.contains("registry-relay: ok (0 errors, 0 warnings)"),
            "{human}"
        );
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
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
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
    fn doctor_reports_missing_product_binary_without_panic() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let empty_path = temp.path().join("empty-path");
        fs::create_dir_all(&empty_path).unwrap();

        let report = run_doctor_report_with_path(&project_dir, None, Some(&empty_path)).unwrap();

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
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
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

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
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
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
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

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
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
    fn doctor_carries_audit_shipping_section_through_typed_aggregation() {
        // registryctl deserializes each product's doctor JSON into
        // ConfigDiagnosticReport and re-serializes it into the aggregated
        // report. If the struct doesn't model audit_shipping, this section is
        // silently dropped even though the product emitted it.
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let product_json = serde_json::json!({
            "schema_version": "registry.config.diagnostic_report.v1",
            "product": "registry-relay",
            "config_schema_version": "registry.relay.config.v1",
            "source": {"kind": "generated_file", "path": "relay/config.yaml"},
            "status": "ok",
            "summary": {"error_count": 0, "warning_count": 0},
            "diagnostics": [],
            "context_constraints": [],
            "audit_shipping": {
                "sink_type": "file",
                "shipping_target_configured": true,
                "shipping_target": "declared_external",
                "shipping_health": "stale",
                "shipping_observed_at": "2026-06-19T23:00:00Z"
            },
            "generated_at": "2026-06-20T00:00:00Z"
        })
        .to_string();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&product_json)
            ),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
        let json = serde_json::to_value(&report).unwrap();

        let shipping = &json["products"][0]["report"]["audit_shipping"];
        assert_eq!(shipping["sink_type"], "file");
        assert_eq!(shipping["shipping_target_configured"], true);
        assert_eq!(shipping["shipping_target"], "declared_external");
        assert_eq!(shipping["shipping_health"], "stale");
        assert_eq!(shipping["shipping_observed_at"], "2026-06-19T23:00:00Z");
    }

    #[test]
    fn doctor_report_json_has_registryctl_schema() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits, &test_image_lock()).unwrap();
        let fake_bin = temp.path().join("bin");
        fs::create_dir_all(&fake_bin).unwrap();
        write_fake_product(
            &fake_bin.join("registry-relay"),
            &format!(
                "printf '%s\\n' {}\nexit 0\n",
                shell_single_quoted(&fake_product_report("registry-relay", "ok", vec![]))
            ),
        );

        let report = run_doctor_report_with_path(&project_dir, None, Some(&fake_bin)).unwrap();
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

    #[test]
    fn doctor_human_values_cannot_inject_terminal_lines() {
        assert_eq!(
            human_line_value("line\nreturn\r tab\t escape\u{1b}"),
            "line\\nreturn\\r tab\\t escape\\u001b"
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
    fn assert_private_file(project: &Path, path: &str) {
        use std::os::unix::fs::PermissionsExt;

        let actual_mode = fs::metadata(project.join(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(actual_mode, 0o600, "{path} should be private");
    }

    #[cfg(not(unix))]
    fn assert_private_file(_project: &Path, _path: &str) {}

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

    #[cfg(unix)]
    fn assert_notary_runtime_input_owners_match_project(project: &Path) {
        use std::os::unix::fs::MetadataExt;

        let project_metadata = fs::metadata(project).unwrap();
        let identity = runtime_identity_for_owner(project_metadata.uid(), project_metadata.gid());
        for relative in [NOTARY_CONFIG_DIR, CONSULTATION_RELAY_CONFIG_DIR] {
            assert_runtime_input_tree_owner(&project.join(relative), identity);
        }
        let token = project.join(NOTARY_RELAY_TOKEN_PATH);
        assert_runtime_input_owner(&token, identity);
    }

    #[cfg(not(unix))]
    fn assert_notary_runtime_input_owners_match_project(_project: &Path) {}

    #[cfg(unix)]
    fn assert_runtime_input_tree_owner(path: &Path, expected: RuntimeIdentity) {
        let metadata = assert_runtime_input_owner(path, expected);
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                assert_runtime_input_tree_owner(&entry.unwrap().path(), expected);
            }
        }
    }

    #[cfg(unix)]
    fn assert_runtime_input_owner(path: &Path, expected: RuntimeIdentity) -> fs::Metadata {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (expected.uid, expected.gid),
            "{} should be owned by the selected runtime identity",
            path.display()
        );
        metadata
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

    fn env_value(env: &str, name: &str) -> String {
        env.lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then(|| value.to_string()))
            .unwrap_or_else(|| panic!("{name} should be present"))
    }
}
