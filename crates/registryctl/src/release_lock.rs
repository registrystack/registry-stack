// SPDX-License-Identifier: Apache-2.0
//! Offline verification for the maintainer-produced Registry Stack release lock.
//!
//! The lock is a signed capability, not configuration. Only this module may turn
//! its untrusted wire representation into deployment image and runtime mappings.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sigstore_verify::trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
use sigstore_verify::types::Bundle;
use sigstore_verify::{verify, VerificationPolicy};

pub const RELEASE_LOCK_SCHEMA_ID: &str = "io.registrystack.registry_release_lock";
pub const RELEASE_LOCK_SCHEMA_VERSION: &str = "1.0";

const RELEASE_REPOSITORY: &str = "registrystack/registry-stack";
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const RELEASE_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_RELEASE_LOCK_BYTES: usize = 2 * 1024 * 1024;
const MAX_SIGNED_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const PRODUCTION_TRUST_ROOT_SHA256: &str =
    "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";

const CONFIG_BUNDLE_SCHEMA: &str = "registry.platform.config_bundle.v1";
const CONFIG_SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";
const ANCHOR_TRANSITION_SCHEMA: &str = "registry.platform.anchor_transition@1.0";
const RELAY_CONFIG_SCHEMA: &str =
    "https://id.registrystack.org/schemas/registry-relay/registry-relay.config.schema.json";
const NOTARY_CONFIG_SCHEMA: &str =
    "https://id.registrystack.org/schemas/registry-notary/registry-notary.config.schema.json";
const PRODUCT_BUNDLE_TARGET: &str = "/run/registry/bundle";
const PRODUCT_ANCHOR_TARGET: &str = "/run/registry/anchor";
const PRODUCT_STATE_TARGET: &str = "/var/lib/registry/state";
const PRODUCT_AUDIT_TARGET: &str = "/var/lib/registry/audit";
const POSTGRESQL_DATA_TARGET: &str = "/var/lib/postgresql/data";
// SHA-256 of `POSTGRESQL_BOOTSTRAP_SCRIPT` in
// `release/scripts/registry_release_lock.py`. The release-lock verifier must
// authorize the exact reviewed script, not a shell command that contains a
// few expected fragments.
const POSTGRESQL_BOOTSTRAP_SCRIPT_SHA256: &str =
    "cbad443afb9700702df52be6513cf8afd95b97747d75a0a417df4fd079a2e79c";
const POSTGRESQL_BOOTSTRAP_KEYS: [&str; 8] = [
    "REGISTRY_RELAY_MIGRATOR_PASSWORD",
    "REGISTRY_RELAY_RUNTIME_PASSWORD",
    "REGISTRY_RELAY_MAINTENANCE_PASSWORD",
    "REGISTRY_RELAY_READER_PASSWORD",
    "REGISTRY_NOTARY_MIGRATOR_PASSWORD",
    "REGISTRY_NOTARY_RUNTIME_PASSWORD",
    "REGISTRY_NOTARY_MAINTENANCE_PASSWORD",
    "REGISTRY_NOTARY_READER_PASSWORD",
];

/// The strict, self-contained wire envelope shipped as
/// `registry-release-lock.v1.json`.
///
/// `signed_payload` is the base64 encoding of RFC 8785 canonical JSON. Keeping
/// the exact signed bytes in the envelope avoids a detached-file substitution
/// boundary while still allowing the payload to be parsed into a closed type.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryReleaseLockEnvelopeV1 {
    schema_id: String,
    schema_version: String,
    signed_payload: String,
    sigstore_bundle: Value,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReleaseLockV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub release: LockedReleaseIdentityV1,
    pub registryctl_artifacts: Vec<LockedRegistryctlArtifactV1>,
    pub images: LockedManagedImagesV1,
    pub runtime: LockedRuntimeRecipesV1,
    pub supported_contracts: SupportedContractsV1,
    pub embedded_starters: Vec<LockedEmbeddedStarterV1>,
    pub minimum_compose_version: String,
    pub postgresql_major_version: u16,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedReleaseIdentityV1 {
    pub product_version: String,
    pub release_tag: String,
    pub source_repository: String,
    pub source_workflow: String,
    pub source_ref: String,
    pub manifest_source_ref: String,
    pub tag_target: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryctlPlatformV1 {
    LinuxAmd64,
    LinuxArm64,
    MacosArm64,
}

impl RegistryctlPlatformV1 {
    fn asset_suffix(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "linux-amd64",
            Self::LinuxArm64 => "linux-arm64",
            Self::MacosArm64 => "macos-arm64",
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRegistryctlArtifactV1 {
    pub platform: RegistryctlPlatformV1,
    pub filename: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciPlatformV1 {
    LinuxAmd64,
    LinuxArm64,
}

impl OciPlatformV1 {
    pub fn compose_platform(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "linux/amd64",
            Self::LinuxArm64 => "linux/arm64",
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedOciPlatformV1 {
    pub platform: OciPlatformV1,
    pub manifest_digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedOciImageV1 {
    pub identity: String,
    pub platforms: Vec<LockedOciPlatformV1>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedManagedImagesV1 {
    pub relay: LockedOciImageV1,
    pub notary: LockedOciImageV1,
    pub postgresql_state_plane: LockedOciImageV1,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedProductRecipeV1 {
    pub serve: LockedRuntimeActionV1,
    pub prepare_state_store: LockedRuntimeActionV1,
    pub initialize_state: LockedRuntimeActionV1,
    pub preview_state: LockedRuntimeActionV1,
    pub accept_state: LockedRuntimeActionV1,
    pub verify_state: LockedRuntimeActionV1,
    pub development_prepare_state_store: LockedRuntimeActionV1,
    pub development_initialize_state: LockedRuntimeActionV1,
    pub development_serve: LockedRuntimeActionV1,
    pub health_probe: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockedMountSourceV1 {
    Bundle,
    Anchor,
    AntiRollbackState,
    Audit,
    PostgresqlData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRuntimeMountV1 {
    pub source: LockedMountSourceV1,
    pub target: String,
    pub read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSecretProjectionV1 {
    pub file_id: String,
    pub target: String,
    pub mode: String,
    pub uid: String,
    pub gid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRuntimeActionV1 {
    pub command: Vec<String>,
    pub mounts: Vec<LockedRuntimeMountV1>,
    pub environment_files: Vec<String>,
    pub secret_files: Vec<LockedSecretProjectionV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockedOperatorFileFormatV1 {
    Dotenv,
    PemCertificate,
    PemPrivateKey,
    JsonWebKey,
    CompactJwt,
    Opaque,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedOperatorFileV1 {
    pub id: String,
    pub format: LockedOperatorFileFormatV1,
    pub mode: String,
    pub allowed_owners: Vec<String>,
    pub required_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedServiceHardeningV1 {
    pub user: String,
    pub read_only_root_filesystem: bool,
    pub cap_drop: Vec<String>,
    pub security_opt: Vec<String>,
    pub tmpfs: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedPostgresqlRecipeV1 {
    pub serve: LockedRuntimeActionV1,
    pub bootstrap: LockedRuntimeActionV1,
    pub health_probe: Vec<String>,
    pub server_environment: Vec<String>,
    pub hardening: LockedServiceHardeningV1,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRuntimeRecipesV1 {
    pub relay_public: LockedProductRecipeV1,
    pub relay_consultation: LockedProductRecipeV1,
    pub notary: LockedProductRecipeV1,
    pub postgresql_state_plane: LockedPostgresqlRecipeV1,
    pub operator_files: Vec<LockedOperatorFileV1>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedContractsV1 {
    pub config_bundle_schema: String,
    pub config_signature_schema: String,
    pub trust_anchor_schema: String,
    pub anchor_transition_schema: String,
    pub relay_config_schema: String,
    pub notary_config_schema: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedEmbeddedStarterV1 {
    pub id: String,
    pub release: String,
    pub content_digest: String,
}

/// Capability returned only after strict parsing, trust-root pinning, full
/// offline Sigstore verification, and semantic lock validation.
///
/// This type intentionally implements neither `Serialize` nor `Debug`.
pub struct VerifiedReleaseLockV1 {
    lock: RegistryReleaseLockV1,
    signed_payload_sha256: String,
    envelope: RetainedVerifiedEnvelope,
}

struct RetainedVerifiedEnvelope {
    bytes: Box<[u8]>,
    sha256: String,
}

impl RetainedVerifiedEnvelope {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedManagedImagesV1 {
    relay: String,
    relay_platform: OciPlatformV1,
    notary: String,
    notary_platform: OciPlatformV1,
    postgresql_state_plane: String,
    postgresql_state_plane_platform: OciPlatformV1,
}

impl VerifiedManagedImagesV1 {
    pub fn relay(&self) -> &str {
        &self.relay
    }

    pub fn relay_platform(&self) -> OciPlatformV1 {
        self.relay_platform
    }

    pub fn notary(&self) -> &str {
        &self.notary
    }

    pub fn notary_platform(&self) -> OciPlatformV1 {
        self.notary_platform
    }

    pub fn postgresql_state_plane(&self) -> &str {
        &self.postgresql_state_plane
    }

    pub fn postgresql_state_plane_platform(&self) -> OciPlatformV1 {
        self.postgresql_state_plane_platform
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedProductRuntimeV1 {
    serve: LockedRuntimeActionV1,
    prepare_state_store: LockedRuntimeActionV1,
    initialize_state: LockedRuntimeActionV1,
    preview_state: LockedRuntimeActionV1,
    accept_state: LockedRuntimeActionV1,
    verify_state: LockedRuntimeActionV1,
    development_prepare_state_store: LockedRuntimeActionV1,
    development_initialize_state: LockedRuntimeActionV1,
    development_serve: LockedRuntimeActionV1,
    health_probe: Vec<String>,
}

impl VerifiedProductRuntimeV1 {
    pub fn serve(&self) -> &[String] {
        &self.serve.command
    }

    pub fn prepare_state_store(&self) -> &[String] {
        &self.prepare_state_store.command
    }

    pub fn initialize_state(&self) -> &[String] {
        &self.initialize_state.command
    }

    pub fn verify_state(&self) -> &[String] {
        &self.verify_state.command
    }

    pub fn preview_state(&self) -> &[String] {
        &self.preview_state.command
    }

    pub fn accept_state(&self) -> &[String] {
        &self.accept_state.command
    }

    pub fn serve_action(&self) -> &LockedRuntimeActionV1 {
        &self.serve
    }

    pub fn prepare_state_store_action(&self) -> &LockedRuntimeActionV1 {
        &self.prepare_state_store
    }

    pub fn initialize_state_action(&self) -> &LockedRuntimeActionV1 {
        &self.initialize_state
    }

    pub fn verify_state_action(&self) -> &LockedRuntimeActionV1 {
        &self.verify_state
    }

    pub fn preview_state_action(&self) -> &LockedRuntimeActionV1 {
        &self.preview_state
    }

    pub fn accept_state_action(&self) -> &LockedRuntimeActionV1 {
        &self.accept_state
    }

    pub fn development_prepare_state_store_action(&self) -> &LockedRuntimeActionV1 {
        &self.development_prepare_state_store
    }

    pub fn development_initialize_state_action(&self) -> &LockedRuntimeActionV1 {
        &self.development_initialize_state
    }

    pub fn development_serve_action(&self) -> &LockedRuntimeActionV1 {
        &self.development_serve
    }

    pub fn health_probe(&self) -> &[String] {
        &self.health_probe
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedPostgresqlRuntimeV1 {
    serve: LockedRuntimeActionV1,
    bootstrap: LockedRuntimeActionV1,
    health_probe: Vec<String>,
    server_environment: Vec<String>,
    hardening: LockedServiceHardeningV1,
}

impl VerifiedPostgresqlRuntimeV1 {
    pub fn command(&self) -> &[String] {
        &self.serve.command
    }

    pub fn serve(&self) -> &LockedRuntimeActionV1 {
        &self.serve
    }

    pub fn bootstrap(&self) -> &LockedRuntimeActionV1 {
        &self.bootstrap
    }

    pub fn health_probe(&self) -> &[String] {
        &self.health_probe
    }

    pub fn server_environment(&self) -> &[String] {
        &self.server_environment
    }

    pub fn hardening(&self) -> &LockedServiceHardeningV1 {
        &self.hardening
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRuntimeMappingV1 {
    relay_public: VerifiedProductRuntimeV1,
    relay_consultation: VerifiedProductRuntimeV1,
    notary: VerifiedProductRuntimeV1,
    postgresql_state_plane: VerifiedPostgresqlRuntimeV1,
    operator_files: Vec<LockedOperatorFileV1>,
}

impl VerifiedRuntimeMappingV1 {
    pub fn relay_public(&self) -> &VerifiedProductRuntimeV1 {
        &self.relay_public
    }

    pub fn relay_consultation(&self) -> &VerifiedProductRuntimeV1 {
        &self.relay_consultation
    }

    pub fn notary(&self) -> &VerifiedProductRuntimeV1 {
        &self.notary
    }

    pub fn postgresql_state_plane(&self) -> &VerifiedPostgresqlRuntimeV1 {
        &self.postgresql_state_plane
    }

    pub fn operator_files(&self) -> &[LockedOperatorFileV1] {
        &self.operator_files
    }
}

impl VerifiedReleaseLockV1 {
    pub fn product_version(&self) -> &str {
        &self.lock.release.product_version
    }

    pub fn release_tag(&self) -> &str {
        &self.lock.release.release_tag
    }

    pub fn manifest_source_ref(&self) -> &str {
        &self.lock.release.manifest_source_ref
    }

    pub fn tag_target(&self) -> &str {
        &self.lock.release.tag_target
    }

    pub fn signed_payload_sha256(&self) -> &str {
        &self.signed_payload_sha256
    }

    /// The exact bounded envelope bytes that passed offline verification.
    ///
    /// Callers can copy these bytes into a generated package without
    /// re-encoding the signed release evidence.
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope.bytes
    }

    /// SHA-256 digest of `envelope_bytes`, including its original JSON
    /// whitespace and ordering.
    pub fn envelope_sha256(&self) -> &str {
        &self.envelope.sha256
    }

    pub fn registryctl_artifacts(&self) -> &[LockedRegistryctlArtifactV1] {
        &self.lock.registryctl_artifacts
    }

    pub fn supported_contracts(&self) -> &SupportedContractsV1 {
        &self.lock.supported_contracts
    }

    pub fn embedded_starters(&self) -> &[LockedEmbeddedStarterV1] {
        &self.lock.embedded_starters
    }

    pub fn minimum_compose_version(&self) -> &str {
        &self.lock.minimum_compose_version
    }

    pub fn postgresql_major_version(&self) -> u16 {
        self.lock.postgresql_major_version
    }

    pub fn managed_images(&self) -> VerifiedManagedImagesV1 {
        VerifiedManagedImagesV1 {
            relay: self.lock.images.relay.identity.clone(),
            relay_platform: self.lock.images.relay.platforms[0].platform,
            notary: self.lock.images.notary.identity.clone(),
            notary_platform: self.lock.images.notary.platforms[0].platform,
            postgresql_state_plane: self.lock.images.postgresql_state_plane.identity.clone(),
            postgresql_state_plane_platform: self.lock.images.postgresql_state_plane.platforms[0]
                .platform,
        }
    }

    pub fn runtime_mapping(&self) -> VerifiedRuntimeMappingV1 {
        VerifiedRuntimeMappingV1 {
            relay_public: self.lock.runtime.relay_public.clone().into(),
            relay_consultation: self.lock.runtime.relay_consultation.clone().into(),
            notary: self.lock.runtime.notary.clone().into(),
            postgresql_state_plane: self.lock.runtime.postgresql_state_plane.clone().into(),
            operator_files: self.lock.runtime.operator_files.clone(),
        }
    }
}

impl From<LockedPostgresqlRecipeV1> for VerifiedPostgresqlRuntimeV1 {
    fn from(value: LockedPostgresqlRecipeV1) -> Self {
        Self {
            serve: value.serve,
            bootstrap: value.bootstrap,
            health_probe: value.health_probe,
            server_environment: value.server_environment,
            hardening: value.hardening,
        }
    }
}

impl From<LockedProductRecipeV1> for VerifiedProductRuntimeV1 {
    fn from(value: LockedProductRecipeV1) -> Self {
        Self {
            serve: value.serve,
            prepare_state_store: value.prepare_state_store,
            initialize_state: value.initialize_state,
            preview_state: value.preview_state,
            accept_state: value.accept_state,
            verify_state: value.verify_state,
            development_prepare_state_store: value.development_prepare_state_store,
            development_initialize_state: value.development_initialize_state,
            development_serve: value.development_serve,
            health_probe: value.health_probe,
        }
    }
}

/// Verify a package lock without network access or adopter-supplied trust
/// material. A newer Registryctl 1.x may inspect and deploy an older signed 1.x
/// package, so this boundary intentionally does not bind the running binary.
pub fn verify_release_lock_for_package(bytes: &[u8]) -> Result<VerifiedReleaseLockV1> {
    let verified = verify_release_lock_material(bytes)?;
    if release_major(verified.product_version())? != 1 {
        bail!("package release lock is outside the supported Registry Stack 1.x line");
    }
    Ok(verified)
}

/// Exercise the exact post-signature admission boundary with a payload emitted
/// by the release producer. The parity test cannot mint a production Sigstore
/// identity, so only the cryptographic authentication step is omitted.
#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by a direct-module integration test")
)]
pub(crate) fn semantically_admit_release_lock_payload_for_test(
    signed_payload: &[u8],
) -> Result<VerifiedReleaseLockV1> {
    let lock = parse_and_validate_signed_payload(signed_payload)?;
    if release_major(&lock.release.product_version)? != 1 {
        bail!("test release lock payload is outside the supported Registry Stack 1.x line");
    }
    Ok(VerifiedReleaseLockV1 {
        signed_payload_sha256: format!("sha256:{}", hex::encode(Sha256::digest(signed_payload))),
        envelope: RetainedVerifiedEnvelope::new(signed_payload),
        lock,
    })
}

/// Verify the installed lock and bind it to this exact Registryctl executable.
///
/// The lock envelope contains its Sigstore bundle inline, so reading this one
/// sibling artifact is sufficient for offline verification. Symlinks are
/// rejected to prevent replacing the installed lock through another path.
pub fn verify_installed_release_lock(path: &Path) -> Result<VerifiedReleaseLockV1> {
    let executable = std::env::current_exe().context("running Registryctl path is unavailable")?;
    ensure_sibling_release_lock(path, &executable)?;
    let metadata = fs::symlink_metadata(path).context("installed release lock is unavailable")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("installed release lock must be a regular non-symlink file");
    }
    if metadata.len() > MAX_RELEASE_LOCK_BYTES as u64 {
        bail!("installed release lock exceeds its size bound");
    }
    let bytes = fs::read(path).context("installed release lock could not be read")?;
    let verified = verify_release_lock_material(&bytes)?;
    if verified.product_version() != env!("CARGO_PKG_VERSION") {
        bail!("installed release lock does not match the running Registryctl version");
    }

    let current_platform = current_registryctl_platform()?;
    let artifact = verified
        .registryctl_artifacts()
        .iter()
        .find(|artifact| artifact.platform == current_platform)
        .ok_or_else(|| anyhow!("installed release lock has no artifact for this platform"))?;
    let executable_metadata =
        fs::symlink_metadata(&executable).context("running Registryctl metadata is unavailable")?;
    if !executable_metadata.file_type().is_file() || executable_metadata.file_type().is_symlink() {
        bail!("running Registryctl must be a regular non-symlink file");
    }
    let executable_bytes =
        fs::read(&executable).context("running Registryctl executable could not be read")?;
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(&executable_bytes)));
    if actual != artifact.sha256 {
        bail!("installed release lock does not bind the running Registryctl executable");
    }
    Ok(verified)
}

fn ensure_sibling_release_lock(path: &Path, executable: &Path) -> Result<()> {
    if path.file_name().and_then(|name| name.to_str()) != Some("registry-release-lock.v1.json") {
        bail!("installed release lock must use its fixed v1 filename");
    }
    let lock_parent = path
        .parent()
        .ok_or_else(|| anyhow!("installed release lock has no parent directory"))?
        .canonicalize()
        .context("installed release lock parent is unavailable")?;
    let executable_parent = executable
        .parent()
        .ok_or_else(|| anyhow!("running Registryctl has no parent directory"))?
        .canonicalize()
        .context("running Registryctl parent is unavailable")?;
    if lock_parent != executable_parent {
        bail!("installed release lock must be a sibling of the running Registryctl");
    }
    Ok(())
}

fn verify_release_lock_material(bytes: &[u8]) -> Result<VerifiedReleaseLockV1> {
    if bytes.len() > MAX_RELEASE_LOCK_BYTES {
        bail!("release lock exceeds its size bound");
    }
    let envelope_value =
        parse_json_strict(bytes).context("release lock is not strict duplicate-free JSON")?;
    let envelope: RegistryReleaseLockEnvelopeV1 = serde_json::from_value(envelope_value)
        .context("release lock envelope does not match the closed v1 schema")?;
    if envelope.schema_id != RELEASE_LOCK_SCHEMA_ID
        || envelope.schema_version != RELEASE_LOCK_SCHEMA_VERSION
    {
        bail!("release lock envelope schema is unsupported");
    }

    let signed_payload = STANDARD
        .decode(envelope.signed_payload.as_bytes())
        .context("release lock signed_payload is not canonical base64")?;
    if signed_payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
        bail!("release lock signed payload exceeds its size bound");
    }
    if STANDARD.encode(&signed_payload) != envelope.signed_payload {
        bail!("release lock signed_payload is not canonical base64");
    }

    let lock = parse_and_validate_signed_payload(&signed_payload)?;

    let bundle_json = serde_json::to_string(&envelope.sigstore_bundle)
        .context("release lock Sigstore bundle cannot be encoded")?;
    if bundle_json.len() > MAX_BUNDLE_BYTES {
        bail!("release lock Sigstore bundle exceeds its size bound");
    }
    let identity = format!(
        "https://github.com/{RELEASE_REPOSITORY}/{RELEASE_WORKFLOW}@{}",
        lock.release.source_ref
    );
    verify_sigstore_material(
        &signed_payload,
        &bundle_json,
        &identity,
        RELEASE_ISSUER,
        SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        Some(PRODUCTION_TRUST_ROOT_SHA256),
    )?;

    Ok(VerifiedReleaseLockV1 {
        signed_payload_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&signed_payload))),
        envelope: RetainedVerifiedEnvelope::new(bytes),
        lock,
    })
}

fn parse_and_validate_signed_payload(signed_payload: &[u8]) -> Result<RegistryReleaseLockV1> {
    if signed_payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
        bail!("release lock signed payload exceeds its size bound");
    }
    let payload_value = parse_json_strict(signed_payload)
        .context("release lock signed payload is not strict duplicate-free JSON")?;
    if canonicalize_json(&payload_value)
        .context("release lock signed payload cannot be canonicalized")?
        != signed_payload
    {
        bail!("release lock signed payload is not RFC 8785 canonical JSON");
    }
    let lock: RegistryReleaseLockV1 = serde_json::from_value(payload_value)
        .context("release lock signed payload does not match the closed v1 schema")?;
    lock.validate()?;
    Ok(lock)
}

fn release_major(version: &str) -> Result<u64> {
    version
        .split('.')
        .next()
        .ok_or_else(|| anyhow!("release lock product version has no major version"))?
        .parse()
        .context("release lock product major version is invalid")
}

fn current_registryctl_platform() -> Result<RegistryctlPlatformV1> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(RegistryctlPlatformV1::LinuxAmd64),
        ("linux", "aarch64") => Ok(RegistryctlPlatformV1::LinuxArm64),
        ("macos", "aarch64") => Ok(RegistryctlPlatformV1::MacosArm64),
        _ => bail!("this platform has no released Registryctl artifact"),
    }
}

fn verify_sigstore_material(
    artifact: &[u8],
    bundle_json: &str,
    identity: &str,
    issuer: &str,
    trust_root_json: &str,
    expected_trust_root_sha256: Option<&str>,
) -> Result<()> {
    if let Some(expected) = expected_trust_root_sha256 {
        let actual = hex::encode(Sha256::digest(trust_root_json.as_bytes()));
        if actual != expected {
            bail!("embedded Sigstore production trust root does not match its reviewed digest");
        }
    }
    let trusted_root = TrustedRoot::from_json(trust_root_json)
        .context("embedded Sigstore trusted root is invalid")?;
    let bundle = Bundle::from_json(bundle_json).context("Sigstore bundle is invalid")?;
    let policy = VerificationPolicy::default()
        .require_identity(identity)
        .require_issuer(issuer);
    verify(artifact, &bundle, &policy, &trusted_root)
        .map(|_| ())
        .context("release lock Sigstore verification failed")
}

impl RegistryReleaseLockV1 {
    fn validate(&self) -> Result<()> {
        if self.schema_id != RELEASE_LOCK_SCHEMA_ID
            || self.schema_version != RELEASE_LOCK_SCHEMA_VERSION
        {
            bail!("release lock signed payload schema is unsupported");
        }
        self.release.validate()?;
        validate_registryctl_artifacts(&self.registryctl_artifacts, &self.release.release_tag)?;
        self.images.validate()?;
        self.runtime.validate()?;
        self.supported_contracts.validate()?;
        validate_starters(&self.embedded_starters, &self.release.product_version)?;
        if self.minimum_compose_version != "2.35.0" {
            bail!("release lock minimum Compose version is unsupported");
        }
        if self.postgresql_major_version != 17 {
            bail!("release lock PostgreSQL major version is unsupported");
        }
        Ok(())
    }
}

impl LockedReleaseIdentityV1 {
    fn validate(&self) -> Result<()> {
        validate_release_version(&self.product_version)?;
        if self.release_tag != format!("v{}", self.product_version) {
            bail!("release lock tag does not match its product version");
        }
        if self.source_repository != RELEASE_REPOSITORY || self.source_workflow != RELEASE_WORKFLOW
        {
            bail!("release lock source repository or workflow is not trusted");
        }
        if self.source_ref != format!("refs/tags/{}", self.release_tag) {
            bail!("release lock source ref must be its immutable release tag");
        }
        validate_lower_hex(&self.manifest_source_ref, 40, "release manifest source ref")?;
        validate_lower_hex(&self.tag_target, 40, "release tag target")?;
        if self.manifest_source_ref != self.tag_target {
            bail!("release lock manifest source ref and tag target must be identical");
        }
        Ok(())
    }
}

impl LockedManagedImagesV1 {
    fn validate(&self) -> Result<()> {
        self.relay.validate("Relay")?;
        self.notary.validate("Notary")?;
        self.postgresql_state_plane
            .validate("PostgreSQL state plane")
    }
}

impl LockedOciImageV1 {
    fn validate(&self, label: &str) -> Result<()> {
        validate_image_identity(&self.identity)
            .with_context(|| format!("{label} image identity is invalid"))?;
        if self.platforms.len() != 1 || self.platforms[0].platform != OciPlatformV1::LinuxAmd64 {
            bail!("{label} image must approve exactly linux-amd64");
        }
        validate_digest(
            &self.platforms[0].manifest_digest,
            "image platform manifest digest",
        )?;
        Ok(())
    }
}

fn validate_image_identity(value: &str) -> Result<()> {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        bail!("image identity must use an explicit sha256 digest");
    };
    if repository.is_empty()
        || repository.chars().any(char::is_whitespace)
        || repository.contains('@')
    {
        bail!("image repository is invalid");
    }
    validate_lower_hex(digest, 64, "image digest")
}

impl LockedRuntimeRecipesV1 {
    fn validate(&self) -> Result<()> {
        self.relay_public.validate("Relay public")?;
        self.relay_consultation.validate("Relay consultation")?;
        self.notary.validate("Notary")?;
        self.postgresql_state_plane
            .validate("PostgreSQL state plane")?;
        validate_operator_files(self)?;
        Ok(())
    }
}

impl LockedProductRecipeV1 {
    fn validate(&self, label: &str) -> Result<()> {
        for (action, recipe) in [
            ("serve", &self.serve),
            ("prepare_state_store", &self.prepare_state_store),
            ("initialize_state", &self.initialize_state),
            ("preview_state", &self.preview_state),
            ("accept_state", &self.accept_state),
            ("verify_state", &self.verify_state),
            (
                "development_prepare_state_store",
                &self.development_prepare_state_store,
            ),
            (
                "development_initialize_state",
                &self.development_initialize_state,
            ),
            ("development_serve", &self.development_serve),
        ] {
            recipe.validate(&format!("{label} {action}"))?;
        }
        validate_command(&self.health_probe, &format!("{label} health_probe"))?;
        validate_product_recipe_commands(self, label)?;
        validate_product_recipe_shape(self, label)
    }
}

impl LockedPostgresqlRecipeV1 {
    fn validate(&self, label: &str) -> Result<()> {
        self.serve.validate(&format!("{label} serve"))?;
        self.bootstrap
            .validate_postgresql_bootstrap(&format!("{label} bootstrap"))?;
        validate_command(&self.health_probe, &format!("{label} health probe"))?;
        validate_postgresql_recipe_commands(self)?;
        if self.server_environment
            != [
                "POSTGRES_USER=registry_stack_bootstrap",
                "POSTGRES_DB=postgres",
                "POSTGRES_PASSWORD_FILE=/run/secrets/postgresql-admin-password",
                "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust",
            ]
        {
            bail!("PostgreSQL state plane server environment is unsupported");
        }
        if self.hardening.user != "999:999"
            || !self.hardening.read_only_root_filesystem
            || self.hardening.cap_drop != ["ALL"]
            || self.hardening.security_opt != ["no-new-privileges:true"]
            || self.hardening.tmpfs != ["/tmp", "/var/run/postgresql:uid=999,gid=999,mode=0750"]
        {
            bail!("PostgreSQL state plane hardening is unsupported");
        }
        validate_action_shape(
            &self.serve,
            &[LockedMountSourceV1::PostgresqlData],
            &[],
            &[
                "postgresql-admin-password",
                "postgresql-tls-certificate",
                "postgresql-tls-private-key",
            ],
            "PostgreSQL state plane serve",
        )?;
        validate_action_shape(
            &self.bootstrap,
            &[],
            &["postgresql-bootstrap-environment"],
            &["postgresql-admin-password", "postgresql-tls-certificate"],
            "PostgreSQL state plane bootstrap",
        )?;
        Ok(())
    }
}

impl LockedRuntimeActionV1 {
    fn validate(&self, label: &str) -> Result<()> {
        validate_command(&self.command, &format!("{label} command"))?;
        self.validate_inputs(label)
    }

    fn validate_postgresql_bootstrap(&self, label: &str) -> Result<()> {
        validate_multiline_command(&self.command, &format!("{label} command"))?;
        self.validate_inputs(label)
    }

    fn validate_inputs(&self, label: &str) -> Result<()> {
        if self.mounts.len() > 8 || self.environment_files.len() > 2 || self.secret_files.len() > 8
        {
            bail!("{label} input projection exceeds its closed bound");
        }
        let mut sources = BTreeSet::new();
        for mount in &self.mounts {
            if !sources.insert(mount.source) {
                bail!("{label} repeats a runtime mount source");
            }
            let (target, read_only) = match mount.source {
                LockedMountSourceV1::Bundle => (PRODUCT_BUNDLE_TARGET, true),
                LockedMountSourceV1::Anchor => (PRODUCT_ANCHOR_TARGET, true),
                LockedMountSourceV1::AntiRollbackState => {
                    if mount.target != PRODUCT_STATE_TARGET {
                        bail!("{label} contains an unsupported runtime mount");
                    }
                    continue;
                }
                LockedMountSourceV1::Audit => (PRODUCT_AUDIT_TARGET, false),
                LockedMountSourceV1::PostgresqlData => (POSTGRESQL_DATA_TARGET, false),
            };
            if mount.target != target || mount.read_only != read_only {
                bail!("{label} contains an unsupported runtime mount");
            }
        }
        let mut environment_files = BTreeSet::new();
        for file_id in &self.environment_files {
            validate_runtime_id(file_id, label)?;
            if !environment_files.insert(file_id) {
                bail!("{label} repeats an environment file");
            }
        }
        let mut secret_targets = BTreeSet::new();
        for projection in &self.secret_files {
            validate_runtime_id(&projection.file_id, label)?;
            if !projection.target.starts_with("/run/secrets/")
                || projection.target.contains("..")
                || projection.mode != "0400"
                || !matches!(projection.uid.as_str(), "65532" | "999")
                || projection.gid != projection.uid
                || !secret_targets.insert(projection.target.as_str())
            {
                bail!("{label} contains an unsupported secret-file projection");
            }
        }
        Ok(())
    }
}

fn validate_product_recipe_shape(recipe: &LockedProductRecipeV1, label: &str) -> Result<()> {
    let id = match label {
        "Relay public" => "relay-public",
        "Relay consultation" => "relay-consultation",
        "Notary" => "notary",
        _ => bail!("product runtime recipe label is unsupported"),
    };
    let environment = format!("{id}-environment");
    let preparation_secrets = if id == "relay-public" {
        &[][..]
    } else {
        &["postgresql-tls-certificate"][..]
    };
    validate_action_shape(
        &recipe.prepare_state_store,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        preparation_secrets,
        &format!("{label} prepare_state_store"),
    )?;
    let initialization_secrets = if id == "relay-consultation" {
        &["postgresql-tls-certificate"][..]
    } else {
        &[][..]
    };
    validate_action_shape(
        &recipe.initialize_state,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        initialization_secrets,
        &format!("{label} initialize_state"),
    )?;
    validate_mount_access(
        &recipe.initialize_state,
        LockedMountSourceV1::AntiRollbackState,
        false,
        &format!("{label} initialize_state"),
    )?;
    let serve_secrets: &[&str] = match id {
        "relay-public" => &[],
        "relay-consultation" => &["postgresql-tls-certificate"],
        "notary" => &[
            "postgresql-tls-certificate",
            "notary-relay-workload-credential",
            "notary-signing-key",
        ],
        _ => unreachable!(),
    };
    validate_action_shape(
        &recipe.preview_state,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
        ],
        &[],
        &[],
        &format!("{label} preview_state"),
    )?;
    validate_mount_access(
        &recipe.preview_state,
        LockedMountSourceV1::AntiRollbackState,
        true,
        &format!("{label} preview_state"),
    )?;
    validate_action_shape(
        &recipe.accept_state,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        &[],
        &format!("{label} accept_state"),
    )?;
    validate_action_shape(
        &recipe.verify_state,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
        ],
        &[],
        &[],
        &format!("{label} verify_state"),
    )?;
    validate_action_shape(
        &recipe.serve,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        serve_secrets,
        &format!("{label} serve"),
    )?;
    for (name, action, read_only) in [
        ("serve", &recipe.serve, true),
        ("accept_state", &recipe.accept_state, false),
        ("verify_state", &recipe.verify_state, true),
    ] {
        validate_mount_access(
            action,
            LockedMountSourceV1::AntiRollbackState,
            read_only,
            &format!("{label} {name}"),
        )?;
    }
    validate_action_shape(
        &recipe.development_prepare_state_store,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        if id == "relay-public" {
            &[]
        } else {
            &["postgresql-tls-certificate"]
        },
        &format!("{label} development_prepare_state_store"),
    )?;
    validate_action_shape(
        &recipe.development_initialize_state,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        if id == "relay-public" {
            &[]
        } else {
            &["postgresql-tls-certificate"]
        },
        &format!("{label} development_initialize_state"),
    )?;
    validate_mount_access(
        &recipe.development_initialize_state,
        LockedMountSourceV1::AntiRollbackState,
        false,
        &format!("{label} development_initialize_state"),
    )?;
    validate_action_shape(
        &recipe.development_serve,
        &[
            LockedMountSourceV1::Bundle,
            LockedMountSourceV1::Anchor,
            LockedMountSourceV1::AntiRollbackState,
            LockedMountSourceV1::Audit,
        ],
        &[environment.as_str()],
        serve_secrets,
        &format!("{label} development_serve"),
    )?;
    validate_mount_access(
        &recipe.development_serve,
        LockedMountSourceV1::AntiRollbackState,
        true,
        &format!("{label} development_serve"),
    )?;
    Ok(())
}

fn validate_mount_access(
    action: &LockedRuntimeActionV1,
    source: LockedMountSourceV1,
    read_only: bool,
    label: &str,
) -> Result<()> {
    if action
        .mounts
        .iter()
        .find(|mount| mount.source == source)
        .is_none_or(|mount| mount.read_only != read_only)
    {
        bail!("{label} has unsupported runtime mount access");
    }
    Ok(())
}

fn validate_product_recipe_commands(recipe: &LockedProductRecipeV1, label: &str) -> Result<()> {
    let (product, lane) = match label {
        "Relay public" => ("registry-relay", Some("relay-public")),
        "Relay consultation" => ("registry-relay", Some("relay-consultation")),
        "Notary" => ("registry-notary", None),
        _ => bail!("product runtime recipe label is unsupported"),
    };
    for (name, action) in [
        ("serve", &recipe.serve),
        ("prepare_state_store", &recipe.prepare_state_store),
        ("initialize_state", &recipe.initialize_state),
        ("preview_state", &recipe.preview_state),
        ("accept_state", &recipe.accept_state),
        ("verify_state", &recipe.verify_state),
    ] {
        let expected = if let Some(lane) = lane {
            vec!["product-action", lane, name]
        } else {
            vec!["product-action", name]
        };
        validate_exact_command(
            &action.command,
            &expected,
            &format!("{label} {name} command"),
        )?;
    }
    for (name, action) in [
        (
            "prepare_state_store",
            &recipe.development_prepare_state_store,
        ),
        ("initialize_state", &recipe.development_initialize_state),
        ("serve", &recipe.development_serve),
    ] {
        let expected = if let Some(lane) = lane {
            vec!["development-action", lane, name]
        } else {
            vec!["development-action", name]
        };
        validate_exact_command(
            &action.command,
            &expected,
            &format!("{label} development {name} command"),
        )?;
    }
    let health_binary = format!("/usr/local/bin/{product}");
    let health_url = if product == "registry-notary" {
        "http://127.0.0.1:8081/ready"
    } else {
        "http://127.0.0.1:8080/ready"
    };
    validate_exact_command(
        &recipe.health_probe,
        &[
            "CMD",
            health_binary.as_str(),
            "healthcheck",
            "--url",
            health_url,
        ],
        &format!("{label} health probe"),
    )
}

fn validate_postgresql_recipe_commands(recipe: &LockedPostgresqlRecipeV1) -> Result<()> {
    validate_exact_command(
        &recipe.serve.command,
        &[
            "postgres",
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=/run/secrets/postgresql-tls.crt",
            "-c",
            "ssl_key_file=/run/secrets/postgresql-tls.key",
            "-c",
            "ssl_min_protocol_version=TLSv1.2",
            "-c",
            "password_encryption=scram-sha-256",
            "-c",
            "listen_addresses=0.0.0.0",
        ],
        "PostgreSQL state plane serve command",
    )?;
    validate_exact_command(
        &recipe.health_probe,
        &[
            "CMD",
            "pg_isready",
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
            "--username",
            "registry_stack_bootstrap",
            "--dbname",
            "postgres",
        ],
        "PostgreSQL state plane health probe",
    )?;
    if recipe.bootstrap.command.len() != 3
        || recipe.bootstrap.command[0] != "/bin/bash"
        || recipe.bootstrap.command[1] != "-ceu"
        || hex::encode(Sha256::digest(recipe.bootstrap.command[2].as_bytes()))
            != POSTGRESQL_BOOTSTRAP_SCRIPT_SHA256
    {
        bail!("PostgreSQL state plane bootstrap command is not the exact reviewed recipe");
    }
    Ok(())
}

fn validate_action_shape(
    action: &LockedRuntimeActionV1,
    mounts: &[LockedMountSourceV1],
    environment_files: &[&str],
    secret_files: &[&str],
    label: &str,
) -> Result<()> {
    if action
        .mounts
        .iter()
        .map(|mount| mount.source)
        .collect::<Vec<_>>()
        != mounts
        || action
            .environment_files
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != environment_files
        || action
            .secret_files
            .iter()
            .map(|projection| projection.file_id.as_str())
            .collect::<Vec<_>>()
            != secret_files
    {
        bail!("{label} input projection is not the supported closed recipe");
    }
    Ok(())
}

fn validate_operator_files(runtime: &LockedRuntimeRecipesV1) -> Result<()> {
    let mut files = BTreeSet::new();
    for file in &runtime.operator_files {
        validate_runtime_id(&file.id, "operator file")?;
        if !files.insert(file.id.clone())
            || file.mode != "0600"
            || file.allowed_owners.is_empty()
            || file
                .allowed_owners
                .iter()
                .any(|owner| !matches!(owner.as_str(), "root:root" | "65532:65532" | "999:999"))
        {
            bail!("release lock operator-file inventory is invalid");
        }
        let keys = file
            .required_keys
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if keys.len() != file.required_keys.len()
            || file
                .required_keys
                .iter()
                .any(|key| !valid_environment_key(key))
            || (file.format != LockedOperatorFileFormatV1::Dotenv && !keys.is_empty())
        {
            bail!("release lock operator-file schema is invalid");
        }
        validate_operator_file_contract(file)?;
    }
    let mut referenced = BTreeSet::new();
    let mut collect = |action: &LockedRuntimeActionV1| {
        referenced.extend(action.environment_files.iter().cloned());
        referenced.extend(
            action
                .secret_files
                .iter()
                .map(|projection| projection.file_id.clone()),
        );
    };
    for product in [
        &runtime.relay_public,
        &runtime.relay_consultation,
        &runtime.notary,
    ] {
        collect(&product.prepare_state_store);
        collect(&product.initialize_state);
        collect(&product.preview_state);
        collect(&product.accept_state);
        collect(&product.verify_state);
        collect(&product.serve);
        collect(&product.development_prepare_state_store);
        collect(&product.development_initialize_state);
        collect(&product.development_serve);
    }
    collect(&runtime.postgresql_state_plane.serve);
    collect(&runtime.postgresql_state_plane.bootstrap);
    if files != referenced {
        bail!("release lock operator-file inventory does not match runtime consumers");
    }
    Ok(())
}

fn validate_operator_file_contract(file: &LockedOperatorFileV1) -> Result<()> {
    let (format, allowed_owners, required_keys): (LockedOperatorFileFormatV1, &[&str], &[&str]) =
        match file.id.as_str() {
            "relay-public-environment"
            | "relay-consultation-environment"
            | "notary-environment" => (
                LockedOperatorFileFormatV1::Dotenv,
                &["root:root", "65532:65532"],
                &[],
            ),
            "notary-signing-key" => (
                LockedOperatorFileFormatV1::JsonWebKey,
                &["root:root", "65532:65532"],
                &[],
            ),
            "notary-relay-workload-credential" => (
                LockedOperatorFileFormatV1::CompactJwt,
                &["root:root", "65532:65532"],
                &[],
            ),
            "postgresql-tls-certificate" => (
                LockedOperatorFileFormatV1::PemCertificate,
                &["root:root", "65532:65532", "999:999"],
                &[],
            ),
            "postgresql-tls-private-key" => (
                LockedOperatorFileFormatV1::PemPrivateKey,
                &["root:root", "999:999"],
                &[],
            ),
            "postgresql-admin-password" => (
                LockedOperatorFileFormatV1::Opaque,
                &["root:root", "999:999"],
                &[],
            ),
            "postgresql-bootstrap-environment" => (
                LockedOperatorFileFormatV1::Dotenv,
                &["root:root", "999:999"],
                &POSTGRESQL_BOOTSTRAP_KEYS,
            ),
            _ => bail!("release lock operator-file inventory is unsupported"),
        };
    if file.format != format
        || !file
            .allowed_owners
            .iter()
            .map(String::as_str)
            .eq(allowed_owners.iter().copied())
        || !file
            .required_keys
            .iter()
            .map(String::as_str)
            .eq(required_keys.iter().copied())
    {
        bail!("release lock operator-file contract is unsupported");
    }
    Ok(())
}

fn validate_runtime_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("{label} contains an invalid closed identifier");
    }
    Ok(())
}

fn valid_environment_key(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

impl SupportedContractsV1 {
    fn validate(&self) -> Result<()> {
        let actual = [
            self.config_bundle_schema.as_str(),
            self.config_signature_schema.as_str(),
            self.trust_anchor_schema.as_str(),
            self.anchor_transition_schema.as_str(),
            self.relay_config_schema.as_str(),
            self.notary_config_schema.as_str(),
        ];
        let expected = [
            CONFIG_BUNDLE_SCHEMA,
            CONFIG_SIGNATURE_SCHEMA,
            TRUST_ANCHOR_SCHEMA,
            ANCHOR_TRANSITION_SCHEMA,
            RELAY_CONFIG_SCHEMA,
            NOTARY_CONFIG_SCHEMA,
        ];
        if actual != expected {
            bail!("release lock supported-contract roster is unsupported");
        }
        Ok(())
    }
}

fn validate_registryctl_artifacts(
    artifacts: &[LockedRegistryctlArtifactV1],
    tag: &str,
) -> Result<()> {
    let expected = BTreeSet::from([
        RegistryctlPlatformV1::LinuxAmd64,
        RegistryctlPlatformV1::LinuxArm64,
        RegistryctlPlatformV1::MacosArm64,
    ]);
    let mut actual = BTreeSet::new();
    for artifact in artifacts {
        if !actual.insert(artifact.platform) {
            bail!("release lock repeats a registryctl platform artifact");
        }
        let filename = format!("registryctl-{tag}-{}", artifact.platform.asset_suffix());
        if artifact.filename != filename {
            bail!("release lock registryctl artifact name does not match its platform");
        }
        validate_digest(&artifact.sha256, "registryctl artifact digest")?;
    }
    if actual != expected {
        bail!("release lock registryctl artifact roster is incomplete");
    }
    Ok(())
}

fn validate_starters(starters: &[LockedEmbeddedStarterV1], product_version: &str) -> Result<()> {
    let expected = BTreeSet::from(["http", "spreadsheet"]);
    let mut actual = BTreeSet::new();
    for starter in starters {
        if !actual.insert(starter.id.as_str()) {
            bail!("release lock repeats an embedded starter");
        }
        if starter.release != product_version {
            bail!("release lock starter release does not match the product version");
        }
        validate_digest(&starter.content_digest, "embedded starter content digest")?;
    }
    if actual != expected {
        bail!("release lock embedded-starter roster is incomplete");
    }
    Ok(())
}

fn validate_release_version(value: &str) -> Result<()> {
    let (core, prerelease) = value
        .split_once('-')
        .map_or((value, None), |(core, prerelease)| (core, Some(prerelease)));
    let components = core.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
        || prerelease.is_some_and(|prerelease| {
            prerelease.is_empty()
                || prerelease.split('.').any(|identifier| {
                    identifier.is_empty()
                        || (identifier.bytes().all(|byte| byte.is_ascii_digit())
                            && identifier.len() > 1
                            && identifier.starts_with('0'))
                })
        })
    {
        bail!("release lock product version is not canonical semver");
    }
    Ok(())
}

fn validate_command(command: &[String], label: &str) -> Result<()> {
    validate_command_controls(command, label, false)
}

fn validate_multiline_command(command: &[String], label: &str) -> Result<()> {
    validate_command_controls(command, label, true)
}

fn validate_command_controls(command: &[String], label: &str, allow_lf: bool) -> Result<()> {
    if command.is_empty()
        || command.len() > 32
        || command.iter().any(|part| {
            part.is_empty()
                || part.len() > 32 * 1024
                || part
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && (!allow_lf || byte != b'\n'))
        })
    {
        bail!("{label} is not a bounded closed command");
    }
    Ok(())
}

fn validate_exact_command(command: &[String], expected: &[&str], label: &str) -> Result<()> {
    if command
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        bail!("{label} is not the exact supported command");
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{label} must use sha256:<64 lowercase hex>");
    };
    validate_lower_hex(hex, 64, label)
}

fn validate_lower_hex(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not canonical lowercase hex");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn verify_sigstore_fixture(
    artifact: &[u8],
    bundle_json: &str,
    identity: &str,
    issuer: &str,
    trust_root_json: &str,
) -> Result<()> {
    verify_sigstore_material(
        artifact,
        bundle_json,
        identity,
        issuer,
        trust_root_json,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_verify::trust_root::SIGSTORE_STAGING_TRUSTED_ROOT;

    const COSIGN_V3_ARTIFACT: &[u8] =
        include_bytes!("../tests/fixtures/release-lock/cosign-3.0.4-checksums.txt");
    const COSIGN_V3_BUNDLE: &str =
        include_str!("../tests/fixtures/release-lock/cosign-3.0.4-checksums.sigstore.json");
    const COSIGN_V3_IDENTITY: &str = "keyless@projectsigstore.iam.gserviceaccount.com";
    const COSIGN_V3_ISSUER: &str = "https://accounts.google.com";

    fn command_action(parts: &[&str]) -> LockedRuntimeActionV1 {
        LockedRuntimeActionV1 {
            command: parts.iter().map(|part| (*part).to_string()).collect(),
            mounts: Vec::new(),
            environment_files: Vec::new(),
            secret_files: Vec::new(),
        }
    }

    fn command_recipe(product: &str, lane: Option<&str>) -> LockedProductRecipeV1 {
        let health_url = if product == "registry-notary" {
            "http://127.0.0.1:8081/ready"
        } else {
            "http://127.0.0.1:8080/ready"
        };
        let action = |name: &str| {
            let mut command = vec!["product-action"];
            if let Some(lane) = lane {
                command.push(lane);
            }
            command.push(name);
            command_action(&command)
        };
        let development_action = |name: &str| {
            let mut command = vec!["development-action"];
            if let Some(lane) = lane {
                command.push(lane);
            }
            command.push(name);
            command_action(&command)
        };
        LockedProductRecipeV1 {
            serve: action("serve"),
            prepare_state_store: action("prepare_state_store"),
            initialize_state: action("initialize_state"),
            preview_state: action("preview_state"),
            accept_state: action("accept_state"),
            verify_state: action("verify_state"),
            development_prepare_state_store: development_action("prepare_state_store"),
            development_initialize_state: development_action("initialize_state"),
            development_serve: development_action("serve"),
            health_probe: vec![
                "CMD".to_string(),
                format!("/usr/local/bin/{product}"),
                "healthcheck".to_string(),
                "--url".to_string(),
                health_url.to_string(),
            ],
        }
    }

    #[test]
    fn closed_product_action_slots_reject_swapped_commands() {
        for (label, product, lane) in [
            ("Relay public", "registry-relay", Some("relay-public")),
            (
                "Relay consultation",
                "registry-relay",
                Some("relay-consultation"),
            ),
            ("Notary", "registry-notary", None),
        ] {
            let recipe = command_recipe(product, lane);
            assert_eq!(
                recipe.health_probe,
                vec![
                    "CMD".to_string(),
                    format!("/usr/local/bin/{product}"),
                    "healthcheck".to_string(),
                    "--url".to_string(),
                    if product == "registry-notary" {
                        "http://127.0.0.1:8081/ready".to_string()
                    } else {
                        "http://127.0.0.1:8080/ready".to_string()
                    },
                ]
            );
            validate_product_recipe_commands(&recipe, label)
                .expect("the release generator's exact action mapping is accepted");

            for slot in [
                "serve",
                "prepare_state_store",
                "initialize_state",
                "preview_state",
                "accept_state",
                "verify_state",
            ] {
                let mut swapped = recipe.clone();
                let action = match slot {
                    "serve" => &mut swapped.serve,
                    "prepare_state_store" => &mut swapped.prepare_state_store,
                    "initialize_state" => &mut swapped.initialize_state,
                    "preview_state" => &mut swapped.preview_state,
                    "accept_state" => &mut swapped.accept_state,
                    "verify_state" => &mut swapped.verify_state,
                    _ => unreachable!(),
                };
                *action
                    .command
                    .last_mut()
                    .expect("product action command has an action name") = if slot == "serve" {
                    "initialize_state".to_string()
                } else {
                    "serve".to_string()
                };
                let error = validate_product_recipe_commands(&swapped, label)
                    .expect_err("an action command cannot move to another closed slot");
                assert!(
                    error.to_string().contains("exact supported command"),
                    "{label} {slot}: {error:#}"
                );
            }
            for slot in [
                "development_prepare_state_store",
                "development_initialize_state",
                "development_serve",
            ] {
                let mut swapped = recipe.clone();
                let action = match slot {
                    "development_prepare_state_store" => {
                        &mut swapped.development_prepare_state_store
                    }
                    "development_initialize_state" => &mut swapped.development_initialize_state,
                    "development_serve" => &mut swapped.development_serve,
                    _ => unreachable!(),
                };
                action.command[0] = "product-action".to_string();
                assert!(
                    validate_product_recipe_commands(&swapped, label).is_err(),
                    "{label} {slot} accepted the governed action namespace"
                );
            }

            let mut wrong_health = recipe;
            wrong_health.health_probe[2] = "serve".to_string();
            assert!(validate_product_recipe_commands(&wrong_health, label).is_err());
            let mut wrong_health_url = command_recipe(product, lane);
            wrong_health_url.health_probe[4] = "http://127.0.0.1:8080/healthz".to_string();
            assert!(validate_product_recipe_commands(&wrong_health_url, label).is_err());
        }
    }

    #[test]
    fn reviewed_trust_root_digest_remains_pinned() {
        assert_eq!(
            hex::encode(Sha256::digest(SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes())),
            PRODUCTION_TRUST_ROOT_SHA256
        );
    }

    #[test]
    fn version_validation_rejects_mutable_or_ambiguous_forms() {
        for invalid in [
            "1",
            "1.0",
            "01.0.0",
            "1.0.0+build",
            "1.0.0/main",
            "1.0.0-",
            "1.0.0-rc..1",
            "1.0.0-rc.01",
        ] {
            assert!(validate_release_version(invalid).is_err(), "{invalid}");
        }
        for valid in ["1.0.0", "1.0.0-rc.1"] {
            assert!(validate_release_version(valid).is_ok(), "{valid}");
        }
    }

    #[test]
    fn release_identity_uses_one_exact_candidate_and_tag_revision() {
        let mut identity = LockedReleaseIdentityV1 {
            product_version: "1.0.0".to_string(),
            release_tag: "v1.0.0".to_string(),
            source_repository: RELEASE_REPOSITORY.to_string(),
            source_workflow: RELEASE_WORKFLOW.to_string(),
            source_ref: "refs/tags/v1.0.0".to_string(),
            manifest_source_ref: "a".repeat(40),
            tag_target: "a".repeat(40),
        };
        identity
            .validate()
            .expect("one exact candidate and tag revision is accepted");

        identity.tag_target = "b".repeat(40);
        let error = identity
            .validate()
            .expect_err("a distinct tag target must be rejected");
        assert!(error.to_string().contains("must be identical"), "{error:#}");
    }

    #[test]
    fn signed_lock_starter_roster_is_the_closed_public_pair() {
        let starter = |id: &str| LockedEmbeddedStarterV1 {
            id: id.to_string(),
            release: "1.0.0".to_string(),
            content_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let mut starters = vec![starter("http"), starter("spreadsheet")];
        validate_starters(&starters, "1.0.0").expect("the closed 1.0 starter roster is accepted");

        for internal_fixture in ["dhis2-tracker", "fhir-r4", "opencrvs-dci", "snapshot"] {
            starters.push(starter(internal_fixture));
            assert!(validate_starters(&starters, "1.0.0").is_err());
            starters.pop();
        }
        starters.pop();
        assert!(validate_starters(&starters, "1.0.0").is_err());
        assert!(validate_starters(&[], "1.0.0").is_err());
    }

    #[test]
    fn operator_file_contract_uses_one_semantically_parsed_dotenv_per_lane() {
        let mut environment = LockedOperatorFileV1 {
            id: "relay-consultation-environment".to_string(),
            format: LockedOperatorFileFormatV1::Dotenv,
            mode: "0600".to_string(),
            allowed_owners: vec!["root:root".to_string(), "65532:65532".to_string()],
            required_keys: Vec::new(),
        };
        validate_operator_file_contract(&environment)
            .expect("the lane-owned product environment is accepted");

        environment.id = "relay-consultation-serve-environment".to_string();
        assert!(validate_operator_file_contract(&environment).is_err());
        environment.id = "relay-consultation-environment".to_string();
        environment.required_keys.push("DATABASE_URL".to_string());
        assert!(validate_operator_file_contract(&environment).is_err());

        let mut notary_signing_key = LockedOperatorFileV1 {
            id: "notary-signing-key".to_string(),
            format: LockedOperatorFileFormatV1::JsonWebKey,
            mode: "0600".to_string(),
            allowed_owners: vec!["root:root".to_string(), "65532:65532".to_string()],
            required_keys: Vec::new(),
        };
        validate_operator_file_contract(&notary_signing_key)
            .expect("the Notary-only signing-key projection is accepted");
        notary_signing_key
            .allowed_owners
            .push("999:999".to_string());
        assert!(validate_operator_file_contract(&notary_signing_key).is_err());

        let listener_certificate = LockedOperatorFileV1 {
            id: "notary-tls-certificate".to_string(),
            format: LockedOperatorFileFormatV1::PemCertificate,
            mode: "0600".to_string(),
            allowed_owners: vec!["root:root".to_string(), "65532:65532".to_string()],
            required_keys: Vec::new(),
        };
        assert!(validate_operator_file_contract(&listener_certificate).is_err());
    }

    #[test]
    fn image_identity_requires_digest_and_platform_closure() {
        let mut image = LockedOciImageV1 {
            identity: "ghcr.io/registrystack/registry-relay:latest".to_string(),
            platforms: vec![LockedOciPlatformV1 {
                platform: OciPlatformV1::LinuxAmd64,
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
            }],
        };
        assert!(image.validate("Relay").is_err());

        image.identity = format!(
            "ghcr.io/registrystack/registry-relay@sha256:{}",
            "b".repeat(64)
        );
        image.platforms[0].platform = OciPlatformV1::LinuxArm64;
        assert!(image.validate("Relay").is_err());

        image.platforms[0].platform = OciPlatformV1::LinuxAmd64;
        image.platforms.push(image.platforms[0].clone());
        assert!(image.validate("Relay").is_err());

        image.platforms.truncate(1);
        image
            .validate("Relay")
            .expect("one exact linux-amd64 platform is accepted");
    }

    #[test]
    fn installed_lock_path_must_be_the_fixed_sibling() {
        let temporary = tempfile::tempdir().unwrap();
        let bin = temporary.path().join("bin");
        let other = temporary.path().join("other");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&other).unwrap();
        let executable = bin.join("registryctl");

        ensure_sibling_release_lock(&bin.join("registry-release-lock.v1.json"), &executable)
            .unwrap();
        assert!(ensure_sibling_release_lock(&bin.join("other.json"), &executable).is_err());
        assert!(ensure_sibling_release_lock(
            &other.join("registry-release-lock.v1.json"),
            &executable
        )
        .is_err());
    }

    #[test]
    fn retained_envelope_preserves_exact_bytes_and_binds_tampering() {
        let original = b"{ \"schema_id\": \"example\" }\n";
        let retained = RetainedVerifiedEnvelope::new(original);
        assert_eq!(original, retained.bytes.as_ref());
        assert_eq!(
            retained.sha256,
            format!("sha256:{}", hex::encode(Sha256::digest(original)))
        );

        let mut tampered = original.to_vec();
        tampered[2] = b'X';
        assert_ne!(
            retained.sha256,
            RetainedVerifiedEnvelope::new(&tampered).sha256
        );
    }

    #[test]
    fn verifies_actual_cosign_v3_bundle_fully_offline() {
        verify_sigstore_fixture(
            COSIGN_V3_ARTIFACT,
            COSIGN_V3_BUNDLE,
            COSIGN_V3_IDENTITY,
            COSIGN_V3_ISSUER,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .expect("actual Cosign v3 bundle verifies against embedded production material");
    }

    #[test]
    fn rejects_tampered_artifact_and_wrong_identity() {
        let mut tampered = COSIGN_V3_ARTIFACT.to_vec();
        tampered[0] ^= 1;
        assert!(verify_sigstore_fixture(
            &tampered,
            COSIGN_V3_BUNDLE,
            COSIGN_V3_IDENTITY,
            COSIGN_V3_ISSUER,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .is_err());
        assert!(verify_sigstore_fixture(
            COSIGN_V3_ARTIFACT,
            COSIGN_V3_BUNDLE,
            "https://github.com/registrystack/other/.github/workflows/release.yml@refs/tags/v1.0.0",
            COSIGN_V3_ISSUER,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_root_and_corrupt_log_proof() {
        assert!(verify_sigstore_fixture(
            COSIGN_V3_ARTIFACT,
            COSIGN_V3_BUNDLE,
            COSIGN_V3_IDENTITY,
            COSIGN_V3_ISSUER,
            SIGSTORE_STAGING_TRUSTED_ROOT,
        )
        .is_err());

        let mut bundle: Value = serde_json::from_str(COSIGN_V3_BUNDLE).expect("fixture JSON");
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] =
            Value::String(STANDARD.encode([0_u8; 32]));
        let corrupt = serde_json::to_string(&bundle).expect("corrupt bundle serializes");
        assert!(verify_sigstore_fixture(
            COSIGN_V3_ARTIFACT,
            &corrupt,
            COSIGN_V3_IDENTITY,
            COSIGN_V3_ISSUER,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .is_err());
    }

    #[test]
    fn rejects_unproved_time_outside_the_certificate_window() {
        let mut bundle: Value = serde_json::from_str(COSIGN_V3_BUNDLE).expect("fixture JSON");
        bundle["verificationMaterial"]["tlogEntries"][0]["integratedTime"] =
            Value::String("4102444800".to_string());
        let corrupt = serde_json::to_string(&bundle).expect("corrupt bundle serializes");
        assert!(verify_sigstore_fixture(
            COSIGN_V3_ARTIFACT,
            &corrupt,
            COSIGN_V3_IDENTITY,
            COSIGN_V3_ISSUER,
            SIGSTORE_PRODUCTION_TRUSTED_ROOT,
        )
        .is_err());
    }
}
