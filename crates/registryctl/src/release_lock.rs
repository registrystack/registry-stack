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
    pub source_sha: String,
}

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciPlatformV1 {
    LinuxAmd64,
    LinuxArm64,
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
    pub private_namespace_holder: LockedOciImageV1,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedProductRecipeV1 {
    pub serve: Vec<String>,
    pub prepare_state_store: Vec<String>,
    pub initialize_state: Vec<String>,
    pub verify_state: Vec<String>,
    pub health_probe: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSupportingRecipeV1 {
    pub command: Vec<String>,
    pub health_probe: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRuntimeRecipesV1 {
    pub relay_public: LockedProductRecipeV1,
    pub relay_consultation: LockedProductRecipeV1,
    pub notary: LockedProductRecipeV1,
    pub postgresql_state_plane: LockedSupportingRecipeV1,
    pub private_namespace_holder: LockedSupportingRecipeV1,
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
    notary: String,
    postgresql_state_plane: String,
    private_namespace_holder: String,
}

impl VerifiedManagedImagesV1 {
    pub fn relay(&self) -> &str {
        &self.relay
    }

    pub fn notary(&self) -> &str {
        &self.notary
    }

    pub fn postgresql_state_plane(&self) -> &str {
        &self.postgresql_state_plane
    }

    pub fn private_namespace_holder(&self) -> &str {
        &self.private_namespace_holder
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedProductRuntimeV1 {
    serve: Vec<String>,
    prepare_state_store: Vec<String>,
    initialize_state: Vec<String>,
    verify_state: Vec<String>,
    health_probe: Vec<String>,
}

impl VerifiedProductRuntimeV1 {
    pub fn serve(&self) -> &[String] {
        &self.serve
    }

    pub fn prepare_state_store(&self) -> &[String] {
        &self.prepare_state_store
    }

    pub fn initialize_state(&self) -> &[String] {
        &self.initialize_state
    }

    pub fn verify_state(&self) -> &[String] {
        &self.verify_state
    }

    pub fn health_probe(&self) -> &[String] {
        &self.health_probe
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedSupportingRuntimeV1 {
    command: Vec<String>,
    health_probe: Vec<String>,
}

impl VerifiedSupportingRuntimeV1 {
    pub fn command(&self) -> &[String] {
        &self.command
    }

    pub fn health_probe(&self) -> &[String] {
        &self.health_probe
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedRuntimeMappingV1 {
    relay_public: VerifiedProductRuntimeV1,
    relay_consultation: VerifiedProductRuntimeV1,
    notary: VerifiedProductRuntimeV1,
    postgresql_state_plane: VerifiedSupportingRuntimeV1,
    private_namespace_holder: VerifiedSupportingRuntimeV1,
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

    pub fn postgresql_state_plane(&self) -> &VerifiedSupportingRuntimeV1 {
        &self.postgresql_state_plane
    }

    pub fn private_namespace_holder(&self) -> &VerifiedSupportingRuntimeV1 {
        &self.private_namespace_holder
    }
}

impl VerifiedReleaseLockV1 {
    pub fn product_version(&self) -> &str {
        &self.lock.release.product_version
    }

    pub fn release_tag(&self) -> &str {
        &self.lock.release.release_tag
    }

    pub fn source_sha(&self) -> &str {
        &self.lock.release.source_sha
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
            notary: self.lock.images.notary.identity.clone(),
            postgresql_state_plane: self.lock.images.postgresql_state_plane.identity.clone(),
            private_namespace_holder: self.lock.images.private_namespace_holder.identity.clone(),
        }
    }

    pub fn runtime_mapping(&self) -> VerifiedRuntimeMappingV1 {
        VerifiedRuntimeMappingV1 {
            relay_public: self.lock.runtime.relay_public.clone().into(),
            relay_consultation: self.lock.runtime.relay_consultation.clone().into(),
            notary: self.lock.runtime.notary.clone().into(),
            postgresql_state_plane: self.lock.runtime.postgresql_state_plane.clone().into(),
            private_namespace_holder: self.lock.runtime.private_namespace_holder.clone().into(),
        }
    }
}

impl From<LockedProductRecipeV1> for VerifiedProductRuntimeV1 {
    fn from(value: LockedProductRecipeV1) -> Self {
        Self {
            serve: value.serve,
            prepare_state_store: value.prepare_state_store,
            initialize_state: value.initialize_state,
            verify_state: value.verify_state,
            health_probe: value.health_probe,
        }
    }
}

impl From<LockedSupportingRecipeV1> for VerifiedSupportingRuntimeV1 {
    fn from(value: LockedSupportingRecipeV1) -> Self {
        Self {
            command: value.command,
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

    let payload_value = parse_json_strict(&signed_payload)
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
        validate_lower_hex(&self.source_sha, 40, "release source SHA")
    }
}

impl LockedManagedImagesV1 {
    fn validate(&self) -> Result<()> {
        self.relay.validate("Relay")?;
        self.notary.validate("Notary")?;
        self.postgresql_state_plane
            .validate("PostgreSQL state plane")?;
        self.private_namespace_holder
            .validate("private namespace holder")
    }
}

impl LockedOciImageV1 {
    fn validate(&self, label: &str) -> Result<()> {
        validate_image_identity(&self.identity)
            .with_context(|| format!("{label} image identity is invalid"))?;
        if self.platforms.is_empty() {
            bail!("{label} image has no approved platforms");
        }
        let mut platforms = BTreeSet::new();
        for platform in &self.platforms {
            if !platforms.insert(platform.platform) {
                bail!("{label} image repeats an approved platform");
            }
            validate_digest(&platform.manifest_digest, "image platform manifest digest")?;
        }
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
        self.private_namespace_holder
            .validate("private namespace holder")?;
        Ok(())
    }
}

impl LockedProductRecipeV1 {
    fn validate(&self, label: &str) -> Result<()> {
        for (action, command) in [
            ("serve", &self.serve),
            ("prepare_state_store", &self.prepare_state_store),
            ("initialize_state", &self.initialize_state),
            ("verify_state", &self.verify_state),
            ("health_probe", &self.health_probe),
        ] {
            validate_command(command, &format!("{label} {action}"))?;
        }
        Ok(())
    }
}

impl LockedSupportingRecipeV1 {
    fn validate(&self, label: &str) -> Result<()> {
        validate_command(&self.command, &format!("{label} command"))?;
        validate_command(&self.health_probe, &format!("{label} health probe"))
    }
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
    let expected = BTreeSet::from([
        "dhis2-tracker",
        "fhir-r4",
        "http",
        "opencrvs-dci",
        "snapshot",
        "spreadsheet",
    ]);
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
    if command.is_empty()
        || command.len() > 32
        || command.iter().any(|part| {
            part.is_empty()
                || part.len() > 1024
                || part
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_control())
        })
    {
        bail!("{label} is not a bounded closed command");
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
    fn image_identity_requires_digest_and_platform_closure() {
        let mutable = LockedOciImageV1 {
            identity: "ghcr.io/registrystack/registry-relay:latest".to_string(),
            platforms: vec![LockedOciPlatformV1 {
                platform: OciPlatformV1::LinuxAmd64,
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
            }],
        };
        assert!(mutable.validate("Relay").is_err());
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
