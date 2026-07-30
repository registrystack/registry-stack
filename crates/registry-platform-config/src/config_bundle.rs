use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{
    canonicalize_json, parse_json_strict, verify, PublicJwk, SigningAlgorithm,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{sha256_uri, validate_sha256_uri};

#[cfg(unix)]
use rustix::fs::{Mode, OFlags};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub const MAX_CONFIG_BUNDLE_SEQUENCE: u64 = 9_007_199_254_740_991;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MAX_SIGNATURE_ENVELOPE_BYTES: u64 = 256 * 1024;
pub const MAX_TRUST_ANCHOR_BYTES: u64 = 1024 * 1024;
pub const MAX_BUNDLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ACCEPTANCE_ID_COMPONENT_BYTES: usize = 128;
pub const MAX_TRUST_ANCHOR_SIGNERS: usize = 64;
pub const MAX_ANCHOR_TRANSITION_SIGNATURES: usize = 64;
pub const MAX_ANCHOR_TRANSITION_BYTES: usize = 1024 * 1024;

const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "manifest.sig.json";
const BUNDLE_SCHEMA: &str = "registry.platform.config_bundle.v1";
const SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";
const BREAK_GLASS_SCHEMA: &str = "registry.platform.config_break_glass.v1";
pub const ANCHOR_TRANSITION_SCHEMA_ID: &str = "registry.platform.anchor_transition";
pub const ANCHOR_TRANSITION_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProductTrustDomainV1 {
    Governed,
    Development,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProductAcceptanceLaneV1 {
    #[serde(rename = "relay-public")]
    RelayPublic,
    #[serde(rename = "relay-consultation")]
    RelayConsultation,
    #[serde(rename = "notary")]
    Notary,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProductAcceptanceProductV1 {
    #[serde(rename = "registry-relay")]
    RegistryRelay,
    #[serde(rename = "registry-notary")]
    RegistryNotary,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductAcceptanceIdentityV1 {
    pub trust_domain: ProductTrustDomainV1,
    pub project: String,
    pub environment: String,
    pub lane: ProductAcceptanceLaneV1,
    pub product: ProductAcceptanceProductV1,
    pub stream: String,
    pub instance: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundleManifest {
    pub schema: String,
    pub acceptance_identity: ProductAcceptanceIdentityV1,
    pub bundle_id: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_config_hash: Option<String>,
    pub config_hash: String,
    pub files: Vec<ConfigBundleFile>,
    pub created_at: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundleFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundleSignatureEnvelope {
    pub schema: String,
    pub signatures: Vec<ConfigBundleSignature>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBundleSignature {
    pub kid: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigTrustAnchor {
    pub schema: String,
    pub acceptance_identity: ProductAcceptanceIdentityV1,
    pub version: u64,
    pub threshold: u32,
    pub enabled_signers: Vec<ConfigTrustAnchorSigner>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigTrustAnchorSigner {
    pub kid: String,
    pub jwk: PublicJwk,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorTransitionV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub payload: AnchorTransitionPayloadV1,
    pub signatures: Vec<ConfigBundleSignature>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorTransitionPayloadV1 {
    pub acceptance_identity: ProductAcceptanceIdentityV1,
    pub predecessor_anchor_digest: String,
    pub predecessor_anchor_version: u64,
    pub next_anchor_digest: String,
    pub next_anchor_version: u64,
    pub next_enabled_signers: Vec<ConfigTrustAnchorSigner>,
    pub next_threshold: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBreakGlassOverride {
    pub schema: String,
    pub mode: ConfigBreakGlassMode,
    pub config_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
    pub reason: String,
    pub operator: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigBreakGlassMode {
    AcceptRollback,
    AcceptUnsigned,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedConfigBundle {
    pub manifest: ConfigBundleManifest,
    pub manifest_hash: String,
    pub signer_kids: Vec<String>,
    pub trust_anchor: ConfigTrustAnchor,
    pub config_path: PathBuf,
    pub config_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConfigBundleError {
    Io(String),
    Json(String),
    InvalidAcceptanceIdentity(&'static str),
    InvalidManifest(&'static str),
    InvalidTrustAnchor(&'static str),
    InvalidAnchorTransition(&'static str),
    InvalidPermissions(&'static str),
    InvalidBreakGlass(&'static str),
    InvalidSignatureEnvelope(&'static str),
    BindingMismatch(&'static str),
    SignatureRejected,
    AnchorTransitionRejected(&'static str),
    FileClosure(String),
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ConfigBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(f, "config bundle I/O error: {message}"),
            Self::Json(message) => write!(f, "config bundle JSON error: {message}"),
            Self::InvalidAcceptanceIdentity(reason) => {
                write!(f, "product acceptance identity is invalid: {reason}")
            }
            Self::InvalidManifest(reason) => {
                write!(f, "config bundle manifest is invalid: {reason}")
            }
            Self::InvalidTrustAnchor(reason) => {
                write!(f, "config trust anchor is invalid: {reason}")
            }
            Self::InvalidAnchorTransition(reason) => {
                write!(f, "anchor transition is invalid: {reason}")
            }
            Self::InvalidPermissions(reason) => {
                write!(f, "config artifact permissions are invalid: {reason}")
            }
            Self::InvalidBreakGlass(reason) => {
                write!(f, "config break-glass override is invalid: {reason}")
            }
            Self::InvalidSignatureEnvelope(reason) => {
                write!(f, "config bundle signature envelope is invalid: {reason}")
            }
            Self::BindingMismatch(field) => {
                write!(
                    f,
                    "config bundle binding does not match trust anchor: {field}"
                )
            }
            Self::SignatureRejected => write!(f, "config bundle signature was not accepted"),
            Self::AnchorTransitionRejected(reason) => {
                write!(f, "anchor transition was not accepted: {reason}")
            }
            Self::FileClosure(reason) => write!(f, "config bundle file closure failed: {reason}"),
            Self::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "config bundle file hash mismatch for {path}: expected {expected}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for ConfigBundleError {}

fn deserialize_strict<T>(bytes: &[u8]) -> Result<T, ConfigBundleError>
where
    T: DeserializeOwned,
{
    let value =
        parse_json_strict(bytes).map_err(|error| ConfigBundleError::Json(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| ConfigBundleError::Json(error.to_string()))
}

pub fn verify_config_bundle(
    bundle_dir: impl AsRef<Path>,
    trust_anchor_path: impl AsRef<Path>,
) -> Result<VerifiedConfigBundle, ConfigBundleError> {
    let bundle_dir = bundle_dir.as_ref();
    let anchor = load_trust_anchor(trust_anchor_path.as_ref())?;
    let manifest_path = bundle_dir.join(MANIFEST_FILE);
    let signature_path = bundle_dir.join(SIGNATURE_FILE);
    let manifest_bytes = read_limited(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest_value = parse_json_strict(&manifest_bytes)
        .map_err(|error| ConfigBundleError::Json(error.to_string()))?;
    let manifest: ConfigBundleManifest = serde_json::from_value(manifest_value.clone())
        .map_err(|error| ConfigBundleError::Json(error.to_string()))?;
    manifest.validate()?;
    anchor.validate()?;

    let signature_bytes = read_limited(&signature_path, MAX_SIGNATURE_ENVELOPE_BYTES)?;
    let envelope: ConfigBundleSignatureEnvelope = deserialize_strict(&signature_bytes)?;
    envelope.validate()?;
    let canonical_manifest = canonicalize_json(&manifest_value)
        .map_err(|error| ConfigBundleError::Json(error.to_string()))?;
    let manifest_hash = sha256_uri(&canonical_manifest);
    let signer_kids = verify_manifest_signatures(&canonical_manifest, &envelope, &anchor)?;
    manifest.validate_binding(&anchor)?;
    let (config_path, config_bytes) = verify_file_closure(bundle_dir, &manifest)?;
    Ok(VerifiedConfigBundle {
        manifest,
        manifest_hash,
        signer_kids,
        trust_anchor: anchor,
        config_path,
        config_bytes,
    })
}

pub fn load_trust_anchor(path: &Path) -> Result<ConfigTrustAnchor, ConfigBundleError> {
    let bytes = read_limited_with_permissions(
        path,
        MAX_TRUST_ANCHOR_BYTES,
        ArtifactPermissions::TrustAnchor,
    )?;
    let anchor: ConfigTrustAnchor = deserialize_strict(&bytes)?;
    anchor.validate()?;
    Ok(anchor)
}

pub fn parse_anchor_transition(bytes: &[u8]) -> Result<AnchorTransitionV1, ConfigBundleError> {
    if bytes.len() > MAX_ANCHOR_TRANSITION_BYTES {
        return Err(ConfigBundleError::InvalidAnchorTransition("document size"));
    }
    let transition: AnchorTransitionV1 = deserialize_strict(bytes)?;
    transition.validate()?;
    Ok(transition)
}

pub fn canonical_product_acceptance_identity(
    identity: &ProductAcceptanceIdentityV1,
) -> Result<Vec<u8>, ConfigBundleError> {
    identity.validate()?;
    canonicalize_serializable(identity)
}

pub fn canonical_trust_anchor(anchor: &ConfigTrustAnchor) -> Result<Vec<u8>, ConfigBundleError> {
    anchor.validate()?;
    canonicalize_serializable(anchor)
}

pub fn trust_anchor_digest(anchor: &ConfigTrustAnchor) -> Result<String, ConfigBundleError> {
    Ok(sha256_uri(&canonical_trust_anchor(anchor)?))
}

pub fn canonical_anchor_transition_payload(
    transition: &AnchorTransitionV1,
) -> Result<Vec<u8>, ConfigBundleError> {
    transition.validate_payload()?;
    canonicalize_serializable(&transition.payload)
}

pub fn verify_anchor_transition(
    current_anchor: &ConfigTrustAnchor,
    next_anchor: &ConfigTrustAnchor,
    transition: &AnchorTransitionV1,
) -> Result<Vec<String>, ConfigBundleError> {
    current_anchor.validate()?;
    next_anchor.validate()?;
    transition.validate()?;

    if current_anchor.acceptance_identity != next_anchor.acceptance_identity
        || transition.payload.acceptance_identity != current_anchor.acceptance_identity
    {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "acceptance_identity",
        ));
    }
    if transition.payload.predecessor_anchor_version != current_anchor.version {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "predecessor_anchor_version",
        ));
    }
    if transition.payload.predecessor_anchor_digest != trust_anchor_digest(current_anchor)? {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "predecessor_anchor_digest",
        ));
    }
    let expected_next_version = current_anchor
        .version
        .checked_add(1)
        .filter(|version| *version <= MAX_CONFIG_BUNDLE_SEQUENCE)
        .ok_or(ConfigBundleError::AnchorTransitionRejected(
            "next_anchor_version",
        ))?;
    if next_anchor.version != expected_next_version
        || transition.payload.next_anchor_version != expected_next_version
    {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "next_anchor_version",
        ));
    }
    if transition.payload.next_anchor_digest != trust_anchor_digest(next_anchor)? {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "next_anchor_digest",
        ));
    }
    if transition.payload.next_enabled_signers != next_anchor.enabled_signers {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "next_enabled_signers",
        ));
    }
    if transition.payload.next_threshold != next_anchor.threshold {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "next_threshold",
        ));
    }

    let next_signer_kids = next_anchor
        .enabled_signers
        .iter()
        .map(|signer| signer.kid.as_str())
        .collect::<BTreeSet<_>>();
    let retained_current_signers = current_anchor
        .enabled_signers
        .iter()
        .filter(|signer| next_signer_kids.contains(signer.kid.as_str()))
        .count();
    if retained_current_signers < current_anchor.threshold as usize {
        return Err(ConfigBundleError::AnchorTransitionRejected(
            "signer_overlap",
        ));
    }

    let canonical_payload = canonical_anchor_transition_payload(transition)?;
    verify_transition_signatures(&canonical_payload, transition, current_anchor)
}

impl ProductAcceptanceIdentityV1 {
    pub fn validate(&self) -> Result<(), ConfigBundleError> {
        validate_identity_component("project", &self.project)?;
        validate_identity_component("environment", &self.environment)?;
        validate_identity_component("stream", &self.stream)?;
        validate_identity_component("instance", &self.instance)?;
        match (self.lane, self.product) {
            (
                ProductAcceptanceLaneV1::RelayPublic | ProductAcceptanceLaneV1::RelayConsultation,
                ProductAcceptanceProductV1::RegistryRelay,
            )
            | (ProductAcceptanceLaneV1::Notary, ProductAcceptanceProductV1::RegistryNotary) => {
                Ok(())
            }
            _ => Err(ConfigBundleError::InvalidAcceptanceIdentity("lane/product")),
        }
    }
}

impl ConfigBundleManifest {
    pub fn validate(&self) -> Result<(), ConfigBundleError> {
        if self.schema != BUNDLE_SCHEMA {
            return Err(ConfigBundleError::InvalidManifest("schema"));
        }
        self.acceptance_identity.validate()?;
        validate_non_empty_manifest("bundle_id", &self.bundle_id)?;
        validate_sequence(self.sequence)?;
        validate_hash_manifest("config_hash", &self.config_hash)?;
        if let Some(previous) = &self.previous_config_hash {
            validate_hash_manifest("previous_config_hash", previous)?;
        }
        if self.files.is_empty() {
            return Err(ConfigBundleError::InvalidManifest("files"));
        }
        let mut seen = BTreeSet::new();
        for file in &self.files {
            let normalized = normalize_bundle_path(&file.path)?;
            if !seen.insert(normalized) {
                return Err(ConfigBundleError::FileClosure(format!(
                    "duplicate file path '{}'",
                    file.path
                )));
            }
            validate_hash_manifest("files[].sha256", &file.sha256)?;
        }
        validate_non_empty_manifest("created_at", &self.created_at)?;
        Ok(())
    }

    fn validate_binding(&self, anchor: &ConfigTrustAnchor) -> Result<(), ConfigBundleError> {
        if self.acceptance_identity != anchor.acceptance_identity {
            return Err(ConfigBundleError::BindingMismatch(
                acceptance_identity_mismatch(
                    &self.acceptance_identity,
                    &anchor.acceptance_identity,
                ),
            ));
        }
        Ok(())
    }
}

impl ConfigTrustAnchor {
    pub fn validate_initial(&self) -> Result<(), ConfigBundleError> {
        self.validate()?;
        if self.version != 1 {
            return Err(ConfigBundleError::InvalidTrustAnchor("initial version"));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigBundleError> {
        if self.schema != TRUST_ANCHOR_SCHEMA {
            return Err(ConfigBundleError::InvalidTrustAnchor("schema"));
        }
        self.acceptance_identity.validate()?;
        validate_anchor_version(self.version)?;
        if self.enabled_signers.is_empty() || self.enabled_signers.len() > MAX_TRUST_ANCHOR_SIGNERS
        {
            return Err(ConfigBundleError::InvalidTrustAnchor("enabled_signers"));
        }
        if self.threshold == 0 || self.threshold as usize > self.enabled_signers.len() {
            return Err(ConfigBundleError::InvalidTrustAnchor("threshold"));
        }
        let mut seen = BTreeSet::new();
        let mut previous_kid: Option<&str> = None;
        for signer in &self.enabled_signers {
            validate_non_empty_anchor("enabled_signers[].kid", &signer.kid)?;
            if !seen.insert(signer.kid.clone()) {
                return Err(ConfigBundleError::InvalidTrustAnchor(
                    "duplicate signer kid",
                ));
            }
            if previous_kid.is_some_and(|previous| previous >= signer.kid.as_str()) {
                return Err(ConfigBundleError::InvalidTrustAnchor(
                    "enabled_signers order",
                ));
            }
            previous_kid = Some(&signer.kid);
            let computed = signer
                .jwk
                .jkt()
                .map_err(|_| ConfigBundleError::InvalidTrustAnchor("enabled_signers[].jwk"))?;
            if computed != signer.kid {
                return Err(ConfigBundleError::InvalidTrustAnchor("kid/jwk mismatch"));
            }
        }
        Ok(())
    }

    fn enabled_signers_by_kid(&self) -> BTreeMap<&str, &PublicJwk> {
        self.enabled_signers
            .iter()
            .map(|signer| (signer.kid.as_str(), &signer.jwk))
            .collect()
    }
}

impl AnchorTransitionV1 {
    pub fn unsigned(
        current_anchor: &ConfigTrustAnchor,
        next_anchor: &ConfigTrustAnchor,
    ) -> Result<Self, ConfigBundleError> {
        current_anchor.validate()?;
        next_anchor.validate()?;
        if current_anchor.acceptance_identity != next_anchor.acceptance_identity {
            return Err(ConfigBundleError::AnchorTransitionRejected(
                "acceptance_identity",
            ));
        }
        let expected_next_version = current_anchor
            .version
            .checked_add(1)
            .filter(|version| *version <= MAX_CONFIG_BUNDLE_SEQUENCE)
            .ok_or(ConfigBundleError::AnchorTransitionRejected(
                "next_anchor_version",
            ))?;
        if next_anchor.version != expected_next_version {
            return Err(ConfigBundleError::AnchorTransitionRejected(
                "next_anchor_version",
            ));
        }
        let next_signer_kids = next_anchor
            .enabled_signers
            .iter()
            .map(|signer| signer.kid.as_str())
            .collect::<BTreeSet<_>>();
        let retained_current_signers = current_anchor
            .enabled_signers
            .iter()
            .filter(|signer| next_signer_kids.contains(signer.kid.as_str()))
            .count();
        if retained_current_signers < current_anchor.threshold as usize {
            return Err(ConfigBundleError::AnchorTransitionRejected(
                "signer_overlap",
            ));
        }
        Ok(Self {
            schema_id: ANCHOR_TRANSITION_SCHEMA_ID.to_string(),
            schema_version: ANCHOR_TRANSITION_SCHEMA_VERSION.to_string(),
            payload: AnchorTransitionPayloadV1 {
                acceptance_identity: current_anchor.acceptance_identity.clone(),
                predecessor_anchor_digest: trust_anchor_digest(current_anchor)?,
                predecessor_anchor_version: current_anchor.version,
                next_anchor_digest: trust_anchor_digest(next_anchor)?,
                next_anchor_version: next_anchor.version,
                next_enabled_signers: next_anchor.enabled_signers.clone(),
                next_threshold: next_anchor.threshold,
            },
            signatures: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), ConfigBundleError> {
        self.validate_payload()?;
        if self.signatures.is_empty() || self.signatures.len() > MAX_ANCHOR_TRANSITION_SIGNATURES {
            return Err(ConfigBundleError::InvalidAnchorTransition("signatures"));
        }
        let mut seen = BTreeSet::new();
        for signature in &self.signatures {
            validate_non_empty_transition("signatures[].kid", &signature.kid)?;
            validate_non_empty_transition("signatures[].alg", &signature.alg)?;
            validate_non_empty_transition("signatures[].sig", &signature.sig)?;
            if !seen.insert(signature.kid.as_str()) {
                return Err(ConfigBundleError::InvalidAnchorTransition(
                    "duplicate signature kid",
                ));
            }
        }
        Ok(())
    }

    fn validate_payload(&self) -> Result<(), ConfigBundleError> {
        if self.schema_id != ANCHOR_TRANSITION_SCHEMA_ID {
            return Err(ConfigBundleError::InvalidAnchorTransition("schema_id"));
        }
        if self.schema_version != ANCHOR_TRANSITION_SCHEMA_VERSION {
            return Err(ConfigBundleError::InvalidAnchorTransition("schema_version"));
        }
        self.payload.acceptance_identity.validate()?;
        validate_hash_transition(
            "predecessor_anchor_digest",
            &self.payload.predecessor_anchor_digest,
        )?;
        validate_anchor_transition_version(
            "predecessor_anchor_version",
            self.payload.predecessor_anchor_version,
        )?;
        validate_hash_transition("next_anchor_digest", &self.payload.next_anchor_digest)?;
        validate_anchor_transition_version(
            "next_anchor_version",
            self.payload.next_anchor_version,
        )?;
        if self.payload.next_enabled_signers.is_empty()
            || self.payload.next_enabled_signers.len() > MAX_TRUST_ANCHOR_SIGNERS
        {
            return Err(ConfigBundleError::InvalidAnchorTransition(
                "next_enabled_signers",
            ));
        }
        if self.payload.next_threshold == 0
            || self.payload.next_threshold as usize > self.payload.next_enabled_signers.len()
        {
            return Err(ConfigBundleError::InvalidAnchorTransition("next_threshold"));
        }
        validate_transition_signer_set(&self.payload.next_enabled_signers)
    }
}

impl ConfigBundleSignatureEnvelope {
    fn validate(&self) -> Result<(), ConfigBundleError> {
        if self.schema != SIGNATURE_SCHEMA {
            return Err(ConfigBundleError::InvalidSignatureEnvelope("schema"));
        }
        if self.signatures.is_empty() {
            return Err(ConfigBundleError::InvalidSignatureEnvelope("signatures"));
        }
        for signature in &self.signatures {
            validate_non_empty_signature("signatures[].kid", &signature.kid)?;
            validate_non_empty_signature("signatures[].alg", &signature.alg)?;
            validate_non_empty_signature("signatures[].sig", &signature.sig)?;
        }
        Ok(())
    }
}

impl ConfigBreakGlassOverride {
    pub fn validate_fields(&self) -> Result<(), ConfigBundleError> {
        if self.schema != BREAK_GLASS_SCHEMA {
            return Err(ConfigBundleError::InvalidBreakGlass("schema"));
        }
        validate_sha256_uri("config_hash", &self.config_hash)
            .map_err(|_| ConfigBundleError::InvalidBreakGlass("config_hash"))?;
        validate_non_empty_break_glass("reason", &self.reason)?;
        validate_non_empty_break_glass("operator", &self.operator)?;
        let created_at = parse_break_glass_time("created_at", &self.created_at)?;
        let expires_at = parse_break_glass_time("expires_at", &self.expires_at)?;
        if expires_at <= created_at {
            return Err(ConfigBundleError::InvalidBreakGlass("expires_at"));
        }
        if expires_at - created_at > time::Duration::hours(24) {
            return Err(ConfigBundleError::InvalidBreakGlass("expires_at"));
        }
        if expires_at <= OffsetDateTime::now_utc() {
            return Err(ConfigBundleError::InvalidBreakGlass("expired"));
        }
        match self.mode {
            ConfigBreakGlassMode::AcceptRollback if self.config_path.is_some() => {
                Err(ConfigBundleError::InvalidBreakGlass("rollback config_path"))
            }
            ConfigBreakGlassMode::AcceptUnsigned if self.config_path.is_none() => {
                Err(ConfigBundleError::InvalidBreakGlass("unsigned config_path"))
            }
            ConfigBreakGlassMode::AcceptUnsigned
                if self
                    .config_path
                    .as_deref()
                    .is_some_and(|path| !path.is_absolute()) =>
            {
                Err(ConfigBundleError::InvalidBreakGlass("unsigned config_path"))
            }
            _ => Ok(()),
        }
    }
}

pub fn load_break_glass_override(
    path: &Path,
) -> Result<ConfigBreakGlassOverride, ConfigBundleError> {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".consumed-"))
    {
        return Err(ConfigBundleError::InvalidBreakGlass("consumed"));
    }
    let bytes = read_limited_with_permissions(
        path,
        MAX_SIGNATURE_ENVELOPE_BYTES,
        ArtifactPermissions::BreakGlassOverride,
    )?;
    let override_file: ConfigBreakGlassOverride = deserialize_strict(&bytes)?;
    override_file.validate_fields()?;
    if matches!(override_file.mode, ConfigBreakGlassMode::AcceptUnsigned) {
        let config_path = override_file
            .config_path
            .as_deref()
            .ok_or(ConfigBundleError::InvalidBreakGlass("unsigned config_path"))?;
        let config_bytes = read_limited(config_path, MAX_BUNDLE_FILE_BYTES)?;
        let actual = sha256_uri(&config_bytes);
        if actual != override_file.config_hash {
            return Err(ConfigBundleError::HashMismatch {
                path: config_path.display().to_string(),
                expected: override_file.config_hash.clone(),
                actual,
            });
        }
    }
    Ok(override_file)
}

pub fn read_config_file_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ConfigBundleError> {
    read_limited(path, max_bytes)
}

fn verify_manifest_signatures(
    canonical_manifest: &[u8],
    envelope: &ConfigBundleSignatureEnvelope,
    anchor: &ConfigTrustAnchor,
) -> Result<Vec<String>, ConfigBundleError> {
    let signers = anchor.enabled_signers_by_kid();
    let mut verified = BTreeSet::new();
    for signature in &envelope.signatures {
        let Some(jwk) = signers.get(signature.kid.as_str()) else {
            continue;
        };
        if signature.alg != signing_alg_label(jwk)? {
            continue;
        }
        let sig = match URL_SAFE_NO_PAD.decode(signature.sig.as_bytes()) {
            Ok(sig) => sig,
            Err(_) => continue,
        };
        if verify(canonical_manifest, &sig, jwk).is_ok() {
            verified.insert(signature.kid.clone());
        }
    }
    if verified.len() < anchor.threshold as usize {
        return Err(ConfigBundleError::SignatureRejected);
    }
    Ok(verified.into_iter().collect())
}

fn verify_transition_signatures(
    canonical_payload: &[u8],
    transition: &AnchorTransitionV1,
    current_anchor: &ConfigTrustAnchor,
) -> Result<Vec<String>, ConfigBundleError> {
    let signers = current_anchor.enabled_signers_by_kid();
    let mut verified = BTreeSet::new();
    for signature in &transition.signatures {
        let Some(jwk) = signers.get(signature.kid.as_str()) else {
            continue;
        };
        if signature.alg != signing_alg_label(jwk)? {
            continue;
        }
        let sig = match URL_SAFE_NO_PAD.decode(signature.sig.as_bytes()) {
            Ok(sig) => sig,
            Err(_) => continue,
        };
        if verify(canonical_payload, &sig, jwk).is_ok() {
            verified.insert(signature.kid.clone());
        }
    }
    if verified.len() < current_anchor.threshold as usize {
        return Err(ConfigBundleError::AnchorTransitionRejected("signatures"));
    }
    Ok(verified.into_iter().collect())
}

fn signing_alg_label(jwk: &PublicJwk) -> Result<&'static str, ConfigBundleError> {
    match jwk
        .algorithm()
        .map_err(|_| ConfigBundleError::InvalidTrustAnchor("enabled_signers[].jwk"))?
    {
        SigningAlgorithm::EdDsa => Ok("EdDSA"),
        SigningAlgorithm::Es256 => Ok("ES256"),
        SigningAlgorithm::Rs256 => Ok("RS256"),
    }
}

fn verify_file_closure(
    bundle_dir: &Path,
    manifest: &ConfigBundleManifest,
) -> Result<(PathBuf, Vec<u8>), ConfigBundleError> {
    reject_symlinks_and_collect_files(bundle_dir, bundle_dir, &mut BTreeSet::new())?;

    let mut expected = BTreeMap::new();
    for file in &manifest.files {
        expected.insert(normalize_bundle_path(&file.path)?, file.sha256.as_str());
    }
    let mut present = BTreeSet::new();
    collect_regular_bundle_files(bundle_dir, bundle_dir, &mut present)?;
    for reserved in [MANIFEST_FILE, SIGNATURE_FILE] {
        present.remove(reserved);
    }
    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    if present != expected_paths {
        let missing = expected_paths
            .difference(&present)
            .next()
            .map(String::as_str);
        if let Some(missing) = missing {
            return Err(ConfigBundleError::FileClosure(format!(
                "listed file is missing: {missing}"
            )));
        }
        let unlisted = present
            .difference(&expected_paths)
            .next()
            .expect("unlisted file");
        return Err(ConfigBundleError::FileClosure(format!(
            "present file is unlisted: {unlisted}"
        )));
    }

    let mut primary: Option<(PathBuf, Vec<u8>)> = None;
    for file in &manifest.files {
        let normalized = normalize_bundle_path(&file.path)?;
        let path = bundle_dir.join(Path::new(&normalized));
        let bytes = read_limited(&path, MAX_BUNDLE_FILE_BYTES)?;
        let actual = sha256_uri(&bytes);
        if actual != file.sha256 {
            return Err(ConfigBundleError::HashMismatch {
                path: normalized,
                expected: file.sha256.clone(),
                actual,
            });
        }
        if file.sha256 == manifest.config_hash && primary.is_none() {
            primary = Some((path, bytes));
        }
    }
    primary.ok_or(ConfigBundleError::InvalidManifest(
        "config_hash primary file",
    ))
}

fn reject_symlinks_and_collect_files(
    root: &Path,
    dir: &Path,
    seen_dirs: &mut BTreeSet<PathBuf>,
) -> Result<(), ConfigBundleError> {
    let metadata =
        fs::symlink_metadata(dir).map_err(|error| ConfigBundleError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigBundleError::FileClosure(format!(
            "symlink is not allowed: {}",
            display_relative(root, dir)
        )));
    }
    if !metadata.is_dir() {
        return Err(ConfigBundleError::FileClosure(format!(
            "bundle path is not a directory: {}",
            dir.display()
        )));
    }
    let canonical = dir
        .canonicalize()
        .map_err(|error| ConfigBundleError::Io(error.to_string()))?;
    if !seen_dirs.insert(canonical) {
        return Err(ConfigBundleError::FileClosure(
            "directory cycle".to_string(),
        ));
    }
    for entry in fs::read_dir(dir).map_err(|error| ConfigBundleError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| ConfigBundleError::Io(error.to_string()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| ConfigBundleError::Io(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigBundleError::FileClosure(format!(
                "symlink is not allowed: {}",
                display_relative(root, &path)
            )));
        }
        if metadata.is_dir() {
            reject_symlinks_and_collect_files(root, &path, seen_dirs)?;
        }
    }
    Ok(())
}

fn collect_regular_bundle_files(
    root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), ConfigBundleError> {
    for entry in fs::read_dir(dir).map_err(|error| ConfigBundleError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| ConfigBundleError::Io(error.to_string()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| ConfigBundleError::Io(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigBundleError::FileClosure(format!(
                "symlink is not allowed: {}",
                display_relative(root, &path)
            )));
        }
        if metadata.is_dir() {
            collect_regular_bundle_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.insert(display_relative(root, &path));
        } else {
            return Err(ConfigBundleError::FileClosure(format!(
                "unsupported file type: {}",
                display_relative(root, &path)
            )));
        }
    }
    Ok(())
}

fn normalize_bundle_path(value: &str) -> Result<String, ConfigBundleError> {
    if value.trim().is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value == MANIFEST_FILE
        || value == SIGNATURE_FILE
    {
        return Err(ConfigBundleError::FileClosure(format!(
            "invalid file path '{value}'"
        )));
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(ConfigBundleError::FileClosure(format!(
                "invalid file path '{value}'"
            )));
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ConfigBundleError> {
    read_limited_with_open_file(path, max_bytes, None)
}

#[derive(Clone, Copy)]
enum ArtifactPermissions {
    TrustAnchor,
    BreakGlassOverride,
}

fn read_limited_with_permissions(
    path: &Path,
    max_bytes: u64,
    permissions: ArtifactPermissions,
) -> Result<Vec<u8>, ConfigBundleError> {
    read_limited_with_open_file(path, max_bytes, Some(permissions))
}

fn read_limited_with_open_file(
    path: &Path,
    max_bytes: u64,
    permissions: Option<ArtifactPermissions>,
) -> Result<Vec<u8>, ConfigBundleError> {
    let file = open_read_only_no_follow(path)?;
    read_limited_from_file(file, max_bytes, permissions)
}

fn read_limited_from_file(
    mut file: File,
    max_bytes: u64,
    permissions: Option<ArtifactPermissions>,
) -> Result<Vec<u8>, ConfigBundleError> {
    let metadata = file
        .metadata()
        .map_err(|error| ConfigBundleError::Io(error.to_string()))?;
    match permissions {
        Some(permissions) => validate_artifact_file_permissions(&metadata, permissions)?,
        None => validate_readable_regular_file(&metadata)?,
    }
    if metadata.len() > max_bytes {
        return Err(ConfigBundleError::Io("file exceeds size cap".to_string()));
    }
    let mut bytes = Vec::new();
    let read_cap = max_bytes
        .checked_add(1)
        .ok_or_else(|| ConfigBundleError::Io("file size cap overflow".to_string()))?;
    file.by_ref()
        .take(read_cap)
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigBundleError::Io(error.to_string()))?;
    let len = u64::try_from(bytes.len())
        .map_err(|_| ConfigBundleError::Io("file length overflow".to_string()))?;
    if len > max_bytes {
        return Err(ConfigBundleError::Io("file exceeds size cap".to_string()));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> Result<File, ConfigBundleError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ConfigBundleError::Io(error.to_string()))?;
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_read_only_no_follow(path: &Path) -> Result<File, ConfigBundleError> {
    File::open(path).map_err(|error| ConfigBundleError::Io(error.to_string()))
}

fn validate_readable_regular_file(metadata: &fs::Metadata) -> Result<(), ConfigBundleError> {
    if !metadata.is_file() {
        return Err(ConfigBundleError::Io(
            "path is not a regular file".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_artifact_file_permissions(
    metadata: &fs::Metadata,
    permissions: ArtifactPermissions,
) -> Result<(), ConfigBundleError> {
    validate_not_symlink_file(metadata)?;
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        let reason = match permissions {
            ArtifactPermissions::TrustAnchor => "trust anchor must not be group/world writable",
            ArtifactPermissions::BreakGlassOverride => {
                "break-glass override must not be group/world writable"
            }
        };
        return Err(ConfigBundleError::InvalidPermissions(reason));
    }
    let owner = metadata.uid();
    match permissions {
        ArtifactPermissions::TrustAnchor if owner != 0 && owner != current_euid() => {
            return Err(ConfigBundleError::InvalidPermissions(
                "trust anchor owner must be root or current service user",
            ));
        }
        ArtifactPermissions::BreakGlassOverride if owner != 0 => {
            return Err(ConfigBundleError::InvalidPermissions(
                "break-glass override owner must be root",
            ));
        }
        _ => {}
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_artifact_file_permissions(
    metadata: &fs::Metadata,
    _permissions: ArtifactPermissions,
) -> Result<(), ConfigBundleError> {
    validate_not_symlink_file(metadata)
}

fn validate_not_symlink_file(metadata: &fs::Metadata) -> Result<(), ConfigBundleError> {
    if metadata.file_type().is_symlink() {
        return Err(ConfigBundleError::InvalidPermissions(
            "symlink path rejected",
        ));
    }
    if !metadata.is_file() {
        return Err(ConfigBundleError::InvalidPermissions(
            "path must be a regular file",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn validate_sequence(sequence: u64) -> Result<(), ConfigBundleError> {
    if sequence == 0 || sequence > MAX_CONFIG_BUNDLE_SEQUENCE {
        return Err(ConfigBundleError::InvalidManifest("sequence"));
    }
    Ok(())
}

fn validate_anchor_version(version: u64) -> Result<(), ConfigBundleError> {
    if version == 0 || version > MAX_CONFIG_BUNDLE_SEQUENCE {
        return Err(ConfigBundleError::InvalidTrustAnchor("version"));
    }
    Ok(())
}

fn validate_anchor_transition_version(
    field: &'static str,
    version: u64,
) -> Result<(), ConfigBundleError> {
    if version == 0 || version > MAX_CONFIG_BUNDLE_SEQUENCE {
        return Err(ConfigBundleError::InvalidAnchorTransition(field));
    }
    Ok(())
}

fn validate_identity_component(field: &'static str, value: &str) -> Result<(), ConfigBundleError> {
    if value.is_empty()
        || value.len() > MAX_ACCEPTANCE_ID_COMPONENT_BYTES
        || value.trim() != value
        || !value.is_ascii()
    {
        return Err(ConfigBundleError::InvalidAcceptanceIdentity(field));
    }
    let mut characters = value.bytes();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, b'-' | b'.' | b'_')
        })
    {
        return Err(ConfigBundleError::InvalidAcceptanceIdentity(field));
    }
    Ok(())
}

fn acceptance_identity_mismatch(
    manifest: &ProductAcceptanceIdentityV1,
    anchor: &ProductAcceptanceIdentityV1,
) -> &'static str {
    if manifest.trust_domain != anchor.trust_domain {
        "trust_domain"
    } else if manifest.project != anchor.project {
        "project"
    } else if manifest.environment != anchor.environment {
        "environment"
    } else if manifest.lane != anchor.lane {
        "lane"
    } else if manifest.product != anchor.product {
        "product"
    } else if manifest.stream != anchor.stream {
        "stream"
    } else {
        "instance"
    }
}

fn canonicalize_serializable<T: Serialize>(value: &T) -> Result<Vec<u8>, ConfigBundleError> {
    let value =
        serde_json::to_value(value).map_err(|error| ConfigBundleError::Json(error.to_string()))?;
    canonicalize_json(&value).map_err(|error| ConfigBundleError::Json(error.to_string()))
}

fn validate_transition_signer_set(
    signers: &[ConfigTrustAnchorSigner],
) -> Result<(), ConfigBundleError> {
    let mut seen = BTreeSet::new();
    let mut previous_kid: Option<&str> = None;
    for signer in signers {
        validate_non_empty_transition("next_enabled_signers[].kid", &signer.kid)?;
        if !seen.insert(signer.kid.as_str()) {
            return Err(ConfigBundleError::InvalidAnchorTransition(
                "duplicate next signer kid",
            ));
        }
        if previous_kid.is_some_and(|previous| previous >= signer.kid.as_str()) {
            return Err(ConfigBundleError::InvalidAnchorTransition(
                "next_enabled_signers order",
            ));
        }
        previous_kid = Some(&signer.kid);
        let computed = signer.jwk.jkt().map_err(|_| {
            ConfigBundleError::InvalidAnchorTransition("next_enabled_signers[].jwk")
        })?;
        if computed != signer.kid {
            return Err(ConfigBundleError::InvalidAnchorTransition(
                "next signer kid/jwk mismatch",
            ));
        }
    }
    Ok(())
}

fn parse_break_glass_time(
    field: &'static str,
    value: &str,
) -> Result<OffsetDateTime, ConfigBundleError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ConfigBundleError::InvalidBreakGlass(field))
}

fn validate_hash_manifest(field: &'static str, value: &str) -> Result<(), ConfigBundleError> {
    validate_sha256_uri(field, value).map_err(|_| ConfigBundleError::InvalidManifest(field))
}

fn validate_hash_transition(field: &'static str, value: &str) -> Result<(), ConfigBundleError> {
    validate_sha256_uri(field, value).map_err(|_| ConfigBundleError::InvalidAnchorTransition(field))
}

fn validate_non_empty_manifest(field: &'static str, value: &str) -> Result<(), ConfigBundleError> {
    if value.trim().is_empty() {
        return Err(ConfigBundleError::InvalidManifest(field));
    }
    Ok(())
}

fn validate_non_empty_anchor(field: &'static str, value: &str) -> Result<(), ConfigBundleError> {
    if value.trim().is_empty() {
        return Err(ConfigBundleError::InvalidTrustAnchor(field));
    }
    Ok(())
}

fn validate_non_empty_signature(field: &'static str, value: &str) -> Result<(), ConfigBundleError> {
    if value.trim().is_empty() {
        return Err(ConfigBundleError::InvalidSignatureEnvelope(field));
    }
    Ok(())
}

fn validate_non_empty_transition(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigBundleError> {
    if value.trim().is_empty() {
        return Err(ConfigBundleError::InvalidAnchorTransition(field));
    }
    Ok(())
}

fn validate_non_empty_break_glass(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigBundleError> {
    if value.trim().is_empty() {
        return Err(ConfigBundleError::InvalidBreakGlass(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    const ED25519_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registry-platform-testing-ed25519-1"}"#;
    const ED25519_ROTATED_PRIVATE_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"registry-platform-testing-ed25519-2"}"#;

    struct BundleFixture {
        tmp: TempDir,
        bundle_dir: PathBuf,
        anchor_path: PathBuf,
        manifest: ConfigBundleManifest,
        private: PrivateJwk,
    }

    fn notary_identity() -> ProductAcceptanceIdentityV1 {
        ProductAcceptanceIdentityV1 {
            trust_domain: ProductTrustDomainV1::Governed,
            project: "civil-registry".to_string(),
            environment: "production".to_string(),
            lane: ProductAcceptanceLaneV1::Notary,
            product: ProductAcceptanceProductV1::RegistryNotary,
            stream: "civil-registration".to_string(),
            instance: "notary-011".to_string(),
        }
    }

    fn fixture() -> BundleFixture {
        let tmp = TempDir::new().expect("tempdir");
        let bundle_dir = tmp.path().join("bundle");
        fs::create_dir_all(bundle_dir.join("config")).expect("bundle dir");
        let config_bytes = b"server:\n  bind: 127.0.0.1:8080\n";
        fs::write(bundle_dir.join("config/notary.yaml"), config_bytes).expect("config");
        let config_hash = sha256_uri(config_bytes);
        let manifest = ConfigBundleManifest {
            schema: BUNDLE_SCHEMA.to_string(),
            acceptance_identity: notary_identity(),
            bundle_id: "2026-07-07-rollout-3".to_string(),
            sequence: MAX_CONFIG_BUNDLE_SEQUENCE,
            previous_config_hash: Some(sha256_uri(b"previous")),
            config_hash: config_hash.clone(),
            files: vec![ConfigBundleFile {
                path: "config/notary.yaml".to_string(),
                sha256: config_hash,
            }],
            created_at: "2026-07-07T10:00:00Z".to_string(),
        };
        let private = PrivateJwk::parse(ED25519_PRIVATE_JWK).expect("private jwk");
        write_manifest_and_signature(&bundle_dir, &manifest, &private);
        let public = private.public();
        let kid = public.jkt().expect("jkt");
        let anchor = ConfigTrustAnchor {
            schema: TRUST_ANCHOR_SCHEMA.to_string(),
            acceptance_identity: notary_identity(),
            version: 1,
            threshold: 1,
            enabled_signers: vec![ConfigTrustAnchorSigner { kid, jwk: public }],
        };
        let anchor_path = tmp.path().join("trust_anchor.json");
        fs::write(
            &anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor json"),
        )
        .expect("anchor");
        BundleFixture {
            tmp,
            bundle_dir,
            anchor_path,
            manifest,
            private,
        }
    }

    fn write_manifest_and_signature(
        bundle_dir: &Path,
        manifest: &ConfigBundleManifest,
        private: &PrivateJwk,
    ) {
        let manifest_value = serde_json::to_value(manifest).expect("manifest value");
        let canonical = canonicalize_json(&manifest_value).expect("canonical manifest");
        let signature = sign(&canonical, private).expect("sign");
        let kid = private.public().jkt().expect("jkt");
        let envelope = ConfigBundleSignatureEnvelope {
            schema: SIGNATURE_SCHEMA.to_string(),
            signatures: vec![ConfigBundleSignature {
                kid,
                alg: "EdDSA".to_string(),
                sig: URL_SAFE_NO_PAD.encode(signature),
            }],
        };
        fs::write(
            bundle_dir.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(manifest).expect("manifest json"),
        )
        .expect("manifest");
        fs::write(
            bundle_dir.join(SIGNATURE_FILE),
            serde_json::to_vec_pretty(&envelope).expect("signature json"),
        )
        .expect("signature");
    }

    fn anchor_from_keys(
        acceptance_identity: ProductAcceptanceIdentityV1,
        version: u64,
        threshold: u32,
        private_keys: &[&PrivateJwk],
    ) -> ConfigTrustAnchor {
        let mut enabled_signers = private_keys
            .iter()
            .map(|private| {
                let jwk = private.public();
                ConfigTrustAnchorSigner {
                    kid: jwk.jkt().expect("signer kid"),
                    jwk,
                }
            })
            .collect::<Vec<_>>();
        enabled_signers.sort_by(|left, right| left.kid.cmp(&right.kid));
        ConfigTrustAnchor {
            schema: TRUST_ANCHOR_SCHEMA.to_string(),
            acceptance_identity,
            version,
            threshold,
            enabled_signers,
        }
    }

    fn sign_anchor_transition(transition: &mut AnchorTransitionV1, private_keys: &[&PrivateJwk]) {
        let payload =
            canonical_anchor_transition_payload(transition).expect("canonical transition payload");
        transition.signatures = private_keys
            .iter()
            .map(|private| ConfigBundleSignature {
                kid: private.public().jkt().expect("signer kid"),
                alg: "EdDSA".to_string(),
                sig: URL_SAFE_NO_PAD.encode(sign(&payload, private).expect("transition signature")),
            })
            .collect();
    }

    fn signed_rotation_fixture() -> (
        PrivateJwk,
        PrivateJwk,
        ConfigTrustAnchor,
        ConfigTrustAnchor,
        AnchorTransitionV1,
    ) {
        let first = PrivateJwk::parse(ED25519_PRIVATE_JWK).expect("first private key");
        let second = PrivateJwk::parse(ED25519_ROTATED_PRIVATE_JWK).expect("second private key");
        let current = anchor_from_keys(notary_identity(), 1, 2, &[&first, &second]);
        let next = anchor_from_keys(notary_identity(), 2, 1, &[&first, &second]);
        let mut transition =
            AnchorTransitionV1::unsigned(&current, &next).expect("unsigned transition");
        sign_anchor_transition(&mut transition, &[&first, &second]);
        (first, second, current, next, transition)
    }

    #[test]
    fn verifies_signed_bundle_with_max_safe_sequence() {
        let fixture = fixture();
        let expected_anchor = load_trust_anchor(&fixture.anchor_path).expect("expected anchor");

        let verified =
            verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path).expect("verified");

        assert_eq!(verified.manifest.sequence, MAX_CONFIG_BUNDLE_SEQUENCE);
        assert_eq!(verified.signer_kids.len(), 1);
        assert_eq!(verified.trust_anchor, expected_anchor);
        assert_eq!(
            verified.config_path,
            fixture.bundle_dir.join("config/notary.yaml")
        );
        assert_eq!(
            sha256_uri(&verified.config_bytes),
            fixture.manifest.config_hash
        );
        assert!(fixture.tmp.path().exists());
    }

    #[test]
    fn rejects_duplicate_members_in_every_signed_json_artifact() {
        let fixture = fixture();

        let manifest_path = fixture.bundle_dir.join(MANIFEST_FILE);
        let manifest = fs::read_to_string(&manifest_path).expect("manifest text");
        fs::write(
            &manifest_path,
            manifest.replacen("\"schema\":", "\"schema\":\"shadow\",\"schema\":", 1),
        )
        .expect("duplicate manifest");
        assert!(matches!(
            verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path),
            Err(ConfigBundleError::Json(message))
                if message.contains("duplicate JSON object member")
        ));

        write_manifest_and_signature(&fixture.bundle_dir, &fixture.manifest, &fixture.private);
        let signature_path = fixture.bundle_dir.join(SIGNATURE_FILE);
        let signature = fs::read_to_string(&signature_path).expect("signature text");
        fs::write(
            &signature_path,
            signature.replacen("\"kid\":", "\"kid\":\"shadow\",\"kid\":", 1),
        )
        .expect("duplicate signature");
        assert!(matches!(
            verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path),
            Err(ConfigBundleError::Json(message))
                if message.contains("duplicate JSON object member")
        ));

        let anchor = fs::read_to_string(&fixture.anchor_path).expect("anchor text");
        fs::write(
            &fixture.anchor_path,
            anchor.replacen("\"kty\":", "\"kty\":\"shadow\",\"kty\":", 1),
        )
        .expect("duplicate trust anchor");
        assert!(matches!(
            load_trust_anchor(&fixture.anchor_path),
            Err(ConfigBundleError::Json(message))
                if message.contains("duplicate JSON object member")
        ));
    }

    #[test]
    fn trust_anchor_rejects_private_members_inside_public_jwks() {
        const PRIVATE_MARKER: &str = "PRIVATE_KEY_MATERIAL_MUST_NOT_SURVIVE";

        for member in ["d", "k", "oth"] {
            let fixture = fixture();
            let bytes = fs::read(&fixture.anchor_path).expect("anchor bytes");
            let mut anchor: serde_json::Value =
                serde_json::from_slice(&bytes).expect("anchor fixture JSON");
            anchor["enabled_signers"][0]["jwk"][member] = serde_json::json!(PRIVATE_MARKER);
            fs::write(
                &fixture.anchor_path,
                serde_json::to_vec_pretty(&anchor).expect("private anchor fixture"),
            )
            .expect("write private anchor fixture");

            let error = load_trust_anchor(&fixture.anchor_path)
                .expect_err("public trust anchors must reject private JWK members");
            let diagnostic = format!("{error:?} {error}");
            assert!(diagnostic.contains("public JWK contains private material"));
            assert!(!diagnostic.contains(PRIVATE_MARKER));
        }
    }

    #[test]
    fn rejects_every_acceptance_identity_dimension_mismatch() {
        let base = notary_identity();
        let mismatches = [
            (
                "trust_domain",
                ProductAcceptanceIdentityV1 {
                    trust_domain: ProductTrustDomainV1::Development,
                    ..base.clone()
                },
            ),
            (
                "project",
                ProductAcceptanceIdentityV1 {
                    project: "other-project".to_string(),
                    ..base.clone()
                },
            ),
            (
                "environment",
                ProductAcceptanceIdentityV1 {
                    environment: "staging".to_string(),
                    ..base.clone()
                },
            ),
            (
                "lane",
                ProductAcceptanceIdentityV1 {
                    lane: ProductAcceptanceLaneV1::RelayPublic,
                    product: ProductAcceptanceProductV1::RegistryRelay,
                    ..base.clone()
                },
            ),
            (
                "stream",
                ProductAcceptanceIdentityV1 {
                    stream: "other-stream".to_string(),
                    ..base.clone()
                },
            ),
            (
                "instance",
                ProductAcceptanceIdentityV1 {
                    instance: "notary-012".to_string(),
                    ..base
                },
            ),
        ];

        for (field, identity) in mismatches {
            let mut fixture = fixture();
            fixture.manifest.acceptance_identity = identity;
            write_manifest_and_signature(&fixture.bundle_dir, &fixture.manifest, &fixture.private);

            let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
                .expect_err("identity mismatch rejected");

            assert_eq!(err, ConfigBundleError::BindingMismatch(field), "{field}");
        }
    }

    #[test]
    fn rejects_invalid_lane_product_pair() {
        let mut fixture = fixture();
        fixture.manifest.acceptance_identity.product = ProductAcceptanceProductV1::RegistryRelay;
        write_manifest_and_signature(&fixture.bundle_dir, &fixture.manifest, &fixture.private);

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("invalid product rejected");

        assert_eq!(
            err,
            ConfigBundleError::InvalidAcceptanceIdentity("lane/product")
        );
    }

    #[test]
    fn acceptance_identity_validation_is_closed_and_bounded() {
        let mut identity = notary_identity();
        identity.project = "x".repeat(MAX_ACCEPTANCE_ID_COMPONENT_BYTES + 1);
        assert_eq!(
            identity.validate(),
            Err(ConfigBundleError::InvalidAcceptanceIdentity("project"))
        );

        let mut identity = notary_identity();
        identity.stream = "civil/registry".to_string();
        assert_eq!(
            identity.validate(),
            Err(ConfigBundleError::InvalidAcceptanceIdentity("stream"))
        );

        let mut identity = notary_identity();
        identity.instance.clear();
        assert_eq!(
            identity.validate(),
            Err(ConfigBundleError::InvalidAcceptanceIdentity("instance"))
        );

        let mut value = serde_json::to_value(notary_identity()).expect("identity JSON");
        value["trust_domain"] = json!("external");
        assert!(serde_json::from_value::<ProductAcceptanceIdentityV1>(value).is_err());

        let mut value = serde_json::to_value(notary_identity()).expect("identity JSON");
        value["lane"] = json!("relay");
        assert!(serde_json::from_value::<ProductAcceptanceIdentityV1>(value).is_err());
    }

    #[test]
    fn acceptance_identity_canonicalization_is_deterministic() {
        let expected = canonical_product_acceptance_identity(&notary_identity())
            .expect("canonical acceptance identity");
        let reordered: ProductAcceptanceIdentityV1 = serde_json::from_str(
            r#"{
                "instance":"notary-011",
                "stream":"civil-registration",
                "product":"registry-notary",
                "lane":"notary",
                "environment":"production",
                "project":"civil-registry",
                "trust_domain":"governed"
            }"#,
        )
        .expect("reordered identity");

        assert_eq!(
            canonical_product_acceptance_identity(&reordered)
                .expect("reordered canonical identity"),
            expected
        );
        assert_eq!(
            std::str::from_utf8(&expected).expect("canonical utf8"),
            r#"{"environment":"production","instance":"notary-011","lane":"notary","product":"registry-notary","project":"civil-registry","stream":"civil-registration","trust_domain":"governed"}"#
        );
    }

    #[test]
    fn verifies_canonical_anchor_transition_with_distinct_current_threshold() {
        let (_first, _second, current, next, transition) = signed_rotation_fixture();

        let verified =
            verify_anchor_transition(&current, &next, &transition).expect("rotation verified");

        assert_eq!(verified.len(), 2);
        assert_eq!(transition.payload.predecessor_anchor_version, 1);
        assert_eq!(transition.payload.next_anchor_version, 2);
        assert_eq!(
            transition.payload.predecessor_anchor_digest,
            trust_anchor_digest(&current).expect("current digest")
        );
        assert_eq!(
            transition.payload.next_anchor_digest,
            trust_anchor_digest(&next).expect("next digest")
        );
    }

    #[test]
    fn rejects_anchor_and_transition_threshold_failures() {
        let (first, _second, current, next, mut transition) = signed_rotation_fixture();

        let mut invalid_anchor = current.clone();
        invalid_anchor.threshold = 0;
        assert_eq!(
            invalid_anchor.validate(),
            Err(ConfigBundleError::InvalidTrustAnchor("threshold"))
        );
        invalid_anchor.threshold = 3;
        assert_eq!(
            invalid_anchor.validate(),
            Err(ConfigBundleError::InvalidTrustAnchor("threshold"))
        );

        sign_anchor_transition(&mut transition, &[&first]);
        assert_eq!(
            verify_anchor_transition(&current, &next, &transition),
            Err(ConfigBundleError::AnchorTransitionRejected("signatures"))
        );
    }

    #[test]
    fn rejects_anchor_rotation_without_current_threshold_overlap() {
        let first = PrivateJwk::parse(ED25519_PRIVATE_JWK).expect("first private key");
        let second = PrivateJwk::parse(ED25519_ROTATED_PRIVATE_JWK).expect("second private key");
        let current = anchor_from_keys(notary_identity(), 1, 2, &[&first, &second]);
        let next = anchor_from_keys(notary_identity(), 2, 1, &[&first]);

        assert_eq!(
            AnchorTransitionV1::unsigned(&current, &next),
            Err(ConfigBundleError::AnchorTransitionRejected(
                "signer_overlap"
            ))
        );
    }

    #[test]
    fn rejects_anchor_rotation_identity_change_before_signing() {
        let first = PrivateJwk::parse(ED25519_PRIVATE_JWK).expect("first private key");
        let current = anchor_from_keys(notary_identity(), 1, 1, &[&first]);
        let mut next_identity = notary_identity();
        next_identity.instance = "notary-012".to_string();
        let next = anchor_from_keys(next_identity, 2, 1, &[&first]);

        assert_eq!(
            AnchorTransitionV1::unsigned(&current, &next),
            Err(ConfigBundleError::AnchorTransitionRejected(
                "acceptance_identity"
            ))
        );
    }

    #[test]
    fn rejects_transition_identity_change_and_incomplete_next_signer_set() {
        let (_first, _second, current, next, mut transition) = signed_rotation_fixture();
        transition.payload.acceptance_identity.instance = "notary-012".to_string();
        assert_eq!(
            verify_anchor_transition(&current, &next, &transition),
            Err(ConfigBundleError::AnchorTransitionRejected(
                "acceptance_identity"
            ))
        );

        let (_first, _second, current, next, mut transition) = signed_rotation_fixture();
        transition.payload.next_enabled_signers.pop();
        assert_eq!(
            verify_anchor_transition(&current, &next, &transition),
            Err(ConfigBundleError::AnchorTransitionRejected(
                "next_enabled_signers"
            ))
        );
    }

    #[test]
    fn rejects_wrong_anchor_transition_predecessor() {
        let (_first, _second, current, next, mut transition) = signed_rotation_fixture();
        transition.payload.predecessor_anchor_digest = sha256_uri(b"wrong predecessor");

        assert_eq!(
            verify_anchor_transition(&current, &next, &transition),
            Err(ConfigBundleError::AnchorTransitionRejected(
                "predecessor_anchor_digest"
            ))
        );

        let (_first, _second, current, next, mut transition) = signed_rotation_fixture();
        transition.payload.predecessor_anchor_version = 2;
        assert_eq!(
            verify_anchor_transition(&current, &next, &transition),
            Err(ConfigBundleError::AnchorTransitionRejected(
                "predecessor_anchor_version"
            ))
        );
    }

    #[test]
    fn anchor_transition_payload_canonicalization_is_deterministic() {
        let (_first, _second, _current, _next, transition) = signed_rotation_fixture();
        let expected =
            canonical_anchor_transition_payload(&transition).expect("canonical transition");
        let value = serde_json::to_value(&transition).expect("transition value");
        let reparsed: AnchorTransitionV1 =
            serde_json::from_value(value).expect("reparsed transition");

        assert_eq!(
            canonical_anchor_transition_payload(&reparsed).expect("reparsed canonical transition"),
            expected
        );
    }

    #[test]
    fn rejects_unknown_fields_in_identity_anchor_and_transition() {
        let fixture = fixture();
        let anchor: ConfigTrustAnchor =
            serde_json::from_slice(&fs::read(&fixture.anchor_path).expect("anchor bytes"))
                .expect("anchor");
        let mut anchor_value = serde_json::to_value(anchor).expect("anchor value");
        anchor_value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<ConfigTrustAnchor>(anchor_value).is_err());

        let mut identity_value = serde_json::to_value(notary_identity()).expect("identity value");
        identity_value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<ProductAcceptanceIdentityV1>(identity_value).is_err());

        let (_first, _second, _current, _next, transition) = signed_rotation_fixture();
        let mut transition_value = serde_json::to_value(transition).expect("transition value");
        transition_value["payload"]["unexpected"] = json!(true);
        let bytes = serde_json::to_vec(&transition_value).expect("transition bytes");
        assert!(matches!(
            parse_anchor_transition(&bytes),
            Err(ConfigBundleError::Json(_))
        ));
    }

    #[test]
    fn rejects_oversized_anchor_transition_document() {
        let oversized = vec![b' '; MAX_ANCHOR_TRANSITION_BYTES + 1];

        assert_eq!(
            parse_anchor_transition(&oversized),
            Err(ConfigBundleError::InvalidAnchorTransition("document size"))
        );
    }

    #[test]
    fn rejects_duplicate_anchor_transition_signatures() {
        let (_first, _second, current, next, mut transition) = signed_rotation_fixture();
        transition.signatures.push(transition.signatures[0].clone());

        assert_eq!(
            verify_anchor_transition(&current, &next, &transition),
            Err(ConfigBundleError::InvalidAnchorTransition(
                "duplicate signature kid"
            ))
        );
    }

    #[test]
    fn initial_anchor_requires_version_one() {
        let first = PrivateJwk::parse(ED25519_PRIVATE_JWK).expect("first private key");
        let initial = anchor_from_keys(notary_identity(), 1, 1, &[&first]);
        assert!(initial.validate_initial().is_ok());

        let rotated = anchor_from_keys(notary_identity(), 2, 1, &[&first]);
        assert_eq!(
            rotated.validate_initial(),
            Err(ConfigBundleError::InvalidTrustAnchor("initial version"))
        );
    }

    #[test]
    fn rejects_sequence_outside_interop_safe_range() {
        let mut fixture = fixture();
        fixture.manifest.sequence = MAX_CONFIG_BUNDLE_SEQUENCE + 1;
        write_manifest_and_signature(&fixture.bundle_dir, &fixture.manifest, &fixture.private);

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("sequence rejected");

        assert_eq!(err, ConfigBundleError::InvalidManifest("sequence"));
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let fixture = fixture();
        let mut value = serde_json::to_value(&fixture.manifest).expect("manifest value");
        value["unexpected"] = json!(true);
        fs::write(
            fixture.bundle_dir.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&value).expect("manifest json"),
        )
        .expect("manifest");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("unknown field rejected");

        assert!(matches!(err, ConfigBundleError::Json(_)));
    }

    #[test]
    fn rejects_signature_before_classifying_binding_mismatch() {
        let mut fixture = fixture();
        fixture.manifest.acceptance_identity.environment = "staging".to_string();
        fs::write(
            fixture.bundle_dir.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&fixture.manifest).expect("manifest json"),
        )
        .expect("manifest");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("tampered manifest rejected by signature first");

        assert_eq!(err, ConfigBundleError::SignatureRejected);
    }

    #[test]
    fn rejects_present_but_unlisted_regular_file() {
        let fixture = fixture();
        fs::write(fixture.bundle_dir.join("config/extra.yaml"), b"extra").expect("extra");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("unlisted file rejected");

        assert!(
            matches!(err, ConfigBundleError::FileClosure(reason) if reason.contains("unlisted"))
        );
    }

    #[test]
    fn rejects_listed_but_missing_regular_file() {
        let fixture = fixture();
        fs::remove_file(fixture.bundle_dir.join("config/notary.yaml")).expect("remove");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("missing file rejected");

        assert!(
            matches!(err, ConfigBundleError::FileClosure(reason) if reason.contains("missing"))
        );
    }

    #[test]
    fn rejects_changed_bytes_at_manifest_config_path() {
        let fixture = fixture();
        fs::write(fixture.bundle_dir.join("config/notary.yaml"), b"changed").expect("rewrite");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("changed config rejected");

        assert!(
            matches!(err, ConfigBundleError::HashMismatch { path, .. } if path == "config/notary.yaml")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_regular_bundle_entry() {
        use std::os::unix::net::UnixListener;

        let fixture = fixture();
        let socket_path = fixture.bundle_dir.join("config/notary.sock");
        let _listener = UnixListener::bind(&socket_path).expect("socket");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("socket entry rejected");

        assert!(
            matches!(err, ConfigBundleError::FileClosure(reason) if reason.contains("unsupported file type"))
        );
    }

    #[test]
    fn rejects_duplicate_paths_after_normalization() {
        let mut fixture = fixture();
        fixture.manifest.files.push(ConfigBundleFile {
            path: "config//notary.yaml".to_string(),
            sha256: fixture.manifest.config_hash.clone(),
        });
        write_manifest_and_signature(&fixture.bundle_dir, &fixture.manifest, &fixture.private);

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("duplicate rejected");

        assert!(matches!(err, ConfigBundleError::FileClosure(_)));
    }

    #[test]
    fn rejects_absolute_and_traversal_bundle_paths() {
        for bad_path in ["/config/notary.yaml", "config/../notary.yaml"] {
            let mut fixture = fixture();
            fixture.manifest.files[0].path = bad_path.to_string();
            write_manifest_and_signature(&fixture.bundle_dir, &fixture.manifest, &fixture.private);

            let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
                .expect_err("bad path rejected");

            assert!(matches!(err, ConfigBundleError::FileClosure(_)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_writable_trust_anchor() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = fixture();
        let mut permissions = fs::metadata(&fixture.anchor_path)
            .expect("anchor metadata")
            .permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&fixture.anchor_path, permissions).expect("permissions set");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("group writable anchor rejected");

        assert!(matches!(err, ConfigBundleError::InvalidPermissions(_)));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_permission_validation_observes_open_descriptor() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = fixture();
        let mut permissions = fs::metadata(&fixture.anchor_path)
            .expect("anchor metadata")
            .permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&fixture.anchor_path, permissions).expect("permissions set");
        let opened = open_read_only_no_follow(&fixture.anchor_path).expect("anchor opens");
        let anchor: ConfigTrustAnchor =
            serde_json::from_slice(&fs::read(&fixture.anchor_path).expect("anchor"))
                .expect("anchor");
        fs::remove_file(&fixture.anchor_path).expect("remove original path");
        fs::write(
            &fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor json"),
        )
        .expect("replacement writes");
        let mut replacement_permissions = fs::metadata(&fixture.anchor_path)
            .expect("replacement metadata")
            .permissions();
        replacement_permissions.set_mode(0o600);
        fs::set_permissions(&fixture.anchor_path, replacement_permissions)
            .expect("replacement permissions set");

        let err = read_limited_from_file(
            opened,
            MAX_TRUST_ANCHOR_BYTES,
            Some(ArtifactPermissions::TrustAnchor),
        )
        .expect_err("opened descriptor permissions are enforced");

        assert!(matches!(err, ConfigBundleError::InvalidPermissions(_)));
        assert!(load_trust_anchor(&fixture.anchor_path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn break_glass_permission_validation_observes_open_descriptor() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("break_glass_override.json");
        fs::write(&path, b"{}").expect("override");
        let mut permissions = fs::metadata(&path)
            .expect("override metadata")
            .permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&path, permissions).expect("permissions set");
        let opened = open_read_only_no_follow(&path).expect("override opens");
        fs::remove_file(&path).expect("remove original path");
        fs::write(&path, b"{}").expect("replacement writes");
        let mut replacement_permissions = fs::metadata(&path)
            .expect("replacement metadata")
            .permissions();
        replacement_permissions.set_mode(0o600);
        fs::set_permissions(&path, replacement_permissions).expect("replacement permissions set");

        let err = read_limited_from_file(
            opened,
            MAX_SIGNATURE_ENVELOPE_BYTES,
            Some(ArtifactPermissions::BreakGlassOverride),
        )
        .expect_err("opened descriptor permissions are enforced");

        assert!(matches!(
            err,
            ConfigBundleError::InvalidPermissions(
                "break-glass override must not be group/world writable"
            )
        ));
    }

    #[test]
    fn rejects_manifest_signature_below_anchor_threshold() {
        let fixture = fixture();
        let mut anchor: ConfigTrustAnchor =
            serde_json::from_slice(&fs::read(&fixture.anchor_path).expect("anchor"))
                .expect("anchor");
        let rotated = PrivateJwk::parse(ED25519_ROTATED_PRIVATE_JWK).expect("rotated private");
        let rotated_public = rotated.public();
        anchor.enabled_signers.push(ConfigTrustAnchorSigner {
            kid: rotated_public.jkt().expect("rotated kid"),
            jwk: rotated_public,
        });
        anchor
            .enabled_signers
            .sort_by(|left, right| left.kid.cmp(&right.kid));
        anchor.threshold = 2;
        fs::write(
            &fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor json"),
        )
        .expect("anchor");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("sub-threshold signature rejected");

        assert_eq!(err, ConfigBundleError::SignatureRejected);
    }

    #[test]
    fn rejects_anchor_kid_jwk_mismatch() {
        let fixture = fixture();
        let mut anchor: ConfigTrustAnchor =
            serde_json::from_slice(&fs::read(&fixture.anchor_path).expect("anchor"))
                .expect("anchor");
        anchor.enabled_signers[0].kid = "not-the-thumbprint".to_string();
        fs::write(
            &fixture.anchor_path,
            serde_json::to_vec_pretty(&anchor).expect("anchor json"),
        )
        .expect("anchor");

        let err = verify_config_bundle(&fixture.bundle_dir, &fixture.anchor_path)
            .expect_err("kid mismatch rejected");

        assert_eq!(
            err,
            ConfigBundleError::InvalidTrustAnchor("kid/jwk mismatch")
        );
    }

    #[test]
    fn break_glass_rejects_relative_unsigned_path() {
        let override_file = ConfigBreakGlassOverride {
            schema: BREAK_GLASS_SCHEMA.to_string(),
            mode: ConfigBreakGlassMode::AcceptUnsigned,
            config_hash: sha256_uri(b"rollback"),
            config_path: Some(PathBuf::from("rollback.yaml")),
            reason: "control plane unavailable".to_string(),
            operator: "jeremi".to_string(),
            created_at: "2099-07-07T10:00:00Z".to_string(),
            expires_at: "2099-07-07T12:00:00Z".to_string(),
        };

        let err = override_file
            .validate_fields()
            .expect_err("relative path rejected");

        assert_eq!(
            err,
            ConfigBundleError::InvalidBreakGlass("unsigned config_path")
        );
    }

    #[test]
    fn break_glass_rejects_expired_or_too_long_windows() {
        let mut override_file = ConfigBreakGlassOverride {
            schema: BREAK_GLASS_SCHEMA.to_string(),
            mode: ConfigBreakGlassMode::AcceptRollback,
            config_hash: sha256_uri(b"rollback"),
            config_path: None,
            reason: "signed rollback".to_string(),
            operator: "jeremi".to_string(),
            created_at: "2099-07-07T10:00:00Z".to_string(),
            expires_at: "2099-07-09T10:00:00Z".to_string(),
        };

        let too_long = override_file
            .validate_fields()
            .expect_err("window over 24h rejected");
        assert_eq!(too_long, ConfigBundleError::InvalidBreakGlass("expires_at"));

        override_file.created_at = "2000-07-07T10:00:00Z".to_string();
        override_file.expires_at = "2000-07-07T12:00:00Z".to_string();
        let expired = override_file
            .validate_fields()
            .expect_err("expired override rejected");
        assert_eq!(expired, ConfigBundleError::InvalidBreakGlass("expired"));
    }

    #[test]
    fn break_glass_rejects_duplicate_json_members_before_interpretation() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("break_glass_override.json");
        fs::write(&path, br#"{"schema":"first","schema":"second"}"#).expect("override fixture");

        let bytes = fs::read(&path).expect("override bytes");
        assert!(matches!(
            deserialize_strict::<ConfigBreakGlassOverride>(&bytes),
            Err(ConfigBundleError::Json(message))
                if message.contains("duplicate JSON object member")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_writable_break_glass_file_before_use() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("break_glass_override.json");
        fs::write(&path, b"{}").expect("override");
        let mut permissions = fs::metadata(&path)
            .expect("override metadata")
            .permissions();
        permissions.set_mode(0o664);
        fs::set_permissions(&path, permissions).expect("permissions set");

        let err = load_break_glass_override(&path).expect_err("mode rejected");

        assert!(matches!(err, ConfigBundleError::InvalidPermissions(_)));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_regular_break_glass_file_without_waiting() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("break_glass_override.json");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo command runs");
        assert!(status.success(), "mkfifo exits successfully");

        let err = load_break_glass_override(&path).expect_err("non-regular override rejected");

        assert!(matches!(
            err,
            ConfigBundleError::InvalidPermissions("path must be a regular file")
        ));
    }
}
