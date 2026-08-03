// SPDX-License-Identifier: Apache-2.0

//! Fixed two-lane Relay approved baseline set assembly.
//!
//! This module deliberately does not make an approved set a signature or an
//! activation authority. Product-specific verification remains responsible
//! for constructing [`VerifiedApprovedLaneV1`]. Assembly then proves that all
//! two independently verified lanes form one compatible governed set.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use registry_platform_config::{
    load_anchor_transition, load_trust_anchor, sha256_uri, trust_anchor_digest,
    verify_anchor_transition, verify_config_bundle, ConfigBundleManifest,
    ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1, ProductAcceptanceProductV1,
    ProductTrustDomainV1, MAX_BUNDLE_FILE_BYTES, MAX_CONFIG_BUNDLE_SEQUENCE,
};
use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use serde::{Deserialize, Serialize};

pub const APPROVED_BASELINE_SET_SCHEMA_ID: &str = "registry.stack.approved_baseline_set";
pub const APPROVED_BASELINE_SET_SCHEMA_VERSION: &str = "1.0";
pub const MAX_APPROVED_BASELINE_SET_BYTES: u64 = 1024 * 1024;
const MAX_PORTABLE_LOCATOR_BYTES: usize = 1024;
const MAX_ANCHOR_TRANSITIONS: usize = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum ApprovedLaneV1 {
    #[serde(rename = "relay-public")]
    RelayPublic,
    #[serde(rename = "relay-consultation")]
    RelayConsultation,
}

impl ApprovedLaneV1 {
    pub const ALL: [Self; 2] = [Self::RelayPublic, Self::RelayConsultation];

    pub const fn acceptance_lane(self) -> ProductAcceptanceLaneV1 {
        match self {
            Self::RelayPublic => ProductAcceptanceLaneV1::RelayPublic,
            Self::RelayConsultation => ProductAcceptanceLaneV1::RelayConsultation,
        }
    }

    pub const fn product(self) -> ProductAcceptanceProductV1 {
        match self {
            Self::RelayPublic | Self::RelayConsultation => {
                ProductAcceptanceProductV1::RegistryRelay
            }
        }
    }

    pub fn try_from_acceptance_lane(lane: ProductAcceptanceLaneV1) -> Result<Self> {
        match lane {
            ProductAcceptanceLaneV1::RelayPublic => Ok(Self::RelayPublic),
            ProductAcceptanceLaneV1::RelayConsultation => Ok(Self::RelayConsultation),
            _ => bail!("acceptance lane is not supported by registryctl"),
        }
    }

    pub const fn closure_name(self) -> &'static str {
        match self {
            Self::RelayPublic => "relay",
            Self::RelayConsultation => "relay_consultation",
        }
    }
}

impl fmt::Display for ApprovedLaneV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RelayPublic => "relay-public",
            Self::RelayConsultation => "relay-consultation",
        })
    }
}

/// A package-portable locator relative to a verifier-selected closure root.
///
/// Absolute paths, parent traversal, platform prefixes, URL-like strings, and
/// backslashes are rejected so a portable artifact cannot retain a source
/// host path. A verifier chooses the closure root for its context, such as the
/// approved-set document directory for a standalone handoff or `generated/`
/// for a deployment package, and resolution rejects symlinks and escape from
/// that root.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct PortableArtifactLocator(String);

impl PortableArtifactLocator {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let locator = Self(value.into());
        locator.validate()?;
        Ok(locator)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    fn validate(&self) -> Result<()> {
        if self.0.is_empty()
            || self.0.len() > MAX_PORTABLE_LOCATOR_BYTES
            || !self.0.is_ascii()
            || self.0.contains('\\')
            || self.0.contains(':')
            || self.0.ends_with('/')
            || self.0.contains("//")
            || self.0.bytes().any(|byte| byte.is_ascii_control())
        {
            bail!("approved-set artifact locator is not a bounded portable relative path");
        }
        let path = Path::new(&self.0);
        if path.is_absolute() {
            bail!("approved-set artifact locator must be relative");
        }
        let mut components = 0usize;
        for component in path.components() {
            match component {
                Component::Normal(value) if !value.is_empty() => components += 1,
                _ => bail!("approved-set artifact locator contains a non-portable component"),
            }
        }
        if components == 0 {
            bail!("approved-set artifact locator must identify an artifact");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedAnchorTransitionLinkV1 {
    pub predecessor_anchor: PortableArtifactLocator,
    pub transition: PortableArtifactLocator,
}

impl ApprovedAnchorTransitionLinkV1 {
    fn validate(&self) -> Result<()> {
        self.predecessor_anchor.validate()?;
        self.transition.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedLaneLocatorsV1 {
    pub bundle: PortableArtifactLocator,
    pub signed_manifest: PortableArtifactLocator,
    pub anchor: PortableArtifactLocator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchor_transitions: Vec<ApprovedAnchorTransitionLinkV1>,
}

impl ApprovedLaneLocatorsV1 {
    fn validate(&self) -> Result<()> {
        self.bundle.validate()?;
        self.signed_manifest.validate()?;
        self.anchor.validate()?;
        if self.anchor_transitions.len() > MAX_ANCHOR_TRANSITIONS {
            bail!("approved-set anchor transition chain exceeds its bounded length");
        }
        let mut seen = BTreeSet::new();
        for link in &self.anchor_transitions {
            link.validate()?;
            if !seen.insert(&link.predecessor_anchor) || !seen.insert(&link.transition) {
                bail!("approved-set anchor transition chain contains a duplicate locator");
            }
        }
        if seen.contains(&self.anchor) {
            bail!("approved-set terminal anchor duplicates a history locator");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedLaneBindingV1 {
    pub lane_scoped_reviewed_input_digest: String,
    pub signing_input_closure_digest: String,
}

impl ReviewedLaneBindingV1 {
    fn validate_for_lane(&self, _lane: ApprovedLaneV1) -> Result<()> {
        validate_sha256_digest(
            &self.lane_scoped_reviewed_input_digest,
            "lane-scoped reviewed-input digest",
        )?;
        validate_sha256_digest(
            &self.signing_input_closure_digest,
            "signing-input closure digest",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedLaneEntryV1 {
    pub locators: ApprovedLaneLocatorsV1,
    pub signed_manifest_digest: String,
    pub bundle_digest: String,
    pub anchor_digest: String,
    pub lane_scoped_reviewed_input_digest: String,
    pub signing_input_closure_digest: String,
}

impl ApprovedLaneEntryV1 {
    pub fn reviewed_binding(&self) -> ReviewedLaneBindingV1 {
        ReviewedLaneBindingV1 {
            lane_scoped_reviewed_input_digest: self.lane_scoped_reviewed_input_digest.clone(),
            signing_input_closure_digest: self.signing_input_closure_digest.clone(),
        }
    }

    fn validate_for_lane(&self, lane: ApprovedLaneV1) -> Result<()> {
        self.locators.validate()?;
        validate_sha256_digest(&self.signed_manifest_digest, "signed manifest digest")?;
        validate_sha256_digest(&self.bundle_digest, "bundle digest")?;
        validate_sha256_digest(&self.anchor_digest, "anchor digest")?;
        self.reviewed_binding().validate_for_lane(lane)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedBaselineLanesV1 {
    #[serde(rename = "relay-public")]
    pub relay_public: ApprovedLaneEntryV1,
    #[serde(rename = "relay-consultation")]
    pub relay_consultation: ApprovedLaneEntryV1,
}

impl ApprovedBaselineLanesV1 {
    pub fn get(&self, lane: ApprovedLaneV1) -> &ApprovedLaneEntryV1 {
        match lane {
            ApprovedLaneV1::RelayPublic => &self.relay_public,
            ApprovedLaneV1::RelayConsultation => &self.relay_consultation,
        }
    }

    fn validate(&self) -> Result<()> {
        for lane in ApprovedLaneV1::ALL {
            self.get(lane).validate_for_lane(lane)?;
        }

        let bundle_locators =
            ApprovedLaneV1::ALL.map(|lane| self.get(lane).locators.bundle.as_str());
        if bundle_locators.into_iter().collect::<BTreeSet<_>>().len() != 2 {
            bail!("approved set contains a duplicated lane bundle locator");
        }
        let manifest_locators =
            ApprovedLaneV1::ALL.map(|lane| self.get(lane).locators.signed_manifest.as_str());
        if manifest_locators.into_iter().collect::<BTreeSet<_>>().len() != 2 {
            bail!("approved set contains a duplicated lane manifest locator");
        }
        let anchor_locators =
            ApprovedLaneV1::ALL.map(|lane| self.get(lane).locators.anchor.as_str());
        if anchor_locators.into_iter().collect::<BTreeSet<_>>().len() != 2 {
            bail!("approved set contains a duplicated lane anchor locator");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedBaselineSetV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub lanes: ApprovedBaselineLanesV1,
}

impl ApprovedBaselineSetV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_id != APPROVED_BASELINE_SET_SCHEMA_ID {
            bail!("approved-set schema_id is unsupported");
        }
        if self.schema_version != APPROVED_BASELINE_SET_SCHEMA_VERSION {
            bail!("approved-set schema_version is unsupported");
        }
        self.lanes.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("failed to serialize approved baseline set")?;
        canonicalize_json(&value).context("failed to canonicalize approved baseline set")
    }

    pub fn digest(&self) -> Result<String> {
        Ok(sha256_uri(&self.canonical_bytes()?))
    }
}

/// Evidence returned only after independent bundle, manifest, anchor, and
/// optional transition-chain verification.
///
/// The complete acceptance identity and manifest lineage remain outside the
/// serialized set. They are retained here so assembly can compare all identity
/// fields and enforce initial/update sequence semantics without turning the set
/// into an activation document.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedApprovedLaneV1 {
    lane: ApprovedLaneV1,
    acceptance_identity: ProductAcceptanceIdentityV1,
    manifest_sequence: u64,
    config_hash: String,
    previous_config_hash: Option<String>,
    anchor_chain_digests: Vec<String>,
    entry: ApprovedLaneEntryV1,
}

impl VerifiedApprovedLaneV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_independent_verification(
        lane: ApprovedLaneV1,
        acceptance_identity: ProductAcceptanceIdentityV1,
        manifest_sequence: u64,
        config_hash: String,
        previous_config_hash: Option<String>,
        entry: ApprovedLaneEntryV1,
    ) -> Result<Self> {
        acceptance_identity
            .validate()
            .context("verified lane acceptance identity is invalid")?;
        if acceptance_identity.trust_domain != ProductTrustDomainV1::Governed {
            bail!("verified approved lane must use the governed trust domain");
        }
        if acceptance_identity.lane != lane.acceptance_lane()
            || acceptance_identity.product != lane.product()
        {
            bail!("verified acceptance identity does not match the selected approved lane");
        }
        if manifest_sequence == 0 || manifest_sequence > MAX_CONFIG_BUNDLE_SEQUENCE {
            bail!("verified lane manifest sequence is invalid");
        }
        validate_sha256_digest(&config_hash, "verified lane configuration hash")?;
        if let Some(previous) = &previous_config_hash {
            validate_sha256_digest(previous, "verified lane previous configuration hash")?;
        }
        entry.validate_for_lane(lane)?;
        let terminal_anchor_digest = entry.anchor_digest.clone();
        Ok(Self {
            lane,
            acceptance_identity,
            manifest_sequence,
            config_hash,
            previous_config_hash,
            anchor_chain_digests: vec![terminal_anchor_digest],
            entry,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn from_verified_artifacts(
        lane: ApprovedLaneV1,
        acceptance_identity: ProductAcceptanceIdentityV1,
        manifest_sequence: u64,
        config_hash: String,
        previous_config_hash: Option<String>,
        anchor_chain_digests: Vec<String>,
        entry: ApprovedLaneEntryV1,
    ) -> Result<Self> {
        let mut verified = Self::from_independent_verification(
            lane,
            acceptance_identity,
            manifest_sequence,
            config_hash,
            previous_config_hash,
            entry,
        )?;
        if anchor_chain_digests.is_empty()
            || anchor_chain_digests.last() != Some(&verified.entry.anchor_digest)
        {
            bail!("verified anchor chain does not terminate at the selected lane anchor");
        }
        for digest in &anchor_chain_digests {
            validate_sha256_digest(digest, "verified anchor-chain digest")?;
        }
        verified.anchor_chain_digests = anchor_chain_digests;
        Ok(verified)
    }

    #[allow(dead_code)]
    pub fn lane(&self) -> ApprovedLaneV1 {
        self.lane
    }

    pub fn acceptance_identity(&self) -> &ProductAcceptanceIdentityV1 {
        &self.acceptance_identity
    }

    #[allow(dead_code)]
    pub fn entry(&self) -> &ApprovedLaneEntryV1 {
        &self.entry
    }

    pub(crate) fn manifest_sequence(&self) -> u64 {
        self.manifest_sequence
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "integration rejection tests include this module directly"
    )]
    pub(crate) fn with_test_anchor_chain(mut self, anchor_chain_digests: Vec<String>) -> Self {
        self.entry.anchor_digest = anchor_chain_digests
            .last()
            .expect("test anchor chain is non-empty")
            .clone();
        self.anchor_chain_digests = anchor_chain_digests;
        self
    }

    pub(crate) fn config_hash(&self) -> &str {
        &self.config_hash
    }
}

#[derive(Debug, Clone)]
pub struct InitialApprovedSetInputs {
    pub relay_public: PathBuf,
    pub relay_consultation: PathBuf,
}

impl InitialApprovedSetInputs {
    fn get(&self, lane: ApprovedLaneV1) -> &Path {
        match lane {
            ApprovedLaneV1::RelayPublic => &self.relay_public,
            ApprovedLaneV1::RelayConsultation => &self.relay_consultation,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AffectedLaneReplacements {
    pub relay_public: Option<PathBuf>,
    pub relay_consultation: Option<PathBuf>,
}

impl AffectedLaneReplacements {
    fn get(&self, lane: ApprovedLaneV1) -> Option<&Path> {
        match lane {
            ApprovedLaneV1::RelayPublic => self.relay_public.as_deref(),
            ApprovedLaneV1::RelayConsultation => self.relay_consultation.as_deref(),
        }
    }
}

/// The exact affected-lane closure emitted by a reviewed build.
///
/// `Some` means affected and carries the signed input closure the replacement
/// must bind. `None` means the preceding verified lane must be carried forward
/// byte-for-byte at the approved-set entry level.
#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedBuildUpdateV1 {
    pub relay_public: Option<ReviewedLaneBindingV1>,
    pub relay_consultation: Option<ReviewedLaneBindingV1>,
}

impl ReviewedBuildUpdateV1 {
    pub fn affected_lanes(&self) -> Vec<ApprovedLaneV1> {
        ApprovedLaneV1::ALL
            .into_iter()
            .filter(|lane| self.get(*lane).is_some())
            .collect()
    }

    pub fn get(&self, lane: ApprovedLaneV1) -> Option<&ReviewedLaneBindingV1> {
        match lane {
            ApprovedLaneV1::RelayPublic => self.relay_public.as_ref(),
            ApprovedLaneV1::RelayConsultation => self.relay_consultation.as_ref(),
        }
    }

    pub(crate) fn validate_bindings(&self) -> Result<()> {
        for lane in ApprovedLaneV1::ALL {
            if let Some(binding) = self.get(lane) {
                binding.validate_for_lane(lane)?;
            }
        }
        Ok(())
    }

    fn validate_update(&self) -> Result<()> {
        self.validate_bindings()?;
        if self.affected_lanes().is_empty() {
            bail!("approved-set update requires at least one reviewed affected lane");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum LaneVerificationSourceV1 {
    LaneDirectory(PathBuf),
    PrecedingApprovedEntry {
        set_file: PathBuf,
        entry: Box<ApprovedLaneEntryV1>,
    },
}

#[derive(Debug, Clone)]
pub struct LaneVerificationRequestV1 {
    pub lane: ApprovedLaneV1,
    pub source: LaneVerificationSourceV1,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApprovedSetAssemblyReportV1 {
    pub approved_set: ApprovedBaselineSetV1,
    pub approved_set_digest: String,
    pub affected_lanes: Vec<ApprovedLaneV1>,
    pub output_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ApprovedSetAssembleOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    pub preceding_set: Option<PathBuf>,
    pub relay_public: Option<PathBuf>,
    pub relay_consultation: Option<PathBuf>,
    pub output_file: PathBuf,
}

impl ApprovedSetAssembleOptions {
    fn replacement(&self, lane: ApprovedLaneV1) -> Option<&Path> {
        match lane {
            ApprovedLaneV1::RelayPublic => self.relay_public.as_deref(),
            ApprovedLaneV1::RelayConsultation => self.relay_consultation.as_deref(),
        }
    }
}

pub fn assemble_approved_set(
    options: &ApprovedSetAssembleOptions,
) -> Result<ApprovedSetAssemblyReportV1> {
    validate_absent_output_file(&options.output_file)?;
    let reviewed_build = crate::project_authoring::load_current_reviewed_build_record(
        &options.project_directory,
        &options.environment,
    )?;
    if reviewed_build.project
        != crate::project_authoring::reviewed_project_id(
            &options.project_directory,
            &options.environment,
        )?
        || reviewed_build.environment != options.environment
    {
        bail!("reviewed build does not match the selected project and environment");
    }
    reviewed_build.validate()?;

    let output_parent = options
        .output_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output_parent = fs::canonicalize(output_parent)
        .context("failed to resolve approved-set output directory")?;

    if let Some(preceding_file) = &options.preceding_set {
        if reviewed_build.preceding_approved_set_digest.as_deref()
            != Some(
                load_approved_baseline_set(preceding_file)?
                    .digest()?
                    .as_str(),
            )
        {
            bail!("reviewed build is not bound to the selected preceding approved set");
        }
        let replacements = AffectedLaneReplacements {
            relay_public: options.relay_public.clone(),
            relay_consultation: options.relay_consultation.clone(),
        };
        return assemble_updated_approved_set(
            preceding_file,
            &reviewed_build.bindings,
            &reviewed_build.anchor_rotation_lanes,
            &replacements,
            &options.output_file,
            |request| match &request.source {
                LaneVerificationSourceV1::PrecedingApprovedEntry { set_file, entry: _ } => {
                    let root = set_file
                        .parent()
                        .filter(|parent| !parent.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."));
                    let closure_root = fs::canonicalize(root)
                        .context("failed to resolve preceding approved-set closure root")?;
                    verify_lane_request(request, &closure_root)
                }
                LaneVerificationSourceV1::LaneDirectory(_) => {
                    verify_lane_request(request, &output_parent)
                }
            },
        );
    }

    if reviewed_build.preceding_approved_set_digest.is_some()
        || reviewed_build.affected_lanes != ApprovedLaneV1::ALL
        || ApprovedLaneV1::ALL
            .into_iter()
            .any(|lane| options.replacement(lane).is_none())
    {
        bail!("initial approved-set assembly requires one reviewed replacement for every lane");
    }
    let inputs = InitialApprovedSetInputs {
        relay_public: options.relay_public.clone().expect("all lanes checked"),
        relay_consultation: options
            .relay_consultation
            .clone()
            .expect("all lanes checked"),
    };
    assemble_initial_approved_set(&inputs, &options.output_file, |request| {
        let lane = request.lane;
        let verified = verify_lane_request(request, &output_parent)?;
        if reviewed_build.bindings.get(lane) != Some(&verified.entry.reviewed_binding()) {
            bail!("initial signed lane does not match the reviewed build closure");
        }
        Ok(verified)
    })
}

pub fn assemble_initial_approved_set(
    inputs: &InitialApprovedSetInputs,
    output_file: &Path,
    mut verify: impl FnMut(LaneVerificationRequestV1) -> Result<VerifiedApprovedLaneV1>,
) -> Result<ApprovedSetAssemblyReportV1> {
    validate_absent_output_file(output_file)?;
    let mut verified = Vec::with_capacity(2);
    for lane in ApprovedLaneV1::ALL {
        let request = LaneVerificationRequestV1 {
            lane,
            source: LaneVerificationSourceV1::LaneDirectory(inputs.get(lane).to_path_buf()),
        };
        let lane_evidence =
            verify(request).map_err(|_| anyhow!("independent verification failed for {lane}"))?;
        validate_verifier_lane(lane, &lane_evidence)?;
        if lane_evidence.manifest_sequence != 1 || lane_evidence.previous_config_hash.is_some() {
            bail!("initial approved lane must use sequence 1 without a predecessor hash");
        }
        verified.push(lane_evidence);
    }

    validate_identity_set(&verified)?;
    let approved_set = set_from_verified(&verified)?;
    publish_approved_set(approved_set, ApprovedLaneV1::ALL.to_vec(), output_file)
}

pub fn assemble_updated_approved_set(
    preceding_set_file: &Path,
    reviewed_build: &ReviewedBuildUpdateV1,
    anchor_rotation_lanes: &[ApprovedLaneV1],
    replacements: &AffectedLaneReplacements,
    output_file: &Path,
    mut verify: impl FnMut(LaneVerificationRequestV1) -> Result<VerifiedApprovedLaneV1>,
) -> Result<ApprovedSetAssemblyReportV1> {
    validate_absent_output_file(output_file)?;
    reviewed_build.validate_update()?;
    let expected_rotation_lanes = ApprovedLaneV1::ALL
        .into_iter()
        .filter(|lane| anchor_rotation_lanes.contains(lane))
        .collect::<Vec<_>>();
    if anchor_rotation_lanes != expected_rotation_lanes
        || anchor_rotation_lanes
            .iter()
            .any(|lane| reviewed_build.get(*lane).is_none())
    {
        bail!("anchor rotation lanes must be a canonical affected-lane subset");
    }
    for lane in ApprovedLaneV1::ALL {
        if reviewed_build.get(lane).is_some() != replacements.get(lane).is_some() {
            bail!("replacement lanes must exactly match the reviewed build affected lanes");
        }
    }

    let preceding = load_approved_baseline_set_document(preceding_set_file)?;
    let mut verified_preceding = Vec::with_capacity(2);
    for lane in ApprovedLaneV1::ALL {
        let entry = preceding.lanes.get(lane).clone();
        let request = LaneVerificationRequestV1 {
            lane,
            source: LaneVerificationSourceV1::PrecedingApprovedEntry {
                set_file: preceding_set_file.to_path_buf(),
                entry: Box::new(entry.clone()),
            },
        };
        let lane_evidence = verify(request)
            .map_err(|_| anyhow!("independent preceding-lane verification failed for {lane}"))?;
        validate_verifier_lane(lane, &lane_evidence)?;
        if lane_evidence.entry != entry {
            bail!("verified preceding lane does not match its approved-set entry");
        }
        verified_preceding.push(lane_evidence);
    }
    validate_identity_set(&verified_preceding)?;

    let mut final_lanes = Vec::with_capacity(2);
    for lane in ApprovedLaneV1::ALL {
        let preceding_lane = verified_for(&verified_preceding, lane);
        if let (Some(expected), Some(directory)) =
            (reviewed_build.get(lane), replacements.get(lane))
        {
            let request = LaneVerificationRequestV1 {
                lane,
                source: LaneVerificationSourceV1::LaneDirectory(directory.to_path_buf()),
            };
            let replacement = verify(request)
                .map_err(|_| anyhow!("independent replacement verification failed for {lane}"))?;
            validate_verifier_lane(lane, &replacement)?;
            if replacement.acceptance_identity != preceding_lane.acceptance_identity {
                bail!("replacement lane changed its complete product acceptance identity");
            }
            let expected_sequence = preceding_lane
                .manifest_sequence
                .checked_add(1)
                .filter(|sequence| *sequence <= MAX_CONFIG_BUNDLE_SEQUENCE)
                .ok_or_else(|| anyhow!("preceding lane sequence cannot be advanced"))?;
            if replacement.manifest_sequence != expected_sequence
                || replacement.previous_config_hash.as_deref()
                    != Some(preceding_lane.config_hash.as_str())
            {
                bail!("replacement lane does not extend the preceding signed manifest");
            }
            let anchor_changed =
                replacement.entry.anchor_digest != preceding_lane.entry.anchor_digest;
            if anchor_rotation_lanes.contains(&lane) && !anchor_changed {
                bail!("explicit anchor rotation lane retained its preceding anchor");
            }
            if !anchor_rotation_lanes.contains(&lane) && anchor_changed {
                bail!("replacement lane changed its anchor without explicit rotation selection");
            }
            if !anchor_changed {
                if replacement.anchor_chain_digests != preceding_lane.anchor_chain_digests {
                    bail!("replacement lane changed anchor history without rotating its anchor");
                }
            } else {
                let mut expected_chain = preceding_lane.anchor_chain_digests.clone();
                expected_chain.push(replacement.entry.anchor_digest.clone());
                if replacement.anchor_chain_digests != expected_chain {
                    bail!(
                        "replacement lane anchor history does not append exactly one authenticated transition"
                    );
                }
            }
            if &replacement.entry.reviewed_binding() != expected {
                bail!("replacement lane does not match the reviewed build closure");
            }
            final_lanes.push(replacement);
        } else {
            final_lanes.push(preceding_lane.clone());
        }
    }

    validate_identity_set(&final_lanes)?;
    let approved_set = set_from_verified(&final_lanes)?;
    publish_approved_set(approved_set, reviewed_build.affected_lanes(), output_file)
}

pub fn load_approved_baseline_set(path: &Path) -> Result<ApprovedBaselineSetV1> {
    let root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    load_approved_baseline_set_with_root(path, root)
}

pub(crate) fn load_approved_baseline_set_with_root(
    path: &Path,
    closure_root: &Path,
) -> Result<ApprovedBaselineSetV1> {
    let approved_set = load_approved_baseline_set_document(path)?;
    let canonical_root =
        fs::canonicalize(closure_root).context("failed to resolve approved-set closure root")?;
    let mut verified = Vec::with_capacity(2);
    for lane in ApprovedLaneV1::ALL {
        verified.push(verify_lane_request(
            LaneVerificationRequestV1 {
                lane,
                source: LaneVerificationSourceV1::PrecedingApprovedEntry {
                    set_file: path.to_path_buf(),
                    entry: Box::new(approved_set.lanes.get(lane).clone()),
                },
            },
            &canonical_root,
        )?);
    }
    validate_identity_set(&verified)?;
    Ok(approved_set)
}

fn load_approved_baseline_set_document(path: &Path) -> Result<ApprovedBaselineSetV1> {
    let bytes = read_bounded_regular_file_no_follow(path, MAX_APPROVED_BASELINE_SET_BYTES)
        .context("failed to read bounded approved-set input")?;
    let value = parse_json_strict(&bytes).context("approved set is not strict JSON")?;
    let approved_set: ApprovedBaselineSetV1 =
        serde_json::from_value(value).context("approved set does not match its closed schema")?;
    approved_set.validate()?;
    Ok(approved_set)
}

#[cfg(test)]
#[allow(dead_code)]
pub fn load_approved_baseline_set_structure(path: &Path) -> Result<ApprovedBaselineSetV1> {
    load_approved_baseline_set_document(path)
}

pub(crate) fn verify_approved_lane_from_set(
    set_file: &Path,
    lane: ApprovedLaneV1,
) -> Result<VerifiedApprovedLaneV1> {
    let root = set_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    verify_approved_lane_from_set_with_root(set_file, lane, root)
}

pub(crate) fn verify_approved_lane_from_set_with_root(
    set_file: &Path,
    lane: ApprovedLaneV1,
    closure_root: &Path,
) -> Result<VerifiedApprovedLaneV1> {
    let set = load_approved_baseline_set_document(set_file)?;
    let request = LaneVerificationRequestV1 {
        lane,
        source: LaneVerificationSourceV1::PrecedingApprovedEntry {
            set_file: set_file.to_path_buf(),
            entry: Box::new(set.lanes.get(lane).clone()),
        },
    };
    verify_lane_request(
        request,
        &fs::canonicalize(closure_root).context("failed to resolve approved-set closure root")?,
    )
}

#[cfg(test)]
pub(crate) fn verify_signed_lane_directory(
    lane: ApprovedLaneV1,
    directory: &Path,
) -> Result<VerifiedApprovedLaneV1> {
    let root = directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    verify_lane_request(
        LaneVerificationRequestV1 {
            lane,
            source: LaneVerificationSourceV1::LaneDirectory(directory.to_path_buf()),
        },
        &fs::canonicalize(root).context("failed to resolve signed lane parent")?,
    )
}

pub(crate) fn verify_lane_request(
    request: LaneVerificationRequestV1,
    portable_root: &Path,
) -> Result<VerifiedApprovedLaneV1> {
    let (bundle, manifest_path, anchor_path, transition_links, expected_entry, locators) =
        match request.source {
            LaneVerificationSourceV1::LaneDirectory(directory) => {
                let canonical = fs::canonicalize(&directory)
                    .context("failed to resolve signed lane directory")?;
                if !canonical.starts_with(portable_root) {
                    bail!(
                        "signed lane directory must be beneath the approved-set output directory"
                    );
                }
                let relative = canonical
                    .strip_prefix(portable_root)
                    .context("signed lane directory escaped the portable root")?;
                let bundle_locator =
                    PortableArtifactLocator::new(relative.join("bundle").to_string_lossy())?;
                let manifest_locator = PortableArtifactLocator::new(
                    relative.join("bundle/manifest.json").to_string_lossy(),
                )?;
                let anchor_locator =
                    PortableArtifactLocator::new(relative.join("anchor.json").to_string_lossy())?;
                let transition_locators =
                    discover_signed_lane_anchor_history(&canonical, relative)?;
                let locators = ApprovedLaneLocatorsV1 {
                    bundle: bundle_locator,
                    signed_manifest: manifest_locator,
                    anchor: anchor_locator,
                    anchor_transitions: transition_locators,
                };
                let bundle = resolve_portable_artifact(portable_root, &locators.bundle)?;
                let manifest = resolve_portable_artifact(portable_root, &locators.signed_manifest)?;
                let anchor = resolve_portable_artifact(portable_root, &locators.anchor)?;
                let transitions = locators
                    .anchor_transitions
                    .iter()
                    .map(|link| {
                        Ok((
                            resolve_portable_artifact(portable_root, &link.predecessor_anchor)?,
                            resolve_portable_artifact(portable_root, &link.transition)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                (bundle, manifest, anchor, transitions, None, locators)
            }
            LaneVerificationSourceV1::PrecedingApprovedEntry { set_file: _, entry } => (
                resolve_portable_artifact(portable_root, &entry.locators.bundle)?,
                resolve_portable_artifact(portable_root, &entry.locators.signed_manifest)?,
                resolve_portable_artifact(portable_root, &entry.locators.anchor)?,
                entry
                    .locators
                    .anchor_transitions
                    .iter()
                    .map(|link| {
                        Ok((
                            resolve_portable_artifact(portable_root, &link.predecessor_anchor)?,
                            resolve_portable_artifact(portable_root, &link.transition)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
                Some((*entry).clone()),
                entry.locators.clone(),
            ),
        };

    if manifest_path != bundle.join("manifest.json") {
        bail!("approved lane manifest locator does not identify its bundle manifest");
    }
    let verified = verify_config_bundle(&bundle, &anchor_path)
        .context("signed lane bundle, signature, or anchor verification failed")?;
    if verified.manifest.acceptance_identity.lane != request.lane.acceptance_lane()
        || verified.manifest.acceptance_identity.product != request.lane.product()
        || verified.trust_anchor.acceptance_identity != verified.manifest.acceptance_identity
    {
        bail!("signed lane carries a mismatched complete product acceptance identity");
    }
    let marker = crate::trust::load_signing_input_marker(&bundle)?;
    if marker.acceptance_identity != verified.manifest.acceptance_identity {
        bail!("signed lane marker does not match its manifest and anchor identity");
    }

    let reviewed =
        reviewed_binding_from_verified_bundle(request.lane, &bundle, &verified.manifest)?;
    let anchor_digest =
        trust_anchor_digest(&verified.trust_anchor).context("failed to digest lane anchor")?;
    if usize::try_from(verified.trust_anchor.version).ok() != Some(transition_links.len() + 1) {
        bail!("lane anchor history is incomplete for the terminal anchor version");
    }
    let predecessor_anchors = transition_links
        .iter()
        .map(|(anchor_path, _)| {
            load_trust_anchor(anchor_path).context("failed to load historical predecessor anchor")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut anchor_chain_digests = Vec::with_capacity(predecessor_anchors.len() + 1);
    for (index, (predecessor, (_, transition_path))) in predecessor_anchors
        .iter()
        .zip(&transition_links)
        .enumerate()
    {
        let next = predecessor_anchors
            .get(index + 1)
            .unwrap_or(&verified.trust_anchor);
        let transition = load_anchor_transition(transition_path)
            .context("failed to load historical anchor transition")?;
        verify_anchor_transition(predecessor, next, &transition)
            .context("historical lane anchor transition verification failed")?;
        anchor_chain_digests.push(
            trust_anchor_digest(predecessor)
                .context("failed to digest historical predecessor anchor")?,
        );
    }
    anchor_chain_digests.push(anchor_digest.clone());

    let entry = ApprovedLaneEntryV1 {
        locators,
        signed_manifest_digest: verified.manifest_hash.clone(),
        bundle_digest: signed_bundle_digest(&bundle, &verified.manifest, &verified.manifest_hash)?,
        anchor_digest,
        lane_scoped_reviewed_input_digest: reviewed.lane_scoped_reviewed_input_digest,
        signing_input_closure_digest: reviewed.signing_input_closure_digest,
    };
    if expected_entry
        .as_ref()
        .is_some_and(|expected| expected != &entry)
    {
        bail!("verified lane bytes do not match their approved-set entry");
    }
    VerifiedApprovedLaneV1::from_verified_artifacts(
        request.lane,
        verified.manifest.acceptance_identity,
        verified.manifest.sequence,
        verified.manifest.config_hash,
        verified.manifest.previous_config_hash,
        anchor_chain_digests,
        entry,
    )
}

fn discover_signed_lane_anchor_history(
    signed_lane: &Path,
    relative_lane: &Path,
) -> Result<Vec<ApprovedAnchorTransitionLinkV1>> {
    let history = signed_lane.join("anchor-history");
    let metadata = match fs::symlink_metadata(&history) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("failed to inspect signed lane anchor history"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("signed lane anchor history must be a real directory");
    }
    let mut names = fs::read_dir(&history)
        .context("failed to enumerate signed lane anchor history")?
        .map(|entry| {
            let entry = entry.context("failed to inspect signed lane anchor-history entry")?;
            let metadata = entry
                .file_type()
                .context("failed to inspect signed lane anchor-history entry type")?;
            if metadata.is_symlink() || !metadata.is_file() {
                bail!("signed lane anchor-history entries must be regular files");
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("signed lane anchor-history filename must be UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    if names.len() > MAX_ANCHOR_TRANSITIONS * 2 || names.len() % 2 != 0 {
        bail!("signed lane anchor history is not a bounded sequence of closed links");
    }
    let links = names.len() / 2;
    for index in 0..links {
        let expected_anchor = format!("{index:04}.anchor.json");
        let expected_transition = format!("{index:04}.transition.json");
        if names[index * 2] != expected_anchor || names[index * 2 + 1] != expected_transition {
            bail!("signed lane anchor history is not a contiguous ordered link sequence");
        }
    }
    (0..links)
        .map(|index| {
            Ok(ApprovedAnchorTransitionLinkV1 {
                predecessor_anchor: PortableArtifactLocator::new(
                    relative_lane
                        .join(format!("anchor-history/{index:04}.anchor.json"))
                        .to_string_lossy(),
                )?,
                transition: PortableArtifactLocator::new(
                    relative_lane
                        .join(format!("anchor-history/{index:04}.transition.json"))
                        .to_string_lossy(),
                )?,
            })
        })
        .collect()
}

pub(crate) fn resolve_portable_artifact(
    root: &Path,
    locator: &PortableArtifactLocator,
) -> Result<PathBuf> {
    let canonical_root =
        fs::canonicalize(root).context("failed to resolve approved-set artifact root")?;
    let mut current = canonical_root.clone();
    for component in locator.as_path().components() {
        let Component::Normal(component) = component else {
            bail!("approved-set artifact locator contains a non-portable component");
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .context("approved-set artifact or one of its parent components is unavailable")?;
        if metadata.file_type().is_symlink() {
            bail!("approved-set artifacts and their parent components must not be symbolic links");
        }
    }
    let resolved = fs::canonicalize(&current).context("failed to resolve approved-set artifact")?;
    if !resolved.starts_with(&canonical_root) {
        bail!("approved-set artifact escaped its portable root");
    }
    Ok(resolved)
}

fn reviewed_binding_from_verified_bundle(
    lane: ApprovedLaneV1,
    bundle: &Path,
    manifest: &ConfigBundleManifest,
) -> Result<ReviewedLaneBindingV1> {
    let state = read_manifest_payload(bundle, manifest, "approval/project-state.json")?;
    let state =
        parse_json_strict(&state).context("signed lane approval state is not strict JSON")?;
    let lane_digest = state
        .pointer(&format!(
            "/generated_closure_digests/{}",
            lane.closure_name()
        ))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("signed lane approval state lacks its reviewed lane digest"))?
        .to_string();
    validate_sha256_digest(&lane_digest, "lane-scoped reviewed-input digest")?;
    let lane_files = manifest
        .files
        .iter()
        .filter(|file| {
            !matches!(
                file.path.as_str(),
                "approval/review.json"
                    | "approval/project-state.json"
                    | crate::SIGNING_INPUT_MARKER_FILE
            )
        })
        .map(|file| {
            serde_json::json!({
                "path": file.path,
                "sha256": file.sha256,
            })
        })
        .collect::<Vec<_>>();
    let actual_lane_digest = sha256_uri(
        &canonicalize_json(&serde_json::Value::Array(lane_files))
            .context("failed to canonicalize verified lane closure")?,
    );
    if actual_lane_digest != lane_digest {
        bail!("signed lane files do not match the lane-scoped reviewed-input digest");
    }
    let mut closure = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect::<Vec<_>>();
    closure.sort_by(|left, right| left.0.cmp(right.0));
    let mut closure_hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    for (path, digest) in closure {
        closure_hasher.update(path.as_bytes());
        closure_hasher.update([0]);
        closure_hasher.update(digest.as_bytes());
        closure_hasher.update([b'\n']);
    }
    let signing_input_closure_digest = format!("sha256:{}", hex::encode(closure_hasher.finalize()));
    if signing_input_closure_digest != manifest.bundle_id {
        bail!("signed lane manifest bundle_id does not match its exact input closure");
    }

    Ok(ReviewedLaneBindingV1 {
        lane_scoped_reviewed_input_digest: lane_digest,
        signing_input_closure_digest,
    })
}

fn read_manifest_payload(
    bundle: &Path,
    manifest: &ConfigBundleManifest,
    relative: &str,
) -> Result<Vec<u8>> {
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == relative)
        .ok_or_else(|| anyhow!("signed lane manifest lacks required reviewed evidence"))?;
    let bytes = read_bounded_regular_file_no_follow(&bundle.join(relative), MAX_BUNDLE_FILE_BYTES)?;
    if sha256_uri(&bytes) != file.sha256 {
        bail!("signed lane reviewed evidence changed after bundle verification");
    }
    Ok(bytes)
}

fn signed_bundle_digest(
    bundle: &Path,
    manifest: &ConfigBundleManifest,
    manifest_hash: &str,
) -> Result<String> {
    let signature = read_bounded_regular_file_no_follow(
        &bundle.join("manifest.sig.json"),
        MAX_BUNDLE_FILE_BYTES,
    )?;
    let signature = parse_json_strict(&signature)
        .context("signed lane signature envelope is not strict JSON")?;
    let signature = canonicalize_json(&signature)
        .context("failed to canonicalize signed lane signature envelope")?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(manifest_hash.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(sha256_uri(&signature).as_bytes());
    bytes.push(b'\n');
    for file in &manifest.files {
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(file.sha256.as_bytes());
        bytes.push(b'\n');
    }
    Ok(sha256_uri(&bytes))
}

fn publish_approved_set(
    approved_set: ApprovedBaselineSetV1,
    affected_lanes: Vec<ApprovedLaneV1>,
    output_file: &Path,
) -> Result<ApprovedSetAssemblyReportV1> {
    let canonical = approved_set.canonical_bytes()?;
    let approved_set_digest = sha256_uri(&canonical);
    let mut bytes = canonical;
    bytes.push(b'\n');
    atomic_write_new_file(output_file, &bytes)?;
    Ok(ApprovedSetAssemblyReportV1 {
        approved_set,
        approved_set_digest,
        affected_lanes,
        output_file: output_file.to_path_buf(),
    })
}

fn set_from_verified(verified: &[VerifiedApprovedLaneV1]) -> Result<ApprovedBaselineSetV1> {
    let approved_set = ApprovedBaselineSetV1 {
        schema_id: APPROVED_BASELINE_SET_SCHEMA_ID.to_string(),
        schema_version: APPROVED_BASELINE_SET_SCHEMA_VERSION.to_string(),
        lanes: ApprovedBaselineLanesV1 {
            relay_public: verified_for(verified, ApprovedLaneV1::RelayPublic)
                .entry
                .clone(),
            relay_consultation: verified_for(verified, ApprovedLaneV1::RelayConsultation)
                .entry
                .clone(),
        },
    };
    approved_set.validate()?;
    Ok(approved_set)
}

fn verified_for(
    verified: &[VerifiedApprovedLaneV1],
    lane: ApprovedLaneV1,
) -> &VerifiedApprovedLaneV1 {
    verified
        .iter()
        .find(|candidate| candidate.lane == lane)
        .expect("all fixed lanes were verified before assembly")
}

fn validate_verifier_lane(
    selected: ApprovedLaneV1,
    verified: &VerifiedApprovedLaneV1,
) -> Result<()> {
    if verified.lane != selected
        || verified.acceptance_identity.lane != selected.acceptance_lane()
        || verified.acceptance_identity.product != selected.product()
    {
        bail!("lane verifier returned evidence for a different product lane");
    }
    verified
        .acceptance_identity
        .validate()
        .context("verified lane acceptance identity is invalid")?;
    verified.entry.validate_for_lane(selected)
}

fn validate_identity_set(verified: &[VerifiedApprovedLaneV1]) -> Result<()> {
    if verified.len() != 2 {
        bail!("approved set requires exactly two independently verified Relay lanes");
    }
    let lanes = verified
        .iter()
        .map(|lane| lane.lane)
        .collect::<BTreeSet<_>>();
    if lanes != ApprovedLaneV1::ALL.into_iter().collect() {
        bail!("approved set is missing or duplicates a required product lane");
    }
    let common = &verified[0].acceptance_identity;
    for lane in verified {
        let identity = &lane.acceptance_identity;
        if identity.trust_domain != ProductTrustDomainV1::Governed {
            bail!("approved lanes must use the governed trust domain");
        }
        if identity.project != common.project || identity.environment != common.environment {
            bail!("approved lanes do not share one project and environment");
        }
        if identity.lane != lane.lane.acceptance_lane() || identity.product != lane.lane.product() {
            bail!("approved lane has an incompatible acceptance identity");
        }
    }
    Ok(())
}

fn validate_sha256_digest(value: &str, label: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("{label} must use the sha256 URI form");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must contain one lowercase SHA-256 digest");
    }
    Ok(())
}

fn validate_absent_output_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("approved-set output already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => bail!("failed to inspect approved-set output posture"),
    }
}

fn atomic_write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_absent_output_file(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).context("failed to inspect approved-set output directory")?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("approved-set output parent must be a real directory");
    }
    let mut staged = tempfile::Builder::new()
        .prefix(".approved-set.")
        .tempfile_in(parent)
        .context("failed to stage approved-set output")?;
    use std::io::Write as _;
    staged
        .write_all(bytes)
        .context("failed to stage approved-set bytes")?;
    staged
        .as_file()
        .sync_all()
        .context("failed to sync approved-set output")?;
    staged
        .persist_noclobber(path)
        .map_err(|_| anyhow!("failed to atomically publish absent approved-set output"))?;
    Ok(())
}

fn read_bounded_regular_file_no_follow(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let mut file = open_read_only_no_follow(path)?;
    let metadata = file
        .metadata()
        .context("failed to inspect open approved-set input")?;
    if !metadata.is_file() {
        bail!("approved-set input must be a regular file");
    }
    if metadata.len() > max_bytes {
        bail!("approved-set input exceeds its byte limit");
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("failed to read approved-set input")?;
    if bytes.len() as u64 > max_bytes {
        bail!("approved-set input exceeds its byte limit");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("failed to open approved-set input without following symlinks")?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_read_only_no_follow(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path).context("failed to inspect approved-set input")?;
    if metadata.file_type().is_symlink() {
        bail!("approved-set input must not be a symbolic link");
    }
    File::open(path).context("failed to open approved-set input")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn non_relay_acceptance_lane_fails_without_panicking() {
        let error = ApprovedLaneV1::try_from_acceptance_lane(ProductAcceptanceLaneV1::Notary)
            .expect_err("the retired acceptance lane must fail closed");
        assert_eq!(
            error.to_string(),
            "acceptance lane is not supported by registryctl"
        );
    }

    #[test]
    fn portable_artifact_resolution_rejects_intermediate_symlink_escape() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("package");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&root).expect("package root");
        fs::create_dir_all(outside.join("bundle")).expect("outside bundle");
        symlink(&outside, root.join("approved")).expect("planted intermediate symlink");

        let locator =
            PortableArtifactLocator::new("approved/bundle").expect("portable syntax is valid");
        let error = resolve_portable_artifact(&root, &locator)
            .expect_err("portable syntax must not permit a filesystem escape");
        assert!(format!("{error:#}").contains("symbolic links"));
    }

    #[test]
    fn portable_artifact_resolution_uses_the_verifier_selected_closure_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let generated = temporary.path().join("generated");
        let artifact = generated.join("bundles/relay-public/manifest-digest");
        fs::create_dir_all(&artifact).expect("package artifact");
        fs::create_dir_all(generated.join("inputs")).expect("nested set directory");

        let locator = PortableArtifactLocator::new("bundles/relay-public/manifest-digest")
            .expect("normalized package locator");
        assert_eq!(
            resolve_portable_artifact(&generated, &locator).expect("selected root resolves"),
            fs::canonicalize(artifact).expect("artifact canonicalizes")
        );
        assert!(resolve_portable_artifact(&generated.join("inputs"), &locator).is_err());
    }
}
