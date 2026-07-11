// SPDX-License-Identifier: Apache-2.0
//! Closed consent-evidence parsing and offline verification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{
    hmac_sha256_base64url_no_pad, sign, verify, PrivateJwk, PublicJwk, SigningAlgorithm,
};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CONSENT_EVIDENCE_BYTES: usize = 8 * 1024;
pub const CONSENT_EVIDENCE_JWS_TYPE: &str = "consent-evidence+jws";
const MAX_IDENTIFIER_TYPE_BYTES: usize = 64;
const MAX_IDENTIFIER_VALUE_BYTES: usize = 256;
const MAX_PURPOSES: usize = 8;
const MAX_PURPOSE_BYTES: usize = 128;
const MAX_ORGANIZATION_BYTES: usize = 256;
const MAX_METHOD_BYTES: usize = 64;
const MAX_CONTEXT_BYTES: usize = 512;
const MAX_REFERENCE_BYTES: usize = 256;
const MAX_LANGUAGE_BYTES: usize = 35;
const MAX_TARGET_PROFILE_BYTES: usize = 256;
const MAX_STATUS_REVISION_BYTES: usize = 64;
const MAX_KID_BYTES: usize = 128;

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactIdentifier {
    pub identifier_type: String,
    pub value: String,
}

impl Zeroize for ExactIdentifier {
    fn zeroize(&mut self) {
        self.identifier_type.zeroize();
        self.value.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentingPartyRelationship {
    #[serde(rename = "self")]
    Self_,
    Parent,
    Guardian,
    AuthorizedRepresentative,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentingParty {
    pub identifier: ExactIdentifier,
    pub relationship: ConsentingPartyRelationship,
}

impl Zeroize for ConsentingParty {
    fn zeroize(&mut self) {
        self.identifier.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentAssurance {
    SystemOfRecordSigned,
    OrganizationAttested,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeModality {
    Written,
    Audio,
    Pictorial,
    Interpreted,
    Assisted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProfileBindingKind {
    ProfileId,
    ContractHash,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfileBinding {
    pub kind: TargetProfileBindingKind,
    pub value: String,
}

impl Zeroize for TargetProfileBinding {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// The compact, published ConsentEvidenceV1 payload schema.
///
/// It is serializable for the signing helper, but intentionally is not
/// `Debug`; callers must not copy assertion payloads into diagnostics.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentEvidenceV1 {
    pub version: u8,
    pub subject: ExactIdentifier,
    pub consenting_party: ConsentingParty,
    pub purposes: Vec<String>,
    pub recipient: String,
    pub controller: String,
    pub assurance: ConsentAssurance,
    pub collection_method: String,
    pub collection_context: String,
    pub collected_at: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub consent_id: String,
    pub notice_reference: String,
    pub notice_language: String,
    /// `sha256:` plus the lowercase hex digest of the immutable notice content.
    pub notice_content_digest: String,
    pub notice_modality: NoticeModality,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_profile: Option<TargetProfileBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_section_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_revision: Option<String>,
}

impl ConsentEvidenceV1 {
    pub fn parse_json(input: &[u8]) -> Result<Self, ConsentError> {
        if input.len() > MAX_CONSENT_EVIDENCE_BYTES {
            return Err(ConsentError::Malformed);
        }
        reject_duplicate_members(input)?;
        let evidence: Self = serde_json::from_slice(input).map_err(|_| ConsentError::Malformed)?;
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ConsentError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ConsentError::Malformed)
    }

    pub fn sign_compact(&self, key: &PrivateJwk) -> Result<ConsentArtifact, ConsentError> {
        self.validate()?;
        if key.algorithm().map_err(|_| ConsentError::InvalidKey)? != SigningAlgorithm::EdDsa {
            return Err(ConsentError::InvalidKey);
        }
        let kid = key
            .kid
            .as_deref()
            .filter(|kid| valid_text(kid, MAX_KID_BYTES))
            .ok_or(ConsentError::InvalidKey)?;
        let header = ProtectedHeader {
            alg: JwsAlgorithm::EdDsa,
            typ: CONSENT_EVIDENCE_JWS_TYPE.to_string(),
            kid: kid.to_string(),
        };
        let protected = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| ConsentError::Malformed)?);
        let payload = URL_SAFE_NO_PAD.encode(self.to_json_bytes()?);
        let signing_input = format!("{protected}.{payload}");
        let signature =
            sign(signing_input.as_bytes(), key).map_err(|_| ConsentError::InvalidKey)?;
        ConsentArtifact::parse(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn validate(&self) -> Result<(), ConsentError> {
        if self.version != 1
            || !valid_identifier(&self.subject)
            || !valid_identifier(&self.consenting_party.identifier)
            || self.purposes.is_empty()
            || self.purposes.len() > MAX_PURPOSES
            || self
                .purposes
                .iter()
                .any(|purpose| !valid_text(purpose, MAX_PURPOSE_BYTES))
            || self.purposes.iter().collect::<BTreeSet<_>>().len() != self.purposes.len()
            || !valid_text(&self.recipient, MAX_ORGANIZATION_BYTES)
            || !valid_text(&self.controller, MAX_ORGANIZATION_BYTES)
            || !valid_text(&self.collection_method, MAX_METHOD_BYTES)
            || !valid_text(&self.collection_context, MAX_CONTEXT_BYTES)
            || self.collected_at <= 0
            || self.issued_at <= 0
            || self.collected_at > self.issued_at
            || self.issued_at >= self.expires_at
            || !valid_text(&self.consent_id, MAX_REFERENCE_BYTES)
            || !valid_text(&self.notice_reference, MAX_REFERENCE_BYTES)
            || !valid_language(&self.notice_language)
            || !valid_sha256_digest(&self.notice_content_digest)
            || self
                .target_profile
                .as_ref()
                .is_some_and(|binding| match binding.kind {
                    TargetProfileBindingKind::ProfileId => {
                        !valid_text(&binding.value, MAX_TARGET_PROFILE_BYTES)
                    }
                    TargetProfileBindingKind::ContractHash => !valid_sha256_digest(&binding.value),
                })
            || self
                .verifier_section_hash
                .as_deref()
                .is_some_and(|value| !valid_sha256_digest(value))
            || self
                .status_revision
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_STATUS_REVISION_BYTES))
        {
            return Err(ConsentError::InvalidPayload);
        }
        if self.consenting_party.relationship == ConsentingPartyRelationship::Self_
            && self.consenting_party.identifier != self.subject
        {
            return Err(ConsentError::InvalidPayload);
        }
        Ok(())
    }
}

impl Drop for ConsentEvidenceV1 {
    fn drop(&mut self) {
        self.subject.zeroize();
        self.consenting_party.zeroize();
        self.purposes.zeroize();
        self.recipient.zeroize();
        self.controller.zeroize();
        self.collection_method.zeroize();
        self.collection_context.zeroize();
        self.consent_id.zeroize();
        self.notice_reference.zeroize();
        self.notice_language.zeroize();
        self.notice_content_digest.zeroize();
        self.target_profile.zeroize();
        self.verifier_section_hash.zeroize();
        self.status_revision.zeroize();
    }
}

fn valid_identifier(identifier: &ExactIdentifier) -> bool {
    valid_text(&identifier.identifier_type, MAX_IDENTIFIER_TYPE_BYTES)
        && valid_text(&identifier.value, MAX_IDENTIFIER_VALUE_BYTES)
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_language(value: &str) -> bool {
    valid_text(value, MAX_LANGUAGE_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reject_duplicate_members(input: &[u8]) -> Result<(), ConsentError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    RejectDuplicateValue::deserialize(&mut deserializer).map_err(|_| ConsentError::Malformed)?;
    deserializer.end().map_err(|_| ConsentError::Malformed)
}

struct RejectDuplicateValue;

impl<'de> Deserialize<'de> for RejectDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateVisitor)
    }
}

struct RejectDuplicateVisitor;

impl<'de> Visitor<'de> for RejectDuplicateVisitor {
    type Value = RejectDuplicateValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            map.next_value::<RejectDuplicateValue>()?;
        }
        Ok(RejectDuplicateValue)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<RejectDuplicateValue>()?.is_some() {}
        Ok(RejectDuplicateValue)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RejectDuplicateValue)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: JwsAlgorithm,
    typ: String,
    kid: String,
}

impl Drop for ProtectedHeader {
    fn drop(&mut self) {
        self.typ.zeroize();
        self.kid.zeroize();
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
enum JwsAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
}

/// Size-bounded compact consent JWS. Raw material is intentionally opaque.
pub struct ConsentArtifact {
    compact: Zeroizing<String>,
    protected: ProtectedHeader,
    evidence: ConsentEvidenceV1,
    signing_input_len: usize,
}

impl ConsentArtifact {
    pub fn parse(compact: String) -> Result<Self, ConsentError> {
        if compact.is_empty() || compact.len() > MAX_CONSENT_EVIDENCE_BYTES || !compact.is_ascii() {
            return Err(ConsentError::Malformed);
        }
        let mut segments = compact.split('.');
        let protected_segment = segments.next().ok_or(ConsentError::Malformed)?;
        let payload_segment = segments.next().ok_or(ConsentError::Malformed)?;
        let signature_segment = segments.next().ok_or(ConsentError::Malformed)?;
        if segments.next().is_some()
            || protected_segment.is_empty()
            || payload_segment.is_empty()
            || signature_segment.is_empty()
        {
            return Err(ConsentError::Malformed);
        }
        let protected_bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(protected_segment)
                .map_err(|_| ConsentError::Malformed)?,
        );
        reject_duplicate_members(&protected_bytes)?;
        let protected: ProtectedHeader =
            serde_json::from_slice(&protected_bytes).map_err(|_| ConsentError::Malformed)?;
        if protected.typ != CONSENT_EVIDENCE_JWS_TYPE || !valid_text(&protected.kid, MAX_KID_BYTES)
        {
            return Err(ConsentError::Malformed);
        }
        let payload = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(payload_segment)
                .map_err(|_| ConsentError::Malformed)?,
        );
        let evidence = ConsentEvidenceV1::parse_json(&payload)?;
        let signature = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(signature_segment)
                .map_err(|_| ConsentError::Malformed)?,
        );
        if signature.len() != 64 {
            return Err(ConsentError::Malformed);
        }
        let signing_input_len = protected_segment.len() + 1 + payload_segment.len();
        Ok(Self {
            compact: Zeroizing::new(compact),
            protected,
            evidence,
            signing_input_len,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.compact.as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationModel {
    LifetimeOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableBehavior {
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectBindingRule {
    ExactIdentifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PurposeCoverageRule {
    AllRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentVerifierSpec {
    pub verifier_id: String,
    pub revision: String,
    pub evidence_format_profile: String,
    pub evidence_format_version: u8,
    pub maximum_evidence_age_seconds: u64,
    pub revocation: RevocationModel,
    pub revocation_propagation_seconds: u64,
    pub unavailable: UnavailableBehavior,
    pub subject_binding: SubjectBindingRule,
    pub accepted_assurance: BTreeSet<ConsentAssurance>,
    pub purpose_coverage: PurposeCoverageRule,
}

impl ConsentVerifierSpec {
    pub fn validate(&self) -> Result<(), ConsentError> {
        if !valid_text(&self.verifier_id, 128)
            || !valid_text(&self.revision, 128)
            || self.evidence_format_profile != "registry.consent-evidence"
            || self.evidence_format_version != 1
            || self.maximum_evidence_age_seconds == 0
            || self.revocation_propagation_seconds == 0
            || self.maximum_evidence_age_seconds > self.revocation_propagation_seconds
            || self.accepted_assurance.is_empty()
        {
            return Err(ConsentError::InvalidVerifierSpec);
        }
        Ok(())
    }
}

pub struct PinnedConsentKeys {
    by_kid: BTreeMap<String, PublicJwk>,
}

impl PinnedConsentKeys {
    pub fn new(keys: impl IntoIterator<Item = PublicJwk>) -> Result<Self, ConsentError> {
        let mut by_kid = BTreeMap::new();
        for key in keys {
            if key.algorithm().map_err(|_| ConsentError::InvalidKey)? != SigningAlgorithm::EdDsa {
                return Err(ConsentError::InvalidKey);
            }
            let kid = key
                .kid
                .as_deref()
                .filter(|kid| valid_text(kid, MAX_KID_BYTES))
                .ok_or(ConsentError::InvalidKey)?
                .to_string();
            if by_kid.insert(kid, key).is_some() {
                return Err(ConsentError::DuplicatePinnedKeyId);
            }
        }
        if by_kid.is_empty() {
            return Err(ConsentError::InvalidKey);
        }
        Ok(Self { by_kid })
    }
}

pub struct VerificationContext<'a> {
    pub subject: &'a ExactIdentifier,
    pub recipient: &'a str,
    pub required_purposes: &'a BTreeSet<String>,
    pub now: i64,
    pub required_target_profile: Option<&'a TargetProfileBinding>,
    pub required_verifier_section_hash: Option<&'a str>,
    pub required_status_revision: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedConsent {
    pub verifier_id: String,
    pub verifier_revision: String,
    pub signer_key_id: String,
    pub checked_at: i64,
    pub expires_at: i64,
    pub assurance: ConsentAssurance,
    pub revocation: RevocationModel,
}

pub fn verify_consent(
    artifact: &ConsentArtifact,
    keys: &PinnedConsentKeys,
    spec: &ConsentVerifierSpec,
    context: &VerificationContext<'_>,
) -> Result<VerifiedConsent, ConsentError> {
    spec.validate()?;
    validate_verification_context(context)?;
    let key = keys
        .by_kid
        .get(&artifact.protected.kid)
        .ok_or(ConsentError::Denied)?;
    let signature_segment = artifact
        .compact
        .rsplit_once('.')
        .map(|(_, signature)| signature)
        .ok_or(ConsentError::Malformed)?;
    let signature = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(signature_segment)
            .map_err(|_| ConsentError::Malformed)?,
    );
    verify(
        &artifact.compact.as_bytes()[..artifact.signing_input_len],
        &signature,
        key,
    )
    .map_err(|_| ConsentError::Denied)?;

    let evidence = &artifact.evidence;
    let age = context
        .now
        .checked_sub(evidence.issued_at)
        .ok_or(ConsentError::Denied)?;
    if &evidence.subject != context.subject
        || evidence.recipient != context.recipient
        || !spec.accepted_assurance.contains(&evidence.assurance)
        || context
            .required_purposes
            .iter()
            .any(|required| !evidence.purposes.contains(required))
        || age < 0
        || u64::try_from(age).map_err(|_| ConsentError::Denied)? > spec.maximum_evidence_age_seconds
        || context.now >= evidence.expires_at
        || context
            .required_target_profile
            .is_some_and(|required| evidence.target_profile.as_ref() != Some(required))
        || binding_mismatch(
            context.required_verifier_section_hash,
            evidence.verifier_section_hash.as_deref(),
        )
        || binding_mismatch(
            context.required_status_revision,
            evidence.status_revision.as_deref(),
        )
    {
        return Err(ConsentError::Denied);
    }

    Ok(VerifiedConsent {
        verifier_id: spec.verifier_id.clone(),
        verifier_revision: spec.revision.clone(),
        signer_key_id: artifact.protected.kid.clone(),
        checked_at: context.now,
        expires_at: evidence.expires_at,
        assurance: evidence.assurance,
        revocation: spec.revocation,
    })
}

fn validate_verification_context(context: &VerificationContext<'_>) -> Result<(), ConsentError> {
    if !valid_identifier(context.subject)
        || !valid_text(context.recipient, MAX_ORGANIZATION_BYTES)
        || context.required_purposes.is_empty()
        || context.required_purposes.len() > MAX_PURPOSES
        || context
            .required_purposes
            .iter()
            .any(|purpose| !valid_text(purpose, MAX_PURPOSE_BYTES))
        || context.now <= 0
        || context
            .required_target_profile
            .is_some_and(|binding| match binding.kind {
                TargetProfileBindingKind::ProfileId => {
                    !valid_text(&binding.value, MAX_TARGET_PROFILE_BYTES)
                }
                TargetProfileBindingKind::ContractHash => !valid_sha256_digest(&binding.value),
            })
        || context
            .required_verifier_section_hash
            .is_some_and(|value| !valid_sha256_digest(value))
        || context
            .required_status_revision
            .is_some_and(|value| !valid_text(value, MAX_STATUS_REVISION_BYTES))
    {
        return Err(ConsentError::InvalidVerificationContext);
    }
    Ok(())
}

fn binding_mismatch(required: Option<&str>, actual: Option<&str>) -> bool {
    required.is_some_and(|required| actual != Some(required))
}

/// Evaluation-scoped evidence. Its shape cannot represent per-claim artifacts.
pub struct EvaluationConsentEvidence(Option<ConsentArtifact>);

impl EvaluationConsentEvidence {
    #[must_use]
    pub const fn none() -> Self {
        Self(None)
    }

    #[must_use]
    pub const fn one(artifact: ConsentArtifact) -> Self {
        Self(Some(artifact))
    }

    pub fn from_artifacts(
        artifacts: impl IntoIterator<Item = ConsentArtifact>,
    ) -> Result<Self, ConsentError> {
        let mut artifacts = artifacts.into_iter();
        let first = artifacts.next();
        if artifacts.next().is_some() {
            return Err(ConsentError::TooManyArtifacts);
        }
        Ok(Self(first))
    }

    #[must_use]
    pub const fn artifact(&self) -> Option<&ConsentArtifact> {
        self.0.as_ref()
    }

    pub fn validate_requirement(&self, consent_required: bool) -> Result<(), ConsentError> {
        if consent_required != self.0.is_some() {
            return Err(ConsentError::InvalidEvaluationEvidence);
        }
        Ok(())
    }
}

/// Produce the only audit-safe representation of a raw compact artifact.
pub fn consent_evidence_commitment(
    key: &[u8],
    runtime_domain: &str,
    verifier_id: &str,
    artifact: &ConsentArtifact,
) -> Result<String, ConsentError> {
    if !valid_text(runtime_domain, 128) || !valid_text(verifier_id, 128) {
        return Err(ConsentError::InvalidVerifierSpec);
    }
    let mut input = Zeroizing::new(Vec::with_capacity(
        runtime_domain.len() + verifier_id.len() + artifact.compact.len() + 2,
    ));
    input.extend_from_slice(runtime_domain.as_bytes());
    input.push(0);
    input.extend_from_slice(verifier_id.as_bytes());
    input.push(0);
    input.extend_from_slice(artifact.compact.as_bytes());
    Ok(format!(
        "hmac-sha256:{}",
        hmac_sha256_base64url_no_pad(key, &input)
    ))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsentError {
    #[error("malformed consent evidence")]
    Malformed,
    #[error("invalid consent evidence payload")]
    InvalidPayload,
    #[error("invalid consent verifier specification")]
    InvalidVerifierSpec,
    #[error("invalid consent verification context")]
    InvalidVerificationContext,
    #[error("invalid pinned consent key")]
    InvalidKey,
    #[error("duplicate pinned consent key id")]
    DuplicatePinnedKeyId,
    #[error("consent evidence denied")]
    Denied,
    #[error("at most one consent artifact is allowed per evaluation")]
    TooManyArtifacts,
    #[error("consent evidence does not match the evaluation requirement")]
    InvalidEvaluationEvidence,
}
