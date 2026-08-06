//! Strict verifier for the Evidence Version 1 flattened JWS profile and for
//! the SD-JWT VC profile that projects the same payload.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use registry_platform_crypto::{parse_json_strict, verify, PublicJwk, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    contracts::evidence_contract_accepts,
    model::{Evidence, FlattenedJws, HolderPublicKey, JwksDocument},
    sdjwt_vc::evidence_payload_from_claims,
    AssuranceProfile, EVIDENCE_JWS_CTY, EVIDENCE_JWS_TYP, EVIDENCE_SCHEMA_V1,
    EVIDENCE_SD_JWT_VC_TYP,
};

const MAX_JWS_BYTES: usize = 256 * 1024;
const MAX_PROTECTED_BYTES: usize = 8 * 1024;
const MAX_PAYLOAD_BYTES: usize = 128 * 1024;
pub(crate) const MAX_TRUSTED_KEYS: usize = 33;
/// One disclosure per Supported Value, bounded well above the largest
/// requirement a Version 1 bundle can declare.
const MAX_DISCLOSURES: usize = 64;
const MAX_DISCLOSURE_BYTES: usize = 8 * 1024;
const MINIMUM_SALT_BYTES: usize = 16;
const MAXIMUM_SALT_BYTES: usize = 64;

/// Shortest maximum assertion lifetime a policy may state, per the
/// verification policy contract.
///
/// This bound and the bounds below it are the contract constraints on a policy
/// that fail open, so they are enforced here. A pattern,
/// length, or uniqueness violation elsewhere in a policy fails closed: the
/// payload is itself contract-checked, so an out-of-contract expectation is one
/// no conformant payload can match and verification refuses the response. A
/// lifetime or skew wider than the contract allows fails the other way, making
/// this verifier accept assertions a conformant relying party must refuse. The
/// failure-class vocabulary is frozen and has no class for an unusable policy,
/// so a forbidden bound is refused where a policy is read or built, never
/// reported as a verification outcome.
pub const MINIMUM_ASSERTION_LIFETIME_SECONDS: u64 = 1;
/// Longest maximum assertion lifetime a policy may state, per the same
/// contract.
pub const MAXIMUM_ASSERTION_LIFETIME_SECONDS: u64 = 31_536_000;
/// Largest clock skew tolerance a policy may state, per the same contract.
/// Omitting the tolerance means zero, which is always inside the bound.
pub const MAXIMUM_CLOCK_SKEW_SECONDS: u64 = 300;
/// Smallest list cardinality a policy may state.
pub const MINIMUM_EXPECTED_LIST_ITEMS: usize = 1;
/// Largest list cardinality a policy may state.
pub const MAXIMUM_EXPECTED_LIST_ITEMS: usize = 64;

/// A policy stating a bound the verification policy contract forbids.
///
/// This is a refusal to use the policy at all, not a verification outcome. Both
/// Variants carry the stated value, which is a relying party's own expectation
/// and never comes from a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PolicyBoundsError {
    #[error("maximumAssertionLifetimeSeconds must be {MINIMUM_ASSERTION_LIFETIME_SECONDS} to {MAXIMUM_ASSERTION_LIFETIME_SECONDS}, not {0}")]
    AssertionLifetime(u64),
    #[error("clockSkewSeconds must be at most {MAXIMUM_CLOCK_SKEW_SECONDS}, not {0}")]
    ClockSkew(u64),
    #[error("minimumItems must be {MINIMUM_EXPECTED_LIST_ITEMS} to {MAXIMUM_EXPECTED_LIST_ITEMS}, not {0}")]
    MinimumItems(usize),
    #[error("maximumItems must be {MINIMUM_EXPECTED_LIST_ITEMS} to {MAXIMUM_EXPECTED_LIST_ITEMS}, not {0}")]
    MaximumItems(usize),
}

fn checked_assertion_lifetime(seconds: u64) -> Result<Duration, PolicyBoundsError> {
    if !(MINIMUM_ASSERTION_LIFETIME_SECONDS..=MAXIMUM_ASSERTION_LIFETIME_SECONDS).contains(&seconds)
    {
        return Err(PolicyBoundsError::AssertionLifetime(seconds));
    }
    Ok(Duration::from_secs(seconds))
}

fn checked_clock_skew(seconds: u64) -> Result<Duration, PolicyBoundsError> {
    if seconds > MAXIMUM_CLOCK_SKEW_SECONDS {
        return Err(PolicyBoundsError::ClockSkew(seconds));
    }
    Ok(Duration::from_secs(seconds))
}

fn checked_minimum_items(items: usize) -> Result<usize, PolicyBoundsError> {
    if !(MINIMUM_EXPECTED_LIST_ITEMS..=MAXIMUM_EXPECTED_LIST_ITEMS).contains(&items) {
        return Err(PolicyBoundsError::MinimumItems(items));
    }
    Ok(items)
}

fn checked_maximum_items(items: usize) -> Result<usize, PolicyBoundsError> {
    if !(MINIMUM_EXPECTED_LIST_ITEMS..=MAXIMUM_EXPECTED_LIST_ITEMS).contains(&items) {
        return Err(PolicyBoundsError::MaximumItems(items));
    }
    Ok(items)
}

/// Complete relying-procedure expectations for strict verification.
///
/// Every expectation comes from independent trusted state such as the relying
/// procedure, a previously trusted binding, or a trusted requirement contract.
/// Copying values out of the JWS under verification proves nothing.
///
/// The two time bounds are private, so the only ways to a policy are the
/// checked conversions on this type and on
/// [`EvidenceVerificationPolicyDocument`], and no caller can state a bound the
/// contract forbids.
#[derive(Debug, Clone)]
pub struct EvidenceVerificationPolicy {
    pub assurance_profile: AssuranceProfile,
    pub issued_by: String,
    pub provided_by: String,
    pub requirement: String,
    pub evidence_type: String,
    pub purpose: String,
    pub audience: String,
    pub configuration_revision: String,
    /// The exact nonce from the independently retained original request.
    pub request_nonce: String,
    /// Expected role-bound opaque subject bindings as an unordered set of
    /// unique pairs. Subject order alone is never semantic.
    pub expected_subjects: Vec<ExpectedSubject>,
    /// Expected concept identifiers, value forms, and cardinalities.
    pub expected_outputs: Vec<ExpectedOutput>,
    /// Service key thumbprints that fail closed even if present in a stale or
    /// otherwise trusted JWKS document.
    pub revoked_key_ids: Vec<String>,
    /// Longest acceptable `validUntil - issuedAt` interval. Read it with
    /// [`EvidenceVerificationPolicy::maximum_assertion_lifetime`].
    maximum_assertion_lifetime: Duration,
    pub now: DateTime<Utc>,
    /// Read it with [`EvidenceVerificationPolicy::clock_skew`].
    clock_skew: Duration,
}

/// Closed wire document for independently retained verification expectations.
///
/// The runtime-facing policy keeps an explicit verification instant and Rust
/// durations. This document is the serializable form used by offline operator
/// boundaries, including the local pre-response context. It never learns
/// expectations from the response it is asked to verify.
///
/// Reading one refuses the two time bounds the contract forbids, so an
/// out-of-contract document never reaches verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerificationPolicyDocument {
    pub expected_assurance_profile: AssuranceProfile,
    pub issued_by: String,
    pub provided_by: String,
    pub requirement: String,
    pub evidence_type: String,
    pub purpose: String,
    pub audience: String,
    pub configuration_revision: String,
    /// The exact nonce from the independently retained original request.
    pub request_nonce: String,
    pub expected_subjects: Vec<ExpectedSubjectDocument>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
    pub revoked_key_ids: Vec<String>,
    #[serde(deserialize_with = "read_assertion_lifetime_seconds")]
    pub maximum_assertion_lifetime_seconds: u64,
    #[serde(default, deserialize_with = "read_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
}

fn read_assertion_lifetime_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let seconds = u64::deserialize(deserializer)?;
    checked_assertion_lifetime(seconds).map_err(serde::de::Error::custom)?;
    Ok(seconds)
}

fn read_clock_skew_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let seconds = u64::deserialize(deserializer)?;
    checked_clock_skew(seconds).map_err(serde::de::Error::custom)?;
    Ok(seconds)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedSubjectDocument {
    pub role: String,
    pub binding: String,
}

impl std::fmt::Debug for ExpectedSubjectDocument {
    /// A binding is a pseudonymous per-subject identifier, so only the role is
    /// rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExpectedSubjectDocument")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedOutputDocument {
    pub concept: String,
    pub form: ExpectedFormDocument,
}

/// The closed expected value-form vocabulary as written in a policy document.
///
/// The two alternatives are untagged because the policy schema writes a scalar
/// form as a plain string and the list form as a mapping under `list`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExpectedFormDocument {
    Scalar(ExpectedScalarFormDocument),
    List(ExpectedListFormDocument),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedScalarFormDocument {
    Boolean,
    Integer,
    String,
    DateBucket,
    TimeBucket,
    EntityReference,
    Structured,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedListFormDocument {
    pub list: ExpectedListDocument,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedListDocument {
    #[serde(deserialize_with = "read_minimum_items")]
    pub minimum_items: usize,
    #[serde(deserialize_with = "read_maximum_items")]
    pub maximum_items: usize,
}

fn read_minimum_items<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let items = usize::deserialize(deserializer)?;
    checked_minimum_items(items).map_err(serde::de::Error::custom)
}

fn read_maximum_items<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let items = usize::deserialize(deserializer)?;
    checked_maximum_items(items).map_err(serde::de::Error::custom)
}

impl EvidenceVerificationPolicyDocument {
    /// The runtime-facing policy for one verification instant, or a refusal when
    /// the document states a bound the contract forbids.
    ///
    /// Reading a document already refuses bounded fields, so this is what holds
    /// them for a document built in code, where the public fields accept any value.
    pub fn try_into_policy(
        self,
        now: DateTime<Utc>,
    ) -> Result<EvidenceVerificationPolicy, PolicyBoundsError> {
        let maximum_assertion_lifetime =
            checked_assertion_lifetime(self.maximum_assertion_lifetime_seconds)?;
        let clock_skew = checked_clock_skew(self.clock_skew_seconds)?;
        Ok(EvidenceVerificationPolicy {
            assurance_profile: self.expected_assurance_profile,
            issued_by: self.issued_by,
            provided_by: self.provided_by,
            requirement: self.requirement,
            evidence_type: self.evidence_type,
            purpose: self.purpose,
            audience: self.audience,
            configuration_revision: self.configuration_revision,
            request_nonce: self.request_nonce,
            expected_subjects: self
                .expected_subjects
                .into_iter()
                .map(|subject| ExpectedSubject {
                    role: subject.role,
                    binding: subject.binding,
                })
                .collect(),
            expected_outputs: self
                .expected_outputs
                .into_iter()
                .map(|output| {
                    Ok(ExpectedOutput {
                        concept: output.concept,
                        form: expected_value_form_document(output.form)?,
                    })
                })
                .collect::<Result<Vec<_>, PolicyBoundsError>>()?,
            revoked_key_ids: self.revoked_key_ids,
            maximum_assertion_lifetime,
            now,
            clock_skew,
        })
    }
}

fn expected_value_form_document(
    document: ExpectedFormDocument,
) -> Result<ExpectedValueForm, PolicyBoundsError> {
    Ok(match document {
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean) => {
            ExpectedValueForm::Boolean
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Integer) => {
            ExpectedValueForm::Integer
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::String) => {
            ExpectedValueForm::String
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::DateBucket) => {
            ExpectedValueForm::DateBucket
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::TimeBucket) => {
            ExpectedValueForm::TimeBucket
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::EntityReference) => {
            ExpectedValueForm::EntityReference
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Structured) => {
            ExpectedValueForm::Structured
        }
        ExpectedFormDocument::List(wrapper) => ExpectedValueForm::List {
            minimum_items: checked_minimum_items(wrapper.list.minimum_items)?,
            maximum_items: checked_maximum_items(wrapper.list.maximum_items)?,
        },
    })
}

impl EvidenceVerificationPolicy {
    /// Longest acceptable `validUntil - issuedAt` interval, within the bounds
    /// the verification policy contract states.
    #[must_use]
    pub fn maximum_assertion_lifetime(&self) -> Duration {
        self.maximum_assertion_lifetime
    }

    /// Accepted clock skew tolerance, within the same contract's bound.
    #[must_use]
    pub fn clock_skew(&self) -> Duration {
        self.clock_skew
    }

    /// Build expectations from evidence accepted in an original trusted
    /// transaction, for later re-verification of the stored response.
    ///
    /// This is only meaningful when `evidence` was itself verified and
    /// accepted at transaction time and then retained under the relying
    /// party's record policy. Parsing an untrusted JWS and passing its own
    /// values back as expectations proves nothing. The expected nonce comes
    /// from the independently retained original request, never from the
    /// response.
    ///
    /// The two time bounds are the relying party's own, stated in seconds as the
    /// contract states them, and a value the contract forbids is refused rather
    /// than honoured.
    pub fn from_accepted_transaction(
        evidence: &Evidence,
        retained_request_nonce: &str,
        maximum_assertion_lifetime_seconds: u64,
        now: DateTime<Utc>,
        clock_skew_seconds: u64,
    ) -> Result<Self, PolicyBoundsError> {
        let maximum_assertion_lifetime =
            checked_assertion_lifetime(maximum_assertion_lifetime_seconds)?;
        let clock_skew = checked_clock_skew(clock_skew_seconds)?;
        Ok(Self {
            assurance_profile: evidence.assurance_profile,
            issued_by: evidence.issued_by.clone(),
            provided_by: evidence.provided_by.clone(),
            requirement: evidence.supports_requirement.clone(),
            evidence_type: evidence.is_conformant_to.clone(),
            purpose: evidence.purpose.clone(),
            audience: evidence.audience.clone(),
            configuration_revision: evidence.configuration_revision.clone(),
            request_nonce: retained_request_nonce.to_owned(),
            expected_subjects: evidence
                .subjects
                .iter()
                .map(|subject| ExpectedSubject {
                    role: subject.role.clone(),
                    binding: subject.binding.clone(),
                })
                .collect(),
            expected_outputs: evidence
                .supported_values
                .iter()
                .map(|value| ExpectedOutput {
                    concept: value.provides_value_for.clone(),
                    form: expected_form_of(&value.value),
                })
                .collect(),
            revoked_key_ids: Vec::new(),
            maximum_assertion_lifetime,
            now,
            clock_skew,
        })
    }
}

fn expected_form_of(value: &crate::model::PublicValue) -> ExpectedValueForm {
    use crate::model::{BucketForm, PublicValue};
    match value {
        PublicValue::Boolean(_) => ExpectedValueForm::Boolean,
        PublicValue::Integer(_) => ExpectedValueForm::Integer,
        PublicValue::String(_) => ExpectedValueForm::String,
        PublicValue::Bucket(bucket) => {
            if bucket.form == BucketForm::DateBucket {
                ExpectedValueForm::DateBucket
            } else {
                ExpectedValueForm::TimeBucket
            }
        }
        PublicValue::EntityReference(_) => ExpectedValueForm::EntityReference,
        PublicValue::Structured(_) => ExpectedValueForm::Structured,
        PublicValue::List(items) => ExpectedValueForm::List {
            minimum_items: items.len(),
            maximum_items: items.len(),
        },
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExpectedSubject {
    pub role: String,
    pub binding: String,
}

impl std::fmt::Debug for ExpectedSubject {
    /// A binding is a pseudonymous per-subject identifier, so only the role is
    /// rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExpectedSubject")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct ExpectedOutput {
    pub concept: String,
    pub form: ExpectedValueForm,
}

/// Closed expected form for one disclosed Supported Value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedValueForm {
    Boolean,
    Integer,
    String,
    DateBucket,
    TimeBucket,
    EntityReference,
    Structured,
    List {
        minimum_items: usize,
        maximum_items: usize,
    },
}

/// Result of verifying a stored signed response.
///
/// A returned report means the trusted key signed the exact payload and every
/// policy expectation held. Current usability is reported separately so an
/// expired assertion can remain cryptographically authentic without being
/// treated as current evidence.
#[derive(Debug)]
pub struct VerificationReport {
    pub evidence: Evidence,
    pub currently_valid: bool,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    #[error("flattened JWS is malformed")]
    MalformedJws,
    #[error("protected JWS header is not allowed")]
    ProtectedHeader,
    #[error("JWS key identifier is unknown or ambiguous")]
    Key,
    #[error("JWS signature is invalid")]
    Signature,
    #[error("Evidence payload is malformed")]
    Payload,
    #[error("Evidence payload does not match the relying procedure")]
    Policy,
    #[error("Evidence payload is outside its validity interval")]
    Time,
    #[error("SD-JWT VC disclosures do not match the signed digests")]
    Disclosure,
}

impl VerificationError {
    /// A stable, machine-readable name for which kind of verification failure
    /// this is.
    ///
    /// It exists for callers that want to branch or aggregate on the failure
    /// without matching this crate's enum directly: a metric label, a
    /// structured log field, or a language binding that carries the
    /// discriminant across a boundary a Rust enum cannot cross. The rendered
    /// message is for people and may be reworded; these names are part of the
    /// crate's contract and will not be renamed.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::MalformedJws => "malformed_jws",
            Self::ProtectedHeader => "protected_header",
            Self::Key => "key",
            Self::Signature => "signature",
            Self::Payload => "payload",
            Self::Policy => "policy",
            Self::Time => "time",
            Self::Disclosure => "disclosure",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
    cty: String,
}

/// The SD-JWT VC header carries no `cty`: the credential type travels in the
/// signed `vct` claim.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdJwtHeader {
    alg: String,
    kid: String,
    typ: String,
}

/// Whether a pinned trusted key set is one this verifier could ever use.
///
/// Verification applies this rule to every response, so a key set that fails it
/// can never verify anything. Exposing it lets a relying party apply it once,
/// where it pinned the set, instead of learning per response that the pinning
/// decision was unusable. The rule stays owned here: this is the same check
/// verification performs, not a restatement of it.
pub fn trusted_keys_are_usable(trusted_jwks: &JwksDocument) -> Result<(), VerificationError> {
    trusted_keys(trusted_jwks).map(|_| ())
}

/// Strict one-call verification: cryptographic authenticity, every policy
/// expectation, and current validity must all hold.
pub fn verify_flattened_jws(
    serialized_jws: &[u8],
    trusted_jwks: &JwksDocument,
    policy: &EvidenceVerificationPolicy,
) -> Result<Evidence, VerificationError> {
    let report = verify_flattened_jws_report(serialized_jws, trusted_jwks, policy)?;
    if !report.currently_valid {
        return Err(VerificationError::Time);
    }
    Ok(report.evidence)
}

/// Verify a stored signed response against a pinned trusted key set and the
/// complete independent policy, reporting cryptographic authenticity
/// separately from current validity.
pub fn verify_flattened_jws_report(
    serialized_jws: &[u8],
    trusted_jwks: &JwksDocument,
    policy: &EvidenceVerificationPolicy,
) -> Result<VerificationReport, VerificationError> {
    if serialized_jws.is_empty() || serialized_jws.len() > MAX_JWS_BYTES {
        return Err(VerificationError::MalformedJws);
    }
    let strict = parse_json_strict(serialized_jws).map_err(|_| VerificationError::MalformedJws)?;
    let jws: FlattenedJws =
        serde_json::from_value(strict).map_err(|_| VerificationError::MalformedJws)?;

    let protected_bytes = decode_bounded(
        &jws.protected,
        MAX_PROTECTED_BYTES,
        VerificationError::ProtectedHeader,
    )?;
    let protected_strict =
        parse_json_strict(&protected_bytes).map_err(|_| VerificationError::ProtectedHeader)?;
    let protected: ProtectedHeader =
        serde_json::from_value(protected_strict).map_err(|_| VerificationError::ProtectedHeader)?;
    if protected.alg != "ES256"
        || protected.typ != EVIDENCE_JWS_TYP
        || protected.cty != EVIDENCE_JWS_CTY
        || !key_identifier_is_thumbprint(&protected.kid)
    {
        return Err(VerificationError::ProtectedHeader);
    }
    validate_revocations(&policy.revoked_key_ids)?;
    if policy
        .revoked_key_ids
        .iter()
        .any(|kid| kid == &protected.kid)
    {
        return Err(VerificationError::Key);
    }

    let keys = trusted_keys(trusted_jwks)?;
    let key = keys.get(&protected.kid).ok_or(VerificationError::Key)?;
    if key.algorithm().ok() != Some(SigningAlgorithm::Es256) {
        return Err(VerificationError::Key);
    }
    let signature = decode_bounded(
        &jws.signature,
        MAX_PROTECTED_BYTES,
        VerificationError::Signature,
    )?;
    let signing_input = [jws.protected.as_bytes(), b".", jws.payload.as_bytes()].concat();
    verify(&signing_input, &signature, key).map_err(|_| VerificationError::Signature)?;

    // Parse and act on the payload only after signature verification.
    let payload = decode_bounded(&jws.payload, MAX_PAYLOAD_BYTES, VerificationError::Payload)?;
    let payload_strict = parse_json_strict(&payload).map_err(|_| VerificationError::Payload)?;
    if !evidence_contract_accepts(&payload_strict).map_err(|_| VerificationError::Payload)? {
        return Err(VerificationError::Payload);
    }
    let evidence: Evidence =
        serde_json::from_value(payload_strict).map_err(|_| VerificationError::Payload)?;
    let currently_valid = validate_policy(&evidence, policy)?;
    Ok(VerificationReport {
        evidence,
        currently_valid,
    })
}

/// Strict one-call verification of an issued SD-JWT VC: cryptographic
/// authenticity, complete disclosure resolution, every policy expectation, and
/// current validity must all hold.
pub fn verify_sd_jwt_vc(
    serialized: &[u8],
    trusted_jwks: &JwksDocument,
    policy: &EvidenceVerificationPolicy,
) -> Result<Evidence, VerificationError> {
    let report = verify_sd_jwt_vc_report(serialized, trusted_jwks, policy)?;
    if !report.currently_valid {
        return Err(VerificationError::Time);
    }
    Ok(report.evidence)
}

/// Verify an issued SD-JWT VC against a pinned trusted key set and the
/// complete independent policy, reporting cryptographic authenticity
/// separately from current validity.
///
/// Version 1 issues only complete credentials, so verification requires every
/// signed digest to be resolved by exactly one presented disclosure. A holder
/// presenting a subset is out of scope for the issuance profile, and the
/// relying procedure's expected output contract would reject it in any case.
/// A key-binding JWT is never accepted here: the serialization must end with
/// the trailing tilde that marks its absence.
pub fn verify_sd_jwt_vc_report(
    serialized: &[u8],
    trusted_jwks: &JwksDocument,
    policy: &EvidenceVerificationPolicy,
) -> Result<VerificationReport, VerificationError> {
    if serialized.is_empty() || serialized.len() > MAX_JWS_BYTES {
        return Err(VerificationError::MalformedJws);
    }
    let serialized =
        std::str::from_utf8(serialized).map_err(|_| VerificationError::MalformedJws)?;
    let body = serialized
        .strip_suffix('~')
        .ok_or(VerificationError::MalformedJws)?;
    let mut segments = body.split('~');
    let jwt = segments.next().ok_or(VerificationError::MalformedJws)?;
    let encoded_disclosures: Vec<&str> = segments.collect();
    if encoded_disclosures.len() > MAX_DISCLOSURES
        || encoded_disclosures.iter().any(|value| value.is_empty())
    {
        return Err(VerificationError::MalformedJws);
    }

    let mut parts = jwt.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerificationError::MalformedJws);
    };

    let header_bytes = decode_bounded(
        encoded_header,
        MAX_PROTECTED_BYTES,
        VerificationError::ProtectedHeader,
    )?;
    let header_strict =
        parse_json_strict(&header_bytes).map_err(|_| VerificationError::ProtectedHeader)?;
    let header: SdJwtHeader =
        serde_json::from_value(header_strict).map_err(|_| VerificationError::ProtectedHeader)?;
    if header.alg != "ES256"
        || header.typ != EVIDENCE_SD_JWT_VC_TYP
        || !key_identifier_is_thumbprint(&header.kid)
    {
        return Err(VerificationError::ProtectedHeader);
    }
    validate_revocations(&policy.revoked_key_ids)?;
    if policy.revoked_key_ids.iter().any(|kid| kid == &header.kid) {
        return Err(VerificationError::Key);
    }

    let keys = trusted_keys(trusted_jwks)?;
    let key = keys.get(&header.kid).ok_or(VerificationError::Key)?;
    if key.algorithm().ok() != Some(SigningAlgorithm::Es256) {
        return Err(VerificationError::Key);
    }
    let signature = decode_bounded(
        encoded_signature,
        MAX_PROTECTED_BYTES,
        VerificationError::Signature,
    )?;
    let signing_input = [encoded_header.as_bytes(), b".", encoded_payload.as_bytes()].concat();
    verify(&signing_input, &signature, key).map_err(|_| VerificationError::Signature)?;

    // Parse and act on the payload only after signature verification.
    let payload_bytes = decode_bounded(
        encoded_payload,
        MAX_PAYLOAD_BYTES,
        VerificationError::Payload,
    )?;
    let payload_strict =
        parse_json_strict(&payload_bytes).map_err(|_| VerificationError::Payload)?;
    let Value::Object(mut claims) = payload_strict else {
        return Err(VerificationError::Payload);
    };

    let digests = signed_digests(&mut claims)?;
    let disclosed = resolve_disclosures(&encoded_disclosures, &digests, &mut claims)?;
    if let Some(confirmation) = claims.remove("cnf") {
        validate_confirmation(&confirmation)?;
    }

    let payload = evidence_payload_from_claims(&claims, &disclosed)
        .map_err(|_| VerificationError::Payload)?;
    if !evidence_contract_accepts(&payload).map_err(|_| VerificationError::Payload)? {
        return Err(VerificationError::Payload);
    }
    let evidence: Evidence =
        serde_json::from_value(payload).map_err(|_| VerificationError::Payload)?;
    let currently_valid = validate_policy(&evidence, policy)?;
    Ok(VerificationReport {
        evidence,
        currently_valid,
    })
}

/// Take the signed digest set out of the claims. The set must be sorted and
/// free of duplicates, matching the issuance profile exactly.
fn signed_digests(claims: &mut Map<String, Value>) -> Result<Vec<String>, VerificationError> {
    if claims
        .remove("_sd_alg")
        .and_then(|alg| alg.as_str().map(str::to_owned))
        != Some("sha-256".to_string())
    {
        return Err(VerificationError::Disclosure);
    }
    let listed = claims
        .remove("_sd")
        .ok_or(VerificationError::Disclosure)?
        .as_array()
        .ok_or(VerificationError::Disclosure)?
        .iter()
        .map(|digest| digest.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .ok_or(VerificationError::Disclosure)?;
    if listed.len() > MAX_DISCLOSURES
        || listed.windows(2).any(|pair| pair[0] >= pair[1])
        || listed.iter().any(|digest| digest.len() != 43)
    {
        return Err(VerificationError::Disclosure);
    }
    Ok(listed)
}

/// Resolve every presented disclosure against the signed digests. Each digest
/// must be claimed by exactly one disclosure, each disclosure must carry a
/// distinct name, and no disclosure may shadow a public claim.
fn resolve_disclosures(
    encoded: &[&str],
    digests: &[String],
    claims: &mut Map<String, Value>,
) -> Result<Vec<(String, Value)>, VerificationError> {
    #[derive(Clone)]
    enum Location {
        Root,
        Object(String),
    }

    let mut locations = BTreeMap::<String, Location>::new();
    for digest in digests {
        if locations.insert(digest.clone(), Location::Root).is_some() {
            return Err(VerificationError::Disclosure);
        }
    }
    let structured_claims = match claims.get("structuredValues") {
        None => Vec::new(),
        Some(Value::Object(metadata)) => metadata.keys().cloned().collect::<Vec<_>>(),
        Some(_) => return Err(VerificationError::Disclosure),
    };
    for claim in structured_claims {
        let object = claims
            .get_mut(&claim)
            .and_then(Value::as_object_mut)
            .ok_or(VerificationError::Disclosure)?;
        if object.len() != 1 {
            return Err(VerificationError::Disclosure);
        }
        let nested = object
            .remove("_sd")
            .and_then(|value| value.as_array().cloned())
            .ok_or(VerificationError::Disclosure)?;
        let nested = nested
            .iter()
            .map(|digest| digest.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or(VerificationError::Disclosure)?;
        if nested.is_empty()
            || nested.len() > 64
            || nested.windows(2).any(|pair| pair[0] >= pair[1])
            || nested.iter().any(|digest| digest.len() != 43)
        {
            return Err(VerificationError::Disclosure);
        }
        for digest in nested {
            if locations
                .insert(digest, Location::Object(claim.clone()))
                .is_some()
            {
                return Err(VerificationError::Disclosure);
            }
        }
    }
    if encoded.len() != locations.len() {
        return Err(VerificationError::Disclosure);
    }
    let mut resolved = Vec::with_capacity(encoded.len());
    let mut seen_digests = BTreeSet::new();
    let mut root_names = BTreeSet::new();
    let mut object_names = BTreeMap::<String, BTreeSet<String>>::new();
    for disclosure in encoded {
        if disclosure.len() > MAX_DISCLOSURE_BYTES {
            return Err(VerificationError::Disclosure);
        }
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
        let location = locations
            .get(&digest)
            .cloned()
            .ok_or(VerificationError::Disclosure)?;
        if !seen_digests.insert(digest) {
            return Err(VerificationError::Disclosure);
        }
        let decoded = decode_bounded(
            disclosure,
            MAX_DISCLOSURE_BYTES,
            VerificationError::Disclosure,
        )?;
        let strict = parse_json_strict(&decoded).map_err(|_| VerificationError::Disclosure)?;
        let Value::Array(members) = strict else {
            return Err(VerificationError::Disclosure);
        };
        let [salt, name, value] = members.as_slice() else {
            return Err(VerificationError::Disclosure);
        };
        let salt = salt.as_str().ok_or(VerificationError::Disclosure)?;
        let salt_bytes = URL_SAFE_NO_PAD
            .decode(salt)
            .map_err(|_| VerificationError::Disclosure)?;
        if salt_bytes.len() < MINIMUM_SALT_BYTES || salt_bytes.len() > MAXIMUM_SALT_BYTES {
            return Err(VerificationError::Disclosure);
        }
        let name = name.as_str().ok_or(VerificationError::Disclosure)?;
        match location {
            Location::Root => {
                if claims.contains_key(name) || !root_names.insert(name.to_owned()) {
                    return Err(VerificationError::Disclosure);
                }
                resolved.push((name.to_owned(), value.clone()));
            }
            Location::Object(claim) => {
                if name.is_empty()
                    || name.len() > 128
                    || name == "_sd"
                    || name == "..."
                    || name.chars().any(char::is_control)
                    || !object_names
                        .entry(claim.clone())
                        .or_default()
                        .insert(name.to_owned())
                {
                    return Err(VerificationError::Disclosure);
                }
                let object = claims
                    .get_mut(&claim)
                    .and_then(Value::as_object_mut)
                    .ok_or(VerificationError::Disclosure)?;
                if object.insert(name.to_owned(), value.clone()).is_some() {
                    return Err(VerificationError::Disclosure);
                }
            }
        }
    }
    Ok(resolved)
}

/// The confirmation, when present, carries exactly one P-256 public key and
/// no private material.
fn validate_confirmation(confirmation: &Value) -> Result<(), VerificationError> {
    let Some(members) = confirmation.as_object() else {
        return Err(VerificationError::Payload);
    };
    if members.len() != 1 {
        return Err(VerificationError::Payload);
    }
    let jwk = members.get("jwk").ok_or(VerificationError::Payload)?;
    let key: HolderPublicKey =
        serde_json::from_value(jwk.clone()).map_err(|_| VerificationError::Payload)?;
    if !key.is_acceptable() {
        return Err(VerificationError::Payload);
    }
    Ok(())
}

fn trusted_keys(jwks: &JwksDocument) -> Result<BTreeMap<String, PublicJwk>, VerificationError> {
    if jwks.keys.is_empty() || jwks.keys.len() > MAX_TRUSTED_KEYS {
        return Err(VerificationError::Key);
    }
    let mut output = BTreeMap::new();
    for value in &jwks.keys {
        let members = value.as_object().ok_or(VerificationError::Key)?;
        let exact_members = ["alg", "crv", "kid", "kty", "x", "y"]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if members.keys().map(String::as_str).collect::<BTreeSet<_>>() != exact_members {
            return Err(VerificationError::Key);
        }
        let key: PublicJwk =
            serde_json::from_value(value.clone()).map_err(|_| VerificationError::Key)?;
        let kid = key.kid.clone().ok_or(VerificationError::Key)?;
        if !key_identifier_is_thumbprint(&kid)
            || key.algorithm().ok() != Some(SigningAlgorithm::Es256)
            || key.jkt().ok().as_deref() != Some(kid.as_str())
            || output.insert(kid, key).is_some()
        {
            return Err(VerificationError::Key);
        }
    }
    Ok(output)
}

/// Validate a relying party's emergency service-key denylist.
///
/// This is public so clients can reject unusable pinned trust configuration at
/// construction rather than deferring the same failure to every verification.
/// An identifier may deliberately still appear in a cached JWKS: revocation is
/// checked first and overrides that cached key.
pub fn revoked_key_ids_are_usable(revoked_key_ids: &[String]) -> Result<(), VerificationError> {
    if revoked_key_ids.len() > MAX_TRUSTED_KEYS
        || revoked_key_ids
            .iter()
            .any(|kid| !key_identifier_is_thumbprint(kid))
        || revoked_key_ids.iter().collect::<BTreeSet<_>>().len() != revoked_key_ids.len()
    {
        return Err(VerificationError::Key);
    }
    Ok(())
}

fn validate_revocations(revoked_key_ids: &[String]) -> Result<(), VerificationError> {
    revoked_key_ids_are_usable(revoked_key_ids)
}

fn key_identifier_is_thumbprint(kid: &str) -> bool {
    kid.len() == 43
        && kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && URL_SAFE_NO_PAD
            .decode(kid)
            .is_ok_and(|decoded| decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == kid)
}

/// Compare every policy expectation after signature and schema verification.
///
/// Every mismatch, including the expected nonce, expected role-bound subject
/// set, and expected output contract, returns the one generic policy error so
/// verification does not reveal which hidden comparison failed. The returned
/// boolean is current validity, which is reported separately from
/// authenticity and policy conformance.
fn validate_policy(
    evidence: &Evidence,
    policy: &EvidenceVerificationPolicy,
) -> Result<bool, VerificationError> {
    if evidence.schema != EVIDENCE_SCHEMA_V1
        || evidence.assurance_profile != policy.assurance_profile
        || evidence.issued_by != policy.issued_by
        || evidence.provided_by != policy.provided_by
        || evidence.supports_requirement != policy.requirement
        || evidence.is_conformant_to != policy.evidence_type
        || evidence.purpose != policy.purpose
        || evidence.audience != policy.audience
        || evidence.configuration_revision != policy.configuration_revision
        || evidence.subjects.is_empty()
        || evidence.supported_values.is_empty()
        || evidence.request_nonce != policy.request_nonce
    {
        return Err(VerificationError::Policy);
    }
    validate_expected_subjects(evidence, policy)?;
    validate_expected_outputs(evidence, policy)?;

    let issued = parse_time(&evidence.issued_at)?;
    let observed = parse_time(&evidence.observed_at)?;
    let valid_until = parse_time(&evidence.valid_until)?;
    let skew =
        chrono::Duration::from_std(policy.clock_skew).map_err(|_| VerificationError::Time)?;
    let maximum_lifetime = chrono::Duration::from_std(policy.maximum_assertion_lifetime)
        .map_err(|_| VerificationError::Time)?;
    let expiration_with_skew = valid_until
        .checked_add_signed(skew)
        .ok_or(VerificationError::Time)?;
    // Internal chronology and the accepted-lifetime ceiling are hard errors;
    // an internally inconsistent or over-long assertion is never acceptable.
    if issued < observed
        || valid_until <= observed
        || valid_until <= issued
        || valid_until - issued > maximum_lifetime
    {
        return Err(VerificationError::Time);
    }
    let latest_acceptable_issue = policy
        .now
        .checked_add_signed(skew)
        .ok_or(VerificationError::Time)?;
    let currently_valid = issued <= latest_acceptable_issue
        && observed <= latest_acceptable_issue
        && policy.now < expiration_with_skew;
    Ok(currently_valid)
}

/// Compare the unordered set of unique expected `(role, binding)` pairs.
fn validate_expected_subjects(
    evidence: &Evidence,
    policy: &EvidenceVerificationPolicy,
) -> Result<(), VerificationError> {
    let mut expected = policy.expected_subjects.clone();
    expected.sort();
    if expected.is_empty() || expected.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(VerificationError::Policy);
    }
    let mut actual = evidence
        .subjects
        .iter()
        .map(|subject| ExpectedSubject {
            role: subject.role.clone(),
            binding: subject.binding.clone(),
        })
        .collect::<Vec<_>>();
    actual.sort();
    if actual != expected {
        return Err(VerificationError::Policy);
    }
    Ok(())
}

/// Compare the expected concept identifiers, value forms, and cardinalities.
fn validate_expected_outputs(
    evidence: &Evidence,
    policy: &EvidenceVerificationPolicy,
) -> Result<(), VerificationError> {
    let expected = &policy.expected_outputs;
    if expected.is_empty() || evidence.supported_values.len() != expected.len() {
        return Err(VerificationError::Policy);
    }
    let mut concepts = BTreeMap::new();
    for output in expected {
        if concepts
            .insert(output.concept.as_str(), &output.form)
            .is_some()
        {
            return Err(VerificationError::Policy);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in &evidence.supported_values {
        let concept = value.provides_value_for.as_str();
        let Some(form) = concepts.get(concept) else {
            return Err(VerificationError::Policy);
        };
        if !seen.insert(concept) || !value_matches_form(&value.value, form) {
            return Err(VerificationError::Policy);
        }
    }
    Ok(())
}

fn value_matches_form(value: &crate::model::PublicValue, form: &ExpectedValueForm) -> bool {
    use crate::model::{BucketForm, PublicValue};
    match (value, form) {
        (PublicValue::Boolean(_), ExpectedValueForm::Boolean)
        | (PublicValue::Integer(_), ExpectedValueForm::Integer)
        | (PublicValue::String(_), ExpectedValueForm::String)
        | (PublicValue::EntityReference(_), ExpectedValueForm::EntityReference)
        | (PublicValue::Structured(_), ExpectedValueForm::Structured) => true,
        (PublicValue::Bucket(bucket), ExpectedValueForm::DateBucket) => {
            bucket.form == BucketForm::DateBucket
        }
        (PublicValue::Bucket(bucket), ExpectedValueForm::TimeBucket) => {
            bucket.form == BucketForm::TimeBucket
        }
        (
            PublicValue::List(items),
            ExpectedValueForm::List {
                minimum_items,
                maximum_items,
            },
        ) => items.len() >= *minimum_items && items.len() <= *maximum_items,
        _ => false,
    }
}

fn parse_time(input: &str) -> Result<DateTime<Utc>, VerificationError> {
    DateTime::parse_from_rfc3339(input)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| VerificationError::Time)
}

fn decode_bounded(
    input: &str,
    maximum: usize,
    error: VerificationError,
) -> Result<Vec<u8>, VerificationError> {
    let decoded = URL_SAFE_NO_PAD.decode(input).map_err(|_| error)?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(error);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use p256::elliptic_curve::rand_core::OsRng;
    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
    use serde::Deserialize;
    use serde_json::{json, Value};

    use super::*;
    use crate::fixtures::{jwks_document, EvidenceSigner};
    use crate::model::{
        EvidenceObjectType, PublicValue, StructuredValue, StructuredValueForm, SubjectBinding,
        SupportedValue,
    };

    const KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
    const RETIRED_KEY_ID: &str = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M";
    const PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
    const RETIRED_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}"#;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExternalVectorFixture {
        fixture: String,
        synthetic_only: bool,
        compatibility_claim: String,
        purpose: String,
        issuer_public_jwk: PublicJwk,
        vectors: Vec<ExternalVector>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExternalVector {
        id: String,
        standard: String,
        provenance: ExternalVectorProvenance,
        serialized: String,
        expected: ExternalVectorExpected,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ExternalVectorProvenance {
        source: String,
        revision: String,
        location: String,
        derivation: String,
        serialized_sha256: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ExternalVectorExpected {
        protected_typ: String,
        issuer: String,
        #[serde(default)]
        vct: Option<String>,
        disclosure_names: Vec<String>,
        evidence_profile_rejection: String,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ExternalPresentation {
        protected_typ: String,
        issuer: String,
        vct: Option<String>,
        disclosure_names: Vec<String>,
    }

    fn verify_external_presentation(
        serialized: &str,
        public_key: &PublicJwk,
    ) -> Result<ExternalPresentation, &'static str> {
        let without_trailing_tilde = serialized
            .strip_suffix('~')
            .ok_or("presentation lacks the no-KB-JWT trailing tilde")?;
        let mut presentation_parts = without_trailing_tilde.split('~');
        let jwt = presentation_parts.next().ok_or("issuer JWT is absent")?;
        let disclosures = presentation_parts.collect::<Vec<_>>();
        if disclosures.is_empty() || disclosures.iter().any(|value| value.is_empty()) {
            return Err("presentation disclosures are absent or empty");
        }

        let jwt_parts = jwt.split('.').collect::<Vec<_>>();
        let [protected, payload, encoded_signature] = jwt_parts.as_slice() else {
            return Err("issuer JWT is not compact JWS");
        };
        let header_bytes = URL_SAFE_NO_PAD
            .decode(protected)
            .map_err(|_| "protected header is not base64url")?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "payload is not base64url")?;
        let signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| "signature is not base64url")?;
        let header = parse_json_strict(&header_bytes).map_err(|_| "header is not strict JSON")?;
        let payload_value =
            parse_json_strict(&payload_bytes).map_err(|_| "payload is not strict JSON")?;
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err("external vector is not ES256");
        }
        verify(
            format!("{protected}.{payload}").as_bytes(),
            &signature,
            public_key,
        )
        .map_err(|_| "external ES256 signature does not verify")?;

        let payload = payload_value
            .as_object()
            .ok_or("external payload is not an object")?;
        if payload.get("_sd_alg").and_then(Value::as_str) != Some("sha-256") {
            return Err("external vector does not select sha-256 disclosures");
        }
        let mut embedded_digests = BTreeSet::new();
        collect_external_sd_digests(&payload_value, &mut embedded_digests);
        let mut disclosure_names = Vec::with_capacity(disclosures.len());
        for disclosure in disclosures {
            let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
            if !embedded_digests.contains(&digest) {
                return Err("presented disclosure digest is not signed");
            }
            let disclosure_bytes = URL_SAFE_NO_PAD
                .decode(disclosure)
                .map_err(|_| "disclosure is not base64url")?;
            let disclosure_value = parse_json_strict(&disclosure_bytes)
                .map_err(|_| "disclosure is not strict JSON")?;
            let disclosure_array = disclosure_value
                .as_array()
                .filter(|members| members.len() == 3)
                .ok_or("disclosure is not a property disclosure")?;
            disclosure_names.push(
                disclosure_array[1]
                    .as_str()
                    .ok_or("disclosure name is not a string")?
                    .to_owned(),
            );
        }

        Ok(ExternalPresentation {
            protected_typ: header
                .get("typ")
                .and_then(Value::as_str)
                .ok_or("protected typ is absent")?
                .to_owned(),
            issuer: payload
                .get("iss")
                .and_then(Value::as_str)
                .ok_or("issuer is absent")?
                .to_owned(),
            vct: payload
                .get("vct")
                .and_then(Value::as_str)
                .map(str::to_owned),
            disclosure_names,
        })
    }

    fn collect_external_sd_digests(value: &Value, output: &mut BTreeSet<String>) {
        match value {
            Value::Object(members) => {
                if members.len() == 1 {
                    if let Some(digest) = members.get("...").and_then(Value::as_str) {
                        output.insert(digest.to_owned());
                    }
                }
                if let Some(digests) = members.get("_sd").and_then(Value::as_array) {
                    output.extend(digests.iter().filter_map(Value::as_str).map(str::to_owned));
                }
                for member in members.values() {
                    collect_external_sd_digests(member, output);
                }
            }
            Value::Array(members) => {
                for member in members {
                    collect_external_sd_digests(member, output);
                }
            }
            _ => {}
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn mutate_external_signature(serialized: &str) -> String {
        let mut presentation_parts = serialized
            .strip_suffix('~')
            .expect("fixture has trailing tilde")
            .split('~')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut jwt_parts = presentation_parts[0]
            .split('.')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut signature = URL_SAFE_NO_PAD
            .decode(&jwt_parts[2])
            .expect("fixture signature decodes");
        signature[0] ^= 1;
        jwt_parts[2] = URL_SAFE_NO_PAD.encode(signature);
        presentation_parts[0] = jwt_parts.join(".");
        format!("{}~", presentation_parts.join("~"))
    }

    fn mutate_first_external_disclosure(serialized: &str) -> String {
        let mut parts = serialized
            .strip_suffix('~')
            .expect("fixture has trailing tilde")
            .split('~')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let disclosure = parts.get_mut(1).expect("fixture has a disclosure");
        let last = disclosure.pop().expect("fixture disclosure is nonempty");
        disclosure.push(if last == 'A' { 'B' } else { 'A' });
        format!("{}~", parts.join("~"))
    }

    async fn sign_with_protected_header(
        private_jwk: &str,
        protected_header: Value,
        evidence: &Evidence,
    ) -> (Vec<u8>, PublicJwk) {
        sign_payload_bytes(
            private_jwk,
            protected_header,
            &serde_json::to_vec(evidence).expect("Evidence serializes"),
        )
        .await
    }

    async fn sign_payload_bytes(
        private_jwk: &str,
        protected_header: Value,
        payload_bytes: &[u8],
    ) -> (Vec<u8>, PublicJwk) {
        let private = PrivateJwk::parse(private_jwk).expect("test key parses");
        let signer = LocalJwkSigner::new(private).expect("test signer builds");
        let protected = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&protected_header).expect("protected header serializes"));
        let payload = URL_SAFE_NO_PAD.encode(payload_bytes);
        let signing_input = format!("{protected}.{payload}");
        let signature = signer
            .sign(signing_input.as_bytes())
            .await
            .expect("test JWS signs");
        let jws = FlattenedJws {
            protected,
            payload,
            signature: URL_SAFE_NO_PAD.encode(signature),
        };
        (
            serde_json::to_vec(&jws).expect("JWS serializes"),
            signer.public_jwk(),
        )
    }

    const FIXTURE_NONCE: &str = "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I";

    fn fixture_evidence() -> Evidence {
        Evidence {
            schema: EVIDENCE_SCHEMA_V1.to_string(),
            assurance_profile: AssuranceProfile::EvidenceGrade,
            request_nonce: FIXTURE_NONCE.to_string(),
            id: "urn:ulid:01K1EXAMPLE0000000000000000".to_string(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "urn:example:requirement:v1".to_string(),
            is_conformant_to: "urn:example:type:v1".to_string(),
            issued_by: "urn:example:issuer".to_string(),
            provided_by: "urn:example:provider".to_string(),
            issued_at: "2026-08-02T00:00:00Z".to_string(),
            observed_at: "2026-08-02T00:00:00Z".to_string(),
            valid_until: "2026-08-03T00:00:00Z".to_string(),
            purpose: "casework".to_string(),
            audience: "urn:example:audience".to_string(),
            configuration_revision: format!("sha256:{}", "0".repeat(64)),
            subjects: vec![SubjectBinding {
                role: "subject".to_string(),
                binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
            }],
            supported_values: vec![SupportedValue {
                provides_value_for: "urn:example:concept".to_string(),
                value: PublicValue::Boolean(false),
            }],
        }
    }

    async fn signed_evidence(
        evidence: Evidence,
        now: DateTime<Utc>,
    ) -> (Vec<u8>, JwksDocument, EvidenceVerificationPolicy) {
        let private = PrivateJwk::parse(PRIVATE_JWK).expect("key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("signer builds"));
        let signer = EvidenceSigner::initialize(provider, KEY_ID)
            .await
            .expect("signer initializes");
        let jws = signer.sign_json(&evidence).await.expect("evidence signs");
        let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let policy = policy_for(&evidence, now);
        (serialized, jwks, policy)
    }

    /// Build expectations equal to one known evidence value. Production
    /// relying parties obtain these from independent trusted state; the test
    /// simulates that state from the fixture it controls.
    fn policy_for(evidence: &Evidence, now: DateTime<Utc>) -> EvidenceVerificationPolicy {
        EvidenceVerificationPolicy::from_accepted_transaction(
            evidence,
            &evidence.request_nonce,
            48 * 60 * 60,
            now,
            30,
        )
        .expect("the fixture policy states bounds the contract allows")
    }

    async fn signed_fixture() -> (Vec<u8>, JwksDocument, EvidenceVerificationPolicy) {
        signed_evidence(
            fixture_evidence(),
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        )
        .await
    }

    #[test]
    fn external_rfc9901_and_draft18_vectors_verify_shared_cryptography_and_preserve_profile_boundary(
    ) {
        let fixture: ExternalVectorFixture = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/external-sd-jwt-vectors.yaml"
        ))
        .expect("external vector fixture parses");
        assert_eq!(
            fixture.fixture,
            "registry.evidence.external-sd-jwt-vectors/v1"
        );
        assert!(fixture.synthetic_only);
        assert_eq!(fixture.compatibility_claim, "none");
        assert!(fixture.purpose.contains("shared ES256 and RFC 9901"));
        assert_eq!(fixture.vectors.len(), 2);

        let mut evidence_jwk = fixture.issuer_public_jwk.clone();
        evidence_jwk.kid = Some(
            evidence_jwk
                .jkt()
                .expect("external key thumbprint computes"),
        );
        let evidence_jwks = jwks_document(evidence_jwk, []).expect("strict Evidence JWKS builds");
        let evidence_policy = policy_for(
            &fixture_evidence(),
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        );

        for vector in &fixture.vectors {
            let (expected_standard, expected_source, expected_revision, expected_sha256) =
                match vector.id.as_str() {
                    "rfc-9901-section-5-single-disclosure" => (
                        "RFC 9901",
                        "https://www.rfc-editor.org/rfc/rfc9901.txt",
                        "RFC 9901, November 2025",
                        "ded07ccce2201ac557def085e1f514f2669e1274914c33efdd7459a04bae50f2",
                    ),
                    "sd-jwt-vc-draft-18-figure-10" => (
                        "draft-ietf-oauth-sd-jwt-vc-18",
                        "https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.txt",
                        "draft-ietf-oauth-sd-jwt-vc-18; oauth-wg tag commit 69e50ea623367c212c12c680e35e256b640b5f6b",
                        "d76ee28606ccc124fb90567f2511ddd5f2cddf2ee3f2ff7eeebfa51b3e759ad2",
                    ),
                    other => panic!("unexpected external vector {other}"),
                };
            assert_eq!(vector.standard, expected_standard);
            assert_eq!(vector.provenance.source, expected_source);
            assert_eq!(vector.provenance.revision, expected_revision);
            assert!(!vector.provenance.location.is_empty());
            assert!(!vector.provenance.derivation.is_empty());
            assert_eq!(vector.provenance.serialized_sha256, expected_sha256);
            assert_eq!(sha256_hex(vector.serialized.as_bytes()), expected_sha256);

            let verified =
                verify_external_presentation(&vector.serialized, &fixture.issuer_public_jwk)
                    .expect("authoritative external vector verifies");
            assert_eq!(
                verified,
                ExternalPresentation {
                    protected_typ: vector.expected.protected_typ.clone(),
                    issuer: vector.expected.issuer.clone(),
                    vct: vector.expected.vct.clone(),
                    disclosure_names: vector.expected.disclosure_names.clone(),
                }
            );

            assert!(verify_external_presentation(
                &mutate_external_signature(&vector.serialized),
                &fixture.issuer_public_jwk,
            )
            .is_err());
            assert!(verify_external_presentation(
                &mutate_first_external_disclosure(&vector.serialized),
                &fixture.issuer_public_jwk,
            )
            .is_err());

            assert_eq!(
                vector.expected.evidence_profile_rejection,
                "protected-header"
            );
            assert_eq!(
                verify_sd_jwt_vc(
                    vector.serialized.as_bytes(),
                    &evidence_jwks,
                    &evidence_policy,
                ),
                Err(VerificationError::ProtectedHeader),
                "external standards vectors must not silently widen the Evidence profile",
            );
        }
    }

    #[test]
    fn verifier_requires_canonical_sha256_thumbprint_encoding() {
        assert!(key_identifier_is_thumbprint(&"A".repeat(43)));
        assert!(!key_identifier_is_thumbprint(&format!(
            "{}B",
            "A".repeat(42)
        )));
    }

    #[tokio::test]
    async fn signed_false_round_trips_and_verifies() {
        let (jws, jwks, policy) = signed_fixture().await;
        let evidence = verify_flattened_jws(&jws, &jwks, &policy).expect("JWS verifies");
        assert_eq!(
            evidence.supported_values[0].value,
            PublicValue::Boolean(false)
        );
    }

    #[tokio::test]
    async fn authentic_local_assertions_fail_deployable_assurance_expectations() {
        let mut local = fixture_evidence();
        local.assurance_profile = AssuranceProfile::Local;
        let (jws, jwks, mut strict_policy) = signed_evidence(
            local.clone(),
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        )
        .await;
        strict_policy.assurance_profile = AssuranceProfile::Production;
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &strict_policy),
            Err(VerificationError::Policy)
        );

        let signer = fixture_signer().await;
        let input = crate::sdjwt_vc::issuance_input(&local, None, &BTreeMap::new())
            .expect("local evidence maps");
        let serialized = signer
            .sign_sd_jwt_vc(input)
            .await
            .expect("local SD-JWT VC serializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        assert_eq!(
            verify_sd_jwt_vc(serialized.as_bytes(), &jwks, &strict_policy),
            Err(VerificationError::Policy)
        );
    }

    #[tokio::test]
    async fn signed_payload_must_satisfy_the_complete_evidence_schema() {
        let mut cases = Vec::new();

        let mut invalid_id = fixture_evidence();
        invalid_id.id = "not a URI".to_owned();
        cases.push(invalid_id);

        let mut invalid_role = fixture_evidence();
        invalid_role.subjects[0].role = "Uppercase".to_owned();
        cases.push(invalid_role);

        let mut invalid_binding = fixture_evidence();
        invalid_binding.subjects[0].binding = "raw-subject-identifier".to_owned();
        cases.push(invalid_binding);

        let mut invalid_concept = fixture_evidence();
        invalid_concept.supported_values[0].provides_value_for = "not a URI".to_owned();
        cases.push(invalid_concept);

        let mut empty_public_string = fixture_evidence();
        empty_public_string.supported_values[0].value = PublicValue::String(String::new());
        cases.push(empty_public_string);

        let mut excessive_subjects = fixture_evidence();
        excessive_subjects.subjects = (0..9)
            .map(|index| SubjectBinding {
                role: format!("subject-{index}"),
                binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
            })
            .collect();
        cases.push(excessive_subjects);

        for evidence in cases {
            let (jws, jwks, policy) = signed_evidence(
                evidence,
                "2026-08-02T12:00:00Z".parse().expect("time parses"),
            )
            .await;
            assert_eq!(
                verify_flattened_jws(&jws, &jwks, &policy),
                Err(VerificationError::Payload)
            );
        }
    }

    #[tokio::test]
    async fn signed_schema_integer_lexical_forms_verify_without_type_loss() {
        let base = serde_json::to_string(&fixture_evidence()).expect("Evidence serializes");
        assert_eq!(base.matches("\"value\":false").count(), 1);
        let header = json!({
            "alg": "ES256",
            "kid": KEY_ID,
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY
        });
        let (_, _, mut policy) = signed_fixture().await;
        policy.expected_outputs[0].form = ExpectedValueForm::Integer;

        for number in ["1.0", "1e0"] {
            let payload = base.replace("\"value\":false", &format!("\"value\":{number}"));
            let (serialized, public) =
                sign_payload_bytes(PRIVATE_JWK, header.clone(), payload.as_bytes()).await;
            let jwks = jwks_document(public, []).expect("JWKS builds");
            let evidence = verify_flattened_jws(&serialized, &jwks, &policy)
                .expect("schema-valid integral JSON number verifies");
            assert_eq!(evidence.supported_values[0].value, PublicValue::Integer(1));
        }
    }

    #[tokio::test]
    async fn payload_and_protected_header_mutation_fail() {
        let (jws, jwks, policy) = signed_fixture().await;
        let mut value: serde_json::Value = serde_json::from_slice(&jws).expect("JWS parses");
        let payload = value["payload"].as_str().expect("payload").to_string();
        value["payload"] = Value::String(format!("A{}", &payload[1..]));
        assert!(matches!(
            verify_flattened_jws(
                &serde_json::to_vec(&value).expect("serializes"),
                &jwks,
                &policy
            ),
            Err(VerificationError::Signature)
        ));

        let (jws, jwks, policy) = signed_fixture().await;
        let mut value: serde_json::Value = serde_json::from_slice(&jws).expect("JWS parses");
        let protected = value["protected"].as_str().expect("protected").to_string();
        value["protected"] = Value::String(format!("A{}", &protected[1..]));
        assert!(verify_flattened_jws(
            &serde_json::to_vec(&value).expect("serializes"),
            &jwks,
            &policy
        )
        .is_err());
    }

    #[tokio::test]
    async fn duplicate_jws_members_and_unknown_kid_are_rejected() {
        let (jws, mut jwks, policy) = signed_fixture().await;
        let value: serde_json::Value = serde_json::from_slice(&jws).expect("JWS parses");
        let duplicate = format!(
            "{{\"protected\":{},\"protected\":{},\"payload\":{},\"signature\":{}}}",
            value["protected"], value["protected"], value["payload"], value["signature"]
        );
        assert_eq!(
            verify_flattened_jws(duplicate.as_bytes(), &jwks, &policy),
            Err(VerificationError::MalformedJws)
        );
        jwks.keys.clear();
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &policy),
            Err(VerificationError::Key)
        );
    }

    #[tokio::test]
    async fn signature_never_substitutes_for_provider_and_issuer_trust_policy() {
        let (jws, jwks, policy) = signed_fixture().await;
        let mut untrusted_provider = policy.clone();
        untrusted_provider.provided_by = "urn:example:untrusted-provider".to_owned();
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &untrusted_provider),
            Err(VerificationError::Policy)
        );

        let mut untrusted_issuer = policy;
        untrusted_issuer.issued_by = "urn:example:untrusted-issuer".to_owned();
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &untrusted_issuer),
            Err(VerificationError::Policy)
        );
    }

    #[tokio::test]
    async fn signed_chronology_and_clock_arithmetic_fail_closed() {
        let mut reversed = fixture_evidence();
        reversed.observed_at = "2026-08-02T00:01:00Z".to_owned();
        let (jws, jwks, policy) = signed_evidence(
            reversed,
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        )
        .await;
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &policy),
            Err(VerificationError::Time)
        );

        let mut expired_when_issued = fixture_evidence();
        expired_when_issued.issued_at = "2026-08-03T00:00:00Z".to_owned();
        expired_when_issued.valid_until = "2026-08-03T00:00:00Z".to_owned();
        let (jws, jwks, policy) = signed_evidence(
            expired_when_issued,
            "2026-08-03T00:00:00Z".parse().expect("time parses"),
        )
        .await;
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &policy),
            Err(VerificationError::Time)
        );

        let (jws, jwks, mut policy) = signed_fixture().await;
        policy.now = DateTime::<Utc>::MAX_UTC;
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &policy),
            Err(VerificationError::Time)
        );
    }

    #[tokio::test]
    async fn complete_jws_negative_fixture_is_executable() {
        let fixture: Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/fixtures/conformance/jws-cases.yaml"
        ))
        .expect("JWS fixture parses");
        let negatives = fixture["negative"]
            .as_array()
            .expect("negative cases are an array")
            .iter()
            .map(|value| value.as_str().expect("negative case is text"))
            .collect::<Vec<_>>();
        assert_eq!(
            negatives,
            [
                "mutate one protected-header byte",
                "mutate one payload byte",
                "remove signature",
                "add an unprotected header",
                "add jku, x5u, jwk, x5c, crit, or b64",
                "unknown kid",
                "revoked kid, even when the key remains in a cached JWKS",
                "algorithm mismatch",
                "signed payload violates the Evidence JSON Schema",
                "duplicate evidence object beside payload",
                "signing-provider failure",
            ]
        );

        let evidence = fixture_evidence();
        let base_header = json!({
            "alg": "ES256",
            "kid": KEY_ID,
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY
        });
        let (valid, public) =
            sign_with_protected_header(PRIVATE_JWK, base_header.clone(), &evidence).await;
        let jwks = jwks_document(public, []).expect("JWKS builds");
        let (_, _, policy) = signed_fixture().await;
        assert!(verify_flattened_jws(&valid, &jwks, &policy).is_ok());
        let mut revoked = policy.clone();
        revoked.revoked_key_ids = vec![KEY_ID.to_owned()];
        assert_eq!(
            verify_flattened_jws(&valid, &jwks, &revoked),
            Err(VerificationError::Key)
        );

        let mut missing_signature: Value = serde_json::from_slice(&valid).expect("JWS parses");
        missing_signature
            .as_object_mut()
            .expect("JWS is an object")
            .remove("signature");
        assert_eq!(
            verify_flattened_jws(
                &serde_json::to_vec(&missing_signature).expect("serializes"),
                &jwks,
                &policy
            ),
            Err(VerificationError::MalformedJws)
        );

        for extra in [
            ("header", json!({"kid": KEY_ID})),
            (
                "evidence",
                serde_json::to_value(&evidence).expect("Evidence serializes"),
            ),
        ] {
            let mut value: Value = serde_json::from_slice(&valid).expect("JWS parses");
            value
                .as_object_mut()
                .expect("JWS is an object")
                .insert(extra.0.to_owned(), extra.1);
            assert_eq!(
                verify_flattened_jws(
                    &serde_json::to_vec(&value).expect("serializes"),
                    &jwks,
                    &policy
                ),
                Err(VerificationError::MalformedJws)
            );
        }

        for (name, value) in [
            ("jku", json!("https://attacker.invalid/jwks.json")),
            ("x5u", json!("https://attacker.invalid/cert.pem")),
            ("jwk", json!({"kty": "OKP"})),
            ("x5c", json!(["certificate-canary"])),
            ("crit", json!(["exp"])),
            ("b64", json!(false)),
        ] {
            let mut header = base_header.clone();
            header
                .as_object_mut()
                .expect("header is an object")
                .insert(name.to_owned(), value);
            let (serialized, public) =
                sign_with_protected_header(PRIVATE_JWK, header, &evidence).await;
            let keys = jwks_document(public, []).expect("JWKS builds");
            assert_eq!(
                verify_flattened_jws(&serialized, &keys, &policy),
                Err(VerificationError::ProtectedHeader),
                "{name}"
            );
        }

        for (header, expected) in [
            (
                json!({
                    "alg": "ES256", "kid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "typ": EVIDENCE_JWS_TYP,
                    "cty": EVIDENCE_JWS_CTY
                }),
                VerificationError::Key,
            ),
            (
                json!({
                    "alg": "HS256", "kid": KEY_ID, "typ": EVIDENCE_JWS_TYP,
                    "cty": EVIDENCE_JWS_CTY
                }),
                VerificationError::ProtectedHeader,
            ),
        ] {
            let (serialized, _) = sign_with_protected_header(PRIVATE_JWK, header, &evidence).await;
            assert_eq!(
                verify_flattened_jws(&serialized, &jwks, &policy),
                Err(expected)
            );
        }
    }

    #[tokio::test]
    async fn expected_nonce_must_match_and_reuse_is_not_replay_prevention() {
        let (jws, jwks, policy) = signed_fixture().await;

        // Changing the expected nonce fails with the generic policy mismatch.
        let mut wrong_expectation = policy.clone();
        wrong_expectation.request_nonce = "B".repeat(43);
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &wrong_expectation),
            Err(VerificationError::Policy)
        );

        // Changing the signed nonce fails: re-signing a mutated payload with
        // the same trusted key still mismatches the retained expectation.
        let mut mutated = fixture_evidence();
        mutated.request_nonce = "B".repeat(43);
        let header = json!({
            "alg": "ES256",
            "kid": KEY_ID,
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY
        });
        let (mutated_jws, public) = sign_with_protected_header(PRIVATE_JWK, header, &mutated).await;
        let mutated_jwks = jwks_document(public, []).expect("JWKS builds");
        assert_eq!(
            verify_flattened_jws(&mutated_jws, &mutated_jwks, &policy),
            Err(VerificationError::Policy)
        );

        // The runtime does not store nonces, so verifying the same stored
        // response twice with the same expectation succeeds. The nonce proves
        // correlation with the retained request, never one-time use.
        assert!(verify_flattened_jws(&jws, &jwks, &policy).is_ok());
        assert!(verify_flattened_jws(&jws, &jwks, &policy).is_ok());
    }

    #[tokio::test]
    async fn expected_subject_set_is_unordered_unique_and_exact() {
        let mut evidence = fixture_evidence();
        evidence.subjects = vec![
            SubjectBinding {
                role: "child".to_string(),
                binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
            },
            SubjectBinding {
                role: "candidate-parent".to_string(),
                binding: format!("urn:evidence:subject:v1_{}", "B".repeat(43)),
            },
        ];
        let (jws, jwks, policy) = signed_evidence(
            evidence,
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        )
        .await;

        // Subject order alone is non-semantic.
        let mut reordered = policy.clone();
        reordered.expected_subjects.reverse();
        assert!(verify_flattened_jws(&jws, &jwks, &reordered).is_ok());

        // Missing, extra, duplicated, substituted, and wrong-key-version
        // expectations all fail with the one generic policy mismatch.
        let mut missing = policy.clone();
        missing.expected_subjects.pop();
        let mut extra = policy.clone();
        extra.expected_subjects.push(ExpectedSubject {
            role: "witness".to_string(),
            binding: format!("urn:evidence:subject:v1_{}", "C".repeat(43)),
        });
        let mut duplicated = policy.clone();
        let first = duplicated.expected_subjects[0].clone();
        duplicated.expected_subjects.push(first);
        let mut substituted = policy.clone();
        substituted.expected_subjects[0].binding =
            format!("urn:evidence:subject:v1_{}", "D".repeat(43));
        let mut wrong_key_version = policy.clone();
        wrong_key_version.expected_subjects[0].binding = wrong_key_version.expected_subjects[0]
            .binding
            .replace(":v1_", ":v2_");
        let mut empty = policy.clone();
        empty.expected_subjects.clear();
        for broken in [
            missing,
            extra,
            duplicated,
            substituted,
            wrong_key_version,
            empty,
        ] {
            assert_eq!(
                verify_flattened_jws(&jws, &jwks, &broken),
                Err(VerificationError::Policy)
            );
        }
    }

    const DEBUG_BINDING_CANARY: &str = "verifier-debug-binding-canary-x7q";

    #[test]
    fn expected_subject_document_debug_never_carries_its_binding() {
        let subject = ExpectedSubjectDocument {
            role: "candidate-parent".to_string(),
            binding: DEBUG_BINDING_CANARY.to_string(),
        };
        let rendered = format!("{subject:?}");
        assert!(!rendered.contains(DEBUG_BINDING_CANARY), "{rendered}");
        assert!(rendered.contains("candidate-parent"), "{rendered}");
    }

    #[test]
    fn expected_subject_debug_never_carries_its_binding() {
        let subject = ExpectedSubject {
            role: "candidate-parent".to_string(),
            binding: DEBUG_BINDING_CANARY.to_string(),
        };
        let rendered = format!("{subject:?}");
        assert!(!rendered.contains(DEBUG_BINDING_CANARY), "{rendered}");
        assert!(rendered.contains("candidate-parent"), "{rendered}");
    }

    /// The policy document derives its `Debug`, so this proves the derive
    /// delegates to `ExpectedSubjectDocument`'s own redaction rather than
    /// relying on a second hand-written impl here.
    #[test]
    fn policy_document_debug_never_carries_a_subject_binding_through_derive() {
        let policy = EvidenceVerificationPolicyDocument {
            expected_assurance_profile: AssuranceProfile::EvidenceGrade,
            issued_by: "urn:example:issuer".to_string(),
            provided_by: "urn:example:provider".to_string(),
            requirement: "urn:example:requirement:v1".to_string(),
            evidence_type: "urn:example:type:v1".to_string(),
            purpose: "casework".to_string(),
            audience: "urn:example:audience".to_string(),
            configuration_revision: format!("sha256:{}", "0".repeat(64)),
            request_nonce: FIXTURE_NONCE.to_string(),
            expected_subjects: vec![ExpectedSubjectDocument {
                role: "candidate-parent".to_string(),
                binding: DEBUG_BINDING_CANARY.to_string(),
            }],
            expected_outputs: Vec::new(),
            revoked_key_ids: Vec::new(),
            maximum_assertion_lifetime_seconds: 48 * 60 * 60,
            clock_skew_seconds: 30,
        };
        let rendered = format!("{policy:?}");
        assert!(!rendered.contains(DEBUG_BINDING_CANARY), "{rendered}");
    }

    /// A valid policy document whose two contract-bounded time fields the
    /// caller sets, so a bound test states only what it is about.
    fn policy_document_with_time_bounds(
        maximum_assertion_lifetime_seconds: u64,
        clock_skew_seconds: u64,
    ) -> EvidenceVerificationPolicyDocument {
        EvidenceVerificationPolicyDocument {
            expected_assurance_profile: AssuranceProfile::EvidenceGrade,
            issued_by: "urn:example:issuer".to_string(),
            provided_by: "urn:example:provider".to_string(),
            requirement: "urn:example:requirement:v1".to_string(),
            evidence_type: "urn:example:type:v1".to_string(),
            purpose: "casework".to_string(),
            audience: "urn:example:audience".to_string(),
            configuration_revision: format!("sha256:{}", "0".repeat(64)),
            request_nonce: FIXTURE_NONCE.to_string(),
            expected_subjects: Vec::new(),
            expected_outputs: Vec::new(),
            revoked_key_ids: Vec::new(),
            maximum_assertion_lifetime_seconds,
            clock_skew_seconds,
        }
    }

    fn policy_document_with_list_bounds(
        minimum_items: usize,
        maximum_items: usize,
    ) -> EvidenceVerificationPolicyDocument {
        let mut document = policy_document_with_time_bounds(48 * 60 * 60, 30);
        document.expected_outputs.push(ExpectedOutputDocument {
            concept: "urn:example:concept".to_string(),
            form: ExpectedFormDocument::List(ExpectedListFormDocument {
                list: ExpectedListDocument {
                    minimum_items,
                    maximum_items,
                },
            }),
        });
        document
    }

    /// The bounds this crate enforces are the contract's, not a second opinion
    /// about them.
    #[test]
    fn the_enforced_time_bounds_are_the_contract_bounds() {
        let contract: serde_norway::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/verification-policy.schema.yaml"
        ))
        .expect("the verification policy contract is YAML");
        let bound = |field: &str, bound: &str| -> u64 {
            serde_norway::from_value(contract["properties"][field][bound].clone())
                .unwrap_or_else(|error| panic!("the contract states {field} {bound}: {error}"))
        };
        assert_eq!(
            bound("maximumAssertionLifetimeSeconds", "minimum"),
            MINIMUM_ASSERTION_LIFETIME_SECONDS
        );
        assert_eq!(
            bound("maximumAssertionLifetimeSeconds", "maximum"),
            MAXIMUM_ASSERTION_LIFETIME_SECONDS
        );
        assert_eq!(bound("clockSkewSeconds", "minimum"), 0);
        assert_eq!(
            bound("clockSkewSeconds", "maximum"),
            MAXIMUM_CLOCK_SKEW_SECONDS
        );

        let list =
            &contract["$defs"]["expected-form"]["oneOf"][1]["properties"]["list"]["properties"];
        let list_bound = |field: &str, bound: &str| -> usize {
            serde_norway::from_value(list[field][bound].clone())
                .unwrap_or_else(|error| panic!("the contract states {field} {bound}: {error}"))
        };
        for field in ["minimumItems", "maximumItems"] {
            assert_eq!(list_bound(field, "minimum"), MINIMUM_EXPECTED_LIST_ITEMS);
            assert_eq!(list_bound(field, "maximum"), MAXIMUM_EXPECTED_LIST_ITEMS);
        }
    }

    /// A policy document is an input, and one that states a time bound the
    /// contract forbids is unusable rather than merely unsatisfied. Reading it
    /// has to refuse it: the failure-class vocabulary is frozen, so verification
    /// has no class to report it under, and honouring it would make this
    /// verifier accept assertions a conformant relying party must refuse.
    #[test]
    fn a_policy_document_stating_a_forbidden_time_bound_is_refused_when_read() {
        let refused = |document: EvidenceVerificationPolicyDocument| {
            let bytes = serde_json::to_vec(&document).expect("the document serializes");
            serde_json::from_slice::<EvidenceVerificationPolicyDocument>(&bytes)
                .expect_err("a document outside the contract bounds is refused")
                .to_string()
        };
        for (label, document) in [
            (
                "a zero lifetime",
                policy_document_with_time_bounds(MINIMUM_ASSERTION_LIFETIME_SECONDS - 1, 0),
            ),
            (
                "a lifetime past the ceiling",
                policy_document_with_time_bounds(MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1, 0),
            ),
        ] {
            let message = refused(document);
            assert!(
                message.contains("maximumAssertionLifetimeSeconds"),
                "{label} is refused for the field it states: {message}"
            );
        }
        let message = refused(policy_document_with_time_bounds(
            MAXIMUM_ASSERTION_LIFETIME_SECONDS,
            MAXIMUM_CLOCK_SKEW_SECONDS + 1,
        ));
        assert!(message.contains("clockSkewSeconds"), "{message}");
    }

    #[test]
    fn a_policy_document_at_the_contract_bounds_is_read() {
        for (lifetime, skew) in [
            (MINIMUM_ASSERTION_LIFETIME_SECONDS, 0),
            (
                MAXIMUM_ASSERTION_LIFETIME_SECONDS,
                MAXIMUM_CLOCK_SKEW_SECONDS,
            ),
        ] {
            let bytes = serde_json::to_vec(&policy_document_with_time_bounds(lifetime, skew))
                .expect("the document serializes");
            let read: EvidenceVerificationPolicyDocument = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("{lifetime}s and {skew}s skew are read: {error}"));
            assert_eq!(read.maximum_assertion_lifetime_seconds, lifetime);
            assert_eq!(read.clock_skew_seconds, skew);
        }

        for (minimum_items, maximum_items) in [
            (MINIMUM_EXPECTED_LIST_ITEMS, MINIMUM_EXPECTED_LIST_ITEMS),
            (MAXIMUM_EXPECTED_LIST_ITEMS, MAXIMUM_EXPECTED_LIST_ITEMS),
        ] {
            let bytes = serde_json::to_vec(&policy_document_with_list_bounds(
                minimum_items,
                maximum_items,
            ))
            .expect("the document serializes");
            serde_json::from_slice::<EvidenceVerificationPolicyDocument>(&bytes).unwrap_or_else(
                |error| panic!("{minimum_items}..={maximum_items} items are read: {error}"),
            );
        }
    }

    #[test]
    fn a_policy_document_stating_a_forbidden_list_bound_is_refused_when_read() {
        for (label, minimum_items, maximum_items) in [
            ("zero minimum", 0, 1),
            (
                "minimum past the ceiling",
                MAXIMUM_EXPECTED_LIST_ITEMS + 1,
                MAXIMUM_EXPECTED_LIST_ITEMS,
            ),
            ("zero maximum", 1, 0),
            (
                "maximum past the ceiling",
                MINIMUM_EXPECTED_LIST_ITEMS,
                MAXIMUM_EXPECTED_LIST_ITEMS + 1,
            ),
        ] {
            let bytes = serde_json::to_vec(&policy_document_with_list_bounds(
                minimum_items,
                maximum_items,
            ))
            .expect("the document serializes");
            assert!(
                serde_json::from_slice::<EvidenceVerificationPolicyDocument>(&bytes).is_err(),
                "{label} was accepted"
            );
        }
    }

    /// The document fields are public, so a caller can build one in code
    /// without going through a reader. The conversion to a policy is the second
    /// place the bounds hold.
    #[test]
    fn a_policy_document_built_in_code_cannot_widen_the_contract_bounds() {
        let now = "2026-08-02T12:00:00Z".parse().expect("time parses");
        let refusal = |lifetime, skew| {
            policy_document_with_time_bounds(lifetime, skew)
                .try_into_policy(now)
                .map(|_| ())
        };
        assert_eq!(
            refusal(MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1, 0),
            Err(PolicyBoundsError::AssertionLifetime(
                MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1
            ))
        );
        assert_eq!(refusal(0, 0), Err(PolicyBoundsError::AssertionLifetime(0)));
        assert_eq!(
            refusal(
                MAXIMUM_ASSERTION_LIFETIME_SECONDS,
                MAXIMUM_CLOCK_SKEW_SECONDS + 1
            ),
            Err(PolicyBoundsError::ClockSkew(MAXIMUM_CLOCK_SKEW_SECONDS + 1))
        );
        let policy = policy_document_with_time_bounds(
            MAXIMUM_ASSERTION_LIFETIME_SECONDS,
            MAXIMUM_CLOCK_SKEW_SECONDS,
        )
        .try_into_policy(now)
        .expect("a document at the bounds converts");
        assert_eq!(
            policy.maximum_assertion_lifetime(),
            Duration::from_secs(MAXIMUM_ASSERTION_LIFETIME_SECONDS)
        );
        assert_eq!(
            policy.clock_skew(),
            Duration::from_secs(MAXIMUM_CLOCK_SKEW_SECONDS)
        );

        assert_eq!(
            policy_document_with_list_bounds(0, 1)
                .try_into_policy(now)
                .map(|_| ()),
            Err(PolicyBoundsError::MinimumItems(0))
        );
        assert_eq!(
            policy_document_with_list_bounds(1, MAXIMUM_EXPECTED_LIST_ITEMS + 1)
                .try_into_policy(now)
                .map(|_| ()),
            Err(PolicyBoundsError::MaximumItems(
                MAXIMUM_EXPECTED_LIST_ITEMS + 1
            ))
        );
    }

    /// Re-verifying a retained response is the third way to a policy, and it
    /// never reads a document, so it carries the same bounds itself.
    #[test]
    fn an_accepted_transaction_cannot_widen_the_contract_bounds() {
        let evidence = fixture_evidence();
        let now = "2026-08-02T12:00:00Z".parse().expect("time parses");
        let policy_for_bounds = |lifetime, skew| {
            EvidenceVerificationPolicy::from_accepted_transaction(
                &evidence,
                &evidence.request_nonce,
                lifetime,
                now,
                skew,
            )
        };
        assert_eq!(
            policy_for_bounds(MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1, 0).map(|_| ()),
            Err(PolicyBoundsError::AssertionLifetime(
                MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1
            ))
        );
        assert_eq!(
            policy_for_bounds(0, 0).map(|_| ()),
            Err(PolicyBoundsError::AssertionLifetime(0))
        );
        assert_eq!(
            policy_for_bounds(48 * 60 * 60, MAXIMUM_CLOCK_SKEW_SECONDS + 1).map(|_| ()),
            Err(PolicyBoundsError::ClockSkew(MAXIMUM_CLOCK_SKEW_SECONDS + 1))
        );
        let policy = policy_for_bounds(MINIMUM_ASSERTION_LIFETIME_SECONDS, 0)
            .expect("a transaction at the bounds builds a policy");
        assert_eq!(
            policy.maximum_assertion_lifetime(),
            Duration::from_secs(MINIMUM_ASSERTION_LIFETIME_SECONDS)
        );
        assert_eq!(policy.clock_skew(), Duration::ZERO);
    }

    #[tokio::test]
    async fn expected_output_contract_is_exact_after_signature_verification() {
        let (jws, jwks, policy) = signed_fixture().await;

        let mut missing = policy.clone();
        missing.expected_outputs.clear();
        let mut extra = policy.clone();
        extra.expected_outputs.push(ExpectedOutput {
            concept: "urn:example:other-concept".to_string(),
            form: ExpectedValueForm::Boolean,
        });
        let mut duplicated = policy.clone();
        duplicated.expected_outputs.push(ExpectedOutput {
            concept: policy.expected_outputs[0].concept.clone(),
            form: ExpectedValueForm::Boolean,
        });
        let mut wrong_concept = policy.clone();
        wrong_concept.expected_outputs[0].concept = "urn:example:unexpected".to_string();
        let mut wrong_form = policy.clone();
        wrong_form.expected_outputs[0].form = ExpectedValueForm::String;
        let mut wrong_cardinality = policy.clone();
        wrong_cardinality.expected_outputs[0].form = ExpectedValueForm::List {
            minimum_items: 2,
            maximum_items: 4,
        };
        for broken in [
            missing,
            extra,
            duplicated,
            wrong_concept,
            wrong_form,
            wrong_cardinality,
        ] {
            assert_eq!(
                verify_flattened_jws(&jws, &jwks, &broken),
                Err(VerificationError::Policy)
            );
        }
    }

    #[tokio::test]
    async fn authenticity_is_reported_separately_from_current_validity() {
        // Verified after expiry: still authentic and policy-conformant, but
        // not current evidence.
        let (jws, jwks, mut policy) = signed_fixture().await;
        policy.now = "2026-08-04T00:00:00Z".parse().expect("time parses");
        let report = verify_flattened_jws_report(&jws, &jwks, &policy)
            .expect("expired assertion remains cryptographically authentic");
        assert!(!report.currently_valid);
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &policy),
            Err(VerificationError::Time)
        );

        // While current, both entry points agree.
        let (jws, jwks, policy) = signed_fixture().await;
        let report = verify_flattened_jws_report(&jws, &jwks, &policy).expect("report verifies");
        assert!(report.currently_valid);

        // A mutated payload is not authentic in either entry point.
        let mut value: serde_json::Value = serde_json::from_slice(&jws).expect("JWS parses");
        let payload = value["payload"].as_str().expect("payload").to_string();
        value["payload"] = Value::String(format!("A{}", &payload[1..]));
        let mutated = serde_json::to_vec(&value).expect("serializes");
        assert!(verify_flattened_jws_report(&mutated, &jwks, &policy).is_err());
    }

    #[tokio::test]
    async fn assertion_lifetime_above_the_accepted_maximum_fails() {
        let (jws, jwks, mut policy) = signed_fixture().await;
        policy.maximum_assertion_lifetime = Duration::from_secs(60 * 60);
        assert_eq!(
            verify_flattened_jws(&jws, &jwks, &policy),
            Err(VerificationError::Time)
        );
        assert!(verify_flattened_jws_report(&jws, &jwks, &policy).is_err());
    }

    #[tokio::test]
    async fn unsigned_envelope_is_rejected_by_the_strict_jws_verifier() {
        let (_, jwks, policy) = signed_fixture().await;
        let envelope = crate::model::UnsignedEvidenceEnvelope {
            schema: crate::EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1.to_owned(),
            envelope_type: crate::model::UnsignedEnvelopeType::UnsignedEvidenceEnvelope,
            integrity_protection: crate::model::UnsignedIntegrityProtection::None,
            warning: crate::model::UnsignedEnvelopeWarning::NotCryptographicallyVerifiable,
            evidence: fixture_evidence(),
        };
        let serialized = serde_json::to_vec(&envelope).expect("envelope serializes");
        assert_eq!(
            verify_flattened_jws(&serialized, &jwks, &policy),
            Err(VerificationError::MalformedJws)
        );
        assert!(verify_flattened_jws_report(&serialized, &jwks, &policy).is_err());
    }

    #[tokio::test]
    async fn retired_public_key_verifies_only_while_published_and_payload_is_current() {
        let evidence = fixture_evidence();
        let header = json!({
            "alg": "ES256",
            "kid": RETIRED_KEY_ID,
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY
        });
        let (serialized, retired_public) =
            sign_with_protected_header(RETIRED_PRIVATE_JWK, header, &evidence).await;

        let active_private = PrivateJwk::parse(PRIVATE_JWK).expect("active key parses");
        let active_public = LocalJwkSigner::new(active_private)
            .expect("active signer builds")
            .public_jwk();
        let with_retired =
            jwks_document(active_public.clone(), [retired_public]).expect("rotated JWKS builds");
        let without_retired = jwks_document(active_public, []).expect("active JWKS builds");
        let (_, _, policy) = signed_fixture().await;

        assert!(verify_flattened_jws(&serialized, &with_retired, &policy).is_ok());
        assert_eq!(
            verify_flattened_jws(&serialized, &without_retired, &policy),
            Err(VerificationError::Key)
        );

        let mut outside_window = policy;
        outside_window.now = "2026-08-03T00:00:31Z".parse().expect("time parses");
        assert_eq!(
            verify_flattened_jws(&serialized, &with_retired, &outside_window),
            Err(VerificationError::Time)
        );
    }

    #[tokio::test]
    async fn active_plus_maximum_retired_keys_is_a_usable_trusted_set() {
        let (jws, _, policy) = signed_fixture().await;
        let private = PrivateJwk::parse(PRIVATE_JWK).expect("active key parses");
        let active = LocalJwkSigner::new(private)
            .expect("active signer builds")
            .public_jwk();
        let retired = (0..32).map(|_| generated_public_jwk());
        let maximum = jwks_document(active.clone(), retired).expect("maximum JWKS builds");
        assert_eq!(maximum.keys.len(), MAX_TRUSTED_KEYS);
        assert!(verify_flattened_jws(&jws, &maximum, &policy).is_ok());

        let mut excess = maximum;
        let extra = generated_public_jwk();
        excess
            .keys
            .push(serde_json::to_value(extra).expect("extra key serializes"));
        assert_eq!(
            verify_flattened_jws(&jws, &excess, &policy),
            Err(VerificationError::Key)
        );
    }

    /// A relying party pins its trusted key set once, long before any response
    /// arrives. This check is what lets it learn there that the set is unusable,
    /// so it must refuse exactly what verification refuses.
    #[tokio::test]
    async fn the_pinned_key_set_check_agrees_with_what_verification_would_refuse() {
        let (jws, usable, policy) = signed_fixture().await;
        assert!(trusted_keys_are_usable(&usable).is_ok());
        assert!(verify_flattened_jws(&jws, &usable, &policy).is_ok());

        let one_key = usable.keys[0].clone();
        let mut private_material = one_key.clone();
        private_material["d"] = serde_json::json!("cHJpdmF0ZS1zY2FsYXItcGxhY2Vob2xkZXI");
        let mut absent_kid = one_key.clone();
        absent_kid
            .as_object_mut()
            .expect("the key is an object")
            .remove("kid");
        let mut empty_kid = one_key.clone();
        empty_kid["kid"] = serde_json::json!("");
        for keys in [
            // Nothing to verify against.
            vec![],
            // Private material a public set must never carry.
            vec![private_material],
            // No identifier to select the key by.
            vec![absent_kid],
            vec![empty_kid],
            // Two keys claiming one identifier.
            vec![one_key.clone(), one_key.clone()],
            // Not the signature algorithm the profile fixes.
            vec![
                serde_json::json!({"kty": "EC", "crv": "P-256", "kid": "es256", "alg": "ES256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}),
            ],
        ] {
            let refused = JwksDocument { keys };
            assert_eq!(
                trusted_keys_are_usable(&refused),
                Err(VerificationError::Key),
                "the pinning check accepted a set verification refuses"
            );
            assert_eq!(
                verify_flattened_jws(&jws, &refused, &policy),
                Err(VerificationError::Key),
                "verification and the pinning check disagree"
            );
        }
    }

    /// Issue the fixture as an SD-JWT VC through the same signer, mapping, and
    /// key set the runtime uses.
    async fn issued_sd_jwt_vc() -> (String, JwksDocument, EvidenceVerificationPolicy) {
        let evidence = fixture_evidence();
        let signer = fixture_signer().await;
        let input = crate::sdjwt_vc::issuance_input(&evidence, None, &BTreeMap::new())
            .expect("evidence maps");
        let serialized = signer
            .sign_sd_jwt_vc(input)
            .await
            .expect("SD-JWT VC serializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let policy = policy_for(
            &evidence,
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        );
        (serialized, jwks, policy)
    }

    async fn fixture_signer() -> EvidenceSigner {
        let private = PrivateJwk::parse(PRIVATE_JWK).expect("key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("signer builds"));
        EvidenceSigner::initialize(provider, KEY_ID)
            .await
            .expect("signer initializes")
    }

    /// Split an issued serialization into its JWT and its disclosures.
    fn split_sd_jwt(serialized: &str) -> (String, Vec<String>) {
        let body = serialized.strip_suffix('~').expect("trailing tilde");
        let mut segments = body.split('~');
        let jwt = segments.next().expect("JWT segment").to_owned();
        (jwt, segments.map(str::to_owned).collect())
    }

    fn join_sd_jwt(jwt: &str, disclosures: &[String]) -> String {
        let mut serialized = jwt.to_owned();
        for disclosure in disclosures {
            serialized.push('~');
            serialized.push_str(disclosure);
        }
        serialized.push('~');
        serialized
    }

    fn encode_disclosure(salt: &str, name: &str, value: Value) -> String {
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!([salt, name, value])).expect("disclosure serializes"))
    }

    /// Decode the signed JWT payload of an issued serialization.
    fn sd_jwt_claims(jwt: &str) -> Map<String, Value> {
        let encoded = jwt.split('.').nth(1).expect("payload segment");
        let decoded = URL_SAFE_NO_PAD.decode(encoded).expect("payload decodes");
        serde_json::from_slice(&decoded).expect("payload parses")
    }

    /// Re-encode a JWT with a replaced segment, keeping the original signature.
    fn replace_segment(jwt: &str, index: usize, replacement: &str) -> String {
        let mut parts: Vec<String> = jwt.split('.').map(str::to_owned).collect();
        parts[index] = replacement.to_owned();
        parts.join(".")
    }

    #[tokio::test]
    async fn sd_jwt_vc_round_trips_and_verifies_under_the_same_policy() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let evidence =
            verify_sd_jwt_vc(serialized.as_bytes(), &jwks, &policy).expect("SD-JWT VC verifies");
        // The rebuilt payload is the payload the signed JWS would carry.
        assert_eq!(evidence, fixture_evidence());
    }

    #[tokio::test]
    async fn revoked_key_rejects_sd_jwt_even_when_cached_jwks_still_contains_it() {
        let (serialized, jwks, mut policy) = issued_sd_jwt_vc().await;
        policy.revoked_key_ids = vec![KEY_ID.to_owned()];

        assert_eq!(
            verify_sd_jwt_vc(serialized.as_bytes(), &jwks, &policy),
            Err(VerificationError::Key)
        );
    }

    #[tokio::test]
    async fn structured_value_round_trips_as_top_level_field_disclosures() {
        let mut evidence = fixture_evidence();
        evidence.supported_values = vec![SupportedValue {
            provides_value_for: "urn:example:concept:birth-certificate".to_owned(),
            value: PublicValue::Structured(StructuredValue {
                form: StructuredValueForm::ReviewedStructuredValue,
                schema: "urn:example:schema:birth-certificate:v1".to_owned(),
                fields: BTreeMap::from([
                    ("dateOfBirth".to_owned(), json!("2000-05-23")),
                    ("familyName".to_owned(), json!("Smith")),
                    ("givenName".to_owned(), json!("John")),
                    (
                        "placeOfBirth".to_owned(),
                        json!({"city": "Dusseldorf", "country": "DE"}),
                    ),
                ]),
            }),
        }];
        let projections = BTreeMap::from([(
            "urn:example:concept:birth-certificate".to_owned(),
            "birthCertificate".to_owned(),
        )]);
        let signer = fixture_signer().await;
        let input = crate::sdjwt_vc::issuance_input(&evidence, None, &projections)
            .expect("structured evidence maps");
        let serialized = signer
            .sign_sd_jwt_vc(input)
            .await
            .expect("SD-JWT VC serializes");
        let (jwt, disclosures) = split_sd_jwt(&serialized);
        let claims = sd_jwt_claims(&jwt);
        assert_eq!(
            claims["birthCertificate"]
                .as_object()
                .expect("container object")
                .keys()
                .collect::<Vec<_>>(),
            vec!["_sd"]
        );
        assert_eq!(disclosures.len(), 4);

        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let policy = policy_for(
            &evidence,
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        );
        let verified = verify_sd_jwt_vc(serialized.as_bytes(), &jwks, &policy)
            .expect("field-disclosed credential verifies");
        assert_eq!(verified, evidence);
    }

    #[tokio::test]
    async fn sd_jwt_vc_confirmation_is_accepted_and_carries_no_private_material() {
        let evidence = fixture_evidence();
        let signer = fixture_signer().await;
        let holder = crate::model::HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4".to_owned(),
            y: "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU".to_owned(),
            alg: Some("ES256".to_owned()),
            kid: Some("holder-1".to_owned()),
        };
        let input = crate::sdjwt_vc::issuance_input(&evidence, Some(&holder), &BTreeMap::new())
            .expect("evidence maps");
        let serialized = signer
            .sign_sd_jwt_vc(input)
            .await
            .expect("SD-JWT VC serializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let policy = policy_for(
            &evidence,
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        );

        let (jwt, _) = split_sd_jwt(&serialized);
        let claims = sd_jwt_claims(&jwt);
        assert_eq!(claims["cnf"]["jwk"]["x"], json!(holder.x));
        assert!(claims["cnf"]["jwk"].get("d").is_none());
        assert!(
            verify_sd_jwt_vc(serialized.as_bytes(), &jwks, &policy).is_ok(),
            "a confirmed credential still verifies"
        );
    }

    #[tokio::test]
    async fn sd_jwt_disclosure_modification_rejected() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let (jwt, disclosures) = split_sd_jwt(&serialized);
        let original = URL_SAFE_NO_PAD
            .decode(&disclosures[0])
            .expect("disclosure decodes");
        let members: Vec<Value> = serde_json::from_slice(&original).expect("disclosure parses");
        let salt = members[0].as_str().expect("salt is a string");
        let name = members[1].as_str().expect("name is a string");

        let flipped = encode_disclosure(salt, name, json!(true));
        assert_eq!(
            verify_sd_jwt_vc(join_sd_jwt(&jwt, &[flipped]).as_bytes(), &jwks, &policy),
            Err(VerificationError::Disclosure)
        );

        let renamed = encode_disclosure(salt, "urn:example:other-concept", json!(false));
        assert_eq!(
            verify_sd_jwt_vc(join_sd_jwt(&jwt, &[renamed]).as_bytes(), &jwks, &policy),
            Err(VerificationError::Disclosure)
        );

        let unsalted = encode_disclosure("", name, json!(false));
        assert_eq!(
            verify_sd_jwt_vc(join_sd_jwt(&jwt, &[unsalted]).as_bytes(), &jwks, &policy),
            Err(VerificationError::Disclosure)
        );
    }

    #[tokio::test]
    async fn sd_jwt_added_disclosure_rejected() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let (jwt, disclosures) = split_sd_jwt(&serialized);

        let mut extra = disclosures.clone();
        extra.push(encode_disclosure(
            "0123456789abcdef0123ab",
            "urn:example:extra-concept",
            json!(true),
        ));
        assert_eq!(
            verify_sd_jwt_vc(join_sd_jwt(&jwt, &extra).as_bytes(), &jwks, &policy),
            Err(VerificationError::Disclosure)
        );

        // Presenting the same signed disclosure twice claims one digest twice.
        let mut repeated = disclosures.clone();
        repeated.push(disclosures[0].clone());
        assert_eq!(
            verify_sd_jwt_vc(join_sd_jwt(&jwt, &repeated).as_bytes(), &jwks, &policy),
            Err(VerificationError::Disclosure)
        );
    }

    #[tokio::test]
    async fn sd_jwt_removed_digest_rejected() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let (jwt, _) = split_sd_jwt(&serialized);

        // Version 1 issues complete credentials, so an unresolved signed digest
        // is a mutation rather than a selective presentation.
        assert_eq!(
            verify_sd_jwt_vc(join_sd_jwt(&jwt, &[]).as_bytes(), &jwks, &policy),
            Err(VerificationError::Disclosure)
        );

        // A stripped trailing tilde is not a valid issued serialization.
        assert_eq!(
            verify_sd_jwt_vc(serialized.trim_end_matches('~').as_bytes(), &jwks, &policy),
            Err(VerificationError::MalformedJws)
        );
    }

    #[tokio::test]
    async fn sd_jwt_payload_modification_rejected() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let (jwt, disclosures) = split_sd_jwt(&serialized);
        let mut claims = sd_jwt_claims(&jwt);
        claims.insert(
            "audience".to_owned(),
            json!("urn:example:other-relying-party"),
        );
        let replacement =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
        let mutated = replace_segment(&jwt, 1, &replacement);

        assert_eq!(
            verify_sd_jwt_vc(
                join_sd_jwt(&mutated, &disclosures).as_bytes(),
                &jwks,
                &policy
            ),
            Err(VerificationError::Signature)
        );
    }

    #[tokio::test]
    async fn sd_jwt_protected_header_modification_rejected() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let (jwt, disclosures) = split_sd_jwt(&serialized);

        for header in [
            json!({"alg": "none", "kid": KEY_ID, "typ": EVIDENCE_SD_JWT_VC_TYP}),
            json!({"alg": "ES256", "kid": KEY_ID, "typ": "JWT"}),
            json!({"alg": "ES256", "kid": KEY_ID, "typ": EVIDENCE_SD_JWT_VC_TYP, "jwk": {"kty": "EC"}}),
        ] {
            let replacement =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serializes"));
            let mutated = replace_segment(&jwt, 0, &replacement);
            assert_eq!(
                verify_sd_jwt_vc(
                    join_sd_jwt(&mutated, &disclosures).as_bytes(),
                    &jwks,
                    &policy
                ),
                Err(VerificationError::ProtectedHeader)
            );
        }
    }

    #[tokio::test]
    async fn sd_jwt_unknown_kid_rejected() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        let (jwt, disclosures) = split_sd_jwt(&serialized);
        let header = json!({
            "alg": "ES256",
            "kid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "typ": EVIDENCE_SD_JWT_VC_TYP
        });
        let replacement =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serializes"));
        let mutated = replace_segment(&jwt, 0, &replacement);

        assert_eq!(
            verify_sd_jwt_vc(
                join_sd_jwt(&mutated, &disclosures).as_bytes(),
                &jwks,
                &policy
            ),
            Err(VerificationError::Key)
        );
    }

    fn generated_public_jwk() -> PublicJwk {
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let mut key = PublicJwk {
            kty: "EC".to_owned(),
            kid: None,
            alg: Some("ES256".to_owned()),
            crv: Some("P-256".to_owned()),
            x: point.x().map(|x| URL_SAFE_NO_PAD.encode(x)),
            y: point.y().map(|y| URL_SAFE_NO_PAD.encode(y)),
            n: None,
            e: None,
        };
        key.kid = Some(key.jkt().expect("thumbprint computes"));
        key
    }

    #[tokio::test]
    async fn sd_jwt_prohibited_claim_rejected() {
        let signer = fixture_signer().await;
        let evidence = fixture_evidence();
        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let policy = policy_for(
            &evidence,
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        );

        for (name, value) in [
            (
                "status",
                json!({"status_list": {"uri": "https://example.test/status"}}),
            ),
            ("aud", json!("urn:example:relying-party")),
            ("nbf", json!(1_785_662_100_i64)),
            ("selector", json!({"profile": "national-identifier"})),
        ] {
            let mut input = crate::sdjwt_vc::issuance_input(&evidence, None, &BTreeMap::new())
                .expect("evidence maps");
            if name == "status" {
                input.status = Some(value.clone());
            } else {
                input.public_claims.insert(name.to_owned(), value.clone());
            }
            let Ok(serialized) = signer.sign_sd_jwt_vc(input).await else {
                // The issuer refuses reserved claim names outright, which is a
                // stronger outcome than verifier rejection.
                continue;
            };
            assert_eq!(
                verify_sd_jwt_vc(serialized.as_bytes(), &jwks, &policy),
                Err(VerificationError::Payload),
                "{name} must never be published"
            );
        }
    }

    #[tokio::test]
    async fn sd_jwt_rejected_by_flattened_jws_verifier() {
        let (serialized, jwks, policy) = issued_sd_jwt_vc().await;
        assert_eq!(
            verify_flattened_jws(serialized.as_bytes(), &jwks, &policy),
            Err(VerificationError::MalformedJws)
        );

        // The reverse also holds: a flattened JWS is not an SD-JWT VC.
        let (jws, _, _) = signed_fixture().await;
        assert_eq!(
            verify_sd_jwt_vc(&jws, &jwks, &policy),
            Err(VerificationError::MalformedJws)
        );
    }

    /// The discriminant is what a binding, a metric label, or a caller's own
    /// branch reads, so every variant has one and no two share it.
    #[test]
    fn every_verification_failure_reports_its_own_stable_kind() {
        let cases = [
            (VerificationError::MalformedJws, "malformed_jws"),
            (VerificationError::ProtectedHeader, "protected_header"),
            (VerificationError::Key, "key"),
            (VerificationError::Signature, "signature"),
            (VerificationError::Payload, "payload"),
            (VerificationError::Policy, "policy"),
            (VerificationError::Time, "time"),
            (VerificationError::Disclosure, "disclosure"),
        ];
        for (error, kind) in &cases {
            assert_eq!(error.kind(), *kind, "{error}");
        }
        let kinds: BTreeSet<&str> = cases.iter().map(|(error, _)| error.kind()).collect();
        assert_eq!(kinds.len(), cases.len(), "two variants share a kind");
    }
}
