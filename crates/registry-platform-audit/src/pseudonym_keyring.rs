// SPDX-License-Identifier: Apache-2.0
//! Pure audit-pseudonym key epoch and transient-input contracts.
//!
//! This module intentionally exposes no production write or historical-lookup
//! capability. Caller-supplied metadata, timestamps, and key-id history can be
//! validated as data, but they cannot prove that a generation is the current
//! PostgreSQL state-plane generation or that a clock reading and history set
//! came from that authority. The future production wrapper must obtain current
//! PostgreSQL time, metadata binding and generation, and complete used-key-id
//! history for every operation before it can issue or use a capability. It must
//! also enforce the hash-covered active-write deadline.
//!
//! Internal test-only capability scaffolding exercises exact source sets,
//! duplicate-material rejection, expiry, stale binding, and deterministic
//! lookup behavior without exporting an unsafe production path.
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::AuditPseudonymWriteKey;
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::AuditPseudonymLookupKeyring;
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::TransientPseudonymInput;
//! let input = TransientPseudonymInput::from_jcs_value(serde_json::json!({"id": "raw"}))?;
//! let _copy = input.clone();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::TransientPseudonymInput;
//! let input = TransientPseudonymInput::from_jcs_value(serde_json::json!({"id": "raw"}))?;
//! let _serialized = serde_json::to_string(&input)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyringMetadata;
//! let _metadata: AuditPseudonymKeyringMetadata = serde_json::from_str("{}")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyMaterial;
//! use zeroize::Zeroizing;
//! let key = AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![7; 32]))?;
//! let _copy = key.clone();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyMaterial;
//! use zeroize::Zeroizing;
//! let key = AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![7; 32]))?;
//! let _serialized = serde_json::to_string(&key)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ```compile_fail
//! use registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyMaterial;
//! use zeroize::Zeroizing;
//! let key = AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![7; 32]))?;
//! let _raw_key = key.as_bytes();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    hex_lower, hkdf_expand_sha256, hmac_sha256_bytes, read_secret_env, AuditError, SecretBytes,
    MIN_AUDIT_SECRET_BYTES,
};

const MAX_KEY_ID_BYTES: usize = 64;
const MAX_ENV_VAR_NAME_BYTES: usize = 128;
const MAX_KEYRING_EPOCHS: usize = 32;
const MAX_CANONICAL_INPUT_BYTES: usize = 8 * 1024;
const MAX_CANONICAL_INPUT_DEPTH: usize = 64;
const MAX_EXACT_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_AUDIT_PSEUDONYM_SECRET_BYTES: usize = 4 * 1024;
const KEYRING_METADATA_SCHEMA_V1: &str = "registry.audit-pseudonym-keyring/v1";
const AUDIT_PSEUDONYM_KEY_DERIVATION_INFO: &[u8] =
    b"registry-platform-audit/audit-pseudonym-key/v1";
const KEY_MATERIAL_PROBE_INPUT: &[u8] =
    b"registry-platform-audit/audit-pseudonym-material-probe/v1";

/// Public, non-secret identifier for one audit-pseudonym key epoch.
///
/// The canonical v1 syntax is a lowercase ASCII letter or digit followed by at
/// most 63 lowercase ASCII letters, digits, dots, underscores, or hyphens.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuditPseudonymKeyId(String);

impl AuditPseudonymKeyId {
    /// Parse and validate one canonical key epoch identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, AuditPseudonymKeyringError> {
        let value = value.into();
        if !is_bounded_token(&value, MAX_KEY_ID_BYTES) {
            return Err(AuditPseudonymKeyringError::InvalidKeyId);
        }
        Ok(Self(value))
    }

    /// Return the stable public key id recorded with a pseudonym handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuditPseudonymKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AuditPseudonymKeyId").field(&self.0).finish()
    }
}

impl fmt::Display for AuditPseudonymKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for AuditPseudonymKeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AuditPseudonymKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Closed HMAC domains for Relay consultation commitments.
///
/// The exact preimage is the selected ASCII domain, one NUL byte, and the RFC
/// 8785 bytes held by [`TransientPseudonymInput`]. Tenant, registry instance,
/// profile, operation, and other semantic fields belong inside that JCS value;
/// no class, scope, or length framing is added here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayConsultationCommitmentDomain {
    /// `HMAC(key, "registry.relay.consultation-subject.v1\0" || JCS(input))`.
    Subject,
    /// `HMAC(key, "registry.relay.consultation-input.v1\0" || JCS(input))`.
    Input,
    /// `HMAC(key, "registry.relay.consultation-predicate.v1\0" || JCS(input))`.
    Predicate,
    /// `HMAC(key, "registry.relay.consultation-consent.v1\0" || JCS(input))`.
    Consent,
}

impl RelayConsultationCommitmentDomain {
    /// Return the exact frozen v1 domain without its trailing NUL separator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "registry.relay.consultation-subject.v1",
            Self::Input => "registry.relay.consultation-input.v1",
            Self::Predicate => "registry.relay.consultation-predicate.v1",
            Self::Consent => "registry.relay.consultation-consent.v1",
        }
    }
}

/// Bounded wall-clock value used by pure lifecycle validation.
///
/// This type validates representation only. It carries no clock provenance and
/// must never be treated as proof of current time or used by itself to authorize
/// a production key operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuditPseudonymTime(i64);

impl AuditPseudonymTime {
    pub fn from_unix_ms(value: i64) -> Result<Self, AuditPseudonymKeyringError> {
        if !(0..=MAX_EXACT_JSON_INTEGER).contains(&value) {
            return Err(AuditPseudonymKeyringError::InvalidTime);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn unix_ms(self) -> i64 {
        self.0
    }
}

/// A test-only secret source reference for one key epoch.
///
/// The environment-variable name is deployment configuration, not key
/// material. The loaded value is validated and HKDF-domain-separated by the
/// platform audit primitive.
#[cfg(test)]
#[derive(Clone, PartialEq, Eq)]
struct AuditPseudonymKeySource {
    key_id: AuditPseudonymKeyId,
    secret_env_var: String,
}

#[cfg(test)]
impl AuditPseudonymKeySource {
    /// Construct one validated test source.
    fn new(
        key_id: AuditPseudonymKeyId,
        secret_env_var: impl Into<String>,
    ) -> Result<Self, AuditPseudonymKeyringError> {
        let secret_env_var = secret_env_var.into();
        if !is_environment_variable_name(&secret_env_var) {
            return Err(AuditPseudonymKeyringError::InvalidEnvironmentVariableName);
        }
        Ok(Self {
            key_id,
            secret_env_var,
        })
    }
}

#[cfg(test)]
impl fmt::Debug for AuditPseudonymKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditPseudonymKeySource")
            .field("key_id", &self.key_id)
            .field("secret_env_var", &"<configured>")
            .finish()
    }
}

/// RFC 8785 canonical JSON bounded to 8 KiB and 64 levels of nesting.
///
/// Construction consumes the input [`Value`], recursively scrubs all owned
/// string keys and values on success and failure, and retains only zeroizing
/// canonical bytes. This value is neither cloneable nor serializable.
pub struct TransientPseudonymInput(Zeroizing<Vec<u8>>);

impl TransientPseudonymInput {
    /// Canonicalize and take ownership of a privacy-reviewed pseudonym input.
    pub fn from_jcs_value(mut value: Value) -> Result<Self, AuditPseudonymKeyringError> {
        if let Err(error) = bounded_json_size(&value, 0) {
            scrub_json_strings(&mut value);
            return Err(error);
        }

        let canonical = registry_platform_canonical_json::canonicalize_json(&value);
        scrub_json_strings(&mut value);
        let canonical = Zeroizing::new(
            canonical.map_err(|_| AuditPseudonymKeyringError::InvalidCanonicalInput)?,
        );
        if canonical.len() > MAX_CANONICAL_INPUT_BYTES {
            return Err(AuditPseudonymKeyringError::CanonicalInputTooLarge);
        }
        Ok(Self(canonical))
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("RFC 8785 output is UTF-8")
    }
}

impl fmt::Debug for TransientPseudonymInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransientPseudonymInput(<redacted>)")
    }
}

/// One domain-separated audit-pseudonym HMAC sub-key.
///
/// Construction always treats the supplied bytes as master key material and
/// derives a dedicated 32-byte sub-key with the fixed
/// `registry-platform-audit/audit-pseudonym-key/v1` HKDF-Expand label. The
/// derived key is distinct from the audit-chain and generic identifier keys.
/// Raw and derived bytes are zeroized on every path. This type is deliberately
/// neither cloneable nor serializable and exposes no raw-key accessor.
///
/// Possession proves only cryptographic key material. It does not prove the
/// current PostgreSQL key id, generation, metadata binding, time, lookup grant,
/// or write authority. Relay must bind it through the state-plane authority
/// before a commitment can enter a governed event.
pub struct AuditPseudonymKeyMaterial(SecretBytes);

impl AuditPseudonymKeyMaterial {
    /// Retain an exact already-derived HMAC key for frozen framing vectors.
    ///
    /// Production constructors must always derive from deployment master
    /// material. This helper exists only in this module's unit-test build so
    /// the established v1 domain/framing vectors remain independent of the
    /// newer master-to-sub-key derivation contract.
    #[cfg(test)]
    fn from_test_derived_key(mut derived_key: Zeroizing<Vec<u8>>) -> Option<Self> {
        if derived_key.len() != 32 {
            return None;
        }
        Some(Self(SecretBytes(std::mem::take(&mut *derived_key))))
    }

    /// Derive the dedicated audit-pseudonym sub-key from owned zeroizing master
    /// secret bytes.
    pub fn from_secret_bytes(
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AuditPseudonymKeyringError> {
        validate_secret_length(secret.len())?;
        Ok(Self(SecretBytes(hkdf_expand_sha256(
            &secret,
            AUDIT_PSEUDONYM_KEY_DERIVATION_INFO,
        ))))
    }

    /// Load one exact environment value and derive the dedicated
    /// audit-pseudonym sub-key.
    ///
    /// The value is not trimmed, decoded, or otherwise normalized. Environment
    /// names use the conservative portable identifier grammar already used by
    /// the keyring source contract. This is a single-key crypto constructor,
    /// not a keyring loader or state-plane authority.
    pub fn from_env_derived(env_var_name: &str) -> Result<Self, AuditPseudonymKeyringError> {
        if !is_environment_variable_name(env_var_name) {
            return Err(AuditPseudonymKeyringError::InvalidEnvironmentVariableName);
        }
        let mut value = read_secret_env(env_var_name)?;
        if let Err(error) = validate_secret_length(value.len()) {
            value.zeroize();
            return Err(error);
        }
        // `String::into_bytes` transfers the environment allocation without a
        // plaintext copy. Validation has completed, so the allocation moves
        // immediately under a zeroizing owner before sub-key derivation.
        Self::from_secret_bytes(Zeroizing::new(value.into_bytes()))
    }

    /// Compute the frozen Relay consultation-subject commitment.
    #[must_use]
    pub fn consultation_subject_commitment(
        &self,
        canonical_input: &TransientPseudonymInput,
    ) -> AuditPseudonymCommitment {
        self.commitment(RelayConsultationCommitmentDomain::Subject, canonical_input)
    }

    /// Compute the frozen Relay consultation-input commitment.
    #[must_use]
    pub fn consultation_input_commitment(
        &self,
        canonical_input: &TransientPseudonymInput,
    ) -> AuditPseudonymCommitment {
        self.commitment(RelayConsultationCommitmentDomain::Input, canonical_input)
    }

    /// Compute the frozen Relay consultation-predicate commitment.
    #[must_use]
    pub fn consultation_predicate_commitment(
        &self,
        canonical_input: &TransientPseudonymInput,
    ) -> AuditPseudonymCommitment {
        self.commitment(
            RelayConsultationCommitmentDomain::Predicate,
            canonical_input,
        )
    }

    /// Compute the frozen Relay consultation-consent commitment.
    #[must_use]
    pub fn consultation_consent_commitment(
        &self,
        canonical_input: &TransientPseudonymInput,
    ) -> AuditPseudonymCommitment {
        self.commitment(RelayConsultationCommitmentDomain::Consent, canonical_input)
    }

    /// Compare derived material in constant time without exposing either key.
    ///
    /// Both keys authenticate one fixed private probe. The transient tags are
    /// compared in constant time and scrubbed before return; neither the probe
    /// nor its tags are exposed or persisted.
    #[must_use]
    pub fn is_same_material(&self, other: &Self) -> bool {
        let mut left = hmac_sha256_bytes(&self.0 .0, b"", KEY_MATERIAL_PROBE_INPUT);
        let mut right = hmac_sha256_bytes(&other.0 .0, b"", KEY_MATERIAL_PROBE_INPUT);
        let same = bool::from(left.ct_eq(&right));
        left.zeroize();
        right.zeroize();
        same
    }

    fn commitment(
        &self,
        domain: RelayConsultationCommitmentDomain,
        canonical_input: &TransientPseudonymInput,
    ) -> AuditPseudonymCommitment {
        let preimage = relay_consultation_commitment_preimage(domain, canonical_input);
        let mut tag = hmac_sha256_bytes(&self.0 .0, b"", &preimage);
        let value = format!("hmac-sha256:{}", hex_lower(&tag));
        tag.zeroize();
        AuditPseudonymCommitment(value)
    }
}

impl fmt::Debug for AuditPseudonymKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditPseudonymKeyMaterial(<redacted>)")
    }
}

/// Audit-safe output of one closed audit-pseudonym commitment operation.
///
/// This value intentionally carries no key id or state-plane authority. The
/// authoritative wrapper binds it to the PostgreSQL-issued epoch separately.
#[derive(PartialEq, Eq)]
pub struct AuditPseudonymCommitment(String);

impl AuditPseudonymCommitment {
    /// Return the stable `hmac-sha256:<lowercase hex>` representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuditPseudonymCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditPseudonymCommitment(hmac-sha256:<redacted>)")
    }
}

fn relay_consultation_commitment_preimage(
    domain: RelayConsultationCommitmentDomain,
    canonical_input: &TransientPseudonymInput,
) -> Zeroizing<Vec<u8>> {
    let mut preimage = Zeroizing::new(Vec::with_capacity(
        domain.as_str().len() + 1 + canonical_input.as_str().len(),
    ));
    preimage.extend_from_slice(domain.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical_input.0);
    preimage
}

/// Audit-safe keyed handle recorded in an event or used in an exact lookup.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AuditPseudonymHandle {
    key_id: AuditPseudonymKeyId,
    value: String,
}

impl AuditPseudonymHandle {
    #[must_use]
    pub fn key_id(&self) -> &AuditPseudonymKeyId {
        &self.key_id
    }

    /// Return the platform-encoded keyed hash value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for AuditPseudonymHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditPseudonymHandle")
            .field("key_id", &self.key_id)
            .field("value", &"hmac-sha256:<redacted>")
            .finish()
    }
}

/// Non-secret lifecycle metadata for a retained, read-only key epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetainedAuditPseudonymKeyEpoch {
    key_id: AuditPseudonymKeyId,
    retired_at_unix_ms: i64,
    destroy_after_unix_ms: i64,
}

impl RetainedAuditPseudonymKeyEpoch {
    pub fn new(
        key_id: AuditPseudonymKeyId,
        retired_at_unix_ms: i64,
        destroy_after_unix_ms: i64,
    ) -> Result<Self, AuditPseudonymKeyringError> {
        if !(0..=MAX_EXACT_JSON_INTEGER).contains(&retired_at_unix_ms)
            || destroy_after_unix_ms <= retired_at_unix_ms
            || destroy_after_unix_ms > MAX_EXACT_JSON_INTEGER
        {
            return Err(AuditPseudonymKeyringError::InvalidKeyLifecycle);
        }
        Ok(Self {
            key_id,
            retired_at_unix_ms,
            destroy_after_unix_ms,
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &AuditPseudonymKeyId {
        &self.key_id
    }

    #[must_use]
    pub const fn retired_at_unix_ms(&self) -> i64 {
        self.retired_at_unix_ms
    }

    #[must_use]
    pub const fn destroy_after_unix_ms(&self) -> i64 {
        self.destroy_after_unix_ms
    }
}

/// Hash-covered, non-secret deployment metadata for one keyring generation.
///
/// There is deliberately no default retention period. A retained key must
/// remain available for at least the configured audit-event retention window
/// after its write retirement. This pure value is not a current-generation
/// attestation or serving capability. It includes an explicit exclusive active
/// write deadline, which the future PostgreSQL authority must enforce against
/// authoritative current time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditPseudonymKeyringMetadata {
    schema: String,
    generation: u64,
    active_key_id: AuditPseudonymKeyId,
    active_since_unix_ms: i64,
    active_write_deadline_unix_ms: i64,
    audit_event_retention_ms: i64,
    retained_keys: Vec<RetainedAuditPseudonymKeyEpoch>,
}

impl AuditPseudonymKeyringMetadata {
    pub fn new(
        generation: u64,
        active_key_id: AuditPseudonymKeyId,
        active_since_unix_ms: i64,
        active_write_deadline_unix_ms: i64,
        audit_event_retention_ms: i64,
        mut retained_keys: Vec<RetainedAuditPseudonymKeyEpoch>,
    ) -> Result<Self, AuditPseudonymKeyringError> {
        if generation == 0
            || generation > MAX_EXACT_JSON_INTEGER as u64
            || !(0..=MAX_EXACT_JSON_INTEGER).contains(&active_since_unix_ms)
            || active_write_deadline_unix_ms <= active_since_unix_ms
            || active_write_deadline_unix_ms > MAX_EXACT_JSON_INTEGER
            || audit_event_retention_ms <= 0
            || audit_event_retention_ms > MAX_EXACT_JSON_INTEGER
        {
            return Err(AuditPseudonymKeyringError::InvalidKeyLifecycle);
        }
        if retained_keys.len() > MAX_KEYRING_EPOCHS - 1 {
            return Err(AuditPseudonymKeyringError::TooManyKeyEpochs);
        }
        retained_keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let mut previous = None;
        for retained in &retained_keys {
            if retained.key_id == active_key_id || previous == Some(&retained.key_id) {
                return Err(AuditPseudonymKeyringError::DuplicateKeyId);
            }
            if retained.retired_at_unix_ms > active_since_unix_ms
                || retained.destroy_after_unix_ms <= active_since_unix_ms
            {
                return Err(AuditPseudonymKeyringError::InvalidKeyLifecycle);
            }
            let required_destroy_after = retained
                .retired_at_unix_ms
                .checked_add(audit_event_retention_ms)
                .ok_or(AuditPseudonymKeyringError::InvalidKeyLifecycle)?;
            if retained.destroy_after_unix_ms < required_destroy_after {
                return Err(AuditPseudonymKeyringError::RetentionTooShort);
            }
            previous = Some(&retained.key_id);
        }
        Ok(Self {
            schema: KEYRING_METADATA_SCHEMA_V1.to_string(),
            generation,
            active_key_id,
            active_since_unix_ms,
            active_write_deadline_unix_ms,
            audit_event_retention_ms,
            retained_keys,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn active_key_id(&self) -> &AuditPseudonymKeyId {
        &self.active_key_id
    }

    #[must_use]
    pub const fn active_since_unix_ms(&self) -> i64 {
        self.active_since_unix_ms
    }

    /// Exclusive deadline for writes under the active epoch.
    #[must_use]
    pub const fn active_write_deadline_unix_ms(&self) -> i64 {
        self.active_write_deadline_unix_ms
    }

    #[must_use]
    pub const fn audit_event_retention_ms(&self) -> i64 {
        self.audit_event_retention_ms
    }

    #[must_use]
    pub fn retained_keys(&self) -> &[RetainedAuditPseudonymKeyEpoch] {
        &self.retained_keys
    }

    /// Return the stable generation and RFC 8785 metadata digest.
    pub fn binding(&self) -> Result<AuditPseudonymMetadataBinding, AuditPseudonymKeyringError> {
        let value = serde_json::to_value(self)
            .map_err(|_| AuditPseudonymKeyringError::MetadataSerializationFailed)?;
        let canonical = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| AuditPseudonymKeyringError::MetadataCanonicalizationFailed)?;
        let digest: [u8; 32] = Sha256::digest(&canonical).into();
        Ok(AuditPseudonymMetadataBinding {
            generation: self.generation,
            digest,
        })
    }

    /// Apply lifecycle rules to this metadata value at a supplied time value.
    ///
    /// This is pure validation. It does not prove that either argument came
    /// from the current PostgreSQL state-plane transaction and therefore cannot
    /// authorize a production write or lookup.
    pub fn validate_lifecycle_at(
        &self,
        now: AuditPseudonymTime,
    ) -> Result<(), AuditPseudonymKeyringError> {
        if now.unix_ms() < self.active_since_unix_ms {
            return Err(AuditPseudonymKeyringError::MetadataNotActive);
        }
        if now.unix_ms() >= self.active_write_deadline_unix_ms {
            return Err(AuditPseudonymKeyringError::ActiveWriteDeadlineReached);
        }
        if self
            .retained_keys
            .iter()
            .any(|key| now.unix_ms() >= key.destroy_after_unix_ms)
        {
            return Err(AuditPseudonymKeyringError::ExpiredKeyEpoch);
        }
        Ok(())
    }

    /// Apply active-key rotation rules to two metadata values and a supplied
    /// history set.
    ///
    /// `previously_used_key_ids` must be the complete state-plane uniqueness
    /// history and must contain every id in `self`, including epochs omitted
    /// from older metadata. This pure function cannot prove that completeness
    /// or persist the transition. Production rotation must query and update the
    /// history transactionally through the PostgreSQL authority.
    pub fn validate_rotation_successor_values(
        &self,
        successor: &Self,
        previously_used_key_ids: &BTreeSet<AuditPseudonymKeyId>,
        activation_time: AuditPseudonymTime,
    ) -> Result<(), AuditPseudonymKeyringError> {
        if self
            .declared_key_ids()
            .any(|key_id| !previously_used_key_ids.contains(key_id))
        {
            return Err(AuditPseudonymKeyringError::IncompleteKeyIdHistory);
        }
        if successor.generation <= self.generation
            || successor.active_since_unix_ms != activation_time.unix_ms()
            || successor.active_since_unix_ms <= self.active_since_unix_ms
            || activation_time.unix_ms() > self.active_write_deadline_unix_ms
            || successor.active_write_deadline_unix_ms <= self.active_write_deadline_unix_ms
            || successor.audit_event_retention_ms < self.audit_event_retention_ms
        {
            return Err(AuditPseudonymKeyringError::InvalidRotationTransition);
        }
        if previously_used_key_ids.contains(&successor.active_key_id)
            || self
                .declared_key_ids()
                .any(|key_id| key_id == &successor.active_key_id)
        {
            return Err(AuditPseudonymKeyringError::ReusedKeyId);
        }
        successor.validate_lifecycle_at(activation_time)?;

        let previous_retained = self.retained_by_id();
        let successor_retained = successor.retained_by_id();
        let retired_active = successor_retained
            .get(&self.active_key_id)
            .ok_or(AuditPseudonymKeyringError::PriorActiveKeyNotRetained)?;
        if retired_active.retired_at_unix_ms != activation_time.unix_ms() {
            return Err(AuditPseudonymKeyringError::InvalidRotationTransition);
        }

        for previous in &self.retained_keys {
            if previous.destroy_after_unix_ms <= activation_time.unix_ms() {
                if successor_retained.contains_key(&previous.key_id) {
                    return Err(AuditPseudonymKeyringError::RetainedEpochChanged);
                }
                continue;
            }
            match successor_retained.get(&previous.key_id) {
                Some(current)
                    if current.retired_at_unix_ms == previous.retired_at_unix_ms
                        && current.destroy_after_unix_ms >= previous.destroy_after_unix_ms => {}
                Some(_) => return Err(AuditPseudonymKeyringError::RetainedEpochChanged),
                None => return Err(AuditPseudonymKeyringError::UnexpiredEpochRemoved),
            }
        }
        for current in &successor.retained_keys {
            if current.key_id != self.active_key_id
                && !previous_retained.contains_key(&current.key_id)
            {
                return Err(AuditPseudonymKeyringError::RetainedEpochChanged);
            }
        }
        Ok(())
    }

    /// Apply same-active maintenance rules to two metadata values and a
    /// supplied history set.
    ///
    /// Maintenance may only remove retained epochs whose destruction deadline
    /// has been reached. It cannot add, mutate, extend, or resurrect a retained
    /// epoch, and it cannot alter the active key id, activation time, or active
    /// write deadline. The generation must increase and event retention cannot
    /// be shortened. As with rotation validation, the supplied history is pure
    /// data; only the future PostgreSQL authority can prove completeness and
    /// persist this transition atomically.
    pub fn validate_maintenance_successor_values(
        &self,
        successor: &Self,
        previously_used_key_ids: &BTreeSet<AuditPseudonymKeyId>,
        maintenance_time: AuditPseudonymTime,
    ) -> Result<(), AuditPseudonymKeyringError> {
        if self
            .declared_key_ids()
            .any(|key_id| !previously_used_key_ids.contains(key_id))
        {
            return Err(AuditPseudonymKeyringError::IncompleteKeyIdHistory);
        }
        if successor.generation <= self.generation
            || successor.active_key_id != self.active_key_id
            || successor.active_since_unix_ms != self.active_since_unix_ms
            || successor.active_write_deadline_unix_ms != self.active_write_deadline_unix_ms
            || successor.audit_event_retention_ms < self.audit_event_retention_ms
            || maintenance_time.unix_ms() < self.active_since_unix_ms
            || maintenance_time.unix_ms() >= self.active_write_deadline_unix_ms
        {
            return Err(AuditPseudonymKeyringError::InvalidMaintenanceTransition);
        }

        let previous_retained = self.retained_by_id();
        let successor_retained = successor.retained_by_id();
        for previous in &self.retained_keys {
            if previous.destroy_after_unix_ms <= maintenance_time.unix_ms() {
                if successor_retained.contains_key(&previous.key_id) {
                    return Err(AuditPseudonymKeyringError::RetainedEpochChanged);
                }
                continue;
            }
            match successor_retained.get(&previous.key_id) {
                Some(current) if *current == previous => {}
                Some(_) => return Err(AuditPseudonymKeyringError::RetainedEpochChanged),
                None => return Err(AuditPseudonymKeyringError::UnexpiredEpochRemoved),
            }
        }
        if successor_retained
            .keys()
            .any(|key_id| !previous_retained.contains_key(key_id))
        {
            return Err(AuditPseudonymKeyringError::RetainedEpochChanged);
        }
        successor.validate_lifecycle_at(maintenance_time)?;
        Ok(())
    }

    fn declared_key_ids(&self) -> impl Iterator<Item = &AuditPseudonymKeyId> {
        std::iter::once(&self.active_key_id).chain(self.retained_keys.iter().map(|key| &key.key_id))
    }

    fn retained_by_id(&self) -> BTreeMap<AuditPseudonymKeyId, &RetainedAuditPseudonymKeyEpoch> {
        self.retained_keys
            .iter()
            .map(|key| (key.key_id.clone(), key))
            .collect()
    }

    #[cfg(test)]
    fn lookup_expiry(
        &self,
        key_id: &AuditPseudonymKeyId,
        now: AuditPseudonymTime,
    ) -> Result<Option<i64>, AuditPseudonymKeyringError> {
        if key_id == &self.active_key_id {
            return Ok(None);
        }
        let retained = self
            .retained_keys
            .iter()
            .find(|retained| &retained.key_id == key_id)
            .ok_or(AuditPseudonymKeyringError::UndeclaredLookupKey)?;
        if now.unix_ms() >= retained.destroy_after_unix_ms {
            return Err(AuditPseudonymKeyringError::ExpiredKeyEpoch);
        }
        Ok(Some(retained.destroy_after_unix_ms))
    }
}

/// Stable identity of one metadata value.
///
/// Equality detects ordinary drift but is not an attestation that the value is
/// the current persisted generation. Production use requires the PostgreSQL
/// authority boundary described in the module documentation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditPseudonymMetadataBinding {
    generation: u64,
    digest: [u8; 32],
}

impl AuditPseudonymMetadataBinding {
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for AuditPseudonymMetadataBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditPseudonymMetadataBinding")
            .field("generation", &self.generation)
            .field("digest", &"sha256:<redacted>")
            .finish()
    }
}

/// Test-only model of the future state-plane-issued write capability.
///
/// This is deliberately absent from production builds. Passing a metadata copy
/// and a timestamp cannot establish that either is current.
#[cfg(test)]
struct AuditPseudonymWriteKey {
    key_id: AuditPseudonymKeyId,
    metadata_binding: AuditPseudonymMetadataBinding,
    material: AuditPseudonymKeyMaterial,
}

#[cfg(test)]
impl AuditPseudonymWriteKey {
    /// Exercise environment loading and complete-generation preflight in tests.
    fn preflight_from_env<I>(
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        sources: I,
    ) -> Result<Self, AuditPseudonymKeyringError>
    where
        I: IntoIterator<Item = AuditPseudonymKeySource>,
    {
        metadata.validate_lifecycle_at(now)?;
        let sources = collect_sources(sources)?;
        ensure_exact_source_ids(metadata, &sources)?;
        let loaded = load_env_materials(sources)?;
        Self::from_preflight_materials(metadata, now, loaded)
    }

    fn from_preflight_materials<I>(
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        materials: I,
    ) -> Result<Self, AuditPseudonymKeyringError>
    where
        I: IntoIterator<Item = (AuditPseudonymKeyId, AuditPseudonymKeyMaterial)>,
    {
        metadata.validate_lifecycle_at(now)?;
        let mut loaded = collect_unique_materials(materials)?;
        ensure_exact_loaded_ids(metadata, &loaded)?;
        reject_duplicate_key_material(&loaded)?;
        let material = loaded
            .remove(metadata.active_key_id())
            .ok_or(AuditPseudonymKeyringError::MetadataSourceMismatch)?;
        drop(loaded);
        Ok(Self {
            key_id: metadata.active_key_id.clone(),
            metadata_binding: metadata.binding()?,
            material,
        })
    }

    #[must_use]
    fn key_id(&self) -> &AuditPseudonymKeyId {
        &self.key_id
    }

    #[must_use]
    const fn metadata_binding(&self) -> AuditPseudonymMetadataBinding {
        self.metadata_binding
    }

    /// Prove that this capability still matches the current metadata snapshot.
    fn validate_current_metadata(
        &self,
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
    ) -> Result<(), AuditPseudonymKeyringError> {
        metadata.validate_lifecycle_at(now)?;
        if self.key_id != metadata.active_key_id || self.metadata_binding != metadata.binding()? {
            return Err(AuditPseudonymKeyringError::StaleMetadata);
        }
        Ok(())
    }

    /// Compute one exact Relay consultation commitment in the test model.
    fn consultation_commitment(
        &self,
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        domain: RelayConsultationCommitmentDomain,
        canonical_input: &TransientPseudonymInput,
    ) -> Result<AuditPseudonymHandle, AuditPseudonymKeyringError> {
        self.validate_current_metadata(metadata, now)?;
        Ok(AuditPseudonymHandle {
            key_id: self.key_id.clone(),
            value: self
                .material
                .commitment(domain, canonical_input)
                .as_str()
                .to_owned(),
        })
    }
}

#[cfg(test)]
impl fmt::Debug for AuditPseudonymWriteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditPseudonymWriteKey")
            .field("key_id", &self.key_id)
            .field("metadata_binding", &self.metadata_binding)
            .field("key_material", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
struct LookupKey {
    material: AuditPseudonymKeyMaterial,
    destroy_after_unix_ms: Option<i64>,
}

/// Test-only model of a state-plane-authorized exact lookup-key subset.
///
/// This is deliberately absent from production builds because a caller-supplied
/// subset, metadata copy, and timestamp cannot prove investigation authority or
/// current lifecycle state.
#[cfg(test)]
struct AuditPseudonymLookupKeyring {
    metadata_binding: AuditPseudonymMetadataBinding,
    keys: BTreeMap<AuditPseudonymKeyId, LookupKey>,
}

#[cfg(test)]
impl AuditPseudonymLookupKeyring {
    /// Exercise exact declared environment-source loading in tests.
    fn from_env<I>(
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        sources: I,
    ) -> Result<Self, AuditPseudonymKeyringError>
    where
        I: IntoIterator<Item = AuditPseudonymKeySource>,
    {
        metadata.validate_lifecycle_at(now)?;
        let sources = collect_sources(sources)?;
        if sources.is_empty() {
            return Err(AuditPseudonymKeyringError::EmptyLookupKeySet);
        }
        let mut expiries = BTreeMap::new();
        for source in &sources {
            if expiries
                .insert(
                    source.key_id.clone(),
                    metadata.lookup_expiry(&source.key_id, now)?,
                )
                .is_some()
            {
                return Err(AuditPseudonymKeyringError::DuplicateKeyId);
            }
        }
        let loaded = load_env_materials(sources)?;
        Self::from_materials_and_expiries(metadata, now, loaded, expiries)
    }

    #[cfg(test)]
    fn from_materials<I>(
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        materials: I,
    ) -> Result<Self, AuditPseudonymKeyringError>
    where
        I: IntoIterator<Item = (AuditPseudonymKeyId, AuditPseudonymKeyMaterial)>,
    {
        metadata.validate_lifecycle_at(now)?;
        let loaded = collect_unique_materials(materials)?;
        if loaded.is_empty() {
            return Err(AuditPseudonymKeyringError::EmptyLookupKeySet);
        }
        let mut expiries = BTreeMap::new();
        for key_id in loaded.keys() {
            expiries.insert(key_id.clone(), metadata.lookup_expiry(key_id, now)?);
        }
        Self::from_materials_and_expiries(metadata, now, loaded, expiries)
    }

    fn from_materials_and_expiries(
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        loaded: BTreeMap<AuditPseudonymKeyId, AuditPseudonymKeyMaterial>,
        expiries: BTreeMap<AuditPseudonymKeyId, Option<i64>>,
    ) -> Result<Self, AuditPseudonymKeyringError> {
        metadata.validate_lifecycle_at(now)?;
        reject_duplicate_key_material(&loaded)?;
        let keys = loaded
            .into_iter()
            .map(|(key_id, material)| {
                let destroy_after_unix_ms = expiries
                    .get(&key_id)
                    .copied()
                    .ok_or(AuditPseudonymKeyringError::MetadataSourceMismatch)?;
                Ok((
                    key_id,
                    LookupKey {
                        material,
                        destroy_after_unix_ms,
                    },
                ))
            })
            .collect::<Result<_, AuditPseudonymKeyringError>>()?;
        Ok(Self {
            metadata_binding: metadata.binding()?,
            keys,
        })
    }

    /// Return the exact public ids loaded into this restricted lookup keyring.
    fn key_ids(&self) -> impl ExactSizeIterator<Item = &AuditPseudonymKeyId> {
        self.keys.keys()
    }

    /// Prove that every loaded epoch is still declared and usable.
    fn validate_current_metadata(
        &self,
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
    ) -> Result<(), AuditPseudonymKeyringError> {
        metadata.validate_lifecycle_at(now)?;
        if self.metadata_binding != metadata.binding()? {
            return Err(AuditPseudonymKeyringError::StaleMetadata);
        }
        for (key_id, key) in &self.keys {
            let current_expiry = metadata.lookup_expiry(key_id, now)?;
            if current_expiry != key.destroy_after_unix_ms {
                return Err(AuditPseudonymKeyringError::StaleMetadata);
            }
            if key
                .destroy_after_unix_ms
                .is_some_and(|destroy_after| now.unix_ms() >= destroy_after)
            {
                return Err(AuditPseudonymKeyringError::ExpiredKeyEpoch);
            }
        }
        Ok(())
    }

    /// Compute one exact consultation candidate per granted epoch.
    fn consultation_candidate_handles(
        &self,
        metadata: &AuditPseudonymKeyringMetadata,
        now: AuditPseudonymTime,
        domain: RelayConsultationCommitmentDomain,
        canonical_input: &TransientPseudonymInput,
    ) -> Result<Vec<AuditPseudonymHandle>, AuditPseudonymKeyringError> {
        self.validate_current_metadata(metadata, now)?;
        self.keys
            .iter()
            .map(|(key_id, key)| {
                Ok(AuditPseudonymHandle {
                    key_id: key_id.clone(),
                    value: key
                        .material
                        .commitment(domain, canonical_input)
                        .as_str()
                        .to_owned(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
impl fmt::Debug for AuditPseudonymLookupKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditPseudonymLookupKeyring")
            .field("metadata_binding", &self.metadata_binding)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .field("key_material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditPseudonymKeyringError {
    #[error("audit pseudonym key id is not canonical")]
    InvalidKeyId,
    #[error("audit pseudonym time value is invalid")]
    InvalidTime,
    #[error("audit pseudonym key environment-variable name is invalid")]
    InvalidEnvironmentVariableName,
    #[error("audit pseudonym key material is empty")]
    EmptyKeyMaterial,
    #[error("audit pseudonym key material is weaker than the 32-byte minimum")]
    WeakKeyMaterial,
    #[error("audit pseudonym key material exceeds the 4096-byte limit")]
    KeyMaterialTooLarge,
    #[error("audit pseudonym canonical input is not valid interoperable JCS")]
    InvalidCanonicalInput,
    #[error("audit pseudonym canonical input exceeds the 8 KiB limit")]
    CanonicalInputTooLarge,
    #[error("audit pseudonym canonical input exceeds the nesting limit")]
    CanonicalInputTooDeep,
    #[error("audit pseudonym lookup key set is empty")]
    EmptyLookupKeySet,
    #[error("audit pseudonym key set exceeds the v1 epoch limit")]
    TooManyKeyEpochs,
    #[error("audit pseudonym key id is duplicated")]
    DuplicateKeyId,
    #[error("two audit pseudonym key ids resolve to the same key material")]
    DuplicateKeyMaterial,
    #[error("audit pseudonym key sources do not match current metadata")]
    MetadataSourceMismatch,
    #[error("audit pseudonym lookup key is not declared by current metadata")]
    UndeclaredLookupKey,
    #[error("audit pseudonym key epoch is expired")]
    ExpiredKeyEpoch,
    #[error("audit pseudonym metadata is not active yet")]
    MetadataNotActive,
    #[error("audit pseudonym active write deadline was reached")]
    ActiveWriteDeadlineReached,
    #[error("audit pseudonym capability metadata is stale")]
    StaleMetadata,
    #[error("audit pseudonym key lifecycle metadata is invalid")]
    InvalidKeyLifecycle,
    #[error("audit pseudonym key retention is shorter than event retention")]
    RetentionTooShort,
    #[error("persisted audit pseudonym key id history is incomplete")]
    IncompleteKeyIdHistory,
    #[error("audit pseudonym key id was already used")]
    ReusedKeyId,
    #[error("audit pseudonym keyring rotation transition is invalid")]
    InvalidRotationTransition,
    #[error("audit pseudonym keyring maintenance transition is invalid")]
    InvalidMaintenanceTransition,
    #[error("the prior active audit pseudonym key was not retained")]
    PriorActiveKeyNotRetained,
    #[error("an unexpired retained audit pseudonym key was removed")]
    UnexpiredEpochRemoved,
    #[error("retained audit pseudonym key metadata changed")]
    RetainedEpochChanged,
    #[error("audit pseudonym metadata serialization failed")]
    MetadataSerializationFailed,
    #[error("audit pseudonym metadata canonicalization failed")]
    MetadataCanonicalizationFailed,
    #[error("audit pseudonym key loading failed: {0}")]
    Audit(#[from] AuditError),
}

fn validate_secret_length(length: usize) -> Result<(), AuditPseudonymKeyringError> {
    if length == 0 {
        return Err(AuditPseudonymKeyringError::EmptyKeyMaterial);
    }
    if length < MIN_AUDIT_SECRET_BYTES {
        return Err(AuditPseudonymKeyringError::WeakKeyMaterial);
    }
    if length > MAX_AUDIT_PSEUDONYM_SECRET_BYTES {
        return Err(AuditPseudonymKeyringError::KeyMaterialTooLarge);
    }
    Ok(())
}

fn is_environment_variable_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_ENV_VAR_NAME_BYTES
        && matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn is_bounded_token(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= max_bytes
        && matches!(first, b'a'..=b'z' | b'0'..=b'9')
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

#[cfg(test)]
fn collect_sources<I>(
    sources: I,
) -> Result<Vec<AuditPseudonymKeySource>, AuditPseudonymKeyringError>
where
    I: IntoIterator<Item = AuditPseudonymKeySource>,
{
    let mut collected = Vec::new();
    for source in sources {
        if collected.len() == MAX_KEYRING_EPOCHS {
            return Err(AuditPseudonymKeyringError::TooManyKeyEpochs);
        }
        collected.push(source);
    }
    Ok(collected)
}

#[cfg(test)]
fn ensure_exact_source_ids(
    metadata: &AuditPseudonymKeyringMetadata,
    sources: &[AuditPseudonymKeySource],
) -> Result<(), AuditPseudonymKeyringError> {
    let expected = metadata
        .declared_key_ids()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual = sources
        .iter()
        .map(|source| source.key_id.clone())
        .collect::<BTreeSet<_>>();
    if actual.len() != sources.len() {
        return Err(AuditPseudonymKeyringError::DuplicateKeyId);
    }
    if actual != expected {
        return Err(AuditPseudonymKeyringError::MetadataSourceMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn ensure_exact_loaded_ids(
    metadata: &AuditPseudonymKeyringMetadata,
    loaded: &BTreeMap<AuditPseudonymKeyId, AuditPseudonymKeyMaterial>,
) -> Result<(), AuditPseudonymKeyringError> {
    let expected = metadata
        .declared_key_ids()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual = loaded.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(AuditPseudonymKeyringError::MetadataSourceMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn load_env_materials(
    sources: Vec<AuditPseudonymKeySource>,
) -> Result<BTreeMap<AuditPseudonymKeyId, AuditPseudonymKeyMaterial>, AuditPseudonymKeyringError> {
    collect_unique_materials(
        sources
            .into_iter()
            .map(|source| {
                let material = AuditPseudonymKeyMaterial::from_env_derived(&source.secret_env_var)?;
                Ok((source.key_id, material))
            })
            .collect::<Result<Vec<_>, AuditPseudonymKeyringError>>()?,
    )
}

#[cfg(test)]
fn collect_unique_materials<I>(
    materials: I,
) -> Result<BTreeMap<AuditPseudonymKeyId, AuditPseudonymKeyMaterial>, AuditPseudonymKeyringError>
where
    I: IntoIterator<Item = (AuditPseudonymKeyId, AuditPseudonymKeyMaterial)>,
{
    let mut loaded = BTreeMap::new();
    for (key_id, material) in materials {
        if loaded.len() == MAX_KEYRING_EPOCHS {
            return Err(AuditPseudonymKeyringError::TooManyKeyEpochs);
        }
        if loaded.insert(key_id, material).is_some() {
            return Err(AuditPseudonymKeyringError::DuplicateKeyId);
        }
    }
    Ok(loaded)
}

#[cfg(test)]
fn reject_duplicate_key_material(
    loaded: &BTreeMap<AuditPseudonymKeyId, AuditPseudonymKeyMaterial>,
) -> Result<(), AuditPseudonymKeyringError> {
    for (index, material) in loaded.values().enumerate() {
        if loaded
            .values()
            .take(index)
            .any(|previous| material.is_same_material(previous))
        {
            return Err(AuditPseudonymKeyringError::DuplicateKeyMaterial);
        }
    }
    Ok(())
}

fn bounded_json_size(value: &Value, depth: usize) -> Result<usize, AuditPseudonymKeyringError> {
    if depth > MAX_CANONICAL_INPUT_DEPTH {
        return Err(AuditPseudonymKeyringError::CanonicalInputTooDeep);
    }
    let size = match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => {
            validate_jcs_number(number)?;
            // The longest finite binary64 JCS representation is 24 bytes. Use
            // the fixed bound instead of allocating a plaintext decimal copy.
            24
        }
        Value::String(value) => escaped_json_string_size(value),
        Value::Array(values) => {
            let mut size = 2usize
                .checked_add(values.len().saturating_sub(1))
                .ok_or(AuditPseudonymKeyringError::CanonicalInputTooLarge)?;
            for value in values {
                size = size
                    .checked_add(bounded_json_size(value, depth + 1)?)
                    .ok_or(AuditPseudonymKeyringError::CanonicalInputTooLarge)?;
                if size > MAX_CANONICAL_INPUT_BYTES {
                    return Err(AuditPseudonymKeyringError::CanonicalInputTooLarge);
                }
            }
            size
        }
        Value::Object(fields) => {
            let mut size = 2usize
                .checked_add(fields.len().saturating_sub(1))
                .ok_or(AuditPseudonymKeyringError::CanonicalInputTooLarge)?;
            for (key, value) in fields {
                let value_size = bounded_json_size(value, depth + 1)?;
                size = size
                    .checked_add(escaped_json_string_size(key))
                    .and_then(|size| size.checked_add(1))
                    .and_then(|size| size.checked_add(value_size))
                    .ok_or(AuditPseudonymKeyringError::CanonicalInputTooLarge)?;
                if size > MAX_CANONICAL_INPUT_BYTES {
                    return Err(AuditPseudonymKeyringError::CanonicalInputTooLarge);
                }
            }
            size
        }
    };
    if size > MAX_CANONICAL_INPUT_BYTES {
        return Err(AuditPseudonymKeyringError::CanonicalInputTooLarge);
    }
    Ok(size)
}

fn validate_jcs_number(number: &serde_json::Number) -> Result<(), AuditPseudonymKeyringError> {
    let exact_integer = |magnitude: u64| {
        if magnitude == 0 {
            return true;
        }
        let significant_bits = u64::BITS - magnitude.leading_zeros();
        significant_bits <= 53 || magnitude.trailing_zeros() >= significant_bits - 53
    };
    if let Some(value) = number.as_i64() {
        return exact_integer(value.unsigned_abs())
            .then_some(())
            .ok_or(AuditPseudonymKeyringError::InvalidCanonicalInput);
    }
    if let Some(value) = number.as_u64() {
        return exact_integer(value)
            .then_some(())
            .ok_or(AuditPseudonymKeyringError::InvalidCanonicalInput);
    }
    number
        .as_f64()
        .filter(|value| value.is_finite())
        .map(|_| ())
        .ok_or(AuditPseudonymKeyringError::InvalidCanonicalInput)
}

fn escaped_json_string_size(value: &str) -> usize {
    value.chars().fold(2usize, |size, character| {
        let escaped = match character {
            '"' | '\\' | '\u{08}' | '\u{09}' | '\n' | '\u{0c}' | '\r' => 2,
            character if character <= '\u{1f}' => 6,
            character => character.len_utf8(),
        };
        size.saturating_add(escaped)
    })
}

fn scrub_json_strings(value: &mut Value) {
    let mut pending = vec![std::mem::replace(value, Value::Null)];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(mut value) => value.zeroize(),
            Value::Array(values) => pending.extend(values),
            Value::Object(fields) => {
                for (mut key, value) in fields {
                    key.zeroize();
                    pending.push(value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(value: &str) -> AuditPseudonymKeyId {
        AuditPseudonymKeyId::parse(value).expect("valid test key id")
    }

    fn time(value: i64) -> AuditPseudonymTime {
        AuditPseudonymTime::from_unix_ms(value).expect("valid test time")
    }

    fn input(value: Value) -> TransientPseudonymInput {
        TransientPseudonymInput::from_jcs_value(value).expect("valid test input")
    }

    fn material(byte: u8) -> AuditPseudonymKeyMaterial {
        AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![byte; 32]))
            .expect("strong test audit pseudonym secret")
    }

    fn commitment_vector_inputs() -> [(RelayConsultationCommitmentDomain, Value, &'static str); 4] {
        [
            (
                RelayConsultationCommitmentDomain::Subject,
                json!({
                    "tenant": "example-government",
                    "registry_instance": "people-primary",
                    "identifier_type": "national_id",
                    "canonical_subject": "123456789",
                }),
                "{\"canonical_subject\":\"123456789\",\"identifier_type\":\"national_id\",\"registry_instance\":\"people-primary\",\"tenant\":\"example-government\"}",
            ),
            (
                RelayConsultationCommitmentDomain::Input,
                json!({
                    "profile_id": "example.person-status.exact",
                    "profile_version": "1",
                    "canonical_inputs": {"subject_id": "123456789"},
                }),
                "{\"canonical_inputs\":{\"subject_id\":\"123456789\"},\"profile_id\":\"example.person-status.exact\",\"profile_version\":\"1\"}",
            ),
            (
                RelayConsultationCommitmentDomain::Predicate,
                json!({
                    "binding_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "source_operation": "person.lookup-exact",
                    "exact_predicate": {"national_id": "123456789"},
                }),
                "{\"binding_hash\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"exact_predicate\":{\"national_id\":\"123456789\"},\"source_operation\":\"person.lookup-exact\"}",
            ),
            (
                RelayConsultationCommitmentDomain::Consent,
                json!({
                    "verifier_id": "government-consent-service",
                    "raw_consent_reference": "consent-abc-123",
                }),
                "{\"raw_consent_reference\":\"consent-abc-123\",\"verifier_id\":\"government-consent-service\"}",
            ),
        ]
    }

    fn commitment_for_domain(
        material: &AuditPseudonymKeyMaterial,
        domain: RelayConsultationCommitmentDomain,
        canonical_input: &TransientPseudonymInput,
    ) -> AuditPseudonymCommitment {
        match domain {
            RelayConsultationCommitmentDomain::Subject => {
                material.consultation_subject_commitment(canonical_input)
            }
            RelayConsultationCommitmentDomain::Input => {
                material.consultation_input_commitment(canonical_input)
            }
            RelayConsultationCommitmentDomain::Predicate => {
                material.consultation_predicate_commitment(canonical_input)
            }
            RelayConsultationCommitmentDomain::Consent => {
                material.consultation_consent_commitment(canonical_input)
            }
        }
    }

    fn retained(
        key_id: &str,
        retired_at_unix_ms: i64,
        destroy_after_unix_ms: i64,
    ) -> RetainedAuditPseudonymKeyEpoch {
        RetainedAuditPseudonymKeyEpoch::new(id(key_id), retired_at_unix_ms, destroy_after_unix_ms)
            .expect("valid retained epoch")
    }

    fn metadata(
        generation: u64,
        active_key_id: &str,
        active_since_unix_ms: i64,
        retention_ms: i64,
        retained_keys: Vec<RetainedAuditPseudonymKeyEpoch>,
    ) -> AuditPseudonymKeyringMetadata {
        metadata_with_deadline(
            generation,
            active_key_id,
            active_since_unix_ms,
            active_since_unix_ms + 10_000,
            retention_ms,
            retained_keys,
        )
    }

    fn metadata_with_deadline(
        generation: u64,
        active_key_id: &str,
        active_since_unix_ms: i64,
        active_write_deadline_unix_ms: i64,
        retention_ms: i64,
        retained_keys: Vec<RetainedAuditPseudonymKeyEpoch>,
    ) -> AuditPseudonymKeyringMetadata {
        AuditPseudonymKeyringMetadata::new(
            generation,
            id(active_key_id),
            active_since_unix_ms,
            active_write_deadline_unix_ms,
            retention_ms,
            retained_keys,
        )
        .expect("valid metadata")
    }

    #[test]
    fn identifiers_and_time_are_bounded() {
        for value in ["epoch-2026-07", "a", "0.key_id"] {
            assert_eq!(id(value).as_str(), value);
        }
        for value in ["", "UPPER", "-leading", "with space", "é"] {
            assert!(AuditPseudonymKeyId::parse(value).is_err(), "{value:?}");
        }
        assert!(AuditPseudonymKeyId::parse("x".repeat(MAX_KEY_ID_BYTES)).is_ok());
        assert!(AuditPseudonymKeyId::parse("x".repeat(MAX_KEY_ID_BYTES + 1)).is_err());

        let max_env_name = format!("A{}", "A".repeat(MAX_ENV_VAR_NAME_BYTES - 1));
        assert!(AuditPseudonymKeySource::new(id("epoch-env"), max_env_name).is_ok());
        assert!(AuditPseudonymKeySource::new(
            id("epoch-env"),
            format!("A{}", "A".repeat(MAX_ENV_VAR_NAME_BYTES)),
        )
        .is_err());

        assert!(AuditPseudonymTime::from_unix_ms(0).is_ok());
        assert!(AuditPseudonymTime::from_unix_ms(MAX_EXACT_JSON_INTEGER).is_ok());
        assert!(AuditPseudonymTime::from_unix_ms(-1).is_err());
    }

    #[test]
    fn transient_input_is_jcs_bounded_and_scrubbed() {
        let left: Value =
            serde_json::from_str(r#"{"z":"selector-123","a":{"z":2,"a":1}}"#).expect("left JSON");
        let right: Value =
            serde_json::from_str(r#"{"a":{"a":1,"z":2},"z":"selector-123"}"#).expect("right JSON");
        let left = input(left);
        let right = input(right);
        assert_eq!(left.as_str(), right.as_str());
        assert!(!format!("{left:?}").contains("selector-123"));

        assert!(matches!(
            TransientPseudonymInput::from_jcs_value(json!({
                "value": 9_007_199_254_740_993_u64,
            })),
            Err(AuditPseudonymKeyringError::InvalidCanonicalInput)
        ));
        assert!(matches!(
            TransientPseudonymInput::from_jcs_value(json!({
                "a_sensitive_prefix": "selector-before-invalid-number",
                "z_invalid": 9_007_199_254_740_993_u64,
            })),
            Err(AuditPseudonymKeyringError::InvalidCanonicalInput)
        ));
        assert!(TransientPseudonymInput::from_jcs_value(json!({
            "exact_large_integer": 1_u64 << 60,
        }))
        .is_ok());

        let exact_value_bytes = MAX_CANONICAL_INPUT_BYTES - 8;
        let exact = input(json!({"v": "x".repeat(exact_value_bytes)}));
        assert_eq!(exact.as_str().len(), MAX_CANONICAL_INPUT_BYTES);
        assert!(matches!(
            TransientPseudonymInput::from_jcs_value(
                json!({"v": "x".repeat(exact_value_bytes + 1)})
            ),
            Err(AuditPseudonymKeyringError::CanonicalInputTooLarge)
        ));

        let mut owned = serde_json::from_str::<Value>(
            r#"{"secret-key":"secret-value","nested":["other-secret"]}"#,
        )
        .expect("owned JSON");
        scrub_json_strings(&mut owned);
        assert_eq!(owned, Value::Null);

        let mut deeply_nested = Value::Null;
        for _ in 0..=MAX_CANONICAL_INPUT_DEPTH {
            deeply_nested = Value::Array(vec![deeply_nested]);
        }
        assert!(matches!(
            TransientPseudonymInput::from_jcs_value(deeply_nested),
            Err(AuditPseudonymKeyringError::CanonicalInputTooDeep)
        ));
    }

    #[test]
    fn production_key_material_is_bounded_domain_separated_and_redacted() {
        assert_ne!(
            AUDIT_PSEUDONYM_KEY_DERIVATION_INFO,
            crate::CHAIN_KEY_DERIVATION_INFO
        );
        assert_ne!(
            AUDIT_PSEUDONYM_KEY_DERIVATION_INFO,
            crate::IDENTIFIER_KEY_DERIVATION_INFO
        );
        assert!(matches!(
            AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(Vec::new())),
            Err(AuditPseudonymKeyringError::EmptyKeyMaterial)
        ));
        assert!(matches!(
            AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![7; 31])),
            Err(AuditPseudonymKeyringError::WeakKeyMaterial)
        ));
        assert!(
            AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![
                7;
                MAX_AUDIT_PSEUDONYM_SECRET_BYTES
            ]))
            .is_ok()
        );
        assert!(matches!(
            AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(vec![
                7;
                MAX_AUDIT_PSEUDONYM_SECRET_BYTES
                    + 1
            ])),
            Err(AuditPseudonymKeyringError::KeyMaterialTooLarge)
        ));

        let same_left = material(9);
        let same_right = material(9);
        let different = material(10);
        assert!(same_left.is_same_material(&same_right));
        assert!(!same_left.is_same_material(&different));

        let canonical_input = input(json!({"same": "canonical-input"}));
        let commitments = [
            same_left.consultation_subject_commitment(&canonical_input),
            same_left.consultation_input_commitment(&canonical_input),
            same_left.consultation_predicate_commitment(&canonical_input),
            same_left.consultation_consent_commitment(&canonical_input),
        ];
        let distinct = commitments
            .iter()
            .map(AuditPseudonymCommitment::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(distinct.len(), commitments.len());

        let diagnostics = format!("{same_left:?} {:?}", commitments[0]);
        assert!(!diagnostics.contains("canonical-input"));
        assert!(!diagnostics.contains(commitments[0].as_str()));
        assert_eq!(diagnostics, "AuditPseudonymKeyMaterial(<redacted>) AuditPseudonymCommitment(hmac-sha256:<redacted>)");

        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretBytes>();
    }

    #[test]
    fn production_key_material_uses_exact_environment_bytes() {
        const ENV_NAME: &str = "REGISTRY_AUDIT_PSEUDONYM_MATERIAL_EXACT_TEST";
        const MASTER: &str = " exact-pseudonym-master-secret-0123456789abcdef ";
        std::env::set_var(ENV_NAME, MASTER);
        let from_env =
            AuditPseudonymKeyMaterial::from_env_derived(ENV_NAME).expect("environment material");
        std::env::remove_var(ENV_NAME);
        let explicit = AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(
            MASTER.as_bytes().to_vec(),
        ))
        .expect("explicit material");
        assert!(from_env.is_same_material(&explicit));
        let trimmed = AuditPseudonymKeyMaterial::from_secret_bytes(Zeroizing::new(
            MASTER.trim().as_bytes().to_vec(),
        ))
        .expect("trimmed material");
        assert!(!from_env.is_same_material(&trimmed));

        for invalid_name in ["", " with-space", "9LEADING", "NON-ASCII-É"] {
            assert!(matches!(
                AuditPseudonymKeyMaterial::from_env_derived(invalid_name),
                Err(AuditPseudonymKeyringError::InvalidEnvironmentVariableName)
            ));
        }
    }

    #[test]
    fn production_key_material_rejects_invalid_environment_values_without_leaks() {
        const EMPTY_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_EMPTY_MATERIAL_TEST";
        const WEAK_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_WEAK_MATERIAL_TEST";
        const LARGE_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_LARGE_MATERIAL_TEST";
        const MISSING_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_MISSING_MATERIAL_TEST";
        const WEAK_MARKER: &str = "weak-material-must-not-leak";
        std::env::set_var(EMPTY_ENV, "");
        std::env::set_var(WEAK_ENV, WEAK_MARKER);
        std::env::set_var(
            LARGE_ENV,
            "large-material-must-not-leak".repeat(
                MAX_AUDIT_PSEUDONYM_SECRET_BYTES / "large-material-must-not-leak".len() + 1,
            ),
        );
        std::env::remove_var(MISSING_ENV);

        let errors = [
            AuditPseudonymKeyMaterial::from_env_derived(EMPTY_ENV)
                .expect_err("empty material is rejected"),
            AuditPseudonymKeyMaterial::from_env_derived(WEAK_ENV)
                .expect_err("weak material is rejected"),
            AuditPseudonymKeyMaterial::from_env_derived(LARGE_ENV)
                .expect_err("oversized material is rejected"),
            AuditPseudonymKeyMaterial::from_env_derived(MISSING_ENV)
                .expect_err("missing material is rejected"),
        ];
        std::env::remove_var(EMPTY_ENV);
        std::env::remove_var(WEAK_ENV);
        std::env::remove_var(LARGE_ENV);

        assert!(matches!(
            errors[0],
            AuditPseudonymKeyringError::EmptyKeyMaterial
        ));
        assert!(matches!(
            errors[1],
            AuditPseudonymKeyringError::WeakKeyMaterial
        ));
        assert!(matches!(
            errors[2],
            AuditPseudonymKeyringError::KeyMaterialTooLarge
        ));
        assert!(matches!(
            errors[3],
            AuditPseudonymKeyringError::Audit(AuditError::EnvVarUnavailable { .. })
        ));
        for error in errors {
            let diagnostics = format!("{error:?} {error}");
            assert!(!diagnostics.contains(WEAK_MARKER));
            assert!(!diagnostics.contains("large-material-must-not-leak"));
        }
    }

    #[test]
    fn production_commitment_is_canonical_key_order_invariant() {
        let left =
            input(serde_json::from_str(r#"{"z":{"b":2,"a":1},"a":"same"}"#).expect("left input"));
        let right =
            input(serde_json::from_str(r#"{"a":"same","z":{"a":1,"b":2}}"#).expect("right input"));
        let left_material = material(17);
        let right_material = material(17);
        assert_eq!(
            left_material.consultation_subject_commitment(&left),
            right_material.consultation_subject_commitment(&right),
        );
    }

    #[test]
    fn consultation_commitment_domains_match_pinned_exact_preimages_and_hmacs() {
        const EXPECTED_ALREADY_DERIVED_KEY_HANDLES: [&str; 4] = [
            "hmac-sha256:f684cfafd11414f19ecb060115ecaac7fec6420d42e075dc8b2ef770097896bc",
            "hmac-sha256:15c3415ebc99c3dab853f6081f3baa621c9603d39f32a9b8b00369382f25f33f",
            "hmac-sha256:346bad213b8477d67cbbb8dbba9705b85eb71477eda8e97b8c1300204fd007e8",
            "hmac-sha256:00d9035914a65b4931f8b6c3685bcbde8ec4a8691350d2e7058518ff5cca205e",
        ];

        assert!(
            AuditPseudonymKeyMaterial::from_test_derived_key(Zeroizing::new(vec![0x42; 31]))
                .is_none()
        );
        assert!(
            AuditPseudonymKeyMaterial::from_test_derived_key(Zeroizing::new(vec![0x42; 33]))
                .is_none()
        );
        // These frozen v1 vectors treat 0x42 * 32 as the already-derived HMAC
        // domain key. They pin domain || NUL || JCS framing independently of
        // deployment-master derivation.
        let commitment_material =
            AuditPseudonymKeyMaterial::from_test_derived_key(Zeroizing::new(vec![0x42; 32]))
                .expect("exact test-only derived key");
        for ((domain, value, expected_jcs), expected_handle) in commitment_vector_inputs()
            .into_iter()
            .zip(EXPECTED_ALREADY_DERIVED_KEY_HANDLES)
        {
            let canonical_input = input(value);
            assert_eq!(canonical_input.as_str(), expected_jcs);
            let expected_preimage = format!("{}\0{expected_jcs}", domain.as_str());
            assert_eq!(
                relay_consultation_commitment_preimage(domain, &canonical_input).as_slice(),
                expected_preimage.as_bytes(),
            );
            let commitment = commitment_for_domain(&commitment_material, domain, &canonical_input);
            assert_eq!(commitment.as_str(), expected_handle);
        }
    }

    #[test]
    fn production_master_derivation_matches_pinned_end_to_end_commitments() {
        const EXPECTED_MASTER_DERIVED_HANDLES: [&str; 4] = [
            "hmac-sha256:80d4a9f979be7df1455203f542a3c393c995aeca508a3009cdbd7e37c45021da",
            "hmac-sha256:432d0c8e572abd017f848b4e74be7fbb9c9da015a54c3ef47458f0fabe147021",
            "hmac-sha256:614cfadc2079ff97728a5007908f6c53447f087a22d084eaefb80c5a682fbba6",
            "hmac-sha256:25483260fc7fa92958c120142cbde1a4a071fc62f3f02ac32ff2e216741e5d6b",
        ];

        // The same fixture bytes are deployment master material here. The
        // production constructor first applies the dedicated HKDF-Expand label,
        // so these vectors pin the complete master -> sub-key -> commitment path.
        let commitment_material = material(0x42);
        for ((domain, value, _), expected_handle) in commitment_vector_inputs()
            .into_iter()
            .zip(EXPECTED_MASTER_DERIVED_HANDLES)
        {
            let canonical_input = input(value);
            let commitment = commitment_for_domain(&commitment_material, domain, &canonical_input);
            assert_eq!(commitment.as_str(), expected_handle);
        }
    }

    #[test]
    fn test_write_model_is_bound_to_supplied_metadata_and_time() {
        let current = metadata(1, "epoch-1", 1_000, 2_000, vec![]);
        let write = AuditPseudonymWriteKey::from_preflight_materials(
            &current,
            time(1_000),
            [(id("epoch-1"), material(1))],
        )
        .expect("write key");
        assert_eq!(write.key_id(), current.active_key_id());
        assert_eq!(
            write.metadata_binding(),
            current.binding().expect("binding")
        );

        let canonical_input = input(json!({"selector": "selector-123"}));
        let handle = write
            .consultation_commitment(
                &current,
                time(1_001),
                RelayConsultationCommitmentDomain::Subject,
                &canonical_input,
            )
            .expect("current metadata hashes");
        assert_eq!(handle.key_id(), current.active_key_id());
        assert!(handle.value().starts_with("hmac-sha256:"));

        let changed_same_generation = metadata(1, "epoch-1", 1_000, 3_000, vec![]);
        assert!(matches!(
            write.validate_current_metadata(&changed_same_generation, time(1_001)),
            Err(AuditPseudonymKeyringError::StaleMetadata)
        ));
        assert!(matches!(
            AuditPseudonymWriteKey::from_preflight_materials(
                &current,
                time(999),
                [(id("epoch-1"), material(1))]
            ),
            Err(AuditPseudonymKeyringError::MetadataNotActive)
        ));
    }

    #[test]
    fn test_preflight_requires_exact_ids_and_unique_material_across_all_epochs() {
        let current = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 4_000)],
        );
        assert!(matches!(
            AuditPseudonymWriteKey::from_preflight_materials(
                &current,
                time(2_000),
                [(id("epoch-2"), material(2))]
            ),
            Err(AuditPseudonymKeyringError::MetadataSourceMismatch)
        ));
        assert!(matches!(
            AuditPseudonymWriteKey::from_preflight_materials(
                &current,
                time(2_000),
                [(id("epoch-1"), material(1)), (id("epoch-2"), material(1)),]
            ),
            Err(AuditPseudonymKeyringError::DuplicateKeyMaterial)
        ));
        assert!(matches!(
            AuditPseudonymWriteKey::from_preflight_materials(
                &current,
                time(2_000),
                [
                    (id("epoch-1"), material(1)),
                    (id("epoch-1"), material(2)),
                    (id("epoch-2"), material(3)),
                ]
            ),
            Err(AuditPseudonymKeyringError::DuplicateKeyId)
        ));

        let write = AuditPseudonymWriteKey::from_preflight_materials(
            &current,
            time(2_000),
            [(id("epoch-1"), material(1)), (id("epoch-2"), material(2))],
        )
        .expect("complete unique preflight");
        assert_eq!(write.key_id().as_str(), "epoch-2");
    }

    #[test]
    fn lookup_rejects_undeclared_expired_and_stale_metadata() {
        let current = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 4_000)],
        );
        assert!(matches!(
            AuditPseudonymLookupKeyring::from_materials(&current, time(2_500), []),
            Err(AuditPseudonymKeyringError::EmptyLookupKeySet)
        ));
        assert!(matches!(
            AuditPseudonymLookupKeyring::from_materials(
                &current,
                time(2_500),
                [(id("epoch-0"), material(3))]
            ),
            Err(AuditPseudonymKeyringError::UndeclaredLookupKey)
        ));
        assert!(matches!(
            AuditPseudonymLookupKeyring::from_materials(
                &current,
                time(4_000),
                [(id("epoch-1"), material(1))]
            ),
            Err(AuditPseudonymKeyringError::ExpiredKeyEpoch)
        ));
        assert!(matches!(
            AuditPseudonymLookupKeyring::from_materials(
                &current,
                time(2_500),
                [(id("epoch-1"), material(1)), (id("epoch-2"), material(1)),]
            ),
            Err(AuditPseudonymKeyringError::DuplicateKeyMaterial)
        ));

        let lookup = AuditPseudonymLookupKeyring::from_materials(
            &current,
            time(2_500),
            [(id("epoch-2"), material(2)), (id("epoch-1"), material(1))],
        )
        .expect("declared lookup");
        let canonical_input = input(json!({"selector": "selector-123"}));
        assert_eq!(
            lookup
                .consultation_candidate_handles(
                    &current,
                    time(3_999),
                    RelayConsultationCommitmentDomain::Subject,
                    &canonical_input,
                )
                .expect("before destruction")
                .len(),
            2
        );
        assert!(matches!(
            lookup.consultation_candidate_handles(
                &current,
                time(4_000),
                RelayConsultationCommitmentDomain::Subject,
                &canonical_input,
            ),
            Err(AuditPseudonymKeyringError::ExpiredKeyEpoch)
        ));

        let changed = metadata(
            3,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 5_000)],
        );
        assert!(matches!(
            lookup.validate_current_metadata(&changed, time(2_500)),
            Err(AuditPseudonymKeyringError::StaleMetadata)
        ));
    }

    #[test]
    fn lookup_order_is_deterministic_for_reversed_grants_and_jcs_order() {
        let current = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 4_000)],
        );
        let forward = AuditPseudonymLookupKeyring::from_materials(
            &current,
            time(2_500),
            [(id("epoch-1"), material(1)), (id("epoch-2"), material(2))],
        )
        .expect("forward");
        let reversed = AuditPseudonymLookupKeyring::from_materials(
            &current,
            time(2_500),
            [(id("epoch-2"), material(2)), (id("epoch-1"), material(1))],
        )
        .expect("reversed");
        let input_a = input(serde_json::from_str(r#"{"z":2,"a":1}"#).expect("input a"));
        let input_b = input(serde_json::from_str(r#"{"a":1,"z":2}"#).expect("input b"));
        let left = forward
            .consultation_candidate_handles(
                &current,
                time(2_500),
                RelayConsultationCommitmentDomain::Subject,
                &input_a,
            )
            .expect("left");
        let right = reversed
            .consultation_candidate_handles(
                &current,
                time(2_500),
                RelayConsultationCommitmentDomain::Subject,
                &input_b,
            )
            .expect("right");
        assert_eq!(left, right);
        assert_eq!(
            left.iter()
                .map(|handle| handle.key_id().as_str())
                .collect::<Vec<_>>(),
            ["epoch-1", "epoch-2"]
        );
    }

    #[test]
    fn successor_transition_preserves_active_and_unexpired_history() {
        let previous = metadata(1, "epoch-1", 1_000, 2_000, vec![]);
        let successor = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 2_000, 4_000)],
        );
        let history = BTreeSet::from([id("epoch-1")]);
        previous
            .validate_rotation_successor_values(&successor, &history, time(2_000))
            .expect("valid rotation");

        let rollback_or_replay = metadata(
            1,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 2_000, 4_000)],
        );
        assert!(matches!(
            previous
                .validate_rotation_successor_values(&rollback_or_replay, &history, time(2_000),),
            Err(AuditPseudonymKeyringError::InvalidRotationTransition)
        ));

        let missing_prior_active = metadata(2, "epoch-2", 2_000, 2_000, vec![]);
        assert!(matches!(
            previous.validate_rotation_successor_values(
                &missing_prior_active,
                &history,
                time(2_000),
            ),
            Err(AuditPseudonymKeyringError::PriorActiveKeyNotRetained)
        ));

        let wrong_retirement = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_999, 4_000)],
        );
        assert!(matches!(
            previous.validate_rotation_successor_values(&wrong_retirement, &history, time(2_000),),
            Err(AuditPseudonymKeyringError::InvalidRotationTransition)
        ));

        let reused = metadata(
            2,
            "epoch-0",
            2_000,
            2_000,
            vec![retained("epoch-1", 2_000, 4_000)],
        );
        let history_with_old = BTreeSet::from([id("epoch-0"), id("epoch-1")]);
        assert!(matches!(
            previous.validate_rotation_successor_values(&reused, &history_with_old, time(2_000),),
            Err(AuditPseudonymKeyringError::ReusedKeyId)
        ));
    }

    #[test]
    fn successor_cannot_drop_or_mutate_unexpired_retained_epochs() {
        let previous = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 6_000)],
        );
        let history = BTreeSet::from([id("epoch-1"), id("epoch-2")]);
        let dropped = metadata(
            3,
            "epoch-3",
            3_000,
            2_000,
            vec![retained("epoch-2", 3_000, 5_000)],
        );
        assert!(matches!(
            previous.validate_rotation_successor_values(&dropped, &history, time(3_000)),
            Err(AuditPseudonymKeyringError::UnexpiredEpochRemoved)
        ));

        let shortened = metadata(
            3,
            "epoch-3",
            3_000,
            2_000,
            vec![
                retained("epoch-1", 1_000, 5_000),
                retained("epoch-2", 3_000, 5_000),
            ],
        );
        assert!(matches!(
            previous.validate_rotation_successor_values(&shortened, &history, time(3_000)),
            Err(AuditPseudonymKeyringError::RetainedEpochChanged)
        ));

        let expired_previous = metadata(
            2,
            "epoch-2",
            2_000,
            1_000,
            vec![retained("epoch-1", 1_000, 2_500)],
        );
        let omit_expired = metadata(
            3,
            "epoch-3",
            3_000,
            1_000,
            vec![retained("epoch-2", 3_000, 4_000)],
        );
        expired_previous
            .validate_rotation_successor_values(&omit_expired, &history, time(3_000))
            .expect("expired retained epoch may be omitted");

        let resurrect_expired = metadata(
            3,
            "epoch-3",
            3_000,
            1_000,
            vec![
                retained("epoch-1", 1_000, 3_500),
                retained("epoch-2", 3_000, 4_000),
            ],
        );
        assert!(matches!(
            expired_previous.validate_rotation_successor_values(
                &resurrect_expired,
                &history,
                time(3_000),
            ),
            Err(AuditPseudonymKeyringError::RetainedEpochChanged)
        ));
    }

    #[test]
    fn active_write_deadline_is_hash_covered_and_exclusive() {
        let current = metadata_with_deadline(1, "epoch-1", 1_000, 2_000, 500, vec![]);
        assert_eq!(current.active_write_deadline_unix_ms(), 2_000);
        assert!(matches!(
            current.validate_lifecycle_at(time(999)),
            Err(AuditPseudonymKeyringError::MetadataNotActive)
        ));
        current
            .validate_lifecycle_at(time(1_000))
            .expect("activation is inclusive");
        current
            .validate_lifecycle_at(time(1_999))
            .expect("instant before deadline is valid");
        assert!(matches!(
            current.validate_lifecycle_at(time(2_000)),
            Err(AuditPseudonymKeyringError::ActiveWriteDeadlineReached)
        ));

        let changed_deadline = metadata_with_deadline(1, "epoch-1", 1_000, 2_001, 500, vec![]);
        assert_ne!(
            current.binding().expect("current binding"),
            changed_deadline.binding().expect("changed binding")
        );
        let serialized = serde_json::to_value(&current).expect("metadata JSON");
        assert_eq!(serialized["active_write_deadline_unix_ms"], 2_000);

        assert!(matches!(
            AuditPseudonymWriteKey::from_preflight_materials(
                &current,
                time(2_000),
                [(id("epoch-1"), material(1))],
            ),
            Err(AuditPseudonymKeyringError::ActiveWriteDeadlineReached)
        ));
    }

    #[test]
    fn rotation_respects_old_deadline_and_requires_a_later_new_deadline() {
        let previous = metadata_with_deadline(1, "epoch-1", 1_000, 2_000, 500, vec![]);
        let history = BTreeSet::from([id("epoch-1")]);
        let on_deadline = metadata_with_deadline(
            2,
            "epoch-2",
            2_000,
            3_000,
            500,
            vec![retained("epoch-1", 2_000, 2_500)],
        );
        previous
            .validate_rotation_successor_values(&on_deadline, &history, time(2_000))
            .expect("rotation at the old exclusive write deadline is allowed");

        let late = metadata_with_deadline(
            2,
            "epoch-2",
            2_001,
            3_001,
            500,
            vec![retained("epoch-1", 2_001, 2_501)],
        );
        assert!(matches!(
            previous.validate_rotation_successor_values(&late, &history, time(2_001)),
            Err(AuditPseudonymKeyringError::InvalidRotationTransition)
        ));

        let deadline_not_extended = metadata_with_deadline(
            2,
            "epoch-2",
            1_500,
            2_000,
            500,
            vec![retained("epoch-1", 1_500, 2_000)],
        );
        assert!(matches!(
            previous.validate_rotation_successor_values(
                &deadline_not_extended,
                &history,
                time(1_500),
            ),
            Err(AuditPseudonymKeyringError::InvalidRotationTransition)
        ));
    }

    #[test]
    fn same_active_maintenance_only_prunes_epochs_at_their_deadline() {
        let previous = metadata_with_deadline(
            2,
            "epoch-2",
            2_000,
            10_000,
            2_000,
            vec![
                retained("epoch-0", 500, 3_000),
                retained("epoch-1", 1_000, 7_000),
            ],
        );
        let history = BTreeSet::from([id("epoch-0"), id("epoch-1"), id("epoch-2")]);
        let pruned = metadata_with_deadline(
            3,
            "epoch-2",
            2_000,
            10_000,
            2_000,
            vec![retained("epoch-1", 1_000, 7_000)],
        );
        previous
            .validate_maintenance_successor_values(&pruned, &history, time(3_000))
            .expect("deadline-reached epoch may be pruned");

        assert!(matches!(
            previous.validate_maintenance_successor_values(&pruned, &history, time(2_999)),
            Err(AuditPseudonymKeyringError::UnexpiredEpochRemoved)
        ));

        let kept_expired = metadata_with_deadline(
            3,
            "epoch-2",
            2_000,
            10_000,
            2_000,
            vec![
                retained("epoch-0", 500, 3_000),
                retained("epoch-1", 1_000, 7_000),
            ],
        );
        assert!(matches!(
            previous.validate_maintenance_successor_values(&kept_expired, &history, time(3_000),),
            Err(AuditPseudonymKeyringError::RetainedEpochChanged)
        ));

        let extended = metadata_with_deadline(
            3,
            "epoch-2",
            2_000,
            10_000,
            2_000,
            vec![retained("epoch-1", 1_000, 8_000)],
        );
        assert!(matches!(
            previous.validate_maintenance_successor_values(&extended, &history, time(3_000)),
            Err(AuditPseudonymKeyringError::RetainedEpochChanged)
        ));

        let added_or_resurrected = metadata_with_deadline(
            4,
            "epoch-2",
            2_000,
            10_000,
            2_000,
            vec![
                retained("epoch-0", 500, 6_000),
                retained("epoch-1", 1_000, 7_000),
            ],
        );
        assert!(matches!(
            pruned.validate_maintenance_successor_values(
                &added_or_resurrected,
                &history,
                time(4_000),
            ),
            Err(AuditPseudonymKeyringError::RetainedEpochChanged)
        ));

        let changed_deadline = metadata_with_deadline(
            3,
            "epoch-2",
            2_000,
            11_000,
            2_000,
            vec![retained("epoch-1", 1_000, 7_000)],
        );
        assert!(matches!(
            previous.validate_maintenance_successor_values(
                &changed_deadline,
                &history,
                time(3_000),
            ),
            Err(AuditPseudonymKeyringError::InvalidMaintenanceTransition)
        ));

        let changed_active = metadata_with_deadline(
            3,
            "epoch-3",
            2_001,
            10_000,
            2_000,
            vec![retained("epoch-1", 1_000, 7_000)],
        );
        assert!(matches!(
            previous.validate_maintenance_successor_values(&changed_active, &history, time(3_000),),
            Err(AuditPseudonymKeyringError::InvalidMaintenanceTransition)
        ));

        let shortened_retention = metadata_with_deadline(
            3,
            "epoch-2",
            2_000,
            10_000,
            1_000,
            vec![retained("epoch-1", 1_000, 7_000)],
        );
        assert!(matches!(
            previous.validate_maintenance_successor_values(
                &shortened_retention,
                &history,
                time(3_000),
            ),
            Err(AuditPseudonymKeyringError::InvalidMaintenanceTransition)
        ));

        assert!(matches!(
            previous.validate_maintenance_successor_values(&pruned, &BTreeSet::new(), time(3_000),),
            Err(AuditPseudonymKeyringError::IncompleteKeyIdHistory)
        ));
    }

    #[test]
    fn metadata_and_loading_enforce_exact_epoch_bounds() {
        assert!(AuditPseudonymKeyringMetadata::new(
            MAX_EXACT_JSON_INTEGER as u64,
            id("epoch-max"),
            MAX_EXACT_JSON_INTEGER - 1,
            MAX_EXACT_JSON_INTEGER,
            1,
            vec![],
        )
        .is_ok());
        assert!(matches!(
            AuditPseudonymKeyringMetadata::new(
                MAX_EXACT_JSON_INTEGER as u64 + 1,
                id("epoch-max"),
                1,
                2,
                1,
                vec![],
            ),
            Err(AuditPseudonymKeyringError::InvalidKeyLifecycle)
        ));
        assert!(matches!(
            AuditPseudonymKeyringMetadata::new(1, id("epoch-deadline"), 1_000, 1_000, 1, vec![],),
            Err(AuditPseudonymKeyringError::InvalidKeyLifecycle)
        ));
        assert!(matches!(
            AuditPseudonymKeyringMetadata::new(
                1,
                id("epoch-deadline"),
                MAX_EXACT_JSON_INTEGER - 1,
                MAX_EXACT_JSON_INTEGER + 1,
                1,
                vec![],
            ),
            Err(AuditPseudonymKeyringError::InvalidKeyLifecycle)
        ));

        let retained_keys = (0..MAX_KEYRING_EPOCHS - 1)
            .map(|index| retained(&format!("epoch-{index:02}"), 1_000, 3_000))
            .collect::<Vec<_>>();
        let maximum = metadata(32, "epoch-active", 2_000, 2_000, retained_keys.clone());
        let materials = maximum
            .declared_key_ids()
            .enumerate()
            .map(|(index, key_id)| (key_id.clone(), material((index + 1) as u8)))
            .collect::<Vec<_>>();
        let lookup = AuditPseudonymLookupKeyring::from_materials(&maximum, time(2_000), materials)
            .expect("32 epochs load");
        assert_eq!(lookup.key_ids().len(), MAX_KEYRING_EPOCHS);

        let mut too_many_retained = retained_keys;
        too_many_retained.push(retained("epoch-extra", 1_000, 3_000));
        assert!(matches!(
            AuditPseudonymKeyringMetadata::new(
                33,
                id("epoch-active"),
                2_000,
                12_000,
                2_000,
                too_many_retained,
            ),
            Err(AuditPseudonymKeyringError::TooManyKeyEpochs)
        ));

        let sources = (0..=MAX_KEYRING_EPOCHS)
            .map(|index| {
                AuditPseudonymKeySource::new(
                    id(&format!("source-{index:02}")),
                    format!("AUDIT_SOURCE_{index:02}"),
                )
                .expect("source")
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            collect_sources(sources),
            Err(AuditPseudonymKeyringError::TooManyKeyEpochs)
        ));
    }

    #[test]
    fn metadata_digest_is_deterministic_and_serializable_without_bypass() {
        let left = metadata(
            3,
            "epoch-3",
            3_000,
            2_000,
            vec![
                retained("epoch-2", 2_000, 5_000),
                retained("epoch-1", 1_000, 5_000),
            ],
        );
        let right = metadata(
            3,
            "epoch-3",
            3_000,
            2_000,
            vec![
                retained("epoch-1", 1_000, 5_000),
                retained("epoch-2", 2_000, 5_000),
            ],
        );
        assert_eq!(left, right);
        assert_eq!(
            left.binding().expect("left"),
            right.binding().expect("right")
        );
        let serialized = serde_json::to_value(&left).expect("metadata JSON");
        assert_eq!(serialized["schema"], KEYRING_METADATA_SCHEMA_V1);
        assert_eq!(serialized["generation"], 3);
        assert_eq!(serialized["retained_keys"][0]["key_id"], "epoch-1");
        assert!(serde_json::from_str::<AuditPseudonymKeyId>("\"UPPER\"").is_err());
    }

    #[test]
    fn pure_metadata_time_and_history_checks_do_not_confer_authority() {
        let current = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 4_000)],
        );
        assert!(matches!(
            current.validate_lifecycle_at(time(1_999)),
            Err(AuditPseudonymKeyringError::MetadataNotActive)
        ));
        current
            .validate_lifecycle_at(time(2_000))
            .expect("supplied activation boundary is valid as data");
        assert!(matches!(
            current.validate_lifecycle_at(time(4_000)),
            Err(AuditPseudonymKeyringError::ExpiredKeyEpoch)
        ));

        let changed_same_generation = metadata(
            2,
            "epoch-2",
            2_000,
            2_500,
            vec![retained("epoch-1", 1_000, 4_500)],
        );
        assert_ne!(
            current.binding().expect("current binding"),
            changed_same_generation.binding().expect("changed binding")
        );

        let successor = metadata(
            3,
            "epoch-3",
            3_000,
            2_000,
            vec![
                retained("epoch-1", 1_000, 4_000),
                retained("epoch-2", 3_000, 5_000),
            ],
        );
        assert!(matches!(
            current.validate_rotation_successor_values(&successor, &BTreeSet::new(), time(3_000),),
            Err(AuditPseudonymKeyringError::IncompleteKeyIdHistory)
        ));
        current
            .validate_rotation_successor_values(
                &successor,
                &BTreeSet::from([id("epoch-1"), id("epoch-2")]),
                time(3_000),
            )
            .expect("complete supplied history satisfies the pure transition rules");
    }

    #[test]
    fn test_only_env_preflight_returns_only_active_and_redacts_diagnostics() {
        const ACTIVE_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_ACTIVE_TEST";
        const RETAINED_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_RETAINED_TEST";
        std::env::set_var(ACTIVE_ENV, "active-secret-0123456789abcdef0123456789");
        std::env::set_var(RETAINED_ENV, "retained-secret-0123456789abcdef01234567");

        let current = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 4_000)],
        );
        let active_source =
            AuditPseudonymKeySource::new(id("epoch-2"), ACTIVE_ENV).expect("active source");
        let retained_source =
            AuditPseudonymKeySource::new(id("epoch-1"), RETAINED_ENV).expect("retained source");
        let source_debug = format!("{active_source:?}{retained_source:?}");
        assert!(!source_debug.contains(ACTIVE_ENV));
        assert!(!source_debug.contains(RETAINED_ENV));

        let write = AuditPseudonymWriteKey::preflight_from_env(
            &current,
            time(2_000),
            [retained_source.clone(), active_source.clone()],
        )
        .expect("test preflight");
        let lookup =
            AuditPseudonymLookupKeyring::from_env(&current, time(2_000), [retained_source])
                .expect("test lookup");
        std::env::remove_var(ACTIVE_ENV);
        std::env::remove_var(RETAINED_ENV);

        assert_eq!(write.key_id().as_str(), "epoch-2");
        assert_eq!(lookup.key_ids().len(), 1);
        let raw_selector = "selector-test-only";
        let canonical_input = input(json!({"selector": raw_selector}));
        let handle = write
            .consultation_commitment(
                &current,
                time(2_001),
                RelayConsultationCommitmentDomain::Subject,
                &canonical_input,
            )
            .expect("test hash");
        let diagnostics = format!("{write:?}{lookup:?}{canonical_input:?}{handle:?}");
        assert!(!diagnostics.contains(raw_selector));
        assert!(!diagnostics.contains(handle.value()));
    }

    #[test]
    fn test_only_env_preflight_rejects_ambiguous_sources_without_value_leaks() {
        const ACTIVE_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_SOURCE_ACTIVE_TEST";
        const RETAINED_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_SOURCE_RETAINED_TEST";
        const EXTRA_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_SOURCE_EXTRA_TEST";
        const MISSING_ENV: &str = "REGISTRY_AUDIT_PSEUDONYM_SOURCE_MISSING_TEST";
        const SECRET_MARKER: &str = "IDENTICAL_PSEUDONYM_SECRET_MUST_NOT_LEAK_0123456789abcdef";
        std::env::set_var(ACTIVE_ENV, SECRET_MARKER);
        std::env::set_var(RETAINED_ENV, SECRET_MARKER);
        std::env::set_var(EXTRA_ENV, "extra-secret-must-not-leak-0123456789abcdef");
        std::env::remove_var(MISSING_ENV);

        let current = metadata(
            2,
            "epoch-2",
            2_000,
            2_000,
            vec![retained("epoch-1", 1_000, 4_000)],
        );
        let active = AuditPseudonymKeySource::new(id("epoch-2"), ACTIVE_ENV).expect("active");
        let retained_source =
            AuditPseudonymKeySource::new(id("epoch-1"), RETAINED_ENV).expect("retained");
        let extra = AuditPseudonymKeySource::new(id("epoch-extra"), EXTRA_ENV).expect("extra");
        let missing_material_source =
            AuditPseudonymKeySource::new(id("epoch-2"), MISSING_ENV).expect("missing material");

        let missing =
            AuditPseudonymWriteKey::preflight_from_env(&current, time(2_000), [active.clone()])
                .expect_err("missing retained source");
        let extra_error = AuditPseudonymWriteKey::preflight_from_env(
            &current,
            time(2_000),
            [active.clone(), retained_source.clone(), extra],
        )
        .expect_err("extra source");
        let duplicate_id = AuditPseudonymWriteKey::preflight_from_env(
            &current,
            time(2_000),
            [active.clone(), active.clone(), retained_source.clone()],
        )
        .expect_err("duplicate key id");
        let duplicate_material = AuditPseudonymWriteKey::preflight_from_env(
            &current,
            time(2_000),
            [active, retained_source],
        )
        .expect_err("different env names resolve to identical key material");
        let missing_material = AuditPseudonymWriteKey::preflight_from_env(
            &current,
            time(2_000),
            [
                missing_material_source,
                AuditPseudonymKeySource::new(id("epoch-1"), RETAINED_ENV).expect("retained"),
            ],
        )
        .expect_err("declared source has no environment material");

        std::env::remove_var(ACTIVE_ENV);
        std::env::remove_var(RETAINED_ENV);
        std::env::remove_var(EXTRA_ENV);

        assert!(matches!(
            &missing,
            AuditPseudonymKeyringError::MetadataSourceMismatch
        ));
        assert!(matches!(
            &extra_error,
            AuditPseudonymKeyringError::MetadataSourceMismatch
        ));
        assert!(matches!(
            &duplicate_id,
            AuditPseudonymKeyringError::DuplicateKeyId
        ));
        assert!(matches!(
            &duplicate_material,
            AuditPseudonymKeyringError::DuplicateKeyMaterial
        ));
        assert!(matches!(
            &missing_material,
            AuditPseudonymKeyringError::Audit(AuditError::EnvVarUnavailable { .. })
        ));
        for error in [
            missing,
            extra_error,
            duplicate_id,
            duplicate_material,
            missing_material,
        ] {
            let diagnostics = format!("{error:?} {error}");
            assert!(!diagnostics.contains(SECRET_MARKER));
            assert!(!diagnostics.contains("extra-secret-must-not-leak"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_only_keyring_error_redacts_non_unicode_secret_value() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        const ENV_NAME: &str = "REGISTRY_AUDIT_PSEUDONYM_NON_UNICODE_TEST";
        const MARKER: &str = "PSEUDONYM_SECRET_MUST_NOT_LEAK";
        let mut secret = vec![0xff];
        secret.extend_from_slice(MARKER.as_bytes());
        std::env::set_var(ENV_NAME, OsString::from_vec(secret));

        let current = metadata(1, "epoch-1", 1_000, 2_000, vec![]);
        let source = AuditPseudonymKeySource::new(id("epoch-1"), ENV_NAME).expect("source");
        let error = AuditPseudonymWriteKey::preflight_from_env(&current, time(1_000), [source])
            .expect_err("non-Unicode secret is rejected");
        std::env::remove_var(ENV_NAME);

        assert!(matches!(
            &error,
            AuditPseudonymKeyringError::Audit(AuditError::EnvVarNotUnicode { .. })
        ));
        assert!(!format!("{error:?}").contains(MARKER));
        assert!(!error.to_string().contains(MARKER));
        let source = std::error::Error::source(&error).expect("redacted audit error source");
        assert!(!format!("{source:?}").contains(MARKER));
        assert!(!source.to_string().contains(MARKER));
        assert!(std::error::Error::source(source).is_none());
    }
}
