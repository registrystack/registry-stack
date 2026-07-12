// SPDX-License-Identifier: Apache-2.0
//! Strict, hash-covered consultation source-plan artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::destination::input_pattern::{
    MAX_BOUNDED_INPUT_BYTES as MAX_INPUT_BYTES,
    MAX_BOUNDED_INPUT_PATTERN_BYTES as MAX_PATTERN_BYTES,
};
use registry_platform_httputil::destination::validate_fixed_destination_path;
use reqwest::Url;
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::consultation::{
    AcquiredField, AcquisitionClass, AssertionContractHash, AssertionContractId,
    AssertionContractIdentity, IntegrationPackHash, IntegrationPackId, IntegrationPackIdentity,
    OperationBounds, OperationId, PolicyHash, PolicyId, PolicyIdentity, ProfileContractHash,
    ProfileId, ProfileIdentity, ProfileVersion, RegistryInstanceId, RequiredConsultationScope,
    SelectorProvenance, TenantId, WorkloadId,
};

use super::identifiers::{
    CanonicalPurpose, CredentialReferenceId, LegalBasisId, SourceDestinationId,
};

pub(super) const CONTRACT_SCHEMA: &str = "registry.relay.consultation-contract.v1";
pub(super) const PACK_SCHEMA: &str = "registry.relay.integration-pack.v1";

const CONTRACT_HASH_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
const PACK_HASH_DOMAIN: &[u8] = b"registry.relay.integration-pack.v1\0";
const BINDING_HASH_DOMAIN: &[u8] = b"registry.relay.consultation-binding.v1\0";
const REQUEST_TEMPLATE_HASH_DOMAIN: &[u8] = b"registry.relay.request-template.v1\0";

const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
const MAX_STABLE_TEXT_BYTES: usize = 512;
const MAX_PURPOSE_BYTES: usize = 256;
const MAX_DATA_RESPONSE_BYTES: u32 = 256 * 1024;
const MAX_PUBLIC_RESPONSE_BYTES: u32 = 64 * 1024;
const MAX_IN_FLIGHT: u16 = 16;
const MAX_QUOTA_PER_MINUTE: u32 = 60;
const MAX_QUOTA_BURST: u16 = 10;
pub(super) const MAX_PATH_BYTES: usize = 2_048;
const MAX_POINTER_BYTES: usize = 512;
const MAX_STATIC_COMPONENTS: usize = 32;
pub(super) const MAX_ARTIFACTS_PER_BUNDLE: usize = 256;
const MAX_ACQUIRED_FIELDS: usize = 64;
const MAX_PURPOSES: usize = 32;
const MAX_SUPPORTED_VERSIONS: usize = 32;
pub(super) const MAX_EVIDENCE_FILES_PER_CLASS: usize = 32;
const MAX_DEPLOYMENT_PARAMETERS: usize = 32;
const MAX_BODY_TEMPLATE_NODES: usize = 128;
const MAX_BODY_TEMPLATE_DEPTH: usize = 8;
const MAX_BODY_LITERAL_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_SCHEMA_DEPTH: usize = 8;
const MAX_RESPONSE_SCHEMA_NODES: usize = 256;
const MAX_RESPONSE_SCHEMA_EXPANDED_NODES: usize = 4_096;
const MAX_RESPONSE_ARRAY_ITEMS: u16 = 256;
const MAX_REQUEST_BYTES: u32 = 1024 * 1024;
const MAX_REQUEST_TARGET_BYTES: usize = 4_096;
const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;
const MAX_REQUEST_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_PARAMETER_VALUES: usize = 32;
const MAX_SNAPSHOT_AGE_MS: u64 = 31 * 24 * 60 * 60 * 1_000;
const MAX_RHAI_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RHAI_CPU_MS: u32 = 1_000;
const MAX_RHAI_IPC_FRAME_BYTES: u32 = 256 * 1024;
const MAX_RHAI_INSTRUCTIONS: u64 = 100_000;
const MAX_RHAI_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_RHAI_CALL_DEPTH: u8 = 16;
const MAX_RHAI_STRING_BYTES: u32 = 64 * 1024;
const MAX_RHAI_COLLECTION_ITEMS: u32 = 1_024;
const MAX_RHAI_OUTPUT_BYTES: u32 = 64 * 1024;
const MAX_CONSENT_AGE_MS: u32 = 24 * 60 * 60 * 1_000;
const MAX_JSON_INTEROPERABLE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_OAUTH_TOKEN_LIFETIME_MS: u32 = 24 * 60 * 60 * 1_000;
const MAX_OAUTH_CLIENT_ID_BYTES: u16 = 4 * 1024;
const MAX_OAUTH_CLIENT_SECRET_BYTES: u16 = 4 * 1024;
const MAX_OAUTH_ACCESS_TOKEN_BYTES: u16 = 8 * 1024 - 7;
pub(super) const MAX_EVIDENCE_FILE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_EVIDENCE_CLASS_BYTES: usize = 4 * 1024 * 1024;

/// A safe reason that a hash-covered source-plan artifact was rejected.
///
/// Variants deliberately omit raw artifact values. In particular, private
/// binding values must never be copied into an error, log, or readiness report.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourcePlanArtifactError {
    /// The raw artifact exceeded its pre-parse allocation ceiling.
    #[error("source-plan artifact exceeds the raw input ceiling")]
    InputTooLarge,
    /// JSON/YAML was malformed, ambiguous, duplicated, or not exactly representable.
    #[error("source-plan artifact is not strict JSON or strict YAML")]
    StrictJson,
    /// The JSON does not match the closed artifact type.
    #[error("source-plan artifact does not match its closed schema")]
    ClosedSchema,
    /// The schema discriminator is missing or from another protocol version.
    #[error("source-plan artifact has an unsupported schema")]
    UnsupportedSchema,
    /// A stable identifier, version, or hash is invalid.
    #[error("source-plan artifact contains an invalid identity")]
    InvalidIdentity,
    /// A bounded string or fixed path is invalid.
    #[error("source-plan artifact contains invalid bounded text")]
    InvalidText,
    /// A set-like field is empty, duplicated, or exceeds its ceiling.
    #[error("source-plan artifact contains an invalid closed set")]
    InvalidSet,
    /// Numeric limits are zero, inconsistent, or exceed v1 ceilings.
    #[error("source-plan artifact contains invalid limits")]
    InvalidLimits,
    /// Acquisition, cardinality, or output semantics are internally inconsistent.
    #[error("source-plan artifact has inconsistent acquisition semantics")]
    InvalidAcquisition,
    /// A template contains an unsupported or internally inconsistent plan shape.
    #[error("source-plan artifact has an invalid plan template")]
    InvalidPlan,
    /// A request expression refers outside the pack's closed inputs or parameters.
    #[error("source-plan artifact contains an invalid request expression")]
    InvalidExpression,
    /// The private binding contains an invalid destination policy.
    #[error("source-plan binding contains an invalid destination")]
    InvalidDestination,
    /// Canonical typed JSON could not be produced.
    #[error("source-plan artifact could not be canonicalized")]
    Canonicalization,
    /// A committed hash does not match the typed artifact.
    #[error("source-plan artifact hash does not match its committed digest")]
    HashMismatch,
    /// The authored policy hash does not match the policy derived from the contract.
    #[error("consultation policy hash does not match its derived digest")]
    PolicyHashMismatch,
}

pub(super) struct ValidatedAuthorization {
    pub(super) workload_id: WorkloadId,
    pub(super) required_scope: RequiredConsultationScope,
    pub(super) policy_identity: PolicyIdentity,
    pub(super) consent_verifier: Option<(OperationId, IntegrationPackHash)>,
    pub(super) purposes: Box<[CanonicalPurpose]>,
    pub(super) legal_basis: LegalBasisId,
}

/// A closed source-plan template kind accepted by consultation v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePlanKind {
    /// An exact lookup over an immutable, separately materialized snapshot.
    SnapshotExact,
    /// A fixed sequence of bounded HTTP operations.
    BoundedHttp,
    /// A pinned script orchestrating only the pack's bounded operations.
    SandboxedRhai,
}

/// The closed cardinality contract for one subject lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCardinality {
    /// The source contract returns at most one record.
    Singleton,
    /// Relay may acquire two rows only to prove ambiguity.
    AmbiguityProbe,
}

impl SourceCardinality {
    pub(super) const fn max_source_matches(self) -> u8 {
        match self {
            Self::Singleton => 1,
            Self::AmbiguityProbe => 2,
        }
    }
}

/// A read-only method accepted by a reviewed HTTP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadMethod {
    /// A read-only GET operation.
    Get,
    /// A product operation independently reviewed as a read-only POST.
    ReadOnlyPost,
}

/// Validated public and runtime limits for one compiled plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePlanLimits {
    operation: OperationBounds,
    max_in_flight: u16,
    quota_per_minute: u32,
    quota_burst: u16,
    max_public_response_bytes: u32,
}

impl SourcePlanLimits {
    /// Return the closed acquisition and transport footprint.
    #[must_use]
    pub const fn operation(&self) -> OperationBounds {
        self.operation
    }

    /// Return the maximum concurrently executing consultations.
    #[must_use]
    pub const fn max_in_flight(&self) -> u16 {
        self.max_in_flight
    }

    /// Return the maximum consultations admitted per minute.
    #[must_use]
    pub const fn quota_per_minute(&self) -> u32 {
        self.quota_per_minute
    }

    /// Return the token-bucket burst ceiling.
    #[must_use]
    pub const fn quota_burst(&self) -> u16 {
        self.quota_burst
    }

    /// Return the maximum serialized public response bytes.
    #[must_use]
    pub const fn max_public_response_bytes(&self) -> u32 {
        self.max_public_response_bytes
    }

    pub(super) fn from_documents(
        document: LimitsDocument,
        refinement: Option<BindingLimitsDocument>,
    ) -> Result<Self, SourcePlanArtifactError> {
        let refinement = refinement.unwrap_or_default();
        let max_source_bytes = refinement
            .max_source_bytes
            .unwrap_or(document.max_source_bytes);
        let timeout_ms = refinement.timeout_ms.unwrap_or(document.timeout_ms);
        let max_in_flight = refinement.max_in_flight.unwrap_or(document.max_in_flight);
        let quota_per_minute = refinement
            .quota_per_minute
            .unwrap_or(document.quota_per_minute);
        let quota_burst = refinement.quota_burst.unwrap_or(document.quota_burst);
        let max_public_response_bytes = refinement
            .max_public_response_bytes
            .unwrap_or(MAX_PUBLIC_RESPONSE_BYTES);
        if max_source_bytes == 0
            || max_source_bytes > document.max_source_bytes
            || timeout_ms == 0
            || timeout_ms > document.timeout_ms
            || max_in_flight == 0
            || max_in_flight > document.max_in_flight
            || quota_per_minute == 0
            || quota_per_minute > document.quota_per_minute
            || quota_burst == 0
            || quota_burst > document.quota_burst
            || u32::from(quota_burst) > quota_per_minute
            || max_public_response_bytes == 0
            || max_public_response_bytes > MAX_PUBLIC_RESPONSE_BYTES
            || refinement.max_token_lifetime_ms == Some(0)
        {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        Ok(Self {
            operation: OperationBounds {
                max_source_matches: document.max_source_matches,
                max_disclosed_records: document.max_disclosed_records,
                max_data_exchanges: document.max_data_exchanges,
                max_credential_exchanges: document.max_credential_exchanges,
                max_data_destinations: document.max_data_destinations,
                max_source_bytes,
                timeout_ms,
            },
            max_in_flight,
            quota_per_minute,
            quota_burst,
            max_public_response_bytes,
        })
    }

    pub(super) const fn from_document(document: LimitsDocument) -> Self {
        Self {
            operation: OperationBounds {
                max_source_matches: document.max_source_matches,
                max_disclosed_records: document.max_disclosed_records,
                max_data_exchanges: document.max_data_exchanges,
                max_credential_exchanges: document.max_credential_exchanges,
                max_data_destinations: document.max_data_destinations,
                max_source_bytes: document.max_source_bytes,
                timeout_ms: document.timeout_ms,
            },
            max_in_flight: document.max_in_flight,
            quota_per_minute: document.quota_per_minute,
            quota_burst: document.quota_burst,
            max_public_response_bytes: MAX_PUBLIC_RESPONSE_BYTES,
        }
    }

    pub(super) fn with_max_data_exchanges(
        mut self,
        max_data_exchanges: u8,
    ) -> Result<Self, SourcePlanArtifactError> {
        if max_data_exchanges == 0 || max_data_exchanges > self.operation.max_data_exchanges {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        self.operation.max_data_exchanges = max_data_exchanges;
        Ok(self)
    }
}

/// Hash of one typed private binding with secret values excluded by schema.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrivateBindingHash(Box<str>);

impl PrivateBindingHash {
    /// Return the canonical lowercase `sha256:` digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn from_digest(value: String) -> Self {
        Self(value.into_boxed_str())
    }
}

impl fmt::Debug for PrivateBindingHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateBindingHash")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for PrivateBindingHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

mod document;
pub use document::EvidenceClass;
pub(super) use document::*;

mod parsing;
use parsing::hash_document;
pub(super) use parsing::{
    parse_integration_pack, parse_private_binding, parse_public_contract, sha256_label,
};

mod policy;
pub(super) use policy::derive_consultation_policy;

mod validation;
#[cfg(test)]
pub(super) use validation::validate_response_schema;
pub(super) use validation::{decode_pointer_tokens, response_record_schema};

mod bounds;
pub(super) use bounds::*;

mod pattern;
use pattern::{
    is_sensitive_name, validate_bounded_text, validate_input_pattern, validate_query_name,
    validate_stable_text, validate_token,
};
pub(super) use pattern::{parse_input_pattern, BoundedInputPattern};
