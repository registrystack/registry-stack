// SPDX-License-Identifier: Apache-2.0
//! Registry Witness request, response, and view types.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const FORMAT_CLAIM_RESULT_JSON: &str = "application/vnd.registry-witness.claim-result+json";
pub const FORMAT_CCCEV_JSONLD: &str = "application/ld+json; profile=\"cccev\"";
pub const FORMAT_SD_JWT_VC: &str = "application/dc+sd-jwt";
pub const SD_JWT_VC_JWT_TYP: &str = "dc+sd-jwt";
pub const SD_JWT_VC_SIGNING_ALG: &str = "EdDSA";
pub const SD_JWT_VC_ISSUER_KEY_TYPE: &str = "OKP/Ed25519";
pub const SD_JWT_VC_HOLDER_BINDING_METHOD: &str = "did:jwk";

pub const MAX_BOUNDED_CLAIM_ID_LEN: usize = 128;
pub const MAX_CONFIG_METADATA_LEN: usize = 256;
pub const MAX_CORRELATION_ID_LEN: usize = 128;
pub const MAX_POLICY_ID_LEN: usize = 128;
pub const MAX_RATE_LIMIT_BUCKET_LEN: usize = 128;
pub const MAX_TOKEN_CLAIM_VALUE_LEN: usize = 512;
pub const MAX_VERIFIED_CLAIM_NAME_LEN: usize = 256;
pub const MAX_VERIFIED_CLAIM_VALUE_LEN: usize = 512;

pub type BoundedClaimId = Bounded<MAX_BOUNDED_CLAIM_ID_LEN>;
pub type BoundedCorrelationId = Bounded<MAX_CORRELATION_ID_LEN>;
pub type BoundedPolicyId = Bounded<MAX_POLICY_ID_LEN>;
pub type ConfigMetadata = Bounded<MAX_CONFIG_METADATA_LEN>;
pub type RateLimitBucket = Bounded<MAX_RATE_LIMIT_BUCKET_LEN>;
pub type VerifiedClaimName = Bounded<MAX_VERIFIED_CLAIM_NAME_LEN>;
pub type VerifiedClaimValue = Bounded<MAX_VERIFIED_CLAIM_VALUE_LEN>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Unknown,
    #[default]
    MachineClient,
    SelfAttestation,
}

impl AccessMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::MachineClient => "machine_client",
            Self::SelfAttestation => "self_attestation",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "machine_client" => Some(Self::MachineClient),
            "self_attestation" => Some(Self::SelfAttestation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfAttestationDenialCode {
    Disabled,
    OperationDenied,
    ClaimDenied,
    DisclosureDenied,
    FormatDenied,
    ProfileDenied,
    SubjectClaimMissing,
    SubjectMismatch,
    RateLimited,
    InvalidToken,
    AssuranceDenied,
    BatchDenied,
}

impl SelfAttestationDenialCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "self_attestation.disabled",
            Self::OperationDenied => "self_attestation.operation_denied",
            Self::ClaimDenied => "self_attestation.claim_denied",
            Self::DisclosureDenied => "self_attestation.disclosure_denied",
            Self::FormatDenied => "self_attestation.format_denied",
            Self::ProfileDenied => "self_attestation.profile_denied",
            Self::SubjectClaimMissing => "self_attestation.subject_claim_missing",
            Self::SubjectMismatch => "self_attestation.subject_mismatch",
            Self::RateLimited => "self_attestation.rate_limited",
            Self::InvalidToken => "self_attestation.invalid_token",
            Self::AssuranceDenied => "self_attestation.assurance_denied",
            Self::BatchDenied => "self_attestation.batch_denied",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "self_attestation.disabled" => Some(Self::Disabled),
            "self_attestation.operation_denied" => Some(Self::OperationDenied),
            "self_attestation.claim_denied" => Some(Self::ClaimDenied),
            "self_attestation.disclosure_denied" => Some(Self::DisclosureDenied),
            "self_attestation.format_denied" => Some(Self::FormatDenied),
            "self_attestation.profile_denied" => Some(Self::ProfileDenied),
            "self_attestation.subject_claim_missing" => Some(Self::SubjectClaimMissing),
            "self_attestation.subject_mismatch" => Some(Self::SubjectMismatch),
            "self_attestation.rate_limited" => Some(Self::RateLimited),
            "self_attestation.invalid_token" => Some(Self::InvalidToken),
            "self_attestation.assurance_denied" => Some(Self::AssuranceDenied),
            "self_attestation.batch_denied" => Some(Self::BatchDenied),
            _ => None,
        }
    }
}

impl Serialize for SelfAttestationDenialCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SelfAttestationDenialCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| de::Error::custom("unknown self-attestation denial code"))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bounded<const N: usize>(String);

impl<const N: usize> Bounded<N> {
    pub fn new(value: impl Into<String>) -> Result<Self, BoundedStringError> {
        let value = value.into();
        if value.len() > N {
            return Err(BoundedStringError {
                max: N,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const N: usize> fmt::Debug for Bounded<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Bounded").field(&self.0).finish()
    }
}

impl<const N: usize> TryFrom<String> for Bounded<N> {
    type Error = BoundedStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const N: usize> TryFrom<&str> for Bounded<N> {
    type Error = BoundedStringError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const N: usize> Serialize for Bounded<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Bounded<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedStringError {
    pub max: usize,
    pub actual: usize,
}

impl fmt::Display for BoundedStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bounded string length {} exceeds maximum {}",
            self.actual, self.max
        )
    }
}

impl std::error::Error for BoundedStringError {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hashed<T> {
    value: String,
    _marker: PhantomData<T>,
}

impl<T> Hashed<T> {
    #[must_use]
    pub fn from_hash(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            _marker: PhantomData,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.value
    }
}

impl<T> fmt::Debug for Hashed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hashed").field(&self.value).finish()
    }
}

impl<T> Serialize for Hashed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.value)
    }
}

impl<'de, T> Deserialize<'de> for Hashed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashedVisitor<T>(PhantomData<T>);

        impl<T> Visitor<'_> for HashedVisitor<T> {
            type Value = Hashed<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a hashed identifier string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Hashed::from_hash(value))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Hashed::from_hash(value))
            }
        }

        deserializer.deserialize_string(HashedVisitor(PhantomData))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectBinding {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSet {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyIdentifier {}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedVerifiedClaims {
    pub issuer: VerifiedClaimValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_binding_claim: Option<VerifiedClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_binding_value: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
}

impl fmt::Debug for BoundedVerifiedClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedVerifiedClaims")
            .field("issuer", &self.issuer)
            .field("audiences", &self.audiences)
            .field("client_id", &self.client_id)
            .field("token_type", &self.token_type)
            .field("scopes", &self.scopes)
            .field("subject", &self.subject.as_ref().map(|_| "<redacted>"))
            .field("subject_binding_claim", &self.subject_binding_claim)
            .field(
                "subject_binding_value",
                &self.subject_binding_value.as_ref().map(|_| "<redacted>"),
            )
            .field("acr", &self.acr)
            .field("auth_time", &self.auth_time)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("nbf", &self.nbf)
            .finish()
    }
}

impl BoundedVerifiedClaims {
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|candidate| candidate.as_str() == scope)
    }

    #[must_use]
    pub fn claim_value(&self, claim_name: &str) -> Option<&str> {
        match claim_name {
            "iss" => Some(self.issuer.as_str()),
            "sub" => self.subject.as_ref().map(Bounded::as_str),
            "typ" | "token_type" => self.token_type.as_ref().map(Bounded::as_str),
            "client_id" | "azp" => self.client_id.as_ref().map(Bounded::as_str),
            "acr" => self.acr.as_ref().map(Bounded::as_str),
            other => self
                .subject_binding_claim
                .as_ref()
                .filter(|configured| configured.as_str() == other)
                .and(self.subject_binding_value.as_ref())
                .map(Bounded::as_str),
        }
    }

    #[must_use]
    pub fn subject_binding_value(&self, claim_name: &str) -> Option<&str> {
        self.subject_binding_claim
            .as_ref()
            .filter(|configured| configured.as_str() == claim_name)
            .and(self.subject_binding_value.as_ref())
            .map(Bounded::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SourceCapability {
    Machine {
        #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
        scopes: BTreeSet<String>,
    },
    SelfAttestation {
        claim_id: BoundedClaimId,
        subject_binding_hash: Hashed<SubjectBinding>,
    },
}

impl SourceCapability {
    #[must_use]
    pub fn access_mode(&self) -> AccessMode {
        match self {
            Self::Machine { .. } => AccessMode::MachineClient,
            Self::SelfAttestation { .. } => AccessMode::SelfAttestation,
        }
    }

    #[must_use]
    pub fn allows_scope(&self, scope: &str) -> bool {
        match self {
            Self::Machine { scopes } => scopes.contains(scope),
            Self::SelfAttestation { .. } => false,
        }
    }

    #[must_use]
    pub fn allows_self_attestation_claim(&self, claim_id: &str) -> bool {
        match self {
            Self::Machine { .. } => false,
            Self::SelfAttestation {
                claim_id: allowed, ..
            } => allowed.as_str() == claim_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureProfile {
    Value,
    Predicate,
    Redacted,
}

impl DisclosureProfile {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "value" => Some(Self::Value),
            "predicate" => Some(Self::Predicate),
            "redacted" => Some(Self::Redacted),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Predicate => "predicate",
            Self::Redacted => "redacted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDowngrade {
    Deny,
    Default,
    Redacted,
}

impl DisclosureDowngrade {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "deny" | "none" => Some(Self::Deny),
            "default" => Some(Self::Default),
            "redacted" => Some(Self::Redacted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    pub subject: SubjectRequest,
    pub claims: Vec<String>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectRequest {
    pub id: String,
    #[serde(default)]
    pub id_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchEvaluateRequest {
    pub subjects: Vec<SubjectRequest>,
    pub claims: Vec<String>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchEvaluateResponse {
    pub batch_id: String,
    pub status: BatchStatus,
    pub claims: Vec<String>,
    pub items: Vec<BatchItemResponse>,
    pub summary: BatchSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Completed,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchSummary {
    pub succeeded: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchItemResponse {
    pub input_index: usize,
    pub subject_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_id: Option<String>,
    pub status: BatchItemStatus,
    pub claim_results: Vec<BatchClaimResultView>,
    pub errors: Vec<BatchItemError>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchItemStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchClaimResultView {
    pub result_id: String,
    pub claim_id: String,
    pub claim_version: String,
    pub value_type: String,
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satisfied: Option<bool>,
    pub disclosure: String,
    pub provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchItemError {
    pub code: String,
    pub title: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RenderRequest {
    pub evaluation_id: String,
    pub format: String,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub claims: Option<Vec<String>>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialIssueRequest {
    pub evaluation_id: String,
    #[serde(default)]
    pub credential_profile: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub claims: Option<Vec<String>>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub holder: Option<HolderRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HolderRequest {
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFormat {
    pub id: String,
    pub kind: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResultView {
    pub evaluation_id: String,
    pub claim_id: String,
    pub claim_version: String,
    pub subject_type: String,
    pub subject_ref: String,
    pub value: Option<Value>,
    pub satisfied: Option<bool>,
    pub disclosure: String,
    pub format: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProvenance {
    pub source_count: usize,
    pub source_versions: BTreeMap<String, String>,
    pub computed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvaluation {
    pub client_id: String,
    pub purpose: String,
    pub claim_ids: Vec<String>,
    pub disclosure: String,
    pub format: String,
    pub results: Vec<ClaimResultView>,
    pub created_at: String,
    pub expires_at: String,
    pub request_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_attestation: Option<StoredSelfAttestationMetadata>,
}

impl StoredEvaluation {
    #[must_use]
    pub fn access_mode(&self) -> AccessMode {
        self.self_attestation
            .as_ref()
            .map(|metadata| metadata.access_mode)
            .unwrap_or(AccessMode::MachineClient)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSelfAttestationMetadata {
    #[serde(default = "self_attestation_access_mode")]
    pub access_mode: AccessMode,
    pub issuer: VerifiedClaimValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<VerifiedClaimValue>,
    pub principal_hash: Hashed<PrincipalIdentifier>,
    pub subject_id_type: ConfigMetadata,
    pub subject_binding_claim: ConfigMetadata,
    pub subject_binding_hash: Hashed<SubjectBinding>,
    pub requested_claims_hash: Hashed<ClaimSet>,
    pub disclosure: ConfigMetadata,
    pub result_format: ConfigMetadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<Hashed<PrincipalIdentifier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<BoundedPolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<Hashed<PolicyIdentifier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_expires_at: Option<String>,
}

const fn self_attestation_access_mode() -> AccessMode {
    AccessMode::SelfAttestation
}

#[derive(Debug, Clone)]
pub struct EvidencePrincipal {
    pub principal_id: String,
    pub scopes: Vec<String>,
    pub access_mode: AccessMode,
    pub verified_claims: Option<BoundedVerifiedClaims>,
}

impl EvidencePrincipal {
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|candidate| candidate == scope)
    }

    #[must_use]
    pub fn has_any_scope<'a>(&self, scopes: impl IntoIterator<Item = &'a str>) -> bool {
        scopes.into_iter().any(|scope| self.has_scope(scope))
    }

    #[must_use]
    pub const fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    #[must_use]
    pub const fn is_self_attestation(&self) -> bool {
        matches!(self.access_mode, AccessMode::SelfAttestation)
    }

    #[must_use]
    pub fn verified_claim(&self, claim_name: &str) -> Option<&str> {
        self.verified_claims
            .as_ref()
            .and_then(|claims| claims.claim_value(claim_name))
    }

    #[must_use]
    pub fn verified_subject_binding_value(&self, claim_name: &str) -> Option<&str> {
        self.verified_claims
            .as_ref()
            .and_then(|claims| claims.subject_binding_value(claim_name))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceAuditEvent {
    pub event_id: String,
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id_hash: Option<Hashed<PrincipalIdentifier>>,
    pub decision: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub verification_id: Option<String>,
    pub claim_hash: Option<String>,
    pub row_count: Option<u64>,
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<AccessMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_code: Option<SelfAttestationDenialCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_claim_name: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<BoundedCorrelationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_profile: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_binding_mode: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_bucket: Option<RateLimitBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<BoundedPolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<Hashed<PolicyIdentifier>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bounded<const N: usize>(value: &str) -> Bounded<N> {
        Bounded::new(value).expect("test value is bounded")
    }

    #[test]
    fn access_mode_serializes_as_stable_snake_case() {
        assert_eq!(
            serde_json::to_value(AccessMode::SelfAttestation).expect("access mode serializes"),
            json!("self_attestation")
        );
        assert_eq!(
            AccessMode::parse("machine_client"),
            Some(AccessMode::MachineClient)
        );
    }

    #[test]
    fn bounded_rejects_values_over_limit() {
        let err = Bounded::<4>::new("12345").expect_err("value exceeds limit");
        assert_eq!(err.max, 4);
        assert_eq!(err.actual, 5);
    }

    #[test]
    fn verified_claim_lookup_exposes_only_bounded_allow_listed_claims() {
        let claims = BoundedVerifiedClaims {
            issuer: bounded("https://id.example.gov"),
            audiences: vec![bounded("registry-witness-citizen")],
            client_id: Some(bounded("citizen-portal")),
            token_type: Some(bounded("JWT")),
            scopes: vec![bounded("self_attestation")],
            subject: Some(bounded("login-subject")),
            subject_binding_claim: Some(bounded("https://id.example.gov/claims/national_id")),
            subject_binding_value: Some(bounded("NAT-123")),
            acr: Some(bounded("urn:example:loa:substantial")),
            auth_time: Some(1_800_000_000),
            exp: Some(1_800_000_900),
            iat: Some(1_800_000_000),
            nbf: None,
        };

        assert!(claims.has_scope("self_attestation"));
        assert_eq!(claims.claim_value("sub"), Some("login-subject"));
        assert_eq!(claims.claim_value("email"), None);
        assert_eq!(
            claims.subject_binding_value("https://id.example.gov/claims/national_id"),
            Some("NAT-123")
        );
    }

    #[test]
    fn source_capability_separates_machine_scopes_from_self_attestation_claims() {
        let machine = SourceCapability::Machine {
            scopes: BTreeSet::from(["civil_registry:evidence_verification".to_string()]),
        };
        assert_eq!(machine.access_mode(), AccessMode::MachineClient);
        assert!(machine.allows_scope("civil_registry:evidence_verification"));
        assert!(!machine.allows_self_attestation_claim("person-is-alive"));

        let citizen = SourceCapability::SelfAttestation {
            claim_id: bounded("person-is-alive"),
            subject_binding_hash: Hashed::from_hash("sha256:test"),
        };
        assert_eq!(citizen.access_mode(), AccessMode::SelfAttestation);
        assert!(!citizen.allows_scope("civil_registry:evidence_verification"));
        assert!(citizen.allows_self_attestation_claim("person-is-alive"));
    }

    #[test]
    fn audit_self_attestation_fields_are_serializable_without_raw_values() {
        let event = EvidenceAuditEvent {
            event_id: "01HX".to_string(),
            occurred_at: "2026-05-25T00:00:00Z".to_string(),
            principal_id_hash: Some(Hashed::from_hash("hmac-sha256:principal")),
            decision: "denied".to_string(),
            method: "POST".to_string(),
            path: "/claims/evaluate".to_string(),
            status: 403,
            verification_id: None,
            claim_hash: Some("sha256:claims".to_string()),
            row_count: None,
            error_code: Some("self_attestation.denied".to_string()),
            access_mode: Some(AccessMode::SelfAttestation),
            denial_code: Some(SelfAttestationDenialCode::SubjectMismatch),
            token_claim_name: Some(bounded("national_id")),
            correlation_id: Some(bounded("req-123")),
            credential_profile: None,
            protocol: Some(bounded("openid4vci")),
            credential_configuration_id: Some(bounded("person_is_alive_sd_jwt")),
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_version: Some(bounded("citizen-v1")),
            policy_hash: Some(Hashed::from_hash("sha256:policy")),
        };

        let value = serde_json::to_value(event).expect("audit event serializes");
        assert_eq!(value["access_mode"], json!("self_attestation"));
        assert_eq!(
            value["denial_code"],
            json!("self_attestation.subject_mismatch")
        );
        assert_eq!(value["token_claim_name"], json!("national_id"));
        assert_eq!(value["correlation_id"], json!("req-123"));
        assert_eq!(value["protocol"], json!("openid4vci"));
        assert_eq!(
            value["credential_configuration_id"],
            json!("person_is_alive_sd_jwt")
        );
        assert_eq!(value["principal_id_hash"], json!("hmac-sha256:principal"));
        assert!(value.get("principal_id").is_none());
        assert!(value.get("subject_binding_value").is_none());
    }

    #[test]
    fn stored_evaluation_without_self_attestation_defaults_to_machine_client() {
        let raw = json!({
            "client_id": "client",
            "purpose": "verification",
            "claim_ids": ["person-is-alive"],
            "disclosure": "predicate",
            "format": FORMAT_CLAIM_RESULT_JSON,
            "results": [],
            "created_at": "2026-05-25T00:00:00Z",
            "expires_at": "2026-05-25T00:15:00Z",
            "request_hash": "sha256:request"
        });
        let stored: StoredEvaluation =
            serde_json::from_value(raw).expect("legacy stored evaluation deserializes");
        assert_eq!(stored.access_mode(), AccessMode::MachineClient);
        assert!(stored.self_attestation.is_none());
    }
}
