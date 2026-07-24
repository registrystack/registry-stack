// SPDX-License-Identifier: Apache-2.0
//! Registry Notary request, response, and view types.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const FORMAT_CLAIM_RESULT_JSON: &str = "application/vnd.registry-notary.claim-result+json";
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
pub const MAX_REQUEST_VARIABLES_V1: usize = 16;
pub const MAX_REQUEST_VARIABLE_NAME_BYTES_V1: usize = 96;

pub type BoundedClaimId = Bounded<MAX_BOUNDED_CLAIM_ID_LEN>;
pub type BoundedCorrelationId = Bounded<MAX_CORRELATION_ID_LEN>;
pub type BoundedPolicyId = Bounded<MAX_POLICY_ID_LEN>;
pub type ConfigMetadata = Bounded<MAX_CONFIG_METADATA_LEN>;
pub type RateLimitBucket = Bounded<MAX_RATE_LIMIT_BUCKET_LEN>;
pub type VerifiedClaimName = Bounded<MAX_VERIFIED_CLAIM_NAME_LEN>;
pub type VerifiedClaimValue = Bounded<MAX_VERIFIED_CLAIM_VALUE_LEN>;

/// Closed v1 request variables. The first contract admits only named RFC 3339
/// full-date strings, with service configuration deciding which names exist.
#[derive(Clone, Default, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct RequestVariables(BTreeMap<String, String>);

impl fmt::Debug for RequestVariables {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestVariables([REDACTED])")
    }
}

impl RequestVariables {
    pub fn try_new(values: BTreeMap<String, String>) -> Result<Self, &'static str> {
        if values.len() > MAX_REQUEST_VARIABLES_V1
            || values.iter().any(|(name, value)| {
                !is_request_variable_name(name) || !is_rfc3339_full_date(value)
            })
        {
            return Err("request variables must be bounded named RFC 3339 full-date strings");
        }
        Ok(Self(values))
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for RequestVariables {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<String, String>::deserialize(deserializer)?;
        Self::try_new(values).map_err(de::Error::custom)
    }
}

#[must_use]
pub fn is_request_variable_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= MAX_REQUEST_VARIABLE_NAME_BYTES_V1
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

#[must_use]
pub fn is_rfc3339_full_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u16>().ok();
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let Ok(month) = time::Month::try_from(u8::try_from(month).unwrap_or(0)) else {
        return false;
    };
    time::Date::from_calendar_date(i32::from(year), month, u8::try_from(day).unwrap_or(0)).is_ok()
}

/// The authentication trust profile that produced an [`EvidencePrincipal`].
///
/// These identifiers are deliberately closed and credential-independent so
/// they can safely participate in caller binding without incorporating raw
/// API keys, bearer tokens, or attacker-controlled token claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthProfileId {
    StaticApiKey,
    StaticBearer,
    ExternalOidc,
    NotaryAccessToken,
    Federation,
}

impl EvidenceAuthProfileId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticApiKey => "static_api_key",
            Self::StaticBearer => "static_bearer",
            Self::ExternalOidc => "external_oidc",
            Self::NotaryAccessToken => "notary_access_token",
            Self::Federation => "federation",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Unknown,
    #[default]
    MachineClient,
    SubjectBound,
    DelegatedAttestation,
}

impl AccessMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::MachineClient => "machine_client",
            Self::SubjectBound => "subject_bound",
            Self::DelegatedAttestation => "delegated_attestation",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "machine_client" => Some(Self::MachineClient),
            "subject_bound" => Some(Self::SubjectBound),
            "delegated_attestation" => Some(Self::DelegatedAttestation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectAccessDenialCode {
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
    DelegatedRelationshipUnproven,
    DelegatedRelationshipNotAllowed,
    DelegatedClaimDenied,
    DelegatedSubjectNotPermitted,
    DelegatedProofDenied,
}

impl SubjectAccessDenialCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "subject_access.disabled",
            Self::OperationDenied => "subject_access.operation_denied",
            Self::ClaimDenied => "subject_access.claim_denied",
            Self::DisclosureDenied => "subject_access.disclosure_denied",
            Self::FormatDenied => "subject_access.format_denied",
            Self::ProfileDenied => "subject_access.profile_denied",
            Self::SubjectClaimMissing => "subject_access.subject_claim_missing",
            Self::SubjectMismatch => "subject_access.subject_mismatch",
            Self::RateLimited => "subject_access.rate_limited",
            Self::InvalidToken => "subject_access.invalid_token",
            Self::AssuranceDenied => "subject_access.assurance_denied",
            Self::BatchDenied => "subject_access.batch_denied",
            Self::DelegatedRelationshipUnproven => "delegated.relationship_unproven",
            Self::DelegatedRelationshipNotAllowed => "delegated.relationship_not_allowed",
            Self::DelegatedClaimDenied => "delegated.claim_denied",
            Self::DelegatedSubjectNotPermitted => "delegated.subject_not_permitted",
            Self::DelegatedProofDenied => "delegated.proof_denied",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "subject_access.disabled" => Some(Self::Disabled),
            "subject_access.operation_denied" => Some(Self::OperationDenied),
            "subject_access.claim_denied" => Some(Self::ClaimDenied),
            "subject_access.disclosure_denied" => Some(Self::DisclosureDenied),
            "subject_access.format_denied" => Some(Self::FormatDenied),
            "subject_access.profile_denied" => Some(Self::ProfileDenied),
            "subject_access.subject_claim_missing" => Some(Self::SubjectClaimMissing),
            "subject_access.subject_mismatch" => Some(Self::SubjectMismatch),
            "subject_access.rate_limited" => Some(Self::RateLimited),
            "subject_access.invalid_token" => Some(Self::InvalidToken),
            "subject_access.assurance_denied" => Some(Self::AssuranceDenied),
            "subject_access.batch_denied" => Some(Self::BatchDenied),
            "delegated.relationship_unproven" => Some(Self::DelegatedRelationshipUnproven),
            "delegated.relationship_not_allowed" => Some(Self::DelegatedRelationshipNotAllowed),
            "delegated.claim_denied" => Some(Self::DelegatedClaimDenied),
            "delegated.subject_not_permitted" => Some(Self::DelegatedSubjectNotPermitted),
            "delegated.proof_denied" => Some(Self::DelegatedProofDenied),
            _ => None,
        }
    }
}

impl Serialize for SubjectAccessDenialCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubjectAccessDenialCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| de::Error::custom("unknown subject-access denial code"))
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
pub enum EvidenceEntityReference {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreAuthorizedCodeIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSet {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyIdentifier {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestIdentifier {}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_transaction_id: Option<VerifiedClaimValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_transaction_commitment: Option<VerifiedClaimValue>,
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
            .field(
                "credential_configuration_id",
                &self.credential_configuration_id,
            )
            .field("issuance_transaction_id", &"<redacted>")
            .field(
                "issuance_transaction_commitment",
                &self.issuance_transaction_commitment,
            )
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
            "credential_configuration_id" => self
                .credential_configuration_id
                .as_ref()
                .map(Bounded::as_str),
            "issuance_transaction_id" => self.issuance_transaction_id.as_ref().map(Bounded::as_str),
            "issuance_transaction_commitment" => self
                .issuance_transaction_commitment
                .as_ref()
                .map(Bounded::as_str),
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
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EvaluationCapability {
    Machine {
        #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
        scopes: BTreeSet<String>,
    },
    SubjectBound {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim_id: Option<BoundedClaimId>,
        #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
        allowed_claim_ids: BTreeSet<BoundedClaimId>,
        subject_binding_hash: Hashed<SubjectBinding>,
    },
    DelegatedAttestation {
        proof_claim_id: BoundedClaimId,
        #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
        allowed_claim_ids: BTreeSet<BoundedClaimId>,
        requester_subject_binding_hash: Hashed<SubjectBinding>,
        dependent_target_hash: Hashed<SubjectBinding>,
        relationship_type: ConfigMetadata,
    },
}

impl EvaluationCapability {
    #[must_use]
    pub fn access_mode(&self) -> AccessMode {
        match self {
            Self::Machine { .. } => AccessMode::MachineClient,
            Self::SubjectBound { .. } => AccessMode::SubjectBound,
            Self::DelegatedAttestation { .. } => AccessMode::DelegatedAttestation,
        }
    }

    #[must_use]
    pub fn allows_scope(&self, scope: &str) -> bool {
        match self {
            Self::Machine { scopes } => scopes.contains(scope),
            Self::SubjectBound { .. } => false,
            Self::DelegatedAttestation { .. } => false,
        }
    }

    #[must_use]
    pub fn allows_subject_access_claim(&self, claim_id: &str) -> bool {
        match self {
            Self::Machine { .. } => false,
            Self::SubjectBound {
                claim_id: allowed,
                allowed_claim_ids,
                ..
            } => {
                allowed
                    .as_ref()
                    .is_some_and(|allowed| allowed.as_str() == claim_id)
                    || allowed_claim_ids
                        .iter()
                        .any(|allowed| allowed.as_str() == claim_id)
            }
            Self::DelegatedAttestation { .. } => false,
        }
    }

    #[must_use]
    pub fn allows_delegated_claim(&self, claim_id: &str) -> bool {
        match self {
            Self::DelegatedAttestation {
                proof_claim_id,
                allowed_claim_ids,
                ..
            } => {
                proof_claim_id.as_str() == claim_id
                    || allowed_claim_ids
                        .iter()
                        .any(|allowed| allowed.as_str() == claim_id)
            }
            Self::Machine { .. } | Self::SubjectBound { .. } => false,
        }
    }

    #[must_use]
    pub fn required_delegated_proof_for_claim(&self, claim_id: &str) -> Option<&str> {
        match self {
            Self::DelegatedAttestation {
                proof_claim_id,
                allowed_claim_ids,
                ..
            } if proof_claim_id.as_str() != claim_id
                && allowed_claim_ids
                    .iter()
                    .any(|allowed| allowed.as_str() == claim_id) =>
            {
                Some(proof_claim_id.as_str())
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn is_delegated_proof_claim(&self, claim_id: &str) -> bool {
        match self {
            Self::DelegatedAttestation { proof_claim_id, .. } => {
                proof_claim_id.as_str() == claim_id
            }
            Self::Machine { .. } | Self::SubjectBound { .. } => false,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl ClaimRef {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: None,
        }
    }

    #[must_use]
    pub fn with_version(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: Some(version.into()),
        }
    }
}

impl From<String> for ClaimRef {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl From<&str> for ClaimRef {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl std::ops::Deref for ClaimRef {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.id.as_str()
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClaimRefObject {
    id: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
enum WireClaimRef {
    Id(String),
    Object(ClaimRefObject),
}

impl<'de> Deserialize<'de> for ClaimRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match WireClaimRef::deserialize(deserializer)? {
            WireClaimRef::Id(id) => Ok(Self::new(id)),
            WireClaimRef::Object(object) => Ok(Self {
                id: object.id,
                version: object.version,
            }),
        }
    }
}

impl JsonSchema for ClaimRef {
    fn schema_name() -> Cow<'static, str> {
        "ClaimRef".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        generator.subschema_for::<WireClaimRef>()
    }
}

/// Frozen minimal actor/delegation envelope for `on_behalf_of`.
///
/// Replaces the previous free-form `Option<Value>`. This is the beta-frozen
/// shape per the 2026-06-11 evidence-contracts decision record (D4): a
/// structured actor plus an opaque `delegation_ref`. Simple deployments send no
/// envelope at all (the field stays optional). No OAuth token exchange, RAR, or
/// CIBA machinery is required here; those arrive post-1.0 as additive profiles
/// (notary#180) that map the actor onto OAuth `act`-claim semantics. The shape
/// does not bake in a single-actor assumption: an actor chain is expressed by
/// `delegation_ref` indirection, so the additive mapping stays open.
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceOnBehalfOf {
    pub actor: EvidenceActor,
    /// Opaque reference to an out-of-band delegation record. The envelope does
    /// not interpret its contents; it is the indirection point through which a
    /// later OAuth profile resolves an actor chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
}

/// A structured actor in the delegation envelope. The same vocabulary is reused
/// for stored delegation-chain entries so wire requests and stored evaluations
/// do not diverge.
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceActor {
    #[serde(rename = "type")]
    pub actor_type: String,
    /// Keyed-hash identifier of the actor in `hmac-sha256:<hex>` format per the
    /// D7 vocabulary. Never a raw principal value.
    pub id_hash: String,
    /// Optional assurance level of the actor (for example an `acr` value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    #[serde(default)]
    pub requester: Option<EvidenceEntity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EvidenceEntity>,
    #[serde(default)]
    pub relationship: Option<EvidenceRelationship>,
    #[serde(default)]
    pub on_behalf_of: Option<EvidenceOnBehalfOf>,
    #[serde(default, skip_serializing_if = "RequestVariables::is_empty")]
    pub variables: RequestVariables,
    pub claims: Vec<ClaimRef>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

impl EvaluateRequest {
    #[must_use]
    pub fn target_subject(&self) -> Option<SubjectRequest> {
        self.target
            .as_ref()
            .and_then(EvidenceEntity::to_subject_request)
    }

    #[must_use]
    pub fn request_context(&self) -> Option<EvidenceRequestContext> {
        self.target.as_ref().map(|target| EvidenceRequestContext {
            requester: self.requester.clone(),
            target: target.clone(),
            relationship: self.relationship.clone(),
            on_behalf_of: self.on_behalf_of.clone(),
            variables: self.variables.clone(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequestContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<EvidenceEntity>,
    pub target: EvidenceEntity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<EvidenceRelationship>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<EvidenceOnBehalfOf>,
    #[serde(default, skip_serializing_if = "RequestVariables::is_empty")]
    pub variables: RequestVariables,
}

impl EvidenceRequestContext {
    #[must_use]
    pub fn target_subject(&self) -> Option<SubjectRequest> {
        self.target.to_subject_request()
    }

    #[must_use]
    pub fn lookup_value(&self, path: &str) -> Option<Value> {
        match path {
            "target.id" => self
                .target
                .id
                .as_ref()
                .map(|value| Value::String(value.clone())),
            "requester.id" => self
                .requester
                .as_ref()
                .and_then(|requester| requester.id.as_ref())
                .map(|value| Value::String(value.clone())),
            _ if path.starts_with("target.attributes.") => {
                let key = path.strip_prefix("target.attributes.")?;
                self.target.attributes.get(key).cloned()
            }
            _ if path.starts_with("requester.attributes.") => {
                let key = path.strip_prefix("requester.attributes.")?;
                self.requester
                    .as_ref()
                    .and_then(|requester| requester.attributes.get(key))
                    .cloned()
            }
            _ if path.starts_with("relationship.attributes.") => {
                let key = path.strip_prefix("relationship.attributes.")?;
                self.relationship
                    .as_ref()
                    .and_then(|relationship| relationship.attributes.get(key))
                    .cloned()
            }
            _ if path.starts_with("target.identifiers.") => {
                let scheme = path.strip_prefix("target.identifiers.")?;
                self.target
                    .identifier_value(scheme)
                    .map(|value| Value::String(value.to_string()))
            }
            _ if path.starts_with("requester.identifiers.") => {
                let scheme = path.strip_prefix("requester.identifiers.")?;
                self.requester
                    .as_ref()
                    .and_then(|requester| requester.identifier_value(scheme))
                    .map(|value| Value::String(value.to_string()))
            }
            _ if path.starts_with("variables.") => {
                let name = path.strip_prefix("variables.")?;
                self.variables
                    .get(name)
                    .map(|value| Value::String(value.to_string()))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEntity {
    #[serde(rename = "type")]
    pub entity_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<EvidenceIdentifier>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<EvidenceAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl EvidenceEntity {
    #[must_use]
    pub fn new(entity_type: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            id: None,
            identifiers: Vec::new(),
            attributes: BTreeMap::new(),
            assurance: None,
            profile: None,
        }
    }

    #[must_use]
    pub fn with_identifier(
        entity_type: impl Into<String>,
        scheme: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            entity_type: entity_type.into(),
            id: None,
            identifiers: vec![EvidenceIdentifier {
                scheme: scheme.into(),
                value: value.into(),
                issuer: None,
                country: None,
            }],
            attributes: BTreeMap::new(),
            assurance: None,
            profile: None,
        }
    }

    #[must_use]
    pub fn from_subject_request(entity_type: impl Into<String>, subject: SubjectRequest) -> Self {
        match subject.id_type {
            Some(id_type) => Self::with_identifier(entity_type, id_type, subject.id),
            None => {
                let mut entity = Self::new(entity_type);
                entity.id = Some(subject.id);
                entity
            }
        }
    }

    #[must_use]
    pub fn to_subject_request(&self) -> Option<SubjectRequest> {
        if let Some(identifier) = self.identifiers.first() {
            return Some(SubjectRequest {
                id: identifier.value.clone(),
                id_type: Some(identifier.scheme.clone()),
            });
        }
        self.id.as_ref().map(|id| SubjectRequest {
            id: id.clone(),
            id_type: None,
        })
    }

    #[must_use]
    pub fn identifier_value(&self, scheme: &str) -> Option<&str> {
        self.identifiers
            .iter()
            .find(|identifier| identifier.scheme == scheme)
            .map(|identifier| identifier.value.as_str())
    }

    #[must_use]
    pub fn has_matching_input(&self) -> bool {
        self.id.as_ref().is_some_and(|id| !id.trim().is_empty())
            || self
                .identifiers
                .iter()
                .any(|identifier| !identifier.value.trim().is_empty())
            || !self.attributes.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentifier {
    pub scheme: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAssurance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRelationship {
    #[serde(rename = "type")]
    pub relationship_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
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
pub struct BatchSubjectRequest {
    pub id: String,
    #[serde(default)]
    pub id_type: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

impl From<BatchSubjectRequest> for SubjectRequest {
    fn from(subject: BatchSubjectRequest) -> Self {
        Self {
            id: subject.id,
            id_type: subject.id_type,
        }
    }
}

impl From<SubjectRequest> for BatchSubjectRequest {
    fn from(subject: SubjectRequest) -> Self {
        Self {
            id: subject.id,
            id_type: subject.id_type,
            purpose: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchEvaluateItemRequest {
    pub target: EvidenceEntity,
    #[serde(default)]
    pub requester: Option<EvidenceEntity>,
    #[serde(default)]
    pub relationship: Option<EvidenceRelationship>,
    #[serde(default)]
    pub on_behalf_of: Option<EvidenceOnBehalfOf>,
    #[serde(default)]
    pub purpose: Option<String>,
}

impl BatchEvaluateItemRequest {
    #[must_use]
    pub fn target_subject(&self) -> Option<SubjectRequest> {
        self.target.to_subject_request()
    }

    #[must_use]
    pub fn request_context(&self) -> EvidenceRequestContext {
        EvidenceRequestContext {
            requester: self.requester.clone(),
            target: self.target.clone(),
            relationship: self.relationship.clone(),
            on_behalf_of: self.on_behalf_of.clone(),
            variables: RequestVariables::default(),
        }
    }
}

impl From<BatchSubjectRequest> for BatchEvaluateItemRequest {
    fn from(subject: BatchSubjectRequest) -> Self {
        let purpose = subject.purpose.clone();
        Self {
            target: EvidenceEntity::from_subject_request("Person", SubjectRequest::from(subject)),
            requester: None,
            relationship: None,
            on_behalf_of: None,
            purpose,
        }
    }
}

impl From<SubjectRequest> for BatchEvaluateItemRequest {
    fn from(subject: SubjectRequest) -> Self {
        Self {
            target: EvidenceEntity::from_subject_request("Person", subject),
            requester: None,
            relationship: None,
            on_behalf_of: None,
            purpose: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchEvaluateRequest {
    pub items: Vec<BatchEvaluateItemRequest>,
    pub claims: Vec<ClaimRef>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEvaluateResponse {
    pub batch_id: String,
    pub status: BatchStatus,
    pub claims: Vec<String>,
    pub items: Vec<BatchItemResponse>,
    pub summary: BatchSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    pub succeeded: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemResponse {
    pub input_index: usize,
    pub target_ref: TargetRefView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_ref: Option<EvidenceEntityRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_id: Option<String>,
    pub status: BatchItemStatus,
    pub claim_results: Vec<BatchClaimResultView>,
    pub errors: Vec<BatchItemError>,
    /// Request-local consultation evidence for restricted audit assembly.
    /// This is never serialized into the public response or durable state.
    #[doc(hidden)]
    #[serde(skip)]
    pub runtime_audit: BatchItemRuntimeAudit,
}

/// Request-local, value-free consultation evidence for a batch member.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct BatchItemRuntimeAudit {
    pub relay_forwarded_count: u64,
    pub relay_consultation_ids: Vec<String>,
}

impl std::fmt::Debug for BatchItemRuntimeAudit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BatchItemRuntimeAudit")
            .field("relay_forwarded_count", &self.relay_forwarded_count)
            .field("relay_consultation_ids", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchItemStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemError {
    pub code: String,
    pub title: String,
    pub retryable: bool,
    #[serde(default, skip)]
    pub audit_code: Option<String>,
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
pub struct RenderEvaluationRequest {
    pub format: String,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub claims: Option<Vec<String>>,
    #[serde(default)]
    pub purpose: Option<String>,
}

impl RenderEvaluationRequest {
    #[must_use]
    pub fn with_evaluation_id(self, evaluation_id: String) -> RenderRequest {
        RenderRequest {
            evaluation_id,
            format: self.format,
            disclosure: self.disclosure,
            claims: self.claims,
            purpose: self.purpose,
        }
    }
}

impl From<RenderRequest> for RenderEvaluationRequest {
    fn from(request: RenderRequest) -> Self {
        Self {
            format: request.format,
            disclosure: request.disclosure,
            claims: request.claims,
            purpose: request.purpose,
        }
    }
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
    pub purpose: Option<String>,
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
#[serde(deny_unknown_fields)]
pub struct ClaimResultView {
    pub evaluation_id: String,
    pub claim_id: String,
    pub claim_version: String,
    pub subject_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_ref: Option<EvidenceEntityRef>,
    pub target_ref: TargetRefView,
    pub value: Option<Value>,
    pub satisfied: Option<bool>,
    pub disclosure: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
    pub format: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRefView {
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub entity_type: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier_schemes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEntityRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifier_schemes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// `schema_version` value carried by every [`ClaimProvenance`]. V2 names the
/// consumed boundary as Relay consultations and removes unreleased source
/// runtime aliases.
pub const CLAIM_PROVENANCE_SCHEMA_VERSION: &str = "registry-notary-claim-provenance/v2";

/// The `type` value for a claim-evaluation provenance record.
pub const PROVENANCE_GENERATED_BY_CLAIM_EVALUATION: &str = "claim_evaluation";

/// Versioned claim provenance attached to every public claim result.
///
/// This contract lets a verifier answer which evaluation produced the result,
/// under which policy, and across how many Relay consultations. The shape is
/// documented as PROV-mappable but is not PROV-O.
/// Requester-side identity (client, actor, subject) is deliberately absent;
/// those live in restricted audit, never on the public wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimProvenance {
    pub schema_version: String,
    pub generated_by: ProvenanceGeneratedBy,
    pub used: ProvenanceUsed,
    /// Upstream provenance records this result was derived from. Reserved for
    /// cross-evaluation linking; always empty in v2 but present in the shape so
    /// adding entries later is additive.
    pub derived_from: Vec<Value>,
}

impl ClaimProvenance {
    /// Construct a provenance record at the current schema version with the
    /// canonical `generated_by.type`.
    #[must_use]
    pub fn new(
        service_id: String,
        evaluation_id: String,
        claim_id: String,
        claim_version: String,
        used: ProvenanceUsed,
    ) -> Self {
        Self {
            schema_version: CLAIM_PROVENANCE_SCHEMA_VERSION.to_string(),
            generated_by: ProvenanceGeneratedBy {
                entry_type: PROVENANCE_GENERATED_BY_CLAIM_EVALUATION.to_string(),
                service_id,
                evaluation_id,
                claim_id,
                claim_version,
                policy_id: None,
                policy_version: None,
                policy_hash: None,
                pack_id: None,
                pack_version: None,
            },
            used,
            derived_from: Vec::new(),
        }
    }
}

/// The producing side of a claim provenance record.
///
/// `policy_id` here names the *evaluation* policy under which the result was
/// produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceGeneratedBy {
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Identifier of the service that produced the result. Replaces the
    /// dropped `computed_by` field; the CCCEV renderer maps its provider agent
    /// from here.
    pub service_id: String,
    pub evaluation_id: String,
    pub claim_id: String,
    pub claim_version: String,
    /// Evaluation policy identifier. Present for flows evaluated under a named
    /// policy (e.g. subject-access); omitted for machine-client flows with no
    /// evaluation policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// `sha256:<hex>` digest of the evaluation policy. Public in v1: a hash,
    /// revealing no policy content, that lets a verifier correlate the result
    /// with a policy evidence-pack later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_version: Option<String>,
}

/// The consumed side of a claim provenance record: how many Relay consultations
/// contributed to the claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceUsed {
    pub relay_consultation_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvaluation {
    pub client_id: String,
    pub purpose: String,
    pub claim_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_refs: Vec<ClaimRef>,
    pub disclosure: String,
    pub format: String,
    pub results: Vec<ClaimResultView>,
    pub created_at: String,
    pub expires_at: String,
    pub request_hash: String,
    /// Private issuance-only Relay provenance for the selected dependency closure.
    ///
    /// This is deliberately separate from public [`ClaimProvenance`]. It is
    /// persisted only for credential-capable selections so a later credential
    /// request can prove that every fact being signed came from the exact
    /// compiler-pinned Relay consultation. Evaluation-only selections retain
    /// no private Relay execution identifiers. Evaluations written before this
    /// field existed remain readable, but are not credential-issuable and must
    /// be evaluated again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_provenance: Option<StoredIssuanceProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_access: Option<StoredSubjectAccessMetadata>,
}

impl StoredEvaluation {
    #[must_use]
    pub fn access_mode(&self) -> AccessMode {
        self.subject_access
            .as_ref()
            .map(|metadata| metadata.access_mode)
            .unwrap_or(AccessMode::MachineClient)
    }

    #[must_use]
    pub fn selected_claim_refs(&self) -> Vec<ClaimRef> {
        if self.claim_refs.is_empty() {
            self.claim_ids
                .iter()
                .map(|claim_id| ClaimRef::from(claim_id.as_str()))
                .collect()
        } else {
            self.claim_refs.clone()
        }
    }
}

/// Bounded private provenance retained for credential issuance.
///
/// The runtime admits at most the v1 claim-closure bound and the issuance
/// verifier rejects an over-sized or incomplete set before any signer or
/// credential-status side effect. Consultation identifiers remain restricted
/// state and never appear in evaluation, render, or credential responses.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIssuanceProvenance {
    pub claims: Vec<StoredIssuanceClaimProvenance>,
    /// Unique Relay executions referenced by the claim closure.
    ///
    /// Keeping executions separate permits one coalesced Relay consultation to
    /// support several claim pins without duplicating the restricted execution
    /// record. A missing empty legacy field is readable but nonissuable.
    #[serde(default)]
    pub consultations: Vec<StoredIssuanceConsultationProvenance>,
}

impl std::fmt::Debug for StoredIssuanceProvenance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredIssuanceProvenance")
            .field("claim_count", &self.claims.len())
            .field("consultation_count", &self.consultations.len())
            .finish()
    }
}

/// The exact compiler pin and successful Relay execution for one claim in a
/// selected root's dependency closure. This restricted persistence shape is
/// not a public API model.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIssuanceClaimProvenance {
    pub claim_id: String,
    pub claim_version: String,
    pub relay_profile_id: String,
    pub relay_contract_hash: String,
    pub canonical_purpose: String,
    pub consultation_id: String,
    /// Deterministic SHA-256 commitment over this compiler pin, its Relay
    /// execution record, and the claim result provenance produced by the
    /// evaluation. A missing legacy value remains readable but is not
    /// credential-issuable.
    #[serde(default)]
    pub execution_binding: String,
}

impl std::fmt::Debug for StoredIssuanceClaimProvenance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredIssuanceClaimProvenance")
            .field("claim_id", &self.claim_id)
            .field("claim_version", &self.claim_version)
            .field("relay_profile_id", &self.relay_profile_id)
            .field("relay_contract_hash", &self.relay_contract_hash)
            .field("canonical_purpose", &self.canonical_purpose)
            .field("consultation_id", &"[REDACTED]")
            .field("execution_binding", &self.execution_binding)
            .finish()
    }
}

/// One unique successful Relay execution retained for issuance verification.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIssuanceConsultationProvenance {
    pub consultation_id: String,
    pub acquired_at: String,
}

impl std::fmt::Debug for StoredIssuanceConsultationProvenance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredIssuanceConsultationProvenance")
            .field("consultation_id", &"[REDACTED]")
            .field("acquired_at", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSubjectAccessMetadata {
    #[serde(default = "subject_access_access_mode")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependent_target_hash: Option<Hashed<SubjectBinding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_type: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_claim_id: Option<BoundedClaimId>,
    pub requested_claims_hash: Hashed<ClaimSet>,
    pub disclosure: ConfigMetadata,
    pub result_format: ConfigMetadata,
    /// Delegation chain in the frozen envelope vocabulary (D4). Empty in v1;
    /// populated post-1.0 by the additive OAuth profile (notary#180). The empty
    /// case serializes identically to the previous placeholder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<EvidenceActor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<BoundedPolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<Hashed<PolicyIdentifier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_expires_at: Option<String>,
}

const fn subject_access_access_mode() -> AccessMode {
    AccessMode::SubjectBound
}

/// Versioned authorization fields shared by static configuration and token/OIDC JSON.
///
/// Unknown metadata is intentionally ignored for forward-compatible interoperability.
/// Authorization decisions consume only the modeled fields and must never infer authority
/// from an unrecognized extension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct EvidenceAuthorizationDetails {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<EvidenceAuthorizationSubject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EvidenceAuthorizationTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<EvidenceAuthorizationRelationship>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<AccessMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_access_context: Option<EvidenceAssistedAccessContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct EvidenceAuthorizationSubject {
    pub binding_claim: String,
    pub id_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct EvidenceAuthorizationTarget {
    pub id_type: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct EvidenceAuthorizationRelationship {
    pub relationship_type: String,
    pub proof_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct EvidenceAssistedAccessContext {
    pub channel: String,
}

#[derive(Debug, Clone)]
pub struct EvidencePrincipal {
    pub auth_profile_id: EvidenceAuthProfileId,
    pub principal_id: String,
    pub scopes: Vec<String>,
    pub access_mode: AccessMode,
    pub verified_claims: Option<BoundedVerifiedClaims>,
    pub authorization_details: Option<EvidenceAuthorizationDetails>,
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
    pub const fn is_subject_access(&self) -> bool {
        matches!(
            self.access_mode,
            AccessMode::SubjectBound | AccessMode::DelegatedAttestation
        )
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

#[derive(Clone, Deserialize, Serialize)]
pub struct EvidenceAuditEvent {
    pub event_id: String,
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id_hash: Option<Hashed<PrincipalIdentifier>>,
    #[serde(default)]
    pub scopes_used: Vec<String>,
    pub decision: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_consultation_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_consultation_ids: Vec<String>,
    /// Conservative dispatch-attempt marker. `true` means Notary committed to
    /// Relay work that may have reached Relay, not that Relay received it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<AccessMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_peer_id_hash: Option<Hashed<PrincipalIdentifier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_request_jti_hash: Option<Hashed<RequestIdentifier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_subject_ref_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_code: Option<SubjectAccessDenialCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_claim_name: Option<ConfigMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id_hash: Option<Hashed<RequestIdentifier>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_items: Option<Vec<EvidenceBatchItemAuditEvent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigAuditEvent>,
}

impl std::fmt::Debug for EvidenceAuditEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceAuditEvent")
            .field("event_id", &"[REDACTED]")
            .field("decision", &self.decision)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("status", &self.status)
            .field("verification_id", &"[REDACTED]")
            .field("relay_consultation_ids", &"[REDACTED]")
            .field("forwarded", &self.forwarded)
            .field("error_code", &self.error_code)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigAuditEvent {
    pub action: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(
        default,
        rename = "bundle_sequence",
        skip_serializing_if = "Option::is_none"
    )]
    pub sequence: Option<u64>,
    pub signer_kids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash_matched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    pub product_validation_result: String,
    pub apply_result: String,
    pub posture_result: String,
    pub applied: bool,
    pub restart_required: bool,
    pub change_classes: Vec<String>,
    pub break_glass: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_approval_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_reason_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_emergency_change_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_expires_at_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass_rate_limit_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_approval_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_approval_approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_approval_reason_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_approval_change_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_approval_expires_at_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_approval_rate_limit_identity: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct EvidenceBatchItemAuditEvent {
    pub input_index: usize,
    #[serde(default)]
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default)]
    pub relay_consultation_count: u64,
    #[serde(default)]
    pub forwarded: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_consultation_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_ref_hash: Option<Hashed<EvidenceEntityReference>>,
}

impl std::fmt::Debug for EvidenceBatchItemAuditEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceBatchItemAuditEvent")
            .field("input_index", &self.input_index)
            .field("outcome", &self.outcome)
            .field("error_code", &self.error_code)
            .field("relay_consultation_count", &self.relay_consultation_count)
            .field("forwarded", &self.forwarded)
            .field("relay_consultation_ids", &"[REDACTED]")
            .finish_non_exhaustive()
    }
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
            serde_json::to_value(AccessMode::SubjectBound).expect("access mode serializes"),
            json!("subject_bound")
        );
        assert_eq!(
            AccessMode::parse("machine_client"),
            Some(AccessMode::MachineClient)
        );
    }

    #[test]
    fn evidence_auth_profile_ids_are_closed_and_stable() {
        for (profile, expected) in [
            (EvidenceAuthProfileId::StaticApiKey, "static_api_key"),
            (EvidenceAuthProfileId::StaticBearer, "static_bearer"),
            (EvidenceAuthProfileId::ExternalOidc, "external_oidc"),
            (
                EvidenceAuthProfileId::NotaryAccessToken,
                "notary_access_token",
            ),
            (EvidenceAuthProfileId::Federation, "federation"),
        ] {
            assert_eq!(profile.as_str(), expected);
            assert_eq!(
                serde_json::to_value(profile).expect("auth profile serializes"),
                json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<EvidenceAuthProfileId>(json!(expected))
                    .expect("known auth profile deserializes"),
                profile
            );
        }
        assert!(
            serde_json::from_value::<EvidenceAuthProfileId>(json!("attacker_selected")).is_err()
        );
    }

    #[test]
    fn claim_ref_deserializes_string_and_versioned_object() {
        let legacy: ClaimRef =
            serde_json::from_value(json!("person-is-alive")).expect("legacy claim id deserializes");
        assert_eq!(legacy.id, "person-is-alive");
        assert_eq!(legacy.version, None);

        let versioned: ClaimRef =
            serde_json::from_value(json!({ "id": "person-is-alive", "version": "2026-05" }))
                .expect("versioned claim ref deserializes");
        assert_eq!(versioned.id, "person-is-alive");
        assert_eq!(versioned.version.as_deref(), Some("2026-05"));
    }

    #[test]
    fn evaluate_request_deserializes_identity_bundle_target() {
        let request: EvaluateRequest = serde_json::from_value(json!({
            "requester": {
                "type": "person",
                "identifiers": [
                    { "scheme": "national_id", "value": "NID-9001", "country": "RW" }
                ]
            },
            "target": {
                "type": "person",
                "identifiers": [
                    { "scheme": "national_id", "value": "NID-1001" }
                ],
                "attributes": {
                    "given_name": "Amina",
                    "family_name": "Kamanzi",
                    "date_of_birth": "1990-01-15"
                },
                "assurance": {
                    "method": "oidc",
                    "level_scheme": "example-loa",
                    "level": "substantial"
                }
            },
            "relationship": {
                "type": "self"
            },
            "on_behalf_of": {
                "actor": {
                    "type": "operator",
                    "id_hash": "hmac-sha256:abc123"
                }
            },
            "claims": ["person-is-alive"],
            "purpose": "https://purpose.example/social-protection"
        }))
        .expect("new request shape deserializes");

        let target = request.target.as_ref().expect("target is present");
        assert_eq!(target.entity_type, "person");
        assert_eq!(
            request
                .target_subject()
                .expect("identifier target maps to source subject")
                .id_type
                .as_deref(),
            Some("national_id")
        );
        assert_eq!(target.attributes["date_of_birth"], json!("1990-01-15"));
    }

    #[test]
    fn evaluate_request_variables_are_closed_bounded_full_dates() {
        let request: EvaluateRequest = serde_json::from_value(json!({
            "target": { "type": "person", "id": "person-1" },
            "variables": { "as_of_date": "2026-01-01" },
            "claims": ["age-band"]
        }))
        .expect("declared-shape request variable parses");
        assert_eq!(request.variables.get("as_of_date"), Some("2026-01-01"));
        assert_eq!(
            request
                .request_context()
                .and_then(|context| context.lookup_value("variables.as_of_date")),
            Some(json!("2026-01-01"))
        );
        let debug = format!("{:?}", request.variables);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("2026-01-01"));

        for variables in [
            json!({ "AsOf": "2026-01-01" }),
            json!({ "as_of_date": "2026-02-30" }),
            json!({ "as_of_date": 20260101 }),
        ] {
            assert!(serde_json::from_value::<EvaluateRequest>(json!({
                "target": { "type": "person", "id": "person-1" },
                "variables": variables,
                "claims": ["age-band"]
            }))
            .is_err());
        }
        let too_many = (0..=MAX_REQUEST_VARIABLES_V1)
            .map(|index| (format!("date_{index}"), json!("2026-01-01")))
            .collect::<serde_json::Map<_, _>>();
        assert!(serde_json::from_value::<EvaluateRequest>(json!({
            "target": { "type": "person", "id": "person-1" },
            "variables": too_many,
            "claims": ["age-band"]
        }))
        .is_err());
    }

    #[test]
    fn evaluate_request_allows_missing_target_for_server_derived_context() {
        let request: EvaluateRequest = serde_json::from_value(json!({
            "claims": ["person-is-alive"],
            "purpose": "https://purpose.example/self"
        }))
        .expect("target may be omitted when the server derives subject-access context");

        assert!(request.target.is_none());
        assert!(request.target_subject().is_none());
        assert!(request.request_context().is_none());
    }

    #[test]
    fn evaluate_request_rejects_old_subject_shape() {
        let error = serde_json::from_value::<EvaluateRequest>(json!({
            "subject": { "id": "NID-1001", "id_type": "national_id" },
            "claims": ["person-is-alive"]
        }))
        .expect_err("old subject shape is no longer accepted");

        assert!(
            error.to_string().contains("missing field `target`")
                || error.to_string().contains("unknown field `subject`"),
            "unexpected serde error: {error}"
        );
    }

    #[test]
    fn evidence_entity_reports_matching_input_only_when_non_empty() {
        let mut entity = EvidenceEntity::new("Person");
        assert!(!entity.has_matching_input());

        entity.id = Some("   ".to_string());
        entity.identifiers.push(EvidenceIdentifier {
            scheme: "national_id".to_string(),
            value: "  ".to_string(),
            issuer: None,
            country: None,
        });
        assert!(!entity.has_matching_input());

        entity.identifiers[0].value = "NID-1001".to_string();
        assert!(entity.has_matching_input());

        entity.identifiers[0].value = "  ".to_string();
        entity
            .attributes
            .insert("district".to_string(), json!("north"));
        assert!(entity.has_matching_input());
    }

    #[test]
    fn batch_evaluate_request_deserializes_items_with_mixed_targets() {
        let request: BatchEvaluateRequest = serde_json::from_value(json!({
            "items": [
                {
                    "target": {
                        "type": "person",
                        "identifiers": [
                            { "scheme": "national_id", "value": "NID-1001" }
                        ]
                    }
                },
                {
                    "target": {
                        "type": "land_parcel",
                        "identifiers": [
                            { "scheme": "parcel_id", "value": "LP-42" }
                        ]
                    },
                    "purpose": "https://purpose.example/land"
                }
            ],
            "claims": ["eligibility"]
        }))
        .expect("batch request shape deserializes");

        assert_eq!(request.items.len(), 2);
        assert_eq!(
            request.items[1]
                .target_subject()
                .expect("target maps to source subject")
                .id_type
                .as_deref(),
            Some("parcel_id")
        );
    }

    #[test]
    fn result_views_serialize_target_ref_without_subject_ref_or_id_type() {
        let result = ClaimResultView {
            evaluation_id: "eval-1".to_string(),
            claim_id: "person-is-alive".to_string(),
            claim_version: "1.0.0".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:test".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "predicate".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_CLAIM_RESULT_JSON.to_string(),
            issued_at: "2026-05-31T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "test".to_string(),
                "eval-1".to_string(),
                "person-is-alive".to_string(),
                "1.0.0".to_string(),
                ProvenanceUsed {
                    relay_consultation_count: 1,
                },
            ),
        };

        let value = serde_json::to_value(result).expect("result serializes");
        assert!(value.get("target_ref").is_some());
        assert!(value.get("subject_ref").is_none());
        assert!(value["target_ref"].get("id_type").is_none());
    }

    #[test]
    fn claim_provenance_v2_serializes_relay_consultation_shape() {
        let mut provenance = ClaimProvenance::new(
            "registry-notary".to_string(),
            "eval_01HX".to_string(),
            "person_is_alive".to_string(),
            "1".to_string(),
            ProvenanceUsed {
                relay_consultation_count: 1,
            },
        );
        provenance.generated_by.policy_id = Some("subject-access".to_string());
        provenance.generated_by.policy_version = Some("v1".to_string());
        provenance.generated_by.policy_hash = Some("sha256:def456".to_string());

        let value = serde_json::to_value(&provenance).expect("provenance serializes");

        assert_eq!(
            value["schema_version"],
            json!("registry-notary-claim-provenance/v2")
        );
        let generated_by = &value["generated_by"];
        assert_eq!(generated_by["type"], json!("claim_evaluation"));
        assert_eq!(generated_by["service_id"], json!("registry-notary"));
        assert_eq!(generated_by["evaluation_id"], json!("eval_01HX"));
        assert_eq!(generated_by["claim_id"], json!("person_is_alive"));
        assert_eq!(generated_by["claim_version"], json!("1"));
        assert_eq!(generated_by["policy_id"], json!("subject-access"));
        assert_eq!(generated_by["policy_version"], json!("v1"));
        assert_eq!(generated_by["policy_hash"], json!("sha256:def456"));

        let used = &value["used"];
        assert_eq!(used["relay_consultation_count"], json!(1));
        assert!(used.get("source_count").is_none());
        assert!(used.get("source_versions").is_none());
        assert_eq!(value["derived_from"], json!([]));
    }

    #[test]
    fn claim_provenance_v2_round_trips() {
        let provenance = ClaimProvenance::new(
            "registry-notary".to_string(),
            "eval_01HX".to_string(),
            "person_is_alive".to_string(),
            "1".to_string(),
            ProvenanceUsed {
                relay_consultation_count: 2,
            },
        );
        let value = serde_json::to_value(&provenance).expect("serializes");
        let parsed: ClaimProvenance =
            serde_json::from_value(value).expect("provenance round-trips");
        assert_eq!(parsed.schema_version, CLAIM_PROVENANCE_SCHEMA_VERSION);
        assert_eq!(parsed.used.relay_consultation_count, 2);
        assert!(parsed.generated_by.policy_id.is_none());
    }

    #[test]
    fn claim_provenance_omits_computed_by_and_requester_side_fields() {
        let provenance = ClaimProvenance::new(
            "registry-notary".to_string(),
            "eval_01HX".to_string(),
            "claim".to_string(),
            "1".to_string(),
            ProvenanceUsed {
                relay_consultation_count: 0,
            },
        );
        let value = serde_json::to_value(&provenance).expect("serializes");
        let text = value.to_string();
        assert!(
            !text.contains("computed_by"),
            "computed_by must be gone from the provenance wire shape"
        );
        for forbidden in ["client", "actor", "subject"] {
            assert!(
                value.get(forbidden).is_none()
                    && value["generated_by"].get(forbidden).is_none()
                    && value["used"].get(forbidden).is_none(),
                "requester-side field {forbidden} must not appear in claim provenance"
            );
        }
    }

    #[test]
    fn on_behalf_of_envelope_serializes_and_round_trips() {
        let envelope = EvidenceOnBehalfOf {
            actor: EvidenceActor {
                actor_type: "service_account".to_string(),
                id_hash: "hmac-sha256:abc123".to_string(),
                assurance: Some("urn:example:loa:substantial".to_string()),
            },
            delegation_ref: Some("urn:delegation:42".to_string()),
        };
        let value = serde_json::to_value(&envelope).expect("envelope serializes");
        assert_eq!(value["actor"]["type"], json!("service_account"));
        assert_eq!(value["actor"]["id_hash"], json!("hmac-sha256:abc123"));
        assert_eq!(
            value["actor"]["assurance"],
            json!("urn:example:loa:substantial")
        );
        assert_eq!(value["delegation_ref"], json!("urn:delegation:42"));

        let parsed: EvidenceOnBehalfOf =
            serde_json::from_value(value).expect("envelope round-trips");
        assert_eq!(parsed.actor.actor_type, "service_account");
        assert_eq!(parsed.delegation_ref.as_deref(), Some("urn:delegation:42"));
    }

    #[test]
    fn on_behalf_of_minimal_envelope_omits_optional_fields() {
        let envelope = EvidenceOnBehalfOf {
            actor: EvidenceActor {
                actor_type: "operator".to_string(),
                id_hash: "hmac-sha256:def456".to_string(),
                assurance: None,
            },
            delegation_ref: None,
        };
        let value = serde_json::to_value(&envelope).expect("envelope serializes");
        assert!(value.get("delegation_ref").is_none());
        assert!(value["actor"].get("assurance").is_none());
    }

    #[test]
    fn on_behalf_of_rejects_free_form_payloads() {
        let legacy = json!({ "delegator": "did:example:123", "scope": "read" });
        let err = serde_json::from_value::<EvidenceOnBehalfOf>(legacy)
            .expect_err("free-form on_behalf_of must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("unknown field") || message.contains("missing field"),
            "rejection should be a schema mismatch, got: {message}"
        );
    }

    #[test]
    fn on_behalf_of_rejects_unknown_actor_field() {
        let payload = json!({
            "actor": {
                "type": "operator",
                "id_hash": "hmac-sha256:def456",
                "raw_id": "leaked"
            }
        });
        let err = serde_json::from_value::<EvidenceOnBehalfOf>(payload)
            .expect_err("unknown actor field must be rejected");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn evaluate_request_accepts_envelope_and_rejects_loose_json() {
        let accepted = serde_json::from_value::<EvaluateRequest>(json!({
            "target": { "type": "Person", "identifiers": [{ "scheme": "id", "value": "x" }] },
            "claims": ["person_is_alive"],
            "on_behalf_of": {
                "actor": { "type": "operator", "id_hash": "hmac-sha256:abc" }
            }
        }));
        assert!(accepted.is_ok(), "structured envelope must be accepted");

        let rejected = serde_json::from_value::<EvaluateRequest>(json!({
            "target": { "type": "Person", "identifiers": [{ "scheme": "id", "value": "x" }] },
            "claims": ["person_is_alive"],
            "on_behalf_of": { "anything": "goes" }
        }));
        assert!(
            rejected.is_err(),
            "free-form on_behalf_of must be rejected at request level"
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
            audiences: vec![bounded("registry-notary-citizen")],
            client_id: Some(bounded("citizen-portal")),
            token_type: Some(bounded("JWT")),
            credential_configuration_id: None,
            issuance_transaction_id: None,
            issuance_transaction_commitment: None,
            scopes: vec![bounded("subject_access")],
            subject: Some(bounded("login-subject")),
            subject_binding_claim: Some(bounded("https://id.example.gov/claims/national_id")),
            subject_binding_value: Some(bounded("NAT-123")),
            acr: Some(bounded("urn:example:loa:substantial")),
            auth_time: Some(1_800_000_000),
            exp: Some(1_800_000_900),
            iat: Some(1_800_000_000),
            nbf: None,
        };

        assert!(claims.has_scope("subject_access"));
        assert_eq!(claims.claim_value("sub"), Some("login-subject"));
        assert_eq!(claims.claim_value("email"), None);
        assert_eq!(
            claims.subject_binding_value("https://id.example.gov/claims/national_id"),
            Some("NAT-123")
        );
    }

    #[test]
    fn verified_claim_lookup_treats_blank_subject_binding_value_as_missing() {
        for blank in ["", "   "] {
            let claims = BoundedVerifiedClaims {
                issuer: bounded("https://id.example.gov"),
                audiences: vec![bounded("registry-notary-citizen")],
                client_id: Some(bounded("citizen-portal")),
                token_type: Some(bounded("JWT")),
                credential_configuration_id: None,
                issuance_transaction_id: None,
                issuance_transaction_commitment: None,
                scopes: vec![bounded("subject_access")],
                subject: Some(bounded("login-subject")),
                subject_binding_claim: Some(bounded("https://id.example.gov/claims/national_id")),
                subject_binding_value: Some(bounded(blank)),
                acr: None,
                auth_time: None,
                exp: None,
                iat: None,
                nbf: None,
            };

            assert_eq!(
                claims.subject_binding_value("https://id.example.gov/claims/national_id"),
                None
            );
        }
    }

    #[test]
    fn evaluation_capability_separates_machine_scopes_from_subject_access_claims() {
        let machine = EvaluationCapability::Machine {
            scopes: BTreeSet::from(["civil_registry:evidence_verification".to_string()]),
        };
        assert_eq!(machine.access_mode(), AccessMode::MachineClient);
        assert!(machine.allows_scope("civil_registry:evidence_verification"));
        assert!(!machine.allows_subject_access_claim("person-is-alive"));

        let citizen = EvaluationCapability::SubjectBound {
            claim_id: Some(bounded("person-is-alive")),
            allowed_claim_ids: BTreeSet::new(),
            subject_binding_hash: Hashed::from_hash("sha256:test"),
        };
        assert_eq!(citizen.access_mode(), AccessMode::SubjectBound);
        assert!(!citizen.allows_scope("civil_registry:evidence_verification"));
        assert!(citizen.allows_subject_access_claim("person-is-alive"));
    }

    #[test]
    fn audit_subject_access_fields_round_trip_without_raw_values() {
        let event = EvidenceAuditEvent {
            event_id: "01HX".to_string(),
            occurred_at: "2026-05-25T00:00:00Z".to_string(),
            principal_id_hash: Some(Hashed::from_hash("hmac-sha256:principal")),
            scopes_used: vec!["subject_access".to_string()],
            decision: "denied".to_string(),
            method: "POST".to_string(),
            path: "/v1/evaluations".to_string(),
            status: 403,
            verification_id: None,
            claim_hash: Some("sha256:claims".to_string()),
            purposes: None,
            row_count: None,
            relay_consultation_count: None,
            relay_consultation_ids: vec!["01JRELAYCORRELATIONSENSITIVE".to_string()],
            forwarded: None,
            error_code: Some("subject_access.denied".to_string()),
            access_mode: Some(AccessMode::SubjectBound),
            federation_peer_id_hash: None,
            federation_issuer: None,
            federation_profile: None,
            federation_purpose: None,
            federation_request_jti_hash: None,
            federation_subject_ref_hash: None,
            denial_code: Some(SubjectAccessDenialCode::SubjectMismatch),
            token_claim_name: Some(bounded("national_id")),
            correlation_id_hash: Some(Hashed::from_hash("hmac-sha256:req-123")),
            credential_profile: None,
            protocol: Some(bounded("openid4vci")),
            credential_configuration_id: Some(bounded("person_is_alive_sd_jwt")),
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_version: Some(bounded("citizen-v1")),
            policy_hash: Some(Hashed::from_hash("sha256:policy")),
            target_type: Some("person".to_string()),
            target_ref_hash: Some(Hashed::from_hash("hmac-sha256:target")),
            requester_type: Some("person".to_string()),
            requester_ref_hash: Some(Hashed::from_hash("hmac-sha256:requester")),
            redacted_fields: None,
            batch_items: Some(vec![EvidenceBatchItemAuditEvent {
                input_index: 0,
                outcome: "failed".to_string(),
                error_code: Some("evidence.not_available".to_string()),
                relay_consultation_count: 1,
                forwarded: true,
                relay_consultation_ids: vec!["01JRELAYBATCHSENSITIVE".to_string()],
                target_type: Some("person".to_string()),
                target_ref_hash: Some(Hashed::from_hash("hmac-sha256:batch-target")),
                requester_type: Some("person".to_string()),
                requester_ref_hash: Some(Hashed::from_hash("hmac-sha256:batch-requester")),
            }]),
            config: None,
        };

        let value = serde_json::to_value(&event).expect("audit event serializes");
        assert_eq!(
            value["relay_consultation_ids"],
            json!(["01JRELAYCORRELATIONSENSITIVE"])
        );
        let debug = format!("{event:?}");
        assert!(!debug.contains("01JRELAYCORRELATIONSENSITIVE"));
        assert!(!debug.contains("01JRELAYBATCHSENSITIVE"));
        assert!(debug.contains("relay_consultation_ids: \"[REDACTED]\""));
        assert_eq!(value["access_mode"], json!("subject_bound"));
        assert_eq!(
            value["denial_code"],
            json!("subject_access.subject_mismatch")
        );
        assert_eq!(value["token_claim_name"], json!("national_id"));
        assert_eq!(value["correlation_id_hash"], json!("hmac-sha256:req-123"));
        assert!(value.get("correlation_id").is_none());
        assert_eq!(value["protocol"], json!("openid4vci"));
        assert_eq!(
            value["credential_configuration_id"],
            json!("person_is_alive_sd_jwt")
        );
        assert_eq!(value["principal_id_hash"], json!("hmac-sha256:principal"));
        assert_eq!(value["scopes_used"], json!(["subject_access"]));
        assert!(value.get("principal_id").is_none());
        assert!(value.get("subject_binding_value").is_none());
        assert_eq!(value["target_type"], json!("person"));
        assert_eq!(value["target_ref_hash"], json!("hmac-sha256:target"));
        assert_eq!(value["requester_type"], json!("person"));
        assert_eq!(value["requester_ref_hash"], json!("hmac-sha256:requester"));
        assert_eq!(
            value["batch_items"][0]["target_ref_hash"],
            json!("hmac-sha256:batch-target")
        );
        assert!(value.get("target_id").is_none());
        assert!(value.get("target_attributes").is_none());
        assert!(value.get("requester_id").is_none());

        let decoded: EvidenceAuditEvent =
            serde_json::from_value(value).expect("audit event deserializes");
        assert_eq!(decoded.event_id, event.event_id);
        assert_eq!(decoded.scopes_used, vec!["subject_access"]);
        assert_eq!(decoded.access_mode, Some(AccessMode::SubjectBound));
        assert_eq!(
            decoded.denial_code,
            Some(SubjectAccessDenialCode::SubjectMismatch)
        );
        assert_eq!(
            decoded.token_claim_name.as_ref().map(Bounded::as_str),
            Some("national_id")
        );
        assert_eq!(
            decoded.correlation_id_hash.as_ref().map(Hashed::as_str),
            Some("hmac-sha256:req-123")
        );
        assert_eq!(
            decoded.policy_hash.as_ref().map(Hashed::as_str),
            Some("sha256:policy")
        );
        assert_eq!(decoded.target_type.as_deref(), Some("person"));
        assert_eq!(
            decoded.target_ref_hash.as_ref().map(Hashed::as_str),
            Some("hmac-sha256:target")
        );
        assert_eq!(decoded.requester_type.as_deref(), Some("person"));
        assert_eq!(
            decoded.requester_ref_hash.as_ref().map(Hashed::as_str),
            Some("hmac-sha256:requester")
        );
        assert_eq!(decoded.batch_items.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn audit_event_missing_optional_fields_defaults_to_none() {
        let decoded: EvidenceAuditEvent = serde_json::from_value(json!({
            "event_id": "01HX",
            "occurred_at": "2026-05-25T00:00:00Z",
            "decision": "allowed",
            "method": "GET",
            "path": "/v1/claims",
            "status": 200
        }))
        .expect("legacy audit event deserializes");

        assert!(decoded.verification_id.is_none());
        assert!(decoded.claim_hash.is_none());
        assert!(decoded.purposes.is_none());
        assert!(decoded.scopes_used.is_empty());
        assert!(decoded.row_count.is_none());
        assert!(decoded.error_code.is_none());
        assert!(decoded.access_mode.is_none());
        assert!(decoded.target_type.is_none());
        assert!(decoded.target_ref_hash.is_none());
        assert!(decoded.requester_type.is_none());
        assert!(decoded.requester_ref_hash.is_none());
        assert!(decoded.batch_items.is_none());
    }

    #[test]
    fn stored_evaluation_without_subject_access_defaults_to_machine_client() {
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
        assert_eq!(
            stored.selected_claim_refs(),
            vec![ClaimRef::from("person-is-alive")]
        );
        assert!(stored.issuance_provenance.is_none());
        assert!(stored.subject_access.is_none());
    }
}
