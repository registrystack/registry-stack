//! Response-side wire types: the Evidence payload, its public value forms, and
//! the three response serializations a relying party can receive.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};
use utoipa::ToSchema;

use crate::AssuranceProfile;

/// Caller-supplied Ed25519 holder public key. `deny_unknown_fields` is the
/// primary defence against private key members: a body carrying `d` or any
/// other unexpected member fails to parse.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HolderPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Exact byte length of a raw Ed25519 public key.
const HOLDER_KEY_DECODED_LENGTH: usize = 32;
const MAX_HOLDER_KEY_ID_BYTES: usize = 256;

impl HolderPublicKey {
    /// Accept only a public OKP Ed25519 JWK whose coordinate is the canonical
    /// unpadded base64url encoding of exactly 32 bytes.
    pub fn is_acceptable(&self) -> bool {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return false;
        }
        if self.alg.as_deref().is_some_and(|alg| alg != "EdDSA") {
            return false;
        }
        if self
            .kid
            .as_deref()
            .is_some_and(|kid| kid.is_empty() || kid.len() > MAX_HOLDER_KEY_ID_BYTES)
        {
            return false;
        }
        URL_SAFE_NO_PAD
            .decode(&self.x)
            .is_ok_and(|decoded| decoded.len() == HOLDER_KEY_DECODED_LENGTH)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub assurance_profile: AssuranceProfile,
    /// Exact echo of the caller's request nonce for request-response
    /// correlation. The runtime does not store it or reject reuse.
    pub request_nonce: String,
    pub id: String,
    #[serde(rename = "type")]
    pub evidence_type_name: EvidenceObjectType,
    pub supports_requirement: String,
    pub is_conformant_to: String,
    pub issued_by: String,
    pub provided_by: String,
    pub issued_at: String,
    pub observed_at: String,
    pub valid_until: String,
    pub purpose: String,
    pub audience: String,
    pub configuration_revision: String,
    pub subjects: Vec<SubjectBinding>,
    pub supported_values: Vec<SupportedValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
pub enum EvidenceObjectType {
    Evidence,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SubjectBinding {
    pub role: String,
    pub binding: String,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupportedValue {
    pub provides_value_for: String,
    pub value: PublicValue,
}

#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema, ToSchema)]
#[serde(untagged)]
pub enum PublicValue {
    Boolean(bool),
    Integer(i64),
    String(String),
    Bucket(BucketValue),
    EntityReference(EntityReferenceValue),
    Structured(StructuredValue),
    List(Vec<ScalarOrEntityReference>),
}

impl<'de> Deserialize<'de> for PublicValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Bool(value) => Ok(Self::Boolean(value)),
            Value::Number(value) => safe_json_integer(&value)
                .map(Self::Integer)
                .ok_or_else(|| de::Error::custom("public number is not a safe JSON integer")),
            Value::String(value) => Ok(Self::String(value)),
            Value::Array(values) => serde_json::from_value(Value::Array(values))
                .map(Self::List)
                .map_err(de::Error::custom),
            Value::Object(object) => {
                let form = object
                    .get("form")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let value = Value::Object(object);
                match form.as_deref() {
                    Some("date-bucket" | "time-bucket") => serde_json::from_value(value)
                        .map(Self::Bucket)
                        .map_err(de::Error::custom),
                    Some("audience-scoped-entity-reference") => serde_json::from_value(value)
                        .map(Self::EntityReference)
                        .map_err(de::Error::custom),
                    Some("reviewed-structured-value") => serde_json::from_value(value)
                        .map(Self::Structured)
                        .map_err(de::Error::custom),
                    _ => Err(de::Error::custom("public object has an unsupported form")),
                }
            }
            Value::Null => Err(de::Error::custom("public value cannot be null")),
        }
    }
}

/// Canonicalize a JSON number to the safe integer range shared by every
/// scalar the wire formats accept.
pub fn safe_json_integer(number: &Number) -> Option<i64> {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

    if let Some(value) = number.as_i64() {
        return (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER)
            .contains(&value)
            .then_some(value);
    }
    if let Some(value) = number.as_u64() {
        return (value <= MAX_SAFE_INTEGER as u64).then_some(value as i64);
    }
    let value = number.as_f64()?;
    (value.is_finite()
        && value.fract() == 0.0
        && value >= -(MAX_SAFE_INTEGER as f64)
        && value <= MAX_SAFE_INTEGER as f64)
        .then_some(value as i64)
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(untagged)]
pub enum ScalarOrEntityReference {
    String(String),
    EntityReference(EntityReferenceValue),
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BucketValue {
    pub form: BucketForm,
    pub scheme: String,
    pub bucket: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BucketForm {
    DateBucket,
    TimeBucket,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityReferenceValue {
    pub form: EntityReferenceForm,
    pub reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EntityReferenceForm {
    AudienceScopedEntityReference,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StructuredValue {
    pub form: StructuredValueForm,
    pub schema: String,
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StructuredValueForm {
    ReviewedStructuredValue,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FlattenedJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// Self-identifying unsigned response envelope. It deliberately does not
/// serialize as the signed Evidence payload by itself and carries no JWS
/// member, so the strict JWS verifier rejects it.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsignedEvidenceEnvelope {
    pub schema: String,
    #[serde(rename = "type")]
    pub envelope_type: UnsignedEnvelopeType,
    pub integrity_protection: UnsignedIntegrityProtection,
    pub warning: UnsignedEnvelopeWarning,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
pub enum UnsignedEnvelopeType {
    UnsignedEvidenceEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum UnsignedIntegrityProtection {
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum UnsignedEnvelopeWarning {
    NotCryptographicallyVerifiable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct JwksDocument {
    pub keys: Vec<Value>,
}

/// Replace the derived `Debug` of a wire type with a redacted placeholder so
/// disclosed material cannot reach a log line, a panic message, or a snapshot.
#[macro_export]
macro_rules! redacted_debug {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl ::core::fmt::Debug for $type_name {
                fn fmt(
                    &self,
                    formatter: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    formatter
                        .debug_struct(stringify!($type_name))
                        .field("protected", &"<redacted>")
                        .finish()
                }
            }
        )+
    };
}

redacted_debug!(
    HolderPublicKey,
    Evidence,
    SubjectBinding,
    SupportedValue,
    PublicValue,
    ScalarOrEntityReference,
    BucketValue,
    EntityReferenceValue,
    StructuredValue,
    FlattenedJws,
    UnsignedEvidenceEnvelope,
);
