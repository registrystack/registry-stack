use std::{collections::BTreeMap, fmt};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};
use utoipa::ToSchema;

/// Exact encoded length of the required caller-generated request nonce: the
/// canonical unpadded base64url form of 32 random bytes.
pub const REQUEST_NONCE_ENCODED_LENGTH: usize = 43;
const REQUEST_NONCE_DECODED_LENGTH: usize = 32;

/// Deterministic canonical nonce for offline fixture evaluation and internal
/// non-released request shapes. Real callers generate a fresh random value
/// for every request.
pub const OFFLINE_EVALUATION_REQUEST_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Accept only the canonical 43-character unpadded base64url encoding of
/// exactly 32 bytes. Padding, wrong length, non-alphabet bytes, and a
/// noncanonical final symbol all fail.
pub fn request_nonce_is_canonical(nonce: &str) -> bool {
    if nonce.len() != REQUEST_NONCE_ENCODED_LENGTH
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(nonce) {
        Ok(decoded) => decoded.len() == REQUEST_NONCE_DECODED_LENGTH,
        Err(_) => false,
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequest {
    /// Uninterpreted caller-generated correlation nonce. It is echoed into the
    /// Evidence payload and never reaches authorization, rate limits, Rhai,
    /// source requests, logs, metrics, traces, or native audit.
    pub request_nonce: String,
    pub requirement: String,
    pub purpose: String,
    /// Unordered role set encoded as an array. Roles are resolved by name and
    /// canonicalized to requirement declaration order.
    pub subjects: Vec<RequestedSubject>,
    /// Optional holder public key echoed into the SD-JWT VC `cnf` claim. It is
    /// meaningful only for the SD-JWT VC response format, never reaches
    /// authorization, selectors, Rhai, source requests, or audit, and never
    /// appears in the signed-JWS payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<HolderPublicKey>,
}

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

/// Requester-scoped descriptions of the exact Evidence request shapes that
/// the authenticated caller can currently invoke.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinitions {
    pub schema: String,
    pub configuration_revision: String,
    pub issued_by: String,
    pub provided_by: String,
    pub definitions: Vec<EvidenceDefinition>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinition {
    pub requirement: String,
    pub kind: String,
    pub evidence_type: String,
    pub purpose: String,
    pub reference_frameworks: Vec<String>,
    pub subjects: Vec<EvidenceDefinitionSubject>,
    pub concepts: Vec<EvidenceDefinitionConcept>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDefinitionSubject {
    pub role: String,
    pub cardinality: String,
    pub selector: EvidenceDefinitionSelector,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinitionSelector {
    pub profile: String,
    pub value_origin: String,
    pub fields: Vec<EvidenceSelectorField>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinitionConcept {
    pub id: String,
    pub form: String,
}

/// Public validation metadata for a selector field. Controlled-code
/// definitions expose their governed scheme identity, never the bundle path or
/// the configured list of supported values.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EvidenceSelectorField {
    String {
        name: String,
        #[serde(rename = "minimumBytes")]
        minimum_bytes: u64,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
    Date {
        name: String,
    },
    Integer {
        name: String,
        minimum: i64,
        maximum: i64,
    },
    Boolean {
        name: String,
    },
    ControlledCode {
        name: String,
        scheme: String,
        version: String,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestedSubject {
    pub role: String,
    pub selector: RequestedSelector,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestedSelector {
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<BTreeMap<String, SelectorValue>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema, ToSchema)]
#[serde(untagged)]
pub enum SelectorValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
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

impl<'de> Deserialize<'de> for SelectorValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::String(value) => Ok(Self::String(value)),
            Value::Number(value) => safe_json_integer(&value)
                .map(Self::Integer)
                .ok_or_else(|| de::Error::custom("selector number is not a safe JSON integer")),
            Value::Bool(value) => Ok(Self::Boolean(value)),
            _ => Err(de::Error::custom("selector value is not a scalar")),
        }
    }
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

fn safe_json_integer(number: &Number) -> Option<i64> {
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProblemBody {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    pub operation: String,
}

#[derive(Clone, PartialEq)]
pub enum LookupResult {
    Match(BTreeMap<String, Value>),
    NoMatch,
    Ambiguous,
}

macro_rules! redacted_debug {
    ($($type_name:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type_name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    EvidenceRequest,
    HolderPublicKey,
    EvidenceDefinitions,
    EvidenceDefinition,
    EvidenceDefinitionSubject,
    EvidenceDefinitionSelector,
    EvidenceDefinitionConcept,
    EvidenceSelectorField,
    RequestedSubject,
    RequestedSelector,
    SelectorValue,
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
    LookupResult,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_integer_lexical_forms_canonicalize_to_safe_i64() {
        for input in ["1", "1.0", "1e0"] {
            assert_eq!(
                serde_json::from_str::<SelectorValue>(input).expect("selector integer parses"),
                SelectorValue::Integer(1)
            );
            let public = serde_json::from_str::<PublicValue>(input).expect("public integer parses");
            assert_eq!(public, PublicValue::Integer(1));
            assert_eq!(
                serde_json::to_string(&public).expect("integer serializes"),
                "1"
            );
        }
        for input in ["1.5", "9007199254740992", "-9007199254740992"] {
            assert!(serde_json::from_str::<SelectorValue>(input).is_err());
            assert!(serde_json::from_str::<PublicValue>(input).is_err());
        }
    }

    #[test]
    fn request_rejects_query_material_and_unknown_fields() {
        let input = serde_json::json!({
            "requestNonce": "A".repeat(43),
            "requirement": "urn:example:requirement:v1",
            "purpose": "casework",
            "subjects": [{
                "role": "subject",
                "selector": {"profile": "profile-v1", "values": {"opaque": "value"}}
            }],
            "threshold": 18
        });
        assert!(serde_json::from_value::<EvidenceRequest>(input).is_err());

        let caller_grant_reference = serde_json::json!({
            "requestNonce": "A".repeat(43),
            "requirement": "urn:example:requirement:v1",
            "purpose": "casework",
            "grantId": "caller-selected-grant",
            "grantAuthority": "caller-selected-authority",
            "subjects": [{
                "role": "subject",
                "selector": {"profile": "profile-v1", "values": {"opaque": "value"}}
            }]
        });
        assert!(serde_json::from_value::<EvidenceRequest>(caller_grant_reference).is_err());

        let missing_nonce = serde_json::json!({
            "requirement": "urn:example:requirement:v1",
            "purpose": "casework",
            "subjects": [{
                "role": "subject",
                "selector": {"profile": "profile-v1", "values": {"opaque": "value"}}
            }]
        });
        assert!(serde_json::from_value::<EvidenceRequest>(missing_nonce).is_err());
    }

    #[test]
    fn request_nonce_canonicality_is_exact() {
        assert!(request_nonce_is_canonical(
            "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I"
        ));
        assert!(request_nonce_is_canonical(&"A".repeat(43)));

        let noncanonical_final_symbol = format!("{}B", "A".repeat(42));
        for invalid in [
            "",
            "short",
            &"A".repeat(42),
            &"A".repeat(44),
            &format!("{}=", "A".repeat(42)),
            &format!("{}+", "A".repeat(42)),
            &format!("{}/", "A".repeat(42)),
            &format!("{} ", "A".repeat(42)),
            &format!("{}\u{e9}", "A".repeat(42)),
            noncanonical_final_symbol.as_str(),
        ] {
            assert!(!request_nonce_is_canonical(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn evidence_has_no_selector_echo_field() {
        let serialized = serde_json::to_value(Evidence {
            schema: crate::EVIDENCE_SCHEMA_V1.to_string(),
            request_nonce: "A".repeat(43),
            id: "urn:ulid:01K1EXAMPLE0000000000000000".to_string(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "urn:example:requirement:v1".to_string(),
            is_conformant_to: "urn:example:evidence-type:v1".to_string(),
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
                binding: format!("urn:evidence:subject:v1_{}", "a".repeat(43)),
            }],
            supported_values: vec![SupportedValue {
                provides_value_for: "urn:example:concept".to_string(),
                value: PublicValue::Boolean(true),
            }],
        })
        .expect("evidence serializes");
        let text = serialized.to_string();
        assert!(!text.contains("selector"));
        assert!(!text.contains("opaque"));
    }

    #[test]
    fn debug_surfaces_redact_requests_facts_disclosures_and_signed_payloads() {
        let request = EvidenceRequest {
            request_nonce: "protected-request-nonce-canary".to_owned(),
            requirement: "urn:example:protected-requirement-canary".to_owned(),
            purpose: "protected-purpose-canary".to_owned(),
            subjects: vec![RequestedSubject {
                role: "subject".to_owned(),
                selector: RequestedSelector {
                    profile: "protected-profile-canary".to_owned(),
                    values: Some(BTreeMap::from([(
                        "protected-field-canary".to_owned(),
                        SelectorValue::String("protected-selector-canary".to_owned()),
                    )])),
                },
            }],
            holder_key: None,
        };
        let evidence = Evidence {
            schema: "protected-schema-canary".to_owned(),
            request_nonce: "protected-request-nonce-canary".to_owned(),
            id: "protected-evidence-id-canary".to_owned(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "protected-requirement-canary".to_owned(),
            is_conformant_to: "protected-evidence-type-canary".to_owned(),
            issued_by: "protected-issuer-canary".to_owned(),
            provided_by: "protected-provider-canary".to_owned(),
            issued_at: "2026-08-02T00:00:00Z".to_owned(),
            observed_at: "2026-08-02T00:00:00Z".to_owned(),
            valid_until: "2026-08-03T00:00:00Z".to_owned(),
            purpose: "protected-purpose-canary".to_owned(),
            audience: "protected-audience-canary".to_owned(),
            configuration_revision: "protected-revision-canary".to_owned(),
            subjects: vec![SubjectBinding {
                role: "subject".to_owned(),
                binding: "protected-binding-canary".to_owned(),
            }],
            supported_values: vec![SupportedValue {
                provides_value_for: "protected-concept-canary".to_owned(),
                value: PublicValue::String("protected-supported-value-canary".to_owned()),
            }],
        };
        let lookup = LookupResult::Match(BTreeMap::from([(
            "protected-fact-name-canary".to_owned(),
            serde_json::json!("protected-fact-value-canary"),
        )]));
        let signed = FlattenedJws {
            protected: "protected-header-canary".to_owned(),
            payload: "protected-payload-canary".to_owned(),
            signature: "protected-signature-canary".to_owned(),
        };
        let definitions = EvidenceDefinitions {
            schema: "protected-discovery-schema-canary".to_owned(),
            configuration_revision: "protected-discovery-revision-canary".to_owned(),
            issued_by: "protected-discovery-issuer-canary".to_owned(),
            provided_by: "protected-discovery-provider-canary".to_owned(),
            definitions: Vec::new(),
        };

        let unsigned_envelope = UnsignedEvidenceEnvelope {
            schema: crate::EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1.to_owned(),
            envelope_type: UnsignedEnvelopeType::UnsignedEvidenceEnvelope,
            integrity_protection: UnsignedIntegrityProtection::None,
            warning: UnsignedEnvelopeWarning::NotCryptographicallyVerifiable,
            evidence: evidence.clone(),
        };

        for diagnostic in [
            format!("{request:?}"),
            format!("{definitions:?}"),
            format!("{unsigned_envelope:?}"),
            format!(
                "{:?}",
                SelectorValue::String("protected-selector-canary".to_owned())
            ),
            format!("{evidence:?}"),
            format!(
                "{:?}",
                PublicValue::String("protected-supported-value-canary".to_owned())
            ),
            format!("{lookup:?}"),
            format!("{signed:?}"),
        ] {
            assert!(diagnostic.contains("<redacted>"));
            assert!(!diagnostic.contains("canary"));
        }
    }
}
