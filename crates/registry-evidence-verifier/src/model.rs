//! Response-side wire types: the Evidence payload, its public value forms, and
//! the three response serializations a relying party can receive.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::VerifyingKey;
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};
use utoipa::ToSchema;

use crate::AssuranceProfile;

/// Caller-supplied P-256 holder public key. `deny_unknown_fields` is the
/// primary defence against private key members: a body carrying `d` or any
/// other unexpected member fails to parse.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HolderPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Exact byte length of each P-256 affine coordinate.
const HOLDER_KEY_DECODED_LENGTH: usize = 32;
const MAX_HOLDER_KEY_ID_BYTES: usize = 256;

impl HolderPublicKey {
    /// Accept only a public EC P-256 JWK whose coordinates are canonical
    /// unpadded base64url encodings of exactly 32 bytes and form a curve point.
    pub fn is_acceptable(&self) -> bool {
        if self.kty != "EC" || self.crv != "P-256" {
            return false;
        }
        if self.alg.as_deref().is_some_and(|alg| alg != "ES256") {
            return false;
        }
        if self
            .kid
            .as_deref()
            .is_some_and(|kid| kid.is_empty() || kid.len() > MAX_HOLDER_KEY_ID_BYTES)
        {
            return false;
        }
        let Ok(x) = URL_SAFE_NO_PAD.decode(&self.x) else {
            return false;
        };
        let Ok(y) = URL_SAFE_NO_PAD.decode(&self.y) else {
            return false;
        };
        if x.len() != HOLDER_KEY_DECODED_LENGTH || y.len() != HOLDER_KEY_DECODED_LENGTH {
            return false;
        }
        let mut encoded = Vec::with_capacity(65);
        encoded.push(0x04);
        encoded.extend_from_slice(&x);
        encoded.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&encoded).is_ok()
    }
}

/// What the subject bindings in an assertion are derived under.
///
/// An audience-scoped assertion names the one relying party that may act on it.
/// A holder-bound assertion names no relying party at all: its bindings are
/// derived under the holder key, so possession of that key rather than an
/// audience match is what a verifier checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectBindingMode {
    AudienceScoped,
    HolderBound,
}

/// An assertion whose declared binding mode does not agree with the members it
/// carries. The two are correlated in code rather than in the payload schema,
/// because a closed single-object contract cannot express the implication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubjectBindingShapeError {
    #[error("an audience-scoped assertion must carry an audience and a request nonce")]
    AudienceScopedMembersMissing,
    #[error("a holder-bound assertion must carry no audience and no request nonce")]
    HolderBoundMembersPresent,
}

/// Refuse an assertion whose binding mode and members disagree.
///
/// Called at issuance and at every verification entry point, so neither side
/// can accept an assertion that names a relying party it is not scoped to, nor
/// one that silently drops the audience it was scoped to.
pub fn validate_subject_binding_shape(evidence: &Evidence) -> Result<(), SubjectBindingShapeError> {
    match evidence.subject_binding {
        SubjectBindingMode::AudienceScoped => {
            if evidence.audience.is_none() || evidence.request_nonce.is_none() {
                return Err(SubjectBindingShapeError::AudienceScopedMembersMissing);
            }
        }
        SubjectBindingMode::HolderBound => {
            if evidence.audience.is_some() || evidence.request_nonce.is_some() {
                return Err(SubjectBindingShapeError::HolderBoundMembersPresent);
            }
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub assurance_profile: AssuranceProfile,
    /// What the subject bindings below are derived under. Always present, so a
    /// verifier never has to infer the mode from which members are absent.
    pub subject_binding: SubjectBindingMode,
    /// Exact echo of the caller's request nonce for request-response
    /// correlation. The runtime does not store it or reject reuse. Absent from
    /// a holder-bound assertion, which has no single request to correlate to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_nonce: Option<String>,
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
    /// The one relying party an audience-scoped assertion is issued to. Absent
    /// from a holder-bound assertion, which names no relying party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every wire type this crate declares takes its `Debug` from
    /// `redacted_debug!`, so a verified payload cannot leak disclosed material
    /// into a log line, a panic message, or a snapshot. Each value below is
    /// built from canary strings that must not survive formatting.
    #[test]
    fn debug_surfaces_redact_every_wire_type_this_crate_owns() {
        let evidence = Evidence {
            schema: "protected-schema-canary".to_owned(),
            assurance_profile: AssuranceProfile::EvidenceGrade,
            subject_binding: SubjectBindingMode::AudienceScoped,
            request_nonce: Some("protected-request-nonce-canary".to_owned()),
            id: "protected-evidence-id-canary".to_owned(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "protected-requirement-canary".to_owned(),
            is_conformant_to: "protected-evidence-type-canary".to_owned(),
            issued_by: "protected-issuer-canary".to_owned(),
            provided_by: "protected-provider-canary".to_owned(),
            issued_at: "2026-08-05T00:00:00Z".to_owned(),
            observed_at: "2026-08-05T00:00:00Z".to_owned(),
            valid_until: "2026-08-06T00:00:00Z".to_owned(),
            purpose: "protected-purpose-canary".to_owned(),
            audience: Some("protected-audience-canary".to_owned()),
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
        let holder_key = HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: "protected-holder-coordinate-canary".to_owned(),
            y: "protected-holder-y-coordinate-canary".to_owned(),
            alg: Some("ES256".to_owned()),
            kid: Some("protected-holder-key-id-canary".to_owned()),
        };
        let bucket = BucketValue {
            form: BucketForm::DateBucket,
            scheme: "protected-bucket-scheme-canary".to_owned(),
            bucket: "protected-bucket-canary".to_owned(),
        };
        let entity_reference = EntityReferenceValue {
            form: EntityReferenceForm::AudienceScopedEntityReference,
            reference: "protected-reference-canary".to_owned(),
        };
        let structured = StructuredValue {
            form: StructuredValueForm::ReviewedStructuredValue,
            schema: "protected-structured-schema-canary".to_owned(),
            fields: BTreeMap::from([(
                "protected-field-name-canary".to_owned(),
                Value::String("protected-field-value-canary".to_owned()),
            )]),
        };
        let signed = FlattenedJws {
            protected: "protected-header-canary".to_owned(),
            payload: "protected-payload-canary".to_owned(),
            signature: "protected-signature-canary".to_owned(),
        };
        // The envelope's other fields are enum discriminants and a nested
        // `Evidence` that redacts itself, so only a canary here makes the
        // envelope's own redaction load-bearing.
        let unsigned_envelope = UnsignedEvidenceEnvelope {
            schema: "protected-envelope-schema-canary".to_owned(),
            envelope_type: UnsignedEnvelopeType::UnsignedEvidenceEnvelope,
            integrity_protection: UnsignedIntegrityProtection::None,
            warning: UnsignedEnvelopeWarning::NotCryptographicallyVerifiable,
            evidence: evidence.clone(),
        };

        for diagnostic in [
            format!("{holder_key:?}"),
            format!("{evidence:?}"),
            format!("{:?}", evidence.subjects[0]),
            format!("{:?}", evidence.supported_values[0]),
            format!(
                "{:?}",
                PublicValue::String("protected-supported-value-canary".to_owned())
            ),
            format!(
                "{:?}",
                ScalarOrEntityReference::String("protected-list-item-canary".to_owned())
            ),
            format!("{bucket:?}"),
            format!("{entity_reference:?}"),
            format!("{structured:?}"),
            format!("{signed:?}"),
            format!("{unsigned_envelope:?}"),
        ] {
            assert!(diagnostic.contains("<redacted>"), "{diagnostic}");
            assert!(!diagnostic.contains("canary"), "{diagnostic}");
        }
    }

    fn shaped_evidence(mode: SubjectBindingMode) -> Evidence {
        Evidence {
            schema: crate::EVIDENCE_SCHEMA_V1.to_owned(),
            assurance_profile: AssuranceProfile::Production,
            subject_binding: mode,
            request_nonce: None,
            id: "urn:evidence:assertion:v1_2f0a".to_owned(),
            evidence_type_name: EvidenceObjectType::Evidence,
            supports_requirement: "urn:example:requirement".to_owned(),
            is_conformant_to: "urn:example:evidence-type".to_owned(),
            issued_by: "urn:example:issuer".to_owned(),
            provided_by: "urn:example:provider".to_owned(),
            issued_at: "2026-08-05T00:00:00Z".to_owned(),
            observed_at: "2026-08-05T00:00:00Z".to_owned(),
            valid_until: "2026-08-06T00:00:00Z".to_owned(),
            purpose: "enrolment".to_owned(),
            audience: None,
            configuration_revision: "sha256:00".to_owned(),
            subjects: vec![SubjectBinding {
                role: "subject".to_owned(),
                binding: "urn:evidence:subject:v1_aaaa".to_owned(),
            }],
            supported_values: vec![SupportedValue {
                provides_value_for: "urn:example:concept".to_owned(),
                value: PublicValue::Boolean(true),
            }],
        }
    }

    /// The payload contract is one closed object, so the correlation between
    /// the declared mode and the members that mode implies is enforced here.
    #[test]
    fn the_declared_binding_mode_must_agree_with_the_members_carried() {
        let mut audience_scoped = shaped_evidence(SubjectBindingMode::AudienceScoped);
        assert_eq!(
            validate_subject_binding_shape(&audience_scoped),
            Err(SubjectBindingShapeError::AudienceScopedMembersMissing)
        );
        audience_scoped.audience = Some("https://relying.example/service".to_owned());
        assert_eq!(
            validate_subject_binding_shape(&audience_scoped),
            Err(SubjectBindingShapeError::AudienceScopedMembersMissing)
        );
        audience_scoped.request_nonce = Some("A".repeat(43));
        assert_eq!(validate_subject_binding_shape(&audience_scoped), Ok(()));

        let mut missing_nonce = audience_scoped.clone();
        missing_nonce.request_nonce = None;
        assert_eq!(
            validate_subject_binding_shape(&missing_nonce),
            Err(SubjectBindingShapeError::AudienceScopedMembersMissing)
        );

        let holder_bound = shaped_evidence(SubjectBindingMode::HolderBound);
        assert_eq!(validate_subject_binding_shape(&holder_bound), Ok(()));

        let mut leftover_audience = holder_bound.clone();
        leftover_audience.audience = Some("https://relying.example/service".to_owned());
        assert_eq!(
            validate_subject_binding_shape(&leftover_audience),
            Err(SubjectBindingShapeError::HolderBoundMembersPresent)
        );

        let mut leftover_nonce = holder_bound.clone();
        leftover_nonce.request_nonce = Some("A".repeat(43));
        assert_eq!(
            validate_subject_binding_shape(&leftover_nonce),
            Err(SubjectBindingShapeError::HolderBoundMembersPresent)
        );
    }

    /// The mode is a payload member with a stable wire spelling, so a verifier
    /// never infers it from which members are absent.
    #[test]
    fn the_binding_mode_serializes_to_its_contract_spelling() {
        assert_eq!(
            serde_json::to_value(SubjectBindingMode::AudienceScoped).expect("serializes"),
            Value::String("audience-scoped".to_owned())
        );
        assert_eq!(
            serde_json::to_value(SubjectBindingMode::HolderBound).expect("serializes"),
            Value::String("holder-bound".to_owned())
        );
    }

    /// A holder-bound assertion names no relying party, so neither member may
    /// survive serialization as an explicit null.
    #[test]
    fn a_holder_bound_payload_omits_the_audience_and_request_nonce() {
        let rendered = serde_json::to_value(shaped_evidence(SubjectBindingMode::HolderBound))
            .expect("serializes");
        let object = rendered.as_object().expect("object");
        assert!(!object.contains_key("audience"));
        assert!(!object.contains_key("requestNonce"));
        assert_eq!(
            object.get("subjectBinding"),
            Some(&Value::String("holder-bound".to_owned()))
        );
    }
}
