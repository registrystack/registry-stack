use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_evidence_verifier::{model::safe_json_integer, redacted_debug};
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::config::AssuranceProfile;

/// The response-side wire types are owned by the portable
/// `registry-evidence-verifier` crate and served here at the runtime's own
/// paths, beside the request-side types that only the runtime needs.
pub use registry_evidence_verifier::model::{
    BucketForm, BucketValue, EntityReferenceForm, EntityReferenceValue, Evidence,
    EvidenceObjectType, FlattenedJws, HolderPublicKey, JwksDocument, PublicValue,
    ScalarOrEntityReference, StructuredValue, StructuredValueForm, SubjectBinding,
    SubjectBindingMode, SupportedValue, UnsignedEnvelopeType, UnsignedEnvelopeWarning,
    UnsignedEvidenceEnvelope, UnsignedIntegrityProtection,
};

/// Exact encoded length of the required caller-generated request nonce: the
/// canonical unpadded base64url form of 32 random bytes.
pub const REQUEST_NONCE_ENCODED_LENGTH: usize = 43;
const REQUEST_NONCE_DECODED_LENGTH: usize = 32;

/// Deterministic canonical nonce for offline fixture evaluation and internal
/// non-released request shapes. Real callers generate a fresh random value
/// for every request.
pub const OFFLINE_EVALUATION_REQUEST_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Deterministic stand-in holder key for offline fixture evaluation, the
/// counterpart of the canonical offline nonce above.
///
/// A holder-bound requirement resolves its subject scope from a presented
/// holder key, so an offline caller that presented none could not evaluate such
/// a requirement's cases at all. This supplies one, and only there: nothing
/// reads it on a served request path, where the key always comes from the
/// caller.
///
/// The coordinates are the P-256 generator point. That is a deliberate choice
/// over a freshly generated key: the generator is a published constant that
/// belongs to nobody, so this cannot be mistaken for key material anyone holds,
/// exactly as the all-zero nonce above cannot be mistaken for a real nonce. It
/// is still a well-formed public point, so binding derivation, thumbprinting,
/// and confirmation all behave as they do for a caller-supplied key.
pub fn offline_evaluation_holder_key() -> HolderPublicKey {
    HolderPublicKey {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY".to_owned(),
        y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU".to_owned(),
        alg: Some("ES256".to_owned()),
        kid: None,
    }
}

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
    /// Holder public keys, each echoed into the `cnf` claim of the credential
    /// issued for it. A single-credential request is an array of one, and an
    /// empty array is the same as none at all.
    ///
    /// The keys are meaningful only to the credential response formats and
    /// never appear in the signed-JWS payload. They never reach Rhai, source
    /// requests, or audit. Under a holder-bound requirement each key's RFC 7638
    /// thumbprint scopes the subject binding of that key's own credential, so a
    /// thumbprint reaches subject scope resolution and nothing downstream of
    /// it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holder_keys: Vec<HolderPublicKey>,
}

/// Issuance container for a holder-bound release carrying one SD-JWT VC
/// serialization per presented holder key.
///
/// It is issuance-only. Nothing consumes it at verification: a relying party
/// receives one member and verifies it as an ordinary holder-bound credential.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SdJwtVcBatchEnvelope {
    pub schema: String,
    #[serde(rename = "type")]
    pub envelope_type: SdJwtVcBatchEnvelopeType,
    /// One combined SD-JWT VC issuance serialization per presented holder key,
    /// in the order the keys were presented.
    pub credentials: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
pub enum SdJwtVcBatchEnvelopeType {
    SdJwtVcBatchEnvelope,
}

/// Requester-scoped descriptions of the exact Evidence request shapes that
/// the authenticated caller can currently invoke.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinitions {
    pub schema: String,
    pub assurance_profile: AssuranceProfile,
    pub issued_by: String,
    pub provided_by: String,
    pub definitions: Vec<EvidenceDefinition>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinition {
    pub requirement: String,
    /// The revision an assertion for this requirement carries. It covers this
    /// requirement's own configuration and artifact closure, so a relying party
    /// pins one requirement without depending on the rest of the deployment.
    pub configuration_revision: String,
    pub kind: String,
    /// What the subject bindings in this requirement's assertions are derived
    /// under. Omitted for audience-scoped, the mode every requirement already
    /// had, so a definition written before binding modes existed keeps
    /// exactly the response it already served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_binding_mode: Option<SubjectBindingMode>,
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

redacted_debug!(
    EvidenceRequest,
    EvidenceDefinitions,
    EvidenceDefinition,
    EvidenceDefinitionSubject,
    EvidenceDefinitionSelector,
    EvidenceDefinitionConcept,
    EvidenceSelectorField,
    RequestedSubject,
    RequestedSelector,
    SelectorValue,
    LookupResult,
    SdJwtVcBatchEnvelope,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offline_stand_in_holder_key_is_a_key_the_request_boundary_would_accept() {
        // Offline evaluation resolves a holder-bound subject scope from this
        // key, so a key the served boundary would reject would make offline
        // evaluation exercise a shape no request could ever present.
        let key = offline_evaluation_holder_key();
        assert!(key.is_acceptable());
        assert!(
            registry_evidence_verifier::sdjwt_vc::holder_thumbprint(&key).is_ok(),
            "the offline stand-in key has no RFC 7638 thumbprint to bind under"
        );
    }

    #[test]
    fn holder_public_key_rejects_coordinates_that_are_not_on_p256() {
        let key = HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: "A".repeat(43),
            y: "A".repeat(43),
            alg: Some("ES256".to_owned()),
            kid: Some("wallet-owned-key-7".to_owned()),
        };

        assert!(!key.is_acceptable());
    }

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
            assurance_profile: AssuranceProfile::EvidenceGrade,
            subject_binding: SubjectBindingMode::AudienceScoped,
            request_nonce: Some("A".repeat(43)),
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
            audience: Some("urn:example:audience".to_string()),
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
            holder_keys: Vec::new(),
        };
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
            issued_at: "2026-08-02T00:00:00Z".to_owned(),
            observed_at: "2026-08-02T00:00:00Z".to_owned(),
            valid_until: "2026-08-03T00:00:00Z".to_owned(),
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
            assurance_profile: AssuranceProfile::EvidenceGrade,
            issued_by: "protected-discovery-issuer-canary".to_owned(),
            provided_by: "protected-discovery-provider-canary".to_owned(),
            definitions: vec![EvidenceDefinition {
                requirement: "protected-discovery-requirement-canary".to_owned(),
                configuration_revision: "protected-discovery-revision-canary".to_owned(),
                kind: "protected-discovery-kind-canary".to_owned(),
                subject_binding_mode: None,
                evidence_type: "protected-discovery-type-canary".to_owned(),
                purpose: "protected-discovery-purpose-canary".to_owned(),
                reference_frameworks: vec!["protected-discovery-framework-canary".to_owned()],
                subjects: Vec::new(),
                concepts: Vec::new(),
            }],
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
