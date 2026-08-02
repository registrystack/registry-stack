//! Strict verifier for the Evidence Version 1 flattened JWS profile.

use std::{collections::BTreeMap, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use registry_platform_crypto::{parse_json_strict, verify, PublicJwk, SigningAlgorithm};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    contracts::evidence_contract_accepts,
    model::{Evidence, FlattenedJws, JwksDocument},
    EVIDENCE_JWS_CTY, EVIDENCE_JWS_TYP, EVIDENCE_SCHEMA_V1,
};

const MAX_JWS_BYTES: usize = 256 * 1024;
const MAX_PROTECTED_BYTES: usize = 8 * 1024;
const MAX_PAYLOAD_BYTES: usize = 128 * 1024;
const MAX_TRUSTED_KEYS: usize = 33;

#[derive(Debug, Clone)]
pub struct EvidenceVerificationPolicy {
    pub issued_by: String,
    pub provided_by: String,
    pub requirement: String,
    pub evidence_type: String,
    pub purpose: String,
    pub audience: String,
    pub configuration_revision: String,
    pub now: DateTime<Utc>,
    pub clock_skew: Duration,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
    cty: String,
}

pub fn verify_flattened_jws(
    serialized_jws: &[u8],
    trusted_jwks: &JwksDocument,
    policy: &EvidenceVerificationPolicy,
) -> Result<Evidence, VerificationError> {
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
    if protected.alg != "EdDSA"
        || protected.typ != EVIDENCE_JWS_TYP
        || protected.cty != EVIDENCE_JWS_CTY
        || protected.kid.is_empty()
        || protected.kid.len() > 256
        || protected.kid.chars().any(char::is_control)
    {
        return Err(VerificationError::ProtectedHeader);
    }

    let keys = trusted_keys(trusted_jwks)?;
    let key = keys.get(&protected.kid).ok_or(VerificationError::Key)?;
    if key.algorithm().ok() != Some(SigningAlgorithm::EdDsa) {
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
    validate_policy(&evidence, policy)?;
    Ok(evidence)
}

fn trusted_keys(jwks: &JwksDocument) -> Result<BTreeMap<String, PublicJwk>, VerificationError> {
    if jwks.keys.is_empty() || jwks.keys.len() > MAX_TRUSTED_KEYS {
        return Err(VerificationError::Key);
    }
    let mut output = BTreeMap::new();
    for value in &jwks.keys {
        let key: PublicJwk =
            serde_json::from_value(value.clone()).map_err(|_| VerificationError::Key)?;
        let kid = key.kid.clone().ok_or(VerificationError::Key)?;
        if kid.is_empty()
            || kid.len() > 256
            || kid.chars().any(char::is_control)
            || key.algorithm().ok() != Some(SigningAlgorithm::EdDsa)
            || output.insert(kid, key).is_some()
        {
            return Err(VerificationError::Key);
        }
    }
    Ok(output)
}

fn validate_policy(
    evidence: &Evidence,
    policy: &EvidenceVerificationPolicy,
) -> Result<(), VerificationError> {
    if evidence.schema != EVIDENCE_SCHEMA_V1
        || evidence.issued_by != policy.issued_by
        || evidence.provided_by != policy.provided_by
        || evidence.supports_requirement != policy.requirement
        || evidence.is_conformant_to != policy.evidence_type
        || evidence.purpose != policy.purpose
        || evidence.audience != policy.audience
        || evidence.configuration_revision != policy.configuration_revision
        || evidence.subjects.is_empty()
        || evidence.supported_values.is_empty()
    {
        return Err(VerificationError::Policy);
    }

    let issued = parse_time(&evidence.issued_at)?;
    let observed = parse_time(&evidence.observed_at)?;
    let valid_until = parse_time(&evidence.valid_until)?;
    let skew =
        chrono::Duration::from_std(policy.clock_skew).map_err(|_| VerificationError::Time)?;
    let latest_acceptable_issue = policy
        .now
        .checked_add_signed(skew)
        .ok_or(VerificationError::Time)?;
    let expiration_with_skew = valid_until
        .checked_add_signed(skew)
        .ok_or(VerificationError::Time)?;
    if issued < observed
        || issued > latest_acceptable_issue
        || observed > latest_acceptable_issue
        || valid_until <= observed
        || valid_until <= issued
        || policy.now >= expiration_with_skew
    {
        return Err(VerificationError::Time);
    }
    Ok(())
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
    use std::sync::Arc;

    use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        model::{EvidenceObjectType, PublicValue, SubjectBinding, SupportedValue},
        signing::{jwks_document, EvidenceSigner},
    };

    const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"evidence-key-1"}"#;
    const RETIRED_PRIVATE_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"retired-evidence-key"}"#;

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

    fn fixture_evidence() -> Evidence {
        Evidence {
            schema: EVIDENCE_SCHEMA_V1.to_string(),
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
        let signer = EvidenceSigner::initialize(provider, "evidence-key-1")
            .await
            .expect("signer initializes");
        let jws = signer.sign_json(&evidence).await.expect("evidence signs");
        let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("JWKS builds");
        let policy = EvidenceVerificationPolicy {
            issued_by: evidence.issued_by,
            provided_by: evidence.provided_by,
            requirement: evidence.supports_requirement,
            evidence_type: evidence.is_conformant_to,
            purpose: evidence.purpose,
            audience: evidence.audience,
            configuration_revision: evidence.configuration_revision,
            now,
            clock_skew: Duration::from_secs(30),
        };
        (serialized, jwks, policy)
    }

    async fn signed_fixture() -> (Vec<u8>, JwksDocument, EvidenceVerificationPolicy) {
        signed_evidence(
            fixture_evidence(),
            "2026-08-02T12:00:00Z".parse().expect("time parses"),
        )
        .await
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
            "alg": "EdDSA",
            "kid": "evidence-key-1",
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY
        });
        let (_, _, policy) = signed_fixture().await;

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
                "algorithm mismatch",
                "signed payload violates the Evidence JSON Schema",
                "duplicate evidence object beside payload",
                "signing-provider failure",
            ]
        );

        let evidence = fixture_evidence();
        let base_header = json!({
            "alg": "EdDSA",
            "kid": "evidence-key-1",
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY
        });
        let (valid, public) =
            sign_with_protected_header(PRIVATE_JWK, base_header.clone(), &evidence).await;
        let jwks = jwks_document(public, []).expect("JWKS builds");
        let (_, _, policy) = signed_fixture().await;
        assert!(verify_flattened_jws(&valid, &jwks, &policy).is_ok());

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
            ("header", json!({"kid": "evidence-key-1"})),
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
                    "alg": "EdDSA", "kid": "unknown-key", "typ": EVIDENCE_JWS_TYP,
                    "cty": EVIDENCE_JWS_CTY
                }),
                VerificationError::Key,
            ),
            (
                json!({
                    "alg": "HS256", "kid": "evidence-key-1", "typ": EVIDENCE_JWS_TYP,
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
    async fn retired_public_key_verifies_only_while_published_and_payload_is_current() {
        let evidence = fixture_evidence();
        let header = json!({
            "alg": "EdDSA",
            "kid": "retired-evidence-key",
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
        let retired = (0..32).map(|index| {
            let mut key = active.clone();
            key.kid = Some(format!("retired-evidence-key-{index:02}"));
            key
        });
        let maximum = jwks_document(active.clone(), retired).expect("maximum JWKS builds");
        assert_eq!(maximum.keys.len(), MAX_TRUSTED_KEYS);
        assert!(verify_flattened_jws(&jws, &maximum, &policy).is_ok());

        let mut excess = maximum;
        let mut extra = active;
        extra.kid = Some("retired-evidence-key-excess".to_owned());
        excess
            .keys
            .push(serde_json::to_value(extra).expect("extra key serializes"));
        assert_eq!(
            verify_flattened_jws(&jws, &excess, &policy),
            Err(VerificationError::Key)
        );
    }
}
