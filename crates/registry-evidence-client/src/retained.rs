//! Self-contained verification state retained before a response exists.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use registry_evidence_verifier::{
    model::{Evidence, FlattenedJws, JwksDocument, SubjectBinding},
    verifier::{
        trusted_keys_are_usable, verify_flattened_jws, verify_sd_jwt_vc,
        EvidenceVerificationPolicyDocument, ExpectedSubjectDocument,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    client::VerifiedEvidence,
    error::EvidenceClientError,
    prepare::{PreparedEvidenceRequest, SubjectExpectations, MAXIMUM_SUBJECTS},
    response_format::EvidenceResponseFormat,
};

/// Schema identifier for a retained, self-contained verification context.
pub const RETAINED_EVIDENCE_VERIFICATION_SCHEMA_V1: &str =
    "registry.evidence-client.retained-verification/v1";

/// Maximum signed response size both portable verifiers accept.
const MAXIMUM_SIGNED_RESPONSE_BYTES: usize = 256 * 1024;

/// Trusted state sufficient to verify one retained response without I/O.
///
/// This document is created before the response exists. It includes the pinned
/// verification keys and every policy expectation, but deliberately excludes
/// the request's selector values.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedEvidenceVerification {
    schema: String,
    response_format: EvidenceResponseFormat,
    trusted_jwks: JwksDocument,
    verification_policy: EvidenceVerificationPolicyDocument,
    subject_expectation: RetainedSubjectExpectation,
}

impl std::fmt::Debug for RetainedEvidenceVerification {
    /// Opaque subject bindings and pinned key material are retained trust
    /// state, so diagnostics expose only the context's public shape.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedEvidenceVerification")
            .field("schema", &self.schema)
            .field("response_format", &self.response_format)
            .field("subject_expectation", &self.subject_expectation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum RetainedSubjectExpectation {
    Pinned,
    AcceptFirstUse { roles: Vec<String> },
}

impl RetainedEvidenceVerification {
    pub(crate) fn new(prepared: &PreparedEvidenceRequest, trusted_jwks: JwksDocument) -> Self {
        let subject_expectation = match prepared.subject_expectations() {
            SubjectExpectations::Pinned(_) => RetainedSubjectExpectation::Pinned,
            SubjectExpectations::AcceptFirstUse => RetainedSubjectExpectation::AcceptFirstUse {
                roles: prepared.requested_roles(),
            },
        };
        Self {
            schema: RETAINED_EVIDENCE_VERIFICATION_SCHEMA_V1.to_owned(),
            response_format: prepared.response_format(),
            trusted_jwks,
            verification_policy: prepared.policy_document().clone(),
            subject_expectation,
        }
    }

    /// Verify retained response bytes against this pre-response context.
    ///
    /// This operation is synchronous, offline, and idempotent. The returned
    /// value has no HTTP operation identifier because only response bytes were
    /// retained here.
    pub fn verify(&self, response: &[u8]) -> Result<VerifiedEvidence, EvidenceClientError> {
        self.verify_as_of(response, Utc::now())
    }

    /// Verify retained response bytes as of one caller-selected instant.
    ///
    /// This is the retained-record counterpart to
    /// [`crate::EvidenceClient::verify_as_of`]. A current decision should use
    /// [`Self::verify`] so an expired assertion is not accepted as current.
    pub fn verify_as_of(
        &self,
        response: &[u8],
        now: DateTime<Utc>,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        self.verify_with_revocations(response, now, None, None)
    }

    pub(crate) fn verify_with_revocations(
        &self,
        response: &[u8],
        now: DateTime<Utc>,
        revoked_key_ids: Option<&[String]>,
        operation: Option<String>,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        self.validate()?;
        let mut policy_document = self.verification_policy.clone();
        if let RetainedSubjectExpectation::AcceptFirstUse { roles } = &self.subject_expectation {
            let claimed = untrusted_subject_bindings(self.response_format, response);
            policy_document.expected_subjects = if covers_roles(roles, &claimed) {
                claimed
            } else {
                Vec::new()
            };
        }
        if let Some(revoked_key_ids) = revoked_key_ids {
            policy_document.revoked_key_ids = revoked_key_ids.to_vec();
        }
        let policy = policy_document.try_into_policy(now).map_err(|_| {
            EvidenceClientError::configuration(
                "the retained policy states a time bound the verification policy contract forbids",
            )
        })?;
        let evidence = match self.response_format {
            EvidenceResponseFormat::SignedJws => {
                verify_flattened_jws(response, &self.trusted_jwks, &policy)
            }
            EvidenceResponseFormat::SdJwtVc => {
                verify_sd_jwt_vc(response, &self.trusted_jwks, &policy)
            }
            // Unreachable: `validate` refuses the batch format above, so the
            // caller is told what it did rather than shown a parse failure for
            // an envelope nothing was ever going to verify.
            EvidenceResponseFormat::SdJwtVcBatch => return Err(batch_is_not_one_response()),
        }
        .map_err(EvidenceClientError::Verification)?;
        Ok(VerifiedEvidence {
            evidence,
            operation,
        })
    }

    fn validate(&self) -> Result<(), EvidenceClientError> {
        // A batch is packaging, not a response with a verdict. Refusing here
        // covers every verification entry point, including this crate's client,
        // so the category error is named once and named early.
        if !self.response_format.is_verifiable_alone() {
            return Err(batch_is_not_one_response());
        }
        if self.schema != RETAINED_EVIDENCE_VERIFICATION_SCHEMA_V1 {
            return Err(EvidenceClientError::configuration(
                "the retained verification context schema is not supported",
            ));
        }
        trusted_keys_are_usable(&self.trusted_jwks).map_err(EvidenceClientError::Verification)?;
        match &self.subject_expectation {
            RetainedSubjectExpectation::Pinned => {
                if self.verification_policy.expected_subjects.is_empty() {
                    return Err(EvidenceClientError::configuration(
                        "the retained pinned subject expectation is empty",
                    ));
                }
            }
            RetainedSubjectExpectation::AcceptFirstUse { roles } => {
                let unique = roles.iter().collect::<BTreeSet<_>>();
                if !self.verification_policy.expected_subjects.is_empty()
                    || roles.is_empty()
                    || roles.len() > MAXIMUM_SUBJECTS
                    || unique.len() != roles.len()
                {
                    return Err(EvidenceClientError::configuration(
                        "the retained first-use subject expectation is inconsistent",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A caller asked to verify a batch envelope as though it were one response.
///
/// The envelope carries no signature and makes no assertion, so there is no
/// verdict to reach about it. The failure says what to do instead, because a
/// caller here is one step away from being right: split the envelope, then
/// verify each credential under the singular format it is.
fn batch_is_not_one_response() -> EvidenceClientError {
    EvidenceClientError::configuration(
        "a batch envelope is issuance packaging, not one verifiable response: read it with \
         SdJwtVcBatchResponse and verify each credential individually",
    )
}

fn covers_roles(roles: &[String], claimed: &[ExpectedSubjectDocument]) -> bool {
    claimed.len() == roles.len()
        && roles.iter().all(|role| {
            claimed
                .iter()
                .filter(|subject| subject.role == *role)
                .count()
                == 1
        })
}

/// Read claimed role-bound bindings only so first-use acceptance can turn them
/// into expectations for the ordinary strict verifier. Nothing returned here
/// is trusted unless that later verification succeeds.
fn untrusted_subject_bindings(
    format: EvidenceResponseFormat,
    response: &[u8],
) -> Vec<ExpectedSubjectDocument> {
    if response.is_empty() || response.len() > MAXIMUM_SIGNED_RESPONSE_BYTES {
        return Vec::new();
    }
    let subjects = match format {
        EvidenceResponseFormat::SignedJws => untrusted_jws_subjects(response),
        EvidenceResponseFormat::SdJwtVc => untrusted_sd_jwt_vc_subjects(response),
        // Unreachable: verification refuses the batch format before reaching
        // here. Claiming no binding is the safe answer regardless, because an
        // empty claim can only narrow first-use acceptance, never widen it.
        EvidenceResponseFormat::SdJwtVcBatch => None,
    };
    subjects
        .unwrap_or_default()
        .into_iter()
        .map(|subject| ExpectedSubjectDocument {
            role: subject.role,
            binding: subject.binding,
        })
        .collect()
}

fn untrusted_jws_subjects(response: &[u8]) -> Option<Vec<SubjectBinding>> {
    let jws = serde_json::from_slice::<FlattenedJws>(response).ok()?;
    let payload = URL_SAFE_NO_PAD.decode(jws.payload.as_bytes()).ok()?;
    serde_json::from_slice::<Evidence>(&payload)
        .ok()
        .map(|evidence| evidence.subjects)
}

fn untrusted_sd_jwt_vc_subjects(response: &[u8]) -> Option<Vec<SubjectBinding>> {
    let serialized = std::str::from_utf8(response).ok()?;
    let jwt = serialized.strip_suffix('~')?.split('~').next()?;
    let mut parts = jwt.split('.');
    let (_header, payload, _signature, None) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next())
    else {
        return None;
    };
    let claims = URL_SAFE_NO_PAD.decode(payload.as_bytes()).ok()?;
    let mut claims =
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&claims).ok()?;
    serde_json::from_value(claims.remove("subjects")?).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use registry_evidence_verifier::{
        verifier::{
            ExpectedFormDocument, ExpectedOutputDocument, ExpectedScalarFormDocument,
            VerificationError,
        },
        AssuranceProfile,
    };
    use url::Url;

    use super::*;
    use crate::{
        fixtures::{
            holder_key, signed_evidence, SignedEvidenceFixture, AUDIENCE, CONCEPT,
            CONFIGURATION_REVISION, EVIDENCE_TYPE, ISSUED_BY, MAXIMUM_LIFETIME_SECONDS,
            PROVIDED_BY, PURPOSE, REQUIREMENT,
        },
        prepare::{EvidenceRequestSpec, SubjectRequest},
        request::SelectorValue,
        token::StaticToken,
        EvidenceClient, EvidenceClientConfig,
    };

    fn client(fixture: &SignedEvidenceFixture) -> EvidenceClient {
        EvidenceClient::new(EvidenceClientConfig::new(
            Url::parse("http://127.0.0.1:9").expect("the loopback URL parses"),
            Arc::new(StaticToken::new("unused-token").expect("the token is usable")),
            fixture.trusted_jwks.clone(),
            Vec::new(),
        ))
        .expect("the offline client configuration is valid")
    }

    fn spec(subject_expectations: SubjectExpectations) -> EvidenceRequestSpec {
        EvidenceRequestSpec {
            response_format: EvidenceResponseFormat::SignedJws,
            requirement: REQUIREMENT.to_owned(),
            purpose: PURPOSE.to_owned(),
            audience: AUDIENCE.to_owned(),
            evidence_type: EVIDENCE_TYPE.to_owned(),
            issued_by: ISSUED_BY.to_owned(),
            provided_by: PROVIDED_BY.to_owned(),
            configuration_revision: CONFIGURATION_REVISION.to_owned(),
            expected_assurance_profile: AssuranceProfile::Local,
            subjects: vec![SubjectRequest {
                role: "subject".to_owned(),
                selector_profile: "record-lookup-v1".to_owned(),
                selector_values: Some(vec![(
                    "record_reference".to_owned(),
                    SelectorValue::from("synthetic-record-001"),
                )]),
            }],
            holder_keys: Vec::new(),
            expected_outputs: vec![ExpectedOutputDocument {
                concept: CONCEPT.to_owned(),
                form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
            }],
            maximum_assertion_lifetime_seconds: MAXIMUM_LIFETIME_SECONDS,
            clock_skew_seconds: 60,
            subject_expectations,
        }
    }

    #[test]
    fn preparation_and_retention_are_offline_and_the_context_omits_selectors() {
        let fixture = signed_evidence();
        // Nothing listens on this origin. These synchronous operations still
        // succeed because neither is allowed to reach the transport or token
        // provider.
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the request is prepared offline");
        let request = String::from_utf8(prepared.request_json().expect("the request serializes"))
            .expect("the request is JSON");
        let retained = client.retain_verification(&prepared);
        let context = serde_json::to_string(&retained).expect("the context serializes");

        assert!(request.contains("synthetic-record-001"), "{request}");
        assert!(!context.contains("synthetic-record-001"), "{context}");
        assert!(context.contains(RETAINED_EVIDENCE_VERIFICATION_SCHEMA_V1));
        assert_eq!(
            prepared.response_format(),
            EvidenceResponseFormat::SignedJws
        );
    }

    #[test]
    fn retained_context_debug_omits_bindings_selectors_and_pinned_keys() {
        let fixture = signed_evidence();
        let key_coordinate = fixture.trusted_jwks.keys[0]["x"]
            .as_str()
            .expect("the fixture key has an x coordinate")
            .to_owned();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::Pinned(vec![
                ExpectedSubjectDocument {
                    role: "subject".to_owned(),
                    binding: fixture.subject_binding.clone(),
                },
            ])))
            .expect("the pinned request is prepared");
        let rendered = format!("{:?}", client.retain_verification(&prepared));

        assert!(!rendered.contains(&fixture.subject_binding), "{rendered}");
        assert!(!rendered.contains("synthetic-record-001"), "{rendered}");
        assert!(!rendered.contains(&key_coordinate), "{rendered}");
        assert!(rendered.contains("Pinned"), "{rendered}");
    }

    #[test]
    fn retained_jws_context_round_trips_and_verifies_offline() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the request is prepared");
        let serialized = serde_json::to_vec(&client.retain_verification(&prepared))
            .expect("the retained context serializes");
        let retained: RetainedEvidenceVerification =
            serde_json::from_slice(&serialized).expect("the retained context parses");
        let verified = retained
            .verify_as_of(&fixture.sign(prepared.request_nonce()), fixture.now)
            .expect("the retained response verifies");

        assert_eq!(
            verified.evidence().request_nonce,
            Some(prepared.request_nonce().to_owned())
        );
        assert_eq!(verified.operation(), None);
        assert_eq!(verified.pinned_subject_expectations().len(), 1);
    }

    #[tokio::test]
    async fn retained_sd_jwt_vc_context_round_trips_and_formats_do_not_cross() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let jws = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the JWS request is prepared");
        let mut sd_jwt_vc_spec = spec(SubjectExpectations::AcceptFirstUse);
        sd_jwt_vc_spec.response_format = EvidenceResponseFormat::SdJwtVc;
        let sd_jwt_vc = client
            .prepare(sd_jwt_vc_spec)
            .expect("the SD-JWT VC request is prepared");
        let jws_response = fixture.sign(jws.request_nonce());
        let sd_jwt_response = fixture.sign_sd_jwt_vc(sd_jwt_vc.request_nonce()).await;
        let retained: RetainedEvidenceVerification = serde_json::from_slice(
            &serde_json::to_vec(&client.retain_verification(&sd_jwt_vc))
                .expect("the context serializes"),
        )
        .expect("the context parses");

        retained
            .verify_as_of(&sd_jwt_response, fixture.now)
            .expect("the SD-JWT VC verifies under its retained format");
        assert_eq!(
            retained
                .verify_as_of(&jws_response, fixture.now)
                .expect_err("JWS bytes cannot cross into SD-JWT VC verification"),
            EvidenceClientError::Verification(VerificationError::MalformedJws)
        );
        assert_eq!(
            client
                .retain_verification(&jws)
                .verify_as_of(&sd_jwt_response, fixture.now)
                .expect_err("SD-JWT VC bytes cannot cross into JWS verification"),
            EvidenceClientError::Verification(VerificationError::MalformedJws)
        );
    }

    /// A retained batch context is still a document a caller may hold and
    /// serialize, but every path that would verify it as one response refuses,
    /// and says why. The refusal does not depend on the bytes offered: a real
    /// envelope is refused exactly as anything else is, because the objection
    /// is to the question, not to the answer.
    #[tokio::test]
    async fn a_retained_batch_context_refuses_to_verify_as_one_response() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let mut batch_spec = spec(SubjectExpectations::AcceptFirstUse);
        batch_spec.response_format = EvidenceResponseFormat::SdJwtVcBatch;
        batch_spec.holder_keys = vec![holder_key()];
        let prepared = client
            .prepare(batch_spec)
            .expect("the batch request is prepared");
        let retained: RetainedEvidenceVerification = serde_json::from_slice(
            &serde_json::to_vec(&client.retain_verification(&prepared))
                .expect("the context serializes"),
        )
        .expect("the context parses");
        let envelope = serde_json::json!({
            "schema": "registry.sd-jwt-vc-batch-envelope/v1",
            "type": "SdJwtVcBatchEnvelope",
            "credentials": [fixture.sign_sd_jwt_vc(prepared.request_nonce()).await],
        })
        .to_string();

        for (description, body) in [
            ("a real envelope", envelope.into_bytes()),
            ("arbitrary bytes", b"anything at all".to_vec()),
            ("no bytes", Vec::new()),
        ] {
            let failure = retained
                .verify_as_of(&body, fixture.now)
                .expect_err(description);
            let EvidenceClientError::Configuration { reason } = &failure else {
                panic!("{description}: {failure:?}");
            };
            assert!(reason.contains("issuance packaging"), "{description}");
            assert!(reason.contains("SdJwtVcBatchResponse"), "{description}");
        }
    }

    /// Every format either names a verifier or is refused by name. A variant
    /// added without deciding which would otherwise reach verification and be
    /// judged as something it is not.
    #[test]
    fn only_a_singular_format_is_verifiable_as_one_response() {
        for format in [
            EvidenceResponseFormat::SignedJws,
            EvidenceResponseFormat::SdJwtVc,
        ] {
            assert!(format.is_verifiable_alone(), "{format:?}");
        }
        assert!(!EvidenceResponseFormat::SdJwtVcBatch.is_verifiable_alone());
    }

    #[test]
    fn retained_context_tampering_fails_closed() {
        let fixture = signed_evidence();
        let client = client(&fixture);
        let prepared = client
            .prepare(spec(SubjectExpectations::AcceptFirstUse))
            .expect("the request is prepared");
        let response = fixture.sign(prepared.request_nonce());
        let context = client.retain_verification(&prepared);

        let mut wrong_schema = serde_json::to_value(&context).expect("the context serializes");
        wrong_schema["schema"] = serde_json::json!("registry.example/unknown");
        let wrong_schema: RetainedEvidenceVerification =
            serde_json::from_value(wrong_schema).expect("the altered shape parses");
        assert!(matches!(
            wrong_schema.verify_as_of(&response, fixture.now),
            Err(EvidenceClientError::Configuration { .. })
        ));

        let mut wrong_revision = serde_json::to_value(context).expect("the context serializes");
        wrong_revision["verificationPolicy"]["configurationRevision"] = serde_json::json!(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let wrong_revision: RetainedEvidenceVerification =
            serde_json::from_value(wrong_revision).expect("the altered context parses");
        assert_eq!(
            wrong_revision
                .verify_as_of(&response, fixture.now)
                .expect_err("a response cannot change the retained revision"),
            EvidenceClientError::Verification(VerificationError::Policy)
        );
    }
}
