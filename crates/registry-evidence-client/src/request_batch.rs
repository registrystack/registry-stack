//! One ordered request batch with one closed verification policy per item.

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};

use registry_evidence_verifier::{verifier::ExpectedOutputDocument, AssuranceProfile};
use registry_platform_crypto::canonicalize_json;
use serde::Serialize;

use crate::{
    client::VerifiedEvidence,
    error::EvidenceClientError,
    prepare::{EvidenceRequestSpec, PreparedEvidenceRequest, SubjectExpectations, SubjectRequest},
    request::RequestedSubject,
    response_format::EvidenceResponseFormat,
};

/// Largest multi-subject request batch accepted by the Version 1 transport.
pub const MAXIMUM_REQUEST_BATCH_ITEMS: usize = 16;
/// Protocol byte ceiling for one request-batch response envelope.
pub const MAX_EVIDENCE_REQUEST_BATCH_RESPONSE_BYTES: usize = 1024 * 1024;

/// One ordered multi-subject Evidence request batch before its nonces exist.
#[derive(Debug, Clone)]
pub struct EvidenceRequestBatchSpec {
    /// Requirement shared by every independently verified item.
    pub requirement: String,
    /// Purpose shared by every independently verified item.
    pub purpose: String,
    pub audience: String,
    pub evidence_type: String,
    pub issued_by: String,
    pub provided_by: String,
    pub configuration_revision: String,
    pub expected_assurance_profile: AssuranceProfile,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
    pub maximum_assertion_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
    /// Ordered item specifications. Each closes its own verification policy.
    pub items: Vec<EvidenceRequestBatchItemSpec>,
}

/// One positional subject set and its subject-verification stance.
#[derive(Debug, Clone)]
pub struct EvidenceRequestBatchItemSpec {
    pub subjects: Vec<SubjectRequest>,
    pub subject_expectations: SubjectExpectations,
}

/// Serialized request batch and the ordered policies that will judge it.
///
/// This type is deliberately not `Clone`. Its first send attempt consumes the
/// one network use of every nonce in the batch, even when that attempt fails.
pub struct PreparedEvidenceRequestBatch {
    requirement: String,
    purpose: String,
    items: Vec<PreparedEvidenceRequest>,
    sent: AtomicBool,
}

impl PreparedEvidenceRequestBatch {
    pub(crate) fn new_with_revoked_key_ids(
        spec: EvidenceRequestBatchSpec,
        revoked_key_ids: Vec<String>,
    ) -> Result<Self, EvidenceClientError> {
        if !(1..=MAXIMUM_REQUEST_BATCH_ITEMS).contains(&spec.items.len()) {
            return Err(EvidenceClientError::configuration(
                "a request batch must carry between one and sixteen items",
            ));
        }

        let EvidenceRequestBatchSpec {
            requirement,
            purpose,
            audience,
            evidence_type,
            issued_by,
            provided_by,
            configuration_revision,
            expected_assurance_profile,
            expected_outputs,
            maximum_assertion_lifetime_seconds,
            clock_skew_seconds,
            items,
        } = spec;
        let items = items
            .into_iter()
            .map(|item| {
                PreparedEvidenceRequest::new_with_revoked_key_ids(
                    EvidenceRequestSpec {
                        response_format: EvidenceResponseFormat::SignedJws,
                        requirement: requirement.clone(),
                        purpose: purpose.clone(),
                        audience: audience.clone(),
                        evidence_type: evidence_type.clone(),
                        issued_by: issued_by.clone(),
                        provided_by: provided_by.clone(),
                        configuration_revision: configuration_revision.clone(),
                        expected_assurance_profile,
                        subjects: item.subjects,
                        holder_keys: Vec::new(),
                        expected_outputs: expected_outputs.clone(),
                        maximum_assertion_lifetime_seconds,
                        clock_skew_seconds,
                        subject_expectations: item.subject_expectations,
                    },
                    revoked_key_ids.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !pairwise_distinct(items.iter().map(PreparedEvidenceRequest::request_nonce)) {
            return Err(EvidenceClientError::configuration(
                "every request-batch item must have a distinct nonce",
            ));
        }

        Ok(Self {
            requirement,
            purpose,
            items,
            sent: AtomicBool::new(false),
        })
    }

    /// Number of positional items and independently generated nonces.
    #[must_use]
    pub fn count(&self) -> usize {
        self.items.len()
    }

    /// Nonce generated for the item at `index`.
    #[must_use]
    pub fn request_nonce(&self, index: usize) -> Option<&str> {
        self.items
            .get(index)
            .map(PreparedEvidenceRequest::request_nonce)
    }

    /// All independently generated item nonces in request order.
    #[must_use]
    pub fn request_nonces(&self) -> Vec<&str> {
        self.items
            .iter()
            .map(PreparedEvidenceRequest::request_nonce)
            .collect()
    }

    /// Policy independently closed for the item at `index`.
    #[must_use]
    pub fn policy_document(
        &self,
        index: usize,
    ) -> Option<&registry_evidence_verifier::verifier::EvidenceVerificationPolicyDocument> {
        self.items
            .get(index)
            .map(PreparedEvidenceRequest::policy_document)
    }

    /// Subject-verification stance closed for the item at `index`.
    #[must_use]
    pub fn subject_expectations(&self, index: usize) -> Option<&SubjectExpectations> {
        self.items
            .get(index)
            .map(PreparedEvidenceRequest::subject_expectations)
    }

    /// Serialize the exact common-fields-plus-items request body.
    pub fn request_json(&self) -> Result<Vec<u8>, EvidenceClientError> {
        let body = EvidenceRequestBatchBody {
            requirement: &self.requirement,
            purpose: &self.purpose,
            items: self
                .items
                .iter()
                .map(|item| EvidenceRequestBatchItemBody {
                    request_nonce: item.request_nonce(),
                    subjects: &item.request_body().subjects,
                })
                .collect(),
        };
        let value = serde_json::to_value(body).map_err(|_| {
            EvidenceClientError::configuration("the request batch body cannot be serialized")
        })?;
        canonicalize_json(&value).map_err(|_| {
            EvidenceClientError::configuration("the request batch body cannot be serialized")
        })
    }

    pub(crate) fn items(&self) -> &[PreparedEvidenceRequest] {
        &self.items
    }

    pub(crate) fn claim_single_send(&self) -> Result<(), EvidenceClientError> {
        if self.sent.swap(true, Ordering::SeqCst) {
            return Err(EvidenceClientError::configuration(
                "a prepared request batch may be sent once; prepare again for fresh nonces",
            ));
        }
        Ok(())
    }
}

fn pairwise_distinct<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

impl std::fmt::Debug for PreparedEvidenceRequestBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedEvidenceRequestBatch")
            .field("requirement", &self.requirement)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceRequestBatchBody<'a> {
    requirement: &'a str,
    purpose: &'a str,
    items: Vec<EvidenceRequestBatchItemBody<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceRequestBatchItemBody<'a> {
    request_nonce: &'a str,
    subjects: &'a [RequestedSubject],
}

/// Request-batch response bytes read but not yet judged.
#[derive(Clone)]
pub struct RawEvidenceRequestBatchResponse {
    pub(crate) body: Vec<u8>,
    pub(crate) trace_id: Option<String>,
}

impl RawEvidenceRequestBatchResponse {
    /// Response envelope bytes exactly as received.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The validated W3C trace identifier for the batch exchange.
    ///
    /// It is support correlation only, not an Evidence audit operation
    /// identity.
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
}

impl std::fmt::Debug for RawEvidenceRequestBatchResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawEvidenceRequestBatchResponse")
            .field("body_bytes", &self.body.len())
            .field("trace_id", &self.trace_id)
            .finish_non_exhaustive()
    }
}

/// One verified positional result from a request batch.
// Keeping the verified value direct is the public SDK contract: callers and
// thin language bindings match `Available(VerifiedEvidence)`. A batch is
// bounded to sixteen items, so the resulting collection remains bounded too.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum VerifiedEvidenceRequestBatchItem {
    /// The available member passed the corresponding item's closed policy.
    Available(VerifiedEvidence),
    /// The deployment released no evidence for this exact item.
    NotAvailable,
}

/// All ordered results of an atomically verified request-batch envelope.
#[derive(Debug, Clone)]
pub struct VerifiedEvidenceRequestBatch {
    pub(crate) items: Vec<VerifiedEvidenceRequestBatchItem>,
    pub(crate) trace_id: Option<String>,
}

impl VerifiedEvidenceRequestBatch {
    /// Ordered verified and unavailable results.
    #[must_use]
    pub fn items(&self) -> &[VerifiedEvidenceRequestBatchItem] {
        &self.items
    }

    /// Number of positional results.
    #[must_use]
    pub fn count(&self) -> usize {
        self.items.len()
    }

    /// Result at `index`.
    #[must_use]
    pub fn item(&self, index: usize) -> Option<&VerifiedEvidenceRequestBatchItem> {
        self.items.get(index)
    }

    /// Consume the batch and return its ordered results.
    #[must_use]
    pub fn into_items(self) -> Vec<VerifiedEvidenceRequestBatchItem> {
        self.items
    }

    /// The validated W3C trace identifier for the batch exchange.
    ///
    /// It is support correlation only, not an Evidence audit operation
    /// identity.
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fixtures::{
            signed_evidence, AUDIENCE, CONCEPT, CONFIGURATION_REVISION, EVIDENCE_TYPE, ISSUED_BY,
            MAXIMUM_LIFETIME_SECONDS, PROVIDED_BY, PURPOSE, REQUIREMENT,
        },
        request::SelectorValue,
    };
    use registry_evidence_verifier::verifier::{ExpectedFormDocument, ExpectedScalarFormDocument};

    fn item() -> EvidenceRequestBatchItemSpec {
        EvidenceRequestBatchItemSpec {
            subjects: vec![SubjectRequest {
                role: "subject".to_owned(),
                selector_profile: "record-lookup-v1".to_owned(),
                selector_values: Some(vec![(
                    "record_reference".to_owned(),
                    SelectorValue::from("synthetic-record-001"),
                )]),
            }],
            subject_expectations: SubjectExpectations::AcceptFirstUse,
        }
    }

    fn spec(items: Vec<EvidenceRequestBatchItemSpec>) -> EvidenceRequestBatchSpec {
        EvidenceRequestBatchSpec {
            requirement: REQUIREMENT.to_owned(),
            purpose: PURPOSE.to_owned(),
            audience: AUDIENCE.to_owned(),
            evidence_type: EVIDENCE_TYPE.to_owned(),
            issued_by: ISSUED_BY.to_owned(),
            provided_by: PROVIDED_BY.to_owned(),
            configuration_revision: CONFIGURATION_REVISION.to_owned(),
            expected_assurance_profile: AssuranceProfile::Local,
            expected_outputs: vec![ExpectedOutputDocument {
                handle: "status-holds".to_owned(),
                concept: CONCEPT.to_owned(),
                required: true,
                form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
            }],
            maximum_assertion_lifetime_seconds: MAXIMUM_LIFETIME_SECONDS,
            clock_skew_seconds: 60,
            items,
        }
    }

    #[test]
    fn preparation_generates_independent_nonces_and_the_exact_wire_shape() {
        let prepared = PreparedEvidenceRequestBatch::new_with_revoked_key_ids(
            spec(vec![item(), item()]),
            Vec::new(),
        )
        .expect("the request batch is prepared");

        assert_ne!(prepared.request_nonce(0), prepared.request_nonce(1));
        for nonce in [prepared.request_nonce(0), prepared.request_nonce(1)] {
            let nonce = nonce.expect("the nonce exists");
            assert!(crate::RequestNonce::parse(nonce).is_ok());
        }
        let request: serde_json::Value =
            serde_json::from_slice(&prepared.request_json().expect("the request serializes"))
                .expect("the request is JSON");
        assert_eq!(
            request,
            serde_json::json!({
                "requirement": REQUIREMENT,
                "purpose": PURPOSE,
                "items": [
                    {
                        "requestNonce": prepared.request_nonce(0).expect("first nonce"),
                        "subjects": [{
                            "role": "subject",
                            "selector": {
                                "profile": "record-lookup-v1",
                                "values": {"record_reference": "synthetic-record-001"}
                            }
                        }]
                    },
                    {
                        "requestNonce": prepared.request_nonce(1).expect("second nonce"),
                        "subjects": [{
                            "role": "subject",
                            "selector": {
                                "profile": "record-lookup-v1",
                                "values": {"record_reference": "synthetic-record-001"}
                            }
                        }]
                    }
                ]
            })
        );
        assert_eq!(
            prepared
                .policy_document(0)
                .expect("first policy")
                .request_nonce,
            prepared.request_nonce(0).expect("first nonce")
        );
        assert_eq!(
            prepared
                .policy_document(1)
                .expect("second policy")
                .request_nonce,
            prepared.request_nonce(1).expect("second nonce")
        );
        let diagnostic = format!("{prepared:?}");
        assert!(!diagnostic.contains("synthetic-record-001"));
        assert!(!diagnostic.contains(signed_evidence().subject_binding.as_str()));
    }

    #[test]
    fn preparation_refuses_empty_and_oversized_batches() {
        for items in [Vec::new(), vec![item(); MAXIMUM_REQUEST_BATCH_ITEMS + 1]] {
            assert!(matches!(
                PreparedEvidenceRequestBatch::new_with_revoked_key_ids(spec(items), Vec::new(),),
                Err(EvidenceClientError::Configuration { .. })
            ));
        }
    }

    #[test]
    fn the_pairwise_nonce_invariant_refuses_a_repeated_value() {
        assert!(pairwise_distinct(["first", "second"]));
        assert!(!pairwise_distinct(["repeated", "repeated"]));
    }
}
