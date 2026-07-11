// SPDX-License-Identifier: Apache-2.0
//! Sealed public response for one decoder-validated consultation.
//!
//! Serialization happens before durable completion. Until the state plane
//! returns a publication grant, the complete candidate response remains in a
//! zeroizing owner and cannot be converted into an HTTP body.

use std::fmt;
use std::io::{self, Write};

use registry_platform_httputil::destination::json::{ProjectedJsonRecord, ProjectedJsonScalar};
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::source_plan::runtime_profile::CompiledRuntimeProfile;
use crate::state_plane::ConsultationPublicationGrant;

use super::{AcquisitionClass, ConsultationId, ConsultationOutcome, NotaryEvaluationId};

/// Frozen v1 public response-body ceiling.
pub(crate) const MAX_CONSULTATION_RESPONSE_BYTES: usize = 64 * 1_024;

/// Value-free failure while preparing a candidate public response.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConsultationResponseError {
    #[error("consultation response time is invalid")]
    InvalidTime,
    #[error("consultation response could not be serialized")]
    Serialization,
    #[error("consultation response exceeds the v1 bound")]
    ResponseTooLarge,
}

/// Candidate response bytes that remain non-publishable until durable normal
/// completion returns the exact paired grant.
#[must_use = "candidate consultation output requires a durable publication grant"]
pub(crate) struct PublishableConsultationResponse {
    bytes: Zeroizing<Vec<u8>>,
}

impl PublishableConsultationResponse {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_validated_live_result(
        consultation_id: ConsultationId,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        profile: &CompiledRuntimeProfile,
        outcome: ConsultationOutcome,
        record: Option<&ProjectedJsonRecord>,
        relay_acquired_at_unix_ms: i64,
    ) -> Result<Self, ConsultationResponseError> {
        Self::serialize_validated_live_result(
            consultation_id,
            notary_evaluation_id,
            profile,
            outcome,
            record.map(ProjectedRecord::Platform),
            relay_acquired_at_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn serialize_validated_live_result(
        consultation_id: ConsultationId,
        notary_evaluation_id: Option<NotaryEvaluationId>,
        profile: &CompiledRuntimeProfile,
        outcome: ConsultationOutcome,
        data: Option<ProjectedRecord<'_>>,
        relay_acquired_at_unix_ms: i64,
    ) -> Result<Self, ConsultationResponseError> {
        let relay_acquired_at = rfc3339_milliseconds(relay_acquired_at_unix_ms)?;
        let consultation_id = consultation_id.to_canonical_string();
        let notary_evaluation_id =
            notary_evaluation_id.map(NotaryEvaluationId::to_canonical_string);
        let profile_identity = profile.profile();
        let integration_pack = profile.integration_pack();
        let policy = profile.authorization().policy();
        let data = match (outcome, data) {
            (ConsultationOutcome::Match, Some(record)) => Some(record),
            (ConsultationOutcome::NoMatch | ConsultationOutcome::Ambiguous, None) => None,
            _ => return Err(ConsultationResponseError::Serialization),
        };
        let envelope = ConsultationResult {
            schema: "registry.relay.consultation-result.v1",
            consultation_id: &consultation_id,
            notary_evaluation_id: notary_evaluation_id.as_deref(),
            profile: ResponseProfile {
                id: profile_identity.id().as_str(),
                version: profile_identity.version().to_string(),
                contract_hash: profile_identity.contract_hash().as_str(),
            },
            outcome: outcome_str(outcome),
            data,
            provenance: ResponseProvenance {
                relay_acquired_at: &relay_acquired_at,
                source_observed_at: None,
                source_revision: None,
                acquisition_class: acquisition_class_str(profile.footprint().acquisition_class()),
                integration_pack: ResponseIntegrationPack {
                    id: integration_pack.id().as_str(),
                    version: integration_pack.version().to_string(),
                    hash: integration_pack.hash().as_str(),
                },
                policy_id: policy.id().as_str(),
                policy_hash: policy.hash().as_str(),
                consent: ResponseConsent {
                    outcome: "not_required",
                    verifier_id: None,
                    verifier_revision: None,
                    checked_at: None,
                    expires_at: None,
                    revocation_status: "not_applicable",
                },
            },
        };
        let configured_limit =
            usize::try_from(profile.effective_limits().max_public_response_bytes())
                .map_err(|_| ConsultationResponseError::ResponseTooLarge)?;
        let limit = configured_limit.min(MAX_CONSULTATION_RESPONSE_BYTES);
        if limit == 0 {
            return Err(ConsultationResponseError::ResponseTooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
        let mut writer = BoundedResponseWriter::new(&mut bytes, limit);
        if serde_json::to_writer(&mut writer, &envelope).is_err() {
            return Err(if writer.exceeded {
                ConsultationResponseError::ResponseTooLarge
            } else {
                ConsultationResponseError::Serialization
            });
        }
        Ok(Self { bytes })
    }

    /// Declassify the already validated public bytes only while consuming the
    /// durable publication authority returned for the same completed attempt.
    pub(super) fn into_http_body(mut self, _grant: ConsultationPublicationGrant) -> Vec<u8> {
        std::mem::take(self.bytes.as_mut())
    }

    #[cfg(test)]
    fn bytes_for_test(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for PublishableConsultationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishableConsultationResponse")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct ConsultationResult<'a> {
    schema: &'static str,
    consultation_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notary_evaluation_id: Option<&'a str>,
    profile: ResponseProfile<'a>,
    outcome: &'static str,
    data: Option<ProjectedRecord<'a>>,
    provenance: ResponseProvenance<'a>,
}

#[derive(Serialize)]
struct ResponseProfile<'a> {
    id: &'a str,
    version: String,
    contract_hash: &'a str,
}

#[derive(Serialize)]
struct ResponseProvenance<'a> {
    relay_acquired_at: &'a str,
    source_observed_at: Option<&'a str>,
    source_revision: Option<&'a str>,
    acquisition_class: &'static str,
    integration_pack: ResponseIntegrationPack<'a>,
    policy_id: &'a str,
    policy_hash: &'a str,
    consent: ResponseConsent<'a>,
}

#[derive(Serialize)]
struct ResponseIntegrationPack<'a> {
    id: &'a str,
    version: String,
    hash: &'a str,
}

#[derive(Serialize)]
struct ResponseConsent<'a> {
    outcome: &'static str,
    verifier_id: Option<&'a str>,
    verifier_revision: Option<&'a str>,
    checked_at: Option<&'a str>,
    expires_at: Option<&'a str>,
    revocation_status: &'static str,
}

enum ProjectedRecord<'a> {
    Platform(&'a ProjectedJsonRecord),
    #[cfg(test)]
    Test(&'a [(&'a str, TestProjectedScalar<'a>)]),
}

impl Serialize for ProjectedRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Platform(record) => {
                let mut map = serializer.serialize_map(Some(record.len()))?;
                for field in record.fields() {
                    map.serialize_entry(field.name(), &ProjectedScalar(field.value()))?;
                }
                map.end()
            }
            #[cfg(test)]
            Self::Test(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (name, value) in *fields {
                    map.serialize_entry(name, value)?;
                }
                map.end()
            }
        }
    }
}

#[cfg(test)]
enum TestProjectedScalar<'a> {
    Null,
    String(&'a str),
    Boolean(bool),
    Integer(i64),
    Number(f64),
}

#[cfg(test)]
impl Serialize for TestProjectedScalar<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::String(value) => serializer.serialize_str(value),
            Self::Boolean(value) => serializer.serialize_bool(*value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::Number(value) => serializer.serialize_f64(*value),
        }
    }
}

struct ProjectedScalar<'a>(&'a ProjectedJsonScalar);

impl Serialize for ProjectedScalar<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            ProjectedJsonScalar::Null => serializer.serialize_none(),
            ProjectedJsonScalar::String(value) => serializer.serialize_str(value),
            ProjectedJsonScalar::Boolean(value) => serializer.serialize_bool(*value),
            ProjectedJsonScalar::Integer(value) => serializer.serialize_i64(*value),
            ProjectedJsonScalar::Number(value) => serializer.serialize_f64(*value),
        }
    }
}

struct BoundedResponseWriter<'a> {
    bytes: &'a mut Zeroizing<Vec<u8>>,
    limit: usize,
    exceeded: bool,
}

impl<'a> BoundedResponseWriter<'a> {
    fn new(bytes: &'a mut Zeroizing<Vec<u8>>, limit: usize) -> Self {
        Self {
            bytes,
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedResponseWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let within_limit = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .is_some_and(|length| length <= self.limit);
        if !within_limit {
            self.exceeded = true;
            return Err(io::Error::other("consultation response limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn rfc3339_milliseconds(unix_ms: i64) -> Result<String, ConsultationResponseError> {
    let unix_nanos = i128::from(unix_ms)
        .checked_mul(1_000_000)
        .ok_or(ConsultationResponseError::InvalidTime)?;
    OffsetDateTime::from_unix_timestamp_nanos(unix_nanos)
        .map_err(|_| ConsultationResponseError::InvalidTime)?
        .format(&Rfc3339)
        .map_err(|_| ConsultationResponseError::InvalidTime)
}

const fn outcome_str(outcome: ConsultationOutcome) -> &'static str {
    match outcome {
        ConsultationOutcome::Match => "match",
        ConsultationOutcome::NoMatch => "no_match",
        ConsultationOutcome::Ambiguous => "ambiguous",
    }
}

const fn acquisition_class_str(class: AcquisitionClass) -> &'static str {
    match class {
        AcquisitionClass::SourceProjectedExact => "source_projected_exact",
        AcquisitionClass::BoundedFullRecord => "bounded_full_record",
        AcquisitionClass::MaterializedSnapshot => "materialized_snapshot",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{json, Value};

    use crate::source_plan::dhis2_runtime_vector_plan_fixture;

    #[test]
    fn response_timestamp_is_utc_rfc3339_and_millisecond_exact() {
        assert_eq!(
            rfc3339_milliseconds(1_752_148_800_123).unwrap(),
            "2025-07-10T12:00:00.123Z"
        );
        assert_eq!(
            rfc3339_milliseconds(-1),
            Ok("1969-12-31T23:59:59.999Z".into())
        );
    }

    #[test]
    fn frozen_public_vocabulary_is_complete() {
        assert_eq!(outcome_str(ConsultationOutcome::Match), "match");
        assert_eq!(outcome_str(ConsultationOutcome::NoMatch), "no_match");
        assert_eq!(outcome_str(ConsultationOutcome::Ambiguous), "ambiguous");
        assert_eq!(
            acquisition_class_str(AcquisitionClass::SourceProjectedExact),
            "source_projected_exact"
        );
        assert_eq!(
            acquisition_class_str(AcquisitionClass::BoundedFullRecord),
            "bounded_full_record"
        );
        assert_eq!(
            acquisition_class_str(AcquisitionClass::MaterializedSnapshot),
            "materialized_snapshot"
        );
    }

    #[test]
    fn exact_response_shape_covers_all_outcomes_consent_and_optional_notary_id() {
        let plan = dhis2_runtime_vector_plan_fixture();
        let profile = plan.runtime_profile();
        let notary = NotaryEvaluationId::try_parse("01JYZZZZZZZZZZZZZZZZZZZZZZ").unwrap();
        let match_fields = [("status", TestProjectedScalar::String("ACTIVE"))];
        let cases = [
            (
                ConsultationOutcome::Match,
                Some(ProjectedRecord::Test(&match_fields[..])),
                Some(notary),
                json!({"status": "ACTIVE"}),
            ),
            (ConsultationOutcome::NoMatch, None, None, Value::Null),
            (ConsultationOutcome::Ambiguous, None, None, Value::Null),
        ];

        for (outcome, data, evaluation_id, expected_data) in cases {
            let candidate = PublishableConsultationResponse::serialize_validated_live_result(
                ConsultationId::generate(),
                evaluation_id,
                profile,
                outcome,
                data,
                1_752_148_800_123,
            )
            .expect("frozen response serializes");
            let value: Value = serde_json::from_slice(candidate.bytes_for_test()).unwrap();
            assert_eq!(
                value.as_object().unwrap().keys().collect::<Vec<_>>(),
                [
                    "consultation_id",
                    "data",
                    "notary_evaluation_id",
                    "outcome",
                    "profile",
                    "provenance",
                    "schema",
                ]
                .into_iter()
                .filter(|key| evaluation_id.is_some() || *key != "notary_evaluation_id")
                .collect::<Vec<_>>()
            );
            assert_eq!(value["schema"], "registry.relay.consultation-result.v1");
            assert_eq!(value["outcome"], outcome_str(outcome));
            assert_eq!(value["data"], expected_data);
            assert_eq!(value["profile"]["id"], profile.profile().id().as_str());
            assert_eq!(
                value["profile"]["contract_hash"],
                profile.profile().contract_hash().as_str()
            );
            assert_eq!(
                value["provenance"]["relay_acquired_at"],
                "2025-07-10T12:00:00.123Z"
            );
            assert_eq!(value["provenance"]["source_observed_at"], Value::Null);
            assert_eq!(value["provenance"]["source_revision"], Value::Null);
            assert_eq!(
                value["provenance"]["consent"],
                json!({
                    "outcome": "not_required",
                    "verifier_id": null,
                    "verifier_revision": null,
                    "checked_at": null,
                    "expires_at": null,
                    "revocation_status": "not_applicable"
                })
            );
            assert_eq!(
                value.get("notary_evaluation_id").and_then(Value::as_str),
                evaluation_id.map(|id| id.to_canonical_string()).as_deref()
            );
        }
    }

    #[test]
    fn bounded_writer_never_grows_or_retains_bytes_beyond_its_limit() {
        let mut bytes = Zeroizing::new(Vec::with_capacity(4));
        let mut writer = BoundedResponseWriter::new(&mut bytes, 4);
        assert_eq!(writer.write(b"1234").unwrap(), 4);
        assert!(writer.write(b"5").is_err());
        assert!(writer.exceeded);
        assert_eq!(bytes.as_slice(), b"1234");
        assert_eq!(bytes.capacity(), 4);
    }

    #[test]
    fn test_projection_serializer_covers_every_platform_scalar_kind() {
        let fields = [
            ("null", TestProjectedScalar::Null),
            ("string", TestProjectedScalar::String("value")),
            ("boolean", TestProjectedScalar::Boolean(true)),
            ("integer", TestProjectedScalar::Integer(7)),
            ("number", TestProjectedScalar::Number(1.5)),
        ];
        assert_eq!(
            serde_json::to_value(ProjectedRecord::Test(&fields)).unwrap(),
            json!({
                "null": null,
                "string": "value",
                "boolean": true,
                "integer": 7,
                "number": 1.5
            })
        );
    }
}
