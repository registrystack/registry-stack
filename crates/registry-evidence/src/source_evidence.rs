//! The signed Evidence protocol over the ordinary bounded HTTP source channel.
//!
//! The governed definition owns the request and verification expectations.
//! Scripts supply minimized subject selectors and receive only verified values;
//! nonce generation, signing-key trust and protocol validation stay in Rust.

use std::collections::{BTreeMap, BTreeSet};

use registry_evidence_client::{
    EvidenceDefinitionsDocument, EvidenceRequestSpec, EvidenceResponseFormat,
    PreparedEvidenceRequest, RetainedEvidenceVerification, SelectorValue, SelectorValueOrigin,
    SubjectExpectations, SubjectRequest,
};
use registry_evidence_verifier::{
    model::{JwksDocument, SubjectBindingMode},
    verifier::{
        revoked_key_ids_are_usable, trusted_keys_are_usable, MAXIMUM_ASSERTION_LIFETIME_SECONDS,
        MAXIMUM_CLOCK_SKEW_SECONDS, MINIMUM_ASSERTION_LIFETIME_SECONDS,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    config::{ConfigError, FixedRequest, HttpMethod, PreparationChannelPolicy},
    rhai_runtime::RequestParts,
    source::SourceError,
};

/// A locally accepted, single-definition contract and its independently pinned
/// public verification keys. This is governed source configuration, never
/// discovered or replaced while answering a request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSourceConfig {
    pub contract: EvidenceDefinitionsDocument,
    pub trusted_jwks: JwksDocument,
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    pub maximum_assertion_lifetime_seconds: u64,
    #[serde(default)]
    pub clock_skew_seconds: u64,
}

impl EvidenceSourceConfig {
    pub(crate) fn validate(&self, request: &FixedRequest) -> Result<(), ConfigError> {
        let invalid = || ConfigError::Invalid("the signed Evidence source contract is invalid");
        self.contract
            .validate_for_request()
            .map_err(|_| invalid())?;
        let [definition] = self.contract.definitions.as_slice() else {
            return Err(ConfigError::Invalid(
                "an Evidence source must pin exactly one definition",
            ));
        };
        if definition.subject_binding_mode == Some(SubjectBindingMode::HolderBound)
            || !definition
                .response_formats
                .iter()
                .any(|format| format.supports(EvidenceResponseFormat::SignedJws))
            || !(MINIMUM_ASSERTION_LIFETIME_SECONDS..=MAXIMUM_ASSERTION_LIFETIME_SECONDS)
                .contains(&self.maximum_assertion_lifetime_seconds)
            || self.clock_skew_seconds > MAXIMUM_CLOCK_SKEW_SECONDS
        {
            return Err(invalid());
        }
        // The upstream authenticates this service's own source credential, so
        // it would resolve an authenticated selector from that credential and
        // never from the downstream caller's subject.
        if definition
            .subjects
            .iter()
            .any(|subject| subject.selector.value_origin != SelectorValueOrigin::Request)
        {
            return Err(ConfigError::Invalid(
                "a signed Evidence source accepts only request-origin selectors, because the upstream would resolve an authenticated selector from this service's own source credential",
            ));
        }
        trusted_keys_are_usable(&self.trusted_jwks).map_err(|_| invalid())?;
        revoked_key_ids_are_usable(&self.revoked_key_ids).map_err(|_| invalid())?;
        if request.method != HttpMethod::POST
            || request.path_is_template()
            || !request.path.ends_with("/v1/evidence")
            || request.preparation_limits.query != PreparationChannelPolicy::Forbidden
            || request.preparation_limits.json_body != PreparationChannelPolicy::Required
            || request
                .fixed_headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("accept"))
        {
            return Err(ConfigError::Invalid(
                "an Evidence source requires a fixed POST evidence path, no query or Accept override, and a required JSON body",
            ));
        }
        Ok(())
    }

    /// Validate the script's closed selector-only request before source access.
    pub(crate) fn validate_parts(&self, parts: &RequestParts) -> Result<(), SourceError> {
        if !parts.query.is_empty() {
            return Err(SourceError::InvalidPlan);
        }
        self.subjects(parts.body.as_ref()).map(|_| ())
    }

    fn subjects(&self, body: Option<&Value>) -> Result<Vec<SubjectRequest>, SourceError> {
        let request: PreparedSubjects =
            serde_json::from_value(body.cloned().ok_or(SourceError::InvalidPlan)?)
                .map_err(|_| SourceError::InvalidPlan)?;
        let [definition] = self.contract.definitions.as_slice() else {
            return Err(SourceError::InvalidPlan);
        };
        if request.subjects.len() != definition.subjects.len() {
            return Err(SourceError::InvalidPlan);
        }
        let mut seen = BTreeSet::new();
        request
            .subjects
            .into_iter()
            .map(|subject| {
                let declared = definition
                    .subjects
                    .iter()
                    .find(|declared| declared.role == subject.role)
                    .ok_or(SourceError::InvalidPlan)?;
                if !seen.insert(subject.role.clone())
                    || declared.selector.profile != subject.selector.profile
                {
                    return Err(SourceError::InvalidPlan);
                }
                let values: Option<BTreeMap<_, _>> = subject.selector.values.map(|fields| {
                    fields
                        .into_iter()
                        .map(|(name, value)| {
                            let value = match value {
                                crate::model::SelectorValue::String(value) => {
                                    SelectorValue::String(value)
                                }
                                crate::model::SelectorValue::Integer(value) => {
                                    SelectorValue::Integer(value)
                                }
                                crate::model::SelectorValue::Boolean(value) => {
                                    SelectorValue::Boolean(value)
                                }
                            };
                            (name, value)
                        })
                        .collect()
                });
                match (declared.selector.value_origin, &values) {
                    (SelectorValueOrigin::Request, Some(values))
                        if declared.selector.accepts_request_values(values) => {}
                    _ => return Err(SourceError::InvalidPlan),
                }
                Ok(SubjectRequest {
                    role: subject.role,
                    selector_profile: subject.selector.profile,
                    selector_values: values.map(|values| values.into_iter().collect()),
                })
            })
            .collect()
    }

    /// Draw a fresh nonce and close the complete verification policy before
    /// credentials or the HTTP exchange. Nothing from the eventual response
    /// can change these independently accepted expectations.
    pub(crate) fn prepare(
        &self,
        body: Option<&Value>,
        maximum_bytes: usize,
    ) -> Result<(Vec<u8>, RetainedEvidenceVerification), SourceError> {
        let subjects = self.subjects(body)?;
        let [definition] = self.contract.definitions.as_slice() else {
            return Err(SourceError::InvalidPlan);
        };
        let expected_outputs = definition
            .concepts
            .iter()
            .map(|concept| {
                concept
                    .scalar_expected_output()
                    .or_else(|| concept.list_expected_output())
                    .ok_or(SourceError::InvalidPlan)
            })
            .collect::<Result<_, _>>()?;
        let prepared = PreparedEvidenceRequest::prepare(
            EvidenceRequestSpec {
                response_format: EvidenceResponseFormat::SignedJws,
                requirement: definition.requirement.clone(),
                purpose: definition.purpose.clone(),
                audience: self.contract.audience.clone(),
                evidence_type: definition.evidence_type.clone(),
                issued_by: self.contract.issued_by.clone(),
                provided_by: self.contract.provided_by.clone(),
                configuration_revision: definition.configuration_revision.clone(),
                expected_assurance_profile: self.contract.assurance_profile,
                subjects,
                holder_keys: Vec::new(),
                expected_outputs,
                maximum_assertion_lifetime_seconds: self.maximum_assertion_lifetime_seconds,
                clock_skew_seconds: self.clock_skew_seconds,
                subject_expectations: SubjectExpectations::AcceptFirstUse,
            },
            self.revoked_key_ids.clone(),
        )
        .map_err(|_| SourceError::InvalidPlan)?;
        let bytes = prepared
            .claim_request_json()
            .map_err(|_| SourceError::InvalidPlan)?;
        if bytes.len() > maximum_bytes {
            return Err(SourceError::InvalidPlan);
        }
        let verification =
            RetainedEvidenceVerification::from_prepared(&prepared, self.trusted_jwks.clone())
                .map_err(|_| SourceError::InvalidPlan)?;
        Ok((bytes, verification))
    }

    pub(crate) fn verified_values(
        &self,
        verification: &RetainedEvidenceVerification,
        response: &[u8],
    ) -> Result<Value, SourceError> {
        let verified = verification
            .verify(response)
            .map_err(|_| SourceError::Verification)?;
        let [definition] = self.contract.definitions.as_slice() else {
            return Err(SourceError::InvalidPlan);
        };
        let mut values = serde_json::Map::new();
        for concept in &definition.concepts {
            if let Some(supported) = verified
                .evidence()
                .supported_values
                .iter()
                .find(|supported| supported.provides_value_for == concept.concept)
            {
                values.insert(
                    concept.handle.clone(),
                    serde_json::to_value(&supported.value)
                        .map_err(|_| SourceError::Verification)?,
                );
            }
        }
        Ok(json!({"values": values}))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedSubjects {
    subjects: Vec<PreparedSubject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedSubject {
    role: String,
    selector: PreparedSelector,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedSelector {
    profile: String,
    values: Option<BTreeMap<String, crate::model::SelectorValue>>,
}
