//! Progressive, profile-driven audience-scoped requests.

use std::collections::{BTreeMap, BTreeSet};

use registry_evidence_verifier::{
    model::{Evidence, PublicValue},
    verifier::ExpectedSubjectDocument,
};
use serde::{Deserialize, Serialize};

use crate::{
    definitions::{EvidenceDefinition, SelectorValueOrigin},
    error::EvidenceClientError,
    prepare::{EvidenceRequestSpec, SubjectExpectations, SubjectRequest},
    request::SelectorValue,
    response_format::EvidenceResponseFormat,
    VerifiedEvidence,
};

pub const SUBJECT_BINDING_RECEIPT_SCHEMA_V1: &str = "registry.evidence-subject-binding-receipt/v1";

/// The small, application-authored input for one progressive request.
#[derive(Clone)]
pub struct AudienceScopedRequest {
    pub(crate) requirement: String,
    pub(crate) selectors: BTreeMap<String, SelectorValue>,
    pub(crate) subjects: Option<BTreeMap<String, BTreeMap<String, SelectorValue>>>,
    pub(crate) response_format: EvidenceResponseFormat,
    pub(crate) binding_receipt: Option<SubjectBindingReceipt>,
}

impl AudienceScopedRequest {
    #[must_use]
    pub fn new(requirement: impl Into<String>, selectors: BTreeMap<String, SelectorValue>) -> Self {
        Self {
            requirement: requirement.into(),
            selectors,
            subjects: None,
            response_format: EvidenceResponseFormat::SignedJws,
            binding_receipt: None,
        }
    }

    #[must_use]
    pub fn with_subjects(
        mut self,
        subjects: BTreeMap<String, BTreeMap<String, SelectorValue>>,
    ) -> Self {
        self.subjects = Some(subjects);
        self
    }

    #[must_use]
    pub fn with_response_format(mut self, response_format: EvidenceResponseFormat) -> Self {
        self.response_format = response_format;
        self
    }

    #[must_use]
    pub fn with_binding_receipt(mut self, receipt: SubjectBindingReceipt) -> Self {
        self.binding_receipt = Some(receipt);
        self
    }
}

impl std::fmt::Debug for AudienceScopedRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AudienceScopedRequest")
            .field("requirement", &self.requirement)
            .field(
                "subject_count",
                &self.subjects.as_ref().map_or(1, BTreeMap::len),
            )
            .field("response_format", &self.response_format)
            .field("has_binding_receipt", &self.binding_receipt.is_some())
            .finish_non_exhaustive()
    }
}

/// Opaque, application-owned continuity state.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectBindingReceipt {
    pub schema: String,
    pub audience: String,
    pub issued_by: String,
    pub provided_by: String,
    pub requirement: String,
    pub evidence_type: String,
    pub purpose: String,
    pub configuration_revision: String,
    pub selector_profiles: BTreeMap<String, String>,
    pub subjects: Vec<ExpectedSubjectDocument>,
}

impl std::fmt::Debug for SubjectBindingReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubjectBindingReceipt")
            .field("schema", &self.schema)
            .field("subject_count", &self.subjects.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub enum SubjectContinuity {
    FirstUse { receipt: SubjectBindingReceipt },
    Matched { receipt: SubjectBindingReceipt },
}

impl std::fmt::Debug for SubjectContinuity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstUse { .. } => formatter.write_str("FirstUse(<redacted>)"),
            Self::Matched { .. } => formatter.write_str("Matched(<redacted>)"),
        }
    }
}

#[derive(Clone)]
pub struct VerifiedAssertion {
    evidence: Evidence,
    trace_id: Option<String>,
    assertion: Vec<u8>,
    values: BTreeMap<String, PublicValue>,
    subject_continuity: SubjectContinuity,
}

#[derive(Clone)]
pub struct VerifiedAudienceScopedCredential {
    evidence: Evidence,
    trace_id: Option<String>,
    credential: String,
    values: BTreeMap<String, PublicValue>,
    subject_continuity: SubjectContinuity,
}

pub enum VerifiedAudienceScopedEvidence {
    Assertion(VerifiedAssertion),
    Credential(VerifiedAudienceScopedCredential),
}

/// The authenticated, client-safe contract candidate an application may review.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceClientContracts {
    pub schema: String,
    pub assurance_profile: registry_evidence_verifier::AssuranceProfile,
    pub audience: String,
    pub issued_by: String,
    pub provided_by: String,
    pub definitions: Vec<crate::EvidenceDefinition>,
}

/// Owner-only artifacts for an external HTTP client such as curl.
pub struct ProgressivePreparedRequest {
    pub(crate) endpoint: String,
    pub(crate) accept: String,
    pub(crate) authorization: String,
    pub(crate) request_json: Vec<u8>,
    pub(crate) retained_verification: Vec<u8>,
}

impl ProgressivePreparedRequest {
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    #[must_use]
    pub fn accept(&self) -> &str {
        &self.accept
    }
    #[must_use]
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
    #[must_use]
    pub fn request_json(&self) -> &[u8] {
        &self.request_json
    }
    #[must_use]
    pub fn retained_verification(&self) -> &[u8] {
        &self.retained_verification
    }
}

impl std::fmt::Debug for ProgressivePreparedRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProgressivePreparedRequest")
            .field("request_bytes", &self.request_json.len())
            .field("retained_bytes", &self.retained_verification.len())
            .finish_non_exhaustive()
    }
}

impl From<crate::EvidenceDefinitionsDocument> for EvidenceClientContracts {
    fn from(document: crate::EvidenceDefinitionsDocument) -> Self {
        Self {
            schema: crate::EVIDENCE_CLIENT_CONTRACTS_SCHEMA_V1.to_owned(),
            assurance_profile: document.assurance_profile,
            audience: document.audience,
            issued_by: document.issued_by,
            provided_by: document.provided_by,
            definitions: document.definitions,
        }
    }
}

/// Compatibility spelling used by the Node binding.
pub type AudienceScopedResult = VerifiedAudienceScopedEvidence;

macro_rules! verified_accessors {
    ($type_name:ty) => {
        impl $type_name {
            #[must_use]
            pub fn evidence(&self) -> &Evidence {
                &self.evidence
            }
            #[must_use]
            pub fn trace_id(&self) -> Option<&str> {
                self.trace_id.as_deref()
            }
            #[must_use]
            pub fn values(&self) -> &BTreeMap<String, PublicValue> {
                &self.values
            }
            pub fn value(&self) -> Result<&PublicValue, EvidenceClientError> {
                if self.values.len() != 1 {
                    return Err(EvidenceClientError::configuration(
                        "the verified result does not have exactly one output; use values instead",
                    ));
                }
                Ok(self
                    .values
                    .values()
                    .next()
                    .expect("the map has exactly one value"))
            }
            #[must_use]
            pub fn subject_continuity(&self) -> &SubjectContinuity {
                &self.subject_continuity
            }
        }
    };
}

verified_accessors!(VerifiedAssertion);
verified_accessors!(VerifiedAudienceScopedCredential);

impl VerifiedAssertion {
    #[must_use]
    pub fn assertion_bytes(&self) -> &[u8] {
        &self.assertion
    }
}

impl VerifiedAudienceScopedCredential {
    #[must_use]
    pub fn credential(&self) -> &str {
        &self.credential
    }
}

impl std::fmt::Debug for VerifiedAssertion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAssertion")
            .field("trace_id", &self.trace_id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for VerifiedAudienceScopedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAudienceScopedCredential")
            .field("trace_id", &self.trace_id)
            .finish_non_exhaustive()
    }
}

pub(crate) fn select_definition<'a>(
    definitions: &'a crate::EvidenceDefinitionsDocument,
    request: &AudienceScopedRequest,
) -> Result<&'a EvidenceDefinition, EvidenceClientError> {
    // Published and reviewed modes both normalize to this document before
    // selection. Validate the complete catalog, not merely the selected entry,
    // so an ambiguous or malformed sibling cannot be hidden by a valid handle.
    definitions.validate_for_progressive_request()?;
    if !matches!(
        request.response_format,
        EvidenceResponseFormat::SignedJws | EvidenceResponseFormat::SdJwtVc
    ) {
        return Err(EvidenceClientError::configuration(
            "the progressive API supports signed JWS and audience-scoped SD-JWT VC only",
        ));
    }
    let matches = definitions
        .definitions
        .iter()
        .filter(|definition| {
            definition.handle == request.requirement
                && definition.subject_binding_mode.unwrap_or(
                    registry_evidence_verifier::model::SubjectBindingMode::AudienceScoped,
                ) == registry_evidence_verifier::model::SubjectBindingMode::AudienceScoped
                && definition
                    .response_formats
                    .iter()
                    .any(|format| format.supports(request.response_format))
                && definition_shape_matches(definition, request)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(EvidenceClientError::configuration(
            "the request did not select exactly one complete published definition",
        ));
    }
    Ok(matches[0])
}

fn definition_shape_matches(
    definition: &EvidenceDefinition,
    request: &AudienceScopedRequest,
) -> bool {
    let request_origin = definition
        .subjects
        .iter()
        .filter(|subject| subject.selector.value_origin == SelectorValueOrigin::Request)
        .collect::<Vec<_>>();
    if let Some(subjects) = &request.subjects {
        if !request.selectors.is_empty() {
            return false;
        }
        let expected_roles = request_origin
            .iter()
            .map(|subject| subject.role.as_str())
            .collect::<BTreeSet<_>>();
        let actual_roles = subjects.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if expected_roles != actual_roles {
            return false;
        }
        request_origin.iter().all(|subject| {
            subjects
                .get(&subject.role)
                .is_some_and(|values| exact_fields(subject, values))
        })
    } else if request_origin.is_empty() {
        request.selectors.is_empty()
    } else {
        request_origin.len() == 1 && exact_fields(request_origin[0], &request.selectors)
    }
}

fn exact_fields(
    subject: &crate::DefinitionSubject,
    values: &BTreeMap<String, SelectorValue>,
) -> bool {
    let fields = subject
        .selector
        .fields
        .iter()
        .map(|field| field.name())
        .collect::<BTreeSet<_>>();
    fields == values.keys().map(String::as_str).collect::<BTreeSet<_>>()
        && subject.selector.fields.iter().all(|field| {
            values
                .get(field.name())
                .is_some_and(|value| field.accepts(value))
        })
}

pub(crate) fn spec_from_definition(
    document: &crate::EvidenceDefinitionsDocument,
    definition: &EvidenceDefinition,
    request: &AudienceScopedRequest,
    maximum_assertion_lifetime_seconds: u64,
    clock_skew_seconds: u64,
) -> Result<EvidenceRequestSpec, EvidenceClientError> {
    document.validate_for_progressive_request()?;
    let subjects = definition
        .subjects
        .iter()
        .map(|subject| {
            let selector_values = if subject.selector.value_origin == SelectorValueOrigin::Request {
                let values = request
                    .subjects
                    .as_ref()
                    .and_then(|subjects| subjects.get(&subject.role))
                    .unwrap_or(&request.selectors);
                Some(
                    values
                        .iter()
                        .map(|(name, value)| (name.clone(), value.clone()))
                        .collect(),
                )
            } else {
                None
            };
            SubjectRequest {
                role: subject.role.clone(),
                selector_profile: subject.selector.profile.clone(),
                selector_values,
            }
        })
        .collect();
    let expected_outputs = definition
        .concepts
        .iter()
        .map(|concept| {
            concept
                .scalar_expected_output()
                .or_else(|| concept.list_expected_output())
                .ok_or_else(|| {
                    EvidenceClientError::configuration("the published output form is unsupported")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let subject_expectations = match &request.binding_receipt {
        Some(receipt) => {
            if receipt.schema != SUBJECT_BINDING_RECEIPT_SCHEMA_V1
                || receipt.audience != document.audience
                || receipt.issued_by != document.issued_by
                || receipt.provided_by != document.provided_by
                || receipt.requirement != definition.requirement
                || receipt.evidence_type != definition.evidence_type
                || receipt.purpose != definition.purpose
                || receipt.configuration_revision != definition.configuration_revision
                || receipt.selector_profiles
                    != definition
                        .subjects
                        .iter()
                        .map(|subject| (subject.role.clone(), subject.selector.profile.clone()))
                        .collect()
                || !receipt_subjects_are_valid(receipt, definition)
            {
                return Err(EvidenceClientError::configuration(
                    "the subject-binding receipt has the wrong verification scope",
                ));
            }
            SubjectExpectations::Pinned(receipt.subjects.clone())
        }
        None => SubjectExpectations::AcceptFirstUse,
    };
    Ok(EvidenceRequestSpec {
        response_format: request.response_format,
        requirement: definition.requirement.clone(),
        purpose: definition.purpose.clone(),
        audience: document.audience.clone(),
        evidence_type: definition.evidence_type.clone(),
        issued_by: document.issued_by.clone(),
        provided_by: document.provided_by.clone(),
        configuration_revision: definition.configuration_revision.clone(),
        expected_assurance_profile: document.assurance_profile,
        subjects,
        holder_keys: Vec::new(),
        expected_outputs,
        maximum_assertion_lifetime_seconds,
        clock_skew_seconds,
        subject_expectations,
    })
}

fn receipt_subjects_are_valid(
    receipt: &SubjectBindingReceipt,
    definition: &EvidenceDefinition,
) -> bool {
    if receipt.subjects.len() != definition.subjects.len() || receipt.subjects.is_empty() {
        return false;
    }
    let expected_roles = definition
        .subjects
        .iter()
        .map(|subject| subject.role.as_str())
        .collect::<BTreeSet<_>>();
    let mut actual_roles = BTreeSet::new();
    receipt.subjects.iter().all(|subject| {
        expected_roles.contains(subject.role.as_str())
            && actual_roles.insert(subject.role.as_str())
            && valid_subject_binding(&subject.binding)
    }) && actual_roles == expected_roles
}

fn valid_subject_binding(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("urn:evidence:subject:v") else {
        return false;
    };
    let Some((version, binding)) = rest.split_once('_') else {
        return false;
    };
    !version.is_empty()
        && version.as_bytes()[0] != b'0'
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && binding.len() == 43
        && binding
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn progressive_result(
    definition: &EvidenceDefinition,
    format: EvidenceResponseFormat,
    raw: crate::RawEvidenceResponse,
    verified: VerifiedEvidence,
    matched: bool,
) -> Result<VerifiedAudienceScopedEvidence, EvidenceClientError> {
    let values = definition
        .concepts
        .iter()
        .map(|concept| {
            let value = verified
                .evidence
                .supported_values
                .iter()
                .find(|value| value.provides_value_for == concept.concept)
                .map(|value| value.value.clone());
            (concept, value)
        })
        .filter_map(|(concept, value)| value.map(|value| (concept.handle.clone(), value)))
        .collect::<BTreeMap<_, _>>();
    let receipt = SubjectBindingReceipt {
        schema: SUBJECT_BINDING_RECEIPT_SCHEMA_V1.to_owned(),
        audience: verified.evidence.audience.clone().ok_or_else(|| {
            EvidenceClientError::configuration("the verified result is not audience scoped")
        })?,
        issued_by: verified.evidence.issued_by.clone(),
        provided_by: verified.evidence.provided_by.clone(),
        requirement: verified.evidence.supports_requirement.clone(),
        evidence_type: verified.evidence.is_conformant_to.clone(),
        purpose: verified.evidence.purpose.clone(),
        configuration_revision: verified.evidence.configuration_revision.clone(),
        selector_profiles: definition
            .subjects
            .iter()
            .map(|subject| (subject.role.clone(), subject.selector.profile.clone()))
            .collect(),
        subjects: verified.pinned_subject_expectations(),
    };
    let continuity = if matched {
        SubjectContinuity::Matched { receipt }
    } else {
        SubjectContinuity::FirstUse { receipt }
    };
    match format {
        EvidenceResponseFormat::SignedJws => Ok(VerifiedAudienceScopedEvidence::Assertion(
            VerifiedAssertion {
                evidence: verified.evidence,
                trace_id: verified.trace_id,
                assertion: raw.body().to_vec(),
                values,
                subject_continuity: continuity,
            },
        )),
        EvidenceResponseFormat::SdJwtVc => {
            let credential = String::from_utf8(raw.body().to_vec()).map_err(|_| {
                EvidenceClientError::configuration("the verified credential is not UTF-8")
            })?;
            Ok(VerifiedAudienceScopedEvidence::Credential(
                VerifiedAudienceScopedCredential {
                    evidence: verified.evidence,
                    trace_id: verified.trace_id,
                    credential,
                    values,
                    subject_continuity: continuity,
                },
            ))
        }
        EvidenceResponseFormat::SdJwtVcBatch => Err(EvidenceClientError::configuration(
            "the progressive API does not support batches",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definitions() -> crate::EvidenceDefinitionsDocument {
        serde_json::from_value(serde_json::json!({
            "schema": "registry.evidence-definitions/v1",
            "assuranceProfile": "local",
            "audience": "urn:example:audience:client",
            "issuedBy": "urn:example:issuer",
            "providedBy": "urn:example:provider",
            "holderBoundBatchMaxSize": 1,
            "definitions": [{
                "handle": "status-check",
                "requirement": "urn:example:requirement:status",
                "configurationRevision": format!("sha256:{}", "1".repeat(64)),
                "kind": "criterion",
                "evidenceType": "urn:example:evidence-type:status",
                "purpose": "decision",
                "responseFormats": ["signed-jws", "sd-jwt-vc"],
                "referenceFrameworks": ["urn:example:framework"],
                "subjects": [{
                    "role": "person",
                    "cardinality": "one",
                    "selector": {
                        "profile": "person-id",
                        "valueOrigin": "request",
                        "fields": [{"type":"string","name":"person_id","minimumBytes":1,"maximumBytes":64}]
                    }
                }],
                "concepts": [{"handle":"eligible","concept":"urn:example:concept:eligible","required":true,"form":"boolean"}]
            }]
        })).expect("definition fixture parses")
    }

    fn request() -> AudienceScopedRequest {
        AudienceScopedRequest::new(
            "status-check",
            BTreeMap::from([("person_id".to_owned(), SelectorValue::from("person-123"))]),
        )
    }

    #[test]
    fn one_public_handle_and_exact_selector_shape_selects_one_definition() {
        let definitions = definitions();
        let selected = select_definition(&definitions, &request()).expect("one definition matches");
        assert_eq!(selected.handle, "status-check");

        let wrong_handle = AudienceScopedRequest::new("other", BTreeMap::new());
        assert!(select_definition(&definitions, &wrong_handle).is_err());
        let extra_field = AudienceScopedRequest::new(
            "status-check",
            BTreeMap::from([
                ("person_id".to_owned(), SelectorValue::from("person-123")),
                ("extra".to_owned(), SelectorValue::from("refused")),
            ]),
        );
        assert!(select_definition(&definitions, &extra_field).is_err());
    }

    #[test]
    fn selector_values_must_match_the_published_scalar_type_and_bounds() {
        let definitions = definitions();
        for selectors in [
            BTreeMap::from([("person_id".to_owned(), SelectorValue::from(true))]),
            BTreeMap::from([("person_id".to_owned(), SelectorValue::from(""))]),
            BTreeMap::from([("person_id".to_owned(), SelectorValue::from("x".repeat(65)))]),
        ] {
            let request = AudienceScopedRequest::new("status-check", selectors);
            assert!(select_definition(&definitions, &request).is_err());
        }
    }

    #[test]
    fn malformed_catalogs_fail_before_definition_selection() {
        let mut malformed = definitions();
        malformed.definitions[0].concepts[0].handle = "Uppercase".to_owned();
        assert!(select_definition(&malformed, &request()).is_err());

        let mut ambiguous = definitions();
        let mut duplicate = ambiguous.definitions[0].clone();
        duplicate.requirement = "urn:example:requirement:other".to_owned();
        ambiguous.definitions.push(duplicate);
        assert!(select_definition(&ambiguous, &request()).is_err());

        let mut non_unique_list = definitions();
        non_unique_list.definitions[0].concepts[0].form =
            crate::definitions::DefinitionConceptForm::List(
                crate::definitions::DefinitionListForm {
                    list: crate::definitions::DefinitionList {
                        items: crate::definitions::DefinitionListItemForm::String,
                        minimum_items: 1,
                        maximum_items: 2,
                        unique: false,
                    },
                },
            );
        assert!(select_definition(&non_unique_list, &request()).is_err());
    }

    #[test]
    fn reviewed_contract_drift_reaches_the_same_closed_validation_path() {
        // Profile loading normalizes the reviewed schema into the requester
        // definitions shape. Semantic drift in its client-safe definitions
        // must therefore fail at the same pre-selection enforcement point as
        // drift in a live published catalog.
        let mut normalized_reviewed = definitions();
        normalized_reviewed.definitions[0].configuration_revision = "unreviewed".to_owned();
        assert!(select_definition(&normalized_reviewed, &request()).is_err());
    }

    #[test]
    fn required_and_optional_output_status_is_retained_in_the_closed_policy() {
        let mut definitions = definitions();
        definitions.definitions[0].concepts[0].required = false;
        let definition =
            select_definition(&definitions, &request()).expect("the optional definition matches");
        let spec = spec_from_definition(&definitions, definition, &request(), 300, 30)
            .expect("the optional output policy closes");
        assert_eq!(spec.expected_outputs.len(), 1);
        assert!(!spec.expected_outputs[0].required);
    }

    #[test]
    fn first_use_is_explicit_and_a_receipt_must_match_the_complete_scope() {
        let definitions = definitions();
        let definition =
            select_definition(&definitions, &request()).expect("one definition matches");
        let first = spec_from_definition(&definitions, definition, &request(), 300, 30)
            .expect("first-use request closes");
        assert!(matches!(
            first.subject_expectations,
            SubjectExpectations::AcceptFirstUse
        ));

        let receipt = SubjectBindingReceipt {
            schema: SUBJECT_BINDING_RECEIPT_SCHEMA_V1.to_owned(),
            audience: definitions.audience.clone(),
            issued_by: definitions.issued_by.clone(),
            provided_by: definitions.provided_by.clone(),
            requirement: definition.requirement.clone(),
            evidence_type: definition.evidence_type.clone(),
            purpose: definition.purpose.clone(),
            configuration_revision: definition.configuration_revision.clone(),
            selector_profiles: BTreeMap::from([("person".to_owned(), "person-id".to_owned())]),
            subjects: vec![ExpectedSubjectDocument {
                role: "person".to_owned(),
                binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
            }],
        };
        let matched = request().with_binding_receipt(receipt.clone());
        let spec = spec_from_definition(&definitions, definition, &matched, 300, 30)
            .expect("matching receipt closes");
        assert!(matches!(
            spec.subject_expectations,
            SubjectExpectations::Pinned(_)
        ));

        let mut wrong = receipt;
        wrong.purpose = "another-purpose".to_owned();
        assert!(spec_from_definition(
            &definitions,
            definition,
            &request().with_binding_receipt(wrong),
            300,
            30,
        )
        .is_err());
    }

    #[test]
    fn a_receipt_with_malformed_duplicate_or_wrong_roles_is_refused() {
        let definitions = definitions();
        let definition = &definitions.definitions[0];
        let receipt = SubjectBindingReceipt {
            schema: SUBJECT_BINDING_RECEIPT_SCHEMA_V1.to_owned(),
            audience: definitions.audience.clone(),
            issued_by: definitions.issued_by.clone(),
            provided_by: definitions.provided_by.clone(),
            requirement: definition.requirement.clone(),
            evidence_type: definition.evidence_type.clone(),
            purpose: definition.purpose.clone(),
            configuration_revision: definition.configuration_revision.clone(),
            selector_profiles: BTreeMap::from([("person".to_owned(), "person-id".to_owned())]),
            subjects: vec![ExpectedSubjectDocument {
                role: "person".to_owned(),
                binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
            }],
        };

        let mut malformed = receipt.clone();
        malformed.subjects[0].binding = "raw-selector-value".to_owned();
        let mut wrong_role = receipt.clone();
        wrong_role.subjects[0].role = "another-role".to_owned();
        let mut duplicate = receipt;
        duplicate.subjects.push(duplicate.subjects[0].clone());
        for receipt in [malformed, wrong_role, duplicate] {
            assert!(spec_from_definition(
                &definitions,
                definition,
                &request().with_binding_receipt(receipt),
                300,
                30,
            )
            .is_err());
        }
    }
}
