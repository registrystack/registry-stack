//! Closing the expectations before the request exists.
//!
//! A relying party decides what an acceptable answer looks like from its own
//! trusted state: the relying procedure, a requirement contract it already
//! trusts, and subject bindings it already holds. `prepare` writes those
//! decisions into a verification policy document and generates the request
//! nonce, all before any byte leaves the process. Verification then compares the
//! response against a policy the response could not have influenced.

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};

use registry_evidence_verifier::{
    verifier::{
        EvidenceVerificationPolicyDocument, ExpectedOutputDocument, ExpectedSubjectDocument,
    },
    AssuranceProfile,
};

use crate::{
    error::EvidenceClientError,
    nonce::RequestNonce,
    request::{EvidenceRequestBody, RequestedSelector, RequestedSubject, SelectorValue},
};

/// Largest role set one request may carry, per the request contract.
///
/// The refusal message spells this bound in words, and a test asserts the two
/// agree, so a changed constant cannot leave the message stating a rule the
/// client does not apply. The same holds for the two bounds below it.
pub const MAXIMUM_SUBJECTS: usize = 8;
/// Largest selector value set one subject may carry, per the request contract.
pub const MAXIMUM_SELECTOR_VALUES: usize = 16;
/// Largest expected output set a policy may state. A Version 1 requirement
/// cannot publish more concepts than this.
pub const MAXIMUM_EXPECTED_OUTPUTS: usize = 16;
/// Longest identifier any expectation may carry.
pub const MAXIMUM_IDENTIFIER_BYTES: usize = 512;
/// Longest string a selector value may carry.
pub const MAXIMUM_SELECTOR_STRING_BYTES: usize = 512;
/// Smallest selector integer the request contract accepts. The bound is the
/// range a double represents exactly, so the value survives every JSON reader
/// between here and the source.
pub const MINIMUM_SELECTOR_INTEGER: i64 = -9_007_199_254_740_991;
/// Largest selector integer the request contract accepts.
pub const MAXIMUM_SELECTOR_INTEGER: i64 = 9_007_199_254_740_991;

/// One requested subject, before the request body exists.
#[derive(Debug, Clone)]
pub struct SubjectRequest {
    pub role: String,
    pub selector_profile: String,
    /// Present only for a selector profile whose values originate in the
    /// request. Discovery states each profile's value origin.
    pub selector_values: Option<Vec<(String, SelectorValue)>>,
}

/// What the relying party will accept, and from which request.
///
/// Every field except `subjects` is an expectation. The values come from the
/// relying procedure; discovery is a convenient place to read them once while
/// authoring that procedure, never a per-request authority.
#[derive(Debug, Clone)]
pub struct EvidenceRequestSpec {
    pub requirement: String,
    pub purpose: String,
    /// The relying party's own audience identifier, as the deployment
    /// registered it.
    pub audience: String,
    /// The requirement's evidence type. The payload states it as
    /// `isConformantTo`, and discovery publishes it as `evidenceType`.
    pub evidence_type: String,
    pub issued_by: String,
    pub provided_by: String,
    pub configuration_revision: String,
    pub expected_assurance_profile: AssuranceProfile,
    pub subjects: Vec<SubjectRequest>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
    pub maximum_assertion_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
    pub subject_expectations: SubjectExpectations,
}

/// How the role-bound subject bindings in the response are to be judged.
///
/// A binding is a keyed one-way value the deployment computes with a secret it
/// alone holds. A relying party therefore cannot derive the expected binding
/// for a subject it has never seen, and the verifier requires the subject set
/// to match exactly. That leaves two honest options, and this enum is both of
/// them.
#[derive(Clone)]
pub enum SubjectExpectations {
    /// Bindings the relying party already holds for these roles, from an
    /// out-of-band exchange or from an earlier accepted transaction.
    ///
    /// This is the only setting under which a verified response proves that the
    /// assertion is about the subject the relying party meant.
    Pinned(Vec<ExpectedSubjectDocument>),

    /// Adopt the bindings this response carries, then pin them.
    ///
    /// Verification still enforces every other expectation: the signature
    /// against the pinned key set, the issuer, the provider, the requirement,
    /// the evidence type, the purpose, the audience, the configuration
    /// revision, the request nonce, the expected outputs and their forms, and
    /// the validity interval. Only the subject set is taken from the payload.
    ///
    /// What this does not prove: that the assertion is about the subject the
    /// relying party meant. The deployment resolved the selector, and this
    /// setting accepts its answer for the identity question. It is the
    /// first-contact case, modelled on re-verifying a retained response from an
    /// accepted transaction: accept once, persist the bindings the verified
    /// response exposes, and pass `Pinned` from then on, at which point a
    /// changed subject becomes a verification failure.
    AcceptFirstUse,
}

impl std::fmt::Debug for SubjectExpectations {
    /// A binding is a pseudonymous per-subject identifier, so only the shape of
    /// the expectation is rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pinned(subjects) => formatter
                .debug_struct("Pinned")
                .field("roles", &subjects.len())
                .finish_non_exhaustive(),
            Self::AcceptFirstUse => formatter.write_str("AcceptFirstUse"),
        }
    }
}

/// A request body and the closed policy that will judge its answer.
///
/// One prepared request is good for exactly one exchange, and this type enforces
/// that: the first send attempt claims it, and a second is refused before any
/// I/O. A nonce reused across two requests would let an answer to the first
/// satisfy the policy for the second, and a deployment never uniqueness-checks
/// the nonce, so a resend would silently earn a second source access and a
/// second audit entry. Retrying means preparing again.
///
/// Verifying is separate and unrestricted: it is offline and idempotent, so a
/// relying party may re-verify a retained response as often as it likes.
///
/// This type is deliberately not `Clone`. A clone would carry the same nonce
/// with its own unclaimed flag, which is exactly the reuse the flag prevents.
pub struct PreparedEvidenceRequest {
    body: EvidenceRequestBody,
    /// The policy with every expectation except the subject set, which
    /// `subject_expectations` decides.
    policy: EvidenceVerificationPolicyDocument,
    subject_expectations: SubjectExpectations,
    /// Whether a send attempt has already claimed this request.
    sent: AtomicBool,
}

impl PreparedEvidenceRequest {
    /// Validate a specification, generate its nonce, and close its policy.
    pub(crate) fn new(spec: EvidenceRequestSpec) -> Result<Self, EvidenceClientError> {
        validate(&spec)?;
        let nonce = RequestNonce::generate()?;

        let subjects = spec
            .subjects
            .into_iter()
            .map(|subject| RequestedSubject {
                role: subject.role,
                selector: RequestedSelector {
                    profile: subject.selector_profile,
                    values: subject
                        .selector_values
                        .map(|values| values.into_iter().collect()),
                },
            })
            .collect();
        let body = EvidenceRequestBody {
            request_nonce: nonce.as_str().to_owned(),
            requirement: spec.requirement.clone(),
            purpose: spec.purpose.clone(),
            subjects,
        };

        let expected_subjects = match &spec.subject_expectations {
            SubjectExpectations::Pinned(subjects) => subjects.clone(),
            // The response has not been fetched, so there is nothing honest to
            // put here yet. Verification substitutes the adopted set.
            SubjectExpectations::AcceptFirstUse => Vec::new(),
        };
        let policy = EvidenceVerificationPolicyDocument {
            expected_assurance_profile: spec.expected_assurance_profile,
            issued_by: spec.issued_by,
            provided_by: spec.provided_by,
            requirement: spec.requirement,
            evidence_type: spec.evidence_type,
            purpose: spec.purpose,
            audience: spec.audience,
            configuration_revision: spec.configuration_revision,
            request_nonce: nonce.as_str().to_owned(),
            expected_subjects,
            expected_outputs: spec.expected_outputs,
            maximum_assertion_lifetime_seconds: spec.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: spec.clock_skew_seconds,
        };
        Ok(Self {
            body,
            policy,
            subject_expectations: spec.subject_expectations,
            sent: AtomicBool::new(false),
        })
    }

    /// The nonce this request carries. Retain it with the transaction record:
    /// re-verifying the stored response later needs the nonce from the request,
    /// not from the response.
    #[must_use]
    pub fn request_nonce(&self) -> &str {
        &self.body.request_nonce
    }

    /// The closed policy, with the subject set as `prepare` left it. It is
    /// serializable, so a relying party can retain it beside the response.
    #[must_use]
    pub fn policy_document(&self) -> &EvidenceVerificationPolicyDocument {
        &self.policy
    }

    #[must_use]
    pub fn subject_expectations(&self) -> &SubjectExpectations {
        &self.subject_expectations
    }

    pub(crate) fn body(&self) -> &EvidenceRequestBody {
        &self.body
    }

    /// Claim the single send this prepared request is good for.
    ///
    /// The claim is taken before any I/O, and an attempt that fails on the wire
    /// still spends it: the deployment may have answered the request even when
    /// the relying party never read the answer, and resending the same nonce
    /// would earn a second source access and a second audit entry there.
    pub(crate) fn claim_single_send(&self) -> Result<(), EvidenceClientError> {
        if self.sent.swap(true, Ordering::SeqCst) {
            return Err(EvidenceClientError::configuration(
                "a prepared request may be sent once; prepare again for a fresh nonce",
            ));
        }
        Ok(())
    }

    /// The same policy with an explicit subject set. This is how first-use
    /// acceptance reaches the ordinary verifier: the adopted bindings become
    /// stated expectations, and nothing else about the policy changes.
    ///
    /// First use defers which subject an assertion is about, not which roles were
    /// asked about. A claimed set that does not cover exactly the requested roles,
    /// once each, is adopted as nothing at all, which leaves the verifier to
    /// refuse the response on the policy it was given.
    pub(crate) fn policy_with_subjects(
        &self,
        claimed_subjects: Vec<ExpectedSubjectDocument>,
    ) -> EvidenceVerificationPolicyDocument {
        let mut policy = self.policy.clone();
        policy.expected_subjects = if self.covers_requested_roles(&claimed_subjects) {
            claimed_subjects
        } else {
            Vec::new()
        };
        policy
    }

    /// Whether a claimed subject set names exactly the requested roles, once
    /// each.
    fn covers_requested_roles(&self, claimed_subjects: &[ExpectedSubjectDocument]) -> bool {
        claimed_subjects.len() == self.body.subjects.len()
            && self.body.subjects.iter().all(|requested| {
                claimed_subjects
                    .iter()
                    .filter(|claimed| claimed.role == requested.role)
                    .count()
                    == 1
            })
    }
}

impl std::fmt::Debug for PreparedEvidenceRequest {
    /// The selector values and the expected bindings are withheld.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedEvidenceRequest")
            .field("requirement", &self.policy.requirement)
            .field("request_nonce", &self.policy.request_nonce)
            .field("subject_expectations", &self.subject_expectations)
            .finish_non_exhaustive()
    }
}

/// Refuse a specification the deployment would refuse, or one whose policy
/// could not decide anything.
fn validate(spec: &EvidenceRequestSpec) -> Result<(), EvidenceClientError> {
    // Presence and length only. The contract also states `format: uri` for
    // these identifiers, and the deployment asserts it, so restating it here
    // would put a second opinion in front of the deciding one: a URL parser and
    // a JSON Schema `uri` implementation can disagree in either direction, and
    // either disagreement is a bug the adopter cannot work around. The
    // deployment's answer stands.
    //
    // Each field carries its own reason, because the fix is a different edit to
    // the relying procedure in each case.
    for (identifier, reason) in [
        (
            &spec.requirement,
            "the requirement identifier must be present and bounded",
        ),
        (
            &spec.audience,
            "the audience identifier must be present and bounded",
        ),
        (
            &spec.evidence_type,
            "the evidence type identifier must be present and bounded",
        ),
        (
            &spec.issued_by,
            "the issuer identifier must be present and bounded",
        ),
        (
            &spec.provided_by,
            "the provider identifier must be present and bounded",
        ),
        (
            &spec.configuration_revision,
            "the configuration revision identifier must be present and bounded",
        ),
    ] {
        if identifier.is_empty() || identifier.len() > MAXIMUM_IDENTIFIER_BYTES {
            return Err(EvidenceClientError::configuration(reason));
        }
    }
    if !is_purpose(&spec.purpose) {
        return Err(EvidenceClientError::configuration(
            "the purpose must match the request contract's own lexical rule",
        ));
    }
    if spec.subjects.is_empty() || spec.subjects.len() > MAXIMUM_SUBJECTS {
        return Err(EvidenceClientError::configuration(
            "a request must carry between one and eight subject roles",
        ));
    }

    let mut roles = BTreeSet::new();
    for subject in &spec.subjects {
        if !is_role(&subject.role) || !roles.insert(subject.role.clone()) {
            return Err(EvidenceClientError::configuration(
                "each subject role must match the request contract's lexical rule and appear once",
            ));
        }
        if !is_selector_profile(&subject.selector_profile) {
            return Err(EvidenceClientError::configuration(
                "each selector profile must match the request contract's lexical rule",
            ));
        }
        validate_selector_values(subject.selector_values.as_deref())?;
    }

    if spec.expected_outputs.is_empty() || spec.expected_outputs.len() > MAXIMUM_EXPECTED_OUTPUTS {
        return Err(EvidenceClientError::configuration(
            "a policy must expect between one and sixteen outputs",
        ));
    }
    let mut concepts = BTreeSet::new();
    for output in &spec.expected_outputs {
        if output.concept.is_empty()
            || output.concept.len() > MAXIMUM_IDENTIFIER_BYTES
            || !concepts.insert(output.concept.as_str())
        {
            return Err(EvidenceClientError::configuration(
                "each expected output must name a bounded concept once",
            ));
        }
    }

    if spec.maximum_assertion_lifetime_seconds == 0 {
        return Err(EvidenceClientError::configuration(
            "the maximum assertion lifetime must be greater than zero",
        ));
    }

    if let SubjectExpectations::Pinned(pinned) = &spec.subject_expectations {
        let pinned_roles: BTreeSet<String> = pinned
            .iter()
            .filter(|subject| !subject.binding.is_empty())
            .map(|subject| subject.role.clone())
            .collect();
        // The verifier requires the subject sets to match exactly, so a policy
        // that pins a different role set than the request asks for could never
        // accept a well-formed answer.
        if pinned.len() != pinned_roles.len() || pinned_roles != roles {
            return Err(EvidenceClientError::configuration(
                "the pinned subject bindings must cover exactly the requested roles, once each",
            ));
        }
    }

    Ok(())
}

fn validate_selector_values(
    values: Option<&[(String, SelectorValue)]>,
) -> Result<(), EvidenceClientError> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.is_empty() || values.len() > MAXIMUM_SELECTOR_VALUES {
        return Err(EvidenceClientError::configuration(
            "a selector that carries values must carry between one and sixteen of them",
        ));
    }
    let mut names = BTreeSet::new();
    for (name, value) in values {
        if !is_selector_field_name(name) || !names.insert(name.as_str()) {
            return Err(EvidenceClientError::configuration(
                "each selector field name must match the request contract's lexical rule and appear once",
            ));
        }
        match value {
            SelectorValue::String(text) => {
                if text.is_empty() || text.len() > MAXIMUM_SELECTOR_STRING_BYTES {
                    return Err(EvidenceClientError::configuration(
                        "each selector string value must be present and bounded",
                    ));
                }
            }
            SelectorValue::Integer(number) => {
                if !(MINIMUM_SELECTOR_INTEGER..=MAXIMUM_SELECTOR_INTEGER).contains(number) {
                    return Err(EvidenceClientError::configuration(
                        "each selector integer value must be within the range a double represents exactly",
                    ));
                }
            }
            SelectorValue::Boolean(_) => {}
        }
    }
    Ok(())
}

/// `^[a-z][a-z0-9._:-]{0,127}$`
fn is_purpose(value: &str) -> bool {
    bounded_lowercase(value, 128, |byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b':' | b'-')
    })
}

/// `^[a-z][a-z0-9._-]{0,63}$`
fn is_role(value: &str) -> bool {
    bounded_lowercase(value, 64, is_name_byte)
}

/// `^[a-z][a-z0-9._-]{0,63}$`
fn is_selector_field_name(value: &str) -> bool {
    bounded_lowercase(value, 64, is_name_byte)
}

/// `^[a-z][a-z0-9._-]{0,127}$`
fn is_selector_profile(value: &str) -> bool {
    bounded_lowercase(value, 128, is_name_byte)
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
}

fn bounded_lowercase(value: &str, maximum_bytes: usize, acceptable: impl Fn(u8) -> bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.bytes().all(acceptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_evidence_verifier::verifier::{ExpectedFormDocument, ExpectedScalarFormDocument};

    fn expected_output() -> ExpectedOutputDocument {
        ExpectedOutputDocument {
            concept: "urn:example:client:concept:status-holds".to_owned(),
            form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
        }
    }

    fn spec() -> EvidenceRequestSpec {
        EvidenceRequestSpec {
            requirement: "urn:example:client:requirement:status:v1".to_owned(),
            purpose: "example-decision".to_owned(),
            audience: "urn:example:client:audience:relying-party".to_owned(),
            evidence_type: "urn:example:client:evidence-type:status:v1".to_owned(),
            issued_by: "urn:example:client:issuer".to_owned(),
            provided_by: "urn:example:client:provider".to_owned(),
            configuration_revision: "sha256:00".to_owned(),
            expected_assurance_profile: AssuranceProfile::Local,
            subjects: vec![SubjectRequest {
                role: "subject".to_owned(),
                selector_profile: "record-lookup-v1".to_owned(),
                selector_values: Some(vec![(
                    "record_reference".to_owned(),
                    SelectorValue::from("synthetic-record-001"),
                )]),
            }],
            expected_outputs: vec![expected_output()],
            maximum_assertion_lifetime_seconds: 300,
            clock_skew_seconds: 60,
            subject_expectations: SubjectExpectations::AcceptFirstUse,
        }
    }

    fn pinned() -> SubjectExpectations {
        SubjectExpectations::Pinned(vec![ExpectedSubjectDocument {
            role: "subject".to_owned(),
            binding: "y0KMdWluZGluZw".to_owned(),
        }])
    }

    #[test]
    fn preparing_closes_the_policy_and_generates_the_nonce_before_any_exchange() {
        let mut spec = spec();
        spec.subject_expectations = pinned();
        let prepared = PreparedEvidenceRequest::new(spec).expect("the specification is accepted");

        // The nonce is one value, shared by the request the deployment sees and
        // the policy that judges its answer.
        assert_eq!(prepared.request_nonce().len(), 43);
        assert_eq!(
            prepared.policy_document().request_nonce,
            prepared.request_nonce()
        );
        assert_eq!(prepared.body().request_nonce, prepared.request_nonce());

        let policy = serde_json::to_value(prepared.policy_document())
            .expect("the policy document serializes");
        assert_eq!(
            policy,
            serde_json::json!({
                "expectedAssuranceProfile": "local",
                "issuedBy": "urn:example:client:issuer",
                "providedBy": "urn:example:client:provider",
                "requirement": "urn:example:client:requirement:status:v1",
                "evidenceType": "urn:example:client:evidence-type:status:v1",
                "purpose": "example-decision",
                "audience": "urn:example:client:audience:relying-party",
                "configurationRevision": "sha256:00",
                "requestNonce": prepared.request_nonce(),
                "expectedSubjects": [{"role": "subject", "binding": "y0KMdWluZGluZw"}],
                "expectedOutputs": [{
                    "concept": "urn:example:client:concept:status-holds",
                    "form": "boolean",
                }],
                "maximumAssertionLifetimeSeconds": 300,
                "clockSkewSeconds": 60,
            })
        );
    }

    #[test]
    fn two_prepared_requests_never_share_a_nonce() {
        let first = PreparedEvidenceRequest::new(spec()).expect("the specification is accepted");
        let second = PreparedEvidenceRequest::new(spec()).expect("the specification is accepted");
        assert_ne!(first.request_nonce(), second.request_nonce());
    }

    #[test]
    fn first_use_acceptance_states_no_subject_until_a_response_supplies_one() {
        let prepared = PreparedEvidenceRequest::new(spec()).expect("the specification is accepted");
        assert!(prepared.policy_document().expected_subjects.is_empty());
        assert!(matches!(
            prepared.subject_expectations(),
            SubjectExpectations::AcceptFirstUse
        ));

        // Adopting a subject set changes only the subject set.
        let adopted = prepared.policy_with_subjects(vec![ExpectedSubjectDocument {
            role: "subject".to_owned(),
            binding: "y0KMdWluZGluZw".to_owned(),
        }]);
        let mut before =
            serde_json::to_value(prepared.policy_document()).expect("the policy serializes");
        let mut after = serde_json::to_value(&adopted).expect("the policy serializes");
        assert_eq!(
            after["expectedSubjects"],
            serde_json::json!([{"role": "subject", "binding": "y0KMdWluZGluZw"}])
        );
        before
            .as_object_mut()
            .expect("the policy is an object")
            .remove("expectedSubjects");
        after
            .as_object_mut()
            .expect("the policy is an object")
            .remove("expectedSubjects");
        assert_eq!(before, after);
    }

    /// One named way of breaking an otherwise acceptable specification.
    type Breakage = (&'static str, Box<dyn Fn(&mut EvidenceRequestSpec)>);

    #[test]
    fn a_specification_the_deployment_would_refuse_is_refused_here() {
        let cases: Vec<Breakage> = vec![
            (
                "an empty requirement",
                Box::new(|spec| spec.requirement = String::new()),
            ),
            (
                "an empty audience",
                Box::new(|spec| spec.audience = String::new()),
            ),
            (
                "an empty evidence type",
                Box::new(|spec| spec.evidence_type = String::new()),
            ),
            (
                "an empty issuer",
                Box::new(|spec| spec.issued_by = String::new()),
            ),
            (
                "an empty provider",
                Box::new(|spec| spec.provided_by = String::new()),
            ),
            (
                "an empty configuration revision",
                Box::new(|spec| spec.configuration_revision = String::new()),
            ),
            (
                "an oversized requirement",
                Box::new(|spec| spec.requirement = "u".repeat(MAXIMUM_IDENTIFIER_BYTES + 1)),
            ),
            (
                "an uppercase purpose",
                Box::new(|spec| spec.purpose = "Example-Decision".to_owned()),
            ),
            (
                "a purpose with a space",
                Box::new(|spec| spec.purpose = "example decision".to_owned()),
            ),
            (
                "an empty purpose",
                Box::new(|spec| spec.purpose = String::new()),
            ),
            ("no subject", Box::new(|spec| spec.subjects.clear())),
            (
                "more subjects than the contract allows",
                Box::new(|spec| {
                    spec.subjects = (0..MAXIMUM_SUBJECTS + 1)
                        .map(|index| SubjectRequest {
                            role: format!("role-{index}"),
                            selector_profile: "record-lookup-v1".to_owned(),
                            selector_values: None,
                        })
                        .collect();
                }),
            ),
            (
                "a repeated role",
                Box::new(|spec| {
                    let subject = spec.subjects[0].clone();
                    spec.subjects.push(subject);
                }),
            ),
            (
                "an uppercase role",
                Box::new(|spec| spec.subjects[0].role = "Subject".to_owned()),
            ),
            (
                "a selector profile with a colon",
                Box::new(|spec| spec.subjects[0].selector_profile = "record:lookup".to_owned()),
            ),
            (
                "a selector that announces values but carries none",
                Box::new(|spec| spec.subjects[0].selector_values = Some(Vec::new())),
            ),
            (
                "an uppercase selector field name",
                Box::new(|spec| {
                    spec.subjects[0].selector_values = Some(vec![(
                        "Record_Reference".to_owned(),
                        SelectorValue::from(1),
                    )]);
                }),
            ),
            (
                "an empty selector string value",
                Box::new(|spec| {
                    spec.subjects[0].selector_values = Some(vec![(
                        "record_reference".to_owned(),
                        SelectorValue::from(""),
                    )]);
                }),
            ),
            (
                "a selector integer below the contract's minimum",
                Box::new(|spec| {
                    spec.subjects[0].selector_values = Some(vec![(
                        "record_reference".to_owned(),
                        SelectorValue::from(MINIMUM_SELECTOR_INTEGER - 1),
                    )]);
                }),
            ),
            (
                "a selector integer above the contract's maximum",
                Box::new(|spec| {
                    spec.subjects[0].selector_values = Some(vec![(
                        "record_reference".to_owned(),
                        SelectorValue::from(MAXIMUM_SELECTOR_INTEGER + 1),
                    )]);
                }),
            ),
            (
                "no expected output",
                Box::new(|spec| spec.expected_outputs.clear()),
            ),
            (
                "a repeated expected concept",
                Box::new(|spec| spec.expected_outputs.push(expected_output())),
            ),
            (
                "a lifetime of zero",
                Box::new(|spec| spec.maximum_assertion_lifetime_seconds = 0),
            ),
            (
                "a pinned role the request does not ask for",
                Box::new(|spec| {
                    spec.subject_expectations =
                        SubjectExpectations::Pinned(vec![ExpectedSubjectDocument {
                            role: "other".to_owned(),
                            binding: "y0KMdWluZGluZw".to_owned(),
                        }]);
                }),
            ),
            (
                "a pinned subject with no binding",
                Box::new(|spec| {
                    spec.subject_expectations =
                        SubjectExpectations::Pinned(vec![ExpectedSubjectDocument {
                            role: "subject".to_owned(),
                            binding: String::new(),
                        }]);
                }),
            ),
            (
                "no pinned subject at all",
                Box::new(|spec| {
                    spec.subject_expectations = SubjectExpectations::Pinned(Vec::new());
                }),
            ),
        ];
        for (description, break_it) in cases {
            let mut spec = spec();
            break_it(&mut spec);
            assert!(
                PreparedEvidenceRequest::new(spec).is_err(),
                "{description} was accepted"
            );
        }
    }

    /// Six identifiers share one rule, and a shared message would leave an
    /// adopter to guess which of the six the request will not carry. Each names
    /// itself.
    #[test]
    fn each_refused_identifier_names_itself() {
        let cases: [Breakage; 6] = [
            (
                "the requirement identifier must be present and bounded",
                Box::new(|spec| spec.requirement.clear()),
            ),
            (
                "the audience identifier must be present and bounded",
                Box::new(|spec| spec.audience.clear()),
            ),
            (
                "the evidence type identifier must be present and bounded",
                Box::new(|spec| spec.evidence_type.clear()),
            ),
            (
                "the issuer identifier must be present and bounded",
                Box::new(|spec| spec.issued_by.clear()),
            ),
            (
                "the provider identifier must be present and bounded",
                Box::new(|spec| spec.provided_by.clear()),
            ),
            (
                "the configuration revision identifier must be present and bounded",
                Box::new(|spec| spec.configuration_revision.clear()),
            ),
        ];
        for (reason, break_it) in cases {
            let mut spec = spec();
            break_it(&mut spec);
            assert_eq!(
                PreparedEvidenceRequest::new(spec).expect_err(reason),
                EvidenceClientError::configuration(reason)
            );
        }
    }

    /// The refusals spell their bounds in words, which is the readable form for
    /// an adopter. A constant that moved without its message would leave the
    /// client stating a rule it does not apply.
    #[test]
    fn the_bounds_the_refusals_spell_are_the_bounds_that_apply() {
        assert_eq!(
            MAXIMUM_SUBJECTS, 8,
            "a refusal says \"between one and eight subject roles\""
        );
        assert_eq!(
            MAXIMUM_EXPECTED_OUTPUTS, 16,
            "a refusal says \"between one and sixteen outputs\""
        );
        assert_eq!(
            MAXIMUM_SELECTOR_VALUES, 16,
            "a refusal says \"between one and sixteen of them\""
        );
    }

    /// The contract's integer bounds are the ones a double can represent
    /// exactly, and both extremes are inside them.
    #[test]
    fn a_selector_integer_at_the_contracts_bounds_is_accepted() {
        for value in [MINIMUM_SELECTOR_INTEGER, 0, MAXIMUM_SELECTOR_INTEGER] {
            let mut spec = spec();
            spec.subjects[0].selector_values = Some(vec![(
                "record_reference".to_owned(),
                SelectorValue::from(value),
            )]);
            PreparedEvidenceRequest::new(spec)
                .unwrap_or_else(|error| panic!("{value} was refused: {error}"));
        }
    }

    #[test]
    fn a_prepared_request_is_claimable_exactly_once() {
        let prepared = PreparedEvidenceRequest::new(spec()).expect("the specification is accepted");
        prepared
            .claim_single_send()
            .expect("the first send may proceed");
        assert_eq!(
            prepared
                .claim_single_send()
                .expect_err("the second send is refused"),
            EvidenceClientError::configuration(
                "a prepared request may be sent once; prepare again for a fresh nonce"
            )
        );
    }

    #[test]
    fn a_selector_whose_values_come_from_the_authenticated_caller_carries_none() {
        let mut spec = spec();
        spec.subjects[0].selector_values = None;
        let prepared = PreparedEvidenceRequest::new(spec).expect("the specification is accepted");
        let body = serde_json::to_string(prepared.body()).expect("the body serializes");
        assert!(!body.contains("values"), "{body}");
    }

    #[test]
    fn debug_output_withholds_selector_values_and_bindings() {
        let mut spec = spec();
        spec.subject_expectations = pinned();
        let prepared = PreparedEvidenceRequest::new(spec).expect("the specification is accepted");
        let rendered = format!("{prepared:?}");
        assert!(!rendered.contains("synthetic-record-001"), "{rendered}");
        assert!(!rendered.contains("y0KMdWluZGluZw"), "{rendered}");
        assert!(rendered.contains("Pinned"), "{rendered}");
    }
}
