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
    model::HolderPublicKey,
    sdjwt_vc::holder_thumbprint,
    verifier::{
        EvidenceVerificationPolicyDocument, ExpectedFormDocument, ExpectedOutputDocument,
        ExpectedSubjectDocument, MAXIMUM_ASSERTION_LIFETIME_SECONDS, MAXIMUM_CLOCK_SKEW_SECONDS,
        MINIMUM_ASSERTION_LIFETIME_SECONDS,
    },
    AssuranceProfile,
};
use registry_platform_crypto::canonicalize_json;

use crate::{
    error::EvidenceClientError,
    nonce::RequestNonce,
    request::{EvidenceRequestBody, RequestedSelector, RequestedSubject, SelectorValue},
    response_format::EvidenceResponseFormat,
};

/// Largest role set one request may carry, per the request contract.
///
/// The refusal message spells this bound in words, and a test asserts the two
/// agree, so a changed constant cannot leave the message stating a rule the
/// client does not apply. The same holds for the two bounds below it.
pub const MAXIMUM_SUBJECTS: usize = 8;
/// Largest selector value set one subject may carry, per the request contract.
pub const MAXIMUM_SELECTOR_VALUES: usize = 16;
/// Largest holder key set one request may carry, per the request contract.
///
/// This is the contract's ceiling, not a deployment's. A deployment declares
/// its own batch ceiling at or below this, and a request within this bound may
/// still be refused there.
pub const MAXIMUM_HOLDER_KEYS: usize = 16;
/// Largest expected output set a policy may state. A Version 1 requirement
/// cannot publish more concepts than this.
pub const MAXIMUM_EXPECTED_OUTPUTS: usize = 16;
/// Longest identifier any expectation may carry.
pub const MAXIMUM_IDENTIFIER_BYTES: usize = 512;
/// Longest string a selector value may carry under the published contract.
///
/// A selected definition still applies its narrower per-field and aggregate
/// bounds before this shared preparation boundary.
pub const MAXIMUM_SELECTOR_STRING_BYTES: usize = 8 * 1024;
/// Smallest selector integer the request contract accepts. The bound is the
/// range a double represents exactly, so the value survives every JSON reader
/// between here and the source.
pub const MINIMUM_SELECTOR_INTEGER: i64 = -9_007_199_254_740_991;
/// Largest selector integer the request contract accepts.
pub const MAXIMUM_SELECTOR_INTEGER: i64 = 9_007_199_254_740_991;
/// Largest list cardinality, minimum or maximum, a list-form expected output
/// may state, per the same contract.
pub const MAXIMUM_LIST_ITEMS: usize = 64;
/// The serializations a holder-bound request may ask for, per the response
/// contract.
///
/// A holder-bound assertion names no relying party, so it can only travel in a
/// serialization that carries the holder key confirmation its verifier checks
/// possession against. The flattened JWS form carries none, so no deployment
/// may transport one in it. The set is restated here, like the ceilings above,
/// because this crate does not depend on the runtime that decides it.
const HOLDER_BOUND_RESPONSE_FORMATS: [EvidenceResponseFormat; 2] = [
    EvidenceResponseFormat::SdJwtVc,
    EvidenceResponseFormat::SdJwtVcBatch,
];

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
    /// Signed response encoding to negotiate and retain for verification.
    pub response_format: EvidenceResponseFormat,
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
    /// Holder public keys the caller already holds, in the order it wants them
    /// answered. Empty for a request that presents none, which is the request
    /// this client has always sent.
    ///
    /// The keys are forwarded unchanged and are never interpreted here. What
    /// they mean to an assertion is the deployment's decision: a batch answer
    /// carries one credential per key, in this order, and under a holder-bound
    /// requirement each credential's subject binding is scoped to its own key.
    /// Neither statement is derived, inferred, or checked by this crate.
    ///
    /// Only public key material can be put here, and this crate never obtains
    /// or wants the private half.
    pub holder_keys: Vec<HolderPublicKey>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
    pub maximum_assertion_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
    pub subject_expectations: SubjectExpectations,
}

/// What the relying party will request when the requirement is holder-bound.
///
/// This is [`EvidenceRequestSpec`] with the audience removed and the holder key
/// set made mandatory, and it is a separate type rather than an
/// `Option<String>` on the one specification. A holder-bound assertion names no
/// audience at all, so an audience member here could only ever be a value the
/// answer will not contain, and a caller would be asked to state it anyway.
///
/// The precedent is the runtime's own: when holder binding arrived it replaced
/// the audience member of its subject-binding input with an enum over the two
/// scopes, so a holder-bound binding that also carries an audience cannot be
/// written down. Two specification types do the same thing one level up.
///
/// Every other expectation is stated exactly as the audience-scoped
/// specification states it, and the same bounds apply to all of them. Where
/// they go afterwards differs: only `requirement`, `purpose`, `subjects`, and
/// `holder_keys` reach the request body, and the rest are checked for the
/// bounds a deployment would refuse and then belong to the relying party's own
/// record and to whoever verifies the eventual presentation. No policy is
/// closed over them here, because none could be; see
/// [`PreparedHolderBoundRequest`].
#[derive(Debug, Clone)]
pub struct HolderBoundRequestSpec {
    /// Signed response encoding to negotiate.
    pub response_format: EvidenceResponseFormat,
    pub requirement: String,
    pub purpose: String,
    /// The requirement's evidence type. The payload states it as
    /// `isConformantTo`, and discovery publishes it as `evidenceType`.
    pub evidence_type: String,
    pub issued_by: String,
    pub provided_by: String,
    pub configuration_revision: String,
    pub expected_assurance_profile: AssuranceProfile,
    pub subjects: Vec<SubjectRequest>,
    /// Holder public keys the caller already holds, in the order it wants them
    /// answered. At least one is required: a holder-bound requirement derives
    /// every subject binding under a presented key, so a request presenting
    /// none is one no deployment can answer.
    ///
    /// The keys are forwarded unchanged and are never interpreted here, exactly
    /// as on the audience-scoped path. Only public key material can be put
    /// here, and this crate never obtains or wants the private half.
    pub holder_keys: Vec<HolderPublicKey>,
    pub expected_outputs: Vec<ExpectedOutputDocument>,
    pub maximum_assertion_lifetime_seconds: u64,
    pub clock_skew_seconds: u64,
    /// The subject bindings the relying party will judge a presentation
    /// against, carried forward so they survive alongside the request record.
    /// Nothing here judges an issuance-time answer; see
    /// [`PreparedHolderBoundRequest`] for why there is no policy to judge it
    /// with.
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
    response_format: EvidenceResponseFormat,
    /// The policy with every expectation except the subject set, which
    /// `subject_expectations` decides.
    policy: EvidenceVerificationPolicyDocument,
    subject_expectations: SubjectExpectations,
    /// Whether a send attempt has already claimed this request.
    sent: AtomicBool,
}

impl PreparedEvidenceRequest {
    /// Validate a specification, generate its nonce, and close its policy.
    pub(crate) fn new_with_revoked_key_ids(
        spec: EvidenceRequestSpec,
        revoked_key_ids: Vec<String>,
    ) -> Result<Self, EvidenceClientError> {
        validate(&spec)?;
        let nonce = RequestNonce::generate()?;
        let response_format = spec.response_format;

        let body = request_body(
            &nonce,
            spec.requirement.clone(),
            spec.purpose.clone(),
            spec.subjects,
            spec.holder_keys,
        );

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
            revoked_key_ids,
            maximum_assertion_lifetime_seconds: spec.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: spec.clock_skew_seconds,
        };
        Ok(Self {
            body,
            response_format,
            policy,
            subject_expectations: spec.subject_expectations,
            sent: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    fn new(spec: EvidenceRequestSpec) -> Result<Self, EvidenceClientError> {
        Self::new_with_revoked_key_ids(spec, Vec::new())
    }

    /// The nonce this request carries. Retain it with the transaction record:
    /// re-verifying the stored response later needs the nonce from the request,
    /// not from the response.
    #[must_use]
    pub fn request_nonce(&self) -> &str {
        &self.body.request_nonce
    }

    /// Serialize the exact request body that corresponds to the closed policy.
    ///
    /// This performs no I/O. Selector values are present because they are part
    /// of the request, so callers should retain the returned bytes with the
    /// same care as the original selector input.
    pub fn request_json(&self) -> Result<Vec<u8>, EvidenceClientError> {
        serialize_request(&self.body)
    }

    /// The response encoding selected before this request is sent.
    #[must_use]
    pub fn response_format(&self) -> EvidenceResponseFormat {
        self.response_format
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

    pub(crate) fn requested_roles(&self) -> Vec<String> {
        self.body
            .subjects
            .iter()
            .map(|subject| subject.role.clone())
            .collect()
    }

    pub(crate) fn request_body(&self) -> &EvidenceRequestBody {
        &self.body
    }

    /// Claim the single send this prepared request is good for.
    ///
    /// The claim is taken before any I/O, and an attempt that fails on the wire
    /// still spends it: the deployment may have answered the request even when
    /// the relying party never read the answer, and resending the same nonce
    /// would earn a second source access and a second audit entry there.
    pub(crate) fn claim_single_send(&self) -> Result<(), EvidenceClientError> {
        claim_single_send(&self.sent)
    }
}

impl std::fmt::Debug for PreparedEvidenceRequest {
    /// The selector values and the expected bindings are withheld.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedEvidenceRequest")
            .field("requirement", &self.policy.requirement)
            .field("request_nonce", &self.policy.request_nonce)
            .field("response_format", &self.response_format)
            .field("subject_expectations", &self.subject_expectations)
            .finish_non_exhaustive()
    }
}

/// A holder-bound request body, and no policy to judge its answer with.
///
/// The missing policy is the point, not an omission. A Version 1 verification
/// policy pins one audience and expects an audience-scoped assertion; a
/// holder-bound credential names no audience, so no such document describes
/// one, and closing a policy here would close one that could never accept any
/// answer to this request. Nothing is substituted for it: an invented
/// placeholder would be a verification decision this crate has no standing to
/// make.
///
/// Issuance-side non-verification is correct behaviour here rather than a gap.
/// What proves a holder-bound credential is a presentation, and a presentation
/// carries a key-binding JWT signed with the holder private half, over an
/// audience and a nonce the verifier supplies at that moment. None of that
/// exists yet when the credential is issued, and this crate never holds the
/// private half in any case.
///
/// The single-send rule is the audience-scoped rule, unchanged: the first send
/// attempt claims this request and a second is refused before any I/O, because
/// a resent nonce earns a second source access and a second audit entry at the
/// deployment. Not `Clone`, for the same reason.
pub struct PreparedHolderBoundRequest {
    body: EvidenceRequestBody,
    response_format: EvidenceResponseFormat,
    /// Carried forward for the relying party's own record, and read by nothing
    /// here. There is no policy for it to complete.
    subject_expectations: SubjectExpectations,
    /// Whether a send attempt has already claimed this request.
    sent: AtomicBool,
}

impl PreparedHolderBoundRequest {
    /// Validate a holder-bound specification and generate its nonce.
    pub(crate) fn new(spec: HolderBoundRequestSpec) -> Result<Self, EvidenceClientError> {
        validate_holder_bound(&spec)?;
        let nonce = RequestNonce::generate()?;
        let body = request_body(
            &nonce,
            spec.requirement,
            spec.purpose,
            spec.subjects,
            spec.holder_keys,
        );
        Ok(Self {
            body,
            response_format: spec.response_format,
            subject_expectations: spec.subject_expectations,
            sent: AtomicBool::new(false),
        })
    }

    /// The nonce this request carries. Retain it with the transaction record.
    #[must_use]
    pub fn request_nonce(&self) -> &str {
        &self.body.request_nonce
    }

    /// Serialize the exact request body this prepared request will send.
    ///
    /// This performs no I/O. Selector values and holder keys are present
    /// because they are part of the request, so callers should retain the
    /// returned bytes with the same care as the original input.
    pub fn request_json(&self) -> Result<Vec<u8>, EvidenceClientError> {
        serialize_request(&self.body)
    }

    /// The response encoding selected before this request is sent.
    #[must_use]
    pub fn response_format(&self) -> EvidenceResponseFormat {
        self.response_format
    }

    /// The subject expectations the caller stated, returned unchanged.
    #[must_use]
    pub fn subject_expectations(&self) -> &SubjectExpectations {
        &self.subject_expectations
    }

    /// Claim the single send this prepared request is good for.
    pub(crate) fn claim_single_send(&self) -> Result<(), EvidenceClientError> {
        claim_single_send(&self.sent)
    }
}

impl std::fmt::Debug for PreparedHolderBoundRequest {
    /// The selector values, the holder keys, and the expected bindings are
    /// withheld. The body's own `Debug` renders none of them either; this
    /// states the same discipline at the level a caller actually logs.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedHolderBoundRequest")
            .field("requirement", &self.body.requirement)
            .field("request_nonce", &self.body.request_nonce)
            .field("response_format", &self.response_format)
            .field(
                "holder_keys",
                &self.body.holder_keys.as_ref().map_or(0, Vec::len),
            )
            .field("subject_expectations", &self.subject_expectations)
            .finish_non_exhaustive()
    }
}

/// The request body both binding modes send, built once so neither can drift
/// from the frozen wire form the other uses.
fn request_body(
    nonce: &RequestNonce,
    requirement: String,
    purpose: String,
    subjects: Vec<SubjectRequest>,
    holder_keys: Vec<HolderPublicKey>,
) -> EvidenceRequestBody {
    let subjects = subjects
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
    // No key set and an empty key set are the same request, and the
    // deployment reads them that way, so only the first shape is sent.
    let holder_keys = Some(holder_keys).filter(|keys| !keys.is_empty());
    EvidenceRequestBody {
        request_nonce: nonce.as_str().to_owned(),
        requirement,
        purpose,
        subjects,
        holder_keys,
    }
}

fn serialize_request(body: &EvidenceRequestBody) -> Result<Vec<u8>, EvidenceClientError> {
    let value = serde_json::to_value(body)
        .map_err(|_| EvidenceClientError::configuration("the request body cannot be serialized"))?;
    canonicalize_json(&value)
        .map_err(|_| EvidenceClientError::configuration("the request body cannot be serialized"))
}

/// The claim is taken before any I/O, and an attempt that fails on the wire
/// still spends it: the deployment may have answered the request even when the
/// relying party never read the answer.
fn claim_single_send(sent: &AtomicBool) -> Result<(), EvidenceClientError> {
    if sent.swap(true, Ordering::SeqCst) {
        return Err(EvidenceClientError::configuration(
            "a prepared request may be sent once; prepare again for a fresh nonce",
        ));
    }
    Ok(())
}

/// The parts of a request specification both binding modes state, borrowed for
/// validation.
///
/// The audience is deliberately outside it. An audience-scoped request must
/// state one and a holder-bound request has none to state, which is the whole
/// reason the two specifications are separate types; folding it in here as an
/// `Option` would reintroduce the state those types exist to rule out.
struct SharedRequestFacts<'a> {
    response_format: EvidenceResponseFormat,
    requirement: &'a str,
    purpose: &'a str,
    evidence_type: &'a str,
    issued_by: &'a str,
    provided_by: &'a str,
    configuration_revision: &'a str,
    subjects: &'a [SubjectRequest],
    holder_keys: &'a [HolderPublicKey],
    expected_outputs: &'a [ExpectedOutputDocument],
    maximum_assertion_lifetime_seconds: u64,
    clock_skew_seconds: u64,
    subject_expectations: &'a SubjectExpectations,
}

impl EvidenceRequestSpec {
    fn shared(&self) -> SharedRequestFacts<'_> {
        SharedRequestFacts {
            response_format: self.response_format,
            requirement: &self.requirement,
            purpose: &self.purpose,
            evidence_type: &self.evidence_type,
            issued_by: &self.issued_by,
            provided_by: &self.provided_by,
            configuration_revision: &self.configuration_revision,
            subjects: &self.subjects,
            holder_keys: &self.holder_keys,
            expected_outputs: &self.expected_outputs,
            maximum_assertion_lifetime_seconds: self.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: self.clock_skew_seconds,
            subject_expectations: &self.subject_expectations,
        }
    }
}

impl HolderBoundRequestSpec {
    fn shared(&self) -> SharedRequestFacts<'_> {
        SharedRequestFacts {
            response_format: self.response_format,
            requirement: &self.requirement,
            purpose: &self.purpose,
            evidence_type: &self.evidence_type,
            issued_by: &self.issued_by,
            provided_by: &self.provided_by,
            configuration_revision: &self.configuration_revision,
            subjects: &self.subjects,
            holder_keys: &self.holder_keys,
            expected_outputs: &self.expected_outputs,
            maximum_assertion_lifetime_seconds: self.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: self.clock_skew_seconds,
            subject_expectations: &self.subject_expectations,
        }
    }
}

/// Refuse a specification the deployment would refuse, or one whose policy
/// could not decide anything.
fn validate(spec: &EvidenceRequestSpec) -> Result<(), EvidenceClientError> {
    // The one expectation this mode states and the holder-bound mode cannot.
    // Presence and length only, for the reason the shared rules give.
    if spec.audience.is_empty() || spec.audience.len() > MAXIMUM_IDENTIFIER_BYTES {
        return Err(EvidenceClientError::configuration(
            "the audience identifier must be present and bounded",
        ));
    }
    validate_shared(&spec.shared())
}

/// Refuse a holder-bound specification the deployment would refuse.
///
/// There is no policy to check for decidability here, because this mode closes
/// none.
fn validate_holder_bound(spec: &HolderBoundRequestSpec) -> Result<(), EvidenceClientError> {
    // A holder-bound requirement derives every subject binding under a
    // presented key, so a request presenting none is one no deployment can
    // answer. Refusing here catches only what nothing could accept, exactly as
    // the shared ceiling does, and it costs the caller nothing: preparation is
    // offline, and the single send is still unspent.
    if spec.holder_keys.is_empty() {
        return Err(EvidenceClientError::configuration(
            "a holder-bound request must present at least one holder public key",
        ));
    }
    // The mode also decides which serializations can carry the answer, and a
    // format outside that set is refused by the deployment as an authorization
    // failure. Refusing it here is the same offline saving: the caller learns
    // what it stated, rather than what it may ask for.
    if !HOLDER_BOUND_RESPONSE_FORMATS.contains(&spec.response_format) {
        return Err(EvidenceClientError::configuration(
            "a holder-bound request must ask for a holder-bound response format",
        ));
    }
    validate_shared(&spec.shared())
}

/// The rules that apply whatever the subject binding is scoped to.
fn validate_shared(spec: &SharedRequestFacts<'_>) -> Result<(), EvidenceClientError> {
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
            spec.requirement,
            "the requirement identifier must be present and bounded",
        ),
        (
            spec.evidence_type,
            "the evidence type identifier must be present and bounded",
        ),
        (
            spec.issued_by,
            "the issuer identifier must be present and bounded",
        ),
        (
            spec.provided_by,
            "the provider identifier must be present and bounded",
        ),
        (
            spec.configuration_revision,
            "the configuration revision identifier must be present and bounded",
        ),
    ] {
        if identifier.is_empty() || identifier.len() > MAXIMUM_IDENTIFIER_BYTES {
            return Err(EvidenceClientError::configuration(reason));
        }
    }
    if !is_purpose(spec.purpose) {
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
    for subject in spec.subjects {
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

    if spec.holder_keys.len() > MAXIMUM_HOLDER_KEYS {
        return Err(EvidenceClientError::configuration(
            "a request may carry at most sixteen holder public keys",
        ));
    }
    // The rule is the portable verifier's own, called rather than restated:
    // a second opinion about which key material is acceptable is exactly the
    // kind of Evidence semantics this crate must not hold. It refuses here
    // only so the caller learns before spending its single send.
    if !spec.holder_keys.iter().all(HolderPublicKey::is_acceptable) {
        return Err(EvidenceClientError::configuration(
            "each holder key must be public EC P-256 material the verifier accepts",
        ));
    }
    // The runtime tells keys apart by RFC 7638 thumbprint, which covers only
    // kty, crv, x, and y, so two keys differing only in kid or alg are the
    // same key to the deployment even though they are distinct structs here.
    // The thumbprint function is the verifier's own, called rather than
    // restated, so the two rules cannot drift.
    let mut thumbprints = BTreeSet::new();
    for key in spec.holder_keys {
        let thumbprint = holder_thumbprint(key).map_err(|_| {
            EvidenceClientError::configuration(
                "each holder key must be public EC P-256 material the verifier accepts",
            )
        })?;
        if !thumbprints.insert(thumbprint) {
            return Err(EvidenceClientError::configuration(
                "each holder key must present a distinct key, by RFC 7638 thumbprint",
            ));
        }
    }
    // A batch is one credential per holder key, so a batch of none is an empty
    // request no deployment can answer. Refusing here catches only what nothing
    // could accept, exactly as the ceiling above does; which requests may carry
    // holder keys at all stays the deployment's decision.
    if spec.response_format == EvidenceResponseFormat::SdJwtVcBatch && spec.holder_keys.is_empty() {
        return Err(EvidenceClientError::configuration(
            "a batch response format requires at least one holder public key",
        ));
    }

    if spec.expected_outputs.is_empty() || spec.expected_outputs.len() > MAXIMUM_EXPECTED_OUTPUTS {
        return Err(EvidenceClientError::configuration(
            "a policy must expect between one and sixteen outputs",
        ));
    }
    let mut concepts = BTreeSet::new();
    let mut handles = BTreeSet::new();
    // Ties the message below to the constant, so the constant cannot drift
    // from the number the message states.
    const _: () = assert!(MAXIMUM_LIST_ITEMS == 64);
    for output in spec.expected_outputs {
        if !is_output_handle(&output.handle)
            || !handles.insert(output.handle.as_str())
            || output.concept.is_empty()
            || output.concept.len() > MAXIMUM_IDENTIFIER_BYTES
            || !concepts.insert(output.concept.as_str())
        {
            return Err(EvidenceClientError::configuration(
                "each expected output must name a bounded concept once",
            ));
        }
        if let ExpectedFormDocument::List(list) = &output.form {
            let minimum_items = list.list.minimum_items;
            let maximum_items = list.list.maximum_items;
            // A specification with a minimum above its maximum can never be
            // satisfied, so accepting it would only defer the failure to the
            // deployment, where the caller cannot diagnose it.
            if !list.list.unique
                || !(1..=MAXIMUM_LIST_ITEMS).contains(&minimum_items)
                || !(1..=MAXIMUM_LIST_ITEMS).contains(&maximum_items)
                || minimum_items > maximum_items
            {
                return Err(EvidenceClientError::configuration(
                    "each list-form output must state a cardinality within 1..=64 items, with the minimum no greater than the maximum",
                ));
            }
        }
    }

    // Ties the message below to the constant, so the constant cannot drift
    // from the number the message states.
    const _: () = assert!(MINIMUM_ASSERTION_LIFETIME_SECONDS == 1);
    const _: () = assert!(MAXIMUM_ASSERTION_LIFETIME_SECONDS == 31_536_000);
    if !(MINIMUM_ASSERTION_LIFETIME_SECONDS..=MAXIMUM_ASSERTION_LIFETIME_SECONDS)
        .contains(&spec.maximum_assertion_lifetime_seconds)
    {
        return Err(EvidenceClientError::configuration(
            "the maximum assertion lifetime must be within 1..=31536000 seconds",
        ));
    }

    const _: () = assert!(MAXIMUM_CLOCK_SKEW_SECONDS == 300);
    if spec.clock_skew_seconds > MAXIMUM_CLOCK_SKEW_SECONDS {
        return Err(EvidenceClientError::configuration(
            "the clock skew must be within 0..=300 seconds",
        ));
    }

    if let SubjectExpectations::Pinned(pinned) = spec.subject_expectations {
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

/// `^[a-z][a-z0-9._-]{0,127}$`
fn is_output_handle(value: &str) -> bool {
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
    use registry_evidence_verifier::verifier::{
        ExpectedFormDocument, ExpectedListDocument, ExpectedListFormDocument,
        ExpectedScalarFormDocument,
    };

    fn expected_output() -> ExpectedOutputDocument {
        ExpectedOutputDocument {
            handle: "status-holds".to_owned(),
            concept: "urn:example:client:concept:status-holds".to_owned(),
            required: true,
            form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
        }
    }

    fn list_expected_output(minimum_items: usize, maximum_items: usize) -> ExpectedOutputDocument {
        ExpectedOutputDocument {
            handle: "list-output".to_owned(),
            concept: "urn:example:client:concept:list-output".to_owned(),
            required: true,
            form: ExpectedFormDocument::List(ExpectedListFormDocument {
                list: ExpectedListDocument {
                    items:
                        registry_evidence_verifier::verifier::ExpectedListItemFormDocument::String,
                    minimum_items,
                    maximum_items,
                    unique: true,
                },
            }),
        }
    }

    fn spec() -> EvidenceRequestSpec {
        EvidenceRequestSpec {
            response_format: EvidenceResponseFormat::SignedJws,
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
            holder_keys: Vec::new(),
            expected_outputs: vec![expected_output()],
            maximum_assertion_lifetime_seconds: 300,
            clock_skew_seconds: 60,
            subject_expectations: SubjectExpectations::AcceptFirstUse,
        }
    }

    /// A real point on P-256, so the verifier's acceptance rule admits it.
    /// Sixteen distinct real points are listed, one for every position up to
    /// the holder key ceiling, because a test that wants that many keys wants
    /// them genuinely distinct by coordinate, not merely under distinct `kid`
    /// values.
    fn holder_key(index: usize) -> HolderPublicKey {
        let (x, y) = [
            (
                "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            ),
            (
                "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
                "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
            ),
            (
                "n3_Yes5MjqlxuTx-yYJ8BsBmpDzqRB66Ixu1lE7k5JM",
                "w76HqEWwlYMl1DnNp-hqViCI7PwdjO5jxlRwHCPEtwE",
            ),
            (
                "faOMDnMgcQokki2BO06-LgkBU_4G1Gnt7tS7Y7eujFM",
                "KBZcokD-2DQ2pEbR33UwDwEyW6Rf_ZVmU2faZxiof3o",
            ),
            (
                "5fIy6bNYSfu68U4Y2Hp7JjWnk0BLwrXucGUyrlFCj8Y",
                "35IdEV5jMeGwBt7_99hjwXpaT_BHUaZIvki_xNay4sg",
            ),
            (
                "ZaYnt2GL6NlylnH2xYBGzQB1BYrS5lvTcztyIYpmo5s",
                "qrRst3n2kZ1EHT8EmV3wVIFQxxJjt5GBpVXsVBYD_TU",
            ),
            (
                "ctrDhQwO16bzK19RBI6i-X13Q_9po8H3xY5wwHJX2uU",
                "LXEvoTX689TGU1D2oRw_ncWPD2trkxhV-f38B_mhGNk",
            ),
            (
                "HcRmRb5scPLUBbIMp34l4wlT8MjxV0d6U1uqu2S_B4s",
                "yDSKYA-9bFX4ScN-pYsrcbGYwAgq2HSqhuemKPGWALU",
            ),
            (
                "3-pq6l86SMBtCJ97YvB-qSJ4hgdX9VNOho_gKCdxFSI",
                "fvo4jt9PYvOyyYvLXVtNl-Stmgd69JZ3qhAfYK2EOKk",
            ),
            (
                "4W1T-pztHXrsfjUYsS3S8QhUudffFke2xr8Lq5yDoWA",
                "Gs0pjlLWVpgIIQpQ3X6A0duOry32x7YaJ_W7XUn9dwo",
            ),
            (
                "BKWbnbrISjEA9xLp_5JhiP_JtwnG4siWFI7tb5vk8X0",
                "lbMD8eMEeovBheYcaOQmaf8jp6kDAEJBtx2ZfIOi5XU",
            ),
            (
                "Nk5nWFTqy0BaI0p4XwA3L6lJXceTclJktxSakh9_Zfg",
                "3B23XCnyRTUnUkLQ9KslMCshFxdcRnDOj-tMsMvXoo0",
            ),
            (
                "FtLKOsRAC7ZRL4mYZukcXKujZX9kK7vaTkuJFbsM2Xg",
                "_6-H2VFs9FZW9p8Q0ohmNfIVUKJZosxo_9rUYoEnQ1E",
            ),
            (
                "q2olombbAFCOBPo-P4UFkQ3phHc-TDJuEo0OVz-sOUk",
                "4H1qpy54MmIERtlBfNFkX3dHRGjCX_4B9OOoRLRznkU",
            ),
            (
                "gxPvjLdEuMOIkN-YlphQ3J4XzIkrI7FwPp65qllBqfE",
                "D9kz6uWM4suBJeuYFpLl5LCYalWRzjMnFqOQuhb8ips",
            ),
            (
                "yzQUNRa-CAgUzArNijK8m21GdtyUjAnEqUujwXGEXic",
                "8h84GxfXQDMBS9G72Ium96zcE6vfKrvo4AumLOsNx_o",
            ),
        ][index % MAXIMUM_HOLDER_KEYS];
        HolderPublicKey {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: x.to_owned(),
            y: y.to_owned(),
            alg: Some("ES256".to_owned()),
            kid: Some(format!("holder-key-{index}")),
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
        let body: serde_json::Value =
            serde_json::from_slice(&prepared.request_json().expect("the request serializes"))
                .expect("the request parses");
        assert_eq!(body["requestNonce"], prepared.request_nonce());

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
                    "handle": "status-holds",
                    "concept": "urn:example:client:concept:status-holds",
                    "required": true,
                    "form": "boolean",
                }],
                "revokedKeyIds": [],
                "maximumAssertionLifetimeSeconds": 300,
                "clockSkewSeconds": 60,
            })
        );
    }

    /// Array position is the whole contract for holder keys: the answer carries
    /// one credential per key in this order, so the order the caller stated has
    /// to be the order that reaches the wire, unchanged and unsorted.
    #[test]
    fn holder_keys_reach_the_wire_in_the_order_the_caller_stated() {
        let mut spec = spec();
        spec.holder_keys = vec![holder_key(1), holder_key(0)];
        let prepared = PreparedEvidenceRequest::new(spec).expect("the specification is accepted");

        let body: serde_json::Value =
            serde_json::from_slice(&prepared.request_json().expect("the request serializes"))
                .expect("the request parses");
        assert_eq!(
            body["holderKeys"],
            serde_json::json!([
                serde_json::to_value(holder_key(1)).expect("the key serializes"),
                serde_json::to_value(holder_key(0)).expect("the key serializes"),
            ])
        );
    }

    /// A caller that never heard of holder keys sends the request it always
    /// sent.
    #[test]
    fn a_request_presenting_no_holder_key_carries_no_holder_key_member() {
        let prepared = PreparedEvidenceRequest::new(spec()).expect("the specification is accepted");
        let body = String::from_utf8(prepared.request_json().expect("the body serializes"))
            .expect("the request is UTF-8 JSON");
        assert!(!body.contains("holderKeys"), "{body}");
    }

    /// The keys are request material, not policy material. Nothing about them
    /// belongs in a document that judges the answer, and putting them there
    /// would be this crate inventing a verification rule.
    #[test]
    fn holder_keys_never_reach_the_verification_policy() {
        let mut spec = spec();
        spec.holder_keys = vec![holder_key(0)];
        let prepared = PreparedEvidenceRequest::new(spec).expect("the specification is accepted");
        let policy = serde_json::to_string(prepared.policy_document())
            .expect("the policy document serializes");
        assert!(!policy.contains("holder"), "{policy}");
        assert!(
            !policy.contains("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"),
            "{policy}"
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
                "an invalid expected output handle",
                Box::new(|spec| spec.expected_outputs[0].handle = "Uppercase".to_owned()),
            ),
            (
                "a repeated expected output handle",
                Box::new(|spec| {
                    let mut other = expected_output();
                    other.concept = "urn:example:client:concept:other".to_owned();
                    spec.expected_outputs.push(other);
                }),
            ),
            (
                "a lifetime of zero",
                Box::new(|spec| spec.maximum_assertion_lifetime_seconds = 0),
            ),
            (
                "a lifetime above the contract's ceiling",
                Box::new(|spec| {
                    spec.maximum_assertion_lifetime_seconds =
                        MAXIMUM_ASSERTION_LIFETIME_SECONDS + 1;
                }),
            ),
            (
                "a clock skew above the contract's ceiling",
                Box::new(|spec| {
                    spec.clock_skew_seconds = MAXIMUM_CLOCK_SKEW_SECONDS + 1;
                }),
            ),
            (
                "a list cardinality of zero",
                Box::new(|spec| spec.expected_outputs.push(list_expected_output(0, 1))),
            ),
            (
                "a list cardinality above the contract's ceiling",
                Box::new(|spec| {
                    spec.expected_outputs
                        .push(list_expected_output(1, MAXIMUM_LIST_ITEMS + 1));
                }),
            ),
            (
                "a list minimum above its maximum",
                Box::new(|spec| spec.expected_outputs.push(list_expected_output(2, 1))),
            ),
            (
                "a list that does not require uniqueness",
                Box::new(|spec| {
                    let mut output = list_expected_output(1, 2);
                    let ExpectedFormDocument::List(form) = &mut output.form else {
                        unreachable!("the helper constructs a list")
                    };
                    form.list.unique = false;
                    spec.expected_outputs.push(output);
                }),
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
            (
                "more holder keys than the contract allows",
                Box::new(|spec| {
                    spec.holder_keys = (0..MAXIMUM_HOLDER_KEYS + 1).map(holder_key).collect();
                }),
            ),
            (
                "a holder key whose coordinates are not a point on the curve",
                Box::new(|spec| {
                    let mut key = holder_key(0);
                    key.x = "A".repeat(43);
                    spec.holder_keys = vec![key];
                }),
            ),
            (
                "a holder key on another curve",
                Box::new(|spec| {
                    let mut key = holder_key(0);
                    key.crv = "P-384".to_owned();
                    spec.holder_keys = vec![key];
                }),
            ),
            (
                "a holder key naming a signature algorithm the profile does not use",
                Box::new(|spec| {
                    let mut key = holder_key(0);
                    key.alg = Some("ES384".to_owned());
                    spec.holder_keys = vec![key];
                }),
            ),
            (
                "a batch response format with no holder key to issue against",
                Box::new(|spec| {
                    spec.response_format = EvidenceResponseFormat::SdJwtVcBatch;
                    spec.holder_keys = Vec::new();
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

    /// A batch is one credential per holder key, so a batch of no keys is a
    /// request for nothing. The refusal names the format's own requirement,
    /// says nothing about why a deployment might want a key, and applies to no
    /// other format: a singular request carrying no holder key is ordinary.
    #[test]
    fn a_batch_of_no_holder_keys_is_refused_and_one_key_is_enough() {
        let mut empty_batch = spec();
        empty_batch.response_format = EvidenceResponseFormat::SdJwtVcBatch;
        let failure = PreparedEvidenceRequest::new(empty_batch)
            .map(|_| ())
            .expect_err("a batch of no holder keys is not a request");
        let EvidenceClientError::Configuration { reason } = &failure else {
            panic!("{failure:?}");
        };
        assert_eq!(
            *reason,
            "a batch response format requires at least one holder public key"
        );

        let mut one_key = spec();
        one_key.response_format = EvidenceResponseFormat::SdJwtVcBatch;
        one_key.holder_keys = vec![holder_key(0)];
        PreparedEvidenceRequest::new(one_key).expect("one holder key is a batch of one");

        for format in [
            EvidenceResponseFormat::SignedJws,
            EvidenceResponseFormat::SdJwtVc,
        ] {
            let mut singular = spec();
            singular.response_format = format;
            PreparedEvidenceRequest::new(singular)
                .unwrap_or_else(|error| panic!("{format:?} without a holder key: {error}"));
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
        assert_eq!(
            MAXIMUM_ASSERTION_LIFETIME_SECONDS, 31_536_000,
            "a refusal says \"1..=31536000 seconds\""
        );
        assert_eq!(
            MAXIMUM_CLOCK_SKEW_SECONDS, 300,
            "a refusal says \"0..=300 seconds\""
        );
        assert_eq!(MAXIMUM_LIST_ITEMS, 64, "a refusal says \"1..=64 items\"");
        assert_eq!(
            MAXIMUM_HOLDER_KEYS, 16,
            "a refusal says \"at most sixteen holder public keys\""
        );

        let mut at_the_holder_key_ceiling = spec();
        at_the_holder_key_ceiling.holder_keys = (0..MAXIMUM_HOLDER_KEYS).map(holder_key).collect();
        PreparedEvidenceRequest::new(at_the_holder_key_ceiling)
            .expect("the holder key ceiling itself is accepted");

        // The ceiling itself, and the floor itself, are still legal: a refusal
        // one step past an edge does not mean the edge itself is refused.
        let mut at_the_lifetime_ceiling = spec();
        at_the_lifetime_ceiling.maximum_assertion_lifetime_seconds =
            MAXIMUM_ASSERTION_LIFETIME_SECONDS;
        PreparedEvidenceRequest::new(at_the_lifetime_ceiling)
            .expect("the lifetime ceiling itself is accepted");

        let mut at_the_skew_ceiling = spec();
        at_the_skew_ceiling.clock_skew_seconds = MAXIMUM_CLOCK_SKEW_SECONDS;
        PreparedEvidenceRequest::new(at_the_skew_ceiling)
            .expect("the clock skew ceiling itself is accepted");

        let mut at_the_list_floor_and_ceiling = spec();
        at_the_list_floor_and_ceiling
            .expected_outputs
            .push(list_expected_output(1, MAXIMUM_LIST_ITEMS));
        PreparedEvidenceRequest::new(at_the_list_floor_and_ceiling)
            .expect("a list cardinality spanning the floor to the ceiling is accepted");

        let mut equal_at_the_list_ceiling = spec();
        equal_at_the_list_ceiling
            .expected_outputs
            .push(list_expected_output(MAXIMUM_LIST_ITEMS, MAXIMUM_LIST_ITEMS));
        PreparedEvidenceRequest::new(equal_at_the_list_ceiling)
            .expect("a minimum equal to the maximum is accepted, even at the ceiling");
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
    fn selector_strings_enforce_the_contract_wide_envelope() {
        let mut at_the_ceiling = spec();
        at_the_ceiling.subjects[0].selector_values = Some(vec![(
            "record_reference".to_owned(),
            SelectorValue::from("x".repeat(MAXIMUM_SELECTOR_STRING_BYTES)),
        )]);
        PreparedEvidenceRequest::new(at_the_ceiling)
            .expect("the contract-wide selector string ceiling is accepted");

        let mut above_the_ceiling = spec();
        above_the_ceiling.subjects[0].selector_values = Some(vec![(
            "record_reference".to_owned(),
            SelectorValue::from("x".repeat(MAXIMUM_SELECTOR_STRING_BYTES + 1)),
        )]);
        assert_eq!(
            PreparedEvidenceRequest::new(above_the_ceiling)
                .expect_err("a selector string above the contract-wide ceiling is refused"),
            EvidenceClientError::configuration(
                "each selector string value must be present and bounded"
            )
        );
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
        let body = String::from_utf8(prepared.request_json().expect("the body serializes"))
            .expect("the request is UTF-8 JSON");
        assert!(!body.contains("values"), "{body}");
    }

    #[test]
    fn debug_output_withholds_selector_values_and_bindings() {
        let mut spec = spec();
        spec.subject_expectations = pinned();
        spec.holder_keys = vec![holder_key(0)];
        let prepared = PreparedEvidenceRequest::new(spec).expect("the specification is accepted");
        let rendered = format!("{prepared:?}");
        assert!(!rendered.contains("synthetic-record-001"), "{rendered}");
        assert!(!rendered.contains("y0KMdWluZGluZw"), "{rendered}");
        assert!(!rendered.contains("holder-key-0"), "{rendered}");
        assert!(rendered.contains("Pinned"), "{rendered}");
    }

    /// The specification is a caller-facing struct with a derived `Debug`, and
    /// a holder key is caller input, so the key's own redaction is what keeps
    /// it out of a log line.
    #[test]
    fn a_specification_never_renders_its_holder_keys() {
        let mut spec = spec();
        spec.holder_keys = vec![holder_key(0)];
        let rendered = format!("{spec:?}");
        assert!(!rendered.contains("holder-key-0"), "{rendered}");
        assert!(
            !rendered.contains("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"),
            "{rendered}"
        );
    }

    /// The audience-scoped specification with the audience gone and one holder
    /// key present, so a difference a test observes is the difference the two
    /// types exist for.
    fn holder_bound_spec() -> HolderBoundRequestSpec {
        let spec = spec();
        HolderBoundRequestSpec {
            response_format: EvidenceResponseFormat::SdJwtVc,
            requirement: spec.requirement,
            purpose: spec.purpose,
            evidence_type: spec.evidence_type,
            issued_by: spec.issued_by,
            provided_by: spec.provided_by,
            configuration_revision: spec.configuration_revision,
            expected_assurance_profile: spec.expected_assurance_profile,
            subjects: spec.subjects,
            holder_keys: vec![holder_key(0)],
            expected_outputs: spec.expected_outputs,
            maximum_assertion_lifetime_seconds: spec.maximum_assertion_lifetime_seconds,
            clock_skew_seconds: spec.clock_skew_seconds,
            subject_expectations: spec.subject_expectations,
        }
    }

    /// The deployment refuses a holder-bound request presenting no key, so this
    /// crate refuses it first: the caller learns before it spends a source
    /// access and an audit entry on an answer that cannot exist.
    #[test]
    fn a_holder_bound_request_presenting_no_holder_key_is_refused_before_any_exchange() {
        let mut spec = holder_bound_spec();
        spec.holder_keys = Vec::new();
        let failure =
            PreparedHolderBoundRequest::new(spec).expect_err("a request with no key is refused");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "a holder-bound request must present at least one holder public key"
                }
            ),
            "{failure:?}"
        );
    }

    /// The specification has no audience member, so the only way an audience
    /// could reach the deployment is a field this crate invented. The body is
    /// checked against the whole audience-scoped vocabulary rather than one
    /// spelling of it.
    #[test]
    fn a_holder_bound_request_body_carries_the_holder_keys_and_no_audience() {
        let prepared = PreparedHolderBoundRequest::new(holder_bound_spec())
            .expect("the specification is accepted");
        let serialized = prepared.request_json().expect("the request serializes");
        let body: serde_json::Value =
            serde_json::from_slice(&serialized).expect("the request parses");

        assert_eq!(body["requestNonce"], prepared.request_nonce());
        assert_eq!(
            body["holderKeys"],
            serde_json::to_value([holder_key(0)]).expect("the key serializes")
        );
        let object = body.as_object().expect("the body is an object");
        for absent in ["audience", "aud", "audienceIdentifier"] {
            assert!(!object.contains_key(absent), "{body}");
        }
        let text = String::from_utf8(serialized).expect("the request is UTF-8");
        assert!(
            !text.contains("urn:example:client:audience:relying-party"),
            "{text}"
        );
    }

    /// The single-send rule is the audience-scoped rule, and it is stated once
    /// rather than reimplemented, so this proves the shared claim reaches the
    /// holder-bound type.
    #[test]
    fn a_holder_bound_request_is_good_for_exactly_one_send() {
        let prepared = PreparedHolderBoundRequest::new(holder_bound_spec())
            .expect("the specification is accepted");
        prepared
            .claim_single_send()
            .expect("the first send is allowed");
        let failure = prepared
            .claim_single_send()
            .expect_err("the second send is refused");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "a prepared request may be sent once; prepare again for a fresh nonce"
                }
            ),
            "{failure:?}"
        );
    }

    /// The bounds both modes share are applied to a holder-bound request too,
    /// rather than only to the path they were written on.
    #[test]
    fn the_shared_bounds_apply_to_a_holder_bound_request() {
        let mut spec = holder_bound_spec();
        spec.holder_keys = (0..=MAXIMUM_HOLDER_KEYS).map(holder_key).collect();
        assert!(
            PreparedHolderBoundRequest::new(spec).is_err(),
            "the holder key ceiling applies"
        );

        let mut spec = holder_bound_spec();
        spec.requirement = String::new();
        assert!(
            PreparedHolderBoundRequest::new(spec).is_err(),
            "the requirement must be present"
        );

        let mut spec = holder_bound_spec();
        spec.expected_outputs = Vec::new();
        assert!(
            PreparedHolderBoundRequest::new(spec).is_err(),
            "a request that expects nothing decides nothing"
        );
    }

    /// A holder-bound assertion names no relying party, so it can only travel
    /// in a serialization carrying the holder key confirmation its verifier
    /// checks possession against, and a deployment refuses the flattened JWS
    /// form for one. Refusing at preparation costs the caller nothing: the
    /// single send is still unspent.
    #[test]
    fn a_holder_bound_request_asking_for_a_format_no_deployment_serves_is_refused() {
        let mut spec = holder_bound_spec();
        spec.response_format = EvidenceResponseFormat::SignedJws;
        let failure = PreparedHolderBoundRequest::new(spec)
            .expect_err("the flattened JWS form carries no holder key confirmation");
        assert!(
            matches!(
                failure,
                EvidenceClientError::Configuration {
                    reason: "a holder-bound request must ask for a holder-bound response format"
                }
            ),
            "{failure:?}"
        );
    }

    /// The refusal above names the one form a holder-bound assertion cannot
    /// travel in, not a set narrower than the contract's. Both formats that
    /// carry the confirmation stay available, the batch among them.
    #[test]
    fn both_holder_bound_response_formats_are_accepted() {
        for format in [
            EvidenceResponseFormat::SdJwtVc,
            EvidenceResponseFormat::SdJwtVcBatch,
        ] {
            let mut spec = holder_bound_spec();
            spec.response_format = format;
            PreparedHolderBoundRequest::new(spec)
                .unwrap_or_else(|error| panic!("{format:?} is a holder-bound format: {error}"));
        }
    }

    /// The runtime tells two keys apart by RFC 7638 thumbprint, which covers
    /// only `kty`, `crv`, `x`, and `y`, so a second `kid` on the same point is
    /// the same key wearing two names to the deployment, even though the two
    /// structs differ here. Admitting it would let a batch request silently
    /// collapse to fewer holders than the caller asked for, and the caller
    /// would only learn that from a 400 after spending its single send.
    #[test]
    fn a_repeated_point_under_a_different_key_id_is_refused() {
        let mut spec = holder_bound_spec();
        let mut second = holder_key(0);
        second.kid = Some("a-different-key-id".to_owned());
        spec.holder_keys = vec![holder_key(0), second];
        assert!(
            PreparedHolderBoundRequest::new(spec).is_err(),
            "the same point under a second key id was accepted"
        );
    }

    /// The thumbprint also ignores `alg`, so a copy of the same point with the
    /// declared algorithm stripped is still the same key to the runtime.
    #[test]
    fn a_repeated_point_with_alg_present_on_only_one_copy_is_refused() {
        let mut spec = holder_bound_spec();
        let mut without_alg = holder_key(0);
        without_alg.alg = None;
        spec.holder_keys = vec![holder_key(0), without_alg];
        assert!(
            PreparedHolderBoundRequest::new(spec).is_err(),
            "the same point with alg dropped on one copy was accepted"
        );
    }

    /// Guards against an over-broad rejection: two keys on genuinely different
    /// points are still accepted.
    #[test]
    fn genuinely_distinct_holder_keys_are_accepted() {
        let mut spec = holder_bound_spec();
        spec.response_format = EvidenceResponseFormat::SdJwtVcBatch;
        spec.holder_keys = vec![holder_key(0), holder_key(1)];
        PreparedHolderBoundRequest::new(spec).expect("two distinct points are accepted");
    }

    #[test]
    fn a_holder_bound_debug_withholds_selector_values_keys_and_bindings() {
        let mut spec = holder_bound_spec();
        spec.subject_expectations = pinned();
        let prepared =
            PreparedHolderBoundRequest::new(spec).expect("the specification is accepted");
        let rendered = format!("{prepared:?}");
        assert!(!rendered.contains("synthetic-record-001"), "{rendered}");
        assert!(!rendered.contains("y0KMdWluZGluZw"), "{rendered}");
        assert!(!rendered.contains("holder-key-0"), "{rendered}");
        assert!(
            !rendered.contains("axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"),
            "{rendered}"
        );
        assert!(rendered.contains("Pinned"), "{rendered}");
    }
}
