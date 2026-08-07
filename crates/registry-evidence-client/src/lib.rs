//! Relying-party client for signed Evidence responses.
//!
//! This crate asks an Evidence deployment for an assertion over HTTP and then
//! verifies the answer offline with [`registry_evidence_verifier`]. It
//! re-implements no part of evaluation, signing, or verification: every
//! judgement about a response is the portable verifier's, applied to a policy
//! the caller closed before the request was sent.
//!
//! # The shape of one exchange
//!
//! ```text
//! prepare(spec) -> nonce + closed policy   (no I/O)
//! send(prepared) -> signed response bytes  (exactly one request)
//! verify(prepared, response) -> Evidence   (offline, pinned keys)
//! ```
//!
//! [`EvidenceClient::request_and_verify`] performs the last two steps together.
//! The split exists so a relying party can retain the exact bytes it verified.
//!
//! # The published key set is discovery, not a trust anchor
//!
//! The trusted key set is the one an integrator pins in
//! [`EvidenceClientConfig::new`], out of band, and it is the only key set
//! verification ever consults. [`EvidenceClient::fetch_jwks`] exists to support
//! that out-of-band workflow: fetch the deployment's published keys once, review
//! them against what the operator published elsewhere, and configure the
//! reviewed set. Nothing in this crate fetches keys at verification time. A key
//! set retrieved from the same origin as the response it would verify
//! establishes nothing about that response.
//!
//! # Subject bindings, and what a verified response proves
//!
//! An Evidence payload names each subject by a role-bound opaque binding. The
//! deployment computes it with a secret only it holds, so a relying party cannot
//! derive the binding for a subject it has never seen, and the verifier requires
//! the subject set to match the policy exactly. That leaves two honest options,
//! both in [`SubjectExpectations`]:
//!
//! - [`SubjectExpectations::Pinned`]: the relying party already holds the
//!   bindings for these roles. Only here does a verified response prove that the
//!   assertion is about the subject the relying party meant.
//! - [`SubjectExpectations::AcceptFirstUse`]: adopt the bindings this response
//!   carries, verify everything else against the closed policy, then persist
//!   [`VerifiedEvidence::pinned_subject_expectations`] and pin them from then
//!   on. First use does not prove subject identity. It accepts the deployment's
//!   own answer to the identity question once, and turns every later answer
//!   about a different subject into a verification failure. It adopts bindings
//!   only for exactly the roles the request asked about, once each; a response
//!   that renames, adds, or drops a role is refused rather than adopted.
//!
//! There is no third option, and this crate does not offer a way around the
//! verifier's subject comparison.
//!
//! # One request, no retries
//!
//! A nonce identifies exactly one request and a policy accepts exactly the
//! answer to that request. Neither this crate nor its HTTP client retries
//! anything: a second attempt is a second [`EvidenceClient::prepare`] with a
//! fresh nonce.
//!
//! The rule is enforced rather than advised. A prepared request allows one send,
//! and a second [`EvidenceClient::send`] or
//! [`EvidenceClient::request_and_verify`] with it fails locally, before any I/O.
//! A deployment never uniqueness-checks a nonce, so a resend would earn a second
//! source access and a second audit entry there for one relying-party decision.
//! Verification is exempt: it is offline and idempotent, so a retained response
//! may be re-verified as often as the relying party likes.
//!
//! # What the async surface requires
//!
//! Preparing and verifying are synchronous. The HTTP methods, however, are
//! `reqwest` calls, and `reqwest` needs a tokio-compatible reactor to drive them,
//! so an application that awaits [`EvidenceClient::send`],
//! [`EvidenceClient::request_and_verify`], [`EvidenceClient::discover`], or
//! [`EvidenceClient::fetch_jwks`] has to do so on one. [`PrivateKeyJwt`] runs
//! there too: it awaits a token endpoint, and it guards its cached credential
//! with tokio's asynchronous lock so a caller waiting for a token in flight does
//! not block the reactor thread.

pub mod client;
pub mod config;
pub mod definitions;
pub mod error;
pub mod nonce;
pub mod prepare;
pub mod private_key_jwt;
pub mod request;
pub mod response_format;
pub mod retained;
pub mod token;

/// One rule set for every outbound exchange. Which rules apply to a credential
/// leaving the process is not a caller's choice, so the options and the client
/// construction stay internal.
mod outbound;

/// The closed problem contract is an internal parsing detail. What a caller acts
/// on is the mapped failure in [`error`], never a problem body.
mod problem;

#[cfg(test)]
mod fixtures;

pub use client::{EvidenceClient, RawEvidenceResponse, VerifiedEvidence};
pub use config::{
    EvidenceClientConfig, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_REQUEST_TIMEOUT,
};
pub use definitions::{
    ConceptForm, DefinitionCardinality, DefinitionConcept, DefinitionKind, DefinitionSelector,
    DefinitionSubject, EvidenceDefinition, EvidenceDefinitionsDocument, SelectorField,
    SelectorValueOrigin, EVIDENCE_DEFINITIONS_SCHEMA_V1,
};
pub use error::{EvidenceClientError, TransportKind};
pub use nonce::{NonceError, RequestNonce};
pub use prepare::{
    EvidenceRequestSpec, PreparedEvidenceRequest, SubjectExpectations, SubjectRequest,
    MAXIMUM_EXPECTED_OUTPUTS, MAXIMUM_IDENTIFIER_BYTES, MAXIMUM_SELECTOR_INTEGER,
    MAXIMUM_SELECTOR_STRING_BYTES, MAXIMUM_SELECTOR_VALUES, MAXIMUM_SUBJECTS,
    MINIMUM_SELECTOR_INTEGER,
};
pub use private_key_jwt::{
    PrivateKeyJwt, PrivateKeyJwtConfig, DEFAULT_ASSERTION_LIFETIME_SECONDS,
    DEFAULT_REFRESH_MARGIN_SECONDS, MAXIMUM_ASSERTION_LIFETIME_SECONDS,
    MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS,
};
pub use request::SelectorValue;
pub use response_format::EvidenceResponseFormat;
pub use retained::{RetainedEvidenceVerification, RETAINED_EVIDENCE_VERIFICATION_SCHEMA_V1};
pub use token::{BearerToken, OAuthErrorCode, StaticToken, TokenError, TokenProvider};

// The verification seam, re-exported so a relying party does not have to depend
// on the verifier crate directly to name the types this API returns and accepts.
pub use registry_evidence_verifier::{
    model::{
        BucketForm, BucketValue, EntityReferenceForm, EntityReferenceValue, Evidence,
        EvidenceObjectType, JwksDocument, PublicValue, ScalarOrEntityReference, StructuredValue,
        StructuredValueForm, SubjectBinding, SupportedValue,
    },
    verifier::{
        EvidenceVerificationPolicyDocument, ExpectedFormDocument, ExpectedListDocument,
        ExpectedListFormDocument, ExpectedOutputDocument, ExpectedScalarFormDocument,
        ExpectedSubjectDocument, VerificationError,
    },
    AssuranceProfile,
};
