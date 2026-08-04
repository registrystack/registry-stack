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

pub mod client;
pub mod config;
pub mod definitions;
pub mod error;
pub mod nonce;
pub mod prepare;
pub mod problem;
pub mod request;
pub mod token;

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
};
pub use request::SelectorValue;
pub use token::{BearerToken, StaticToken, TokenError, TokenProvider};

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
