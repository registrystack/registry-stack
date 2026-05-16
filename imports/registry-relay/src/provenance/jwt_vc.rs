// SPDX-License-Identifier: Apache-2.0
//! VC-JWT envelope for Verifiable Credentials Data Model 2.0.
//!
//! Implements the W3C "Securing Verifiable Credentials using JOSE and
//! COSE" Recommendation: the VCDM 2.0 credential is the JWT payload
//! directly. There is NO legacy nested `vc` claim (`decisions/
//! wave-3-data-provenance.md` Section 9).
//!
//! Compact wire format:
//! `base64url(header).base64url(payload).base64url(signature)`.
//!
//! The encoder is signer-agnostic: it constructs the canonical header
//! and payload as `serde_json::Value`, hands both to the [`Signer`]
//! trait (whose impls own base64url encoding + cryptographic signing),
//! and returns the compact JWS string.

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use super::signer::{Signer, SignerError};

/// VCDM 2.0 base context. Pinned by the W3C Recommendation; never
/// changes for a given VCDM version.
pub const VCDM_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// Claim-type slug + the URI fragment for its in-tree JSON Schema.
///
/// The variant string equals the `type[1]` array entry. The
/// `schema_path` is appended to `<schema_base_url>/` to yield the
/// `credentialSchema.id`. The `audit_label` is the literal value
/// recorded in audit log `claim_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimType {
    VerifyResult,
    AggregateResult,
    EntityRecord,
}

impl ClaimType {
    /// Type tag emitted as `type[1]` in the VC.
    pub fn type_tag(self) -> &'static str {
        match self {
            ClaimType::VerifyResult => "VerifyResult",
            ClaimType::AggregateResult => "AggregateResult",
            ClaimType::EntityRecord => "EntityRecord",
        }
    }

    /// Schema URL path appended to the configured `schema_base_url`.
    pub fn schema_path(self) -> &'static str {
        match self {
            ClaimType::VerifyResult => "verify-result/v1.json",
            ClaimType::AggregateResult => "aggregate-result/v1.json",
            ClaimType::EntityRecord => "entity-record/v1.json",
        }
    }
}

/// Inputs the orchestrator gathers per request. Owned values keep the
/// encoder free of lifetime annotations; the encoder is called at most
/// once per response so the clone cost is negligible.
#[derive(Debug, Clone)]
pub struct VcEnvelopeInputs {
    pub claim_type: ClaimType,
    pub issuer_did: String,
    pub verification_method_id: String,
    pub subject_uri: String,
    pub credential_subject: Value,
    pub provenance_context_url: String,
    pub credential_schema_url: String,
    pub issued_at: OffsetDateTime,
    pub valid_until: OffsetDateTime,
}

/// Output of the encoder, returned to the orchestrator and forwarded to
/// the audit event builder. The compact JWS is the only artefact that
/// reaches the wire; the rest is metadata the audit layer records.
#[derive(Debug, Clone)]
pub struct SignedEnvelope {
    pub compact_jws: String,
    pub jti: String,
    pub claim_type: ClaimType,
    pub subject_uri: String,
    pub issuer_did: String,
    pub verification_method_id: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

/// VC-JWT encoding error. The variants do not leak payload bytes; the
/// orchestrator maps them to [`crate::error::ProvenanceError`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// Building the RFC 3339 timestamp for `validFrom` / `validUntil`
    /// failed. The `time` crate's `Rfc3339` formatter only errors on
    /// out-of-range years, which the orchestrator's clamp prevents in
    /// practice; we still propagate rather than panic.
    #[error("timestamp formatting failed")]
    TimestampFormat,
    /// The signer rejected the header / payload pair. Carries the
    /// underlying [`SignerError`] for the orchestrator to map to a
    /// taxonomy code.
    #[error("signer rejected envelope: {0}")]
    Signer(#[from] SignerError),
}

/// Build the canonical VCDM 2.0 + JWT-claim payload, then ask the
/// signer for the compact JWS. The encoder owns the `@context` /
/// `type` / `validFrom` / `validUntil` invariants; the caller owns the
/// `credentialSubject` shape per claim type.
///
/// Conformance: see `decisions/wave-3-data-provenance.md` Section 9.
pub fn encode(
    signer: &dyn Signer,
    inputs: VcEnvelopeInputs,
) -> Result<SignedEnvelope, EncodeError> {
    let jti = format!("urn:uuid:{}", Uuid::new_v4());
    let iat = inputs.issued_at.unix_timestamp();
    let nbf = iat;
    let exp = inputs.valid_until.unix_timestamp();
    let valid_from_str = inputs
        .issued_at
        .format(&Rfc3339)
        .map_err(|_| EncodeError::TimestampFormat)?;
    let valid_until_str = inputs
        .valid_until
        .format(&Rfc3339)
        .map_err(|_| EncodeError::TimestampFormat)?;

    let header = json!({
        "alg": signer.algorithm().jws_alg(),
        "typ": "vc+jwt",
        "cty": "vc",
        "kid": &inputs.verification_method_id,
    });

    let payload = json!({
        "@context": [VCDM_V2_CONTEXT, &inputs.provenance_context_url],
        "type": ["VerifiableCredential", inputs.claim_type.type_tag()],
        "id": &jti,
        "issuer": &inputs.issuer_did,
        "validFrom": &valid_from_str,
        "validUntil": &valid_until_str,
        "credentialSubject": &inputs.credential_subject,
        "credentialSchema": {
            "id": &inputs.credential_schema_url,
            "type": "JsonSchema",
        },
        "iss": &inputs.issuer_did,
        "sub": &inputs.subject_uri,
        "jti": &jti,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
    });

    let compact_jws = signer.sign(header, payload)?;
    Ok(SignedEnvelope {
        compact_jws,
        jti,
        claim_type: inputs.claim_type,
        subject_uri: inputs.subject_uri,
        issuer_did: inputs.issuer_did,
        verification_method_id: inputs.verification_method_id,
        iat,
        nbf,
        exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_type_tags_match_spec() {
        assert_eq!(ClaimType::VerifyResult.type_tag(), "VerifyResult");
        assert_eq!(ClaimType::AggregateResult.type_tag(), "AggregateResult");
        assert_eq!(ClaimType::EntityRecord.type_tag(), "EntityRecord");
    }

    #[test]
    fn claim_type_schema_paths_match_spec() {
        assert_eq!(
            ClaimType::VerifyResult.schema_path(),
            "verify-result/v1.json"
        );
        assert_eq!(
            ClaimType::AggregateResult.schema_path(),
            "aggregate-result/v1.json"
        );
        assert_eq!(
            ClaimType::EntityRecord.schema_path(),
            "entity-record/v1.json"
        );
    }
}
