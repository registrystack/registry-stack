// SPDX-License-Identifier: Apache-2.0
//! Compact signed JWT receipts for evidence verification.
//!
//! These receipts are intentionally not VC-JWTs. They are server-to-server
//! attestations over a verification event, with the submitted facts bound by
//! HMAC hashes rather than disclosed as credential subject data.

use serde_json::{json, Value};
use time::OffsetDateTime;

use super::signer::{Signer, SignerError};

pub const EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE: &str =
    "application/vnd.registry-relay.evidence-verification+jwt";
pub const EVIDENCE_VERIFICATION_RECEIPT_JWT_TYP: &str = "evidence-verification-receipt+jwt";
pub const EVIDENCE_VERIFICATION_RECEIPT_TYPE: &str = "relay-verification-receipt";
const EVIDENCE_VERIFICATION_RECEIPT_NBF_SKEW_SECONDS: i64 = 5;

#[derive(Debug, Clone)]
pub struct EvidenceVerificationReceiptInputs {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub verification_id: String,
    pub decision: String,
    pub requirement: Option<String>,
    pub evidence_type: String,
    pub evidence_offering: String,
    pub issuing_authority: Value,
    pub jurisdiction: Option<Value>,
    pub level_of_assurance: Option<String>,
    pub dataset: String,
    pub entity: String,
    pub purpose_declared: Option<String>,
    pub checked_at: String,
    pub claim_salt: String,
    pub claim_hash: String,
    pub evidence_hash: Option<String>,
    pub issued_at: OffsetDateTime,
    pub valid_until: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct SignedReceipt {
    pub compact_jws: String,
    pub jti: String,
    pub issuer: String,
    pub verification_method_id: String,
    pub subject: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("signer rejected receipt: {0}")]
    Signer(#[from] SignerError),
}

pub fn encode(
    signer: &dyn Signer,
    inputs: EvidenceVerificationReceiptInputs,
) -> Result<SignedReceipt, EncodeError> {
    let jti = format!(
        "urn:registry-relay:evidence-verification:{}",
        inputs.verification_id
    );
    let iat = inputs.issued_at.unix_timestamp();
    let nbf = iat.saturating_sub(EVIDENCE_VERIFICATION_RECEIPT_NBF_SKEW_SECONDS);
    let exp = inputs.valid_until.unix_timestamp();
    let header = json!({
        "alg": signer.algorithm().jws_alg(),
        "typ": EVIDENCE_VERIFICATION_RECEIPT_JWT_TYP,
        "kid": signer.verification_method_id(),
    });
    let mut payload = json!({
        "iss": &inputs.issuer,
        "sub": &inputs.subject,
        "aud": &inputs.audience,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "jti": &jti,
        "receipt_type": EVIDENCE_VERIFICATION_RECEIPT_TYPE,
        "disclaimer": "Registry Relay evidence-verification receipts attest only to a registry comparison event. They are not official source credentials and do not decide eligibility.",
        "verification_id": &inputs.verification_id,
        "decision": &inputs.decision,
        "evidence_type": &inputs.evidence_type,
        "evidence_offering": &inputs.evidence_offering,
        "issuing_authority": &inputs.issuing_authority,
        "dataset": &inputs.dataset,
        "entity": &inputs.entity,
        "checked_at": &inputs.checked_at,
        "claim_salt": &inputs.claim_salt,
        "claim_hash": &inputs.claim_hash,
    });
    if let Some(requirement) = &inputs.requirement {
        payload["requirement"] = Value::String(requirement.clone());
    }
    if let Some(jurisdiction) = &inputs.jurisdiction {
        payload["jurisdiction"] = jurisdiction.clone();
    }
    if let Some(level_of_assurance) = &inputs.level_of_assurance {
        payload["level_of_assurance"] = Value::String(level_of_assurance.clone());
    }
    if let Some(purpose_declared) = &inputs.purpose_declared {
        payload["purpose_declared"] = Value::String(purpose_declared.clone());
    }
    if let Some(evidence_hash) = &inputs.evidence_hash {
        payload["evidence_hash"] = Value::String(evidence_hash.clone());
    }
    let compact_jws = signer.sign(header, payload)?;
    Ok(SignedReceipt {
        compact_jws,
        jti,
        issuer: inputs.issuer,
        verification_method_id: signer.verification_method_id().to_string(),
        subject: inputs.subject,
        iat,
        nbf,
        exp,
    })
}
