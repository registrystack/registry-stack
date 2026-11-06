// SPDX-License-Identifier: Apache-2.0
//! RFC 3161 signature timestamps: the request a signer sends its timestamp
//! authority, and the checks on the authority's response.
//!
//! The authority is reached by the caller; this module neither opens
//! connections nor decides which authorities to trust. It checks that a token
//! answers this request, verifies under the certificate it carries, and that
//! certificate is a timestamping certificate valid at the token's time.

use super::asn1::{oid, MessageImprint, TimeStampReq, TimeStampResp, TspGeneralizedTime, TstInfo};
use super::certificate::{x509_time, CertificateFingerprint};
use super::verify::{verify_signed_data, DigestAlgorithm, SignerVerificationError};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Int, OctetString, Uint};
use der::{Decode as _, Encode as _, Tag, Tagged as _};
use thiserror::Error;
use time::OffsetDateTime;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

/// The largest timestamp response [`accept_timestamp_response`] reads. A
/// token holds one TSTInfo and the authority's certificates; 64 KiB leaves
/// room for a long chain.
pub const MAX_TIMESTAMP_RESPONSE_BYTES: usize = 64 * 1024;

/// A checked RFC 3161 timestamp token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureTimestamp {
    /// The token, a DER `ContentInfo`, for
    /// [`add_signature_timestamp`](super::add_signature_timestamp).
    pub token_der: Vec<u8>,
    /// The time the authority attests, `genTime` of its TSTInfo.
    pub gen_time: OffsetDateTime,
}

/// Why a timestamp request could not be built or a response was refused.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TimestampError {
    #[error("the timestamp response exceeds {MAX_TIMESTAMP_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("the timestamp response is not a DER TimeStampResp")]
    MalformedResponse,
    #[error("the timestamp authority did not grant the request (PKIStatus {status})")]
    NotGranted { status: u32 },
    #[error("the timestamp authority granted the request but sent no token")]
    MissingToken,
    #[error("the timestamp token is not CMS SignedData over a TSTInfo")]
    NotTstInfo,
    #[error("the timestamp token's TSTInfo is malformed or not version 1")]
    MalformedTstInfo,
    #[error("the timestamp token does not cover the SHA-256 digest of this signature value")]
    MessageImprintMismatch,
    #[error("the timestamp token does not carry the request's nonce")]
    NonceMismatch,
    #[error("the timestamp token does not verify: {0}")]
    TokenSignature(#[source] SignerVerificationError),
    #[error(
        "timestamp authority certificate {fingerprint} lacks a critical extended key usage of timeStamping alone"
    )]
    TsaCertificateNotForTimestamping { fingerprint: CertificateFingerprint },
    #[error("timestamp authority certificate {fingerprint} is not valid at the token's time")]
    TsaCertificateNotValidAtGenTime { fingerprint: CertificateFingerprint },
    #[error("the timestamp request could not be DER encoded: {0}")]
    Encoding(#[from] der::Error),
    #[error("the system random number generator failed")]
    RandomUnavailable,
}

/// A fresh 64-bit nonce for [`timestamp_request`], from the system random
/// number generator.
pub fn random_timestamp_nonce() -> Result<u64, TimestampError> {
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| TimestampError::RandomUnavailable)?;
    Ok(u64::from_be_bytes(bytes))
}

/// The DER `TimeStampReq` for a signature timestamp over `signature_value`:
/// version 1, a SHA-256 message imprint of the value, `nonce`, and `certReq`
/// TRUE so the token carries the authority's certificate. Send it as
/// `application/timestamp-query` (RFC 3161 section 3.4).
pub fn timestamp_request(signature_value: &[u8], nonce: u64) -> Result<Vec<u8>, TimestampError> {
    let request = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: DigestAlgorithm::Sha256.identifier(),
            hashed_message: OctetString::new(DigestAlgorithm::Sha256.digest(&[signature_value]))?,
        },
        req_policy: None,
        nonce: Some(Uint::new(&nonce.to_be_bytes())?),
        cert_req: Some(true),
        extensions: None,
    };
    Ok(request.to_der()?)
}

/// Check a DER `TimeStampResp` to a [`timestamp_request`] for
/// `signature_value` and `nonce`, and return its token.
///
/// Refuses, in order: a response over [`MAX_TIMESTAMP_RESPONSE_BYTES`] or
/// not DER; a status other than granted or granted with modifications; a
/// missing token; a token that is not `SignedData` over a version 1 TSTInfo;
/// a message imprint other than SHA-256 of `signature_value`; a missing or
/// different nonce; a token signature that does not verify under the
/// certificate the token carries; a certificate without a critical extended
/// key usage of exactly id-kp-timeStamping (RFC 3161 section 2.3); and a
/// `genTime` outside that certificate's validity.
///
/// Whether the authority is trusted, and whether its certificate is revoked,
/// is not checked here.
pub fn accept_timestamp_response(
    response_der: &[u8],
    signature_value: &[u8],
    nonce: u64,
) -> Result<SignatureTimestamp, TimestampError> {
    if response_der.len() > MAX_TIMESTAMP_RESPONSE_BYTES {
        return Err(TimestampError::ResponseTooLarge);
    }
    let response =
        TimeStampResp::from_der(response_der).map_err(|_| TimestampError::MalformedResponse)?;
    // RFC 3161 section 2.4.2: granted (0) and grantedWithMods (1) carry a token.
    let status = response.status.status;
    if status > 1 {
        return Err(TimestampError::NotGranted { status });
    }
    let token_info = response
        .time_stamp_token
        .ok_or(TimestampError::MissingToken)?;
    let token = read_token(&token_info)?;
    check_imprint(&token.tst_info, signature_value)?;
    let expected_nonce = Int::from(Uint::new(&nonce.to_be_bytes())?);
    if token.tst_info.nonce.as_ref() != Some(&expected_nonce) {
        return Err(TimestampError::NonceMismatch);
    }
    let gen_time = verify_token(&token)?;
    Ok(SignatureTimestamp {
        token_der: token_info.to_der()?,
        gen_time,
    })
}

/// A timestamp token, decoded but not yet verified.
pub(super) struct TimestampToken {
    signed_data: SignedData,
    tst_info_der: Vec<u8>,
    pub(super) tst_info: TstInfo,
}

/// Decode a token as `SignedData` encapsulating a version 1 TSTInfo.
pub(super) fn read_token(token: &ContentInfo) -> Result<TimestampToken, TimestampError> {
    if token.content_type != oid::SIGNED_DATA {
        return Err(TimestampError::NotTstInfo);
    }
    let signed_data = token
        .content
        .decode_as::<SignedData>()
        .map_err(|_| TimestampError::MalformedResponse)?;
    if signed_data.encap_content_info.econtent_type != oid::TST_INFO {
        return Err(TimestampError::NotTstInfo);
    }
    let tst_info_der = match &signed_data.encap_content_info.econtent {
        Some(econtent) if econtent.tag() == Tag::OctetString => econtent.value().to_vec(),
        _ => return Err(TimestampError::NotTstInfo),
    };
    let tst_info =
        TstInfo::from_der(&tst_info_der).map_err(|_| TimestampError::MalformedTstInfo)?;
    if tst_info.version != 1 {
        return Err(TimestampError::MalformedTstInfo);
    }
    Ok(TimestampToken {
        signed_data,
        tst_info_der,
        tst_info,
    })
}

/// Check that a TSTInfo's message imprint is the SHA-256 digest of
/// `signature_value`, the imprint [`timestamp_request`] asks for.
pub(super) fn check_imprint(
    tst_info: &TstInfo,
    signature_value: &[u8],
) -> Result<(), TimestampError> {
    let imprint = &tst_info.message_imprint;
    let algorithm = DigestAlgorithm::from_identifier(&imprint.hash_algorithm);
    if algorithm != Some(DigestAlgorithm::Sha256)
        || imprint.hashed_message.as_bytes()
            != DigestAlgorithm::Sha256
                .digest(&[signature_value])
                .as_slice()
    {
        return Err(TimestampError::MessageImprintMismatch);
    }
    Ok(())
}

/// Verify a token's signature, its authority's certificate usage, and that
/// certificate's validity at `genTime`, and return `genTime`.
pub(super) fn verify_token(token: &TimestampToken) -> Result<OffsetDateTime, TimestampError> {
    let certificate = verify_signed_data(&token.signed_data, &[&token.tst_info_der])
        .map_err(TimestampError::TokenSignature)?;
    let fingerprint = CertificateFingerprint::of(&certificate.to_der()?);
    if !only_critical_timestamping(certificate) {
        return Err(TimestampError::TsaCertificateNotForTimestamping { fingerprint });
    }
    let gen_time = TspGeneralizedTime::to_offset_date_time(token.tst_info.gen_time);
    let validity = &certificate.tbs_certificate.validity;
    if gen_time < x509_time(validity.not_before) || gen_time > x509_time(validity.not_after) {
        return Err(TimestampError::TsaCertificateNotValidAtGenTime { fingerprint });
    }
    Ok(gen_time)
}

/// RFC 3161 section 2.3: one extended key usage extension, critical, whose
/// only purpose is id-kp-timeStamping.
fn only_critical_timestamping(certificate: &Certificate) -> bool {
    let mut extensions = certificate
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|extension| extension.extn_id == oid::EXTENDED_KEY_USAGE);
    let (Some(extension), None) = (extensions.next(), extensions.next()) else {
        return false;
    };
    extension.critical
        && ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())
            .is_ok_and(|usage| usage.0 == [oid::KP_TIME_STAMPING])
}
