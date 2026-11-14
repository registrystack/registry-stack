// SPDX-License-Identifier: Apache-2.0
//! RFC 3161 signature timestamps: the request a signer sends its timestamp
//! authority, and the checks on the authority's response.
//!
//! The authority is reached by the caller; this module neither opens
//! connections nor decides which authorities to trust. It checks that a token
//! answers this request, verifies under the certificate it carries, names
//! that certificate in its ESS signing-certificate attribute, and that
//! certificate is a timestamping certificate valid at the token's time.

use super::asn1::{
    oid, IssuerSerial, MessageImprint, SigningCertificate, SigningCertificateV2, TimeStampReq,
    TimeStampResp, TspGeneralizedTime, TstInfo,
};
use super::certificate::{x509_time, CertificateFingerprint};
use super::verify::{
    single_attribute, verify_signed_data, DigestAlgorithm, SignerVerificationError,
};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use cms::cert::x509::attr::Attributes;
use cms::cert::x509::ext::pkix::name::GeneralName;
use cms::cert::x509::ext::pkix::ExtendedKeyUsage;
use cms::cert::x509::Certificate;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Int, OctetString, Uint};
use der::{Any, Decode as _, Encode as _, Tag, Tagged as _};
use thiserror::Error;
use time::OffsetDateTime;

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
    #[error(
        "the timestamp token has no ESS signing-certificate attribute naming its authority's certificate {fingerprint}"
    )]
    TsaCertificateNotNamedBySigningCertificate { fingerprint: CertificateFingerprint },
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
/// certificate the token carries; a token whose ESS signing-certificate
/// attribute is missing or names another certificate (RFC 3161 section
/// 2.4.1, RFC 5816); a certificate without a critical extended key usage of
/// exactly id-kp-timeStamping (RFC 3161 section 2.3); and a `genTime` outside
/// that certificate's validity.
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

/// Verify a token's signature, that its signing-certificate attribute names
/// the certificate it verifies under, that certificate's usage, and its
/// validity at `genTime`, and return `genTime`.
pub(super) fn verify_token(token: &TimestampToken) -> Result<OffsetDateTime, TimestampError> {
    let certificate = verify_signed_data(&token.signed_data, &[&token.tst_info_der])
        .map_err(TimestampError::TokenSignature)?;
    let certificate_der = certificate.to_der()?;
    let fingerprint = CertificateFingerprint::of(&certificate_der);
    let names_certificate = token
        .signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .and_then(|signer| signer.signed_attrs.as_ref())
        .is_some_and(|attributes| names_signer(attributes, certificate, &certificate_der));
    if !names_certificate {
        return Err(TimestampError::TsaCertificateNotNamedBySigningCertificate { fingerprint });
    }
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

/// RFC 3161 section 2.4.1, as RFC 5816 updates it: the signer carries
/// signingCertificate (RFC 2634) or signingCertificateV2 (RFC 5035), and the
/// first certificate each identifies is `certificate`, by hash and, when
/// given, by issuer and serial number. Each attribute present must be a
/// single value that decodes; at least one must be present.
fn names_signer(
    attributes: &Attributes,
    certificate: &Certificate,
    certificate_der: &[u8],
) -> bool {
    let attribute = |wanted| {
        attributes
            .iter()
            .any(|attribute| attribute.oid == wanted)
            .then(|| single_attribute(attributes, wanted))
    };
    let v2 = attribute(oid::SIGNING_CERTIFICATE_V2);
    let v1 = attribute(oid::SIGNING_CERTIFICATE);
    if v1.is_none() && v2.is_none() {
        return false;
    }
    let v2_names = |value: &Any| {
        value
            .decode_as::<SigningCertificateV2>()
            .ok()
            .and_then(|attribute| attribute.certs.into_iter().next())
            .is_some_and(|id| {
                // RFC 5035 section 4: SHA-256 when the algorithm is absent.
                let digest = match &id.hash_algorithm {
                    None => Some(DigestAlgorithm::Sha256),
                    Some(identifier) => DigestAlgorithm::from_identifier(identifier),
                };
                digest.is_some_and(|digest| {
                    id.cert_hash.as_bytes() == digest.digest(&[certificate_der]).as_slice()
                }) && issuer_serial_names(id.issuer_serial.as_ref(), certificate)
            })
    };
    let v1_names = |value: &Any| {
        value
            .decode_as::<SigningCertificate>()
            .ok()
            .and_then(|attribute| attribute.certs.into_iter().next())
            .is_some_and(|id| {
                let sha1 = aws_lc_rs::digest::digest(
                    &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                    certificate_der,
                );
                id.cert_hash.as_bytes() == sha1.as_ref()
                    && issuer_serial_names(id.issuer_serial.as_ref(), certificate)
            })
    };
    v2.is_none_or(|value| value.is_some_and(v2_names))
        && v1.is_none_or(|value| value.is_some_and(v1_names))
}

/// An absent `issuerSerial`, or one whose serial number and a directory name
/// are `certificate`'s issuer and serial number.
fn issuer_serial_names(issuer_serial: Option<&IssuerSerial>, certificate: &Certificate) -> bool {
    let tbs = &certificate.tbs_certificate;
    issuer_serial.is_none_or(|issuer_serial| {
        issuer_serial.serial_number == tbs.serial_number
            && issuer_serial.issuer.iter().any(
                |name| matches!(name, GeneralName::DirectoryName(issuer) if *issuer == tbs.issuer),
            )
    })
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
