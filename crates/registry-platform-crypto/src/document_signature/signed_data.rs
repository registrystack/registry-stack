// SPDX-License-Identifier: Apache-2.0
//! Detached CMS signed data for PAdES baseline signatures (ETSI EN 319 142-1),
//! and the signature timestamp that raises one from B-B to B-T.

use super::asn1::{oid, EcdsaSigValue, EssCertIdV2, IssuerSerial, SigningCertificateV2};
use super::certificate::{CertificateChain, CertificateError};
use super::timestamp::{check_imprint, read_token, verify_token, TimestampError};
use super::verify::{verify_signed_data, DigestAlgorithm, SignerVerificationError};
use crate::{SigningAlgorithm, SigningError, SigningProvider};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec, Uint};
use der::{Any, Decode as _, Encode as _};
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

/// A detached CMS signature, ready to embed in a PDF signature dictionary.
#[derive(Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    /// The DER `ContentInfo` holding the `SignedData`.
    pub cms_der: Vec<u8>,
    /// The signer's signature octets, the value an RFC 3161 signature
    /// timestamp covers.
    pub signature_value: Vec<u8>,
}

impl fmt::Debug for DetachedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetachedSignature")
            .field("cms_der_len", &self.cms_der.len())
            .field("signature_value_len", &self.signature_value.len())
            .finish()
    }
}

/// Why a detached signature could not be produced or extended.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CmsError {
    #[error(
        "document signatures use ES256, ES384, RS256 or RS384; the signer uses {}",
        .0.jwa_name()
    )]
    UnsupportedAlgorithm(SigningAlgorithm),
    #[error("the seal certificate may not sign: {0}")]
    Certificate(#[from] CertificateError),
    #[error("the signing provider failed: {0}")]
    Signing(#[source] SigningError),
    #[error("the signing provider returned a malformed signature: {0}")]
    MalformedProviderSignature(&'static str),
    #[error("the produced signature does not verify: {0}")]
    SelfVerification(#[source] SignerVerificationError),
    #[error("CMS encoding failed: {0}")]
    Encoding(#[from] der::Error),
    #[error("the CMS signature is not DER SignedData with exactly one signer")]
    MalformedSignedData,
    #[error("the timestamp token is not DER CMS SignedData over a TSTInfo")]
    MalformedTimestampToken,
    #[error("the timestamp token does not cover this signature value")]
    TimestampMismatch,
    #[error("the timestamp token was refused: {0}")]
    TimestampRefused(#[source] TimestampError),
    #[error("the signature already carries a signature timestamp")]
    TimestampAlreadyPresent,
}

/// How one signing algorithm is written into CMS.
struct SignerProfile {
    digest: DigestAlgorithm,
    signature_algorithm: AlgorithmIdentifierOwned,
    /// The width of each ECDSA half in a JWS `r || s` signature.
    ecdsa_half_width: Option<usize>,
}

impl SignerProfile {
    fn for_algorithm(algorithm: SigningAlgorithm) -> Result<Self, CmsError> {
        let ecdsa = |digest, signature_oid, width| Self {
            digest,
            // RFC 5758 section 3.2: the ECDSA identifiers carry no parameters.
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: signature_oid,
                parameters: None,
            },
            ecdsa_half_width: Some(width),
        };
        let rsa = |digest| Self {
            digest,
            // RFC 3370 section 3.2: rsaEncryption, with NULL parameters.
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: oid::RSA_ENCRYPTION,
                parameters: Some(Any::null()),
            },
            ecdsa_half_width: None,
        };
        match algorithm {
            SigningAlgorithm::Es256 => {
                Ok(ecdsa(DigestAlgorithm::Sha256, oid::ECDSA_WITH_SHA256, 32))
            }
            SigningAlgorithm::Es384 => {
                Ok(ecdsa(DigestAlgorithm::Sha384, oid::ECDSA_WITH_SHA384, 48))
            }
            SigningAlgorithm::Rs256 => Ok(rsa(DigestAlgorithm::Sha256)),
            SigningAlgorithm::Rs384 => Ok(rsa(DigestAlgorithm::Sha384)),
            SigningAlgorithm::EdDsa => Err(CmsError::UnsupportedAlgorithm(algorithm)),
        }
    }
}

/// Sign the concatenation of `content_parts` as detached CMS `SignedData`
/// for a PAdES baseline B-B signature.
///
/// For a PDF the parts are the byte ranges around the signature value. The
/// signed data carries `chain` in `certificates` and one signer, identified by
/// issuer and serial number, whose signed attributes are content type
/// (id-data), message digest and signing certificate v2. It carries no
/// signing time: PAdES puts the claimed time in the signature dictionary's
/// `M` entry. ES256 and RS256 digest with SHA-256, ES384 and RS384 with
/// SHA-384; EdDSA is refused, since PAdES validators do not accept it.
///
/// Before signing, the seal certificate is checked against the provider's
/// key at the current time ([`CertificateChain::check_for_signing`]). After
/// signing, the encoded result is decoded and verified, so a provider that
/// signs with another key or other bytes is refused here rather than by a
/// relying party.
pub async fn sign_detached(
    content_parts: &[&[u8]],
    chain: &CertificateChain,
    signer: &dyn SigningProvider,
) -> Result<DetachedSignature, CmsError> {
    let profile = SignerProfile::for_algorithm(signer.algorithm())?;
    chain.check_for_signing(&signer.public_jwk(), OffsetDateTime::now_utc())?;
    let leaf = &chain.leaf().parsed;

    let signed_attrs = signed_attributes(
        oid::DATA,
        profile.digest,
        &profile.digest.digest(content_parts),
        chain.leaf_der(),
        leaf,
    )?;
    // RFC 5652 section 5.4: the signature covers the DER of the attributes
    // as a SET OF, not the [0] IMPLICIT encoding inside SignerInfo.
    let provider_signature = signer
        .sign(&signed_attrs.to_der()?)
        .await
        .map_err(CmsError::Signing)?;
    let signature_value = match profile.ecdsa_half_width {
        Some(width) => jws_ecdsa_to_der(&provider_signature, width)?,
        None => provider_signature,
    };

    let certificates: Vec<Certificate> = chain
        .certificates()
        .iter()
        .map(|certificate| certificate.parsed.clone())
        .collect();
    let signed_data = assemble_signed_data(
        profile.digest,
        EncapsulatedContentInfo {
            econtent_type: oid::DATA,
            econtent: None,
        },
        &certificates,
        leaf,
        signed_attrs,
        profile.signature_algorithm,
        signature_value.clone(),
    )?;
    let cms_der = content_info(&signed_data)?.to_der()?;

    // Verify what a relying party will read: the encoded bytes.
    let decoded = decode_signed_data(&cms_der).ok_or(CmsError::MalformedSignedData)?;
    let verified =
        verify_signed_data(&decoded, content_parts).map_err(CmsError::SelfVerification)?;
    if verified.to_der()? != chain.leaf_der() {
        return Err(CmsError::SelfVerification(
            SignerVerificationError::SignerCertificateMissing,
        ));
    }
    Ok(DetachedSignature {
        cms_der,
        signature_value,
    })
}

/// Add an RFC 3161 timestamp token as the signer's
/// `id-aa-signatureTimeStampToken` unsigned attribute, raising a PAdES B-B
/// signature to B-T. The signed attributes and signature are unchanged.
///
/// Check the timestamp authority's response with
/// [`accept_timestamp_response`](super::accept_timestamp_response) first; that
/// is where the request's nonce is matched. This re-checks the token itself:
/// it must cover this signature value, verify, and come from a timestamping
/// certificate valid at its time.
pub fn add_signature_timestamp(cms_der: &[u8], token_der: &[u8]) -> Result<Vec<u8>, CmsError> {
    let mut signed_data = decode_signed_data(cms_der).ok_or(CmsError::MalformedSignedData)?;
    if signed_data.signer_infos.0.len() != 1 {
        return Err(CmsError::MalformedSignedData);
    }
    let token = ContentInfo::from_der(token_der).map_err(|_| CmsError::MalformedTimestampToken)?;
    let token = read_token(&token).map_err(|error| match error {
        TimestampError::NotTstInfo
        | TimestampError::MalformedTstInfo
        | TimestampError::MalformedResponse => CmsError::MalformedTimestampToken,
        other => CmsError::TimestampRefused(other),
    })?;

    let mut signers = signed_data.signer_infos.0.into_vec();
    let signer = &mut signers[0];
    check_imprint(&token.tst_info, signer.signature.as_bytes()).map_err(|error| match error {
        TimestampError::MessageImprintMismatch => CmsError::TimestampMismatch,
        other => CmsError::TimestampRefused(other),
    })?;
    verify_token(&token).map_err(CmsError::TimestampRefused)?;

    let mut unsigned = signer.unsigned_attrs.take().unwrap_or_default();
    if unsigned
        .iter()
        .any(|attribute| attribute.oid == oid::SIGNATURE_TIME_STAMP_TOKEN)
    {
        return Err(CmsError::TimestampAlreadyPresent);
    }
    unsigned.insert(Attribute {
        oid: oid::SIGNATURE_TIME_STAMP_TOKEN,
        values: SetOfVec::try_from(vec![Any::from_der(token_der)?])?,
    })?;
    signer.unsigned_attrs = Some(unsigned);
    signed_data.signer_infos = SignerInfos(SetOfVec::try_from(signers)?);
    Ok(content_info(&signed_data)?.to_der()?)
}

/// The signed attributes of a signer over content of `content_type` with
/// digest `content_digest`: content type, message digest, and a signing
/// certificate v2 naming `signer` by hash, issuer and serial number.
pub(super) fn signed_attributes(
    content_type: ObjectIdentifier,
    digest: DigestAlgorithm,
    content_digest: &[u8],
    signer_der: &[u8],
    signer: &Certificate,
) -> Result<Attributes, der::Error> {
    let signing_certificate = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            // RFC 5035 section 4: SHA-256 is the DEFAULT, which DER omits.
            hash_algorithm: (digest != DigestAlgorithm::Sha256).then(|| digest.identifier()),
            cert_hash: OctetString::new(digest.digest(&[signer_der]))?,
            issuer_serial: Some(IssuerSerial {
                issuer: vec![GeneralName::DirectoryName(
                    signer.tbs_certificate.issuer.clone(),
                )],
                serial_number: signer.tbs_certificate.serial_number.clone(),
            }),
        }],
        policies: None,
    };
    let attribute = |oid, value: Any| -> Result<Attribute, der::Error> {
        Ok(Attribute {
            oid,
            values: SetOfVec::try_from(vec![value])?,
        })
    };
    SetOfVec::try_from(vec![
        attribute(oid::CONTENT_TYPE, Any::encode_from(&content_type)?)?,
        attribute(
            oid::MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(content_digest)?)?,
        )?,
        attribute(
            oid::SIGNING_CERTIFICATE_V2,
            Any::encode_from(&signing_certificate)?,
        )?,
    ])
}

/// `SignedData` with one signer identified by issuer and serial number.
/// RFC 5652 section 5.1 sets the version: 1 for id-data, 3 otherwise.
#[allow(clippy::too_many_arguments)]
pub(super) fn assemble_signed_data(
    digest: DigestAlgorithm,
    encap_content_info: EncapsulatedContentInfo,
    certificates: &[Certificate],
    signer: &Certificate,
    signed_attrs: Attributes,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: Vec<u8>,
) -> Result<SignedData, der::Error> {
    let version = if encap_content_info.econtent_type == oid::DATA {
        CmsVersion::V1
    } else {
        CmsVersion::V3
    };
    let certificates = if certificates.is_empty() {
        None
    } else {
        Some(CertificateSet(SetOfVec::try_from(
            certificates
                .iter()
                .cloned()
                .map(CertificateChoices::Certificate)
                .collect::<Vec<_>>(),
        )?))
    };
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: signer.tbs_certificate.issuer.clone(),
            serial_number: signer.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: digest.identifier(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm,
        signature: OctetString::new(signature)?,
        unsigned_attrs: None,
    };
    Ok(SignedData {
        version,
        digest_algorithms: SetOfVec::try_from(vec![digest.identifier()])?,
        encap_content_info,
        certificates,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info])?),
    })
}

pub(super) fn content_info(signed_data: &SignedData) -> Result<ContentInfo, der::Error> {
    Ok(ContentInfo {
        content_type: oid::SIGNED_DATA,
        content: Any::encode_from(signed_data)?,
    })
}

/// Read a DER `ContentInfo` holding `SignedData`.
pub(super) fn decode_signed_data(der: &[u8]) -> Option<SignedData> {
    let content_info = ContentInfo::from_der(der).ok()?;
    if content_info.content_type != oid::SIGNED_DATA {
        return None;
    }
    content_info.content.decode_as::<SignedData>().ok()
}

/// Convert a JWS ECDSA signature, `r || s` with each half `half_width` bytes
/// (RFC 7518 section 3.4), into the DER `ECDSA-Sig-Value` CMS carries
/// (RFC 5753 section 7.2 and RFC 5480 section 2.2).
pub(super) fn jws_ecdsa_to_der(signature: &[u8], half_width: usize) -> Result<Vec<u8>, CmsError> {
    if signature.len() != 2 * half_width {
        return Err(CmsError::MalformedProviderSignature(
            "the ECDSA signature is not r || s at the curve's width",
        ));
    }
    let (r, s) = signature.split_at(half_width);
    if r.iter().all(|byte| *byte == 0) || s.iter().all(|byte| *byte == 0) {
        return Err(CmsError::MalformedProviderSignature(
            "an ECDSA signature half is zero",
        ));
    }
    Ok(EcdsaSigValue {
        r: Uint::new(r)?,
        s: Uint::new(s)?,
    }
    .to_der()?)
}
