// SPDX-License-Identifier: Apache-2.0
//! Verification of one CMS signer: the self-check after signing, and the
//! check of a timestamp authority's token.
//!
//! This verifies the signature arithmetic and the signed attributes that bind
//! it to the content. It does not validate a certification path, and it does
//! not decide whether the signer's certificate is trusted.

use super::asn1::oid;
use aws_lc_rs::signature::{
    UnparsedPublicKey, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1,
    ECDSA_P256_SHA512_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA512_ASN1,
    ECDSA_P521_SHA256_ASN1, ECDSA_P521_SHA384_ASN1, ECDSA_P521_SHA512_ASN1,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use cms::cert::x509::attr::Attributes;
use cms::cert::x509::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use cms::cert::x509::Certificate;
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Any, Decode as _, Encode as _, Tag, Tagged as _};
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;

/// Why a CMS signer did not verify.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignerVerificationError {
    #[error("the signed data holds {count} signers; exactly one is expected")]
    SignerCount { count: usize },
    #[error("the signer's certificate is not in the signed data")]
    SignerCertificateMissing,
    #[error("the signer has no signed attributes")]
    SignedAttributesMissing,
    #[error("the signed attribute {name} is missing, repeated or malformed")]
    MalformedAttribute { name: &'static str },
    #[error("the content-type attribute does not name the encapsulated content type")]
    ContentTypeMismatch,
    #[error("the message digest does not match the signed content")]
    MessageDigestMismatch,
    #[error("the signer's digest algorithm is not SHA-256, SHA-384 or SHA-512")]
    UnsupportedDigestAlgorithm,
    #[error(
        "the signer's signature algorithm is not RSA PKCS #1 v1.5 or ECDSA on P-256, P-384 or P-521 with its digest algorithm"
    )]
    UnsupportedSignatureAlgorithm,
    #[error("the signature does not verify under the signer's certificate")]
    SignatureInvalid,
    #[error("the signed attributes could not be DER encoded")]
    Encoding,
}

/// A SHA-2 digest this module signs with or accepts from a signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub(super) fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => oid::SHA256,
            Self::Sha384 => oid::SHA384,
            Self::Sha512 => oid::SHA512,
        }
    }

    /// The identifier this module writes: parameters absent, as RFC 5754
    /// section 2 requires of a sender.
    pub(super) fn identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// Read an identifier. RFC 5754 section 2 asks receivers to accept NULL
    /// parameters as well as absent ones.
    pub(super) fn from_identifier(identifier: &AlgorithmIdentifierOwned) -> Option<Self> {
        if !absent_or_null(identifier.parameters.as_ref()) {
            return None;
        }
        match identifier.oid {
            oid::SHA256 => Some(Self::Sha256),
            oid::SHA384 => Some(Self::Sha384),
            oid::SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The digest of the parts, concatenated.
    pub(super) fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: sha2::Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut hasher = D::new();
            for part in parts {
                hasher.update(part);
            }
            hasher.finalize().to_vec()
        }
        match self {
            Self::Sha256 => run::<Sha256>(parts),
            Self::Sha384 => run::<Sha384>(parts),
            Self::Sha512 => run::<Sha512>(parts),
        }
    }
}

fn absent_or_null(parameters: Option<&Any>) -> bool {
    parameters
        .is_none_or(|parameters| parameters.tag() == Tag::Null && parameters.value().is_empty())
}

/// Verify the one signer of `signed_data` over `content`, the detached
/// content's parts or an encapsulated content's octets, and return the
/// signer's certificate from the signed data's `certificates`.
///
/// Checks, in order: one signer; a SHA-2 digest algorithm; the signer's
/// certificate is present; signed attributes are present; exactly one
/// content-type attribute naming the encapsulated content type; exactly one
/// message-digest attribute equal to the content's digest; the signature over
/// the DER `SET OF` signed attributes, under the certificate's key.
pub(super) fn verify_signed_data<'a>(
    signed_data: &'a SignedData,
    content: &[&[u8]],
) -> Result<&'a Certificate, SignerVerificationError> {
    let count = signed_data.signer_infos.0.len();
    let Some(signer) = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .filter(|_| count == 1)
    else {
        return Err(SignerVerificationError::SignerCount { count });
    };
    let digest = DigestAlgorithm::from_identifier(&signer.digest_alg)
        .ok_or(SignerVerificationError::UnsupportedDigestAlgorithm)?;
    let certificate = signer_certificate(signed_data, &signer.sid)
        .ok_or(SignerVerificationError::SignerCertificateMissing)?;
    let attributes = signer
        .signed_attrs
        .as_ref()
        .ok_or(SignerVerificationError::SignedAttributesMissing)?;

    let content_type = single_attribute(attributes, oid::CONTENT_TYPE)
        .and_then(|value| value.decode_as::<ObjectIdentifier>().ok())
        .ok_or(SignerVerificationError::MalformedAttribute {
            name: "contentType",
        })?;
    if content_type != signed_data.encap_content_info.econtent_type {
        return Err(SignerVerificationError::ContentTypeMismatch);
    }
    let message_digest = single_attribute(attributes, oid::MESSAGE_DIGEST)
        .and_then(|value| value.decode_as::<OctetString>().ok())
        .ok_or(SignerVerificationError::MalformedAttribute {
            name: "messageDigest",
        })?;
    if message_digest.as_bytes() != digest.digest(content).as_slice() {
        return Err(SignerVerificationError::MessageDigestMismatch);
    }

    let signed_message = attributes
        .to_der()
        .map_err(|_| SignerVerificationError::Encoding)?;
    verify_signature(
        &certificate.tbs_certificate.subject_public_key_info,
        &signer.signature_algorithm,
        digest,
        &signed_message,
        signer.signature.as_bytes(),
    )?;
    Ok(certificate)
}

/// The one value of the one attribute of type `wanted`, or none when the
/// attribute is absent, repeated, or multi-valued (RFC 5652 section 5.3).
pub(super) fn single_attribute(attributes: &Attributes, wanted: ObjectIdentifier) -> Option<&Any> {
    let mut matching = attributes
        .iter()
        .filter(|attribute| attribute.oid == wanted);
    let attribute = matching.next()?;
    if matching.next().is_some() || attribute.values.len() != 1 {
        return None;
    }
    attribute.values.iter().next()
}

fn signer_certificate<'a>(
    signed_data: &'a SignedData,
    sid: &SignerIdentifier,
) -> Option<&'a Certificate> {
    signed_data
        .certificates
        .as_ref()?
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate),
            CertificateChoices::Other(_) => None,
        })
        .find(|certificate| identifies(sid, certificate))
}

fn identifies(sid: &SignerIdentifier, certificate: &Certificate) -> bool {
    let tbs = &certificate.tbs_certificate;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
            tbs.issuer == issuer_and_serial.issuer
                && tbs.serial_number == issuer_and_serial.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(wanted) => tbs
            .extensions
            .iter()
            .flatten()
            .filter(|extension| extension.extn_id == oid::SUBJECT_KEY_IDENTIFIER)
            .filter_map(|extension| OctetString::from_der(extension.extn_value.as_bytes()).ok())
            .any(|identifier| identifier == wanted.0),
    }
}

/// Verify `signature` over `message` under `spki`.
///
/// An RSA signer may name `rsaEncryption` (RFC 3370 section 3.2) or a
/// `shaNNNWithRSAEncryption` whose hash is the digest algorithm. An ECDSA
/// signer names `ecdsa-with-SHANNN` with absent parameters (RFC 5758
/// section 3.2), whose hash must be the digest algorithm, and its signature is
/// a DER `ECDSA-Sig-Value`.
pub(super) fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest: DigestAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignerVerificationError> {
    let algorithm = verification_algorithm(spki, signature_algorithm, digest)
        .ok_or(SignerVerificationError::UnsupportedSignatureAlgorithm)?;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(SignerVerificationError::SignatureInvalid)?;
    UnparsedPublicKey::new(algorithm, key)
        .verify(message, signature)
        .map_err(|_| SignerVerificationError::SignatureInvalid)
}

fn verification_algorithm(
    spki: &SubjectPublicKeyInfoOwned,
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest: DigestAlgorithm,
) -> Option<&'static dyn VerificationAlgorithm> {
    use DigestAlgorithm::{Sha256, Sha384, Sha512};

    let named_hash = match signature_algorithm.oid {
        oid::RSA_ENCRYPTION => None,
        oid::SHA256_WITH_RSA | oid::ECDSA_WITH_SHA256 => Some(Sha256),
        oid::SHA384_WITH_RSA | oid::ECDSA_WITH_SHA384 => Some(Sha384),
        oid::SHA512_WITH_RSA | oid::ECDSA_WITH_SHA512 => Some(Sha512),
        _ => return None,
    };
    if named_hash.is_some_and(|hash| hash != digest) {
        return None;
    }
    let ecdsa = matches!(
        signature_algorithm.oid,
        oid::ECDSA_WITH_SHA256 | oid::ECDSA_WITH_SHA384 | oid::ECDSA_WITH_SHA512
    );

    if ecdsa {
        if signature_algorithm.parameters.is_some() || spki.algorithm.oid != oid::EC_PUBLIC_KEY {
            return None;
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()?
            .decode_as::<ObjectIdentifier>()
            .ok()?;
        let algorithm: &'static dyn VerificationAlgorithm = match (curve, digest) {
            (oid::SECP256R1, Sha256) => &ECDSA_P256_SHA256_ASN1,
            (oid::SECP256R1, Sha384) => &ECDSA_P256_SHA384_ASN1,
            (oid::SECP256R1, Sha512) => &ECDSA_P256_SHA512_ASN1,
            (oid::SECP384R1, Sha256) => &ECDSA_P384_SHA256_ASN1,
            (oid::SECP384R1, Sha384) => &ECDSA_P384_SHA384_ASN1,
            (oid::SECP384R1, Sha512) => &ECDSA_P384_SHA512_ASN1,
            (oid::SECP521R1, Sha256) => &ECDSA_P521_SHA256_ASN1,
            (oid::SECP521R1, Sha384) => &ECDSA_P521_SHA384_ASN1,
            (oid::SECP521R1, Sha512) => &ECDSA_P521_SHA512_ASN1,
            _ => return None,
        };
        return Some(algorithm);
    }

    if !absent_or_null(signature_algorithm.parameters.as_ref())
        || spki.algorithm.oid != oid::RSA_ENCRYPTION
    {
        return None;
    }
    Some(match digest {
        Sha256 => &RSA_PKCS1_2048_8192_SHA256,
        Sha384 => &RSA_PKCS1_2048_8192_SHA384,
        Sha512 => &RSA_PKCS1_2048_8192_SHA512,
    })
}
