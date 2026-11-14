// SPDX-License-Identifier: Apache-2.0
//! PKCS #10 certificate requests (RFC 2986) for a seal key, signed through
//! its signing provider so the private key never leaves the provider.

use super::asn1::oid;
use super::signed_data::jws_ecdsa_to_der;
use super::verify::{verify_signature, DigestAlgorithm};
use crate::{
    decode_fixed, decode_nonempty, JwkError, PublicJwk, SigningAlgorithm, SigningError,
    SigningProvider,
};
use cms::cert::x509::attr::AttributeTypeAndValue;
use cms::cert::x509::name::{Name, RdnSequence, RelativeDistinguishedName};
use cms::cert::x509::request::{CertReq, CertReqInfo, Version};
use cms::cert::x509::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use der::asn1::{BitString, ObjectIdentifier, PrintableStringRef, SetOfVec, Utf8StringRef};
use der::pem::LineEnding;
use der::{Any, Decode as _, Encode as _};
use pkcs1::der::{asn1::UintRef as Pkcs1UintRef, Encode as _};
use std::fmt;
use thiserror::Error;

/// The X.520 upper bound on a common name and an organization name, in
/// characters (`ub-common-name` and `ub-organization-name`).
const MAX_NAME_CHARACTERS: usize = 64;

/// The subject a seal certificate request names. The certificate authority
/// decides what the issued certificate finally carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequestSubject {
    /// The seal's name, written as `commonName`.
    pub common_name: String,
    /// The institution, written as `organizationName`.
    pub organization: Option<String>,
    /// The ISO 3166 two-letter country code, written as `countryName`.
    pub country: Option<String>,
}

/// A DER PKCS #10 certificate request.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    der: Vec<u8>,
}

impl CertificateRequest {
    /// The DER `CertificationRequest`.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The request as a `CERTIFICATE REQUEST` PEM block (RFC 7468 section
    /// 7), the form certificate authorities and `openssl req` read.
    #[must_use]
    pub fn to_pem(&self) -> String {
        der::pem::encode_string("CERTIFICATE REQUEST", LineEnding::LF, &self.der)
            .expect("a DER request well under the PEM size limit encodes")
    }
}

impl fmt::Debug for CertificateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateRequest")
            .field("der_len", &self.der.len())
            .finish()
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertificateRequestError {
    #[error("the request subject's {member} {reason}")]
    Subject {
        /// The X.520 attribute name: `commonName`, `organizationName` or
        /// `countryName`.
        member: &'static str,
        reason: &'static str,
    },
    #[error(
        "seal certificate requests use ES256, ES384, RS256 or RS384; the signer uses {}",
        .0.jwa_name()
    )]
    UnsupportedAlgorithm(SigningAlgorithm),
    #[error("the signer's public key is not a usable JWK: {0}")]
    InvalidKey(#[source] JwkError),
    #[error("the signing provider failed: {0}")]
    Signing(#[source] SigningError),
    #[error("the signing provider returned a malformed signature: {0}")]
    MalformedProviderSignature(&'static str),
    #[error("the signed request does not verify under the signer's public key")]
    SelfVerification,
    #[error("certificate request encoding failed: {0}")]
    Encoding(#[from] der::Error),
    #[error("certificate request RSA public-key encoding failed: {0}")]
    RsaEncoding(#[from] pkcs1::der::Error),
}

/// How one seal algorithm signs a certificate request.
struct RequestProfile {
    digest: DigestAlgorithm,
    signature_algorithm: AlgorithmIdentifierOwned,
    /// The curve and the width of each coordinate and signature half, for
    /// ECDSA.
    ecdsa: Option<(ObjectIdentifier, usize)>,
}

impl RequestProfile {
    fn for_algorithm(algorithm: SigningAlgorithm) -> Result<Self, CertificateRequestError> {
        // RFC 5758 section 3.2: the ECDSA identifiers carry no parameters.
        let ecdsa = |digest, signature_oid, curve, width| Self {
            digest,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: signature_oid,
                parameters: None,
            },
            ecdsa: Some((curve, width)),
        };
        // RFC 4055 section 5: the PKCS #1 v1.5 identifiers carry NULL.
        let rsa = |digest, signature_oid| Self {
            digest,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: signature_oid,
                parameters: Some(Any::null()),
            },
            ecdsa: None,
        };
        match algorithm {
            SigningAlgorithm::Es256 => Ok(ecdsa(
                DigestAlgorithm::Sha256,
                oid::ECDSA_WITH_SHA256,
                oid::SECP256R1,
                32,
            )),
            SigningAlgorithm::Es384 => Ok(ecdsa(
                DigestAlgorithm::Sha384,
                oid::ECDSA_WITH_SHA384,
                oid::SECP384R1,
                48,
            )),
            SigningAlgorithm::Rs256 => Ok(rsa(DigestAlgorithm::Sha256, oid::SHA256_WITH_RSA)),
            SigningAlgorithm::Rs384 => Ok(rsa(DigestAlgorithm::Sha384, oid::SHA384_WITH_RSA)),
            SigningAlgorithm::EdDsa => {
                Err(CertificateRequestError::UnsupportedAlgorithm(algorithm))
            }
        }
    }
}

/// Build a PKCS #10 certificate request for `signer`'s key, naming
/// `subject`, and sign it through the provider.
///
/// The subject is written country, organization, common name, one
/// attribute to each relative distinguished name, the country as a
/// `PrintableString` and the names as `UTF8String` (RFC 5280 section
/// 4.1.2.4). The request carries no attributes, so no extension is
/// requested: the certificate authority sets key usage and basic
/// constraints. The encoded request is decoded and verified under its own
/// public key before it is returned, so a provider that signs with another
/// key or other bytes is refused here rather than by the certificate
/// authority.
pub async fn certificate_request(
    subject: &CertificateRequestSubject,
    signer: &dyn SigningProvider,
) -> Result<CertificateRequest, CertificateRequestError> {
    let profile = RequestProfile::for_algorithm(signer.algorithm())?;
    let info = CertReqInfo {
        version: Version::V1,
        subject: subject_name(subject)?,
        public_key: public_key_info(&signer.public_jwk(), &profile)?,
        attributes: SetOfVec::new(),
    };
    let provider_signature = signer
        .sign(&info.to_der()?)
        .await
        .map_err(CertificateRequestError::Signing)?;
    let signature = match profile.ecdsa {
        Some((_, width)) => jws_ecdsa_to_der(&provider_signature, width).map_err(|_| {
            CertificateRequestError::MalformedProviderSignature(
                "the ECDSA signature is not a nonzero r || s at the curve's width",
            )
        })?,
        None => provider_signature,
    };
    let der = CertReq {
        info,
        algorithm: profile.signature_algorithm,
        signature: BitString::from_bytes(&signature)?,
    }
    .to_der()?;

    // Verify what the certificate authority will read: the encoded bytes.
    let decoded = CertReq::from_der(&der)?;
    let signature = decoded
        .signature
        .as_bytes()
        .ok_or(CertificateRequestError::SelfVerification)?;
    verify_signature(
        &decoded.info.public_key,
        &decoded.algorithm,
        profile.digest,
        &decoded.info.to_der()?,
        signature,
    )
    .map_err(|_| CertificateRequestError::SelfVerification)?;
    Ok(CertificateRequest { der })
}

fn subject_name(subject: &CertificateRequestSubject) -> Result<Name, CertificateRequestError> {
    let mut rdns = Vec::with_capacity(3);
    if let Some(country) = &subject.country {
        if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(CertificateRequestError::Subject {
                member: "countryName",
                reason: "is not two uppercase ISO 3166 letters",
            });
        }
        rdns.push(rdn(
            oid::COUNTRY_NAME,
            Any::encode_from(&PrintableStringRef::new(country)?)?,
        )?);
    }
    if let Some(organization) = &subject.organization {
        rdns.push(rdn(
            oid::ORGANIZATION_NAME,
            directory_name("organizationName", organization)?,
        )?);
    }
    rdns.push(rdn(
        oid::COMMON_NAME,
        directory_name("commonName", &subject.common_name)?,
    )?);
    Ok(RdnSequence(rdns))
}

fn directory_name(member: &'static str, value: &str) -> Result<Any, CertificateRequestError> {
    let refuse = |reason| Err(CertificateRequestError::Subject { member, reason });
    if value.trim().is_empty() {
        return refuse("is empty");
    }
    if value.chars().count() > MAX_NAME_CHARACTERS {
        return refuse("is longer than 64 characters");
    }
    if value.chars().any(char::is_control) {
        return refuse("contains a control character");
    }
    Ok(Any::encode_from(&Utf8StringRef::new(value)?)?)
}

fn rdn(
    attribute: ObjectIdentifier,
    value: Any,
) -> Result<RelativeDistinguishedName, CertificateRequestError> {
    Ok(RelativeDistinguishedName(SetOfVec::try_from(vec![
        AttributeTypeAndValue {
            oid: attribute,
            value,
        },
    ])?))
}

/// The `SubjectPublicKeyInfo` of a seal key's public JWK: id-ecPublicKey with
/// its named curve and the uncompressed point (RFC 5480 section 2), or
/// rsaEncryption with NULL parameters and the PKCS #1 `RSAPublicKey` (RFC
/// 3279 section 2.3.1).
fn public_key_info(
    jwk: &PublicJwk,
    profile: &RequestProfile,
) -> Result<SubjectPublicKeyInfoOwned, CertificateRequestError> {
    let invalid = CertificateRequestError::InvalidKey;
    match profile.ecdsa {
        Some((curve, width)) => {
            let x = decode_fixed(jwk.x.as_deref(), width, "x").map_err(invalid)?;
            let y = decode_fixed(jwk.y.as_deref(), width, "y").map_err(invalid)?;
            let point = [&[0x04][..], &x, &y].concat();
            Ok(SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: oid::EC_PUBLIC_KEY,
                    parameters: Some(Any::encode_from(&curve)?),
                },
                subject_public_key: BitString::from_bytes(&point)?,
            })
        }
        None => {
            let n = decode_nonempty(jwk.n.as_deref(), "n").map_err(invalid)?;
            let e = decode_nonempty(jwk.e.as_deref(), "e").map_err(invalid)?;
            let key = pkcs1::RsaPublicKey {
                modulus: Pkcs1UintRef::new(&n)?,
                public_exponent: Pkcs1UintRef::new(&e)?,
            }
            .to_der()?;
            Ok(SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: oid::RSA_ENCRYPTION,
                    parameters: Some(Any::null()),
                },
                subject_public_key: BitString::from_bytes(&key)?,
            })
        }
    }
}
