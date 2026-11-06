// SPDX-License-Identifier: Apache-2.0
//! Seal certificate chains: PEM loading, chain order, and the checks a signer
//! makes before it signs under a certificate.

use super::asn1::oid;
use crate::{decode_fixed, decode_nonempty, PublicJwk, SigningAlgorithm};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use der::asn1::ObjectIdentifier;
use der::{Decode as _, Tag, Tagged as _};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use x509_cert::ext::pkix::KeyUsage;
use x509_cert::name::Name;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Time as X509Time;
use x509_cert::Certificate;

/// SHA-256 over a certificate's DER encoding: the only certificate value this
/// module prints, in errors, audit records and logs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    pub(super) fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// The 32 digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hexadecimal, 64 characters.
impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateFingerprint({self})")
    }
}

/// Why a certificate chain was refused, or why its leaf may not sign.
///
/// Positions count PEM blocks or certificates from 1, the leaf. No variant
/// carries certificate or key contents; leaf checks name the leaf's
/// fingerprint, because a subject can carry personal data.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertificateError {
    #[error("the certificate chain holds no PEM certificate")]
    Empty,
    #[error("PEM block {position} is malformed")]
    MalformedPem { position: usize },
    #[error("PEM block {position} is not a CERTIFICATE")]
    NotACertificate { position: usize },
    #[error("certificate {position} is not a DER X.509 certificate")]
    MalformedCertificate { position: usize },
    #[error("certificate {position} appears earlier in the chain")]
    DuplicateCertificate { position: usize },
    #[error(
        "certificate {position} was not issued by the certificate after it; list the leaf first, then each issuer in turn"
    )]
    ChainOutOfOrder { position: usize },
    #[error("seal certificate {fingerprint} does not hold the signing key's public key")]
    KeyMismatch { fingerprint: CertificateFingerprint },
    #[error("seal certificate {fingerprint} has neither the digitalSignature nor the nonRepudiation key usage")]
    MissingSigningKeyUsage { fingerprint: CertificateFingerprint },
    #[error("seal certificate {fingerprint} is not yet valid at the signing time")]
    NotYetValid { fingerprint: CertificateFingerprint },
    #[error("seal certificate {fingerprint} has expired at the signing time")]
    Expired { fingerprint: CertificateFingerprint },
    #[error("seal certificate {fingerprint}: documents are signed with ECDSA P-256, ECDSA P-384 or RSA keys only")]
    UnsupportedKey { fingerprint: CertificateFingerprint },
}

/// A seal certificate followed by the intermediates that issued it, in order.
#[derive(Clone)]
pub struct CertificateChain {
    certificates: Vec<ChainCertificate>,
    display_name: Option<String>,
}

#[derive(Clone)]
pub(super) struct ChainCertificate {
    pub(super) der: Vec<u8>,
    pub(super) parsed: Certificate,
}

impl fmt::Debug for CertificateChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateChain")
            .field("leaf", &self.leaf_sha256_fingerprint())
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl CertificateChain {
    /// Read PEM `CERTIFICATE` blocks: the leaf first, then each issuer in
    /// turn. Text outside the blocks is ignored. Refuses input with no
    /// certificate, any other PEM block (a private key included), a block that
    /// is not a DER X.509 certificate, a repeated certificate, and a chain
    /// whose issuer and subject names do not link each certificate to the
    /// next.
    pub fn from_pem(pem: &[u8]) -> Result<Self, CertificateError> {
        let blocks = pem_certificate_blocks(pem)?;
        if blocks.is_empty() {
            return Err(CertificateError::Empty);
        }
        let mut seen = HashSet::new();
        let mut certificates = Vec::with_capacity(blocks.len());
        for (index, der) in blocks.into_iter().enumerate() {
            let position = index + 1;
            let parsed = Certificate::from_der(&der)
                .map_err(|_| CertificateError::MalformedCertificate { position })?;
            if !seen.insert(CertificateFingerprint::of(&der)) {
                return Err(CertificateError::DuplicateCertificate { position });
            }
            certificates.push(ChainCertificate { der, parsed });
        }
        for (index, pair) in certificates.windows(2).enumerate() {
            if pair[0].parsed.tbs_certificate.issuer != pair[1].parsed.tbs_certificate.subject {
                return Err(CertificateError::ChainOutOfOrder {
                    position: index + 1,
                });
            }
        }
        let display_name = display_name(&certificates[0].parsed.tbs_certificate.subject);
        Ok(Self {
            certificates,
            display_name,
        })
    }

    /// The seal certificate, DER encoded.
    #[must_use]
    pub fn leaf_der(&self) -> &[u8] {
        &self.leaf().der
    }

    /// The DER size of every certificate in the chain, together: what the
    /// chain adds to a signature's `certificates`. A caller reserving space
    /// for the signature in a document sizes it from this.
    #[must_use]
    pub fn der_len(&self) -> usize {
        self.certificates
            .iter()
            .map(|certificate| certificate.der.len())
            .sum()
    }

    /// SHA-256 over the seal certificate's DER encoding.
    #[must_use]
    pub fn leaf_sha256_fingerprint(&self) -> CertificateFingerprint {
        CertificateFingerprint::of(&self.leaf().der)
    }

    /// The first instant the seal certificate is valid.
    #[must_use]
    pub fn not_before(&self) -> OffsetDateTime {
        x509_time(self.leaf().parsed.tbs_certificate.validity.not_before)
    }

    /// The last instant the seal certificate is valid.
    #[must_use]
    pub fn not_after(&self) -> OffsetDateTime {
        x509_time(self.leaf().parsed.tbs_certificate.validity.not_after)
    }

    /// The name to print on a sealed document: the seal certificate subject's
    /// organization, else its common name, else none.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Check that the seal certificate may sign for `public_jwk` at `at`: it
    /// holds exactly that public key, it carries the digitalSignature or
    /// nonRepudiation key usage, and `at` lies within its validity, both
    /// bounds included. Revocation and trust in the issuer are not checked.
    pub fn check_for_signing(
        &self,
        public_jwk: &PublicJwk,
        at: OffsetDateTime,
    ) -> Result<(), CertificateError> {
        self.check_key(public_jwk)?;
        let fingerprint = self.leaf_sha256_fingerprint();
        if !self.leaf_may_sign()? {
            return Err(CertificateError::MissingSigningKeyUsage { fingerprint });
        }
        if at < self.not_before() {
            return Err(CertificateError::NotYetValid { fingerprint });
        }
        if at > self.not_after() {
            return Err(CertificateError::Expired { fingerprint });
        }
        Ok(())
    }

    /// Refuse a provider key the seal certificate does not hold.
    fn check_key(&self, public_jwk: &PublicJwk) -> Result<(), CertificateError> {
        let fingerprint = self.leaf_sha256_fingerprint();
        let spki = &self.leaf().parsed.tbs_certificate.subject_public_key_info;
        match spki_matches_jwk(spki, public_jwk) {
            KeyComparison::Match => Ok(()),
            KeyComparison::Mismatch => Err(CertificateError::KeyMismatch { fingerprint }),
            KeyComparison::Unsupported => Err(CertificateError::UnsupportedKey { fingerprint }),
        }
    }

    pub(super) fn leaf(&self) -> &ChainCertificate {
        &self.certificates[0]
    }

    pub(super) fn certificates(&self) -> &[ChainCertificate] {
        &self.certificates
    }

    fn leaf_may_sign(&self) -> Result<bool, CertificateError> {
        let fingerprint = self.leaf_sha256_fingerprint();
        let Some(extension) = self
            .leaf()
            .parsed
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|extension| extension.extn_id == oid::KEY_USAGE)
        else {
            return Ok(false);
        };
        let usage = KeyUsage::from_der(extension.extn_value.as_bytes())
            .map_err(|_| CertificateError::MissingSigningKeyUsage { fingerprint })?;
        Ok(usage.digital_signature() || usage.non_repudiation())
    }
}

enum KeyComparison {
    Match,
    Mismatch,
    Unsupported,
}

fn spki_matches_jwk(spki: &SubjectPublicKeyInfoOwned, jwk: &PublicJwk) -> KeyComparison {
    let Ok(algorithm) = jwk.validate_public().and_then(|()| jwk.algorithm()) else {
        return KeyComparison::Unsupported;
    };
    let Some(certificate_key) = spki.subject_public_key.as_bytes() else {
        return KeyComparison::Mismatch;
    };
    let matches = match algorithm {
        SigningAlgorithm::Es256 | SigningAlgorithm::Es384 => {
            let (curve, width) = if algorithm == SigningAlgorithm::Es256 {
                (oid::SECP256R1, 32)
            } else {
                (oid::SECP384R1, 48)
            };
            let (Ok(x), Ok(y)) = (
                decode_fixed(jwk.x.as_deref(), width, "x"),
                decode_fixed(jwk.y.as_deref(), width, "y"),
            ) else {
                return KeyComparison::Unsupported;
            };
            let named_curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
            spki.algorithm.oid == oid::EC_PUBLIC_KEY
                && named_curve == Some(curve)
                && certificate_key.first() == Some(&0x04)
                && certificate_key[1..] == [x, y].concat()
        }
        SigningAlgorithm::Rs256 | SigningAlgorithm::Rs384 => {
            let (Ok(n), Ok(e)) = (
                decode_nonempty(jwk.n.as_deref(), "n"),
                decode_nonempty(jwk.e.as_deref(), "e"),
            ) else {
                return KeyComparison::Unsupported;
            };
            spki.algorithm.oid == oid::RSA_ENCRYPTION
                && pkcs1::RsaPublicKey::from_der(certificate_key).is_ok_and(|key| {
                    key.modulus.as_bytes() == strip_leading_zeros(&n)
                        && key.public_exponent.as_bytes() == strip_leading_zeros(&e)
                })
        }
        SigningAlgorithm::EdDsa => return KeyComparison::Unsupported,
    };
    if matches {
        KeyComparison::Match
    } else {
        KeyComparison::Mismatch
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

pub(super) fn x509_time(time: X509Time) -> OffsetDateTime {
    let seconds = i64::try_from(time.to_unix_duration().as_secs())
        .expect("X.509 times end in year 9999, inside i64 seconds");
    OffsetDateTime::from_unix_timestamp(seconds)
        .expect("X.509 times end in year 9999, inside OffsetDateTime")
}

/// The leaf subject's organization, else its common name. Later attributes
/// in a distinguished name are more specific, so the last match wins.
fn display_name(subject: &Name) -> Option<String> {
    let attribute = |wanted: ObjectIdentifier| {
        subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .filter(|attribute| attribute.oid == wanted)
            .filter_map(|attribute| directory_string(&attribute.value))
            .rfind(|value| !value.trim().is_empty())
    };
    attribute(oid::ORGANIZATION_NAME).or_else(|| attribute(oid::COMMON_NAME))
}

/// Decode an X.520 DirectoryString. Values with control characters are
/// treated as absent rather than printed on a document.
fn directory_string(value: &der::Any) -> Option<String> {
    let text = match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
            String::from_utf8(value.value().to_vec()).ok()?
        }
        Tag::BmpString => {
            let units: Vec<u16> = value
                .value()
                .chunks(2)
                .map(|pair| match pair {
                    [high, low] => Some(u16::from_be_bytes([*high, *low])),
                    _ => None,
                })
                .collect::<Option<_>>()?;
            String::from_utf16(&units).ok()?
        }
        _ => return None,
    };
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(text)
}

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_DASHES: &str = "-----";

/// Split PEM text into the DER bodies of its blocks, refusing any block that
/// is malformed or not labelled `CERTIFICATE`.
fn pem_certificate_blocks(pem: &[u8]) -> Result<Vec<Vec<u8>>, CertificateError> {
    let text =
        std::str::from_utf8(pem).map_err(|_| CertificateError::MalformedPem { position: 1 })?;
    let mut blocks = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix(PEM_BEGIN)
            .and_then(|rest| rest.strip_suffix(PEM_DASHES))
        else {
            continue;
        };
        let position = blocks.len() + 1;
        // Refuse another label before reading its body, so a private key
        // pasted into the chain is never copied.
        if label != "CERTIFICATE" {
            return Err(CertificateError::NotACertificate { position });
        }
        let malformed = CertificateError::MalformedPem { position };
        let mut body = String::new();
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end_label) = line
                .strip_prefix(PEM_END)
                .and_then(|rest| rest.strip_suffix(PEM_DASHES))
            {
                if end_label != label {
                    return Err(malformed);
                }
                ended = true;
                break;
            }
            // RFC 1421 encapsulated headers mark an encrypted or legacy block.
            if line.contains(':') || line.starts_with(PEM_BEGIN) {
                return Err(malformed);
            }
            body.push_str(line);
        }
        if !ended {
            return Err(malformed);
        }
        let der = STANDARD.decode(body.as_bytes()).map_err(|_| malformed)?;
        blocks.push(der);
    }
    Ok(blocks)
}
