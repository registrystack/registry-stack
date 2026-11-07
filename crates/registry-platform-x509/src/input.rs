// SPDX-License-Identifier: Apache-2.0
//! Bounded parsing of an `x5c` header value and of operator-supplied trust anchors.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::X509Error;

/// Most certificates an `x5c` chain may hold.
pub const MAX_X5C_CERTS: usize = 8;
/// Largest accepted DER certificate.
pub const MAX_CERT_DER_LEN: usize = 16 * 1024;
/// Most configured trust anchors.
pub const MAX_TRUST_ANCHORS: usize = 64;
/// Largest accepted PEM bundle.
pub const MAX_PEM_LEN: usize = 1024 * 1024;

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_BEGIN_CERT: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END_CERT: &str = "-----END CERTIFICATE-----";
const ANCHOR_SET_DOMAIN: &[u8] = b"registry-platform-x509/trust-anchors/v1\0";

pub(crate) fn parse_certificate(der: &[u8]) -> Result<Certificate, X509Error> {
    if der.len() > MAX_CERT_DER_LEN {
        return Err(X509Error::CertificateTooLarge);
    }
    Certificate::from_der(der).map_err(|_| X509Error::BadCertificate)
}

/// Splits a PEM bundle into DER certificates, keeping each certificate's exact bytes. Text
/// outside PEM blocks is ignored; a block that is not a certificate is refused.
fn pem_certificates(pem: &[u8], max: usize) -> Result<Vec<Vec<u8>>, X509Error> {
    if pem.len() > MAX_PEM_LEN {
        return Err(X509Error::PemTooLarge);
    }
    let text = std::str::from_utf8(pem).map_err(|_| X509Error::BadPem)?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(PEM_BEGIN) {
        rest = &rest[start..];
        if !rest.starts_with(PEM_BEGIN_CERT) {
            return Err(X509Error::BadPem);
        }
        let end = rest.find(PEM_END_CERT).ok_or(X509Error::BadPem)? + PEM_END_CERT.len();
        let (_, der) =
            der::pem::decode_vec(&rest.as_bytes()[..end]).map_err(|_| X509Error::BadPem)?;
        if out.len() == max {
            return Err(X509Error::TooManyCertificates);
        }
        out.push(der);
        rest = &rest[end..];
    }
    Ok(out)
}

/// A JOSE `x5c` certificate chain, leaf first. Every certificate parsed as DER within bounds.
#[derive(Clone, PartialEq, Eq)]
pub struct X5cChain {
    ders: Vec<Vec<u8>>,
}

impl X5cChain {
    /// Parses the JOSE `x5c` value: standard base64 DER strings, leaf first.
    pub fn parse<S: AsRef<str>>(x5c: &[S]) -> Result<Self, X509Error> {
        if x5c.is_empty() {
            return Err(X509Error::EmptyChain);
        }
        if x5c.len() > MAX_X5C_CERTS {
            return Err(X509Error::TooManyCertificates);
        }
        let max_encoded = MAX_CERT_DER_LEN.div_ceil(3) * 4;
        let ders = x5c
            .iter()
            .map(|entry| {
                let entry = entry.as_ref();
                if entry.len() > max_encoded {
                    return Err(X509Error::CertificateTooLarge);
                }
                let der = STANDARD.decode(entry).map_err(|_| X509Error::BadEncoding)?;
                parse_certificate(&der)?;
                Ok(der)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { ders })
    }

    /// Parses a PEM bundle of certificates, leaf first, as a service operator loads it.
    pub fn from_pem(pem: &[u8]) -> Result<Self, X509Error> {
        let ders = pem_certificates(pem, MAX_X5C_CERTS)?;
        if ders.is_empty() {
            return Err(X509Error::EmptyChain);
        }
        for der in &ders {
            parse_certificate(der)?;
        }
        Ok(Self { ders })
    }

    /// The `x5c` header value: standard base64 DER, leaf first.
    #[must_use]
    pub fn to_x5c(&self) -> Vec<String> {
        self.ders.iter().map(|d| STANDARD.encode(d)).collect()
    }

    /// DER of the leaf certificate.
    #[must_use]
    pub fn leaf_der(&self) -> &[u8] {
        &self.ders[0]
    }

    pub(crate) fn ders(&self) -> &[Vec<u8>] {
        &self.ders
    }

    /// Number of certificates, at least one.
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ders.len()
    }
}

impl std::fmt::Debug for X5cChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X5cChain")
            .field("certificates", &self.ders.len())
            .finish()
    }
}

/// Operator-configured trust anchors. A chain only ever leads to one of these.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustAnchors {
    ders: Vec<Vec<u8>>,
    digest: String,
}

impl TrustAnchors {
    /// Builds the set from DER certificates the caller loaded.
    pub fn from_der_certificates(ders: &[Vec<u8>]) -> Result<Self, X509Error> {
        if ders.is_empty() {
            return Err(X509Error::NoTrustAnchors);
        }
        if ders.len() > MAX_TRUST_ANCHORS {
            return Err(X509Error::TooManyTrustAnchors);
        }
        let mut digests = Vec::with_capacity(ders.len());
        for der in ders {
            parse_certificate(der)?;
            let cert = rustls_pki_types::CertificateDer::from(der.as_slice());
            webpki::anchor_from_trusted_cert(&cert).map_err(|_| X509Error::UnusableTrustAnchor)?;
            digests.push(Sha256::digest(der));
        }
        // Sorted so the digest does not depend on load order.
        digests.sort();
        let mut hasher = Sha256::new();
        hasher.update(ANCHOR_SET_DOMAIN);
        for d in &digests {
            hasher.update(d);
        }
        Ok(Self {
            ders: ders.to_vec(),
            digest: URL_SAFE_NO_PAD.encode(hasher.finalize()),
        })
    }

    /// Builds the set from a PEM bundle the caller loaded.
    pub fn from_pem(pem: &[u8]) -> Result<Self, X509Error> {
        Self::from_der_certificates(&pem_certificates(pem, MAX_TRUST_ANCHORS)?)
    }

    /// Stable, order-independent digest of the anchor set (base64url, no padding), for logging
    /// which set was used.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Number of anchors, at least one.
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.ders.len()
    }

    pub(crate) fn ders(&self) -> &[Vec<u8>] {
        &self.ders
    }
}

impl std::fmt::Debug for TrustAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustAnchors")
            .field("anchors", &self.ders.len())
            .field("digest", &self.digest)
            .finish()
    }
}
