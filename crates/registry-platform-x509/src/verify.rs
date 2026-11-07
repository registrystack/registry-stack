// SPDX-License-Identifier: Apache-2.0
//! Chain verification against configured trust anchors.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use der::asn1::ObjectIdentifier;
use registry_platform_crypto::PublicJwk;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use std::time::Duration;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
use x509_cert::Certificate;

use crate::input::{parse_certificate, TrustAnchors, X5cChain};
use crate::X509Error;

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const MAX_SUBJECT_CHARS: usize = 256;

/// Leaf public key types the policy can allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKeyType {
    /// ECDSA over P-256, for ES256.
    P256,
    /// Ed25519, for EdDSA.
    Ed25519,
}

/// What a chain must satisfy beyond reaching a configured anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPolicy {
    /// Most intermediate CA certificates allowed on the verified path between the leaf and the
    /// trust anchor. A configured anchor the chain also ships does not count.
    pub max_path_length: u8,
    /// Leaf key types accepted.
    pub allowed_leaf_key_types: Vec<LeafKeyType>,
}

impl Default for ChainPolicy {
    /// At most one intermediate; P-256 and Ed25519 leaf keys. The leaf must always carry a
    /// KeyUsage extension with digitalSignature.
    fn default() -> Self {
        Self {
            max_path_length: 1,
            allowed_leaf_key_types: vec![LeafKeyType::P256, LeafKeyType::Ed25519],
        }
    }
}

/// The result of a successful chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLeaf {
    /// Leaf public key, for verifying a JWS signature.
    pub public_jwk: PublicJwk,
    /// `dNSName` entries of the subjectAltName extension.
    pub san_dns_names: Vec<String>,
    /// `uniformResourceIdentifier` entries of the subjectAltName extension.
    pub san_uris: Vec<String>,
    /// RFC 4514 subject, control characters replaced and length bounded, for logs.
    pub subject: String,
    /// The `x509_hash` client identifier value of the leaf.
    pub x509_hash: String,
}

/// `base64url` (no padding) of SHA-256 over the leaf DER, as OpenID4VP 1.0 defines the
/// `x509_hash` client identifier.
#[must_use]
pub fn x509_hash(leaf_der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(leaf_der))
}

/// Accepts every extended key usage set, including none; the chain policy does not constrain EKU.
struct AnyExtendedKeyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyExtendedKeyUsage {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for id in iter {
            id?;
        }
        Ok(())
    }
}

fn map_webpki(err: webpki::Error) -> X509Error {
    match err {
        webpki::Error::CertExpired { .. } => X509Error::Expired,
        webpki::Error::CertNotValidYet { .. } => X509Error::NotYetValid,
        webpki::Error::UnknownIssuer => X509Error::UnknownIssuer,
        webpki::Error::CaUsedAsEndEntity => X509Error::CaAsLeaf,
        webpki::Error::PathLenConstraintViolated => X509Error::PathLengthExceeded,
        _ => X509Error::ChainRejected,
    }
}

/// Verifies `chain` at Unix time `now` (seconds). The chain must lead to one of the configured
/// `anchors`; a certificate the chain ships for itself never becomes an anchor.
pub fn verify_chain(
    chain: &X5cChain,
    anchors: &TrustAnchors,
    policy: &ChainPolicy,
    now: i64,
) -> Result<VerifiedLeaf, X509Error> {
    let secs = u64::try_from(now).map_err(|_| X509Error::InvalidTime)?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(secs));
    // Upper bound before any parsing: the intermediates plus one shipped anchor. The exact
    // count comes from the path that verification builds.
    if chain.len() - 1 > usize::from(policy.max_path_length) + 1 {
        return Err(X509Error::PathLengthExceeded);
    }

    let certs: Vec<CertificateDer<'_>> = chain
        .ders()
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let anchor_certs: Vec<CertificateDer<'_>> = anchors
        .ders()
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let trust_anchors = anchor_certs
        .iter()
        .map(|c| webpki::anchor_from_trusted_cert(c).map_err(|_| X509Error::UnusableTrustAnchor))
        .collect::<Result<Vec<_>, _>>()?;

    let leaf = webpki::EndEntityCert::try_from(&certs[0]).map_err(|_| X509Error::BadCertificate)?;
    let path = leaf
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &certs[1..],
            time,
            AnyExtendedKeyUsage,
            None,
            None,
        )
        .map_err(map_webpki)?;
    if path.intermediate_certificates().count() > usize::from(policy.max_path_length) {
        return Err(X509Error::PathLengthExceeded);
    }

    let parsed = parse_certificate(chain.leaf_der())?;
    check_leaf_extensions(&parsed)?;
    let (public_jwk, key_type) = leaf_public_jwk(&parsed)?;
    if !policy.allowed_leaf_key_types.contains(&key_type) {
        return Err(X509Error::LeafKeyTypeNotAllowed);
    }
    Ok(VerifiedLeaf {
        public_jwk,
        san_dns_names: san_names(&parsed, |name| match name {
            GeneralName::DnsName(dns) => Some(dns.as_str().to_owned()),
            _ => None,
        })?,
        san_uris: san_names(&parsed, |name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_owned()),
            _ => None,
        })?,
        subject: printable_subject(&parsed),
        x509_hash: x509_hash(chain.leaf_der()),
    })
}

/// webpki ignores KeyUsage; the leaf must carry it with digitalSignature. A leaf asserting
/// cA is refused here as well, independent of the path builder.
fn check_leaf_extensions(leaf: &Certificate) -> Result<(), X509Error> {
    let tbs = &leaf.tbs_certificate;
    let basic = tbs
        .get::<BasicConstraints>()
        .map_err(|_| X509Error::BadCertificate)?;
    if basic.is_some_and(|(_, bc)| bc.ca) {
        return Err(X509Error::CaAsLeaf);
    }
    let usage = tbs
        .get::<KeyUsage>()
        .map_err(|_| X509Error::BadCertificate)?
        .ok_or(X509Error::KeyUsage)?;
    if !usage.1 .0.contains(KeyUsages::DigitalSignature) {
        return Err(X509Error::KeyUsage);
    }
    Ok(())
}

/// The certificate's public key as a JWK, for the key types this crate supports.
pub(crate) fn leaf_public_jwk(cert: &Certificate) -> Result<(PublicJwk, LeafKeyType), X509Error> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(X509Error::UnsupportedLeafKey)?;
    let enc = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    let (json, key_type) = if spki.algorithm.oid == OID_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            == Some(OID_P256)
    {
        // Uncompressed point: 0x04 || X || Y.
        if key.len() != 65 || key[0] != 0x04 {
            return Err(X509Error::UnsupportedLeafKey);
        }
        (
            serde_json::json!({
                "kty": "EC", "crv": "P-256", "alg": "ES256",
                "x": enc(&key[1..33]), "y": enc(&key[33..65]),
            }),
            LeafKeyType::P256,
        )
    } else if spki.algorithm.oid == OID_ED25519 && spki.algorithm.parameters.is_none() {
        if key.len() != 32 {
            return Err(X509Error::UnsupportedLeafKey);
        }
        (
            serde_json::json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": enc(key)}),
            LeafKeyType::Ed25519,
        )
    } else {
        return Err(X509Error::UnsupportedLeafKey);
    };
    let jwk = PublicJwk::parse(&json.to_string()).map_err(|_| X509Error::UnsupportedLeafKey)?;
    Ok((jwk, key_type))
}

fn san_names(
    cert: &Certificate,
    select: impl Fn(GeneralName) -> Option<String>,
) -> Result<Vec<String>, X509Error> {
    let san = cert
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|_| X509Error::BadCertificate)?;
    Ok(san
        .into_iter()
        .flat_map(|(_, san)| san.0)
        .filter_map(select)
        .collect())
}

fn printable_subject(cert: &Certificate) -> String {
    cert.tbs_certificate
        .subject
        .to_string()
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_SUBJECT_CHARS)
        .collect()
}
