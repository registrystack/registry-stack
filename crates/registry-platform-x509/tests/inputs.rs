// SPDX-License-Identifier: Apache-2.0
//! Input bounds and parsing for `X5cChain` and `TrustAnchors`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rcgen::{CertificateParams, KeyPair};
use registry_platform_x509::{
    TrustAnchors, X509Error, X5cChain, MAX_CERT_DER_LEN, MAX_TRUST_ANCHORS, MAX_X5C_CERTS,
};

fn pem(cert: &rcgen::Certificate) -> String {
    let b64 = B64.encode(cert.der());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

fn self_signed(cn: &str) -> rcgen::Certificate {
    let params = CertificateParams::new(vec![format!("{cn}.example")]).unwrap();
    params.self_signed(&KeyPair::generate().unwrap()).unwrap()
}

#[test]
fn empty_x5c_is_refused() {
    let none: [String; 0] = [];
    assert_eq!(X5cChain::parse(&none).unwrap_err(), X509Error::EmptyChain);
}

#[test]
fn too_many_certificates_are_refused() {
    let c = B64.encode(self_signed("a").der());
    let many = vec![c; MAX_X5C_CERTS + 1];
    assert_eq!(
        X5cChain::parse(&many).unwrap_err(),
        X509Error::TooManyCertificates
    );
    let ok = vec![B64.encode(self_signed("a").der()); MAX_X5C_CERTS];
    assert_eq!(X5cChain::parse(&ok).unwrap().len(), MAX_X5C_CERTS);
}

#[test]
fn oversized_certificate_is_refused_before_decoding() {
    let huge = "A".repeat(MAX_CERT_DER_LEN * 2);
    assert_eq!(
        X5cChain::parse(&[huge]).unwrap_err(),
        X509Error::CertificateTooLarge
    );
    let der = vec![0x30u8; MAX_CERT_DER_LEN + 1];
    assert_eq!(
        X5cChain::parse(&[B64.encode(der)]).unwrap_err(),
        X509Error::CertificateTooLarge
    );
}

#[test]
fn bad_base64_is_refused() {
    assert_eq!(
        X5cChain::parse(&["not base64!!".to_string()]).unwrap_err(),
        X509Error::BadEncoding
    );
    // base64url is not standard base64.
    let url = B64
        .encode([0xfbu8, 0xff, 0xfe])
        .replace('+', "-")
        .replace('/', "_");
    assert_eq!(X5cChain::parse(&[url]).unwrap_err(), X509Error::BadEncoding);
}

#[test]
fn non_certificate_der_is_refused() {
    assert_eq!(
        X5cChain::parse(&[B64.encode(b"hello")]).unwrap_err(),
        X509Error::BadCertificate
    );
}

#[test]
fn header_value_round_trips() {
    let a = B64.encode(self_signed("a").der());
    let b = B64.encode(self_signed("b").der());
    let chain = X5cChain::parse(&[a.clone(), b.clone()]).unwrap();
    assert_eq!(chain.to_x5c(), vec![a, b]);
}

#[test]
fn chain_from_pem_keeps_exact_der() {
    let a = self_signed("a");
    let b = self_signed("b");
    let pem = format!("{}{}", pem(&a), pem(&b));
    let chain = X5cChain::from_pem(pem.as_bytes()).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain.leaf_der(), a.der().as_ref());
}

#[test]
fn anchors_from_pem_bundle_and_der_agree() {
    let a = self_signed("a");
    let b = self_signed("b");
    let from_pem = TrustAnchors::from_pem(format!("{}{}", pem(&a), pem(&b)).as_bytes()).unwrap();
    let from_der =
        TrustAnchors::from_der_certificates(&[b.der().to_vec(), a.der().to_vec()]).unwrap();
    assert_eq!(from_pem.len(), 2);
    assert_eq!(from_pem.digest(), from_der.digest());
}

#[test]
fn anchor_digest_is_stable_and_set_specific() {
    let a = self_signed("a");
    let b = self_signed("b");
    let one = TrustAnchors::from_der_certificates(&[a.der().to_vec()]).unwrap();
    let both = TrustAnchors::from_der_certificates(&[a.der().to_vec(), b.der().to_vec()]).unwrap();
    assert_ne!(one.digest(), both.digest());
    assert_eq!(one.digest().len(), 43);
    assert_eq!(
        one.digest(),
        TrustAnchors::from_der_certificates(&[a.der().to_vec()])
            .unwrap()
            .digest()
    );
}

#[test]
fn empty_and_garbage_anchor_sets_are_refused() {
    assert_eq!(
        TrustAnchors::from_der_certificates(&[]).unwrap_err(),
        X509Error::NoTrustAnchors
    );
    assert_eq!(
        TrustAnchors::from_pem(b"").unwrap_err(),
        X509Error::NoTrustAnchors
    );
    assert_eq!(
        TrustAnchors::from_der_certificates(&[b"junk".to_vec()]).unwrap_err(),
        X509Error::BadCertificate
    );
    assert_eq!(
        TrustAnchors::from_pem(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")
            .unwrap_err(),
        X509Error::BadPem
    );
}

#[test]
fn anchor_count_and_size_are_bounded() {
    let c = self_signed("a").der().to_vec();
    let many = vec![c; MAX_TRUST_ANCHORS + 1];
    assert_eq!(
        TrustAnchors::from_der_certificates(&many).unwrap_err(),
        X509Error::TooManyTrustAnchors
    );
    let big = vec![0x30u8; MAX_CERT_DER_LEN + 1];
    assert_eq!(
        TrustAnchors::from_der_certificates(&[big]).unwrap_err(),
        X509Error::CertificateTooLarge
    );
    let huge_pem = vec![b'A'; 4 * 1024 * 1024];
    assert_eq!(
        TrustAnchors::from_pem(&huge_pem).unwrap_err(),
        X509Error::PemTooLarge
    );
}

#[test]
fn pem_block_that_is_not_a_certificate_is_refused() {
    let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    assert_eq!(
        TrustAnchors::from_pem(pem.as_bytes()).unwrap_err(),
        X509Error::BadPem
    );
    assert_eq!(
        X5cChain::from_pem(pem.as_bytes()).unwrap_err(),
        X509Error::BadPem
    );
}
