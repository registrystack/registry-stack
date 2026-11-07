// SPDX-License-Identifier: Apache-2.0
//! `CertifiedSigner` construction and exposure.

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use registry_platform_crypto::{PublicJwk, SigningAlgorithm, SigningError, SigningProvider};
use registry_platform_x509::{x509_hash, CertifiedSigner, X509Error, X5cChain};
use std::sync::Arc;

struct StubSigner {
    jwk: PublicJwk,
    alg: SigningAlgorithm,
}

#[async_trait]
impl SigningProvider for StubSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.alg
    }
    fn key_id(&self) -> &str {
        "stub-kid"
    }
    fn public_jwk(&self) -> PublicJwk {
        self.jwk.clone()
    }
    async fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        Err(SigningError::external("stub"))
    }
}

fn p256_signer(key: &KeyPair) -> StubSigner {
    let raw = key.public_key_raw();
    StubSigner {
        alg: SigningAlgorithm::Es256,
        jwk: PublicJwk {
            kty: "EC".into(),
            kid: Some("stub-kid".into()),
            alg: Some("ES256".into()),
            crv: Some("P-256".into()),
            x: Some(URL_SAFE_NO_PAD.encode(&raw[1..33])),
            y: Some(URL_SAFE_NO_PAD.encode(&raw[33..65])),
            n: None,
            e: None,
        },
    }
}

fn cert_for(key: &KeyPair) -> rcgen::Certificate {
    CertificateParams::new(vec!["issuer.example".into()])
        .unwrap()
        .self_signed(key)
        .unwrap()
}

#[test]
fn matching_chain_is_accepted_and_exposes_x5c_and_hash() {
    let key = KeyPair::generate().unwrap();
    let cert = cert_for(&key);
    let chain = X5cChain::parse(&[B64.encode(cert.der())]).unwrap();
    let signer = CertifiedSigner::new(Arc::new(p256_signer(&key)), chain).unwrap();
    assert_eq!(signer.x5c(), vec![B64.encode(cert.der())]);
    assert_eq!(signer.x509_hash(), x509_hash(cert.der()));
    assert_eq!(signer.signer().key_id(), "stub-kid");
}

#[test]
fn mismatched_chain_is_refused() {
    let signing_key = KeyPair::generate().unwrap();
    let other_key = KeyPair::generate().unwrap();
    let chain = X5cChain::parse(&[B64.encode(cert_for(&other_key).der())]).unwrap();
    let e = CertifiedSigner::new(Arc::new(p256_signer(&signing_key)), chain).unwrap_err();
    assert_eq!(e, X509Error::SignerKeyMismatch);
}

#[test]
fn key_type_mismatch_is_refused() {
    let signing_key = KeyPair::generate().unwrap();
    let ed = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let chain = X5cChain::parse(&[B64.encode(cert_for(&ed).der())]).unwrap();
    let e = CertifiedSigner::new(Arc::new(p256_signer(&signing_key)), chain).unwrap_err();
    assert_eq!(e, X509Error::SignerKeyMismatch);
}

#[test]
fn debug_output_names_no_key_material_or_certificate_bytes() {
    let key = KeyPair::generate().unwrap();
    let cert = cert_for(&key);
    let chain = X5cChain::parse(&[B64.encode(cert.der())]).unwrap();
    let signer = CertifiedSigner::new(Arc::new(p256_signer(&key)), chain).unwrap();
    let shown = format!("{signer:?}");
    let raw = key.public_key_raw();
    assert!(!shown.contains(&URL_SAFE_NO_PAD.encode(&raw[1..33])));
    assert!(!shown.contains(&B64.encode(cert.der())[..40]));
    assert!(shown.contains("CertifiedSigner"));
}
