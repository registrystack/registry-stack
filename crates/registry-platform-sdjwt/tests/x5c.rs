// SPDX-License-Identifier: Apache-2.0
//! Issuer `x5c` header from a certificate-backed signer.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rcgen::{CertificateParams, KeyPair};
use registry_platform_crypto::PrivateJwk;
use registry_platform_sdjwt::{SdJwtIssuanceInput, SdJwtIssuer};
use registry_platform_x509::{CertifiedSigner, X5cChain};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

const ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;

/// PKCS#8 v1 wrapper for a raw Ed25519 seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn input() -> SdJwtIssuanceInput {
    SdJwtIssuanceInput {
        iss: "https://issuer.test".to_string(),
        sub_ref: "subject".to_string(),
        credential_id: None,
        iat: 1_800_000_000,
        exp: 1_800_003_600,
        vct: "https://issuer.test/vct".to_string(),
        status: None,
        public_claims: BTreeMap::new(),
        cnf: None,
        disclosures: Vec::new(),
        object_disclosures: Vec::new(),
    }
}

fn header(jwt: &str) -> (String, Value) {
    let segment = jwt.split('.').next().expect("header segment");
    let value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("base64url")).expect("json");
    (segment.to_string(), value)
}

fn certified_signer() -> CertifiedSigner {
    let jwk = PrivateJwk::parse(ISSUER_JWK).expect("jwk");
    let seed = URL_SAFE_NO_PAD
        .decode(jwk.d.as_deref().expect("private scalar"))
        .expect("seed");
    let der = [ED25519_PKCS8_PREFIX.as_slice(), seed.as_slice()].concat();
    let key = KeyPair::try_from(der.as_slice()).expect("rcgen key");
    let cert = CertificateParams::new(vec!["issuer.test".to_string()])
        .expect("params")
        .self_signed(&key)
        .expect("certificate");
    let chain = X5cChain::parse(&[STANDARD.encode(cert.der())]).expect("chain");
    let signer = registry_platform_crypto::LocalJwkSigner::new(jwk).expect("signer");
    CertifiedSigner::new(Arc::new(signer), chain).expect("certified signer")
}

#[tokio::test]
async fn certified_signer_puts_the_chain_in_the_x5c_header() {
    let certified = certified_signer();
    let expected = certified.x5c();
    let issuer = SdJwtIssuer::from_certified_signer(certified);
    let signed = issuer.issue(input()).await.expect("issues");
    let (_, header) = header(&signed.jwt);
    assert_eq!(header["x5c"], json!(expected));
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "dc+sd-jwt");
    assert_eq!(header["kid"], "did:web:issuer.test#key-1");
}

#[tokio::test]
async fn plain_constructors_emit_no_x5c_and_the_historical_header_bytes() {
    let expected_header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "dc+sd-jwt",
            "kid": "did:web:issuer.test#key-1",
        }))
        .expect("json"),
    );
    let issuer =
        SdJwtIssuer::from_jwk(PrivateJwk::parse(ISSUER_JWK).expect("jwk")).expect("issuer");
    let signed = issuer.issue(input()).await.expect("issues");
    let (segment, header) = header(&signed.jwt);
    assert!(header.get("x5c").is_none());
    assert_eq!(segment, expected_header);

    let compact = issuer
        .sign_compact_jwt("status-list+jwt", json!({"sub": "x"}))
        .await
        .expect("signs");
    let (_, header) = header_of(&compact);
    assert!(header.get("x5c").is_none());
}

fn header_of(jwt: &str) -> (String, Value) {
    header(jwt)
}
