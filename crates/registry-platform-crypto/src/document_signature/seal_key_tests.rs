// SPDX-License-Identifier: Apache-2.0
//! Seal keys and their certificate requests: generation, PKCS #8 import, the
//! forms import refuses, and PKCS #10 requests checked independently.

use super::asn1::oid;
use super::*;
use crate::{
    generate_private_jwk, GeneratedKeyAlgorithm, KeyReadiness, LocalJwkSigner, PrivateJwk,
    PublicJwk, SigningAlgorithm, SigningError, SigningProvider,
};
use async_trait::async_trait;
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair as AwsRsaKeyPair, KeySize as AwsRsaKeySize};
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair as _, UnparsedPublicKey, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cms::cert::x509::request::{CertReq, Version};
use der::asn1::ObjectIdentifier;
use der::pem::LineEnding;
use der::{Any, Decode as _, Encode as _, Tag, Tagged as _};

const SEAL_KEY_ALGORITHMS: [SigningAlgorithm; 4] = [
    SigningAlgorithm::Es256,
    SigningAlgorithm::Es384,
    SigningAlgorithm::Rs256,
    SigningAlgorithm::Rs384,
];

fn pem(label: &str, der: &[u8]) -> String {
    der::pem::encode_string(label, LineEnding::LF, der).expect("PEM")
}

/// A PKCS #8 key made by aws-lc-rs, the way `openssl genpkey` writes one, with
/// the public key that verifies its signatures.
struct ForeignKey {
    pem: String,
    public_key: Vec<u8>,
}

fn foreign_p256() -> ForeignKey {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &aws_lc_rs::rand::SystemRandom::new(),
    )
    .expect("P-256 key");
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).expect("P-256");
    ForeignKey {
        pem: pem("PRIVATE KEY", pkcs8.as_ref()),
        public_key: key.public_key().as_ref().to_vec(),
    }
}

fn foreign_p384() -> ForeignKey {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P384_SHA384_FIXED_SIGNING,
        &aws_lc_rs::rand::SystemRandom::new(),
    )
    .expect("P-384 key");
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref()).expect("P-384");
    ForeignKey {
        pem: pem("PRIVATE KEY", pkcs8.as_ref()),
        public_key: key.public_key().as_ref().to_vec(),
    }
}

fn foreign_rsa() -> ForeignKey {
    let key = AwsRsaKeyPair::generate(AwsRsaKeySize::Rsa2048).expect("RSA key");
    let pkcs8 = key.as_der().expect("PKCS #8");
    ForeignKey {
        pem: pem("PRIVATE KEY", pkcs8.as_ref()),
        public_key: key.public_key().as_ref().to_vec(),
    }
}

async fn signs_like(
    jwk: PrivateJwk,
    key: &ForeignKey,
    verification: &'static dyn VerificationAlgorithm,
) {
    let signer = LocalJwkSigner::new(jwk).expect("signer");
    let signature = signer.sign(b"seal key import").await.expect("signature");
    UnparsedPublicKey::new(verification, &key.public_key)
        .verify(b"seal key import", &signature)
        .expect("the imported key signs as the original");
}

// ----- Generation -----

#[test]
fn a_generated_seal_key_carries_its_algorithm_and_thumbprint() {
    for algorithm in SEAL_KEY_ALGORITHMS {
        let jwk = generate_seal_key(algorithm).expect("seal key");
        assert_eq!(jwk.algorithm().expect("algorithm"), algorithm);
        assert_eq!(jwk.kid, Some(jwk.public().jkt().expect("thumbprint")));
    }
}

#[test]
fn a_seal_key_file_holds_the_whole_private_jwk_on_one_line() {
    for algorithm in SEAL_KEY_ALGORITHMS {
        let jwk = generate_seal_key(algorithm).expect("seal key");
        let json = private_seal_key_json(&jwk).expect("key file");
        let text = std::str::from_utf8(&json).expect("UTF-8");
        assert!(
            text.ends_with("}\n") && text.lines().count() == 1,
            "{algorithm:?}"
        );
        let read = PrivateJwk::parse(text.trim()).expect("the file parses as a private JWK");
        assert_eq!(read.public(), jwk.public());
        assert_eq!(read.d, jwk.d);
        assert_eq!(
            (&read.p, &read.q, &read.dp, &read.dq, &read.qi),
            (&jwk.p, &jwk.q, &jwk.dp, &jwk.dq, &jwk.qi)
        );
        assert_eq!(read.algorithm().expect("algorithm"), algorithm);
    }
}

#[test]
fn a_seal_key_is_never_eddsa() {
    assert!(matches!(
        generate_seal_key(SigningAlgorithm::EdDsa),
        Err(SealKeyError::UnsupportedAlgorithm(SigningAlgorithm::EdDsa))
    ));
}

// ----- PKCS #8 import -----

#[tokio::test]
async fn pkcs8_keys_import_as_the_jwk_that_signs_like_them() {
    let p256 = foreign_p256();
    let jwk = seal_key_from_pkcs8_pem(p256.pem.as_bytes(), None).expect("P-256");
    assert_eq!(jwk.algorithm().expect("algorithm"), SigningAlgorithm::Es256);
    assert_eq!(jwk.kid, Some(jwk.public().jkt().expect("thumbprint")));
    signs_like(jwk, &p256, &ECDSA_P256_SHA256_FIXED).await;

    let p384 = foreign_p384();
    let jwk = seal_key_from_pkcs8_pem(p384.pem.as_bytes(), None).expect("P-384");
    assert_eq!(jwk.algorithm().expect("algorithm"), SigningAlgorithm::Es384);
    signs_like(jwk, &p384, &ECDSA_P384_SHA384_FIXED).await;

    let rsa = foreign_rsa();
    let jwk = seal_key_from_pkcs8_pem(rsa.pem.as_bytes(), None).expect("RSA");
    assert_eq!(jwk.algorithm().expect("algorithm"), SigningAlgorithm::Rs256);
    assert_eq!(jwk.kid, Some(jwk.public().jkt().expect("thumbprint")));
    signs_like(jwk, &rsa, &RSA_PKCS1_2048_8192_SHA256).await;
    let jwk = seal_key_from_pkcs8_pem(rsa.pem.as_bytes(), Some(SigningAlgorithm::Rs384))
        .expect("RSA as RS384");
    assert_eq!(jwk.algorithm().expect("algorithm"), SigningAlgorithm::Rs384);
    signs_like(jwk, &rsa, &RSA_PKCS1_2048_8192_SHA384).await;
}

#[test]
fn pkcs8_import_skips_explanatory_text_around_the_key() {
    // `openssl pkcs12 -nocerts -nodes` writes bag attributes before the key.
    let key = foreign_p256();
    let text = format!(
        "Bag Attributes\n    localKeyID: 01 02 03\nKey Attributes: <No Attributes>\n{}\n",
        key.pem.replace('\n', "\r\n")
    );
    assert!(seal_key_from_pkcs8_pem(text.as_bytes(), None).is_ok());
}

#[test]
fn pkcs8_import_refuses_an_algorithm_the_key_cannot_sign() {
    let p256 = foreign_p256();
    for requested in [SigningAlgorithm::Es384, SigningAlgorithm::Rs256] {
        let error =
            seal_key_from_pkcs8_pem(p256.pem.as_bytes(), Some(requested)).expect_err("mismatch");
        assert!(
            matches!(error, SealKeyError::AlgorithmMismatch { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("P-256"), "{error}");
        assert!(error.to_string().contains(requested.jwa_name()), "{error}");
    }
    let rsa = foreign_rsa();
    assert!(matches!(
        seal_key_from_pkcs8_pem(rsa.pem.as_bytes(), Some(SigningAlgorithm::Es256)),
        Err(SealKeyError::AlgorithmMismatch { .. })
    ));
}

#[test]
fn pkcs8_import_refuses_other_key_forms_without_reading_them() {
    // The bodies are never decoded, so a marker in one never reaches an error.
    let body = "U0VDUkVULUtFWS1NQVRFUklBTA==";
    let block = |label: &str| format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n");
    let cases = [
        (block("ENCRYPTED PRIVATE KEY"), "EncryptedPkcs8"),
        (block("EC PRIVATE KEY"), "Legacy"),
        (block("RSA PRIVATE KEY"), "Legacy"),
        (block("CERTIFICATE"), "NoPrivateKey"),
        (String::new(), "NoPrivateKey"),
        ("not a key\n".to_owned(), "NoPrivateKey"),
    ];
    for (text, expected) in cases {
        let error = seal_key_from_pkcs8_pem(text.as_bytes(), None).expect_err("refused");
        let matched = match &error {
            SealKeyError::EncryptedPkcs8 => "EncryptedPkcs8",
            SealKeyError::LegacyPem { .. } => "Legacy",
            SealKeyError::NoPrivateKey => "NoPrivateKey",
            other => panic!("unexpected refusal {other:?}"),
        };
        assert_eq!(matched, expected, "{text}");
        assert!(!error.to_string().contains(body));
        assert!(!format!("{error:?}").contains(body));
    }
    let legacy =
        seal_key_from_pkcs8_pem(block("EC PRIVATE KEY").as_bytes(), None).expect_err("refused");
    assert!(legacy.to_string().contains("SEC 1"), "{legacy}");
    let legacy =
        seal_key_from_pkcs8_pem(block("RSA PRIVATE KEY").as_bytes(), None).expect_err("refused");
    assert!(legacy.to_string().contains("PKCS #1"), "{legacy}");
}

#[test]
fn pkcs8_import_refuses_a_pkcs12_file() {
    // PFX ::= SEQUENCE { version INTEGER {v3(3)}, authSafe ContentInfo, ... }
    let pfx = [0x30, 0x05, 0x02, 0x01, 0x03, 0x30, 0x00];
    assert!(matches!(
        seal_key_from_pkcs8_pem(&pfx, None),
        Err(SealKeyError::Pkcs12)
    ));
}

#[test]
fn pkcs8_import_refuses_two_keys_a_bad_body_and_a_key_that_cannot_seal() {
    let first = foreign_p256();
    let second = foreign_p256();
    let two = format!("{}{}", first.pem, second.pem);
    assert!(matches!(
        seal_key_from_pkcs8_pem(two.as_bytes(), None),
        Err(SealKeyError::MultipleKeys)
    ));

    let unterminated = first.pem.replace("-----END PRIVATE KEY-----\n", "");
    let headers = first
        .pem
        .replacen("-----\n", "-----\nProc-Type: 4,ENCRYPTED\n", 1);
    let not_der = pem("PRIVATE KEY", b"not DER");
    for text in [unterminated, headers, not_der] {
        assert!(
            matches!(
                seal_key_from_pkcs8_pem(text.as_bytes(), None),
                Err(SealKeyError::Malformed)
            ),
            "{text}"
        );
    }

    let ed25519 =
        aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new())
            .expect("Ed25519 key");
    let error = seal_key_from_pkcs8_pem(pem("PRIVATE KEY", ed25519.as_ref()).as_bytes(), None)
        .expect_err("refused");
    assert!(matches!(error, SealKeyError::UnsupportedKey(_)), "{error}");
}

// ----- PKCS #10 certificate requests -----

fn subject(common_name: &str) -> CertificateRequestSubject {
    CertificateRequestSubject {
        common_name: common_name.to_owned(),
        organization: Some("Ministère de la Santé".to_owned()),
        country: Some("FR".to_owned()),
    }
}

fn decode_b64(value: Option<&str>) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.expect("member"))
        .expect("base64url")
}

/// Check a request the way a certificate authority does, with no code from
/// the module under test: the subject, the public key against the JWK, and
/// the signature over the encoded request information under that key.
fn check_request(request: &CertificateRequest, jwk: &PublicJwk, algorithm: SigningAlgorithm) {
    let decoded = CertReq::from_der(request.der()).expect("PKCS #10 DER");
    assert_eq!(decoded.info.version, Version::V1);
    assert!(decoded.info.attributes.is_empty());

    let rdns: Vec<(ObjectIdentifier, Tag, String)> = decoded
        .info
        .subject
        .0
        .iter()
        .map(|rdn| {
            assert_eq!(rdn.0.len(), 1, "one attribute per RDN");
            let attribute = rdn.0.get(0).expect("attribute");
            (
                attribute.oid,
                attribute.value.tag(),
                String::from_utf8(attribute.value.value().to_vec()).expect("text"),
            )
        })
        .collect();
    assert_eq!(
        rdns,
        [
            (oid::COUNTRY_NAME, Tag::PrintableString, "FR".to_owned()),
            (
                oid::ORGANIZATION_NAME,
                Tag::Utf8String,
                "Ministère de la Santé".to_owned()
            ),
            (
                oid::COMMON_NAME,
                Tag::Utf8String,
                "Civil Registry Seal".to_owned()
            ),
        ]
    );

    let spki = &decoded.info.public_key;
    let key_bits = spki
        .subject_public_key
        .as_bytes()
        .expect("octet-aligned key");
    let signed = decoded.info.to_der().expect("info DER");
    let signature = decoded
        .signature
        .as_bytes()
        .expect("octet-aligned signature");
    let (signature_oid, verification): (ObjectIdentifier, &'static dyn VerificationAlgorithm) =
        match algorithm {
            SigningAlgorithm::Es256 | SigningAlgorithm::Es384 => {
                let (curve, signature_oid, verification): (
                    _,
                    _,
                    &'static dyn VerificationAlgorithm,
                ) = if algorithm == SigningAlgorithm::Es256 {
                    (
                        oid::SECP256R1,
                        oid::ECDSA_WITH_SHA256,
                        &ECDSA_P256_SHA256_ASN1,
                    )
                } else {
                    (
                        oid::SECP384R1,
                        oid::ECDSA_WITH_SHA384,
                        &ECDSA_P384_SHA384_ASN1,
                    )
                };
                assert_eq!(spki.algorithm.oid, oid::EC_PUBLIC_KEY);
                assert_eq!(
                    spki.algorithm
                        .parameters
                        .as_ref()
                        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok()),
                    Some(curve)
                );
                let point = [
                    vec![0x04],
                    decode_b64(jwk.x.as_deref()),
                    decode_b64(jwk.y.as_deref()),
                ]
                .concat();
                assert_eq!(key_bits, point.as_slice());
                // RFC 5758 section 3.2: no parameters.
                assert!(decoded.algorithm.parameters.is_none());
                (signature_oid, verification)
            }
            SigningAlgorithm::Rs256 | SigningAlgorithm::Rs384 => {
                assert_eq!(spki.algorithm.oid, oid::RSA_ENCRYPTION);
                assert_eq!(spki.algorithm.parameters, Some(Any::null()));
                let key = pkcs1::RsaPublicKeyRef::try_from(key_bits).expect("RSAPublicKey");
                assert_eq!(
                    key.modulus.as_bytes(),
                    decode_b64(jwk.n.as_deref()).as_slice()
                );
                assert_eq!(
                    key.public_exponent.as_bytes(),
                    decode_b64(jwk.e.as_deref()).as_slice()
                );
                // RFC 4055 section 5: NULL parameters.
                assert_eq!(decoded.algorithm.parameters, Some(Any::null()));
                if algorithm == SigningAlgorithm::Rs256 {
                    (oid::SHA256_WITH_RSA, &RSA_PKCS1_2048_8192_SHA256)
                } else {
                    (oid::SHA384_WITH_RSA, &RSA_PKCS1_2048_8192_SHA384)
                }
            }
            SigningAlgorithm::EdDsa => unreachable!("not a seal algorithm"),
        };
    assert_eq!(decoded.algorithm.oid, signature_oid);
    UnparsedPublicKey::new(verification, key_bits)
        .verify(&signed, signature)
        .expect("the request verifies under its own public key");
}

#[tokio::test]
async fn a_certificate_request_verifies_under_its_key_for_each_seal_algorithm() {
    for algorithm in SEAL_KEY_ALGORITHMS {
        let signer =
            LocalJwkSigner::new(generate_seal_key(algorithm).expect("key")).expect("signer");
        let request = certificate_request(&subject("Civil Registry Seal"), &signer)
            .await
            .expect("certificate request");
        check_request(&request, &signer.public_jwk(), algorithm);

        let text = request.to_pem();
        assert!(
            text.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"),
            "{text}"
        );
        assert!(
            text.ends_with("-----END CERTIFICATE REQUEST-----\n"),
            "{text}"
        );
        let (label, der) = der::pem::decode_vec(text.as_bytes()).expect("PEM");
        assert_eq!(label, "CERTIFICATE REQUEST");
        assert_eq!(der, request.der());
    }
}

#[tokio::test]
async fn a_certificate_request_names_only_the_members_given() {
    let signer = LocalJwkSigner::new(generate_seal_key(SigningAlgorithm::Es256).expect("key"))
        .expect("signer");
    let request = certificate_request(
        &CertificateRequestSubject {
            common_name: "Civil Registry Seal".to_owned(),
            organization: None,
            country: None,
        },
        &signer,
    )
    .await
    .expect("certificate request");
    let decoded = CertReq::from_der(request.der()).expect("PKCS #10 DER");
    let oids: Vec<ObjectIdentifier> = decoded
        .info
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter().map(|attribute| attribute.oid))
        .collect();
    assert_eq!(oids, [oid::COMMON_NAME]);
}

#[tokio::test]
async fn a_certificate_request_refuses_a_subject_outside_its_bounds() {
    let signer = LocalJwkSigner::new(generate_seal_key(SigningAlgorithm::Es256).expect("key"))
        .expect("signer");
    let long = "é".repeat(65);
    let cases = [
        (subject(""), "commonName"),
        (subject("   "), "commonName"),
        (subject(&long), "commonName"),
        (subject("Seal\nInjected"), "commonName"),
        (
            CertificateRequestSubject {
                organization: Some(String::new()),
                ..subject("Seal")
            },
            "organizationName",
        ),
        (
            CertificateRequestSubject {
                country: Some("fr".to_owned()),
                ..subject("Seal")
            },
            "countryName",
        ),
        (
            CertificateRequestSubject {
                country: Some("FRA".to_owned()),
                ..subject("Seal")
            },
            "countryName",
        ),
    ];
    for (subject, member) in cases {
        let error = certificate_request(&subject, &signer)
            .await
            .expect_err("refused");
        assert!(
            matches!(&error, CertificateRequestError::Subject { member: found, .. } if *found == member),
            "{error}"
        );
    }
    // Sixty-four characters is the X.520 upper bound, counted in characters.
    let at_bound = "é".repeat(64);
    assert!(certificate_request(&subject(&at_bound), &signer)
        .await
        .is_ok());
}

struct MisbehavingSigner {
    inner: LocalJwkSigner,
    behaviour: Misbehaviour,
}

enum Misbehaviour {
    SignsOtherBytes,
    Returns(Vec<u8>),
    Fails,
}

#[async_trait]
impl SigningProvider for MisbehavingSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }
    fn key_id(&self) -> &str {
        self.inner.key_id()
    }
    fn public_jwk(&self) -> PublicJwk {
        self.inner.public_jwk()
    }
    fn readiness(&self) -> KeyReadiness {
        self.inner.readiness()
    }
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        match &self.behaviour {
            Misbehaviour::SignsOtherBytes => {
                let mut other = payload.to_vec();
                other.push(0);
                self.inner.sign(&other).await
            }
            Misbehaviour::Returns(bytes) => Ok(bytes.clone()),
            Misbehaviour::Fails => Err(SigningError::external("signer offline")),
        }
    }
}

#[tokio::test]
async fn a_certificate_request_refuses_a_provider_that_does_not_sign_it() {
    for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Rs256] {
        let signer = MisbehavingSigner {
            inner: LocalJwkSigner::new(generate_seal_key(algorithm).expect("key")).expect("signer"),
            behaviour: Misbehaviour::SignsOtherBytes,
        };
        assert!(matches!(
            certificate_request(&subject("Seal"), &signer).await,
            Err(CertificateRequestError::SelfVerification)
        ));
    }
    let signer = MisbehavingSigner {
        inner: LocalJwkSigner::new(generate_seal_key(SigningAlgorithm::Es256).expect("key"))
            .expect("signer"),
        behaviour: Misbehaviour::Returns(vec![0x30; 70]),
    };
    assert!(matches!(
        certificate_request(&subject("Seal"), &signer).await,
        Err(CertificateRequestError::MalformedProviderSignature(_))
    ));
    let signer = MisbehavingSigner {
        inner: LocalJwkSigner::new(generate_seal_key(SigningAlgorithm::Es256).expect("key"))
            .expect("signer"),
        behaviour: Misbehaviour::Fails,
    };
    let error = certificate_request(&subject("Seal"), &signer)
        .await
        .expect_err("refused");
    assert!(
        matches!(error, CertificateRequestError::Signing(_)),
        "{error}"
    );
    assert!(error.to_string().contains("signer offline"), "{error}");
}

#[tokio::test]
async fn a_certificate_request_refuses_eddsa() {
    let signer =
        LocalJwkSigner::new(generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).expect("key"))
            .expect("signer");
    assert!(matches!(
        certificate_request(&subject("Seal"), &signer).await,
        Err(CertificateRequestError::UnsupportedAlgorithm(
            SigningAlgorithm::EdDsa
        ))
    ));
}
