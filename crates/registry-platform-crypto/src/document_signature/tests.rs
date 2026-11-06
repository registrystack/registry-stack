// SPDX-License-Identifier: Apache-2.0
//! Round trips, refusals and encoding edge cases for document signatures.

use super::asn1::{oid, EcdsaSigValue, SigningCertificateV2, TimeStampReq, TspGeneralizedTime};
use super::signed_data::jws_ecdsa_to_der;
use super::test_support::{
    critical_extended_key_usage, pem_block, refuse_timestamp_request, respond_to_timestamp_request,
    respond_with, verify_detached_signature, TestPki, TestSeal,
};
use super::verify::verify_signed_data;
use super::*;
use crate::{
    generate_private_jwk, GeneratedKeyAlgorithm, KeyReadiness, LocalJwkSigner, PublicJwk,
    SigningAlgorithm, SigningError, SigningProvider,
};
use async_trait::async_trait;
use aws_lc_rs::signature::{
    UnparsedPublicKey, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
};
use cms::cert::CertificateChoices;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{Int, ObjectIdentifier, OctetString};
use der::{Any, Decode, Encode};
use rcgen::{DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose};
use sha2::{Digest, Sha256, Sha384};
use time::{Duration, OffsetDateTime};
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

const FIRST_RANGE: &[u8] = b"%PDF-1.7\n% first byte range before the signature value\n";
const SECOND_RANGE: &[u8] = b"\n% second byte range after the signature value\n%%EOF\n";
const SEAL_ORGANIZATION: &str = "Registry Stack Test Ministry";

fn test_pki() -> TestPki {
    TestPki::generate().expect("test PKI")
}

fn seal(pki: &TestPki, algorithm: SigningAlgorithm) -> TestSeal {
    pki.issue_seal(algorithm).expect("test seal")
}

fn content() -> Vec<u8> {
    [FIRST_RANGE, SECOND_RANGE].concat()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_signed_data(cms_der: &[u8]) -> SignedData {
    let content_info = ContentInfo::from_der(cms_der).expect("CMS ContentInfo");
    assert_eq!(content_info.content_type, oid::SIGNED_DATA);
    content_info
        .content
        .decode_as::<SignedData>()
        .expect("CMS SignedData")
}

fn attribute_values(attributes: &Attributes, wanted: ObjectIdentifier) -> Vec<&Any> {
    attributes
        .iter()
        .filter(|attribute| attribute.oid == wanted)
        .flat_map(|attribute| attribute.values.iter())
        .collect()
}

async fn sign(seal: &TestSeal) -> DetachedSignature {
    let chain = seal.chain().expect("seal chain");
    let signer = seal.signer().expect("seal signer");
    sign_detached(&[FIRST_RANGE, SECOND_RANGE], &chain, &signer)
        .await
        .expect("detached signature")
}

// ----- Certificate chains -----

#[test]
fn chain_parses_leaf_first_with_its_accessors() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let chain = seal.chain().expect("chain");

    assert_eq!(chain.leaf_der(), seal.certificate_der());
    let fingerprint = chain.leaf_sha256_fingerprint();
    assert_eq!(
        fingerprint.as_bytes().as_slice(),
        Sha256::digest(seal.certificate_der()).as_slice()
    );
    assert_eq!(
        fingerprint.to_string(),
        hex(&Sha256::digest(seal.certificate_der()))
    );
    assert_eq!(chain.display_name(), Some(SEAL_ORGANIZATION));
    assert!(chain.not_before() < OffsetDateTime::now_utc());
    assert!(chain.not_after() > OffsetDateTime::now_utc());
    assert!(chain.not_before() < chain.not_after());
    assert_eq!(
        chain.der_len(),
        seal.certificate_der().len() + pki.issuing_ca_certificate_der().len(),
        "the chain's DER size counts the seal certificate and its issuer"
    );
}

#[test]
fn chain_display_name_falls_back_to_common_name() {
    let pki = test_pki();
    let seal = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "Licensing Seal");
            params.distinguished_name = name;
        })
        .expect("seal");
    let chain = seal.chain().expect("chain");
    assert_eq!(chain.display_name(), Some("Licensing Seal"));
}

#[test]
fn chain_without_organization_or_common_name_has_no_display_name() {
    let pki = test_pki();
    let seal = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            let mut name = DistinguishedName::new();
            name.push(DnType::CountryName, "ZZ");
            params.distinguished_name = name;
        })
        .expect("seal");
    assert_eq!(seal.chain().expect("chain").display_name(), None);
}

#[test]
fn chain_accepts_explanatory_text_and_crlf() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let pem = format!(
        "subject=Registry Stack test seal\r\n{}issuer=Registry Stack test issuing CA\r\n{}",
        pem_block("CERTIFICATE", seal.certificate_der()).replace('\n', "\r\n"),
        pem_block("CERTIFICATE", pki.issuing_ca_certificate_der()).replace('\n', "\r\n"),
    );
    let chain = CertificateChain::from_pem(pem.as_bytes()).expect("chain");
    assert_eq!(chain.leaf_der(), seal.certificate_der());
}

#[test]
fn chain_refuses_empty_input() {
    for input in [&b""[..], b"   \n\n", b"no PEM here\n"] {
        assert!(matches!(
            CertificateChain::from_pem(input),
            Err(CertificateError::Empty)
        ));
    }
}

#[test]
fn chain_refuses_a_non_certificate_block() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let pem = format!(
        "{}{}",
        pem_block("CERTIFICATE", seal.certificate_der()),
        pem_block(
            "PRIVATE KEY",
            b"not a key, but the label alone must be refused"
        ),
    );
    let error = CertificateChain::from_pem(pem.as_bytes()).expect_err("refused");
    assert!(matches!(
        error,
        CertificateError::NotACertificate { position: 2 }
    ));
    assert!(!error.to_string().contains("PRIVATE"));
}

#[test]
fn chain_refuses_malformed_pem() {
    let unterminated = "-----BEGIN CERTIFICATE-----\nMIIB\n";
    let mismatched = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----\n";
    let bad_base64 = "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n";
    let with_headers =
        "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END CERTIFICATE-----\n";
    for input in [unterminated, mismatched, bad_base64, with_headers] {
        assert!(
            matches!(
                CertificateChain::from_pem(input.as_bytes()),
                Err(CertificateError::MalformedPem { position: 1 })
            ),
            "{input:?}"
        );
    }
}

#[test]
fn chain_refuses_a_block_that_is_not_der_x509() {
    let pem = pem_block("CERTIFICATE", b"\x30\x03\x02\x01\x01");
    assert!(matches!(
        CertificateChain::from_pem(pem.as_bytes()),
        Err(CertificateError::MalformedCertificate { position: 1 })
    ));
}

#[test]
fn chain_refuses_issuer_before_leaf() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let pem = format!(
        "{}{}",
        pem_block("CERTIFICATE", pki.issuing_ca_certificate_der()),
        pem_block("CERTIFICATE", seal.certificate_der()),
    );
    assert!(matches!(
        CertificateChain::from_pem(pem.as_bytes()),
        Err(CertificateError::ChainOutOfOrder { position: 1 })
    ));
}

#[test]
fn chain_refuses_an_unrelated_second_certificate() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let pem = format!(
        "{}{}",
        pem_block("CERTIFICATE", seal.certificate_der()),
        pem_block("CERTIFICATE", pki.tsa().certificate_der()),
    );
    assert!(matches!(
        CertificateChain::from_pem(pem.as_bytes()),
        Err(CertificateError::ChainOutOfOrder { position: 1 })
    ));
}

#[test]
fn chain_refuses_a_repeated_certificate() {
    let pki = test_pki();
    let root = pem_block("CERTIFICATE", pki.root_certificate_der());
    let pem = format!("{root}{root}");
    assert!(matches!(
        CertificateChain::from_pem(pem.as_bytes()),
        Err(CertificateError::DuplicateCertificate { position: 2 })
    ));
}

#[test]
fn check_for_signing_accepts_the_matching_key_inside_validity() {
    let pki = test_pki();
    for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Rs256] {
        let seal = seal(&pki, algorithm);
        let chain = seal.chain().expect("chain");
        let public = seal.private_jwk().public();
        chain
            .check_for_signing(&public, OffsetDateTime::now_utc())
            .expect("usable for signing");
        chain
            .check_for_signing(&public, chain.not_before())
            .expect("valid at not_before");
        chain
            .check_for_signing(&public, chain.not_after())
            .expect("valid at not_after");
    }
}

#[test]
fn check_for_signing_refuses_another_key() {
    let pki = test_pki();
    let seal_a = seal(&pki, SigningAlgorithm::Es256);
    let seal_b = seal(&pki, SigningAlgorithm::Es256);
    let rsa = seal(&pki, SigningAlgorithm::Rs256);
    let chain = seal_a.chain().expect("chain");
    let now = OffsetDateTime::now_utc();
    for other in [seal_b.private_jwk().public(), rsa.private_jwk().public()] {
        let error = chain.check_for_signing(&other, now).expect_err("refused");
        assert!(matches!(error, CertificateError::KeyMismatch { .. }));
        assert!(error
            .to_string()
            .contains(&chain.leaf_sha256_fingerprint().to_string()));
        assert!(!error.to_string().contains(SEAL_ORGANIZATION));
    }
    let rsa_chain = rsa.chain().expect("chain");
    assert!(matches!(
        rsa_chain.check_for_signing(&seal_a.private_jwk().public(), now),
        Err(CertificateError::KeyMismatch { .. })
    ));
}

#[test]
fn check_for_signing_refuses_a_leaf_without_a_signing_key_usage() {
    let pki = test_pki();
    let now = OffsetDateTime::now_utc();
    let wrong_usage = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            params.key_usages = vec![KeyUsagePurpose::KeyAgreement];
        })
        .expect("seal");
    let no_usage = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| params.key_usages.clear())
        .expect("seal");
    for seal in [wrong_usage, no_usage] {
        let chain = seal.chain().expect("chain");
        assert!(matches!(
            chain.check_for_signing(&seal.private_jwk().public(), now),
            Err(CertificateError::MissingSigningKeyUsage { .. })
        ));
        assert!(!chain.may_sign(), "the usage alone is read without the key");
    }
}

#[test]
fn check_for_signing_accepts_either_signing_key_usage_alone() {
    let pki = test_pki();
    let now = OffsetDateTime::now_utc();
    for usage in [
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ] {
        let seal = pki
            .issue_seal_with(SigningAlgorithm::Es256, move |params| {
                params.key_usages = vec![usage];
            })
            .expect("seal");
        let chain = seal.chain().expect("chain");
        chain
            .check_for_signing(&seal.private_jwk().public(), now)
            .expect("accepted");
        assert!(chain.may_sign());
    }
}

#[test]
fn check_for_signing_refuses_outside_validity() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let chain = seal.chain().expect("chain");
    let public = seal.private_jwk().public();
    assert!(matches!(
        chain.check_for_signing(&public, chain.not_before() - Duration::seconds(1)),
        Err(CertificateError::NotYetValid { .. })
    ));
    assert!(matches!(
        chain.check_for_signing(&public, chain.not_after() + Duration::seconds(1)),
        Err(CertificateError::Expired { .. })
    ));
}

#[test]
fn check_for_signing_refuses_an_eddsa_key() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let chain = seal.chain().expect("chain");
    let ed25519 = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).expect("key");
    assert!(matches!(
        chain.check_for_signing(&ed25519.public(), OffsetDateTime::now_utc()),
        Err(CertificateError::UnsupportedKey { .. })
    ));
}

#[test]
fn chain_debug_names_the_fingerprint_not_the_subject() {
    let pki = test_pki();
    let chain = seal(&pki, SigningAlgorithm::Es256).chain().expect("chain");
    let debug = format!("{chain:?}");
    assert!(debug.contains(&chain.leaf_sha256_fingerprint().to_string()));
    assert!(!debug.contains(SEAL_ORGANIZATION));
}

// ----- Detached CMS signatures -----

struct RoundTrip {
    algorithm: SigningAlgorithm,
    digest: ObjectIdentifier,
    signature_algorithm: ObjectIdentifier,
    verification: &'static dyn VerificationAlgorithm,
}

async fn assert_round_trip(case: RoundTrip) {
    let pki = test_pki();
    let seal = seal(&pki, case.algorithm);
    let signature = sign(&seal).await;
    let leaf = Certificate::from_der(seal.certificate_der()).expect("leaf");
    let signed_data = parse_signed_data(&signature.cms_der);

    assert_eq!(signed_data.version, CmsVersion::V1);
    let digests: Vec<_> = signed_data.digest_algorithms.iter().collect();
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].oid, case.digest);
    assert!(digests[0].parameters.is_none());
    assert_eq!(signed_data.encap_content_info.econtent_type, oid::DATA);
    assert!(signed_data.encap_content_info.econtent.is_none());
    assert!(signed_data.crls.is_none());

    let mut certificates: Vec<Vec<u8>> = signed_data
        .certificates
        .as_ref()
        .expect("certificates")
        .0
        .iter()
        .map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => certificate.to_der().expect("DER"),
            CertificateChoices::Other(_) => panic!("unexpected certificate format"),
        })
        .collect();
    certificates.sort();
    let mut expected = vec![
        seal.certificate_der().to_vec(),
        pki.issuing_ca_certificate_der().to_vec(),
    ];
    expected.sort();
    assert_eq!(certificates, expected);

    let signer_infos: Vec<_> = signed_data.signer_infos.0.iter().collect();
    assert_eq!(signer_infos.len(), 1);
    let signer = signer_infos[0];
    assert_eq!(signer.version, CmsVersion::V1);
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
            assert_eq!(issuer_and_serial.issuer, leaf.tbs_certificate.issuer);
            assert_eq!(
                issuer_and_serial.serial_number,
                leaf.tbs_certificate.serial_number
            );
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => panic!("expected issuerAndSerialNumber"),
    }
    assert_eq!(signer.digest_alg.oid, case.digest);
    assert!(signer.digest_alg.parameters.is_none());

    let attributes = signer.signed_attrs.as_ref().expect("signed attributes");
    let mut present: Vec<_> = attributes.iter().map(|attribute| attribute.oid).collect();
    present.sort();
    let mut wanted = vec![
        oid::CONTENT_TYPE,
        oid::MESSAGE_DIGEST,
        oid::SIGNING_CERTIFICATE_V2,
    ];
    wanted.sort();
    assert_eq!(present, wanted, "exactly the three B-B signed attributes");
    assert!(attribute_values(attributes, oid::SIGNING_TIME).is_empty());
    assert!(attributes
        .iter()
        .all(|attribute| attribute.values.len() == 1));

    let content_type = attribute_values(attributes, oid::CONTENT_TYPE)[0]
        .decode_as::<ObjectIdentifier>()
        .expect("content type");
    assert_eq!(content_type, oid::DATA);

    let content = content();
    let (content_digest, leaf_digest) = if case.digest == oid::SHA256 {
        (
            Sha256::digest(&content).to_vec(),
            Sha256::digest(seal.certificate_der()).to_vec(),
        )
    } else {
        (
            Sha384::digest(&content).to_vec(),
            Sha384::digest(seal.certificate_der()).to_vec(),
        )
    };
    let message_digest = attribute_values(attributes, oid::MESSAGE_DIGEST)[0]
        .decode_as::<OctetString>()
        .expect("message digest");
    assert_eq!(message_digest.as_bytes(), content_digest.as_slice());

    let signing_certificate = attribute_values(attributes, oid::SIGNING_CERTIFICATE_V2)[0]
        .decode_as::<SigningCertificateV2>()
        .expect("signing certificate v2");
    assert_eq!(signing_certificate.certs.len(), 1);
    assert!(signing_certificate.policies.is_none());
    let cert_id = &signing_certificate.certs[0];
    assert_eq!(cert_id.cert_hash.as_bytes(), leaf_digest.as_slice());
    if case.digest == oid::SHA256 {
        assert!(
            cert_id.hash_algorithm.is_none(),
            "SHA-256 is the DER default and must be omitted"
        );
    } else {
        assert_eq!(
            cert_id.hash_algorithm.as_ref().expect("hash algorithm").oid,
            case.digest
        );
    }
    let issuer_serial = cert_id.issuer_serial.as_ref().expect("issuerSerial");
    assert_eq!(
        issuer_serial.issuer,
        vec![GeneralName::DirectoryName(
            leaf.tbs_certificate.issuer.clone()
        )]
    );
    assert_eq!(
        issuer_serial.serial_number,
        leaf.tbs_certificate.serial_number
    );

    assert_eq!(signer.signature_algorithm.oid, case.signature_algorithm);
    if case.signature_algorithm == oid::RSA_ENCRYPTION {
        assert_eq!(
            signer.signature_algorithm.parameters,
            Some(Any::null()),
            "rsaEncryption carries NULL parameters"
        );
    } else {
        assert!(signer.signature_algorithm.parameters.is_none());
    }
    assert!(signer.unsigned_attrs.is_none());
    assert_eq!(signature.signature_value, signer.signature.as_bytes());

    // Verify independently of this module's verifier: aws-lc-rs over the DER
    // SET OF signed attributes, under the leaf certificate's own key.
    let signed_message = attributes.to_der().expect("signed attributes DER");
    assert_eq!(signed_message[0], 0x31, "signed over a SET OF tag");
    let leaf_key = leaf
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    UnparsedPublicKey::new(case.verification, leaf_key)
        .verify(&signed_message, signer.signature.as_bytes())
        .expect("signature verifies under the leaf key");

    let verified = verify_signed_data(&signed_data, &[&content]).expect("verifies");
    assert_eq!(
        verified.to_der().expect("DER"),
        seal.certificate_der().to_vec()
    );
}

#[tokio::test]
async fn es256_round_trip() {
    assert_round_trip(RoundTrip {
        algorithm: SigningAlgorithm::Es256,
        digest: oid::SHA256,
        signature_algorithm: oid::ECDSA_WITH_SHA256,
        verification: &ECDSA_P256_SHA256_ASN1,
    })
    .await;
}

#[tokio::test]
async fn es384_round_trip() {
    assert_round_trip(RoundTrip {
        algorithm: SigningAlgorithm::Es384,
        digest: oid::SHA384,
        signature_algorithm: oid::ECDSA_WITH_SHA384,
        verification: &ECDSA_P384_SHA384_ASN1,
    })
    .await;
}

#[tokio::test]
async fn rs256_round_trip() {
    assert_round_trip(RoundTrip {
        algorithm: SigningAlgorithm::Rs256,
        digest: oid::SHA256,
        signature_algorithm: oid::RSA_ENCRYPTION,
        verification: &RSA_PKCS1_2048_8192_SHA256,
    })
    .await;
}

#[tokio::test]
async fn rs384_round_trip() {
    assert_round_trip(RoundTrip {
        algorithm: SigningAlgorithm::Rs384,
        digest: oid::SHA384,
        signature_algorithm: oid::RSA_ENCRYPTION,
        verification: &RSA_PKCS1_2048_8192_SHA384,
    })
    .await;
}

#[tokio::test]
async fn message_digest_covers_the_concatenated_parts() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let chain = seal.chain().expect("chain");
    let signer = seal.signer().expect("signer");
    let whole = content();
    let (left, right) = whole.split_at(7);
    let signature = sign_detached(&[left, &[], right], &chain, &signer)
        .await
        .expect("signature");
    let signed_data = parse_signed_data(&signature.cms_der);
    verify_signed_data(&signed_data, &[&whole]).expect("same digest as one part");
}

#[tokio::test]
async fn tampered_content_or_signature_does_not_verify() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let signature = sign(&seal).await;
    let signed_data = parse_signed_data(&signature.cms_der);
    assert!(matches!(
        verify_signed_data(&signed_data, &[FIRST_RANGE, b"tampered"]),
        Err(SignerVerificationError::MessageDigestMismatch)
    ));

    let mut tampered = signed_data.clone();
    let mut signers = tampered.signer_infos.0.into_vec();
    let mut value = signers[0].signature.as_bytes().to_vec();
    let last = value.len() - 2;
    value[last] ^= 0x01;
    signers[0].signature = OctetString::new(value).expect("octets");
    tampered.signer_infos.0 = signers.try_into().expect("signer set");
    assert!(matches!(
        verify_signed_data(&tampered, &[&content()]),
        Err(SignerVerificationError::SignatureInvalid)
    ));
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

async fn sign_with(
    seal: &TestSeal,
    behaviour: Misbehaviour,
) -> Result<DetachedSignature, CmsError> {
    let signer = MisbehavingSigner {
        inner: seal.signer().expect("signer"),
        behaviour,
    };
    sign_detached(
        &[FIRST_RANGE, SECOND_RANGE],
        &seal.chain().expect("chain"),
        &signer,
    )
    .await
}

#[tokio::test]
async fn sign_detached_refuses_a_signature_that_fails_self_verification() {
    let pki = test_pki();
    for algorithm in [SigningAlgorithm::Es256, SigningAlgorithm::Rs256] {
        let seal = seal(&pki, algorithm);
        assert!(matches!(
            sign_with(&seal, Misbehaviour::SignsOtherBytes).await,
            Err(CmsError::SelfVerification(
                SignerVerificationError::SignatureInvalid
            ))
        ));
    }
}

#[tokio::test]
async fn sign_detached_refuses_a_malformed_provider_signature() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    // A DER ECDSA-Sig-Value where the JWS form was expected.
    let der_shaped = vec![0x30; 70];
    assert!(matches!(
        sign_with(&seal, Misbehaviour::Returns(der_shaped)).await,
        Err(CmsError::MalformedProviderSignature(_))
    ));
    assert!(matches!(
        sign_with(&seal, Misbehaviour::Returns(vec![0; 64])).await,
        Err(CmsError::MalformedProviderSignature(_))
    ));
}

#[tokio::test]
async fn sign_detached_reports_a_provider_failure() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let error = sign_with(&seal, Misbehaviour::Fails)
        .await
        .expect_err("refused");
    assert!(matches!(error, CmsError::Signing(_)));
    assert!(error.to_string().contains("signer offline"));
}

#[tokio::test]
async fn sign_detached_refuses_eddsa() {
    let pki = test_pki();
    let chain = seal(&pki, SigningAlgorithm::Es256).chain().expect("chain");
    let signer =
        LocalJwkSigner::new(generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).expect("key"))
            .expect("signer");
    assert!(matches!(
        sign_detached(&[FIRST_RANGE], &chain, &signer).await,
        Err(CmsError::UnsupportedAlgorithm(SigningAlgorithm::EdDsa))
    ));
}

#[tokio::test]
async fn sign_detached_refuses_a_chain_for_another_key() {
    let pki = test_pki();
    let chain = seal(&pki, SigningAlgorithm::Es256).chain().expect("chain");
    let other = seal(&pki, SigningAlgorithm::Es256)
        .signer()
        .expect("signer");
    assert!(matches!(
        sign_detached(&[FIRST_RANGE], &chain, &other).await,
        Err(CmsError::Certificate(CertificateError::KeyMismatch { .. }))
    ));
}

// ----- JWS ECDSA to DER -----

#[test]
fn jws_ecdsa_to_der_strips_leading_zeros_and_pads_high_bits() {
    let mut r = [0u8; 32];
    r[2..].copy_from_slice(&[0x11; 30]);
    let mut s = [0x80u8; 32];
    s[31] = 0x01;
    let der = jws_ecdsa_to_der(&[r, s].concat(), 32).expect("DER");

    let mut expected = vec![0x30, 2 + 30 + 2 + 33, 0x02, 30];
    expected.extend_from_slice(&r[2..]);
    expected.extend_from_slice(&[0x02, 33, 0x00]);
    expected.extend_from_slice(&s);
    assert_eq!(der, expected);
}

#[test]
fn jws_ecdsa_to_der_keeps_a_zero_byte_before_a_high_bit_after_stripping() {
    let mut r = [0u8; 48];
    r[1] = 0xff;
    r[2..].copy_from_slice(&[0x22; 46]);
    let s = [0x7fu8; 48];
    let der = jws_ecdsa_to_der(&[r, s].concat(), 48).expect("DER");

    let mut expected = vec![0x30, 2 + 48 + 2 + 48, 0x02, 48, 0x00];
    expected.extend_from_slice(&r[1..]);
    expected.extend_from_slice(&[0x02, 48]);
    expected.extend_from_slice(&s);
    assert_eq!(der, expected);
    let parsed = EcdsaSigValue::from_der(&der).expect("ECDSA-Sig-Value");
    assert_eq!(parsed.r.as_bytes(), &r[1..]);
    assert_eq!(parsed.s.as_bytes(), &s);
}

#[test]
fn jws_ecdsa_to_der_handles_single_byte_halves() {
    let mut signature = [0u8; 64];
    signature[31] = 0x01;
    signature[63] = 0x80;
    let der = jws_ecdsa_to_der(&signature, 32).expect("DER");
    assert_eq!(
        der,
        vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80]
    );
}

#[test]
fn jws_ecdsa_to_der_refuses_wrong_lengths_and_zero_halves() {
    let mut zero_r = [0x01u8; 64];
    zero_r[..32].fill(0);
    let mut zero_s = [0x01u8; 64];
    zero_s[32..].fill(0);
    for (signature, width) in [
        (vec![0x01; 63], 32),
        (vec![0x01; 65], 32),
        (vec![0x01; 64], 48),
        (vec![], 32),
        (zero_r.to_vec(), 32),
        (zero_s.to_vec(), 32),
    ] {
        assert!(
            matches!(
                jws_ecdsa_to_der(&signature, width),
                Err(CmsError::MalformedProviderSignature(_))
            ),
            "length {} width {width}",
            signature.len()
        );
    }
}

// ----- Timestamps -----

fn now_seconds() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0).expect("whole second")
}

#[test]
fn timestamp_request_asks_for_a_sha256_imprint_nonce_and_certificate() {
    let signature_value = b"signature value octets";
    let cases: [(u64, &[u8]); 3] = [
        (1, &[0x02, 0x01, 0x01]),
        (
            0x0102_0304_0506_0708,
            &[0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ),
        (
            u64::MAX,
            &[
                0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ),
    ];
    for (nonce, expected_nonce) in cases {
        let request_der = timestamp_request(signature_value, nonce).expect("request");
        let request = TimeStampReq::from_der(&request_der).expect("TimeStampReq");
        assert_eq!(request.version, 1);
        assert_eq!(request.message_imprint.hash_algorithm.oid, oid::SHA256);
        assert!(request.message_imprint.hash_algorithm.parameters.is_none());
        assert_eq!(
            request.message_imprint.hashed_message.as_bytes(),
            Sha256::digest(signature_value).as_slice()
        );
        assert!(request.req_policy.is_none());
        assert_eq!(
            request.nonce.expect("nonce").to_der().expect("DER"),
            expected_nonce,
            "nonce {nonce} is a positive INTEGER"
        );
        assert_eq!(request.cert_req, Some(true));
        assert!(request.extensions.is_none());
    }
}

#[test]
fn random_timestamp_nonces_differ() {
    let first = random_timestamp_nonce().expect("nonce");
    let second = random_timestamp_nonce().expect("nonce");
    assert_ne!(first, second);
}

#[tokio::test]
async fn timestamp_round_trip_reaches_b_t() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let signature = sign(&seal).await;
    let nonce = 0x8000_0000_0000_0001;
    let request = timestamp_request(&signature.signature_value, nonce).expect("request");
    let gen_time = now_seconds();
    let response = respond_to_timestamp_request(&request, &pki, gen_time).expect("response");

    let timestamp =
        accept_timestamp_response(&response, &signature.signature_value, nonce).expect("accepted");
    assert_eq!(timestamp.gen_time, gen_time);
    let token = ContentInfo::from_der(&timestamp.token_der).expect("token");
    assert_eq!(token.content_type, oid::SIGNED_DATA);

    let with_timestamp =
        add_signature_timestamp(&signature.cms_der, &timestamp.token_der).expect("B-T");
    let before = parse_signed_data(&signature.cms_der);
    let after = parse_signed_data(&with_timestamp);
    let signer_before = before.signer_infos.0.iter().next().expect("signer");
    let signer_after = after.signer_infos.0.iter().next().expect("signer");
    assert_eq!(signer_before.signed_attrs, signer_after.signed_attrs);
    assert_eq!(signer_before.signature, signer_after.signature);
    assert_eq!(before.certificates, after.certificates);
    let unsigned = signer_after.unsigned_attrs.as_ref().expect("unsigned");
    assert_eq!(unsigned.len(), 1);
    let tokens = attribute_values(unsigned, oid::SIGNATURE_TIME_STAMP_TOKEN);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].to_der().expect("DER"), timestamp.token_der);
    verify_signed_data(&after, &[&content()]).expect("still verifies");
}

#[test]
fn accept_timestamp_response_accepts_granted_with_modifications() {
    let pki = test_pki();
    let request = timestamp_request(b"value", 7).expect("request");
    let response = respond_with(&request, pki.tsa(), now_seconds(), |parts| {
        parts.status = 1;
    })
    .expect("response");
    accept_timestamp_response(&response, b"value", 7).expect("accepted");
}

fn refusal(
    pki: &TestPki,
    customise: impl FnOnce(&mut super::test_support::ResponseParts),
) -> TimestampError {
    let request = timestamp_request(b"signature value", 42).expect("request");
    let response = respond_with(&request, pki.tsa(), now_seconds(), customise).expect("response");
    accept_timestamp_response(&response, b"signature value", 42).expect_err("refused")
}

#[test]
fn accept_timestamp_response_refuses_a_status_that_is_not_granted() {
    let pki = test_pki();
    for status in [2_u32, 3, 4, 5] {
        let error = refusal(&pki, |parts| {
            parts.status = status;
            parts.include_token = false;
        });
        assert!(
            matches!(error, TimestampError::NotGranted { status: got } if got == status),
            "{error}"
        );
    }
}

#[test]
fn accept_timestamp_response_refuses_a_grant_without_a_token() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| parts.include_token = false),
        TimestampError::MissingToken
    ));
}

#[test]
fn accept_timestamp_response_refuses_a_token_over_other_content() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| parts.econtent_type = oid::DATA),
        TimestampError::NotTstInfo
    ));
}

#[test]
fn accept_timestamp_response_refuses_an_unknown_tst_info_version() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| parts.tst_info.version = 2),
        TimestampError::MalformedTstInfo
    ));
}

#[test]
fn accept_timestamp_response_refuses_a_wrong_message_imprint() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| {
            parts.tst_info.message_imprint.hashed_message =
                OctetString::new(vec![0; 32]).expect("octets");
        }),
        TimestampError::MessageImprintMismatch
    ));
    assert!(matches!(
        refusal(&pki, |parts| {
            parts.tst_info.message_imprint.hash_algorithm.oid = oid::SHA384;
        }),
        TimestampError::MessageImprintMismatch
    ));
}

#[test]
fn accept_timestamp_response_refuses_a_wrong_or_missing_nonce() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| {
            parts.tst_info.nonce = Some(Int::new(&[43]).expect("int"));
        }),
        TimestampError::NonceMismatch
    ));
    assert!(matches!(
        refusal(&pki, |parts| parts.tst_info.nonce = None),
        TimestampError::NonceMismatch
    ));
}

#[test]
fn accept_timestamp_response_refuses_a_tampered_token_signature() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| parts.tamper_signature = true),
        TimestampError::TokenSignature(SignerVerificationError::SignatureInvalid)
    ));
}

#[test]
fn accept_timestamp_response_refuses_a_token_without_its_tsa_certificate() {
    let pki = test_pki();
    assert!(matches!(
        refusal(&pki, |parts| parts.include_certificates = false),
        TimestampError::TokenSignature(SignerVerificationError::SignerCertificateMissing)
    ));
}

#[test]
fn accept_timestamp_response_refuses_a_tsa_without_critical_timestamping() {
    let pki = test_pki();
    let non_critical = pki
        .issue_tsa_with(|params| {
            params.custom_extensions.clear();
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::TimeStamping];
        })
        .expect("TSA");
    let extra_purpose = pki
        .issue_tsa_with(|params| {
            params.custom_extensions = vec![critical_extended_key_usage(&[
                oid::KP_TIME_STAMPING,
                ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4"),
            ])
            .expect("extension")];
        })
        .expect("TSA");
    let missing = pki
        .issue_tsa_with(|params| params.custom_extensions.clear())
        .expect("TSA");
    for tsa in [non_critical, extra_purpose, missing] {
        let request = timestamp_request(b"value", 9).expect("request");
        let response = respond_with(&request, &tsa, now_seconds(), |_| {}).expect("response");
        let error = accept_timestamp_response(&response, b"value", 9).expect_err("refused");
        assert!(
            matches!(
                error,
                TimestampError::TsaCertificateNotForTimestamping { .. }
            ),
            "{error}"
        );
    }
}

#[test]
fn accept_timestamp_response_refuses_a_gen_time_outside_tsa_validity() {
    let pki = test_pki();
    let request = timestamp_request(b"value", 5).expect("request");
    let far_future = now_seconds() + Duration::days(365 * 30);
    let response = respond_with(&request, pki.tsa(), far_future, |_| {}).expect("response");
    assert!(matches!(
        accept_timestamp_response(&response, b"value", 5),
        Err(TimestampError::TsaCertificateNotValidAtGenTime { .. })
    ));
}

#[test]
fn accept_timestamp_response_refuses_malformed_or_oversized_input() {
    assert!(matches!(
        accept_timestamp_response(b"\x30\x03\x02\x01", b"value", 1),
        Err(TimestampError::MalformedResponse)
    ));
    let oversized = vec![0x30; MAX_TIMESTAMP_RESPONSE_BYTES + 1];
    assert!(matches!(
        accept_timestamp_response(&oversized, b"value", 1),
        Err(TimestampError::ResponseTooLarge)
    ));
}

#[tokio::test]
async fn add_signature_timestamp_refuses_a_token_for_another_signature() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let signature = sign(&seal).await;
    let request = timestamp_request(b"some other signature", 3).expect("request");
    let response = respond_to_timestamp_request(&request, &pki, now_seconds()).expect("response");
    let other = accept_timestamp_response(&response, b"some other signature", 3).expect("ok");
    assert!(matches!(
        add_signature_timestamp(&signature.cms_der, &other.token_der),
        Err(CmsError::TimestampMismatch)
    ));
}

#[tokio::test]
async fn add_signature_timestamp_refuses_a_second_timestamp_and_garbage() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let signature = sign(&seal).await;
    let request = timestamp_request(&signature.signature_value, 11).expect("request");
    let response = respond_to_timestamp_request(&request, &pki, now_seconds()).expect("response");
    let timestamp =
        accept_timestamp_response(&response, &signature.signature_value, 11).expect("ok");
    let once = add_signature_timestamp(&signature.cms_der, &timestamp.token_der).expect("B-T");
    assert!(matches!(
        add_signature_timestamp(&once, &timestamp.token_der),
        Err(CmsError::TimestampAlreadyPresent)
    ));
    assert!(matches!(
        add_signature_timestamp(b"\x30\x00", &timestamp.token_der),
        Err(CmsError::MalformedSignedData)
    ));
    assert!(matches!(
        add_signature_timestamp(&signature.cms_der, b"\x30\x00"),
        Err(CmsError::MalformedTimestampToken)
    ));
}

#[test]
fn generalized_time_reads_rfc_3161_fractions() {
    let cases = [
        ("20261106120000Z", 0),
        ("20261106120000.5Z", 500_000_000),
        ("20261106120000.123456Z", 123_456_000),
        ("20261106120000.000000001Z", 1),
    ];
    for (text, nanosecond) in cases {
        let encoded = [&[0x18, text.len() as u8][..], text.as_bytes()].concat();
        let time = TspGeneralizedTime::from_der(&encoded).expect(text);
        let value = time.to_offset_date_time();
        assert_eq!(value.year(), 2026);
        assert_eq!(value.hour(), 12);
        assert_eq!(value.nanosecond(), nanosecond, "{text}");
        assert_eq!(
            time.to_der().expect("DER"),
            encoded,
            "{text} re-encodes as read"
        );
    }
}

#[test]
fn generalized_time_refuses_other_forms() {
    for text in [
        "202611061200Z",
        "20261106120000",
        "20261106120000+0100",
        "20261306120000Z",
        "20261106120000.Z",
        "20261106120000.1234567890Z",
        "2026110612000aZ",
    ] {
        let encoded = [&[0x18, text.len() as u8][..], text.as_bytes()].concat();
        assert!(TspGeneralizedTime::from_der(&encoded).is_err(), "{text}");
    }
}

// ----- Interoperability artifacts -----

/// Writes signatures, timestamp requests and responses for checking with
/// OpenSSL outside cargo. Set `REGISTRY_CMS_INTEROP_DIR` to an empty
/// directory and run this ignored test; the crate README lists the commands.
#[tokio::test]
#[ignore = "writes OpenSSL interoperability artifacts to REGISTRY_CMS_INTEROP_DIR"]
async fn write_openssl_interop_artifacts() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("REGISTRY_CMS_INTEROP_DIR").expect("REGISTRY_CMS_INTEROP_DIR"),
    );
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(directory.join(name), bytes).expect("write artifact");
    };
    let pki = test_pki();
    write("root.pem", pki.root_certificate_pem().as_bytes());
    write("content.bin", &content());
    for (label, algorithm) in [
        ("es256", SigningAlgorithm::Es256),
        ("es384", SigningAlgorithm::Es384),
        ("rs256", SigningAlgorithm::Rs256),
    ] {
        let seal = seal(&pki, algorithm);
        let signature = sign(&seal).await;
        let nonce = random_timestamp_nonce().expect("nonce");
        let request = timestamp_request(&signature.signature_value, nonce).expect("request");
        let response =
            respond_to_timestamp_request(&request, &pki, now_seconds()).expect("response");
        let timestamp =
            accept_timestamp_response(&response, &signature.signature_value, nonce).expect("ok");
        let with_timestamp =
            add_signature_timestamp(&signature.cms_der, &timestamp.token_der).expect("B-T");
        write(&format!("{label}-b-b.p7s"), &signature.cms_der);
        write(&format!("{label}-b-t.p7s"), &with_timestamp);
        write(
            &format!("{label}-signature-value.bin"),
            &signature.signature_value,
        );
        write(&format!("{label}.tsq"), &request);
        write(&format!("{label}.tsr"), &response);
        write(&format!("{label}-chain.pem"), seal.chain_pem().as_bytes());
    }
}

// ----- Test support verifier -----

#[tokio::test]
async fn the_test_verifier_checks_the_parts_the_signer_and_an_embedded_timestamp() {
    let pki = test_pki();
    let seal = seal(&pki, SigningAlgorithm::Es256);
    let signature = sign(&seal).await;
    let fingerprint = seal.chain().expect("chain").leaf_sha256_fingerprint();

    let verified = verify_detached_signature(&signature.cms_der, &[FIRST_RANGE, SECOND_RANGE])
        .expect("B-B verifies");
    assert_eq!(verified.signer_fingerprint, fingerprint);
    assert_eq!(verified.timestamp_gen_time, None);
    assert!(
        verify_detached_signature(&signature.cms_der, &[FIRST_RANGE, b"tampered"]).is_err(),
        "a changed byte range is refused"
    );
    assert!(verify_detached_signature(b"not der", &[FIRST_RANGE]).is_err());

    let nonce = 7;
    let request = timestamp_request(&signature.signature_value, nonce).expect("request");
    let gen_time = now_seconds();
    let response = respond_to_timestamp_request(&request, &pki, gen_time).expect("response");
    let timestamp =
        accept_timestamp_response(&response, &signature.signature_value, nonce).expect("granted");
    let stamped = add_signature_timestamp(&signature.cms_der, &timestamp.token_der).expect("B-T");
    let verified =
        verify_detached_signature(&stamped, &[FIRST_RANGE, SECOND_RANGE]).expect("B-T verifies");
    assert_eq!(verified.signer_fingerprint, fingerprint);
    assert_eq!(verified.timestamp_gen_time, Some(gen_time));
}

#[test]
fn the_refusing_test_authority_answers_with_a_rejection() {
    let pki = test_pki();
    let request = timestamp_request(b"signature value", 9).expect("request");
    let response = refuse_timestamp_request(&request, &pki).expect("response");
    assert!(matches!(
        accept_timestamp_response(&response, b"signature value", 9),
        Err(TimestampError::NotGranted { status: 2 })
    ));
}
