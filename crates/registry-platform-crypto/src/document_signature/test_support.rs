// SPDX-License-Identifier: Apache-2.0
//! A throwaway PKI and RFC 3161 timestamp authority for tests.
//!
//! [`TestPki::generate`] creates a root CA, an issuing CA under it, and a
//! timestamp authority certificate issued by the root with a critical
//! extended key usage of id-kp-timeStamping. [`TestPki::issue_seal`] issues
//! seal certificates under the issuing CA, each with a fresh private JWK for
//! [`LocalJwkSigner`]. Every key is generated at call time and lives only in
//! memory. Nothing here is fit for production signing.

use super::asn1::{
    oid, Accuracy, EssCertId, EssCertIdV2, IssuerSerial, PkiStatusInfo, SigningCertificate,
    SigningCertificateV2, TimeStampReq, TimeStampResp, TspGeneralizedTime, TstInfo,
};
use super::certificate::{CertificateChain, CertificateError, CertificateFingerprint};
use super::signed_data::{
    assemble_signed_data, content_info, decode_signed_data, jws_ecdsa_to_der, signed_attributes,
    CmsError,
};
use super::timestamp::{check_imprint, read_token, verify_token};
use super::verify::{single_attribute, verify_signed_data, DigestAlgorithm};
use crate::{
    generate_private_jwk, sign, CryptoError, GeneratedKeyAlgorithm, LocalJwkSigner, PrivateJwk,
    SigningAlgorithm, SigningError,
};
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use cms::signed_data::EncapsulatedContentInfo;
use der::asn1::{Int, ObjectIdentifier, OctetString, UintRef};
use der::{Any, Decode as _, Encode as _, Tag};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, PublicKeyData, SerialNumber, SignatureAlgorithm,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

/// The organization every test seal certificate names.
pub const TEST_SEAL_ORGANIZATION: &str = "Registry Stack Test Ministry";

/// The TSA policy test tokens carry: the sample policy of OpenSSL's
/// `openssl.cnf` TSA section, which no production authority uses.
const TEST_TSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4.1");

/// Why the test PKI could not issue a certificate or answer a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TestPkiError {
    #[error("test certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("test key generation or signing failed: {0}")]
    Key(#[from] CryptoError),
    #[error("test DER encoding failed: {0}")]
    Der(#[from] der::Error),
    #[error("test token signature failed: {0}")]
    Signature(#[from] CmsError),
    #[error("the test PKI issues ES256, ES384, RS256 and RS384 seals only")]
    UnsupportedAlgorithm,
    #[error("the system random number generator failed")]
    RandomUnavailable,
}

/// A root CA, an issuing CA, and a timestamp authority, all in memory.
pub struct TestPki {
    root: TestCa,
    issuing_ca: TestCa,
    tsa: TestTsa,
}

struct TestCa {
    certificate_der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

/// A seal certificate under the test issuing CA, and its private key.
pub struct TestSeal {
    certificate_der: Vec<u8>,
    issuing_ca_der: Vec<u8>,
    private_jwk: PrivateJwk,
}

/// A timestamp authority certificate and its private key.
pub struct TestTsa {
    certificate_der: Vec<u8>,
    private_jwk: PrivateJwk,
}

impl TestPki {
    /// Generate the root CA, the issuing CA and the timestamp authority.
    pub fn generate() -> Result<Self, TestPkiError> {
        let mut root_params = ca_params("Registry Stack Test Root CA")?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let root = TestCa {
            certificate_der: root_params.self_signed(&root_key)?.der().to_vec(),
            issuer: Issuer::new(root_params, root_key),
        };

        let mut issuing_params = ca_params("Registry Stack Test Issuing CA")?;
        issuing_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let issuing_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let issuing_ca = TestCa {
            certificate_der: issuing_params
                .signed_by(&issuing_key, &root.issuer)?
                .der()
                .to_vec(),
            issuer: Issuer::new(issuing_params, issuing_key),
        };

        let tsa = issue_tsa(&root, |_| {})?;
        Ok(Self {
            root,
            issuing_ca,
            tsa,
        })
    }

    /// The root CA certificate, the trust anchor for seals and timestamps.
    #[must_use]
    pub fn root_certificate_der(&self) -> &[u8] {
        &self.root.certificate_der
    }

    /// The root CA certificate as PEM, for `openssl -CAfile`.
    #[must_use]
    pub fn root_certificate_pem(&self) -> String {
        pem_block("CERTIFICATE", &self.root.certificate_der)
    }

    /// The issuing CA certificate every seal names as its issuer.
    #[must_use]
    pub fn issuing_ca_certificate_der(&self) -> &[u8] {
        &self.issuing_ca.certificate_der
    }

    /// The timestamp authority [`respond_to_timestamp_request`] signs with.
    #[must_use]
    pub fn tsa(&self) -> &TestTsa {
        &self.tsa
    }

    /// Issue a seal certificate for a fresh key: organization
    /// [`TEST_SEAL_ORGANIZATION`], key usages digitalSignature and
    /// nonRepudiation, valid from an hour ago for a year.
    pub fn issue_seal(&self, algorithm: SigningAlgorithm) -> Result<TestSeal, TestPkiError> {
        self.issue_seal_with(algorithm, |_| {})
    }

    /// [`issue_seal`](Self::issue_seal), with `customise` changing the
    /// certificate parameters before issuance.
    pub fn issue_seal_with(
        &self,
        algorithm: SigningAlgorithm,
        customise: impl FnOnce(&mut CertificateParams),
    ) -> Result<TestSeal, TestPkiError> {
        let private_jwk = seal_key(algorithm)?;
        let public_key = JwkPublicKey::from_private(&private_jwk)?;
        let mut params = base_params()?;
        let mut name = DistinguishedName::new();
        name.push(DnType::OrganizationName, TEST_SEAL_ORGANIZATION);
        name.push(DnType::CommonName, "Registry Stack Test Seal");
        params.distinguished_name = name;
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        customise(&mut params);
        let certificate = params.signed_by(&public_key, &self.issuing_ca.issuer)?;
        Ok(TestSeal {
            certificate_der: certificate.der().to_vec(),
            issuing_ca_der: self.issuing_ca.certificate_der.clone(),
            private_jwk,
        })
    }

    /// Issue another timestamp authority certificate under the root, with
    /// `customise` changing the parameters before issuance. The critical
    /// extended key usage is in `custom_extensions`.
    pub fn issue_tsa_with(
        &self,
        customise: impl FnOnce(&mut CertificateParams),
    ) -> Result<TestTsa, TestPkiError> {
        issue_tsa(&self.root, customise)
    }
}

impl TestSeal {
    /// The seal certificate, DER encoded.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// The seal's private key.
    #[must_use]
    pub fn private_jwk(&self) -> &PrivateJwk {
        &self.private_jwk
    }

    /// A signer holding the seal's private key.
    pub fn signer(&self) -> Result<LocalJwkSigner, SigningError> {
        LocalJwkSigner::new(self.private_jwk.clone())
    }

    /// The seal certificate then the issuing CA, as PEM.
    #[must_use]
    pub fn chain_pem(&self) -> String {
        pem_block("CERTIFICATE", &self.certificate_der)
            + &pem_block("CERTIFICATE", &self.issuing_ca_der)
    }

    /// The seal's [`CertificateChain`].
    pub fn chain(&self) -> Result<CertificateChain, CertificateError> {
        CertificateChain::from_pem(self.chain_pem().as_bytes())
    }
}

impl TestTsa {
    /// The timestamp authority certificate, DER encoded.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}

/// Answer a DER `TimeStampReq` as the test PKI's timestamp authority, with a
/// granted token at `gen_time` carrying the request's imprint and nonce.
pub fn respond_to_timestamp_request(
    request_der: &[u8],
    pki: &TestPki,
    gen_time: OffsetDateTime,
) -> Result<Vec<u8>, TestPkiError> {
    respond_with(request_der, pki.tsa(), gen_time, |_| {})
}

/// [`respond_to_timestamp_request`], with the token's signer carrying
/// `signing_certificate` as its ESS signing-certificate attribute.
pub fn respond_to_timestamp_request_with(
    request_der: &[u8],
    pki: &TestPki,
    gen_time: OffsetDateTime,
    signing_certificate: EssAttribute,
) -> Result<Vec<u8>, TestPkiError> {
    respond_with(request_der, pki.tsa(), gen_time, |parts| {
        parts.signing_certificate = signing_certificate;
    })
}

/// Answer a DER `TimeStampReq` as a timestamp authority that refuses it:
/// status `rejection` (2) and no token.
pub fn refuse_timestamp_request(
    request_der: &[u8],
    pki: &TestPki,
) -> Result<Vec<u8>, TestPkiError> {
    respond_with(request_der, pki.tsa(), OffsetDateTime::now_utc(), |parts| {
        parts.status = 2;
        parts.include_token = false;
    })
}

/// What [`verify_detached_signature`] established about a detached CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedDetachedSignature {
    /// The fingerprint of the certificate whose key the signature verified
    /// under.
    pub signer_fingerprint: CertificateFingerprint,
    /// The verified `genTime` of the signature timestamp token, when the
    /// signer carries one.
    pub timestamp_gen_time: Option<OffsetDateTime>,
}

/// Verify a detached CMS signature over `content_parts` as a test's relying
/// party: the one signer verifies over the parts under the certificate the
/// signed data names, and a signature timestamp token, when present, covers
/// that signature value and verifies under a timestamping certificate valid
/// at its time. It validates no path to a trust anchor and checks no
/// revocation, like the rest of this module.
pub fn verify_detached_signature(
    cms_der: &[u8],
    content_parts: &[&[u8]],
) -> Result<VerifiedDetachedSignature, CmsError> {
    let signed_data = decode_signed_data(cms_der).ok_or(CmsError::MalformedSignedData)?;
    let certificate =
        verify_signed_data(&signed_data, content_parts).map_err(CmsError::SelfVerification)?;
    let signer_fingerprint = CertificateFingerprint::of(&certificate.to_der()?);
    let signer = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(CmsError::MalformedSignedData)?;
    let token = signer
        .unsigned_attrs
        .as_ref()
        .and_then(|attributes| single_attribute(attributes, oid::SIGNATURE_TIME_STAMP_TOKEN));
    let timestamp_gen_time = match token {
        None => None,
        Some(token) => {
            let token = token
                .decode_as::<cms::content_info::ContentInfo>()
                .map_err(|_| CmsError::MalformedTimestampToken)?;
            let token = read_token(&token).map_err(CmsError::TimestampRefused)?;
            check_imprint(&token.tst_info, signer.signature.as_bytes())
                .map_err(|_| CmsError::TimestampMismatch)?;
            Some(verify_token(&token).map_err(CmsError::TimestampRefused)?)
        }
    };
    Ok(VerifiedDetachedSignature {
        signer_fingerprint,
        timestamp_gen_time,
    })
}

/// The parts of a timestamp response, for tests that make it wrong.
pub(super) struct ResponseParts {
    pub(super) status: u32,
    pub(super) include_token: bool,
    pub(super) include_certificates: bool,
    pub(super) tamper_signature: bool,
    pub(super) econtent_type: ObjectIdentifier,
    pub(super) tst_info: TstInfo,
    pub(super) signing_certificate: EssAttribute,
}

/// The ESS signing-certificate attribute a test token's signer carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EssAttribute {
    /// signingCertificateV2 naming the authority's certificate by SHA-256,
    /// issuer and serial number.
    V2,
    /// signingCertificate naming the authority's certificate by SHA-1,
    /// issuer and serial number.
    V1,
    /// Neither attribute.
    Absent,
    /// signingCertificateV2 whose hash is over other bytes.
    OtherCertificate,
    /// signingCertificate whose hash is over other bytes.
    V1OtherCertificate,
    /// signingCertificateV2 with the right hash and another serial number.
    OtherIssuerSerial,
}

/// Answer `request_der` as `tsa`, with `customise` changing the response
/// before it is signed and encoded.
pub(super) fn respond_with(
    request_der: &[u8],
    tsa: &TestTsa,
    gen_time: OffsetDateTime,
    customise: impl FnOnce(&mut ResponseParts),
) -> Result<Vec<u8>, TestPkiError> {
    let request = TimeStampReq::from_der(request_der)?;
    let mut parts = ResponseParts {
        status: 0,
        include_token: true,
        include_certificates: request.cert_req == Some(true),
        tamper_signature: false,
        econtent_type: oid::TST_INFO,
        signing_certificate: EssAttribute::V2,
        tst_info: TstInfo {
            version: 1,
            policy: TEST_TSA_POLICY.into(),
            message_imprint: request.message_imprint,
            serial_number: Int::new(&random_serial()?)?,
            gen_time: TspGeneralizedTime::new(gen_time),
            accuracy: Some(Accuracy {
                seconds: Some(Int::new(&[1])?),
                millis: None,
                micros: None,
            }),
            ordering: None,
            nonce: request.nonce.map(Int::from),
            tsa: None,
            extensions: None,
        },
    };
    customise(&mut parts);
    let time_stamp_token = if parts.include_token {
        Some(timestamp_token(&parts, tsa)?)
    } else {
        None
    };
    let response = TimeStampResp {
        status: PkiStatusInfo {
            status: parts.status,
            status_string: None,
            fail_info: None,
        },
        time_stamp_token,
    };
    Ok(response.to_der()?)
}

fn timestamp_token(
    parts: &ResponseParts,
    tsa: &TestTsa,
) -> Result<cms::content_info::ContentInfo, TestPkiError> {
    let tst_info_der = parts.tst_info.to_der()?;
    let certificate = Certificate::from_der(&tsa.certificate_der)?;
    let digest = DigestAlgorithm::Sha256;
    let signed_attrs = signed_attributes(
        parts.econtent_type,
        digest,
        &digest.digest(&[&tst_info_der]),
        &tsa.certificate_der,
        &certificate,
    )?;
    let signed_attrs = with_signing_certificate(
        signed_attrs,
        parts.signing_certificate,
        &tsa.certificate_der,
        &certificate,
    )?;
    let jws = sign(&signed_attrs.to_der()?, &tsa.private_jwk)?;
    let mut signature = jws_ecdsa_to_der(&jws, 32)?;
    if parts.tamper_signature {
        if let Some(last) = signature.last_mut() {
            *last ^= 0x01;
        }
    }
    let certificates = if parts.include_certificates {
        vec![certificate.clone()]
    } else {
        Vec::new()
    };
    let signed_data = assemble_signed_data(
        digest,
        EncapsulatedContentInfo {
            econtent_type: parts.econtent_type,
            econtent: Some(Any::new(Tag::OctetString, tst_info_der)?),
        },
        &certificates,
        &certificate,
        signed_attrs,
        ecdsa_with_sha256(),
        signature,
    )?;
    Ok(content_info(&signed_data)?)
}

/// Replace the signingCertificateV2 that [`signed_attributes`] writes with
/// the attribute `choice` names.
fn with_signing_certificate(
    signed_attrs: x509_cert::attr::Attributes,
    choice: EssAttribute,
    certificate_der: &[u8],
    certificate: &Certificate,
) -> Result<x509_cert::attr::Attributes, TestPkiError> {
    if choice == EssAttribute::V2 {
        return Ok(signed_attrs);
    }
    let mut attributes: Vec<_> = signed_attrs
        .into_vec()
        .into_iter()
        .filter(|attribute| attribute.oid != oid::SIGNING_CERTIFICATE_V2)
        .collect();
    let issuer_serial = || IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(
            certificate.tbs_certificate.issuer.clone(),
        )],
        serial_number: certificate.tbs_certificate.serial_number.clone(),
    };
    let v2 = |hash: Vec<u8>, issuer_serial: IssuerSerial| -> Result<_, TestPkiError> {
        Ok((
            oid::SIGNING_CERTIFICATE_V2,
            Any::encode_from(&SigningCertificateV2 {
                certs: vec![EssCertIdV2 {
                    hash_algorithm: None,
                    cert_hash: OctetString::new(hash)?,
                    issuer_serial: Some(issuer_serial),
                }],
                policies: None,
            })?,
        ))
    };
    let v1 = |hash: &[u8]| -> Result<_, TestPkiError> {
        Ok((
            oid::SIGNING_CERTIFICATE,
            Any::encode_from(&SigningCertificate {
                certs: vec![EssCertId {
                    cert_hash: OctetString::new(hash)?,
                    issuer_serial: Some(issuer_serial()),
                }],
                policies: None,
            })?,
        ))
    };
    let sha1 = |bytes: &[u8]| {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, bytes)
            .as_ref()
            .to_vec()
    };
    let sha256 = |bytes: &[u8]| DigestAlgorithm::Sha256.digest(&[bytes]);
    let added = match choice {
        EssAttribute::V2 | EssAttribute::Absent => None,
        EssAttribute::V1 => Some(v1(&sha1(certificate_der))?),
        EssAttribute::OtherCertificate => {
            Some(v2(sha256(b"another certificate"), issuer_serial())?)
        }
        EssAttribute::V1OtherCertificate => Some(v1(&sha1(b"another certificate"))?),
        EssAttribute::OtherIssuerSerial => {
            let mut other = issuer_serial();
            other.serial_number = x509_cert::serial_number::SerialNumber::new(&[0x7f; 8])?;
            Some(v2(sha256(certificate_der), other)?)
        }
    };
    if let Some((oid, value)) = added {
        attributes.push(x509_cert::attr::Attribute {
            oid,
            values: der::asn1::SetOfVec::try_from(vec![value])?,
        });
    }
    Ok(der::asn1::SetOfVec::try_from(attributes)?)
}

fn ecdsa_with_sha256() -> x509_cert::spki::AlgorithmIdentifierOwned {
    x509_cert::spki::AlgorithmIdentifierOwned {
        oid: oid::ECDSA_WITH_SHA256,
        parameters: None,
    }
}

/// A critical extended key usage extension with exactly `purposes`, for
/// `CertificateParams::custom_extensions`. rcgen writes its own extended key
/// usage as non-critical, which RFC 3161 refuses for a timestamp authority.
pub fn critical_extended_key_usage(
    purposes: &[ObjectIdentifier],
) -> Result<CustomExtension, TestPkiError> {
    let content = ExtendedKeyUsage(purposes.to_vec()).to_der()?;
    let mut extension = CustomExtension::from_oid_content(&[2, 5, 29, 37], content);
    extension.set_criticality(true);
    Ok(extension)
}

/// PEM-encode `der` under `label`, in 64-character lines (RFC 7468).
#[must_use]
pub fn pem_block(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn issue_tsa(
    root: &TestCa,
    customise: impl FnOnce(&mut CertificateParams),
) -> Result<TestTsa, TestPkiError> {
    let private_jwk = generate_private_jwk(GeneratedKeyAlgorithm::Es256)?;
    let public_key = JwkPublicKey::from_private(&private_jwk)?;
    let mut params = base_params()?;
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Registry Stack Test PKI");
    name.push(
        DnType::CommonName,
        "Registry Stack Test Timestamp Authority",
    );
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.custom_extensions = vec![critical_extended_key_usage(&[oid::KP_TIME_STAMPING])?];
    customise(&mut params);
    let certificate = params.signed_by(&public_key, &root.issuer)?;
    Ok(TestTsa {
        certificate_der: certificate.der().to_vec(),
        private_jwk,
    })
}

fn ca_params(common_name: &str) -> Result<CertificateParams, TestPkiError> {
    let mut params = base_params()?;
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Registry Stack Test PKI");
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

/// Valid from an hour ago for ten years, with a random serial number and an
/// authority key identifier.
fn base_params() -> Result<CertificateParams, TestPkiError> {
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(3650);
    params.serial_number = Some(SerialNumber::from_slice(&random_serial()?));
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

/// Sixteen random bytes, positive and without a leading zero byte.
fn random_serial() -> Result<[u8; 16], TestPkiError> {
    let mut serial = [0u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| TestPkiError::RandomUnavailable)?;
    serial[0] = (serial[0] & 0x7f) | 0x40;
    Ok(serial)
}

fn seal_key(algorithm: SigningAlgorithm) -> Result<PrivateJwk, TestPkiError> {
    Ok(match algorithm {
        SigningAlgorithm::Es256 => generate_private_jwk(GeneratedKeyAlgorithm::Es256)?,
        SigningAlgorithm::Es384 => generate_private_jwk(GeneratedKeyAlgorithm::Es384)?,
        SigningAlgorithm::Rs384 => generate_private_jwk(GeneratedKeyAlgorithm::Rs384)?,
        // The generator writes RSA keys as RS384; the key itself serves
        // either hash, and the thumbprint `kid` does not cover `alg`.
        SigningAlgorithm::Rs256 => {
            let mut jwk = generate_private_jwk(GeneratedKeyAlgorithm::Rs384)?;
            jwk.alg = Some(SigningAlgorithm::Rs256.jwa_name().to_owned());
            jwk
        }
        SigningAlgorithm::EdDsa => return Err(TestPkiError::UnsupportedAlgorithm),
    })
}

/// A JWK's public half as rcgen's subject public key: the SEC 1 point for
/// ECDSA, the PKCS #1 `RSAPublicKey` for RSA.
struct JwkPublicKey {
    key_bits: Vec<u8>,
    algorithm: &'static SignatureAlgorithm,
}

impl JwkPublicKey {
    fn from_private(jwk: &PrivateJwk) -> Result<Self, TestPkiError> {
        let member = |value: &Option<String>| -> Result<Vec<u8>, TestPkiError> {
            let value = value.as_deref().ok_or(TestPkiError::UnsupportedAlgorithm)?;
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| TestPkiError::UnsupportedAlgorithm)
        };
        let ec_point = || -> Result<Vec<u8>, TestPkiError> {
            Ok([vec![0x04], member(&jwk.x)?, member(&jwk.y)?].concat())
        };
        let algorithm = jwk.algorithm().map_err(CryptoError::from)?;
        let (key_bits, algorithm) = match algorithm {
            SigningAlgorithm::Es256 => (ec_point()?, &rcgen::PKCS_ECDSA_P256_SHA256),
            SigningAlgorithm::Es384 => (ec_point()?, &rcgen::PKCS_ECDSA_P384_SHA384),
            SigningAlgorithm::Rs256 | SigningAlgorithm::Rs384 => {
                let n = member(&jwk.n)?;
                let e = member(&jwk.e)?;
                let key = pkcs1::RsaPublicKey {
                    modulus: UintRef::new(&n)?,
                    public_exponent: UintRef::new(&e)?,
                };
                (key.to_der()?, &rcgen::PKCS_RSA_SHA256)
            }
            SigningAlgorithm::EdDsa => return Err(TestPkiError::UnsupportedAlgorithm),
        };
        Ok(Self {
            key_bits,
            algorithm,
        })
    }
}

impl PublicKeyData for JwkPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.key_bits
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}
