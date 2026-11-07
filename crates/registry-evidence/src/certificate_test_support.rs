//! Certificate chains for tests, generated with `rcgen` for a key the test
//! already holds. The platform signer holds the private key; the certificate
//! authority only ever sees its public half.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use registry_platform_crypto::PrivateJwk;
use time::{Duration, OffsetDateTime};

pub(crate) struct TestPki {
    pub(crate) root: CertifiedIssuer<'static, KeyPair>,
    pub(crate) intermediate: CertifiedIssuer<'static, KeyPair>,
}

fn validity(params: &mut CertificateParams, not_before: i64, not_after: i64) {
    params.not_before = OffsetDateTime::from_unix_timestamp(not_before).expect("time");
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after).expect("time");
}

fn authority(name: &str, path_len: Option<u8>, around: i64) -> CertificateParams {
    let mut params = CertificateParams::new(vec![]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = match path_len {
        Some(length) => IsCa::Ca(BasicConstraints::Constrained(length)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    validity(
        &mut params,
        around - Duration::days(30).whole_seconds(),
        around + Duration::days(365).whole_seconds(),
    );
    params
}

/// A root and one intermediate, both valid around `around` (Unix seconds).
pub(crate) fn pki(around: i64) -> TestPki {
    let root = CertifiedIssuer::self_signed(
        authority("evidence test root", None, around),
        KeyPair::generate().expect("key"),
    )
    .expect("root");
    let intermediate = CertifiedIssuer::signed_by(
        authority("evidence test intermediate", Some(0), around),
        KeyPair::generate().expect("key"),
        &root,
    )
    .expect("intermediate");
    TestPki { root, intermediate }
}

/// PKCS#8 for the P-256 private key a JWK holds, so a certificate authority
/// can certify exactly the key the platform signer signs with.
fn p256_pkcs8(private: &PrivateJwk) -> Vec<u8> {
    const PREFIX: [u8; 36] = [
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    const PUBLIC_PREFIX: [u8; 5] = [0xa1, 0x44, 0x03, 0x42, 0x00];
    let part = |value: &Option<String>| {
        URL_SAFE_NO_PAD
            .decode(value.as_deref().expect("JWK member"))
            .expect("base64url")
    };
    [
        PREFIX.as_slice(),
        part(&private.d).as_slice(),
        PUBLIC_PREFIX.as_slice(),
        [0x04].as_slice(),
        part(&private.x).as_slice(),
        part(&private.y).as_slice(),
    ]
    .concat()
}

/// The `x5c` chain (standard base64 DER, leaf first, then the intermediate)
/// certifying the JWK's key. `uris` become URI subject alternative names.
pub(crate) fn chain_for(
    pki: &TestPki,
    private: &PrivateJwk,
    uris: &[&str],
    not_before: i64,
    not_after: i64,
) -> Vec<String> {
    let key = KeyPair::try_from(p256_pkcs8(private).as_slice()).expect("key pair");
    let mut params = CertificateParams::new(vec![]).expect("params");
    for uri in uris {
        params
            .subject_alt_names
            .push(SanType::URI((*uri).try_into().expect("URI")));
    }
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "evidence test signer");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    validity(&mut params, not_before, not_after);
    let leaf = params
        .signed_by(&key, &pki.intermediate)
        .expect("leaf certificate");
    vec![
        STANDARD.encode(leaf.der()),
        STANDARD.encode(pki.intermediate.der()),
    ]
}

/// A PEM bundle of base64 DER certificates, as a bundle chain file holds them.
pub(crate) fn pem(x5c: &[String]) -> String {
    x5c.iter()
        .map(|der| {
            let lines = der
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).expect("base64"))
                .collect::<Vec<_>>()
                .join("\n");
            format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n")
        })
        .collect()
}
