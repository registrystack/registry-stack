// SPDX-License-Identifier: Apache-2.0
//! Chain validation against `rcgen` PKIs. `now` is passed explicitly, as production callers do.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};
use registry_platform_x509::{
    verify_chain, x509_hash, ChainPolicy, LeafKeyType, TrustAnchors, X509Error, X5cChain,
};
use time::{Duration, OffsetDateTime};

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d
}

fn ca_params(cn: &str, path_len: Option<u8>) -> CertificateParams {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name = dn(cn);
    p.is_ca = match path_len {
        Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = OffsetDateTime::now_utc() - Duration::days(30);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    p
}

fn leaf_params(cn: &str) -> CertificateParams {
    let mut p =
        CertificateParams::new(vec!["verifier.example".into(), "alt.example".into()]).unwrap();
    p.distinguished_name = dn(cn);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(30);
    p
}

struct Pki {
    root: CertifiedIssuer<'static, KeyPair>,
    inter: CertifiedIssuer<'static, KeyPair>,
}

fn pki(name: &str) -> Pki {
    let root = CertifiedIssuer::self_signed(
        ca_params(&format!("{name} root"), None),
        KeyPair::generate().unwrap(),
    )
    .unwrap();
    let inter = CertifiedIssuer::signed_by(
        ca_params(&format!("{name} intermediate"), Some(1)),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    Pki { root, inter }
}

fn leaf(p: &Pki, params: CertificateParams) -> Vec<u8> {
    params
        .signed_by(&KeyPair::generate().unwrap(), &p.inter)
        .unwrap()
        .der()
        .to_vec()
}

fn chain(ders: &[&[u8]]) -> X5cChain {
    let strings: Vec<String> = ders.iter().map(|d| B64.encode(d)).collect();
    X5cChain::parse(&strings).unwrap()
}

fn anchors(p: &Pki) -> TrustAnchors {
    TrustAnchors::from_der_certificates(&[p.root.der().to_vec()]).unwrap()
}

fn policy() -> ChainPolicy {
    ChainPolicy::default()
}

#[test]
fn valid_chain_to_configured_anchor() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("leaf"));
    let v = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap();
    assert_eq!(v.public_jwk.kty, "EC");
    assert_eq!(v.public_jwk.crv.as_deref(), Some("P-256"));
    assert_eq!(v.x509_hash, x509_hash(&l));
}

#[test]
fn chain_may_ship_the_configured_root() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("leaf"));
    verify_chain(
        &chain(&[&l, p.inter.der(), p.root.der()]),
        &anchors(&p),
        &policy(),
        now(),
    )
    .unwrap();
}

#[test]
fn leaf_issued_directly_by_anchor() {
    let root =
        CertifiedIssuer::self_signed(ca_params("r", None), KeyPair::generate().unwrap()).unwrap();
    let l = leaf_params("direct")
        .signed_by(&KeyPair::generate().unwrap(), &root)
        .unwrap();
    let a = TrustAnchors::from_der_certificates(&[root.der().to_vec()]).unwrap();
    let pol = ChainPolicy {
        max_path_length: 0,
        ..policy()
    };
    verify_chain(&chain(&[l.der()]), &a, &pol, now()).unwrap();
}

#[test]
fn ed25519_leaf_yields_okp_jwk() {
    let p = pki("a");
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let l = leaf_params("ed").signed_by(&key, &p.inter).unwrap();
    let v = verify_chain(
        &chain(&[l.der(), p.inter.der()]),
        &anchors(&p),
        &policy(),
        now(),
    )
    .unwrap();
    assert_eq!(v.public_jwk.kty, "OKP");
    assert_eq!(v.public_jwk.crv.as_deref(), Some("Ed25519"));
    let raw = key.public_key_raw();
    assert_eq!(
        v.public_jwk.x.as_deref(),
        Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(raw)
                .as_str()
        )
    );
}

#[test]
fn p256_leaf_coordinates_match_certificate_key() {
    let p = pki("a");
    let key = KeyPair::generate().unwrap();
    let l = leaf_params("ec").signed_by(&key, &p.inter).unwrap();
    let v = verify_chain(
        &chain(&[l.der(), p.inter.der()]),
        &anchors(&p),
        &policy(),
        now(),
    )
    .unwrap();
    let raw = key.public_key_raw();
    let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    assert_eq!(v.public_jwk.x.as_deref(), Some(enc(&raw[1..33]).as_str()));
    assert_eq!(v.public_jwk.y.as_deref(), Some(enc(&raw[33..65]).as_str()));
}

#[test]
fn ed25519_refused_when_policy_allows_only_p256() {
    let p = pki("a");
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let l = leaf_params("ed").signed_by(&key, &p.inter).unwrap();
    let pol = ChainPolicy {
        allowed_leaf_key_types: vec![LeafKeyType::P256],
        ..policy()
    };
    let e = verify_chain(&chain(&[l.der(), p.inter.der()]), &anchors(&p), &pol, now()).unwrap_err();
    assert_eq!(e, X509Error::LeafKeyTypeNotAllowed);
}

#[test]
fn p384_leaf_is_unsupported() {
    let p = pki("a");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let l = leaf_params("p384").signed_by(&key, &p.inter).unwrap();
    let e = verify_chain(
        &chain(&[l.der(), p.inter.der()]),
        &anchors(&p),
        &policy(),
        now(),
    )
    .unwrap_err();
    assert_eq!(e, X509Error::UnsupportedLeafKey);
}

#[test]
fn expired_leaf_is_refused() {
    let p = pki("a");
    let mut params = leaf_params("old");
    params.not_before = OffsetDateTime::now_utc() - Duration::days(60);
    params.not_after = OffsetDateTime::now_utc() - Duration::days(30);
    let l = leaf(&p, params);
    let e = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap_err();
    assert_eq!(e, X509Error::Expired);
}

#[test]
fn not_yet_valid_leaf_is_refused() {
    let p = pki("a");
    let mut params = leaf_params("future");
    params.not_before = OffsetDateTime::now_utc() + Duration::days(10);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(40);
    let l = leaf(&p, params);
    let e = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap_err();
    assert_eq!(e, X509Error::NotYetValid);
}

#[test]
fn verification_time_decides_validity() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("leaf"));
    let c = chain(&[&l, p.inter.der()]);
    let later = now() + 60 * 24 * 3600;
    assert_eq!(
        verify_chain(&c, &anchors(&p), &policy(), later).unwrap_err(),
        X509Error::Expired
    );
}

#[test]
fn negative_time_is_refused() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("leaf"));
    let e = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), -1).unwrap_err();
    assert_eq!(e, X509Error::InvalidTime);
}

#[test]
fn wrong_anchor_is_refused() {
    let p = pki("a");
    let other = pki("b");
    let l = leaf(&p, leaf_params("leaf"));
    let e = verify_chain(
        &chain(&[&l, p.inter.der()]),
        &anchors(&other),
        &policy(),
        now(),
    )
    .unwrap_err();
    assert_eq!(e, X509Error::UnknownIssuer);
}

#[test]
fn anchor_shipped_in_x5c_but_not_configured_never_counts() {
    let p = pki("a");
    let other = pki("b");
    let l = leaf(&p, leaf_params("leaf"));
    let c = chain(&[&l, p.inter.der(), p.root.der()]);
    let pol = ChainPolicy {
        max_path_length: 2,
        ..policy()
    };
    assert_eq!(
        verify_chain(&c, &anchors(&other), &pol, now()).unwrap_err(),
        X509Error::UnknownIssuer
    );
}

#[test]
fn missing_intermediate_is_refused() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("leaf"));
    let e = verify_chain(&chain(&[&l]), &anchors(&p), &policy(), now()).unwrap_err();
    assert_eq!(e, X509Error::UnknownIssuer);
}

#[test]
fn leaf_without_digital_signature_is_refused() {
    let p = pki("a");
    let mut params = leaf_params("enc");
    params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
    let l = leaf(&p, params);
    let e = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap_err();
    assert_eq!(e, X509Error::KeyUsage);
}

#[test]
fn leaf_without_key_usage_extension_is_refused() {
    let p = pki("a");
    let mut params = leaf_params("nku");
    params.key_usages = vec![];
    let l = leaf(&p, params);
    let e = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap_err();
    assert_eq!(e, X509Error::KeyUsage);
}

#[test]
fn ca_certificate_as_leaf_is_refused() {
    let p = pki("a");
    let e = verify_chain(&chain(&[p.inter.der()]), &anchors(&p), &policy(), now()).unwrap_err();
    assert_eq!(e, X509Error::CaAsLeaf);
}

#[test]
fn policy_path_length_is_enforced() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("leaf"));
    let pol = ChainPolicy {
        max_path_length: 0,
        ..policy()
    };
    let e = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &pol, now()).unwrap_err();
    assert_eq!(e, X509Error::PathLengthExceeded);
}

#[test]
fn two_intermediates_on_the_path_exceed_a_limit_of_one() {
    let root =
        CertifiedIssuer::self_signed(ca_params("r", None), KeyPair::generate().unwrap()).unwrap();
    let i1 = CertifiedIssuer::signed_by(ca_params("i1", None), KeyPair::generate().unwrap(), &root)
        .unwrap();
    let i2 = CertifiedIssuer::signed_by(ca_params("i2", None), KeyPair::generate().unwrap(), &i1)
        .unwrap();
    let l = leaf_params("deep")
        .signed_by(&KeyPair::generate().unwrap(), &i2)
        .unwrap();
    let a = TrustAnchors::from_der_certificates(&[root.der().to_vec()]).unwrap();
    for shipped in [
        vec![l.der().as_ref(), i2.der(), i1.der()],
        vec![l.der().as_ref(), i2.der(), i1.der(), root.der()],
    ] {
        let e = verify_chain(&chain(&shipped), &a, &policy(), now()).unwrap_err();
        assert_eq!(e, X509Error::PathLengthExceeded);
    }
    let two = ChainPolicy {
        max_path_length: 2,
        ..policy()
    };
    verify_chain(
        &chain(&[l.der(), i2.der(), i1.der(), root.der()]),
        &a,
        &two,
        now(),
    )
    .unwrap();
}

#[test]
fn certificate_path_length_constraint_is_enforced() {
    let root =
        CertifiedIssuer::self_signed(ca_params("r", None), KeyPair::generate().unwrap()).unwrap();
    let i1 = CertifiedIssuer::signed_by(
        ca_params("i1", Some(0)),
        KeyPair::generate().unwrap(),
        &root,
    )
    .unwrap();
    let i2 =
        CertifiedIssuer::signed_by(ca_params("i2", Some(0)), KeyPair::generate().unwrap(), &i1)
            .unwrap();
    let l = leaf_params("deep")
        .signed_by(&KeyPair::generate().unwrap(), &i2)
        .unwrap();
    let a = TrustAnchors::from_der_certificates(&[root.der().to_vec()]).unwrap();
    let pol = ChainPolicy {
        max_path_length: 4,
        ..policy()
    };
    let e = verify_chain(&chain(&[l.der(), i2.der(), i1.der()]), &a, &pol, now()).unwrap_err();
    assert_eq!(e, X509Error::PathLengthExceeded);
}

#[test]
fn san_dns_names_and_subject_are_extracted() {
    let p = pki("a");
    let l = leaf(&p, leaf_params("my leaf"));
    let v = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap();
    assert_eq!(v.san_dns_names, vec!["verifier.example", "alt.example"]);
    assert_eq!(v.subject, "CN=my leaf");
}

#[test]
fn san_uris_are_extracted() {
    let p = pki("a");
    let mut params = leaf_params("uri leaf");
    params.subject_alt_names.push(rcgen::SanType::URI(
        "https://issuer.example/tenant".try_into().unwrap(),
    ));
    let l = leaf(&p, params);
    let v = verify_chain(&chain(&[&l, p.inter.der()]), &anchors(&p), &policy(), now()).unwrap();
    assert_eq!(v.san_uris, vec!["https://issuer.example/tenant"]);
    assert_eq!(v.san_dns_names, vec!["verifier.example", "alt.example"]);
}

#[test]
fn error_display_carries_no_certificate_bytes() {
    let p = pki("a");
    let other = pki("b");
    let l = leaf(&p, leaf_params("secret-subject"));
    let e = verify_chain(
        &chain(&[&l, p.inter.der()]),
        &anchors(&other),
        &policy(),
        now(),
    )
    .unwrap_err();
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("secret-subject"));
    assert!(!shown.contains(&B64.encode(&l)[..40]));
}

const HASH_VECTOR_DER_B64: &str = include_str!("data/hash-vector-leaf.der.b64");
const HASH_VECTOR: &str = include_str!("data/hash-vector-leaf.x509_hash");

#[test]
fn x509_hash_matches_independently_computed_vector() {
    let der = B64.decode(HASH_VECTOR_DER_B64.trim()).unwrap();
    assert_eq!(x509_hash(&der), HASH_VECTOR.trim());
}
