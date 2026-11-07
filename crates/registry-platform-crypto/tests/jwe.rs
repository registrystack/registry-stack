// SPDX-License-Identifier: Apache-2.0
//! Compact JWE (`ECDH-ES`, P-256, AES-GCM) decryption.
//!
//! The reason of a failure is observable only with the `jwe-test-support`
//! feature; callers see one opaque category.
#![cfg(feature = "jwe-test-support")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use registry_platform_crypto::jwe::{
    decrypt_compact_ecdh_es, encrypt_compact_ecdh_es_for_tests, EcdhEsP256Key, JweEnc, JweError,
    JweFailureReason as R, JweLimits,
};
use serde_json::{json, Value};

const BOTH: [JweEnc; 2] = [JweEnc::A128Gcm, JweEnc::A256Gcm];

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/jwe-vectors.json")).unwrap()
}

/// The jwcrypto recipient. Its `kid` is the one the "-kid" vectors carry.
fn recipient() -> EcdhEsP256Key {
    let d = B64
        .decode(vectors()["recipient_private_jwk"]["d"].as_str().unwrap())
        .unwrap();
    EcdhEsP256Key::from_private_scalar(&d, "enc-1").unwrap()
}

fn limits() -> JweLimits {
    JweLimits::default()
}

fn decrypt(token: &str, key: &EcdhEsP256Key) -> Result<Vec<u8>, R> {
    decrypt_compact_ecdh_es(token, key, &BOTH, &limits())
        .map(|d| d.plaintext.to_vec())
        .map_err(|e| e.reason())
}

fn rewrite_header(compact: &str, f: impl FnOnce(&mut Value)) -> String {
    let mut p: Vec<String> = compact.split('.').map(String::from).collect();
    let mut h: Value = serde_json::from_slice(&B64.decode(&p[0]).unwrap()).unwrap();
    f(&mut h);
    p[0] = B64.encode(serde_json::to_vec(&h).unwrap());
    p.join(".")
}

fn case(index: usize) -> String {
    vectors()["cases"][index]["compact"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn tamper_segment(token: &str, index: usize) -> String {
    let mut p: Vec<String> = token.split('.').map(String::from).collect();
    let mut raw = B64.decode(&p[index]).unwrap();
    raw[0] ^= 1;
    p[index] = B64.encode(raw);
    p.join(".")
}

#[test]
fn jwcrypto_vectors_decrypt() {
    let v = vectors();
    let key = recipient();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let token = c["compact"].as_str().unwrap();
        let out = decrypt_compact_ecdh_es(token, &key, &BOTH, &limits())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            out.plaintext.as_slice(),
            c["plaintext"].as_str().unwrap().as_bytes(),
            "{name}"
        );
        let want_enc = if name.starts_with("A128") {
            JweEnc::A128Gcm
        } else {
            JweEnc::A256Gcm
        };
        assert_eq!(out.enc, want_enc, "{name}");
        if name.ends_with("apu_apv") {
            assert_eq!(out.apu, b"Alice");
            assert_eq!(out.apv, b"nonce-123");
        } else {
            assert!(out.apu.is_empty() && out.apv.is_empty(), "{name}");
        }
        assert_eq!(
            out.kid.as_deref(),
            name.ends_with("-kid").then_some("enc-1"),
            "{name}"
        );
    }
}

#[test]
fn round_trips_through_test_encrypt_for_both_enc_values() {
    let key = EcdhEsP256Key::generate("wallet-1").unwrap();
    for enc in BOTH {
        for (apu, apv) in [(&b""[..], &b""[..]), (b"mdoc-gen", b"nonce-xyz")] {
            let token = encrypt_compact_ecdh_es_for_tests(
                b"{\"vp_token\":{}}",
                &key.public_jwk(),
                enc,
                apu,
                apv,
                Some("wallet-1"),
            )
            .unwrap();
            assert_eq!(token.split('.').count(), 5);
            assert_eq!(token.split('.').nth(1), Some(""));
            let out = decrypt_compact_ecdh_es(&token, &key, &[enc], &limits()).unwrap();
            assert_eq!(out.plaintext.as_slice(), b"{\"vp_token\":{}}");
            assert_eq!(out.enc, enc);
            assert_eq!(out.apu, apu);
            assert_eq!(out.apv, apv);
            assert_eq!(out.kid.as_deref(), Some("wallet-1"));
        }
    }
}

#[test]
fn each_encryption_uses_a_fresh_ephemeral_key_and_iv() {
    let key = EcdhEsP256Key::generate("k").unwrap();
    let a =
        encrypt_compact_ecdh_es_for_tests(b"x", &key.public_jwk(), JweEnc::A128Gcm, b"", b"", None)
            .unwrap();
    let b =
        encrypt_compact_ecdh_es_for_tests(b"x", &key.public_jwk(), JweEnc::A128Gcm, b"", b"", None)
            .unwrap();
    assert_ne!(a, b);
}

#[test]
fn public_jwk_export_shape() {
    let key = EcdhEsP256Key::generate("enc-key-1").unwrap();
    let jwk = key.public_jwk();
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["use"], "enc");
    assert_eq!(jwk["alg"], "ECDH-ES");
    assert_eq!(jwk["kid"], "enc-key-1");
    assert_eq!(B64.decode(jwk["x"].as_str().unwrap()).unwrap().len(), 32);
    assert_eq!(B64.decode(jwk["y"].as_str().unwrap()).unwrap().len(), 32);
    assert_eq!(jwk.len(), 7, "no other members, and never `d`");
    assert!(key.thumbprint().unwrap().len() >= 43);
}

#[test]
fn from_pkcs8_der_round_trips() {
    let key = EcdhEsP256Key::generate("k").unwrap();
    let der = key.to_pkcs8_der_for_tests().unwrap();
    let loaded = EcdhEsP256Key::from_pkcs8_der(&der, "k").unwrap();
    assert_eq!(loaded.public_jwk(), key.public_jwk());
    assert!(EcdhEsP256Key::from_pkcs8_der(&der[..der.len() - 1], "k").is_err());
    assert!(EcdhEsP256Key::from_pkcs8_der(b"not der", "k").is_err());
    assert!(EcdhEsP256Key::from_private_scalar(&[0u8; 32], "k").is_err());
    assert!(EcdhEsP256Key::from_private_scalar(&[1u8; 31], "k").is_err());
}

#[test]
fn rejects_wrong_alg() {
    let key = recipient();
    let v = vectors();
    let r = decrypt(v["wrong_alg"].as_str().unwrap(), &key);
    // ECDH-ES+A128KW carries a non-empty encrypted key; either refusal is fine,
    // and neither may reach the cipher.
    assert!(
        matches!(r, Err(R::UnsupportedAlg | R::EncryptedKeyPresent)),
        "{r:?}"
    );
    for alg in ["dir", "RSA-OAEP", "ECDH-ES+A256KW", "none", "ecdh-es", ""] {
        let t = rewrite_header(&case(0), |h| h["alg"] = alg.into());
        assert_eq!(decrypt(&t, &key), Err(R::UnsupportedAlg), "{alg}");
    }
    let t = rewrite_header(&case(0), |h| h["alg"] = 5.into());
    assert_eq!(decrypt(&t, &key), Err(R::InvalidHeader));
    let t = rewrite_header(&case(0), |h| {
        h.as_object_mut().unwrap().remove("alg");
    });
    assert_eq!(decrypt(&t, &key), Err(R::InvalidHeader));
}

#[test]
fn rejects_wrong_enc_and_enc_outside_allow_list() {
    let key = recipient();
    let v = vectors();
    assert_eq!(
        decrypt(v["wrong_enc"].as_str().unwrap(), &key),
        Err(R::UnsupportedEnc)
    );
    for enc in ["A192GCM", "A128CBC-HS256", "none", ""] {
        let t = rewrite_header(&case(0), |h| h["enc"] = enc.into());
        assert_eq!(decrypt(&t, &key), Err(R::UnsupportedEnc), "{enc}");
    }
    // A128GCM vector, caller allows only A256GCM.
    let r = decrypt_compact_ecdh_es(&case(0), &key, &[JweEnc::A256Gcm], &limits());
    assert_eq!(r.unwrap_err().reason(), R::UnsupportedEnc);
    let r = decrypt_compact_ecdh_es(&case(0), &key, &[], &limits());
    assert_eq!(r.unwrap_err().reason(), R::UnsupportedEnc);
}

#[test]
fn rejects_tampered_tag_iv_ciphertext_and_header() {
    let key = recipient();
    let c = case(1); // A128GCM with apu and apv
    assert!(decrypt(&c, &key).is_ok());
    for idx in [2usize, 3, 4] {
        assert_eq!(
            decrypt(&tamper_segment(&c, idx), &key),
            Err(R::AuthenticationFailed),
            "segment {idx}"
        );
    }
    // apv feeds both the KDF and the AAD.
    let t = rewrite_header(&c, |h| h["apv"] = B64.encode(b"other").into());
    assert_eq!(decrypt(&t, &key), Err(R::AuthenticationFailed));
    // The AAD is the transmitted segment: the same JSON re-serialised fails.
    let t = rewrite_header(&c, |_| {});
    if t.split('.').next() != c.split('.').next() {
        assert_eq!(decrypt(&t, &key), Err(R::AuthenticationFailed));
    }
    // A header with an extra, ignored member changes the AAD.
    let t = rewrite_header(&c, |h| h["typ"] = "JWT".into());
    assert_eq!(decrypt(&t, &key), Err(R::AuthenticationFailed));
}

#[test]
fn rejects_wrong_key() {
    let v = vectors();
    let other = EcdhEsP256Key::from_private_scalar(&[7u8; 32], "enc-1").unwrap();
    assert_eq!(decrypt(&case(0), &other), Err(R::AuthenticationFailed));
    assert_eq!(
        decrypt(v["other_recipient"].as_str().unwrap(), &recipient()),
        Err(R::AuthenticationFailed)
    );
}

#[test]
fn rejects_epk_on_other_curve_off_curve_private_or_malformed() {
    let key = recipient();
    let v = vectors();
    assert_eq!(
        decrypt(v["other_curve"].as_str().unwrap(), &key),
        Err(R::InvalidEpk)
    );
    let c = case(0);
    let epk = |f: fn(&mut Value)| rewrite_header(&c, |h| f(&mut h["epk"]));
    let cases: Vec<(&str, String)> = vec![
        ("crv P-384", epk(|e| e["crv"] = "P-384".into())),
        ("crv P-256K", epk(|e| e["crv"] = "secp256k1".into())),
        ("kty OKP", epk(|e| e["kty"] = "OKP".into())),
        // 32-byte coordinates that are not a point on P-256.
        ("off curve", epk(|e| e["y"] = B64.encode([1u8; 32]).into())),
        (
            "zero point",
            epk(|e| {
                e["x"] = B64.encode([0u8; 32]).into();
                e["y"] = B64.encode([0u8; 32]).into();
            }),
        ),
        ("private d", epk(|e| e["d"] = "AA".into())),
        ("unknown member", epk(|e| e["extra"] = 1.into())),
        ("short x", epk(|e| e["x"] = B64.encode([1u8; 31]).into())),
        ("long y", epk(|e| e["y"] = B64.encode([1u8; 33]).into())),
        ("bad base64 x", epk(|e| e["x"] = "!!!".into())),
        ("x not string", epk(|e| e["x"] = 1.into())),
        (
            "missing y",
            epk(|e| {
                e.as_object_mut().unwrap().remove("y");
            }),
        ),
        ("epk not object", epk(|e| *e = "abc".into())),
    ];
    for (name, token) in cases {
        assert_eq!(decrypt(&token, &key), Err(R::InvalidEpk), "{name}");
    }
    let t = rewrite_header(&c, |h| {
        h.as_object_mut().unwrap().remove("epk");
    });
    assert_eq!(decrypt(&t, &key), Err(R::InvalidHeader));
}

#[test]
fn rejects_oversize_and_malformed_forms() {
    let key = recipient();
    let l = limits();
    let big = "a".repeat(l.max_compact_bytes + 1);
    assert_eq!(decrypt(&big, &key), Err(R::TooLarge));

    let c = case(0);
    for bad in [
        "",
        "a",
        "a.b.c",
        "a.b.c.d",
        "a.b.c.d.e.f",
        "....",
        &format!("{c}.x"),
    ] {
        assert_eq!(decrypt(bad, &key), Err(R::Malformed), "{bad:?}");
    }
    let parts: Vec<&str> = c.split('.').collect();
    // Non-empty encrypted key.
    let t = [parts[0], "AAAA", parts[2], parts[3], parts[4]].join(".");
    assert_eq!(decrypt(&t, &key), Err(R::EncryptedKeyPresent));
    // IV of the wrong length, tag of the wrong length, empty IV or tag.
    let short_iv = B64.encode([0u8; 11]);
    let long_iv = B64.encode([0u8; 13]);
    let short_tag = B64.encode([0u8; 15]);
    for iv in [short_iv.as_str(), long_iv.as_str(), ""] {
        let t = [parts[0], "", iv, parts[3], parts[4]].join(".");
        assert_eq!(decrypt(&t, &key), Err(R::Malformed), "iv {iv:?}");
    }
    for tag in [short_tag.as_str(), ""] {
        let t = [parts[0], "", parts[2], parts[3], tag].join(".");
        assert_eq!(decrypt(&t, &key), Err(R::Malformed), "tag {tag:?}");
    }
    // Segments that are not base64url.
    for idx in [0usize, 2, 3, 4] {
        let mut p = parts.clone();
        p[idx] = "@@@@";
        assert_eq!(
            decrypt(&p.join("."), &key),
            Err(R::Malformed),
            "segment {idx}"
        );
    }
    // Padding is not base64url without padding.
    let mut p = parts.clone();
    let padded = format!("{}=", parts[2]);
    p[2] = &padded;
    assert_eq!(decrypt(&p.join("."), &key), Err(R::Malformed));
}

#[test]
fn rejects_non_object_and_duplicate_member_headers() {
    let key = recipient();
    let parts: Vec<String> = case(0).split('.').map(String::from).collect();
    let rebuild = |header: &str| {
        [
            B64.encode(header).as_str(),
            "",
            &parts[2],
            &parts[3],
            &parts[4],
        ]
        .join(".")
    };
    for header in ["[]", "\"ECDH-ES\"", "null", "{", "{\"alg\":\"ECDH-ES\"} x"] {
        assert_eq!(
            decrypt(&rebuild(header), &key),
            Err(R::InvalidHeader),
            "{header}"
        );
    }
    let dup = r#"{"alg":"ECDH-ES","alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}"#;
    assert_eq!(decrypt(&rebuild(dup), &key), Err(R::InvalidHeader));
}

#[test]
fn rejects_zip_and_crit() {
    let key = recipient();
    let t = rewrite_header(&case(0), |h| h["zip"] = "DEF".into());
    assert_eq!(decrypt(&t, &key), Err(R::UnsupportedHeader));
    for crit in [json!(["exp"]), json!([]), json!("exp")] {
        let t = rewrite_header(&case(0), |h| h["crit"] = crit.clone());
        assert_eq!(decrypt(&t, &key), Err(R::UnsupportedHeader), "{crit}");
    }
}

#[test]
fn kid_when_present_must_equal_the_key_kid() {
    let key = recipient(); // kid "enc-1"
    assert!(decrypt(&case(2), &key).is_ok(), "matching kid decrypts");
    let other = EcdhEsP256Key::from_private_scalar(
        &B64.decode(vectors()["recipient_private_jwk"]["d"].as_str().unwrap())
            .unwrap(),
        "enc-2",
    )
    .unwrap();
    assert_eq!(decrypt(&case(2), &other), Err(R::KidMismatch));
    let t = rewrite_header(&case(0), |h| h["kid"] = 5.into());
    assert_eq!(decrypt(&t, &key), Err(R::InvalidHeader));
}

#[test]
fn bounds_header_party_info_and_plaintext() {
    let key = recipient();
    let tight = JweLimits {
        max_header_bytes: 64,
        ..limits()
    };
    let r = decrypt_compact_ecdh_es(&case(0), &key, &BOTH, &tight);
    assert_eq!(r.unwrap_err().reason(), R::TooLarge);

    let small_plaintext = JweLimits {
        max_plaintext_bytes: 1000,
        ..limits()
    };
    // The 20000 byte vector is refused from its segment length alone.
    let r = decrypt_compact_ecdh_es(&case(3), &key, &BOTH, &small_plaintext);
    assert_eq!(r.unwrap_err().reason(), R::TooLarge);
    assert!(decrypt_compact_ecdh_es(&case(0), &key, &BOTH, &small_plaintext).is_ok());

    let party = JweLimits {
        max_party_info_bytes: 4,
        ..limits()
    };
    let r = decrypt_compact_ecdh_es(&case(1), &key, &BOTH, &party);
    assert_eq!(r.unwrap_err().reason(), R::InvalidPartyInfo);
    let t = rewrite_header(&case(0), |h| h["apu"] = "@@@".into());
    assert_eq!(decrypt(&t, &key), Err(R::InvalidPartyInfo));
    let t = rewrite_header(&case(0), |h| h["apv"] = 7.into());
    assert_eq!(decrypt(&t, &key), Err(R::InvalidPartyInfo));
}

#[test]
fn failures_are_one_opaque_category_with_no_secret_text() {
    let key = recipient();
    let tampered = tamper_segment(&case(1), 3);
    let errs: Vec<JweError> = [
        tampered.clone(),
        "a.b.c".to_owned(),
        rewrite_header(&case(0), |h| h["alg"] = "dir".into()),
        rewrite_header(&case(0), |h| h["epk"]["crv"] = "P-384".into()),
    ]
    .iter()
    .map(|t| decrypt_compact_ecdh_es(t, &key, &BOTH, &limits()).unwrap_err())
    .collect();
    let first = errs[0].to_string();
    for e in &errs {
        assert_eq!(e.to_string(), first, "Display must not distinguish causes");
        assert_eq!(format!("{e:?}"), format!("{:?}", errs[0]), "nor Debug");
    }
    for part in tampered.split('.').filter(|p| p.len() > 8) {
        assert!(!first.contains(part));
    }
}

#[test]
fn key_and_plaintext_debug_carry_no_secret_bytes() {
    let d = [0x5au8; 32];
    let key = EcdhEsP256Key::from_private_scalar(&d, "kid-canary").unwrap();
    let debug = format!("{key:?}");
    let jwk = key.public_jwk();
    assert!(debug.contains("EcdhEsP256Key"));
    for secret in [
        B64.encode(d),
        "5a5a5a".to_owned(),
        jwk["x"].as_str().unwrap().to_owned(),
        jwk["y"].as_str().unwrap().to_owned(),
        "90, 90".to_owned(),
    ] {
        assert!(!debug.contains(&secret), "Debug leaked {secret}");
    }

    let wallet = EcdhEsP256Key::generate("w").unwrap();
    let token = encrypt_compact_ecdh_es_for_tests(
        b"plaintext-canary",
        &wallet.public_jwk(),
        JweEnc::A128Gcm,
        b"apu-canary",
        b"apv-canary",
        None,
    )
    .unwrap();
    let out = decrypt_compact_ecdh_es(&token, &wallet, &BOTH, &limits()).unwrap();
    let debug = format!("{out:?}");
    assert!(!debug.contains("plaintext-canary"));
    assert!(
        !debug.contains("112, 108"),
        "byte-array rendering of plaintext"
    );
}
