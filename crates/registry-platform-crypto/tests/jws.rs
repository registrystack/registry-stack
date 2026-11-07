// SPDX-License-Identifier: Apache-2.0
//! Compact JWS signing and verification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use registry_platform_crypto::jws::{parse_compact_jws, sign_compact_jws, JwsError, JwsLimits};
use registry_platform_crypto::{
    generate_private_jwk, GeneratedKeyAlgorithm, LocalJwkSigner, PublicJwk, SigningAlgorithm,
    SigningProvider,
};
use serde_json::{json, Map, Value};

fn signer(algorithm: GeneratedKeyAlgorithm) -> LocalJwkSigner {
    LocalJwkSigner::new(generate_private_jwk(algorithm).expect("generate")).expect("signer")
}

fn extra(value: Value) -> Map<String, Value> {
    value.as_object().expect("object").clone()
}

fn limits() -> JwsLimits {
    JwsLimits::default()
}

fn sign_raw(signer: &LocalJwkSigner, header: &str, payload: &[u8]) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    let signature = futures_block(signer.sign(input.as_bytes())).expect("sign");
    format!("{input}.{}", B64.encode(signature))
}

fn futures_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(f)
}

#[tokio::test]
async fn sign_then_verify_with_extra_header_members() {
    for (algorithm, expected) in [
        (GeneratedKeyAlgorithm::Es256, SigningAlgorithm::Es256),
        (GeneratedKeyAlgorithm::Ed25519, SigningAlgorithm::EdDsa),
    ] {
        let signer = signer(algorithm);
        let token = sign_compact_jws(
            extra(json!({"typ": "oauth-authz-req+jwt", "x5c": ["AAAA"]})),
            b"{\"hello\":\"world\"}",
            &signer,
        )
        .await
        .expect("sign");
        let parsed = parse_compact_jws(&token, &limits()).expect("parse");
        assert_eq!(parsed.algorithm().expect("alg"), expected);
        assert_eq!(parsed.header()["typ"], "oauth-authz-req+jwt");
        assert_eq!(parsed.header()["x5c"], json!(["AAAA"]));
        assert_eq!(parsed.header()["kid"], signer.key_id());
        let payload = parsed
            .verify(&signer.public_jwk(), &[expected])
            .expect("verify");
        assert_eq!(payload, b"{\"hello\":\"world\"}");
    }
}

#[tokio::test]
async fn sign_refuses_caller_supplied_alg_kid_crit_and_b64() {
    let signer = signer(GeneratedKeyAlgorithm::Es256);
    for member in ["alg", "kid", "crit", "b64"] {
        let mut header = Map::new();
        header.insert(member.to_owned(), json!("x"));
        let err = sign_compact_jws(header, b"p", &signer)
            .await
            .expect_err(member);
        assert!(
            matches!(err, JwsError::ReservedHeader | JwsError::UnsupportedHeader),
            "{member}: {err:?}"
        );
    }
}

#[tokio::test]
async fn verify_refuses_wrong_key_algorithm_and_outside_allow_list() {
    let es = signer(GeneratedKeyAlgorithm::Es256);
    let ed = signer(GeneratedKeyAlgorithm::Ed25519);
    let token = sign_compact_jws(Map::new(), b"p", &es).await.expect("sign");
    let parsed = parse_compact_jws(&token, &limits()).expect("parse");
    // Header says ES256, key is Ed25519.
    assert_eq!(
        parsed
            .verify(
                &ed.public_jwk(),
                &[SigningAlgorithm::Es256, SigningAlgorithm::EdDsa]
            )
            .unwrap_err(),
        JwsError::AlgorithmMismatch
    );
    // Right key, but ES256 is not allowed.
    assert_eq!(
        parsed
            .verify(&es.public_jwk(), &[SigningAlgorithm::EdDsa])
            .unwrap_err(),
        JwsError::AlgorithmNotAllowed
    );
    assert_eq!(
        parsed.verify(&es.public_jwk(), &[]).unwrap_err(),
        JwsError::AlgorithmNotAllowed
    );
}

#[tokio::test]
async fn verify_refuses_tampered_signature_payload_and_other_key() {
    let es = signer(GeneratedKeyAlgorithm::Es256);
    let other = signer(GeneratedKeyAlgorithm::Es256);
    let token = sign_compact_jws(Map::new(), b"payload", &es)
        .await
        .expect("sign");
    let allowed = [SigningAlgorithm::Es256];

    let parts: Vec<&str> = token.split('.').collect();
    let mut sig = B64.decode(parts[2]).expect("sig");
    sig[0] ^= 1;
    let tampered = format!("{}.{}.{}", parts[0], parts[1], B64.encode(sig));
    let parsed = parse_compact_jws(&tampered, &limits()).expect("parse");
    assert_eq!(
        parsed.verify(&es.public_jwk(), &allowed).unwrap_err(),
        JwsError::SignatureInvalid
    );

    let swapped = format!("{}.{}.{}", parts[0], B64.encode(b"other"), parts[2]);
    let parsed = parse_compact_jws(&swapped, &limits()).expect("parse");
    assert_eq!(
        parsed.verify(&es.public_jwk(), &allowed).unwrap_err(),
        JwsError::SignatureInvalid
    );

    let parsed = parse_compact_jws(&token, &limits()).expect("parse");
    assert_eq!(
        parsed.verify(&other.public_jwk(), &allowed).unwrap_err(),
        JwsError::SignatureInvalid
    );
}

#[test]
fn refuses_alg_none_crit_b64_and_unknown_algorithms() {
    let es = signer(GeneratedKeyAlgorithm::Es256);
    let allowed = [SigningAlgorithm::Es256, SigningAlgorithm::EdDsa];
    let key: PublicJwk = es.public_jwk();

    for alg in ["none", "None", "HS256", "PS256", "ES512", ""] {
        let token = sign_raw(&es, &format!(r#"{{"alg":"{alg}"}}"#), b"p");
        let parsed = parse_compact_jws(&token, &limits()).expect("parse");
        assert_eq!(
            parsed.algorithm().unwrap_err(),
            JwsError::UnsupportedAlgorithm,
            "{alg}"
        );
        assert_eq!(
            parsed.verify(&key, &allowed).unwrap_err(),
            JwsError::UnsupportedAlgorithm,
            "{alg}"
        );
    }
    // Missing and non-string alg.
    for header in [r#"{"kid":"k"}"#, r#"{"alg":5}"#, r#"{"alg":null}"#] {
        let token = sign_raw(&es, header, b"p");
        let parsed = parse_compact_jws(&token, &limits()).expect("parse");
        assert_eq!(
            parsed.verify(&key, &allowed).unwrap_err(),
            JwsError::UnsupportedAlgorithm,
            "{header}"
        );
    }
    for header in [
        r#"{"alg":"ES256","crit":["exp"],"exp":1}"#,
        r#"{"alg":"ES256","crit":[]}"#,
        r#"{"alg":"ES256","b64":false}"#,
        r#"{"alg":"ES256","b64":true}"#,
    ] {
        let token = sign_raw(&es, header, b"p");
        assert_eq!(
            parse_compact_jws(&token, &limits()).unwrap_err(),
            JwsError::UnsupportedHeader,
            "{header}"
        );
    }
}

#[test]
fn refuses_duplicate_header_members_and_non_object_headers() {
    let es = signer(GeneratedKeyAlgorithm::Es256);
    let token = sign_raw(&es, r#"{"alg":"ES256","alg":"ES256"}"#, b"p");
    assert_eq!(
        parse_compact_jws(&token, &limits()).unwrap_err(),
        JwsError::InvalidHeader
    );
    for header in ["[]", "\"ES256\"", "null", "{", "{\"alg\":\"ES256\"} x"] {
        let token = sign_raw(&es, header, b"p");
        assert_eq!(
            parse_compact_jws(&token, &limits()).unwrap_err(),
            JwsError::InvalidHeader,
            "{header}"
        );
    }
}

#[test]
fn refuses_malformed_compact_forms() {
    let l = limits();
    for token in [
        "",
        "a",
        "a.b",
        "a.b.c.d",
        "..",
        "a..c",
        ".b.c",
        "a.b.",
        "a b.c.d",
        "e30.e30.@@@",
        "e30=.e30.AA",
        "e30.e30.AA=",
    ] {
        assert!(parse_compact_jws(token, &l).is_err(), "{token:?}");
    }
    // A JWS JSON serialization is not compact.
    assert!(parse_compact_jws(r#"{"payload":"e30"}"#, &l).is_err());
}

#[test]
fn bounds_sizes_before_decoding() {
    let es = signer(GeneratedKeyAlgorithm::Es256);
    let small = JwsLimits {
        max_compact_bytes: 10_000,
        max_header_bytes: 64,
        max_payload_bytes: 128,
    };
    let ok = sign_raw(&es, r#"{"alg":"ES256"}"#, &[b'a'; 100]);
    assert!(parse_compact_jws(&ok, &small).is_ok());

    let big_payload = sign_raw(&es, r#"{"alg":"ES256"}"#, &[b'a'; 129]);
    assert_eq!(
        parse_compact_jws(&big_payload, &small).unwrap_err(),
        JwsError::TooLarge
    );
    let padding = " ".repeat(64);
    let big_header = sign_raw(&es, &format!(r#"{{"alg":"ES256"{padding}}}"#), b"p");
    assert_eq!(
        parse_compact_jws(&big_header, &small).unwrap_err(),
        JwsError::TooLarge
    );
    let tiny = JwsLimits {
        max_compact_bytes: 20,
        ..small
    };
    assert_eq!(
        parse_compact_jws(&ok, &tiny).unwrap_err(),
        JwsError::TooLarge
    );
    // The check is on the encoded segment: undecodable garbage over the bound is
    // reported as too large, not as a decoding error.
    let garbage = format!("{}.{}.AA", B64.encode("{}"), "@".repeat(2000));
    assert_eq!(
        parse_compact_jws(&garbage, &small).unwrap_err(),
        JwsError::TooLarge
    );
    let long_sig = format!("e30.e30.{}", "A".repeat(2000));
    assert_eq!(
        parse_compact_jws(&long_sig, &limits()).unwrap_err(),
        JwsError::TooLarge
    );
}

#[tokio::test]
async fn errors_and_parsed_tokens_carry_no_token_or_key_material() {
    let es = signer(GeneratedKeyAlgorithm::Es256);
    let token = sign_compact_jws(extra(json!({"typ": "canary-typ"})), b"canary-payload", &es)
        .await
        .expect("sign");
    let parsed = parse_compact_jws(&token, &limits()).expect("parse");
    let debug = format!("{parsed:?}");
    let parts: Vec<&str> = token.split('.').collect();
    for secret in [parts[0], parts[1], parts[2], "canary-payload", "canary-typ"] {
        assert!(!debug.contains(secret), "Debug leaked {secret}");
    }

    let other = signer(GeneratedKeyAlgorithm::Ed25519);
    let err = parsed
        .verify(&other.public_jwk(), &[SigningAlgorithm::Es256])
        .unwrap_err();
    let rendered = format!("{err} {err:?}");
    for secret in parts.iter().copied().chain(["canary-payload"]) {
        assert!(!rendered.contains(secret));
    }
    let err = parse_compact_jws(&format!("{}.{}.", parts[0], parts[1]), &limits()).unwrap_err();
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains(parts[0]));
}
