// SPDX-License-Identifier: Apache-2.0
//! RFC 9901 presentation parsing, disclosure resolution, and key-binding policy.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::jws::{parse_compact_jws, JwsLimits};
use registry_platform_crypto::{sign, PrivateJwk, PublicJwk, SigningAlgorithm};
use registry_platform_sdjwt::{
    parse_presentation, resolve_disclosures, sd_hash, validate_key_binding_jwt_with_options,
    KeyBindingExtraClaims, KeyBindingOptions, KeyBindingPolicy, PresentationError, SdJwtError,
    SdJwtLimits,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

const RFC_PRESENTATION: &str = include_str!("data/rfc-9901-section-5-2-presentation.txt");
const EXTERNAL_VECTORS: &str = include_str!("data/external-sd-jwt-vectors.json");

/// The holder key of the RFC 9901 example. The RFC prints it without `alg`.
const RFC_HOLDER_JWK: &str = r#"{"kty":"EC","crv":"P-256","alg":"ES256","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc","y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}"#;
const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:jwk:holder#p256-key-1"}"#;
const ED25519_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:jwk:holder#key-1"}"#;

fn limits() -> SdJwtLimits {
    SdJwtLimits::default()
}

/// Encode one disclosure and return it with its sha-256 digest.
fn disclose(salt: &str, name: Option<&str>, value: Value) -> (String, String) {
    let array = match name {
        Some(name) => json!([salt, name, value]),
        None => json!([salt, value]),
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&array).expect("json"));
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
    (encoded, digest)
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn resolve(payload: Value, disclosures: &[&str]) -> Result<Map<String, Value>, SdJwtError> {
    resolve_disclosures(&object(payload), disclosures, &limits())
}

fn refused(result: Result<Map<String, Value>, SdJwtError>) -> PresentationError {
    match result {
        Err(SdJwtError::Presentation(err)) => err,
        other => panic!("expected a presentation refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[test]
fn parses_the_rfc_9901_presentation_with_a_key_binding_jwt() {
    let parsed = parse_presentation(RFC_PRESENTATION, &limits()).expect("parses");
    assert_eq!(parsed.disclosures.len(), 4);
    assert!(parsed.key_binding_jwt.is_some());
    assert_eq!(parsed.issuer_jwt.split('.').count(), 3);
    let boundary = RFC_PRESENTATION.rfind('~').unwrap();
    assert_eq!(parsed.sd_hash_input, &RFC_PRESENTATION[..=boundary]);
    assert_eq!(
        Some(parsed.sd_hash_input.len()),
        Some(boundary + 1),
        "the hash input includes the last tilde"
    );
}

#[test]
fn parses_a_presentation_without_a_key_binding_jwt() {
    let parsed = parse_presentation("a.b.c~d1~d2~", &limits()).expect("parses");
    assert_eq!(parsed.disclosures, vec!["d1", "d2"]);
    assert!(parsed.key_binding_jwt.is_none());
    assert_eq!(parsed.sd_hash_input, "a.b.c~d1~d2~");

    let bare = parse_presentation("a.b.c~", &limits()).expect("parses");
    assert!(bare.disclosures.is_empty());
}

#[test]
fn refuses_malformed_presentation_shapes() {
    for input in [
        "",
        "a.b.c",
        "~d1~",
        "a.b~d1~",
        "a.b.c.d~d1~",
        "a.b.c~~d1~",
        "a.b.c~d1~~kb.kb.kb",
        "a.b.c~d1~kb.kb",
    ] {
        assert!(
            matches!(
                parse_presentation(input, &limits()),
                Err(SdJwtError::Presentation(PresentationError::Malformed))
            ),
            "{input:?} must be malformed"
        );
    }
}

#[test]
fn bounds_size_and_disclosure_count_before_decoding() {
    let small = SdJwtLimits {
        max_serialized_bytes: 32,
        ..limits()
    };
    assert!(matches!(
        parse_presentation("a.b.c~aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa~", &small),
        Err(SdJwtError::Presentation(PresentationError::TooLarge))
    ));

    let few = SdJwtLimits {
        max_disclosures: 2,
        ..limits()
    };
    assert!(matches!(
        parse_presentation("a.b.c~d1~d2~d3~", &few),
        Err(SdJwtError::Presentation(
            PresentationError::TooManyDisclosures
        ))
    ));
    assert!(parse_presentation("a.b.c~d1~d2~", &few).is_ok());

    let narrow = SdJwtLimits {
        max_disclosure_bytes: 4,
        ..limits()
    };
    assert!(matches!(
        parse_presentation("a.b.c~abcdefgh~", &narrow),
        Err(SdJwtError::Presentation(PresentationError::TooLarge))
    ));
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

#[test]
fn resolves_the_rfc_9901_presentation() {
    let parsed = parse_presentation(RFC_PRESENTATION, &limits()).unwrap();
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parsed.issuer_jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    let claims = resolve_disclosures(payload.as_object().unwrap(), &parsed.disclosures, &limits())
        .expect("resolves");
    assert_eq!(claims["family_name"], "Doe");
    assert_eq!(claims["given_name"], "John");
    assert_eq!(claims["address"]["locality"], "Anytown");
    assert_eq!(claims["nationalities"], json!(["US"]));
    assert_eq!(claims["iss"], "https://issuer.example.com");
    assert!(claims.contains_key("cnf"));
    assert!(!claims.contains_key("_sd"));
    assert!(!claims.contains_key("_sd_alg"));
}

#[test]
fn rfc_9901_sd_hash_matches_the_key_binding_jwt() {
    let parsed = parse_presentation(RFC_PRESENTATION, &limits()).unwrap();
    assert_eq!(
        sd_hash(parsed.sd_hash_input),
        "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY"
    );
    assert_eq!(parsed.sd_hash(), sd_hash(parsed.sd_hash_input));
}

#[test]
fn rfc_9901_key_binding_jwt_validates_under_both_policies() {
    let parsed = parse_presentation(RFC_PRESENTATION, &limits()).unwrap();
    let kb = parsed.key_binding_jwt.unwrap();
    let holder = PublicJwk::parse(RFC_HOLDER_JWK).unwrap();
    let policy = KeyBindingPolicy {
        audience: "https://verifier.example.org".to_string(),
        nonce: "1234567890".to_string(),
        max_age: Duration::from_secs(300),
        max_future_skew: Duration::from_secs(30),
    };
    for options in [
        KeyBindingOptions::default(),
        KeyBindingOptions::third_party(),
    ] {
        let claims = validate_key_binding_jwt_with_options(
            kb,
            &holder,
            parsed.sd_hash_input,
            &policy,
            &options,
            1_748_537_244,
        )
        .expect("validates");
        assert_eq!(claims.nonce, "1234567890");
    }
}

#[test]
fn external_vectors_parse_resolve_and_verify_against_the_issuer_key() {
    let fixture: Value = serde_json::from_str(EXTERNAL_VECTORS).unwrap();
    let issuer = PublicJwk::parse(&fixture["issuer_public_jwk"].to_string()).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    for vector in vectors {
        let id = vector["id"].as_str().unwrap();
        let parsed = parse_presentation(vector["serialized"].as_str().unwrap(), &limits())
            .unwrap_or_else(|err| panic!("{id}: {err}"));
        let jws = parse_compact_jws(parsed.issuer_jwt, &JwsLimits::default()).unwrap();
        let payload = jws
            .verify(&issuer, &[SigningAlgorithm::Es256])
            .unwrap_or_else(|err| panic!("{id}: {err}"));
        let payload: Value = serde_json::from_slice(payload).unwrap();
        let claims =
            resolve_disclosures(payload.as_object().unwrap(), &parsed.disclosures, &limits())
                .unwrap_or_else(|err| panic!("{id}: {err}"));
        assert_eq!(claims["iss"], vector["issuer"], "{id}");
        for name in vector["disclosureNames"].as_array().unwrap() {
            assert!(claims.contains_key(name.as_str().unwrap()), "{id}: {name}");
        }
        assert!(!claims.contains_key("_sd"));
        assert!(!claims.contains_key("_sd_alg"));
    }
}

#[test]
fn resolves_object_disclosures_and_ignores_decoys() {
    let (a, da) = disclose("s1", Some("given_name"), json!("Ada"));
    let (b, db) = disclose("s2", Some("age"), json!(36));
    let claims = resolve(
        json!({"iss": "i", "_sd_alg": "sha-256", "_sd": [da, "decoy-digest-1", db, "decoy-digest-2"]}),
        &[&a, &b],
    )
    .unwrap();
    assert_eq!(claims["given_name"], "Ada");
    assert_eq!(claims["age"], 36);
    assert_eq!(claims.len(), 3);
}

#[test]
fn an_absent_sd_alg_means_sha_256_and_withheld_claims_stay_absent() {
    let (a, da) = disclose("s1", Some("given_name"), json!("Ada"));
    let claims = resolve(json!({"_sd": [da, "other"]}), &[]).unwrap();
    assert!(claims.is_empty());
    let claims = resolve(json!({"_sd": [da]}), &[&a]).unwrap();
    assert_eq!(claims["given_name"], "Ada");
}

#[test]
fn resolves_disclosures_in_nested_objects() {
    let (a, da) = disclose("s1", Some("street"), json!("1 Main"));
    let claims = resolve(
        json!({"address": {"country": "US", "_sd": [da]}, "_sd_alg": "sha-256"}),
        &[&a],
    )
    .unwrap();
    assert_eq!(
        claims["address"],
        json!({"country": "US", "street": "1 Main"})
    );
}

#[test]
fn resolves_array_element_disclosures_and_drops_decoy_elements() {
    let (a, da) = disclose("s1", None, json!("US"));
    let (b, db) = disclose("s2", None, json!("FR"));
    let claims = resolve(
        json!({"nationalities": [{"...": da}, "DE", {"...": "decoy"}, {"...": db}]}),
        &[&a, &b],
    )
    .unwrap();
    assert_eq!(claims["nationalities"], json!(["US", "DE", "FR"]));

    let claims = resolve(json!({"nationalities": [{"...": da}, {"...": db}]}), &[&a]).unwrap();
    assert_eq!(claims["nationalities"], json!(["US"]));
}

#[test]
fn resolves_recursive_disclosures() {
    let (inner, d_inner) = disclose("s1", Some("street"), json!("1 Main"));
    let (outer, d_outer) = disclose(
        "s2",
        Some("address"),
        json!({"city": "X", "_sd": [d_inner]}),
    );
    let (elem_inner, d_elem_inner) = disclose("s3", Some("code"), json!("ZZ"));
    let (elem, d_elem) = disclose("s4", None, json!({"_sd": [d_elem_inner]}));
    let claims = resolve(
        json!({"_sd": [d_outer], "list": [{"...": d_elem}]}),
        &[&inner, &outer, &elem_inner, &elem],
    )
    .unwrap();
    assert_eq!(claims["address"], json!({"city": "X", "street": "1 Main"}));
    assert_eq!(claims["list"], json!([{"code": "ZZ"}]));
}

#[test]
fn a_disclosed_array_can_hold_element_disclosures() {
    let (el, d_el) = disclose("s1", None, json!(1));
    let (arr, d_arr) = disclose("s2", Some("numbers"), json!([{"...": d_el}, 2]));
    let claims = resolve(json!({"_sd": [d_arr]}), &[&el, &arr]).unwrap();
    assert_eq!(claims["numbers"], json!([1, 2]));
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn refuses_an_unsupported_hash_algorithm() {
    for alg in [json!("sha-512"), json!("SHA-256"), json!(256), json!(null)] {
        assert_eq!(
            refused(resolve(json!({"_sd_alg": alg}), &[])),
            PresentationError::UnsupportedHashAlgorithm
        );
    }
}

#[test]
fn refuses_a_disclosure_referenced_twice() {
    let (a, da) = disclose("s1", Some("given_name"), json!("Ada"));
    assert_eq!(
        refused(resolve(json!({"_sd": [da, da]}), &[&a])),
        PresentationError::DuplicateDigest
    );
    assert_eq!(
        refused(resolve(
            json!({"_sd": [da], "nested": {"_sd": [da]}}),
            &[&a]
        )),
        PresentationError::DuplicateDigest
    );
    let (e, de) = disclose("s2", None, json!("US"));
    assert_eq!(
        refused(resolve(json!({"l": [{"...": de}, {"...": de}]}), &[&e])),
        PresentationError::DuplicateDigest
    );
}

#[test]
fn refuses_a_digest_appearing_twice_even_when_it_is_a_decoy() {
    assert_eq!(
        refused(resolve(json!({"_sd": ["x", "y", "x"]}), &[])),
        PresentationError::DuplicateDigest
    );
    assert_eq!(
        refused(resolve(json!({"_sd": ["x"], "o": {"_sd": ["x"]}}), &[])),
        PresentationError::DuplicateDigest
    );
}

#[test]
fn refuses_the_same_disclosure_presented_twice() {
    let (a, da) = disclose("s1", Some("given_name"), json!("Ada"));
    assert_eq!(
        refused(resolve(json!({"_sd": [da]}), &[&a, &a])),
        PresentationError::DuplicateDisclosure
    );
}

#[test]
fn refuses_an_unreferenced_disclosure() {
    let (a, _) = disclose("s1", Some("given_name"), json!("Ada"));
    assert_eq!(
        refused(resolve(json!({"_sd": ["something-else"]}), &[&a])),
        PresentationError::UnreferencedDisclosure
    );
}

#[test]
fn refuses_a_disclosed_name_that_exists_at_that_level() {
    let (a, da) = disclose("s1", Some("given_name"), json!("Ada"));
    assert_eq!(
        refused(resolve(json!({"given_name": "Bob", "_sd": [da]}), &[&a])),
        PresentationError::ClaimNameCollision
    );
    let (b, db) = disclose("s2", Some("given_name"), json!("Eve"));
    assert_eq!(
        refused(resolve(json!({"_sd": [da, db]}), &[&a, &b])),
        PresentationError::ClaimNameCollision
    );
}

#[test]
fn refuses_reserved_claim_names() {
    for name in ["_sd", "..."] {
        let (a, da) = disclose("s1", Some(name), json!("x"));
        assert_eq!(
            refused(resolve(json!({"_sd": [da]}), &[&a])),
            PresentationError::ReservedClaimName,
            "{name}"
        );
    }
}

#[test]
fn refuses_malformed_disclosures() {
    let encode = |value: Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    let cases = [
        encode(json!([])),
        encode(json!(["salt"])),
        encode(json!(["salt", "name", 1, 2])),
        encode(json!([1, "name", "value"])),
        encode(json!(["salt", 5, "value"])),
        encode(json!({"salt": "x"})),
        encode(json!("salt")),
        "not*base64".to_string(),
        URL_SAFE_NO_PAD.encode(b"{not json"),
        URL_SAFE_NO_PAD.encode(br#"["salt","name","a","name"#),
    ];
    for case in cases {
        assert_eq!(
            refused(resolve(json!({"_sd": ["x"]}), &[&case])),
            PresentationError::MalformedDisclosure,
            "{case}"
        );
    }
}

#[test]
fn refuses_a_disclosure_of_the_wrong_kind_for_its_reference() {
    let (object_kind, d_object) = disclose("s1", Some("name"), json!("v"));
    let (array_kind, d_array) = disclose("s2", None, json!("v"));
    assert_eq!(
        refused(resolve(json!({"l": [{"...": d_object}]}), &[&object_kind])),
        PresentationError::MalformedDisclosure
    );
    assert_eq!(
        refused(resolve(json!({"_sd": [d_array]}), &[&array_kind])),
        PresentationError::MalformedDisclosure
    );
}

#[test]
fn refuses_malformed_sd_and_array_markers() {
    assert_eq!(
        refused(resolve(json!({"_sd": "not-an-array"}), &[])),
        PresentationError::MalformedPayload
    );
    assert_eq!(
        refused(resolve(json!({"_sd": [1]}), &[])),
        PresentationError::MalformedPayload
    );
    assert_eq!(
        refused(resolve(json!({"l": [{"...": "x", "other": 1}]}), &[])),
        PresentationError::MalformedPayload
    );
    assert_eq!(
        refused(resolve(json!({"l": [{"...": 5}]}), &[])),
        PresentationError::MalformedPayload
    );
}

#[test]
fn bounds_depth_and_disclosure_count_during_resolution() {
    let mut nested = json!({"leaf": true});
    for _ in 0..40 {
        nested = json!({"n": nested});
    }
    let shallow = SdJwtLimits {
        max_depth: 8,
        ..limits()
    };
    assert_eq!(
        refused(resolve_disclosures(&object(nested), &[], &shallow)),
        PresentationError::DepthExceeded
    );

    // A chain of recursive disclosures counts toward depth as well.
    let (first, mut digest) = disclose("s0", Some("c"), json!(1));
    let mut all = vec![first];
    for i in 1..20 {
        let (encoded, next_digest) =
            disclose(&format!("s{i}"), Some("c"), json!({"_sd": [digest]}));
        all.push(encoded);
        digest = next_digest;
    }
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    assert_eq!(
        refused(resolve_disclosures(
            &object(json!({"_sd": [digest]})),
            &refs,
            &shallow
        )),
        PresentationError::DepthExceeded
    );

    let few = SdJwtLimits {
        max_disclosures: 1,
        ..limits()
    };
    assert_eq!(
        refused(resolve_disclosures(&object(json!({})), &["a", "b"], &few)),
        PresentationError::TooManyDisclosures
    );
}

#[test]
fn presentation_errors_echo_no_input() {
    let canary = "canary-claim-value-7f3a";
    let (a, da) = disclose("s1", Some("_sd"), json!(canary));
    let message = resolve(json!({"_sd": [da]}), &[&a])
        .unwrap_err()
        .to_string();
    assert!(!message.contains(canary));
    let message = parse_presentation(&format!("{canary}~"), &limits())
        .unwrap_err()
        .to_string();
    assert!(!message.contains(canary));
}

// ---------------------------------------------------------------------------
// Key-binding policy
// ---------------------------------------------------------------------------

const NOW: i64 = 1_800_000_000;
const HASH_INPUT: &str = "issuer.jwt~d1~";
const PREFIXED_AUDIENCE: &str = "x509_san_dns:verifier.example";

fn kb_policy(audience: &str) -> KeyBindingPolicy {
    KeyBindingPolicy {
        audience: audience.to_string(),
        nonce: "challenge-1".to_string(),
        max_age: Duration::from_secs(300),
        max_future_skew: Duration::from_secs(30),
    }
}

fn kb_payload() -> Map<String, Value> {
    object(json!({
        "nonce": "challenge-1",
        "aud": PREFIXED_AUDIENCE,
        "iat": NOW,
        "sd_hash": sd_hash(HASH_INPUT),
    }))
}

fn kb_jwt(key: &str, alg: &str, typ: &str, payload: Map<String, Value>) -> String {
    let jwk = PrivateJwk::parse(key).unwrap();
    let header =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg": alg, "typ": typ})).unwrap());
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Value::Object(payload)).unwrap());
    let input = format!("{header}.{body}");
    let signature = sign(input.as_bytes(), &jwk).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn holder(key: &str) -> PublicJwk {
    PrivateJwk::parse(key).unwrap().public()
}

fn check(
    kb: &str,
    key: &str,
    audience: &str,
    options: &KeyBindingOptions,
) -> Result<(), SdJwtError> {
    validate_key_binding_jwt_with_options(
        kb,
        &holder(key),
        HASH_INPUT,
        &kb_policy(audience),
        options,
        NOW,
    )
    .map(|_| ())
}

#[test]
fn key_binding_defaults_keep_the_strict_es256_profile() {
    let options = KeyBindingOptions::default();
    assert_eq!(options.extra_claims, KeyBindingExtraClaims::Strict);
    assert_eq!(options.allowed_algorithms, vec![SigningAlgorithm::Es256]);
    let third_party = KeyBindingOptions::third_party();
    assert_eq!(
        third_party.extra_claims,
        KeyBindingExtraClaims::IgnoreUnknown
    );
    assert_eq!(
        third_party.allowed_algorithms,
        vec![SigningAlgorithm::Es256, SigningAlgorithm::EdDsa]
    );
}

#[test]
fn key_binding_accepts_es256_and_eddsa_for_third_party_wallets() {
    let options = KeyBindingOptions::third_party();
    let es = kb_jwt(P256_JWK, "ES256", "kb+jwt", kb_payload());
    check(&es, P256_JWK, PREFIXED_AUDIENCE, &options).expect("es256");
    let ed = kb_jwt(ED25519_JWK, "EdDSA", "kb+jwt", kb_payload());
    check(&ed, ED25519_JWK, PREFIXED_AUDIENCE, &options).expect("eddsa");
}

#[test]
fn key_binding_refuses_an_algorithm_outside_the_allow_list() {
    let ed = kb_jwt(ED25519_JWK, "EdDSA", "kb+jwt", kb_payload());
    assert!(matches!(
        check(
            &ed,
            ED25519_JWK,
            PREFIXED_AUDIENCE,
            &KeyBindingOptions::default()
        ),
        Err(SdJwtError::KeyBindingInvalid)
    ));
    let es = kb_jwt(P256_JWK, "ES256", "kb+jwt", kb_payload());
    let eddsa_only = KeyBindingOptions {
        allowed_algorithms: vec![SigningAlgorithm::EdDsa],
        ..KeyBindingOptions::third_party()
    };
    assert!(matches!(
        check(&es, P256_JWK, PREFIXED_AUDIENCE, &eddsa_only),
        Err(SdJwtError::KeyBindingInvalid)
    ));
}

#[test]
fn key_binding_refuses_an_algorithm_that_disagrees_with_the_key() {
    // Signed by the P-256 key but claiming EdDSA, checked against the Ed25519 key.
    let forged = kb_jwt(P256_JWK, "EdDSA", "kb+jwt", kb_payload());
    assert!(matches!(
        check(
            &forged,
            ED25519_JWK,
            PREFIXED_AUDIENCE,
            &KeyBindingOptions::third_party()
        ),
        Err(SdJwtError::KeyBindingInvalid)
    ));
}

#[test]
fn extra_claims_are_refused_when_strict_and_accepted_when_ignored() {
    let mut payload = kb_payload();
    payload.insert("jti".to_string(), json!("wallet-added"));
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", payload);

    assert!(matches!(
        check(
            &kb,
            P256_JWK,
            PREFIXED_AUDIENCE,
            &KeyBindingOptions::default()
        ),
        Err(SdJwtError::KeyBindingInvalid)
    ));
    let ignore = KeyBindingOptions {
        extra_claims: KeyBindingExtraClaims::IgnoreUnknown,
        ..KeyBindingOptions::default()
    };
    check(&kb, P256_JWK, PREFIXED_AUDIENCE, &ignore).expect("extra claims ignored");
}

#[test]
fn ignoring_extra_claims_still_requires_the_four_claims() {
    let options = KeyBindingOptions::third_party();
    for missing in ["nonce", "aud", "iat", "sd_hash"] {
        let mut payload = kb_payload();
        payload.remove(missing);
        payload.insert("jti".to_string(), json!("x"));
        let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", payload);
        assert!(
            matches!(
                check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options),
                Err(SdJwtError::KeyBindingInvalid)
            ),
            "{missing}"
        );
    }
}

#[test]
fn key_binding_audience_is_compared_exactly_with_the_prefixed_client_id() {
    let options = KeyBindingOptions::third_party();
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", kb_payload());
    check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options).expect("exact prefixed match");
    for wrong in [
        "verifier.example",
        "x509_san_dns:verifier.example.evil",
        "X509_SAN_DNS:verifier.example",
        "x509_hash:verifier.example",
        "",
    ] {
        assert!(
            matches!(
                check(&kb, P256_JWK, wrong, &options),
                Err(SdJwtError::KeyBindingInvalid)
            ),
            "{wrong:?}"
        );
    }

    let mut bare = kb_payload();
    bare.insert("aud".to_string(), json!("verifier.example"));
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", bare);
    assert!(matches!(
        check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options),
        Err(SdJwtError::KeyBindingInvalid)
    ));

    let mut list = kb_payload();
    list.insert("aud".to_string(), json!([PREFIXED_AUDIENCE]));
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", list);
    assert!(matches!(
        check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options),
        Err(SdJwtError::KeyBindingInvalid)
    ));
}

#[test]
fn key_binding_checks_type_nonce_iat_and_sd_hash() {
    let options = KeyBindingOptions::third_party();

    let wrong_typ = kb_jwt(P256_JWK, "ES256", "JWT", kb_payload());
    assert!(check(&wrong_typ, P256_JWK, PREFIXED_AUDIENCE, &options).is_err());

    let mut payload = kb_payload();
    payload.insert("nonce".to_string(), json!("challenge-2"));
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", payload);
    assert!(check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options).is_err());

    for iat in [NOW - 301, NOW + 31] {
        let mut payload = kb_payload();
        payload.insert("iat".to_string(), json!(iat));
        let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", payload);
        assert!(
            check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options).is_err(),
            "{iat}"
        );
    }

    let mut payload = kb_payload();
    payload.insert(
        "sd_hash".to_string(),
        json!(sd_hash("another~presentation~")),
    );
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", payload);
    assert!(check(&kb, P256_JWK, PREFIXED_AUDIENCE, &options).is_err());
}

#[test]
fn key_binding_refuses_a_signature_from_another_key() {
    let kb = kb_jwt(P256_JWK, "ES256", "kb+jwt", kb_payload());
    let other = r#"{"kty":"EC","crv":"P-256","d":"M1bGIfUqjBuVWN85Q3qxTW1HUYYNnM-bR9alZAB-KtQ","x":"1vBja0WEJgw_GjigW1Er6WdhpAmnKHsTGPIov3lQ5Ak","y":"wrAAc7K8b9KkjqvrL51AXvmFeYfiio4yNDEIiM-2jyE","alg":"ES256"}"#;
    assert!(check(
        &kb,
        other,
        PREFIXED_AUDIENCE,
        &KeyBindingOptions::third_party()
    )
    .is_err());
}
