//! Token Status List conformance for the pure status check: the draft's
//! Appendix C encoding vectors, one refusal per SL 8.3 failure, the inflation
//! and size bounds, and the bit-order round trip.
//!
//! The standard pin is draft-ietf-oauth-status-list-21, as in
//! `products/evidence/contracts/sd-jwt-vc-profile.yaml`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use proptest::prelude::*;
use registry_evidence_verifier::status_list::{
    check_status, check_status_report, decode, encode, StatusList, StatusListError, StatusOutcome,
    StatusPolicy, StatusReference, StatusUnknown, PROFILE_MAX_INFLATED_BYTES,
};
use registry_platform_crypto::{
    generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk, PublicJwk,
};
use serde::Deserialize;
use serde_json::{json, Value};

const URI: &str = "https://status.example.org/status/v1/lists/3Kd9xQ";
const IAT: i64 = 1_700_000_000;

// Appendix C vectors. Each file names its draft section in `source`.
const VECTORS: [(&str, &str); 4] = [
    ("C.1", include_str!("status_list/appendix-c1-1bit.json")),
    ("C.2", include_str!("status_list/appendix-c2-2bit.json")),
    ("C.3", include_str!("status_list/appendix-c3-4bit.json")),
    ("C.4", include_str!("status_list/appendix-c4-8bit.json")),
];

#[derive(Deserialize)]
struct Vector {
    bits: u8,
    size: usize,
    entries: Vec<(usize, u8)>,
    lst: String,
}

fn vector_values(vector: &Vector) -> Vec<u8> {
    let mut values = vec![0_u8; vector.size];
    for (index, value) in &vector.entries {
        values[*index] = *value;
    }
    values
}

#[test]
fn every_appendix_c_vector_decodes_to_the_listed_entries() {
    for (name, text) in VECTORS {
        let vector: Vector = serde_json::from_str(text).expect(name);
        let compressed = URL_SAFE_NO_PAD.decode(&vector.lst).expect(name);
        let list = decode(vector.bits, &compressed, 1 << 20).expect(name);
        assert_eq!(list.bits(), vector.bits, "{name}");
        assert_eq!(list.len(), vector.size, "{name}");
        assert_eq!(list.to_values(), vector_values(&vector), "{name}");
        for (index, value) in &vector.entries {
            assert_eq!(list.get(*index), Some(*value), "{name} entry {index}");
        }
    }
}

#[test]
fn every_appendix_c_vector_re_encodes_to_the_same_list() {
    for (name, text) in VECTORS {
        let vector: Vector = serde_json::from_str(text).expect(name);
        let values = vector_values(&vector);
        let compressed = encode(vector.bits, &values).expect(name);
        let again = decode(vector.bits, &compressed, 1 << 20).expect(name);
        assert_eq!(again.to_values(), values, "{name}");
    }
}

#[test]
fn bit_order_puts_entry_zero_in_the_least_significant_bits() {
    // SL 4.1 worked example: twelve 2-bit entries pack to 0xC9 0x44 0xF9.
    let values = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
    let list = StatusList::from_values(2, &values).expect("list builds");
    assert_eq!(list.as_bytes(), &[0xC9, 0x44, 0xF9]);
    // SL 4.1 worked example: sixteen 1-bit entries pack to 0xB9 0xA3.
    let ones = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    let list = StatusList::from_values(1, &ones).expect("list builds");
    assert_eq!(list.as_bytes(), &[0xB9, 0xA3]);
    // The draft's compressed form of the 2-bit example decodes to those bytes.
    let compressed = URL_SAFE_NO_PAD
        .decode("eNo76fITAAPfAgc")
        .expect("lst decodes");
    let decoded = decode(2, &compressed, 16).expect("draft example decodes");
    assert_eq!(decoded.as_bytes(), &[0xC9, 0x44, 0xF9]);
}

proptest! {
    #[test]
    fn encode_then_decode_is_the_identity_for_two_bit_lists(
        quads in proptest::collection::vec(0_u8..4, 0..2048),
    ) {
        let mut values = quads;
        values.truncate(values.len() / 4 * 4);
        let compressed = encode(2, &values).unwrap();
        let list = decode(2, &compressed, 1 << 20).unwrap();
        prop_assert_eq!(list.to_values(), values);
    }
}

// ---------------------------------------------------------------------------
// Token fixtures

struct Issuer {
    private: PrivateJwk,
    public: PublicJwk,
}

impl Issuer {
    fn new() -> Self {
        let private = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("key generates");
        let public = private.public();
        Self { private, public }
    }

    fn kid(&self) -> String {
        self.public.kid.clone().expect("generated key has a kid")
    }
}

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(IAT + 3600, 0)
        .single()
        .expect("valid time")
}

fn list_lst(values: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(encode(2, values).expect("list encodes"))
}

fn default_values() -> Vec<u8> {
    // Index 0 VALID, 1 INVALID, 2 SUSPENDED, 3 never written.
    let mut values = vec![0_u8; 1024];
    values[1] = 1;
    values[2] = 2;
    values[3] = 3;
    values
}

fn header(issuer: &Issuer) -> Value {
    json!({"alg": "ES256", "typ": "statuslist+jwt", "kid": issuer.kid()})
}

fn claims() -> Value {
    json!({
        "sub": URI,
        "iat": IAT,
        "exp": IAT + 86_400,
        "ttl": 3600,
        "status_list": {"bits": 2, "lst": list_lst(&default_values())},
    })
}

fn compact(issuer: &Issuer, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims")),
    );
    let signature = sign(signing_input.as_bytes(), &issuer.private).expect("test key signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn reference(idx: u64) -> StatusReference {
    StatusReference::new(URI, idx).expect("reference builds")
}

fn check(token: &str, issuer: &Issuer, idx: u64) -> StatusOutcome {
    check_status(
        &reference(idx),
        token.as_bytes(),
        std::slice::from_ref(&issuer.public),
        now(),
        &StatusPolicy::default(),
    )
}

fn unknown(reason: StatusUnknown) -> StatusOutcome {
    StatusOutcome::Unknown(reason)
}

// ---------------------------------------------------------------------------
// Outcomes

#[test]
fn values_zero_one_and_two_map_to_valid_invalid_and_suspended() {
    let issuer = Issuer::new();
    let token = compact(&issuer, &header(&issuer), &claims());
    assert_eq!(check(&token, &issuer, 0), StatusOutcome::Valid);
    assert_eq!(check(&token, &issuer, 1), StatusOutcome::Invalid);
    assert_eq!(check(&token, &issuer, 2), StatusOutcome::Suspended);
    assert_eq!(check(&token, &issuer, 500), StatusOutcome::Valid);
}

#[test]
fn value_three_is_never_valid() {
    let issuer = Issuer::new();
    let token = compact(&issuer, &header(&issuer), &claims());
    assert_eq!(check(&token, &issuer, 3), StatusOutcome::Invalid);
}

#[test]
fn the_report_carries_the_clamped_ttl_and_the_honoured_expiry() {
    let issuer = Issuer::new();
    let token = compact(&issuer, &header(&issuer), &claims());
    let report = check_status_report(
        &reference(0),
        token.as_bytes(),
        std::slice::from_ref(&issuer.public),
        now(),
        &StatusPolicy::default(),
    );
    assert_eq!(report.outcome, StatusOutcome::Valid);
    assert_eq!(report.ttl_seconds, Some(3600));
    assert_eq!(
        report.honoured_until,
        Utc.timestamp_opt(IAT + 86_400, 0).single()
    );
}

#[test]
fn a_key_selected_without_a_kid_header_still_verifies() {
    let issuer = Issuer::new();
    let mut header = header(&issuer);
    header.as_object_mut().expect("object").remove("kid");
    let token = compact(&issuer, &header, &claims());
    assert_eq!(check(&token, &issuer, 0), StatusOutcome::Valid);
}

// ---------------------------------------------------------------------------
// SL 8.3 failures

#[test]
fn a_wrong_typ_is_refused_including_typ_confusion() {
    let issuer = Issuer::new();
    for typ in ["dc+sd-jwt", "JWT", "evidence+jws", "statuslist+JWT", ""] {
        let mut header = header(&issuer);
        header["typ"] = json!(typ);
        let token = compact(&issuer, &header, &claims());
        assert_eq!(
            check(&token, &issuer, 0),
            unknown(StatusUnknown::WrongType),
            "typ {typ:?}"
        );
    }
    let mut missing = header(&issuer);
    missing.as_object_mut().expect("object").remove("typ");
    let token = compact(&issuer, &missing, &claims());
    assert_eq!(check(&token, &issuer, 0), unknown(StatusUnknown::WrongType));
}

#[test]
fn typ_is_checked_before_the_signature() {
    let issuer = Issuer::new();
    let mut header = header(&issuer);
    header["typ"] = json!("JWT");
    let token = compact(&issuer, &header, &claims());
    let other = Issuer::new();
    assert_eq!(check(&token, &other, 0), unknown(StatusUnknown::WrongType));
}

#[test]
fn a_wrong_alg_is_refused() {
    let issuer = Issuer::new();
    for alg in ["ES384", "RS256", "none", "HS256", "EdDSA"] {
        let mut header = header(&issuer);
        header["alg"] = json!(alg);
        let token = compact(&issuer, &header, &claims());
        assert_eq!(
            check(&token, &issuer, 0),
            unknown(StatusUnknown::UnsupportedAlgorithm),
            "alg {alg}"
        );
    }
}

#[test]
fn a_critical_header_is_refused() {
    let issuer = Issuer::new();
    let mut header = header(&issuer);
    header["crit"] = json!(["exp"]);
    let token = compact(&issuer, &header, &claims());
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::UnsupportedCriticalHeader)
    );
}

#[test]
fn a_bad_signature_is_refused() {
    let issuer = Issuer::new();
    let token = compact(&issuer, &header(&issuer), &claims());
    let (signing_input, _) = token.rsplit_once('.').expect("compact form");
    let forged = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode([7_u8; 64]));
    assert_eq!(
        check(&forged, &issuer, 0),
        unknown(StatusUnknown::BadSignature)
    );
    // A payload edited after signing no longer matches the signature.
    let parts: Vec<&str> = token.split('.').collect();
    let mut edited = claims();
    edited["status_list"]["lst"] = json!(list_lst(&vec![0_u8; 1024]));
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&edited).expect("claims")),
        parts[2]
    );
    assert_eq!(
        check(&tampered, &issuer, 1),
        unknown(StatusUnknown::BadSignature)
    );
}

#[test]
fn a_token_signed_by_an_unpinned_key_is_refused() {
    let issuer = Issuer::new();
    let stranger = Issuer::new();
    // The header names a kid the verifier does not pin.
    let token = compact(&stranger, &header(&stranger), &claims());
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::UnknownKey)
    );
    // The header borrows a pinned kid but the signature is another key's.
    let mut borrowed = header(&stranger);
    borrowed["kid"] = json!(issuer.kid());
    let token = compact(&stranger, &borrowed, &claims());
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::BadSignature)
    );
    // No pinned keys at all.
    let token = compact(&issuer, &header(&issuer), &claims());
    let outcome = check_status(
        &reference(0),
        token.as_bytes(),
        &[],
        now(),
        &StatusPolicy::default(),
    );
    assert_eq!(outcome, unknown(StatusUnknown::UnknownKey));
}

#[test]
fn a_sub_that_differs_from_the_reference_uri_is_refused() {
    let issuer = Issuer::new();
    for sub in [
        "https://status.example.org/status/v1/lists/other",
        "https://status.example.org/status/v1/lists/3Kd9xQ/",
        "HTTPS://status.example.org/status/v1/lists/3Kd9xQ",
    ] {
        let mut claims = claims();
        claims["sub"] = json!(sub);
        let token = compact(&issuer, &header(&issuer), &claims);
        assert_eq!(
            check(&token, &issuer, 0),
            unknown(StatusUnknown::SubjectMismatch),
            "sub {sub}"
        );
    }
    let mut claims = claims();
    claims.as_object_mut().expect("object").remove("sub");
    let token = compact(&issuer, &header(&issuer), &claims);
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::SubjectMismatch)
    );
}

#[test]
fn iat_must_be_present_and_an_integer() {
    let issuer = Issuer::new();
    let mut missing = claims();
    missing.as_object_mut().expect("object").remove("iat");
    let token = compact(&issuer, &header(&issuer), &missing);
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::MissingIssuedAt)
    );
    let mut text = claims();
    text["iat"] = json!("1700000000");
    let token = compact(&issuer, &header(&issuer), &text);
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::MissingIssuedAt)
    );
}

#[test]
fn exp_must_be_present_and_not_passed() {
    let issuer = Issuer::new();
    let mut missing = claims();
    missing.as_object_mut().expect("object").remove("exp");
    let token = compact(&issuer, &header(&issuer), &missing);
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::MissingExpiry)
    );

    let mut passed = claims();
    passed["exp"] = json!(IAT + 60);
    let token = compact(&issuer, &header(&issuer), &passed);
    assert_eq!(check(&token, &issuer, 0), unknown(StatusUnknown::Expired));

    // The instant of expiry is already expired.
    let mut boundary = claims();
    boundary["exp"] = json!(IAT + 3600);
    let token = compact(&issuer, &header(&issuer), &boundary);
    assert_eq!(check(&token, &issuer, 0), unknown(StatusUnknown::Expired));
}

#[test]
fn exp_is_honoured_no_later_than_iat_plus_the_ceiling() {
    let issuer = Issuer::new();
    let mut far = claims();
    far["exp"] = json!(IAT + 30 * 86_400);
    let token = compact(&issuer, &header(&issuer), &far);
    let policy = StatusPolicy::default();
    let keys = std::slice::from_ref(&issuer.public);
    let at = |seconds: i64| Utc.timestamp_opt(IAT + seconds, 0).single().expect("time");

    let within = check_status_report(
        &reference(0),
        token.as_bytes(),
        keys,
        at(6 * 86_400),
        &policy,
    );
    assert_eq!(within.outcome, StatusOutcome::Valid);
    assert_eq!(within.honoured_until, Some(at(7 * 86_400)));

    let beyond = check_status(
        &reference(0),
        token.as_bytes(),
        keys,
        at(8 * 86_400),
        &policy,
    );
    assert_eq!(beyond, unknown(StatusUnknown::Expired));
}

#[test]
fn ttl_is_clamped_to_the_policy_range_and_reported() {
    let issuer = Issuer::new();
    let keys = std::slice::from_ref(&issuer.public);
    let policy = StatusPolicy::default();
    for (ttl, expected) in [
        (1, 60),
        (59, 60),
        (60, 60),
        (3600, 3600),
        (86_400, 86_400),
        (10_000_000, 86_400),
    ] {
        let mut claims = claims();
        claims["ttl"] = json!(ttl);
        let token = compact(&issuer, &header(&issuer), &claims);
        let report = check_status_report(&reference(0), token.as_bytes(), keys, now(), &policy);
        assert_eq!(report.outcome, StatusOutcome::Valid, "ttl {ttl}");
        assert_eq!(report.ttl_seconds, Some(expected), "ttl {ttl}");
    }
    // An absent ttl gives the relying party no hint, so the policy maximum applies.
    let mut absent = claims();
    absent.as_object_mut().expect("object").remove("ttl");
    let token = compact(&issuer, &header(&issuer), &absent);
    let report = check_status_report(&reference(0), token.as_bytes(), keys, now(), &policy);
    assert_eq!(report.ttl_seconds, Some(86_400));
}

#[test]
fn a_ttl_that_is_not_a_positive_integer_is_refused() {
    let issuer = Issuer::new();
    for ttl in [json!(0), json!(-5), json!("3600"), json!(60.5), json!(null)] {
        let mut claims = claims();
        claims["ttl"] = ttl.clone();
        let token = compact(&issuer, &header(&issuer), &claims);
        assert_eq!(
            check(&token, &issuer, 0),
            unknown(StatusUnknown::MalformedClaims),
            "ttl {ttl}"
        );
    }
}

#[test]
fn bits_other_than_two_are_refused() {
    let issuer = Issuer::new();
    for bits in [json!(1), json!(4), json!(8), json!(3), json!(0), json!("2")] {
        let mut claims = claims();
        claims["status_list"]["bits"] = bits.clone();
        let token = compact(&issuer, &header(&issuer), &claims);
        assert_eq!(
            check(&token, &issuer, 0),
            unknown(StatusUnknown::UnsupportedBits),
            "bits {bits}"
        );
    }
}

#[test]
fn an_index_outside_the_list_is_refused() {
    let issuer = Issuer::new();
    let token = compact(&issuer, &header(&issuer), &claims());
    // 1024 entries: the last valid index is 1023.
    assert_eq!(check(&token, &issuer, 1023), StatusOutcome::Valid);
    assert_eq!(
        check(&token, &issuer, 1024),
        unknown(StatusUnknown::IndexOutOfBounds)
    );
    assert_eq!(
        check(&token, &issuer, u64::MAX),
        unknown(StatusUnknown::IndexOutOfBounds)
    );
}

#[test]
fn a_missing_or_malformed_status_list_claim_is_refused() {
    let issuer = Issuer::new();
    let mut missing = claims();
    missing
        .as_object_mut()
        .expect("object")
        .remove("status_list");
    let mut not_base64 = claims();
    not_base64["status_list"]["lst"] = json!("***not base64***");
    let mut not_zlib = claims();
    not_zlib["status_list"]["lst"] = json!(URL_SAFE_NO_PAD.encode(b"plainly not deflate"));
    for (name, claims) in [
        ("missing", missing),
        ("base64", not_base64),
        ("zlib", not_zlib),
    ] {
        let token = compact(&issuer, &header(&issuer), &claims);
        assert_eq!(
            check(&token, &issuer, 0),
            unknown(StatusUnknown::MalformedList),
            "{name}"
        );
    }
}

#[test]
fn a_structurally_malformed_token_is_refused() {
    let issuer = Issuer::new();
    for token in ["", "a.b", "a.b.c.d", "....", "!!!.!!!.!!!"] {
        assert_eq!(
            check(token, &issuer, 0),
            unknown(StatusUnknown::MalformedToken),
            "token {token:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Bounds

fn inflation_bomb_claims(entries: usize) -> Value {
    let mut claims = claims();
    // All zeros compress by roughly a thousandfold.
    claims["status_list"]["lst"] = json!(list_lst(&vec![0_u8; entries]));
    claims
}

#[test]
fn a_list_at_the_profile_maximum_is_accepted() {
    let issuer = Issuer::new();
    let claims = inflation_bomb_claims(1 << 20);
    let token = compact(&issuer, &header(&issuer), &claims);
    assert!(
        token.len() < 4096,
        "the full list stays a few KiB while sparse"
    );
    assert_eq!(check(&token, &issuer, (1 << 20) - 1), StatusOutcome::Valid);
}

#[test]
fn a_small_token_that_inflates_past_the_cap_is_refused() {
    let issuer = Issuer::new();
    // 2^21 entries at 2 bits is 512 KiB inflated, twice the profile maximum.
    let claims = inflation_bomb_claims(1 << 21);
    let token = compact(&issuer, &header(&issuer), &claims);
    assert!(token.len() < 4096, "the bomb is small on the wire");
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::ListTooLarge)
    );
}

#[test]
fn the_codec_stops_inflating_at_the_cap() {
    let compressed = encode(2, &vec![0_u8; 1 << 21]).expect("list encodes");
    let refused = decode(2, &compressed, PROFILE_MAX_INFLATED_BYTES);
    assert_eq!(
        refused.err(),
        Some(StatusListError::Oversize {
            limit: PROFILE_MAX_INFLATED_BYTES
        })
    );
    // Exactly at the cap is accepted.
    let compressed = encode(2, &vec![0_u8; 1 << 20]).expect("list encodes");
    let list = decode(2, &compressed, PROFILE_MAX_INFLATED_BYTES).expect("at the cap");
    assert_eq!(list.len(), 1 << 20);
    // One byte under the cap refuses.
    assert!(matches!(
        decode(2, &compressed, PROFILE_MAX_INFLATED_BYTES - 1),
        Err(StatusListError::Oversize { .. })
    ));
}

#[test]
fn an_oversize_compressed_token_is_refused_before_it_is_parsed() {
    let issuer = Issuer::new();
    let token = compact(&issuer, &header(&issuer), &claims());
    let policy = StatusPolicy::new(256, 60, 86_400, 7 * 86_400).expect("policy builds");
    assert!(token.len() > 256);
    let outcome = check_status(
        &reference(0),
        token.as_bytes(),
        std::slice::from_ref(&issuer.public),
        now(),
        &policy,
    );
    assert_eq!(outcome, unknown(StatusUnknown::TokenTooLarge));
    // The default bound refuses a megabyte of garbage without parsing it.
    let outcome = check_status(
        &reference(0),
        &vec![b'a'; 1_048_577],
        std::slice::from_ref(&issuer.public),
        now(),
        &StatusPolicy::default(),
    );
    assert_eq!(outcome, unknown(StatusUnknown::TokenTooLarge));
}

#[test]
fn a_duplicate_claim_is_refused() {
    let issuer = Issuer::new();
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header(&issuer)).expect("header")),
        URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"sub":"{URI}","sub":"https://evil.example/x","iat":{IAT},"exp":{},"status_list":{{"bits":2,"lst":"eNo76fITAAPfAgc"}}}}"#,
                IAT + 86_400
            )
        ),
    );
    let signature = sign(signing_input.as_bytes(), &issuer.private).expect("signs");
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    assert_eq!(
        check(&token, &issuer, 0),
        unknown(StatusUnknown::MalformedClaims)
    );
}
