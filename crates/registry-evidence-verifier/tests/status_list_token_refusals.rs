//! The failure reason each malformed Status List Token draws. Every row isolates
//! one fault of the compact serialization: the other segments are authentic.
//! `status_list_conformance.rs` covers the claim-level refusals.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use registry_evidence_verifier::status_list::{
    check_status, StatusOutcome, StatusPolicy, StatusReference, StatusUnknown,
};
use registry_platform_crypto::{
    generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk, PublicJwk,
};
use serde_json::{json, Value};

const URI: &str = "https://status.example.org/status/v1/lists/3Kd9xQ";
const IAT: i64 = 1_700_000_000;

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(IAT + 3600, 0)
        .single()
        .expect("valid time")
}

fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serializes"))
}

fn header(public: &PublicJwk) -> Value {
    json!({"alg": "ES256", "typ": "statuslist+jwt", "kid": public.kid})
}

fn claims() -> Value {
    json!({
        "sub": URI,
        "iat": IAT,
        "exp": IAT + 86_400,
        "ttl": 3600,
        "status_list": {"bits": 2, "lst": "eNo76fITAAPfAgc"},
    })
}

/// Sign the text `header.payload` exactly as given.
fn signed(private: &PrivateJwk, header_segment: &str, payload_segment: &str) -> String {
    let signing_input = format!("{header_segment}.{payload_segment}");
    let signature = sign(signing_input.as_bytes(), private).expect("test key signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn outcome(token: &[u8], public: &PublicJwk, policy: &StatusPolicy) -> StatusOutcome {
    check_status(
        &StatusReference::new(URI, 0).expect("reference builds"),
        token,
        std::slice::from_ref(public),
        now(),
        policy,
    )
}

/// Index 0 of the draft's example list holds 0x01, so a token that is read and
/// trusted reports `Invalid`: any outcome other than `Unknown` means the
/// token was accepted.
const READ: StatusOutcome = StatusOutcome::Invalid;

fn unknown(reason: StatusUnknown) -> StatusOutcome {
    StatusOutcome::Unknown(reason)
}

/// A segment that cannot be decoded, or a signature segment past the longest
/// signature, is refused while the token is split, so it draws the structural
/// reason instead of the reason of the later check that would have read it.
/// A `b64` header member is refused with the critical-parameter reason.
#[test]
fn each_malformed_token_draws_its_failure_reason() {
    let private = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("key generates");
    let public = private.public();
    let good_header = header(&public);
    let header_segment = encode(&good_header);
    let payload_segment = encode(&claims());
    let token = signed(&private, &header_segment, &payload_segment);
    let signature_segment = token.rsplit('.').next().expect("signature").to_owned();
    let with_member = |name: &str, value: Value| {
        let mut header = good_header.clone();
        header[name] = value;
        encode(&header)
    };
    let tail = |header: &str| format!("{header}.{payload_segment}.{signature_segment}");

    let cases: Vec<(&str, String, StatusOutcome)> = vec![
        ("authentic token", token.clone(), READ),
        (
            "two segments",
            format!("{header_segment}.{payload_segment}"),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "four segments",
            format!("{token}.extra"),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "empty header segment",
            format!(".{payload_segment}.{signature_segment}"),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "header segment not base64url",
            format!("!!!.{payload_segment}.{signature_segment}"),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "header not JSON",
            tail(&URL_SAFE_NO_PAD.encode("not json")),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "header is an array",
            tail(&encode(&json!([1, 2]))),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "header repeats a member",
            tail(&URL_SAFE_NO_PAD.encode(format!(
                r#"{{"alg":"ES256","typ":"statuslist+jwt","typ":"statuslist+jwt","kid":{}}}"#,
                json!(public.kid)
            ))),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "kid is not a string",
            tail(&with_member("kid", json!(7))),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "wrong typ",
            tail(&with_member("typ", json!("JWT"))),
            unknown(StatusUnknown::WrongType),
        ),
        (
            "wrong alg",
            tail(&with_member("alg", json!("none"))),
            unknown(StatusUnknown::UnsupportedAlgorithm),
        ),
        (
            "critical header member",
            tail(&with_member("crit", json!(["exp"]))),
            unknown(StatusUnknown::UnsupportedCriticalHeader),
        ),
        (
            "unknown kid",
            tail(&with_member("kid", json!("unpinned"))),
            unknown(StatusUnknown::UnknownKey),
        ),
        (
            "signature that does not verify",
            format!(
                "{header_segment}.{payload_segment}.{}",
                URL_SAFE_NO_PAD.encode([7_u8; 64])
            ),
            unknown(StatusUnknown::BadSignature),
        ),
        (
            "empty signature segment",
            format!("{header_segment}.{payload_segment}."),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "signature segment not base64url",
            format!("{header_segment}.{payload_segment}.!!!"),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "signature segment past the signature size",
            format!(
                "{header_segment}.{payload_segment}.{}",
                URL_SAFE_NO_PAD.encode(vec![7_u8; 2000])
            ),
            unknown(StatusUnknown::TokenTooLarge),
        ),
        (
            "signed payload not base64url",
            signed(&private, &header_segment, "!!!"),
            unknown(StatusUnknown::MalformedToken),
        ),
        (
            "signed payload empty",
            signed(&private, &header_segment, ""),
            unknown(StatusUnknown::MalformedClaims),
        ),
        (
            "signed payload not JSON",
            signed(
                &private,
                &header_segment,
                &URL_SAFE_NO_PAD.encode("not json"),
            ),
            unknown(StatusUnknown::MalformedClaims),
        ),
        (
            "signed payload is an array",
            signed(&private, &header_segment, &encode(&json!([1]))),
            unknown(StatusUnknown::MalformedClaims),
        ),
        (
            "unencoded-payload header member",
            signed(
                &private,
                &with_member("b64", json!(false)),
                &payload_segment,
            ),
            unknown(StatusUnknown::UnsupportedCriticalHeader),
        ),
    ];
    let policy = StatusPolicy::default();
    for (name, token, expected) in cases {
        assert_eq!(
            outcome(token.as_bytes(), &public, &policy),
            expected,
            "{name}"
        );
    }
}

#[test]
fn a_token_is_refused_by_size_before_it_is_read() {
    let private = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("key generates");
    let public = private.public();
    let token = signed(&private, &encode(&header(&public)), &encode(&claims()));
    let policy = StatusPolicy::new(token.len(), 60, 86_400, 7 * 86_400).expect("policy builds");
    assert_eq!(outcome(token.as_bytes(), &public, &policy), READ);
    let smaller =
        StatusPolicy::new(token.len() - 1, 60, 86_400, 7 * 86_400).expect("policy builds");
    assert_eq!(
        outcome(token.as_bytes(), &public, &smaller),
        unknown(StatusUnknown::TokenTooLarge)
    );
    assert_eq!(
        outcome(&[0xff, 0xfe], &public, &policy),
        unknown(StatusUnknown::MalformedToken)
    );
}
