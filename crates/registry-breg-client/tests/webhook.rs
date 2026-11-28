use std::time::{Duration, SystemTime, UNIX_EPOCH};

use registry_breg_client::{
    verify_hook_delivery, verify_hook_delivery_at, BRegHookDelivery, BRegHookFreshness,
    BRegHookVerificationError,
};

const KEY: &[u8] = b"webhook-delivery-signing-key-0123456789abcdef";
const BODY: &[u8] = br#"{"entity":"case","values":{"label":"value"}}"#;
/// Unix seconds of the vector's signed delivery time, 2026-08-30T00:00:01Z.
const DELIVERY_EPOCH: u64 = 1_788_048_001;
const SIGNATURE: &str = "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM";

fn headers() -> Vec<(String, String)> {
    [
        ("Ce-Specversion", "1.0"),
        ("CE-ID", "00000000-0000-4000-8000-000000000001"),
        (
            "ce-source",
            "urn:registrystack:registry:example:instance:primary",
        ),
        ("ce-type", "case-created-v1"),
        ("ce-time", "2026-08-30T00:00:00Z"),
        (
            "ce-dataschema",
            "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
        ),
        ("x-registry-event-generation", "1"),
        ("x-registry-delivery-attempt", "1"),
        ("x-registry-delivery-time", "2026-08-30T00:00:01Z"),
        (
            "idempotency-key",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("content-type", "application/json"),
        ("x-registry-signature", SIGNATURE),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

fn delivery<'a>(
    headers: &'a [(String, String)],
    body: &'a [u8],
    key: &'a [u8],
) -> BRegHookDelivery<'a> {
    BRegHookDelivery {
        method: "POST",
        path: "/hooks/registry",
        headers,
        body,
        key,
        freshness: BRegHookFreshness::CallerEnforced,
    }
}

fn delivery_with<'a>(
    headers: &'a [(String, String)],
    freshness: BRegHookFreshness,
) -> BRegHookDelivery<'a> {
    BRegHookDelivery {
        freshness,
        ..delivery(headers, BODY, KEY)
    }
}

fn at(offset_seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(DELIVERY_EPOCH.checked_add_signed(offset_seconds).unwrap())
}

fn set_header(headers: &mut [(String, String)], name: &str, value: impl Into<String>) {
    headers
        .iter_mut()
        .find(|(candidate, _)| candidate == name)
        .unwrap()
        .1 = value.into();
}

#[test]
fn fixed_vector_verifies_and_returns_exact_delivery() {
    let headers = headers();
    let verified = verify_hook_delivery_at(
        delivery_with(&headers, BRegHookFreshness::DefaultWindow),
        at(0),
    )
    .unwrap();

    assert_eq!(verified.id, "00000000-0000-4000-8000-000000000001");
    assert_eq!(
        verified.source,
        "urn:registrystack:registry:example:instance:primary"
    );
    assert_eq!(verified.event_type, "case-created-v1");
    assert_eq!(verified.time, "2026-08-30T00:00:00Z");
    assert_eq!(
        verified.data_schema,
        "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa"
    );
    assert_eq!(verified.generation, "1");
    assert_eq!(verified.attempt, "1");
    assert_eq!(verified.delivery_time, "2026-08-30T00:00:01Z");
    assert_eq!(
        verified.idempotency_key,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(verified.body, BODY);

    let debug = format!("{verified:?}");
    assert!(!debug.contains(&format!("{:?}", BODY.to_vec())));
    assert!(debug.contains("body_bytes"));
}

#[test]
fn refusal_codes_are_closed_and_value_free() {
    let mut missing = headers();
    missing.retain(|(name, _)| name != "ce-type");
    assert_eq!(
        verify_hook_delivery(delivery(&missing, BODY, KEY)),
        Err(BRegHookVerificationError::MissingHeader)
    );

    let mut malformed = headers();
    set_header(&mut malformed, "x-registry-signature", "v1=truncated");
    assert_eq!(
        verify_hook_delivery(delivery(&malformed, BODY, KEY)),
        Err(BRegHookVerificationError::MalformedSignature)
    );

    let mut unsupported = headers();
    set_header(
        &mut unsupported,
        "x-registry-signature",
        SIGNATURE.replacen("v1=", "v2=", 1),
    );
    assert_eq!(
        verify_hook_delivery(delivery(&unsupported, BODY, KEY)),
        Err(BRegHookVerificationError::UnsupportedVersion)
    );

    let mut tampered = headers();
    set_header(&mut tampered, "ce-type", "case-patched-v1");
    assert_eq!(
        verify_hook_delivery(delivery(&tampered, BODY, KEY)),
        Err(BRegHookVerificationError::SignatureMismatch)
    );

    for error in [
        BRegHookVerificationError::MissingHeader,
        BRegHookVerificationError::MalformedSignature,
        BRegHookVerificationError::SignatureMismatch,
        BRegHookVerificationError::UnsupportedVersion,
    ] {
        assert!(!error.to_string().contains(SIGNATURE));
        assert!(!error.to_string().contains("case-patched-v1"));
    }
}

#[test]
fn invalid_delivery_time_names_the_delivery_time_fix() {
    let mut invalid = headers();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../registry-platform-crypto/tests/fixtures/delivery-signatures.json"
    ))
    .unwrap();
    let vector = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["valid"] == false)
        .unwrap();
    set_header(
        &mut invalid,
        "x-registry-delivery-time",
        vector["deliveryTime"].as_str().unwrap(),
    );
    set_header(
        &mut invalid,
        "x-registry-signature",
        vector["signature"].as_str().unwrap(),
    );
    let error = verify_hook_delivery(delivery(&invalid, BODY, KEY)).unwrap_err();
    assert_eq!(error, BRegHookVerificationError::InvalidDeliveryTime);
    assert_eq!(error.code(), "invalid-delivery-time");
    assert_eq!(
        error.to_string(),
        "the Base Registry Engine hook delivery time is invalid; check the signed delivery time and sender clock"
    );
}

#[test]
fn duplicate_header_names_the_header_fix() {
    let mut duplicate = headers();
    duplicate.push(("ce-type".into(), "case-created-v1".into()));
    let error = verify_hook_delivery(delivery(&duplicate, BODY, KEY)).unwrap_err();
    assert_eq!(error, BRegHookVerificationError::DuplicateHeader);
    assert_eq!(error.code(), "duplicate-header");
    assert_eq!(
        error.to_string(),
        "a Base Registry Engine hook header is repeated; remove duplicate signed headers"
    );
}

#[test]
fn oversized_body_names_the_body_size_fix() {
    let oversized = vec![b'x'; 1_048_577];
    let error = verify_hook_delivery(delivery(&headers(), &oversized, KEY)).unwrap_err();
    assert_eq!(error, BRegHookVerificationError::BodyTooLarge);
    assert_eq!(error.code(), "body-too-large");
    assert_eq!(
        error.to_string(),
        "the Base Registry Engine hook body exceeds the Version 1 limit; reduce the body size"
    );
    assert!(!error.to_string().contains(&"x".repeat(64)));
}

#[test]
fn invalid_key_names_the_key_configuration_fix() {
    let error = verify_hook_delivery(delivery(&headers(), BODY, b"short-key")).unwrap_err();
    assert_eq!(error, BRegHookVerificationError::InvalidKey);
    assert_eq!(error.code(), "invalid-key");
    assert_eq!(
        error.to_string(),
        "the Base Registry Engine hook verification key is too short; configure a key of at least 32 bytes"
    );
    assert!(!error.to_string().contains("short-key"));
}

#[test]
fn the_default_window_is_300_seconds_in_both_directions() {
    let headers = headers();
    let default = || delivery_with(&headers, BRegHookFreshness::DefaultWindow);
    assert_eq!(
        BRegHookFreshness::default(),
        BRegHookFreshness::DefaultWindow
    );
    for offset in [299, -299, 0] {
        verify_hook_delivery_at(default(), at(offset)).expect("inside the window");
    }
    for offset in [301, -301] {
        let error = verify_hook_delivery_at(default(), at(offset)).unwrap_err();
        assert_eq!(error, BRegHookVerificationError::StaleDelivery, "{offset}");
        assert_eq!(error.code(), "stale-delivery");
    }
}

#[test]
fn the_system_clock_default_refuses_the_old_fixed_vector() {
    let headers = headers();
    assert_eq!(
        verify_hook_delivery(delivery_with(&headers, BRegHookFreshness::DefaultWindow)),
        Err(BRegHookVerificationError::StaleDelivery)
    );
}

#[test]
fn a_named_window_replaces_the_default() {
    let headers = headers();
    let within = |skew| delivery_with(&headers, BRegHookFreshness::Within { skew });
    let ten = Duration::from_secs(10);
    verify_hook_delivery_at(within(ten), at(10)).expect("at the edge");
    assert_eq!(
        verify_hook_delivery_at(within(ten), at(11)),
        Err(BRegHookVerificationError::StaleDelivery)
    );
    verify_hook_delivery_at(within(Duration::from_secs(3600)), at(3600)).expect("wide window");
}

#[test]
fn caller_enforced_freshness_accepts_a_year_old_delivery() {
    let headers = headers();
    let year = 365 * 24 * 3600;
    verify_hook_delivery_at(
        delivery_with(&headers, BRegHookFreshness::CallerEnforced),
        at(year),
    )
    .expect("the caller owns the window");
}

#[test]
fn stale_delivery_names_the_clock_fix() {
    let error = BRegHookVerificationError::StaleDelivery;
    assert_eq!(
        error.to_string(),
        "the Base Registry Engine hook delivery time is outside the freshness window; check the receiver clock, or pass a wider window"
    );
}
