use std::time::{Duration, UNIX_EPOCH};

use registry_breg_client::{verify_hook_delivery_at, BRegHookDelivery, BRegHookFreshness};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const PREVIOUS: &[u8] = b"abcdef0123456789abcdef0123456789";
const BODY: &[u8] = br#"{"causation":{"hop":0,"root":"00000000-0000-4000-8000-000000000001"},"data":{},"dataschema":"https://example.test/schema","id":"00000000-0000-4000-8000-000000000001","source":"/products/breg/deployments/example","subject":{"recordReference":"breg/case/42","recordRevision":7},"time":"2026-08-30T00:00:00.123Z","type":"case-created-v1"}"#;
const TS: u64 = 1_788_048_001;
const SIGNATURE: &str = "v1,NELq97rzqnAqQUxh1eiskBB3oOl+4FsqaI1ZV/lAqQY=";

fn headers(id: &str, timestamp: &str, signature: &str) -> Vec<(String, String)> {
    [
        ("Content-Type", "application/json"),
        ("Webhook-ID", id),
        ("webhook-timestamp", timestamp),
        ("webhook-signature", signature),
    ]
    .map(|(name, value)| (name.into(), value.into()))
    .to_vec()
}

fn verify(
    freshness: BRegHookFreshness,
    offset: i64,
) -> Result<
    registry_breg_client::BRegVerifiedHookDelivery,
    registry_breg_client::BRegHookVerificationError,
> {
    verify_hook_delivery_at(
        BRegHookDelivery {
            headers: &headers(ID, &TS.to_string(), SIGNATURE),
            body: BODY,
            key: KEY,
            previous_key: None,
            freshness,
        },
        UNIX_EPOCH + Duration::from_secs(TS.checked_add_signed(offset).unwrap()),
    )
}

#[test]
fn a_signed_envelope_verifies_and_returns_its_attributes() {
    let result = verify(BRegHookFreshness::DefaultWindow, 0).unwrap();
    assert_eq!(result.id, ID);
    assert_eq!(result.timestamp, TS);
    assert_eq!(result.source, "/products/breg/deployments/example");
    assert_eq!(result.event_type, "case-created-v1");
    assert_eq!(result.time, "2026-08-30T00:00:00.123Z");
    assert_eq!(result.data_schema, "https://example.test/schema");
    assert_eq!(result.body, BODY);
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_committed_vector_gets_its_expected_code() {
    let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../registry-platform-crypto/tests/fixtures/standard-webhooks.json"
    ))
    .unwrap();
    for vector in vectors {
        let key = unhex(vector["keyHex"].as_str().unwrap());
        let previous = vector["previousKeyHex"].as_str().map(unhex);
        let error = verify_hook_delivery_at(
            BRegHookDelivery {
                headers: &headers(
                    vector["id"].as_str().unwrap(),
                    vector["timestamp"].as_str().unwrap(),
                    vector["signature"].as_str().unwrap(),
                ),
                body: vector["body"].as_str().unwrap().as_bytes(),
                key: &key,
                previous_key: previous.as_deref(),
                freshness: BRegHookFreshness::DefaultWindow,
            },
            UNIX_EPOCH + Duration::from_secs(vector["now"].as_u64().unwrap()),
        )
        .unwrap_err();
        let expected = match (
            vector["keyPolicy"].as_str(),
            vector["expected"].as_str().unwrap(),
        ) {
            (Some("below-minimum"), _) => "invalid-key",
            (_, "accepted") => "invalid-envelope",
            (_, code) => code,
        };
        assert_eq!(error.code(), expected, "{}", vector["name"]);
    }
}

#[test]
fn the_default_window_is_300_seconds_in_both_directions() {
    for offset in [-300, 300] {
        verify(BRegHookFreshness::DefaultWindow, offset).unwrap();
    }
    for offset in [-301, 301] {
        assert_eq!(
            verify(BRegHookFreshness::DefaultWindow, offset)
                .unwrap_err()
                .code(),
            "stale-delivery"
        );
    }
}

#[test]
fn a_named_window_replaces_the_default() {
    let freshness = BRegHookFreshness::Within {
        skew: Duration::from_secs(10),
    };
    verify(freshness, 10).unwrap();
    assert_eq!(verify(freshness, 11).unwrap_err().code(), "stale-delivery");
}

#[test]
fn caller_enforced_freshness_accepts_a_year_old_delivery() {
    verify(BRegHookFreshness::CallerEnforced, 365 * 24 * 3600).unwrap();
}

#[test]
fn a_previous_key_verifies_a_rotated_delivery() {
    let input = BRegHookDelivery {
        headers: &headers(
            ID,
            &TS.to_string(),
            "v1,VJrqYnKSCnccY0zIQARwZ/xIh/dVWuudwj1QQyTzYx0=",
        ),
        body: BODY,
        key: KEY,
        previous_key: Some(PREVIOUS),
        freshness: BRegHookFreshness::CallerEnforced,
    };
    assert_eq!(
        registry_breg_client::verify_hook_delivery(input)
            .unwrap()
            .id,
        ID
    );
}

#[test]
fn a_webhook_id_that_differs_from_the_envelope_id_is_refused() {
    let input = BRegHookDelivery {
        headers: &headers(
            "00000000-0000-4000-8000-000000000002",
            &TS.to_string(),
            "v1,5utAVSfp86oJRURFYIoR2F3is1nWXe+aIL6vtd13e1Y=",
        ),
        body: BODY,
        key: KEY,
        previous_key: None,
        freshness: BRegHookFreshness::CallerEnforced,
    };
    assert_eq!(
        registry_breg_client::verify_hook_delivery(input)
            .unwrap_err()
            .code(),
        "id-mismatch"
    );
}

#[test]
fn an_invalid_key_names_its_length_and_newline_without_its_bytes() {
    for (key, previous_key, checks) in [
        (&[b'x'; 31][..], None, &["31", "32"][..]),
        (
            &[
                &[b'x'; 64][..],
                b"
",
            ]
            .concat()[..],
            None,
            &["65", "newline"],
        ),
        (
            &b"whsec_synthetic_key_text_for_test"[..],
            None,
            &["whsec_", "33"],
        ),
        (KEY, Some(KEY), &["previous", "equals", "32"]),
    ] {
        let error = registry_breg_client::verify_hook_delivery(BRegHookDelivery {
            headers: &headers(ID, &TS.to_string(), SIGNATURE),
            body: BODY,
            key,
            previous_key,
            freshness: BRegHookFreshness::CallerEnforced,
        })
        .unwrap_err();
        assert_eq!(error.code(), "invalid-key");
        let message = error.to_string();
        for check in checks {
            assert!(message.contains(check), "{message}");
        }
        assert!(!message.contains(std::str::from_utf8(key).unwrap()));
    }
}

#[test]
fn refusal_codes_are_closed_and_value_free() {
    use registry_breg_client::BRegHookVerificationError::*;
    let errors = [
        MissingHeader,
        DuplicateHeader,
        InvalidContentType,
        InvalidId,
        InvalidTimestamp,
        StaleDelivery,
        MalformedSignature,
        UnsupportedVersion,
        SignatureMismatch,
        BodyTooLarge,
        InvalidKey {
            detail: "configure a 32-byte key".into(),
        },
        InvalidEnvelope,
        IdMismatch,
    ];
    assert_eq!(
        errors.each_ref().map(|error| error.code()),
        [
            "missing-header",
            "duplicate-header",
            "invalid-content-type",
            "invalid-id",
            "invalid-timestamp",
            "stale-delivery",
            "malformed-signature",
            "unsupported-version",
            "signature-mismatch",
            "body-too-large",
            "invalid-key",
            "invalid-envelope",
            "id-mismatch",
        ]
    );
    for error in errors {
        assert!(!error.to_string().contains(ID));
        assert!(!error.to_string().contains(SIGNATURE));
    }
}
