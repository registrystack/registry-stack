// SPDX-License-Identifier: Apache-2.0
use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use registry_platform_crypto::delivery_signature::*;
use serde::Deserialize;

const BODY: &[u8] = b"{\"ok\":true}";
const ID: &str = "msg_demo";
const TIMESTAMP: u64 = 1_788_048_001;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    name: String,
    key_hex: String,
    previous_key_hex: Option<String>,
    id: String,
    timestamp: String,
    body: String,
    signature: String,
    now: u64,
    expected: String,
    key_policy: String,
}

fn from_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn key(byte: u8) -> DeliveryKey {
    DeliveryKey::new(&[byte; 32]).unwrap()
}

fn keys() -> DeliveryKeys {
    DeliveryKeys::new(key(1), None).unwrap()
}

fn content(signature: &str) -> SignedContent<'_> {
    SignedContent {
        id: ID,
        timestamp: "1788048001",
        signature,
        body: BODY,
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

#[test]
fn shared_vectors_sign_and_verify() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("fixtures/standard-webhooks.json")).unwrap();
    for vector in vectors {
        let current = DeliveryKey::new(&from_hex(&vector.key_hex));
        if vector.key_policy == "below-minimum" {
            assert_eq!(
                current.unwrap_err(),
                DeliveryKeyError::TooShort { length: 24 }
            );
            continue;
        }
        assert_eq!(vector.key_policy, "accepted");
        let previous = vector
            .previous_key_hex
            .map(|hex| DeliveryKey::new(&from_hex(&hex)).unwrap());
        let keys = DeliveryKeys::new(current.unwrap(), previous).unwrap();
        let signed = SignedContent {
            id: &vector.id,
            timestamp: &vector.timestamp,
            signature: &vector.signature,
            body: vector.body.as_bytes(),
        };
        let result = verify(&keys, signed, at(vector.now), DELIVERY_TOLERANCE);
        if vector.expected == "accepted" {
            let timestamp = vector.timestamp.parse().unwrap();
            assert_eq!(result, Ok(timestamp), "{}", vector.name);
            assert_eq!(
                sign(&keys, &vector.id, timestamp, vector.body.as_bytes()).unwrap(),
                vector.signature,
                "{}",
                vector.name
            );
        } else {
            assert_eq!(
                result.unwrap_err().code(),
                vector.expected,
                "{}",
                vector.name
            );
        }
    }
}

#[test]
fn a_key_below_32_bytes_is_refused_even_though_the_published_vector_uses_one() {
    let error = DeliveryKey::new(&[0; 24]).unwrap_err();
    assert_eq!(error, DeliveryKeyError::TooShort { length: 24 });
    assert_eq!(error.code(), "key-too-short");
    assert!(error.to_string().contains("24"));
}

#[test]
fn a_key_above_64_bytes_names_its_length_and_trailing_newline() {
    let mut bytes = [b'a'; 65];
    bytes[64] = b'\n';
    let error = DeliveryKey::new(&bytes).unwrap_err();
    assert_eq!(
        error,
        DeliveryKeyError::TooLong {
            length: 65,
            trailing_newline: true
        }
    );
    assert_eq!(error.code(), "key-too-long");
    assert!(error.to_string().contains("65"));
    assert!(error.to_string().contains("newline"));
    assert_eq!(
        DeliveryKey::new(&[0; 65]).unwrap_err(),
        DeliveryKeyError::TooLong {
            length: 65,
            trailing_newline: false
        }
    );
}

#[test]
fn whsec_text_is_refused_as_key_material() {
    let error = DeliveryKey::new(b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap_err();
    assert_eq!(error, DeliveryKeyError::SecretText);
    assert_eq!(error.code(), "key-is-secret-text");
}

#[test]
fn two_keys_sign_two_entries_current_first() {
    let rotated = DeliveryKeys::new(key(1), Some(key(2))).unwrap();
    let previous = DeliveryKeys::new(key(2), None).unwrap();
    let first = sign(&keys(), ID, TIMESTAMP, BODY).unwrap();
    let second = sign(&previous, ID, TIMESTAMP, BODY).unwrap();
    assert_eq!(
        sign(&rotated, ID, TIMESTAMP, BODY).unwrap(),
        format!("{first} {second}")
    );
}

#[test]
fn a_rotated_signature_verifies_under_either_key() {
    let rotated = DeliveryKeys::new(key(1), Some(key(2))).unwrap();
    let header = sign(&rotated, ID, TIMESTAMP, BODY).unwrap();
    for byte in [1, 2] {
        let single = DeliveryKeys::new(key(byte), None).unwrap();
        assert_eq!(
            verify_authenticity(&single, content(&header)),
            Ok(TIMESTAMP)
        );
        let single_header = sign(&single, ID, TIMESTAMP, BODY).unwrap();
        assert_eq!(
            verify_authenticity(&rotated, content(&single_header)),
            Ok(TIMESTAMP)
        );
    }
}

#[test]
fn a_previous_key_equal_to_the_current_key_is_refused() {
    let error = DeliveryKeys::new(key(1), Some(key(1))).unwrap_err();
    assert_eq!(error, DeliveryKeyError::PreviousEqualsCurrent);
    assert_eq!(error.code(), "previous-key-equals-current");
}

#[test]
fn unknown_versions_are_skipped_and_no_v1_is_unsupported() {
    let keys = keys();
    let header = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
    assert_eq!(
        verify_authenticity(&keys, content(&format!("v1a,opaque {header} v2,opaque"))),
        Ok(TIMESTAMP)
    );
    assert_eq!(
        verify_authenticity(&keys, content("v1a,opaque")),
        Err(DeliverySignatureError::UnsupportedVersion)
    );
}

#[test]
fn more_than_four_entries_is_malformed() {
    let keys = keys();
    let header = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
    assert_eq!(
        verify_authenticity(&keys, content(&format!("{header} v2,a v2,b v2,c"))),
        Ok(TIMESTAMP)
    );
    assert_eq!(
        verify_authenticity(&keys, content(&format!("{header} v2,a v2,b v2,c v2,d"))),
        Err(DeliverySignatureError::MalformedSignature)
    );
}

#[test]
fn malformed_entries_refuse_the_entire_header() {
    let keys = keys();
    let header = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
    for malformed in [
        String::new(),
        format!(" {header}"),
        format!("{header}  v2,opaque"),
        format!("{header} broken"),
        format!("{header} {}", header.trim_end_matches('=')),
        format!("{header} v1,{}B=", "A".repeat(42)),
        format!("{header} v1,{}=", "_".repeat(43)),
        format!("{header} v1,"),
    ] {
        assert_eq!(
            verify_authenticity(&keys, content(&malformed)),
            Err(DeliverySignatureError::MalformedSignature)
        );
    }
}

#[test]
fn the_window_is_300_seconds_in_both_directions() {
    let keys = keys();
    let header = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
    assert_eq!(DELIVERY_TOLERANCE, Duration::from_secs(300));
    let timestamp = at(TIMESTAMP);
    for edge in [
        timestamp - DELIVERY_TOLERANCE,
        timestamp + DELIVERY_TOLERANCE,
    ] {
        assert_eq!(
            verify(&keys, content(&header), edge, DELIVERY_TOLERANCE),
            Ok(TIMESTAMP)
        );
    }
    let outside = DELIVERY_TOLERANCE + Duration::from_nanos(1);
    for stale in [timestamp - outside, timestamp + outside] {
        assert_eq!(
            verify(&keys, content(&header), stale, DELIVERY_TOLERANCE),
            Err(DeliverySignatureError::StaleDelivery)
        );
    }
}

#[test]
fn ids_with_a_period_or_a_space_are_refused() {
    let keys = keys();
    let header = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
    for id in ["has.period", "has space", "", "é", "\x7f", &"x".repeat(257)] {
        assert_eq!(
            sign(&keys, id, TIMESTAMP, BODY),
            Err(DeliverySignatureError::InvalidId)
        );
        assert_eq!(
            verify_authenticity(
                &keys,
                SignedContent {
                    id,
                    ..content(&header)
                }
            ),
            Err(DeliverySignatureError::InvalidId)
        );
    }
    assert!(sign(&keys, &"~".repeat(MAX_WEBHOOK_ID_BYTES), TIMESTAMP, BODY).is_ok());
}

#[test]
fn timestamps_must_be_canonical_decimal() {
    let keys = keys();
    let header = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
    for timestamp in [
        "",
        "00",
        "01",
        "+1",
        "-1",
        " 1",
        "1\t",
        "١",
        "18446744073709551616",
        "111111111111111111111",
    ] {
        assert_eq!(
            verify_authenticity(
                &keys,
                SignedContent {
                    timestamp,
                    ..content(&header)
                }
            ),
            Err(DeliverySignatureError::InvalidTimestamp)
        );
    }
    for value in [0, u64::MAX] {
        let timestamp = value.to_string();
        let signature = sign(&keys, ID, value, BODY).unwrap();
        assert_eq!(
            verify_authenticity(
                &keys,
                SignedContent {
                    timestamp: &timestamp,
                    ..content(&signature)
                }
            ),
            Ok(value)
        );
    }
}

#[test]
fn body_bounds_apply_to_signing_and_verification() {
    let keys = keys();
    let body = vec![0xFF; MAX_BODY_BYTES + 1];
    let signature = sign(&keys, ID, TIMESTAMP, &body[..MAX_BODY_BYTES]).unwrap();
    assert_eq!(
        verify_authenticity(
            &keys,
            SignedContent {
                body: &body[..MAX_BODY_BYTES],
                ..content(&signature)
            }
        ),
        Ok(TIMESTAMP)
    );
    assert_eq!(
        verify_authenticity(
            &keys,
            SignedContent {
                body: &body,
                ..content(&signature)
            }
        ),
        Err(DeliverySignatureError::BodyTooLarge)
    );
    assert_eq!(
        sign(&keys, ID, TIMESTAMP, &body),
        Err(DeliverySignatureError::BodyTooLarge)
    );
}

#[test]
fn distinct_delivery_keys_names_both_paths() {
    let first = key(b'x');
    let second = key(b'y');
    let same = key(b'x');
    distinct_delivery_keys([("one.current", &first), ("one.previous", &second)]).unwrap();
    let error = distinct_delivery_keys([
        ("one.current", &first),
        ("one.previous", &second),
        ("two.previous", &same),
    ])
    .unwrap_err();
    assert_eq!(error.code(), "key-repeated");
    let message = error.to_string();
    assert!(message.contains("one.current"));
    assert!(message.contains("two.previous"));
    assert!(!message.contains(&"x".repeat(32)));
}

#[test]
fn debug_redacts_delivery_keys() {
    assert_eq!(format!("{:?}", key(b'x')), "[REDACTED]");
    assert_eq!(
        format!(
            "{:?}",
            DeliveryKeys::new(key(b'x'), Some(key(b'y'))).unwrap()
        ),
        "DeliveryKeys { current: [REDACTED], previous: Some([REDACTED]) }"
    );
}

#[test]
fn verifies_freshness_at_extreme_timestamps_without_panicking() {
    let keys = DeliveryKeys::new(key(1), None).unwrap();
    for (timestamp, now) in [
        (u64::MAX, SystemTime::UNIX_EPOCH),
        (TIMESTAMP, SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
    ] {
        let signature = sign(&keys, ID, timestamp, BODY).unwrap();
        let result = verify(
            &keys,
            SignedContent {
                id: ID,
                timestamp: &timestamp.to_string(),
                signature: &signature,
                body: BODY,
            },
            now,
            DELIVERY_TOLERANCE,
        );
        assert_eq!(result, Err(DeliverySignatureError::StaleDelivery));
    }
}

fn signature_entries() -> impl Strategy<Value = Vec<(String, String)>> {
    let version =
        prop_oneof![Just("v1"), Just("v1a"), Just("v2"), Just("")].prop_map(str::to_owned);
    let value = prop_oneof![
        4 => "[A-Za-z0-9+/=_,-]{44}",
        1 => "[A-Za-z0-9+/=_,-]{0,46}",
    ];
    proptest::collection::vec((version, value), 1..=6)
}

proptest! {
    #[test]
    fn a_structured_signature_header_only_authenticates_with_a_real_tag(
        entries in signature_entries(),
        real_entry in proptest::option::of(0usize..6),
        double_space in any::<bool>(),
    ) {
        let keys = DeliveryKeys::new(key(1), None).unwrap();
        let signature = sign(&keys, ID, TIMESTAMP, BODY).unwrap();
        let mut entries: Vec<_> = entries.into_iter().map(|(version, value)| {
            format!("{version},{value}")
        }).collect();
        if let Some(index) = real_entry {
            let slot = index % entries.len();
            entries[slot].clone_from(&signature);
        }
        let header = entries.join(if double_space { "  " } else { " " });
        let result = verify_authenticity(&keys, SignedContent {
            id: ID, timestamp: &TIMESTAMP.to_string(), signature: &header, body: BODY,
        });
        prop_assert!(result.is_err() || entries.contains(&signature));
    }

    #[test]
    fn the_signature_header_parser_never_panics_and_round_trips(
        arbitrary_header in any::<String>(),
        id in "[a-zA-Z0-9_-]{1,256}",
        timestamp in any::<u64>(),
        body in proptest::collection::vec(any::<u8>(), 0..1024),
        rotate in any::<bool>(),
    ) {
        let keys = DeliveryKeys::new(key(1), rotate.then(|| key(2))).unwrap();
        let signature = sign(&keys, &id, timestamp, &body).unwrap();
        let timestamp_text = timestamp.to_string();
        let signed = SignedContent { id: &id, timestamp: &timestamp_text, signature: &signature, body: &body };
        let _ = verify_authenticity(&keys, SignedContent { signature: &arbitrary_header, ..signed });
        prop_assert_eq!(verify_authenticity(&keys, signed), Ok(timestamp));
    }
}
