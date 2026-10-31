// SPDX-License-Identifier: Apache-2.0

//! The continuation cursor codec of `products/adapter/CONCEPT.md`
//! section 8.11.2: a search route's `AdapterNextContinuation` value
//! sealed as the opaque `nextCursor` and opened back, bound to the
//! concrete operation, the binding id, the caller's issuer and `sub`,
//! the deployment, the filter digest, and an expiry. Every refusal is the one
//! caller-facing `facade.invalid-cursor`; the reason stays
//! distinguishable here and in the journal, and carries no cursor
//! content (section 13.7).
//!
//! Camel has no counterpart: its REST DSL passes paging parameters
//! through as plain headers, so no `camel-4.23.0:` rule decides a case
//! in this module.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_adapter::component::rest::continuation::{
    filter_digest, ContinuationCodec, ContinuationConfigError, CursorBinding, CursorKey,
    CursorRefusal, CursorTtl, FilterDigest, SealError, CONTINUATION_MAXIMUM_BYTES,
    CURSOR_KEY_BYTES, CURSOR_MAXIMUM_TOKEN_BYTES, CURSOR_TTL_DEFAULT_SECONDS,
    CURSOR_TTL_MAXIMUM_SECONDS, CURSOR_TTL_MINIMUM_SECONDS,
};
use registry_adapter_core::ErrorClass;
use serde_json::{json, Value};
use zeroize::Zeroizing;

const CURRENT: &[u8; 32] = b"continuation-test-key-current-01";
const PREVIOUS: &[u8; 32] = b"continuation-test-key-previous-1";
const UNRELATED: &[u8; 32] = b"continuation-test-key-unrelated1";

/// A substring every test key carries, for the redaction assertions.
const KEY_MARKER: &str = "continuation-test-key";
/// A substring the sealed continuation values carry, for the same.
const VALUE_MARKER: &str = "upstream-position-marker";

const ISSUED_AT: u64 = 1_800_000_000;

/// The project lock digest the test deployment serves.
const DEPLOYMENT: &str = "sha256:0f3a9c1e5b7d2468ace0f3a9c1e5b7d2468ace0f3a9c1e5b7d2468ace0f3a9c";

fn secret(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes.to_vec())
}

fn key(bytes: &[u8]) -> CursorKey {
    CursorKey::new(secret(bytes)).expect("a 32-byte test key")
}

fn codec_with(current: &[u8], previous: Option<&[u8]>, ttl_seconds: u64) -> ContinuationCodec {
    ContinuationCodec::new(
        key(current),
        previous.map(key),
        CursorTtl::from_seconds(ttl_seconds).expect("a TTL inside the bounds"),
    )
}

fn codec() -> ContinuationCodec {
    codec_with(CURRENT, None, CURSOR_TTL_DEFAULT_SECONDS)
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn inputs() -> Value {
    json!({"recordType": "persons", "filters": {"region": "north", "active": true}})
}

fn digest() -> FilterDigest {
    filter_digest(&inputs(), 25).expect("canonicalizable inputs")
}

fn binding(filters: FilterDigest) -> CursorBinding<'static> {
    CursorBinding {
        operation: "search-persons",
        binding_id: "persons-search",
        issuer: "https://issuer.example",
        subject: "caller-1",
        deployment: DEPLOYMENT,
        filters,
    }
}

fn continuation() -> Value {
    json!({
        "upstreamCursor": VALUE_MARKER,
        "offset": 40,
        "next": "https://source.example/fhir/Patient?_page=3",
    })
}

fn sealed(codec: &ContinuationCodec, value: &Value) -> String {
    codec
        .seal(Some(value), &binding(digest()), at(ISSUED_AT))
        .expect("seal succeeds")
        .expect("a non-null value seals to a cursor")
}

fn open(codec: &ContinuationCodec, token: &str) -> Result<Value, CursorRefusal> {
    codec.open(token, &binding(digest()), at(ISSUED_AT + 1))
}

/// A JSON string whose compact serialization is exactly `bytes` long.
fn string_of_serialized_length(bytes: usize) -> Value {
    Value::String("a".repeat(bytes - 2))
}

// Round trip and the last-page rule.

#[test]
fn a_sealed_continuation_opens_to_the_same_value() {
    let codec = codec();
    let value = continuation();
    let token = sealed(&codec, &value);
    assert_eq!(open(&codec, &token), Ok(value));
}

#[test]
fn every_json_shape_round_trips() {
    let codec = codec();
    for value in [
        json!(0),
        json!(40),
        json!(-1),
        json!(1.5),
        json!("opaque"),
        json!(true),
        json!([1, "two", null]),
        json!({"a": {"b": [null, false]}}),
    ] {
        let token = sealed(&codec, &value);
        assert_eq!(open(&codec, &token), Ok(value));
    }
}

#[test]
fn an_absent_or_null_continuation_is_the_last_page() {
    let codec = codec();
    let binding = binding(digest());
    assert_eq!(codec.seal(None, &binding, at(ISSUED_AT)), Ok(None));
    assert_eq!(
        codec.seal(Some(&Value::Null), &binding, at(ISSUED_AT)),
        Ok(None)
    );
}

#[test]
fn the_cursor_is_opaque_and_never_repeats() {
    let codec = codec();
    let value = continuation();
    let first = sealed(&codec, &value);
    let second = sealed(&codec, &value);
    assert_ne!(first, second, "a fresh random nonce per seal");
    for token in [&first, &second] {
        assert!(!token.contains(VALUE_MARKER));
        let envelope = URL_SAFE_NO_PAD.decode(token).expect("url-safe base64");
        let plain = String::from_utf8_lossy(&envelope);
        assert!(!plain.contains(VALUE_MARKER), "the value is encrypted");
        assert!(
            !plain.contains("caller-1"),
            "the binding is not on the wire"
        );
        assert!(token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    }
}

// Tamper.

#[test]
fn flipping_any_character_of_the_token_is_refused() {
    let codec = codec();
    let token = sealed(&codec, &continuation());
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for position in 0..token.len() {
        let mut bytes = token.clone().into_bytes();
        let index = alphabet
            .iter()
            .position(|candidate| *candidate == bytes[position])
            .expect("the token is url-safe base64");
        bytes[position] = alphabet[(index + 1) % alphabet.len()];
        let tampered = String::from_utf8(bytes).expect("ascii");
        let refusal = open(&codec, &tampered).expect_err("a tampered token is refused");
        assert!(
            matches!(
                refusal,
                CursorRefusal::Unauthenticated
                    | CursorRefusal::Malformed
                    | CursorRefusal::UnsupportedVersion
            ),
            "position {position} refused as {refusal:?}"
        );
    }
}

#[test]
fn flipping_any_bit_of_the_decoded_envelope_is_refused() {
    let codec = codec();
    let token = sealed(&codec, &continuation());
    let envelope = URL_SAFE_NO_PAD.decode(&token).expect("url-safe base64");
    for position in 0..envelope.len() {
        for bit in 0..8 {
            let mut tampered = envelope.clone();
            tampered[position] ^= 1 << bit;
            let expected = if position == 0 {
                CursorRefusal::UnsupportedVersion
            } else {
                CursorRefusal::Unauthenticated
            };
            assert_eq!(
                open(&codec, &URL_SAFE_NO_PAD.encode(&tampered)),
                Err(expected),
                "byte {position} bit {bit}"
            );
        }
    }
}

#[test]
fn a_truncated_or_extended_envelope_is_refused() {
    let codec = codec();
    let token = sealed(&codec, &continuation());
    let envelope = URL_SAFE_NO_PAD.decode(&token).expect("url-safe base64");
    let mut shorter = envelope.clone();
    shorter.pop();
    assert_eq!(
        open(&codec, &URL_SAFE_NO_PAD.encode(&shorter)),
        Err(CursorRefusal::Unauthenticated)
    );
    let mut longer = envelope;
    longer.push(0);
    assert_eq!(
        open(&codec, &URL_SAFE_NO_PAD.encode(&longer)),
        Err(CursorRefusal::Unauthenticated)
    );
}

// Expiry.

#[test]
fn a_cursor_opens_until_the_second_before_its_expiry_and_not_after() {
    for ttl in [CURSOR_TTL_MINIMUM_SECONDS, CURSOR_TTL_DEFAULT_SECONDS] {
        let codec = codec_with(CURRENT, None, ttl);
        let value = continuation();
        let token = sealed(&codec, &value);
        let binding = binding(digest());
        assert_eq!(
            codec.open(&token, &binding, at(ISSUED_AT + ttl - 1)),
            Ok(value.clone()),
            "ttl {ttl}: one second before expiry"
        );
        assert_eq!(
            codec.open(&token, &binding, at(ISSUED_AT + ttl)),
            Err(CursorRefusal::Expired),
            "ttl {ttl}: at expiry"
        );
        assert_eq!(
            codec.open(&token, &binding, at(ISSUED_AT + ttl + 1)),
            Err(CursorRefusal::Expired),
            "ttl {ttl}: after expiry"
        );
    }
}

#[test]
fn a_shortened_ttl_applies_to_cursors_already_issued() {
    let long = codec_with(CURRENT, None, 3_600);
    let token = sealed(&long, &continuation());
    let short = codec_with(CURRENT, None, CURSOR_TTL_MINIMUM_SECONDS);
    assert_eq!(
        short.open(
            &token,
            &binding(digest()),
            at(ISSUED_AT + CURSOR_TTL_MINIMUM_SECONDS)
        ),
        Err(CursorRefusal::Expired)
    );
}

#[test]
fn a_clock_before_the_epoch_refuses_to_seal_and_to_open() {
    let codec = codec();
    let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
    let binding = binding(digest());
    assert_eq!(
        codec.seal(Some(&continuation()), &binding, before_epoch),
        Err(SealError::Clock)
    );
    let token = sealed(&codec, &continuation());
    assert_eq!(
        codec.open(&token, &binding, before_epoch),
        Err(CursorRefusal::Clock)
    );
}

// Binding: caller, operation, binding id, deployment, filters, page size.

fn assert_refused_under(other: &CursorBinding<'_>) {
    let codec = codec();
    let token = sealed(&codec, &continuation());
    assert_eq!(
        codec.open(&token, other, at(ISSUED_AT + 1)),
        Err(CursorRefusal::Unauthenticated)
    );
}

#[test]
fn a_cursor_replayed_by_a_caller_under_another_issuer_is_refused() {
    assert_refused_under(&CursorBinding {
        issuer: "https://other-issuer.example",
        ..binding(digest())
    });
}

#[test]
fn a_cursor_replayed_by_another_subject_is_refused() {
    assert_refused_under(&CursorBinding {
        subject: "caller-2",
        ..binding(digest())
    });
}

#[test]
fn a_cursor_presented_to_another_operation_is_refused() {
    assert_refused_under(&CursorBinding {
        operation: "search-households",
        ..binding(digest())
    });
}

#[test]
fn a_cursor_presented_to_another_binding_is_refused() {
    assert_refused_under(&CursorBinding {
        binding_id: "persons-search-v2",
        ..binding(digest())
    });
}

#[test]
fn a_cursor_minted_before_a_redeploy_is_refused_by_the_new_deployment() {
    assert_refused_under(&CursorBinding {
        deployment: "sha256:7e1b4d8a2c6f0935bd7e1b4d8a2c6f0935bd7e1b4d8a2c6f0935bd7e1b4d8a2c",
        ..binding(digest())
    });
}

#[test]
fn a_cursor_replayed_with_other_filters_is_refused() {
    let other = filter_digest(
        &json!({"recordType": "persons", "filters": {"region": "south", "active": true}}),
        25,
    )
    .expect("canonicalizable inputs");
    assert_refused_under(&binding(other));
}

#[test]
fn a_cursor_replayed_with_another_page_size_is_refused() {
    let other = filter_digest(&inputs(), 50).expect("canonicalizable inputs");
    assert_refused_under(&binding(other));
}

fn assert_shift_refused(original: &CursorBinding<'_>, shifted: &CursorBinding<'_>) {
    let codec = codec();
    let token = codec
        .seal(Some(&continuation()), original, at(ISSUED_AT))
        .expect("seal succeeds")
        .expect("a cursor");
    assert_eq!(
        codec.open(&token, shifted, at(ISSUED_AT + 1)),
        Err(CursorRefusal::Unauthenticated)
    );
}

#[test]
fn field_boundaries_cannot_be_shifted_between_binding_fields() {
    assert_shift_refused(
        &CursorBinding {
            operation: "search",
            binding_id: "persons",
            ..binding(digest())
        },
        &CursorBinding {
            operation: "searchp",
            binding_id: "ersons",
            ..binding(digest())
        },
    );
}

#[test]
fn field_boundaries_cannot_be_shifted_between_subject_and_deployment() {
    assert_shift_refused(
        &CursorBinding {
            subject: "caller-1",
            deployment: "sha256:abc",
            ..binding(digest())
        },
        &CursorBinding {
            subject: "caller-1s",
            deployment: "ha256:abc",
            ..binding(digest())
        },
    );
}

// Key rotation.

#[test]
fn a_cursor_sealed_under_the_previous_key_opens_after_rotation() {
    let before = codec_with(PREVIOUS, None, CURSOR_TTL_DEFAULT_SECONDS);
    let value = continuation();
    let token = sealed(&before, &value);
    let rotated = codec_with(CURRENT, Some(PREVIOUS), CURSOR_TTL_DEFAULT_SECONDS);
    assert_eq!(open(&rotated, &token), Ok(value));
}

#[test]
fn a_cursor_sealed_under_an_unrelated_key_is_refused() {
    let stranger = codec_with(UNRELATED, None, CURSOR_TTL_DEFAULT_SECONDS);
    let token = sealed(&stranger, &continuation());
    let rotated = codec_with(CURRENT, Some(PREVIOUS), CURSOR_TTL_DEFAULT_SECONDS);
    assert_eq!(open(&rotated, &token), Err(CursorRefusal::Unauthenticated));
}

#[test]
fn sealing_never_uses_the_previous_key() {
    let rotated = codec_with(CURRENT, Some(PREVIOUS), CURSOR_TTL_DEFAULT_SECONDS);
    let value = continuation();
    let token = sealed(&rotated, &value);
    let current_only = codec_with(CURRENT, None, CURSOR_TTL_DEFAULT_SECONDS);
    assert_eq!(open(&current_only, &token), Ok(value));
    let previous_only = codec_with(PREVIOUS, None, CURSOR_TTL_DEFAULT_SECONDS);
    assert_eq!(
        open(&previous_only, &token),
        Err(CursorRefusal::Unauthenticated)
    );
}

#[test]
fn a_previous_key_cursor_still_expires_on_time() {
    let before = codec_with(PREVIOUS, None, CURSOR_TTL_DEFAULT_SECONDS);
    let token = sealed(&before, &continuation());
    let rotated = codec_with(CURRENT, Some(PREVIOUS), CURSOR_TTL_DEFAULT_SECONDS);
    assert_eq!(
        rotated.open(
            &token,
            &binding(digest()),
            at(ISSUED_AT + CURSOR_TTL_DEFAULT_SECONDS)
        ),
        Err(CursorRefusal::Expired)
    );
}

// Size bounds.

#[test]
fn a_continuation_at_the_bound_seals_and_one_byte_over_is_refused() {
    let codec = codec();
    let at_bound = string_of_serialized_length(CONTINUATION_MAXIMUM_BYTES);
    assert_eq!(
        serde_json::to_vec(&at_bound).expect("a value").len(),
        CONTINUATION_MAXIMUM_BYTES
    );
    let token = sealed(&codec, &at_bound);
    assert_eq!(token.len(), CURSOR_MAXIMUM_TOKEN_BYTES);
    // The largest token stays within the 4096-character cursor bound of
    // the GovStack Consultation draft and uses only URL-safe characters.
    assert!(token.len() <= 4096, "{} characters", token.len());
    assert!(token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    assert_eq!(open(&codec, &token), Ok(at_bound));

    let over = string_of_serialized_length(CONTINUATION_MAXIMUM_BYTES + 1);
    assert_eq!(
        codec.seal(Some(&over), &binding(digest()), at(ISSUED_AT)),
        Err(SealError::ValueTooLarge)
    );
}

#[test]
fn an_oversize_token_is_refused_before_any_decode() {
    let codec = codec();
    // Not base64 at all: a decode would answer `Malformed`, so `Oversize`
    // proves the length bound runs first.
    let garbage = "!".repeat(CURSOR_MAXIMUM_TOKEN_BYTES + 1);
    assert_eq!(open(&codec, &garbage), Err(CursorRefusal::Oversize));
    let alphabet_only = "A".repeat(CURSOR_MAXIMUM_TOKEN_BYTES + 1);
    assert_eq!(open(&codec, &alphabet_only), Err(CursorRefusal::Oversize));
    let huge = "A".repeat(1 << 20);
    assert_eq!(open(&codec, &huge), Err(CursorRefusal::Oversize));
}

// Malformed and versioned.

#[test]
fn a_token_that_is_not_url_safe_unpadded_base64_is_malformed() {
    let codec = codec();
    let token = sealed(&codec, &continuation());
    let standard_alphabet = token.replace('-', "+").replace('_', "/");
    let mut candidates = vec![
        String::new(),
        "!!!!".to_owned(),
        "a b c".to_owned(),
        format!("{token}="),
        "A".to_owned(),
    ];
    if standard_alphabet != token {
        candidates.push(standard_alphabet);
    }
    for candidate in candidates {
        assert_eq!(
            open(&codec, &candidate),
            Err(CursorRefusal::Malformed),
            "{candidate:?}"
        );
    }
}

#[test]
fn an_envelope_too_short_to_hold_a_header_and_tag_is_malformed() {
    let codec = codec();
    for length in [1, 24, 25, 40, 1 + 24 + 16, 1 + 24 + 8 + 16] {
        let mut envelope = vec![0_u8; length];
        envelope[0] = 1;
        assert_eq!(
            open(&codec, &URL_SAFE_NO_PAD.encode(&envelope)),
            Err(CursorRefusal::Malformed),
            "envelope of {length} bytes"
        );
    }
}

#[test]
fn a_token_under_another_wire_version_is_refused() {
    let codec = codec();
    let token = sealed(&codec, &continuation());
    let envelope = URL_SAFE_NO_PAD.decode(&token).expect("url-safe base64");
    assert_eq!(envelope[0], 1, "the wire format is version 1");
    for version in [0_u8, 2, 255] {
        let mut other = envelope.clone();
        other[0] = version;
        assert_eq!(
            open(&codec, &URL_SAFE_NO_PAD.encode(&other)),
            Err(CursorRefusal::UnsupportedVersion),
            "version {version}"
        );
    }
}

// Configuration.

#[test]
fn the_ttl_is_bounded_60_to_86400_with_a_default_of_900() {
    assert_eq!(CURSOR_TTL_MINIMUM_SECONDS, 60);
    assert_eq!(CURSOR_TTL_MAXIMUM_SECONDS, 86_400);
    assert_eq!(CURSOR_TTL_DEFAULT_SECONDS, 900);
    assert_eq!(CursorTtl::default().seconds(), 900);
    for refused in [0, 59, 86_401, u64::MAX] {
        assert_eq!(
            CursorTtl::from_seconds(refused),
            Err(ContinuationConfigError::TtlOutOfBounds),
            "{refused}"
        );
    }
    for accepted in [60, 900, 86_400] {
        assert_eq!(
            CursorTtl::from_seconds(accepted).map(CursorTtl::seconds),
            Ok(accepted)
        );
    }
}

#[test]
fn a_cursor_key_is_exactly_32_bytes() {
    assert_eq!(CURSOR_KEY_BYTES, 32);
    for length in [0, 1, 16, 31, 33, 64] {
        assert_eq!(
            CursorKey::new(secret(&vec![7_u8; length])).err(),
            Some(ContinuationConfigError::KeyLength),
            "{length} bytes"
        );
    }
    assert!(CursorKey::new(secret(&[7_u8; 32])).is_ok());
}

// Filter digest.

#[test]
fn the_filter_digest_ignores_member_order() {
    let forward: Value = serde_json::from_str(
        r#"{"recordType":"persons","filters":{"region":"north","active":true,"born":{"year":1990,"month":3}}}"#,
    )
    .expect("json");
    let reversed: Value = serde_json::from_str(
        r#"{"filters":{"born":{"month":3,"year":1990},"active":true,"region":"north"},"recordType":"persons"}"#,
    )
    .expect("json");
    assert_eq!(
        filter_digest(&forward, 25).expect("digest"),
        filter_digest(&reversed, 25).expect("digest")
    );
}

#[test]
fn the_filter_digest_changes_with_every_input_and_the_page_size() {
    let base = filter_digest(&inputs(), 25).expect("digest");
    let variants = [
        json!({"recordType": "households", "filters": {"region": "north", "active": true}}),
        json!({"recordType": "persons", "filters": {"region": "north", "active": false}}),
        json!({"recordType": "persons", "filters": {"region": "North", "active": true}}),
        json!({"recordType": "persons", "filters": {"region": "north"}}),
        json!({"recordType": "persons", "filters": {"region": "north", "active": true, "age": 3}}),
        json!({"recordType": "persons", "filters": {"region": "north", "active": "true"}}),
        json!({"recordType": "persons", "filters": {}}),
    ];
    for variant in variants {
        assert_ne!(
            filter_digest(&variant, 25).expect("digest"),
            base,
            "{variant}"
        );
    }
    for page_size in [0, 1, 24, 26, u32::MAX] {
        assert_ne!(
            filter_digest(&inputs(), page_size).expect("digest"),
            base,
            "page size {page_size}"
        );
    }
    assert_eq!(filter_digest(&inputs(), 25).expect("digest"), base);
}

#[test]
fn inputs_outside_i_json_have_no_digest() {
    let unrepresentable = json!({"filters": {"count": u64::MAX}});
    assert!(filter_digest(&unrepresentable, 25).is_err());
}

// Redaction and the caller-facing mapping.

fn assert_value_free(rendered: &str, token: &str) {
    assert!(!rendered.contains(KEY_MARKER), "{rendered}");
    // The key bytes as `Debug` of a byte slice would print them.
    assert!(!rendered.contains("99, 111, 110, 116"), "{rendered}");
    assert!(!rendered.contains(VALUE_MARKER), "{rendered}");
    assert!(!rendered.contains("caller-1"), "{rendered}");
    assert!(!rendered.contains(&token[..16]), "{rendered}");
}

#[test]
fn errors_and_debug_output_carry_no_key_bytes_and_no_cursor_content() {
    let codec = codec_with(CURRENT, Some(PREVIOUS), CURSOR_TTL_DEFAULT_SECONDS);
    let token = sealed(&codec, &continuation());

    let refusals = [
        CursorRefusal::Oversize,
        CursorRefusal::Malformed,
        CursorRefusal::UnsupportedVersion,
        CursorRefusal::Unauthenticated,
        CursorRefusal::Expired,
        CursorRefusal::Clock,
    ];
    for refusal in refusals {
        assert_value_free(&format!("{refusal} {refusal:?}"), &token);
    }
    let seal_errors = [
        SealError::ValueTooLarge,
        SealError::Clock,
        SealError::Randomness,
        SealError::Encryption,
    ];
    for error in seal_errors {
        assert_value_free(&format!("{error} {error:?}"), &token);
    }
    for error in [
        ContinuationConfigError::KeyLength,
        ContinuationConfigError::TtlOutOfBounds,
    ] {
        assert_value_free(&format!("{error} {error:?}"), &token);
    }

    let mut tampered = token.clone().into_bytes();
    tampered[40] = if tampered[40] == b'A' { b'B' } else { b'A' };
    let refusal = open(&codec, &String::from_utf8(tampered).expect("ascii"))
        .expect_err("a tampered token is refused");
    assert_value_free(&format!("{refusal} {refusal:?}"), &token);

    assert_value_free(&format!("{codec:?}"), &token);
    assert_value_free(&format!("{:?}", key(CURRENT)), &token);
    assert_value_free(&format!("{:?}", binding(digest())), &token);
    let digest_debug = format!("{:?}", digest());
    assert!(digest_debug.contains("redacted"), "{digest_debug}");
}

#[test]
fn every_refusal_is_the_one_caller_facing_invalid_request_with_a_distinct_reason() {
    let refusals = [
        CursorRefusal::Oversize,
        CursorRefusal::Malformed,
        CursorRefusal::UnsupportedVersion,
        CursorRefusal::Unauthenticated,
        CursorRefusal::Expired,
        CursorRefusal::Clock,
    ];
    let mut reasons = Vec::new();
    for refusal in refusals {
        assert_eq!(refusal.error_class(), ErrorClass::FacadeInvalidCursor);
        assert_eq!(refusal.error_class().class(), "facade.invalid-cursor");
        reasons.push(refusal.reason());
    }
    let mut distinct = reasons.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), reasons.len(), "{reasons:?}");
}

#[test]
fn key_material_is_wiped_on_drop_and_the_codec_is_shareable() {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    fn shareable<T: Send + Sync>() {}
    wiped_on_drop::<CursorKey>();
    wiped_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
    shareable::<ContinuationCodec>();
}
