// SPDX-License-Identifier: Apache-2.0

use crate::destination::sensitive_json::zeroize_json_value;
use crate::destination::{BoundedDestinationBody, DataDestinationBody};

use super::preflight::{preflight_json, JsonPreflightError};
use super::*;

use std::marker::PhantomData;

use serde_json::json;

const SCHEMA_DEPTH: usize = 8;

fn body(raw: impl AsRef<[u8]>) -> DataDestinationBody {
    BoundedDestinationBody {
        bytes: zeroize::Zeroizing::new(raw.as_ref().to_vec()),
        slot: PhantomData,
    }
}

#[test]
fn successful_parse_tree_scrubbing_clears_strings_and_members() {
    let mut value = json!({
        "secret-key": ["secret-value", {"nested-secret": "other-secret"}],
    });
    zeroize_json_value(&mut value);
    assert_eq!(value, json!({}));
}

#[test]
fn encoded_body_ceiling_accepts_exact_cap_and_rejects_cap_plus_one() {
    let mut exact = br#"{"value":null}"#.to_vec();
    exact.resize(MAX_CLOSED_JSON_ENCODED_BODY_BYTES, b' ');
    assert!(decode_script_json(body(&exact)).is_ok());

    exact.push(b' ');
    assert_eq!(
        decode_script_json(body(&exact)).unwrap_err(),
        ScriptResponseDecodeError::StructuralLimitExceeded
    );
}

#[test]
fn preflight_counts_every_value_and_object_key_without_undercounting() {
    let cases: &[(&[u8], usize, usize)] = &[
        (b"null", 1, 1),
        (b"[]", 1, 1),
        (b"{}", 1, 1),
        (br#"[null,true,0,"x",{}]"#, 6, 2),
        (br#"{"a":0,"b":{"c":"x"}}"#, 7, 3),
        (br#"{"key":"escaped quote: \" and braces: {}[]"}"#, 3, 2),
    ];
    for (raw, expected_tokens, expected_depth) in cases {
        let stats = preflight_json(raw, *expected_tokens, *expected_depth).unwrap();
        assert_eq!(stats.tokens, *expected_tokens);
        assert_eq!(stats.maximum_depth, *expected_depth);
        assert_eq!(
            preflight_json(raw, expected_tokens - 1, *expected_depth).unwrap_err(),
            JsonPreflightError::ContractLimitExceeded
        );
    }
}

#[test]
fn preflight_enforces_exact_token_and_schema_depth_boundaries() {
    let exact_tokens = br#"[0,1,2]"#;
    assert_eq!(preflight_json(exact_tokens, 4, 2).unwrap().tokens, 4);
    assert_eq!(
        preflight_json(exact_tokens, 3, 2).unwrap_err(),
        JsonPreflightError::ContractLimitExceeded
    );
    assert_eq!(
        preflight_json(br#"[0,1,2,3]"#, 4, 2).unwrap_err(),
        JsonPreflightError::ContractLimitExceeded
    );

    let exact_depth = format!(
        "{}null{}",
        "[".repeat(SCHEMA_DEPTH - 1),
        "]".repeat(SCHEMA_DEPTH - 1)
    );
    let stats = preflight_json(exact_depth.as_bytes(), SCHEMA_DEPTH, SCHEMA_DEPTH).unwrap();
    assert_eq!(stats.tokens, SCHEMA_DEPTH);
    assert_eq!(stats.maximum_depth, SCHEMA_DEPTH);

    let too_deep = format!(
        "{}null{}",
        "[".repeat(SCHEMA_DEPTH),
        "]".repeat(SCHEMA_DEPTH)
    );
    assert_eq!(
        preflight_json(too_deep.as_bytes(), SCHEMA_DEPTH + 1, SCHEMA_DEPTH,).unwrap_err(),
        JsonPreflightError::ContractLimitExceeded
    );
}

#[test]
fn preflight_is_string_and_escape_aware_and_rejects_malformed_strings() {
    let valid = [
        br#""escaped \" quote and {}[],: comma""#.as_slice(),
        br#""escaped \\ slash \/ controls \b\f\n\r\t""#.as_slice(),
        br#""unicode \u007b not structure""#.as_slice(),
        br#""surrogate pair \ud83d\ude03""#.as_slice(),
        "\"raw UTF-8: สวัสดี\"".as_bytes(),
    ];
    for raw in valid {
        let stats = preflight_json(raw, 1, 1).unwrap();
        assert_eq!(stats.tokens, 1);
        assert_eq!(stats.maximum_depth, 1);
    }

    let invalid = [
        b"\"unterminated".as_slice(),
        br#""bad \q escape""#.as_slice(),
        br#""short \u12""#.as_slice(),
        br#""non-hex \u12xz""#.as_slice(),
        br#""lone leading \ud800""#.as_slice(),
        br#""lone trailing \udc00""#.as_slice(),
        br#""wrong pair \ud800\u0041""#.as_slice(),
        b"\"raw\nnewline\"".as_slice(),
        &[0xff],
    ];
    for raw in invalid {
        assert_eq!(
            preflight_json(raw, 16, 8).unwrap_err(),
            JsonPreflightError::InvalidJson
        );
    }
}

#[test]
fn preflight_conservatively_bounds_duplicates_and_rejects_bad_structure() {
    let duplicate = br#"{"a":1,"a":2}"#;
    let stats = preflight_json(duplicate, 5, 2).unwrap();
    assert_eq!(stats.tokens, 5);
    assert_eq!(stats.maximum_depth, 2);
    assert_eq!(
        preflight_json(duplicate, 4, 2).unwrap_err(),
        JsonPreflightError::ContractLimitExceeded
    );

    for raw in [
        b"{} {}".as_slice(),
        br#"{"a" 1}"#.as_slice(),
        br#"{"a":[1,]}"#.as_slice(),
        br#"{"a":1,}"#.as_slice(),
        br#"[1 2]"#.as_slice(),
        br#"01"#.as_slice(),
        br#"1."#.as_slice(),
        br#"1e+"#.as_slice(),
    ] {
        assert_eq!(
            preflight_json(raw, 32, 8).unwrap_err(),
            JsonPreflightError::InvalidJson
        );
    }
}
