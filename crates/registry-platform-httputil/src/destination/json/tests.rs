// SPDX-License-Identifier: Apache-2.0

use crate::destination::{BoundedDestinationBody, DataDestinationBody};

use super::decode::zeroize_json_value;
use super::preflight::{preflight_json, JsonPreflightError};
use super::*;

use std::marker::PhantomData;

use serde_json::json;

fn body(raw: impl AsRef<[u8]>) -> DataDestinationBody {
    BoundedDestinationBody {
        bytes: zeroize::Zeroizing::new(raw.as_ref().to_vec()),
        slot: PhantomData,
    }
}

fn field(name: &str, required: bool, schema: ClosedJsonSchema) -> ClosedJsonField {
    ClosedJsonField::new(name, required, schema).unwrap()
}

fn string(nullable: bool, max_bytes: u32) -> ClosedJsonSchema {
    ClosedJsonSchema::string(nullable, max_bytes).unwrap()
}

fn integer(nullable: bool, minimum: i64, maximum: i64) -> ClosedJsonSchema {
    ClosedJsonSchema::integer(nullable, minimum, maximum).unwrap()
}

fn object(fields: Vec<ClosedJsonField>) -> ClosedJsonSchema {
    ClosedJsonSchema::object(false, fields).unwrap()
}

fn projection(name: &str, tokens: &[&str]) -> ClosedJsonScalarProjection {
    ClosedJsonScalarProjection::new(name, tokens.iter().copied()).unwrap()
}

fn dhis2_decoder() -> ClosedJsonDecoder {
    let enrollment = object(vec![field("status", true, string(false, 32))]);
    let pager = object(vec![
        field("page", true, integer(false, 1, 1)),
        field("pageSize", true, integer(false, 2, 2)),
    ]);
    let schema = object(vec![
        field(
            "enrollments",
            true,
            ClosedJsonSchema::array(false, 2, enrollment).unwrap(),
        ),
        field("page", true, integer(false, 1, 1)),
        field("pageSize", true, integer(false, 2, 2)),
        field("pager", true, pager),
    ]);
    ClosedJsonDecoder::new(
        schema,
        ClosedJsonRecordRoot::ObjectArrayProbeTwo { field_index: 0 },
        vec![projection("status", &["status"])],
    )
    .unwrap()
}

fn dhis2_response(records: &str) -> String {
    format!(
        r#"{{"enrollments":{records},"page":1,"pageSize":2,"pager":{{"page":1,"pageSize":2}}}}"#
    )
}

fn fresh_projection_record() -> ClosedJsonSchema {
    object(vec![
        field("status", true, string(false, 8)),
        field(
            "nested",
            true,
            object(vec![field(
                "values",
                true,
                ClosedJsonSchema::array(false, 2, string(false, 8)).unwrap(),
            )]),
        ),
    ])
}

#[test]
fn dhis2_wrapper_releases_only_declared_bounded_status() {
    let decoder = dhis2_decoder();
    let outcome = decoder
        .decode(body(dhis2_response(r#"[{"status":"ACTIVE"}]"#)))
        .unwrap();
    let ClosedJsonOutcome::One(record) = &outcome else {
        panic!("one source record expected");
    };
    assert_eq!(record.len(), 1);
    assert!(matches!(
        record.get("status"),
        Some(ProjectedJsonScalar::String(value)) if value.as_str() == "ACTIVE"
    ));
    let diagnostic = format!("{decoder:?} {outcome:?}");
    for forbidden in ["ACTIVE", "status", "enrollments"] {
        assert!(!diagnostic.contains(forbidden));
    }
}

#[test]
fn probe_two_distinguishes_cardinality_without_releasing_ambiguous_values() {
    let decoder = dhis2_decoder();
    assert!(matches!(
        decoder.decode(body(dhis2_response("[]"))).unwrap(),
        ClosedJsonOutcome::NoMatch
    ));
    assert!(matches!(
        decoder
            .decode(body(dhis2_response(r#"[{"status":"A"}]"#)))
            .unwrap(),
        ClosedJsonOutcome::One(_)
    ));
    let ambiguous = decoder
        .decode(body(dhis2_response(
            r#"[{"status":"SECRET-A"},{"status":"SECRET-B"}]"#,
        )))
        .unwrap();
    assert!(matches!(ambiguous, ClosedJsonOutcome::Ambiguous));
    assert!(!format!("{ambiguous:?}").contains("SECRET"));
}

#[test]
fn excess_records_are_a_distinct_value_free_failure() {
    let error = dhis2_decoder()
        .decode(body(dhis2_response(
            r#"[{"status":"A"},{"status":"B"},{"status":"SECRET-C"}]"#,
        )))
        .unwrap_err();
    assert_eq!(error, ClosedJsonDecodeError::CardinalityViolation);
    assert!(!format!("{error:?} {error}").contains("SECRET-C"));
}

#[test]
fn all_three_root_normalizations_are_exact() {
    let record = || object(vec![field("status", true, string(false, 8))]);
    let root_object = ClosedJsonDecoder::new(
        record(),
        ClosedJsonRecordRoot::Object,
        vec![projection("status", &["status"])],
    )
    .unwrap();
    assert!(matches!(
        root_object.decode(body(br#"{"status":"READY"}"#)).unwrap(),
        ClosedJsonOutcome::One(_)
    ));

    let root_array = ClosedJsonDecoder::new(
        ClosedJsonSchema::array(false, 2, record()).unwrap(),
        ClosedJsonRecordRoot::ArrayProbeTwo,
        vec![projection("status", &["status"])],
    )
    .unwrap();
    assert!(matches!(
        root_array.decode(body(b"[]")).unwrap(),
        ClosedJsonOutcome::NoMatch
    ));
    assert!(matches!(
        root_array.decode(body(br#"[{"status":"READY"}]"#)).unwrap(),
        ClosedJsonOutcome::One(_)
    ));

    assert_eq!(
        ClosedJsonDecoder::new(
            ClosedJsonSchema::array(false, 2, record()).unwrap(),
            ClosedJsonRecordRoot::Object,
            vec![],
        )
        .unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidNormalization
    );
}

#[test]
fn strict_json_rejects_duplicates_trailing_values_and_inexact_integers() {
    let decoder = dhis2_decoder();
    let valid = dhis2_response(r#"[{"status":"A"}]"#);
    for raw in [
        dhis2_response(r#"[{"status":"A","status":"B"}]"#),
        dhis2_response(r#"[{"status":"A","\u0073tatus":"B"}]"#),
        format!("{valid} true"),
        valid.replace("\"page\":1", "\"page\":9007199254740993"),
    ] {
        assert_eq!(
            decoder.decode(body(raw)).unwrap_err(),
            ClosedJsonDecodeError::InvalidJson
        );
    }
}

#[test]
fn entire_tree_is_closed_and_recursively_bounded() {
    let decoder = dhis2_decoder();
    let valid = dhis2_response(r#"[{"status":"ACTIVE"}]"#);
    let invalid = [
        valid.replace("\"page\":1,", "\"unknown\":true,\"page\":1,"),
        valid.replace("\"status\":\"ACTIVE\"", "\"status\":\"ACTIVE\",\"extra\":1"),
        valid.replace("\"page\":1,", ""),
        valid.replace("\"page\":1", "\"page\":2"),
        valid.replace("\"pageSize\":2", "\"pageSize\":2.0"),
        valid.replace("\"status\":\"ACTIVE\"", "\"status\":null"),
        valid.replace("ACTIVE", &"X".repeat(33)),
    ];
    for raw in invalid {
        assert_eq!(
            decoder.decode(body(raw)).unwrap_err(),
            ClosedJsonDecodeError::ResponseContractViolation
        );
    }
}

#[test]
fn nullable_projection_maps_missing_member_and_index_to_null_only_when_allowed() {
    let decoder = ClosedJsonDecoder::new(
        object(vec![
            field("optional", false, string(true, 8)),
            field(
                "values",
                false,
                ClosedJsonSchema::array(false, 2, string(true, 8)).unwrap(),
            ),
        ]),
        ClosedJsonRecordRoot::Object,
        vec![
            projection("optional", &["optional"]),
            projection("index", &["values", "1"]),
        ],
    )
    .unwrap();
    let ClosedJsonOutcome::One(record) =
        decoder.decode(body(br#"{"values":["present"]}"#)).unwrap()
    else {
        panic!("one root object expected");
    };
    assert!(matches!(
        record.get("optional"),
        Some(ProjectedJsonScalar::Null)
    ));
    assert!(matches!(
        record.get("index"),
        Some(ProjectedJsonScalar::Null)
    ));

    let non_nullable = ClosedJsonDecoder::new(
        object(vec![field("optional", false, string(false, 8))]),
        ClosedJsonRecordRoot::Object,
        vec![projection("optional", &["optional"])],
    )
    .unwrap();
    assert_eq!(
        non_nullable.decode(body(b"{}")).unwrap_err(),
        ClosedJsonDecodeError::ProjectionContractViolation
    );
}

#[test]
fn all_scalar_kinds_are_validated_and_projected() {
    let names = ["text", "flag", "count", "ratio", "empty"];
    let decoder = ClosedJsonDecoder::new(
        object(vec![
            field("text", true, string(false, 8)),
            field("flag", true, ClosedJsonSchema::boolean(false)),
            field("count", true, integer(false, -2, 2)),
            field(
                "ratio",
                true,
                ClosedJsonSchema::number(false, -2, 2).unwrap(),
            ),
            field("empty", true, string(true, 8)),
        ]),
        ClosedJsonRecordRoot::Object,
        names
            .into_iter()
            .map(|name| projection(name, &[name]))
            .collect(),
    )
    .unwrap();
    let ClosedJsonOutcome::One(record) = decoder
        .decode(body(
            br#"{"text":"safe","flag":true,"count":-1,"ratio":1.5,"empty":null}"#,
        ))
        .unwrap()
    else {
        panic!("one root object expected");
    };
    assert!(matches!(
        record.get("text"),
        Some(ProjectedJsonScalar::String(_))
    ));
    assert!(matches!(
        record.get("flag"),
        Some(ProjectedJsonScalar::Boolean(true))
    ));
    assert!(matches!(
        record.get("count"),
        Some(ProjectedJsonScalar::Integer(-1))
    ));
    assert!(matches!(
        record.get("ratio"),
        Some(ProjectedJsonScalar::Number(value)) if *value == 1.5
    ));
    assert!(matches!(
        record.get("empty"),
        Some(ProjectedJsonScalar::Null)
    ));
}

#[test]
fn schema_compilation_rejects_local_depth_expansion_and_normalization_errors() {
    assert_eq!(
        ClosedJsonSchema::object(false, vec![]).unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidSchema
    );
    assert!(ClosedJsonSchema::array(false, 0, string(false, 1)).is_err());
    assert!(ClosedJsonSchema::string(false, 0).is_err());
    assert!(ClosedJsonSchema::integer(false, 2, 1).is_err());
    assert_eq!(
        ClosedJsonSchema::object(
            false,
            vec![
                field("same", true, string(false, 1)),
                field("same", true, string(false, 1)),
            ],
        )
        .unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidSchema
    );
    let too_many_fields = (0..=MAX_CLOSED_JSON_OBJECT_FIELDS)
        .map(|index| field(&format!("field{index}"), true, string(false, 1)))
        .collect();
    assert_eq!(
        ClosedJsonSchema::object(false, too_many_fields).unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidSchema
    );

    let mut deep = string(false, 1);
    for index in 0..MAX_CLOSED_JSON_SCHEMA_DEPTH {
        deep = object(vec![field(&format!("level{index}"), true, deep)]);
    }
    assert_eq!(
        ClosedJsonDecoder::new(deep, ClosedJsonRecordRoot::Object, vec![]).unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidSchema
    );

    let expanded = ClosedJsonSchema::array(
        false,
        MAX_CLOSED_JSON_ARRAY_ITEMS,
        ClosedJsonSchema::array(
            false,
            MAX_CLOSED_JSON_ARRAY_ITEMS,
            object(vec![field("value", true, string(false, 1))]),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ClosedJsonDecoder::new(expanded, ClosedJsonRecordRoot::ArrayProbeTwo, vec![]).unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidSchema
    );

    let optional_records = object(vec![field(
        "records",
        false,
        ClosedJsonSchema::array(
            false,
            2,
            object(vec![field("value", true, string(false, 1))]),
        )
        .unwrap(),
    )]);
    assert_eq!(
        ClosedJsonDecoder::new(
            optional_records,
            ClosedJsonRecordRoot::ObjectArrayProbeTwo { field_index: 0 },
            vec![],
        )
        .unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidNormalization
    );

    let multiple_arrays = object(vec![
        field(
            "records",
            true,
            ClosedJsonSchema::array(
                false,
                2,
                object(vec![field("value", true, string(false, 1))]),
            )
            .unwrap(),
        ),
        field(
            "other",
            false,
            ClosedJsonSchema::array(false, 1, string(false, 1)).unwrap(),
        ),
    ]);
    assert_eq!(
        ClosedJsonDecoder::new(
            multiple_arrays,
            ClosedJsonRecordRoot::ObjectArrayProbeTwo { field_index: 0 },
            vec![],
        )
        .unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidNormalization
    );
}

#[test]
fn projection_compilation_rejects_missing_composite_noncanonical_and_duplicates() {
    for projections in [
        vec![projection("missing", &["missing"])],
        vec![projection("object", &["nested"])],
        vec![projection("bad_index", &["nested", "values", "01"])],
        vec![
            projection("one", &["status"]),
            projection("two", &["status"]),
        ],
        vec![
            projection("same", &["status"]),
            projection("same", &["nested", "values", "0"]),
        ],
    ] {
        assert_eq!(
            ClosedJsonDecoder::new(
                fresh_projection_record(),
                ClosedJsonRecordRoot::Object,
                projections,
            )
            .unwrap_err(),
            ClosedJsonDecoderBuildError::InvalidProjection
        );
    }

    let too_many = (0..=MAX_CLOSED_JSON_PROJECTIONS)
        .map(|index| projection(&format!("projection{index}"), &["status"]))
        .collect();
    assert_eq!(
        ClosedJsonDecoder::new(
            fresh_projection_record(),
            ClosedJsonRecordRoot::Object,
            too_many,
        )
        .unwrap_err(),
        ClosedJsonDecoderBuildError::InvalidProjection
    );
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
    let decoder = ClosedJsonDecoder::new(
        object(vec![field("value", true, string(true, 1))]),
        ClosedJsonRecordRoot::Object,
        vec![],
    )
    .unwrap();
    let mut exact = br#"{"value":null}"#.to_vec();
    exact.resize(MAX_CLOSED_JSON_ENCODED_BODY_BYTES, b' ');
    assert!(matches!(
        decoder.decode(body(&exact)).unwrap(),
        ClosedJsonOutcome::One(_)
    ));

    exact.push(b' ');
    assert_eq!(
        decoder.decode(body(&exact)).unwrap_err(),
        ClosedJsonDecodeError::ResponseContractViolation
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
        "[".repeat(MAX_CLOSED_JSON_SCHEMA_DEPTH - 1),
        "]".repeat(MAX_CLOSED_JSON_SCHEMA_DEPTH - 1)
    );
    let stats = preflight_json(
        exact_depth.as_bytes(),
        MAX_CLOSED_JSON_SCHEMA_DEPTH,
        MAX_CLOSED_JSON_SCHEMA_DEPTH,
    )
    .unwrap();
    assert_eq!(stats.tokens, MAX_CLOSED_JSON_SCHEMA_DEPTH);
    assert_eq!(stats.maximum_depth, MAX_CLOSED_JSON_SCHEMA_DEPTH);

    let too_deep = format!(
        "{}null{}",
        "[".repeat(MAX_CLOSED_JSON_SCHEMA_DEPTH),
        "]".repeat(MAX_CLOSED_JSON_SCHEMA_DEPTH)
    );
    assert_eq!(
        preflight_json(
            too_deep.as_bytes(),
            MAX_CLOSED_JSON_SCHEMA_DEPTH + 1,
            MAX_CLOSED_JSON_SCHEMA_DEPTH,
        )
        .unwrap_err(),
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

    let decoder = ClosedJsonDecoder::new(
        object(vec![
            field("a", true, integer(false, 0, 2)),
            field("b", false, integer(false, 0, 2)),
        ]),
        ClosedJsonRecordRoot::Object,
        vec![],
    )
    .unwrap();
    assert_eq!(decoder.preflight_token_limit, 10);
    assert_eq!(decoder.preflight_depth_limit, 2);
    assert_eq!(
        decoder.decode(body(duplicate)).unwrap_err(),
        ClosedJsonDecodeError::InvalidJson
    );
}

#[test]
fn compiled_preflight_budget_matches_closed_dhis2_schema_shape() {
    let decoder = dhis2_decoder();
    assert_eq!(decoder.preflight_token_limit, 38);
    assert_eq!(decoder.preflight_depth_limit, 4);

    let escaped_structure = dhis2_response(r#"[{"status":"ACTIVE {}[],: \\\""}]"#);
    assert!(matches!(
        decoder.decode(body(escaped_structure)).unwrap(),
        ClosedJsonOutcome::One(_)
    ));
}
