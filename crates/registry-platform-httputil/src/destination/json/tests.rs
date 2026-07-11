// SPDX-License-Identifier: Apache-2.0

use crate::destination::{BoundedDestinationBody, DataDestinationBody};

use super::decode::zeroize_json_value;
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
