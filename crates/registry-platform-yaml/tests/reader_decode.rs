// SPDX-License-Identifier: Apache-2.0
//! Typed decoding: the value table, the shared types, unions, shared blocks,
//! substitution hooks, and the diagnostics decoding writes.

mod common;

use std::collections::BTreeSet;

use common::*;
use registry_platform_yaml::{
    shape_union, tagged_union, ApiVersion, BoundedU32, BoundedU64, DataLiteral, Digest,
    EnvelopeRule, Expect, ExternalId, FormatSpec, Identified, Invalid, LocalId, ProjectIdentity,
    Reader, Refusal, Related, Report, ScalarHook, ScalarSite, Severity, UniqueIdList, UniqueList,
    Url, CODES, MAXIMUM_DIAGNOSTICS_PER_FILE,
};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Settings {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    ratio: Option<f64>,
    #[serde(default)]
    retention_days: Option<BoundedU32<1, 36500>>,
    #[serde(default)]
    timeout_seconds: Option<BoundedU32<1, 3600>>,
    #[serde(default)]
    max_bytes: Option<BoundedU64<1, 10_000_000_000>>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    listener: Option<Listener>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Listener {
    bind: String,
    #[serde(default)]
    port: Option<u16>,
}

fn settings(body: &str) -> Settings {
    decode::<Settings>(body).unwrap_or_else(|report| panic!("{report}"))
}

// ----- CFG-VAL-1 -----

#[test]
fn cfg_val_1_an_integer_position_refuses_a_number() {
    for body in ["port: 1e3\n", "port: 5.0\n"] {
        let report = refusal::<Settings>(body);
        assert_diagnostic(
            only(&report),
            "config.expected-integer",
            "/port",
            (3, 7),
            "expected a whole number of 0 or more",
            "Write digits only.",
        );
    }
}

#[test]
fn cfg_val_1_a_number_position_accepts_integers_and_numbers() {
    assert_eq!(settings("ratio: 2\n").ratio, Some(2.0));
    assert_eq!(settings("ratio: -0.25\n").ratio, Some(-0.25));
    assert_eq!(settings("ratio: 2.5E-3\n").ratio, Some(0.0025));
}

#[test]
fn cfg_val_1_an_integer_outside_its_type_is_out_of_range() {
    let report = refusal::<Settings>("port: 70000\n");
    assert_diagnostic(
        only(&report),
        "config.out-of-range",
        "/port",
        (3, 7),
        "the value is outside its bounds; expected a whole number from 0 to 65535",
        "Write a whole number from 0 to 65535.",
    );
    let report = refusal::<Settings>("port: -1\n");
    assert_eq!(codes(&report), ["config.out-of-range"]);
}

#[test]
fn cfg_val_1_signed_zero_reads_as_zero() {
    #[derive(Debug, Deserialize)]
    struct Offset {
        offset: i32,
    }
    assert_eq!(decode::<Offset>("offset: -0\n").unwrap().offset, 0);
    assert_eq!(decode::<Offset>("offset: +5\n").unwrap().offset, 5);
}

// ----- CFG-VAL-2 -----

#[test]
fn cfg_val_2_a_text_position_accepts_only_a_string() {
    for (body, found) in [
        ("name: true\n", "a boolean"),
        ("name: 1.0\n", "a number"),
        ("name: 123\n", "an integer"),
    ] {
        let report = refusal::<Settings>(body);
        assert_diagnostic(
            only(&report),
            "config.expected-string",
            "/name",
            (3, 7),
            &format!("expected text, not {found}"),
            "Quote the value to make it text.",
        );
    }
    assert_eq!(settings("name: \"true\"\n").name.as_deref(), Some("true"));
    assert_eq!(settings("name: yes\n").name.as_deref(), Some("yes"));
    assert_eq!(settings("name: 09:00\n").name.as_deref(), Some("09:00"));
}

#[test]
fn cfg_val_2_a_leading_zero_is_refused_in_a_text_position_too() {
    let report = refusal::<Settings>("name: 0123\n");
    assert_eq!(codes(&report), ["yaml.ambiguous-number"]);
}

// ----- CFG-VAL-3 and the CFG-DIAG-6 value table -----

#[test]
fn cfg_val_3_a_quoted_number_is_refused_at_the_quote() {
    let report = refusal::<Settings>("retentionDays: \"90\"\n");
    assert_diagnostic(
        only(&report),
        "config.expected-integer",
        "/retentionDays",
        (3, 16),
        "expected a whole number of days from 1 to 36500; quoted values are text",
        "Remove the quotes.",
    );
    let report = refusal::<Settings>("port: '8080'\n");
    assert_diagnostic(
        only(&report),
        "config.expected-integer",
        "/port",
        (3, 7),
        "expected a whole number of 0 or more; quoted values are text",
        "Remove the quotes.",
    );
}

#[test]
fn cfg_diag_6_a_unit_suffix_is_refused_naming_the_unit() {
    let report = refusal::<Settings>("timeoutSeconds: 5s\n");
    assert_diagnostic(
        only(&report),
        "config.expected-integer",
        "/timeoutSeconds",
        (3, 17),
        "expected a whole number of seconds from 1 to 3600",
        "Write the number of seconds as digits.",
    );
}

#[test]
fn cfg_diag_6_separators_and_exponents_are_refused_with_digits_only() {
    for body in ["retentionDays: 1_000\n", "retentionDays: 1e6\n"] {
        let report = refusal::<Settings>(body);
        assert_diagnostic(
            only(&report),
            "config.expected-integer",
            "/retentionDays",
            (3, 16),
            "expected a whole number of days from 1 to 36500",
            "Write digits only.",
        );
    }
}

#[test]
fn cfg_diag_6_yes_no_on_off_are_text() {
    for word in ["yes", "no", "on", "off", "Yes", "OFF"] {
        let report = refusal::<Settings>(&format!("enabled: {word}\n"));
        assert_diagnostic(
            only(&report),
            "config.expected-boolean",
            "/enabled",
            (3, 10),
            "expected true or false; yes, no, on, and off are text",
            "Write true or false.",
        );
    }
    let report = refusal::<Settings>("enabled: \"true\"\n");
    assert_diagnostic(
        only(&report),
        "config.expected-boolean",
        "/enabled",
        (3, 10),
        "expected true or false; quoted values are text",
        "Remove the quotes.",
    );
}

/// Replaces every value written `${...}` with a value, as runtime
/// substitution does.
struct Substitute(&'static str);

impl ScalarHook for Substitute {
    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Ok(site.text.starts_with("${").then(|| self.0.to_string()))
    }
}

fn decode_with_hook<T: serde::de::DeserializeOwned>(
    body: &str,
    hook: &mut dyn ScalarHook,
) -> Result<T, Report> {
    Reader::new(FILE)
        .with_hook(hook)
        .decode::<T>(with_envelope(body).as_bytes(), &EXPECT)
        .map(|decoded| decoded.value)
}

#[test]
fn cfg_diag_6_substitution_fills_text_values_only() {
    for (body, code, column) in [
        ("port: ${PORT}\n", "config.expected-integer", 7),
        ("enabled: ${ENABLED}\n", "config.expected-boolean", 10),
        ("ratio: ${RATIO}\n", "config.expected-number", 8),
    ] {
        let report = decode_with_hook::<Settings>(body, &mut Substitute("8080")).unwrap_err();
        let diagnostic = only(&report);
        assert_eq!(diagnostic.code, code, "{body}");
        assert_eq!(at(diagnostic), (3, column), "{body}");
        assert_eq!(diagnostic.message, "substitution fills text values only");
        assert_eq!(
            diagnostic.suggested_action,
            "Write the value, or template the whole file."
        );
    }
    let filled: Settings = decode_with_hook("name: ${NAME}\n", &mut Substitute("filled")).unwrap();
    assert_eq!(filled.name.as_deref(), Some("filled"));
}

#[test]
fn cfg_val_1_substituted_text_is_never_resolved_again() {
    let filled: Settings = decode_with_hook("name: ${NAME}\n", &mut Substitute("true")).unwrap();
    assert_eq!(filled.name.as_deref(), Some("true"));
    let filled: Settings = decode_with_hook("name: ${NAME}\n", &mut Substitute("0x1F")).unwrap();
    assert_eq!(filled.name.as_deref(), Some("0x1F"));
}

// ----- CFG-QTY-4 -----

#[test]
fn cfg_qty_4_bounded_integers_accept_both_bounds() {
    assert_eq!(
        settings("retentionDays: 1\n").retention_days.unwrap().get(),
        1
    );
    assert_eq!(
        settings("retentionDays: 36500\n")
            .retention_days
            .unwrap()
            .get(),
        36500
    );
    assert_eq!(
        settings("maxBytes: 10000000000\n").max_bytes.unwrap().get(),
        10_000_000_000
    );
}

#[test]
fn cfg_qty_4_bounded_integers_refuse_values_outside_naming_the_bounds_and_unit() {
    for value in ["0", "36501", "-3"] {
        let report = refusal::<Settings>(&format!("retentionDays: {value}\n"));
        assert_diagnostic(
            only(&report),
            "config.out-of-range",
            "/retentionDays",
            (3, 16),
            "the value is outside its bounds; expected a whole number of days from 1 to 36500",
            "Write a whole number of days from 1 to 36500.",
        );
    }
    let report = refusal::<Settings>("maxBytes: 10000000001\n");
    assert_diagnostic(
        only(&report),
        "config.out-of-range",
        "/maxBytes",
        (3, 11),
        "the value is outside its bounds; expected a whole number of bytes from 1 to 10000000000",
        "Write a whole number of bytes from 1 to 10000000000.",
    );
}

#[test]
fn cfg_qty_4_a_product_bound_check_is_worded_by_the_reader() {
    #[derive(Debug, Deserialize)]
    #[serde(try_from = "u32")]
    struct Even(#[allow(dead_code)] u32);

    impl TryFrom<u32> for Even {
        type Error = Invalid;

        fn try_from(value: u32) -> Result<Even, Invalid> {
            if value > 10 {
                return Err(Invalid::out_of_range(0, 10));
            }
            if !value.is_multiple_of(2) {
                return Err(Invalid::expected(
                    "an even whole number",
                    "Write an even number.",
                ));
            }
            Ok(Even(value))
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Holder {
        #[allow(dead_code)]
        workers: Even,
    }

    let report = refusal::<Holder>("workers: 12\n");
    assert_diagnostic(
        only(&report),
        "config.out-of-range",
        "/workers",
        (3, 10),
        "the value is outside its bounds; expected a whole number from 0 to 10",
        "Write a whole number from 0 to 10.",
    );
    let report = refusal::<Holder>("workers: 3\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-value",
        "/workers",
        (3, 10),
        "expected an even whole number",
        "Write an even number.",
    );
}

// ----- CFG-DIAG-6: a type's extremes are not bounds a format declared -----

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Extremes {
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    level: Option<u8>,
    #[serde(default)]
    timeout_milliseconds: Option<u32>,
    #[serde(default)]
    offset: Option<i32>,
    #[serde(default)]
    shift_minutes: Option<i64>,
    #[serde(default)]
    total: Option<i128>,
    #[serde(default)]
    quota: Option<BoundedU64<0, { u64::MAX }>>,
    #[serde(default)]
    floor_bytes: Option<BoundedU32<5, { u32::MAX }>>,
}

#[test]
fn cfg_diag_6_an_upper_bound_at_the_type_maximum_reads_or_more() {
    for (body, code, path, column, message, action) in [
        (
            "count: \"5\"\n",
            "config.expected-integer",
            "/count",
            8,
            "expected a whole number of 0 or more; quoted values are text",
            "Remove the quotes.",
        ),
        (
            "count: many\n",
            "config.expected-integer",
            "/count",
            8,
            "expected a whole number of 0 or more, not unquoted text",
            "Write a whole number of 0 or more.",
        ),
        (
            "count: -1\n",
            "config.out-of-range",
            "/count",
            8,
            "the value is outside its bounds; expected a whole number of 0 or more",
            "Write a whole number of 0 or more.",
        ),
        (
            "level: 1.5\n",
            "config.expected-integer",
            "/level",
            8,
            "expected a whole number of 0 or more",
            "Write digits only.",
        ),
        (
            "timeoutMilliseconds: 5ms\n",
            "config.expected-integer",
            "/timeoutMilliseconds",
            22,
            "expected a whole number of 0 or more milliseconds",
            "Write the number of milliseconds as digits.",
        ),
        (
            "quota: \"5\"\n",
            "config.expected-integer",
            "/quota",
            8,
            "expected a whole number of 0 or more; quoted values are text",
            "Remove the quotes.",
        ),
        (
            "floorBytes: 2\n",
            "config.out-of-range",
            "/floorBytes",
            13,
            "the value is outside its bounds; expected a whole number of 5 or more bytes",
            "Write a whole number of 5 or more bytes.",
        ),
    ] {
        let report = refusal::<Extremes>(body);
        assert_diagnostic(only(&report), code, path, (3, column), message, action);
        assert!(
            !report.render_human().contains("18446744073709551615")
                && !report.render_human().contains("4294967295"),
            "{report}"
        );
    }
}

#[test]
fn cfg_diag_6_a_signed_type_with_both_extremes_names_no_bound() {
    for (body, path, column, message, action) in [
        (
            "offset: \"5\"\n",
            "/offset",
            9,
            "expected a whole number; quoted values are text",
            "Remove the quotes.",
        ),
        (
            "shiftMinutes: 5m\n",
            "/shiftMinutes",
            15,
            "expected a whole number of minutes",
            "Write the number of minutes as digits.",
        ),
        (
            "shiftMinutes: soon\n",
            "/shiftMinutes",
            15,
            "expected a whole number of minutes, not unquoted text",
            "Write a whole number of minutes.",
        ),
        (
            "total: \"1\"\n",
            "/total",
            8,
            "expected a whole number; quoted values are text",
            "Remove the quotes.",
        ),
    ] {
        let report = refusal::<Extremes>(body);
        assert_diagnostic(
            only(&report),
            "config.expected-integer",
            path,
            (3, column),
            message,
            action,
        );
    }
}

#[test]
fn cfg_diag_6_a_value_past_a_type_extreme_is_told_that_extreme() {
    for (body, path, column, message, action) in [
        (
            "level: 256\n",
            "/level",
            8,
            "the value is outside its bounds; expected a whole number from 0 to 255",
            "Write a whole number from 0 to 255.",
        ),
        (
            "offset: 3000000000\n",
            "/offset",
            9,
            "the value is outside its bounds; expected a whole number of 2147483647 or less",
            "Write a whole number of 2147483647 or less.",
        ),
        (
            "offset: -3000000000\n",
            "/offset",
            9,
            "the value is outside its bounds; expected a whole number of -2147483648 or more",
            "Write a whole number of -2147483648 or more.",
        ),
        (
            "floorBytes: 4294967296\n",
            "/floorBytes",
            13,
            "the value is outside its bounds; expected a whole number of bytes from 5 to 4294967295",
            "Write a whole number of bytes from 5 to 4294967295.",
        ),
    ] {
        let report = refusal::<Extremes>(body);
        assert_diagnostic(
            only(&report),
            "config.out-of-range",
            path,
            (3, column),
            message,
            action,
        );
    }
}

#[test]
fn cfg_diag_6_bounds_a_format_declares_are_named_in_full() {
    let report = refusal::<Settings>("retentionDays: \"90\"\n");
    assert_eq!(
        only(&report).message,
        "expected a whole number of days from 1 to 36500; quoted values are text"
    );
    let report = refusal::<Settings>("maxBytes: 0\n");
    assert_eq!(
        only(&report).suggested_action,
        "Write a whole number of bytes from 1 to 10000000000."
    );
}

#[test]
fn cfg_diag_1_the_json_of_a_range_refusal_keeps_its_fields() {
    let report = refusal::<Extremes>("count: \"5\"\n");
    assert_eq!(
        report.to_json_value(),
        serde_json::json!([{
            "severity": "error",
            "code": "config.expected-integer",
            "artifact": "ExampleRuntimeConfig",
            "path": "/count",
            "message": "expected a whole number of 0 or more; quoted values are text",
            "suggestedAction": "Remove the quotes.",
            "source": {"file": "runtime.yaml", "line": 3, "column": 8}
        }])
    );
}

// ----- CFG-EMPTY-1 -----

#[test]
fn cfg_empty_1_a_null_member_is_refused() {
    for body in ["name:\n", "name: ~\n", "name: null\n", "port: NULL\n"] {
        let report = refusal::<Settings>(body);
        let diagnostic = only(&report);
        assert_eq!(diagnostic.code, "config.null-value", "{body}");
        assert_eq!(
            diagnostic.message,
            "null is never a value; an empty value after a key is null too"
        );
        assert_eq!(
            diagnostic.suggested_action,
            "Give a value, or remove the key if the member is optional."
        );
    }
}

#[test]
fn cfg_empty_1_a_null_required_member_is_not_told_to_remove_the_key() {
    let report = refusal::<Settings>("listener:\n  bind:\n");
    assert_diagnostic(
        only(&report),
        "config.null-value",
        "/listener/bind",
        (4, 3),
        "null is never a value; an empty value after a key is null too",
        "Give a value, or remove the key if the member is optional.",
    );

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Holder {
        source: Source,
    }
    let report = refusal::<Holder>("source:\n  type:\n");
    assert_diagnostic(
        only(&report),
        "config.null-value",
        "/source/type",
        (4, 3),
        "null is never a value; an empty value after a key is null too",
        "Give one of `http`, `file`, `none`.",
    );
}

#[test]
fn cfg_empty_1_a_null_value_is_placed_at_its_key_when_it_is_empty() {
    let report = refusal::<Settings>("name:\nport: 1\n");
    assert_eq!(at(only(&report)), (3, 1));
    let report = refusal::<Settings>("name: ~\n");
    assert_eq!(at(only(&report)), (3, 7));
}

#[test]
fn cfg_empty_1_a_null_list_item_is_refused() {
    let report = refusal::<Settings>("tags:\n  - a\n  -\n  - c\n");
    assert_diagnostic(
        only(&report),
        "config.null-value",
        "/tags/1",
        (5, 3),
        "null is never a value; an empty list item is null too",
        "Remove the item, or give a value.",
    );
}

#[test]
fn cfg_empty_1_a_null_block_names_the_empty_mapping() {
    let report = refusal::<Settings>("listener:\n");
    assert_diagnostic(
        only(&report),
        "config.null-value",
        "/listener",
        (3, 1),
        "null is never a value; an empty value after a key is null too",
        "Give a value (`{}` for a block with no members), or remove the key if the block is optional.",
    );
}

#[test]
fn cfg_empty_1_an_optional_data_literal_keeps_null_apart_from_absence() {
    #[derive(Debug, Deserialize)]
    struct Fixture {
        #[serde(default)]
        expected: Option<DataLiteral>,
    }
    let read = decode::<Fixture>("expected: null\n").unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(read.expected, Some(DataLiteral::Null));
    let read = decode::<Fixture>("").unwrap();
    assert_eq!(read.expected, None);
}

#[test]
fn cfg_empty_1_an_absent_member_is_none() {
    let read = settings("port: 1\n");
    assert!(read.name.is_none());
    assert!(read.listener.is_none());
}

#[test]
fn cfg_empty_1_a_data_literal_is_the_one_place_null_is_a_value() {
    #[derive(Debug, Deserialize)]
    struct Fixture {
        values: Vec<DataLiteral>,
        expected: DataLiteral,
    }
    let fixture = decode::<Fixture>("values: [null, ~, true, 3, 2.5, text, \"7\"]\nexpected:\n")
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(
        fixture.values,
        [
            DataLiteral::Null,
            DataLiteral::Null,
            DataLiteral::Boolean(true),
            DataLiteral::Number(3.into()),
            DataLiteral::Number(serde_json::Number::from_f64(2.5).unwrap()),
            DataLiteral::String("text".to_string()),
            DataLiteral::String("7".to_string()),
        ]
    );
    assert_eq!(fixture.expected, DataLiteral::Null);

    let report = refusal::<Fixture>("values:\n  - [1, 2]\nexpected: 1\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-type");
    assert_eq!(diagnostic.path, "/values/0");
    assert_eq!(at(diagnostic), (4, 5));
    assert_eq!(
        diagnostic.message,
        "expected null, a boolean, a number, or text, not a list"
    );
}

// ----- CFG-SEC-2 (the hook interface) -----

/// Refuses every value written `${...}`, as an authored-file check does.
struct RefuseSubstitution;

impl ScalarHook for RefuseSubstitution {
    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        if site.text.contains("${") {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_string(),
                message: "substitution is not available in an authored file".to_string(),
                suggested_action: "Write the value in full.".to_string(),
            });
        }
        Ok(None)
    }

    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        if site.text.contains("${") {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_string(),
                message: "a key is never filled by substitution".to_string(),
                suggested_action: "Write the key in full.".to_string(),
            });
        }
        Ok(())
    }
}

#[test]
fn cfg_sec_2_a_hook_refusal_is_a_structural_problem_reported_with_the_others() {
    let body = "name: ${NAME}\n${KEY}: 1\nlistener:\n  bind: a\nlistener:\n  bind: b\n";
    let report = decode_with_hook::<Settings>(body, &mut RefuseSubstitution).unwrap_err();
    let found: Vec<(&str, &str, (usize, usize))> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str(), at(d)))
        .collect();
    assert_eq!(
        found,
        [
            ("config.substitution-not-allowed", "/name", (3, 7)),
            ("config.substitution-not-allowed", "/${KEY}", (4, 1)),
            ("yaml.duplicate-key", "/listener", (7, 1)),
        ]
    );
}

#[test]
fn cfg_sec_2_the_hook_sees_the_pointer_and_the_keys_on_the_way() {
    #[derive(Default)]
    struct Record(Vec<(String, Vec<String>)>);

    impl ScalarHook for Record {
        fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
            self.0.push((
                site.pointer.to_string(),
                site.keys.iter().map(|key| key.to_string()).collect(),
            ));
            Ok(None)
        }
    }

    let mut record = Record::default();
    let _: Settings = decode_with_hook("listener:\n  bind: a\ntags: [x]\n", &mut record).unwrap();
    assert_eq!(
        record.0,
        [
            ("/apiVersion".to_string(), vec!["apiVersion".to_string()]),
            ("/kind".to_string(), vec!["kind".to_string()]),
            (
                "/listener/bind".to_string(),
                vec!["listener".to_string(), "bind".to_string()]
            ),
            ("/tags/0".to_string(), vec!["tags".to_string()]),
        ]
    );
}

// ----- CFG-SEC-3 -----

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Mode {
    Strict,
    Lenient,
}

/// A type whose own deserializer writes the value into its error.
#[derive(Debug)]
struct Leaky;

impl<'de> Deserialize<'de> for Leaky {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Leaky, D::Error> {
        let text = String::deserialize(deserializer)?;
        Err(D::Error::custom(format!("cannot use {text}")))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Everything {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    id: Option<LocalId>,
    #[serde(default)]
    issuer_id: Option<ExternalId>,
    #[serde(default)]
    digest: Option<Digest>,
    #[serde(default)]
    url: Option<Url>,
    #[serde(default)]
    leaky: Option<Leaky>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    scopes: Option<UniqueList<String>>,
    #[serde(default)]
    retention_days: Option<BoundedU32<1, 36500>>,
}

#[test]
fn cfg_sec_3_no_diagnostic_repeats_a_value() {
    let cases = [
        format!("port: \"{MARKER}\"\n"),
        format!("port: {MARKER}\n"),
        format!("name: [{MARKER}]\n"),
        format!("name: {{a: {MARKER}}}\n"),
        format!("mode: {MARKER}\n"),
        format!("id: {MARKER}\n"),
        format!("issuerId: \"{MARKER}\u{7}\"\n"),
        format!("digest: {MARKER}\n"),
        format!("url: {MARKER}\n"),
        format!("url: https://{MARKER}@example.org/\n"),
        format!("leaky: {MARKER}\n"),
        format!("enabled: {MARKER}\n"),
        format!("scopes: [{MARKER}, {MARKER}]\n"),
        format!("retentionDays: {MARKER}\n"),
        format!("name: &{MARKER} a\n"),
        format!("name: *{MARKER}\n"),
        format!("name: !{MARKER} a\n"),
        format!("name: \"{MARKER}\n"),
        format!("name: {MARKER}: b\n"),
        format!("name: [{MARKER}\n"),
        format!("port: 8080#{MARKER}\n"),
        format!("mode: strict#{MARKER}\n"),
        format!("id: core#{MARKER}\n"),
        format!("url: ftp://{MARKER}.example/#{MARKER}\n"),
    ];
    for body in &cases {
        let report = match decode::<Everything>(body) {
            Ok(value) => panic!("expected a refusal for {body:?}, decoded {value:?}"),
            Err(report) => report,
        };
        assert_no_marker(&report);
    }
}

#[test]
fn cfg_sec_3_a_message_from_a_type_is_never_passed_through() {
    let report = refusal::<Everything>("leaky: secret-value\n");
    let diagnostic = only(&report);
    assert_diagnostic(
        diagnostic,
        "config.invalid-value",
        "/leaky",
        (3, 8),
        "the value is not valid here",
        "Check the value against the format's reference for this member.",
    );
    assert!(!report.render_human().contains("secret-value"));
}

/// A type whose visitor writes part of the value into its `expecting` text.
#[derive(Debug)]
struct LeakyExpecting;

impl<'de> Deserialize<'de> for LeakyExpecting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<LeakyExpecting, D::Error> {
        let text = String::deserialize(deserializer)?;
        let scheme = text.split("://").next().unwrap_or_default();
        let expected = format!("a link whose scheme is not {scheme}");
        Err(D::Error::invalid_value(
            serde::de::Unexpected::Other("a link"),
            &expected.as_str(),
        ))
    }
}

/// A type whose visitor describes itself in its own static words.
#[derive(Debug)]
struct OwnWords;

impl<'de> Deserialize<'de> for OwnWords {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<OwnWords, D::Error> {
        struct OwnWordsVisitor;

        impl<'de> serde::de::Visitor<'de> for OwnWordsVisitor {
            type Value = OwnWords;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object with unique members")
            }
        }

        deserializer.deserialize_any(OwnWordsVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Expectations {
    #[serde(default)]
    leaky: Option<LeakyExpecting>,
    #[serde(default)]
    own: Option<OwnWords>,
    #[serde(default)]
    letter: Option<char>,
    #[serde(default)]
    workers: Option<std::num::NonZeroU32>,
}

#[test]
fn cfg_sec_3_expected_text_from_a_type_outside_the_reader_is_never_shown() {
    let generic = (
        "the value is not valid here",
        "Check the value against the format's reference for this member.",
    );
    let report = refusal::<Expectations>("leaky: s3cr3t://x\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(
        (
            diagnostic.message.as_str(),
            diagnostic.suggested_action.as_str()
        ),
        generic
    );
    assert!(!report.render_human().contains("s3cr3t"), "{report}");

    let report =
        decode_with_hook::<Expectations>("leaky: \"${SET}://x\"\n", &mut Substitute("t0ken://x"))
            .unwrap_err();
    let diagnostic = only(&report);
    assert_eq!(
        (
            diagnostic.message.as_str(),
            diagnostic.suggested_action.as_str()
        ),
        generic
    );
    assert!(!report.render_human().contains("t0ken"), "{report}");
    assert!(!report.to_json_value().to_string().contains("t0ken"));

    let report = refusal::<Expectations>("own: text\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-type");
    assert_eq!(
        (
            diagnostic.message.as_str(),
            diagnostic.suggested_action.as_str()
        ),
        generic
    );
}

#[test]
fn cfg_sec_3_expected_text_from_serde_primitives_is_kept() {
    for (body, message, action) in [
        (
            "letter: ab\n",
            "expected a single character",
            "Write a single character.",
        ),
        (
            "workers: 0\n",
            "expected a whole number other than 0",
            "Write a whole number other than 0.",
        ),
    ] {
        let report = refusal::<Expectations>(body);
        let diagnostic = only(&report);
        assert_eq!(diagnostic.code, "config.invalid-value", "{body}");
        assert_eq!(diagnostic.message, message, "{body}");
        assert_eq!(diagnostic.suggested_action, action, "{body}");
    }
}

#[test]
fn cfg_sec_3_a_checking_type_reads_as_one_sentence_under_another_deserializer() {
    assert_eq!(
        Invalid::expected("an even number", "Write an even number.").to_string(),
        "expected an even number"
    );
    assert_eq!(
        Invalid::out_of_range(1, 10).to_string(),
        "expected a whole number from 1 to 10"
    );
    let errors = [
        serde_json::from_str::<LocalId>("\"A\"").unwrap_err(),
        serde_json::from_str::<Url>("\"x\"").unwrap_err(),
        serde_json::from_str::<Digest>("\"x\"").unwrap_err(),
        serde_json::from_str::<BoundedU32<1, 10>>("11").unwrap_err(),
        serde_json::from_str::<UniqueList<String>>("[\"a\", \"a\"]").unwrap_err(),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(!text.contains('\u{1f}'), "{text:?}");
        assert!(!text.contains("registry-platform-yaml"), "{text:?}");
        assert!(
            text.starts_with("expected ") || text.starts_with("item "),
            "{text:?}"
        );
    }
}

#[test]
fn cfg_sec_3_into_error_words_a_checking_type_like_custom() {
    #[derive(Debug)]
    struct Even;

    impl<'de> Deserialize<'de> for Even {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Even, D::Error> {
            let value = u32::deserialize(deserializer)?;
            if value.is_multiple_of(2) {
                Ok(Even)
            } else {
                Err(Invalid::expected("an even whole number", "Write an even number.").into_error())
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Holder {
        workers: Even,
    }

    let report = refusal::<Holder>("workers: 3\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-value",
        "/workers",
        (3, 10),
        "expected an even whole number",
        "Write an even number.",
    );
    let error = serde_json::from_str::<Holder>("{\"workers\": 3}").unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("expected an even whole number"),
        "{error}"
    );
}

#[test]
fn cfg_sec_3_an_unknown_variant_names_the_accepted_values_only() {
    let report = refusal::<Everything>("mode: strictest\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-variant",
        "/mode",
        (3, 7),
        "expected one of `strict`, `lenient`",
        "Use one of `strict`, `lenient`.",
    );
}

#[test]
fn cfg_diag_6_an_unknown_variant_names_the_value_it_is_close_to() {
    for (body, action) in [
        ("mode: Strict\n", "Use `strict`; letter case matters."),
        ("mode: LENIENT\n", "Use `lenient`; letter case matters."),
        (
            "mode: strcit\n",
            "Use `strict`, the closest accepted value.",
        ),
        (
            "mode: lenent\n",
            "Use `lenient`, the closest accepted value.",
        ),
    ] {
        let report = refusal::<Everything>(body);
        assert_diagnostic(
            only(&report),
            "config.unknown-variant",
            "/mode",
            (3, 7),
            "expected one of `strict`, `lenient`",
            action,
        );
    }

    let report = refusal::<Sources>("source:\n  type: htp\n");
    assert_eq!(
        only(&report).suggested_action,
        "Use `http`, the closest accepted value."
    );
    let report = refusal::<WithAuth>("auth:\n  Bearer:\n    tokenRef: a\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-variant",
        "/auth/Bearer",
        (4, 3),
        "expected one of `bearer`, `basic`",
        "Use `bearer`; letter case matters.",
    );
}

#[test]
fn cfg_sec_3_a_substituted_value_gets_no_closest_value_hint() {
    let report =
        decode_with_hook::<Everything>("mode: ${MODE}\n", &mut Substitute("Strict")).unwrap_err();
    assert_eq!(
        only(&report).suggested_action,
        "Use one of `strict`, `lenient`."
    );
}

// ----- CFG-DIAG-6: a `#` with no space before it is part of the value -----

const HASH_HINT: &str =
    "A `#` starts a comment only after a space: put a space before the `#` that starts the comment.";
const LOCAL_ID_MESSAGE: &str = "expected a local identifier matching `^[a-z][a-z0-9_-]{0,63}$`";
const LOCAL_ID_ACTION: &str =
    "Use lowercase letters, digits, `_`, and `-`, starting with a letter, at most 64 characters.";

#[test]
fn cfg_diag_6_a_refused_value_with_an_unspaced_hash_says_where_comments_start() {
    let digest = format!("digest: sha256:{}#main\n", "a".repeat(64));
    for (body, code, path, column, message, action) in [
        (
            "port: 8080#main\n",
            "config.expected-integer",
            "/port",
            7,
            "expected a whole number of 0 or more",
            "Write digits only.",
        ),
        (
            "retentionDays: 90#days\n",
            "config.expected-integer",
            "/retentionDays",
            16,
            "expected a whole number of days from 1 to 36500",
            "Write digits only.",
        ),
        (
            "mode: strict#main\n",
            "config.unknown-variant",
            "/mode",
            7,
            "expected one of `strict`, `lenient`",
            "Use one of `strict`, `lenient`.",
        ),
        (
            "id: core#main\n",
            "config.invalid-value",
            "/id",
            5,
            LOCAL_ID_MESSAGE,
            LOCAL_ID_ACTION,
        ),
        (
            "enabled: true#main\n",
            "config.expected-boolean",
            "/enabled",
            10,
            "expected true or false, not unquoted text",
            "Write true or false.",
        ),
        (
            &digest,
            "config.invalid-value",
            "/digest",
            9,
            "expected a digest written `sha256:` followed by 64 lowercase hex digits",
            "Write the digest as `sha256:` followed by 64 lowercase hex digits.",
        ),
        (
            "url: ftp://a.example/#main\n",
            "config.invalid-value",
            "/url",
            6,
            "expected an absolute http or https URL with a host, no user information, and at most 2048 characters",
            "Write an absolute URL starting with `https://` or `http://`, without user information.",
        ),
    ] {
        let report = refusal::<Everything>(body);
        assert_diagnostic(
            only(&report),
            code,
            path,
            (3, column),
            message,
            &format!("{action} {HASH_HINT}"),
        );
    }
}

#[test]
fn cfg_diag_6_the_hash_hint_is_given_only_for_an_unquoted_value_that_fails() {
    let text = with_envelope("name: a#b\nid: core\nurl: https://a.example/#main\n");
    let decoded = Reader::new(FILE)
        .decode::<Everything>(text.as_bytes(), &EXPECT)
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(decoded.value.name.as_deref(), Some("a#b"));
    assert!(decoded.document.warnings().diagnostics().is_empty());
    for body in ["port: \"8080#main\"\n", "port: main # 8080\n"] {
        let report = refusal::<Everything>(body);
        assert_eq!(
            only(&report).suggested_action,
            "Write a whole number of 0 or more.",
            "{body}"
        );
    }
}

#[test]
fn cfg_sec_3_the_hash_hint_is_never_given_for_a_substituted_value() {
    for (body, code, message, action) in [
        (
            "id: ${ID}\n",
            "config.invalid-value",
            LOCAL_ID_MESSAGE,
            LOCAL_ID_ACTION,
        ),
        (
            "port: ${PORT}\n",
            "config.expected-integer",
            "substitution fills text values only",
            "Write the value, or template the whole file.",
        ),
    ] {
        let report =
            decode_with_hook::<Everything>(body, &mut Substitute("core#main")).unwrap_err();
        let diagnostic = only(&report);
        assert_eq!(diagnostic.code, code, "{body}");
        assert_eq!(diagnostic.message, message, "{body}");
        assert_eq!(diagnostic.suggested_action, action, "{body}");
        assert!(!report.render_human().contains("core#main"), "{report}");
    }
}

// ----- CFG-DIAG-1 -----

#[test]
fn cfg_diag_1_a_diagnostic_has_the_documented_json_shape() {
    let report = refusal::<Settings>("listener:\n  bind: a\nlistener:\n  bind: b\n");
    let json = report.to_json_value();
    assert_eq!(
        json,
        serde_json::json!([{
            "severity": "error",
            "code": "yaml.duplicate-key",
            "artifact": "ExampleRuntimeConfig",
            "path": "/listener",
            "message": "the key is already defined in this mapping",
            "suggestedAction": "Keep one definition of the key.",
            "source": {"file": "runtime.yaml", "line": 5, "column": 1},
            "related": [{
                "file": "runtime.yaml",
                "line": 3,
                "column": 1,
                "path": "/listener",
                "message": "the first definition"
            }]
        }])
    );
}

#[test]
fn cfg_diag_1_a_key_problem_is_placed_at_the_key() {
    let report = refusal::<Settings>("listener:\n  bind: a\n  bnid: b\n");
    assert_eq!(only(&report).code, "config.unknown-key");
    assert_eq!(only(&report).path, "/listener/bnid");
    assert_eq!(at(only(&report)), (5, 3));
}

#[test]
fn cfg_diag_1_a_value_problem_is_placed_at_the_first_character_of_the_value() {
    let report = refusal::<Settings>("listener:\n  bind: a\n  port:    \"80\"\n");
    assert_eq!(only(&report).path, "/listener/port");
    assert_eq!(at(only(&report)), (5, 12));
    let report = refusal::<Settings>("tags:\n  - a\n  - [b]\n");
    assert_eq!(only(&report).path, "/tags/1");
    assert_eq!(at(only(&report)), (5, 5));
}

#[test]
fn cfg_diag_1_a_missing_member_is_placed_at_the_key_of_the_mapping_that_lacks_it() {
    let report = refusal::<Settings>("name: a\nlistener:\n  port: 80\n");
    assert_diagnostic(
        only(&report),
        "config.missing-key",
        "/listener",
        (4, 1),
        "the required member `bind` is missing",
        "Add `bind`.",
    );

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Required {
        name: String,
    }
    let report = refusal::<Required>("");
    assert_diagnostic(
        only(&report),
        "config.missing-key",
        "",
        (1, 1),
        "the required member `name` is missing",
        "Add `name`.",
    );
}

// ----- CFG-DIAG-2 -----

const MESSAGING_FORMAT: FormatSpec = FormatSpec {
    kind: "MessagingRuntimeConfig",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(
            "id.registrystack.org/formats/messaging/runtime/v1alpha1",
        )],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct MessagingRuntime {
    listener: MessagingListener,
    audit: MessagingAudit,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MessagingListener {
    bind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct MessagingAudit {
    retention_days: BoundedU32<1, 36500>,
}

#[test]
fn cfg_diag_2_the_convention_example_renders_as_written() {
    let text = "apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1
kind: MessagingRuntimeConfig
listener:
  bind: 127.0.0.1:8443
audit:
  retentionDays: \"90\"
listener:
  bind: 0.0.0.0:8443
";
    let report = Reader::new("runtime.yaml")
        .decode::<MessagingRuntime>(text.as_bytes(), &Expect::one(&MESSAGING_FORMAT))
        .unwrap_err();
    assert_eq!(
        report.render_human(),
        "error[yaml.duplicate-key] runtime.yaml:7:1 /listener
  the key is already defined in this mapping
  next: Keep one definition of the key.
  note: runtime.yaml:3:1 /listener the first definition
1 error, 0 warnings in 1 file
"
    );

    let fixed = text.replace("listener:\n  bind: 0.0.0.0:8443\n", "");
    let report = Reader::new("runtime.yaml")
        .decode::<MessagingRuntime>(fixed.as_bytes(), &Expect::one(&MESSAGING_FORMAT))
        .unwrap_err();
    assert_eq!(
        report.render_human(),
        "error[config.expected-integer] runtime.yaml:6:18 /audit/retentionDays
  expected a whole number of days from 1 to 36500; quoted values are text
  next: Remove the quotes.
1 error, 0 warnings in 1 file
"
    );
}

#[test]
fn cfg_diag_2_control_characters_in_keys_are_escaped_in_human_output() {
    let report = refusal::<Settings>("\"na\\u001bme\": a\n");
    let human = report.render_human();
    assert!(!human.contains('\u{1b}'), "{human:?}");
}

// ----- CFG-DIAG-5 -----

#[test]
fn cfg_diag_5_unknown_keys_are_recorded_until_decoding_stops_at_the_first_type_error() {
    let body = "nmae: a\nport: \"1\"\nenabled: maybe\nlistener:\n  bind: a\n  extra: 1\nother: 2\n";
    let report = refusal::<Settings>(body);
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("config.unknown-key", "/nmae"),
            ("config.expected-integer", "/port"),
            // The rest of the mapping that stopped is still checked for
            // unknown keys; `listener` was never reached, so its own
            // unknown key is not.
            ("config.unknown-key", "/other"),
        ]
    );
    assert_eq!(report.summary(), "3 errors, 0 warnings in 1 file");
}

#[test]
fn cfg_diag_5_a_close_misspelling_is_named_and_the_list_goes_to_the_next_key() {
    let report = refusal::<Settings>("nmae: a\nzzz: 1\nqqq: 2\nwww: 3\n");
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.path.as_str(), d.suggested_action.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("/nmae", "Rename `nmae` to `name`, or remove it."),
            (
                "/zzz",
                "Remove `zzz`; the accepted keys are `name`, `port`, `enabled`, `ratio`, \
                 `retentionDays`, `timeoutSeconds`, `maxBytes`, `tags`, `listener`."
            ),
            (
                "/qqq",
                "Remove `qqq`; the accepted keys are listed at line 4."
            ),
            (
                "/www",
                "Remove `www`; the accepted keys are listed at line 4."
            ),
        ]
    );
}

#[test]
fn cfg_diag_5_each_mapping_lists_its_own_accepted_keys() {
    let report = refusal::<Settings>("zzz: 1\nlistener:\n  bind: a\n  qqq: 2\n");
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.path.as_str(), d.suggested_action.as_str()))
        .collect();
    assert_eq!(
        found[1],
        (
            "/listener/qqq",
            "Remove `qqq`; the accepted keys are `bind`, `port`."
        )
    );
}

#[test]
fn cfg_diag_5_unknown_keys_past_the_bound_are_counted() {
    let body: String = (0..MAXIMUM_DIAGNOSTICS_PER_FILE + 20)
        .map(|index| format!("unknown{index}: 1\n"))
        .collect();
    let report = refusal::<Listener>(&format!("bind: a\n{body}"));
    let diagnostics = report.diagnostics();
    assert_eq!(diagnostics.len(), MAXIMUM_DIAGNOSTICS_PER_FILE + 1);
    assert!(diagnostics[..MAXIMUM_DIAGNOSTICS_PER_FILE]
        .iter()
        .all(|d| d.code == "config.unknown-key"));
    let rest = &diagnostics[MAXIMUM_DIAGNOSTICS_PER_FILE];
    assert_eq!(rest.code, "config.too-many-problems");
    assert_eq!(rest.message, "20 more problems in this file are not shown");
}

#[test]
fn cfg_diag_5_structural_problems_stop_before_decoding() {
    let report = refusal::<Settings>("nmae: a\nport: &p 1\nport: 2\n");
    assert_eq!(codes(&report), ["yaml.anchor", "yaml.duplicate-key"]);
}

// ----- CFG-SCHEMA-8: closed structs -----

#[test]
fn cfg_schema_8_unknown_keys_are_refused_without_deny_unknown_fields() {
    let report = refusal::<Settings>("nmae: a\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-key",
        "/nmae",
        (3, 1),
        "`nmae` is not a member of this mapping",
        "Rename `nmae` to `name`, or remove it.",
    );
    let report = refusal::<Listener>("bind: a\nzzz: 1\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-key",
        "/zzz",
        (4, 1),
        "`zzz` is not a member of this mapping",
        "Remove `zzz`; the accepted keys are `bind`, `port`.",
    );
}

#[test]
fn cfg_schema_8_a_mapping_with_no_members_says_so() {
    #[derive(Debug, Deserialize)]
    struct Empty {}
    let report = refusal::<Empty>("zzz: 1\n");
    assert_eq!(
        only(&report).suggested_action,
        "Remove `zzz`; this mapping takes no members."
    );
}

#[test]
fn cfg_schema_8_a_top_level_extension_key_is_unknown_with_the_comment_fix() {
    let report = refusal::<Settings>("x-note: kept for later\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-key",
        "/x-note",
        (3, 1),
        "`x-note` is not a member of this mapping; extension fields are not supported; use a comment",
        "Remove the key, and write the note as a comment.",
    );
    // Below the top level, an `x-` key is an ordinary unknown key.
    let report = refusal::<Settings>("listener:\n  bind: a\n  x-note: 1\n");
    assert_eq!(
        only(&report).message,
        "`x-note` is not a member of this mapping"
    );
}

#[test]
fn cfg_schema_8_a_type_that_declares_the_envelope_receives_it() {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WithEnvelope {
        api_version: String,
        kind: String,
    }
    let read = decode::<WithEnvelope>("").unwrap();
    assert_eq!(read.api_version, API_VERSION);
    assert_eq!(read.kind, "ExampleRuntimeConfig");
}

#[test]
fn cfg_schema_8_a_member_given_under_two_accepted_spellings_is_refused() {
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Aliased {
        #[serde(alias = "hostname")]
        host: String,
    }
    let report = refusal::<Aliased>("host: a\nhostname: b\n");
    assert_diagnostic(
        only(&report),
        "config.duplicate-key",
        "/hostname",
        (4, 1),
        "the member `host` is given twice, under its name and under another spelling",
        "Keep one of the two keys.",
    );
}

// ----- CFG-SCHEMA-8: unions -----

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum Source {
    Http {
        base_url: Url,
        #[serde(default)]
        timeout_seconds: Option<BoundedU32<1, 60>>,
    },
    File {
        path: String,
    },
    None {},
}
tagged_union!(Source);

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum Check {
    Equals { field: String, value: DataLiteral },
    Present { field: String },
}
tagged_union!(Check, tag = "op");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Sources {
    #[serde(default)]
    source: Option<Source>,
    #[serde(default)]
    checks: Option<Vec<Check>>,
}

#[test]
fn cfg_schema_8_an_internally_tagged_union_decodes_its_variants() {
    let read = decode::<Sources>(
        "source:\n  type: http\n  baseUrl: https://a.example/\n  timeoutSeconds: 5\n",
    )
    .unwrap_or_else(|report| panic!("{report}"));
    let Some(Source::Http {
        base_url,
        timeout_seconds,
    }) = read.source
    else {
        panic!("an http source");
    };
    assert_eq!(base_url.as_str(), "https://a.example/");
    assert_eq!(timeout_seconds.map(BoundedU32::get), Some(5));

    let read = decode::<Sources>("source:\n  type: none\n").unwrap();
    assert!(matches!(read.source, Some(Source::None {})));
}

#[test]
fn cfg_schema_8_an_unknown_tag_names_the_variants() {
    let report = refusal::<Sources>("source:\n  type: ftp\n  path: a\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-variant",
        "/source/type",
        (4, 9),
        "expected one of `http`, `file`, `none`",
        "Use one of `http`, `file`, `none`.",
    );
}

#[test]
fn cfg_schema_8_a_missing_tag_names_the_variants() {
    let report = refusal::<Sources>("source:\n  path: a\n");
    assert_diagnostic(
        only(&report),
        "config.missing-key",
        "/source",
        (3, 1),
        "the member `type` is missing; it names which form this mapping takes",
        "Add `type` with one of `http`, `file`, `none`.",
    );
}

#[test]
fn cfg_schema_8_positions_are_kept_inside_a_variant() {
    let report = refusal::<Sources>(
        "source:\n  type: http\n  baseUrl: https://a.example/\n  timeoutSeconds: \"5\"\n  extra: 1\n",
    );
    let found: Vec<(&str, &str, (usize, usize))> = report
        .diagnostics()
        .iter()
        .map(|d| (d.code.as_str(), d.path.as_str(), at(d)))
        .collect();
    assert_eq!(
        found,
        [
            ("config.expected-integer", "/source/timeoutSeconds", (6, 19)),
            ("config.unknown-key", "/source/extra", (7, 3)),
        ]
    );
    assert_eq!(
        report.diagnostics()[0].message,
        "expected a whole number of seconds from 1 to 60; quoted values are text"
    );
    assert_eq!(
        report.diagnostics()[1].suggested_action,
        "Remove `extra`; the accepted keys are `type`, `baseUrl`, `timeoutSeconds`."
    );
}

#[test]
fn cfg_schema_8_a_variant_with_no_members_refuses_extra_keys() {
    let report = refusal::<Sources>("source:\n  type: none\n  path: a\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-key",
        "/source/path",
        (5, 3),
        "`path` is not a member of this mapping",
        "Remove `path`; the accepted keys are `type`.",
    );
}

#[test]
fn cfg_schema_8_a_union_may_name_its_own_tag() {
    let read = decode::<Sources>(
        "checks:\n  - op: equals\n    field: status\n    value: null\n  - op: present\n    field: name\n",
    )
    .unwrap_or_else(|report| panic!("{report}"));
    let checks = read.checks.unwrap();
    assert!(matches!(
        &checks[0],
        Check::Equals {
            value: DataLiteral::Null,
            ..
        }
    ));
    assert!(matches!(&checks[1], Check::Present { field } if field == "name"));

    let report = refusal::<Sources>("checks:\n  - field: status\n");
    assert_diagnostic(
        only(&report),
        "config.missing-key",
        "/checks/0",
        (4, 5),
        "the member `op` is missing; it names which form this mapping takes",
        "Add `op` with one of `equals`, `present`.",
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
#[allow(dead_code)]
enum Auth {
    Bearer { token_ref: String },
    Basic { user_ref: String },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct WithAuth {
    auth: Auth,
}

#[test]
fn cfg_schema_8_an_externally_tagged_union_reads_one_key() {
    let read = decode::<WithAuth>("auth:\n  bearer:\n    tokenRef: secret:env/A\n")
        .unwrap_or_else(|report| panic!("{report}"));
    assert!(matches!(read.auth, Auth::Bearer { token_ref } if token_ref == "secret:env/A"));

    let report =
        refusal::<WithAuth>("auth:\n  bearer:\n    tokenRef: a\n  basic:\n    userRef: b\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-type",
        "/auth",
        (4, 3),
        "expected a mapping with exactly one key, naming one of `bearer`, `basic`",
        "Write one key from `bearer`, `basic` with its value.",
    );

    let report = refusal::<WithAuth>("auth:\n  digest:\n    a: 1\n");
    assert_diagnostic(
        only(&report),
        "config.unknown-variant",
        "/auth/digest",
        (4, 3),
        "expected one of `bearer`, `basic`",
        "Use one of `bearer`, `basic`.",
    );

    let report = refusal::<WithAuth>("auth:\n  bearer:\n    tokenRef: a\n    extra: 1\n");
    assert_eq!(only(&report).path, "/auth/bearer/extra");
    assert_eq!(at(only(&report)), (6, 5));
}

#[derive(Debug)]
enum Scopes {
    One(String),
    Many(Vec<String>),
}
shape_union!(Scopes { scalar => One, list => Many });

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct WithScopes {
    scopes: Scopes,
}

#[test]
fn cfg_schema_8_a_shape_union_chooses_by_node_kind() {
    let read = decode::<WithScopes>("scopes: read\n").unwrap();
    assert!(matches!(read.scopes, Scopes::One(scope) if scope == "read"));
    let read = decode::<WithScopes>("scopes: [read, write]\n").unwrap();
    assert!(matches!(read.scopes, Scopes::Many(scopes) if scopes.len() == 2));

    let report = refusal::<WithScopes>("scopes:\n  read: true\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-type",
        "/scopes",
        (4, 3),
        "expected a single value or a list, not a mapping",
        "Write a single value or a list.",
    );
    let report = refusal::<WithScopes>("scopes: [read, 1]\n");
    assert_diagnostic(
        only(&report),
        "config.expected-string",
        "/scopes/1",
        (3, 16),
        "expected text, not an integer",
        "Quote the value to make it text.",
    );
}

// ----- CFG-SCHEMA-8: shared blocks -----

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Package {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/project"))]
    project: ProjectIdentity,
    title: String,
}

#[test]
fn cfg_schema_8_a_shared_block_places_its_members_beside_the_host() {
    let read = decode::<Package>("id: core\nversion: \"1.2\"\ntitle: Core\n")
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(read.project.id.as_str(), "core");
    assert_eq!(read.project.version, "1.2");
    assert_eq!(read.title, "Core");
}

#[test]
fn cfg_schema_8_an_unknown_key_beside_a_shared_block_names_every_accepted_key() {
    let report = refusal::<Package>("id: core\nversion: \"1\"\ntitle: Core\nzzz: 1\nqqq: 2\n");
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|d| (d.path.as_str(), d.suggested_action.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            (
                "/zzz",
                "Remove `zzz`; the accepted keys are `id`, `version`, `title`."
            ),
            // A mapping lists its accepted keys once.
            (
                "/qqq",
                "Remove `qqq`; the accepted keys are listed at line 6."
            ),
        ]
    );
}

#[test]
fn cfg_schema_8_errors_inside_a_shared_block_keep_their_positions() {
    let report = refusal::<Package>("title: Core\nversion: \"1\"\nid: Core\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-value",
        "/id",
        (5, 5),
        "expected a local identifier matching `^[a-z][a-z0-9_-]{0,63}$`",
        "Use lowercase letters, digits, `_`, and `-`, starting with a letter, at most 64 characters.",
    );
    let report = refusal::<Package>("title: Core\nid: core\n");
    assert_diagnostic(
        only(&report),
        "config.missing-key",
        "",
        (1, 1),
        "the required member `version` is missing",
        "Add `version`.",
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FlattenedPackage {
    #[serde(flatten)]
    project: ProjectIdentity,
    title: String,
}

#[derive(Debug, Deserialize)]
struct FlattenedHost {
    package: FlattenedPackage,
}

#[test]
fn cfg_schema_8_serde_flatten_with_deny_unknown_fields_reports_the_first_unknown_key() {
    let read = decode::<FlattenedHost>("package:\n  id: core\n  version: \"1\"\n  title: Core\n")
        .unwrap_or_else(|report| panic!("{report}"));
    assert_eq!(read.package.project.id.as_str(), "core");
    assert_eq!(read.package.title, "Core");

    // serde hands back only the first key no member claimed, and not the
    // accepted keys.
    let report = refusal::<FlattenedHost>(
        "package:\n  id: core\n  version: \"1\"\n  title: Core\n  zzz: 1\n  qqq: 2\n",
    );
    assert_diagnostic(
        only(&report),
        "config.unknown-key",
        "/package/zzz",
        (7, 3),
        "`zzz` is not a member of this mapping",
        "Remove `zzz`.",
    );
}

#[test]
fn cfg_schema_8_serde_flatten_places_errors_inside_the_block_at_the_host() {
    let report =
        refusal::<FlattenedHost>("package:\n  title: Core\n  version: \"1\"\n  id: Core\n");
    let diagnostic = only(&report);
    assert_eq!(diagnostic.code, "config.invalid-value");
    assert_eq!(diagnostic.path, "/package");
    assert_eq!(at(diagnostic), (4, 3));
    assert_eq!(
        diagnostic.message,
        "a value inside this member must be a local identifier matching `^[a-z][a-z0-9_-]{0,63}$`; \
         the format reads this member as a whole, so the reader cannot point to the value"
    );
}

#[test]
fn cfg_schema_8_serde_flatten_without_deny_unknown_fields_cannot_see_unknown_keys() {
    // serde keeps the keys no member claimed and drops them; the reader
    // never sees which ones they were. This is why the source lint refuses
    // `flatten` in a reader type (CFG-SCHEMA-8).
    #[derive(Debug, Deserialize)]
    struct Open {
        #[serde(flatten)]
        project: ProjectIdentity,
    }
    #[derive(Debug, Deserialize)]
    struct Host {
        package: Open,
    }
    let read = decode::<Host>("package:\n  id: core\n  version: \"1\"\n  zzz: 1\n").unwrap();
    assert_eq!(read.package.project.id.as_str(), "core");
}

// ----- CFG-SCHEMA-8: a type's own checks -----

#[derive(Debug, Deserialize)]
#[serde(try_from = "String")]
struct Even(#[allow(dead_code)] String);

impl TryFrom<String> for Even {
    type Error = Invalid;

    fn try_from(text: String) -> Result<Even, Invalid> {
        if text.chars().count().is_multiple_of(2) {
            Ok(Even(text))
        } else {
            Err(Invalid::expected(
                "text with an even number of characters",
                "Add or remove one character.",
            ))
        }
    }
}

#[test]
fn cfg_schema_8_a_try_from_refusal_is_placed_at_the_value() {
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Holder {
        items: Vec<Even>,
    }
    let report = refusal::<Holder>("items:\n  - ab\n  - abc\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-value",
        "/items/1",
        (5, 5),
        "expected text with an even number of characters",
        "Add or remove one character.",
    );
}

/// The checking types the README's "Writing a checking type" section shows.
mod readme {
    use registry_platform_yaml::Invalid;
    use serde::{Deserialize, Deserializer};

    /// A queue name: 1 to 32 lowercase letters or `-`.
    #[derive(Debug, Deserialize)]
    #[serde(try_from = "String")]
    pub struct QueueName(#[allow(dead_code)] String);

    impl TryFrom<String> for QueueName {
        type Error = Invalid;

        fn try_from(text: String) -> Result<QueueName, Invalid> {
            let valid = (1..=32).contains(&text.len())
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
            if !valid {
                return Err(Invalid::expected(
                    "a queue name of 1 to 32 lowercase letters or `-`",
                    "Use lowercase letters and `-` only, at most 32 characters.",
                ));
            }
            Ok(QueueName(text))
        }
    }

    /// A worker count: a power of two, at most 64.
    #[derive(Debug)]
    pub struct Workers(#[allow(dead_code)] u32);

    impl<'de> Deserialize<'de> for Workers {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Workers, D::Error> {
            let count = u32::deserialize(deserializer)?;
            if !(1..=64).contains(&count) {
                return Err(Invalid::out_of_range(1, 64).into_error());
            }
            if !count.is_power_of_two() {
                return Err(
                    Invalid::expected("a power of two", "Use 1, 2, 4, 8, 16, 32, or 64.")
                        .into_error(),
                );
            }
            Ok(Workers(count))
        }
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    pub struct Pool {
        pub minimum: u32,
        pub maximum: u32,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    pub struct Runtime {
        #[serde(default)]
        pub queue: Option<QueueName>,
        #[serde(default)]
        pub workers: Option<Workers>,
        #[serde(default)]
        pub pool: Option<Pool>,
    }
}

#[test]
fn cfg_diag_6_the_readme_checking_types_report_their_own_fix() {
    let report = refusal::<readme::Runtime>("workers: 6\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-value",
        "/workers",
        (3, 10),
        "expected a power of two",
        "Use 1, 2, 4, 8, 16, 32, or 64.",
    );
    assert!(
        report.render_human().starts_with(
            "error[config.invalid-value] runtime.yaml:3:10 /workers\n  expected a power of two\n  next: Use 1, 2, 4, 8, 16, 32, or 64.\n"
        ),
        "{report}"
    );
    let report = refusal::<readme::Runtime>("workers: 128\n");
    assert_diagnostic(
        only(&report),
        "config.out-of-range",
        "/workers",
        (3, 10),
        "the value is outside its bounds; expected a whole number from 1 to 64",
        "Write a whole number from 1 to 64.",
    );
    let report = refusal::<readme::Runtime>("queue: Jobs\n");
    assert_diagnostic(
        only(&report),
        "config.invalid-value",
        "/queue",
        (3, 8),
        "expected a queue name of 1 to 32 lowercase letters or `-`",
        "Use lowercase letters and `-` only, at most 32 characters.",
    );
    let error = serde_json::from_str::<readme::Runtime>("{\"queue\": \"Jobs\"}").unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("expected a queue name of 1 to 32 lowercase letters or `-`"),
        "{error}"
    );
}

#[test]
fn cfg_diag_6_the_readme_cross_member_check_points_at_both_members() {
    let text = with_envelope("pool:\n  minimum: 8\n  maximum: 4\n");
    let document = Reader::new(FILE).read(text.as_bytes(), &EXPECT).unwrap();
    let runtime: readme::Runtime = document.decode().unwrap();
    let pool = runtime.pool.unwrap();
    assert!(pool.minimum > pool.maximum);
    let mut report = Report::new(Vec::new());
    let mut diagnostic = document.diagnostic_at_value(
        Severity::Error,
        "example.pool.minimum-above-maximum",
        "/pool/minimum",
        "the minimum is greater than the maximum",
        "Lower `minimum` to at most `maximum`, or raise `maximum`.",
    );
    let maximum = document.span_of("/pool/maximum").map(|span| span.start);
    diagnostic.related.push(Related {
        file: document.file().to_string(),
        line: maximum.map(|position| position.line),
        column: maximum.map(|position| position.column),
        path: "/pool/maximum".to_string(),
        message: "the maximum".to_string(),
    });
    report.push(diagnostic);
    assert_eq!(
        report.render_human(),
        "error[example.pool.minimum-above-maximum] runtime.yaml:4:12 /pool/minimum\n  the minimum is greater than the maximum\n  next: Lower `minimum` to at most `maximum`, or raise `maximum`.\n  note: runtime.yaml:5:12 /pool/maximum the maximum\n1 error, 0 warnings in 1 file\n"
    );
}

// ----- CFG-ID-1, CFG-ID-2 -----

#[test]
fn cfg_id_1_a_local_id_is_refused_at_its_value_naming_the_grammar() {
    for value in ["Core", "1core", "core.v2", "\"\""] {
        let report = refusal::<Everything>(&format!("id: {value}\n"));
        assert_diagnostic(
            only(&report),
            "config.invalid-value",
            "/id",
            (3, 5),
            "expected a local identifier matching `^[a-z][a-z0-9_-]{0,63}$`",
            "Use lowercase letters, digits, `_`, and `-`, starting with a letter, at most 64 characters.",
        );
    }
    let read = decode::<Everything>("id: core_v2-x\n").unwrap();
    assert_eq!(read.id.unwrap().as_str(), "core_v2-x");
}

#[test]
fn cfg_id_2_an_external_id_is_kept_as_its_issuer_wrote_it() {
    let read = decode::<Everything>("issuerId: \" 0012/AB \"\n").unwrap();
    assert_eq!(read.issuer_id.unwrap().as_str(), " 0012/AB ");
    let report = refusal::<Everything>("issuerId: \"\"\n");
    assert_eq!(codes(&report), ["config.invalid-value"]);
}

// ----- CFG-ID-5, CFG-ID-6 -----

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Step {
    id: LocalId,
    #[serde(default)]
    title: Option<String>,
}

impl Identified for Step {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Steps {
    steps: UniqueIdList<Step>,
}

#[test]
fn cfg_id_5_a_repeated_id_is_refused_at_the_second_id() {
    let report = refusal::<Steps>(
        "steps:\n  - id: intake\n  - id: review\n  - id: intake\n    title: Again\n",
    );
    let diagnostic = only(&report);
    assert_diagnostic(
        diagnostic,
        "config.duplicate-id",
        "/steps/2/id",
        (6, 9),
        "this `id` repeats the `id` of the item at index 0; it is unique in this list",
        "Give each item its own `id`.",
    );
    assert_eq!(diagnostic.related.len(), 1);
    let related = &diagnostic.related[0];
    assert_eq!(related.path, "/steps/0/id");
    assert_eq!((related.line, related.column), (Some(4), Some(9)));
    assert_eq!(related.message, "the first item with this id");

    let read = decode::<Steps>("steps:\n  - id: intake\n  - id: review\n").unwrap();
    assert!(read.steps.get("review").is_some());
}

#[test]
fn cfg_id_6_a_repeated_item_in_a_set_is_refused_at_the_repeat() {
    let report = refusal::<Everything>("scopes: [read, write, read]\n");
    let diagnostic = only(&report);
    assert_diagnostic(
        diagnostic,
        "config.duplicate-item",
        "/scopes/2",
        (3, 23),
        "this item repeats the item at index 0; the list is a set",
        "Remove the repeated item.",
    );
    assert_eq!(diagnostic.related[0].path, "/scopes/0");
    assert_eq!(
        (diagnostic.related[0].line, diagnostic.related[0].column),
        (Some(3), Some(10))
    );
}

// ----- CFG-VAL-6, CFG-VAL-7 -----

#[test]
fn cfg_val_6_a_digest_is_sha256_and_lowercase_hex() {
    let good = format!("sha256:{}", "a".repeat(64));
    let read = decode::<Everything>(&format!("digest: {good}\n")).unwrap();
    assert_eq!(read.digest.unwrap().hex(), "a".repeat(64));
    for value in [
        format!("sha256:{}", "A".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
        "sha256:abc".to_string(),
    ] {
        let report = refusal::<Everything>(&format!("digest: {value}\n"));
        assert_diagnostic(
            only(&report),
            "config.invalid-value",
            "/digest",
            (3, 9),
            "expected a digest written `sha256:` followed by 64 lowercase hex digits",
            "Write the digest as `sha256:` followed by 64 lowercase hex digits.",
        );
    }
}

#[test]
fn cfg_val_7_a_url_is_absolute_with_a_host_and_no_user_information() {
    let read = decode::<Everything>("url: http://a.example:8080/x\n").unwrap();
    assert!(!read.url.unwrap().is_https());
    for value in [
        "/relative",
        "https://user:pw@a.example/",
        "mailto:a@b.example",
        "ftp://a.example/",
    ] {
        let report = refusal::<Everything>(&format!("url: \"{value}\"\n"));
        assert_diagnostic(
            only(&report),
            "config.invalid-value",
            "/url",
            (3, 6),
            "expected an absolute http or https URL with a host, no user information, and at most 2048 characters",
            "Write an absolute URL starting with `https://` or `http://`, without user information.",
        );
    }
}

// ----- JSON input -----

#[test]
fn cfg_yaml_1_json_is_read_as_yaml_flow_content() {
    let text = format!(
        "{{\"apiVersion\": \"{API_VERSION}\", \"kind\": \"ExampleRuntimeConfig\",\n \"port\": \"8080\"}}\n"
    );
    let report = decode_text::<Settings>(&text).unwrap_err();
    assert_diagnostic(
        only(&report),
        "config.expected-integer",
        "/port",
        (2, 10),
        "expected a whole number of 0 or more; quoted values are text",
        "Remove the quotes.",
    );
    let text = format!(
        "{{\"apiVersion\": \"{API_VERSION}\", \"kind\": \"ExampleRuntimeConfig\", \"port\": 1, \"port\": 2}}"
    );
    let report = decode_text::<Settings>(&text).unwrap_err();
    assert_eq!(codes(&report), ["yaml.duplicate-key"]);
    let text = format!(
        "{{\"apiVersion\": \"{API_VERSION}\", \"kind\": \"ExampleRuntimeConfig\", \"port\": 8080}}"
    );
    assert_eq!(decode_text::<Settings>(&text).unwrap().port, Some(8080));
}

// ----- Document helpers -----

#[test]
fn decode_at_reports_full_paths_from_the_root() {
    let text = with_envelope("listener:\n  bind: a\n  port: \"80\"\n");
    let document = Reader::new(FILE).read(text.as_bytes(), &EXPECT).unwrap();
    let report = document.decode_at::<Listener>("/listener").unwrap_err();
    assert_diagnostic(
        only(&report),
        "config.expected-integer",
        "/listener/port",
        (5, 9),
        "expected a whole number of 0 or more; quoted values are text",
        "Remove the quotes.",
    );
    let report = document.decode_at::<Listener>("/nowhere").unwrap_err();
    assert_eq!(codes(&report), ["config.missing-key"]);
    assert!(only(&report)
        .suggested_action
        .contains("product maintainers"));
}

#[test]
fn a_product_diagnostic_is_placed_at_the_value_or_the_key() {
    let text = with_envelope("listener:\n  bind: a\n");
    let document = Reader::new(FILE).read(text.as_bytes(), &EXPECT).unwrap();
    let value = document.diagnostic_at_value(
        Severity::Error,
        "example.listener.unreachable",
        "/listener/bind",
        "the address is not one this host listens on",
        "Use an address of this host.",
    );
    assert_eq!(at(&value), (4, 9));
    assert_eq!(value.artifact.as_deref(), Some("ExampleRuntimeConfig"));
    let key = document.diagnostic_at_key(
        Severity::Warning,
        "example.listener.unused",
        "/listener",
        "the listener is not used",
        "Remove the listener.",
    );
    assert_eq!(at(&key), (3, 1));
    assert_eq!(key.severity, Severity::Warning);
}

#[test]
fn cfg_diag_2_a_report_over_several_files_counts_them() {
    let mut report = refusal::<Settings>("nmae: a\n");
    let other = Reader::new("other.yaml")
        .decode::<Settings>(with_envelope("port: x\n").as_bytes(), &EXPECT)
        .unwrap_err();
    report.extend(other);
    assert_eq!(report.summary(), "2 errors, 0 warnings in 2 files");
    report.set_files_checked(5);
    assert_eq!(report.summary(), "2 errors, 0 warnings in 5 files");
    assert!(report.has_errors());
}

// ----- CFG-DIAG-6: the code table -----

#[test]
fn cfg_diag_6_every_reader_code_has_two_kebab_case_segments() {
    let mut seen = BTreeSet::new();
    for info in CODES {
        let (prefix, rest) = info.code.split_once('.').expect("a two-segment code");
        assert!(prefix == "yaml" || prefix == "config", "{}", info.code);
        assert!(
            !rest.is_empty()
                && !rest.contains('.')
                && rest.split('-').all(|word| !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())),
            "{}",
            info.code
        );
        assert!(!info.meaning.is_empty(), "{}", info.code);
        assert!(seen.insert(info.code), "{} is listed twice", info.code);
    }
}

#[test]
fn cfg_diag_6_every_code_in_the_source_is_in_the_table() {
    let listed: BTreeSet<&str> = CODES.iter().map(|info| info.code).collect();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut used = BTreeSet::new();
    for entry in std::fs::read_dir(&source).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for (index, _) in text.match_indices('"') {
            let rest = &text[index + 1..];
            for prefix in ["yaml.", "config."] {
                if let Some(tail) = rest.strip_prefix(prefix) {
                    let end = tail
                        .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
                        .unwrap_or(tail.len());
                    if tail[end..].starts_with('"') && end > 0 {
                        used.insert(format!("{prefix}{}", &tail[..end]));
                    }
                }
            }
        }
    }
    assert!(used.len() > 20, "{used:?}");
    for code in &used {
        assert!(
            listed.contains(code.as_str()),
            "{code} is emitted but not listed"
        );
    }
    for code in &listed {
        assert!(used.contains(*code), "{code} is listed but never emitted");
    }
}
