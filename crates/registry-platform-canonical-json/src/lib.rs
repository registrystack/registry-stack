// SPDX-License-Identifier: Apache-2.0
//! RFC 8785 JSON Canonicalization Scheme shared across Registry Stack.

use serde_json::{Map, Value};
use thiserror::Error;

/// Failures while canonicalizing an already parsed I-JSON value.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JcsError {
    #[error("JCS number is not a finite IEEE 754 binary64 value")]
    InvalidNumber,
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialize a JSON value using RFC 8785 JSON Canonicalization Scheme (JCS).
///
/// Object names are ordered by UTF-16 code units and numbers use ECMAScript's
/// finite IEEE 754 binary64 serialization. Callers that need integers outside
/// binary64's exact range must represent them as strings, as RFC 8785 advises.
/// The input must already satisfy I-JSON, including duplicate-property
/// rejection at the raw JSON boundary; a parsed [`Value`] cannot recover
/// duplicate names that a parser discarded.
pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            let value = number.as_f64().ok_or(JcsError::InvalidNumber)?;
            write_ecmascript_number(value, out)?;
        }
        Value::String(value) => out.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_canonical_object(map, out)?,
    }
    Ok(())
}

fn write_ecmascript_number(value: f64, out: &mut Vec<u8>) -> Result<(), JcsError> {
    if !value.is_finite() {
        return Err(JcsError::InvalidNumber);
    }
    let mut buffer = ryu_js::Buffer::new();
    out.extend_from_slice(buffer.format_finite(value).as_bytes());
    Ok(())
}

fn write_canonical_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<(), JcsError> {
    out.push(b'{');
    let mut entries = map.iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(serde_json::to_string(key)?.as_bytes());
        out.push(b':');
        write_canonical(value, out)?;
    }
    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalizes_nested_objects_recursively() {
        let value = json!({"z": 1, "a": {"b": true, "a": [null, "x"]}});

        assert_eq!(
            String::from_utf8(canonicalize_json(&value).expect("canonicalizes")).expect("UTF-8"),
            r#"{"a":{"a":[null,"x"],"b":true},"z":1}"#
        );
    }

    #[test]
    fn matches_rfc_8785_section_3_2_sample() {
        let value: Value = serde_json::from_str(
            r#"{
                "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
                "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
                "literals": [null, true, false]
            }"#,
        )
        .expect("RFC 8785 sample parses");

        assert_eq!(
            String::from_utf8(canonicalize_json(&value).expect("canonicalizes")).expect("UTF-8"),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    #[test]
    fn matches_rfc_8785_appendix_b_finite_vectors() {
        let vectors = [
            (0x0000_0000_0000_0000, "0"),
            (0x8000_0000_0000_0000, "0"),
            (0x0000_0000_0000_0001, "5e-324"),
            (0x8000_0000_0000_0001, "-5e-324"),
            (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
            (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
            (0x4340_0000_0000_0000, "9007199254740992"),
            (0xc340_0000_0000_0000, "-9007199254740992"),
            (0x4430_0000_0000_0000, "295147905179352830000"),
            (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
            (0x44b5_2d02_c7e1_4af6, "1e+23"),
            (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
            (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
            (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
            (0x444b_1ae4_d6e2_ef50, "1e+21"),
            (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
            (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
            (0x41b3_de43_5555_5553, "333333333.3333332"),
            (0x41b3_de43_5555_5554, "333333333.33333325"),
            (0x41b3_de43_5555_5555, "333333333.3333333"),
            (0x41b3_de43_5555_5556, "333333333.3333334"),
            (0x41b3_de43_5555_5557, "333333333.33333343"),
            (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
            (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
        ];

        for (bits, expected) in vectors {
            let number = serde_json::Number::from_f64(f64::from_bits(bits))
                .expect("RFC finite vector is a JSON number");
            let canonical = canonicalize_json(&Value::Number(number)).expect("canonicalizes");
            assert_eq!(String::from_utf8(canonical).expect("UTF-8"), expected);
        }
    }

    #[test]
    fn sorts_names_by_utf16_code_units() {
        let value: Value = serde_json::from_str(
            r#"{
                "\u20ac": "Euro Sign",
                "\r": "Carriage Return",
                "\ufb33": "Hebrew Letter Dalet With Dagesh",
                "1": "One",
                "\ud83d\ude00": "Emoji: Grinning Face",
                "\u0080": "Control",
                "\u00f6": "Latin Small Letter O With Diaeresis"
            }"#,
        )
        .expect("RFC 8785 property-order fixture parses");

        assert_eq!(
            String::from_utf8(canonicalize_json(&value).expect("canonicalizes")).expect("UTF-8"),
            concat!(
                "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"",
                "\u{80}",
                "\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",",
                "\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",",
                "\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"
            )
        );
    }

    #[test]
    fn uses_ecmascript_boundaries_and_rejects_non_finite_values() {
        let value: Value =
            serde_json::from_str(r#"[-0,1e-7,1e-6,1e20,1e21]"#).expect("fixture parses");
        assert_eq!(
            String::from_utf8(canonicalize_json(&value).expect("canonicalizes")).expect("UTF-8"),
            "[0,1e-7,0.000001,100000000000000000000,1e+21]"
        );

        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut out = Vec::new();
            assert!(matches!(
                write_ecmascript_number(value, &mut out),
                Err(JcsError::InvalidNumber)
            ));
            assert!(out.is_empty());
        }
    }

    #[test]
    fn preserves_array_order_and_unicode_without_normalization() {
        let composed = "é";
        let decomposed = "e\u{301}";
        let value = json!([
            {"nested": {"z": 1, "a": 2}},
            composed,
            decomposed,
            "😀"
        ]);

        let canonical = canonicalize_json(&value).expect("canonicalizes");
        assert_eq!(
            String::from_utf8(canonical.clone()).expect("UTF-8"),
            "[{\"nested\":{\"a\":2,\"z\":1}},\"é\",\"é\",\"😀\"]"
        );
        let reparsed: Value = serde_json::from_slice(&canonical).expect("canonical JSON parses");
        assert_eq!(
            canonicalize_json(&reparsed).expect("canonicalizes"),
            canonical
        );
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
    }
}
