// SPDX-License-Identifier: Apache-2.0
//! RFC 8785 JSON Canonicalization Scheme shared across Registry Stack.

use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use thiserror::Error;

/// Failure to decode one structurally unambiguous JSON value.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StrictJsonError {
    /// A raw integer token would lose information when decoded as binary64.
    #[error("strict JSON integer is not exactly representable as IEEE 754 binary64")]
    IntegerNotExactlyRepresentable,
    /// Syntax, recursion, number, or duplicate-member rejection.
    #[error("strict JSON decoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Parse JSON while rejecting duplicate object members at every depth and raw
/// plain-integer tokens that are not exactly representable as binary64.
///
/// Parsing directly into [`Value`] erases duplicate names. Callers that hash,
/// sign, compile, or structurally interpret JSON must use this boundary before
/// deserializing the returned value into their closed type. This check also
/// runs before `serde_json` can round a plain integer outside its native integer
/// representations through `f64`. Fractional and exponent-form tokens retain
/// RFC 8785's normal correctly rounded binary64 semantics. The caller remains
/// responsible for bounding `bytes` before parsing.
pub fn parse_json_strict(bytes: &[u8]) -> Result<Value, StrictJsonError> {
    reject_inexact_raw_integer_tokens(bytes)?;
    serde_json::from_slice::<DuplicateFreeJsonValue>(bytes)
        .map(DuplicateFreeJsonValue::into_inner)
        .map_err(StrictJsonError::from)
}

/// Reject integer lexemes that `serde_json` would otherwise round through an
/// `f64` after they exceed its signed and unsigned integer representations.
///
/// A finite binary64 integer has at most 1,024 significant bits. The fixed
/// limb accumulator therefore covers every potentially valid value without an
/// allocation or an input-size-dependent big-integer operation.
fn reject_inexact_raw_integer_tokens(bytes: &[u8]) -> Result<(), StrictJsonError> {
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }

        let number_start = if byte.is_ascii_digit()
            || (byte == b'-' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit))
        {
            Some(index)
        } else {
            None
        };
        let Some(start) = number_start else {
            index += 1;
            continue;
        };

        let mut end = start + usize::from(bytes[start] == b'-');
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }

        let has_fraction = bytes.get(end) == Some(&b'.');
        if has_fraction {
            end += 1;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
        }

        let has_exponent = matches!(bytes.get(end), Some(b'e' | b'E'));
        if has_exponent {
            end += 1;
            if matches!(bytes.get(end), Some(b'+' | b'-')) {
                end += 1;
            }
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
        }

        if !has_fraction && !has_exponent && !decimal_integer_is_exact_binary64(&bytes[start..end])
        {
            return Err(StrictJsonError::IntegerNotExactlyRepresentable);
        }
        index = end;
    }
    Ok(())
}

fn decimal_integer_is_exact_binary64(token: &[u8]) -> bool {
    const LIMBS: usize = 16;

    let digits = token.strip_prefix(b"-").unwrap_or(token);
    let mut magnitude = [0_u64; LIMBS];
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return false;
        }
        let mut carry = u128::from(digit - b'0');
        for limb in &mut magnitude {
            let next = u128::from(*limb) * 10 + carry;
            *limb = next as u64;
            carry = next >> u64::BITS;
        }
        if carry != 0 {
            return false;
        }
    }

    let Some(highest_index) = magnitude.iter().rposition(|limb| *limb != 0) else {
        return true;
    };
    let significant_bits =
        highest_index as u32 * u64::BITS + (u64::BITS - magnitude[highest_index].leading_zeros());
    if significant_bits <= 53 {
        return true;
    }

    let trailing_zero_bits = magnitude.iter().take_while(|limb| **limb == 0).count() as u32
        * u64::BITS
        + magnitude
            .iter()
            .find(|limb| **limb != 0)
            .map_or(0, |limb| limb.trailing_zeros());
    trailing_zero_bits >= significant_bits - 53
}

/// Internal wrapper that prevents `serde_json::Value` from erasing duplicate
/// object members during recursive decoding.
struct DuplicateFreeJsonValue(Value);

impl DuplicateFreeJsonValue {
    fn into_inner(self) -> Value {
        self.0
    }
}

impl<'de> Deserialize<'de> for DuplicateFreeJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateFreeJsonValueVisitor)
    }
}

struct DuplicateFreeJsonValueVisitor;

impl<'de> Visitor<'de> for DuplicateFreeJsonValueVisitor {
    type Value = DuplicateFreeJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-free JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(DuplicateFreeJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(DuplicateFreeJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateFreeJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateFreeJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateFreeJsonValue>()? {
            values.push(value.into_inner());
        }
        Ok(DuplicateFreeJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            let value = object.next_value::<DuplicateFreeJsonValue>()?;
            values.insert(key, value.into_inner());
        }
        Ok(DuplicateFreeJsonValue(Value::Object(values)))
    }
}

/// Failures while canonicalizing an already parsed I-JSON value.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JcsError {
    #[error("JCS number is not a finite IEEE 754 binary64 value")]
    InvalidNumber,
    #[error("JCS integer is not exactly representable as IEEE 754 binary64")]
    IntegerNotExactlyRepresentable,
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serialize a JSON value using RFC 8785 JSON Canonicalization Scheme (JCS).
///
/// Object names are ordered by UTF-16 code units and numbers use ECMAScript's
/// finite IEEE 754 binary64 serialization. Integer `Value`s that are not
/// exactly representable as binary64 are rejected; callers must represent them
/// as strings, as RFC 8785 advises.
/// The input must already satisfy I-JSON, including duplicate-property
/// rejection at the raw JSON boundary; a parsed [`Value`] cannot recover
/// duplicate names that a parser discarded.
pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, JcsError> {
    validate_canonical_numbers(value)?;
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn validate_canonical_numbers(value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Number(number) => {
            number_as_exact_binary64(number)?;
        }
        Value::Array(values) => {
            for value in values {
                validate_canonical_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_canonical_numbers(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            let value = number_as_exact_binary64(number)?;
            write_ecmascript_number(value, out)?;
        }
        Value::String(value) => serde_json::to_writer(&mut *out, value)?,
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

fn number_as_exact_binary64(number: &serde_json::Number) -> Result<f64, JcsError> {
    if let Some(value) = number.as_i64() {
        if !integer_magnitude_is_exact_binary64(value.unsigned_abs()) {
            return Err(JcsError::IntegerNotExactlyRepresentable);
        }
        return Ok(value as f64);
    }
    if let Some(value) = number.as_u64() {
        if !integer_magnitude_is_exact_binary64(value) {
            return Err(JcsError::IntegerNotExactlyRepresentable);
        }
        return Ok(value as f64);
    }
    number.as_f64().ok_or(JcsError::InvalidNumber)
}

fn integer_magnitude_is_exact_binary64(value: u64) -> bool {
    if value == 0 {
        return true;
    }
    let significant_bits = u64::BITS - value.leading_zeros();
    significant_bits <= 53 || value.trailing_zeros() >= significant_bits - 53
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
        serde_json::to_writer(&mut *out, key)?;
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
    fn strict_parser_accepts_every_unambiguous_json_shape() {
        let parsed = parse_json_strict(br#"{"z":[null,true,-1,2,3.5,"value"],"a":{"ok":false}}"#)
            .expect("duplicate-free fixture");
        assert_eq!(
            parsed,
            json!({"z": [null, true, -1, 2, 3.5, "value"], "a": {"ok": false}})
        );
    }

    #[test]
    fn strict_parser_rejects_duplicate_members_at_every_depth() {
        for raw in [
            br#"{"id":1,"id":2}"#.as_slice(),
            br#"{"id":1,"\u0069d":2}"#.as_slice(),
            br#"{"outer":{"id":1,"id":2}}"#.as_slice(),
            br#"[{"id":1,"id":2}]"#.as_slice(),
            br#"{"items":[{"ok":1},{"id":1,"id":2}]}"#.as_slice(),
        ] {
            let error = parse_json_strict(raw).expect_err("duplicate member rejected");
            assert!(error.to_string().contains("duplicate JSON object member"));
        }
    }

    #[test]
    fn strict_parser_rejects_trailing_or_multiple_values() {
        for raw in [br#"{} []"#.as_slice(), br#"{} trailing"#.as_slice()] {
            parse_json_strict(raw).expect_err("one complete JSON value is required");
        }
    }

    #[test]
    fn strict_parser_rejects_integer_tokens_that_would_round_to_a_neighbor() {
        for raw in [
            br#"9007199254740993"#.as_slice(),
            br#"-9007199254740993"#.as_slice(),
            br#"18446744073709551617"#.as_slice(),
            br#"{"nested":18446744073709551617}"#.as_slice(),
        ] {
            assert!(matches!(
                parse_json_strict(raw),
                Err(StrictJsonError::IntegerNotExactlyRepresentable)
            ));
        }

        let left = parse_json_strict(br#"18446744073709551616"#)
            .expect("two to the sixty-fourth is exact");
        assert!(parse_json_strict(br#"18446744073709551617"#).is_err());
        assert_eq!(
            canonicalize_json(&left).expect("exact value canonicalizes"),
            b"18446744073709552000"
        );
    }

    #[test]
    fn strict_parser_accepts_exact_large_integers_and_float_lexemes() {
        for raw in [
            br#"9007199254740992"#.as_slice(),
            br#"1152921504606846976"#.as_slice(),
            br#"1267650600228229401496703205376"#.as_slice(),
            br#"1e20"#.as_slice(),
            br#"18446744073709551617.0"#.as_slice(),
            br#""18446744073709551617""#.as_slice(),
        ] {
            parse_json_strict(raw).expect("binary64-safe JSON value");
        }

        let escaped_string = br#"{"value":"escaped \\\" 18446744073709551617"}"#;
        parse_json_strict(escaped_string)
            .expect("integer text inside an escaped string is ignored");

        let too_large_integer = format!("1{}", "0".repeat(309));
        assert!(matches!(
            parse_json_strict(too_large_integer.as_bytes()),
            Err(StrictJsonError::IntegerNotExactlyRepresentable)
        ));
    }

    #[test]
    fn raw_decimal_exactness_matches_the_binary_rule_across_u128_boundaries() {
        let mut values = vec![
            0_u128,
            1,
            (1_u128 << 53) - 1,
            1_u128 << 53,
            (1_u128 << 53) + 1,
            1_u128 << 64,
            (1_u128 << 64) + 1,
            1_u128 << 100,
            (1_u128 << 100) + 1,
            1_u128 << 127,
            (u128::MAX >> 75) << 75,
            (1_u128 << 127) + (1_u128 << 74),
            (1_u128 << 127) + 1,
        ];
        let mut sample = 0x9e37_79b9_7f4a_7c15_d1b5_4a32_d192_ed03_u128;
        for _ in 0..10_000 {
            sample = sample
                .wrapping_mul(0xda94_2042_e4dd_58b5_5bd1_e995_4a4f_6cdd)
                .wrapping_add(0x94d0_49bb_1331_11eb);
            values.push(sample);
        }

        for value in values {
            let significant_bits = u128::BITS - value.leading_zeros();
            let expected = value == 0
                || significant_bits <= 53
                || value.trailing_zeros() >= significant_bits - 53;
            assert_eq!(
                decimal_integer_is_exact_binary64(value.to_string().as_bytes()),
                expected,
                "decimal exactness mismatch for {value}"
            );
        }
    }

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
    fn rejects_integer_values_that_would_collapse_to_a_neighboring_binary64() {
        let positive = Value::Number(serde_json::Number::from(9_007_199_254_740_993_u64));
        let negative = Value::Number(serde_json::Number::from(-9_007_199_254_740_993_i64));
        let maximum = Value::Number(serde_json::Number::from(u64::MAX));
        for value in [positive, negative, maximum] {
            assert!(matches!(
                canonicalize_json(&value),
                Err(JcsError::IntegerNotExactlyRepresentable)
            ));
        }

        for (value, expected) in [
            (9_007_199_254_740_992_u64, "9007199254740992"),
            (1_u64 << 60, "1152921504606847000"),
        ] {
            let canonical = canonicalize_json(&Value::Number(serde_json::Number::from(value)))
                .expect("exact integer canonicalizes");
            assert_eq!(String::from_utf8(canonical).expect("UTF-8"), expected);
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
