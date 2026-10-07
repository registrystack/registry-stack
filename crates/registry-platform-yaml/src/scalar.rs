// SPDX-License-Identifier: Apache-2.0
//! The one resolution table for plain scalars (CFG-VAL-1).
//!
//! | Plain scalar | Resolves to |
//! |---|---|
//! | `null`, `Null`, `NULL`, `~`, or nothing | null |
//! | `true`, `True`, `TRUE`, `false`, `False`, `FALSE` | boolean |
//! | `[-+]?(0\|[1-9][0-9]*)` (`-0` and `+0` read as 0) | integer |
//! | the same with a fraction and/or an exponent (`1.5`, `-0.25`, `1e3`) | number |
//! | a leading zero (`0123`, `01.5`), a bare point (`.5`, `5.`), a base prefix in any sign or case (`0x1F`, `0o17`, `0b101`), `.inf` or `.nan` in any sign or case | refused, `yaml.ambiguous-number` |
//! | anything else (`yes`, `no`, `on`, `off`, `1_000`, `1:30`, `09:00`) | string |
//!
//! Quoted and block scalars are always strings and never pass through this
//! table.

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Resolved {
    Null,
    Bool(bool),
    Integer(i128),
    Float(f64),
    String,
    Ambiguous,
    /// An integer literal outside `i64::MIN..=u64::MAX`.
    IntegerOutOfRange,
    /// A number literal that overflows binary64.
    FloatOutOfRange,
}

pub(crate) fn resolve_plain(text: &str) -> Resolved {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Resolved::Null,
        "true" | "True" | "TRUE" => return Resolved::Bool(true),
        "false" | "False" | "FALSE" => return Resolved::Bool(false),
        _ => {}
    }
    let unsigned = text
        .strip_prefix('-')
        .or_else(|| text.strip_prefix('+'))
        .unwrap_or(text);
    if unsigned.eq_ignore_ascii_case(".inf") || unsigned.eq_ignore_ascii_case(".nan") {
        return Resolved::Ambiguous;
    }
    if has_base_prefix(unsigned) {
        return Resolved::Ambiguous;
    }
    match decimal_shape(unsigned) {
        Shape::NotANumber => Resolved::String,
        Shape::Ambiguous => Resolved::Ambiguous,
        Shape::Integer => {
            let negative = text.starts_with('-');
            match unsigned.parse::<u128>() {
                Ok(magnitude) if magnitude <= u128::from(u64::MAX) => {
                    let magnitude = magnitude as i128;
                    if negative {
                        if -magnitude < i128::from(i64::MIN) {
                            Resolved::IntegerOutOfRange
                        } else {
                            Resolved::Integer(-magnitude)
                        }
                    } else {
                        Resolved::Integer(magnitude)
                    }
                }
                _ => Resolved::IntegerOutOfRange,
            }
        }
        Shape::Float => match text.parse::<f64>() {
            Ok(value) if value.is_finite() => {
                // `-0.0` and `0.0` are the same number in configuration.
                Resolved::Float(if value == 0.0 { 0.0 } else { value })
            }
            _ => Resolved::FloatOutOfRange,
        },
    }
}

enum Shape {
    NotANumber,
    Ambiguous,
    Integer,
    Float,
}

fn has_base_prefix(unsigned: &str) -> bool {
    let bytes = unsigned.as_bytes();
    if bytes.len() < 3 || bytes[0] != b'0' {
        return false;
    }
    let digits = &bytes[2..];
    match bytes[1] {
        b'x' | b'X' => digits.iter().all(u8::is_ascii_hexdigit),
        b'o' | b'O' => digits.iter().all(|byte| (b'0'..=b'7').contains(byte)),
        b'b' | b'B' => digits.iter().all(|&byte| byte == b'0' || byte == b'1'),
        _ => false,
    }
}

/// Classify an unsigned decimal: digits, an optional `.` fraction, an
/// optional exponent.
fn decimal_shape(unsigned: &str) -> Shape {
    let bytes = unsigned.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    let integer_digits = index;
    let mut point = false;
    let mut fraction_digits = 0;
    if index < bytes.len() && bytes[index] == b'.' {
        point = true;
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
            fraction_digits += 1;
        }
    }
    let mut exponent = false;
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        let mut cursor = index + 1;
        if cursor < bytes.len() && (bytes[cursor] == b'-' || bytes[cursor] == b'+') {
            cursor += 1;
        }
        let digits_start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == digits_start {
            return Shape::NotANumber;
        }
        exponent = true;
        index = cursor;
    }
    if index != bytes.len() {
        return Shape::NotANumber;
    }
    if integer_digits == 0 {
        // `.5` is a bare point; `.` or `e5` alone is text.
        return if point && fraction_digits > 0 {
            Shape::Ambiguous
        } else {
            Shape::NotANumber
        };
    }
    let leading_zero = integer_digits > 1 && bytes[0] == b'0';
    if leading_zero {
        return Shape::Ambiguous;
    }
    if point && fraction_digits == 0 {
        return Shape::Ambiguous;
    }
    if point || exponent {
        Shape::Float
    } else {
        Shape::Integer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_val_1_table_rows_resolve_as_written() {
        for null in ["", "~", "null", "Null", "NULL"] {
            assert_eq!(resolve_plain(null), Resolved::Null, "{null:?}");
        }
        for (text, value) in [
            ("true", true),
            ("True", true),
            ("TRUE", true),
            ("false", false),
            ("False", false),
            ("FALSE", false),
        ] {
            assert_eq!(resolve_plain(text), Resolved::Bool(value), "{text}");
        }
        for (text, value) in [
            ("0", 0),
            ("-0", 0),
            ("+0", 0),
            ("7", 7),
            ("+42", 42),
            ("-42", -42),
            ("18446744073709551615", i128::from(u64::MAX)),
            ("-9223372036854775808", i128::from(i64::MIN)),
        ] {
            assert_eq!(resolve_plain(text), Resolved::Integer(value), "{text}");
        }
        for (text, value) in [
            ("1.5", 1.5),
            ("-0.25", -0.25),
            ("1e3", 1000.0),
            ("1E3", 1000.0),
            ("2.5e-1", 0.25),
            ("0.5", 0.5),
            ("0e5", 0.0),
            ("-0.0", 0.0),
            ("5.0", 5.0),
        ] {
            assert_eq!(resolve_plain(text), Resolved::Float(value), "{text}");
        }
        for text in [
            "0123", "-0123", "00", "01.5", ".5", "-.5", "+.5", "5.", "5.e3", "0x1F", "0X1f",
            "-0x1F", "0o17", "0O17", "0b101", "+0B101", ".inf", "-.inf", "+.INF", ".Inf", ".nan",
            ".NaN", ".NAN", "-.nan",
        ] {
            assert_eq!(resolve_plain(text), Resolved::Ambiguous, "{text}");
        }
        for text in [
            "yes", "no", "on", "off", "Yes", "1_000", "1:30", "09:00", "5s", "48h", "1e", "e5",
            ".", "-", "+", "0xZZ", "0b102", "inf", "nan", "1.2.3", "v1", "abc", "1 000",
        ] {
            assert_eq!(resolve_plain(text), Resolved::String, "{text}");
        }
    }

    #[test]
    fn cfg_val_1_unrepresentable_literals_are_out_of_range() {
        assert_eq!(
            resolve_plain("18446744073709551616"),
            Resolved::IntegerOutOfRange
        );
        assert_eq!(
            resolve_plain("-9223372036854775809"),
            Resolved::IntegerOutOfRange
        );
        assert_eq!(
            resolve_plain("99999999999999999999999999999999999999999999"),
            Resolved::IntegerOutOfRange
        );
        assert_eq!(resolve_plain("1e400"), Resolved::FloatOutOfRange);
        assert_eq!(resolve_plain("-1e400"), Resolved::FloatOutOfRange);
    }

    #[test]
    fn cfg_val_1_non_ascii_text_after_a_leading_zero_is_text() {
        for text in [
            "0\u{6d6}",
            "-0\u{6d6}",
            "0\u{e9}1",
            "0x\u{e9}",
            "0\u{1f600}",
        ] {
            assert_eq!(resolve_plain(text), Resolved::String, "{text:?}");
        }
    }
}
