// SPDX-License-Identifier: Apache-2.0
//! Pure, closed transforms for compiled Relay access profiles.

use chrono::{DateTime, NaiveDate};
use registry_platform_sqlite::Value;

use crate::contract::{DateInputType, DatePrecision, PartialStringReveal};
use crate::model::CompiledTransform;

pub const PARTIAL_STRING_MARKER: &str = "***";
const MAXIMUM_TRANSFORM_INPUT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformError;

pub fn apply(transform: &CompiledTransform, value: &Value) -> Result<Value, TransformError> {
    let Value::String(value) = value else {
        return Err(TransformError);
    };
    if value.len() > MAXIMUM_TRANSFORM_INPUT_BYTES || value.chars().any(char::is_control) {
        return Err(TransformError);
    }
    match transform {
        CompiledTransform::PartialString {
            reveal, characters, ..
        } => partial_string(value, *reveal, *characters),
        CompiledTransform::DatePrecision {
            source_type,
            precision,
            ..
        } => date_precision(value, *source_type, *precision),
    }
    .map(Value::String)
}

fn partial_string(
    value: &str,
    reveal: PartialStringReveal,
    characters: u16,
) -> Result<String, TransformError> {
    let reveal_count = usize::from(characters);
    if reveal_count == 0 {
        return Err(TransformError);
    }
    let values = value.chars().collect::<Vec<_>>();
    if values.len() <= reveal_count {
        return Ok(PARTIAL_STRING_MARKER.to_owned());
    }
    let revealed = match reveal {
        PartialStringReveal::Prefix => values[..reveal_count].iter().collect::<String>(),
        PartialStringReveal::Suffix => values[values.len() - reveal_count..]
            .iter()
            .collect::<String>(),
    };
    Ok(match reveal {
        PartialStringReveal::Prefix => format!("{revealed}{PARTIAL_STRING_MARKER}"),
        PartialStringReveal::Suffix => format!("{PARTIAL_STRING_MARKER}{revealed}"),
    })
}

fn date_precision(
    value: &str,
    source_type: DateInputType,
    precision: DatePrecision,
) -> Result<String, TransformError> {
    let date = match source_type {
        DateInputType::Date => {
            NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| TransformError)?
        }
        DateInputType::DateTime => DateTime::parse_from_rfc3339(value)
            .map_err(|_| TransformError)?
            .date_naive(),
    };
    Ok(match precision {
        DatePrecision::Year => date.format("%Y").to_string(),
        DatePrecision::YearMonth => date.format("%Y-%m").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_string_never_reveals_a_complete_short_input() {
        let suffix = CompiledTransform::PartialString {
            identifier: "partial-string:suffix:2".into(),
            reveal: PartialStringReveal::Suffix,
            characters: 2,
        };
        assert_eq!(
            apply(&suffix, &Value::String("กข".into())).unwrap(),
            Value::String(PARTIAL_STRING_MARKER.into())
        );
    }

    #[test]
    fn partial_string_counts_unicode_scalars() {
        let suffix = CompiledTransform::PartialString {
            identifier: "partial-string:suffix:2".into(),
            reveal: PartialStringReveal::Suffix,
            characters: 2,
        };
        assert_eq!(
            apply(&suffix, &Value::String("Aกข".into())).unwrap(),
            Value::String("***กข".into())
        );
    }

    #[test]
    fn transforms_reject_wrong_type_and_oversized_input() {
        let partial = CompiledTransform::PartialString {
            identifier: "partial-string:suffix:2".into(),
            reveal: PartialStringReveal::Suffix,
            characters: 2,
        };
        let date = CompiledTransform::DatePrecision {
            identifier: "date-precision:date:year".into(),
            source_type: DateInputType::Date,
            precision: DatePrecision::Year,
        };
        assert_eq!(apply(&partial, &Value::Integer(42)), Err(TransformError));
        let oversized = Value::String("A".repeat(MAXIMUM_TRANSFORM_INPUT_BYTES + 1));
        assert_eq!(apply(&partial, &oversized), Err(TransformError));
        assert_eq!(apply(&date, &oversized), Err(TransformError));
    }

    #[test]
    fn date_precision_accepts_only_the_compiled_source_shape() {
        let year_month = CompiledTransform::DatePrecision {
            identifier: "date-precision:date:year-month".into(),
            source_type: DateInputType::Date,
            precision: DatePrecision::YearMonth,
        };
        assert_eq!(
            apply(&year_month, &Value::String("2026-08-10".into())).unwrap(),
            Value::String("2026-08".into())
        );
        assert!(apply(&year_month, &Value::String("10/08/2026".into())).is_err());
        assert!(apply(&year_month, &Value::Null).is_err());
    }
}
