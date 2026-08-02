//! Core-owned exact and protected values crossing the Rhai boundary.

use std::{cmp::Ordering, fmt, str::FromStr};

use serde::{Serialize, Serializer};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_DECIMAL_PRECISION: usize = 28;
const MAX_DECIMAL_SCALE: u32 = 9;
const MAX_ENTITY_SEED_BYTES: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub struct Decimal {
    coefficient: i128,
    scale: u32,
    canonical: String,
}

impl Decimal {
    pub fn parse(input: &str) -> Result<Self, DecimalError> {
        if input.is_empty()
            || input.starts_with('+')
            || input.contains(['e', 'E'])
            || matches!(input, "NaN" | "Infinity" | "-Infinity")
        {
            return Err(DecimalError::Lexical);
        }

        let (negative, unsigned) = match input.strip_prefix('-') {
            Some(unsigned) => (true, unsigned),
            None => (false, input),
        };
        if unsigned.is_empty() {
            return Err(DecimalError::Lexical);
        }
        let (integer, fraction) = match unsigned.split_once('.') {
            Some((integer, fraction)) => (integer, Some(fraction)),
            None => (unsigned, None),
        };

        if integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || (integer.len() > 1 && integer.starts_with('0'))
        {
            return Err(DecimalError::Lexical);
        }
        let scale = match fraction {
            Some(fraction)
                if !fraction.is_empty()
                    && fraction.bytes().all(|byte| byte.is_ascii_digit())
                    && !fraction.ends_with('0') =>
            {
                u32::try_from(fraction.len()).map_err(|_| DecimalError::Scale)?
            }
            Some(_) => return Err(DecimalError::Lexical),
            None => 0,
        };
        if scale > MAX_DECIMAL_SCALE {
            return Err(DecimalError::Scale);
        }

        let digits = match fraction {
            Some(fraction) => format!("{integer}{fraction}"),
            None => integer.to_owned(),
        };
        let significant = digits.trim_start_matches('0');
        let precision = significant.len().max(1);
        if precision > MAX_DECIMAL_PRECISION {
            return Err(DecimalError::Precision);
        }
        let magnitude = if significant.is_empty() {
            0
        } else {
            i128::from_str(significant).map_err(|_| DecimalError::Precision)?
        };
        if magnitude == 0 && (negative || scale != 0) {
            return Err(DecimalError::Zero);
        }
        let coefficient = if negative { -magnitude } else { magnitude };

        Ok(Self {
            coefficient,
            scale,
            canonical: input.to_owned(),
        })
    }

    pub fn from_integer(value: i64) -> Self {
        Self {
            coefficient: i128::from(value),
            scale: 0,
            canonical: value.to_string(),
        }
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn scale(&self) -> u32 {
        self.scale
    }

    pub fn compare(&self, other: &Self) -> Ordering {
        match self.scale.cmp(&other.scale) {
            Ordering::Equal => self.coefficient.cmp(&other.coefficient),
            Ordering::Less => self
                .coefficient
                .saturating_mul(power_of_ten(other.scale - self.scale))
                .cmp(&other.coefficient),
            Ordering::Greater => self.coefficient.cmp(
                &other
                    .coefficient
                    .saturating_mul(power_of_ten(self.scale - other.scale)),
            ),
        }
    }
}

impl fmt::Debug for Decimal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Decimal([REDACTED])")
    }
}

impl Serialize for Decimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical)
    }
}

impl FromStr for Decimal {
    type Err = DecimalError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DecimalError {
    #[error("decimal text is not canonical")]
    Lexical,
    #[error("decimal zero must be represented as 0")]
    Zero,
    #[error("decimal precision exceeds the supported bound")]
    Precision,
    #[error("decimal scale exceeds the supported bound")]
    Scale,
}

fn power_of_ten(exponent: u32) -> i128 {
    10_i128.pow(exponent)
}

pub struct EntityReferenceSeed(Zeroizing<Vec<u8>>);

impl EntityReferenceSeed {
    pub fn new(input: &str) -> Result<Self, EntityReferenceSeedError> {
        let bytes = input.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_ENTITY_SEED_BYTES {
            return Err(EntityReferenceSeedError);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    pub(crate) fn expose_for_projection(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Clone for EntityReferenceSeed {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_vec()))
    }
}

impl fmt::Debug for EntityReferenceSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntityReferenceSeed(<redacted>)")
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("entity-reference seed is empty or exceeds its bound")]
pub struct EntityReferenceSeedError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_decimals_round_trip_as_json_strings() {
        for text in [
            "0",
            "1",
            "-1",
            "0.25",
            "-10.5",
            "1234567890123456789012345678",
            "0.000000001",
        ] {
            let value = Decimal::parse(text).expect("decimal parses");
            assert_eq!(value.canonical(), text);
            assert_eq!(
                serde_json::to_string(&value).expect("serializes"),
                format!("\"{text}\"")
            );
        }
    }

    #[test]
    fn noncanonical_or_excessive_decimals_are_rejected() {
        for text in [
            "",
            "+1",
            "01.0",
            "1.0",
            "1.",
            ".1",
            "-0",
            "-0.0",
            "0.0",
            "1e2",
            "NaN",
            "12345678901234567890123456789",
            "0.1234567891",
        ] {
            assert!(Decimal::parse(text).is_err(), "{text} must be rejected");
        }
    }

    #[test]
    fn decimal_comparison_is_exact_across_scales() {
        let one = Decimal::parse("1").expect("parses");
        let one_point_five = Decimal::parse("1.5").expect("parses");
        let negative_tenth = Decimal::parse("-0.1").expect("parses");
        assert_eq!(one.compare(&one_point_five), Ordering::Less);
        assert_eq!(one_point_five.compare(&one), Ordering::Greater);
        assert_eq!(negative_tenth.compare(&one), Ordering::Less);
    }

    #[test]
    fn entity_seed_debug_is_redacted() {
        let seed = EntityReferenceSeed::new("protected-canary").expect("seed builds");
        let debug = format!("{seed:?}");
        assert!(!debug.contains("protected-canary"));
        assert_eq!(debug, "EntityReferenceSeed(<redacted>)");

        let decimal = Decimal::parse("8192.125").expect("decimal parses");
        let debug = format!("{decimal:?}");
        assert!(!debug.contains("8192.125"));
        assert_eq!(debug, "Decimal([REDACTED])");
    }
}
