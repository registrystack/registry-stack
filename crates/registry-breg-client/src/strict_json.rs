//! Duplicate-key-refusing JSON decoding for response trust boundaries.

use registry_platform_canonical_json::parse_json_preserving_integers;
use serde_json::{Number, Value};

pub(crate) fn from_slice(bytes: &[u8]) -> Result<Value, ()> {
    validate_number_tokens(bytes)?;
    parse_json_preserving_integers(bytes).map_err(|_| ())
}

/// Refuse numeric literals that serde would silently round. Equivalent decimal
/// spellings (for example 1e2 and 100) remain accepted.
pub(crate) fn validate_number_tokens(bytes: &[u8]) -> Result<(), ()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'"' => {
                offset += 1;
                while offset < bytes.len() && bytes[offset] != b'"' {
                    if bytes[offset] == b'\\' {
                        offset += 1;
                    }
                    offset += 1;
                }
                offset += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = offset;
                while offset < bytes.len()
                    && matches!(
                        bytes[offset],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    offset += 1;
                }
                let token = std::str::from_utf8(&bytes[start..offset]).map_err(|_| ())?;
                let number: Number = serde_json::from_str(token).map_err(|_| ())?;
                if decimal_identity(token)? != decimal_identity(&number.to_string())? {
                    return Err(());
                }
            }
            _ => offset += 1,
        }
    }
    Ok(())
}

fn decimal_identity(token: &str) -> Result<(bool, String, i64), ()> {
    let negative = token.starts_with('-');
    let unsigned = token.trim_start_matches('-');
    let (mantissa, exponent) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
    let exponent: i64 = exponent.parse().map_err(|_| ())?;
    let fraction = mantissa.split_once('.').map_or(0, |(_, part)| part.len());
    let digits = mantissa.replace('.', "");
    let leading = digits.trim_start_matches('0');
    if leading.is_empty() {
        return Ok((false, "0".into(), 0));
    }
    let trimmed = leading.trim_end_matches('0');
    let scale = exponent
        .checked_sub(i64::try_from(fraction).map_err(|_| ())?)
        .and_then(|value| value.checked_add((leading.len() - trimmed.len()) as i64))
        .ok_or(())?;
    Ok((negative, trimmed.into(), scale))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_members_are_refused_at_every_depth() {
        assert!(from_slice(br#"{"outer":{"member":1,"member":2}}"#).is_err());
        assert!(from_slice(br#"{"outer":{"member":1},"other":2}"#).is_ok());
    }
}
