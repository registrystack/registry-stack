// SPDX-License-Identifier: Apache-2.0
//! Shared claim-verification primitives.

use std::collections::BTreeMap;

use hmac::{KeyInit, Mac, SimpleHmac};
use serde_json::{Number, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, InternalError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimVerificationKeyError {
    MissingPrefix,
    InvalidHex,
    TooShort,
}

const MIN_BINDING_KEY_HEX_LEN: usize = 64;

/// HMAC key used to bind submitted claim-verification inputs without
/// exposing those inputs in responses or signed receipts.
pub struct ClaimVerificationHasher {
    binding_key_id: String,
    key: Zeroizing<Vec<u8>>,
}

impl ClaimVerificationHasher {
    #[must_use]
    pub(crate) fn new(binding_key_id: String, key: Zeroizing<Vec<u8>>) -> Self {
        Self {
            binding_key_id,
            key,
        }
    }

    /// Build a hasher from a configured `hex:<64-or-more-lowercase-hex-chars>`
    /// binding key value.
    pub fn from_encoded_key(
        binding_key_id: String,
        encoded_key: &str,
    ) -> Result<Self, ClaimVerificationKeyError> {
        Ok(Self::new(binding_key_id, decode_binding_key(encoded_key)?))
    }

    #[must_use]
    pub fn binding_key_id(&self) -> &str {
        &self.binding_key_id
    }

    pub fn hmac_hex(&self, value: &Value) -> Result<String, Error> {
        self.hmac_hex_with_key(self.key.as_ref(), value)
    }

    pub fn hmac_hex_for_offering(
        &self,
        offering_iri: &str,
        value: &Value,
    ) -> Result<String, Error> {
        let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(self.key.as_ref())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(b"registry-relay:evidence-offering:v1:");
        mac.update(offering_iri.as_bytes());
        let derived = mac.finalize().into_bytes();
        self.hmac_hex_with_key(&derived, value)
    }

    fn hmac_hex_with_key(&self, key: &[u8], value: &Value) -> Result<String, Error> {
        let canonical = canonical_json(value)?;
        let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(canonical.as_bytes());
        let bytes = mac.finalize().into_bytes();
        Ok(format!("hmac-sha256:{}", hex_lower(&bytes)))
    }
}

impl std::fmt::Debug for ClaimVerificationHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimVerificationHasher")
            .field("binding_key_id", &self.binding_key_id)
            .finish_non_exhaustive()
    }
}

pub fn normalize_claims_for_hash(claims: &BTreeMap<String, Value>) -> Value {
    Value::Object(
        claims
            .iter()
            .map(|(key, value)| (key.clone(), normalize_claim_value_for_hash(value)))
            .collect(),
    )
}

pub fn normalize_claim_value_for_hash(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(normalize_claim_string(value)),
        Value::Number(number) => {
            Value::String(canonical_number(number).unwrap_or_else(|_| number.to_string()))
        }
        Value::Array(values) => {
            Value::Array(values.iter().map(normalize_claim_value_for_hash).collect())
        }
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), normalize_claim_value_for_hash(value)))
                .collect(),
        ),
        Value::Bool(_) | Value::Null => value.clone(),
    }
}

pub fn normalize_claim_value_for_match(value: &Value) -> String {
    match value {
        Value::String(value) => normalize_claim_string(value),
        Value::Number(value) => canonical_number(value).unwrap_or_else(|_| value.to_string()),
        Value::Bool(value) => value.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn normalize_claim_string(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub(crate) fn canonical_json(value: &Value) -> Result<String, Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            serde_json::to_string(value).map_err(|_| InternalError::Unhandled.into())
        }
        Value::Number(number) => canonical_number(number),
        Value::Array(values) => {
            let mut output = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&canonical_json(value)?);
            }
            output.push(']');
            Ok(output)
        }
        Value::Object(object) => {
            let sorted = object.iter().collect::<BTreeMap<_, _>>();
            let mut output = String::from("{");
            for (index, (key, value)) in sorted.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|_| Error::from(InternalError::Unhandled))?,
                );
                output.push(':');
                output.push_str(&canonical_json(value)?);
            }
            output.push('}');
            Ok(output)
        }
    }
}

fn canonical_number(number: &Number) -> Result<String, Error> {
    if let Some(value) = number.as_i64() {
        return Ok(value.to_string());
    }
    if let Some(value) = number.as_u64() {
        return Ok(value.to_string());
    }
    let Some(value) = number.as_f64() else {
        return Err(InternalError::Unhandled.into());
    };
    if value == 0.0 {
        return Ok("0".to_string());
    }
    if value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0 {
        return Ok(format!("{value:.0}"));
    }
    let mut buffer = ryu::Buffer::new();
    Ok(buffer.format_finite(value).to_string())
}

pub(crate) fn decode_binding_key(
    encoded_key: &str,
) -> Result<Zeroizing<Vec<u8>>, ClaimVerificationKeyError> {
    let Some(hex) = encoded_key.strip_prefix("hex:") else {
        return Err(ClaimVerificationKeyError::MissingPrefix);
    };
    if hex.len() < MIN_BINDING_KEY_HEX_LEN {
        return Err(ClaimVerificationKeyError::TooShort);
    }
    if hex.len() % 2 != 0 {
        return Err(ClaimVerificationKeyError::InvalidHex);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(Zeroizing::new(out))
}

fn decode_hex_nibble(byte: u8) -> Result<u8, ClaimVerificationKeyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ClaimVerificationKeyError::InvalidHex),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_keys_and_normalizes_numbers() {
        let value = json!({
            "z": -0.0,
            "a": [1.0, 2, true],
            "m": {"b": "x", "a": null}
        });
        assert_eq!(
            canonical_json(&value).expect("canonical json"),
            r#"{"a":[1,2,true],"m":{"a":null,"b":"x"},"z":0}"#
        );
    }

    #[test]
    fn hmac_has_stable_test_vector() {
        let hasher = ClaimVerificationHasher::from_encoded_key(
            "test-key".to_string(),
            "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("test key decodes");
        let claims = BTreeMap::from([
            ("birth_order".to_string(), json!(1.0)),
            ("date_of_birth".to_string(), json!("1992-04-18")),
            ("family_name".to_string(), json!("durand")),
        ]);
        let value = json!({
            "version": 1,
            "verification_id": "01J5K8M0000000000000000ABC",
            "dataset_id": "civil_registry",
            "entity": "birth_record",
            "ruleset": "identity-match-v1",
            "purpose": "benefits-eligibility",
            "claims": normalize_claims_for_hash(&claims),
            "evidence": []
        });
        assert_eq!(
            hasher.hmac_hex(&value).expect("hmac"),
            "hmac-sha256:b215ba274c0d4d925a7e99d46d12338fc23dcab4a2673146bdaa080526da2db0"
        );
    }
}
