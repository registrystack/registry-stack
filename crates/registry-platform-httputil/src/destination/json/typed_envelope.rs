// SPDX-License-Identifier: Apache-2.0
//! Opaque strict-JSON verification for public typed-hash envelopes.

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_crypto::domain_separated_sha256;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::destination::{BoundedDestinationBody, DataDestinationBody};

use super::preflight::{preflight_json, JsonPreflightError};

const MAX_DOMAIN_BYTES: usize = 128;
const MAX_HASH_LABEL_BYTES: usize = 71;

/// Hash-only evidence released from a strict public-contract envelope.
///
/// The parsed document and opaque response bytes never leave the platform
/// decoder. Consumers can compare these labels with an independently compiled
/// pin without gaining a general registry-response inspection capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedHashEnvelope {
    advertised_hash: String,
    computed_hash: String,
}

/// Strict typed-hash evidence paired with one caller-owned closed contract.
///
/// The opaque destination body and its raw bytes remain inside the platform
/// decoder. Callers receive only a type that they explicitly chose and whose
/// deserializer is responsible for enforcing its closed semantic contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTypedHashEnvelope<T> {
    advertised_hash: String,
    computed_hash: String,
    contract: T,
}

impl<T> DecodedTypedHashEnvelope<T> {
    #[must_use]
    pub fn advertised_hash(&self) -> &str {
        &self.advertised_hash
    }

    #[must_use]
    pub fn computed_hash(&self) -> &str {
        &self.computed_hash
    }

    /// Consume the verified envelope and release only the closed typed value.
    #[must_use]
    pub fn into_contract(self) -> T {
        self.contract
    }
}

impl TypedHashEnvelope {
    #[must_use]
    pub fn advertised_hash(&self) -> &str {
        &self.advertised_hash
    }

    #[must_use]
    pub fn computed_hash(&self) -> &str {
        &self.computed_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TypedHashEnvelopeError {
    #[error("typed-hash envelope domain is invalid")]
    InvalidDomain,
    #[error("typed-hash envelope is not strict bounded JSON")]
    InvalidJson,
    #[error("typed-hash envelope has an invalid closed shape")]
    InvalidEnvelope,
    #[error("typed-hash envelope cannot be canonicalized")]
    Canonicalization,
    #[error("typed-hash envelope contract does not match the requested closed type")]
    InvalidContract,
}

/// Consume a bounded data body containing exactly
/// `{ "contract_hash": ..., "contract": <object> }` and release only its
/// advertised and computed typed hashes.
pub fn decode_typed_hash_envelope(
    body: DataDestinationBody,
    domain: &'static [u8],
) -> Result<TypedHashEnvelope, TypedHashEnvelopeError> {
    let envelope = decode_typed_hash_envelope_as::<serde_json::Value>(body, domain)?;
    Ok(TypedHashEnvelope {
        advertised_hash: envelope.advertised_hash,
        computed_hash: envelope.computed_hash,
    })
}

/// Consume a bounded strict envelope and decode its contract into one closed
/// caller-selected type after computing the hash from the canonical object.
///
/// This is deliberately not a raw-byte escape hatch. A consumer that needs to
/// inspect the contract must provide an independently validated serde model.
pub fn decode_typed_hash_envelope_as<T: DeserializeOwned>(
    body: DataDestinationBody,
    domain: &'static [u8],
) -> Result<DecodedTypedHashEnvelope<T>, TypedHashEnvelopeError> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_BYTES
        || domain.last() != Some(&0)
        || domain[..domain.len() - 1]
            .iter()
            .any(|byte| !byte.is_ascii_graphic())
    {
        return Err(TypedHashEnvelopeError::InvalidDomain);
    }
    let BoundedDestinationBody { bytes, slot: _ } = body;
    preflight_json(bytes.as_slice(), 32_768, 32).map_err(|error| match error {
        JsonPreflightError::InvalidJson | JsonPreflightError::ContractLimitExceeded => {
            TypedHashEnvelopeError::InvalidJson
        }
    })?;
    let mut parsed =
        parse_json_strict(bytes.as_slice()).map_err(|_| TypedHashEnvelopeError::InvalidJson)?;
    drop(bytes);
    let object = parsed
        .as_object_mut()
        .ok_or(TypedHashEnvelopeError::InvalidEnvelope)?;
    if object.len() != 2
        || !object.contains_key("contract_hash")
        || !object.contains_key("contract")
    {
        return Err(TypedHashEnvelopeError::InvalidEnvelope);
    }
    let advertised_hash = object
        .remove("contract_hash")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .filter(|value| valid_hash_label(value))
        .ok_or(TypedHashEnvelopeError::InvalidEnvelope)?;
    let contract = object
        .remove("contract")
        .filter(serde_json::Value::is_object)
        .ok_or(TypedHashEnvelopeError::InvalidEnvelope)?;
    let canonical =
        canonicalize_json(&contract).map_err(|_| TypedHashEnvelopeError::Canonicalization)?;
    let computed_hash = hash_label(domain_separated_sha256(domain, &canonical));
    let contract =
        serde_json::from_value(contract).map_err(|_| TypedHashEnvelopeError::InvalidContract)?;
    Ok(DecodedTypedHashEnvelope {
        advertised_hash,
        computed_hash,
        contract,
    })
}

fn valid_hash_label(value: &str) -> bool {
    value.len() == MAX_HASH_LABEL_BYTES
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn hash_label(digest: [u8; 32]) -> String {
    let mut label = String::with_capacity(MAX_HASH_LABEL_BYTES);
    label.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut label, "{byte:02x}").expect("writing to String cannot fail");
    }
    label
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::marker::PhantomData;
    use zeroize::Zeroizing;

    const DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";

    fn body(value: &str) -> DataDestinationBody {
        BoundedDestinationBody {
            bytes: Zeroizing::new(value.as_bytes().to_vec()),
            slot: PhantomData,
        }
    }

    #[test]
    fn releases_only_matching_hash_evidence() {
        let contract = serde_json::json!({"schema":"registry.relay.consultation-contract.v1"});
        let canonical = canonicalize_json(&contract).expect("canonical contract");
        let hash = hash_label(domain_separated_sha256(DOMAIN, &canonical));
        let envelope = decode_typed_hash_envelope(
            body(&serde_json::json!({"contract_hash":hash,"contract":contract}).to_string()),
            DOMAIN,
        )
        .expect("valid envelope");
        assert_eq!(envelope.advertised_hash(), hash);
        assert_eq!(envelope.computed_hash(), hash);
    }

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ClosedContract {
        schema: String,
    }

    #[test]
    fn releases_only_the_requested_closed_contract_type() {
        let contract = serde_json::json!({"schema":"registry.relay.consultation-contract.v1"});
        let canonical = canonicalize_json(&contract).expect("canonical contract");
        let hash = hash_label(domain_separated_sha256(DOMAIN, &canonical));
        let envelope = decode_typed_hash_envelope_as::<ClosedContract>(
            body(&serde_json::json!({"contract_hash":hash,"contract":contract}).to_string()),
            DOMAIN,
        )
        .expect("closed contract");

        assert_eq!(envelope.advertised_hash(), hash);
        assert_eq!(envelope.computed_hash(), hash);
        assert_eq!(
            envelope.into_contract(),
            ClosedContract {
                schema: "registry.relay.consultation-contract.v1".to_string()
            }
        );
    }

    #[test]
    fn typed_decode_rejects_contract_members_outside_the_closed_model() {
        let value = serde_json::json!({
            "contract_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "contract":{"schema":"registry.relay.consultation-contract.v1","extra":true}
        });
        assert_eq!(
            decode_typed_hash_envelope_as::<ClosedContract>(body(&value.to_string()), DOMAIN),
            Err(TypedHashEnvelopeError::InvalidContract)
        );
    }

    #[test]
    fn rejects_unknown_members_and_non_objects() {
        for value in [
            serde_json::json!({"contract_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","contract":{},"extra":true}),
            serde_json::json!({"contract_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","contract":"{}"}),
        ] {
            assert_eq!(
                decode_typed_hash_envelope(body(&value.to_string()), DOMAIN),
                Err(TypedHashEnvelopeError::InvalidEnvelope)
            );
        }
    }
}
