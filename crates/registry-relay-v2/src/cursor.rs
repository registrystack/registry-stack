// SPDX-License-Identifier: Apache-2.0
//! Client-opaque, confidential and integrity-protected keyset cursors.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const CURSOR_VERSION: u8 = 2;
const MAX_CURSOR_BYTES: usize = 8 * 1024;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ENVELOPE_OVERHEAD: usize = 1 + NONCE_BYTES + TAG_BYTES;
const CURSOR_AAD: &[u8] = b"registry-relay-v2-cursor-v2";

type HmacSha256 = Hmac<Sha256>;

/// All request properties which must stay fixed across a keyset page chain.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CursorPayload {
    pub version: u8,
    pub expires_at_unix_seconds: u64,
    pub contract_revision: String,
    pub source_revision: String,
    pub operation: String,
    pub representation: String,
    pub disclosure_profile: String,
    pub transforms_digest: String,
    pub filters_digest: String,
    pub selected_fields_digest: String,
    pub authorization_digest: String,
    pub order_digest: String,
    pub last_record_identifier: String,
    #[serde(default)]
    pub page_size: u32,
    #[serde(default)]
    pub filters: BTreeMap<String, CursorValue>,
    #[serde(default)]
    pub selected_fields: Vec<String>,
    #[serde(default)]
    pub last_order_values: Vec<CursorValue>,
}

/// Closed scalar set carried by a cursor. Collection filters are non-personal
/// and exact-match-only; row authority remains represented solely by its
/// digest and is freshly derived from the verified token on every page.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CursorValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorBindings {
    pub representation: String,
    pub disclosure_profile: String,
    pub transforms_digest: String,
    pub filters_digest: String,
    pub selected_fields_digest: String,
    pub authorization_digest: String,
    pub order_digest: String,
    pub last_record_identifier: String,
}

impl CursorPayload {
    #[must_use]
    pub fn new(
        expires_at_unix_seconds: u64,
        contract_revision: String,
        source_revision: String,
        operation: String,
        bindings: CursorBindings,
    ) -> Self {
        Self {
            version: CURSOR_VERSION,
            expires_at_unix_seconds,
            contract_revision,
            source_revision,
            operation,
            representation: bindings.representation,
            disclosure_profile: bindings.disclosure_profile,
            transforms_digest: bindings.transforms_digest,
            filters_digest: bindings.filters_digest,
            selected_fields_digest: bindings.selected_fields_digest,
            authorization_digest: bindings.authorization_digest,
            order_digest: bindings.order_digest,
            last_record_identifier: bindings.last_record_identifier,
            page_size: 0,
            filters: BTreeMap::new(),
            selected_fields: Vec::new(),
            last_order_values: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_query_context(
        mut self,
        page_size: u32,
        filters: BTreeMap<String, CursorValue>,
        selected_fields: Vec<String>,
        last_order_values: Vec<CursorValue>,
    ) -> Self {
        self.page_size = page_size;
        self.filters = filters;
        self.selected_fields = selected_fields;
        self.last_order_values = last_order_values;
        self
    }
}

/// Cursor protection key. `Debug` intentionally cannot expose key material.
pub struct CursorKey(Zeroizing<[u8; KEY_BYTES]>);

impl CursorKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CursorError> {
        if bytes.len() < KEY_BYTES {
            return Err(CursorError::Configuration);
        }
        let bytes = Zeroizing::new(bytes);
        let mut derivation =
            HmacSha256::new_from_slice(bytes.as_slice()).map_err(|_| CursorError::Configuration)?;
        derivation.update(b"registry-relay-v2-cursor-key-v2");
        let derived: [u8; KEY_BYTES] = derivation.finalize().into_bytes().into();
        Ok(Self(Zeroizing::new(derived)))
    }

    /// Domain-separated binding used for authorization and query-context
    /// commitments embedded in a cursor.
    pub fn binding_digest(&self, domain: &[u8], value: &[u8]) -> Result<String, CursorError> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_slice())
            .map_err(|_| CursorError::Configuration)?;
        mac.update(b"registry-relay-v2-cursor-binding-v1\0");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(value);
        Ok(format!(
            "hmac-sha256:{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }
}

impl fmt::Debug for CursorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CursorError {
    #[error("cursor configuration is invalid")]
    Configuration,
    #[error("cursor is malformed")]
    Malformed,
    #[error("cursor protection is invalid")]
    Integrity,
    #[error("cursor is expired")]
    Expired,
    #[error("cursor does not match this request")]
    Mismatch,
}

pub fn encode(key: &CursorKey, payload: &CursorPayload) -> Result<String, CursorError> {
    let plaintext = serde_json::to_vec(payload).map_err(|_| CursorError::Malformed)?;
    if plaintext.is_empty() || plaintext.len() > MAX_CURSOR_BYTES {
        return Err(CursorError::Malformed);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_slice())
        .map_err(|_| CursorError::Configuration)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| CursorError::Configuration)?;
    let nonce_value = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: plaintext.as_slice(),
                aad: CURSOR_AAD,
            },
        )
        .map_err(|_| CursorError::Configuration)?;
    let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    envelope.push(CURSOR_VERSION);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(envelope))
}

pub fn decode(
    key: &CursorKey,
    encoded: &str,
    now_unix_seconds: u64,
) -> Result<CursorPayload, CursorError> {
    if encoded.is_empty() || encoded.len() > (MAX_CURSOR_BYTES + ENVELOPE_OVERHEAD) * 2 {
        return Err(CursorError::Malformed);
    }
    let envelope = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CursorError::Malformed)?;
    if envelope.len() <= ENVELOPE_OVERHEAD
        || envelope.len() > MAX_CURSOR_BYTES + ENVELOPE_OVERHEAD
        || envelope[0] != CURSOR_VERSION
    {
        return Err(CursorError::Malformed);
    }
    let (nonce, ciphertext) = envelope[1..].split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| CursorError::Malformed)?;
    let nonce = XNonce::from(nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_slice())
        .map_err(|_| CursorError::Configuration)?;
    let payload_bytes = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: CURSOR_AAD,
            },
        )
        .map_err(|_| CursorError::Integrity)?;
    let payload: CursorPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| CursorError::Malformed)?;
    if payload.version != CURSOR_VERSION {
        return Err(CursorError::Malformed);
    }
    if payload.expires_at_unix_seconds <= now_unix_seconds {
        return Err(CursorError::Expired);
    }
    Ok(payload)
}

/// Compare all request-bound fields except the last keyset value.
pub fn require_same_request(
    cursor: &CursorPayload,
    request: &CursorPayload,
) -> Result<(), CursorError> {
    if cursor.contract_revision != request.contract_revision
        || cursor.source_revision != request.source_revision
        || cursor.operation != request.operation
        || cursor.representation != request.representation
        || cursor.disclosure_profile != request.disclosure_profile
        || cursor.transforms_digest != request.transforms_digest
        || cursor.filters_digest != request.filters_digest
        || cursor.selected_fields_digest != request.selected_fields_digest
        || cursor.authorization_digest != request.authorization_digest
        || cursor.order_digest != request.order_digest
    {
        return Err(CursorError::Mismatch);
    }
    Ok(())
}

#[must_use]
pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> CursorPayload {
        CursorPayload::new(
            100,
            "sha256:contract".to_owned(),
            "sha256:source".to_owned(),
            "resource.list".to_owned(),
            CursorBindings {
                representation: "public".to_owned(),
                disclosure_profile: "public".to_owned(),
                transforms_digest: "sha256:transforms".to_owned(),
                filters_digest: "sha256:filters".to_owned(),
                selected_fields_digest: "sha256:fields".to_owned(),
                authorization_digest: "sha256:authorization".to_owned(),
                order_digest: "sha256:order".to_owned(),
                last_record_identifier: "record-1".to_owned(),
            },
        )
    }

    #[test]
    fn cursor_conceals_order_values_and_refuses_tampering() {
        let key = CursorKey::new(vec![7; 32]).expect("key is sufficient");
        let mut protected = payload();
        protected.last_record_identifier = "protected-record-id-canary".to_owned();
        protected.filters.insert(
            "status".to_owned(),
            CursorValue::String("protected-filter-value-canary".to_owned()),
        );
        protected.selected_fields = vec!["omitted-field-name-canary".to_owned()];
        protected.last_order_values = vec![CursorValue::String(
            "protected-order-value-canary".to_owned(),
        )];
        let encoded = encode(&key, &protected).expect("cursor encodes");
        let mut envelope = URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("cursor is base64url");
        for canary in [
            b"protected-record-id-canary".as_slice(),
            b"protected-filter-value-canary".as_slice(),
            b"omitted-field-name-canary".as_slice(),
            b"protected-order-value-canary".as_slice(),
        ] {
            assert!(!envelope
                .windows(canary.len())
                .any(|window| window == canary));
        }
        assert_eq!(
            decode(&key, &encoded, 1).expect("cursor decrypts"),
            protected
        );
        let final_byte = envelope.len() - 1;
        envelope[final_byte] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(envelope);
        assert!(matches!(
            decode(&key, &tampered, 1),
            Err(CursorError::Integrity) | Err(CursorError::Malformed)
        ));
    }

    #[test]
    fn encrypting_the_same_cursor_twice_uses_distinct_nonces() {
        let key = CursorKey::new(vec![7; 32]).expect("key is sufficient");
        let first = encode(&key, &payload()).expect("first cursor encodes");
        let second = encode(&key, &payload()).expect("second cursor encodes");
        assert_ne!(first, second);
    }

    #[test]
    fn cursor_refuses_every_mismatched_request_binding_and_expiry() {
        let expected = payload();
        let mut mismatches = Vec::new();

        let mut request = payload();
        request.contract_revision = "sha256:other-contract".to_owned();
        mismatches.push(request);
        let mut request = payload();
        request.source_revision = "sha256:other-source".to_owned();
        mismatches.push(request);
        let mut request = payload();
        request.operation = "other.list".to_owned();
        mismatches.push(request);
        let mut request = payload();
        request.filters_digest = "sha256:other-filters".to_owned();
        mismatches.push(request);
        let mut request = payload();
        request.selected_fields_digest = "sha256:other-fields".to_owned();
        mismatches.push(request);
        let mut request = payload();
        request.authorization_digest = "sha256:other-authorization".to_owned();
        mismatches.push(request);
        let mut request = payload();
        request.order_digest = "sha256:other-order".to_owned();
        mismatches.push(request);

        for request in mismatches {
            assert_eq!(
                require_same_request(&expected, &request),
                Err(CursorError::Mismatch)
            );
        }

        let key = CursorKey::new(vec![7; 32]).expect("key is sufficient");
        let encoded = encode(&key, &expected).expect("cursor encodes");
        assert_eq!(decode(&key, &encoded, 100), Err(CursorError::Expired));
    }

    #[test]
    fn cursor_cannot_cross_representation_disclosure_or_transform_contexts() {
        let alterations: [fn(&mut CursorPayload); 3] = [
            |payload: &mut CursorPayload| payload.representation = "caseworker".to_owned(),
            |payload: &mut CursorPayload| {
                payload.disclosure_profile = "caseworker".to_owned();
            },
            |payload: &mut CursorPayload| {
                payload.transforms_digest = "sha256:other-transforms".to_owned();
            },
        ];
        for alter in alterations {
            let mut request = payload();
            alter(&mut request);
            assert_eq!(
                require_same_request(&payload(), &request),
                Err(CursorError::Mismatch)
            );
        }
    }
}
