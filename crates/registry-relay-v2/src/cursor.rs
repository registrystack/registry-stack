// SPDX-License-Identifier: Apache-2.0
//! Opaque, integrity-protected keyset cursors.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const CURSOR_VERSION: u8 = 1;
const MAX_CURSOR_BYTES: usize = 8 * 1024;
const MAC_BYTES: usize = 32;

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

/// Cursor HMAC key. `Debug` intentionally cannot expose key material.
pub struct CursorKey(Zeroizing<Vec<u8>>);

impl CursorKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CursorError> {
        if bytes.len() < MAC_BYTES {
            return Err(CursorError::Configuration);
        }
        Ok(Self(Zeroizing::new(bytes)))
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
    #[error("cursor signature is invalid")]
    Integrity,
    #[error("cursor is expired")]
    Expired,
    #[error("cursor does not match this request")]
    Mismatch,
}

pub fn encode(key: &CursorKey, payload: &CursorPayload) -> Result<String, CursorError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| CursorError::Malformed)?;
    if encoded.is_empty() || encoded.len() > MAX_CURSOR_BYTES {
        return Err(CursorError::Malformed);
    }
    let mut mac =
        HmacSha256::new_from_slice(key.0.as_slice()).map_err(|_| CursorError::Configuration)?;
    mac.update(&encoded);
    let signature = mac.finalize().into_bytes();
    let mut envelope = Vec::with_capacity(encoded.len() + MAC_BYTES);
    envelope.extend_from_slice(&encoded);
    envelope.extend_from_slice(&signature);
    Ok(URL_SAFE_NO_PAD.encode(envelope))
}

pub fn decode(
    key: &CursorKey,
    encoded: &str,
    now_unix_seconds: u64,
) -> Result<CursorPayload, CursorError> {
    if encoded.is_empty() || encoded.len() > MAX_CURSOR_BYTES * 2 {
        return Err(CursorError::Malformed);
    }
    let envelope = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CursorError::Malformed)?;
    if envelope.len() <= MAC_BYTES || envelope.len() > MAX_CURSOR_BYTES + MAC_BYTES {
        return Err(CursorError::Malformed);
    }
    let (payload_bytes, supplied_signature) = envelope.split_at(envelope.len() - MAC_BYTES);
    let mut mac =
        HmacSha256::new_from_slice(key.0.as_slice()).map_err(|_| CursorError::Configuration)?;
    mac.update(payload_bytes);
    mac.verify_slice(supplied_signature)
        .map_err(|_| CursorError::Integrity)?;
    let payload: CursorPayload =
        serde_json::from_slice(payload_bytes).map_err(|_| CursorError::Malformed)?;
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
                filters_digest: "sha256:filters".to_owned(),
                selected_fields_digest: "sha256:fields".to_owned(),
                authorization_digest: "sha256:authorization".to_owned(),
                order_digest: "sha256:order".to_owned(),
                last_record_identifier: "record-1".to_owned(),
            },
        )
    }

    #[test]
    fn cursor_is_opaque_and_refuses_tampering() {
        let key = CursorKey::new(vec![7; 32]).expect("key is sufficient");
        let encoded = encode(&key, &payload()).expect("cursor encodes");
        assert!(!encoded.contains("record-1"));
        let mut tampered = encoded.into_bytes();
        let final_byte = tampered.len() - 1;
        tampered[final_byte] = if tampered[final_byte] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = String::from_utf8(tampered).expect("cursor stays text");
        assert!(matches!(
            decode(&key, &tampered, 1),
            Err(CursorError::Integrity) | Err(CursorError::Malformed)
        ));
    }

    #[test]
    fn cursor_cannot_cross_authorization_or_filter_contexts() {
        let mut request = payload();
        request.authorization_digest = "sha256:other".to_owned();
        assert_eq!(
            require_same_request(&payload(), &request),
            Err(CursorError::Mismatch)
        );
    }
}
