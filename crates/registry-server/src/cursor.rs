// SPDX-License-Identifier: Apache-2.0
//! Registry Server-owned confidential keyset cursor codec.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::model::CompiledQueryKind;

const WIRE_VERSION: u8 = 1;
const ROOT_SECRET_MIN_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
const MAX_TOKEN_BYTES: usize = (1 + NONCE_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES) * 2;
const MAX_AGE_SECONDS: u64 = 86_400;
const CURSOR_AAD: &[u8] = b"registry-server-cursor-v1";
const AEAD_LABEL: &[u8] = b"registry-server-cursor-aead-key-v1";
const BINDING_LABEL: &[u8] = b"registry-server-cursor-binding-key-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct CursorCodec {
    aead_key: Zeroizing<[u8; KEY_BYTES]>,
    binding_key: Zeroizing<[u8; KEY_BYTES]>,
    max_age: Duration,
}

impl CursorCodec {
    pub fn new(root_secret: Zeroizing<Vec<u8>>, max_age: Duration) -> Result<Self, CursorError> {
        if root_secret.len() < ROOT_SECRET_MIN_BYTES
            || max_age.is_zero()
            || max_age.as_secs() > MAX_AGE_SECONDS
        {
            return Err(CursorError::Configuration);
        }
        Ok(Self {
            aead_key: derive_key(root_secret.as_slice(), AEAD_LABEL)?,
            binding_key: derive_key(root_secret.as_slice(), BINDING_LABEL)?,
            max_age,
        })
    }

    pub fn encode(&self, payload: &CursorPayload) -> Result<String, CursorError> {
        if payload.version != WIRE_VERSION || payload.expires_at_unix_seconds > payload.max_expiry()
        {
            return Err(CursorError::Malformed);
        }
        let plaintext = serde_json::to_vec(payload).map_err(|_| CursorError::Malformed)?;
        if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
            return Err(CursorError::Malformed);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.aead_key.as_slice())
            .map_err(|_| CursorError::Configuration)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| CursorError::Configuration)?;
        let nonce = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: CURSOR_AAD,
                },
            )
            .map_err(|_| CursorError::Configuration)?;
        let mut envelope = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        envelope.push(WIRE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(envelope))
    }

    pub(crate) fn open_after_authorization(
        &self,
        token: &str,
        now_unix_seconds: u64,
        expected: impl FnOnce(&CursorPayload) -> Result<CursorBinding, CursorError>,
    ) -> Result<CursorPayload, CursorError> {
        let payload = self.decode(token, now_unix_seconds)?;
        if payload.binding != expected(&payload)? {
            return Err(CursorError::Mismatch);
        }
        Ok(payload)
    }

    fn decode(&self, token: &str, now_unix_seconds: u64) -> Result<CursorPayload, CursorError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(CursorError::Invalid);
        }
        let envelope = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CursorError::Invalid)?;
        if envelope.len() <= 1 + NONCE_BYTES + TAG_BYTES
            || envelope.len() > 1 + NONCE_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES
            || envelope[0] != WIRE_VERSION
        {
            return Err(CursorError::Invalid);
        }
        let (nonce, ciphertext) = envelope[1..].split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| CursorError::Invalid)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.aead_key.as_slice())
            .map_err(|_| CursorError::Configuration)?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: CURSOR_AAD,
                },
            )
            .map_err(|_| CursorError::Invalid)?;
        if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
            return Err(CursorError::Invalid);
        }
        let payload: CursorPayload =
            serde_json::from_slice(&plaintext).map_err(|_| CursorError::Invalid)?;
        if payload.version != WIRE_VERSION {
            return Err(CursorError::Invalid);
        }
        if payload
            .issued_at_unix_seconds
            .checked_add(self.max_age.as_secs())
            .filter(|max| payload.expires_at_unix_seconds <= *max)
            .is_none()
        {
            return Err(CursorError::Invalid);
        }
        if payload.expires_at_unix_seconds <= now_unix_seconds {
            return Err(CursorError::Expired);
        }
        Ok(payload)
    }

    pub fn new_payload(
        &self,
        issued_at_unix_seconds: u64,
        binding: CursorBinding,
        query: CursorQuery,
        continuation: CursorContinuation,
    ) -> Result<CursorPayload, CursorError> {
        let expires_at_unix_seconds = issued_at_unix_seconds
            .checked_add(self.max_age.as_secs())
            .ok_or(CursorError::Configuration)?;
        Ok(CursorPayload {
            version: WIRE_VERSION,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            binding,
            query,
            continuation,
        })
    }

    pub fn binding_digest(
        &self,
        domain: &'static [u8],
        value: &Value,
    ) -> Result<String, CursorError> {
        let bytes = canonicalize_json(value).map_err(|_| CursorError::Malformed)?;
        self.binding_digest_bytes(domain, &bytes)
    }

    pub fn binding_digest_bytes(
        &self,
        domain: &'static [u8],
        value: &[u8],
    ) -> Result<String, CursorError> {
        let mut mac = HmacSha256::new_from_slice(self.binding_key.as_slice())
            .map_err(|_| CursorError::Configuration)?;
        mac.update(domain);
        mac.update(&[0]);
        mac.update(value);
        Ok(format!(
            "hmac-sha256:{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }
}

impl fmt::Debug for CursorCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorCodec")
            .field("aead_key", &"<redacted>")
            .field("binding_key", &"<redacted>")
            .field("max_age", &self.max_age)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorPayload {
    pub(crate) version: u8,
    pub(crate) issued_at_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) binding: CursorBinding,
    pub(crate) query: CursorQuery,
    pub(crate) continuation: CursorContinuation,
}

impl CursorPayload {
    fn max_expiry(&self) -> u64 {
        self.issued_at_unix_seconds.saturating_add(MAX_AGE_SECONDS)
    }
}

impl fmt::Debug for CursorPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorPayload")
            .field("version", &self.version)
            .field("issued_at_unix_seconds", &self.issued_at_unix_seconds)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("binding", &self.binding)
            .field("query", &"<redacted>")
            .field("continuation", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorBinding {
    pub(crate) package_revision: String,
    pub(crate) schema_fingerprint: String,
    pub(crate) registry_revision: String,
    pub(crate) route_id: String,
    pub(crate) query_operation_id: String,
    pub(crate) query_kind: CompiledQueryKind,
    pub(crate) selected_profile: String,
    pub(crate) principal_reference: Option<String>,
    pub(crate) purpose_reference: Option<String>,
    pub(crate) row_boundary_reference: String,
    pub(crate) projection_reference: String,
    pub(crate) query_reference: String,
    pub(crate) sort_reference: String,
    pub(crate) page_size: u16,
    pub(crate) temporal_instant: Option<String>,
    pub(crate) selected_fields: Vec<String>,
}

impl fmt::Debug for CursorBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorBinding")
            .field("package_revision", &self.package_revision)
            .field("schema_fingerprint", &self.schema_fingerprint)
            .field("registry_revision", &self.registry_revision)
            .field("route_id", &self.route_id)
            .field("query_operation_id", &self.query_operation_id)
            .field("query_kind", &self.query_kind)
            .field("selected_profile", &self.selected_profile)
            .field(
                "principal_reference",
                &self.principal_reference.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "purpose_reference",
                &self.purpose_reference.as_ref().map(|_| "<redacted>"),
            )
            .field("row_boundary_reference", &"<redacted>")
            .field("projection_reference", &"<redacted>")
            .field("query_reference", &"<redacted>")
            .field("sort_reference", &"<redacted>")
            .field("page_size", &self.page_size)
            .field(
                "temporal_instant",
                &self.temporal_instant.as_ref().map(|_| "<redacted>"),
            )
            .field("selected_fields", &self.selected_fields)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorQuery {
    pub(crate) filters: Vec<CursorFilter>,
    pub(crate) sort: Option<String>,
}

impl fmt::Debug for CursorQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorQuery(<redacted>)")
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorFilter {
    pub(crate) field: String,
    pub(crate) operator: String,
    pub(crate) values: Vec<String>,
}

impl fmt::Debug for CursorFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorFilter")
            .field("field", &self.field)
            .field("operator", &self.operator)
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CursorContinuation {
    pub(crate) last_record_id: String,
    pub(crate) sort_value: Option<String>,
}

impl fmt::Debug for CursorContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorContinuation(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CursorError {
    #[error("cursor configuration is invalid")]
    Configuration,
    #[error("cursor is malformed")]
    Malformed,
    #[error("cursor is invalid")]
    Invalid,
    #[error("cursor is expired")]
    Expired,
    #[error("cursor does not match this request")]
    Mismatch,
}

pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn derive_key(secret: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>, CursorError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| CursorError::Configuration)?;
    mac.update(label);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> CursorCodec {
        CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(60))
            .expect("cursor codec accepts strong test secret")
    }

    fn binding() -> CursorBinding {
        CursorBinding {
            package_revision: "package-a".to_owned(),
            schema_fingerprint: "schema-a".to_owned(),
            registry_revision: "registry-a".to_owned(),
            route_id: "records.asset.list".to_owned(),
            query_operation_id: "records.asset.operator.list".to_owned(),
            query_kind: CompiledQueryKind::List,
            selected_profile: "operator".to_owned(),
            principal_reference: Some("hmac-sha256:principal".to_owned()),
            purpose_reference: Some("hmac-sha256:purpose".to_owned()),
            row_boundary_reference: "hmac-sha256:row-boundary".to_owned(),
            projection_reference: "hmac-sha256:projection".to_owned(),
            query_reference: "hmac-sha256:query".to_owned(),
            sort_reference: "hmac-sha256:sort".to_owned(),
            page_size: 50,
            temporal_instant: Some("2026-01-01T00:00:00Z".to_owned()),
            selected_fields: vec!["label".to_owned()],
        }
    }

    fn payload() -> CursorPayload {
        CursorPayload {
            version: WIRE_VERSION,
            issued_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 1_060,
            binding: binding(),
            query: CursorQuery {
                filters: vec![CursorFilter {
                    field: "label".to_owned(),
                    operator: "prefix".to_owned(),
                    values: vec!["al".to_owned()],
                }],
                sort: Some("label".to_owned()),
            },
            continuation: CursorContinuation {
                last_record_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                sort_value: Some("alpha".to_owned()),
            },
        }
    }

    #[test]
    fn cursor_codec_conceals_payload_and_uses_fresh_nonces() {
        let codec = codec();
        let payload = payload();
        let first = codec.encode(&payload).expect("first cursor encodes");
        let second = codec.encode(&payload).expect("second cursor encodes");
        assert_ne!(first, second);
        for token in [&first, &second] {
            assert!(!token.contains("package-a"));
            assert!(!token.contains("principal"));
            let envelope = URL_SAFE_NO_PAD.decode(token).expect("cursor is base64url");
            let envelope_text = String::from_utf8_lossy(&envelope);
            assert!(!envelope_text.contains("package-a"));
            assert!(!envelope_text.contains("principal"));
            assert!(!envelope_text.contains("alpha"));
            assert_eq!(codec.decode(token, 1_001).expect("cursor decodes"), payload);
        }
    }

    #[test]
    fn cursor_codec_refuses_tamper_expiry_and_size_bounds() {
        assert!(CursorCodec::new(Zeroizing::new(vec![0x51; 31]), Duration::from_secs(60)).is_err());
        assert!(
            CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(86_401)).is_err()
        );
        let codec = codec();
        let token = codec.encode(&payload()).expect("cursor encodes");
        let mut tampered = token.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("base64url remains UTF-8");
        assert!(matches!(
            codec.decode(&tampered, 1_001),
            Err(CursorError::Invalid)
        ));
        let expired = codec.encode(&payload()).expect("cursor encodes");
        assert!(matches!(
            codec.decode(&expired, 1_061),
            Err(CursorError::Expired)
        ));

        let mut too_large = payload();
        too_large.continuation.sort_value = Some("x".repeat(MAX_PAYLOAD_BYTES));
        assert!(matches!(
            codec.encode(&too_large),
            Err(CursorError::Malformed)
        ));
        assert!(matches!(
            codec.decode(&"A".repeat(MAX_TOKEN_BYTES + 1), 1),
            Err(CursorError::Invalid)
        ));
    }

    #[test]
    fn cursor_binding_mismatch_cases_are_separate_and_value_free() {
        let codec = codec();
        let expected = binding();
        let token = codec.encode(&payload()).expect("cursor encodes");
        let cases = [
            {
                let mut value = expected.clone();
                value.package_revision = "package-b".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.schema_fingerprint = "schema-b".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.registry_revision = "registry-b".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.route_id = "records.asset.current".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.query_operation_id = "records.asset.operator.current".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.selected_profile = "public".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.principal_reference = Some("hmac-sha256:other-principal".to_owned());
                value
            },
            {
                let mut value = expected.clone();
                value.purpose_reference = None;
                value
            },
            {
                let mut value = expected.clone();
                value.row_boundary_reference = "hmac-sha256:other-row".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.projection_reference = "hmac-sha256:other-projection".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.query_reference = "hmac-sha256:other-query".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.sort_reference = "hmac-sha256:other-sort".to_owned();
                value
            },
            {
                let mut value = expected.clone();
                value.page_size = 51;
                value
            },
            {
                let mut value = expected.clone();
                value.temporal_instant = Some("2026-01-02T00:00:00Z".to_owned());
                value
            },
        ];
        for actual in cases {
            assert!(matches!(
                codec.open_after_authorization(&token, 1_001, |_| Ok(actual)),
                Err(CursorError::Mismatch)
            ));
        }
        assert_eq!(format!("{:?}", CursorError::Mismatch), "Mismatch");
        let opened = codec
            .open_after_authorization(&token, 1_001, |_| Ok(expected))
            .expect("matching authorized binding opens cursor");
        assert_eq!(opened.continuation.sort_value.as_deref(), Some("alpha"));
    }
}
