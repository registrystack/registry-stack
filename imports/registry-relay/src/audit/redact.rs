// SPDX-License-Identifier: Apache-2.0
//! Reusable audit query redaction primitives.
//!
//! Sensitive field values are replaced with deterministic, field-bound
//! SHA-256 digests so subject-keyed audit lookup can match future
//! requests without storing raw PII.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const UNKEYED_HASH_PREFIX: &str = "sha256:";
const KEYED_HASH_PREFIX: &str = "hmac-sha256:";

/// Shared per-deploy secret used to HMAC sensitive audit values.
/// Stored behind `Arc` so cloning into per-request `QueryRedactor`s is
/// O(1). Heap bytes are not wrapped in `Zeroizing` because HMAC needs
/// stable read access for the full process lifetime; the secret is
/// loaded once at startup and never copied beyond this `Arc`.
pub type AuditHashSecret = Arc<[u8]>;

/// Generic secret-bearing parameter names. These are redacted without a
/// lookup hash because they are credentials, not subject keys.
const SECRET_PARAM_NAMES: &[&str] = &[
    "token",
    "key",
    "api_key",
    "apikey",
    "password",
    "secret",
    "authorization",
    "auth",
];

/// Redacts URL query parameters into the audit `query_params` shape.
///
/// When `secret` is `Some`, sensitive field values are HMAC-SHA256'd
/// with the per-deploy secret. When `None`, the redactor falls back to
/// an unkeyed domain-separated SHA-256: the resulting hashes are stable
/// across processes but offer no brute-force resistance against an
/// attacker who can enumerate the value space. The keyed path is the
/// production default; the unkeyed path exists for tests and for
/// callers who do not need brute-force resistance.
#[derive(Debug, Clone, Default)]
pub struct QueryRedactor {
    sensitive_fields: BTreeSet<String>,
    secret: Option<AuditHashSecret>,
}

impl QueryRedactor {
    #[must_use]
    pub fn new<I, S>(sensitive_fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            sensitive_fields: sensitive_fields.into_iter().map(Into::into).collect(),
            secret: None,
        }
    }

    #[must_use]
    pub fn with_secret<I, S>(secret: Option<AuditHashSecret>, sensitive_fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            sensitive_fields: sensitive_fields.into_iter().map(Into::into).collect(),
            secret,
        }
    }

    #[must_use]
    pub fn redact_query(&self, query: &str) -> Value {
        if query.is_empty() {
            return json!({});
        }

        let mut out = BTreeMap::new();
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = decode_query_component(raw_name);
            let value = decode_query_component(raw_value);
            let (field, op) = split_field_operator(&name);

            let entry = if is_secret_param_name(field) {
                json!({ "op": "redacted" })
            } else if self.sensitive_fields.contains(field) {
                json!({
                    "op": op,
                    "value_hash": sensitive_value_hash_keyed(self.secret.as_deref(), field, &value),
                })
            } else {
                json!({ "op": op })
            };

            out.insert(name, entry);
        }

        serde_json::to_value(out).unwrap_or_else(|_| json!({}))
    }
}

/// Unkeyed domain-separated SHA-256. Stable across processes; **no**
/// brute-force resistance. Kept as a thin wrapper for tests and for
/// callers that explicitly do not need keying. Production paths should
/// prefer [`sensitive_value_hash_keyed`].
#[must_use]
pub fn sensitive_value_hash(field: &str, value: &str) -> String {
    sensitive_value_hash_keyed(None, field, value)
}

/// HMAC-SHA256 of `field || \0 || value` under `secret`, or unkeyed
/// SHA-256 when `secret` is `None`. The keyed form closes the
/// rainbow-table risk on small-keyspace values (e.g. national IDs):
/// without the per-deploy secret, an attacker holding the audit log
/// cannot precompute hashes for guessed values.
#[must_use]
pub fn sensitive_value_hash_keyed(secret: Option<&[u8]>, field: &str, value: &str) -> String {
    match secret {
        Some(key) => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                .expect("HMAC-SHA256 accepts any key length");
            mac.update(field.as_bytes());
            mac.update(b"\0");
            mac.update(value.as_bytes());
            let tag = mac.finalize().into_bytes();
            format!("{KEYED_HASH_PREFIX}{}", hex_lower(&tag))
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(field.as_bytes());
            hasher.update(b"\0");
            hasher.update(value.as_bytes());
            format!("{UNKEYED_HASH_PREFIX}{}", hex_lower(&hasher.finalize()))
        }
    }
}

#[must_use]
pub fn redact_query_with_sensitive_fields<I, S>(query: &str, sensitive_fields: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    QueryRedactor::new(sensitive_fields).redact_query(query)
}

#[must_use]
pub fn redact_query_with_secret_and_fields<I, S>(
    secret: Option<AuditHashSecret>,
    query: &str,
    sensitive_fields: I,
) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    QueryRedactor::with_secret(secret, sensitive_fields).redact_query(query)
}

fn split_field_operator(name: &str) -> (&str, &str) {
    match name.rsplit_once('.') {
        Some((field, op)) if !field.is_empty() && !op.is_empty() => (field, op),
        _ => (name, "eq"),
    }
}

pub(crate) fn is_secret_param_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_PARAM_NAMES.iter().any(|secret| *secret == lower)
}

fn decode_query_component(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi << 4) | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
