// SPDX-License-Identifier: Apache-2.0

//! Idempotency keys for registry writes.
//!
//! A chat host retries. The key for one write is a keyed hash of the citizen's
//! pseudonym, the tool, and the canonical request the gateway will send,
//! including the target it resolved itself, so a retried call replays the
//! registry's first answer and a different request can never collide with it.
//! A start adds its position in a chain of keys over the same values, so a
//! citizen whose earlier identical application closed is not replayed onto it.

use registry_breg_client::BRegIdempotencyKey;
use registry_platform_audit::AuditKeyHasher;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};

const PREFIX: &str = "bregmcp-v1-";

/// A value-free reason a key could not be derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the idempotency key could not be derived")]
pub(crate) struct IdempotencyError;

pub(crate) fn idempotency_key(
    hasher: &AuditKeyHasher,
    citizen_pseudonym: &str,
    tool: &str,
    request: &Value,
) -> Result<BRegIdempotencyKey, IdempotencyError> {
    let canonical = canonicalize_json(&json!({ "tool": tool, "request": request }))
        .map_err(|_| IdempotencyError)?;
    let canonical = String::from_utf8(canonical).map_err(|_| IdempotencyError)?;
    let digest = hasher.hash(&format!("idempotency:v1\n{citizen_pseudonym}\n{canonical}"));
    BRegIdempotencyKey::parse(format!("{PREFIX}{digest}")).map_err(|_| IdempotencyError)
}

#[cfg(test)]
mod tests {
    use registry_platform_audit::AuditProfile;
    use zeroize::Zeroizing;

    use super::*;

    fn hasher() -> AuditKeyHasher {
        AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![7; 32]))
            .expect("profile")
            .key_hasher()
    }

    fn key(citizen: &str, tool: &str, request: &Value) -> String {
        idempotency_key(&hasher(), citizen, tool, request)
            .expect("key")
            .as_str()
            .to_owned()
    }

    #[test]
    fn the_same_request_from_the_same_citizen_gets_the_same_key() {
        let request = json!({"b": 1, "a": "x"});
        let reordered = json!({"a": "x", "b": 1});
        assert_eq!(
            key("citizen-a", "start_application", &request),
            key("citizen-a", "start_application", &reordered)
        );
    }

    #[test]
    fn the_key_separates_citizens_tools_and_requests() {
        let request = json!({"a": "x"});
        let base = key("citizen-a", "start_application", &request);
        assert_ne!(base, key("citizen-b", "start_application", &request));
        assert_ne!(base, key("citizen-a", "update_application", &request));
        assert_ne!(
            base,
            key("citizen-a", "start_application", &json!({"a": "y"}))
        );
    }

    #[test]
    fn the_key_is_bounded_and_reveals_no_input() {
        let request = json!({"newAddressLine": "canary-address-value"});
        let key = key("canary-citizen", "start_application", &request);
        assert!(key.len() <= 256);
        assert!(key.starts_with(PREFIX));
        assert!(!key.contains("canary"));
    }
}
