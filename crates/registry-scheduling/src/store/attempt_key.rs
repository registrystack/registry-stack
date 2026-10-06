// SPDX-License-Identifier: Apache-2.0

//! The identity of an idempotency attempt.
//!
//! An attempt row is found and kept unique by a digest of its verified
//! caller, its command scope, and its key, never by the raw values. The raw
//! issuer, subject, and key stay on the row only while its receipt does: the
//! retention sweep clears them with the receipt, and the digest alone keeps
//! the key spent for that caller afterwards.

use sha2::{Digest as _, Sha256};

/// The domain the digest is computed in. A digest computed for another
/// purpose over the same values cannot collide with an attempt identity.
const ATTEMPT_KEY_DOMAIN: &str = "scheduling-idempotency-key-v1";

/// The digest an attempt is identified by: SHA-256 over the domain and the
/// verified issuer, subject, command scope, and idempotency key, each
/// prefixed by its byte length as a big-endian `u64` so no two different
/// tuples share one input. Rendered as `sha256:` and 64 lowercase hex digits.
///
/// Migration 11 computes the same digest in SQL for the rows it re-keys, so
/// a change here is a change to that migration as well.
pub fn attempt_key_reference(issuer: &str, subject: &str, scope: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [ATTEMPT_KEY_DOMAIN, issuer, subject, scope, key] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut rendered = String::with_capacity(7 + digest.len() * 2);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::attempt_key_reference;

    #[test]
    fn the_attempt_key_reference_is_a_length_prefixed_domain_digest() {
        assert_eq!(
            attempt_key_reference(
                "https://issuer.test",
                "subject-1",
                "appointment:create",
                "key-1"
            ),
            "sha256:d8dc523a999693e01f64ff59a6a1af6eb097ba608e0aa92ebb932405ec790118"
        );
        // The length prefixes keep a boundary moved between two parts from
        // naming the same attempt.
        assert_ne!(
            attempt_key_reference("issuer", "subject-a", "appointment:create", "b"),
            attempt_key_reference("issuer", "subject-", "appointment:create", "ab"),
        );
        // Each part is bound: another caller, scope, or key is another digest.
        let reference = attempt_key_reference("issuer", "subject", "hold:create", "key");
        assert_ne!(
            reference,
            attempt_key_reference("issuer", "other", "hold:create", "key")
        );
        assert_ne!(
            reference,
            attempt_key_reference("other", "subject", "hold:create", "key")
        );
        assert_ne!(
            reference,
            attempt_key_reference("issuer", "subject", "appointment:create", "key")
        );
        assert_ne!(
            reference,
            attempt_key_reference("issuer", "subject", "hold:create", "other")
        );
    }
}
