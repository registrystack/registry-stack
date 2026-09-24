// SPDX-License-Identifier: Apache-2.0

//! The reusable idempotency-key recipe.

use sha2::{Digest, Sha256};

/// The idempotency key for one attempt identity: the product's domain, then
/// each identity part prefixed by its length as a big-endian `u64`, digested
/// with SHA-256 and spelled `sha256:` plus lowercase hex.
///
/// The domain separates one product's keys from another's and must stay
/// stable for the life of retained work, because a changed domain changes
/// every future key. The length prefixes make the encoding injective, so no
/// two distinct part lists share an input. A product that puts the job
/// generation among its parts gets a key that is stable across retries of
/// one generation and changes on operator replay.
#[must_use]
pub fn idempotency_key(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut input =
        Vec::with_capacity(domain.len() + parts.iter().map(|part| part.len() + 8).sum::<usize>());
    input.extend_from_slice(domain);
    for part in parts {
        input.extend_from_slice(&(part.len() as u64).to_be_bytes());
        input.extend_from_slice(part);
    }
    format!("sha256:{}", hex::encode(Sha256::digest(input)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_digests_the_domain_and_length_prefixed_parts() {
        let mut expected = b"domain-v1".to_vec();
        expected.extend_from_slice(&3_u64.to_be_bytes());
        expected.extend_from_slice(b"one");
        expected.extend_from_slice(&0_u64.to_be_bytes());
        expected.extend_from_slice(&1_u64.to_be_bytes());
        expected.extend_from_slice(b"2");
        assert_eq!(
            idempotency_key(b"domain-v1", &[b"one", b"", b"2"]),
            format!("sha256:{}", hex::encode(Sha256::digest(expected)))
        );
    }

    #[test]
    fn the_length_prefixes_keep_part_boundaries_apart() {
        assert_ne!(
            idempotency_key(b"d", &[b"ab", b"c"]),
            idempotency_key(b"d", &[b"a", b"bc"])
        );
        assert_ne!(
            idempotency_key(b"d", &[b"abc"]),
            idempotency_key(b"d", &[b"abc", b""])
        );
    }

    #[test]
    fn the_domain_and_every_part_change_the_key() {
        let key = idempotency_key(b"domain-a", &[b"job", b"1"]);
        assert_ne!(key, idempotency_key(b"domain-b", &[b"job", b"1"]));
        assert_ne!(key, idempotency_key(b"domain-a", &[b"job", b"2"]));
        assert_eq!(key, idempotency_key(b"domain-a", &[b"job", b"1"]));
        assert!(key.starts_with("sha256:"));
        assert_eq!(key.len(), "sha256:".len() + 64);
    }
}
