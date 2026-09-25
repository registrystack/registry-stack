//! Generic in-memory keyed rate limiting.
//!
//! Two independent primitives share one shape: a caller presents an opaque
//! key (a pseudonym, never raw caller-controlled text) and gets back either
//! admission or a refusal.
//!
//! - [`token_bucket::TokenBucketLimiter`] is a smooth per-key request budget
//!   with burst: `requests per minute` refills a per-key bucket of size
//!   `burst`, and admission costs a caller-declared number of tokens. A
//!   refusal carries how long the caller should wait before the bucket can
//!   admit the same cost, so a caller can set `Retry-After`.
//! - [`fixed_window::FixedWindowCounter`] is a per-key ceiling on how many
//!   times an event may be recorded inside a rolling window, for budgets that
//!   should reset in one step rather than refill smoothly (for example,
//!   failed-attempt counters).
//!
//! Both primitives track keys in memory only: process-local, not shared
//! across replicas. Both cap the number of distinct keys they will track at
//! [`MAX_TRACKED_KEYS`] and prune stale entries before admitting a new key
//! past that cap, so an unbounded population of one-shot keys cannot grow
//! memory without bound. `tracked_key_count` on each type exists so a
//! deployment can publish that population as a metric.

pub mod fixed_window;
pub mod token_bucket;

/// Ceiling on distinct keys tracked by one limiter instance, independent of
/// key content. This bounds the population of tracked keys (for example, one
/// per distinct caller pseudonym), not the request volume any single key may
/// present, which each limiter's own configuration governs.
pub const MAX_TRACKED_KEYS: usize = 100_000;

/// Maximum byte length of an opaque limiter key.
pub const MAX_KEY_BYTES: usize = 256;

/// A limiter key failed validation: empty, too long, or containing
/// whitespace.
///
/// Keys are opaque pseudonyms a caller derives before presenting them here
/// (an audit pseudonym or similar), never raw caller-controlled text, so a
/// key that fails this check is a caller programming error rather than a
/// request the limiter can charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidKey;

pub(crate) fn validate_key(key: &str) -> Result<(), InvalidKey> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES || key.chars().any(char::is_whitespace) {
        return Err(InvalidKey);
    }
    Ok(())
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn empty_key_is_invalid() {
        assert_eq!(validate_key(""), Err(InvalidKey));
    }

    #[test]
    fn key_over_the_byte_ceiling_is_invalid() {
        let key = "a".repeat(MAX_KEY_BYTES + 1);
        assert_eq!(validate_key(&key), Err(InvalidKey));
    }

    #[test]
    fn key_at_the_byte_ceiling_is_valid() {
        let key = "a".repeat(MAX_KEY_BYTES);
        assert_eq!(validate_key(&key), Ok(()));
    }

    #[test]
    fn key_with_whitespace_is_invalid() {
        assert_eq!(validate_key("has space"), Err(InvalidKey));
        assert_eq!(validate_key("has\ttab"), Err(InvalidKey));
        assert_eq!(validate_key("has\nnewline"), Err(InvalidKey));
    }

    #[test]
    fn ordinary_pseudonym_key_is_valid() {
        assert_eq!(validate_key("stable-pseudonym-a"), Ok(()));
    }
}
