//! Single-use enforcement for client assertion `jti` values.
//!
//! A captured client assertion is a bearer credential until it expires. The
//! cache remembers every accepted `jti` until its own expiry, so a captured
//! assertion buys an attacker nothing.

use std::{collections::HashMap, sync::Mutex};

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReplayError {
    #[error("the assertion identifier has already been used")]
    AlreadyUsed,
    #[error("the replay cache is saturated")]
    Saturated,
    #[error("the replay cache is poisoned")]
    Poisoned,
}

/// A bounded set of assertion identifiers that have already been spent.
#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    entries: Mutex<HashMap<String, i64>>,
}

impl ReplayCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Record `jti` as spent until `expires_at`.
    ///
    /// Saturation fails closed rather than evicting a live entry. Evicting the
    /// oldest entry would let a caller flush the cache with fresh assertions
    /// and then replay the one it evicted, which is precisely what this cache
    /// exists to prevent. Only clients that already passed signature
    /// verification can reach this code, so the failure is bounded to
    /// authenticated misbehaviour and is visible to operators.
    pub fn remember(&self, jti: &str, expires_at: i64, now: i64) -> Result<(), ReplayError> {
        let mut entries = self.entries.lock().map_err(|_| ReplayError::Poisoned)?;
        entries.retain(|_, entry_expiry| *entry_expiry > now);
        if entries.contains_key(jti) {
            return Err(ReplayError::AlreadyUsed);
        }
        if entries.len() >= self.capacity {
            return Err(ReplayError::Saturated);
        }
        entries.insert(jti.to_owned(), expires_at);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_identifier_is_accepted_once_and_then_refused() {
        let cache = ReplayCache::new(16);
        assert_eq!(cache.remember("jti-1", 100, 0), Ok(()));
        assert_eq!(
            cache.remember("jti-1", 100, 0),
            Err(ReplayError::AlreadyUsed)
        );
    }

    #[test]
    fn distinct_identifiers_do_not_collide() {
        let cache = ReplayCache::new(16);
        assert_eq!(cache.remember("jti-1", 100, 0), Ok(()));
        assert_eq!(cache.remember("jti-2", 100, 0), Ok(()));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn entries_are_pruned_once_their_own_expiry_passes() {
        let cache = ReplayCache::new(16);
        assert_eq!(cache.remember("jti-1", 100, 0), Ok(()));
        // At 101 the assertion is expired anyway, so forgetting it is safe and
        // the slot is reclaimed.
        assert_eq!(cache.remember("jti-2", 200, 101), Ok(()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn saturation_fails_closed_instead_of_evicting_a_live_entry() {
        let cache = ReplayCache::new(2);
        assert_eq!(cache.remember("jti-1", 100, 0), Ok(()));
        assert_eq!(cache.remember("jti-2", 100, 0), Ok(()));
        assert_eq!(cache.remember("jti-3", 100, 0), Err(ReplayError::Saturated));
        // The entry an attacker would have wanted evicted is still remembered.
        assert_eq!(
            cache.remember("jti-1", 100, 0),
            Err(ReplayError::AlreadyUsed)
        );
    }
}
