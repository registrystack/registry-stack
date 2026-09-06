//! Single-use enforcement for client assertion `jti` values.
//!
//! A captured client assertion is a bearer credential until it expires. The
//! cache remembers every accepted `jti` until its own expiry, so a captured
//! assertion buys an attacker nothing.

use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
};

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
    entries: Mutex<ReplayEntries>,
}

#[derive(Debug, Default)]
struct ReplayEntries {
    identifiers: HashSet<Arc<str>>,
    /// One entry per remembered identifier, grouped by its exact expiry.
    /// Sharing the identifier avoids copying its bytes into the expiry index.
    expirations: BTreeMap<i64, Vec<Arc<str>>>,
}

impl ReplayCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(ReplayEntries::default()),
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
        // Inspect only expired buckets, so live replays and saturation do not
        // scan every remembered assertion while holding the shared mutex.
        while entries
            .expirations
            .first_key_value()
            .is_some_and(|(expiry, _)| *expiry <= now)
        {
            let (_, identifiers) = entries
                .expirations
                .pop_first()
                .expect("an expired bucket is present");
            if entries.expirations.is_empty() {
                // The last expired bucket covers every remaining identifier;
                // clearing it avoids rehashing the entire cohort for removal.
                entries.identifiers.clear();
            } else {
                for identifier in identifiers {
                    entries.identifiers.remove(identifier.as_ref());
                }
            }
        }
        if entries.identifiers.contains(jti) {
            return Err(ReplayError::AlreadyUsed);
        }
        if entries.identifiers.len() >= self.capacity {
            return Err(ReplayError::Saturated);
        }
        let identifier: Arc<str> = Arc::from(jti);
        entries.identifiers.insert(Arc::clone(&identifier));
        entries
            .expirations
            .entry(expires_at)
            .or_default()
            .push(identifier);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.identifiers.len())
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
    use std::{collections::HashMap, sync::Barrier, thread};

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

    #[test]
    fn expiry_order_is_independent_of_insertion_order() {
        let cache = ReplayCache::new(3);
        cache.remember("long", 300, 0).unwrap();
        cache.remember("short", 100, 0).unwrap();
        cache.remember("middle", 200, 0).unwrap();

        assert_eq!(
            cache.remember("fresh", 400, 99),
            Err(ReplayError::Saturated)
        );
        // Exact expiry reclaims the short entry, even though it arrived after
        // the long one. Reusing its identifier must acquire the fresh expiry.
        assert_eq!(cache.remember("short", 400, 100), Ok(()));
        assert_eq!(cache.remember("fresh", 500, 200), Ok(()));
        assert_eq!(
            cache.remember("short", 500, 300),
            Err(ReplayError::AlreadyUsed)
        );
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.remember("short", 500, 400), Ok(()));
    }

    #[test]
    fn rejected_attempts_do_not_grow_state_or_change_an_expiry() {
        let cache = ReplayCache::new(1);
        cache.remember("spent", 100, 0).unwrap();
        for expiry in 101..1_000 {
            assert_eq!(
                cache.remember("spent", expiry, 0),
                Err(ReplayError::AlreadyUsed)
            );
            assert_eq!(
                cache.remember("unremembered", expiry, 0),
                Err(ReplayError::Saturated)
            );
        }
        {
            let entries = cache.entries.lock().unwrap();
            assert_eq!(entries.identifiers.len(), 1);
            assert_eq!(entries.expirations.len(), 1);
            assert_eq!(entries.expirations[&100].len(), 1);
        }
        assert_eq!(cache.remember("spent", 200, 100), Ok(()));
    }

    #[test]
    fn concurrent_calls_accept_an_identifier_exactly_once() {
        let cache = ReplayCache::new(16);
        let barrier = Barrier::new(16);
        let results = thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        cache.remember("shared", 100, 0)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(ReplayError::AlreadyUsed))
                .count(),
            15
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn mixed_expiries_and_clock_changes_match_the_full_scan_model() {
        for capacity in [0, 1, 16, 256] {
            let cache = ReplayCache::new(capacity);
            let mut model = HashMap::<String, i64>::new();
            let mut sequence = 1_u64;
            for step in 0..10_000 {
                // Deterministic synthetic requests include clock backsteps,
                // repeated identifiers, saturation, and already expired input.
                sequence = sequence
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let now = step / 40 + ((sequence >> 32) % 11) as i64 - 5;
                let expiry = now + ((sequence >> 16) % 63) as i64 - 1;
                let identifier = format!("jti-{}", (sequence >> 48) % 128);

                model.retain(|_, expiry| *expiry > now);
                let expected = if model.contains_key(&identifier) {
                    Err(ReplayError::AlreadyUsed)
                } else if model.len() >= capacity {
                    Err(ReplayError::Saturated)
                } else {
                    model.insert(identifier.clone(), expiry);
                    Ok(())
                };
                assert_eq!(cache.remember(&identifier, expiry, now), expected);
                assert_eq!(cache.len(), model.len());

                let entries = cache.entries.lock().unwrap();
                let indexed: usize = entries.expirations.values().map(Vec::len).sum();
                assert_eq!(indexed, model.len());
                assert!(indexed <= capacity);
            }
        }
    }
}
