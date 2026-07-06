// SPDX-License-Identifier: Apache-2.0
//! Local, coarse, in-process throttle on repeated authentication failures
//! from a single client address.
//!
//! This is a backstop, not the primary defense: ingress rate limiting in
//! front of the relay is expected to absorb abusive traffic before it
//! reaches this process (see `deployment.evidence.ingress_rate_limit` and
//! the `relay.ingress.rate_limit_missing` finding). This throttle exists
//! for deployments that run without such a gateway, or want a second
//! layer scoped to the auth path specifically.
//!
//! The counter is a fixed window keyed by the resolved client address
//! string (the same trust-proxy-aware resolution the audit middleware
//! uses, via [`crate::net::resolve_remote_addr`]), mirroring the
//! structure of `registry-notary-server`'s self-attestation rate limiter.
//! The map is bounded so that a flood of spoofed addresses cannot grow it
//! without bound.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::AuthFailureThrottleConfig;

/// Hard cap on the number of distinct client addresses tracked at once.
/// Once at capacity, the entry with the oldest window start is evicted to
/// make room for a newly observed address. This bounds memory use under a
/// flood of spoofed source addresses; it does not need to be precise,
/// only bounded.
const MAX_TRACKED_ADDRESSES: usize = 10_000;

/// Outcome of a throttle check for a resolved client address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The address is under the failure limit for the current window.
    Allowed,
    /// The address has met or exceeded the failure limit for the current
    /// window. `retry_after_seconds` is the remaining time in the window,
    /// rounded up to at least one second.
    Throttled { retry_after_seconds: u64 },
}

#[derive(Debug, Clone, Copy)]
struct Counter {
    window_start: Instant,
    failures: u32,
}

impl Counter {
    fn in_window(&self, now: Instant, window: Duration) -> bool {
        now.duration_since(self.window_start) < window
    }
}

/// In-process fixed-window counter of authentication failures per client
/// address. Constructed only when `auth.failure_throttle.enabled` is
/// true; disabled deployments never allocate one, so their behavior is
/// unaffected by this feature.
pub struct AuthFailureThrottle {
    max_failures: u32,
    window: Duration,
    counters: Mutex<HashMap<String, Counter>>,
}

impl AuthFailureThrottle {
    /// Build a throttle from config, or `None` when disabled.
    #[must_use]
    pub fn new(config: &AuthFailureThrottleConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            max_failures: config.max_failures,
            window: Duration::from_secs(config.window_seconds),
            counters: Mutex::new(HashMap::new()),
        })
    }

    /// Check whether `key` (a resolved client address string) is
    /// currently over the failure limit. Does not itself record a
    /// failure; call [`Self::record_failure`] on authentication failure
    /// outcomes.
    #[must_use]
    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Decision {
        let mut counters = self.counters.lock().unwrap_or_else(|poisoned| {
            // A panicking holder cannot invalidate the counts already
            // recorded; recovering keeps the throttle serving decisions
            // instead of taking down the auth path.
            poisoned.into_inner()
        });
        prune_expired(&mut counters, now, self.window);
        match counters.get(key) {
            Some(counter) if counter.failures >= self.max_failures => {
                let elapsed = now.duration_since(counter.window_start);
                let remaining = self.window.saturating_sub(elapsed);
                Decision::Throttled {
                    retry_after_seconds: remaining.as_secs().max(1),
                }
            }
            _ => Decision::Allowed,
        }
    }

    /// Record an authentication failure for `key`, incrementing the
    /// current window's count (starting a new window if the previous one
    /// expired).
    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now());
    }

    fn record_failure_at(&self, key: &str, now: Instant) {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune_expired(&mut counters, now, self.window);
        if !counters.contains_key(key) && counters.len() >= MAX_TRACKED_ADDRESSES {
            evict_oldest(&mut counters);
        }
        let counter = counters.entry(key.to_string()).or_insert(Counter {
            window_start: now,
            failures: 0,
        });
        if !counter.in_window(now, self.window) {
            counter.window_start = now;
            counter.failures = 0;
        }
        counter.failures = counter.failures.saturating_add(1);
    }

    #[cfg(test)]
    fn tracked_addresses(&self) -> usize {
        self.counters.lock().unwrap().len()
    }
}

fn prune_expired(counters: &mut HashMap<String, Counter>, now: Instant, window: Duration) {
    counters.retain(|_, counter| counter.in_window(now, window));
}

/// Evict the entry with the oldest `window_start`. Used only when the map
/// is at capacity and a new address needs to be tracked; a linear scan is
/// acceptable since it only runs at the bound, not on every request.
fn evict_oldest(counters: &mut HashMap<String, Counter>) {
    let Some(oldest_key) = counters
        .iter()
        .min_by_key(|(_, counter)| counter.window_start)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    counters.remove(&oldest_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(max_failures: u32, window_seconds: u64) -> AuthFailureThrottleConfig {
        AuthFailureThrottleConfig {
            enabled: true,
            max_failures,
            window_seconds,
        }
    }

    #[test]
    fn disabled_config_yields_no_throttle() {
        let mut disabled = config(1, 60);
        disabled.enabled = false;
        assert!(AuthFailureThrottle::new(&disabled).is_none());
    }

    #[test]
    fn enabled_config_yields_a_throttle() {
        assert!(AuthFailureThrottle::new(&config(1, 60)).is_some());
    }

    #[test]
    fn allows_failures_under_the_limit() {
        let throttle = AuthFailureThrottle::new(&config(3, 60)).expect("enabled");
        let now = Instant::now();
        assert_eq!(throttle.check_at("1.2.3.4", now), Decision::Allowed);
        throttle.record_failure_at("1.2.3.4", now);
        assert_eq!(throttle.check_at("1.2.3.4", now), Decision::Allowed);
        throttle.record_failure_at("1.2.3.4", now);
        assert_eq!(throttle.check_at("1.2.3.4", now), Decision::Allowed);
    }

    #[test]
    fn throttles_once_failures_reach_the_limit() {
        let throttle = AuthFailureThrottle::new(&config(3, 60)).expect("enabled");
        let now = Instant::now();
        throttle.record_failure_at("1.2.3.4", now);
        throttle.record_failure_at("1.2.3.4", now);
        throttle.record_failure_at("1.2.3.4", now);
        match throttle.check_at("1.2.3.4", now) {
            Decision::Throttled {
                retry_after_seconds,
            } => {
                assert!(retry_after_seconds > 0 && retry_after_seconds <= 60);
            }
            Decision::Allowed => panic!("expected throttled decision at the limit"),
        }
    }

    #[test]
    fn window_expiry_clears_the_throttle() {
        let throttle = AuthFailureThrottle::new(&config(2, 10)).expect("enabled");
        let start = Instant::now();
        throttle.record_failure_at("1.2.3.4", start);
        throttle.record_failure_at("1.2.3.4", start);
        assert!(matches!(
            throttle.check_at("1.2.3.4", start),
            Decision::Throttled { .. }
        ));

        let after_window = start + Duration::from_secs(11);
        assert_eq!(
            throttle.check_at("1.2.3.4", after_window),
            Decision::Allowed,
            "a new window clears the prior failure count"
        );
    }

    #[test]
    fn different_addresses_are_tracked_independently() {
        let throttle = AuthFailureThrottle::new(&config(1, 60)).expect("enabled");
        let now = Instant::now();
        throttle.record_failure_at("1.2.3.4", now);
        assert!(matches!(
            throttle.check_at("1.2.3.4", now),
            Decision::Throttled { .. }
        ));
        assert_eq!(throttle.check_at("5.6.7.8", now), Decision::Allowed);
    }

    #[test]
    fn map_is_bounded_under_a_flood_of_distinct_addresses() {
        let throttle = AuthFailureThrottle::new(&config(1, 60)).expect("enabled");
        let now = Instant::now();
        for i in 0..(MAX_TRACKED_ADDRESSES + 500) {
            throttle.record_failure_at(&format!("10.0.{}.{}", i / 256, i % 256), now);
        }
        assert!(
            throttle.tracked_addresses() <= MAX_TRACKED_ADDRESSES,
            "tracked addresses must stay bounded, got {}",
            throttle.tracked_addresses()
        );
    }

    #[test]
    fn eviction_makes_room_for_new_addresses_once_at_capacity() {
        let throttle = AuthFailureThrottle::new(&config(1, 60)).expect("enabled");
        let now = Instant::now();
        for i in 0..MAX_TRACKED_ADDRESSES {
            throttle.record_failure_at(
                &format!("10.0.{}.{}", i / 256, i % 256),
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(throttle.tracked_addresses(), MAX_TRACKED_ADDRESSES);

        // One more, later than everything above, should evict the oldest
        // rather than growing past the bound.
        let newcomer_time = now + Duration::from_millis(MAX_TRACKED_ADDRESSES as u64 + 1000);
        throttle.record_failure_at("192.0.2.1", newcomer_time);
        assert_eq!(throttle.tracked_addresses(), MAX_TRACKED_ADDRESSES);
        assert!(matches!(
            throttle.check_at("192.0.2.1", newcomer_time),
            Decision::Throttled { .. }
        ));
    }
}
