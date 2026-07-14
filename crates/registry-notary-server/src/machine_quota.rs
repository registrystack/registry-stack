// SPDX-License-Identifier: Apache-2.0
//! Quota for machine (non-subject-access) `evaluate` and `batch_evaluate`
//! traffic. PostgreSQL is authoritative when a state plane is configured;
//! the bounded in-memory path remains for local and test deployments.
//!
//! Budget is counted in subjects per principal over a fixed one-minute
//! window: a single `/v1/evaluations` call consumes 1, a batch consumes
//! `items.len()`. A request whose cost would cross the remaining budget is
//! rejected whole so the response stays deterministic and no partial
//! evaluation work is ever performed for a rejected request.
//!
//! Self-attestation principals never reach this limiter; enforcement in
//! `api.rs` only calls it for principals that failed
//! [`registry_notary_core::model::EvidencePrincipal::is_subject_access`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use registry_notary_core::{Bounded, MachineQuotaConfig};
use registry_platform_audit::AuditKeyHasher;
use time::{Duration, OffsetDateTime};

use crate::state_plane::NotaryStatePlaneHandle;

const MAX_MACHINE_QUOTA_KEY_LEN: usize = 128;

/// Upper bound on the number of distinct principals tracked at once. Once
/// this many principals are being tracked, adding a new one evicts the
/// least-recently-started window so the map cannot grow without bound.
const MAX_TRACKED_PRINCIPALS: usize = 10_000;

const WINDOW: Duration = Duration::minutes(1);

type MachineQuotaKey = Bounded<MAX_MACHINE_QUOTA_KEY_LEN>;

/// The machine quota budget was exhausted for a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineQuotaExceeded {
    pub retry_after_seconds: u64,
}

#[derive(Debug)]
struct Counter {
    window_start: OffsetDateTime,
    used: u32,
}

impl Counter {
    fn in_window(&self, now: OffsetDateTime) -> bool {
        now < self.window_start + WINDOW
    }

    /// Seconds until the current window rolls over, rounded up so callers
    /// never see a zero-second hint while still inside the window.
    fn retry_after_seconds(&self, now: OffsetDateTime) -> u64 {
        let remaining = (self.window_start + WINDOW) - now;
        remaining.whole_seconds().max(1) as u64
    }
}

/// Fixed-window quota limiter keyed by an audit pseudonym of `principal_id`,
/// with a single bucket kind and cost-aware consumption.
#[derive(Debug)]
pub struct MachineQuotaLimiter {
    config: MachineQuotaConfig,
    state_plane: Option<Arc<NotaryStatePlaneHandle>>,
    principal_hasher: AuditKeyHasher,
    counters: Mutex<HashMap<MachineQuotaKey, Counter>>,
}

impl MachineQuotaLimiter {
    #[must_use]
    pub fn new(config: MachineQuotaConfig) -> Self {
        Self {
            config,
            state_plane: None,
            principal_hasher: AuditKeyHasher::unkeyed_dev_only(),
            counters: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub(crate) fn with_state_plane(
        config: MachineQuotaConfig,
        state_plane: Arc<NotaryStatePlaneHandle>,
        principal_hasher: AuditKeyHasher,
    ) -> Self {
        Self {
            config,
            state_plane: Some(state_plane),
            principal_hasher,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Atomically check and consume `cost` subjects from `principal_id`'s
    /// budget. When the quota is disabled this always succeeds. A `cost`
    /// that would exceed the remaining budget is rejected in full: nothing
    /// is consumed, so the caller may retry with a smaller batch (or wait
    /// out the window) without having partially spent its quota.
    pub async fn check_and_consume(
        &self,
        principal_id: &str,
        cost: u32,
    ) -> Result<(), MachineQuotaExceeded> {
        if !self.config.enabled || cost == 0 {
            return Ok(());
        }
        validate_principal_id(principal_id)?;
        let Some(state_plane) = self
            .state_plane
            .as_ref()
            .filter(|state_plane| !state_plane.is_in_memory())
        else {
            return self.check_and_consume_at(principal_id, cost, OffsetDateTime::now_utc());
        };
        self.check_and_consume_postgres(state_plane, principal_id, cost)
            .await
    }

    pub(crate) fn batch_reservation_parameters(
        &self,
        principal_id: &str,
        cost: u32,
    ) -> Result<(Vec<u8>, Option<i32>, i32), MachineQuotaExceeded> {
        validate_principal_id(principal_id)?;
        let principal_hash = machine_quota_hash(&self.principal_hasher, principal_id)?;
        let cost = i32::try_from(cost)
            .ok()
            .filter(|cost| *cost > 0)
            .ok_or_else(quota_failure)?;
        let limit = self
            .config
            .enabled
            .then(|| i32::try_from(self.config.subjects_per_minute).ok())
            .flatten()
            .filter(|limit| *limit > 0);
        if self.config.enabled && limit.is_none() {
            return Err(quota_failure());
        }
        Ok((principal_hash, limit, cost))
    }

    async fn check_and_consume_postgres(
        &self,
        state_plane: &NotaryStatePlaneHandle,
        principal_id: &str,
        cost: u32,
    ) -> Result<(), MachineQuotaExceeded> {
        let limit = i32::try_from(self.config.subjects_per_minute)
            .ok()
            .filter(|limit| *limit > 0)
            .ok_or_else(quota_failure)?;
        let cost = i32::try_from(cost)
            .ok()
            .filter(|cost| *cost > 0)
            .ok_or_else(quota_failure)?;
        let principal_hash = machine_quota_hash(&self.principal_hasher, principal_id)?;
        let runtime = state_plane.runtime().map_err(|_| quota_failure())?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| quota_failure())?;
        let row = session
            .run_operation(session.client().query_one(
                concat!(
                    "SELECT allowed, retry_after_seconds ",
                    "FROM registry_notary_api.machine_quota_debit_v1($1, $2, $3)"
                ),
                &[&principal_hash, &limit, &cost],
            ))
            .await
            .map_err(|_| quota_failure())?;
        let allowed: bool = row.try_get("allowed").map_err(|_| quota_failure())?;
        if allowed {
            return Ok(());
        }
        let retry_after_seconds: i64 = row
            .try_get("retry_after_seconds")
            .map_err(|_| quota_failure())?;
        Err(MachineQuotaExceeded {
            retry_after_seconds: retry_after_seconds.max(1) as u64,
        })
    }

    fn check_and_consume_at(
        &self,
        principal_id: &str,
        cost: u32,
        now: OffsetDateTime,
    ) -> Result<(), MachineQuotaExceeded> {
        if !self.config.enabled || cost == 0 {
            return Ok(());
        }

        // A principal id that does not fit the bounded key is treated as
        // over quota rather than silently bypassing the limiter: this is a
        // denial surface, so failures must fail closed.
        let key = match MachineQuotaKey::new(principal_id) {
            Ok(key) => key,
            Err(_) => {
                return Err(MachineQuotaExceeded {
                    retry_after_seconds: WINDOW.whole_seconds() as u64,
                })
            }
        };

        let mut counters = match self.counters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        prune_expired(&mut counters, now);

        let limit = self.config.subjects_per_minute;
        let (window_start, used) = match counters.get(&key) {
            Some(counter) if counter.in_window(now) => (counter.window_start, counter.used),
            _ => (now, 0),
        };

        let remaining = limit.saturating_sub(used);
        if cost > remaining {
            let retry_after_seconds = match counters.get(&key) {
                Some(counter) if counter.in_window(now) => counter.retry_after_seconds(now),
                _ => WINDOW.whole_seconds() as u64,
            };
            return Err(MachineQuotaExceeded {
                retry_after_seconds,
            });
        }

        if !counters.contains_key(&key) {
            evict_oldest_if_at_capacity(&mut counters);
        }
        counters.insert(
            key,
            Counter {
                window_start,
                used: used + cost,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    fn tracked_principal_count(&self) -> usize {
        self.counters
            .lock()
            .expect("counter mutex is not poisoned")
            .len()
    }

    #[cfg(test)]
    fn is_tracked(&self, principal_id: &str) -> bool {
        let key = MachineQuotaKey::new(principal_id).expect("test principal id is bounded");
        self.counters
            .lock()
            .expect("counter mutex is not poisoned")
            .contains_key(&key)
    }
}

fn validate_principal_id(principal_id: &str) -> Result<(), MachineQuotaExceeded> {
    MachineQuotaKey::new(principal_id)
        .map(|_| ())
        .map_err(|_| quota_failure())
}

fn quota_failure() -> MachineQuotaExceeded {
    MachineQuotaExceeded {
        retry_after_seconds: WINDOW.whole_seconds() as u64,
    }
}

fn machine_quota_hash(
    hasher: &AuditKeyHasher,
    principal_id: &str,
) -> Result<Vec<u8>, MachineQuotaExceeded> {
    let encoded = hasher
        .audit_reference_hash("notary-machine-quota-v1", "", principal_id)
        .map_err(|_| quota_failure())?;
    let digest = encoded
        .strip_prefix("hmac-sha256:")
        .or_else(|| encoded.strip_prefix("sha256:"))
        .ok_or_else(quota_failure)?;
    decode_32_byte_hex(digest).ok_or_else(quota_failure)
}

fn decode_32_byte_hex(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() != 64 {
        return None;
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn prune_expired(counters: &mut HashMap<MachineQuotaKey, Counter>, now: OffsetDateTime) {
    counters.retain(|_, counter| counter.in_window(now));
}

fn evict_oldest_if_at_capacity(counters: &mut HashMap<MachineQuotaKey, Counter>) {
    if counters.len() < MAX_TRACKED_PRINCIPALS {
        return;
    }
    if let Some(oldest_key) = counters
        .iter()
        .min_by_key(|(_, counter)| counter.window_start)
        .map(|(key, _)| key.clone())
    {
        counters.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed timestamp is valid")
    }

    fn config(enabled: bool, subjects_per_minute: u32) -> MachineQuotaConfig {
        MachineQuotaConfig {
            enabled,
            subjects_per_minute,
        }
    }

    #[test]
    fn disabled_quota_never_denies() {
        let limiter = MachineQuotaLimiter::new(config(false, 1));
        for _ in 0..1000 {
            assert!(limiter
                .check_and_consume_at("machine-a", 1_000_000, now())
                .is_ok());
        }
    }

    #[test]
    fn exact_boundary_batch_exhausts_then_next_call_fails() {
        let limiter = MachineQuotaLimiter::new(config(true, 10));

        assert!(limiter.check_and_consume_at("machine-a", 10, now()).is_ok());

        let err = limiter
            .check_and_consume_at("machine-a", 1, now())
            .expect_err("budget is exhausted");
        assert_eq!(err.retry_after_seconds, 60);
    }

    #[test]
    fn window_expiry_resets_budget() {
        let limiter = MachineQuotaLimiter::new(config(true, 10));
        assert!(limiter.check_and_consume_at("machine-a", 10, now()).is_ok());

        // Still inside the window: exhausted.
        assert!(limiter
            .check_and_consume_at("machine-a", 1, now() + Duration::seconds(59))
            .is_err());

        // Window has rolled over: budget resets.
        assert!(limiter
            .check_and_consume_at("machine-a", 10, now() + Duration::seconds(61))
            .is_ok());
    }

    #[test]
    fn cost_greater_than_remaining_rejects_whole_batch_without_partial_consumption() {
        let limiter = MachineQuotaLimiter::new(config(true, 10));
        assert!(limiter.check_and_consume_at("machine-a", 4, now()).is_ok());

        // 8 would push used from 4 to 12, over the limit of 10: rejected,
        // and nothing should be consumed.
        let err = limiter
            .check_and_consume_at("machine-a", 8, now())
            .expect_err("cost exceeds remaining budget");
        assert_eq!(err.retry_after_seconds, 60);

        // The remaining budget (6) must be untouched by the rejected call.
        assert!(limiter.check_and_consume_at("machine-a", 6, now()).is_ok());
        assert!(limiter.check_and_consume_at("machine-a", 1, now()).is_err());
    }

    #[test]
    fn distinct_principals_track_independent_budgets() {
        let limiter = MachineQuotaLimiter::new(config(true, 5));
        assert!(limiter.check_and_consume_at("machine-a", 5, now()).is_ok());
        assert!(limiter.check_and_consume_at("machine-a", 1, now()).is_err());

        // machine-b has its own, untouched budget.
        assert!(limiter.check_and_consume_at("machine-b", 5, now()).is_ok());
    }

    #[test]
    fn map_is_bounded_and_evicts_oldest_entry() {
        // Nanosecond-spaced timestamps keep every principal inside the same
        // one-minute window (10,000ns is far under 60s), while still giving
        // each one a strictly distinct, increasing `window_start` so the
        // "oldest" entry is well-defined for the eviction assertion below.
        let limiter = MachineQuotaLimiter::new(config(true, 1));
        for index in 0..MAX_TRACKED_PRINCIPALS {
            let principal = format!("machine-{index}");
            assert!(limiter
                .check_and_consume_at(&principal, 1, now() + Duration::nanoseconds(index as i64))
                .is_ok());
        }
        assert_eq!(limiter.tracked_principal_count(), MAX_TRACKED_PRINCIPALS);

        // One more distinct principal pushes the map over capacity: the
        // oldest tracked window (machine-0) must be evicted to make room.
        let overflow_now = now() + Duration::nanoseconds(MAX_TRACKED_PRINCIPALS as i64);
        assert!(limiter
            .check_and_consume_at("machine-overflow", 1, overflow_now)
            .is_ok());
        assert_eq!(limiter.tracked_principal_count(), MAX_TRACKED_PRINCIPALS);
        assert!(!limiter.is_tracked("machine-0"));
        assert!(limiter.is_tracked("machine-overflow"));
    }

    #[test]
    fn oversized_principal_id_fails_closed() {
        let limiter = MachineQuotaLimiter::new(config(true, 1000));
        let oversized = "x".repeat(MAX_MACHINE_QUOTA_KEY_LEN + 1);
        let err = limiter
            .check_and_consume_at(&oversized, 1, now())
            .expect_err("oversized principal id must fail closed");
        assert_eq!(err.retry_after_seconds, 60);
    }

    #[test]
    fn zero_cost_never_denies() {
        let limiter = MachineQuotaLimiter::new(config(true, 1));
        assert!(limiter.check_and_consume_at("machine-a", 0, now()).is_ok());
        assert!(limiter.check_and_consume_at("machine-a", 0, now()).is_ok());
    }

    #[tokio::test]
    async fn public_in_memory_path_uses_the_same_atomic_budget() {
        let limiter = MachineQuotaLimiter::new(config(true, 2));
        assert!(limiter.check_and_consume("machine-a", 2).await.is_ok());
        assert!(limiter.check_and_consume("machine-a", 1).await.is_err());
    }

    #[test]
    fn database_principal_key_is_a_fixed_width_audit_pseudonym() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();
        let pseudonym = machine_quota_hash(&hasher, "machine-a").unwrap();

        assert_eq!(pseudonym.len(), 32);
        assert_ne!(pseudonym, b"machine-a");
    }
}
