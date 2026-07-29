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
const MAX_TRACKED_OPERATIONS: usize = 65_536;

const WINDOW: Duration = Duration::minutes(1);
pub(crate) const OPERATION_LEASE_SECONDS: i64 = 60;
const OPERATION_LEASE: Duration = Duration::seconds(OPERATION_LEASE_SECONDS);

type MachineQuotaKey = Bounded<MAX_MACHINE_QUOTA_KEY_LEN>;

/// The machine quota budget was exhausted for a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineQuotaExceeded {
    pub retry_after_seconds: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum MachineQuotaOperationOutcome {
    Acquired(MachineQuotaOperationFence),
    Existing,
    Conflict,
}

#[derive(Debug, Clone)]
pub(crate) struct MachineQuotaOperationFence {
    principal_key: MachineQuotaKey,
    principal_hash: [u8; 32],
    operation_hash: [u8; 32],
    request_hash: [u8; 32],
    lease_owner_hash: [u8; 32],
    in_memory: Option<Arc<Mutex<InMemoryQuotaState>>>,
}

#[derive(Debug)]
struct Counter {
    window_start: OffsetDateTime,
    used: u32,
}

#[derive(Debug, Default)]
struct InMemoryQuotaState {
    counters: HashMap<MachineQuotaKey, Counter>,
    operations: HashMap<(MachineQuotaKey, [u8; 32]), QuotaOperation>,
}

#[derive(Debug)]
struct QuotaOperation {
    request_hash: [u8; 32],
    lease_owner_hash: [u8; 32],
    lease_expires_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl MachineQuotaOperationFence {
    pub(crate) fn principal_hash(&self) -> &[u8; 32] {
        &self.principal_hash
    }

    pub(crate) fn operation_hash(&self) -> &[u8; 32] {
        &self.operation_hash
    }

    pub(crate) fn lease_owner_hash(&self) -> &[u8; 32] {
        &self.lease_owner_hash
    }

    pub(crate) fn complete_in_memory<T>(&self, operation: impl FnOnce() -> T) -> Result<T, ()> {
        self.complete_in_memory_at(OffsetDateTime::now_utc(), operation)
    }

    fn complete_in_memory_at<T>(
        &self,
        now: OffsetDateTime,
        operation: impl FnOnce() -> T,
    ) -> Result<T, ()> {
        let Some(in_memory) = self.in_memory.as_ref() else {
            return Err(());
        };
        let state = match in_memory.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(stored) = state
            .operations
            .get(&(self.principal_key.clone(), self.operation_hash))
        else {
            return Err(());
        };
        if stored.request_hash != self.request_hash
            || stored.lease_owner_hash != self.lease_owner_hash
            || stored.lease_expires_at <= now
        {
            return Err(());
        }
        Ok(operation())
    }
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
    in_memory: Arc<Mutex<InMemoryQuotaState>>,
}

impl MachineQuotaLimiter {
    #[must_use]
    pub fn new(config: MachineQuotaConfig) -> Self {
        Self {
            config,
            state_plane: None,
            principal_hasher: AuditKeyHasher::unkeyed_dev_only(),
            in_memory: Arc::new(Mutex::new(InMemoryQuotaState::default())),
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
            in_memory: Arc::new(Mutex::new(InMemoryQuotaState::default())),
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

    /// Consume quota once for one canonical operation. Concurrent exact
    /// retries share the operation hash, so only the first attempt spends
    /// budget. One leased owner may reach the authoritative reservation;
    /// contenders wait or take over without another debit.
    pub(crate) async fn check_and_consume_once(
        &self,
        principal_id: &str,
        cost: u32,
        operation_id: &str,
        request_id: &str,
        lease_owner_id: &str,
        operation_expires_at: OffsetDateTime,
    ) -> Result<MachineQuotaOperationOutcome, MachineQuotaExceeded> {
        validate_principal_id(principal_id)?;
        if cost == 0 {
            return Err(quota_failure());
        }
        let operation_hash = machine_quota_operation_hash(&self.principal_hasher, operation_id)?;
        let request_hash = machine_quota_operation_request_hash(request_id)?;
        let lease_owner_hash =
            machine_quota_operation_owner_hash(&self.principal_hasher, lease_owner_id)?;
        if operation_expires_at <= OffsetDateTime::now_utc() {
            return Err(quota_failure());
        }
        let Some(state_plane) = self
            .state_plane
            .as_ref()
            .filter(|state_plane| !state_plane.is_in_memory())
        else {
            return self.check_and_consume_once_at(
                principal_id,
                cost,
                Some(operation_hash),
                Some(request_hash),
                Some(lease_owner_hash),
                Some(operation_expires_at),
                OffsetDateTime::now_utc(),
            );
        };
        self.check_and_consume_once_postgres(
            state_plane,
            principal_id,
            cost,
            &operation_hash,
            &request_hash,
            &lease_owner_hash,
            operation_expires_at,
        )
        .await
    }

    /// Release only the operation claim after a post-debit failure. The quota
    /// debit is intentionally retained, so retries cannot turn signer or
    /// construction failures into free work.
    pub(crate) async fn release_operation(
        &self,
        principal_id: &str,
        operation_id: &str,
        lease_owner_id: &str,
    ) -> Result<(), MachineQuotaExceeded> {
        validate_principal_id(principal_id)?;
        let operation_hash = machine_quota_operation_hash(&self.principal_hasher, operation_id)?;
        let lease_owner_hash =
            machine_quota_operation_owner_hash(&self.principal_hasher, lease_owner_id)?;
        let Some(state_plane) = self
            .state_plane
            .as_ref()
            .filter(|state_plane| !state_plane.is_in_memory())
        else {
            let key = MachineQuotaKey::new(principal_id).map_err(|_| quota_failure())?;
            let mut state = match self.in_memory.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(operation) = state.operations.get_mut(&(key, operation_hash)) {
                if operation.lease_owner_hash == lease_owner_hash {
                    operation.lease_expires_at = OffsetDateTime::now_utc();
                }
            }
            return Ok(());
        };
        let principal_hash = machine_quota_hash(&self.principal_hasher, principal_id)?;
        let runtime = state_plane.runtime().map_err(|_| quota_failure())?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| quota_failure())?;
        session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.machine_quota_operation_release_v1($1, $2, $3)",
                &[
                    &principal_hash,
                    &&operation_hash[..],
                    &&lease_owner_hash[..],
                ],
            ))
            .await
            .map_err(|_| quota_failure())?;
        Ok(())
    }

    #[must_use]
    pub(crate) const fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn operation_fence(
        &self,
        principal_id: &str,
        operation_hash: [u8; 32],
        request_hash: [u8; 32],
        lease_owner_hash: [u8; 32],
        in_memory: bool,
    ) -> Result<MachineQuotaOperationFence, MachineQuotaExceeded> {
        Ok(MachineQuotaOperationFence {
            principal_key: MachineQuotaKey::new(principal_id).map_err(|_| quota_failure())?,
            principal_hash: machine_quota_hash(&self.principal_hasher, principal_id)?
                .try_into()
                .map_err(|_| quota_failure())?,
            operation_hash,
            request_hash,
            lease_owner_hash,
            in_memory: in_memory.then(|| Arc::clone(&self.in_memory)),
        })
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

    // Keep each hash explicit at the trust boundary so operation, request,
    // and owner identities cannot be accidentally substituted or reordered.
    #[allow(clippy::too_many_arguments)]
    async fn check_and_consume_once_postgres(
        &self,
        state_plane: &NotaryStatePlaneHandle,
        principal_id: &str,
        cost: u32,
        operation_hash: &[u8; 32],
        request_hash: &[u8; 32],
        lease_owner_hash: &[u8; 32],
        operation_expires_at: OffsetDateTime,
    ) -> Result<MachineQuotaOperationOutcome, MachineQuotaExceeded> {
        let limit = if self.config.enabled {
            Some(
                i32::try_from(self.config.subjects_per_minute)
                    .ok()
                    .filter(|limit| *limit > 0)
                    .ok_or_else(quota_failure)?,
            )
        } else {
            None
        };
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
                    "SELECT allowed, acquired, conflict, retry_after_seconds ",
                    "FROM registry_notary_api.machine_quota_debit_once_v1(",
                    "$1, $2, $3, $4, $5, $6, $7, $8)"
                ),
                &[
                    &principal_hash,
                    &&operation_hash[..],
                    &&request_hash[..],
                    &&lease_owner_hash[..],
                    &limit,
                    &cost,
                    &(OPERATION_LEASE.whole_seconds() as i32),
                    &operation_expires_at,
                ],
            ))
            .await
            .map_err(|_| quota_failure())?;
        let allowed: bool = row.try_get("allowed").map_err(|_| quota_failure())?;
        if allowed {
            let conflict: bool = row.try_get("conflict").map_err(|_| quota_failure())?;
            if conflict {
                return Ok(MachineQuotaOperationOutcome::Conflict);
            }
            let acquired: bool = row.try_get("acquired").map_err(|_| quota_failure())?;
            return Ok(if acquired {
                MachineQuotaOperationOutcome::Acquired(self.operation_fence(
                    principal_id,
                    *operation_hash,
                    *request_hash,
                    *lease_owner_hash,
                    false,
                )?)
            } else {
                MachineQuotaOperationOutcome::Existing
            });
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
        self.check_and_consume_once_at(principal_id, cost, None, None, None, None, now)
            .map(|_| ())
    }

    // Tests inject every clock and identity component independently to cover
    // takeover and stale-owner behavior without wall-clock sleeps.
    #[allow(clippy::too_many_arguments)]
    fn check_and_consume_once_at(
        &self,
        principal_id: &str,
        cost: u32,
        operation_hash: Option<[u8; 32]>,
        request_hash: Option<[u8; 32]>,
        lease_owner_hash: Option<[u8; 32]>,
        operation_expires_at: Option<OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Result<MachineQuotaOperationOutcome, MachineQuotaExceeded> {
        if cost == 0 {
            return Err(quota_failure());
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

        let mut state = match self.in_memory.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        prune_expired(&mut state, now);

        let operation = operation_hash
            .zip(request_hash)
            .zip(lease_owner_hash)
            .zip(operation_expires_at)
            .map(
                |(((operation_hash, request_hash), lease_owner_hash), operation_expires_at)| {
                    (
                        (key.clone(), operation_hash),
                        request_hash,
                        lease_owner_hash,
                        operation_expires_at,
                    )
                },
            );
        if operation_hash.is_some() != operation.is_some()
            || request_hash.is_some() != operation.is_some()
            || lease_owner_hash.is_some() != operation.is_some()
            || operation_expires_at.is_some() != operation.is_some()
        {
            return Err(quota_failure());
        }
        if let Some((operation_key, request_hash, lease_owner_hash, _)) = operation.as_ref() {
            if let Some(stored) = state.operations.get_mut(operation_key) {
                if stored.request_hash != *request_hash {
                    return Ok(MachineQuotaOperationOutcome::Conflict);
                }
                if stored.lease_owner_hash == *lease_owner_hash || stored.lease_expires_at <= now {
                    stored.lease_owner_hash = *lease_owner_hash;
                    stored.lease_expires_at =
                        std::cmp::min(now + OPERATION_LEASE, stored.expires_at);
                    return Ok(MachineQuotaOperationOutcome::Acquired(
                        self.operation_fence(
                            principal_id,
                            operation_key.1,
                            *request_hash,
                            *lease_owner_hash,
                            true,
                        )?,
                    ));
                }
                return Ok(MachineQuotaOperationOutcome::Existing);
            }
        }
        if operation.is_some() && state.operations.len() >= MAX_TRACKED_OPERATIONS {
            return Err(quota_failure());
        }

        if self.config.enabled {
            let limit = self.config.subjects_per_minute;
            let (window_start, used) = match state.counters.get(&key) {
                Some(counter) if counter.in_window(now) => (counter.window_start, counter.used),
                _ => (now, 0),
            };

            let remaining = limit.saturating_sub(used);
            if cost > remaining {
                let retry_after_seconds = match state.counters.get(&key) {
                    Some(counter) if counter.in_window(now) => counter.retry_after_seconds(now),
                    _ => WINDOW.whole_seconds() as u64,
                };
                return Err(MachineQuotaExceeded {
                    retry_after_seconds,
                });
            }

            if !state.counters.contains_key(&key) {
                evict_oldest_if_at_capacity(&mut state.counters);
            }
            state.counters.insert(
                key,
                Counter {
                    window_start,
                    used: used + cost,
                },
            );
        }
        if let Some((operation_key, request_hash, lease_owner_hash, operation_expires_at)) =
            operation
        {
            state.operations.insert(
                operation_key,
                QuotaOperation {
                    request_hash,
                    lease_owner_hash,
                    lease_expires_at: std::cmp::min(now + OPERATION_LEASE, operation_expires_at),
                    expires_at: operation_expires_at,
                },
            );
        }
        let Some(operation_hash) = operation_hash else {
            return Ok(MachineQuotaOperationOutcome::Existing);
        };
        Ok(MachineQuotaOperationOutcome::Acquired(
            self.operation_fence(
                principal_id,
                operation_hash,
                request_hash.ok_or_else(quota_failure)?,
                lease_owner_hash.ok_or_else(quota_failure)?,
                true,
            )?,
        ))
    }

    #[cfg(test)]
    fn tracked_principal_count(&self) -> usize {
        self.in_memory
            .lock()
            .expect("counter mutex is not poisoned")
            .counters
            .len()
    }

    #[cfg(test)]
    fn is_tracked(&self, principal_id: &str) -> bool {
        let key = MachineQuotaKey::new(principal_id).expect("test principal id is bounded");
        self.in_memory
            .lock()
            .expect("counter mutex is not poisoned")
            .counters
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

fn machine_quota_operation_hash(
    hasher: &AuditKeyHasher,
    operation_id: &str,
) -> Result<[u8; 32], MachineQuotaExceeded> {
    if operation_id.is_empty() || operation_id.len() > 512 {
        return Err(quota_failure());
    }
    let encoded = hasher
        .audit_reference_hash("notary-machine-quota-operation-v1", "", operation_id)
        .map_err(|_| quota_failure())?;
    let digest = encoded
        .strip_prefix("hmac-sha256:")
        .or_else(|| encoded.strip_prefix("sha256:"))
        .ok_or_else(quota_failure)?;
    decode_32_byte_hex(digest)
        .ok_or_else(quota_failure)?
        .try_into()
        .map_err(|_| quota_failure())
}

fn machine_quota_operation_request_hash(
    request_id: &str,
) -> Result<[u8; 32], MachineQuotaExceeded> {
    let digest = request_id
        .strip_prefix("sha256:")
        .ok_or_else(quota_failure)?;
    decode_32_byte_hex(digest)
        .ok_or_else(quota_failure)?
        .try_into()
        .map_err(|_| quota_failure())
}

fn machine_quota_operation_owner_hash(
    hasher: &AuditKeyHasher,
    lease_owner_id: &str,
) -> Result<[u8; 32], MachineQuotaExceeded> {
    if lease_owner_id.is_empty() || lease_owner_id.len() > 256 {
        return Err(quota_failure());
    }
    let encoded = hasher
        .audit_reference_hash(
            "notary-machine-quota-operation-owner-v1",
            "",
            lease_owner_id,
        )
        .map_err(|_| quota_failure())?;
    let digest = encoded
        .strip_prefix("hmac-sha256:")
        .or_else(|| encoded.strip_prefix("sha256:"))
        .ok_or_else(quota_failure)?;
    decode_32_byte_hex(digest)
        .ok_or_else(quota_failure)?
        .try_into()
        .map_err(|_| quota_failure())
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

fn prune_expired(state: &mut InMemoryQuotaState, now: OffsetDateTime) {
    state.counters.retain(|_, counter| counter.in_window(now));
    state
        .operations
        .retain(|_, operation| operation.expires_at > now);
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

    fn acquired(
        outcome: Result<MachineQuotaOperationOutcome, MachineQuotaExceeded>,
    ) -> MachineQuotaOperationFence {
        match outcome.expect("operation succeeds") {
            MachineQuotaOperationOutcome::Acquired(fence) => fence,
            other => panic!("expected acquired operation, got {other:?}"),
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
    fn exact_operation_retries_consume_quota_once() {
        let limiter = MachineQuotaLimiter::new(config(true, 1));
        let exact_operation = [0x11; 32];
        let distinct_operation = [0x22; 32];
        let exact_request = [0x21; 32];

        assert!(limiter
            .check_and_consume_once_at(
                "machine-a",
                1,
                Some(exact_operation),
                Some(exact_request),
                Some([0x31; 32]),
                Some(now() + Duration::minutes(5)),
                now(),
            )
            .is_ok());
        assert!(matches!(
            limiter
                .check_and_consume_once_at(
                    "machine-a",
                    1,
                    Some(exact_operation),
                    Some(exact_request),
                    Some([0x32; 32]),
                    Some(now() + Duration::minutes(5)),
                    now(),
                )
                .unwrap(),
            MachineQuotaOperationOutcome::Existing
        ));
        assert!(matches!(
            limiter
                .check_and_consume_once_at(
                    "machine-a",
                    1,
                    Some(exact_operation),
                    Some([0x23; 32]),
                    Some([0x32; 32]),
                    Some(now() + Duration::minutes(5)),
                    now(),
                )
                .unwrap(),
            MachineQuotaOperationOutcome::Conflict
        ));
        assert!(limiter
            .check_and_consume_once_at(
                "machine-a",
                1,
                Some(distinct_operation),
                Some([0x24; 32]),
                Some([0x33; 32]),
                Some(now() + Duration::minutes(5)),
                now(),
            )
            .is_err());
        acquired(limiter.check_and_consume_once_at(
            "machine-a",
            1,
            Some(exact_operation),
            Some(exact_request),
            Some([0x32; 32]),
            Some(now() + Duration::minutes(5)),
            now() + Duration::seconds(61),
        ));
    }

    #[test]
    fn operation_identity_outlives_the_quota_window() {
        let limiter = MachineQuotaLimiter::new(config(true, 1));
        let exact_operation = [0x33; 32];

        assert!(limiter
            .check_and_consume_once_at(
                "machine-a",
                1,
                Some(exact_operation),
                Some([0x34; 32]),
                Some([0x41; 32]),
                Some(now() + Duration::minutes(5)),
                now(),
            )
            .is_ok());
        let next_window = now() + Duration::seconds(61);
        acquired(limiter.check_and_consume_once_at(
            "machine-a",
            1,
            Some(exact_operation),
            Some([0x34; 32]),
            Some([0x42; 32]),
            Some(now() + Duration::minutes(5)),
            next_window,
        ));
        assert!(limiter
            .check_and_consume_once_at(
                "machine-a",
                1,
                Some([0x44; 32]),
                Some([0x35; 32]),
                Some([0x43; 32]),
                Some(now() + Duration::minutes(5)),
                next_window,
            )
            .is_ok());
    }

    #[test]
    fn owner_renewal_keeps_contenders_outside_the_completion_window() {
        let limiter = MachineQuotaLimiter::new(config(true, 1));
        let operation = [0x51; 32];
        let request = [0x52; 32];
        let owner = [0x53; 32];
        let contender = [0x54; 32];
        let expires_at = now() + Duration::minutes(5);

        acquired(limiter.check_and_consume_once_at(
            "machine-a",
            1,
            Some(operation),
            Some(request),
            Some(owner),
            Some(expires_at),
            now(),
        ));
        let renewed_fence = acquired(limiter.check_and_consume_once_at(
            "machine-a",
            1,
            Some(operation),
            Some(request),
            Some(owner),
            Some(expires_at),
            now() + Duration::seconds(25),
        ));
        assert!(matches!(
            limiter
                .check_and_consume_once_at(
                    "machine-a",
                    1,
                    Some(operation),
                    Some(request),
                    Some(contender),
                    Some(expires_at),
                    now() + Duration::seconds(61),
                )
                .unwrap(),
            MachineQuotaOperationOutcome::Existing
        ));
        let takeover_fence = acquired(limiter.check_and_consume_once_at(
            "machine-a",
            1,
            Some(operation),
            Some(request),
            Some(contender),
            Some(expires_at),
            now() + Duration::seconds(86),
        ));
        assert!(
            renewed_fence
                .complete_in_memory_at(now() + Duration::seconds(86), || ())
                .is_err(),
            "a stale owner is fenced after crash-style lease takeover",
        );
        assert!(takeover_fence
            .complete_in_memory_at(now() + Duration::seconds(86), || ())
            .is_ok());
    }

    #[test]
    fn disabled_quota_still_serializes_idempotent_operations() {
        let limiter = MachineQuotaLimiter::new(config(false, 1));
        let operation = [0x61; 32];
        let request = [0x62; 32];
        acquired(limiter.check_and_consume_once_at(
            "machine-a",
            1,
            Some(operation),
            Some(request),
            Some([0x63; 32]),
            Some(now() + Duration::minutes(5)),
            now(),
        ));
        assert!(matches!(
            limiter
                .check_and_consume_once_at(
                    "machine-a",
                    1,
                    Some(operation),
                    Some(request),
                    Some([0x64; 32]),
                    Some(now() + Duration::minutes(5)),
                    now(),
                )
                .unwrap(),
            MachineQuotaOperationOutcome::Existing
        ));
        assert!(matches!(
            limiter
                .check_and_consume_once_at(
                    "machine-a",
                    1,
                    Some(operation),
                    Some([0x65; 32]),
                    Some([0x64; 32]),
                    Some(now() + Duration::minutes(5)),
                    now(),
                )
                .unwrap(),
            MachineQuotaOperationOutcome::Conflict
        ));
        assert_eq!(limiter.tracked_principal_count(), 0);
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
