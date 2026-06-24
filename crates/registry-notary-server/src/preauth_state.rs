// SPDX-License-Identifier: Apache-2.0
//! Short-lived, single-use in-memory stores for the pre-authorized-code flow.
//!
//! Two value stores back the flow:
//!
//! - The login state: `offer/start` reserves a `LoginState` (PKCE verifier,
//!   eSignet nonce, selected configuration) keyed by an opaque `state` and
//!   hands the `state` to eSignet. `offer/callback` consumes that state exactly
//!   once; an unknown, expired, or already-consumed state is rejected, which is
//!   the CSRF/replay guard for the login leg.
//! - The `tx_code` session: `offer/callback` stores the per-code PIN keyed by
//!   the pre-authorized code's `jti`. `/oid4vci/token` reads the PIN to verify
//!   the holder-presented `tx_code` (constant time) and consumes the session on
//!   success.
//!
//! These are value stores, not presence stores: the replay store only tracks
//! one-time identifiers, so it cannot carry the PKCE verifier or the PIN. The
//! single-use pre-authorized code `jti` itself is tracked in the replay store.

use std::collections::HashMap;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

/// The login state reserved at `offer/start` and consumed at `offer/callback`.
///
/// The PKCE verifier and the eSignet nonce are sensitive (they gate the token
/// exchange and bind the `id_token`), so `Debug` redacts them.
#[derive(Clone)]
pub(crate) struct LoginState {
    /// PKCE code verifier; the S256 challenge derived from it went to eSignet.
    pub(crate) pkce_verifier: String,
    /// Nonce echoed by eSignet in the `id_token`.
    pub(crate) nonce: String,
    /// Selected credential configuration id the offer will be bound to.
    pub(crate) credential_configuration_id: String,
}

impl std::fmt::Debug for LoginState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginState")
            .field("pkce_verifier", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field(
                "credential_configuration_id",
                &self.credential_configuration_id,
            )
            .finish()
    }
}

/// The per-code `tx_code` PIN session keyed by the pre-authorized code's `jti`.
///
/// The PIN is a secret; `Debug` redacts it.
#[derive(Clone)]
pub(crate) struct TxCodeSession {
    pub(crate) pin: String,
}

impl std::fmt::Debug for TxCodeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxCodeSession")
            .field("pin", &"[redacted]")
            .finish()
    }
}

struct StoredEntry<V> {
    value: V,
    expires_at: OffsetDateTime,
}

/// In-memory, single-use, TTL-bounded value store.
///
/// Single-instance only (like the in-memory replay store). The pre-auth login
/// leg is browser-driven on one node, so this matches the existing in-memory
/// pattern. `Debug` renders only metadata so stored secrets never leak.
pub(crate) struct SingleUseStore<V> {
    entries: Mutex<HashMap<String, StoredEntry<V>>>,
    max_entries: Option<usize>,
}

impl<V> std::fmt::Debug for SingleUseStore<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleUseStore")
            .field("entries", &"<redacted>")
            .finish()
    }
}

impl<V> Default for SingleUseStore<V> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SingleUseReserveError {
    Duplicate,
    Capacity,
    Unavailable,
}

impl<V: Clone> SingleUseStore<V> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn new_with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: Some(max_entries),
        }
    }

    /// Reserve `value` under `key` for `ttl`. Returns `false` if the key already
    /// exists (a collision is rejected rather than silently overwritten).
    pub(crate) fn reserve(&self, key: &str, value: V, ttl_seconds: u64) -> bool {
        self.try_reserve_at(key, value, ttl_seconds, OffsetDateTime::now_utc())
            .is_ok()
    }

    pub(crate) fn try_reserve(
        &self,
        key: &str,
        value: V,
        ttl_seconds: u64,
    ) -> Result<(), SingleUseReserveError> {
        self.try_reserve_at(key, value, ttl_seconds, OffsetDateTime::now_utc())
    }

    /// Consume the value under `key` exactly once. Returns `None` for unknown,
    /// expired, or already-consumed keys.
    pub(crate) fn consume(&self, key: &str) -> Option<V> {
        self.consume_at(key, OffsetDateTime::now_utc())
    }

    /// Read the value under `key` without consuming it. Returns `None` for
    /// unknown or expired keys. Used by the token endpoint to verify the
    /// `tx_code` without burning the code on a wrong PIN.
    pub(crate) fn peek(&self, key: &str) -> Option<V> {
        self.peek_at(key, OffsetDateTime::now_utc())
    }

    /// Remove the value under `key` (idempotent). Used to drop the `tx_code`
    /// session once the code has been single-used in the replay store.
    pub(crate) fn remove(&self, key: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }

    #[cfg(test)]
    fn reserve_at(&self, key: &str, value: V, ttl_seconds: u64, now: OffsetDateTime) -> bool {
        self.try_reserve_at(key, value, ttl_seconds, now).is_ok()
    }

    fn try_reserve_at(
        &self,
        key: &str,
        value: V,
        ttl_seconds: u64,
        now: OffsetDateTime,
    ) -> Result<(), SingleUseReserveError> {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => return Err(SingleUseReserveError::Unavailable),
        };
        prune_expired(&mut entries, now);
        if entries.contains_key(key) {
            return Err(SingleUseReserveError::Duplicate);
        }
        if self
            .max_entries
            .is_some_and(|max_entries| entries.len() >= max_entries)
        {
            return Err(SingleUseReserveError::Capacity);
        }
        entries.insert(
            key.to_string(),
            StoredEntry {
                value,
                expires_at: now + Duration::seconds(ttl_seconds as i64),
            },
        );
        Ok(())
    }

    fn consume_at(&self, key: &str, now: OffsetDateTime) -> Option<V> {
        let mut entries = self.entries.lock().ok()?;
        prune_expired(&mut entries, now);
        let stored = entries.remove(key)?;
        if now >= stored.expires_at {
            return None;
        }
        Some(stored.value)
    }

    fn peek_at(&self, key: &str, now: OffsetDateTime) -> Option<V> {
        let entries = self.entries.lock().ok()?;
        let stored = entries.get(key)?;
        if now >= stored.expires_at {
            return None;
        }
        Some(stored.value.clone())
    }
}

fn prune_expired<V>(entries: &mut HashMap<String, StoredEntry<V>>, now: OffsetDateTime) {
    entries.retain(|_, stored| now < stored.expires_at);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_state() -> LoginState {
        LoginState {
            pkce_verifier: "verifier-secret".to_string(),
            nonce: "nonce-secret".to_string(),
            credential_configuration_id: "person_is_alive_sd_jwt".to_string(),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp")
    }

    #[test]
    fn reserved_state_is_consumed_exactly_once() {
        let store = SingleUseStore::new();
        assert!(store.reserve_at("state-1", login_state(), 300, now()));

        let consumed = store
            .consume_at("state-1", now())
            .expect("reserved state consumes once");
        assert_eq!(
            consumed.credential_configuration_id,
            "person_is_alive_sd_jwt"
        );

        assert!(
            store.consume_at("state-1", now()).is_none(),
            "a state must not be consumable twice"
        );
    }

    #[test]
    fn unknown_state_is_rejected() {
        let store: SingleUseStore<LoginState> = SingleUseStore::new();
        assert!(store.consume_at("never-reserved", now()).is_none());
    }

    #[test]
    fn expired_state_is_rejected() {
        let store = SingleUseStore::new();
        assert!(store.reserve_at("state-1", login_state(), 300, now()));
        assert!(
            store
                .consume_at("state-1", now() + Duration::seconds(301))
                .is_none(),
            "an expired state must not consume"
        );
    }

    #[test]
    fn duplicate_reservation_is_rejected() {
        let store = SingleUseStore::new();
        assert!(store.reserve_at("state-1", login_state(), 300, now()));
        assert!(
            !store.reserve_at("state-1", login_state(), 300, now()),
            "a colliding state key must not overwrite an existing reservation"
        );
    }

    #[test]
    fn capped_reservations_reject_unexpired_entries_over_capacity() {
        let store = SingleUseStore::new_with_max_entries(1);
        assert!(store.reserve_at("state-1", login_state(), 300, now()));
        assert_eq!(
            store.try_reserve_at("state-2", login_state(), 300, now()),
            Err(SingleUseReserveError::Capacity)
        );
        assert!(
            store.reserve_at(
                "state-3",
                login_state(),
                300,
                now() + Duration::seconds(301)
            ),
            "expired entries are pruned before capacity is enforced"
        );
    }

    #[test]
    fn login_state_debug_redacts_pkce_verifier_and_nonce() {
        let state = login_state();
        let debug = format!("{state:?}");
        assert!(debug.contains("LoginState"));
        assert!(debug.contains("person_is_alive_sd_jwt"));
        assert!(!debug.contains("verifier-secret"));
        assert!(!debug.contains("nonce-secret"));
    }

    #[test]
    fn tx_code_session_debug_redacts_pin() {
        let session = TxCodeSession {
            pin: "246810".to_string(),
        };
        let debug = format!("{session:?}");
        assert!(debug.contains("TxCodeSession"));
        assert!(!debug.contains("246810"));
    }
}
