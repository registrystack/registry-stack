// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::Mutex;

#[derive(Default)]
pub(super) struct FederationReplayStore {
    entries: Mutex<BTreeMap<String, FederationReplayEntry>>,
    next_sequence: AtomicU64,
    evictions: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
struct FederationReplayEntry {
    expires_at: i64,
    inserted_sequence: u64,
}

impl FederationReplayStore {
    pub(super) async fn insert_once(
        &self,
        issuer: &str,
        jti: &str,
        exp: i64,
        clock_leeway_seconds: u64,
        now: i64,
        max_entries: usize,
    ) -> bool {
        let mut entries = self.entries.lock().await;
        let before_expiry_retain = entries.len();
        entries.retain(|_, entry| entry.expires_at >= now);
        self.evictions
            .fetch_add(before_expiry_retain - entries.len(), Ordering::Relaxed);
        let key = format!("{issuer}:{jti}");
        if entries.contains_key(&key) {
            return false;
        }
        while entries.len() >= max_entries {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_sequence)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        entries.insert(
            key,
            FederationReplayEntry {
                expires_at: exp.saturating_add(clock_leeway_seconds as i64),
                inserted_sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed),
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn federation_replay_store_retains_jti_until_exp_plus_leeway() {
        let store = FederationReplayStore::default();

        assert!(
            store
                .insert_once("https://issuer.example", "01JTI", 100, 60, 100, 10)
                .await
        );
        assert!(
            !store
                .insert_once("https://issuer.example", "01JTI", 100, 60, 150, 10)
                .await
        );
        assert!(
            store
                .insert_once("https://issuer.example", "01JTI", 100, 60, 161, 10)
                .await
        );
        assert_eq!(store.evictions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn federation_replay_store_evicts_oldest_inserted_entry_when_full() {
        let store = FederationReplayStore::default();

        assert!(store.insert_once("issuer", "a", 1000, 0, 0, 2).await);
        assert!(store.insert_once("issuer", "b", 1000, 0, 0, 2).await);
        assert!(store.insert_once("issuer", "c", 1000, 0, 0, 2).await);

        assert!(!store.insert_once("issuer", "b", 1000, 0, 0, 2).await);
        assert_eq!(store.evictions.load(Ordering::Relaxed), 1);
    }
}
