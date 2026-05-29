// SPDX-License-Identifier: Apache-2.0
//! Replay-store wiring for Registry Notary one-time identifiers.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use registry_notary_core::{ReplayConfig, REPLAY_STORAGE_REDIS};
use registry_platform_replay::{
    require_insert_once, ConsumableNonceStore, InMemoryConsumableNonceStore, InMemoryReplayStore,
    RedisReplayBuildError, RedisReplayStore, ReplayKey, ReplayScope, ReplayStore, ReplayStoreError,
    RequiredReplayError,
};
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum ReplayBuildError {
    #[error("replay redis URL environment variable is missing or empty: {0}")]
    MissingRedisUrlEnv(String),
    #[error("replay redis store could not be built")]
    InvalidRedisStore(#[source] RedisReplayBuildError),
}

#[derive(Clone)]
pub(crate) struct ReplayStores {
    store: Arc<dyn ReplayStore>,
    nonce_store: Arc<dyn ConsumableNonceStore>,
    redis_ready: Option<Arc<RedisReplayStore>>,
}

impl std::fmt::Debug for ReplayStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayStores")
            .field("store", &"<redacted>")
            .field("nonce_store", &"<redacted>")
            .finish()
    }
}

impl ReplayStores {
    pub(crate) fn from_config(config: &ReplayConfig) -> Result<Self, ReplayBuildError> {
        match config.storage.as_str() {
            REPLAY_STORAGE_REDIS => {
                let url = env::var(&config.redis.url_env)
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        ReplayBuildError::MissingRedisUrlEnv(config.redis.url_env.clone())
                    })?;
                let store = Arc::new(
                    RedisReplayStore::new(
                        &url,
                        config.redis.key_prefix.clone(),
                        Duration::from_millis(config.redis.connect_timeout_ms),
                        Duration::from_millis(config.redis.operation_timeout_ms),
                    )
                    .map_err(ReplayBuildError::InvalidRedisStore)?,
                );
                Ok(Self {
                    store: store.clone(),
                    nonce_store: store.clone(),
                    redis_ready: Some(store),
                })
            }
            _ => {
                let store = Arc::new(InMemoryReplayStore::new());
                let nonce_store = Arc::new(InMemoryConsumableNonceStore::new());
                Ok(Self {
                    store,
                    nonce_store,
                    redis_ready: None,
                })
            }
        }
    }

    pub(crate) fn memory() -> Self {
        let store = Arc::new(InMemoryReplayStore::new());
        let nonce_store = Arc::new(InMemoryConsumableNonceStore::new());
        Self {
            store,
            nonce_store,
            redis_ready: None,
        }
    }

    pub(crate) fn store(&self) -> Arc<dyn ReplayStore> {
        Arc::clone(&self.store)
    }

    pub(crate) fn nonce_store(&self) -> Arc<dyn ConsumableNonceStore> {
        Arc::clone(&self.nonce_store)
    }

    pub(crate) async fn check_ready(&self) -> Result<(), ReplayStoreError> {
        match &self.redis_ready {
            Some(redis) => redis.check_ready().await,
            None => Ok(()),
        }
    }
}

pub(crate) async fn require_replay_insert(
    store: &dyn ReplayStore,
    scope: &ReplayScope,
    key: &ReplayKey,
    expires_at: OffsetDateTime,
) -> Result<(), RequiredReplayError> {
    require_insert_once(store, scope, key, expires_at).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_replay::{ReplayInsertOutcome, DEFAULT_IN_MEMORY_NONCE_MAX_ENTRIES};

    fn oid4vci_nonce_scope() -> ReplayScope {
        ReplayScope::oid4vci_nonce(
            "tenant.example",
            "https://issuer.example",
            "person_is_alive_sd_jwt",
        )
        .expect("scope is valid")
    }

    #[tokio::test]
    async fn memory_nonce_store_consumes_once_and_rejects_replay() {
        let stores = ReplayStores::memory();
        let scope = oid4vci_nonce_scope();
        let key = ReplayKey::new("nonce-digest-1").expect("key is valid");
        let wrong_scope = ReplayScope::oid4vci_nonce(
            "tenant.example",
            "https://issuer.example",
            "other_credential_sd_jwt",
        )
        .expect("scope is valid");

        stores
            .nonce_store()
            .reserve_nonce(
                &scope,
                &key,
                OffsetDateTime::now_utc() + time::Duration::seconds(60),
            )
            .await
            .expect("nonce reserves");

        assert_eq!(
            stores
                .nonce_store()
                .consume_nonce(&wrong_scope, &key)
                .await
                .expect("wrong scope checks cleanly"),
            ReplayInsertOutcome::AlreadySeen
        );
        assert_eq!(
            stores
                .nonce_store()
                .consume_nonce(&scope, &key)
                .await
                .expect("first nonce use succeeds"),
            ReplayInsertOutcome::Inserted
        );
        assert_eq!(
            stores
                .nonce_store()
                .consume_nonce(&scope, &key)
                .await
                .expect("second nonce use checks cleanly"),
            ReplayInsertOutcome::AlreadySeen
        );
    }

    #[tokio::test]
    async fn memory_replay_store_rejects_holder_proof_duplicate() {
        let stores = ReplayStores::memory();
        let scope = ReplayScope::holder_proof_jwt(
            "tenant.example",
            "https://issuer.example",
            "person_is_alive_sd_jwt",
            "holder-thumbprint",
        )
        .expect("scope is valid");
        let key = ReplayKey::new("holder-proof-jti").expect("key is valid");
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(60);

        require_replay_insert(stores.store().as_ref(), &scope, &key, expires_at)
            .await
            .expect("first proof use succeeds");
        assert!(matches!(
            require_replay_insert(stores.store().as_ref(), &scope, &key, expires_at).await,
            Err(RequiredReplayError::AlreadySeen)
        ));
    }

    #[tokio::test]
    async fn memory_nonce_store_rejects_reservations_over_cap() {
        let store = InMemoryConsumableNonceStore::new();
        let scope = oid4vci_nonce_scope();
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(60);

        for index in 0..DEFAULT_IN_MEMORY_NONCE_MAX_ENTRIES {
            store
                .reserve_nonce(
                    &scope,
                    &ReplayKey::new(format!("nonce-{index}")).expect("key is valid"),
                    expires_at,
                )
                .await
                .expect("nonce below cap reserves");
        }

        let err = store
            .reserve_nonce(
                &scope,
                &ReplayKey::new("nonce-over-cap").expect("key is valid"),
                expires_at,
            )
            .await
            .expect_err("nonce over cap fails closed");
        assert!(
            err.to_string().contains("in-memory cache store is full"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn redis_keys_hash_scope_and_key_material() {
        let store = RedisReplayStore::new(
            "redis://127.0.0.1:6379/",
            "registry-notary",
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .expect("redis URL is syntactically valid");
        let scope = ReplayScope::federation_request_jwt(
            "tenant-secret",
            "https://peer.example/issuer",
            "https://notary.example",
            "profile-sensitive",
        )
        .expect("scope is valid");
        let key = ReplayKey::new("jti-sensitive-123").expect("key is valid");

        let redis_key = store
            .redis_key("one-time", &scope, &key)
            .expect("redis key builds");

        assert!(redis_key.starts_with("registry-notary:one-time:"));
        assert!(!redis_key.contains("tenant-secret"));
        assert!(!redis_key.contains("peer.example"));
        assert!(!redis_key.contains("notary.example"));
        assert!(!redis_key.contains("profile-sensitive"));
        assert!(!redis_key.contains("jti-sensitive-123"));
    }
}
