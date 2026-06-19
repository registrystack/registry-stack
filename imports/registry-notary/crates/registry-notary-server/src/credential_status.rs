// SPDX-License-Identifier: Apache-2.0
//! Storage-backed SD-JWT VC credential status records.

use std::collections::hash_map::DefaultHasher;
use std::env;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use registry_notary_core::{
    CredentialStatusConfig, CREDENTIAL_STATUS_EXPIRED, CREDENTIAL_STATUS_REVOKED,
    CREDENTIAL_STATUS_STORAGE_REDIS, CREDENTIAL_STATUS_SUSPENDED, CREDENTIAL_STATUS_VALID,
};
use registry_platform_cache::{
    CacheKey, CacheKeyError, CacheStore, CacheStoreError, InMemoryCacheStore, RedisCacheBuildError,
    RedisCacheStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

type CredentialStatusTransitionLock = Arc<tokio::sync::Mutex<()>>;
type CredentialStatusTransitionLocks = Arc<Vec<CredentialStatusTransitionLock>>;
const CREDENTIAL_STATUS_TRANSITION_LOCK_STRIPES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum CredentialStatusBuildError {
    #[error("credential status redis URL environment variable is missing or empty: {0}")]
    MissingRedisUrlEnv(String),
    #[error("credential status redis store could not be built")]
    InvalidRedisStore(#[source] RedisCacheBuildError),
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialStatusStoreError {
    #[error("credential status record is invalid")]
    InvalidRecord,
    #[error("credential status transition is invalid")]
    InvalidTransition,
    #[error("credential status key is invalid")]
    InvalidKey(#[source] CacheKeyError),
    #[error("credential status store failed")]
    Store(#[source] CacheStoreError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CredentialStatusRecord {
    pub credential_id: String,
    pub issuer: String,
    pub credential_profile: String,
    pub status: String,
    pub issued_at: String,
    pub expires_at: String,
    pub updated_at: String,
}

impl CredentialStatusRecord {
    pub(crate) fn effective_status(&self, now: OffsetDateTime) -> String {
        if self.status == CREDENTIAL_STATUS_REVOKED {
            return CREDENTIAL_STATUS_REVOKED.to_string();
        }
        if self.status == CREDENTIAL_STATUS_SUSPENDED {
            return CREDENTIAL_STATUS_SUSPENDED.to_string();
        }
        let expired = OffsetDateTime::parse(&self.expires_at, &Rfc3339).is_ok_and(|exp| exp <= now);
        if expired {
            CREDENTIAL_STATUS_EXPIRED.to_string()
        } else {
            self.status.clone()
        }
    }

    pub(crate) fn response_body(&self, now: OffsetDateTime) -> Value {
        json!({
            "credential_id": self.credential_id,
            "issuer": self.issuer,
            "credential_profile": self.credential_profile,
            "status": self.effective_status(now),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "updated_at": self.updated_at,
        })
    }
}

#[derive(Clone)]
pub(crate) struct CredentialStatusStore {
    enabled: bool,
    base_url: String,
    retention_seconds: u64,
    key_prefix: String,
    store: Option<Arc<dyn CacheStore>>,
    redis_ready: Option<Arc<RedisCacheStore>>,
    transition_locks: CredentialStatusTransitionLocks,
}

impl std::fmt::Debug for CredentialStatusStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStatusStore")
            .field("enabled", &self.enabled)
            .field("base_url", &self.base_url)
            .field("retention_seconds", &self.retention_seconds)
            .field("key_prefix", &self.key_prefix)
            .field("store", &self.store.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CredentialStatusStore {
    pub(crate) fn from_config(
        config: &CredentialStatusConfig,
    ) -> Result<Self, CredentialStatusBuildError> {
        if !config.enabled {
            return Ok(Self::disabled());
        }
        match config.storage.as_str() {
            CREDENTIAL_STATUS_STORAGE_REDIS => {
                let url = env::var(&config.redis.url_env)
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        CredentialStatusBuildError::MissingRedisUrlEnv(config.redis.url_env.clone())
                    })?;
                let redis = Arc::new(
                    RedisCacheStore::new(
                        &url,
                        Duration::from_millis(config.redis.connect_timeout_ms),
                        Duration::from_millis(config.redis.operation_timeout_ms),
                    )
                    .map_err(CredentialStatusBuildError::InvalidRedisStore)?,
                );
                Ok(Self {
                    enabled: true,
                    base_url: config.base_url.trim_end_matches('/').to_string(),
                    retention_seconds: config.retention_seconds,
                    key_prefix: config.redis.key_prefix.clone(),
                    store: Some(redis.clone()),
                    redis_ready: Some(redis),
                    transition_locks: transition_locks(),
                })
            }
            _ => Ok(Self {
                enabled: true,
                base_url: config.base_url.trim_end_matches('/').to_string(),
                retention_seconds: config.retention_seconds,
                key_prefix: "registry-notary".to_string(),
                store: Some(Arc::new(InMemoryCacheStore::new())),
                redis_ready: None,
                transition_locks: transition_locks(),
            }),
        }
    }

    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            retention_seconds: 86_400,
            key_prefix: "registry-notary".to_string(),
            store: None,
            redis_ready: None,
            transition_locks: transition_locks(),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn status_claim(&self, credential_id: &str) -> Option<Value> {
        self.enabled.then(|| {
            json!({
                "status_list": {
                    "idx": 0,
                    "uri": self.status_url(credential_id),
                }
            })
        })
    }

    pub(crate) fn status_url(&self, credential_id: &str) -> String {
        format!("{}/v1/credentials/{}/status", self.base_url, credential_id)
    }

    pub(crate) async fn record_issued(
        &self,
        credential_id: String,
        issuer: String,
        credential_profile: String,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), CredentialStatusStoreError> {
        if !self.enabled {
            return Ok(());
        }
        let record = CredentialStatusRecord {
            credential_id,
            issuer,
            credential_profile,
            status: CREDENTIAL_STATUS_VALID.to_string(),
            issued_at: format_time(issued_at),
            expires_at: format_time(expires_at),
            updated_at: format_time(OffsetDateTime::now_utc()),
        };
        self.write_record(&record).await
    }

    pub(crate) async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<CredentialStatusRecord>, CredentialStatusStoreError> {
        if !self.enabled {
            return Ok(None);
        }
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let key = self.key(credential_id)?;
        let Some(raw) = store
            .get(&key)
            .await
            .map_err(CredentialStatusStoreError::Store)?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&raw).map_err(|_| CredentialStatusStoreError::InvalidRecord)
    }

    pub(crate) async fn update_status(
        &self,
        credential_id: &str,
        status: &str,
    ) -> Result<Option<CredentialStatusRecord>, CredentialStatusStoreError> {
        if !self.enabled {
            return Ok(None);
        }
        let transition_lock = self.transition_lock(credential_id);
        let _transition_guard = transition_lock.lock().await;
        // This guard makes the read-check-write transition atomic for the
        // process-local memory store. Redis still relies on this process-local
        // guard because CacheStore does not expose compare-and-set or Lua.
        let Some(mut record) = self.get(credential_id).await? else {
            return Ok(None);
        };
        if record.status == CREDENTIAL_STATUS_REVOKED && status != CREDENTIAL_STATUS_REVOKED {
            return Err(CredentialStatusStoreError::InvalidTransition);
        }
        record.status = status.to_string();
        record.updated_at = format_time(OffsetDateTime::now_utc());
        self.write_record(&record).await?;
        Ok(Some(record))
    }

    pub(crate) async fn check_ready(&self) -> Result<(), CacheStoreError> {
        match &self.redis_ready {
            Some(redis) => redis.check_ready().await,
            None => Ok(()),
        }
    }

    async fn write_record(
        &self,
        record: &CredentialStatusRecord,
    ) -> Result<(), CredentialStatusStoreError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        let retention_seconds = i64::try_from(self.retention_seconds)
            .map_err(|_| CredentialStatusStoreError::InvalidRecord)?;
        let expires_at = OffsetDateTime::parse(&record.expires_at, &Rfc3339)
            .map_err(|_| CredentialStatusStoreError::InvalidRecord)?
            .checked_add(time::Duration::seconds(retention_seconds))
            .ok_or(CredentialStatusStoreError::InvalidRecord)?;
        let key = self.key(&record.credential_id)?;
        let value =
            serde_json::to_vec(record).map_err(|_| CredentialStatusStoreError::InvalidRecord)?;
        store
            .set(&key, &value, expires_at)
            .await
            .map_err(CredentialStatusStoreError::Store)
    }

    fn key(&self, credential_id: &str) -> Result<CacheKey, CredentialStatusStoreError> {
        CacheKey::from_hashed_parts(
            &self.key_prefix,
            "credential-status",
            [("credential_id", credential_id)],
        )
        .map_err(CredentialStatusStoreError::InvalidKey)
    }

    fn transition_lock(&self, credential_id: &str) -> CredentialStatusTransitionLock {
        let mut hasher = DefaultHasher::new();
        credential_id.hash(&mut hasher);
        let bucket = hasher.finish() as usize % self.transition_locks.len();
        Arc::clone(&self.transition_locks[bucket])
    }
}

pub(crate) fn is_mutable_status(value: &str) -> bool {
    matches!(
        value,
        CREDENTIAL_STATUS_VALID | CREDENTIAL_STATUS_SUSPENDED | CREDENTIAL_STATUS_REVOKED
    )
}

pub(crate) fn status_list_value(status: &str) -> u8 {
    match status {
        CREDENTIAL_STATUS_VALID => 0,
        CREDENTIAL_STATUS_SUSPENDED => 2,
        _ => 1,
    }
}

pub(crate) fn encoded_single_entry_status_list(status: &str) -> &'static str {
    match status_list_value(status) {
        0 => "eJxjAAAAAQAB",
        2 => "eJxjAgAAAwAD",
        _ => "eJxjBAAAAgAC",
    }
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

fn transition_locks() -> CredentialStatusTransitionLocks {
    Arc::new(
        (0..CREDENTIAL_STATUS_TRANSITION_LOCK_STRIPES)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use registry_notary_core::CredentialStatusRedisConfig;
    use registry_platform_cache::CacheSetOutcome;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;

    struct BlockingInMemoryCacheStore {
        inner: InMemoryCacheStore,
        block_next_suspended_set: AtomicBool,
        suspended_set_started: Notify,
        release_suspended_set: Notify,
        revoked_set_finished: Notify,
    }

    impl BlockingInMemoryCacheStore {
        fn new() -> Self {
            Self {
                inner: InMemoryCacheStore::new(),
                block_next_suspended_set: AtomicBool::new(true),
                suspended_set_started: Notify::new(),
                release_suspended_set: Notify::new(),
                revoked_set_finished: Notify::new(),
            }
        }
    }

    #[async_trait]
    impl CacheStore for BlockingInMemoryCacheStore {
        async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheStoreError> {
            self.inner.get(key).await
        }

        async fn set(
            &self,
            key: &CacheKey,
            value: &[u8],
            expires_at: OffsetDateTime,
        ) -> Result<(), CacheStoreError> {
            let status = serde_json::from_slice::<CredentialStatusRecord>(value)
                .ok()
                .map(|record| record.status);
            if status.as_deref() == Some(CREDENTIAL_STATUS_SUSPENDED)
                && self.block_next_suspended_set.swap(false, Ordering::SeqCst)
            {
                self.suspended_set_started.notify_one();
                self.release_suspended_set.notified().await;
            }
            let result = self.inner.set(key, value, expires_at).await;
            if status.as_deref() == Some(CREDENTIAL_STATUS_REVOKED) {
                self.revoked_set_finished.notify_one();
            }
            result
        }

        async fn set_if_absent(
            &self,
            key: &CacheKey,
            value: &[u8],
            expires_at: OffsetDateTime,
        ) -> Result<CacheSetOutcome, CacheStoreError> {
            self.inner.set_if_absent(key, value, expires_at).await
        }

        async fn delete(&self, key: &CacheKey) -> Result<bool, CacheStoreError> {
            self.inner.delete(key).await
        }

        async fn check_ready(&self) -> Result<(), CacheStoreError> {
            Ok(())
        }
    }

    fn memory_store() -> CredentialStatusStore {
        CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example/".to_string(),
            retention_seconds: 60,
            ..CredentialStatusConfig::default()
        })
        .expect("store builds")
    }

    fn memory_store_with_cache(cache: Arc<dyn CacheStore>) -> CredentialStatusStore {
        CredentialStatusStore {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            retention_seconds: 60,
            key_prefix: "registry-notary".to_string(),
            store: Some(cache),
            redis_ready: None,
            transition_locks: transition_locks(),
        }
    }

    async fn record_test_credential(store: &CredentialStatusStore, credential_id: &str) {
        let issued_at = OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(120);
        store
            .record_issued(
                credential_id.to_string(),
                "did:web:issuer.example".to_string(),
                "civil_status_sd_jwt".to_string(),
                issued_at,
                expires_at,
            )
            .await
            .expect("record writes");
    }

    #[tokio::test]
    async fn memory_store_records_updates_and_derives_expired_status() {
        let store = memory_store();
        let issued_at = OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(10);

        store
            .record_issued(
                "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC".to_string(),
                "did:web:issuer.example".to_string(),
                "civil_status_sd_jwt".to_string(),
                issued_at,
                expires_at,
            )
            .await
            .expect("record writes");
        let record = store
            .get("urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC")
            .await
            .expect("lookup succeeds")
            .expect("record exists");
        assert_eq!(record.status, CREDENTIAL_STATUS_VALID);
        assert_eq!(record.effective_status(issued_at), CREDENTIAL_STATUS_VALID);
        assert_eq!(
            record.effective_status(expires_at + time::Duration::seconds(1)),
            CREDENTIAL_STATUS_EXPIRED
        );

        let revoked = store
            .update_status(
                "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NC",
                CREDENTIAL_STATUS_REVOKED,
            )
            .await
            .expect("update succeeds")
            .expect("record exists");
        assert_eq!(
            revoked.effective_status(expires_at + time::Duration::seconds(1)),
            CREDENTIAL_STATUS_REVOKED
        );
    }

    #[tokio::test]
    async fn memory_store_allows_valid_and_suspended_until_revoked() {
        let store = memory_store();
        let credential_id = "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8ND";
        record_test_credential(&store, credential_id).await;

        let suspended = store
            .update_status(credential_id, CREDENTIAL_STATUS_SUSPENDED)
            .await
            .expect("valid to suspended succeeds")
            .expect("record exists");
        assert_eq!(suspended.status, CREDENTIAL_STATUS_SUSPENDED);

        let valid = store
            .update_status(credential_id, CREDENTIAL_STATUS_VALID)
            .await
            .expect("suspended to valid succeeds")
            .expect("record exists");
        assert_eq!(valid.status, CREDENTIAL_STATUS_VALID);

        let revoked = store
            .update_status(credential_id, CREDENTIAL_STATUS_REVOKED)
            .await
            .expect("valid to revoked succeeds")
            .expect("record exists");
        assert_eq!(revoked.status, CREDENTIAL_STATUS_REVOKED);
    }

    #[tokio::test]
    async fn memory_store_rejects_revoked_to_valid_transition() {
        let store = memory_store();
        let credential_id = "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NE";
        record_test_credential(&store, credential_id).await;
        store
            .update_status(credential_id, CREDENTIAL_STATUS_REVOKED)
            .await
            .expect("revocation succeeds")
            .expect("record exists");

        let err = store
            .update_status(credential_id, CREDENTIAL_STATUS_VALID)
            .await
            .expect_err("revoked credential must not become valid");
        assert!(matches!(err, CredentialStatusStoreError::InvalidTransition));

        let record = store
            .get(credential_id)
            .await
            .expect("lookup succeeds")
            .expect("record exists");
        assert_eq!(record.status, CREDENTIAL_STATUS_REVOKED);
    }

    #[tokio::test]
    async fn memory_store_rejects_revoked_to_suspended_transition() {
        let store = memory_store();
        let credential_id = "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NF";
        record_test_credential(&store, credential_id).await;
        store
            .update_status(credential_id, CREDENTIAL_STATUS_REVOKED)
            .await
            .expect("revocation succeeds")
            .expect("record exists");

        let err = store
            .update_status(credential_id, CREDENTIAL_STATUS_SUSPENDED)
            .await
            .expect_err("revoked credential must not become suspended");
        assert!(matches!(err, CredentialStatusStoreError::InvalidTransition));

        let record = store
            .get(credential_id)
            .await
            .expect("lookup succeeds")
            .expect("record exists");
        assert_eq!(record.status, CREDENTIAL_STATUS_REVOKED);
    }

    #[tokio::test]
    async fn memory_store_concurrent_revoke_wins_over_stale_non_revoked_update() {
        let cache = Arc::new(BlockingInMemoryCacheStore::new());
        let store = memory_store_with_cache(cache.clone());
        let credential_id = "urn:ulid:01HX7Y5F2WAJ7ZP0Q4M5K9E8NG";
        record_test_credential(&store, credential_id).await;

        let suspended_store = store.clone();
        let suspended_update = tokio::spawn(async move {
            suspended_store
                .update_status(credential_id, CREDENTIAL_STATUS_SUSPENDED)
                .await
        });
        cache.suspended_set_started.notified().await;

        let revoked_store = store.clone();
        let revoked_update = tokio::spawn(async move {
            revoked_store
                .update_status(credential_id, CREDENTIAL_STATUS_REVOKED)
                .await
        });
        let revoked_before_suspended_released = tokio::time::timeout(
            Duration::from_millis(50),
            cache.revoked_set_finished.notified(),
        )
        .await;
        assert!(
            revoked_before_suspended_released.is_err(),
            "revocation must wait for the in-flight non-revoked transition"
        );

        cache.release_suspended_set.notify_waiters();
        let suspended = suspended_update
            .await
            .expect("suspended task joins")
            .expect("suspended update succeeds")
            .expect("record exists");
        assert_eq!(suspended.status, CREDENTIAL_STATUS_SUSPENDED);
        let revoked = revoked_update
            .await
            .expect("revoked task joins")
            .expect("revoked update succeeds")
            .expect("record exists");
        assert_eq!(revoked.status, CREDENTIAL_STATUS_REVOKED);

        let record = store
            .get(credential_id)
            .await
            .expect("lookup succeeds")
            .expect("record exists");
        assert_eq!(record.status, CREDENTIAL_STATUS_REVOKED);
    }

    #[tokio::test]
    async fn redis_store_records_reads_updates_and_checks_readiness_when_env_is_set() {
        if env::var("REGISTRY_PLATFORM_REDIS_TEST_URL").is_err() {
            return;
        }
        let credential_id = format!(
            "urn:registry-notary:test:{}:{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let store = CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example/".to_string(),
            storage: CREDENTIAL_STATUS_STORAGE_REDIS.to_string(),
            retention_seconds: 60,
            redis: CredentialStatusRedisConfig {
                url_env: "REGISTRY_PLATFORM_REDIS_TEST_URL".to_string(),
                key_prefix: format!(
                    "registry-notary-credential-status-test:{}:{}",
                    std::process::id(),
                    OffsetDateTime::now_utc().unix_timestamp_nanos()
                ),
                connect_timeout_ms: 500,
                operation_timeout_ms: 500,
            },
        })
        .expect("redis credential status store builds");
        if store.check_ready().await.is_err() {
            return;
        }

        let issued_at = OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(120);
        store
            .record_issued(
                credential_id.clone(),
                "did:web:issuer.example".to_string(),
                "civil_status_sd_jwt".to_string(),
                issued_at,
                expires_at,
            )
            .await
            .expect("redis record writes");

        let record = store
            .get(&credential_id)
            .await
            .expect("redis lookup succeeds")
            .expect("redis record exists");
        assert_eq!(record.credential_id, credential_id);
        assert_eq!(record.issuer, "did:web:issuer.example");
        assert_eq!(record.credential_profile, "civil_status_sd_jwt");
        assert_eq!(record.status, CREDENTIAL_STATUS_VALID);

        let suspended = store
            .update_status(&credential_id, CREDENTIAL_STATUS_SUSPENDED)
            .await
            .expect("redis update succeeds")
            .expect("redis record exists");
        assert_eq!(suspended.status, CREDENTIAL_STATUS_SUSPENDED);

        let reread = store
            .get(&credential_id)
            .await
            .expect("redis reread succeeds")
            .expect("redis record still exists");
        assert_eq!(reread.status, CREDENTIAL_STATUS_SUSPENDED);

        if let Some(cache) = store.store.as_ref() {
            let key = store.key(&credential_id).expect("redis cleanup key builds");
            let _ = cache.delete(&key).await;
        }
    }

    #[test]
    fn status_claim_uses_trimmed_base_url() {
        let store = CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example/".to_string(),
            ..CredentialStatusConfig::default()
        })
        .expect("store builds");

        assert_eq!(
            store.status_claim("credential-1"),
            Some(json!({
                "status_list": {
                    "idx": 0,
                    "uri": "https://issuer.example/v1/credentials/credential-1/status"
                }
            }))
        );
    }

    #[test]
    fn status_list_values_use_registered_token_status_codes() {
        assert_eq!(status_list_value(CREDENTIAL_STATUS_VALID), 0);
        assert_eq!(status_list_value(CREDENTIAL_STATUS_REVOKED), 1);
        assert_eq!(status_list_value(CREDENTIAL_STATUS_EXPIRED), 1);
        assert_eq!(status_list_value(CREDENTIAL_STATUS_SUSPENDED), 2);
        assert_eq!(
            encoded_single_entry_status_list(CREDENTIAL_STATUS_VALID),
            "eJxjAAAAAQAB"
        );
    }
}
