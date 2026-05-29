// SPDX-License-Identifier: Apache-2.0
//! Storage-backed SD-JWT VC credential status records.

use std::env;
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
                })
            }
            _ => Ok(Self {
                enabled: true,
                base_url: config.base_url.trim_end_matches('/').to_string(),
                retention_seconds: config.retention_seconds,
                key_prefix: "registry-notary".to_string(),
                store: Some(Arc::new(InMemoryCacheStore::new())),
                redis_ready: None,
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
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn status_claim(&self, credential_id: &str) -> Option<Value> {
        self.enabled.then(|| {
            json!({
                "type": "RegistryNotaryCredentialStatus",
                "statusUrl": self.status_url(credential_id),
            })
        })
    }

    pub(crate) fn status_url(&self, credential_id: &str) -> String {
        format!("{}/credentials/status/{}", self.base_url, credential_id)
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
        let Some(mut record) = self.get(credential_id).await? else {
            return Ok(None);
        };
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
}

pub(crate) fn is_mutable_status(value: &str) -> bool {
    matches!(
        value,
        CREDENTIAL_STATUS_VALID | CREDENTIAL_STATUS_SUSPENDED | CREDENTIAL_STATUS_REVOKED
    )
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("OffsetDateTime within supported RFC3339 range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_notary_core::CredentialStatusRedisConfig;

    #[tokio::test]
    async fn memory_store_records_updates_and_derives_expired_status() {
        let store = CredentialStatusStore::from_config(&CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example/".to_string(),
            retention_seconds: 60,
            ..CredentialStatusConfig::default()
        })
        .expect("store builds");
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
                "type": "RegistryNotaryCredentialStatus",
                "statusUrl": "https://issuer.example/credentials/status/credential-1"
            }))
        );
    }
}
