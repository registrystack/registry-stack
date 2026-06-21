// SPDX-License-Identifier: Apache-2.0
//! Generic cache-store primitives for registry services.

#[cfg(feature = "redis")]
use std::time::Duration;
use std::{
    collections::HashMap,
    error::Error as StdError,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    value: Arc<str>,
}

impl CacheKey {
    pub fn new(value: impl Into<String>) -> Result<Self, CacheKeyError> {
        let value = value.into();
        validate_key_segment("key", &value)?;
        Ok(Self {
            value: Arc::from(value.into_boxed_str()),
        })
    }

    pub fn from_hashed_parts<I, K, V>(
        prefix: &str,
        purpose: &str,
        parts: I,
    ) -> Result<Self, CacheKeyError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        validate_key_segment("prefix", prefix)?;
        validate_key_segment("purpose", purpose)?;

        let mut hasher = Sha256::new();
        hasher.update(purpose.as_bytes());
        hasher.update([0]);
        let mut seen_part = false;
        for (name, value) in parts {
            let name = name.as_ref();
            let value = value.as_ref();
            validate_hash_part("part name", name)?;
            validate_hash_part("part value", value)?;
            seen_part = true;
            hasher.update((name.len() as u64).to_be_bytes());
            hasher.update(name.as_bytes());
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        if !seen_part {
            return Err(CacheKeyError::EmptyParts);
        }

        Self::new(format!(
            "{prefix}:{purpose}:{}",
            hex_lower(hasher.finalize())
        ))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheKey")
            .field("len", &self.value.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSetOutcome {
    Stored,
    AlreadyExists,
}

/// Result of updating a live cache record only when its bytes match exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheCompareAndSetOutcome {
    /// The current value matched `expected` and the new value was stored.
    Stored,
    /// The key exists and has not expired, but its bytes did not match.
    Mismatch,
    /// The key was absent or the stored record had expired.
    Missing,
}

#[async_trait]
pub trait CacheStore: Send + Sync {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheStoreError>;

    async fn set(
        &self,
        key: &CacheKey,
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), CacheStoreError>;

    async fn set_if_absent(
        &self,
        key: &CacheKey,
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<CacheSetOutcome, CacheStoreError>;

    async fn compare_and_set(
        &self,
        key: &CacheKey,
        expected: &[u8],
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<CacheCompareAndSetOutcome, CacheStoreError>;

    async fn delete(&self, key: &CacheKey) -> Result<bool, CacheStoreError>;

    async fn check_ready(&self) -> Result<(), CacheStoreError>;
}

#[derive(Debug, Clone)]
pub struct InMemoryCacheStore {
    records: Arc<Mutex<HashMap<CacheKey, CacheRecord>>>,
    max_entries: Option<usize>,
}

impl InMemoryCacheStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            max_entries: None,
        }
    }

    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            max_entries: Some(max_entries),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records
            .lock()
            .expect("in-memory cache store lock is healthy")
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn purge_expired(&self, now: OffsetDateTime) -> usize {
        let mut records = self
            .records
            .lock()
            .expect("in-memory cache store lock is healthy");
        purge_expired_locked(&mut records, now)
    }

    fn check_expiry(expires_at: OffsetDateTime) -> Result<(), CacheStoreError> {
        if expires_at <= OffsetDateTime::now_utc() {
            return Err(CacheStoreError::ExpiredRecord { expires_at });
        }
        Ok(())
    }

    fn ensure_capacity(
        &self,
        records: &mut HashMap<CacheKey, CacheRecord>,
        key: &CacheKey,
    ) -> Result<(), CacheStoreError> {
        if records.contains_key(key) {
            return Ok(());
        }
        if let Some(max_entries) = self.max_entries {
            if records.len() >= max_entries {
                purge_expired_locked(records, OffsetDateTime::now_utc());
                if records.len() >= max_entries {
                    return Err(CacheStoreError::Operation {
                        message: "in-memory cache store is full".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl Default for InMemoryCacheStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheStore for InMemoryCacheStore {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheStoreError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .records
            .lock()
            .expect("in-memory cache store lock is healthy");
        if let Some(record) = records.get(key) {
            if record.expires_at > now {
                return Ok(Some(record.value.clone()));
            }
            records.remove(key);
        }
        Ok(None)
    }

    async fn set(
        &self,
        key: &CacheKey,
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), CacheStoreError> {
        Self::check_expiry(expires_at)?;
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .records
            .lock()
            .expect("in-memory cache store lock is healthy");
        if let Some(record) = records.get(key) {
            if record.expires_at <= now {
                records.remove(key);
            }
        }
        self.ensure_capacity(&mut records, key)?;
        records.insert(
            key.clone(),
            CacheRecord {
                value: value.to_vec(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &CacheKey,
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<CacheSetOutcome, CacheStoreError> {
        Self::check_expiry(expires_at)?;
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .records
            .lock()
            .expect("in-memory cache store lock is healthy");
        if let Some(record) = records.get(key) {
            if record.expires_at > now {
                return Ok(CacheSetOutcome::AlreadyExists);
            }
            records.remove(key);
        }
        self.ensure_capacity(&mut records, key)?;
        records.insert(
            key.clone(),
            CacheRecord {
                value: value.to_vec(),
                expires_at,
            },
        );
        Ok(CacheSetOutcome::Stored)
    }

    async fn compare_and_set(
        &self,
        key: &CacheKey,
        expected: &[u8],
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<CacheCompareAndSetOutcome, CacheStoreError> {
        Self::check_expiry(expires_at)?;
        let now = OffsetDateTime::now_utc();
        let mut records = self
            .records
            .lock()
            .expect("in-memory cache store lock is healthy");
        let Some(record) = records.get_mut(key) else {
            return Ok(CacheCompareAndSetOutcome::Missing);
        };
        if record.expires_at <= now {
            records.remove(key);
            return Ok(CacheCompareAndSetOutcome::Missing);
        }
        if record.value != expected {
            return Ok(CacheCompareAndSetOutcome::Mismatch);
        }
        record.value = value.to_vec();
        record.expires_at = expires_at;
        Ok(CacheCompareAndSetOutcome::Stored)
    }

    async fn delete(&self, key: &CacheKey) -> Result<bool, CacheStoreError> {
        let mut records = self
            .records
            .lock()
            .expect("in-memory cache store lock is healthy");
        Ok(records.remove(key).is_some())
    }

    async fn check_ready(&self) -> Result<(), CacheStoreError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct CacheRecord {
    value: Vec<u8>,
    expires_at: OffsetDateTime,
}

fn purge_expired_locked(
    records: &mut HashMap<CacheKey, CacheRecord>,
    now: OffsetDateTime,
) -> usize {
    let before = records.len();
    records.retain(|_, record| record.expires_at > now);
    before - records.len()
}

#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisCacheStore {
    client: redis::Client,
    connection: Arc<tokio::sync::OnceCell<redis::aio::MultiplexedConnection>>,
    connect_timeout: Duration,
    operation_timeout: Duration,
}

#[cfg(feature = "redis")]
impl RedisCacheStore {
    pub fn new(
        url: &str,
        connect_timeout: Duration,
        operation_timeout: Duration,
    ) -> Result<Self, RedisCacheBuildError> {
        let client = redis::Client::open(url).map_err(RedisCacheBuildError::InvalidUrl)?;
        Ok(Self {
            client,
            connection: Arc::new(tokio::sync::OnceCell::new()),
            connect_timeout,
            operation_timeout,
        })
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection, CacheStoreError> {
        self.connection
            .get_or_try_init(|| async {
                tokio::time::timeout(
                    self.connect_timeout,
                    self.client.get_multiplexed_async_connection(),
                )
                .await
                .map_err(|_| CacheStoreError::Operation {
                    message: "redis cache connection timed out".to_string(),
                })?
                .map_err(|source| CacheStoreError::Unavailable {
                    source: Box::new(source),
                })
            })
            .await
            .cloned()
    }

    async fn redis_call<T>(
        &self,
        future: impl std::future::Future<Output = redis::RedisResult<T>>,
    ) -> Result<T, CacheStoreError> {
        tokio::time::timeout(self.operation_timeout, future)
            .await
            .map_err(|_| CacheStoreError::Operation {
                message: "redis cache operation timed out".to_string(),
            })?
            .map_err(|source| CacheStoreError::Unavailable {
                source: Box::new(source),
            })
    }

    fn ttl_ms(expires_at: OffsetDateTime) -> Result<u64, CacheStoreError> {
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(CacheStoreError::ExpiredRecord { expires_at });
        }
        Ok((expires_at - now).whole_milliseconds().max(1) as u64)
    }
}

#[cfg(feature = "redis")]
impl fmt::Debug for RedisCacheStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisCacheStore")
            .field("client", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

#[cfg(feature = "redis")]
const REDIS_COMPARE_AND_SET_SCRIPT: &str = r#"
local current = redis.call("GET", KEYS[1])
if not current then
  return "missing"
end
if current ~= ARGV[1] then
  return "mismatch"
end
redis.call("PSETEX", KEYS[1], ARGV[3], ARGV[2])
return "stored"
"#;

#[cfg(feature = "redis")]
#[async_trait]
impl CacheStore for RedisCacheStore {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheStoreError> {
        let mut connection = self.connection().await?;
        self.redis_call(
            redis::cmd("GET")
                .arg(key.as_str())
                .query_async(&mut connection),
        )
        .await
    }

    async fn set(
        &self,
        key: &CacheKey,
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), CacheStoreError> {
        let ttl_ms = Self::ttl_ms(expires_at)?;
        let mut connection = self.connection().await?;
        let _: String = self
            .redis_call(
                redis::cmd("SET")
                    .arg(key.as_str())
                    .arg(value)
                    .arg("PX")
                    .arg(ttl_ms)
                    .query_async(&mut connection),
            )
            .await?;
        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &CacheKey,
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<CacheSetOutcome, CacheStoreError> {
        let ttl_ms = Self::ttl_ms(expires_at)?;
        let mut connection = self.connection().await?;
        let set: Option<String> = self
            .redis_call(
                redis::cmd("SET")
                    .arg(key.as_str())
                    .arg(value)
                    .arg("PX")
                    .arg(ttl_ms)
                    .arg("NX")
                    .query_async(&mut connection),
            )
            .await?;
        Ok(match set.as_deref() {
            Some("OK") => CacheSetOutcome::Stored,
            _ => CacheSetOutcome::AlreadyExists,
        })
    }

    async fn compare_and_set(
        &self,
        key: &CacheKey,
        expected: &[u8],
        value: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<CacheCompareAndSetOutcome, CacheStoreError> {
        let ttl_ms = Self::ttl_ms(expires_at)?;
        let mut connection = self.connection().await?;
        let outcome: String = self
            .redis_call(
                redis::cmd("EVAL")
                    .arg(REDIS_COMPARE_AND_SET_SCRIPT)
                    .arg(1)
                    .arg(key.as_str())
                    .arg(expected)
                    .arg(value)
                    .arg(ttl_ms)
                    .query_async(&mut connection),
            )
            .await?;
        Ok(match outcome.as_str() {
            "stored" => CacheCompareAndSetOutcome::Stored,
            "mismatch" => CacheCompareAndSetOutcome::Mismatch,
            _ => CacheCompareAndSetOutcome::Missing,
        })
    }

    async fn delete(&self, key: &CacheKey) -> Result<bool, CacheStoreError> {
        let mut connection = self.connection().await?;
        let deleted: i64 = self
            .redis_call(
                redis::cmd("DEL")
                    .arg(key.as_str())
                    .query_async(&mut connection),
            )
            .await?;
        Ok(deleted > 0)
    }

    async fn check_ready(&self) -> Result<(), CacheStoreError> {
        let mut connection = self.connection().await?;
        let _: String = self
            .redis_call(redis::cmd("PING").query_async(&mut connection))
            .await?;
        let readiness_key = CacheKey::new(format!(
            "registry-platform-cache:ready:{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
        .map_err(|error| CacheStoreError::Operation {
            message: error.to_string(),
        })?;
        self.set_if_absent(
            &readiness_key,
            b"1",
            OffsetDateTime::now_utc() + time::Duration::seconds(1),
        )
        .await?;
        let _ = self.delete(&readiness_key).await?;
        Ok(())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CacheKeyError {
    #[error("cache {field} must not be empty")]
    EmptyValue { field: &'static str },
    #[error("cache {field} must not contain ASCII control characters")]
    ControlCharacter { field: &'static str },
    #[error("cache key hash input must contain at least one part")]
    EmptyParts,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CacheStoreError {
    #[error("cache record expiry must be in the future")]
    ExpiredRecord { expires_at: OffsetDateTime },
    #[error("cache store is unavailable: {source}")]
    Unavailable {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("cache store operation failed: {message}")]
    Operation { message: String },
}

#[cfg(feature = "redis")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RedisCacheBuildError {
    #[error("redis cache URL is invalid")]
    InvalidUrl(#[source] redis::RedisError),
}

fn validate_key_segment(field: &'static str, value: &str) -> Result<(), CacheKeyError> {
    validate_hash_part(field, value)?;
    if value.contains([' ', '\t', '\n', '\r']) {
        return Err(CacheKeyError::ControlCharacter { field });
    }
    Ok(())
}

fn validate_hash_part(field: &'static str, value: &str) -> Result<(), CacheKeyError> {
    if value.is_empty() {
        return Err(CacheKeyError::EmptyValue { field });
    }
    if value.chars().any(|ch| ch.is_ascii_control()) {
        return Err(CacheKeyError::ControlCharacter { field });
    }
    Ok(())
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn future() -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::from_secs(60)
    }

    #[tokio::test]
    async fn in_memory_cache_get_set_delete_round_trip() {
        let store = InMemoryCacheStore::new();
        let key = CacheKey::new("test:key").expect("key is valid");

        assert_eq!(store.get(&key).await.expect("get succeeds"), None);
        store
            .set(&key, b"value", future())
            .await
            .expect("set succeeds");
        assert_eq!(
            store.get(&key).await.expect("get succeeds"),
            Some(b"value".to_vec())
        );
        assert!(store.delete(&key).await.expect("delete succeeds"));
        assert_eq!(store.get(&key).await.expect("get succeeds"), None);
    }

    #[tokio::test]
    async fn in_memory_set_if_absent_is_atomic_under_lock() {
        let store = InMemoryCacheStore::new();
        let key = CacheKey::new("test:key").expect("key is valid");

        assert_eq!(
            store
                .set_if_absent(&key, b"one", future())
                .await
                .expect("first set succeeds"),
            CacheSetOutcome::Stored
        );
        assert_eq!(
            store
                .set_if_absent(&key, b"two", future())
                .await
                .expect("second set succeeds"),
            CacheSetOutcome::AlreadyExists
        );
        assert_eq!(
            store.get(&key).await.expect("get succeeds"),
            Some(b"one".to_vec())
        );
    }

    #[tokio::test]
    async fn in_memory_compare_and_set_distinguishes_outcomes() {
        let store = InMemoryCacheStore::new();
        let key = CacheKey::new("test:key").expect("key is valid");

        assert_eq!(
            store
                .compare_and_set(&key, b"one", b"two", future())
                .await
                .expect("missing compare succeeds"),
            CacheCompareAndSetOutcome::Missing
        );

        store
            .set(&key, b"one", future())
            .await
            .expect("set succeeds");
        assert_eq!(
            store
                .compare_and_set(&key, b"wrong", b"two", future())
                .await
                .expect("mismatch compare succeeds"),
            CacheCompareAndSetOutcome::Mismatch
        );
        assert_eq!(
            store.get(&key).await.expect("get succeeds"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            store
                .compare_and_set(&key, b"one", b"two", future())
                .await
                .expect("matching compare succeeds"),
            CacheCompareAndSetOutcome::Stored
        );
        assert_eq!(
            store.get(&key).await.expect("get succeeds"),
            Some(b"two".to_vec())
        );

        let expired_key = CacheKey::new("test:expired").expect("key is valid");
        store.records.lock().unwrap().insert(
            expired_key.clone(),
            CacheRecord {
                value: b"old".to_vec(),
                expires_at: OffsetDateTime::UNIX_EPOCH,
            },
        );
        assert_eq!(
            store
                .compare_and_set(&expired_key, b"old", b"new", future())
                .await
                .expect("expired compare succeeds"),
            CacheCompareAndSetOutcome::Missing
        );
        assert_eq!(store.get(&expired_key).await.expect("get succeeds"), None);
    }

    #[tokio::test]
    async fn in_memory_cache_enforces_optional_capacity() {
        let store = InMemoryCacheStore::with_max_entries(1);
        let first = CacheKey::new("test:first").expect("key is valid");
        let second = CacheKey::new("test:second").expect("key is valid");

        store
            .set(&first, b"one", future())
            .await
            .expect("first set succeeds");
        let err = store
            .set(&second, b"two", future())
            .await
            .expect_err("over capacity fails");
        assert!(err.to_string().contains("in-memory cache store is full"));
    }

    #[test]
    fn hashed_key_omits_sensitive_parts() {
        let key = CacheKey::from_hashed_parts(
            "registry-notary",
            "one-time",
            [
                ("tenant", "tenant-secret"),
                ("issuer", "https://issuer.example"),
                ("jti", "jti-sensitive"),
            ],
        )
        .expect("key hashes");

        assert!(key.as_str().starts_with("registry-notary:one-time:"));
        assert!(!key.as_str().contains("tenant-secret"));
        assert!(!key.as_str().contains("issuer.example"));
        assert!(!key.as_str().contains("jti-sensitive"));
    }

    #[test]
    fn debug_output_redacts_key_value() {
        let key = CacheKey::new("secret:key:material").expect("key is valid");
        let debug = format!("{key:?}");

        assert!(!debug.contains("secret:key:material"));
        assert!(debug.contains("len"));
    }

    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn redis_compare_and_set_round_trips_when_env_is_set() {
        let Ok(url) = std::env::var("REGISTRY_PLATFORM_REDIS_TEST_URL") else {
            return;
        };
        let store =
            RedisCacheStore::new(&url, Duration::from_millis(500), Duration::from_millis(500))
                .expect("redis cache store builds");
        store.check_ready().await.expect("redis is ready");
        let key = CacheKey::new(format!(
            "registry-platform-cache-test:cas:{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
        .expect("key is valid");

        assert_eq!(
            store
                .compare_and_set(&key, b"one", b"two", future())
                .await
                .expect("missing compare succeeds"),
            CacheCompareAndSetOutcome::Missing
        );
        store
            .set(&key, b"one", future())
            .await
            .expect("set succeeds");
        assert_eq!(
            store
                .compare_and_set(&key, b"wrong", b"two", future())
                .await
                .expect("mismatch compare succeeds"),
            CacheCompareAndSetOutcome::Mismatch
        );
        assert_eq!(
            store.get(&key).await.expect("get succeeds"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            store
                .compare_and_set(&key, b"one", b"two", future())
                .await
                .expect("matching compare succeeds"),
            CacheCompareAndSetOutcome::Stored
        );
        assert_eq!(
            store.get(&key).await.expect("get succeeds"),
            Some(b"two".to_vec())
        );
        assert!(store.delete(&key).await.expect("delete succeeds"));
    }
}
