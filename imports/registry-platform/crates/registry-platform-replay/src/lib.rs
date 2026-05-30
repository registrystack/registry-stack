// SPDX-License-Identifier: Apache-2.0
//! Replay-store primitives for one-time JWT ids and nonce values.

use std::{error::Error as StdError, fmt, sync::Arc};

use async_trait::async_trait;
use registry_platform_cache::{
    CacheKey, CacheKeyError, CacheSetOutcome, CacheStore, CacheStoreError, InMemoryCacheStore,
};
#[cfg(feature = "redis")]
use registry_platform_cache::{RedisCacheBuildError, RedisCacheStore};
use thiserror::Error;
use time::OffsetDateTime;

/// A structured namespace for replay identifiers.
///
/// Scopes should include every application boundary needed to keep one protocol,
/// issuer, tenant, credential profile, or peer from colliding with another.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayScope {
    parts: Arc<[(String, String)]>,
}

impl ReplayScope {
    /// Build a scope from ordered `(name, value)` parts.
    ///
    /// The first part is normally the protocol or flow name. Values are stored
    /// as provided, but `Debug` redacts them so accidental logs do not expose
    /// tenant ids, issuer ids, or peer ids.
    pub fn new<I, K, V>(parts: I) -> Result<Self, ReplayKeyError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let parts = parts
            .into_iter()
            .map(|(name, value)| validate_part(name.into(), value.into()))
            .collect::<Result<Vec<_>, _>>()?;

        if parts.is_empty() {
            return Err(ReplayKeyError::EmptyScope);
        }

        Ok(Self {
            parts: Arc::from(parts.into_boxed_slice()),
        })
    }

    /// Recommended scope for Registry Notary federation request JWT `jti`
    /// values.
    pub fn federation_request_jwt(
        tenant: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        profile: impl Into<String>,
    ) -> Result<Self, ReplayKeyError> {
        Self::new([
            (
                "protocol".to_string(),
                "registry-notary-federation/v0.1".to_string(),
            ),
            ("flow".to_string(), "request-jwt".to_string()),
            ("tenant".to_string(), tenant.into()),
            ("issuer".to_string(), issuer.into()),
            ("audience".to_string(), audience.into()),
            ("profile".to_string(), profile.into()),
        ])
    }

    /// Recommended scope for OpenID4VCI `c_nonce` consumption.
    pub fn oid4vci_nonce(
        tenant: impl Into<String>,
        credential_issuer: impl Into<String>,
        credential_configuration_id: impl Into<String>,
    ) -> Result<Self, ReplayKeyError> {
        Self::new([
            ("protocol".to_string(), "openid4vci".to_string()),
            ("flow".to_string(), "c_nonce".to_string()),
            ("tenant".to_string(), tenant.into()),
            ("credential_issuer".to_string(), credential_issuer.into()),
            (
                "credential_configuration_id".to_string(),
                credential_configuration_id.into(),
            ),
        ])
    }

    /// Recommended scope for OpenID4VCI holder proof JWT `jti` values.
    pub fn holder_proof_jwt(
        tenant: impl Into<String>,
        credential_issuer: impl Into<String>,
        credential_configuration_id: impl Into<String>,
        holder_binding: impl Into<String>,
    ) -> Result<Self, ReplayKeyError> {
        Self::new([
            ("protocol".to_string(), "openid4vci".to_string()),
            ("flow".to_string(), "holder-proof-jwt".to_string()),
            ("tenant".to_string(), tenant.into()),
            ("credential_issuer".to_string(), credential_issuer.into()),
            (
                "credential_configuration_id".to_string(),
                credential_configuration_id.into(),
            ),
            ("holder_binding".to_string(), holder_binding.into()),
        ])
    }

    #[must_use]
    pub fn parts(&self) -> &[(String, String)] {
        &self.parts
    }
}

impl fmt::Debug for ReplayScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts = self
            .parts
            .iter()
            .map(|(name, value)| RedactedPart {
                name,
                value_len: value.len(),
            })
            .collect::<Vec<_>>();
        f.debug_struct("ReplayScope")
            .field("parts", &parts)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    value: Arc<str>,
}

impl ReplayKey {
    /// Build a replay key from a caller-owned one-time identifier.
    ///
    /// Pass the smallest one-time identifier needed for replay detection, such
    /// as a JWT `jti`, nonce, or a service-generated digest. Do not pass compact
    /// JWTs, raw credentials, subject identifiers, or holder secrets.
    pub fn new(value: impl Into<String>) -> Result<Self, ReplayKeyError> {
        let value = value.into();
        validate_value("key", &value)?;
        Ok(Self {
            value: Arc::from(value.into_boxed_str()),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayKey")
            .field(
                "value",
                &RedactedValue {
                    len: self.value.len(),
                },
            )
            .finish()
    }
}

/// Result of an attempt to record a one-time replay identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayInsertOutcome {
    /// The scoped key was not already active and is now recorded until expiry.
    Inserted,
    /// The scoped key already exists and has not expired.
    AlreadySeen,
}

/// Async replay store abstraction for durable or in-memory implementations.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Insert a scoped key exactly once until `expires_at`.
    ///
    /// `expires_at` is an absolute UTC expiry. Stores should evict records after
    /// this point and may reject records that are already expired.
    async fn insert_once(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError>;
}

#[async_trait]
pub trait ConsumableNonceStore: Send + Sync {
    async fn reserve_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), ReplayStoreError>;

    async fn consume_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError>;
}

#[derive(Clone)]
pub struct CacheReplayStore {
    cache: Arc<dyn CacheStore>,
    key_prefix: Arc<str>,
}

impl CacheReplayStore {
    #[must_use]
    pub fn new(cache: Arc<dyn CacheStore>, key_prefix: impl Into<String>) -> Self {
        Self {
            cache,
            key_prefix: Arc::from(key_prefix.into().into_boxed_str()),
        }
    }

    pub async fn check_ready(&self) -> Result<(), ReplayStoreError> {
        self.cache.check_ready().await.map_err(Into::into)
    }

    pub fn cache_key(
        &self,
        flow: &str,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<CacheKey, ReplayStoreError> {
        Ok(replay_cache_key(&self.key_prefix, flow, scope, key)?)
    }
}

impl fmt::Debug for CacheReplayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheReplayStore")
            .field("key_prefix", &self.key_prefix)
            .field("cache", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl ReplayStore for CacheReplayStore {
    async fn insert_once(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        let cache_key = self.cache_key("one-time", scope, key)?;
        let outcome = self
            .cache
            .set_if_absent(&cache_key, b"1", expires_at)
            .await?;
        Ok(match outcome {
            CacheSetOutcome::Stored => ReplayInsertOutcome::Inserted,
            CacheSetOutcome::AlreadyExists => ReplayInsertOutcome::AlreadySeen,
        })
    }
}

#[derive(Clone)]
pub struct ConsumableNonceCacheStore {
    cache: Arc<dyn CacheStore>,
    key_prefix: Arc<str>,
}

impl ConsumableNonceCacheStore {
    #[must_use]
    pub fn new(cache: Arc<dyn CacheStore>, key_prefix: impl Into<String>) -> Self {
        Self {
            cache,
            key_prefix: Arc::from(key_prefix.into().into_boxed_str()),
        }
    }

    pub async fn check_ready(&self) -> Result<(), ReplayStoreError> {
        self.cache.check_ready().await.map_err(Into::into)
    }

    pub fn cache_key(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<CacheKey, ReplayStoreError> {
        Ok(replay_cache_key(&self.key_prefix, "nonce", scope, key)?)
    }
}

impl fmt::Debug for ConsumableNonceCacheStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumableNonceCacheStore")
            .field("key_prefix", &self.key_prefix)
            .field("cache", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl ConsumableNonceStore for ConsumableNonceCacheStore {
    async fn reserve_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), ReplayStoreError> {
        let cache_key = self.cache_key(scope, key)?;
        match self
            .cache
            .set_if_absent(&cache_key, b"1", expires_at)
            .await?
        {
            CacheSetOutcome::Stored => Ok(()),
            CacheSetOutcome::AlreadyExists => Err(ReplayStoreError::Operation {
                message: "nonce is already reserved".to_string(),
            }),
        }
    }

    async fn consume_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        let cache_key = self.cache_key(scope, key)?;
        Ok(if self.cache.delete(&cache_key).await? {
            ReplayInsertOutcome::Inserted
        } else {
            ReplayInsertOutcome::AlreadySeen
        })
    }
}

/// In-memory replay store for tests and single-process development.
///
/// This store does not provide cross-process or active-active protection. Use a
/// durable shared backend for production multi-instance deployments.
#[derive(Debug, Clone)]
pub struct InMemoryReplayStore {
    cache: InMemoryCacheStore,
    replay: CacheReplayStore,
}

pub const DEFAULT_IN_MEMORY_REPLAY_MAX_ENTRIES: usize = 4096;

impl InMemoryReplayStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_IN_MEMORY_REPLAY_MAX_ENTRIES)
    }

    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        let cache = InMemoryCacheStore::with_max_entries(max_entries);
        let replay = CacheReplayStore::new(Arc::new(cache.clone()), "registry-platform-replay");
        Self { cache, replay }
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn purge_expired(&self, now: OffsetDateTime) -> usize {
        self.cache.purge_expired(now)
    }
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn insert_once(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        self.replay.insert_once(scope, key, expires_at).await
    }
}

pub const DEFAULT_IN_MEMORY_NONCE_MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
pub struct InMemoryConsumableNonceStore {
    cache: InMemoryCacheStore,
    nonces: ConsumableNonceCacheStore,
}

impl InMemoryConsumableNonceStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_IN_MEMORY_NONCE_MAX_ENTRIES)
    }

    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        let cache = InMemoryCacheStore::with_max_entries(max_entries);
        let nonces =
            ConsumableNonceCacheStore::new(Arc::new(cache.clone()), "registry-platform-replay");
        Self { cache, nonces }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for InMemoryConsumableNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ConsumableNonceStore for InMemoryConsumableNonceStore {
    async fn reserve_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), ReplayStoreError> {
        self.nonces.reserve_nonce(scope, key, expires_at).await
    }

    async fn consume_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        self.nonces.consume_nonce(scope, key).await
    }
}

#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisReplayStore {
    cache: RedisCacheStore,
    replay: CacheReplayStore,
    nonces: ConsumableNonceCacheStore,
}

#[cfg(feature = "redis")]
impl RedisReplayStore {
    pub fn new(
        url: &str,
        key_prefix: impl Into<String>,
        connect_timeout: std::time::Duration,
        operation_timeout: std::time::Duration,
    ) -> Result<Self, RedisReplayBuildError> {
        let redis_cache = RedisCacheStore::new(url, connect_timeout, operation_timeout)?;
        let cache: Arc<dyn CacheStore> = Arc::new(redis_cache.clone());
        let key_prefix = key_prefix.into();
        Ok(Self {
            cache: redis_cache,
            replay: CacheReplayStore::new(Arc::clone(&cache), key_prefix.clone()),
            nonces: ConsumableNonceCacheStore::new(cache, key_prefix),
        })
    }

    pub async fn check_ready(&self) -> Result<(), ReplayStoreError> {
        self.cache.check_ready().await.map_err(Into::into)
    }

    pub fn redis_key(
        &self,
        flow: &str,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<String, ReplayStoreError> {
        Ok(self
            .replay
            .cache_key(flow, scope, key)?
            .as_str()
            .to_string())
    }
}

#[cfg(feature = "redis")]
impl fmt::Debug for RedisReplayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisReplayStore")
            .field("cache", &"<redacted>")
            .field("replay", &self.replay)
            .field("nonces", &self.nonces)
            .finish()
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl ReplayStore for RedisReplayStore {
    async fn insert_once(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        self.replay.insert_once(scope, key, expires_at).await
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl ConsumableNonceStore for RedisReplayStore {
    async fn reserve_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), ReplayStoreError> {
        self.nonces.reserve_nonce(scope, key, expires_at).await
    }

    async fn consume_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        self.nonces.consume_nonce(scope, key).await
    }
}

/// Record a replay key when replay protection is required.
///
/// This helper is intentionally fail closed: store errors and duplicate keys are
/// both returned as errors so callers can deny the request.
pub async fn require_insert_once(
    store: &dyn ReplayStore,
    scope: &ReplayScope,
    key: &ReplayKey,
    expires_at: OffsetDateTime,
) -> Result<(), RequiredReplayError> {
    match store.insert_once(scope, key, expires_at).await {
        Ok(ReplayInsertOutcome::Inserted) => Ok(()),
        Ok(ReplayInsertOutcome::AlreadySeen) => Err(RequiredReplayError::AlreadySeen),
        Err(source) => Err(RequiredReplayError::Store { source }),
    }
}

/// Consume a pre-reserved nonce when replay protection is required.
///
/// This helper is intentionally fail closed: store errors and missing or
/// already-consumed nonces are both returned as errors so callers can deny the
/// request.
pub async fn require_consume_once(
    store: &dyn ConsumableNonceStore,
    scope: &ReplayScope,
    key: &ReplayKey,
) -> Result<(), RequiredReplayError> {
    match store.consume_nonce(scope, key).await {
        Ok(ReplayInsertOutcome::Inserted) => Ok(()),
        Ok(ReplayInsertOutcome::AlreadySeen) => Err(RequiredReplayError::AlreadySeen),
        Err(source) => Err(RequiredReplayError::Store { source }),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayKeyError {
    #[error("replay scope must contain at least one part")]
    EmptyScope,
    #[error("replay {field} must not be empty")]
    EmptyValue { field: &'static str },
    #[error("replay {field} must not contain ASCII control characters")]
    ControlCharacter { field: &'static str },
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReplayStoreError {
    #[error("replay record expiry must be in the future")]
    ExpiredRecord { expires_at: OffsetDateTime },
    #[error("replay store is unavailable: {source}")]
    Unavailable {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("replay store operation failed: {message}")]
    Operation { message: String },
}

impl From<CacheStoreError> for ReplayStoreError {
    fn from(error: CacheStoreError) -> Self {
        match error {
            CacheStoreError::ExpiredRecord { expires_at } => Self::ExpiredRecord { expires_at },
            CacheStoreError::Unavailable { source } => Self::Unavailable { source },
            CacheStoreError::Operation { message } => Self::Operation { message },
            other => Self::Operation {
                message: other.to_string(),
            },
        }
    }
}

impl From<CacheKeyError> for ReplayStoreError {
    fn from(error: CacheKeyError) -> Self {
        Self::Operation {
            message: error.to_string(),
        }
    }
}

#[cfg(feature = "redis")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RedisReplayBuildError {
    #[error("redis replay store could not be built: {0}")]
    Cache(#[from] RedisCacheBuildError),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RequiredReplayError {
    #[error("replay key was already seen")]
    AlreadySeen,
    #[error("required replay protection failed closed: {source}")]
    Store {
        #[source]
        source: ReplayStoreError,
    },
}

fn replay_cache_key(
    key_prefix: &str,
    flow: &str,
    scope: &ReplayScope,
    key: &ReplayKey,
) -> Result<CacheKey, CacheKeyError> {
    let mut parts = Vec::with_capacity(scope.parts().len() + 1);
    for (name, value) in scope.parts() {
        parts.push((name.as_str(), value.as_str()));
    }
    parts.push(("key", key.as_str()));
    CacheKey::from_hashed_parts(key_prefix, flow, parts)
}

struct RedactedPart<'a> {
    name: &'a str,
    value_len: usize,
}

impl fmt::Debug for RedactedPart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayScopePart")
            .field("name", &self.name)
            .field("value_len", &self.value_len)
            .finish()
    }
}

struct RedactedValue {
    len: usize,
}

impl fmt::Debug for RedactedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactedValue")
            .field("len", &self.len)
            .finish()
    }
}

fn validate_part(name: String, value: String) -> Result<(String, String), ReplayKeyError> {
    validate_value("scope part name", &name)?;
    validate_value("scope part value", &value)?;
    Ok((name, value))
}

fn validate_value(field: &'static str, value: &str) -> Result<(), ReplayKeyError> {
    if value.is_empty() {
        return Err(ReplayKeyError::EmptyValue { field });
    }
    if value.chars().any(|ch| ch.is_ascii_control()) {
        return Err(ReplayKeyError::ControlCharacter { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn scope(name: &str) -> ReplayScope {
        ReplayScope::new([("protocol", name), ("issuer", "issuer-a")]).expect("valid scope")
    }

    fn key(value: &str) -> ReplayKey {
        ReplayKey::new(value).expect("valid key")
    }

    fn future() -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::from_secs(60)
    }

    #[tokio::test]
    async fn duplicate_keys_are_rejected_until_expiry() {
        let store = InMemoryReplayStore::new();
        let scope = scope("openid4vci");
        let key = key("nonce-1");

        assert_eq!(
            store.insert_once(&scope, &key, future()).await.unwrap(),
            ReplayInsertOutcome::Inserted
        );
        assert_eq!(
            store.insert_once(&scope, &key, future()).await.unwrap(),
            ReplayInsertOutcome::AlreadySeen
        );
    }

    #[tokio::test]
    async fn same_key_is_accepted_after_expiry() {
        let store = InMemoryReplayStore::new();
        let scope = scope("openid4vci");
        let key = key("nonce-1");

        assert_eq!(
            store
                .insert_once(
                    &scope,
                    &key,
                    OffsetDateTime::now_utc() + Duration::from_millis(10),
                )
                .await
                .unwrap(),
            ReplayInsertOutcome::Inserted
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            store.insert_once(&scope, &key, future()).await.unwrap(),
            ReplayInsertOutcome::Inserted
        );
    }

    #[tokio::test]
    async fn expired_records_can_be_purged_without_insert_scan() {
        let store = InMemoryReplayStore::new();
        let first_scope = scope("openid4vci");
        let second_scope = scope("federation");
        let first_key = key("nonce-1");
        let second_key = key("nonce-2");

        let now = OffsetDateTime::now_utc();
        store
            .insert_once(&first_scope, &first_key, now + Duration::from_millis(10))
            .await
            .expect("first insert succeeds");
        store
            .insert_once(&second_scope, &second_key, now + Duration::from_secs(60))
            .await
            .expect("second insert succeeds");
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(store.len(), 2);
        assert_eq!(store.purge_expired(OffsetDateTime::now_utc()), 1);
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[tokio::test]
    async fn cross_scope_keys_do_not_collide() {
        let store = InMemoryReplayStore::new();
        let first_scope =
            ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("valid scope");
        let second_scope =
            ReplayScope::holder_proof_jwt("tenant-a", "issuer-a", "profile-a", "did:jwk:holder-a")
                .expect("valid scope");
        let key = key("shared-jti");

        assert_eq!(
            store
                .insert_once(&first_scope, &key, future())
                .await
                .unwrap(),
            ReplayInsertOutcome::Inserted
        );
        assert_eq!(
            store
                .insert_once(&second_scope, &key, future())
                .await
                .unwrap(),
            ReplayInsertOutcome::Inserted
        );
    }

    #[tokio::test]
    async fn concurrent_inserts_cannot_both_succeed() {
        let store = Arc::new(InMemoryReplayStore::new());
        let scope = scope("openid4vci");
        let key = key("nonce-1");
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let store = Arc::clone(&store);
            let scope = scope.clone();
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                store.insert_once(&scope, &key, future()).await.unwrap()
            }));
        }

        let mut inserted = 0;
        let mut already_seen = 0;
        for task in tasks {
            match task.await.expect("task joins") {
                ReplayInsertOutcome::Inserted => inserted += 1,
                ReplayInsertOutcome::AlreadySeen => already_seen += 1,
            }
        }

        assert_eq!(inserted, 1);
        assert_eq!(already_seen, 15);
    }

    #[tokio::test]
    async fn in_memory_replay_store_enforces_capacity() {
        let store = InMemoryReplayStore::with_max_entries(1);
        let scope = scope("openid4vci");

        store
            .insert_once(&scope, &key("nonce-1"), future())
            .await
            .expect("first replay key stores");
        let err = store
            .insert_once(&scope, &key("nonce-2"), future())
            .await
            .expect_err("capacity failure is surfaced");
        assert!(err.to_string().contains("in-memory cache store is full"));
    }

    #[tokio::test]
    async fn in_memory_replay_capacity_purges_expired_records() {
        let store = InMemoryReplayStore::with_max_entries(1);
        let scope = scope("openid4vci");

        store
            .insert_once(
                &scope,
                &key("nonce-1"),
                OffsetDateTime::now_utc() + Duration::from_millis(10),
            )
            .await
            .expect("first replay key stores");
        tokio::time::sleep(Duration::from_millis(20)).await;
        store
            .insert_once(&scope, &key("nonce-2"), future())
            .await
            .expect("expired record is purged before capacity is enforced");
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn required_helper_fails_closed_on_duplicates() {
        let store = InMemoryReplayStore::new();
        let scope = scope("openid4vci");
        let key = key("nonce-1");

        require_insert_once(&store, &scope, &key, future())
            .await
            .expect("first insert succeeds");
        assert!(matches!(
            require_insert_once(&store, &scope, &key, future()).await,
            Err(RequiredReplayError::AlreadySeen)
        ));
    }

    #[tokio::test]
    async fn required_consume_helper_fails_closed_on_missing_or_duplicate_nonce() {
        let store = InMemoryConsumableNonceStore::new();
        let scope =
            ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("valid scope");
        let key = key("nonce-1");

        assert!(matches!(
            require_consume_once(&store, &scope, &key).await,
            Err(RequiredReplayError::AlreadySeen)
        ));

        store
            .reserve_nonce(&scope, &key, future())
            .await
            .expect("nonce reserves");
        require_consume_once(&store, &scope, &key)
            .await
            .expect("reserved nonce consumes once");
        assert!(matches!(
            require_consume_once(&store, &scope, &key).await,
            Err(RequiredReplayError::AlreadySeen)
        ));
    }

    #[tokio::test]
    async fn consumable_nonce_store_reserves_and_consumes_once() {
        let store = InMemoryConsumableNonceStore::new();
        let scope =
            ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("valid scope");
        let key = key("nonce-1");
        let wrong_scope =
            ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-b").expect("valid scope");

        store
            .reserve_nonce(&scope, &key, future())
            .await
            .expect("nonce reserves");
        assert_eq!(
            store
                .consume_nonce(&wrong_scope, &key)
                .await
                .expect("wrong scope checks cleanly"),
            ReplayInsertOutcome::AlreadySeen
        );
        assert_eq!(
            store
                .consume_nonce(&scope, &key)
                .await
                .expect("first consume succeeds"),
            ReplayInsertOutcome::Inserted
        );
        assert_eq!(
            store
                .consume_nonce(&scope, &key)
                .await
                .expect("second consume checks cleanly"),
            ReplayInsertOutcome::AlreadySeen
        );
    }

    #[tokio::test]
    async fn consumable_nonce_store_enforces_capacity() {
        let store = InMemoryConsumableNonceStore::with_max_entries(1);
        let scope =
            ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("valid scope");

        store
            .reserve_nonce(&scope, &key("nonce-1"), future())
            .await
            .expect("first nonce reserves");
        let err = store
            .reserve_nonce(&scope, &key("nonce-2"), future())
            .await
            .expect_err("capacity failure is surfaced");
        assert!(err.to_string().contains("in-memory cache store is full"));
    }

    #[test]
    fn cache_replay_keys_hash_scope_and_key_material() {
        let cache = Arc::new(registry_platform_cache::InMemoryCacheStore::new());
        let store = CacheReplayStore::new(cache, "registry-notary");
        let scope = ReplayScope::federation_request_jwt(
            "tenant-secret",
            "https://peer.example/issuer",
            "https://notary.example",
            "profile-sensitive",
        )
        .expect("valid scope");
        let key = key("jti-sensitive-123");

        let cache_key = store
            .cache_key("one-time", &scope, &key)
            .expect("cache key builds");
        let rendered = cache_key.as_str();

        assert!(rendered.starts_with("registry-notary:one-time:"));
        assert!(!rendered.contains("tenant-secret"));
        assert!(!rendered.contains("peer.example"));
        assert!(!rendered.contains("notary.example"));
        assert!(!rendered.contains("profile-sensitive"));
        assert!(!rendered.contains("jti-sensitive-123"));
    }

    #[cfg(feature = "redis")]
    #[test]
    fn redis_replay_store_builds_hashed_keys_without_connecting() {
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
        .expect("valid scope");
        let key = key("jti-sensitive-123");

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

    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn redis_replay_store_round_trips_when_env_is_set() {
        let Ok(url) = std::env::var("REGISTRY_PLATFORM_REDIS_TEST_URL") else {
            return;
        };
        let prefix = format!(
            "registry-platform-replay-test:{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let store = RedisReplayStore::new(
            &url,
            prefix,
            Duration::from_millis(500),
            Duration::from_millis(500),
        )
        .expect("redis replay store builds");
        let scope =
            ReplayScope::oid4vci_nonce("tenant-a", "issuer-a", "profile-a").expect("valid scope");
        let replay_key = key("nonce-1");

        store.check_ready().await.expect("redis is ready");
        assert_eq!(
            store
                .insert_once(&scope, &replay_key, future())
                .await
                .expect("first insert succeeds"),
            ReplayInsertOutcome::Inserted
        );
        assert_eq!(
            store
                .insert_once(&scope, &replay_key, future())
                .await
                .expect("duplicate insert succeeds"),
            ReplayInsertOutcome::AlreadySeen
        );

        let nonce_key = key("nonce-2");
        store
            .reserve_nonce(&scope, &nonce_key, future())
            .await
            .expect("nonce reserves");
        assert_eq!(
            store
                .consume_nonce(&scope, &nonce_key)
                .await
                .expect("first consume succeeds"),
            ReplayInsertOutcome::Inserted
        );
        assert_eq!(
            store
                .consume_nonce(&scope, &nonce_key)
                .await
                .expect("second consume succeeds"),
            ReplayInsertOutcome::AlreadySeen
        );
    }

    #[test]
    fn debug_output_redacts_scope_values_and_key() {
        let scope = ReplayScope::oid4vci_nonce("tenant-secret", "issuer-secret", "profile-secret")
            .expect("valid scope");
        let key = key("raw-secret-token-material");
        let debug = format!("{scope:?} {key:?}");

        assert!(!debug.contains("tenant-secret"));
        assert!(!debug.contains("issuer-secret"));
        assert!(!debug.contains("profile-secret"));
        assert!(!debug.contains("raw-secret-token-material"));
        assert!(debug.contains("value_len"));
        assert!(debug.contains("len"));
    }
}
