// SPDX-License-Identifier: Apache-2.0
//! Replay-store primitives for one-time JWT ids and nonce values.

use std::{
    collections::HashMap,
    error::Error as StdError,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
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

    /// Recommended scope for Registry Witness federation request JWT `jti`
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
                "registry-witness-federation/v0.1".to_string(),
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

/// In-memory replay store for tests and single-process development.
///
/// This store does not provide cross-process or active-active protection. Use a
/// durable shared backend for production multi-instance deployments.
#[derive(Debug, Default, Clone)]
pub struct InMemoryReplayStore {
    records: Arc<Mutex<HashMap<StoredReplayKey, OffsetDateTime>>>,
}

impl InMemoryReplayStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records
            .lock()
            .expect("in-memory replay store lock is healthy")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.records
            .lock()
            .expect("in-memory replay store lock is healthy")
            .is_empty()
    }

    pub fn purge_expired(&self, now: OffsetDateTime) -> usize {
        let mut records = self
            .records
            .lock()
            .expect("in-memory replay store lock is healthy");
        let before = records.len();
        records.retain(|_, expires_at| *expires_at > now);
        before - records.len()
    }

    fn insert_once_sync(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayInsertOutcome, ReplayStoreError> {
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(ReplayStoreError::ExpiredRecord { expires_at });
        }

        let mut records = self
            .records
            .lock()
            .expect("in-memory replay store lock is healthy");
        let stored_key = StoredReplayKey::new(scope, key);
        match records.get_mut(&stored_key) {
            Some(existing_expires_at) if *existing_expires_at > now => {
                Ok(ReplayInsertOutcome::AlreadySeen)
            }
            _ => {
                records.insert(stored_key, expires_at);
                Ok(ReplayInsertOutcome::Inserted)
            }
        }
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
        self.insert_once_sync(scope, key, expires_at)
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

#[derive(Clone, PartialEq, Eq, Hash)]
struct StoredReplayKey {
    scope: ReplayScope,
    key: ReplayKey,
}

impl StoredReplayKey {
    fn new(scope: &ReplayScope, key: &ReplayKey) -> Self {
        Self {
            scope: scope.clone(),
            key: key.clone(),
        }
    }
}

impl fmt::Debug for StoredReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredReplayKey")
            .field("scope", &self.scope)
            .field("key", &self.key)
            .finish()
    }
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
