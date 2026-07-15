// SPDX-License-Identifier: Apache-2.0
//! Replay-store wiring for Registry Notary one-time identifiers.

use std::sync::Arc;

use async_trait::async_trait;
use registry_platform_replay::{
    require_insert_once, ConsumableNonceStore, InMemoryConsumableNonceStore, InMemoryReplayStore,
    ReplayKey, ReplayScope, ReplayStore, ReplayStoreError, RequiredReplayError,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::state_plane::{NotaryPostgresStatePlaneReadiness, NotaryStatePlaneHandle};

#[derive(Clone)]
pub(crate) struct ReplayStores {
    store: Arc<dyn ReplayStore>,
    nonce_store: Arc<dyn ConsumableNonceStore>,
    state_plane: Option<Arc<NotaryStatePlaneHandle>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayReadiness {
    Ready,
    Degraded,
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
    pub(crate) fn memory() -> Self {
        let store = Arc::new(InMemoryReplayStore::new());
        let nonce_store = Arc::new(InMemoryConsumableNonceStore::new());
        Self {
            store,
            nonce_store,
            state_plane: None,
        }
    }

    pub(crate) fn configured_in_memory(state_plane: Arc<NotaryStatePlaneHandle>) -> Self {
        let store = Arc::new(InMemoryReplayStore::new());
        let nonce_store = Arc::new(InMemoryConsumableNonceStore::new());
        Self {
            store,
            nonce_store,
            state_plane: Some(state_plane),
        }
    }

    pub(crate) fn postgres(state_plane: Arc<NotaryStatePlaneHandle>) -> Self {
        let store = Arc::new(PostgresReplayStore {
            state_plane: Arc::clone(&state_plane),
        });
        Self {
            store: store.clone(),
            nonce_store: store,
            state_plane: Some(state_plane),
        }
    }

    pub(crate) fn store(&self) -> Arc<dyn ReplayStore> {
        Arc::clone(&self.store)
    }

    pub(crate) fn nonce_store(&self) -> Arc<dyn ConsumableNonceStore> {
        Arc::clone(&self.nonce_store)
    }

    pub(crate) async fn check_ready(&self) -> Result<ReplayReadiness, ReplayStoreError> {
        let Some(state_plane) = &self.state_plane else {
            return Ok(ReplayReadiness::Degraded);
        };
        match state_plane.readiness().await {
            NotaryPostgresStatePlaneReadiness::Ready => Ok(ReplayReadiness::Ready),
            _ => Err(replay_operation_error()),
        }
    }
}

#[derive(Clone)]
struct PostgresReplayStore {
    state_plane: Arc<NotaryStatePlaneHandle>,
}

#[async_trait]
impl ReplayStore for PostgresReplayStore {
    async fn insert_once(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<registry_platform_replay::ReplayInsertOutcome, ReplayStoreError> {
        let runtime = self
            .state_plane
            .runtime()
            .map_err(|_| replay_operation_error())?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| replay_operation_error())?;
        let scope_hash = replay_scope_hash(scope);
        let identifier_hash = replay_key_hash(key);
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.replay_insert_v1($1, $2, $3) AS inserted",
                &[
                    &scope_hash.as_slice(),
                    &identifier_hash.as_slice(),
                    &expires_at,
                ],
            ))
            .await
            .map_err(|_| replay_operation_error())?;
        let inserted = row
            .try_get::<_, bool>("inserted")
            .map_err(|_| replay_operation_error())?;
        Ok(if inserted {
            registry_platform_replay::ReplayInsertOutcome::Inserted
        } else {
            registry_platform_replay::ReplayInsertOutcome::AlreadySeen
        })
    }
}

#[async_trait]
impl ConsumableNonceStore for PostgresReplayStore {
    async fn reserve_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), ReplayStoreError> {
        let runtime = self
            .state_plane
            .runtime()
            .map_err(|_| replay_operation_error())?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| replay_operation_error())?;
        let scope_hash = replay_scope_hash(scope);
        let nonce_hash = replay_key_hash(key);
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.nonce_reserve_v1($1, $2, $3) AS reserved",
                &[&scope_hash.as_slice(), &nonce_hash.as_slice(), &expires_at],
            ))
            .await
            .map_err(|_| replay_operation_error())?;
        if row
            .try_get::<_, bool>("reserved")
            .map_err(|_| replay_operation_error())?
        {
            Ok(())
        } else {
            Err(ReplayStoreError::Operation {
                message: "nonce is already reserved".to_string(),
            })
        }
    }

    async fn consume_nonce(
        &self,
        scope: &ReplayScope,
        key: &ReplayKey,
    ) -> Result<registry_platform_replay::ReplayInsertOutcome, ReplayStoreError> {
        let runtime = self
            .state_plane
            .runtime()
            .map_err(|_| replay_operation_error())?;
        let session = runtime
            .open_domain_session()
            .await
            .map_err(|_| replay_operation_error())?;
        let scope_hash = replay_scope_hash(scope);
        let nonce_hash = replay_key_hash(key);
        let generation = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.nonce_reservation_generation_v1($1, $2) AS generation",
                &[&scope_hash.as_slice(), &nonce_hash.as_slice()],
            ))
            .await
            .map_err(|_| replay_operation_error())?
            .try_get::<_, Option<i64>>("generation")
            .map_err(|_| replay_operation_error())?;
        let Some(generation) = generation else {
            return Ok(registry_platform_replay::ReplayInsertOutcome::AlreadySeen);
        };
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.nonce_consume_v1($1, $2, $3) AS consumed",
                &[&scope_hash.as_slice(), &nonce_hash.as_slice(), &generation],
            ))
            .await
            .map_err(|_| replay_operation_error())?;
        let consumed = row
            .try_get::<_, bool>("consumed")
            .map_err(|_| replay_operation_error())?;
        Ok(if consumed {
            registry_platform_replay::ReplayInsertOutcome::Inserted
        } else {
            registry_platform_replay::ReplayInsertOutcome::AlreadySeen
        })
    }
}

pub(crate) fn replay_scope_hash(scope: &ReplayScope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-notary:replay-scope:v1\0");
    for (name, value) in scope.parts() {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().into()
}

pub(crate) fn replay_key_hash(key: &ReplayKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"registry-notary:replay-identifier:v1\0");
    hasher.update((key.as_str().len() as u64).to_be_bytes());
    hasher.update(key.as_str().as_bytes());
    hasher.finalize().into()
}

fn replay_operation_error() -> ReplayStoreError {
    ReplayStoreError::Operation {
        message: "Notary PostgreSQL replay operation is unavailable".to_string(),
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
    async fn memory_replay_store_reports_degraded_readiness() {
        let stores = ReplayStores::memory();

        assert_eq!(
            stores.check_ready().await.expect("memory store reports"),
            ReplayReadiness::Degraded
        );
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
}
