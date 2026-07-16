// SPDX-License-Identifier: Apache-2.0
//! Typed correctness state for the OID4VCI pre-authorized-code flow.
//!
//! PostgreSQL mode delegates to the fixed Notary-owned transactions. The
//! in-memory backend intentionally remains local-only and holds all three
//! related decisions under one mutex so a successful PIN check, replay claim,
//! and PIN-verifier removal are atomic within the process.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use registry_platform_replay::ReplayScope;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    replay::{replay_identifier_hash, replay_scope_hash},
    state_plane::{NotaryStatePlaneHandle, SensitiveStateError, SensitiveStateKeys},
};

const PREAUTH_LOGIN_STATE_MAX_ENTRIES: usize = 4_096;

/// The login state reserved at `offer/start` and consumed exactly once at the
/// eSignet callback. Secret fields are redacted from `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct LoginState {
    pub(crate) pkce_verifier: String,
    pub(crate) nonce: String,
    pub(crate) credential_configuration_id: String,
}

impl std::fmt::Debug for LoginState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoginState")
            .field("pkce_verifier", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field(
                "credential_configuration_id",
                &self.credential_configuration_id,
            )
            .finish()
    }
}

/// Opaque proof that a transaction code matched the verifier stored for one
/// stable JTI hash. It contains no plaintext PIN and is consumed by redemption.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct VerifiedTransactionCode {
    jti_hash: [u8; 32],
    verifier: [u8; 32],
}

impl VerifiedTransactionCode {
    pub(crate) fn new(jti_hash: [u8; 32], verifier: [u8; 32]) -> Self {
        Self { jti_hash, verifier }
    }

    pub(crate) fn into_verifier_for(mut self, expected_jti_hash: &[u8; 32]) -> Option<[u8; 32]> {
        if self.jti_hash.ct_eq(expected_jti_hash).unwrap_u8() != 1 {
            return None;
        }
        Some(std::mem::take(&mut self.verifier))
    }
}

impl std::fmt::Debug for VerifiedTransactionCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedTransactionCode")
            .finish_non_exhaustive()
    }
}

/// Stable, value-free failures for the typed preauthorization state API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PreauthorizationStateError {
    #[error("preauthorization login state already exists")]
    DuplicateLoginState,
    #[error("preauthorization login-state capacity is exhausted")]
    LoginStateCapacity,
    #[error("preauthorization state is unavailable")]
    Unavailable,
    #[error("preauthorization transaction-code proof is incompatible")]
    IncompatibleTransactionCodeProof,
    #[error("preauthorization expiry is invalid")]
    InvalidExpiry,
    #[error(transparent)]
    SensitiveState(#[from] SensitiveStateError),
}

/// Implementer-facing preauthorization state contract. Callers select the
/// backend once during runtime compilation and cannot issue arbitrary storage
/// operations.
pub(crate) struct PreauthorizationState {
    backend: PreauthorizationBackend,
}

enum PreauthorizationBackend {
    InMemory(Arc<InMemoryPreauthorizationState>),
    Postgresql(Arc<NotaryStatePlaneHandle>),
}

impl PreauthorizationState {
    pub(crate) fn from_state_plane(
        state_plane: Arc<NotaryStatePlaneHandle>,
    ) -> Result<Self, PreauthorizationStateError> {
        let backend = if state_plane.is_in_memory() {
            PreauthorizationBackend::InMemory(Arc::new(InMemoryPreauthorizationState::new()?))
        } else {
            PreauthorizationBackend::Postgresql(state_plane)
        };
        Ok(Self { backend })
    }

    pub(crate) async fn reserve_login(
        &self,
        opaque_state: &str,
        login: LoginState,
        ttl_seconds: u64,
    ) -> Result<(), PreauthorizationStateError> {
        let expires_at = expiry_after(ttl_seconds)?;
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => {
                state.reserve_login(opaque_state, login, expires_at)
            }
            PreauthorizationBackend::Postgresql(handle) => {
                use crate::state_plane::LoginReserveOutcome;
                match handle
                    .sensitive_state()?
                    .reserve_login(opaque_state, &login, expires_at)
                    .await?
                {
                    LoginReserveOutcome::Reserved => Ok(()),
                    LoginReserveOutcome::Duplicate => {
                        Err(PreauthorizationStateError::DuplicateLoginState)
                    }
                    LoginReserveOutcome::Capacity => {
                        Err(PreauthorizationStateError::LoginStateCapacity)
                    }
                }
            }
        }
    }

    pub(crate) async fn consume_login(
        &self,
        opaque_state: &str,
    ) -> Result<Option<LoginState>, PreauthorizationStateError> {
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => state.consume_login(opaque_state),
            PreauthorizationBackend::Postgresql(handle) => Ok(handle
                .sensitive_state()?
                .consume_login(opaque_state)
                .await?),
        }
    }

    pub(crate) async fn reserve_transaction_code(
        &self,
        jti: &str,
        pin: &str,
        pin_length: u64,
        expires_at: OffsetDateTime,
    ) -> Result<bool, PreauthorizationStateError> {
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => {
                state.reserve_transaction_code(jti, pin, pin_length, expires_at)
            }
            PreauthorizationBackend::Postgresql(handle) => Ok(handle
                .sensitive_state()?
                .reserve_transaction_code(jti, pin, pin_length, expires_at)
                .await?),
        }
    }

    /// Verify a PIN without mutation. `Ok(None)` means the PIN was wrong or
    /// the offer is absent/expired, and therefore does not burn a valid offer.
    pub(crate) async fn verify_transaction_code(
        &self,
        jti: &str,
        presented_pin: &str,
    ) -> Result<Option<VerifiedTransactionCode>, PreauthorizationStateError> {
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => {
                state.verify_transaction_code(jti, presented_pin)
            }
            PreauthorizationBackend::Postgresql(handle) => Ok(handle
                .sensitive_state()?
                .verify_transaction_code(jti, presented_pin)
                .await?),
        }
    }

    /// Atomically claim the code JTI and, when required by the signed code,
    /// validate and remove the corresponding transaction-code verifier.
    pub(crate) async fn redeem(
        &self,
        scope: &ReplayScope,
        jti: &str,
        expires_at: OffsetDateTime,
        transaction_code_required: bool,
        proof: Option<VerifiedTransactionCode>,
    ) -> Result<bool, PreauthorizationStateError> {
        if transaction_code_required != proof.is_some() {
            return Err(PreauthorizationStateError::IncompatibleTransactionCodeProof);
        }
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => {
                state.redeem(scope, jti, expires_at, transaction_code_required, proof)
            }
            PreauthorizationBackend::Postgresql(handle) => {
                let sensitive = handle.sensitive_state()?;
                // Issuance reserves before exposing the signed code, and no
                // typed path adds a verifier for an existing code afterward.
                // A concurrent successful redemption can only remove this row;
                // the atomic replay claim below still makes that request lose.
                if !transaction_code_required && sensitive.has_live_transaction_code(jti).await? {
                    return Ok(false);
                }
                Ok(sensitive.redeem(scope, jti, expires_at, proof).await?)
            }
        }
    }
}

impl std::fmt::Debug for PreauthorizationState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreauthorizationState")
            .field(
                "backend",
                &match self.backend {
                    PreauthorizationBackend::InMemory(_) => "in_memory_local_only",
                    PreauthorizationBackend::Postgresql(_) => "postgresql",
                },
            )
            .finish()
    }
}

struct InMemoryPreauthorizationState {
    keys: SensitiveStateKeys,
    records: Mutex<InMemoryRecords>,
}

#[derive(Default)]
struct InMemoryRecords {
    login: HashMap<[u8; 32], Stored<LoginState>>,
    transaction_codes: HashMap<[u8; 32], Stored<TransactionCodeVerifier>>,
    redeemed: HashMap<([u8; 32], [u8; 32]), OffsetDateTime>,
}

struct Stored<V> {
    value: V,
    expires_at: OffsetDateTime,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct TransactionCodeVerifier {
    verifier: [u8; 32],
    pin_length: usize,
}

impl InMemoryPreauthorizationState {
    fn new() -> Result<Self, PreauthorizationStateError> {
        Ok(Self {
            keys: SensitiveStateKeys::random()?,
            records: Mutex::new(InMemoryRecords::default()),
        })
    }

    fn reserve_login(
        &self,
        opaque_state: &str,
        login: LoginState,
        expires_at: OffsetDateTime,
    ) -> Result<(), PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        let mut records = self.lock_records()?;
        records.login.retain(|_, stored| stored.expires_at > now);
        let state_hash = self.keys.login_state_hash(opaque_state);
        if records.login.contains_key(&state_hash) {
            return Err(PreauthorizationStateError::DuplicateLoginState);
        }
        if records.login.len() >= PREAUTH_LOGIN_STATE_MAX_ENTRIES {
            return Err(PreauthorizationStateError::LoginStateCapacity);
        }
        records.login.insert(
            state_hash,
            Stored {
                value: login,
                expires_at,
            },
        );
        Ok(())
    }

    fn consume_login(
        &self,
        opaque_state: &str,
    ) -> Result<Option<LoginState>, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        let state_hash = self.keys.login_state_hash(opaque_state);
        let mut records = self.lock_records()?;
        let Some(stored) = records.login.remove(&state_hash) else {
            return Ok(None);
        };
        Ok((stored.expires_at > now).then_some(stored.value))
    }

    fn reserve_transaction_code(
        &self,
        jti: &str,
        pin: &str,
        pin_length: u64,
        expires_at: OffsetDateTime,
    ) -> Result<bool, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(PreauthorizationStateError::InvalidExpiry);
        }
        let pin_length =
            usize::try_from(pin_length).map_err(|_| PreauthorizationStateError::Unavailable)?;
        let jti_hash = replay_identifier_hash(jti);
        let verifier = self.keys.pin_verifier(&jti_hash, pin);
        let mut records = self.lock_records()?;
        records
            .transaction_codes
            .retain(|_, stored| stored.expires_at > now);
        if records.transaction_codes.contains_key(&jti_hash) {
            return Ok(false);
        }
        records.transaction_codes.insert(
            jti_hash,
            Stored {
                value: TransactionCodeVerifier {
                    verifier,
                    pin_length,
                },
                expires_at,
            },
        );
        Ok(true)
    }

    fn verify_transaction_code(
        &self,
        jti: &str,
        presented_pin: &str,
    ) -> Result<Option<VerifiedTransactionCode>, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        let jti_hash = replay_identifier_hash(jti);
        let records = self.lock_records()?;
        let Some(stored) = records.transaction_codes.get(&jti_hash) else {
            return Ok(None);
        };
        if stored.expires_at <= now || stored.value.pin_length != presented_pin.len() {
            return Ok(None);
        }
        let expected = self.keys.pin_verifier(&jti_hash, presented_pin);
        if expected.ct_eq(&stored.value.verifier).unwrap_u8() != 1 {
            return Ok(None);
        }
        Ok(Some(VerifiedTransactionCode::new(jti_hash, expected)))
    }

    fn redeem(
        &self,
        scope: &ReplayScope,
        jti: &str,
        expires_at: OffsetDateTime,
        transaction_code_required: bool,
        proof: Option<VerifiedTransactionCode>,
    ) -> Result<bool, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Ok(false);
        }
        let scope_hash = replay_scope_hash(scope);
        let jti_hash = replay_identifier_hash(jti);
        let replay_key = (scope_hash, jti_hash);
        let mut records = self.lock_records()?;
        records.redeemed.retain(|_, expiry| *expiry > now);
        if records.redeemed.contains_key(&replay_key) {
            return Ok(false);
        }
        let has_live_transaction_code = records
            .transaction_codes
            .get(&jti_hash)
            .is_some_and(|stored| stored.expires_at > now);
        if transaction_code_required != has_live_transaction_code {
            return Ok(false);
        }
        if let Some(proof) = proof {
            let Some(proof_verifier) = proof.into_verifier_for(&jti_hash) else {
                return Err(PreauthorizationStateError::IncompatibleTransactionCodeProof);
            };
            let Some(stored) = records.transaction_codes.get(&jti_hash) else {
                return Ok(false);
            };
            if stored.expires_at <= now
                || proof_verifier.ct_eq(&stored.value.verifier).unwrap_u8() != 1
            {
                return Ok(false);
            }
        }
        records.redeemed.insert(replay_key, expires_at);
        records.transaction_codes.remove(&jti_hash);
        Ok(true)
    }

    fn lock_records(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, InMemoryRecords>, PreauthorizationStateError> {
        self.records
            .lock()
            .map_err(|_| PreauthorizationStateError::Unavailable)
    }
}

fn expiry_after(ttl_seconds: u64) -> Result<OffsetDateTime, PreauthorizationStateError> {
    let seconds =
        i64::try_from(ttl_seconds).map_err(|_| PreauthorizationStateError::InvalidExpiry)?;
    OffsetDateTime::now_utc()
        .checked_add(Duration::seconds(seconds))
        .ok_or(PreauthorizationStateError::InvalidExpiry)
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

    fn memory_state() -> PreauthorizationState {
        PreauthorizationState {
            backend: PreauthorizationBackend::InMemory(Arc::new(
                InMemoryPreauthorizationState::new().unwrap(),
            )),
        }
    }

    fn scope() -> ReplayScope {
        ReplayScope::new([("tenant", "tenant-a"), ("kind", "oid4vci-preauth-code")]).unwrap()
    }

    #[tokio::test]
    async fn login_state_is_consumed_exactly_once() {
        let state = memory_state();
        state
            .reserve_login("opaque", login_state(), 300)
            .await
            .unwrap();
        assert!(state.consume_login("opaque").await.unwrap().is_some());
        assert!(state.consume_login("opaque").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_pin_preserves_offer_and_successful_redemption_is_single_use() {
        let state = memory_state();
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        assert!(state
            .reserve_transaction_code("jti", "246810", 6, expires_at)
            .await
            .unwrap());
        assert!(state
            .verify_transaction_code("jti", "000000")
            .await
            .unwrap()
            .is_none());
        let proof = state
            .verify_transaction_code("jti", "246810")
            .await
            .unwrap()
            .expect("correct PIN remains available after wrong PIN");
        assert!(state
            .redeem(&scope(), "jti", expires_at, true, Some(proof))
            .await
            .unwrap());
        assert!(state
            .verify_transaction_code("jti", "246810")
            .await
            .unwrap()
            .is_none());
        assert!(state
            .redeem(&scope(), "jti", expires_at, true, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn live_transaction_code_row_rejects_no_pin_policy() {
        let backend = Arc::new(InMemoryPreauthorizationState::new().unwrap());
        let issuing_runtime = PreauthorizationState {
            backend: PreauthorizationBackend::InMemory(Arc::clone(&backend)),
        };
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        assert!(issuing_runtime
            .reserve_transaction_code("reconfigured-jti", "246810", 6, expires_at)
            .await
            .unwrap());

        let reconfigured_runtime = PreauthorizationState {
            backend: PreauthorizationBackend::InMemory(backend),
        };
        assert!(matches!(
            reconfigured_runtime
                .redeem(&scope(), "reconfigured-jti", expires_at, true, None)
                .await,
            Err(PreauthorizationStateError::IncompatibleTransactionCodeProof)
        ));
        assert!(!reconfigured_runtime
            .redeem(&scope(), "reconfigured-jti", expires_at, false, None)
            .await
            .unwrap());
        let proof = reconfigured_runtime
            .verify_transaction_code("reconfigured-jti", "246810")
            .await
            .unwrap()
            .expect("the persisted per-code PIN requirement remains redeemable");
        assert!(reconfigured_runtime
            .redeem(&scope(), "reconfigured-jti", expires_at, true, Some(proof),)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn redemption_without_pin_is_atomic_and_single_use() {
        let state = memory_state();
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        assert!(state
            .redeem(&scope(), "jti", expires_at, false, None)
            .await
            .unwrap());
        assert!(!state
            .redeem(&scope(), "jti", expires_at, false, None)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn concurrent_redemptions_have_exactly_one_winner() {
        let state = Arc::new(memory_state());
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut attempts = Vec::new();
        for _ in 0..2 {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            attempts.push(tokio::spawn(async move {
                barrier.wait().await;
                state
                    .redeem(&scope(), "jti", expires_at, false, None)
                    .await
                    .unwrap()
            }));
        }
        barrier.wait().await;
        let first = attempts.remove(0).await.unwrap();
        let second = attempts.remove(0).await.unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn debug_redacts_login_secrets_and_transaction_code_proof() {
        let login = login_state();
        let rendered = format!("{login:?}");
        assert!(!rendered.contains("verifier-secret"));
        assert!(!rendered.contains("nonce-secret"));
        let proof = VerifiedTransactionCode::new([7; 32], [9; 32]);
        let rendered = format!("{proof:?}");
        assert!(!rendered.contains('7'));
        assert!(!rendered.contains('9'));
    }

    #[test]
    fn login_state_has_an_explicit_zeroize_lifecycle() {
        fn requires_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        requires_zeroize::<LoginState>();
    }
}
