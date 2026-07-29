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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    replay::{replay_identifier_hash, replay_scope_hash},
    state_plane::{NotaryStatePlaneHandle, SensitiveStateError, SensitiveStateKeys},
};

const PREAUTH_LOGIN_STATE_MAX_ENTRIES: usize = 4_096;
const OID4VCI_ISSUANCE_TRANSACTION_MAX_ENTRIES: usize = 4_096;
const REGISTRY_CLIENT_OFFER_MAX_ENTRIES: usize = 4_096;
const EVALUATION_ISSUANCE_MAX_ENTRIES: usize = 4_096;
const MACHINE_QUOTA_MAX_ENTRIES: usize = 10_000;
const MACHINE_QUOTA_WINDOW: Duration = Duration::minutes(1);
const EVALUATION_ISSUANCE_CONTEXT: &[u8] = b"oid4vci-evaluation-issuance";

/// The authority that initiated an immutable issuance transaction.
///
/// The registry-client variant is encrypted at rest in PostgreSQL. Its custom
/// `Debug` implementation deliberately omits the client, target, scopes,
/// service, and purpose because those values can be identifying.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum IssuanceAuthority {
    #[default]
    SubjectAccess,
    RegistryClient {
        initiating_client_id: String,
        initiating_client_id_hash: String,
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId,
        authorized_scopes: Vec<String>,
        target_ref: registry_notary_core::TargetRefView,
        service_id: String,
        purpose: String,
    },
}

impl std::fmt::Debug for IssuanceAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubjectAccess => formatter.write_str("SubjectAccess"),
            Self::RegistryClient {
                auth_profile_id, ..
            } => formatter
                .debug_struct("RegistryClient")
                .field("auth_profile_id", auth_profile_id)
                .finish_non_exhaustive(),
        }
    }
}

/// Immutable authority-bearing portion of one registry-backed issuance.
///
/// The raw authenticated civil identifier is deliberately absent. The stored
/// evaluation is retrieved through its secret-keyed client binding, while the
/// commitment covers only normalized, authority-bearing values.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IssuanceTransaction {
    pub(crate) transaction_id: String,
    pub(crate) evaluation_id: String,
    pub(crate) evaluation_client_id: String,
    pub(crate) credential_configuration_id: String,
    pub(crate) commitment: String,
    #[serde(default)]
    pub(crate) authority: IssuanceAuthority,
}

impl std::fmt::Debug for IssuanceTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuanceTransaction")
            .field("transaction_id", &"[redacted]")
            .field("evaluation_id", &"[redacted]")
            .field("evaluation_client_id", &"[redacted]")
            .field(
                "credential_configuration_id",
                &self.credential_configuration_id,
            )
            .field("commitment", &self.commitment)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Exact response cached by the atomic registry-client offer operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryClientOfferResponse {
    pub(crate) credential_offer_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tx_code: Option<String>,
    pub(crate) expires_at: String,
}

impl std::fmt::Debug for RegistryClientOfferResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryClientOfferResponse")
            .field("credential_offer_uri", &"[redacted]")
            .field("tx_code", &self.tx_code.as_ref().map(|_| "[redacted]"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Optional out-of-band PIN material consumed by an atomic offer reservation.
///
/// The plaintext is accepted only at this typed boundary, converted to a keyed
/// verifier inside the same state transition, and zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct RegistryClientTransactionCode {
    pub(crate) pin: String,
    pub(crate) pin_length: u64,
}

impl std::fmt::Debug for RegistryClientTransactionCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryClientTransactionCode")
            .field("pin", &"[redacted]")
            .field("pin_length", &self.pin_length)
            .finish()
    }
}

/// Complete input for one registry-client offer reservation.
///
/// The idempotency key must already be represented as
/// `hmac-sha256:<lowercase hex>`. The request hash is the endpoint's canonical
/// `sha256:<lowercase hex>` request identity. Neither raw value is rendered by
/// `Debug`.
pub(crate) struct RegistryClientOfferReservation {
    pub(crate) transaction_id: String,
    pub(crate) evaluation_id: String,
    pub(crate) evaluation_expires_at: OffsetDateTime,
    pub(crate) idempotency_key_hash: String,
    pub(crate) canonical_request_hash: String,
    pub(crate) transaction: IssuanceTransaction,
    pub(crate) transaction_code: Option<RegistryClientTransactionCode>,
    pub(crate) code_expires_at: OffsetDateTime,
    pub(crate) transaction_expires_at: OffsetDateTime,
    pub(crate) response: RegistryClientOfferResponse,
    pub(crate) retention_expires_at: OffsetDateTime,
    pub(crate) quota_principal_hash: Vec<u8>,
    pub(crate) quota_limit: Option<i32>,
    pub(crate) quota_cost: i32,
}

impl std::fmt::Debug for RegistryClientOfferReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryClientOfferReservation")
            .field("transaction_id", &"[redacted]")
            .field("evaluation_id", &"[redacted]")
            .field("evaluation_expires_at", &self.evaluation_expires_at)
            .field("idempotency_key_hash", &"[redacted]")
            .field("canonical_request_hash", &"[redacted]")
            .field("transaction", &self.transaction)
            .field("transaction_code", &self.transaction_code)
            .field("code_expires_at", &self.code_expires_at)
            .field("transaction_expires_at", &self.transaction_expires_at)
            .field("response", &self.response)
            .field("retention_expires_at", &self.retention_expires_at)
            .field("quota_principal_hash", &"[redacted]")
            .field("quota_limit", &self.quota_limit)
            .field("quota_cost", &self.quota_cost)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RegistryClientOfferReservationOutcome {
    Created(RegistryClientOfferResponse),
    Replayed(RegistryClientOfferResponse),
}

impl std::fmt::Debug for RegistryClientOfferReservationOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created(_) => formatter.write_str("Created([redacted])"),
            Self::Replayed(_) => formatter.write_str("Replayed([redacted])"),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum CredentialMaterialization {
    Acquired(IssuanceTransaction),
    Cached(Value),
    Busy,
    Denied,
}

#[derive(Clone)]
enum MaterializationState {
    Ready,
    Issuing {
        holder_thumbprint: String,
        request_hash: String,
    },
    Completed {
        holder_thumbprint: String,
        request_hash: String,
        response: Value,
    },
    Failed,
}

#[derive(Clone)]
struct StoredIssuanceTransaction {
    transaction: IssuanceTransaction,
    nonce: Option<String>,
    state: MaterializationState,
}

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
    #[error("issuance transaction already exists")]
    DuplicateIssuanceTransaction,
    #[error("preauthorization login-state capacity is exhausted")]
    LoginStateCapacity,
    #[error("issuance transaction capacity is exhausted")]
    IssuanceTransactionCapacity,
    #[error("preauthorization state is unavailable")]
    Unavailable,
    #[error("preauthorization transaction-code proof is incompatible")]
    IncompatibleTransactionCodeProof,
    #[error("preauthorization expiry is invalid")]
    InvalidExpiry,
    #[error("registry-client offer idempotency key conflicts with its original request")]
    IdempotencyConflict,
    #[error("evaluation issuance lineage was already consumed")]
    EvaluationConsumed,
    #[error("registry-client offer quota was exhausted")]
    MachineQuotaExceeded { retry_after_seconds: u64 },
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

    pub(crate) async fn reserve_issuance_transaction(
        &self,
        transaction_id: &str,
        transaction: IssuanceTransaction,
        expires_at: OffsetDateTime,
    ) -> Result<(), PreauthorizationStateError> {
        if let PreauthorizationBackend::Postgresql(handle) = &self.backend {
            use crate::state_plane::IssuanceReserveOutcome;
            return match handle
                .sensitive_state()?
                .reserve_issuance_transaction(transaction_id, &transaction, expires_at)
                .await?
            {
                IssuanceReserveOutcome::Reserved => Ok(()),
                IssuanceReserveOutcome::Duplicate => {
                    Err(PreauthorizationStateError::DuplicateIssuanceTransaction)
                }
                IssuanceReserveOutcome::Capacity => {
                    Err(PreauthorizationStateError::IssuanceTransactionCapacity)
                }
            };
        }
        let PreauthorizationBackend::InMemory(state) = &self.backend else {
            unreachable!("PostgreSQL issuance reservation returned above");
        };
        state.reserve_issuance_transaction(transaction_id, transaction, expires_at)
    }

    /// Atomically reserve the immutable transaction, optional transaction-code
    /// verifier, evaluation consumption, and exact response for a
    /// registry-client initiated offer.
    pub(crate) async fn reserve_registry_client_offer(
        &self,
        reservation: RegistryClientOfferReservation,
    ) -> Result<RegistryClientOfferReservationOutcome, PreauthorizationStateError> {
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => {
                state.reserve_registry_client_offer(reservation)
            }
            PreauthorizationBackend::Postgresql(handle) => {
                handle
                    .sensitive_state()?
                    .reserve_registry_client_offer(reservation)
                    .await
            }
        }
    }

    /// Terminally consume one evaluation lineage before direct issuance side
    /// effects. Registry-client offer creation uses the same ledger, so only
    /// one path can win for an evaluation and its owning client.
    pub(crate) async fn reserve_evaluation_issuance(
        &self,
        evaluation_id: &str,
        evaluation_client_id: &str,
        evaluation_expires_at: OffsetDateTime,
    ) -> Result<(), PreauthorizationStateError> {
        match &self.backend {
            PreauthorizationBackend::InMemory(state) => state.reserve_evaluation_issuance(
                evaluation_id,
                evaluation_client_id,
                evaluation_expires_at,
            ),
            PreauthorizationBackend::Postgresql(handle) => {
                handle
                    .sensitive_state()?
                    .reserve_evaluation_issuance(
                        evaluation_id,
                        evaluation_client_id,
                        evaluation_expires_at,
                    )
                    .await
            }
        }
    }

    pub(crate) async fn transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<IssuanceTransaction>, PreauthorizationStateError> {
        if let PreauthorizationBackend::Postgresql(handle) = &self.backend {
            return Ok(handle
                .sensitive_state()?
                .issuance_transaction(transaction_id)
                .await?);
        }
        let PreauthorizationBackend::InMemory(state) = &self.backend else {
            unreachable!("PostgreSQL issuance lookup returned above");
        };
        state.transaction(transaction_id)
    }

    pub(crate) async fn bind_transaction_nonce(
        &self,
        transaction_id: &str,
        commitment: &str,
        nonce: String,
    ) -> Result<bool, PreauthorizationStateError> {
        if let PreauthorizationBackend::Postgresql(handle) = &self.backend {
            return Ok(handle
                .sensitive_state()?
                .bind_issuance_nonce(transaction_id, commitment, &nonce)
                .await?);
        }
        let PreauthorizationBackend::InMemory(state) = &self.backend else {
            unreachable!("PostgreSQL nonce binding returned above");
        };
        state.bind_transaction_nonce(transaction_id, commitment, nonce)
    }

    pub(crate) async fn begin_credential_materialization(
        &self,
        transaction_id: &str,
        commitment: &str,
        configuration_id: &str,
        nonce: &str,
        holder_thumbprint: &str,
        request_hash: &str,
    ) -> Result<CredentialMaterialization, PreauthorizationStateError> {
        if let PreauthorizationBackend::Postgresql(handle) = &self.backend {
            return Ok(handle
                .sensitive_state()?
                .begin_issuance_materialization(
                    transaction_id,
                    commitment,
                    configuration_id,
                    nonce,
                    holder_thumbprint,
                    request_hash,
                )
                .await?);
        }
        let PreauthorizationBackend::InMemory(state) = &self.backend else {
            unreachable!("PostgreSQL materialization begin returned above");
        };
        state.begin_credential_materialization(
            transaction_id,
            commitment,
            configuration_id,
            nonce,
            holder_thumbprint,
            request_hash,
        )
    }

    pub(crate) async fn complete_credential_materialization(
        &self,
        transaction_id: &str,
        holder_thumbprint: &str,
        request_hash: &str,
        response: Value,
    ) -> Result<bool, PreauthorizationStateError> {
        if let PreauthorizationBackend::Postgresql(handle) = &self.backend {
            return Ok(handle
                .sensitive_state()?
                .complete_issuance_materialization(
                    transaction_id,
                    holder_thumbprint,
                    request_hash,
                    &response,
                )
                .await?);
        }
        let PreauthorizationBackend::InMemory(state) = &self.backend else {
            unreachable!("PostgreSQL materialization completion returned above");
        };
        state.complete_credential_materialization(
            transaction_id,
            holder_thumbprint,
            request_hash,
            response,
        )
    }

    pub(crate) async fn fail_credential_materialization(
        &self,
        transaction_id: &str,
        holder_thumbprint: &str,
    ) -> Result<(), PreauthorizationStateError> {
        if let PreauthorizationBackend::Postgresql(handle) = &self.backend {
            return Ok(handle
                .sensitive_state()?
                .fail_issuance_materialization(transaction_id, holder_thumbprint)
                .await?);
        }
        let PreauthorizationBackend::InMemory(state) = &self.backend else {
            unreachable!("PostgreSQL materialization failure returned above");
        };
        state.fail_credential_materialization(transaction_id, holder_thumbprint)
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
    issuance: HashMap<[u8; 32], Stored<StoredIssuanceTransaction>>,
    registry_client_offers: HashMap<[u8; 32], StoredRegistryClientOffer>,
    consumed_evaluations: HashMap<[u8; 32], OffsetDateTime>,
    machine_quota: HashMap<[u8; 32], StoredMachineQuota>,
}

struct StoredRegistryClientOffer {
    request_hash: [u8; 32],
    response: RegistryClientOfferResponse,
    retention_expires_at: OffsetDateTime,
    purge_after: OffsetDateTime,
}

struct StoredMachineQuota {
    window_expires_at: OffsetDateTime,
    used: i32,
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

    fn reserve_issuance_transaction(
        &self,
        transaction_id: &str,
        transaction: IssuanceTransaction,
        expires_at: OffsetDateTime,
    ) -> Result<(), PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(PreauthorizationStateError::InvalidExpiry);
        }
        let key = replay_identifier_hash(transaction_id);
        let mut records = self.lock_records()?;
        records.issuance.retain(|_, record| record.expires_at > now);
        if records.issuance.contains_key(&key) {
            return Err(PreauthorizationStateError::DuplicateIssuanceTransaction);
        }
        if records.issuance.len() >= OID4VCI_ISSUANCE_TRANSACTION_MAX_ENTRIES {
            return Err(PreauthorizationStateError::IssuanceTransactionCapacity);
        }
        records.issuance.insert(
            key,
            Stored {
                value: StoredIssuanceTransaction {
                    transaction,
                    nonce: None,
                    state: MaterializationState::Ready,
                },
                expires_at,
            },
        );
        Ok(())
    }

    fn reserve_registry_client_offer(
        &self,
        reservation: RegistryClientOfferReservation,
    ) -> Result<RegistryClientOfferReservationOutcome, PreauthorizationStateError> {
        validate_registry_client_offer_structure(&reservation)?;
        let idempotency_hash = decode_hash_uri(&reservation.idempotency_key_hash, "hmac-sha256:")?;
        let request_hash = decode_hash_uri(&reservation.canonical_request_hash, "sha256:")?;
        let evaluation_hash = self.evaluation_issuance_hash(
            &reservation.evaluation_id,
            &reservation.transaction.evaluation_client_id,
        );
        let transaction_hash = replay_identifier_hash(&reservation.transaction_id);
        let now = OffsetDateTime::now_utc();
        let mut records = self.lock_records()?;
        prune_offer_records(&mut records, now);

        if let Some(stored) = records.registry_client_offers.get(&idempotency_hash) {
            if stored.request_hash != request_hash {
                return Err(PreauthorizationStateError::IdempotencyConflict);
            }
            if stored.retention_expires_at > now {
                return Ok(RegistryClientOfferReservationOutcome::Replayed(
                    stored.response.clone(),
                ));
            }
            return Err(PreauthorizationStateError::EvaluationConsumed);
        }

        validate_registry_client_offer_reservation(&reservation, now)?;
        if records.consumed_evaluations.contains_key(&evaluation_hash) {
            return Err(PreauthorizationStateError::EvaluationConsumed);
        }
        if records.issuance.contains_key(&transaction_hash)
            || records.transaction_codes.contains_key(&transaction_hash)
        {
            return Err(PreauthorizationStateError::DuplicateIssuanceTransaction);
        }
        if records.issuance.len() >= OID4VCI_ISSUANCE_TRANSACTION_MAX_ENTRIES
            || records.registry_client_offers.len() >= REGISTRY_CLIENT_OFFER_MAX_ENTRIES
            || records.consumed_evaluations.len() >= EVALUATION_ISSUANCE_MAX_ENTRIES
        {
            return Err(PreauthorizationStateError::IssuanceTransactionCapacity);
        }
        let transaction_code = reservation
            .transaction_code
            .as_ref()
            .map(|code| {
                let pin_length = usize::try_from(code.pin_length)
                    .map_err(|_| PreauthorizationStateError::Unavailable)?;
                Ok::<TransactionCodeVerifier, PreauthorizationStateError>(TransactionCodeVerifier {
                    verifier: self.keys.pin_verifier(&transaction_hash, &code.pin),
                    pin_length,
                })
            })
            .transpose()?;
        reserve_offer_quota(&mut records, &reservation, now)?;
        let response = reservation.response.clone();
        let purge_after = std::cmp::max(
            reservation.evaluation_expires_at,
            reservation.retention_expires_at,
        );

        records.issuance.insert(
            transaction_hash,
            Stored {
                value: StoredIssuanceTransaction {
                    transaction: reservation.transaction,
                    nonce: None,
                    state: MaterializationState::Ready,
                },
                expires_at: reservation.transaction_expires_at,
            },
        );
        if let Some(verifier) = transaction_code {
            records.transaction_codes.insert(
                transaction_hash,
                Stored {
                    value: verifier,
                    expires_at: reservation.code_expires_at,
                },
            );
        }
        records
            .consumed_evaluations
            .insert(evaluation_hash, reservation.evaluation_expires_at);
        records.registry_client_offers.insert(
            idempotency_hash,
            StoredRegistryClientOffer {
                request_hash,
                response: reservation.response,
                retention_expires_at: reservation.retention_expires_at,
                purge_after,
            },
        );
        Ok(RegistryClientOfferReservationOutcome::Created(response))
    }

    fn reserve_evaluation_issuance(
        &self,
        evaluation_id: &str,
        evaluation_client_id: &str,
        evaluation_expires_at: OffsetDateTime,
    ) -> Result<(), PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        if evaluation_id.is_empty() || evaluation_client_id.is_empty() {
            return Err(PreauthorizationStateError::Unavailable);
        }
        if evaluation_expires_at <= now {
            return Err(PreauthorizationStateError::InvalidExpiry);
        }
        let evaluation_hash = self.evaluation_issuance_hash(evaluation_id, evaluation_client_id);
        let mut records = self.lock_records()?;
        prune_offer_records(&mut records, now);
        if records.consumed_evaluations.contains_key(&evaluation_hash) {
            return Err(PreauthorizationStateError::EvaluationConsumed);
        }
        if records.consumed_evaluations.len() >= EVALUATION_ISSUANCE_MAX_ENTRIES {
            return Err(PreauthorizationStateError::IssuanceTransactionCapacity);
        }
        records
            .consumed_evaluations
            .insert(evaluation_hash, evaluation_expires_at);
        Ok(())
    }

    fn evaluation_issuance_hash(
        &self,
        evaluation_id: &str,
        evaluation_client_id: &str,
    ) -> [u8; 32] {
        self.keys.identifier_hash_fields(
            EVALUATION_ISSUANCE_CONTEXT,
            &[evaluation_id.as_bytes(), evaluation_client_id.as_bytes()],
        )
    }

    fn transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<IssuanceTransaction>, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        let key = replay_identifier_hash(transaction_id);
        let mut records = self.lock_records()?;
        records.issuance.retain(|_, record| record.expires_at > now);
        Ok(records
            .issuance
            .get(&key)
            .map(|record| record.value.transaction.clone()))
    }

    fn bind_transaction_nonce(
        &self,
        transaction_id: &str,
        commitment: &str,
        nonce: String,
    ) -> Result<bool, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        let key = replay_identifier_hash(transaction_id);
        let mut records = self.lock_records()?;
        records.issuance.retain(|_, record| record.expires_at > now);
        let Some(record) = records.issuance.get_mut(&key) else {
            return Ok(false);
        };
        if record.value.transaction.commitment != commitment || record.value.nonce.is_some() {
            return Ok(false);
        }
        record.value.nonce = Some(nonce);
        Ok(true)
    }

    fn begin_credential_materialization(
        &self,
        transaction_id: &str,
        commitment: &str,
        configuration_id: &str,
        nonce: &str,
        holder_thumbprint: &str,
        request_hash: &str,
    ) -> Result<CredentialMaterialization, PreauthorizationStateError> {
        let now = OffsetDateTime::now_utc();
        let key = replay_identifier_hash(transaction_id);
        let mut records = self.lock_records()?;
        records.issuance.retain(|_, record| record.expires_at > now);
        let Some(record) = records.issuance.get_mut(&key) else {
            return Ok(CredentialMaterialization::Denied);
        };
        let transaction = &record.value.transaction;
        if transaction.commitment != commitment
            || transaction.credential_configuration_id != configuration_id
            || record.value.nonce.as_deref() != Some(nonce)
        {
            return Ok(CredentialMaterialization::Denied);
        }
        match &record.value.state {
            MaterializationState::Ready => {
                let transaction = transaction.clone();
                record.value.state = MaterializationState::Issuing {
                    holder_thumbprint: holder_thumbprint.to_string(),
                    request_hash: request_hash.to_string(),
                };
                Ok(CredentialMaterialization::Acquired(transaction))
            }
            MaterializationState::Issuing {
                holder_thumbprint: bound,
                request_hash: bound_request,
            } if bound == holder_thumbprint && bound_request == request_hash => {
                Ok(CredentialMaterialization::Busy)
            }
            MaterializationState::Completed {
                holder_thumbprint: bound,
                request_hash: bound_request,
                response,
            } if bound == holder_thumbprint && bound_request == request_hash => {
                Ok(CredentialMaterialization::Cached(response.clone()))
            }
            MaterializationState::Issuing { .. }
            | MaterializationState::Completed { .. }
            | MaterializationState::Failed => Ok(CredentialMaterialization::Denied),
        }
    }

    fn complete_credential_materialization(
        &self,
        transaction_id: &str,
        holder_thumbprint: &str,
        request_hash: &str,
        response: Value,
    ) -> Result<bool, PreauthorizationStateError> {
        let key = replay_identifier_hash(transaction_id);
        let mut records = self.lock_records()?;
        let Some(record) = records.issuance.get_mut(&key) else {
            return Ok(false);
        };
        match &record.value.state {
            MaterializationState::Issuing {
                holder_thumbprint: bound,
                request_hash: bound_request,
            } if bound == holder_thumbprint && bound_request == request_hash => {
                record.value.state = MaterializationState::Completed {
                    holder_thumbprint: holder_thumbprint.to_string(),
                    request_hash: request_hash.to_string(),
                    response,
                };
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn fail_credential_materialization(
        &self,
        transaction_id: &str,
        holder_thumbprint: &str,
    ) -> Result<(), PreauthorizationStateError> {
        let key = replay_identifier_hash(transaction_id);
        let mut records = self.lock_records()?;
        if let Some(record) = records.issuance.get_mut(&key) {
            if matches!(
                &record.value.state,
                MaterializationState::Issuing { holder_thumbprint: bound, .. } if bound == holder_thumbprint
            ) {
                record.value.state = MaterializationState::Failed;
            }
        }
        Ok(())
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

fn prune_offer_records(records: &mut InMemoryRecords, now: OffsetDateTime) {
    records.issuance.retain(|_, stored| stored.expires_at > now);
    records
        .transaction_codes
        .retain(|_, stored| stored.expires_at > now);
    records
        .registry_client_offers
        .retain(|_, stored| stored.purge_after > now);
    records
        .consumed_evaluations
        .retain(|_, expires_at| *expires_at > now);
    records
        .machine_quota
        .retain(|_, quota| quota.window_expires_at > now);
}

fn reserve_offer_quota(
    records: &mut InMemoryRecords,
    reservation: &RegistryClientOfferReservation,
    now: OffsetDateTime,
) -> Result<(), PreauthorizationStateError> {
    let principal_hash: [u8; 32] = reservation
        .quota_principal_hash
        .as_slice()
        .try_into()
        .map_err(|_| PreauthorizationStateError::Unavailable)?;
    if reservation.quota_cost <= 0 || reservation.quota_limit.is_some_and(|limit| limit <= 0) {
        return Err(PreauthorizationStateError::Unavailable);
    }
    let Some(limit) = reservation.quota_limit else {
        return Ok(());
    };
    let (window_expires_at, used) = records
        .machine_quota
        .get(&principal_hash)
        .filter(|quota| quota.window_expires_at > now)
        .map_or((now + MACHINE_QUOTA_WINDOW, 0), |quota| {
            (quota.window_expires_at, quota.used)
        });
    if reservation.quota_cost > limit.saturating_sub(used) {
        let remaining_millis = (window_expires_at - now).whole_milliseconds().max(1);
        return Err(PreauthorizationStateError::MachineQuotaExceeded {
            retry_after_seconds: ((remaining_millis + 999) / 1_000) as u64,
        });
    }
    if !records.machine_quota.contains_key(&principal_hash)
        && records.machine_quota.len() >= MACHINE_QUOTA_MAX_ENTRIES
    {
        if let Some(oldest) = records
            .machine_quota
            .iter()
            .min_by_key(|(_, quota)| quota.window_expires_at)
            .map(|(principal_hash, _)| *principal_hash)
        {
            records.machine_quota.remove(&oldest);
        }
    }
    records.machine_quota.insert(
        principal_hash,
        StoredMachineQuota {
            window_expires_at,
            used: used + reservation.quota_cost,
        },
    );
    Ok(())
}

pub(crate) fn validate_registry_client_offer_reservation(
    reservation: &RegistryClientOfferReservation,
    now: OffsetDateTime,
) -> Result<(), PreauthorizationStateError> {
    validate_registry_client_offer_structure(reservation)?;
    if reservation.code_expires_at <= now
        || reservation.transaction_expires_at < reservation.code_expires_at
        || reservation.evaluation_expires_at <= now
        || reservation.retention_expires_at < reservation.code_expires_at
    {
        return Err(PreauthorizationStateError::InvalidExpiry);
    }
    Ok(())
}

pub(crate) fn validate_registry_client_offer_structure(
    reservation: &RegistryClientOfferReservation,
) -> Result<(), PreauthorizationStateError> {
    if reservation.transaction_id != reservation.transaction.transaction_id
        || reservation.evaluation_id != reservation.transaction.evaluation_id
    {
        return Err(PreauthorizationStateError::Unavailable);
    }
    let IssuanceAuthority::RegistryClient {
        initiating_client_id,
        initiating_client_id_hash,
        target_ref,
        ..
    } = &reservation.transaction.authority
    else {
        return Err(PreauthorizationStateError::Unavailable);
    };
    if initiating_client_id.is_empty()
        || initiating_client_id != &reservation.transaction.evaluation_client_id
        || decode_hash_uri(initiating_client_id_hash, "hmac-sha256:").is_err()
        || target_ref.handle.is_empty()
        || reservation.quota_principal_hash.len() != 32
        || reservation.quota_cost <= 0
        || reservation.quota_limit.is_some_and(|limit| limit <= 0)
    {
        return Err(PreauthorizationStateError::Unavailable);
    }
    match (
        reservation.transaction_code.as_ref(),
        reservation.response.tx_code.as_deref(),
    ) {
        (None, None) => {}
        (Some(code), Some(response_code))
            if (4..=12).contains(&code.pin_length)
                && usize::try_from(code.pin_length).ok() == Some(code.pin.len())
                && code.pin.bytes().all(|byte| byte.is_ascii_digit())
                && response_code
                    .as_bytes()
                    .ct_eq(code.pin.as_bytes())
                    .unwrap_u8()
                    == 1 => {}
        _ => return Err(PreauthorizationStateError::Unavailable),
    }
    Ok(())
}

pub(crate) fn decode_hash_uri(
    value: &str,
    expected_prefix: &str,
) -> Result<[u8; 32], PreauthorizationStateError> {
    let encoded = value
        .strip_prefix(expected_prefix)
        .ok_or(PreauthorizationStateError::Unavailable)?;
    if encoded.len() != 64 {
        return Err(PreauthorizationStateError::Unavailable);
    }
    let mut decoded = [0_u8; 32];
    for (destination, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let high = hex_nibble(pair[0]).ok_or(PreauthorizationStateError::Unavailable)?;
        let low = hex_nibble(pair[1]).ok_or(PreauthorizationStateError::Unavailable)?;
        *destination = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
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

    fn issuance_transaction() -> IssuanceTransaction {
        IssuanceTransaction {
            transaction_id: "transaction-1".to_string(),
            evaluation_id: "evaluation-1".to_string(),
            evaluation_client_id: "client-1".to_string(),
            credential_configuration_id: "person_is_alive_sd_jwt".to_string(),
            commitment: format!("sha256:{}", "a".repeat(64)),
            authority: IssuanceAuthority::SubjectAccess,
        }
    }

    fn registry_client_offer_reservation(
        transaction_id: &str,
        evaluation_id: &str,
        idempotency_byte: char,
        request_byte: char,
    ) -> RegistryClientOfferReservation {
        let now = OffsetDateTime::now_utc();
        let pin = "246810".to_string();
        RegistryClientOfferReservation {
            transaction_id: transaction_id.to_string(),
            evaluation_id: evaluation_id.to_string(),
            evaluation_expires_at: now + Duration::minutes(20),
            idempotency_key_hash: format!(
                "hmac-sha256:{}",
                idempotency_byte.to_string().repeat(64)
            ),
            canonical_request_hash: format!("sha256:{}", request_byte.to_string().repeat(64)),
            transaction: IssuanceTransaction {
                transaction_id: transaction_id.to_string(),
                evaluation_id: evaluation_id.to_string(),
                evaluation_client_id: "registry-client".to_string(),
                credential_configuration_id: "person_is_alive_sd_jwt".to_string(),
                commitment: format!("sha256:{}", "a".repeat(64)),
                authority: IssuanceAuthority::RegistryClient {
                    initiating_client_id: "registry-client".to_string(),
                    initiating_client_id_hash: format!("hmac-sha256:{}", "c".repeat(64)),
                    auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
                    authorized_scopes: vec!["registry:evidence".to_string()],
                    target_ref: registry_notary_core::TargetRefView {
                        entity_type: "Person".to_string(),
                        handle: "opaque-target-handle".to_string(),
                        identifier_schemes: Vec::new(),
                        profile: None,
                    },
                    service_id: "notary.test".to_string(),
                    purpose: "civil-registration".to_string(),
                },
            },
            transaction_code: Some(RegistryClientTransactionCode {
                pin: pin.clone(),
                pin_length: 6,
            }),
            code_expires_at: now + Duration::minutes(5),
            transaction_expires_at: now + Duration::minutes(15),
            response: RegistryClientOfferResponse {
                credential_offer_uri: format!(
                    "openid-credential-offer://?credential_offer_uri={transaction_id}"
                ),
                tx_code: Some(pin),
                expires_at: "2030-01-01T00:00:00Z".to_string(),
            },
            retention_expires_at: now + Duration::minutes(10),
            quota_principal_hash: vec![0x71; 32],
            quota_limit: None,
            quota_cost: 1,
        }
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
    async fn issuance_materialization_binds_holder_and_exact_request_and_caches_response() {
        let state = memory_state();
        let transaction = issuance_transaction();
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        state
            .reserve_issuance_transaction(
                &transaction.transaction_id,
                transaction.clone(),
                expires_at,
            )
            .await
            .unwrap();
        assert!(state
            .bind_transaction_nonce(
                &transaction.transaction_id,
                &transaction.commitment,
                "token-nonce".to_string(),
            )
            .await
            .unwrap());
        assert!(matches!(
            state
                .begin_credential_materialization(
                    &transaction.transaction_id,
                    &transaction.commitment,
                    &transaction.credential_configuration_id,
                    "token-nonce",
                    "holder-one",
                    "request-one",
                )
                .await
                .unwrap(),
            CredentialMaterialization::Acquired(_)
        ));
        assert!(matches!(
            state
                .begin_credential_materialization(
                    &transaction.transaction_id,
                    &transaction.commitment,
                    &transaction.credential_configuration_id,
                    "token-nonce",
                    "holder-two",
                    "request-one",
                )
                .await
                .unwrap(),
            CredentialMaterialization::Denied
        ));
        let response = serde_json::json!({"credential": "signed-once"});
        assert!(state
            .complete_credential_materialization(
                &transaction.transaction_id,
                "holder-one",
                "request-one",
                response.clone(),
            )
            .await
            .unwrap());
        match state
            .begin_credential_materialization(
                &transaction.transaction_id,
                &transaction.commitment,
                &transaction.credential_configuration_id,
                "token-nonce",
                "holder-one",
                "request-one",
            )
            .await
            .unwrap()
        {
            CredentialMaterialization::Cached(cached) => assert_eq!(cached, response),
            outcome => panic!("expected cached response, got {outcome:?}"),
        }
        assert!(matches!(
            state
                .begin_credential_materialization(
                    &transaction.transaction_id,
                    &transaction.commitment,
                    &transaction.credential_configuration_id,
                    "token-nonce",
                    "holder-one",
                    "different-request",
                )
                .await
                .unwrap(),
            CredentialMaterialization::Denied
        ));
    }

    #[tokio::test]
    async fn failed_issuance_materialization_is_terminal() {
        let state = memory_state();
        let transaction = issuance_transaction();
        state
            .reserve_issuance_transaction(
                &transaction.transaction_id,
                transaction.clone(),
                OffsetDateTime::now_utc() + Duration::minutes(5),
            )
            .await
            .unwrap();
        assert!(state
            .bind_transaction_nonce(
                &transaction.transaction_id,
                &transaction.commitment,
                "token-nonce".to_string(),
            )
            .await
            .unwrap());
        assert!(matches!(
            state
                .begin_credential_materialization(
                    &transaction.transaction_id,
                    &transaction.commitment,
                    &transaction.credential_configuration_id,
                    "token-nonce",
                    "holder-one",
                    "request-one",
                )
                .await
                .unwrap(),
            CredentialMaterialization::Acquired(_)
        ));
        state
            .fail_credential_materialization(&transaction.transaction_id, "holder-one")
            .await
            .unwrap();
        assert!(matches!(
            state
                .begin_credential_materialization(
                    &transaction.transaction_id,
                    &transaction.commitment,
                    &transaction.credential_configuration_id,
                    "token-nonce",
                    "holder-one",
                    "request-one",
                )
                .await
                .unwrap(),
            CredentialMaterialization::Denied
        ));
    }

    #[tokio::test]
    async fn registry_client_offer_exact_replay_returns_the_cached_response() {
        let state = memory_state();
        let reservation =
            registry_client_offer_reservation("offer-transaction", "evaluation", '1', 'a');
        let expected = reservation.response.clone();
        assert_eq!(
            state
                .reserve_registry_client_offer(reservation)
                .await
                .unwrap(),
            RegistryClientOfferReservationOutcome::Created(expected.clone())
        );
        assert_eq!(
            state
                .reserve_registry_client_offer(registry_client_offer_reservation(
                    "offer-transaction",
                    "evaluation",
                    '1',
                    'a',
                ))
                .await
                .unwrap(),
            RegistryClientOfferReservationOutcome::Replayed(expected)
        );
    }

    #[tokio::test]
    async fn registry_client_offer_conflict_and_consumed_evaluation_are_distinct() {
        let state = memory_state();
        state
            .reserve_registry_client_offer(registry_client_offer_reservation(
                "offer-transaction",
                "evaluation",
                '1',
                'a',
            ))
            .await
            .unwrap();
        assert!(matches!(
            state
                .reserve_registry_client_offer(registry_client_offer_reservation(
                    "offer-transaction",
                    "evaluation",
                    '1',
                    'b',
                ))
                .await,
            Err(PreauthorizationStateError::IdempotencyConflict)
        ));
        assert!(matches!(
            state
                .reserve_registry_client_offer(registry_client_offer_reservation(
                    "other-transaction",
                    "evaluation",
                    '2',
                    'a',
                ))
                .await,
            Err(PreauthorizationStateError::EvaluationConsumed)
        ));
        assert!(state
            .transaction("other-transaction")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn concurrent_exact_retries_create_once_and_replay_once() {
        let state = Arc::new(memory_state());
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut attempts = Vec::new();
        for _ in 0..2 {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            attempts.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut reservation =
                    registry_client_offer_reservation("offer-transaction", "evaluation", '1', 'a');
                reservation.quota_limit = Some(1);
                state
                    .reserve_registry_client_offer(reservation)
                    .await
                    .unwrap()
            }));
        }
        barrier.wait().await;
        let outcomes = [
            attempts.remove(0).await.unwrap(),
            attempts.remove(0).await.unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    RegistryClientOfferReservationOutcome::Created(_)
                ))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    RegistryClientOfferReservationOutcome::Replayed(_)
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_idempotency_keys_consume_an_evaluation_once() {
        let state = Arc::new(memory_state());
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut attempts = Vec::new();
        for (transaction_id, idempotency_byte) in [
            ("offer-transaction-one", '1'),
            ("offer-transaction-two", '2'),
        ] {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            attempts.push(tokio::spawn(async move {
                barrier.wait().await;
                state
                    .reserve_registry_client_offer(registry_client_offer_reservation(
                        transaction_id,
                        "evaluation",
                        idempotency_byte,
                        'a',
                    ))
                    .await
            }));
        }
        barrier.wait().await;
        let outcomes = [
            attempts.remove(0).await.unwrap(),
            attempts.remove(0).await.unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    Ok(RegistryClientOfferReservationOutcome::Created(_))
                ))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    Err(PreauthorizationStateError::EvaluationConsumed)
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn direct_and_offer_reservations_share_one_evaluation_lineage() {
        let state = memory_state();
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(20);
        state
            .reserve_evaluation_issuance("direct-first", "registry-client", expires_at)
            .await
            .unwrap();
        assert!(matches!(
            state
                .reserve_registry_client_offer(registry_client_offer_reservation(
                    "offer-after-direct",
                    "direct-first",
                    '3',
                    'a',
                ))
                .await,
            Err(PreauthorizationStateError::EvaluationConsumed)
        ));

        state
            .reserve_registry_client_offer(registry_client_offer_reservation(
                "offer-first",
                "offer-first-evaluation",
                '4',
                'a',
            ))
            .await
            .unwrap();
        assert!(matches!(
            state
                .reserve_evaluation_issuance(
                    "offer-first-evaluation",
                    "registry-client",
                    expires_at,
                )
                .await,
            Err(PreauthorizationStateError::EvaluationConsumed)
        ));
    }

    #[tokio::test]
    async fn concurrent_direct_and_offer_reservations_have_exactly_one_winner() {
        let state = Arc::new(memory_state());
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let direct_state = Arc::clone(&state);
        let direct_barrier = Arc::clone(&barrier);
        let direct = tokio::spawn(async move {
            direct_barrier.wait().await;
            direct_state
                .reserve_evaluation_issuance(
                    "raced-evaluation",
                    "registry-client",
                    OffsetDateTime::now_utc() + Duration::minutes(20),
                )
                .await
                .map(|()| "direct")
        });
        let offer_state = Arc::clone(&state);
        let offer_barrier = Arc::clone(&barrier);
        let offer = tokio::spawn(async move {
            offer_barrier.wait().await;
            offer_state
                .reserve_registry_client_offer(registry_client_offer_reservation(
                    "raced-offer",
                    "raced-evaluation",
                    '5',
                    'a',
                ))
                .await
                .map(|_| "offer")
        });
        barrier.wait().await;
        let outcomes = [direct.await.unwrap(), offer.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    Err(PreauthorizationStateError::EvaluationConsumed)
                ))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn offer_quota_charges_only_a_new_winning_reservation() {
        let state = memory_state();
        let mut first =
            registry_client_offer_reservation("quota-first", "quota-evaluation-one", '6', 'a');
        first.quota_limit = Some(1);
        assert!(matches!(
            state.reserve_registry_client_offer(first).await,
            Ok(RegistryClientOfferReservationOutcome::Created(_))
        ));

        let mut replay =
            registry_client_offer_reservation("quota-first", "quota-evaluation-one", '6', 'a');
        replay.quota_limit = Some(1);
        assert!(matches!(
            state.reserve_registry_client_offer(replay).await,
            Ok(RegistryClientOfferReservationOutcome::Replayed(_))
        ));

        let mut second =
            registry_client_offer_reservation("quota-second", "quota-evaluation-two", '7', 'a');
        second.quota_limit = Some(1);
        assert!(matches!(
            state.reserve_registry_client_offer(second).await,
            Err(PreauthorizationStateError::MachineQuotaExceeded {
                retry_after_seconds: 1..=60
            })
        ));
        state
            .reserve_evaluation_issuance(
                "quota-evaluation-two",
                "registry-client",
                OffsetDateTime::now_utc() + Duration::minutes(20),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejected_registry_client_offer_rolls_back_every_reservation() {
        let state = memory_state();
        let mut invalid =
            registry_client_offer_reservation("offer-transaction", "evaluation", '1', 'a');
        invalid.retention_expires_at = OffsetDateTime::now_utc() + Duration::minutes(1);
        assert!(matches!(
            state.reserve_registry_client_offer(invalid).await,
            Err(PreauthorizationStateError::InvalidExpiry)
        ));
        let valid = registry_client_offer_reservation("offer-transaction", "evaluation", '1', 'a');
        assert!(matches!(
            state.reserve_registry_client_offer(valid).await,
            Ok(RegistryClientOfferReservationOutcome::Created(_))
        ));
        assert!(state
            .verify_transaction_code("offer-transaction", "246810")
            .await
            .unwrap()
            .is_some());
        assert!(state
            .transaction("offer-transaction")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn registry_client_offer_without_pin_remains_atomically_redeemable() {
        let state = memory_state();
        let mut reservation =
            registry_client_offer_reservation("offer-transaction", "evaluation", '1', 'a');
        reservation.transaction_code = None;
        reservation.response.tx_code = None;
        let code_expires_at = reservation.code_expires_at;
        assert!(matches!(
            state.reserve_registry_client_offer(reservation).await,
            Ok(RegistryClientOfferReservationOutcome::Created(_))
        ));
        assert!(state
            .redeem(&scope(), "offer-transaction", code_expires_at, false, None,)
            .await
            .unwrap());
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

        let reservation =
            registry_client_offer_reservation("secret-transaction", "secret-evaluation", '1', 'a');
        let rendered = format!("{reservation:?}");
        for secret in [
            "registry-client",
            "opaque-target-handle",
            "civil-registration",
            "secret-transaction",
            "secret-evaluation",
            "openid-credential-offer",
            "246810",
        ] {
            assert!(!rendered.contains(secret), "Debug exposed {secret}");
        }
    }

    #[test]
    fn login_state_has_an_explicit_zeroize_lifecycle() {
        fn requires_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        requires_zeroize::<LoginState>();
        requires_zeroize::<RegistryClientOfferResponse>();
        requires_zeroize::<RegistryClientTransactionCode>();
    }
}
