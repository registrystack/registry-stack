// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine's hooks: its side of the platform delivery core.
//!
//! `registry-platform-hooks` owns the at-least-once delivery worker, the
//! signing URL destination, the pooled connection seam, the audit record
//! shape, and the local hook program executor. This module supplies the
//! seams only Base Registry Engine can: the runtime pool, the
//! deployment-identity preflight, the keyed hook audit references, the
//! operational vocabulary, the activated destinations, the local programs the
//! running package holds, and proposal application with its completion
//! barrier. The signed bytes on the wire are produced by the shared URL
//! destination from the same field values and key material, and the
//! idempotency domain and delivery source identity are passed through
//! unchanged.

use std::path::Path;
#[cfg(feature = "postgres-test")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use registry_platform_dispatch::postgres::PooledClient;
use registry_platform_hooks::delivery::{
    DeliveryAuditRecord, DeliveryConfig, DeliveryConnection, DeliveryError,
    DeliveryOperationalEvent, DeliverySeams, DeliveryService, DeliveryTransitionCode,
    DeliveryWorker, HookHandlerBinding, ProposalApplication, ProposalOutcome,
    ProposalReceiptRecovery, SharedUrlDestination,
};
use registry_platform_hooks::executor::{LocalHookHandler, LocalHookHandlers, LocalHookProgram};
#[cfg(feature = "wasm")]
use registry_platform_hooks::executor::{WasmHookBudgets, WasmHookRuntime, WasmHookRuntimeError};
use registry_platform_hooks::{BoundedText, MAX_REFUSAL_SUMMARY_BYTES};
use tokio::sync::watch;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::audit::{hook_entry, RegistryAudit};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::field_encryption::FieldEncryptionService;
use crate::idempotency::IdempotencyPolicy;
use crate::model::CompiledRegistry;
use crate::mutation::{HookChangeApplication, HookChangeOutcome, MutationTransaction};
use crate::package::PackageError;
use crate::postgres::{ExpectedRegistryIdentity, RegistryLockKey, RuntimePool};
use crate::runtime_config::load_runtime_config;
use crate::startup::{HookStateTransitionCode, OperationalEvent};

pub use registry_platform_hooks::delivery::{
    DeliveryError as HookDeliveryError, DeliveryFailureReason as HookDeliveryFailureReason,
    DeliveryOutcome as HookWorkOutcome, DeliveryStatus as HookDeliveryStatus,
    DeliveryStatusKind as HookDeliveryStatusKind, RetainedBindingError as HookRetainedBindingError,
    MAX_DELIVERY_STATUS_RESULTS as MAX_HOOK_STATUS_RESULTS,
};

const IDEMPOTENCY_DOMAIN: &[u8] = b"breg-webhook-idempotency-v1";
/// The schema Base Registry Engine installs the platform delivery tables
/// into, and the one the worker and the capture INSERT read and write.
pub(crate) const DELIVERY_SCHEMA: &str = "registry_internal";

/// The event source one registry deployment stamps on every captured envelope
/// and every delivery header.
pub(crate) fn delivery_source(package_id: &str, instance_id: &str) -> String {
    format!("urn:registrystack:registry:{package_id}:instance:{instance_id}")
}

/// Every local hook program the running package holds, admitted by the
/// shared executor under `package_revision`.
///
/// A program whose recorded identity digest does not cover its own bytes, or
/// that speaks another handler ABI, is left out, so a delivery row bound to it
/// resolves no handler and is refused as a binding mismatch rather than run.
/// WASM programs need a hook runtime attached with
/// [`LocalHookHandlers::with_wasm_runtime`] before one can run.
#[must_use]
pub fn local_hook_handlers(
    compiled: &CompiledRegistry,
    package_revision: &str,
) -> LocalHookHandlers {
    let mut handlers = LocalHookHandlers::new(package_revision);
    for delivery in &compiled.event_deliveries().deliveries {
        let Some(handler) = delivery.handler.as_ref() else {
            continue;
        };
        if let Ok(program) = LocalHookProgram::new(
            handler.kind.shared(),
            &handler.abi,
            &handler.digest,
            handler.bytes.clone(),
            Duration::from_millis(u64::from(delivery.attempt_timeout_ms)),
            delivery.maximum_attempts,
        ) {
            handlers.insert(&delivery.id, program);
        }
    }
    handlers
}

/// The hook-owned WASM runtime, under the operator's configured module and
/// guest memory budgets and backend. It is separate from the action handler
/// runtime and its module cache: hook programs and action handlers never
/// share prepared modules.
///
/// # Errors
///
/// [`WasmHookRuntimeError`] when the engine or its epoch ticker cannot start.
#[cfg(feature = "wasm")]
pub fn hook_wasm_runtime(
    config: &crate::runtime_config::WasmExecutionConfig,
) -> Result<Arc<WasmHookRuntime>, WasmHookRuntimeError> {
    start_hook_wasm_runtime(
        WasmHookBudgets {
            max_module_bytes: config.max_module_bytes() as usize,
            max_guest_memory_bytes: config.max_guest_memory_bytes() as usize,
        },
        config.backend(),
    )
}

/// The hook-owned WASM runtime under the default module and guest memory
/// budgets and backend, for an embedder that assembles the delivery path
/// without a runtime configuration file.
///
/// # Errors
///
/// [`WasmHookRuntimeError`] when the engine or its epoch ticker cannot start.
#[cfg(feature = "wasm")]
pub fn default_hook_wasm_runtime() -> Result<Arc<WasmHookRuntime>, WasmHookRuntimeError> {
    start_hook_wasm_runtime(
        WasmHookBudgets {
            max_module_bytes: crate::wasm_handler::DEFAULT_WASM_MODULE_BYTES,
            max_guest_memory_bytes: crate::wasm_handler::DEFAULT_WASM_GUEST_MEMORY_BYTES,
        },
        crate::wasm_handler::WasmExecutionBackend::default(),
    )
}

#[cfg(feature = "wasm")]
fn start_hook_wasm_runtime(
    budgets: WasmHookBudgets,
    backend: crate::wasm_handler::WasmExecutionBackend,
) -> Result<Arc<WasmHookRuntime>, WasmHookRuntimeError> {
    WasmHookRuntime::new(budgets, crate::wasm_handler::execution_backend(backend)).map(Arc::new)
}

const _: () = assert!(
    crate::compiler::MAX_HOOK_PAYLOAD_BYTES as usize
        == registry_platform_crypto::delivery_signature::MAX_BODY_BYTES
);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HookOperatorError {
    /// The package at `package.root` is not the one the runtime file's
    /// `package.expectedDigest` pins. Both digests are package identities,
    /// not secrets, so the refusal names them.
    #[error("{0}")]
    PackagePinMismatch(registry_platform_config::blocks::PackageDigestMismatch),
    #[error("hook operator request is unavailable")]
    Unavailable,
}

/// Verified, product-owned operator boundary used by `bregctl`.
///
/// Construction closes package, database identity, destination, and audit
/// bindings before operator actions are available. Listing deliberately
/// remains available when retained rows name a superseded binding; replay
/// still checks the exact captured binding itself. The CLI therefore owns no
/// SQL, retry transition, or signing behavior.
pub struct HookOperatorService {
    delivery: HookDeliveryService,
}

impl HookOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self, HookOperatorError> {
        Self::from_runtime_config_with_execution(path, false).await
    }

    /// Drain only due local work using the active runtime's execution bindings.
    pub async fn drain_local(
        path: &Path,
        max_attempts: u16,
        timeout: Duration,
    ) -> Result<HookDrainReport, HookOperatorError> {
        validate_drain_budget(max_attempts, timeout).map_err(|_| HookOperatorError::Unavailable)?;
        let service = Self::from_runtime_config_with_execution(path, true).await?;
        service
            .delivery
            .drain_local(max_attempts, timeout)
            .await
            .map_err(|_| HookOperatorError::Unavailable)
    }

    async fn from_runtime_config_with_execution(
        path: &Path,
        execute_local_hooks: bool,
    ) -> Result<Self, HookOperatorError> {
        let config = load_runtime_config(path).map_err(|_| HookOperatorError::Unavailable)?;
        let package = config.load_active_package().map_err(|error| match error {
            PackageError::ExpectedDigestMismatch(mismatch) => {
                HookOperatorError::PackagePinMismatch(mismatch)
            }
            _ => HookOperatorError::Unavailable,
        })?;
        let connection = config
            .runtime_database_connection_config()
            .map_err(|_| HookOperatorError::Unavailable)?;
        let pool = connection
            .build_pool()
            .map_err(|_| HookOperatorError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| HookOperatorError::Unavailable)?;
        let startup = crate::startup::prepare_loaded_startup(
            package,
            config.identity().database_id(),
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| HookOperatorError::Unavailable)?;
        drop(client);
        let destinations = Arc::new(
            config
                .activate_event_destinations(startup.package().registry())
                .map_err(|_| HookOperatorError::Unavailable)?,
        );
        let audit = RegistryAudit::open_companion(&config)
            .await
            .map_err(|_| HookOperatorError::Unavailable)?;
        let handlers = local_hook_handlers(
            startup.package().registry(),
            &startup.expected_identity().activation_id,
        );
        // Inspection and explicit recovery need no executable handler or
        // encryption key. A drain does, and uses the same active bindings
        // and custody checks as the serving mutation path.
        let registry = startup.package().registry();
        let field_encryption = if execute_local_hooks
            && registry.entities().values().any(|entity| {
                entity
                    .fields
                    .values()
                    .any(|field| field.encryption.is_some())
            }) {
            let provider = config
                .field_encryption()
                .provider()
                .ok_or(HookOperatorError::Unavailable)?;
            if matches!(
                provider,
                crate::field_encryption::FieldEncryptionProvider::LocalFile { .. }
            ) && config.identity().database_initialization_environment() != "local"
            {
                return Err(HookOperatorError::Unavailable);
            }
            let secrets = config
                .secret_resolver()
                .map_err(|_| HookOperatorError::Unavailable)?;
            let client = pool
                .get()
                .await
                .map_err(|_| HookOperatorError::Unavailable)?;
            Some(Arc::new(
                FieldEncryptionService::open_existing(
                    provider,
                    registry.registry_id(),
                    &secrets,
                    &**client,
                )
                .await
                .map_err(|_| HookOperatorError::Unavailable)?,
            ))
        } else {
            None
        };
        // A drain runs WASM programs on its own hook runtime under the
        // operator budgets and backend; inspection and recovery run none.
        #[cfg(feature = "wasm")]
        let handlers = if execute_local_hooks {
            handlers.with_wasm_runtime(
                hook_wasm_runtime(config.wasm_execution())
                    .map_err(|_| HookOperatorError::Unavailable)?,
            )
        } else {
            handlers
        };
        let handlers = Arc::new(handlers);
        let idempotency = config
            .idempotency_policy()
            .map_err(|_| HookOperatorError::Unavailable)?;
        let delivery = HookDeliveryService::new_with_runtime_bindings(
            pool,
            destinations,
            handlers,
            Arc::new(startup.package().registry().clone()),
            startup.expected_identity().clone(),
            config.identity().instance_id(),
            startup.lock_key(),
            config.operational_timeouts().record_lock,
            audit,
            field_encryption,
            idempotency,
        );
        Ok(Self { delivery })
    }

    pub async fn list(&self, limit: u16) -> Result<Vec<HookDeliveryStatus>, HookOperatorError> {
        self.delivery
            .list(limit)
            .await
            .map_err(|_| HookOperatorError::Unavailable)
    }

    pub async fn replay(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, HookOperatorError> {
        self.delivery
            .replay(event_id, compiled_delivery_id, expected_generation)
            .await
            .map_err(|_| HookOperatorError::Unavailable)
    }

    pub async fn discard(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, HookOperatorError> {
        self.delivery
            .discard(event_id, compiled_delivery_id, expected_generation)
            .await
            .map_err(|_| HookOperatorError::Unavailable)
    }
}

/// Base Registry Engine's seams under the platform delivery worker: the
/// runtime pool, the deployment-identity preflight, the hook audit
/// journal, the operational vocabulary, and the activated destinations.
#[derive(Clone)]
struct BregDeliverySeams {
    pool: RuntimePool,
    destinations: Arc<ActivatedEventDestinationRegistry>,
    handlers: Arc<LocalHookHandlers>,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    instance_id: String,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: RegistryAudit,
    field_encryption: Option<Arc<FieldEncryptionService>>,
    idempotency: IdempotencyPolicy,
    last_success: Arc<crate::metrics::LastSuccess>,
    #[cfg(feature = "postgres-test")]
    completion_barrier: Arc<tokio::sync::Mutex<Option<ProposalCompletionBarrier>>>,
}

#[cfg(feature = "postgres-test")]
struct ProposalCompletionBarrier {
    reached: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

const MAX_RETENTION_BATCHES_PER_TICK: usize = 100;

#[derive(Clone, Copy)]
enum RetentionFailureReason {
    RegistryNotReady,
    LockTimeout,
    QueryCancelled,
    Database,
}

impl RetentionFailureReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::RegistryNotReady => "registry-not-ready",
            Self::LockTimeout => "lock-timeout",
            Self::QueryCancelled => "query-cancelled",
            Self::Database => "database",
        }
    }

    fn sqlstate(code: Option<&str>) -> Self {
        match code {
            Some("55P03") => Self::LockTimeout,
            Some("57014") => Self::QueryCancelled,
            _ => Self::Database,
        }
    }

    fn admission(error: crate::postgres::RegistryTransactionError) -> Self {
        use crate::postgres::{PostgresKernelError, RegistryLockFailure, RegistryTransactionError};
        match error {
            RegistryTransactionError::Kernel(PostgresKernelError::RegistryUnavailable) => {
                Self::RegistryNotReady
            }
            RegistryTransactionError::Lock(RegistryLockFailure::Timeout) => Self::LockTimeout,
            RegistryTransactionError::Lock(RegistryLockFailure::QueryCancelled) => {
                Self::QueryCancelled
            }
            _ => Self::Database,
        }
    }
}

impl BregDeliverySeams {
    async fn verify_delivery_transaction(
        &self,
        transaction: &Transaction<'_>,
        allow_superseded_package: bool,
    ) -> Result<(), DeliveryError> {
        if self.lock_timeout.is_zero() || self.lock_timeout > Duration::from_secs(30) {
            return Err(DeliveryError::Unavailable);
        }
        let timeout_millis =
            i32::try_from(self.lock_timeout.as_millis()).map_err(|_| DeliveryError::Unavailable)?;
        transaction
            .execute(
                "SELECT set_config('lock_timeout', $1::text, true)",
                &[&format!("{timeout_millis}ms")],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        let state = transaction
            .query_opt(
                "SELECT package_id, database_id, active_package_digest,
                        active_activation_id::text, schema_fingerprint, maintenance_status
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?
            .ok_or(DeliveryError::Unavailable)?;
        let ready = state.try_get::<_, String>(5).ok().as_deref() == Some("ready")
            && state.try_get::<_, String>(0).ok().as_deref()
                == Some(self.expected.package_id.as_str())
            && state.try_get::<_, String>(1).ok().as_deref()
                == Some(self.expected.database_id.as_str());
        let active_package_matches = state.try_get::<_, String>(2).ok().as_deref()
            == Some(self.expected.package_digest.as_str())
            && state.try_get::<_, String>(3).ok().as_deref()
                == Some(self.expected.activation_id.as_str())
            && state.try_get::<_, String>(4).ok().as_deref()
                == Some(self.expected.schema_fingerprint.as_str());
        if !ready || (!allow_superseded_package && !active_package_matches) {
            return Err(DeliveryError::Unavailable);
        }
        Ok(())
    }

    async fn run_retention(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                _ = async {
                    interval.tick().await;
                    let _ = self.prune_terminal(MAX_RETENTION_BATCHES_PER_TICK).await;
                } => {}
            }
        }
    }

    async fn prune_terminal(&self, max_batches: usize) -> Result<(u64, bool), DeliveryError> {
        let mut removed = 0;
        for _ in 0..max_batches {
            let batch = match self.prune_terminal_batch().await {
                Ok(batch) => batch,
                Err(reason) => {
                    tracing::error!(
                        removed,
                        reason = reason.as_str(),
                        "hook metadata retention failed"
                    );
                    return Err(DeliveryError::Unavailable);
                }
            };
            removed += batch;
            // Hooks returns deleted rows, without exposing its page bound.
            // An empty batch terminates without copying that private limit.
            if batch == 0 {
                if removed != 0 {
                    tracing::info!(removed, "hook metadata retention completed");
                }
                return Ok((removed, false));
            }
        }
        tracing::warn!(
            removed,
            "hook metadata retention reached its per-tick batch bound"
        );
        Ok((removed, true))
    }

    async fn prune_terminal_batch(&self) -> Result<u64, RetentionFailureReason> {
        // Keep metadata for at least the receipt horizon and the payload replay
        // window. The platform primitive also requires completed payload expiry
        // for dead letters and never removes active or uncertain delivery work.
        let horizon = Duration::from_secs(
            u64::from(self.idempotency.receipt_retention_days()) * 24 * 60 * 60,
        )
        .max(self.destinations.payload_retention());
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| RetentionFailureReason::Database)?;
        let mut guard =
            crate::postgres::cancellation::QueryCancellationGuard::new(self.pool.clone(), client);
        let transaction = crate::postgres::begin_registry_transaction_with_reason(
            guard.client(),
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(RetentionFailureReason::admission)?;
        transaction
            .set_statement_budget(Duration::from_secs(10))
            .await
            .map_err(|_| RetentionFailureReason::Database)?;
        let now: std::time::SystemTime = transaction
            .transaction()
            .query_one("SELECT transaction_timestamp()", &[])
            .await
            .map_err(|error| {
                RetentionFailureReason::sqlstate(error.code().map(|code| code.code()))
            })?
            .get(0);
        let before = now
            .checked_sub(horizon)
            .ok_or(RetentionFailureReason::Database)?;
        let removed = registry_platform_hooks::delivery::prune_terminal_deliveries(
            transaction.transaction(),
            DELIVERY_SCHEMA,
            before,
        )
        .await
        .map_err(|error| RetentionFailureReason::sqlstate(error.sqlstate()))?;
        transaction
            .commit()
            .await
            .map_err(|_| RetentionFailureReason::Database)?;
        guard.disarm();
        Ok(removed)
    }

    fn mutation_transaction(&self) -> MutationTransaction {
        let coordinator = MutationTransaction::new_with_event_destinations(
            self.lock_key,
            self.lock_timeout,
            self.expected.clone(),
            &self.instance_id,
            self.audit.clone(),
            Some(Arc::clone(&self.destinations)),
        )
        .with_idempotency_policy(self.idempotency.clone());
        match &self.field_encryption {
            Some(field_encryption) => {
                coordinator.with_field_encryption(Arc::clone(field_encryption))
            }
            None => coordinator,
        }
    }
}

#[async_trait::async_trait]
impl DeliverySeams for BregDeliverySeams {
    type Destination = SharedUrlDestination;
    type Handler = LocalHookHandler;

    fn proposal_replay_allowed(&self, code: Option<&str>) -> bool {
        code != Some("hook.proposal.package_unavailable")
    }

    async fn apply_proposal(
        &self,
        application: ProposalApplication<'_>,
    ) -> Result<ProposalOutcome, DeliveryError> {
        // A per-call coordinator over the seams' own identity, so the apply
        // runs in fresh transactions and its committed events enqueue their
        // own delivery rows through the same destinations.
        let coordinator = self.mutation_transaction();
        let mut application_lock = HookChangeLock::acquire(
            self.pool.clone(),
            &coordinator,
            application.event_id,
            application.compiled_delivery_id,
        )
        .await?;
        let outcome = coordinator
            .apply_hook_change(
                application_lock.client(),
                &self.registry,
                &HookChangeApplication {
                    event_id: application.event_id,
                    compiled_delivery_id: application.compiled_delivery_id,
                    generation: application.generation,
                    attempt: application.attempt,
                    lease_token: application.lease_token,
                    package_revision: application.package_revision,
                    envelope: application.envelope,
                    answer: application.answer,
                    answer_digest: application.answer_digest,
                },
            )
            .await;
        application_lock.release(&coordinator).await?;
        let outcome = outcome.map_err(|_| DeliveryError::Unavailable)?;
        #[cfg(feature = "postgres-test")]
        {
            let barrier = self.completion_barrier.lock().await.take();
            if let Some(barrier) = barrier {
                let _ = barrier.reached.send(());
                barrier
                    .release
                    .await
                    .map_err(|_| DeliveryError::Unavailable)?;
            }
        }
        Ok(match outcome {
            HookChangeOutcome::Applied(resulting_revision) => {
                ProposalOutcome::Applied { resulting_revision }
            }
            HookChangeOutcome::Refused { code, summary } => ProposalOutcome::Refused {
                code: proposal_code(code),
                summary: proposal_summary(summary),
            },
            HookChangeOutcome::DeadLettered { code, summary } => ProposalOutcome::DeadLettered {
                code: proposal_code(code),
                summary: proposal_summary(summary),
            },
        })
    }

    async fn recover_proposal_receipt(
        &self,
        recovery: ProposalReceiptRecovery<'_>,
    ) -> Result<Option<ProposalOutcome>, DeliveryError> {
        let coordinator = self.mutation_transaction();
        let mut application_lock = HookChangeLock::acquire(
            self.pool.clone(),
            &coordinator,
            recovery.event_id,
            recovery.compiled_delivery_id,
        )
        .await?;
        let outcome = coordinator
            .recover_hook_change_receipt(
                &***application_lock.client(),
                recovery.event_id,
                recovery.compiled_delivery_id,
            )
            .await;
        application_lock.release(&coordinator).await?;
        let outcome = outcome.map_err(|_| DeliveryError::Unavailable)?;
        Ok(outcome.map(|outcome| match outcome {
            HookChangeOutcome::Applied(resulting_revision) => {
                ProposalOutcome::Applied { resulting_revision }
            }
            HookChangeOutcome::Refused { code, summary } => ProposalOutcome::Refused {
                code: proposal_code(code),
                summary: proposal_summary(summary),
            },
            HookChangeOutcome::DeadLettered { code, summary } => ProposalOutcome::DeadLettered {
                code: proposal_code(code),
                summary: proposal_summary(summary),
            },
        }))
    }

    async fn recover_proposal_receipt_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        recovery: ProposalReceiptRecovery<'_>,
    ) -> Result<Option<ProposalOutcome>, DeliveryError> {
        let coordinator = self.mutation_transaction();
        let key_reference = coordinator
            .hook_change_key_reference(recovery.event_id, recovery.compiled_delivery_id)
            .map_err(|_| DeliveryError::Unavailable)?;
        coordinator
            .acquire_hook_change_transaction_lock(transaction, &key_reference)
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        let outcome = coordinator
            .recover_hook_change_receipt(
                transaction,
                recovery.event_id,
                recovery.compiled_delivery_id,
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        Ok(outcome.map(|outcome| match outcome {
            HookChangeOutcome::Applied(resulting_revision) => {
                ProposalOutcome::Applied { resulting_revision }
            }
            HookChangeOutcome::Refused { code, summary } => ProposalOutcome::Refused {
                code: proposal_code(code),
                summary: proposal_summary(summary),
            },
            HookChangeOutcome::DeadLettered { code, summary } => ProposalOutcome::DeadLettered {
                code: proposal_code(code),
                summary: proposal_summary(summary),
            },
        }))
    }

    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        Ok(PooledClient::boxed(client))
    }

    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError> {
        self.verify_delivery_transaction(transaction, false).await
    }

    async fn verify_proposal_completion(
        &self,
        transaction: &Transaction<'_>,
        outcome: &ProposalOutcome,
    ) -> Result<(), DeliveryError> {
        // Hooks admits only consistent terminal URL outcome pairs here.
        // Classification held the activation lock, or recovered an existing
        // receipt. Record that settled decision without granting new work
        // authority to this worker. A new outcome variant requires review.
        match outcome {
            ProposalOutcome::Applied { .. }
            | ProposalOutcome::Refused { .. }
            | ProposalOutcome::DeadLettered { .. } => {
                self.verify_delivery_transaction(transaction, true).await
            }
        }
    }

    fn destination(&self, logical_destination_id: &str) -> Option<Self::Destination> {
        self.destinations
            .lookup_shared(logical_destination_id)
            .map(SharedUrlDestination)
    }

    fn handler(&self, binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
        self.handlers.handler(binding)
    }

    /// The platform worker records an attempt's start before its lease
    /// commits, answering it with a worker interruption if that commit
    /// fails, and records a terminal disposition, an expiry, and a replay's
    /// outcome only after the transition commits, so an entry never stands
    /// for a transition that rolled back.
    async fn record_audit(&self, record: DeliveryAuditRecord<'_>) -> Result<(), DeliveryError> {
        let entry =
            hook_entry(self.audit.profile(), &record).map_err(|_| DeliveryError::Unavailable)?;
        self.audit
            .append(entry)
            .await
            .map_err(|_| DeliveryError::Unavailable)
    }

    fn operational_event(&self, event: DeliveryOperationalEvent) {
        match event {
            DeliveryOperationalEvent::IterationFailed => {
                OperationalEvent::HookWorkerIterationFailed.emit();
            }
            DeliveryOperationalEvent::TransitionFailed(code) => {
                OperationalEvent::HookStateTransitionFailed(transition_code(code)).emit();
            }
        }
    }

    fn iteration_succeeded(&self) {
        self.last_success.record();
    }
}

/// A cancellation-safe session lock over one hook proposal application.
///
/// Normal completion explicitly unlocks and returns the connection to the
/// pool. Cancellation or any early return discards it instead, which closes
/// the PostgreSQL session and cannot leak an advisory lock into later work.
struct HookChangeLock {
    pool: RuntimePool,
    client: Option<deadpool_postgres::Client>,
    key_reference: String,
}

impl HookChangeLock {
    async fn acquire(
        pool: RuntimePool,
        coordinator: &MutationTransaction,
        event_id: Uuid,
        compiled_delivery_id: &str,
    ) -> Result<Self, DeliveryError> {
        let client = pool.get().await.map_err(|_| DeliveryError::Unavailable)?;
        let key_reference = coordinator
            .hook_change_key_reference(event_id, compiled_delivery_id)
            .map_err(|_| DeliveryError::Unavailable)?;
        let lock = Self {
            pool,
            client: Some(client),
            key_reference,
        };
        coordinator
            .acquire_hook_change_lock(
                lock.client
                    .as_ref()
                    .expect("hook proposal lock owns its client while acquiring"),
                &lock.key_reference,
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        Ok(lock)
    }

    fn client(&mut self) -> &mut deadpool_postgres::Client {
        self.client
            .as_mut()
            .expect("hook proposal lock owns its client until release")
    }

    async fn release(mut self, coordinator: &MutationTransaction) -> Result<(), DeliveryError> {
        let client = self
            .client
            .as_ref()
            .expect("hook proposal lock owns its client until release");
        if coordinator
            .release_hook_change_lock(client, &self.key_reference)
            .await
            .is_err()
        {
            return Err(DeliveryError::Unavailable);
        }
        let client = self
            .client
            .take()
            .expect("hook proposal lock owns its client after release");
        drop(client);
        Ok(())
    }
}

impl Drop for HookChangeLock {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            self.pool.discard(client);
        }
    }
}

/// A product-authored refusal code, static and well inside the code bound.
fn proposal_code(code: &'static str) -> registry_platform_hooks::delivery::ProposalCode {
    BoundedText::new(code.to_owned()).expect("a static proposal code fits the code bound")
}

/// A product-authored refusal summary under the summary bound. Summaries are
/// short by construction; trimming keeps the bound the contract even if one
/// grows past it, because the disposition must stay readable either way.
fn proposal_summary(summary: String) -> registry_platform_hooks::delivery::ProposalSummary {
    let mut summary = summary;
    if summary.len() > MAX_REFUSAL_SUMMARY_BYTES {
        let mut end = MAX_REFUSAL_SUMMARY_BYTES;
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
    }
    BoundedText::new(summary).expect("a non-empty trimmed summary fits the summary bound")
}

fn transition_code(code: DeliveryTransitionCode) -> HookStateTransitionCode {
    match code {
        DeliveryTransitionCode::ClaimIdentityRefused => {
            HookStateTransitionCode::ClaimIdentityRefused
        }
        DeliveryTransitionCode::ClaimRecoveryFailed => HookStateTransitionCode::ClaimRecoveryFailed,
        DeliveryTransitionCode::ClaimSelectFailed => HookStateTransitionCode::ClaimSelectFailed,
        DeliveryTransitionCode::ClaimPolicyRefused => HookStateTransitionCode::ClaimPolicyRefused,
        DeliveryTransitionCode::ClaimUpdateFailed => HookStateTransitionCode::ClaimUpdateFailed,
        DeliveryTransitionCode::ClaimAuditFailed => HookStateTransitionCode::ClaimAuditFailed,
        DeliveryTransitionCode::ClaimCommitFailed => HookStateTransitionCode::ClaimCommitFailed,
    }
}

/// Why a bounded local drain stopped starting attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookDrainStopReason {
    Idle,
    AttemptBudget,
    TimeBudget,
}

/// Value-free result of a bounded attempt to settle local hooks.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookDrainReport {
    pub activation_id: String,
    pub completed_attempts: u16,
    pub delivered: u16,
    pub retry_scheduled: u16,
    pub dead_lettered: u16,
    pub stop_reason: HookDrainStopReason,
    pub remaining: crate::postgres::RetainedLocalHookDeliveries,
}

fn validate_drain_budget(max_attempts: u16, timeout: Duration) -> Result<(), HookDeliveryError> {
    if !(1..=1000).contains(&max_attempts)
        || !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&timeout)
    {
        return Err(HookDeliveryError::Unavailable);
    }
    Ok(())
}

/// Base Registry Engine's delivery service: the platform delivery worker
/// bound to Base Registry Engine's seams and constants.
#[derive(Clone)]
pub struct HookDeliveryService {
    delivery: DeliveryService<BregDeliverySeams>,
    seams: BregDeliverySeams,
    last_success: Arc<crate::metrics::LastSuccess>,
}

impl HookDeliveryService {
    /// Pause after proposal classification releases its locks, before the
    /// shared dispatcher starts finalization. Only the test build has this seam.
    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn pause_proposal_completion_for_test(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (reached, observed) = tokio::sync::oneshot::channel();
        let (release, resumed) = tokio::sync::oneshot::channel();
        *self.seams.completion_barrier.lock().await = Some(ProposalCompletionBarrier {
            reached,
            release: resumed,
        });
        (observed, release)
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn prune_terminal_for_test(
        &self,
        max_batches: usize,
    ) -> Result<(u64, bool), DeliveryError> {
        self.seams.prune_terminal(max_batches).await
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: RuntimePool,
        destinations: Arc<ActivatedEventDestinationRegistry>,
        handlers: Arc<LocalHookHandlers>,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        instance_id: &str,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
    ) -> Self {
        Self::new_with_field_encryption(
            pool,
            destinations,
            handlers,
            registry,
            expected,
            instance_id,
            lock_key,
            lock_timeout,
            audit,
            None,
        )
    }

    /// Bind the delivery worker to the same optional field-encryption key
    /// state used by request-path mutations.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_field_encryption(
        pool: RuntimePool,
        destinations: Arc<ActivatedEventDestinationRegistry>,
        handlers: Arc<LocalHookHandlers>,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        instance_id: &str,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
        field_encryption: Option<Arc<FieldEncryptionService>>,
    ) -> Self {
        Self::new_with_runtime_bindings(
            pool,
            destinations,
            handlers,
            registry,
            expected,
            instance_id,
            lock_key,
            lock_timeout,
            audit,
            field_encryption,
            IdempotencyPolicy::default(),
        )
    }

    /// Bind the delivery worker to the same optional field-encryption key
    /// state and the same idempotency policy used by request-path mutations,
    /// so a hook proposal receipt is held for the configured horizon.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_runtime_bindings(
        pool: RuntimePool,
        destinations: Arc<ActivatedEventDestinationRegistry>,
        handlers: Arc<LocalHookHandlers>,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        instance_id: &str,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
        field_encryption: Option<Arc<FieldEncryptionService>>,
        idempotency: IdempotencyPolicy,
    ) -> Self {
        let config = DeliveryConfig {
            schema: DELIVERY_SCHEMA.to_owned(),
            idempotency_domain: IDEMPOTENCY_DOMAIN.to_vec(),
            delivery_source: delivery_source(&expected.package_id, instance_id),
        };
        let last_success = Arc::<crate::metrics::LastSuccess>::default();
        let seams = BregDeliverySeams {
            pool,
            destinations,
            handlers,
            registry,
            expected,
            instance_id: instance_id.to_owned(),
            lock_key,
            lock_timeout,
            audit,
            field_encryption,
            idempotency,
            last_success: Arc::clone(&last_success),
            #[cfg(feature = "postgres-test")]
            completion_barrier: Arc::default(),
        };
        Self {
            delivery: DeliveryService::new(seams.clone(), config),
            seams,
            last_success,
        }
    }

    /// The handle the delivery worker notes each iteration without failure
    /// on.
    #[must_use]
    pub fn last_success(&self) -> Arc<crate::metrics::LastSuccess> {
        Arc::clone(&self.last_success)
    }

    /// Claim, audit, send, and finalize at most one due delivery.
    ///
    /// The pre-egress audit and lease commit before request rendering or
    /// destination policy execution. Delivery is therefore explicitly
    /// at-least-once when a process stops after network I/O and before CAS
    /// finalization.
    pub async fn deliver_once(&self) -> Result<HookWorkOutcome, HookDeliveryError> {
        self.delivery.deliver_once().await
    }

    /// Attempt due local work under this active package, without replaying
    /// dead letters, sending URL work, or borrowing a successor's authority.
    /// A deadline may leave a lease unfinished for ordinary expiry recovery.
    pub async fn drain_local(
        &self,
        max_attempts: u16,
        timeout: Duration,
    ) -> Result<HookDrainReport, HookDeliveryError> {
        validate_drain_budget(max_attempts, timeout)?;
        let deadline = tokio::time::Instant::now() + timeout;
        let local = self
            .delivery
            .local_only_for_package(&self.seams.expected.activation_id, deadline)?;
        let mut report = HookDrainReport {
            activation_id: self.seams.expected.activation_id.clone(),
            completed_attempts: 0,
            delivered: 0,
            retry_scheduled: 0,
            dead_lettered: 0,
            stop_reason: HookDrainStopReason::AttemptBudget,
            remaining: crate::postgres::RetainedLocalHookDeliveries::default(),
        };
        for _ in 0..max_attempts {
            let outcome = match tokio::time::timeout_at(deadline, local.deliver_once()).await {
                Ok(result) => result?,
                Err(_) => {
                    report.stop_reason = HookDrainStopReason::TimeBudget;
                    break;
                }
            };
            match outcome {
                HookWorkOutcome::Idle => {
                    report.stop_reason = HookDrainStopReason::Idle;
                    break;
                }
                HookWorkOutcome::Delivered => report.delivered += 1,
                HookWorkOutcome::RetryScheduled => report.retry_scheduled += 1,
                HookWorkOutcome::DeadLettered => report.dead_lettered += 1,
            }
            report.completed_attempts += 1;
        }
        let mut client = self
            .seams
            .pool
            .get()
            .await
            .map_err(|_| HookDeliveryError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| HookDeliveryError::Unavailable)?;
        self.seams.verify_transaction(&transaction).await?;
        report.remaining = crate::postgres::retained_local_hook_deliveries(&*transaction)
            .await
            .map_err(|_| HookDeliveryError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| HookDeliveryError::Unavailable)?;
        Ok(report)
    }

    /// Refuse startup or operator use if retained work cannot use its exact
    /// captured destination under the active deployment bindings.
    pub async fn verify_retained_bindings(&self) -> Result<(), HookRetainedBindingError> {
        self.delivery.verify_retained_bindings().await
    }

    /// Return bounded, value-free pending and terminal operator metadata.
    pub async fn list(&self, limit: u16) -> Result<Vec<HookDeliveryStatus>, HookDeliveryError> {
        self.delivery.list(limit).await
    }

    /// Reset one terminal delivery for an explicitly permitted operator replay
    /// and return the committed replacement generation.
    ///
    /// Every absent, stale, forbidden, or nonterminal target returns the same
    /// value-free refusal.
    pub async fn replay(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, HookDeliveryError> {
        self.delivery
            .replay(event_id, compiled_delivery_id, expected_generation)
            .await
    }

    /// Irreversibly discard retained delivery work under an optimistic
    /// generation guard, without delivering it under a replacement binding.
    pub async fn discard(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, HookDeliveryError> {
        self.delivery
            .discard(event_id, compiled_delivery_id, expected_generation)
            .await
    }
}

#[derive(Clone)]
pub struct HookWorker {
    kind: HookWorkerKind,
}

impl HookWorker {
    #[must_use]
    pub fn new(service: HookDeliveryService) -> Self {
        Self {
            kind: HookWorkerKind::Delivery(Box::new(service)),
        }
    }

    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        #[cfg(not(feature = "postgres-test"))]
        let HookWorkerKind::Delivery(service) = self.kind;
        #[cfg(feature = "postgres-test")]
        let service = match self.kind {
            HookWorkerKind::Delivery(service) => service,
            HookWorkerKind::LifecycleProbe(probe) => {
                probe.run(shutdown).await;
                return;
            }
        };
        // Both loops observe shutdown, but the delivery loop must finish its
        // in-flight attempt during the server's existing grace period.
        tokio::join!(
            DeliveryWorker::new(service.delivery).run(shutdown.clone()),
            service.seams.run_retention(shutdown),
        );
    }
}

#[derive(Clone)]
enum HookWorkerKind {
    Delivery(Box<HookDeliveryService>),
    #[cfg(feature = "postgres-test")]
    LifecycleProbe(HookWorkerLifecycleProbe),
}

/// Test-only observation point for proving startup task ownership.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
#[derive(Clone)]
pub struct HookWorkerLifecycleProbe {
    state: Arc<HookWorkerLifecycleState>,
    mode: HookWorkerLifecycleMode,
}

/// How the probe ends: on the shutdown signal, never, or on its own before
/// shutdown is requested.
#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy)]
enum HookWorkerLifecycleMode {
    UntilShutdown,
    Hang,
    Panic,
    Return,
}

#[cfg(feature = "postgres-test")]
struct HookWorkerLifecycleState {
    started: AtomicBool,
    running: AtomicBool,
    stopped: AtomicBool,
}

#[cfg(feature = "postgres-test")]
impl HookWorkerLifecycleProbe {
    #[must_use]
    pub fn new(hang: bool) -> Self {
        Self::with_mode(if hang {
            HookWorkerLifecycleMode::Hang
        } else {
            HookWorkerLifecycleMode::UntilShutdown
        })
    }

    /// A probe that panics as soon as it starts.
    #[must_use]
    pub fn panicking() -> Self {
        Self::with_mode(HookWorkerLifecycleMode::Panic)
    }

    /// A probe that returns as soon as it starts, without a shutdown signal.
    #[must_use]
    pub fn returning() -> Self {
        Self::with_mode(HookWorkerLifecycleMode::Return)
    }

    fn with_mode(mode: HookWorkerLifecycleMode) -> Self {
        Self {
            state: Arc::new(HookWorkerLifecycleState {
                started: AtomicBool::new(false),
                running: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
            }),
            mode,
        }
    }

    #[must_use]
    pub fn worker(&self) -> HookWorker {
        HookWorker {
            kind: HookWorkerKind::LifecycleProbe(self.clone()),
        }
    }

    #[must_use]
    pub fn started(&self) -> bool {
        self.state.started.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn running(&self) -> bool {
        self.state.running.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn stopped(&self) -> bool {
        self.state.stopped.load(Ordering::SeqCst)
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) {
        self.state.started.store(true, Ordering::SeqCst);
        self.state.running.store(true, Ordering::SeqCst);
        let _guard = HookWorkerLifecycleGuard(Arc::clone(&self.state));
        match self.mode {
            HookWorkerLifecycleMode::UntilShutdown => {}
            HookWorkerLifecycleMode::Hang => std::future::pending::<()>().await,
            HookWorkerLifecycleMode::Panic => panic!("hook worker lifecycle probe panicked"),
            HookWorkerLifecycleMode::Return => return,
        }
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(feature = "postgres-test")]
struct HookWorkerLifecycleGuard(Arc<HookWorkerLifecycleState>);

#[cfg(feature = "postgres-test")]
impl Drop for HookWorkerLifecycleGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::SeqCst);
        self.0.stopped.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[path = "tests/hooks_tests.rs"]
mod hooks_tests;
