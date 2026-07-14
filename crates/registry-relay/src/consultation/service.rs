// SPDX-License-Identifier: Apache-2.0
//! Concrete consultation service for the maintained product journeys.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use datafusion::execution::context::SessionContext;
use registry_platform_audit::{
    AuditChainHasher, DurableAuditOperationId, DurableAuditPhase, DurableAuditSink,
    DurableAuditStreamKind, DurableAuditWrite, DurableAuditWriteError, DurableAuditWriteOutcome,
};
use registry_platform_httputil::destination::json::MAX_CLOSED_JSON_STRING_BYTES;
use serde_json::json;
use thiserror::Error;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;
use ulid::Ulid;

use crate::api::consultation::ParsedConsultationEnvelope;
use crate::auth::AuthenticationResult;
use crate::config::{
    AuthMode as ConfigAuthMode, Config, ConsultationConfig, FieldType,
    VerifiedConsultationArtifactClosure,
};
use crate::ingest::declared_schema::DeclaredSchema;
use crate::ingest::IngestRegistry;
#[cfg(all(target_os = "linux", not(test)))]
use crate::rhai_worker::WorkerProcess;
use crate::source_backend::{PublishedSnapshotRegistry, SnapshotMaterializationCoordinator};
use crate::source_plan::{
    initialize_rhai_worker_capabilities, validate_source_credential_catalog,
    CompiledBasicSourceCredentialProvider, CompiledConsultationRegistry,
    CompiledOAuthSourceCredentialProvider, CompiledResponseSchema, CompiledScalarShape,
    CompiledSourcePlan, CompiledStaticBearerSourceCredentialProvider,
    InitializedConsentVerifierRegistry, SourcePlanKind,
};
use crate::state_plane::{
    BatchChildReplayContext, BatchChildReplayReservation, ConsultationCompletionOutcome,
    ConsultationPermitSet, ConsultationStatePlaneReadiness, ConsultationStatePlaneRuntime,
    EffectiveQuotaLimits, PublicQuotaLimits, QuotaKey, QuotaReservation,
};

use super::audit::{prepare_atomic_consultation_attempt, FinalizedConcreteConsultation};
use super::commitments::{
    authorize_consultation_attempt, build_pseudonym_inputs, CanonicalConsultationInputs,
    ConsultationCommitmentError, VerifiedConsentAuthority,
};
use super::executor::ConcreteExecutorKind;
use super::policy::evaluate_compiled_policy;
use super::pseudonym::AuditPseudonymMaterialProvider;
use super::response::PublishableConsultationResponse;
use super::{
    AuthenticatedConsultationWorkload, ClientClaimSelector, ConfiguredAudience,
    ConfiguredClientBinding, ConfiguredIssuer, ConfiguredOidcWorkloadProof, ConfiguredPrincipalId,
    ConsultationId, ConsultationKey, ConsultationWorkloadBinding, ConsultationWorkloadRole,
    ExpectedClientValue, PreAuthorizationConsultationCore, ProfileId, ResolvedConsultationProfile,
};

const MAX_PROTECTED_CONTRACT_JSON_BYTES: usize = MAX_CLOSED_JSON_STRING_BYTES as usize;
const MAX_PROTECTED_PROFILE_METADATA_BYTES: usize = 256 * 1_024;
const DENIAL_DECISION_SCHEMA: &str = "registry.relay.consultation.denial-decision.v1";
const UNMATCHED_CONSULTATION_ROUTE: &str = "/v1/consultations/{unmatched}";

/// Closed public route identity for a rejected consultation request. Raw path
/// segments can never enter the durable denial payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsultationDenialRoute {
    Profile,
    Execute,
    Unmatched,
}

impl ConsultationDenialRoute {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Profile => crate::api::consultation::PROFILE_ROUTE,
            Self::Execute => crate::api::consultation::EXECUTE_ROUTE,
            Self::Unmatched => UNMATCHED_CONSULTATION_ROUTE,
        }
    }
}

/// Coarse, closed denial classes. Request values and dependency diagnostics
/// cannot be projected into this taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsultationDenialReason {
    InvalidCredentials,
    InvalidRequest,
    Denied,
    NotFound,
    RateLimited,
    Capacity,
    Conflict,
}

impl ConsultationDenialReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::InvalidRequest => "invalid_request",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::Capacity => "capacity",
            Self::Conflict => "batch_child_conflict",
        }
    }

    pub(crate) const fn accepts_status(self, status: u16) -> bool {
        match self {
            Self::InvalidCredentials => status == 401,
            Self::Denied => status == 403,
            Self::NotFound => status == 404,
            Self::RateLimited => status == 429,
            Self::Capacity => status == 503,
            Self::Conflict => status == 409,
            Self::InvalidRequest => {
                (status >= 400 && status <= 499)
                    && status != 401
                    && status != 403
                    && status != 404
                    && status != 429
            }
        }
    }
}

/// Value-free startup failure for the closed consultation runtime.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ConsultationServiceActivationError {
    #[error("consultation service configuration is unavailable")]
    MissingConfiguration,
    #[error("consultation service workload binding is invalid")]
    InvalidWorkloadBinding,
    #[error("consultation service registry activation failed")]
    RegistryActivation,
    #[error("consultation service plan is unsupported")]
    UnsupportedPlan,
    #[error("consultation service quota limits are invalid")]
    InvalidQuotaLimits,
    #[error("consultation service protected metadata is invalid")]
    InvalidMetadata,
    #[error("consultation service source credentials are unavailable")]
    SourceCredentials,
    #[error("consultation service pseudonym material is unavailable")]
    PseudonymMaterial,
    #[error("consultation service state plane is unavailable")]
    StatePlane,
}

/// Conjunctive readiness for consultation admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultationServiceReadiness {
    Ready,
    Unavailable,
}

/// Value-free one-shot shutdown failure.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ConsultationServiceShutdownError {
    #[error("consultation service shutdown already started")]
    AlreadyStarted,
    #[error("consultation service state-plane shutdown failed")]
    StatePlane,
}

/// Bounded public Retry-After instruction. Diagnostics deliberately redact the
/// value even though the API may publish it as a response header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsultationRetryAfter(u8);

impl ConsultationRetryAfter {
    fn from_duration(duration: Duration) -> Option<Self> {
        let milliseconds = duration.as_millis();
        let seconds = milliseconds.checked_add(999)?.checked_div(1_000)?;
        u8::try_from(seconds)
            .ok()
            .filter(|seconds| (1..=60).contains(seconds))
            .map(Self)
    }

    pub(crate) const fn seconds(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for ConsultationRetryAfter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsultationRetryAfter(<bounded>)")
    }
}

/// Closed request failure taxonomy. No variant retains an input, identity,
/// source diagnostic, or dependency error.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConsultationServiceError {
    #[error("consultation credentials are invalid")]
    InvalidCredentials,
    #[error("consultation request is denied")]
    Denied,
    #[error("consultation profile was not found")]
    ProfileNotFound,
    #[error("consultation request is invalid")]
    InvalidRequest,
    #[error("consultation batch child conflicts with durable state")]
    Conflict,
    #[error("consultation quota is exhausted")]
    RateLimited(ConsultationRetryAfter),
    #[error("consultation service is unavailable")]
    Unavailable,
}

/// Private zero-sized proof attached only after the tracked execution task has
/// durably persisted its public denial decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsultationDenialRecorded {
    _private: (),
}

impl ConsultationDenialRecorded {
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Closed execution failure carrying optional proof that the tracked task
/// already owns the dedicated denial record. It retains no request values.
pub(crate) struct ConsultationExecutionError {
    error: ConsultationServiceError,
    denial_recorded: Option<ConsultationDenialRecorded>,
}

impl ConsultationExecutionError {
    fn unaudited(error: ConsultationServiceError) -> Self {
        Self {
            error,
            denial_recorded: None,
        }
    }

    fn denial_recorded(error: ConsultationServiceError) -> Self {
        Self {
            error,
            denial_recorded: Some(ConsultationDenialRecorded { _private: () }),
        }
    }

    pub(crate) const fn into_parts(
        self,
    ) -> (ConsultationServiceError, Option<ConsultationDenialRecorded>) {
        (self.error, self.denial_recorded)
    }
}

/// Opaque result of fixed-identity authentication and profile resolution.
/// It is move-only and cannot be constructed by the HTTP layer.
pub(crate) struct ResolvedConsultationContext {
    key: ConsultationKey,
    resolved_profile: ResolvedConsultationProfile,
    workload: AuthenticatedConsultationWorkload,
    metadata: Arc<[u8]>,
}

impl ResolvedConsultationContext {
    pub(crate) const fn resolved_profile(&self) -> &ResolvedConsultationProfile {
        &self.resolved_profile
    }

    pub(crate) const fn authorized_workload(&self) -> &AuthenticatedConsultationWorkload {
        &self.workload
    }

    pub(crate) fn metadata_bytes(&self) -> &[u8] {
        &self.metadata
    }
}

struct ActivatedQuotaLimits {
    public: PublicQuotaLimits,
    effective: EffectiveQuotaLimits,
}

impl ActivatedQuotaLimits {
    fn effective(&self) -> EffectiveQuotaLimits {
        let _ = self.public;
        self.effective
    }
}

struct ActivatedProfile {
    workload_binding: ConsultationWorkloadBinding,
    quota_limits: ActivatedQuotaLimits,
    semaphore: Arc<Semaphore>,
    rhai_worker_semaphore: Option<Arc<Semaphore>>,
    metadata: Arc<[u8]>,
    executor: ConcreteExecutorKind,
    dispatch_budget: crate::state_plane::DispatchPermitBudget,
}

struct CompiledServiceActivation {
    registry: CompiledConsultationRegistry,
    fixed_workload_identity: ConfiguredOidcWorkloadProof,
    profiles: BTreeMap<ConsultationKey, ActivatedProfile>,
    basic_credentials: Option<CompiledBasicSourceCredentialProvider>,
    static_bearer_credentials: Option<CompiledStaticBearerSourceCredentialProvider>,
    oauth_credentials: Option<CompiledOAuthSourceCredentialProvider>,
    pseudonym_materials: Option<AuditPseudonymMaterialProvider>,
    snapshots: Arc<PublishedSnapshotRegistry>,
}

/// Restart-only concrete consultation service.
pub struct ConsultationService {
    registry: CompiledConsultationRegistry,
    fixed_workload_identity: ConfiguredOidcWorkloadProof,
    profiles: BTreeMap<ConsultationKey, ActivatedProfile>,
    basic_credentials: CompiledBasicSourceCredentialProvider,
    static_bearer_credentials: CompiledStaticBearerSourceCredentialProvider,
    oauth_credentials: CompiledOAuthSourceCredentialProvider,
    pseudonym_materials: AuditPseudonymMaterialProvider,
    snapshots: Arc<PublishedSnapshotRegistry>,
    datafusion: Arc<SessionContext>,
    materializations: Arc<SnapshotMaterializationCoordinator>,
    state_plane: Arc<ConsultationStatePlaneRuntime>,
    admission_open: AtomicBool,
    audit_healthy: AtomicBool,
    accepted_tasks: Mutex<Option<JoinSet<()>>>,
}

impl ConsultationService {
    /// Compile the complete hash-pinned artifact closure without connecting to
    /// the state plane or any governed source. Used by offline diagnostics.
    pub fn validate_configuration(
        config: &Config,
        artifacts: VerifiedConsultationArtifactClosure,
    ) -> Result<(), ConsultationServiceActivationError> {
        compile_service_activation(config, artifacts, false).map(drop)
    }

    /// Compile every process-local capability, then connect the concrete state
    /// plane last so failed static activation never acquires serving authority.
    pub async fn activate(
        config: &Config,
        artifacts: VerifiedConsultationArtifactClosure,
        chain_hasher: AuditChainHasher,
        datafusion: Arc<SessionContext>,
    ) -> Result<Arc<Self>, ConsultationServiceActivationError> {
        let compiled = compile_service_activation(config, artifacts, true)?;
        let basic_credentials = compiled
            .basic_credentials
            .ok_or(ConsultationServiceActivationError::SourceCredentials)?;
        let static_bearer_credentials = compiled
            .static_bearer_credentials
            .ok_or(ConsultationServiceActivationError::SourceCredentials)?;
        let oauth_credentials = compiled
            .oauth_credentials
            .ok_or(ConsultationServiceActivationError::SourceCredentials)?;
        let consultation = config
            .consultation
            .as_ref()
            .ok_or(ConsultationServiceActivationError::MissingConfiguration)?;
        let state_plane = Arc::new(
            ConsultationStatePlaneRuntime::connect(&consultation.state_plane, chain_hasher)
                .await
                .map_err(|error| {
                    // The state-plane error taxonomy is deliberately
                    // value-free. Preserve its actionable class for operators
                    // while the public activation error stays coarse.
                    tracing::error!(
                        code = "consultation.state_plane_activation_failed",
                        reason = %error,
                        "consultation state-plane activation failed"
                    );
                    ConsultationServiceActivationError::StatePlane
                })?,
        );
        let current_authority = match state_plane
            .pseudonym_keyring()
            .current_write_authority()
            .await
        {
            Ok(authority) => authority,
            Err(error) => {
                tracing::error!(
                    code = "consultation.pseudonym_authority_activation_failed",
                    reason = %error,
                    "consultation pseudonym write authority is unavailable at activation"
                );
                let _ = state_plane.shutdown().await;
                return Err(ConsultationServiceActivationError::StatePlane);
            }
        };
        let pseudonym_materials = compiled
            .pseudonym_materials
            .ok_or(ConsultationServiceActivationError::PseudonymMaterial)?;
        if pseudonym_materials.bind_write(current_authority).is_err() {
            let _ = state_plane.shutdown().await;
            return Err(ConsultationServiceActivationError::PseudonymMaterial);
        }
        let materializations = SnapshotMaterializationCoordinator::compile(
            &compiled.registry,
            Arc::clone(&compiled.snapshots),
            Arc::clone(&state_plane),
        )
        .map_err(|_| ConsultationServiceActivationError::UnsupportedPlan)?;
        Ok(Arc::new(Self {
            registry: compiled.registry,
            fixed_workload_identity: compiled.fixed_workload_identity,
            profiles: compiled.profiles,
            basic_credentials,
            static_bearer_credentials,
            oauth_credentials,
            pseudonym_materials,
            snapshots: compiled.snapshots,
            datafusion,
            materializations,
            state_plane,
            admission_open: AtomicBool::new(true),
            audit_healthy: AtomicBool::new(true),
            accepted_tasks: Mutex::new(Some(JoinSet::new())),
        }))
    }

    pub fn bind_ingest_registry(
        &self,
        ingest: &IngestRegistry,
    ) -> Result<(), ConsultationServiceActivationError> {
        ingest
            .bind_snapshot_materialization(Arc::clone(&self.materializations))
            .map_err(|_| ConsultationServiceActivationError::UnsupportedPlan)
    }

    pub async fn readiness(&self) -> ConsultationServiceReadiness {
        if !self.admission_open.load(Ordering::Acquire)
            || !self.audit_healthy.load(Ordering::Acquire)
        {
            return ConsultationServiceReadiness::Unavailable;
        }
        let ready = matches!(
            self.state_plane.readiness().await,
            ConsultationStatePlaneReadiness::Ready
        );
        if !ready {
            return ConsultationServiceReadiness::Unavailable;
        }
        let material_ready = match self
            .state_plane
            .pseudonym_keyring()
            .current_write_authority()
            .await
        {
            Ok(authority) => self.pseudonym_materials.bind_write(authority).is_ok(),
            Err(_) => false,
        };
        if !material_ready
            || !self.admission_open.load(Ordering::Acquire)
            || !self.audit_healthy.load(Ordering::Acquire)
        {
            return ConsultationServiceReadiness::Unavailable;
        }
        ConsultationServiceReadiness::Ready
    }

    /// Prove the fixed authorized workload identity before consulting the profile map, then
    /// apply the selected profile's exact scope and workload binding.
    pub(crate) fn resolve(
        &self,
        authentication: &AuthenticationResult,
        profile_id: &ProfileId,
    ) -> Result<ResolvedConsultationContext, ConsultationServiceError> {
        if !self.admission_open.load(Ordering::Acquire)
            || !self.audit_healthy.load(Ordering::Acquire)
        {
            return Err(ConsultationServiceError::Unavailable);
        }
        self.fixed_workload_identity
            .precheck_authentication(authentication)
            .map_err(|_| ConsultationServiceError::InvalidCredentials)?;
        let (key, activated) = self
            .profiles
            .iter()
            .find(|(key, _)| key.id() == profile_id)
            .ok_or(ConsultationServiceError::ProfileNotFound)?;
        let workload = AuthenticatedConsultationWorkload::try_bind(
            authentication,
            &activated.workload_binding,
        )
        .map_err(|_| ConsultationServiceError::Denied)?;
        let (resolved_profile, plan) = self
            .registry
            .resolve_for_authenticated_workload(key, &workload)
            .ok_or(ConsultationServiceError::Unavailable)?;
        if !self.snapshots.is_ready(plan) {
            return Err(ConsultationServiceError::Unavailable);
        }
        Ok(ResolvedConsultationContext {
            key: key.clone(),
            resolved_profile,
            workload,
            metadata: Arc::clone(&activated.metadata),
        })
    }

    /// Submit one accepted execution to the tracked task set before awaiting
    /// its result. Dropping or timing out the handler cannot cancel durable
    /// completion after this method has submitted the task.
    pub(crate) async fn execute(
        self: &Arc<Self>,
        context: ResolvedConsultationContext,
        envelope: ParsedConsultationEnvelope,
    ) -> Result<Vec<u8>, ConsultationExecutionError> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut tasks = self
                .accepted_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !self.admission_open.load(Ordering::Acquire) {
                return Err(ConsultationExecutionError::unaudited(
                    ConsultationServiceError::Unavailable,
                ));
            }
            let Some(tasks) = tasks.as_mut() else {
                return Err(ConsultationExecutionError::unaudited(
                    ConsultationServiceError::Unavailable,
                ));
            };
            while tasks.try_join_next().is_some() {}
            let service = Arc::clone(self);
            tasks.spawn(async move {
                let result = service.execute_accepted(context, envelope).await;
                let result = service.close_tracked_execute_result(result).await;
                let _ = sender.send(result);
            });
        }
        receiver.await.unwrap_or_else(|_| {
            Err(ConsultationExecutionError::unaudited(
                ConsultationServiceError::Unavailable,
            ))
        })
    }

    async fn close_tracked_execute_result(
        &self,
        result: Result<Vec<u8>, ConsultationServiceError>,
    ) -> Result<Vec<u8>, ConsultationExecutionError> {
        let Err(error) = result else {
            return result.map_err(ConsultationExecutionError::unaudited);
        };
        let Some((public_status, reason)) = tracked_execute_denial(error) else {
            return Err(ConsultationExecutionError::unaudited(error));
        };
        match self
            .record_denial_inner(ConsultationDenialRoute::Execute, public_status, reason)
            .await
        {
            Ok(()) => Err(ConsultationExecutionError::denial_recorded(error)),
            Err(_) => Err(ConsultationExecutionError::unaudited(
                ConsultationServiceError::Unavailable,
            )),
        }
    }

    async fn execute_accepted(
        &self,
        context: ResolvedConsultationContext,
        envelope: ParsedConsultationEnvelope,
    ) -> Result<Vec<u8>, ConsultationServiceError> {
        if !self.audit_healthy.load(Ordering::Acquire) {
            return Err(ConsultationServiceError::Unavailable);
        }
        let ResolvedConsultationContext {
            key,
            resolved_profile,
            workload,
            metadata: _,
        } = context;
        let plan = self
            .registry
            .get_for_authenticated_workload(&key, &workload)
            .ok_or(ConsultationServiceError::Unavailable)?;
        let activated = self
            .profiles
            .get(&key)
            .ok_or(ConsultationServiceError::Unavailable)?;
        let (purpose, input, notary_evaluation_id, batch_child_identity) = envelope.into_parts();
        if !plan
            .runtime_profile()
            .purposes()
            .any(|known| known == purpose.as_str())
        {
            return Err(ConsultationServiceError::Denied);
        }
        let core = PreAuthorizationConsultationCore::from_resolved_plan(
            resolved_profile,
            plan,
            purpose,
            input,
        )
        .map_err(|_| ConsultationServiceError::Unavailable)?;
        let canonical = CanonicalConsultationInputs::try_from_resolved_core(plan, core)
            .map_err(map_request_commitment_error)?;
        let batch_binding = batch_child_identity
            .as_ref()
            .map(|child| canonical.batch_child_replay_binding(child, &workload))
            .transpose()
            .map_err(map_request_commitment_error)?;
        let consultation_id = ConsultationId::generate();
        let batch_context = if let Some(binding) = batch_binding {
            match self
                .state_plane
                .audit()
                .reserve_batch_child_replay(binding, consultation_id)
                .await
                .map_err(|_| ConsultationServiceError::Unavailable)?
            {
                BatchChildReplayReservation::Reserved(context) => Some(context),
                BatchChildReplayReservation::Replay(replay) => {
                    let (original_consultation_id, persisted) = replay.into_parts();
                    return PublishableConsultationResponse::replay_http_body(
                        persisted,
                        &original_consultation_id,
                        plan.runtime_profile(),
                        notary_evaluation_id,
                    )
                    .map_err(|_| ConsultationServiceError::Unavailable);
                }
                BatchChildReplayReservation::InProgress => {
                    return Err(ConsultationServiceError::Unavailable);
                }
                BatchChildReplayReservation::Conflict => {
                    return Err(ConsultationServiceError::Conflict);
                }
            }
        } else {
            None
        };
        let consent = match VerifiedConsentAuthority::consent_not_required(canonical) {
            Ok(consent) => consent,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let _local_permit = match Arc::clone(&activated.semaphore).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                self.record_denial_inner(
                    ConsultationDenialRoute::Execute,
                    503,
                    ConsultationDenialReason::Capacity,
                )
                .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let _rhai_worker_permit = if let Some(semaphore) = &activated.rhai_worker_semaphore {
            match Arc::clone(semaphore).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                        .await?;
                    self.record_denial_inner(
                        ConsultationDenialRoute::Execute,
                        503,
                        ConsultationDenialReason::Capacity,
                    )
                    .await?;
                    return Err(ConsultationServiceError::Unavailable);
                }
            }
        } else {
            None
        };
        let authority = match self
            .state_plane
            .pseudonym_keyring()
            .current_write_authority()
            .await
        {
            Ok(authority) => authority,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let committer = match self.pseudonym_materials.bind_write(authority) {
            Ok(committer) => committer,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let pseudonym_inputs = match build_pseudonym_inputs(consent) {
            Ok(inputs) => inputs,
            Err(error) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(map_request_commitment_error(error));
            }
        };
        let pseudonyms = committer.prepare_attempt(pseudonym_inputs);
        let reservation = self
            .state_plane
            .quota()
            .reserve(
                QuotaKey::from_authenticated(&workload, plan.profile()),
                activated.quota_limits.effective(),
            )
            .await;
        let quota = match reservation {
            Ok(QuotaReservation::Allowed(grant)) => grant,
            Ok(QuotaReservation::Exhausted(exhaustion)) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                let retry_after =
                    ConsultationRetryAfter::from_duration(exhaustion.into_retry_after())
                        .ok_or(ConsultationServiceError::Unavailable)?;
                return Err(ConsultationServiceError::RateLimited(retry_after));
            }
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let decision = match evaluate_compiled_policy(pseudonyms, &workload, quota) {
            Ok(decision) => decision,
            Err(error) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(map_authorization_commitment_error(error));
            }
        };
        let attempt = match authorize_consultation_attempt(decision) {
            Ok(attempt) => attempt,
            Err(error) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(map_authorization_commitment_error(error));
            }
        };
        let (credential_permits, verification_permits, data_permits) =
            match activated.executor.permit_counts(plan) {
                Ok(counts) => counts,
                Err(_) => {
                    release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                        .await?;
                    return Err(ConsultationServiceError::Unavailable);
                }
            };
        let permit_set = match ConsultationPermitSet::from_counts(
            credential_permits,
            verification_permits,
            data_permits,
        ) {
            Ok(permits) => permits,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let fence = match self
            .state_plane
            .serving_fence()
            .authorize_consultation_attempt(activated.dispatch_budget, permit_set)
            .await
        {
            Ok(fence) => fence,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let prepared = match prepare_atomic_consultation_attempt(
            consultation_id,
            notary_evaluation_id,
            attempt,
            fence,
        ) {
            Ok(prepared) => prepared,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let audited = match self
            .state_plane
            .audit()
            .write_attempt_with_completion_intent(prepared)
            .await
        {
            Ok(audited) => audited,
            Err(_) => {
                release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                    .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        match audited
            .execute_concrete_consultation(
                activated.executor,
                self.state_plane.serving_fence(),
                &self.basic_credentials,
                &self.static_bearer_credentials,
                &self.oauth_credentials,
                &self.snapshots,
                &self.datafusion,
            )
            .await
        {
            Ok(executed) => {
                match self
                    .state_plane
                    .audit()
                    .finalize_concrete_consultation(
                        executed,
                        self.state_plane.pseudonym_keyring(),
                        batch_context,
                    )
                    .await
                    .map_err(|_| ConsultationServiceError::Unavailable)?
                {
                    FinalizedConcreteConsultation::Published(response) => {
                        Ok((*response).into_http_body())
                    }
                    FinalizedConcreteConsultation::FinalizedFailure(_) => {
                        Err(ConsultationServiceError::Unavailable)
                    }
                }
            }
            Err(unfinished) => {
                let receipt = self
                    .state_plane
                    .audit()
                    .close_unfinished_consultation(unfinished, self.state_plane.pseudonym_keyring())
                    .await
                    .map_err(|_| ConsultationServiceError::Unavailable)?;
                if receipt.outcome() == ConsultationCompletionOutcome::NotStarted {
                    release_batch_child_before_dispatch(&self.state_plane, batch_context.as_ref())
                        .await?;
                }
                Err(ConsultationServiceError::Unavailable)
            }
        }
    }

    /// Persist one server-owned, non-pseudonym denial decision. Any failure is
    /// fail-closed and permanently removes consultation audit readiness until
    /// the process restarts.
    pub(crate) async fn record_denial(
        self: &Arc<Self>,
        route: ConsultationDenialRoute,
        public_status: u16,
        reason: ConsultationDenialReason,
    ) -> Result<(), ConsultationServiceError> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut tasks = self
                .accepted_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !self.admission_open.load(Ordering::Acquire) {
                return Err(ConsultationServiceError::Unavailable);
            }
            let tasks = tasks
                .as_mut()
                .ok_or(ConsultationServiceError::Unavailable)?;
            while tasks.try_join_next().is_some() {}
            let service = Arc::clone(self);
            tasks.spawn(async move {
                let result = service
                    .record_denial_inner(route, public_status, reason)
                    .await;
                let _ = sender.send(result);
            });
        }
        receiver
            .await
            .unwrap_or(Err(ConsultationServiceError::Unavailable))
    }

    async fn record_denial_inner(
        &self,
        route: ConsultationDenialRoute,
        public_status: u16,
        reason: ConsultationDenialReason,
    ) -> Result<(), ConsultationServiceError> {
        if !self.audit_healthy.load(Ordering::Acquire) {
            return Err(ConsultationServiceError::Unavailable);
        }
        let timestamp_unix_ms = match trusted_timestamp_unix_ms() {
            Some(timestamp) => timestamp,
            None => {
                self.latch_audit_unhealthy();
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let write = match build_denial_decision_write(
            Ulid::new(),
            route,
            public_status,
            reason,
            timestamp_unix_ms,
        ) {
            Ok(write) => write,
            Err(()) => {
                self.latch_audit_unhealthy();
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let outcome = self.state_plane.audit().write_phase(&write).await;
        complete_denial_write(&self.audit_healthy, outcome)
    }

    fn latch_audit_unhealthy(&self) {
        self.audit_healthy.store(false, Ordering::Release);
    }

    /// Close admission under the same task-set lock used for submission,
    /// drain every accepted task, then release the state plane exactly once.
    pub async fn shutdown(&self) -> Result<(), ConsultationServiceShutdownError> {
        if self
            .admission_open
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ConsultationServiceShutdownError::AlreadyStarted);
        }
        let mut tasks = self
            .accepted_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or(ConsultationServiceShutdownError::AlreadyStarted)?;
        while tasks.join_next().await.is_some() {}
        self.state_plane
            .shutdown()
            .await
            .map_err(|_| ConsultationServiceShutdownError::StatePlane)
    }
}

async fn release_batch_child_before_dispatch(
    state_plane: &ConsultationStatePlaneRuntime,
    context: Option<&BatchChildReplayContext>,
) -> Result<(), ConsultationServiceError> {
    if let Some(context) = context {
        state_plane
            .audit()
            .release_batch_child_replay(context)
            .await
            .map_err(|_| ConsultationServiceError::Unavailable)?;
    }
    Ok(())
}

fn trusted_timestamp_unix_ms() -> Option<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
}

const fn tracked_execute_denial(
    error: ConsultationServiceError,
) -> Option<(u16, ConsultationDenialReason)> {
    match error {
        ConsultationServiceError::InvalidRequest => {
            Some((400, ConsultationDenialReason::InvalidRequest))
        }
        ConsultationServiceError::Conflict => Some((409, ConsultationDenialReason::Conflict)),
        ConsultationServiceError::Denied => Some((403, ConsultationDenialReason::Denied)),
        ConsultationServiceError::RateLimited(_) => {
            Some((429, ConsultationDenialReason::RateLimited))
        }
        ConsultationServiceError::InvalidCredentials
        | ConsultationServiceError::ProfileNotFound
        | ConsultationServiceError::Unavailable => None,
    }
}

fn build_denial_decision_write(
    denial_id: Ulid,
    route: ConsultationDenialRoute,
    public_status: u16,
    reason: ConsultationDenialReason,
    timestamp_unix_ms: i64,
) -> Result<DurableAuditWrite, ()> {
    if !reason.accepts_status(public_status) {
        return Err(());
    }
    let operation_id = DurableAuditOperationId::from_ulid(denial_id);
    DurableAuditWrite::new(
        DurableAuditStreamKind::Denial,
        operation_id.clone(),
        DurableAuditPhase::DenialDecision,
        json!({
            "schema": DENIAL_DECISION_SCHEMA,
            "denial_id": operation_id.as_str(),
            "route_template": route.as_str(),
            "public_status": public_status,
            "reason_class": reason.as_str(),
            "timestamp_unix_ms": timestamp_unix_ms,
        }),
    )
    .map_err(|_| ())
}

fn complete_denial_write(
    audit_healthy: &AtomicBool,
    outcome: Result<DurableAuditWriteOutcome, DurableAuditWriteError>,
) -> Result<(), ConsultationServiceError> {
    if matches!(outcome, Ok(DurableAuditWriteOutcome::Inserted(_))) {
        return Ok(());
    }
    audit_healthy.store(false, Ordering::Release);
    Err(ConsultationServiceError::Unavailable)
}

fn compile_service_activation(
    config: &Config,
    artifacts: VerifiedConsultationArtifactClosure,
    production: bool,
) -> Result<CompiledServiceActivation, ConsultationServiceActivationError> {
    let consultation = config
        .consultation
        .as_ref()
        .ok_or(ConsultationServiceActivationError::MissingConfiguration)?;
    let fixed_workload_identity = compile_fixed_workload_identity(config, consultation)?;
    let rhai_workers = initialize_rhai_worker_capabilities(&artifacts)
        .map_err(|_| ConsultationServiceActivationError::RegistryActivation)?;
    let mut registry = CompiledConsultationRegistry::compile(
        artifacts,
        &rhai_workers,
        &InitializedConsentVerifierRegistry::empty(),
    )
    .map_err(|_| ConsultationServiceActivationError::RegistryActivation)?;
    if production {
        validate_production_rhai_worker_platform(&registry)?;
        registry
            .activate_private_transports()
            .map_err(|_| ConsultationServiceActivationError::RegistryActivation)?;
    }
    validate_snapshot_config_bindings(config, &registry)?;
    let mut profiles = BTreeMap::new();
    for plan in registry.plans_for_concrete_activation() {
        let (key, activated) = compile_profile_activation(plan, &fixed_workload_identity)?;
        insert_activated_profile(&mut profiles, key, activated)?;
    }
    let (basic_credentials, static_bearer_credentials, oauth_credentials) = if production {
        (
            Some(
                CompiledBasicSourceCredentialProvider::compile_for_consultations(
                    &consultation.source_credentials,
                    &registry,
                )
                .map_err(|_| ConsultationServiceActivationError::SourceCredentials)?,
            ),
            Some(
                CompiledStaticBearerSourceCredentialProvider::compile_for_consultations(
                    &consultation.source_credentials,
                    &registry,
                )
                .map_err(|_| ConsultationServiceActivationError::SourceCredentials)?,
            ),
            Some(
                CompiledOAuthSourceCredentialProvider::compile_for_consultations(
                    &consultation.source_credentials,
                    &registry,
                )
                .map_err(|_| ConsultationServiceActivationError::SourceCredentials)?,
            ),
        )
    } else {
        validate_source_credential_catalog(&consultation.source_credentials, &registry)
            .map_err(|_| ConsultationServiceActivationError::SourceCredentials)?;
        (None, None, None)
    };
    let pseudonym_materials = if production {
        Some(
            AuditPseudonymMaterialProvider::compile(consultation)
                .map_err(|_| ConsultationServiceActivationError::PseudonymMaterial)?,
        )
    } else {
        AuditPseudonymMaterialProvider::validate_catalog(consultation)
            .map_err(|_| ConsultationServiceActivationError::PseudonymMaterial)?;
        None
    };
    let snapshots = Arc::new(
        PublishedSnapshotRegistry::compile(&registry)
            .map_err(|_| ConsultationServiceActivationError::UnsupportedPlan)?,
    );
    Ok(CompiledServiceActivation {
        registry,
        fixed_workload_identity,
        profiles,
        basic_credentials,
        static_bearer_credentials,
        oauth_credentials,
        pseudonym_materials,
        snapshots,
    })
}

fn insert_activated_profile(
    profiles: &mut BTreeMap<ConsultationKey, ActivatedProfile>,
    key: ConsultationKey,
    activated: ActivatedProfile,
) -> Result<(), ConsultationServiceActivationError> {
    if profiles
        .keys()
        .any(|active: &ConsultationKey| active.id() == key.id())
    {
        return Err(ConsultationServiceActivationError::RegistryActivation);
    }
    profiles.insert(key, activated);
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_production_rhai_worker_platform(
    registry: &CompiledConsultationRegistry,
) -> Result<(), ConsultationServiceActivationError> {
    validate_production_rhai_worker_requirement(
        registry
            .plans_for_concrete_activation()
            .any(|plan| plan.kind() == crate::source_plan::SourcePlanKind::Script),
    )
}

#[cfg(not(target_os = "linux"))]
fn validate_production_rhai_worker_platform(
    registry: &CompiledConsultationRegistry,
) -> Result<(), ConsultationServiceActivationError> {
    validate_production_rhai_worker_requirement(
        registry
            .plans_for_concrete_activation()
            .any(|plan| plan.kind() == crate::source_plan::SourcePlanKind::Script),
    )
}

#[cfg(target_os = "linux")]
fn validate_production_rhai_worker_requirement(
    has_rhai: bool,
) -> Result<(), ConsultationServiceActivationError> {
    #[cfg(test)]
    let _ = has_rhai;
    #[cfg(not(test))]
    if has_rhai && WorkerProcess::dedicated_executable().is_err() {
        return Err(ConsultationServiceActivationError::UnsupportedPlan);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_production_rhai_worker_requirement(
    has_rhai: bool,
) -> Result<(), ConsultationServiceActivationError> {
    if has_rhai {
        Err(ConsultationServiceActivationError::UnsupportedPlan)
    } else {
        Ok(())
    }
}

fn compiled_rhai_worker_semaphore(
    runtime: &crate::source_plan::runtime_profile::CompiledRuntimeProfile,
) -> Option<Arc<Semaphore>> {
    runtime
        .dispatch()
        .script_limits()
        .map(|limits| Arc::new(Semaphore::new(usize::from(limits.concurrency()))))
}

fn validate_snapshot_config_bindings(
    config: &Config,
    registry: &CompiledConsultationRegistry,
) -> Result<(), ConsultationServiceActivationError> {
    for plan in registry
        .plans_for_concrete_activation()
        .filter(|plan| plan.kind() == SourcePlanKind::SnapshotExact)
    {
        let binding = plan
            .snapshot_binding()
            .ok_or(ConsultationServiceActivationError::UnsupportedPlan)?;
        let resource = config
            .datasets
            .iter()
            .flat_map(|dataset| {
                dataset
                    .table_configs()
                    .map(move |resource| (dataset, resource))
            })
            .find(|(dataset, resource)| {
                crate::ingest::table_name(&dataset.id, &resource.id) == binding.table_provider()
            })
            .map(|(_, resource)| resource)
            .ok_or(ConsultationServiceActivationError::UnsupportedPlan)?;
        let declared = DeclaredSchema::from(&resource.schema);
        if !declared.strict {
            return Err(ConsultationServiceActivationError::UnsupportedPlan);
        }
        for (logical, physical) in binding.projection() {
            let acquired = plan
                .runtime_profile()
                .acquisition()
                .fields()
                .find(|field| field.name() == logical)
                .ok_or(ConsultationServiceActivationError::UnsupportedPlan)?;
            let configured = declared
                .field(physical)
                .ok_or(ConsultationServiceActivationError::UnsupportedPlan)?;
            if !snapshot_field_type_compatible(acquired.schema(), configured.ty)
                || acquired.schema().nullable() != configured.nullable
            {
                return Err(ConsultationServiceActivationError::UnsupportedPlan);
            }
        }
        if binding.keys().any(|(_, physical)| {
            declared
                .field(physical)
                .is_none_or(|field| field.ty != FieldType::String || field.nullable)
        }) {
            return Err(ConsultationServiceActivationError::UnsupportedPlan);
        }
        for (logical, physical) in [
            binding.source_observed_at_extraction(),
            binding
                .source_revision_extraction()
                .map(|(logical, physical, _)| (logical, physical)),
        ]
        .into_iter()
        .flatten()
        {
            let acquired = plan
                .runtime_profile()
                .acquisition()
                .fields()
                .find(|field| field.name() == logical)
                .ok_or(ConsultationServiceActivationError::UnsupportedPlan)?;
            let configured = declared
                .field(physical)
                .ok_or(ConsultationServiceActivationError::UnsupportedPlan)?;
            if !matches!(
                acquired.schema(),
                CompiledResponseSchema::Scalar(CompiledScalarShape::String { .. })
            ) || configured.ty != FieldType::String
                || acquired.schema().nullable() != configured.nullable
            {
                return Err(ConsultationServiceActivationError::UnsupportedPlan);
            }
        }
    }
    Ok(())
}

fn snapshot_field_type_compatible(schema: &CompiledResponseSchema, field_type: FieldType) -> bool {
    matches!(
        (schema, field_type),
        (
            CompiledResponseSchema::Scalar(CompiledScalarShape::String { .. }),
            FieldType::String
        ) | (
            CompiledResponseSchema::Scalar(CompiledScalarShape::Date { .. }),
            FieldType::Date
        ) | (
            CompiledResponseSchema::Scalar(CompiledScalarShape::Boolean { .. }),
            FieldType::Boolean
        ) | (
            CompiledResponseSchema::Scalar(CompiledScalarShape::Integer { .. }),
            FieldType::Integer
        ) | (
            CompiledResponseSchema::Scalar(CompiledScalarShape::Number { .. }),
            FieldType::Number
        )
    )
}

fn compile_fixed_workload_identity(
    config: &Config,
    consultation: &ConsultationConfig,
) -> Result<ConfiguredOidcWorkloadProof, ConsultationServiceActivationError> {
    if config.auth.mode != ConfigAuthMode::Oidc {
        return Err(ConsultationServiceActivationError::InvalidWorkloadBinding);
    }
    let oidc = config
        .auth
        .oidc
        .as_ref()
        .ok_or(ConsultationServiceActivationError::InvalidWorkloadBinding)?;
    let configured = &consultation.authorized_workload;
    if !oidc
        .audiences
        .iter()
        .any(|audience| audience == &configured.audience)
    {
        return Err(ConsultationServiceActivationError::InvalidWorkloadBinding);
    }
    if !oidc.allowed_clients.is_empty()
        && (configured.client_claim_selector
            != crate::config::ConsultationClientClaimSelectorConfig::Azp
            || !oidc
                .allowed_clients
                .iter()
                .any(|client| client == &configured.client_value))
    {
        return Err(ConsultationServiceActivationError::InvalidWorkloadBinding);
    }
    let selector = ClientClaimSelector::try_from(configured.client_claim_selector.as_str())
        .map_err(|_| ConsultationServiceActivationError::InvalidWorkloadBinding)?;
    Ok(ConfiguredOidcWorkloadProof::new(
        ConfiguredIssuer::try_from_with_local_loopback(
            oidc.issuer.as_str(),
            oidc.allow_dev_insecure_fetch_urls,
        )
        .map_err(|_| ConsultationServiceActivationError::InvalidWorkloadBinding)?,
        ConfiguredAudience::try_from(configured.audience.as_str())
            .map_err(|_| ConsultationServiceActivationError::InvalidWorkloadBinding)?,
        ConfiguredClientBinding::new(
            selector,
            ExpectedClientValue::try_from(configured.client_value.as_str())
                .map_err(|_| ConsultationServiceActivationError::InvalidWorkloadBinding)?,
        ),
        ConfiguredPrincipalId::try_from(configured.principal_id.as_str())
            .map_err(|_| ConsultationServiceActivationError::InvalidWorkloadBinding)?,
    ))
}

fn compile_profile_activation(
    plan: &CompiledSourcePlan,
    fixed_workload_identity: &ConfiguredOidcWorkloadProof,
) -> Result<(ConsultationKey, ActivatedProfile), ConsultationServiceActivationError> {
    let executor = ConcreteExecutorKind::activate(plan)
        .map_err(|_| ConsultationServiceActivationError::UnsupportedPlan)?;
    let runtime = plan.runtime_profile();
    let key = ConsultationKey::try_parse(
        runtime.profile().id().as_str(),
        runtime.profile().version().to_string().as_str(),
    )
    .map_err(|_| ConsultationServiceActivationError::RegistryActivation)?;
    let public = quota_limits(runtime.public_limits())?;
    let effective_rate = u16::try_from(runtime.effective_limits().quota_per_minute())
        .map_err(|_| ConsultationServiceActivationError::InvalidQuotaLimits)?;
    let effective_burst = u8::try_from(runtime.effective_limits().quota_burst())
        .map_err(|_| ConsultationServiceActivationError::InvalidQuotaLimits)?;
    let effective = EffectiveQuotaLimits::lowered_from(public, effective_rate, effective_burst)
        .map_err(|_| ConsultationServiceActivationError::InvalidQuotaLimits)?;
    let max_in_flight = usize::from(runtime.effective_limits().max_in_flight());
    let rhai_worker_semaphore = compiled_rhai_worker_semaphore(runtime);
    let metadata = Arc::from(protected_metadata_bytes(plan)?.into_boxed_slice());
    let workload_binding = ConsultationWorkloadBinding::new(
        ConsultationWorkloadRole::Authorized,
        runtime.workload_id().clone(),
        fixed_workload_identity.clone(),
        runtime.required_scope().clone(),
        runtime.tenant().clone(),
        runtime.registry_instance().clone(),
    );
    Ok((
        key,
        ActivatedProfile {
            workload_binding,
            quota_limits: ActivatedQuotaLimits { public, effective },
            semaphore: Arc::new(Semaphore::new(max_in_flight)),
            rhai_worker_semaphore,
            metadata,
            executor,
            dispatch_budget: executor
                .dispatch_budget(plan)
                .map_err(|_| ConsultationServiceActivationError::UnsupportedPlan)?,
        },
    ))
}

fn quota_limits(
    limits: crate::source_plan::SourcePlanLimits,
) -> Result<PublicQuotaLimits, ConsultationServiceActivationError> {
    PublicQuotaLimits::new(
        u16::try_from(limits.quota_per_minute())
            .map_err(|_| ConsultationServiceActivationError::InvalidQuotaLimits)?,
        u8::try_from(limits.quota_burst())
            .map_err(|_| ConsultationServiceActivationError::InvalidQuotaLimits)?,
    )
    .map_err(|_| ConsultationServiceActivationError::InvalidQuotaLimits)
}

fn protected_metadata_bytes(
    plan: &CompiledSourcePlan,
) -> Result<Vec<u8>, ConsultationServiceActivationError> {
    encode_protected_metadata(
        plan.profile().contract_hash().as_str(),
        plan.canonical_public_contract(),
    )
}

fn encode_protected_metadata(
    contract_hash: &str,
    contract: &[u8],
) -> Result<Vec<u8>, ConsultationServiceActivationError> {
    if contract.len() > MAX_PROTECTED_CONTRACT_JSON_BYTES {
        return Err(ConsultationServiceActivationError::InvalidMetadata);
    }
    let contract = registry_platform_crypto::parse_json_strict(contract)
        .map_err(|_| ConsultationServiceActivationError::InvalidMetadata)?;
    let metadata = serde_json::to_vec(&json!({
        "contract_hash": contract_hash,
        "contract": contract,
    }))
    .map_err(|_| ConsultationServiceActivationError::InvalidMetadata)?;
    if metadata.len() > MAX_PROTECTED_PROFILE_METADATA_BYTES {
        return Err(ConsultationServiceActivationError::InvalidMetadata);
    }
    Ok(metadata)
}

const fn map_request_commitment_error(
    error: ConsultationCommitmentError,
) -> ConsultationServiceError {
    match error {
        ConsultationCommitmentError::CanonicalInputMismatch
        | ConsultationCommitmentError::InputOutOfBounds
        | ConsultationCommitmentError::Canonicalization => ConsultationServiceError::InvalidRequest,
        ConsultationCommitmentError::AuthorizationMismatch => ConsultationServiceError::Denied,
        ConsultationCommitmentError::ConsentMismatch | ConsultationCommitmentError::InvalidTime => {
            ConsultationServiceError::Unavailable
        }
    }
}

const fn map_authorization_commitment_error(
    error: ConsultationCommitmentError,
) -> ConsultationServiceError {
    match error {
        ConsultationCommitmentError::AuthorizationMismatch => ConsultationServiceError::Denied,
        ConsultationCommitmentError::CanonicalInputMismatch
        | ConsultationCommitmentError::ConsentMismatch
        | ConsultationCommitmentError::InvalidTime
        | ConsultationCommitmentError::InputOutOfBounds
        | ConsultationCommitmentError::Canonicalization => ConsultationServiceError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_audit::{AuditChainHasher, DurableAuditStoredIdentity};
    use registry_platform_crypto::parse_json_strict;

    use super::*;
    use crate::source_plan::{
        bounded_runtime_vector_plan_fixture, dhis2_runtime_vector_plan_fixture,
        rhai_runtime_vector_plan_fixture,
    };

    fn fixed_identity() -> ConfiguredOidcWorkloadProof {
        ConfiguredOidcWorkloadProof::new(
            ConfiguredIssuer::try_from("https://issuer.example.test/realms/registry").unwrap(),
            ConfiguredAudience::try_from("registry-relay").unwrap(),
            ConfiguredClientBinding::new(
                ClientClaimSelector::Azp,
                ExpectedClientValue::try_from("registry-notary").unwrap(),
            ),
            ConfiguredPrincipalId::try_from("registry-notary").unwrap(),
        )
    }

    #[test]
    fn profile_activation_accepts_capability_bounded_http_and_precomputes_public_metadata() {
        let plan = dhis2_runtime_vector_plan_fixture();
        let (key, activated) = compile_profile_activation(&plan, &fixed_identity()).unwrap();
        assert_eq!(key.id(), plan.profile().id());
        assert_eq!(key.version(), plan.profile().version());
        assert_eq!(
            activated.semaphore.available_permits(),
            usize::from(plan.limits().max_in_flight())
        );
        let metadata = parse_json_strict(&activated.metadata).unwrap();
        assert_eq!(
            metadata["contract_hash"].as_str(),
            Some(plan.profile().contract_hash().as_str())
        );
        assert_eq!(
            metadata["contract"],
            parse_json_strict(plan.canonical_public_contract()).unwrap()
        );
        assert!(!metadata
            .as_object()
            .unwrap()
            .contains_key("private_binding"));
        assert!(!metadata.as_object().unwrap().contains_key("contract_json"));
        assert_eq!(metadata.as_object().unwrap().len(), 2);

        let bounded = bounded_runtime_vector_plan_fixture();
        let (_, activated) = compile_profile_activation(&bounded, &fixed_identity())
            .expect("bounded HTTP capability activates");
        assert_eq!(activated.executor, ConcreteExecutorKind::BoundedHttp);
    }

    #[test]
    fn activation_rejects_two_internal_versions_for_one_public_profile_id() {
        let plan = dhis2_runtime_vector_plan_fixture();
        let (_, first) = compile_profile_activation(&plan, &fixed_identity()).unwrap();
        let (_, second) = compile_profile_activation(&plan, &fixed_identity()).unwrap();
        let mut profiles = BTreeMap::new();
        insert_activated_profile(
            &mut profiles,
            ConsultationKey::try_parse(plan.profile().id().as_str(), "1").unwrap(),
            first,
        )
        .unwrap();
        assert_eq!(
            insert_activated_profile(
                &mut profiles,
                ConsultationKey::try_parse(plan.profile().id().as_str(), "2").unwrap(),
                second,
            ),
            Err(ConsultationServiceActivationError::RegistryActivation)
        );
    }

    #[test]
    fn script_activation_enforces_the_compiled_worker_concurrency_permit() {
        let plan = rhai_runtime_vector_plan_fixture();
        let worker =
            compiled_rhai_worker_semaphore(plan.runtime_profile()).expect("Rhai worker semaphore");
        assert_eq!(worker.available_permits(), 1);
        let first = Arc::clone(&worker)
            .try_acquire_owned()
            .expect("first worker permit");
        assert!(Arc::clone(&worker).try_acquire_owned().is_err());
        drop(first);
        assert!(Arc::clone(&worker).try_acquire_owned().is_ok());
    }

    #[test]
    fn production_rhai_activation_requires_the_linux_process_sandbox() {
        assert_eq!(validate_production_rhai_worker_requirement(false), Ok(()));
        #[cfg(target_os = "linux")]
        assert_eq!(validate_production_rhai_worker_requirement(true), Ok(()));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            validate_production_rhai_worker_requirement(true),
            Err(ConsultationServiceActivationError::UnsupportedPlan)
        );
    }

    #[test]
    fn snapshot_date_binding_requires_the_typed_date_field() {
        let date = CompiledResponseSchema::Scalar(CompiledScalarShape::Date { nullable: false });
        let string = CompiledResponseSchema::Scalar(CompiledScalarShape::String {
            nullable: false,
            max_bytes: 10,
        });

        assert!(snapshot_field_type_compatible(&date, FieldType::Date));
        assert!(!snapshot_field_type_compatible(&date, FieldType::String));
        assert!(!snapshot_field_type_compatible(&string, FieldType::Date));
        assert!(snapshot_field_type_compatible(&string, FieldType::String));
    }

    #[test]
    fn protected_metadata_embeds_the_complete_bounded_contract_object() {
        let hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let encoded = encode_protected_metadata(
            hash,
            br#"{"spec":{"integration":{"id":"individual-status","revision":3}},"value":"line\nquote\""}"#,
        )
        .expect("bounded canonical contract");
        let metadata = parse_json_strict(&encoded).expect("strict metadata");
        assert_eq!(metadata["contract_hash"], hash);
        assert_eq!(
            metadata["contract"],
            json!({
                "spec": {"integration": {"id": "individual-status", "revision": 3}},
                "value": "line\nquote\""
            })
        );
        assert!(metadata["contract"]["spec"]["integration_pack"].is_null());
        assert!(metadata["contract"]["spec"]["integration"]["hash"].is_null());
        assert!(metadata["contract"].is_object());

        assert_eq!(
            encode_protected_metadata(hash, &[0xff]),
            Err(ConsultationServiceActivationError::InvalidMetadata)
        );
        assert_eq!(
            encode_protected_metadata(hash, &vec![b'x'; MAX_PROTECTED_CONTRACT_JSON_BYTES + 1],),
            Err(ConsultationServiceActivationError::InvalidMetadata)
        );
    }

    #[test]
    fn retry_after_is_ceiling_rounded_and_closed_to_one_minute() {
        assert_eq!(
            ConsultationRetryAfter::from_duration(Duration::from_millis(1))
                .unwrap()
                .seconds(),
            1
        );
        assert_eq!(
            ConsultationRetryAfter::from_duration(Duration::from_millis(1_001))
                .unwrap()
                .seconds(),
            2
        );
        assert_eq!(
            ConsultationRetryAfter::from_duration(Duration::from_secs(60))
                .unwrap()
                .seconds(),
            60
        );
        assert!(ConsultationRetryAfter::from_duration(Duration::ZERO).is_none());
        assert!(ConsultationRetryAfter::from_duration(Duration::from_millis(60_001)).is_none());
    }

    #[test]
    fn service_error_mapping_is_closed_and_value_free() {
        assert_eq!(
            map_request_commitment_error(ConsultationCommitmentError::CanonicalInputMismatch),
            ConsultationServiceError::InvalidRequest
        );
        assert_eq!(
            map_request_commitment_error(ConsultationCommitmentError::AuthorizationMismatch),
            ConsultationServiceError::Denied
        );
        let rate_limited = ConsultationServiceError::RateLimited(
            ConsultationRetryAfter::from_duration(Duration::from_secs(3)).unwrap(),
        );
        assert_eq!(format!("{rate_limited}"), "consultation quota is exhausted");
        assert!(!format!("{rate_limited:?}").contains('3'));
    }

    #[test]
    fn denial_decision_payload_is_closed_and_marker_free() {
        let denial_id = Ulid::new();
        let denial_id_text = denial_id.to_string();
        let write = build_denial_decision_write(
            denial_id,
            ConsultationDenialRoute::Execute,
            403,
            ConsultationDenialReason::Denied,
            1_787_000_000_123,
        )
        .expect("closed denial payload builds");
        let envelope = write
            .build_envelope_at_chain_head(None, &AuditChainHasher::unkeyed_dev_only())
            .expect("test envelope builds");
        assert_eq!(envelope.record["stream_kind"], "denial");
        assert_eq!(envelope.record["phase"], "denial_decision");
        assert_eq!(envelope.record["operation_id"], denial_id_text);
        assert_eq!(
            envelope.record["payload"],
            json!({
                "schema": DENIAL_DECISION_SCHEMA,
                "denial_id": denial_id_text,
                "route_template": crate::api::consultation::EXECUTE_ROUTE,
                "public_status": 403,
                "reason_class": "denied",
                "timestamp_unix_ms": 1_787_000_000_123_i64,
            })
        );
        let encoded = serde_json::to_string(&envelope.record).unwrap();
        for forbidden in [
            "credential-secret-marker",
            "notary-evaluation-id-marker",
            "subject-selector-marker",
            "data-purpose-marker",
            "principal-marker",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn denial_routes_and_reason_status_pairs_are_closed() {
        assert_eq!(
            ConsultationDenialRoute::Profile.as_str(),
            crate::api::consultation::PROFILE_ROUTE
        );
        assert_eq!(
            ConsultationDenialRoute::Execute.as_str(),
            crate::api::consultation::EXECUTE_ROUTE
        );
        assert_eq!(
            ConsultationDenialRoute::Unmatched.as_str(),
            "/v1/consultations/{unmatched}"
        );
        assert!(build_denial_decision_write(
            Ulid::new(),
            ConsultationDenialRoute::Profile,
            401,
            ConsultationDenialReason::InvalidCredentials,
            1,
        )
        .is_ok());
        assert!(build_denial_decision_write(
            Ulid::new(),
            ConsultationDenialRoute::Profile,
            503,
            ConsultationDenialReason::InvalidCredentials,
            1,
        )
        .is_err());
        assert!(build_denial_decision_write(
            Ulid::new(),
            ConsultationDenialRoute::Execute,
            503,
            ConsultationDenialReason::Capacity,
            1,
        )
        .is_ok());
    }

    #[test]
    fn denial_write_failure_and_duplicate_latch_audit_unhealthy() {
        let healthy = AtomicBool::new(true);
        assert_eq!(
            complete_denial_write(&healthy, Err(DurableAuditWriteError::StoreUnavailable)),
            Err(ConsultationServiceError::Unavailable)
        );
        assert!(!healthy.load(Ordering::Acquire));

        let write = build_denial_decision_write(
            Ulid::new(),
            ConsultationDenialRoute::Unmatched,
            404,
            ConsultationDenialReason::NotFound,
            1,
        )
        .unwrap();
        let envelope = write
            .build_envelope_at_chain_head(None, &AuditChainHasher::unkeyed_dev_only())
            .unwrap();
        let stored = DurableAuditStoredIdentity::from_envelope(&envelope).unwrap();
        let healthy = AtomicBool::new(true);
        assert_eq!(
            complete_denial_write(
                &healthy,
                Ok(DurableAuditWriteOutcome::ConflictingDuplicate(
                    stored.clone(),
                )),
            ),
            Err(ConsultationServiceError::Unavailable)
        );
        assert!(!healthy.load(Ordering::Acquire));

        let healthy = AtomicBool::new(true);
        assert_eq!(
            complete_denial_write(&healthy, Ok(DurableAuditWriteOutcome::Inserted(stored))),
            Ok(())
        );
        assert!(healthy.load(Ordering::Acquire));
    }

    #[test]
    fn tracked_execute_denials_are_closed_and_carry_a_private_recorded_proof() {
        assert_eq!(
            tracked_execute_denial(ConsultationServiceError::InvalidRequest),
            Some((400, ConsultationDenialReason::InvalidRequest))
        );
        assert_eq!(
            tracked_execute_denial(ConsultationServiceError::Denied),
            Some((403, ConsultationDenialReason::Denied))
        );
        assert_eq!(
            tracked_execute_denial(ConsultationServiceError::Conflict),
            Some((409, ConsultationDenialReason::Conflict))
        );
        let rate_limited = ConsultationServiceError::RateLimited(
            ConsultationRetryAfter::from_duration(Duration::from_secs(2)).unwrap(),
        );
        assert_eq!(
            tracked_execute_denial(rate_limited),
            Some((429, ConsultationDenialReason::RateLimited))
        );
        assert_eq!(
            tracked_execute_denial(ConsultationServiceError::Unavailable),
            None
        );

        let (error, proof) =
            ConsultationExecutionError::denial_recorded(ConsultationServiceError::Denied)
                .into_parts();
        assert_eq!(error, ConsultationServiceError::Denied);
        assert_eq!(proof, Some(ConsultationDenialRecorded::for_test()));
    }
}
