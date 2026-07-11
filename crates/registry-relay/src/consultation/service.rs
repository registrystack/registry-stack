// SPDX-License-Identifier: Apache-2.0
//! Concrete consultation service for the one-step Basic GET product journey.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use registry_platform_audit::{
    AuditChainHasher, DurableAuditOperationId, DurableAuditPhase, DurableAuditSink,
    DurableAuditStreamKind, DurableAuditWrite, DurableAuditWriteError, DurableAuditWriteOutcome,
};
use serde_json::json;
use thiserror::Error;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;
use ulid::Ulid;

use crate::api::consultation::ParsedConsultationEnvelope;
use crate::auth::AuthenticationResult;
use crate::config::{
    AuthMode as ConfigAuthMode, Config, ConsultationConfig, VerifiedConsultationArtifactClosure,
};
use crate::source_plan::{
    CompiledBasicSourceCredentialProvider, CompiledConsultationRegistry, CompiledSourcePlan,
    InitializedConsentVerifierRegistry,
};
use crate::state_plane::{
    ConsultationPermitSet, ConsultationStatePlaneReadiness, ConsultationStatePlaneRuntime,
    EffectiveQuotaLimits, PublicQuotaLimits, QuotaKey, QuotaReservation,
};

use super::audit::{prepare_atomic_consultation_attempt, FinalizedBasicGetConsultation};
use super::commitments::{
    authorize_consultation_attempt, build_pseudonym_inputs, CanonicalConsultationInputs,
    ConsultationCommitmentError, VerifiedConsentAuthority,
};
use super::executor::{dispatch_budget, validate_basic_get_activation};
use super::policy::evaluate_compiled_policy;
use super::pseudonym::AuditPseudonymMaterialProvider;
use super::{
    AuthenticatedConsultationWorkload, AuthenticatedNotaryWorkload, ClientClaimSelector,
    ConfiguredAudience, ConfiguredClientBinding, ConfiguredIssuer, ConfiguredOidcWorkloadProof,
    ConfiguredPrincipalId, ConsultationId, ConsultationKey, ConsultationWorkloadBinding,
    ConsultationWorkloadRole, ExpectedClientValue, PreAuthorizationConsultationCore,
    ResolvedConsultationProfile,
};

const MAX_PROTECTED_PROFILE_METADATA_BYTES: usize = 257 * 1_024;
const METADATA_PREFIX: &[u8] = br#"{"contract_hash":""#;
const METADATA_CONTRACT_MEMBER: &[u8] = br#"","contract":"#;
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
        }
    }

    pub(crate) const fn accepts_status(self, status: u16) -> bool {
        match self {
            Self::InvalidCredentials => status == 401,
            Self::Denied => status == 403,
            Self::NotFound => status == 404,
            Self::RateLimited => status == 429,
            Self::Capacity => status == 503,
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

    pub(crate) fn notary_workload(&self) -> AuthenticatedNotaryWorkload<'_> {
        self.workload
            .try_as_notary()
            .expect("resolved consultation contexts always bind the fixed Notary role")
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
    metadata: Arc<[u8]>,
    dispatch_budget: crate::state_plane::DispatchPermitBudget,
}

struct CompiledServiceActivation {
    registry: CompiledConsultationRegistry,
    fixed_notary_identity: ConfiguredOidcWorkloadProof,
    profiles: BTreeMap<ConsultationKey, ActivatedProfile>,
    credentials: CompiledBasicSourceCredentialProvider,
    pseudonym_materials: AuditPseudonymMaterialProvider,
}

/// Restart-only concrete consultation service.
pub struct ConsultationService {
    registry: CompiledConsultationRegistry,
    fixed_notary_identity: ConfiguredOidcWorkloadProof,
    profiles: BTreeMap<ConsultationKey, ActivatedProfile>,
    credentials: CompiledBasicSourceCredentialProvider,
    pseudonym_materials: AuditPseudonymMaterialProvider,
    state_plane: ConsultationStatePlaneRuntime,
    admission_open: AtomicBool,
    audit_healthy: AtomicBool,
    accepted_tasks: Mutex<Option<JoinSet<()>>>,
}

impl ConsultationService {
    /// Compile every process-local capability, then connect the concrete state
    /// plane last so failed static activation never acquires serving authority.
    pub async fn activate(
        config: &Config,
        artifacts: VerifiedConsultationArtifactClosure,
        chain_hasher: AuditChainHasher,
    ) -> Result<Arc<Self>, ConsultationServiceActivationError> {
        let compiled = compile_service_activation(config, artifacts)?;
        let consultation = config
            .consultation
            .as_ref()
            .ok_or(ConsultationServiceActivationError::MissingConfiguration)?;
        let state_plane =
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
                })?;
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
        if compiled
            .pseudonym_materials
            .bind_write(current_authority)
            .is_err()
        {
            let _ = state_plane.shutdown().await;
            return Err(ConsultationServiceActivationError::PseudonymMaterial);
        }
        Ok(Arc::new(Self {
            registry: compiled.registry,
            fixed_notary_identity: compiled.fixed_notary_identity,
            profiles: compiled.profiles,
            credentials: compiled.credentials,
            pseudonym_materials: compiled.pseudonym_materials,
            state_plane,
            admission_open: AtomicBool::new(true),
            audit_healthy: AtomicBool::new(true),
            accepted_tasks: Mutex::new(Some(JoinSet::new())),
        }))
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

    /// Prove the fixed Notary identity before consulting the profile map, then
    /// apply the selected profile's exact scope and workload binding.
    pub(crate) fn resolve(
        &self,
        authentication: &AuthenticationResult,
        key: &ConsultationKey,
    ) -> Result<ResolvedConsultationContext, ConsultationServiceError> {
        if !self.admission_open.load(Ordering::Acquire)
            || !self.audit_healthy.load(Ordering::Acquire)
        {
            return Err(ConsultationServiceError::Unavailable);
        }
        self.fixed_notary_identity
            .precheck_authentication(authentication)
            .map_err(|_| ConsultationServiceError::InvalidCredentials)?;
        let activated = self
            .profiles
            .get(key)
            .ok_or(ConsultationServiceError::ProfileNotFound)?;
        let workload = AuthenticatedConsultationWorkload::try_bind(
            authentication,
            &activated.workload_binding,
        )
        .map_err(|_| ConsultationServiceError::Denied)?;
        let (resolved_profile, _) = self
            .registry
            .resolve_for_authenticated_workload(key, &workload)
            .ok_or(ConsultationServiceError::Unavailable)?;
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
        let (purpose, input, notary_evaluation_id) = envelope.into_parts();
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
        let consent = VerifiedConsentAuthority::consent_not_required(canonical)
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        let _local_permit = match Arc::clone(&activated.semaphore).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.record_denial_inner(
                    ConsultationDenialRoute::Execute,
                    503,
                    ConsultationDenialReason::Capacity,
                )
                .await?;
                return Err(ConsultationServiceError::Unavailable);
            }
        };
        let reservation = self
            .state_plane
            .quota()
            .reserve(
                QuotaKey::from_authenticated(&workload, plan.profile()),
                activated.quota_limits.effective(),
            )
            .await
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        let quota = match reservation {
            QuotaReservation::Allowed(grant) => grant,
            QuotaReservation::Exhausted(exhaustion) => {
                let retry_after =
                    ConsultationRetryAfter::from_duration(exhaustion.into_retry_after())
                        .ok_or(ConsultationServiceError::Unavailable)?;
                return Err(ConsultationServiceError::RateLimited(retry_after));
            }
        };
        let authority = self
            .state_plane
            .pseudonym_keyring()
            .current_write_authority()
            .await
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        let committer = self
            .pseudonym_materials
            .bind_write(authority)
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        let pseudonym_inputs =
            build_pseudonym_inputs(consent).map_err(map_request_commitment_error)?;
        let pseudonyms = committer.prepare_attempt(pseudonym_inputs);
        let decision = evaluate_compiled_policy(pseudonyms, &workload, quota)
            .map_err(map_authorization_commitment_error)?;
        let attempt =
            authorize_consultation_attempt(decision).map_err(map_authorization_commitment_error)?;
        let permit_set = ConsultationPermitSet::from_counts(0, 1)
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        let fence = self
            .state_plane
            .serving_fence()
            .authorize_consultation_attempt(activated.dispatch_budget, permit_set)
            .await
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        let consultation_id = ConsultationId::generate();
        let prepared = prepare_atomic_consultation_attempt(
            consultation_id,
            notary_evaluation_id,
            attempt,
            fence,
        )
        .map_err(|_| ConsultationServiceError::Unavailable)?;
        let audited = self
            .state_plane
            .audit()
            .write_attempt_with_completion_intent(prepared)
            .await
            .map_err(|_| ConsultationServiceError::Unavailable)?;
        match audited
            .execute_one_step_basic_get(self.state_plane.serving_fence(), &self.credentials)
            .await
        {
            Ok(executed) => match self
                .state_plane
                .audit()
                .finalize_basic_get_consultation(executed, self.state_plane.pseudonym_keyring())
                .await
                .map_err(|_| ConsultationServiceError::Unavailable)?
            {
                FinalizedBasicGetConsultation::Published(response) => Ok(response.into_http_body()),
                FinalizedBasicGetConsultation::FinalizedFailure(_) => {
                    Err(ConsultationServiceError::Unavailable)
                }
            },
            Err(unfinished) => {
                self.state_plane
                    .audit()
                    .close_unfinished_consultation(unfinished, self.state_plane.pseudonym_keyring())
                    .await
                    .map_err(|_| ConsultationServiceError::Unavailable)?;
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
) -> Result<CompiledServiceActivation, ConsultationServiceActivationError> {
    let consultation = config
        .consultation
        .as_ref()
        .ok_or(ConsultationServiceActivationError::MissingConfiguration)?;
    let fixed_notary_identity = compile_fixed_notary_identity(config, consultation)?;
    let registry = CompiledConsultationRegistry::compile(
        artifacts,
        &[],
        &InitializedConsentVerifierRegistry::empty(),
    )
    .map_err(|_| ConsultationServiceActivationError::RegistryActivation)?;
    let mut profiles = BTreeMap::new();
    for plan in registry.plans_for_basic_get_activation() {
        let (key, activated) = compile_profile_activation(plan, &fixed_notary_identity)?;
        if profiles.insert(key, activated).is_some() {
            return Err(ConsultationServiceActivationError::RegistryActivation);
        }
    }
    let credentials = CompiledBasicSourceCredentialProvider::compile_for_consultations(
        &consultation.source_credentials,
        &registry,
    )
    .map_err(|_| ConsultationServiceActivationError::SourceCredentials)?;
    let pseudonym_materials = AuditPseudonymMaterialProvider::compile(consultation)
        .map_err(|_| ConsultationServiceActivationError::PseudonymMaterial)?;
    Ok(CompiledServiceActivation {
        registry,
        fixed_notary_identity,
        profiles,
        credentials,
        pseudonym_materials,
    })
}

fn compile_fixed_notary_identity(
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
    let configured = &consultation.notary_workload;
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
        ConfiguredIssuer::try_from(oidc.issuer.as_str())
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
    fixed_notary_identity: &ConfiguredOidcWorkloadProof,
) -> Result<(ConsultationKey, ActivatedProfile), ConsultationServiceActivationError> {
    validate_basic_get_activation(plan)
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
    let metadata = Arc::from(protected_metadata_bytes(plan)?.into_boxed_slice());
    let workload_binding = ConsultationWorkloadBinding::new(
        ConsultationWorkloadRole::Notary,
        runtime.workload_id().clone(),
        fixed_notary_identity.clone(),
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
            metadata,
            dispatch_budget: dispatch_budget(plan)
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
    let contract = plan.canonical_public_contract();
    let contract_hash = plan.profile().contract_hash().as_str().as_bytes();
    let capacity = METADATA_PREFIX
        .len()
        .checked_add(contract_hash.len())
        .and_then(|length| length.checked_add(METADATA_CONTRACT_MEMBER.len()))
        .and_then(|length| length.checked_add(contract.len()))
        .and_then(|length| length.checked_add(1))
        .filter(|length| *length <= MAX_PROTECTED_PROFILE_METADATA_BYTES)
        .ok_or(ConsultationServiceActivationError::InvalidMetadata)?;
    let mut metadata = Vec::with_capacity(capacity);
    metadata.extend_from_slice(METADATA_PREFIX);
    metadata.extend_from_slice(contract_hash);
    metadata.extend_from_slice(METADATA_CONTRACT_MEMBER);
    metadata.extend_from_slice(contract);
    metadata.push(b'}');
    if metadata.len() != capacity {
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
    fn profile_activation_accepts_only_basic_get_and_precomputes_public_metadata() {
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

        assert_eq!(
            compile_profile_activation(&bounded_runtime_vector_plan_fixture(), &fixed_identity(),)
                .err(),
            Some(ConsultationServiceActivationError::UnsupportedPlan)
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
