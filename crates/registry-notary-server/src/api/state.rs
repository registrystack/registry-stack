// SPDX-License-Identifier: Apache-2.0
//! API runtime state and atomic runtime-snapshot publication.

use super::*;

pub(super) const AUDIT_ACK_CURSOR_READ_TIMEOUT: Duration = Duration::from_millis(500);
pub(super) static AUDIT_ACK_CURSOR_READ_PERMIT: OnceLock<Arc<tokio::sync::Semaphore>> =
    OnceLock::new();

pub(super) fn audit_ack_cursor_read_permit() -> Arc<tokio::sync::Semaphore> {
    Arc::clone(
        AUDIT_ACK_CURSOR_READ_PERMIT.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1))),
    )
}

pub(super) async fn bounded_audit_ack_observation(
    config: &StandaloneRegistryNotaryConfig,
) -> AckObservation {
    let Some(path) = config
        .deployment
        .evidence
        .audit_ack_cursor_path()
        .map(std::path::Path::to_path_buf)
    else {
        return AckObservation::unverified();
    };
    let max_age = config.deployment.evidence.audit_ack_max_age();
    let permit = match audit_ack_cursor_read_permit().try_acquire_owned() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::Closed) => {
            return AckObservation::invalid("ack cursor read worker is unavailable");
        }
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return AckObservation::invalid("ack cursor read is still in progress");
        }
    };
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        registry_platform_ops::evaluate_ack_health(Some(path.as_path()), SystemTime::now(), max_age)
    });
    match tokio::time::timeout(AUDIT_ACK_CURSOR_READ_TIMEOUT, worker).await {
        Ok(Ok(observation)) => observation,
        Ok(Err(_)) => AckObservation::invalid("ack cursor read worker failed"),
        Err(_) => AckObservation::invalid("ack cursor read timed out"),
    }
}
pub trait EvidenceIssuerResolver: Send + Sync {
    fn issuer(
        &self,
        profile_id: &str,
    ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError>;

    fn public_jwks(&self, evidence: &EvidenceConfig) -> Result<Vec<Value>, EvidenceError> {
        evidence
            .credential_profiles
            .keys()
            .map(|profile_id| {
                self.issuer(profile_id)
                    .map(|issuer| issuer.public_jwk().clone())
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct RegistryNotaryApiState {
    pub(crate) evidence: Arc<EvidenceConfig>,
    pub(crate) self_attestation: Arc<SelfAttestationConfig>,
    pub(crate) oid4vci: Arc<Oid4vciConfig>,
    pub(crate) federation: Arc<FederationConfig>,
    pub(super) self_attestation_rate_limiter: Arc<SelfAttestationRateLimiter>,
    pub(crate) self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    pub(super) machine_quota_limiter: Arc<MachineQuotaLimiter>,
    pub(crate) replay: ReplayStores,
    pub(crate) credential_status: CredentialStatusStore,
    pub(super) status_list_jwt_cache: Arc<StatusListJwtCache>,
    pub(crate) metrics: Arc<AppMetrics>,
    pub(crate) source: Arc<dyn SourceReader>,
    pub(crate) store: Arc<EvidenceStore>,
    pub(super) runtime: Arc<RwLock<Arc<ApiRuntimeSnapshot>>>,
    pub(super) auth_state: Option<Arc<AuthAuditState>>,
    pub(super) audit: Option<crate::standalone::AuditPipeline>,
    pub(crate) posture: Option<Arc<PostureContext>>,
    pub(crate) deployment_gates: Arc<crate::standalone::DeploymentGateState>,
    pub(super) config_apply_posture: Arc<RwLock<ConfigApplyPosture>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) cel_config: Arc<RegistryNotaryCelConfig>,
}

#[derive(Clone)]
pub(super) struct ApiRuntimeSnapshot {
    pub(super) federation_runtime: Option<Arc<crate::federation::FederationRuntimeState>>,
    pub(super) issuer_runtime: Arc<IssuerRuntimeBundle>,
    pub(super) config_governance: ConfigGovernanceContext,
    pub(super) runtime_config: Option<Arc<StandaloneRegistryNotaryConfig>>,
    /// Pre-authorized-code flow runtime. `None` unless the flow is enabled and
    /// the dedicated access-token signing key plus eSignet RP settings loaded.
    pub(super) preauth: Option<Arc<PreAuthRuntime>>,
}

pub(super) struct IssuerRuntimeBundle {
    pub(super) issuers: Arc<dyn EvidenceIssuerResolver>,
    pub(super) signer_readiness: SignerReadiness,
}

impl RegistryNotaryApiState {
    #[must_use]
    pub fn new(
        evidence: Arc<EvidenceConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation(
            evidence,
            Arc::new(SelfAttestationConfig::default()),
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci(
            evidence,
            self_attestation,
            Arc::new(Oid4vciConfig::default()),
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation_and_oid4vci(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci_hasher(
            evidence,
            self_attestation,
            oid4vci,
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation_hasher(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_self_attestation_and_oid4vci_hasher(
            evidence,
            self_attestation,
            Arc::new(Oid4vciConfig::default()),
            audit_hasher,
            source,
            store,
            issuers,
        )
    }

    #[must_use]
    pub fn new_with_self_attestation_and_oid4vci_hasher(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        audit_hasher: AuditKeyHasher,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
    ) -> Self {
        Self::new_with_runtime_blocks(
            evidence,
            self_attestation,
            oid4vci,
            Arc::new(FederationConfig::default()),
            None,
            audit_hasher,
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
            source,
            store,
            issuers,
            SignerReadiness::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_federation(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        federation: Arc<FederationConfig>,
        audit_hasher: AuditKeyHasher,
        federation_audit: Option<crate::standalone::AuditPipeline>,
        replay: ReplayStores,
        credential_status: CredentialStatusStore,
        metrics: Arc<AppMetrics>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
        federation_signing_provider: Option<Arc<dyn SigningProvider>>,
    ) -> Result<Self, crate::standalone::StandaloneServerError> {
        let federation_runtime = federation
            .enabled
            .then(|| {
                let signing_provider = federation_signing_provider.clone().ok_or_else(|| {
                    crate::standalone::StandaloneServerError::InvalidFederationConfig(
                        "federation signing provider was not built".to_string(),
                    )
                })?;
                crate::federation::FederationRuntimeState::from_config(
                    &federation,
                    signing_provider,
                    federation_audit,
                    replay.store(),
                    Arc::clone(&metrics),
                )
            })
            .transpose()?
            .map(Arc::new);
        Ok(Self::new_with_runtime_blocks(
            evidence,
            self_attestation,
            oid4vci,
            federation,
            federation_runtime,
            audit_hasher,
            replay,
            credential_status,
            metrics,
            source,
            store,
            issuers,
            SignerReadiness::default(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_runtime_blocks(
        evidence: Arc<EvidenceConfig>,
        self_attestation: Arc<SelfAttestationConfig>,
        oid4vci: Arc<Oid4vciConfig>,
        federation: Arc<FederationConfig>,
        federation_runtime: Option<Arc<crate::federation::FederationRuntimeState>>,
        audit_hasher: AuditKeyHasher,
        replay: ReplayStores,
        credential_status: CredentialStatusStore,
        metrics: Arc<AppMetrics>,
        source: Arc<dyn SourceReader>,
        store: Arc<EvidenceStore>,
        issuers: Arc<dyn EvidenceIssuerResolver>,
        signer_readiness: SignerReadiness,
    ) -> Self {
        let self_attestation_rate_limiter = Arc::new(SelfAttestationRateLimiter::new(
            self_attestation.rate_limits.clone(),
        ));
        let self_attestation_rate_keys = Arc::new(SelfAttestationRateLimitKeys::new(audit_hasher));
        let machine_quota_limiter = Arc::new(MachineQuotaLimiter::new(evidence.machine_quota));
        let issuer_runtime = Arc::new(IssuerRuntimeBundle {
            issuers,
            signer_readiness,
        });
        let runtime = Arc::new(ApiRuntimeSnapshot {
            federation_runtime,
            issuer_runtime,
            config_governance: ConfigGovernanceContext::default(),
            runtime_config: None,
            preauth: None,
        });
        Self {
            evidence,
            self_attestation,
            oid4vci,
            federation,
            self_attestation_rate_limiter,
            self_attestation_rate_keys,
            machine_quota_limiter,
            replay,
            credential_status,
            status_list_jwt_cache: Arc::new(StatusListJwtCache::default()),
            metrics,
            source,
            store,
            runtime: Arc::new(RwLock::new(runtime)),
            auth_state: None,
            audit: None,
            posture: None,
            deployment_gates: Arc::new(crate::standalone::DeploymentGateState::default()),
            config_apply_posture: Arc::new(RwLock::new(ConfigApplyPosture::default())),
            #[cfg(feature = "registry-notary-cel")]
            cel_worker: None,
            #[cfg(feature = "registry-notary-cel")]
            cel_config: Arc::new(RegistryNotaryCelConfig::default()),
        }
    }

    #[must_use]
    pub(crate) fn with_auth_state(mut self, auth_state: Arc<AuthAuditState>) -> Self {
        self.auth_state = Some(auth_state);
        self
    }

    #[must_use]
    pub(crate) fn with_audit_pipeline(mut self, audit: crate::standalone::AuditPipeline) -> Self {
        self.audit = Some(audit);
        self
    }

    #[must_use]
    pub(crate) fn with_preauth_runtime(self, preauth: Option<Arc<PreAuthRuntime>>) -> Self {
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.preauth = preauth;
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(crate) fn with_signer_readiness(self, signer_readiness: SignerReadiness) -> Self {
        let current = self.issuer_runtime();
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.issuer_runtime = Arc::new(IssuerRuntimeBundle {
            issuers: current.issuers.clone(),
            signer_readiness,
        });
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(crate) fn with_posture_context(mut self, posture: PostureContext) -> Self {
        self.posture = Some(Arc::new(posture));
        self
    }

    pub(crate) fn with_deployment_gates(
        mut self,
        gates: crate::standalone::DeploymentGateState,
    ) -> Self {
        self.deployment_gates = Arc::new(gates);
        self
    }

    pub(crate) fn with_config_governance(self, context: ConfigGovernanceContext) -> Self {
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.config_governance = context;
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(crate) fn with_runtime_config(self, config: Arc<StandaloneRegistryNotaryConfig>) -> Self {
        let mut runtime = (*self.runtime_snapshot()).clone();
        runtime.runtime_config = Some(config);
        self.publish_runtime_snapshot(Arc::new(runtime));
        self
    }

    pub(super) fn runtime_snapshot(&self) -> Arc<ApiRuntimeSnapshot> {
        self.runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn publish_runtime_snapshot(&self, snapshot: Arc<ApiRuntimeSnapshot>) {
        *self
            .runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }

    pub(crate) fn runtime_config(&self) -> Option<Arc<StandaloneRegistryNotaryConfig>> {
        self.runtime_snapshot().runtime_config.clone()
    }

    pub(crate) fn deployment_gates_for_observation(
        &self,
        config: &StandaloneRegistryNotaryConfig,
        observation: &registry_platform_ops::AckObservation,
    ) -> crate::standalone::DeploymentGateState {
        self.deployment_gates.evaluate_current(config, observation)
    }

    pub(crate) async fn current_audit_ack_observation(
        &self,
        config: &StandaloneRegistryNotaryConfig,
    ) -> registry_platform_ops::AckObservation {
        let observation = bounded_audit_ack_observation(config).await;
        if !observation.requires_audit_tail_binding() {
            return observation;
        }
        let tail = match &self.audit {
            Some(audit) => audit.current_tail_hash_bounded().await,
            None => None,
        };
        observation.bind_to_audit_tail(tail)
    }

    pub(crate) async fn current_deployment_gates(&self) -> crate::standalone::DeploymentGateState {
        let Some(config) = self.runtime_config() else {
            return (*self.deployment_gates).clone();
        };
        let observation = self.current_audit_ack_observation(&config).await;
        self.deployment_gates_for_observation(&config, &observation)
    }

    pub(super) fn openapi_requires_auth(&self) -> bool {
        self.auth_state.as_ref().map_or_else(
            || {
                self.runtime_config()
                    .map(|config| config.server.openapi_requires_auth)
                    .unwrap_or(true)
            },
            |auth_state| auth_state.openapi_requires_auth(),
        )
    }

    pub(crate) fn federation_runtime(
        &self,
    ) -> Option<Arc<crate::federation::FederationRuntimeState>> {
        self.runtime_snapshot().federation_runtime.clone()
    }

    pub(crate) fn config_apply_posture(&self) -> ConfigApplyPosture {
        self.config_apply_posture
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn record_config_apply(&self, posture: ConfigApplyPosture) {
        *self
            .config_apply_posture
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = posture;
    }

    pub(super) fn issuer_runtime(&self) -> Arc<IssuerRuntimeBundle> {
        self.runtime_snapshot().issuer_runtime.clone()
    }

    pub(super) fn issuer_resolver(&self) -> Arc<dyn EvidenceIssuerResolver> {
        self.issuer_runtime().issuers.clone()
    }

    pub(crate) fn signer_readiness(&self) -> SignerReadiness {
        self.issuer_runtime().signer_readiness.clone()
    }

    #[cfg(feature = "registry-notary-cel")]
    #[must_use]
    pub(crate) fn with_cel_worker(mut self, cel_worker: Option<Arc<CelWorker>>) -> Self {
        self.cel_worker = cel_worker;
        self
    }

    #[cfg(feature = "registry-notary-cel")]
    #[must_use]
    pub(crate) fn with_cel_config(mut self, cel_config: Arc<RegistryNotaryCelConfig>) -> Self {
        self.cel_config = cel_config;
        self
    }

    pub(crate) fn runtime(&self) -> RegistryNotaryRuntime {
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(
            &self.self_attestation_rate_keys,
        ));
        #[cfg(feature = "registry-notary-cel")]
        {
            runtime
                .with_cel_worker(self.cel_worker.as_ref().map(Arc::clone))
                .with_cel_config(Arc::clone(&self.cel_config))
        }
        #[cfg(not(feature = "registry-notary-cel"))]
        {
            runtime
        }
    }

    pub(crate) fn enabled_evidence(&self) -> Result<&EvidenceConfig, EvidenceError> {
        if self.evidence.enabled {
            Ok(&self.evidence)
        } else {
            Err(EvidenceError::ServerDisabled)
        }
    }
}
