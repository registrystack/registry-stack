use super::*;

/// Build a source-free Notary router synchronously.
///
/// Registry-backed configurations intentionally return
/// [`StandaloneServerError::RelayNotActivated`]. Processes serving those
/// configurations must compile the runtime, await
/// [`NotaryRuntimeSnapshot::activate_relay`], and only then build listeners.
pub fn standalone_router(
    config: StandaloneRegistryNotaryConfig,
) -> Result<Router, StandaloneServerError> {
    let admin_listener_mode = config.server.admin_listener.mode;
    let runtime = compile_notary_runtime(config)?;
    match admin_listener_mode {
        RegistryNotaryAdminListenerMode::SharedWithPublic => notary_router_from_runtime(runtime),
        RegistryNotaryAdminListenerMode::Dedicated | RegistryNotaryAdminListenerMode::Disabled => {
            Ok(notary_routers_from_runtime(runtime)?.public)
        }
    }
}

pub struct NotaryRuntimeSnapshot {
    metrics: Arc<AppMetrics>,
    auth_state: Arc<AuthAuditState>,
    api_state: Arc<RegistryNotaryApiState>,
    cors_policy: registry_platform_httpsec::CorsPolicy,
    wallet_cors_policy: SelfAttestationWalletCorsPolicy,
    http_limits: NotaryHttpLimits,
    federation_enabled: bool,
}

impl NotaryRuntimeSnapshot {
    /// Authenticate to Relay and verify the exact pinned consultation profile.
    ///
    /// Source-free runtimes complete without reading credentials or performing
    /// network I/O.
    pub async fn activate_relay(self) -> Result<Self, StandaloneServerError> {
        let config = self
            .api_state
            .runtime_config()
            .ok_or(StandaloneServerError::InvalidRelayActivationPlan)?;
        if let Some(activated) = activate_relay_from_config(&config).await? {
            self.api_state
                .install_activated_relay(activated)
                .map_err(|_| StandaloneServerError::RelayAlreadyActivated)?;
        }
        self.ensure_ready_to_serve()?;
        Ok(self)
    }

    fn ensure_ready_to_serve(&self) -> Result<(), StandaloneServerError> {
        if self.api_state.relay_required() && !self.api_state.relay_activated() {
            return Err(StandaloneServerError::RelayNotActivated);
        }
        Ok(())
    }

    pub async fn emit_config_boot_audit(
        &self,
        event: &'static str,
        audit: ConfigAuditEvent,
    ) -> Result<(), AuditError> {
        self.auth_state
            .audit
            .emit(&config_boot_audit_event(event, audit))
            .await
    }
}

#[derive(Debug, Clone, Copy)]
struct NotaryHttpLimits {
    request_timeout: Duration,
    request_body_timeout: Duration,
}

pub struct NotaryRouters {
    pub public: Router,
    pub admin: Router,
}

pub fn compile_notary_runtime(
    config: StandaloneRegistryNotaryConfig,
) -> Result<NotaryRuntimeSnapshot, StandaloneServerError> {
    compile_notary_runtime_with_provenance(config, ConfigSource::LocalFile, None)
}

/// Perform the same authenticated, hash-pinned Relay metadata verification
/// used during startup without constructing the rest of the Notary runtime.
/// Returns `false` only when the configuration has no Registry-backed claims.
pub async fn verify_relay_from_config(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<bool, StandaloneServerError> {
    config.validate()?;
    Ok(activate_relay_from_config(config).await?.is_some())
}

pub fn compile_notary_runtime_with_provenance(
    config: StandaloneRegistryNotaryConfig,
    config_source: ConfigSource,
    config_provenance: Option<ConfigProvenance>,
) -> Result<NotaryRuntimeSnapshot, StandaloneServerError> {
    config.validate()?;
    let deployment_gates = DeploymentGateState::evaluate_with_config_source(&config, config_source);
    deployment_gates.fail_startup_if_blocked()?;
    let federation_enabled = config.federation.enabled;
    let http_limits = NotaryHttpLimits {
        request_timeout: config.server.request_timeout,
        request_body_timeout: config.server.request_body_timeout,
    };
    let evidence = Arc::new(config.evidence.clone());
    let self_attestation = Arc::new(config.self_attestation.clone());
    let oid4vci = Arc::new(config.oid4vci.clone());
    let federation = Arc::new(config.federation.clone());
    let metrics = Arc::new(AppMetrics::default());
    let replay = ReplayStores::from_config(&config.replay)?;
    let credential_status = CredentialStatusStore::from_config(&config.credential_status)?;
    let gate_input = config.gate_input();
    if gate_input.replay_in_memory && gate_input.high_risk_replay_mode() {
        tracing::warn!(
            target: "registry_notary::replay",
            "replay store is in-memory single-instance only; a high-risk mode \
             (federation, OID4VCI pre-authorized code, holder proof, wallet traffic, \
             or declared multi-instance) is active. Do not run active-active without \
             shared replay storage."
        );
    }
    let source = Arc::new(HttpEvidenceSources::from_config(
        &config.evidence,
        Arc::clone(&metrics),
    )?);
    let store = Arc::new(EvidenceStore::default());
    let reuse_scoped_key_ids = config.reuse_scoped_signing_key_ids();
    let signing_keys = Arc::new(SigningKeyRegistry::from_config(
        &config.evidence,
        &reuse_scoped_key_ids,
    )?);
    let signer_readiness = signing_keys.signer_readiness();
    let issuers = Arc::new(EvidenceIssuerRegistry::from_signing_keys(
        &config.evidence,
        &signing_keys,
    )?);
    let federation_signing_provider = if config.federation.enabled {
        Some(
            signing_keys
                .signing_provider(config.federation.signing.signing_key.as_str())
                .ok_or_else(|| {
                    invalid_signing_key(
                        config.federation.signing.signing_key.as_str(),
                        "active federation signing key was not built",
                    )
                })?,
        )
    } else {
        None
    };
    let cors_policy = registry_platform_httpsec::CorsPolicy {
        allowed_origins: config.server.cors.allowed_origins.clone(),
        allowed_methods: Vec::new(),
        allowed_headers: Vec::new(),
        allow_credentials: false,
    };
    cors_policy.validate()?;
    let wallet_cors_policy = SelfAttestationWalletCorsPolicy::from_config(&config);
    let auth_state = Arc::new(AuthAuditState::from_config(
        &config,
        Arc::clone(&metrics),
        replay.clone(),
    )?);
    let posture_context =
        PostureContext::from_config(&config, &auth_state.audit).map_err(|error| {
            StandaloneServerError::InvalidSigningKey {
                key: error.key_id().to_string(),
                reason: "unsupported signing key status".to_string(),
            }
        })?;
    #[cfg(feature = "registry-notary-cel")]
    let cel_worker = build_cel_worker(&config, Arc::clone(&metrics))?;
    let preauth_runtime =
        PreAuthRuntime::from_config(&config, &signing_keys, auth_state.audit.clone())?
            .map(Arc::new);
    let api_state = RegistryNotaryApiState::new_with_federation(
        evidence,
        self_attestation,
        oid4vci,
        federation,
        auth_state.audit.profile.key_hasher(),
        config.federation.enabled.then(|| auth_state.audit.clone()),
        replay,
        credential_status,
        Arc::clone(&metrics),
        source,
        store,
        issuers,
        federation_signing_provider,
    )?
    .with_auth_state(Arc::clone(&auth_state))
    .with_audit_pipeline(auth_state.audit.clone())
    .with_preauth_runtime(preauth_runtime)
    .with_signer_readiness(signer_readiness)
    .with_posture_context(posture_context)
    .with_deployment_gates(deployment_gates)
    .with_config_governance(ConfigGovernanceContext::from_config(&config))
    .with_runtime_config(Arc::new(config.clone()));
    if let Some(provenance) = config_provenance {
        api_state.record_config_apply(crate::api::ConfigApplyPosture::from_provenance(provenance));
    }
    #[cfg(feature = "registry-notary-cel")]
    let api_state = api_state
        .with_cel_worker(cel_worker)
        .with_cel_config(Arc::new(config.cel.clone()));
    let api_state = Arc::new(api_state);
    Ok(NotaryRuntimeSnapshot {
        metrics,
        auth_state,
        api_state,
        cors_policy,
        wallet_cors_policy,
        http_limits,
        federation_enabled,
    })
}

pub fn notary_router_from_runtime(
    snapshot: NotaryRuntimeSnapshot,
) -> Result<Router, StandaloneServerError> {
    notary_shared_router_from_runtime(snapshot)
}

pub fn notary_shared_router_from_runtime(
    snapshot: NotaryRuntimeSnapshot,
) -> Result<Router, StandaloneServerError> {
    snapshot.ensure_ready_to_serve()?;
    let NotaryRuntimeSnapshot {
        metrics,
        auth_state,
        api_state,
        cors_policy,
        wallet_cors_policy,
        http_limits,
        federation_enabled,
    } = snapshot;
    let mut routes = router();
    if federation_enabled {
        routes = routes.merge(crate::api::federation_router());
    }
    routes = routes.route(
        "/metrics",
        get(admin_metrics_handler).with_state(Arc::clone(&metrics)),
    );

    Ok(layer_notary_routes(
        routes,
        metrics,
        auth_state,
        api_state,
        cors_policy,
        wallet_cors_policy,
        http_limits,
    ))
}

pub fn notary_routers_from_runtime(
    snapshot: NotaryRuntimeSnapshot,
) -> Result<NotaryRouters, StandaloneServerError> {
    snapshot.ensure_ready_to_serve()?;
    let NotaryRuntimeSnapshot {
        metrics,
        auth_state,
        api_state,
        cors_policy,
        wallet_cors_policy,
        http_limits,
        federation_enabled,
    } = snapshot;
    let mut public_routes = crate::api::public_router();
    if federation_enabled {
        public_routes = public_routes.merge(crate::api::federation_router());
    }
    let admin_routes = crate::api::admin_router().route(
        "/metrics",
        get(admin_metrics_handler).with_state(Arc::clone(&metrics)),
    );

    Ok(NotaryRouters {
        public: layer_notary_routes(
            public_routes,
            Arc::clone(&metrics),
            Arc::clone(&auth_state),
            Arc::clone(&api_state),
            cors_policy.clone(),
            wallet_cors_policy.clone(),
            http_limits,
        ),
        admin: layer_notary_routes(
            admin_routes,
            metrics,
            auth_state,
            api_state,
            cors_policy,
            wallet_cors_policy,
            http_limits,
        ),
    })
}

/// Build the router mounted on the public listener.
///
/// The returned router is still wrapped in auth/audit middleware; only explicit
/// probe and public protocol routes are exempted from authentication.
pub fn notary_public_router_from_runtime(
    snapshot: NotaryRuntimeSnapshot,
) -> Result<Router, StandaloneServerError> {
    Ok(notary_routers_from_runtime(snapshot)?.public)
}

pub fn notary_admin_router_from_runtime(
    snapshot: NotaryRuntimeSnapshot,
) -> Result<Router, StandaloneServerError> {
    Ok(notary_routers_from_runtime(snapshot)?.admin)
}

fn layer_notary_routes(
    routes: Router,
    metrics: Arc<AppMetrics>,
    auth_state: Arc<AuthAuditState>,
    api_state: Arc<RegistryNotaryApiState>,
    cors_policy: registry_platform_httpsec::CorsPolicy,
    wallet_cors_policy: SelfAttestationWalletCorsPolicy,
    http_limits: NotaryHttpLimits,
) -> Router {
    let cors_layer = match cors_policy.try_layer() {
        Ok(layer) => layer,
        Err(err) => {
            tracing::error!(
                error = %err,
                "cors policy failed platform validation; falling back to deny-all"
            );
            tower_http::cors::CorsLayer::new()
        }
    };
    routes
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            http_limits.request_timeout,
        ))
        .layer(from_fn_with_state(Arc::clone(&metrics), metrics_middleware))
        .layer(axum::Extension(Arc::clone(&api_state)))
        .layer(from_fn_with_state(auth_state, auth_audit_middleware))
        // Axum executes later layers first. Keep the proof precheck here so a
        // malformed OID4VCI proof is rejected before authentication side effects.
        .layer(from_fn_with_state(
            api_state,
            crate::api::oid4vci_proof_precheck_middleware,
        ))
        .layer(registry_platform_httpsec::security_headers(
            registry_platform_httpsec::CspBuilder::restrictive(),
        ))
        .layer(cors_layer)
        .layer(from_fn_with_state(
            wallet_cors_policy,
            self_attestation_wallet_cors_middleware,
        ))
        .layer(registry_platform_httpsec::corp_conditional())
        .layer(registry_platform_httpsec::request_body_limit(
            MAX_INBOUND_REQUEST_BODY_BYTES,
        ))
        .layer(RequestBodyTimeoutLayer::new(
            http_limits.request_body_timeout,
        ))
        .layer(axum::middleware::from_fn(rewrite_payload_too_large_problem))
        .layer(axum::middleware::from_fn(reject_oversized_request_uri))
        .layer(axum::middleware::from_fn(
            attach_request_id_to_problem_response,
        ))
}

#[derive(Debug, thiserror::Error)]
pub enum StandaloneServerError {
    #[error(transparent)]
    Config(#[from] registry_notary_core::EvidenceConfigError),
    #[error("configured credential environment variable is missing or empty: {0}")]
    MissingCredentialEnv(String),
    #[error(
        "configured credential hash environment variable contains an invalid fingerprint: {0}"
    )]
    InvalidCredentialHash(String, #[source] FingerprintFormatError),
    #[error("configured source token environment variable is missing or empty: {0}")]
    MissingSourceTokenEnv(String),
    #[error("configured Relay destination is invalid")]
    InvalidRelayDestination,
    #[error("configured Relay consultation activation plan is invalid")]
    InvalidRelayActivationPlan,
    #[error("Relay consultation activation failed")]
    RelayActivation,
    #[error("Relay consultation client was already activated")]
    RelayAlreadyActivated,
    #[error("Relay consultation client was not activated before serving")]
    RelayNotActivated,
    #[error("Relay workload credential is unavailable")]
    RelayCredentialUnavailable,
    #[error("Relay rejected the configured workload credential")]
    RelayCredentialsRejected,
    #[error("Relay consultation profile was not found")]
    RelayProfileNotFound,
    #[error("Relay consultation profile does not match its configured pin")]
    RelayProfileMismatch,
    #[error("Relay consultation service is unavailable")]
    RelayUnavailable,
    #[error("invalid source auth configuration: {0}")]
    InvalidSourceAuth(String),
    #[error("signing key '{key}' is invalid: {reason}")]
    InvalidSigningKey { key: String, reason: String },
    #[error("signing key provider '{provider}' is not enabled")]
    SigningKeyProviderUnavailable { provider: String },
    #[error("federation secret environment variable is missing or empty: {0}")]
    MissingFederationSecretEnv(String),
    #[error("audit sink path is required when sink=file or sink=jsonl")]
    MissingAuditPath,
    #[error("audit.hash_secret_env is required")]
    MissingAuditHashSecretEnv,
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Cors(#[from] registry_platform_httpsec::CorsValidationError),
    #[error("unsupported audit sink: {0}")]
    InvalidAuditSink(String),
    #[error("invalid audit configuration: {0}")]
    InvalidAuditConfig(String),
    #[error(transparent)]
    Replay(#[from] ReplayBuildError),
    #[error(transparent)]
    CredentialStatus(#[from] CredentialStatusBuildError),
    #[error("failed to build HTTP source client")]
    HttpClient(#[source] reqwest::Error),
    #[error("invalid OIDC auth configuration: {0}")]
    InvalidOidcConfig(String),
    #[error("invalid federation configuration: {0}")]
    InvalidFederationConfig(String),
    #[cfg(feature = "registry-notary-cel")]
    #[error("invalid CEL worker configuration: {0}")]
    InvalidCelConfig(String),
    #[error(
        "deployment profile '{profile}' refuses startup; failing gates: {findings}; {DEPLOYMENT_PROFILE_REQUIRED_ACTION}"
    )]
    DeploymentGateStartupFailure { profile: String, findings: String },
}
#[cfg(feature = "registry-notary-cel")]
fn build_cel_worker(
    config: &StandaloneRegistryNotaryConfig,
    metrics: Arc<AppMetrics>,
) -> Result<Option<Arc<CelWorker>>, StandaloneServerError> {
    let evidence = &config.evidence;
    if !evidence_uses_cel(evidence) {
        return Ok(None);
    }
    if config.cel.mode == "disabled" {
        return Err(StandaloneServerError::InvalidCelConfig(
            "CEL claims require cel.mode = worker".to_string(),
        ));
    }
    validate_cel_claims_for_startup(evidence, &config.cel)
        .map_err(|_| StandaloneServerError::InvalidCelConfig("invalid CEL policy".to_string()))?;
    let worker =
        CelWorker::lazy(CelWorkerConfig::from_standalone_config(&config.cel)).with_metrics(metrics);
    worker
        .validate_config()
        .map_err(|error| StandaloneServerError::InvalidCelConfig(error.to_string()))?;
    Ok(Some(Arc::new(worker)))
}

#[cfg(feature = "registry-notary-cel")]
fn evidence_uses_cel(evidence: &EvidenceConfig) -> bool {
    evidence
        .claims
        .iter()
        .any(|claim| matches!(&claim.rule, registry_notary_core::RuleConfig::Cel { .. }))
}
