use crate::*;

pub(crate) fn value_free_configuration_failure<E>(
    _: E,
) -> registry_notary_server::NotaryActivationFailure {
    registry_notary_server::NotaryActivationCode::CONFIGURATION_INVALID.into()
}

fn value_free_runtime_activation_failure<E>(
    _: E,
) -> registry_notary_server::NotaryActivationFailure {
    registry_notary_server::NotaryActivationCode::RUNTIME_ACTIVATION_FAILED.into()
}

pub(crate) async fn run_server(
    config_input: impl Into<ServerConfigInput>,
    bind_override: Option<SocketAddr>,
    initialize_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    run_server_with_acceptance(
        config_input.into(),
        bind_override,
        initialize_state,
        ServerAcceptanceMode::Legacy,
    )
    .await
}

pub(crate) async fn run_governed_server(
    config_input: ServerConfigInput,
    previous_anchor: Option<registry_platform_config::ConfigTrustAnchor>,
    transition: Option<registry_platform_config::AnchorTransitionV1>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_server_with_acceptance(
        config_input,
        None,
        false,
        ServerAcceptanceMode::Governed(Box::new(GovernedServerAcceptance {
            previous_anchor,
            transition,
        })),
    )
    .await
}

enum ServerAcceptanceMode {
    Legacy,
    Governed(Box<GovernedServerAcceptance>),
}

struct GovernedServerAcceptance {
    previous_anchor: Option<registry_platform_config::ConfigTrustAnchor>,
    transition: Option<registry_platform_config::AnchorTransitionV1>,
}

enum PreparedServerAcceptance {
    Legacy(Option<PendingBundleAcceptance>),
    GovernedExact {
        acceptance: PendingBundleAcceptance,
        audit_evidence: GovernedAcceptanceAuditEvidence,
    },
    GovernedMutation(Box<GovernedServerMutation>),
}

struct GovernedAcceptanceAuditEvidence {
    acceptance_identity: registry_platform_config::ProductAcceptanceIdentityV1,
    bundle_manifest_hash: String,
    anchor_digest: String,
    anchor_version: u64,
}

impl GovernedAcceptanceAuditEvidence {
    fn from_intent(intent: &registry_platform_ops::AcceptanceAuditIntentV1) -> Self {
        Self {
            acceptance_identity: intent.key.acceptance_identity.clone(),
            bundle_manifest_hash: intent.bundle_manifest_hash.clone(),
            anchor_digest: intent.anchor_digest.clone(),
            anchor_version: intent.anchor_version,
        }
    }

    fn from_exact_acceptance(
        acceptance: &PendingBundleAcceptance,
    ) -> Result<Self, BundleVerificationFailure> {
        Ok(Self {
            acceptance_identity: acceptance.key.acceptance_identity.clone(),
            bundle_manifest_hash: acceptance.bundle_manifest_hash.clone().ok_or_else(|| {
                BundleVerificationFailure::from(BundleVerificationCode::REJECTED_VALIDATION)
            })?,
            anchor_digest: acceptance.accepted_anchor.digest.clone(),
            anchor_version: acceptance.accepted_anchor.version,
        })
    }
}

struct GovernedServerMutation {
    acceptance: PendingBundleAcceptance,
    store: registry_platform_ops::FileAntiRollbackStore,
    plan: registry_platform_ops::AcceptanceStatePlanV1,
}

async fn run_server_with_acceptance(
    config_input: ServerConfigInput,
    bind_override: Option<SocketAddr>,
    initialize_state: bool,
    acceptance_mode: ServerAcceptanceMode,
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing().map_err(value_free_configuration_failure)?;

    let loaded = load_server_config_input(&config_input, initialize_state)?;
    let prepared_acceptance = prepare_server_acceptance(&loaded, acceptance_mode)?;
    let mut config = loaded.config;
    apply_bind_override(&mut config, bind_override);
    let bind = config.server.bind;
    let admin_mode = config.server.admin_listener.mode;
    let admin_bind = config.server.admin_listener.bind;
    let serve_limits = ServeLimits::from_config(&config.server);
    let runtime = compile_notary_runtime_with_provenance(
        config,
        loaded.config_source,
        loaded.config_provenance.clone(),
    )
    .map_err(registry_notary_server::NotaryActivationFailure::from)?
    .activate()
    .await
    .map_err(registry_notary_server::NotaryActivationFailure::from)?;
    match admin_mode {
        RegistryNotaryAdminListenerMode::Dedicated => {
            let public_listener = tokio::net::TcpListener::bind(bind).await?;
            let public_addr: SocketAddr = public_listener.local_addr()?;
            let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
            let admin_addr: SocketAddr = admin_listener.local_addr()?;
            finalize_server_acceptance(&runtime, prepared_acceptance)
                .await
                .map_err(value_free_runtime_activation_failure)?;
            let routers = notary_routers_from_runtime(runtime)
                .map_err(registry_notary_server::NotaryActivationFailure::from)?;
            tracing::info!(
                %public_addr,
                %admin_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening with dedicated admin listener"
            );

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = shutdown_tx.send(true);
            });
            let public_shutdown = shutdown_when_signaled(shutdown_rx.clone());
            let admin_shutdown = shutdown_when_signaled(shutdown_rx);
            let public = serve_listener(
                public_listener,
                routers
                    .public
                    .layer(TraceLayer::new_for_http().make_span_with(http_trace_span)),
                serve_limits,
                public_shutdown,
            );
            let admin = serve_listener(
                admin_listener,
                routers
                    .admin
                    .layer(TraceLayer::new_for_http().make_span_with(http_trace_span)),
                serve_limits,
                admin_shutdown,
            );
            tokio::try_join!(public, admin)?;
        }
        RegistryNotaryAdminListenerMode::SharedWithPublic => {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let local_addr: SocketAddr = listener.local_addr()?;
            finalize_server_acceptance(&runtime, prepared_acceptance)
                .await
                .map_err(value_free_runtime_activation_failure)?;
            let app = notary_shared_router_from_runtime(runtime)
                .map_err(registry_notary_server::NotaryActivationFailure::from)?
                .layer(TraceLayer::new_for_http().make_span_with(http_trace_span));
            tracing::info!(
                %local_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening"
            );

            serve_listener(listener, app, serve_limits, shutdown_signal()).await?;
        }
        RegistryNotaryAdminListenerMode::Disabled => {
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let local_addr: SocketAddr = listener.local_addr()?;
            finalize_server_acceptance(&runtime, prepared_acceptance)
                .await
                .map_err(value_free_runtime_activation_failure)?;
            let app = notary_routers_from_runtime(runtime)
                .map_err(registry_notary_server::NotaryActivationFailure::from)?
                .public
                .layer(TraceLayer::new_for_http().make_span_with(http_trace_span));
            tracing::info!(
                %local_addr,
                build_features = ?compiled_build_features(),
                "registry notary listening without admin listener"
            );

            serve_listener(listener, app, serve_limits, shutdown_signal()).await?;
        }
    }
    Ok(())
}

fn prepare_server_acceptance(
    loaded: &LoadedServerConfig,
    mode: ServerAcceptanceMode,
) -> Result<PreparedServerAcceptance, Box<dyn std::error::Error>> {
    match mode {
        ServerAcceptanceMode::Legacy => Ok(PreparedServerAcceptance::Legacy(
            loaded.pending_bundle_acceptance.clone(),
        )),
        ServerAcceptanceMode::Governed(governed) => {
            let GovernedServerAcceptance {
                previous_anchor,
                transition,
            } = *governed;
            let acceptance = loaded.pending_bundle_acceptance.clone().ok_or_else(|| {
                Box::new(BundleVerificationFailure::from(
                    BundleVerificationCode::REJECTED_VALIDATION,
                )) as Box<dyn std::error::Error>
            })?;
            let candidate = loaded.verified_acceptance_state.as_ref().ok_or_else(|| {
                Box::new(BundleVerificationFailure::from(
                    BundleVerificationCode::REJECTED_VALIDATION,
                )) as Box<dyn std::error::Error>
            })?;
            let store = registry_platform_ops::FileAntiRollbackStore::new(&acceptance.state_path);
            if store.verify_state(candidate.expectation()).is_ok() {
                if previous_anchor.is_some() || transition.is_some() {
                    return Err(map_config_boot_error(ConfigBootError::Store(
                        registry_platform_ops::AntiRollbackStoreError::UnexpectedAnchorTransition,
                    )));
                }
                let audit_evidence =
                    GovernedAcceptanceAuditEvidence::from_exact_acceptance(&acceptance)?;
                return Ok(PreparedServerAcceptance::GovernedExact {
                    acceptance,
                    audit_evidence,
                });
            }
            let plan = store
                .plan_acceptance(candidate, previous_anchor.as_ref(), transition.as_ref())
                .map_err(|error| map_config_boot_error(ConfigBootError::Store(error)))?;
            ensure_acceptance_audit_matches_plan(&acceptance, plan.audit_intent())?;
            Ok(PreparedServerAcceptance::GovernedMutation(Box::new(
                GovernedServerMutation {
                    acceptance,
                    store,
                    plan,
                },
            )))
        }
    }
}

async fn finalize_server_acceptance(
    runtime: &registry_notary_server::NotaryRuntimeSnapshot,
    prepared: PreparedServerAcceptance,
) -> Result<(), Box<dyn std::error::Error>> {
    match prepared {
        PreparedServerAcceptance::Legacy(acceptance) => {
            emit_and_persist_boot_acceptance(runtime, acceptance.as_ref()).await
        }
        PreparedServerAcceptance::GovernedExact {
            acceptance,
            audit_evidence,
        } => {
            emit_boot_config_audits_for_action(runtime, &acceptance, "serve", Some(&audit_evidence))
                .await
        }
        PreparedServerAcceptance::GovernedMutation(mutation) => {
            let GovernedServerMutation {
                acceptance,
                store,
                plan,
            } = *mutation;
            store
                .commit_acceptance(plan, |intent| async move {
                    ensure_acceptance_audit_matches_plan(&acceptance, &intent)?;
                    let audit_evidence = GovernedAcceptanceAuditEvidence::from_intent(&intent);
                    emit_boot_config_audits_for_action(
                        runtime,
                        &acceptance,
                        "serve",
                        Some(&audit_evidence),
                    )
                    .await
                })
                .await
                .map_err(|error| map_config_boot_error(ConfigBootError::Store(error)))?;
            Ok(())
        }
    }
}

pub(crate) async fn initialize_state_once(
    config_input: impl Into<ServerConfigInput>,
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing().map_err(value_free_configuration_failure)?;

    let config_input = config_input.into();
    let loaded = load_server_config_input(&config_input, true)?;
    let acceptance = loaded.pending_bundle_acceptance.clone().ok_or_else(|| {
        Box::new(BundleVerificationFailure::from(
            BundleVerificationCode::REJECTED_VALIDATION,
        )) as Box<dyn std::error::Error>
    })?;
    let verified_acceptance_state = loaded.verified_acceptance_state.clone().ok_or_else(|| {
        Box::new(BundleVerificationFailure::from(
            BundleVerificationCode::REJECTED_VALIDATION,
        )) as Box<dyn std::error::Error>
    })?;
    if acceptance.source != ConfigSource::SignedBundleFile
        || acceptance.sequence != Some(1)
        || acceptance.state_action != BundleStateAction::Initialize
    {
        return Err(Box::new(BundleVerificationFailure::from(
            BundleVerificationCode::REJECTED_ROLLBACK,
        )));
    }
    let store = registry_platform_ops::FileAntiRollbackStore::new(&acceptance.state_path);
    let plan = store
        .plan_initialize(&verified_acceptance_state)
        .map_err(|error| map_config_boot_error(ConfigBootError::Store(error)))?;
    ensure_acceptance_audit_matches_plan(&acceptance, plan.audit_intent())?;

    let runtime = compile_notary_runtime_with_provenance(
        loaded.config,
        loaded.config_source,
        loaded.config_provenance,
    )
    .map_err(registry_notary_server::NotaryActivationFailure::from)?
    .activate()
    .await
    .map_err(registry_notary_server::NotaryActivationFailure::from)?;

    store
        .commit_acceptance(plan, |intent| async move {
            ensure_acceptance_audit_matches_plan(&acceptance, &intent)?;
            let audit_evidence = GovernedAcceptanceAuditEvidence::from_intent(&intent);
            emit_boot_config_audits_for_action(
                &runtime,
                &acceptance,
                "initialize_state",
                Some(&audit_evidence),
            )
            .await
        })
        .await
        .map_err(|error| value_free_runtime_activation_failure(ConfigBootError::Store(error)))?;
    Ok(())
}

fn ensure_acceptance_audit_matches_plan(
    acceptance: &PendingBundleAcceptance,
    intent: &registry_platform_ops::AcceptanceAuditIntentV1,
) -> Result<(), Box<dyn std::error::Error>> {
    if acceptance.key == intent.key
        && acceptance.sequence == Some(intent.sequence)
        && acceptance.config_hash == intent.config_hash
        && acceptance.bundle_manifest_hash.as_deref() == Some(&intent.bundle_manifest_hash)
        && acceptance.bundle_id.as_deref() == Some(&intent.bundle_id)
        && acceptance.accepted_anchor.digest == intent.anchor_digest
        && acceptance.accepted_anchor.version == intent.anchor_version
    {
        return Ok(());
    }
    Err(Box::new(BundleVerificationFailure::from(
        BundleVerificationCode::REJECTED_VALIDATION,
    )))
}

#[cfg(test)]
pub(crate) fn bundle_acceptance_audit(acceptance: &PendingBundleAcceptance) -> ConfigAuditEvent {
    bundle_acceptance_audit_for_action(acceptance, "boot", None)
}

#[cfg(test)]
pub(crate) fn governed_bundle_acceptance_audit(
    acceptance: &PendingBundleAcceptance,
    intent: &registry_platform_ops::AcceptanceAuditIntentV1,
) -> Result<ConfigAuditEvent, Box<dyn std::error::Error>> {
    ensure_acceptance_audit_matches_plan(acceptance, intent)?;
    let audit_evidence = GovernedAcceptanceAuditEvidence::from_intent(intent);
    Ok(bundle_acceptance_audit_for_action(
        acceptance,
        "initialize_state",
        Some(&audit_evidence),
    ))
}

fn bundle_acceptance_audit_for_action(
    acceptance: &PendingBundleAcceptance,
    action: &str,
    governed_evidence: Option<&GovernedAcceptanceAuditEvidence>,
) -> ConfigAuditEvent {
    ConfigAuditEvent {
        action: action.to_string(),
        source: acceptance.source.as_posture_str().to_string(),
        acceptance_identity: governed_evidence.map(|evidence| evidence.acceptance_identity.clone()),
        bundle_id: acceptance.bundle_id.clone(),
        bundle_manifest_hash: governed_evidence
            .map(|evidence| evidence.bundle_manifest_hash.clone()),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        anchor_digest: governed_evidence.map(|evidence| evidence.anchor_digest.clone()),
        anchor_version: governed_evidence.map(|evidence| evidence.anchor_version),
        product_validation_result: "accepted".to_string(),
        apply_result: "pending".to_string(),
        posture_result: "accepted".to_string(),
        applied: false,
        restart_required: false,
        change_classes: Vec::new(),
        break_glass: acceptance.break_glass,
        break_glass_approval_reference: None,
        break_glass_approved_by: None,
        break_glass_reason_hash: None,
        break_glass_emergency_change_class: None,
        break_glass_expires_at_unix_seconds: None,
        break_glass_rate_limit_identity: None,
        local_approval_reference: None,
        local_approval_approved_by: None,
        local_approval_reason_hash: None,
        local_approval_change_class: None,
        local_approval_expires_at_unix_seconds: None,
        local_approval_rate_limit_identity: None,
    }
}

pub(crate) async fn emit_boot_config_audits(
    runtime: &registry_notary_server::NotaryRuntimeSnapshot,
    acceptance: &PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error>> {
    emit_boot_config_audits_for_action(runtime, acceptance, "boot", None).await
}

async fn emit_boot_config_audits_for_action(
    runtime: &registry_notary_server::NotaryRuntimeSnapshot,
    acceptance: &PendingBundleAcceptance,
    action: &str,
    governed_evidence: Option<&GovernedAcceptanceAuditEvidence>,
) -> Result<(), Box<dyn std::error::Error>> {
    if acceptance.emits_break_glass_used_audit() {
        runtime
            .emit_config_boot_audit(
                "config.break_glass_used",
                break_glass_used_audit(acceptance)?,
            )
            .await?;
    }
    if acceptance.source == ConfigSource::SignedBundleFile {
        runtime
            .emit_config_boot_audit(
                "config.bundle_accepted",
                bundle_acceptance_audit_for_action(acceptance, action, governed_evidence),
            )
            .await?;
    }
    Ok(())
}

pub(crate) fn break_glass_used_audit(
    acceptance: &PendingBundleAcceptance,
) -> Result<ConfigAuditEvent, Box<dyn std::error::Error>> {
    let pin = acceptance
        .override_pin
        .as_ref()
        .ok_or("break-glass acceptance is missing override pin")?;
    Ok(ConfigAuditEvent {
        action: "boot".to_string(),
        source: acceptance.source.as_posture_str().to_string(),
        acceptance_identity: None,
        bundle_id: acceptance.bundle_id.clone(),
        bundle_manifest_hash: None,
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        anchor_digest: None,
        anchor_version: None,
        product_validation_result: "accepted".to_string(),
        apply_result: "applied".to_string(),
        posture_result: "accepted".to_string(),
        applied: true,
        restart_required: false,
        change_classes: Vec::new(),
        break_glass: true,
        break_glass_approval_reference: None,
        break_glass_approved_by: Some(pin.operator.clone()),
        break_glass_reason_hash: Some(sha256_hash(&pin.reason)),
        break_glass_emergency_change_class: Some(match pin.mode {
            ConfigOverrideMode::AcceptRollback => "accept_rollback".to_string(),
            ConfigOverrideMode::AcceptUnsigned => "accept_unsigned".to_string(),
        }),
        break_glass_expires_at_unix_seconds: pin.expires_at.as_deref().and_then(rfc3339_unix),
        break_glass_rate_limit_identity: None,
        local_approval_reference: None,
        local_approval_approved_by: None,
        local_approval_reason_hash: None,
        local_approval_change_class: None,
        local_approval_expires_at_unix_seconds: None,
        local_approval_rate_limit_identity: None,
    })
}

pub(crate) fn rfc3339_unix(value: &str) -> Option<u64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
}

pub(crate) fn persist_bundle_acceptance(
    acceptance: &PendingBundleAcceptance,
) -> Result<(), Box<dyn std::error::Error>> {
    persist_config_bundle_acceptance(acceptance)?;
    Ok(())
}

pub(crate) fn persist_after_successful_boot_audit(
    acceptance: &PendingBundleAcceptance,
    audit_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    audit_result?;
    persist_bundle_acceptance(acceptance)
}

pub(crate) async fn emit_and_persist_boot_acceptance(
    runtime: &registry_notary_server::NotaryRuntimeSnapshot,
    acceptance: Option<&PendingBundleAcceptance>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(acceptance) = acceptance else {
        return Ok(());
    };
    let audit_result = emit_boot_config_audits(runtime, acceptance).await;
    persist_after_successful_boot_audit(acceptance, audit_result)
}

pub(crate) async fn shutdown_when_signaled(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    let _ = shutdown_rx.wait_for(|shutdown| *shutdown).await;
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
#[cfg(test)]
#[path = "boot/tests.rs"]
mod tests;
