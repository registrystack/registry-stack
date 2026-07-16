use crate::*;

pub(crate) async fn run_server(
    config_path: &Path,
    bind_override: Option<SocketAddr>,
    initialize_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing()?;

    let loaded = load_server_config(config_path, initialize_state)?;
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
    )?
    .activate()
    .await?;
    match admin_mode {
        RegistryNotaryAdminListenerMode::Dedicated => {
            let public_listener = tokio::net::TcpListener::bind(bind).await?;
            let public_addr: SocketAddr = public_listener.local_addr()?;
            let admin_listener = tokio::net::TcpListener::bind(admin_bind).await?;
            let admin_addr: SocketAddr = admin_listener.local_addr()?;
            emit_and_persist_boot_acceptance(&runtime, loaded.pending_bundle_acceptance.as_ref())
                .await?;
            let routers = notary_routers_from_runtime(runtime)?;
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
            emit_and_persist_boot_acceptance(&runtime, loaded.pending_bundle_acceptance.as_ref())
                .await?;
            let app = notary_shared_router_from_runtime(runtime)?
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
            emit_and_persist_boot_acceptance(&runtime, loaded.pending_bundle_acceptance.as_ref())
                .await?;
            let app = notary_routers_from_runtime(runtime)?
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

pub(crate) fn bundle_acceptance_audit(acceptance: &PendingBundleAcceptance) -> ConfigAuditEvent {
    ConfigAuditEvent {
        action: "boot".to_string(),
        source: acceptance.source.as_posture_str().to_string(),
        bundle_id: acceptance.bundle_id.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
        product_validation_result: "accepted".to_string(),
        apply_result: "applied".to_string(),
        posture_result: "accepted".to_string(),
        applied: true,
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
                bundle_acceptance_audit(acceptance),
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
        bundle_id: acceptance.bundle_id.clone(),
        sequence: acceptance.sequence,
        signer_kids: acceptance.signer_kids.clone(),
        previous_config_hash: acceptance.previous_config_hash.clone(),
        previous_hash_matched: acceptance.previous_hash_matched,
        config_hash: Some(acceptance.config_hash.clone()),
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
