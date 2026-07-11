// SPDX-License-Identifier: Apache-2.0
//! Health and readiness probe handlers.

use super::*;

pub(super) async fn healthz() -> Response {
    Json(json!({
        "status": "ok",
        "checks": {
            "total": 1,
            "ok": 1,
            "failed": 0,
        },
    }))
    .into_response()
}

pub(super) async fn ready(state: Option<Extension<Arc<RegistryNotaryApiState>>>) -> Response {
    let (base_ready, base_degraded, signer_total, signer_ok, signer_failed) = match state.as_ref() {
        Some(Extension(state)) if state.enabled_evidence().is_ok() => {
            let replay_readiness = state.replay.check_ready().await;
            let credential_status_ready = state.credential_status.check_ready().await.is_ok();
            let replay_ready = matches!(replay_readiness, Ok(ReplayReadiness::Ready));
            let signer_readiness = state.signer_readiness();
            let signer_ready = signer_readiness.is_ready();
            let degraded = matches!(replay_readiness, Ok(ReplayReadiness::Degraded))
                && credential_status_ready
                && signer_ready;
            (
                replay_ready && credential_status_ready && signer_ready && !degraded,
                degraded,
                signer_readiness.total(),
                signer_readiness.ready_count(),
                signer_readiness.failed_count(),
            )
        }
        _ => (false, false, 0, 0, 0),
    };
    let degraded = usize::from(base_degraded);
    let current_deployment_gates = match state.as_ref() {
        Some(Extension(state)) => Some(state.current_deployment_gates().await),
        None => None,
    };
    #[cfg(feature = "registry-notary-cel")]
    let (total, ok, failed) = {
        let mut total = 1 + signer_total;
        let mut ok = usize::from(base_ready) + signer_ok;
        let mut failed = usize::from(!base_ready && !base_degraded) + signer_failed;
        if let Some(Extension(state)) = state.as_ref() {
            if state.source.has_readiness_check() {
                total += 1;
                if state.source.check_ready().await {
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
            if let Some(cel_worker) = &state.cel_worker {
                total += 1;
                if cel_worker.check_ready().await {
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
            if let Some(gates) = current_deployment_gates
                .as_ref()
                .filter(|gates| gates.is_bound())
            {
                total += 1;
                if gates.has_readiness_failure() {
                    failed += 1;
                } else {
                    ok += 1;
                }
            }
        }
        (total, ok, failed)
    };
    #[cfg(not(feature = "registry-notary-cel"))]
    let (total, ok, failed) = {
        let mut total = 1 + signer_total;
        let mut ok = usize::from(base_ready) + signer_ok;
        let mut failed = usize::from(!base_ready && !base_degraded) + signer_failed;
        if let Some(Extension(state)) = state.as_ref() {
            if state.source.has_readiness_check() {
                total += 1;
                if state.source.check_ready().await {
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
            if let Some(gates) = current_deployment_gates
                .as_ref()
                .filter(|gates| gates.is_bound())
            {
                total += 1;
                if gates.has_readiness_failure() {
                    failed += 1;
                } else {
                    ok += 1;
                }
            }
        }
        (total, ok, failed)
    };

    let ready = ok == total;
    let is_degraded = !ready && failed == 0 && degraded > 0;
    let state_ref = state.as_ref().map(|Extension(state)| state.as_ref());
    let signer_custody = state_ref
        .map(signer_custody_checks)
        .unwrap_or_else(default_signer_custody_checks);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status_text = match (ready, is_degraded) {
        (true, _) => KeyReadiness::Ready,
        (false, true) => KeyReadiness::Degraded,
        (false, false) => KeyReadiness::NotReady,
    };
    let checks = json!({
        "total": total,
        "ok": ok,
        "degraded": degraded,
        "failed": failed,
        "signing_providers": {
            "total": signer_total,
            "ok": signer_ok,
            "failed": signer_failed,
            "custody": signer_custody,
        },
    });
    if ready {
        return Json(json!({
            "status": status_text.as_str(),
            "checks": checks,
        }))
        .into_response();
    }

    let request_id = crate::standalone::current_request_correlation_id()
        .unwrap_or_else(crate::standalone::new_request_correlation_id);
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}/readiness/not-ready", crate::PROBLEM_TYPE_BASE_URL),
            "title": "Evidence runtime is not ready",
            "status": status.as_u16(),
            "detail": "one or more readiness checks are not ready",
            "code": "readiness.not_ready",
            "request_id": request_id.as_str(),
            "readiness_status": status_text.as_str(),
            "checks": checks,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/problem+json".parse().unwrap(),
    );
    response.headers_mut().insert(
        "x-request-id",
        request_id
            .as_str()
            .parse()
            .expect("bounded correlation id is a valid header value"),
    );
    response
}

pub(super) fn signer_custody_checks(state: &RegistryNotaryApiState) -> Value {
    let signer_readiness = state.signer_readiness();
    let provider_counts = signer_readiness.provider_counts();
    let config = state.runtime_config();
    let custody_approved = config
        .as_deref()
        .is_some_and(|config| config.deployment.evidence.signer_custody_approved);
    let approval_required = config
        .as_deref()
        .is_some_and(signer_custody_approval_required);
    let scoped = config
        .as_deref()
        .map(custody_scoped_signer_counts)
        .unwrap_or_default();
    let credential_issuance = config
        .as_deref()
        .map(credential_issuance_signer_counts)
        .unwrap_or_default();
    let access_token_issuance = config
        .as_deref()
        .map(access_token_issuance_signer_counts)
        .unwrap_or_default();
    let access_token_issuance_enabled = config
        .as_deref()
        .is_some_and(|config| config.auth.access_token_signing.enabled);
    let federation = config
        .as_deref()
        .map(federation_signer_counts)
        .unwrap_or_default();
    let federation_enabled = config
        .as_deref()
        .is_some_and(|config| config.federation.enabled);

    json!({
        "active_provider_counts": provider_counts,
        "signing_provider_count": scoped.total,
        "local_software_signing_provider_count": scoped.local_software,
        "custody_approval_required": approval_required,
        "custody_approved": custody_approved,
        "unapproved_signing_provider_count": unapproved_signer_count(
            scoped.total,
            custody_approved,
        ),
        "surfaces": {
            "credential_issuance": signer_surface_checks(
                credential_issuance,
                custody_approved,
            ),
            "access_token_issuance": signer_surface_checks_with_enabled(
                access_token_issuance_enabled,
                access_token_issuance,
                custody_approved,
            ),
            "federation": {
                "enabled": federation_enabled,
                "signing_provider_count": federation.total,
                "local_software_signing_provider_count": federation.local_software,
                "unapproved_signing_provider_count": unapproved_signer_count(
                    federation.total,
                    custody_approved,
                ),
            },
        },
    })
}

pub(super) fn default_signer_custody_checks() -> Value {
    json!({
        "active_provider_counts": {},
        "signing_provider_count": 0,
        "local_software_signing_provider_count": 0,
        "custody_approval_required": false,
        "custody_approved": false,
        "unapproved_signing_provider_count": 0,
        "surfaces": {
            "credential_issuance": {
                "signing_provider_count": 0,
                "local_software_signing_provider_count": 0,
                "unapproved_signing_provider_count": 0,
            },
            "access_token_issuance": {
                "enabled": false,
                "signing_provider_count": 0,
                "local_software_signing_provider_count": 0,
                "unapproved_signing_provider_count": 0,
            },
            "federation": {
                "enabled": false,
                "signing_provider_count": 0,
                "local_software_signing_provider_count": 0,
                "unapproved_signing_provider_count": 0,
            },
        },
    })
}

#[derive(Clone, Copy, Default)]
pub(super) struct SignerCounts {
    pub(super) total: usize,
    pub(super) local_software: usize,
}

pub(super) fn signer_custody_approval_required(config: &StandaloneRegistryNotaryConfig) -> bool {
    matches!(
        config.deployment.profile,
        Some(DeploymentProfile::Production | DeploymentProfile::EvidenceGrade)
    )
}

pub(super) fn custody_scoped_signer_counts(
    config: &StandaloneRegistryNotaryConfig,
) -> SignerCounts {
    signing_key_counts(config, config.custody_scoped_signing_key_ids())
}

pub(super) fn credential_issuance_signer_counts(
    config: &StandaloneRegistryNotaryConfig,
) -> SignerCounts {
    signing_key_counts(
        config,
        config
            .evidence
            .credential_profiles
            .values()
            .map(|profile| profile.signing_key.as_str()),
    )
}

pub(super) fn access_token_issuance_signer_counts(
    config: &StandaloneRegistryNotaryConfig,
) -> SignerCounts {
    if !config.auth.access_token_signing.enabled {
        return SignerCounts::default();
    }
    signing_key_counts(
        config,
        [config.auth.access_token_signing.signing_key_id.as_str()],
    )
}

pub(super) fn federation_signer_counts(config: &StandaloneRegistryNotaryConfig) -> SignerCounts {
    if !config.federation.enabled {
        return SignerCounts::default();
    }
    signing_key_counts(config, [config.federation.signing.signing_key.as_str()])
}

pub(super) fn signing_key_counts<'a>(
    config: &StandaloneRegistryNotaryConfig,
    key_ids: impl IntoIterator<Item = &'a str>,
) -> SignerCounts {
    let mut counts = SignerCounts::default();
    for key_id in key_ids.into_iter().collect::<BTreeSet<_>>() {
        let Some(key) = config
            .evidence
            .signing_keys
            .get(key_id)
            .filter(|key| key.status.may_sign())
        else {
            continue;
        };
        counts.total += 1;
        counts.local_software += usize::from(signing_key_uses_local_software_custody(key));
    }
    counts
}

pub(super) fn signer_surface_checks(counts: SignerCounts, custody_approved: bool) -> Value {
    json!({
        "signing_provider_count": counts.total,
        "local_software_signing_provider_count": counts.local_software,
        "unapproved_signing_provider_count": unapproved_signer_count(
            counts.total,
            custody_approved,
        ),
    })
}

pub(super) fn signer_surface_checks_with_enabled(
    enabled: bool,
    counts: SignerCounts,
    custody_approved: bool,
) -> Value {
    let mut checks = signer_surface_checks(counts, custody_approved);
    checks["enabled"] = json!(enabled);
    checks
}

pub(super) const fn unapproved_signer_count(count: usize, custody_approved: bool) -> usize {
    if custody_approved {
        0
    } else {
        count
    }
}
