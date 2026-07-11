// SPDX-License-Identifier: Apache-2.0
//! Administrative handlers and posture response helpers.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct ConfigApplyPosture {
    pub(crate) source: ConfigSource,
    pub(crate) last_config_hash: Option<String>,
    pub(crate) last_bundle_id: Option<String>,
    pub(crate) last_bundle_sequence: Option<u64>,
    pub(crate) last_bundle_signer_kids: Vec<String>,
    pub(crate) override_pin: Option<ConfigOverridePin>,
    pub(crate) last_apply_result: Option<PostureApplyResult>,
    pub(crate) last_apply_at: Option<String>,
    pub(crate) restart_required: bool,
    pub(crate) emergency: Option<ConfigEmergencyPosture>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConfigEmergencyPosture {
    pub(crate) last_emergency_sequence: u64,
    pub(crate) last_emergency_change_class: String,
    pub(crate) last_emergency_at: Option<String>,
    pub(crate) accepted_expires_at_unix_seconds: Vec<u64>,
}

impl Default for ConfigApplyPosture {
    fn default() -> Self {
        Self {
            source: ConfigSource::LocalFile,
            last_config_hash: None,
            last_bundle_id: None,
            last_bundle_sequence: None,
            last_bundle_signer_kids: Vec::new(),
            override_pin: None,
            last_apply_result: None,
            last_apply_at: None,
            restart_required: false,
            emergency: None,
        }
    }
}

impl ConfigApplyPosture {
    pub(crate) fn from_provenance(provenance: ConfigProvenance) -> Self {
        Self {
            source: provenance.source,
            last_config_hash: Some(provenance.internal_config_hash),
            last_bundle_id: provenance.last_bundle_id,
            last_bundle_sequence: provenance.last_bundle_sequence,
            last_bundle_signer_kids: provenance.last_bundle_signer_kids,
            override_pin: provenance.override_pin,
            last_apply_result: provenance.last_apply_result,
            last_apply_at: provenance.last_apply_at,
            restart_required: provenance.restart_required,
            emergency: None,
        }
    }
}
pub(super) async fn admin_reload(principal: Option<Extension<EvidencePrincipal>>) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(ADMIN_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: ADMIN_SCOPE.to_string(),
        });
    }
    admin_problem_response(
        StatusCode::NOT_IMPLEMENTED,
        ADMIN_CAPABILITY_NOT_SUPPORTED_CODE,
        "Admin capability not supported",
        "registry-notary standalone runtime does not support reload",
        Some("reload.config_reload"),
    )
}

pub(super) async fn admin_capabilities(
    principal: Option<Extension<EvidencePrincipal>>,
    Extension(state): Extension<Arc<RegistryNotaryApiState>>,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(OPS_READ_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: OPS_READ_SCOPE.to_string(),
        });
    }
    let listeners = admin_capabilities_listeners(state.runtime_config().as_deref());
    let mut response = Json(json!({
        "schema": "registry.admin.capabilities.v1",
        "product": "registry-notary",
        "admin_api_version": "v1",
        "supported_posture_tiers": ["default", "restricted"],
        "config": {
            "verify": {
                "supported": false,
                "currently_available": false
            },
            "dry_run": {
                "supported": false,
                "currently_available": false
            },
            "apply": {
                "supported": false,
                "currently_available": false,
                "supported_sources": [],
                "requires_signed_input": true
            }
        },
        "break_glass": {
            "supported": false,
            "currently_available": false,
            "rate_limit_scope": "none"
        },
        "listeners": listeners,
        "root_transition": {
            "supported": false,
            "currently_available": false
        },
        "hot_swap": {
            "supported": false,
            "currently_available": false,
            "components": []
        },
        "reload": {
            "resource_reload": {
                "supported": false,
                "currently_available": false
            },
            "table_reload": {
                "supported": false,
                "currently_available": false
            },
            "config_reload": {
                "supported": false,
                "currently_available": false
            }
        }
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) fn admin_capabilities_listeners(
    config: Option<&StandaloneRegistryNotaryConfig>,
) -> Value {
    let mode = config
        .map(|config| config.server.admin_listener.mode)
        .unwrap_or(RegistryNotaryAdminListenerMode::SharedWithPublic);
    match mode {
        RegistryNotaryAdminListenerMode::Dedicated => json!({
            "admin": {
                "mode": "dedicated",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "admin",
                "requires_admin_scope": false,
                "required_scope": METRICS_SCOPE
            }
        }),
        RegistryNotaryAdminListenerMode::SharedWithPublic => json!({
            "admin": {
                "mode": "shared_with_public",
                "public_admin_routes": true
            },
            "metrics": {
                "mode": "shared_with_public",
                "requires_admin_scope": false,
                "required_scope": METRICS_SCOPE
            }
        }),
        RegistryNotaryAdminListenerMode::Disabled => json!({
            "admin": {
                "mode": "disabled",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "disabled",
                "requires_admin_scope": false,
                "required_scope": METRICS_SCOPE
            }
        }),
    }
}

pub(super) async fn admin_posture(
    Query(query): Query<PostureQuery>,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(OPS_READ_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: OPS_READ_SCOPE.to_string(),
        });
    }
    let Some(Extension(state)) = state else {
        return posture_unavailable();
    };
    let tier = match query.tier.as_deref() {
        Some("restricted") => registry_platform_ops::PostureTier::Restricted,
        Some("default") | None => registry_platform_ops::PostureTier::Default,
        Some(_) => {
            return admin_problem_response(
                StatusCode::BAD_REQUEST,
                POSTURE_TIER_INVALID_CODE,
                "Admin posture tier invalid",
                "posture tier must be default or restricted",
                None,
            )
        }
    };
    match posture_document(&state, tier).await {
        Ok(posture) => Json(posture).into_response(),
        Err(error) => posture_filter_failed(error),
    }
}

pub(super) fn admin_problem_response(
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    detail: &'static str,
    capability: Option<&'static str>,
) -> Response {
    let mut body = json!({
        "schema": "registry.admin.error.v1",
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": title,
        "status": status.as_u16(),
        "code": code,
        "message": detail,
        "detail": detail,
    });
    if let Some(capability) = capability {
        body["capability"] = json!(capability);
    }
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

/// Service-unavailable problem for the admin posture endpoint when shared
/// server state is not installed. Mirrors the other admin posture problems so
/// the body shape and `application/problem+json` media type stay consistent.
pub(super) fn posture_unavailable() -> Response {
    admin_problem_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "posture.unavailable",
        "Admin posture unavailable",
        "posture state is unavailable",
        None,
    )
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct PostureQuery {
    pub(super) tier: Option<String>,
}
pub(super) fn posture_filter_failed(error: PostureDocumentError) -> Response {
    let detail = match &error {
        PostureDocumentError::Filter(filter_error) => {
            tracing::error!(error = %filter_error, "failed to filter admin posture");
            "admin posture could not be filtered for the requested tier"
        }
        PostureDocumentError::SigningKey(signing_key_error) => {
            tracing::error!(
                key_id = signing_key_error.key_id(),
                "failed to project signing key posture"
            );
            "admin posture contains an unsupported signing key status"
        }
    };
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}/posture/filter_failed", crate::PROBLEM_TYPE_BASE_URL),
            "title": "Admin posture unavailable",
            "status": status.as_u16(),
            "detail": detail,
            "code": POSTURE_FILTER_FAILED_CODE,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response.extensions_mut().insert(EvidenceErrorCodeContext(
        POSTURE_FILTER_FAILED_CODE.to_string(),
    ));
    response
}
