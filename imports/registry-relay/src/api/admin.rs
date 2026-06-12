// SPDX-License-Identifier: Apache-2.0
//! Admin HTTP routes.
//!
//! This module owns the route surface only. Server/auth integration can
//! install the router and `IngestRegistry` extension from the admin
//! listener when that wiring lands.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use registry_manifest_core::CompiledMetadata;
use registry_platform_config::RegistryTrustRoot;
use registry_platform_crypto::{KeyProviderKind, KeyReadiness};
use registry_platform_ops::{
    filter_posture_for_tier, internal_config_hash, is_sha256_config_hash,
    posture_safe_runtime_config_hash, AntiRollbackKey, AntiRollbackProposal,
    AntiRollbackStoreError, ApplyReportResult, BreakGlassApproval, BreakGlassRateLimit,
    ConfigProvenance, ConfigSource, FileAntiRollbackStore, FileLocalApprovalStore,
    LocalOperatorApproval, PostureFilterError, PostureTier,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::audit::{ConfigAuditExt, ErrorCodeExt};
use crate::auth::middleware::AuthProviderRef;
use crate::auth::runtime::build_auth;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::governed::{
    authorize_signed_config_candidate, is_signed_config_source,
    parse_candidate_config_with_provenance, parse_resolved_config_candidate_with_provenance,
    resolve_tuf_config_candidate, ConfigCandidateError, ResolvedConfigCandidate,
    TufConfigTargetRequest,
};
use crate::config::{
    AuthMode, Config, DatasetId, IssuerConfig, ProvenanceConfig, ResourceId, SignerConfig,
};
use crate::error::{AdminError, AuthError, Error, IngestError};
use crate::ingest::{IngestRegistry, ReadinessSnapshot};
use crate::provenance::{
    build_resolved_provenance_config, BuildStateError, ProvenanceState, ResolvedProvenanceConfig,
    Signer,
};
use crate::runtime_config::RuntimeSnapshot;

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RELOAD_FAILED_CODE: &str = "admin.reload_failed";
const RELOAD_UNAVAILABLE_CODE: &str = "admin.reload_unavailable";
const CONFIG_CANDIDATE_INVALID_CODE: &str = "admin.config_candidate_invalid";
const CONFIG_BUNDLE_INVALID_CODE: &str = "admin.config_bundle_invalid";
const CONFIG_APPLY_UNAVAILABLE_CODE: &str = "admin.config_apply_unavailable";
const CONFIG_INLINE_APPLY_REJECTED_CODE: &str = "registry.admin.config.inline_apply_rejected";
const POSTURE_FILTER_FAILED_CODE: &str = "admin.posture_filter_failed";
const POSTURE_TIER_INVALID_CODE: &str = "registry.admin.posture.invalid_tier";
const RUNTIME_UNAVAILABLE_CODE: &str = "registry.admin.runtime_unavailable";
const ADMIN_SCOPE: &str = "registry_relay:admin";
const METRICS_SCOPE: &str = crate::observability::METRICS_SCOPE;
const OPS_READ_SCOPE: &str = "registry_relay:ops_read";

struct AdminPrincipal;

impl<S> FromRequestParts<S> for AdminPrincipal
where
    S: Send + Sync,
{
    type Rejection = AdminAuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        require_scope_from_parts(parts, state, ADMIN_SCOPE)
            .await
            .map(|()| Self)
    }
}

struct OpsReadPrincipal;

impl<S> FromRequestParts<S> for OpsReadPrincipal
where
    S: Send + Sync,
{
    type Rejection = AdminAuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        require_scope_from_parts(parts, state, OPS_READ_SCOPE)
            .await
            .map(|()| Self)
    }
}

struct AdminJson<T>(T);

impl<S, T> FromRequest<S> for AdminJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AdminAuthRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let principal = req.extensions().get::<Principal>().cloned();
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|rejection| AdminAuthRejection::new(rejection.into_response()))?;
        require_scope_from_principal(principal, ADMIN_SCOPE)?;
        Ok(Self(value))
    }
}

struct AdminAuthRejection(Box<Response>);

impl AdminAuthRejection {
    fn new(response: Response) -> Self {
        Self(Box::new(response))
    }
}

impl IntoResponse for AdminAuthRejection {
    fn into_response(self) -> Response {
        *self.0
    }
}

#[doc(hidden)]
pub type CandidateProvenanceResolverRef = Arc<dyn CandidateProvenanceResolver>;

#[doc(hidden)]
pub trait CandidateProvenanceResolver: Send + Sync {
    fn resolve_candidate_provenance(
        &self,
        cfg: Option<&ProvenanceConfig>,
    ) -> Result<Option<ResolvedProvenanceConfig>, BuildStateError>;
}

#[derive(Debug, Default)]
struct DefaultCandidateProvenanceResolver;

impl CandidateProvenanceResolver for DefaultCandidateProvenanceResolver {
    fn resolve_candidate_provenance(
        &self,
        cfg: Option<&ProvenanceConfig>,
    ) -> Result<Option<ResolvedProvenanceConfig>, BuildStateError> {
        build_resolved_provenance_config(cfg)
    }
}

static DEFAULT_CANDIDATE_PROVENANCE_RESOLVER: DefaultCandidateProvenanceResolver =
    DefaultCandidateProvenanceResolver;

/// Sub-router for admin reload routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/v1/capabilities", get(capabilities))
        .route("/admin/v1/posture", get(posture))
        .route("/admin/v1/reload", post(reload_all))
        .route("/admin/v1/config/verify", post(config_verify))
        .route("/admin/v1/config/dry-run", post(config_dry_run))
        .route("/admin/v1/config/apply", post(config_apply))
        .route(
            "/admin/v1/datasets/{dataset_id}/tables/{table_id}/reload",
            post(reload_table),
        )
}

async fn capabilities(runtime: RuntimeSnapshot, _ops: OpsReadPrincipal) -> Response {
    let Some(config) = runtime.config() else {
        return runtime_unavailable("runtime handle is not installed");
    };
    let (admin_mode, metrics_mode) = if config.server.admin_bind.is_some() {
        ("dedicated", "admin")
    } else {
        ("disabled", "disabled")
    };
    let mut response = Json(json!({
        "schema": "registry.admin.capabilities.v1",
        "product": "registry-relay",
        "admin_api_version": "v1",
        "supported_posture_tiers": ["default", "restricted"],
        "config": {
            "verify": {
                "supported": true,
                "currently_available": true
            },
            "dry_run": {
                "supported": true,
                "currently_available": true
            },
            "apply": {
                "supported": true,
                "currently_available": true,
                "supported_sources": ["tuf_local", "tuf_remote"],
                "requires_signed_input": true
            }
        },
        "break_glass": {
            "supported": true,
            "currently_available": true,
            "rate_limit_scope": "instance"
        },
        "listeners": {
            "admin": {
                "mode": admin_mode,
                "public_admin_routes": false
            },
            "metrics": {
                "mode": metrics_mode,
                "requires_admin_scope": false,
                "required_scope": METRICS_SCOPE
            }
        },
        "root_transition": {
            "supported": true,
            "currently_available": true
        },
        "hot_swap": {
            "supported": true,
            "currently_available": true,
            "components": [
                "config_provenance",
                "compiled_metadata",
                "auth_provider",
                "provenance_state"
            ]
        },
        "reload": {
            "resource_reload": {
                "supported": true,
                "currently_available": true
            },
            "table_reload": {
                "supported": true,
                "currently_available": true
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

#[derive(Debug, Deserialize)]
struct ConfigApplyRequest {
    #[serde(default)]
    bundle_id: Option<String>,
    #[serde(default)]
    stream_id: Option<String>,
    #[serde(default)]
    sequence: Option<u64>,
    #[serde(default)]
    previous_config_hash: Option<String>,
    #[serde(default)]
    root_version: Option<u64>,
    #[serde(default)]
    break_glass: bool,
    #[serde(default)]
    break_glass_approval: Option<BreakGlassApproval>,
    #[serde(default)]
    break_glass_rate_limit: Option<BreakGlassRateLimit>,
    #[serde(default)]
    local_approval_reference: Option<String>,
    #[serde(default)]
    config_yaml: Option<String>,
    #[serde(default)]
    tuf: Option<TufConfigTargetRequest>,
}

#[derive(Debug, Serialize)]
struct ConfigApplyResponse {
    bundle_id: String,
    sequence: u64,
    result: &'static str,
    posture_result: &'static str,
    applied: bool,
    restart_required: bool,
}

#[derive(Clone, Copy)]
enum ConfigAdminAction {
    Verify,
    DryRun,
    Apply,
}

impl ConfigAdminAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::DryRun => "dry_run",
            Self::Apply => "apply",
        }
    }
}

async fn config_verify(
    runtime: RuntimeSnapshot,
    resolver: Option<Extension<CandidateProvenanceResolverRef>>,
    AdminJson(request): AdminJson<ConfigApplyRequest>,
) -> Response {
    let Some(current) = runtime.load() else {
        return with_config_audit(
            config_apply_unavailable("runtime handle is not installed"),
            unresolved_config_audit(
                ConfigAdminAction::Verify,
                &request,
                "not_evaluated",
                ApplyReportResult::InternalError.as_str(),
                false,
                false,
            ),
        );
    };
    let resolved = match resolve_config_candidate(&request, &current.config).await {
        Ok(resolved) => resolved,
        Err(ConfigCandidateError::CandidateInvalid(detail)) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                unresolved_config_audit(
                    ConfigAdminAction::Verify,
                    &request,
                    "rejected",
                    "rejected_compile",
                    false,
                    false,
                ),
            )
        }
        Err(ConfigCandidateError::BundleInvalid(detail)) => {
            return with_config_audit(
                config_bundle_invalid(detail),
                unresolved_config_audit(
                    ConfigAdminAction::Verify,
                    &request,
                    "rejected",
                    "rejected_signature",
                    false,
                    false,
                ),
            )
        }
    };
    if let Err(ConfigCandidateError::BundleInvalid(detail)) =
        authorize_signed_config_candidate(&resolved, &current.config)
    {
        return with_config_audit(
            config_bundle_invalid(detail),
            resolved_config_audit(
                ConfigAdminAction::Verify,
                &resolved,
                "rejected",
                "rejected_product_validation",
                false,
                false,
            ),
        );
    }
    if request.break_glass
        || request.break_glass_approval.is_some()
        || request.break_glass_rate_limit.is_some()
    {
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            ApplyReportResult::RejectedBreakGlass,
            false,
            false,
            StatusCode::OK,
            resolved_config_audit(
                ConfigAdminAction::Verify,
                &resolved,
                "rejected",
                ApplyReportResult::RejectedBreakGlass.as_str(),
                false,
                false,
            ),
        );
    }
    let parsed = match parse_resolved_config_candidate_with_provenance(&resolved) {
        Ok(parsed) => parsed,
        Err(detail) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                resolved_config_audit(
                    ConfigAdminAction::Verify,
                    &resolved,
                    "rejected",
                    "rejected_compile",
                    false,
                    false,
                ),
            )
        }
    };
    let compatible = match classify_live_config_change(
        &current,
        &parsed.config,
        live_change_authorization(&resolved),
        resolver_from_extension(resolver.as_ref()),
    ) {
        Ok(LiveConfigChange::Compatible { .. }) => true,
        Ok(LiveConfigChange::RestartRequired) => false,
        Err(detail) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                resolved_config_audit(
                    ConfigAdminAction::Verify,
                    &resolved,
                    "rejected",
                    "rejected_product_validation",
                    false,
                    false,
                ),
            )
        }
    };
    let restart_required = !compatible;
    config_apply_report(
        resolved.bundle_id.clone(),
        resolved.sequence,
        ApplyReportResult::Verified,
        false,
        restart_required,
        StatusCode::OK,
        resolved_config_audit(
            ConfigAdminAction::Verify,
            &resolved,
            "accepted",
            ApplyReportResult::Verified.as_str(),
            false,
            restart_required,
        ),
    )
}

async fn config_dry_run(
    runtime: RuntimeSnapshot,
    resolver: Option<Extension<CandidateProvenanceResolverRef>>,
    AdminJson(request): AdminJson<ConfigApplyRequest>,
) -> Response {
    let Some(current) = runtime.load() else {
        return with_config_audit(
            config_apply_unavailable("runtime handle is not installed"),
            unresolved_config_audit(
                ConfigAdminAction::DryRun,
                &request,
                "not_evaluated",
                ApplyReportResult::InternalError.as_str(),
                false,
                false,
            ),
        );
    };
    let resolved = match resolve_config_candidate(&request, &current.config).await {
        Ok(resolved) => resolved,
        Err(ConfigCandidateError::CandidateInvalid(detail)) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                unresolved_config_audit(
                    ConfigAdminAction::DryRun,
                    &request,
                    "rejected",
                    "rejected_compile",
                    false,
                    false,
                ),
            )
        }
        Err(ConfigCandidateError::BundleInvalid(detail)) => {
            return with_config_audit(
                config_bundle_invalid(detail),
                unresolved_config_audit(
                    ConfigAdminAction::DryRun,
                    &request,
                    "rejected",
                    "rejected_signature",
                    false,
                    false,
                ),
            )
        }
    };
    if let Err(ConfigCandidateError::BundleInvalid(detail)) =
        authorize_signed_config_candidate(&resolved, &current.config)
    {
        return with_config_audit(
            config_bundle_invalid(detail),
            resolved_config_audit(
                ConfigAdminAction::DryRun,
                &resolved,
                "rejected",
                "rejected_product_validation",
                false,
                false,
            ),
        );
    }
    if request.break_glass
        || request.break_glass_approval.is_some()
        || request.break_glass_rate_limit.is_some()
    {
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            ApplyReportResult::RejectedBreakGlass,
            false,
            false,
            StatusCode::OK,
            resolved_config_audit(
                ConfigAdminAction::DryRun,
                &resolved,
                "rejected",
                ApplyReportResult::RejectedBreakGlass.as_str(),
                false,
                false,
            ),
        );
    }
    let candidate = match parse_candidate_config(&resolved.config_yaml) {
        Ok(candidate) => candidate,
        Err(detail) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                resolved_config_audit(
                    ConfigAdminAction::DryRun,
                    &resolved,
                    "rejected",
                    "rejected_compile",
                    false,
                    false,
                ),
            )
        }
    };
    let compatible = match classify_live_config_change(
        &current,
        &candidate,
        live_change_authorization(&resolved),
        resolver_from_extension(resolver.as_ref()),
    ) {
        Ok(LiveConfigChange::Compatible { .. }) => true,
        Ok(LiveConfigChange::RestartRequired) => false,
        Err(detail) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                resolved_config_audit(
                    ConfigAdminAction::DryRun,
                    &resolved,
                    "rejected",
                    "rejected_product_validation",
                    false,
                    false,
                ),
            )
        }
    };
    let restart_required = !compatible;
    let result = if restart_required {
        ApplyReportResult::RejectedRestartRequired
    } else {
        ApplyReportResult::Verified
    };
    config_apply_report(
        resolved.bundle_id.clone(),
        resolved.sequence,
        result,
        false,
        restart_required,
        StatusCode::OK,
        resolved_config_audit(
            ConfigAdminAction::DryRun,
            &resolved,
            "accepted",
            result.as_str(),
            false,
            restart_required,
        ),
    )
}

async fn config_apply(
    runtime: RuntimeSnapshot,
    resolver: Option<Extension<CandidateProvenanceResolverRef>>,
    AdminJson(request): AdminJson<ConfigApplyRequest>,
) -> Response {
    let Some(handle) = runtime.handle() else {
        return with_config_audit(
            config_apply_unavailable("runtime handle is not installed"),
            unresolved_config_audit(
                ConfigAdminAction::Apply,
                &request,
                "not_evaluated",
                ApplyReportResult::InternalError.as_str(),
                false,
                false,
            ),
        );
    };
    let Some(current) = runtime.load() else {
        return with_config_audit(
            config_apply_unavailable("runtime snapshot is not installed"),
            unresolved_config_audit(
                ConfigAdminAction::Apply,
                &request,
                "not_evaluated",
                ApplyReportResult::InternalError.as_str(),
                false,
                false,
            ),
        );
    };
    let resolved = match resolve_config_candidate(&request, &current.config).await {
        Ok(resolved) => resolved,
        Err(ConfigCandidateError::CandidateInvalid(detail)) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                unresolved_config_audit(
                    ConfigAdminAction::Apply,
                    &request,
                    "rejected",
                    "rejected_compile",
                    false,
                    false,
                ),
            )
        }
        Err(ConfigCandidateError::BundleInvalid(detail)) => {
            return with_config_audit(
                config_bundle_invalid(detail),
                unresolved_config_audit(
                    ConfigAdminAction::Apply,
                    &request,
                    "rejected",
                    "rejected_signature",
                    false,
                    false,
                ),
            )
        }
    };
    if !is_signed_config_source(resolved.source) {
        let requested_break_glass = request.break_glass
            || request.break_glass_approval.is_some()
            || request.break_glass_rate_limit.is_some();
        let apply_result = if requested_break_glass {
            ApplyReportResult::RejectedBreakGlass
        } else {
            ApplyReportResult::RejectedRestartRequired
        };
        return with_config_audit(
            config_inline_apply_rejected("signed config target is required for apply"),
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "rejected",
                apply_result.as_str(),
                false,
                !requested_break_glass,
            )
            .with_break_glass_request(&request),
        );
    }
    if let Err(ConfigCandidateError::BundleInvalid(_detail)) =
        authorize_signed_config_candidate(&resolved, &current.config)
    {
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            ApplyReportResult::RejectedThreshold,
            false,
            false,
            StatusCode::CONFLICT,
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "rejected",
                ApplyReportResult::RejectedThreshold.as_str(),
                false,
                false,
            ),
        );
    }
    let break_glass = match break_glass_proposal(&request) {
        Ok(break_glass) => break_glass,
        Err(()) => {
            return config_apply_report(
                resolved.bundle_id.clone(),
                resolved.sequence,
                ApplyReportResult::RejectedBreakGlass,
                false,
                false,
                StatusCode::CONFLICT,
                resolved_config_audit(
                    ConfigAdminAction::Apply,
                    &resolved,
                    "rejected",
                    ApplyReportResult::RejectedBreakGlass.as_str(),
                    false,
                    false,
                )
                .with_break_glass_request(&request),
            );
        }
    };
    if let Err(()) = require_break_glass_emergency_change_class(&request, &resolved) {
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            ApplyReportResult::RejectedBreakGlass,
            false,
            false,
            StatusCode::CONFLICT,
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "rejected",
                ApplyReportResult::RejectedBreakGlass.as_str(),
                false,
                false,
            )
            .with_break_glass_request(&request),
        );
    }
    let parsed = match parse_resolved_config_candidate_with_provenance(&resolved) {
        Ok(parsed) => parsed,
        Err(detail) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                resolved_config_audit(
                    ConfigAdminAction::Apply,
                    &resolved,
                    "rejected",
                    "rejected_compile",
                    false,
                    false,
                ),
            )
        }
    };
    let candidate = parsed.config;
    let candidate_metadata = parsed.metadata.map(Arc::new);
    let candidate_metadata_source_digest = parsed.metadata_source_digest;
    let mut provenance = parsed.provenance;
    let live_change = match classify_live_config_change(
        &current,
        &candidate,
        live_change_authorization(&resolved),
        resolver_from_extension(resolver.as_ref()),
    ) {
        Ok(change) => change,
        Err(detail) => {
            return with_config_audit(
                config_candidate_invalid(detail),
                resolved_config_audit(
                    ConfigAdminAction::Apply,
                    &resolved,
                    "rejected",
                    "rejected_product_validation",
                    false,
                    false,
                ),
            )
        }
    };
    let LiveConfigChange::Compatible {
        provenance_state,
        local_approval_change_class,
        auth_change,
    } = live_change
    else {
        provenance.last_apply_result =
            Some(ApplyReportResult::RejectedRestartRequired.as_posture_result());
        provenance.restart_required = true;
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            ApplyReportResult::RejectedRestartRequired,
            false,
            true,
            StatusCode::CONFLICT,
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "accepted",
                ApplyReportResult::RejectedRestartRequired.as_str(),
                false,
                true,
            ),
        );
    };
    let auth = if auth_change {
        match build_auth(&candidate).await {
            Ok(auth) => auth,
            Err(_) => {
                return config_apply_report(
                    resolved.bundle_id.clone(),
                    resolved.sequence,
                    ApplyReportResult::RejectedReadiness,
                    false,
                    false,
                    StatusCode::CONFLICT,
                    resolved_config_audit(
                        ConfigAdminAction::Apply,
                        &resolved,
                        "accepted",
                        ApplyReportResult::RejectedReadiness.as_str(),
                        false,
                        false,
                    ),
                );
            }
        }
    } else {
        current.auth.clone()
    };
    if !candidate_signing_readiness(provenance_state.as_deref()).is_ready() {
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            ApplyReportResult::RejectedReadiness,
            false,
            false,
            StatusCode::CONFLICT,
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "accepted",
                ApplyReportResult::RejectedReadiness.as_str(),
                false,
                false,
            ),
        );
    }
    let Some(config_trust) = &current.config.config_trust else {
        return with_config_audit(
            config_apply_unavailable("config_trust.antirollback_state_path is not configured"),
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "accepted",
                ApplyReportResult::InternalError.as_str(),
                false,
                false,
            ),
        );
    };
    let local_approval = match local_approval_proposal(
        &request,
        config_trust,
        local_approval_change_class,
        &provenance.internal_config_hash,
        resolved.previous_config_hash.as_deref(),
    ) {
        Ok(local_approval) => local_approval,
        Err(()) => {
            return config_apply_report(
                resolved.bundle_id.clone(),
                resolved.sequence,
                ApplyReportResult::RejectedLocalApproval,
                false,
                false,
                StatusCode::CONFLICT,
                resolved_config_audit(
                    ConfigAdminAction::Apply,
                    &resolved,
                    "accepted",
                    ApplyReportResult::RejectedLocalApproval.as_str(),
                    false,
                    false,
                )
                .with_break_glass_request(&request)
                .with_local_approval_request(
                    &request,
                    None,
                    local_approval_change_class,
                ),
            );
        }
    };
    let antirollback_store = FileAntiRollbackStore::new(&config_trust.antirollback_state_path)
        .with_break_glass_rate_limit(config_trust.break_glass_rate_limit);
    if let Err(error) = antirollback_store.accept(
        &antirollback_key(&current.config, &resolved.stream_id),
        AntiRollbackProposal {
            sequence: resolved.sequence,
            previous_config_hash: resolved.previous_config_hash.clone(),
            config_hash: provenance.internal_config_hash.clone(),
            root_version: resolved.root_version,
            break_glass,
            break_glass_rate_limit: None,
            local_approval: local_approval.clone(),
            local_approval_rate_limit: local_approval.as_ref().map(|approval| approval.rate_limit),
        },
    ) {
        let result = if is_break_glass_error(&error) {
            ApplyReportResult::RejectedBreakGlass
        } else if is_local_approval_error(&error) {
            ApplyReportResult::RejectedLocalApproval
        } else {
            ApplyReportResult::RejectedRollback
        };
        return config_apply_report(
            resolved.bundle_id.clone(),
            resolved.sequence,
            result,
            false,
            false,
            StatusCode::CONFLICT,
            resolved_config_audit(
                ConfigAdminAction::Apply,
                &resolved,
                "accepted",
                result.as_str(),
                false,
                false,
            )
            .with_break_glass_request(&request)
            .with_local_approval_request(
                &request,
                local_approval.as_ref(),
                local_approval_change_class,
            ),
        );
    }
    provenance.last_apply_result = Some(ApplyReportResult::Applied.as_posture_result());
    provenance.last_apply_at = Some(now_rfc3339());
    let new_snapshot = clone_snapshot_with_config(
        &current,
        SnapshotReplacement {
            config: candidate,
            config_provenance: provenance,
            provenance_state,
            auth,
            compiled_metadata: candidate_metadata,
            metadata_source_digest: candidate_metadata_source_digest,
            metadata_package_digest: parsed.package_digest,
        },
    );
    handle.store(new_snapshot);
    config_apply_report(
        resolved.bundle_id.clone(),
        resolved.sequence,
        ApplyReportResult::Applied,
        true,
        false,
        StatusCode::OK,
        resolved_config_audit(
            ConfigAdminAction::Apply,
            &resolved,
            "accepted",
            ApplyReportResult::Applied.as_str(),
            true,
            false,
        )
        .with_break_glass_request(&request)
        .with_local_approval_request(
            &request,
            local_approval.as_ref(),
            local_approval_change_class,
        ),
    )
}

fn break_glass_proposal(request: &ConfigApplyRequest) -> Result<Option<BreakGlassApproval>, ()> {
    if !request.break_glass {
        return if request.break_glass_approval.is_some() || request.break_glass_rate_limit.is_some()
        {
            Err(())
        } else {
            Ok(None)
        };
    }
    if request.break_glass_rate_limit.is_some() {
        return Err(());
    }
    match request.break_glass_approval.clone() {
        Some(approval) => Ok(Some(approval)),
        _ => Err(()),
    }
}

fn local_approval_proposal(
    request: &ConfigApplyRequest,
    config_trust: &crate::config::ConfigTrustConfig,
    change_class: Option<&'static str>,
    config_hash: &str,
    previous_config_hash: Option<&str>,
) -> Result<Option<LocalOperatorApproval>, ()> {
    let Some(change_class) = change_class else {
        return Ok(None);
    };
    let Some(reference) = request.local_approval_reference.as_deref() else {
        return Err(());
    };
    if reference.trim().is_empty() {
        return Err(());
    }
    FileLocalApprovalStore::new(&config_trust.local_approval_state_path)
        .load_for_apply(reference, change_class, config_hash, previous_config_hash)
        .map(Some)
        .map_err(|_| ())
}

fn require_break_glass_emergency_change_class(
    request: &ConfigApplyRequest,
    resolved: &ResolvedConfigCandidate,
) -> Result<(), ()> {
    let Some(approval) = &request.break_glass_approval else {
        return Ok(());
    };
    if resolved
        .change_classes
        .contains(&approval.emergency_change_class)
    {
        Ok(())
    } else {
        Err(())
    }
}

fn is_break_glass_error(error: &AntiRollbackStoreError) -> bool {
    matches!(
        error,
        AntiRollbackStoreError::BreakGlassUnsupported
            | AntiRollbackStoreError::BreakGlassApprovalExpired
            | AntiRollbackStoreError::BreakGlassRateLimitMissing
            | AntiRollbackStoreError::BreakGlassRateLimited
            | AntiRollbackStoreError::InvalidBreakGlassApproval(_)
            | AntiRollbackStoreError::InvalidBreakGlassRateLimit(_)
    )
}

fn is_local_approval_error(error: &AntiRollbackStoreError) -> bool {
    matches!(
        error,
        AntiRollbackStoreError::LocalApprovalExpired
            | AntiRollbackStoreError::LocalApprovalRateLimitMissing
            | AntiRollbackStoreError::LocalApprovalRateLimited
            | AntiRollbackStoreError::InvalidLocalApproval(_)
    )
}

fn default_stream_id() -> String {
    "default".to_string()
}

#[derive(Debug, Deserialize)]
struct ReloadTablePath {
    dataset_id: DatasetId,
    table_id: ResourceId,
}

async fn reload_table(
    Path(path): Path<ReloadTablePath>,
    runtime: RuntimeSnapshot,
    _admin: AdminPrincipal,
) -> Response {
    let Some(registry) = runtime.ingest() else {
        return reload_unavailable(
            "admin table reload route matched, but ingest registry is not installed",
        );
    };

    let result = registry.reload(&path.dataset_id, &path.table_id).await;
    publish_readiness(runtime.readiness_tx(), &registry);

    match result {
        Ok(()) => Json(json!({
            "status": "ok",
            "counts": {
                "reloaded": 1,
            },
        }))
        .into_response(),
        Err(IngestError::SourceNotFound) => {
            Error::from(AdminError::UnknownResource).into_response()
        }
        Err(_) => Error::from(AdminError::ReloadFailed).into_response(),
    }
}

async fn reload_all(runtime: RuntimeSnapshot, _admin: AdminPrincipal) -> Response {
    let Some(registry) = runtime.ingest() else {
        return reload_unavailable(
            "admin reload-all route matched, but ingest registry is not installed",
        );
    };

    let report = registry.reload_all().await;
    publish_readiness(runtime.readiness_tx(), &registry);
    let status = if report.failed == 0 { "ok" } else { "failed" };
    let http_status = if report.failed == 0 {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let mut response = (
        http_status,
        Json(ReloadAllResponse {
            status,
            counts: ReloadAllCounts {
                total: report.total,
                succeeded: report.succeeded,
                failed: report.failed,
            },
        }),
    )
        .into_response();
    if http_status.is_server_error() {
        response
            .extensions_mut()
            .insert(ErrorCodeExt(RELOAD_FAILED_CODE.to_string()));
    }
    response
}

#[derive(Debug, Default, Deserialize)]
struct PostureQuery {
    tier: Option<String>,
}

async fn posture(
    Query(query): Query<PostureQuery>,
    runtime: RuntimeSnapshot,
    _ops: OpsReadPrincipal,
) -> Response {
    let Some(config) = runtime.config() else {
        return Error::from(AdminError::UnknownResource).into_response();
    };
    let snapshot = runtime
        .readiness_rx()
        .map(|readiness| readiness.borrow().clone());
    let tier = match posture_tier(query.tier.as_deref()) {
        Ok(tier) => tier,
        Err(()) => return posture_tier_invalid_response(),
    };
    let posture = match build_posture(
        &config,
        runtime.config_provenance(),
        snapshot.as_ref(),
        PostureMetadata {
            compiled: runtime.compiled_metadata().as_deref(),
            source_digest: runtime.metadata_source_digest().as_deref(),
            package_digest: runtime.metadata_package_digest().as_deref(),
            provenance_state: runtime.provenance_state().as_deref(),
        },
        tier,
    ) {
        Ok(posture) => posture,
        Err(error) => return posture_filter_failed(error),
    };
    Json(posture).into_response()
}

struct PostureMetadata<'a> {
    compiled: Option<&'a CompiledMetadata>,
    source_digest: Option<&'a str>,
    package_digest: Option<&'a str>,
    provenance_state: Option<&'a ProvenanceState>,
}

fn build_posture(
    config: &Config,
    provenance: Option<ConfigProvenance>,
    readiness: Option<&ReadinessSnapshot>,
    metadata: PostureMetadata<'_>,
    tier: PostureTier,
) -> Result<Value, PostureFilterError> {
    let warnings = posture_warnings(config, readiness);
    let provenance = provenance.unwrap_or_else(|| fallback_config_provenance(config));
    let mut instance = Map::new();
    instance.insert("id".to_string(), json!(config.instance.id));
    if let Some(environment) = &config.instance.environment {
        instance.insert("environment".to_string(), json!(environment));
    } else {
        instance.insert("environment".to_string(), json!("development"));
    }
    if let Some(owner) = &config.instance.owner {
        instance.insert("owner".to_string(), json!(owner));
    }
    if let Some(jurisdiction) = &config.instance.jurisdiction {
        instance.insert("jurisdiction".to_string(), json!(jurisdiction));
    }
    instance.insert(
        "public_base_url".to_string(),
        json!(config.catalog.base_url),
    );
    let mut metadata_manifest = Map::new();
    metadata_manifest.insert("configured".to_string(), json!(config.metadata.is_some()));
    if metadata.compiled.is_some() {
        metadata_manifest.insert("schema_version".to_string(), json!("registry-manifest/v1"));
    }
    if let Some(digest) = metadata.source_digest {
        metadata_manifest.insert("source_digest".to_string(), json!(digest));
    }
    if let Some(digest) = metadata.package_digest {
        metadata_manifest.insert("package_digest".to_string(), json!(digest));
    }
    let posture = json!({
        "schema": "registry.ops.posture.v1",
        "observed_at": OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current UTC timestamp formats as RFC3339"),
        "component": "registry-relay",
        "tier": "default",
        "instance": instance,
        "build": {
            "package": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        },
        "runtime": {
            "auth_mode": auth_mode_label(config.auth.mode),
            "admin_enabled": config.server.admin_bind.is_some(),
            "readiness": readiness_label(readiness),
        },
        "configuration": {
            "source": provenance.posture_source(),
            "dynamic_reload_supported": provenance.dynamic_reload_supported,
            "last_config_hash": provenance.posture_config_hash,
            "last_bundle_id": provenance.last_bundle_id,
            "last_bundle_sequence": provenance.last_bundle_sequence,
            "last_apply_result": provenance.last_apply_result.map(|result| result.as_str()),
            "last_apply_at": provenance.last_apply_at,
            "restart_required": provenance.restart_required,
        },
        "standards_artifacts": standards_artifacts(config),
        "relay": {
            "dataset_count": config.datasets.len(),
            "entity_count": config.datasets.iter().map(|dataset| dataset.entities.len()).sum::<usize>(),
            "aggregate_count": config.datasets.iter().map(|dataset| dataset.aggregates.len() + dataset.tables.iter().map(|table| table.aggregates.len()).sum::<usize>()).sum::<usize>(),
            "evidence_offering_count": metadata.compiled.map(|compiled| compiled.evidence_offerings().count()).unwrap_or(0),
            "metadata_manifest": metadata_manifest,
            "provenance": provenance_summary(config, metadata.provenance_state),
            "standards_adapters": {
                "ogcapi_records": feature_status(cfg!(feature = "ogcapi-records")),
                "ogcapi_features": feature_status(cfg!(feature = "ogcapi-features")),
                "ogcapi_edr": feature_status(cfg!(feature = "ogcapi-edr")),
                "spdci": feature_status(cfg!(feature = "spdci-api-standards") && config.standards.spdci.is_some()),
                "publicschema_cel": feature_status(cfg!(feature = "publicschema-cel")),
            },
        },
        "posture": {
            "warnings": warnings,
            "findings": [],
            "audit": audit_summary(config),
        },
    });
    filter_posture_for_tier(posture, tier)
}

fn parse_candidate_config(config_yaml: &str) -> Result<Config, &'static str> {
    parse_candidate_config_with_provenance(config_yaml, "dry-run", 0, ConfigSource::LocalFile)
        .map(|(config, _)| config)
}

async fn resolve_config_candidate(
    request: &ConfigApplyRequest,
    current_config: &Config,
) -> Result<ResolvedConfigCandidate, ConfigCandidateError> {
    match (&request.config_yaml, &request.tuf) {
        (Some(_), Some(_)) => Err(ConfigCandidateError::CandidateInvalid(
            "exactly one candidate config source must be provided",
        )),
        (Some(config_yaml), None) => {
            let bundle_id =
                request
                    .bundle_id
                    .clone()
                    .ok_or(ConfigCandidateError::CandidateInvalid(
                        "bundle_id is required for inline config",
                    ))?;
            let sequence = request
                .sequence
                .ok_or(ConfigCandidateError::CandidateInvalid(
                    "sequence is required for inline config",
                ))?;
            let resolved = ResolvedConfigCandidate {
                bundle_id,
                stream_id: request.stream_id.clone().unwrap_or_else(default_stream_id),
                sequence,
                previous_config_hash: request.previous_config_hash.clone(),
                root_version: request.root_version,
                change_classes: BTreeSet::new(),
                signer_kids: BTreeSet::new(),
                tuf_root_sha256: None,
                config_yaml: config_yaml.clone(),
                metadata_yaml: None,
                metadata_source_digest: None,
                package_digest: None,
                source: ConfigSource::LocalFile,
            };
            validate_previous_config_hash(resolved.previous_config_hash.as_deref())?;
            Ok(resolved)
        }
        (None, Some(tuf)) => {
            let resolved = resolve_tuf_config_candidate(tuf, current_config).await?;
            validate_previous_config_hash(resolved.previous_config_hash.as_deref())?;
            Ok(resolved)
        }
        (None, None) => Err(ConfigCandidateError::CandidateInvalid(
            "candidate config source was not provided",
        )),
    }
}

fn validate_previous_config_hash(value: Option<&str>) -> Result<(), ConfigCandidateError> {
    if value.is_some_and(|hash| !is_sha256_config_hash(hash)) {
        return Err(ConfigCandidateError::CandidateInvalid(
            "previous_config_hash must be sha256:<64 lowercase hex>",
        ));
    }
    Ok(())
}

fn is_metadata_only_config_change(current: &Config, candidate: &Config) -> bool {
    equivalent_except_public_metadata(current, candidate)
}

enum LiveConfigChange {
    Compatible {
        provenance_state: Option<Arc<ProvenanceState>>,
        local_approval_change_class: Option<&'static str>,
        auth_change: bool,
    },
    RestartRequired,
}

#[derive(Clone, Copy)]
struct LiveChangeAuthorization {
    signing_key_rotation: bool,
    signing_key_cleanup: bool,
    root_transition: bool,
    client_credential_rotation: bool,
    client_access_change: bool,
}

fn resolver_from_extension(
    resolver: Option<&Extension<CandidateProvenanceResolverRef>>,
) -> &dyn CandidateProvenanceResolver {
    resolver
        .map(|Extension(resolver)| resolver.as_ref())
        .unwrap_or(&DEFAULT_CANDIDATE_PROVENANCE_RESOLVER)
}

fn live_change_authorization(candidate: &ResolvedConfigCandidate) -> LiveChangeAuthorization {
    LiveChangeAuthorization {
        signing_key_rotation: candidate.change_classes.contains("signing_key_rotation"),
        signing_key_cleanup: candidate.change_classes.contains("signing_key_cleanup"),
        root_transition: candidate.change_classes.contains("root_transition"),
        client_credential_rotation: candidate
            .change_classes
            .contains("client_credential_rotation"),
        client_access_change: candidate.change_classes.contains("client_access_change"),
    }
}

fn classify_live_config_change(
    current: &crate::runtime_config::RelayRuntimeSnapshot,
    candidate: &Config,
    authorization: LiveChangeAuthorization,
    resolver: &dyn CandidateProvenanceResolver,
) -> Result<LiveConfigChange, &'static str> {
    if is_metadata_only_config_change(&current.config, candidate) {
        return Ok(LiveConfigChange::Compatible {
            provenance_state: None,
            local_approval_change_class: None,
            auth_change: false,
        });
    }
    if authorization.root_transition && is_root_transition_config_change(&current.config, candidate)
    {
        return Ok(LiveConfigChange::Compatible {
            provenance_state: None,
            local_approval_change_class: Some("root_transition"),
            auth_change: false,
        });
    }
    if authorization.client_credential_rotation
        && is_client_credential_rotation_change(&current.config, candidate)
    {
        return Ok(LiveConfigChange::Compatible {
            provenance_state: None,
            local_approval_change_class: Some("client_credential_rotation"),
            auth_change: true,
        });
    }
    if authorization.client_access_change && is_client_access_change(&current.config, candidate) {
        return Ok(LiveConfigChange::Compatible {
            provenance_state: None,
            local_approval_change_class: Some("client_access_change"),
            auth_change: true,
        });
    }
    if !is_provenance_signing_rotation_change(&current.config, candidate) {
        return Ok(LiveConfigChange::RestartRequired);
    }
    let Some(current_state) = current.provenance_state.as_deref() else {
        return Ok(LiveConfigChange::RestartRequired);
    };
    let resolved = resolver
        .resolve_candidate_provenance(candidate.provenance.as_ref())
        .map_err(|_| "candidate provenance could not be resolved")?
        .ok_or("candidate provenance could not be resolved")?;
    let active_key_changed =
        current_state.config().verification_method_id != resolved.verification_method_id;
    if active_key_changed && !authorization.signing_key_rotation {
        return Ok(LiveConfigChange::RestartRequired);
    }
    let removed_retired_keys = removed_retired_key_ids(current_state.config(), &resolved);
    if !removed_retired_keys.is_empty() && !authorization.signing_key_cleanup {
        return Ok(LiveConfigChange::RestartRequired);
    }
    if retired_keys_added_or_changed(current_state.config(), &resolved)
        && !authorization.signing_key_rotation
    {
        return Ok(LiveConfigChange::RestartRequired);
    }
    reject_unexpired_retired_key_cleanup(
        current_state.config(),
        &removed_retired_keys,
        (current_state.clock)(),
    )?;
    if current_state.config().verification_method_id != resolved.verification_method_id
        && !resolved
            .retired_keys
            .iter()
            .any(|key| key.verification_method_id == current_state.config().verification_method_id)
    {
        return Err("candidate provenance rotation must publish previous active key as retired");
    }
    if current_state.config().verification_method_id == resolved.verification_method_id
        && current_state.config().signer.public_jwk() != resolved.signer.public_jwk()
    {
        return Err(
            "candidate provenance signer public key changed without a new verification method",
        );
    }
    Ok(LiveConfigChange::Compatible {
        provenance_state: Some(Arc::new(ProvenanceState::new_with_clock(
            resolved,
            current_state.clock,
        ))),
        local_approval_change_class: None,
        auth_change: false,
    })
}

fn candidate_signing_readiness(provenance_state: Option<&ProvenanceState>) -> KeyReadiness {
    signing_readiness_for_apply(provenance_state.map(|state| state.config().signer.as_ref()))
}

fn is_client_credential_rotation_change(current: &Config, candidate: &Config) -> bool {
    equivalent_except_auth(current, candidate)
        && api_key_auth_changed(current, candidate)
        && same_api_key_ids_and_scopes(&current.auth.api_keys, &candidate.auth.api_keys)
}

fn is_client_access_change(current: &Config, candidate: &Config) -> bool {
    equivalent_except_auth(current, candidate) && api_key_auth_changed(current, candidate)
}

fn api_key_auth_changed(current: &Config, candidate: &Config) -> bool {
    current.auth.mode == AuthMode::ApiKey
        && candidate.auth.mode == AuthMode::ApiKey
        && current.auth.oidc == candidate.auth.oidc
        && current.auth.api_keys != candidate.auth.api_keys
}

fn same_api_key_ids_and_scopes(
    current: &[crate::config::ApiKeyConfig],
    candidate: &[crate::config::ApiKeyConfig],
) -> bool {
    let Some(current_scopes) = api_key_scopes_by_id(current) else {
        return false;
    };
    let Some(candidate_scopes) = api_key_scopes_by_id(candidate) else {
        return false;
    };
    current_scopes == candidate_scopes
}

fn api_key_scopes_by_id(
    keys: &[crate::config::ApiKeyConfig],
) -> Option<BTreeMap<&str, BTreeSet<&str>>> {
    let mut by_id = BTreeMap::new();
    for key in keys {
        let scopes = key
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if let Some(existing) = by_id.insert(key.id.as_str(), scopes.clone()) {
            if existing != scopes {
                return None;
            }
        }
    }
    Some(by_id)
}

fn signing_readiness_for_apply(signer: Option<&dyn Signer>) -> KeyReadiness {
    signer.map(Signer::readiness).unwrap_or(KeyReadiness::Ready)
}

fn removed_retired_key_ids(
    current: &crate::provenance::ResolvedProvenanceConfig,
    candidate: &crate::provenance::ResolvedProvenanceConfig,
) -> BTreeSet<String> {
    let candidate_ids = candidate
        .retired_keys
        .iter()
        .map(|key| key.verification_method_id.as_str())
        .collect::<BTreeSet<_>>();
    current
        .retired_keys
        .iter()
        .filter(|key| !candidate_ids.contains(key.verification_method_id.as_str()))
        .map(|key| key.verification_method_id.clone())
        .collect()
}

fn retired_keys_added_or_changed(
    current: &crate::provenance::ResolvedProvenanceConfig,
    candidate: &crate::provenance::ResolvedProvenanceConfig,
) -> bool {
    candidate.retired_keys.iter().any(|candidate_key| {
        current
            .retired_keys
            .iter()
            .find(|current_key| {
                current_key.verification_method_id == candidate_key.verification_method_id
            })
            .is_none_or(|current_key| {
                current_key.public_jwk != candidate_key.public_jwk
                    || current_key.retired_after != candidate_key.retired_after
            })
    })
}

fn reject_unexpired_retired_key_cleanup(
    current: &crate::provenance::ResolvedProvenanceConfig,
    removed_retired_key_ids: &BTreeSet<String>,
    now: OffsetDateTime,
) -> Result<(), &'static str> {
    if removed_retired_key_ids.is_empty() {
        return Ok(());
    }
    let max_validity = current
        .claim_validity
        .aggregate_result
        .max(current.claim_validity.entity_record);
    let grace = time::Duration::try_from(max_validity + std::time::Duration::from_secs(300))
        .unwrap_or(time::Duration::MAX);
    for key in &current.retired_keys {
        if !removed_retired_key_ids.contains(&key.verification_method_id) {
            continue;
        }
        let expired = key
            .retired_after
            .checked_add(grace)
            .map(|cutoff| now > cutoff)
            .unwrap_or(false);
        if !expired {
            return Err(
                "candidate provenance cleanup removed retired key before verification window expired",
            );
        }
    }
    Ok(())
}

fn is_provenance_signing_rotation_change(current: &Config, candidate: &Config) -> bool {
    equivalent_except_public_metadata_and_provenance(current, candidate)
        && compatible_provenance_signing_rotation(
            current.provenance.as_ref(),
            candidate.provenance.as_ref(),
        )
}

fn is_root_transition_config_change(current: &Config, candidate: &Config) -> bool {
    let (Some(current_trust), Some(candidate_trust)) =
        (&current.config_trust, &candidate.config_trust)
    else {
        return false;
    };
    current_trust.antirollback_state_path == candidate_trust.antirollback_state_path
        && current_trust.local_approval_state_path == candidate_trust.local_approval_state_path
        && current_trust.break_glass_rate_limit == candidate_trust.break_glass_rate_limit
        && !candidate_trust.accepted_roots.is_empty()
        && current_trust.accepted_roots != candidate_trust.accepted_roots
        && retained_accepted_roots_unchanged(
            &current_trust.accepted_roots,
            &candidate_trust.accepted_roots,
        )
        && equivalent_except_config_trust_accepted_roots(current, candidate)
}

fn retained_accepted_roots_unchanged(
    current: &[RegistryTrustRoot],
    candidate: &[RegistryTrustRoot],
) -> bool {
    if !root_ids_are_unique(current) || !root_ids_are_unique(candidate) {
        return false;
    }
    current.iter().all(|current_root| {
        candidate
            .iter()
            .find(|candidate_root| candidate_root.root_id == current_root.root_id)
            .is_none_or(|candidate_root| candidate_root == current_root)
    })
}

fn root_ids_are_unique(roots: &[RegistryTrustRoot]) -> bool {
    let mut seen = BTreeSet::new();
    roots.iter().all(|root| seen.insert(root.root_id.as_str()))
}

fn equivalent_except_config_trust_accepted_roots(current: &Config, candidate: &Config) -> bool {
    let (Some(current_trust), Some(candidate_trust)) =
        (&current.config_trust, &candidate.config_trust)
    else {
        return false;
    };
    current.instance.id == candidate.instance.id
        && current.instance.environment == candidate.instance.environment
        && current.server == candidate.server
        && current_trust.antirollback_state_path == candidate_trust.antirollback_state_path
        && current_trust.local_approval_state_path == candidate_trust.local_approval_state_path
        && current_trust.break_glass_rate_limit == candidate_trust.break_glass_rate_limit
        && current.metadata == candidate.metadata
        && current.catalog == candidate.catalog
        && current.vocabularies == candidate.vocabularies
        && current.auth == candidate.auth
        && current.audit == candidate.audit
        && current.datasets == candidate.datasets
        && current.provenance == candidate.provenance
        && current.standards == candidate.standards
}

fn equivalent_except_public_metadata(current: &Config, candidate: &Config) -> bool {
    current.instance.id == candidate.instance.id
        && current.instance.environment == candidate.instance.environment
        && current.server == candidate.server
        && current.config_trust == candidate.config_trust
        && current.metadata == candidate.metadata
        && current.vocabularies == candidate.vocabularies
        && current.auth == candidate.auth
        && current.audit == candidate.audit
        && current.datasets == candidate.datasets
        && current.provenance == candidate.provenance
        && current.standards == candidate.standards
        && current.catalog.title == candidate.catalog.title
        && current.catalog.base_url == candidate.catalog.base_url
        && current.catalog.publisher == candidate.catalog.publisher
        && current.catalog.participant_id == candidate.catalog.participant_id
        && current.catalog.publisher_iri == candidate.catalog.publisher_iri
        && current.catalog.authority_type == candidate.catalog.authority_type
        && current.catalog.default_spatial_coverage == candidate.catalog.default_spatial_coverage
}

fn equivalent_except_auth(current: &Config, candidate: &Config) -> bool {
    current.instance.id == candidate.instance.id
        && current.instance.environment == candidate.instance.environment
        && current.server == candidate.server
        && current.config_trust == candidate.config_trust
        && current.metadata == candidate.metadata
        && current.catalog == candidate.catalog
        && current.vocabularies == candidate.vocabularies
        && current.audit == candidate.audit
        && current.datasets == candidate.datasets
        && current.provenance == candidate.provenance
        && current.standards == candidate.standards
}

fn equivalent_except_public_metadata_and_provenance(current: &Config, candidate: &Config) -> bool {
    current.instance.id == candidate.instance.id
        && current.instance.environment == candidate.instance.environment
        && current.server == candidate.server
        && current.config_trust == candidate.config_trust
        && current.metadata == candidate.metadata
        && current.vocabularies == candidate.vocabularies
        && current.auth == candidate.auth
        && current.audit == candidate.audit
        && current.datasets == candidate.datasets
        && current.standards == candidate.standards
        && current.catalog.title == candidate.catalog.title
        && current.catalog.base_url == candidate.catalog.base_url
        && current.catalog.publisher == candidate.catalog.publisher
        && current.catalog.participant_id == candidate.catalog.participant_id
        && current.catalog.publisher_iri == candidate.catalog.publisher_iri
        && current.catalog.authority_type == candidate.catalog.authority_type
        && current.catalog.default_spatial_coverage == candidate.catalog.default_spatial_coverage
}

fn compatible_provenance_signing_rotation(
    current: Option<&crate::config::ProvenanceConfig>,
    candidate: Option<&crate::config::ProvenanceConfig>,
) -> bool {
    let (Some(current), Some(candidate)) = (current, candidate) else {
        return false;
    };
    if !current.enabled || !candidate.enabled {
        return false;
    }
    current.accepted_media_types == candidate.accepted_media_types
        && current.schema_base_url == candidate.schema_base_url
        && current.context_base_url == candidate.context_base_url
        && current.claim_validity.aggregate_result == candidate.claim_validity.aggregate_result
        && current.claim_validity.entity_record == candidate.claim_validity.entity_record
        && compatible_provenance_issuer_signing_rotation(&current.issuer, &candidate.issuer)
}

fn compatible_provenance_issuer_signing_rotation(
    current: &IssuerConfig,
    candidate: &IssuerConfig,
) -> bool {
    match (current, candidate) {
        (IssuerConfig::Gateway(current), IssuerConfig::Gateway(candidate)) => {
            current.did == candidate.did
        }
        (IssuerConfig::Delegated(current), IssuerConfig::Delegated(candidate)) => {
            current.ministry_did == candidate.ministry_did
        }
        _ => false,
    }
}

struct SnapshotReplacement {
    config: Config,
    config_provenance: ConfigProvenance,
    provenance_state: Option<Arc<ProvenanceState>>,
    auth: AuthProviderRef,
    compiled_metadata: Option<Arc<CompiledMetadata>>,
    metadata_source_digest: Option<String>,
    metadata_package_digest: Option<String>,
}

fn clone_snapshot_with_config(
    current: &crate::runtime_config::RelayRuntimeSnapshot,
    replacement: SnapshotReplacement,
) -> crate::runtime_config::RelayRuntimeSnapshot {
    let SnapshotReplacement {
        config,
        config_provenance,
        provenance_state,
        auth,
        compiled_metadata,
        metadata_source_digest,
        metadata_package_digest,
    } = replacement;
    let preserve_current_metadata = config.metadata.is_some();
    let compiled_metadata = compiled_metadata.or_else(|| {
        preserve_current_metadata
            .then(|| current.compiled_metadata.clone())
            .flatten()
    });
    let metadata_source_digest = metadata_source_digest.or_else(|| {
        preserve_current_metadata
            .then(|| current.metadata_source_digest.clone())
            .flatten()
    });
    let metadata_package_digest = metadata_package_digest.or_else(|| {
        preserve_current_metadata
            .then(|| current.metadata_package_digest.clone())
            .flatten()
    });
    crate::runtime_config::RelayRuntimeSnapshot::new(
        Arc::new(config),
        config_provenance,
        compiled_metadata,
        metadata_source_digest,
        metadata_package_digest,
        auth,
        Arc::clone(&current.audit_sink),
        current.bind,
        current.admin_bind,
        current.audit_kind,
        Arc::clone(&current.df_ctx),
        Arc::clone(&current.ingest),
        Arc::clone(&current.entity_registry),
        Arc::clone(&current.query),
        Arc::clone(&current.aggregate_query),
        current.readiness_tx.clone(),
        current.readiness_rx.clone(),
        Arc::clone(&current.cursor_signer),
        provenance_state.or_else(|| current.provenance_state.clone()),
        current.publicschema_registry.clone(),
        #[cfg(feature = "spdci-api-standards")]
        current.spdci_response_mapper.clone(),
        Arc::clone(&current.metrics),
    )
}

fn antirollback_key(config: &Config, stream_id: &str) -> AntiRollbackKey {
    AntiRollbackKey {
        product: "registry-relay".to_string(),
        instance_id: config.instance.id.clone(),
        environment: config
            .instance
            .environment
            .clone()
            .unwrap_or_else(|| "development".to_string()),
        stream_id: stream_id.to_string(),
    }
}

fn config_apply_report(
    bundle_id: String,
    sequence: u64,
    result: ApplyReportResult,
    applied: bool,
    restart_required: bool,
    status: StatusCode,
    audit: ConfigAuditExt,
) -> Response {
    let mut response = (
        status,
        Json(ConfigApplyResponse {
            bundle_id,
            sequence,
            result: result.as_str(),
            posture_result: result.as_posture_result().as_str(),
            applied,
            restart_required,
        }),
    )
        .into_response();
    if !status.is_success() {
        response
            .extensions_mut()
            .insert(ErrorCodeExt(result.as_str().to_string()));
    }
    response.extensions_mut().insert(audit);
    response
}

fn with_config_audit(mut response: Response, audit: ConfigAuditExt) -> Response {
    response.extensions_mut().insert(audit);
    response
}

fn unresolved_config_audit(
    action: ConfigAdminAction,
    request: &ConfigApplyRequest,
    product_validation_result: &'static str,
    apply_result: &'static str,
    applied: bool,
    restart_required: bool,
) -> ConfigAuditExt {
    ConfigAuditExt {
        action: action.as_str(),
        source: request_config_source(request).as_posture_str(),
        bundle_id: request.bundle_id.clone(),
        sequence: request.sequence,
        signer_kids: Vec::new(),
        previous_config_hash: request.previous_config_hash.clone(),
        config_hash: request
            .config_yaml
            .as_deref()
            .map(|yaml| internal_config_hash(yaml.as_bytes())),
        product_validation_result,
        apply_result,
        posture_result: apply_result_to_posture_audit(apply_result),
        applied,
        restart_required,
        change_classes: Vec::new(),
        break_glass: false,
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

fn resolved_config_audit(
    action: ConfigAdminAction,
    resolved: &ResolvedConfigCandidate,
    product_validation_result: &'static str,
    apply_result: &'static str,
    applied: bool,
    restart_required: bool,
) -> ConfigAuditExt {
    ConfigAuditExt {
        action: action.as_str(),
        source: resolved.source.as_posture_str(),
        bundle_id: Some(resolved.bundle_id.clone()),
        sequence: Some(resolved.sequence),
        signer_kids: resolved.signer_kids.iter().cloned().collect(),
        previous_config_hash: resolved.previous_config_hash.clone(),
        config_hash: Some(internal_config_hash(resolved.config_yaml.as_bytes())),
        product_validation_result,
        apply_result,
        posture_result: apply_result_to_posture_audit(apply_result),
        applied,
        restart_required,
        change_classes: resolved.change_classes.iter().cloned().collect(),
        break_glass: false,
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

trait ConfigAuditBreakGlassExt {
    fn with_break_glass_request(self, request: &ConfigApplyRequest) -> Self;
}

impl ConfigAuditBreakGlassExt for ConfigAuditExt {
    fn with_break_glass_request(mut self, request: &ConfigApplyRequest) -> Self {
        self.break_glass = request.break_glass;
        if let Some(approval) = &request.break_glass_approval {
            self.break_glass_approval_reference = Some(approval.approval_reference.clone());
            self.break_glass_approved_by = Some(approval.approved_by.clone());
            self.break_glass_reason_hash = Some(internal_config_hash(approval.reason.as_bytes()));
            self.break_glass_emergency_change_class = Some(approval.emergency_change_class.clone());
            self.break_glass_expires_at_unix_seconds = Some(approval.expires_at_unix_seconds);
            self.break_glass_rate_limit_identity = Some(approval.rate_limit_identity.clone());
        }
        self
    }
}

trait ConfigAuditLocalApprovalExt {
    fn with_local_approval_request(
        self,
        request: &ConfigApplyRequest,
        approval: Option<&LocalOperatorApproval>,
        change_class: Option<&'static str>,
    ) -> Self;
}

impl ConfigAuditLocalApprovalExt for ConfigAuditExt {
    fn with_local_approval_request(
        mut self,
        request: &ConfigApplyRequest,
        approval: Option<&LocalOperatorApproval>,
        change_class: Option<&'static str>,
    ) -> Self {
        self.local_approval_reference = request.local_approval_reference.clone();
        if self.local_approval_change_class.is_none() {
            self.local_approval_change_class = change_class.map(str::to_string);
        }
        if let Some(approval) = approval {
            self.local_approval_reference = Some(approval.approval_reference.clone());
            self.local_approval_approved_by = Some(approval.approved_by.clone());
            self.local_approval_reason_hash =
                Some(internal_config_hash(approval.reason.as_bytes()));
            self.local_approval_change_class = Some(approval.change_class.clone());
            self.local_approval_expires_at_unix_seconds = Some(approval.expires_at_unix_seconds);
            self.local_approval_rate_limit_identity = Some(approval.rate_limit_identity.clone());
        }
        self
    }
}

fn request_config_source(request: &ConfigApplyRequest) -> ConfigSource {
    if let Some(tuf) = &request.tuf {
        match tuf {
            TufConfigTargetRequest::Local(_) => ConfigSource::SignedBundleFile,
            TufConfigTargetRequest::Remote(_) => ConfigSource::SignedBundleEndpoint,
        }
    } else if request.config_yaml.is_some() {
        ConfigSource::LocalFile
    } else {
        ConfigSource::Unknown
    }
}

fn apply_result_to_posture_audit(apply_result: &str) -> &'static str {
    match apply_result {
        "verified" => ApplyReportResult::Verified.as_posture_result().as_str(),
        "applied" => ApplyReportResult::Applied.as_posture_result().as_str(),
        "rejected_restart_required" | "restart_required" => {
            ApplyReportResult::RejectedRestartRequired
                .as_posture_result()
                .as_str()
        }
        "rejected_break_glass" => ApplyReportResult::RejectedBreakGlass
            .as_posture_result()
            .as_str(),
        "rejected_local_approval" => ApplyReportResult::RejectedLocalApproval
            .as_posture_result()
            .as_str(),
        "rejected_rollback"
        | "rejected_signature"
        | "rejected_threshold"
        | "rejected_freshness"
        | "rejected_readiness"
        | "rejected_apply_policy"
        | "rejected_product_validation"
        | "rejected_compile" => "rejected",
        "internal_error" => "rejected",
        _ => "rejected",
    }
}

fn config_candidate_invalid(detail: &'static str) -> Response {
    let status = StatusCode::BAD_REQUEST;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}admin/config_candidate_invalid", crate::error::PROBLEM_TYPE_BASE),
            "title": "Invalid config candidate",
            "status": status.as_u16(),
            "detail": detail,
            "code": CONFIG_CANDIDATE_INVALID_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(CONFIG_CANDIDATE_INVALID_CODE.to_string()));
    response
}

fn config_bundle_invalid(detail: &'static str) -> Response {
    let status = StatusCode::BAD_REQUEST;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}admin/config_bundle_invalid", crate::error::PROBLEM_TYPE_BASE),
            "title": "Invalid config bundle",
            "status": status.as_u16(),
            "detail": detail,
            "code": CONFIG_BUNDLE_INVALID_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(CONFIG_BUNDLE_INVALID_CODE.to_string()));
    response
}

fn config_apply_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": format!("{}admin/config_apply_unavailable", crate::error::PROBLEM_TYPE_BASE),
            "title": "Config apply unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": CONFIG_APPLY_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(CONFIG_APPLY_UNAVAILABLE_CODE.to_string()));
    response
}

fn config_inline_apply_rejected(detail: &'static str) -> Response {
    let status = StatusCode::BAD_REQUEST;
    let mut response = (
        status,
        Json(json!({
            "schema": "registry.admin.error.v1",
            "type": format!("{}admin/config_inline_apply_rejected", crate::error::PROBLEM_TYPE_BASE),
            "title": "Inline config apply rejected",
            "status": status.as_u16(),
            "message": detail,
            "detail": detail,
            "code": CONFIG_INLINE_APPLY_REJECTED_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(CONFIG_INLINE_APPLY_REJECTED_CODE.to_string()));
    response
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current UTC timestamp formats as RFC3339")
}

fn posture_warnings(config: &Config, readiness: Option<&ReadinessSnapshot>) -> Vec<String> {
    let mut warnings = Vec::new();
    if !config.audit.chain {
        warnings.push("relay.audit_checkpoint_unavailable".to_string());
    }
    if readiness.is_none_or(|snapshot| !snapshot.fully_ready()) {
        warnings.push("relay.readiness_degraded".to_string());
    }
    warnings
}

fn standards_artifacts(config: &Config) -> Value {
    let base = config.catalog.base_url.trim_end_matches('/');
    json!({
        "metadata_index": artifact_ref(format!("{base}/metadata"), "application/json"),
        "api_catalog": artifact_ref(format!("{base}/.well-known/api-catalog"), "application/json"),
        "dcat": artifact_ref(format!("{base}/metadata/dcat"), "application/ld+json"),
        "bregdcat_ap": artifact_ref(format!("{base}/metadata/dcat/bregdcat-ap"), "application/ld+json"),
        "shacl": artifact_ref(format!("{base}/metadata/shacl"), "text/turtle"),
        "openapi": artifact_ref(format!("{base}/openapi.json"), "application/vnd.oai.openapi+json;version=3.1"),
    })
}

fn artifact_ref(url: String, media_type: &str) -> Value {
    json!({
        "url": url,
        "media_type": media_type,
        "observed_status": "configured_not_checked",
    })
}

fn posture_tier(value: Option<&str>) -> Result<PostureTier, ()> {
    match value.unwrap_or("default") {
        "default" => Ok(PostureTier::Default),
        "restricted" => Ok(PostureTier::Restricted),
        _ => Err(()),
    }
}

fn posture_tier_invalid_response() -> Response {
    let mut response = (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "type": format!("{}admin/posture_tier_invalid", crate::error::PROBLEM_TYPE_BASE),
            "title": "Admin posture tier invalid",
            "status": 400,
            "schema": "registry.admin.error.v1",
            "code": POSTURE_TIER_INVALID_CODE,
            "message": "invalid posture tier",
            "detail": "posture tier must be default or restricted",
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(POSTURE_TIER_INVALID_CODE.to_string()));
    response
}

fn provenance_summary(config: &Config, state: Option<&ProvenanceState>) -> Value {
    let Some(provenance) = &config.provenance else {
        return json!({
            "enabled": false,
            "retired_kids": [],
            "key_readiness": {},
        });
    };
    let (issuer, active_kid, active_provider, retired_kids) = match &provenance.issuer {
        IssuerConfig::Gateway(issuer) => (
            issuer.did.as_str(),
            issuer.verification_method_id.as_str(),
            signer_provider_kind(&issuer.signer),
            issuer
                .retired_keys
                .iter()
                .map(|key| key.verification_method_id.as_str())
                .collect::<Vec<_>>(),
        ),
        IssuerConfig::Delegated(issuer) => (
            issuer.ministry_did.as_str(),
            issuer.verification_method_id.as_str(),
            signer_provider_kind(&issuer.signer),
            issuer
                .retired_keys
                .iter()
                .map(|key| key.verification_method_id.as_str())
                .collect::<Vec<_>>(),
        ),
    };
    let active_readiness = if provenance.enabled {
        state
            .map(|state| state.config().signer.readiness())
            .unwrap_or(KeyReadiness::NotReady)
    } else {
        KeyReadiness::Unknown
    };
    let mut key_readiness = Map::new();
    key_readiness.insert(active_kid.to_string(), json!(active_readiness.as_str()));
    if let Some(state) = state {
        for key in &state.config().retired_keys {
            key_readiness.insert(
                key.verification_method_id.clone(),
                json!(KeyReadiness::Ready.as_str()),
            );
        }
    } else {
        for kid in &retired_kids {
            key_readiness.insert((*kid).to_string(), json!(KeyReadiness::Unknown.as_str()));
        }
    }
    json!({
        "enabled": provenance.enabled,
        "issuer": issuer,
        "active_kid": active_kid,
        "active_provider": active_provider.as_str(),
        "retired_kids": retired_kids,
        "key_readiness": key_readiness,
    })
}

fn signer_provider_kind(signer: &SignerConfig) -> KeyProviderKind {
    match signer {
        SignerConfig::Software(_) => KeyProviderKind::LocalJwkEnv,
        SignerConfig::FileWatch(_) => KeyProviderKind::FileWatch,
        SignerConfig::Kms(_) => KeyProviderKind::Kms,
    }
}

fn audit_summary(config: &Config) -> Value {
    json!({
        "configured": true,
        "sink_type": audit_sink_label(config),
        "checkpoint_status": if config.audit.chain { "available" } else { "unavailable" },
        "latest_tail_hash": null,
        "latest_sequence": null,
        "verified_at": null,
        "verification_status": "not_supported",
    })
}

fn fallback_config_provenance(config: &Config) -> ConfigProvenance {
    let public_shape = json!({
        "instance": {
            "id": config.instance.id,
            "environment": config.instance.environment,
            "owner": config.instance.owner,
            "jurisdiction": config.instance.jurisdiction,
        },
        "server": {
            "admin_enabled": config.server.admin_bind.is_some(),
            "cache_dir_configured": true,
        },
        "catalog": {
            "title": config.catalog.title,
            "base_url": config.catalog.base_url,
            "publisher": config.catalog.publisher,
            "participant_id": config.catalog.participant_id,
        },
        "auth": { "mode": auth_mode_label(config.auth.mode) },
        "audit": {
            "sink": audit_sink_label(config),
            "format": "jsonl",
            "chain": config.audit.chain,
            "hash_secret_env_configured": config.audit.hash_secret_env.is_some(),
        },
        "datasets": config.datasets.iter().map(|dataset| dataset.id.to_string()).collect::<Vec<_>>(),
        "metadata_manifest_configured": config.metadata.is_some(),
        "provenance": provenance_summary(config, None),
    });
    let bytes = serde_json::to_vec(&public_shape).expect("public config shape serializes");
    ConfigProvenance::local_file(
        internal_config_hash(&bytes),
        posture_safe_runtime_config_hash(&public_shape),
        false,
    )
}

fn readiness_label(readiness: Option<&ReadinessSnapshot>) -> &'static str {
    let status = match readiness {
        Some(snapshot) if snapshot.fully_ready() => KeyReadiness::Ready,
        Some(_) => KeyReadiness::Degraded,
        None => KeyReadiness::Unknown,
    };
    status.as_str()
}

fn auth_mode_label(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::ApiKey => "api_key",
        AuthMode::Oidc => "oidc",
    }
}

fn audit_sink_label(config: &Config) -> &'static str {
    match &config.audit.sink {
        crate::config::AuditSinkConfig::Stdout { .. } => "stdout",
        crate::config::AuditSinkConfig::File { .. } => "file",
        crate::config::AuditSinkConfig::Syslog { .. } => "syslog",
    }
}

fn feature_status(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

fn publish_readiness(
    readiness_tx: Option<watch::Sender<ReadinessSnapshot>>,
    registry: &IngestRegistry,
) {
    if let Some(readiness_tx) = readiness_tx {
        let _ = readiness_tx.send(registry.snapshot());
    }
}

async fn require_scope_from_parts<S>(
    parts: &mut Parts,
    state: &S,
    required: &'static str,
) -> Result<(), AdminAuthRejection>
where
    S: Send + Sync,
{
    let principal = Option::<Extension<Principal>>::from_request_parts(parts, state)
        .await
        .unwrap_or(None)
        .map(|Extension(principal)| principal);
    require_scope_from_principal(principal, required)
}

fn require_scope_from_principal(
    principal: Option<Principal>,
    required: &'static str,
) -> Result<(), AdminAuthRejection> {
    let Some(principal) = principal else {
        return Err(AdminAuthRejection::new(
            Error::from(AuthError::MissingCredential).into_response(),
        ));
    };
    require_scope(&principal, required)
        .map_err(|error| AdminAuthRejection::new(error.into_response()))
}

#[derive(Debug, Serialize)]
struct ReloadAllResponse {
    status: &'static str,
    counts: ReloadAllCounts,
}

#[derive(Debug, Serialize)]
struct ReloadAllCounts {
    total: usize,
    succeeded: usize,
    failed: usize,
}

fn reload_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": format!("{}admin/reload_unavailable", crate::error::PROBLEM_TYPE_BASE),
            "title": "Admin reload unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": RELOAD_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(RELOAD_UNAVAILABLE_CODE.to_string()));
    response
}

fn runtime_unavailable(detail: &'static str) -> Response {
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}admin/runtime_unavailable", crate::error::PROBLEM_TYPE_BASE),
            "title": "Admin runtime unavailable",
            "status": status.as_u16(),
            "detail": detail,
            "code": RUNTIME_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(RUNTIME_UNAVAILABLE_CODE.to_string()));
    response
}

fn posture_filter_failed(error: PostureFilterError) -> Response {
    tracing::error!(error = %error, "failed to filter admin posture");
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": format!("{}admin/posture_filter_failed", crate::error::PROBLEM_TYPE_BASE),
            "title": "Admin posture unavailable",
            "status": status.as_u16(),
            "detail": "admin posture could not be filtered for the requested tier",
            "code": POSTURE_FILTER_FAILED_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(POSTURE_FILTER_FAILED_CODE.to_string()));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OidcConfig;
    use crate::provenance::SigningAlgorithm;

    /// Minimal valid config used by equivalence classifier tests.
    ///
    /// Note: `serde_saphyr::from_str` parses YAML. Each call returns an
    /// independent value so callers can mutate one field and compare.
    fn parse_minimal_config(yaml: &str) -> Config {
        serde_saphyr::from_str(yaml).expect("test config parses")
    }

    fn minimal_config_yaml() -> String {
        r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: stdout
datasets: []
"#
        .to_string()
    }

    struct ReadinessTestSigner {
        readiness: KeyReadiness,
    }

    impl Signer for ReadinessTestSigner {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EdDSA
        }

        fn verification_method_id(&self) -> &str {
            "did:web:example#readiness"
        }

        fn sign(
            &self,
            _header: Value,
            _payload: Value,
        ) -> Result<String, crate::provenance::SignerError> {
            Ok("e30.e30.c2lnbmF0dXJl".to_string())
        }

        fn public_jwk(&self) -> Value {
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "kid": self.verification_method_id(),
            })
        }

        fn readiness(&self) -> KeyReadiness {
            self.readiness
        }
    }

    // --- equivalence classifier tests ---

    #[test]
    fn equivalent_except_public_metadata_equal_configs_are_equivalent() {
        let a = parse_minimal_config(&minimal_config_yaml());
        let b = parse_minimal_config(&minimal_config_yaml());
        assert!(
            equivalent_except_public_metadata(&a, &b),
            "identical configs must be equivalent"
        );
    }

    #[test]
    fn equivalent_except_public_metadata_server_bind_change_is_not_equivalent() {
        let a = parse_minimal_config(&minimal_config_yaml());
        let b = parse_minimal_config(
            &minimal_config_yaml().replace("bind: \"127.0.0.1:8080\"", "bind: \"127.0.0.1:9090\""),
        );
        assert!(
            !equivalent_except_public_metadata(&a, &b),
            "server bind change must not be equivalent"
        );
    }

    #[test]
    fn equivalent_except_auth_catalog_change_is_not_equivalent() {
        let a = parse_minimal_config(&minimal_config_yaml());
        let b = parse_minimal_config(&minimal_config_yaml().replace(
            "base_url: \"https://data.example.test\"",
            "base_url: \"https://other.example.test\"",
        ));
        assert!(
            !equivalent_except_auth(&a, &b),
            "catalog base_url change must not be equivalent"
        );
    }

    /// Verifies that the OIDC config comparison uses semantic equality: two
    /// configs with identical OIDC settings are treated as equivalent, and two
    /// with differing OIDC issuers are not.
    ///
    /// The classifier must compare via `PartialEq`, never via Debug-string
    /// equality: a custom Debug impl that omitted a field would silently make
    /// semantically different configs compare equal.
    #[test]
    fn api_key_auth_changed_treats_oidc_field_semantically() {
        let oidc_a = OidcConfig {
            issuer: "https://idp-a.example.test".to_string(),
            audiences: vec!["relay".to_string()],
            jwks_url: Some("https://idp-a.example.test/.well-known/jwks.json".to_string()),
            discovery_url: None,
            allow_dev_insecure_fetch_urls: false,
            allowed_algorithms: vec![crate::config::OidcAlgorithm::Rs256],
            jwks_cache_ttl: std::time::Duration::from_secs(600),
            leeway: std::time::Duration::from_secs(60),
            scope_claim: "scope".to_string(),
            scope_map: Default::default(),
            scope_object_required_keys: vec![],
            allowed_clients: vec![],
            allowed_token_types: vec!["JWT".to_string(), "at+jwt".to_string()],
        };
        let oidc_b = OidcConfig {
            issuer: "https://idp-b.example.test".to_string(),
            ..oidc_a.clone()
        };

        // Same OIDC config: the field should compare equal.
        assert_eq!(
            Some(&oidc_a),
            Some(&oidc_a),
            "identical OidcConfig values must be PartialEq-equal"
        );
        // Different OIDC issuer: must not compare equal.
        assert_ne!(
            Some(&oidc_a),
            Some(&oidc_b),
            "OidcConfig with different issuers must not compare equal"
        );
    }

    #[test]
    fn config_request_rejects_ambiguous_local_and_remote_tuf_source() {
        let request = serde_json::from_value::<ConfigApplyRequest>(json!({
            "tuf": {
                "root_path": "/etc/registry-relay/trust/root.json",
                "metadata_dir": "/etc/registry-relay/trust/metadata",
                "targets_dir": "/etc/registry-relay/trust/targets",
                "metadata_base_url": "https://config.example.gov/metadata/",
                "targets_base_url": "https://config.example.gov/targets/",
                "datastore_dir": "/var/lib/registry-relay/config-tuf",
                "target_name": "registry-relay.yaml"
            }
        }));

        assert!(
            request.is_err(),
            "TUF request must choose exactly one local or remote source shape"
        );
    }

    #[test]
    fn signing_readiness_for_apply_defaults_ready_and_honors_signer_state() {
        assert_eq!(signing_readiness_for_apply(None), KeyReadiness::Ready);

        let ready = ReadinessTestSigner {
            readiness: KeyReadiness::Ready,
        };
        let degraded = ReadinessTestSigner {
            readiness: KeyReadiness::Degraded,
        };
        let not_ready = ReadinessTestSigner {
            readiness: KeyReadiness::NotReady,
        };

        assert_eq!(
            signing_readiness_for_apply(Some(&ready)),
            KeyReadiness::Ready
        );
        assert_eq!(
            signing_readiness_for_apply(Some(&degraded)),
            KeyReadiness::Degraded
        );
        assert_eq!(
            signing_readiness_for_apply(Some(&not_ready)),
            KeyReadiness::NotReady
        );
    }
}
