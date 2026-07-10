// SPDX-License-Identifier: Apache-2.0
//! Admin HTTP routes.
//!
//! This module owns the route surface only. Server/auth integration can
//! install the router and `IngestRegistry` extension from the admin
//! listener when that wiring lands.

use axum::extract::{FromRequestParts, Path, Query};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use registry_manifest_core::CompiledMetadata;
use registry_platform_crypto::KeyReadiness;
use registry_platform_ops::{
    audit_shipping_target, filter_posture_for_tier, internal_config_hash, override_pin_posture,
    posture_safe_runtime_config_hash, AuditSinkKind, AuditWritePolicy, ConfigProvenance,
    ConfigSource, PostureFilterError, PostureTier,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::audit::{audit_write_failed_response, ErrorCodeExt, OperationalAuditEvent};
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{AuthMode, Config, DatasetId, ResourceId};
use crate::error::{AdminError, AuthError, Error, IngestError};
use crate::ingest::{IngestRegistry, ReadinessSnapshot};
use crate::runtime_config::RuntimeSnapshot;

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RELOAD_FAILED_CODE: &str = "admin.reload_failed";
const RELOAD_UNAVAILABLE_CODE: &str = "admin.reload_unavailable";
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

/// Sub-router for admin reload routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/v1/capabilities", get(capabilities))
        .route("/admin/v1/posture", get(posture))
        .route("/admin/v1/reload", post(reload_all))
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

    if let Err(response) =
        fail_closed_admin_mutation_preflight(&runtime, "admin.reload_table.preflight").await
    {
        return response;
    }
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

    if let Err(response) =
        fail_closed_admin_mutation_preflight(&runtime, "admin.reload_all.preflight").await
    {
        return response;
    }
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

async fn fail_closed_admin_mutation_preflight(
    runtime: &RuntimeSnapshot,
    event: &'static str,
) -> Result<(), Response> {
    let Some(config) = runtime.config() else {
        return Ok(());
    };
    if config.audit.write_policy != AuditWritePolicy::FailClosed {
        return Ok(());
    }
    let Some(sink) = runtime.audit_sink() else {
        return Err(audit_write_failed_response());
    };
    if let Err(error) = sink
        .write_operational_event(OperationalAuditEvent::success(event))
        .await
    {
        tracing::error!(error = %error, event, "audit.write_failed");
        return Err(audit_write_failed_response());
    }
    Ok(())
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
    let observation = crate::deployment::audit_ack_observation_bounded(&config).await;
    let observation = if observation.requires_audit_tail_binding() {
        let tail = match runtime.audit_sink() {
            Some(audit) if audit.chain_healthy() => audit.current_tail_hash_bounded().await,
            _ => None,
        };
        observation.bind_to_audit_tail(tail)
    } else {
        observation
    };
    let posture = match build_posture_with_observation(
        &config,
        runtime.config_provenance(),
        snapshot.as_ref(),
        &observation,
        PostureMetadata {
            compiled: runtime.compiled_metadata().as_deref(),
            source_digest: runtime.metadata_source_digest().as_deref(),
            package_digest: runtime.metadata_package_digest().as_deref(),
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
}

fn build_posture_with_observation(
    config: &Config,
    provenance: Option<ConfigProvenance>,
    readiness: Option<&ReadinessSnapshot>,
    observation: &registry_platform_ops::AckObservation,
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
    let (deployment, deployment_ready) =
        deployment_summary_with_observation(config, provenance.source, observation);
    let runtime_readiness = if deployment_ready {
        readiness_label(readiness)
    } else {
        "not_ready"
    };
    let mut configuration = Map::new();
    configuration.insert("source".to_string(), json!(provenance.posture_source()));
    configuration.insert(
        "dynamic_reload_supported".to_string(),
        json!(provenance.dynamic_reload_supported),
    );
    configuration.insert(
        "last_config_hash".to_string(),
        json!(provenance.posture_config_hash),
    );
    configuration.insert(
        "last_bundle_id".to_string(),
        json!(provenance.last_bundle_id),
    );
    configuration.insert(
        "last_bundle_sequence".to_string(),
        json!(provenance.last_bundle_sequence),
    );
    configuration.insert(
        "last_bundle_signer_kids".to_string(),
        json!(provenance.last_bundle_signer_kids),
    );
    configuration.insert(
        "last_apply_result".to_string(),
        json!(provenance.last_apply_result.map(|result| result.as_str())),
    );
    configuration.insert("last_apply_at".to_string(), json!(provenance.last_apply_at));
    configuration.insert(
        "restart_required".to_string(),
        json!(provenance.restart_required),
    );
    if let Some(pin) = &provenance.override_pin {
        configuration.insert("override".to_string(), override_pin_posture(pin));
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
            "readiness": runtime_readiness,
        },
        "configuration": configuration,
        "deployment": deployment,
        "audit": audit_assurance(config),
        "standards_artifacts": standards_artifacts(config),
        "relay": {
            "dataset_count": config.datasets.len(),
            "entity_count": config.datasets.iter().map(|dataset| dataset.entities.len()).sum::<usize>(),
            "aggregate_count": config.datasets.iter().map(|dataset| dataset.aggregates.len() + dataset.tables.iter().map(|table| table.aggregates.len()).sum::<usize>()).sum::<usize>(),
            "evidence_offering_count": metadata.compiled.map(|compiled| compiled.evidence_offerings().count()).unwrap_or(0),
            "metadata_manifest": metadata_manifest,
            "standards_adapters": {
                "ogcapi_records": feature_status(cfg!(feature = "ogcapi-records")),
                "ogcapi_features": feature_status(cfg!(feature = "ogcapi-features")),
                "ogcapi_edr": feature_status(cfg!(feature = "ogcapi-edr")),
                "spdci": feature_status(cfg!(feature = "spdci-api-standards") && config.standards.spdci.is_some()),
            },
        },
        "posture": {
            "warnings": warnings,
            "findings": [],
            "audit": audit_summary_with_observation(config, observation),
        },
    });
    filter_posture_for_tier(posture, tier)
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

fn audit_summary_with_observation(
    config: &Config,
    observation: &registry_platform_ops::AckObservation,
) -> Value {
    let (shipping_target_configured, shipping_target) = audit_shipping_state(config);
    // Observed shipping freshness from the local ack cursor (declared state is
    // above; this is the observed counterpart). Reading the cursor here mirrors
    // the doctor report via the shared helpers so the two never drift.
    let (shipping_health, shipping_observed_at) =
        crate::deployment::shipping_health_fields(observation, shipping_target_configured);
    json!({
        "configured": true,
        "sink_type": audit_sink_label(config),
        "shipping_target_configured": shipping_target_configured,
        "shipping_target": shipping_target,
        "shipping_health": shipping_health,
        "shipping_observed_at": shipping_observed_at,
        "checkpoint_status": if config.audit.chain { "available" } else { "unavailable" },
        "latest_tail_hash": null,
        "latest_sequence": null,
        "verified_at": null,
        "verification_status": "not_supported",
    })
}

fn audit_shipping_state(config: &Config) -> (bool, &'static str) {
    // Relay's sink is a closed enum, so the shared classifier never sees
    // `Unknown` here.
    let sink = match &config.audit.sink {
        crate::config::AuditSinkConfig::Stdout { .. } => AuditSinkKind::Stdout,
        crate::config::AuditSinkConfig::Syslog { .. } => AuditSinkKind::Syslog,
        crate::config::AuditSinkConfig::File { .. } => AuditSinkKind::LocalFile,
    };
    audit_shipping_target(sink, config.deployment.evidence.audit_offhost_shipping)
}

/// Build the `deployment` posture object: declared profile, gate findings, and
/// active waivers. Findings carry only `{id, severity, status}` plus an
/// optional waiver block; the default-tier posture filter strips waiver
/// reasons. `findings` and `waivers` are always present (possibly empty).
fn deployment_summary_with_observation(
    config: &Config,
    config_source: ConfigSource,
    observation: &registry_platform_ops::AckObservation,
) -> (Value, bool) {
    let facts = crate::deployment::facts_from_config_with_ack_observation(
        config,
        config_source,
        observation,
    );
    let waivers = crate::deployment::waivers_from_config(config);
    let evaluation = crate::deployment::evaluate(
        config.deployment.profile,
        &facts,
        &waivers,
        &crate::deployment::today_utc(),
    );
    let mut summary = Map::new();
    if let Some(profile) = config.deployment.profile {
        summary.insert("profile".to_string(), json!(profile.as_str()));
    }
    summary.insert(
        "findings".to_string(),
        json!(evaluation
            .findings
            .iter()
            .map(deployment_finding_json)
            .collect::<Vec<_>>()),
    );
    summary.insert(
        "waivers".to_string(),
        json!(evaluation
            .active_waivers
            .iter()
            .map(|waiver| json!({
                "finding": waiver.finding,
                "reason": waiver.reason,
                "expires": waiver.expires,
            }))
            .collect::<Vec<_>>()),
    );
    (Value::Object(summary), !evaluation.has_readiness_failure())
}

#[cfg(test)]
fn build_posture(
    config: &Config,
    provenance: Option<ConfigProvenance>,
    readiness: Option<&ReadinessSnapshot>,
    metadata: PostureMetadata<'_>,
    tier: PostureTier,
) -> Result<Value, PostureFilterError> {
    let observation = crate::deployment::audit_ack_observation(config);
    build_posture_with_observation(config, provenance, readiness, &observation, metadata, tier)
}

#[cfg(test)]
fn audit_summary(config: &Config) -> Value {
    let observation = crate::deployment::audit_ack_observation(config);
    audit_summary_with_observation(config, &observation)
}

#[cfg(test)]
fn deployment_summary(config: &Config, config_source: ConfigSource) -> Value {
    let observation = crate::deployment::audit_ack_observation(config);
    deployment_summary_with_observation(config, config_source, &observation).0
}

fn deployment_finding_json(finding: &registry_platform_ops::DeploymentFinding) -> Value {
    let mut object = Map::new();
    object.insert("id".to_string(), json!(finding.id));
    object.insert("severity".to_string(), json!(finding.severity.as_str()));
    object.insert("status".to_string(), json!(finding.status.as_str()));
    if let Some(waiver) = &finding.waiver {
        object.insert(
            "waiver".to_string(),
            json!({
                "reason": waiver.reason,
                "expires": waiver.expires,
            }),
        );
    }
    Value::Object(object)
}

/// Build the top-level `audit` assurance object: eight separately named facts
/// describing what the audit trail does and does not guarantee. Each is
/// reported truthfully from config so "audit exists" cannot be overclaimed.
fn audit_assurance(config: &Config) -> Value {
    use registry_platform_ops::{
        AuditAnchoring, AuditCheckpoints, AuditHashChain, AuditKeyedIntegrity, AuditRedactionMode,
        AuditRetentionOwner, AuditSinkClass,
    };

    let write_policy = config.audit.write_policy;
    let keyed_integrity = if config.audit.hash_secret_env.is_some() {
        AuditKeyedIntegrity::Hmac
    } else {
        AuditKeyedIntegrity::None
    };
    // Platform audit envelopes always chain `prev_hash`/`record_hash` in
    // process; the chain is not independently retained or anchored.
    let hash_chain = AuditHashChain::ProcessLocal;
    let sink_class = match &config.audit.sink {
        crate::config::AuditSinkConfig::Stdout { .. } => AuditSinkClass::Stdout,
        crate::config::AuditSinkConfig::File { .. } => AuditSinkClass::File,
        crate::config::AuditSinkConfig::Syslog { .. } => AuditSinkClass::External,
    };
    let checkpoints = if config.audit.chain {
        AuditCheckpoints::Enabled
    } else {
        AuditCheckpoints::Supported
    };

    // The ops assurance enums serialize to their snake_case wire strings, the
    // canonical posture vocabulary. `to_value` cannot fail for these unit
    // enums.
    json!({
        "write_policy": json!(write_policy),
        "redaction_mode": json!(AuditRedactionMode::Redacted),
        "hash_chain": json!(hash_chain),
        "keyed_integrity": json!(keyed_integrity),
        "sink_class": json!(sink_class),
        "retention_owner": json!(AuditRetentionOwner::Operator),
        "checkpoints": json!(checkpoints),
        "anchoring": json!(AuditAnchoring::None),
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

    // --- deployment posture surface tests ---

    use registry_platform_ops::{AuditWritePolicy, DeploymentProfile};

    /// Compile the shared posture schema once per call. Validation here proves
    /// the posture document relay emits, including the `deployment` and `audit`
    /// blocks, matches `registry.ops.posture.v1`.
    fn assert_posture_schema_valid(body: &Value) {
        let schema: Value = serde_json::from_str(registry_platform_ops::POSTURE_SCHEMA_V1)
            .expect("posture schema parses");
        let compiled = jsonschema::JSONSchema::compile(&schema).expect("posture schema compiles");
        let errors = compiled
            .validate(body)
            .err()
            .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        assert!(
            errors.is_empty(),
            "posture did not match registry.ops.posture.v1: {errors:?}\n{body:#}"
        );
    }

    fn empty_posture_metadata() -> PostureMetadata<'static> {
        PostureMetadata {
            compiled: None,
            source_digest: None,
            package_digest: None,
        }
    }

    fn build_default_tier_posture(config: &Config) -> Value {
        build_posture(
            config,
            None,
            None,
            empty_posture_metadata(),
            PostureTier::Default,
        )
        .expect("default-tier posture builds")
    }

    /// The eight audit assurance facts are always present and named, so "audit
    /// exists" cannot be overclaimed: each fact is reported on its own.
    #[test]
    fn audit_assurance_reports_eight_named_facts() {
        let config = parse_minimal_config(&minimal_config_yaml());
        let audit = audit_assurance(&config);
        for field in [
            "write_policy",
            "redaction_mode",
            "hash_chain",
            "keyed_integrity",
            "sink_class",
            "retention_owner",
            "checkpoints",
            "anchoring",
        ] {
            assert!(
                audit.get(field).is_some(),
                "audit assurance must report the `{field}` fact"
            );
        }
        // Default config: fail-closed, stdout sink, no keyed integrity.
        assert_eq!(audit["write_policy"], "fail_closed");
        assert_eq!(audit["sink_class"], "stdout");
        assert_eq!(audit["keyed_integrity"], "none");
        assert_eq!(audit["hash_chain"], "process_local");
        assert_eq!(audit["anchoring"], "none");
    }

    /// `write_policy` is reported truthfully from config, not assumed.
    #[test]
    fn audit_assurance_write_policy_follows_config() {
        let mut config = parse_minimal_config(&minimal_config_yaml());
        config.audit.write_policy = AuditWritePolicy::AvailabilityFirst;
        let audit = audit_assurance(&config);
        assert_eq!(audit["write_policy"], "availability_first");
    }

    #[test]
    fn posture_audit_summary_reports_shipping_state() {
        let mut config = parse_minimal_config(&minimal_config_yaml());
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_target_configured"], true);
        assert_eq!(audit["shipping_target"], "stdout");

        config.audit.sink = crate::config::AuditSinkConfig::File {
            path: std::path::PathBuf::from("/tmp/relay-audit.jsonl"),
            rotate: crate::config::RotateConfig::default(),
        };
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_target_configured"], false);
        assert_eq!(audit["shipping_target"], "none");

        config.deployment.evidence.audit_offhost_shipping = true;
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_target_configured"], true);
        assert_eq!(audit["shipping_target"], "declared_external");
    }

    #[test]
    fn posture_audit_summary_reports_shipping_health() {
        // Stdout ships inherently and has no cursor: health is "unverified",
        // observed_at is null.
        let mut config = parse_minimal_config(&minimal_config_yaml());
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_health"], "unverified");
        assert!(audit["shipping_observed_at"].is_null());

        // A local file sink with no off-host shipping has no shipping target, so
        // health is null (not "unverified").
        config.audit.sink = crate::config::AuditSinkConfig::File {
            path: std::path::PathBuf::from("/tmp/relay-audit.jsonl"),
            rotate: crate::config::RotateConfig::default(),
        };
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_target_configured"], false);
        assert!(audit["shipping_health"].is_null());
        assert!(audit["shipping_observed_at"].is_null());

        // A fresh cursor is still unverified until runtime binds its watermark
        // to the live keyed chain tail.
        config.deployment.evidence.audit_offhost_shipping = true;
        let dir = tempfile::tempdir().expect("tempdir");
        let cursor_path = dir.path().join("ack-cursor.json");
        let acked_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("rfc3339 timestamp");
        std::fs::write(
            &cursor_path,
            format!(
                r#"{{"schema":"registry.audit.ack_cursor.v1","acked_at":"{acked_at}","last_acked_hash":"sha256:{hash}","writer":"test-shipper"}}"#,
                hash = "4".repeat(64)
            ),
        )
        .expect("cursor writes");
        config.deployment.evidence.audit_ack_cursor_path = Some(cursor_path.clone());
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_health"], "unverified");
        assert_eq!(audit["shipping_observed_at"], acked_at);
        let observation =
            crate::deployment::audit_ack_observation(&config).bind_to_audit_tail(Some([0x44; 32]));
        let audit = audit_summary_with_observation(&config, &observation);
        assert_eq!(audit["shipping_health"], "ok");
        assert_eq!(audit["shipping_observed_at"], acked_at);

        // Removing the file leaves the cursor configured but missing: fail
        // closed to "missing".
        std::fs::remove_file(&cursor_path).expect("cursor removed");
        let audit = audit_summary(&config);
        assert_eq!(audit["shipping_health"], "missing");
        assert!(audit["shipping_observed_at"].is_null());
    }

    #[test]
    fn named_posture_example_audit_matches_live_projection() {
        let mut config = parse_minimal_config(&minimal_config_yaml());
        config.audit.sink = crate::config::AuditSinkConfig::File {
            path: std::path::PathBuf::from("/tmp/relay-audit.jsonl"),
            rotate: crate::config::RotateConfig::default(),
        };
        config.audit.chain = true;
        config.deployment.evidence.audit_offhost_shipping = true;
        let observation = registry_platform_ops::AckObservation {
            health: registry_platform_ops::AckHealth::Ok,
            acked_at: Some("2026-06-04T09:59:00Z".to_string()),
            last_acked_hash: Some(format!("sha256:{}", "4".repeat(64))),
            detail: None,
        };
        let live = audit_summary_with_observation(&config, &observation);
        let example: Value = serde_json::from_str(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1)
            .expect("named Relay posture example parses");

        assert_eq!(example["posture"]["audit"], live);
    }

    /// An undeclared profile (the minimal config default) omits `profile`,
    /// reports the single `deployment.profile_undeclared` startup finding, and
    /// carries no waivers. The server startup path rejects this before posture is
    /// served; this unit test pins the serializer for diagnostic callers.
    #[test]
    fn deployment_summary_undeclared_profile_reports_startup_failure() {
        let config = parse_minimal_config(&minimal_config_yaml());
        assert!(config.deployment.profile.is_none());
        let summary = deployment_summary(&config, ConfigSource::LocalFile);
        assert!(
            summary.get("profile").is_none(),
            "undeclared profile must not be reported"
        );
        let findings = summary["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["id"], crate::deployment::PROFILE_UNDECLARED);
        assert_eq!(findings[0]["severity"], "startup_fail");
        assert_eq!(findings[0]["status"], "active");
        assert!(summary["waivers"].as_array().expect("waivers").is_empty());
    }

    /// A declared profile is echoed in the summary. `hosted_lab` here triggers
    /// the api-key-no-rotation and config-unsigned findings (no evidence
    /// declared, local file), all at finding-level severity.
    #[test]
    fn deployment_summary_declared_profile_reports_findings() {
        let mut config = parse_minimal_config(&minimal_config_yaml());
        config.deployment.profile = Some(DeploymentProfile::HostedLab);
        let summary = deployment_summary(&config, ConfigSource::LocalFile);
        assert_eq!(summary["profile"], "hosted_lab");
        let ids: Vec<&str> = summary["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .map(|finding| finding["id"].as_str().expect("finding id"))
            .collect();
        assert!(ids.contains(&"relay.config.unsigned"));
        assert!(ids.contains(&"relay.auth.api_key_no_rotation_evidence"));
        assert!(ids.contains(&"relay.ingress.rate_limit_missing"));
    }

    /// The full posture document is schema-valid for every declared profile and
    /// for the undeclared default. `evidence_grade` from a local file would
    /// trip a startup gate at load time, so its posture is exercised with a
    /// signed (governed-bundle) source where no startup gate fires.
    #[test]
    fn posture_document_is_schema_valid_across_profiles() {
        let config = parse_minimal_config(&minimal_config_yaml());
        assert_posture_schema_valid(&build_default_tier_posture(&config));

        for profile in [
            DeploymentProfile::Local,
            DeploymentProfile::HostedLab,
            DeploymentProfile::Production,
        ] {
            let mut config = parse_minimal_config(&minimal_config_yaml());
            config.deployment.profile = Some(profile);
            assert_posture_schema_valid(&build_default_tier_posture(&config));
        }

        // Evidence-grade: declare the operator evidence and use a signed source
        // so no startup gate fires, then confirm the posture validates.
        let mut config = parse_minimal_config(&minimal_config_yaml());
        config.deployment.profile = Some(DeploymentProfile::EvidenceGrade);
        config.deployment.evidence.ingress_rate_limit = true;
        config.deployment.evidence.api_key_rotation = true;
        let posture = build_posture(
            &config,
            None,
            None,
            empty_posture_metadata(),
            PostureTier::Default,
        )
        .expect("evidence-grade posture builds");
        assert_posture_schema_valid(&posture);
    }

    /// The default-tier allowlist exposes only finding id/severity/status; the
    /// whole deployment `waivers` block (finding, reason, expires) is dropped.
    /// The restricted tier returns the unfiltered document, so the waiver and
    /// its reason appear there. This pins the allowlist contract for the new
    /// deployment block, including that synthetic waiver reasons never leak at
    /// the default tier.
    #[test]
    fn posture_default_tier_drops_waivers_restricted_keeps_them() {
        let mut config = parse_minimal_config(&minimal_config_yaml());
        config.deployment.profile = Some(DeploymentProfile::HostedLab);
        config.deployment.waivers = vec![crate::config::DeploymentWaiverConfig {
            finding: "relay.config.unsigned".to_string(),
            reason: "synthetic-waiver-reason-not-a-secret".to_string(),
            expires: "2999-01-01".to_string(),
        }];

        // Default tier: waivers array filtered away entirely, and the waived
        // finding carries no `waiver` sub-object.
        let default_tier = build_default_tier_posture(&config);
        assert!(
            default_tier["deployment"].get("waivers").is_none(),
            "default tier must not expose the deployment waivers array"
        );
        let waived = default_tier["deployment"]["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .find(|finding| finding["id"] == "relay.config.unsigned")
            .expect("config.unsigned finding present");
        assert_eq!(waived["status"], "waived");
        assert!(
            waived.get("waiver").is_none(),
            "default tier must strip the per-finding waiver block"
        );
        let serialized = default_tier.to_string();
        assert!(
            !serialized.contains("synthetic-waiver-reason-not-a-secret"),
            "default-tier posture must never leak a waiver reason"
        );

        // Restricted tier: full document, waiver and reason present.
        let restricted = build_posture(
            &config,
            None,
            None,
            empty_posture_metadata(),
            PostureTier::Restricted,
        )
        .expect("restricted posture builds");
        let restricted_waivers = restricted["deployment"]["waivers"]
            .as_array()
            .expect("restricted waivers array");
        assert_eq!(restricted_waivers.len(), 1);
        assert_eq!(restricted_waivers[0]["finding"], "relay.config.unsigned");
        assert_eq!(restricted_waivers[0]["expires"], "2999-01-01");
        assert_eq!(
            restricted_waivers[0]["reason"],
            "synthetic-waiver-reason-not-a-secret"
        );
    }

    /// Default-config posture regression: the gate train adds exactly the
    /// `deployment` and `audit` top-level blocks and nothing else. The default
    /// config declares no profile, so `deployment` is exactly the single
    /// `profile_undeclared` startup finding, and `audit` is the eight assurance
    /// facts at their default values. This pins the serializer for diagnostic
    /// callers; server startup rejects the same config before posture is served.
    #[test]
    fn default_config_posture_regression() {
        let config = parse_minimal_config(&minimal_config_yaml());
        let posture = build_default_tier_posture(&config);

        // Top-level shape is stable. `observed_at` is volatile, so we pin the
        // key set rather than the whole document.
        let mut keys: Vec<&str> = posture
            .as_object()
            .expect("posture is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "audit",
                "build",
                "component",
                "configuration",
                "deployment",
                "instance",
                "observed_at",
                "posture",
                "relay",
                "runtime",
                "schema",
                "standards_artifacts",
                "tier",
            ],
            "default-config posture top-level keys changed"
        );

        // `deployment`: undeclared profile, single startup finding, no waivers.
        assert_eq!(
            posture["deployment"],
            json!({
                "findings": [
                    {
                        "id": crate::deployment::PROFILE_UNDECLARED,
                        "severity": "startup_fail",
                        "status": "active",
                    }
                ],
            }),
            "default-config deployment block changed"
        );

        // `audit`: the eight assurance facts at their default-config values.
        assert_eq!(
            posture["audit"],
            json!({
                "write_policy": "fail_closed",
                "redaction_mode": "redacted",
                "hash_chain": "process_local",
                "keyed_integrity": "none",
                "sink_class": "stdout",
                "retention_owner": "operator",
                "checkpoints": "supported",
                "anchoring": "none",
            }),
            "default-config audit assurance block changed"
        );
    }
}
