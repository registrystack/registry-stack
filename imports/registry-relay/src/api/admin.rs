// SPDX-License-Identifier: Apache-2.0
//! Admin HTTP routes.
//!
//! This module owns the route surface only. Server/auth integration can
//! install the router and `IngestRegistry` extension from the admin
//! listener when that wiring lands.

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use registry_manifest_core::CompiledMetadata;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::audit::ErrorCodeExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{AuthMode, Config, DatasetId, IssuerConfig, ResourceId};
use crate::error::{AdminError, AuthError, Error, IngestError};
use crate::ingest::{IngestRegistry, ReadinessSnapshot};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RELOAD_FAILED_CODE: &str = "admin.reload_failed";
const RELOAD_UNAVAILABLE_CODE: &str = "admin.reload_unavailable";
const OPS_READ_SCOPE: &str = "registry_relay:ops_read";

/// Sub-router for admin reload routes.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin/v1/posture", get(posture))
        .route("/admin/v1/reload", post(reload_all))
        .route(
            "/admin/v1/datasets/{dataset_id}/tables/{table_id}/reload",
            post(reload_table),
        )
}

#[derive(Debug, Deserialize)]
struct ReloadTablePath {
    dataset_id: DatasetId,
    table_id: ResourceId,
}

async fn reload_table(
    Path(path): Path<ReloadTablePath>,
    registry: Option<Extension<Arc<IngestRegistry>>>,
    readiness_tx: Option<Extension<watch::Sender<ReadinessSnapshot>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(registry)) = registry else {
        return reload_unavailable(
            "admin table reload route matched, but ingest registry is not installed",
        );
    };
    if let Err(error) = require_admin_scope(principal) {
        return error.into_response();
    }

    let result = registry.reload(&path.dataset_id, &path.table_id).await;
    publish_readiness(readiness_tx, &registry);

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

async fn reload_all(
    registry: Option<Extension<Arc<IngestRegistry>>>,
    readiness_tx: Option<Extension<watch::Sender<ReadinessSnapshot>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_admin_scope(principal) {
        return error.into_response();
    }
    let Some(Extension(registry)) = registry else {
        return reload_unavailable(
            "admin reload-all route matched, but ingest registry is not installed",
        );
    };

    let report = registry.reload_all().await;
    publish_readiness(readiness_tx, &registry);
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

async fn posture(
    config: Option<Extension<Arc<Config>>>,
    readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>,
    metadata: Option<Extension<Arc<CompiledMetadata>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    if let Err(error) = require_ops_scope(principal) {
        return error.into_response();
    }
    let Some(Extension(config)) = config else {
        return Error::from(AdminError::UnknownResource).into_response();
    };
    let snapshot = readiness.map(|Extension(rx)| rx.borrow().clone());
    Json(build_posture(
        &config,
        snapshot.as_ref(),
        metadata.as_ref().map(|Extension(m)| m.as_ref()),
    ))
    .into_response()
}

fn build_posture(
    config: &Config,
    readiness: Option<&ReadinessSnapshot>,
    metadata: Option<&CompiledMetadata>,
) -> Value {
    let warnings = posture_warnings(config, readiness);
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
    json!({
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
            "source": "local_file",
            "dynamic_reload_supported": false,
            "last_config_hash": config_hash(config),
            "last_bundle_id": null,
            "last_bundle_sequence": null,
            "last_apply_result": null,
            "last_apply_at": null,
            "restart_required": false,
        },
        "standards_artifacts": standards_artifacts(config),
        "relay": {
            "dataset_count": config.datasets.len(),
            "entity_count": config.datasets.iter().map(|dataset| dataset.entities.len()).sum::<usize>(),
            "aggregate_count": config.datasets.iter().map(|dataset| dataset.aggregates.len() + dataset.tables.iter().map(|table| table.aggregates.len()).sum::<usize>()).sum::<usize>(),
            "evidence_offering_count": metadata.map(|compiled| compiled.evidence_offerings().count()).unwrap_or(0),
            "metadata_manifest": {
                "configured": config.metadata.is_some(),
            },
            "provenance": provenance_summary(config),
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
    })
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

fn provenance_summary(config: &Config) -> Value {
    let Some(provenance) = &config.provenance else {
        return json!({
            "enabled": false,
            "retired_kids": [],
        });
    };
    let (issuer, active_kid, retired_kids) = match &provenance.issuer {
        IssuerConfig::Gateway(issuer) => (
            issuer.did.as_str(),
            issuer.verification_method_id.as_str(),
            issuer
                .retired_keys
                .iter()
                .map(|key| key.verification_method_id.as_str())
                .collect::<Vec<_>>(),
        ),
        IssuerConfig::Delegated(issuer) => (
            issuer.ministry_did.as_str(),
            issuer.verification_method_id.as_str(),
            issuer
                .retired_keys
                .iter()
                .map(|key| key.verification_method_id.as_str())
                .collect::<Vec<_>>(),
        ),
    };
    json!({
        "enabled": provenance.enabled,
        "issuer": issuer,
        "active_kid": active_kid,
        "retired_kids": retired_kids,
    })
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

fn config_hash(config: &Config) -> String {
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
        "provenance": provenance_summary(config),
    });
    let bytes = serde_json::to_vec(&public_shape).expect("public config shape serializes");
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn readiness_label(readiness: Option<&ReadinessSnapshot>) -> &'static str {
    match readiness {
        Some(snapshot) if snapshot.fully_ready() => "ready",
        Some(_) => "degraded",
        None => "unknown",
    }
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
    readiness_tx: Option<Extension<watch::Sender<ReadinessSnapshot>>>,
    registry: &IngestRegistry,
) {
    if let Some(Extension(readiness_tx)) = readiness_tx {
        let _ = readiness_tx.send(registry.snapshot());
    }
}

fn require_admin_scope(principal: Option<Extension<Principal>>) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, "admin")
}

fn require_ops_scope(principal: Option<Extension<Principal>>) -> Result<(), Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(&principal, OPS_READ_SCOPE)
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
