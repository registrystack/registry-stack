// SPDX-License-Identifier: Apache-2.0
//! Redacted Registry Ops posture for standalone Registry Notary.

use std::collections::{BTreeMap, BTreeSet};

use registry_notary_core::{
    BulkMode, CredentialStatusConfig, EvidenceAuditConfig, StandaloneRegistryNotaryConfig,
    CREDENTIAL_STATUS_STORAGE_REDIS, REPLAY_STORAGE_IN_MEMORY, REPLAY_STORAGE_REDIS,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    format_time, replay::ReplayReadiness, standalone::AuditPipeline, RegistryNotaryApiState,
};

#[derive(Clone, Debug)]
pub(crate) struct PostureContext {
    instance: InstancePosture,
    auth_mode: String,
    config_hash: String,
    replay_storage: String,
    credential_status_enabled: bool,
    credential_status_storage: String,
    audit: AuditPosture,
    source_connections: SourceConnectionPosture,
}

#[derive(Clone, Debug)]
struct InstancePosture {
    id: String,
    environment: String,
    owner: Option<String>,
    jurisdiction: Option<String>,
    public_base_url: Option<String>,
}

#[derive(Clone, Debug)]
struct AuditPosture {
    sink: String,
    configured: bool,
}

#[derive(Clone, Debug)]
struct SourceConnectionPosture {
    by_kind: BTreeMap<String, usize>,
}

impl PostureContext {
    pub(crate) fn from_config(
        config: &StandaloneRegistryNotaryConfig,
        _audit: &AuditPipeline,
    ) -> Self {
        Self {
            instance: InstancePosture {
                id: config.instance.id.clone(),
                environment: config.instance.environment.clone(),
                owner: config.instance.owner.clone(),
                jurisdiction: config.instance.jurisdiction.clone(),
                public_base_url: config.instance.public_base_url.clone(),
            },
            auth_mode: config.auth.mode.clone(),
            config_hash: config_hash(config),
            replay_storage: classify_replay_storage(config.replay.storage.as_str()),
            credential_status_enabled: config.credential_status.enabled,
            credential_status_storage: classify_credential_status_storage(
                &config.credential_status,
            ),
            audit: audit_posture(&config.audit),
            source_connections: SourceConnectionPosture {
                by_kind: source_connection_counts_by_kind(config),
            },
        }
    }
}

pub(crate) async fn posture_document(state: &RegistryNotaryApiState) -> Value {
    let replay_ready = state.replay.check_ready().await;
    let replay_ready_bool = replay_ready.is_ok();
    let credential_status_ready = state.credential_status.check_ready().await.is_ok();
    let signer_ready = state.signer_readiness.is_ready();
    let readiness = if replay_ready_bool && credential_status_ready && signer_ready {
        "ready"
    } else if matches!(replay_ready, Ok(ReplayReadiness::Degraded))
        && credential_status_ready
        && signer_ready
    {
        "degraded"
    } else {
        "not_ready"
    };

    let context = state
        .posture
        .as_ref()
        .map(|context| (**context).clone())
        .unwrap_or_else(default_posture_context);
    let mut warnings = Vec::<String>::new();
    let mut findings = Vec::new();
    if production_like(context.instance.environment.as_str())
        && context.replay_storage == REPLAY_STORAGE_IN_MEMORY
    {
        let finding = json!({
            "id": "notary.replay.in_memory.production",
            "severity": "high",
            "title": "Production Notary uses in-memory replay storage",
            "detail": "Multiple instances cannot share replay decisions.",
            "evidence": [
                {
                    "field": "notary.replay.storage",
                    "value": "in_memory"
                }
            ],
            "standards_refs": [],
            "recommended_action": "Use Redis replay storage before enabling active-active production traffic."
        });
        warnings.push("notary.replay.in_memory.production".to_string());
        findings.push(finding);
    }
    if !context.audit.configured {
        warnings.push("notary.audit.not_configured".to_string());
    }

    let mut instance = Map::new();
    instance.insert("id".to_string(), json!(context.instance.id));
    instance.insert(
        "environment".to_string(),
        json!(context.instance.environment),
    );
    if let Some(owner) = context.instance.owner {
        instance.insert("owner".to_string(), json!(owner));
    }
    if let Some(jurisdiction) = context.instance.jurisdiction {
        instance.insert("jurisdiction".to_string(), json!(jurisdiction));
    }
    if let Some(public_base_url) = context.instance.public_base_url {
        instance.insert("public_base_url".to_string(), json!(public_base_url));
    }

    json!({
        "schema": "registry.ops.posture.v1",
        "observed_at": format_time(OffsetDateTime::now_utc()),
        "component": "registry-notary",
        "tier": "default",
        "instance": instance,
        "build": {
            "package": "registry-notary",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "runtime": {
            "auth_mode": context.auth_mode,
            "admin_enabled": true,
            "readiness": readiness,
        },
        "configuration": {
            "source": "local_file",
            "dynamic_reload_supported": false,
            "last_config_hash": context.config_hash,
            "last_bundle_id": Value::Null,
            "last_bundle_sequence": Value::Null,
            "last_apply_result": Value::Null,
            "last_apply_at": Value::Null,
            "restart_required": false,
        },
        "standards_artifacts": standards_artifacts(state),
        "notary": {
            "claim_count": state.evidence.claims.len(),
            "source_connection_counts": context.source_connections.by_kind,
            "credential_profile_count": state.evidence.credential_profiles.len(),
            "replay": {
                "storage": context.replay_storage,
                "ready": replay_ready_bool,
            },
            "credential_status": {
                "enabled": context.credential_status_enabled,
                "storage": context.credential_status_storage,
            },
            "federation": federation_summary(state),
            "oid4vci": {
                "enabled": state.oid4vci.enabled,
                "credential_configuration_count": state.oid4vci.credential_configurations.len(),
            },
        },
        "posture": {
            "warnings": warnings,
            "findings": findings,
            "audit": {
                "configured": context.audit.configured,
                "sink_type": context.audit.sink,
                "checkpoint_status": "unavailable",
                "latest_tail_hash": Value::Null,
                "latest_sequence": Value::Null,
                "verified_at": Value::Null,
                "verification_status": "not_supported",
            },
        },
    })
}

fn default_posture_context() -> PostureContext {
    PostureContext {
        instance: InstancePosture {
            id: "registry-notary-standalone".to_string(),
            environment: "development".to_string(),
            owner: None,
            jurisdiction: None,
            public_base_url: None,
        },
        auth_mode: "unknown".to_string(),
        config_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        replay_storage: REPLAY_STORAGE_IN_MEMORY.to_string(),
        credential_status_enabled: false,
        credential_status_storage: "disabled".to_string(),
        audit: AuditPosture {
            sink: "unknown".to_string(),
            configured: false,
        },
        source_connections: SourceConnectionPosture {
            by_kind: BTreeMap::new(),
        },
    }
}

fn config_hash(config: &StandaloneRegistryNotaryConfig) -> String {
    let value = serde_json::to_value(config).unwrap_or(Value::Null);
    let bytes = canonical_json_bytes(value);
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn canonical_json_bytes(mut value: Value) -> Vec<u8> {
    sort_json(&mut value);
    serde_json::to_vec(&value).unwrap_or_default()
}

fn sort_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let sorted = std::mem::take(map).into_iter().collect::<BTreeMap<_, _>>();
            for (key, mut child) in sorted {
                sort_json(&mut child);
                map.insert(key, child);
            }
        }
        Value::Array(items) => {
            for item in items {
                sort_json(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn classify_replay_storage(storage: &str) -> String {
    match storage {
        REPLAY_STORAGE_REDIS => REPLAY_STORAGE_REDIS.to_string(),
        _ => REPLAY_STORAGE_IN_MEMORY.to_string(),
    }
}

fn classify_credential_status_storage(config: &CredentialStatusConfig) -> String {
    if !config.enabled {
        "disabled".to_string()
    } else if config.storage == CREDENTIAL_STATUS_STORAGE_REDIS {
        "redis".to_string()
    } else {
        "in_memory".to_string()
    }
}

fn audit_posture(config: &EvidenceAuditConfig) -> AuditPosture {
    AuditPosture {
        sink: match config.sink.as_str() {
            "file" | "jsonl" => "file".to_string(),
            "syslog" => "syslog".to_string(),
            "stdout" => "stdout".to_string(),
            _ => "unknown".to_string(),
        },
        configured: config.hash_secret_env.is_some(),
    }
}

fn source_connection_counts_by_kind(
    config: &StandaloneRegistryNotaryConfig,
) -> BTreeMap<String, usize> {
    let mut seen = BTreeSet::new();
    let mut seen_connections = BTreeSet::new();
    let mut counts = BTreeMap::new();
    for claim in &config.evidence.claims {
        for binding in claim.source_bindings.values() {
            let Some(connection) = binding.connection.as_deref() else {
                continue;
            };
            seen_connections.insert(connection.to_string());
            if !seen.insert((
                connection.to_string(),
                source_connector_kind(binding.connector),
            )) {
                continue;
            }
            *counts
                .entry(source_connector_kind(binding.connector).to_string())
                .or_insert(0) += 1;
        }
    }
    for (connection_id, connection) in &config.evidence.source_connections {
        if seen_connections.contains(connection_id) {
            continue;
        }
        *counts
            .entry(unused_source_connection_kind(connection.bulk_mode).to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn unused_source_connection_kind(bulk_mode: BulkMode) -> &'static str {
    match bulk_mode {
        BulkMode::RdaInFilter => "registry_data_api",
        BulkMode::DciBatchedSearch => "dci",
        BulkMode::OpenFnSidecarBatch => "openfn_sidecar",
        BulkMode::None => "unknown",
    }
}

fn source_connector_kind(kind: registry_notary_core::SourceConnectorKind) -> &'static str {
    match kind {
        registry_notary_core::SourceConnectorKind::RegistryDataApi => "registry_data_api",
        registry_notary_core::SourceConnectorKind::Dci => "dci",
        registry_notary_core::SourceConnectorKind::OpenFnSidecar => "openfn_sidecar",
    }
}

fn federation_summary(state: &RegistryNotaryApiState) -> Value {
    let allowed_profiles = state
        .federation
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_profiles.iter().cloned())
        .collect::<BTreeSet<_>>();
    let allowed_purposes = state
        .federation
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_purposes.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut summary = Map::new();
    summary.insert("enabled".to_string(), json!(state.federation.enabled));
    if state.federation.enabled {
        summary.insert("node_id".to_string(), json!(state.federation.node_id));
    }
    summary.insert(
        "peer_count".to_string(),
        json!(state.federation.peers.len()),
    );
    summary.insert(
        "supported_protocol_versions".to_string(),
        json!(state.federation.supported_protocol_versions),
    );
    summary.insert(
        "allowed_profile_count".to_string(),
        json!(allowed_profiles.len()),
    );
    summary.insert(
        "allowed_purpose_count".to_string(),
        json!(allowed_purposes.len()),
    );
    Value::Object(summary)
}

fn standards_artifacts(state: &RegistryNotaryApiState) -> Value {
    json!({
        "evidence_service_discovery": artifact_ref(
            service_url(&state.evidence.api_base_url, "/.well-known/evidence-service"),
            "application/json",
        ),
        "jwks": artifact_ref(
            service_url(&state.evidence.api_base_url, "/.well-known/evidence/jwks.json"),
            "application/json",
        ),
        "openapi": artifact_ref(
            service_url(&state.evidence.api_base_url, "/openapi.json"),
            "application/json",
        ),
        "oid4vci_issuer_metadata": if state.oid4vci.enabled {
            artifact_ref(
                service_url(&state.evidence.api_base_url, "/.well-known/openid-credential-issuer"),
                "application/json",
            )
        } else {
            json!({ "observed_status": "not_configured" })
        },
    })
}

fn artifact_ref(url: Option<String>, media_type: &str) -> Value {
    match url {
        Some(url) => json!({
            "url": url,
            "media_type": media_type,
            "observed_status": "configured_not_checked",
        }),
        None => json!({ "observed_status": "not_configured" }),
    }
}

fn service_url(base_url: &str, path: &str) -> Option<String> {
    let base = base_url.trim_end_matches('/');
    if base.starts_with("https://") {
        Some(format!("{base}{path}"))
    } else {
        None
    }
}

fn production_like(environment: &str) -> bool {
    matches!(
        environment.to_ascii_lowercase().as_str(),
        "production" | "prod" | "pilot" | "staging" | "production-like"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_bytes_sorts_nested_objects() {
        let left = json!({
            "b": 1,
            "a": {
                "z": true,
                "y": false
            },
            "c": [
                {
                    "d": "last",
                    "a": "first"
                }
            ]
        });
        let right = json!({
            "c": [
                {
                    "a": "first",
                    "d": "last"
                }
            ],
            "a": {
                "y": false,
                "z": true
            },
            "b": 1
        });

        assert_eq!(canonical_json_bytes(left), canonical_json_bytes(right));
    }

    #[test]
    fn production_like_environment_is_case_insensitive() {
        assert!(production_like("Production"));
        assert!(production_like("STAGING"));
        assert!(production_like("production-like"));
        assert!(!production_like("development"));
    }
}
