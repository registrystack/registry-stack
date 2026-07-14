// SPDX-License-Identifier: Apache-2.0
//! Redacted Registry Ops posture for standalone Registry Notary.

use registry_notary_core::{
    CredentialStatusConfig, DeploymentEvidenceConfig, EvidenceAuditConfig, SelfAttestationConfig,
    SelfAttestationRateLimitMode, SigningKeyStatus, StandaloneRegistryNotaryConfig,
    CREDENTIAL_STATUS_STORAGE_REDIS, MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS,
    REPLAY_STORAGE_IN_MEMORY, REPLAY_STORAGE_REDIS,
};
use registry_platform_ops::{
    audit_shipping_target, filter_posture_for_tier, override_pin_posture,
    posture_safe_runtime_config_hash, AckObservation, AuditSinkKind, PostureFilterError,
    PostureTier,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

use crate::{
    api::{ConfigApplyPosture, ConfigEmergencyPosture},
    format_time,
    replay::ReplayReadiness,
    standalone::{AuditPipeline, DeploymentGateState},
    RegistryNotaryApiState,
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
    signing_keys: SigningKeyPosture,
    oid4vci: Oid4vciPosture,
    self_attestation: SelfAttestationPosture,
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
    shipping_target_configured: bool,
    shipping_target: String,
    /// Observed off-host shipping health from the local ack cursor. `None`
    /// (rendered null) iff `shipping_target_configured` is false. Runtime `ok`
    /// requires freshness plus a watermark bound to the live keyed chain tail.
    shipping_health: Option<String>,
    /// The ack cursor's `acked_at` when one was read, else `None` (null).
    shipping_observed_at: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct SigningKeyPosture {
    active: Vec<String>,
    publish_only: Vec<String>,
    disabled: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SigningKeyPostureError {
    UnknownStatus { key_id: String },
}

impl SigningKeyPostureError {
    pub(crate) fn key_id(&self) -> &str {
        match self {
            Self::UnknownStatus { key_id } => key_id,
        }
    }
}

#[derive(Debug)]
pub(crate) enum PostureDocumentError {
    Filter(PostureFilterError),
    SigningKey(SigningKeyPostureError),
}

#[derive(Clone, Debug)]
struct Oid4vciPosture {
    pre_authorized_code_enabled: bool,
    pre_authorized_code_ttl_seconds: u64,
    tx_code_required: bool,
    offer_security_mode: String,
}

#[derive(Clone, Debug)]
struct SelfAttestationPosture {
    enabled: bool,
    allowed_claim_count: usize,
    allowed_purpose_count: usize,
    credential_profile_count: usize,
    wallet_origin_count: usize,
    rate_limit_mode: String,
}

impl PostureContext {
    pub(crate) fn from_config(
        config: &StandaloneRegistryNotaryConfig,
        _audit: &AuditPipeline,
    ) -> Result<Self, SigningKeyPostureError> {
        // Runtime posture replaces this boot-time placeholder with one bounded
        // cursor sample bound to the live audit tail.
        let audit_observation = registry_platform_ops::AckObservation::unverified();
        Ok(Self {
            instance: InstancePosture {
                id: config.instance.id.clone(),
                environment: config.instance.environment.clone(),
                owner: config.instance.owner.clone(),
                jurisdiction: config.instance.jurisdiction.clone(),
                public_base_url: config.instance.public_base_url.clone(),
            },
            auth_mode: config.auth.mode.as_str().to_string(),
            config_hash: config_hash(config),
            replay_storage: classify_replay_storage(config.replay.storage.as_str()),
            credential_status_enabled: config.credential_status.enabled,
            credential_status_storage: classify_credential_status_storage(
                &config.credential_status,
            ),
            audit: audit_posture(
                &config.audit,
                &config.deployment.evidence,
                &audit_observation,
            ),
            signing_keys: signing_key_posture(config)?,
            oid4vci: oid4vci_posture(config),
            self_attestation: self_attestation_posture(&config.self_attestation),
        })
    }
}

pub(crate) async fn posture_document(
    state: &RegistryNotaryApiState,
    tier: PostureTier,
) -> Result<Value, PostureDocumentError> {
    let replay_ready = state.replay.check_ready().await;
    let replay_ready_bool = matches!(replay_ready, Ok(ReplayReadiness::Ready));
    let credential_status_ready = state.credential_status.check_ready().await.is_ok();
    let signer_readiness = state.signer_readiness();
    let signer_ready = signer_readiness.is_ready();
    let config_apply = state.config_apply_posture();
    let runtime_config = state.runtime_config();
    let (deployment_gates, current_audit) = match runtime_config.as_deref() {
        Some(config) => {
            let observation = state.current_audit_ack_observation(config).await;
            (
                state.deployment_gates_for_observation(config, &observation),
                Some(audit_posture(
                    &config.audit,
                    &config.deployment.evidence,
                    &observation,
                )),
            )
        }
        None => ((*state.deployment_gates).clone(), None),
    };
    let deployment_ready = !deployment_gates.has_readiness_failure();
    let readiness =
        if replay_ready_bool && credential_status_ready && signer_ready && deployment_ready {
            "ready"
        } else if matches!(replay_ready, Ok(ReplayReadiness::Degraded))
            && credential_status_ready
            && signer_ready
            && deployment_ready
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
    let audit = current_audit.unwrap_or_else(|| context.audit.clone());
    let signing_keys = match runtime_config.as_deref() {
        Some(config) => signing_key_posture(config).map_err(PostureDocumentError::SigningKey)?,
        None => context.signing_keys.clone(),
    };
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
    if context.oid4vci.pre_authorized_code_enabled && !context.oid4vci.tx_code_required {
        let finding = json!({
            "id": "notary.oid4vci.bearer_offer",
            "severity": "medium",
            "title": "OID4VCI pre-authorized-code offers run without tx_code",
            "detail": "A copied offer URI can be redeemed until the pre-authorized code expires.",
            "evidence": [
                {
                    "field": "notary.oid4vci.offer_security_mode",
                    "value": context.oid4vci.offer_security_mode.as_str()
                },
                {
                    "field": "notary.oid4vci.pre_authorized_code_ttl_seconds",
                    "value": context.oid4vci.pre_authorized_code_ttl_seconds
                },
                {
                    "field": "notary.oid4vci.max_bearer_pre_authorized_code_ttl_seconds",
                    "value": MAX_BEARER_PRE_AUTHORIZED_CODE_TTL_SECONDS
                }
            ],
            "standards_refs": [],
            "recommended_action": "Require tx_code where wallets support it; otherwise keep bearer-offer mode limited to controlled demos."
        });
        warnings.push("notary.oid4vci.bearer_offer".to_string());
        findings.push(finding);
    }

    let mut instance = Map::new();
    instance.insert("id".to_string(), json!(context.instance.id));
    instance.insert(
        "environment".to_string(),
        json!(context.instance.environment),
    );
    if let Some(owner) = &context.instance.owner {
        instance.insert("owner".to_string(), json!(owner));
    }
    if let Some(jurisdiction) = &context.instance.jurisdiction {
        instance.insert("jurisdiction".to_string(), json!(jurisdiction));
    }
    if let Some(public_base_url) = &context.instance.public_base_url {
        instance.insert("public_base_url".to_string(), json!(public_base_url));
    }

    let deployment = deployment_object(&deployment_gates);
    let audit_assurance = audit_assurance_object(runtime_config.as_deref());
    let configuration = configuration_object(&config_apply, &context);

    let posture = json!({
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
        "deployment": deployment,
        "audit": audit_assurance,
        "configuration": configuration,
        "standards_artifacts": standards_artifacts(state),
        "notary": {
            "claim_count": state.evidence.claims.len(),
            "signing_keys": {
                "active": signing_keys.active,
                "publish_only": signing_keys.publish_only,
                "disabled": signing_keys.disabled,
                "readiness": signing_key_readiness_by_kid(state),
            },
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
            "self_attestation": {
                "enabled": context.self_attestation.enabled,
                "allowed_claim_count": context.self_attestation.allowed_claim_count,
                "allowed_purpose_count": context.self_attestation.allowed_purpose_count,
                "credential_profile_count": context.self_attestation.credential_profile_count,
                "wallet_origin_count": context.self_attestation.wallet_origin_count,
                "rate_limit_mode": context.self_attestation.rate_limit_mode,
            },
        },
        "posture": {
            "warnings": warnings,
            "findings": findings,
            "audit": audit_posture_object(&audit),
        },
    });
    filter_posture_for_tier(posture, tier).map_err(PostureDocumentError::Filter)
}

fn audit_posture_object(audit: &AuditPosture) -> Value {
    json!({
        "configured": audit.configured,
        "sink_type": audit.sink,
        "shipping_target_configured": audit.shipping_target_configured,
        "shipping_target": audit.shipping_target,
        "shipping_health": audit.shipping_health,
        "shipping_observed_at": audit.shipping_observed_at,
        "checkpoint_status": "unavailable",
        "latest_tail_hash": Value::Null,
        "latest_sequence": Value::Null,
        "verified_at": Value::Null,
        "verification_status": "not_supported",
    })
}

fn configuration_object(config_apply: &ConfigApplyPosture, context: &PostureContext) -> Value {
    let mut configuration = Map::new();
    configuration.insert(
        "source".to_string(),
        json!(config_apply.source.as_posture_str()),
    );
    configuration.insert("dynamic_reload_supported".to_string(), json!(false));
    configuration.insert(
        "last_config_hash".to_string(),
        json!(config_apply
            .last_config_hash
            .as_deref()
            .unwrap_or(context.config_hash.as_str())),
    );
    configuration.insert(
        "last_bundle_id".to_string(),
        config_apply
            .last_bundle_id
            .as_ref()
            .map_or(Value::Null, |value| json!(value)),
    );
    configuration.insert(
        "last_bundle_sequence".to_string(),
        config_apply
            .last_bundle_sequence
            .map_or(Value::Null, |value| json!(value)),
    );
    configuration.insert(
        "last_bundle_signer_kids".to_string(),
        json!(config_apply.last_bundle_signer_kids),
    );
    configuration.insert(
        "last_apply_result".to_string(),
        config_apply
            .last_apply_result
            .map_or(Value::Null, |value| json!(value.as_str())),
    );
    configuration.insert(
        "last_apply_at".to_string(),
        config_apply
            .last_apply_at
            .as_ref()
            .map_or(Value::Null, |value| json!(value)),
    );
    configuration.insert(
        "restart_required".to_string(),
        json!(config_apply.restart_required),
    );
    if let Some(emergency) = &config_apply.emergency {
        configuration.insert(
            "emergency".to_string(),
            emergency_object(config_apply, emergency),
        );
    }
    if let Some(pin) = &config_apply.override_pin {
        configuration.insert("override".to_string(), override_pin_posture(pin));
    }
    Value::Object(configuration)
}

fn emergency_object(
    config_apply: &ConfigApplyPosture,
    emergency: &ConfigEmergencyPosture,
) -> Value {
    let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    let open_expiries = emergency
        .accepted_expires_at_unix_seconds
        .iter()
        .copied()
        .filter(|expires_at| *expires_at > now)
        .collect::<Vec<_>>();
    let exception_window_expires_at = open_expiries
        .iter()
        .copied()
        .max()
        .and_then(unix_seconds_rfc3339);
    let last_apply_emergency = config_apply
        .last_bundle_sequence
        .is_some_and(|sequence| sequence == emergency.last_emergency_sequence);

    json!({
        "last_apply_emergency": last_apply_emergency,
        "last_emergency_change_class": emergency.last_emergency_change_class,
        "last_emergency_at": emergency.last_emergency_at,
        "exception_window_open": !open_expiries.is_empty(),
        "exception_window_expires_at": exception_window_expires_at,
        "open_exception_count": open_expiries.len(),
    })
}

fn unix_seconds_rfc3339(seconds: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds.try_into().ok()?)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
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
            shipping_target_configured: false,
            shipping_target: "unknown".to_string(),
            shipping_health: None,
            shipping_observed_at: None,
        },
        signing_keys: SigningKeyPosture::default(),
        oid4vci: Oid4vciPosture {
            pre_authorized_code_enabled: false,
            pre_authorized_code_ttl_seconds: 0,
            tx_code_required: true,
            offer_security_mode: "disabled".to_string(),
        },
        self_attestation: SelfAttestationPosture {
            enabled: false,
            allowed_claim_count: 0,
            allowed_purpose_count: 0,
            credential_profile_count: 0,
            wallet_origin_count: 0,
            rate_limit_mode: "disabled".to_string(),
        },
    }
}

fn config_hash(config: &StandaloneRegistryNotaryConfig) -> String {
    let value = serde_json::to_value(config).expect("notary config serializes to JSON");
    posture_safe_runtime_config_hash(&value)
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

fn audit_posture(
    config: &EvidenceAuditConfig,
    evidence: &DeploymentEvidenceConfig,
    observation: &AckObservation,
) -> AuditPosture {
    // Map the config sink string onto the shared classifier's sink kinds; an
    // unrecognised sink is explicitly Unknown rather than a silent wildcard.
    let sink_kind = match config.sink.as_str() {
        "stdout" => AuditSinkKind::Stdout,
        "syslog" => AuditSinkKind::Syslog,
        "file" | "jsonl" => AuditSinkKind::LocalFile,
        _ => AuditSinkKind::Unknown,
    };
    let (shipping_target_configured, shipping_target) =
        audit_shipping_target(sink_kind, evidence.audit_offhost_shipping);
    let shipping_health =
        shipping_target_configured.then(|| observation.health.as_str().to_string());
    AuditPosture {
        sink: match config.sink.as_str() {
            "file" | "jsonl" => "file".to_string(),
            "syslog" => "syslog".to_string(),
            "stdout" => "stdout".to_string(),
            _ => "unknown".to_string(),
        },
        configured: config.hash_secret_env.is_some(),
        shipping_target_configured,
        shipping_target: shipping_target.to_string(),
        shipping_health,
        shipping_observed_at: observation.acked_at.clone(),
    }
}

/// Render the operator-declared deployment profile, gate findings, and active
/// waivers as the posture `deployment` object. The default tier strips waiver
/// reasons via the allowlist; this object carries them so the restricted tier
/// can surface them to Trust Operations.
fn deployment_object(gates: &DeploymentGateState) -> Value {
    let mut object = Map::new();
    if let Some(profile) = gates.profile {
        object.insert("profile".to_string(), json!(profile));
    }
    let findings = gates
        .findings
        .iter()
        .map(|finding| {
            let mut entry = Map::new();
            entry.insert("id".to_string(), json!(finding.id));
            entry.insert("severity".to_string(), json!(finding.severity.as_str()));
            entry.insert("status".to_string(), json!(finding.status.as_str()));
            if let Some(waiver) = &finding.waiver {
                entry.insert(
                    "waiver".to_string(),
                    json!({
                        "reason": waiver.reason,
                        "expires": waiver.expires,
                    }),
                );
            }
            Value::Object(entry)
        })
        .collect::<Vec<_>>();
    object.insert("findings".to_string(), Value::Array(findings));
    let waivers = gates
        .active_waivers
        .iter()
        .map(|waiver| {
            json!({
                "finding": waiver.finding,
                "reason": waiver.reason,
                "expires": waiver.expires,
            })
        })
        .collect::<Vec<_>>();
    object.insert("waivers".to_string(), Value::Array(waivers));
    Value::Object(object)
}

/// Render the audit assurance object: eight separate facts so "audit exists"
/// cannot be overclaimed. Protected routes fail closed once a hash secret is
/// configured; the keyed integrity is HMAC whenever that secret is present.
fn audit_assurance_object(config: Option<&StandaloneRegistryNotaryConfig>) -> Value {
    let audit = config.map(|config| &config.audit);
    let keyed = audit.is_some_and(|audit| audit.hash_secret_env.is_some());
    let sink_class = match audit.map(|audit| audit.sink.as_str()) {
        Some("file" | "jsonl") => "file",
        Some("syslog") => "external",
        Some("stdout") => "stdout",
        Some("none") => "none",
        Some(_) | None => "none",
    };
    let durable = matches!(sink_class, "file" | "external");
    json!({
        "write_policy": if keyed { "fail_closed_route_families" } else { "availability_first" },
        "redaction_mode": "redacted",
        "hash_chain": if keyed { "process_local" } else { "none" },
        "keyed_integrity": if keyed { "hmac" } else { "none" },
        "sink_class": sink_class,
        "retention_owner": if durable { "operator" } else { "unspecified" },
        "checkpoints": "unsupported",
        "anchoring": "none",
    })
}

fn signing_key_readiness_by_kid(state: &RegistryNotaryApiState) -> BTreeMap<String, String> {
    state
        .signer_readiness()
        .by_kid()
        .into_iter()
        .map(|entry| (entry.kid, entry.readiness.as_str().to_string()))
        .collect()
}

fn signing_key_posture(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<SigningKeyPosture, SigningKeyPostureError> {
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0);
    let mut posture = SigningKeyPosture::default();
    for (key_id, key) in &config.evidence.signing_keys {
        project_signing_key_status(
            key_id,
            Some(key.status),
            key.may_publish_at(now),
            &mut posture,
        )?;
    }
    Ok(posture)
}

fn project_signing_key_status(
    key_id: &str,
    status: Option<SigningKeyStatus>,
    currently_published: bool,
    posture: &mut SigningKeyPosture,
) -> Result<(), SigningKeyPostureError> {
    match status {
        Some(SigningKeyStatus::Active) => posture.active.push(key_id.to_string()),
        Some(SigningKeyStatus::PublishOnly) if currently_published => {
            posture.publish_only.push(key_id.to_string());
        }
        Some(SigningKeyStatus::PublishOnly) => {}
        Some(SigningKeyStatus::Disabled) => posture.disabled.push(key_id.to_string()),
        Some(_) | None => {
            return Err(SigningKeyPostureError::UnknownStatus {
                key_id: key_id.to_string(),
            })
        }
    }
    Ok(())
}

fn oid4vci_posture(config: &StandaloneRegistryNotaryConfig) -> Oid4vciPosture {
    let preauth = &config.oid4vci.pre_authorized_code;
    let offer_security_mode = if !config.oid4vci.enabled || !preauth.enabled {
        "disabled"
    } else if preauth.tx_code.required {
        "tx_code"
    } else {
        "bearer_offer"
    };
    Oid4vciPosture {
        pre_authorized_code_enabled: config.oid4vci.enabled && preauth.enabled,
        pre_authorized_code_ttl_seconds: preauth.pre_authorized_code_ttl_seconds,
        tx_code_required: preauth.tx_code.required,
        offer_security_mode: offer_security_mode.to_string(),
    }
}

fn self_attestation_posture(config: &SelfAttestationConfig) -> SelfAttestationPosture {
    SelfAttestationPosture {
        enabled: config.enabled,
        allowed_claim_count: config.allowed_claims.len(),
        allowed_purpose_count: config.allowed_purposes.len(),
        credential_profile_count: config.credential_profiles.len(),
        wallet_origin_count: config.allowed_wallet_origins.len(),
        rate_limit_mode: if config.enabled {
            rate_limit_mode_label(config.rate_limits.mode).to_string()
        } else {
            "disabled".to_string()
        },
    }
}

fn rate_limit_mode_label(mode: SelfAttestationRateLimitMode) -> &'static str {
    match mode {
        SelfAttestationRateLimitMode::InProcess => "in_process",
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
    fn named_posture_example_audit_matches_live_projection() {
        let example: Value = serde_json::from_str(registry_platform_ops::NOTARY_POSTURE_EXAMPLE_V1)
            .expect("named Notary posture example parses");
        let live = audit_posture_object(&AuditPosture {
            sink: "file".to_string(),
            configured: true,
            shipping_target_configured: true,
            shipping_target: "declared_external".to_string(),
            shipping_health: Some("ok".to_string()),
            shipping_observed_at: Some("2026-06-04T09:59:00Z".to_string()),
        });

        assert_eq!(example["posture"]["audit"], live);
    }

    #[test]
    fn config_hash_is_stable_for_json_object_order() {
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

        assert_eq!(
            posture_safe_runtime_config_hash(&left),
            posture_safe_runtime_config_hash(&right)
        );
    }

    #[test]
    fn production_like_environment_is_case_insensitive() {
        assert!(production_like("Production"));
        assert!(production_like("STAGING"));
        assert!(production_like("production-like"));
        assert!(!production_like("development"));
    }

    #[test]
    fn unknown_signing_key_status_projection_fails_closed() {
        let mut posture = SigningKeyPosture::default();
        // SigningKeyStatus is non_exhaustive, so None is the unit-test stand-in
        // for a future status variant that this product has not classified yet.
        let error = project_signing_key_status("future-key", None, true, &mut posture)
            .expect_err("future signing key status must fail closed");

        assert_eq!(
            error,
            SigningKeyPostureError::UnknownStatus {
                key_id: "future-key".to_string()
            }
        );
        assert!(posture.active.is_empty());
        assert!(posture.publish_only.is_empty());
        assert!(posture.disabled.is_empty());
    }
}
