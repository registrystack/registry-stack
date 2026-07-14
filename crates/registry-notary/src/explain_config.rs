use crate::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExplainConfigOutputFormat {
    Json,
    Text,
}

impl fmt::Display for ExplainConfigOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Text => f.write_str("text"),
        }
    }
}

pub(crate) fn explain_config(
    config_path: &Path,
    env_report: &EnvFileReport,
    bind_override: Option<SocketAddr>,
    format: ExplainConfigOutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(config_path)?;
    let mut config = parse_expanded_config(&raw)?;
    apply_bind_override(&mut config, bind_override);
    match format {
        ExplainConfigOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&config_explanation_json(
                    config_path,
                    &raw,
                    &config,
                    env_report,
                ))?
            );
        }
        ExplainConfigOutputFormat::Text => {
            println!(
                "{}",
                serde_json::to_string_pretty(&redacted_config(&config))?
            );
            println!();
            println!("Required env vars:");
            for env in required_env_vars(&config) {
                let status = if std::env::var_os(&env).is_some() {
                    "present"
                } else if env_report.contains(&env) {
                    "from env-file"
                } else {
                    "missing"
                };
                println!("- {env}: {status}");
            }
            println!("Relay connection:");
            println!(
                "- {}",
                serde_json::to_string(&notary_relay_connection_report(&config))?
            );
            println!();
            println!("Relay consultations:");
            for consultation in notary_relay_consultations_report(&config) {
                println!("- {}", serde_json::to_string(&consultation)?);
            }
        }
    }
    Ok(())
}

pub(crate) fn config_explanation_json(
    config_path: &Path,
    raw_config: &str,
    config: &StandaloneRegistryNotaryConfig,
    env_report: &EnvFileReport,
) -> Value {
    json!({
        "schema_version": "registry.config.explanation.v1",
        "product": "registry-notary",
        "config_schema_version": NOTARY_CONFIG_SCHEMA_VERSION,
        "source": {
            "kind": "local_file",
            "path": path_for_json(config_path),
        },
        "required_env": required_env_report(required_env_vars(config), env_report),
        "defaults_applied": [],
        "optional_sections_absent": optional_config_sections_absent(config),
        "live_apply": notary_live_apply_classes(),
        "context_constraints": [],
        "relay_connection": notary_relay_connection_report(config),
        "relay_consultations": notary_relay_consultations_report(config),
        "resolved_config": redacted_config(config),
        "hashes": {
            "internal_config_hash": sha256_hash(raw_config),
        },
        "generated_at": now_rfc3339(),
    })
}

pub(crate) fn notary_relay_connection_report(config: &StandaloneRegistryNotaryConfig) -> Value {
    let Some(relay) = &config.evidence.relay else {
        return Value::Null;
    };
    json!({
        "credential": {
            "mode": "reloadable_token_file",
            "reload": "per_operation",
            "offline_file_status": relay_credential_file_status(&relay.token_file),
        },
        "network": {
            "transport": if relay.base_url.starts_with("https://") {
                "https"
            } else {
                "loopback_http"
            },
            "allowed_private_cidr_count": relay.allowed_private_cidrs.len(),
            "allow_insecure_localhost": relay.allow_insecure_localhost,
        },
    })
}

fn relay_credential_file_status(path: &Path) -> &'static str {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => "present",
        Ok(_) => "not_regular",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing",
        Err(_) => "unreadable",
    }
}

pub(crate) fn optional_config_sections_absent(
    config: &StandaloneRegistryNotaryConfig,
) -> Vec<Value> {
    let mut sections = Vec::new();
    if config.evidence.relay.is_none() {
        sections.push(json!({
            "path": "/evidence/relay",
            "reason": "no Registry Relay connection configured",
        }));
    }
    if !config.credential_status.enabled {
        sections.push(json!({
            "path": "/credential_status",
            "reason": "credential status is disabled",
        }));
    }
    sections
}

pub(crate) fn notary_relay_consultations_report(
    config: &StandaloneRegistryNotaryConfig,
) -> Vec<Value> {
    let mut entries = Vec::new();
    for (claim_index, claim) in config.evidence.claims.iter().enumerate() {
        let registry_notary_core::ClaimEvidenceMode::RegistryBacked { consultations } =
            &claim.evidence_mode
        else {
            continue;
        };
        for (name, consultation) in consultations {
            entries.push(json!({
                "container_path": format!(
                    "/evidence/claims/{claim_index}/evidence_mode/consultations/{}",
                    json_pointer_segment(name),
                ),
                "claim_id": claim.id,
                "consultation": name,
                "profile": {
                    "id": consultation.profile.id,
                    "contract_hash": consultation.profile.contract_hash,
                },
                "purpose": claim.purpose,
                "required_scopes": claim.required_scopes,
                "inputs": consultation.inputs,
            }));
        }
    }
    entries
}

pub(crate) fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

pub(crate) fn notary_live_apply_classes() -> Vec<Value> {
    vec![
        json!({
            "path": "/evidence/relay",
            "class": LiveApplyClass::RestartRequired.as_str(),
        }),
        json!({
            "path": "/evidence/signing_keys",
            "class": LiveApplyClass::RestartRequired.as_str(),
        }),
        json!({
            "path": "/server",
            "class": LiveApplyClass::RestartRequired.as_str(),
        }),
        json!({
            "path": "/config_trust",
            "class": LiveApplyClass::UnsupportedLiveApply.as_str(),
        }),
    ]
}

pub(crate) fn apply_bind_override(
    config: &mut StandaloneRegistryNotaryConfig,
    bind: Option<SocketAddr>,
) {
    if let Some(bind) = bind {
        config.server.bind = bind;
    }
}

pub(crate) fn required_env_vars(config: &StandaloneRegistryNotaryConfig) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    for credential in config
        .auth
        .api_keys
        .iter()
        .chain(config.auth.bearer_tokens.iter())
    {
        if let Some(env) = credential.fingerprint.name.clone() {
            vars.insert(env);
        }
    }
    if let Some(env) = &config.audit.hash_secret_env {
        vars.insert(env.clone());
    }
    if config.state.storage == STATE_STORAGE_POSTGRESQL {
        vars.insert(config.state.postgresql.url_env.clone());
        if config.oid4vci.pre_authorized_code.enabled {
            vars.insert(config.state.postgresql.sensitive_state_key_env.clone());
        }
    }
    if config.federation.enabled {
        vars.insert(config.federation.pairwise_subject_hash.secret_env.clone());
    }
    for key in config.evidence.signing_keys.values() {
        if !key.private_jwk_env.trim().is_empty() {
            vars.insert(key.private_jwk_env.clone());
        }
        if !key.public_jwk_env.trim().is_empty() {
            vars.insert(key.public_jwk_env.clone());
        }
        if !key.pin_env.trim().is_empty() {
            vars.insert(key.pin_env.clone());
        }
        if !key.password_env.trim().is_empty() {
            vars.insert(key.password_env.clone());
        }
    }
    vars
}

pub(crate) fn redacted_config(config: &StandaloneRegistryNotaryConfig) -> Value {
    let mut value = serde_json::to_value(config).expect("config serializes");
    redact_value(&mut value);
    value
}

pub(crate) fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if ["secret", "token", "jwk", "pin", "password"]
                    .iter()
                    .any(|term| lower.contains(term))
                    || (lower.contains("key") && lower != "signing_keys" && lower != "api_keys")
                    || lower == "credential"
                    || lower.ends_with("_credential")
                    || lower == "credential_env"
                {
                    *value = Value::String("[redacted]".to_string());
                } else {
                    redact_value(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_value(value);
            }
        }
        _ => {}
    }
}
#[cfg(test)]
#[path = "explain_config/tests.rs"]
mod tests;
