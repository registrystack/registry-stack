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
            println!();
            println!("Claim source bindings:");
            for claim in &config.evidence.claims {
                for (binding_id, binding) in &claim.source_bindings {
                    println!(
                        "- {}.{} uses connection {} via {:?}",
                        claim.id,
                        binding_id,
                        binding.connection.as_deref().unwrap_or("(default)"),
                        binding.connector
                    );
                }
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
        "context_constraints": notary_context_constraints_report(config),
        "resolved_config": redacted_config(config),
        "hashes": {
            "internal_config_hash": sha256_hash(raw_config),
        },
        "generated_at": now_rfc3339(),
    })
}

pub(crate) fn optional_config_sections_absent(
    config: &StandaloneRegistryNotaryConfig,
) -> Vec<Value> {
    let mut sections = Vec::new();
    if config.evidence.source_connections.is_empty() {
        sections.push(json!({
            "path": "/evidence/source_connections",
            "reason": "no external source connections configured",
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

pub(crate) fn notary_context_constraints_report(
    config: &StandaloneRegistryNotaryConfig,
) -> Vec<Value> {
    let mut entries = Vec::new();
    for (claim_index, claim) in config.evidence.claims.iter().enumerate() {
        for (binding_id, binding) in &claim.source_bindings {
            let matching = &binding.matching;
            if !notary_matching_has_context_constraints(matching) {
                continue;
            }
            let legal_basis_source = notary_trusted_value_source(
                config,
                "legal_basis",
                notary_legal_basis_configured(matching),
            );
            let consent_source =
                notary_trusted_value_source(config, "consent", notary_consent_configured(matching));
            let jurisdiction_source = notary_trusted_value_source(
                config,
                "jurisdiction",
                !matching.permitted_jurisdictions.is_empty(),
            );
            let assurance_source = notary_trusted_value_source(
                config,
                "assurance",
                !matching.allowed_assurance.is_empty() || matching.minimum_assurance.is_some(),
            );
            let (observation_source, observation_proven) =
                notary_source_observation_report(config, binding);

            entries.push(json!({
                "container_path": format!(
                    "/evidence/claims/{claim_index}/source_bindings/{}/matching",
                    json_pointer_segment(binding_id)
                ),
                "product": "registry-notary",
                "platform_contract": PLATFORM_CONTEXT_CONSTRAINTS_CONTRACT_V1,
                "hash_material_contract": PLATFORM_CONTEXT_CONSTRAINTS_HASH_MATERIAL_CONTRACT_V1,
                "legal_basis": {
                    "required": matching.require_legal_basis,
                    "approved_value_check": !matching.allowed_legal_basis_refs.is_empty(),
                    "allowed_ref_count": matching.allowed_legal_basis_refs.len(),
                    "trusted_value_source": legal_basis_source,
                },
                "consent": {
                    "required": matching.require_consent,
                    "approved_value_check": !matching.allowed_consent_refs.is_empty(),
                    "allowed_ref_count": matching.allowed_consent_refs.len(),
                    "trusted_value_source": consent_source,
                },
                "jurisdiction": {
                    "permitted_count": matching.permitted_jurisdictions.len(),
                    "trusted_value_source": jurisdiction_source,
                },
                "assurance": {
                    "allowed_count": matching.allowed_assurance.len(),
                    "minimum": matching.minimum_assurance.as_deref(),
                    "trusted_value_source": assurance_source,
                    "authn_derived": false,
                },
                "source_freshness": {
                    "max_age_seconds": matching.max_source_age_seconds,
                    "observation_field": matching.source_observed_at_field.as_deref(),
                    "observation_timestamp_source": observation_source,
                    "observation_contract_proven": observation_proven,
                },
                "product_owned_adjacent_controls": notary_adjacent_matching_controls(binding),
            }));
        }
    }
    entries
}

pub(crate) fn notary_matching_has_context_constraints(
    matching: &registry_notary_core::SourceMatchingConfig,
) -> bool {
    matching.has_context_constraints()
}

pub(crate) fn notary_legal_basis_configured(
    matching: &registry_notary_core::SourceMatchingConfig,
) -> bool {
    matching.require_legal_basis || !matching.allowed_legal_basis_refs.is_empty()
}

pub(crate) fn notary_consent_configured(
    matching: &registry_notary_core::SourceMatchingConfig,
) -> bool {
    matching.require_consent || !matching.allowed_consent_refs.is_empty()
}

pub(crate) fn notary_trusted_value_source(
    config: &StandaloneRegistryNotaryConfig,
    field: &str,
    configured: bool,
) -> &'static str {
    if !configured {
        return TrustedValueSource::NotConfigured.as_str();
    }
    if notary_static_authorization_details_has(config, field) {
        return TrustedValueSource::StaticCredentialAuthorizationDetails.as_str();
    }
    if config.auth.mode == EvidenceAuthMode::Oidc {
        return TrustedValueSource::OidcAuthorizationDetails.as_str();
    }
    TrustedValueSource::Unknown.as_str()
}

pub(crate) fn notary_static_authorization_details_has(
    config: &StandaloneRegistryNotaryConfig,
    field: &str,
) -> bool {
    config
        .auth
        .api_keys
        .iter()
        .chain(config.auth.bearer_tokens.iter())
        .filter_map(|credential| credential.authorization_details.as_ref())
        .any(|details| match field {
            "legal_basis" => details.legal_basis_ref.as_deref().is_some_and(non_empty),
            "consent" => details.consent_ref.as_deref().is_some_and(non_empty),
            "jurisdiction" => details.jurisdiction.as_deref().is_some_and(non_empty),
            "assurance" => details.assurance_level.as_deref().is_some_and(non_empty),
            _ => false,
        })
}

pub(crate) fn notary_source_observation_report(
    config: &StandaloneRegistryNotaryConfig,
    binding: &registry_notary_core::SourceBindingConfig,
) -> (&'static str, bool) {
    if binding.matching.max_source_age_seconds.is_none() {
        return (TrustedValueSource::NotConfigured.as_str(), false);
    }
    let Some(field) = binding.matching.source_observed_at_field.as_deref() else {
        return (TrustedValueSource::Unknown.as_str(), false);
    };
    if binding.connector != SourceConnectorKind::Dci {
        return (TrustedValueSource::Unknown.as_str(), false);
    }
    let Some(connection_id) = binding.connection.as_deref() else {
        return (TrustedValueSource::Unknown.as_str(), false);
    };
    let Some(connection) = config.evidence.source_connections.get(connection_id) else {
        return (TrustedValueSource::Unknown.as_str(), false);
    };
    if connection
        .dci
        .field_paths
        .get(field)
        .is_some_and(|path| path.starts_with("$response:"))
    {
        return (
            TrustedValueSource::SourceObservationTimestamp.as_str(),
            true,
        );
    }
    (TrustedValueSource::Unknown.as_str(), false)
}

pub(crate) fn notary_adjacent_matching_controls(
    binding: &registry_notary_core::SourceBindingConfig,
) -> Vec<&'static str> {
    let matching = &binding.matching;
    let mut controls = vec!["source_lookup"];
    if !matching.sufficient_target_inputs.is_empty() || !matching.allowed_target_inputs.is_empty() {
        controls.push("target_input_minimization");
    }
    if matching.collapse_matching_errors {
        controls.push("matching_error_collapse");
    }
    if matching.confidence.is_some() {
        controls.push("confidence_label");
    }
    if !matching.redaction_fields.is_empty() {
        controls.push("redaction_fields");
    }
    controls
}

pub(crate) fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

pub(crate) fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

pub(crate) fn notary_live_apply_classes() -> Vec<Value> {
    vec![
        json!({
            "path": "/evidence/source_connections",
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
    if config.replay.storage == "redis" {
        vars.insert(config.replay.redis.url_env.clone());
    }
    if config.credential_status.enabled && config.credential_status.storage == "redis" {
        vars.insert(config.credential_status.redis.url_env.clone());
    }
    if config.federation.enabled {
        vars.insert(config.federation.pairwise_subject_hash.secret_env.clone());
    }
    for connection in config.evidence.source_connections.values() {
        if !connection.token_env.trim().is_empty() {
            vars.insert(connection.token_env.clone());
        }
        if let Some(SourceAuthConfig::Oauth2ClientCredentials(auth)) = &connection.source_auth {
            vars.insert(auth.client_id_env.clone());
            vars.insert(auth.client_secret_env.clone());
        }
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
