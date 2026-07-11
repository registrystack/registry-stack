use crate::*;

#[derive(Debug)]
pub(crate) struct LoadedServerConfig {
    pub(crate) config: StandaloneRegistryNotaryConfig,
    pub(crate) config_source: ConfigSource,
    pub(crate) config_provenance: Option<ConfigProvenance>,
    pub(crate) pending_bundle_acceptance: Option<PendingBundleAcceptance>,
}

#[derive(Debug)]
pub(crate) struct ParsedConfigDocument {
    pub(crate) config: StandaloneRegistryNotaryConfig,
    pub(crate) value: Value,
    pub(crate) admin_listener_present: bool,
}

pub(crate) fn parse_expanded_config(
    raw: &str,
) -> Result<StandaloneRegistryNotaryConfig, Box<dyn std::error::Error>> {
    let parsed = parse_config_document(raw)?;
    validate_config_document(&parsed)?;
    Ok(parsed.config)
}

pub(crate) fn parse_config_document(
    raw: &str,
) -> Result<ParsedConfigDocument, Box<dyn std::error::Error>> {
    let expanded = expand_config_env_vars(raw)?;
    let parsed_value = parse_config_value(&expanded)?;
    validate_admin_listener_shape(&parsed_value)?;
    reject_deprecated_config_fields(&parsed_value, &deprecated_config_fields())?;
    let admin_listener_present = server_admin_listener_block_present(&parsed_value);
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(&expanded)?;
    Ok(ParsedConfigDocument {
        config,
        value: parsed_value,
        admin_listener_present,
    })
}

pub(crate) fn validate_config_document(
    parsed: &ParsedConfigDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_config_document_with_mode(parsed, false)
}

pub(crate) fn validate_signed_bundle_config_document(
    parsed: &ParsedConfigDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_config_document_with_mode(parsed, true)
}

pub(crate) fn validate_config_document_with_mode(
    parsed: &ParsedConfigDocument,
    governed_runtime: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = &parsed.config;
    if governed_runtime {
        config.validate_governed_runtime()?;
    } else {
        config.validate()?;
    }
    if admin_listener_default_warning_needed(config, parsed.admin_listener_present) {
        tracing::warn!(
            restore_key = "server.admin_listener.mode",
            "server.admin_listener is absent; admin listener defaults to disabled; set server.admin_listener.mode to shared_with_public or dedicated to enable the admin surface"
        );
    }
    Ok(())
}

pub(crate) fn load_server_config(
    config_path: &Path,
    initialize_state: bool,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(config_path)?;
    let bootstrap = parse_config_document(&raw)?;
    let Some(config_trust) = bootstrap.config.config_trust.as_ref() else {
        validate_config_document(&bootstrap)?;
        return Ok(LoadedServerConfig {
            config: bootstrap.config,
            config_source: ConfigSource::LocalFile,
            config_provenance: None,
            pending_bundle_acceptance: None,
        });
    };

    let verified =
        match verify_config_bundle(&config_trust.bundle_path, &config_trust.trust_anchor_path) {
            Ok(verified) => verified,
            Err(error) => {
                if let Some(loaded) = load_unsigned_break_glass_or_pin_server_config(
                    config_trust,
                    config_trust.break_glass_override_path.as_deref(),
                )? {
                    return Ok(loaded);
                }
                log_bundle_verification_error(&error);
                return Err(Box::<dyn std::error::Error>::from(error));
            }
        };
    match load_verified_bundle_server_config(config_trust, initialize_state, verified) {
        Ok(loaded) => Ok(loaded),
        Err(error) => {
            if let Some(loaded) = load_unsigned_break_glass_or_pin_server_config(
                config_trust,
                config_trust.break_glass_override_path.as_deref(),
            )? {
                return Ok(loaded);
            }
            Err(error)
        }
    }
}

pub(crate) fn load_verified_bundle_server_config(
    config_trust: &ConfigTrustConfig,
    initialize_state: bool,
    verified: VerifiedConfigBundle,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    let key = antirollback_key_from_verified_bundle(&verified);
    let state_decision = resolve_bundle_state_action(BundleStateRequest {
        state_path: &config_trust.antirollback_state_path,
        key: &key,
        sequence: verified.manifest.sequence,
        config_hash: &verified.manifest.config_hash,
        bundle_manifest_hash: &verified.manifest_hash,
        previous_config_hash: verified.manifest.previous_config_hash.as_deref(),
        rollback_override_path: config_trust.break_glass_override_path.as_deref(),
        initialize_state,
    })
    .map_err(map_config_boot_error)?;
    let config_text = std::str::from_utf8(&verified.config_bytes).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "signed config bundle primary config is not UTF-8"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Box::<dyn std::error::Error>::from(error)
    })?;
    let parsed = parse_config_document(config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "signed config bundle primary config failed to parse"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    validate_signed_bundle_config_document(&parsed).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "signed config bundle primary config failed product validation"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    let provenance = ConfigProvenance {
        source: ConfigSource::SignedBundleFile,
        internal_config_hash: verified.manifest.config_hash.clone(),
        posture_config_hash: posture_safe_runtime_config_hash(&parsed.value),
        dynamic_reload_supported: false,
        last_bundle_id: Some(verified.manifest.bundle_id.clone()),
        last_bundle_sequence: Some(verified.manifest.sequence),
        last_bundle_signer_kids: verified.signer_kids.clone(),
        override_pin: state_decision.override_pin.clone(),
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    Ok(LoadedServerConfig {
        config: parsed.config,
        config_source: ConfigSource::SignedBundleFile,
        config_provenance: Some(provenance),
        pending_bundle_acceptance: Some(PendingBundleAcceptance {
            state_path: config_trust.antirollback_state_path.clone(),
            key,
            source: ConfigSource::SignedBundleFile,
            bundle_id: Some(verified.manifest.bundle_id),
            bundle_manifest_hash: Some(verified.manifest_hash),
            sequence: Some(verified.manifest.sequence),
            config_hash: verified.manifest.config_hash,
            previous_config_hash: verified.manifest.previous_config_hash,
            previous_hash_matched: state_decision.previous_hash_matched,
            signer_kids: verified.signer_kids,
            break_glass: matches!(
                state_decision.state_action,
                BundleStateAction::PersistOverridePin
            ),
            state_action: state_decision.state_action,
            override_pin: state_decision.override_pin,
            override_path: state_decision.override_path,
        }),
    })
}

pub(crate) fn load_unsigned_break_glass_or_pin_server_config(
    config_trust: &ConfigTrustConfig,
    override_path: Option<&Path>,
) -> Result<Option<LoadedServerConfig>, Box<dyn std::error::Error>> {
    let Some(selection) = load_unsigned_break_glass_or_pin(
        &config_trust.trust_anchor_path,
        &config_trust.antirollback_state_path,
        override_path,
    )
    .map_err(map_config_boot_error)?
    else {
        return Ok(None);
    };
    load_unsigned_pin_server_config(config_trust, selection).map(Some)
}

pub(crate) fn load_unsigned_pin_server_config(
    config_trust: &ConfigTrustConfig,
    selection: UnsignedConfigSelection,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    let config_text = std::str::from_utf8(&selection.config_bytes).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config is not UTF-8"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Box::<dyn std::error::Error>::from(error)
    })?;
    let parsed = parse_config_document(config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config failed to parse"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    validate_config_document(&parsed).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config failed product validation"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    let override_pin = Some(selection.pin.clone());
    Ok(LoadedServerConfig {
        config: parsed.config,
        config_source: ConfigSource::LocalFile,
        config_provenance: Some(ConfigProvenance {
            source: ConfigSource::LocalFile,
            internal_config_hash: selection.pin.config_hash.clone(),
            posture_config_hash: posture_safe_runtime_config_hash(&parsed.value),
            dynamic_reload_supported: false,
            last_bundle_id: selection.record.last_bundle_id,
            last_bundle_sequence: Some(selection.record.last_sequence),
            last_bundle_signer_kids: Vec::new(),
            override_pin: override_pin.clone(),
            last_apply_result: None,
            last_apply_at: None,
            restart_required: false,
        }),
        pending_bundle_acceptance: Some(PendingBundleAcceptance {
            state_path: config_trust.antirollback_state_path.clone(),
            key: selection.key,
            source: ConfigSource::LocalFile,
            bundle_id: None,
            bundle_manifest_hash: None,
            sequence: None,
            config_hash: selection.pin.config_hash,
            previous_config_hash: None,
            previous_hash_matched: None,
            signer_kids: Vec::new(),
            break_glass: matches!(
                selection.state_action,
                BundleStateAction::PersistOverridePin
            ),
            state_action: selection.state_action,
            override_pin,
            override_path: selection.override_path,
        }),
    })
}

pub(crate) fn log_bundle_verification_error(error: &ConfigBundleError) {
    let result = bundle_verify_rejection_result(error);
    tracing::error!(
        code = "config.bundle_rejected",
        result,
        error = %error,
        "signed config bundle verification failed"
    );
    eprintln!("config.bundle_rejected result={result} error={error}");
}

pub(crate) fn map_config_boot_error(error: ConfigBootError) -> Box<dyn std::error::Error> {
    if let Some(reason) = error.break_glass_invalid_reason() {
        tracing::error!(
            code = "config.break_glass_invalid",
            error = %error,
            reason,
            "config break-glass override rejected"
        );
        eprintln!("config.break_glass_invalid error={error}");
    }
    let result = error.bundle_rejection_result();
    tracing::error!(
        code = "config.bundle_rejected",
        result,
        error = %error,
        "config bundle boot state rejected startup"
    );
    eprintln!("config.bundle_rejected result={result} error={error}");
    Box::new(error)
}

#[derive(Debug)]
pub(crate) struct ConfigShapeError(String);

impl fmt::Display for ConfigShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigShapeError {}

pub(crate) fn parse_config_value(raw: &str) -> Result<Value, serde_norway::Error> {
    serde_norway::from_str(raw)
}

pub(crate) fn validate_admin_listener_shape(value: &Value) -> Result<(), ConfigShapeError> {
    let Some(admin_listener) = value
        .get("server")
        .and_then(Value::as_object)
        .and_then(|server| server.get("admin_listener"))
    else {
        return Ok(());
    };
    if admin_listener.is_object() {
        return Ok(());
    }
    Err(ConfigShapeError(
        "server.admin_listener must be a mapping with accepted mode values: disabled, dedicated, shared_with_public; use server.admin_listener.mode to restore the admin surface".to_string(),
    ))
}

pub(crate) fn server_admin_listener_block_present(value: &Value) -> bool {
    value
        .get("server")
        .and_then(Value::as_object)
        .is_some_and(|server| server.contains_key("admin_listener"))
}

pub(crate) fn admin_listener_default_warning_needed(
    config: &StandaloneRegistryNotaryConfig,
    admin_listener_present: bool,
) -> bool {
    !admin_listener_present
        && config.server.admin_listener.mode == RegistryNotaryAdminListenerMode::Disabled
}
#[cfg(test)]
#[path = "config_loader/tests.rs"]
mod tests;
