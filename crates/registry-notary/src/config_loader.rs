use crate::*;

use registry_notary_server::{NotaryActivationCode, NotaryActivationFailure};

const NOTARY_CONFIG_BUNDLE_PRODUCT: &str = "registry-notary";

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ServerConfigInput {
    LocalFile(PathBuf),
    SignedBundle {
        bundle_dir: PathBuf,
        anchor_path: PathBuf,
        state_path: PathBuf,
    },
}

impl fmt::Debug for ServerConfigInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalFile(_) => formatter.write_str("ServerConfigInput::LocalFile(<redacted>)"),
            Self::SignedBundle { .. } => {
                formatter.write_str("ServerConfigInput::SignedBundle(<redacted>)")
            }
        }
    }
}

impl From<&Path> for ServerConfigInput {
    fn from(config_path: &Path) -> Self {
        Self::LocalFile(config_path.to_path_buf())
    }
}

impl From<&PathBuf> for ServerConfigInput {
    fn from(config_path: &PathBuf) -> Self {
        Self::from(config_path.as_path())
    }
}

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
    let raw = fs::read_to_string(config_path).map_err(|_| {
        log_safe_configuration_rejection(
            NotaryActivationCode::CONFIGURATION_INVALID.as_str(),
            "rejected_validation",
            None,
        );
        configuration_failure()
    })?;
    let bootstrap = parse_config_document(&raw).map_err(|_| {
        log_safe_configuration_rejection(
            NotaryActivationCode::CONFIGURATION_INVALID.as_str(),
            "rejected_validation",
            None,
        );
        configuration_failure()
    })?;
    let Some(config_trust) = bootstrap.config.config_trust.as_ref() else {
        validate_config_document(&bootstrap).map_err(|_| {
            log_safe_configuration_rejection(
                NotaryActivationCode::CONFIGURATION_INVALID.as_str(),
                "rejected_validation",
                None,
            );
            configuration_failure()
        })?;
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
                let code = log_bundle_verification_error(&error);
                return Err(bundle_verification_failure(code));
            }
        };
    // A bundle and anchor can be internally consistent while belonging to a
    // different product. Bind the verified manifest to this binary before the
    // legacy loader may consider any local recovery selection.
    ensure_notary_config_bundle_product(&verified)?;
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

pub(crate) fn load_server_config_input(
    input: &ServerConfigInput,
    initialize_state: bool,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    match input {
        ServerConfigInput::LocalFile(config_path) => {
            load_server_config(config_path, initialize_state)
        }
        ServerConfigInput::SignedBundle {
            bundle_dir,
            anchor_path,
            state_path,
        } => load_direct_signed_bundle_server_config(
            bundle_dir,
            anchor_path,
            state_path,
            initialize_state,
        ),
    }
}

pub(crate) fn load_direct_signed_bundle_server_config(
    bundle_dir: &Path,
    anchor_path: &Path,
    state_path: &Path,
    initialize_state: bool,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    // These operator-selected paths are the complete trust input for direct
    // startup. Do not consult config_trust from another file or fall back to an
    // unsigned selection when verification or anti-rollback checks fail.
    let verified = verify_config_bundle(bundle_dir, anchor_path).map_err(|error| {
        let code = log_bundle_verification_error(&error);
        bundle_verification_failure(code)
    })?;
    load_verified_bundle_server_config_with_state(state_path, None, initialize_state, verified)
}

pub(crate) fn load_verified_bundle_server_config(
    config_trust: &ConfigTrustConfig,
    initialize_state: bool,
    verified: VerifiedConfigBundle,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    load_verified_bundle_server_config_with_state(
        &config_trust.antirollback_state_path,
        config_trust.break_glass_override_path.as_deref(),
        initialize_state,
        verified,
    )
}

fn load_verified_bundle_server_config_with_state(
    state_path: &Path,
    rollback_override_path: Option<&Path>,
    initialize_state: bool,
    verified: VerifiedConfigBundle,
) -> Result<LoadedServerConfig, Box<dyn std::error::Error>> {
    ensure_notary_config_bundle_product(&verified)?;
    let key = antirollback_key_from_verified_bundle(&verified);
    let state_decision = resolve_bundle_state_action(BundleStateRequest {
        state_path,
        key: &key,
        sequence: verified.manifest.sequence,
        config_hash: &verified.manifest.config_hash,
        bundle_manifest_hash: &verified.manifest_hash,
        previous_config_hash: verified.manifest.previous_config_hash.as_deref(),
        rollback_override_path,
        initialize_state,
    })
    .map_err(map_config_boot_error)?;
    let config_text = std::str::from_utf8(&verified.config_bytes).map_err(|_| {
        log_safe_bundle_rejection(
            "config.bundle_rejected",
            BundleVerificationCode::REJECTED_VALIDATION,
            None,
        );
        bundle_verification_failure(BundleVerificationCode::REJECTED_VALIDATION)
    })?;
    let parsed = parse_config_document(config_text).map_err(|_| {
        log_safe_bundle_rejection(
            "config.bundle_rejected",
            BundleVerificationCode::REJECTED_VALIDATION,
            None,
        );
        bundle_verification_failure(BundleVerificationCode::REJECTED_VALIDATION)
    })?;
    validate_signed_bundle_config_document(&parsed).map_err(|_| {
        log_safe_bundle_rejection(
            "config.bundle_rejected",
            BundleVerificationCode::REJECTED_VALIDATION,
            None,
        );
        bundle_verification_failure(BundleVerificationCode::REJECTED_VALIDATION)
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
            state_path: state_path.to_path_buf(),
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

fn ensure_notary_config_bundle_product(
    verified: &VerifiedConfigBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    if verified.manifest.product == NOTARY_CONFIG_BUNDLE_PRODUCT {
        return Ok(());
    }
    log_safe_bundle_rejection(
        "config.bundle_rejected",
        BundleVerificationCode::REJECTED_BINDING,
        None,
    );
    Err(bundle_verification_failure(
        BundleVerificationCode::REJECTED_BINDING,
    ))
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
    let config_text = std::str::from_utf8(&selection.config_bytes).map_err(|_| {
        log_safe_bundle_rejection(
            "config.bundle_rejected",
            BundleVerificationCode::REJECTED_VALIDATION,
            None,
        );
        bundle_verification_failure(BundleVerificationCode::REJECTED_VALIDATION)
    })?;
    let parsed = parse_config_document(config_text).map_err(|_| {
        log_safe_bundle_rejection(
            "config.bundle_rejected",
            BundleVerificationCode::REJECTED_VALIDATION,
            None,
        );
        bundle_verification_failure(BundleVerificationCode::REJECTED_VALIDATION)
    })?;
    validate_config_document(&parsed).map_err(|_| {
        log_safe_bundle_rejection(
            "config.bundle_rejected",
            BundleVerificationCode::REJECTED_VALIDATION,
            None,
        );
        bundle_verification_failure(BundleVerificationCode::REJECTED_VALIDATION)
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

pub(crate) fn log_bundle_verification_error(error: &ConfigBundleError) -> BundleVerificationCode {
    let code = bundle_verify_rejection_code(error);
    log_safe_bundle_rejection("config.bundle_rejected", code, None);
    code
}

pub(crate) fn map_config_boot_error(error: ConfigBootError) -> Box<dyn std::error::Error> {
    let code = error.bundle_rejection_code();
    if let Some(reason) = error.break_glass_invalid_reason() {
        log_safe_bundle_rejection("config.break_glass_invalid", code, Some(reason));
    }
    log_safe_bundle_rejection("config.bundle_rejected", code, None);
    bundle_verification_failure(code)
}

fn configuration_failure() -> Box<dyn std::error::Error> {
    Box::new(NotaryActivationFailure::from(
        NotaryActivationCode::CONFIGURATION_INVALID,
    ))
}

fn bundle_verification_failure(code: BundleVerificationCode) -> Box<dyn std::error::Error> {
    Box::new(BundleVerificationFailure::from(code))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SafeStartupRejection {
    classification_code: &'static str,
    result: &'static str,
    reason: &'static str,
    activation_code: &'static str,
    safe_meaning: &'static str,
    safe_remediation: &'static str,
}

fn safe_configuration_rejection(
    classification_code: &'static str,
    result: &'static str,
    reason: Option<&'static str>,
) -> SafeStartupRejection {
    let definition = NotaryActivationCode::CONFIGURATION_INVALID.definition();
    SafeStartupRejection {
        classification_code,
        result,
        reason: reason.unwrap_or("none"),
        activation_code: definition.code.as_str(),
        safe_meaning: definition.meaning,
        safe_remediation: definition.remediation,
    }
}

fn safe_bundle_rejection(
    classification_code: &'static str,
    code: BundleVerificationCode,
    reason: Option<&'static str>,
) -> SafeStartupRejection {
    let definition = code.definition();
    SafeStartupRejection {
        classification_code,
        result: code.as_str(),
        reason: reason.unwrap_or("none"),
        activation_code: NotaryActivationCode::CONFIGURATION_INVALID.as_str(),
        safe_meaning: definition.safe_meaning,
        safe_remediation: definition.safe_remediation,
    }
}

fn log_safe_configuration_rejection(
    classification_code: &'static str,
    result: &'static str,
    reason: Option<&'static str>,
) {
    log_safe_startup_rejection(safe_configuration_rejection(
        classification_code,
        result,
        reason,
    ));
}

fn log_safe_bundle_rejection(
    classification_code: &'static str,
    code: BundleVerificationCode,
    reason: Option<&'static str>,
) {
    log_safe_startup_rejection(safe_bundle_rejection(classification_code, code, reason));
}

fn log_safe_startup_rejection(rejection: SafeStartupRejection) {
    tracing::error!(
        code = rejection.classification_code,
        result = rejection.result,
        reason = rejection.reason,
        activation_code = rejection.activation_code,
        safe_meaning = rejection.safe_meaning,
        safe_remediation = rejection.safe_remediation,
        "registry notary startup configuration rejected"
    );
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
