// SPDX-License-Identifier: Apache-2.0
//! Read a config file from disk, parse it, and run cross-field
//! validation.
//!
//! The loader deliberately scrubs the surfaced [`crate::error::Error`]
//! detail: response and audit detail strings never carry the source
//! path. The operational `tracing::error!` line includes the path so
//! operators can locate the offending file in their logs.

use std::fs;
use std::path::{Path, PathBuf};

use registry_manifest_core::{
    self as metadata_core, CompiledMetadata, MetadataError as CoreMetadataError, MetadataManifest,
};
use registry_platform_config::{
    expand_config_env_vars, load_break_glass_override, load_trust_anchor,
    reject_deprecated_config_fields, sha256_uri, verify_config_bundle, ConfigBreakGlassMode,
    ConfigBreakGlassOverride, ConfigBundleError, DeprecatedConfigField, VerifiedConfigBundle,
};
use registry_platform_ops::{
    internal_config_hash, is_sha256_config_hash, override_pin_active_and_unexpired,
    posture_safe_runtime_config_hash, AntiRollbackKey, AntiRollbackRecord, ConfigOverrideMode,
    ConfigOverridePin, ConfigProvenance, ConfigSource, FileAntiRollbackStore,
};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{ConfigError, Error, MetadataError};

use super::validate;
use super::Config;

#[derive(Debug)]
pub struct LoadedConfig {
    pub runtime: Config,
    pub metadata: Option<CompiledMetadata>,
    pub metadata_source_digest: Option<String>,
    pub provenance: ConfigProvenance,
    pub pending_bundle_acceptance: Option<PendingBundleAcceptance>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    pub initialize_state: bool,
}

#[derive(Debug, Clone)]
pub struct PendingBundleAcceptance {
    pub state_path: PathBuf,
    pub key: AntiRollbackKey,
    pub source: ConfigSource,
    pub bundle_id: Option<String>,
    pub sequence: Option<u64>,
    pub config_hash: String,
    pub previous_config_hash: Option<String>,
    pub previous_hash_matched: Option<bool>,
    pub signer_kids: Vec<String>,
    pub break_glass: bool,
    pub state_action: BundleStateAction,
    pub override_pin: Option<ConfigOverridePin>,
    pub override_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BundleStateAction {
    Initialize,
    Accept,
    PersistOverridePin,
    AlreadyPinned,
}

/// Load and validate the YAML configuration at `path`.
///
/// # Errors
///
/// - [`ConfigError::ParseError`] on filesystem read failure or YAML
///   deserialisation failure. The path and serde error are logged via
///   `tracing` at error level; the returned `Error` is scrubbed.
/// - [`ConfigError::ValidationError`], [`ConfigError::MissingSecret`],
///   [`ConfigError::DuplicateId`] propagated from
///   [`validate::run`] on cross-field validation failures.
pub fn load(path: &Path) -> Result<Config, Error> {
    Ok(load_config_document(path, LoadOptions::default())?.runtime)
}

fn load_config_document(path: &Path, options: LoadOptions) -> Result<LoadedConfigDocument, Error> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(
                code = "config.parse_error",
                path = %path.display(),
                error = %err,
                "failed to read config file"
            );
            return Err(Error::from(ConfigError::ParseError));
        }
    };

    let expanded = match expand_config_env_vars(&raw) {
        Ok(expanded) => expanded,
        Err(err) => {
            tracing::error!(
                code = "config.parse_error",
                path = %path.display(),
                error = %err,
                "failed to expand config environment expressions"
            );
            return Err(Error::from(ConfigError::ParseError));
        }
    };

    let config_value: Value = match serde_saphyr::from_str(&expanded) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(
                code = "config.parse_error",
                path = %path.display(),
                error = %err,
                "failed to parse config YAML"
            );
            return Err(Error::from(ConfigError::ParseError));
        }
    };
    if let Err(err) = reject_deprecated_config_fields(&config_value, &deprecated_config_fields()) {
        tracing::error!(
            code = "config.parse_error",
            path = %path.display(),
            error = %err,
            "config uses a removed or renamed field"
        );
        return Err(Error::from(ConfigError::ParseError));
    }
    let config: Config = match serde_saphyr::from_str(&expanded) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(
                code = "config.parse_error",
                path = %path.display(),
                error = %err,
                "failed to parse config YAML"
            );
            return Err(Error::from(ConfigError::ParseError));
        }
    };

    if config.config_trust.is_some() {
        return load_bundle_config_document(&config, options);
    }

    validate::run(&config)?;
    let provenance = ConfigProvenance::local_file(
        internal_config_hash(expanded.as_bytes()),
        posture_safe_runtime_config_hash(&config_value),
        false,
    );
    Ok(LoadedConfigDocument {
        config_path: path.to_path_buf(),
        runtime: config,
        provenance,
        pending_bundle_acceptance: None,
    })
}

fn load_bundle_config_document(
    bootstrap: &Config,
    options: LoadOptions,
) -> Result<LoadedConfigDocument, Error> {
    let config_trust = bootstrap
        .config_trust
        .as_ref()
        .expect("caller checked config_trust");
    let verified =
        match verify_config_bundle(&config_trust.bundle_path, &config_trust.trust_anchor_path) {
            Ok(verified) => verified,
            Err(error) => {
                if let Some(document) = load_unsigned_break_glass_or_pin_config_document(
                    config_trust,
                    config_trust.break_glass_override_path.as_deref(),
                )? {
                    return Ok(document);
                }
                log_bundle_verification_error(&error);
                return Err(Error::from(ConfigError::ValidationError));
            }
        };
    match load_verified_bundle_config_document(config_trust, options, verified) {
        Ok(document) => Ok(document),
        Err(error) => {
            if let Some(document) = load_unsigned_break_glass_or_pin_config_document(
                config_trust,
                config_trust.break_glass_override_path.as_deref(),
            )? {
                return Ok(document);
            }
            Err(error)
        }
    }
}

fn load_verified_bundle_config_document(
    config_trust: &super::ConfigTrustConfig,
    options: LoadOptions,
    verified: VerifiedConfigBundle,
) -> Result<LoadedConfigDocument, Error> {
    let key = AntiRollbackKey {
        product: verified.manifest.product.clone(),
        instance_id: verified.manifest.instance_id.clone().unwrap_or_default(),
        environment: verified.manifest.environment.clone(),
        stream_id: verified.manifest.stream_id.clone(),
    };
    let (state_action, override_pin, previous_hash_matched, override_path) =
        resolve_bundle_state_action(
            &config_trust.antirollback_state_path,
            &key,
            verified.manifest.sequence,
            &verified.manifest.config_hash,
            verified.manifest.previous_config_hash.as_deref(),
            config_trust.break_glass_override_path.as_deref(),
            options.initialize_state,
        )?;
    let (config, config_value) =
        parse_config_bytes_for_bundle(&verified.config_bytes, ConfigSource::SignedBundleFile)?;
    let mut provenance = ConfigProvenance {
        source: ConfigSource::SignedBundleFile,
        internal_config_hash: verified.manifest.config_hash.clone(),
        posture_config_hash: posture_safe_runtime_config_hash(&config_value),
        dynamic_reload_supported: false,
        last_bundle_id: Some(verified.manifest.bundle_id.clone()),
        last_bundle_sequence: Some(verified.manifest.sequence),
        last_bundle_signer_kids: verified.signer_kids.clone(),
        override_pin: override_pin.clone(),
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    if verified.manifest.bundle_id.trim().is_empty() {
        provenance.last_bundle_id = None;
    }
    Ok(LoadedConfigDocument {
        config_path: verified.config_path,
        runtime: config,
        provenance,
        pending_bundle_acceptance: Some(PendingBundleAcceptance {
            state_path: config_trust.antirollback_state_path.clone(),
            key,
            source: ConfigSource::SignedBundleFile,
            bundle_id: Some(verified.manifest.bundle_id),
            sequence: Some(verified.manifest.sequence),
            config_hash: verified.manifest.config_hash,
            previous_config_hash: verified.manifest.previous_config_hash,
            previous_hash_matched,
            signer_kids: verified.signer_kids,
            break_glass: matches!(state_action, BundleStateAction::PersistOverridePin),
            state_action,
            override_pin,
            override_path,
        }),
    })
}

fn load_unsigned_break_glass_or_pin_config_document(
    config_trust: &super::ConfigTrustConfig,
    override_path: Option<&Path>,
) -> Result<Option<LoadedConfigDocument>, Error> {
    let anchor = match load_trust_anchor(&config_trust.trust_anchor_path) {
        Ok(anchor) => anchor,
        Err(error) => {
            tracing::error!(
                code = "config.bundle_rejected",
                result = "rejected_signature",
                error = %error,
                "unsigned break-glass config trust anchor failed validation"
            );
            eprintln!("config.bundle_rejected result=rejected_signature error={error}");
            return Err(Error::from(ConfigError::ValidationError));
        }
    };
    let key = AntiRollbackKey {
        product: anchor.product,
        instance_id: anchor.instance_id,
        environment: anchor.environment,
        stream_id: anchor.stream_id,
    };
    let store = FileAntiRollbackStore::new(&config_trust.antirollback_state_path);
    let record = match store.load(&key) {
        Ok(record) => record,
        Err(error) => {
            tracing::error!(
                code = "config.bundle_rejected",
                result = "rejected_rollback",
                error = %error,
                "unsigned break-glass config requires existing anti-rollback state"
            );
            eprintln!("config.bundle_rejected result=rejected_rollback error={error}");
            return Err(Error::from(ConfigError::ValidationError));
        }
    };
    if let Some(pin) = record
        .override_pin
        .as_ref()
        .filter(|pin| {
            pin.mode == ConfigOverrideMode::AcceptUnsigned && override_pin_active_and_unexpired(pin)
        })
        .cloned()
    {
        let recovery_override_path = matching_leftover_override_path(override_path, &pin);
        return load_unsigned_pin_config_document(
            config_trust,
            key,
            record,
            pin,
            BundleStateAction::AlreadyPinned,
            recovery_override_path,
        )
        .map(Some);
    }
    let Some((override_path, override_file)) =
        load_optional_break_glass_override(override_path, ConfigBreakGlassMode::AcceptUnsigned)?
    else {
        return Ok(None);
    };
    let pin = override_pin_from_file(&override_file);
    load_unsigned_pin_config_document(
        config_trust,
        key,
        record,
        pin,
        BundleStateAction::PersistOverridePin,
        Some(override_path),
    )
    .map(Some)
}

fn load_unsigned_pin_config_document(
    config_trust: &super::ConfigTrustConfig,
    key: AntiRollbackKey,
    record: AntiRollbackRecord,
    pin: ConfigOverridePin,
    state_action: BundleStateAction,
    override_path: Option<PathBuf>,
) -> Result<LoadedConfigDocument, Error> {
    let config_path = pin
        .config_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| Error::from(ConfigError::ValidationError))?;
    let config_bytes = read_unsigned_config_bytes(&config_path)?;
    let actual = sha256_uri(&config_bytes);
    if actual != pin.config_hash {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_rollback",
            expected = %pin.config_hash,
            actual,
            "unsigned break-glass pinned config hash mismatch"
        );
        eprintln!("config.bundle_rejected result=rejected_rollback error=hash_mismatch");
        return Err(Error::from(ConfigError::ValidationError));
    }
    let (config, config_value) =
        parse_config_bytes_for_bundle(&config_bytes, ConfigSource::LocalFile)?;
    let override_pin = Some(pin.clone());
    Ok(LoadedConfigDocument {
        config_path,
        runtime: config,
        provenance: ConfigProvenance {
            source: ConfigSource::LocalFile,
            internal_config_hash: pin.config_hash.clone(),
            posture_config_hash: posture_safe_runtime_config_hash(&config_value),
            dynamic_reload_supported: false,
            last_bundle_id: record.last_bundle_id,
            last_bundle_sequence: Some(record.last_sequence),
            last_bundle_signer_kids: Vec::new(),
            override_pin: override_pin.clone(),
            last_apply_result: None,
            last_apply_at: None,
            restart_required: false,
        },
        pending_bundle_acceptance: Some(PendingBundleAcceptance {
            state_path: config_trust.antirollback_state_path.clone(),
            key,
            source: ConfigSource::LocalFile,
            bundle_id: None,
            sequence: None,
            config_hash: pin.config_hash,
            previous_config_hash: None,
            previous_hash_matched: None,
            signer_kids: Vec::new(),
            break_glass: matches!(state_action, BundleStateAction::PersistOverridePin),
            state_action,
            override_pin,
            override_path,
        }),
    })
}

fn parse_config_bytes_for_bundle(
    bytes: &[u8],
    source: ConfigSource,
) -> Result<(Config, Value), Error> {
    let config_text = std::str::from_utf8(bytes).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "config bundle primary config is not UTF-8"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Error::from(ConfigError::ParseError)
    })?;
    let expanded_config_text = expand_config_env_vars(config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "config bundle primary config failed environment expansion"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Error::from(ConfigError::ParseError)
    })?;
    let config_value: Value = serde_saphyr::from_str(&expanded_config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "config bundle primary config failed to parse"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Error::from(ConfigError::ParseError)
    })?;
    if let Err(err) = reject_deprecated_config_fields(&config_value, &deprecated_config_fields()) {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %err,
            "config bundle primary config uses a removed or renamed field"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={err}");
        return Err(Error::from(ConfigError::ParseError));
    }
    let config: Config = serde_saphyr::from_str(&expanded_config_text).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "config bundle primary config failed to deserialize"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Error::from(ConfigError::ParseError)
    })?;
    validate::run_with_source(&config, source).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "config bundle primary config failed product validation"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        error
    })?;
    Ok((config, config_value))
}

fn resolve_bundle_state_action(
    state_path: &Path,
    key: &AntiRollbackKey,
    sequence: u64,
    config_hash: &str,
    previous_config_hash: Option<&str>,
    rollback_override_path: Option<&Path>,
    initialize_state: bool,
) -> Result<
    (
        BundleStateAction,
        Option<ConfigOverridePin>,
        Option<bool>,
        Option<PathBuf>,
    ),
    Error,
> {
    let store = FileAntiRollbackStore::new(state_path);
    match store.load(key) {
        Ok(record) if sequence > record.last_sequence => Ok((
            BundleStateAction::Accept,
            None,
            previous_hash_matched(previous_config_hash, &record),
            None,
        )),
        Ok(record)
            if sequence == record.last_sequence && config_hash == record.last_config_hash =>
        {
            let matched = previous_hash_matched(previous_config_hash, &record);
            let active_pin = record
                .override_pin
                .filter(override_pin_active_and_unexpired);
            Ok((BundleStateAction::Accept, active_pin, matched, None))
        }
        Ok(record)
            if record.override_pin.as_ref().is_some_and(|pin| {
                override_pin_active_and_unexpired(pin) && pin.config_hash == config_hash
            }) =>
        {
            let matched = previous_hash_matched(previous_config_hash, &record);
            Ok((
                BundleStateAction::AlreadyPinned,
                record.override_pin,
                matched,
                None,
            ))
        }
        Ok(record) => {
            let Some((override_path, override_file)) = load_optional_break_glass_override(
                rollback_override_path,
                ConfigBreakGlassMode::AcceptRollback,
            )?
            else {
                tracing::error!(
                    code = "config.bundle_rejected",
                    result = "rejected_rollback",
                    "signed config bundle sequence is not monotonic"
                );
                eprintln!("config.bundle_rejected result=rejected_rollback");
                return Err(Error::from(ConfigError::ValidationError));
            };
            if override_file.config_hash != config_hash {
                tracing::error!(
                    code = "config.break_glass_invalid",
                    error = "hash_mismatch",
                    "rollback break-glass override hash does not match bundle config hash"
                );
                eprintln!("config.break_glass_invalid error=hash_mismatch");
                tracing::error!(
                    code = "config.bundle_rejected",
                    result = "rejected_rollback",
                    "signed config bundle sequence is not monotonic"
                );
                eprintln!("config.bundle_rejected result=rejected_rollback");
                return Err(Error::from(ConfigError::ValidationError));
            }
            let matched = previous_hash_matched(previous_config_hash, &record);
            Ok((
                BundleStateAction::PersistOverridePin,
                Some(override_pin_from_file(&override_file)),
                matched,
                Some(override_path),
            ))
        }
        Err(registry_platform_ops::AntiRollbackStoreError::MissingState) if initialize_state => {
            Ok((
                BundleStateAction::Initialize,
                None,
                previous_config_hash.map(|_| false),
                None,
            ))
        }
        Err(error) => {
            tracing::error!(
                code = "config.bundle_rejected",
                result = "rejected_rollback",
                error = %error,
                "signed config bundle anti-rollback state rejected startup"
            );
            eprintln!("config.bundle_rejected result=rejected_rollback error={error}");
            Err(Error::from(ConfigError::ValidationError))
        }
    }
}

fn load_optional_break_glass_override(
    path: Option<&Path>,
    mode: ConfigBreakGlassMode,
) -> Result<Option<(PathBuf, ConfigBreakGlassOverride)>, Error> {
    let Some(path) = path else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let override_file = load_break_glass_override(path).map_err(|error| {
        tracing::error!(
            code = "config.break_glass_invalid",
            error = %error,
            "config break-glass override rejected"
        );
        eprintln!("config.break_glass_invalid error={error}");
        Error::from(ConfigError::ValidationError)
    })?;
    if override_file.mode != mode {
        return Ok(None);
    }
    Ok(Some((path.to_path_buf(), override_file)))
}

fn matching_leftover_override_path(
    path: Option<&Path>,
    pin: &ConfigOverridePin,
) -> Option<PathBuf> {
    let path = path?;
    if !path.exists() {
        return None;
    }
    match load_break_glass_override(path) {
        Ok(override_file)
            if override_file.mode == ConfigBreakGlassMode::AcceptUnsigned
                && override_file.config_hash == pin.config_hash =>
        {
            Some(path.to_path_buf())
        }
        Ok(_) => None,
        Err(error) => {
            tracing::error!(
                code = "config.break_glass_invalid",
                error = %error,
                "config break-glass override rejected during pin recovery"
            );
            eprintln!("config.break_glass_invalid error={error}");
            None
        }
    }
}

fn read_unsigned_config_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config failed to stat"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Error::from(ConfigError::ParseError)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            "unsigned break-glass config path is not a regular file"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error=not_regular_file");
        return Err(Error::from(ConfigError::ValidationError));
    }
    if metadata.len() > registry_platform_config::MAX_BUNDLE_FILE_BYTES {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            "unsigned break-glass config exceeds maximum size"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error=max_size");
        return Err(Error::from(ConfigError::ValidationError));
    }
    let bytes = fs::read(path).map_err(|error| {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            error = %error,
            "unsigned break-glass config failed to read"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error={error}");
        Error::from(ConfigError::ParseError)
    })?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|len| len > registry_platform_config::MAX_BUNDLE_FILE_BYTES)
    {
        tracing::error!(
            code = "config.bundle_rejected",
            result = "rejected_validation",
            "unsigned break-glass config exceeds maximum size"
        );
        eprintln!("config.bundle_rejected result=rejected_validation error=max_size");
        return Err(Error::from(ConfigError::ValidationError));
    }
    Ok(bytes)
}

fn log_bundle_verification_error(error: &ConfigBundleError) {
    let result = bundle_verify_rejection_result(error);
    tracing::error!(
        code = "config.bundle_rejected",
        result,
        error = %error,
        "signed config bundle verification failed"
    );
    eprintln!("config.bundle_rejected result={result} error={error}");
}

fn previous_hash_matched(
    previous_config_hash: Option<&str>,
    record: &AntiRollbackRecord,
) -> Option<bool> {
    previous_config_hash.map(|previous| previous == record.last_config_hash)
}

fn override_pin_from_file(override_file: &ConfigBreakGlassOverride) -> ConfigOverridePin {
    ConfigOverridePin {
        active: true,
        mode: match override_file.mode {
            ConfigBreakGlassMode::AcceptRollback => ConfigOverrideMode::AcceptRollback,
            ConfigBreakGlassMode::AcceptUnsigned => ConfigOverrideMode::AcceptUnsigned,
        },
        config_hash: override_file.config_hash.clone(),
        config_path: override_file
            .config_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        expires_at: Some(override_file.expires_at.clone()),
        used_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        operator: override_file.operator.clone(),
        reason: override_file.reason.clone(),
    }
}

fn bundle_verify_rejection_result(error: &ConfigBundleError) -> &'static str {
    match error {
        ConfigBundleError::BindingMismatch(_) => "rejected_binding",
        ConfigBundleError::SignatureRejected
        | ConfigBundleError::InvalidSignatureEnvelope(_)
        | ConfigBundleError::InvalidTrustAnchor(_)
        | ConfigBundleError::InvalidPermissions(_) => "rejected_signature",
        ConfigBundleError::Io(_)
        | ConfigBundleError::Json(_)
        | ConfigBundleError::InvalidManifest(_)
        | ConfigBundleError::InvalidBreakGlass(_)
        | ConfigBundleError::FileClosure(_)
        | ConfigBundleError::HashMismatch { .. } => "rejected_validation",
    }
}

fn deprecated_config_fields() -> Vec<DeprecatedConfigField> {
    vec![
        DeprecatedConfigField::renamed("auth.oidc.audience", "auth.oidc.audiences"),
        DeprecatedConfigField::renamed("auth.oidc.algorithms", "auth.oidc.allowed_algorithms"),
        DeprecatedConfigField::renamed("auth.oidc.token_types", "auth.oidc.allowed_token_types"),
    ]
}

/// Load runtime config and, when configured, the split metadata manifest.
pub fn load_with_metadata(path: &Path) -> Result<LoadedConfig, Error> {
    load_with_metadata_options(path, LoadOptions::default())
}

pub fn load_with_metadata_options(
    path: &Path,
    options: LoadOptions,
) -> Result<LoadedConfig, Error> {
    let document = load_config_document(path, options)?;
    let (metadata, metadata_source_digest) =
        load_config_metadata(&document.config_path, &document.runtime)?;
    Ok(LoadedConfig {
        runtime: document.runtime,
        metadata,
        metadata_source_digest,
        provenance: document.provenance,
        pending_bundle_acceptance: document.pending_bundle_acceptance,
    })
}

pub fn load_config_metadata(
    config_path: &Path,
    config: &Config,
) -> Result<(Option<CompiledMetadata>, Option<String>), Error> {
    let (metadata, metadata_source_digest) = match config.metadata.as_ref() {
        Some(metadata) => {
            let manifest_path = resolve_relative_to_config(config_path, &metadata.source.path);
            let (compiled, digest) = load_metadata_manifest_with_digest(&manifest_path)?;
            if config.config_trust.is_some() && metadata.source.digest.is_none() {
                tracing::error!(
                    code = "metadata.manifest.digest_required",
                    "governed configuration requires metadata.source.digest"
                );
                return Err(MetadataError::ManifestDigestRequired.into());
            }
            if let Some(expected) = metadata.source.digest.as_deref() {
                if !is_sha256_config_hash(expected) {
                    tracing::error!(
                        code = "metadata.manifest.digest_invalid",
                        "metadata manifest configured digest is not a canonical sha256 digest"
                    );
                    return Err(MetadataError::ManifestDigestInvalid.into());
                }
                if expected != digest {
                    tracing::error!(
                        code = "metadata.manifest.digest_mismatch",
                        expected = %expected,
                        actual = %digest,
                        "metadata manifest configured digest does not match loaded manifest"
                    );
                    return Err(MetadataError::ManifestDigestMismatch.into());
                }
            }
            validate::validate_runtime_bindings(config, &compiled)?;
            (Some(compiled), Some(digest))
        }
        None => (None, None),
    };
    Ok((metadata, metadata_source_digest))
}

struct LoadedConfigDocument {
    config_path: PathBuf,
    runtime: Config,
    provenance: ConfigProvenance,
    pending_bundle_acceptance: Option<PendingBundleAcceptance>,
}

impl PendingBundleAcceptance {
    pub fn initial_record(&self) -> AntiRollbackRecord {
        AntiRollbackRecord {
            key: self.key.clone(),
            last_sequence: self
                .sequence
                .expect("initial state requires bundle sequence"),
            last_config_hash: self.config_hash.clone(),
            last_bundle_id: self.bundle_id.clone(),
            root_version: None,
            override_pin: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        }
    }
}

pub fn load_metadata_manifest(path: &Path) -> Result<CompiledMetadata, Error> {
    load_metadata_manifest_with_digest(path).map(|(compiled, _)| compiled)
}

pub fn load_metadata_manifest_with_digest(
    path: &Path,
) -> Result<(CompiledMetadata, String), Error> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(
                code = "metadata.manifest.file_not_found",
                path = %path.display(),
                error = %err,
                "failed to read metadata manifest"
            );
            return Err(MetadataError::ManifestFileNotFound.into());
        }
    };
    let manifest: MetadataManifest = match serde_saphyr::from_str(&raw) {
        Ok(manifest) => manifest,
        Err(err) => {
            tracing::error!(
                code = "metadata.manifest.parse_failed",
                path = %path.display(),
                error = %err,
                "failed to parse metadata manifest YAML"
            );
            return Err(MetadataError::ManifestParseFailed.into());
        }
    };
    let digest = metadata_core::source_manifest_digest(&manifest).map_err(|err| {
        tracing::error!(
            code = "metadata.manifest.digest_invalid",
            path = %path.display(),
            error = %err,
            "failed to compute metadata manifest digest"
        );
        Error::from(MetadataError::ManifestDigestInvalid)
    })?;
    let compiled = metadata_core::compile_manifest(&manifest).map_err(|err| {
        let code = match &err {
            CoreMetadataError::VersionUnsupported => "metadata.manifest.version_unsupported",
            CoreMetadataError::Validation { .. } => "metadata.manifest.validation_failed",
        };
        tracing::error!(
            code = code,
            path = %path.display(),
            error = %err,
            "metadata manifest failed validation"
        );
        match err {
            CoreMetadataError::VersionUnsupported => {
                Error::from(MetadataError::ManifestVersionUnsupported)
            }
            CoreMetadataError::Validation { .. } => {
                Error::from(MetadataError::ManifestValidationFailed)
            }
        }
    })?;
    Ok((compiled, digest))
}

fn resolve_relative_to_config(config_path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        return target.to_path_buf();
    }
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn missing_file_returns_parse_error() {
        let path = Path::new("/no/such/path/registry_relay_unit_test.yaml");
        let err = load(path).expect_err("missing path must fail");
        assert_eq!(err.code(), "config.parse_error");
    }

    #[test]
    fn unparseable_yaml_returns_parse_error() {
        let mut file = NamedTempFile::new().expect("tempfile");
        // Tab indentation under a mapping is not valid YAML and will
        // also fail the document grammar check.
        writeln!(file, ":\n\t- not yaml").unwrap();
        let err = load(file.path()).expect_err("garbled yaml must fail");
        assert_eq!(err.code(), "config.parse_error");
    }

    #[test]
    fn posture_config_hash_masks_secrets_and_topology() {
        let base = json!({
            "instance": { "id": "relay", "owner": "ops" },
            "server": {
                "bind": "127.0.0.1:8080",
                "admin_bind": "127.0.0.1:9090",
                "cache_dir": "/var/lib/relay"
            },
            "audit": { "hash_secret_env": "AUDIT_SECRET_A" },
            "auth": {
                "api_keys": [{
                    "key_id": "ops",
                    "fingerprint": {
                        "provider": "env",
                        "name": "KEY_HASH_A"
                    }
                }]
            },
            "datasets": [{
                "id": "benefits",
                "tables": [{
                    "id": "people",
                    "source": { "kind": "file", "path": "/private/a.csv" }
                }]
            }],
            "provenance": {
                "issuer": {
                    "did": "did:web:issuer-a.example",
                    "verification_method_id": "did:web:issuer-a.example#key-1",
                    "signer": { "kind": "software", "jwk_env": "JWK_A" }
                }
            }
        });
        let mut changed = base.clone();
        changed["server"]["bind"] = json!("10.0.0.5:8080");
        changed["server"]["cache_dir"] = json!("/srv/relay");
        changed["audit"]["hash_secret_env"] = json!("AUDIT_SECRET_B");
        changed["auth"]["api_keys"][0]["fingerprint"]["name"] = json!("KEY_HASH_B");
        changed["datasets"][0]["tables"][0]["source"]["path"] = json!("/private/b.csv");
        changed["provenance"]["issuer"]["did"] = json!("did:web:issuer-b.example");
        changed["provenance"]["issuer"]["verification_method_id"] =
            json!("did:web:issuer-b.example#key-2");
        changed["provenance"]["issuer"]["signer"]["jwk_env"] = json!("JWK_B");

        assert_eq!(
            posture_safe_runtime_config_hash(&base),
            posture_safe_runtime_config_hash(&changed)
        );
    }

    #[test]
    fn posture_config_hash_changes_for_public_config() {
        let base = json!({ "instance": { "id": "relay", "owner": "ops" } });
        let changed = json!({ "instance": { "id": "relay", "owner": "data-office" } });

        assert_ne!(
            posture_safe_runtime_config_hash(&base),
            posture_safe_runtime_config_hash(&changed)
        );

        let base = json!({ "catalog": { "base_url": "https://relay-a.example.test" } });
        let changed = json!({ "catalog": { "base_url": "https://relay-b.example.test" } });

        assert_ne!(
            posture_safe_runtime_config_hash(&base),
            posture_safe_runtime_config_hash(&changed)
        );
    }
}
