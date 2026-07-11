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
    expand_config_env_vars, reject_deprecated_config_fields, verify_config_bundle,
    ConfigBundleError, DeprecatedConfigField, VerifiedConfigBundle,
};
use registry_platform_ops::{
    antirollback_key_from_verified_bundle, bundle_verify_rejection_result, internal_config_hash,
    is_sha256_config_hash, load_unsigned_break_glass_or_pin, posture_safe_runtime_config_hash,
    resolve_bundle_state_action, BundleStateRequest, ConfigBootError, ConfigProvenance,
    ConfigSource, UnsignedConfigSelection,
};
pub use registry_platform_ops::{BundleStateAction, PendingBundleAcceptance};
use serde_json::Value;

use crate::error::{ConfigError, Error, MetadataError};

use super::consultation_artifacts::{
    load_consultation_artifacts, ConsultationArtifactClosureError, SignedBundleRuntimeFiles,
};
use super::validate;
use super::{Config, VerifiedConsultationArtifactClosure};

#[derive(Debug)]
pub struct LoadedConfig {
    pub runtime: Config,
    pub metadata: Option<CompiledMetadata>,
    pub metadata_source_digest: Option<String>,
    /// Verified startup inputs for consultation compilation. `None` means
    /// consultation execution is disabled, never an empty ready registry.
    pub consultation_artifacts: Option<VerifiedConsultationArtifactClosure>,
    pub provenance: ConfigProvenance,
    pub pending_bundle_acceptance: Option<PendingBundleAcceptance>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    pub initialize_state: bool,
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
    let consultation_artifacts =
        load_consultation_artifacts(path, &config, ConfigSource::LocalFile, None)
            .map_err(map_consultation_artifact_error)?;
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
        signed_bundle_files: None,
        consultation_artifacts,
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
    let key = antirollback_key_from_verified_bundle(&verified);
    let state_decision = resolve_bundle_state_action(BundleStateRequest {
        state_path: &config_trust.antirollback_state_path,
        key: &key,
        sequence: verified.manifest.sequence,
        config_hash: &verified.manifest.config_hash,
        bundle_manifest_hash: &verified.manifest_hash,
        previous_config_hash: verified.manifest.previous_config_hash.as_deref(),
        rollback_override_path: config_trust.break_glass_override_path.as_deref(),
        initialize_state: options.initialize_state,
    })
    .map_err(map_config_boot_error)?;
    let (config, config_value) =
        parse_config_bytes_for_bundle(&verified.config_bytes, ConfigSource::SignedBundleFile)?;
    let signed_bundle_files = SignedBundleRuntimeFiles::from_verified(&verified)
        .map_err(map_consultation_artifact_error)?;
    let consultation_artifacts = load_consultation_artifacts(
        &verified.config_path,
        &config,
        ConfigSource::SignedBundleFile,
        Some(&signed_bundle_files),
    )
    .map_err(map_consultation_artifact_error)?;
    let provenance = ConfigProvenance {
        source: ConfigSource::SignedBundleFile,
        internal_config_hash: verified.manifest.config_hash.clone(),
        posture_config_hash: posture_safe_runtime_config_hash(&config_value),
        dynamic_reload_supported: false,
        last_bundle_id: Some(verified.manifest.bundle_id.clone()),
        last_bundle_sequence: Some(verified.manifest.sequence),
        last_bundle_signer_kids: verified.signer_kids.clone(),
        override_pin: state_decision.override_pin.clone(),
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    Ok(LoadedConfigDocument {
        config_path: verified.config_path,
        runtime: config,
        provenance,
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
        signed_bundle_files: Some(signed_bundle_files),
        consultation_artifacts,
    })
}

fn load_unsigned_break_glass_or_pin_config_document(
    config_trust: &super::ConfigTrustConfig,
    override_path: Option<&Path>,
) -> Result<Option<LoadedConfigDocument>, Error> {
    let Some(selection) = load_unsigned_break_glass_or_pin(
        &config_trust.trust_anchor_path,
        &config_trust.antirollback_state_path,
        override_path,
    )
    .map_err(map_config_boot_error)?
    else {
        return Ok(None);
    };
    load_unsigned_pin_config_document(config_trust, selection).map(Some)
}

fn load_unsigned_pin_config_document(
    config_trust: &super::ConfigTrustConfig,
    selection: UnsignedConfigSelection,
) -> Result<LoadedConfigDocument, Error> {
    let (config, config_value) =
        parse_config_bytes_for_bundle(&selection.config_bytes, ConfigSource::LocalFile)?;
    let override_pin = Some(selection.pin.clone());
    let consultation_artifacts = load_consultation_artifacts(
        &selection.config_path,
        &config,
        ConfigSource::LocalFile,
        None,
    )
    .map_err(map_consultation_artifact_error)?;
    Ok(LoadedConfigDocument {
        config_path: selection.config_path,
        runtime: config,
        provenance: ConfigProvenance {
            source: ConfigSource::LocalFile,
            internal_config_hash: selection.pin.config_hash.clone(),
            posture_config_hash: posture_safe_runtime_config_hash(&config_value),
            dynamic_reload_supported: false,
            last_bundle_id: selection.record.last_bundle_id,
            last_bundle_sequence: Some(selection.record.last_sequence),
            last_bundle_signer_kids: Vec::new(),
            override_pin: override_pin.clone(),
            last_apply_result: None,
            last_apply_at: None,
            restart_required: false,
        },
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
        signed_bundle_files: None,
        consultation_artifacts,
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

fn map_config_boot_error(error: ConfigBootError) -> Error {
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
    Error::from(ConfigError::ValidationError)
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
    let (metadata, metadata_source_digest) = load_config_metadata_for_source(
        &document.config_path,
        &document.runtime,
        document.provenance.source,
        document.signed_bundle_files.as_ref(),
    )?;
    Ok(LoadedConfig {
        runtime: document.runtime,
        metadata,
        metadata_source_digest,
        consultation_artifacts: document.consultation_artifacts,
        provenance: document.provenance,
        pending_bundle_acceptance: document.pending_bundle_acceptance,
    })
}

pub fn validate_verified_bundle_runtime(verified: &VerifiedConfigBundle) -> Result<(), Error> {
    let (runtime, _) =
        parse_config_bytes_for_bundle(&verified.config_bytes, ConfigSource::SignedBundleFile)?;
    let signed_bundle_files = SignedBundleRuntimeFiles::from_verified(verified)
        .map_err(map_consultation_artifact_error)?;
    load_consultation_artifacts(
        &verified.config_path,
        &runtime,
        ConfigSource::SignedBundleFile,
        Some(&signed_bundle_files),
    )
    .map_err(map_consultation_artifact_error)?;
    load_config_metadata_for_source(
        &verified.config_path,
        &runtime,
        ConfigSource::SignedBundleFile,
        Some(&signed_bundle_files),
    )?;
    Ok(())
}

pub fn load_config_metadata(
    config_path: &Path,
    config: &Config,
) -> Result<(Option<CompiledMetadata>, Option<String>), Error> {
    load_config_metadata_for_source(config_path, config, ConfigSource::LocalFile, None)
}

fn load_config_metadata_for_source(
    config_path: &Path,
    config: &Config,
    source: ConfigSource,
    signed_bundle_files: Option<&SignedBundleRuntimeFiles>,
) -> Result<(Option<CompiledMetadata>, Option<String>), Error> {
    let (metadata, metadata_source_digest) = match config.metadata.as_ref() {
        Some(metadata) => {
            let manifest_path = if source == ConfigSource::SignedBundleFile {
                signed_bundle_files
                    .ok_or_else(|| Error::from(MetadataError::ManifestFileNotFound))?
                    .resolve_metadata_path(&metadata.source.path)
                    .map_err(|_| Error::from(MetadataError::ManifestFileNotFound))?
            } else {
                resolve_relative_to_config(config_path, &metadata.source.path)
            };
            let (compiled, digest) = load_metadata_manifest_with_digest(&manifest_path)?;
            if (config.config_trust.is_some() || source == ConfigSource::SignedBundleFile)
                && metadata.source.digest.is_none()
            {
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
    signed_bundle_files: Option<SignedBundleRuntimeFiles>,
    consultation_artifacts: Option<VerifiedConsultationArtifactClosure>,
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

fn map_consultation_artifact_error(error: ConsultationArtifactClosureError) -> Error {
    tracing::error!(
        code = "config.consultation_artifact_closure_rejected",
        error = %error,
        "consultation artifact closure rejected startup"
    );
    Error::from(ConfigError::ValidationError)
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
            }]
        });
        let mut changed = base.clone();
        changed["server"]["bind"] = json!("10.0.0.5:8080");
        changed["server"]["cache_dir"] = json!("/srv/relay");
        changed["audit"]["hash_secret_env"] = json!("AUDIT_SECRET_B");
        changed["auth"]["api_keys"][0]["fingerprint"]["name"] = json!("KEY_HASH_B");
        changed["datasets"][0]["tables"][0]["source"]["path"] = json!("/private/b.csv");

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
