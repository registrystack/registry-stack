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

use crate::error::{ConfigError, Error, MetadataError};

use super::validate;
use super::Config;

#[derive(Debug)]
pub struct LoadedConfig {
    pub runtime: Config,
    pub metadata: Option<CompiledMetadata>,
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

    let config: Config = match serde_saphyr::from_str(&raw) {
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

    validate::run(&config)?;
    Ok(config)
}

/// Load runtime config and, when configured, the split metadata manifest.
pub fn load_with_metadata(path: &Path) -> Result<LoadedConfig, Error> {
    let config = load(path)?;
    let metadata = match config.metadata.as_ref() {
        Some(metadata) => {
            let manifest_path = resolve_relative_to_config(path, &metadata.manifest_path);
            let compiled = load_metadata_manifest(&manifest_path)?;
            validate::validate_runtime_bindings(&config, &compiled)?;
            Some(compiled)
        }
        None => None,
    };
    Ok(LoadedConfig {
        runtime: config,
        metadata,
    })
}

pub fn load_metadata_manifest(path: &Path) -> Result<CompiledMetadata, Error> {
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
    metadata_core::compile_manifest(&manifest).map_err(|err| {
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
    })
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
}
