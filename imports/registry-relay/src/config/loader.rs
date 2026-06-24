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
    expand_config_env_vars, reject_deprecated_config_fields, DeprecatedConfigField,
};
use registry_platform_ops::{
    internal_config_hash, is_sha256_config_hash, posture_safe_runtime_config_hash, ConfigProvenance,
};
use serde_json::Value;

use crate::error::{ConfigError, Error, MetadataError};

use super::validate;
use super::Config;

#[derive(Debug)]
pub struct LoadedConfig {
    pub runtime: Config,
    pub metadata: Option<CompiledMetadata>,
    pub metadata_source_digest: Option<String>,
    pub provenance: ConfigProvenance,
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
    Ok(load_config_document(path)?.runtime)
}

fn load_config_document(path: &Path) -> Result<LoadedConfigDocument, Error> {
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

    validate::run(&config)?;
    let provenance = ConfigProvenance::local_file(
        internal_config_hash(expanded.as_bytes()),
        posture_safe_runtime_config_hash(&config_value),
        false,
    );
    Ok(LoadedConfigDocument {
        runtime: config,
        provenance,
    })
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
    let document = load_config_document(path)?;
    let (metadata, metadata_source_digest) = load_config_metadata(path, &document.runtime)?;
    Ok(LoadedConfig {
        runtime: document.runtime,
        metadata,
        metadata_source_digest,
        provenance: document.provenance,
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
    runtime: Config,
    provenance: ConfigProvenance,
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
                        "name": "KEY_HASH_A",
                        "commitment": "sha256:dd137781fa21a07dab0c30e53cde951cd974d201b8fa2183a5bef5f6ad3219d5"
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
        changed["auth"]["api_keys"][0]["fingerprint"]["commitment"] =
            json!("sha256:3b25f6aee025d6b906b835f3d18d0a6a683c9ab8cb91c43517e2fe2c74f7be65");
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
