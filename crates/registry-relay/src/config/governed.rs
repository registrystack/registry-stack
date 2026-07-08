// SPDX-License-Identifier: Apache-2.0
//! Shared parsing helpers for signed config bundle verification.

use registry_manifest_core::{self as metadata_core, CompiledMetadata, MetadataManifest};
use registry_platform_ops::{
    internal_config_hash, posture_safe_runtime_config_hash, ConfigProvenance, ConfigSource,
};
use serde_json::Value;

use crate::config::{self, Config};

pub struct ParsedConfigCandidate {
    pub config: Config,
    pub provenance: ConfigProvenance,
    pub metadata: Option<CompiledMetadata>,
    pub metadata_source_digest: Option<String>,
    pub package_digest: Option<String>,
}

struct ResolvedConfigCandidate {
    bundle_id: String,
    sequence: u64,
    signer_kids: Vec<String>,
    config_yaml: String,
    metadata_yaml: Option<String>,
    metadata_source_digest: Option<String>,
    package_digest: Option<String>,
    source: ConfigSource,
}

pub fn parse_candidate_config_with_provenance(
    config_yaml: &str,
    bundle_id: &str,
    sequence: u64,
    source: ConfigSource,
) -> Result<(Config, ConfigProvenance), &'static str> {
    let parsed = parse_resolved_config_candidate_with_provenance(&ResolvedConfigCandidate {
        bundle_id: bundle_id.to_string(),
        sequence,
        signer_kids: Vec::new(),
        config_yaml: config_yaml.to_string(),
        metadata_yaml: None,
        metadata_source_digest: None,
        package_digest: None,
        source,
    })?;
    Ok((parsed.config, parsed.provenance))
}

fn parse_resolved_config_candidate_with_provenance(
    candidate: &ResolvedConfigCandidate,
) -> Result<ParsedConfigCandidate, &'static str> {
    let config_value: Value = serde_saphyr::from_str(&candidate.config_yaml)
        .map_err(|_| "candidate config could not be parsed")?;
    let config: Config = serde_saphyr::from_str(&candidate.config_yaml)
        .map_err(|_| "candidate config could not be parsed")?;
    config::validate::run_with_source(&config, candidate.source)
        .map_err(|_| "candidate config did not validate")?;
    let (metadata, metadata_source_digest) = parse_candidate_metadata(&config, candidate)?;
    let package_digest = candidate.package_digest.clone();
    let internal_hash = if metadata_source_digest.is_some() || package_digest.is_some() {
        runtime_package_digest(
            &candidate.config_yaml,
            &config,
            metadata_source_digest.as_deref(),
            package_digest.as_deref(),
            candidate.source,
        )?
    } else {
        internal_config_hash(candidate.config_yaml.as_bytes())
    };
    let mut provenance = ConfigProvenance {
        source: candidate.source,
        internal_config_hash: internal_hash,
        posture_config_hash: posture_safe_runtime_config_hash(&config_value),
        dynamic_reload_supported: false,
        last_bundle_id: Some(candidate.bundle_id.clone()),
        last_bundle_sequence: Some(candidate.sequence),
        last_bundle_signer_kids: candidate.signer_kids.clone(),
        override_pin: None,
        last_apply_result: None,
        last_apply_at: None,
        restart_required: false,
    };
    if candidate.bundle_id.trim().is_empty() {
        provenance.last_bundle_id = None;
    }
    Ok(ParsedConfigCandidate {
        config,
        provenance,
        metadata,
        metadata_source_digest,
        package_digest,
    })
}

fn parse_candidate_metadata(
    config: &Config,
    candidate: &ResolvedConfigCandidate,
) -> Result<(Option<CompiledMetadata>, Option<String>), &'static str> {
    match (&config.metadata, candidate.metadata_yaml.as_deref()) {
        (Some(metadata_config), Some(metadata_yaml)) => {
            let manifest: MetadataManifest = serde_saphyr::from_str(metadata_yaml)
                .map_err(|_| "candidate metadata payload could not be parsed")?;
            let digest = metadata_core::source_manifest_digest(&manifest)
                .map_err(|_| "candidate metadata digest could not be computed")?;
            if let Some(expected) = metadata_config.source.digest.as_deref() {
                if expected != digest {
                    return Err("candidate metadata digest did not match runtime config");
                }
            }
            if let Some(expected) = candidate.metadata_source_digest.as_deref() {
                if expected != digest {
                    return Err("candidate metadata digest did not match signed target metadata");
                }
            }
            let compiled = metadata_core::compile_manifest(&manifest)
                .map_err(|_| "candidate metadata payload did not validate")?;
            config::validate::validate_runtime_bindings(config, &compiled)
                .map_err(|_| "candidate metadata did not match runtime bindings")?;
            Ok((Some(compiled), Some(digest)))
        }
        (Some(_), None)
            if candidate.metadata_source_digest.is_some() || candidate.package_digest.is_some() =>
        {
            Err("candidate metadata payload is required")
        }
        (Some(_), None) => Ok((None, None)),
        (None, Some(_)) => Err("candidate metadata payload was provided without metadata config"),
        (None, None) => Ok((None, None)),
    }
}

fn runtime_package_digest(
    config_yaml: &str,
    config: &Config,
    metadata_source_digest: Option<&str>,
    package_digest: Option<&str>,
    source: ConfigSource,
) -> Result<String, &'static str> {
    let environment = config
        .instance
        .environment
        .as_deref()
        .unwrap_or("development");
    let mut preimage = serde_json::json!({
        "schema_version": "registry-runtime-package/v1",
        "product": "registry-relay",
        "instance_id": config.instance.id,
        "environment": environment,
        "runtime_config_digest": internal_config_hash(config_yaml.as_bytes()),
        "source": source.as_posture_str(),
    });
    if let Some(digest) = metadata_source_digest {
        preimage["source_manifest_digest"] = Value::String(digest.to_string());
    }
    if let Some(digest) = package_digest {
        preimage["package_digest"] = Value::String(digest.to_string());
    }
    let bytes = metadata_core::canonicalize_json(&preimage)
        .map_err(|_| "runtime package digest could not be computed")?;
    Ok(internal_config_hash(&bytes))
}
