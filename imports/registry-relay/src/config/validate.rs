// SPDX-License-Identifier: Apache-2.0
//! Cross-field validation for the parsed [`Config`].
//!
//! Each check returns the most specific [`ConfigError`] variant from
//! the taxonomy; operator-visible context (offending dataset / resource
//! / field id, env var name, etc.) is emitted to `tracing` at error
//! level so the operator sees what failed in their logs while the
//! response/audit detail strings stay scrubbed.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::net::IpAddr;

use crate::error::{ConfigError, Error};

use super::{
    AggregateConfig, AllowedFilter, AuthMode, Config, DatasetConfig, EntityConfig,
    EntityRelationshipConfig, FieldConfig, MaterializationMode, RefreshConfig, RelationshipKind,
    ResourceConfig, SourceConfig,
};

/// Prefix for the special `admin` scope. Spec.md Section 8.
const ADMIN_SCOPE: &str = "admin";

/// Run every cross-field check on a freshly deserialised [`Config`].
///
/// # Errors
///
/// Returns the corresponding [`ConfigError`] variant on the first
/// failure. Multiple failures are not aggregated in V1 to keep the
/// error type unit-shaped; the operator log line names the offending
/// field.
pub fn run(config: &Config) -> Result<(), Error> {
    super::vocabularies::validate_registry(&config.vocabularies).map_err(Error::from)?;
    validate_server(config).map_err(Error::from)?;
    validate_ids_and_uniqueness(config).map_err(Error::from)?;
    validate_scopes(config).map_err(Error::from)?;
    validate_env_vars_and_hashes(config).map_err(Error::from)?;
    validate_resources(config).map_err(Error::from)?;
    if let Some(provenance) = &config.provenance {
        validate_provenance(provenance).map_err(Error::from)?;
    }
    validate_publicschema_feature(config).map_err(Error::from)?;
    validate_spdci_feature(config).map_err(Error::from)?;
    Ok(())
}

fn validate_spdci_feature(config: &Config) -> Result<(), ConfigError> {
    let Some(spdci) = &config.standards.spdci else {
        return Ok(());
    };
    validate_spdci_config(config, spdci)
}

#[cfg(not(feature = "spdci-api-standards"))]
fn validate_spdci_config(
    _config: &Config,
    _spdci: &super::SpdciStandardsConfig,
) -> Result<(), ConfigError> {
    tracing::error!(
        code = "spdci.config.feature_disabled",
        "standards.spdci is configured but binary was built without the spdci-api-standards feature",
    );
    Err(ConfigError::SpdciFeatureDisabled)
}

#[cfg(feature = "spdci-api-standards")]
fn validate_spdci_config(
    config: &Config,
    spdci: &super::SpdciStandardsConfig,
) -> Result<(), ConfigError> {
    let Some(disability) = &spdci.disability_registry else {
        tracing::error!(
            code = "config.validation_error",
            "standards.spdci must declare at least one adapter"
        );
        return Err(ConfigError::ValidationError);
    };
    validate_spdci_disability_registry(config, disability)
}

#[cfg(feature = "spdci-api-standards")]
fn validate_spdci_disability_registry(
    config: &Config,
    disability: &super::SpdciDisabilityRegistryConfig,
) -> Result<(), ConfigError> {
    if disability.entity.trim().is_empty()
        || disability.query_key.trim().is_empty()
        || disability.query_field.trim().is_empty()
        || disability.disabled_status_field.trim().is_empty()
        || disability.disabled_positive_values.is_empty()
        || disability
            .disabled_positive_values
            .iter()
            .any(|value| value.trim().is_empty())
    {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %disability.dataset,
            entity = %disability.entity,
            "standards.spdci.disability_registry fields must not be empty"
        );
        return Err(ConfigError::ValidationError);
    }

    let dataset = config
        .datasets
        .iter()
        .find(|dataset| dataset.id == disability.dataset)
        .ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %disability.dataset,
                "standards.spdci.disability_registry references an unknown dataset"
            );
            ConfigError::ValidationError
        })?;
    let entity = dataset
        .entities
        .iter()
        .find(|entity| entity.name == disability.entity)
        .ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %disability.dataset,
                entity = %disability.entity,
                "standards.spdci.disability_registry references an unknown entity"
            );
            ConfigError::ValidationError
        })?;
    let table = dataset
        .table_configs()
        .find(|table| table.id == entity.table)
        .ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %disability.dataset,
                entity = %disability.entity,
                table_id = %entity.table,
                "standards.spdci.disability_registry entity references an unknown table"
            );
            ConfigError::ValidationError
        })?;
    let fields = exposed_entity_fields(entity, table)?;
    for required in [
        disability.query_field.as_str(),
        disability.disabled_status_field.as_str(),
    ] {
        if !fields.contains_key(required) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %disability.dataset,
                entity = %disability.entity,
                field = %required,
                "standards.spdci.disability_registry references an unknown entity field"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    if !entity
        .api
        .allowed_filters
        .iter()
        .any(|filter| filter.field == disability.query_field)
    {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %disability.dataset,
            entity = %disability.entity,
            field = %disability.query_field,
            "standards.spdci.disability_registry query_field must be allowed as an entity filter"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_publicschema_feature(config: &Config) -> Result<(), ConfigError> {
    for dataset in &config.datasets {
        for entity in &dataset.entities {
            let Some(publicschema) = &entity.publicschema else {
                continue;
            };
            #[cfg(not(feature = "publicschema-cel"))]
            {
                let _ = publicschema;
                tracing::error!(
                    code = "publicschema.config.feature_disabled",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "entity declares publicschema mapping but binary was built without the publicschema-cel feature",
                );
                return Err(ConfigError::PublicSchemaFeatureDisabled);
            }

            #[cfg(feature = "publicschema-cel")]
            {
                if publicschema.target.trim().is_empty() {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        "publicschema.target must not be empty",
                    );
                    return Err(ConfigError::ValidationError);
                }
                if publicschema.mapping_path.as_os_str().is_empty() {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        "publicschema.mapping_path must not be empty",
                    );
                    return Err(ConfigError::ValidationError);
                }
                if let Some(context_url) = &publicschema.context_url {
                    if !is_http_url(context_url) {
                        tracing::error!(
                            code = "config.validation_error",
                            dataset_id = %dataset.id,
                            entity = %entity.name,
                            "publicschema.context_url must be an http(s) URL",
                        );
                        return Err(ConfigError::ValidationError);
                    }
                }
                if let Some(schema_url) = &publicschema.schema_url {
                    if !is_http_url(schema_url) {
                        tracing::error!(
                            code = "config.validation_error",
                            dataset_id = %dataset.id,
                            entity = %entity.name,
                            "publicschema.schema_url must be an http(s) URL",
                        );
                        return Err(ConfigError::ValidationError);
                    }
                }
                if publicschema
                    .schema_validation_path
                    .as_ref()
                    .is_some_and(|path| path.as_os_str().is_empty())
                {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        "publicschema.schema_validation_path must not be empty",
                    );
                    return Err(ConfigError::ValidationError);
                }
                if publicschema
                    .credential_type
                    .as_deref()
                    .is_some_and(|credential_type| credential_type.trim().is_empty())
                {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        "publicschema.credential_type must not be empty",
                    );
                    return Err(ConfigError::ValidationError);
                }
            }
        }
    }
    Ok(())
}

/// Cross-field validation for provenance configuration.
///
/// When `enabled = false` the block still validates its shape so
/// operators get fast feedback when they enable it.
fn validate_provenance(cfg: &super::provenance::ProvenanceConfig) -> Result<(), ConfigError> {
    use super::provenance::{IssuerConfig, SignerConfig};

    // Claim validity windows: 1 minute lower bound, 365 days upper.
    let min = std::time::Duration::from_secs(60);
    let max = std::time::Duration::from_secs(60 * 60 * 24 * 365);
    for (name, value) in [
        ("verify_result", cfg.claim_validity.verify_result),
        ("aggregate_result", cfg.claim_validity.aggregate_result),
        ("entity_record", cfg.claim_validity.entity_record),
    ] {
        if value < min || value > max {
            tracing::error!(
                code = "provenance.config.claim_validity_out_of_range",
                claim = %name,
                "claim_validity.{name} must be between 1m and 365d",
            );
            return Err(ConfigError::ProvenanceClaimValidityOutOfRange);
        }
    }

    if !is_http_url(&cfg.context_base_url) {
        tracing::error!(
            code = "provenance.config.context_base_url_invalid",
            "context_base_url must be a syntactically valid http(s) URL",
        );
        return Err(ConfigError::ProvenanceContextBaseUrlInvalid);
    }
    if !is_http_url(&cfg.schema_base_url) {
        tracing::error!(
            code = "provenance.config.schema_base_url_invalid",
            "schema_base_url must be a syntactically valid http(s) URL",
        );
        return Err(ConfigError::ProvenanceSchemaBaseUrlInvalid);
    }

    let (issuer_did, vm_id, signer, _retired) = match &cfg.issuer {
        IssuerConfig::Gateway(g) => (
            g.did.as_str(),
            g.verification_method_id.as_str(),
            &g.signer,
            &g.retired_keys,
        ),
        IssuerConfig::Delegated(d) => (
            d.ministry_did.as_str(),
            d.verification_method_id.as_str(),
            &d.signer,
            &d.retired_keys,
        ),
    };

    if issuer_did.is_empty() {
        tracing::error!(
            code = "provenance.config.missing_issuer",
            "issuer DID is empty",
        );
        return Err(ConfigError::ProvenanceMissingIssuer);
    }
    // `verification_method_id` must start with `<did>#`.
    let prefix = format!("{issuer_did}#");
    if !vm_id.starts_with(&prefix) {
        tracing::error!(
            code = "provenance.config.verification_method_mismatch",
            "verification_method_id must be a fragment of the issuer DID",
        );
        return Err(ConfigError::ProvenanceVerificationMethodMismatch);
    }

    // Signer-level validation.
    match signer {
        SignerConfig::Software(s) => {
            if !matches!(
                s.signing_algorithm,
                super::provenance::ProvenanceAlgorithm::EdDSA
                    | super::provenance::ProvenanceAlgorithm::ES256
            ) {
                tracing::error!(
                    code = "provenance.config.algorithm_unsupported",
                    "signing_algorithm must be EdDSA or ES256",
                );
                return Err(ConfigError::ProvenanceAlgorithmUnsupported);
            }
            // The in-process software signer only ships the EdDSA path
            // in V1; `SoftwareSigner::from_config` returns a `KeyLoad`
            // error at sign-time for ES256. Reject the combination
            // here so operators discover the gap at startup rather
            // than on the first protected request.
            if s.signing_algorithm == super::provenance::ProvenanceAlgorithm::ES256 {
                tracing::error!(
                    code = "provenance.config.algorithm_unsupported",
                    "software signer does not yet support ES256; use EdDSA",
                );
                return Err(ConfigError::ProvenanceAlgorithmUnsupported);
            }
            // Only require the env var to be present at validation time
            // when provenance is enabled. With `enabled: false` the env
            // var may legitimately be absent in non-production.
            if cfg.enabled {
                let present = env::var(&s.jwk_env)
                    .ok()
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                if !present {
                    tracing::error!(
                        code = "provenance.config.jwk_env_missing",
                        jwk_env = %s.jwk_env,
                        "software signer jwk_env is unset or empty",
                    );
                    return Err(ConfigError::ProvenanceJwkEnvMissing);
                }
            }
        }
        SignerConfig::Kms(k) => {
            tracing::error!(
                code = "provenance.config.signer_kind_invalid",
                provider = ?k.provider,
                signing_algorithm = %k.signing_algorithm.as_str(),
                "kms signer is reserved for future backends; V1 supports only software signing",
            );
            return Err(ConfigError::ProvenanceSignerKindInvalid);
        }
    }

    Ok(())
}

fn is_http_url(s: &str) -> bool {
    // Minimal scheme check. Full URL parsing is out of scope for V1
    // (no `url` crate dependency).
    s.starts_with("http://") || s.starts_with("https://")
}

/// Match `^[a-z][a-z0-9_]*$` without pulling in a regex crate.
fn is_valid_id(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn validate_server(config: &Config) -> Result<(), ConfigError> {
    for cidr in &config.server.trust_proxy.trusted_proxies {
        if !is_trusted_proxy_spec(cidr) {
            tracing::error!(
                code = "config.validation_error",
                trusted_proxy = %cidr,
                "trusted_proxies entry must be an IP address or CIDR range"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    for origin in &config.server.cors.allowed_origins {
        if !is_valid_cors_origin(origin) {
            tracing::error!(
                code = "config.validation_error",
                "cors allowed_origins entry must be scheme://host[:port] with no path or query; wildcard '*' is not permitted"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

/// Validate a CORS origin entry.
///
/// Accepts `scheme://host` or `scheme://host:port`. Rejects `*`,
/// origins with a path component, query strings, or missing scheme.
fn is_valid_cors_origin(s: &str) -> bool {
    // Reject the wildcard explicitly; it would allow any origin.
    if s == "*" {
        return false;
    }
    // Must start with a scheme followed by "://".
    let after_scheme = match s.split_once("://") {
        Some((scheme, rest)) if !scheme.is_empty() => rest,
        _ => return false,
    };
    if after_scheme.is_empty() {
        return false;
    }
    // No path or query allowed after the host[:port] portion.
    if after_scheme.contains('/') || after_scheme.contains('?') || after_scheme.contains('#') {
        return false;
    }
    // The host portion must be non-empty (port after ':' is optional).
    let host = after_scheme
        .split_once(':')
        .map_or(after_scheme, |(h, _)| h);
    !host.is_empty()
}

fn is_trusted_proxy_spec(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((addr, prefix)) = trimmed.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let Ok(bits) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => bits <= 32,
        IpAddr::V6(_) => bits <= 128,
    }
}

fn validate_ids_and_uniqueness(config: &Config) -> Result<(), ConfigError> {
    let mut dataset_ids: HashSet<&str> = HashSet::new();
    for dataset in &config.datasets {
        if !is_valid_id(dataset.id.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                "dataset id does not match ^[a-z][a-z0-9_]*$"
            );
            return Err(ConfigError::ValidationError);
        }
        if !dataset_ids.insert(dataset.id.as_str()) {
            tracing::error!(
                code = "config.duplicate_id",
                dataset_id = %dataset.id,
                "duplicate dataset id"
            );
            return Err(ConfigError::DuplicateId);
        }

        let mut resource_ids: HashSet<&str> = HashSet::new();
        for resource in dataset.table_configs() {
            if !is_valid_id(resource.id.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    "resource id does not match ^[a-z][a-z0-9_]*$"
                );
                return Err(ConfigError::ValidationError);
            }
            if !resource_ids.insert(resource.id.as_str()) {
                tracing::error!(
                    code = "config.duplicate_id",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    "duplicate resource id within dataset"
                );
                return Err(ConfigError::DuplicateId);
            }

            let mut aggregate_ids: HashSet<&str> = HashSet::new();
            for aggregate in &resource.aggregates {
                if !is_valid_id(aggregate.id.as_str()) {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        resource_id = %resource.id,
                        aggregate_id = %aggregate.id,
                        "aggregate id does not match ^[a-z][a-z0-9_]*$"
                    );
                    return Err(ConfigError::ValidationError);
                }
                if !aggregate_ids.insert(aggregate.id.as_str()) {
                    tracing::error!(
                        code = "config.duplicate_id",
                        dataset_id = %dataset.id,
                        resource_id = %resource.id,
                        aggregate_id = %aggregate.id,
                        "duplicate aggregate id within resource"
                    );
                    return Err(ConfigError::DuplicateId);
                }
            }
        }

        let mut entity_names: HashSet<&str> = HashSet::new();
        for entity in &dataset.entities {
            if !is_valid_id(&entity.name) || is_reserved_entity_segment(&entity.name) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "entity name is invalid or reserved"
                );
                return Err(ConfigError::ValidationError);
            }
            if !entity_names.insert(&entity.name) {
                tracing::error!(
                    code = "config.duplicate_id",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "duplicate entity name within dataset"
                );
                return Err(ConfigError::DuplicateId);
            }
        }
    }
    Ok(())
}

fn validate_scopes(config: &Config) -> Result<(), ConfigError> {
    let dataset_ids: HashSet<&str> = config.datasets.iter().map(|d| d.id.as_str()).collect();

    for key in &config.auth.api_keys {
        if !is_valid_id(&key.id) {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                "api key id does not match ^[a-z][a-z0-9_]*$"
            );
            return Err(ConfigError::ValidationError);
        }
        for scope in &key.scopes {
            validate_scope(scope, &dataset_ids, &key.id)?;
        }
    }
    Ok(())
}

fn validate_scope(
    scope: &str,
    dataset_ids: &HashSet<&str>,
    api_key_id: &str,
) -> Result<(), ConfigError> {
    if scope == ADMIN_SCOPE {
        return Ok(());
    }
    let (dataset, level) = scope.split_once(':').ok_or_else(|| {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %api_key_id,
            scope = %scope,
            "scope must be 'admin' or '<dataset_id>:<metadata|aggregate|rows|verify|bulk_export>'"
        );
        ConfigError::ValidationError
    })?;

    match level {
        "metadata" | "aggregate" | "rows" | "verify" | "bulk_export" => {}
        _ => {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %api_key_id,
                scope = %scope,
                "unknown scope level (allowed: metadata, aggregate, rows, verify, bulk_export)"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    if !dataset_ids.contains(dataset) {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %api_key_id,
            scope = %scope,
            dataset_id = %dataset,
            "scope references unknown dataset"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_env_vars_and_hashes(config: &Config) -> Result<(), ConfigError> {
    if config.auth.mode != AuthMode::ApiKey {
        return Ok(());
    }
    for key in &config.auth.api_keys {
        if key.hash_env.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                "hash_env must be a non-empty environment variable name"
            );
            return Err(ConfigError::ValidationError);
        }
        let value = match env::var(&key.hash_env) {
            Ok(v) => v,
            Err(_) => {
                tracing::error!(
                    code = "config.missing_secret",
                    api_key_id = %key.id,
                    hash_env = %key.hash_env,
                    "hash_env environment variable is not set"
                );
                return Err(ConfigError::MissingSecret);
            }
        };
        if let Err(reason) = validate_api_key_fingerprint(&value) {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                hash_env = %key.hash_env,
                reason = %reason,
                "hash_env value failed API key fingerprint validation"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

/// Validate a high-entropy API key fingerprint. Raw API keys are random
/// 32-byte values generated out-of-band; configs store only
/// `sha256:<64 lowercase hex chars>` so request authentication is a
/// digest plus a map lookup.
fn validate_api_key_fingerprint(value: &str) -> Result<(), &'static str> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or("API key fingerprint must start with sha256:")?;
    if hex.len() != 64 {
        return Err("API key fingerprint must contain 64 lowercase hex characters");
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("API key fingerprint must contain lowercase hex only");
    }
    Ok(())
}

fn validate_resources(config: &Config) -> Result<(), ConfigError> {
    for dataset in &config.datasets {
        validate_dataset_uris(&config.vocabularies, dataset)?;
        validate_sources(dataset)?;
        validate_format_overrides(dataset)?;
        for resource in dataset.table_configs() {
            validate_schema_uris(&config.vocabularies, dataset, resource)?;
            validate_allowed_filters(dataset, resource)?;
            for aggregate in &resource.aggregates {
                validate_aggregate(dataset, resource, aggregate)?;
            }
        }
        validate_entities(&config.vocabularies, dataset)?;
    }
    Ok(())
}

fn validate_format_overrides(dataset: &DatasetConfig) -> Result<(), ConfigError> {
    if let Some(SourceConfig::File {
        format: Some(format),
        ..
    }) = &dataset.source
    {
        validate_dataset_format_config(dataset, format, "dataset.source.format")?;
    }

    for resource in dataset.table_configs() {
        if let Some(format) = &resource.format {
            validate_format_config(dataset, resource, format, "resource.format")?;
        }
        if let Some(SourceConfig::File {
            format: Some(format),
            ..
        }) = &resource.source
        {
            validate_format_config(dataset, resource, format, "resource.source.format")?;
        }
    }
    Ok(())
}

fn validate_dataset_format_config(
    dataset: &DatasetConfig,
    format: &super::ResourceFormatConfig,
    field: &'static str,
) -> Result<(), ConfigError> {
    let count = usize::from(format.csv.is_some())
        + usize::from(format.xlsx.is_some())
        + usize::from(format.parquet.is_some());
    if count != 1 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            field,
            "format config must declare exactly one of csv, xlsx, parquet"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_format_config(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    format: &super::ResourceFormatConfig,
    field: &'static str,
) -> Result<(), ConfigError> {
    let count = usize::from(format.csv.is_some())
        + usize::from(format.xlsx.is_some())
        + usize::from(format.parquet.is_some());
    if count != 1 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            field,
            "format config must declare exactly one of csv, xlsx, parquet"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_sources(dataset: &DatasetConfig) -> Result<(), ConfigError> {
    if let Some(source) = &dataset.source {
        validate_source_config(dataset, None, source)?;
    }

    for resource in dataset.table_configs() {
        let source = resource.effective_source(dataset).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "table source is required when dataset.source is absent"
            );
            ConfigError::ValidationError
        })?;
        let refresh = resource.effective_refresh(dataset).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "table refresh is required when no dataset refresh/default is configured"
            );
            ConfigError::ValidationError
        })?;
        validate_source_config(dataset, Some(resource), source)?;
        validate_materialization_refresh(dataset, resource, source, refresh)?;
    }
    Ok(())
}

fn validate_dataset_uris(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
) -> Result<(), ConfigError> {
    for uri in &dataset.conforms_to {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                uri = %uri,
                "conforms_to URI uses an unregistered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_source_config(
    dataset: &DatasetConfig,
    resource: Option<&ResourceConfig>,
    source: &SourceConfig,
) -> Result<(), ConfigError> {
    match source {
        SourceConfig::File { path, .. } => {
            if path.as_os_str().is_empty() {
                log_table_validation_error(dataset, resource, "source.path is empty");
                return Err(ConfigError::ValidationError);
            }
        }
        SourceConfig::Postgres {
            connection_env,
            table,
            query,
            change_token_sql,
            connect_timeout,
            query_timeout,
            live_max_connections,
        } => {
            if !is_valid_env_var_name(connection_env) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                    connection_env = %connection_env,
                    "postgres connection_env must be a non-empty environment variable name"
                );
                return Err(ConfigError::ValidationError);
            }

            if table.is_some() == query.is_some() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                    "postgres source must declare exactly one of table or query"
                );
                return Err(ConfigError::ValidationError);
            }

            if let Some(table) = table {
                if !is_valid_postgres_identifier(&table.schema)
                    || !is_valid_postgres_identifier(&table.name)
                {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                        connection_env = %connection_env,
                        "postgres table schema and name must be simple identifiers"
                    );
                    return Err(ConfigError::ValidationError);
                }
            }

            if query.as_deref().is_some_and(|sql| sql.trim().is_empty()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                    connection_env = %connection_env,
                    "postgres query must not be empty"
                );
                return Err(ConfigError::ValidationError);
            }
            if let Some(sql) = query.as_deref() {
                validate_configured_postgres_query(dataset, resource, connection_env, sql)?;
            }

            if change_token_sql
                .as_deref()
                .is_some_and(|sql| sql.trim().is_empty())
            {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                    connection_env = %connection_env,
                    "postgres change_token_sql must not be empty when configured"
                );
                return Err(ConfigError::ValidationError);
            }
            if let Some(sql) = change_token_sql.as_deref() {
                validate_configured_postgres_query(dataset, resource, connection_env, sql)?;
            }

            if connect_timeout.is_zero() || query_timeout.is_zero() || *live_max_connections == 0 {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                    connection_env = %connection_env,
                    "postgres timeouts must be non-zero and live_max_connections must be greater than zero"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn validate_configured_postgres_query(
    dataset: &DatasetConfig,
    resource: Option<&ResourceConfig>,
    connection_env: &str,
    sql: &str,
) -> Result<(), ConfigError> {
    let trimmed = sql.trim();
    if trimmed.contains(';') {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
            connection_env = %connection_env,
            "postgres configured SQL must be a single statement without semicolons"
        );
        return Err(ConfigError::ValidationError);
    }

    let first_word = trimmed
        .split_whitespace()
        .next()
        .map(str::to_ascii_lowercase);
    if !matches!(first_word.as_deref(), Some("select" | "with")) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
            connection_env = %connection_env,
            "postgres configured SQL must start with SELECT or WITH"
        );
        return Err(ConfigError::ValidationError);
    }

    Ok(())
}

fn validate_materialization_refresh(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    source: &SourceConfig,
    refresh: &RefreshConfig,
) -> Result<(), ConfigError> {
    let materialization = resource.effective_materialization(dataset);

    if materialization == MaterializationMode::Live && matches!(source, SourceConfig::File { .. }) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            "file sources support only snapshot materialization"
        );
        return Err(ConfigError::ValidationError);
    }

    if matches!(
        (materialization, source),
        (
            MaterializationMode::Live,
            SourceConfig::Postgres { query: Some(_), .. }
        )
    ) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            "postgres live materialization supports table sources only"
        );
        return Err(ConfigError::ValidationError);
    }

    if materialization == MaterializationMode::Live
        && matches!(refresh, RefreshConfig::Mtime { .. })
    {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            "live materialization does not support mtime refresh"
        );
        return Err(ConfigError::ValidationError);
    }

    if let (
        SourceConfig::Postgres {
            change_token_sql, ..
        },
        RefreshConfig::Mtime { .. },
    ) = (source, refresh)
    {
        if change_token_sql.is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "postgres mtime refresh requires change_token_sql"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    Ok(())
}

fn log_table_validation_error(
    dataset: &DatasetConfig,
    resource: Option<&ResourceConfig>,
    msg: &str,
) {
    if let Some(resource) = resource {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            "{msg}"
        );
    } else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            "{msg}"
        );
    }
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_valid_postgres_identifier(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn validate_schema_uris(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
) -> Result<(), ConfigError> {
    for field in &resource.schema.fields {
        if let Some(uri) = &field.concept_uri {
            if super::vocabularies::expand(uri, registry).is_none() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    field = %field.name,
                    uri = %uri,
                    "field.concept_uri uses an unregistered vocabulary prefix"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn validate_allowed_filters(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
) -> Result<(), ConfigError> {
    let field_names: HashSet<&str> = field_names_of(resource);
    for filter in &resource.api.allowed_filters {
        validate_filter(dataset, resource, filter, &field_names)?;
    }
    Ok(())
}

/// Project the schema's field name set; reused by aggregate validation.
fn field_names_of(resource: &ResourceConfig) -> HashSet<&str> {
    resource
        .schema
        .fields
        .iter()
        .map(|f: &FieldConfig| f.name.as_str())
        .collect()
}

fn validate_filter(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    filter: &AllowedFilter,
    field_names: &HashSet<&str>,
) -> Result<(), ConfigError> {
    if !field_names.contains(filter.field.as_str()) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            field = %filter.field,
            "allowed_filters references a field not in the resource schema"
        );
        return Err(ConfigError::ValidationError);
    }
    if filter.ops.is_empty() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            field = %filter.field,
            "allowed_filters entry must declare at least one op"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_aggregate(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    aggregate: &AggregateConfig,
) -> Result<(), ConfigError> {
    let field_names: HashSet<&str> = field_names_of(resource);

    if aggregate.disclosure_control.min_group_size < 1 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = %resource.id,
            aggregate_id = %aggregate.id,
            "disclosure_control.min_group_size must be >= 1"
        );
        return Err(ConfigError::ValidationError);
    }

    for column in &aggregate.group_by {
        if !field_names.contains(column.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                aggregate_id = %aggregate.id,
                column = %column,
                "aggregate group_by references a field not in the resource schema"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    for measure in &aggregate.measures {
        if !field_names.contains(measure.column.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                aggregate_id = %aggregate.id,
                measure = %measure.name,
                column = %measure.column,
                "aggregate measure references a field not in the resource schema"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_entities(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
) -> Result<(), ConfigError> {
    if dataset.entities.is_empty() {
        return Ok(());
    }

    let tables: BTreeMap<&str, &ResourceConfig> = dataset
        .table_configs()
        .map(|table| (table.id.as_str(), table))
        .collect();
    let entities: BTreeMap<&str, &EntityConfig> = dataset
        .entities
        .iter()
        .map(|entity| (entity.name.as_str(), entity))
        .collect();

    for entity in &dataset.entities {
        validate_entity_uris(registry, dataset, entity)?;
        let table = tables.get(entity.table.as_str()).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                table_id = %entity.table,
                "entity references an unknown backing table"
            );
            ConfigError::ValidationError
        })?;

        let exposed_fields = exposed_entity_fields(entity, table)?;
        validate_entity_primary_key(dataset, entity, table, &exposed_fields)?;
        validate_entity_filters(dataset, entity, &exposed_fields)?;
        validate_entity_aggregates(dataset, entity, &exposed_fields)?;
        validate_entity_relationships(dataset, entity, table, &tables, &entities)?;
    }

    Ok(())
}

fn validate_entity_uris(
    registry: &BTreeMap<String, String>,
    dataset: &DatasetConfig,
    entity: &EntityConfig,
) -> Result<(), ConfigError> {
    if let Some(uri) = &entity.concept_uri {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                uri = %uri,
                "entity concept_uri uses an unregistered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    for field in &entity.fields {
        if let Some(uri) = &field.concept_uri {
            if super::vocabularies::expand(uri, registry).is_none() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    field = %field.name,
                    uri = %uri,
                    "entity field concept_uri uses an unregistered vocabulary prefix"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    for relationship in &entity.relationships {
        if let Some(uri) = &relationship.concept_uri {
            if super::vocabularies::expand(uri, registry).is_none() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    relationship = %relationship.name,
                    uri = %uri,
                    "entity relationship concept_uri uses an unregistered vocabulary prefix"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn exposed_entity_fields(
    entity: &EntityConfig,
    table: &ResourceConfig,
) -> Result<BTreeMap<String, String>, ConfigError> {
    let table_fields = field_names_of(table);
    if entity.fields.is_empty() {
        return Ok(table
            .schema
            .fields
            .iter()
            .map(|field| (field.name.clone(), field.name.clone()))
            .collect());
    }

    let mut exposed = BTreeMap::new();
    for field in &entity.fields {
        if !is_valid_id(&field.name) {
            tracing::error!(
                code = "config.validation_error",
                entity = %entity.name,
                field = %field.name,
                "entity field name is not a valid lower-snake id"
            );
            return Err(ConfigError::ValidationError);
        }
        let source = field.from.as_deref().unwrap_or(&field.name);
        if !table_fields.contains(source) {
            tracing::error!(
                code = "config.validation_error",
                entity = %entity.name,
                field = %field.name,
                from = %source,
                table_id = %table.id,
                "entity field projection references a missing table column"
            );
            return Err(ConfigError::ValidationError);
        }
        if exposed
            .insert(field.name.clone(), source.to_string())
            .is_some()
        {
            tracing::error!(
                code = "config.duplicate_id",
                entity = %entity.name,
                field = %field.name,
                "duplicate entity field"
            );
            return Err(ConfigError::DuplicateId);
        }
    }
    Ok(exposed)
}

fn validate_entity_primary_key(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let Some(primary_key) = table.primary_key.as_deref() else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            table_id = %table.id,
            "entity backing table must declare primary_key"
        );
        return Err(ConfigError::ValidationError);
    };
    let pk_exposures = exposed_fields
        .values()
        .filter(|from| from.as_str() == primary_key)
        .count();
    if pk_exposures != 1 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            table_id = %table.id,
            primary_key = %primary_key,
            exposures = pk_exposures,
            "exactly one entity field must expose the backing table primary key"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_entity_filters(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let allowed_filter_fields: HashSet<&str> = entity
        .api
        .allowed_filters
        .iter()
        .map(|f| f.field.as_str())
        .collect();

    for filter in &entity.api.allowed_filters {
        if !exposed_fields.contains_key(&filter.field) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %filter.field,
                "entity allowed_filters references a non-exposed field"
            );
            return Err(ConfigError::ValidationError);
        }
        if filter.ops.is_empty() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %filter.field,
                "entity allowed_filters entry must declare at least one op"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    for field in &entity.api.required_filters {
        if !allowed_filter_fields.contains(field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %field,
                "entity required_filters entry is not present in allowed_filters"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    Ok(())
}

fn validate_entity_aggregates(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for aggregate in &entity.aggregates {
        let join_names: HashSet<&str> = aggregate
            .joins
            .iter()
            .map(|join| join.relationship.as_str())
            .collect();
        for join in &aggregate.joins {
            if !entity
                .relationships
                .iter()
                .any(|rel| rel.name == join.relationship)
            {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    aggregate_id = %aggregate.id,
                    relationship = %join.relationship,
                    "entity aggregate join references an unknown relationship"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        if aggregate.disclosure_control.min_group_size < 1 {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                aggregate_id = %aggregate.id,
                "entity aggregate min_group_size must be >= 1"
            );
            return Err(ConfigError::ValidationError);
        }
        for field in &aggregate.group_by {
            if let Some((relationship, related_field)) = field.split_once('.') {
                if !join_names.contains(relationship) || related_field.is_empty() {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        aggregate_id = %aggregate.id,
                        field = %field,
                        "relationship-prefixed aggregate group_by must reference a declared aggregate join"
                    );
                    return Err(ConfigError::ValidationError);
                }
            } else if !exposed_fields.contains_key(field) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    aggregate_id = %aggregate.id,
                    field = %field,
                    "entity aggregate group_by references a non-exposed field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        for measure in &aggregate.measures {
            if !exposed_fields.contains_key(&measure.column) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    aggregate_id = %aggregate.id,
                    column = %measure.column,
                    "entity aggregate measure references a non-exposed field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

fn validate_entity_relationships(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    tables: &BTreeMap<&str, &ResourceConfig>,
    entities: &BTreeMap<&str, &EntityConfig>,
) -> Result<(), ConfigError> {
    let mut names = HashSet::new();
    if !entity.api.allowed_expansions.is_empty()
        && !entity
            .api
            .allowed_expansions
            .iter()
            .all(|name| entity.relationships.iter().any(|rel| &rel.name == name))
    {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            "allowed_expansions references an unknown relationship"
        );
        return Err(ConfigError::ValidationError);
    }

    for relationship in &entity.relationships {
        if !is_valid_id(&relationship.name)
            || is_reserved_relationship_segment(&relationship.name)
            || !names.insert(relationship.name.as_str())
        {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                relationship = %relationship.name,
                "relationship name is invalid, reserved, or duplicated"
            );
            return Err(ConfigError::ValidationError);
        }
        let target = entities.get(relationship.target.as_str()).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                relationship = %relationship.name,
                target = %relationship.target,
                "relationship target entity does not exist"
            );
            ConfigError::ValidationError
        })?;
        let target_table = tables
            .get(target.table.as_str())
            .expect("target entity table was validated earlier or will be validated in same pass");
        validate_relationship_fk(dataset, entity, table, relationship, target, target_table)?;
    }
    Ok(())
}

fn validate_relationship_fk(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    relationship: &EntityRelationshipConfig,
    target: &EntityConfig,
    target_table: &ResourceConfig,
) -> Result<(), ConfigError> {
    let (fk_table, pk_table) = match relationship.kind {
        RelationshipKind::BelongsTo => (table, target_table),
        RelationshipKind::HasMany | RelationshipKind::HasOne => (target_table, table),
    };
    let Some(fk_field) = field_by_name(fk_table, &relationship.foreign_key) else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            foreign_key = %relationship.foreign_key,
            "relationship foreign_key is missing on the expected table"
        );
        return Err(ConfigError::ValidationError);
    };
    let Some(pk_name) = pk_table.primary_key.as_deref() else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            target = %target.name,
            "relationship target/source table lacks primary_key"
        );
        return Err(ConfigError::ValidationError);
    };
    let Some(pk_field) = field_by_name(pk_table, pk_name) else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            primary_key = %pk_name,
            "relationship primary key column is missing"
        );
        return Err(ConfigError::ValidationError);
    };
    if fk_field.r#type != pk_field.r#type {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            foreign_key = %relationship.foreign_key,
            "relationship foreign_key type does not match primary key type"
        );
        return Err(ConfigError::ValidationError);
    }
    if relationship.kind == RelationshipKind::HasOne {
        tracing::warn!(
            code = "config.validation_warning",
            dataset_id = %dataset.id,
            entity = %entity.name,
            relationship = %relationship.name,
            "has_one uniqueness cannot be statically proven from config"
        );
    }
    Ok(())
}

fn field_by_name<'a>(resource: &'a ResourceConfig, name: &str) -> Option<&'a FieldConfig> {
    resource
        .schema
        .fields
        .iter()
        .find(|field| field.name == name)
}

fn is_reserved_entity_segment(name: &str) -> bool {
    matches!(
        name,
        "catalog" | "admin" | "health" | "ready" | "openapi.json"
    )
}

fn is_reserved_relationship_segment(name: &str) -> bool {
    matches!(name, "aggregates" | "schema" | "verify" | "exports")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_regex_accepts_canonical() {
        assert!(is_valid_id("social_registry"));
        assert!(is_valid_id("a"));
        assert!(is_valid_id("a1_b2"));
    }

    #[test]
    fn id_regex_rejects_uppercase_or_leading_digit_or_dash() {
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("Social_registry"));
        assert!(!is_valid_id("1_social"));
        assert!(!is_valid_id("social-registry"));
        assert!(!is_valid_id("social registry"));
    }

    #[test]
    fn api_key_fingerprint_check_accepts_canonical_shape() {
        let sample = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(
            validate_api_key_fingerprint(sample).is_ok(),
            "canonical shape should pass"
        );
    }

    #[test]
    fn api_key_fingerprint_check_rejects_missing_prefix_and_plain_text() {
        assert!(validate_api_key_fingerprint("not_a_fingerprint").is_err());
        assert!(validate_api_key_fingerprint("$argon2id$...").is_err());
        assert!(validate_api_key_fingerprint("").is_err());
    }

    #[test]
    fn api_key_fingerprint_check_rejects_wrong_length() {
        let err = validate_api_key_fingerprint("sha256:abc").expect_err("short hash rejected");
        assert!(
            err.contains("64 lowercase hex"),
            "error mentions length: {err}"
        );
    }

    #[test]
    fn api_key_fingerprint_check_rejects_uppercase_hex() {
        let err = validate_api_key_fingerprint(
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .expect_err("uppercase hash rejected");
        assert!(err.contains("lowercase hex"), "error mentions hex: {err}");
    }

    #[test]
    fn cors_origin_accepts_scheme_host() {
        assert!(is_valid_cors_origin("https://allowed.example.gov"));
        assert!(is_valid_cors_origin("https://allowed.example.gov:8443"));
        assert!(is_valid_cors_origin("http://localhost:3000"));
    }

    #[test]
    fn cors_origin_rejects_wildcard_and_paths() {
        assert!(!is_valid_cors_origin("*"));
        assert!(!is_valid_cors_origin("https://example.gov/path"));
        assert!(!is_valid_cors_origin("https://example.gov?q=1"));
        assert!(!is_valid_cors_origin("https://example.gov#anchor"));
        assert!(!is_valid_cors_origin("example.gov"));
        assert!(!is_valid_cors_origin("://example.gov"));
    }

    #[test]
    fn trusted_proxy_specs_accept_ips_and_cidrs() {
        assert!(is_trusted_proxy_spec("127.0.0.1"));
        assert!(is_trusted_proxy_spec("10.0.0.0/8"));
        assert!(is_trusted_proxy_spec("::1"));
        assert!(is_trusted_proxy_spec("2001:db8::/32"));
    }

    #[test]
    fn trusted_proxy_specs_reject_bad_values() {
        assert!(!is_trusted_proxy_spec(""));
        assert!(!is_trusted_proxy_spec("not-an-ip"));
        assert!(!is_trusted_proxy_spec("10.0.0.0/99"));
        assert!(!is_trusted_proxy_spec("2001:db8::/129"));
    }
}
