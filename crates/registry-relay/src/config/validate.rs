// SPDX-License-Identifier: Apache-2.0
//! Cross-field validation for the parsed [`Config`].
//!
//! Each check returns the most specific [`ConfigError`] variant from
//! the taxonomy; operator-visible context (offending dataset / resource
//! / field id, env var name, etc.) is emitted to `tracing` at error
//! level so the operator sees what failed in their logs while the
//! response/audit detail strings stay scrubbed.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use crate::error::{ConfigError, Error, RuntimeBindingError};
use crate::table_provider::table_name;
use registry_manifest_core::CompiledMetadata;
use registry_platform_authcommon::CredentialFingerprintRefError;
use registry_platform_httpsec::CorsPolicy;
use registry_platform_ops::ConfigSource;

use super::capabilities::source_capabilities;
use super::{
    AggregateConfig, AggregateSpatialConfig, AllowedFilter, AttributeReleaseProfile,
    AuditSinkConfig, AuthMode, Config, DatasetConfig, EntityConfig, EntityRelationshipConfig,
    EntitySpatialConfig, FieldConfig, FieldType, FilterOp, GovernedPolicyConfig, OidcConfig,
    RefreshConfig, RelationshipKind, ReleaseClaimConfig, ResourceConfig, Sensitivity, SourceConfig,
    SpatialBboxFieldsConfig, SpatialGeometryConfig, CRS84,
};

/// Product-scoped admin capability required by private admin mutations.
const ADMIN_SCOPE: &str = "registry_relay:admin";
const METRICS_SCOPE: &str = crate::observability::METRICS_SCOPE;
const OPS_READ_SCOPE: &str = "registry_relay:ops_read";
const RESERVED_SCOPE_DATASET_IDS: &[&str] = &["registry_relay"];
const DEPLOYMENT_PROFILE_REQUIRED_ACTION: &str =
    "set deployment.profile: local for development, or production/evidence_grade for deployment";

/// Run every cross-field check on a freshly deserialised [`Config`] loaded
/// from a local YAML file.
///
/// This is the startup path: the config originates from a local file, so the
/// deployment gates are evaluated against [`ConfigSource::LocalFile`]. The
/// signed governed apply path calls [`run_with_source`] with the candidate's
/// real provenance source instead.
///
/// # Errors
///
/// Returns the corresponding [`ConfigError`] variant on the first
/// failure. Multiple failures are not aggregated in V1 to keep the
/// error type unit-shaped; the operator log line names the offending
/// field.
pub fn run(config: &Config) -> Result<(), Error> {
    run_with_source(config, ConfigSource::LocalFile)
}

/// Run every cross-field check, evaluating the deployment gates against the
/// config's real provenance `source`.
///
/// All checks other than the deployment gates are provenance-independent, so
/// they behave identically to [`run`]. Only the `relay.config.unsigned` gate
/// reads `source`: a signed bundle clears it, a local file (or unknown
/// provenance) does not.
///
/// # Errors
///
/// Returns the corresponding [`ConfigError`] variant on the first failure.
pub fn run_with_source(config: &Config, source: ConfigSource) -> Result<(), Error> {
    super::vocabularies::validate_registry(&config.vocabularies).map_err(Error::from)?;
    validate_server(config).map_err(Error::from)?;
    validate_config_trust(config).map_err(Error::from)?;
    validate_consultation(config).map_err(Error::from)?;
    validate_auth_mode(config).map_err(Error::from)?;
    validate_auth_failure_throttle(config).map_err(Error::from)?;
    validate_ids_and_uniqueness(config).map_err(Error::from)?;
    validate_scopes(config).map_err(Error::from)?;
    validate_env_vars_and_hashes(config).map_err(Error::from)?;
    validate_catalog_uris(config).map_err(Error::from)?;
    validate_ogc_feature_flags(config).map_err(Error::from)?;
    validate_resources(config).map_err(Error::from)?;
    validate_spdci_feature(config).map_err(Error::from)?;
    validate_audit_ack_cursor(config).map_err(Error::from)?;
    validate_deployment(config, source).map_err(Error::from)?;
    Ok(())
}

/// Validate the restart-only audit-pseudonym material catalog without loading
/// any secret values.
///
/// Key-id and environment-name grammar is enforced by the typed serde model.
/// This pass enforces the cross-entry bounds and uniqueness that cannot be
/// expressed by individual value types. Source names are deliberately omitted
/// from diagnostics.
fn validate_consultation(config: &Config) -> Result<(), ConfigError> {
    let Some(consultation) = &config.consultation else {
        return Ok(());
    };
    super::consultation_artifacts::validate_consultation_artifact_config(consultation).map_err(
        |error| {
            tracing::error!(
                code = "config.consultation_artifact_closure_invalid",
                error = %error,
                "consultation artifact closure configuration is invalid"
            );
            ConfigError::ValidationError
        },
    )?;
    let entries = consultation.audit_pseudonym_materials.entries();
    if entries.is_empty() || entries.len() > super::MAX_AUDIT_PSEUDONYM_MATERIALS {
        tracing::error!(
            code = "config.validation_error",
            field = "consultation.audit_pseudonym_materials",
            count = entries.len(),
            "audit-pseudonym material catalog must contain between 1 and 32 entries"
        );
        return Err(ConfigError::ValidationError);
    }

    let mut key_ids = HashSet::with_capacity(entries.len());
    let mut source_names = HashSet::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if !key_ids.insert(entry.key_id.as_str()) {
            tracing::error!(
                code = "config.duplicate_id",
                field = "consultation.audit_pseudonym_materials",
                index,
                "audit-pseudonym material catalog contains a duplicate key id"
            );
            return Err(ConfigError::DuplicateId);
        }
        if !source_names.insert(entry.source.environment_name().as_str()) {
            tracing::error!(
                code = "config.validation_error",
                field = "consultation.audit_pseudonym_materials",
                index,
                "audit-pseudonym material catalog contains a duplicate source reference"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

/// Validate the audit off-host ack cursor evidence declarations.
///
/// A cursor observes off-host shipping freshness, so its config must be
/// self-consistent:
///
/// * `audit_ack_max_age_secs` without `audit_ack_cursor_path` is rejected: a
///   freshness window is meaningless with no cursor to observe.
/// * `audit_ack_cursor_path` on a local file sink whose operator has not
///   declared `audit_offhost_shipping` is rejected: the cursor asserts observed
///   shipping that the deployment does not claim. Stdout and syslog sinks ship
///   inherently, so they may configure a cursor without the boolean.
fn validate_audit_ack_cursor(config: &Config) -> Result<(), ConfigError> {
    let evidence = &config.deployment.evidence;
    if evidence.audit_ack_max_age_secs.is_some() && evidence.audit_ack_cursor_path.is_none() {
        tracing::error!(
            code = "config.validation_error",
            field = "deployment.evidence.audit_ack_max_age_secs",
            "audit_ack_max_age_secs is set without deployment.evidence.audit_ack_cursor_path; a \
             freshness window is meaningless without a cursor to observe"
        );
        return Err(ConfigError::ValidationError);
    }
    if evidence.audit_ack_cursor_path.is_some()
        && matches!(config.audit.sink, AuditSinkConfig::File { .. })
        && !evidence.audit_offhost_shipping
    {
        tracing::error!(
            code = "config.validation_error",
            field = "deployment.evidence.audit_ack_cursor_path",
            "audit_ack_cursor_path asserts observed off-host shipping, but the audit sink is a \
             local file and deployment.evidence.audit_offhost_shipping is false; set \
             audit_offhost_shipping: true or remove the cursor path"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

/// Validate the deployment block and evaluate startup gates.
///
/// Waiver finding ids must match the finding id pattern, waiver dates must be
/// well-formed `YYYY-MM-DD`, reasons must be non-empty, and the deployment must
/// not omit `deployment.profile` or declare a profile under which any unwaived
/// `startup_fail` gate triggers. An invalid profile value is rejected earlier by
/// `serde` (the parse error path); this check covers the conditions that only
/// hold once the whole config is deserialised.
///
/// `source` is the config's real provenance source. The startup path passes
/// [`ConfigSource::LocalFile`]; the signed governed apply path threads the
/// candidate's real source so a signed bundle is evaluated as such and the
/// `relay.config.unsigned` gate does not fire for it.
fn validate_deployment(config: &Config, source: ConfigSource) -> Result<(), ConfigError> {
    for waiver in &config.deployment.waivers {
        if waiver.finding.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                "deployment waiver is missing a finding id"
            );
            return Err(ConfigError::ValidationError);
        }
        if !is_valid_finding_id(&waiver.finding) {
            tracing::error!(
                code = "config.validation_error",
                finding = %waiver.finding,
                "deployment waiver finding id does not match ^[a-z][a-z0-9]*(?:\\.[a-z][a-z0-9_-]*)*$"
            );
            return Err(ConfigError::ValidationError);
        }
        if waiver.reason.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                finding = %waiver.finding,
                "deployment waiver is missing a reason"
            );
            return Err(ConfigError::ValidationError);
        }
        if !is_iso8601_date(&waiver.expires) {
            tracing::error!(
                code = "config.validation_error",
                finding = %waiver.finding,
                "deployment waiver expiry must be an ISO 8601 YYYY-MM-DD date"
            );
            return Err(ConfigError::ValidationError);
        }
        // A waiver that names a hard, non-waivable gate (startup_fail or
        // readiness_fail) under the active profile can never suppress it.
        // Silently dropping such a waiver would let an operator believe a hard
        // gate was waived when it was not, so reject it at load, mirroring
        // Notary's `HardGateNotWaivable`. Waivable and unbound gates are left to
        // gate evaluation. This check keys on the gate's severity under the
        // profile, not on whether its condition currently holds, so the operator
        // hears about an impossible waiver even before the condition trips.
        if let Some(severity) =
            crate::deployment::gate_severity_for_profile(&waiver.finding, config.deployment.profile)
        {
            if !crate::deployment::severity_is_waivable(severity) {
                tracing::error!(
                    code = "config.validation_error",
                    finding = %waiver.finding,
                    action = crate::deployment::hard_gate_remediation(&waiver.finding),
                    "deployment waiver names a hard deployment gate that cannot be waived under the active profile"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }

    let facts = crate::deployment::facts_from_config(config, source);
    let waivers = crate::deployment::waivers_from_config(config);
    let evaluation = crate::deployment::evaluate(
        config.deployment.profile,
        &facts,
        &waivers,
        &crate::deployment::today_utc(),
    );
    log_deployment_boot_findings(&evaluation);
    if evaluation.has_startup_failure() {
        tracing::error!(
            code = "config.validation_error",
            gates = ?evaluation.startup_failures,
            action = DEPLOYMENT_PROFILE_REQUIRED_ACTION,
            "deployment profile gates refuse startup"
        );
        if evaluation
            .startup_failures
            .iter()
            .any(|finding| finding == crate::deployment::PROFILE_UNDECLARED)
        {
            return Err(ConfigError::DeploymentProfileRequired);
        }
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

/// Boot-time visibility for gate outcomes that pass validation. A waiver
/// actively suppressing a finding, an expired waiver, and an undeclared
/// profile each get a warn line, so a boot that runs with reduced posture is
/// loud in the log instead of visible only on the posture surface.
fn log_deployment_boot_findings(evaluation: &crate::deployment::GateEvaluation) {
    fn waiver_fields(finding: &registry_platform_ops::DeploymentFinding) -> (&str, &str) {
        finding.waiver.as_ref().map_or(("", ""), |waiver| {
            (waiver.reason.as_str(), waiver.expires.as_str())
        })
    }

    for finding in &evaluation.findings {
        if finding.status == registry_platform_ops::DeploymentFindingStatus::Waived {
            let (reason, expires) = waiver_fields(finding);
            tracing::warn!(
                code = "deployment.gate_waived",
                finding = %finding.id,
                reason = %reason,
                expires = %expires,
                "deployment gate finding is suppressed by an active waiver"
            );
        } else if finding.id == crate::deployment::WAIVER_EXPIRED {
            let (reason, expires) = waiver_fields(finding);
            tracing::warn!(
                code = "deployment.waiver_expired",
                reason = %reason,
                expires = %expires,
                "deployment waiver is expired; its gate binds again"
            );
        } else if finding.id == crate::deployment::PROFILE_UNDECLARED {
            tracing::warn!(
                code = "deployment.profile_undeclared",
                "deployment profile is undeclared; no profile gates bind"
            );
        }
    }
}

/// Lenient `YYYY-MM-DD` shape check: four digits, dash, two digits, dash, two
/// digits, with calendar parsing to reject impossible dates.
fn is_iso8601_date(value: &str) -> bool {
    use time::format_description::well_known::Iso8601;
    use time::Date;

    Date::parse(value, &Iso8601::DATE).is_ok()
}

fn validate_config_trust(config: &Config) -> Result<(), ConfigError> {
    let Some(config_trust) = &config.config_trust else {
        return Ok(());
    };
    if config_trust.trust_anchor_path.as_os_str().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            "config_trust.trust_anchor_path must not be empty"
        );
        return Err(ConfigError::ValidationError);
    }
    if config_trust.bundle_path.as_os_str().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            "config_trust.bundle_path must not be empty"
        );
        return Err(ConfigError::ValidationError);
    }
    if config_trust.antirollback_state_path.as_os_str().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            "config_trust.antirollback_state_path must not be empty"
        );
        return Err(ConfigError::ValidationError);
    }
    if config_trust
        .break_glass_override_path
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        tracing::error!(
            code = "config.validation_error",
            "config_trust.break_glass_override_path must not be empty when set"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

/// Validate runtime bindings against a compiled split metadata manifest.
pub fn validate_runtime_bindings(
    config: &Config,
    metadata: &CompiledMetadata,
) -> Result<(), RuntimeBindingError> {
    validate_ecosystem_binding_selector(config, metadata)?;
    let selected_governed_binding = config
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.ecosystem_binding.as_ref())
        .is_some();
    for dataset in &config.datasets {
        let Some(metadata_dataset) = metadata.dataset(dataset.id.as_str()) else {
            tracing::error!(
                code = "runtime.binding.dataset_missing",
                dataset_id = %dataset.id,
                "runtime dataset is not declared in the metadata manifest"
            );
            return Err(RuntimeBindingError::DatasetMissing);
        };
        let tables = dataset
            .table_configs()
            .map(|table| (table.id.as_str(), table))
            .collect::<BTreeMap<_, _>>();
        for entity in &dataset.entities {
            let Some(metadata_entity) = metadata_dataset.entities.get(&entity.name) else {
                tracing::error!(
                    code = "runtime.binding.entity_missing",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "runtime entity is not declared in the metadata manifest"
                );
                return Err(RuntimeBindingError::EntityMissing);
            };
            let table = tables.get(entity.table.as_str()).ok_or_else(|| {
                tracing::error!(
                    code = "runtime.binding.table_missing",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    table_id = %entity.table,
                    "runtime entity references an unknown backing table"
                );
                RuntimeBindingError::TableMissing
            })?;
            let exposed_fields = exposed_entity_fields(entity, table)
                .map_err(|_| RuntimeBindingError::FieldMissing)?;
            for field in exposed_fields.keys() {
                if !metadata_entity.fields.contains_key(field) {
                    tracing::error!(
                        code = "runtime.binding.field_missing",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        field = %field,
                        "runtime field is not declared in the metadata manifest"
                    );
                    return Err(RuntimeBindingError::FieldMissing);
                }
            }
            for filter in &entity.api.allowed_filters {
                if !metadata_entity.fields.contains_key(&filter.field) {
                    tracing::error!(
                        code = "runtime.binding.filter_missing",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        field = %filter.field,
                        "runtime allowed filter is not declared in the metadata manifest"
                    );
                    return Err(RuntimeBindingError::FilterMissing);
                }
            }
            for field in &entity.api.required_filters {
                if !metadata_entity.fields.contains_key(field) {
                    tracing::error!(
                        code = "runtime.binding.filter_missing",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        field = %field,
                        "runtime required filter is not declared in the metadata manifest"
                    );
                    return Err(RuntimeBindingError::FilterMissing);
                }
            }
            if selected_governed_binding && governed_runtime_surface_is_inert(dataset, entity) {
                tracing::error!(
                    code = "runtime.binding.ecosystem_binding_invalid",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    "selected governed ecosystem binding requires sensitive runtime entities to declare an enforced purpose header or governed policy gate"
                );
                return Err(RuntimeBindingError::EcosystemBindingInvalid);
            }
            for relationship in &entity.relationships {
                if !metadata_dataset.entities.contains_key(&relationship.target) {
                    tracing::error!(
                        code = "runtime.binding.relationship_missing",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        relationship = %relationship.name,
                        target = %relationship.target,
                        "relationship target is not declared in the metadata manifest"
                    );
                    return Err(RuntimeBindingError::RelationshipMissing);
                }
                let Some(metadata_relationship) = metadata_entity
                    .relationships
                    .iter()
                    .find(|candidate| candidate.name == relationship.name)
                else {
                    tracing::error!(
                        code = "runtime.binding.relationship_missing",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        relationship = %relationship.name,
                        "runtime relationship is not declared in the metadata manifest"
                    );
                    return Err(RuntimeBindingError::RelationshipMissing);
                };
                if metadata_relationship.target != relationship.target {
                    tracing::error!(
                        code = "runtime.binding.relationship_missing",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        relationship = %relationship.name,
                        manifest_target = %metadata_relationship.target,
                        runtime_target = %relationship.target,
                        "runtime relationship target does not match the metadata manifest"
                    );
                    return Err(RuntimeBindingError::RelationshipMissing);
                }
            }
        }
        for offering in metadata_dataset.evidence_offerings.values() {
            let _entity = dataset
                .entities
                .iter()
                .find(|entity| entity.name == offering.entity)
                .ok_or_else(|| {
                    tracing::error!(
                        code = "runtime.binding.entity_missing",
                        dataset_id = %dataset.id,
                        offering = %offering.id,
                        entity = %offering.entity,
                        "evidence offering references an unknown runtime entity"
                    );
                    RuntimeBindingError::EntityMissing
                })?;
            let Some(metadata_entity) = metadata_dataset.entities.get(&offering.entity) else {
                tracing::error!(
                    code = "runtime.binding.entity_missing",
                    dataset_id = %dataset.id,
                    offering = %offering.id,
                    entity = %offering.entity,
                    "evidence offering references an entity not declared in metadata"
                );
                return Err(RuntimeBindingError::EntityMissing);
            };
            for field in &offering.lookup_keys {
                if !metadata_entity.fields.contains_key(field) {
                    tracing::error!(
                        code = "runtime.binding.field_missing",
                        dataset_id = %dataset.id,
                        offering = %offering.id,
                        field = %field,
                        "evidence offering lookup key is not declared in metadata"
                    );
                    return Err(RuntimeBindingError::FieldMissing);
                }
            }
            if offering.access.kind != "registry-notary" {
                tracing::error!(
                    code = "runtime.binding.unsupported_evidence_offering",
                    dataset_id = %dataset.id,
                    offering = %offering.id,
                    access_kind = %offering.access.kind,
                    "Registry Relay only supports external Registry Notary evidence offerings"
                );
                return Err(RuntimeBindingError::UnsupportedEvidenceOffering);
            }
        }
    }
    Ok(())
}

fn governed_runtime_surface_is_inert(dataset: &DatasetConfig, entity: &EntityConfig) -> bool {
    matches!(
        dataset.sensitivity,
        Sensitivity::Personal | Sensitivity::Confidential | Sensitivity::Secret
    ) && !entity.api.require_purpose_header
        && !entity
            .api
            .governed_policy
            .as_ref()
            .is_some_and(governed_policy_has_enforced_gate)
}

fn validate_ecosystem_binding_selector(
    config: &Config,
    metadata: &CompiledMetadata,
) -> Result<(), RuntimeBindingError> {
    let Some(selector) = config
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.ecosystem_binding.as_ref())
    else {
        return Ok(());
    };
    if selector.id.trim().is_empty()
        || selector
            .version
            .as_deref()
            .is_some_and(|version| version.trim().is_empty())
    {
        tracing::error!(
            code = "runtime.binding.ecosystem_binding_invalid",
            "metadata.ecosystem_binding must declare a non-empty id and version when present"
        );
        return Err(RuntimeBindingError::EcosystemBindingInvalid);
    }

    let matches = metadata
        .ecosystem_bindings()
        .iter()
        .filter(|binding| {
            binding.id == selector.id
                && selector
                    .version
                    .as_deref()
                    .is_none_or(|version| binding.version == version)
        })
        .collect::<Vec<_>>();
    let binding = match matches.as_slice() {
        [binding] => *binding,
        [] => {
            tracing::error!(
                code = "runtime.binding.ecosystem_binding_missing",
                binding_id = %selector.id,
                binding_version = selector.version.as_deref().unwrap_or("<any>"),
                "configured ecosystem binding selector is absent from the metadata manifest"
            );
            return Err(RuntimeBindingError::EcosystemBindingMissing);
        }
        _ => {
            tracing::error!(
                code = "runtime.binding.ecosystem_binding_invalid",
                binding_id = %selector.id,
                "configured ecosystem binding selector matched multiple metadata bindings"
            );
            return Err(RuntimeBindingError::EcosystemBindingInvalid);
        }
    };
    let evidence_pack = binding.evidence_pack.as_ref();
    if binding.binding_type != "governed-evidence"
        || evidence_pack
            .and_then(|pack| pack.policy_id.as_deref())
            .is_none_or(|policy_id| policy_id.trim().is_empty())
        || evidence_pack
            .and_then(|pack| pack.policy_hash.as_deref())
            .is_none_or(|policy_hash| policy_hash.trim().is_empty())
        || evidence_pack
            .and_then(|pack| pack.odrl_enforcement.as_ref())
            .is_none()
    {
        tracing::error!(
            code = "runtime.binding.ecosystem_binding_invalid",
            binding_id = %binding.id,
            binding_version = %binding.version,
            binding_type = %binding.binding_type,
            "configured ecosystem binding must be a governed-evidence binding with evidence_pack policy_id, policy_hash, and odrl_enforcement"
        );
        return Err(RuntimeBindingError::EcosystemBindingInvalid);
    }
    Ok(())
}

/// BRegDCAT-AP catalog-level IRI fields must resolve via the configured
/// vocabulary registry. Without this check, a typo'd `publisher_iri`,
/// `authority_type`, or `default_spatial_coverage` would be silently dropped
/// at emit time.
fn validate_catalog_uris(config: &Config) -> Result<(), ConfigError> {
    let registry = &config.vocabularies;
    if let Some(uri) = config.catalog.publisher_iri.as_deref() {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                field = "catalog.publisher_iri",
                uri = %uri,
                "publisher_iri is neither absolute nor a registered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    if let Some(uri) = config.catalog.authority_type.as_deref() {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                field = "catalog.authority_type",
                uri = %uri,
                "authority_type IRI is neither absolute nor a registered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    if let Some(uri) = config.catalog.default_spatial_coverage.as_deref() {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                field = "catalog.default_spatial_coverage",
                uri = %uri,
                "default_spatial_coverage IRI is neither absolute nor a registered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
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
    config: &Config,
    spdci: &super::SpdciStandardsConfig,
) -> Result<(), ConfigError> {
    let _ = (config, spdci);
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
    if spdci.disability_registry.is_none() && spdci.registries.is_empty() {
        tracing::error!(
            code = "config.validation_error",
            "standards.spdci must declare at least one adapter"
        );
        return Err(ConfigError::ValidationError);
    };
    if let Some(disability) = &spdci.disability_registry {
        validate_spdci_disability_registry(config, disability)?;
    }
    for (name, registry) in &spdci.registries {
        validate_spdci_registry(config, name, registry)?;
    }
    Ok(())
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

    let (entity, fields) = spdci_entity_fields(
        config,
        disability.dataset.as_str(),
        &disability.entity,
        "standards.spdci.disability_registry",
    )?;
    if entity.access.evidence_verification_scope.trim().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %disability.dataset,
            entity = %disability.entity,
            "standards.spdci.disability_registry requires evidence_verification_scope"
        );
        return Err(ConfigError::ValidationError);
    }
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

#[cfg(feature = "spdci-api-standards")]
fn validate_spdci_registry(
    config: &Config,
    name: &str,
    registry: &super::SpdciRegistryConfig,
) -> Result<(), ConfigError> {
    if name.trim().is_empty()
        || registry.entity.trim().is_empty()
        || registry.registry_type.trim().is_empty()
        || registry.record_type.trim().is_empty()
        || registry.identifiers.is_empty()
        || registry.default_limit == 0
    {
        tracing::error!(
            code = "config.validation_error",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            "standards.spdci.registries entries must declare non-empty bindings"
        );
        return Err(ConfigError::ValidationError);
    }

    let (entity, fields) = spdci_entity_fields(
        config,
        registry.dataset.as_str(),
        &registry.entity,
        "standards.spdci.registries",
    )?;
    if entity.access.evidence_verification_scope.trim().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            "standards.spdci.registries entries require evidence_verification_scope"
        );
        return Err(ConfigError::ValidationError);
    }
    for (query_name, field) in registry
        .identifiers
        .iter()
        .chain(registry.expression_fields.iter())
    {
        if query_name.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                "standards.spdci.registries query mapping keys must not be empty"
            );
            return Err(ConfigError::ValidationError);
        }
        if field.trim().is_empty() || !fields.contains_key(field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                field = %field,
                "standards.spdci.registries references an unknown entity field"
            );
            return Err(ConfigError::ValidationError);
        }
        if !entity
            .api
            .allowed_filters
            .iter()
            .any(|filter| filter.field == *field)
        {
            tracing::error!(
                code = "config.validation_error",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                field = %field,
                "standards.spdci.registries search fields must be allowed entity filters"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    validate_spdci_response_fields(name, registry, &fields)?;
    validate_spdci_response_mapping(name, registry)?;
    validate_spdci_response_schema(name, registry)?;
    Ok(())
}

#[cfg(feature = "spdci-api-standards")]
fn validate_spdci_response_fields(
    name: &str,
    registry: &super::SpdciRegistryConfig,
    fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for (target_path, source_field) in &registry.response_fields {
        if !is_valid_spdci_response_path(target_path) {
            tracing::error!(
                code = "config.validation_error",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                target_path = %target_path,
                "standards.spdci.registries response_fields target paths must not be empty"
            );
            return Err(ConfigError::ValidationError);
        }
        if source_field.trim().is_empty() || !fields.contains_key(source_field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                field = %source_field,
                target_path = %target_path,
                "standards.spdci.registries response_fields references an unknown entity field"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

#[cfg(feature = "spdci-api-standards")]
fn is_valid_spdci_response_path(path: &str) -> bool {
    let trimmed = path.trim();
    !trimmed.is_empty()
        && trimmed == path
        && trimmed
            .split('.')
            .all(|segment| !segment.trim().is_empty() && segment.trim() == segment)
}

#[cfg(feature = "spdci-api-standards")]
fn validate_spdci_response_mapping(
    name: &str,
    registry: &super::SpdciRegistryConfig,
) -> Result<(), ConfigError> {
    let Some(path) = &registry.response_mapping_path else {
        return Ok(());
    };

    #[cfg(not(feature = "standards-cel-mapping"))]
    {
        tracing::error!(
            code = "spdci.config.mapping_feature_disabled",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            path = %path.display(),
            "standards.spdci.registries response_mapping_path requires the standards-cel-mapping feature"
        );
        Err(ConfigError::SpdciMappingFeatureDisabled)
    }

    #[cfg(feature = "standards-cel-mapping")]
    {
        if path.as_os_str().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                "standards.spdci.registries response_mapping_path must not be empty"
            );
            return Err(ConfigError::ValidationError);
        }

        let mapping_text = std::fs::read_to_string(path).map_err(|err| {
            tracing::error!(
                code = "spdci.config.mapping_read_failed",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                path = %path.display(),
                error = %err,
                "failed to read SP DCI response mapping",
            );
            ConfigError::ValidationError
        })?;

        let rt = crosswalk_core::MappingRuntime::new(crosswalk_core::RuntimeOptions::default());
        rt.compile_mapping(&mapping_text).map_err(|err| {
            tracing::error!(
                code = "spdci.config.mapping_compile_failed",
                registry = name,
                dataset_id = %registry.dataset,
                entity = %registry.entity,
                path = %path.display(),
                error = %err,
                "failed to compile SP DCI response mapping",
            );
            ConfigError::ValidationError
        })?;

        Ok(())
    }
}

#[cfg(feature = "spdci-api-standards")]
fn validate_spdci_response_schema(
    name: &str,
    registry: &super::SpdciRegistryConfig,
) -> Result<(), ConfigError> {
    let Some(path) = &registry.response_schema_path else {
        return Ok(());
    };
    if path.as_os_str().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            "standards.spdci.registries response_schema_path must not be empty"
        );
        return Err(ConfigError::ValidationError);
    }

    let raw_schema = std::fs::read_to_string(path).map_err(|err| {
        tracing::error!(
            code = "spdci.config.schema_read_failed",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            path = %path.display(),
            error = %err,
            "failed to read SP DCI response schema",
        );
        ConfigError::ValidationError
    })?;
    let schema_json: serde_json::Value = serde_json::from_str(&raw_schema).map_err(|err| {
        tracing::error!(
            code = "spdci.config.schema_parse_failed",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            path = %path.display(),
            error = %err,
            "failed to parse SP DCI response schema",
        );
        ConfigError::ValidationError
    })?;
    jsonschema::JSONSchema::compile(&schema_json).map_err(|err| {
        tracing::error!(
            code = "spdci.config.schema_compile_failed",
            registry = name,
            dataset_id = %registry.dataset,
            entity = %registry.entity,
            path = %path.display(),
            error = %err,
            "failed to compile SP DCI response schema",
        );
        ConfigError::ValidationError
    })?;

    Ok(())
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_entity_fields<'a>(
    config: &'a Config,
    dataset_id: &str,
    entity_name: &str,
    context: &str,
) -> Result<(&'a EntityConfig, BTreeMap<String, String>), ConfigError> {
    let dataset = config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_ref() == dataset_id)
        .ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id,
                "{context} references an unknown dataset"
            );
            ConfigError::ValidationError
        })?;
    let entity = dataset
        .entities
        .iter()
        .find(|entity| entity.name == entity_name)
        .ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id,
                entity = entity_name,
                "{context} references an unknown entity"
            );
            ConfigError::ValidationError
        })?;
    let table = dataset
        .table_configs()
        .find(|table| table.id == entity.table)
        .ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id,
                entity = entity_name,
                table_id = %entity.table,
                "{context} entity references an unknown table"
            );
            ConfigError::ValidationError
        })?;
    let fields = exposed_entity_fields(entity, table)?;
    Ok((entity, fields))
}

fn validate_ogc_feature_flags(_config: &Config) -> Result<(), ConfigError> {
    #[cfg(any(
        not(feature = "ogcapi-features"),
        not(feature = "ogcapi-edr"),
        not(feature = "ogcapi-records")
    ))]
    {
        let config = _config;
        for dataset in &config.datasets {
            #[cfg(not(feature = "ogcapi-records"))]
            for uri in &dataset.conforms_to {
                if is_ogc_records_conformance_uri(uri) {
                    tracing::error!(
                        code = "ogcapi.records.config.feature_disabled",
                        dataset_id = %dataset.id,
                        uri = %uri,
                        "dataset declares OGC API Records conformance but binary was built without the ogcapi-records feature",
                    );
                    return Err(ConfigError::OgcApiRecordsFeatureDisabled);
                }
            }

            #[cfg(not(feature = "ogcapi-edr"))]
            for aggregate in &dataset.aggregates {
                if aggregate.spatial.is_some() {
                    tracing::error!(
                        code = "ogcapi.edr.config.feature_disabled",
                        dataset_id = %dataset.id,
                        aggregate_id = %aggregate.id,
                        "aggregate declares OGC EDR spatial config but binary was built without the ogcapi-edr feature",
                    );
                    return Err(ConfigError::OgcApiEdrFeatureDisabled);
                }
            }

            #[cfg(not(feature = "ogcapi-features"))]
            for entity in &dataset.entities {
                if entity.spatial.is_some() {
                    tracing::error!(
                        code = "ogcapi.features.config.feature_disabled",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        "entity declares OGC API Features spatial config but binary was built without the ogcapi-features feature",
                    );
                    return Err(ConfigError::OgcApiFeaturesFeatureDisabled);
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "ogcapi-records"))]
fn is_ogc_records_conformance_uri(uri: &str) -> bool {
    uri.starts_with("http://www.opengis.net/spec/ogcapi-records-1/")
        || uri.starts_with("https://www.opengis.net/spec/ogcapi-records-1/")
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

/// Attribute-release profile ids additionally allow hyphens. They are URL path
/// segments and the eSignet contract uses ids like `esignet-civil-userinfo`, so
/// the charset is `[a-z][a-z0-9_-]*` (the `is_valid_id` set plus `-`).
fn is_valid_profile_id(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Release claim names map to OIDC/UserInfo claims, which include dotted names
/// such as `address.region`. Each dot-separated segment must match the
/// snake-case `is_valid_id` charset; a leading, trailing, or doubled dot (an
/// empty segment) is rejected.
fn is_valid_claim_name(s: &str) -> bool {
    s.split('.').all(is_valid_id)
}

/// Match the deployment finding id pattern
/// `^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_-]*)*$` without pulling in a regex crate.
///
/// The first dot-separated segment is `[a-z][a-z0-9]*` (no underscore or dash);
/// every following segment is `[a-z][a-z0-9_-]*`. This matches the ids the gate
/// catalog emits (for example `relay.config.unsigned`,
/// `relay.auth.api_key_no_rotation_evidence`, `deployment.profile_undeclared`).
/// A waiver naming a malformed id would otherwise pass non-empty validation and
/// only surface later as restricted-tier posture schema invalidity.
fn is_valid_finding_id(s: &str) -> bool {
    let mut segments = s.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if !is_valid_finding_segment(first, false) {
        return false;
    }
    segments.all(|segment| is_valid_finding_segment(segment, true))
}

/// One dot-separated finding id segment. The leading character must be
/// `[a-z]`; trailing characters are `[a-z0-9]`, plus `_` and `-` when
/// `allow_underscore_dash` is set (every segment after the first).
fn is_valid_finding_segment(segment: &str, allow_underscore_dash: bool) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || (allow_underscore_dash && (c == '_' || c == '-'))
    })
}

fn validate_server(config: &Config) -> Result<(), ConfigError> {
    if config.server.request_timeout.is_zero()
        || config.server.request_body_timeout.is_zero()
        || config.server.http1_header_read_timeout.is_zero()
        || config.server.max_connections == 0
    {
        tracing::error!(
            code = "config.validation_error",
            "server timeouts must be non-zero and max_connections must be greater than zero"
        );
        return Err(ConfigError::ValidationError);
    }
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
    if let Err(err) = platform_cors_policy(config).validate() {
        tracing::error!(
            code = "config.validation_error",
            error = %err,
            "server.cors failed shared platform validation"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn platform_cors_policy(config: &Config) -> CorsPolicy {
    CorsPolicy {
        allowed_origins: config.server.cors.allowed_origins.clone(),
        allowed_methods: Vec::new(),
        allowed_headers: Vec::new(),
        allow_credentials: false,
    }
}

#[cfg(test)]
fn is_valid_cors_origin(s: &str) -> bool {
    CorsPolicy {
        allowed_origins: vec![s.to_string()],
        allowed_methods: Vec::new(),
        allowed_headers: Vec::new(),
        allow_credentials: false,
    }
    .validate()
    .is_ok()
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
    let mut api_key_ids: HashSet<&str> = HashSet::new();
    for key in &config.auth.api_keys {
        if !api_key_ids.insert(key.id.as_str()) {
            tracing::error!(
                code = "config.duplicate_id",
                api_key_id = %key.id,
                "duplicate API key id"
            );
            return Err(ConfigError::DuplicateId);
        }
    }

    let mut dataset_ids: HashSet<&str> = HashSet::new();
    let mut datafusion_table_names: BTreeMap<String, (String, String)> = BTreeMap::new();
    // Attribute-release profiles are identified by a globally unique
    // `(id, version)` pair across every dataset/entity (see plan §3). Hoist the
    // accumulator above the dataset loop, mirroring `datafusion_table_names`.
    let mut release_profile_ids: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
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

        let mut aggregate_ids: HashSet<&str> = HashSet::new();
        let mut edr_collection_ids: HashSet<String> = HashSet::new();
        for aggregate in &dataset.aggregates {
            if !is_valid_id(aggregate.id.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    "aggregate id does not match ^[a-z][a-z0-9_]*$"
                );
                return Err(ConfigError::ValidationError);
            }
            if !aggregate_ids.insert(aggregate.id.as_str()) {
                tracing::error!(
                    code = "config.duplicate_id",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    "duplicate aggregate id within dataset"
                );
                return Err(ConfigError::DuplicateId);
            }
            if let Some(collection_id) = aggregate_edr_collection_id(dataset, aggregate) {
                if !is_valid_id(&collection_id) {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset.id,
                        aggregate_id = %aggregate.id,
                        collection_id,
                        "aggregate EDR collection_id is not a valid lower-snake id"
                    );
                    return Err(ConfigError::ValidationError);
                }
                if !edr_collection_ids.insert(collection_id.clone()) {
                    tracing::error!(
                        code = "config.duplicate_id",
                        dataset_id = %dataset.id,
                        aggregate_id = %aggregate.id,
                        collection_id,
                        "duplicate aggregate EDR collection_id"
                    );
                    return Err(ConfigError::DuplicateId);
                }
            }
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
            let datafusion_table_name = table_name(&dataset.id, &resource.id);
            if let Some((existing_dataset, existing_resource)) = datafusion_table_names.insert(
                datafusion_table_name.clone(),
                (dataset.id.to_string(), resource.id.to_string()),
            ) {
                tracing::error!(
                    code = "config.duplicate_id",
                    dataset_id = %dataset.id,
                    resource_id = %resource.id,
                    datafusion_table_name,
                    existing_dataset,
                    existing_resource,
                    "duplicate derived DataFusion table name"
                );
                return Err(ConfigError::DuplicateId);
            }

            let mut resource_aggregate_ids: HashSet<&str> = HashSet::new();
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
                if !resource_aggregate_ids.insert(aggregate.id.as_str()) {
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
            for profile in &entity.attribute_release_profiles {
                if let Some((existing_dataset, existing_entity)) = release_profile_ids.insert(
                    (profile.id.clone(), profile.version.clone()),
                    (dataset.id.to_string(), entity.name.clone()),
                ) {
                    tracing::error!(
                        code = "config.duplicate_id",
                        dataset_id = %dataset.id,
                        entity = %entity.name,
                        profile_id = %profile.id,
                        profile_version = %profile.version,
                        existing_dataset,
                        existing_entity,
                        "duplicate attribute_release_profiles (id, version) across configuration"
                    );
                    return Err(ConfigError::DuplicateId);
                }
            }
        }
    }
    Ok(())
}

fn aggregate_edr_collection_id(
    dataset: &DatasetConfig,
    aggregate: &AggregateConfig,
) -> Option<String> {
    match aggregate.spatial.as_ref()? {
        AggregateSpatialConfig::AdminArea { collection_id, .. } => collection_id
            .clone()
            .or_else(|| Some(format!("{}_{}", dataset.id, aggregate.id))),
    }
}

/// Enforce the mode invariant: exactly one of `api_keys` and `oidc` is
/// populated, matching the `mode` discriminator. Mixed-mode operation
/// is not supported.
fn validate_auth_mode(config: &Config) -> Result<(), ConfigError> {
    match config.auth.mode {
        AuthMode::ApiKey => {
            if config.auth.oidc.is_some() {
                tracing::error!(
                    code = "config.validation_error",
                    "auth.oidc must not be set when auth.mode = api_key"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        AuthMode::Oidc => {
            if !config.auth.api_keys.is_empty() {
                tracing::error!(
                    code = "config.validation_error",
                    "auth.api_keys must be empty when auth.mode = oidc"
                );
                return Err(ConfigError::ValidationError);
            }
            let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
                tracing::error!(
                    code = "config.validation_error",
                    "auth.oidc is required when auth.mode = oidc"
                );
                ConfigError::ValidationError
            })?;
            validate_oidc(oidc)?;
        }
    }
    Ok(())
}

/// Validate the local auth-failure throttle block. No constraints apply
/// when the throttle is disabled (the default), since an unused block's
/// field values cannot affect runtime behavior.
fn validate_auth_failure_throttle(config: &Config) -> Result<(), ConfigError> {
    let throttle = &config.auth.failure_throttle;
    if !throttle.enabled {
        return Ok(());
    }
    if throttle.max_failures == 0 {
        tracing::error!(
            code = "config.validation_error",
            "auth.failure_throttle.max_failures must be greater than zero"
        );
        return Err(ConfigError::ValidationError);
    }
    if throttle.window_seconds == 0 {
        tracing::error!(
            code = "config.validation_error",
            "auth.failure_throttle.window_seconds must be greater than zero"
        );
        return Err(ConfigError::ValidationError);
    }
    let trust_proxy = &config.server.trust_proxy;
    // The throttle keys on the address resolved by `crate::net`, which only
    // honors `X-Forwarded-For` when trust_proxy is enabled AND at least one
    // trusted proxy is configured: an empty `trusted_proxies` list matches no
    // peer, so every forwarded request still collapses onto the proxy's own
    // socket address, the same shared-bucket self-DoS as trust_proxy disabled.
    if !trust_proxy.enabled || trust_proxy.trusted_proxies.is_empty() {
        let reason = if !trust_proxy.enabled {
            "server.trust_proxy is disabled"
        } else {
            "server.trust_proxy is enabled but server.trust_proxy.trusted_proxies is empty, so no \
             peer is trusted and X-Forwarded-For is ignored"
        };
        tracing::warn!(
            code = "config.validation_warning",
            "auth.failure_throttle is enabled but {reason}: the client address then resolves to the \
             socket peer, so all requests arriving via a proxy or load balancer share one throttle \
             bucket keyed by the proxy address, and the throttle can 429 every client after \
             max_failures combined failures; enable server.trust_proxy and populate \
             server.trust_proxy.trusted_proxies when the relay sits behind a proxy"
        );
    }
    Ok(())
}

/// Bounds for the OIDC JWKS cache TTL. The lower bound prevents tight
/// re-fetch loops; the upper bound keeps rotation pickup latency
/// sensible without exposing operators to the runtime cost of a
/// freshness deadline that they thought was disabling the cache.
const OIDC_MIN_JWKS_CACHE_TTL: Duration = Duration::from_secs(30);
const OIDC_MAX_JWKS_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const OIDC_MAX_LEEWAY: Duration = Duration::from_secs(5 * 60);
const ZITADEL_PROJECT_ROLES_CLAIM: &str = "urn:zitadel:iam:org:project:roles";

fn validate_oidc(oidc: &OidcConfig) -> Result<(), ConfigError> {
    if !is_allowed_oidc_url(&oidc.issuer, oidc.allow_dev_insecure_fetch_urls) {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.issuer",
            "issuer must be an absolute https:// URL unless allow_dev_insecure_fetch_urls is true for loopback dev"
        );
        return Err(ConfigError::ValidationError);
    }

    if oidc.audiences.is_empty() || oidc.audiences.iter().any(|aud| aud.trim().is_empty()) {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.audiences",
            "audience must list one or more non-empty values"
        );
        return Err(ConfigError::ValidationError);
    }

    match (oidc.jwks_url.as_deref(), oidc.discovery_url.as_deref()) {
        (Some(_), Some(_)) => {
            tracing::error!(
                code = "config.validation_error",
                "auth.oidc.jwks_url and auth.oidc.discovery_url are mutually exclusive"
            );
            return Err(ConfigError::ValidationError);
        }
        (None, None) => {
            tracing::error!(
                code = "config.validation_error",
                "auth.oidc requires exactly one of jwks_url or discovery_url"
            );
            return Err(ConfigError::ValidationError);
        }
        (Some(url), None) | (None, Some(url)) => {
            if !is_allowed_oidc_url(url, oidc.allow_dev_insecure_fetch_urls) {
                tracing::error!(
                    code = "config.validation_error",
                    field = "auth.oidc.jwks_url|discovery_url",
                    "JWKS or discovery URL must be https:// unless allow_dev_insecure_fetch_urls is true for loopback dev"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }

    if oidc.allowed_algorithms.is_empty() {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.allowed_algorithms",
            "algorithms must list at least one entry"
        );
        return Err(ConfigError::ValidationError);
    }

    if oidc.jwks_cache_ttl < OIDC_MIN_JWKS_CACHE_TTL
        || oidc.jwks_cache_ttl > OIDC_MAX_JWKS_CACHE_TTL
    {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.jwks_cache_ttl",
            min_secs = OIDC_MIN_JWKS_CACHE_TTL.as_secs(),
            max_secs = OIDC_MAX_JWKS_CACHE_TTL.as_secs(),
            "jwks_cache_ttl out of range"
        );
        return Err(ConfigError::ValidationError);
    }

    if oidc.leeway > OIDC_MAX_LEEWAY {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.leeway",
            max_secs = OIDC_MAX_LEEWAY.as_secs(),
            "leeway must not exceed 5 minutes"
        );
        return Err(ConfigError::ValidationError);
    }

    if oidc.scope_claim.trim().is_empty() || oidc.scope_claim.chars().any(char::is_whitespace) {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.scope_claim",
            "scope_claim must be a non-empty JSON key with no whitespace"
        );
        return Err(ConfigError::ValidationError);
    }
    if oidc.scope_claim == "aud" {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.scope_claim",
            "audience is an OIDC routing claim and must not be used as a Relay scope source"
        );
        return Err(ConfigError::ValidationError);
    }

    for (from, to) in &oidc.scope_map {
        if from.trim().is_empty() || to.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                field = "auth.oidc.scope_map",
                "scope_map keys and values must be non-empty"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    if oidc
        .scope_object_required_keys
        .iter()
        .any(|key| key.trim().is_empty())
    {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.scope_object_required_keys",
            "scope_object_required_keys entries must be non-empty"
        );
        return Err(ConfigError::ValidationError);
    }
    if oidc.scope_claim == ZITADEL_PROJECT_ROLES_CLAIM && oidc.scope_object_required_keys.is_empty()
    {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.scope_object_required_keys",
            "Zitadel project role object claims must declare required object keys"
        );
        return Err(ConfigError::ValidationError);
    }

    if oidc
        .allowed_clients
        .iter()
        .any(|client| client.trim().is_empty())
    {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.allowed_clients",
            "allowed_clients entries must be non-empty"
        );
        return Err(ConfigError::ValidationError);
    }

    if oidc.allowed_token_types.is_empty()
        || oidc.allowed_token_types.iter().any(|t| t.trim().is_empty())
    {
        tracing::error!(
            code = "config.validation_error",
            field = "auth.oidc.allowed_token_types",
            "token_types must list one or more non-empty JOSE `typ` values"
        );
        return Err(ConfigError::ValidationError);
    }

    Ok(())
}

fn is_allowed_oidc_url(url: &str, allow_dev_insecure_fetch_urls: bool) -> bool {
    is_https_or_dev_loopback_url(url, allow_dev_insecure_fetch_urls)
}

fn is_https_or_dev_loopback_url(url: &str, allow_dev_insecure_fetch_urls: bool) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.host_str().is_none() {
        return false;
    }
    match parsed.scheme() {
        "https" => true,
        "http" if allow_dev_insecure_fetch_urls => parsed
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("localhost") || is_loopback_ip(host)),
        _ => false,
    }
}

fn is_loopback_ip(host: &str) -> bool {
    host.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
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
    for dataset in &config.datasets {
        let dataset_id = dataset.id.as_str();
        for entity in &dataset.entities {
            validate_entity_scope(
                &entity.access.metadata_scope,
                dataset_id,
                &entity.name,
                "metadata_scope",
                true,
            )?;
            validate_entity_scope(
                &entity.access.aggregate_scope,
                dataset_id,
                &entity.name,
                "aggregate_scope",
                true,
            )?;
            validate_entity_scope(
                &entity.access.read_scope,
                dataset_id,
                &entity.name,
                "read_scope",
                true,
            )?;
            validate_entity_scope(
                &entity.access.evidence_verification_scope,
                dataset_id,
                &entity.name,
                "evidence_verification_scope",
                false,
            )?;
            for profile in &entity.attribute_release_profiles {
                validate_entity_scope(
                    &profile.release_scope,
                    dataset_id,
                    &entity.name,
                    "attribute_release_profiles.release_scope",
                    true,
                )?;
                if profile.release_scope == entity.access.read_scope {
                    tracing::error!(
                        code = "config.validation_error",
                        dataset_id = %dataset_id,
                        entity = %entity.name,
                        profile_id = %profile.id,
                        "attribute_release_profiles release_scope must differ from the entity read_scope"
                    );
                    return Err(ConfigError::ValidationError);
                }
            }
        }
        for aggregate in &dataset.aggregates {
            if let Some(access) = &aggregate.access {
                if let Some(scope) = &access.metadata_scope {
                    validate_entity_scope(
                        scope,
                        dataset_id,
                        aggregate.id.as_str(),
                        "aggregate.access.metadata_scope",
                        true,
                    )?;
                }
                if let Some(scope) = &access.aggregate_scope {
                    validate_entity_scope(
                        scope,
                        dataset_id,
                        aggregate.id.as_str(),
                        "aggregate.access.aggregate_scope",
                        true,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_entity_scope(
    scope: &str,
    dataset_id: &str,
    entity_name: &str,
    field: &str,
    required: bool,
) -> Result<(), ConfigError> {
    if scope.trim().is_empty() {
        if required {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset_id,
                entity = %entity_name,
                field = %field,
                "entity access scope must not be empty"
            );
            return Err(ConfigError::ValidationError);
        }
        return Ok(());
    }

    let (scope_dataset, suffix) = scope.split_once(':').ok_or_else(|| {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset_id,
            entity = %entity_name,
            field = %field,
            scope = %scope,
            "entity access scope must be '<dataset_id>:<scope-suffix>'"
        );
        ConfigError::ValidationError
    })?;
    if scope_dataset != dataset_id || suffix.trim().is_empty() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset_id,
            entity = %entity_name,
            field = %field,
            scope = %scope,
            "entity access scope must be bound to its enclosing dataset id"
        );
        return Err(ConfigError::ValidationError);
    }
    if RESERVED_SCOPE_DATASET_IDS.contains(&scope_dataset) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset_id,
            entity = %entity_name,
            field = %field,
            scope = %scope,
            "entity access scope must not use a reserved operations scope namespace"
        );
        return Err(ConfigError::ValidationError);
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
    if scope == OPS_READ_SCOPE {
        return Ok(());
    }
    if scope == METRICS_SCOPE {
        return Ok(());
    }
    let (dataset, level) = scope.split_once(':').ok_or_else(|| {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %api_key_id,
            scope = %scope,
            "scope must be 'registry_relay:admin', 'registry_relay:ops_read', 'registry_relay:metrics_read', or '<dataset_id>:<metadata|aggregate|rows|verify|evidence_verification|identity_release>'"
        );
        ConfigError::ValidationError
    })?;

    if !is_valid_scope_level(level) {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %api_key_id,
            scope = %scope,
            "unknown scope level (allowed: metadata, aggregate, rows, verify, evidence_verification, identity_release)"
        );
        return Err(ConfigError::ValidationError);
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

fn is_valid_scope_level(level: &str) -> bool {
    matches!(
        level,
        "metadata" | "aggregate" | "rows" | "verify" | "evidence_verification" | "identity_release"
    ) || level
        .strip_prefix("evidence_verification:")
        .is_some_and(|suffix| !suffix.trim().is_empty())
}

fn validate_env_vars_and_hashes(config: &Config) -> Result<(), ConfigError> {
    if config.auth.mode != AuthMode::ApiKey {
        return Ok(());
    }
    let mut fingerprints = HashSet::with_capacity(config.auth.api_keys.len());
    for key in &config.auth.api_keys {
        match key.fingerprint.resolve() {
            Ok(fingerprint) => {
                if !fingerprints.insert(fingerprint) {
                    tracing::error!(
                        code = "config.validation_error",
                        api_key_id = %key.id,
                        "duplicate API key fingerprint resolved from configured credential references"
                    );
                    return Err(ConfigError::ValidationError);
                }
            }
            Err(error) => {
                match error {
                    CredentialFingerprintRefError::MissingSecret => {
                        tracing::error!(
                            code = "config.missing_secret",
                            api_key_id = %key.id,
                            "configured API key fingerprint secret is not set"
                        );
                        return Err(ConfigError::MissingSecret);
                    }
                    other => {
                        tracing::error!(
                            code = "config.validation_error",
                            api_key_id = %key.id,
                            reason = ?other,
                            "configured API key fingerprint reference is invalid"
                        );
                    }
                }
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
}

/// Validate a high-entropy API key fingerprint. Raw API keys are generated
/// as at least 32 bytes of random material; configs store only
/// `sha256:<64 lowercase hex chars>` so request authentication is a
/// digest plus a map lookup.
#[cfg(test)]
fn validate_api_key_fingerprint(value: &str) -> Result<(), &'static str> {
    registry_platform_authcommon::parse_fingerprint(value)
        .map(|_| ())
        .map_err(|error| match error {
            registry_platform_authcommon::FingerprintFormatError::MissingPrefix => {
                "API key fingerprint must start with sha256:"
            }
            registry_platform_authcommon::FingerprintFormatError::InvalidLength => {
                "API key fingerprint must contain 64 lowercase hex characters"
            }
            registry_platform_authcommon::FingerprintFormatError::InvalidHex => {
                "API key fingerprint must contain lowercase hex only"
            }
            _ => "API key fingerprint is invalid",
        })
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
        validate_dataset_aggregates(dataset)?;
    }
    Ok(())
}

fn validate_format_overrides(dataset: &DatasetConfig) -> Result<(), ConfigError> {
    for resource in dataset.table_configs() {
        if let SourceConfig::File {
            format: Some(format),
            ..
        } = &resource.source
        {
            validate_format_config(dataset, resource, format, "resource.source.format")?;
        }
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
    for resource in dataset.table_configs() {
        let refresh = resource.effective_refresh(dataset).ok_or_else(|| {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "table refresh is required when no dataset refresh/default is configured"
            );
            ConfigError::ValidationError
        })?;
        validate_source_config(dataset, Some(resource), &resource.source)?;
        validate_materialization_refresh(dataset, resource, &resource.source, refresh)?;
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
    for uri in &dataset.applicable_legislation {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                uri = %uri,
                "applicable_legislation URI uses an unregistered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    if let Some(uri) = dataset.spatial_coverage.as_deref() {
        if super::vocabularies::expand(uri, registry).is_none() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                field = "spatial_coverage",
                uri = %uri,
                "spatial_coverage IRI is neither absolute nor a registered vocabulary prefix"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    for service in &dataset.public_services {
        if service.title.trim().is_empty() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                "public service title must not be empty"
            );
            return Err(ConfigError::ValidationError);
        }
        if service.id.as_deref().is_some_and(str::is_empty) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                "public service id must not be empty"
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
            live_max_rows,
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

            if connect_timeout.is_zero()
                || query_timeout.is_zero()
                || *live_max_connections == 0
                || *live_max_rows == 0
            {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
                    connection_env = %connection_env,
                    "postgres timeouts must be non-zero and live limits must be greater than zero"
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

    if postgres_configured_sql_has_disallowed_token(trimmed) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            resource_id = resource.map(|r| r.id.as_str()).unwrap_or("<dataset>"),
            connection_env = %connection_env,
            "postgres configured SQL must be read-only and must not change session state"
        );
        return Err(ConfigError::ValidationError);
    }

    Ok(())
}

fn postgres_configured_sql_has_disallowed_token(sql: &str) -> bool {
    const DISALLOWED: &[&str] = &[
        "alter",
        "analyze",
        "begin",
        "call",
        "cluster",
        "commit",
        "copy",
        "create",
        "delete",
        "drop",
        "execute",
        "grant",
        "insert",
        "listen",
        "load",
        "lock",
        "merge",
        "nextval",
        "notify",
        "perform",
        "pg_advisory_lock",
        "pg_read_binary_file",
        "pg_read_file",
        "pg_sleep",
        "refresh",
        "reindex",
        "reset",
        "revoke",
        "rollback",
        "set",
        "set_config",
        "truncate",
        "update",
        "vacuum",
    ];
    postgres_sql_tokens(sql)
        .iter()
        .any(|token| DISALLOWED.contains(&token.as_str()))
}

fn postgres_sql_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_single_quote = false;
    let mut is_escape_quote = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if in_single_quote {
            if is_escape_quote && ch == '\\' {
                chars.next();
            } else if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                } else {
                    in_single_quote = false;
                    is_escape_quote = false;
                }
            }
            continue;
        }
        match ch {
            '-' if chars.peek() == Some(&'-') => {
                chars.next();
                push_postgres_sql_token(&mut tokens, &mut current);
                in_line_comment = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                push_postgres_sql_token(&mut tokens, &mut current);
                in_block_comment = true;
            }
            '\'' => {
                is_escape_quote = current.eq_ignore_ascii_case("e");
                push_postgres_sql_token(&mut tokens, &mut current);
                in_single_quote = true;
            }
            '"' => {
                push_postgres_sql_token(&mut tokens, &mut current);
                let token = read_postgres_quoted_identifier(&mut chars);
                if !token.is_empty() {
                    tokens.push(token.to_ascii_lowercase());
                }
            }
            ch if ch.is_ascii_alphanumeric() || ch == '_' => {
                current.push(ch.to_ascii_lowercase());
            }
            _ => push_postgres_sql_token(&mut tokens, &mut current),
        }
    }
    push_postgres_sql_token(&mut tokens, &mut current);
    tokens
}

fn read_postgres_quoted_identifier<I>(chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = char>,
{
    let mut identifier = String::new();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if chars.peek() == Some(&'"') {
                chars.next();
                identifier.push('"');
            } else {
                break;
            }
        } else {
            identifier.push(ch);
        }
    }
    identifier
}

fn push_postgres_sql_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

fn validate_materialization_refresh(
    dataset: &DatasetConfig,
    resource: &ResourceConfig,
    source: &SourceConfig,
    refresh: &RefreshConfig,
) -> Result<(), ConfigError> {
    let materialization = resource.effective_materialization(dataset);
    let capabilities = source_capabilities(source, materialization);

    if !capabilities.materialization_supported {
        match source {
            SourceConfig::File { .. } => tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "file sources support only snapshot materialization"
            ),
            SourceConfig::Postgres { query: Some(_), .. } => tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "postgres live materialization supports table sources only"
            ),
            SourceConfig::Postgres { .. } => tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                resource_id = %resource.id,
                "source does not support live materialization"
            ),
        }
        return Err(ConfigError::ValidationError);
    }

    if matches!(refresh, RefreshConfig::Mtime { .. }) && !capabilities.mtime_refresh {
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

    if aggregate.disclosure_control.effective_min_cell_size() < 1 {
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
    let mut collection_ids = HashSet::new();

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
        validate_entity_spatial(dataset, entity, table, &exposed_fields, &mut collection_ids)?;
        validate_entity_relationships(dataset, entity, table, &tables, &entities)?;
        validate_entity_release_profiles(dataset, entity, &exposed_fields)?;
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

fn validate_dataset_aggregates(dataset: &DatasetConfig) -> Result<(), ConfigError> {
    let tables: BTreeMap<&str, &ResourceConfig> = dataset
        .table_configs()
        .map(|table| (table.id.as_str(), table))
        .collect();
    let entities: BTreeMap<&str, &EntityConfig> = dataset
        .entities
        .iter()
        .map(|entity| (entity.name.as_str(), entity))
        .collect();
    let exposed_by_entity = dataset
        .entities
        .iter()
        .map(|entity| {
            let table = tables
                .get(entity.table.as_str())
                .ok_or(ConfigError::ValidationError)?;
            exposed_entity_fields(entity, table).map(|fields| (entity.name.as_str(), fields))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    for aggregate in &dataset.aggregates {
        if aggregate.disclosure_control.effective_min_cell_size() < 1 {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                "aggregate disclosure_control.min_cell_size must be >= 1"
            );
            return Err(ConfigError::ValidationError);
        }
        let Some(source_entity_name) = aggregate.source_entity.as_deref() else {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                "dataset aggregate source_entity is required"
            );
            return Err(ConfigError::ValidationError);
        };
        let Some(source_entity) = entities.get(source_entity_name) else {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                source_entity = %source_entity_name,
                "dataset aggregate references an unknown source_entity"
            );
            return Err(ConfigError::ValidationError);
        };
        let Some(source_fields) = exposed_by_entity.get(source_entity_name) else {
            return Err(ConfigError::ValidationError);
        };
        if aggregate
            .access
            .as_ref()
            .is_some_and(|access| access.aggregate_only_execution)
            && matches!(
                dataset.sensitivity,
                Sensitivity::Personal | Sensitivity::Confidential | Sensitivity::Secret
            )
            && aggregate.disclosure_control.effective_min_cell_size() < 2
        {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                "aggregate_only_execution on personal, confidential, or secret datasets requires disclosure_control.min_cell_size >= 2"
            );
            return Err(ConfigError::ValidationError);
        }
        validate_reserved_ids(dataset, aggregate)?;
        let dimension_ids = aggregate
            .dimensions
            .iter()
            .map(|dimension| dimension.id.as_str())
            .collect::<HashSet<_>>();
        let indicator_ids = aggregate
            .indicators
            .iter()
            .map(|indicator| indicator.id.as_str())
            .collect::<HashSet<_>>();
        if dimension_ids.len() != aggregate.dimensions.len()
            || indicator_ids.len() != aggregate.indicators.len()
        {
            tracing::error!(
                code = "config.duplicate_id",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                "duplicate aggregate dimension or indicator id"
            );
            return Err(ConfigError::DuplicateId);
        }
        for dimension in &aggregate.dimensions {
            validate_aggregate_field_ref(
                dataset,
                aggregate,
                source_entity,
                &entities,
                &exposed_by_entity,
                &dimension.field,
                "dimension",
            )?;
        }
        for group in &aggregate.default_group_by {
            if !dimension_ids.contains(group.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    group_by = %group,
                    "aggregate default_group_by references an unknown dimension"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        for indicator in &aggregate.indicators {
            if !source_fields.contains_key(&indicator.column) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    indicator = %indicator.id,
                    column = %indicator.column,
                    "aggregate indicator column references a non-exposed source field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        if let Some(temporal_field) = aggregate.temporal_field.as_deref() {
            if !source_fields.contains_key(temporal_field) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = temporal_field,
                    "aggregate temporal_field references a non-exposed source field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        let filter_fields = aggregate
            .allowed_filters
            .iter()
            .map(|filter| filter.field.as_str())
            .collect::<HashSet<_>>();
        if let Some(temporal_field) = aggregate.temporal_field.as_deref() {
            if !filter_fields.contains(temporal_field) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = temporal_field,
                    "aggregate temporal_field must also be declared in allowed_filters"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        for filter in &aggregate.allowed_filters {
            if filter.ops.is_empty() {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %filter.field,
                    "aggregate allowed_filters entry must declare at least one op"
                );
                return Err(ConfigError::ValidationError);
            }
            if !source_fields.contains_key(&filter.field)
                && !dimension_ids.contains(filter.field.as_str())
            {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %filter.field,
                    "aggregate allowed_filters references neither a source field nor dimension id"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        let mut required_filter_fields = HashSet::new();
        for required in &aggregate.required_filters {
            if !filter_fields.contains(required.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %required,
                    "aggregate required_filters must reference allowed_filters"
                );
                return Err(ConfigError::ValidationError);
            }
            if !required_filter_fields.insert(required.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %required,
                    "aggregate required_filters contains a duplicate field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        let mut binding_fields = HashSet::new();
        for binding in &aggregate.required_filter_bindings {
            if !filter_fields.contains(binding.field.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %binding.field,
                    "aggregate required_filter_bindings references neither a source field nor dimension id"
                );
                return Err(ConfigError::ValidationError);
            }
            if !required_filter_fields.contains(binding.field.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %binding.field,
                    "aggregate required_filter_bindings entry is not present in required_filters"
                );
                return Err(ConfigError::ValidationError);
            }
            if !binding_fields.insert(binding.field.as_str()) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    field = %binding.field,
                    "aggregate required_filter_bindings contains a duplicate field"
                );
                return Err(ConfigError::ValidationError);
            }
        }
        if !aggregate.required_filters.is_empty() && binding_fields.is_empty() {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                "aggregate required_filters must declare at least one required_filter_bindings principal binding"
            );
            return Err(ConfigError::ValidationError);
        }
        validate_aggregate_spatial(dataset, aggregate, &entities, &exposed_by_entity)?;
    }
    Ok(())
}

fn validate_reserved_ids(
    dataset: &DatasetConfig,
    aggregate: &AggregateConfig,
) -> Result<(), ConfigError> {
    for id in aggregate
        .dimensions
        .iter()
        .map(|dimension| dimension.id.as_str())
        .chain(
            aggregate
                .indicators
                .iter()
                .map(|indicator| indicator.id.as_str()),
        )
    {
        if !is_valid_id(id) || id.ends_with("$status") || id.ends_with("$conf") {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                id,
                "aggregate dimension or indicator id is invalid or reserved"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_aggregate_field_ref(
    dataset: &DatasetConfig,
    aggregate: &AggregateConfig,
    source_entity: &EntityConfig,
    entities: &BTreeMap<&str, &EntityConfig>,
    exposed_by_entity: &BTreeMap<&str, BTreeMap<String, String>>,
    field: &str,
    kind: &'static str,
) -> Result<(), ConfigError> {
    if let Some((relationship_name, related_field)) = field.split_once('.') {
        let Some(relationship) = source_entity
            .relationships
            .iter()
            .find(|relationship| relationship.name == relationship_name)
        else {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                field,
                "aggregate {kind} references an unknown relationship"
            );
            return Err(ConfigError::ValidationError);
        };
        if relationship.kind != RelationshipKind::BelongsTo {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                field,
                "aggregate {kind} relationship dimensions must be belongs_to"
            );
            return Err(ConfigError::ValidationError);
        }
        let Some(target) = entities.get(relationship.target.as_str()) else {
            return Err(ConfigError::ValidationError);
        };
        let Some(target_fields) = exposed_by_entity.get(target.name.as_str()) else {
            return Err(ConfigError::ValidationError);
        };
        if !target_fields.contains_key(related_field) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                aggregate_id = %aggregate.id,
                field,
                "aggregate {kind} references a non-exposed related field"
            );
            return Err(ConfigError::ValidationError);
        }
        return Ok(());
    }
    let Some(source_fields) = exposed_by_entity.get(source_entity.name.as_str()) else {
        return Err(ConfigError::ValidationError);
    };
    if source_fields.contains_key(field) {
        Ok(())
    } else {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            aggregate_id = %aggregate.id,
            field,
            "aggregate {kind} references a non-exposed source field"
        );
        Err(ConfigError::ValidationError)
    }
}

fn validate_aggregate_spatial(
    dataset: &DatasetConfig,
    aggregate: &AggregateConfig,
    entities: &BTreeMap<&str, &EntityConfig>,
    exposed_by_entity: &BTreeMap<&str, BTreeMap<String, String>>,
) -> Result<(), ConfigError> {
    let Some(spatial) = &aggregate.spatial else {
        return Ok(());
    };
    match spatial {
        AggregateSpatialConfig::AdminArea {
            dimension,
            geometry_entity,
            geometry_id_field,
            geometry_field,
            max_geometry_vertices,
            ..
        } => {
            if *max_geometry_vertices == 0 {
                return Err(ConfigError::ValidationError);
            }
            if !aggregate
                .dimensions
                .iter()
                .any(|candidate| candidate.id == *dimension)
            {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    dimension,
                    "aggregate spatial.dimension references an unknown dimension"
                );
                return Err(ConfigError::ValidationError);
            }
            let spatial_filter_supported = aggregate
                .allowed_filters
                .iter()
                .any(|filter| filter.field == *dimension && filter.ops.contains(&FilterOp::In));
            if !spatial_filter_supported {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    dimension,
                    "aggregate spatial.dimension must be allowed as an in filter"
                );
                return Err(ConfigError::ValidationError);
            }
            let Some(entity) = entities.get(geometry_entity.as_str()) else {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    geometry_entity,
                    "aggregate spatial.geometry_entity is unknown"
                );
                return Err(ConfigError::ValidationError);
            };
            let Some(fields) = exposed_by_entity.get(entity.name.as_str()) else {
                return Err(ConfigError::ValidationError);
            };
            if !fields.contains_key(geometry_id_field) || !fields.contains_key(geometry_field) {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    aggregate_id = %aggregate.id,
                    geometry_entity,
                    "aggregate spatial geometry id/geometry fields must be exposed"
                );
                return Err(ConfigError::ValidationError);
            }
        }
    }
    Ok(())
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

    let mut required_filter_fields = HashSet::new();
    for field in &entity.api.required_filters {
        if !exposed_fields.contains_key(field) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %field,
                "entity required_filters references a non-exposed field"
            );
            return Err(ConfigError::ValidationError);
        }
        if !required_filter_fields.insert(field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %field,
                "entity required_filters contains a duplicate field"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    let mut binding_fields = HashSet::new();
    for binding in &entity.api.required_filter_bindings {
        if !exposed_fields.contains_key(&binding.field) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %binding.field,
                "entity required_filter_bindings references a non-exposed field"
            );
            return Err(ConfigError::ValidationError);
        }
        if !required_filter_fields.contains(binding.field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %binding.field,
                "entity required_filter_bindings entry is not present in required_filters"
            );
            return Err(ConfigError::ValidationError);
        }
        if !binding_fields.insert(binding.field.as_str()) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %binding.field,
                "entity required_filter_bindings contains a duplicate field"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    if !entity.api.required_filters.is_empty() && binding_fields.is_empty() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            "entity required_filters must declare at least one required_filter_bindings principal binding"
        );
        return Err(ConfigError::ValidationError);
    }
    if let Some(policy) = entity.api.governed_policy.as_ref() {
        validate_entity_governed_policy(dataset, entity, policy)?;
    }

    Ok(())
}

fn validate_entity_governed_policy(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    policy: &GovernedPolicyConfig,
) -> Result<(), ConfigError> {
    if !governed_policy_has_enforced_gate(policy) {
        return entity_governed_policy_error(
            dataset,
            entity,
            "governed_policy must declare at least one enforced gate",
        );
    }
    for purpose in &policy.permitted_purposes {
        if purpose.trim().is_empty() {
            return entity_governed_policy_error(dataset, entity, "empty permitted_purposes entry");
        }
    }
    for jurisdiction in &policy.permitted_jurisdictions {
        if jurisdiction.trim().is_empty() {
            return entity_governed_policy_error(
                dataset,
                entity,
                "empty permitted_jurisdictions entry",
            );
        }
    }
    for assurance in &policy.allowed_assurance {
        if assurance.trim().is_empty() {
            return entity_governed_policy_error(dataset, entity, "empty allowed_assurance entry");
        }
    }
    if policy
        .minimum_assurance
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return entity_governed_policy_error(dataset, entity, "empty minimum_assurance");
    }
    if policy.max_source_age_seconds == Some(0) {
        return entity_governed_policy_error(
            dataset,
            entity,
            "max_source_age_seconds must be greater than zero",
        );
    }
    for field in &policy.redaction_fields {
        if field.trim().is_empty() {
            return entity_governed_policy_error(dataset, entity, "empty redaction_fields entry");
        }
        if !is_top_level_redaction_field(field) {
            return entity_governed_policy_error(
                dataset,
                entity,
                "redaction_fields entries must be top-level exposed entity fields",
            );
        }
        if !redaction_field_exists_on_entity_or_aggregate_output(dataset, entity, field) {
            return entity_governed_policy_error(
                dataset,
                entity,
                "redaction_fields entries must exist as entity fields or aggregate output fields",
            );
        }
    }
    let trusted = &policy.trusted_context;
    if trusted
        .jurisdiction
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return entity_governed_policy_error(dataset, entity, "empty trusted_context.jurisdiction");
    }
    if trusted
        .asserted_assurance
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return entity_governed_policy_error(
            dataset,
            entity,
            "empty trusted_context.asserted_assurance",
        );
    }
    if trusted
        .legal_basis_ref
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return entity_governed_policy_error(
            dataset,
            entity,
            "empty trusted_context.legal_basis_ref",
        );
    }
    if trusted
        .consent_ref
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return entity_governed_policy_error(dataset, entity, "empty trusted_context.consent_ref");
    }
    if trusted.jurisdiction.is_some()
        || trusted.asserted_assurance.is_some()
        || trusted.legal_basis_ref.is_some()
        || trusted.consent_ref.is_some()
        || trusted.source_observed_age_seconds.is_some()
    {
        return entity_governed_policy_error(
            dataset,
            entity,
            "trusted_context values must be supplied by per-request trust headers",
        );
    }
    Ok(())
}

/// A release claim must declare exactly one of `source_field` or
/// `expression.cel`: a claim is either a direct source-field projection or a
/// CEL-computed value, never both and never neither.
fn release_claim_has_exactly_one_source(claim: &ReleaseClaimConfig) -> bool {
    claim.source_field.is_some() ^ claim.expression.is_some()
}

/// Validate the attribute-release profiles attached to an entity (plan §5.1).
///
/// `exposed_fields` is the entity's resolved projection (claim/subject
/// `source_field`s must be members). Subject/claim membership reuses the
/// `validate_entity_filters` membership discipline. CEL expressions are
/// compile-checked through the Relay-owned adapter when the
/// `attribute-release` feature is enabled. When the feature is disabled, any
/// configured profile is rejected at load so the default 1.0 build does not
/// silently accept a beta config surface whose routes are not mounted.
fn validate_entity_release_profiles(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    exposed_fields: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    #[cfg(not(feature = "attribute-release"))]
    if let Some(profile) = entity.attribute_release_profiles.first() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            profile_id = %profile.id,
            "attribute_release_profiles require the attribute-release feature"
        );
        return Err(ConfigError::ValidationError);
    }

    for profile in &entity.attribute_release_profiles {
        validate_entity_release_profile(dataset, entity, exposed_fields, profile)?;
    }
    Ok(())
}

fn validate_entity_release_profile(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    exposed_fields: &BTreeMap<String, String>,
    profile: &AttributeReleaseProfile,
) -> Result<(), ConfigError> {
    let release_error = |message: &str| -> Result<(), ConfigError> {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            profile_id = %profile.id,
            "{message}"
        );
        Err(ConfigError::ValidationError)
    };

    if profile.id.trim().is_empty() {
        return release_error("attribute_release_profiles id must not be empty");
    }
    if !is_valid_profile_id(&profile.id) {
        return release_error("attribute_release_profiles id does not match ^[a-z][a-z0-9_-]*$");
    }
    if profile.version.trim().is_empty() {
        return release_error("attribute_release_profiles version must not be empty");
    }

    // Subject source field must be exposed by the entity projection.
    if !exposed_fields.contains_key(&profile.subject.source_field) {
        return release_error(
            "attribute_release_profiles subject.source_field references a non-exposed field",
        );
    }
    if profile.subject.input.trim().is_empty() {
        return release_error("attribute_release_profiles subject.input must not be empty");
    }

    // Claims: non-empty, ≥1 required, unique names, each a valid id, and each
    // declaring exactly one of source_field / expression.cel.
    if profile.claims.is_empty() {
        return release_error("attribute_release_profiles must declare at least one claim");
    }
    let mut claim_names: HashSet<&str> = HashSet::new();
    let mut has_required = false;
    for claim in &profile.claims {
        if !is_valid_claim_name(&claim.name) {
            return release_error(
                "attribute_release_profiles claim name does not match \
                 ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$",
            );
        }
        if !claim_names.insert(claim.name.as_str()) {
            tracing::error!(
                code = "config.duplicate_id",
                dataset_id = %dataset.id,
                entity = %entity.name,
                profile_id = %profile.id,
                claim = %claim.name,
                "duplicate attribute_release_profiles claim name"
            );
            return Err(ConfigError::DuplicateId);
        }
        if !release_claim_has_exactly_one_source(claim) {
            return release_error(
                "attribute_release_profiles claim must declare exactly one of source_field or expression.cel",
            );
        }
        if let Some(source_field) = &claim.source_field {
            if !exposed_fields.contains_key(source_field) {
                return release_error(
                    "attribute_release_profiles claim source_field references a non-exposed field",
                );
            }
        }
        has_required |= claim.required;
    }
    if !has_required {
        return release_error(
            "attribute_release_profiles must declare at least one required claim",
        );
    }

    // Purpose coupling: when the backing entity governs purposes, the profile
    // purpose must be set and a member of the permitted set.
    if let Some(policy) = entity.api.governed_policy.as_ref() {
        if !policy.permitted_purposes.is_empty() {
            match profile.purpose.as_ref() {
                Some(purpose) if policy.permitted_purposes.iter().any(|p| p == purpose) => {}
                Some(_) => {
                    return release_error(
                        "attribute_release_profiles purpose must be one of the entity governed_policy permitted_purposes",
                    );
                }
                None => {
                    return release_error(
                        "attribute_release_profiles purpose is required when the entity governs permitted_purposes",
                    );
                }
            }
        }
    }

    validate_release_profile_expressions(dataset, entity, profile)?;

    Ok(())
}

/// Collect every CEL expression a profile carries (release condition +
/// computed claims) and compile-check it through the Relay-owned adapter.
///
/// When the `attribute-release` feature is enabled each expression is compiled
/// at load so invalid CEL fails closed. Feature-disabled builds reject the
/// enclosing profile before this expression-level check runs.
fn validate_release_profile_expressions(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    profile: &AttributeReleaseProfile,
) -> Result<(), ConfigError> {
    let has_expression = profile.release_conditions.is_some()
        || profile
            .claims
            .iter()
            .any(|claim| claim.expression.is_some());

    #[cfg(not(feature = "attribute-release"))]
    {
        if has_expression {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                profile_id = %profile.id,
                "attribute_release_profiles CEL expressions require the attribute-release feature"
            );
            return Err(ConfigError::ValidationError);
        }
        Ok(())
    }

    #[cfg(feature = "attribute-release")]
    {
        let _ = has_expression;
        if let Some(conditions) = profile.release_conditions.as_ref() {
            compile_release_expression(dataset, entity, profile, &conditions.expression.cel)?;
        }
        for claim in &profile.claims {
            if let Some(expression) = claim.expression.as_ref() {
                compile_release_expression(dataset, entity, profile, &expression.cel)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "attribute-release")]
fn compile_release_expression(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    profile: &AttributeReleaseProfile,
    cel: &str,
) -> Result<(), ConfigError> {
    crate::attribute_release::validate_release_expression(cel).map_err(|err| {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            profile_id = %profile.id,
            error = %err,
            "attribute_release_profiles CEL expression failed to compile"
        );
        ConfigError::ValidationError
    })
}

fn governed_policy_has_enforced_gate(policy: &GovernedPolicyConfig) -> bool {
    !policy.permitted_purposes.is_empty()
        || !policy.permitted_jurisdictions.is_empty()
        || !policy.allowed_assurance.is_empty()
        || policy.minimum_assurance.is_some()
        || policy.max_source_age_seconds.is_some()
        || policy.require_legal_basis
        || policy.require_consent
        || !policy.redaction_fields.is_empty()
}

fn is_top_level_redaction_field(field: &str) -> bool {
    !field.contains('.') && !field.contains('[') && !field.contains(']') && !field.contains('*')
}

fn redaction_field_exists_on_entity_or_aggregate_output(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    field: &str,
) -> bool {
    entity
        .fields
        .iter()
        .any(|configured| configured.name == field)
        || dataset
            .aggregates
            .iter()
            .filter(|aggregate| aggregate.source_entity.as_deref() == Some(entity.name.as_str()))
            .any(|aggregate| {
                aggregate
                    .dimensions
                    .iter()
                    .any(|dimension| dimension.id == field)
                    || aggregate
                        .indicators
                        .iter()
                        .any(|indicator| indicator.id == field)
            })
}

fn entity_governed_policy_error(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    reason: &str,
) -> Result<(), ConfigError> {
    tracing::error!(
        code = "config.validation_error",
        dataset_id = %dataset.id,
        entity = %entity.name,
        reason = %reason,
        "entity governed_policy is invalid"
    );
    Err(ConfigError::ValidationError)
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
        if aggregate.disclosure_control.effective_min_cell_size() < 1 {
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

fn validate_entity_spatial(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
    collection_ids: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let Some(spatial) = &entity.spatial else {
        return Ok(());
    };

    let collection_id = spatial
        .collection_id
        .as_deref()
        .unwrap_or(entity.name.as_str());
    if !is_valid_id(collection_id) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            collection_id = %collection_id,
            "spatial collection_id is not a valid lower-snake id"
        );
        return Err(ConfigError::ValidationError);
    }
    if !collection_ids.insert(collection_id.to_string()) {
        tracing::error!(
            code = "config.duplicate_id",
            dataset_id = %dataset.id,
            entity = %entity.name,
            collection_id = %collection_id,
            "duplicate spatial collection_id within dataset"
        );
        return Err(ConfigError::DuplicateId);
    }

    if !spatial.max_bbox_degrees.is_finite() || spatial.max_bbox_degrees <= 0.0 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            collection_id = %collection_id,
            "spatial max_bbox_degrees must be a positive finite number"
        );
        return Err(ConfigError::ValidationError);
    }
    if spatial.max_geometry_vertices == 0 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            collection_id = %collection_id,
            "spatial max_geometry_vertices must be greater than zero"
        );
        return Err(ConfigError::ValidationError);
    }

    validate_spatial_geometry(dataset, entity, table, exposed_fields, spatial)?;
    if let Some(bbox_fields) = &spatial.bbox_fields {
        validate_spatial_bbox_fields(dataset, entity, table, exposed_fields, bbox_fields)?;
    }
    if let Some(datetime_field) = &spatial.datetime_field {
        let field_type =
            exposed_field_type(table, exposed_fields, datetime_field).ok_or_else(|| {
                tracing::error!(
                    code = "config.validation_error",
                    dataset_id = %dataset.id,
                    entity = %entity.name,
                    field = %datetime_field,
                    "spatial datetime_field references a non-exposed field"
                );
                ConfigError::ValidationError
            })?;
        if !matches!(field_type, FieldType::Date | FieldType::Timestamp) {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %datetime_field,
                "spatial datetime_field must be a date or timestamp field"
            );
            return Err(ConfigError::ValidationError);
        }
    }

    Ok(())
}

fn validate_spatial_geometry(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
    spatial: &EntitySpatialConfig,
) -> Result<(), ConfigError> {
    match &spatial.geometry {
        SpatialGeometryConfig::Point {
            longitude_field,
            latitude_field,
            crs,
        } => {
            validate_spatial_crs(dataset, entity, crs)?;
            validate_numeric_exposed_field(
                dataset,
                entity,
                table,
                exposed_fields,
                longitude_field,
            )?;
            validate_numeric_exposed_field(dataset, entity, table, exposed_fields, latitude_field)?;
        }
        SpatialGeometryConfig::Geojson { field, crs } => {
            validate_spatial_crs(dataset, entity, crs)?;
            validate_exposed_spatial_field(dataset, entity, table, exposed_fields, field)?;
        }
        SpatialGeometryConfig::Wkt { field, crs } | SpatialGeometryConfig::Wkb { field, crs } => {
            tracing::error!(
                code = "config.validation_error",
                dataset_id = %dataset.id,
                entity = %entity.name,
                field = %field,
                crs = %crs,
                "spatial geometry kind is reserved for a later OGC implementation phase"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

fn validate_spatial_crs(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    crs: &str,
) -> Result<(), ConfigError> {
    if crs != CRS84 {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            crs = %crs,
            "spatial CRS must be CRS84 in Phase 1"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_spatial_bbox_fields(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
    bbox_fields: &SpatialBboxFieldsConfig,
) -> Result<(), ConfigError> {
    for field in [
        &bbox_fields.min_x,
        &bbox_fields.min_y,
        &bbox_fields.max_x,
        &bbox_fields.max_y,
    ] {
        validate_numeric_exposed_field(dataset, entity, table, exposed_fields, field)?;
    }
    Ok(())
}

fn validate_exposed_spatial_field(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
    field: &str,
) -> Result<(), ConfigError> {
    if exposed_field_type(table, exposed_fields, field).is_none() {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            field = %field,
            "spatial geometry field references a non-exposed field"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn validate_numeric_exposed_field(
    dataset: &DatasetConfig,
    entity: &EntityConfig,
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
    field: &str,
) -> Result<(), ConfigError> {
    let field_type = exposed_field_type(table, exposed_fields, field).ok_or_else(|| {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            field = %field,
            "spatial numeric field references a non-exposed field"
        );
        ConfigError::ValidationError
    })?;
    if !matches!(field_type, FieldType::Number | FieldType::Integer) {
        tracing::error!(
            code = "config.validation_error",
            dataset_id = %dataset.id,
            entity = %entity.name,
            field = %field,
            "spatial field must be numeric"
        );
        return Err(ConfigError::ValidationError);
    }
    Ok(())
}

fn exposed_field_type(
    table: &ResourceConfig,
    exposed_fields: &BTreeMap<String, String>,
    field: &str,
) -> Option<FieldType> {
    let source = exposed_fields.get(field)?;
    field_by_name(table, source).map(|field| field.r#type)
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
    fn profile_id_allows_hyphens_but_not_uppercase_or_leading_dash() {
        // eSignet contract ids use hyphens.
        assert!(is_valid_profile_id("esignet-civil-userinfo"));
        assert!(is_valid_profile_id("civil_identity"));
        assert!(is_valid_profile_id("a1-b2_c3"));
        assert!(!is_valid_profile_id(""));
        assert!(!is_valid_profile_id("-leading"));
        assert!(!is_valid_profile_id("1-leading-digit"));
        assert!(!is_valid_profile_id("Esignet"));
        assert!(!is_valid_profile_id("with space"));
    }

    #[test]
    fn claim_name_allows_dotted_segments_but_not_empty_segments() {
        // OIDC UserInfo claim names include dotted forms.
        assert!(is_valid_claim_name("address.region"));
        assert!(is_valid_claim_name("given_name"));
        assert!(is_valid_claim_name("a.b.c"));
        assert!(!is_valid_claim_name(""));
        assert!(!is_valid_claim_name(".region"));
        assert!(!is_valid_claim_name("address."));
        assert!(!is_valid_claim_name("address..region"));
        assert!(!is_valid_claim_name("Address.Region"));
        assert!(!is_valid_claim_name("address-region"));
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

    #[test]
    fn oidc_dev_http_url_exception_requires_parsed_loopback_host() {
        assert!(is_allowed_oidc_url("http://127.0.0.1:8080/jwks", true));
        assert!(is_allowed_oidc_url("http://[::1]:8080/jwks", true));
        assert!(is_allowed_oidc_url(
            "http://localhost/.well-known/openid-configuration",
            true
        ));

        assert!(!is_allowed_oidc_url(
            "http://127.0.0.1:80@evil.example/jwks",
            true
        ));
        assert!(!is_allowed_oidc_url(
            "http://localhost:pw@evil.example/jwks",
            true
        ));
        assert!(!is_allowed_oidc_url("http://10.0.0.1/jwks", true));
        assert!(!is_allowed_oidc_url("http://evil.example/jwks", true));
        assert!(!is_allowed_oidc_url(
            "https://user:pw@idp.example.test/jwks",
            false
        ));
    }

    fn deployment_config_yaml(extra: &str) -> String {
        format!(
            r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: stdout
datasets: []
{extra}
"#
        )
    }

    fn parse_deployment_config(extra: &str) -> Config {
        serde_saphyr::from_str(&deployment_config_yaml(extra)).expect("config parses")
    }

    fn consultation_section(entries: &[(&str, &str)]) -> String {
        use std::fmt::Write as _;

        let mut yaml = String::from("consultation:\n  audit_pseudonym_materials:\n");
        for (key_id, source_name) in entries {
            writeln!(
                yaml,
                "    - key_id: \"{key_id}\"\n      source:\n        provider: environment\n        name: \"{source_name}\""
            )
            .expect("write consultation section");
        }
        yaml.push_str("deployment:\n  profile: local");
        yaml
    }

    #[derive(Clone, Default)]
    struct SharedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    struct SharedLogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLog {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter(std::sync::Arc::clone(&self.0))
        }
    }

    impl std::io::Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `f` with a capturing subscriber and returns its result alongside
    /// the rendered log output.
    fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        let logs = SharedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .compact()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let result = f();
        drop(guard);
        let rendered = String::from_utf8(logs.0.lock().expect("log buffer lock").clone())
            .expect("logs are utf-8");
        (result, rendered)
    }

    /// Runs `run(config)` with a capturing subscriber and returns the
    /// rendered log output alongside the validation result.
    fn run_with_captured_logs(config: &Config) -> (Result<(), Error>, String) {
        capture_logs(|| run(config))
    }

    #[test]
    fn consultation_material_catalog_accepts_one_and_thirty_two_entries() {
        let one = parse_deployment_config(&consultation_section(&[("epoch-0", "SOURCE_0")]));
        run(&one).expect("one material is valid");

        let owned = (0..32)
            .map(|index| (format!("epoch-{index}"), format!("SOURCE_{index}")))
            .collect::<Vec<_>>();
        let entries = owned
            .iter()
            .map(|(key_id, source)| (key_id.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let thirty_two = parse_deployment_config(&consultation_section(&entries));
        run(&thirty_two).expect("32 materials are valid");
    }

    #[test]
    fn consultation_material_catalog_rejects_empty_and_over_bound() {
        let empty = parse_deployment_config(&consultation_section(&[]));
        assert!(matches!(
            run(&empty),
            Err(Error::Config(ConfigError::ValidationError))
        ));

        let owned = (0..33)
            .map(|index| (format!("epoch-{index}"), format!("SOURCE_{index}")))
            .collect::<Vec<_>>();
        let entries = owned
            .iter()
            .map(|(key_id, source)| (key_id.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let over_bound = parse_deployment_config(&consultation_section(&entries));
        assert!(matches!(
            run(&over_bound),
            Err(Error::Config(ConfigError::ValidationError))
        ));
    }

    #[test]
    fn consultation_material_catalog_rejects_duplicate_ids_and_sources_without_leaks() {
        let duplicate_id = parse_deployment_config(&consultation_section(&[
            ("epoch-a", "SOURCE_A"),
            ("epoch-a", "SOURCE_B"),
        ]));
        assert!(matches!(
            run(&duplicate_id),
            Err(Error::Config(ConfigError::DuplicateId))
        ));

        let source_marker = "SOURCE_REFERENCE_MUST_NOT_LEAK";
        let duplicate_source = parse_deployment_config(&consultation_section(&[
            ("epoch-a", source_marker),
            ("epoch-b", source_marker),
        ]));
        let (result, logs) = run_with_captured_logs(&duplicate_source);
        assert!(matches!(
            result,
            Err(Error::Config(ConfigError::ValidationError))
        ));
        assert!(!logs.contains(source_marker));
    }

    #[test]
    fn active_waiver_is_loud_in_the_boot_log() {
        let config = parse_deployment_config(
            "deployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"",
        );
        let (result, rendered) = run_with_captured_logs(&config);
        result.expect("a waived hosted_lab gate must pass validation");
        assert!(
            rendered.contains("deployment.gate_waived"),
            "expected deployment.gate_waived in boot log: {rendered}"
        );
        assert!(
            rendered.contains("relay.config.unsigned"),
            "expected the waived finding id in boot log: {rendered}"
        );
        assert!(
            rendered.contains("synthetic-waiver-not-a-secret"),
            "expected the waiver reason in boot log: {rendered}"
        );
        assert!(
            rendered.contains("2999-01-01"),
            "expected the waiver expiry in boot log: {rendered}"
        );
    }

    #[test]
    fn expired_waiver_is_loud_in_the_boot_log() {
        let config = parse_deployment_config(
            "deployment:\n  profile: hosted_lab\n  waivers:\n    - finding: relay.config.unsigned\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2000-01-01\"",
        );
        let (result, rendered) = run_with_captured_logs(&config);
        result.expect("an expired hosted_lab waiver must still pass validation");
        assert!(
            rendered.contains("deployment.waiver_expired"),
            "expected deployment.waiver_expired in boot log: {rendered}"
        );
        assert!(
            rendered.contains("2000-01-01"),
            "expected the expired waiver expiry in boot log: {rendered}"
        );
    }

    #[test]
    fn undeclared_profile_is_loud_in_the_boot_log() {
        let config = parse_deployment_config("");
        let (result, rendered) = run_with_captured_logs(&config);
        assert!(matches!(
            result,
            Err(Error::Config(ConfigError::DeploymentProfileRequired))
        ));
        assert!(
            rendered.contains("deployment.profile_undeclared"),
            "expected deployment.profile_undeclared in boot log: {rendered}"
        );
    }

    #[test]
    fn declared_profile_without_waivers_keeps_the_boot_log_quiet() {
        let config = parse_deployment_config("deployment:\n  profile: local");
        let (result, rendered) = run_with_captured_logs(&config);
        result.expect("a local profile must pass validation");
        assert!(
            !rendered.contains("deployment.gate_waived"),
            "no waiver line expected: {rendered}"
        );
        assert!(
            !rendered.contains("deployment.profile_undeclared"),
            "no undeclared-profile line expected: {rendered}"
        );
    }

    #[test]
    fn evidence_grade_via_signed_bundle_source_boots() {
        // The same evidence_grade config that a local file rejects must validate
        // when the candidate source is a signed bundle: the `relay.config.unsigned`
        // startup gate does not fire for a signed bundle.
        let config = parse_deployment_config(
            "deployment:\n  profile: evidence_grade\n  evidence:\n    ingress_rate_limit: true\n    api_key_rotation: true\n    audit_ack_cursor_path: /var/run/registry-relay/audit-ack-cursor.json",
        );
        for source in [
            ConfigSource::SignedBundleFile,
            ConfigSource::SignedBundleEndpoint,
        ] {
            run_with_source(&config, source)
                .unwrap_or_else(|err| panic!("signed {source:?} must boot, got {err:?}"));
        }
    }

    #[test]
    fn evidence_grade_via_local_file_refuses_startup() {
        let config = parse_deployment_config(
            "deployment:\n  profile: evidence_grade\n  evidence:\n    ingress_rate_limit: true\n    api_key_rotation: true",
        );
        assert!(
            run_with_source(&config, ConfigSource::LocalFile).is_err(),
            "evidence_grade from a local file must refuse startup"
        );
    }

    #[test]
    fn evidence_grade_via_unknown_source_refuses_startup() {
        // Unknown provenance must fail closed: it counts as unsigned, so the
        // `relay.config.unsigned` startup gate fires under evidence_grade.
        let config = parse_deployment_config(
            "deployment:\n  profile: evidence_grade\n  evidence:\n    ingress_rate_limit: true\n    api_key_rotation: true",
        );
        assert!(
            run_with_source(&config, ConfigSource::Unknown).is_err(),
            "evidence_grade with unknown provenance must refuse startup (fail closed)"
        );
    }

    #[test]
    fn waiver_finding_id_must_match_finding_id_pattern() {
        // A malformed finding id is rejected at config load, before it could
        // surface later as restricted-tier posture schema invalidity.
        let config = parse_deployment_config(
            "deployment:\n  profile: hosted_lab\n  waivers:\n    - finding: \"Relay.Config.Unsigned\"\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"",
        );
        assert!(
            run(&config).is_err(),
            "a waiver with a malformed finding id must fail validation"
        );
    }

    #[test]
    fn waiver_finding_id_accepts_canonical_dotted_id() {
        let config = parse_deployment_config(
            "deployment:\n  profile: hosted_lab\n  waivers:\n    - finding: \"relay.config.unsigned\"\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"",
        );
        run(&config).expect("a canonical dotted finding id must pass validation");
    }

    #[test]
    fn waiver_on_hard_gate_is_rejected_at_load() {
        // Under evidence_grade the retention gate is a startup_fail gate and
        // cannot be waived. The waiver must be rejected at load, not silently
        // dropped. Evaluate as a signed bundle so the `relay.config.unsigned`
        // startup gate does not fire: the hard-gate waiver is then the only
        // reason validation can fail (the base config uses a stdout sink, so
        // the retention condition itself does not even trigger here).
        let config = parse_deployment_config(
            "deployment:\n  profile: evidence_grade\n  waivers:\n    - finding: relay.audit.retention_local_only\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"",
        );
        let (result, rendered) =
            capture_logs(|| run_with_source(&config, ConfigSource::SignedBundleFile));
        assert!(
            matches!(result, Err(Error::Config(ConfigError::ValidationError))),
            "a waiver on a hard evidence_grade gate must be rejected, got {result:?}"
        );
        assert!(
            rendered.contains("cannot be waived under the active profile"),
            "expected the hard-gate rejection message in the log: {rendered}"
        );
        assert!(
            rendered.contains("relay.audit.retention_local_only"),
            "expected the rejected finding id in the log: {rendered}"
        );
        assert!(
            rendered.contains("audit_offhost_shipping"),
            "expected the audit off-host remediation in the log: {rendered}"
        );
    }

    #[test]
    fn waiver_on_waivable_gate_still_loads_and_waives() {
        // The same finding under production is a waivable finding_warn. A
        // file-sink deployment triggers the retention condition, and the waiver
        // must be accepted and suppress it (reported as waived in the boot log).
        let config: Config = serde_saphyr::from_str(
            r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: file
  path: "/var/log/relay/audit.jsonl"
datasets: []
deployment:
  profile: production
  waivers:
    - finding: relay.audit.retention_local_only
      reason: "synthetic-waiver-not-a-secret"
      expires: "2999-01-01"
"#,
        )
        .expect("config parses");
        let (result, rendered) = run_with_captured_logs(&config);
        result.expect("a waivable production gate waiver must pass validation");
        assert!(
            rendered.contains("deployment.gate_waived"),
            "expected the retention gate to be reported waived: {rendered}"
        );
        assert!(
            rendered.contains("relay.audit.retention_local_only"),
            "expected the waived finding id in the boot log: {rendered}"
        );
        assert!(
            !rendered.contains("cannot be waived"),
            "a waivable gate must not trigger the hard-gate rejection: {rendered}"
        );
    }

    #[test]
    fn waiver_on_readiness_gate_is_rejected_at_load() {
        // Under evidence_grade `relay.audit.best_effort` is a readiness_fail
        // gate, which is non-waivable under Notary's (now Relay's) semantics.
        // The waiver must be rejected at config load with the structured
        // validation error, not silently dropped, even though the condition
        // itself does not hold here. Evaluate as a signed bundle so the
        // `relay.config.unsigned` startup gate does not fire and the readiness
        // waiver is the only reason validation can fail.
        let config = parse_deployment_config(
            "deployment:\n  profile: evidence_grade\n  waivers:\n    - finding: relay.audit.best_effort\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"",
        );
        let (result, rendered) =
            capture_logs(|| run_with_source(&config, ConfigSource::SignedBundleFile));
        assert!(
            matches!(result, Err(Error::Config(ConfigError::ValidationError))),
            "a waiver on a readiness_fail evidence_grade gate must be rejected, got {result:?}"
        );
        assert!(
            rendered.contains("config.validation_error"),
            "expected the structured validation error code in the log: {rendered}"
        );
        assert!(
            rendered.contains("cannot be waived under the active profile"),
            "expected the hard-gate rejection message in the log: {rendered}"
        );
        assert!(
            rendered.contains("relay.audit.best_effort"),
            "expected the rejected readiness-gate finding id in the log: {rendered}"
        );
    }

    #[test]
    fn audit_ack_max_age_without_cursor_is_rejected() {
        // A freshness window is meaningless without a cursor path to observe.
        let config = parse_deployment_config(
            "deployment:\n  profile: local\n  evidence:\n    audit_ack_max_age_secs: 60",
        );
        let (result, rendered) = run_with_captured_logs(&config);
        assert!(
            matches!(result, Err(Error::Config(ConfigError::ValidationError))),
            "max_age without a cursor path must be rejected, got {result:?}"
        );
        assert!(
            rendered.contains("audit_ack_max_age_secs"),
            "expected the offending field in the log: {rendered}"
        );
    }

    #[test]
    fn audit_ack_cursor_on_local_file_without_offhost_is_rejected() {
        // A cursor asserts observed off-host shipping; a local file sink that
        // does not declare off-host shipping must not configure one.
        let config: Config = serde_saphyr::from_str(
            r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: file
  path: "/var/log/relay/audit.jsonl"
datasets: []
deployment:
  profile: local
  evidence:
    audit_ack_cursor_path: "/var/lib/relay/ack-cursor.json"
"#,
        )
        .expect("config parses");
        let (result, rendered) = run_with_captured_logs(&config);
        assert!(
            matches!(result, Err(Error::Config(ConfigError::ValidationError))),
            "a cursor on a local file sink without off-host shipping must be rejected, got {result:?}"
        );
        assert!(
            rendered.contains("audit_ack_cursor_path"),
            "expected the offending field in the log: {rendered}"
        );
        assert!(
            rendered.contains("audit_offhost_shipping"),
            "expected the off-host remediation in the log: {rendered}"
        );
    }

    #[test]
    fn audit_ack_cursor_on_local_file_with_offhost_loads() {
        // The same local file sink loads once off-host shipping is declared.
        let config: Config = serde_saphyr::from_str(
            r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: file
  path: "/var/log/relay/audit.jsonl"
datasets: []
deployment:
  profile: local
  evidence:
    audit_offhost_shipping: true
    audit_ack_cursor_path: "/var/lib/relay/ack-cursor.json"
    audit_ack_max_age_secs: 600
"#,
        )
        .expect("config parses");
        run(&config).expect("a declared-off-host local file sink with a cursor must load");
    }

    #[test]
    fn audit_ack_cursor_on_stdout_without_offhost_loads() {
        // Stdout ships inherently, so a cursor may be configured without the
        // off-host boolean.
        let config = parse_deployment_config(
            "deployment:\n  profile: local\n  evidence:\n    audit_ack_cursor_path: \"/var/lib/relay/ack-cursor.json\"",
        );
        run(&config).expect("a stdout sink with a cursor and no boolean must load");
    }

    #[test]
    fn waiver_on_shipping_stale_is_rejected_at_load() {
        // Under evidence_grade `relay.audit.shipping_stale` is a readiness_fail
        // gate, which is non-waivable. The waiver must be rejected at load, not
        // silently dropped, even though no cursor is configured so the condition
        // does not hold. Evaluate as a signed bundle so the
        // `relay.config.unsigned` startup gate does not fire.
        let config = parse_deployment_config(
            "deployment:\n  profile: evidence_grade\n  waivers:\n    - finding: relay.audit.shipping_stale\n      reason: \"synthetic-waiver-not-a-secret\"\n      expires: \"2999-01-01\"",
        );
        let (result, rendered) =
            capture_logs(|| run_with_source(&config, ConfigSource::SignedBundleFile));
        assert!(
            matches!(result, Err(Error::Config(ConfigError::ValidationError))),
            "a waiver on the readiness_fail shipping_stale gate must be rejected, got {result:?}"
        );
        assert!(
            rendered.contains("cannot be waived under the active profile"),
            "expected the hard-gate rejection message in the log: {rendered}"
        );
        assert!(
            rendered.contains("relay.audit.shipping_stale"),
            "expected the rejected finding id in the log: {rendered}"
        );
        assert!(
            rendered.contains("audit_ack_max_age_secs"),
            "expected the shipping_stale remediation in the log: {rendered}"
        );
    }

    #[test]
    fn finding_id_pattern_matches_catalog_ids() {
        // The pattern must admit every id the catalog can emit, including the
        // framework findings with their dotted segments.
        assert!(is_valid_finding_id("relay.config.unsigned"));
        assert!(is_valid_finding_id("relay.admin.public_exposure"));
        assert!(is_valid_finding_id("deployment.profile_undeclared"));
        assert!(is_valid_finding_id("deployment.waiver_expired"));
        assert!(is_valid_finding_id(
            "relay.auth.api_key_no_rotation_evidence"
        ));
    }

    #[test]
    fn finding_id_pattern_rejects_malformed_ids() {
        assert!(!is_valid_finding_id(""));
        assert!(!is_valid_finding_id("Relay.config.unsigned"));
        assert!(!is_valid_finding_id("1relay.config"));
        assert!(!is_valid_finding_id(".relay.config"));
        assert!(!is_valid_finding_id("relay..config"));
        assert!(!is_valid_finding_id("relay.config."));
        assert!(!is_valid_finding_id("relay.Config"));
        assert!(!is_valid_finding_id("relay config"));
    }

    fn release_claim(source_field: Option<&str>, expression: Option<&str>) -> ReleaseClaimConfig {
        ReleaseClaimConfig {
            name: "given_name".to_string(),
            source_field: source_field.map(str::to_string),
            expression: expression.map(|cel| crate::config::ReleaseExpressionConfig {
                cel: cel.to_string(),
            }),
            required: false,
            sensitivity: None,
            format: None,
            locale: None,
            shareable: true,
        }
    }

    #[test]
    fn scope_level_allowlist_includes_identity_release() {
        assert!(is_valid_scope_level("identity_release"));
        assert!(is_valid_scope_level("metadata"));
        assert!(is_valid_scope_level("rows"));
        assert!(!is_valid_scope_level("identity_release_extra"));
        assert!(!is_valid_scope_level("unknown"));
    }

    #[test]
    fn release_claim_source_xor_accepts_exactly_one() {
        assert!(release_claim_has_exactly_one_source(&release_claim(
            Some("given_name"),
            None
        )));
        assert!(release_claim_has_exactly_one_source(&release_claim(
            None,
            Some("source.given_name")
        )));
    }

    #[test]
    fn release_claim_source_xor_rejects_both_or_neither() {
        assert!(!release_claim_has_exactly_one_source(&release_claim(
            Some("given_name"),
            Some("source.given_name")
        )));
        assert!(!release_claim_has_exactly_one_source(&release_claim(
            None, None
        )));
    }

    #[test]
    fn auth_failure_throttle_disabled_ignores_zero_fields() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-disabled-secret",
        );
        config.auth.failure_throttle.max_failures = 0;
        config.auth.failure_throttle.window_seconds = 0;
        assert!(super::run(&config).is_ok());
    }

    #[test]
    fn auth_failure_throttle_enabled_rejects_zero_max_failures() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-zero-max-secret",
        );
        config.auth.failure_throttle.enabled = true;
        config.auth.failure_throttle.max_failures = 0;
        let err = super::run(&config).expect_err("zero max_failures rejected");
        assert_eq!(err.code(), "config.validation_error");
    }

    #[test]
    fn auth_failure_throttle_enabled_rejects_zero_window_seconds() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-zero-window-secret",
        );
        config.auth.failure_throttle.enabled = true;
        config.auth.failure_throttle.window_seconds = 0;
        let err = super::run(&config).expect_err("zero window_seconds rejected");
        assert_eq!(err.code(), "config.validation_error");
    }

    #[test]
    fn auth_failure_throttle_enabled_accepts_positive_values() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-valid-secret",
        );
        config.auth.failure_throttle.enabled = true;
        config.auth.failure_throttle.max_failures = 5;
        config.auth.failure_throttle.window_seconds = 30;
        assert!(super::run(&config).is_ok());
    }

    /// Runs `validate_auth_failure_throttle` under a captured tracing
    /// subscriber and returns the rendered log output.
    fn captured_throttle_validation_logs(config: &Config) -> String {
        let logs = SharedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .compact()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);
        let result = validate_auth_failure_throttle(config);
        drop(guard);

        result.expect("throttle validation succeeds");
        let rendered = logs.0.lock().expect("log buffer lock").clone();
        String::from_utf8(rendered).expect("logs are utf-8")
    }

    #[test]
    fn auth_failure_throttle_without_trust_proxy_warns() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-no-trust-proxy-secret",
        );
        config.auth.failure_throttle.enabled = true;
        config.server.trust_proxy.enabled = false;
        let rendered = captured_throttle_validation_logs(&config);
        assert!(
            rendered.contains("config.validation_warning"),
            "expected a validation warning: {rendered}"
        );
        assert!(
            rendered.contains("trust_proxy"),
            "expected the warning to mention trust_proxy: {rendered}"
        );
    }

    #[test]
    fn auth_failure_throttle_with_trust_proxy_is_silent() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-with-trust-proxy-secret",
        );
        config.auth.failure_throttle.enabled = true;
        config.server.trust_proxy.enabled = true;
        config.server.trust_proxy.trusted_proxies = vec!["10.0.0.0/8".to_string()];
        let rendered = captured_throttle_validation_logs(&config);
        assert!(
            !rendered.contains("config.validation_warning"),
            "did not expect a validation warning: {rendered}"
        );
    }

    #[test]
    fn auth_failure_throttle_with_trust_proxy_but_empty_trusted_proxies_warns() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-trust-proxy-empty-list-secret",
        );
        config.auth.failure_throttle.enabled = true;
        config.server.trust_proxy.enabled = true;
        config.server.trust_proxy.trusted_proxies = Vec::new();
        let rendered = captured_throttle_validation_logs(&config);
        assert!(
            rendered.contains("config.validation_warning"),
            "expected a validation warning: {rendered}"
        );
        assert!(
            rendered.contains("trusted_proxies"),
            "expected the warning to mention the empty trusted_proxies list: {rendered}"
        );
    }

    #[test]
    fn auth_failure_throttle_disabled_is_silent_regardless_of_trust_proxy() {
        let mut config = crate::config::test_support::load_example_config_for_tests(
            "validate-test-auth-failure-throttle-disabled-silent-secret",
        );
        config.auth.failure_throttle.enabled = false;
        config.server.trust_proxy.enabled = false;
        let rendered = captured_throttle_validation_logs(&config);
        assert!(
            !rendered.contains("config.validation_warning"),
            "did not expect a validation warning: {rendered}"
        );
    }
}
