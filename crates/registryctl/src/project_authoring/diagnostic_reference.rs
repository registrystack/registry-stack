// SPDX-License-Identifier: Apache-2.0
//! Pure, deterministic references for closed Registry Stack diagnostic codes.
//!
//! Product owners retain their code, meaning, rule, remediation, lifecycle,
//! and evidence-policy definitions. This module projects those definitions
//! into one strict public shape without reading a workspace, environment,
//! secret, runtime service, or process-local diagnostic value.

use std::collections::BTreeSet;

use registry_notary_server::{
    NotaryActivationCode, NotaryActivationCodeLifecycle, NOTARY_ACTIVATION_CODE_DEFINITIONS,
};
use registry_platform_ops::{
    BundleVerificationCode, BundleVerificationCodeLifecycle, BundleVerificationEvidencePolicy,
    BUNDLE_VERIFICATION_CODE_DEFINITIONS,
};
use registry_relay::consultation::{
    consultation_service_activation_definitions, ConsultationServiceActivationCode,
    ConsultationServiceActivationLifecycle,
};
use registry_relay::process_startup::{
    ProcessStartupCode, ProcessStartupCodeLifecycle, ProcessStartupEvidencePolicy,
    PROCESS_STARTUP_CODE_DEFINITIONS,
};
use serde::{Deserialize, Serialize};

use super::fixture_diagnostics::{fixture_diagnostic_definition, FIXTURE_DIAGNOSTIC_DEFINITIONS};
use super::{
    preflight_diagnostic_definition, project_authoring_diagnostic_definitions,
    PREFLIGHT_DIAGNOSTIC_DEFINITIONS,
};

pub const AUTHORING_ERROR_REFERENCE_SCHEMA_VERSION_V1: &str =
    "registryctl.authoring_error_reference.v1";
pub const FIXTURE_ERROR_REFERENCE_SCHEMA_VERSION_V1: &str =
    "registryctl.fixture_error_reference.v1";
pub const OPERATOR_ERROR_REFERENCE_SCHEMA_VERSION_V1: &str =
    "registryctl.operator_error_reference.v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReferenceFamily {
    AuthoringValidation,
    BundleVerification,
    FixtureExecution,
    NotaryActivation,
    OperatorPreflight,
    RelayActivation,
    RelayProcessStartup,
}

impl ErrorReferenceFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthoringValidation => "authoring_validation",
            Self::BundleVerification => "bundle_verification",
            Self::FixtureExecution => "fixture_execution",
            Self::NotaryActivation => "notary_activation",
            Self::OperatorPreflight => "operator_preflight",
            Self::RelayActivation => "relay_activation",
            Self::RelayProcessStartup => "relay_process_startup",
        }
    }

    const fn docs_catalog(self) -> &'static str {
        match self {
            Self::AuthoringValidation => "authoring",
            Self::FixtureExecution => "fixture",
            Self::BundleVerification
            | Self::NotaryActivation
            | Self::OperatorPreflight
            | Self::RelayActivation
            | Self::RelayProcessStartup => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReferenceOwner {
    RegistryNotary,
    RegistryPlatformOps,
    RegistryRelay,
    Registryctl,
}

impl ErrorReferenceOwner {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistryNotary => "registry_notary",
            Self::RegistryPlatformOps => "registry_platform_ops",
            Self::RegistryRelay => "registry_relay",
            Self::Registryctl => "registryctl",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReferenceProduct {
    RegistryNotary,
    RegistryPlatformOps,
    RegistryRelay,
    Registryctl,
    RegistryctlRelayOfflineHarness,
}

impl ErrorReferenceProduct {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistryNotary => "registry_notary",
            Self::RegistryPlatformOps => "registry_platform_ops",
            Self::RegistryRelay => "registry_relay",
            Self::Registryctl => "registryctl",
            Self::RegistryctlRelayOfflineHarness => "registryctl_relay_offline_harness",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReferenceValuePolicy {
    NoReceivedValue,
    NoRuntimeValues,
    ReceivedTypeOnly,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReferenceLifecycle {
    Active,
    Deprecated,
    Released,
    Unreleased,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReferenceStability {
    Pre1StableCode,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorReferenceEntry {
    pub family: ErrorReferenceFamily,
    pub code: String,
    pub owner: ErrorReferenceOwner,
    pub product: ErrorReferenceProduct,
    pub phase: String,
    pub safe_meaning: String,
    pub rule: String,
    pub safe_remediation: String,
    pub field_address_pattern: Option<String>,
    pub evidence_scope: String,
    pub secret_sensitive_value_policy: ErrorReferenceValuePolicy,
    pub docs_anchor: String,
    pub lifecycle: ErrorReferenceLifecycle,
    pub introduced_in: Option<String>,
    pub stability: ErrorReferenceStability,
    pub evidence_limitation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringErrorReferenceV1 {
    pub schema_version: String,
    pub entries: Vec<ErrorReferenceEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureErrorReferenceV1 {
    pub schema_version: String,
    pub entries: Vec<ErrorReferenceEntry>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorErrorOmissionFamily {
    BundleVerification,
    NotaryActivation,
    OperatorPreflight,
    RelayActivation,
    RelayProcessStartup,
}

impl OperatorErrorOmissionFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BundleVerification => "bundle_verification",
            Self::NotaryActivation => "notary_activation",
            Self::OperatorPreflight => "operator_preflight",
            Self::RelayActivation => "relay_activation",
            Self::RelayProcessStartup => "relay_process_startup",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorErrorOmissionReason {
    NoCompletePublicCodeCatalog,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorErrorOmission {
    pub family: OperatorErrorOmissionFamily,
    pub product: ErrorReferenceProduct,
    pub reason: OperatorErrorOmissionReason,
    pub evidence: String,
    pub required_action: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorErrorReferenceV1 {
    pub schema_version: String,
    pub entries: Vec<ErrorReferenceEntry>,
    pub omissions: Vec<OperatorErrorOmission>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorReferenceValidationError {
    SchemaVersionMismatch,
    DuplicateEntry,
    UnsortedEntries,
    LifecycleVersionMismatch,
    DocsAnchorMismatch,
    EntriesDoNotMatchSources,
    DuplicateOmission,
    UnsortedOmissions,
    OmissionsDoNotMatchSources,
    SourceCatalogMismatch,
}

#[must_use]
pub fn authoring_error_reference() -> AuthoringErrorReferenceV1 {
    let mut entries = project_authoring_diagnostic_definitions()
        .iter()
        .map(|definition| ErrorReferenceEntry {
            family: ErrorReferenceFamily::AuthoringValidation,
            code: definition.code.to_string(),
            owner: ErrorReferenceOwner::Registryctl,
            product: ErrorReferenceProduct::Registryctl,
            phase: definition.phase.to_string(),
            safe_meaning: definition.accepted.to_string(),
            rule: definition.rule.to_string(),
            safe_remediation: definition.safe_remediation.to_string(),
            field_address_pattern: authoring_address_pattern(definition.code).map(str::to_string),
            evidence_scope: "offline authored project files selected for registryctl check"
                .to_string(),
            secret_sensitive_value_policy: match definition.safe_summary_policy {
                "no_received_value" => ErrorReferenceValuePolicy::NoReceivedValue,
                "received_type_only" => ErrorReferenceValuePolicy::ReceivedTypeOnly,
                _ => unreachable!("authoring safe summary policy is closed"),
            },
            docs_anchor: definition.documentation.to_string(),
            lifecycle: ErrorReferenceLifecycle::Unreleased,
            introduced_in: None,
            stability: ErrorReferenceStability::Pre1StableCode,
            evidence_limitation:
                "Static authoring evidence does not prove live source or deployment compatibility."
                    .to_string(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| entry_key(left).cmp(&entry_key(right)));
    AuthoringErrorReferenceV1 {
        schema_version: AUTHORING_ERROR_REFERENCE_SCHEMA_VERSION_V1.to_string(),
        entries,
    }
}

#[must_use]
pub fn fixture_error_reference() -> FixtureErrorReferenceV1 {
    let mut entries = FIXTURE_DIAGNOSTIC_DEFINITIONS
        .iter()
        .map(|definition| {
            let code = closed_string(&definition.code);
            ErrorReferenceEntry {
                family: ErrorReferenceFamily::FixtureExecution,
                code: code.clone(),
                owner: ErrorReferenceOwner::Registryctl,
                product: ErrorReferenceProduct::RegistryctlRelayOfflineHarness,
                phase: "offline_execution".to_string(),
                safe_meaning: definition.safe_meaning.to_string(),
                rule: definition.rule.to_string(),
                safe_remediation: definition.safe_remediation.to_string(),
                field_address_pattern: None,
                evidence_scope: "offline synthetic fixture execution".to_string(),
                secret_sensitive_value_policy: ErrorReferenceValuePolicy::NoRuntimeValues,
                docs_anchor: docs_anchor(
                    ErrorReferenceFamily::FixtureExecution,
                    ErrorReferenceProduct::RegistryctlRelayOfflineHarness,
                    &code,
                ),
                lifecycle: ErrorReferenceLifecycle::Unreleased,
                introduced_in: None,
                stability: ErrorReferenceStability::Pre1StableCode,
                evidence_limitation:
                    "Offline synthetic evidence does not prove live source compatibility."
                        .to_string(),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| entry_key(left).cmp(&entry_key(right)));
    FixtureErrorReferenceV1 {
        schema_version: FIXTURE_ERROR_REFERENCE_SCHEMA_VERSION_V1.to_string(),
        entries,
    }
}

#[must_use]
pub fn operator_error_reference() -> OperatorErrorReferenceV1 {
    let mut entries = preflight_reference_entries();
    entries.extend(bundle_verification_reference_entries());
    entries.extend(notary_activation_reference_entries());
    entries.extend(relay_activation_reference_entries());
    entries.extend(relay_process_startup_reference_entries());
    entries.sort_by(|left, right| entry_key(left).cmp(&entry_key(right)));

    OperatorErrorReferenceV1 {
        schema_version: OPERATOR_ERROR_REFERENCE_SCHEMA_VERSION_V1.to_string(),
        entries,
        omissions: expected_operator_omissions(),
    }
}

fn preflight_reference_entries() -> Vec<ErrorReferenceEntry> {
    PREFLIGHT_DIAGNOSTIC_DEFINITIONS
        .iter()
        .map(|definition| {
            let code = closed_string(&definition.code);
            ErrorReferenceEntry {
                family: ErrorReferenceFamily::OperatorPreflight,
                code: code.clone(),
                owner: ErrorReferenceOwner::Registryctl,
                product: ErrorReferenceProduct::Registryctl,
                phase: closed_string(&definition.phase),
                safe_meaning: closed_string(&definition.safe_meaning),
                rule: closed_string(&definition.rule),
                safe_remediation: definition.safe_remediation.to_string(),
                field_address_pattern: definition.field_address_pattern.map(str::to_string),
                evidence_scope: "offline local operator preflight".to_string(),
                secret_sensitive_value_policy: ErrorReferenceValuePolicy::NoRuntimeValues,
                docs_anchor: docs_anchor(
                    ErrorReferenceFamily::OperatorPreflight,
                    ErrorReferenceProduct::Registryctl,
                    &code,
                ),
                lifecycle: ErrorReferenceLifecycle::Unreleased,
                introduced_in: None,
                stability: ErrorReferenceStability::Pre1StableCode,
                evidence_limitation:
                    "Preflight does not contact live sources or prove remote availability."
                        .to_string(),
            }
        })
        .collect()
}

fn bundle_verification_reference_entries() -> Vec<ErrorReferenceEntry> {
    BUNDLE_VERIFICATION_CODE_DEFINITIONS
        .iter()
        .map(|definition| {
            let code = definition.code.as_str().to_string();
            let lifecycle = match definition.lifecycle {
                BundleVerificationCodeLifecycle::Unreleased => ErrorReferenceLifecycle::Unreleased,
                BundleVerificationCodeLifecycle::Active => ErrorReferenceLifecycle::Active,
                BundleVerificationCodeLifecycle::Deprecated => ErrorReferenceLifecycle::Deprecated,
            };
            ErrorReferenceEntry {
                family: ErrorReferenceFamily::BundleVerification,
                code: code.clone(),
                owner: ErrorReferenceOwner::RegistryPlatformOps,
                product: ErrorReferenceProduct::RegistryPlatformOps,
                phase: definition.phase.to_string(),
                safe_meaning: definition.safe_meaning.to_string(),
                rule: definition.rule.to_string(),
                safe_remediation: definition.safe_remediation.to_string(),
                field_address_pattern: None,
                evidence_scope: definition.evidence_scope.to_string(),
                secret_sensitive_value_policy: match definition.evidence_policy {
                    BundleVerificationEvidencePolicy::NoRuntimeValues => {
                        ErrorReferenceValuePolicy::NoRuntimeValues
                    }
                    _ => panic!("unsupported bundle-verification evidence policy"),
                },
                docs_anchor: docs_anchor(
                    ErrorReferenceFamily::BundleVerification,
                    ErrorReferenceProduct::RegistryPlatformOps,
                    definition.docs_slug,
                ),
                lifecycle,
                introduced_in: definition.introduced_in.map(str::to_string),
                stability: ErrorReferenceStability::Pre1StableCode,
                evidence_limitation: definition.evidence_limitation.to_string(),
            }
        })
        .collect()
}

fn relay_activation_reference_entries() -> Vec<ErrorReferenceEntry> {
    consultation_service_activation_definitions()
        .iter()
        .map(|definition| {
            let code = definition.code.as_str().to_string();
            let lifecycle = match definition.lifecycle {
                ConsultationServiceActivationLifecycle::Unreleased => {
                    ErrorReferenceLifecycle::Unreleased
                }
                ConsultationServiceActivationLifecycle::Active => ErrorReferenceLifecycle::Active,
                ConsultationServiceActivationLifecycle::Deprecated => {
                    ErrorReferenceLifecycle::Deprecated
                }
                _ => panic!("unsupported Relay activation lifecycle"),
            };
            ErrorReferenceEntry {
                family: ErrorReferenceFamily::RelayActivation,
                code: code.clone(),
                owner: ErrorReferenceOwner::RegistryRelay,
                product: ErrorReferenceProduct::RegistryRelay,
                phase: definition.phase.to_string(),
                safe_meaning: definition.meaning.to_string(),
                rule: definition.rule.to_string(),
                safe_remediation: definition.remediation.to_string(),
                field_address_pattern: None,
                evidence_scope: definition.evidence_scope.to_string(),
                secret_sensitive_value_policy: ErrorReferenceValuePolicy::NoRuntimeValues,
                docs_anchor: docs_anchor(
                    ErrorReferenceFamily::RelayActivation,
                    ErrorReferenceProduct::RegistryRelay,
                    definition.docs_slug,
                ),
                lifecycle,
                introduced_in: definition
                    .introduced_in
                    .map(|version| version.as_str().to_string()),
                stability: ErrorReferenceStability::Pre1StableCode,
                evidence_limitation: definition.evidence_limitation.to_string(),
            }
        })
        .collect()
}

fn relay_process_startup_reference_entries() -> Vec<ErrorReferenceEntry> {
    PROCESS_STARTUP_CODE_DEFINITIONS
        .iter()
        .map(|definition| {
            let code = definition.code.as_str().to_string();
            let lifecycle = match definition.lifecycle {
                ProcessStartupCodeLifecycle::Unreleased => ErrorReferenceLifecycle::Unreleased,
                ProcessStartupCodeLifecycle::Active => ErrorReferenceLifecycle::Active,
                ProcessStartupCodeLifecycle::Deprecated => ErrorReferenceLifecycle::Deprecated,
            };
            ErrorReferenceEntry {
                family: ErrorReferenceFamily::RelayProcessStartup,
                code: code.clone(),
                owner: ErrorReferenceOwner::RegistryRelay,
                product: ErrorReferenceProduct::RegistryRelay,
                phase: definition.phase.to_string(),
                safe_meaning: definition.safe_meaning.to_string(),
                rule: definition.rule.to_string(),
                safe_remediation: definition.safe_remediation.to_string(),
                field_address_pattern: None,
                evidence_scope: definition.evidence_scope.to_string(),
                secret_sensitive_value_policy: match definition.evidence_policy {
                    ProcessStartupEvidencePolicy::NoRuntimeValues => {
                        ErrorReferenceValuePolicy::NoRuntimeValues
                    }
                },
                docs_anchor: docs_anchor(
                    ErrorReferenceFamily::RelayProcessStartup,
                    ErrorReferenceProduct::RegistryRelay,
                    definition.docs_slug,
                ),
                lifecycle,
                introduced_in: definition.introduced_in.map(str::to_string),
                stability: ErrorReferenceStability::Pre1StableCode,
                evidence_limitation: definition.evidence_limitation.to_string(),
            }
        })
        .collect()
}

fn notary_activation_reference_entries() -> Vec<ErrorReferenceEntry> {
    NOTARY_ACTIVATION_CODE_DEFINITIONS
        .iter()
        .map(|definition| {
            let code = definition.code.as_str().to_string();
            let lifecycle = match definition.lifecycle {
                NotaryActivationCodeLifecycle::Unreleased => ErrorReferenceLifecycle::Unreleased,
                NotaryActivationCodeLifecycle::Released { .. } => ErrorReferenceLifecycle::Released,
            };
            ErrorReferenceEntry {
                family: ErrorReferenceFamily::NotaryActivation,
                code: code.clone(),
                owner: ErrorReferenceOwner::RegistryNotary,
                product: ErrorReferenceProduct::RegistryNotary,
                phase: definition.phase.to_string(),
                safe_meaning: definition.meaning.to_string(),
                rule: definition.rule.to_string(),
                safe_remediation: definition.remediation.to_string(),
                field_address_pattern: None,
                evidence_scope: definition.evidence_scope.to_string(),
                secret_sensitive_value_policy: ErrorReferenceValuePolicy::NoRuntimeValues,
                docs_anchor: docs_anchor(
                    ErrorReferenceFamily::NotaryActivation,
                    ErrorReferenceProduct::RegistryNotary,
                    definition.docs_slug,
                ),
                lifecycle,
                introduced_in: definition
                    .lifecycle
                    .introduced_version()
                    .map(str::to_string),
                stability: ErrorReferenceStability::Pre1StableCode,
                evidence_limitation: definition.evidence_limitation.to_string(),
            }
        })
        .collect()
}

fn expected_operator_omissions() -> Vec<OperatorErrorOmission> {
    Vec::new()
}

pub fn validate_authoring_error_reference(
    reference: &AuthoringErrorReferenceV1,
) -> Result<(), ErrorReferenceValidationError> {
    if reference.schema_version != AUTHORING_ERROR_REFERENCE_SCHEMA_VERSION_V1 {
        return Err(ErrorReferenceValidationError::SchemaVersionMismatch);
    }
    validate_source_catalogs()?;
    validate_entries(&reference.entries, &authoring_error_reference().entries)
}

pub fn validate_fixture_error_reference(
    reference: &FixtureErrorReferenceV1,
) -> Result<(), ErrorReferenceValidationError> {
    if reference.schema_version != FIXTURE_ERROR_REFERENCE_SCHEMA_VERSION_V1 {
        return Err(ErrorReferenceValidationError::SchemaVersionMismatch);
    }
    validate_source_catalogs()?;
    validate_entries(&reference.entries, &fixture_error_reference().entries)
}

pub fn validate_operator_error_reference(
    reference: &OperatorErrorReferenceV1,
) -> Result<(), ErrorReferenceValidationError> {
    if reference.schema_version != OPERATOR_ERROR_REFERENCE_SCHEMA_VERSION_V1 {
        return Err(ErrorReferenceValidationError::SchemaVersionMismatch);
    }
    validate_source_catalogs()?;
    validate_entries(&reference.entries, &operator_error_reference().entries)?;
    validate_omissions(&reference.omissions, &expected_operator_omissions())
}

fn validate_entries(
    entries: &[ErrorReferenceEntry],
    expected: &[ErrorReferenceEntry],
) -> Result<(), ErrorReferenceValidationError> {
    let keys = entries.iter().map(entry_key).collect::<Vec<_>>();
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return Err(ErrorReferenceValidationError::DuplicateEntry);
    }
    if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ErrorReferenceValidationError::UnsortedEntries);
    }
    for entry in entries {
        if !lifecycle_version_is_valid(entry.lifecycle, entry.introduced_in.as_deref()) {
            return Err(ErrorReferenceValidationError::LifecycleVersionMismatch);
        }
        if entry.docs_anchor != expected_docs_anchor(entry) {
            return Err(ErrorReferenceValidationError::DocsAnchorMismatch);
        }
    }
    if entries != expected {
        return Err(ErrorReferenceValidationError::EntriesDoNotMatchSources);
    }
    Ok(())
}

fn validate_omissions(
    omissions: &[OperatorErrorOmission],
    expected: &[OperatorErrorOmission],
) -> Result<(), ErrorReferenceValidationError> {
    let keys = omissions.iter().map(omission_key).collect::<Vec<_>>();
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return Err(ErrorReferenceValidationError::DuplicateOmission);
    }
    if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ErrorReferenceValidationError::UnsortedOmissions);
    }
    if omissions != expected {
        return Err(ErrorReferenceValidationError::OmissionsDoNotMatchSources);
    }
    Ok(())
}

fn validate_source_catalogs() -> Result<(), ErrorReferenceValidationError> {
    if !project_authoring_diagnostic_definitions()
        .windows(2)
        .all(|pair| pair[0].code < pair[1].code)
    {
        return Err(ErrorReferenceValidationError::SourceCatalogMismatch);
    }
    if !FIXTURE_DIAGNOSTIC_DEFINITIONS
        .iter()
        .all(|definition| fixture_diagnostic_definition(definition.code) == definition)
        || !PREFLIGHT_DIAGNOSTIC_DEFINITIONS
            .iter()
            .all(|definition| preflight_diagnostic_definition(definition.code) == definition)
    {
        return Err(ErrorReferenceValidationError::SourceCatalogMismatch);
    }
    let mut bundle_docs_slugs = BTreeSet::new();
    if BUNDLE_VERIFICATION_CODE_DEFINITIONS.len() != BundleVerificationCode::ALL.len()
        || !BundleVerificationCode::ALL.iter().all(|code| {
            let definition = code.definition();
            definition.code == *code
                && definition.lifecycle_metadata_is_valid()
                && static_metadata_is_complete(&[
                    definition.phase,
                    definition.safe_meaning,
                    definition.rule,
                    definition.safe_remediation,
                    definition.safe_report_message,
                    definition.evidence_scope,
                    definition.evidence_limitation,
                ])
                && docs_slug_is_valid(definition.docs_slug)
                && bundle_docs_slugs.insert(definition.docs_slug)
                && BUNDLE_VERIFICATION_CODE_DEFINITIONS.contains(definition)
        })
    {
        return Err(ErrorReferenceValidationError::SourceCatalogMismatch);
    }
    let relay_definitions = consultation_service_activation_definitions();
    let mut relay_docs_slugs = BTreeSet::new();
    if relay_definitions.len() != ConsultationServiceActivationCode::ALL.len()
        || !ConsultationServiceActivationCode::ALL.iter().all(|code| {
            let definition = code.definition();
            definition.code == *code
                && definition.catalog_metadata_is_valid()
                && static_metadata_is_complete(&[
                    definition.phase,
                    definition.meaning,
                    definition.rule,
                    definition.remediation,
                    definition.evidence_scope,
                    definition.evidence_policy,
                    definition.evidence_limitation,
                ])
                && docs_slug_is_valid(definition.docs_slug)
                && relay_docs_slugs.insert(definition.docs_slug)
                && relay_definitions.contains(definition)
        })
    {
        return Err(ErrorReferenceValidationError::SourceCatalogMismatch);
    }
    let mut process_startup_docs_slugs = BTreeSet::new();
    if PROCESS_STARTUP_CODE_DEFINITIONS.len() != ProcessStartupCode::ALL.len()
        || !ProcessStartupCode::ALL.iter().all(|code| {
            let definition = code.definition();
            definition.code == *code
                && definition.lifecycle_metadata_is_valid()
                && static_metadata_is_complete(&[
                    definition.phase,
                    definition.safe_meaning,
                    definition.rule,
                    definition.safe_remediation,
                    definition.evidence_scope,
                    definition.evidence_limitation,
                ])
                && docs_slug_is_valid(definition.docs_slug)
                && process_startup_docs_slugs.insert(definition.docs_slug)
                && PROCESS_STARTUP_CODE_DEFINITIONS.contains(definition)
        })
    {
        return Err(ErrorReferenceValidationError::SourceCatalogMismatch);
    }
    let mut notary_docs_slugs = BTreeSet::new();
    if NOTARY_ACTIVATION_CODE_DEFINITIONS.len() != NotaryActivationCode::ALL.len()
        || !NotaryActivationCode::ALL.iter().all(|code| {
            let definition = code.definition();
            definition.code == *code
                && notary_lifecycle_version_is_valid(definition.lifecycle)
                && static_metadata_is_complete(&[
                    definition.phase,
                    definition.meaning,
                    definition.rule,
                    definition.remediation,
                    definition.evidence_scope,
                    definition.evidence_policy,
                    definition.evidence_limitation,
                ])
                && docs_slug_is_valid(definition.docs_slug)
                && notary_docs_slugs.insert(definition.docs_slug)
                && NOTARY_ACTIVATION_CODE_DEFINITIONS.contains(definition)
        })
    {
        return Err(ErrorReferenceValidationError::SourceCatalogMismatch);
    }
    Ok(())
}

fn static_metadata_is_complete(fields: &[&str]) -> bool {
    fields.iter().all(|field| !field.trim().is_empty())
}

fn docs_slug_is_valid(slug: &str) -> bool {
    !slug.is_empty()
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn notary_lifecycle_version_is_valid(lifecycle: NotaryActivationCodeLifecycle) -> bool {
    match lifecycle {
        NotaryActivationCodeLifecycle::Unreleased => lifecycle.introduced_version().is_none(),
        NotaryActivationCodeLifecycle::Released { introduced_version } => {
            is_numeric_release_version(introduced_version)
        }
    }
}

fn lifecycle_version_is_valid(
    lifecycle: ErrorReferenceLifecycle,
    introduced_in: Option<&str>,
) -> bool {
    match lifecycle {
        ErrorReferenceLifecycle::Unreleased => introduced_in.is_none(),
        ErrorReferenceLifecycle::Active
        | ErrorReferenceLifecycle::Deprecated
        | ErrorReferenceLifecycle::Released => {
            introduced_in.is_some_and(is_numeric_release_version)
        }
    }
}

fn is_numeric_release_version(version: &str) -> bool {
    let mut parts = version.split('.');
    (0..3).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) && parts.next().is_none()
}

fn entry_key(entry: &ErrorReferenceEntry) -> (&str, &str, &str) {
    (
        entry.family.as_str(),
        entry.product.as_str(),
        entry.code.as_str(),
    )
}

fn omission_key(omission: &OperatorErrorOmission) -> (&str, &str) {
    (omission.family.as_str(), omission.product.as_str())
}

fn docs_anchor(
    family: ErrorReferenceFamily,
    product: ErrorReferenceProduct,
    fragment: &str,
) -> String {
    format!(
        "/reference/diagnostics/{}/#{}--{}",
        family.docs_catalog(),
        product.as_str(),
        fragment
    )
}

fn expected_docs_anchor(entry: &ErrorReferenceEntry) -> String {
    let source_slug = match entry.family {
        ErrorReferenceFamily::BundleVerification => BUNDLE_VERIFICATION_CODE_DEFINITIONS
            .iter()
            .find(|definition| definition.code.as_str() == entry.code)
            .map(|definition| definition.docs_slug),
        ErrorReferenceFamily::NotaryActivation => NOTARY_ACTIVATION_CODE_DEFINITIONS
            .iter()
            .find(|definition| definition.code.as_str() == entry.code)
            .map(|definition| definition.docs_slug),
        ErrorReferenceFamily::RelayActivation => consultation_service_activation_definitions()
            .iter()
            .find(|definition| definition.code.as_str() == entry.code)
            .map(|definition| definition.docs_slug),
        ErrorReferenceFamily::RelayProcessStartup => PROCESS_STARTUP_CODE_DEFINITIONS
            .iter()
            .find(|definition| definition.code.as_str() == entry.code)
            .map(|definition| definition.docs_slug),
        ErrorReferenceFamily::AuthoringValidation
        | ErrorReferenceFamily::FixtureExecution
        | ErrorReferenceFamily::OperatorPreflight => None,
    };
    docs_anchor(
        entry.family,
        entry.product,
        source_slug.unwrap_or(&entry.code),
    )
}

fn closed_string(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .expect("closed diagnostic enum serializes")
        .as_str()
        .expect("closed diagnostic enum serializes as a string")
        .to_string()
}

fn authoring_address_pattern(code: &str) -> Option<&'static str> {
    match code {
        "registryctl.authoring.diagnostics.truncated" => None,
        "registryctl.authoring.entity.invalid" => Some("<entity-file>#<field>"),
        "registryctl.authoring.environment.invalid" => Some("environments/<id>.yaml#<field>"),
        "registryctl.authoring.file.too_large"
        | "registryctl.authoring.file.unreadable"
        | "registryctl.authoring.path.unsafe" => Some("<project-relative-file>#<field>"),
        "registryctl.authoring.fixture.invalid"
        | "registryctl.authoring.fixture.reserved_body_field" => {
            Some("integrations/<id>/fixtures/<fixture>.yaml#<field>")
        }
        "registryctl.authoring.integration.invalid" => {
            Some("integrations/<id>/integration.yaml#<field>")
        }
        "registryctl.authoring.project.invalid"
        | "registryctl.authoring.project.scope_collision" => Some("registry-stack.yaml#<field>"),
        "registryctl.authoring.script.closed_contract_violation"
        | "registryctl.authoring.script.invalid_signature"
        | "registryctl.authoring.script.syntax_error"
        | "registryctl.authoring.script.unknown_function" => Some("<script-file>#<location>"),
        "registryctl.authoring.yaml.invalid_syntax"
        | "registryctl.authoring.yaml.unknown_field" => {
            Some("<project-relative-yaml-file>#<field>")
        }
        _ => unreachable!("authoring diagnostic catalog coverage is exact"),
    }
}
