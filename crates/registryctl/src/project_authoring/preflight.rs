// SPDX-License-Identifier: Apache-2.0
//! Offline-only project preflight primitives.
//!
//! This module deliberately has no network, process-launch, fixture, compiler-output, or
//! product-service dependency. The command adapter must construct [`OfflinePreflightInput`] only
//! after the existing project loader, environment validator, compiler, and linked product
//! validators have completed. That keeps their bounds and topology decisions authoritative.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub const PROJECT_PREFLIGHT_SCHEMA_VERSION_V1: &str = "registryctl.project_preflight.v1";
pub(crate) const MAX_PREFLIGHT_CHECKS: usize = 256;
pub(crate) const MAX_PREFLIGHT_DIAGNOSTICS: usize = 256;
const MAX_RUNTIME_FILE_BYTES: u64 = 1024 * 1024;
// Relay accepts source files up to 256 MiB by default. Preflight uses the same ceiling so a
// Relay-compatible country dataset is not rejected before startup while still bounding local
// metadata checks deterministically.
const MAX_ENTITY_PROVIDER_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REPORT_STRING_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum ProjectPreflightSchemaVersion {
    #[serde(rename = "registryctl.project_preflight.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Ready,
    NotReady,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightCheckState {
    Available,
    Missing,
    Empty,
    NotRegular,
    UnsafeOwner,
    UnsafeMode,
    NotChecked,
    StaticValid,
    LocallyAvailable,
}

impl PreflightCheckState {
    const fn is_success(self) -> bool {
        matches!(
            self,
            Self::Available | Self::StaticValid | Self::LocallyAvailable
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightGenerationState {
    Declared,
    NotDeclared,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStaticCapability {
    ProjectModel,
    EnvironmentCompleteness,
    OriginRelationships,
    NonWideningBounds,
}

const REQUIRED_STATIC_CAPABILITIES: [PreflightStaticCapability; 4] = [
    PreflightStaticCapability::ProjectModel,
    PreflightStaticCapability::EnvironmentCompleteness,
    PreflightStaticCapability::OriginRelationships,
    PreflightStaticCapability::NonWideningBounds,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightProduct {
    RegistryRelay,
    RegistryNotary,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightProductCapability {
    ConfigurationValidation,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightSecretConsumer {
    SourceBasicUsername,
    SourceBasicPassword,
    SourceBearerToken,
    SourceOauthClientId,
    SourceOauthClientSecret,
    SourceApiKeyValue,
    SourceMtlsPrivateKey,
    SourceOauthMtlsPrivateKey,
    SourceJwksMtlsPrivateKey,
    EntityPostgresConnection,
    IssuanceSigningKey,
    CallerApiKeyFingerprint,
    Oid4vciClientSigningKey,
    Oid4vciAccessTokenSigningKey,
    Oid4vciSensitiveStateKey,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightRuntimeFileKind {
    SourceCa,
    SourceMtlsCertificate,
    SourceOauthCa,
    SourceOauthMtlsCertificate,
    SourceJwksCa,
    SourceJwksMtlsCertificate,
    EntityCsv,
    EntityXlsx,
    EntityParquet,
    RelayStateRootCertificate,
    NotaryStateRootCertificate,
    NotaryToRelayToken,
}

impl PreflightRuntimeFileKind {
    const fn posture(self) -> RuntimeFilePosture {
        match self {
            // Entity source files can contain country-held person data, so they retain the same
            // owner-only posture as private credential material.
            Self::EntityCsv | Self::EntityXlsx | Self::EntityParquet | Self::NotaryToRelayToken => {
                RuntimeFilePosture::PrivateMaterial
            }
            Self::SourceCa
            | Self::SourceMtlsCertificate
            | Self::SourceOauthCa
            | Self::SourceOauthMtlsCertificate
            | Self::SourceJwksCa
            | Self::SourceJwksMtlsCertificate
            | Self::RelayStateRootCertificate
            | Self::NotaryStateRootCertificate => RuntimeFilePosture::PublicTrustMaterial,
        }
    }

    const fn max_bytes(self) -> u64 {
        match self {
            Self::EntityCsv | Self::EntityXlsx | Self::EntityParquet => {
                MAX_ENTITY_PROVIDER_FILE_BYTES
            }
            Self::SourceCa
            | Self::SourceMtlsCertificate
            | Self::SourceOauthCa
            | Self::SourceOauthMtlsCertificate
            | Self::SourceJwksCa
            | Self::SourceJwksMtlsCertificate
            | Self::RelayStateRootCertificate
            | Self::NotaryStateRootCertificate
            | Self::NotaryToRelayToken => MAX_RUNTIME_FILE_BYTES,
        }
    }

    const fn generation(self) -> PreflightGenerationState {
        match self {
            Self::RelayStateRootCertificate
            | Self::NotaryStateRootCertificate
            | Self::NotaryToRelayToken => PreflightGenerationState::NotDeclared,
            Self::SourceCa
            | Self::SourceMtlsCertificate
            | Self::SourceOauthCa
            | Self::SourceOauthMtlsCertificate
            | Self::SourceJwksCa
            | Self::SourceJwksMtlsCertificate
            | Self::EntityCsv
            | Self::EntityXlsx
            | Self::EntityParquet => PreflightGenerationState::Declared,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuntimeFilePosture {
    PublicTrustMaterial,
    PrivateMaterial,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightSeverity {
    Error,
    Warning,
    Information,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightPhase {
    StaticValidation,
    SecretAvailability,
    RuntimeFilePosture,
    ProductCapability,
    ReportBoundary,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum PreflightDiagnosticCode {
    #[serde(rename = "registryctl.preflight.static_validation_not_checked")]
    StaticValidationNotChecked,
    #[serde(rename = "registryctl.preflight.product_validator_not_checked")]
    ProductValidatorNotChecked,
    #[serde(rename = "registryctl.preflight.secret_missing")]
    SecretMissing,
    #[serde(rename = "registryctl.preflight.secret_empty")]
    SecretEmpty,
    #[serde(rename = "registryctl.preflight.runtime_file_missing")]
    RuntimeFileMissing,
    #[serde(rename = "registryctl.preflight.runtime_file_empty")]
    RuntimeFileEmpty,
    #[serde(rename = "registryctl.preflight.runtime_file_not_regular")]
    RuntimeFileNotRegular,
    #[serde(rename = "registryctl.preflight.runtime_file_unsafe_owner")]
    RuntimeFileUnsafeOwner,
    #[serde(rename = "registryctl.preflight.runtime_file_unsafe_mode")]
    RuntimeFileUnsafeMode,
    #[serde(rename = "registryctl.preflight.runtime_file_not_checked")]
    RuntimeFileNotChecked,
    #[serde(rename = "registryctl.preflight.report_capacity_exceeded")]
    ReportCapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum PreflightRuleId {
    #[serde(rename = "registryctl.preflight.authoritative_static_validation")]
    AuthoritativeStaticValidation,
    #[serde(rename = "registryctl.preflight.product_validator_locally_available")]
    ProductValidatorLocallyAvailable,
    #[serde(rename = "registryctl.preflight.secret_reference_available")]
    SecretReferenceAvailable,
    #[serde(rename = "registryctl.preflight.runtime_file_bounded_regular")]
    RuntimeFileBoundedRegular,
    #[serde(rename = "registryctl.preflight.runtime_file_safe_owner")]
    RuntimeFileSafeOwner,
    #[serde(rename = "registryctl.preflight.runtime_file_safe_mode")]
    RuntimeFileSafeMode,
    #[serde(rename = "registryctl.preflight.runtime_file_posture_supported")]
    RuntimeFilePostureSupported,
    #[serde(rename = "registryctl.preflight.report_capacity")]
    ReportCapacity,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum PreflightDiagnosticMessage {
    #[serde(rename = "Required authoritative static validation was not completed.")]
    StaticValidationNotCompleted,
    #[serde(rename = "A required linked product validator was not checked locally.")]
    ProductValidatorNotChecked,
    #[serde(rename = "A required secret reference is unavailable to this process.")]
    SecretMissing,
    #[serde(rename = "A required secret reference contains only whitespace.")]
    SecretEmpty,
    #[serde(rename = "A declared runtime file is missing.")]
    RuntimeFileMissing,
    #[serde(rename = "A declared runtime file is empty.")]
    RuntimeFileEmpty,
    #[serde(rename = "A declared runtime file is not an acceptable bounded regular file.")]
    RuntimeFileNotRegular,
    #[serde(rename = "A declared runtime file has an unsafe owner.")]
    RuntimeFileUnsafeOwner,
    #[serde(rename = "A declared runtime file has unsafe local access permissions.")]
    RuntimeFileUnsafeMode,
    #[serde(
        rename = "Runtime file posture could not be checked with the required local invariant."
    )]
    RuntimeFileNotChecked,
    #[serde(rename = "The preflight report reached its deterministic safety cap.")]
    ReportCapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightRemediation {
    CompleteAuthoritativeStaticValidation,
    EnableLinkedProductValidator,
    ProvideSecretToProcessEnvironment,
    ReplaceRuntimeFile,
    SetRuntimeFileOwner,
    TightenRuntimeFilePermissions,
    RunOnSupportedUnix,
    ReduceDeclaredPreflightInputs,
}

/// Registryctl-owned static metadata for one operator-preflight failure code.
///
/// Runtime reports and generated references share these closed enum members;
/// the reference aggregator consumes this table without copying its prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreflightDiagnosticDefinition {
    pub code: PreflightDiagnosticCode,
    pub phase: PreflightPhase,
    pub rule: PreflightRuleId,
    pub safe_meaning: PreflightDiagnosticMessage,
    pub safe_remediation: &'static str,
    pub field_address_pattern: Option<&'static str>,
}

macro_rules! preflight_diagnostic {
    (
        $code:ident,
        $phase:ident,
        $rule:ident,
        $meaning:ident,
        $remediation:literal,
        $address:expr
    ) => {
        PreflightDiagnosticDefinition {
            code: PreflightDiagnosticCode::$code,
            phase: PreflightPhase::$phase,
            rule: PreflightRuleId::$rule,
            safe_meaning: PreflightDiagnosticMessage::$meaning,
            safe_remediation: $remediation,
            field_address_pattern: $address,
        }
    };
}

/// Complete Registryctl operator-preflight diagnostic catalog in lexical code
/// order.
pub(crate) const PREFLIGHT_DIAGNOSTIC_DEFINITIONS: &[PreflightDiagnosticDefinition] = &[
    preflight_diagnostic!(
        ProductValidatorNotChecked,
        ProductCapability,
        ProductValidatorLocallyAvailable,
        ProductValidatorNotChecked,
        "Enable the linked product validator.",
        None
    ),
    preflight_diagnostic!(
        ReportCapacityExceeded,
        ReportBoundary,
        ReportCapacity,
        ReportCapacityExceeded,
        "Reduce declared preflight inputs.",
        None
    ),
    preflight_diagnostic!(
        RuntimeFileEmpty,
        RuntimeFilePosture,
        RuntimeFileBoundedRegular,
        RuntimeFileEmpty,
        "Replace the runtime file.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        RuntimeFileMissing,
        RuntimeFilePosture,
        RuntimeFileBoundedRegular,
        RuntimeFileMissing,
        "Replace the runtime file.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        RuntimeFileNotChecked,
        RuntimeFilePosture,
        RuntimeFilePostureSupported,
        RuntimeFileNotChecked,
        "Run preflight on a supported Unix platform.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        RuntimeFileNotRegular,
        RuntimeFilePosture,
        RuntimeFileBoundedRegular,
        RuntimeFileNotRegular,
        "Replace the runtime file.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        RuntimeFileUnsafeMode,
        RuntimeFilePosture,
        RuntimeFileSafeMode,
        RuntimeFileUnsafeMode,
        "Tighten runtime file permissions.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        RuntimeFileUnsafeOwner,
        RuntimeFilePosture,
        RuntimeFileSafeOwner,
        RuntimeFileUnsafeOwner,
        "Set the runtime file owner.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        SecretEmpty,
        SecretAvailability,
        SecretReferenceAvailable,
        SecretEmpty,
        "Provide a non-empty secret to the process environment.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        SecretMissing,
        SecretAvailability,
        SecretReferenceAvailable,
        SecretMissing,
        "Provide the secret to the process environment.",
        Some("<declared-field-address>")
    ),
    preflight_diagnostic!(
        StaticValidationNotChecked,
        StaticValidation,
        AuthoritativeStaticValidation,
        StaticValidationNotCompleted,
        "Complete authoritative static validation.",
        Some("<project-field-address>")
    ),
];

/// Return the single catalog definition for a closed preflight code.
///
/// The exhaustive match makes a newly added preflight code a compile failure
/// until its product-owned reference metadata is added.
pub(crate) const fn preflight_diagnostic_definition(
    code: PreflightDiagnosticCode,
) -> &'static PreflightDiagnosticDefinition {
    match code {
        PreflightDiagnosticCode::ProductValidatorNotChecked => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[0],
        PreflightDiagnosticCode::ReportCapacityExceeded => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[1],
        PreflightDiagnosticCode::RuntimeFileEmpty => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[2],
        PreflightDiagnosticCode::RuntimeFileMissing => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[3],
        PreflightDiagnosticCode::RuntimeFileNotChecked => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[4],
        PreflightDiagnosticCode::RuntimeFileNotRegular => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[5],
        PreflightDiagnosticCode::RuntimeFileUnsafeMode => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[6],
        PreflightDiagnosticCode::RuntimeFileUnsafeOwner => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[7],
        PreflightDiagnosticCode::SecretEmpty => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[8],
        PreflightDiagnosticCode::SecretMissing => &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[9],
        PreflightDiagnosticCode::StaticValidationNotChecked => {
            &PREFLIGHT_DIAGNOSTIC_DEFINITIONS[10]
        }
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PreflightProjectRelativeFile(String);

impl PreflightProjectRelativeFile {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, PreflightInputError> {
        let value = value.into();
        if !is_project_relative_file(&value) {
            return Err(PreflightInputError::ProjectRelativeFile);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PreflightProjectRelativeFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PreflightProjectRelativeFile")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for PreflightProjectRelativeFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PreflightProjectRelativeFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PreflightJsonPointer(String);

impl PreflightJsonPointer {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, PreflightInputError> {
        let value = value.into();
        if !is_json_pointer(&value) {
            return Err(PreflightInputError::JsonPointer);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PreflightJsonPointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PreflightJsonPointer")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for PreflightJsonPointer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PreflightJsonPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightFieldAddress {
    pub file: PreflightProjectRelativeFile,
    pub pointer: PreflightJsonPointer,
}

impl PreflightFieldAddress {
    pub(crate) fn new(
        file: impl Into<String>,
        pointer: impl Into<String>,
    ) -> Result<Self, PreflightInputError> {
        Ok(Self {
            file: PreflightProjectRelativeFile::new(file)?,
            pointer: PreflightJsonPointer::new(pointer)?,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightDiagnostic {
    pub code: PreflightDiagnosticCode,
    pub severity: PreflightSeverity,
    pub phase: PreflightPhase,
    pub addresses: Vec<PreflightFieldAddress>,
    pub rule_id: PreflightRuleId,
    pub message: PreflightDiagnosticMessage,
    pub remediation: PreflightRemediation,
}

impl PreflightDiagnostic {
    fn new(
        code: PreflightDiagnosticCode,
        phase: PreflightPhase,
        mut addresses: Vec<PreflightFieldAddress>,
        rule_id: PreflightRuleId,
        message: PreflightDiagnosticMessage,
        remediation: PreflightRemediation,
    ) -> Self {
        addresses.sort();
        addresses.dedup();
        Self {
            code,
            severity: PreflightSeverity::Error,
            phase,
            addresses,
            rule_id,
            message,
            remediation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightStaticCheck {
    pub capability: PreflightStaticCapability,
    pub addresses: Vec<PreflightFieldAddress>,
    pub state: PreflightCheckState,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightProductValidatorCheck {
    pub product: PreflightProduct,
    pub capability: PreflightProductCapability,
    pub state: PreflightCheckState,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightSecretCheck {
    pub consumers: Vec<PreflightSecretConsumer>,
    pub addresses: Vec<PreflightFieldAddress>,
    pub state: PreflightCheckState,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRuntimeFileCheck {
    pub kind: PreflightRuntimeFileKind,
    pub addresses: Vec<PreflightFieldAddress>,
    pub generation: PreflightGenerationState,
    pub state: PreflightCheckState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightMode {
    Offline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightContact {
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightAttemptState {
    NotAttempted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightWriteState {
    NotWritten,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightExecutionBoundary {
    pub mode: PreflightMode,
    pub contact: PreflightContact,
    pub network: PreflightAttemptState,
    pub live_reachability: PreflightAttemptState,
    pub fixture_execution: PreflightAttemptState,
    pub external_processes: PreflightAttemptState,
    pub build_output: PreflightWriteState,
}

impl Default for PreflightExecutionBoundary {
    fn default() -> Self {
        Self {
            mode: PreflightMode::Offline,
            contact: PreflightContact::None,
            network: PreflightAttemptState::NotAttempted,
            live_reachability: PreflightAttemptState::NotAttempted,
            fixture_execution: PreflightAttemptState::NotAttempted,
            external_processes: PreflightAttemptState::NotAttempted,
            build_output: PreflightWriteState::NotWritten,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightRuntimeScope {
    CurrentMountNamespaceAndEffectiveIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightPermissionInvariant {
    UnixOwnerAndModeEnforced,
    NotCheckedNonUnix,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRuntimeBoundary {
    pub posture_scope: PreflightRuntimeScope,
    pub permission_invariant: PreflightPermissionInvariant,
}

impl Default for PreflightRuntimeBoundary {
    fn default() -> Self {
        Self {
            posture_scope: PreflightRuntimeScope::CurrentMountNamespaceAndEffectiveIdentity,
            permission_invariant: permission_invariant(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReportLimits {
    pub max_checks: usize,
    pub max_diagnostics: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPreflightReportV1 {
    pub schema_version: ProjectPreflightSchemaVersion,
    pub status: PreflightStatus,
    pub project: String,
    pub environment: String,
    pub execution: PreflightExecutionBoundary,
    pub runtime_boundary: PreflightRuntimeBoundary,
    pub static_checks: Vec<PreflightStaticCheck>,
    pub product_validators: Vec<PreflightProductValidatorCheck>,
    pub secret_checks: Vec<PreflightSecretCheck>,
    pub runtime_files: Vec<PreflightRuntimeFileCheck>,
    pub diagnostics: Vec<PreflightDiagnostic>,
    pub limits: PreflightReportLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreflightInputError {
    Identifier,
    ProjectRelativeFile,
    JsonPointer,
    SecretReference,
    RuntimePath,
}

impl fmt::Display for PreflightInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Identifier => "preflight identifier is invalid",
            Self::ProjectRelativeFile => "preflight project-relative file is invalid",
            Self::JsonPointer => "preflight JSON pointer is invalid",
            Self::SecretReference => "preflight secret reference is invalid",
            Self::RuntimePath => "preflight runtime path is invalid",
        })
    }
}

impl std::error::Error for PreflightInputError {}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct SecretReferenceName(String);

impl SecretReferenceName {
    fn new(value: impl Into<String>) -> Result<Self, PreflightInputError> {
        let value = value.into();
        if !is_secret_reference(&value) {
            return Err(PreflightInputError::SecretReference);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SecretReferenceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-secret-reference>")
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimePath(PathBuf);

impl RuntimePath {
    fn new(value: impl Into<PathBuf>) -> Result<Self, PreflightInputError> {
        let value = value.into();
        if !is_normalized_absolute_runtime_path(&value) {
            return Err(PreflightInputError::RuntimePath);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for RuntimePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-runtime-path>")
    }
}

#[derive(Clone)]
struct SecretRequirement {
    name: SecretReferenceName,
    consumer: PreflightSecretConsumer,
    address: PreflightFieldAddress,
}

impl fmt::Debug for SecretRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRequirement")
            .field("name", &self.name)
            .field("consumer", &self.consumer)
            .field("address", &self.address)
            .finish()
    }
}

#[derive(Clone)]
struct RuntimeFileRequirement {
    path: RuntimePath,
    kind: PreflightRuntimeFileKind,
    address: PreflightFieldAddress,
}

impl fmt::Debug for RuntimeFileRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeFileRequirement")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("address", &self.address)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct OfflinePreflightInput {
    project: String,
    environment: String,
    static_checks: BTreeMap<PreflightStaticCapability, Vec<PreflightFieldAddress>>,
    required_products: BTreeSet<PreflightProduct>,
    available_product_validators: BTreeSet<PreflightProduct>,
    secrets: Vec<SecretRequirement>,
    runtime_files: Vec<RuntimeFileRequirement>,
}

impl fmt::Debug for OfflinePreflightInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflinePreflightInput")
            .field("project", &self.project)
            .field("environment", &self.environment)
            .field("static_checks", &self.static_checks)
            .field("required_products", &self.required_products)
            .field(
                "available_product_validators",
                &self.available_product_validators,
            )
            .field("secret_requirement_count", &self.secrets.len())
            .field("runtime_file_requirement_count", &self.runtime_files.len())
            .finish()
    }
}

impl OfflinePreflightInput {
    pub(crate) fn new(
        project: impl Into<String>,
        environment: impl Into<String>,
    ) -> Result<Self, PreflightInputError> {
        let project = project.into();
        let environment = environment.into();
        if !is_identifier(&project) || !is_identifier(&environment) {
            return Err(PreflightInputError::Identifier);
        }
        Ok(Self {
            project,
            environment,
            static_checks: BTreeMap::new(),
            required_products: BTreeSet::new(),
            available_product_validators: BTreeSet::new(),
            secrets: Vec::new(),
            runtime_files: Vec::new(),
        })
    }

    /// Records evidence from the existing authoritative project/environment validation path.
    ///
    /// The preflight module does not perform or substitute for that validation.
    pub(crate) fn record_static_validation(
        &mut self,
        capability: PreflightStaticCapability,
        evidence_addresses: impl IntoIterator<Item = PreflightFieldAddress>,
    ) {
        let addresses = self.static_checks.entry(capability).or_default();
        addresses.extend(evidence_addresses);
        addresses.sort();
        addresses.dedup();
    }

    pub(crate) fn require_product(&mut self, product: PreflightProduct) {
        self.required_products.insert(product);
    }

    /// Records that the command adapter reached the linked product configuration validator.
    pub(crate) fn record_product_validator_available(&mut self, product: PreflightProduct) {
        self.available_product_validators.insert(product);
    }

    pub(crate) fn add_secret_reference(
        &mut self,
        name: impl Into<String>,
        consumer: PreflightSecretConsumer,
        address: PreflightFieldAddress,
    ) -> Result<(), PreflightInputError> {
        self.secrets.push(SecretRequirement {
            name: SecretReferenceName::new(name)?,
            consumer,
            address,
        });
        Ok(())
    }

    pub(crate) fn add_runtime_file(
        &mut self,
        path: impl Into<PathBuf>,
        kind: PreflightRuntimeFileKind,
        address: PreflightFieldAddress,
    ) -> Result<(), PreflightInputError> {
        self.runtime_files.push(RuntimeFileRequirement {
            path: RuntimePath::new(path)?,
            kind,
            address,
        });
        Ok(())
    }
}

pub(crate) trait PreflightSecretLookup {
    fn get(&self, name: &str) -> Option<OsString>;
}

impl<F> PreflightSecretLookup for F
where
    F: Fn(&str) -> Option<OsString>,
{
    fn get(&self, name: &str) -> Option<OsString> {
        self(name)
    }
}

struct ProcessEnvironment;

impl PreflightSecretLookup for ProcessEnvironment {
    fn get(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

pub(crate) fn run_offline_preflight(input: OfflinePreflightInput) -> ProjectPreflightReportV1 {
    run_offline_preflight_with_secret_lookup(input, &ProcessEnvironment)
}

pub(crate) fn run_offline_preflight_with_secret_lookup(
    input: OfflinePreflightInput,
    secrets: &impl PreflightSecretLookup,
) -> ProjectPreflightReportV1 {
    let root_address = PreflightFieldAddress::new("registry-stack.yaml", "")
        .expect("the fixed preflight root address is valid");
    let mut diagnostics = Vec::new();
    let mut truncated = false;

    let static_checks = REQUIRED_STATIC_CAPABILITIES
        .into_iter()
        .filter_map(|capability| {
            if let Some(addresses) = input
                .static_checks
                .get(&capability)
                .filter(|addresses| !addresses.is_empty())
            {
                Some(PreflightStaticCheck {
                    capability,
                    addresses: sorted_addresses(addresses.clone()),
                    state: PreflightCheckState::StaticValid,
                })
            } else {
                diagnostics.push(PreflightDiagnostic::new(
                    PreflightDiagnosticCode::StaticValidationNotChecked,
                    PreflightPhase::StaticValidation,
                    vec![root_address.clone()],
                    PreflightRuleId::AuthoritativeStaticValidation,
                    PreflightDiagnosticMessage::StaticValidationNotCompleted,
                    PreflightRemediation::CompleteAuthoritativeStaticValidation,
                ));
                None
            }
        })
        .collect::<Vec<_>>();

    let product_validators = input
        .required_products
        .iter()
        .copied()
        .map(|product| {
            let state = if input.available_product_validators.contains(&product) {
                PreflightCheckState::LocallyAvailable
            } else {
                diagnostics.push(PreflightDiagnostic::new(
                    PreflightDiagnosticCode::ProductValidatorNotChecked,
                    PreflightPhase::ProductCapability,
                    vec![root_address.clone()],
                    PreflightRuleId::ProductValidatorLocallyAvailable,
                    PreflightDiagnosticMessage::ProductValidatorNotChecked,
                    PreflightRemediation::EnableLinkedProductValidator,
                ));
                PreflightCheckState::NotChecked
            };
            PreflightProductValidatorCheck {
                product,
                capability: PreflightProductCapability::ConfigurationValidation,
                state,
            }
        })
        .collect::<Vec<_>>();

    let (secret_checks, secret_truncated) =
        collect_secret_checks(input.secrets, secrets, &mut diagnostics);
    truncated |= secret_truncated;
    let (runtime_files, runtime_truncated) =
        collect_runtime_file_checks(input.runtime_files, &mut diagnostics);
    truncated |= runtime_truncated;

    diagnostics.sort();
    diagnostics.dedup();
    if diagnostics.len() > MAX_PREFLIGHT_DIAGNOSTICS {
        diagnostics.truncate(MAX_PREFLIGHT_DIAGNOSTICS - 1);
        truncated = true;
    }
    if truncated {
        let capacity_diagnostic = PreflightDiagnostic::new(
            PreflightDiagnosticCode::ReportCapacityExceeded,
            PreflightPhase::ReportBoundary,
            vec![root_address],
            PreflightRuleId::ReportCapacity,
            PreflightDiagnosticMessage::ReportCapacityExceeded,
            PreflightRemediation::ReduceDeclaredPreflightInputs,
        );
        if diagnostics.len() == MAX_PREFLIGHT_DIAGNOSTICS {
            diagnostics.truncate(MAX_PREFLIGHT_DIAGNOSTICS - 1);
        }
        diagnostics.push(capacity_diagnostic);
    }

    let checks_succeed = static_checks.len() == REQUIRED_STATIC_CAPABILITIES.len()
        && product_validators
            .iter()
            .all(|check| check.state.is_success())
        && secret_checks.iter().all(|check| check.state.is_success())
        && runtime_files.iter().all(|check| check.state.is_success());
    let status = if checks_succeed && diagnostics.is_empty() && !truncated {
        PreflightStatus::Ready
    } else {
        PreflightStatus::NotReady
    };

    ProjectPreflightReportV1 {
        schema_version: ProjectPreflightSchemaVersion::V1,
        status,
        project: input.project,
        environment: input.environment,
        execution: PreflightExecutionBoundary::default(),
        runtime_boundary: PreflightRuntimeBoundary::default(),
        static_checks,
        product_validators,
        secret_checks,
        runtime_files,
        diagnostics,
        limits: PreflightReportLimits {
            max_checks: MAX_PREFLIGHT_CHECKS,
            max_diagnostics: MAX_PREFLIGHT_DIAGNOSTICS,
            truncated,
        },
    }
}

#[derive(Default)]
struct GroupedSecret {
    consumers: BTreeSet<PreflightSecretConsumer>,
    addresses: BTreeSet<PreflightFieldAddress>,
}

fn collect_secret_checks(
    requirements: Vec<SecretRequirement>,
    lookup: &impl PreflightSecretLookup,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) -> (Vec<PreflightSecretCheck>, bool) {
    let mut grouped = BTreeMap::<SecretReferenceName, GroupedSecret>::new();
    for requirement in requirements {
        let entry = grouped.entry(requirement.name).or_default();
        entry.consumers.insert(requirement.consumer);
        entry.addresses.insert(requirement.address);
    }
    let mut grouped = grouped.into_iter().collect::<Vec<_>>();
    grouped.sort_by(|left, right| {
        left.1
            .addresses
            .cmp(&right.1.addresses)
            .then_with(|| left.1.consumers.cmp(&right.1.consumers))
    });
    let truncated = grouped.len() > MAX_PREFLIGHT_CHECKS;
    grouped.truncate(MAX_PREFLIGHT_CHECKS);

    let mut checks = Vec::with_capacity(grouped.len());
    for (name, grouped) in grouped {
        let state = match lookup.get(&name.0) {
            None => PreflightCheckState::Missing,
            Some(value) if os_string_is_whitespace(&value) => PreflightCheckState::Empty,
            Some(_) => PreflightCheckState::Available,
        };
        let consumers = grouped.consumers.into_iter().collect::<Vec<_>>();
        let addresses = grouped.addresses.into_iter().collect::<Vec<_>>();
        match state {
            PreflightCheckState::Missing => diagnostics.push(PreflightDiagnostic::new(
                PreflightDiagnosticCode::SecretMissing,
                PreflightPhase::SecretAvailability,
                addresses.clone(),
                PreflightRuleId::SecretReferenceAvailable,
                PreflightDiagnosticMessage::SecretMissing,
                PreflightRemediation::ProvideSecretToProcessEnvironment,
            )),
            PreflightCheckState::Empty => diagnostics.push(PreflightDiagnostic::new(
                PreflightDiagnosticCode::SecretEmpty,
                PreflightPhase::SecretAvailability,
                addresses.clone(),
                PreflightRuleId::SecretReferenceAvailable,
                PreflightDiagnosticMessage::SecretEmpty,
                PreflightRemediation::ProvideSecretToProcessEnvironment,
            )),
            PreflightCheckState::Available => {}
            _ => unreachable!("secret availability has a closed state mapping"),
        }
        checks.push(PreflightSecretCheck {
            consumers,
            addresses,
            state,
        });
    }
    checks.sort_by(|left, right| {
        left.addresses
            .cmp(&right.addresses)
            .then_with(|| left.consumers.cmp(&right.consumers))
    });
    (checks, truncated)
}

#[derive(Default)]
struct GroupedRuntimeFile {
    addresses: BTreeSet<PreflightFieldAddress>,
}

fn collect_runtime_file_checks(
    requirements: Vec<RuntimeFileRequirement>,
    diagnostics: &mut Vec<PreflightDiagnostic>,
) -> (Vec<PreflightRuntimeFileCheck>, bool) {
    let mut grouped =
        BTreeMap::<(RuntimePath, PreflightRuntimeFileKind), GroupedRuntimeFile>::new();
    for requirement in requirements {
        grouped
            .entry((requirement.path, requirement.kind))
            .or_default()
            .addresses
            .insert(requirement.address);
    }
    let mut grouped = grouped.into_iter().collect::<Vec<_>>();
    grouped.sort_by(
        |((_, left_kind), left_group), ((_, right_kind), right_group)| {
            left_kind
                .cmp(right_kind)
                .then_with(|| left_group.addresses.cmp(&right_group.addresses))
        },
    );
    let truncated = grouped.len() > MAX_PREFLIGHT_CHECKS;
    grouped.truncate(MAX_PREFLIGHT_CHECKS);

    let mut inspection_cache =
        BTreeMap::<(RuntimePath, RuntimeFilePosture, u64), PreflightCheckState>::new();
    let mut checks = Vec::with_capacity(grouped.len());
    for ((path, kind), grouped) in grouped {
        let posture = kind.posture();
        let max_bytes = kind.max_bytes();
        let state = *inspection_cache
            .entry((path.clone(), posture, max_bytes))
            .or_insert_with(|| inspect_runtime_file(&path.0, posture, max_bytes));
        let addresses = grouped.addresses.into_iter().collect::<Vec<_>>();
        if let Some(diagnostic) = runtime_file_diagnostic(state, addresses.clone()) {
            diagnostics.push(diagnostic);
        }
        checks.push(PreflightRuntimeFileCheck {
            kind,
            addresses,
            generation: kind.generation(),
            state,
        });
    }
    checks.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.addresses.cmp(&right.addresses))
    });
    (checks, truncated)
}

fn runtime_file_diagnostic(
    state: PreflightCheckState,
    addresses: Vec<PreflightFieldAddress>,
) -> Option<PreflightDiagnostic> {
    let fields = match state {
        PreflightCheckState::Available => return None,
        PreflightCheckState::Missing => (
            PreflightDiagnosticCode::RuntimeFileMissing,
            PreflightRuleId::RuntimeFileBoundedRegular,
            PreflightDiagnosticMessage::RuntimeFileMissing,
            PreflightRemediation::ReplaceRuntimeFile,
        ),
        PreflightCheckState::Empty => (
            PreflightDiagnosticCode::RuntimeFileEmpty,
            PreflightRuleId::RuntimeFileBoundedRegular,
            PreflightDiagnosticMessage::RuntimeFileEmpty,
            PreflightRemediation::ReplaceRuntimeFile,
        ),
        PreflightCheckState::NotRegular => (
            PreflightDiagnosticCode::RuntimeFileNotRegular,
            PreflightRuleId::RuntimeFileBoundedRegular,
            PreflightDiagnosticMessage::RuntimeFileNotRegular,
            PreflightRemediation::ReplaceRuntimeFile,
        ),
        PreflightCheckState::UnsafeOwner => (
            PreflightDiagnosticCode::RuntimeFileUnsafeOwner,
            PreflightRuleId::RuntimeFileSafeOwner,
            PreflightDiagnosticMessage::RuntimeFileUnsafeOwner,
            PreflightRemediation::SetRuntimeFileOwner,
        ),
        PreflightCheckState::UnsafeMode => (
            PreflightDiagnosticCode::RuntimeFileUnsafeMode,
            PreflightRuleId::RuntimeFileSafeMode,
            PreflightDiagnosticMessage::RuntimeFileUnsafeMode,
            PreflightRemediation::TightenRuntimeFilePermissions,
        ),
        PreflightCheckState::NotChecked => (
            PreflightDiagnosticCode::RuntimeFileNotChecked,
            PreflightRuleId::RuntimeFilePostureSupported,
            PreflightDiagnosticMessage::RuntimeFileNotChecked,
            PreflightRemediation::RunOnSupportedUnix,
        ),
        PreflightCheckState::StaticValid | PreflightCheckState::LocallyAvailable => {
            unreachable!("runtime files have a closed posture state mapping")
        }
    };
    Some(PreflightDiagnostic::new(
        fields.0,
        PreflightPhase::RuntimeFilePosture,
        addresses,
        fields.1,
        fields.2,
        fields.3,
    ))
}

#[cfg(unix)]
fn inspect_runtime_file(
    path: &Path,
    posture: RuntimeFilePosture,
    max_bytes: u64,
) -> PreflightCheckState {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return PreflightCheckState::Missing;
        }
        Err(_) => return PreflightCheckState::NotChecked,
    };
    if before.file_type().is_symlink() || !before.is_file() {
        return PreflightCheckState::NotRegular;
    }

    let descriptor = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let error = std::io::Error::from(error);
            return if error.kind() == std::io::ErrorKind::NotFound {
                PreflightCheckState::Missing
            } else {
                PreflightCheckState::NotChecked
            };
        }
    };
    let file = fs::File::from(descriptor);
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return PreflightCheckState::NotChecked,
    };
    if !metadata.is_file() {
        return PreflightCheckState::NotRegular;
    }
    if before.dev() != metadata.dev() || before.ino() != metadata.ino() {
        return PreflightCheckState::NotChecked;
    }
    if metadata.len() == 0 {
        return PreflightCheckState::Empty;
    }
    if metadata.len() > max_bytes {
        return PreflightCheckState::NotRegular;
    }

    let owner = metadata.uid();
    let effective_user = rustix::process::geteuid().as_raw();
    if owner != 0 && owner != effective_user {
        return PreflightCheckState::UnsafeOwner;
    }
    let unsafe_bits = match posture {
        RuntimeFilePosture::PublicTrustMaterial => 0o022,
        RuntimeFilePosture::PrivateMaterial => 0o077,
    };
    if metadata.mode() & unsafe_bits != 0 {
        return PreflightCheckState::UnsafeMode;
    }
    PreflightCheckState::Available
}

#[cfg(not(unix))]
fn inspect_runtime_file(
    _path: &Path,
    _posture: RuntimeFilePosture,
    _max_bytes: u64,
) -> PreflightCheckState {
    // The Unix ownership and access-bit invariant cannot be proved portably. Do not silently
    // weaken it or report a pass on another platform.
    PreflightCheckState::NotChecked
}

#[cfg(unix)]
const fn permission_invariant() -> PreflightPermissionInvariant {
    PreflightPermissionInvariant::UnixOwnerAndModeEnforced
}

#[cfg(not(unix))]
const fn permission_invariant() -> PreflightPermissionInvariant {
    PreflightPermissionInvariant::NotCheckedNonUnix
}

fn sorted_addresses(mut addresses: Vec<PreflightFieldAddress>) -> Vec<PreflightFieldAddress> {
    addresses.sort();
    addresses.dedup();
    addresses
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphanumeric())
        && value.len() <= 96
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_project_relative_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPORT_STRING_BYTES
        && !value.starts_with('/')
        && !value.contains('\\')
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn is_json_pointer(value: &str) -> bool {
    if value.len() > MAX_REPORT_STRING_BYTES
        || (!value.is_empty() && !value.starts_with('/'))
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

fn is_secret_reference(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first == b'_' || first.is_ascii_uppercase())
        && value.len() <= 128
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_normalized_absolute_runtime_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.len() < 2
        || value.len() > MAX_REPORT_STRING_BYTES
        || !value.starts_with('/')
        || value.contains("//")
    {
        return false;
    }
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && components.all(|component| matches!(component, Component::Normal(_)))
}

fn os_string_is_whitespace(value: &OsStr) -> bool {
    if value.is_empty() {
        return true;
    }
    match value.to_str() {
        Some(value) => value.chars().all(char::is_whitespace),
        None => os_string_bytes_are_ascii_whitespace(value),
    }
}

#[cfg(unix)]
fn os_string_bytes_are_ascii_whitespace(value: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    value.as_bytes().iter().all(u8::is_ascii_whitespace)
}

#[cfg(not(unix))]
fn os_string_bytes_are_ascii_whitespace(_value: &OsStr) -> bool {
    false
}
