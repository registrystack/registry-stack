//! Shared configuration report contracts for Registry products and local tools.
//!
//! Products own their runtime configuration models and validation rules. This
//! crate owns only the report envelopes, schema assets, shared vocabulary, and
//! redaction helpers used when those product-owned decisions are reported.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const PRODUCT_DIAGNOSTIC_REPORT_SCHEMA_V1: &str =
    include_str!("../schemas/registry.config.diagnostic_report.v1.schema.json");

pub const CONFIG_EXPLANATION_SCHEMA_V1: &str =
    include_str!("../schemas/registry.config.explanation.v1.schema.json");

pub const REGISTRYCTL_VALIDATION_REPORT_SCHEMA_V1: &str =
    include_str!("../schemas/registryctl.validation.report.v1.schema.json");

pub const RELAY_DIAGNOSTIC_OK_FIXTURE_V1: &str =
    include_str!("../fixtures/diagnostics/registry-relay.ok.json");

pub const RELAY_DIAGNOSTIC_ERROR_FIXTURE_V1: &str =
    include_str!("../fixtures/diagnostics/registry-relay.error.json");

pub const NOTARY_DIAGNOSTIC_OK_FIXTURE_V1: &str =
    include_str!("../fixtures/diagnostics/registry-notary.ok.json");

pub const NOTARY_DIAGNOSTIC_ERROR_FIXTURE_V1: &str =
    include_str!("../fixtures/diagnostics/registry-notary.error.json");

pub const CONFIG_EXPLANATION_FIXTURE_V1: &str =
    include_str!("../fixtures/explanations/registry-relay.explanation.json");

pub const REGISTRYCTL_VALIDATION_FIXTURE_V1: &str =
    include_str!("../fixtures/registryctl/registryctl.validation.error.json");

pub const REDACTION_INPUT_FIXTURE_V1: &str =
    include_str!("../fixtures/diagnostics/redaction-input.json");

pub const CONTEXT_CONSTRAINTS_REPORT_CONTRACT_V1: &str =
    "registry.config_report.context_constraints.v1";
pub const PLATFORM_CONTEXT_CONSTRAINTS_CONTRACT_V1: &str =
    "registry-platform-pdp.context_constraints.v1";
pub const PLATFORM_CONTEXT_CONSTRAINTS_HASH_MATERIAL_CONTRACT_V1: &str =
    "registry-platform-pdp.context_constraints.hash_material.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReportStatus {
    Ok,
    Warning,
    Error,
    NotRun,
}

impl ReportStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::NotRun => "not_run",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl DiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfigSourceKind {
    LocalFile,
    GeneratedFile,
    SignedBundleFile,
    SignedBundleEndpoint,
    Unknown,
}

impl ConfigSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalFile => "local_file",
            Self::GeneratedFile => "generated_file",
            Self::SignedBundleFile => "signed_bundle_file",
            Self::SignedBundleEndpoint => "signed_bundle_endpoint",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfigValueClassification {
    Public,
    Secret,
    TopologySensitive,
    InternalOnly,
}

impl ConfigValueClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Secret => "secret",
            Self::TopologySensitive => "topology_sensitive",
            Self::InternalOnly => "internal_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequiredEnvStatus {
    Present,
    Missing,
    NotChecked,
}

impl RequiredEnvStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::NotChecked => "not_checked",
        }
    }
}

fn config_hashes_option_is_empty(hashes: &Option<ConfigHashes>) -> bool {
    hashes.as_ref().is_none_or(ConfigHashes::is_empty)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LiveApplyClass {
    HotSwappable,
    RestartRequired,
    UnsupportedLiveApply,
}

impl LiveApplyClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HotSwappable => "hot_swappable",
            Self::RestartRequired => "restart_required",
            Self::UnsupportedLiveApply => "unsupported_live_apply",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigSourceRef {
    pub kind: ConfigSourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct DiagnosticSummary {
    pub error_count: u64,
    pub warning_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_key: Option<String>,
}

/// A required environment variable, its data classification, and presence.
///
/// # Operator-sensitive
///
/// This type is OPERATOR-SENSITIVE. It enumerates the *names* of secret- and
/// internal-only-classified environment variables and whether each one is set.
/// Disclosing these names and their presence can reveal which secrets a
/// deployment expects and aid an attacker. It MUST only be exposed behind
/// operator authentication and MUST NEVER appear on an unauthenticated or
/// otherwise public diagnostic surface.
///
/// For a ready-made public-safe list projection, use
/// [`RequiredEnvVar::public_safe_entries`], which omits sensitive entries
/// entirely so names, presence, and counts are not disclosed.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RequiredEnvVar {
    pub name: String,
    pub classification: ConfigValueClassification,
    pub status: RequiredEnvStatus,
}

impl RequiredEnvVar {
    /// Returns a compatibility-safe projection of this single entry.
    ///
    /// `Public` entries are returned as-is. Non-public entries are collapsed to
    /// one generic, not-checked placeholder so names, classifications, and
    /// presence state do not leak from a single-entry projection.
    ///
    /// For lists, prefer [`Self::public_safe_entries`] so non-public entry counts
    /// do not leak either.
    #[must_use]
    pub fn public_safe(&self) -> Self {
        match self.classification {
            ConfigValueClassification::Public => self.clone(),
            ConfigValueClassification::Secret
            | ConfigValueClassification::TopologySensitive
            | ConfigValueClassification::InternalOnly => Self {
                name: REDACTED_VALUE.to_string(),
                classification: ConfigValueClassification::Public,
                status: RequiredEnvStatus::NotChecked,
            },
        }
    }

    /// Returns only entries suitable for a public diagnostic surface.
    ///
    /// Non-public entries are omitted so their names, classifications, presence
    /// state, and list cardinality do not leak.
    #[must_use]
    pub fn public_safe_entries(entries: &[Self]) -> Vec<Self> {
        entries
            .iter()
            .filter(|entry| entry.classification == ConfigValueClassification::Public)
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigHashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_config_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture_safe_config_hash: Option<String>,
}

impl ConfigHashes {
    pub fn is_empty(&self) -> bool {
        self.internal_config_hash.is_none() && self.posture_safe_config_hash.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TrustedValueSource {
    StaticCredentialAuthorizationDetails,
    OidcAuthorizationDetails,
    FederationAuthorizationDetails,
    PrincipalScope,
    RouteDefault,
    SourceObservationTimestamp,
    AdapterInjectedObservationTimestamp,
    NotConfigured,
    Unknown,
}

impl TrustedValueSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticCredentialAuthorizationDetails => "static_credential_authorization_details",
            Self::OidcAuthorizationDetails => "oidc_authorization_details",
            Self::FederationAuthorizationDetails => "federation_authorization_details",
            Self::PrincipalScope => "principal_scope",
            Self::RouteDefault => "route_default",
            Self::SourceObservationTimestamp => "source_observation_timestamp",
            Self::AdapterInjectedObservationTimestamp => "adapter_injected_observation_timestamp",
            Self::NotConfigured => "not_configured",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContextConstraintLegalBasisReport {
    pub required: bool,
    pub approved_value_check: bool,
    pub allowed_ref_count: u64,
    pub trusted_value_source: TrustedValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContextConstraintConsentReport {
    pub required: bool,
    pub approved_value_check: bool,
    pub allowed_ref_count: u64,
    pub trusted_value_source: TrustedValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContextConstraintJurisdictionReport {
    pub permitted_count: u64,
    pub trusted_value_source: TrustedValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContextConstraintAssuranceReport {
    pub allowed_count: u64,
    pub minimum: Option<String>,
    pub trusted_value_source: TrustedValueSource,
    pub authn_derived: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContextConstraintSourceFreshnessReport {
    pub max_age_seconds: Option<u64>,
    pub observation_field: Option<String>,
    pub observation_timestamp_source: TrustedValueSource,
    pub observation_contract_proven: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ContextConstraintsReportEntry {
    pub container_path: String,
    pub product: String,
    pub platform_contract: String,
    pub hash_material_contract: String,
    pub legal_basis: ContextConstraintLegalBasisReport,
    pub consent: ContextConstraintConsentReport,
    pub jurisdiction: ContextConstraintJurisdictionReport,
    pub assurance: ContextConstraintAssuranceReport,
    pub source_freshness: ContextConstraintSourceFreshnessReport,
    pub product_owned_adjacent_controls: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigDiagnosticReport {
    pub schema_version: String,
    pub product: String,
    pub config_schema_version: String,
    pub source: ConfigSourceRef,
    pub status: ReportStatus,
    pub summary: DiagnosticSummary,
    pub diagnostics: Vec<ConfigDiagnostic>,
    /// Operator-sensitive: see [`RequiredEnvVar`]. Enumerates secret env-var
    /// names and presence; must only be exposed behind operator authentication.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_env: Vec<RequiredEnvVar>,
    #[serde(default)]
    pub context_constraints: Vec<ContextConstraintsReportEntry>,
    #[serde(skip_serializing_if = "config_hashes_option_is_empty")]
    pub hashes: Option<ConfigHashes>,
    pub generated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigDefault {
    pub path: String,
    pub value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct OptionalSection {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LiveApplyComponent {
    pub path: String,
    pub class: LiveApplyClass,
}

/// A configuration tree that is guaranteed to have passed through redaction.
///
/// This newtype makes redaction unbypassable at the type level: the only way to
/// build a populated `RedactedConfig` from a raw [`Value`] in producing code is
/// [`RedactedConfig::redacted`], which runs [`redact_config_value`] internally.
/// There is intentionally no public constructor that wraps an arbitrary
/// `Value` without redacting.
///
/// The wire representation is identical to a bare `Value` (see
/// `#[serde(transparent)]`). Deserializing this producer-side type treats the
/// incoming tree as untrusted and collapses it to [`REDACTED_VALUE`]; code that
/// needs to inspect an already-rendered report should use
/// [`ConfigExplanationDocument`], whose `resolved_config` is a plain [`Value`]
/// and carries no producer-side redaction guarantee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RedactedConfig(Value);

impl<'de> Deserialize<'de> for RedactedConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(Self(redact_config_value(&value, |_, _| {
            ConfigValueClassification::Secret
        })))
    }
}

impl RedactedConfig {
    /// Redacts `value` with `classify` and wraps the result.
    ///
    /// This is the only constructor that accepts a raw config tree, ensuring a
    /// populated `RedactedConfig` can never hold un-redacted secrets.
    pub fn redacted(
        value: &Value,
        classify: impl Fn(&[&str], &Value) -> ConfigValueClassification,
    ) -> Self {
        Self(redact_config_value(value, classify))
    }

    /// Borrows the redacted configuration tree.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consumes the newtype, returning the redacted configuration tree.
    pub fn into_value(self) -> Value {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigExplanation {
    pub schema_version: String,
    pub product: String,
    pub config_schema_version: String,
    pub source: ConfigSourceRef,
    /// Operator-sensitive: see [`RequiredEnvVar`]. Enumerates secret env-var
    /// names and presence; must only be exposed behind operator authentication.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_env: Vec<RequiredEnvVar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub defaults_applied: Vec<ConfigDefault>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_sections_absent: Vec<OptionalSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_apply: Vec<LiveApplyComponent>,
    #[serde(default)]
    pub context_constraints: Vec<ContextConstraintsReportEntry>,
    pub resolved_config: RedactedConfig,
    #[serde(skip_serializing_if = "config_hashes_option_is_empty")]
    pub hashes: Option<ConfigHashes>,
    pub generated_at: String,
}

/// Deserialize-only wire view of a rendered [`ConfigExplanation`].
///
/// Use this type when deserializing report JSON. It preserves the schema and
/// wire format but does not claim that its `resolved_config` was produced by
/// [`RedactedConfig::redacted`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct ConfigExplanationDocument {
    pub schema_version: String,
    pub product: String,
    pub config_schema_version: String,
    pub source: ConfigSourceRef,
    #[serde(default)]
    pub required_env: Vec<RequiredEnvVar>,
    #[serde(default)]
    pub defaults_applied: Vec<ConfigDefault>,
    #[serde(default)]
    pub optional_sections_absent: Vec<OptionalSection>,
    #[serde(default)]
    pub live_apply: Vec<LiveApplyComponent>,
    #[serde(default)]
    pub context_constraints: Vec<ContextConstraintsReportEntry>,
    pub resolved_config: Value,
    pub hashes: Option<ConfigHashes>,
    pub generated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RegistryctlProjectRef {
    pub path: String,
    pub profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RegistryctlProductReport {
    pub product: String,
    pub status: ReportStatus,
    pub report: ConfigDiagnosticReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RegistryctlValidationReport {
    pub schema_version: String,
    pub project: RegistryctlProjectRef,
    pub status: ReportStatus,
    pub products: Vec<RegistryctlProductReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_product_diagnostics: Vec<ConfigDiagnostic>,
    pub generated_at: String,
}

pub fn redact_config_value(
    value: &Value,
    classify: impl Fn(&[&str], &Value) -> ConfigValueClassification,
) -> Value {
    let mut path = [""; REDACTION_PATH_STACK_LIMIT];
    redact_config_value_at(value, &mut path, 0, &classify)
}

fn redact_config_value_at<'a>(
    value: &'a Value,
    path: &mut [&'a str],
    depth: usize,
    classify: &impl Fn(&[&str], &Value) -> ConfigValueClassification,
) -> Value {
    if classify(&path[..depth], value) != ConfigValueClassification::Public {
        return Value::String(REDACTED_VALUE.to_string());
    }

    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_child(item, path, depth, "*", classify))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| (key.clone(), redact_child(child, path, depth, key, classify)))
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn redact_child<'a>(
    value: &'a Value,
    path: &mut [&'a str],
    depth: usize,
    segment: &'a str,
    classify: &impl Fn(&[&str], &Value) -> ConfigValueClassification,
) -> Value {
    if depth < path.len() {
        path[depth] = segment;
        redact_config_value_at(value, path, depth + 1, classify)
    } else {
        let mut overflow_path = Vec::with_capacity(path.len() + 16);
        overflow_path.extend_from_slice(path);
        overflow_path.push(segment);
        redact_config_value_overflow(value, &mut overflow_path, classify)
    }
}

fn redact_config_value_overflow<'a>(
    value: &'a Value,
    path: &mut Vec<&'a str>,
    classify: &impl Fn(&[&str], &Value) -> ConfigValueClassification,
) -> Value {
    if classify(path, value) != ConfigValueClassification::Public {
        return Value::String(REDACTED_VALUE.to_string());
    }

    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| {
                    path.push("*");
                    let redacted = redact_config_value_overflow(item, path, classify);
                    path.pop();
                    redacted
                })
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| {
                    path.push(key);
                    let redacted = redact_config_value_overflow(child, path, classify);
                    path.pop();
                    (key.clone(), redacted)
                })
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

pub const REDACTED_VALUE: &str = "[redacted]";

const REDACTION_PATH_STACK_LIMIT: usize = 64;
