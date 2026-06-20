//! Shared configuration report contracts for Registry products and local tools.
//!
//! Products own their runtime configuration models and validation rules. This
//! crate owns only the report envelopes, schema assets, shared vocabulary, and
//! redaction helpers used when those product-owned decisions are reported.

use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RequiredEnvVar {
    pub name: String,
    pub classification: ConfigValueClassification,
    pub status: RequiredEnvStatus,
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigDiagnosticReport {
    pub schema_version: String,
    pub product: String,
    pub config_schema_version: String,
    pub source: ConfigSourceRef,
    pub status: ReportStatus,
    pub summary: DiagnosticSummary,
    pub diagnostics: Vec<ConfigDiagnostic>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_env: Vec<RequiredEnvVar>,
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigExplanation {
    pub schema_version: String,
    pub product: String,
    pub config_schema_version: String,
    pub source: ConfigSourceRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_env: Vec<RequiredEnvVar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub defaults_applied: Vec<ConfigDefault>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_sections_absent: Vec<OptionalSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_apply: Vec<LiveApplyComponent>,
    pub resolved_config: Value,
    #[serde(skip_serializing_if = "config_hashes_option_is_empty")]
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
