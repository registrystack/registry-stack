//! Public operations contract assets shared by Registry runtimes.
//!
//! Relay and Notary own route wiring, authorization, and local posture
//! collection. This crate owns the shared public contract and the emit-only
//! sensitivity-tier filter used before posture leaves a runtime.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Write as _};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use registry_platform_crypto::canonicalize_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const POSTURE_SCHEMA_V1: &str = include_str!("../schemas/registry.ops.posture.v1.schema.json");

pub const ADMIN_ERROR_SCHEMA_V1: &str =
    include_str!("../schemas/registry.admin.error.v1.schema.json");

pub const ADMIN_CAPABILITIES_SCHEMA_V1: &str =
    include_str!("../schemas/registry.admin.capabilities.v1.schema.json");

pub const CONFIG_APPLY_REPORT_SCHEMA_V1: &str =
    include_str!("../schemas/registry.platform.config_apply_report.v1.schema.json");

pub const RELAY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-relay.posture.valid.json");

pub const NOTARY_POSTURE_EXAMPLE_V1: &str =
    include_str!("../examples/registry-notary.posture.valid.json");

pub const DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-allowlist.json");

pub const REDACTION_INPUT_SENSITIVE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/redaction-input-sensitive.json");

pub const DEFAULT_REDACTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/default-redacted.posture.valid.json");

pub const RESTRICTED_POSTURE_FIXTURE_V1: &str =
    include_str!("../fixtures/posture/restricted-posture.valid.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeploymentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

impl DeploymentProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::HostedLab => "hosted_lab",
            Self::Production => "production",
            Self::EvidenceGrade => "evidence_grade",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GateSeverity {
    StartupFail,
    ReadinessFail,
    FindingError,
    FindingWarn,
}

impl GateSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartupFail => "startup_fail",
            Self::ReadinessFail => "readiness_fail",
            Self::FindingError => "finding_error",
            Self::FindingWarn => "finding_warn",
        }
    }

    /// Whether an operator waiver can suppress this severity's runtime effect.
    ///
    /// Startup and readiness failures are hard profile gates: `startup_fail`
    /// means running would falsify the declared profile, and `readiness_fail`
    /// means the process may run but must not report ready.
    pub const fn is_waivable(self) -> bool {
        matches!(self, Self::FindingError | Self::FindingWarn)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeploymentFindingStatus {
    Active,
    Waived,
}

impl DeploymentFindingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Waived => "waived",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct DeploymentFindingWaiver {
    pub reason: String,
    pub expires: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct DeploymentFinding {
    pub id: String,
    pub severity: GateSeverity,
    pub status: DeploymentFindingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiver: Option<DeploymentFindingWaiver>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct DeploymentWaiver {
    pub finding: String,
    pub reason: String,
    pub expires: String,
}

/// Finding id emitted when no deployment profile is declared.
pub const PROFILE_UNDECLARED_FINDING_ID: &str = "deployment.profile_undeclared";

/// Finding id emitted for each expired deployment waiver.
pub const WAIVER_EXPIRED_FINDING_ID: &str = "deployment.waiver_expired";

/// Per-profile severities for one product-owned gate.
///
/// `None` means the gate does not bind to that profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProfileGateSeverities {
    pub local: Option<GateSeverity>,
    pub hosted_lab: Option<GateSeverity>,
    pub production: Option<GateSeverity>,
    pub evidence_grade: Option<GateSeverity>,
}

impl ProfileGateSeverities {
    pub const fn severity_for(self, profile: DeploymentProfile) -> Option<GateSeverity> {
        match profile {
            DeploymentProfile::Local => self.local,
            DeploymentProfile::HostedLab => self.hosted_lab,
            DeploymentProfile::Production => self.production,
            DeploymentProfile::EvidenceGrade => self.evidence_grade,
        }
    }
}

/// One row in a product-owned deployment gate catalog.
///
/// Products keep their own facts projection and catalog. Platform owns the
/// shared evaluation rules, severity vocabulary, waiver expiry handling, and
/// undeclared-profile diagnostic.
#[derive(Clone, Copy, Debug)]
pub struct Gate<I> {
    pub id: &'static str,
    pub condition: fn(&I) -> bool,
    pub severities: ProfileGateSeverities,
}

impl<I> Gate<I> {
    pub const fn severity_for(&self, profile: DeploymentProfile) -> Option<GateSeverity> {
        self.severities.severity_for(profile)
    }
}

/// Outcome of evaluating a product catalog against one profile.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GateEvaluation {
    /// Findings to render into posture, in catalog order followed by framework
    /// findings such as expired waivers.
    pub findings: Vec<DeploymentFinding>,
    /// Active, non-expired waivers echoed for operator review.
    pub active_waivers: Vec<DeploymentWaiver>,
    /// Unsuppressed `startup_fail` finding ids.
    pub startup_failures: Vec<String>,
    /// Unsuppressed `readiness_fail` finding ids.
    pub readiness_failures: Vec<String>,
}

impl GateEvaluation {
    #[must_use]
    pub fn has_startup_failure(&self) -> bool {
        !self.startup_failures.is_empty()
    }

    #[must_use]
    pub fn has_readiness_failure(&self) -> bool {
        !self.readiness_failures.is_empty()
    }
}

/// Evaluate a product-owned gate catalog.
///
/// `today` is a `YYYY-MM-DD` date used for deterministic waiver expiry. Invalid
/// dates fail closed as expired so an unparsable waiver cannot suppress a gate.
#[must_use]
pub fn evaluate<I>(
    profile: Option<DeploymentProfile>,
    catalog: &[Gate<I>],
    facts: &I,
    waivers: &[DeploymentWaiver],
    today: &str,
) -> GateEvaluation {
    let Some(profile) = profile else {
        return GateEvaluation {
            findings: vec![DeploymentFinding {
                id: PROFILE_UNDECLARED_FINDING_ID.to_string(),
                severity: GateSeverity::FindingWarn,
                status: DeploymentFindingStatus::Active,
                waiver: None,
            }],
            active_waivers: Vec::new(),
            startup_failures: Vec::new(),
            readiness_failures: Vec::new(),
        };
    };

    let mut evaluation = GateEvaluation::default();

    for gate in catalog {
        let Some(severity) = gate.severity_for(profile) else {
            continue;
        };
        if !(gate.condition)(facts) {
            continue;
        }

        let active_waiver = if severity.is_waivable() {
            waivers
                .iter()
                .find(|waiver| waiver.finding == gate.id && !waiver_is_expired(waiver, today))
        } else {
            None
        };

        if let Some(waiver) = active_waiver {
            evaluation.findings.push(DeploymentFinding {
                id: gate.id.to_string(),
                severity,
                status: DeploymentFindingStatus::Waived,
                waiver: Some(DeploymentFindingWaiver {
                    reason: waiver.reason.clone(),
                    expires: waiver.expires.clone(),
                }),
            });
            continue;
        }

        match severity {
            GateSeverity::StartupFail => evaluation.startup_failures.push(gate.id.to_string()),
            GateSeverity::ReadinessFail => evaluation.readiness_failures.push(gate.id.to_string()),
            GateSeverity::FindingError | GateSeverity::FindingWarn => {}
        }
        evaluation.findings.push(DeploymentFinding {
            id: gate.id.to_string(),
            severity,
            status: DeploymentFindingStatus::Active,
            waiver: None,
        });
    }

    let mut expired_findings = Vec::new();
    for waiver in waivers {
        if waiver_is_expired(waiver, today) {
            expired_findings.push(DeploymentFinding {
                id: WAIVER_EXPIRED_FINDING_ID.to_string(),
                severity: GateSeverity::FindingError,
                status: DeploymentFindingStatus::Active,
                waiver: Some(DeploymentFindingWaiver {
                    reason: waiver.reason.clone(),
                    expires: waiver.expires.clone(),
                }),
            });
        } else {
            evaluation.active_waivers.push(waiver.clone());
        }
    }
    evaluation.findings.extend(expired_findings);

    evaluation
}

fn waiver_is_expired(waiver: &DeploymentWaiver, today: &str) -> bool {
    match (parse_iso_date(&waiver.expires), parse_iso_date(today)) {
        (Some(_), Some(_)) => waiver.expires.as_str() < today,
        _ => true,
    }
}

fn parse_iso_date(value: &str) -> Option<(u16, u8, u8)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: u16 = value.get(0..4)?.parse().ok()?;
    let month: u8 = value.get(5..7)?.parse().ok()?;
    let day: u8 = value.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > max_day {
        return None;
    }
    Some((year, month, day))
}

const fn is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

pub const COMPLIANCE_REGIME_GDPR: &str = "gdpr";

pub const REGISTRYSTACK_IRI_NAMESPACE: &str = "registrystack:";

pub const GDPR_CONSENT_CAPTURE_OBLIGATION: &str = "registrystack:gdpr.art7.consent_capture";
pub const GDPR_RECTIFICATION_EXECUTION_OBLIGATION: &str =
    "registrystack:gdpr.art16.rectification_execution";
pub const GDPR_AUTOMATED_DECISION_SAFEGUARDS_OBLIGATION: &str =
    "registrystack:gdpr.art22.automated_decision_safeguards";
pub const GDPR_BREACH_NOTIFICATION_WORKFLOW_OBLIGATION: &str =
    "registrystack:gdpr.art33_34.breach_notification_workflow";

/// Top-level `compliance` posture block.
///
/// In the MVP, products should omit this block entirely when no regime is
/// declared. When present, `findings` is expected to be empty until compliance
/// gate content lands.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct CompliancePosture {
    pub regimes: Vec<String>,
    pub findings: Vec<ComplianceFinding>,
    pub not_applicable: Vec<ComplianceNotApplicable>,
}

impl CompliancePosture {
    #[must_use]
    pub fn for_declared_regimes<I, S>(regimes: I) -> Option<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let regimes = regimes.into_iter().map(Into::into).collect::<Vec<_>>();
        if regimes.is_empty() {
            return None;
        }
        let not_applicable = regimes
            .iter()
            .flat_map(|regime| static_not_applicable_for_regime(regime))
            .collect();
        Some(Self {
            regimes,
            findings: Vec::new(),
            not_applicable,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ComplianceFinding {
    pub id: String,
    pub regime_severities: BTreeMap<String, GateSeverity>,
    pub status: DeploymentFindingStatus,
    pub kind: ComplianceFindingKind,
    pub discharges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiver: Option<DeploymentFindingWaiver>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ComplianceFindingKind {
    Observed,
    Asserted,
}

impl ComplianceFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Asserted => "asserted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ComplianceNotApplicable {
    pub obligation: String,
    pub reason: String,
}

fn static_not_applicable_for_regime(regime: &str) -> Vec<ComplianceNotApplicable> {
    match regime {
        COMPLIANCE_REGIME_GDPR => gdpr_static_not_applicable(),
        _ => Vec::new(),
    }
}

fn gdpr_static_not_applicable() -> Vec<ComplianceNotApplicable> {
    [
        (
            GDPR_CONSENT_CAPTURE_OBLIGATION,
            "Consent capture is outside the platform posture MVP.",
        ),
        (
            GDPR_RECTIFICATION_EXECUTION_OBLIGATION,
            "Rectification execution is outside the platform posture MVP.",
        ),
        (
            GDPR_AUTOMATED_DECISION_SAFEGUARDS_OBLIGATION,
            "Automated-decision safeguards are outside the platform posture MVP.",
        ),
        (
            GDPR_BREACH_NOTIFICATION_WORKFLOW_OBLIGATION,
            "Breach-notification workflow is outside the platform posture MVP.",
        ),
    ]
    .into_iter()
    .map(|(obligation, reason)| ComplianceNotApplicable {
        obligation: obligation.to_string(),
        reason: reason.to_string(),
    })
    .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditWritePolicy {
    AvailabilityFirst,
    FailClosed,
    FailClosedRouteFamilies,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditRedactionMode {
    Redacted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditHashChain {
    None,
    ProcessLocal,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditKeyedIntegrity {
    None,
    Hmac,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditSinkClass {
    None,
    Stdout,
    File,
    Http,
    External,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditRetentionOwner {
    Unspecified,
    Operator,
    Host,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditCheckpoints {
    Unsupported,
    Supported,
    Enabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAnchoring {
    None,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AuditAssurance {
    pub write_policy: AuditWritePolicy,
    pub redaction_mode: AuditRedactionMode,
    pub hash_chain: AuditHashChain,
    pub keyed_integrity: AuditKeyedIntegrity,
    pub sink_class: AuditSinkClass,
    pub retention_owner: AuditRetentionOwner,
    pub checkpoints: AuditCheckpoints,
    pub anchoring: AuditAnchoring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigSource {
    LocalFile,
    SignedBundleFile,
    SignedBundleEndpoint,
    Unknown,
}

impl ConfigSource {
    pub fn as_posture_str(self) -> &'static str {
        match self {
            Self::LocalFile => "local_file",
            Self::SignedBundleFile => "signed_bundle_file",
            Self::SignedBundleEndpoint => "signed_bundle_endpoint",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigProvenance {
    pub source: ConfigSource,
    pub internal_config_hash: String,
    pub posture_config_hash: String,
    pub dynamic_reload_supported: bool,
    pub last_bundle_id: Option<String>,
    pub last_bundle_sequence: Option<u64>,
    pub last_apply_result: Option<PostureApplyResult>,
    pub last_apply_at: Option<String>,
    pub restart_required: bool,
}

impl ConfigProvenance {
    pub fn local_file(
        internal_config_hash: impl Into<String>,
        posture_config_hash: impl Into<String>,
        dynamic_reload_supported: bool,
    ) -> Self {
        Self {
            source: ConfigSource::LocalFile,
            internal_config_hash: internal_config_hash.into(),
            posture_config_hash: posture_config_hash.into(),
            dynamic_reload_supported,
            last_bundle_id: None,
            last_bundle_sequence: None,
            last_apply_result: None,
            last_apply_at: None,
            restart_required: false,
        }
    }

    pub fn posture_source(&self) -> &'static str {
        self.source.as_posture_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplyReportResult {
    Verified,
    Applied,
    RejectedSignature,
    RejectedThreshold,
    RejectedFreshness,
    RejectedRollback,
    RejectedRestartRequired,
    RejectedReadiness,
    RejectedBreakGlass,
    RejectedLocalApproval,
    InternalError,
}

impl ApplyReportResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Applied => "applied",
            Self::RejectedSignature => "rejected_signature",
            Self::RejectedThreshold => "rejected_threshold",
            Self::RejectedFreshness => "rejected_freshness",
            Self::RejectedRollback => "rejected_rollback",
            Self::RejectedRestartRequired => "rejected_restart_required",
            Self::RejectedReadiness => "rejected_readiness",
            Self::RejectedBreakGlass => "rejected_break_glass",
            Self::RejectedLocalApproval => "rejected_local_approval",
            Self::InternalError => "internal_error",
        }
    }

    pub fn as_posture_result(self) -> PostureApplyResult {
        match self {
            Self::Verified => PostureApplyResult::NotApplied,
            Self::Applied => PostureApplyResult::Accepted,
            Self::RejectedSignature
            | Self::RejectedThreshold
            | Self::RejectedFreshness
            | Self::RejectedRollback
            | Self::RejectedRestartRequired
            | Self::RejectedReadiness
            | Self::RejectedBreakGlass
            | Self::RejectedLocalApproval => PostureApplyResult::Rejected,
            Self::InternalError => PostureApplyResult::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PostureApplyResult {
    Accepted,
    Rejected,
    Failed,
    NotApplied,
}

impl PostureApplyResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::NotApplied => "not_applied",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AntiRollbackKey {
    pub product: String,
    pub instance_id: String,
    pub environment: String,
    pub stream_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AntiRollbackRecord {
    pub key: AntiRollbackKey,
    pub last_sequence: u64,
    pub last_config_hash: String,
    pub root_version: Option<u64>,
    #[serde(default)]
    pub break_glass: BreakGlassState,
    #[serde(default)]
    pub local_approvals: LocalApprovalState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntiRollbackProposal {
    pub sequence: u64,
    pub previous_config_hash: Option<String>,
    pub config_hash: String,
    pub root_version: Option<u64>,
    pub break_glass: Option<BreakGlassApproval>,
    /// Compatibility-only break-glass rate limit policy.
    ///
    /// Production callers should configure verifier-owned policy on
    /// [`FileAntiRollbackStore::with_break_glass_rate_limit`] and leave this
    /// field empty. A proposal-supplied policy is still accepted only when the
    /// store has no local break-glass policy configured, preserving older test
    /// and integration callers until the next breaking API revision can remove
    /// this request-controlled field.
    pub break_glass_rate_limit: Option<BreakGlassRateLimit>,
    pub local_approval: Option<LocalOperatorApproval>,
    /// Rate limit policy loaded with a trusted local approval record.
    ///
    /// This differs from break-glass proposal policy: local approvals are
    /// retrieved from a verifier-owned approval store before the proposal is
    /// built, so the rate limit is not controlled by an apply request.
    pub local_approval_rate_limit: Option<BreakGlassRateLimit>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct BreakGlassState {
    #[serde(default)]
    pub accepted: Vec<BreakGlassAcceptance>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BreakGlassAcceptance {
    pub accepted_at_unix_seconds: u64,
    pub approval_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_change_class: Option<String>,
    pub rate_limit_identity: String,
    pub sequence: u64,
    pub config_hash: String,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct LocalApprovalState {
    #[serde(default)]
    pub accepted: Vec<LocalApprovalAcceptance>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LocalApprovalAcceptance {
    pub accepted_at_unix_seconds: u64,
    pub approval_reference: String,
    pub change_class: String,
    pub rate_limit_identity: String,
    pub sequence: u64,
    pub config_hash: String,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LocalOperatorApproval {
    pub approved_by: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    pub reason: String,
    pub approval_reference: String,
    pub change_class: String,
    pub config_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_config_hash: Option<String>,
    pub expires_at_unix_seconds: u64,
    pub rate_limit_identity: String,
    pub rate_limit: BreakGlassRateLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BreakGlassApproval {
    pub approved_by: String,
    pub reason: String,
    pub approval_reference: String,
    pub emergency_change_class: String,
    pub expires_at_unix_seconds: u64,
    pub rate_limit_identity: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BreakGlassRateLimit {
    pub max_accepted: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AntiRollbackStoreError {
    MissingState,
    KeyMismatch,
    NonMonotonicSequence,
    RootVersionRollback,
    PreviousConfigHashMismatch,
    BreakGlassUnsupported,
    BreakGlassApprovalExpired,
    BreakGlassRateLimitMissing,
    BreakGlassRateLimited,
    LocalApprovalExpired,
    LocalApprovalRateLimitMissing,
    LocalApprovalRateLimited,
    InvalidLocalApproval(&'static str),
    InvalidBreakGlassApproval(&'static str),
    InvalidBreakGlassRateLimit(&'static str),
    InvalidState(String),
    Io(String),
    Json(String),
}

impl Display for AntiRollbackStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingState => write!(f, "anti-rollback state is missing"),
            Self::KeyMismatch => write!(f, "anti-rollback state key does not match runtime"),
            Self::NonMonotonicSequence => write!(f, "bundle sequence is not monotonic"),
            Self::RootVersionRollback => write!(f, "TUF root version is not monotonic"),
            Self::PreviousConfigHashMismatch => write!(f, "previous config hash does not match"),
            Self::BreakGlassUnsupported => write!(f, "break-glass approval is not supported"),
            Self::BreakGlassApprovalExpired => write!(f, "break-glass approval is expired"),
            Self::BreakGlassRateLimitMissing => {
                write!(f, "break-glass rate limit policy is missing")
            }
            Self::BreakGlassRateLimited => write!(f, "break-glass rate limit exceeded"),
            Self::LocalApprovalExpired => write!(f, "local approval is expired"),
            Self::LocalApprovalRateLimitMissing => {
                write!(f, "local approval rate limit policy is missing")
            }
            Self::LocalApprovalRateLimited => write!(f, "local approval rate limit exceeded"),
            Self::InvalidLocalApproval(field) => {
                write!(f, "local approval field is invalid: {field}")
            }
            Self::InvalidBreakGlassApproval(field) => {
                write!(f, "break-glass approval field is invalid: {field}")
            }
            Self::InvalidBreakGlassRateLimit(field) => {
                write!(f, "break-glass rate limit field is invalid: {field}")
            }
            Self::InvalidState(message) => write!(f, "invalid anti-rollback state: {message}"),
            Self::Io(message) => write!(f, "anti-rollback state I/O error: {message}"),
            Self::Json(message) => write!(f, "anti-rollback state JSON error: {message}"),
        }
    }
}

impl std::error::Error for AntiRollbackStoreError {}

#[derive(Clone, Debug)]
pub struct FileAntiRollbackStore {
    path: PathBuf,
    break_glass_rate_limit: Option<BreakGlassRateLimit>,
}

impl FileAntiRollbackStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            break_glass_rate_limit: None,
        }
    }

    #[must_use]
    /// Configure verifier-owned break-glass rate limit policy for this store.
    ///
    /// Product runtimes that support break-glass should use this constructor
    /// path and leave [`AntiRollbackProposal::break_glass_rate_limit`] empty.
    /// When both are present, the proposal policy must match the local policy;
    /// a mismatch is rejected instead of allowing request-controlled policy to
    /// loosen the verifier's limit.
    pub fn with_break_glass_rate_limit(mut self, rate_limit: BreakGlassRateLimit) -> Self {
        self.break_glass_rate_limit = Some(rate_limit);
        self
    }

    pub fn load(
        &self,
        key: &AntiRollbackKey,
    ) -> Result<AntiRollbackRecord, AntiRollbackStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AntiRollbackStoreError::MissingState);
            }
            Err(error) => return Err(AntiRollbackStoreError::Io(error.to_string())),
        };
        let record: AntiRollbackRecord = serde_json::from_slice(&bytes)
            .map_err(|error| AntiRollbackStoreError::Json(error.to_string()))?;
        record.validate()?;
        if &record.key != key {
            return Err(AntiRollbackStoreError::KeyMismatch);
        }
        Ok(record)
    }

    pub fn initialize(&self, record: AntiRollbackRecord) -> Result<(), AntiRollbackStoreError> {
        let _lock = self.acquire_lock()?;
        record.validate()?;
        self.write_record(&record)
    }

    pub fn accept(
        &self,
        key: &AntiRollbackKey,
        proposal: AntiRollbackProposal,
    ) -> Result<AntiRollbackRecord, AntiRollbackStoreError> {
        self.accept_at(key, proposal, current_unix_seconds()?)
    }

    pub fn accept_at(
        &self,
        key: &AntiRollbackKey,
        proposal: AntiRollbackProposal,
        now_unix_seconds: u64,
    ) -> Result<AntiRollbackRecord, AntiRollbackStoreError> {
        let _lock = self.acquire_lock()?;
        let current = self.load(key)?;
        if let (Some(current_root_version), Some(proposed_root_version)) =
            (current.root_version, proposal.root_version)
        {
            if proposed_root_version < current_root_version {
                return Err(AntiRollbackStoreError::RootVersionRollback);
            }
        }
        if proposal.sequence < current.last_sequence {
            return Err(AntiRollbackStoreError::NonMonotonicSequence);
        }
        if proposal.sequence == current.last_sequence {
            if proposal.config_hash != current.last_config_hash
                || proposal.break_glass.is_some()
                || proposal.local_approval.is_some()
            {
                return Err(AntiRollbackStoreError::NonMonotonicSequence);
            }
            let accepted_root_version = match (current.root_version, proposal.root_version) {
                (Some(current), Some(proposed)) => Some(current.max(proposed)),
                (None, Some(proposed)) => Some(proposed),
                _ => current.root_version,
            };
            if accepted_root_version == current.root_version {
                return Ok(current);
            }
            let accepted = AntiRollbackRecord {
                root_version: accepted_root_version,
                ..current
            };
            accepted.validate()?;
            self.write_record(&accepted)?;
            return Ok(accepted);
        }
        let mut break_glass = current.break_glass.clone();
        let mut local_approvals = current.local_approvals.clone();
        let approved_break_glass = if let Some(approval) = &proposal.break_glass {
            let rate_limit = match (self.break_glass_rate_limit, proposal.break_glass_rate_limit) {
                (Some(local), Some(proposed)) if local != proposed => {
                    return Err(AntiRollbackStoreError::InvalidBreakGlassRateLimit(
                        "policy_mismatch",
                    ));
                }
                (Some(local), _) => local,
                (None, Some(proposed)) => proposed,
                (None, None) => return Err(AntiRollbackStoreError::BreakGlassRateLimitMissing),
            };
            validate_break_glass_approval(approval, now_unix_seconds)?;
            validate_break_glass_rate_limit(rate_limit)?;
            enforce_break_glass_rate_limit(
                &mut break_glass,
                approval,
                rate_limit,
                proposal.sequence,
                &proposal.config_hash,
                now_unix_seconds,
            )?;
            true
        } else {
            false
        };
        if !approved_break_glass
            && proposal.previous_config_hash.as_deref() != Some(current.last_config_hash.as_str())
        {
            return Err(AntiRollbackStoreError::PreviousConfigHashMismatch);
        }
        if let Some(approval) = &proposal.local_approval {
            let rate_limit = proposal
                .local_approval_rate_limit
                .ok_or(AntiRollbackStoreError::LocalApprovalRateLimitMissing)?;
            validate_local_approval(
                approval,
                &proposal.config_hash,
                proposal.previous_config_hash.as_deref(),
                now_unix_seconds,
            )?;
            validate_break_glass_rate_limit(rate_limit)?;
            if approval.rate_limit != rate_limit {
                return Err(AntiRollbackStoreError::InvalidLocalApproval("rate_limit"));
            }
            enforce_local_approval_rate_limit(
                &mut local_approvals,
                approval,
                rate_limit,
                proposal.sequence,
                now_unix_seconds,
            )?;
        }
        let accepted = AntiRollbackRecord {
            key: key.clone(),
            last_sequence: proposal.sequence,
            last_config_hash: proposal.config_hash,
            root_version: proposal.root_version.or(current.root_version),
            break_glass,
            local_approvals,
        };
        accepted.validate()?;
        self.write_record(&accepted)?;
        Ok(accepted)
    }

    fn write_record(&self, record: &AntiRollbackRecord) -> Result<(), AntiRollbackStoreError> {
        let target_path = self.write_target_path()?;
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
        }
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| AntiRollbackStoreError::Json(error.to_string()))?;
        let tmp_path = target_path.with_extension("tmp");
        {
            let mut file = fs::File::create(&tmp_path)
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
            file.write_all(&bytes)
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
            file.write_all(b"\n")
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
        }
        fs::rename(&tmp_path, &target_path)
            .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
        Ok(())
    }

    fn write_target_path(&self) -> Result<PathBuf, AntiRollbackStoreError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_symlink() => self
                .path
                .canonicalize()
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string())),
            Ok(_) => Ok(self.path.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(self.path.clone()),
            Err(error) => Err(AntiRollbackStoreError::Io(error.to_string())),
        }
    }

    fn acquire_lock(&self) -> Result<AntiRollbackStoreLock, AntiRollbackStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
        }
        let lock_path = self.path.with_extension("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
        file.lock_exclusive()
            .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))?;
        Ok(AntiRollbackStoreLock { file })
    }
}

struct AntiRollbackStoreLock {
    file: fs::File,
}

impl Drop for AntiRollbackStoreLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl AntiRollbackRecord {
    fn validate(&self) -> Result<(), AntiRollbackStoreError> {
        validate_non_empty("product", &self.key.product)?;
        validate_non_empty("instance_id", &self.key.instance_id)?;
        validate_non_empty("environment", &self.key.environment)?;
        validate_non_empty("stream_id", &self.key.stream_id)?;
        validate_hash(&self.last_config_hash)?;
        for accepted in &self.break_glass.accepted {
            validate_non_empty(
                "break_glass.approval_reference",
                &accepted.approval_reference,
            )?;
            validate_non_empty(
                "break_glass.rate_limit_identity",
                &accepted.rate_limit_identity,
            )?;
            validate_hash(&accepted.config_hash)?;
        }
        for accepted in &self.local_approvals.accepted {
            validate_non_empty(
                "local_approvals.approval_reference",
                &accepted.approval_reference,
            )?;
            validate_non_empty("local_approvals.change_class", &accepted.change_class)?;
            validate_non_empty(
                "local_approvals.rate_limit_identity",
                &accepted.rate_limit_identity,
            )?;
            validate_hash(&accepted.config_hash)?;
        }
        Ok(())
    }
}

fn validate_break_glass_approval(
    approval: &BreakGlassApproval,
    now_unix_seconds: u64,
) -> Result<(), AntiRollbackStoreError> {
    validate_approval_field("approved_by", &approval.approved_by)?;
    validate_approval_field("reason", &approval.reason)?;
    validate_approval_field("approval_reference", &approval.approval_reference)?;
    validate_approval_field("emergency_change_class", &approval.emergency_change_class)?;
    validate_approval_field("rate_limit_identity", &approval.rate_limit_identity)?;
    if approval.expires_at_unix_seconds <= now_unix_seconds {
        return Err(AntiRollbackStoreError::BreakGlassApprovalExpired);
    }
    Ok(())
}

fn validate_local_approval(
    approval: &LocalOperatorApproval,
    config_hash: &str,
    previous_config_hash: Option<&str>,
    now_unix_seconds: u64,
) -> Result<(), AntiRollbackStoreError> {
    validate_local_approval_field("approved_by", &approval.approved_by)?;
    validate_distinct_approvers(&approval.approved_by, &approval.approvers)?;
    validate_local_approval_field("reason", &approval.reason)?;
    validate_local_approval_field("approval_reference", &approval.approval_reference)?;
    validate_local_approval_field("change_class", &approval.change_class)?;
    validate_local_approval_field("rate_limit_identity", &approval.rate_limit_identity)?;
    validate_hash(&approval.config_hash)?;
    if approval.config_hash != config_hash {
        return Err(AntiRollbackStoreError::InvalidLocalApproval("config_hash"));
    }
    if approval.previous_config_hash.as_deref() != previous_config_hash {
        return Err(AntiRollbackStoreError::InvalidLocalApproval(
            "previous_config_hash",
        ));
    }
    validate_break_glass_rate_limit(approval.rate_limit)
        .map_err(|_| AntiRollbackStoreError::InvalidLocalApproval("rate_limit"))?;
    if approval.expires_at_unix_seconds <= now_unix_seconds {
        return Err(AntiRollbackStoreError::LocalApprovalExpired);
    }
    Ok(())
}

fn validate_local_approval_field(
    name: &'static str,
    value: &str,
) -> Result<(), AntiRollbackStoreError> {
    if value.trim().is_empty() {
        return Err(AntiRollbackStoreError::InvalidLocalApproval(name));
    }
    Ok(())
}

fn validate_distinct_approvers(
    approved_by: &str,
    approvers: &[String],
) -> Result<(), AntiRollbackStoreError> {
    let mut trimmed = Vec::with_capacity(approvers.len() + 1);
    trimmed.push(approved_by.trim());
    for approver in approvers {
        let approver = approver.trim();
        if approver.is_empty() {
            return Err(AntiRollbackStoreError::InvalidLocalApproval("approvers"));
        }
        trimmed.push(approver);
    }
    for index in 0..trimmed.len() {
        if trimmed[index + 1..]
            .iter()
            .any(|candidate| *candidate == trimmed[index])
        {
            return Err(AntiRollbackStoreError::InvalidLocalApproval("approvers"));
        }
    }
    Ok(())
}

fn validate_approval_field(name: &'static str, value: &str) -> Result<(), AntiRollbackStoreError> {
    if value.trim().is_empty() {
        return Err(AntiRollbackStoreError::InvalidBreakGlassApproval(name));
    }
    Ok(())
}

fn validate_break_glass_rate_limit(
    rate_limit: BreakGlassRateLimit,
) -> Result<(), AntiRollbackStoreError> {
    if rate_limit.max_accepted == 0 {
        return Err(AntiRollbackStoreError::InvalidBreakGlassRateLimit(
            "max_accepted",
        ));
    }
    if rate_limit.window_seconds == 0 {
        return Err(AntiRollbackStoreError::InvalidBreakGlassRateLimit(
            "window_seconds",
        ));
    }
    Ok(())
}

fn enforce_local_approval_rate_limit(
    state: &mut LocalApprovalState,
    approval: &LocalOperatorApproval,
    rate_limit: BreakGlassRateLimit,
    sequence: u64,
    now_unix_seconds: u64,
) -> Result<(), AntiRollbackStoreError> {
    state.accepted.retain(|accepted| {
        accepted
            .accepted_at_unix_seconds
            .saturating_add(rate_limit.window_seconds)
            > now_unix_seconds
    });
    let in_window_for_identity = state
        .accepted
        .iter()
        .filter(|accepted| accepted.rate_limit_identity == approval.rate_limit_identity)
        .count();
    if in_window_for_identity >= rate_limit.max_accepted as usize {
        return Err(AntiRollbackStoreError::LocalApprovalRateLimited);
    }
    state.accepted.push(LocalApprovalAcceptance {
        accepted_at_unix_seconds: now_unix_seconds,
        approval_reference: approval.approval_reference.clone(),
        change_class: approval.change_class.clone(),
        rate_limit_identity: approval.rate_limit_identity.clone(),
        sequence,
        config_hash: approval.config_hash.clone(),
        expires_at_unix_seconds: approval.expires_at_unix_seconds,
    });
    Ok(())
}

fn enforce_break_glass_rate_limit(
    state: &mut BreakGlassState,
    approval: &BreakGlassApproval,
    rate_limit: BreakGlassRateLimit,
    sequence: u64,
    config_hash: &str,
    now_unix_seconds: u64,
) -> Result<(), AntiRollbackStoreError> {
    state.accepted.retain(|accepted| {
        accepted
            .accepted_at_unix_seconds
            .saturating_add(rate_limit.window_seconds)
            > now_unix_seconds
    });
    let in_window_for_identity = state
        .accepted
        .iter()
        .filter(|accepted| accepted.rate_limit_identity == approval.rate_limit_identity)
        .count();
    if in_window_for_identity >= rate_limit.max_accepted as usize {
        return Err(AntiRollbackStoreError::BreakGlassRateLimited);
    }
    state.accepted.push(BreakGlassAcceptance {
        accepted_at_unix_seconds: now_unix_seconds,
        approval_reference: approval.approval_reference.clone(),
        emergency_change_class: Some(approval.emergency_change_class.clone()),
        rate_limit_identity: approval.rate_limit_identity.clone(),
        sequence,
        config_hash: config_hash.to_string(),
        expires_at_unix_seconds: approval.expires_at_unix_seconds,
    });
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LocalApprovalFile {
    #[serde(default)]
    pub approvals: Vec<LocalOperatorApproval>,
}

#[derive(Clone, Debug)]
pub struct FileLocalApprovalStore {
    path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalApprovalStoreError {
    MissingState,
    ApprovalNotFound,
    ApprovalExpired,
    InvalidApproval(&'static str),
    InvalidState(String),
    Io(String),
    Json(String),
}

impl Display for LocalApprovalStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingState => write!(f, "local approval state is missing"),
            Self::ApprovalNotFound => write!(f, "local approval was not found"),
            Self::ApprovalExpired => write!(f, "local approval is expired"),
            Self::InvalidApproval(field) => write!(f, "local approval field is invalid: {field}"),
            Self::InvalidState(message) => write!(f, "invalid local approval state: {message}"),
            Self::Io(message) => write!(f, "local approval state I/O error: {message}"),
            Self::Json(message) => write!(f, "local approval state JSON error: {message}"),
        }
    }
}

impl std::error::Error for LocalApprovalStoreError {}

impl FileLocalApprovalStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn load_for_apply(
        &self,
        approval_reference: &str,
        change_class: &str,
        config_hash: &str,
        previous_config_hash: Option<&str>,
    ) -> Result<LocalOperatorApproval, LocalApprovalStoreError> {
        self.load_for_apply_at(
            approval_reference,
            change_class,
            config_hash,
            previous_config_hash,
            current_unix_seconds()
                .map_err(|error| LocalApprovalStoreError::Io(error.to_string()))?,
        )
    }

    pub fn load_for_apply_at(
        &self,
        approval_reference: &str,
        change_class: &str,
        config_hash: &str,
        previous_config_hash: Option<&str>,
        now_unix_seconds: u64,
    ) -> Result<LocalOperatorApproval, LocalApprovalStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(LocalApprovalStoreError::MissingState);
            }
            Err(error) => return Err(LocalApprovalStoreError::Io(error.to_string())),
        };
        let state: LocalApprovalFile = serde_json::from_slice(&bytes)
            .map_err(|error| LocalApprovalStoreError::Json(error.to_string()))?;
        let approval = state
            .approvals
            .into_iter()
            .find(|approval| {
                approval.approval_reference == approval_reference
                    && approval.change_class == change_class
                    && approval.config_hash == config_hash
                    && approval.previous_config_hash.as_deref() == previous_config_hash
            })
            .ok_or(LocalApprovalStoreError::ApprovalNotFound)?;
        validate_local_approval(
            &approval,
            config_hash,
            previous_config_hash,
            now_unix_seconds,
        )
        .map_err(local_approval_store_error)?;
        Ok(approval)
    }
}

fn local_approval_store_error(error: AntiRollbackStoreError) -> LocalApprovalStoreError {
    match error {
        AntiRollbackStoreError::LocalApprovalExpired => LocalApprovalStoreError::ApprovalExpired,
        AntiRollbackStoreError::InvalidLocalApproval(field) => {
            LocalApprovalStoreError::InvalidApproval(field)
        }
        other => LocalApprovalStoreError::InvalidState(other.to_string()),
    }
}

fn current_unix_seconds() -> Result<u64, AntiRollbackStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| AntiRollbackStoreError::Io(error.to_string()))
}

fn validate_non_empty(name: &str, value: &str) -> Result<(), AntiRollbackStoreError> {
    if value.trim().is_empty() {
        return Err(AntiRollbackStoreError::InvalidState(format!(
            "{name} is empty"
        )));
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), AntiRollbackStoreError> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        AntiRollbackStoreError::InvalidState("hash must start with sha256:".to_string())
    })?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AntiRollbackStoreError::InvalidState(
            "hash must be sha256 plus 64 lowercase hex characters".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigValueSensitivity {
    Public,
    Secret,
}

/// Hash the exact source bytes read by the local loader.
///
/// This intentionally tracks byte identity for local files. Structured config
/// hash preimages, including posture-safe hashes, are canonicalized separately.
pub fn internal_config_hash(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn is_sha256_config_hash(value: &str) -> bool {
    validate_hash(value).is_ok()
}

pub fn posture_safe_runtime_config_hash(value: &Value) -> String {
    posture_safe_config_hash(value, registry_runtime_config_sensitivity)
}

pub fn posture_safe_config_hash(
    value: &Value,
    classify: impl Fn(&[&str], &Value) -> ConfigValueSensitivity,
) -> String {
    let mut path = [""; CONFIG_REDACTION_PATH_STACK_LIMIT];
    let redacted = redact_config_secrets(value, &mut path, 0, &classify);
    let bytes = canonicalize_json(&redacted).expect("serde_json::Value canonicalizes");
    sha256_hex(&bytes)
}

pub fn registry_runtime_config_sensitivity(
    path: &[&str],
    _value: &Value,
) -> ConfigValueSensitivity {
    if path.is_empty() || is_public_runtime_config_path(path) || has_public_descendant(path) {
        ConfigValueSensitivity::Public
    } else {
        ConfigValueSensitivity::Secret
    }
}

fn is_public_runtime_config_path(path: &[&str]) -> bool {
    matches!(
        path,
        ["instance", "id"]
            | ["instance", "environment"]
            | ["instance", "owner"]
            | ["instance", "jurisdiction"]
            | ["instance", "public_base_url"]
            | ["catalog", "base_url"]
            | ["auth", "mode"]
            | ["audit", "sink"]
            | ["replay", "storage"]
            | ["credential_status", "enabled"]
            | ["credential_status", "storage"]
    )
}

fn has_public_descendant(path: &[&str]) -> bool {
    PUBLIC_RUNTIME_CONFIG_PATHS
        .iter()
        .any(|public_path| path.len() < public_path.len() && public_path.starts_with(path))
}

const PUBLIC_RUNTIME_CONFIG_PATHS: &[&[&str]] = &[
    &["instance", "id"],
    &["instance", "environment"],
    &["instance", "owner"],
    &["instance", "jurisdiction"],
    &["instance", "public_base_url"],
    &["catalog", "base_url"],
    &["auth", "mode"],
    &["audit", "sink"],
    &["replay", "storage"],
    &["credential_status", "enabled"],
    &["credential_status", "storage"],
];

const CONFIG_REDACTION_PATH_STACK_LIMIT: usize = 64;

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity("sha256:".len() + 64);
    output.push_str("sha256:");
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn redact_config_secrets<'a>(
    value: &'a Value,
    path: &mut [&'a str],
    depth: usize,
    classify: &impl Fn(&[&str], &Value) -> ConfigValueSensitivity,
) -> Value {
    if classify(&path[..depth], value) == ConfigValueSensitivity::Secret {
        return Value::String("[secret]".to_string());
    }

    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_config_secrets_child(item, path, depth, "*", classify))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| {
                    (
                        key.clone(),
                        redact_config_secrets_child(child, path, depth, key, classify),
                    )
                })
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn redact_config_secrets_child<'a>(
    value: &'a Value,
    path: &mut [&'a str],
    depth: usize,
    segment: &'a str,
    classify: &impl Fn(&[&str], &Value) -> ConfigValueSensitivity,
) -> Value {
    if depth < path.len() {
        path[depth] = segment;
        redact_config_secrets(value, path, depth + 1, classify)
    } else {
        let mut overflow_path = Vec::with_capacity(path.len() + 1);
        overflow_path.extend_from_slice(path);
        overflow_path.push(segment);
        redact_config_secrets_overflow(value, &mut overflow_path, classify)
    }
}

fn redact_config_secrets_overflow<'a>(
    value: &'a Value,
    path: &mut Vec<&'a str>,
    classify: &impl Fn(&[&str], &Value) -> ConfigValueSensitivity,
) -> Value {
    if classify(path, value) == ConfigValueSensitivity::Secret {
        return Value::String("[secret]".to_string());
    }

    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| {
                    path.push("*");
                    let redacted = redact_config_secrets_overflow(item, path, classify);
                    path.pop();
                    redacted
                })
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| {
                    path.push(key);
                    let redacted = redact_config_secrets_overflow(child, path, classify);
                    path.pop();
                    (key.clone(), redacted)
                })
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostureTier {
    Default,
    Restricted,
}

impl PostureTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Restricted => "restricted",
        }
    }
}

#[derive(Clone, Debug)]
pub enum PostureFilterError {
    InvalidAllowlist,
    MissingAllowedPointers,
    InvalidAllowedPointer,
    FilteredToEmptyDocument,
}

impl std::fmt::Display for PostureFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAllowlist => write!(f, "invalid posture allowlist"),
            Self::MissingAllowedPointers => write!(f, "posture allowlist is missing pointers"),
            Self::InvalidAllowedPointer => {
                write!(f, "posture allowlist contains a non-string pointer")
            }
            Self::FilteredToEmptyDocument => {
                write!(f, "posture filter removed the entire document")
            }
        }
    }
}

impl std::error::Error for PostureFilterError {}

pub fn filter_posture_for_tier(
    mut posture: Value,
    tier: PostureTier,
) -> Result<Value, PostureFilterError> {
    posture["tier"] = Value::String(tier.as_str().to_string());
    match tier {
        PostureTier::Default => filter_default_posture(posture),
        PostureTier::Restricted => Ok(posture),
    }
}

fn filter_default_posture(posture: Value) -> Result<Value, PostureFilterError> {
    let allowed = default_allowed_patterns()?;
    let mut path = Vec::new();
    filter_value(&posture, &mut path, allowed).ok_or(PostureFilterError::FilteredToEmptyDocument)
}

static DEFAULT_ALLOWED_PATTERNS: OnceLock<Result<Vec<PointerPattern>, PostureFilterError>> =
    OnceLock::new();

fn default_allowed_patterns() -> Result<&'static [PointerPattern], PostureFilterError> {
    DEFAULT_ALLOWED_PATTERNS
        .get_or_init(load_default_allowed_patterns)
        .as_deref()
        .map_err(Clone::clone)
}

fn load_default_allowed_patterns() -> Result<Vec<PointerPattern>, PostureFilterError> {
    let allowlist: Value = serde_json::from_str(DEFAULT_POSTURE_ALLOWLIST_FIXTURE_V1)
        .map_err(|_| PostureFilterError::InvalidAllowlist)?;
    allowlist["allowed_json_pointers"]
        .as_array()
        .ok_or(PostureFilterError::MissingAllowedPointers)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(PointerPattern::parse)
                .ok_or(PostureFilterError::InvalidAllowedPointer)
        })
        .collect::<Result<Vec<_>, _>>()
}

fn filter_value<'a>(
    value: &'a Value,
    path: &mut Vec<&'a str>,
    allowed: &[PointerPattern],
) -> Option<Value> {
    if allowed.iter().any(|pattern| pattern.matches(path)) {
        if let Some(allowed_value) = clone_allowed_leaf_value(value) {
            return Some(allowed_value);
        }
    }

    match value {
        Value::Object(map) => {
            let filtered = map
                .iter()
                .filter_map(|(key, child)| {
                    path.push(key.as_str());
                    let filtered = filter_value(child, path, allowed);
                    path.pop();
                    filtered.map(|child| (key.clone(), child))
                })
                .collect::<serde_json::Map<_, _>>();
            (!filtered.is_empty()
                || (map.is_empty()
                    && allowed
                        .iter()
                        .any(|pattern| pattern.has_descendant_of(path))))
            .then_some(Value::Object(filtered))
        }
        Value::Array(items) => {
            let filtered = items
                .iter()
                .filter_map(|child| {
                    path.push("*");
                    let filtered = filter_value(child, path, allowed);
                    path.pop();
                    filtered
                })
                .collect::<Vec<_>>();
            (!filtered.is_empty()
                || (items.is_empty()
                    && allowed
                        .iter()
                        .any(|pattern| pattern.has_descendant_of(path))))
            .then_some(Value::Array(filtered))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

fn clone_allowed_leaf_value(value: &Value) -> Option<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Some(value.clone()),
        Value::Array(items) => {
            let filtered = items
                .iter()
                .filter(|item| is_scalar_value(item))
                .cloned()
                .collect::<Vec<_>>();
            (!filtered.is_empty() || items.is_empty()).then_some(Value::Array(filtered))
        }
        Value::Object(map) => map
            .is_empty()
            .then_some(Value::Object(serde_json::Map::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clone_allowed_leaf_value_preserves_only_empty_objects() {
        assert_eq!(clone_allowed_leaf_value(&json!({})), Some(json!({})));
        assert_eq!(
            clone_allowed_leaf_value(&json!({ "secret": "value" })),
            None
        );
    }
}

fn is_scalar_value(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

#[derive(Clone, Debug)]
struct PointerPattern {
    segments: Vec<String>,
}

impl PointerPattern {
    fn parse(pointer: &str) -> Self {
        Self {
            segments: pointer_segments(pointer),
        }
    }

    fn matches(&self, path: &[&str]) -> bool {
        self.segments.len() == path.len()
            && self
                .segments
                .iter()
                .zip(path)
                .all(|(pattern, segment)| pattern == "*" || pattern == segment)
    }

    fn has_descendant_of(&self, path: &[&str]) -> bool {
        self.segments.len() > path.len()
            && self
                .segments
                .iter()
                .zip(path)
                .all(|(pattern, segment)| pattern == "*" || pattern == segment)
    }
}

fn pointer_segments(pointer: &str) -> Vec<String> {
    pointer
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(unescape_pointer_segment)
        .collect()
}

fn unescape_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}
