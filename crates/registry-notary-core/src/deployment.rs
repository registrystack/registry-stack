// SPDX-License-Identifier: Apache-2.0
//! Operator-declared deployment profile and gate evaluation.
//!
//! A deployment profile is an explicit operator declaration of how a Notary
//! instance is deployed. It is never inferred from the environment label, the
//! hostname, or the network position. The profile binds a set of gates; each
//! gate inspects the running configuration and reports an effect at a defined
//! severity. An undeclared deployment is a startup failure; `local` is the
//! explicit opt-out for development.

use serde::{Deserialize, Serialize};

/// The set of deployment profiles an operator can declare.
///
/// Frozen at introduction; new profiles may be added but existing ones never
/// change meaning. Deserialization is strict: an unknown profile string fails,
/// which surfaces as a startup error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
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

/// Severity vocabulary shared across products.
///
/// `startup_fail` and `readiness_fail` are hard gates and bind only on declared
/// profiles. `finding_error` and `finding_warn` surface as posture findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
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

    /// Hard deployment gates cannot be waived. `startup_fail` means running at
    /// all would falsify the profile claim; `readiness_fail` means the process
    /// may run but must not report ready until the condition is cleared.
    pub const fn is_waivable(self) -> bool {
        matches!(self, Self::FindingError | Self::FindingWarn)
    }
}

/// Status of a finding in posture output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
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

/// The operator-declared `deployment` config block.
///
/// An absent profile means an undeclared deployment, which refuses startup. The
/// `multi_instance` flag is an operator declaration that the instance is one of
/// several sharing the same workload; it is never inferred.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<DeploymentProfile>,
    #[serde(default)]
    pub multi_instance: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<DeploymentWaiverConfig>,
    /// Operator declarations of assurance evidence the runtime cannot observe
    /// for itself. Absent declarations leave the corresponding gates active.
    #[serde(default)]
    pub evidence: DeploymentEvidenceConfig,
}

impl DeploymentConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Operator-asserted assurance evidence for conditions the runtime cannot
/// observe directly. Each flag defaults to `false`, meaning "no evidence
/// declared", which keeps the corresponding gate active until the operator
/// asserts the control is in place out of band.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentEvidenceConfig {
    /// Operator asserts audit log events are shipped off-host (for example to
    /// a log aggregator or SIEM) so a local file sink does not cap retention.
    #[serde(default)]
    pub audit_offhost_shipping: bool,
}

/// One operator-configured waiver.
///
/// A waiver names exactly one finding id, a free-text reason, and a mandatory
/// expiry date (`YYYY-MM-DD`). Reasons must not contain secrets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentWaiverConfig {
    pub finding: String,
    pub reason: String,
    pub expires: String,
}

/// Errors raised while validating the deployment block at config load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentConfigError {
    #[error("deployment.waivers[{index}].finding must not be empty")]
    EmptyWaiverFinding { index: usize },
    #[error("deployment.waivers[{index}].reason must not be empty")]
    EmptyWaiverReason { index: usize },
    #[error("deployment.waivers[{index}].expires must be a YYYY-MM-DD date")]
    InvalidWaiverExpiry { index: usize },
    #[error(
        "deployment.waivers[{index}] waives finding '{finding}', which is a hard deployment gate and cannot be waived"
    )]
    HardGateNotWaivable { index: usize, finding: String },
    #[error(
        "deployment.waivers[{index}] waives unknown finding id '{finding}'; check the catalog"
    )]
    UnknownWaivedFinding { index: usize, finding: String },
}

impl DeploymentConfig {
    /// Validate the deployment block at config load.
    ///
    /// This checks waiver shape (non-empty fields, parseable expiry) and the
    /// hard rule that `startup_fail` and `readiness_fail` gates can never be
    /// waived under the declared profile. An undeclared profile still validates
    /// waiver shape here so typos are caught early; startup refusal is handled by
    /// gate evaluation.
    pub fn validate(&self) -> Result<(), DeploymentConfigError> {
        for (index, waiver) in self.waivers.iter().enumerate() {
            if waiver.finding.trim().is_empty() {
                return Err(DeploymentConfigError::EmptyWaiverFinding { index });
            }
            if waiver.reason.trim().is_empty() {
                return Err(DeploymentConfigError::EmptyWaiverReason { index });
            }
            if parse_iso_date(&waiver.expires).is_none() {
                return Err(DeploymentConfigError::InvalidWaiverExpiry { index });
            }
            let Some(gate) = gate_catalog().iter().find(|gate| gate.id == waiver.finding) else {
                return Err(DeploymentConfigError::UnknownWaivedFinding {
                    index,
                    finding: waiver.finding.clone(),
                });
            };
            if let Some(profile) = self.profile {
                if let Some(severity) = gate.severity_for(profile) {
                    if !severity.is_waivable() {
                        return Err(DeploymentConfigError::HardGateNotWaivable {
                            index,
                            finding: waiver.finding.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// Snapshot of the configuration facts every gate predicate reads.
///
/// Building this once keeps gate predicates pure and free of config-shape
/// knowledge, which makes the catalog easy to read and test.
#[derive(Debug, Clone, Default)]
pub struct GateInput {
    pub replay_in_memory: bool,
    pub federation_enabled: bool,
    pub oid4vci_preauth_enabled: bool,
    pub holder_proof_required: bool,
    pub wallet_facing: bool,
    pub multi_instance: bool,
    pub audit_sink_class_durable: bool,
    pub audit_retention_local_only: bool,
    pub source_insecure_url: bool,
    pub source_private_network_escape: bool,
    pub source_adapter_sidecar_without_expected_sidecar: bool,
    pub admin_shared_exposure: bool,
    pub openapi_public: bool,
    pub config_unsigned: bool,
    pub self_attestation_enabled: bool,
    pub transaction_token_anchor_configured: bool,
    pub transaction_token_sender_constrained: bool,
    pub source_binding_without_matching_policy: bool,
}

impl GateInput {
    /// True when any high-risk replay mode is declared. Federation, OID4VCI
    /// pre-authorized code, holder proof, wallet-facing flows, and declared
    /// multi-instance all rely on shared, durable replay decisions.
    pub fn high_risk_replay_mode(&self) -> bool {
        self.federation_enabled
            || self.oid4vci_preauth_enabled
            || self.holder_proof_required
            || self.wallet_facing
            || self.multi_instance
    }
}

/// A finding row in the catalog: an id and its severity under each profile that
/// binds it. A profile with no entry leaves the gate unbound.
struct Gate {
    id: &'static str,
    hosted_lab: Option<GateSeverity>,
    production: Option<GateSeverity>,
    evidence_grade: Option<GateSeverity>,
    /// Predicate over the gate input; true means the gate condition is met.
    condition: fn(&GateInput) -> bool,
}

impl Gate {
    fn severity_for(&self, profile: DeploymentProfile) -> Option<GateSeverity> {
        match profile {
            DeploymentProfile::Local => None,
            DeploymentProfile::HostedLab => self.hosted_lab,
            DeploymentProfile::Production => self.production,
            DeploymentProfile::EvidenceGrade => self.evidence_grade,
        }
    }
}

// Finding ids. Stable once shipped; consumers treat unknown ids as opaque.
pub const FINDING_REPLAY_IN_MEMORY_HIGH_RISK: &str = "notary.replay.in_memory_high_risk";
pub const FINDING_AUDIT_SINK_MISSING: &str = "notary.audit.sink_missing";
pub const FINDING_AUDIT_RETENTION_LOCAL_ONLY: &str = "notary.audit.retention_local_only";
pub const FINDING_SOURCE_INSECURE_URL: &str = "notary.source.insecure_url";
pub const FINDING_SOURCE_PRIVATE_NETWORK_ESCAPE: &str = "notary.source.private_network_escape";
pub const FINDING_SIDECAR_EXPECTED_MISSING: &str = "notary.sidecar.expected_sidecar_missing";
pub const FINDING_ADMIN_SHARED_EXPOSURE: &str = "notary.admin.shared_exposure";
pub const FINDING_OPENAPI_PUBLIC: &str = "notary.openapi.public";
pub const FINDING_CONFIG_UNSIGNED: &str = "notary.config.unsigned";
pub const FINDING_ASSISTED_ACCESS_TRANSACTION_TOKEN_ANCHOR_MISSING: &str =
    "notary.assisted_access.transaction_token_anchor_missing";
pub const FINDING_ASSISTED_ACCESS_SENDER_CONSTRAINT_MISSING: &str =
    "notary.assisted_access.sender_constraint_missing";
pub const FINDING_SOURCE_BINDING_NO_MATCHING_POLICY: &str =
    "notary.source_binding.no_matching_policy";

// Diagnostic finding ids emitted by the framework itself.
pub const FINDING_PROFILE_UNDECLARED: &str = "deployment.profile_undeclared";
pub const FINDING_WAIVER_EXPIRED: &str = "deployment.waiver_expired";

/// The severity `gate_id` binds under `profile`, or `None` if the gate is
/// unbound at that profile (including an undeclared profile) or `gate_id` is
/// unknown. Lets callers outside the gate-evaluation path (e.g. doctor
/// diagnostics) check whether a gate already covers a finding before also
/// reporting it explicitly.
pub fn gate_severity_for_profile(
    gate_id: &str,
    profile: Option<DeploymentProfile>,
) -> Option<GateSeverity> {
    let profile = profile?;
    gate_catalog()
        .iter()
        .find(|gate| gate.id == gate_id)
        .and_then(|gate| gate.severity_for(profile))
}

fn gate_catalog() -> &'static [Gate] {
    use GateSeverity::{FindingError, FindingWarn, ReadinessFail, StartupFail};
    &[
        // notary.replay.in_memory_high_risk: in-memory replay while a high-risk
        // mode is declared. (#206)
        Gate {
            id: FINDING_REPLAY_IN_MEMORY_HIGH_RISK,
            hosted_lab: Some(FindingError),
            production: Some(ReadinessFail),
            evidence_grade: Some(StartupFail),
            condition: |input| input.replay_in_memory && input.high_risk_replay_mode(),
        },
        // notary.audit.sink_missing: no durable, retained audit sink. (#207)
        Gate {
            id: FINDING_AUDIT_SINK_MISSING,
            hosted_lab: Some(FindingError),
            production: Some(StartupFail),
            evidence_grade: Some(StartupFail),
            condition: |input| !input.audit_sink_class_durable,
        },
        // notary.audit.retention_local_only: a local file sink caps retention
        // and an attacker with host access can destroy audit evidence, unless
        // the operator attests logs are shipped off-host. stdout and syslog
        // are exempt: their retention is owned by the orchestrator log
        // pipeline or the syslog daemon's own forwarding surface.
        Gate {
            id: FINDING_AUDIT_RETENTION_LOCAL_ONLY,
            hosted_lab: None,
            production: Some(FindingWarn),
            evidence_grade: Some(StartupFail),
            condition: |input| input.audit_retention_local_only,
        },
        // Risky-but-legal defaults, surfaced as profile-bound findings. (#208)
        Gate {
            id: FINDING_SOURCE_INSECURE_URL,
            hosted_lab: Some(FindingError),
            production: Some(ReadinessFail),
            evidence_grade: Some(StartupFail),
            condition: |input| input.source_insecure_url,
        },
        Gate {
            id: FINDING_SOURCE_PRIVATE_NETWORK_ESCAPE,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(FindingError),
            condition: |input| input.source_private_network_escape,
        },
        Gate {
            id: FINDING_SIDECAR_EXPECTED_MISSING,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(ReadinessFail),
            condition: |input| input.source_adapter_sidecar_without_expected_sidecar,
        },
        Gate {
            id: FINDING_ADMIN_SHARED_EXPOSURE,
            hosted_lab: Some(FindingError),
            production: Some(ReadinessFail),
            evidence_grade: Some(StartupFail),
            condition: |input| input.admin_shared_exposure,
        },
        Gate {
            id: FINDING_OPENAPI_PUBLIC,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(FindingError),
            condition: |input| input.openapi_public,
        },
        Gate {
            id: FINDING_CONFIG_UNSIGNED,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(StartupFail),
            condition: |input| input.config_unsigned,
        },
        Gate {
            id: FINDING_ASSISTED_ACCESS_TRANSACTION_TOKEN_ANCHOR_MISSING,
            hosted_lab: Some(FindingError),
            production: Some(ReadinessFail),
            evidence_grade: Some(StartupFail),
            condition: |input| {
                input.self_attestation_enabled && !input.transaction_token_anchor_configured
            },
        },
        Gate {
            id: FINDING_ASSISTED_ACCESS_SENDER_CONSTRAINT_MISSING,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(ReadinessFail),
            condition: |input| {
                input.transaction_token_anchor_configured
                    && !input.transaction_token_sender_constrained
            },
        },
        // notary.source_binding.no_matching_policy: a claim source binding
        // declares no matching policy_id and no context-constraint gates, so
        // resolution falls back to unrestricted, identifier-only matching
        // (spec RS-DM-CLAIM). Resolution behavior is unchanged and
        // spec-conformant, so local/hosted_lab stay quiet; production nags,
        // evidence_grade treats it as an error. Both bound tiers are
        // waivable: a waiver is the sanctioned way to accept the fallback
        // deliberately. (#171)
        Gate {
            id: FINDING_SOURCE_BINDING_NO_MATCHING_POLICY,
            hosted_lab: None,
            production: Some(FindingWarn),
            evidence_grade: Some(FindingError),
            condition: |input| input.source_binding_without_matching_policy,
        },
    ]
}

/// A finding produced by gate evaluation, ready to render into posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedFinding {
    pub id: String,
    pub severity: GateSeverity,
    pub status: DeploymentFindingStatus,
    pub waiver: Option<EvaluatedWaiver>,
}

/// An active waiver echoed into posture so Trust Operations can review it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedWaiver {
    pub finding: String,
    pub reason: String,
    pub expires: String,
}

/// The full result of evaluating gates for a declared profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateEvaluation {
    /// Finding ids whose effect is `startup_fail` (never waived). A non-empty
    /// list means the process must refuse to start.
    pub startup_failures: Vec<String>,
    /// Finding ids whose effect is `readiness_fail`. The process runs but
    /// readiness reports not-ready.
    pub readiness_failures: Vec<String>,
    /// Findings to render into posture, both active and waived.
    pub findings: Vec<EvaluatedFinding>,
    /// Active waivers, including ones whose gate is not currently triggered.
    pub active_waivers: Vec<EvaluatedWaiver>,
}

/// Evaluate the gate catalog for a configuration snapshot.
///
/// `today` is the date used to decide whether a waiver has expired, passed in
/// so callers and tests can be deterministic. An undeclared profile (`None`)
/// emits `deployment.profile_undeclared` as a startup failure.
pub fn evaluate_gates(
    profile: Option<DeploymentProfile>,
    input: &GateInput,
    waivers: &[DeploymentWaiverConfig],
    today: &str,
) -> GateEvaluation {
    let Some(profile) = profile else {
        return GateEvaluation {
            startup_failures: vec![FINDING_PROFILE_UNDECLARED.to_string()],
            readiness_failures: Vec::new(),
            findings: vec![EvaluatedFinding {
                id: FINDING_PROFILE_UNDECLARED.to_string(),
                severity: GateSeverity::StartupFail,
                status: DeploymentFindingStatus::Active,
                waiver: None,
            }],
            active_waivers: Vec::new(),
        };
    };

    let mut evaluation = GateEvaluation::default();
    let mut waived_findings: Vec<&DeploymentWaiverConfig> = Vec::new();

    // An expired waiver stops suppressing its finding and additionally emits a
    // diagnostic error finding so Trust Operations sees the lapse.
    for waiver in waivers {
        if waiver_is_expired(&waiver.expires, today) {
            evaluation.findings.push(EvaluatedFinding {
                id: FINDING_WAIVER_EXPIRED.to_string(),
                severity: GateSeverity::FindingError,
                status: DeploymentFindingStatus::Active,
                waiver: Some(EvaluatedWaiver {
                    finding: waiver.finding.clone(),
                    reason: waiver.reason.clone(),
                    expires: waiver.expires.clone(),
                }),
            });
        } else {
            let Some(severity) = gate_catalog()
                .iter()
                .find(|gate| gate.id == waiver.finding)
                .and_then(|gate| gate.severity_for(profile))
            else {
                continue;
            };
            if !severity.is_waivable() {
                continue;
            }
            waived_findings.push(waiver);
            evaluation.active_waivers.push(EvaluatedWaiver {
                finding: waiver.finding.clone(),
                reason: waiver.reason.clone(),
                expires: waiver.expires.clone(),
            });
        }
    }

    for gate in gate_catalog() {
        let Some(severity) = gate.severity_for(profile) else {
            continue;
        };
        if !(gate.condition)(input) {
            continue;
        }

        // A waiver only suppresses waivable severities. startup_fail is never
        // waivable, so even an active waiver leaves it as a hard failure.
        let active_waiver = if severity.is_waivable() {
            waived_findings
                .iter()
                .find(|waiver| waiver.finding == gate.id)
                .copied()
        } else {
            None
        };

        if let Some(waiver) = active_waiver {
            evaluation.findings.push(EvaluatedFinding {
                id: gate.id.to_string(),
                severity,
                status: DeploymentFindingStatus::Waived,
                waiver: Some(EvaluatedWaiver {
                    finding: waiver.finding.clone(),
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
        evaluation.findings.push(EvaluatedFinding {
            id: gate.id.to_string(),
            severity,
            status: DeploymentFindingStatus::Active,
            waiver: None,
        });
    }

    evaluation
}

/// Parse a strict `YYYY-MM-DD` date into a comparable tuple.
///
/// Lexicographic string comparison of `YYYY-MM-DD` dates is equivalent to
/// chronological order, so callers compare the raw strings; this function only
/// validates the shape and ranges.
fn parse_iso_date(value: &str) -> Option<(u16, u8, u8)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: u16 = value.get(0..4)?.parse().ok()?;
    let month: u8 = value.get(5..7)?.parse().ok()?;
    let day: u8 = value.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// A waiver is expired once its expiry date is strictly before today.
fn waiver_is_expired(expires: &str, today: &str) -> bool {
    match (parse_iso_date(expires), parse_iso_date(today)) {
        (Some(_), Some(_)) => expires < today,
        // An unparseable expiry was rejected at config load; treat it as
        // expired here so a bad value never silently suppresses a finding.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiver(finding: &str, expires: &str) -> DeploymentWaiverConfig {
        DeploymentWaiverConfig {
            finding: finding.to_string(),
            reason: "synthetic test waiver reason".to_string(),
            expires: expires.to_string(),
        }
    }

    fn high_risk_in_memory_input() -> GateInput {
        GateInput {
            replay_in_memory: true,
            federation_enabled: true,
            audit_sink_class_durable: true,
            ..GateInput::default()
        }
    }

    #[test]
    fn undeclared_profile_is_startup_failure() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(None, &input, &[], "2026-06-13");
        assert_eq!(
            evaluation.startup_failures,
            vec![FINDING_PROFILE_UNDECLARED.to_string()]
        );
        assert!(evaluation.readiness_failures.is_empty());
        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(evaluation.findings[0].id, FINDING_PROFILE_UNDECLARED);
        assert_eq!(evaluation.findings[0].severity, GateSeverity::StartupFail);
    }

    #[test]
    fn local_profile_binds_no_gates() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(Some(DeploymentProfile::Local), &input, &[], "2026-06-13");
        assert!(evaluation.startup_failures.is_empty());
        assert!(evaluation.readiness_failures.is_empty());
        assert!(evaluation.findings.is_empty());
    }

    #[test]
    fn evidence_grade_in_memory_high_risk_is_startup_fail() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::EvidenceGrade),
            &input,
            &[],
            "2026-06-13",
        );
        assert!(evaluation
            .startup_failures
            .contains(&FINDING_REPLAY_IN_MEMORY_HIGH_RISK.to_string()));
    }

    #[test]
    fn production_in_memory_high_risk_is_readiness_fail() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[],
            "2026-06-13",
        );
        assert!(evaluation
            .readiness_failures
            .contains(&FINDING_REPLAY_IN_MEMORY_HIGH_RISK.to_string()));
        assert!(evaluation.startup_failures.is_empty());
    }

    #[test]
    fn hosted_lab_high_risk_is_waivable_finding_error() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::HostedLab),
            &input,
            &[],
            "2026-06-13",
        );
        let finding = evaluation
            .findings
            .iter()
            .find(|f| f.id == FINDING_REPLAY_IN_MEMORY_HIGH_RISK)
            .expect("high-risk finding present");
        assert_eq!(finding.severity, GateSeverity::FindingError);
        assert_eq!(finding.status, DeploymentFindingStatus::Active);
    }

    #[test]
    fn waiver_suppresses_waivable_finding_and_reports_waived() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::HostedLab),
            &input,
            &[waiver(FINDING_REPLAY_IN_MEMORY_HIGH_RISK, "2099-01-01")],
            "2026-06-13",
        );
        let finding = evaluation
            .findings
            .iter()
            .find(|f| f.id == FINDING_REPLAY_IN_MEMORY_HIGH_RISK)
            .expect("waived finding present");
        assert_eq!(finding.status, DeploymentFindingStatus::Waived);
        assert!(finding.waiver.is_some());
        assert_eq!(evaluation.active_waivers.len(), 1);
    }

    #[test]
    fn expired_waiver_re_triggers_finding_and_emits_waiver_expired() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[waiver(FINDING_REPLAY_IN_MEMORY_HIGH_RISK, "2020-01-01")],
            "2026-06-13",
        );
        // The gate re-triggers at full severity.
        assert!(evaluation
            .readiness_failures
            .contains(&FINDING_REPLAY_IN_MEMORY_HIGH_RISK.to_string()));
        // The expiry diagnostic is emitted.
        assert!(evaluation
            .findings
            .iter()
            .any(|f| f.id == FINDING_WAIVER_EXPIRED && f.severity == GateSeverity::FindingError));
        // The expired waiver is not active.
        assert!(evaluation.active_waivers.is_empty());
    }

    #[test]
    fn startup_fail_gate_is_not_waivable_even_with_active_waiver() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::EvidenceGrade),
            &input,
            &[waiver(FINDING_REPLAY_IN_MEMORY_HIGH_RISK, "2099-01-01")],
            "2026-06-13",
        );
        assert!(evaluation
            .startup_failures
            .contains(&FINDING_REPLAY_IN_MEMORY_HIGH_RISK.to_string()));
    }

    #[test]
    fn readiness_fail_gate_is_not_waivable_even_with_active_waiver() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[waiver(FINDING_REPLAY_IN_MEMORY_HIGH_RISK, "2099-01-01")],
            "2026-06-13",
        );
        assert!(evaluation
            .readiness_failures
            .contains(&FINDING_REPLAY_IN_MEMORY_HIGH_RISK.to_string()));
        let finding = evaluation
            .findings
            .iter()
            .find(|finding| finding.id == FINDING_REPLAY_IN_MEMORY_HIGH_RISK)
            .expect("high-risk replay finding exists");
        assert_eq!(finding.status, DeploymentFindingStatus::Active);
        assert!(evaluation.active_waivers.is_empty());
    }

    #[test]
    fn validate_rejects_waiver_for_hard_startup_gate() {
        let config = DeploymentConfig {
            profile: Some(DeploymentProfile::EvidenceGrade),
            multi_instance: false,
            waivers: vec![waiver(FINDING_AUDIT_SINK_MISSING, "2099-01-01")],
            evidence: DeploymentEvidenceConfig::default(),
        };
        let error = config.validate().expect_err("startup_fail waiver rejected");
        assert!(matches!(
            error,
            DeploymentConfigError::HardGateNotWaivable { .. }
        ));
    }

    #[test]
    fn validate_rejects_waiver_for_hard_readiness_gate() {
        let config = DeploymentConfig {
            profile: Some(DeploymentProfile::Production),
            multi_instance: false,
            waivers: vec![waiver(FINDING_REPLAY_IN_MEMORY_HIGH_RISK, "2099-01-01")],
            evidence: DeploymentEvidenceConfig::default(),
        };
        let error = config
            .validate()
            .expect_err("readiness_fail waiver rejected");
        assert!(matches!(
            error,
            DeploymentConfigError::HardGateNotWaivable { .. }
        ));
    }

    #[test]
    fn validate_rejects_unknown_waived_finding() {
        let config = DeploymentConfig {
            profile: Some(DeploymentProfile::Production),
            multi_instance: false,
            waivers: vec![waiver("notary.made.up", "2099-01-01")],
            evidence: DeploymentEvidenceConfig::default(),
        };
        let error = config.validate().expect_err("unknown finding rejected");
        assert!(matches!(
            error,
            DeploymentConfigError::UnknownWaivedFinding { .. }
        ));
    }

    #[test]
    fn validate_rejects_missing_or_malformed_expiry() {
        let config = DeploymentConfig {
            profile: Some(DeploymentProfile::Production),
            multi_instance: false,
            waivers: vec![waiver(FINDING_OPENAPI_PUBLIC, "not-a-date")],
            evidence: DeploymentEvidenceConfig::default(),
        };
        let error = config.validate().expect_err("malformed expiry rejected");
        assert!(matches!(
            error,
            DeploymentConfigError::InvalidWaiverExpiry { .. }
        ));
    }

    #[test]
    fn audit_sink_missing_binds_startup_fail_under_production() {
        let input = GateInput {
            audit_sink_class_durable: false,
            ..GateInput::default()
        };
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[],
            "2026-06-13",
        );
        assert!(evaluation
            .startup_failures
            .contains(&FINDING_AUDIT_SINK_MISSING.to_string()));
    }

    #[test]
    fn audit_sink_durable_clears_the_gate() {
        let input = GateInput {
            audit_sink_class_durable: true,
            ..GateInput::default()
        };
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[],
            "2026-06-13",
        );
        assert!(evaluation.startup_failures.is_empty());
        assert!(evaluation.findings.is_empty());
    }

    #[test]
    fn audit_retention_local_only_binds_finding_warn_under_production() {
        let input = GateInput {
            audit_sink_class_durable: true,
            audit_retention_local_only: true,
            ..GateInput::default()
        };
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[],
            "2026-06-13",
        );
        let finding = evaluation
            .findings
            .iter()
            .find(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY)
            .expect("retention finding present under production");
        assert_eq!(finding.severity, GateSeverity::FindingWarn);
        assert_eq!(finding.status, DeploymentFindingStatus::Active);
        assert!(evaluation.startup_failures.is_empty());
        assert!(evaluation.readiness_failures.is_empty());
    }

    #[test]
    fn audit_retention_local_only_binds_startup_fail_under_evidence_grade() {
        let input = GateInput {
            audit_sink_class_durable: true,
            audit_retention_local_only: true,
            ..GateInput::default()
        };
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::EvidenceGrade),
            &input,
            &[],
            "2026-06-13",
        );
        let finding = evaluation
            .findings
            .iter()
            .find(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY)
            .expect("retention finding present under evidence_grade");
        assert_eq!(finding.severity, GateSeverity::StartupFail);
        assert_eq!(
            evaluation.startup_failures,
            vec![FINDING_AUDIT_RETENTION_LOCAL_ONLY.to_string()]
        );
        assert!(evaluation.readiness_failures.is_empty());
    }

    #[test]
    fn audit_retention_local_only_is_unbound_under_local_and_hosted_lab() {
        let input = GateInput {
            audit_sink_class_durable: true,
            audit_retention_local_only: true,
            ..GateInput::default()
        };
        for profile in [DeploymentProfile::Local, DeploymentProfile::HostedLab] {
            let evaluation = evaluate_gates(Some(profile), &input, &[], "2026-06-13");
            assert!(
                !evaluation
                    .findings
                    .iter()
                    .any(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY),
                "retention finding must be unbound under profile '{}'",
                profile.as_str()
            );
        }
    }

    #[test]
    fn audit_retention_local_only_absent_when_condition_not_met() {
        let input = GateInput {
            audit_sink_class_durable: true,
            audit_retention_local_only: false,
            ..GateInput::default()
        };
        for profile in [
            DeploymentProfile::Production,
            DeploymentProfile::EvidenceGrade,
        ] {
            let evaluation = evaluate_gates(Some(profile), &input, &[], "2026-06-13");
            assert!(
                !evaluation
                    .findings
                    .iter()
                    .any(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY),
                "retention finding must be absent under profile '{}' when unattested sink is not local-only",
                profile.as_str()
            );
        }
    }

    #[test]
    fn audit_retention_local_only_waiver_suppresses_production_finding() {
        let input = GateInput {
            audit_sink_class_durable: true,
            audit_retention_local_only: true,
            ..GateInput::default()
        };
        let evaluation = evaluate_gates(
            Some(DeploymentProfile::Production),
            &input,
            &[waiver(FINDING_AUDIT_RETENTION_LOCAL_ONLY, "2099-01-01")],
            "2026-06-13",
        );
        let finding = evaluation
            .findings
            .iter()
            .find(|f| f.id == FINDING_AUDIT_RETENTION_LOCAL_ONLY)
            .expect("waived retention finding present");
        assert_eq!(finding.status, DeploymentFindingStatus::Waived);
        assert!(finding.waiver.is_some());
    }

    #[test]
    fn deployment_evidence_rejects_unknown_field() {
        let result: Result<DeploymentConfig, _> = serde_json::from_str(
            r#"{ "evidence": { "audit_offhost_shipping": true, "made_up": true } }"#,
        );
        assert!(result.is_err());
    }

    // Gate-binding tests for the #208 risky-but-legal findings.
    //
    // Each case pairs a triggering GateInput with the expected severity per
    // profile, and a non-triggering GateInput that must produce no finding.
    // All three bound profiles (hosted_lab, production, evidence_grade) are
    // checked; local is skipped because it binds no gates.

    struct GateCase {
        id: &'static str,
        triggering: GateInput,
        non_triggering: GateInput,
        hosted_lab: GateSeverity,
        production: GateSeverity,
        evidence_grade: GateSeverity,
    }

    fn gate_cases() -> Vec<GateCase> {
        vec![
            GateCase {
                id: FINDING_SOURCE_INSECURE_URL,
                triggering: GateInput {
                    source_insecure_url: true,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    source_insecure_url: false,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingError,
                production: GateSeverity::ReadinessFail,
                evidence_grade: GateSeverity::StartupFail,
            },
            GateCase {
                id: FINDING_SOURCE_PRIVATE_NETWORK_ESCAPE,
                triggering: GateInput {
                    source_private_network_escape: true,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    source_private_network_escape: false,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingWarn,
                production: GateSeverity::FindingError,
                evidence_grade: GateSeverity::FindingError,
            },
            GateCase {
                id: FINDING_SIDECAR_EXPECTED_MISSING,
                triggering: GateInput {
                    source_adapter_sidecar_without_expected_sidecar: true,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    source_adapter_sidecar_without_expected_sidecar: false,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingWarn,
                production: GateSeverity::FindingError,
                evidence_grade: GateSeverity::ReadinessFail,
            },
            GateCase {
                id: FINDING_ADMIN_SHARED_EXPOSURE,
                triggering: GateInput {
                    admin_shared_exposure: true,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    admin_shared_exposure: false,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingError,
                production: GateSeverity::ReadinessFail,
                evidence_grade: GateSeverity::StartupFail,
            },
            GateCase {
                id: FINDING_OPENAPI_PUBLIC,
                triggering: GateInput {
                    openapi_public: true,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    openapi_public: false,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingWarn,
                production: GateSeverity::FindingError,
                evidence_grade: GateSeverity::FindingError,
            },
            GateCase {
                id: FINDING_CONFIG_UNSIGNED,
                triggering: GateInput {
                    config_unsigned: true,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    config_unsigned: false,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingWarn,
                production: GateSeverity::FindingError,
                evidence_grade: GateSeverity::StartupFail,
            },
            GateCase {
                id: FINDING_ASSISTED_ACCESS_TRANSACTION_TOKEN_ANCHOR_MISSING,
                triggering: GateInput {
                    self_attestation_enabled: true,
                    transaction_token_anchor_configured: false,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    self_attestation_enabled: true,
                    transaction_token_anchor_configured: true,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingError,
                production: GateSeverity::ReadinessFail,
                evidence_grade: GateSeverity::StartupFail,
            },
            GateCase {
                id: FINDING_ASSISTED_ACCESS_SENDER_CONSTRAINT_MISSING,
                triggering: GateInput {
                    transaction_token_anchor_configured: true,
                    transaction_token_sender_constrained: false,
                    ..GateInput::default()
                },
                non_triggering: GateInput {
                    transaction_token_anchor_configured: true,
                    transaction_token_sender_constrained: true,
                    ..GateInput::default()
                },
                hosted_lab: GateSeverity::FindingWarn,
                production: GateSeverity::FindingError,
                evidence_grade: GateSeverity::ReadinessFail,
            },
        ]
    }

    #[test]
    fn risky_default_findings_bind_correct_severity_per_profile() {
        for case in gate_cases() {
            for (profile, expected_severity) in [
                (DeploymentProfile::HostedLab, case.hosted_lab),
                (DeploymentProfile::Production, case.production),
                (DeploymentProfile::EvidenceGrade, case.evidence_grade),
            ] {
                let evaluation = evaluate_gates(Some(profile), &case.triggering, &[], "2026-06-13");

                // For startup_fail findings the finding also lands in
                // startup_failures; for readiness_fail it lands in
                // readiness_failures. Both paths still push into findings.
                let found = evaluation
                    .findings
                    .iter()
                    .find(|f| f.id == case.id)
                    .unwrap_or_else(|| {
                        panic!(
                            "expected finding '{}' under profile '{}' (triggering input)",
                            case.id,
                            profile.as_str()
                        )
                    });
                assert_eq!(
                    found.severity,
                    expected_severity,
                    "finding '{}' under profile '{}': expected severity {:?}, got {:?}",
                    case.id,
                    profile.as_str(),
                    expected_severity,
                    found.severity
                );

                // startup_fail and readiness_fail findings must also appear
                // in their respective hard-gate lists.
                match expected_severity {
                    GateSeverity::StartupFail => {
                        assert!(
                            evaluation.startup_failures.contains(&case.id.to_string()),
                            "finding '{}' under profile '{}' must be in startup_failures",
                            case.id,
                            profile.as_str()
                        );
                    }
                    GateSeverity::ReadinessFail => {
                        assert!(
                            evaluation.readiness_failures.contains(&case.id.to_string()),
                            "finding '{}' under profile '{}' must be in readiness_failures",
                            case.id,
                            profile.as_str()
                        );
                    }
                    GateSeverity::FindingError | GateSeverity::FindingWarn => {}
                }
            }
        }
    }

    #[test]
    fn risky_default_findings_absent_when_condition_not_met() {
        for case in gate_cases() {
            for profile in [
                DeploymentProfile::HostedLab,
                DeploymentProfile::Production,
                DeploymentProfile::EvidenceGrade,
            ] {
                let evaluation =
                    evaluate_gates(Some(profile), &case.non_triggering, &[], "2026-06-13");

                // The non-triggering input must not produce the finding.
                assert!(
                    !evaluation.findings.iter().any(|f| f.id == case.id),
                    "finding '{}' must be absent under profile '{}' with non-triggering input",
                    case.id,
                    profile.as_str()
                );
                assert!(
                    !evaluation.startup_failures.contains(&case.id.to_string()),
                    "finding '{}' must not be in startup_failures under profile '{}' (non-triggering)",
                    case.id,
                    profile.as_str()
                );
                assert!(
                    !evaluation.readiness_failures.contains(&case.id.to_string()),
                    "finding '{}' must not be in readiness_failures under profile '{}' (non-triggering)",
                    case.id,
                    profile.as_str()
                );
            }
        }
    }

    // Gate-binding table for #171: a source binding without a matching
    // policy is quiet under local/hosted_lab, a warn under production, and an
    // error under evidence_grade.
    #[test]
    fn source_binding_no_matching_policy_binds_correct_severity_per_profile() {
        let triggering = GateInput {
            source_binding_without_matching_policy: true,
            ..GateInput::default()
        };
        let non_triggering = GateInput {
            source_binding_without_matching_policy: false,
            ..GateInput::default()
        };
        let cases = [
            (DeploymentProfile::Local, None),
            (DeploymentProfile::HostedLab, None),
            (
                DeploymentProfile::Production,
                Some(GateSeverity::FindingWarn),
            ),
            (
                DeploymentProfile::EvidenceGrade,
                Some(GateSeverity::FindingError),
            ),
        ];
        for (profile, expected_severity) in cases {
            let evaluation = evaluate_gates(Some(profile), &triggering, &[], "2026-06-13");
            let found = evaluation
                .findings
                .iter()
                .find(|finding| finding.id == FINDING_SOURCE_BINDING_NO_MATCHING_POLICY);
            match expected_severity {
                Some(severity) => {
                    let finding = found.unwrap_or_else(|| {
                        panic!(
                            "expected finding '{}' under profile '{}'",
                            FINDING_SOURCE_BINDING_NO_MATCHING_POLICY,
                            profile.as_str()
                        )
                    });
                    assert_eq!(finding.severity, severity);
                }
                None => assert!(
                    found.is_none(),
                    "finding '{}' must be unbound under profile '{}'",
                    FINDING_SOURCE_BINDING_NO_MATCHING_POLICY,
                    profile.as_str()
                ),
            }

            let clear_evaluation =
                evaluate_gates(Some(profile), &non_triggering, &[], "2026-06-13");
            assert!(
                !clear_evaluation
                    .findings
                    .iter()
                    .any(|finding| finding.id == FINDING_SOURCE_BINDING_NO_MATCHING_POLICY),
                "finding '{}' must be absent under profile '{}' with non-triggering input",
                FINDING_SOURCE_BINDING_NO_MATCHING_POLICY,
                profile.as_str()
            );
        }
    }

    #[test]
    fn invalid_profile_string_fails_deserialization() {
        let result: Result<DeploymentConfig, _> = serde_json::from_str(r#"{ "profile": "prod" }"#);
        assert!(result.is_err());
    }

    #[test]
    fn iso_date_parser_accepts_valid_and_rejects_invalid() {
        assert!(parse_iso_date("2026-06-13").is_some());
        assert!(parse_iso_date("2026-13-01").is_none());
        assert!(parse_iso_date("2026-06-32").is_none());
        assert!(parse_iso_date("2026/06/13").is_none());
        assert!(parse_iso_date("26-06-13").is_none());
    }
}
