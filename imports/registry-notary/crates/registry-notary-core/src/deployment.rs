// SPDX-License-Identifier: Apache-2.0
//! Operator-declared deployment profile and gate evaluation.
//!
//! A deployment profile is an explicit operator declaration of how a Notary
//! instance is deployed. It is never inferred from the environment label, the
//! hostname, or the network position. The profile binds a set of gates; each
//! gate inspects the running configuration and reports an effect at a defined
//! severity. Undeclared deployments bind no gates and keep their existing
//! behavior unchanged.

use registry_platform_ops::{self as platform_ops, DeploymentFinding, DeploymentWaiver, Gate};
pub use registry_platform_ops::{
    DeploymentFindingStatus, DeploymentProfile, GateEvaluation, GateSeverity, ProfileGateSeverities,
};
use serde::{Deserialize, Serialize};

/// The operator-declared `deployment` config block.
///
/// An absent block means an undeclared profile, which binds no gates. The
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
}

impl DeploymentConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
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
    /// waiver shape so typos are caught early.
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
    pub source_insecure_url: bool,
    pub source_private_network_escape: bool,
    pub source_adapter_sidecar_without_expected_sidecar: bool,
    pub admin_shared_exposure: bool,
    pub openapi_public: bool,
    pub config_unsigned: bool,
    pub self_attestation_enabled: bool,
    pub transaction_token_anchor_configured: bool,
    pub transaction_token_sender_constrained: bool,
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

const fn severities(
    hosted_lab: Option<GateSeverity>,
    production: Option<GateSeverity>,
    evidence_grade: Option<GateSeverity>,
) -> ProfileGateSeverities {
    ProfileGateSeverities {
        local: None,
        hosted_lab,
        production,
        evidence_grade,
    }
}

// Finding ids. Stable once shipped; consumers treat unknown ids as opaque.
pub const FINDING_REPLAY_IN_MEMORY_HIGH_RISK: &str = "notary.replay.in_memory_high_risk";
pub const FINDING_AUDIT_SINK_MISSING: &str = "notary.audit.sink_missing";
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

// Diagnostic finding ids emitted by the framework itself.
pub const FINDING_PROFILE_UNDECLARED: &str = "deployment.profile_undeclared";
pub const FINDING_WAIVER_EXPIRED: &str = "deployment.waiver_expired";

use GateSeverity::{FindingError, FindingWarn, ReadinessFail, StartupFail};

const GATE_CATALOG: &[Gate<GateInput>] = &[
    // notary.replay.in_memory_high_risk: in-memory replay while a high-risk
    // mode is declared. (#206)
    Gate {
        id: FINDING_REPLAY_IN_MEMORY_HIGH_RISK,
        condition: |input| input.replay_in_memory && input.high_risk_replay_mode(),
        severities: severities(Some(FindingError), Some(ReadinessFail), Some(StartupFail)),
    },
    // notary.audit.sink_missing: no durable, retained audit sink. (#207)
    Gate {
        id: FINDING_AUDIT_SINK_MISSING,
        condition: |input| !input.audit_sink_class_durable,
        severities: severities(Some(FindingError), Some(StartupFail), Some(StartupFail)),
    },
    // Risky-but-legal defaults, surfaced as profile-bound findings. (#208)
    Gate {
        id: FINDING_SOURCE_INSECURE_URL,
        condition: |input| input.source_insecure_url,
        severities: severities(Some(FindingError), Some(ReadinessFail), Some(StartupFail)),
    },
    Gate {
        id: FINDING_SOURCE_PRIVATE_NETWORK_ESCAPE,
        condition: |input| input.source_private_network_escape,
        severities: severities(Some(FindingWarn), Some(FindingError), Some(FindingError)),
    },
    Gate {
        id: FINDING_SIDECAR_EXPECTED_MISSING,
        condition: |input| input.source_adapter_sidecar_without_expected_sidecar,
        severities: severities(Some(FindingWarn), Some(FindingError), Some(ReadinessFail)),
    },
    Gate {
        id: FINDING_ADMIN_SHARED_EXPOSURE,
        condition: |input| input.admin_shared_exposure,
        severities: severities(Some(FindingError), Some(ReadinessFail), Some(StartupFail)),
    },
    Gate {
        id: FINDING_OPENAPI_PUBLIC,
        condition: |input| input.openapi_public,
        severities: severities(Some(FindingWarn), Some(FindingError), Some(FindingError)),
    },
    Gate {
        id: FINDING_CONFIG_UNSIGNED,
        condition: |input| input.config_unsigned,
        severities: severities(Some(FindingWarn), Some(FindingError), Some(StartupFail)),
    },
    Gate {
        id: FINDING_ASSISTED_ACCESS_TRANSACTION_TOKEN_ANCHOR_MISSING,
        condition: |input| {
            input.self_attestation_enabled && !input.transaction_token_anchor_configured
        },
        severities: severities(Some(FindingError), Some(ReadinessFail), Some(StartupFail)),
    },
    Gate {
        id: FINDING_ASSISTED_ACCESS_SENDER_CONSTRAINT_MISSING,
        condition: |input| {
            input.transaction_token_anchor_configured && !input.transaction_token_sender_constrained
        },
        severities: severities(Some(FindingWarn), Some(FindingError), Some(ReadinessFail)),
    },
];

fn gate_catalog() -> &'static [Gate<GateInput>] {
    GATE_CATALOG
}

pub type EvaluatedFinding = DeploymentFinding;
pub type EvaluatedWaiver = DeploymentWaiver;

/// Evaluate the gate catalog for a configuration snapshot.
///
/// `today` is the date used to decide whether a waiver has expired, passed in
/// so callers and tests can be deterministic. An undeclared profile (`None`)
/// binds no gates and emits the `deployment.profile_undeclared` warn finding.
pub fn evaluate_gates(
    profile: Option<DeploymentProfile>,
    input: &GateInput,
    waivers: &[DeploymentWaiverConfig],
    today: &str,
) -> GateEvaluation {
    let waivers = waivers
        .iter()
        .map(|waiver| DeploymentWaiver {
            finding: waiver.finding.clone(),
            reason: waiver.reason.clone(),
            expires: waiver.expires.clone(),
        })
        .collect::<Vec<_>>();
    platform_ops::evaluate(profile, gate_catalog(), input, &waivers, today)
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
    fn undeclared_profile_binds_no_gates_and_emits_diagnostic() {
        let input = high_risk_in_memory_input();
        let evaluation = evaluate_gates(None, &input, &[], "2026-06-13");
        assert!(evaluation.startup_failures.is_empty());
        assert!(evaluation.readiness_failures.is_empty());
        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(evaluation.findings[0].id, FINDING_PROFILE_UNDECLARED);
        assert_eq!(evaluation.findings[0].severity, GateSeverity::FindingWarn);
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
        assert_eq!(evaluation.active_waivers.len(), 1);
        assert_eq!(
            evaluation.active_waivers[0].finding,
            FINDING_REPLAY_IN_MEMORY_HIGH_RISK
        );
    }

    #[test]
    fn validate_rejects_waiver_for_hard_startup_gate() {
        let config = DeploymentConfig {
            profile: Some(DeploymentProfile::EvidenceGrade),
            multi_instance: false,
            waivers: vec![waiver(FINDING_AUDIT_SINK_MISSING, "2099-01-01")],
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
                    _ => {}
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

    #[test]
    fn invalid_profile_string_fails_deserialization() {
        let result: Result<DeploymentConfig, _> = serde_json::from_str(r#"{ "profile": "prod" }"#);
        assert!(result.is_err());
    }

    #[test]
    fn iso_date_parser_accepts_valid_and_rejects_invalid() {
        assert!(parse_iso_date("2026-06-13").is_some());
        assert!(parse_iso_date("2024-02-29").is_some());
        assert!(parse_iso_date("2026-13-01").is_none());
        assert!(parse_iso_date("2026-06-32").is_none());
        assert!(parse_iso_date("2026-02-31").is_none());
        assert!(parse_iso_date("2025-02-29").is_none());
        assert!(parse_iso_date("2026/06/13").is_none());
        assert!(parse_iso_date("26-06-13").is_none());
    }
}
