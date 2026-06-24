// SPDX-License-Identifier: Apache-2.0
//! Deployment profile gates.
//!
//! An operator declares one deployment profile in config. The profile is
//! never inferred from environment, hostname, or network position: it is an
//! explicit statement of the assurance level a deployment claims. Each gate
//! binds to a set of profiles and, when its condition holds on a declared
//! profile, contributes a finding at a defined severity.
//!
//! Severities map to three evaluation points:
//!
//! * `startup_fail`: the process refuses to start. Never waivable.
//! * `readiness_fail`: the readiness endpoint reports not-ready; the process
//!   keeps running.
//! * `finding_error` / `finding_warn`: a posture finding only.
//!
//! Finding-error and finding-warning gates can be suppressed by a config waiver
//! that names the finding, carries a free-text reason, and a mandatory expiry
//! date. A waived finding reports status `waived` instead of its severity
//! effect. An expired waiver stops suppressing the finding and additionally
//! raises `deployment.waiver_expired`. `startup_fail` and `readiness_fail` gates
//! are hard gates and are never waivable.
//!
//! When no profile is declared, no gates bind and the deployment keeps its
//! existing behavior exactly; a single `deployment.profile_undeclared` warn
//! finding is emitted so operators are nagged, not broken.

use registry_platform_ops::{
    self as platform_ops, AuditWritePolicy, ConfigSource, DeploymentProfile, DeploymentWaiver,
    Gate, GateEvaluation, GateSeverity, ProfileGateSeverities,
};
#[cfg(test)]
use registry_platform_ops::{DeploymentFinding, DeploymentFindingStatus};

use crate::config::{AuthMode, Config};

/// Finding id emitted when no deployment profile is declared.
pub const PROFILE_UNDECLARED: &str = "deployment.profile_undeclared";

/// Finding id emitted, in addition to the re-triggered gate, when a waiver
/// has passed its expiry date.
pub const WAIVER_EXPIRED: &str = "deployment.waiver_expired";

pub type WaiverInput = DeploymentWaiver;

/// Derived, profile-independent inputs that gate conditions read. The caller
/// projects these from the runtime config so gate evaluation stays a pure
/// function over plain facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentFacts {
    /// Admin routes are reachable on a non-loopback (public) bind.
    pub admin_public_exposure: bool,
    /// OpenAPI is served without authentication.
    pub openapi_public: bool,
    /// No ingress rate-limit evidence has been declared by the operator.
    pub rate_limit_evidence_missing: bool,
    /// OIDC auth is enabled.
    pub oidc_enabled: bool,
    /// OIDC `allowed_clients` is empty (any client accepted).
    pub oidc_allowlist_empty: bool,
    /// API-key auth mode is active.
    pub api_key_mode: bool,
    /// No API-key rotation evidence has been declared by the operator.
    pub api_key_rotation_evidence_missing: bool,
    /// Config is a local YAML file rather than a signed governed bundle.
    pub config_unsigned: bool,
    /// The audit write policy is availability-first (best effort).
    pub audit_best_effort: bool,
}

use GateSeverity::{FindingError, FindingWarn, ReadinessFail, StartupFail};

/// The relay findings catalog. Order is stable so posture output is
/// deterministic.
const GATES: &[Gate<DeploymentFacts>] = &[
    Gate {
        id: "relay.admin.public_exposure",
        condition: |facts| facts.admin_public_exposure,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(FindingError),
            production: Some(ReadinessFail),
            evidence_grade: Some(StartupFail),
        },
    },
    Gate {
        id: "relay.openapi.public",
        condition: |facts| facts.openapi_public,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(FindingError),
        },
    },
    Gate {
        id: "relay.ingress.rate_limit_missing",
        condition: |facts| facts.rate_limit_evidence_missing,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(FindingError),
        },
    },
    Gate {
        id: "relay.oidc.client_allowlist_empty",
        condition: |facts| facts.oidc_enabled && facts.oidc_allowlist_empty,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(ReadinessFail),
        },
    },
    Gate {
        id: "relay.auth.api_key_no_rotation_evidence",
        condition: |facts| facts.api_key_mode && facts.api_key_rotation_evidence_missing,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(FindingError),
        },
    },
    Gate {
        id: "relay.config.unsigned",
        condition: |facts| facts.config_unsigned,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(FindingWarn),
            production: Some(FindingError),
            evidence_grade: Some(StartupFail),
        },
    },
    Gate {
        id: "relay.audit.best_effort",
        condition: |facts| facts.audit_best_effort,
        // The natural hosted_lab binding for a best-effort audit policy is an
        // info-level finding, but the shared `GateSeverity` vocabulary has no
        // `info` level. Binding it at `finding_warn` here would overstate the
        // concern for a lab, so the hosted_lab binding is intentionally omitted
        // until the shared severity vocabulary gains an info level (a cross-repo
        // vocabulary decision tracked outside this catalog).
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: None,
            production: Some(FindingWarn),
            evidence_grade: Some(ReadinessFail),
        },
    },
];

/// Evaluate the relay gate catalog.
///
/// `today` is the current date in `YYYY-MM-DD` form.
pub fn evaluate(
    profile: Option<DeploymentProfile>,
    facts: &DeploymentFacts,
    waivers: &[WaiverInput],
    today: &str,
) -> GateEvaluation {
    platform_ops::evaluate(profile, GATES, facts, waivers, today)
}

/// Project the runtime config into the profile-independent facts the gates
/// read.
///
/// `config_source` is the provenance source of the loaded config: a signed
/// governed bundle clears `relay.config.unsigned`; a local YAML file does not,
/// and neither does unknown provenance (which fails closed as unsigned).
pub fn facts_from_config(config: &Config, config_source: ConfigSource) -> DeploymentFacts {
    DeploymentFacts {
        admin_public_exposure: admin_public_exposure(config),
        openapi_public: !config.server.openapi_requires_auth,
        rate_limit_evidence_missing: !config.deployment.evidence.ingress_rate_limit,
        oidc_enabled: config.auth.mode == AuthMode::Oidc,
        oidc_allowlist_empty: config
            .auth
            .oidc
            .as_ref()
            .map(|oidc| oidc.allowed_clients.is_empty())
            .unwrap_or(true),
        api_key_mode: config.auth.mode == AuthMode::ApiKey,
        api_key_rotation_evidence_missing: !config.deployment.evidence.api_key_rotation,
        // Only a genuine signed bundle clears `relay.config.unsigned`. A local
        // file is unsigned, and so is unknown provenance: an unrecognized source
        // must fail closed rather than silently clear the gate.
        config_unsigned: !matches!(
            config_source,
            ConfigSource::SignedBundleFile | ConfigSource::SignedBundleEndpoint
        ),
        audit_best_effort: config.audit.write_policy == AuditWritePolicy::AvailabilityFirst,
    }
}

/// Admin routes are "publicly exposed" when the admin listener is bound to a
/// non-loopback address, making it reachable beyond the local host. An absent
/// admin listener or a loopback bind is not an exposure.
fn admin_public_exposure(config: &Config) -> bool {
    config
        .server
        .admin_bind
        .is_some_and(|addr| !addr.ip().is_loopback())
}

/// Project the declared config waivers into the evaluation input shape.
pub fn waivers_from_config(config: &Config) -> Vec<WaiverInput> {
    config
        .deployment
        .waivers
        .iter()
        .map(|waiver| WaiverInput {
            finding: waiver.finding.clone(),
            reason: waiver.reason.clone(),
            expires: waiver.expires.clone(),
        })
        .collect()
}

/// Today's date in `YYYY-MM-DD` (UTC), used to compare against waiver expiry.
pub fn today_utc() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    let format = Iso8601::DATE;
    OffsetDateTime::now_utc()
        .date()
        .format(&format)
        .expect("ISO 8601 date formats")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUTURE: &str = "2999-01-01";
    const PAST: &str = "2000-01-01";
    const TODAY: &str = "2026-06-13";

    /// Facts with no condition triggering. Each gate test flips exactly the
    /// fact it cares about.
    fn clean_facts() -> DeploymentFacts {
        DeploymentFacts {
            admin_public_exposure: false,
            openapi_public: false,
            rate_limit_evidence_missing: false,
            oidc_enabled: false,
            oidc_allowlist_empty: false,
            api_key_mode: false,
            api_key_rotation_evidence_missing: false,
            config_unsigned: false,
            audit_best_effort: false,
        }
    }

    fn finding_ids(evaluation: &GateEvaluation) -> Vec<String> {
        evaluation.findings.iter().map(|f| f.id.clone()).collect()
    }

    fn finding<'a>(evaluation: &'a GateEvaluation, id: &str) -> &'a DeploymentFinding {
        evaluation
            .findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("missing finding {id}"))
    }

    #[test]
    fn undeclared_profile_binds_zero_gates_and_nags() {
        // Even with every risky fact set, an undeclared profile binds nothing
        // and emits exactly the one warn finding.
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            openapi_public: true,
            rate_limit_evidence_missing: true,
            oidc_enabled: true,
            oidc_allowlist_empty: true,
            api_key_mode: true,
            api_key_rotation_evidence_missing: true,
            config_unsigned: true,
            audit_best_effort: true,
        };
        let evaluation = evaluate(None, &facts, &[], TODAY);
        assert_eq!(finding_ids(&evaluation), vec![PROFILE_UNDECLARED]);
        assert_eq!(
            finding(&evaluation, PROFILE_UNDECLARED).severity,
            FindingWarn
        );
        assert!(!evaluation.has_startup_failure());
        assert!(!evaluation.has_readiness_failure());
        assert!(evaluation.active_waivers.is_empty());
    }

    #[test]
    fn local_profile_binds_no_hard_gates_when_clean() {
        let evaluation = evaluate(Some(DeploymentProfile::Local), &clean_facts(), &[], TODAY);
        assert!(evaluation.findings.is_empty());
        assert!(!evaluation.has_startup_failure());
        assert!(!evaluation.has_readiness_failure());
    }

    #[test]
    fn local_profile_does_not_trigger_relay_gates() {
        // `local` binds no gates in the initial catalog; risky facts are
        // silent under it.
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            config_unsigned: true,
            ..clean_facts()
        };
        let evaluation = evaluate(Some(DeploymentProfile::Local), &facts, &[], TODAY);
        assert!(evaluation.findings.is_empty());
    }

    #[test]
    fn admin_public_exposure_escalates_across_profiles() {
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            ..clean_facts()
        };
        let id = "relay.admin.public_exposure";

        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert_eq!(finding(&hosted, id).severity, FindingError);
        assert!(!hosted.has_readiness_failure());

        let production = evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY);
        assert_eq!(finding(&production, id).severity, ReadinessFail);
        assert_eq!(production.readiness_failures, vec![id.to_string()]);

        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert_eq!(evidence.startup_failures, vec![id.to_string()]);
    }

    #[test]
    fn admin_public_exposure_silent_when_not_exposed() {
        // Non-triggering case across every bound profile.
        for profile in [
            DeploymentProfile::HostedLab,
            DeploymentProfile::Production,
            DeploymentProfile::EvidenceGrade,
        ] {
            let evaluation = evaluate(Some(profile), &clean_facts(), &[], TODAY);
            assert!(
                !finding_ids(&evaluation).contains(&"relay.admin.public_exposure".to_string()),
                "unexpected admin exposure finding under {profile:?}"
            );
        }
    }

    #[test]
    fn openapi_public_triggers_and_clears() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let id = "relay.openapi.public";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        // Non-triggering.
        let clean = evaluate(
            Some(DeploymentProfile::Production),
            &clean_facts(),
            &[],
            TODAY,
        );
        assert!(!finding_ids(&clean).contains(&id.to_string()));
    }

    #[test]
    fn rate_limit_missing_triggers_and_clears() {
        let facts = DeploymentFacts {
            rate_limit_evidence_missing: true,
            ..clean_facts()
        };
        let id = "relay.ingress.rate_limit_missing";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let clean = evaluate(
            Some(DeploymentProfile::Production),
            &clean_facts(),
            &[],
            TODAY,
        );
        assert!(!finding_ids(&clean).contains(&id.to_string()));
    }

    #[test]
    fn oidc_allowlist_empty_only_when_oidc_enabled() {
        let id = "relay.oidc.client_allowlist_empty";
        // Empty allowlist but OIDC disabled: no finding.
        let disabled = DeploymentFacts {
            oidc_enabled: false,
            oidc_allowlist_empty: true,
            ..clean_facts()
        };
        let evaluation = evaluate(Some(DeploymentProfile::Production), &disabled, &[], TODAY);
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));

        // OIDC enabled with empty allowlist: escalates.
        let enabled = DeploymentFacts {
            oidc_enabled: true,
            oidc_allowlist_empty: true,
            ..clean_facts()
        };
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &enabled, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &enabled, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &enabled, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, ReadinessFail);
        assert_eq!(evidence.readiness_failures, vec![id.to_string()]);
    }

    #[test]
    fn api_key_rotation_evidence_only_when_api_key_mode() {
        let id = "relay.auth.api_key_no_rotation_evidence";
        let not_api_key = DeploymentFacts {
            api_key_mode: false,
            api_key_rotation_evidence_missing: true,
            ..clean_facts()
        };
        let evaluation = evaluate(
            Some(DeploymentProfile::Production),
            &not_api_key,
            &[],
            TODAY,
        );
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));

        let api_key = DeploymentFacts {
            api_key_mode: true,
            api_key_rotation_evidence_missing: true,
            ..clean_facts()
        };
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &api_key, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &api_key, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
    }

    #[test]
    fn config_unsigned_startup_fails_under_evidence_grade() {
        let facts = DeploymentFacts {
            config_unsigned: true,
            ..clean_facts()
        };
        let id = "relay.config.unsigned";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert_eq!(evidence.startup_failures, vec![id.to_string()]);
    }

    #[test]
    fn audit_sink_missing_is_not_an_evaluated_gate() {
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            openapi_public: true,
            rate_limit_evidence_missing: true,
            oidc_enabled: true,
            oidc_allowlist_empty: true,
            api_key_mode: true,
            api_key_rotation_evidence_missing: true,
            config_unsigned: true,
            audit_best_effort: true,
        };

        for profile in [
            DeploymentProfile::HostedLab,
            DeploymentProfile::Production,
            DeploymentProfile::EvidenceGrade,
        ] {
            let evaluation = evaluate(Some(profile), &facts, &[], TODAY);
            assert!(
                !finding_ids(&evaluation).contains(&"relay.audit.sink_missing".to_string()),
                "unrepresentable audit sink absence must not be reported under {profile:?}"
            );
        }
    }

    #[test]
    fn audit_best_effort_binds_production_and_evidence_only() {
        let facts = DeploymentFacts {
            audit_best_effort: true,
            ..clean_facts()
        };
        let id = "relay.audit.best_effort";
        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert!(!finding_ids(&hosted).contains(&id.to_string()));
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, ReadinessFail);
        assert_eq!(evidence.readiness_failures, vec![id.to_string()]);
    }

    #[test]
    fn active_waiver_suppresses_finding_and_reports_waived() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.openapi.public".to_string(),
            reason: "synthetic test waiver".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        let f = finding(&evaluation, "relay.openapi.public");
        assert_eq!(f.status, DeploymentFindingStatus::Waived);
        assert_eq!(f.severity, FindingError);
        assert_eq!(
            f.waiver.as_ref().unwrap().reason,
            "synthetic test waiver".to_string()
        );
        // An active waiver is reported in the waivers list.
        assert_eq!(evaluation.active_waivers.len(), 1);
        assert_eq!(evaluation.active_waivers[0].finding, "relay.openapi.public");
        assert!(!finding_ids(&evaluation).contains(&WAIVER_EXPIRED.to_string()));
    }

    #[test]
    fn waiver_does_not_suppress_readiness_fail() {
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.admin.public_exposure".to_string(),
            reason: "synthetic readiness waiver".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        assert_eq!(
            finding(&evaluation, "relay.admin.public_exposure").status,
            DeploymentFindingStatus::Active
        );
        assert!(evaluation.has_readiness_failure());
        assert_eq!(evaluation.active_waivers.len(), 1);
        assert_eq!(
            evaluation.active_waivers[0].finding,
            "relay.admin.public_exposure"
        );
    }

    #[test]
    fn expired_waiver_retriggers_and_raises_waiver_expired() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.openapi.public".to_string(),
            reason: "synthetic expired waiver".to_string(),
            expires: PAST.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        // The underlying finding re-triggers as active at its real severity.
        let f = finding(&evaluation, "relay.openapi.public");
        assert_eq!(f.status, DeploymentFindingStatus::Active);
        assert_eq!(f.severity, FindingError);
        // The waiver no longer counts as active.
        assert!(evaluation.active_waivers.is_empty());
        // And a separate waiver_expired error is raised.
        assert_eq!(finding(&evaluation, WAIVER_EXPIRED).severity, FindingError);
    }

    #[test]
    fn startup_fail_is_never_waivable() {
        let facts = DeploymentFacts {
            config_unsigned: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.config.unsigned".to_string(),
            reason: "synthetic attempt to waive a startup gate".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(
            Some(DeploymentProfile::EvidenceGrade),
            &facts,
            &waivers,
            TODAY,
        );
        // The waiver is ignored for a startup_fail gate: the finding stays
        // active and startup still fails.
        let f = finding(&evaluation, "relay.config.unsigned");
        assert_eq!(f.status, DeploymentFindingStatus::Active);
        assert!(evaluation.has_startup_failure());
        // The waiver is, however, still listed as active for review; it simply
        // does not suppress the gate.
        assert_eq!(evaluation.active_waivers.len(), 1);
    }

    #[test]
    fn waiver_on_expiry_day_still_suppresses() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.openapi.public".to_string(),
            reason: "synthetic boundary waiver".to_string(),
            expires: TODAY.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        assert_eq!(
            finding(&evaluation, "relay.openapi.public").status,
            DeploymentFindingStatus::Waived
        );
    }

    fn minimal_config() -> Config {
        serde_saphyr::from_str(
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
"#,
        )
        .expect("config parses")
    }

    #[test]
    fn config_unsigned_fact_classifies_sources_fail_closed() {
        let config = minimal_config();
        // A local file is unsigned.
        assert!(facts_from_config(&config, ConfigSource::LocalFile).config_unsigned);
        // Unknown provenance fails closed: it counts as unsigned, so the
        // `relay.config.unsigned` gate fires rather than silently clearing.
        assert!(facts_from_config(&config, ConfigSource::Unknown).config_unsigned);
        // Only a genuine signed bundle clears the gate.
        assert!(!facts_from_config(&config, ConfigSource::SignedBundleFile).config_unsigned);
        assert!(!facts_from_config(&config, ConfigSource::SignedBundleEndpoint).config_unsigned);
    }
}
