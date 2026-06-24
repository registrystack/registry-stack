use registry_platform_ops::{
    AuditAnchoring, AuditAssurance, AuditCheckpoints, AuditHashChain, AuditKeyedIntegrity,
    AuditRedactionMode, AuditRetentionOwner, AuditSinkClass, AuditWritePolicy, ComplianceFinding,
    ComplianceFindingKind, CompliancePosture, DeploymentFinding, DeploymentFindingStatus,
    DeploymentFindingWaiver, DeploymentProfile, DeploymentWaiver, Gate, GateSeverity,
    ProfileGateSeverities, POSTURE_SCHEMA_V1, PROFILE_UNDECLARED_FINDING_ID,
    WAIVER_EXPIRED_FINDING_ID,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("fixture parses as JSON")
}

fn posture_validator() -> jsonschema::Validator {
    let schema = parse(POSTURE_SCHEMA_V1);
    jsonschema::validator_for(&schema).expect("posture schema compiles")
}

fn assert_valid(validator: &jsonschema::Validator, instance: &Value) {
    let errors: Vec<_> = validator.iter_errors(instance).collect();
    assert!(
        errors.is_empty(),
        "expected valid posture, got errors: {errors:?}"
    );
}

fn assert_invalid(validator: &jsonschema::Validator, instance: &Value) {
    assert!(
        !validator.is_valid(instance),
        "expected invalid posture: {instance:#}"
    );
}

fn round_trip<T>(value: T, expected_json: Value)
where
    T: DeserializeOwned + Serialize + std::fmt::Debug + PartialEq,
{
    let encoded = serde_json::to_value(&value).expect("value serializes");
    assert_eq!(encoded, expected_json);
    let decoded: T = serde_json::from_value(encoded).expect("value deserializes");
    assert_eq!(decoded, value);
}

fn posture_with_profile_gates() -> Value {
    let mut posture = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    posture["deployment"] = json!({
        "profile": "production",
        "findings": [
            {
                "id": "audit.sink.missing",
                "severity": "finding_error",
                "status": "active"
            },
            {
                "id": "readiness.cache.degraded",
                "severity": "finding_warn",
                "status": "waived",
                "waiver": {
                    "reason": "temporary maintenance window",
                    "expires": "2026-07-01"
                }
            }
        ],
        "waivers": [
            {
                "finding": "readiness.cache.degraded",
                "reason": "temporary maintenance window",
                "expires": "2026-07-01"
            }
        ]
    });
    posture["audit"] = json!({
        "write_policy": "fail_closed_route_families",
        "redaction_mode": "redacted",
        "hash_chain": "retained",
        "keyed_integrity": "hmac",
        "sink_class": "file",
        "retention_owner": "operator",
        "checkpoints": "enabled",
        "anchoring": "external"
    });
    posture
}

#[test]
fn posture_schema_accepts_profile_gates_and_undeclared_profile() {
    let validator = posture_validator();
    assert_valid(&validator, &posture_with_profile_gates());

    let undeclared = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    assert_valid(&validator, &undeclared);
}

#[test]
fn posture_schema_rejects_unknown_profile_or_severity_and_missing_waiver_expiry() {
    let validator = posture_validator();

    let mut unknown_profile = posture_with_profile_gates();
    unknown_profile["deployment"]["profile"] = json!("pilot");
    assert_invalid(&validator, &unknown_profile);

    let mut unknown_severity = posture_with_profile_gates();
    unknown_severity["deployment"]["findings"][0]["severity"] = json!("critical");
    assert_invalid(&validator, &unknown_severity);

    let mut missing_expiry = posture_with_profile_gates();
    missing_expiry["deployment"]["waivers"][0]
        .as_object_mut()
        .expect("waiver is object")
        .remove("expires");
    assert_invalid(&validator, &missing_expiry);

    let mut invalid_expiry = posture_with_profile_gates();
    invalid_expiry["deployment"]["waivers"][0]["expires"] = json!("not-a-date");
    assert_invalid(&validator, &invalid_expiry);
}

#[test]
fn posture_profile_gate_types_round_trip_and_reject_unknown_closed_enums() {
    round_trip(DeploymentProfile::Local, json!("local"));
    round_trip(DeploymentProfile::HostedLab, json!("hosted_lab"));
    round_trip(DeploymentProfile::Production, json!("production"));
    round_trip(DeploymentProfile::EvidenceGrade, json!("evidence_grade"));

    round_trip(GateSeverity::StartupFail, json!("startup_fail"));
    round_trip(GateSeverity::ReadinessFail, json!("readiness_fail"));
    round_trip(GateSeverity::FindingError, json!("finding_error"));
    round_trip(GateSeverity::FindingWarn, json!("finding_warn"));

    round_trip(DeploymentFindingStatus::Active, json!("active"));
    round_trip(DeploymentFindingStatus::Waived, json!("waived"));

    assert!(serde_json::from_str::<DeploymentProfile>("\"pilot\"").is_err());
    assert!(serde_json::from_str::<GateSeverity>("\"critical\"").is_err());
}

#[test]
fn posture_profile_gate_structs_round_trip_and_accept_unknown_finding_ids() {
    round_trip(
        DeploymentFinding {
            id: "future.product.finding".to_string(),
            severity: GateSeverity::FindingWarn,
            status: DeploymentFindingStatus::Waived,
            waiver: Some(DeploymentFindingWaiver {
                reason: "operator approved temporary exception".to_string(),
                expires: "2026-07-01".to_string(),
            }),
        },
        json!({
            "id": "future.product.finding",
            "severity": "finding_warn",
            "status": "waived",
            "waiver": {
                "reason": "operator approved temporary exception",
                "expires": "2026-07-01"
            }
        }),
    );

    round_trip(
        DeploymentWaiver {
            finding: "future.product.finding".to_string(),
            reason: "operator approved temporary exception".to_string(),
            expires: "2026-07-01".to_string(),
        },
        json!({
            "finding": "future.product.finding",
            "reason": "operator approved temporary exception",
            "expires": "2026-07-01"
        }),
    );
}

#[test]
fn generic_gate_engine_uses_strict_waivers_and_framework_findings() {
    #[derive(Clone, Copy)]
    struct Facts {
        risky: bool,
        noisy: bool,
    }

    const CATALOG: &[Gate<Facts>] = &[
        Gate {
            id: "product.risky",
            condition: |facts| facts.risky,
            severities: ProfileGateSeverities {
                local: None,
                hosted_lab: Some(GateSeverity::FindingWarn),
                production: Some(GateSeverity::ReadinessFail),
                evidence_grade: Some(GateSeverity::StartupFail),
            },
        },
        Gate {
            id: "product.noisy",
            condition: |facts| facts.noisy,
            severities: ProfileGateSeverities {
                local: None,
                hosted_lab: Some(GateSeverity::FindingWarn),
                production: Some(GateSeverity::FindingWarn),
                evidence_grade: Some(GateSeverity::FindingError),
            },
        },
    ];

    let facts = Facts {
        risky: true,
        noisy: true,
    };
    let waivers = vec![
        DeploymentWaiver {
            finding: "product.risky".to_string(),
            reason: "not allowed to suppress readiness".to_string(),
            expires: "2026-07-01".to_string(),
        },
        DeploymentWaiver {
            finding: "product.noisy".to_string(),
            reason: "accepted temporary posture finding".to_string(),
            expires: "2026-07-01".to_string(),
        },
        DeploymentWaiver {
            finding: "product.expired".to_string(),
            reason: "stale exception".to_string(),
            expires: "2026-06-01".to_string(),
        },
    ];

    let evaluation = registry_platform_ops::evaluate(
        Some(DeploymentProfile::Production),
        CATALOG,
        &facts,
        &waivers,
        "2026-06-24",
    );

    assert_eq!(evaluation.readiness_failures, vec!["product.risky"]);
    assert!(evaluation.startup_failures.is_empty());
    assert_eq!(evaluation.active_waivers.len(), 2);
    assert_eq!(evaluation.findings[0].id, "product.risky");
    assert_eq!(
        evaluation.findings[0].status,
        DeploymentFindingStatus::Active
    );
    assert_eq!(evaluation.findings[1].id, "product.noisy");
    assert_eq!(
        evaluation.findings[1].status,
        DeploymentFindingStatus::Waived
    );
    assert_eq!(evaluation.findings[2].id, WAIVER_EXPIRED_FINDING_ID);

    let undeclared = registry_platform_ops::evaluate(None, CATALOG, &facts, &[], "2026-06-24");
    assert_eq!(undeclared.findings.len(), 1);
    assert_eq!(undeclared.findings[0].id, PROFILE_UNDECLARED_FINDING_ID);
    assert!(undeclared.startup_failures.is_empty());
    assert!(undeclared.readiness_failures.is_empty());
}

#[test]
fn generic_gate_engine_treats_impossible_waiver_dates_as_expired() {
    #[derive(Clone, Copy)]
    struct Facts {
        risky: bool,
    }

    const CATALOG: &[Gate<Facts>] = &[Gate {
        id: "product.risky",
        condition: |facts| facts.risky,
        severities: ProfileGateSeverities {
            local: None,
            hosted_lab: Some(GateSeverity::FindingWarn),
            production: Some(GateSeverity::FindingWarn),
            evidence_grade: Some(GateSeverity::FindingWarn),
        },
    }];

    for expires in ["2026-02-31", "2025-02-29"] {
        let evaluation = registry_platform_ops::evaluate(
            Some(DeploymentProfile::Production),
            CATALOG,
            &Facts { risky: true },
            &[DeploymentWaiver {
                finding: "product.risky".to_string(),
                reason: "invalid date must not suppress".to_string(),
                expires: expires.to_string(),
            }],
            "2026-02-01",
        );
        assert!(evaluation.active_waivers.is_empty());
        assert_eq!(evaluation.findings[0].id, "product.risky");
        assert_eq!(
            evaluation.findings[0].status,
            DeploymentFindingStatus::Active
        );
        assert_eq!(evaluation.findings[1].id, WAIVER_EXPIRED_FINDING_ID);
    }

    let leap_day = registry_platform_ops::evaluate(
        Some(DeploymentProfile::Production),
        CATALOG,
        &Facts { risky: true },
        &[DeploymentWaiver {
            finding: "product.risky".to_string(),
            reason: "valid leap day".to_string(),
            expires: "2024-02-29".to_string(),
        }],
        "2024-02-29",
    );
    assert_eq!(leap_day.active_waivers.len(), 1);
    assert_eq!(leap_day.findings[0].status, DeploymentFindingStatus::Waived);
}

#[test]
fn compliance_posture_types_round_trip_and_reuse_gate_vocabularies() {
    let empty = CompliancePosture::for_declared_regimes(Vec::<String>::new());
    assert_eq!(empty, None);

    let posture = CompliancePosture::for_declared_regimes(["gdpr"]).expect("gdpr posture");
    assert_eq!(posture.regimes, vec!["gdpr"]);
    assert!(posture.findings.is_empty());
    assert_eq!(posture.not_applicable.len(), 4);

    let mut regime_severities = BTreeMap::new();
    regime_severities.insert("gdpr".to_string(), GateSeverity::FindingWarn);
    round_trip(
        ComplianceFinding {
            id: "compliance.example".to_string(),
            regime_severities,
            status: DeploymentFindingStatus::Active,
            kind: ComplianceFindingKind::Asserted,
            discharges: vec!["https://w3id.org/dpv#Purpose".to_string()],
            waiver: None,
        },
        json!({
            "id": "compliance.example",
            "regime_severities": { "gdpr": "finding_warn" },
            "status": "active",
            "kind": "asserted",
            "discharges": ["https://w3id.org/dpv#Purpose"]
        }),
    );
}

#[test]
fn posture_schema_accepts_compliance_block_and_rejects_bad_vocabulary() {
    let validator = posture_validator();
    let mut posture = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    posture["compliance"] = serde_json::to_value(
        CompliancePosture::for_declared_regimes(["gdpr"]).expect("compliance posture"),
    )
    .expect("compliance posture serializes");
    assert_valid(&validator, &posture);

    let mut with_finding = posture.clone();
    with_finding["compliance"]["findings"] = json!([
        {
            "id": "compliance.audit.evidence",
            "regime_severities": { "gdpr": "finding_warn" },
            "status": "active",
            "kind": "observed",
            "discharges": ["https://w3id.org/dpv#Process"]
        }
    ]);
    assert_valid(&validator, &with_finding);

    let mut empty_regimes = posture.clone();
    empty_regimes["compliance"]["regimes"] = json!([]);
    assert_invalid(&validator, &empty_regimes);

    let mut unknown_kind = with_finding.clone();
    unknown_kind["compliance"]["findings"][0]["kind"] = json!("claimed");
    assert_invalid(&validator, &unknown_kind);

    let mut unknown_severity = with_finding.clone();
    unknown_severity["compliance"]["findings"][0]["regime_severities"]["gdpr"] = json!("critical");
    assert_invalid(&validator, &unknown_severity);
}

#[test]
fn default_filter_preserves_compliance_public_block_without_waiver_reasons() {
    let validator = posture_validator();
    let mut posture = parse(registry_platform_ops::RELAY_POSTURE_EXAMPLE_V1);
    posture["compliance"] = json!({
        "regimes": ["gdpr"],
        "findings": [
            {
                "id": "compliance.audit.evidence",
                "regime_severities": { "gdpr": "finding_warn" },
                "status": "waived",
                "kind": "asserted",
                "discharges": ["https://w3id.org/dpv#Process"],
                "waiver": {
                    "reason": "operator-only compliance note",
                    "expires": "2026-07-01"
                }
            }
        ],
        "not_applicable": [
            {
                "obligation": "registrystack:gdpr.art7.consent_capture",
                "reason": "Consent capture is outside the platform posture MVP."
            }
        ]
    });

    let filtered = registry_platform_ops::filter_posture_for_tier(
        posture,
        registry_platform_ops::PostureTier::Default,
    )
    .expect("default posture filters");
    assert_valid(&validator, &filtered);
    assert_eq!(filtered["compliance"]["regimes"], json!(["gdpr"]));
    assert_eq!(
        filtered["compliance"]["findings"][0]["regime_severities"]["gdpr"],
        json!("finding_warn")
    );
    assert!(filtered["compliance"]["findings"][0]
        .as_object()
        .expect("finding object")
        .get("waiver")
        .is_none());
    assert!(!serde_json::to_string(&filtered)
        .expect("filtered posture renders")
        .contains("operator-only compliance note"));
}

#[test]
fn audit_assurance_types_round_trip() {
    round_trip(
        AuditWritePolicy::AvailabilityFirst,
        json!("availability_first"),
    );
    round_trip(AuditWritePolicy::FailClosed, json!("fail_closed"));
    round_trip(
        AuditWritePolicy::FailClosedRouteFamilies,
        json!("fail_closed_route_families"),
    );
    round_trip(AuditRedactionMode::Redacted, json!("redacted"));
    round_trip(AuditHashChain::None, json!("none"));
    round_trip(AuditHashChain::ProcessLocal, json!("process_local"));
    round_trip(AuditHashChain::Retained, json!("retained"));
    round_trip(AuditKeyedIntegrity::None, json!("none"));
    round_trip(AuditKeyedIntegrity::Hmac, json!("hmac"));
    round_trip(AuditSinkClass::External, json!("external"));
    round_trip(AuditRetentionOwner::Unspecified, json!("unspecified"));
    round_trip(AuditRetentionOwner::Operator, json!("operator"));
    round_trip(AuditRetentionOwner::Host, json!("host"));
    round_trip(AuditCheckpoints::Unsupported, json!("unsupported"));
    round_trip(AuditCheckpoints::Supported, json!("supported"));
    round_trip(AuditCheckpoints::Enabled, json!("enabled"));
    round_trip(AuditAnchoring::None, json!("none"));
    round_trip(AuditAnchoring::External, json!("external"));

    round_trip(
        AuditAssurance {
            write_policy: AuditWritePolicy::FailClosedRouteFamilies,
            redaction_mode: AuditRedactionMode::Redacted,
            hash_chain: AuditHashChain::Retained,
            keyed_integrity: AuditKeyedIntegrity::Hmac,
            sink_class: AuditSinkClass::File,
            retention_owner: AuditRetentionOwner::Operator,
            checkpoints: AuditCheckpoints::Enabled,
            anchoring: AuditAnchoring::External,
        },
        json!({
            "write_policy": "fail_closed_route_families",
            "redaction_mode": "redacted",
            "hash_chain": "retained",
            "keyed_integrity": "hmac",
            "sink_class": "file",
            "retention_owner": "operator",
            "checkpoints": "enabled",
            "anchoring": "external"
        }),
    );
}

#[test]
fn default_filter_drops_waiver_reasons_from_profile_gate_fields() {
    let filtered = registry_platform_ops::filter_posture_for_tier(
        posture_with_profile_gates(),
        registry_platform_ops::PostureTier::Default,
    )
    .expect("default posture filters");
    let rendered = serde_json::to_string(&filtered).expect("filtered posture renders");

    assert_eq!(filtered["tier"], "default");
    assert_eq!(filtered["deployment"]["profile"], json!("production"));
    assert!(filtered["deployment"]["findings"][1]
        .as_object()
        .expect("finding is object")
        .get("waiver")
        .is_none());
    assert!(filtered["deployment"]
        .as_object()
        .expect("deployment is object")
        .get("waivers")
        .is_none());
    assert!(!rendered.contains("temporary maintenance window"));
}
