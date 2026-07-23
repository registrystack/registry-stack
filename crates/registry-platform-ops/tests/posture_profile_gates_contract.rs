use registry_platform_ops::{
    deployment_waiver_reference_schema_fragment, deployment_waiver_summary_schema_fragment,
    validate_deployment_waiver_metadata, AuditAnchoring, AuditAssurance, AuditCheckpoints,
    AuditHashChain, AuditKeyedIntegrity, AuditRedactionMode, AuditRetentionOwner, AuditSinkClass,
    AuditWritePolicy, DeploymentFinding, DeploymentFindingStatus, DeploymentFindingWaiver,
    DeploymentProfile, DeploymentWaiver, DeploymentWaiverMetadataError, GateSeverity,
    POSTURE_SCHEMA_V1,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

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
                    "reference": "OPS-2026-0042",
                    "summary": "Temporary maintenance window",
                    "expires": "2026-07-01"
                }
            }
        ],
        "waivers": [
            {
                "finding": "readiness.cache.degraded",
                "reference": "OPS-2026-0042",
                "summary": "Temporary maintenance window",
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

const WAIVER_POINTERS: [&str; 2] = ["/deployment/findings/1/waiver", "/deployment/waivers/0"];

fn posture_with_waiver_field(waiver_pointer: &str, field: &str, value: Value) -> Value {
    let mut posture = posture_with_profile_gates();
    posture
        .pointer_mut(waiver_pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("waiver object exists at {waiver_pointer}"))
        .insert(field.to_string(), value);
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
fn posture_waiver_definitions_share_structural_metadata_contracts() {
    let schema = parse(POSTURE_SCHEMA_V1);
    assert_eq!(
        schema.pointer("/$defs/waiver_reference"),
        Some(&deployment_waiver_reference_schema_fragment())
    );
    assert_eq!(
        schema.pointer("/$defs/waiver_summary"),
        Some(&deployment_waiver_summary_schema_fragment())
    );
    for waiver_definition in ["deployment_finding_waiver", "deployment_waiver"] {
        assert_eq!(
            schema.pointer(&format!(
                "/$defs/{waiver_definition}/properties/reference/$ref"
            )),
            Some(&json!("#/$defs/waiver_reference"))
        );
        assert_eq!(
            schema.pointer(&format!(
                "/$defs/{waiver_definition}/properties/summary/$ref"
            )),
            Some(&json!("#/$defs/waiver_summary"))
        );
    }
}

#[test]
fn posture_schema_waiver_reference_matches_runtime_prefix_contract() {
    let validator = posture_validator();

    for reference in [
        "OPS-42",
        "Bearer:",
        "Basic:",
        "Authorization:Bearer:",
        "authorization:bAsIc:",
    ] {
        validate_deployment_waiver_metadata(reference, None).unwrap_or_else(|error| {
            panic!("runtime rejected valid reference {reference:?}: {error}")
        });
        for waiver_pointer in WAIVER_POINTERS {
            assert_valid(
                &validator,
                &posture_with_waiver_field(waiver_pointer, "reference", json!(reference)),
            );
        }
    }

    for reference in [
        "Bearer:abcdef",
        "bAsIc:credential-value",
        "Authorization:Bearer:abc123",
        "authorization:bAsIc:abc123",
        "Bearer::",
    ] {
        assert_eq!(
            validate_deployment_waiver_metadata(reference, None),
            Err(DeploymentWaiverMetadataError::ReferenceCredentialLiteral),
            "runtime must reject credential-shaped reference {reference:?}"
        );
        for waiver_pointer in WAIVER_POINTERS {
            assert_invalid(
                &validator,
                &posture_with_waiver_field(waiver_pointer, "reference", json!(reference)),
            );
        }
    }
}

#[test]
fn posture_schema_waiver_summary_matches_runtime_structural_contract() {
    let validator = posture_validator();

    for summary in [
        "Ordinary operator summary".to_string(),
        "\u{feff}summary\u{feff}".to_string(),
        "summary\u{2028}continued".to_string(),
        "é".repeat(256),
    ] {
        validate_deployment_waiver_metadata("OPS-42", Some(&summary))
            .unwrap_or_else(|error| panic!("runtime rejected valid summary {summary:?}: {error}"));
        for waiver_pointer in WAIVER_POINTERS {
            assert_valid(
                &validator,
                &posture_with_waiver_field(waiver_pointer, "summary", json!(summary)),
            );
        }
    }

    for summary in [String::new(), "é".repeat(257)] {
        assert!(
            validate_deployment_waiver_metadata("OPS-42", Some(&summary)).is_err(),
            "runtime must reject structurally invalid summary {summary:?}"
        );
        for waiver_pointer in WAIVER_POINTERS {
            assert_invalid(
                &validator,
                &posture_with_waiver_field(waiver_pointer, "summary", json!(summary)),
            );
        }
    }

    for whitespace in (0..=char::MAX as u32)
        .filter_map(char::from_u32)
        .filter(|character| character.is_whitespace())
    {
        for summary in [
            format!("{whitespace}summary"),
            format!("summary{whitespace}"),
        ] {
            assert!(
                validate_deployment_waiver_metadata("OPS-42", Some(&summary)).is_err(),
                "runtime must reject edge whitespace U+{:04X}",
                whitespace as u32
            );
            for waiver_pointer in WAIVER_POINTERS {
                assert_invalid(
                    &validator,
                    &posture_with_waiver_field(waiver_pointer, "summary", json!(summary)),
                );
            }
        }
    }

    for value in (0..=0x1f).chain(0x7f..=0x9f) {
        let control = char::from_u32(value).expect("C0/C1 value is a Unicode scalar");
        assert!(control.is_control());
        let summary = format!("summary{control}continued");
        assert_eq!(
            validate_deployment_waiver_metadata("OPS-42", Some(&summary)),
            Err(DeploymentWaiverMetadataError::SummaryControlCharacter),
            "runtime must reject control U+{value:04X}"
        );
        for waiver_pointer in WAIVER_POINTERS {
            assert_invalid(
                &validator,
                &posture_with_waiver_field(waiver_pointer, "summary", json!(summary)),
            );
        }
    }
}

#[test]
fn posture_schema_summary_acceptance_does_not_replace_semantic_validation() {
    let validator = posture_validator();

    // JSON Schema stops at portable structural rules. Producers must also use
    // validate_deployment_waiver_metadata for contextual credential and
    // private-key marker rejection before emitting either waiver shape.
    for summary in [
        "Authorization: ＂Bearer abcdef＂",
        concat!("accidentally pasted -----BEGIN PRIVATE ", "KEY-----"),
    ] {
        assert_eq!(
            validate_deployment_waiver_metadata("OPS-42", Some(summary)),
            Err(DeploymentWaiverMetadataError::SummaryCredentialLiteral)
        );
        for waiver_pointer in WAIVER_POINTERS {
            assert_valid(
                &validator,
                &posture_with_waiver_field(waiver_pointer, "summary", json!(summary)),
            );
        }
    }
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
                reference: "OPS-2026-0042".to_string(),
                summary: Some("Operator approved temporary exception".to_string()),
                expires: "2026-07-01".to_string(),
            }),
        },
        json!({
            "id": "future.product.finding",
            "severity": "finding_warn",
            "status": "waived",
            "waiver": {
                "reference": "OPS-2026-0042",
                "summary": "Operator approved temporary exception",
                "expires": "2026-07-01"
            }
        }),
    );

    round_trip(
        DeploymentWaiver {
            finding: "future.product.finding".to_string(),
            reference: "OPS-2026-0042".to_string(),
            summary: None,
            expires: "2026-07-01".to_string(),
        },
        json!({
            "finding": "future.product.finding",
            "reference": "OPS-2026-0042",
            "expires": "2026-07-01"
        }),
    );
}

#[test]
fn posture_waiver_structs_reject_explicit_null_summary() {
    let finding_waiver = json!({
        "reference": "OPS-2026-0042",
        "summary": null,
        "expires": "2026-07-01"
    });
    assert!(
        serde_json::from_value::<DeploymentFindingWaiver>(finding_waiver).is_err(),
        "finding waiver summary must be omitted rather than null"
    );

    let waiver = json!({
        "finding": "future.product.finding",
        "reference": "OPS-2026-0042",
        "summary": null,
        "expires": "2026-07-01"
    });
    assert!(
        serde_json::from_value::<DeploymentWaiver>(waiver).is_err(),
        "deployment waiver summary must be omitted rather than null"
    );
}

#[test]
fn posture_waiver_structs_reject_retired_or_invalid_metadata() {
    for invalid in [
        json!({
            "finding": "future.product.finding",
            "reference": "OPS-42",
            "reason": "retired waiver text",
            "expires": "2026-07-01"
        }),
        json!({
            "finding": "future.product.finding",
            "reference": "OPS..42",
            "expires": "2026-07-01"
        }),
        json!({
            "finding": "future.product.finding",
            "reference": "OPS-42",
            "summary": "bearer credential-value",
            "expires": "2026-07-01"
        }),
    ] {
        assert!(
            serde_json::from_value::<DeploymentWaiver>(invalid).is_err(),
            "shared deployment waiver deserialization must enforce the closed metadata contract"
        );
    }

    for invalid in [
        json!({
            "reference": "OPS-42",
            "reason": "retired waiver text",
            "expires": "2026-07-01"
        }),
        json!({
            "reference": "OPS..42",
            "expires": "2026-07-01"
        }),
        json!({
            "reference": "OPS-42",
            "summary": "summary\nwith control",
            "expires": "2026-07-01"
        }),
    ] {
        assert!(
            serde_json::from_value::<DeploymentFindingWaiver>(invalid).is_err(),
            "shared finding waiver deserialization must enforce the closed metadata contract"
        );
    }
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
fn default_filter_drops_waiver_metadata_from_profile_gate_fields() {
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
    assert!(!rendered.contains("OPS-2026-0042"));
    assert!(!rendered.contains("Temporary maintenance window"));
}
