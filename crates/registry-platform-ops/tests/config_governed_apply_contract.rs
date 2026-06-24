use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackProposal, AntiRollbackRecord, AntiRollbackStoreError,
    ApplyReportResult, BreakGlassApproval, BreakGlassRateLimit, FileAntiRollbackStore,
    FileLocalApprovalStore, LocalApprovalStoreError, LocalOperatorApproval, PostureApplyResult,
    ADMIN_CAPABILITIES_SCHEMA_V1, ADMIN_ERROR_SCHEMA_V1, CONFIG_APPLY_REPORT_SCHEMA_V1,
};
use serde_json::{json, Value};

fn key() -> AntiRollbackKey {
    AntiRollbackKey {
        product: "registry-relay".to_string(),
        instance_id: "relay-a".to_string(),
        environment: "production".to_string(),
        stream_id: "national-config".to_string(),
    }
}

fn hash(label: &str) -> String {
    format!(
        "sha256:{:0<64}",
        label
            .as_bytes()
            .iter()
            .fold(String::new(), |mut output, byte| {
                output.push_str(&format!("{byte:02x}"));
                output
            })
    )
}

fn record(sequence: u64, config_hash: &str) -> AntiRollbackRecord {
    AntiRollbackRecord {
        key: key(),
        last_sequence: sequence,
        last_config_hash: config_hash.to_string(),
        root_version: Some(3),
        break_glass: Default::default(),
        local_approvals: Default::default(),
    }
}

fn approval(expires_at_unix_seconds: u64) -> BreakGlassApproval {
    BreakGlassApproval {
        approved_by: "ops@example.test".to_string(),
        reason: "recover from bad live config".to_string(),
        approval_reference: "INC-4242".to_string(),
        emergency_change_class: "emergency_break_glass".to_string(),
        expires_at_unix_seconds,
        rate_limit_identity: "registry-relay/relay-a/production/national-config".to_string(),
    }
}

fn local_approval(expires_at_unix_seconds: u64, config_hash: &str) -> LocalOperatorApproval {
    LocalOperatorApproval {
        approved_by: "security@example.test".to_string(),
        approvers: Vec::new(),
        reason: "rotate config trust roots".to_string(),
        approval_reference: "ROOT-2026-Q2".to_string(),
        change_class: "root_transition".to_string(),
        config_hash: config_hash.to_string(),
        previous_config_hash: Some(hash("current")),
        expires_at_unix_seconds,
        rate_limit_identity: "registry-relay/relay-a/production/root-transition".to_string(),
        rate_limit: rate_limit(),
    }
}

fn rate_limit() -> BreakGlassRateLimit {
    BreakGlassRateLimit {
        max_accepted: 1,
        window_seconds: 3600,
    }
}

fn loose_rate_limit() -> BreakGlassRateLimit {
    BreakGlassRateLimit {
        max_accepted: 100,
        window_seconds: 1,
    }
}

#[test]
fn apply_report_result_projects_to_posture_vocabulary() {
    let cases = [
        (
            ApplyReportResult::Verified,
            "verified",
            PostureApplyResult::NotApplied,
        ),
        (
            ApplyReportResult::Applied,
            "applied",
            PostureApplyResult::Accepted,
        ),
        (
            ApplyReportResult::RejectedSignature,
            "rejected_signature",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedThreshold,
            "rejected_threshold",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedFreshness,
            "rejected_freshness",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedRollback,
            "rejected_rollback",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedRestartRequired,
            "rejected_restart_required",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedReadiness,
            "rejected_readiness",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedBreakGlass,
            "rejected_break_glass",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedLocalApproval,
            "rejected_local_approval",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::InternalError,
            "internal_error",
            PostureApplyResult::Failed,
        ),
    ];

    for (result, label, posture) in cases {
        assert_eq!(result.as_str(), label);
        assert_eq!(result.as_posture_result(), posture);
    }

    assert_eq!(PostureApplyResult::Accepted.as_str(), "accepted");
    assert_eq!(PostureApplyResult::Rejected.as_str(), "rejected");
    assert_eq!(PostureApplyResult::Failed.as_str(), "failed");
    assert_eq!(PostureApplyResult::NotApplied.as_str(), "not_applied");
}

fn validator(schema: &str) -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(schema).expect("schema parses");
    jsonschema::validator_for(&schema).expect("schema compiles")
}

fn assert_valid(schema: &str, document: &Value) {
    let validator = validator(schema);
    if let Err(error) = validator.validate(document) {
        panic!("expected valid document, got {error}: {document:#}");
    }
}

fn assert_invalid(schema: &str, document: &Value) {
    let validator = validator(schema);
    assert!(
        validator.validate(document).is_err(),
        "expected invalid document: {document:#}"
    );
}

#[test]
fn admin_error_schema_accepts_stable_error_envelope() {
    let document = json!({
        "schema": "registry.admin.error.v1",
        "code": "registry.admin.posture.invalid_tier",
        "message": "invalid posture tier",
        "details": {
            "supported_tiers": ["default", "restricted"]
        }
    });

    assert_valid(ADMIN_ERROR_SCHEMA_V1, &document);

    let mut invalid = document;
    invalid["code"] = json!("posture.invalid_tier");
    assert_invalid(ADMIN_ERROR_SCHEMA_V1, &invalid);
}

#[test]
fn admin_capabilities_schema_distinguishes_supported_operations() {
    let document = json!({
        "schema": "registry.admin.capabilities.v1",
        "product": "registry-relay",
        "admin_api_version": "v1",
        "supported_posture_tiers": ["default", "restricted"],
        "config": {
            "verify": {"supported": true, "currently_available": true},
            "dry_run": {"supported": true, "currently_available": true},
            "apply": {
                "supported": true,
                "currently_available": true,
                "requires_signed_input": true,
                "supported_sources": ["tuf_local"]
            }
        },
        "break_glass": {
            "supported": true,
            "currently_available": true,
            "rate_limit_scope": "instance"
        },
        "listeners": {
            "admin": {
                "mode": "dedicated",
                "public_admin_routes": false
            },
            "metrics": {
                "mode": "admin",
                "requires_admin_scope": false,
                "required_scope": "registry_relay:metrics_read"
            }
        },
        "root_transition": {
            "supported": true,
            "currently_available": true
        },
        "hot_swap": {
            "supported": true,
            "currently_available": true,
            "components": ["compiled_metadata", "provenance_state"]
        },
        "reload": {
            "resource_reload": {"supported": true, "currently_available": true},
            "table_reload": {"supported": true, "currently_available": true},
            "config_reload": {"supported": false, "currently_available": false}
        }
    });

    assert_valid(ADMIN_CAPABILITIES_SCHEMA_V1, &document);

    let mut invalid = document;
    invalid["supported_posture_tiers"] = json!(["restricted"]);
    assert_invalid(ADMIN_CAPABILITIES_SCHEMA_V1, &invalid);
}

#[test]
fn admin_capabilities_schema_rejects_topology_leaks_and_unknown_modes() {
    let document = json!({
        "schema": "registry.admin.capabilities.v1",
        "product": "registry-notary",
        "admin_api_version": "v1",
        "supported_posture_tiers": ["default", "restricted"],
        "config": {
            "verify": {"supported": true, "currently_available": true},
            "dry_run": {"supported": true, "currently_available": true},
            "apply": {
                "supported": true,
                "currently_available": true,
                "requires_signed_input": true,
                "supported_sources": ["tuf_local", "tuf_remote"]
            }
        },
        "break_glass": {
            "supported": true,
            "currently_available": true,
            "rate_limit_scope": "instance"
        },
        "listeners": {
            "admin": {
                "mode": "shared_with_public",
                "public_admin_routes": true
            },
            "metrics": {
                "mode": "shared_with_public",
                "requires_admin_scope": false,
                "required_scope": "registry_notary:metrics_read"
            }
        },
        "root_transition": {
            "supported": true,
            "currently_available": true
        },
        "hot_swap": {
            "supported": true,
            "currently_available": true,
            "components": ["signing_keys"]
        },
        "reload": {
            "resource_reload": {"supported": false, "currently_available": false},
            "table_reload": {"supported": false, "currently_available": false},
            "config_reload": {"supported": false, "currently_available": false}
        }
    });

    assert_valid(ADMIN_CAPABILITIES_SCHEMA_V1, &document);

    let mut invalid_mode = document.clone();
    invalid_mode["listeners"]["admin"]["mode"] = json!("public");
    assert_invalid(ADMIN_CAPABILITIES_SCHEMA_V1, &invalid_mode);

    let mut leaked_address = document;
    leaked_address["listeners"]["admin"]["bind"] = json!("127.0.0.1:8081");
    assert_invalid(ADMIN_CAPABILITIES_SCHEMA_V1, &leaked_address);
}

#[test]
fn config_apply_report_schema_matches_shared_result_vocabulary() {
    let base = json!({
        "schema": "registry.platform.config_apply_report.v1",
        "attempt_id": "01JZ0000000000000000000000",
        "component": "registry-relay",
        "stream_id": "default",
        "source": "signed_bundle_file",
        "bundle_id": "01JZ0000000000000000000001",
        "bundle_sequence": 42,
        "previous_config_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "config_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "result": "applied",
        "restart_required": false,
        "change_classes": ["signing_key_rotation"],
        "affected_components": ["provenance_state"],
        "warnings": [],
        "errors": []
    });

    for result in [
        ApplyReportResult::Verified,
        ApplyReportResult::Applied,
        ApplyReportResult::RejectedSignature,
        ApplyReportResult::RejectedThreshold,
        ApplyReportResult::RejectedFreshness,
        ApplyReportResult::RejectedRollback,
        ApplyReportResult::RejectedRestartRequired,
        ApplyReportResult::RejectedReadiness,
        ApplyReportResult::RejectedBreakGlass,
        ApplyReportResult::RejectedLocalApproval,
        ApplyReportResult::InternalError,
    ] {
        let mut document = base.clone();
        document["result"] = json!(result.as_str());
        assert_valid(CONFIG_APPLY_REPORT_SCHEMA_V1, &document);
    }

    let mut invalid = base;
    invalid["result"] = json!("rejected_compile");
    assert_invalid(CONFIG_APPLY_REPORT_SCHEMA_V1, &invalid);
}

#[test]
fn antirollback_missing_state_fails_closed_for_apply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));

    let err = store
        .load(&key())
        .expect_err("missing state is not accepted");
    assert_eq!(err, AntiRollbackStoreError::MissingState);
}

#[test]
fn antirollback_state_survives_new_store_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config-antirollback.json");
    let first = FileAntiRollbackStore::new(&path);
    first
        .initialize(record(41, &hash("old")))
        .expect("initial state writes");

    let second = FileAntiRollbackStore::new(&path);
    assert_eq!(
        second.load(&key()).expect("state loads after restart"),
        record(41, &hash("old"))
    );
}

#[cfg(unix)]
#[test]
fn antirollback_atomic_write_preserves_symlink_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target_dir = dir.path().join("target");
    std::fs::create_dir(&target_dir).expect("target dir creates");
    let target_path = target_dir.join("config-antirollback.json");
    std::fs::write(&target_path, "{}").expect("target placeholder writes");
    let link_path = dir.path().join("config-antirollback.json");
    symlink(&target_path, &link_path).expect("state symlink creates");

    let store = FileAntiRollbackStore::new(&link_path);
    store
        .initialize(record(41, &hash("old")))
        .expect("initial state writes through symlink");

    assert!(
        std::fs::symlink_metadata(&link_path)
            .expect("link metadata reads")
            .file_type()
            .is_symlink(),
        "state path remains a symlink"
    );
    assert_eq!(
        FileAntiRollbackStore::new(&target_path)
            .load(&key())
            .expect("target state loads"),
        record(41, &hash("old"))
    );
}

#[test]
fn antirollback_accepts_idempotent_replay_without_advancing_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 42,
                previous_config_hash: Some(hash("previous")),
                config_hash: hash("current"),
                root_version: Some(3),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: None,
                local_approval_rate_limit: None,
            },
        )
        .expect("exact replay is accepted");

    assert_eq!(accepted, record(42, &hash("current")));
    assert_eq!(
        store.load(&key()).expect("state remains unchanged"),
        record(42, &hash("current"))
    );
}

#[test]
fn antirollback_records_newer_root_version_for_idempotent_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 42,
                previous_config_hash: Some(hash("previous")),
                config_hash: hash("current"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: None,
                local_approval_rate_limit: None,
            },
        )
        .expect("same config under newer root is accepted");

    let mut expected = record(42, &hash("current"));
    expected.root_version = Some(4);
    assert_eq!(accepted, expected);
    assert_eq!(
        store.load(&key()).expect("new root version persists"),
        expected
    );
}

#[test]
fn antirollback_rejects_same_sequence_with_different_config_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 42,
                previous_config_hash: Some(hash("current")),
                config_hash: hash("next"),
                root_version: Some(3),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: None,
                local_approval_rate_limit: None,
            },
        )
        .expect_err("same sequence cannot carry different config");

    assert_eq!(err, AntiRollbackStoreError::NonMonotonicSequence);
}

#[test]
fn antirollback_rejects_previous_hash_mismatch_without_break_glass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("next"),
                root_version: Some(3),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: None,
                local_approval_rate_limit: None,
            },
        )
        .expect_err("previous hash mismatch is rejected");

    assert_eq!(err, AntiRollbackStoreError::PreviousConfigHashMismatch);
}

#[test]
fn antirollback_rejects_root_version_rollback() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("current")),
                config_hash: hash("next"),
                root_version: Some(2),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: None,
                local_approval_rate_limit: None,
            },
        )
        .expect_err("root version rollback is rejected");

    assert_eq!(err, AntiRollbackStoreError::RootVersionRollback);
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_requires_local_approval_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
        )
        .expect_err("break-glass requires local approval policy");

    assert_eq!(err, AntiRollbackStoreError::PreviousConfigHashMismatch);
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_waives_previous_hash_only_with_valid_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect("approved break-glass can waive previous hash");

    assert_eq!(accepted.last_sequence, 43);
    assert_eq!(accepted.last_config_hash, hash("recovery"));
    assert_eq!(accepted.root_version, Some(4));
    assert_eq!(accepted.break_glass.accepted.len(), 1);
    assert_eq!(accepted.break_glass.accepted[0].sequence, 43);
    assert_eq!(
        accepted.break_glass.accepted[0].emergency_change_class,
        Some("emergency_break_glass".to_string())
    );
    assert_eq!(
        accepted.break_glass.accepted[0].approval_reference,
        "INC-4242"
    );
}

#[test]
fn configured_break_glass_policy_does_not_require_proposal_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"))
        .with_break_glass_rate_limit(rate_limit());
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: None,
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect("local store policy can authorize break-glass");

    assert_eq!(accepted.last_sequence, 43);
    assert_eq!(accepted.break_glass.accepted.len(), 1);
}

#[test]
fn configured_break_glass_policy_rejects_client_policy_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"))
        .with_break_glass_rate_limit(rate_limit());
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(loose_rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect_err("proposal cannot override local store policy");

    assert_eq!(
        err,
        AntiRollbackStoreError::InvalidBreakGlassRateLimit("policy_mismatch")
    );
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_never_waives_monotonic_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 42,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect_err("sequence rollback is rejected before approval can waive hash");

    assert_eq!(err, AntiRollbackStoreError::NonMonotonicSequence);
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_rejects_expired_or_incomplete_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let expired = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(999)),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect_err("expired approval is rejected");
    assert_eq!(expired, AntiRollbackStoreError::BreakGlassApprovalExpired);

    let mut incomplete = approval(2_000);
    incomplete.reason.clear();
    let invalid = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(incomplete),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect_err("reason is required");
    assert_eq!(
        invalid,
        AntiRollbackStoreError::InvalidBreakGlassApproval("reason")
    );

    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_is_rate_limited_in_rolling_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_000,
        )
        .expect("first break-glass is accepted");

    let limited = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("wrong-again")),
                config_hash: hash("recovery2"),
                root_version: Some(4),
                break_glass: Some(approval(2_100)),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            1_100,
        )
        .expect_err("second break-glass in same window is rejected");
    assert_eq!(limited, AntiRollbackStoreError::BreakGlassRateLimited);

    let accepted_after_window = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("wrong-again")),
                config_hash: hash("recovery2"),
                root_version: Some(4),
                break_glass: Some(approval(6_000)),
                break_glass_rate_limit: Some(rate_limit()),
                local_approval: None,
                local_approval_rate_limit: None,
            },
            5_000,
        )
        .expect("break-glass outside the rolling window is accepted");
    assert_eq!(accepted_after_window.last_sequence, 44);
}

#[test]
fn local_operator_approval_store_loads_matching_unexpired_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let approval_path = dir.path().join("config-approvals.json");
    std::fs::write(
        &approval_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "approvals": [
                local_approval(2_000, &hash("next"))
            ]
        }))
        .expect("approval file serializes"),
    )
    .expect("approval file writes");
    let store = FileLocalApprovalStore::new(&approval_path);

    let approval = store
        .load_for_apply_at(
            "ROOT-2026-Q2",
            "root_transition",
            &hash("next"),
            Some(hash("current").as_str()),
            1_000,
        )
        .expect("matching approval loads");

    assert_eq!(approval.approval_reference, "ROOT-2026-Q2");
    assert_eq!(approval.change_class, "root_transition");

    assert_eq!(
        store
            .load_for_apply_at(
                "ROOT-2026-Q2",
                "root_transition",
                &hash("other"),
                Some(hash("current").as_str()),
                1_000,
            )
            .expect_err("approval is bound to config hash"),
        LocalApprovalStoreError::ApprovalNotFound
    );
    assert_eq!(
        store
            .load_for_apply_at(
                "ROOT-2026-Q2",
                "root_transition",
                &hash("next"),
                Some(hash("current").as_str()),
                2_000,
            )
            .expect_err("expired approval is rejected"),
        LocalApprovalStoreError::ApprovalExpired
    );
}

#[test]
fn local_operator_approval_store_loads_distinct_approvers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let approval_path = dir.path().join("config-approvals.json");
    std::fs::write(
        &approval_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "approvals": [
                {
                    "approved_by": "security@example.test",
                    "approvers": ["ops@example.test"],
                    "reason": "approve emergency",
                    "approval_reference": "BG-2026-Q2",
                    "change_class": "emergency_break_glass",
                    "config_hash": hash("next"),
                    "expires_at_unix_seconds": 2_000,
                    "rate_limit_identity": "registry-relay/relay-a/production/national-config",
                    "rate_limit": rate_limit()
                }
            ]
        }))
        .expect("approval file serializes"),
    )
    .expect("approval file writes");
    let store = FileLocalApprovalStore::new(&approval_path);

    let approval = store
        .load_for_apply_at(
            "BG-2026-Q2",
            "emergency_break_glass",
            &hash("next"),
            None,
            1_000,
        )
        .expect("matching approval loads");

    assert_eq!(approval.approvers, vec!["ops@example.test".to_string()]);
}

#[test]
fn local_operator_approval_store_rejects_duplicate_approvers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let approval_path = dir.path().join("config-approvals.json");
    std::fs::write(
        &approval_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "approvals": [
                {
                    "approved_by": "security@example.test",
                    "approvers": ["security@example.test", " security@example.test "],
                    "reason": "approve emergency",
                    "approval_reference": "BG-2026-Q2",
                    "change_class": "emergency_break_glass",
                    "config_hash": hash("next"),
                    "expires_at_unix_seconds": 2_000,
                    "rate_limit_identity": "registry-relay/relay-a/production/national-config",
                    "rate_limit": rate_limit()
                }
            ]
        }))
        .expect("approval file serializes"),
    )
    .expect("approval file writes");
    let store = FileLocalApprovalStore::new(&approval_path);

    assert_eq!(
        store
            .load_for_apply_at(
                "BG-2026-Q2",
                "emergency_break_glass",
                &hash("next"),
                None,
                1_000,
            )
            .expect_err("duplicate approver identities are rejected"),
        LocalApprovalStoreError::InvalidApproval("approvers")
    );
}

#[test]
fn antirollback_records_local_operator_approval_without_waiving_previous_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("current")),
                config_hash: hash("next"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: Some(local_approval(2_000, &hash("next"))),
                local_approval_rate_limit: Some(local_approval(2_000, &hash("next")).rate_limit),
            },
            1_000,
        )
        .expect("local approval records root transition acceptance");

    assert_eq!(accepted.last_sequence, 43);
    assert_eq!(accepted.last_config_hash, hash("next"));
    assert_eq!(accepted.local_approvals.accepted.len(), 1);
    assert_eq!(
        accepted.local_approvals.accepted[0].approval_reference,
        "ROOT-2026-Q2"
    );

    let mut approval_for_wrong_previous_hash = local_approval(3_000, &hash("another"));
    approval_for_wrong_previous_hash.previous_config_hash = Some(hash("wrong"));
    let previous_hash_mismatch = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("wrong")),
                config_hash: hash("another"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: Some(approval_for_wrong_previous_hash),
                local_approval_rate_limit: Some(rate_limit()),
            },
            1_100,
        )
        .expect_err("local approval does not waive previous hash mismatch");
    assert_eq!(
        previous_hash_mismatch,
        AntiRollbackStoreError::PreviousConfigHashMismatch
    );

    let mut mismatched_rate_limit_approval = local_approval(3_000, &hash("another"));
    mismatched_rate_limit_approval.previous_config_hash = Some(hash("next"));
    let mismatched_rate_limit = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("next")),
                config_hash: hash("another"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: Some(mismatched_rate_limit_approval),
                local_approval_rate_limit: Some(BreakGlassRateLimit {
                    max_accepted: 2,
                    window_seconds: 3600,
                }),
            },
            1_100,
        )
        .expect_err("caller cannot replace the approval rate limit");
    assert_eq!(
        mismatched_rate_limit,
        AntiRollbackStoreError::InvalidLocalApproval("rate_limit")
    );

    let mut second_approval = local_approval(3_000, &hash("another"));
    second_approval.previous_config_hash = Some(hash("next"));
    let limited = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("next")),
                config_hash: hash("another"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: Some(second_approval),
                local_approval_rate_limit: Some(rate_limit()),
            },
            1_100,
        )
        .expect_err("second local approval in same window is rejected");
    assert_eq!(limited, AntiRollbackStoreError::LocalApprovalRateLimited);
}
