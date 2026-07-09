use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackProposal, AntiRollbackRecord, AntiRollbackStoreError,
    ApplyReportResult, BreakGlassApproval, BreakGlassRateLimit, ConfigOverrideMode,
    ConfigOverridePin, FileAntiRollbackStore, FileLocalApprovalStore, LocalApprovalStoreError,
    LocalOperatorApproval, PostureApplyResult, ADMIN_CAPABILITIES_SCHEMA_V1, ADMIN_ERROR_SCHEMA_V1,
    CONFIG_APPLY_REPORT_SCHEMA_V1,
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

fn future_rfc3339() -> String {
    "2999-01-01T00:00:00Z".to_string()
}

fn record(sequence: u64, config_hash: &str) -> AntiRollbackRecord {
    AntiRollbackRecord {
        key: key(),
        last_sequence: sequence,
        last_config_hash: config_hash.to_string(),
        last_bundle_manifest_hash: None,
        last_bundle_id: None,
        root_version: Some(3),
        override_pin: None,
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
            ApplyReportResult::RejectedSignature,
            "rejected_signature",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedBinding,
            "rejected_binding",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedValidation,
            "rejected_validation",
            PostureApplyResult::Rejected,
        ),
        (
            ApplyReportResult::RejectedRollback,
            "rejected_rollback",
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
            "verify": {"supported": false, "currently_available": false},
            "dry_run": {"supported": false, "currently_available": false},
            "apply": {
                "supported": false,
                "currently_available": false,
                "requires_signed_input": true,
                "supported_sources": []
            }
        },
        "break_glass": {
            "supported": false,
            "currently_available": false,
            "rate_limit_scope": "none"
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
            "supported": false,
            "currently_available": false
        },
        "hot_swap": {
            "supported": false,
            "currently_available": false,
            "components": []
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
            "verify": {"supported": false, "currently_available": false},
            "dry_run": {"supported": false, "currently_available": false},
            "apply": {
                "supported": false,
                "currently_available": false,
                "requires_signed_input": true,
                "supported_sources": []
            }
        },
        "break_glass": {
            "supported": false,
            "currently_available": false,
            "rate_limit_scope": "none"
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
            "supported": false,
            "currently_available": false
        },
        "hot_swap": {
            "supported": false,
            "currently_available": false,
            "components": []
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
        "result": "verified",
        "restart_required": false,
        "change_classes": ["trust_root_rotation"],
        "affected_components": ["runtime_config"],
        "warnings": [],
        "errors": []
    });

    for result in [
        ApplyReportResult::Verified,
        ApplyReportResult::RejectedSignature,
        ApplyReportResult::RejectedBinding,
        ApplyReportResult::RejectedValidation,
        ApplyReportResult::RejectedRollback,
        ApplyReportResult::InternalError,
    ] {
        let mut document = base.clone();
        document["result"] = json!(result.as_str());
        assert_valid(CONFIG_APPLY_REPORT_SCHEMA_V1, &document);
    }

    for old_result in [
        "applied",
        "rejected_threshold",
        "rejected_freshness",
        "rejected_restart_required",
        "rejected_readiness",
        "rejected_break_glass",
        "rejected_local_approval",
        "rejected_compile",
    ] {
        let mut invalid = base.clone();
        invalid["result"] = json!(old_result);
        assert_invalid(CONFIG_APPLY_REPORT_SCHEMA_V1, &invalid);
    }
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

#[test]
fn antirollback_initialize_does_not_overwrite_existing_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config-antirollback.json");
    let store = FileAntiRollbackStore::new(&path);
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .initialize(record(41, &hash("old")))
        .expect_err("initialize must not lower an existing state floor");

    assert!(matches!(err, AntiRollbackStoreError::InvalidState(_)));
    assert_eq!(
        store.load(&key()).expect("state did not roll back"),
        record(42, &hash("current"))
    );
}

#[test]
fn antirollback_state_key_serializes_without_instance_id() {
    let serialized = serde_json::to_value(record(41, &hash("old"))).expect("record serializes");

    assert_eq!(serialized["key"]["product"], "registry-relay");
    assert_eq!(serialized["key"]["environment"], "production");
    assert_eq!(serialized["key"]["stream_id"], "national-config");
    assert!(serialized["key"].get("instance_id").is_none());

    let same_stream_other_instance = AntiRollbackKey {
        product: "registry-relay".to_string(),
        instance_id: "relay-b".to_string(),
        environment: "production".to_string(),
        stream_id: "national-config".to_string(),
    };
    assert_eq!(key(), same_stream_other_instance);
}

#[test]
fn antirollback_persists_unsigned_override_pin_with_absolute_locator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let pin = ConfigOverridePin {
        active: true,
        mode: ConfigOverrideMode::AcceptUnsigned,
        config_hash: hash("rollback"),
        config_path: Some("/etc/registry/rollback.yaml".to_string()),
        expires_at: Some(future_rfc3339()),
        used_at: "2026-07-07T10:00:00Z".to_string(),
        operator: "jeremi".to_string(),
        reason: "control plane unavailable".to_string(),
    };
    let accepted = store
        .persist_override_pin(&key(), pin.clone())
        .expect("pin persists");

    assert_eq!(accepted.last_sequence, 42);
    assert_eq!(accepted.last_config_hash, hash("current"));
    assert_eq!(accepted.override_pin, Some(pin));
}

#[test]
fn antirollback_rejects_expired_active_override_pin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .persist_override_pin_at(
            &key(),
            ConfigOverridePin {
                active: true,
                mode: ConfigOverrideMode::AcceptUnsigned,
                config_hash: hash("rollback"),
                config_path: Some("/etc/registry/rollback.yaml".to_string()),
                expires_at: Some("2026-07-07T10:00:00Z".to_string()),
                used_at: "2026-07-07T09:00:00Z".to_string(),
                operator: "jeremi".to_string(),
                reason: "control plane unavailable".to_string(),
            },
            1_783_428_401,
        )
        .expect_err("expired active pin must not persist");

    assert!(matches!(err, AntiRollbackStoreError::InvalidState(_)));
    assert_eq!(
        store.load(&key()).expect("state did not change"),
        record(42, &hash("current"))
    );
}

#[test]
fn antirollback_rejects_wrong_mode_override_pin_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .persist_override_pin(
            &key(),
            ConfigOverridePin {
                active: true,
                mode: ConfigOverrideMode::AcceptRollback,
                config_hash: hash("rollback"),
                config_path: Some("/etc/registry/rollback.yaml".to_string()),
                expires_at: Some(future_rfc3339()),
                used_at: "2026-07-07T10:00:00Z".to_string(),
                operator: "jeremi".to_string(),
                reason: "signed rollback".to_string(),
            },
        )
        .expect_err("rollback pin must not include config path");

    assert!(matches!(err, AntiRollbackStoreError::InvalidState(_)));
}

#[test]
fn normal_bundle_acceptance_clears_active_override_pin_even_on_same_bundle_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    let mut current = record(42, &hash("current"));
    current.last_bundle_id = Some("2026-07-07-rollout-3".to_string());
    current.last_bundle_manifest_hash = Some(hash("manifest"));
    store.initialize(current).expect("initial state writes");
    store
        .persist_override_pin(
            &key(),
            ConfigOverridePin {
                active: true,
                mode: ConfigOverrideMode::AcceptRollback,
                config_hash: hash("current"),
                config_path: None,
                expires_at: Some(future_rfc3339()),
                used_at: "2026-07-07T10:00:00Z".to_string(),
                operator: "jeremi".to_string(),
                reason: "signed rollback".to_string(),
            },
        )
        .expect("pin persists");

    let accepted = store
        .accept_bundle(
            &key(),
            "2026-07-07-rollout-3".to_string(),
            42,
            hash("current"),
            hash("manifest"),
        )
        .expect("normal verification clears pin");

    assert_eq!(accepted.last_sequence, 42);
    assert_eq!(
        accepted.last_bundle_id.as_deref(),
        Some("2026-07-07-rollout-3")
    );
    assert_eq!(accepted.override_pin, None);

    let serialized = serde_json::to_value(&accepted).expect("record serializes");
    assert!(serialized.get("root_version").is_none());
    assert!(serialized.get("break_glass").is_none());
    assert!(serialized.get("local_approvals").is_none());
}

#[cfg(unix)]
#[test]
fn antirollback_initialize_rejects_existing_symlink_path() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target_dir = dir.path().join("target");
    std::fs::create_dir(&target_dir).expect("target dir creates");
    let target_path = target_dir.join("config-antirollback.json");
    std::fs::write(&target_path, "{}").expect("target placeholder writes");
    let link_path = dir.path().join("config-antirollback.json");
    symlink(&target_path, &link_path).expect("state symlink creates");

    let store = FileAntiRollbackStore::new(&link_path);
    let err = store
        .initialize(record(41, &hash("old")))
        .expect_err("existing symlink requires explicit operator deletion");

    assert!(matches!(
        err,
        AntiRollbackStoreError::InvalidState(message)
            if message == "anti-rollback state already exists"
    ));
    assert!(
        std::fs::symlink_metadata(&link_path)
            .expect("link metadata reads")
            .file_type()
            .is_symlink(),
        "state path remains a symlink"
    );
    assert_eq!(
        std::fs::read_to_string(&target_path).expect("target placeholder reads"),
        "{}"
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
fn antirollback_treats_previous_hash_mismatch_as_advisory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
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
        .expect("previous hash mismatch is advisory");

    assert_eq!(accepted.last_sequence, 43);
    assert_eq!(accepted.last_config_hash, hash("next"));
    assert_eq!(store.load(&key()).expect("state advanced"), accepted);
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
fn break_glass_rate_limit_without_approval_does_not_create_override() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
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
        .expect("normal acceptance ignores stray break-glass rate limit");

    assert_eq!(accepted.last_sequence, 43);
    assert!(accepted.break_glass.accepted.is_empty());
}

#[test]
fn legacy_break_glass_records_valid_approval() {
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
        .expect("approved break-glass records emergency use");

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
fn antirollback_records_local_operator_approval_and_validates_approval_hash_claim() {
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
                previous_config_hash: Some(hash("next")),
                config_hash: hash("another"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: None,
                local_approval: Some(approval_for_wrong_previous_hash),
                local_approval_rate_limit: Some(rate_limit()),
            },
            1_100,
        )
        .expect_err("local approval must match proposal previous hash claim");
    assert_eq!(
        previous_hash_mismatch,
        AntiRollbackStoreError::InvalidLocalApproval("previous_config_hash")
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
