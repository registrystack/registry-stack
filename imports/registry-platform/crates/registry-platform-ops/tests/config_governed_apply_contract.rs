use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackProposal, AntiRollbackRecord, AntiRollbackStoreError,
    ApplyReportResult, BreakGlassApproval, BreakGlassRateLimit, FileAntiRollbackStore,
    FileLocalApprovalStore, LocalApprovalStoreError, LocalOperatorApproval, PostureApplyResult,
};

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
    assert_eq!(
        ApplyReportResult::Verified.as_posture_result(),
        PostureApplyResult::NotApplied
    );
    assert_eq!(
        ApplyReportResult::Applied.as_posture_result(),
        PostureApplyResult::Accepted
    );
    assert_eq!(
        ApplyReportResult::RejectedRollback.as_posture_result(),
        PostureApplyResult::Rejected
    );
    assert_eq!(
        ApplyReportResult::RejectedLocalApproval.as_posture_result(),
        PostureApplyResult::Rejected
    );
    assert_eq!(
        ApplyReportResult::RejectedLocalApproval.as_str(),
        "rejected_local_approval"
    );
    assert_eq!(
        ApplyReportResult::InternalError.as_posture_result(),
        PostureApplyResult::Failed
    );

    assert_eq!(PostureApplyResult::Accepted.as_str(), "accepted");
    assert_eq!(PostureApplyResult::Rejected.as_str(), "rejected");
    assert_eq!(PostureApplyResult::Failed.as_str(), "failed");
    assert_eq!(PostureApplyResult::NotApplied.as_str(), "not_applied");
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
fn antirollback_rejects_non_monotonic_sequence() {
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
        .expect_err("same sequence is rollback");

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
