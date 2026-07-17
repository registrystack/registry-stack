// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::{notary_test_config, ENV_LOCK};
use registry_platform_audit::{
    verify_jsonl_lines_with_hasher, AuditProfile, ChainState, JsonlFileSink,
};

const SECRET_ENV: &str = "TEST_NOTARY_AUDIT_QUARANTINE_SECRET";

#[test]
fn audit_quarantine_cli_parses_required_and_optional_fields() {
    let args = Args::try_parse_from([
        "registry-notary",
        "--config",
        "/etc/registry-notary.yaml",
        "audit",
        "quarantine",
        "--reason",
        "retained chain verification failed",
        "--operator",
        "operator-1",
    ])
    .expect("audit quarantine parses");

    match args.command {
        Some(Command::Audit {
            command: AuditCommand::Quarantine(quarantine),
        }) => {
            assert_eq!(
                args.config,
                Some(PathBuf::from("/etc/registry-notary.yaml"))
            );
            assert_eq!(quarantine.reason, "retained chain verification failed");
            assert_eq!(quarantine.operator.as_deref(), Some("operator-1"));
        }
        command => panic!("unexpected command: {command:?}"),
    }
}

#[test]
fn audit_quarantine_cli_requires_reason() {
    let error = Args::try_parse_from([
        "registry-notary",
        "--config",
        "/etc/registry-notary.yaml",
        "audit",
        "quarantine",
    ])
    .expect_err("missing reason is rejected");

    assert!(error.to_string().contains("--reason"));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn audit_quarantine_recovers_tampered_chain_and_preserves_break() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var(SECRET_ENV, "0123456789abcdef0123456789abcdef");
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config_path = tmp.path().join("notary.yaml");
    let profile = AuditProfile::registry_notary_from_env(SECRET_ENV).expect("profile loads");

    {
        let sink = JsonlFileSink::with_rotation_single_writer(&audit_path, 1024 * 1024, 2)
            .expect("audit sink builds");
        let chain = ChainState::bootstrap_or_start_empty(&sink, profile.chain_hasher())
            .await
            .expect("chain starts");
        chain
            .append(&sink, json!({ "event": "test.one" }))
            .await
            .expect("first event writes");
        chain
            .append(&sink, json!({ "event": "test.two" }))
            .await
            .expect("second event writes");
    }

    let contents = std::fs::read_to_string(&audit_path).expect("audit reads");
    std::fs::write(&audit_path, contents.replace("test.two", "tampered"))
        .expect("audit is tampered");
    let mut config = notary_test_config();
    config.audit.sink = "file".to_string();
    config.audit.path = Some(path_for_json(&audit_path));
    config.audit.hash_secret_env = Some(SECRET_ENV.to_string());
    config.audit.max_files = Some(2);
    std::fs::write(
        &config_path,
        serde_norway::to_string(&config).expect("config serializes"),
    )
    .expect("config writes");

    audit_quarantine(
        &config_path,
        AuditQuarantineArgs {
            reason: "unit recovery".to_string(),
            operator: Some("ci".to_string()),
        },
    )
    .expect("quarantine succeeds");

    let archive_count = std::fs::read_dir(tmp.path())
        .expect("audit directory reads")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("audit.jsonl.corrupt-")
        })
        .count();
    assert_eq!(archive_count, 1);
    let recovered = std::fs::read_to_string(&audit_path).expect("recovered chain reads");
    verify_jsonl_lines_with_hasher(recovered.lines(), &profile.chain_hasher())
        .expect("recovered chain verifies");
    let envelope: Value = serde_json::from_str(recovered.trim()).expect("envelope parses");
    assert_eq!(envelope["record"]["event"], "audit.chain.break");
    assert_eq!(envelope["record"]["reason"], "unit recovery");
    assert_eq!(envelope["record"]["operator"], "ci");

    std::env::remove_var(SECRET_ENV);
}

#[test]
fn audit_quarantine_refuses_to_run_while_server_lock_is_held() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var(SECRET_ENV, "0123456789abcdef0123456789abcdef");
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let config_path = tmp.path().join("notary.yaml");
    let mut config = notary_test_config();
    config.audit.sink = "file".to_string();
    config.audit.path = Some(path_for_json(&audit_path));
    config.audit.hash_secret_env = Some(SECRET_ENV.to_string());
    std::fs::write(
        &config_path,
        serde_norway::to_string(&config).expect("config serializes"),
    )
    .expect("config writes");
    let _live_writer = JsonlFileSink::with_rotation_single_writer(&audit_path, 1024 * 1024, 2)
        .expect("server writer lock is held");

    let error = audit_quarantine(
        &config_path,
        AuditQuarantineArgs {
            reason: "must stop server".to_string(),
            operator: None,
        },
    )
    .expect_err("online recovery is rejected");
    assert!(
        error
            .to_string()
            .contains("single-writer lock is already held"),
        "unexpected error: {error}"
    );

    std::env::remove_var(SECRET_ENV);
}
