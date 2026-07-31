// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;
use registry_notary_server::{NotaryActivationCode, NotaryActivationFailure};
use registry_platform_ops::{BundleVerificationCode, BundleVerificationFailure};

fn assert_value_free_activation_failure(
    error: &(dyn std::error::Error + 'static),
    expected_code: NotaryActivationCode,
    forbidden_values: &[&str],
) {
    let failure = error
        .downcast_ref::<NotaryActivationFailure>()
        .expect("runtime activation errors use the redacted process boundary");
    assert_eq!(failure.code(), expected_code);
    assert!(
        std::error::Error::source(failure).is_none(),
        "the public failure must not retain an inner error"
    );
    let rendered = failure.to_string();
    assert!(rendered.contains(expected_code.as_str()));
    for forbidden in forbidden_values {
        assert!(
            !rendered.contains(forbidden),
            "activation boundary exposed forbidden value {forbidden:?}: {rendered}"
        );
    }
}

#[test]
fn top_level_server_error_renderer_drops_unknown_error_values() {
    const SENTINEL: &str = "SENTINEL_PRIVATE_USERNAME_COUNTRY_SECRET_PATH_AND_DIGEST";
    let unknown = std::io::Error::other(SENTINEL);

    let rendered = crate::top_level_error_message(&unknown, true);

    assert!(rendered.contains(NotaryActivationCode::RUNTIME_ACTIVATION_FAILED.as_str()));
    assert!(!rendered.contains(SENTINEL));
}

#[test]
fn top_level_server_error_renderer_preserves_safe_activation_code() {
    let failure = NotaryActivationFailure::from(NotaryActivationCode::CONFIGURATION_INVALID);

    let rendered = crate::top_level_error_message(&failure, true);

    assert!(rendered.contains(NotaryActivationCode::CONFIGURATION_INVALID.as_str()));
    assert!(!rendered.contains("SENTINEL"));
}

#[test]
fn top_level_server_error_renderer_preserves_safe_bundle_verification_code() {
    let failure = BundleVerificationFailure::from(BundleVerificationCode::REJECTED_SIGNATURE);

    let rendered = crate::top_level_error_message(&failure, true);

    assert_eq!(rendered, failure.to_string());
    assert!(rendered.contains(BundleVerificationCode::REJECTED_SIGNATURE.as_str()));
    assert!(!rendered.contains("SENTINEL"));
}

#[test]
fn boot_bundle_acceptance_audit_failure_aborts_before_antirollback_persist() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("antirollback.json");
    let acceptance = PendingBundleAcceptance {
        state_path: state_path.clone(),
        key: registry_platform_ops::AntiRollbackKey {
            acceptance_identity: notary_acceptance_identity(),
        },
        accepted_anchor: notary_accepted_anchor_pin(),
        source: ConfigSource::SignedBundleFile,
        bundle_id: Some("notary-loader-bundle".to_string()),
        bundle_manifest_hash: Some(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        ),
        sequence: Some(1),
        config_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .to_string(),
        previous_config_hash: None,
        previous_hash_matched: None,
        signer_kids: vec!["kid-1".to_string()],
        break_glass: false,
        state_action: BundleStateAction::Initialize,
        override_pin: None,
        override_path: None,
    };
    let audit_result: Result<(), Box<dyn std::error::Error>> =
        Err(Box::new(std::io::Error::other("boot audit write failed")));

    let result = persist_after_successful_boot_audit(&acceptance, audit_result);

    assert!(result.is_err());
    let err = registry_platform_ops::FileAntiRollbackStore::new(&state_path)
        .load(&acceptance.key)
        .expect_err("state remains absent");
    assert_eq!(
        err,
        registry_platform_ops::AntiRollbackStoreError::MissingState
    );
}

#[test]
fn governed_acceptance_audit_persists_complete_validated_recovery_evidence() {
    let acceptance_identity = notary_acceptance_identity();
    let acceptance = PendingBundleAcceptance {
        state_path: PathBuf::from("/var/lib/registry/state/antirollback.json"),
        key: registry_platform_ops::AntiRollbackKey {
            acceptance_identity: acceptance_identity.clone(),
        },
        accepted_anchor: notary_accepted_anchor_pin(),
        source: ConfigSource::SignedBundleFile,
        bundle_id: Some("notary-loader-bundle".to_string()),
        bundle_manifest_hash: Some(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        ),
        sequence: Some(1),
        config_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .to_string(),
        previous_config_hash: None,
        previous_hash_matched: None,
        signer_kids: vec!["kid-1".to_string()],
        break_glass: false,
        state_action: BundleStateAction::Initialize,
        override_pin: None,
        override_path: None,
    };
    let intent = registry_platform_ops::AcceptanceAuditIntentV1 {
        mutation: registry_platform_ops::AcceptanceMutationKindV1::Initialize,
        key: acceptance.key.clone(),
        sequence: acceptance.sequence.expect("governed sequence"),
        config_hash: acceptance.config_hash.clone(),
        bundle_manifest_hash: acceptance
            .bundle_manifest_hash
            .clone()
            .expect("governed manifest hash"),
        bundle_id: acceptance.bundle_id.clone().expect("governed bundle id"),
        anchor_digest: acceptance.accepted_anchor.digest.clone(),
        anchor_version: acceptance.accepted_anchor.version,
    };

    let audit =
        governed_bundle_acceptance_audit(&acceptance, &intent).expect("validated audit evidence");

    assert_eq!(audit.acceptance_identity, Some(acceptance_identity));
    assert_eq!(
        audit.bundle_manifest_hash.as_deref(),
        Some(intent.bundle_manifest_hash.as_str())
    );
    assert_eq!(
        audit.anchor_digest.as_deref(),
        Some(intent.anchor_digest.as_str())
    );
    assert_eq!(audit.anchor_version, Some(intent.anchor_version));
    assert_eq!(audit.apply_result, "pending");
    assert!(!audit.applied);
}

#[tokio::test]
async fn governed_acceptance_commit_failure_never_records_applied_audit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    let loaded = load_direct_signed_bundle_server_config(
        &fixture.bundle_dir,
        &fixture.anchor_path,
        &fixture.state_path,
        true,
    )
    .expect("governed bundle prepares without mutating state");
    let acceptance = loaded
        .pending_bundle_acceptance
        .expect("pending acceptance is available");
    let candidate = loaded
        .verified_acceptance_state
        .expect("verified acceptance state is available");
    let store = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path);
    let plan = store
        .plan_initialize(&candidate)
        .expect("initialization plan is read-only");
    let mut observed = None;

    let error = store
        .commit_acceptance(plan, |intent| {
            observed = Some(
                governed_bundle_acceptance_audit(&acceptance, &intent)
                    .expect("checked intent audit builds"),
            );
            std::fs::write(&fixture.state_path, b"concurrent-state")
                .expect("concurrent state creation forces commit failure");
            async { Ok::<(), std::convert::Infallible>(()) }
        })
        .await
        .expect_err("state commit fails after the checked audit callback");

    assert!(matches!(
        error,
        registry_platform_ops::AntiRollbackStoreError::InvalidState(_)
    ));
    let audit = observed.expect("the pre-mutation audit was recorded");
    assert_eq!(audit.apply_result, "pending");
    assert!(
        !audit.applied,
        "failed state commit must have no applied audit"
    );
}

#[test]
fn legacy_acceptance_audit_omits_governed_recovery_evidence() {
    let acceptance = PendingBundleAcceptance {
        state_path: PathBuf::from("/tmp/legacy-antirollback.json"),
        key: registry_platform_ops::AntiRollbackKey {
            acceptance_identity: notary_acceptance_identity(),
        },
        accepted_anchor: notary_accepted_anchor_pin(),
        source: ConfigSource::SignedBundleFile,
        bundle_id: Some("legacy-bundle".to_string()),
        bundle_manifest_hash: Some(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
        ),
        sequence: Some(1),
        config_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .to_string(),
        previous_config_hash: None,
        previous_hash_matched: None,
        signer_kids: vec!["kid-1".to_string()],
        break_glass: false,
        state_action: BundleStateAction::Initialize,
        override_pin: None,
        override_path: None,
    };

    let audit = bundle_acceptance_audit(&acceptance);
    let serialized = serde_json::to_value(audit).expect("legacy audit serializes");

    for field in [
        "acceptance_identity",
        "bundle_manifest_hash",
        "anchor_digest",
        "anchor_version",
    ] {
        assert!(
            serialized.get(field).is_none(),
            "legacy audit unexpectedly retained {field}"
        );
    }
}

#[tokio::test]
async fn boot_configuration_boundary_redacts_paths_and_parser_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("SENTINEL_PRIVATE_CONFIG_PATH.yaml");
    fs::write(
        &config_path,
        "SENTINEL_COUNTRY_IDENTIFIER: [invalid parser value",
    )
    .expect("invalid startup config writes");

    let error = run_server(&config_path, None, false)
        .await
        .expect_err("invalid startup config fails closed");

    assert_value_free_activation_failure(
        error.as_ref(),
        NotaryActivationCode::CONFIGURATION_INVALID,
        &[
            "SENTINEL_PRIVATE_CONFIG_PATH",
            "SENTINEL_COUNTRY_IDENTIFIER",
            "invalid parser value",
            config_path.to_str().expect("config path is UTF-8"),
        ],
    );
}

#[tokio::test]
async fn direct_signed_bundle_without_instance_id_cannot_start_or_initialize_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    rewrite_signed_bundle_instance_id(&fixture, None);
    let input = ServerConfigInput::SignedBundle {
        bundle_dir: fixture.bundle_dir.clone(),
        anchor_path: fixture.anchor_path.clone(),
        state_path: fixture.state_path.clone(),
    };

    let error = run_server(input, None, true)
        .await
        .expect_err("instance-unbound direct bundle must not start");

    let failure = error
        .downcast_ref::<BundleVerificationFailure>()
        .expect("missing instance binding failure is typed");
    assert_eq!(failure.code(), BundleVerificationCode::REJECTED_BINDING);
    let rendered = format!("{failure} {failure:?}");
    assert!(!rendered.contains(fixture.bundle_dir.to_string_lossy().as_ref()));
    assert!(!rendered.contains(fixture.anchor_path.to_string_lossy().as_ref()));
    assert!(!rendered.contains(fixture.state_path.to_string_lossy().as_ref()));
    assert!(
        !fixture.state_path.exists(),
        "failed startup must not initialize anti-rollback state"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn explicit_initialization_is_sequence_one_one_shot_and_never_serves() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("TEST_NOTARY_LOADER_API_HASH", sha256_hash("api-token"));
    std::env::set_var(
        "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
        "registry-notary-loader-audit-secret-32-bytes",
    );
    std::env::set_var(
        "TEST_NOTARY_LOADER_ISSUER_JWK",
        demo_issuer_jwk("did:web:issuer.example#key-1").expect("issuer key generates"),
    );
    let public_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("public port binds");
    let admin_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("admin port binds");
    let runtime_config = notary_bundle_runtime_config()
        .replace(
            "127.0.0.1:4255",
            &public_listener
                .local_addr()
                .expect("public address")
                .to_string(),
        )
        .replace(
            "127.0.0.1:4256",
            &admin_listener
                .local_addr()
                .expect("admin address")
                .to_string(),
        );
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle_with_config(&tmp, runtime_config);
    let input = ServerConfigInput::SignedBundle {
        bundle_dir: fixture.bundle_dir.clone(),
        anchor_path: fixture.anchor_path.clone(),
        state_path: fixture.state_path.clone(),
    };

    initialize_state_once(input.clone())
        .await
        .expect("first initialization succeeds without binding listeners");

    let verified = verify_notary_product_bundle(&fixture.bundle_dir, &fixture.anchor_path)
        .expect("bundle remains verified");
    let expected =
        registry_platform_ops::VerifiedAcceptanceStateV1::from_verified_bundle(&verified)
            .expect("acceptance expectation builds");
    let record = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
        .verify_state(expected.expectation())
        .expect("sequence-1 state is exact");
    assert_eq!(record.last_sequence, 1);

    let second = initialize_state_once(input)
        .await
        .expect_err("initialization is one shot");
    assert_eq!(
        second
            .downcast_ref::<BundleVerificationFailure>()
            .expect("repeat initialization is a typed rollback rejection")
            .code(),
        BundleVerificationCode::REJECTED_ROLLBACK
    );

    drop(public_listener);
    drop(admin_listener);
    std::env::remove_var("TEST_NOTARY_LOADER_API_HASH");
    std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
    std::env::remove_var("TEST_NOTARY_LOADER_ISSUER_JWK");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn governed_boot_integrity_failure_persists_nothing_and_serves_nothing() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("TEST_NOTARY_LOADER_API_HASH", sha256_hash("api-token"));
    std::env::set_var(
        "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
        "registry-notary-loader-audit-secret-32-bytes",
    );
    std::env::set_var(
        "TEST_NOTARY_LOADER_ISSUER_JWK",
        demo_issuer_jwk("did:web:issuer.example#key-1").expect("issuer key generates"),
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let public_probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe binds");
    let public_addr = public_probe.local_addr().expect("probe address");
    let admin_probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe binds");
    let admin_addr = admin_probe.local_addr().expect("probe address");
    drop(public_probe);
    drop(admin_probe);

    let profile = registry_platform_audit::AuditProfile::registry_notary_from_env(
        "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
    )
    .expect("audit profile loads");
    {
        let sink = registry_platform_audit::JsonlFileSink::new(&audit_path);
        let chain = registry_platform_audit::ChainState::bootstrap_or_start_empty(
            &sink,
            profile.chain_hasher(),
        )
        .await
        .expect("audit chain starts");
        chain
            .append(&sink, json!({ "event": "governed.boot.preexisting" }))
            .await
            .expect("audit event writes");
    }
    let contents = std::fs::read_to_string(&audit_path).expect("audit reads");
    std::fs::write(
        &audit_path,
        contents.replace("governed.boot.preexisting", "governed.boot.tampered"),
    )
    .expect("audit is tampered");

    let runtime_config = notary_bundle_runtime_config()
        .replace("127.0.0.1:4255", &public_addr.to_string())
        .replace("127.0.0.1:4256", &admin_addr.to_string())
        .replace(
            "audit:\n  sink: stdout\n  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
            &format!(
                "audit:\n  sink: file\n  path: {}\n  hash_secret_env: TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
                audit_path.display()
            ),
        );
    let fixture = write_signed_notary_bundle_with_config(&tmp, runtime_config);
    let config_path = tmp.path().join("bootstrap.yaml");
    std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");

    let error = run_server(&config_path, None, true)
        .await
        .expect_err("governed boot audit failure aborts startup");
    assert_value_free_activation_failure(
        error.as_ref(),
        NotaryActivationCode::RUNTIME_ACTIVATION_FAILED,
        &[
            "audit chain verification failed",
            audit_path.to_str().expect("audit path is UTF-8"),
            "governed.boot.tampered",
        ],
    );
    let key = registry_platform_ops::AntiRollbackKey {
        acceptance_identity: notary_acceptance_identity(),
    };
    let state_error = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
        .load(&key)
        .expect_err("bundle acceptance state remains absent");
    assert_eq!(
        state_error,
        registry_platform_ops::AntiRollbackStoreError::MissingState
    );
    let rebound_public = std::net::TcpListener::bind(public_addr)
        .expect("public listener was released before any serving loop");
    let rebound_admin = std::net::TcpListener::bind(admin_addr)
        .expect("admin listener was released before any serving loop");
    drop(rebound_public);
    drop(rebound_admin);

    audit_quarantine(
        &config_path,
        AuditQuarantineArgs {
            reason: "recover governed first boot".to_string(),
            operator: Some("ci".to_string()),
        },
    )
    .expect("offline recovery can read the verified pending bundle");
    let state_after_recovery =
        registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
            .load(&key)
            .expect_err("offline audit recovery does not accept the bundle");
    assert_eq!(
        state_after_recovery,
        registry_platform_ops::AntiRollbackStoreError::MissingState
    );

    std::env::remove_var("TEST_NOTARY_LOADER_API_HASH");
    std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
    std::env::remove_var("TEST_NOTARY_LOADER_ISSUER_JWK");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn boot_listener_bind_failure_aborts_before_antirollback_persist() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("TEST_NOTARY_LOADER_API_HASH", sha256_hash("api-token"));
    std::env::set_var(
        "TEST_NOTARY_LOADER_AUDIT_HASH_SECRET",
        "registry-notary-loader-audit-secret-32-bytes",
    );
    std::env::set_var(
        "TEST_NOTARY_LOADER_ISSUER_JWK",
        demo_issuer_jwk("did:web:issuer.example#key-1").expect("issuer key generates"),
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_signed_notary_bundle(&tmp);
    let config_path = tmp.path().join("bootstrap.yaml");
    std::fs::write(&config_path, notary_bootstrap_config(&fixture)).expect("bootstrap writes");
    let held_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
    let held_addr = held_listener
        .local_addr()
        .expect("test listener exposes local addr");

    let error = run_server(&config_path, Some(held_addr), true)
        .await
        .expect_err("occupied listener rejects startup");

    assert!(
        error.to_string().contains("Address already in use"),
        "unexpected error: {error}"
    );
    let key = registry_platform_ops::AntiRollbackKey {
        acceptance_identity: notary_acceptance_identity(),
    };
    let err = registry_platform_ops::FileAntiRollbackStore::new(&fixture.state_path)
        .load(&key)
        .expect_err("state remains absent");
    assert_eq!(
        err,
        registry_platform_ops::AntiRollbackStoreError::MissingState
    );

    drop(held_listener);
    std::env::remove_var("TEST_NOTARY_LOADER_API_HASH");
    std::env::remove_var("TEST_NOTARY_LOADER_AUDIT_HASH_SECRET");
    std::env::remove_var("TEST_NOTARY_LOADER_ISSUER_JWK");
}

#[tokio::test]
async fn run_server_compiles_runtime_before_binding_listener() {
    let held_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
    let held_addr = held_listener
        .local_addr()
        .expect("test listener exposes local addr");
    let config_path = std::env::temp_dir().join(format!(
        "registry-notary-invalid-startup-{}.yaml",
        Ulid::new()
    ));
    let config = notary_test_config();
    fs::write(
        &config_path,
        serde_norway::to_string(&config).expect("startup config serializes"),
    )
    .expect("invalid startup config writes");

    let error = run_server(&config_path, Some(held_addr), false)
        .await
        .expect_err("invalid runtime config fails before serving");
    let message = error.to_string();

    assert_value_free_activation_failure(
        error.as_ref(),
        NotaryActivationCode::CONFIGURATION_INVALID,
        &[
            "TEST_DOCTOR_OAUTH_CLIENT_ID",
            "TEST_DOCTOR_OAUTH_CLIENT_SECRET",
            "audit.hash_secret_env",
        ],
    );
    assert!(
        !message.contains("Address already in use"),
        "server bound before compile failure: {message}"
    );

    let _ = fs::remove_file(config_path);
    drop(held_listener);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn run_server_fails_fast_when_active_signing_key_env_is_missing() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::set_var(
        "TEST_STARTUP_API_HASH",
        "sha256:31f2999a69fa6301763a9f61eea44388a13318ce8b80a16a115a9efdb62b883b",
    );
    std::env::set_var(
        "TEST_STARTUP_AUDIT_HASH_SECRET",
        "registry-notary-startup-audit-secret-32-bytes",
    );
    std::env::remove_var("TEST_STARTUP_ISSUER_JWK");

    let held_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener binds");
    let held_addr = held_listener
        .local_addr()
        .expect("test listener exposes local addr");
    let config_path = std::env::temp_dir().join(format!(
        "registry-notary-missing-signing-env-{}.yaml",
        Ulid::new()
    ));
    fs::write(
        &config_path,
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  api_keys:
    - id: local
      fingerprint:
        provider: env
        name: TEST_STARTUP_API_HASH
      scopes: [registry_notary:credential_issue]
audit:
  sink: stdout
  hash_secret_env: TEST_STARTUP_AUDIT_HASH_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer:
      provider: local_jwk_env
      private_jwk_env: TEST_STARTUP_ISSUER_JWK
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
"#,
    )
    .expect("startup config writes");

    let error = run_server(&config_path, Some(held_addr), false)
        .await
        .expect_err("missing signing key env fails before serving");
    let message = error.to_string();

    assert_value_free_activation_failure(
        error.as_ref(),
        NotaryActivationCode::CONFIGURATION_INVALID,
        &[
            "signing key 'issuer'",
            "private_jwk_env",
            "TEST_STARTUP_ISSUER_JWK",
        ],
    );
    assert!(
        !message.contains("Address already in use"),
        "server bound before signing key validation failed: {message}"
    );

    let _ = fs::remove_file(config_path);
    drop(held_listener);
    std::env::remove_var("TEST_STARTUP_API_HASH");
    std::env::remove_var("TEST_STARTUP_AUDIT_HASH_SECRET");
}

#[test]
fn bind_cli_override_wins_over_env() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::set_var("REGISTRY_NOTARY_BIND", "0.0.0.0:8080");
    let args = Args::try_parse_from([
        "registry-notary",
        "--bind",
        "127.0.0.1:9000",
        "explain-config",
    ])
    .expect("args parse");
    std::env::remove_var("REGISTRY_NOTARY_BIND");

    assert_eq!(
        args.bind,
        Some("127.0.0.1:9000".parse().expect("socket addr parses"))
    );
}

#[test]
fn env_bind_override_is_loaded_by_cli() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::set_var("REGISTRY_NOTARY_BIND", "0.0.0.0:8080");
    let args = Args::try_parse_from(["registry-notary", "explain-config"]).expect("args parse");
    std::env::remove_var("REGISTRY_NOTARY_BIND");

    assert_eq!(
        args.bind,
        Some("0.0.0.0:8080".parse().expect("socket addr parses"))
    );
}

#[test]
fn direct_signed_bundle_startup_arguments_resolve_as_one_closed_input() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::remove_var("REGISTRY_NOTARY_CONFIG");
    let args = Args::try_parse_from([
        "registry-notary",
        "--bundle-dir",
        "operator-inputs/notary-bundle",
        "--anchor-path",
        "operator-inputs/notary-trust-anchor.json",
        "--state-path",
        "runtime-state/notary-antirollback.json",
        "--initialize-state",
    ])
    .expect("complete direct bundle arguments parse");

    assert_eq!(
        server_config_input(&args).expect("server input resolves"),
        ServerConfigInput::SignedBundle {
            bundle_dir: PathBuf::from("operator-inputs/notary-bundle"),
            anchor_path: PathBuf::from("operator-inputs/notary-trust-anchor.json"),
            state_path: PathBuf::from("runtime-state/notary-antirollback.json"),
        }
    );
    assert!(args.initialize_state);
}

#[test]
fn direct_signed_bundle_startup_rejects_every_partial_argument_set() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::remove_var("REGISTRY_NOTARY_CONFIG");
    for partial in [
        vec!["--bundle-dir", "bundle"],
        vec!["--anchor-path", "anchor.json"],
        vec!["--state-path", "state.json"],
        vec!["--bundle-dir", "bundle", "--anchor-path", "anchor.json"],
        vec!["--bundle-dir", "bundle", "--state-path", "state.json"],
        vec!["--anchor-path", "anchor.json", "--state-path", "state.json"],
    ] {
        let mut argv = vec!["registry-notary"];
        argv.extend(partial);
        let error = Args::try_parse_from(argv).expect_err("partial bundle input must not parse");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}

#[test]
fn local_and_direct_signed_bundle_startup_inputs_are_mutually_exclusive() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::remove_var("REGISTRY_NOTARY_CONFIG");
    let error = Args::try_parse_from([
        "registry-notary",
        "--config",
        "/private/SENTINEL_LOCAL_CONFIG.yaml",
        "--bundle-dir",
        "bundle",
        "--anchor-path",
        "anchor.json",
        "--state-path",
        "state.json",
    ])
    .expect_err("mixed local and signed-bundle inputs must not parse");

    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    assert!(!error.to_string().contains("SENTINEL_LOCAL_CONFIG"));
}

#[test]
fn environment_local_config_cannot_silently_mix_with_direct_bundle_startup() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::set_var(
        "REGISTRY_NOTARY_CONFIG",
        "/private/SENTINEL_LOCAL_BOOTSTRAP_CONFIG.yaml",
    );
    let error = Args::try_parse_from([
        "registry-notary",
        "--bundle-dir",
        "bundle",
        "--anchor-path",
        "anchor.json",
        "--state-path",
        "state.json",
    ])
    .expect_err("environment config must conflict with direct bundle input");
    std::env::remove_var("REGISTRY_NOTARY_CONFIG");

    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    assert!(
        !error
            .to_string()
            .contains("SENTINEL_LOCAL_BOOTSTRAP_CONFIG"),
        "clap conflict diagnostics must not disclose the environment config path"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn env_file_local_config_cannot_silently_mix_with_direct_bundle_startup() {
    let _guard = ENV_LOCK.lock().expect("env lock is not poisoned");
    std::env::remove_var("REGISTRY_NOTARY_CONFIG");
    let tmp = tempfile::tempdir().expect("tempdir");
    let env_path = tmp.path().join("SENTINEL_PRIVATE_STARTUP.env");
    std::fs::write(
        &env_path,
        "REGISTRY_NOTARY_CONFIG=/private/SENTINEL_LOCAL_BOOTSTRAP_CONFIG.yaml\n",
    )
    .expect("env file writes");
    let args = Args::try_parse_from([
        "registry-notary",
        "--bundle-dir",
        "bundle",
        "--anchor-path",
        "anchor.json",
        "--state-path",
        "state.json",
        "--env-file",
        env_path.to_str().expect("env path is UTF-8"),
    ])
    .expect("arguments parse before the env file is loaded");

    let error = run(args)
        .await
        .expect_err("env-file local config must reject direct bundle startup");
    std::env::remove_var("REGISTRY_NOTARY_CONFIG");

    assert_value_free_activation_failure(
        error.as_ref(),
        NotaryActivationCode::CONFIGURATION_INVALID,
        &[
            "SENTINEL_PRIVATE_STARTUP",
            "SENTINEL_LOCAL_BOOTSTRAP_CONFIG",
            env_path.to_str().expect("env path is UTF-8"),
        ],
    );
}
