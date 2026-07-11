// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

#[test]
fn boot_bundle_acceptance_audit_failure_aborts_before_antirollback_persist() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_path = tmp.path().join("antirollback.json");
    let acceptance = PendingBundleAcceptance {
        state_path: state_path.clone(),
        key: registry_platform_ops::AntiRollbackKey {
            product: "registry-notary".to_string(),
            instance_id: "notary-loader".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-loader-test".to_string(),
        },
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
        product: "registry-notary".to_string(),
        instance_id: String::new(),
        environment: "development".to_string(),
        stream_id: "notary-loader-test".to_string(),
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
    let config = doctor_live_test_config("http://127.0.0.1:1");
    fs::write(
        &config_path,
        serde_norway::to_string(&config).expect("startup config serializes"),
    )
    .expect("invalid startup config writes");

    let error = run_server(&config_path, Some(held_addr), false)
        .await
        .expect_err("invalid runtime config fails before serving");
    let message = error.to_string();

    assert!(
        message.contains("TEST_DOCTOR_OAUTH_CLIENT_ID")
            || message.contains("TEST_DOCTOR_OAUTH_CLIENT_SECRET")
            || message.contains("audit.hash_secret_env"),
        "unexpected error: {message}"
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
  mode: api_key
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

    assert!(
        message.contains("signing key 'issuer' is invalid")
            && message.contains("private_jwk_env is missing or empty"),
        "unexpected error: {message}"
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
