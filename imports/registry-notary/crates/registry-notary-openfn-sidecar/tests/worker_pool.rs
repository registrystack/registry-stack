use registry_notary_openfn_sidecar::{WorkerCommand, WorkerError, WorkerPool, WorkerPoolConfig};
use serde_json::json;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static WORKER_POOL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixture_command() -> WorkerCommand {
    WorkerCommand::new(cargo_bin("openfn-sidecar-worker-fixture"))
}

fn pool_config(max_workers: usize) -> WorkerPoolConfig {
    WorkerPoolConfig {
        command: fixture_command(),
        forbidden_env_names: BTreeSet::new(),
        max_workers,
        request_timeout: Duration::from_millis(30_000),
        max_request_bytes: 4096,
        max_stdout_bytes: 4096,
        max_stderr_bytes: 128,
        max_memory_bytes: None,
    }
}

#[tokio::test]
async fn worker_env_is_cleared_except_explicit_envs() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    std::env::set_var(
        "REGISTRY_NOTARY_TEST_SOURCE_CREDENTIAL_JSON",
        "source-secret",
    );
    std::env::set_var("REGISTRY_NOTARY_TEST_BEARER_HASH", "bearer-secret");
    let command = fixture_command().env("REGISTRY_NOTARY_TEST_ALLOWED", "benign");
    let mut config = pool_config(1);
    config.command = command;
    let pool = WorkerPool::new(config).await.unwrap();

    let response = pool
        .execute_json(json!({
            "mode": "env",
            "env_keys": [
                "REGISTRY_NOTARY_TEST_SOURCE_CREDENTIAL_JSON",
                "REGISTRY_NOTARY_TEST_BEARER_HASH",
                "REGISTRY_NOTARY_TEST_ALLOWED"
            ]
        }))
        .await
        .unwrap();

    assert!(response["env"]["REGISTRY_NOTARY_TEST_SOURCE_CREDENTIAL_JSON"].is_null());
    assert!(response["env"]["REGISTRY_NOTARY_TEST_BEARER_HASH"].is_null());
    assert_eq!(response["env"]["REGISTRY_NOTARY_TEST_ALLOWED"], "benign");
    std::env::remove_var("REGISTRY_NOTARY_TEST_SOURCE_CREDENTIAL_JSON");
    std::env::remove_var("REGISTRY_NOTARY_TEST_BEARER_HASH");
}

#[tokio::test]
async fn worker_config_rejects_forbidden_explicit_envs() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.forbidden_env_names.insert(OsString::from(
        "REGISTRY_NOTARY_TEST_SOURCE_CREDENTIAL_JSON",
    ));
    config.command = fixture_command().env(
        "REGISTRY_NOTARY_TEST_SOURCE_CREDENTIAL_JSON",
        "source-secret",
    );

    let error = match WorkerPool::new(config).await {
        Ok(_) => panic!("forbidden explicit worker env must fail validation"),
        Err(error) => error,
    };
    assert!(matches!(error, WorkerError::InvalidConfig { .. }));
}

#[cfg(unix)]
#[tokio::test]
async fn worker_reports_resource_limits() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let pool = WorkerPool::new(pool_config(1)).await.unwrap();

    let response = pool
        .execute_json(json!({ "mode": "rlimits" }))
        .await
        .unwrap();

    assert_eq!(response["rlimits"]["cpu"]["soft"], json!(60 * 60));
    assert_eq!(response["rlimits"]["fsize"]["soft"], json!(1024 * 1024));
    assert_eq!(response["rlimits"]["nofile"]["soft"], json!(64));
    assert_eq!(response["rlimits"]["core"]["soft"], json!(0));
    #[cfg(target_os = "linux")]
    assert_eq!(response["rlimits"]["nproc"]["soft"], json!(1024));
}

#[tokio::test]
async fn reuses_long_lived_workers_for_line_protocol_requests() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let pool = WorkerPool::new(pool_config(1)).await.unwrap();

    let first = pool
        .execute_json(json!({ "value": "first" }))
        .await
        .unwrap();
    let second = pool
        .execute_json(json!({ "value": "second" }))
        .await
        .unwrap();

    assert_eq!(first["ok"], true);
    assert_eq!(second["ok"], true);
    assert_eq!(first["pid"], second["pid"]);
    assert_eq!(first["value"], "first");
    assert_eq!(second["value"], "second");
}

#[tokio::test]
async fn returns_saturated_when_all_workers_are_busy() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let pool = Arc::new(WorkerPool::new(pool_config(1)).await.unwrap());
    let busy_pool = pool.clone();
    let busy = tokio::spawn(async move {
        busy_pool
            .execute_json(json!({ "mode": "sleep", "sleep_ms": 1_000 }))
            .await
            .unwrap()
    });

    wait_for_in_flight(&pool, 1).await;
    let error = pool
        .execute_json(json!({ "value": "must-not-queue" }))
        .await
        .unwrap_err();

    assert!(matches!(error, WorkerError::Saturated { max_workers: 1 }));
    let _ = busy.await.unwrap();
}

#[tokio::test]
async fn timeout_kills_worker_and_restarts_pool_without_retrying_request() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.request_timeout = Duration::from_millis(3_000);
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .unwrap_err();

    assert!(matches!(error, WorkerError::Timeout { .. }));
    let restarted = pool
        .execute_json(json!({ "value": "after" }))
        .await
        .unwrap();
    assert_eq!(restarted["ok"], true);
    assert_eq!(restarted["value"], "after");
}

#[tokio::test]
async fn oversized_stdout_kills_worker_and_restarts_pool() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.max_stdout_bytes = 64;
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "big-stdout", "stdout_bytes": 128 }))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        WorkerError::StdoutTooLarge { limit: 64, .. }
    ));
    let restarted = pool
        .execute_json(json!({ "value": "after" }))
        .await
        .unwrap();
    assert_eq!(restarted["value"], "after");
}

#[tokio::test]
async fn stderr_is_drained_but_retained_only_to_configured_cap() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.max_stderr_bytes = 32;
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "stderr-then-crash", "stderr_bytes": 256 }))
        .await
        .unwrap_err();
    let stderr = error.stderr().expect("stderr capture");

    assert!(matches!(error, WorkerError::WorkerExited { .. }));
    assert_eq!(stderr.len(), 32);
    assert!(stderr.is_truncated());
    assert_eq!(stderr.as_bytes(), &[b'e'; 32]);
    assert!(!format!("{error:?}").contains("eeee"));
    assert!(!error.to_string().contains("eeee"));
}

#[tokio::test]
async fn invalid_output_is_not_retried_for_the_same_request() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let state_path = unique_state_path();
    let command = fixture_command().env(
        OsString::from("WORKER_FIXTURE_STATE"),
        state_path.as_os_str().to_os_string(),
    );
    let mut config = pool_config(1);
    config.command = command;
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "fail-once-invalid-json" }))
        .await
        .unwrap_err();

    assert!(matches!(error, WorkerError::InvalidOutput { .. }));
    let after = pool
        .execute_json(json!({ "mode": "fail-once-invalid-json" }))
        .await
        .unwrap();
    assert_eq!(after["ok"], true);
}

#[tokio::test]
async fn request_size_is_checked_before_worker_acquisition() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.max_request_bytes = 8;
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "value": "too large" }))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        WorkerError::RequestTooLarge {
            bytes,
            limit: 8
        } if bytes > 8
    ));
}

fn unique_state_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "registry-notary-openfn-sidecar-worker-fixture-{nanos}.state"
    ))
}

fn cargo_bin(name: &str) -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_BIN_EXE_openfn-sidecar-worker-fixture"));
    if env_path
        .parent()
        .and_then(|parent| parent.file_name())
        .is_some_and(|file_name| file_name == "deps")
    {
        let candidate = env_path
            .parent()
            .and_then(|parent| parent.parent())
            .expect("target debug dir")
            .join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    env_path
}

async fn wait_for_in_flight(pool: &WorkerPool, expected: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if pool.snapshot().await.in_flight == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker pool did not reach in_flight={expected}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
