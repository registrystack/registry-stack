use registry_notary_worker_harness::{WorkerCommand, WorkerError, WorkerPool, WorkerPoolConfig};
use serde_json::json;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static WORKER_POOL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixture_command() -> WorkerCommand {
    WorkerCommand::new(cargo_bin("registry-notary-worker-harness-fixture"))
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
        replacement_window: Duration::from_secs(60),
        max_replacements_per_window: 64,
        circuit_breaker_cooldown: Duration::from_secs(30),
    }
}

#[tokio::test]
async fn worker_env_is_cleared_except_allow_list_and_explicit_envs() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    std::env::set_var("REGISTRY_NOTARY_HARNESS_SECRET", "source-secret");
    std::env::set_var("REGISTRY_NOTARY_HARNESS_BEARER", "bearer-secret");
    let command = fixture_command().env("REGISTRY_NOTARY_HARNESS_ALLOWED", "benign");
    let mut config = pool_config(1);
    config.command = command;
    let pool = WorkerPool::new(config).await.unwrap();

    let response = pool
        .execute_json(json!({
            "mode": "env",
            "env_keys": [
                "REGISTRY_NOTARY_HARNESS_SECRET",
                "REGISTRY_NOTARY_HARNESS_BEARER",
                "REGISTRY_NOTARY_HARNESS_ALLOWED",
                "PATH"
            ]
        }))
        .await
        .unwrap();

    assert!(response["env"]["REGISTRY_NOTARY_HARNESS_SECRET"].is_null());
    assert!(response["env"]["REGISTRY_NOTARY_HARNESS_BEARER"].is_null());
    assert_eq!(response["env"]["REGISTRY_NOTARY_HARNESS_ALLOWED"], "benign");
    assert_eq!(
        response["env"]["PATH"],
        std::env::var("PATH").unwrap_or_default()
    );
    std::env::remove_var("REGISTRY_NOTARY_HARNESS_SECRET");
    std::env::remove_var("REGISTRY_NOTARY_HARNESS_BEARER");
}

#[tokio::test]
async fn worker_config_rejects_forbidden_explicit_envs() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config
        .forbidden_env_names
        .insert(OsString::from("REGISTRY_NOTARY_HARNESS_SECRET"));
    config.command = fixture_command().env("REGISTRY_NOTARY_HARNESS_SECRET", "source-secret");

    let error = match WorkerPool::new(config).await {
        Ok(_) => panic!("forbidden explicit worker env must fail validation"),
        Err(error) => error,
    };
    assert!(matches!(error, WorkerError::InvalidConfig { .. }));
}

#[tokio::test]
async fn request_size_is_checked_before_worker_acquisition() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.max_request_bytes = 64;
    let pool = Arc::new(WorkerPool::new(config).await.unwrap());
    let busy_pool = pool.clone();
    let busy = tokio::spawn(async move {
        busy_pool
            .execute_json(json!({ "mode": "sleep", "sleep_ms": 300 }))
            .await
            .unwrap()
    });

    wait_for_in_flight(&pool, 1).await;
    assert_eq!(pool.snapshot().await.idle_workers, 0);
    let error = pool
        .execute_json(json!({
            "value": "this request is too large for the configured cap and must be rejected before worker acquisition"
        }))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        WorkerError::RequestTooLarge {
            bytes,
            limit: 64
        } if bytes > 64
    ));
    let _ = busy.await.unwrap();
}

#[tokio::test]
async fn returns_saturated_when_all_workers_are_busy() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let pool = Arc::new(WorkerPool::new(pool_config(1)).await.unwrap());
    let busy_pool = pool.clone();
    let busy = tokio::spawn(async move {
        busy_pool
            .execute_json(json!({ "mode": "sleep", "sleep_ms": 300 }))
            .await
            .unwrap()
    });

    wait_for_in_flight(&pool, 1).await;
    let error = pool
        .execute_json(json!({ "value": "small" }))
        .await
        .unwrap_err();

    assert!(matches!(error, WorkerError::Saturated { max_workers: 1 }));
    let _ = busy.await.unwrap();
}

#[tokio::test]
async fn timeout_kills_worker_and_replaces_it_without_retrying_request() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.request_timeout = Duration::from_millis(100);
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .unwrap_err();
    let failed_worker_id = error.worker_id().expect("timeout worker id");

    assert!(matches!(error, WorkerError::Timeout { .. }));
    let restarted = pool
        .execute_json_with_metadata(json!({ "value": "after" }))
        .await
        .unwrap();
    assert_ne!(failed_worker_id, restarted.worker_id);
    assert_eq!(restarted.value["ok"], true);
    assert_eq!(restarted.value["value"], "after");
    assert_eq!(pool.snapshot().await.completed_total, 2);
}

#[tokio::test]
async fn oversized_stdout_kills_worker_and_replaces_it() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.max_stdout_bytes = 64;
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "big-stdout", "stdout_bytes": 128 }))
        .await
        .unwrap_err();
    let failed_worker_id = error.worker_id().expect("stdout worker id");

    assert!(matches!(
        error,
        WorkerError::StdoutTooLarge { limit: 64, .. }
    ));
    let restarted = pool
        .execute_json_with_metadata(json!({ "value": "after" }))
        .await
        .unwrap();
    assert_ne!(failed_worker_id, restarted.worker_id);
    assert_eq!(restarted.value["value"], "after");
}

#[tokio::test]
async fn stderr_is_capped_and_not_disclosed_by_error_formatting() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.max_stderr_bytes = 32;
    let pool = WorkerPool::new(config).await.unwrap();
    let secret = "HARNESS_SECRET";

    let error = pool
        .execute_json(json!({
            "mode": "stderr-then-crash",
            "stderr_bytes": 256,
            "stderr_payload": secret
        }))
        .await
        .unwrap_err();
    let stderr = error.stderr().expect("stderr capture");

    assert!(matches!(error, WorkerError::WorkerExited { .. }));
    assert_eq!(stderr.len(), 32);
    assert!(stderr.is_truncated());
    assert!(stderr.to_string_lossy().starts_with(secret));
    assert!(!format!("{error:?}").contains(secret));
    assert!(!error.to_string().contains(secret));
}

#[tokio::test]
async fn snapshot_counters_track_idle_busy_and_completed_workers() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let pool = Arc::new(WorkerPool::new(pool_config(1)).await.unwrap());
    let initial = pool.snapshot().await;
    assert_eq!(initial.max_workers, 1);
    assert_eq!(initial.idle_workers, 1);
    assert_eq!(initial.in_flight, 0);
    assert_eq!(initial.completed_total, 0);
    assert!(initial.active_for.is_none());
    assert!(initial.completed_within.is_none());

    let busy_pool = pool.clone();
    let busy = tokio::spawn(async move {
        busy_pool
            .execute_json(json!({ "mode": "sleep", "sleep_ms": 150 }))
            .await
            .unwrap()
    });
    wait_for_in_flight(&pool, 1).await;
    let active = pool.snapshot().await;
    assert_eq!(active.idle_workers, 0);
    assert_eq!(active.in_flight, 1);
    assert_eq!(active.completed_total, 0);
    assert!(active.active_for.is_some());

    let _ = busy.await.unwrap();
    wait_for_in_flight(&pool, 0).await;
    let completed = pool.snapshot().await;
    assert_eq!(completed.idle_workers, 1);
    assert_eq!(completed.in_flight, 0);
    assert_eq!(completed.completed_total, 1);
    assert!(completed.active_for.is_none());
    assert!(completed.completed_within.is_some());
}

#[tokio::test]
async fn check_ready_detects_replaces_and_fails_current_check_for_dead_idle_worker() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let state_path = unique_state_path();
    let mut config = pool_config(1);
    config.command = fixture_command().env(
        OsString::from("WORKER_HARNESS_EXIT_ONCE_STATE"),
        state_path.as_os_str().to_os_string(),
    );
    let pool = WorkerPool::new(config).await.unwrap();
    wait_for_path(&state_path).await;

    assert!(!pool.check_ready().await);
    assert!(pool.check_ready().await);
    let response = pool
        .execute_json(json!({ "value": "after-replacement" }))
        .await
        .unwrap();
    assert_eq!(response["value"], "after-replacement");
}

#[tokio::test]
async fn repeated_worker_failures_open_circuit_and_recover_after_cooldown() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.request_timeout = Duration::from_secs(1);
    config.max_replacements_per_window = 1;
    config.replacement_window = Duration::from_secs(60);
    config.circuit_breaker_cooldown = Duration::from_millis(100);
    let pool = WorkerPool::new(config).await.unwrap();

    let first = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .unwrap_err();
    assert!(matches!(first, WorkerError::Timeout { .. }));
    let snapshot = pool.snapshot().await;
    assert!(!snapshot.circuit_open);
    assert_eq!(snapshot.replacements_total, 1);

    let opens = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .unwrap_err();
    assert!(matches!(opens, WorkerError::Timeout { .. }));
    let snapshot = pool.snapshot().await;
    assert!(snapshot.circuit_open);
    assert_eq!(snapshot.replacements_total, 1);
    assert!(!pool.check_ready().await);

    let second = pool
        .execute_json(json!({ "value": "blocked" }))
        .await
        .unwrap_err();
    assert!(matches!(second, WorkerError::CircuitOpen { .. }));

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!pool.check_ready().await);
    assert!(pool.check_ready().await);
    let response = pool
        .execute_json(json!({ "value": "after-cooldown" }))
        .await
        .unwrap();
    assert_eq!(response["value"], "after-cooldown");
}

#[tokio::test]
async fn execute_replenishes_worker_after_circuit_cooldown_without_readiness_probe() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.request_timeout = Duration::from_millis(100);
    config.max_replacements_per_window = 1;
    config.replacement_window = Duration::from_secs(60);
    config.circuit_breaker_cooldown = Duration::from_millis(100);
    let pool = WorkerPool::new(config).await.unwrap();

    pool.execute_json(json!({ "mode": "hang" }))
        .await
        .expect_err("first timeout fails");
    pool.execute_json(json!({ "mode": "hang" }))
        .await
        .expect_err("second timeout opens circuit");
    assert!(pool.snapshot().await.circuit_open);

    tokio::time::sleep(Duration::from_millis(150)).await;
    let response = pool
        .execute_json(json!({ "value": "after-direct-execute" }))
        .await
        .expect("execute path replenishes after cooldown");
    assert_eq!(response["value"], "after-direct-execute");
}

#[tokio::test]
async fn worker_stdout_is_drained_while_large_stdin_request_is_written() {
    let _guard = WORKER_POOL_TEST_LOCK.lock().await;
    let mut config = pool_config(1);
    config.command = fixture_command().env("WORKER_HARNESS_PREWRITE_STDOUT_BYTES", "131072");
    config.request_timeout = Duration::from_secs(5);
    config.max_request_bytes = 192 * 1024;
    config.max_stdout_bytes = 192 * 1024;
    let pool = WorkerPool::new(config).await.unwrap();

    let response = pool
        .execute_json(json!({ "value": "x".repeat(128 * 1024) }))
        .await
        .expect("duplex request avoids pipe-buffer deadlock");

    assert_eq!(response["ok"], true);
    assert_eq!(
        response["prewritten"]
            .as_str()
            .expect("prewritten payload is string")
            .len(),
        131072
    );
}

fn cargo_bin(name: &str) -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_BIN_EXE_registry-notary-worker-harness-fixture"));
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

fn unique_state_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "registry-notary-worker-harness-fixture-{nanos}.state"
    ))
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

async fn wait_for_path(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if path.exists() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "fixture state path was not created: {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
