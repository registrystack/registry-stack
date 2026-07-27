use registry_notary_worker_harness::{
    WorkerCommand, WorkerError, WorkerPool, WorkerPoolConfig, WorkerStartupProbe,
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct WorkerPoolTestLock {
    path: PathBuf,
}

impl Drop for WorkerPoolTestLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn fixture_command() -> WorkerCommand {
    WorkerCommand::new(cargo_bin("registry-notary-worker-harness-fixture"))
}

fn pool_config(max_workers: usize) -> WorkerPoolConfig {
    WorkerPoolConfig {
        command: fixture_command(),
        forbidden_env_names: BTreeSet::new(),
        max_workers,
        startup_probe: Some(WorkerStartupProbe {
            request: json!({ "mode": "startup" }),
            expected_response: json!({ "ready": true }),
        }),
        startup_timeout: Duration::from_secs(30),
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
    let _guard = worker_pool_test_lock().await;
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
    let _guard = worker_pool_test_lock().await;
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

#[test]
fn startup_probe_timeout_validation_has_an_exact_liveness_boundary() {
    let mut config = pool_config(1);
    let required = Duration::from_millis(25) + Duration::from_nanos(1);

    assert_eq!(config.required_startup_timeout(), required);
    config.startup_timeout = required - Duration::from_nanos(1);
    let error = config
        .validate()
        .expect_err("the liveness window alone leaves no time for spawn and probe");
    assert!(matches!(
        error,
        WorkerError::InvalidConfig {
            reason: "startup_timeout must exceed the post-probe liveness window when startup_probe is configured"
        }
    ));

    config.startup_timeout = required;
    config
        .validate()
        .expect("one nanosecond beyond the liveness window is structurally valid");
}

#[test]
fn no_probe_timeout_validation_preserves_the_nonzero_boundary() {
    let mut config = pool_config(1);
    config.startup_probe = None;

    assert_eq!(config.required_startup_timeout(), Duration::from_nanos(1));
    config.startup_timeout = Duration::ZERO;
    let error = config
        .validate()
        .expect_err("a zero startup timeout remains invalid without a probe");
    assert!(matches!(
        error,
        WorkerError::InvalidConfig {
            reason: "startup_timeout must be greater than zero"
        }
    ));

    config.startup_timeout = Duration::from_nanos(1);
    config
        .validate()
        .expect("the smallest nonzero no-probe timeout remains valid");
}

#[tokio::test]
async fn startup_probe_requires_the_exact_response_before_admission() {
    let _guard = worker_pool_test_lock().await;
    let mut config = pool_config(1);
    config.startup_probe = Some(WorkerStartupProbe {
        request: json!({ "mode": "startup" }),
        expected_response: json!({ "ready": false }),
    });

    let error = match WorkerPool::new(config).await {
        Ok(_) => panic!("mismatched startup response must fail pool construction"),
        Err(error) => error,
    };

    assert!(matches!(error, WorkerError::StartupProbeFailed { .. }));
}

#[tokio::test]
async fn startup_probe_rejects_a_worker_that_exits_before_the_protocol_response() {
    let _guard = worker_pool_test_lock().await;
    let state_path = unique_state_path();
    let mut config = pool_config(1);
    config.command = fixture_command().env(
        OsString::from("WORKER_HARNESS_EXIT_ONCE_STATE"),
        state_path.as_os_str().to_os_string(),
    );

    let error = match WorkerPool::new(config.clone()).await {
        Ok(_) => panic!("worker exiting during startup must not be admitted"),
        Err(error) => error,
    };
    assert!(matches!(error, WorkerError::WorkerExited { .. }));
    wait_for_path(&state_path).await;

    let recovered = WorkerPool::new(config)
        .await
        .expect("a later process that passes the probe is admitted");
    assert!(recovered.check_ready().await);
}

#[tokio::test]
async fn startup_probe_rejects_a_worker_that_replies_then_exits() {
    let _guard = worker_pool_test_lock().await;
    let state_dir = unique_state_path();
    fs::create_dir(&state_dir).expect("create fixture start-ordinal directory");
    let mut config = pool_config(1);
    config.command = fixture_command()
        .env(
            OsString::from("WORKER_HARNESS_START_ORDINAL_DIR"),
            state_dir.as_os_str().to_os_string(),
        )
        .env("WORKER_HARNESS_EXIT_START_ORDINALS_THROUGH", "1")
        .env("WORKER_HARNESS_EXIT_AFTER_STARTUP_MS", "0");

    let error = match WorkerPool::new(config).await {
        Ok(_) => panic!("a startup reply without live capacity must not be admitted"),
        Err(error) => error,
    };

    assert!(matches!(error, WorkerError::WorkerExited { .. }));
    fs::remove_dir_all(&state_dir).expect("remove fixture start-ordinal directory");
}

#[tokio::test]
async fn startup_probe_failure_does_not_disclose_captured_stderr() {
    let _guard = worker_pool_test_lock().await;
    let secret = "STARTUP_PROBE_SECRET";
    let mut config = pool_config(1);
    config.startup_probe = Some(WorkerStartupProbe {
        request: json!({
            "mode": "stderr-then-crash",
            "stderr_bytes": 256,
            "stderr_payload": secret,
        }),
        expected_response: json!({ "ready": true }),
    });
    config.max_stderr_bytes = 32;

    let error = match WorkerPool::new(config).await {
        Ok(_) => panic!("crashing startup probe must fail pool construction"),
        Err(error) => error,
    };

    assert!(matches!(error, WorkerError::WorkerExited { .. }));
    assert!(!format!("{error:?}").contains(secret));
    assert!(!error.to_string().contains(secret));
}

#[tokio::test]
async fn startup_and_request_timeouts_are_independent() {
    let _guard = worker_pool_test_lock().await;
    let mut config = pool_config(1);
    config.startup_probe = Some(WorkerStartupProbe {
        request: json!({ "mode": "startup-sleep", "sleep_ms": 100 }),
        expected_response: json!({ "ready": true }),
    });
    config.startup_timeout = Duration::from_secs(1);
    config.request_timeout = Duration::from_millis(50);

    let pool = WorkerPool::new(config)
        .await
        .expect("slow startup probe fits its independent bound");
    let started = Instant::now();
    let error = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .expect_err("request uses the shorter evaluation bound");
    assert!(matches!(error, WorkerError::Timeout { .. }));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "request timeout must not inherit the startup bound"
    );
}

#[tokio::test]
async fn pool_startup_has_one_wall_clock_deadline_for_the_concurrent_batch() {
    let _guard = worker_pool_test_lock().await;
    let mut config = pool_config(3);
    config.startup_probe = Some(WorkerStartupProbe {
        request: json!({ "mode": "startup-sleep", "sleep_ms": 1_000 }),
        expected_response: json!({ "ready": true }),
    });
    config.startup_timeout = Duration::from_millis(100);

    let started = Instant::now();
    let error = match WorkerPool::new(config).await {
        Ok(_) => panic!("the whole startup batch must stop at the common deadline"),
        Err(error) => error,
    };
    let elapsed = started.elapsed();

    assert!(matches!(
        error,
        WorkerError::StartupTimeout { timeout }
            if timeout == Duration::from_millis(100)
    ));
    assert!(
        elapsed >= Duration::from_millis(75),
        "startup failed before the configured wall-clock deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(750),
        "pool startup exceeded its common wall-clock deadline: {elapsed:?}"
    );
}

#[tokio::test]
async fn request_size_is_checked_before_worker_acquisition() {
    let _guard = worker_pool_test_lock().await;
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
    let _guard = worker_pool_test_lock().await;
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
    let _guard = worker_pool_test_lock().await;
    let mut config = pool_config(1);
    config.request_timeout = Duration::from_secs(2);
    let pool = WorkerPool::new(config).await.unwrap();

    let error = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .unwrap_err();
    let failed_worker_id = error.worker_id().expect("timeout worker id");

    assert!(matches!(error, WorkerError::Timeout { .. }));
    wait_for_ready(&pool).await;
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
    let _guard = worker_pool_test_lock().await;
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
    wait_for_ready(&pool).await;
    let restarted = pool
        .execute_json_with_metadata(json!({ "value": "after" }))
        .await
        .unwrap();
    assert_ne!(failed_worker_id, restarted.worker_id);
    assert_eq!(restarted.value["value"], "after");
}

#[tokio::test]
async fn stderr_is_capped_and_not_disclosed_by_error_formatting() {
    let _guard = worker_pool_test_lock().await;
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
    let _guard = worker_pool_test_lock().await;
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
    let _guard = worker_pool_test_lock().await;
    let pool = WorkerPool::new(pool_config(1)).await.unwrap();
    pool.execute_json(json!({ "mode": "exit" }))
        .await
        .expect_err("exited worker fails the request");

    wait_for_not_ready(&pool).await;
    wait_for_ready(&pool).await;
    let response = pool
        .execute_json(json!({ "value": "after-replacement" }))
        .await
        .unwrap();
    assert_eq!(response["value"], "after-replacement");
}

#[tokio::test]
async fn repeated_worker_failures_open_circuit_and_recover_after_cooldown() {
    let _guard = worker_pool_test_lock().await;
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
    wait_for_ready(&pool).await;
    let snapshot = pool.snapshot().await;
    assert!(!snapshot.circuit_open);
    assert_eq!(snapshot.replacements_total, 1);

    let opens = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .unwrap_err();
    assert!(matches!(opens, WorkerError::Timeout { .. }));
    wait_for_circuit(&pool).await;
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
    wait_for_ready(&pool).await;
    let response = pool
        .execute_json(json!({ "value": "after-cooldown" }))
        .await
        .unwrap();
    assert_eq!(response["value"], "after-cooldown");
}

#[tokio::test]
async fn repeated_replacement_probe_failures_open_the_circuit() {
    let _guard = worker_pool_test_lock().await;
    let state_path = unique_state_path();
    let mut config = pool_config(1);
    config.command = fixture_command().env(
        OsString::from("WORKER_HARNESS_FAIL_AFTER_FIRST_START_STATE"),
        state_path.as_os_str().to_os_string(),
    );
    config.request_timeout = Duration::from_millis(50);
    config.max_replacements_per_window = 1;
    config.replacement_window = Duration::from_secs(60);
    let pool = WorkerPool::new(config)
        .await
        .expect("initial worker passes its startup probe");
    wait_for_path(&state_path).await;

    let error = pool
        .execute_json(json!({ "mode": "hang" }))
        .await
        .expect_err("request failure starts replacement recovery");
    assert!(matches!(error, WorkerError::Timeout { .. }));

    wait_for_background_circuit(&pool).await;
    assert!(!pool.check_ready().await);
    assert!(pool.snapshot().await.circuit_open);
}

#[tokio::test]
async fn replacement_batch_installs_healthy_worker_when_its_sibling_fails() {
    let _guard = worker_pool_test_lock().await;
    let state_dir = unique_state_path();
    fs::create_dir(&state_dir).expect("create fixture start-ordinal directory");
    let mut config = pool_config(2);
    config.command = fixture_command()
        .env(
            OsString::from("WORKER_HARNESS_START_ORDINAL_DIR"),
            state_dir.as_os_str().to_os_string(),
        )
        .env("WORKER_HARNESS_FAIL_START_ORDINAL", "3")
        .env("WORKER_HARNESS_EXIT_START_ORDINALS_THROUGH", "2")
        .env("WORKER_HARNESS_EXIT_AFTER_STARTUP_MS", "100");
    config.startup_timeout = Duration::from_secs(1);
    config.max_replacements_per_window = 2;
    config.replacement_window = Duration::from_secs(60);

    let pool = WorkerPool::new(config)
        .await
        .expect("both initial workers pass the startup probe");
    wait_for_start_ordinal(&state_dir, 2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !pool.check_ready().await,
        "dead initial workers must make readiness false"
    );

    wait_for_background_circuit(&pool).await;
    let snapshot = pool.snapshot().await;
    assert_eq!(
        snapshot.idle_workers, 1,
        "the healthy member of the mixed replacement batch must be installed"
    );
    assert_eq!(snapshot.replacements_total, 1);
    assert!(snapshot.circuit_open);
    assert!(
        !state_dir.join("5").exists(),
        "the circuit must open before another worker process is spawned"
    );
    fs::remove_dir_all(&state_dir).expect("remove fixture start-ordinal directory");
}

#[tokio::test]
async fn execute_does_not_wait_for_replenishment_after_circuit_cooldown() {
    let _guard = worker_pool_test_lock().await;
    let mut config = pool_config(1);
    config.request_timeout = Duration::from_secs(2);
    config.max_replacements_per_window = 1;
    config.replacement_window = Duration::from_secs(60);
    config.circuit_breaker_cooldown = Duration::from_millis(100);
    let pool = WorkerPool::new(config).await.unwrap();

    pool.execute_json(json!({ "mode": "hang" }))
        .await
        .expect_err("first timeout fails");
    wait_for_ready(&pool).await;
    pool.execute_json(json!({ "mode": "hang" }))
        .await
        .expect_err("second timeout opens circuit");
    wait_for_circuit(&pool).await;
    assert!(pool.snapshot().await.circuit_open);

    tokio::time::sleep(Duration::from_millis(150)).await;
    let error = pool
        .execute_json(json!({ "value": "after-direct-execute" }))
        .await
        .expect_err("request does not wait for a replacement startup");
    assert!(matches!(error, WorkerError::Saturated { max_workers: 1 }));
    wait_for_ready(&pool).await;
    let response = pool
        .execute_json(json!({ "value": "after-direct-execute" }))
        .await
        .expect("replacement serves a later request");
    assert_eq!(response["value"], "after-direct-execute");
}

#[tokio::test]
async fn worker_stdout_is_drained_while_large_stdin_request_is_written() {
    let _guard = worker_pool_test_lock().await;
    let mut config = pool_config(1);
    config.command = fixture_command().env("WORKER_HARNESS_PREWRITE_STDOUT_BYTES", "131072");
    config.startup_probe = None;
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

async fn worker_pool_test_lock() -> WorkerPoolTestLock {
    let path = std::env::temp_dir().join("registry-notary-worker-pool-tests.lock");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match fs::create_dir(&path) {
            Ok(()) => return WorkerPoolTestLock { path },
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for worker pool test lock: {}",
                    path.display()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!(
                "failed to create worker pool test lock {}: {error}",
                path.display()
            ),
        }
    }
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

async fn wait_for_start_ordinal(directory: &Path, ordinal: usize) {
    wait_for_path(&directory.join(ordinal.to_string())).await;
}

async fn wait_for_not_ready(pool: &WorkerPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !pool.check_ready().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker pool did not observe an unready worker"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_ready(pool: &WorkerPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if pool.check_ready().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker pool did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_circuit(pool: &WorkerPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let _ = pool.check_ready().await;
        if pool.snapshot().await.circuit_open {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker pool circuit did not open"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_background_circuit(pool: &WorkerPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if pool.snapshot().await.circuit_open {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "background replenishment did not open the worker pool circuit"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
