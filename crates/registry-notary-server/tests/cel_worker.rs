#![cfg(feature = "registry-notary-cel")]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use registry_notary_core::RegistryNotaryCelConfig;
use registry_notary_server::cel_worker::{
    cel_policy_hash, CelWorker, CelWorkerConfig, CelWorkerError, CelWorkerLimits,
    CEL_WORKER_MAX_STDIN_BYTES,
};
use registry_notary_worker_harness::WorkerError;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[cfg(feature = "cel-worker-fixture")]
static CEL_WORKER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn cel_worker_bin() -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_BIN_EXE_registry-notary-cel-worker"));
    if env_path
        .parent()
        .and_then(|parent| parent.file_name())
        .is_some_and(|file_name| file_name == "deps")
    {
        let candidate = env_path
            .parent()
            .and_then(|parent| parent.parent())
            .expect("target debug dir")
            .join("registry-notary-cel-worker");
        if candidate.is_file() {
            return candidate;
        }
    }
    env_path
}

#[cfg(feature = "cel-worker-fixture")]
fn cel_worker_fixture_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_registry-notary-cel-worker-fixture"))
}

fn config() -> CelWorkerConfig {
    CelWorkerConfig {
        command: cel_worker_bin(),
        command_args: Vec::new(),
        command_envs: Vec::new(),
        current_dir: None,
        max_workers: 1,
        request_timeout: Duration::from_secs(5),
        max_request_bytes: 8192,
        max_response_bytes: 8192,
        max_stderr_bytes: 128,
        max_memory_bytes: None,
        allow_regex: false,
        limits: CelWorkerLimits::default(),
        forbidden_env_names: BTreeSet::from([
            OsString::from("REGISTRY_NOTARY_TEST_HSM_PIN"),
            OsString::from("REGISTRY_NOTARY_TEST_UNRELATED_SECRET"),
        ]),
    }
}

#[test]
fn cel_worker_default_standalone_request_size_fits_stdio_frame() {
    let worker = CelWorkerConfig::from_standalone_config(&RegistryNotaryCelConfig::default());

    assert!(
        worker.max_request_bytes <= CEL_WORKER_MAX_STDIN_BYTES,
        "default standalone CEL request cap {} exceeds worker stdin cap {}",
        worker.max_request_bytes,
        CEL_WORKER_MAX_STDIN_BYTES
    );
}

#[test]
fn cel_worker_max_standalone_request_size_fits_stdio_frame() {
    let config = RegistryNotaryCelConfig {
        max_binding_json_bytes: 1024 * 1024,
        max_expression_bytes: 256 * 1024,
        ..RegistryNotaryCelConfig::default()
    };
    let worker = CelWorkerConfig::from_standalone_config(&config);

    assert!(
        worker.max_request_bytes <= CEL_WORKER_MAX_STDIN_BYTES,
        "maximum standalone CEL request cap {} exceeds worker stdin cap {}",
        worker.max_request_bytes,
        CEL_WORKER_MAX_STDIN_BYTES
    );
}

#[cfg(feature = "cel-worker-fixture")]
fn fixture_config() -> CelWorkerConfig {
    CelWorkerConfig {
        command: cel_worker_fixture_bin(),
        command_args: Vec::new(),
        command_envs: Vec::new(),
        current_dir: None,
        max_workers: 1,
        request_timeout: Duration::from_secs(5),
        max_request_bytes: 8192,
        max_response_bytes: 8192,
        max_stderr_bytes: 128,
        max_memory_bytes: None,
        allow_regex: false,
        limits: CelWorkerLimits::default(),
        forbidden_env_names: BTreeSet::from([
            OsString::from("REGISTRY_NOTARY_TEST_HSM_PIN"),
            OsString::from("REGISTRY_NOTARY_TEST_UNRELATED_SECRET"),
        ]),
    }
}

#[tokio::test]
async fn cel_worker_evaluates_through_bounded_process_protocol() {
    let worker = CelWorker::new(config()).await.expect("worker starts");

    let value = worker
        .evaluate(
            "source.birth.age >= vars.minimum_age",
            json!({
                "source": { "birth": { "age": 21 } },
                "vars": { "minimum_age": 18 },
                "claims": {},
                "ctx": { "purpose": "test" },
                "meta": {}
            }),
        )
        .await
        .expect("CEL evaluates");

    assert_eq!(value, json!(true));
}

#[tokio::test]
async fn cel_worker_protocol_accepts_json_escaped_multiline_expression() {
    let worker = CelWorker::new(config()).await.expect("worker starts");
    let expression = "health.exists && health.date_of_birth != null\n  ? date.age_on(health.date_of_birth, as_of_date)\n  : null";

    let value = worker
        .evaluate(
            expression,
            json!({
                "health": {
                    "exists": true,
                    "date_of_birth": "2017-06-15",
                },
                "as_of_date": "2026-01-01",
            }),
        )
        .await
        .expect("escaped newlines survive the worker request envelope");

    assert_eq!(value, json!(8));
}

#[tokio::test]
async fn cel_worker_protocol_preserves_successful_null_result() {
    let worker = CelWorker::new(config()).await.expect("worker starts");

    let value = worker
        .evaluate("null", json!({}))
        .await
        .expect("CEL null is a successful result");

    assert_eq!(value, serde_json::Value::Null);
}

#[tokio::test]
async fn cel_worker_evaluates_date_age_against_context_today() {
    let worker = CelWorker::new(config()).await.expect("worker starts");

    let value = worker
        .evaluate(
            "date.age_on(source.patient.birth_date, ctx.today) >= 18",
            json!({
                "source": { "patient": { "birth_date": "2000-06-16" } },
                "vars": {},
                "claims": {},
                "ctx": {
                    "purpose": "test",
                    "today": "2026-06-16"
                },
                "meta": {}
            }),
        )
        .await
        .expect("CEL evaluates");

    assert_eq!(value, json!(true));
}

#[tokio::test]
async fn cel_worker_snapshot_reports_ready_capacity() {
    let worker = CelWorker::new(CelWorkerConfig {
        max_workers: 2,
        ..config()
    })
    .await
    .expect("worker starts");

    let snapshot = worker.snapshot().await.expect("snapshot succeeds");

    assert_eq!(snapshot.max_workers, 2);
    assert_eq!(snapshot.idle_workers, 2);
    assert_eq!(snapshot.in_flight, 0);
    assert!(worker.check_ready().await);
}

#[tokio::test]
async fn cel_worker_request_size_cap_applies_before_worker_dispatch() {
    let worker = CelWorker::new(CelWorkerConfig {
        max_request_bytes: 64,
        ..config()
    })
    .await
    .expect("worker starts");

    let error = worker
        .evaluate(
            "true",
            json!({
                "source": { "value": "x".repeat(256) },
                "vars": {},
                "claims": {},
                "ctx": {},
                "meta": {}
            }),
        )
        .await
        .expect_err("oversized request fails before dispatch");

    assert!(matches!(
        error,
        CelWorkerError::Harness(WorkerError::RequestTooLarge { limit: 64, .. })
    ));
    let snapshot = worker.snapshot().await.expect("snapshot succeeds");
    assert_eq!(snapshot.idle_workers, 1);
    assert_eq!(snapshot.in_flight, 0);
}

#[tokio::test]
async fn cel_worker_errors_do_not_disclose_expression_or_bindings() {
    let worker = CelWorker::new(config()).await.expect("worker starts");
    let secret = "secret-source-value";
    let expression = "source.birth.value == 'secret-source-value' && unknown(";

    let error = worker
        .evaluate(
            expression,
            json!({
                "source": { "birth": { "value": secret } },
                "vars": {},
                "claims": {},
                "ctx": {},
                "meta": {}
            }),
        )
        .await
        .expect_err("invalid expression fails");

    let debug = format!("{error:?}");
    let display = error.to_string();
    assert!(matches!(error, CelWorkerError::Compile));
    assert!(!debug.contains(expression));
    assert!(!display.contains(expression));
    assert!(!debug.contains(secret));
    assert!(!display.contains(secret));
}

#[tokio::test]
#[cfg(feature = "cel-worker-fixture")]
async fn cel_worker_timeout_kills_and_replaces_fixture_worker() {
    let _guard = CEL_WORKER_TEST_LOCK.lock().await;
    let worker = CelWorker::new(fixture_config())
        .await
        .expect("worker starts");

    let error = worker
        .evaluate("fixture.hang", json!({}))
        .await
        .expect_err("hung worker times out");

    assert!(matches!(
        error,
        CelWorkerError::Harness(WorkerError::Timeout { .. })
    ));
    let restarted = worker
        .evaluate("fixture.value", json!({ "value": "after-timeout" }))
        .await
        .expect("replacement worker answers");
    assert_eq!(restarted, json!("after-timeout"));
}

#[tokio::test]
#[cfg(feature = "cel-worker-fixture")]
async fn cel_worker_stdout_cap_kills_and_replaces_fixture_worker() {
    let _guard = CEL_WORKER_TEST_LOCK.lock().await;
    let worker = CelWorker::new(CelWorkerConfig {
        max_response_bytes: 256,
        ..fixture_config()
    })
    .await
    .expect("worker starts");

    let error = worker
        .evaluate("fixture.big_stdout", json!({ "stdout_bytes": 512 }))
        .await
        .expect_err("oversized worker stdout fails");

    assert!(
        matches!(
            error,
            CelWorkerError::Harness(WorkerError::StdoutTooLarge { limit: 256, .. })
        ),
        "{error:?}"
    );
    let restarted = worker
        .evaluate("fixture.value", json!({ "value": "ok" }))
        .await
        .expect("replacement worker answers");
    assert_eq!(restarted, json!("ok"));
}

#[tokio::test]
#[cfg(feature = "cel-worker-fixture")]
async fn cel_worker_stderr_cap_does_not_disclose_fixture_stderr() {
    let _guard = CEL_WORKER_TEST_LOCK.lock().await;
    let worker = CelWorker::new(CelWorkerConfig {
        max_stderr_bytes: 8,
        ..fixture_config()
    })
    .await
    .expect("worker starts");
    let secret = "stderr-secret-value";

    let error = worker
        .evaluate(
            "fixture.stderr_then_crash",
            json!({ "stderr_bytes": 128, "secret": secret }),
        )
        .await
        .expect_err("fixture exits after writing stderr");

    assert!(
        matches!(
            error,
            CelWorkerError::Harness(WorkerError::WorkerExited { .. })
        ),
        "{error:?}"
    );
    let debug = format!("{error:?}");
    let display = error.to_string();
    assert!(!debug.contains(secret));
    assert!(!display.contains(secret));
}

#[tokio::test]
async fn cel_stdio_worker_rejects_oversized_stdin_frame() {
    let mut child = Command::new(cel_worker_bin())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("worker process starts");
    let mut stdin = child.stdin.take().expect("worker stdin is piped");
    let oversized = format!("{}\n", "x".repeat(CEL_WORKER_MAX_STDIN_BYTES + 1));

    if let Err(error) = stdin.write_all(oversized.as_bytes()).await {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("worker exits after oversized frame")
        .expect("worker status");

    assert!(!status.success());
}

#[tokio::test]
async fn cel_stdio_worker_echoes_policy_hash() {
    let expression = "source.age >= 18";
    let policy_hash = cel_policy_hash(expression);
    let mut child = Command::new(cel_worker_bin())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("worker starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(
            serde_json::to_string(&json!({
                "protocol": "registry-notary-cel-worker/v1",
                "policy_hash": policy_hash,
                "expression": expression,
                "root_bindings": {
                    "source": { "age": 21 },
                    "claims": {},
                    "ctx": {},
                    "vars": {},
                    "meta": {}
                }
            }))
            .expect("request serializes")
            .as_bytes(),
        )
        .await
        .expect("write request");
    stdin.write_all(b"\n").await.expect("write newline");
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .expect("worker exits after stdin closes");
    assert!(output.status.success());
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("worker emits JSON");
    assert_eq!(response["policy_hash"], json!(cel_policy_hash(expression)));
    assert_eq!(response["status"], json!("success"));
    assert_eq!(response["value"], json!(true));
}

#[tokio::test]
async fn cel_stdio_worker_rejects_regex_helpers_by_default() {
    let expression = "text.regex_extract(source.name, '^A(.+)$', 1)";
    let mut child = Command::new(cel_worker_bin())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("worker starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(
            serde_json::to_string(&json!({
                "protocol": "registry-notary-cel-worker/v1",
                "policy_hash": cel_policy_hash(expression),
                "expression": expression,
                "root_bindings": {
                    "source": { "name": "Amina" },
                    "claims": {},
                    "ctx": {},
                    "vars": {},
                    "meta": {}
                }
            }))
            .expect("request serializes")
            .as_bytes(),
        )
        .await
        .expect("write request");
    stdin.write_all(b"\n").await.expect("write newline");
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .expect("worker exits after stdin closes");
    assert!(output.status.success());
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("worker emits JSON");
    assert_eq!(response["policy_hash"], json!(cel_policy_hash(expression)));
    assert_eq!(response["status"], json!("error"));
    assert_eq!(response["error"], json!("compile"));
    assert!(response.get("value").is_none());
}

#[tokio::test]
#[cfg(feature = "cel-worker-fixture")]
async fn cel_worker_env_is_cleared_except_explicit_allow_list() {
    let _guard = CEL_WORKER_TEST_LOCK.lock().await;
    std::env::set_var("REGISTRY_NOTARY_TEST_UNRELATED_SECRET", "unrelated-secret");
    std::env::set_var("REGISTRY_NOTARY_TEST_HSM_PIN", "1234");
    let mut config = fixture_config();
    config.command_envs.push((
        OsString::from("REGISTRY_NOTARY_TEST_ALLOWED"),
        OsString::from("benign"),
    ));
    let worker = CelWorker::new(config).await.expect("worker starts");

    let value = worker
        .evaluate(
            "fixture.env",
            json!({
                "env_keys": [
                    "REGISTRY_NOTARY_TEST_UNRELATED_SECRET",
                    "REGISTRY_NOTARY_TEST_HSM_PIN",
                    "REGISTRY_NOTARY_TEST_ALLOWED"
                ]
            }),
        )
        .await
        .expect("fixture reads env");

    assert!(value["REGISTRY_NOTARY_TEST_UNRELATED_SECRET"].is_null());
    assert!(value["REGISTRY_NOTARY_TEST_HSM_PIN"].is_null());
    assert_eq!(value["REGISTRY_NOTARY_TEST_ALLOWED"], "benign");
    std::env::remove_var("REGISTRY_NOTARY_TEST_UNRELATED_SECRET");
    std::env::remove_var("REGISTRY_NOTARY_TEST_HSM_PIN");
}

#[tokio::test]
async fn cel_worker_rejects_forbidden_explicit_env_names() {
    let mut config = config();
    config.command_envs.push((
        OsString::from("REGISTRY_NOTARY_TEST_HSM_PIN"),
        OsString::from("1234"),
    ));

    let error = CelWorker::new(config)
        .await
        .expect_err("forbidden explicit worker env fails validation");

    assert!(matches!(error, CelWorkerError::Harness { .. }));
}

#[test]
fn cel_worker_validate_config_rejects_missing_explicit_command_path() {
    let worker = CelWorker::lazy(CelWorkerConfig {
        command: PathBuf::from("/registry-notary-test/missing-cel-worker"),
        ..config()
    });

    let error = worker
        .validate_config()
        .expect_err("missing explicit command path fails validation");

    assert!(matches!(error, CelWorkerError::Harness { .. }));
    let text = error.to_string();
    assert!(!text.contains("missing-cel-worker"));
}
