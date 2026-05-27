// SPDX-License-Identifier: Apache-2.0

use axum_test::TestServer;
use registry_witness_openfn_sidecar::{sidecar_router, SidecarConfig};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

const DATASET: &str = "civil_registry";
const ENTITY: &str = "civil_person";
const LOOKUP_FIELD: &str = "national_id";
const PURPOSE: &str = "https://purpose.example.test/eligibility";
const TOKEN: &str = "contract-sidecar-token";
const TOKEN_HASH_ENV: &str = "OPENFN_CONTRACT_LOG_SIDECAR_TOKEN_HASH";
const TOKEN_HASH: &str = "sha256:98808b694f3b431dcc2459db07bbfb61b8e3287ad0ab7364a2ff510d35e21418";
const CREDENTIAL_ENV: &str = "OPENCRVS_READER_CREDENTIAL_JSON";

#[derive(Clone)]
struct SharedLogWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for SharedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buffer.lock().expect("log buffer lock").extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn structured_logs_do_not_disclose_credentials_or_request_state() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let writer_logs = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || SharedLogWriter {
            buffer: writer_logs.clone(),
        })
        .finish();
    let dispatch = tracing::Dispatch::new(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");

    tracing::dispatcher::with_default(&dispatch, || {
        runtime.block_on(async {
            let (_tmp, server) = contract_server().await;
            authorized_lookup(&server, "person-123").await;
            authorized_lookup(&server, "stderr-leak").await;
        });
    });

    let logs =
        String::from_utf8(logs.lock().expect("log buffer lock").clone()).expect("logs are UTF-8");
    assert!(logs.contains("sidecar lookup completed"));
    assert!(logs.contains("sidecar lookup failed"));
    assert!(logs.contains("openfn_crvs"));
    assert!(!logs.contains("fixture-token"));
    assert!(!logs.contains("opencrvs.example.test"));
    assert!(!logs.contains(CREDENTIAL_ENV));
    assert!(!logs.contains(TOKEN));
    assert!(!logs.contains("stderr-leak"));
}

async fn contract_server() -> (TempDir, TestServer) {
    std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
    std::env::set_var(
        CREDENTIAL_ENV,
        r#"{"baseUrl":"https://opencrvs.example.test","apiToken":"fixture-token"}"#,
    );
    let tmp = TempDir::new().expect("temp dir");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let worker = fixtures.join("contract_worker.sh");
    let job = fixtures.join("jobs/opencrvs-person-lookup.js");
    let attempt_log = tmp.path().join("worker-attempts.jsonl");
    let raw = format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: witness-contract
      hash_env: {token_hash_env}
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_worker_memory_mb: 256
openfn:
  cli_build_tool: "1.36.0"
  runtime: "1.36.0"
worker:
  command: "/bin/sh"
  args:
    - {worker}
    - {attempt_log}
sources:
  openfn_crvs:
    dataset: civil_registry
    entity: civil_person
    workflow:
      steps:
        - id: lookup
          expression: {job}
          adaptors:
            - "@openfn/language-http@7.2.0"
    credential_env: {credential_env}
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
        token_hash_env = yaml_string(TOKEN_HASH_ENV),
        worker = yaml_path(&worker),
        attempt_log = yaml_path(&attempt_log),
        job = yaml_path(&job),
        credential_env = yaml_string(CREDENTIAL_ENV),
    );
    let config: SidecarConfig = serde_norway::from_str(&raw).expect("manifest parses");
    let app = sidecar_router(config).await.expect("sidecar router builds");
    let server = TestServer::builder().http_transport().build(app);
    (tmp, server)
}

async fn authorized_lookup(server: &TestServer, lookup_value: &str) {
    server
        .get(&format!("/datasets/{DATASET}/{ENTITY}"))
        .add_query_param(LOOKUP_FIELD, lookup_value)
        .add_query_param("fields", "national_id,birth_date")
        .add_query_param("limit", "2")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .add_header("data-purpose", PURPOSE)
        .add_header("x-correlation-id", "contract-correlation")
        .await;
}

fn yaml_path(path: &Path) -> String {
    yaml_string(path.to_str().expect("fixture path is UTF-8"))
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}
