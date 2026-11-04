// SPDX-License-Identifier: Apache-2.0

//! The operational job host's default-off file-source boundary. These tests
//! exercise the actual job artifacts and binary, then carry decoded values
//! through the destination seam. The engine owns file safety and decoder
//! semantics; this suite proves the host exposes that implementation only
//! through its explicit feature.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

#[cfg(feature = "postgres-test")]
use std::str::FromStr as _;

use registry_adapter_engine::job::{compile_job, run_job_page};
use registry_adapter_job::destination::{
    DeliverableItem, FixtureDestination, HandOffOutcome, JobDestination,
};
use registry_adapter_job::projection;
use serde_json::{json, Value};

#[path = "support/fixture_receiver.rs"]
mod fixture_receiver;

use fixture_receiver::{FixtureReceiver, Scripted};

const BASE_PACK: &str =
    include_str!("../../../products/adapter/fixtures/corpus/base-job/pack.yaml");
const BASE_PROFILE: &str =
    include_str!("../../../products/adapter/fixtures/corpus/base-job/profile.yaml");

struct FileFixture {
    _root: tempfile::TempDir,
    pack: PathBuf,
    job: PathBuf,
    runtime: PathBuf,
    source: PathBuf,
}
impl FileFixture {
    fn new(decoder: &str, component: &str, maximum_file_bytes: u64) -> Self {
        let root = tempfile::tempdir().expect("a file-host fixture directory");
        let source = root.path().join("source");
        std::fs::create_dir(&source).expect("the source directory");

        let pack_text = BASE_PACK
            .replace("component: file", &format!("component: {component}"))
            .replace(
                "uri: file:submissions",
                &format!("uri: {component}:submissions"),
            )
            .replace("decoder: csv", &format!("decoder: {decoder}"));
        let pack_text = if decoder == "raw" {
            pack_text.replace("          keyPointer: /id\n", "")
        } else {
            pack_text
        };
        let pack_digest = registry_platform_config::sha256_uri(pack_text.as_bytes());
        let profile_digest = registry_platform_config::sha256_uri(BASE_PROFILE.as_bytes());

        let pack = root.path().join("pack.yaml");
        let job = root.path().join("job.yaml");
        let runtime = root.path().join("runtime.yaml");
        std::fs::write(&pack, pack_text).expect("the pack");
        std::fs::write(root.path().join("profile.yaml"), BASE_PROFILE).expect("the profile");
        std::fs::write(
            root.path().join("project.yaml"),
            project_yaml(&profile_digest, &pack_digest),
        )
        .expect("the project");
        std::fs::write(&job, job_yaml(&pack_digest, maximum_file_bytes)).expect("the job");
        std::fs::write(&runtime, runtime_json(&source, component)).expect("the runtime config");

        Self {
            _root: root,
            pack,
            job,
            runtime,
            source,
        }
    }

    fn write_source(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.source.join(name), bytes).expect("the source file");
    }
}

fn project_yaml(profile_digest: &str, pack_digest: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: case-api-example
  version: "1"
profile:
  id: case-api
  version: "1"
  digest: {profile_digest}
pack:
  id: case-api-pack
  version: "1"
  digest: {pack_digest}
recordTypes:
  - name: case
    fields:
      - name: case_type
        type: string
        required: true
templatedRoutes:
  - routeTemplate: find-cases
    routeId: case-find
bindings:
  - id: case-get
    operation: cases-get
    recordType: case
    route: case-find
    maximumUpstreamCalls: 4
accessProfiles:
  - id: case-reader
    scopes: [cases.read]
    operations: [cases-get]
    recordTypes: [case]
"#
    )
}

fn job_yaml(pack_digest: &str, maximum_file_bytes: u64) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: file-daily
  version: "1"
source:
  pack:
    id: case-api-pack
    version: "1"
    digest: {pack_digest}
  route: kobo-submissions
destination:
  type: signed-coordinator-event
  binding: coordinator-test
  workflow: case-ingestion
  trigger: submitted
  source: urn:registry-adapter:job:file-daily
  eventType: org.example.case-submitted.v1
  dataSchema: urn:example:schema:case-submitted:v1
projection:
  fields: [id, status, note]
triggers:
  - kind: interval
    delayMilliseconds: 60000
profile:
  pageDeadlineMilliseconds: 30000
  maximumResponseBytes: 16777216
  maximumPageItems: 10
  maximumPageBytes: 65536
  maximumUpstreamCalls: 2
  read:
    maximumFileBytes: {maximum_file_bytes}
    maximumRowBytes: 4096
    maximumFieldBytes: 1024
    maximumRowsPerPage: 10
"#
    )
}

/// Only a `file` pack endpoint carries a `sources.file` binding: the
/// engine refuses a binding no declared endpoint of its kind owns before it
/// reaches the per-endpoint serving check, so a fixture for an unserved
/// component binds no source at all.
fn runtime_json(source: &Path, component: &str) -> String {
    let mut runtime = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
        "kind": "AdapterJobRuntimeConfig",
        "id": "file-job-test",
        "endpoints": [{
            "endpoint": "cases",
            "baseUrl": "https://cases.example.invalid",
            "anonymousHttps": "operator-approved",
            "credential": {"type": "none"}
        }],
        "allowedPrivateCidrs": ["10.0.0.0/8"],
        "store": {
            "runtimeUrlRef": "secret:env/JOB_TEST_DB",
            "testOnlyPlaintext": true
        },
        "destinations": {"coordinator-test": {
            "type": "signed-coordinator-event",
            "baseUrl": "http://127.0.0.1:9/events",
            "signingKeyRef": "secret:env/JOB_TEST_SIGNING_KEY",
            "attemptTimeoutMilliseconds": 1000
        }}
    });
    if component == "file" {
        runtime["sources"] = json!({"file": {"submissions": {
            "directory": source,
            "namespace": "submissions",
            "producerAtomicHandover": true
        }}});
    }
    serde_json::to_string_pretty(&runtime).expect("the runtime config renders")
}

fn run_check(fixture: &FileFixture) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_adapter-job"))
        .arg("check")
        .arg(&fixture.job)
        .arg("--pack")
        .arg(&fixture.pack)
        .arg("--runtime")
        .arg(&fixture.runtime)
        .output()
        .expect("run adapter-job check")
}

fn deliverable(
    program: &registry_adapter_engine::job::JobProgram,
    value: &Value,
    key: &str,
) -> DeliverableItem {
    let projected = projection::project(&program.job.projection, value);
    DeliverableItem {
        key: key.to_string(),
        sequence: 1,
        digest: projection::item_digest(&program.job.projection, value),
        prior_run_id: None,
        admitted_before: false,
        first_seen: SystemTime::UNIX_EPOCH,
        event_time: SystemTime::UNIX_EPOCH,
        delivery_attempt: 1,
        projected,
    }
}

#[cfg(feature = "signed-coordinator-event")]
#[test]
fn the_actual_check_accepts_a_file_source_when_the_host_feature_is_present() {
    let fixture = FileFixture::new("csv", "file", 1_048_576);
    fixture.write_source("submissions.csv", b"id,status,note\n001,new,ready\n");
    let output = run_check(&fixture);
    assert!(
        output.status.success(),
        "file-source check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["ok"], true);
    assert_eq!(report["source"]["route"], "kobo-submissions");
}

#[tokio::test]
async fn csv_and_jsonl_values_cross_the_existing_destination_seam() {
    let cases = [
        (
            "csv",
            b"id,status,note\n001,new,\"two\nlines\"\n".as_slice(),
            json!({"id": "001", "status": "new", "note": "two\nlines"}),
            0,
        ),
        (
            "jsonl",
            b"{\"id\":\"002\",\"status\":\"new\",\"note\":null}\nnot-json\n".as_slice(),
            json!({"id": "002", "status": "new", "note": null}),
            1,
        ),
    ];
    for (decoder, bytes, expected, malformed_lines) in cases {
        let fixture = FileFixture::new(decoder, "file", 1_048_576);
        fixture.write_source(&format!("submissions.{decoder}"), bytes);
        let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
            .expect("the file job compiles");
        let page = run_job_page(&program, None)
            .await
            .expect("the file page runs");
        assert_eq!(page.page.items.len(), 1);
        assert_eq!(page.page.items[0].value, expected);
        assert_eq!(page.malformed_lines, malformed_lines);

        let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
        let destination = FixtureDestination::new(&receiver.url).expect("the fixture destination");
        let outcome = destination
            .deliver(
                &program.job.job,
                &deliverable(&program, &page.page.items[0].value, &page.page.items[0].key),
            )
            .await;
        assert_eq!(outcome, HandOffOutcome::Acknowledged { run_id: None });
        let body: Value = serde_json::from_slice(&receiver.requests()[0].body)
            .expect("the delivery body is JSON");
        assert_eq!(body["projected"], expected);
    }
}
#[tokio::test]
async fn an_oversized_file_stops_at_the_engine_bound() {
    let fixture = FileFixture::new("jsonl", "file", 16);
    fixture.write_source(
        "submissions.jsonl",
        b"{\"id\":\"larger-than-sixteen-bytes\"}\n",
    );
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the bounded file job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the oversized file refuses");
    assert_eq!(failure.code, Some("adapter.job.read-bound"));
}

/// Enabling `job-file` serves the file source and nothing else: an SFTP
/// endpoint still refuses unless this build carries `job-sftp`. The postgres
/// source needs a query file and key column before the serving check is
/// reached; its default-build refusal is held in
/// `registry-adapter/tests/adapter_job.rs`.
#[cfg(not(feature = "job-sftp"))]
#[test]
fn unserved_job_sources_remain_refused_by_the_host() {
    let fixture = FileFixture::new("csv", "sftp", 1_048_576);
    let output = run_check(&fixture);
    assert!(!output.status.success(), "sftp must remain refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error[adapter.job.component-unavailable] /endpoints/submissions"),
        "the host names the refused sftp endpoint: {stderr}"
    );
    assert!(
        stderr.contains("next: serve the SFTP source by building with the job-sftp feature"),
        "the host names the build fix: {stderr}"
    );
}

#[cfg(feature = "postgres-test")]
async fn isolated_store_url() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    // The macOS clock ticks in microseconds, so parallel tests can read the
    // same instant; the serial keeps each schema name distinct.
    static NEXT_SCHEMA: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = NEXT_SCHEMA.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("the test clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_job_file_{unique}_{serial}");
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the Adapter test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the Adapter test database connection failed: {error}");
        }
    });
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated file-host schema");
    drop(client);
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    tokio_postgres::Config::from_str(&scoped).expect("the isolated store URL parses");
    scoped
}

/// The actual `pass` command reads the CSV page, migrates and records only
/// identity in a disposable store, then hands the declared projection to the
/// existing fixture destination. This is the host-level operational proof,
/// separate from the engine and seam checks above.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn the_actual_pass_reads_a_file_into_the_destination_seam() {
    let store_url = isolated_store_url().await;
    let fixture = FileFixture::new("csv", "file", 1_048_576);
    fixture.write_source("submissions.csv", b"id,status,note\n007,new,ready\n");
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge {
        run_id: Some("run-file-7".to_string()),
    }])
    .await;
    let job = fixture.job.clone();
    let pack = fixture.pack.clone();
    let runtime = fixture.runtime.clone();
    let receiver_url = receiver.url.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("JOB_TEST_DB", store_url)
            .arg("pass")
            .arg(job)
            .arg("--pack")
            .arg(pack)
            .arg("--runtime")
            .arg(runtime)
            .arg("--fixture")
            .arg("--fixture-url")
            .arg(receiver_url)
            .output()
            .expect("run adapter-job pass")
    })
    .await
    .expect("the adapter-job pass joins");
    assert!(
        output.status.success(),
        "the file pass failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("the pass report is JSON");
    assert_eq!(report["itemsRead"], 1);
    assert_eq!(report["itemsAcknowledged"], 1);
    let requests = receiver.requests();
    assert_eq!(requests.len(), 1, "one file row crosses the seam");
    let body: Value = serde_json::from_slice(&requests[0].body).expect("the delivery is JSON");
    assert_eq!(
        body["projected"],
        json!({"id": "007", "status": "new", "note": "ready"})
    );
}

/// A pre-103 file job cannot prove which decoder/key selector created its
/// durable items. The pass must stop before opening the source or calling the
/// destination, even when the current decoder is the same legacy raw mode.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn legacy_file_and_raw_state_stop_before_source_or_destination_io() {
    for decoder in ["csv", "raw"] {
        let store_url = isolated_store_url().await;
        let fixture = FileFixture::new(decoder, "file", 1_048_576);

        let runtime = fixture.runtime.clone();
        let init_url = store_url.clone();
        let initialized = tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_adapter-job"))
                .env("JOB_TEST_DB", init_url)
                .arg("init-store")
                .arg("--runtime")
                .arg(runtime)
                .output()
                .expect("initialize the legacy-file test store")
        })
        .await
        .expect("the store initialization joins");
        assert!(
            initialized.status.success(),
            "store initialization failed for {decoder}: {}",
            String::from_utf8_lossy(&initialized.stderr)
        );

        let (client, connection) = tokio_postgres::connect(&store_url, tokio_postgres::NoTls)
            .await
            .expect("connect the scoped legacy store");
        let connection = tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the scoped legacy store connection failed: {error}");
            }
        });
        client
            .batch_execute(
                "INSERT INTO adapter_job_state(job_id) VALUES ('file-daily');\
                 INSERT INTO adapter_job_items \
                 (job_id, item_key, last_digest, sequence, status, first_seen, last_seen, \
                  event_time, delivery_attempt, receiver_identity_known) \
                 VALUES ('file-daily', 'legacy/item', \
                 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 1, 'acknowledged', now(), now(), now(), 1, true);",
            )
            .await
            .expect("insert non-empty legacy file state");
        drop(client);
        connection.abort();

        let unavailable = fixture.source.with_extension("unavailable");
        std::fs::rename(&fixture.source, &unavailable)
            .expect("make the fixture-owned source unavailable");
        let receiver = FixtureReceiver::start(Vec::new()).await;
        let job = fixture.job.clone();
        let pack = fixture.pack.clone();
        let runtime = fixture.runtime.clone();
        let receiver_url = receiver.url.clone();
        let pass_url = store_url.clone();
        let output = tokio::task::spawn_blocking(move || {
            Command::new(env!("CARGO_BIN_EXE_adapter-job"))
                .env("JOB_TEST_DB", pass_url)
                .arg("pass")
                .arg(job)
                .arg("--pack")
                .arg(pack)
                .arg("--runtime")
                .arg(runtime)
                .arg("--fixture")
                .arg("--fixture-url")
                .arg(receiver_url)
                .output()
                .expect("run the fenced legacy file pass")
        })
        .await
        .expect("the fenced pass joins");
        assert!(
            !output.status.success(),
            "the {decoder} legacy pass must stop"
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("the stop report is JSON");
        assert_eq!(report["itemsRead"], 0);
        assert_eq!(
            report["stopped"]["code"],
            "page-fault:adapter.job.identity-migration-required"
        );
        assert!(
            receiver.requests().is_empty(),
            "the {decoder} migration fence precedes destination I/O"
        );
    }
}

fn run_host(store_url: &str, fixture: &FileFixture, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_adapter-job"))
        .env("JOB_TEST_DB", store_url)
        .args(args)
        .arg(&fixture.job)
        .arg("--pack")
        .arg(&fixture.pack)
        .arg("--runtime")
        .arg(&fixture.runtime)
        .output()
        .expect("run the adapter-job command")
}

/// The preview applies the item-identity fence read-only, the refusal names
/// the one command that clears it, and that command moves the fence to the
/// job as it is now authored without touching the stored items.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn rebind_identity_clears_the_fence_the_dry_run_reports() {
    let store_url = isolated_store_url().await;
    let fixture = FileFixture::new("csv", "file", 1_048_576);
    fixture.write_source("submissions.csv", b"id,status,note\n001,new,ready\n");
    let runtime = fixture.runtime.clone();
    let initialized = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
        .env("JOB_TEST_DB", &store_url)
        .arg("init-store")
        .arg("--runtime")
        .arg(runtime)
        .output()
        .expect("initialize the fenced test store");
    assert!(initialized.status.success());
    let (client, connection) = tokio_postgres::connect(&store_url, tokio_postgres::NoTls)
        .await
        .expect("connect the scoped fenced store");
    let connection = tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the scoped fenced store connection failed: {error}");
        }
    });
    client
        .batch_execute(
            "INSERT INTO adapter_job_state(job_id) VALUES ('file-daily');\
             INSERT INTO adapter_job_items \
             (job_id, item_key, last_digest, sequence, status, first_seen, last_seen, \
              event_time, delivery_attempt, receiver_identity_known) \
             VALUES ('file-daily', 'legacy/item', \
             'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             1, 'acknowledged', now(), now(), now(), 1, true);",
        )
        .await
        .expect("insert non-empty legacy file state");

    let fenced = run_host(&store_url, &fixture, &["pass", "--dry-run"]);
    assert!(!fenced.status.success(), "the preview applies the fence");
    let report: Value = serde_json::from_slice(&fenced.stdout).expect("the stop report is JSON");
    assert_eq!(
        report["stopped"]["code"],
        "page-fault:adapter.job.identity-migration-required"
    );
    let next = report["stopped"]["next"]
        .as_str()
        .expect("the fence refusal carries a next step");
    assert!(next.contains("adapter-job rebind-identity"), "{next}");

    let rebound = run_host(&store_url, &fixture, &["rebind-identity"]);
    assert!(
        rebound.status.success(),
        "rebind failed: {}",
        String::from_utf8_lossy(&rebound.stderr)
    );
    let receipt: Value = serde_json::from_slice(&rebound.stdout).expect("the receipt is JSON");
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["jobId"], "file-daily");
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["itemsKept"], 1);
    let audit = String::from_utf8_lossy(&rebound.stderr);
    assert!(audit.contains("adapter.job.identity-rebound"), "{audit}");
    assert!(audit.contains("file-daily"), "{audit}");

    let after = run_host(&store_url, &fixture, &["pass", "--dry-run"]);
    let after_report: Value = serde_json::from_slice(&after.stdout).expect("the report is JSON");
    assert!(
        after_report["stopped"].is_null(),
        "the fence is cleared: {after_report}"
    );

    let again = run_host(&store_url, &fixture, &["rebind-identity"]);
    assert!(again.status.success());
    let again: Value = serde_json::from_slice(&again.stdout).expect("the receipt is JSON");
    assert_eq!(again["changed"], false, "a bound job has nothing to rebind");
    let items: i64 = client
        .query_one(
            "SELECT count(*) FROM adapter_job_items WHERE job_id = 'file-daily'",
            &[],
        )
        .await
        .expect("count the kept items")
        .get(0);
    assert_eq!(items, 1, "rebinding never rewrites or removes items");
    drop(client);
    connection.abort();
}
