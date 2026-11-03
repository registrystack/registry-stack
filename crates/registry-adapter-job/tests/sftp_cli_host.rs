// SPDX-License-Identifier: Apache-2.0

//! Operational SFTP acceptance through the actual `adapter-job pass`, item
//! store, and destination seam. The loopback server uses a P-256 host key,
//! private-key client authentication, and completed-name handover.

#![cfg(all(feature = "job-sftp", feature = "postgres-test"))]

use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr as _;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

#[path = "support/fixture_receiver.rs"]
mod fixture_receiver;
#[path = "support/sftp_source_server.rs"]
mod sftp_source_server;

use fixture_receiver::{FixtureReceiver, Scripted};
use sftp_source_server::{SftpSourceServer, CLIENT_KEY_PASSPHRASE, CLIENT_PRIVATE_KEY};

const BASE_PACK: &str =
    include_str!("../../../products/adapter/fixtures/corpus/base-job/pack.yaml");
const BASE_PROFILE: &str =
    include_str!("../../../products/adapter/fixtures/corpus/base-job/profile.yaml");

const FIRST_VERSION: &[u8] = b"id,status,note\n001,new,first-version\n002,ready,second-version\n";
const REPLACEMENT: &[u8] =
    b"id,status,note\n001,revised,replacement-first\n003,new,replacement-second\n";
const UNSUPPORTED_P384_HOST_KEY: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBVFgxJxpCaAALZG/S5BHT8/IUQ5mfuKaj7Av9g7Jw59fBEGHfPBz1wFtHGYw5bdLmfVZTIDfogDid5zqJeAKr1AcD06DKTXDzd2EpUjqeLfQ5b3erHuX758fgu/pSDGRA==";

struct Fixture {
    _root: tempfile::TempDir,
    pack: PathBuf,
    job: PathBuf,
    runtime: PathBuf,
}

impl Fixture {
    fn new(server: &SftpSourceServer) -> Self {
        let root = tempfile::tempdir().expect("SFTP CLI fixture directory");
        let pack_text = BASE_PACK
            .replace("component: file", "component: sftp")
            .replace("uri: file:submissions", "uri: sftp:submissions");
        let pack_digest = registry_platform_config::sha256_uri(pack_text.as_bytes());
        let profile_digest = registry_platform_config::sha256_uri(BASE_PROFILE.as_bytes());
        let pack = root.path().join("pack.yaml");
        let job = root.path().join("job.yaml");
        let runtime = root.path().join("job-runtime.yaml");
        std::fs::write(&pack, pack_text).expect("SFTP pack");
        std::fs::write(root.path().join("profile.yaml"), BASE_PROFILE).expect("SFTP profile");
        std::fs::write(
            root.path().join("project.yaml"),
            project_yaml(&profile_digest, &pack_digest),
        )
        .expect("SFTP project");
        std::fs::write(&job, job_yaml(&pack_digest)).expect("SFTP job");
        std::fs::write(&runtime, runtime_json(server)).expect("SFTP runtime");
        Self {
            _root: root,
            pack,
            job,
            runtime,
        }
    }

    fn replace_pin(&self, pin: &str) {
        let mut document: Value =
            serde_json::from_slice(&std::fs::read(&self.runtime).expect("runtime bytes"))
                .expect("runtime JSON");
        document["sources"]["sftp"]["submissions"]["pinnedHostKey"] = Value::String(pin.to_owned());
        std::fs::write(
            &self.runtime,
            serde_json::to_vec_pretty(&document).expect("runtime JSON renders"),
        )
        .expect("runtime pin replacement");
    }
}

fn project_yaml(profile_digest: &str, pack_digest: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project: {{ id: sftp-cli, version: "1" }}
profile: {{ id: case-api, version: "1", digest: {profile_digest} }}
pack: {{ id: case-api-pack, version: "1", digest: {pack_digest} }}
recordTypes:
  - name: case
    fields:
      - {{ name: case_type, type: string, required: true }}
templatedRoutes:
  - {{ routeTemplate: find-cases, routeId: case-find }}
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

fn job_yaml(pack_digest: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job: {{ id: sftp-cli, version: "1" }}
source:
  pack: {{ id: case-api-pack, version: "1", digest: {pack_digest} }}
  route: kobo-submissions
destination:
  type: signed-coordinator-event
  binding: coordinator-test
  workflow: case-ingestion
  trigger: submitted
  source: urn:registry-adapter:job:sftp-cli
  eventType: org.example.case-submitted.v1
  dataSchema: urn:example:schema:case-submitted:v1
projection: {{ fields: [id, status, note] }}
triggers: [{{ kind: interval, delayMilliseconds: 60000 }}]
profile:
  pageDeadlineMilliseconds: 10000
  maximumResponseBytes: 16777216
  maximumPageItems: 1
  maximumPageBytes: 65536
  maximumUpstreamCalls: 2
  read:
    maximumFileBytes: 1048576
    maximumRowBytes: 4096
    maximumFieldBytes: 1024
    maximumRowsPerPage: 1
"#
    )
}

fn runtime_json(server: &SftpSourceServer) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
        "kind": "AdapterJobRuntimeConfig",
        "id": "sftp-cli",
        "endpoints": [{
            "endpoint": "cases",
            "baseUrl": "https://cases.example.invalid",
            "anonymousHttps": "operator-approved",
            "credential": {"type": "none"}
        }],
        "sources": {"sftp": {"submissions": {
            "host": "127.0.0.1",
            "port": server.port,
            "user": "source-reader",
            "baseDirectory": "/in",
            "pinnedHostKey": server.host_key,
            "credential": {
                "type": "private-key",
                "privateKeyRef": "secret:env/SFTP_CLI_PRIVATE_KEY",
                "passphraseRef": "secret:env/SFTP_CLI_KEY_PASSPHRASE"
            },
            "namespace": "submissions",
            "include": "*.csv",
            "completion": {
                "type": "completed-name",
                "producerAtomicHandover": true
            },
            "maximumListingEntries": 16
        }}},
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
    }))
    .expect("runtime JSON renders")
}

async fn isolated_store_url() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_nanos();
    let schema = format!("adapter_job_sftp_{unique}");
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
        .expect("create isolated SFTP store schema");
    drop(client);
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    tokio_postgres::Config::from_str(&scoped).expect("isolated store URL parses");
    scoped
}

async fn run_pass(fixture: &Fixture, store_url: &str, receiver_url: &str) -> std::process::Output {
    let job = fixture.job.clone();
    let pack = fixture.pack.clone();
    let runtime = fixture.runtime.clone();
    let store_url = store_url.to_owned();
    let receiver_url = receiver_url.to_owned();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("JOB_TEST_DB", store_url)
            .env("SFTP_CLI_PRIVATE_KEY", CLIENT_PRIVATE_KEY)
            .env("SFTP_CLI_KEY_PASSPHRASE", CLIENT_KEY_PASSPHRASE)
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
            .expect("run adapter-job SFTP pass")
    })
    .await
    .expect("SFTP pass process joins")
}

fn report(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "SFTP pass failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "the pass stays value-free");
    serde_json::from_slice(&output.stdout).expect("pass report JSON")
}

#[tokio::test]
async fn check_refuses_invalid_or_unsupported_host_keys_without_effects() {
    let server = SftpSourceServer::start(FIRST_VERSION).await;
    let fixture = Fixture::new(&server);
    for pin in ["ssh-ed25519 not-a-public-key", UNSUPPORTED_P384_HOST_KEY] {
        fixture.replace_pin(pin);
        let output = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .arg("check")
            .arg(&fixture.job)
            .arg("--pack")
            .arg(&fixture.pack)
            .arg("--runtime")
            .arg(&fixture.runtime)
            .output()
            .expect("run adapter-job SFTP check");
        assert!(
            !output.status.success(),
            "check wrongly accepted the refused pin: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("pinned host key"),
            "check refused for the wrong reason: status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(server.auth_calls().await, 0);
}

#[tokio::test]
async fn actual_cli_pass_recovers_cursor_and_same_name_replacement() {
    let server = SftpSourceServer::start(FIRST_VERSION).await;
    let fixture = Fixture::new(&server);
    let store_url = isolated_store_url().await;
    let receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge { run_id: None },
        Scripted::Acknowledge { run_id: None },
        Scripted::Acknowledge { run_id: None },
    ])
    .await;

    let first = report(&run_pass(&fixture, &store_url, &receiver.url).await);
    assert_eq!(first["itemsRead"], 1);
    assert_eq!(first["itemsAcknowledged"], 1);

    server.replace(REPLACEMENT).await;
    let replaced = report(&run_pass(&fixture, &store_url, &receiver.url).await);
    assert_eq!(replaced["itemsRead"], 1);
    assert_eq!(replaced["itemsAcknowledged"], 1);

    let resumed = report(&run_pass(&fixture, &store_url, &receiver.url).await);
    assert_eq!(resumed["itemsRead"], 1);
    assert_eq!(resumed["itemsAcknowledged"], 1);

    // An ongoing scan holds its place at the tail: with no new file the pass
    // reads nothing instead of rereading every retained file.
    let repeated = report(&run_pass(&fixture, &store_url, &receiver.url).await);
    assert_eq!(repeated["itemsRead"], 0);
    assert_eq!(repeated["itemsAcknowledged"], 0);

    let requests = receiver.requests();
    assert_eq!(requests.len(), 3);
    let projected = requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).expect("delivery JSON")["projected"]
                .clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        projected,
        vec![
            json!({"id": "001", "status": "new", "note": "first-version"}),
            json!({"id": "001", "status": "revised", "note": "replacement-first"}),
            json!({"id": "003", "status": "new", "note": "replacement-second"}),
        ]
    );
    assert!(server.auth_calls().await >= 4);
    assert_eq!(server.writes().await, 0);
}
