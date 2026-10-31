// SPDX-License-Identifier: Apache-2.0

//! The JSONL decoder of the governed-ingestion read step: an addition
//! under `products/adapter/CONCEPT.md` section 5.4, not a port (Camel
//! has no JSONL data format). One bounded JSON value per line, a
//! malformed line counted and skipped with the rest continuing, the
//! same row bound as CSV, and the same paging contract.
#![cfg(feature = "job-file")]

use registry_adapter::job::{compile_job, run_job_page};
use registry_platform_config::sha256_uri;
use serde_json::json;
use std::path::PathBuf;

/// The file-source pack with the jsonl decoder.
fn jsonl_pack() -> String {
    r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: drop-pack
version: "1"
testedVersions: []
endpoints:
  - id: dropbox
    component: file
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 16777216
sourceRoutes:
  - id: drop-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - pollEnrich:
          uri: file:dropbox
          timeoutMilliseconds: 10000
          decoder: jsonl
capabilities: {}
"#
    .to_owned()
}

fn job_yaml(pack_digest: &str, rows_per_page: u32) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: drop-daily
  version: "1"
source:
  pack:
    id: drop-pack
    version: "1"
    digest: {pack_digest}
  route: drop-page
projection:
  fields:
    - a
triggers:
  - kind: interval
    delayMilliseconds: 60000
profile:
  pageDeadlineMilliseconds: 60000
  maximumResponseBytes: 16777216
  maximumPageItems: 100
  maximumPageBytes: 16777216
  maximumUpstreamCalls: 4
  read:
    maximumFileBytes: 1073741824
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: {rows_per_page}
"#
    )
}

fn runtime_with_sources(directory: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: drop-deployment
endpoints: []
sources:
  file:
    dropbox:
      directory: '{directory}'
      namespace: exports
allowedPrivateCidrs:
  - 10.0.0.0/8
listener:
  bind: 127.0.0.1:8080
database:
  runtimeUrlRef: secret:env/DROP_DB_RUNTIME
  migrationUrlRef: secret:env/DROP_DB_MIGRATION
oidc:
  issuer: https://issuer.example.invalid
  audience: drop-job
allowedClients:
  - drop-client
audit:
  retentionDays: 90
"#
    )
}

struct Fixture {
    _directory: tempfile::TempDir,
    _files: tempfile::TempDir,
    pack: PathBuf,
    job: PathBuf,
    runtime: PathBuf,
    files: PathBuf,
}

fn write_fixture(rows_per_page: u32) -> Fixture {
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    let files = tempfile::tempdir().expect("a scratch drop directory");
    let files_path = files.path().to_path_buf();
    let pack_text = jsonl_pack();
    std::fs::write(root.join("pack.yaml"), &pack_text).expect("the pack");
    let profile = r#"apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: drop
version: "1"
operations: []
problems:
  - code: drop.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: drop.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: drop.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted, outcome, facade]
  - code: drop.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected]
problemEnvelope: '{"family": "{{problemCode}}"}'
"#;
    std::fs::write(root.join("profile.yaml"), profile).expect("the profile");
    let pack_digest = sha256_uri(pack_text.as_bytes());
    std::fs::write(
        root.join("project.yaml"),
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: drop-example
  version: "1"
profile:
  id: drop
  version: "1"
  digest: {}
pack:
  id: drop-pack
  version: "1"
  digest: {pack_digest}
recordTypes: []
bindings: []
"#,
            sha256_uri(profile.as_bytes())
        ),
    )
    .expect("the project");
    let job = root.join("job.yaml");
    std::fs::write(&job, job_yaml(&pack_digest, rows_per_page)).expect("the job");
    let runtime = root.join("runtime.yaml");
    std::fs::write(
        &runtime,
        runtime_with_sources(files.path().to_str().expect("a path")),
    )
    .expect("the runtime config");
    Fixture {
        _directory: directory,
        _files: files,
        pack: root.join("pack.yaml"),
        job,
        runtime,
        files: files_path,
    }
}

/// One value per line; a malformed line is counted and the remaining
/// lines continue; the count rides the entry's own result member.
#[tokio::test]
async fn a_malformed_line_continues_with_a_count() {
    let fixture = write_fixture(100);
    std::fs::write(
        fixture.files.join("events.jsonl"),
        b"{\"a\":1}\nbroken\n{\"a\":2}\n",
    )
    .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the jsonl job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 2);
    assert_eq!(page.malformed_lines, 1, "the skipped line is counted");
    assert_eq!(page.page.items[0].value, json!({"a": 1}));
    assert_eq!(page.page.items[1].value, json!({"a": 2}));
    assert_eq!(
        page.page.next, None,
        "every line is consumed, so the scan ends"
    );
}

/// The same paging contract as CSV: the rows bound stops the read, and
/// the cursor resumes at the byte offset after the last emitted line
/// with the line ordinal stable across pages.
#[tokio::test]
async fn jsonl_pages_at_the_rows_bound() {
    let fixture = write_fixture(2);
    std::fs::write(
        fixture.files.join("events.jsonl"),
        b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n{\"a\":4}\n",
    )
    .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the jsonl job compiles");
    let first = run_job_page(&program, None)
        .await
        .expect("the first page runs");
    assert_eq!(first.page.items.len(), 2);
    let digest = first
        .page
        .next
        .as_ref()
        .and_then(|next| next.get("digest"))
        .and_then(serde_json::Value::as_str)
        .expect("the cursor carries the digest")
        .to_owned();
    let second = run_job_page(&program, first.page.next.clone())
        .await
        .expect("the second page runs");
    assert_eq!(second.page.items.len(), 2);
    assert_eq!(second.page.next, None);
    let file_digest = sha256_uri(b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n{\"a\":4}\n");
    assert_eq!(digest, file_digest);
    assert_eq!(
        second.page.items[0].key,
        format!("exports:{file_digest}:2"),
        "the line ordinal counts every line of the file"
    );
}

/// A line over the row bound refuses the read; the bound rides the
/// profile, so a rewritten profile changes the reading without a pack
/// change.
#[tokio::test]
async fn an_oversized_line_refuses_the_read() {
    let fixture = write_fixture(100);
    std::fs::write(
        fixture.files.join("events.jsonl"),
        format!("{{\"a\": \"{}\"}}\n", "w".repeat(2_000_000)),
    )
    .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the jsonl job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the wide line refuses the read");
    assert_eq!(failure.code, Some("adapter.job.read-bound"));
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("upstream.too-large".to_owned())
    );
}
