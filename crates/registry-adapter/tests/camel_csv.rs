// SPDX-License-Identifier: Apache-2.0

//! The CSV decoder of the governed-ingestion read step
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2), over a real
//! scratch file through the job entry. The option behavior adapts
//! camel-4.23.0's own unmarshal cases; every case names the upstream
//! test class and method it ports.
#![cfg(feature = "job-file")]

use std::path::PathBuf;

use registry_adapter::engine::job::{compile_job, run_job_page};
use registry_platform_config::sha256_uri;
use serde_json::json;

/// The file-source pack, whose pollEnrich read carries the caller's
/// CSV decoder mapping verbatim.
fn csv_pack(decoder_mapping: &str) -> String {
    format!(
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
          decoder:{decoder_mapping}
capabilities: {{}}
"#
    )
}

fn job_yaml(pack_digest: &str) -> String {
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
    - name
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
    maximumRowsPerPage: 100
"#
    )
}

fn runtime_with_sources(directory: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job-runtime/v1alpha1
kind: AdapterJobRuntimeConfig
id: drop-deployment
endpoints: []
sources:
  file:
    dropbox:
      directory: '{directory}'
      namespace: exports
allowedPrivateCidrs:
  - 10.0.0.0/8
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

fn write_fixture(decoder_mapping: &str) -> Fixture {
    write_pack_fixture(&csv_pack(decoder_mapping))
}

fn write_pack_fixture(pack_text: &str) -> Fixture {
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    let files = tempfile::tempdir().expect("a scratch drop directory");
    let files_path = files.path().to_path_buf();
    let pack_text = pack_text.to_owned();
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
    std::fs::write(&job, job_yaml(&pack_digest)).expect("the job");
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

/// Ports camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalPipeDelimiterTest.java:
/// the delimiter option reads a pipe-delimited body as maps. (The
/// upstream case pipes through `unmarshal`; here the decoder rides the
/// read step, the form CONCEPT 17.2 serves.)
#[tokio::test]
async fn the_pipe_delimiter_reads_maps() {
    let fixture = write_fixture(r#" {"delimiter": "|"}"#);
    std::fs::write(fixture.files.join("people.csv"), b"name|age\nalice|007\n")
        .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 1);
    assert_eq!(
        page.page.items[0].value,
        json!({"name": "alice", "age": "007"}),
        "the pipe delimiter reads, leading zeros as strings"
    );
}

/// Ports camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalTest.java
/// (`testCsvUnMarshalMultiLine`): a quoted multiline field decodes
/// whole, newline inside the quotes and all.
#[tokio::test]
async fn a_quoted_multiline_field_decodes_whole() {
    let fixture = write_fixture(r#" {"quote": "'"}"#);
    std::fs::write(
        fixture.files.join("notes.csv"),
        b"name,note\nalice,'two\nlines'\nbob,3\n",
    )
    .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 2);
    assert_eq!(
        page.page.items[0].value,
        json!({"name": "alice", "note": "two\nlines"}),
        "the single-quote option quotes the multiline field"
    );
}

/// Ports camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalCommentMarkerSpringTest.java:
/// a comment line is not a record.
#[tokio::test]
async fn a_comment_marker_line_is_not_a_record() {
    let fixture = write_fixture(" {\"commentMarker\": \"#\"}");
    std::fs::write(
        fixture.files.join("people.csv"),
        b"# a comment\nname,age\nalice,7\n",
    )
    .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 1);
    assert_eq!(
        page.page.items[0].value,
        json!({"name": "alice", "age": "7"})
    );
    let file_digest = sha256_uri(b"# a comment\nname,age\nalice,7\n");
    assert_eq!(page.page.items[0].key, format!("exports:{file_digest}:1"));
}

/// Ports camel-4.23.0:components/camel-csv/src/test/java/org/apache/camel/dataformat/csv/CsvUnmarshalSkipFirstLineSpringTest.java
/// (`skipFirstLine`, the complement the port keeps as `header: false`):
/// no header record reads every record as data, a bare array per row.
#[tokio::test]
async fn the_header_disabled_decoder_reads_arrays() {
    let fixture = write_fixture(r#" {"header": false}"#);
    std::fs::write(fixture.files.join("people.csv"), b"alice,7\nbob,3\n")
        .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 2);
    assert_eq!(page.page.items[0].value, json!(["alice", "7"]));
    assert_eq!(page.page.items[1].value, json!(["bob", "3"]));
}

/// A bare `csv` decoder name reads at the CsvDataFormat defaults
/// (camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java,
/// the reference DEFAULT format): comma, double quote, header record on.
#[tokio::test]
async fn the_bare_csv_name_reads_at_the_defaults() {
    let fixture = write_fixture(" csv");
    std::fs::write(fixture.files.join("people.csv"), b"name,age\nalice,007\n")
        .expect("the candidate file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(
        page.page.items[0].value,
        json!({"name": "alice", "age": "007"}),
        "leading zeros survive the default reading"
    );
}

/// An unknown decoder name refuses at compile under the authoring
/// check's own code.
#[test]
fn an_unknown_decoder_name_refuses_the_compile() {
    let fixture = write_fixture(" parquet");
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("an unknown decoder refuses");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "adapter.job.decoder-unknown"),
        "the decoder refusal carries its own code: {:?}",
        error.diagnostics
    );
}

/// The csv crate takes one-byte syntax characters. A Unicode scalar must
/// refuse at authoring check rather than truncating to a different byte at
/// runtime. The diagnostic is value-free for every syntax option.
#[test]
fn non_ascii_csv_syntax_refuses_the_compile() {
    for decoder in [
        r#" {"delimiter": "é"}"#,
        r#" {"quote": "“"}"#,
        r#" {"commentMarker": "☃"}"#,
    ] {
        let fixture = write_fixture(decoder);
        let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
            .expect_err("a non-ASCII CSV syntax character refuses");
        let diagnostic = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "adapter.job.decoder-unknown")
            .expect("the decoder refusal carries its own code");
        assert!(
            !diagnostic.message.contains('é')
                && !diagnostic.message.contains('“')
                && !diagnostic.message.contains('☃'),
            "the diagnostic does not repeat the authored value: {diagnostic:?}"
        );
    }
}

/// The strategy machinery is the enrich fold: `use-original` beside the
/// read keeps the route's own body, where the default would replace it
/// with the page, and the page contract then refuses what the route
/// left under its own code.
#[tokio::test]
async fn the_read_aggregates_like_an_enrich() {
    let keeping_pack = r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
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
      - setBody:
          constant: {"kept": true}
      - pollEnrich:
          uri: file:dropbox
          timeoutMilliseconds: 10000
          decoder: {"delimiter": "|"}
          aggregationStrategy:
            type: use-original
capabilities: {}
"#
    .to_owned();
    let fixture = write_pack_fixture(&keeping_pack);
    std::fs::write(fixture.files.join("people.csv"), b"name|age\nalice|7\n")
        .expect("the candidate file");
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the keeping job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the kept body is not an item page");
    assert_eq!(
        failure.code,
        Some("adapter.job.page-shape"),
        "the strategy ran: the route's own body reached the entry, not the page"
    );
}
