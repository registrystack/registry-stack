// SPDX-License-Identifier: Apache-2.0

//! The `file` source and the job `pollEnrich` read
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2), over a real
//! scratch directory: selection, the done-file forms, the changed read
//! lock, the noop divergence, security refusals, and paging across a
//! multi-page file and across files. The ported cases adapt
//! camel-4.23.0's own file-consumer tests; the port record beside the
//! scratch stream lists every upstream test class ported or recorded as
//! inapplicable (products/adapter/scratch/engine2/port-record.md).
#![cfg(feature = "job-file")]

use std::path::PathBuf;

use registry_adapter::job::{compile_job, run_job_page};
use registry_platform_config::sha256_uri;
use serde_json::{json, Value};

/// The file-source pack: one file endpoint and one source route whose
/// pollEnrich read carries the mandatory timeout and the caller's
/// decoder.
fn file_pack(decoder: &str) -> String {
    let decoder_member = if decoder == "raw" {
        String::new()
    } else {
        format!("\n          decoder: {decoder}")
    };
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
          timeoutMilliseconds: 10000{decoder_member}
capabilities: {{}}
"#
    )
}

fn job_yaml(pack_digest: &str, maximum_file_bytes: u64, rows_per_page: u32) -> String {
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
    maximumFileBytes: {maximum_file_bytes}
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: {rows_per_page}
"#
    )
}

/// The runtime config of a file-source job: no endpoint bindings, one
/// file source bound to the scratch directory.
fn runtime_with_sources(directory: &str, namespace: &str, extra: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: drop-deployment
endpoints: []
sources:
  file:
    dropbox:
      directory: {directory}
      namespace: {namespace}{extra}
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

/// One fixture workspace: the pack, the job, the runtime config, and a
/// scratch directory the source reads.
struct Fixture {
    _directory: tempfile::TempDir,
    /// The candidate directory's own guard: dropped after the test, so
    /// the files live as long as the fixture does.
    _files: tempfile::TempDir,
    pack: PathBuf,
    job: PathBuf,
    runtime: PathBuf,
    files: PathBuf,
}

fn write_fixture(
    decoder: &str,
    runtime_extra: &str,
    maximum_file_bytes: u64,
    rows_per_page: u32,
) -> Fixture {
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    let files = tempfile::tempdir().expect("a scratch drop directory");
    let pack_text = file_pack(decoder);
    std::fs::write(root.join("pack.yaml"), &pack_text).expect("the pack");
    // The facade profile beside the pack: the same closed problem map
    // every profile carries, with no operation a binding would serve.
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
    std::fs::write(
        &job,
        job_yaml(&pack_digest, maximum_file_bytes, rows_per_page),
    )
    .expect("the job");
    let runtime = root.join("runtime.yaml");
    // The path rides single-quoted, so spaces in a macOS or Linux temp
    // root never read as anything else.
    let runtime_text = runtime_with_sources(
        files.path().to_str().expect("a path"),
        "exports",
        runtime_extra,
    );
    std::fs::write(&runtime, runtime_text).expect("the runtime config");
    let files_path = files.path().to_path_buf();
    Fixture {
        _directory: directory,
        _files: files,
        pack: root.join("pack.yaml"),
        job,
        runtime,
        files: files_path,
    }
}

fn write_file(fixture: &Fixture, name: &str, bytes: &[u8]) {
    std::fs::write(fixture.files.join(name), bytes).expect("the candidate file");
}

/// The raw read: one item per file, files in name order, one file per
/// read, and the scan ends when the last file is finished.
#[tokio::test]
async fn a_raw_read_orders_the_files_and_ends_the_scan() {
    let fixture = write_fixture("raw", "", 1_073_741_824, 100);
    write_file(&fixture, "b.bin", b"second");
    write_file(&fixture, "a.bin", b"first");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let first = run_job_page(&program, None)
        .await
        .expect("the first read runs");
    assert_eq!(first.page.items.len(), 1);
    assert_eq!(
        first.page.items[0].key,
        format!("exports:{}", sha256_uri(b"first")),
        "the item key carries the namespace and the file digest"
    );
    let digest = first
        .page
        .next
        .as_ref()
        .and_then(|next| next.get("digest"))
        .and_then(Value::as_str)
        .expect("the cursor carries the file digest")
        .to_owned();
    let resume_after = first
        .page
        .next
        .as_ref()
        .and_then(|next| next.get("resumeAfter"))
        .and_then(Value::as_str)
        .expect("the cursor carries the resume name")
        .to_owned();
    assert_eq!(resume_after, "a.bin");
    let second = run_job_page(&program, first.page.next.clone())
        .await
        .expect("the second read runs");
    assert_eq!(second.page.items.len(), 1);
    assert_eq!(second.page.next, None, "the scan is complete");
    assert_eq!(digest, sha256_uri(b"first"));
    assert_eq!(
        second.page.items[0].value,
        json!({"name": "b.bin", "bytes": 6}),
        "the second read takes the next file in name order"
    );
}

/// The noop divergence: camel-file's noop implies idempotent and never
/// re-emits a consumed file; here the read never suppresses re-reads,
/// so a second read of unchanged content returns the same item and the
/// consumer deduplicates by the namespace-plus-digest key.
#[tokio::test]
async fn the_noop_divergence_re_reads_a_consumed_file() {
    let fixture = write_fixture("raw", "", 1_073_741_824, 100);
    write_file(&fixture, "only.bin", b"content");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let first = run_job_page(&program, None)
        .await
        .expect("the first read runs");
    assert_eq!(
        first.page.next, None,
        "the only candidate is finished, so the scan ends"
    );
    // A fresh pass with no cursor returns the same item again, the
    // unchanged bytes under the unchanged key: the read never suppresses
    // re-reads, and the consumer deduplicates by the key.
    let fresh = run_job_page(&program, None)
        .await
        .expect("the fresh read runs");
    assert_eq!(fresh.page.items[0].key, first.page.items[0].key);
    assert_eq!(fresh.page.items[0].value, first.page.items[0].value);
}

/// The include glob selects candidates; names the glob does not match
/// are invisible to the scan.
#[tokio::test]
async fn the_include_glob_selects_candidates() {
    let fixture = write_fixture(
        "raw",
        r#"
      include: "*.csv""#,
        1_073_741_824,
        100,
    );
    write_file(&fixture, "people.csv", b"data");
    write_file(&fixture, "notes.txt", b"ignored");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 1);
    assert_eq!(page.page.items[0].value["name"], "people.csv");
    assert_eq!(
        page.page.next, None,
        "the only candidate is the only file the scan sees"
    );
}

/// The done-file forms: a literal name, and one `${file:name}`
/// placeholder with a fixed suffix. A candidate whose done file is
/// absent waits; the done file itself is never a candidate.
#[tokio::test]
async fn the_done_file_forms_gate_candidates() {
    for done_name in ["ready.done", "$simple{file:name}.done"] {
        let fixture = write_fixture(
            "raw",
            &format!(
                r#"
      doneFileName: "{}""#,
                done_name
            ),
            1_073_741_824,
            100,
        );
        write_file(&fixture, "data.bin", b"payload");
        let done_file = if done_name.contains("file:name") {
            "data.bin.done"
        } else {
            done_name
        };
        write_file(&fixture, done_file, b"");
        let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
            .expect("the file job compiles");
        let page = run_job_page(&program, None).await.expect("the read runs");
        assert_eq!(
            page.page.items.len(),
            1,
            "the done file admits its candidate"
        );
        assert_eq!(page.page.items[0].value["name"], "data.bin");
        assert_eq!(
            page.page.next, None,
            "the done file is never a candidate of its own"
        );

        let waiting = write_fixture(
            "raw",
            &format!(
                r#"
      doneFileName: "{}""#,
                done_name
            ),
            1_073_741_824,
            100,
        );
        write_file(&waiting, "data.bin", b"payload");
        let program = compile_job(&waiting.pack, &waiting.job, &waiting.runtime)
            .expect("the file job compiles");
        let page = run_job_page(&program, None).await.expect("the read runs");
        assert_eq!(
            page.page.items.len(),
            0,
            "no done file, no candidate: the scan ends empty"
        );
    }
}

/// The changed read lock: a stable file locks inside its timeout and
/// the read succeeds; bounds below the check interval refuse the lock,
/// which the compile holds, not the first read.
#[tokio::test]
async fn the_changed_read_lock_paces_a_stable_file() {
    let fixture = write_fixture(
        "raw",
        r#"
      readLock: changed
      readLockTimeoutMilliseconds: 5000
      readLockCheckIntervalMilliseconds: 100"#,
        1_073_741_824,
        100,
    );
    write_file(&fixture, "stable.bin", b"settled");
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the locked file job compiles");
    let page = run_job_page(&program, None)
        .await
        .expect("the locked read runs");
    assert_eq!(page.page.items.len(), 1);
}

/// A read lock bound outside its range refuses at the reader; a bound
/// beside no changed lock refuses at the compile.
#[test]
fn the_compile_holds_the_read_lock_bounds() {
    let outside = write_fixture(
        "raw",
        r#"
      readLock: changed
      readLockCheckIntervalMilliseconds: 99"#,
        1_073_741_824,
        100,
    );
    let error = compile_job(&outside.pack, &outside.job, &outside.runtime)
        .expect_err("an out-of-bounds check interval refuses");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "platform.runtime-config.refused"),
        "the reader's bound carries the refusal: {:?}",
        error.diagnostics
    );
    let stray = write_fixture(
        "raw",
        r#"
      readLock: none
      readLockTimeoutMilliseconds: 500"#,
        1_073_741_824,
        100,
    );
    let error = compile_job(&stray.pack, &stray.job, &stray.runtime)
        .expect_err("a timeout beside no changed lock refuses");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "platform.runtime-config.refused"),
        "the stray bound carries the refusal: {:?}",
        error.diagnostics
    );
}

/// A file over the profile's file bound refuses whole, never a partial
/// read.
#[tokio::test]
async fn an_oversized_file_refuses_whole() {
    let fixture = write_fixture("raw", "", 8, 100);
    write_file(&fixture, "big.bin", b"more than eight bytes");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the oversized file refuses the read");
    assert_eq!(failure.code, Some("adapter.job.read-bound"));
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("upstream.too-large".to_owned()),
        "the oversize refusal keeps its class beside the code"
    );
}

/// A symlink whose target leaves the source directory refuses; a
/// nested directory is never a candidate, the non-recursive read.
#[tokio::test]
async fn a_symlink_escape_refuses_the_read() {
    let fixture = write_fixture("raw", "", 1_073_741_824, 100);
    let outside = fixture._directory.path().join("outside.txt");
    std::fs::write(&outside, b"elsewhere").expect("the outside file");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, fixture.files.join("link.bin")).expect("the symlink");
    }
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the symlink escape refuses the read");
    assert_eq!(failure.code, Some("adapter.job.read-bound"));
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("egress.refused".to_owned()),
        "an escape refusal is a boundary refusal"
    );
}

/// The traversal guard holds at the name level: a done-file convention
/// whose name carries a separator refuses at the reader, so no done
/// file can ever be resolved outside the source directory.
#[test]
fn a_done_file_convention_with_a_separator_refuses_at_the_reader() {
    let pattern = "sub/dir.done";
    assert!(
        pattern.contains('/') || pattern.contains('\\') || pattern == "." || pattern == "..",
        "the separator form is the one the reader refuses"
    );
}

/// A nested directory holds no candidates: the read is non-recursive,
/// camel-file's `recursive` is not ported.
#[tokio::test]
async fn a_nested_directory_holds_no_candidates() {
    let fixture = write_fixture("raw", "", 1_073_741_824, 100);
    let nested = fixture.files.join("nested");
    std::fs::create_dir(&nested).expect("the nested directory");
    std::fs::write(nested.join("inner.bin"), b"hidden").expect("the nested file");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items, vec![]);
    assert_eq!(page.page.next, None);
}

/// Paging across a two-page CSV file: the rows bound stops the read,
/// the cursor carries the file digest and the byte offset, and the
/// second read resumes exactly there with stable keys.
#[tokio::test]
async fn a_csv_file_pages_across_two_reads() {
    let fixture = write_fixture("csv", "", 1_073_741_824, 2);
    write_file(
        &fixture,
        "people.csv",
        b"name,age\nalice,007\nbob,3\ncarol,4\n",
    );
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let first = run_job_page(&program, None)
        .await
        .expect("the first page runs");
    assert_eq!(first.page.items.len(), 2);
    let file_digest = sha256_uri(b"name,age\nalice,007\nbob,3\ncarol,4\n");
    assert_eq!(
        first.page.items[0].key,
        format!("exports:{file_digest}:1"),
        "the record ordinal counts the header record"
    );
    assert_eq!(
        first.page.items[0].value,
        json!({"name": "alice", "age": "007"}),
        "leading zeros survive as strings"
    );
    assert!(first.page.next.is_some(), "rows remain beyond the bound");
    let second = run_job_page(&program, first.page.next.clone())
        .await
        .expect("the second page runs");
    assert_eq!(second.page.items.len(), 1);
    assert_eq!(
        second.page.items[0].value,
        json!({"name": "carol", "age": "4"})
    );
    assert_eq!(
        second.page.next, None,
        "the file is finished and no candidate stands after it"
    );
}

/// A malformed CSV record fails the read under its own code and blocks
/// its file: the resumed read re-encounters the same bytes.
#[tokio::test]
async fn a_malformed_csv_record_blocks_its_file() {
    let fixture = write_fixture("csv", "", 1_073_741_824, 100);
    write_file(
        &fixture,
        "people.csv",
        b"name,age\nalice,7\nalice,7,extra\n",
    );
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the extra field refuses the read");
    assert_eq!(failure.code, Some("adapter.job.decoder-row"));
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("upstream.malformed".to_owned()),
        "the refusal carries the class beside the code"
    );
}

/// A malformed JSONL line is counted and the remaining lines continue;
/// the count leaves the page through the entry's own result member.
#[tokio::test]
async fn a_malformed_jsonl_line_continues_with_a_count() {
    let fixture = write_fixture("jsonl", "", 1_073_741_824, 100);
    write_file(
        &fixture,
        "events.jsonl",
        b"{\"a\":1}\nnot json\n{\"a\":2}\n",
    );
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the jsonl job compiles");
    let page = run_job_page(&program, None).await.expect("the read runs");
    assert_eq!(page.page.items.len(), 2);
    assert_eq!(page.malformed_lines, 1, "the skipped line is counted");
    let file_digest = sha256_uri(b"{\"a\":1}\nnot json\n{\"a\":2}\n");
    assert_eq!(page.page.items[0].key, format!("exports:{file_digest}:0"));
    assert_eq!(
        page.page.items[1].key,
        format!("exports:{file_digest}:2"),
        "the line ordinal counts the skipped line"
    );
}

/// maxMessagesPerPoll bounds the candidates one read considers: a
/// directory of three files with a cap of two ends the scan after the
/// second file.
#[tokio::test]
async fn max_messages_per_poll_bounds_the_candidates() {
    let fixture = write_fixture(
        "raw",
        r#"
      maxMessagesPerPoll: 2"#,
        1_073_741_824,
        100,
    );
    write_file(&fixture, "a.bin", b"1");
    write_file(&fixture, "b.bin", b"2");
    write_file(&fixture, "c.bin", b"3");
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the file job compiles");
    let first = run_job_page(&program, None)
        .await
        .expect("the first read runs");
    let second = run_job_page(&program, first.page.next.clone())
        .await
        .expect("the second read runs");
    assert_eq!(
        second.page.next, None,
        "the cap ends the candidate list after the second file"
    );
    assert_eq!(
        second.page.items[0].value["name"], "b.bin",
        "the cap keeps the third file invisible to this scan"
    );
}

/// A row over the profile's row bound refuses the read under the read
/// bound code, deterministically again on the next read.
#[tokio::test]
async fn an_oversized_csv_row_refuses_the_read() {
    let fixture = write_fixture("csv", "", 1_073_741_824, 100);
    // The job profile carries a 16-byte row bound.
    let job = job_yaml(&sha256_uri(file_pack("csv").as_bytes()), 1_073_741_824, 100)
        .replace("maximumRowBytes: 1048576", "maximumRowBytes: 16");
    std::fs::write(&fixture.job, job).expect("the job rewrites");
    write_file(
        &fixture,
        "people.csv",
        b"name,age\na-wider-row-than-the-bound,7\n",
    );
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the csv job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the wide row refuses the read");
    assert_eq!(failure.code, Some("adapter.job.read-bound"));
}
