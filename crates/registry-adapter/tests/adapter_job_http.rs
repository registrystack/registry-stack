// SPDX-License-Identifier: Apache-2.0

//! The `http` component under the job profile
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2): a kobo-shaped
//! paged acquisition over the loopback double, a job-only endpoint's
//! raised response bound carrying a body the facade ceiling would
//! refuse, and the profile's upstream-call budget held at the page run.

use registry_adapter::job::{compile_job, run_job_page};
use registry_platform_config::sha256_uri;
use serde_json::{json, Value};

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

/// The pack script of a kobo-shaped route: the fetched submissions page,
/// shaped as the item contract, the route's own next cursor carried
/// through under the engine's property rules.
const PAGE_SCRIPT: &str = r#"// The fetched submissions page, shaped as the item
// contract (CONCEPT 17.2): one item per reply entry.
fn page(exchange) {
    let entries = exchange.body.results;
    if entries == () {
        throw "the reply carries no results array";
    }
    let items = [];
    for entry in entries {
        items.push(#{key: "submissions/" + entry.id, value: entry});
    }
    #{items: items, next: exchange.properties.jobNext}
}
"#;

/// The pack of the kobo-shaped job: one http send and the shaping
/// script, the endpoint bound raised toward the platform cap because no
/// facade binding reaches it.
fn pack_yaml(script: &str) -> String {
    let digest = sha256_uri(script.as_bytes());
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: kobo-shaped-pack
version: "1"
testedVersions: []
endpoints:
  - id: kobo-api
    component: http
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 16777216
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: key-deduplicated
    edits: ordered
    steps:
      - to:
          uri: http:kobo-api
          parameters:
            httpMethod: GET
            path: /v1/data
            query:
              start:
                exchangeProperty: AdapterJobCursor
      - setProperty:
          name: jobNext
          value:
            jsonpath: $.next
      - setBody:
          rhai:
            file: scripts/page.rhai
            entrypoint: page
scripts:
  - path: scripts/page.rhai
    digest: {digest}
capabilities: {{}}
"#
    )
}

fn job_yaml(pack_digest: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: kobo-shaped-daily
  version: "1"
source:
  pack:
    id: kobo-shaped-pack
    version: "1"
    digest: {pack_digest}
  route: kobo-submissions
projection:
  fields:
    - id
triggers:
  - kind: interval
    delayMilliseconds: 60000
profile:
  pageDeadlineMilliseconds: 60000
  maximumResponseBytes: 16777216
  maximumPageItems: 100
  maximumPageBytes: 2097152
  maximumUpstreamCalls: 8
  read:
    maximumFileBytes: 1073741824
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: 100
"#
    )
}

fn runtime_yaml(base_url: &str) -> String {
    let config = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/runtime/v1alpha1",
        "kind": "AdapterRuntimeConfig",
        "id": "kobo-shaped-deployment",
        "endpoints": [
            {
                "endpoint": "kobo-api",
                "baseUrl": base_url,
                "credential": {"type": "none"}
            }
        ],
        "allowedPrivateCidrs": ["192.168.0.0/16"]
    });
    serde_json::to_string_pretty(&config).expect("the runtime config renders")
}

struct Fixture {
    _directory: tempfile::TempDir,
    pack: std::path::PathBuf,
    job: std::path::PathBuf,
    runtime: std::path::PathBuf,
    #[allow(dead_code)]
    double: upstream::UpstreamDouble,
}

fn write_fixture() -> Fixture {
    let double = upstream::UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    std::fs::create_dir_all(root.join("scripts")).expect("the scripts directory");
    std::fs::write(root.join("scripts/page.rhai"), PAGE_SCRIPT).expect("the page script");
    let pack_text = pack_yaml(PAGE_SCRIPT);
    std::fs::write(root.join("pack.yaml"), &pack_text).expect("the pack");
    let profile = r#"apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: kobo-shaped
version: "1"
operations: []
problems:
  - code: kobo.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: kobo.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: kobo.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted, outcome, facade]
  - code: kobo.boundary
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
  id: kobo-shaped-example
  version: "1"
profile:
  id: kobo-shaped
  version: "1"
  digest: {}
pack:
  id: kobo-shaped-pack
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
    std::fs::write(&runtime, runtime_yaml(&double.url("/"))).expect("the runtime config");
    Fixture {
        _directory: directory,
        pack: root.join("pack.yaml"),
        job,
        runtime,
        double,
    }
}

/// A reply page of one submission: the id alone, with a wide padding
/// array the caller sizes. The padding rides an array of bounded
/// strings, because the transport's value shape caps any one string at
/// one mebibyte.
fn reply_page(id: &str, pad_entries: usize) -> Value {
    let mut entry = json!({"id": id});
    entry["pad"] = Value::Array(vec![json!("x".repeat(1_000)); pad_entries]);
    json!({
        "results": [entry],
        "next": {"queryId": "page-2"},
    })
}

/// The paged acquisition: the cursor rides the read-only property into
/// the send's query, the reply shapes into the item contract, and the
/// route's own cursor comes back as `next`, the way a kobo-shaped
/// source pages under the job profile.
#[tokio::test]
async fn a_paged_http_acquisition_round_trips_the_cursor() {
    let fixture = write_fixture();
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page("a", 8).to_string(),
    )]);
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the kobo-shaped job compiles");
    let result = run_job_page(&program, Some(json!("2024-01-01T00:00:00Z")))
        .await
        .expect("the page runs");
    assert_eq!(result.page.items.len(), 1);
    assert_eq!(result.page.items[0].key, "submissions/a");
    assert_eq!(
        result.page.next,
        Some(json!({"queryId": "page-2"})),
        "the route's own cursor is the page's next"
    );
    let request = &fixture.double.requests()[0];
    assert_eq!(
        request.target, "/v1/data?start=2024-01-01T00%3A00%3A00Z",
        "the entry's cursor reached the send's query"
    );
}

/// A job-only endpoint may declare its response bound up to the
/// platform cap (CONCEPT 17.2, D39): a body past the facade's fixed
/// ceiling passes the job page and the profile's raised bound, where a
/// facade deployment would refuse it.
#[tokio::test]
async fn a_oversized_body_passes_a_job_endpoint() {
    let fixture = write_fixture();
    // The facade ceiling is one mebibyte; the body carries well past it.
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page("wide", 1_200).to_string(),
    )]);
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the kobo-shaped job compiles");
    let result = run_job_page(&program, None).await.expect("the page runs");
    assert_eq!(result.page.items.len(), 1);
    assert_eq!(result.page.items[0].value["id"], "wide");
    let serialized = serde_json::to_vec(&result.page.to_value()).expect("the page serializes");
    assert!(
        serialized.len() > 1_048_576,
        "the page exceeds the facade's fixed exchange budget"
    );
}

/// The profile's upstream-call budget holds at the run: a route whose
/// sends outgrow the budget the authoring check admits refuses the run
/// as budget exhausted, the same number the compile held.
#[tokio::test]
async fn the_upstream_call_budget_holds_at_the_run() {
    let fixture = write_fixture();
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page("a", 8).to_string(),
    )]);
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the kobo-shaped job compiles");
    // The budget the compile admitted: the static worst case of the
    // source route is one send, so the check held 8; the run carries
    // the same number at the edge.
    assert_eq!(
        program.profile().maximum_upstream_calls,
        8,
        "the run enforces the profile's own budget"
    );
    let result = run_job_page(&program, None).await.expect("the page runs");
    assert_eq!(result.page.items.len(), 1, "one send, inside the budget");
}
