// SPDX-License-Identifier: Apache-2.0

//! The job compiler and page entry
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2): one http
//! send shaped by a pack script into the item contract, the cursor
//! round trip through the read-only `AdapterJobCursor` property, the
//! page faults, and the profile's page deadline.

use std::time::{Duration, Instant};

use registry_adapter::job::{compile_job, run_job_page, ADAPTER_JOB_CURSOR_PROPERTY};
use registry_platform_config::sha256_uri;
use serde_json::{json, Value};

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

const PAGE_SCRIPT: &str = r#"// The fetched submissions page, shaped as the item
// contract (CONCEPT 17.2): one item per reply entry, the route's own
// next cursor carried through under the engine's property rules.
fn page(exchange) {
    let entries = exchange.body.data;
    if entries == () {
        throw "the reply carries no data array";
    }
    let items = [];
    for entry in entries {
        if entry.id == () {
            throw "a reply entry carries no id";
        }
        items.push(#{key: "submissions/" + entry.id, value: entry});
    }
    #{items: items, next: exchange.properties.jobNext}
}
"#;

/// The malformed variant: every item it emits carries an empty key, so
/// the entry refuses the page under `adapter.job.page-key`.
const EMPTY_KEY_SCRIPT: &str = r#"// The fetched submissions page, every item
// keyed by the empty string.
fn page(exchange) {
    let items = [];
    for entry in exchange.body.data {
        items.push(#{key: "", value: entry});
    }
    #{items: items, next: exchange.properties.jobNext}
}
"#;

/// The profile of the fixture job: a page deadline of one minute unless
/// the lane tightens it.
fn profile_json(page_deadline_milliseconds: u64) -> String {
    format!(
        r#""profile": {{
            "pageDeadlineMilliseconds": {page_deadline_milliseconds},
            "maximumResponseBytes": 16777216,
            "maximumPageItems": 100,
            "maximumPageBytes": 1048576,
            "maximumUpstreamCalls": 8,
            "read": {{
                "maximumFileBytes": 1073741824,
                "maximumRowBytes": 1048576,
                "maximumFieldBytes": 65536,
                "maximumRowsPerPage": 100
            }}
        }}"#
    )
}

/// The pack of the fixture job: one http endpoint over the double and
/// one source route that sends, then shapes the reply through the
/// script the pack pins.
fn pack_yaml(script: &str, script_path: &str) -> String {
    let digest = sha256_uri(script.as_bytes());
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions: []
endpoints:
  - id: submissions
    component: http
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 65536
sourceRoutes:
  - id: submissions-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - to:
          uri: http:submissions
          parameters:
            httpMethod: GET
            path: /v1/submissions
            query:
              cursor:
                exchangeProperty: AdapterJobCursor
      - setProperty:
          name: jobNext
          value:
            jsonpath: $.nextCursor
      - setBody:
          rhai:
            file: {script_path}
            entrypoint: page
scripts:
  - path: {script_path}
    digest: {digest}
capabilities: {{}}
"#
    )
}

/// The profile beside the pack: the same facade surface the workspace
/// checks run over, with no operation the job would serve.
const PROFILE_YAML: &str = r#"apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: case-api
version: "1"
operations:
  - id: cases-get
    method: GET
    path: /v2/cases/{type}/{case_id}
    pathParameters:
      - type
      - case_id
    recordTypeParameter: type
    recordIdParameter: case_id
    responseEnvelope: '{"case": {{record}}, "fetchedAt": "{{requestId}}"}'
problems:
  - code: cases.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: cases.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: cases.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted]
  - code: cases.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected, outcome, facade]
problemEnvelope: '{"family": "{{problemCode}}"}'
"#;

fn project_yaml(profile_digest: &str, pack_digest: &str, bind_source_route: bool) -> String {
    let binding = if bind_source_route {
        r#"bindings:
  - id: case-get
    operation: cases-get
    recordType: case
    route: submissions-page
    maximumUpstreamCalls: 4
"#
    } else {
        "bindings: []\n"
    };
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
{binding}"#
    )
}

fn job_yaml(pack_digest: &str, route: &str, page_deadline_milliseconds: u64) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: case-daily
  version: "1"
source:
  pack:
    id: case-api-pack
    version: "1"
    digest: {pack_digest}
  route: {route}
projection:
  fields:
    - id
    - answers.age
triggers:
  - kind: interval
    delayMilliseconds: 60000
{}"#,
        profile_json(page_deadline_milliseconds)
    )
}

fn runtime_yaml(base_url: &str) -> String {
    let config = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/runtime/v1alpha1",
        "kind": "AdapterRuntimeConfig",
        "id": "job-deployment",
        "endpoints": [
            {
                "endpoint": "submissions",
                "baseUrl": base_url,
                "credential": {"type": "none"}
            }
        ],
        "allowedPrivateCidrs": ["192.168.0.0/16"],
        "listener": {"bind": "127.0.0.1:8080"},
        "database": {
            "runtimeUrlRef": "secret:env/JOB_TEST_DB",
            "migrationUrlRef": "secret:env/JOB_TEST_DB"
        },
        "oidc": {
            "issuer": "https://issuer.example.invalid",
            "audience": "job-test"
        },
        "allowedClients": ["job-client"],
        "audit": {"retentionDays": 90}
    });
    serde_json::to_string_pretty(&config).expect("the runtime config renders")
}

/// The runtime config of a source-only job: no endpoint bindings, because
/// the file and postgres sources bind through the runtime's sources
/// block, not an endpoint binding.
fn runtime_yaml_without_bindings() -> String {
    let config = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/runtime/v1alpha1",
        "kind": "AdapterRuntimeConfig",
        "id": "job-deployment",
        "endpoints": [],
        "allowedPrivateCidrs": ["192.168.0.0/16"],
        "listener": {"bind": "127.0.0.1:8080"},
        "database": {
            "runtimeUrlRef": "secret:env/JOB_TEST_DB",
            "migrationUrlRef": "secret:env/JOB_TEST_DB"
        },
        "oidc": {
            "issuer": "https://issuer.example.invalid",
            "audience": "job-test"
        },
        "allowedClients": ["job-client"],
        "audit": {"retentionDays": 90}
    });
    serde_json::to_string_pretty(&config).expect("the runtime config renders")
}

/// One fixture workspace: the profile and project beside the pack, the
/// job, and the operator runtime config, over the loopback double.
struct Fixture {
    _directory: tempfile::TempDir,
    pack: std::path::PathBuf,
    job: std::path::PathBuf,
    runtime: std::path::PathBuf,
    #[allow(dead_code)]
    double: upstream::UpstreamDouble,
}

fn write_fixture(
    script: &str,
    page_deadline_milliseconds: u64,
    bind_source_route: bool,
) -> Fixture {
    let double = upstream::UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    std::fs::create_dir_all(root.join("scripts")).expect("the scripts directory");
    let pack_text = pack_yaml(script, "scripts/page.rhai");
    std::fs::write(root.join("scripts/page.rhai"), script).expect("the page script");
    std::fs::write(root.join("pack.yaml"), &pack_text).expect("the pack");
    std::fs::write(root.join("profile.yaml"), PROFILE_YAML).expect("the profile");
    let profile_digest = sha256_uri(PROFILE_YAML.as_bytes());
    let pack_digest = sha256_uri(pack_text.as_bytes());
    std::fs::write(
        root.join("project.yaml"),
        project_yaml(&profile_digest, &pack_digest, bind_source_route),
    )
    .expect("the project");
    let job = root.join("job.yaml");
    std::fs::write(
        &job,
        job_yaml(&pack_digest, "submissions-page", page_deadline_milliseconds),
    )
    .expect("the job");
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

fn reply_page() -> Value {
    json!({
        "data": [
            {"id": "a", "answers": {"age": "045"}},
            {"id": "b", "answers": {"age": "007"}}
        ],
        "nextCursor": {"position": 2}
    })
}

#[tokio::test]
async fn a_job_route_over_http_returns_a_valid_item_page() {
    let fixture = write_fixture(PAGE_SCRIPT, 60_000, false);
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page().to_string(),
    )]);
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let result = run_job_page(&program, None).await.expect("the page runs");
    assert_eq!(result.page.items.len(), 2, "both reply entries are items");
    assert_eq!(result.page.items[0].key, "submissions/a");
    assert_eq!(result.page.items[0].value["answers"]["age"], "045");
    assert_eq!(result.page.next, Some(json!({"position": 2})));
    assert_eq!(result.malformed_lines, 0, "no decoder ran");
    let request = &fixture.double.requests()[0];
    assert_eq!(
        request.target, "/v1/submissions",
        "an absent cursor leaves the query parameter out"
    );
}

/// The cursor round trip: the entry places the caller's cursor under
/// the read-only `AdapterJobCursor` property, the route reads it into
/// its query, and the route's own next cursor comes back as `next`.
#[tokio::test]
async fn the_cursor_round_trips_through_the_read_only_property() {
    let fixture = write_fixture(PAGE_SCRIPT, 60_000, false);
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page().to_string(),
    )]);
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let result = run_job_page(&program, Some(json!("page-2")))
        .await
        .expect("the page runs");
    let request = &fixture.double.requests()[0];
    assert_eq!(
        request.target, "/v1/submissions?cursor=page-2",
        "the route read the cursor the entry placed"
    );
    assert_eq!(result.page.next, Some(json!({"position": 2})));
}

/// A page the item contract refuses fails with its own closed code,
/// here `adapter.job.page-key` for an empty item key.
#[tokio::test]
async fn a_malformed_page_fails_with_its_page_code() {
    let fixture = write_fixture(EMPTY_KEY_SCRIPT, 60_000, false);
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page().to_string(),
    )]);
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the empty key refuses the page");
    assert_eq!(failure.code, Some("adapter.job.page-key"));
    assert!(failure.class.is_none(), "no route failure ended the run");
}

/// The profile's page deadline bounds the run: a stalling double
/// exhausts a tiny deadline as `budget.exhausted`, long before the
/// engine's own exchange deadline or the attempt timeout would end it.
#[tokio::test]
async fn a_page_deadline_exceeded_fails_as_budget() {
    let fixture = write_fixture(PAGE_SCRIPT, 200, false);
    fixture.double.delay_answers(Duration::from_secs(3));
    fixture.double.respond_with(vec![upstream::Response::json(
        200,
        &reply_page().to_string(),
    )]);
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let started = Instant::now();
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the stalling page exhausts the deadline");
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("budget.exhausted".to_owned()),
        "the deadline failure is a budget failure, not a page fault"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the page deadline, not the exchange deadline, ended the run"
    );
}

/// A job whose source route a facade binding reaches refuses at
/// compile under the authoring check's own code.
#[test]
fn compile_refuses_a_facade_bound_job() {
    let fixture = write_fixture(PAGE_SCRIPT, 60_000, true);
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("a bound source route refuses");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "adapter.job.source-bound-refused"),
        "the binding refusal carries its own code: {:?}",
        error
            .diagnostics
            .iter()
            .map(|d| d.code.clone())
            .collect::<Vec<_>>()
    );
}

/// The cursor property is write-protected: a source route that writes
/// it refuses at compile under the reserved-name rule.
#[test]
fn compile_refuses_a_route_that_writes_the_cursor_property() {
    let script = r#"fn page(exchange) {
    #{items: [], next: exchange.properties.jobNext}
}
"#;
    let fixture = write_fixture(script, 60_000, false);
    let pack = fixture.pack.clone();
    let text = std::fs::read_to_string(&pack).expect("the pack reads");
    let guarded = text.replace(
        "- setProperty:\n          name: jobNext",
        "- setProperty:\n          name: AdapterJobCursor",
    );
    std::fs::write(&pack, &guarded).expect("the pack rewrites");
    let pack_digest = sha256_uri(guarded.as_bytes());
    let workspace = fixture.job.parent().expect("the workspace").to_path_buf();
    std::fs::write(
        &fixture.job,
        job_yaml(&pack_digest, "submissions-page", 60_000),
    )
    .expect("the job rewrites");
    let project = workspace.join("project.yaml");
    let project_text = std::fs::read_to_string(&project).expect("the project reads");
    let repinned = project_text.replace(
        &format!("digest: {}", sha256_uri(text.as_bytes())),
        &format!("digest: {pack_digest}"),
    );
    std::fs::write(&project, repinned).expect("the project rewrites");
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("writing the cursor property refuses");
    assert!(
        error.diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("reserved property")
                || diagnostic.suggested_action.contains("reserved property")
        }),
        "the refusal names the reserved property: {:?}",
        error.diagnostics
    );
}

/// The digest pin of the job refuses a pack whose bytes are not the
/// ones the job pinned.
#[test]
fn compile_refuses_a_job_pinned_to_other_pack_bytes() {
    let fixture = write_fixture(PAGE_SCRIPT, 60_000, false);
    let pack = fixture.pack.clone();
    let text = std::fs::read_to_string(&pack).expect("the pack reads");
    std::fs::write(
        &pack,
        text.replace("testedVersions: []", "testedVersions: [] # changed"),
    )
    .expect("the pack rewrites");
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("the pin refuses other bytes");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "adapter.project.pin-digest-mismatch"),
        "the digest pin refusal carries its own code: {:?}",
        error
            .diagnostics
            .iter()
            .map(|d| d.code.clone())
            .collect::<Vec<_>>()
    );
}

/// The cursor property name stays the one the contract names, so the
/// runner and the packs agree on the read-only slot.
#[test]
fn the_cursor_property_is_the_read_only_engine_slot() {
    assert_eq!(ADAPTER_JOB_CURSOR_PROPERTY, "AdapterJobCursor");
}

/// The pack of a file-source job: one file endpoint, one source route
/// whose pollEnrich read carries the mandatory timeout.
fn file_pack_yaml() -> String {
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
    maximumResponseBytes: 65536
sourceRoutes:
  - id: drop-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - pollEnrich:
          uri: file:dropbox
          timeoutMilliseconds: 10000
capabilities: {}
"#
    .to_owned()
}

/// The pack of a postgres-source job: one read-only postgres endpoint
/// with its digest-pinned query file, one source route that sends.
fn postgres_pack_yaml(query: &str) -> String {
    let digest = sha256_uri(query.as_bytes());
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: ledger-pack
version: "1"
testedVersions: []
endpoints:
  - id: ledger
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 65536
    queryFile: queries/ledger.sql
queryFiles:
  - path: queries/ledger.sql
    digest: {digest}
sourceRoutes:
  - id: ledger-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - to:
          uri: postgres:ledger
          parameters:
            queryParameters:
              offset:
                constant: 0
capabilities: {{}}
"#
    )
}

/// A fixture workspace around a caller-supplied pack text and the source
/// route the job runs: profile and project beside it, the job, and the
/// operator runtime config.
fn write_pack_fixture(pack_text: &str, route: &str) -> Fixture {
    write_pack_fixture_with_runtime(pack_text, route, &runtime_yaml_without_bindings())
}

/// The same fixture with a caller-supplied runtime config text, for the
/// jobs whose pack carries a bound endpoint.
fn write_pack_fixture_with_runtime(pack_text: &str, route: &str, runtime_text: &str) -> Fixture {
    let double = upstream::UpstreamDouble::start();
    let directory = tempfile::tempdir().expect("a scratch workspace");
    let root = directory.path().to_path_buf();
    std::fs::create_dir_all(root.join("queries")).expect("the queries directory");
    std::fs::create_dir_all(root.join("scripts")).expect("the scripts directory");
    // A pack that pins scripts/page.rhai reads this exact file; a pack
    // that inventories no scripts leaves it unread beside the pack.
    std::fs::write(root.join("scripts/page.rhai"), PAGE_SCRIPT).expect("the page script");
    std::fs::write(root.join("pack.yaml"), pack_text).expect("the pack");
    std::fs::write(root.join("profile.yaml"), PROFILE_YAML).expect("the profile");
    let profile_digest = sha256_uri(PROFILE_YAML.as_bytes());
    let pack_digest = sha256_uri(pack_text.as_bytes());
    std::fs::write(
        root.join("project.yaml"),
        project_yaml(&profile_digest, &pack_digest, false),
    )
    .expect("the project");
    let job = root.join("job.yaml");
    std::fs::write(&job, job_yaml(&pack_digest, route, 60_000)).expect("the job");
    let runtime = root.join("runtime.yaml");
    std::fs::write(&runtime, runtime_text).expect("the runtime config");
    Fixture {
        _directory: directory,
        pack: root.join("pack.yaml"),
        job,
        runtime,
        double,
    }
}

/// The default build compiles no file source: a pack whose source route
/// reads a file endpoint refuses at compile under
/// `adapter.job.component-unavailable`, so a facade binary can never
/// reach the file component (CONCEPT 17.1).
#[cfg(not(feature = "job-file"))]
#[test]
fn the_default_build_refuses_a_file_job() {
    let fixture = write_pack_fixture(&file_pack_yaml(), "drop-page");
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("the default build refuses a file source");
    assert!(
        error.diagnostics.iter().any(|diagnostic| diagnostic.code
            == "adapter.job.component-unavailable"
            && diagnostic.path == "/endpoints/dropbox"),
        "the refusal names the file endpoint: {:?}",
        error.diagnostics
    );
}

/// The default build compiles no postgres send: a pack whose source
/// route sends to a postgres endpoint refuses at compile under
/// `adapter.job.component-unavailable`.
#[cfg(not(feature = "job-postgres"))]
#[test]
fn the_default_build_refuses_a_postgres_job() {
    let fixture = write_pack_fixture(&postgres_pack_yaml("SELECT id FROM ledger"), "ledger-page");
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("the default build refuses a postgres source");
    assert!(
        error.diagnostics.iter().any(|diagnostic| diagnostic.code
            == "adapter.job.component-unavailable"
            && diagnostic.path == "/endpoints/ledger"),
        "the refusal names the postgres endpoint: {:?}",
        error.diagnostics
    );
}

/// A source route that sends to a `direct:` route the pack declares no
/// body for refuses at compile under `adapter.job.direct-unknown`, with
/// the sending step's pointer, instead of failing the first page run.
#[test]
fn compile_refuses_a_source_route_to_an_undeclared_direct_route() {
    let pack = r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions: []
endpoints:
  - id: submissions
    component: http
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 65536
sourceRoutes:
  - id: submissions-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - to:
          uri: direct:nowhere
capabilities: {}
"#;
    let fixture = write_pack_fixture_with_runtime(pack, "submissions-page", "");
    let runtime = runtime_yaml(&fixture.double.url("/"));
    std::fs::write(&fixture.runtime, runtime).expect("the runtime config");
    let error = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect_err("an undeclared direct route refuses");
    assert!(
        error
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "adapter.job.direct-unknown"
                && diagnostic.path == "/sourceRoutes/0/steps/0"),
        "the refusal names the sending step: {:?}",
        error.diagnostics
    );
}

/// The job's resilience state covers every internal route the source
/// route reaches: a throttle behind a `direct:` send paces the page
/// runs, so the first run passes and the second rejects inside the
/// throttle's period instead of failing on a pacer the compile never
/// built.
#[tokio::test]
async fn a_page_run_keeps_the_reached_internal_routes_pacer() {
    let pack = format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions: []
endpoints:
  - id: submissions
    component: http
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 65536
routes:
  - id: paced
    from:
      uri: direct:paced
    steps:
      - throttle:
          limit:
            constant: 1
          timePeriodMilliseconds: 3600000
          rejectExecution: true
          steps:
            - to:
                uri: http:submissions
                parameters:
                  httpMethod: GET
                  path: /v1/submissions
sourceRoutes:
  - id: submissions-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - to:
          uri: direct:paced
      - setProperty:
          name: jobNext
          value:
            jsonpath: $.nextCursor
      - setBody:
          rhai:
            file: scripts/page.rhai
            entrypoint: page
scripts:
  - path: scripts/page.rhai
    digest: {digest}
capabilities: {{}}
"#,
        digest = sha256_uri(PAGE_SCRIPT.as_bytes())
    );
    let fixture = write_pack_fixture_with_runtime(&pack, "submissions-page", "");
    let runtime = runtime_yaml(&fixture.double.url("/"));
    std::fs::write(&fixture.runtime, runtime).expect("the runtime config");
    let program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the throttled job compiles");
    let page = upstream::Response::json(200, &reply_page().to_string());
    fixture.double.respond_with(vec![page.clone()]);
    run_job_page(&program, None)
        .await
        .expect("the first page run passes the throttle");
    fixture.double.respond_with(vec![page]);
    let failure = run_job_page(&program, None)
        .await
        .expect_err("the second page run inside the throttle period rejects");
    assert_eq!(
        failure.class.map(|class| class.class().to_owned()),
        Some("throttle.rejected".to_owned()),
        "the reached internal route's pacer rejected the second run"
    );
}
