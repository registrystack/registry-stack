// SPDX-License-Identifier: Apache-2.0

// The shared job fixture: one module included by more than one test
// binary, each using a different part of its surface. The allow keeps
// the parts one binary leaves unread compilable for the other.
#![allow(dead_code)]
//! The job test workspace: a loopback upstream double, and the pack,
//! profile, project, job, and runtime files beside it, compiled through
//! the engine's own `compile_job` the way `registry-adapter`'s
//! `adapter_job.rs` suite compiles its fixtures.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{Request, Response};
use serde_json::{json, Value};

/// One request the double received: the target with its query, and the
/// header names, never the values the tests do not assert on.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// The request target, path and query as sent.
    pub target: String,
    /// The header names, in order.
    pub header_names: Vec<String>,
}

/// The loopback upstream: every request pops the next scripted reply,
/// and the last reply repeats when the queue empties, so a pass can run
/// the same page as often as the test needs.
pub struct UpstreamDouble {
    /// The base URL the runtime config binds the endpoint to.
    pub base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<(u16, String)>>>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl UpstreamDouble {
    /// Start the double with the replies it serves in order.
    pub async fn start(replies: Vec<(u16, Value)>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(
            replies
                .into_iter()
                .map(|(status, body)| {
                    (
                        status,
                        serde_json::to_string(&body).expect("a reply renders"),
                    )
                })
                .collect::<VecDeque<_>>(),
        ));
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the loopback double binds");
        let address = listener.local_addr().expect("the bound address");
        let state = Shared {
            requests: Arc::clone(&requests),
            responses: Arc::clone(&responses),
        };
        let app = axum::Router::new()
            .route("/v1/submissions", axum::routing::any(serve))
            .with_state(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Self {
            base_url: format!("http://{address}"),
            requests,
            responses,
            _shutdown: shutdown,
        }
    }

    /// Every request the double received, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("the double's record lock")
            .clone()
    }
}

#[derive(Clone)]
struct Shared {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<(u16, String)>>>,
}

async fn serve(
    State(shared): State<Shared>,
    request: Request<axum::body::Body>,
) -> Response<axum::body::Body> {
    let target = request
        .uri()
        .path_and_query()
        .map(|target| target.as_str().to_string())
        .unwrap_or_default();
    let header_names = request
        .headers()
        .keys()
        .map(|name| name.as_str().to_string())
        .collect();
    shared
        .requests
        .lock()
        .expect("the double's record lock")
        .push(RecordedRequest {
            target,
            header_names,
        });
    // The next reply pops; when the script runs out, the last reply
    // repeats, so a test can read the same page as often as its passes
    // need.
    let answer = {
        let mut queue = shared.responses.lock().expect("the double's script lock");
        match queue.pop_front() {
            Some(answer) => {
                queue.push_back(answer.clone());
                answer
            }
            None => queue
                .back()
                .cloned()
                .expect("the double starts with at least one reply"),
        }
    };
    Response::builder()
        .status(answer.0)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(answer.1))
        .expect("a scripted reply builds")
}

/// The page-shaping script the pack pins: one item per reply entry, the
/// reply's own `nextCursor` carried out as the page's next cursor.
pub const PAGE_SCRIPT: &str = r#"// The fetched submissions page, shaped as the
// item contract: one item per reply entry, the route's own next cursor
// carried through under the engine's property rules.
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

/// The empty-key variant: every item it emits carries an empty key, so
/// the entry refuses the page under `adapter.job.page-key`.
pub const EMPTY_KEY_SCRIPT: &str = r#"// The fetched submissions page, every
// item keyed by the empty string.
fn page(exchange) {
    let items = [];
    for entry in exchange.body.data {
        items.push(#{key: "", value: entry});
    }
    #{items: items, next: exchange.properties.jobNext}
}
"#;

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
bindings: []
"#
    )
}

/// The source route's edit declaration under test: `ordered`, whose
/// edits the position finds, or `rescan`, whose declared delay starts a
/// scan from the first page.
#[derive(Clone, Copy, Debug)]
pub enum Edits {
    /// edits: ordered, no rescan delay.
    Ordered,
    /// edits: rescan with the declared delay in seconds.
    Rescan(u64),
}

/// The source route's scan declaration under test: a `finite` scan
/// clears its cursor at the end, an `ongoing` scan holds its place at
/// the tail with a cursor on every page.
#[derive(Clone, Copy, Debug)]
pub enum Scan {
    /// scan: finite, nextRecovery: exact-replay.
    Finite,
    /// scan: ongoing, nextRecovery: key-deduplicated.
    Ongoing,
}

/// The pack of the fixture job: one http endpoint over the double and
/// one source route that sends, then shapes the reply through the script
/// the pack pins.
fn pack_yaml(script: &str, edits: Edits, scan: Scan, extra_endpoints: &str) -> String {
    let digest = registry_platform_config::sha256_uri(script.as_bytes());
    let edits_block = match edits {
        Edits::Ordered => "    edits: ordered\n".to_string(),
        Edits::Rescan(seconds) => {
            format!("    edits: rescan\n    rescanDelaySeconds: {seconds}\n")
        }
    };
    let scan_block = match scan {
        Scan::Finite => "    scan: finite\n    nextRecovery: exact-replay\n",
        Scan::Ongoing => "    scan: ongoing\n    nextRecovery: key-deduplicated\n",
    };
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
{extra_endpoints}sourceRoutes:
  - id: submissions-page
{scan_block}{edits_block}    steps:
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
            file: scripts/page.rhai
            entrypoint: page
scripts:
  - path: scripts/page.rhai
    digest: {digest}
capabilities: {{}}
"#
    )
}

fn profile_block() -> String {
    r#""profile": {
        "pageDeadlineMilliseconds": 60000,
        "maximumResponseBytes": 65536,
        "maximumPageItems": 100,
        "maximumPageBytes": 65536,
        "maximumUpstreamCalls": 8,
        "read": {
            "maximumFileBytes": 1048576,
            "maximumRowBytes": 65536,
            "maximumFieldBytes": 65536,
            "maximumRowsPerPage": 100
        }
    }"#
    .to_string()
}

fn job_yaml(pack_digest: &str) -> String {
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
  route: submissions-page
projection:
  fields:
    - id
    - answers.age
triggers:
  - kind: interval
    delayMilliseconds: 60000
{}"#,
        profile_block()
    )
}

fn runtime_yaml(base_url: &str) -> String {
    let config = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
        "kind": "AdapterJobRuntimeConfig",
        "id": "job-deployment",
        "endpoints": [
            {
                "endpoint": "submissions",
                "baseUrl": base_url,
                "credential": {"type": "none"}
            }
        ],
        "allowedPrivateCidrs": ["192.168.0.0/16"],
        "store": {
            "runtimeUrlRef": "secret:env/JOB_TEST_DB",
            "testOnlyPlaintext": true
        }
    });
    serde_json::to_string_pretty(&config).expect("the runtime config renders")
}

/// One fixture workspace: the profile and project beside the pack, the
/// job, and the operator runtime config, over the loopback double.
pub struct JobFixture {
    _directory: tempfile::TempDir,
    /// The pack file the compile reads.
    pub pack: PathBuf,
    /// The job file the compile reads.
    pub job: PathBuf,
    /// The runtime config file the compile reads.
    pub runtime: PathBuf,
    /// The loopback double the endpoint binds to.
    pub double: UpstreamDouble,
}

impl JobFixture {
    /// Write the fixture workspace and start its double with the replies
    /// it serves in order.
    pub async fn start(script: &str, replies: Vec<(u16, Value)>, edits: Edits) -> Self {
        Self::start_with_endpoints(script, replies, edits, "").await
    }

    /// The fixture workspace over an `ongoing` source route, which holds
    /// its place at the tail with a cursor on every page.
    pub async fn start_ongoing(script: &str, replies: Vec<(u16, Value)>, edits: Edits) -> Self {
        Self::build(script, replies, edits, Scan::Ongoing, "").await
    }

    /// The fixture workspace with more endpoint entries appended to the
    /// pack's endpoint list, as YAML list items at the list's indent.
    pub async fn start_with_endpoints(
        script: &str,
        replies: Vec<(u16, Value)>,
        edits: Edits,
        extra_endpoints: &str,
    ) -> Self {
        Self::build(script, replies, edits, Scan::Finite, extra_endpoints).await
    }

    async fn build(
        script: &str,
        replies: Vec<(u16, Value)>,
        edits: Edits,
        scan: Scan,
        extra_endpoints: &str,
    ) -> Self {
        let double = UpstreamDouble::start(replies).await;
        let directory = tempfile::tempdir().expect("a scratch workspace");
        let root = directory.path().to_path_buf();
        std::fs::create_dir_all(root.join("scripts")).expect("the scripts directory");
        let pack_text = pack_yaml(script, edits, scan, extra_endpoints);
        std::fs::write(root.join("scripts/page.rhai"), script).expect("the page script");
        std::fs::write(root.join("pack.yaml"), &pack_text).expect("the pack");
        std::fs::write(root.join("profile.yaml"), PROFILE_YAML).expect("the profile");
        let profile_digest = registry_platform_config::sha256_uri(PROFILE_YAML.as_bytes());
        let pack_digest = registry_platform_config::sha256_uri(pack_text.as_bytes());
        std::fs::write(
            root.join("project.yaml"),
            project_yaml(&profile_digest, &pack_digest),
        )
        .expect("the project");
        let job = root.join("job.yaml");
        std::fs::write(&job, job_yaml(&pack_digest)).expect("the job");
        let runtime = root.join("runtime.yaml");
        std::fs::write(&runtime, runtime_yaml(&format!("{}/", double.base_url)))
            .expect("the runtime config");
        Self {
            _directory: directory,
            pack: root.join("pack.yaml"),
            job,
            runtime,
            double,
        }
    }
}

/// A reply page with the two items the pass tests read, and a next
/// cursor the route carries out. The cursor is the scalar the route's
/// own query parameter can carry.
pub fn reply_page() -> Value {
    json!({
        "data": [
            {"id": "a", "answers": {"age": "045", "secret": "never-projected"}},
            {"id": "b", "answers": {"age": "007", "secret": "never-projected"}}
        ],
        "nextCursor": "p2"
    })
}

/// A short reply page: the finite end, no next cursor.
pub fn reply_page_end() -> Value {
    json!({
        "data": [
            {"id": "c", "answers": {"age": "042", "secret": "never-projected"}}
        ]
    })
}
