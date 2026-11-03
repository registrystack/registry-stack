// SPDX-License-Identifier: Apache-2.0

//! Test-only HTTP source for the maintained Kobo pack. Each response is a
//! captured-sanitized derivative of the controlled KoboToolbox 2.026.37c K4
//! data reads: every provider structural key and scalar type is preserved,
//! while form, submission, person, account, UUID, and time values are replaced.
//! This journey therefore does not replay K4's form, submission, or effect.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};

pub const DATA_PATH: &str = "/api/v2/assets/aCoordinatorFixture0000000000001/data/";
const BASIC_AUTHORIZATION: &str = "Basic Zml4dHVyZS1yZWFkZXI6Zml4dHVyZS1wYXNzd29yZA==";

#[derive(Clone, Debug)]
pub struct SourceRequest {
    pub target: String,
    pub authenticated: bool,
}

#[derive(Clone)]
struct SourceState {
    page: Arc<Mutex<Value>>,
    requests: Arc<Mutex<Vec<SourceRequest>>>,
}

async fn serve(State(state): State<SourceState>, request: Request<Body>) -> Response<Body> {
    let authenticated = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some(BASIC_AUTHORIZATION);
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_default();
    state
        .requests
        .lock()
        .expect("the Kobo request lock")
        .push(SourceRequest {
            target,
            authenticated,
        });
    if !authenticated {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .expect("the unauthorized response builds");
    }
    let body = if request.uri().query().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == "query")
    }) {
        json!({"count": 0, "next": null, "previous": null, "results": []})
    } else {
        state.page.lock().expect("the Kobo page lock").clone()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("the Kobo fixture response renders"),
        ))
        .expect("the Kobo fixture response builds")
}

fn private_file(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write a private Kobo fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("confine a private Kobo fixture file");
}

pub fn initial_page() -> Value {
    json!({
        "count": 1,
        "results": [{
            "_id": 4103,
            "case_ref": "COORD-FIXTURE-4103",
            "respondent_name": "Coordinator Fixture Respondent",
            "household/household_size": "3",
            "meta/instanceID": "uuid:744d9606-73c3-4b3a-960f-df28bc8dd3e2",
            "_xform_id_string": "aCoordinatorFixture0000000000001",
            "_uuid": "744d9606-73c3-4b3a-960f-df28bc8dd3e2",
            "meta/rootUuid": "uuid:744d9606-73c3-4b3a-960f-df28bc8dd3e2",
            "_status": "submitted_via_web",
            "_submission_time": "2026-11-03T00:00:00",
            "_submitted_by": "fixture-reader"
        }]
    })
}

pub fn revised_page() -> Value {
    json!({
        "count": 1,
        "results": [{
            "_id": 4103,
            "case_ref": "COORD-FIXTURE-4103",
            "respondent_name": "Coordinator Fixture Respondent Revised",
            "household/household_size": "3",
            "meta/deprecatedID": "uuid:744d9606-73c3-4b3a-960f-df28bc8dd3e2",
            "meta/rootUuid": "uuid:744d9606-73c3-4b3a-960f-df28bc8dd3e2",
            "_xform_id_string": "aCoordinatorFixture0000000000001",
            "_uuid": "83d64409-3dbd-47fb-a3ba-d2a01ca2adb4",
            "_status": "submitted_via_web",
            "_submission_time": "2026-11-03T00:05:00",
            "_submitted_by": "fixture-reader"
        }]
    })
}

pub struct MaintainedKoboSource {
    pub pack: PathBuf,
    pub job: PathBuf,
    pub runtime: PathBuf,
    pub profile: PathBuf,
    pub project: PathBuf,
    page: Arc<Mutex<Value>>,
    requests: Arc<Mutex<Vec<SourceRequest>>>,
    _root: tempfile::TempDir,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MaintainedKoboSource {
    pub async fn start() -> Self {
        let page = Arc::new(Mutex::new(initial_page()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = SourceState {
            page: Arc::clone(&page),
            requests: Arc::clone(&requests),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the maintained Kobo source fixture");
        let address = listener.local_addr().expect("the Kobo source address");
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(DATA_PATH, any(serve)).with_state(state),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve the maintained Kobo source fixture");
        });

        let root = tempfile::tempdir().expect("a maintained Kobo runtime directory");
        private_file(&root.path().join("kobo-username"), b"fixture-reader");
        private_file(&root.path().join("kobo-password"), b"fixture-password");
        private_file(
            &root.path().join("database"),
            std::env::var("ADAPTER_TEST_DATABASE_URL")
                .expect("the native runner supplies disposable PostgreSQL")
                .as_bytes(),
        );
        private_file(&root.path().join("event-key"), &[0x5a; 32]);
        let runtime = root.path().join("runtime.json");
        let base_url = format!("http://{address}{}", DATA_PATH.trim_end_matches('/'));
        private_file(
            &runtime,
            &serde_json::to_vec_pretty(&json!({
                "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
                "kind": "AdapterJobRuntimeConfig",
                "id": "kobo-coordinator-native",
                "secretProviders": {"file": {"root": root.path()}},
                "endpoints": [{
                    "endpoint": "kobo-api",
                    "baseUrl": base_url,
                    "credential": {
                        "type": "basic",
                        "usernameRef": "secret:file/kobo-username",
                        "passwordRef": "secret:file/kobo-password"
                    }
                }],
                "destinations": {"household-workflow": {
                    "type": "signed-coordinator-event",
                    "baseUrl": "http://127.0.0.1:9/",
                    "signingKeyRef": "secret:file/event-key",
                    "attemptTimeoutMilliseconds": 1000
                }},
                "store": {
                    "runtimeUrlRef": "secret:file/database",
                    "testOnlyPlaintext": true
                }
            }))
            .expect("the maintained Kobo runtime renders"),
        );

        let examples = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/kobotoolbox-job");
        let packs =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/packs/kobotoolbox");
        Self {
            pack: packs.join("pack.yaml"),
            job: examples.join("job.coordinator.yaml"),
            runtime,
            profile: examples.join("profile.yaml"),
            project: examples.join("project.yaml"),
            page,
            requests,
            _root: root,
            _shutdown: shutdown,
        }
    }

    pub fn revise(&self) {
        *self.page.lock().expect("the Kobo page lock") = revised_page();
    }

    pub fn requests(&self) -> Vec<SourceRequest> {
        self.requests.lock().expect("the Kobo request lock").clone()
    }
}
