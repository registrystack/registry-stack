// SPDX-License-Identifier: Apache-2.0

//! The S3 storage branch against a loopback fake object store and a
//! loopback HTTP verifier: content goes to one fresh object per upload
//! attempt behind a staged row, is verified over the real verifier
//! transport, and is released only when the object still matches its
//! digest.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use registry_documents::content::StorageError;
use registry_documents::runtime::{prepare, Prepared, RuntimeError};
use registry_documents_core::ProblemCode;
use registry_platform_objectstore::ObjectStoreError;
use serde_json::json;
use support::{pdf, reservation, Api, Deployment, DATABASE_STORAGE};

const APP: &str = "custodian-app";
const CITIZEN: &str = "citizen-1";
const PDF: &str = "application/pdf";

/// What the fake object store and verifier do on the next request.
const NORMAL: usize = 0;
const UNAVAILABLE: usize = 1;
const CORRUPT: usize = 2;
const PUT_FAILS: usize = 3;
const VERSIONED: usize = 4;
const APPROVE: usize = 0;
const REJECT: usize = 1;

#[derive(Default)]
struct Objects {
    bytes: tokio::sync::Mutex<BTreeMap<String, Vec<u8>>>,
    puts: AtomicUsize,
    probes: AtomicUsize,
    mode: AtomicUsize,
    verifier_mode: AtomicUsize,
    verified: tokio::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

async fn object_request(
    State(state): State<Arc<Objects>>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if uri.path() == "/verify" {
        use sha2::{Digest, Sha256};
        assert_eq!(method, Method::POST);
        assert_eq!(headers["authorization"], "Bearer synthetic-verifier");
        assert_eq!(
            headers["x-content-sha256"].to_str().unwrap(),
            hex::encode(Sha256::digest(&body))
        );
        let content_type = headers["content-type"].to_str().unwrap().to_owned();
        state
            .verified
            .lock()
            .await
            .push((content_type, body.to_vec()));
        return match state.verifier_mode.load(Ordering::SeqCst) {
            REJECT => axum::Json(json!({"verdict": "rejected"})).into_response(),
            APPROVE => axum::Json(json!({"verdict": "approved"})).into_response(),
            _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
    }
    let mode = state.mode.load(Ordering::SeqCst);
    if mode == UNAVAILABLE {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if uri.query().is_some() {
        state.probes.fetch_add(1, Ordering::SeqCst);
        if mode == VERSIONED {
            return (
                StatusCode::OK,
                "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            )
                .into_response();
        }
        return (
            StatusCode::OK,
            "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
        )
            .into_response();
    }
    let path = uri.path().to_owned();
    match method {
        Method::PUT if mode == PUT_FAILS => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Method::PUT => {
            state.puts.fetch_add(1, Ordering::SeqCst);
            state.bytes.lock().await.insert(path, body.to_vec());
            StatusCode::OK.into_response()
        }
        Method::GET => match state.bytes.lock().await.get(&path).cloned() {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(mut bytes) => {
                if mode == CORRUPT && !bytes.is_empty() {
                    bytes[0] ^= 1;
                }
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(bytes))
                    .unwrap()
            }
        },
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

struct Fixture {
    state: Arc<Objects>,
    deployment: Deployment,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let state = Arc::new(Objects::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(object_request)
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let storage = format!(
            "storage:\n  type: s3\n  url: {endpoint}\n  bucket: synthetic-documents\n  region: us-east-1\n  accessKeyIdRef: secret:file/s3-access\n  secretAccessKeyRef: secret:file/s3-key\n"
        );
        let verifier = format!(
            "contentVerification:\n  type: http\n  url: {endpoint}/verify\n  authorizationRef: secret:file/verifier\n  policyId: synthetic-policy\n  attemptTimeoutMilliseconds: 2000\n"
        );
        let mut deployment = Deployment::new(&storage, &verifier).await;
        deployment.secret("s3-access", "synthetic-access");
        deployment.secret("s3-key", "synthetic-test-secret");
        deployment.secret("verifier", "synthetic-verifier");
        deployment.migrate().await;
        Self {
            state,
            deployment,
            server,
        }
    }

    async fn start(&self) -> (Prepared, Api) {
        let prepared = prepare(&self.deployment.runtime)
            .await
            .expect("the runtime prepares over S3");
        let api = Api::new(&prepared);
        (prepared, api)
    }

    async fn count(&self, sql: &str) -> i64 {
        self.deployment.scalar(sql).await
    }
}

async fn upload(api: &Api, content: &[u8]) -> (String, String) {
    let (document, version, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, content, PDF)
            .await,
    );
    let put = api.put(APP, &path, PDF, Body::from(content.to_vec())).await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    (document, version)
}

#[tokio::test]
async fn s3_content_is_staged_verified_over_http_and_released() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let content = pdf(5000, 21);
    let (document, version) = upload(&api, &content).await;

    assert_eq!(fixture.state.puts.load(Ordering::SeqCst), 1);
    let objects = fixture.state.bytes.lock().await.clone();
    assert_eq!(objects.len(), 1);
    let (key, stored) = objects.iter().next().unwrap();
    assert_eq!(stored, &content);
    assert!(key.starts_with("/synthetic-documents/"), "{key}");
    assert!(!key.contains(CITIZEN) && !key.contains(&document), "{key}");
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM documents_staged_objects WHERE committed")
            .await,
        1
    );
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM documents_contents")
            .await,
        0
    );
    let pinned: String = fixture
        .deployment
        .scalar("SELECT backend FROM documents_storage_binding")
        .await;
    assert_eq!(pinned, "s3");

    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
    assert_eq!(prepared.verify_due().await, 1);
    let verified = fixture.state.verified.lock().await.clone();
    assert_eq!(verified, vec![(PDF.to_owned(), content.clone())]);

    let released = api.download(CITIZEN, &document, &version).await;
    assert_eq!(released.status, 200);
    assert_eq!(released.body, content);
    assert_eq!(released.headers["content-type"], PDF);
}

#[tokio::test]
async fn identical_s3_uploads_are_two_objects() {
    let fixture = Fixture::new().await;
    let (_prepared, api) = fixture.start().await;
    let content = pdf(700, 22);
    upload(&api, &content).await;
    upload(&api, &content).await;
    assert_eq!(fixture.state.bytes.lock().await.len(), 2);
    assert_eq!(
        fixture
            .count("SELECT count(DISTINCT object_id) FROM documents_versions")
            .await,
        2
    );
}

#[tokio::test]
async fn an_s3_object_that_no_longer_matches_is_never_released() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, version) = upload(&api, &pdf(900, 23)).await;
    prepared.verify_due().await;
    assert_eq!(api.download(APP, &document, &version).await.status, 200);

    fixture.state.mode.store(CORRUPT, Ordering::SeqCst);
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    let refused = fixture
        .deployment
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["outcome"] == "storage-integrity")
        .count();
    assert_eq!(refused, 1);
}

#[tokio::test]
async fn an_http_verifier_rejection_or_outage_never_releases() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;

    fixture.state.verifier_mode.store(REJECT, Ordering::SeqCst);
    let (rejected, rejected_version) = upload(&api, &pdf(300, 24)).await;
    prepared.verify_due().await;
    assert_eq!(
        api.read(APP, &rejected).await.json()["version"]["status"],
        "rejected"
    );
    api.download(APP, &rejected, &rejected_version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);

    fixture.state.verifier_mode.store(9, Ordering::SeqCst);
    let (waiting, waiting_version) = upload(&api, &pdf(300, 25)).await;
    prepared.verify_due().await;
    assert_eq!(
        api.read(APP, &waiting).await.json()["version"]["status"],
        "pending"
    );
    api.download(APP, &waiting, &waiting_version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
}

#[tokio::test]
async fn a_failed_object_write_keeps_the_staged_row_and_finalizes_nothing() {
    let fixture = Fixture::new().await;
    let (_prepared, api) = fixture.start().await;
    let content = pdf(400, 26);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
            .await,
    );
    // An object store that does not answer at all, and one that refuses
    // the write, each leave the attempt's staged row findable for the sweep.
    for (mode, staged) in [(UNAVAILABLE, 1), (PUT_FAILS, 2)] {
        fixture.state.mode.store(mode, Ordering::SeqCst);
        api.put(APP, &path, PDF, Body::from(content.clone()))
            .await
            .assert_problem(ProblemCode::ServiceUnavailable);
        assert_eq!(
            fixture
                .count("SELECT count(*) FROM documents_staged_objects WHERE NOT committed")
                .await,
            staged,
            "the attempt stays findable for the sweep"
        );
    }
    let state: String = fixture
        .deployment
        .scalar("SELECT upload_state FROM documents_versions")
        .await;
    assert_eq!(state, "reserved");

    // A retry writes a fresh object and finalizes.
    fixture.state.mode.store(NORMAL, Ordering::SeqCst);
    assert_eq!(
        api.put(APP, &path, PDF, Body::from(content)).await.status,
        200
    );
    assert_eq!(
        fixture
            .count("SELECT count(DISTINCT object_id) FROM documents_staged_objects")
            .await,
        3
    );
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM documents_staged_objects WHERE committed")
            .await,
        1
    );
}

#[tokio::test]
async fn switching_storage_after_the_first_s3_write_is_refused_at_startup() {
    let mut fixture = Fixture::new().await;
    {
        let (_prepared, api) = fixture.start().await;
        upload(&api, &pdf(128, 27)).await;
    }
    let verifier = "contentVerification:\n  type: disabled\n";
    fixture.deployment.reconfigure(DATABASE_STORAGE, verifier);
    let error = prepare(&fixture.deployment.runtime)
        .await
        .expect_err("startup is refused");
    assert!(
        matches!(error, RuntimeError::StorageBindingChanged),
        "{error}"
    );
}

/// S3 storage is activated once, at startup: an upload probes bucket
/// versioning only through the write's own check, and verification and
/// release read without probing or activating again.
#[tokio::test]
async fn s3_storage_is_activated_once_at_startup() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let probes = || fixture.state.probes.load(Ordering::SeqCst);
    assert_eq!(probes(), 1, "startup probes the bucket once");

    let (document, version) = upload(&api, &pdf(600, 28)).await;
    assert_eq!(probes(), 2, "the write probes once before it writes");
    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(api.download(APP, &document, &version).await.status, 200);
    assert_eq!(probes(), 2, "verification and release never probe");
}

/// A bucket that has ever enabled versioning is refused before anything is
/// served, so no upload can reach it.
#[tokio::test]
async fn a_versioned_bucket_is_refused_at_startup() {
    let fixture = Fixture::new().await;
    fixture.state.mode.store(VERSIONED, Ordering::SeqCst);
    let error = prepare(&fixture.deployment.runtime)
        .await
        .expect_err("startup is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Storage(StorageError::Object(ObjectStoreError::VersionedBucket))
        ),
        "{error}"
    );
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM documents_storage_binding")
            .await,
        0
    );
}
