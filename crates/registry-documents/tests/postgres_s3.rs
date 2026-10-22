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
use support::{pdf, reservation, Api, Deployment, APP, CITIZEN, DATABASE_STORAGE};

const PDF: &str = "application/pdf";

/// What the fake object store and verifier do on the next request.
const NORMAL: usize = 0;
const UNAVAILABLE: usize = 1;
const CORRUPT: usize = 2;
const PUT_FAILS: usize = 3;
const VERSIONED: usize = 4;
const DELETE_FAILS: usize = 5;
const DELETE_KEEPS: usize = 6;
const PUT_STORES_FAILS: usize = 7;
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
    /// The key scope whose deletes fail whatever the mode.
    stuck: std::sync::Mutex<Option<String>>,
}

/// The key scope of `object_id` under the test deployment's database id.
fn scope_of(object_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("registry-documents-test/{object_id}").as_bytes(),
    ))
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
        // The object is stored but the write is answered as failed, so the
        // upload leaves an uncommitted object behind.
        Method::PUT if mode == PUT_STORES_FAILS => {
            state.bytes.lock().await.insert(path, body.to_vec());
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Method::DELETE if mode == DELETE_FAILS => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Method::DELETE
            if state
                .stuck
                .lock()
                .unwrap()
                .as_deref()
                .is_some_and(|scope| path.contains(scope)) =>
        {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        // A delete the store acknowledges without removing anything.
        Method::DELETE if mode == DELETE_KEEPS => StatusCode::NO_CONTENT.into_response(),
        Method::DELETE => {
            state.bytes.lock().await.remove(&path);
            StatusCode::NO_CONTENT.into_response()
        }
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
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, content, PDF)
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
    assert!(
        !key.contains(CITIZEN.subject) && !key.contains(&document),
        "{key}"
    );
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

    api.download(CITIZEN, &document, &version)
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
    assert_eq!(api.download(CITIZEN, &document, &version).await.status, 200);

    fixture.state.mode.store(CORRUPT, Ordering::SeqCst);
    api.download(CITIZEN, &document, &version)
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

/// The download outcomes the journal recorded, in order.
fn download_outcomes(fixture: &Fixture) -> Vec<serde_json::Value> {
    fixture
        .deployment
        .audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["record"]["event"] == "documents.content-download"
                && entry["record"]["outcome"].is_string()
        })
        .map(|entry| entry["record"].clone())
        .collect()
}

#[tokio::test]
async fn an_s3_outage_on_download_is_journaled_unavailable_not_as_an_integrity_failure() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, version) = upload(&api, &pdf(900, 26)).await;
    prepared.verify_due().await;

    fixture.state.mode.store(UNAVAILABLE, Ordering::SeqCst);
    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    let outcomes = download_outcomes(&fixture);
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0]["outcome"], "storage-unavailable");
    assert_eq!(outcomes[0]["byteCount"], 0);
}

#[tokio::test]
async fn an_s3_object_missing_outside_a_removal_is_an_integrity_failure() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, version) = upload(&api, &pdf(900, 27)).await;
    prepared.verify_due().await;

    fixture.state.bytes.lock().await.clear();
    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    let outcomes = download_outcomes(&fixture);
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0]["outcome"], "storage-integrity");
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
    api.download(CITIZEN, &rejected, &rejected_version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);

    fixture.state.verifier_mode.store(9, Ordering::SeqCst);
    let (waiting, waiting_version) = upload(&api, &pdf(300, 25)).await;
    prepared.verify_due().await;
    assert_eq!(
        api.read(APP, &waiting).await.json()["version"]["status"],
        "pending"
    );
    api.download(CITIZEN, &waiting, &waiting_version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
}

#[tokio::test]
async fn a_failed_object_write_keeps_the_staged_row_and_finalizes_nothing() {
    let fixture = Fixture::new().await;
    let (_prepared, api) = fixture.start().await;
    let content = pdf(400, 26);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
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
    assert_eq!(api.download(CITIZEN, &document, &version).await.status, 200);
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

/// Make every erasure due now, and every retry of one due now.
async fn erasure_due(fixture: &Fixture) {
    fixture
        .deployment
        .execute(
            "UPDATE documents_versions
                SET erasure_requested_at = erasure_requested_at - interval '2 days',
                    erasure_due_at = now() - interval '1 second'
              WHERE erasure_state = 'pending';
             UPDATE documents_erasure_jobs SET next_attempt_at = now()
              WHERE state = 'pending'",
        )
        .await;
}

async fn erasure_state(fixture: &Fixture) -> String {
    fixture
        .deployment
        .scalar("SELECT erasure_state FROM documents_versions")
        .await
}

/// SEC-38: an S3 object is erased by a DELETE that a read answering 404
/// confirms, and only then is the version recorded erased.
#[tokio::test]
async fn an_s3_erasure_deletes_the_object_and_confirms_it_gone() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, version) = upload(&api, &pdf(400, 80)).await;
    prepared.verify_due().await;
    assert_eq!(fixture.state.bytes.lock().await.len(), 1);
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    erasure_due(&fixture).await;
    prepared.sweep_due().await;
    assert_eq!(erasure_state(&fixture).await, "erased");
    assert!(fixture.state.bytes.lock().await.is_empty());
    assert_eq!(
        fixture
            .count("SELECT count(*) FROM documents_staged_objects")
            .await,
        0
    );
    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
}

/// A DELETE the store refuses, or one it acknowledges while the object is
/// still readable, leaves the version pending with its staged row; the
/// next attempt erases it.
#[tokio::test]
async fn an_unconfirmed_s3_delete_keeps_the_version_pending() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, _) = upload(&api, &pdf(400, 81)).await;
    prepared.verify_due().await;
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    for mode in [DELETE_FAILS, DELETE_KEEPS] {
        fixture.state.mode.store(mode, Ordering::SeqCst);
        erasure_due(&fixture).await;
        prepared.sweep_due().await;
        assert_eq!(erasure_state(&fixture).await, "pending", "mode {mode}");
        assert_eq!(fixture.state.bytes.lock().await.len(), 1);
        assert_eq!(
            fixture
                .count("SELECT count(*) FROM documents_staged_objects WHERE committed")
                .await,
            1
        );
    }
    fixture.state.mode.store(NORMAL, Ordering::SeqCst);
    erasure_due(&fixture).await;
    prepared.sweep_due().await;
    assert_eq!(erasure_state(&fixture).await, "erased");
    assert!(fixture.state.bytes.lock().await.is_empty());
}

/// Fault injection: an object deleted by an attempt that never recorded
/// it is confirmed gone by the next attempt, which records the erasure
/// once.
#[tokio::test]
async fn an_s3_erasure_interrupted_after_the_delete_resumes_once() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, _) = upload(&api, &pdf(400, 82)).await;
    prepared.verify_due().await;
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    // The object is gone, as after a DELETE whose attempt was interrupted
    // before its recording transaction committed.
    fixture.state.bytes.lock().await.clear();
    erasure_due(&fixture).await;
    prepared.sweep_due().await;
    prepared.sweep_due().await;
    assert_eq!(erasure_state(&fixture).await, "erased");
    let erased = fixture
        .deployment
        .audit_entries()
        .iter()
        .filter(|entry| {
            entry["record"]["event"] == "documents.erasure"
                && entry["record"]["outcome"] == "erased"
        })
        .count();
    assert_eq!(erased, 1);
}

/// An object an unfinished upload left behind is erased by the orphan
/// sweep once it is older than the longest transfer, and its staged row
/// goes with it; a younger one is left for a write still in flight, and a
/// committed one, however old, is left to erasure. A commit racing the
/// sweep is `a_commit_after_the_orphan_sweep_is_refused`.
#[tokio::test]
async fn the_orphan_sweep_erases_only_old_uncommitted_objects() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    upload(&api, &pdf(400, 88)).await;
    fixture
        .deployment
        .execute(
            "UPDATE documents_staged_objects SET staged_at = now() - interval '1 day'
              WHERE committed",
        )
        .await;
    let content = pdf(400, 83);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    fixture.state.mode.store(PUT_STORES_FAILS, Ordering::SeqCst);
    for _ in 0..2 {
        api.put(APP, &path, PDF, Body::from(content.clone()))
            .await
            .assert_problem(ProblemCode::ServiceUnavailable);
    }
    fixture.state.mode.store(NORMAL, Ordering::SeqCst);
    assert_eq!(fixture.state.bytes.lock().await.len(), 3);
    let old: String = fixture
        .deployment
        .scalar(
            "SELECT object_id::text FROM documents_staged_objects
              WHERE NOT committed ORDER BY staged_at LIMIT 1",
        )
        .await;
    fixture
        .deployment
        .execute(&format!(
            "UPDATE documents_staged_objects SET staged_at = now() - interval '1 day'
              WHERE object_id = '{old}'"
        ))
        .await;
    prepared.sweep_due().await;
    let stored = fixture.state.bytes.lock().await;
    assert_eq!(stored.len(), 2);
    assert!(stored.keys().all(|key| !key.contains(&scope_of(&old))));
    drop(stored);
    let left: String = fixture
        .deployment
        .scalar("SELECT object_id::text FROM documents_staged_objects WHERE NOT committed")
        .await;
    assert_ne!(left, old);
    let committed: i64 = fixture
        .deployment
        .scalar(
            "SELECT count(*) FROM documents_staged_objects
              WHERE committed AND staged_at < now() - interval '23 hours'",
        )
        .await;
    assert_eq!(committed, 1);
    let audited = fixture
        .deployment
        .audit_entries()
        .iter()
        .filter(|entry| {
            entry["record"]["event"] == "documents.orphan-erasure"
                && entry["record"]["outcome"] == "erased"
                && entry["record"]["objectId"] == old.as_str()
        })
        .count();
    assert_eq!(audited, 1);
}

/// Two uncommitted objects, both a day old, left by failed writes of one
/// reservation. Returns them oldest first.
async fn two_old_orphans(fixture: &Fixture, api: &Api, seed: u8) -> (String, String) {
    let content = pdf(400, seed);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    fixture.state.mode.store(PUT_STORES_FAILS, Ordering::SeqCst);
    for _ in 0..2 {
        api.put(APP, &path, PDF, Body::from(content.clone()))
            .await
            .assert_problem(ProblemCode::ServiceUnavailable);
    }
    fixture.state.mode.store(NORMAL, Ordering::SeqCst);
    let first: String = fixture
        .deployment
        .scalar(
            "SELECT object_id::text FROM documents_staged_objects
              WHERE NOT committed ORDER BY staged_at LIMIT 1",
        )
        .await;
    let second: String = fixture
        .deployment
        .scalar(&format!(
            "SELECT object_id::text FROM documents_staged_objects
              WHERE NOT committed AND object_id <> '{first}'"
        ))
        .await;
    fixture
        .deployment
        .execute(
            "UPDATE documents_staged_objects SET staged_at = now() - interval '1 day'
              WHERE NOT committed",
        )
        .await;
    (first, second)
}

/// An orphan whose delete keeps failing is skipped for the rest of the
/// pass, so the objects staged after it are still erased, and the pass
/// counts the failure.
#[tokio::test]
async fn an_orphan_whose_delete_fails_does_not_hold_back_the_others() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (stuck, other) = two_old_orphans(&fixture, &api, 87).await;
    *fixture.state.stuck.lock().unwrap() = Some(scope_of(&stuck));
    let pass = prepared.sweep_due().await;
    assert_eq!(pass.erased_orphans, 1);
    assert_eq!(pass.failed_orphans, 1);
    let left: String = fixture
        .deployment
        .scalar("SELECT string_agg(object_id::text, ',') FROM documents_staged_objects")
        .await;
    assert_eq!(left, stuck);
    let stored = fixture.state.bytes.lock().await;
    assert_eq!(stored.len(), 1);
    assert!(stored.keys().all(|key| !key.contains(&scope_of(&other))));
}

/// Fault injection: an orphan whose staged row's deletion does not commit
/// finishes its audit entry as failed before the pass reports the error, and
/// the next pass finds the row again and removes it.
#[tokio::test]
async fn a_failed_orphan_commit_is_audited_as_failed_and_retried() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (first, second) = two_old_orphans(&fixture, &api, 91).await;
    fixture
        .deployment
        .execute(
            "CREATE FUNCTION refuse_unstage() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'the orphan commit failed'; END $$;
             CREATE CONSTRAINT TRIGGER refuse_unstage AFTER DELETE ON documents_staged_objects
                DEFERRABLE INITIALLY DEFERRED
                FOR EACH ROW EXECUTE FUNCTION refuse_unstage();",
        )
        .await;
    assert!(prepared.cleanup_pass().await.is_err());
    let outcomes = fixture
        .deployment
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["event"] == "documents.orphan-erasure")
        .map(|entry| entry["record"]["outcome"].clone())
        .collect::<Vec<_>>();
    assert_eq!(outcomes, [json!(null), json!("failed")]);
    fixture
        .deployment
        .execute("DROP TRIGGER refuse_unstage ON documents_staged_objects")
        .await;
    let pass = prepared.sweep_due().await;
    assert_eq!(pass.erased_orphans, 2);
    let left: i64 = fixture
        .deployment
        .scalar(&format!(
            "SELECT count(*) FROM documents_staged_objects
              WHERE object_id IN ('{first}', '{second}')"
        ))
        .await;
    assert_eq!(left, 0);
    assert!(fixture.state.bytes.lock().await.is_empty());
}

/// A commit that arrives after the orphan sweep erased its object finds no
/// staged row and is refused, so the version stays unfinalized and no
/// object is left that no row names. The commit is held back by a lock on
/// the version row that the staged row's foreign key check does not wait
/// for, so the object is written first.
#[tokio::test]
async fn a_commit_after_the_orphan_sweep_is_refused() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let content = pdf(400, 89);
    let (_, version, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    let (mut holder, connection) =
        tokio_postgres::connect(&support::database_url(), tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { connection.await.expect("the holding connection") });
    let hold = holder.transaction().await.unwrap();
    hold.execute(
        &format!(
            "SELECT 1 FROM {}.documents_versions WHERE version_id = '{version}' FOR NO KEY UPDATE",
            fixture.deployment.schema
        ),
        &[],
    )
    .await
    .unwrap();
    let writer = api.clone();
    let late = tokio::spawn(async move {
        writer
            .put(APP, &path, PDF, Body::from(content.clone()))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while fixture.state.bytes.lock().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the object is written before the commit waits");
    fixture
        .deployment
        .execute("UPDATE documents_staged_objects SET staged_at = now() - interval '1 day'")
        .await;
    let pass = prepared.sweep_due().await;
    assert_eq!(pass.erased_orphans, 1);
    hold.rollback().await.unwrap();
    late.await
        .unwrap()
        .assert_problem(ProblemCode::ServiceUnavailable);
    assert!(fixture.state.bytes.lock().await.is_empty());
    let (staged, state): (i64, String) = (
        fixture
            .count("SELECT count(*) FROM documents_staged_objects")
            .await,
        fixture
            .deployment
            .scalar("SELECT upload_state FROM documents_versions")
            .await,
    );
    assert_eq!(staged, 0);
    assert_eq!(state, "reserved");
}

/// An erasure job that used every attempt dead-letters, and the sweeps
/// after it neither re-arm it nor erase the bytes: the version stays
/// pending until an operator replays the job.
#[tokio::test]
async fn a_dead_lettered_erasure_waits_for_a_replay() {
    let fixture = Fixture::new().await;
    let (prepared, api) = fixture.start().await;
    let (document, _) = upload(&api, &pdf(400, 90)).await;
    prepared.verify_due().await;
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    fixture.state.mode.store(DELETE_FAILS, Ordering::SeqCst);
    erasure_due(&fixture).await;
    prepared.sweep_due().await;
    fixture
        .deployment
        .execute(&format!(
            "UPDATE documents_erasure_jobs
                SET attempt = {}, next_attempt_at = now()",
            registry_documents::erasure::MAXIMUM_ATTEMPTS - 1
        ))
        .await;
    prepared.sweep_due().await;
    let dead: String = fixture
        .deployment
        .scalar("SELECT state FROM documents_erasure_jobs")
        .await;
    assert_eq!(dead, "dead-lettered");
    fixture.state.mode.store(NORMAL, Ordering::SeqCst);
    for _ in 0..2 {
        prepared.sweep_due().await;
    }
    let (jobs, state, generation): (i64, String, i64) = (
        fixture
            .count("SELECT count(*) FROM documents_erasure_jobs")
            .await,
        fixture
            .deployment
            .scalar("SELECT state FROM documents_erasure_jobs")
            .await,
        fixture
            .count("SELECT generation::bigint FROM documents_erasure_jobs")
            .await,
    );
    assert_eq!((jobs, state.as_str(), generation), (1, "dead-lettered", 1));
    assert_eq!(erasure_state(&fixture).await, "pending");
    assert_eq!(fixture.state.bytes.lock().await.len(), 1);
}
