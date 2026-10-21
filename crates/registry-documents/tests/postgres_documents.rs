// SPDX-License-Identifier: Apache-2.0

//! Database-backed document tests over PostgreSQL storage: reservation,
//! content upload, verification on dispatch, and release, with every
//! refusal the upload design names. Callers are synthetic actors; the
//! verifier is a fake that approves, rejects, or does not answer.

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use registry_documents::audit::DocumentsAudit;
use registry_documents::config::RuntimeConfig;
use registry_documents::content::ContentStorage;
use registry_documents::runtime::{prepare_with_verifier, Prepared, RuntimeError};
use registry_documents::store::PostgresStore;
use registry_documents::verification::{
    dispatcher, VerdictSource, VerificationStore, VerificationTransport, MAXIMUM_ATTEMPTS,
};
use registry_documents_core::ProblemCode;
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_dispatch::DispatchError;
use registry_platform_objectstore::{Verdict, VerifierError};
use support::{
    pdf, reservation, sha256, Api, Deployment, FakeVerifier, APPROVE, DATABASE_STORAGE,
    DISABLED_VERIFIER, REJECT, STARTER_PROJECT, UNAVAILABLE,
};

const APP: &str = "custodian-app";
const CITIZEN: &str = "citizen-1";
const PDF: &str = "application/pdf";

async fn deployment() -> Deployment {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    deployment
}

async fn start(deployment: &Deployment, verifier: &Arc<FakeVerifier>) -> (Prepared, Api) {
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    (prepared, api)
}

/// Reserve and upload `content` for the citizen and return the document
/// and version ids.
async fn upload(api: &Api, content: &[u8]) -> (String, String) {
    let reserved = api
        .reserve(APP, "citizen-delivery", CITIZEN, content, PDF)
        .await;
    let (document, version, path) = reservation(&reserved);
    let put = api.put(APP, &path, PDF, Body::from(content.to_vec())).await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    (document, version)
}

fn status(answer: &support::Answer) -> String {
    answer.json()["version"]["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn an_uploaded_document_is_released_only_after_it_is_verified() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(4096, 7);

    let reserved = api
        .reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
        .await;
    let (document, version, path) = reservation(&reserved);
    assert_eq!(
        reserved.json()["document"]["version"]["status"],
        "awaiting-content"
    );
    assert_eq!(
        reserved.headers["location"],
        format!("/documents/{document}")
    );

    let put = api.put(APP, &path, PDF, Body::from(content.clone())).await;
    assert_eq!(put.status, 200);
    assert_eq!(status(&put), "pending");
    assert_eq!(put.json()["version"]["expectedDigest"], sha256(&content));
    assert!(put.json()["version"]["finalizedAt"].is_string());

    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);

    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(status(&api.read(CITIZEN, &document).await), "ready");

    for reader in [APP, CITIZEN] {
        let released = api.download(reader, &document, &version).await;
        assert_eq!(released.status, 200);
        assert_eq!(released.body, content);
        assert_eq!(released.headers["content-type"], PDF);
        assert_eq!(released.headers["content-length"], "4096");
        assert_eq!(released.headers["content-disposition"], "attachment");
        assert_eq!(released.headers["cache-control"], "no-store");
    }

    // A caller that is neither the custodian nor the reserving caller, and
    // a request with no caller, learn nothing.
    api.read("someone-else", &document)
        .await
        .assert_problem(ProblemCode::RequestNotFound);
    api.download("someone-else", &document, &version)
        .await
        .assert_problem(ProblemCode::RequestNotFound);
    let anonymous = api
        .call(
            axum::http::Request::get(format!("/documents/{document}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    anonymous.assert_problem(ProblemCode::RequestNotFound);

    // Provenance is written once, from the actor, never from the body.
    let institution: String = deployment
        .scalar("SELECT issuing_institution FROM documents_versions")
        .await;
    assert_eq!(institution, "civil-registry");
    let pinned: String = deployment
        .scalar("SELECT backend FROM documents_storage_binding")
        .await;
    assert_eq!(pinned, "database");

    let entries = deployment.audit_entries();
    let events = |event: &str| {
        entries
            .iter()
            .filter(|entry| entry["record"]["event"] == event)
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(events("documents.upload-reservation").len(), 2);
    let content_entries = events("documents.upload-content");
    assert_eq!(content_entries.len(), 2);
    assert_eq!(content_entries[1]["record"]["outcome"], "finalized");
    assert_eq!(content_entries[1]["record"]["byteCount"], 4096);
    assert!(!events("documents.content-verification").is_empty());
    let released = events("documents.content-download")
        .into_iter()
        .filter(|entry| entry["record"]["outcome"] == "released")
        .count();
    assert_eq!(released, 2);
    let journal = std::fs::read_to_string(deployment.audit_path()).unwrap();
    assert!(!journal.contains(CITIZEN), "the journal names no caller");
}

#[tokio::test]
async fn content_that_differs_from_the_reserved_digest_or_length_never_finalizes() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(2048, 1);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
            .await,
    );

    api.put(APP, &path, PDF, Body::from(pdf(2048, 2)))
        .await
        .assert_problem(ProblemCode::UploadDigestMismatch);
    api.put(APP, &path, PDF, Body::from(content[..2047].to_vec()))
        .await
        .assert_problem(ProblemCode::UploadLengthMismatch);
    let kept: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(kept, 0);
    let state: String = deployment
        .scalar("SELECT upload_state FROM documents_versions")
        .await;
    assert_eq!(state, "reserved");
    let jobs: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs")
        .await;
    assert_eq!(jobs, 0);

    // The reservation stays open: the right content still finalizes it.
    assert_eq!(
        api.put(APP, &path, PDF, Body::from(content)).await.status,
        200
    );
}

#[tokio::test]
async fn a_body_over_the_reserved_length_is_cut_off_and_keeps_nothing() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(1000, 3);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
            .await,
    );

    // An unbounded body sent one byte at a time is read only to the
    // reserved length plus one byte.
    let pulled = Arc::new(AtomicUsize::new(0));
    let counter = pulled.clone();
    let endless = futures::stream::repeat_with(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(Bytes::from_static(b"x"))
    });
    api.put(APP, &path, PDF, Body::from_stream(endless))
        .await
        .assert_problem(ProblemCode::UploadLengthMismatch);
    assert_eq!(pulled.load(Ordering::SeqCst), 1001);

    // A declared length above the deployment ceiling is refused before any
    // byte is read, and one other than the reserved length too.
    let over = api
        .call(
            axum::http::Request::put(&path)
                .header(support::TEST_SUBJECT_HEADER, APP)
                .header("content-type", PDF)
                .header("content-length", "16777217")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    over.assert_problem(ProblemCode::RequestBodyTooLarge);
    let other = api
        .call(
            axum::http::Request::put(&path)
                .header(support::TEST_SUBJECT_HEADER, APP)
                .header("content-type", PDF)
                .header("content-length", "999")
                .body(Body::from(content[..999].to_vec()))
                .unwrap(),
        )
        .await;
    other.assert_problem(ProblemCode::UploadLengthMismatch);

    let kept: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(kept, 0);
}

#[tokio::test]
async fn a_media_type_outside_the_policy_is_refused_at_reservation_and_at_upload_without_sniffing()
{
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;

    api.reserve(
        APP,
        "citizen-delivery",
        CITIZEN,
        b"plain text",
        "text/plain",
    )
    .await
    .assert_problem(ProblemCode::DocumentContentTypeNotAllowed);
    api.reserve(
        APP,
        "citizen-delivery",
        CITIZEN,
        b"%PDF",
        "application/pdf; charset=binary",
    )
    .await
    .assert_problem(ProblemCode::DocumentContentTypeNotAllowed);

    // PNG bytes declared as a PDF: the declared type is what is checked and
    // recorded; the bytes are never inspected for a type.
    let png = b"\x89PNG\r\n\x1a\nnot-really-an-image".to_vec();
    let (document, version, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &png, PDF)
            .await,
    );
    api.put(APP, &path, "image/png", Body::from(png.clone()))
        .await
        .assert_problem(ProblemCode::UploadContentTypeMismatch);
    let missing = api
        .call(
            axum::http::Request::put(&path)
                .header(support::TEST_SUBJECT_HEADER, APP)
                .body(Body::from(png.clone()))
                .unwrap(),
        )
        .await;
    missing.assert_problem(ProblemCode::UploadContentTypeMismatch);
    assert_eq!(
        api.put(APP, &path, PDF, Body::from(png.clone()))
            .await
            .status,
        200
    );
    prepared.verify_due().await;
    let released = api.download(APP, &document, &version).await;
    assert_eq!(released.status, 200);
    assert_eq!(released.headers["content-type"], PDF);
    assert_eq!(released.body, png);
}

#[tokio::test]
async fn a_document_above_the_policy_size_is_refused_before_any_byte_moves() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let digest = sha256(b"unused");
    api.reserve_declared(APP, "citizen-delivery", CITIZEN, &digest, 16_777_217, PDF)
        .await
        .assert_problem(ProblemCode::DocumentTooLarge);
    api.reserve_declared(APP, "named-share", CITIZEN, &digest, 10_485_761, PDF)
        .await
        .assert_problem(ProblemCode::DocumentTooLarge);
    api.reserve_declared(APP, "no-such-policy", CITIZEN, &digest, 10, PDF)
        .await
        .assert_problem(ProblemCode::DocumentPolicyUnknown);
    let reserved: i64 = deployment
        .scalar("SELECT count(*) FROM documents_versions")
        .await;
    assert_eq!(reserved, 0);
}

#[tokio::test]
async fn stored_content_that_no_longer_matches_its_digest_is_never_released() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, &pdf(512, 9)).await;
    prepared.verify_due().await;
    assert_eq!(api.download(APP, &document, &version).await.status, 200);

    deployment
        .execute("UPDATE documents_contents SET content = overlay(content placing '\\x00'::bytea from 200)")
        .await;
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    let refused = deployment
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["outcome"] == "storage-integrity")
        .collect::<Vec<_>>();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["record"]["byteCount"], 0);
}

#[tokio::test]
async fn the_storage_binding_is_pinned_at_the_first_write() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let pins: i64 = deployment
        .scalar("SELECT count(*) FROM documents_storage_binding")
        .await;
    assert_eq!(pins, 0, "nothing is pinned before the first write");
    upload(&api, &pdf(64, 4)).await;
    let pins: i64 = deployment
        .scalar("SELECT count(*) FROM documents_storage_binding")
        .await;
    assert_eq!(pins, 1);

    // A running deployment whose pin moved finalizes nothing.
    deployment
        .execute(&format!(
            "UPDATE documents_storage_binding SET binding_digest = '{}'",
            "0".repeat(64)
        ))
        .await;
    let content = pdf(64, 5);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
            .await,
    );
    api.put(APP, &path, PDF, Body::from(content))
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);

    // A start whose storage is not the pinned one is refused.
    drop((prepared, api));
    let error = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect_err("startup is refused");
    assert!(
        matches!(error, RuntimeError::StorageBindingChanged),
        "{error}"
    );
    let kept: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(kept, 1);
}

#[tokio::test]
async fn concurrent_uploads_of_one_reservation_finalize_once() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(65_536, 6);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
            .await,
    );

    let attempts = (0..8)
        .map(|_| {
            let api = api.clone();
            let path = path.clone();
            let content = content.clone();
            tokio::spawn(async move { api.put(APP, &path, PDF, Body::from(content)).await })
        })
        .collect::<Vec<_>>();
    let mut views = Vec::new();
    for attempt in attempts {
        let answer = attempt.await.unwrap();
        match answer.status {
            200 => views.push(answer.json()),
            _ => answer.assert_problem(ProblemCode::UploadFinalized),
        }
    }
    assert!(!views.is_empty());
    assert!(views.windows(2).all(|pair| pair[0] == pair[1]));
    let contents: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    let jobs: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs")
        .await;
    assert_eq!((contents, jobs), (1, 1));

    api.put(APP, &path, PDF, Body::from(content))
        .await
        .assert_problem(ProblemCode::UploadFinalized);
}

#[tokio::test]
async fn the_custodian_quota_holds_against_concurrent_reservations() {
    let project = STARTER_PROJECT.replacen(
        "maximumCustodianBytes: 1073741824",
        "maximumCustodianBytes: 16777216",
        1,
    );
    assert_ne!(project, STARTER_PROJECT);
    let deployment = Deployment::with_project(DATABASE_STORAGE, DISABLED_VERIFIER, &project).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let digest = sha256(b"quota");

    let attempts = (0..8)
        .map(|_| {
            let api = api.clone();
            let digest = digest.clone();
            tokio::spawn(async move {
                api.reserve_declared(APP, "citizen-delivery", CITIZEN, &digest, 10_000_000, PDF)
                    .await
            })
        })
        .collect::<Vec<_>>();
    let mut reserved = 0;
    for attempt in attempts {
        let answer = attempt.await.unwrap();
        if answer.status == 201 {
            reserved += 1;
        } else {
            answer.assert_problem(ProblemCode::CustodyQuotaExceeded);
        }
    }
    assert_eq!(reserved, 1);

    // The quota is per custodian: another custodian is not counted.
    assert_eq!(
        api.reserve_declared(
            APP,
            "citizen-delivery",
            "citizen-2",
            &digest,
            10_000_000,
            PDF
        )
        .await
        .status,
        201
    );
    // A reservation that lapsed holds nothing.
    deployment
        .execute(
            "UPDATE documents_versions
                SET reserved_at = reserved_at - interval '2 days',
                    upload_expires_at = now() - interval '1 second'",
        )
        .await;
    assert_eq!(
        api.reserve_declared(APP, "citizen-delivery", CITIZEN, &digest, 10_000_000, PDF)
            .await
            .status,
        201
    );
}

#[tokio::test]
async fn a_rejected_version_is_never_released() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", REJECT);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, &pdf(256, 8)).await;
    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(status(&api.read(APP, &document).await), "rejected");
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
    let job: String = deployment
        .scalar("SELECT state FROM documents_verification_jobs")
        .await;
    assert_eq!(job, "delivered");

    // A later approval under the same binding does not undo a rejection.
    verifier.answer(APPROVE);
    deployment
        .execute(
            "UPDATE documents_verification_jobs
                SET state = 'pending', next_attempt_at = now(), delivered_at = NULL",
        )
        .await;
    prepared.verify_due().await;
    assert_eq!(status(&api.read(APP, &document).await), "rejected");
}

#[tokio::test]
async fn an_unavailable_verifier_never_releases_and_a_dead_letter_neither_approves_nor_rejects() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, &pdf(256, 10)).await;

    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(status(&api.read(APP, &document).await), "pending");
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
    let scheduled: bool = deployment
        .scalar(
            "SELECT state = 'pending' AND attempt = 1 AND next_attempt_at > now()
               FROM documents_verification_jobs",
        )
        .await;
    assert!(scheduled, "the attempt is retried later");

    // The last attempt dead-letters the job; the version stays pending and
    // suspended.
    deployment
        .execute(&format!(
            "UPDATE documents_verification_jobs
                SET attempt = {}, next_attempt_at = now()",
            MAXIMUM_ATTEMPTS - 1
        ))
        .await;
    assert_eq!(prepared.verify_due().await, 1);
    let job: String = deployment
        .scalar("SELECT state FROM documents_verification_jobs")
        .await;
    assert_eq!(job, "dead-lettered");
    let (verification, eligibility): (String, String) = {
        let verification = deployment
            .scalar("SELECT verification_state FROM documents_versions")
            .await;
        let eligibility = deployment
            .scalar("SELECT eligibility FROM documents_versions")
            .await;
        (verification, eligibility)
    };
    assert_eq!(
        (verification.as_str(), eligibility.as_str()),
        ("pending", "suspended")
    );
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
}

#[tokio::test]
async fn a_verifier_binding_change_at_restart_suspends_and_verifies_again() {
    let deployment = deployment().await;
    let first = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &first).await;
    let (ready, ready_version) = upload(&api, &pdf(300, 11)).await;
    prepared.verify_due().await;
    assert_eq!(status(&api.read(APP, &ready).await), "ready");
    // A second version is finalized while its verifier does not answer.
    first.answer(UNAVAILABLE);
    let (waiting, _) = upload(&api, &pdf(300, 12)).await;
    prepared.verify_due().await;
    assert_eq!(status(&api.read(APP, &waiting).await), "pending");
    drop((prepared, api));

    let second = FakeVerifier::new("binding-b", UNAVAILABLE);
    let (restarted, api) = start(&deployment, &second).await;
    assert_eq!(status(&api.read(APP, &ready).await), "suspended");
    api.download(APP, &ready, &ready_version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
    let jobs: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs WHERE state = 'pending'")
        .await;
    assert_eq!(jobs, 2, "one job per version under the new binding");
    let cancelled: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs WHERE state = 'cancelled'")
        .await;
    assert_eq!(
        cancelled, 1,
        "the stale job under the old binding is cancelled"
    );

    // The new binding's verdict is the one recorded.
    deployment
        .execute(
            "UPDATE documents_verification_jobs SET next_attempt_at = now()
              WHERE state = 'pending'",
        )
        .await;
    second.answer(APPROVE);
    restarted.verify_due().await;
    let dead_lettered: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs WHERE state = 'dead-lettered'")
        .await;
    assert_eq!(dead_lettered, 0);
    assert_eq!(status(&api.read(APP, &ready).await), "ready");
    assert_eq!(status(&api.read(APP, &waiting).await), "ready");
    assert_eq!(second.calls.load(Ordering::SeqCst), 2);
    let binding: String = deployment
        .scalar(&format!(
            "SELECT verified_binding_digest FROM documents_versions WHERE version_id = '{ready_version}'"
        ))
        .await;
    assert_eq!(binding, "binding-b");
    assert_eq!(api.download(APP, &ready, &ready_version).await.status, 200);
}

/// SEC-18: while two instances run under different verifier bindings, a
/// job is never dead-lettered only because the worker that claimed it holds
/// the other binding. It stays pending for a worker under the version's own
/// binding, and the stale job a restart supersedes is cancelled.
#[tokio::test]
async fn a_worker_under_another_binding_leaves_the_job_pending_for_its_own() {
    let deployment = deployment().await;
    let old = FakeVerifier::new("binding-a", APPROVE);
    let (old_instance, old_api) = start(&deployment, &old).await;
    let (swept, _) = upload(&old_api, &pdf(300, 31)).await;

    // A second instance starts under a new binding while the first runs,
    // writing its own audit journal.
    let audit = deployment.audit_path();
    let second_runtime = deployment.directory.path().join("runtime-second.yaml");
    std::fs::write(
        &second_runtime,
        std::fs::read_to_string(&deployment.runtime)
            .unwrap()
            .replace(
                &audit.display().to_string(),
                &audit.with_extension("second.ndjson").display().to_string(),
            ),
    )
    .unwrap();
    let new = FakeVerifier::new("binding-b", APPROVE);
    let new_instance = prepare_with_verifier(&second_runtime, new.clone())
        .await
        .expect("the second instance prepares");
    let new_api = Api::new(&new_instance);
    let states: Vec<String> = deployment
        .admin
        .query(
            &format!(
                "SELECT state FROM {}.documents_verification_jobs ORDER BY state",
                deployment.schema
            ),
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(states, ["cancelled", "pending"]);

    // The old instance finalizes a version under its own binding.
    let (late, late_version) = upload(&old_api, &pdf(300, 32)).await;
    let due = "UPDATE documents_verification_jobs SET next_attempt_at = now()
                WHERE state = 'pending'";

    // The new instance claims both jobs; only the one under its binding is
    // verified, and the other is retried rather than dead-lettered.
    deployment.execute(due).await;
    new_instance.verify_due().await;
    assert_eq!(new.calls.load(Ordering::SeqCst), 1);
    assert_eq!(status(&new_api.read(APP, &swept).await), "ready");
    assert_eq!(status(&new_api.read(APP, &late).await), "pending");
    let late_job: String = deployment
        .scalar(&format!(
            "SELECT state FROM documents_verification_jobs WHERE version_id = '{late_version}'"
        ))
        .await;
    assert_eq!(late_job, "pending");
    let dead_lettered: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs WHERE state = 'dead-lettered'")
        .await;
    assert_eq!(dead_lettered, 0);

    // A worker under the version's own binding verifies it.
    deployment.execute(due).await;
    old_instance.verify_due().await;
    assert_eq!(old.calls.load(Ordering::SeqCst), 1);
    assert_eq!(status(&old_api.read(APP, &late).await), "ready");
}

/// A verifier that approves, and while it answers changes the version's
/// recorded media type once, as a concurrent writer would.
struct TamperingVerifier {
    client: tokio_postgres::Client,
    schema: String,
    tampered: AtomicBool,
}

#[async_trait::async_trait]
impl VerdictSource for TamperingVerifier {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }

    async fn verdict(&self, _: &str, _: &str, _: Vec<u8>) -> Result<Verdict, VerifierError> {
        if !self.tampered.swap(true, Ordering::SeqCst) {
            self.client
                .batch_execute(&format!(
                    "UPDATE {}.documents_versions SET media_type = 'image/png'",
                    self.schema
                ))
                .await
                .expect("the version is changed under the verifier");
        }
        Ok(Verdict::Approved)
    }
}

/// A verdict that records nothing while the version is still under the
/// verifier's binding is not taken as delivered: the attempt is not
/// committed, and the job is retried once its lease lapses.
#[tokio::test]
async fn a_verdict_that_records_nothing_under_the_current_binding_is_retried() {
    let deployment = deployment().await;
    let (client, connection) =
        tokio_postgres::connect(&support::database_url(), tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { connection.await.expect("the tampering connection") });
    let verifier = Arc::new(TamperingVerifier {
        client,
        schema: deployment.schema.clone(),
        tampered: AtomicBool::new(false),
    });
    let prepared = prepare_with_verifier(&deployment.runtime, verifier)
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    let (document, _) = upload(&api, &pdf(300, 33)).await;

    prepared.verify_due().await;
    let job: String = deployment
        .scalar("SELECT state FROM documents_verification_jobs")
        .await;
    assert_eq!(job, "leased", "the attempt is not committed");
    assert_eq!(status(&api.read(APP, &document).await), "pending");

    // Once the version matches again and the lease lapses, the job is
    // verified.
    deployment
        .execute(
            "UPDATE documents_versions SET media_type = 'application/pdf';
             UPDATE documents_verification_jobs
                SET attempt_started_at = now() - interval '2 hours',
                    lease_expires_at = now() - interval '1 hour'",
        )
        .await;
    prepared.verify_due().await;
    deployment
        .execute(
            "UPDATE documents_verification_jobs SET next_attempt_at = now()
              WHERE state = 'pending'",
        )
        .await;
    prepared.verify_due().await;
    assert_eq!(status(&api.read(APP, &document).await), "ready");
}

/// An audit sink that refuses every line.
struct FailingSink;

impl std::io::Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("the audit sink refuses"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("the audit sink refuses"))
    }
}

/// SEC-10: a verification attempt whose audit entry cannot be written is
/// refused before the verifier is asked, and records no verdict.
#[tokio::test]
async fn a_verification_audit_failure_refuses_the_claim_and_records_no_verdict() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let (document, _) = upload(&api, &pdf(300, 34)).await;

    let config = RuntimeConfig::load(&deployment.runtime).unwrap();
    let secrets = Arc::new(config.secret_resolver().unwrap());
    let store = PostgresStore::connect_runtime(&config.database, &secrets).unwrap();
    let audit = DocumentsAudit::new(
        AuditWriter::from_line_sink(Box::new(FailingSink)),
        AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"documents-test-audit-key-not-a-secret".to_vec(),
        ))
        .unwrap()
        .key_hasher(),
    );
    let storage = Arc::new(
        ContentStorage::activate(&config.storage, "registry-documents-test", secrets)
            .await
            .unwrap(),
    );
    let failing = dispatcher(VerificationStore::new(
        store.clone(),
        deployment.schema.clone(),
        audit,
    ))
    .unwrap();
    let transport = VerificationTransport::new(store, storage, verifier.clone());

    let outcome = failing.dispatch_once(&transport).await;
    assert!(
        matches!(outcome, Err(DispatchError::Unavailable)),
        "{outcome:?}"
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    assert_eq!(status(&api.read(APP, &document).await), "pending");
    let verdicts: i64 = deployment
        .scalar("SELECT count(*) FROM documents_versions WHERE verified_at IS NOT NULL")
        .await;
    assert_eq!(verdicts, 0);
    let job: String = deployment
        .scalar("SELECT state || ':' || attempt FROM documents_verification_jobs")
        .await;
    assert_eq!(job, "pending:0", "the claim is not committed");
}

#[tokio::test]
async fn identical_content_uploaded_twice_gives_two_documents() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(128, 13);
    let (first, _) = upload(&api, &content).await;
    let (second, _) = upload(&api, &content).await;
    assert_ne!(first, second);
    let contents: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(contents, 2);
}

#[tokio::test]
async fn an_expired_or_unknown_upload_is_refused() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(128, 14);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN, &content, PDF)
            .await,
    );
    api.put("someone-else", &path, PDF, Body::from(content.clone()))
        .await
        .assert_problem(ProblemCode::RequestNotFound);
    api.put(
        APP,
        "/uploads/00000000-0000-4000-8000-000000000000/content",
        PDF,
        Body::from(content.clone()),
    )
    .await
    .assert_problem(ProblemCode::RequestNotFound);
    deployment
        .execute(
            "UPDATE documents_versions
                SET reserved_at = reserved_at - interval '2 days',
                    upload_expires_at = now() - interval '1 second'",
        )
        .await;
    api.put(APP, &path, PDF, Body::from(content))
        .await
        .assert_problem(ProblemCode::UploadExpired);
}
