// SPDX-License-Identifier: Apache-2.0

//! Database-backed document tests over PostgreSQL storage: reservation,
//! content upload, verification on dispatch, and release, with every
//! refusal the upload design names. Callers present real access tokens
//! from a test issuer; the verifier is a fake that approves, rejects, or
//! does not answer.

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use futures::StreamExt as _;
use registry_documents::audit::DocumentsAudit;
use registry_documents::config::RuntimeConfig;
use registry_documents::content::ContentStorage;
use registry_documents::runtime::{prepare_with_verifier, Prepared, RuntimeError};
use registry_documents::store::PostgresStore;
use registry_documents::transfer::TransferBudget;
use registry_documents::verification::{
    dispatcher, VerdictSource, VerificationStore, VerificationTransport, MAXIMUM_ATTEMPTS,
};
use registry_documents_core::ProblemCode;
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_dispatch::DispatchError;
use registry_platform_objectstore::{Verdict, VerifierError};
use serde_json::json;
use support::{
    access_project, pdf, reservation, reservation_body, sha256, Api, Deployment, FakeVerifier, APP,
    APPROVE, CITIZEN, CITIZEN_AS_READER, DATABASE_STORAGE, DISABLED_VERIFIER, OTHER_APP,
    OTHER_CITIZEN, PARTNER_SERVICE, READER, REJECT, STAFF, STARTER_PROJECT, STRANGER, UNAVAILABLE,
};
use uuid::Uuid;

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
        .reserve(APP, "citizen-delivery", CITIZEN.subject, content, PDF)
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
        .reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
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

    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);

    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(status(&api.read(CITIZEN, &document).await), "ready");

    let released = api.download(CITIZEN, &document, &version).await;
    assert_eq!(released.status, 200);
    assert_eq!(released.body, content);
    assert_eq!(released.headers["content-type"], PDF);
    assert_eq!(released.headers["content-length"], "4096");
    assert_eq!(released.headers["content-disposition"], "attachment");
    assert_eq!(released.headers["cache-control"], "no-store");

    // The reserving system sees the metadata it placed, never the content:
    // custody went to the citizen. It is refused as unauthorized, since it
    // already knows the document exists.
    let placed = api.read(APP, &document).await;
    assert_eq!(placed.status, 200);
    assert_eq!(
        placed.json()["actions"],
        serde_json::json!(["share", "revoke-share", "list-shares"])
    );
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::ProfileNotAuthorized);

    // A caller that is neither the custodian nor the reserving caller learns
    // nothing, and a request with no credential is refused before anything
    // is looked up.
    api.read(STRANGER, &document)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.download(STRANGER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    let anonymous = api
        .call(
            axum::http::Request::get(format!("/documents/{document}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    anonymous.assert_problem(ProblemCode::AuthenticationRefused);

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
    assert_eq!(released, 1);
    let journal = std::fs::read_to_string(deployment.audit_path()).unwrap();
    assert!(
        !journal.contains(CITIZEN.subject),
        "the journal names no caller"
    );
}

#[tokio::test]
async fn content_that_differs_from_the_reserved_digest_or_length_never_finalizes() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(2048, 1);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
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
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
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
            support::request(APP, axum::http::Method::PUT, &path)
                .header("content-type", PDF)
                .header("content-length", "16777217")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    over.assert_problem(ProblemCode::RequestBodyTooLarge);
    let other = api
        .call(
            support::request(APP, axum::http::Method::PUT, &path)
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
        CITIZEN.subject,
        b"plain text",
        "text/plain",
    )
    .await
    .assert_problem(ProblemCode::DocumentContentTypeNotAllowed);
    api.reserve(
        APP,
        "citizen-delivery",
        CITIZEN.subject,
        b"%PDF",
        "application/pdf; charset=binary",
    )
    .await
    .assert_problem(ProblemCode::DocumentContentTypeNotAllowed);

    // PNG bytes declared as a PDF: the declared type is what is checked and
    // recorded; the bytes are never inspected for a type.
    let png = b"\x89PNG\r\n\x1a\nnot-really-an-image".to_vec();
    let (document, version, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &png, PDF)
            .await,
    );
    api.put(APP, &path, "image/png", Body::from(png.clone()))
        .await
        .assert_problem(ProblemCode::UploadContentTypeMismatch);
    let missing = api
        .call(
            support::request(APP, axum::http::Method::PUT, &path)
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
    let released = api.download(CITIZEN, &document, &version).await;
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
    api.reserve_declared(
        APP,
        "citizen-delivery",
        CITIZEN.subject,
        &digest,
        16_777_217,
        PDF,
    )
    .await
    .assert_problem(ProblemCode::DocumentTooLarge);
    api.reserve_declared(
        APP,
        "named-share",
        CITIZEN.subject,
        &digest,
        10_485_761,
        PDF,
    )
    .await
    .assert_problem(ProblemCode::DocumentTooLarge);
    api.reserve_declared(APP, "no-such-policy", CITIZEN.subject, &digest, 10, PDF)
        .await
        .assert_problem(ProblemCode::DocumentPolicyUnknown);
    api.reserve_declared(APP, "citizen-delivery", CITIZEN.subject, &digest, 0, PDF)
        .await
        .assert_problem(ProblemCode::RequestUnprocessable);
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
    assert_eq!(api.download(CITIZEN, &document, &version).await.status, 200);

    deployment
        .execute("UPDATE documents_contents SET content = overlay(content placing '\\x00'::bytea from 200)")
        .await;
    api.download(CITIZEN, &document, &version)
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
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
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
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
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
    // Every attempt that carries the reserved content succeeds: the losers
    // of the finalize race are answered with the finalized view.
    let mut views = Vec::new();
    for attempt in attempts {
        let answer = attempt.await.unwrap();
        assert_eq!(
            answer.status,
            200,
            "{}",
            String::from_utf8_lossy(&answer.body)
        );
        views.push(answer.json());
    }
    assert_eq!(views.len(), 8);
    assert!(views.windows(2).all(|pair| pair[0] == pair[1]));
    let contents: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    let jobs: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs")
        .await;
    assert_eq!((contents, jobs), (1, 1));
}

/// A client that lost the answer to a finished upload may send it again:
/// the same bytes are answered with the finalized view, and other bytes of
/// the same length are refused without touching what was stored.
#[tokio::test]
async fn a_retry_after_finalize_with_the_same_content_is_answered_and_other_content_is_refused() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(2048, 9);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    let first = api.put(APP, &path, PDF, Body::from(content.clone())).await;
    assert_eq!(first.status, 200);

    let retry = api.put(APP, &path, PDF, Body::from(content.clone())).await;
    assert_eq!(retry.status, 200);
    assert_eq!(retry.json(), first.json());

    api.put(APP, &path, PDF, Body::from(pdf(2048, 10)))
        .await
        .assert_problem(ProblemCode::UploadFinalized);
    let stored: Vec<u8> = deployment
        .scalar("SELECT content FROM documents_contents")
        .await;
    assert_eq!(stored, content);
    let jobs: i64 = deployment
        .scalar("SELECT count(*) FROM documents_verification_jobs")
        .await;
    assert_eq!(jobs, 1);
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
                api.reserve_declared(
                    APP,
                    "citizen-delivery",
                    CITIZEN.subject,
                    &digest,
                    10_000_000,
                    PDF,
                )
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
        api.reserve_declared(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            &digest,
            10_000_000,
            PDF
        )
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
    api.download(CITIZEN, &document, &version)
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
    api.download(CITIZEN, &document, &version)
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
    api.download(CITIZEN, &document, &version)
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
    api.download(CITIZEN, &ready, &ready_version)
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
    assert_eq!(
        api.download(CITIZEN, &ready, &ready_version).await.status,
        200
    );
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

/// A verification attempt whose audit entry cannot be written is
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
    let transport = VerificationTransport::new(
        store,
        storage,
        verifier.clone(),
        TransferBudget::new(16_777_216),
    );

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

/// SEC-17 and SEC-18: the database refuses a releasable version whose
/// verdict is not bound to its digest, its media type, and the verifier
/// binding it is currently recorded under, whichever writer tries it.
#[tokio::test]
async fn the_database_refuses_a_releasable_version_under_a_stale_or_mismatched_verdict() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, &pdf(300, 35)).await;
    prepared.verify_due().await;
    assert_eq!(status(&api.read(APP, &document).await), "ready");

    for change in [
        "verification_binding_digest = 'binding-b'",
        "verified_digest = 'sha256:' || repeat('0', 64)",
        "verified_media_type = 'image/png'",
    ] {
        let error = deployment
            .admin
            .batch_execute(&format!(
                "UPDATE {}.documents_versions SET {change} WHERE version_id = '{version}'",
                deployment.schema
            ))
            .await
            .expect_err(change);
        let constraint = error
            .as_db_error()
            .and_then(|error| error.constraint())
            .map(str::to_owned);
        assert_eq!(
            constraint.as_deref(),
            Some("documents_versions_release_shape"),
            "{change}: {error}"
        );
    }
    assert_eq!(api.download(CITIZEN, &document, &version).await.status, 200);
}

#[tokio::test]
async fn the_database_refuses_a_releasable_version_with_a_null_verdict_column() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, &pdf(300, 36)).await;
    prepared.verify_due().await;
    assert_eq!(status(&api.read(APP, &document).await), "ready");

    // Each write runs in its own rolled-back transaction, so every variant is
    // tried against the same releasable row.
    let mut accepted = Vec::new();
    for column in [
        "verified_binding_digest",
        "verified_digest",
        "verified_media_type",
    ] {
        let outcome = deployment
            .admin
            .batch_execute(&format!(
                "BEGIN; UPDATE {}.documents_versions SET {column} = NULL \
                 WHERE version_id = '{version}'; ROLLBACK",
                deployment.schema
            ))
            .await;
        match outcome {
            Ok(()) => accepted.push(column),
            Err(error) => {
                deployment
                    .admin
                    .batch_execute("ROLLBACK")
                    .await
                    .expect("rolls back the refused write");
                let constraint = error
                    .as_db_error()
                    .and_then(|error| error.constraint())
                    .map(str::to_owned);
                assert_eq!(
                    constraint.as_deref(),
                    Some("documents_versions_release_shape"),
                    "{column}: {error}"
                );
            }
        }
    }
    assert!(accepted.is_empty(), "accepted NULL in {accepted:?}");
    assert_eq!(api.download(CITIZEN, &document, &version).await.status, 200);
}

#[tokio::test]
async fn the_database_refuses_a_finalized_version_without_a_computed_digest() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let (_, version) = upload(&api, &pdf(300, 37)).await;

    let error = deployment
        .admin
        .batch_execute(&format!(
            "UPDATE {}.documents_versions SET computed_digest = NULL WHERE version_id = '{version}'",
            deployment.schema
        ))
        .await
        .expect_err("a finalized version without a computed digest");
    let constraint = error
        .as_db_error()
        .and_then(|error| error.constraint())
        .map(str::to_owned);
    assert_eq!(
        constraint.as_deref(),
        Some("documents_versions_finalized_shape"),
        "{error}"
    );
}

/// A grant names one version of the document it is on: the database
/// refuses a grant whose version belongs to another document, and a grant
/// whose grantee kind is outside the closed vocabulary.
#[tokio::test]
async fn the_database_refuses_a_grant_on_another_document_s_version_or_of_an_unknown_kind() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(300, 64)).await;
    let (_, other_version) = ready(&prepared, &api, &pdf(300, 65)).await;

    let insert = |version: &str, kind: &str| {
        format!(
            "INSERT INTO {}.documents_grants
                 (grant_id, document_id, version_id, grantee_issuer, grantee_subject,
                  grantee_kind, granted_by_issuer, granted_by_subject, granted_by_profile,
                  issued_at, expires_at)
             VALUES ('{}', '{document}', '{version}', 'https://issuer.example.test',
                     'reader-1', '{kind}', 'https://issuer.example.test', 'custodian-app',
                     'custodian-app', now(), now() + interval '1 hour')",
            deployment.schema,
            Uuid::new_v4()
        )
    };
    let error = deployment
        .admin
        .batch_execute(&insert(&other_version, "human"))
        .await
        .expect_err("a grant on another document's version");
    let constraint = error
        .as_db_error()
        .and_then(|error| error.constraint())
        .map(str::to_owned);
    assert_eq!(
        constraint.as_deref(),
        Some("documents_grants_document_version"),
        "{error}"
    );
    let error = deployment
        .admin
        .batch_execute(&insert(&version, "organization"))
        .await
        .expect_err("a grant of an unknown grantee kind");
    assert!(
        error
            .as_db_error()
            .and_then(|error| error.constraint())
            .is_some_and(|name| name.starts_with("documents_grants_grantee_kind")),
        "{error}"
    );
    deployment
        .admin
        .batch_execute(&insert(&version, "service"))
        .await
        .expect("a grant on the document's own version");
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
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    api.put(STRANGER, &path, PDF, Body::from(content.clone()))
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.put(
        APP,
        "/uploads/00000000-0000-4000-8000-000000000000/content",
        PDF,
        Body::from(content.clone()),
    )
    .await
    .assert_problem(ProblemCode::ResourceNotFound);
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

/// Upload `content` for the citizen and let the verifier approve it.
async fn ready(prepared: &Prepared, api: &Api, content: &[u8]) -> (String, String) {
    let (document, version) = upload(api, content).await;
    assert_eq!(prepared.verify_due().await, 1);
    (document, version)
}

fn grant_id(answer: &support::Answer) -> String {
    assert_eq!(
        answer.status,
        201,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    answer.json()["id"].as_str().unwrap().to_owned()
}

/// DD18: a human places a document only in its own custody, and only a
/// profile the policy lists as a custody profile places one at all.
#[tokio::test]
async fn custody_is_placed_only_by_a_custody_profile_and_a_human_only_into_its_own() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(512, 40);

    // The citizen is a custody profile under named-share, for itself only.
    api.reserve(CITIZEN, "named-share", OTHER_CITIZEN.subject, &content, PDF)
        .await
        .assert_problem(ProblemCode::CustodyNotPermitted);
    let own = api
        .reserve(CITIZEN, "named-share", CITIZEN.subject, &content, PDF)
        .await;
    assert_eq!(own.status, 201, "{}", String::from_utf8_lossy(&own.body));

    // Under citizen-delivery only the owning system places custody.
    api.reserve(CITIZEN, "citizen-delivery", CITIZEN.subject, &content, PDF)
        .await
        .assert_problem(ProblemCode::CustodyNotPermitted);
    api.reserve(READER, "citizen-delivery", READER.subject, &content, PDF)
        .await
        .assert_problem(ProblemCode::CustodyNotPermitted);

    let reserved: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents")
        .await;
    assert_eq!(reserved, 1);
}

/// A deployment of [`access_project`], migrated.
async fn access_deployment() -> Deployment {
    let deployment =
        Deployment::with_project(DATABASE_STORAGE, DISABLED_VERIFIER, &access_project()).await;
    deployment.migrate().await;
    deployment
}

/// Reserve `content` as the owning system under `policy` for `named`,
/// upload it, and let the verifier approve it.
async fn ready_under(
    prepared: &Prepared,
    api: &Api,
    policy: &str,
    named: &str,
    content: &[u8],
) -> (String, String) {
    let reserved = api.reserve(APP, policy, named, content, PDF).await;
    let (document, version, path) = reservation(&reserved);
    let put = api.put(APP, &path, PDF, Body::from(content.to_vec())).await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    assert_eq!(prepared.verify_due().await, 1);
    (document, version)
}

/// Under `institutional-custody` custody stays with the reserving system
/// for its institution: the person a document names is recorded as the
/// represented principal and has no standing on it. Only a grant releases
/// it to them. Under `citizen-delivery` that person is the custodian.
#[tokio::test]
async fn under_institutional_custody_the_named_person_has_no_standing_without_a_grant() {
    let deployment = access_deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(800, 60);
    let (document, version) = ready_under(
        &prepared,
        &api,
        "institutional-custody",
        CITIZEN.subject,
        &content,
    )
    .await;
    let (subject, kind, represented): (String, String, String) = (
        deployment
            .scalar("SELECT custodian_subject FROM documents_documents")
            .await,
        deployment
            .scalar("SELECT custodian_kind FROM documents_documents")
            .await,
        deployment
            .scalar("SELECT represented_principal_subject FROM documents_documents")
            .await,
    );
    assert_eq!(
        (subject.as_str(), kind.as_str(), represented.as_str()),
        (APP.subject, "service", CITIZEN.subject)
    );

    for person in [CITIZEN, CITIZEN_AS_READER] {
        api.read(person, &document)
            .await
            .assert_problem(ProblemCode::ResourceNotFound);
        api.download(person, &document, &version)
            .await
            .assert_problem(ProblemCode::ResourceNotFound);
        api.get(person, &format!("/documents/{document}/grants"))
            .await
            .assert_problem(ProblemCode::ResourceNotFound);
    }
    assert_eq!(
        api.get(CITIZEN, "/documents").await.json()["items"],
        json!([])
    );
    // The institution holds it and releases it to itself.
    let held = api.read(APP, &document).await;
    assert_eq!(held.json()["custodian"]["subject"], APP.subject);
    assert_eq!(api.download(APP, &document, &version).await.body, content);

    grant_id(
        &api.grant(APP, &document, &version, CITIZEN.subject, None)
            .await,
    );
    let released = api.download(CITIZEN_AS_READER, &document, &version).await;
    assert_eq!(released.status, 200);
    assert_eq!(released.body, content);
    // The grant names a recipient profile; the person's represented
    // principal profile still has no standing.
    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);

    // Under citizen-delivery the same reservation makes the person the
    // custodian.
    let delivered = pdf(700, 61);
    let (document, version) = ready_under(
        &prepared,
        &api,
        "citizen-delivery",
        CITIZEN.subject,
        &delivered,
    )
    .await;
    assert_eq!(
        api.read(CITIZEN, &document).await.json()["custodian"]["subject"],
        CITIZEN.subject
    );
    assert_eq!(
        api.download(CITIZEN, &document, &version).await.body,
        delivered
    );
}

/// The reserving system sees a document it holds for a person and may
/// share it, but is not released its content: it is answered
/// `profile.not-authorized`, never the not-found a stranger gets.
#[tokio::test]
async fn the_owning_system_that_is_not_the_custodian_is_refused_the_content_as_unauthorized() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(600, 62)).await;
    assert_eq!(api.read(APP, &document).await.status, 200);
    api.download(APP, &document, &version)
        .await
        .assert_problem(ProblemCode::ProfileNotAuthorized);
    api.download(OTHER_APP, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
}

/// A grant names its grantee's actor kind as well as its subject, and
/// releases to no caller of another kind at the same subject.
#[tokio::test]
async fn a_grant_releases_only_to_a_caller_of_the_actor_kind_it_names() {
    let deployment = access_deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(600, 63);
    let (document, version) =
        ready_under(&prepared, &api, "named-share", CITIZEN.subject, &content).await;

    let human = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    grant_id(&human);
    assert_eq!(human.json()["grantee"]["kind"], "human");
    assert_eq!(
        api.download(READER, &document, &version).await.body,
        content
    );
    api.read(PARTNER_SERVICE, &document)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.download(PARTNER_SERVICE, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    assert_eq!(
        api.get(PARTNER_SERVICE, "/document-grants").await.json()["items"],
        json!([])
    );

    let service = api
        .grant_kind(
            APP,
            &Uuid::new_v4().to_string(),
            &document,
            &version,
            PARTNER_SERVICE.subject,
            "service",
            None,
        )
        .await;
    let service_grant = grant_id(&service);
    assert_eq!(
        api.download(PARTNER_SERVICE, &document, &version)
            .await
            .body,
        content
    );
    let received = api.get(PARTNER_SERVICE, "/document-grants").await.json();
    assert_eq!(received["items"].as_array().unwrap().len(), 1);
    assert_eq!(received["items"][0]["id"], service_grant.as_str());
    let kinds: String = deployment
        .scalar("SELECT string_agg(grantee_kind, ',' ORDER BY issued_at) FROM documents_grants")
        .await;
    assert_eq!(kinds, "human,service");

    api.grant_kind(
        APP,
        &Uuid::new_v4().to_string(),
        &document,
        &version,
        READER.subject,
        "organization",
        None,
    )
    .await
    .assert_problem(ProblemCode::RequestUnprocessable);
}

/// DD18: the issuing institution is the profile's, never the body's.
#[tokio::test]
async fn the_issuing_institution_comes_from_the_profile_and_a_differing_body_is_refused() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(512, 41);
    let body = |institution: &str| {
        let mut body = reservation_body(
            "citizen-delivery",
            CITIZEN.subject,
            &sha256(&content),
            512,
            PDF,
        );
        body["issuingInstitution"] = json!(institution);
        body
    };

    api.reserve_body(APP, "other-institution", &body("another-ministry"))
        .await
        .assert_problem(ProblemCode::CustodyNotPermitted);
    // A profile with no institution names none.
    let mut own = reservation_body("named-share", CITIZEN.subject, &sha256(&content), 512, PDF);
    own["issuingInstitution"] = json!("civil-registry");
    api.reserve_body(CITIZEN, "citizen-institution", &own)
        .await
        .assert_problem(ProblemCode::CustodyNotPermitted);
    let reserved: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents")
        .await;
    assert_eq!(reserved, 0);

    let same = api
        .reserve_body(APP, "same-institution", &body("civil-registry"))
        .await;
    assert_eq!(same.status, 201, "{}", String::from_utf8_lossy(&same.body));
    let institution: String = deployment
        .scalar("SELECT issuing_institution FROM documents_versions")
        .await;
    assert_eq!(institution, "civil-registry");
}

/// DD18: an idempotency key is bound to its first body. A retry with the
/// same body answers the same document; one with another digest is refused
/// and reserves nothing; a key past its retention is expired.
#[tokio::test]
async fn an_idempotency_key_replays_its_reservation_and_refuses_another_body() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(512, 42);
    let body = reservation_body(
        "citizen-delivery",
        CITIZEN.subject,
        &sha256(&content),
        512,
        PDF,
    );

    let first = api.reserve_body(APP, "reserve-1", &body).await;
    let (document, _, _) = reservation(&first);
    let again = api.reserve_body(APP, "reserve-1", &body).await;
    assert_eq!(again.status, 201);
    assert_eq!(again.json()["document"]["id"], document.as_str());

    let mut other = body.clone();
    other["expectedDigest"] = json!(sha256(&pdf(512, 43)));
    api.reserve_body(APP, "reserve-1", &other)
        .await
        .assert_problem(ProblemCode::IdempotencyKeyReused);
    let (documents, reserved): (i64, i64) = (
        deployment
            .scalar("SELECT count(*) FROM documents_documents")
            .await,
        deployment
            .scalar("SELECT coalesce(sum(length), 0)::bigint FROM documents_versions")
            .await,
    );
    assert_eq!((documents, reserved), (1, 512));

    // The key is the caller's own: another principal's same key is a new
    // reservation.
    let elsewhere = api.reserve_body(OTHER_APP, "reserve-1", &body).await;
    let (other_document, _, _) = reservation(&elsewhere);
    assert_ne!(other_document, document);

    deployment
        .execute("UPDATE documents_idempotency SET created_at = now() - interval '2 days', expires_at = now() - interval '1 second'")
        .await;
    api.reserve_body(APP, "reserve-1", &body)
        .await
        .assert_problem(ProblemCode::IdempotencyExpired);
    let documents: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents")
        .await;
    assert_eq!(documents, 2);
}

/// A grant releases one exact version to one named recipient, until it
/// expires or is revoked. Everyone else, and every other version, is the
/// same not-found answer.
#[tokio::test]
async fn a_grant_releases_one_exact_version_to_its_named_recipient_until_expiry_or_revocation() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(1500, 44);
    let (document, version) = ready(&prepared, &api, &content).await;
    let (other_document, other_version) = ready(&prepared, &api, &pdf(700, 45)).await;

    // Before any grant the reader learns nothing.
    api.read(READER, &document)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);

    let issued = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    let grant = grant_id(&issued);
    let view = issued.json();
    assert_eq!(view["state"], "active");
    assert_eq!(view["versionId"], version.as_str());
    assert_eq!(view["grantee"]["subject"], READER.subject);
    let hours: i64 = deployment
        .scalar("SELECT (extract(epoch FROM expires_at - issued_at) / 3600)::bigint FROM documents_grants")
        .await;
    assert_eq!(hours, 24, "the policy default, frozen at issue");

    let seen = api.read(READER, &document).await;
    assert_eq!(seen.status, 200);
    assert_eq!(seen.json()["actions"], json!(["download"]));
    let released = api.download(READER, &document, &version).await;
    assert_eq!(released.status, 200);
    assert_eq!(released.body, content);

    // The grant names one version: another document's version is not it.
    api.download(READER, &other_document, &other_version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.download(READER, &document, &other_version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    // Another recipient-profile holder is not the named one.
    api.download(STRANGER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    // A named subject under a profile the policy does not list as a
    // recipient is not released to either.
    grant_id(
        &api.grant(APP, &document, &version, STAFF.subject, None)
            .await,
    );
    api.download(STAFF, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);

    // An expired grant releases nothing.
    deployment
        .execute(&format!(
            "UPDATE documents_grants SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 second' WHERE grant_id = '{grant}'"
        ))
        .await;
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.read(READER, &document)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);

    // Nor does a revoked one, and revoking twice is the same answer.
    let renewed = grant_id(
        &api.grant(APP, &document, &version, READER.subject, None)
            .await,
    );
    assert_eq!(api.download(READER, &document, &version).await.status, 200);
    let revoked = api.revoke(APP, &renewed).await;
    assert_eq!(
        revoked.status,
        200,
        "{}",
        String::from_utf8_lossy(&revoked.body)
    );
    assert_eq!(revoked.json()["state"], "revoked");
    assert_eq!(api.revoke(APP, &renewed).await.json(), revoked.json());
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);

    let entries = deployment.audit_entries();
    let count = |event: &str| {
        entries
            .iter()
            .filter(|entry| entry["record"]["event"] == event)
            .count()
    };
    assert!(count("documents.grant-issue") >= 6);
    assert!(count("documents.grant-revoke") >= 4);
    // The release refusals were journalled with the code answered and
    // nothing more.
    let refused = entries
        .iter()
        .filter(|entry| {
            entry["record"]["event"] == "documents.content-download"
                && entry["record"]["outcome"] == "refused"
        })
        .collect::<Vec<_>>();
    assert!(!refused.is_empty());
    for entry in refused {
        assert_eq!(entry["record"]["code"], "resource.not-found");
    }
}

/// A grant on a version that is not releasable now releases nothing, and
/// a releasable row approved under another verifier binding is suspended
/// for the custodian too.
#[tokio::test]
async fn a_version_approved_under_another_binding_is_released_to_nobody() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(900, 46)).await;
    grant_id(
        &api.grant(APP, &document, &version, READER.subject, None)
            .await,
    );
    assert_eq!(api.download(READER, &document, &version).await.status, 200);

    deployment
        .execute(&format!(
            "UPDATE documents_versions SET verification_binding_digest = 'binding-b', verified_binding_digest = 'binding-b' WHERE version_id = '{version}'"
        ))
        .await;
    let eligibility: String = deployment
        .scalar("SELECT eligibility FROM documents_versions")
        .await;
    assert_eq!(eligibility, "releasable");

    assert_eq!(status(&api.read(CITIZEN, &document).await), "suspended");
    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.grant(APP, &document, &version, READER.subject, None)
        .await
        .assert_problem(ProblemCode::DocumentVersionNotReleasable);
}

/// Only the custodian or the owning system issues, revokes, or lists
/// grants, and a probe of an unknown id is the answer a stranger gets for
/// a known one.
#[tokio::test]
async fn grant_authority_and_unknown_ids_answer_without_disclosing_a_document() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(600, 47)).await;
    let unknown = Uuid::new_v4().to_string();

    // A reader without a grant does not see the document at all.
    api.grant(READER, &document, &version, READER.subject, None)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    // The citizen is the custodian, but this policy refuses it grants.
    api.grant(CITIZEN, &document, &version, READER.subject, None)
        .await
        .assert_problem(ProblemCode::ProfileNotAuthorized);
    // An expiry past the policy maximum is refused.
    api.grant(APP, &document, &version, READER.subject, Some(25))
        .await
        .assert_problem(ProblemCode::RequestUnprocessable);
    // A version that is not this document's is not found.
    api.grant(APP, &document, &unknown, READER.subject, None)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    let grants: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants")
        .await;
    assert_eq!(grants, 0);

    let grant = grant_id(
        &api.grant(APP, &document, &version, READER.subject, Some(2))
            .await,
    );
    // A caller that does not see the document learns nothing of its grants;
    // the grantee and the custodian see it but manage no grant here.
    api.revoke(STRANGER, &grant)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.get(STRANGER, &format!("/documents/{document}/grants"))
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    for seeing in [READER, CITIZEN] {
        api.revoke(seeing, &grant)
            .await
            .assert_problem(ProblemCode::ProfileNotAuthorized);
    }
    api.get(READER, &format!("/documents/{document}/grants"))
        .await
        .assert_problem(ProblemCode::ProfileNotAuthorized);
    api.revoke(APP, &unknown)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    let active: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants WHERE revoked_at IS NULL")
        .await;
    assert_eq!(active, 1);

    for principal in [APP, CITIZEN, READER, STRANGER, STAFF] {
        let known_to_stranger = api.read(STRANGER, &document).await;
        let probe = api.read(principal, &unknown).await;
        probe.assert_problem(ProblemCode::ResourceNotFound);
        assert_eq!(probe.json()["detail"], known_to_stranger.json()["detail"]);
        api.download(principal, &unknown, &version)
            .await
            .assert_problem(ProblemCode::ResourceNotFound);
        api.download(principal, &document, &unknown)
            .await
            .assert_problem(ProblemCode::ResourceNotFound);
        api.get(principal, &format!("/documents/{unknown}/grants"))
            .await
            .assert_problem(ProblemCode::ResourceNotFound);
    }
}

/// A grant retry under its idempotency key re-checks authority and never
/// revives a revoked grant.
#[tokio::test]
async fn an_idempotent_grant_retry_after_revocation_releases_nothing() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(600, 48)).await;

    let issued = api
        .grant_with_key(APP, "share-1", &document, &version, READER.subject, None)
        .await;
    let grant = grant_id(&issued);
    api.revoke(APP, &grant).await;

    let retried = api
        .grant_with_key(APP, "share-1", &document, &version, READER.subject, None)
        .await;
    assert_eq!(retried.json()["id"], grant.as_str());
    assert_eq!(retried.json()["state"], "revoked");
    let grants: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants")
        .await;
    assert_eq!(grants, 1);
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);

    // A retry under the key by a caller without the authority is that
    // caller's own refusal, never the cached success.
    api.grant_with_key(
        CITIZEN,
        "share-1",
        &document,
        &version,
        READER.subject,
        None,
    )
    .await
    .assert_problem(ProblemCode::ProfileNotAuthorized);
    let mut other =
        json!({"versionId": version, "grantee": {"subject": STAFF.subject, "kind": "human"}});
    other["expiryHours"] = json!(2);
    api.send_json(
        APP,
        axum::http::Method::POST,
        &format!("/documents/{document}/grants"),
        Some("share-1"),
        &other,
    )
    .await
    .assert_problem(ProblemCode::IdempotencyKeyReused);
}

/// A download admitted before a revocation completes; the next one is
/// refused.
#[tokio::test]
async fn a_transfer_admitted_before_a_revocation_completes() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(200_000, 49);
    let (document, version) = ready(&prepared, &api, &content).await;
    let grant = grant_id(
        &api.grant(APP, &document, &version, READER.subject, None)
            .await,
    );

    let response = api
        .respond(
            support::request(
                READER,
                axum::http::Method::GET,
                &format!("/documents/{document}/versions/{version}/content"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(api.revoke(APP, &grant).await.status, 200);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), content.as_slice());
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
}

/// Lists keep a stable order, page by an opaque cursor, and refuse a page
/// size above the hard cap.
#[tokio::test]
async fn grant_and_document_lists_page_in_a_stable_order() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(600, 50)).await;
    let mut issued = Vec::new();
    for _ in 0..3 {
        issued.push(grant_id(
            &api.grant(APP, &document, &version, READER.subject, None)
                .await,
        ));
    }
    api.revoke(APP, &issued[0]).await;

    let path = format!("/documents/{document}/grants");
    let first = api.get(APP, &format!("{path}?limit=2")).await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    let cursor = first.json()["nextCursor"].as_str().unwrap().to_owned();
    let second = api
        .get(APP, &format!("{path}?limit=2&cursor={cursor}"))
        .await;
    assert_eq!(second.status, 200);
    assert!(second.json()["nextCursor"].is_null());
    let mut listed = first.json()["items"].as_array().unwrap().clone();
    listed.extend(second.json()["items"].as_array().unwrap().clone());
    let ids = listed
        .iter()
        .map(|grant| grant["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut expected = issued.clone();
    expected.sort();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(sorted, expected);
    assert_eq!(api.get(APP, &path).await.json()["items"], json!(listed));
    // The custodian lists the shares too.
    assert_eq!(api.get(CITIZEN, &path).await.status, 200);

    // The recipient's own list shows its active grants only.
    let received = api.get(READER, "/document-grants").await;
    assert_eq!(received.status, 200);
    let received = received.json()["items"].as_array().unwrap().clone();
    assert_eq!(received.len(), 2);
    assert!(received.iter().all(|grant| grant["state"] == "active"));
    assert_eq!(
        api.get(STRANGER, "/document-grants").await.json()["items"],
        json!([])
    );

    for refused in [
        "?limit=0",
        "?limit=101",
        "?cursor=not-a-cursor",
        "?unknown=1",
    ] {
        api.get(APP, &format!("{path}{refused}"))
            .await
            .assert_problem(ProblemCode::RequestInvalid);
    }

    // Documents: the custodian and the reserving system see it; a stranger
    // sees an empty page.
    for principal in [CITIZEN, APP] {
        let page = api.get(principal, "/documents").await;
        assert_eq!(page.status, 200);
        assert_eq!(page.json()["items"][0]["id"], document.as_str());
    }
    assert_eq!(
        api.get(STRANGER, "/documents").await.json()["items"],
        json!([])
    );
}

/// A recipient's own grant list holds only grants it may redeem now, and
/// filters before its limit: a page is short only at the end of the list.
#[tokio::test]
async fn a_recipient_s_grant_list_pages_only_grants_it_may_redeem() {
    let deployment = access_deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    // Staff is no recipient under citizen-delivery: these grants name it
    // but release nothing to it.
    let (delivered, delivered_version) = ready(&prepared, &api, &pdf(500, 66)).await;
    for _ in 0..2 {
        grant_id(
            &api.grant(APP, &delivered, &delivered_version, STAFF.subject, None)
                .await,
        );
    }
    // A grant on a version that is no longer releasable.
    let (suspended, suspended_version) = ready_under(
        &prepared,
        &api,
        "named-share",
        CITIZEN.subject,
        &pdf(500, 67),
    )
    .await;
    grant_id(
        &api.grant(APP, &suspended, &suspended_version, STAFF.subject, None)
            .await,
    );
    deployment
        .execute(&format!(
            "UPDATE documents_versions SET eligibility = 'suspended' WHERE version_id = '{suspended_version}'"
        ))
        .await;
    let (shared, shared_version) = ready_under(
        &prepared,
        &api,
        "named-share",
        CITIZEN.subject,
        &pdf(500, 68),
    )
    .await;
    let redeemable = grant_id(
        &api.grant(APP, &shared, &shared_version, STAFF.subject, None)
            .await,
    );

    let page = api.get(STAFF, "/document-grants?limit=1").await;
    assert_eq!(page.status, 200, "{}", String::from_utf8_lossy(&page.body));
    let page = page.json();
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page["items"][0]["id"], redeemable.as_str());
    assert!(page["nextCursor"].is_null(), "{page}");
}

/// The placeable policies are read with the bounds a caller needs before
/// it reserves.
#[tokio::test]
async fn the_policies_a_caller_may_place_are_read_with_their_bounds() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;

    let app = api.get(APP, "/document-policies").await;
    assert_eq!(app.status, 200);
    let ids = app.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|policy| policy["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        ["citizen-delivery", "institutional-custody", "named-share"]
    );
    let delivery = &app.json()["items"][0];
    assert_eq!(delivery["maximumDocumentBytes"], 16_777_216);
    assert_eq!(delivery["allowedContentTypes"], json!([PDF]));
    assert_eq!(delivery["grantExpiryHours"], 24);
    assert_eq!(delivery["maximumGrantExpiryHours"], 24);

    let citizen = api.get(CITIZEN, "/document-policies").await;
    assert_eq!(citizen.json()["items"][0]["id"], "named-share");
    assert_eq!(citizen.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        api.get(READER, "/document-policies").await.json()["items"],
        json!([])
    );
}

/// A label is stored and returned as given, bounded, and never decides
/// anything.
#[tokio::test]
async fn a_label_is_bounded_and_returned_untouched() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(300, 51);
    let mut body = reservation_body(
        "citizen-delivery",
        CITIZEN.subject,
        &sha256(&content),
        300,
        PDF,
    );
    body["label"] = json!("x".repeat(257));
    api.reserve_body(APP, "label-long", &body)
        .await
        .assert_problem(ProblemCode::RequestUnprocessable);

    body["label"] = json!("Birth certificate <b>copy</b>");
    let (document, _, _) = reservation(&api.reserve_body(APP, "label-ok", &body).await);
    assert_eq!(
        api.read(CITIZEN, &document).await.json()["label"],
        "Birth certificate <b>copy</b>"
    );
    api.read(STRANGER, &document)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
}

/// Uploads and downloads draw on one in-flight byte budget: with none left,
/// both are refused as unavailable before any content moves.
#[tokio::test]
async fn an_exhausted_transfer_budget_refuses_uploads_and_downloads() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(800, 52)).await;
    let content = pdf(800, 53);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );

    let service = prepared.service();
    let budget = service.budget();
    let held = budget
        .try_reserve(budget.available_bytes())
        .expect("the whole budget");
    api.download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    api.put(APP, &path, PDF, Body::from(content.clone()))
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    let stored: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(stored, 1);

    drop(held);
    assert_eq!(api.download(CITIZEN, &document, &version).await.status, 200);
    assert_eq!(
        api.put(APP, &path, PDF, Body::from(content)).await.status,
        200
    );
}

/// An upload body that stalls past its transfer deadline is answered as
/// unavailable and keeps nothing.
#[tokio::test]
async fn a_stalled_upload_is_cut_off_at_its_deadline() {
    let mut deployment = deployment().await;
    deployment
        .configure("transfers:\n  minimumDeadlineSeconds: 1\n  mebibyteAllowanceSeconds: 1\n");
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(1000, 54);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    let head = Bytes::copy_from_slice(&content[..10]);
    let stalled = futures::stream::once(async move { Ok::<_, std::io::Error>(head) })
        .chain(futures::stream::pending());
    let started = std::time::Instant::now();
    api.put(APP, &path, PDF, Body::from_stream(stalled))
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    let stored: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(stored, 0);
}

/// A download whose body is not read before its deadline ends in an error
/// rather than holding its bytes.
#[tokio::test]
async fn a_download_not_read_before_its_deadline_ends_in_an_error() {
    let mut deployment = deployment().await;
    deployment
        .configure("transfers:\n  minimumDeadlineSeconds: 1\n  mebibyteAllowanceSeconds: 1\n");
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready(&prepared, &api, &pdf(800, 55)).await;
    let response = api
        .respond(
            support::request(
                CITIZEN,
                axum::http::Method::GET,
                &format!("/documents/{document}/versions/{version}/content"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(response.status(), 200);
    let available = prepared.service().budget().available_bytes();
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert!(prepared.service().budget().available_bytes() > available);
    assert!(axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .is_err());
}

/// A request whose audit entry cannot be written is refused as unavailable,
/// on upload and on download.
#[tokio::test]
async fn a_request_audit_failure_refuses_the_upload_and_the_download() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let content = pdf(800, 57);
    let (document, version, path) = {
        let (prepared, api) = start(&deployment, &verifier).await;
        let (document, version) = ready(&prepared, &api, &pdf(800, 56)).await;
        let (_, _, path) = reservation(
            &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
                .await,
        );
        (document, version, path)
    };

    let failing = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares again")
        .with_audit(failing_audit());
    let refused = Api::new(&failing);
    refused
        .download(CITIZEN, &document, &version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    refused
        .put(APP, &path, PDF, Body::from(content))
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    let stored: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(stored, 1);
}

fn failing_audit() -> DocumentsAudit {
    DocumentsAudit::new(
        AuditWriter::from_line_sink(Box::new(FailingSink)),
        AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"documents-test-audit-key-not-a-secret".to_vec(),
        ))
        .unwrap()
        .key_hasher(),
    )
}

/// A request body that records whether anything read it.
fn watched_body(polled: &Arc<AtomicBool>) -> Body {
    let polled = polled.clone();
    Body::from_stream(futures::stream::once(async move {
        polled.store(true, Ordering::SeqCst);
        Ok::<_, std::io::Error>(Bytes::from_static(b"{}"))
    }))
}

#[tokio::test]
async fn a_json_body_is_not_read_before_the_caller_is_authenticated() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("none", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let document = Uuid::new_v4();
    for path in [
        "/documents".to_owned(),
        format!("/documents/{document}/grants"),
    ] {
        for authorization in [None, Some("Bearer not-a-token")] {
            let polled = Arc::new(AtomicBool::new(false));
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri(&path)
                .header("content-type", "application/json")
                .header("idempotency-key", "unauthenticated-body");
            if let Some(value) = authorization {
                request = request.header("authorization", value);
            }
            let answer = api.call(request.body(watched_body(&polled)).unwrap()).await;
            answer.assert_problem(ProblemCode::AuthenticationRefused);
            assert!(
                !polled.load(Ordering::SeqCst),
                "{path} read the body of an unauthenticated request"
            );
        }
    }
}

#[tokio::test]
async fn an_authenticated_json_body_over_the_limit_is_refused_as_too_large() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("none", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let chunk = Bytes::from(vec![b' '; 64 * 1024]);
    let body = Body::from_stream(futures::stream::iter(
        (0..17).map(move |_| Ok::<_, std::io::Error>(chunk.clone())),
    ));
    let answer = api
        .call(
            support::request(APP, axum::http::Method::POST, "/documents")
                .header("content-type", "application/json")
                .header("idempotency-key", "oversized-body")
                .body(body)
                .unwrap(),
        )
        .await;
    answer.assert_problem(ProblemCode::RequestBodyTooLarge);
}

#[tokio::test]
async fn an_upload_to_an_unknown_or_another_caller_s_reservation_is_journalled() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(128, 15);
    let (_, _, path) = reservation(
        &api.reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
            .await,
    );
    let unknown = "00000000-0000-4000-8000-000000000000";
    api.put(STRANGER, &path, PDF, Body::from(content.clone()))
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.put(
        APP,
        &format!("/uploads/{unknown}/content"),
        PDF,
        Body::from(content),
    )
    .await
    .assert_problem(ProblemCode::ResourceNotFound);

    let entries = deployment.audit_entries();
    let content_entries = entries
        .iter()
        .filter(|entry| entry["record"]["event"] == "documents.upload-content")
        .collect::<Vec<_>>();
    assert_eq!(content_entries.len(), 4, "{content_entries:#?}");
    let reserved = path
        .trim_start_matches("/uploads/")
        .trim_end_matches("/content");
    assert_eq!(content_entries[0]["record"]["uploadId"], reserved);
    assert_eq!(content_entries[2]["record"]["uploadId"], unknown);
    for refusal in [content_entries[1], content_entries[3]] {
        assert_eq!(refusal["record"]["outcome"], "refused");
        assert_eq!(refusal["record"]["code"], "resource.not-found");
    }
}

#[tokio::test]
async fn the_journal_records_no_unchecked_text_from_a_request() {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let oversized = "X".repeat(64 * 1024);
    let content = pdf(256, 16);
    api.reserve_body(
        APP,
        "oversized-policy",
        &reservation_body(&oversized, CITIZEN.subject, &sha256(&content), 256, PDF),
    )
    .await
    .assert_problem(ProblemCode::DocumentPolicyUnknown);
    api.reserve_body(
        APP,
        "oversized-media-type",
        &reservation_body(
            "citizen-delivery",
            CITIZEN.subject,
            &sha256(&content),
            256,
            &oversized,
        ),
    )
    .await
    .assert_problem(ProblemCode::DocumentContentTypeNotAllowed);
    let (document, _) = ready(&prepared, &api, &content).await;
    api.send_json(
        APP,
        axum::http::Method::POST,
        &format!("/documents/{document}/grants"),
        Some("oversized-version"),
        &json!({"versionId": oversized, "grantee": {"subject": READER.subject, "kind": "human"}}),
    )
    .await
    .assert_problem(ProblemCode::ResourceNotFound);

    let journal = std::fs::read_to_string(deployment.audit_path()).unwrap();
    assert!(
        !journal.contains("XXXX"),
        "the journal recorded an unchecked request value"
    );
    let entries = deployment.audit_entries();
    let begun = |event: &str, field: &str| {
        entries
            .iter()
            .filter(|entry| entry["record"]["event"] == event)
            .filter_map(|entry| entry["record"][field].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let policies = begun("documents.upload-reservation", "policyId");
    assert_eq!(policies[0], "unparsed");
    assert_eq!(policies[1], "citizen-delivery");
    let media_types = begun("documents.upload-reservation", "mediaType");
    assert_eq!(media_types[0], PDF);
    assert_eq!(media_types[1], "unparsed");
    assert_eq!(
        begun("documents.grant-issue", "versionId").last().unwrap(),
        "unparsed"
    );
}

/// An audit sink that keeps its first line and refuses every write after
/// it, so a request entry is written and its response entry is not.
struct FirstLineSink {
    kept: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for FirstLineSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut kept = self.kept.lock().unwrap();
        if kept.contains(&b'\n') {
            return Err(std::io::Error::other("the audit sink refuses"));
        }
        kept.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// SEC-30: an audit response entry that cannot be written after the
/// operation committed answers `service.unavailable`; the committed state
/// stands, the request entry is in the journal, and a retry under the
/// same idempotency key answers the committed result.
#[tokio::test]
async fn a_response_audit_failure_after_commit_answers_unavailable_and_the_retry_answers_the_commit(
) {
    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let content = pdf(512, 58);
    let body = reservation_body(
        "citizen-delivery",
        CITIZEN.subject,
        &sha256(&content),
        512,
        PDF,
    );
    let kept = Arc::new(std::sync::Mutex::new(Vec::new()));
    let failing = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares")
        .with_audit(DocumentsAudit::new(
            AuditWriter::from_line_sink(Box::new(FirstLineSink { kept: kept.clone() })),
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                b"documents-test-audit-key-not-a-secret".to_vec(),
            ))
            .unwrap()
            .key_hasher(),
        ));
    Api::new(&failing)
        .reserve_body(APP, "committed-before-the-journal-failed", &body)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    drop(failing);

    let journal = String::from_utf8(kept.lock().unwrap().clone()).unwrap();
    let entries = journal.lines().collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "{journal}");
    let entry: serde_json::Value = serde_json::from_str(entries[0]).unwrap();
    assert_eq!(entry["record"]["event"], "documents.upload-reservation");
    assert!(entry["record"]["outcome"].is_null(), "{entry}");
    let committed: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents")
        .await;
    assert_eq!(committed, 1, "the committed reservation stands");

    let (_prepared, api) = start(&deployment, &verifier).await;
    let retried = api
        .reserve_body(APP, "committed-before-the-journal-failed", &body)
        .await;
    assert_eq!(
        retried.status,
        201,
        "{}",
        String::from_utf8_lossy(&retried.body)
    );
    let document: String = deployment
        .scalar("SELECT document_id::text FROM documents_documents")
        .await;
    assert_eq!(retried.json()["document"]["id"], document.as_str());
    let still: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents")
        .await;
    assert_eq!(still, 1, "the retry made nothing new");
}

/// SEC-28: verification waits for transfer budget only within its attempt
/// timeout. While every byte of the budget is held, an attempt ends as a
/// transient failure once its attempt deadline passes, without asking the
/// verifier, so a job never holds its lease past that deadline.
#[tokio::test]
async fn a_verification_attempt_waits_for_transfer_budget_only_within_its_attempt_timeout() {
    use registry_documents::verification::{job_part, verification_policy, VerificationJob};
    use registry_platform_dispatch::postgres::{DispatchTransport as _, JobKey, LeasedJob};
    use registry_platform_dispatch::SendOutcome;

    let deployment = deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let config = RuntimeConfig::load(&deployment.runtime).unwrap();
    let secrets = Arc::new(config.secret_resolver().unwrap());
    let store = PostgresStore::connect_runtime(&config.database, &secrets).unwrap();
    let storage = Arc::new(
        ContentStorage::activate(&config.storage, "registry-documents-test", secrets)
            .await
            .unwrap(),
    );
    let budget = TransferBudget::new(1_048_576);
    let held = budget
        .try_reserve(budget.total_bytes())
        .expect("the whole budget is free");
    assert_eq!(budget.available_bytes(), 0);
    let transport = VerificationTransport::new(store, storage, verifier.clone(), budget);

    let version_id = Uuid::new_v4();
    let binding = verifier.binding_digest().to_owned();
    let attempt_timeout = std::time::Duration::from_millis(300);
    let job = LeasedJob {
        key: JobKey::new(version_id, job_part(version_id, &binding)).unwrap(),
        generation: 1,
        attempt: 1,
        attempt_started_at: std::time::SystemTime::now(),
        lease_token: Uuid::new_v4(),
        policy: registry_platform_dispatch::JobPolicy {
            attempt_timeout,
            ..verification_policy()
        },
        job: VerificationJob {
            version_id,
            media_type: PDF.to_owned(),
            computed_digest: sha256(b"held"),
            length: 4096,
            object_id: None,
            binding,
        },
    };

    let started = std::time::Instant::now();
    let sent = tokio::time::timeout(std::time::Duration::from_secs(10), transport.send(&job))
        .await
        .expect("the attempt ends within its own timeout, not when the budget frees")
        .expect("the attempt answers an outcome");
    let waited = started.elapsed();
    assert!(
        matches!(sent.outcome, SendOutcome::Transient { .. }),
        "{:?}",
        sent.outcome
    );
    assert!(waited >= attempt_timeout, "{waited:?}");
    assert!(waited < std::time::Duration::from_secs(5), "{waited:?}");
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    drop(held);
}
