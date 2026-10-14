// SPDX-License-Identifier: Apache-2.0
//! External automatic recovery requires a verified human and an explicit Apply grant.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
};
use registry_platform_oidc::ActorKind;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn registry(automatic: bool) -> registry_breg::CompiledRegistry {
    let boundary = json!([{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]);
    let targets = json!([{"recordType":"contact","rowBoundaries":boundary}]);
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"human-recovery","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://recovery.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"contact","primaryDataset":"directory","route":"contacts","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},"fields":[
                {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"retention":{"mode":"operator-erase"},"application":if automatic {json!({"mode":"automatic","maximumAttempts":3})} else {json!({"mode":"manual"})}}},
            "inputs":[{"id":"contact","type":"reference","target":"contact","required":true,"classification":"internal"},
                {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"contact","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"correction","target":{"fromInput":"contact"},"operation":"patch","set":{"name":{"fromInput":"name"}}}]}}],
        // Omitted actorKind must not convert these explicit recovery grants into
        // permission for a service to recover automatic work as a human.
        "accessProfiles":[{"id":"operator","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{
                "records":[{"recordType":"contact","operations":["create","get"],"readableFields":["name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],"rowBoundaries":boundary}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":targets}],
                "proposals":[{"action":"correct-name","operations":["get","submit","apply","retry"],"ownership":"caller","targets":targets}]}}]
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn claims(kind: Option<ActorKind>) -> VerifiedRequestClaims {
    let scopes = BTreeSet::from(["proposal:manage".into()]);
    let purpose = Some("registry-administration".into());
    let direct = BTreeMap::from([(
        "jurisdiction".into(),
        VerifiedClaimValue::direct_string("zone-a").unwrap(),
    )]);
    // This fixture's documented bearer-admission seam constructs verified
    // claim context, never a ProposalAuthority or a system executor lease.
    match kind {
        Some(kind) => VerifiedRequestClaims::authenticated_with_actor_kind(
            "sub", "operator", scopes, purpose, direct, kind,
        ),
        None => VerifiedRequestClaims::authenticated("sub", "operator", scopes, purpose, direct),
    }
    .unwrap()
}

async fn send(
    http: &client_http::ClientHttp,
    method: Method,
    path: &str,
    body: Value,
    key: Option<&str>,
    etag: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = reqwest::Client::new().request(method, format!("{}{path}", http.base_url));
    if !body.is_null() {
        request = request.json(&body);
    }
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    if let Some(etag) = etag {
        request = request.header("if-match", etag);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().unwrap().to_owned());
    (status, response.json().await.unwrap(), etag)
}

async fn submitted(fixture: &client_http::ClientFixture) -> (String, Value, String) {
    let (status, record, _) = send(
        &fixture.http,
        Method::POST,
        "/v1/records/contacts?accessProfile=operator",
        json!({"data":{"name":"Before","jurisdiction":"zone-a"}}),
        Some("recovery-create"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    let target = record["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, draft, etag) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=operator",
        json!({"input":{"contact":target,"name":"After"}}),
        Some("recovery-start"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{draft}");
    let path = format!(
        "/v1/proposals/{}/submit?accessProfile=operator",
        draft["id"].as_str().unwrap()
    );
    let (status, frozen, etag) = send(
        &fixture.http,
        Method::POST,
        &path,
        json!({}),
        Some("recovery-submit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{frozen}");
    (target, frozen, etag.unwrap())
}

async fn assert_record(
    fixture: &client_http::ClientFixture,
    target: &str,
    name: &str,
    revision: u64,
) {
    let path = format!("/v1/records/contacts/{target}?accessProfile=operator");
    let (status, record, _) =
        send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(status, StatusCode::OK, "{record}");
    assert_eq!(record["data"]["domainData"]["name"], name);
    assert_eq!(record["data"]["revisionIdentifier"], revision.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_external_apply_requires_verified_human_even_when_profile_omits_actor_kind() {
    let fixture =
        client_http::ClientFixture::start(registry(true), claims(Some(ActorKind::Human))).await;
    let (target, frozen, etag) = submitted(&fixture).await;
    let id = frozen["id"].as_str().unwrap();
    let path = format!("/v1/proposals/{id}?accessProfile=operator");
    let apply = format!("/v1/proposals/{id}/apply?accessProfile=operator");
    let body = json!({"submissionVersion":frozen["submissionVersion"],"effectDigest":frozen["effectDigest"]});
    for (label, kind) in [
        ("service", Some(ActorKind::Service)),
        ("agent", Some(ActorKind::Agent)),
        ("unspecified", None),
    ] {
        let caller = fixture.client_for(claims(kind)).await;
        let (status, observed, _) =
            send(&caller, Method::GET, &path, Value::Null, None, None).await;
        if label == "agent" {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "standing agents remain draft-only: {observed}"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::OK,
                "ordinary Get remains authorized: {observed}"
            );
            assert!(
                observed["links"].get("apply").is_none(),
                "{label} gained promoted automatic recovery"
            );
        }
        let (status, refused, _) = send(
            &caller,
            Method::POST,
            &apply,
            body.clone(),
            Some(&format!("refused-{label}")),
            Some(&etag),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{label} borrowed human recovery: {refused}"
        );
        assert_record(&fixture, &target, "Before", 1).await;
        let applications = fixture
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_applications",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            applications.get::<_, i64>(0),
            0,
            "refusal committed application evidence"
        );
    }
    let (status, applied, _) = send(
        &fixture.http,
        Method::POST,
        &apply,
        body,
        Some("human-recovery-apply"),
        Some(&etag),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "explicit human Apply grant recovers automatic work: {applied}"
    );
    assert_eq!(applied["state"], "applied");
    assert_eq!(
        applied["applicationStatus"]["mode"], "automatic",
        "manual recovery preserves frozen mode"
    );
    assert_eq!(
        applied["application"]["submissionVersion"],
        frozen["submissionVersion"]
    );
    assert_eq!(
        applied["application"]["effectDigest"],
        frozen["effectDigest"]
    );
    assert_record(&fixture, &target, "After", 2).await;
    assert!(
        !fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap(),
        "built-in worker does not duplicate human recovery"
    );
    assert_record(&fixture, &target, "After", 2).await;
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_mode_preserves_explicit_service_apply_authority() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims(Some(ActorKind::Service))).await;
    let (target, frozen, etag) = submitted(&fixture).await;
    assert!(frozen["links"].get("apply").is_some());
    let apply = format!(
        "/v1/proposals/{}/apply?accessProfile=operator",
        frozen["id"].as_str().unwrap()
    );
    let (status,applied,_) = send(&fixture.http,Method::POST,&apply,
        json!({"submissionVersion":frozen["submissionVersion"],"effectDigest":frozen["effectDigest"]}),
        Some("manual-service-apply"),Some(&etag)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "manual-mode service grant remains authored authority: {applied}"
    );
    assert_eq!(applied["applicationStatus"]["mode"], "manual");
    assert_record(&fixture, &target, "After", 2).await;
    fixture.finish().await;
}

async fn application_job(fixture: &client_http::ClientFixture, id: &str) -> Value {
    let id = uuid::Uuid::parse_str(id).unwrap();
    let row = fixture.database.admin.query_one(
        "SELECT job_id,proposal_digest,system_grant_revision,state,attempt_count,maximum_attempts,
            last_error_code,next_attempt_at::text,next_attempt_at<=clock_timestamp()
         FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",
        &[&id],
    ).await.unwrap();
    json!({"jobId":row.get::<_,uuid::Uuid>(0).to_string(),
        "effectDigest":row.get::<_,String>(1),"systemGrantRevision":row.get::<_,String>(2),
        "state":row.get::<_,String>(3),"attempts":row.get::<_,i32>(4),
        "maximumAttempts":row.get::<_,i32>(5),"error":row.get::<_,Option<String>>(6),
        "nextAttemptAt":row.get::<_,String>(7),"due":row.get::<_,bool>(8)})
}

async fn set_application_job(
    fixture: &client_http::ClientFixture,
    id: &str,
    state: &str,
    attempts: i32,
    error: &str,
) {
    let id = uuid::Uuid::parse_str(id).unwrap();
    // Establish existing retained worker states. Recovery itself is exercised
    // only through the real HTTP operation; the fixture does not reschedule it.
    assert_eq!(
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_application_jobs
         SET state=$2,attempt_count=$3,last_error_code=$4,claim_token=NULL,
             next_attempt_at=clock_timestamp()+interval '1 hour'
         WHERE proposal_id=$1",
                &[&id, &state, &attempts, &error],
            )
            .await
            .unwrap(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_retry_requires_human_and_preserves_the_exact_job_and_budget() {
    let fixture =
        client_http::ClientFixture::start(registry(true), claims(Some(ActorKind::Human))).await;
    let (target, frozen, etag) = submitted(&fixture).await;
    let id = frozen["id"].as_str().unwrap();
    let path = format!("/v1/proposals/{id}?accessProfile=operator");
    let retry = format!("/v1/proposals/{id}/retry?accessProfile=operator");
    for (label, state, attempts, error) in [
        ("already-queued", "queued", 1, "dependency-outage"),
        ("exhausted", "blocked", 3, "dependency-outage"),
        ("semantic-refusal", "blocked", 1, "precondition-failed"),
    ] {
        set_application_job(&fixture, id, state, attempts, error).await;
        let before = application_job(&fixture, id).await;
        let (status, observed, _) =
            send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
        assert_eq!(status, StatusCode::OK, "{observed}");
        assert_eq!(
            observed["links"]["retry"]["availability"]["available"], false,
            "{label} became retryable"
        );
        let (status, refused, _) = send(
            &fixture.http,
            Method::POST,
            &retry,
            json!({}),
            Some(&format!("human-retry-{label}")),
            Some(&etag),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "{label} was rescheduled: {refused}"
        );
        assert_eq!(
            application_job(&fixture, id).await,
            before,
            "{label} changed retained job state"
        );
        assert_record(&fixture, &target, "Before", 1).await;
    }
    set_application_job(&fixture, id, "blocked", 1, "dependency-outage").await;
    let blocked = application_job(&fixture, id).await;
    for (label, kind) in [
        ("service", Some(ActorKind::Service)),
        ("agent", Some(ActorKind::Agent)),
        ("unspecified", None),
    ] {
        let caller = fixture.client_for(claims(kind)).await;
        let (status, observed, _) =
            send(&caller, Method::GET, &path, Value::Null, None, None).await;
        if label == "agent" {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "standing agent gained observation: {observed}"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::OK,
                "ordinary observation was concealed: {observed}"
            );
            assert!(
                observed["links"].get("retry").is_none(),
                "{label} gained a Retry link"
            );
        }
        let (status, refused, _) = send(
            &caller,
            Method::POST,
            &retry,
            json!({}),
            Some(&format!("nonhuman-retry-{label}")),
            Some(&etag),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{label} borrowed human Retry: {refused}"
        );
        assert_eq!(
            application_job(&fixture, id).await,
            blocked,
            "{label} mutated or rescheduled the job"
        );
        assert_record(&fixture, &target, "Before", 1).await;
    }
    let (status, observed, _) =
        send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(status, StatusCode::OK, "{observed}");
    assert_eq!(
        observed["links"]["retry"]["availability"]["available"],
        true
    );
    let (status, retried, _) = send(
        &fixture.http,
        Method::POST,
        &retry,
        json!({}),
        Some("human-retry-eligible"),
        Some(&etag),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "granted human could not Retry: {retried}"
    );
    for field in [
        "id",
        "actionId",
        "actionRevision",
        "submissionVersion",
        "effectDigest",
    ] {
        assert_eq!(
            retried[field], frozen[field],
            "Retry changed frozen {field}"
        );
    }
    let queued = application_job(&fixture, id).await;
    for field in [
        "jobId",
        "effectDigest",
        "systemGrantRevision",
        "attempts",
        "maximumAttempts",
    ] {
        assert_eq!(
            queued[field], blocked[field],
            "Retry changed retained {field}"
        );
    }
    assert_eq!(queued["state"], "queued");
    assert_eq!(queued["error"], Value::Null);
    assert_eq!(queued["due"], true);
    assert_eq!(
        retried["applicationStatus"]["automaticRetry"],
        json!({"scheduled":true,"attempts":1,"maximumAttempts":3})
    );
    assert_record(&fixture, &target, "Before", 1).await;
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_record(&fixture, &target, "After", 2).await;
    let (status, applied, _) =
        send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["applicationStatus"]["state"], "applied");
    assert_eq!(
        applied["application"]["submissionVersion"],
        frozen["submissionVersion"]
    );
    assert_eq!(
        applied["application"]["effectDigest"],
        frozen["effectDigest"]
    );
    let committed = application_job(&fixture, id).await;
    assert_eq!(committed["state"], "applied");
    assert_eq!(
        committed["attempts"], 2,
        "Retry must not reset the consumed attempt"
    );
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let (status, refused, _) = send(
        &fixture.http,
        Method::POST,
        &retry,
        json!({}),
        Some("stale-human-retry-after-apply"),
        Some(&etag),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "old submitted Retry was accepted: {refused}"
    );
    assert_eq!(application_job(&fixture, id).await, committed);
    assert_record(&fixture, &target, "After", 2).await;
    fixture.finish().await;
}
