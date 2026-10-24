// SPDX-License-Identifier: Apache-2.0
//! Retained task authority governs every uncommitted Proposal application.
#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    auth::{AuthorityClaimConfig, RegistryAuthenticator},
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    task_grant::{TaskGrantBinding, TaskGrantError, TaskGrantStatusChecker},
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Notify;

const ACTIVE: u8 = 0;
const UNAVAILABLE: u8 = 1;
const REFUSED: u8 = 2;

fn registry(automatic: bool, reviewed: bool) -> registry_breg::CompiledRegistry {
    let review = if reviewed {
        json!({
            "type":"required",
            "authority":"local-review",
            "source":"proposal-task-authority",
            "policy":{
                "id":"name-correction",
                "version":"1",
                "digest":format!("sha256:{}", "b".repeat(64))
            }
        })
    } else {
        json!({"type":"none"})
    };
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{
            "id":"proposal-task-authority",
            "version":"1",
            "defaultLanguage":"en",
            "canonicalBaseIri":"https://proposal-task-authority.example.test"
        },
        "datasets":[{"id":"directory"}],
        "reviewAuthorities":if reviewed {
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}])
        } else {
            json!([])
        },
        "recordTypes":[{
            "id":"target",
            "primaryDataset":"directory",
            "route":"targets",
            "mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[
                {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}
            ]
        }],
        "actions":[{
            "id":"correct-name",
            "execution":{"mode":"proposal","proposal":{
                "review":review,
                "application":if automatic {
                    json!({"mode":"automatic","maximumAttempts":3})
                } else {
                    json!({"mode":"manual"})
                },
                "retention":{"mode":"operator-erase"}
            }},
            "inputs":[
                {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}
            ],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{
                "id":"name",
                "target":{"fromInput":"target"},
                "operation":"patch",
                "set":{"name":{"fromInput":"value"}}
            }]}
        }],
        "accessProfiles":[
            {
                "id":"clerk",
                "default":true,
                "principalClaim":"registry_principal",
                "requiredScopes":["proposal:manage"],
                "requiredPurposes":["registry-administration"],
                "permissions":{
                    "records":[{
                        "recordType":"target",
                        "operations":["create","get","list"],
                        "readableFields":["name","jurisdiction"],
                        "writableFields":["name","jurisdiction"],
                        "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
                    }],
                    "actions":[{
                        "action":"correct-name",
                        "operations":["start"],
                        "targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]
                    }],
                    "proposals":[{
                        "action":"correct-name",
                        "operations":["get","edit","submit","retry","cancel","apply"],
                        "ownership":"caller",
                        "targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]
                    }]
                }
            },
            {
                "id":"task-agent",
                "principalClaim":"registry_principal",
                "actorKind":"agent",
                "requesterClients":["agent-client"],
                "requiredScopes":["proposal:manage"],
                "requiredPurposes":["registry-administration"],
                "taskGrant":{"sourceIssuer":"https://casework.example"},
                "permissions":{
                    "actions":[{
                        "action":"correct-name",
                        "operations":["start"],
                        "targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]
                    }],
                    "proposals":[{
                        "action":"correct-name",
                        "operations":["get","edit","submit","cancel"],
                        "ownership":"caller",
                        "targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]
                    }]
                }
            }
        ]
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .expect("task-authority registry compiles")
}

fn clerk() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}

struct Status {
    mode: AtomicU8,
    refused_grant: AtomicU64,
    calls: AtomicUsize,
    pause: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl TaskGrantStatusChecker for Status {
    fn check<'a>(
        &'a self,
        binding: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if binding.grant_id() == grant_id(2) && self.pause.load(Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            match self.mode.load(Ordering::SeqCst) {
                UNAVAILABLE => Err(TaskGrantError::Unavailable),
                REFUSED
                    if binding.grant_id()
                        == grant_id(self.refused_grant.load(Ordering::SeqCst)) =>
                {
                    Err(TaskGrantError::Refused)
                }
                _ => Ok(()),
            }
        })
    }
}

fn status() -> Arc<Status> {
    Arc::new(Status {
        mode: AtomicU8::new(ACTIVE),
        refused_grant: AtomicU64::new(0),
        calls: AtomicUsize::new(0),
        pause: AtomicBool::new(false),
        entered: Notify::new(),
        release: Notify::new(),
    })
}

struct NoToken;

#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for NoToken {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        Err(registry_platform_httputil::TokenError::Unavailable)
    }
}

fn review_binding() -> Arc<registry_breg::review_store::ReviewAuthorityRegistry> {
    use registry_breg::review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry};
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new("http://127.0.0.1:9/".parse().unwrap()),
    )
    .unwrap();
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "local-review".into(),
            client,
            Arc::new(NoToken),
            "producer".into(),
            "proposal-producer".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("local-review".into(), authority)])).unwrap(),
    )
}

struct ApprovedReview {
    calls: AtomicUsize,
    result_id: uuid::Uuid,
}

#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for ApprovedReview {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let now = chrono::Utc::now();
        let result = registry_review_client::ReviewResult {
            result_id: self.result_id,
            request_id: accepted.request_id,
            subject: accepted.subject.clone(),
            policy: accepted.policy.clone(),
            submission_digest: accepted.submission_digest.clone(),
            status: registry_review_client::ReviewResultStatus::Approved,
            outcome: Some("approved".to_owned()),
            public_reason: None,
            result: None,
            completed_at: now - chrono::Duration::seconds(1),
            available_until: now + chrono::Duration::minutes(5),
        };
        registry_breg::review_integration::AcceptedReviewEvidence::from_protocol(
            authority, accepted, &result,
        )
        .map_err(|_| registry_breg::mutation::MutationError::PreconditionFailed)
    }
}

fn grant_id(grant: u64) -> String {
    format!("00000000-0000-4000-8000-{grant:012x}")
}

fn token(grant: u64, permissions: Value) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({
        "aud":"urn:example:breg",
        "sub":"author",
        "azp":"agent-client",
        "registry_principal":"author",
        "registry_actor_kind":"agent",
        "registry_purpose":"registry-administration",
        "scope":"proposal:manage",
        "registry_grant_id":grant_id(grant),
        "registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example",
        "registry_grant_client":"agent-client",
        "registry_grant_resource":"urn:example:breg",
        "registry_grant_exp":now+600,
        "registry_grant_bounds":{"type":"breg","permissions":permissions},
        "identity":{"jurisdiction":"zone-a"},
        "jurisdiction":"zone-b"
    })
}

async fn authenticator(
    registry: &registry_breg::CompiledRegistry,
    idp: &MockIdp,
) -> RegistryAuthenticator {
    let mut verifier = oidc_verifier_config(idp.issuer(), vec!["urn:example:breg".into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    RegistryAuthenticator::new(
        registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into())),
    )
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
    let mut request = reqwest::Client::new()
        .request(method, format!("{}{path}", http.base_url))
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    if let Some(etag) = etag {
        request = request.header("if-match", etag);
    }
    if !body.is_null() {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().unwrap().to_owned());
    (status, response.json().await.unwrap(), etag)
}

async fn create_target(fixture: &client_http::ClientFixture, suffix: &str) -> String {
    let (status, value, _) = send(
        &fixture.http,
        Method::POST,
        "/v1/records/targets?accessProfile=clerk",
        json!({"data":{"name":"Before","jurisdiction":"zone-a"}}),
        Some(&format!("create-target-{suffix}")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn submit_with_task(
    fixture: &client_http::ClientFixture,
    auth: &RegistryAuthenticator,
    idp: &MockIdp,
    target: &str,
    suffix: &str,
) -> (String, Value, String) {
    let starter = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(
                1,
                json!([{"collection":"action:correct-name","operations":["start"]}]),
            )))
            .await
            .unwrap(),
        )
        .await;
    let (status, draft, etag) = send(
        &starter,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=task-agent",
        json!({"input":{"target":target,"value":"After"}}),
        Some(&format!("start-{suffix}")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{draft}");
    let proposal_id = draft["id"].as_str().unwrap().to_owned();
    let lifecycle = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(
                2,
                json!([{
                    "collection":format!("proposal:{proposal_id}"),
                    "operations":["get","edit","submit","cancel"]
                }]),
            )))
            .await
            .unwrap(),
        )
        .await;
    let (status, submitted, submitted_etag) = send(
        &lifecycle,
        Method::POST,
        &format!("/v1/proposals/{proposal_id}/submit?accessProfile=task-agent"),
        json!({}),
        Some(&format!("submit-{suffix}")),
        etag.as_deref(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{submitted}");
    (proposal_id, submitted, submitted_etag.unwrap())
}

async fn read_target_name(fixture: &client_http::ClientFixture, target: &str) -> String {
    let (status, value, _) = send(
        &fixture.http,
        Method::GET,
        &format!("/v1/records/targets/{target}?accessProfile=clerk"),
        Value::Null,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value["data"]["domainData"]["name"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn clerk_proposal(
    fixture: &client_http::ClientFixture,
    proposal_id: &str,
) -> (Value, String) {
    let (status, proposal, etag) = send(
        &fixture.http,
        Method::GET,
        &format!("/v1/proposals/{proposal_id}?accessProfile=clerk"),
        Value::Null,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{proposal}");
    (proposal, etag.unwrap())
}

async fn accept_review(
    fixture: &client_http::ClientFixture,
    proposal_id: &str,
) -> registry_review_client::ReviewRequestAccepted {
    let id = uuid::Uuid::parse_str(proposal_id).unwrap();
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT create_request,expected_policy,expected_submission_digest
             FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(row.get(1)).unwrap(),
        submission_digest: registry_review_client::SubmissionDigest::parse(
            &row.get::<_, String>(2),
        )
        .unwrap(),
    };
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions
             SET state='accepted',accepted_binding=$2 WHERE proposal_id=$1",
            &[&id, &serde_json::to_value(&accepted).unwrap()],
        )
        .await
        .unwrap();
    accepted
}

fn apply_body(submitted: &Value) -> Value {
    json!({
        "submissionVersion":submitted["submissionVersion"],
        "effectDigest":submitted["effectDigest"]
    })
}

async fn wait_until_epoch(deadline: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    tokio::time::sleep(Duration::from_millis(
        (u128::try_from(deadline).unwrap() * 1_000).saturating_sub(now) as u64 + 50,
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_apply_requires_active_retained_task_authority() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "automatic-revoked").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "automatic-revoked").await;
    let before = status.calls.load(Ordering::SeqCst);
    status.refused_grant.store(2, Ordering::SeqCst);
    status.mode.store(REFUSED, Ordering::SeqCst);

    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count FROM registry_internal.registry_proposal_application_jobs
         WHERE proposal_id=$1",
            &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(status.calls.load(Ordering::SeqCst), before + 1);
    assert_eq!(row.get::<_, String>(0), "blocked");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn separately_authorized_manual_apply_requires_active_retained_task_authority() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "manual-revoked").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, submitted, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "manual-revoked").await;
    let (_, etag) = clerk_proposal(&fixture, &proposal_id).await;
    let before = status.calls.load(Ordering::SeqCst);
    status.refused_grant.store(2, Ordering::SeqCst);
    status.mode.store(REFUSED, Ordering::SeqCst);

    let (apply_status, refused, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{proposal_id}/apply?accessProfile=clerk"),
        apply_body(&submitted),
        Some("manual-revoked-apply"),
        Some(&etag),
    )
    .await;
    assert_eq!(apply_status, StatusCode::PRECONDITION_FAILED, "{refused}");
    assert_eq!(status.calls.load(Ordering::SeqCst), before + 1);
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_manual_apply_checks_retained_authority_before_review_evidence() {
    let status = status();
    let checker = status.clone();
    let review = Arc::new(ApprovedReview {
        calls: AtomicUsize::new(0),
        result_id: uuid::Uuid::new_v4(),
    });
    let review_source = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false, true),
        clerk(),
        move |service| {
            service
                .with_task_status(checker)
                .with_proposal_review_substitute_for_test(review_binding(), review_source)
        },
    )
    .await;
    let target = create_target(&fixture, "reviewed-revoked").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, submitted, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "reviewed-revoked").await;
    accept_review(&fixture, &proposal_id).await;
    let (_, etag) = clerk_proposal(&fixture, &proposal_id).await;
    let before = status.calls.load(Ordering::SeqCst);
    status.refused_grant.store(2, Ordering::SeqCst);
    status.mode.store(REFUSED, Ordering::SeqCst);

    let (apply_status, refused, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{proposal_id}/apply?accessProfile=clerk"),
        apply_body(&submitted),
        Some("reviewed-revoked-apply"),
        Some(&etag),
    )
    .await;
    assert_eq!(apply_status, StatusCode::PRECONDITION_FAILED, "{refused}");
    assert_eq!(status.calls.load(Ordering::SeqCst), before + 1);
    assert_eq!(
        review.calls.load(Ordering::SeqCst),
        0,
        "review evidence was disclosed after retained task authority failed"
    );
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_apply_rechecks_status_for_each_retry() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "automatic-retry").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "automatic-retry").await;
    let before = status.calls.load(Ordering::SeqCst);

    status.mode.store(UNAVAILABLE, Ordering::SeqCst);
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let after_outage = status.calls.load(Ordering::SeqCst);
    assert_eq!(after_outage, before + 1);
    assert_eq!(read_target_name(&fixture, &target).await, "Before");

    status.mode.store(ACTIVE, Ordering::SeqCst);
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
         SET next_attempt_at=clock_timestamp() WHERE proposal_id=$1",
            &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
        )
        .await
        .unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(status.calls.load(Ordering::SeqCst), after_outage + 1);
    assert_eq!(read_target_name(&fixture, &target).await, "After");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_apply_rechecks_retained_deadline_before_effects() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "automatic-expired").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "automatic-expired").await;
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_task_authority
         SET binding=jsonb_set(binding,'{expiresAt}',to_jsonb(extract(epoch FROM clock_timestamp())::bigint-1))
         WHERE proposal_id=$1",
        &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
    ).await.unwrap();

    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_deadline_is_rechecked_after_live_status_before_effects() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "deadline-during-status").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "deadline-during-status").await;
    let retained_deadline: i64 = fixture
        .database
        .admin
        .query_one(
            "UPDATE registry_internal.registry_proposal_task_authority
             SET binding=jsonb_set(binding,'{expiresAt}',to_jsonb(extract(epoch FROM clock_timestamp())::bigint+3))
             WHERE proposal_id=$1 RETURNING (binding->>'expiresAt')::bigint",
            &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    status.pause.store(true, Ordering::SeqCst);

    let apply = fixture.mutations.run_automatic_proposal_once_for_test();
    let expire = async {
        tokio::time::timeout(Duration::from_secs(2), status.entered.notified())
            .await
            .expect("automatic Apply checks the retained grant");
        wait_until_epoch(retained_deadline).await;
        status.release.notify_one();
    };
    let (worker, ()) = tokio::join!(apply, expire);
    assert!(worker.unwrap());
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_retained_binding_is_rechecked_after_live_status() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "binding-substitution").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "binding-substitution").await;
    status.pause.store(true, Ordering::SeqCst);

    let apply = fixture.mutations.run_automatic_proposal_once_for_test();
    let substitute = async {
        tokio::time::timeout(Duration::from_secs(2), status.entered.notified())
            .await
            .expect("automatic Apply checks the retained grant");
        let proposal_uuid = uuid::Uuid::parse_str(&proposal_id).unwrap();
        let replacement_grant = grant_id(99);
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_task_authority
                 SET binding=jsonb_set(binding,'{grantId}',to_jsonb($2::text))
                 WHERE proposal_id=$1",
                &[&proposal_uuid, &replacement_grant],
            )
            .await
            .unwrap();
        status.release.notify_one();
    };
    let (worker, ()) = tokio::join!(apply, substitute);
    assert!(worker.unwrap());
    let job = fixture
        .database
        .admin
        .query_one(
            "SELECT state,last_error_code FROM registry_internal.registry_proposal_application_jobs
             WHERE proposal_id=$1",
            &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(job.get::<_, String>(0), "blocked");
    assert_eq!(
        job.get::<_, Option<String>>(1).as_deref(),
        Some("application-refused")
    );
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_deadline_is_rechecked_after_slow_effect_before_commit() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let target = create_target(&fixture, "deadline-during-effect").await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let (proposal_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &target, "deadline-during-effect").await;
    let retained_deadline: i64 = fixture
        .database
        .admin
        .query_one(
            "UPDATE registry_internal.registry_proposal_task_authority
             SET binding=jsonb_set(binding,'{expiresAt}',to_jsonb(extract(epoch FROM clock_timestamp())::bigint+3))
             WHERE proposal_id=$1 RETURNING (binding->>'expiresAt')::bigint",
            &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    let table = &fixture.registry.entities()["target"].physical_table;
    fixture.database.admin.batch_execute(&format!(
        "CREATE FUNCTION registry_data.pause_task_authority_effect() RETURNS trigger LANGUAGE plpgsql AS $body$
         BEGIN
             PERFORM set_config('lock_timeout','10s',true);
             PERFORM pg_advisory_xact_lock(732995002);
             RETURN NEW;
         END $body$;
         CREATE TRIGGER pause_task_authority_effect BEFORE UPDATE ON registry_data.\"{table}\"
         FOR EACH ROW EXECUTE FUNCTION registry_data.pause_task_authority_effect()"
    )).await.unwrap();
    let (barrier, barrier_task) = fixture.database.connect_migration().await;
    barrier
        .execute("SELECT pg_advisory_lock(732995002)", &[])
        .await
        .unwrap();

    let mutations = fixture.mutations.clone();
    let applying =
        tokio::spawn(async move { mutations.run_automatic_proposal_once_for_test().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic Apply reached the effect after retained status and admission");
    wait_until_epoch(retained_deadline).await;
    barrier
        .execute("SELECT pg_advisory_unlock(732995002)", &[])
        .await
        .unwrap();
    barrier_task.abort();

    assert!(applying.await.unwrap().unwrap());
    let job = fixture
        .database
        .admin
        .query_one(
            "SELECT state,last_error_code FROM registry_internal.registry_proposal_application_jobs
             WHERE proposal_id=$1",
            &[&uuid::Uuid::parse_str(&proposal_id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(job.get::<_, String>(0), "blocked");
    assert_eq!(
        job.get::<_, Option<String>>(1).as_deref(),
        Some("application-refused"),
        "the retained deadline fence, not a lock or dependency timeout, refused Apply"
    );
    assert_eq!(read_target_name(&fixture, &target).await, "Before");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn completed_apply_receipt_and_owner_cancel_do_not_require_retained_status() {
    let status = status();
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false, false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;

    let applied_target = create_target(&fixture, "receipt").await;
    let (applied_id, submitted, _) =
        submit_with_task(&fixture, &auth, &idp, &applied_target, "receipt").await;
    let (_, etag) = clerk_proposal(&fixture, &applied_id).await;
    let apply_path = format!("/v1/proposals/{applied_id}/apply?accessProfile=clerk");
    let body = apply_body(&submitted);
    let (apply_status, applied, _) = send(
        &fixture.http,
        Method::POST,
        &apply_path,
        body.clone(),
        Some("receipt-apply"),
        Some(&etag),
    )
    .await;
    assert_eq!(apply_status, StatusCode::OK, "{applied}");

    let cancelled_target = create_target(&fixture, "cancel").await;
    let (cancelled_id, _, _) =
        submit_with_task(&fixture, &auth, &idp, &cancelled_target, "cancel").await;
    let (_, cancelled_etag) = clerk_proposal(&fixture, &cancelled_id).await;
    status.refused_grant.store(2, Ordering::SeqCst);
    status.mode.store(REFUSED, Ordering::SeqCst);
    let calls_before_exceptions = status.calls.load(Ordering::SeqCst);

    let (replay_status, replay, _) = send(
        &fixture.http,
        Method::POST,
        &apply_path,
        body,
        Some("receipt-apply"),
        Some(&etag),
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK, "{replay}");
    let (cancel_status, cancelled, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{cancelled_id}/cancel?accessProfile=clerk"),
        json!({}),
        Some("owner-cancel"),
        Some(&cancelled_etag),
    )
    .await;
    assert_eq!(cancel_status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(status.calls.load(Ordering::SeqCst), calls_before_exceptions);
    fixture.finish().await;
}
