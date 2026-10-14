// SPDX-License-Identifier: Apache-2.0
//! Native Proposal review delivery uses durable, authority-bound PostgreSQL work.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    mutation::MutationError,
    review_store::{
        back_off_review_token_failure_for_test, claim_submission, reconcile_result,
        run_one_cancellation, run_one_submission, run_review_authority_once_for_test,
        ReviewAuthorityClient, ReviewAuthorityRegistry, ReviewCompletionReceiver,
    },
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegRecordFormat,
};
use registry_review_client::{
    BearerToken, PolicyBinding, ReviewCancelRequest, ReviewCancelResponse, ReviewClient,
    ReviewClientConfig, ReviewCompletion, ReviewCompletionType, ReviewCreateRequest,
    ReviewRequestAccepted, ReviewResult, ReviewResultStatus,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;
use zeroize::Zeroizing;

const AUTHORITY: &str = "private-review-authority-canary";
const PRODUCER: &str = "proposal-producer";
const OUTGOING_TOKEN: &str = "synthetic-outgoing-review-token";
const INCOMING_TOKEN: &str = "synthetic-incoming-completion-token";
const RECIPIENT: &str = "private-completion-recipient-canary";
const TRACE: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

struct Token;
#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for Token {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        BearerToken::new(OUTGOING_TOKEN)
    }
}

#[derive(Default)]
struct Gate {
    entered: Notify,
    release: Notify,
}
impl Gate {
    async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
            .await
            .expect("bounded authority request arrives");
    }
    async fn pause(&self) {
        self.entered.notify_one();
        tokio::time::timeout(Duration::from_secs(10), self.release.notified())
            .await
            .expect("test releases bounded authority response");
    }
}

struct AuthorityState {
    gates: [Gate; 2],
    gated: bool,
    first_succeeds: bool,
    requests: AtomicUsize,
    creates: Mutex<Vec<(String, ReviewCreateRequest)>>,
    accepted: Mutex<Option<ReviewRequestAccepted>>,
    result_id: Uuid,
}
struct Authority {
    registry: Arc<ReviewAuthorityRegistry>,
    client: Arc<ReviewClient>,
    state: Arc<AuthorityState>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Authority {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Authority {
    async fn start(gated: bool, first_succeeds: bool) -> Self {
        let state = Arc::new(AuthorityState {
            gates: [Gate::default(), Gate::default()],
            gated,
            first_succeeds,
            requests: 0.into(),
            creates: Mutex::new(Vec::new()),
            accepted: Mutex::new(None),
            result_id: Uuid::new_v4(),
        });
        let app = Router::new()
            .route("/v1/review-requests", post(create_review))
            .route("/v1/review-requests/{id}/cancel", post(cancel_review))
            .route("/v1/review-results", get(empty_feed))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = Arc::new(
            ReviewClient::new(ReviewClientConfig::new(endpoint.parse().unwrap())).unwrap(),
        );
        let authority = Arc::new(
            ReviewAuthorityClient::new(
                AUTHORITY.into(),
                ReviewClient::new(ReviewClientConfig::new(endpoint.parse().unwrap())).unwrap(),
                Arc::new(Token),
                "producer".into(),
                PRODUCER.into(),
                7,
                Some(Zeroizing::new(INCOMING_TOKEN.into())),
                Some(RECIPIENT.into()),
            )
            .unwrap(),
        );
        let registry = Arc::new(
            ReviewAuthorityRegistry::new(BTreeMap::from([(AUTHORITY.into(), authority)])).unwrap(),
        );
        Self {
            registry,
            client,
            state,
            server,
        }
    }
}
fn policy() -> PolicyBinding {
    serde_json::from_value(
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}", "b".repeat(64))}),
    )
    .unwrap()
}
fn authenticated(headers: &HeaderMap) {
    assert_eq!(
        headers.get("authorization").unwrap(),
        format!("Bearer {OUTGOING_TOKEN}").as_str()
    );
    assert_eq!(
        headers.get("registry-casework-profile").unwrap(),
        "producer"
    );
    assert!(headers.contains_key("idempotency-key"));
}
fn response(status: StatusCode, body: Value) -> Response {
    (status, [("traceparent", TRACE)], Json(body)).into_response()
}
async fn create_review(
    State(state): State<Arc<AuthorityState>>,
    headers: HeaderMap,
    Json(request): Json<ReviewCreateRequest>,
) -> Response {
    authenticated(&headers);
    request.check().unwrap();
    assert_eq!(
        request.policy,
        policy(),
        "submit the complete frozen policy pin"
    );
    state.creates.lock().unwrap().push((
        headers["idempotency-key"].to_str().unwrap().into(),
        request.clone(),
    ));
    let accepted = {
        let mut retained = state.accepted.lock().unwrap();
        retained
            .get_or_insert_with(|| ReviewRequestAccepted {
                request_id: Uuid::new_v4(),
                subject: request.subject.clone(),
                policy: policy(),
                submission_digest: registry_review_client::submission_digest(
                    PRODUCER,
                    "proposal-test",
                    &request,
                )
                .unwrap(),
            })
            .clone()
    };
    let call = state.requests.fetch_add(1, Ordering::SeqCst);
    if state.gated {
        state.gates[call].pause().await;
    }
    if call == 0 && !state.first_succeeds {
        return response(StatusCode::SERVICE_UNAVAILABLE, json!({}));
    }
    response(StatusCode::CREATED, json!(accepted))
}
async fn cancel_review(
    State(state): State<Arc<AuthorityState>>,
    headers: HeaderMap,
    Json(request): Json<ReviewCancelRequest>,
) -> Response {
    authenticated(&headers);
    request.check().unwrap();
    let accepted = state.accepted.lock().unwrap().clone().unwrap();
    assert_eq!(request.subject, accepted.subject);
    let call = state.requests.fetch_add(1, Ordering::SeqCst);
    if state.gated {
        state.gates[call].pause().await;
    }
    if call == 0 && !state.first_succeeds {
        return response(StatusCode::SERVICE_UNAVAILABLE, json!({}));
    }
    response(
        StatusCode::OK,
        json!(ReviewCancelResponse::Cancelled {
            result: result(&accepted, state.result_id, ReviewResultStatus::Cancelled)
        }),
    )
}
async fn empty_feed() -> Response {
    response(StatusCode::OK, json!({"items":[]}))
}
fn result(
    accepted: &ReviewRequestAccepted,
    result_id: Uuid,
    status: ReviewResultStatus,
) -> ReviewResult {
    let now = chrono::Utc::now();
    ReviewResult {
        result_id,
        request_id: accepted.request_id,
        subject: accepted.subject.clone(),
        policy: accepted.policy.clone(),
        submission_digest: accepted.submission_digest.clone(),
        status,
        outcome: None,
        result: None,
        completed_at: now - chrono::Duration::seconds(1),
        available_until: now + chrono::Duration::hours(1),
    }
}
fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "sub",
        "author-canary",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}
fn registry() -> registry_breg::CompiledRegistry {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],
        "reviewAuthorities":[{"id":AUTHORITY,"protocol":"id.registrystack.org/protocols/review/v1"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable","mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{"review":{"type":"required","authority":AUTHORITY,"source":"proposal-test","policy":policy()},
            "application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],"requiredPurposes":["registry-administration"],"permissions":{
            "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":["name","jurisdiction"],"writableFields":["name","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
            "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
            "proposals":[{"action":"correct-name","operations":["get","list","submit","cancel"],"ownership":"caller","targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]});
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}
async fn fixture(authority: &Authority) -> client_http::ClientFixture {
    let bindings = authority.registry.clone();
    client_http::ClientFixture::start_with_mutations(registry(), claims(), move |service| {
        service.with_review_result_source(bindings)
    })
    .await
}
async fn submitted(fixture: &client_http::ClientFixture, key_name: &str) -> Uuid {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(
                json!({"name":"Before","jurisdiction":"zone-a"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            &BRegIdempotencyKey::parse(&format!("{key_name}-record")).unwrap(),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        json!({"target":record.value.data.record_identifier,"value":"After"})
            .as_object()
            .unwrap()
            .clone(),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(
            &action,
            &input,
            &BRegIdempotencyKey::parse(&format!("{key_name}-start")).unwrap(),
        )
        .await
        .unwrap()
        .value;
    let submit = client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse(&format!("{key_name}-submit")).unwrap(),
        )
        .unwrap();
    let value = client.execute_proposal(&submit).await.unwrap().value;
    Uuid::parse_str(value.id()).unwrap()
}
async fn retained_binding(fixture: &client_http::ClientFixture, id: Uuid) -> ReviewRequestAccepted {
    let row = fixture.database.admin.query_one("SELECT create_request,expected_policy,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]).await.unwrap();
    let request: ReviewCreateRequest = serde_json::from_value(row.get(0)).unwrap();
    ReviewRequestAccepted {
        request_id: Uuid::new_v4(),
        subject: request.subject,
        policy: serde_json::from_value(row.get(1)).unwrap(),
        submission_digest: registry_review_client::SubmissionDigest::parse(
            &row.get::<_, String>(2),
        )
        .unwrap(),
    }
}
async fn accept(fixture: &client_http::ClientFixture, id: Uuid, binding: &ReviewRequestAccepted) {
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$2,next_result_poll_at=transaction_timestamp()+interval '1 hour' WHERE proposal_id=$1", &[&id, &json!(binding)]).await.unwrap();
}
async fn job(fixture: &client_http::ClientFixture, id: Uuid) -> Value {
    fixture.database.admin.query_one("SELECT jsonb_build_object('state',state,'lease',lease_until,'error',last_error_code,'binding',accepted_binding,'attempts',attempt_count,'deadline',recovery_deadline,'next',next_attempt_at) FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]).await.unwrap().get(0)
}
async fn result_count(fixture: &client_http::ClientFixture) -> i64 {
    fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_review_results",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn native_completion_inbox_deduplicates_refuses_substitution_correlates_and_expires_without_values(
) {
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "completion").await;
    let accepted = retained_binding(&fixture, id).await;
    let result = result(&accepted, Uuid::new_v4(), ReviewResultStatus::Approved);
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: Uuid::new_v4(),
        request_id: accepted.request_id,
        result_id: result.result_id,
        completed_at: result.completed_at,
    };
    let receiver = ReviewCompletionReceiver::new(fixture.pool.clone(), authority.registry.clone());
    for (token, recipient) in [
        (OUTGOING_TOKEN, RECIPIENT),
        (INCOMING_TOKEN, "wrong-recipient"),
        ("wrong-token", RECIPIENT),
    ] {
        assert!(receiver.authority(token, recipient).is_none());
    }
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_review_completions",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let (matched, _) = receiver.authority(INCOMING_TOKEN, RECIPIENT).unwrap();
    assert_eq!(matched, AUTHORITY);
    receiver.receive(&matched, &completion).await.unwrap();
    receiver.receive(&matched, &completion).await.unwrap();
    for changed in [
        ReviewCompletion {
            request_id: Uuid::new_v4(),
            ..completion.clone()
        },
        ReviewCompletion {
            result_id: Uuid::new_v4(),
            ..completion.clone()
        },
        ReviewCompletion {
            completed_at: completion.completed_at + chrono::Duration::seconds(1),
            ..completion.clone()
        },
    ] {
        let error = receiver.receive(&matched, &changed).await.unwrap_err();
        assert!(matches!(error, MutationError::PreconditionFailed));
        let diagnostic = format!("{error:?}: {error}");
        for canary in [
            AUTHORITY,
            RECIPIENT,
            INCOMING_TOKEN,
            OUTGOING_TOKEN,
            &completion.event_id.to_string(),
            &completion.request_id.to_string(),
            &completion.result_id.to_string(),
        ] {
            assert!(
                !diagnostic.contains(canary),
                "completion refusal disclosed a synthetic reference"
            );
        }
    }
    let row = fixture.database.admin.query_one("SELECT count(*),min(state) FROM registry_internal.registry_proposal_review_completions", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>(1), "unmatched");
    accept(&fixture, id, &accepted).await;
    let pending = ReviewCompletion {
        event_id: Uuid::new_v4(),
        ..completion.clone()
    };
    receiver.receive(&matched, &pending).await.unwrap();
    let row = fixture.database.admin.query_one("SELECT c.state,s.next_result_poll_at<=transaction_timestamp() FROM registry_internal.registry_proposal_review_completions c JOIN registry_internal.registry_proposal_review_submissions s ON s.accepted_binding->>'requestId'=c.review_request_id::text WHERE c.event_id=$1", &[&pending.event_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "pending");
    assert!(
        row.get::<_, bool>(1),
        "completion makes the accepted review's result lookup due"
    );
    // A completion accepted before the binding is adopted is correlated by
    // the real result transaction, not a test-written completion state.
    let mut runtime = fixture.pool.get_for_test().await.unwrap();
    let tx = runtime.transaction().await.unwrap();
    reconcile_result(&tx, AUTHORITY, &accepted, &result)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(runtime);
    assert_eq!(fixture.database.admin.query_one("SELECT state FROM registry_internal.registry_proposal_review_completions WHERE event_id=$1", &[&completion.event_id]).await.unwrap().get::<_, String>(0), "correlated");
    let late = ReviewCompletion {
        event_id: Uuid::new_v4(),
        ..completion.clone()
    };
    receiver.receive(&matched, &late).await.unwrap();
    assert_eq!(fixture.database.admin.query_one("SELECT state FROM registry_internal.registry_proposal_review_completions WHERE event_id=$1", &[&late.event_id]).await.unwrap().get::<_, String>(0), "correlated");
    let retained = ReviewCompletion {
        event_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        result_id: Uuid::new_v4(),
        ..completion.clone()
    };
    receiver.receive(&matched, &retained).await.unwrap();
    let expired_unmatched = ReviewCompletion {
        event_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        result_id: Uuid::new_v4(),
        ..completion.clone()
    };
    receiver
        .receive(&matched, &expired_unmatched)
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_completions SET received_at=transaction_timestamp()-interval '2 days',expires_at=transaction_timestamp()-interval '1 day' WHERE event_id IN ($1,$2,$3,$4)", &[&completion.event_id, &pending.event_id, &late.event_id, &expired_unmatched.event_id]).await.unwrap();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let capture = tracing::subscriber::set_default(subscriber);
    assert!(
        run_review_authority_once_for_test(&fixture.pool, &authority.registry)
            .await
            .unwrap()
    );
    drop(capture);
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("BReg review completion retention pass erased expired rows"));
    assert!(output.contains("\"erased\":4"));
    for canary in [
        AUTHORITY,
        RECIPIENT,
        INCOMING_TOKEN,
        OUTGOING_TOKEN,
        &completion.event_id.to_string(),
        &completion.request_id.to_string(),
        &completion.result_id.to_string(),
        &retained.event_id.to_string(),
    ] {
        assert!(
            !output.contains(canary),
            "retention log disclosed a synthetic reference"
        );
    }
    let remaining = fixture.database.admin.query_one("SELECT count(*),bool_and(event_id=$1),bool_and(state='unmatched') FROM registry_internal.registry_proposal_review_completions", &[&retained.event_id]).await.unwrap();
    assert_eq!(remaining.get::<_, i64>(0), 1);
    assert!(remaining.get::<_, bool>(1));
    assert!(remaining.get::<_, bool>(2));
    assert_eq!(result_count(&fixture).await, 1);
    assert_eq!(
        authority.state.requests.load(Ordering::SeqCst),
        0,
        "inbox/retention is local"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn native_submission_reclaims_exact_work_and_fences_late_success_and_failure() {
    for first_succeeds in [false, true] {
        let authority = Authority::start(true, first_succeeds).await;
        let fixture = fixture(&authority).await;
        let id = submitted(&fixture, "submission").await;
        let mut workers = Vec::new();
        for index in 0..2 {
            if index == 1 {
                fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET lease_until=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
            }
            let client = fixture.pool.get_for_test().await.unwrap();
            let review = authority.client.clone();
            workers.push(tokio::spawn(async move {
                run_one_submission(
                    &**client,
                    AUTHORITY,
                    &review,
                    "producer",
                    &BearerToken::new(OUTGOING_TOKEN).unwrap(),
                    30,
                )
                .await
            }));
            authority.state.gates[index].reached().await;
        }
        let replacement = job(&fixture, id).await;
        assert_eq!(replacement["state"], "submitting");
        assert_eq!(replacement["attempts"], 2);
        assert!(!replacement["lease"].is_null());
        // A live claim excludes any third worker, including another authority.
        let client = fixture.pool.get_for_test().await.unwrap();
        assert!(claim_submission(&**client, AUTHORITY, 30)
            .await
            .unwrap()
            .is_none());
        assert!(claim_submission(&**client, "another-authority", 30)
            .await
            .unwrap()
            .is_none());
        drop(client);
        authority.state.gates[0].release.notify_one();
        let old = tokio::time::timeout(Duration::from_secs(5), workers.remove(0))
            .await
            .unwrap()
            .unwrap();
        if first_succeeds {
            assert!(matches!(old, Err(MutationError::PreconditionFailed)));
        } else {
            assert!(old.unwrap());
        }
        assert_eq!(
            job(&fixture, id).await,
            replacement,
            "late old response cannot replace the live adopted lease"
        );
        authority.state.gates[1].release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), workers.remove(0))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
        let retained = job(&fixture, id).await;
        assert_eq!(retained["state"], "accepted");
        assert_eq!(retained["attempts"], 2);
        assert!(retained["lease"].is_null());
        assert!(retained["error"].is_null());
        assert_eq!(
            retained["binding"],
            json!(authority.state.accepted.lock().unwrap().clone().unwrap())
        );
        let creates = authority.state.creates.lock().unwrap();
        assert_eq!(creates.len(), 2);
        assert_eq!(creates[0].1.policy, policy());
        assert_eq!(creates[1].1.policy, policy());
        assert_eq!(
            creates[0].0, creates[1].0,
            "adoption reuses exact idempotency key"
        );
        assert_eq!(
            json!(creates[0].1),
            json!(creates[1].1),
            "adoption reuses exact frozen request"
        );
        drop(creates);
        assert_eq!(result_count(&fixture).await, 0);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn native_cancellation_reclaims_exact_work_and_rolls_back_stale_reconciliation() {
    for first_succeeds in [false, true] {
        let authority = Authority::start(true, first_succeeds).await;
        let fixture = fixture(&authority).await;
        let id = submitted(&fixture, "cancellation").await;
        let accepted = retained_binding(&fixture, id).await;
        accept(&fixture, id, &accepted).await;
        *authority.state.accepted.lock().unwrap() = Some(accepted);
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='cancelling',withdrawn=true WHERE proposal_id=$1", &[&id]).await.unwrap();
        let mut workers = Vec::new();
        for index in 0..2 {
            if index == 1 {
                fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET lease_until=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
            }
            let mut client = fixture.pool.get_for_test().await.unwrap();
            let review = authority.client.clone();
            workers.push(tokio::spawn(async move {
                run_one_cancellation(
                    &mut client,
                    AUTHORITY,
                    &review,
                    "producer",
                    &BearerToken::new(OUTGOING_TOKEN).unwrap(),
                    30,
                )
                .await
            }));
            authority.state.gates[index].reached().await;
        }
        let replacement = job(&fixture, id).await;
        assert_eq!(replacement["state"], "cancelling");
        assert_eq!(replacement["attempts"], 2);
        let client = fixture.pool.get_for_test().await.unwrap();
        back_off_review_token_failure_for_test(&client, AUTHORITY, &["cancelling"])
            .await
            .unwrap();
        drop(client);
        assert_eq!(
            job(&fixture, id).await,
            replacement,
            "token outage cannot clear an active cancellation lease"
        );
        authority.state.gates[0].release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), workers.remove(0))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            job(&fixture, id).await,
            replacement,
            "late old cancellation cannot change the adopted lease"
        );
        assert_eq!(
            result_count(&fixture).await,
            0,
            "stale successful cancellation reconciliation rolls back"
        );
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET recovery_deadline=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
        let expired = job(&fixture, id).await;
        assert!(
            !run_review_authority_once_for_test(&fixture.pool, &authority.registry)
                .await
                .unwrap()
        );
        assert_eq!(
            job(&fixture, id).await,
            expired,
            "recovery expiry leaves the live cancellation lease to its holder"
        );
        authority.state.gates[1].release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), workers.remove(0))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
        let settled = job(&fixture, id).await;
        assert_eq!(settled["state"], "cancelled");
        assert!(settled["lease"].is_null());
        assert!(settled["error"].is_null());
        assert_eq!(settled["binding"], replacement["binding"]);
        assert_eq!(result_count(&fixture).await, 1);
        fixture.finish().await;
    }
}
