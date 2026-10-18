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
    extract::{Path as AxumPath, State},
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

#[derive(Clone, Copy)]
enum ResultReply {
    Pending,
    Unknown,
    Failed,
    Approved,
}

struct AuthorityState {
    gates: [Gate; 2],
    gated: bool,
    first_succeeds: bool,
    result_replies: [ResultReply; 2],
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
        Self::start_with_results(gated, first_succeeds, [ResultReply::Pending; 2]).await
    }
    async fn start_with_results(
        gated: bool,
        first_succeeds: bool,
        result_replies: [ResultReply; 2],
    ) -> Self {
        let state = Arc::new(AuthorityState {
            gates: [Gate::default(), Gate::default()],
            gated,
            first_succeeds,
            result_replies,
            requests: 0.into(),
            creates: Mutex::new(Vec::new()),
            accepted: Mutex::new(None),
            result_id: Uuid::new_v4(),
        });
        let app = Router::new()
            .route("/v1/review-requests", post(create_review))
            .route("/v1/review-requests/{id}/cancel", post(cancel_review))
            .route("/v1/review-requests/{id}/result", get(lookup_result))
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
    assert_eq!(headers.get("registry-review-profile").unwrap(), "producer");
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
    assert!(
        request.policy.matches(&policy()),
        "request selects the provider policy"
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
        if let Some(gate) = state.gates.get(call) {
            gate.pause().await;
        }
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
        if let Some(gate) = state.gates.get(call) {
            gate.pause().await;
        }
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
async fn lookup_result(
    State(state): State<Arc<AuthorityState>>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Response {
    assert_eq!(
        headers.get("authorization").unwrap(),
        format!("Bearer {OUTGOING_TOKEN}").as_str()
    );
    assert_eq!(headers.get("registry-review-profile").unwrap(), "producer");
    let accepted = state.accepted.lock().unwrap().clone().unwrap();
    assert_eq!(id, accepted.request_id);
    let call = state.requests.fetch_add(1, Ordering::SeqCst);
    if state.gated {
        if let Some(gate) = state.gates.get(call) {
            gate.pause().await;
        }
    }
    match state.result_replies[call] {
        ResultReply::Pending => (StatusCode::ACCEPTED, [("traceparent", TRACE)]).into_response(),
        ResultReply::Unknown => (StatusCode::NOT_FOUND, [("traceparent", TRACE)]).into_response(),
        ResultReply::Failed => response(StatusCode::SERVICE_UNAVAILABLE, json!({})),
        ResultReply::Approved => response(
            StatusCode::OK,
            json!(result(
                &accepted,
                state.result_id,
                ReviewResultStatus::Approved
            )),
        ),
    }
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
        // A decided result names its outcome; a closed one carries none.
        outcome: matches!(status, ReviewResultStatus::Approved).then(|| "approved".to_owned()),
        public_reason: None,
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
    registry_with_policy(json!(policy()))
}
fn registry_with_policy(selection: Value) -> registry_breg::CompiledRegistry {
    let source = registry_source(selection);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}
fn registry_source(selection: Value) -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],
        "reviewAuthorities":[{"id":AUTHORITY,"protocol":"id.registrystack.org/protocols/review/v1"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable","mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{"review":{"type":"required","authority":AUTHORITY,"source":"proposal-test","policy":selection},
            "application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],"requiredPurposes":["registry-administration"],"permissions":{
            "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":["name","jurisdiction"],"writableFields":["name","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
            "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
            "proposals":[{"action":"correct-name","operations":["get","list","submit","cancel"],"ownership":"caller","targets":[{"recordType":"target","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]})
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
            &BRegIdempotencyKey::parse(format!("{key_name}-record")).unwrap(),
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
            &BRegIdempotencyKey::parse(format!("{key_name}-start")).unwrap(),
        )
        .await
        .unwrap()
        .value;
    let submit = client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse(format!("{key_name}-submit")).unwrap(),
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
    reconcile_result(&tx, AUTHORITY, &accepted, &result, &fixture.mutations)
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
    assert!(run_review_authority_once_for_test(
        &fixture.pool,
        &authority.registry,
        &fixture.mutations
    )
    .await
    .unwrap());
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
        {
            let creates = authority.state.creates.lock().unwrap();
            assert_eq!(creates.len(), 2);
            assert_eq!(creates[0].1.policy, policy().into());
            assert_eq!(creates[1].1.policy, policy().into());
            assert_eq!(
                creates[0].0, creates[1].0,
                "adoption reuses exact idempotency key"
            );
            assert_eq!(
                json!(creates[0].1),
                json!(creates[1].1),
                "adoption reuses exact frozen request"
            );
        }
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
            let mutations = Arc::clone(&fixture.mutations);
            workers.push(tokio::spawn(async move {
                run_one_cancellation(
                    &mut client,
                    AUTHORITY,
                    &review,
                    "producer",
                    &BearerToken::new(OUTGOING_TOKEN).unwrap(),
                    30,
                    &mutations,
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
        assert!(!run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry,
            &fixture.mutations
        )
        .await
        .unwrap());
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

async fn result_poll_job(fixture: &client_http::ClientFixture, id: Uuid) -> Value {
    fixture.database.admin.query_one("SELECT jsonb_build_object('state',state,'lease',lease_until,'error',last_error_code,'binding',accepted_binding,'pollAttempts',result_poll_attempts,'nextPoll',next_result_poll_at,'updated',updated_at) FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]).await.unwrap().get(0)
}

async fn accepted_due(fixture: &client_http::ClientFixture, authority: &Authority, id: Uuid) {
    let accepted = retained_binding(fixture, id).await;
    accept(fixture, id, &accepted).await;
    *authority.state.accepted.lock().unwrap() = Some(accepted);
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET next_result_poll_at=transaction_timestamp()-interval '1 second',last_error_code='token-unavailable' WHERE proposal_id=$1", &[&id]).await.unwrap();
}

async fn completed_lookup_releases_claim(reply: ResultReply, expected_error: Option<&str>) {
    let authority = Authority::start_with_results(true, true, [reply, ResultReply::Approved]).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "completed-result").await;
    accepted_due(&fixture, &authority, id).await;
    let pool = fixture.pool.clone();
    let registry = authority.registry.clone();
    let mutations = Arc::clone(&fixture.mutations);
    let first = tokio::spawn(async move {
        run_review_authority_once_for_test(&pool, &registry, &mutations).await
    });
    authority.state.gates[0].reached().await;
    let original_lease: chrono::DateTime<chrono::Utc> = fixture.database.admin.query_one("SELECT lease_until FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]).await.unwrap().get(0);
    authority.state.gates[0].release.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap();
    if matches!(reply, ResultReply::Failed) {
        assert!(matches!(outcome, Err(MutationError::Unavailable)));
    } else {
        assert!(outcome.unwrap());
    }
    let settled = result_poll_job(&fixture, id).await;
    assert_eq!(settled["state"], "accepted");
    assert!(
        settled["lease"].is_null(),
        "a completed lookup releases its in-flight claim"
    );
    assert_eq!(settled["error"], json!(expected_error));
    assert_eq!(settled["pollAttempts"], 1);
    let schedule = fixture.database.admin.query_one("SELECT next_result_poll_at=updated_at+interval '5 seconds',next_result_poll_at>transaction_timestamp(),transaction_timestamp()<$2 FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id, &original_lease]).await.unwrap();
    assert!(
        schedule.get::<_, bool>(0),
        "the ordinary five-second first backoff remains exact"
    );
    assert!(
        schedule.get::<_, bool>(1),
        "a completed lookup still backs off"
    );
    assert!(
        schedule.get::<_, bool>(2),
        "the original in-flight lease has not elapsed"
    );
    assert_eq!(result_count(&fixture).await, 0);
    assert!(
        !run_review_authority_once_for_test(&fixture.pool, &authority.registry, &fixture.mutations)
            .await
            .unwrap(),
        "backoff still excludes an immediate retry"
    );
    // Advance only the persisted backoff to due. The original claim must not
    // delay another authoritative lookup after the exchange has completed.
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET next_result_poll_at=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
    let pool = fixture.pool.clone();
    let registry = authority.registry.clone();
    let mutations = Arc::clone(&fixture.mutations);
    let second = tokio::spawn(async move {
        run_review_authority_once_for_test(&pool, &registry, &mutations).await
    });
    authority.state.gates[1].reached().await;
    assert!(
        fixture
            .database
            .admin
            .query_one("SELECT transaction_timestamp()<$1", &[&original_lease])
            .await
            .unwrap()
            .get::<_, bool>(0),
        "a due review is re-polled before its completed claim would have expired"
    );
    authority.state.gates[1].release.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap());
    assert_eq!(
        result_count(&fixture).await,
        1,
        "the next lookup retains the authoritative result"
    );
    assert_eq!(authority.state.requests.load(Ordering::SeqCst), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn native_completed_pending_lookup_releases_claim_before_repoll_is_due() {
    completed_lookup_releases_claim(ResultReply::Pending, None).await;
}

#[tokio::test]
async fn native_completed_unknown_lookup_releases_claim_before_repoll_is_due() {
    completed_lookup_releases_claim(ResultReply::Unknown, Some("result-unknown-to-authority"))
        .await;
}

#[tokio::test]
async fn native_failed_lookup_releases_claim_before_repoll_is_due() {
    completed_lookup_releases_claim(ResultReply::Failed, Some("result-lookup-uncertain")).await;
}

#[tokio::test]
async fn native_stale_result_lookup_preserves_replacement_claim_and_schedule() {
    for reply in [
        ResultReply::Pending,
        ResultReply::Unknown,
        ResultReply::Failed,
    ] {
        let authority =
            Authority::start_with_results(true, true, [reply, ResultReply::Pending]).await;
        let fixture = fixture(&authority).await;
        let id = submitted(&fixture, "stale-result").await;
        accepted_due(&fixture, &authority, id).await;
        let mut workers = Vec::new();
        for index in 0..2 {
            if index == 1 {
                fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET lease_until=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
            }
            let pool = fixture.pool.clone();
            let registry = authority.registry.clone();
            let mutations = Arc::clone(&fixture.mutations);
            workers.push(tokio::spawn(async move {
                run_review_authority_once_for_test(&pool, &registry, &mutations).await
            }));
            authority.state.gates[index].reached().await;
        }
        let replacement = result_poll_job(&fixture, id).await;
        assert!(!replacement["lease"].is_null());
        assert_eq!(replacement["pollAttempts"], 0);
        assert!(
            !run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry,
                &fixture.mutations
            )
            .await
            .unwrap(),
            "the replacement claim excludes a third worker"
        );
        authority.state.gates[0].release.notify_one();
        let old = tokio::time::timeout(Duration::from_secs(5), workers.remove(0))
            .await
            .unwrap()
            .unwrap();
        if matches!(reply, ResultReply::Failed) {
            assert!(matches!(old, Err(MutationError::Unavailable)));
        } else {
            assert!(old.unwrap());
        }
        assert_eq!(result_poll_job(&fixture, id).await, replacement, "a stale completed lookup and its worker fallback preserve the replacement lease and schedule");
        authority.state.gates[1].release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), workers.remove(0))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
        let settled = result_poll_job(&fixture, id).await;
        assert!(settled["lease"].is_null());
        assert!(settled["error"].is_null());
        assert_eq!(
            settled["pollAttempts"], 1,
            "only the replacement spends a poll attempt"
        );
        assert_eq!(settled["binding"], replacement["binding"]);
        assert_eq!(result_count(&fixture).await, 0);
        assert_eq!(authority.state.requests.load(Ordering::SeqCst), 2);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn first_acceptance_refuses_wrong_policy_id_or_exact_pin() {
    for case in [
        "wrong-id",
        "wrong-version",
        "wrong-digest",
        "current-policy",
    ] {
        let authority = Authority::start(false, true).await;
        let selection = match case {
            "wrong-version" | "wrong-digest" => json!(policy()),
            _ => json!({"id":policy().id}),
        };
        let bindings = authority.registry.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            registry_with_policy(selection.clone()),
            claims(),
            move |service| service.with_review_result_source(bindings),
        )
        .await;
        let id = submitted(&fixture, case).await;
        let row = fixture.database.admin.query_one(
            "SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]
        ).await.unwrap();
        let request: ReviewCreateRequest = serde_json::from_value(row.get(0)).unwrap();
        let mut accepted_policy = policy();
        match case {
            "wrong-id" => accepted_policy.id = "another-policy".into(),
            "wrong-version" => accepted_policy.version = "2".into(),
            "wrong-digest" => {
                accepted_policy.digest = registry_review_client::ContentDigest::parse(&format!(
                    "sha256:{}",
                    "c".repeat(64)
                ))
                .unwrap();
            }
            "current-policy" => {
                accepted_policy.version = "2".into();
                accepted_policy.digest = registry_review_client::ContentDigest::parse(&format!(
                    "sha256:{}",
                    "c".repeat(64)
                ))
                .unwrap();
            }
            _ => unreachable!(),
        }
        let accepted = ReviewRequestAccepted {
            request_id: Uuid::new_v4(),
            subject: request.subject.clone(),
            policy: accepted_policy,
            submission_digest: registry_review_client::SubmissionDigest::parse(
                &row.get::<_, String>(1),
            )
            .unwrap(),
        };
        // The provider returns an otherwise correlated acceptance. Only its
        // concrete policy differs, so this exercises the Review client's
        // selection check before BReg can persist an accepted binding.
        *authority.state.accepted.lock().unwrap() = Some(accepted.clone());
        let client = fixture.pool.get_for_test().await.unwrap();
        assert!(run_one_submission(
            &**client,
            AUTHORITY,
            &authority.client,
            "producer",
            &BearerToken::new(OUTGOING_TOKEN).unwrap(),
            30
        )
        .await
        .unwrap());
        let delivered = job(&fixture, id).await;
        if case == "current-policy" {
            assert_eq!(delivered["state"], "accepted");
            assert_eq!(delivered["binding"], json!(accepted));
            assert!(delivered["error"].is_null());
        } else {
            assert_eq!(delivered["state"], "uncertain", "{case}");
            assert_eq!(delivered["error"], "remote-uncertain", "{case}");
            assert!(delivered["binding"].is_null(), "{case}");
        }
        assert!(delivered["lease"].is_null());
        assert_eq!(result_count(&fixture).await, 0);
        let target = &fixture.registry.entities()["target"];
        let names = fixture
            .database
            .admin
            .query(
                &format!(
                    "SELECT \"{}\" FROM registry_data.\"{}\"",
                    target.fields["name"].physical_name, target.physical_table
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].get::<_, String>(0), "Before");
        let frozen: Value = fixture.database.admin.query_one(
            "SELECT expected_policy FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]
        ).await.unwrap().get(0);
        assert_eq!(frozen, selection, "acceptance never rewrites the selector");
        let creates = authority.state.creates.lock().unwrap().clone();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].1, request);
        drop(client);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn current_policy_delivery_recovers_original_request_without_rewriting_frozen_identity() {
    let authority = Authority::start(false, false).await;
    let bindings = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry_with_policy(json!({"id":policy().id})),
        claims(),
        move |service| service.with_review_result_source(bindings),
    )
    .await;
    let id = submitted(&fixture, "current-policy").await;
    let before: Value = fixture.database.admin.query_one(
        "SELECT jsonb_build_object('request',create_request,'digest',expected_submission_digest,'proposalDigest',proposal_digest,'policy',expected_policy) FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]
    ).await.unwrap().get(0);
    let client = fixture.pool.get_for_test().await.unwrap();
    // The provider retains acceptance but returns an unavailable response.
    assert!(run_one_submission(
        &**client,
        AUTHORITY,
        &authority.client,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30
    )
    .await
    .unwrap());
    assert_ne!(job(&fixture, id).await["state"], "accepted");
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET next_attempt_at=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
    assert!(run_one_submission(
        &**client,
        AUTHORITY,
        &authority.client,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30
    )
    .await
    .unwrap());
    let accepted = job(&fixture, id).await;
    assert_eq!(accepted["state"], "accepted");
    assert_eq!(accepted["binding"]["policy"], json!(policy()));
    let after: Value = fixture.database.admin.query_one(
        "SELECT jsonb_build_object('request',create_request,'digest',expected_submission_digest,'proposalDigest',proposal_digest,'policy',expected_policy) FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]
    ).await.unwrap().get(0);
    assert_eq!(
        before, after,
        "acceptance must not repin the frozen request"
    );
    assert_eq!(after["policy"], json!({"id":policy().id}));
    let creates = authority.state.creates.lock().unwrap().clone();
    assert_eq!(creates.len(), 2);
    assert_eq!(
        creates[0], creates[1],
        "unknown-response recovery sends the same key and selector"
    );
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
async fn operator_resubmit_preserves_acceptance_and_refuses_replacement_after_provider_loss() {
    use registry_breg::{
        postgres::{ExpectedManagedCatalog, RegistryLockKey},
        proposal_retention::ProposalRetentionOperatorService,
        review_recovery::{ReviewRecoveryOperatorService, ReviewRecoveryScope},
    };
    for changed in ["none", "policy", "request"] {
        let authority = Authority::start(false, true).await;
        let bindings = authority.registry.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            registry_with_policy(json!({"id":policy().id})),
            claims(),
            move |service| service.with_review_result_source(bindings),
        )
        .await;
        let id = submitted(&fixture, changed).await;
        let client = fixture.pool.get_for_test().await.unwrap();
        let token = BearerToken::new(OUTGOING_TOKEN).unwrap();
        assert!(run_one_submission(
            &**client,
            AUTHORITY,
            &authority.client,
            "producer",
            &token,
            30
        )
        .await
        .unwrap());
        let accepted = authority.state.accepted.lock().unwrap().clone().unwrap();
        let frozen: Value = fixture.database.admin.query_one(
            "SELECT jsonb_build_object('request',create_request,'digest',expected_submission_digest,'proposalDigest',proposal_digest,'policy',expected_policy) FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]
        ).await.unwrap().get(0);
        // A completed result poll reported that the provider no longer knew
        // this request. Recover through the actual audited operator boundary.
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET last_error_code='result-unknown-to-authority' WHERE proposal_id=$1", &[&id]).await.unwrap();
        let operator = ReviewRecoveryOperatorService::over_retention_service_for_test(
            ProposalRetentionOperatorService::new_for_test(
                (*fixture.registry).clone(),
                fixture.identity.clone(),
                ExpectedManagedCatalog::compiled(&fixture.registry),
                RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
                fixture.database.migration_config.clone(),
                fixture.database.migration_role.clone(),
                fixture.database.runtime_role.clone(),
                fixture.database.activation_audit(),
            ),
        );
        operator
            .resubmit(ReviewRecoveryScope {
                action_id: "correct-name",
                proposal_id: id,
                submission_version: 1,
            })
            .await
            .unwrap();
        assert_eq!(job(&fixture, id).await["binding"], json!(accepted));
        let mut response = accepted.clone();
        match changed {
            "policy" => {
                response.policy = serde_json::from_value(json!({
                    "id":policy().id,"version":"2","digest":format!("sha256:{}", "c".repeat(64))
                }))
                .unwrap()
            }
            "request" => response.request_id = Uuid::new_v4(),
            _ => {}
        }
        *authority.state.accepted.lock().unwrap() = Some(response);
        assert!(run_one_submission(
            &**client,
            AUTHORITY,
            &authority.client,
            "producer",
            &token,
            30
        )
        .await
        .unwrap());
        let recovered = job(&fixture, id).await;
        assert_eq!(
            recovered["binding"],
            json!(accepted),
            "a retry never replaces a concrete acceptance"
        );
        if changed == "none" {
            assert_eq!(recovered["state"], "accepted");
        } else {
            assert_eq!(recovered["state"], "failed");
            assert_eq!(recovered["error"], "review-acceptance-changed");
        }
        let after: Value = fixture.database.admin.query_one(
            "SELECT jsonb_build_object('request',create_request,'digest',expected_submission_digest,'proposalDigest',proposal_digest,'policy',expected_policy) FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]
        ).await.unwrap().get(0);
        assert_eq!(
            after, frozen,
            "recovery does not repin the frozen selector or change its digest"
        );
        let creates = authority.state.creates.lock().unwrap().clone();
        assert_eq!(creates.len(), 2);
        assert_eq!(creates[0], creates[1]);
        assert_eq!(result_count(&fixture).await, 0);
        drop(client);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn native_submission_remote_refusal_warns_the_operator_without_values() {
    async fn refuse() -> Response {
        (
            StatusCode::FORBIDDEN,
            [
                ("content-type", "application/problem+json"),
                ("traceparent", TRACE),
            ],
            json!({"type":"https://review-provider.example.test/problems/producer/refused",
                "title":"Forbidden","status":403,"detail":"The producer is not allowed.",
                "code":"producer.refused","traceId":"0123456789abcdef0123456789abcdef"})
            .to_string(),
        )
            .into_response()
    }
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "remote-refusal").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/v1/review-requests", post(refuse)),
        )
        .await
        .unwrap();
    });
    let refusing = ReviewClient::new(ReviewClientConfig::new(endpoint.parse().unwrap())).unwrap();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let capture = tracing::subscriber::set_default(subscriber);
    let client = fixture.pool.get_for_test().await.unwrap();
    assert!(run_one_submission(
        &**client,
        AUTHORITY,
        &refusing,
        "producer",
        &BearerToken::new(OUTGOING_TOKEN).unwrap(),
        30
    )
    .await
    .unwrap());
    drop(capture);
    server.abort();
    let delivered = job(&fixture, id).await;
    assert_eq!(delivered["state"], "failed");
    assert_eq!(delivered["error"], "remote-refused");
    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let warning = output
        .lines()
        .find(|line| line.contains("\"level\":\"WARN\"") && line.contains("refused"))
        .unwrap_or_else(|| panic!("no remote-refusal warning in {output}"));
    assert!(warning.contains("\"status\":403"), "{warning}");
    assert!(
        warning.contains("\"problem_code\":\"producer.refused\""),
        "{warning}"
    );
    for canary in [
        OUTGOING_TOKEN,
        INCOMING_TOKEN,
        RECIPIENT,
        "The producer is not allowed.",
        &id.to_string(),
        "After",
    ] {
        assert!(
            !output.contains(canary),
            "remote-refusal log disclosed {canary}"
        );
    }
    drop(client);
    fixture.finish().await;
}

#[path = "support/review_uncertain_log.rs"]
mod review_uncertain_log;

#[cfg(feature = "tooling")]
#[path = "support/proposal_activation.rs"]
#[allow(dead_code)]
mod proposal_activation;
#[cfg(feature = "tooling")]
#[path = "support/review_go_live.rs"]
mod review_go_live;
