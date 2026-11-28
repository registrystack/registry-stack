// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn storage_installs_the_ask_mirror_answers_and_feed_checkpoint() {
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    for table in [
        "registry_proposal_review_asks",
        "registry_proposal_review_ask_answers",
        "registry_proposal_review_ask_feed_events",
        "registry_proposal_review_ask_feed_checkpoints",
    ] {
        let name = format!("registry_internal.{table}");
        let found: Option<String> = fixture
            .database
            .admin
            .query_one("SELECT to_regclass($1)::text", &[&name])
            .await
            .unwrap()
            .get(0);
        assert!(found.is_some(), "missing ask storage: {table}");
    }
    fixture.finish().await;
}

#[derive(Default)]
pub(super) struct FeedState {
    answer_status: u16,
    deliveries: Vec<(String, Value)>,
    entries: Vec<Value>,
    replies: BTreeMap<Uuid, (StatusCode, Value)>,
    feed_cursors: Vec<Option<Uuid>>,
}

pub(super) async fn feed(
    State(state): State<Arc<AuthorityState>>,
    axum::extract::Query(query): axum::extract::Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    assert_eq!(headers["authorization"], format!("Bearer {OUTGOING_TOKEN}"));
    assert_eq!(headers["registry-review-profile"], "producer");
    let cursor = query.get("cursor").map(|id| Uuid::parse_str(id).unwrap());
    let mut asks = state.asks.lock().unwrap();
    asks.feed_cursors.push(cursor);
    let start = cursor
        .and_then(|cursor| {
            asks.entries
                .iter()
                .position(|item| item["eventId"] == cursor.to_string())
                .map(|index| index + 1)
        })
        .unwrap_or(0);
    let items = &asks.entries[start..];
    response(StatusCode::OK, json!({"items":items}))
}

pub(super) async fn read(
    State(state): State<Arc<AuthorityState>>,
    AxumPath((_request, ask)): AxumPath<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    assert_eq!(headers["authorization"], format!("Bearer {OUTGOING_TOKEN}"));
    assert_eq!(headers["registry-review-profile"], "producer");
    let asks = state.asks.lock().unwrap();
    let (status, body) = asks.replies.get(&ask).unwrap();
    response(*status, body.clone())
}

fn announce(authority: &Authority, binding: &ReviewRequestAccepted) -> (Uuid, Uuid) {
    let ask = Uuid::new_v4();
    let event = Uuid::new_v4();
    let now = chrono::Utc::now();
    let mut state = authority.state.asks.lock().unwrap();
    state
        .entries
        .push(json!({"eventId":event,"requestId":binding.request_id,"askId":ask,"changedAt":now}));
    state.replies.insert(ask,(StatusCode::OK,json!({"askId":ask,"requestId":binding.request_id,"subject":binding.subject,"text":"Synthetic question, never in events","wants":[{"kind":"answer"}],"askedAt":now,"state":"open"})));
    (ask, event)
}

async fn worker(
    fixture: &client_http::ClientFixture,
    authority: &Authority,
) -> Result<bool, MutationError> {
    run_review_authority_once_for_test(&fixture.pool, &authority.registry, &fixture.mutations).await
}

#[tokio::test]
async fn ask_feed_mirrors_two_questions_once_and_bumps_two_revisions_without_changing_the_submission(
) {
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "ask-feed").await;
    let before = read_raw(&fixture, &format!("/v1/proposals/{id}")).await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (_, first) = announce(&authority, &binding);
    let (_, last) = announce(&authority, &binding);
    assert!(worker(&fixture, &authority).await.unwrap());
    let rows = fixture.database.admin.query("SELECT text,state FROM registry_internal.registry_proposal_review_asks WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(rows.len(), 2, "the worker must mirror both asks");
    let after = read_raw(&fixture, &format!("/v1/proposals/{id}")).await;
    assert_eq!(
        after["revision"].as_u64().unwrap(),
        before["revision"].as_u64().unwrap() + 2
    );
    assert_eq!(after["submissionVersion"], before["submissionVersion"]);
    assert_eq!(after["effectDigest"], before["effectDigest"]);
    assert_eq!(after["state"], "submitted");
    let events = fixture.database.admin.query("SELECT event_id,payload FROM registry_internal.registry_outbox WHERE event_type='proposal.asked'",&[]).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_ne!(events[0].get::<_, Uuid>(0), events[1].get::<_, Uuid>(0));
    assert!(!format!("{events:?}").contains("Synthetic question"));
    worker(&fixture, &authority).await.unwrap();
    let cursor: Uuid = fixture
        .database
        .admin
        .query_one(
            "SELECT cursor FROM registry_internal.registry_proposal_review_ask_feed_checkpoints",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_ne!(first, last);
    assert_eq!(cursor, last);
    assert_eq!(
        read_raw(&fixture, &format!("/v1/proposals/{id}")).await["revision"],
        after["revision"]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn ask_feed_skips_unknown_and_bad_bindings_but_transient_reads_leave_the_page_uncommitted() {
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "ask-feed-failures").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let mut unknown = binding.clone();
    unknown.request_id = Uuid::new_v4();
    announce(&authority, &unknown);
    let (bad, _) = announce(&authority, &binding);
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .get_mut(&bad)
        .unwrap()
        .1["subject"]["id"] = json!("other-proposal");
    let (retry, last) = announce(&authority, &binding);
    let good = authority.state.asks.lock().unwrap().replies[&retry].clone();
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .insert(retry, (StatusCode::TOO_MANY_REQUESTS, json!({})));
    assert!(
        worker(&fixture, &authority).await.is_err(),
        "429 must stop this page"
    );
    let counts=fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_proposal_review_ask_feed_events),(SELECT count(*) FROM registry_internal.registry_proposal_review_ask_feed_checkpoints)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 0);
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .insert(retry, good);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    worker(&fixture, &authority).await.unwrap();
    let states:Vec<String>=fixture.database.admin.query("SELECT state FROM registry_internal.registry_proposal_review_ask_feed_events ORDER BY state",&[]).await.unwrap().iter().map(|r|r.get(0)).collect();
    assert_eq!(states, vec!["mirrored", "refused", "unknown"]);
    assert_eq!(fixture.database.admin.query_one("SELECT cursor FROM registry_internal.registry_proposal_review_ask_feed_checkpoints",&[]).await.unwrap().get::<_,Uuid>(0),last);
    fixture.finish().await;
}

#[tokio::test]
async fn ask_feed_turn_uses_the_shared_awaiting_party_rule_and_lists_only_live_unanswered_asks() {
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    let id = submitted(&fixture, "ask-turn").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    let value = read_raw(&fixture, &format!("/v1/proposals/{id}")).await;
    assert_eq!(value["status"], "awaiting-party");
    assert_eq!(value["turn"], "party");
    let page = read_raw(&fixture, "/v1/proposals?turn=party").await;
    assert!(page["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == id.to_string()));
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_asks SET state='answered',answered_at=transaction_timestamp() WHERE ask_id=$1",&[&ask]).await.unwrap();
    let value = read_raw(&fixture, &format!("/v1/proposals/{id}")).await;
    assert_eq!(value["status"], "in-review");
    assert_eq!(value["turn"], "official");
    assert!(
        read_raw(&fixture, "/v1/proposals?turn=party").await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fixture.finish().await;
}

async fn answer_fixture(authority: &Authority) -> client_http::ClientFixture {
    let mut source = registry_source(json!(policy()));
    source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("answer"));
    source["actions"]["correct-name"]["execution"]["proposal"]["reviewContext"] =
        json!({"id":"ask-context","fields":{"value":{"type":"input","input":"value"}}});
    source["actions"]["correct-name"]["execution"]["proposal"]["additions"] = json!({"id":"other","maximumBytes":1024,"maximumCount":8,"contentTypes":["text/plain"],"classification":"internal"});
    let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["proposals"][0];
    grant["operations"].as_array_mut().unwrap().extend([
        json!("get-review-context"),
        json!("add"),
        json!("revise"),
        json!("rebase"),
    ]);
    grant["readableContextFields"] = json!(["value"]);
    grant["readableAttachments"] = json!(["other"]);
    grant["writableAttachments"] = json!(["other"]);
    let mut reviewer = source["accessProfiles"]["clerk"].clone();
    reviewer["default"] = json!(false);
    reviewer["requiredScopes"] = json!(["proposal:review"]);
    let grant = &mut reviewer["permissions"]["proposals"][0];
    grant["operations"] = json!(["get-review-context"]);
    grant.as_object_mut().unwrap().remove("ownership");
    grant["readableAttachments"] = json!([]);
    grant["writableAttachments"] = json!([]);
    source["accessProfiles"]["reviewer"] = reviewer;
    let mut writer = source["accessProfiles"]["clerk"].clone();
    writer["default"] = json!(false);
    writer["permissions"]["proposals"][0]["operations"] =
        json!(["list", "answer", "get-review-status"]);
    writer["permissions"]["proposals"][0]["readableContextFields"] = json!([]);
    writer["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
    writer["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    source["accessProfiles"]["writer"] = writer;
    source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    let bindings = authority.registry.clone();
    client_http::ClientFixture::start_with_mutations(registry, claims(), move |service| {
        service.with_review_result_source(bindings)
    })
    .await
}

async fn request(
    fixture: &client_http::ClientFixture,
    method: &str,
    path: &str,
    etag: Option<&str>,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(etag) = etag {
        req = req.header("if-match", etag);
    }
    if let Some(key) = key {
        req = req.header("idempotency-key", key);
    }
    let response = registry_breg::api::router(fixture.service())
        .layer(axum::Extension(claims()))
        .oneshot(
            req.body(if method == "GET" {
                axum::body::Body::empty()
            } else {
                axum::body::Body::from(serde_json::to_vec(&body).unwrap())
            })
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, value)
}

#[tokio::test]
async fn answer_command_commits_once_with_a_new_etag_and_its_own_delivery_deadline() {
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "answer-command").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    // An accepted review may be older than the submission recovery deadline.
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET recovery_deadline=transaction_timestamp()-interval '1 day' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let (_, before_headers, before) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let etag = before_headers["etag"].to_str().unwrap();
    let path = format!("/v1/proposals/{id}/asks/{ask}/answer");
    let body = json!({"text":"Synthetic answer must stay out of events and audit"});
    let (status, headers, after) = request(
        &fixture,
        "POST",
        &path,
        Some(etag),
        Some("answer-once"),
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["state"], "submitted");
    assert_eq!(after["submissionVersion"], before["submissionVersion"]);
    assert_eq!(after["effectDigest"], before["effectDigest"]);
    assert_ne!(headers["etag"], before_headers["etag"]);
    assert_eq!(
        after["revision"].as_u64().unwrap(),
        before["revision"].as_u64().unwrap() + 1
    );
    assert_eq!(after["status"], "in-review");
    assert_eq!(after["turn"], "official");
    let replay = request(
        &fixture,
        "POST",
        &path,
        Some(etag),
        Some("answer-once"),
        body,
    )
    .await;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.2, after);
    assert_eq!(replay.1["etag"], headers["etag"]);
    let conflict = request(
        &fixture,
        "POST",
        &path,
        Some(etag),
        Some("answer-once"),
        json!({"text":"Other answer"}),
    )
    .await;
    assert_eq!(conflict.0, StatusCode::CONFLICT);
    assert_eq!(conflict.2["code"], "idempotency.key-reused");
    assert_eq!(
        request(
            &fixture,
            "POST",
            &path,
            Some(etag),
            Some("stale-answer"),
            json!({"text":"Other answer"})
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    let row=fixture.database.admin.query_one("SELECT text,delivery_state,delivery_deadline>transaction_timestamp()+interval '6 days',answered_by IS NOT NULL FROM registry_internal.registry_proposal_review_ask_answers WHERE ask_id=$1",&[&ask]).await.unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "Synthetic answer must stay out of events and audit"
    );
    assert_eq!(row.get::<_, String>(1), "pending");
    assert!(row.get::<_, bool>(2));
    assert!(row.get::<_, bool>(3));
    let events=fixture.database.admin.query("SELECT payload FROM registry_internal.registry_outbox WHERE event_type='proposal.answered'",&[]).await.unwrap();
    assert_eq!(events.len(), 1);
    assert!(!format!("{events:?}").contains("Synthetic answer"));
    fixture.finish().await;
}

pub(super) async fn answer_remote(
    State(state): State<Arc<AuthorityState>>,
    AxumPath((_request, ask)): AxumPath<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    authenticated(&headers);
    assert_eq!(
        body.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["answeredAt", "subject"]
    );
    let mut asks = state.asks.lock().unwrap();
    asks.deliveries.push((
        headers["idempotency-key"].to_str().unwrap().into(),
        body.clone(),
    ));
    let status = StatusCode::from_u16(if asks.answer_status == 0 {
        200
    } else {
        asks.answer_status
    })
    .unwrap();
    if status == StatusCode::NOT_FOUND {
        return (status, [("traceparent", TRACE)]).into_response();
    }
    if status == StatusCode::OK {
        let mut reply = asks.replies[&ask].1.clone();
        reply["state"] = json!("answered");
        reply["answeredAt"] = body["answeredAt"].clone();
        reply.as_object_mut().unwrap().remove("closedAt");
        return response(status, reply);
    }
    let code = if status == StatusCode::CONFLICT {
        "review.ask-not-open"
    } else {
        "review.refused"
    };
    (status,[("content-type","application/problem+json"),("traceparent",TRACE)],serde_json::to_vec(&json!({"type":format!("https://review.example.test/problems/{code}"),"title":"Refused","status":status.as_u16(),"detail":"Synthetic refusal","code":code,"traceId":"0123456789abcdef0123456789abcdef"})).unwrap()).into_response()
}

async fn committed_answer(
    authority: &Authority,
    key: &str,
) -> (client_http::ClientFixture, Uuid, Uuid) {
    let fixture = answer_fixture(authority).await;
    let id = submitted(&fixture, key).await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    *authority.state.accepted.lock().unwrap() = Some(binding.clone());
    let (ask, _) = announce(authority, &binding);
    worker(&fixture, authority).await.unwrap();
    let (_, headers, _) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let answered = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("commit-local-answer"),
        json!({"text":"private-answer-not-in-outbound-request"}),
    )
    .await;
    assert_eq!(answered.0, StatusCode::OK, "{}", answered.2);
    (fixture, id, ask)
}
async fn delivery(fixture: &client_http::ClientFixture, ask: Uuid) -> Value {
    fixture.database.admin.query_one("SELECT jsonb_build_object('state',delivery_state,'error',last_error_code,'attempts',attempt_count,'answeredAt',answered_at,'deadline',delivery_deadline) FROM registry_internal.registry_proposal_review_ask_answers WHERE ask_id=$1",&[&ask]).await.unwrap().get(0)
}

#[tokio::test]
async fn stored_on_time_answers_deliver_after_remote_expiry_and_an_old_submission_deadline() {
    let authority = Authority::start(false, true).await;
    let (fixture, id, ask) = committed_answer(&authority, "deliver-answer").await;
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET recovery_deadline=transaction_timestamp()-interval '1 day' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let before = delivery(&fixture, ask).await;
    {
        let mut state = authority.state.asks.lock().unwrap();
        let reply = &mut state.replies.get_mut(&ask).unwrap().1;
        let due: chrono::DateTime<chrono::Utc> =
            before["answeredAt"].as_str().unwrap().parse().unwrap();
        reply["dueAt"] = json!(due);
        reply["closedAt"] = json!(due + chrono::Duration::microseconds(1));
        reply["state"] = json!("expired");
        let request = reply["requestId"].clone();
        state.entries.push(json!({"eventId":Uuid::new_v4(),"requestId":request,"askId":ask,"changedAt":due+chrono::Duration::microseconds(1)}));
    }
    worker(&fixture, &authority).await.unwrap();
    assert_eq!(delivery(&fixture, ask).await["state"], "delivered");
    {
        let state = authority.state.asks.lock().unwrap();
        assert_eq!(state.deliveries.len(), 1);
        assert_eq!(
            state.deliveries[0].1["answeredAt"]
                .as_str()
                .unwrap()
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
            before["answeredAt"]
                .as_str()
                .unwrap()
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
        );
        assert!(!state.deliveries[0].1.to_string().contains("private-answer"));
    }
    fixture.finish().await;
}

#[tokio::test]
async fn answer_delivery_retries_transient_exchanges_with_the_exact_key_and_stored_time() {
    for status in [429, 503, 201] {
        let authority = Authority::start(false, true).await;
        let (fixture, _, ask) = committed_answer(&authority, "retry-answer").await;
        authority.state.asks.lock().unwrap().answer_status = status;
        let _ = worker(&fixture, &authority).await;
        assert_eq!(delivery(&fixture, ask).await["attempts"], 1);
        assert_eq!(delivery(&fixture, ask).await["state"], "pending");
        authority.state.asks.lock().unwrap().answer_status = 200;
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_ask_answers SET next_attempt_at=transaction_timestamp() WHERE ask_id=$1",&[&ask]).await.unwrap();
        worker(&fixture, &authority).await.unwrap();
        assert_eq!(delivery(&fixture, ask).await["state"], "delivered");
        {
            let state = authority.state.asks.lock().unwrap();
            assert_eq!(state.deliveries.len(), 2);
            assert_eq!(state.deliveries[0], state.deliveries[1]);
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn deterministic_answer_delivery_refusals_keep_the_local_answer_without_retrying() {
    for (status, code) in [
        (409, "review.ask-not-open"),
        (404, "ask-concealed-or-unknown"),
        (422, "review.refused"),
    ] {
        let authority = Authority::start(false, true).await;
        let (fixture, _, ask) = committed_answer(&authority, "refused-answer").await;
        authority.state.asks.lock().unwrap().answer_status = status;
        worker(&fixture, &authority).await.unwrap();
        let job = delivery(&fixture, ask).await;
        assert_eq!(job["state"], "refused");
        assert_eq!(job["error"], code);
        assert!(fixture.database.admin.query_one("SELECT text IS NOT NULL FROM registry_internal.registry_proposal_review_ask_answers WHERE ask_id=$1",&[&ask]).await.unwrap().get::<_,bool>(0));
        worker(&fixture, &authority).await.unwrap();
        assert_eq!(authority.state.asks.lock().unwrap().deliveries.len(), 1);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn cancelling_a_submission_closes_its_asks_and_supersedes_its_pending_answers() {
    let authority = Authority::start(false, true).await;
    let (fixture, id, ask) = committed_answer(&authority, "cancel-answer").await;
    let (_, headers, _) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let cancelled = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/cancel"),
        Some(headers["etag"].to_str().unwrap()),
        Some("cancel-with-answer"),
        json!({}),
    )
    .await;
    assert_eq!(cancelled.0, StatusCode::OK, "{}", cancelled.2);
    assert_eq!(delivery(&fixture, ask).await["state"], "superseded");
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT state FROM registry_internal.registry_proposal_review_asks WHERE ask_id=$1",
                &[&ask]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "closed"
    );
    worker(&fixture, &authority).await.unwrap();
    assert!(authority.state.asks.lock().unwrap().deliveries.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn applicant_asks_require_get_even_on_a_command_response_and_report_the_answered_reason() {
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "ask-disclosure").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    let (_, _, value) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(value["asks"][0]["id"], ask.to_string());
    assert_eq!(
        value["asks"][0]["text"],
        "Synthetic question, never in events"
    );
    assert_eq!(
        value["asks"][0]["links"]["answer"]["availability"]["available"],
        true
    );
    let (_, _, page) = request(
        &fixture,
        "GET",
        "/v1/proposals?accessProfile=writer",
        None,
        None,
        Value::Null,
    )
    .await;
    assert!(page["items"][0].get("asks").is_none());
    let (status, headers, status_doc) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}/review-status?accessProfile=writer"),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{status_doc}");
    let answered = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer?accessProfile=writer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("answer-as-writer"),
        json!({"text":"private command answer"}),
    )
    .await;
    assert_eq!(answered.0, StatusCode::OK, "{}", answered.2);
    assert!(answered.2.get("asks").is_none());
    let (_, _, read) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(read["asks"][0]["state"], "answered");
    assert_eq!(read["asks"][0]["answer"]["text"], "private command answer");
    assert_eq!(
        read["asks"][0]["links"]["answer"]["availability"]["reason"],
        "ask-answered"
    );
    assert_eq!(
        read["asks"][0]["links"]["answer"]["availability"]["recovery"],
        "receipt-only"
    );
    fixture.finish().await;
}

fn reviewer_claims(jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "sub",
        "reviewer-own-subject",
        BTreeSet::from(["proposal:review".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
    )
    .unwrap()
}
async fn reviewer_get(
    fixture: &client_http::ClientFixture,
    path: &str,
    jurisdiction: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    use tower::ServiceExt;
    let response = registry_breg::api::router(fixture.service())
        .layer(axum::Extension(reviewer_claims(jurisdiction)))
        .oneshot(
            axum::http::Request::get(path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

#[tokio::test]
async fn intrinsic_review_context_shows_the_answer_outside_the_authored_fields() {
    let authority = Authority::start(false, true).await;
    let (fixture, id, ask) = committed_answer(&authority, "review-answer-context").await;
    let (status, _, bytes) = reviewer_get(
        &fixture,
        &format!("/v1/proposals/{id}/review-context?accessProfile=reviewer"),
        "zone-a",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["context"]["fields"], json!({"value":"After"}));
    assert_eq!(value["context"]["asks"][0]["id"], ask.to_string());
    assert_eq!(
        value["context"]["asks"][0]["answer"]["text"],
        "private-answer-not-in-outbound-request"
    );
    assert_eq!(
        value["context"]["asks"][0]["answer"]["documents"],
        json!([])
    );
    assert!(!value.to_string().contains("reviewer-own-subject"));
    let schema = registry_breg::compiler::review_context::compile_schema(
        &fixture.registry,
        &fixture.registry.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    assert!(
        schema.schema["properties"].get("asks").is_none(),
        "intrinsic asks cannot collide with authored field IDs"
    );
    let denied = reviewer_get(
        &fixture,
        &format!("/v1/proposals/{id}/review-context?accessProfile=reviewer"),
        "zone-b",
    )
    .await;
    assert_eq!(denied.0, StatusCode::NOT_FOUND);
    fixture.finish().await;
}

#[tokio::test]
async fn serving_questions_marks_get_list_and_command_audit_without_recording_text() {
    let authority = Authority::start(false, true).await;
    let (fixture, id, ask) = committed_answer(&authority, "ask-audit").await;
    for path in [format!("/v1/proposals/{id}"), "/v1/proposals".into()] {
        let before = fixture.audit_capture.entries().len();
        let read = request(&fixture, "GET", &path, None, None, Value::Null).await;
        assert_eq!(read.0, StatusCode::OK);
        let entries = fixture.audit_capture.entries();
        assert!(entries[before..]
            .iter()
            .any(
                |entry| entry["record"]["fieldSetReference"] == "proposal-review-ask"
                    || entry["record"]["askFieldSetReference"] == "proposal-review-ask"
            ));
    }
    let entries = fixture.audit_capture.entries();
    let committed = entries
        .iter()
        .find(|entry| {
            entry["record"]["operationId"] == "proposals.correct-name.answer"
                && entry["record"]["outcome"] == "committed"
        })
        .unwrap();
    assert_eq!(committed["record"]["reviewAskId"], ask.to_string());
    assert_eq!(committed["record"]["citedAdditionIds"], json!([]));
    assert_eq!(
        committed["record"]["askFieldSetReference"],
        "proposal-review-ask"
    );
    let journal = serde_json::to_string(&entries).unwrap();
    assert!(!journal.contains("private-answer-not-in-outbound-request"));
    assert!(!journal.contains("Synthetic question"));
    fixture.finish().await;
}

async fn add_file(fixture: &client_http::ClientFixture, id: Uuid, key: &str, bytes: &[u8]) -> Uuid {
    use tower::ServiceExt;
    let (_, headers, _) = request(
        fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let response = registry_breg::api::router(fixture.service())
        .layer(axum::Extension(claims()))
        .oneshot(
            axum::http::Request::post(format!("/v1/proposals/{id}/additions/other"))
                .header("content-type", "text/plain")
                .header("if-match", headers["etag"].clone())
                .header("idempotency-key", key)
                .body(axum::body::Body::from(bytes.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let item = value["additions"]["other"]["items"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    Uuid::parse_str(item["id"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn ask_bound_file_download_discloses_only_cited_verified_files_of_this_review_binding_and_audits_why(
) {
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "review-cited-file").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .get_mut(&ask)
        .unwrap()
        .1["wants"] = json!([{"kind":"answer"},{"kind":"document"}]);
    worker(&fixture, &authority).await.unwrap();
    let cited = add_file(&fixture, id, "cited-file", b"cited bytes").await;
    let other_file = add_file(&fixture, id, "uncited-file", b"uncited bytes").await;
    let (_, headers, _) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let answered = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("cite-document"),
        json!({"text":"The requested statement","additions":[cited]}),
    )
    .await;
    assert_eq!(answered.0, StatusCode::OK, "{}", answered.2);
    let context = reviewer_get(
        &fixture,
        &format!("/v1/proposals/{id}/review-context?accessProfile=reviewer"),
        "zone-a",
    )
    .await;
    assert_eq!(
        context.0,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&context.2)
    );
    let value: Value = serde_json::from_slice(&context.2).unwrap();
    assert_eq!(value["context"]["fields"], json!({"value":"After"}));
    let documents = value["context"]["asks"][0]["answer"]["documents"]
        .as_array()
        .unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["id"], cited.to_string());
    let path = format!(
        "{}&accessProfile=reviewer",
        documents[0]["download"]["path"].as_str().unwrap()
    );
    let before = fixture.audit_capture.entries().len();
    let downloaded = reviewer_get(&fixture, &path, "zone-a").await;
    assert_eq!(
        downloaded.0,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&downloaded.2)
    );
    assert_eq!(downloaded.2, b"cited bytes");
    assert_eq!(downloaded.1["content-type"], "text/plain");
    assert_eq!(downloaded.1["x-content-type-options"], "nosniff");
    assert_eq!(downloaded.1["cache-control"], "no-store");
    assert!(downloaded.1["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("attachment"));
    let entries = fixture.audit_capture.entries();
    let terminal = entries[before..]
        .iter()
        .find(|entry| entry["record"]["phase"] == "terminal")
        .unwrap();
    assert_eq!(terminal["record"]["reviewAskId"], ask.to_string());
    assert_eq!(terminal["record"]["additionId"], cited.to_string());
    assert!(terminal["record"]["principalReference"].is_string());
    let answered_audit = entries
        .iter()
        .find(|entry| {
            entry["record"]["outcome"] == "committed"
                && entry["record"]["operationId"] == "proposals.correct-name.answer"
        })
        .unwrap();
    assert_eq!(answered_audit["record"]["citedAdditionIds"], json!([cited]));
    let other = submitted(&fixture, "other-review").await;
    let other_binding = retained_binding(&fixture, other).await;
    accept(&fixture, other, &other_binding).await;
    let (other_ask, _) = announce(&authority, &other_binding);
    worker(&fixture, &authority).await.unwrap();
    for denied in [
        path.replace(&cited.to_string(), &other_file.to_string()),
        path.replace("submissionVersion=1", "submissionVersion=2"),
        path.replace(&ask.to_string(), &other_ask.to_string()),
    ] {
        assert_eq!(
            reviewer_get(&fixture, &denied, "zone-a").await.0,
            StatusCode::NOT_FOUND,
            "{denied}"
        );
    }
    assert_eq!(
        reviewer_get(&fixture, &path, "zone-b").await.0,
        StatusCode::NOT_FOUND
    );
    let journal = serde_json::to_string(&fixture.audit_capture.entries()).unwrap();
    assert!(!journal.contains("The requested statement"));
    assert!(!journal.contains("cited bytes"));
    fixture.finish().await;
}

#[tokio::test]
async fn operator_erasure_counts_and_scrubs_question_answer_actor_and_cited_files_per_version() {
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "erase-ask-details").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    *authority.state.accepted.lock().unwrap() = Some(binding.clone());
    let (ask, _) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    let file = add_file(&fixture, id, "erase-answer-file", b"retained answer bytes").await;
    let (_, headers, _) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let answered = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("answer-for-erasure"),
        json!({"text":"erase this answer","additions":[file]}),
    )
    .await;
    assert_eq!(answered.0, StatusCode::OK);
    let (mut migration, task) = fixture.database.connect_migration().await;
    let scope = registry_breg::proposal_retention::ProposalDetailErasureScope {
        action_id: "correct-name",
        proposal_id: id,
        submission_version: 1,
    };
    assert!(matches!(
        registry_breg::proposal_retention::erase_proposal_detail(
            &mut migration,
            &fixture.registry,
            scope.clone()
        )
        .await,
        Err(registry_breg::proposal_retention::ProposalRetentionError::ActiveDetailPinned)
    ));
    let (_, headers, _) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let cancelled = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/cancel"),
        Some(headers["etag"].to_str().unwrap()),
        Some("cancel-for-erasure"),
        json!({}),
    )
    .await;
    assert_eq!(cancelled.0, StatusCode::OK);
    worker(&fixture, &authority).await.unwrap();
    let erasure = registry_breg::proposal_retention::erase_proposal_detail(
        &mut migration,
        &fixture.registry,
        scope,
    )
    .await
    .unwrap();
    let counts = serde_json::to_value(erasure).unwrap();
    assert_eq!(counts["reviewAsks"], 1);
    assert_eq!(counts["reviewAnswers"], 1);
    assert_eq!(counts["reviewAnswerFiles"], 1);
    assert_eq!(erasure.attachment_references, 1);
    let row=fixture.database.admin.query_one("SELECT (SELECT text IS NULL FROM registry_internal.registry_proposal_review_asks WHERE ask_id=$1),(SELECT text IS NULL AND answered_by IS NULL AND delivery_state='superseded' AND answered_at IS NOT NULL FROM registry_internal.registry_proposal_review_ask_answers WHERE ask_id=$1),(SELECT count(*) FROM registry_internal.registry_proposal_review_ask_files),(SELECT count(*) FROM registry_internal.registry_proposal_additions WHERE erased_at IS NULL),(SELECT count(*) FROM registry_internal.registry_attachment_blobs)",&[&ask]).await.unwrap();
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, bool>(1));
    for index in 2..5 {
        assert_eq!(row.get::<_, i64>(index), 0);
    }
    drop(migration);
    task.abort();
    fixture.finish().await;
}

#[tokio::test]
async fn answer_refusals_name_only_fields_and_preserve_the_open_ask() {
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "answer-refusals").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .get_mut(&ask)
        .unwrap()
        .1["wants"] = json!([{"kind":"answer"},{"kind":"document"}]);
    worker(&fixture, &authority).await.unwrap();
    let file = add_file(&fixture, id, "answer-file", b"cited bytes").await;
    let (_, headers, before) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let etag = headers["etag"].to_str().unwrap();
    let path = format!("/v1/proposals/{id}/asks/{ask}/answer");
    for (index, body, field) in [
        (0, json!({"additions":[file]}), Some("/text")),
        (1, json!({"text":"  ","additions":[file]}), Some("/text")),
        (2, json!({"text":null,"additions":[file]}), Some("/text")),
        (3, json!({"text":"explanation"}), Some("/additions")),
        (
            4,
            json!({"text":"explanation","additions":[file,file]}),
            Some("/additions"),
        ),
        (
            5,
            json!({"text":"explanation","additions":[Uuid::new_v4()]}),
            Some("/additions"),
        ),
        (
            6,
            json!({"text":"explanation","additions":[file],"unknown":"secret"}),
            None,
        ),
    ] {
        let response = request(
            &fixture,
            "POST",
            &path,
            Some(etag),
            Some(&format!("invalid-answer-{index}")),
            body,
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST, "{}", response.2);
        assert_eq!(response.2["code"], "request.invalid");
        if let Some(field) = field {
            assert_eq!(response.2["fieldPath"], field);
        }
        assert!(!response.2.to_string().contains("cited bytes"));
    }
    let unchanged = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(unchanged.2["revision"], before["revision"]);
    // A file predating the question cannot satisfy a document want.
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_additions SET added_at=transaction_timestamp()-interval '2 days' WHERE addition_id=$1",&[&file]).await.unwrap();
    let too_old = request(
        &fixture,
        "POST",
        &path,
        Some(etag),
        Some("pre-ask-file"),
        json!({"text":"explanation","additions":[file]}),
    )
    .await;
    assert_eq!(too_old.0, StatusCode::BAD_REQUEST);
    assert_eq!(too_old.2["fieldPath"], "/additions");
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_additions SET added_at=transaction_timestamp() WHERE addition_id=$1",&[&file]).await.unwrap();
    let accepted = request(
        &fixture,
        "POST",
        &path,
        Some(etag),
        Some("valid-text-document"),
        json!({"text":"explanation","additions":[file]}),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.2);
    let again = request(
        &fixture,
        "POST",
        &path,
        Some(accepted.1["etag"].to_str().unwrap()),
        Some("second-answer"),
        json!({"text":"again","additions":[file]}),
    )
    .await;
    assert_eq!(again.0, StatusCode::PRECONDITION_FAILED);
    let (second, _) = announce(&authority, &binding);
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .get_mut(&second)
        .unwrap()
        .1["askedAt"] = json!((chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339());
    worker(&fixture, &authority).await.unwrap();
    let (_, headers, _) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    let reused = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{second}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("reused-citation"),
        json!({"text":"second explanation","additions":[file]}),
    )
    .await;
    assert_eq!(reused.0, StatusCode::BAD_REQUEST);
    assert_eq!(reused.2["fieldPath"], "/additions");
    fixture.finish().await;
}

#[tokio::test]
async fn due_and_closed_asks_have_typed_receipt_only_links_and_refuse_fresh_commands() {
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "answer-due").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    for (state, reason) in [("open", "ask-due-passed"), ("closed", "ask-closed")] {
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_asks SET state=$2,asked_at=transaction_timestamp()-interval '2 days',asked_at_wire=$3,due_at=transaction_timestamp()-interval '1 day',due_at_wire=$4 WHERE ask_id=$1",&[&ask,&state,&(chrono::Utc::now()-chrono::Duration::days(2)).to_rfc3339(),&(chrono::Utc::now()-chrono::Duration::days(1)).to_rfc3339()]).await.unwrap();
        let (_, headers, document) = request(
            &fixture,
            "GET",
            &format!("/v1/proposals/{id}"),
            None,
            None,
            Value::Null,
        )
        .await;
        let availability = &document["asks"][0]["links"]["answer"]["availability"];
        assert_eq!(availability["available"], false);
        assert_eq!(availability["reason"], reason);
        assert_eq!(availability["recovery"], "receipt-only");
        assert_eq!(document["status"], "in-review");
        let response = request(
            &fixture,
            "POST",
            &format!("/v1/proposals/{id}/asks/{ask}/answer"),
            Some(headers["etag"].to_str().unwrap()),
            Some(reason),
            json!({"text":"valid"}),
        )
        .await;
        assert_eq!(
            response.0,
            StatusCode::PRECONDITION_FAILED,
            "{}",
            response.2
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn expired_answer_deadlines_refuse_without_sending_or_erasing_local_detail() {
    let authority = Authority::start(false, true).await;
    let (fixture, _, ask) = committed_answer(&authority, "answer-deadline").await;
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_ask_answers SET answered_at=transaction_timestamp()-interval '2 days',delivery_deadline=transaction_timestamp()-interval '1 day' WHERE ask_id=$1",&[&ask]).await.unwrap();
    worker(&fixture, &authority).await.unwrap();
    let row=fixture.database.admin.query_one("SELECT delivery_state,last_error_code,text,attempt_count FROM registry_internal.registry_proposal_review_ask_answers WHERE ask_id=$1",&[&ask]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "refused");
    assert_eq!(row.get::<_, String>(1), "answer-delivery-expired");
    assert!(row.get::<_, Option<String>>(2).is_some());
    assert_eq!(row.get::<_, i32>(3), 0);
    assert!(authority.state.asks.lock().unwrap().deliveries.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn revise_and_rebase_supersede_answers_and_hide_the_previous_round() {
    for operation in ["revise", "rebase"] {
        let authority = Authority::start(false, true).await;
        let (fixture, id, ask) = committed_answer(&authority, operation).await;
        let (_, headers, prior) = request(
            &fixture,
            "GET",
            &format!("/v1/proposals/{id}"),
            None,
            None,
            Value::Null,
        )
        .await;
        let draft = request(
            &fixture,
            "POST",
            &format!("/v1/proposals/{id}/{operation}"),
            Some(headers["etag"].to_str().unwrap()),
            Some(operation),
            json!({"input":prior["input"]}),
        )
        .await;
        assert_eq!(draft.0, StatusCode::OK, "{}", draft.2);
        assert_eq!(draft.2["state"], "draft");
        assert!(draft.2.get("asks").is_none());
        assert_eq!(delivery(&fixture, ask).await["state"], "superseded");
        let denied = request(
            &fixture,
            "POST",
            &format!("/v1/proposals/{id}/asks/{ask}/answer"),
            Some(draft.1["etag"].to_str().unwrap()),
            Some("old-round-answer"),
            json!({"text":"Again"}),
        )
        .await;
        assert_eq!(denied.0, StatusCode::PRECONDITION_FAILED);
        worker(&fixture, &authority).await.unwrap();
        assert!(authority.state.asks.lock().unwrap().deliveries.is_empty());
        fixture.finish().await;
    }
}
