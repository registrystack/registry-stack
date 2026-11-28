// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn answering_requires_the_human_owner_operation_and_current_row_boundary() {
    use registry_platform_oidc::ActorKind;
    let authority = Authority::start(false, true).await;
    let (fixture, _, _) = agent_answer_fixture(&authority).await;
    let id = submitted(&fixture, "answer-authority").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    let (_, headers, before) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    for (key, profile, caller) in [
        (
            "wrong-grant",
            "staff",
            caller_claims("author-canary", ActorKind::Human),
        ),
        (
            "non-owner",
            "clerk",
            caller_claims("other-applicant", ActorKind::Human),
        ),
        (
            "agent",
            "clerk",
            caller_claims("author-canary", ActorKind::Agent),
        ),
    ] {
        let refused = request_as(
            &fixture,
            caller,
            "POST",
            &format!("/v1/proposals/{id}/asks/{ask}/answer?accessProfile={profile}"),
            Some(headers["etag"].to_str().unwrap()),
            Some(key),
            json!({"text":"unauthorized"}),
        )
        .await;
        assert_eq!(refused.0, StatusCode::NOT_FOUND, "{key}: {}", refused.2);
        assert_eq!(refused.2["code"], "resource.not_found", "{key}");
    }
    let other = submitted(&fixture, "another-ask-owner").await;
    let other_binding = retained_binding(&fixture, other).await;
    accept(&fixture, other, &other_binding).await;
    let (foreign_ask, _) = announce(&authority, &other_binding);
    worker(&fixture, &authority).await.unwrap();
    let foreign = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{foreign_ask}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("foreign-ask"),
        json!({"text":"unauthorized"}),
    )
    .await;
    assert_eq!(foreign.0, StatusCode::NOT_FOUND, "{}", foreign.2);
    assert_eq!(foreign.2["code"], "resource.not_found");
    let target = Uuid::parse_str(before["input"]["target"].as_str().unwrap()).unwrap();
    let entity = &fixture.registry.entities()["target"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"=$2 WHERE record_id=$1",
                entity.physical_table, entity.fields["jurisdiction"].physical_name
            ),
            &[&target, &"zone-b"],
        )
        .await
        .unwrap();
    let refused = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("outside-boundary"),
        json!({"text":"unauthorized"}),
    )
    .await;
    assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED, "{}", refused.2);
    assert_eq!(refused.2["code"], "precondition.failed");
    let count: i64 = fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_ask_answers WHERE proposal_id=$1", &[&id]).await.unwrap().get(0);
    assert_eq!(count, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn a_stale_task_grant_cannot_answer_even_when_its_profile_lists_answer() {
    struct Stale;
    impl registry_breg::task_grant::TaskGrantStatusChecker for Stale {
        fn check<'a>(
            &'a self,
            _: &'a registry_breg::task_grant::TaskGrantBinding,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<(), registry_breg::task_grant::TaskGrantError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(registry_breg::task_grant::TaskGrantError::Refused) })
        }
    }
    let authority = Authority::start(false, true).await;
    let (fixture, idp, auth) = agent_answer_fixture_with_checker(&authority, Arc::new(Stale)).await;
    let id = submitted(&fixture, "stale-answer-grant").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (ask, _) = announce(&authority, &binding);
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
    let mut token = agent_token(&idp.issuer(), 4, Some(id));
    token["registry_grant_bounds"] = json!({"type":"breg","permissions":[{"collection":format!("proposal:{id}"),"operations":["get","answer"]}]});
    let caller = auth.authenticate(&idp.mint_token(token)).await.unwrap();
    let refused = request_as(
        &fixture,
        caller,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer?accessProfile=task-answerer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("stale-grant"),
        json!({"text":"unauthorized"}),
    )
    .await;
    assert_eq!(refused.0, StatusCode::NOT_FOUND, "{}", refused.2);
    assert_eq!(refused.2["code"], "resource.not_found");
    assert_eq!(fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_ask_answers WHERE proposal_id=$1", &[&id]).await.unwrap().get::<_,i64>(0), 0);
    fixture.finish().await;
}

#[tokio::test]
async fn only_an_explicit_display_read_serves_and_audits_intrinsic_answers() {
    let authority = Authority::start(false, true).await;
    let (fixture, id, _) = committed_answer(&authority, "answers-opt-in").await;
    let before = fixture.audit_capture.entries().len();
    let plain = reviewer_get(
        &fixture,
        &format!("/v1/proposals/{id}/review-context?accessProfile=reviewer"),
        "zone-a",
    )
    .await;
    assert_eq!(plain.0, StatusCode::OK);
    let value: Value = serde_json::from_slice(&plain.2).unwrap();
    assert!(
        value["context"].get("asks").is_none(),
        "preflight context must omit answers"
    );
    assert!(fixture.audit_capture.entries()[before..]
        .iter()
        .all(|entry| entry["record"].get("askFieldSetReference").is_none()));
    for query in [
        "include=progress",
        "include=answers&include=answers",
        "include=unknown",
    ] {
        let invalid = reviewer_get(
            &fixture,
            &format!("/v1/proposals/{id}/review-context?accessProfile=reviewer&{query}"),
            "zone-a",
        )
        .await;
        assert_eq!(invalid.0, StatusCode::NOT_FOUND, "{query}");
        let problem: Value = serde_json::from_slice(&invalid.2).unwrap();
        assert_eq!(problem["code"], "resource.not_found");
    }
    let before = fixture.audit_capture.entries().len();
    let shown = reviewer_get(
        &fixture,
        &format!("/v1/proposals/{id}/review-context?accessProfile=reviewer&include=answers"),
        "zone-a",
    )
    .await;
    assert_eq!(shown.0, StatusCode::OK);
    let value: Value = serde_json::from_slice(&shown.2).unwrap();
    assert!(value["context"]["asks"][0]["answer"]["text"].is_string());
    assert!(fixture.audit_capture.entries()[before..]
        .iter()
        .any(|entry| entry["record"]["askFieldSetReference"] == "proposal-review-ask"));
    fixture.finish().await;
}

#[tokio::test]
async fn a_document_ask_can_cite_an_uncited_current_file_when_the_additions_slot_is_full() {
    let authority = Authority::start(false, true).await;
    let mut source = answer_source();
    source["actions"]["correct-name"]["execution"]["proposal"]["additions"]["maximumCount"] =
        json!(1);
    let registry = compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap();
    let bindings = authority.registry.clone();
    let fixture =
        client_http::ClientFixture::start_with_mutations(registry, applicant(), move |m| {
            m.with_review_result_source(bindings)
        })
        .await;
    let id = submitted(&fixture, "full-additions-ask").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let file = add_file(&fixture, id, "already-added", b"current submission file").await;
    let (ask, _) = announce(&authority, &binding);
    authority
        .state
        .asks
        .lock()
        .unwrap()
        .replies
        .get_mut(&ask)
        .unwrap()
        .1["wants"] = json!([{"kind":"document"}]);
    worker(&fixture, &authority).await.unwrap();
    let (_, headers, before) = request(
        &fixture,
        "GET",
        &format!("/v1/proposals/{id}"),
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(
        before["additions"]["other"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        before["additions"]["other"]["links"]["add"]["availability"]["reason"],
        "limit-reached"
    );
    let answered = request(
        &fixture,
        "POST",
        &format!("/v1/proposals/{id}/asks/{ask}/answer"),
        Some(headers["etag"].to_str().unwrap()),
        Some("cite-existing"),
        json!({"additions":[file]}),
    )
    .await;
    assert_eq!(answered.0, StatusCode::OK, "{}", answered.2);
    assert_eq!(answered.2["asks"][0]["answer"]["additions"], json!([file]));
    assert_eq!(answered.2["effectDigest"], before["effectDigest"]);
    assert_eq!(answered.2["submissionVersion"], before["submissionVersion"]);
    fixture.finish().await;
}

#[tokio::test]
async fn a_clock_skew_delivery_refusal_keeps_its_code_and_raises_the_operator_signal() {
    let authority = Authority::start(false, true).await;
    let (fixture, _, ask) = committed_answer(&authority, "clock-skew-answer").await;
    {
        let mut state = authority.state.asks.lock().unwrap();
        state.answer_status = 422;
        state.answer_code = Some("review.ask-answer-time-invalid".into());
    }
    let logs = CapturedDiagnosticLogs::default();
    worker(&fixture, &authority)
        .with_subscriber(logs.subscriber_with_max_level(tracing::Level::DEBUG))
        .await
        .unwrap();
    let job = delivery(&fixture, ask).await;
    assert_eq!(job["state"], "refused");
    assert_eq!(job["error"], "review.ask-answer-time-invalid");
    assert!(
        logs.text().contains("review.result_lookups.unavailable"),
        "{}",
        logs.text()
    );
    worker(&fixture, &authority).await.unwrap();
    assert_eq!(authority.state.asks.lock().unwrap().deliveries.len(), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn pruning_a_receipt_then_resetting_the_cursor_never_refetches_or_duplicates_its_stored_ask()
{
    let authority = Authority::start(false, true).await;
    let fixture = answer_fixture(&authority).await;
    let id = submitted(&fixture, "prune-ask-receipt").await;
    let binding = retained_binding(&fixture, id).await;
    accept(&fixture, id, &binding).await;
    let (_, event) = announce(&authority, &binding);
    worker(&fixture, &authority).await.unwrap();
    let before = read_applicant(&fixture, &format!("/v1/proposals/{id}")).await;
    assert_eq!(authority.state.asks.lock().unwrap().reads.len(), 1);
    assert_eq!(fixture.database.admin.query_one("SELECT recovery_days FROM registry_internal.registry_proposal_review_ask_feed_events WHERE event_id=$1", &[&event]).await.unwrap().get::<_,i32>(0), 7);
    let fresh = Uuid::new_v4();
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_ask_feed_events(authority,event_id,review_request_id,ask_id,state,recovery_days) SELECT authority,$2,review_request_id,ask_id,state,recovery_days FROM registry_internal.registry_proposal_review_ask_feed_events WHERE event_id=$1", &[&event,&fresh]).await.unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_ask_feed_events SET observed_at=transaction_timestamp()-interval '8 days' WHERE event_id=$1",&[&event]).await.unwrap();
    let logs = CapturedDiagnosticLogs::default();
    worker(&fixture, &authority)
        .with_subscriber(logs.subscriber_with_max_level(tracing::Level::DEBUG))
        .await
        .unwrap();
    assert_eq!(fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_ask_feed_events WHERE event_id=$1",&[&event]).await.unwrap().get::<_,i64>(0),0,"the maintenance runner prunes an eight-day receipt under this seven-day authority");
    assert!(
        logs.text().contains("\"ask_feed_events_pruned\":1"),
        "{}",
        logs.text()
    );
    assert_eq!(fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_ask_feed_events WHERE event_id=$1", &[&fresh]).await.unwrap().get::<_,i64>(0), 1, "a fresh receipt remains inside its observation recovery window");
    authority.state.asks.lock().unwrap().gone_once = true;
    worker(&fixture, &authority).await.unwrap();
    worker(&fixture, &authority).await.unwrap();
    let after = read_applicant(&fixture, &format!("/v1/proposals/{id}")).await;
    assert_eq!(after["revision"], before["revision"]);
    assert_eq!(after["asks"], before["asks"]);
    assert_eq!(
        authority.state.asks.lock().unwrap().reads.len(),
        1,
        "a pruned receipt and 410 must not fetch its stored ask again"
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_asks SET last_feed_changed_at_wire=NULL WHERE proposal_id=$1", &[&id]).await.unwrap();
    authority.state.asks.lock().unwrap().gone_once = true;
    worker(&fixture, &authority).await.unwrap();
    worker(&fixture, &authority).await.unwrap();
    assert_eq!(
        authority.state.asks.lock().unwrap().reads.len(),
        1,
        "a legacy open mirror uses its original askedAt to skip the opening event"
    );
    fixture.finish().await;
}
