// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn changed_approved_result_id_has_a_specific_412_and_never_applies() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-status"));
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reviewed", "review-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("review-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let expected =
        registry_review_client::submission_digest("proposal-producer", "proposal-test", &create)
            .unwrap();
    assert_eq!(expected.as_str(), row.get::<_, String>(1));
    assert_eq!(create.subject.id, submitted.id());
    assert_eq!(
        create.subject.digest.as_str(),
        submitted.effect_digest().unwrap()
    );
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: expected,
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    registry_breg::review_store::verify_retained_bindings(&fixture.pool, &fixture.registry, None)
        .await
        .unwrap();
    registry_breg::review_store::verify_retained_bindings(
        &fixture.pool,
        &fixture.registry,
        Some(local_review_binding().as_ref()),
    )
    .await
    .unwrap();
    let mut result = review.result(&accepted);
    result.result_id = uuid::Uuid::new_v4();
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
        (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
        VALUES ('correct-name',$1,1,'local-review',$2,$3,'approved',$4,$5)",
        &[&uuid::Uuid::parse_str(submitted.id()).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();

    let current = client.read_proposal(&submitted).await.unwrap().value;
    let apply = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("result-id-mismatch-canary"),
        )
        .unwrap();
    let audit_before = fixture.audit_capture.entries().len();
    let error = client.execute_proposal(&apply).await.unwrap_err();
    match &error {
        registry_breg_client::BaseRegistryClientError::Problem { status, code, .. } => {
            assert_eq!(*status, 412);
            assert_eq!(code.to_string(), "proposal.review_result_mismatch");
        }
        _ => panic!("expected a typed result-mismatch refusal, got {error:?}"),
    }
    assert_ne!(
        error.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let entries = fixture.audit_capture.entries();
    let attempt = &entries[audit_before..];
    assert_eq!(
        attempt.len(),
        2,
        "the refused apply has paired audit entries"
    );
    assert_eq!(attempt[0]["phase"], "request");
    assert_eq!(attempt[1]["phase"], "response");
    assert!(attempt[0]["correlation"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(attempt[0]["correlation"], attempt[1]["correlation"]);
    let trace_id = error
        .trace_id()
        .expect("typed refusal retains its trace")
        .as_str();
    assert_eq!(attempt[1]["record"]["traceId"], trace_id);
    assert!(review.calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
    let after = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(
        after.revision(),
        current.revision(),
        "refused application must not advance the proposal"
    );
    fixture.finish().await;
}
