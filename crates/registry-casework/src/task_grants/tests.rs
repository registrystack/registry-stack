use super::*;
use axum::http::StatusCode;

#[tokio::test]
async fn template_versions_are_immutable_labels_preserve_grants_and_retirement_cannot_revive_them()
{
    let mut fixture = super::http_tests::fixture(900).await;
    let original = fixture.project.task_templates[0].clone();
    let human = super::http_tests::token("human", "human-client", "human", "casework:staff");
    let (status, approved) = super::http_tests::request(
        &fixture,
        "POST",
        &format!("/v1/review-tasks/{}/task-grants", fixture.review_task),
        &human,
        true,
        Some(json!({"templateId":original.id,"templateVersion":original.version})),
        Some("label-proof"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let id: Uuid = approved["id"].as_str().unwrap().parse().unwrap();
    let digest = template_digest(&original).unwrap();
    let mut relabeled = original.clone();
    relabeled.label = "Prepare a private summary".into();
    assert_eq!(
        template_digest(&relabeled).unwrap(),
        digest,
        "presentation cannot change authority"
    );
    let mut templates = fixture.project.task_templates.clone();
    templates[0] = relabeled.clone();
    fixture
        .store
        .activate_task_templates(&templates)
        .await
        .unwrap();
    assert!(
        !fixture
            .store
            .review_task_grant(id)
            .await
            .unwrap()
            .invalidated,
        "label changes cannot revoke admitted authority"
    );
    let mut configured = fixture.project.clone();
    configured.task_templates = templates.clone();
    fixture.app = super::http_tests::test_app(
        &fixture.store,
        &configured,
        fixture.mode.clone(),
        fixture.read_started.clone(),
        fixture.read_continue.clone(),
    );
    let agent =
        super::http_tests::token("agent", "agent-client", "agent", "casework:grants:assert");
    let (status, _) = super::http_tests::request(
        &fixture,
        "POST",
        &format!("/v1/task-grants/{id}/assertion"),
        &agent,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a presentation-only activation preserves live assertion authority"
    );
    let mut mutated = relabeled;
    mutated.purpose = "different-purpose".into();
    templates[0] = mutated;
    assert!(
        matches!(
            fixture.store.activate_task_templates(&templates).await,
            Err(StoreError::Configuration)
        ),
        "behavior cannot change under an active immutable version"
    );
    assert!(
        !fixture
            .store
            .review_task_grant(id)
            .await
            .unwrap()
            .invalidated,
        "a refused activation changes nothing"
    );
    fixture.store.activate_task_templates(&[]).await.unwrap();
    assert!(
        fixture
            .store
            .review_task_grant(id)
            .await
            .unwrap()
            .invalidated
    );
    fixture
        .store
        .activate_task_templates(&fixture.project.task_templates)
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .review_task_grant(id)
            .await
            .unwrap()
            .invalidated,
        "reactivation permits only fresh approvals"
    );
    fixture
        .admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", fixture.schema))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_new_active_template_cannot_replace_the_template_in_an_admitted_policy_closure() {
    let mut fixture = super::http_tests::fixture(900).await;
    let mut configured = fixture.project.clone();
    configured.task_templates[0].version = "2".into();
    configured.task_templates[0].purpose = "different-purpose".into();
    fixture
        .store
        .activate_task_templates(&configured.task_templates)
        .await
        .unwrap();
    fixture.app = super::http_tests::test_app(
        &fixture.store,
        &configured,
        fixture.mode.clone(),
        fixture.read_started.clone(),
        fixture.read_continue.clone(),
    );
    let human = super::http_tests::token("human", "human-client", "human", "casework:staff");
    let (status, body) = super::http_tests::request(
        &fixture,
        "POST",
        &format!("/v1/review-tasks/{}/task-grants", fixture.review_task),
        &human,
        true,
        Some(json!({"templateId":"summary","templateVersion":"2"})),
        Some("substitution-proof"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "operation.not-authorized");
    let db = fixture.store.client().await.unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM casework_review_task_grants WHERE task_id=$1",
            &[&fixture.review_task],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "an unpinned template creates no authority");
    fixture
        .admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", fixture.schema))
        .await
        .unwrap();
}
