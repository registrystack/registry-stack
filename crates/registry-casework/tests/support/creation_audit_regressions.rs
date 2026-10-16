use super::*;

#[tokio::test]
async fn creation_requires_audit_admission_before_any_durable_change() {
    let f = Fixture::new(project_value(false, false)).await;
    f.audit.refuse_after(0);
    let outcome = f
        .service
        .create_review_request(
            &actor("notice-service", CaseworkRole::Requester),
            f.request("new"),
            "new",
        )
        .await;
    assert!(matches!(
        outcome,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
#[tokio::test]
async fn producer_supersession_cannot_bypass_an_unavailable_audit_writer() {
    let f = Fixture::new(project_value(false, false)).await;
    let accepted = f.create("notice").await;
    let before = f.holders().await;
    f.audit.refuse_after(f.audit.entries().len());
    let mut request = f.request("notice");
    request.subject.version = "2".into();
    request.subject.digest = ContentDigest::for_bytes(b"successor");
    let outcome = f
        .service
        .create_review_request(
            &actor("notice-service", CaseworkRole::Requester),
            request,
            "successor",
        )
        .await;
    assert!(matches!(
        outcome,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(f.holders().await, before);
    assert_eq!(
        f.db.query_one(
            "SELECT lifecycle FROM casework_review_requests WHERE request_id=$1",
            &[&accepted.request_id]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "reviewing"
    );
    for table in ["casework_review_results", "casework_review_terminal_events"] {
        assert_eq!(
            f.db.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}
#[tokio::test]
async fn creation_response_is_withheld_until_audit_and_exact_recovery_releases_it() {
    let f = Fixture::new(project_value(false, false)).await;
    let mut request = f.request("notice");
    request.policy = PolicySelection::current("notice-review");
    let expected_policy = f.project.compile_policy("notice-review").unwrap().binding();
    let expected_digest = submission_digest("notice-service", "notice-source", &request).unwrap();
    let producer = actor("notice-service", CaseworkRole::Requester);
    f.audit.refuse_after(1);
    assert!(matches!(
        f.service
            .create_review_request(&producer, request.clone(), "lost-response")
            .await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // A failed destination stays stopped. Recovery uses a restarted runtime
    // with a working writer against the same committed database.
    let (audit, capture) = CaseworkAudit::capture();
    let mut updated_project = f.project.clone();
    updated_project.review_policies[0].version = "2".into();
    let recovered_service = CaseworkService::new(
        f.store.clone().with_audit(audit),
        updated_project,
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    let recovered = recovered_service
        .create_review_request(&producer, request, "lost-response")
        .await
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(recovered.accepted.policy, expected_policy);
    assert_eq!(recovered.accepted.submission_digest, expected_digest);
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let audit = serde_json::to_string(&capture.entries()).unwrap();
    assert!(audit.contains("replayed"));
    assert!(!audit.contains("Private notice"));
    assert!(!audit.contains("human-source-token"));
}
struct HangingDisplay;
#[async_trait]
impl ReviewContextProvider for HangingDisplay {
    fn provider_id(&self) -> &str {
        "notice-context"
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        &[
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus,
            ReviewContextCapability::RoutingContext,
            ReviewContextCapability::TaskGrantContext,
        ]
    }
    async fn human_display(
        &self,
        _request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        std::future::pending().await
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        Ok(ServiceStatusObservation {
            identity: identity.clone(),
            reviewable: true,
        })
    }
}
#[tokio::test]
async fn current_source_task_context_obeys_its_pinned_deadline() {
    let mut value = project_value(true, false);
    value["inbox"] = json!({"pageDeadlineMilliseconds":100});
    let f = Fixture::new(value).await;
    let accepted = f.create("slow").await;
    let task = f.task(accepted.request_id).await;
    let service = CaseworkService::new(
        f.store.clone(),
        f.project.clone(),
        [Arc::new(HangingDisplay) as Arc<dyn ReviewContextProvider>],
    )
    .unwrap();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        service.review_task_context(
            &actor("a", CaseworkRole::Staff),
            task,
            Some("source-staff"),
            "human-source-token",
        ),
    )
    .await;
    assert!(matches!(
        outcome,
        Ok(Err(ReviewRuntimeError::SourceUnavailable))
    ));
    let f = Fixture::new(project_value(false, false)).await;
    let accepted = f.create("standalone").await;
    f.service
        .review_task_context(
            &actor("a", CaseworkRole::Staff),
            f.task(accepted.request_id).await,
            None,
            "",
        )
        .await
        .unwrap();
}
