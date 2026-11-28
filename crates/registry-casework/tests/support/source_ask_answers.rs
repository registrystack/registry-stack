use super::*;

struct AnswerSource {
    inner: ReviewSource,
    answers: Arc<Mutex<serde_json::Value>>,
    reads: Arc<AtomicUsize>,
}

#[async_trait]
impl ReviewContextProvider for AnswerSource {
    fn provider_id(&self) -> &str {
        self.inner.provider_id()
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        self.inner.capabilities()
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut value = serde_json::to_value(self.inner.human_display(request).await?)
            .map_err(|_| ReviewContextError::Invalid)?;
        let answers = self.answers.lock().unwrap().clone();
        if !answers.as_object().unwrap().is_empty() {
            value["answers"] = answers;
        }
        serde_json::from_value(value).map_err(|_| ReviewContextError::Invalid)
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        self.inner.service_status(identity).await
    }
    async fn routing_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        self.inner.routing_context(request).await
    }
    async fn task_grant_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        self.inner.task_grant_context(request).await
    }
}

#[tokio::test]
async fn source_answers_join_known_asks_live_without_entering_the_display_schema_or_store() {
    let fixture = fixture().await;
    let mut project = asks_project(true, true);
    current_source(&mut project);
    let answers = Arc::new(Mutex::new(json!({})));
    let reads = Arc::new(AtomicUsize::new(0));
    let provider = AnswerSource {
        inner: ReviewSource {
            revoked: fixture.source_revoked.clone(),
            state: fixture.source_state.clone(),
            read_blocked: fixture.source_read_blocked.clone(),
            read_started: fixture.source_read_started.clone(),
            read_continue: fixture.source_read_continue.clone(),
            advanced: fixture.source_advanced.clone(),
        },
        answers: answers.clone(),
        reads: reads.clone(),
    };
    let service = CaseworkService::new(
        fixture.store.clone(),
        project,
        [Arc::new(provider) as Arc<dyn ReviewContextProvider>],
    )
    .unwrap();
    let mut create = request("source-answers", "reference-source-answers");
    create.context = ReviewContext::CurrentSource {
        binding: SourceContextBinding {
            reference: "source:answers".into(),
        },
    };
    let created = service
        .create_review_request(
            &fixture.producer,
            bind_request(&service, create),
            "source-answers-create",
        )
        .await
        .unwrap();
    let request_id = created.accepted.request_id;
    let task = task_id(&fixture, request_id, 0).await;
    let held = service
        .claim_review_task(
            &fixture.reviewer_a,
            task,
            Some("staff"),
            "human-token",
            1,
            "source-answers-claim",
        )
        .await
        .unwrap();
    let asked = service
        .ask_applicant(
            &fixture.reviewer_a,
            task,
            ask_request("Why?"),
            Some("staff"),
            "human-token",
            held.revision,
            "source-answers-ask",
        )
        .await
        .unwrap();
    let answer = json!({"text":"synthetic-answer-live-only","documents":[{
        "id":"cited-file","sha256":"a".repeat(64),"contentType":"text/plain","byteSize":7,
        "download":{"method":"GET","operation":"get-review-context","accessProfile":"staff","path":"/files/cited"}
    }],"answeredAt":asked.ask.asked_at});
    *answers.lock().unwrap() = json!({(asked.ask.ask_id.to_string()):answer,
        (Uuid::new_v4().to_string()):{"text":"unknown-answer-must-not-appear","documents":[],"answeredAt":asked.ask.asked_at}});
    let captured = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(captured.clone())
        .finish();
    let context = service
        .review_task_context(&fixture.reviewer_a, task, Some("staff"), "human-token")
        .with_subscriber(subscriber)
        .await;
    assert!(
        context.is_ok(),
        "intrinsic answers bypass the authored display schema: {:?}",
        context.err()
    );
    let value = serde_json::to_value(context.unwrap()).unwrap();
    assert_eq!(value["asks"][0]["answer"], answer);
    assert!(!value.to_string().contains("unknown-answer-must-not-appear"));
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("\"dropped_answers\":1"),
        "unknown answers are counted without their content: {logs}"
    );
    assert!(!logs.contains("unknown-answer-must-not-appear"));
    let mut inconsistent = answer.clone();
    inconsistent["answeredAt"] = json!(asked.ask.asked_at - chrono::Duration::seconds(1));
    *answers.lock().unwrap() = json!({(asked.ask.ask_id.to_string()):inconsistent});
    let captured = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(captured.clone())
        .finish();
    let partial = service
        .review_task_context(&fixture.reviewer_a, task, Some("staff"), "human-token")
        .with_subscriber(subscriber)
        .await
        .unwrap();
    let partial = serde_json::to_value(partial).unwrap();
    assert_eq!(
        partial["context"], value["context"],
        "one bad answer must not hide the authored fields"
    );
    assert!(partial["asks"][0].get("answer").is_none());
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("\"dropped_answers\":1"), "{logs}");
    assert!(!logs.contains("synthetic-answer-live-only"));
    for table in [
        "casework_review_requests",
        "casework_review_tasks",
        "casework_review_history",
    ] {
        let query = format!("SELECT COALESCE(bool_or(to_jsonb(r)::text LIKE '%synthetic-answer-live-only%'),false) FROM {table} r WHERE request_id=$1");
        let retained: bool = fixture
            .database
            .query_one(&query, &[&request_id])
            .await
            .unwrap()
            .get(0);
        assert!(!retained, "source answer text must not enter {table}");
    }
    let before = reads.load(Ordering::SeqCst);
    *answers.lock().unwrap() = json!({});
    let refreshed = service
        .review_task_context(&fixture.reviewer_a, task, Some("staff"), "human-token")
        .await
        .unwrap();
    assert!(serde_json::to_value(refreshed).unwrap()["asks"][0]
        .get("answer")
        .is_none());
    assert_eq!(reads.load(Ordering::SeqCst), before + 1);
}
