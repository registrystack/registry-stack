//! Maintenance uses the existing audit admission and committed response gate.
use super::*;

pub(super) fn clock_project(source: bool) -> Value {
    let mut value = project_value(source, false);
    value["calendars"] = json!([{"id":"office","timezone":"UTC","workingWeekdays":["monday","tuesday","wednesday","thursday","friday","saturday","sunday"],"holidaySet":"office-holidays"}]);
    value["clocks"] = json!([{"id":"deadline","type":"activity","anchor":"stage-entered-at","calendar":"office","after":{"workingDays":1},"dueTime":"17:00","reminders":[{"id":"due-soon","workingDaysBefore":1}],"steps":[{"id":"overdue","because":"Move overdue reviews","at":"due","action":{"reassign":{"queue":"north"}}}]}]);
    value
}
pub(super) async fn due_clock(f: &Fixture, id: &str) -> (Uuid, Uuid) {
    let request = f.create(id).await;
    let task = f.task(request.request_id).await;
    f.service
        .create_holiday_revision(
            &actor("admin", CaseworkRole::Administrator),
            &HolidaySetDocument {
                holiday_set: "office-holidays".into(),
                revision: 1,
                dates: vec![],
            },
            &format!("holidays-{id}"),
        )
        .await
        .unwrap();
    f.db.execute("UPDATE casework_review_clock_occurrences SET anchor_at='2020-01-06T09:00:00Z',next_action_at='2020-01-06T09:00:00Z',updated_at='2020-01-06T09:00:00Z' WHERE task_id=$1",&[&task]).await.unwrap();
    (request.request_id, task)
}
async fn stop_writer(f: &Fixture, task: Uuid) {
    f.audit.refuse_after(f.audit.entries().len());
    assert!(matches!(
        f.service
            .claim_review_task(
                &actor("a", CaseworkRole::Staff),
                task,
                f.profile(),
                "human-source-token",
                1,
                "stop-writer-before-maintenance"
            )
            .await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert!(!f.store.audit_ready().await);
}
fn restored_service(f: &Fixture) -> (CaseworkService, AuditCapture) {
    let (audit, capture) = CaseworkAudit::capture();
    let providers: Vec<Arc<dyn ReviewContextProvider>> = if f.project.context_providers.is_empty() {
        vec![]
    } else {
        vec![Arc::new(SubstituteProvider(Arc::clone(&f.state)))]
    };
    (
        CaseworkService::new(
            f.store.clone().with_audit(audit),
            f.project.clone(),
            providers,
        )
        .unwrap(),
        capture,
    )
}
async fn clock_snapshot(f: &Fixture, task: Uuid) -> Value {
    f.db.query_one("SELECT jsonb_build_object('task',to_jsonb(t),'clock',to_jsonb(c),'effects',(SELECT count(*) FROM casework_review_clock_effects e WHERE e.clock_occurrence_id=c.clock_occurrence_id)) FROM casework_review_tasks t JOIN casework_review_clock_occurrences c USING(task_id) WHERE t.task_id=$1",&[&task]).await.unwrap().get(0)
}
fn minimized(capture: &AuditCapture, subject: &str, request: Uuid, task: Option<Uuid>) {
    let entries = capture.entries();
    assert!(entries.iter().all(|entry| entry["phase"] == "response"));
    for entry in &entries {
        for field in entry["record"].as_object().unwrap().keys() {
            assert!(
                [
                    "event",
                    "eventId",
                    "profileId",
                    "reviewRequestPseudonym",
                    "reviewTaskPseudonym",
                    "queuePseudonym"
                ]
                .contains(&field.as_str()),
                "unexpected audit field {field}"
            );
        }
    }
    let rendered = serde_json::to_string(&entries).unwrap();
    for canary in [
        subject.to_owned(),
        request.to_string(),
        "human-source-token".into(),
        "Private notice".into(),
    ] {
        assert!(!rendered.contains(&canary));
    }
    if let Some(task) = task {
        assert!(!rendered.contains(&task.to_string()));
    }
}

#[tokio::test]
async fn stopped_writer_blocks_clock_effects_and_empty_passes_emit_no_events() {
    let f = Fixture::new(clock_project(false)).await;
    let (request, task) = due_clock(&f, "clock-audit-private-canary").await;
    stop_writer(&f, task).await;
    let before = clock_snapshot(&f, task).await;
    assert!(matches!(
        f.service.process_due_review_clocks(100).await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(before, clock_snapshot(&f, task).await);
    let (service, capture) = restored_service(&f);
    capture.lose_next_commit_acknowledgment();
    assert_eq!(service.process_due_review_clocks(100).await.unwrap(), 2);
    assert_eq!(capture.responses("review-clock-reminder").len(), 1);
    assert_eq!(capture.responses("review-clock-step-applied").len(), 1);
    assert_eq!(clock_snapshot(&f, task).await["task"]["queue_id"], "north");
    minimized(&capture, "clock-audit-private-canary", request, Some(task));
    let count = capture.entries().len();
    assert_eq!(service.process_due_review_clocks(100).await.unwrap(), 0);
    assert_eq!(capture.entries().len(), count);
}

#[tokio::test]
async fn source_clock_deferral_requires_audit_admission() {
    let f = Fixture::new(clock_project(true)).await;
    let (request, task) = due_clock(&f, "source-clock-audit-canary").await;
    stop_writer(&f, task).await;
    f.state.unavailable.store(true, Ordering::SeqCst);
    let before = clock_snapshot(&f, task).await;
    assert!(matches!(
        f.service.process_due_review_clocks(100).await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(before, clock_snapshot(&f, task).await);
    let (service, capture) = restored_service(&f);
    assert_eq!(service.process_due_review_clocks(100).await.unwrap(), 0);
    assert_eq!(capture.responses("review-clock-deferred").len(), 1);
    let after = clock_snapshot(&f, task).await;
    assert_eq!(before["task"], after["task"]);
    assert_eq!(after["effects"], 0);
    assert_ne!(
        before["clock"]["next_action_at"],
        after["clock"]["next_action_at"]
    );
    minimized(&capture, "source-clock-audit-canary", request, Some(task));
}

#[tokio::test]
async fn refused_clock_response_withholds_success_after_exactly_once_effects() {
    let f = Fixture::new(clock_project(false)).await;
    let (_, task) = due_clock(&f, "clock-response-audit-canary").await;
    f.audit.refuse_after(f.audit.entries().len());
    assert!(f.store.audit_ready().await);
    assert!(matches!(
        f.service.process_due_review_clocks(100).await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    let committed = clock_snapshot(&f, task).await;
    assert_eq!(committed["effects"], 2);
    assert_eq!(committed["task"]["queue_id"], "north");
    let (service, capture) = restored_service(&f);
    assert_eq!(service.process_due_review_clocks(100).await.unwrap(), 0);
    assert_eq!(committed, clock_snapshot(&f, task).await);
    assert!(capture.entries().is_empty());
}

pub(super) async fn expired_review(f: &Fixture, id: &str) -> (Uuid, Uuid) {
    let request = f.create(id).await;
    let task = f.task(request.request_id).await;
    f.service
        .cancel_review_request(
            &actor("notice-service", CaseworkRole::Requester),
            request.request_id,
            ReviewCancelRequest {
                subject: f.request(id).subject,
                reason: "The producer no longer needs this review".into(),
            },
            &format!("cancel-{id}"),
        )
        .await
        .unwrap();
    f.db.execute("UPDATE casework_review_requests SET terminal_at=now()-interval '3 days',result_available_until=now()-interval '2 days',accountability_retained_until=now()+interval '1 day' WHERE request_id=$1",&[&request.request_id]).await.unwrap();
    f.db.execute("UPDATE casework_review_results SET completed_at=now()-interval '3 days',available_until=now()-interval '2 days' WHERE request_id=$1",&[&request.request_id]).await.unwrap();
    f.db.execute("UPDATE casework_review_terminal_events SET completed_at=now()-interval '3 days',retained_until=now()-interval '2 days' WHERE request_id=$1",&[&request.request_id]).await.unwrap();
    (request.request_id, task)
}
async fn privacy_snapshot(f: &Fixture, request: Uuid) -> Value {
    f.db.query_one("SELECT jsonb_build_object('request',to_jsonb(r),'results',(SELECT count(*) FROM casework_review_results WHERE request_id=r.request_id),'tasks',(SELECT count(*) FROM casework_review_tasks WHERE request_id=r.request_id),'clocks',(SELECT count(*) FROM casework_review_clock_occurrences WHERE request_id=r.request_id)) FROM casework_review_requests r WHERE request_id=$1",&[&request]).await.unwrap().get(0)
}
#[tokio::test]
async fn stopped_writer_blocks_retention_and_available_writer_erases_minimally() {
    let f = Fixture::new(project_value(false, false)).await;
    let (request, _) = expired_review(&f, "retention-audit-private-canary").await;
    let probe = f.create("retention-writer-stop-probe").await;
    stop_writer(&f, f.task(probe.request_id).await).await;
    let before = privacy_snapshot(&f, request).await;
    assert!(matches!(
        f.service.erase_expired_reviews().await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(before, privacy_snapshot(&f, request).await);
    let (service, capture) = restored_service(&f);
    assert_eq!(service.erase_expired_reviews().await.unwrap(), 0);
    let after = privacy_snapshot(&f, request).await;
    assert_eq!(after["request"]["context"], json!({}));
    assert_eq!(after["results"], 0);
    assert_eq!(after["tasks"], 0);
    assert_eq!(after["clocks"], 0);
    assert_eq!(capture.responses("review-retention-erased").len(), 1);
    minimized(&capture, "retention-audit-private-canary", request, None);
    let count = capture.entries().len();
    assert_eq!(service.erase_expired_reviews().await.unwrap(), 0);
    assert_eq!(capture.entries().len(), count);
}
#[tokio::test]
async fn refused_retention_response_withholds_success_and_retry_has_no_phantom_event() {
    let f = Fixture::new(project_value(false, false)).await;
    let (request, _) = expired_review(&f, "retention-response-canary").await;
    f.audit.refuse_after(f.audit.entries().len());
    assert!(matches!(
        f.service.erase_expired_reviews().await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    let committed = privacy_snapshot(&f, request).await;
    assert_eq!(committed["request"]["context"], json!({}));
    assert_eq!(committed["tasks"], 0);
    let (service, capture) = restored_service(&f);
    assert_eq!(service.erase_expired_reviews().await.unwrap(), 0);
    assert_eq!(committed, privacy_snapshot(&f, request).await);
    assert!(capture.entries().is_empty());
}

#[tokio::test]
async fn expired_unbound_recovery_retention_is_audited_even_without_request_erasure() {
    let f = Fixture::new(project_value(false, false)).await;
    let request = f.create("recovery-retention-audit-canary").await;
    let task = f.task(request.request_id).await;
    f.db.execute("UPDATE casework_review_submission_reservations SET request_id=NULL,recovery_deadline=now()-interval '2 days',retained_until=now()-interval '1 day' WHERE request_id=$1",&[&request.request_id]).await.unwrap();
    stop_writer(&f, task).await;
    assert!(matches!(
        f.service.erase_expired_reviews().await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_submission_reservations WHERE request_id IS NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let (service, capture) = restored_service(&f);
    assert_eq!(service.erase_expired_reviews().await.unwrap(), 0);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_submission_reservations WHERE request_id IS NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        capture.responses("review-recovery-retention-erased").len(),
        1
    );
    minimized(
        &capture,
        "recovery-retention-audit-canary",
        request.request_id,
        None,
    );
    let count = capture.entries().len();
    assert_eq!(service.erase_expired_reviews().await.unwrap(), 0);
    assert_eq!(capture.entries().len(), count);
}

async fn discovery_rows(f: &Fixture) {
    for expired in [true, false] {
        let expires_at = Utc::now() + chrono::Duration::days(if expired { -1 } else { 1 });
        f.db.execute("INSERT INTO casework_review_staffing_previews(preview_id,kind,issuer,subject,profile_id,directory_revision,request,tasks,expires_at) VALUES($1,'caseload','private-discovery-issuer','private-discovery-subject','staff',1,'{\"private-filter\":\"private-source-value\"}','[]',$2)",&[&Uuid::new_v4(),&expires_at]).await.unwrap();
        f.db.execute("INSERT INTO casework_review_staffing_cursors(cursor_id,issuer,subject,profile_id,context_digest,snapshot_digest,position,expires_at) VALUES($1,'private-discovery-issuer','private-discovery-subject','staff','private-context','private-snapshot',0,$2)",&[&Uuid::new_v4(),&expires_at]).await.unwrap();
        f.db.execute("INSERT INTO casework_review_cursors(cursor_id,issuer,subject,casework_profile_id,source_profile_id,context,expires_at) VALUES($1,'private-discovery-issuer','private-discovery-subject','staff','private-profile','private-context',$2)",&[&Uuid::new_v4(),&expires_at]).await.unwrap();
    }
}
async fn discovery_snapshot(f: &Fixture) -> Value {
    let mut snapshot = serde_json::Map::new();
    for (table, key) in [
        ("casework_review_staffing_previews", "preview_id"),
        ("casework_review_staffing_cursors", "cursor_id"),
        ("casework_review_cursors", "cursor_id"),
    ] {
        let rows =
            f.db.query_one(
                &format!(
                    "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY {key}),'[]') FROM {table} t"
                ),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        snapshot.insert(table.into(), rows);
    }
    Value::Object(snapshot)
}
#[tokio::test]
async fn stopped_writer_blocks_discovery_retention_and_success_publishes_only_counts() {
    let f = Fixture::new(project_value(false, false)).await;
    let probe = f.create("discovery-writer-stop-probe").await;
    discovery_rows(&f).await;
    stop_writer(&f, f.task(probe.request_id).await).await;
    let before = discovery_snapshot(&f).await;
    assert!(matches!(
        f.service.erase_expired_review_staffing().await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(before, discovery_snapshot(&f).await);
    let (service, capture) = restored_service(&f);
    assert_eq!(service.erase_expired_review_staffing().await.unwrap(), 3);
    let after = discovery_snapshot(&f).await;
    for rows in after.as_object().unwrap().values() {
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert!(
            chrono::DateTime::parse_from_rfc3339(rows[0]["expires_at"].as_str().unwrap()).unwrap()
                > Utc::now()
        );
    }
    let entries = capture.responses("review-discovery-retention-erased");
    assert_eq!(entries.len(), 1);
    let record = entries[0].as_object().unwrap();
    assert_eq!(record.len(), 4);
    assert_eq!(record["erasedCount"], 3);
    assert_eq!(record["profileId"], "system:review-retention");
    assert!(record["eventId"].as_str().is_some());
    for canary in [
        "private-discovery",
        "private-filter",
        "private-source-value",
        "private-context",
        "private-snapshot",
        "private-profile",
    ] {
        assert!(!serde_json::to_string(&capture.entries())
            .unwrap()
            .contains(canary));
    }
    let count = capture.entries().len();
    assert_eq!(service.erase_expired_review_staffing().await.unwrap(), 0);
    assert_eq!(capture.entries().len(), count);
    assert_eq!(after, discovery_snapshot(&f).await);
}
#[tokio::test]
async fn refused_discovery_retention_response_withholds_success_and_retry_has_no_event() {
    let f = Fixture::new(project_value(false, false)).await;
    discovery_rows(&f).await;
    f.audit.refuse_after(f.audit.entries().len());
    assert!(matches!(
        f.service.erase_expired_review_staffing().await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    let committed = discovery_snapshot(&f).await;
    assert!(committed
        .as_object()
        .unwrap()
        .values()
        .all(|rows| rows.as_array().unwrap().len() == 1));
    let (service, capture) = restored_service(&f);
    assert_eq!(service.erase_expired_review_staffing().await.unwrap(), 0);
    assert!(capture.entries().is_empty());
    assert_eq!(committed, discovery_snapshot(&f).await);
}
