//! PostgreSQL commit uncertainty and caller cancellation preserve audit pairing.
use super::maintenance_audit_regressions::{clock_project, due_clock, expired_review};
use super::*;

async fn claim(
    service: &CaseworkService,
    task: Uuid,
    key: &str,
) -> Result<ReviewTask, ReviewRuntimeError> {
    service
        .claim_review_task(
            &actor("a", CaseworkRole::Staff),
            task,
            None,
            "human-source-token",
            1,
            key,
        )
        .await
}
async fn task_revision(f: &Fixture, task: Uuid) -> i64 {
    f.db.query_one(
        "SELECT revision FROM casework_review_tasks WHERE task_id=$1",
        &[&task],
    )
    .await
    .unwrap()
    .get(0)
}
async fn entries_after(f: &Fixture, written: usize, count: usize) -> Vec<Value> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let entries = f.audit.entries()[written..].to_vec();
        if entries.len() >= count {
            return entries;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "committed operation left no audit response"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
fn claim_pair(entries: &[Value], committed: bool) {
    assert_eq!(entries.len(), 2, "{entries:#?}");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[1]["correlation"], entries[0]["correlation"]);
    assert_eq!(entries[1]["record"]["event"], "casework.task-claimed");
    if committed {
        assert!(entries[1]["record"].get("outcome").is_none());
    } else {
        assert_eq!(
            entries[1]["record"],
            json!({"event":"casework.task-claimed","outcome":"unfinished"})
        );
    }
}
async fn scoped_connection(f: &Fixture) -> tokio_postgres::Client {
    let schema: String =
        f.db.query_one("SELECT current_schema()", &[])
            .await
            .unwrap()
            .get(0);
    let base = std::env::var("CASEWORK_REVIEW_TEST_DATABASE_URL").unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&scoped, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    db
}
async fn delay_commits(f: &Fixture, table: &str) {
    f.db.batch_execute(&format!("CREATE FUNCTION sleep_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER sleep_at_commit AFTER UPDATE ON {table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sleep_at_commit();")).await.unwrap();
}
async fn abort_during_commit<T: std::fmt::Debug>(
    f: &Fixture,
    table: &str,
    task: tokio::task::JoinHandle<T>,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let committing: i64 = f.db.query_one("SELECT count(*) FROM pg_stat_activity a WHERE state='active' AND query='COMMIT' AND wait_event='PgSleep' AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.relation=$1::text::regclass)", &[&table]).await.unwrap().get(0);
        if committing > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "operation never reached delayed COMMIT"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    task.abort();
    assert!(task
        .await
        .expect_err("caller was canceled mid-COMMIT")
        .is_cancelled());
}
#[tokio::test]
async fn a_claim_whose_commit_acknowledgment_is_lost_is_read_back_as_committed() {
    let f = Fixture::new(project_value(false, false)).await;
    let request = f.create("claim-lost-ack").await;
    let task = f.task(request.request_id).await;
    let written = f.audit.entries().len();
    f.audit.lose_next_commit_acknowledgment();
    let claimed = claim(&f.service, task, "claim-lost-ack").await.unwrap();
    assert_eq!(claimed.revision, 2);
    assert_eq!(task_revision(&f, task).await, 2);
    claim_pair(&f.audit.entries()[written..], true);
}
#[tokio::test]
async fn a_claim_refused_at_commit_is_read_back_as_not_committed() {
    let f = Fixture::new(project_value(false, false)).await;
    let request = f.create("claim-refused-commit").await;
    let task = f.task(request.request_id).await;
    f.db.batch_execute("CREATE FUNCTION refuse_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused at commit'; END $$; CREATE CONSTRAINT TRIGGER refuse_at_commit AFTER UPDATE ON casework_review_tasks DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_at_commit();").await.unwrap();
    let written = f.audit.entries().len();
    assert!(matches!(
        claim(&f.service, task, "claim-refused-commit").await,
        Err(ReviewRuntimeError::Store(StoreError::Postgres(_)))
    ));
    assert_eq!(task_revision(&f, task).await, 1);
    claim_pair(&f.audit.entries()[written..], false);
}
#[tokio::test]
async fn a_claim_dropped_inside_its_transaction_writes_one_unfinished_response() {
    let f = Fixture::new(project_value(false, false)).await;
    let request = f.create("claim-dropped-transaction").await;
    let task = f.task(request.request_id).await;
    let written = f.audit.entries().len();
    let mut locker = scoped_connection(&f).await;
    let lock = locker.transaction().await.unwrap();
    lock.execute(
        "SELECT 1 FROM casework_review_requests WHERE request_id=$1 FOR UPDATE",
        &[&request.request_id],
    )
    .await
    .unwrap();
    let locker_pid: i32 = lock
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let service = f.service.clone();
    let operation =
        tokio::spawn(async move { claim(&service, task, "claim-dropped-transaction").await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: i64 =
            f.db.query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",
                &[&locker_pid],
            )
            .await
            .unwrap()
            .get(0);
        if waiting > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "claim never waited on request row"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    let entries = entries_after(&f, written, 2).await;
    claim_pair(&entries, false);
    assert_eq!(task_revision(&f, task).await, 1);
    assert_eq!(f.audit.entries().len(), written + 2);
}
#[tokio::test]
async fn a_claim_canceled_during_its_commit_is_still_answered_by_the_committed_claim() {
    let f = Fixture::new(project_value(false, false)).await;
    let request = f.create("claim-canceled-commit").await;
    let task = f.task(request.request_id).await;
    delay_commits(&f, "casework_review_tasks").await;
    let written = f.audit.entries().len();
    let service = f.service.clone();
    let operation =
        tokio::spawn(async move { claim(&service, task, "claim-canceled-commit").await });
    abort_during_commit(&f, "casework_review_tasks", operation).await;
    let entries = entries_after(&f, written, 2).await;
    claim_pair(&entries, true);
    assert_eq!(task_revision(&f, task).await, 2);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(f.audit.entries().len(), written + 2);
}
#[tokio::test]
async fn background_clock_canceled_during_commit_still_appends_committed_responses() {
    let f = Fixture::new(clock_project(false)).await;
    let (_, task) = due_clock(&f, "clock-canceled-commit").await;
    delay_commits(&f, "casework_review_clock_occurrences").await;
    let written = f.audit.entries().len();
    let service = f.service.clone();
    let operation = tokio::spawn(async move { service.process_due_review_clocks(100).await });
    abort_during_commit(&f, "casework_review_clock_occurrences", operation).await;
    let entries = entries_after(&f, written, 3).await;
    assert_eq!(entries.len(), 3, "{entries:#?}");
    assert!(entries
        .iter()
        .all(|entry| entry["phase"] == "response" && entry["record"].get("outcome").is_none()));
    assert_eq!(f.audit.responses("review-clock-scheduled").len(), 1);
    assert_eq!(f.audit.responses("review-clock-reminder").len(), 1);
    assert_eq!(f.audit.responses("review-clock-step-applied").len(), 1);
    let row =
        f.db.query_one(
            "SELECT queue_id FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "north");
    assert_eq!(f.service.process_due_review_clocks(100).await.unwrap(), 0);
    assert_eq!(f.audit.entries().len(), written + 3);
}
#[tokio::test]
async fn background_retention_canceled_during_commit_still_appends_committed_response() {
    let f = Fixture::new(project_value(false, false)).await;
    let (request, _) = expired_review(&f, "retention-canceled-commit").await;
    delay_commits(&f, "casework_review_requests").await;
    let written = f.audit.entries().len();
    let service = f.service.clone();
    let operation = tokio::spawn(async move { service.erase_expired_reviews().await });
    abort_during_commit(&f, "casework_review_requests", operation).await;
    let entries = entries_after(&f, written, 1).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["phase"], "response");
    assert_eq!(
        entries[0]["record"]["event"],
        "casework.review-retention-erased"
    );
    assert!(entries[0]["record"].get("outcome").is_none());
    let context: Value =
        f.db.query_one(
            "SELECT context FROM casework_review_requests WHERE request_id=$1",
            &[&request],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(context, json!({}));
    assert_eq!(f.service.erase_expired_reviews().await.unwrap(), 0);
    assert_eq!(f.audit.entries().len(), written + 1);
}
#[tokio::test]
async fn a_database_failure_names_the_violated_constraint_without_row_data() {
    let f = Fixture::new(project_value(false, false)).await;
    let violation =
        f.db.execute(
            "INSERT INTO casework_schema_migrations(version,applied_at) VALUES(200,now())",
            &[],
        )
        .await
        .unwrap_err();
    assert!(violation
        .as_db_error()
        .and_then(|error| error.detail())
        .is_some_and(|detail| detail.contains("(version)=(200)")));
    assert_eq!(
        StoreError::Postgres(violation).to_string(),
        "the Casework database operation failed (constraint casework_schema_migrations_pkey)"
    );
}
