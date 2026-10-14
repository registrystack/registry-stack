//! Clock retries preserve completed effects and refresh staffing deadlines.
use super::maintenance_audit_regressions::{clock_project, due_clock};
use super::*;

#[tokio::test]
async fn applied_escalation_losing_service_does_not_block_the_next_served_step() {
    let mut project = clock_project(false);
    project["queues"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"south","label":"South reviews"}));
    project["teams"][0]["serves"]
        .as_array_mut()
        .unwrap()
        .push(json!("south"));
    project["clocks"][0]["reminders"] = json!([]);
    project["clocks"][0]["steps"] = json!([
        {"id":"first","because":"First escalation","at":"due","action":{"reassign":{"queue":"north"}}},
        {"id":"second","because":"Second escalation","at":"due","action":{"reassign":{"queue":"south"}}}
    ]);
    let f = Fixture::new(project).await;
    let (_, task) = due_clock(&f, "two-step-clock").await;
    assert_eq!(f.service.process_due_review_clocks(100).await.unwrap(), 1);
    let first = f.db.query_one("SELECT event_id,applied_at FROM casework_review_clock_effects WHERE effect_kind='step' AND effect_id='first'", &[]).await.unwrap();
    let first_id: Uuid = first.get(0);
    let first_applied_at: chrono::DateTime<Utc> = first.get(1);
    assert_eq!(f.audit.responses("review-clock-step-applied").len(), 1);
    assert_eq!(
        f.audit.responses("review-clock-deferred").len(),
        1,
        "the unapplied unserved target must defer"
    );
    let current: String =
        f.db.query_one(
            "SELECT queue_id FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(current, "north");
    f.db.batch_execute("DELETE FROM casework_queue_service WHERE queue_id='north'; INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('south','review-team',1); UPDATE casework_review_clock_occurrences SET next_action_at=now()-interval '1 second' WHERE scope='activity';").await.unwrap();
    let before = f.audit.entries().len();
    assert_eq!(
        f.service.process_due_review_clocks(100).await.unwrap(),
        1,
        "a completed target no longer needs service before the next escalation"
    );
    let current: String =
        f.db.query_one(
            "SELECT queue_id FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(current, "south");
    let first = f.db.query_one("SELECT event_id,applied_at FROM casework_review_clock_effects WHERE effect_kind='step' AND effect_id='first'", &[]).await.unwrap();
    assert_eq!(first.get::<_, Uuid>(0), first_id);
    assert_eq!(first.get::<_, chrono::DateTime<Utc>>(1), first_applied_at);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_clock_effects WHERE effect_kind='step'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    assert_eq!(f.audit.responses("review-clock-step-applied").len(), 2);
    assert_eq!(f.audit.responses("review-clock-deferred").len(), 1);
    assert_eq!(
        f.audit.entries().len(),
        before + 1,
        "only the newly applied step is audited"
    );
    assert_eq!(f.service.process_due_review_clocks(100).await.unwrap(), 0);
    assert_eq!(f.audit.entries().len(), before + 1);
}

#[tokio::test]
async fn holiday_publication_refreshes_deadlines_and_due_ordered_next() {
    let mut project = clock_project(false);
    project["clocks"][0]["reminders"] = json!([]);
    project["clocks"][0]["steps"] = json!([]);
    let f = Fixture::new(project).await;
    let later = f.create("created-first-due-later").await;
    let later_task = f.task(later.request_id).await;
    let earlier = f.create("created-second-due-earlier").await;
    let earlier_task = f.task(earlier.request_id).await;
    for (task, anchor) in [
        (later_task, "2020-01-10T09:00:00Z"),
        (earlier_task, "2020-01-06T09:00:00Z"),
    ] {
        let anchor = chrono::DateTime::parse_from_rfc3339(anchor)
            .unwrap()
            .with_timezone(&Utc);
        f.db.execute(
            "UPDATE casework_review_clock_occurrences SET anchor_at=$2 WHERE task_id=$1",
            &[&task, &anchor],
        )
        .await
        .unwrap();
    }
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_tasks WHERE deadline_at IS NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    assert_eq!(f.db.query_one("SELECT count(*) FROM casework_review_clock_occurrences WHERE state='source-facts-missing'", &[]).await.unwrap().get::<_, i64>(0), 2);
    f.service
        .create_holiday_revision(
            &actor("admin", CaseworkRole::Administrator),
            &HolidaySetDocument {
                holiday_set: "office-holidays".into(),
                revision: 1,
                dates: vec![],
            },
            "publish-deadline-holidays",
        )
        .await
        .unwrap();
    assert_eq!(f.service.process_due_review_clocks(100).await.unwrap(), 0);
    for task in [later_task, earlier_task] {
        let row = f.db.query_one("SELECT t.deadline_at,c.due_at,c.state FROM casework_review_tasks t JOIN casework_review_clock_occurrences c USING(task_id) WHERE t.task_id=$1", &[&task]).await.unwrap();
        let due: chrono::DateTime<Utc> = row.get(1);
        assert_eq!(row.get::<_, String>(2), "running");
        assert_eq!(
            row.get::<_, Option<chrono::DateTime<Utc>>>(0),
            Some(due),
            "scheduled occurrence and materialized task deadline must agree"
        );
    }
    let next = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            None,
            "human-source-token",
            ReviewStaffingQuery {
                sort: ReviewTaskSort::Due,
                ownership: Some(ReviewTaskOwnership::Unclaimed),
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1);
    assert_eq!(next.items[0].task_id, earlier_task);
    assert!(next.items[0].deadline_at.is_some());
    assert_eq!(f.audit.responses("review-clock-scheduled").len(), 2);
    let written = f.audit.entries().len();
    assert_eq!(f.service.process_due_review_clocks(100).await.unwrap(), 0);
    assert_eq!(f.audit.entries().len(), written);
}
