// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::time::Duration;
use tokio::sync::Notify;

fn bounded_project() -> Value {
    let mut value = project_value(true, false);
    value["inbox"] = json!({"defaultPageSize":2,"maximumSourceReads":4,
        "maximumCandidateScan":4,"pageDeadlineMilliseconds":2000});
    value
}

#[tokio::test]
async fn ordinary_due_and_subject_pages_walk_beyond_the_per_page_scan_budget() {
    for sort in [ReviewTaskSort::Due, ReviewTaskSort::Subject] {
        let f = Fixture::new(bounded_project()).await;
        let mut expected = Vec::new();
        for i in (0..9).rev() {
            let id = format!("notice-{i:02}");
            let accepted = f.create(&id).await;
            let task = f.task(accepted.request_id).await;
            f.db.execute("UPDATE casework_review_tasks SET deadline_at=TIMESTAMPTZ '2030-01-01 00:00:00Z'+($2::bigint * interval '1 minute') WHERE task_id=$1", &[&task, &(i as i64)]).await.unwrap();
            expected.push(id);
        }
        expected.sort();
        let mut cursor = None;
        let mut seen = Vec::new();
        for _ in 0..10 {
            f.state.human_reads.store(0, Ordering::SeqCst);
            let page = f
                .service
                .review_staffing_tasks(
                    &actor("a", CaseworkRole::Staff),
                    Some("source-staff"),
                    "human-source-token",
                    ReviewStaffingQuery {
                        sort,
                        limit: Some(2),
                        cursor,
                        ..Default::default()
                    },
                )
                .await
                .expect("ordinary page does not scan the whole queue");
            assert!(!page.items.is_empty());
            assert!(page.items.len() <= 2);
            assert_eq!(page.status, PageStatus::Complete);
            assert!(f.state.human_reads.load(Ordering::SeqCst) <= 4);
            seen.extend(page.items.into_iter().map(|task| task.subject.id));
            assert!(page.next_cursor.is_none() || page.next_cursor != cursor);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none(), "bounded walk must finish");
        assert_eq!(seen, expected, "no duplicate, skipped or misordered task");
    }
}

#[tokio::test]
async fn live_reference_filter_and_sort_still_refuse_an_incomplete_scan() {
    for query in [
        ReviewStaffingQuery {
            sort: ReviewTaskSort::Reference,
            limit: Some(1),
            ..Default::default()
        },
        ReviewStaffingQuery {
            reference: Some("last-reference-canary".into()),
            limit: Some(1),
            ..Default::default()
        },
    ] {
        let f = Fixture::new(bounded_project()).await;
        for i in 0..8 {
            f.create(&format!("notice-{i:02}")).await;
        }
        f.state
            .references
            .lock()
            .unwrap()
            .insert("notice-07".into(), "last-reference-canary".into());
        assert!(matches!(
            f.service
                .review_staffing_tasks(
                    &actor("a", CaseworkRole::Staff),
                    Some("source-staff"),
                    "human-source-token",
                    query,
                )
                .await,
            Err(ReviewRuntimeError::QueryTooBroad)
        ));
        assert!(f.state.human_reads.load(Ordering::SeqCst) <= 4);
    }
}

#[tokio::test]
async fn duplicate_task_slots_share_one_current_source_read_in_both_inbox_paths() {
    for staffing in [true, false] {
        let mut value = bounded_project();
        value["reviewPolicies"]["notice-review"]["stages"][0]["requiredApprovals"] = json!(2);
        value["inbox"]["maximumSourceReads"] = json!(1);
        let f = Fixture::new(value).await;
        f.create("same-request").await;
        f.state.human_reads.store(0, Ordering::SeqCst);
        let person = actor("a", CaseworkRole::Staff);
        let page = if staffing {
            f.service
                .review_staffing_tasks(
                    &person,
                    Some("source-staff"),
                    "human-source-token",
                    ReviewStaffingQuery {
                        limit: Some(2),
                        ..Default::default()
                    },
                )
                .await
        } else {
            f.service
                .review_tasks(
                    &person,
                    Some("source-staff"),
                    "human-source-token",
                    None,
                    None,
                    2,
                )
                .await
        }
        .unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(
            f.state.human_reads.load(Ordering::SeqCst),
            1,
            "one current request binding needs one source observation per invocation"
        );
        assert!(page.next_cursor.is_none());
    }
}

#[tokio::test]
async fn page_local_visibility_cache_never_crosses_caller_profile_or_invocation() {
    for staffing in [true, false] {
        let f = Fixture::new(bounded_project()).await;
        f.create("cache-canary").await;
        for (who, profile, token, visible) in [
            ("a", "source-staff", "human-source-token", true),
            ("b", "source-staff", "wrong-token-canary", false),
            ("a", "wrong-profile", "human-source-token", false),
            ("b", "source-staff", "human-source-token", true),
        ] {
            let before = f.state.human_reads.load(Ordering::SeqCst);
            let person = actor(who, CaseworkRole::Staff);
            let page = if staffing {
                f.service
                    .review_staffing_tasks(&person, Some(profile), token, Default::default())
                    .await
            } else {
                f.service
                    .review_tasks(&person, Some(profile), token, None, None, 2)
                    .await
            }
            .unwrap();
            assert_eq!(page.items.len(), usize::from(visible));
            assert!(
                f.state.human_reads.load(Ordering::SeqCst) > before,
                "every invocation must recheck the current caller and profile"
            );
        }
        f.state.hidden.lock().unwrap().insert("cache-canary".into());
        let page = if staffing {
            f.service
                .review_staffing_tasks(
                    &actor("a", CaseworkRole::Staff),
                    Some("source-staff"),
                    "human-source-token",
                    Default::default(),
                )
                .await
        } else {
            f.service
                .review_tasks(
                    &actor("a", CaseworkRole::Staff),
                    Some("source-staff"),
                    "human-source-token",
                    None,
                    None,
                    2,
                )
                .await
        }
        .unwrap();
        assert!(
            page.items.is_empty(),
            "a prior visible result cannot survive concealment"
        );
    }
}

struct ControlledProvider {
    inner: SubstituteProvider,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    pause: AtomicBool,
    pause_subject: Option<String>,
    changed: Option<String>,
}
#[async_trait]
impl ReviewContextProvider for ControlledProvider {
    fn provider_id(&self) -> &str {
        "notice-context"
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        self.inner.capabilities()
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        if self.pause.swap(false, Ordering::SeqCst)
            || self.pause_subject.as_deref() == Some(request.identity.subject.id.as_str())
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let changed = self.changed.as_deref() == Some(request.identity.subject.id.as_str());
        let mut observation = self.inner.human_display(request).await?;
        if changed {
            observation.identity.subject.version = "changed-canary".into();
        }
        Ok(observation)
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        self.inner.service_status(identity).await
    }
}
fn controlled_service(
    f: &Fixture,
    pause: bool,
    changed: Option<&str>,
) -> (CaseworkService, Arc<Notify>, Arc<Notify>) {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let provider = ControlledProvider {
        inner: SubstituteProvider(Arc::clone(&f.state)),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        pause: AtomicBool::new(pause),
        pause_subject: None,
        changed: changed.map(str::to_owned),
    };
    (
        CaseworkService::new(
            f.store.clone(),
            f.project.clone(),
            [Arc::new(provider) as Arc<dyn ReviewContextProvider>],
        )
        .unwrap(),
        entered,
        release,
    )
}

#[tokio::test]
async fn concealed_and_changed_candidates_do_not_hide_following_visible_rows() {
    for staffing in [true, false] {
        let mut value = bounded_project();
        value["inbox"]["maximumCandidateScan"] = json!(8);
        value["inbox"]["maximumSourceReads"] = json!(8);
        let f = Fixture::new(value).await;
        for id in [
            "a-hidden-canary",
            "b-changed-canary",
            "c-visible",
            "d-visible",
            "e-visible",
        ] {
            f.create(id).await;
        }
        f.state
            .hidden
            .lock()
            .unwrap()
            .insert("a-hidden-canary".into());
        let (service, _, _) = controlled_service(&f, false, Some("b-changed-canary"));
        let mut cursor = None;
        let mut seen = Vec::new();
        for _ in 0..5 {
            let person = actor("a", CaseworkRole::Staff);
            let page = if staffing {
                service
                    .review_staffing_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        ReviewStaffingQuery {
                            sort: ReviewTaskSort::Subject,
                            limit: Some(2),
                            cursor,
                            ..Default::default()
                        },
                    )
                    .await
            } else {
                service
                    .review_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        None,
                        cursor,
                        2,
                    )
                    .await
            }
            .unwrap();
            let wire = serde_json::to_string(&page).unwrap();
            assert!(!wire.contains("hidden-canary") && !wire.contains("changed-canary"));
            seen.extend(page.items.into_iter().map(|task| task.subject.id));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        assert_eq!(seen, ["c-visible", "d-visible", "e-visible"]);
    }
}

#[tokio::test]
async fn candidate_budget_exhaustion_refuses_the_entire_page_in_both_paths() {
    for staffing in [true, false] {
        let f = Fixture::new(bounded_project()).await;
        for id in ["a-visible", "b-hidden", "c-hidden", "d-hidden", "e-visible"] {
            f.create(id).await;
        }
        f.state.hidden.lock().unwrap().extend([
            "b-hidden".into(),
            "c-hidden".into(),
            "d-hidden".into(),
        ]);
        f.state.human_reads.store(0, Ordering::SeqCst);
        let person = actor("a", CaseworkRole::Staff);
        let page = if staffing {
            f.service
                .review_staffing_tasks(
                    &person,
                    Some("source-staff"),
                    "human-source-token",
                    ReviewStaffingQuery {
                        sort: ReviewTaskSort::Subject,
                        limit: Some(2),
                        ..Default::default()
                    },
                )
                .await
        } else {
            f.service
                .review_tasks(
                    &person,
                    Some("source-staff"),
                    "human-source-token",
                    None,
                    None,
                    2,
                )
                .await
        };
        assert!(
            matches!(page, Err(ReviewRuntimeError::QueryTooBroad)),
            "do not release the first visible row as a partial exhausted page"
        );
        assert!(f.state.human_reads.load(Ordering::SeqCst) <= 4);
    }
}

#[tokio::test]
async fn directory_revocation_during_source_io_is_rechecked_in_both_paths() {
    for staffing in [true, false] {
        let f = Fixture::new(bounded_project()).await;
        f.create("revoked-during-read-canary").await;
        let (service, entered, release) = controlled_service(&f, true, None);
        let reader = async {
            let person = actor("a", CaseworkRole::Staff);
            if staffing {
                service
                    .review_staffing_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        Default::default(),
                    )
                    .await
            } else {
                service
                    .review_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        None,
                        None,
                        2,
                    )
                    .await
            }
        };
        let revoke = async {
            tokio::time::timeout(Duration::from_secs(3), entered.notified())
                .await
                .unwrap();
            f.db.execute(
                "DELETE FROM casework_memberships WHERE subject='a' AND membership_kind='staff'",
                &[],
            )
            .await
            .unwrap();
            release.notify_one();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(reader, revoke)
        })
        .await
        .unwrap();
        match result {
            Ok(page) => assert!(page.items.is_empty()),
            Err(error) => assert!(matches!(
                error,
                ReviewRuntimeError::Forbidden
                    | ReviewRuntimeError::NotFound
                    | ReviewRuntimeError::ResultExpired
            )),
        }
    }
}

#[tokio::test]
async fn provider_deadline_refuses_without_a_partial_page_in_both_paths() {
    for staffing in [true, false] {
        let mut value = bounded_project();
        value["inbox"]["pageDeadlineMilliseconds"] = json!(100);
        let f = Fixture::new(value).await;
        f.create("deadline-canary").await;
        let (service, _, _) = controlled_service(&f, true, None);
        let person = actor("a", CaseworkRole::Staff);
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            if staffing {
                service
                    .review_staffing_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        Default::default(),
                    )
                    .await
            } else {
                service
                    .review_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        None,
                        None,
                        2,
                    )
                    .await
            }
        })
        .await
        .expect("the page deadline bounds blocked source I/O");
        assert!(matches!(
            result,
            Err(ReviewRuntimeError::SourceUnavailable | ReviewRuntimeError::QueryTooBroad)
        ));
    }
}

#[tokio::test]
async fn task_claimed_during_source_io_leaves_the_unclaimed_page_in_both_paths() {
    for staffing in [true, false] {
        let f = Fixture::new(bounded_project()).await;
        let accepted = f.create("claimed-during-read-canary").await;
        let task = f.task(accepted.request_id).await;
        let (service, entered, release) = controlled_service(&f, true, None);
        let reader = async {
            let person = actor("a", CaseworkRole::Staff);
            if staffing {
                service
                    .review_staffing_tasks(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        ReviewStaffingQuery {
                            ownership: Some(ReviewTaskOwnership::Unclaimed),
                            ..Default::default()
                        },
                    )
                    .await
            } else {
                service
                    .review_tasks_with_ownership(
                        &person,
                        Some("source-staff"),
                        "human-source-token",
                        None,
                        Some(ReviewTaskOwnership::Unclaimed),
                        None,
                        2,
                    )
                    .await
            }
        };
        let claim = async {
            tokio::time::timeout(Duration::from_secs(3), entered.notified())
                .await
                .unwrap();
            f.claim(task, "b").await;
            release.notify_one();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(reader, claim)
        })
        .await
        .unwrap();
        match result {
            Ok(page) => assert!(page.items.is_empty()),
            Err(error) => assert!(matches!(
                error,
                ReviewRuntimeError::ResultExpired | ReviewRuntimeError::NotFound
            )),
        }
    }
}

#[tokio::test]
async fn ordinary_pages_budget_the_anchor_without_preflighting_lookahead() {
    let mut project = bounded_project();
    project["inbox"]["defaultPageSize"] = json!(1);
    project["inbox"]["maximumSourceReads"] = json!(2);
    let f = Fixture::new(project).await;
    for id in ["one", "two", "three"] {
        f.create(id).await;
    }
    let mut cursor = None;
    let mut seen = Vec::new();
    loop {
        f.state.human_reads.store(0, Ordering::SeqCst);
        f.state.status_reads.store(0, Ordering::SeqCst);
        let page = f
            .service
            .review_staffing_tasks(
                &actor("a", CaseworkRole::Staff),
                Some("source-staff"),
                "human-source-token",
                ReviewStaffingQuery {
                    limit: Some(1),
                    cursor,
                    ..Default::default()
                },
            )
            .await
            .expect("the anchor and one ordinary item fit the page budget");
        assert_eq!(
            f.state.human_reads.load(Ordering::SeqCst),
            if cursor.is_some() { 2 } else { 1 }
        );
        assert_eq!(
            f.state.status_reads.load(Ordering::SeqCst),
            usize::from(cursor.is_some())
        );
        seen.extend(page.items.into_iter().map(|task| task.subject.id));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, ["one", "two", "three"]);
}

#[derive(Clone)]
struct QueryCounter(Arc<AtomicUsize>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for QueryCounter {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        // Count the driver's actual executions without formatting or retaining
        // SQL parameters, source fields, credentials or Directory identities.
        struct Target(bool);
        impl tracing::field::Visit for Target {
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "log.target" && value == "tokio_postgres::query" {
                    self.0 = true;
                }
            }
        }
        let mut target = Target(event.metadata().target() == "tokio_postgres::query");
        event.record(&mut target);
        if target.0 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[tokio::test]
async fn inbox_sql_execution_count_does_not_grow_per_task() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::{prelude::*, util::SubscriberInitExt};
    let _ = tracing_subscriber::registry()
        .with(QueryCounter(Arc::new(AtomicUsize::new(0))))
        .try_init();
    let mut project = bounded_project();
    project["inbox"]["maximumSourceReads"] = json!(100);
    project["inbox"]["maximumCandidateScan"] = json!(100);
    let f = Fixture::new(project).await;
    for i in 0..25 {
        f.create(&format!("sql-count-{i:02}")).await;
    }
    for staffing in [true, false] {
        let mut counts = Vec::new();
        for limit in [2, 20] {
            let count = Arc::new(AtomicUsize::new(0));
            let subscriber = tracing_subscriber::registry().with(QueryCounter(count.clone()));
            let page = async {
                if staffing {
                    f.service
                        .review_staffing_tasks(
                            &actor("a", CaseworkRole::Staff),
                            Some("source-staff"),
                            "human-source-token",
                            ReviewStaffingQuery {
                                limit: Some(limit),
                                ..Default::default()
                            },
                        )
                        .await
                } else {
                    f.service
                        .review_tasks(
                            &actor("a", CaseworkRole::Staff),
                            Some("source-staff"),
                            "human-source-token",
                            None,
                            None,
                            limit,
                        )
                        .await
                }
            }
            .with_subscriber(subscriber)
            .await
            .unwrap();
            assert_eq!(page.items.len(), limit);
            counts.push(count.load(Ordering::SeqCst));
        }
        assert!(counts[0] >= 3, "the driver must report executed queries");
        assert!(
            counts[1] <= counts[0] + 1,
            "SQL executions must be per batch, not per task: {counts:?}"
        );
    }
}

#[tokio::test]
async fn supervision_retains_a_completed_prefix_when_a_later_request_times_out() {
    let mut value = bounded_project();
    value["inbox"]["pageDeadlineMilliseconds"] = json!(500);
    value["inbox"]["maximumConcurrentSourceReads"] = json!(1);
    let f = Fixture::new(value).await;
    let a = f.create("first").await;
    let b = f.create("second").await;
    let (first, last, hidden) = if a.request_id < b.request_id {
        (a.request_id, b.request_id, "second")
    } else {
        (b.request_id, a.request_id, "first")
    };
    f.db.execute(
        "UPDATE casework_review_tasks SET created_at=TIMESTAMPTZ '2030-01-01' WHERE request_id=$1",
        &[&first],
    )
    .await
    .unwrap();
    f.db.execute(
        "UPDATE casework_review_tasks SET created_at=TIMESTAMPTZ '2030-01-02' WHERE request_id=$1",
        &[&last],
    )
    .await
    .unwrap();
    let provider = ControlledProvider {
        inner: SubstituteProvider(Arc::clone(&f.state)),
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
        pause: AtomicBool::new(false),
        pause_subject: Some(hidden.into()),
        changed: None,
    };
    let service = CaseworkService::new(
        f.store.clone(),
        f.project.clone(),
        [Arc::new(provider) as Arc<dyn ReviewContextProvider>],
    )
    .unwrap();
    let page = service
        .supervisory_review_tasks(
            &actor("supervisor", CaseworkRole::Supervisor),
            Some("source-staff"),
            "human-source-token",
            None,
            None,
            None,
            2,
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].request_id, first);
    assert_eq!(page.status, PageStatus::SourceUnavailable);
    assert!(page.next_cursor.is_some());
}

#[tokio::test]
async fn live_reference_scan_splits_observations_at_the_provider_batch_bound() {
    let mut value = bounded_project();
    value["inbox"]["maximumSourceReads"] = json!(110);
    value["inbox"]["maximumCandidateScan"] = json!(110);
    value["inbox"]["maximumConcurrentSourceReads"] = json!(1);
    value["inbox"]["pageDeadlineMilliseconds"] = json!(30000);
    let f = Fixture::new(value).await;
    for i in 0..101 {
        f.create(&format!("batch-bound-{i:03}")).await;
    }
    f.state.human_reads.store(0, Ordering::SeqCst);
    let page = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            ReviewStaffingQuery {
                sort: ReviewTaskSort::Reference,
                limit: Some(2),
                ..Default::default()
            },
        )
        .await
        .expect("an admitted full scan respects the provider's per-batch bound");
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.status, PageStatus::Complete);
    assert_eq!(f.state.human_reads.load(Ordering::SeqCst), 101);
}

#[tokio::test]
async fn ordinary_continuation_charges_its_anchor_to_the_source_budget() {
    let mut project = bounded_project();
    project["inbox"]["defaultPageSize"] = json!(1);
    project["inbox"]["maximumSourceReads"] = json!(1);
    let f = Fixture::new(project).await;
    for id in ["anchor-one", "anchor-two"] {
        f.create(id).await;
    }
    let query = ReviewStaffingQuery {
        limit: Some(1),
        ..Default::default()
    };
    let first = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            query.clone(),
        )
        .await
        .unwrap();
    f.state.human_reads.store(0, Ordering::SeqCst);
    f.state.status_reads.store(0, Ordering::SeqCst);
    let result = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            ReviewStaffingQuery {
                cursor: first.next_cursor,
                ..query
            },
        )
        .await;
    assert!(
        matches!(result, Err(ReviewRuntimeError::QueryTooBroad)),
        "the anchor exhausts a one-observation continuation budget"
    );
    assert_eq!(f.state.human_reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.state.status_reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn continuation_sizes_its_page_after_charging_the_anchor() {
    let mut project = bounded_project();
    project["inbox"]["maximumSourceReads"] = json!(3);
    let f = Fixture::new(project).await;
    for i in 0..5 {
        f.create(&format!("anchor-sizing-{i}")).await;
    }
    let query = ReviewStaffingQuery {
        limit: Some(3),
        ..Default::default()
    };
    let first = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            query.clone(),
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 3);
    f.state.human_reads.store(0, Ordering::SeqCst);
    f.state.status_reads.store(0, Ordering::SeqCst);
    let next = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            ReviewStaffingQuery {
                cursor: first.next_cursor,
                ..query
            },
        )
        .await
        .unwrap();
    assert_eq!(next.items.len(), 2);
    assert_eq!(next.status, PageStatus::Complete);
    assert!(next.next_cursor.is_none());
    assert_eq!(f.state.human_reads.load(Ordering::SeqCst), 3);
    assert_eq!(f.state.status_reads.load(Ordering::SeqCst), 1);
}
