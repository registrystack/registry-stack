// SPDX-License-Identifier: Apache-2.0

use registry_coordinator::definition::Definition;
use serde_json::{json, Value};

fn project() -> Value {
    let input = json!({
        "type":"object",
        "additionalProperties":false,
        "required":["scheduledAt"],
        "properties":{"scheduledAt":{"type":"string","format":"date-time"}}
    });
    json!({
        "apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind":"CoordinatorProject",
        "project":{"id":"monthly-report","version":"v1"},
        "workflow":{
            "calendarTriggers":{
                "month-end":{
                    "cron":"5 8 L * *",
                    "timezone":"Asia/Bangkok",
                    "label":"Month end",
                    "description":"Start the monthly report in local institutional time."
                }
            },
            "input":input,
            "deadlineSeconds":3600,
            "start":"done",
            "steps":{
                "done":{"type":"finish","outcome":"reported","output":{"type":"input"}}
            },
            "outcomes":{"reported":input}
        }
    })
}

fn write(root: &std::path::Path, value: &Value) {
    std::fs::write(
        root.join("workflow.yaml"),
        serde_norway::to_string(value).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_calendar_trigger_is_checked_explained_and_restored() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), &project());
    let definition = Definition::load(root.path()).expect("the monthly trigger is valid");
    let explained = definition.explain().unwrap();
    assert_eq!(
        explained["calendarTriggers"]["month-end"]["cron"],
        "5 8 L * *"
    );
    assert_eq!(
        explained["calendarTriggers"]["month-end"]["timezone"],
        "Asia/Bangkok"
    );
    assert_eq!(
        explained["presentation"]["calendarTriggers"]["month-end"]["label"],
        "Month end"
    );

    let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(restored.digest, definition.digest);
    assert_eq!(
        restored.workflow.calendar_triggers["month-end"].cron,
        "5 8 L * *"
    );
}

#[test]
fn unsupported_calendar_expressions_and_timezones_are_refused_at_authoring() {
    let root = tempfile::tempdir().unwrap();
    for (cron, timezone) in [
        ("0 9 * * *", "UTC"),
        ("0 9 2 * *", "UTC"),
        ("0 9 1 * *", "Not/A_Zone"),
    ] {
        let mut value = project();
        value["workflow"]["calendarTriggers"]["month-end"]["cron"] = json!(cron);
        value["workflow"]["calendarTriggers"]["month-end"]["timezone"] = json!(timezone);
        write(root.path(), &value);
        let error = Definition::load(root.path())
            .err()
            .expect("unsupported calendar trigger");
        assert_eq!(error.code, "coordinator.definition.calendar-trigger");
        assert!(
            error
                .field
                .as_deref()
                .is_some_and(|field| field.contains("calendarTriggers/month-end")),
            "{error:?}"
        );
    }

    let mut two = project();
    two["workflow"]["calendarTriggers"]["another"] = json!({"cron":"0 9 1 * *","timezone":"UTC"});
    write(root.path(), &two);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.definition.calendar-trigger"
    );

    let mut wrong_input = project();
    wrong_input["workflow"]["input"] = json!({
        "type":"object",
        "additionalProperties":false,
        "required":["other"],
        "properties":{"other":{"type":"string"}}
    });
    write(root.path(), &wrong_input);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.definition.calendar-trigger-input"
    );
}

#[cfg(feature = "postgres-test")]
use registry_coordinator::{
    calendar_trigger::CalendarSchedule,
    runtime::RuntimeConfig,
    store::{CalendarCheck, Store},
};
#[cfg(feature = "postgres-test")]
use std::sync::Arc;

#[cfg(feature = "postgres-test")]
async fn client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}

/// A migrated namespace activated for the calendar fixture, and the runtime
/// that binds its one synthetic source connection.
#[cfg(feature = "postgres-test")]
struct Fixture {
    url: String,
    namespace: String,
    sql: tokio_postgres::Client,
    root: tempfile::TempDir,
    runtime: RuntimeConfig,
}

#[cfg(feature = "postgres-test")]
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("use a disposable PostgreSQL 17+ database");
        let namespace = format!("coordinator_{}", uuid::Uuid::new_v4().simple());
        Store::connect(&url, &namespace)
            .await
            .unwrap()
            .migrate()
            .await
            .unwrap();
        let sql = client(&url).await;
        sql.execute(
            &format!(
                "UPDATE {}.control SET active_flows_digest='calendar-active' WHERE id",
                namespace
            ),
            &[],
        )
        .await
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let runtime: RuntimeConfig = serde_json::from_value(json!({
            "secretProviders":{
                "environment":{},
                "file":{"root":root.path().canonicalize().unwrap()}
            },
            "database":{
                "runtimeUrlRef":"secret:env/COORDINATOR_TEST_DATABASE_URL",
                "migrationUrlRef":"secret:env/COORDINATOR_TEST_DATABASE_URL"
            },
            "namespace":namespace,
            "connections":{
                "source":{
                    "type":"breg",
                    "baseUrl":"http://127.0.0.1:9",
                    "profile":"synthetic-reader",
                    "authorization":{
                        "tokenEndpoint":"http://127.0.0.1:9/token",
                        "clientId":"synthetic-client",
                        "signingKeyRef":"secret:file/client-key",
                        "resource":"urn:example:synthetic-registry",
                        "scopes":["records:read"]
                    }
                }
            }
        }))
        .unwrap();
        runtime.validate().unwrap();
        Self {
            url,
            namespace,
            sql,
            root,
            runtime,
        }
    }

    /// A Store bound to the fixture's activation, as a serving replica is.
    async fn store(&self) -> Arc<Store> {
        Arc::new(
            Store::connect(&self.url, &self.namespace)
                .await
                .unwrap()
                .with_workflows_digest("calendar-active".into()),
        )
    }

    /// A Store like [`Fixture::store`] whose audit lines go to `sink`.
    async fn store_auditing_to(&self, sink: impl std::io::Write + Send + 'static) -> Store {
        use registry_coordinator::{protected_state::StateKeys, store::StoreSecurity};
        use registry_platform_audit::{AuditProfile, AuditWriter};
        Store::open(
            &self.url,
            &self.namespace,
            StoreSecurity {
                database_id: self.namespace.clone(),
                keys: StateKeys::new(
                    1,
                    std::collections::BTreeMap::from([(1, [0x11; 32])]),
                    [0x22; 32],
                )
                .unwrap(),
                audit: AuditWriter::from_line_sink(Box::new(sink)),
                audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                    vec![0x33; 32],
                ))
                .unwrap(),
            },
            None,
        )
        .await
        .unwrap()
        .with_workflows_digest("calendar-active".into())
    }

    fn definition(&self, project: &Value) -> Definition {
        write(self.root.path(), project);
        Definition::load(self.root.path()).unwrap()
    }

    async fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.sql
            .query_one("SELECT transaction_timestamp()", &[])
            .await
            .unwrap()
            .get(0)
    }

    async fn set_cursor(&self, workflow: &str, cursor: chrono::DateTime<chrono::Utc>) {
        self.sql
            .execute(
                &format!(
                    "UPDATE {}.calendar_cursors SET cursor_at=$2 WHERE workflow_id=$1 AND trigger_id='month-end'",
                    self.namespace
                ),
                &[&workflow, &cursor],
            )
            .await
            .unwrap();
    }

    async fn runs(&self) -> i64 {
        self.sql
            .query_one(
                &format!("SELECT count(*) FROM {}.runs", self.namespace),
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
}

#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn calendar_admission_is_latest_only_atomic_and_fenced() {
    use async_trait::async_trait;
    use registry_coordinator::{
        protocol::{AdapterSet, CallOutcome, CallRequest},
        worker::Worker,
    };

    struct NoCalls(String);
    #[async_trait]
    impl AdapterSet for NoCalls {
        fn binding_digest(&self) -> &str {
            &self.0
        }
        async fn call(&self, _: &CallRequest) -> CallOutcome {
            panic!("the calendar fixture finishes without a product call")
        }
    }

    let fixture = Fixture::new().await;
    let (sql, namespace, runtime) = (&fixture.sql, &fixture.namespace, &fixture.runtime);
    let first_store = fixture.store().await;
    let second_store = fixture.store().await;
    let definition = Arc::new(fixture.definition(&project()));
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "not-reviewed", runtime)
            .await
            .unwrap_err()
            .code,
        "calendar-invalid",
        "Store derives the schedule only from the checked trigger"
    );
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Idle
    );
    sql.execute(
        &format!(
            "UPDATE {}.calendar_cursors SET cursor_at=transaction_timestamp()+interval '1 day' WHERE workflow_id=$1 AND trigger_id=$2",
            namespace
        ),
        &[&definition.workflow.id, &"month-end"],
    )
    .await
    .unwrap();
    let future = sql
        .query_one(
            &format!(
                "SELECT cursor_at,xmin::text FROM {}.calendar_cursors WHERE workflow_id=$1 AND trigger_id=$2",
                namespace
            ),
            &[&definition.workflow.id, &"month-end"],
        )
        .await
        .unwrap();
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Idle
    );
    let unchanged = sql
        .query_one(
            &format!(
                "SELECT cursor_at,xmin::text FROM {}.calendar_cursors WHERE workflow_id=$1 AND trigger_id=$2",
                namespace
            ),
            &[&definition.workflow.id, &"month-end"],
        )
        .await
        .unwrap();
    assert_eq!(
        future.get::<_, chrono::DateTime<chrono::Utc>>(0),
        unchanged.get::<_, chrono::DateTime<chrono::Utc>>(0),
        "a backwards database time cannot rewind the cursor"
    );
    assert_eq!(
        future.get::<_, String>(1),
        unchanged.get::<_, String>(1),
        "an idle sweep performs no cursor update"
    );
    let database_now = fixture.now().await;
    let schedule = CalendarSchedule::parse("5 8 L * *", "Asia/Bangkok").unwrap();
    let mut occurrence = schedule
        .next_after(database_now - chrono::Duration::days(200))
        .unwrap();
    let mut due = Vec::new();
    while occurrence.scheduled_at <= database_now {
        due.push(occurrence.clone());
        occurrence = schedule.next_after(occurrence.scheduled_at).unwrap();
    }
    let catch_up_cursor = due[due.len() - 5].scheduled_at;
    fixture
        .set_cursor(&definition.workflow.id, catch_up_cursor)
        .await;

    let (left, right) = tokio::join!(
        first_store.admit_calendar_due(&definition, "month-end", runtime),
        second_store.admit_calendar_due(&definition, "month-end", runtime)
    );
    let admissions = [left.unwrap(), right.unwrap()]
        .into_iter()
        .filter_map(|check| match check {
            CalendarCheck::Admitted(admission) => Some(admission),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(admissions.len(), 1, "replicas admit the due instant once");
    assert_eq!(admissions[0].skipped, 3);
    let run = admissions[0].run_id;
    let row = sql
        .query_one(
            &format!(
                "SELECT skipped_count,(SELECT count(*) FROM {}.runs) FROM {}.calendar_cursors WHERE workflow_id=$1 AND trigger_id=$2",
                namespace, namespace
            ),
            &[&definition.workflow.id, &"month-end"],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 3);
    assert_eq!(row.get::<_, i64>(1), 1);

    let worker = Worker::new(
        first_store.clone(),
        Arc::new(NoCalls(
            runtime.binding_digest_for(&definition.workflow).unwrap(),
        )),
    );
    assert!(worker.tick().await.unwrap());
    let finished = first_store.status(run).await.unwrap();
    assert_eq!(
        finished.state, "finished",
        "failure_code={:?}",
        finished.failure_code
    );
    let output = finished.output.unwrap();
    assert_eq!(output.as_object().unwrap().len(), 1);
    assert!(output["scheduledAt"].as_str().is_some());

    sql.execute(
        &format!(
            "UPDATE {}.calendar_cursors SET cursor_at=$3::timestamptz-interval '1 month' WHERE workflow_id=$1 AND trigger_id=$2",
            namespace
        ),
        &[
            &definition.workflow.id,
            &"month-end",
            &admissions[0].scheduled_at,
        ],
    )
    .await
    .unwrap();
    let CalendarCheck::Admitted(replay) = first_store
        .admit_calendar_due(&definition, "month-end", runtime)
        .await
        .unwrap()
    else {
        panic!("the rewound cursor finds the same occurrence")
    };
    assert_eq!(replay.run_id, run);
    assert_eq!(
        fixture.runs().await,
        1,
        "workflow and occurrence identity admits exactly one run"
    );

    // From here an occurrence is due again.
    let due_cursor = fixture.now().await - chrono::Duration::days(40);
    fixture
        .set_cursor(&definition.workflow.id, due_cursor)
        .await;
    let mut replica = client(&fixture.url).await;
    let held = replica.transaction().await.unwrap();
    held.query_one(
        &format!(
            "SELECT cursor_at FROM {}.calendar_cursors WHERE workflow_id=$1 AND trigger_id='month-end' FOR UPDATE",
            namespace
        ),
        &[&definition.workflow.id],
    )
    .await
    .unwrap();
    let skipped = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        first_store.admit_calendar_due(&definition, "month-end", runtime),
    )
    .await
    .expect("a cursor another replica holds is skipped, not waited on")
    .unwrap();
    assert_eq!(skipped, CalendarCheck::Idle);
    held.rollback().await.unwrap();

    sql.execute(
        &format!(
            "UPDATE {}.control SET restore_hold=true WHERE id",
            namespace
        ),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "month-end", runtime)
            .await
            .unwrap_err()
            .code,
        "restore-hold"
    );
    sql.execute(
        &format!(
            "UPDATE {}.control SET restore_hold=false,admissions_hold=true WHERE id",
            namespace
        ),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "month-end", runtime)
            .await
            .unwrap_err()
            .code,
        "restore-admissions-held"
    );
    sql.execute(
        &format!(
            "UPDATE {}.control SET admissions_hold=false,active_flows_digest='calendar-replaced' WHERE id",
            namespace
        ),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "month-end", runtime)
            .await
            .unwrap_err()
            .code,
        "store-unavailable",
        "a moved activation fences the old calendar runner"
    );
    assert_eq!(fixture.runs().await, 1, "a fenced check admits nothing");
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(feature = "postgres-test")]
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "postgres-test")]
impl Capture {
    fn entries(&self) -> Vec<Value> {
        std::str::from_utf8(&self.0.lock().unwrap())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// A new Workflow revision keeps the trigger's due occurrence when its
/// schedule is unchanged. A changed cron or time zone starts the new schedule
/// at the check's time instead, and the check counts, returns and audits the
/// previous schedule's due occurrences it does not run.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn a_revision_keeps_due_occurrences_unless_its_schedule_changed() {
    let fixture = Fixture::new().await;
    let capture = Capture::default();
    let store = fixture.store_auditing_to(capture.clone()).await;
    let runtime = &fixture.runtime;
    let month_end = CalendarSchedule::parse("5 8 L * *", "Asia/Bangkok").unwrap();
    let definition = fixture.definition(&project());
    let workflow = definition.workflow.id.clone();
    assert_eq!(
        store
            .admit_calendar_due(&definition, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Idle,
        "the first check seeds the cursor"
    );

    let mut revised_project = project();
    revised_project["workflow"]["deadlineSeconds"] = json!(7200);
    let revised = fixture.definition(&revised_project);
    assert_ne!(revised.digest, definition.digest);
    let now = fixture.now().await;
    let cursor = now - chrono::Duration::days(40);
    fixture.set_cursor(&workflow, cursor).await;
    let expected = month_end.latest_since(cursor, now).unwrap();
    let CalendarCheck::Admitted(admission) = store
        .admit_calendar_due(&revised, "month-end", runtime)
        .await
        .unwrap()
    else {
        panic!("a revision with the same schedule keeps the due occurrence")
    };
    assert_eq!(
        Some(admission.scheduled_at),
        expected.latest.map(|occurrence| occurrence.scheduled_at)
    );
    assert_eq!(admission.skipped, expected.skipped);
    assert_eq!(fixture.runs().await, 1);

    let mut same_schedule = revised_project.clone();
    same_schedule["workflow"]["calendarTriggers"]["month-end"]["cron"] = json!("05 08 L * *");
    let rewritten = fixture.definition(&same_schedule);
    assert_ne!(rewritten.digest, revised.digest);
    assert_eq!(
        store
            .admit_calendar_due(&rewritten, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Idle,
        "the same schedule written differently is not a schedule change"
    );

    let cursor_row = |namespace: &str| {
        format!(
            "SELECT workflow_revision,schedule_cron,schedule_timezone,cursor_at,skipped_count FROM {namespace}.calendar_cursors WHERE workflow_id=$1 AND trigger_id='month-end'"
        )
    };
    let before: i64 = fixture
        .sql
        .query_one(&cursor_row(&fixture.namespace), &[&workflow])
        .await
        .unwrap()
        .get(4);
    let now = fixture.now().await;
    let cursor = now - chrono::Duration::days(40);
    fixture.set_cursor(&workflow, cursor).await;
    let previous = month_end.latest_since(cursor, now).unwrap();
    let dropped = previous.skipped + u64::from(previous.latest.is_some());
    assert!(dropped >= 1);
    let first_day = CalendarSchedule::parse("5 8 1 * *", "Asia/Bangkok").unwrap();
    assert!(
        first_day
            .latest_since(cursor, now)
            .unwrap()
            .latest
            .is_some(),
        "the new schedule also has an occurrence the reschedule must not admit"
    );
    let mut changed_project = revised_project.clone();
    changed_project["workflow"]["calendarTriggers"]["month-end"]["cron"] = json!("5 8 1 * *");
    let changed = fixture.definition(&changed_project);
    let audited_before = capture.entries().len();
    assert_eq!(
        store
            .admit_calendar_due(&changed, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Rescheduled { skipped: dropped }
    );
    let row = fixture
        .sql
        .query_one(&cursor_row(&fixture.namespace), &[&workflow])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), changed.digest);
    assert_eq!(row.get::<_, String>(1), "5 8 1 * *");
    assert_eq!(row.get::<_, String>(2), "Asia/Bangkok");
    assert!(row.get::<_, chrono::DateTime<chrono::Utc>>(3) >= now);
    assert_eq!(
        row.get::<_, i64>(4),
        before + i64::try_from(dropped).unwrap()
    );
    assert_eq!(
        fixture.runs().await,
        1,
        "neither schedule's occurrence in the gap is admitted"
    );
    let audited = capture.entries().split_off(audited_before);
    assert_eq!(audited.len(), 2, "{audited:?}");
    assert_eq!(audited[0]["phase"], "request");
    assert_eq!(audited[0]["record"]["action"], "calendar-reschedule");
    assert!(audited[0]["record"]["workflowRef"].is_string());
    assert!(audited[0]["record"]["triggerRef"].is_string());
    assert_eq!(audited[1]["phase"], "response");
    assert_eq!(
        audited[1]["record"],
        json!({"action":"calendar-reschedule","outcome":"accepted","skipped":dropped})
    );
    assert_eq!(
        store
            .admit_calendar_due(&changed, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Idle,
        "the new schedule starts at the reschedule"
    );

    let mut moved_zone = changed_project.clone();
    moved_zone["workflow"]["calendarTriggers"]["month-end"]["timezone"] = json!("UTC");
    let moved = fixture.definition(&moved_zone);
    assert_eq!(
        store
            .admit_calendar_due(&moved, "month-end", runtime)
            .await
            .unwrap(),
        CalendarCheck::Rescheduled { skipped: 0 },
        "a time zone change alone also reschedules"
    );
    assert_eq!(
        fixture
            .sql
            .query_one(&cursor_row(&fixture.namespace), &[&workflow])
            .await
            .unwrap()
            .get::<_, String>(2),
        "UTC"
    );
}

#[cfg(feature = "postgres-test")]
struct AuditOutage;

#[cfg(feature = "postgres-test")]
impl std::io::Write for AuditOutage {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("synthetic audit outage"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Durable audit precedes a calendar admission or reschedule: without it the
/// check refuses and writes nothing.
#[cfg(feature = "postgres-test")]
#[tokio::test]
async fn an_audit_outage_admits_and_reschedules_nothing() {
    let fixture = Fixture::new().await;
    let definition = fixture.definition(&project());
    let workflow = definition.workflow.id.clone();
    let store = fixture.store().await;
    assert_eq!(
        store
            .admit_calendar_due(&definition, "month-end", &fixture.runtime)
            .await
            .unwrap(),
        CalendarCheck::Idle
    );
    let cursor = fixture.now().await - chrono::Duration::days(40);
    fixture.set_cursor(&workflow, cursor).await;
    let mut changed_project = project();
    changed_project["workflow"]["calendarTriggers"]["month-end"]["cron"] = json!("5 8 1 * *");
    let changed = fixture.definition(&changed_project);
    let unaudited = fixture.store_auditing_to(AuditOutage).await;
    for candidate in [&definition, &changed] {
        assert_eq!(
            unaudited
                .admit_calendar_due(candidate, "month-end", &fixture.runtime)
                .await
                .unwrap_err()
                .code,
            "audit-unavailable"
        );
    }
    let row = fixture
        .sql
        .query_one(
            &format!(
                "SELECT schedule_cron,cursor_at,skipped_count FROM {}.calendar_cursors WHERE workflow_id=$1 AND trigger_id='month-end'",
                fixture.namespace
            ),
            &[&workflow],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "5 8 L * *");
    assert_eq!(row.get::<_, chrono::DateTime<chrono::Utc>>(1), cursor);
    assert_eq!(row.get::<_, i64>(2), 0);
    assert_eq!(fixture.runs().await, 0);
}
