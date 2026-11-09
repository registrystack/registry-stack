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
#[tokio::test]
async fn calendar_admission_is_latest_only_atomic_and_fenced() {
    use async_trait::async_trait;
    use registry_coordinator::{
        calendar_trigger::CalendarSchedule,
        protocol::{AdapterSet, CallOutcome, CallRequest},
        runtime::RuntimeConfig,
        store::Store,
        worker::Worker,
    };
    use std::sync::Arc;
    use uuid::Uuid;

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

    async fn client(url: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        client
    }

    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("use a disposable PostgreSQL 17+ database");
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let base = Store::connect(&url, &namespace).await.unwrap();
    base.migrate().await.unwrap();
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
    let first_store = Arc::new(base.with_workflows_digest("calendar-active".into()));
    let second_store = Arc::new(
        Store::connect(&url, &namespace)
            .await
            .unwrap()
            .with_workflows_digest("calendar-active".into()),
    );
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
    write(root.path(), &project());
    let definition = Arc::new(Definition::load(root.path()).unwrap());
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "not-reviewed", &runtime)
            .await
            .unwrap_err()
            .code,
        "calendar-invalid",
        "Store derives the schedule only from the checked trigger"
    );
    assert!(first_store
        .admit_calendar_due(&definition, "month-end", &runtime)
        .await
        .unwrap()
        .is_none());
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
    assert!(first_store
        .admit_calendar_due(&definition, "month-end", &runtime)
        .await
        .unwrap()
        .is_none());
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
    let database_now: chrono::DateTime<chrono::Utc> = sql
        .query_one("SELECT transaction_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
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
    sql.execute(
        &format!(
            "UPDATE {}.calendar_cursors SET cursor_at=$3 WHERE workflow_id=$1 AND trigger_id=$2",
            namespace
        ),
        &[&definition.workflow.id, &"month-end", &catch_up_cursor],
    )
    .await
    .unwrap();

    let (left, right) = tokio::join!(
        first_store.admit_calendar_due(&definition, "month-end", &runtime),
        second_store.admit_calendar_due(&definition, "month-end", &runtime)
    );
    let admissions = [left.unwrap(), right.unwrap()]
        .into_iter()
        .flatten()
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
    let replay = first_store
        .admit_calendar_due(&definition, "month-end", &runtime)
        .await
        .unwrap()
        .expect("the rewound cursor finds the same occurrence");
    assert_eq!(replay.run_id, run);
    assert_eq!(
        sql.query_one(&format!("SELECT count(*) FROM {}.runs", namespace), &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1,
        "workflow and occurrence identity admits exactly one run"
    );

    let revision_now: chrono::DateTime<chrono::Utc> = sql
        .query_one("SELECT transaction_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    let prior_cursor = revision_now - chrono::Duration::days(40);
    assert!(CalendarSchedule::parse("5 8 1 * *", "Asia/Bangkok")
        .unwrap()
        .latest_since(prior_cursor, revision_now)
        .unwrap()
        .latest
        .is_some());
    sql.execute(
        &format!(
            "UPDATE {}.calendar_cursors SET workflow_revision=$3,cursor_at=$4 WHERE workflow_id=$1 AND trigger_id=$2",
            namespace
        ),
        &[
            &definition.workflow.id,
            &"month-end",
            &definition.digest,
            &prior_cursor,
        ],
    )
    .await
    .unwrap();
    let mut changed_project = project();
    changed_project["workflow"]["calendarTriggers"]["month-end"]["cron"] = json!("5 8 1 * *");
    write(root.path(), &changed_project);
    let changed_definition = Definition::load(root.path()).unwrap();
    assert!(first_store
        .admit_calendar_due(&changed_definition, "month-end", &runtime)
        .await
        .unwrap()
        .is_none());
    let revised = sql
        .query_one(
            &format!(
                "SELECT workflow_revision,cursor_at,(SELECT count(*) FROM {}.runs) FROM {}.calendar_cursors WHERE workflow_id=$1 AND trigger_id=$2",
                namespace, namespace
            ),
            &[&definition.workflow.id, &"month-end"],
        )
        .await
        .unwrap();
    assert_eq!(revised.get::<_, String>(0), changed_definition.digest);
    assert!(revised.get::<_, chrono::DateTime<chrono::Utc>>(1) >= revision_now);
    assert_eq!(
        revised.get::<_, i64>(2),
        1,
        "a changed schedule starts observing at its new revision rather than reinterpreting prior time"
    );

    let mut locker = client(&url).await;
    let admission_lock = locker.transaction().await.unwrap();
    admission_lock
        .query_one(
            &format!(
                "SELECT id FROM {}.admission_lock WHERE id FOR UPDATE",
                namespace
            ),
            &[],
        )
        .await
        .unwrap();
    let bounded = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        first_store.admit_calendar_due(&changed_definition, "month-end", &runtime),
    )
    .await
    .expect("calendar lock acquisition must remain bounded");
    assert_eq!(bounded.unwrap_err().code, "store-unavailable");
    admission_lock.rollback().await.unwrap();

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
            .admit_calendar_due(&definition, "month-end", &runtime)
            .await
            .unwrap_err()
            .code,
        "restore-hold"
    );
    sql.execute(
        &format!(
            "UPDATE {}.control SET restore_hold=false,active_flows_digest='calendar-replaced' WHERE id",
            namespace
        ),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        first_store
            .admit_calendar_due(&definition, "month-end", &runtime)
            .await
            .unwrap_err()
            .code,
        "store-unavailable",
        "a moved activation fences the old calendar runner"
    );
}
