#![cfg(feature = "postgres-test")]

use std::env;

use serde_json::json;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, Error, NoTls};
use uuid::Uuid;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_casework.sql")),
    (2, include_str!("../migrations/0002_hosted_casework.sql")),
    (3, include_str!("../migrations/0003_assignment.sql")),
    (4, include_str!("../migrations/0004_clocks.sql")),
    (5, include_str!("../migrations/0005_source_retention.sql")),
    (6, include_str!("../migrations/0006_source_history.sql")),
    (7, include_str!("../migrations/0007_directory_targets.sql")),
    (
        8,
        include_str!("../migrations/0008_retention_and_inbox_indexes.sql"),
    ),
    (
        9,
        include_str!("../migrations/0009_directory_display_names.sql"),
    ),
    (
        10,
        include_str!("../migrations/0010_reference_lookup_and_sort.sql"),
    ),
    (
        11,
        include_str!("../migrations/0011_source_reconciliation_progress.sql"),
    ),
    (12, include_str!("../migrations/0012_absence_cursors.sql")),
    (
        13,
        include_str!("../migrations/0013_sync_claim_indexes.sql"),
    ),
    (14, include_str!("../migrations/0014_task_grants.sql")),
    (15, include_str!("../migrations/0015_unified_reviews.sql")),
];

/// Legacy hosted tables that the unified review migration (0015) drops
/// outright, since no Casework database was ever deployed on the earlier
/// experimental hosted-item schema.
const DROPPED_LEGACY_TABLES: &[&str] = &[
    "casework_hosted_items",
    "casework_hosted_notes",
    "casework_hosted_history",
    "casework_hosted_actor_references",
    "casework_hosted_terminal_events",
    "casework_hosted_accountability",
    "casework_hosted_idempotency",
    "casework_hosted_idempotency_tombstones",
    "casework_hosted_cursors",
];

const UNIFIED_REVIEW_TABLES: &[&str] = &[
    "casework_review_requests",
    "casework_review_submission_reservations",
    "casework_review_tasks",
    "casework_review_task_drafts",
    "casework_review_decisions",
    "casework_review_results",
    "casework_review_terminal_events",
    "casework_review_completion_outbox",
    "casework_review_history",
    "casework_review_accountability",
    "casework_review_task_grants",
    "casework_review_clock_occurrences",
    "casework_review_clock_effects",
];

struct TestSchema {
    admin: Client,
    database: Client,
    schema: String,
}

impl TestSchema {
    async fn create(prefix: &str) -> Self {
        let base = env::var("CASEWORK_REVIEW_MIGRATION_TEST_DATABASE_URL").expect(
            "CASEWORK_REVIEW_MIGRATION_TEST_DATABASE_URL must name a disposable PostgreSQL database",
        );
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
        let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
            .await
            .expect("connect dedicated review migration test database");
        tokio::spawn(async move {
            admin_connection
                .await
                .expect("review migration admin connection")
        });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .expect("create isolated review migration schema");

        let separator = if base.contains('?') { '&' } else { '?' };
        let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (database, database_connection) = tokio_postgres::connect(&scoped, NoTls)
            .await
            .expect("connect to isolated review migration schema");
        tokio::spawn(async move {
            database_connection
                .await
                .expect("review migration schema connection")
        });

        Self {
            admin,
            database,
            schema,
        }
    }

    async fn cleanup(self) {
        drop(self.database);
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .expect("drop isolated review migration schema");
    }
}

/// Apply every migration, 0001 through the unified review migration 0015, in
/// order under the ledger. Nothing in this suite tests a partial or refused
/// application of that sequence, so failures panic immediately.
async fn apply_full_migration_sequence(database: &mut Client) {
    database
        .batch_execute(
            "CREATE TABLE casework_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .expect("create migration ledger");

    for (version, migration) in MIGRATIONS {
        let transaction = database.transaction().await.expect("begin migration");
        transaction
            .batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("apply migration {version}: {error}"));
        transaction
            .execute(
                "INSERT INTO casework_schema_migrations(version, applied_at) VALUES($1, now())",
                &[version],
            )
            .await
            .unwrap_or_else(|error| panic!("record migration {version}: {error}"));
        transaction
            .commit()
            .await
            .unwrap_or_else(|error| panic!("commit migration {version}: {error}"));
    }
}

fn assert_sqlstate(error: &Error, expected: &SqlState, operation: &str) {
    assert_eq!(
        error.as_db_error().map(|database| database.code()),
        Some(expected),
        "{operation} must fail with SQLSTATE {} but returned {error}",
        expected.code()
    );
}

async fn table_exists(database: &Client, name: &str) -> bool {
    database
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&name])
        .await
        .expect("inspect table existence")
        .get(0)
}

#[tokio::test]
async fn fresh_database_migrates_through_unified_reviews() {
    let mut fixture = TestSchema::create("review_cutover_fresh").await;
    apply_full_migration_sequence(&mut fixture.database).await;

    let versions: Vec<i64> = fixture
        .database
        .query(
            "SELECT version FROM casework_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("read complete migration ledger")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(versions, (1..=15).collect::<Vec<_>>());

    for table in UNIFIED_REVIEW_TABLES {
        assert!(
            table_exists(&fixture.database, table).await,
            "unified review migration must create {table}"
        );
    }
    for table in DROPPED_LEGACY_TABLES {
        assert!(
            !table_exists(&fixture.database, table).await,
            "unified review migration must drop the legacy hosted table {table}"
        );
    }

    let draft_pk_columns: Vec<String> = fixture
        .database
        .query(
            "SELECT attname FROM pg_constraint
             JOIN unnest(conkey) WITH ORDINALITY AS key(attnum, ord) ON true
             JOIN pg_attribute ON pg_attribute.attrelid = conrelid AND pg_attribute.attnum = key.attnum
             WHERE conrelid = 'casework_review_task_drafts'::regclass AND contype = 'p'
             ORDER BY key.ord",
            &[],
        )
        .await
        .expect("read task draft primary key columns")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        draft_pk_columns,
        vec!["task_id", "actor_issuer", "actor_subject"],
        "a later holder's draft must not replace a prior holder's retained draft"
    );

    let context_bound: String = fixture
        .database
        .query_one(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint
             WHERE conrelid = 'casework_review_requests'::regclass
               AND conname = 'casework_review_requests_context_check'",
            &[],
        )
        .await
        .expect("read the request context size constraint")
        .get(0);
    assert!(
        context_bound.contains("1048576"),
        "request context must be bounded at one MiB, got: {context_bound}"
    );

    let body_bound: String = fixture
        .database
        .query_one(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint
             WHERE conrelid = 'casework_review_task_drafts'::regclass
               AND conname = 'casework_review_task_drafts_body_check'",
            &[],
        )
        .await
        .expect("read the task draft body size constraint")
        .get(0);
    assert!(
        body_bound.contains("1048576"),
        "draft body must be bounded at one MiB, got: {body_bound}"
    );

    fixture.cleanup().await;
}

async fn insert_review_request(database: &Client, request_id: Uuid, completion: bool) {
    let producer_id = format!("producer-{request_id}");
    let completion_destination = completion.then_some("completion");
    let completion_recipient = completion.then(|| request_id.to_string());
    database
        .execute(
            "INSERT INTO casework_review_requests(\
                 request_id, producer_id, producer_issuer, producer_subject, source_namespace,\
                 subject_source, subject_type, subject_id, subject_version, subject_digest,\
                 requester_reference, context_strategy, context, policy_id, policy_version,\
                 policy_digest, policy_snapshot, submission_digest, completion_destination,\
                 completion_recipient_binding, lifecycle, active_stage_index, revision,\
                 created_at, updated_at\
             ) VALUES(\
                 $1, $2, 'https://issuer.test', 'producer-service', 'source-namespace',\
                 'source', 'record', $3, '1', $4, 'requester-reference', 'submitted', $5,\
                 'policy', '1', $4, $5, $4, $6, $7, 'reviewing', 0, 1, now(), now()\
             )",
            &[
                &request_id,
                &producer_id,
                &request_id.to_string(),
                &format!("sha256:{}", "a".repeat(64)),
                &json!({"bounded": true}),
                &completion_destination,
                &completion_recipient,
            ],
        )
        .await
        .expect("insert review request fixture");
}

async fn insert_review_task(database: &Client, task_id: Uuid, request_id: Uuid) {
    database
        .execute(
            "INSERT INTO casework_review_tasks(\
                 task_id, request_id, stage_index, stage_id, slot, queue_id, state, revision,\
                 created_at, updated_at\
             ) VALUES($1, $2, 0, 'stage', 0, 'review', 'open', 1, now(), now())",
            &[&task_id, &request_id],
        )
        .await
        .expect("insert review task fixture");
}

#[tokio::test]
async fn unified_review_schema_refuses_subject_clock_without_kind_identity() {
    let mut fixture = TestSchema::create("review_subject_clock_identity").await;
    apply_full_migration_sequence(&mut fixture.database).await;
    let request_id = Uuid::new_v4();
    insert_review_request(&fixture.database, request_id, false).await;
    let error = fixture
        .database
        .execute(
            "INSERT INTO casework_review_clock_occurrences(
                clock_occurrence_id,clock_id,scope,correlation_key,
                subject_source,subject_type,subject_id,request_id,policy_digest,
                policy,state,anchor_at,due_at,created_at,updated_at)
             VALUES($1,'deadline','subject','subject','source','record',$2,$3,$4,$5,
                    'running',now(),now()+interval '1 hour',now(),now())",
            &[
                &Uuid::new_v4(),
                &request_id.to_string(),
                &request_id,
                &format!("sha256:{}", "b".repeat(64)),
                &json!({"clock":{"type":"subject"}}),
            ],
        )
        .await
        .expect_err("subject clock without a review-kind identity must be refused");
    assert_sqlstate(
        &error,
        &SqlState::CHECK_VIOLATION,
        "subject clock kind identity",
    );

    fixture.cleanup().await;
}

async fn expect_foreign_key_violation(
    database: &Client,
    statement: &str,
    parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    operation: &str,
) {
    let error = match database.execute(statement, parameters).await {
        Ok(_) => panic!("{operation} unexpectedly accepted a cross-request binding"),
        Err(error) => error,
    };
    assert_sqlstate(&error, &SqlState::FOREIGN_KEY_VIOLATION, operation);
}

#[tokio::test]
async fn composite_foreign_keys_refuse_cross_request_substitution() {
    let mut fixture = TestSchema::create("review_fk").await;
    apply_full_migration_sequence(&mut fixture.database).await;

    let request_a = Uuid::new_v4();
    let request_b = Uuid::new_v4();
    let task_a = Uuid::new_v4();
    insert_review_request(&fixture.database, request_a, true).await;
    insert_review_request(&fixture.database, request_b, true).await;
    insert_review_task(&fixture.database, task_a, request_a).await;

    let decision_id = Uuid::new_v4();
    expect_foreign_key_violation(
        &fixture.database,
        "INSERT INTO casework_review_decisions(\
             decision_id, request_id, task_id, stage_index, actor_issuer, actor_subject,\
             profile_id, decision, decided_at\
         ) VALUES($1, $2, $3, 0, 'https://issuer.test', 'reviewer', 'staff', 'approve', now())",
        &[&decision_id, &request_b, &task_a],
        "decision task/request binding",
    )
    .await;

    let result_a = Uuid::new_v4();
    let producer_a = format!("producer-{request_a}");
    let producer_b = format!("producer-{request_b}");
    fixture
        .database
        .execute(
            "INSERT INTO casework_review_results(\
                 result_id, request_id, status, completed_at, available_until\
             ) VALUES($1, $2, 'approved', now(), now() + interval '1 day')",
            &[&result_a, &request_a],
        )
        .await
        .expect("insert result fixture");
    let mismatched_event = Uuid::new_v4();
    expect_foreign_key_violation(
        &fixture.database,
        "INSERT INTO casework_review_terminal_events(\
             event_id, request_id, result_id, producer_id, completed_at, retained_until\
         ) VALUES($1, $2, $3, $4, now(), now() + interval '1 day')",
        &[&mismatched_event, &request_b, &result_a, &producer_b],
        "terminal event result/request binding",
    )
    .await;

    let mismatched_producer_event = Uuid::new_v4();
    expect_foreign_key_violation(
        &fixture.database,
        "INSERT INTO casework_review_terminal_events(\
             event_id, request_id, result_id, producer_id, completed_at, retained_until\
         ) VALUES($1, $2, $3, $4, now(), now() + interval '1 day')",
        &[
            &mismatched_producer_event,
            &request_a,
            &result_a,
            &producer_b,
        ],
        "terminal event producer/request binding",
    )
    .await;

    let event_a = Uuid::new_v4();
    fixture
        .database
        .execute(
            "INSERT INTO casework_review_terminal_events(\
                 event_id, request_id, result_id, producer_id, completed_at, retained_until\
             ) VALUES($1, $2, $3, $4, now(), now() + interval '1 day')",
            &[&event_a, &request_a, &result_a, &producer_a],
        )
        .await
        .expect("insert terminal event fixture");
    expect_foreign_key_violation(
        &fixture.database,
        "INSERT INTO casework_review_completion_outbox(\
             event_id, request_id, destination_id, recipient_binding, state, next_attempt_at,\
             retained_until\
         ) VALUES($1, $2, 'completion', $3, 'pending', now(), now() + interval '1 day')",
        &[&event_a, &request_b, &request_b.to_string()],
        "completion outbox event/request binding",
    )
    .await;

    expect_foreign_key_violation(
        &fixture.database,
        "INSERT INTO casework_review_completion_outbox(\
             event_id, request_id, destination_id, recipient_binding, state, next_attempt_at,\
             retained_until\
         ) VALUES($1, $2, 'completion', $3, 'pending', now(), now() + interval '1 day')",
        &[&event_a, &request_a, &request_b.to_string()],
        "completion outbox recipient/request binding",
    )
    .await;

    let history_id = Uuid::new_v4();
    expect_foreign_key_violation(
        &fixture.database,
        "INSERT INTO casework_review_history(\
             event_id, request_id, task_id, kind, detail, occurred_at\
         ) VALUES($1, $2, $3, 'decision', '{}'::jsonb, now())",
        &[&history_id, &request_b, &task_a],
        "history task/request binding",
    )
    .await;

    fixture.cleanup().await;
}

async fn expect_result_check_violation(
    database: &Client,
    request_id: Uuid,
    status: &str,
    outcome: Option<&str>,
    result: Option<serde_json::Value>,
) {
    let result_id = Uuid::new_v4();
    let error = match database
        .execute(
            "INSERT INTO casework_review_results(\
                 result_id, request_id, status, outcome, result, completed_at, available_until\
             ) VALUES($1, $2, $3, $4, $5, now(), now() + interval '1 day')",
            &[&result_id, &request_id, &status, &outcome, &result],
        )
        .await
    {
        Ok(_) => panic!("invalid result shape unexpectedly accepted status {status}"),
        Err(error) => error,
    };
    assert_sqlstate(
        &error,
        &SqlState::CHECK_VIOLATION,
        &format!("result shape for status {status}"),
    );
}

#[tokio::test]
async fn result_status_and_outcome_shapes_are_database_enforced() {
    let mut fixture = TestSchema::create("review_result_shape").await;
    apply_full_migration_sequence(&mut fixture.database).await;

    for (status, outcome, result) in [
        ("unknown", None, None),
        ("approved", Some("not-allowed"), None),
        ("approved", None, Some(json!({"not": "allowed"}))),
        ("cancelled", Some("not-allowed"), None),
        ("superseded", None, Some(json!({"not": "allowed"}))),
        ("rejected", None, None),
        ("changes_requested", None, None),
        ("answered", None, None),
    ] {
        let request_id = Uuid::new_v4();
        insert_review_request(&fixture.database, request_id, false).await;
        expect_result_check_violation(&fixture.database, request_id, status, outcome, result).await;
    }

    let approved_request = Uuid::new_v4();
    insert_review_request(&fixture.database, approved_request, false).await;
    fixture
        .database
        .execute(
            "INSERT INTO casework_review_results(\
                 result_id, request_id, status, completed_at, available_until\
             ) VALUES($1, $2, 'approved', now(), now() + interval '1 day')",
            &[&Uuid::new_v4(), &approved_request],
        )
        .await
        .expect("approved result without outcome or body is valid");

    let rejected_request = Uuid::new_v4();
    insert_review_request(&fixture.database, rejected_request, false).await;
    fixture
        .database
        .execute(
            "INSERT INTO casework_review_results(\
                 result_id, request_id, status, outcome, result, completed_at, available_until\
             ) VALUES($1, $2, 'rejected', 'configured-outcome', $3, now(), now() + interval '1 day')",
            &[&Uuid::new_v4(), &rejected_request, &json!({"bounded": true})],
        )
        .await
        .expect("rejected result with a configured outcome is valid");

    fixture.cleanup().await;
}
