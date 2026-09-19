#![cfg(feature = "postgres-test")]

use std::env;

use serde_json::json;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, Error, NoTls};
use uuid::Uuid;

const MIGRATIONS_1_TO_15: &[(i64, &str)] = &[
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
    (15, include_str!("../migrations/0015_hosted_result.sql")),
];
const MIGRATION_16: &str = include_str!("../migrations/0016_unified_reviews.sql");

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

async fn apply_versions_1_to_15(database: &mut Client) {
    database
        .batch_execute(
            "CREATE TABLE casework_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .expect("create migration ledger");

    for (version, migration) in MIGRATIONS_1_TO_15 {
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

async fn apply_version_16(database: &mut Client) -> Result<(), Error> {
    let transaction = database.transaction().await?;
    transaction.batch_execute(MIGRATION_16).await?;
    transaction
        .execute(
            "INSERT INTO casework_schema_migrations(version, applied_at) VALUES(16, now())",
            &[],
        )
        .await?;
    transaction.commit().await
}

fn assert_sqlstate(error: &Error, expected: &SqlState, operation: &str) {
    assert_eq!(
        error.as_db_error().map(|database| database.code()),
        Some(expected),
        "{operation} must fail with SQLSTATE {} but returned {error}",
        expected.code()
    );
}

async fn insert_legacy_item(database: &Client, item_id: Uuid) {
    database
        .execute(
            "INSERT INTO casework_items(\
                 item_id, source_id, subject_kind, subject_id, occurrence_kind, occurrence_key,\
                 binding, state, queue_id, revision, first_observed_at, updated_at\
             ) VALUES($1, 'legacy-source', 'record', $2, 'review', $2, $3,\
                      'open', 'legacy-queue', 1, now(), now())",
            &[
                &item_id,
                &item_id.to_string(),
                &json!({"version": "legacy-1"}),
            ],
        )
        .await
        .expect("insert legacy source item");
}

async fn insert_legacy_hosted_item(database: &Client, item_id: Uuid) {
    database
        .execute(
            "INSERT INTO casework_hosted_items(\
                 item_id, kind_id, kind_version, kind_policy_digest, kind_policy, queue_id,\
                 state, revision, created_at, updated_at\
             ) VALUES($1, 'legacy-kind', '1', 'sha256:legacy', $2, 'legacy-queue',\
                      'open', 1, now(), now())",
            &[&item_id, &json!({"kind": "legacy"})],
        )
        .await
        .expect("insert legacy hosted item");
}

#[derive(Clone, Copy)]
enum OccupiedLegacyTable {
    SourceItems,
    HostedItems,
    TaskGrants,
}

impl OccupiedLegacyTable {
    fn name(self) -> &'static str {
        match self {
            Self::SourceItems => "casework_items",
            Self::HostedItems => "casework_hosted_items",
            Self::TaskGrants => "casework_task_grants",
        }
    }

    fn primary_key(self) -> &'static str {
        match self {
            Self::SourceItems | Self::HostedItems => "item_id",
            Self::TaskGrants => "grant_id",
        }
    }
}

async fn insert_occupied_legacy_row(database: &Client, occupied: OccupiedLegacyTable) -> Uuid {
    let row_id = Uuid::new_v4();
    match occupied {
        OccupiedLegacyTable::SourceItems => insert_legacy_item(database, row_id).await,
        OccupiedLegacyTable::HostedItems => insert_legacy_hosted_item(database, row_id).await,
        OccupiedLegacyTable::TaskGrants => {
            let item_id = Uuid::new_v4();
            insert_legacy_item(database, item_id).await;
            database
                .execute(
                    "INSERT INTO casework_task_grants(\
                         grant_id, item_id, approver_issuer, approver_subject, approver_profile,\
                         approver_role, idempotency_key, request_hash, record, approved_at, expires_at\
                     ) VALUES($1, $2, 'https://issuer.test', 'reviewer', 'staff', 'staff',\
                              'legacy-key', 'legacy-hash', $3, now(), now() + interval '10 minutes')",
                    &[&row_id, &item_id, &json!({"legacy": true})],
                )
                .await
                .expect("insert legacy task grant");

            // A healthy v15 task grant necessarily has a source item parent. Recreate an
            // imported/drifted-but-ledgered v15 snapshot so this case proves the explicit
            // task-grant guard rather than succeeding because the source-item guard fired.
            database
                .batch_execute(
                    "ALTER TABLE casework_task_grants
                         DROP CONSTRAINT casework_task_grants_item_id_fkey;
                     DELETE FROM casework_items;
                     ALTER TABLE casework_task_grants
                         ADD CONSTRAINT casework_task_grants_item_id_fkey
                         FOREIGN KEY (item_id) REFERENCES casework_items(item_id)
                         ON DELETE CASCADE NOT VALID",
                )
                .await
                .expect("isolate legacy task-grant occupancy");
        }
    }
    row_id
}

async fn legacy_row_fingerprint(
    database: &Client,
    occupied: OccupiedLegacyTable,
    row_id: Uuid,
) -> String {
    let query = format!(
        "SELECT row_to_json(selected)::text FROM (SELECT * FROM {} WHERE {}=$1) selected",
        occupied.name(),
        occupied.primary_key()
    );
    database
        .query_one(&query, &[&row_id])
        .await
        .expect("read retained legacy row")
        .get(0)
}

async fn assert_occupied_refusal(occupied: OccupiedLegacyTable) {
    let mut fixture = TestSchema::create("review_cutover_refusal").await;
    apply_versions_1_to_15(&mut fixture.database).await;
    let row_id = insert_occupied_legacy_row(&fixture.database, occupied).await;
    let before = legacy_row_fingerprint(&fixture.database, occupied, row_id).await;

    let error = apply_version_16(&mut fixture.database)
        .await
        .expect_err("occupied legacy workflow state must refuse migration 16");
    assert_sqlstate(
        &error,
        &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
        "occupied legacy cutover",
    );

    assert_eq!(
        legacy_row_fingerprint(&fixture.database, occupied, row_id).await,
        before,
        "refused cutover must leave the legacy row unchanged"
    );
    let version_16_recorded: bool = fixture
        .database
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM casework_schema_migrations WHERE version=16)",
            &[],
        )
        .await
        .expect("read refused migration ledger")
        .get(0);
    assert!(!version_16_recorded, "a refused migration is not ledgered");
    let unified_tables: i64 = fixture
        .database
        .query_one(
            "SELECT count(*)
             FROM pg_class relations
             JOIN pg_namespace schemas ON schemas.oid=relations.relnamespace
             WHERE schemas.nspname=current_schema()
               AND relations.relkind='r'
               AND relations.relname LIKE 'casework_review_%'",
            &[],
        )
        .await
        .expect("inspect refused unified schema")
        .get(0);
    assert_eq!(
        unified_tables, 0,
        "a refused migration must not leave any unified-review table"
    );

    fixture.cleanup().await;
}

#[tokio::test]
async fn fresh_database_applies_the_full_migration_sequence() {
    let mut fixture = TestSchema::create("review_cutover_fresh").await;
    apply_versions_1_to_15(&mut fixture.database).await;
    apply_version_16(&mut fixture.database)
        .await
        .expect("apply unified review migration to an empty legacy schema");

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
    assert_eq!(versions, (1..=16).collect::<Vec<_>>());

    let missing_tables: Vec<String> = fixture
        .database
        .query(
            "SELECT expected.name
             FROM unnest(ARRAY[
                 'casework_review_requests',
                 'casework_review_submission_reservations',
                 'casework_review_tasks',
                 'casework_review_task_drafts',
                 'casework_review_decisions',
                 'casework_review_results',
                 'casework_review_terminal_events',
                 'casework_review_completion_outbox',
                 'casework_review_history',
                 'casework_review_accountability'
             ]) AS expected(name)
             WHERE to_regclass(expected.name) IS NULL",
            &[],
        )
        .await
        .expect("inspect unified review tables")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        missing_tables.is_empty(),
        "migration 16 omitted unified review tables: {missing_tables:?}"
    );

    fixture.cleanup().await;
}

#[tokio::test]
async fn source_item_occupancy_refuses_without_data_loss() {
    assert_occupied_refusal(OccupiedLegacyTable::SourceItems).await;
}

#[tokio::test]
async fn hosted_item_occupancy_refuses_without_data_loss() {
    assert_occupied_refusal(OccupiedLegacyTable::HostedItems).await;
}

#[tokio::test]
async fn task_grant_occupancy_refuses_without_data_loss() {
    assert_occupied_refusal(OccupiedLegacyTable::TaskGrants).await;
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
    apply_versions_1_to_15(&mut fixture.database).await;
    apply_version_16(&mut fixture.database)
        .await
        .expect("apply unified review migration");

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
    apply_versions_1_to_15(&mut fixture.database).await;
    apply_version_16(&mut fixture.database)
        .await
        .expect("apply unified review migration");

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
