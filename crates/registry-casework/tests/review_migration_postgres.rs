#![cfg(feature = "postgres-test")]

use std::env;

use chrono::{TimeDelta, Utc};
use registry_casework::{DatabaseConfig, PostgresStore};
use registry_platform_config::{SecretProvider, SecretResolver};
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

/// The migrations after the unified review migration that precede the
/// review, history, and clock protocol word migrations. A database the
/// previous release wrote has applied every one of them through 0019. The
/// last respells the occurrence states and touches no review table.
const MIGRATIONS_BEFORE_PROTOCOL_WORDS: &[(i64, &str)] = &[
    (
        16,
        include_str!("../migrations/0016_occurrence_identity_excludes_superseded.sql"),
    ),
    (17, include_str!("../migrations/0017_audit_writer.sql")),
    (
        18,
        include_str!("../migrations/0018_source_reconciliation_health.sql"),
    ),
    (19, include_str!("../migrations/0019_activations.sql")),
    (
        20,
        include_str!("../migrations/0020_review_task_discovery_indexes.sql"),
    ),
    (
        21,
        include_str!("../migrations/0021_own_review_decisions.sql"),
    ),
    (
        22,
        include_str!("../migrations/0022_occurrence_state_spelling.sql"),
    ),
];

const REVIEW_OUTCOME_SPELLING_MIGRATION: &str =
    include_str!("../migrations/0023_review_outcome_spelling.sql");

const HISTORY_EVENT_SPELLING_MIGRATION: &str =
    include_str!("../migrations/0024_history_event_spelling.sql");

const CLOCK_STAFFING_INBOX_SPELLING_MIGRATION: &str =
    include_str!("../migrations/0025_clock_staffing_inbox_spelling.sql");

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
    scoped_url: String,
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
            scoped_url: scoped,
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

    apply_migrations(database, MIGRATIONS).await;
}

async fn apply_migrations(database: &mut Client, migrations: &[(i64, &str)]) {
    for (version, migration) in migrations {
        apply_migration(database, *version, migration).await;
    }
}

/// Apply one migration under the ledger, in its own transaction.
async fn apply_migration(database: &mut Client, version: i64, migration: &str) {
    let transaction = database.transaction().await.expect("begin migration");
    transaction
        .batch_execute(migration)
        .await
        .unwrap_or_else(|error| panic!("apply migration {version}: {error}"));
    transaction
        .execute(
            "INSERT INTO casework_schema_migrations(version, applied_at) VALUES($1, now())",
            &[&version],
        )
        .await
        .unwrap_or_else(|error| panic!("record migration {version}: {error}"));
    transaction
        .commit()
        .await
        .unwrap_or_else(|error| panic!("commit migration {version}: {error}"));
}

/// Apply every migration a database holds before the protocol word
/// migrations: the schema the rows of the previous release live in.
async fn apply_migrations_before_protocol_words(database: &mut Client) {
    apply_full_migration_sequence(database).await;
    for (version, migration) in MIGRATIONS_BEFORE_PROTOCOL_WORDS {
        apply_migration(database, *version, migration).await;
    }
}

async fn text_values(database: &Client, query: &str) -> Vec<String> {
    database
        .query(query, &[])
        .await
        .unwrap_or_else(|error| panic!("{query}: {error}"))
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn json_value(database: &Client, query: &str) -> serde_json::Value {
    database
        .query_one(query, &[])
        .await
        .unwrap_or_else(|error| panic!("{query}: {error}"))
        .get(0)
}

/// The CHECK constraints of the listed tables: how many there are, and how
/// many still name `word`.
async fn check_constraints(database: &Client, tables: &[&str], word: &str) -> (i64, i64) {
    let row = database
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE position($2 in pg_get_constraintdef(oid)) > 0)
             FROM pg_constraint
             WHERE contype='c' AND conrelid = ANY(
                 SELECT to_regclass(name)::oid FROM unnest($1::text[]) AS listed(name))",
            &[&tables, &word],
        )
        .await
        .expect("inspect the check constraints");
    (row.get(0), row.get(1))
}

async fn row_count(database: &Client, table: &str) -> i64 {
    database
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .unwrap_or_else(|error| panic!("count {table}: {error}"))
        .get(0)
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
async fn migration_21_backfills_only_retained_legacy_decision_outcomes() {
    migrate_retained_review_outcomes(20).await;
}

#[tokio::test]
async fn migration_26_preserves_existing_retained_decision_outcomes() {
    migrate_retained_review_outcomes(21).await;
}

async fn migrate_retained_review_outcomes(from_schema: i64) {
    assert!((20..=21).contains(&from_schema));
    let mut fixture = TestSchema::create("review_outcome_backfill").await;
    apply_full_migration_sequence(&mut fixture.database).await;
    apply_migrations(
        &mut fixture.database,
        &[
            (
                16,
                include_str!("../migrations/0016_occurrence_identity_excludes_superseded.sql"),
            ),
            (17, include_str!("../migrations/0017_audit_writer.sql")),
            (
                18,
                include_str!("../migrations/0018_source_reconciliation_health.sql"),
            ),
            (19, include_str!("../migrations/0019_activations.sql")),
            (
                20,
                include_str!("../migrations/0020_review_task_discovery_indexes.sql"),
            ),
        ],
    )
    .await;
    assert_eq!(
        fixture
            .database
            .query_one("SELECT max(version) FROM casework_schema_migrations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        20
    );
    let outcome_column_exists: bool = fixture
        .database
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_attribute
             WHERE attrelid='casework_review_accountability'::regclass
               AND attname='outcome' AND NOT attisdropped)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!outcome_column_exists, "seed the actual pre-upgrade schema");

    let now = Utc::now();
    let mut cases = Vec::new();
    for (name, decision, outcome, expired, erased) in [
        ("retained-confirm", "answer", Some("confirm"), false, false),
        ("retained-return", "answer", Some("return"), false, false),
        ("expired-unerased", "answer", Some("confirm"), true, false),
        ("erased", "answer", Some("return"), true, true),
        ("approve", "approve", None, false, false),
    ] {
        let request_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        insert_review_request(&fixture.database, request_id, false).await;
        insert_review_task(&fixture.database, task_id, request_id).await;
        let terminal_at = now - TimeDelta::days(if expired { 91 } else { 1 });
        let available_until = terminal_at + TimeDelta::days(90);
        let retained_until = terminal_at + TimeDelta::days(365);
        let lifecycle = if decision == "approve" {
            "approved"
        } else {
            "answered"
        };
        fixture
            .database
            .execute(
                "UPDATE casework_review_requests
                 SET lifecycle=$2,active_stage_index=NULL,created_at=$3::timestamptz-interval '1 hour',
                     updated_at=$3,terminal_at=$3,result_available_until=$4,
                     accountability_retained_until=$5
                 WHERE request_id=$1",
                &[
                    &request_id,
                    &lifecycle,
                    &terminal_at,
                    &available_until,
                    &retained_until,
                ],
            )
            .await
            .expect("set consistent legacy result and accountability windows");
        fixture
            .database
            .execute(
                "UPDATE casework_review_tasks
                 SET state='decided',holder_issuer='https://issuer.test',holder_subject='reviewer',
                     assignment_kind='claim',created_at=$2::timestamptz-interval '1 hour',updated_at=$2,settled_at=$2
                 WHERE task_id=$1",
                &[&task_id, &terminal_at],
            )
            .await
            .unwrap();
        fixture
            .database
            .execute(
                "INSERT INTO casework_review_decisions(
                     decision_id,request_id,task_id,stage_index,actor_issuer,actor_subject,
                     profile_id,decision,outcome,decided_at)
                 VALUES($1,$2,$3,0,'https://issuer.test','reviewer','staff',$4,$5,$6)",
                &[
                    &Uuid::new_v4(),
                    &request_id,
                    &task_id,
                    &decision,
                    &outcome,
                    &terminal_at,
                ],
            )
            .await
            .unwrap();
        fixture
            .database
            .execute(
                "INSERT INTO casework_review_accountability(
                     event_id,request_id,task_id,queue_id,actor_ref,actor_issuer,actor_subject,
                     profile_id,decision,occurred_at,retained_until)
                 VALUES($1,$2,$3,'review','actor-reference','https://issuer.test','reviewer',
                        'staff',$4,$5,$6)",
                &[
                    &event_id,
                    &request_id,
                    &task_id,
                    &decision,
                    &terminal_at,
                    &retained_until,
                ],
            )
            .await
            .unwrap();
        if erased {
            // Schema 20 erasure removed task/decision data but retained the
            // minimized accountability row through its independent window.
            fixture
                .database
                .execute(
                    "DELETE FROM casework_review_tasks WHERE task_id=$1",
                    &[&task_id],
                )
                .await
                .unwrap();
            fixture
                .database
                .execute(
                    "UPDATE casework_review_requests SET context='{}'::jsonb,result_erased_at=$2
                     WHERE request_id=$1",
                    &[&request_id, &now],
                )
                .await
                .unwrap();
        }
        cases.push((name, event_id, task_id, outcome, expired, erased));
    }

    if from_schema == 21 {
        apply_migrations(
            &mut fixture.database,
            &[(
                21,
                include_str!("../migrations/0021_own_review_decisions.sql"),
            )],
        )
        .await;
    }
    assert_eq!(
        fixture
            .database
            .query_one("SELECT max(version) FROM casework_schema_migrations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        from_schema,
        "exercise the actual predecessor ledger before the runtime upgrade"
    );

    let secret_name =
        format!("CASEWORK_REVIEW_MIGRATION_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &fixture.scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&config, &secrets).unwrap();
    env::remove_var(&secret_name);
    store
        .migrate()
        .await
        .expect("migrate actual schema 20 to the current ledger");
    store.ready().await.expect("the migrated ledger is current");

    for (name, event_id, task_id, original_outcome, expired, erased) in cases {
        let row = fixture
            .database
            .query_one(
                "SELECT a.outcome,a.retained_until>now(),d.outcome,r.result_erased_at IS NOT NULL
                 FROM casework_review_accountability a
                 JOIN casework_review_requests r USING(request_id)
                 LEFT JOIN casework_review_decisions d ON d.task_id=a.task_id
                 WHERE a.event_id=$1 AND a.task_id=$2",
                &[&event_id, &task_id],
            )
            .await
            .unwrap();
        assert_eq!(
            row.get::<_, Option<String>>(0).as_deref(),
            if expired { None } else { original_outcome },
            "legacy backfill for {name} must not recover an expired selection or guess an approval outcome"
        );
        assert!(
            row.get::<_, bool>(1),
            "accountability for {name} is still retained"
        );
        assert_eq!(
            row.get::<_, Option<String>>(2).as_deref(),
            if erased { None } else { original_outcome },
            "{name} must distinguish expired-but-unerased data from erased data"
        );
        assert_eq!(row.get::<_, bool>(3), erased);
    }
    store
        .migrate()
        .await
        .expect("a second migration is a no-op");
    let versions: Vec<i64> = fixture
        .database
        .query(
            "SELECT version FROM casework_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(versions, (1..=26).collect::<Vec<_>>());
    drop(store);
    fixture.cleanup().await;
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

#[tokio::test]
async fn migration_23_respells_the_review_outcome_words_the_previous_release_stored() {
    let mut fixture = TestSchema::create("review_outcome_spelling").await;
    apply_migrations_before_protocol_words(&mut fixture.database).await;
    let database = &fixture.database;

    // Rows as the previous release wrote them: one review settled with changes
    // requested, one approved, one still reviewing after a stage advanced.
    let returned = Uuid::new_v4();
    let approved = Uuid::new_v4();
    let reviewing = Uuid::new_v4();
    let returned_task = Uuid::new_v4();
    let approved_task = Uuid::new_v4();
    let reviewing_task = Uuid::new_v4();
    for (request, task) in [
        (returned, returned_task),
        (approved, approved_task),
        (reviewing, reviewing_task),
    ] {
        insert_review_request(database, request, false).await;
        insert_review_task(database, task, request).await;
    }
    database
        .batch_execute(&format!(
            "UPDATE casework_review_tasks
             SET state='decided',holder_issuer='https://issuer.test',holder_subject='reviewer',
                 assignment_kind='claim',settled_at=now();
             UPDATE casework_review_requests
             SET lifecycle='changes_requested',active_stage_index=NULL,terminal_at=now(),
                 result_available_until=now()+interval '1 day',
                 accountability_retained_until=now()+interval '2 days'
             WHERE request_id='{returned}';
             UPDATE casework_review_requests
             SET lifecycle='approved',active_stage_index=NULL,terminal_at=now(),
                 result_available_until=now()+interval '1 day',
                 accountability_retained_until=now()+interval '2 days'
             WHERE request_id='{approved}';
             INSERT INTO casework_review_decisions(
                 decision_id,request_id,task_id,stage_index,actor_issuer,actor_subject,profile_id,
                 decision,outcome,decided_at)
             VALUES
                 (gen_random_uuid(),'{returned}','{returned_task}',0,'https://issuer.test','reviewer',
                  'staff','changes_requested','needs-change',now()),
                 (gen_random_uuid(),'{approved}','{approved_task}',0,'https://issuer.test','reviewer',
                  'staff','approve',NULL,now()),
                 (gen_random_uuid(),'{reviewing}','{reviewing_task}',0,'https://issuer.test','reviewer',
                  'staff','approve',NULL,now());
             INSERT INTO casework_review_results(
                 result_id,request_id,status,outcome,completed_at,available_until)
             VALUES
                 (gen_random_uuid(),'{returned}','changes_requested','needs-change',now(),
                  now()+interval '1 day'),
                 (gen_random_uuid(),'{approved}','approved',NULL,now(),now()+interval '1 day');
             INSERT INTO casework_review_accountability(
                 event_id,request_id,task_id,queue_id,actor_ref,actor_issuer,actor_subject,
                 profile_id,decision,occurred_at,retained_until)
             VALUES
                 (gen_random_uuid(),'{returned}','{returned_task}','review','actor','https://issuer.test',
                  'reviewer','staff','changes_requested',now(),now()+interval '2 days'),
                 (gen_random_uuid(),'{approved}','{approved_task}','review','actor','https://issuer.test',
                  'reviewer','staff','approve',now(),now()+interval '2 days');
             INSERT INTO casework_review_history(
                 event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
             VALUES
                 (gen_random_uuid(),'{returned}','{returned_task}','review_decided','actor',
                  '{{\"decision\":\"changes_requested\",\"transition\":\"changes_requested\"}}',now()),
                 (gen_random_uuid(),'{returned}',NULL,'review_settled',NULL,
                  '{{\"status\":\"changes_requested\"}}',now()),
                 (gen_random_uuid(),'{reviewing}','{reviewing_task}','review_decided','actor',
                  '{{\"decision\":\"approve\",\"transition\":\"stage_advanced\"}}',now()),
                 (gen_random_uuid(),'{approved}',NULL,'review_settled',NULL,
                  '{{\"status\":\"approved\"}}',now());
             INSERT INTO casework_idempotency(
                 issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,
                 response,created_at,review_request_id)
             VALUES
                 ('https://issuer.test','reviewer','staff','review.task.decide',
                  'review-task:{returned_task}','settled','hash-settled',
                  '{{\"type\":\"settled\",\"settlement\":{{\"status\":\"changes_requested\",\"outcome\":\"needs-change\"}}}}',
                  now(),'{returned}'),
                 ('https://issuer.test','reviewer','staff','review.task.decide',
                  'review-task:{reviewing_task}','advanced','hash-advanced',
                  '{{\"type\":\"stage_advanced\",\"completed_stage\":\"technical\",\"next_stage\":\"authority\"}}',
                  now(),'{reviewing}'),
                 ('https://issuer.test','reviewer','staff','review.task.decide',
                  'review-task:{approved_task}','approved','hash-approved',
                  '{{\"type\":\"settled\",\"settlement\":{{\"status\":\"approved\"}}}}',
                  now(),'{approved}'),
                 ('https://issuer.test','producer-service','producer','review.cancel',
                  'review-request:{returned}','cancel','hash-cancel',
                  '{{\"outcome\":\"already_terminal\",\"result\":{{\"status\":\"changes_requested\",\"outcome\":\"needs-change\"}}}}',
                  now(),'{returned}'),
                 ('https://issuer.test','producer-service','producer','review.cancel',
                  'review-request:{approved}','scrubbed','hash-scrubbed',NULL,now(),'{approved}');"
        ))
        .await
        .expect("store review rows as the previous release wrote them");
    let tables = [
        "casework_review_requests",
        "casework_review_decisions",
        "casework_review_results",
        "casework_review_accountability",
        "casework_review_history",
        "casework_idempotency",
    ];
    let mut counts_before = Vec::new();
    for table in tables {
        counts_before.push(row_count(database, table).await);
    }
    let (constraints_before, naming_previous) =
        check_constraints(database, &tables, "changes_requested").await;
    assert_eq!(naming_previous, 5);

    apply_migration(&mut fixture.database, 23, REVIEW_OUTCOME_SPELLING_MIGRATION).await;
    let database = &fixture.database;

    assert_eq!(
        check_constraints(database, &tables, "changes_requested").await,
        (constraints_before, 0),
        "every constraint is replaced, none is lost, none names the previous spelling"
    );
    assert_eq!(
        check_constraints(database, &tables, "changes-requested")
            .await
            .1,
        5
    );

    let mut counts_after = Vec::new();
    for table in tables {
        counts_after.push(row_count(database, table).await);
    }
    assert_eq!(counts_before, counts_after, "the migration removes no row");
    assert_eq!(
        text_values(
            database,
            "SELECT lifecycle FROM casework_review_requests ORDER BY lifecycle"
        )
        .await,
        ["approved", "changes-requested", "reviewing"]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT decision FROM casework_review_decisions ORDER BY decision"
        )
        .await,
        ["approve", "approve", "changes-requested"]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT status FROM casework_review_results ORDER BY status"
        )
        .await,
        ["approved", "changes-requested"]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT decision FROM casework_review_accountability ORDER BY decision"
        )
        .await,
        ["approve", "changes-requested"]
    );
    assert_eq!(
        json_value(
            database,
            "SELECT jsonb_agg(detail ORDER BY detail::text) FROM casework_review_history"
        )
        .await,
        json!([
            {"decision": "approve", "transition": "stage-advanced"},
            {"decision": "changes-requested", "transition": "changes-requested"},
            {"status": "approved"},
            {"status": "changes-requested"},
        ])
    );
    assert_eq!(
        json_value(
            database,
            "SELECT jsonb_object_agg(idempotency_key, response) FROM casework_idempotency"
        )
        .await,
        json!({
            "settled": {"type": "settled", "settlement": {"status": "changes-requested", "outcome": "needs-change"}},
            "advanced": {"type": "stage-advanced", "completed_stage": "technical", "next_stage": "authority"},
            "approved": {"type": "settled", "settlement": {"status": "approved"}},
            "cancel": {"outcome": "already-terminal", "result": {"status": "changes-requested", "outcome": "needs-change"}},
            "scrubbed": null,
        })
    );
    // A request digest was computed over the request as it was sent and is
    // never recomputed.
    assert_eq!(
        text_values(
            database,
            "SELECT request_hash FROM casework_idempotency ORDER BY request_hash"
        )
        .await,
        [
            "hash-advanced",
            "hash-approved",
            "hash-cancel",
            "hash-scrubbed",
            "hash-settled"
        ]
    );

    // The constraints now hold the current spelling and refuse the previous.
    for statement in [
        format!(
            "UPDATE casework_review_requests SET lifecycle='changes_requested' WHERE request_id='{approved}'"
        ),
        format!(
            "UPDATE casework_review_decisions SET decision='changes_requested',outcome='needs-change' WHERE request_id='{approved}'"
        ),
        format!(
            "UPDATE casework_review_results SET status='changes_requested',outcome='needs-change' WHERE request_id='{approved}'"
        ),
        // The shape constraints still bind the respelled words.
        format!(
            "UPDATE casework_review_decisions SET outcome=NULL WHERE request_id='{returned}'"
        ),
        format!("UPDATE casework_review_results SET outcome=NULL WHERE request_id='{returned}'"),
    ] {
        let error = database
            .batch_execute(&statement)
            .await
            .expect_err("the constraint refuses the statement");
        assert_sqlstate(&error, &SqlState::CHECK_VIOLATION, &statement);
    }

    fixture.cleanup().await;
}

#[tokio::test]
async fn migration_24_respells_the_history_and_event_words_the_previous_release_stored() {
    let mut fixture = TestSchema::create("history_event_spelling").await;
    apply_migrations_before_protocol_words(&mut fixture.database).await;
    apply_migration(&mut fixture.database, 23, REVIEW_OUTCOME_SPELLING_MIGRATION).await;
    let database = &fixture.database;

    // Rows as the previous release wrote them: one item with an entry of
    // every item history kind, one review with an entry of every review
    // history kind, the directory events, and two retained assignments.
    let item = Uuid::new_v4();
    database
        .execute(
            "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,
                 occurrence_key,binding,state,queue_id,revision,first_observed_at,updated_at)
             VALUES($1,'source','request','subject-1','review','review-1',$2,'open','queue',1,
                 now(),now())",
            &[&item, &json!({"version": "1"})],
        )
        .await
        .expect("store the item");
    let item_history: [(&str, &str, serde_json::Value); 25] = [
        ("observed", "system:reconciliation", json!({})),
        ("opened", "staff", json!({})),
        ("claimed", "staff", json!({})),
        (
            "assigned",
            "staff",
            json!({"reason": "directory_membership_changed"}),
        ),
        (
            "delegated",
            "staff",
            json!({"reason": "source_observation"}),
        ),
        ("caseload_moved", "staff", json!({"reason": "not_applied"})),
        ("released", "staff", json!({})),
        (
            "released",
            "system:reconciliation",
            json!({"previousHolder": "holder", "reason": "source_observation", "sourceRevision": 3}),
        ),
        (
            "released",
            "system:directory-reconciliation",
            json!({"previousHolder": "holder", "reason": "directory_membership_changed", "directoryRevision": 4}),
        ),
        ("draft_saved", "staff", json!({})),
        ("task_approved", "staff", json!({"grantId": "grant"})),
        ("task_revoked", "staff", json!({"grantId": "grant"})),
        (
            "task_invalidated",
            "system:task-grants",
            json!({"grantId": "grant"}),
        ),
        ("attempt_reserved", "staff", json!({"operation": "approve"})),
        (
            "attempt_uncertain",
            "staff",
            json!({"operation": "approve"}),
        ),
        ("action_completed", "staff", json!({"operation": "approve"})),
        (
            "attempt_settled",
            "system:operator",
            json!({"outcome": "not_applied", "reason": "the source shows not_applied", "decidedBy": "operator"}),
        ),
        (
            "attempt_settled",
            "system:operator",
            json!({"outcome": "applied", "reason": "confirmed", "decidedBy": "operator"}),
        ),
        ("clock_reminder", "system:clocks", json!({})),
        ("clock_step_applied", "system:clocks", json!({})),
        ("clock_recomputed", "staff", json!({})),
        ("superseded", "system:reconciliation", json!({})),
        ("completed", "system:reconciliation", json!({})),
        (
            "task_invalidated",
            "system:task-grants",
            json!({"grantId": "other"}),
        ),
        ("released", "staff", json!({"reason": "source_observation"})),
    ];
    for (index, (kind, profile, detail)) in item_history.iter().enumerate() {
        let event = Uuid::new_v4();
        let occurred_at = format!("2026-01-01T00:00:{index:02}Z");
        database
            .execute(
                "INSERT INTO casework_history(event_id,item_id,item_revision,kind,occurred_at,
                     profile_id,detail)
                 VALUES($1,$2,1,$3,$4::text::timestamptz,$5,$6)",
                &[&event, &item, kind, &occurred_at, profile, detail],
            )
            .await
            .expect("store an item history entry");
        database
            .execute(
                "INSERT INTO casework_events(event_id,item_id,item_revision,event_kind,occurred_at,
                     actor_reference,detail)
                 VALUES($1,$2,1,$3,$4::text::timestamptz,NULL,$5)",
                &[&event, &item, kind, &occurred_at, detail],
            )
            .await
            .expect("store an item event");
    }

    let request = Uuid::new_v4();
    insert_review_request(database, request, false).await;
    let review_history = [
        "clock_reminder",
        "clock_step_applied",
        "note",
        "request_created",
        "review_cancelled",
        "review_created",
        "review_decided",
        "review_settled",
        "review_superseded",
        "stage_advanced",
        "task_absence_reconciled",
        "task_assigned",
        "task_claimed",
        "task_delegated",
        "task_draft_saved",
        "task_grant_approved",
        "task_grant_invalidated",
        "task_grant_revoked",
        "task_released",
    ];
    for kind in review_history {
        database
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,
                     detail,occurred_at)
                 VALUES(gen_random_uuid(),$1,NULL,$2,NULL,$3,now())",
                &[
                    &request,
                    &kind,
                    &json!({"audience": "requester", "note": kind}),
                ],
            )
            .await
            .expect("store a review history entry");
    }

    let directory_events = [
        "absence_created",
        "absence_deleted",
        "absence_updated",
        "directory_bootstrapped",
        "team_updated",
    ];
    for kind in directory_events {
        database
            .execute(
                "INSERT INTO casework_directory_events(event_id,directory_revision,event_kind,
                     occurred_at,actor_issuer,actor_subject,profile_id,detail)
                 VALUES(gen_random_uuid(),1,$1,now(),'https://issuer.test','administrator',
                     'administrator',$2)",
                &[&kind, &json!({"teamId": "team_one"})],
            )
            .await
            .expect("store a directory event");
    }

    for (operation, key, hash) in [
        ("item.caseload_moved", "moved", "hash-moved"),
        ("item.assigned", "assigned", "hash-assigned"),
    ] {
        database
            .execute(
                "INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,
                     idempotency_key,request_hash,response,created_at)
                 VALUES('https://issuer.test','supervisor','staff',$1,$2,$3,$4,$5,now())",
                &[
                    &operation,
                    &item.to_string(),
                    &key,
                    &hash,
                    &json!({"revision": 2}),
                ],
            )
            .await
            .expect("store a retained assignment");
    }

    let tables = [
        "casework_history",
        "casework_events",
        "casework_review_history",
        "casework_directory_events",
        "casework_idempotency",
    ];
    let mut counts_before = Vec::new();
    for table in tables {
        counts_before.push(row_count(database, table).await);
    }

    apply_migration(&mut fixture.database, 24, HISTORY_EVENT_SPELLING_MIGRATION).await;
    let database = &fixture.database;

    let mut counts_after = Vec::new();
    for table in tables {
        counts_after.push(row_count(database, table).await);
    }
    assert_eq!(counts_before, counts_after, "the migration removes no row");

    let item_kinds = text_values(
        database,
        "SELECT kind FROM casework_history ORDER BY occurred_at",
    )
    .await;
    assert_eq!(
        item_kinds,
        [
            "observed",
            "opened",
            "claimed",
            "assigned",
            "delegated",
            "caseload-moved",
            "released",
            "released",
            "released",
            "draft-saved",
            "task-approved",
            "task-revoked",
            "task-invalidated",
            "attempt-reserved",
            "attempt-uncertain",
            "action-completed",
            "attempt-settled",
            "attempt-settled",
            "clock-reminder",
            "clock-step-applied",
            "clock-recomputed",
            "superseded",
            "completed",
            "task-invalidated",
            "released",
        ]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT event_kind FROM casework_events ORDER BY occurred_at"
        )
        .await,
        item_kinds,
        "an item event keeps the kind of its history entry"
    );
    let item_details = json_value(
        database,
        "SELECT jsonb_agg(detail ORDER BY occurred_at) FROM casework_history",
    )
    .await;
    assert_eq!(
        json_value(
            database,
            "SELECT jsonb_agg(detail ORDER BY occurred_at) FROM casework_events"
        )
        .await,
        item_details,
        "an item event keeps the detail of its history entry"
    );
    let item_details = item_details.as_array().expect("one detail per entry");
    // A reason a caller gave is free text, whatever it reads like.
    assert_eq!(
        item_details[3],
        json!({"reason": "directory_membership_changed"})
    );
    assert_eq!(item_details[4], json!({"reason": "source_observation"}));
    assert_eq!(item_details[5], json!({"reason": "not_applied"}));
    assert_eq!(item_details[24], json!({"reason": "source_observation"}));
    // The two reasons Casework itself writes are closed words.
    assert_eq!(
        item_details[7],
        json!({"previousHolder": "holder", "reason": "source-observation", "sourceRevision": 3})
    );
    assert_eq!(
        item_details[8],
        json!({"previousHolder": "holder", "reason": "directory-membership-changed", "directoryRevision": 4})
    );
    // A settlement outcome is a closed word; its reason is the operator's text.
    assert_eq!(
        item_details[16],
        json!({"outcome": "not-applied", "reason": "the source shows not_applied", "decidedBy": "operator"})
    );
    assert_eq!(
        item_details[17],
        json!({"outcome": "applied", "reason": "confirmed", "decidedBy": "operator"})
    );

    assert_eq!(
        text_values(
            database,
            "SELECT kind FROM casework_review_history ORDER BY kind COLLATE \"C\""
        )
        .await,
        [
            "clock-reminder",
            "clock-step-applied",
            "note",
            "request-created",
            "review-cancelled",
            "review-created",
            "review-decided",
            "review-settled",
            "review-superseded",
            "stage-advanced",
            "task-absence-reconciled",
            "task-assigned",
            "task-claimed",
            "task-delegated",
            "task-draft-saved",
            "task-grant-approved",
            "task-grant-invalidated",
            "task-grant-revoked",
            "task-released",
        ]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT detail->>'note' FROM casework_review_history
             ORDER BY detail->>'note' COLLATE \"C\""
        )
        .await,
        review_history,
        "a review history detail is left as it was written"
    );
    assert_eq!(
        text_values(
            database,
            "SELECT event_kind FROM casework_directory_events ORDER BY event_kind COLLATE \"C\""
        )
        .await,
        [
            "absence-created",
            "absence-deleted",
            "absence-updated",
            "directory-bootstrapped",
            "team-updated",
        ]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT DISTINCT detail->>'teamId' FROM casework_directory_events"
        )
        .await,
        ["team_one"]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT operation || ' ' || request_hash FROM casework_idempotency ORDER BY operation"
        )
        .await,
        [
            "item.assigned hash-assigned",
            "item.caseload-moved hash-moved"
        ],
        "a retained assignment is found under the respelled operation, its request hash unchanged"
    );

    // The invalidation function writes the kind its reader selects, and the
    // index that serves that reader selects on it.
    assert_eq!(
        text_values(
            database,
            "SELECT (position('''task-invalidated''' in prosrc) > 0)::text || ' '
                 || (position('task_invalidated' in prosrc) > 0)::text
             FROM pg_proc
             WHERE proname='casework_invalidate_ineligible_tasks'
               AND pronamespace=current_schema()::regnamespace"
        )
        .await,
        ["true false"]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT (position('task-invalidated' in indexdef) > 0)::text FROM pg_indexes
             WHERE schemaname=current_schema()
               AND indexname='casework_history_task_invalidated_idx'"
        )
        .await,
        ["true"]
    );

    fixture.cleanup().await;
}

#[tokio::test]
async fn migration_25_respells_the_clock_staffing_and_inbox_words_the_previous_release_stored() {
    let mut fixture = TestSchema::create("clock_staffing_spelling").await;
    apply_migrations_before_protocol_words(&mut fixture.database).await;
    apply_migration(&mut fixture.database, 23, REVIEW_OUTCOME_SPELLING_MIGRATION).await;
    apply_migration(&mut fixture.database, 24, HISTORY_EVENT_SPELLING_MIGRATION).await;
    let database = &fixture.database;

    // Rows as the previous release wrote them: one item no cover could take
    // and one staffed item, an item clock in every state, review tasks under
    // every assignment kind and staffing diagnostic, a review clock in every
    // state, the review history of those assignments, retained assignment
    // responses, and inbox cursors issued for every view.
    let blocked_item = Uuid::new_v4();
    let staffed_item = Uuid::new_v4();
    for (item, subject, diagnostic) in [
        (blocked_item, "subject-1", Some("no_cover_available")),
        (staffed_item, "subject-2", None),
    ] {
        database
            .execute(
                "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,
                     occurrence_kind,occurrence_key,binding,state,queue_id,revision,
                     first_observed_at,updated_at,staffing_diagnostic)
                 VALUES($1,'source','request',$2,'review','review-1',$3,'open','queue',1,
                     now(),now(),$4)",
                &[&item, &subject, &json!({"version": "1"}), &diagnostic],
            )
            .await
            .expect("store an item");
    }
    for (index, state) in [
        "running",
        "paused",
        "completed",
        "cancelled",
        "verification_pending",
        "source_facts_missing",
    ]
    .iter()
    .enumerate()
    {
        database
            .execute(
                "INSERT INTO casework_clock_occurrences(clock_occurrence_id,source_id,
                     subject_kind,subject_id,clock_id,scope,scope_key,item_id,state,policy_digest,
                     current_calculation_generation,source_binding_generation,source_revision,
                     source_etag,next_action_at,created_at,updated_at)
                 VALUES(gen_random_uuid(),'source','request','subject-1',$1,'subject','subject',
                     $2,$3,'sha256:clock',0,'1',1,'etag',now(),now(),now())",
                &[&format!("clock-{index}"), &blocked_item, state],
            )
            .await
            .expect("store an item clock");
    }

    let request = Uuid::new_v4();
    insert_review_request(database, request, false).await;
    let review_tasks = [
        ("claimed", Some("cover"), Some("absence_cover"), None),
        ("claimed", Some("delegate"), Some("delegation"), None),
        ("claimed", Some("nominee"), Some("nomination"), None),
        ("claimed", Some("claimant"), Some("claim"), None),
        ("open", None, None, Some("no_cover_available")),
        ("open", None, None, None),
    ];
    let mut task_ids = Vec::new();
    for (slot, (state, holder, kind, diagnostic)) in review_tasks.iter().enumerate() {
        let task = Uuid::new_v4();
        task_ids.push(task);
        database
            .execute(
                "INSERT INTO casework_review_tasks(task_id,request_id,stage_index,stage_id,slot,
                     queue_id,state,holder_issuer,holder_subject,assignment_kind,
                     staffing_diagnostic,revision,created_at,updated_at)
                 VALUES($1,$2,0,'stage',$3,'review',$4,$5,$6,$7,$8,1,now(),now())",
                &[
                    &task,
                    &request,
                    &i32::try_from(slot).expect("slot"),
                    state,
                    &holder.map(|_| "https://issuer.test"),
                    holder,
                    kind,
                    diagnostic,
                ],
            )
            .await
            .expect("store a review task");
    }
    for (index, state) in [
        "running",
        "paused",
        "completed",
        "cancelled",
        "source_facts_missing",
    ]
    .iter()
    .enumerate()
    {
        database
            .execute(
                "INSERT INTO casework_review_clock_occurrences(clock_occurrence_id,clock_id,scope,
                     correlation_key,subject_source,subject_type,subject_id,request_id,
                     policy_digest,policy,state,anchor_at,paused_at,completed_at,created_at,
                     updated_at)
                 VALUES(gen_random_uuid(),'clock','activity',$1,'source','record','subject',$2,
                     $3,'{}'::jsonb,$4,now(),
                     CASE WHEN $4='paused' THEN now() END,
                     CASE WHEN $4='completed' THEN now() END,now(),now())",
                &[
                    &format!("task:{index}"),
                    &request,
                    &format!("sha256:{}", "a".repeat(64)),
                    state,
                ],
            )
            .await
            .expect("store a review clock");
    }
    let review_history = [
        (
            "task-absence-reconciled",
            json!({"assignmentKind": "absence_cover", "staffingBlocked": false, "absenceCount": 1}),
        ),
        (
            "task-assigned",
            json!({"assignmentKind": "absence_cover", "targetRef": "cover", "reason": "absence_cover", "staffingBlocked": false}),
        ),
        (
            "task-delegated",
            json!({"assignmentKind": "delegation", "targetRef": "delegate", "reason": "no_cover_available", "staffingBlocked": true}),
        ),
        ("task-claimed", json!({"assignmentKind": "claim"})),
        ("note", json!({"note": "absence_cover, no_cover_available"})),
    ];
    for (index, (kind, detail)) in review_history.iter().enumerate() {
        let occurred_at = format!("2026-01-01T00:00:{index:02}Z");
        database
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,
                     detail,occurred_at)
                 VALUES(gen_random_uuid(),$1,$2,$3,NULL,$4,$5::text::timestamptz)",
                &[&request, &task_ids[0], kind, detail, &occurred_at],
            )
            .await
            .expect("store a review history entry");
    }

    for (operation, key, hash, response) in [
        (
            "item.assigned",
            "blocked",
            "hash-blocked",
            json!({"itemId": blocked_item, "assignment": {"absenceIds": [], "staffingDiagnostic": "no_cover_available"}, "revision": 2}),
        ),
        (
            "item.delegated",
            "staffed",
            "hash-staffed",
            json!({"itemId": staffed_item, "assignment": {"absenceIds": []}, "revision": 2}),
        ),
        (
            "draft.save",
            "draft",
            "hash-draft",
            json!({"body": {"assignment": {"staffingDiagnostic": "no_cover_available"}}, "revision": 1}),
        ),
    ] {
        database
            .execute(
                "INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,
                     idempotency_key,request_hash,response,created_at)
                 VALUES('https://issuer.test','supervisor','staff',$1,$2,$3,$4,$5,now())",
                &[
                    &operation,
                    &blocked_item.to_string(),
                    &key,
                    &hash,
                    &response,
                ],
            )
            .await
            .expect("store a retained response");
    }

    // An inbox cursor keeps the listing it continues as the compact text the
    // runtime compares. A queue or a subject may carry the same letters.
    let cursor_contexts = [
        r#"{"feed":"list","view":"my_teams","queue":null,"subject":null,"referenceHash":null,"sort":"due","ordering":"source-inbox-v2"}"#,
        r#"{"feed":"list","view":"team_holdings","queue":"review","subject":null,"referenceHash":null,"sort":"age","ordering":"source-inbox-v2"}"#,
        r#"{"feed":"list","view":"completed_by_me","queue":null,"subject":null,"referenceHash":null,"sort":"type","ordering":"source-inbox-v2"}"#,
        r#"{"feed":"list","view":"mine","queue":"my_teams","subject":null,"referenceHash":null,"sort":"due","ordering":"source-inbox-v2"}"#,
        r#"{"feed":"list","view":"overdue","queue":null,"subject":{"sourceId":"source","kind":"request","id":"\"view\":\"my_teams\""},"referenceHash":null,"sort":"due","ordering":"source-inbox-v2"}"#,
    ];
    for (index, context) in cursor_contexts.iter().enumerate() {
        let expires_at = format!("2026-01-01T00:00:{index:02}Z");
        database
            .execute(
                "INSERT INTO casework_cursors(cursor_id,issuer,subject,casework_profile_id,
                     source_profile_id,context,expires_at)
                 VALUES(gen_random_uuid(),'https://issuer.test','staff','staff','source',$1,
                     $2::text::timestamptz)",
                &[context, &expires_at],
            )
            .await
            .expect("store an inbox cursor");
    }

    let tables = [
        "casework_items",
        "casework_clock_occurrences",
        "casework_review_tasks",
        "casework_review_clock_occurrences",
        "casework_review_history",
        "casework_idempotency",
        "casework_cursors",
    ];
    let constrained = [
        "casework_items",
        "casework_clock_occurrences",
        "casework_review_tasks",
        "casework_review_clock_occurrences",
    ];
    let mut counts_before = Vec::new();
    for table in tables {
        counts_before.push(row_count(database, table).await);
    }
    let (constraints_before, _) = check_constraints(database, &constrained, "_").await;

    apply_migration(
        &mut fixture.database,
        25,
        CLOCK_STAFFING_INBOX_SPELLING_MIGRATION,
    )
    .await;
    let database = &fixture.database;

    let mut counts_after = Vec::new();
    for table in tables {
        counts_after.push(row_count(database, table).await);
    }
    assert_eq!(counts_before, counts_after, "the migration removes no row");

    assert_eq!(
        text_values(
            database,
            "SELECT coalesce(staffing_diagnostic,'none') FROM casework_items ORDER BY subject_id"
        )
        .await,
        ["no-cover-available", "none"]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT state FROM casework_clock_occurrences ORDER BY clock_id"
        )
        .await,
        [
            "running",
            "paused",
            "completed",
            "cancelled",
            "verification-pending",
            "source-facts-missing",
        ]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT coalesce(assignment_kind,'none') || ' ' || coalesce(staffing_diagnostic,'none')
             FROM casework_review_tasks ORDER BY slot"
        )
        .await,
        [
            "absence-cover none",
            "delegation none",
            "nomination none",
            "claim none",
            "none no-cover-available",
            "none none",
        ]
    );
    assert_eq!(
        text_values(
            database,
            "SELECT state FROM casework_review_clock_occurrences ORDER BY correlation_key"
        )
        .await,
        [
            "running",
            "paused",
            "completed",
            "cancelled",
            "source-facts-missing",
        ]
    );

    // The assignment kind is a closed word; a reason is the caller's text.
    assert_eq!(
        json_value(
            database,
            "SELECT jsonb_agg(detail ORDER BY occurred_at) FROM casework_review_history"
        )
        .await,
        json!([
            {"assignmentKind": "absence-cover", "staffingBlocked": false, "absenceCount": 1},
            {"assignmentKind": "absence-cover", "targetRef": "cover", "reason": "absence_cover", "staffingBlocked": false},
            {"assignmentKind": "delegation", "targetRef": "delegate", "reason": "no_cover_available", "staffingBlocked": true},
            {"assignmentKind": "claim"},
            {"note": "absence_cover, no_cover_available"},
        ])
    );

    // A retained item response is deserialized into the type that wrote it;
    // a draft body is the caller's and stays as it was sent.
    assert_eq!(
        json_value(
            database,
            "SELECT jsonb_object_agg(idempotency_key, response) FROM casework_idempotency"
        )
        .await,
        json!({
            "blocked": {"itemId": blocked_item, "assignment": {"absenceIds": [], "staffingDiagnostic": "no-cover-available"}, "revision": 2},
            "staffed": {"itemId": staffed_item, "assignment": {"absenceIds": []}, "revision": 2},
            "draft": {"body": {"assignment": {"staffingDiagnostic": "no_cover_available"}}, "revision": 1},
        })
    );
    assert_eq!(
        text_values(
            database,
            "SELECT request_hash FROM casework_idempotency ORDER BY request_hash"
        )
        .await,
        ["hash-blocked", "hash-draft", "hash-staffed"]
    );

    assert_eq!(
        text_values(
            database,
            "SELECT context FROM casework_cursors ORDER BY expires_at"
        )
        .await,
        [
            r#"{"feed":"list","view":"my-teams","queue":null,"subject":null,"referenceHash":null,"sort":"due","ordering":"source-inbox-v2"}"#,
            r#"{"feed":"list","view":"team-holdings","queue":"review","subject":null,"referenceHash":null,"sort":"age","ordering":"source-inbox-v2"}"#,
            r#"{"feed":"list","view":"completed-by-me","queue":null,"subject":null,"referenceHash":null,"sort":"type","ordering":"source-inbox-v2"}"#,
            r#"{"feed":"list","view":"mine","queue":"my_teams","subject":null,"referenceHash":null,"sort":"due","ordering":"source-inbox-v2"}"#,
            r#"{"feed":"list","view":"overdue","queue":null,"subject":{"sourceId":"source","kind":"request","id":"\"view\":\"my_teams\""},"referenceHash":null,"sort":"due","ordering":"source-inbox-v2"}"#,
        ],
        "a cursor continues the listing it was issued for; a queue and a subject keep their letters"
    );

    // Every constraint is still there, and none names a previous spelling.
    for word in [
        "verification_pending",
        "source_facts_missing",
        "no_cover_available",
        "absence_cover",
    ] {
        assert_eq!(
            check_constraints(database, &constrained, word).await,
            (constraints_before, 0),
            "no constraint names {word}"
        );
    }
    for statement in [
        format!(
            "UPDATE casework_items SET staffing_diagnostic='no_cover_available' WHERE item_id='{staffed_item}'"
        ),
        "UPDATE casework_clock_occurrences SET state='verification_pending'".to_owned(),
        "UPDATE casework_clock_occurrences SET state='source_facts_missing'".to_owned(),
        "UPDATE casework_review_tasks SET assignment_kind='absence_cover' WHERE slot=1".to_owned(),
        "UPDATE casework_review_tasks SET staffing_diagnostic='no_cover_available' WHERE slot=5"
            .to_owned(),
        "UPDATE casework_review_clock_occurrences SET state='source_facts_missing' WHERE state='running'"
            .to_owned(),
        // The shape constraints of the respelled columns still bind.
        "UPDATE casework_review_tasks SET assignment_kind=NULL WHERE slot=0".to_owned(),
        "UPDATE casework_review_clock_occurrences SET state='source-facts-missing' WHERE state='paused'"
            .to_owned(),
    ] {
        let error = database
            .batch_execute(&statement)
            .await
            .expect_err("the constraint refuses the statement");
        assert_sqlstate(&error, &SqlState::CHECK_VIOLATION, &statement);
    }

    // The indexes that serve the clock workers select on the stored words.
    assert_eq!(
        text_values(
            database,
            "SELECT indexname || ' ' || (position('verification-pending' in indexdef) > 0
                     OR position('source-facts-missing' in indexdef) > 0)::text
                 || ' ' || (position('verification_pending' in indexdef) > 0
                     OR position('source_facts_missing' in indexdef) > 0)::text
             FROM pg_indexes
             WHERE schemaname=current_schema()
               AND indexname IN ('casework_clock_occurrences_due_idx',
                   'casework_review_clock_missing_facts_idx')
             ORDER BY indexname"
        )
        .await,
        [
            "casework_clock_occurrences_due_idx true false",
            "casework_review_clock_missing_facts_idx true false",
        ]
    );

    fixture.cleanup().await;
}
