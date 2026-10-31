// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL proof for Adapter idempotency response custody and effect safety.
//!
//! Camel eagerly claims a key so an exchange already in progress is a
//! duplicate, and removes that key after a failed exchange when
//! `removeOnFailure` is true
//! (`camel-4.23.0:core/camel-core-processor/src/main/java/org/apache/camel/processor/idempotent/IdempotentConsumer.java`).
//! The pinned `IdempotentConsumerConcurrentTest`,
//! `IdempotentConsumerRemoveOnFailureTest`, and
//! `IdempotentConsumerFailedDuplicateTest` supply the applicable store cases:
//! an eager racing duplicate cannot own or remove the first claim, and failed
//! work is removable only under the configured semantics. `eager` and
//! `completionEager` route-scope behavior belongs to the later processor
//! integration, not this store slice.
//! Adapter keeps those semantics only before an upstream effect. Once a
//! non-safe send may happen, the durable claim is never released as fresh
//! work. Every test runs in its own schema inside the disposable database
//! named by `ADAPTER_TEST_DATABASE_URL`; absence is a failure, never a skip.
#![cfg(feature = "postgres-test")]

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter::idempotent::{
    self, Claim, ClaimRequest, IdempotencyError, StoredResponse, TerminalOutcome,
    VerifiedCallerIdentity, MAX_CALLER_IDENTITY_BYTES, MAX_CALLER_ISSUER_BYTES,
    MAX_STORED_RESPONSE_BYTES,
};
use tokio_postgres::{Client, Config as PgConfig, NoTls};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);
const V0100_SCHEMA: &str = include_str!("../src/idempotent/migrations/0100_idempotency_store.sql");
const V0200_SCHEMA: &str =
    include_str!("../src/idempotent/migrations/0200_logical_deployment_identity.sql");
const RESPONSE_REQUEST_ID: &str = "00000000000000000000000000000001";

#[derive(Clone)]
struct Isolated {
    pool: Pool,
}

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect the adapter idempotency test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the adapter idempotency test connection failed: {error}");
        }
    });
    client
}

async fn isolated() -> Isolated {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_idempotency_{nanos}_{serial}");
    let admin = connect(&base).await;
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated adapter idempotency schema");
    drop(admin);

    let separator = if base.contains('?') { '&' } else { '?' };
    let mut scoped = PgConfig::from_str(&format!(
        "{base}{separator}options=-csearch_path%3D{schema}"
    ))
    .expect("parse the scoped adapter idempotency URL");
    scoped.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let manager = Manager::from_config(
        scoped,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        },
    );
    let pool = Pool::builder(manager)
        .max_size(8)
        .build()
        .expect("build the adapter idempotency test pool");
    Isolated { pool }
}

impl Isolated {
    async fn client(&self) -> deadpool_postgres::Client {
        self.pool
            .get()
            .await
            .expect("a pooled adapter idempotency client")
    }

    async fn store(&self, retention: Duration) -> idempotent::PostgresIdempotencyStore {
        let client = self.client().await;
        idempotent::migrate(&client)
            .await
            .expect("apply the Adapter idempotency migration");
        idempotent::PostgresIdempotencyStore::new(self.pool.clone(), retention)
            .expect("construct the Adapter idempotency store")
    }
}

async fn install_v0100(client: &impl GenericClient) {
    client
        .batch_execute(
            "CREATE TABLE adapter_idempotency_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .expect("create the v0100 migration ledger");
    client
        .batch_execute(V0100_SCHEMA)
        .await
        .expect("apply the historical v0100 schema");
    client
        .execute(
            "INSERT INTO adapter_idempotency_schema_migrations(version, applied_at) \
             VALUES (100, now())",
            &[],
        )
        .await
        .expect("record the historical v0100 migration");
}

async fn install_v0200(client: &impl GenericClient) {
    install_v0100(client).await;
    client
        .batch_execute(V0200_SCHEMA)
        .await
        .expect("apply the historical v0200 semantic migration");
    client
        .execute(
            "INSERT INTO adapter_idempotency_schema_migrations(version, applied_at) \
             VALUES (200, now())",
            &[],
        )
        .await
        .expect("record the historical v0200 migration");
}

async fn migration_versions(client: &impl GenericClient) -> Vec<i64> {
    client
        .query(
            "SELECT version FROM adapter_idempotency_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("read idempotency migration versions")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn insert_claimed_row(client: &impl GenericClient) {
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries \
             (scope_digest, request_digest, state, claimed_at) \
             VALUES ($1, $2, 'claimed', now())",
            &[&[1_u8; 32].as_slice(), &[2_u8; 32].as_slice()],
        )
        .await
        .expect("insert a synthetic claimed idempotency row");
}

fn request<'a>(
    caller: &'a VerifiedCallerIdentity,
    operation: &'a str,
    key: &'a str,
    digest_byte: u8,
) -> ClaimRequest<'a> {
    request_in_deployment(caller, "deployment-a", operation, key, digest_byte)
}

fn request_in_deployment<'a>(
    caller: &'a VerifiedCallerIdentity,
    deployment: &'a str,
    operation: &'a str,
    key: &'a str,
    digest_byte: u8,
) -> ClaimRequest<'a> {
    ClaimRequest {
        caller,
        deployment,
        concrete_operation: operation,
        key,
        request_digest: [digest_byte; 32],
    }
}

fn caller(subject: &str) -> VerifiedCallerIdentity {
    VerifiedCallerIdentity::new("https://issuer.example", subject, "admitted-service")
        .expect("the synthetic caller identity is bounded")
}

fn response(status: u16, content_type: &[u8], body: &[u8]) -> StoredResponse {
    StoredResponse::new(
        status,
        content_type.to_vec(),
        body.to_vec(),
        RESPONSE_REQUEST_ID,
    )
    .expect("the synthetic facade response is bounded")
}

#[test]
fn caller_identity_and_response_custody_are_bounded_without_echoing_values() {
    assert!(matches!(
        VerifiedCallerIdentity::new("i".repeat(MAX_CALLER_ISSUER_BYTES + 1), "subject", "client"),
        Err(IdempotencyError::InvalidInput {
            field: "caller issuer"
        })
    ));
    assert!(matches!(
        VerifiedCallerIdentity::new(
            "https://issuer.example",
            "s".repeat(MAX_CALLER_IDENTITY_BYTES + 1),
            "client"
        ),
        Err(IdempotencyError::InvalidInput {
            field: "caller subject"
        })
    ));
    assert!(matches!(
        VerifiedCallerIdentity::new(
            "https://issuer.example",
            "subject",
            "c".repeat(MAX_CALLER_IDENTITY_BYTES + 1)
        ),
        Err(IdempotencyError::InvalidInput {
            field: "caller client id"
        })
    ));
    assert!(matches!(
        StoredResponse::new(
            200,
            b"application/json".to_vec(),
            vec![0; MAX_STORED_RESPONSE_BYTES + 1],
            RESPONSE_REQUEST_ID,
        ),
        Err(IdempotencyError::InvalidInput {
            field: "response body"
        })
    ));
    assert!(matches!(
        StoredResponse::new(
            200,
            b"application/json\r\nsecret: marker".to_vec(),
            vec![],
            RESPONSE_REQUEST_ID,
        ),
        Err(IdempotencyError::InvalidInput {
            field: "response content type"
        })
    ));
    assert!(matches!(
        StoredResponse::new(
            200,
            b"application/json".to_vec(),
            vec![],
            "CALLER-CONTROLLED"
        ),
        Err(IdempotencyError::InvalidInput {
            field: "response request id"
        })
    ));
}

#[tokio::test]
async fn migration_owns_a_separate_idempotency_ledger_and_is_idempotent() {
    let isolated = isolated().await;
    let client = isolated.client().await;

    idempotent::migrate(&client)
        .await
        .expect("the first migration run applies the idempotency baseline");
    idempotent::migrate(&client)
        .await
        .expect("a second migration run applies nothing twice");

    let relations = client
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = current_schema() ORDER BY table_name",
            &[],
        )
        .await
        .expect("list the migrated idempotency relations")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(
        relations,
        vec![
            "adapter_idempotency_entries".to_owned(),
            "adapter_idempotency_schema_migrations".to_owned(),
        ],
        "the idempotency migration neither creates nor borrows the journal ledger"
    );
    assert_eq!(migration_versions(&client).await, vec![100, 200, 300]);
}

#[tokio::test]
async fn logical_deployment_migration_refuses_legacy_rows_without_altering_them() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    install_v0100(&client).await;
    insert_claimed_row(&client).await;

    let error = idempotent::migrate(&client)
        .await
        .expect_err("opaque v0100 rows cannot be silently moved into the new namespace");
    assert!(matches!(
        error,
        IdempotencyError::LegacyDeploymentIdentityEntries
    ));
    assert_eq!(
        error.to_string(),
        "adapter.idempotency-legacy-deployment-entries: existing idempotency entries require operator reconciliation before the logical deployment identity migration"
    );
    assert_eq!(migration_versions(&client).await, vec![100]);
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM adapter_idempotency_entries", &[])
            .await
            .expect("count the preserved v0100 rows")
            .get::<_, i64>(0),
        1
    );
}

#[tokio::test]
async fn logical_deployment_migration_accepts_an_empty_v0100_ledger() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    install_v0100(&client).await;

    idempotent::migrate(&client)
        .await
        .expect("an empty v0100 ledger can adopt the logical deployment namespace");
    assert_eq!(migration_versions(&client).await, vec![100, 200, 300]);
}

#[tokio::test]
async fn response_identity_migration_refuses_v0200_cached_responses_without_altering_them() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    install_v0200(&client).await;
    for (byte, state) in [(3_u8, "completed"), (4_u8, "failed")] {
        client
            .execute(
                "INSERT INTO adapter_idempotency_entries \
                 (scope_digest, request_digest, state, claimed_at, terminal_at, expires_at, \
                  response_status, response_content_type, response_body) \
                 VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', \
                         409, convert_to('application/problem+json', 'UTF8'), $4)",
                &[
                    &[byte; 32].as_slice(),
                    &[byte + 10; 32].as_slice(),
                    &state,
                    &format!("legacy-response-{state}").into_bytes(),
                ],
            )
            .await
            .expect("insert a replayable v0200 response");
    }

    let error = idempotent::migrate(&client)
        .await
        .expect_err("v0200 response bytes without their original id cannot migrate");
    assert!(matches!(
        error,
        IdempotencyError::LegacyResponseRequestIdEntries
    ));
    assert_eq!(
        error.to_string(),
        "adapter.idempotency-legacy-response-id: existing replayable responses require operator reconciliation before the response identity migration"
    );
    assert_eq!(migration_versions(&client).await, vec![100, 200]);
    let preserved = client
        .query_one(
            "SELECT count(*), bool_and(response_body IS NOT NULL) \
             FROM adapter_idempotency_entries",
            &[],
        )
        .await
        .expect("inspect preserved v0200 response custody");
    assert_eq!(preserved.get::<_, i64>(0), 2);
    assert!(preserved.get::<_, bool>(1));
}

#[tokio::test]
async fn response_identity_migration_accepts_and_preserves_expired_v0200_tombstones() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    install_v0200(&client).await;
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries \
             (scope_digest, request_digest, state, claimed_at, terminal_at, expires_at) \
             VALUES ($1, $2, 'completed_expired', now(), now(), now() - interval '1 hour')",
            &[&[5_u8; 32].as_slice(), &[15_u8; 32].as_slice()],
        )
        .await
        .expect("insert an expired v0200 tombstone");

    idempotent::migrate(&client)
        .await
        .expect("an expired tombstone has no response identity to recover");
    assert_eq!(migration_versions(&client).await, vec![100, 200, 300]);
    let row = client
        .query_one(
            "SELECT state, response_request_id, response_body \
             FROM adapter_idempotency_entries",
            &[],
        )
        .await
        .expect("inspect the migrated tombstone");
    assert_eq!(row.get::<_, String>(0), "completed_expired");
    assert_eq!(row.get::<_, Option<String>>(1), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
}

#[tokio::test]
async fn current_rows_do_not_block_a_subsequent_startup() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    idempotent::migrate(&client)
        .await
        .expect("fresh storage reaches the current schema");
    insert_claimed_row(&client).await;

    idempotent::migrate(&client)
        .await
        .expect("the applied semantic migration does not inspect current rows again");
    assert_eq!(migration_versions(&client).await, vec![100, 200, 300]);
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM adapter_idempotency_entries", &[])
            .await
            .expect("count the current rows")
            .get::<_, i64>(0),
        1
    );
}

#[tokio::test]
async fn current_cached_response_ids_do_not_block_a_subsequent_startup() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("restart-caller");
    let now = SystemTime::now();
    let Claim::Execute(execution) = store
        .claim(
            request(&caller, "records-create.person", "restart-response-key", 8),
            now,
        )
        .await
        .expect("claim a current response")
    else {
        panic!("the current response claim must execute");
    };
    store
        .finish(
            execution,
            TerminalOutcome::Completed,
            response(201, b"application/json", b"{}"),
            now,
        )
        .await
        .expect("store a response with its generated id");

    let client = isolated.client().await;
    idempotent::migrate(&client)
        .await
        .expect("an already-applied response-id migration accepts current custody");
    assert_eq!(migration_versions(&client).await, vec![100, 200, 300]);
    assert_eq!(
        client
            .query_one(
                "SELECT response_request_id FROM adapter_idempotency_entries",
                &[],
            )
            .await
            .expect("read the current response id")
            .get::<_, String>(0),
        RESPONSE_REQUEST_ID
    );
}

#[tokio::test]
async fn concurrent_claims_admit_exactly_one_execution_and_conflict_the_other() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("concurrent-caller");
    let first_store = store.clone();
    let first_caller = caller.clone();
    let second_store = store.clone();
    let second_caller = caller.clone();
    let now = SystemTime::now();

    let (first, second) = tokio::join!(
        async move {
            first_store
                .claim(
                    request(&first_caller, "records-create.person", "race-key", 7),
                    now,
                )
                .await
                .expect("first concurrent claim")
        },
        async move {
            second_store
                .claim(
                    request(&second_caller, "records-create.person", "race-key", 7),
                    now,
                )
                .await
                .expect("second concurrent claim")
        }
    );

    assert!(
        matches!(
            (&first, &second),
            (Claim::Execute(_), Claim::InFlight) | (Claim::InFlight, Claim::Execute(_))
        ),
        "one racing request executes and the other receives the explicit in-flight conflict"
    );
}

#[tokio::test]
async fn replay_preserves_exact_bytes_status_and_content_type_and_scope_is_namespaced() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let first_caller = caller("caller-a");
    let second_caller = caller("caller-b");
    let now = SystemTime::now();
    let exact = response(
        201,
        b"application/vnd.registry+json; profile=exact",
        b"{\"z\":1, \"a\":2}\n",
    );

    let Claim::Execute(mut execution) = store
        .claim(
            request(
                &first_caller,
                "records-create.person",
                "exact-replay-key",
                11,
            ),
            now,
        )
        .await
        .expect("claim exact replay key")
    else {
        panic!("the first exact replay claim must execute");
    };
    store
        .mark_effect_attempted(&mut execution, now)
        .await
        .expect("durably mark the non-safe effect before its send");
    store
        .finish(execution, TerminalOutcome::Completed, exact.clone(), now)
        .await
        .expect("record the exact successful facade response");

    match store
        .claim(
            request(
                &first_caller,
                "records-create.person",
                "exact-replay-key",
                11,
            ),
            now,
        )
        .await
        .expect("claim the completed exact replay key")
    {
        Claim::Replay { outcome, response } => {
            assert_eq!(outcome, TerminalOutcome::Completed);
            assert_eq!(response, exact, "replay is byte-for-byte exact");
            assert_eq!(response.request_id(), RESPONSE_REQUEST_ID);
        }
        other => panic!("the completed claim must replay, got {other:?}"),
    }

    assert!(matches!(
        store
            .claim(
                request(
                    &first_caller,
                    "records-update.person",
                    "exact-replay-key",
                    11,
                ),
                now,
            )
            .await
            .expect("the same key in another concrete operation"),
        Claim::Execute(_)
    ));
    let other_client = VerifiedCallerIdentity::new(
        "https://issuer.example",
        "caller-a",
        "other-admitted-service",
    )
    .expect("the second admitted client is bounded");
    assert!(matches!(
        store
            .claim(
                request(
                    &other_client,
                    "records-create.person",
                    "exact-replay-key",
                    11,
                ),
                now,
            )
            .await
            .expect("the same key for another verified acting client"),
        Claim::Execute(_)
    ));
    assert!(matches!(
        store
            .claim(
                request(
                    &second_caller,
                    "records-create.person",
                    "exact-replay-key",
                    11,
                ),
                now,
            )
            .await
            .expect("the same key for another verified caller"),
        Claim::Execute(_)
    ));
    assert!(matches!(
        store
            .claim(
                request_in_deployment(
                    &first_caller,
                    "deployment-b",
                    "records-create.person",
                    "exact-replay-key",
                    11,
                ),
                now,
            )
            .await
            .expect("the same namespace in another deployment"),
        Claim::Execute(_)
    ));
}

#[tokio::test]
async fn same_namespaced_key_with_a_changed_request_digest_is_a_mismatch() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("digest-caller");
    let now = SystemTime::now();

    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "digest-key", 21),
                now,
            )
            .await
            .expect("claim the original request digest"),
        Claim::Execute(_)
    ));
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "digest-key", 22),
                now,
            )
            .await
            .expect("claim a changed request digest"),
        Claim::Mismatch
    ));
}

#[tokio::test]
async fn remove_on_failure_can_release_only_before_any_effect() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("before-effect-caller");
    let now = SystemTime::now();

    let Claim::Execute(execution) = store
        .claim(
            request(&caller, "records-create.person", "before-effect-key", 31),
            now,
        )
        .await
        .expect("claim before-effect failure")
    else {
        panic!("the first before-effect claim must execute");
    };
    store
        .release_before_effect(execution)
        .await
        .expect("removeOnFailure releases a claim before any effect");
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "before-effect-key", 31,),
                now,
            )
            .await
            .expect("reclaim after a before-effect release"),
        Claim::Execute(_)
    ));

    let retained_problem = response(
        422,
        b"application/problem+json",
        br#"{"code":"adapter.validation"}"#,
    );
    let Claim::Execute(retained) = store
        .claim(
            request(
                &caller,
                "records-create.person",
                "retained-before-effect-key",
                32,
            ),
            now,
        )
        .await
        .expect("claim a before-effect failure retained by removeOnFailure false")
    else {
        panic!("the retained before-effect claim must execute first");
    };
    store
        .finish(
            retained,
            TerminalOutcome::Failed,
            retained_problem.clone(),
            now,
        )
        .await
        .expect("retain a before-effect problem when removeOnFailure is false");
    assert!(matches!(
        store
            .claim(
                request(
                    &caller,
                    "records-create.person",
                    "retained-before-effect-key",
                    32,
                ),
                now,
            )
            .await
            .expect("retry the retained before-effect failure"),
        Claim::Replay {
            outcome: TerminalOutcome::Failed,
            response
        } if response == retained_problem
    ));
}

#[tokio::test]
async fn failed_effect_replays_its_recorded_problem_and_never_executes_again() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("failed-effect-caller");
    let now = SystemTime::now();
    let problem = response(
        502,
        b"application/problem+json",
        br#"{"code":"adapter.upstream-unavailable"}"#,
    );

    let Claim::Execute(mut execution) = store
        .claim(
            request(&caller, "records-update.person", "failed-effect-key", 41),
            now,
        )
        .await
        .expect("claim the failed effect")
    else {
        panic!("the first failed-effect claim must execute");
    };
    store
        .mark_effect_attempted(&mut execution, now)
        .await
        .expect("mark the failed effect before the send");
    store
        .finish(execution, TerminalOutcome::Failed, problem.clone(), now)
        .await
        .expect("record the caller-visible failed problem");

    match store
        .claim(
            request(&caller, "records-update.person", "failed-effect-key", 41),
            now,
        )
        .await
        .expect("retry the failed effect")
    {
        Claim::Replay { outcome, response } => {
            assert_eq!(outcome, TerminalOutcome::Failed);
            assert_eq!(response, problem);
        }
        other => panic!("the failed effect must replay its problem, got {other:?}"),
    }
}

#[tokio::test]
async fn cancellation_or_crash_stays_fail_closed_before_and_after_effect_marking() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("cancelled-caller");
    let now = SystemTime::now();

    {
        let Claim::Execute(_cancelled_execution) = store
            .claim(
                request(&caller, "records-create.person", "cancelled-before-key", 51),
                now,
            )
            .await
            .expect("claim work cancelled before an effect")
        else {
            panic!("the cancelled pre-effect claim must execute first");
        };
    }
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "cancelled-before-key", 51,),
                now,
            )
            .await
            .expect("retry the cancelled pre-effect claim"),
        Claim::InFlight
    ));

    let Claim::Execute(mut after_effect) = store
        .claim(
            request(&caller, "records-create.person", "cancelled-after-key", 52),
            now,
        )
        .await
        .expect("claim work cancelled after an effect")
    else {
        panic!("the cancelled post-effect claim must execute first");
    };
    store
        .mark_effect_attempted(&mut after_effect, now)
        .await
        .expect("persist the effect-unknown boundary before cancellation");
    assert!(matches!(
        store.release_before_effect(after_effect).await,
        Err(IdempotencyError::StateConflict)
    ));
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "cancelled-after-key", 52,),
                now,
            )
            .await
            .expect("retry the cancelled post-effect claim"),
        Claim::EffectUnknown
    ));

    let far_future = now
        .checked_add(Duration::from_secs(366 * 24 * 60 * 60))
        .expect("the far-future sweep instant is representable");
    assert_eq!(
        store
            .sweep_expired(far_future, 100)
            .await
            .expect("sweep must ignore nonterminal claims"),
        0,
        "body retention never sweeps in-flight or effect-unknown entries"
    );
}

#[tokio::test]
async fn sweep_erases_expired_response_custody_without_reopening_the_effect() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(1)).await;
    let caller = caller("expiry-caller");
    let recorded_at = SystemTime::now();

    let Claim::Execute(mut execution) = store
        .claim(
            request(&caller, "records-create.person", "expired-response-key", 61),
            recorded_at,
        )
        .await
        .expect("claim the response that will expire")
    else {
        panic!("the expiring response claim must execute first");
    };
    store
        .mark_effect_attempted(&mut execution, recorded_at)
        .await
        .expect("mark the expiring response's effect");
    store
        .finish(
            execution,
            TerminalOutcome::Completed,
            response(201, b"application/json", b"{\"sensitive\":\"held\"}"),
            recorded_at,
        )
        .await
        .expect("record the response under bounded custody");

    let after_retention = recorded_at
        .checked_add(Duration::from_secs(2))
        .expect("the expiry instant is representable");
    assert_eq!(
        store
            .sweep_expired(after_retention, 100)
            .await
            .expect("erase expired response custody"),
        1
    );
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "expired-response-key", 61,),
                after_retention,
            )
            .await
            .expect("retry an effect whose response expired"),
        Claim::ResponseExpired {
            outcome: TerminalOutcome::Completed
        }
    ));

    let client = isolated.client().await;
    let row = client
        .query_one(
            "SELECT response_status, response_content_type, response_body, \
                    response_request_id, state \
             FROM adapter_idempotency_entries",
            &[],
        )
        .await
        .expect("inspect the expired custody tombstone");
    assert_eq!(row.get::<_, Option<i16>>(0), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(1), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
    assert_eq!(row.get::<_, Option<String>>(3), None);
    assert_eq!(row.get::<_, String>(4), "completed_expired");
}
