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
//! work is removable only under the configured semantics. Direct `eager` and
//! `completionEager` route-scope behavior lives in
//! `camel_idempotent_consumer`; this suite proves that the facade's durable
//! reservation remains independent of those EIP timings.
//! Adapter keeps those semantics only before an upstream effect. Once a
//! non-safe send may happen, the durable claim is never released as fresh
//! work. Every test runs in its own schema inside the disposable database
//! named by `ADAPTER_TEST_DATABASE_URL`; absence is a failure, never a skip.
#![cfg(feature = "postgres-test")]

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter::custody::{ResumeWriteContext, WriteExecutionContext, WriteResolution};
use registry_adapter::engine::exchange::{WriteClaim, WriteCustody};
use registry_adapter::engine::ResumeValue;
use registry_adapter::idempotent::{
    self, AsyncEffectAttempt, Claim, ClaimRequest, IdempotencyError, RecoveryLease,
    ResumeClaimContext, StatusLookup, StatusLookupRequest, StoredResponse, TerminalOutcome,
    VerifiedCallerIdentity, MAX_CALLER_IDENTITY_BYTES, MAX_CALLER_ISSUER_BYTES, MAX_ETAG_BYTES,
    MAX_LOCATION_BYTES, MAX_STORED_RESPONSE_BYTES,
};
use tokio::sync::Barrier;
use tokio_postgres::{Client, Config as PgConfig, NoTls};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);
const V0100_SCHEMA: &str = include_str!("../src/idempotent/migrations/0100_idempotency_store.sql");
const V0200_SCHEMA: &str =
    include_str!("../src/idempotent/migrations/0200_logical_deployment_identity.sql");
const V0300_SCHEMA: &str =
    include_str!("../src/idempotent/migrations/0300_response_request_id.sql");
const V0400_SCHEMA: &str = include_str!("../src/idempotent/migrations/0400_async_completion.sql");
const V0500_SCHEMA: &str =
    include_str!("../src/idempotent/migrations/0500_linear_write_resume.sql");
const V0600_SCHEMA: &str =
    include_str!("../src/idempotent/migrations/0600_source_native_single_resume.sql");
const RESPONSE_REQUEST_ID: &str = "00000000000000000000000000000001";
const OTHER_RESPONSE_REQUEST_ID: &str = "00000000000000000000000000000002";
const THIRD_RESPONSE_REQUEST_ID: &str = "00000000000000000000000000000004";
const RECOVERY_ID: &str = "0000000000000000000000000000000000000000000000000000000000000003";

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
        let mut client = self.client().await;
        idempotent::migrate(&mut client)
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

async fn install_v0300(client: &impl GenericClient) {
    install_v0200(client).await;
    client
        .batch_execute(V0300_SCHEMA)
        .await
        .expect("apply the historical v0300 response-id migration");
    client
        .execute(
            "INSERT INTO adapter_idempotency_schema_migrations(version, applied_at) \
             VALUES (300, now())",
            &[],
        )
        .await
        .expect("record the historical v0300 migration");
}

async fn install_v0500(client: &impl GenericClient) {
    install_v0300(client).await;
    for (version, schema) in [(400_i64, V0400_SCHEMA), (500_i64, V0500_SCHEMA)] {
        client
            .batch_execute(schema)
            .await
            .expect("apply the historical idempotency migration");
        client
            .execute(
                "INSERT INTO adapter_idempotency_schema_migrations(version, applied_at) \
                 VALUES ($1, now())",
                &[&version],
            )
            .await
            .expect("record the historical idempotency migration");
    }
}

async fn install_v0600(client: &impl GenericClient) {
    install_v0500(client).await;
    client
        .batch_execute(V0600_SCHEMA)
        .await
        .expect("apply the historical v0600 single-resume migration");
    client
        .execute(
            "INSERT INTO adapter_idempotency_schema_migrations(version, applied_at) \
             VALUES (600, now())",
            &[],
        )
        .await
        .expect("record the historical v0600 migration");
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

fn async_attempt<'a>(
    request_id: &'a str,
    recovery_id: Option<&'a str>,
    artifact_byte: u8,
    effect_deadline: SystemTime,
) -> AsyncEffectAttempt<'a> {
    AsyncEffectAttempt {
        response_request_id: request_id,
        artifact_digest: [artifact_byte; 32],
        binding_id: "person-create-binding",
        profile_operation: "records-create",
        concrete_operation: "records-create.person",
        record_type: "person",
        recovery_id,
        effect_deadline,
    }
}

fn status_lookup<'a>(
    caller: &'a VerifiedCallerIdentity,
    status_id: &'a str,
    artifact_byte: u8,
) -> StatusLookupRequest<'a> {
    StatusLookupRequest {
        caller,
        deployment: "deployment-a",
        artifact_digest: [artifact_byte; 32],
        status_id,
    }
}

fn resume_context(artifact_byte: u8, deadline: SystemTime) -> ResumeClaimContext {
    ResumeClaimContext {
        artifact_digest: [artifact_byte; 32],
        effect_deadline: deadline,
        step_count: 2,
    }
}

fn single_resume_context(artifact_byte: u8, deadline: SystemTime) -> ResumeClaimContext {
    ResumeClaimContext {
        artifact_digest: [artifact_byte; 32],
        effect_deadline: deadline,
        step_count: 1,
    }
}

fn single_resume_write_context(artifact_byte: u8, deadline: SystemTime) -> ResumeWriteContext {
    ResumeWriteContext {
        artifact_digest: [artifact_byte; 32],
        effect_deadline: deadline,
        step_count: 1,
    }
}

#[tokio::test]
async fn write_context_without_a_claim_is_released_for_original_failure_rendering() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let context = WriteExecutionContext::new(
        store,
        caller("unclaimed-write-failure"),
        "deployment-a".to_owned(),
        "records-create.person".to_owned(),
        [63; 32],
    );

    assert_eq!(context.resolution().await, WriteResolution::Released);
}

#[tokio::test]
async fn failed_single_resume_before_any_effect_releases_its_key_and_artifact_fence() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-before-effect-release");
    let start = SystemTime::now();
    let context = WriteExecutionContext::new_resume(
        store.clone(),
        caller.clone(),
        "deployment-a".to_owned(),
        "records-create.person".to_owned(),
        [67; 32],
        single_resume_write_context(37, start + Duration::from_secs(10)),
    );

    assert_eq!(
        context
            .claim("single-before-effect-key", true)
            .await
            .expect("claim the source-native single write"),
        WriteClaim::Execute
    );
    context
        .complete(false, true)
        .await
        .expect("removeOnFailure releases a proven no-effect single write");
    assert_eq!(context.resolution().await, WriteResolution::Released);

    store
        .ensure_async_artifact_compatible("deployment-a", [38; 32], start + Duration::from_secs(1))
        .await
        .expect("the released resume no longer blocks artifact activation");
    assert!(matches!(
        store
            .claim_resume(
                request(
                    &caller,
                    "records-create.person",
                    "single-before-effect-key",
                    67,
                ),
                single_resume_context(38, start + Duration::from_secs(11)),
                start + Duration::from_secs(1),
            )
            .await
            .expect("claim the released key under the activated artifact"),
        Claim::Execute(_)
    ));
}

#[tokio::test]
async fn reacquired_single_resume_cannot_release_a_prior_unknown_source_effect() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-prior-effect");
    let start = UNIX_EPOCH + Duration::from_secs(3_860_000);
    let mut first = match store
        .claim_resume(
            request(
                &caller,
                "records-create.person",
                "single-prior-effect-key",
                66,
            ),
            single_resume_context(36, start + Duration::from_secs(10)),
            start,
        )
        .await
        .expect("claim the first single write attempt")
    {
        Claim::Execute(execution) => execution,
        other => panic!("the first single write executes: {other:?}"),
    };
    store
        .mark_resume_step_attempted(&mut first, 0, start + Duration::from_secs(1))
        .await
        .expect("durably mark the possibly sent source effect");
    store
        .release_resume_lease(&first, start + Duration::from_secs(2))
        .await
        .expect("release only the failed attempt's lease");
    let resumed = match store
        .claim_resume(
            request(
                &caller,
                "records-create.person",
                "single-prior-effect-key",
                66,
            ),
            single_resume_context(36, start + Duration::from_secs(12)),
            start + Duration::from_secs(2),
        )
        .await
        .expect("reacquire the unfinished source-native step")
    {
        Claim::Resume {
            execution,
            next_step: 0,
            bindings,
        } if bindings.is_empty() => execution,
        other => panic!("the unknown source effect remains resumable: {other:?}"),
    };

    assert!(!store
        .try_release_resume_before_any_effect(&resumed, start + Duration::from_secs(3))
        .await
        .expect("the proof mismatch is a retained resume, not a store failure"));
    store
        .release_resume_lease(&resumed, start + Duration::from_secs(3))
        .await
        .expect("the retained resume releases only its current lease");
    assert!(matches!(
        store
            .claim_resume(
                request(
                    &caller,
                    "records-create.person",
                    "single-prior-effect-key",
                    66
                ),
                single_resume_context(36, start + Duration::from_secs(13)),
                start + Duration::from_secs(3),
            )
            .await
            .expect("the prior possible effect remains resumable"),
        Claim::Resume { next_step: 0, .. }
    ));
}

#[tokio::test]
async fn stale_single_resume_lease_cannot_delete_the_current_claim() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-stale-lease");
    let start = UNIX_EPOCH + Duration::from_secs(3_870_000);
    let old = match store
        .claim_resume(
            request(
                &caller,
                "records-create.person",
                "single-stale-lease-key",
                65,
            ),
            single_resume_context(35, start + Duration::from_secs(10)),
            start,
        )
        .await
        .expect("claim the old lease")
    {
        Claim::Execute(execution) => execution,
        other => panic!("the old lease executes first: {other:?}"),
    };
    store
        .release_resume_lease(&old, start + Duration::from_secs(1))
        .await
        .expect("release the old lease");
    let current = match store
        .claim_resume(
            request(
                &caller,
                "records-create.person",
                "single-stale-lease-key",
                65,
            ),
            single_resume_context(35, start + Duration::from_secs(11)),
            start + Duration::from_secs(1),
        )
        .await
        .expect("acquire the current lease")
    {
        Claim::Resume { execution, .. } => execution,
        other => panic!("the successor owns the current lease: {other:?}"),
    };

    assert!(!store
        .try_release_resume_before_any_effect(&old, start + Duration::from_secs(2))
        .await
        .expect("a stale lease is a proof mismatch"));
    assert!(store
        .try_release_resume_before_any_effect(&current, start + Duration::from_secs(2))
        .await
        .expect("the exact current lease can release the no-effect claim"));
}

#[tokio::test]
async fn remove_on_failure_false_keeps_a_failed_single_resume_member() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-retained-member");
    let start = SystemTime::now();
    let context = WriteExecutionContext::new_resume(
        store,
        caller,
        "deployment-a".to_owned(),
        "records-create.person".to_owned(),
        [64; 32],
        single_resume_write_context(34, start + Duration::from_secs(10)),
    );

    assert_eq!(
        context
            .claim("single-retained-member-key", true)
            .await
            .expect("claim the retained single write"),
        WriteClaim::Execute
    );
    context
        .complete(false, false)
        .await
        .expect("the failed attempt releases its lease but retains membership");
    assert_eq!(context.resolution().await, WriteResolution::ResumePending);
}

#[tokio::test]
async fn single_effect_resume_reacquires_exactly_one_post_and_cleans_up_on_terminal_replay() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-resume-operator");
    let start = UNIX_EPOCH + Duration::from_secs(3_900_000);
    let mut first = match store
        .claim_resume(
            request(&caller, "records-create.person", "single-resume-key", 70),
            single_resume_context(40, start + Duration::from_secs(10)),
            start,
        )
        .await
        .expect("claim the source-native single write")
    {
        Claim::Execute(execution) => execution,
        other => panic!("a fresh single write executes: {other:?}"),
    };
    store
        .mark_resume_step_attempted(&mut first, 0, start + Duration::from_secs(1))
        .await
        .expect("premark the only physical POST");
    store
        .release_resume_lease(&first, start + Duration::from_secs(2))
        .await
        .expect("a cleanly returned attempt releases its finite lease");

    let mut resumed = match store
        .claim_resume(
            request(&caller, "records-create.person", "single-resume-key", 70),
            single_resume_context(40, start + Duration::from_secs(12)),
            start + Duration::from_secs(2),
        )
        .await
        .expect("reacquire the only unfinished step")
    {
        Claim::Resume {
            execution,
            next_step: 0,
            bindings,
        } if bindings.is_empty() => execution,
        other => panic!("the only POST resumes without payload custody: {other:?}"),
    };
    store
        .mark_resume_step_attempted(&mut resumed, 0, start + Duration::from_secs(3))
        .await
        .expect("premark the replayed physical POST");
    store
        .finish(
            resumed,
            TerminalOutcome::Completed,
            response(201, b"application/json", br#"{"batch":"accepted"}"#),
            start + Duration::from_secs(4),
        )
        .await
        .expect("commit terminal response custody and resume cleanup");

    assert!(matches!(
        store
            .claim_resume(
                request(&caller, "records-create.person", "single-resume-key", 70),
                single_resume_context(40, start + Duration::from_secs(15)),
                start + Duration::from_secs(5),
            )
            .await
            .expect("resolve the exact-key retry"),
        Claim::Replay {
            outcome: TerminalOutcome::Completed,
            ..
        }
    ));
    assert!(matches!(
        store
            .claim_resume(
                request(&caller, "records-create.person", "single-resume-key", 99),
                single_resume_context(40, start + Duration::from_secs(15)),
                start + Duration::from_secs(5),
            )
            .await
            .expect("resolve a different request under the spent key"),
        Claim::Mismatch
    ));
    let client = isolated.client().await;
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM adapter_idempotency_resumes", &[])
            .await
            .expect("inspect terminal resume cleanup")
            .get::<_, i64>(0),
        0
    );
}

#[tokio::test]
async fn single_effect_resume_expiry_erases_recovery_but_never_reopens_an_attempted_post() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-resume-expiry");
    let start = UNIX_EPOCH + Duration::from_secs(3_950_000);
    let mut execution = match store
        .claim_resume(
            request(&caller, "records-create.person", "single-expiry-key", 69),
            single_resume_context(39, start + Duration::from_secs(10)),
            start,
        )
        .await
        .expect("claim the source-native single write")
    {
        Claim::Execute(execution) => execution,
        other => panic!("a fresh single write executes: {other:?}"),
    };
    store
        .mark_resume_step_attempted(&mut execution, 0, start + Duration::from_secs(1))
        .await
        .expect("premark the only physical POST");
    let after_expiry = start + Duration::from_secs(61);
    store
        .sweep_expired(after_expiry, 100)
        .await
        .expect("erase expired single-step recovery authority");
    assert!(matches!(
        store
            .claim_resume(
                request(&caller, "records-create.person", "single-expiry-key", 69),
                single_resume_context(39, after_expiry + Duration::from_secs(10)),
                after_expiry,
            )
            .await
            .expect("resolve the spent key after recovery expiry"),
        Claim::EffectUnknown { .. }
    ));
}

#[tokio::test]
async fn source_native_single_resume_refuses_zero_steps() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("single-resume-zero");
    let start = UNIX_EPOCH + Duration::from_secs(3_980_000);
    assert!(matches!(
        store
            .claim_resume(
                request(&caller, "records-create.person", "zero-step-key", 68),
                ResumeClaimContext {
                    artifact_digest: [38; 32],
                    effect_deadline: start + Duration::from_secs(10),
                    step_count: 0,
                },
                start,
            )
            .await,
        Err(IdempotencyError::InvalidInput {
            field: "resume step count"
        })
    ));
}

#[tokio::test]
async fn v0600_additively_admits_one_step_without_rewriting_v0500_rows() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    install_v0500(&client).await;
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries \
             (scope_digest, request_digest, state, claimed_at) \
             VALUES ($1, $2, 'claimed', now())",
            &[&[11_u8; 32].as_slice(), &[12_u8; 32].as_slice()],
        )
        .await
        .expect("insert a historical v0500 claim");
    client
        .execute(
            "INSERT INTO adapter_idempotency_resumes \
             (scope_digest, request_digest, deployment_digest, artifact_digest, \
              next_step, step_count, expires_at, lease_id, lease_until) \
             VALUES ($1, $2, $3, $4, 0, 2, now() + interval '1 hour', $5, \
                     now() + interval '1 minute')",
            &[
                &[11_u8; 32].as_slice(),
                &[12_u8; 32].as_slice(),
                &[13_u8; 32].as_slice(),
                &[14_u8; 32].as_slice(),
                &[15_u8; 16].as_slice(),
            ],
        )
        .await
        .expect("insert one historical two-step resume");

    idempotent::migrate(&mut client)
        .await
        .expect("upgrade v0500 to the additive single-step constraint");
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
    assert_eq!(
        client
            .query_one(
                "SELECT step_count FROM adapter_idempotency_resumes WHERE scope_digest = $1",
                &[&[11_u8; 32].as_slice()],
            )
            .await
            .expect("read the preserved v0500 resume")
            .get::<_, i32>(0),
        2
    );
}

#[tokio::test]
async fn v0700_adds_optional_semantic_headers_without_rewriting_v0600_custody() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    install_v0600(&client).await;
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries \
             (scope_digest, request_digest, state, claimed_at, terminal_at, expires_at, \
              response_status, response_content_type, response_body, response_request_id) \
             VALUES ($1, $2, 'completed', now(), now(), now() + interval '1 hour', \
                     201, $3, $4, $5)",
            &[
                &[21_u8; 32].as_slice(),
                &[22_u8; 32].as_slice(),
                &b"application/json".as_slice(),
                &br#"{"created":true}"#.as_slice(),
                &RESPONSE_REQUEST_ID,
            ],
        )
        .await
        .expect("insert v0600 response custody");
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries \
             (scope_digest, request_digest, state, claimed_at, terminal_at, expires_at, \
              response_status, response_content_type, response_body, response_request_id) \
             VALUES ($1, $2, 'completed', now(), now(), now() + interval '1 hour', \
                     204, $3, $4, $5)",
            &[
                &[23_u8; 32].as_slice(),
                &[24_u8; 32].as_slice(),
                &b"application/json".as_slice(),
                &br#"{"legacy":true}"#.as_slice(),
                &OTHER_RESPONSE_REQUEST_ID,
            ],
        )
        .await
        .expect("insert historically valid v0600 generic 204 custody");

    idempotent::migrate(&mut client)
        .await
        .expect("upgrade v0600 response custody to semantic headers");
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
    let row = client
        .query_one(
            "SELECT response_status, response_content_type, response_location, \
                    response_etag, response_body \
             FROM adapter_idempotency_entries WHERE scope_digest = $1",
            &[&[21_u8; 32].as_slice()],
        )
        .await
        .expect("inspect preserved v0600 response custody");
    assert_eq!(row.get::<_, Option<i16>>(0), Some(201));
    assert_eq!(
        row.get::<_, Option<Vec<u8>>>(1).as_deref(),
        Some(&b"application/json"[..])
    );
    assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(3), None);
    assert_eq!(
        row.get::<_, Option<Vec<u8>>>(4).as_deref(),
        Some(&br#"{"created":true}"#[..])
    );
    let legacy = client
        .query_one(
            "SELECT response_status, response_content_type, response_location, \
                    response_etag, response_body \
             FROM adapter_idempotency_entries WHERE scope_digest = $1",
            &[&[23_u8; 32].as_slice()],
        )
        .await
        .expect("inspect preserved generic v0600 204 custody");
    assert_eq!(legacy.get::<_, Option<i16>>(0), Some(204));
    assert_eq!(
        legacy.get::<_, Option<Vec<u8>>>(1).as_deref(),
        Some(&b"application/json"[..])
    );
    assert_eq!(legacy.get::<_, Option<Vec<u8>>>(2), None);
    assert_eq!(legacy.get::<_, Option<Vec<u8>>>(3), None);
    assert_eq!(
        legacy.get::<_, Option<Vec<u8>>>(4).as_deref(),
        Some(&br#"{"legacy":true}"#[..])
    );
}

#[tokio::test]
async fn linear_resume_checkpoints_only_declared_ids_and_reacquires_the_unfinished_step() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("resume-operator");
    let start = UNIX_EPOCH + Duration::from_secs(4_000_000);
    let mut execution = match store
        .claim_resume(
            request(&caller, "records-create.person", "resume-key", 71),
            resume_context(41, start + Duration::from_secs(10)),
            start,
        )
        .await
        .expect("claim the linear write")
    {
        Claim::Execute(execution) => execution,
        other => panic!("a fresh write executes: {other:?}"),
    };
    store
        .mark_resume_step_attempted(&mut execution, 0, start + Duration::from_secs(1))
        .await
        .expect("premark step zero");
    store
        .checkpoint_resume_step(
            &mut execution,
            0,
            &[ResumeValue::new(
                "record_id".to_string(),
                "source-17".to_string(),
            )],
            start + Duration::from_secs(2),
        )
        .await
        .expect("checkpoint the source identifier only");

    assert!(matches!(
        store
            .claim_resume(
                request(&caller, "records-create.person", "resume-key", 71),
                resume_context(41, start + Duration::from_secs(12)),
                start + Duration::from_secs(3),
            )
            .await
            .expect("a racing retry resolves"),
        Claim::InFlight
    ));
    assert!(matches!(
        store
            .ensure_async_artifact_compatible(
                "deployment-a",
                [42; 32],
                start + Duration::from_secs(3),
            )
            .await,
        Err(IdempotencyError::AsyncArtifactActivationRefused { unfinished: 1, .. })
    ));

    let (mut resumed, next_step, bindings) = match store
        .claim_resume(
            request(&caller, "records-create.person", "resume-key", 71),
            resume_context(41, start + Duration::from_secs(21)),
            start + Duration::from_secs(11),
        )
        .await
        .expect("reacquire after the crashed lease")
    {
        Claim::Resume {
            execution,
            next_step,
            bindings,
        } => (execution, next_step, bindings),
        other => panic!("the unfinished step resumes: {other:?}"),
    };
    assert_eq!(next_step, 1);
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings.get("record_id").map(String::as_str),
        Some("source-17")
    );
    let client = isolated.client().await;
    let stored_columns: i64 = client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_name IN ('adapter_idempotency_resumes', \
                                  'adapter_idempotency_resume_bindings') \
               AND column_name IN ('body', 'payload', 'request_body', 'response_body')",
            &[],
        )
        .await
        .expect("inspect the resume tables")
        .get(0);
    assert_eq!(stored_columns, 0, "resume custody has no payload column");

    store
        .mark_resume_step_attempted(&mut resumed, 1, start + Duration::from_secs(12))
        .await
        .expect("premark the final step");
    store
        .finish(
            resumed,
            TerminalOutcome::Completed,
            response(201, b"application/json", br#"{"record":"done"}"#),
            start + Duration::from_secs(13),
        )
        .await
        .expect("commit the terminal response");
    assert!(matches!(
        store
            .claim_resume(
                request(&caller, "records-create.person", "resume-key", 71),
                resume_context(41, start + Duration::from_secs(30)),
                start + Duration::from_secs(20),
            )
            .await
            .expect("terminal retry resolves"),
        Claim::Replay {
            outcome: TerminalOutcome::Completed,
            ..
        }
    ));
}

#[tokio::test]
async fn a_clean_resume_release_admits_a_new_lease_and_fences_the_old_owner() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("resume-clean-release");
    let start = UNIX_EPOCH + Duration::from_secs(4_100_000);
    let mut old = match store
        .claim_resume(
            request(&caller, "records-create.person", "resume-release-key", 72),
            resume_context(43, start + Duration::from_secs(10)),
            start,
        )
        .await
        .expect("claim the first attempt")
    {
        Claim::Execute(execution) => execution,
        other => panic!("a fresh write executes: {other:?}"),
    };
    store
        .mark_resume_step_attempted(&mut old, 0, start + Duration::from_secs(1))
        .await
        .expect("premark the first physical attempt");
    store
        .release_resume_lease(&old, start + Duration::from_secs(2))
        .await
        .expect("a cleanly returned attempt releases only its lease");

    let mut resumed = match store
        .claim_resume(
            request(&caller, "records-create.person", "resume-release-key", 72),
            resume_context(43, start + Duration::from_secs(12)),
            start + Duration::from_secs(2),
        )
        .await
        .expect("reacquire the released step")
    {
        Claim::Resume {
            execution,
            next_step: 0,
            bindings,
        } if bindings.is_empty() => execution,
        other => panic!("the same unfinished step resumes: {other:?}"),
    };
    assert!(matches!(
        store
            .checkpoint_resume_step(
                &mut old,
                0,
                &[ResumeValue::new("record_id".to_owned(), "stale".to_owned())],
                start + Duration::from_secs(3),
            )
            .await,
        Err(IdempotencyError::StateConflict)
    ));
    store
        .mark_resume_step_attempted(&mut resumed, 0, start + Duration::from_secs(3))
        .await
        .expect("the new lease alone owns the step");
}

/// A resume write whose first step was never marked attempted sent
/// nothing, so its expiry frees the key instead of spending it: a later
/// retry executes fresh, whether the retry or the sweep finds it first.
#[tokio::test]
async fn an_expired_resume_that_never_sent_frees_its_key() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("resume-never-sent");
    let start = UNIX_EPOCH + Duration::from_secs(4_200_000);
    let after_expiry = start + Duration::from_secs(61);
    for (key, sweep_first) in [("never-sent-retry", false), ("never-sent-sweep", true)] {
        assert!(matches!(
            store
                .claim_resume(
                    request(&caller, "records-create.person", key, 73),
                    resume_context(44, start + Duration::from_secs(10)),
                    start,
                )
                .await
                .expect("claim the linear write"),
            Claim::Execute(_)
        ));
        if sweep_first {
            store
                .sweep_expired(after_expiry, 100)
                .await
                .expect("sweep the expired resume");
        }
        assert!(
            matches!(
                store
                    .claim_resume(
                        request(&caller, "records-create.person", key, 73),
                        resume_context(44, after_expiry + Duration::from_secs(10)),
                        after_expiry,
                    )
                    .await
                    .expect("the retry after expiry resolves"),
                Claim::Execute(_)
            ),
            "{key}: an expired write that sent nothing executes fresh"
        );
    }
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
    assert!(matches!(
        StoredResponse::with_semantic_headers(
            204,
            Some(b"application/json".to_vec()),
            None,
            None,
            Vec::new(),
            RESPONSE_REQUEST_ID,
        ),
        Err(IdempotencyError::InvalidInput {
            field: "response content type"
        })
    ));
    assert!(StoredResponse::new(
        204,
        b"application/json".to_vec(),
        br#"{"legacy":true}"#.to_vec(),
        RESPONSE_REQUEST_ID,
    )
    .is_ok());
    assert!(matches!(
        StoredResponse::with_semantic_headers(204, None, None, None, vec![1], RESPONSE_REQUEST_ID,),
        Err(IdempotencyError::InvalidInput {
            field: "response body"
        })
    ));
    assert!(matches!(
        StoredResponse::with_semantic_headers(
            201,
            None,
            Some(vec![b'x'; MAX_LOCATION_BYTES + 1]),
            None,
            Vec::new(),
            RESPONSE_REQUEST_ID,
        ),
        Err(IdempotencyError::InvalidInput {
            field: "response location"
        })
    ));
    assert!(matches!(
        StoredResponse::with_semantic_headers(
            200,
            Some(b"application/json".to_vec()),
            None,
            Some(vec![b'x'; MAX_ETAG_BYTES + 1]),
            b"{}".to_vec(),
            RESPONSE_REQUEST_ID,
        ),
        Err(IdempotencyError::InvalidInput {
            field: "response etag"
        })
    ));
}

#[tokio::test]
async fn bodyless_204_replays_exact_semantic_headers_then_erases_all_custody() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(1)).await;
    let owner = caller("bodyless-replay-owner");
    let now = SystemTime::now();
    let Claim::Execute(execution) = store
        .claim(
            request(&owner, "records-delete.person", "bodyless-key", 61),
            now,
        )
        .await
        .expect("claim the bodyless response")
    else {
        panic!("the bodyless response must execute first");
    };
    let stored = StoredResponse::with_semantic_headers(
        204,
        None,
        Some(b"/v1/records/person/17".to_vec()),
        Some(b"\"0123456789abcdef\"".to_vec()),
        Vec::new(),
        RESPONSE_REQUEST_ID,
    )
    .expect("the bodyless semantic response is bounded");
    store
        .finish(execution, TerminalOutcome::Completed, stored.clone(), now)
        .await
        .expect("store exact bodyless response custody");
    let Claim::Replay { response, .. } = store
        .claim(
            request(&owner, "records-delete.person", "bodyless-key", 61),
            now,
        )
        .await
        .expect("replay the bodyless response")
    else {
        panic!("the terminal response must replay");
    };
    assert_eq!(response, stored);
    assert_eq!(response.content_type_header(), None);
    assert_eq!(response.content_type(), b"");
    assert_eq!(response.location(), Some(&b"/v1/records/person/17"[..]));
    assert_eq!(response.etag(), Some(&b"\"0123456789abcdef\""[..]));
    assert!(response.body().is_empty());

    let after_expiry = now + Duration::from_secs(2);
    store
        .sweep_expired(after_expiry, 100)
        .await
        .expect("erase all semantic response custody");
    let client = isolated.client().await;
    let row = client
        .query_one(
            "SELECT response_content_type, response_location, response_etag, response_body \
             FROM adapter_idempotency_entries",
            &[],
        )
        .await
        .expect("inspect the erased bodyless response");
    assert_eq!(row.get::<_, Option<Vec<u8>>>(0), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(1), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(3), None);
}

#[tokio::test]
async fn an_interrupted_migration_commits_neither_its_schema_nor_its_ledger_row() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    // A ledger that refuses the baseline's version row stands in for a
    // startup interrupted between a schema change and its ledger insert.
    client
        .batch_execute(
            "CREATE TABLE adapter_idempotency_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);\
             CREATE FUNCTION interrupt_the_ledger() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'interrupted before the ledger row committed'; END; $$;\
             CREATE TRIGGER interrupt_the_ledger BEFORE INSERT ON adapter_idempotency_schema_migrations \
             FOR EACH ROW EXECUTE FUNCTION interrupt_the_ledger();",
        )
        .await
        .expect("install the interrupting ledger");
    idempotent::migrate(&mut client)
        .await
        .expect_err("a ledger row that never commits fails the migration");
    let table: Option<String> = client
        .query_one(
            "SELECT to_regclass('adapter_idempotency_entries')::text",
            &[],
        )
        .await
        .expect("look up the idempotency table")
        .get(0);
    assert_eq!(
        table, None,
        "a migration whose ledger row did not commit leaves no schema change behind"
    );

    client
        .batch_execute("DROP TRIGGER interrupt_the_ledger ON adapter_idempotency_schema_migrations")
        .await
        .expect("end the interruption");
    idempotent::migrate(&mut client)
        .await
        .expect("the next startup applies the whole migration set");
    let versions = client
        .query(
            "SELECT version FROM adapter_idempotency_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("read the idempotency ledger")
        .into_iter()
        .map(|row| row.get::<_, i64>(0))
        .collect::<Vec<_>>();
    assert_eq!(versions, [100, 200, 300, 400, 500, 600, 700]);
}

#[tokio::test]
async fn migration_owns_a_separate_idempotency_ledger_and_is_idempotent() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;

    idempotent::migrate(&mut client)
        .await
        .expect("the first migration run applies the idempotency baseline");
    idempotent::migrate(&mut client)
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
            "adapter_idempotency_async_artifacts".to_owned(),
            "adapter_idempotency_entries".to_owned(),
            "adapter_idempotency_resume_bindings".to_owned(),
            "adapter_idempotency_resumes".to_owned(),
            "adapter_idempotency_schema_migrations".to_owned(),
        ],
        "the idempotency migration neither creates nor borrows the journal ledger"
    );
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
}

#[tokio::test]
async fn logical_deployment_migration_refuses_legacy_rows_without_altering_them() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    install_v0100(&client).await;
    insert_claimed_row(&client).await;

    let error = idempotent::migrate(&mut client)
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
    let mut client = isolated.client().await;
    install_v0100(&client).await;

    idempotent::migrate(&mut client)
        .await
        .expect("an empty v0100 ledger can adopt the logical deployment namespace");
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
}

#[tokio::test]
async fn response_identity_migration_refuses_v0200_cached_responses_without_altering_them() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
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

    let error = idempotent::migrate(&mut client)
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
    let mut client = isolated.client().await;
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

    idempotent::migrate(&mut client)
        .await
        .expect("an expired tombstone has no response identity to recover");
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
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
    let mut client = isolated.client().await;
    idempotent::migrate(&mut client)
        .await
        .expect("fresh storage reaches the current schema");
    insert_claimed_row(&client).await;

    idempotent::migrate(&mut client)
        .await
        .expect("the applied semantic migration does not inspect current rows again");
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
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

    let mut client = isolated.client().await;
    idempotent::migrate(&mut client)
        .await
        .expect("an already-applied response-id migration accepts current custody");
    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
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
        Claim::EffectUnknown { .. }
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
async fn a_claim_abandoned_before_its_effect_mark_is_taken_over_after_the_exchange_deadline() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(3600)).await;
    let caller = caller("abandoned-claim-caller");
    let now = SystemTime::now();
    let at = |seconds| {
        now.checked_add(Duration::from_secs(seconds))
            .expect("the test instant is representable")
    };

    let Claim::Execute(mut abandoned) = store
        .claim(
            request(&caller, "records-create.person", "abandoned-key", 81),
            now,
        )
        .await
        .expect("claim work whose owner then dies")
    else {
        panic!("a fresh claim executes");
    };
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "abandoned-key", 81),
                at(1),
            )
            .await
            .expect("retry inside the claim lease"),
        Claim::InFlight
    ));
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "abandoned-key", 82),
                at(61),
            )
            .await
            .expect("a changed body never takes over the claim"),
        Claim::Mismatch
    ));
    let Claim::Execute(mut successor) = store
        .claim(
            request(&caller, "records-create.person", "abandoned-key", 81),
            at(61),
        )
        .await
        .expect("retry after the claim lease")
    else {
        panic!("no effect was marked, so the retry takes the abandoned claim over");
    };
    assert!(matches!(
        store.mark_effect_attempted(&mut abandoned, at(62)).await,
        Err(IdempotencyError::StateConflict)
    ));
    assert!(matches!(
        store.release_before_effect(abandoned).await,
        Err(IdempotencyError::StateConflict)
    ));
    store
        .mark_effect_attempted(&mut successor, at(62))
        .await
        .expect("the successor owns the claim");
    assert!(matches!(
        store
            .claim(
                request(&caller, "records-create.person", "abandoned-key", 81),
                at(600),
            )
            .await
            .expect("retry after the successor marked its effect"),
        Claim::EffectUnknown { .. }
    ));

    let Claim::Execute(mut abandoned_async) = store
        .claim(
            request(&caller, "records-create.person", "abandoned-async-key", 83),
            now,
        )
        .await
        .expect("claim an async write whose owner then dies")
    else {
        panic!("a fresh async claim executes");
    };
    let Claim::Execute(successor_async) = store
        .claim(
            request(&caller, "records-create.person", "abandoned-async-key", 83),
            at(61),
        )
        .await
        .expect("retry the async write after the claim lease")
    else {
        panic!("the async retry takes the abandoned claim over");
    };
    let effect_deadline = at(65);
    assert!(matches!(
        store
            .mark_async_effect_attempted(
                &mut abandoned_async,
                request(&caller, "records-create.person", "abandoned-async-key", 83),
                async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 84, effect_deadline),
                at(62),
            )
            .await,
        Err(IdempotencyError::StateConflict)
    ));
    store
        .release_before_effect(successor_async)
        .await
        .expect("the successor can still release before its effect");
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

/// Camel's non-eager consumer does not add a failed exchange to its
/// repository, regardless of `removeOnFailure`. Adapter may therefore release
/// its separate host reservation only while no non-safe effect was attempted.
#[tokio::test]
async fn eager_false_failure_releases_a_safe_host_reservation() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("non-eager-safe-failure");
    let context = WriteExecutionContext::new(
        store.clone(),
        caller.clone(),
        "deployment-a".to_owned(),
        "records-create.person".to_owned(),
        [71; 32],
    );

    assert_eq!(
        context
            .claim("non-eager-safe-key", false)
            .await
            .expect("reserve the host key"),
        WriteClaim::Execute
    );
    context
        .complete(false, false)
        .await
        .expect("a non-eager failed exchange never becomes an EIP member");
    assert_eq!(context.resolution().await, WriteResolution::Released);

    let retry = WriteExecutionContext::new(
        store,
        caller,
        "deployment-a".to_owned(),
        "records-create.person".to_owned(),
        [71; 32],
    );
    assert_eq!(
        retry
            .claim("non-eager-safe-key", false)
            .await
            .expect("retry the safely released key"),
        WriteClaim::Execute
    );
}

/// Adapter's effect marker is independent of Camel repository timing. Even
/// with `eager=false`, a possible source effect keeps the host reservation
/// spent and the terminal problem replays instead of executing again.
#[tokio::test]
async fn eager_false_failure_after_an_effect_never_reopens_the_key() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let caller = caller("non-eager-effect-failure");
    let context = WriteExecutionContext::new(
        store.clone(),
        caller.clone(),
        "deployment-a".to_owned(),
        "records-update.person".to_owned(),
        [72; 32],
    );

    assert_eq!(
        context
            .claim("non-eager-effect-key", false)
            .await
            .expect("reserve the host key"),
        WriteClaim::Execute
    );
    context
        .before_effect()
        .await
        .expect("persist the effect boundary before the send");
    context
        .complete(false, true)
        .await
        .expect("completion cannot release an attempted effect");
    assert_eq!(context.resolution().await, WriteResolution::Pending);

    let problem = response(
        502,
        b"application/problem+json",
        br#"{"code":"adapter.upstream-unavailable"}"#,
    );
    let client = isolated.client().await;
    context
        .finish_with_client(&client, TerminalOutcome::Failed, problem.clone())
        .await
        .expect("record the terminal response for the attempted effect");

    let retry = WriteExecutionContext::new(
        store,
        caller,
        "deployment-a".to_owned(),
        "records-update.person".to_owned(),
        [72; 32],
    );
    assert_eq!(
        retry
            .claim("non-eager-effect-key", false)
            .await
            .expect("resolve the spent key"),
        WriteClaim::Stop
    );
    assert_eq!(
        retry.resolution().await,
        WriteResolution::Replay {
            outcome: TerminalOutcome::Failed,
            response: problem,
        }
    );
}

#[tokio::test]
async fn v0400_preserves_v0300_terminal_and_spent_rows_without_inventing_async_authority() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    install_v0300(&client).await;
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries (\
                 scope_digest, request_digest, state, claimed_at, terminal_at, expires_at, \
                 response_status, response_content_type, response_body, response_request_id) \
             VALUES ($1, $2, 'completed', now(), now(), now() + interval '1 hour', \
                     201, $3, $4, $5), \
                    ($6, $7, 'failed_expired', now(), now(), now(), \
                     NULL, NULL, NULL, NULL)",
            &[
                &[81_u8; 32].as_slice(),
                &[82_u8; 32].as_slice(),
                &b"application/json".as_slice(),
                &b"{}".as_slice(),
                &RESPONSE_REQUEST_ID,
                &[83_u8; 32].as_slice(),
                &[84_u8; 32].as_slice(),
            ],
        )
        .await
        .expect("insert v0300 terminal and tombstone rows");
    client
        .execute(
            "INSERT INTO adapter_idempotency_entries (\
                 scope_digest, request_digest, state, claimed_at, effect_started_at) \
             VALUES ($1, $2, 'effect_started', now(), now())",
            &[&[85_u8; 32].as_slice(), &[86_u8; 32].as_slice()],
        )
        .await
        .expect("insert a v0300 permanently-spent uncertain effect");

    idempotent::migrate(&mut client)
        .await
        .expect("v0400 accepts existing terminal and spent rows");

    assert_eq!(
        migration_versions(&client).await,
        vec![100, 200, 300, 400, 500, 600, 700]
    );
    let rows = client
        .query(
            "SELECT state, artifact_digest, async_binding_digest, async_recovery_id \
             FROM adapter_idempotency_entries ORDER BY state",
            &[],
        )
        .await
        .expect("inspect migrated v0300 rows");
    assert_eq!(rows.len(), 3);
    assert!(rows
        .iter()
        .any(|row| row.get::<_, String>(0) == "effect_started"));
    for row in rows {
        assert_eq!(row.get::<_, Option<Vec<u8>>>(1), None);
        assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
        assert_eq!(row.get::<_, Option<String>>(3), None);
    }
}

#[tokio::test]
async fn accepted_response_replays_exactly_and_status_metadata_is_exposed_only_after_binding_match()
{
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(60)).await;
    let owner = caller("async-owner");
    let other = caller("async-other");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(10))
        .expect("effect deadline is representable");
    let claim_request = request(&owner, "records-create.person", "accepted-exact-key", 91);
    let Claim::Execute(mut execution) = store
        .claim(claim_request, now)
        .await
        .expect("claim the asynchronous write")
    else {
        panic!("the asynchronous write must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "accepted-exact-key", 91),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 92, effect_deadline),
            now,
        )
        .await
        .expect("precommit asynchronous recovery before the effect");
    let accepted = StoredResponse::with_semantic_headers(
        202,
        Some(b"application/vnd.registry+json; profile=accepted".to_vec()),
        Some(b"/v1/status/00000000000000000000000000000001".to_vec()),
        Some(b"\"accepted-17\"".to_vec()),
        br#"{"status":"accepted", "requestId":"00000000000000000000000000000001"}\n"#.to_vec(),
        RESPONSE_REQUEST_ID,
    )
    .expect("the accepted semantic response is bounded");
    store
        .accept(execution, "source-operation-7", accepted.clone(), now)
        .await
        .expect("commit exact accepted response custody");

    assert!(matches!(
        store
            .claim(
                request(
                    &owner,
                    "records-create.person",
                    "accepted-exact-key",
                    91,
                ),
                now,
            )
            .await
            .expect("retry the accepted write"),
        Claim::Accepted { response } if response == accepted
    ));
    assert!(matches!(
        store
            .lookup_status(status_lookup(&other, RESPONSE_REQUEST_ID, 92), now)
            .await
            .expect("look up as another verified caller"),
        StatusLookup::NotFound
    ));
    assert!(matches!(
        store
            .lookup_status(status_lookup(&owner, RESPONSE_REQUEST_ID, 93), now)
            .await
            .expect("look up under another artifact"),
        StatusLookup::NotFound
    ));
    assert!(matches!(
        store
            .lookup_status(status_lookup(&owner, "ABC", 92), now)
            .await
            .expect("look up a malformed status handle"),
        StatusLookup::NotFound
    ));

    let StatusLookup::Accepted(status) = store
        .lookup_status(status_lookup(&owner, RESPONSE_REQUEST_ID, 92), now)
        .await
        .expect("look up the caller-bound accepted status")
    else {
        panic!("the matching caller and artifact must see accepted custody");
    };
    assert_eq!(status.response(), &accepted);
    assert_eq!(
        status.response().location(),
        Some(&b"/v1/status/00000000000000000000000000000001"[..])
    );
    assert_eq!(status.response().etag(), Some(&b"\"accepted-17\""[..]));
    assert_eq!(status.metadata().binding_id(), "person-create-binding");
    assert_eq!(status.metadata().profile_operation(), "records-create");
    assert_eq!(
        status.metadata().concrete_operation(),
        "records-create.person"
    );
    assert_eq!(status.metadata().record_type(), "person");
}

#[tokio::test]
async fn a_live_async_status_handle_collision_is_refused_without_mutating_the_second_claim() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(30)).await;
    let owner = caller("collision-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");

    let Claim::Execute(mut first) = store
        .claim(
            request(&owner, "records-create.person", "collision-first", 95),
            now,
        )
        .await
        .expect("claim the first handle owner")
    else {
        panic!("the first handle owner must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut first,
            request(&owner, "records-create.person", "collision-first", 95),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 96, effect_deadline),
            now,
        )
        .await
        .expect("commit the first live handle");

    let Claim::Execute(mut second) = store
        .claim(
            request(&owner, "records-create.person", "collision-second", 97),
            now,
        )
        .await
        .expect("claim the second handle owner")
    else {
        panic!("the second handle owner must execute before collision");
    };
    assert!(matches!(
        store
            .mark_async_effect_attempted(
                &mut second,
                request(&owner, "records-create.person", "collision-second", 97),
                async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 96, effect_deadline),
                now,
            )
            .await,
        Err(IdempotencyError::Query(_))
    ));
    store
        .release_before_effect(second)
        .await
        .expect("the refused collision never crossed the effect boundary");
    assert!(matches!(
        store
            .claim(
                request(&owner, "records-create.person", "collision-second", 97),
                now,
            )
            .await
            .expect("reclaim the unmutated collision row"),
        Claim::Execute(_)
    ));
}

#[tokio::test]
async fn one_recovery_lease_owns_a_row_and_terminal_status_lives_until_original_link_expiry() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(10)).await;
    let owner = caller("lease-owner");
    let accepted_at = SystemTime::now();
    let effect_deadline = accepted_at
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");
    let Claim::Execute(mut execution) = store
        .claim(
            request(&owner, "records-create.person", "lease-key", 101),
            accepted_at,
        )
        .await
        .expect("claim the leased asynchronous write")
    else {
        panic!("the leased asynchronous write must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "lease-key", 101),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 102, effect_deadline),
            accepted_at,
        )
        .await
        .expect("precommit recovery custody");
    let accepted = response(202, b"application/json", br#"{"status":"accepted"}"#);
    store
        .accept(
            execution,
            "source-operation-lease",
            accepted.clone(),
            accepted_at,
        )
        .await
        .expect("commit accepted custody");

    let StatusLookup::Accepted(status) = store
        .lookup_status(status_lookup(&owner, RESPONSE_REQUEST_ID, 102), accepted_at)
        .await
        .expect("load pending status")
    else {
        panic!("status must be accepted");
    };
    let lease_deadline = accepted_at
        .checked_add(Duration::from_secs(3))
        .expect("lease deadline is representable");
    let RecoveryLease::Acquired(recovery) = store
        .acquire_status_recovery(&status, accepted_at, lease_deadline)
        .await
        .expect("acquire the first recovery lease")
    else {
        panic!("the first checker must acquire the row");
    };
    assert_eq!(recovery.source_id(), Some("source-operation-lease"));
    assert!(matches!(
        store
            .acquire_status_recovery(&status, accepted_at, lease_deadline)
            .await
            .expect("contend for the recovery lease"),
        RecoveryLease::Busy
    ));

    let terminal_at = accepted_at
        .checked_add(Duration::from_secs(2))
        .expect("terminal time is representable");
    let terminal = StoredResponse::with_semantic_headers(
        200,
        Some(b"application/json".to_vec()),
        Some(b"/v1/records/person/17".to_vec()),
        Some(b"\"record-17\"".to_vec()),
        br#"{"done":true}"#.to_vec(),
        RESPONSE_REQUEST_ID,
    )
    .expect("the recovered terminal semantic response is bounded");
    store
        .finish_recovery(
            recovery,
            TerminalOutcome::Completed,
            terminal.clone(),
            terminal_at,
        )
        .await
        .expect("commit terminal recovery");

    let before_link_expiry = accepted_at
        .checked_add(Duration::from_secs(9))
        .expect("pre-expiry time is representable");
    assert!(matches!(
        store
            .lookup_status(
                status_lookup(&owner, RESPONSE_REQUEST_ID, 102),
                before_link_expiry,
            )
            .await
            .expect("look up terminal response before original link expiry"),
        StatusLookup::Terminal {
            outcome: TerminalOutcome::Completed,
            response,
            ..
        } if response == terminal
    ));

    let client = isolated.client().await;
    let identifiers = client
        .query_one(
            "SELECT async_source_id, async_recovery_id, response_request_id, \
                    async_binding_digest \
             FROM adapter_idempotency_entries",
            &[],
        )
        .await
        .expect("inspect terminal async custody");
    assert_eq!(identifiers.get::<_, Option<String>>(0), None);
    assert_eq!(identifiers.get::<_, Option<String>>(1), None);
    assert_eq!(
        identifiers.get::<_, Option<String>>(2).as_deref(),
        Some(RESPONSE_REQUEST_ID)
    );
    assert!(identifiers.get::<_, Option<Vec<u8>>>(3).is_some());

    let after_link_before_response_expiry = accepted_at
        .checked_add(Duration::from_secs(11))
        .expect("post-link time is representable");
    assert_eq!(
        store
            .sweep_expired(after_link_before_response_expiry, 100)
            .await
            .expect("erase the expired async link"),
        1
    );
    assert!(matches!(
        store
            .lookup_status(
                status_lookup(&owner, RESPONSE_REQUEST_ID, 102),
                after_link_before_response_expiry,
            )
            .await
            .expect("look up an expired status link"),
        StatusLookup::NotFound
    ));
    assert!(matches!(
        store
            .claim(
                request(&owner, "records-create.person", "lease-key", 101),
                after_link_before_response_expiry,
            )
            .await
            .expect("retry before ordinary terminal response expiry"),
        Claim::Replay {
            outcome: TerminalOutcome::Completed,
            response
        } if response == terminal
    ));
}

#[tokio::test]
async fn uncertainty_is_permanently_spent_and_only_precommitted_correlation_can_acquire_recovery() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(5)).await;
    let owner = caller("uncertainty-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");

    let Claim::Execute(mut uncorrelated) = store
        .claim(
            request(&owner, "records-create.person", "uncorrelated-key", 111),
            now,
        )
        .await
        .expect("claim uncorrelated uncertainty")
    else {
        panic!("uncorrelated uncertainty must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut uncorrelated,
            request(&owner, "records-create.person", "uncorrelated-key", 111),
            async_attempt(RESPONSE_REQUEST_ID, None, 112, effect_deadline),
            now,
        )
        .await
        .expect("mark the uncorrelated effect");
    assert!(matches!(
        store
            .acquire_uncertain_recovery(
                request(&owner, "records-create.person", "uncorrelated-key", 111,),
                [112; 32],
                now,
                effect_deadline,
            )
            .await
            .expect("refuse recovery without source-native correlation"),
        RecoveryLease::Stale
    ));

    let Claim::Execute(mut correlated) = store
        .claim(
            request(&owner, "records-create.person", "correlated-key", 113),
            now,
        )
        .await
        .expect("claim correlated uncertainty")
    else {
        panic!("correlated uncertainty must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut correlated,
            request(&owner, "records-create.person", "correlated-key", 113),
            async_attempt(
                OTHER_RESPONSE_REQUEST_ID,
                Some(RECOVERY_ID),
                112,
                effect_deadline,
            ),
            now,
        )
        .await
        .expect("precommit source-native correlation");
    let RecoveryLease::Acquired(recovery) = store
        .acquire_uncertain_recovery(
            request(&owner, "records-create.person", "correlated-key", 113),
            [112; 32],
            now,
            effect_deadline,
        )
        .await
        .expect("acquire correlated uncertainty")
    else {
        panic!("the correlated effect must be recoverable");
    };
    assert_eq!(recovery.recovery_id(), Some(RECOVERY_ID));
    store
        .release_recovery(recovery)
        .await
        .expect("release a pending uncertainty check");

    let after_custody = effect_deadline
        .checked_add(Duration::from_secs(6))
        .expect("uncertainty expiry is representable");
    store
        .sweep_expired(after_custody, 100)
        .await
        .expect("erase expired uncertainty metadata");
    assert!(matches!(
        store
            .claim(
                request(&owner, "records-create.person", "correlated-key", 113,),
                after_custody,
            )
            .await
            .expect("retry after uncertainty metadata expiry"),
        Claim::EffectUnknown { .. }
    ));
}

#[tokio::test]
async fn accepted_expiry_erases_custody_and_never_reopens_the_key() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(1)).await;
    let owner = caller("accepted-expiry-owner");
    let accepted_at = SystemTime::now();
    let Claim::Execute(mut execution) = store
        .claim(
            request(&owner, "records-create.person", "accepted-expiry", 121),
            accepted_at,
        )
        .await
        .expect("claim expiring acceptance")
    else {
        panic!("the expiring acceptance must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "accepted-expiry", 121),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 122, accepted_at),
            accepted_at,
        )
        .await
        .expect("precommit expiring recovery");
    store
        .accept(
            execution,
            "source-expiry",
            StoredResponse::with_semantic_headers(
                202,
                Some(b"application/json".to_vec()),
                Some(b"/v1/status/source-expiry".to_vec()),
                Some(b"\"accepted-expiry\"".to_vec()),
                br#"{"accepted":true}"#.to_vec(),
                RESPONSE_REQUEST_ID,
            )
            .expect("the expiring semantic response is bounded"),
            accepted_at,
        )
        .await
        .expect("commit expiring acceptance");

    let after_expiry = accepted_at
        .checked_add(Duration::from_secs(2))
        .expect("accepted expiry is representable");
    assert_eq!(
        store
            .sweep_expired(after_expiry, 100)
            .await
            .expect("erase accepted custody"),
        1
    );
    assert!(matches!(
        store
            .claim(
                request(&owner, "records-create.person", "accepted-expiry", 121),
                after_expiry,
            )
            .await
            .expect("retry expired acceptance"),
        Claim::AcceptedExpired
    ));
    let client = isolated.client().await;
    let row = client
        .query_one(
            "SELECT response_status, response_content_type, response_location, response_etag, \
                    response_body, response_request_id, artifact_digest, \
                    async_binding_digest, async_source_id, async_recovery_id \
             FROM adapter_idempotency_entries",
            &[],
        )
        .await
        .expect("inspect accepted tombstone");
    assert_eq!(row.get::<_, Option<i16>>(0), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(1), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(2), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(3), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(4), None);
    assert_eq!(row.get::<_, Option<String>>(5), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(6), None);
    assert_eq!(row.get::<_, Option<Vec<u8>>>(7), None);
    assert_eq!(row.get::<_, Option<String>>(8), None);
    assert_eq!(row.get::<_, Option<String>>(9), None);
}

#[tokio::test]
async fn incompatible_artifact_is_refused_while_async_recovery_is_live() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(5)).await;
    let owner = caller("upgrade-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");
    let Claim::Execute(mut execution) = store
        .claim(
            request(&owner, "records-create.person", "upgrade-key", 131),
            now,
        )
        .await
        .expect("claim upgrade-blocking uncertainty")
    else {
        panic!("upgrade-blocking uncertainty must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "upgrade-key", 131),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 132, effect_deadline),
            now,
        )
        .await
        .expect("precommit upgrade-bound recovery");

    store
        .ensure_async_artifact_compatible("deployment-a", [132; 32], now)
        .await
        .expect("the same artifact remains compatible");
    let Err(IdempotencyError::AsyncArtifactActivationRefused {
        unfinished,
        clears_by,
    }) = store
        .ensure_async_artifact_compatible("deployment-a", [133; 32], now)
        .await
    else {
        panic!("a live recovery of another artifact refuses activation");
    };
    assert_eq!(unfinished, 1);
    let expected_clear = effect_deadline + Duration::from_secs(5);
    let drift = clears_by
        .duration_since(expected_clear)
        .or_else(|_| expected_clear.duration_since(clears_by))
        .expect("compare clear instants");
    assert!(
        drift < Duration::from_millis(1),
        "the refusal names when the live recovery expires: {clears_by:?}"
    );
    assert!(
        IdempotencyError::AsyncArtifactActivationRefused {
            unfinished,
            clears_by,
        }
        .to_string()
        .contains("redeploy the previous artifact bytes"),
        "the refusal names the operator's way out"
    );
    store
        .ensure_async_artifact_compatible("another-deployment", [133; 32], now)
        .await
        .expect("another logical deployment is independent");

    let client = isolated.client().await;
    let effect_count: i64 = client
        .query_one(
            "SELECT count(*) FROM adapter_idempotency_entries \
             WHERE state = 'effect_started'",
            &[],
        )
        .await
        .expect("count old-artifact effects after refused activation")
        .get(0);
    assert_eq!(effect_count, 1);
}

#[tokio::test]
async fn a_terminal_async_row_of_another_artifact_does_not_block_activation() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(3600)).await;
    let owner = caller("hotfix-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");
    let Claim::Execute(mut execution) = store
        .claim(
            request(&owner, "records-create.person", "hotfix-key", 134),
            now,
        )
        .await
        .expect("claim an async write under the old artifact")
    else {
        panic!("a fresh async write executes");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "hotfix-key", 134),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 135, effect_deadline),
            now,
        )
        .await
        .expect("precommit the old artifact's async effect");
    store
        .finish(
            execution,
            TerminalOutcome::Completed,
            response(201, b"application/json", br#"{"record":"done"}"#),
            now,
        )
        .await
        .expect("the source answered synchronously, so the write is terminal");

    store
        .ensure_async_artifact_compatible("deployment-a", [136; 32], now)
        .await
        .expect("a terminal row holds no recovery authority, so a hotfix activates");
}

#[tokio::test]
async fn a_new_artifact_activation_fences_late_old_artifact_precommit_before_effect() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(5)).await;
    let owner = caller("new-first-upgrade-owner");
    let now = SystemTime::now();
    store
        .ensure_async_artifact_compatible("deployment-a", [172; 32], now)
        .await
        .expect("activate the new artifact before the old pod attempts an effect");

    let Claim::Execute(mut old_execution) = store
        .claim(
            request(&owner, "records-create.person", "new-first-upgrade", 171),
            now,
        )
        .await
        .expect("claim work in the old pod before its fenced precommit")
    else {
        panic!("the old pod claim must initially be fresh");
    };
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");
    assert!(matches!(
        store
            .mark_async_effect_attempted(
                &mut old_execution,
                request(&owner, "records-create.person", "new-first-upgrade", 171),
                async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 173, effect_deadline,),
                now,
            )
            .await,
        Err(IdempotencyError::AsyncArtifactInUse)
    ));
    store
        .release_before_effect(old_execution)
        .await
        .expect("the refused old artifact never crossed the effect boundary");

    let client = isolated.client().await;
    let effect_count: i64 = client
        .query_one(
            "SELECT count(*) FROM adapter_idempotency_entries \
             WHERE state = 'effect_started'",
            &[],
        )
        .await
        .expect("count effects after the new-first refusal")
        .get(0);
    assert_eq!(effect_count, 0);
}

#[tokio::test]
async fn artifact_activation_and_old_precommit_are_serialized_by_one_postgres_fence() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(5)).await;
    let owner = caller("concurrent-upgrade-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");
    let Claim::Execute(old_execution) = store
        .claim(
            request(&owner, "records-create.person", "concurrent-upgrade", 174),
            now,
        )
        .await
        .expect("claim work before the concurrent upgrade fence")
    else {
        panic!("the concurrent old pod claim must initially be fresh");
    };
    let barrier = Arc::new(Barrier::new(2));
    let mark_barrier = Arc::clone(&barrier);
    let activate_barrier = Arc::clone(&barrier);
    let mark_store = store.clone();
    let activate_store = store.clone();
    let mark_owner = owner.clone();

    let (mark, activation) = tokio::join!(
        async move {
            let mut execution = old_execution;
            mark_barrier.wait().await;
            let result = mark_store
                .mark_async_effect_attempted(
                    &mut execution,
                    request(
                        &mark_owner,
                        "records-create.person",
                        "concurrent-upgrade",
                        174,
                    ),
                    async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 175, effect_deadline),
                    now,
                )
                .await;
            (result, execution)
        },
        async move {
            activate_barrier.wait().await;
            activate_store
                .ensure_async_artifact_compatible("deployment-a", [176; 32], now)
                .await
        }
    );

    let expected_effect_count = match (mark.0, activation) {
        (Ok(()), Err(IdempotencyError::AsyncArtifactActivationRefused { unfinished: 1, .. })) => 1,
        (Err(IdempotencyError::AsyncArtifactInUse), Ok(())) => {
            store
                .release_before_effect(mark.1)
                .await
                .expect("the fenced concurrent old claim remains releasable");
            0
        }
        (mark_result, activation_result) => panic!(
            "exactly one artifact may win the deployment fence: \
             mark={mark_result:?}, activation={activation_result:?}"
        ),
    };
    let client = isolated.client().await;
    let effect_count: i64 = client
        .query_one(
            "SELECT count(*) FROM adapter_idempotency_entries \
             WHERE state = 'effect_started'",
            &[],
        )
        .await
        .expect("count effects after the concurrent deployment fence")
        .get(0);
    assert_eq!(effect_count, expected_effect_count);
}

#[tokio::test]
async fn cleanup_and_late_acceptance_serialize_without_reopening_or_resending() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(1)).await;
    let owner = caller("accept-race-owner");
    let started_at = SystemTime::now();
    let Claim::Execute(mut execution) = store
        .claim(
            request(&owner, "records-create.person", "accept-race", 141),
            started_at,
        )
        .await
        .expect("claim acceptance race")
    else {
        panic!("the acceptance race must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "accept-race", 141),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 142, started_at),
            started_at,
        )
        .await
        .expect("precommit acceptance race metadata");
    let after_uncertainty_expiry = started_at
        .checked_add(Duration::from_secs(2))
        .expect("race time is representable");
    store
        .ensure_async_artifact_compatible("deployment-a", [143; 32], after_uncertainty_expiry)
        .await
        .expect("the new artifact activates after old uncertainty expires");
    let accept_store = store.clone();
    let sweep_store = store.clone();
    let (accepted, swept) = tokio::join!(
        async move {
            accept_store
                .accept(
                    execution,
                    "late-source-id",
                    response(202, b"application/json", br#"{"accepted":true}"#),
                    after_uncertainty_expiry,
                )
                .await
        },
        async move {
            sweep_store
                .sweep_expired(after_uncertainty_expiry, 100)
                .await
        }
    );
    swept.expect("the racing cleanup completes");
    assert!(matches!(accepted, Err(IdempotencyError::StateConflict)));
    assert!(matches!(
        store
            .claim(
                request(&owner, "records-create.person", "accept-race", 141),
                after_uncertainty_expiry,
            )
            .await
            .expect("resolve the raced write"),
        Claim::EffectUnknown { .. }
    ));
}

#[tokio::test]
async fn an_expired_recovery_capability_cannot_finish_but_its_successor_can() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(30)).await;
    let owner = caller("expired-terminal-capability-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(20))
        .expect("effect deadline is representable");
    let Claim::Execute(mut execution) = store
        .claim(
            request(
                &owner,
                "records-create.person",
                "expired-terminal-capability",
                143,
            ),
            now,
        )
        .await
        .expect("claim terminal capability expiry")
    else {
        panic!("terminal capability expiry must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(
                &owner,
                "records-create.person",
                "expired-terminal-capability",
                143,
            ),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 144, effect_deadline),
            now,
        )
        .await
        .expect("precommit terminal capability recovery");
    store
        .accept(
            execution,
            "source-expired-terminal-capability",
            response(202, b"application/json", br#"{"accepted":true}"#),
            now,
        )
        .await
        .expect("commit accepted custody before terminal capability expiry");
    let StatusLookup::Accepted(status) = store
        .lookup_status(status_lookup(&owner, RESPONSE_REQUEST_ID, 144), now)
        .await
        .expect("load accepted status before terminal capability expiry")
    else {
        panic!("terminal capability row must be accepted");
    };
    let first_lease_until = now
        .checked_add(Duration::from_secs(1))
        .expect("first terminal lease deadline is representable");
    let RecoveryLease::Acquired(expired) = store
        .acquire_status_recovery(&status, now, first_lease_until)
        .await
        .expect("acquire the terminal capability that will expire")
    else {
        panic!("the first terminal checker must acquire the row");
    };
    let after_first_lease = now
        .checked_add(Duration::from_secs(2))
        .expect("post-terminal-lease time is representable");
    assert!(matches!(
        store
            .finish_recovery(
                expired,
                TerminalOutcome::Completed,
                response(200, b"application/json", br#"{"late":true}"#),
                after_first_lease,
            )
            .await,
        Err(IdempotencyError::StateConflict)
    ));
    assert!(matches!(
        store
            .lookup_status(
                status_lookup(&owner, RESPONSE_REQUEST_ID, 144),
                after_first_lease,
            )
            .await
            .expect("late terminal capability leaves accepted custody unchanged"),
        StatusLookup::Accepted(_)
    ));

    let successor_lease_until = after_first_lease
        .checked_add(Duration::from_secs(2))
        .expect("successor terminal lease deadline is representable");
    let RecoveryLease::Acquired(successor) = store
        .acquire_status_recovery(&status, after_first_lease, successor_lease_until)
        .await
        .expect("acquire a successor terminal capability")
    else {
        panic!("the successor terminal checker must acquire the row");
    };
    store
        .finish_recovery(
            successor,
            TerminalOutcome::Completed,
            response(200, b"application/json", br#"{"done":true}"#),
            after_first_lease,
        )
        .await
        .expect("the live successor terminal capability commits");
}

#[tokio::test]
async fn an_expired_uncertain_capability_cannot_accept_but_its_successor_can() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(30)).await;
    let owner = caller("expired-accept-capability-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(20))
        .expect("effect deadline is representable");
    let claim_request = request(
        &owner,
        "records-create.person",
        "expired-accept-capability",
        145,
    );
    let Claim::Execute(mut execution) = store
        .claim(claim_request, now)
        .await
        .expect("claim recovered acceptance capability expiry")
    else {
        panic!("recovered acceptance capability expiry must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(
                &owner,
                "records-create.person",
                "expired-accept-capability",
                145,
            ),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 146, effect_deadline),
            now,
        )
        .await
        .expect("precommit recovered acceptance correlation");
    let first_lease_until = now
        .checked_add(Duration::from_secs(1))
        .expect("first recovered acceptance lease deadline is representable");
    let RecoveryLease::Acquired(expired) = store
        .acquire_uncertain_recovery(
            request(
                &owner,
                "records-create.person",
                "expired-accept-capability",
                145,
            ),
            [146; 32],
            now,
            first_lease_until,
        )
        .await
        .expect("acquire the recovered acceptance capability that will expire")
    else {
        panic!("the first recovered acceptance checker must acquire the row");
    };
    let after_first_lease = now
        .checked_add(Duration::from_secs(2))
        .expect("post-recovered-acceptance-lease time is representable");
    let client = isolated.client().await;
    assert!(matches!(
        store
            .accept_recovery_with_client(
                &client,
                expired,
                "late-source-id",
                response(202, b"application/json", br#"{"late":true}"#),
                after_first_lease,
            )
            .await,
        Err(IdempotencyError::StateConflict)
    ));
    assert!(matches!(
        store
            .claim(
                request(
                    &owner,
                    "records-create.person",
                    "expired-accept-capability",
                    145,
                ),
                after_first_lease,
            )
            .await
            .expect("late acceptance capability leaves effect permanently spent"),
        Claim::EffectUnknown { .. }
    ));

    let successor_lease_until = after_first_lease
        .checked_add(Duration::from_secs(2))
        .expect("successor recovered acceptance lease deadline is representable");
    let RecoveryLease::Acquired(successor) = store
        .acquire_uncertain_recovery(
            request(
                &owner,
                "records-create.person",
                "expired-accept-capability",
                145,
            ),
            [146; 32],
            after_first_lease,
            successor_lease_until,
        )
        .await
        .expect("acquire a successor recovered acceptance capability")
    else {
        panic!("the successor recovered acceptance checker must acquire the row");
    };
    let recovered_acceptance = StoredResponse::with_semantic_headers(
        202,
        Some(b"application/json".to_vec()),
        Some(b"/v1/status/recovered-source-id".to_vec()),
        Some(b"\"recovered-acceptance\"".to_vec()),
        br#"{"accepted":true}"#.to_vec(),
        RESPONSE_REQUEST_ID,
    )
    .expect("the recovered accepted semantic response is bounded");
    store
        .accept_recovery_with_client(
            &client,
            successor,
            "recovered-source-id",
            recovered_acceptance.clone(),
            after_first_lease,
        )
        .await
        .expect("the live successor recovered acceptance capability commits");
    assert!(matches!(
        store
            .claim(
                request(
                    &owner,
                    "records-create.person",
                    "expired-accept-capability",
                    145,
                ),
                after_first_lease,
            )
            .await
            .expect("replay recovered acceptance custody"),
        Claim::Accepted { response } if response == recovered_acceptance
    ));
}

#[tokio::test]
async fn accepted_and_terminal_custody_roll_back_with_the_callers_journal_transaction() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(30)).await;
    let owner = caller("atomic-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(5))
        .expect("effect deadline is representable");

    let Claim::Execute(mut rolled_back_execution) = store
        .claim(
            request(&owner, "records-create.person", "accept-rollback", 151),
            now,
        )
        .await
        .expect("claim rolled-back acceptance")
    else {
        panic!("rolled-back acceptance must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut rolled_back_execution,
            request(&owner, "records-create.person", "accept-rollback", 151),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 152, effect_deadline),
            now,
        )
        .await
        .expect("precommit rolled-back acceptance");
    let mut client = isolated.client().await;
    let transaction = client
        .transaction()
        .await
        .expect("begin acceptance journal transaction");
    store
        .accept_with_client(
            &transaction,
            rolled_back_execution,
            "source-rollback",
            response(202, b"application/json", br#"{"accepted":true}"#),
            now,
        )
        .await
        .expect("stage accepted custody");
    transaction
        .rollback()
        .await
        .expect("roll back acceptance with journal");
    assert!(matches!(
        store
            .claim(
                request(&owner, "records-create.person", "accept-rollback", 151),
                now,
            )
            .await
            .expect("resolve rolled-back acceptance"),
        Claim::EffectUnknown { .. }
    ));

    let Claim::Execute(mut terminal_execution) = store
        .claim(
            request(&owner, "records-create.person", "terminal-rollback", 153),
            now,
        )
        .await
        .expect("claim terminal rollback")
    else {
        panic!("terminal rollback must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut terminal_execution,
            request(&owner, "records-create.person", "terminal-rollback", 153),
            async_attempt(
                OTHER_RESPONSE_REQUEST_ID,
                Some(RECOVERY_ID),
                152,
                effect_deadline,
            ),
            now,
        )
        .await
        .expect("precommit terminal rollback recovery");
    let accepted = StoredResponse::new(
        202,
        b"application/json".to_vec(),
        br#"{"accepted":true}"#.to_vec(),
        OTHER_RESPONSE_REQUEST_ID,
    )
    .expect("the alternate accepted response is bounded");
    store
        .accept(
            terminal_execution,
            "source-terminal-rollback",
            accepted,
            now,
        )
        .await
        .expect("commit acceptance before terminal rollback");
    let StatusLookup::Accepted(status) = store
        .lookup_status(status_lookup(&owner, OTHER_RESPONSE_REQUEST_ID, 152), now)
        .await
        .expect("load accepted terminal rollback")
    else {
        panic!("terminal rollback row must be accepted");
    };
    let RecoveryLease::Acquired(recovery) = store
        .acquire_status_recovery(&status, now, effect_deadline)
        .await
        .expect("lease terminal rollback row")
    else {
        panic!("terminal rollback checker must acquire the row");
    };
    let transaction = client
        .transaction()
        .await
        .expect("begin terminal journal transaction");
    store
        .finish_recovery_with_client(
            &transaction,
            recovery,
            TerminalOutcome::Completed,
            StoredResponse::new(
                200,
                b"application/json".to_vec(),
                br#"{"done":true}"#.to_vec(),
                OTHER_RESPONSE_REQUEST_ID,
            )
            .expect("the alternate terminal response is bounded"),
            now,
        )
        .await
        .expect("stage terminal custody");
    transaction
        .rollback()
        .await
        .expect("roll back terminal custody with journal");
    let row = client
        .query_one(
            "SELECT state, async_source_id, response_status \
             FROM adapter_idempotency_entries \
             WHERE response_request_id = $1",
            &[&OTHER_RESPONSE_REQUEST_ID],
        )
        .await
        .expect("inspect rolled-back terminal custody");
    assert_eq!(row.get::<_, String>(0), "accepted");
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some("source-terminal-rollback")
    );
    assert_eq!(row.get::<_, Option<i16>>(2), Some(202));

    let Claim::Execute(mut recovered_acceptance) = store
        .claim(
            request(
                &owner,
                "records-create.person",
                "recovered-accept-rollback",
                155,
            ),
            now,
        )
        .await
        .expect("claim recovered acceptance rollback")
    else {
        panic!("recovered acceptance rollback must execute");
    };
    store
        .mark_async_effect_attempted(
            &mut recovered_acceptance,
            request(
                &owner,
                "records-create.person",
                "recovered-accept-rollback",
                155,
            ),
            async_attempt(
                THIRD_RESPONSE_REQUEST_ID,
                Some(RECOVERY_ID),
                152,
                effect_deadline,
            ),
            now,
        )
        .await
        .expect("precommit recovered acceptance rollback correlation");
    let RecoveryLease::Acquired(recovery) = store
        .acquire_uncertain_recovery(
            request(
                &owner,
                "records-create.person",
                "recovered-accept-rollback",
                155,
            ),
            [152; 32],
            now,
            effect_deadline,
        )
        .await
        .expect("lease recovered acceptance rollback")
    else {
        panic!("recovered acceptance rollback must acquire the row");
    };
    let recovered_response = StoredResponse::new(
        202,
        b"application/json".to_vec(),
        br#"{"accepted":true}"#.to_vec(),
        THIRD_RESPONSE_REQUEST_ID,
    )
    .expect("the recovered acceptance response is bounded");
    let transaction = client
        .transaction()
        .await
        .expect("begin recovered acceptance journal transaction");
    store
        .accept_recovery_with_client(
            &transaction,
            recovery,
            "source-recovered-rollback",
            recovered_response,
            now,
        )
        .await
        .expect("stage recovered acceptance custody");
    transaction
        .rollback()
        .await
        .expect("roll back recovered acceptance with journal");
    let row = client
        .query_one(
            "SELECT state, async_source_id, response_status, async_poll_lease_id \
             FROM adapter_idempotency_entries WHERE response_request_id = $1",
            &[&THIRD_RESPONSE_REQUEST_ID],
        )
        .await
        .expect("inspect rolled-back recovered acceptance custody");
    assert_eq!(row.get::<_, String>(0), "effect_started");
    assert_eq!(row.get::<_, Option<String>>(1), None);
    assert_eq!(row.get::<_, Option<i16>>(2), None);
    assert!(row.get::<_, Option<Vec<u8>>>(3).is_some());
}

#[tokio::test]
async fn a_dropped_recovery_capability_stays_busy_until_its_lease_expires_then_recovers() {
    let isolated = isolated().await;
    let store = isolated.store(Duration::from_secs(30)).await;
    let owner = caller("cancelled-recovery-owner");
    let now = SystemTime::now();
    let effect_deadline = now
        .checked_add(Duration::from_secs(20))
        .expect("effect deadline is representable");
    let Claim::Execute(mut execution) = store
        .claim(
            request(&owner, "records-create.person", "cancelled-recovery", 161),
            now,
        )
        .await
        .expect("claim cancellation recovery")
    else {
        panic!("cancellation recovery must execute first");
    };
    store
        .mark_async_effect_attempted(
            &mut execution,
            request(&owner, "records-create.person", "cancelled-recovery", 161),
            async_attempt(RESPONSE_REQUEST_ID, Some(RECOVERY_ID), 162, effect_deadline),
            now,
        )
        .await
        .expect("precommit cancellation correlation");
    let first_lease_until = now
        .checked_add(Duration::from_secs(2))
        .expect("first lease deadline is representable");
    let RecoveryLease::Acquired(cancelled) = store
        .acquire_uncertain_recovery(
            request(&owner, "records-create.person", "cancelled-recovery", 161),
            [162; 32],
            now,
            first_lease_until,
        )
        .await
        .expect("acquire the cancelled lease")
    else {
        panic!("the first checker must acquire the uncertainty");
    };
    drop(cancelled);
    assert!(matches!(
        store
            .acquire_uncertain_recovery(
                request(&owner, "records-create.person", "cancelled-recovery", 161,),
                [162; 32],
                now,
                first_lease_until,
            )
            .await
            .expect("contend before cancelled lease expiry"),
        RecoveryLease::Busy
    ));

    let after_lease = now
        .checked_add(Duration::from_secs(3))
        .expect("post-lease time is representable");
    let second_lease_until = after_lease
        .checked_add(Duration::from_secs(2))
        .expect("second lease deadline is representable");
    let RecoveryLease::Acquired(recovered) = store
        .acquire_uncertain_recovery(
            request(&owner, "records-create.person", "cancelled-recovery", 161),
            [162; 32],
            after_lease,
            second_lease_until,
        )
        .await
        .expect("recover after cancelled lease expiry")
    else {
        panic!("the next checker must recover the expired lease");
    };
    store
        .release_recovery(recovered)
        .await
        .expect("release recovered uncertainty");
}
