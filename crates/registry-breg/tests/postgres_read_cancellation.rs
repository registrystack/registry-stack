// SPDX-License-Identifier: Apache-2.0

//! A read abandoned at the request deadline stops its PostgreSQL work.
//!
//! The request-timeout boundary drops a read's future when the deadline
//! passes. Every read service holds its pooled session under the shared
//! cancellation guard, so the dropped read cancels its in-flight statement
//! and gives up its session instead of leaving the backend running while the
//! pool opens a replacement. The pool bound therefore holds in
//! `pg_stat_activity`, and the abandoned read's audit attempt is answered
//! exactly once. A read that returns before its I/O cancels nothing and
//! hands its idle session back to the pool.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedRequestClaims,
};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordReadService, PostgresRevisionReadService, PostgresSnapshotReadService,
    ReadFaultPoint, RegistryLockKey, RegistryStateTestIdentity, RevisionReadFaultPoint,
    RuntimePool, SnapshotReadFaultPoint,
};
use registry_breg::startup::with_request_timeout_for_test;
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::ServiceExt;
use zeroize::Zeroizing;

const PACKAGE: &str = "read-cancellation-registry";
const PURPOSE: &str = "case-review";
const RECORD_ID: &str = "00000000-0000-4000-8000-0000000000c1";
/// The runtime pool's `maxSize`.
const POOL_SIZE: usize = 2;
/// Far below every slow statement the faults run: a record read sleeps 30
/// seconds, and a history read outruns its 2 second statement budget.
const REQUEST_DEADLINE: Duration = Duration::from_millis(300);
/// How long an abandoned statement may keep running after its request
/// answered 504. It is well inside the 2 second history statement budget, so
/// only a cancellation, never the budget, ends the statement in time.
const CANCELLATION_GRACE: Duration = Duration::from_millis(1_000);

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

struct Fixture {
    database: TestDatabase,
    slow: Router,
    pool: RuntimePool,
    runtime_role: String,
}

/// The five reads the slow router serves, by route name and URI.
fn read_routes() -> [(&'static str, String); 5] {
    [
        ("record get", format!("/v1/records/entries/{RECORD_ID}")),
        ("record list", "/v1/records/entries".to_owned()),
        (
            "access log",
            format!("/v1/records/entries/{RECORD_ID}/access-log"),
        ),
        (
            "revisions",
            format!("/v1/records/entries/{RECORD_ID}/revisions"),
        ),
        ("snapshot", "/v1/records/entries:snapshot".to_owned()),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_reads_cancel_their_statement_and_stay_within_the_pool_bound() {
    let fixture = fixture().await;
    for (route, uri) in read_routes() {
        let sampler = SessionSampler::start(&fixture).await;
        // More concurrent reads than sessions, twice over, so later reads
        // queue for sessions the earlier ones abandoned.
        for _ in 0..2 {
            let mut reads = tokio::task::JoinSet::new();
            for _ in 0..3 * POOL_SIZE {
                let (app, uri) = (fixture.slow.clone(), uri.clone());
                reads.spawn(async move { send(&app, &uri).await });
            }
            while let Some(status) = reads.join_next().await {
                assert_eq!(
                    status.expect("the read task completes"),
                    StatusCode::GATEWAY_TIMEOUT,
                    "a {route} read past its deadline answers request.timeout"
                );
            }
        }
        let still_running = abandoned_statements_after_grace(&fixture).await;
        let peak = sampler.stop().await;
        eprintln!("{route}: peak {peak} runtime sessions, {still_running} abandoned statements");
        assert_eq!(
            still_running, 0,
            "no runtime backend keeps executing an abandoned {route} statement after its \
             request answered 504"
        );
        assert!(
            peak <= POOL_SIZE as i64,
            "abandoned {route} reads opened {peak} runtime sessions, beyond the pool maxSize \
             of {POOL_SIZE}"
        );
    }
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timed_out_read_answers_its_accepted_attempt_exactly_once() {
    let fixture = fixture().await;
    for uri in [
        format!("/v1/records/entries/{RECORD_ID}"),
        format!("/v1/records/entries/{RECORD_ID}/access-log"),
        format!("/v1/records/entries/{RECORD_ID}/revisions"),
        "/v1/records/entries:snapshot".to_owned(),
    ] {
        assert_eq!(send(&fixture.slow, &uri).await, StatusCode::GATEWAY_TIMEOUT);
    }
    // The four attempts were accepted before the reads touched the database.
    // Each dropped attempt writes its unfinished answer off the request path,
    // so wait for all four before reading the journal.
    let records = settled_audit_records(&fixture.database, 8).await;
    let phases = records
        .iter()
        .map(|record| record["phase"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        phases.iter().filter(|phase| *phase == "attempt").count(),
        4,
        "every abandoned read recorded its pre-I/O attempt once: {records:#?}"
    );
    assert_eq!(
        phases.iter().filter(|phase| *phase == "unfinished").count(),
        4,
        "every abandoned read's attempt is answered unfinished once: {records:#?}"
    );
    assert!(
        !phases.iter().any(|phase| phase == "terminal"),
        "an abandoned read releases nothing, so it writes no terminal entry: {records:#?}"
    );
    for record in records
        .iter()
        .filter(|record| record["phase"] == "unfinished")
    {
        let request_id = &record["requestId"];
        assert_eq!(
            records
                .iter()
                .filter(|other| other["phase"] == "attempt" && other["requestId"] == *request_id)
                .count(),
            1,
            "the unfinished answer pairs with exactly one attempt of its request"
        );
    }
    fixture.database.assert_every_audit_request_answered_once();
    // The cancellation finished every read transaction, so a later read on
    // the same pool is not left behind an abandoned statement.
    assert_eq!(abandoned_statements_after_grace(&fixture).await, 0);
    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_refused_before_its_io_keeps_its_pooled_session() {
    let fixture = fixture().await;
    // Every read now fails its pre-I/O audit before it runs a statement, so
    // any session it already checked out is idle when the read returns.
    fixture.database.audit_capture().fail_after(0);
    let mut churned = Vec::new();
    for (route, uri) in read_routes() {
        let before = pooled_backends(&fixture.pool).await;
        for _ in 0..POOL_SIZE {
            assert_eq!(
                send(&fixture.slow, &uri).await,
                StatusCode::SERVICE_UNAVAILABLE,
                "a {route} read whose audit attempt is refused answers source.unavailable"
            );
        }
        if pooled_backends(&fixture.pool).await != before {
            churned.push(route);
        }
    }
    assert!(
        churned.is_empty(),
        "a read refused before its I/O hands its idle session back to the pool instead of \
         cancelling and discarding it, but these reads replaced pooled sessions: {churned:?}"
    );
    fixture.database.cleanup().await;
}

/// The backend process of every session the pool holds, checked out all at
/// once so each one is a distinct pooled session.
async fn pooled_backends(pool: &RuntimePool) -> BTreeSet<i32> {
    let mut sessions = Vec::with_capacity(POOL_SIZE);
    let mut backends = BTreeSet::new();
    for _ in 0..POOL_SIZE {
        let session = pool
            .get_for_test()
            .await
            .expect("the pool hands out a session");
        let backend: i32 = session
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .expect("the session answers")
            .get(0);
        backends.insert(backend);
        sessions.push(session);
    }
    assert_eq!(
        backends.len(),
        POOL_SIZE,
        "every pooled session is distinct"
    );
    backends
}

async fn fixture() -> Fixture {
    let database = TestDatabase::create(POOL_SIZE).await;
    let registry = Arc::new(compiled_registry());
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the compiled schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "read-cancellation-database",
            label: "read-cancellation-package-1",
        },
    )
    .await
    .expect("migration initializes the registry identity");
    drop(migration);
    task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE).expect("lock identity is bounded");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x4c; 32].into())
            .expect("the audit key is valid"),
    );
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x2e; 32]), Duration::from_secs(300))
            .expect("cursor key is valid"),
    );
    let records = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    )
    .with_fault_for_test(ReadFaultPoint::OutrunRequestDeadline);
    let revisions = PostgresRevisionReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
    )
    .with_fault_for_test(RevisionReadFaultPoint::HistoricalStatementTimeout);
    let snapshots = PostgresSnapshotReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
        cursors.clone(),
    )
    .with_fault_for_test(SnapshotReadFaultPoint::HistoricalStatementTimeout);
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id.clone(),
            schema_fingerprint: identity.schema_fingerprint.clone(),
        },
        Arc::new(records),
        Arc::new(AlwaysReady),
        cursors,
    )
    .with_postgres_revisions(Arc::new(revisions))
    .with_snapshots(Arc::new(snapshots));
    let slow = with_request_timeout_for_test(router(Arc::new(service)), REQUEST_DEADLINE);
    let runtime_role = database.runtime_role.as_str().to_owned();
    Fixture {
        database,
        slow,
        pool,
        runtime_role,
    }
}

/// Samples how many sessions the runtime role holds, as PostgreSQL itself
/// counts them, until stopped, and reports the largest count it saw.
struct SessionSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicI64>,
    task: tokio::task::JoinHandle<()>,
    admin_task: tokio::task::JoinHandle<()>,
}

impl SessionSampler {
    async fn start(fixture: &Fixture) -> Self {
        let (admin, admin_task) = fixture.database.connect_admin().await;
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicI64::new(0));
        let role = fixture.runtime_role.clone();
        let task = tokio::spawn({
            let stop = Arc::clone(&stop);
            let peak = Arc::clone(&peak);
            async move {
                while !stop.load(Ordering::Acquire) {
                    let sessions: i64 = admin
                        .query_one(
                            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
                            &[&role],
                        )
                        .await
                        .expect("the administrator reads pg_stat_activity")
                        .get(0);
                    peak.fetch_max(sessions, Ordering::AcqRel);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        });
        Self {
            stop,
            peak,
            task,
            admin_task,
        }
    }

    async fn stop(self) -> i64 {
        self.stop.store(true, Ordering::Release);
        self.task.await.expect("the session sampler ends cleanly");
        self.admin_task.abort();
        self.peak.load(Ordering::Acquire)
    }
}

/// The runtime backends still executing a fault's sleep once the grace
/// period after the last 504 has passed.
async fn abandoned_statements_after_grace(fixture: &Fixture) -> i64 {
    let (admin, admin_task) = fixture.database.connect_admin().await;
    let deadline = tokio::time::Instant::now() + CANCELLATION_GRACE;
    let running = loop {
        let running: i64 = admin
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                  WHERE usename = $1 AND state = 'active' AND query LIKE '%pg_sleep%'",
                &[&fixture.runtime_role],
            )
            .await
            .expect("the administrator reads pg_stat_activity")
            .get(0);
        if running == 0 || tokio::time::Instant::now() >= deadline {
            break running;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    admin_task.abort();
    running
}

/// The audit records once at least `expected` entries were accepted and no
/// further entry arrived for a moment.
async fn settled_audit_records(database: &TestDatabase, expected: usize) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let count = database.audit_entries().len();
        if count >= expected || tokio::time::Instant::now() >= deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
            return database.audit_records();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn send(app: &Router, uri: &str) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    request.extensions_mut().insert(claims());
    app.clone()
        .oneshot(request)
        .await
        .expect("router answers")
        .status()
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "sub",
        "reader-principal",
        BTreeSet::new(),
        Some(PURPOSE.to_owned()),
        BTreeMap::new(),
    )
    .expect("claims are verified")
}

fn compiled_registry() -> CompiledRegistry {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "entities":[{"id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"restricted",
            "fields":[{"id":"subject","type":"string","minLength":1,"maxLength":128,"required":true,"classification":"restricted"},
                {"id":"label","type":"string","maxLength":128,"required":true,"classification":"restricted"}],
            "accessLog":{"subjectField":"subject"}}],
        "accessProfiles":[
            {"id":"reader","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":[
                {"entity":"entry","operations":["get","list","snapshot","revisions"],"readableFields":["label"],
                    "revisionAccess":true,"rowBoundaries":"unrestricted"}]}
        ]
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).expect("project serializes"))
            .expect("project parses"),
        &[],
        CompileProfile::Authoring,
    )
    .expect("project compiles")
}
