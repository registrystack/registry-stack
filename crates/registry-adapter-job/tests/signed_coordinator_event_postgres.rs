// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "signed-coordinator-event"))]

//! A signed Coordinator event through the actual job pass and store.
//! The receiver uses the platform verifier, deliberately loses its first
//! admitted Run answer, then returns that same Run for the repeated event.

#[path = "support/job_fixture.rs"]
mod job_fixture;

use std::collections::BTreeMap;
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter_connectors::coordinator_event::{
    CoordinatorEventConnector, CoordinatorEventReceiver,
};
use registry_adapter_core::JobIdentity;
use registry_adapter_engine::job::compile_job;
use registry_adapter_engine::job_sources::JobRuntimeConfig;
use registry_adapter_job::destination::{DeliverableItem, HandOffOutcome, JobDestination};
use registry_adapter_job::pass::{run_pass, PassOptions, StopReason};
use registry_adapter_job::runtime_destination::activate_destination;
use registry_adapter_job::signed_coordinator_event::{
    SignedCoordinatorEventDestination, SignedCoordinatorEventReceiver,
};
use registry_adapter_job::store::{self, ItemStatus};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_hooks::receiver::{verify_delivery, DeliveryFreshness, SignedDelivery};
use registry_platform_hooks::{EnvelopeLimits, HookEnvelope};
use registry_platform_httputil::destination::{DestinationProfile, EventDestinationPolicy};
use serde_json::json;
use tokio_postgres::{Config as PgConfig, NoTls};

const KEY: &[u8] = &[0x5a; 32];
const TARGET: &str = "/v1/events/case-ingestion/submitted";
const SOURCE: &str = "urn:registrystack:adapter:synthetic";
const EVENT_TYPE: &str = "case.submitted";
const DATA_SCHEMA: &str = "urn:example:case-submitted:v1";

#[derive(Clone, Default)]
struct Receiver {
    runs: Arc<Mutex<BTreeMap<String, String>>>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn admit(
    State(receiver): State<Receiver>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let pairs = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect::<Vec<_>>();
    let verified = verify_delivery(
        SignedDelivery {
            method: "POST",
            request_target: TARGET,
            headers: pairs,
            body: &body,
            key: KEY,
        },
        DeliveryFreshness::CallerEnforced,
    )
    .expect("the job sent a valid platform signature");
    let envelope = HookEnvelope::from_canonical_bytes(&body, &EnvelopeLimits::default())
        .expect("the job sent a canonical hook envelope");
    assert_eq!(verified.id, envelope.id);
    assert_eq!(verified.source, envelope.source);
    assert_eq!(verified.event_type, envelope.event_type);
    assert_eq!(verified.data_schema, envelope.dataschema);
    assert_eq!(verified.idempotency_key, envelope.id);

    let mut runs = receiver.runs.lock().expect("the receiver run lock");
    let first = !runs.contains_key(&envelope.id);
    let run = runs
        .entry(envelope.id)
        .or_insert_with(|| uuid::Uuid::new_v4().to_string())
        .clone();
    drop(runs);
    receiver
        .bodies
        .lock()
        .expect("the receiver body lock")
        .push(body.to_vec());
    if first {
        // The admission committed, but its answer is lost.
        return StatusCode::NO_CONTENT.into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        "x-coordinator-run-id",
        HeaderValue::from_str(&run).expect("a Run UUID header"),
    );
    response
}

async fn isolated_store() -> Pool {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("adapter_job_event_{}", uuid::Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect the adapter job test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the adapter job test connection failed: {error}");
        }
    });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated adapter job schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let mut scoped = PgConfig::from_str(&url).expect("parse the scoped adapter job URL");
    scoped.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let manager = Manager::from_config(
        scoped,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        },
    );
    let pool = Pool::builder(manager)
        .max_size(2)
        .build()
        .expect("build the scoped adapter job pool");
    let client = pool.get().await.expect("a pooled client");
    store::migrate(&client)
        .await
        .expect("the job store migration applies");
    drop(client);
    pool
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_binding_activates_the_signed_destination_without_fallback() {
    const KEY_ENV: &str = "ADAPTER_JOB_SIGNED_DESTINATION_TEST_KEY";
    struct EnvironmentGuard;
    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            std::env::remove_var(KEY_ENV);
        }
    }

    let receiver = Receiver::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the signed receiver binds");
    let address = listener.local_addr().expect("the receiver address");
    let app = Router::new()
        .route(TARGET, post(admit))
        .with_state(receiver.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the signed receiver serves");
    });
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, json!({"data": [], "nextCursor": null}))],
        job_fixture::Edits::Ordered,
    )
    .await;
    let mut runtime: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.runtime).expect("the runtime reads"))
            .expect("the runtime is JSON");
    runtime["destinations"] = json!({
        "coordinator-test": {
            "type": "signed-coordinator-event",
            "baseUrl": format!("http://127.0.0.1:{}/", address.port()),
            "signingKeyRef": format!("secret:env/{KEY_ENV}"),
            "attemptTimeoutMilliseconds": 2000
        }
    });
    std::fs::write(
        &fixture.runtime,
        serde_json::to_vec_pretty(&runtime).expect("the runtime renders"),
    )
    .expect("the runtime writes");
    std::env::set_var(
        KEY_ENV,
        String::from_utf8(KEY.to_vec()).expect("an ASCII key"),
    );
    let _environment = EnvironmentGuard;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let runtime = JobRuntimeConfig::load(&fixture.runtime).expect("the runtime snapshot loads");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment secret resolver starts");
    let destination = activate_destination(&program, &runtime, &resolver)
        .await
        .expect("the configured signed destination activates");
    let item = DeliverableItem {
        key: "submissions/a".to_string(),
        sequence: 1,
        digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        prior_run_id: None,
        admitted_before: false,
        first_seen: std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        event_time: std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        delivery_attempt: 1,
        projected: json!({"answers.age": "045"}),
    };
    let job = JobIdentity {
        id: "case-daily".parse().expect("a job id"),
        version: "1".to_string(),
    };
    assert!(matches!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::StopPass { .. }
    ));
    assert!(matches!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::Acknowledged { .. }
    ));
    let bodies = receiver.bodies.lock().expect("the receiver body lock");
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1], "a retry preserves envelope bytes");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_signed_event_answer_recovers_one_run_through_the_job_store() {
    let receiver = Receiver::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the signed receiver binds");
    let address = listener.local_addr().expect("the receiver address");
    let app = Router::new()
        .route(TARGET, post(admit))
        .with_state(receiver.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the signed receiver serves");
    });
    let policy = Arc::new(
        EventDestinationPolicy::new(
            "adapter-coordinator-events",
            &format!("http://127.0.0.1:{}/", address.port()),
            DestinationProfile::LoopbackDevelopmentHttp,
            &[],
        )
        .expect("the loopback event policy freezes"),
    );
    let connector = Arc::new(
        CoordinatorEventConnector::new(policy, SOURCE, KEY.to_vec(), Duration::from_secs(2))
            .expect("the signed event connector freezes"),
    );
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(
            200,
            json!({
                "data": [{"id": "a", "answers": {"age": "045"}}],
                "nextCursor": "p2"
            }),
        )],
        job_fixture::Edits::Ordered,
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let event_receiver =
        CoordinatorEventReceiver::new("case-ingestion", "submitted", EVENT_TYPE, DATA_SCHEMA)
            .expect("the primary receiver freezes");
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(event_receiver, [0x11; 32]),
        None,
    );
    let pool = isolated_store().await;

    let first = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(
        first.stopped,
        Some(StopReason::DestinationStop {
            code: "coordinator.event.outcome-uncertain".to_string()
        })
    );
    let client = pool.get().await.expect("a pooled client");
    let pending = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the pending row reads")
        .expect("the pending row exists");
    assert_eq!(pending.status, ItemStatus::Pending);
    assert!(pending.run_id.is_none());
    drop(client);

    let second = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(second.stopped, None);
    assert_eq!(second.items_redelivered, 1);
    assert_eq!(second.items_acknowledged, 1);
    let client = pool.get().await.expect("a pooled client");
    let recovered = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the recovered row reads")
        .expect("the recovered row exists");
    assert_eq!(recovered.status, ItemStatus::Acknowledged);
    assert!(recovered
        .run_id
        .as_deref()
        .is_some_and(|run| uuid::Uuid::parse_str(run).is_ok()));
    let bodies = receiver.bodies.lock().expect("the receiver body lock");
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1], "the repeated event is byte-identical");
    assert_eq!(
        receiver.runs.lock().expect("the receiver run lock").len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_job_version_drift_stops_before_wire_and_restore_recovers() {
    let receiver = Receiver::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the signed receiver binds");
    let address = listener.local_addr().expect("the receiver address");
    let app = Router::new()
        .route(TARGET, post(admit))
        .with_state(receiver.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the signed receiver serves");
    });
    let connector = Arc::new(
        CoordinatorEventConnector::new(
            Arc::new(
                EventDestinationPolicy::new(
                    "adapter-coordinator-body-drift",
                    &format!("http://127.0.0.1:{}/", address.port()),
                    DestinationProfile::LoopbackDevelopmentHttp,
                    &[],
                )
                .expect("the event policy freezes"),
            ),
            SOURCE,
            KEY.to_vec(),
            Duration::from_secs(2),
        )
        .expect("the signed event connector freezes"),
    );
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(
            200,
            json!({
                "data": [{"id": "a", "answers": {"age": "045"}}],
                "nextCursor": "p2"
            }),
        )],
        job_fixture::Edits::Ordered,
    )
    .await;
    let mut program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new("case-ingestion", "submitted", EVENT_TYPE, DATA_SCHEMA)
                .expect("the primary receiver freezes"),
            [0x11; 32],
        ),
        None,
    );
    let pool = isolated_store().await;

    let first = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(
        first.stopped,
        Some(StopReason::DestinationStop {
            code: "coordinator.event.outcome-uncertain".to_string()
        })
    );
    assert_eq!(receiver.bodies.lock().expect("the body lock").len(), 1);

    let client = pool.get().await.expect("a pooled client");
    client
        .execute(
            "UPDATE adapter_job_items SET delivery_attempt = $3 \
             WHERE job_id = $1 AND item_key = $2",
            &[&"case-daily", &"submissions/a", &i64::MAX],
        )
        .await
        .expect("the boundary attempt installs");
    drop(client);
    let exhausted = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(
        exhausted.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.delivery-attempt-exhausted".to_string()
        })
    );
    assert_eq!(receiver.bodies.lock().expect("the body lock").len(), 1);
    let client = pool.get().await.expect("a pooled client");
    client
        .execute(
            "UPDATE adapter_job_items SET delivery_attempt = 1 \
             WHERE job_id = $1 AND item_key = $2",
            &[&"case-daily", &"submissions/a"],
        )
        .await
        .expect("the fixture restores the retryable attempt");
    drop(client);

    let original_version = program.job.job.version.clone();
    program.job.job.version = "2".to_string();
    let drifted = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(
        drifted.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator-receiver-changed".to_string()
        })
    );
    assert_eq!(
        receiver.bodies.lock().expect("the body lock").len(),
        1,
        "body drift is refused before a second recipient call"
    );

    program.job.job.version = original_version;
    let restored = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(restored.stopped, None);
    assert_eq!(restored.items_redelivered, 1);
    assert_eq!(restored.items_acknowledged, 1);
    let bodies = receiver.bodies.lock().expect("the body lock");
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(receiver.runs.lock().expect("the run lock").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_submicrosecond_event_time_keeps_identical_retry_bytes_after_store_roundtrip() {
    let receiver = Receiver::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the signed receiver binds");
    let address = listener.local_addr().expect("the receiver address");
    let app = Router::new()
        .route(TARGET, post(admit))
        .with_state(receiver.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the signed receiver serves");
    });
    let connector = Arc::new(
        CoordinatorEventConnector::new(
            Arc::new(
                EventDestinationPolicy::new(
                    "adapter-coordinator-submicrosecond",
                    &format!("http://127.0.0.1:{}/", address.port()),
                    DestinationProfile::LoopbackDevelopmentHttp,
                    &[],
                )
                .expect("the event policy freezes"),
            ),
            SOURCE,
            KEY.to_vec(),
            Duration::from_secs(2),
        )
        .expect("the signed event connector freezes"),
    );
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new("case-ingestion", "submitted", EVENT_TYPE, DATA_SCHEMA)
                .expect("the primary receiver freezes"),
            [0x11; 32],
        ),
        None,
    );
    let pool = isolated_store().await;
    let mut client = pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the job state exists");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    let digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let original_time = SystemTime::UNIX_EPOCH + Duration::new(1_767_225_600, 123_456_789);
    let first = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        digest,
        false,
        original_time,
        lease.token,
        ttl,
    )
    .await
    .expect("the first sequence stages")
    .expect("the first sequence delivers");
    let job = JobIdentity {
        id: "case-daily".parse().expect("a job id"),
        version: "1".to_string(),
    };
    let deliverable = |staged: &store::StagedItem| DeliverableItem {
        key: "submissions/a".to_string(),
        sequence: staged.sequence,
        digest: digest.to_string(),
        prior_run_id: staged.prior_run_id.clone(),
        admitted_before: staged.admitted_before,
        first_seen: staged.first_seen,
        event_time: staged.event_time,
        delivery_attempt: staged.delivery_attempt,
        projected: json!({"answers.age": "045"}),
    };
    let first_body_identity = destination
        .canonical_body_identity(&job, &deliverable(&first))
        .expect("the signed destination has a body identity")
        .expect("the first envelope is canonical");
    store::bind_delivery_identity(
        &mut client,
        "case-daily",
        "submissions/a",
        &[0x11; 32],
        &first_body_identity,
        first.delivery_attempt,
        false,
        lease.token,
        ttl,
    )
    .await
    .expect("the first delivery identity binds");
    assert_eq!(
        destination.deliver(&job, &deliverable(&first)).await,
        HandOffOutcome::StopPass {
            code: "coordinator.event.outcome-uncertain".to_string()
        }
    );

    let retry = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        digest,
        false,
        original_time + Duration::from_secs(5),
        lease.token,
        ttl,
    )
    .await
    .expect("the retry stages")
    .expect("the pending sequence redelivers");
    let retry_body_identity = destination
        .canonical_body_identity(&job, &deliverable(&retry))
        .expect("the signed destination has a body identity")
        .expect("the retry envelope is canonical");
    store::bind_delivery_identity(
        &mut client,
        "case-daily",
        "submissions/a",
        &[0x11; 32],
        &retry_body_identity,
        retry.delivery_attempt,
        false,
        lease.token,
        ttl,
    )
    .await
    .expect("the exact receiver identity recovers");
    assert_eq!(
        destination.deliver(&job, &deliverable(&retry)).await,
        HandOffOutcome::Acknowledged {
            run_id: receiver
                .runs
                .lock()
                .expect("the receiver run lock")
                .values()
                .next()
                .cloned()
        }
    );

    assert_eq!(first.event_time, original_time);
    assert_eq!(
        original_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the fixture time follows epoch")
            .subsec_nanos()
            % 1_000,
        789,
        "the first delivery carries an intentionally sub-microsecond fraction"
    );
    assert_ne!(retry.event_time, original_time);
    assert_eq!(
        retry
            .event_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the stored fixture time follows epoch")
            .subsec_nanos()
            % 1_000,
        0,
        "PostgreSQL returns its microsecond timestamp precision"
    );
    let bodies = receiver.bodies.lock().expect("the receiver body lock");
    assert_eq!(bodies.len(), 2);
    assert_eq!(
        bodies[0], bodies[1],
        "millisecond canonicalization preserves retry bytes across the store roundtrip"
    );
}

#[derive(Clone)]
struct Problems {
    answers: Arc<Mutex<Vec<(StatusCode, &'static str)>>>,
    requests: Arc<Mutex<u32>>,
}

async fn problem(State(problems): State<Problems>) -> impl IntoResponse {
    *problems.requests.lock().expect("the request count lock") += 1;
    let (status, code) = problems
        .answers
        .lock()
        .expect("the problem script lock")
        .remove(0);
    (
        status,
        [("content-type", "application/problem+json")],
        axum::Json(json!({"code": code, "status": status.as_u16()})),
    )
}

#[tokio::test]
async fn coordinator_item_and_deployment_failures_never_fall_back() {
    let problems = Problems {
        answers: Arc::new(Mutex::new(vec![
            (StatusCode::BAD_REQUEST, "event.invalid"),
            (StatusCode::UNAUTHORIZED, "event.unauthenticated"),
            (StatusCode::CONFLICT, "idempotency.key-reused"),
        ])),
        requests: Arc::new(Mutex::new(0)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the problem receiver binds");
    let address = listener.local_addr().expect("the problem receiver address");
    let app = Router::new()
        .route(TARGET, post(problem))
        .with_state(problems.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the problem receiver serves");
    });
    let connector = Arc::new(
        CoordinatorEventConnector::new(
            Arc::new(
                EventDestinationPolicy::new(
                    "adapter-coordinator-problems",
                    &format!("http://127.0.0.1:{}/", address.port()),
                    DestinationProfile::LoopbackDevelopmentHttp,
                    &[],
                )
                .expect("the problem event policy freezes"),
            ),
            SOURCE,
            KEY.to_vec(),
            Duration::from_secs(2),
        )
        .expect("the problem connector freezes"),
    );
    let event_receiver =
        CoordinatorEventReceiver::new("case-ingestion", "submitted", EVENT_TYPE, DATA_SCHEMA)
            .expect("the primary receiver freezes");
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(event_receiver, [0x11; 32]),
        None,
    );
    let job = JobIdentity {
        id: "case-daily".parse().expect("a job id"),
        version: "1".to_string(),
    };
    let item = DeliverableItem {
        key: "submissions/a".to_string(),
        sequence: 1,
        digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        prior_run_id: None,
        admitted_before: false,
        first_seen: std::time::SystemTime::UNIX_EPOCH,
        event_time: std::time::SystemTime::UNIX_EPOCH,
        delivery_attempt: 1,
        projected: json!({"answers.age": "045"}),
    };
    assert_eq!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::Refused {
            code: "event.invalid".to_string()
        }
    );
    assert_eq!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::StopPass {
            code: "event.unauthenticated".to_string()
        }
    );
    assert_eq!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::StopPass {
            code: "idempotency.key-reused".to_string()
        }
    );
    assert_eq!(
        *problems.requests.lock().expect("the request count lock"),
        3,
        "each answer ends that item attempt without a fallback mutation"
    );
}
