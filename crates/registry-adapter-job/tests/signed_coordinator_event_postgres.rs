// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "signed-coordinator-event"))]

//! A signed Coordinator event through the actual job pass and store.
//! The receiver uses the platform verifier, deliberately loses its first
//! admitted Run answer, then returns that same Run for the repeated event.

#[path = "support/job_fixture.rs"]
mod job_fixture;

use std::collections::{BTreeMap, VecDeque};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter_connectors::coordinator_event::{
    CoordinatorEventConnector, CoordinatorEventReceiver,
};
use registry_adapter_core::JobIdentity;
use registry_adapter_engine::job::{compile_job, JobProgram};
use registry_adapter_engine::job_sources::JobRuntimeConfig;
use registry_adapter_job::destination::{DeliverableItem, HandOffOutcome, JobDestination};
use registry_adapter_job::pass::{run_pass, PassOptions, PassReport, StopReason};
use registry_adapter_job::runtime_destination::activate_destination;
use registry_adapter_job::signed_coordinator_event::{
    receiver_identity, CoordinatorReceiverDigestContext, SignedCoordinatorEventDestination,
    SignedCoordinatorEventReceiver,
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
            code: "adapter.job.coordinator.event.outcome-uncertain".to_string()
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
            code: "adapter.job.coordinator.event.outcome-uncertain".to_string()
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
            code: "adapter.job.coordinator-body-changed".to_string()
        }),
        "body drift has its own code, not the receiver's"
    );
    let client = pool.get().await.expect("a pooled client");
    let counts = registry_adapter_job::store::item_counts(&client, "case-daily")
        .await
        .expect("status counts read");
    assert_eq!(
        counts.pending_keys,
        vec!["submissions/a".to_string()],
        "status names the stuck pending key"
    );
    drop(client);
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
        .delivery_identity(&job, &deliverable(&first))
        .expect("the signed destination has a delivery identity")
        .canonical_body
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
            code: "adapter.job.coordinator.event.outcome-uncertain".to_string()
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
        .delivery_identity(&job, &deliverable(&retry))
        .expect("the signed destination has a delivery identity")
        .canonical_body
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

    assert_eq!(
        original_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the fixture time follows epoch")
            .subsec_nanos()
            % 1_000,
        789,
        "the staged clock reading carries an intentionally sub-microsecond fraction"
    );
    assert_eq!(
        first.event_time,
        SystemTime::UNIX_EPOCH + Duration::new(1_767_225_600, 123_456_000),
        "the first hand-off carries the microsecond time PostgreSQL stores"
    );
    assert_eq!(
        retry.event_time, first.event_time,
        "the redelivery read back from the row carries the first hand-off's time"
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
            code: "adapter.job.coordinator.event.invalid".to_string()
        }
    );
    assert_eq!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::StopPass {
            code: "adapter.job.coordinator.event.unauthenticated".to_string()
        }
    );
    assert_eq!(
        destination.deliver(&job, &item).await,
        HandOffOutcome::StopPass {
            code: "adapter.job.coordinator.idempotency.key-reused".to_string()
        }
    );
    assert_eq!(
        *problems.requests.lock().expect("the request count lock"),
        3,
        "each answer ends that item attempt without a fallback mutation"
    );
}

const REVISED_TARGET: &str = "/v1/events/case-ingestion/revised";

/// One scripted Coordinator answer per signed event.
#[derive(Clone, Copy)]
enum Answer {
    /// The admission committed, but its answer carries no Run.
    Lost,
    /// A Coordinator problem answer.
    Problem(StatusCode, &'static str),
    /// An admitted Run.
    Admitted,
}

/// A Coordinator receiver on both triggers: it verifies each signed event
/// against the path it arrived on, records that path, and answers from
/// its script.
#[derive(Clone)]
struct ScriptedReceiver {
    answers: Arc<Mutex<VecDeque<Answer>>>,
    targets: Arc<Mutex<Vec<String>>>,
}

impl ScriptedReceiver {
    fn targets(&self) -> Vec<String> {
        self.targets.lock().expect("the target lock").clone()
    }
}

async fn scripted(
    State(receiver): State<ScriptedReceiver>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let pairs = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect::<Vec<_>>();
    verify_delivery(
        SignedDelivery {
            method: "POST",
            request_target: uri.path(),
            headers: pairs,
            body: &body,
            key: KEY,
        },
        DeliveryFreshness::CallerEnforced,
    )
    .expect("the job sent a valid platform signature");
    receiver
        .targets
        .lock()
        .expect("the target lock")
        .push(uri.path().to_string());
    let answer = receiver
        .answers
        .lock()
        .expect("the answer lock")
        .pop_front()
        .expect("every signed event has a scripted answer");
    match answer {
        Answer::Lost => StatusCode::NO_CONTENT.into_response(),
        Answer::Problem(status, code) => (
            status,
            [("content-type", "application/problem+json")],
            axum::Json(json!({"code": code, "status": status.as_u16()})),
        )
            .into_response(),
        Answer::Admitted => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                "x-coordinator-run-id",
                HeaderValue::from_str(&uuid::Uuid::new_v4().to_string())
                    .expect("a Run UUID header"),
            );
            response
        }
    }
}

/// A signed Coordinator destination over a receiver that answers from
/// `answers`, on a job with or without a revised trigger.
async fn scripted_destination(
    revised_trigger: bool,
    answers: impl IntoIterator<Item = Answer>,
) -> (ScriptedReceiver, SignedCoordinatorEventDestination) {
    let receiver = ScriptedReceiver {
        answers: Arc::new(Mutex::new(answers.into_iter().collect())),
        targets: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the scripted receiver binds");
    let address = listener.local_addr().expect("the receiver address");
    let app = Router::new()
        .route(TARGET, post(scripted))
        .route(REVISED_TARGET, post(scripted))
        .with_state(receiver.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the scripted receiver serves");
    });
    let connector = Arc::new(
        CoordinatorEventConnector::new(
            Arc::new(
                EventDestinationPolicy::new(
                    "adapter-coordinator-refused-retry",
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
    let revised = revised_trigger.then(|| {
        SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new("case-ingestion", "revised", "case.revised", DATA_SCHEMA)
                .expect("the revised receiver freezes"),
            [0x22; 32],
        )
    });
    let destination = SignedCoordinatorEventDestination::new(
        connector,
        SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new("case-ingestion", "submitted", EVENT_TYPE, DATA_SCHEMA)
                .expect("the primary receiver freezes"),
            [0x11; 32],
        ),
        revised,
    );
    (receiver, destination)
}

/// Lose the first event's answer, then refuse its retry, through two
/// real passes: the row ends refused after two events on the primary
/// trigger.
async fn lose_then_refuse(
    pool: &Pool,
    program: &JobProgram,
    destination: &SignedCoordinatorEventDestination,
    receiver: &ScriptedReceiver,
) {
    let lost = run_pass(pool, program, destination, PassOptions::default()).await;
    assert_eq!(
        lost.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator.event.outcome-uncertain".to_string()
        })
    );
    let retried = run_pass(pool, program, destination, PassOptions::default()).await;
    assert_eq!(retried.stopped, None);
    assert_eq!(retried.items_redelivered, 1);
    assert_eq!(retried.items_refused, 1);
    let client = pool.get().await.expect("a pooled client");
    let refused = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the refused row reads")
        .expect("the refused row exists");
    assert_eq!(refused.status, ItemStatus::Refused);
    assert_eq!(receiver.targets(), vec![TARGET.to_string(); 2]);
}

/// The refused retry of a lost event, scripted: the lost answer, the
/// refusal, then one admission for whatever the caller does next, so a
/// second admission fails the caller's assertions rather than the script.
fn lost_then_refused() -> [Answer; 3] {
    [
        Answer::Lost,
        Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
        Answer::Admitted,
    ]
}

/// Lose the first event's answer, refuse its retry, then edit the source
/// item, through real passes over a job with or without a revised
/// trigger. Returns the edited row and every path the receiver saw.
async fn edit_after_a_refused_retry_of_a_lost_event(
    revised_trigger: bool,
) -> (store::ItemRecord, Vec<String>) {
    let (receiver, destination) = scripted_destination(revised_trigger, lost_then_refused()).await;
    let page = |age: &str| {
        json!({
            "data": [{"id": "a", "answers": {"age": age}}],
            "nextCursor": "p2"
        })
    };
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, page("045")), (200, page("045")), (200, page("046"))],
        job_fixture::Edits::Ordered,
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    lose_then_refuse(&pool, &program, &destination, &receiver).await;

    let edit = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(edit.stopped, None);
    assert_eq!(edit.items_changed, 1);
    let client = pool.get().await.expect("a pooled client");
    let edited = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the edited row reads")
        .expect("the edited row exists");
    (edited, receiver.targets())
}

/// A refusal that answers the retry of a lost event says nothing about
/// whether Coordinator admitted the first one, so without a revised
/// trigger a later source edit is held for an operator and never sent to
/// the primary trigger as a second submission.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_retry_of_a_lost_event_holds_a_later_edit_without_a_revised_trigger() {
    let (edited, targets) = edit_after_a_refused_retry_of_a_lost_event(false).await;
    assert_eq!(
        targets.len(),
        2,
        "the edit of a possibly admitted item sends no event"
    );
    assert_eq!(edited.status, ItemStatus::Held);
    assert_eq!(edited.code.as_deref(), Some("adapter.job.revised-item"));
    assert!(edited.admitted_before);
}

/// With a revised trigger, the same edit is a revision by design: it goes
/// to the revised trigger, never to the primary one.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_retry_of_a_lost_event_sends_a_later_edit_to_the_revised_trigger() {
    let (edited, targets) = edit_after_a_refused_retry_of_a_lost_event(true).await;
    assert_eq!(
        targets,
        vec![
            TARGET.to_string(),
            TARGET.to_string(),
            REVISED_TARGET.to_string()
        ],
        "the edit of a possibly admitted item is a revision"
    );
    assert_eq!(edited.status, ItemStatus::Acknowledged);
    assert!(edited.admitted_before);
}

/// Lose the first event's answer, refuse its retry, then rescan the
/// unchanged source item and run one ordinary pass after the rescan,
/// over a job with or without a revised trigger. Returns both reports,
/// the row as the rescan left it, and every path the receiver saw.
async fn rescan_after_a_refused_retry_of_a_lost_event(
    revised_trigger: bool,
) -> (PassReport, PassReport, store::ItemRecord, Vec<String>) {
    let (receiver, destination) = scripted_destination(revised_trigger, lost_then_refused()).await;
    let page = json!({
        "data": [{"id": "a", "answers": {"age": "045"}}],
        "nextCursor": "p2"
    });
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, page); 4],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    lose_then_refuse(&pool, &program, &destination, &receiver).await;

    let rescan = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    let client = pool.get().await.expect("a pooled client");
    let rescanned = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the rescanned row reads")
        .expect("the rescanned row exists");
    drop(client);
    let after = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    (rescan, after, rescanned, receiver.targets())
}

/// A rescan retries a refused item under its unchanged digest, but a
/// refusal that answers the retry of a lost event says nothing about
/// whether Coordinator admitted the first one. Without a revised trigger
/// the rescan holds the item for an operator, sends nothing to the
/// primary trigger, and leaves the job's later passes running.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescan_of_a_refused_retry_of_a_lost_event_holds_it_without_a_revised_trigger() {
    let (rescan, after, rescanned, targets) =
        rescan_after_a_refused_retry_of_a_lost_event(false).await;
    assert_eq!(
        (rescan.stopped, rescanned.status, rescanned.code.as_deref()),
        (None, ItemStatus::Held, Some("adapter.job.revised-item")),
        "the rescan holds the possibly admitted item instead of stopping the pass"
    );
    assert_eq!(rescan.items_held, 1);
    assert!(rescanned.admitted_before);
    assert_eq!(after.stopped, None, "the next ordinary pass runs");
    assert_eq!(after.items_redelivered, 0);
    assert_eq!(
        targets,
        vec![TARGET.to_string(); 2],
        "the rescan sends no event to the primary trigger"
    );
}

/// With a revised trigger, the same rescan is a revision by design: it
/// goes to the revised trigger, never to the primary one.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescan_of_a_refused_retry_of_a_lost_event_sends_it_to_the_revised_trigger() {
    let (rescan, after, rescanned, targets) =
        rescan_after_a_refused_retry_of_a_lost_event(true).await;
    assert_eq!(rescan.stopped, None);
    assert_eq!(rescanned.status, ItemStatus::Acknowledged);
    assert!(rescanned.admitted_before);
    assert_eq!(after.stopped, None);
    assert_eq!(after.items_redelivered, 0);
    assert_eq!(
        targets,
        vec![
            TARGET.to_string(),
            TARGET.to_string(),
            REVISED_TARGET.to_string()
        ],
        "the rescan of a possibly admitted item is a revision"
    );
}

/// Stage a rescan of the refused, possibly admitted item through the store,
/// then let the lease lapse before anything is sent or recorded: a host
/// killed between staging and its answer. The row is left `pending` with
/// nothing sent since it was staged.
async fn stage_a_rescan_then_die(pool: &Pool) {
    let mut client = pool.get().await.expect("a pooled client");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    let refused = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the refused row reads")
        .expect("the refused row exists");
    assert_eq!(refused.status, ItemStatus::Refused);
    assert!(
        refused.admitted_before,
        "the refused retry of a lost event marks the item"
    );
    let staged = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        &refused.last_digest,
        true,
        SystemTime::now(),
        lease.token,
        ttl,
    )
    .await
    .expect("the rescan stages")
    .expect("the rescan retries the refused item");
    assert!(staged.admitted_before);
    client
        .execute(
            "UPDATE adapter_job_state SET lease_expires = now() - interval '1 second' \
             WHERE job_id = $1",
            &[&"case-daily"],
        )
        .await
        .expect("the lease lapses");
}

/// A host that dies after staging the rescan of a refused, possibly
/// admitted item leaves the row `pending`. Without a revised trigger the
/// next pass holds the item, as the rescan would have, and the job's later
/// items keep moving.
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_after_staging_a_rescan_holds_the_item_and_later_items_move() {
    let (receiver, destination) = scripted_destination(false, lost_then_refused()).await;
    let page_a = json!({
        "data": [{"id": "a", "answers": {"age": "045"}}],
        "nextCursor": "p2"
    });
    let page_ab = json!({
        "data": [
            {"id": "a", "answers": {"age": "045"}},
            {"id": "b", "answers": {"age": "050"}}
        ],
        "nextCursor": "p2"
    });
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, page_a.clone()), (200, page_a), (200, page_ab)],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    lose_then_refuse(&pool, &program, &destination, &receiver).await;
    stage_a_rescan_then_die(&pool).await;

    let after = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    let client = pool.get().await.expect("a pooled client");
    let held = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the held row reads")
        .expect("the held row exists");
    assert_eq!(
        (after.stopped, held.status, held.code.as_deref()),
        (None, ItemStatus::Held, Some("adapter.job.revised-item")),
        "the item the crash left pending is held, and the job does not stop"
    );
    assert!(held.admitted_before);
    assert_eq!(after.items_held, 1);
    let later = store::inspect_item(&client, "case-daily", "submissions/b")
        .await
        .expect("the later row reads")
        .expect("the later row exists");
    assert_eq!(later.status, ItemStatus::Acknowledged, "a later item moves");
    assert_eq!(
        receiver.targets(),
        vec![TARGET.to_string(); 3],
        "the held item sends nothing; only the later item reaches the primary trigger"
    );
}

/// The same crash, then a revised trigger added to the job: the next pass
/// sends the possibly admitted item to the revised trigger. The rescan that
/// died sent nothing, so its staged row keeps no receiver to fence against.
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_after_staging_a_rescan_sends_the_item_to_a_revised_trigger_added_later() {
    let (receiver, destination) = scripted_destination(
        false,
        [
            Answer::Lost,
            Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
        ],
    )
    .await;
    let page = json!({
        "data": [{"id": "a", "answers": {"age": "045"}}],
        "nextCursor": "p2"
    });
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, page); 3],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    lose_then_refuse(&pool, &program, &destination, &receiver).await;
    stage_a_rescan_then_die(&pool).await;

    let (revised_receiver, with_revised) = scripted_destination(true, [Answer::Admitted]).await;
    let after = run_pass(&pool, &program, &with_revised, PassOptions::default()).await;
    assert_eq!(
        after.stopped, None,
        "the rescan that died froze no receiver for this attempt"
    );
    let client = pool.get().await.expect("a pooled client");
    let revised = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the revised row reads")
        .expect("the revised row exists");
    assert_eq!(revised.status, ItemStatus::Acknowledged);
    assert!(revised.admitted_before);
    assert_eq!(
        receiver.targets(),
        vec![TARGET.to_string(); 2],
        "the primary trigger sees no third event"
    );
    assert_eq!(
        revised_receiver.targets(),
        vec![REVISED_TARGET.to_string()],
        "the possibly admitted item goes to the revised trigger once"
    );
}

/// A revised event whose answer is lost, then `destination.revisedReceiver`
/// removed: the destination has no receiver to repeat that event to, so the
/// item is held and the job does not stop. Restoring the trigger does not
/// resend it; the row stays held for an operator to settle under
/// Coordinator's own authority.
#[tokio::test(flavor = "multi_thread")]
async fn removing_then_restoring_a_revised_trigger_with_an_answer_outstanding_holds_the_item() {
    let (revised_receiver, with_revised) = scripted_destination(
        true,
        [
            Answer::Lost,
            Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
            Answer::Lost,
            Answer::Admitted,
        ],
    )
    .await;
    let (primary_receiver, without_revised) = scripted_destination(false, [Answer::Admitted]).await;
    let page = json!({
        "data": [{"id": "a", "answers": {"age": "045"}}],
        "nextCursor": "p2"
    });
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, page); 5],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    lose_then_refuse(&pool, &program, &with_revised, &revised_receiver).await;

    let rescan = run_pass(
        &pool,
        &program,
        &with_revised,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(
        rescan.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator.event.outcome-uncertain".to_string()
        }),
        "the revised event's answer is lost"
    );
    let sent = vec![
        TARGET.to_string(),
        TARGET.to_string(),
        REVISED_TARGET.to_string(),
    ];
    assert_eq!(revised_receiver.targets(), sent);

    let removed = run_pass(&pool, &program, &without_revised, PassOptions::default()).await;
    let client = pool.get().await.expect("a pooled client");
    let held = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the held row reads")
        .expect("the held row exists");
    drop(client);
    assert_eq!(
        (removed.stopped, held.status, held.code.as_deref()),
        (None, ItemStatus::Held, Some("adapter.job.revised-item")),
        "without the revised trigger the outstanding revision is held, and the job does not stop"
    );
    assert_eq!(removed.items_held, 1);
    assert!(
        primary_receiver.targets().is_empty(),
        "the possibly admitted item never reaches the primary trigger"
    );

    let restored = run_pass(&pool, &program, &with_revised, PassOptions::default()).await;
    assert_eq!(restored.stopped, None);
    assert_eq!(
        restored.items_redelivered, 0,
        "restoring the trigger does not resend a held item"
    );
    assert_eq!(revised_receiver.targets(), sent);
    let client = pool.get().await.expect("a pooled client");
    let still = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the held row reads")
        .expect("the held row exists");
    assert_eq!(still.status, ItemStatus::Held);
}

const REVISED_TYPE: &str = "case.revised";
const REVISION_BINDING: &str = "adapter-coordinator-revision";

/// One Coordinator deployment's admissions, keyed the way Coordinator keys
/// an event trigger admission: event source, event id and trigger name. A
/// repeated key answers with the Run its first admission started.
type Admissions = Arc<Mutex<BTreeMap<(String, String, String), String>>>;

/// A Coordinator receiver on the primary and every revised trigger of the
/// `case-ingestion` workflow. It verifies each signed event against the
/// path it arrived on, records the trigger and event id, admits the event
/// into its deployment's [`Admissions`] unless the scripted answer is a
/// problem, and answers from its script.
#[derive(Clone)]
struct AdmittingReceiver {
    admissions: Admissions,
    answers: Arc<Mutex<VecDeque<Answer>>>,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

impl AdmittingReceiver {
    /// Every trigger and event id this receiver was sent, in order.
    fn requests(&self) -> Vec<(String, String)> {
        self.requests.lock().expect("the request lock").clone()
    }

    /// The Runs this receiver's deployment admitted for `event_id`, on any
    /// trigger.
    fn runs_for(&self, event_id: &str) -> Vec<String> {
        self.admissions
            .lock()
            .expect("the admission lock")
            .iter()
            .filter(|((_, id, _), _)| id == event_id)
            .map(|(_, run)| run.clone())
            .collect()
    }
}

async fn admitting(
    State(receiver): State<AdmittingReceiver>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let pairs = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect::<Vec<_>>();
    verify_delivery(
        SignedDelivery {
            method: "POST",
            request_target: uri.path(),
            headers: pairs,
            body: &body,
            key: KEY,
        },
        DeliveryFreshness::CallerEnforced,
    )
    .expect("the job sent a valid platform signature");
    let envelope = HookEnvelope::from_canonical_bytes(&body, &EnvelopeLimits::default())
        .expect("the job sent a canonical hook envelope");
    let trigger = uri
        .path()
        .rsplit('/')
        .next()
        .expect("the path names a trigger")
        .to_string();
    receiver
        .requests
        .lock()
        .expect("the request lock")
        .push((trigger.clone(), envelope.id.clone()));
    let answer = receiver
        .answers
        .lock()
        .expect("the answer lock")
        .pop_front()
        .expect("every signed event has a scripted answer");
    let admit = || {
        receiver
            .admissions
            .lock()
            .expect("the admission lock")
            .entry((
                envelope.source.clone(),
                envelope.id.clone(),
                trigger.clone(),
            ))
            .or_insert_with(|| uuid::Uuid::new_v4().to_string())
            .clone()
    };
    match answer {
        Answer::Problem(status, code) => (
            status,
            [("content-type", "application/problem+json")],
            axum::Json(json!({"code": code, "status": status.as_u16()})),
        )
            .into_response(),
        Answer::Lost => {
            admit();
            StatusCode::NO_CONTENT.into_response()
        }
        Answer::Admitted => {
            let run = admit();
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                "x-coordinator-run-id",
                HeaderValue::from_str(&run).expect("a Run UUID header"),
            );
            response
        }
    }
}

/// Start an [`AdmittingReceiver`] on its own loopback address over the
/// deployment `admissions`. Returns the receiver and its base URL.
async fn start_admitting_receiver(
    admissions: &Admissions,
    answers: impl IntoIterator<Item = Answer>,
) -> (AdmittingReceiver, String) {
    let receiver = AdmittingReceiver {
        admissions: Arc::clone(admissions),
        answers: Arc::new(Mutex::new(answers.into_iter().collect())),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the admitting receiver binds");
    let address = listener.local_addr().expect("the receiver address");
    let app = Router::new()
        .route("/v1/events/case-ingestion/{trigger}", post(admitting))
        .with_state(receiver.clone());
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the admitting receiver serves");
    });
    (receiver, format!("http://127.0.0.1:{}/", address.port()))
}

/// A signed Coordinator destination at `base_url` whose revised receiver is
/// the trigger `revised`. Each receiver carries the identity the runtime
/// derives from its binding, authority and trigger contract.
fn revision_destination(base_url: &str, revised: &str) -> SignedCoordinatorEventDestination {
    let receiver = |trigger: &str, event_type: &str| {
        SignedCoordinatorEventReceiver::new(
            CoordinatorEventReceiver::new("case-ingestion", trigger, event_type, DATA_SCHEMA)
                .expect("the receiver freezes"),
            receiver_identity(&CoordinatorReceiverDigestContext {
                binding: REVISION_BINDING,
                base_url,
                tls_trust_profile: None,
                workflow: "case-ingestion",
                trigger,
                source: SOURCE,
                event_type,
                data_schema: DATA_SCHEMA,
            }),
        )
    };
    let connector = Arc::new(
        CoordinatorEventConnector::new(
            Arc::new(
                EventDestinationPolicy::new(
                    REVISION_BINDING,
                    base_url,
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
    SignedCoordinatorEventDestination::new(
        connector,
        receiver("submitted", EVENT_TYPE),
        Some(receiver(revised, REVISED_TYPE)),
    )
}

/// A job whose item `submissions/a` is registered on the first pass and
/// edited on every later one.
async fn registered_then_edited() -> job_fixture::JobFixture {
    let page = |age: &str| {
        (
            200,
            json!({
                "data": [{"id": "a", "answers": {"age": age}}],
                "nextCursor": "p2"
            }),
        )
    };
    let mut replies = vec![page("045")];
    replies.extend(std::iter::repeat_n(page("046"), 6));
    job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        replies,
        job_fixture::Edits::Rescan(3600),
    )
    .await
}

/// Register the item, edit it, lose the revised event's answer, then
/// refuse that event's retry, through real passes over `destination`.
/// Returns the revised event's id, which Coordinator admitted once.
async fn lose_then_refuse_a_revision(
    pool: &Pool,
    program: &JobProgram,
    destination: &SignedCoordinatorEventDestination,
    receiver: &AdmittingReceiver,
) -> String {
    let registered = run_pass(pool, program, destination, PassOptions::default()).await;
    assert_eq!(registered.stopped, None);
    assert_eq!(registered.items_acknowledged, 1);
    let lost = run_pass(pool, program, destination, PassOptions::default()).await;
    assert_eq!(
        lost.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator.event.outcome-uncertain".to_string()
        })
    );
    let retried = run_pass(pool, program, destination, PassOptions::default()).await;
    assert_eq!(retried.stopped, None);
    assert_eq!(retried.items_redelivered, 1);
    assert_eq!(retried.items_refused, 1);
    let client = pool.get().await.expect("a pooled client");
    let refused = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the refused row reads")
        .expect("the refused row exists");
    assert_eq!(refused.status, ItemStatus::Refused);
    assert!(refused.admitted_before);
    let requests = receiver.requests();
    let triggers = requests
        .iter()
        .map(|(trigger, _)| trigger.as_str())
        .collect::<Vec<_>>();
    assert_eq!(triggers, vec!["submitted", "revised", "revised"]);
    let revision = requests[1].1.clone();
    assert_eq!(
        requests[2].1, revision,
        "the retry repeats the revised event"
    );
    assert_eq!(
        receiver.runs_for(&revision).len(),
        1,
        "the revised event whose answer was lost was admitted"
    );
    revision
}

fn rescan() -> PassOptions {
    PassOptions {
        rescan: true,
        ..PassOptions::default()
    }
}

/// A revised event that may have been admitted fixes the receiver its
/// sequence can reach: after its retry is refused, a rescan under a
/// changed revised trigger stops before anything is sent, so Coordinator
/// never admits the same revision under a second trigger. Restoring the
/// revised trigger lets the item settle on the Run already admitted.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescan_after_a_refused_retry_of_a_lost_revision_never_sends_it_to_a_changed_revised_trigger(
) {
    let admissions = Admissions::default();
    let (receiver, base_url) = start_admitting_receiver(
        &admissions,
        [
            Answer::Admitted,
            Answer::Lost,
            Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
            Answer::Admitted,
        ],
    )
    .await;
    let revised = revision_destination(&base_url, "revised");
    let amended = revision_destination(&base_url, "amended");
    let fixture = registered_then_edited().await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    let revision = lose_then_refuse_a_revision(&pool, &program, &revised, &receiver).await;
    let admitted = receiver.runs_for(&revision);

    let changed = run_pass(&pool, &program, &amended, rescan()).await;
    assert_eq!(
        receiver.runs_for(&revision),
        admitted,
        "Coordinator admits the revision once"
    );
    assert_eq!(
        receiver.requests().len(),
        3,
        "nothing reaches the changed revised trigger"
    );
    assert_eq!(
        changed.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator-receiver-changed".to_string()
        })
    );

    let restored = run_pass(&pool, &program, &revised, PassOptions::default()).await;
    assert_eq!(restored.stopped, None);
    assert_eq!(restored.items_redelivered, 1);
    assert_eq!(restored.items_acknowledged, 1);
    assert_eq!(receiver.runs_for(&revision), admitted);
    let client = pool.get().await.expect("a pooled client");
    let settled = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the settled row reads")
        .expect("the settled row exists");
    assert_eq!(settled.status, ItemStatus::Acknowledged);
    assert_eq!(settled.run_id.as_ref(), admitted.first());
}

/// The same fix holds for the Coordinator authority: after the refused
/// retry of a lost revision, a rescan under a destination at another base
/// URL stops before anything reaches it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescan_after_a_refused_retry_of_a_lost_revision_never_sends_it_to_a_changed_authority() {
    let (receiver, base_url) = start_admitting_receiver(
        &Admissions::default(),
        [
            Answer::Admitted,
            Answer::Lost,
            Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
        ],
    )
    .await;
    let (moved, moved_url) =
        start_admitting_receiver(&Admissions::default(), [Answer::Admitted]).await;
    let fixture = registered_then_edited().await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    lose_then_refuse_a_revision(
        &pool,
        &program,
        &revision_destination(&base_url, "revised"),
        &receiver,
    )
    .await;

    let changed = run_pass(
        &pool,
        &program,
        &revision_destination(&moved_url, "revised"),
        rescan(),
    )
    .await;
    assert!(
        moved.requests().is_empty(),
        "nothing reaches the other Coordinator authority"
    );
    assert_eq!(receiver.requests().len(), 3);
    assert_eq!(
        changed.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator-receiver-changed".to_string()
        })
    );
}

/// The same fix holds for the event body: after the refused retry of a
/// lost revision, a rescan under a changed job version stops before the
/// changed body is sent, and restoring the version lets the item settle on
/// the Run already admitted.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescan_after_a_refused_retry_of_a_lost_revision_never_sends_a_changed_body() {
    let (receiver, base_url) = start_admitting_receiver(
        &Admissions::default(),
        [
            Answer::Admitted,
            Answer::Lost,
            Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
            Answer::Admitted,
        ],
    )
    .await;
    let revised = revision_destination(&base_url, "revised");
    let fixture = registered_then_edited().await;
    let mut program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    let revision = lose_then_refuse_a_revision(&pool, &program, &revised, &receiver).await;
    let admitted = receiver.runs_for(&revision);

    let original_version = program.job.job.version.clone();
    program.job.job.version = "2".to_string();
    let changed = run_pass(&pool, &program, &revised, rescan()).await;
    assert_eq!(receiver.requests().len(), 3, "the changed body is not sent");
    assert_eq!(
        changed.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.coordinator-body-changed".to_string()
        })
    );

    program.job.job.version = original_version;
    let restored = run_pass(&pool, &program, &revised, PassOptions::default()).await;
    assert_eq!(restored.stopped, None);
    assert_eq!(restored.items_acknowledged, 1);
    assert_eq!(receiver.runs_for(&revision), admitted);
}

/// With the receiver, authority and body unchanged, a rescan after the
/// refused retry of a lost revision sends the same revised event again,
/// and the item settles on the Run Coordinator already admitted for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rescan_after_a_refused_retry_of_a_lost_revision_settles_on_the_unchanged_receiver() {
    let (receiver, base_url) = start_admitting_receiver(
        &Admissions::default(),
        [
            Answer::Admitted,
            Answer::Lost,
            Answer::Problem(StatusCode::BAD_REQUEST, "event.invalid"),
            Answer::Admitted,
        ],
    )
    .await;
    let revised = revision_destination(&base_url, "revised");
    let fixture = registered_then_edited().await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    let revision = lose_then_refuse_a_revision(&pool, &program, &revised, &receiver).await;
    let admitted = receiver.runs_for(&revision);

    let unchanged = run_pass(&pool, &program, &revised, rescan()).await;
    assert_eq!(unchanged.stopped, None);
    assert_eq!(unchanged.items_redelivered, 1);
    assert_eq!(unchanged.items_acknowledged, 1);
    assert_eq!(
        receiver.requests().last(),
        Some(&("revised".to_string(), revision.clone()))
    );
    assert_eq!(receiver.requests().len(), 4);
    assert_eq!(receiver.runs_for(&revision), admitted);
    let client = pool.get().await.expect("a pooled client");
    let settled = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the settled row reads")
        .expect("the settled row exists");
    assert_eq!(settled.status, ItemStatus::Acknowledged);
    assert_eq!(settled.run_id.as_ref(), admitted.first());
}
