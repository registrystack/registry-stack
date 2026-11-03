// SPDX-License-Identifier: Apache-2.0

//! RabbitMQ receipt integration through the actual reviewed route, job pass,
//! PostgreSQL item store, and destination seam. The real broker transport is
//! exercised separately by `rabbitmq_source`; these tests isolate final-state
//! settlement ordering and redelivery recovery.

#![cfg(all(feature = "job-rabbitmq", feature = "postgres-test"))]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter_core::JobIdentity;
use registry_adapter_engine::component::rabbitmq::{
    rabbitmq_item_key, RabbitMqMessage, RabbitMqReadFault, RabbitMqReadRequest, RabbitMqSettlement,
    RabbitMqSettlementFault, RabbitMqSource,
};
use registry_adapter_engine::job::compile_job;
use registry_adapter_job::destination::{DeliverableItem, HandOffOutcome, JobDestination};
use registry_adapter_job::pass::{
    run_pass, PassOptions, StopReason, RABBITMQ_DRY_RUN_REFUSED, RABBITMQ_HELD,
    RABBITMQ_SETTLEMENT_UNCERTAIN,
};
use registry_adapter_job::rabbitmq_source::activate_rabbitmq_sources;
use registry_adapter_job::store::{self, ItemStatus};
use registry_platform_config::{SecretProvider, SecretResolver};
use tokio_postgres::{Config as PgConfig, NoTls};

#[path = "support/job_fixture.rs"]
mod job_fixture;
#[path = "support/rabbitmq_broker.rs"]
mod rabbitmq_broker;

use job_fixture::RabbitJobFixture;
use rabbitmq_broker::{
    fixture_connection, next_dead_letter, publish, publish_nonpersistent, BrokerFixture,
    TopologyNames, FIXTURE_PASSWORD, FIXTURE_PASSWORD_ENV,
};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

struct SettlementProbe {
    accepts: AtomicU32,
    refuses: AtomicU32,
    fail_accept: AtomicBool,
    pending_accept: AtomicBool,
}

impl SettlementProbe {
    fn successful() -> Arc<Self> {
        Arc::new(Self {
            accepts: AtomicU32::new(0),
            refuses: AtomicU32::new(0),
            fail_accept: AtomicBool::new(false),
            pending_accept: AtomicBool::new(false),
        })
    }

    fn uncertain_accept() -> Arc<Self> {
        Arc::new(Self {
            accepts: AtomicU32::new(0),
            refuses: AtomicU32::new(0),
            fail_accept: AtomicBool::new(true),
            pending_accept: AtomicBool::new(false),
        })
    }

    fn pending_accept() -> Arc<Self> {
        Arc::new(Self {
            accepts: AtomicU32::new(0),
            refuses: AtomicU32::new(0),
            fail_accept: AtomicBool::new(false),
            pending_accept: AtomicBool::new(true),
        })
    }
}

impl RabbitMqSettlement for SettlementProbe {
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>> {
        Box::pin(async move {
            self.accepts.fetch_add(1, Ordering::Relaxed);
            if self.pending_accept.load(Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            if self.fail_accept.load(Ordering::Relaxed) {
                Err(RabbitMqSettlementFault::Uncertain)
            } else {
                Ok(())
            }
        })
    }

    fn refuse(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>> {
        Box::pin(async move {
            self.refuses.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

struct ScriptedMessage {
    id: &'static str,
    redelivered: bool,
    body: &'static [u8],
    settlement: Arc<SettlementProbe>,
}

struct ScriptedSource {
    messages: Mutex<VecDeque<ScriptedMessage>>,
    reads: AtomicU32,
}

impl ScriptedSource {
    fn new(messages: Vec<ScriptedMessage>) -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(messages.into()),
            reads: AtomicU32::new(0),
        })
    }
}

impl RabbitMqSource for ScriptedSource {
    fn read<'a>(
        &'a self,
        _request: &'a RabbitMqReadRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RabbitMqMessage>, RabbitMqReadFault>> + Send + 'a>>
    {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let Some(message) = self
                .messages
                .lock()
                .expect("the source script lock")
                .pop_front()
            else {
                return Ok(None);
            };
            let settlement: Arc<dyn RabbitMqSettlement> = message.settlement;
            RabbitMqMessage::new(
                Some(message.id),
                message.redelivered,
                message.body.to_vec(),
                settlement,
            )
            .map(Some)
        })
    }
}

#[derive(Default)]
struct ScriptedDestination {
    outcomes: Mutex<VecDeque<HandOffOutcome>>,
    delivered: Mutex<Vec<DeliverableItem>>,
}

impl ScriptedDestination {
    fn new(outcomes: Vec<HandOffOutcome>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into()),
            delivered: Mutex::new(Vec::new()),
        }
    }
}

impl JobDestination for ScriptedDestination {
    fn deliver<'a>(
        &'a self,
        _job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.delivered
                .lock()
                .expect("the delivery record lock")
                .push(item.clone());
            self.outcomes
                .lock()
                .expect("the destination script lock")
                .pop_front()
                .expect("one outcome is scripted for each delivery")
        })
    }
}

async fn connect(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect the disposable PostgreSQL server");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the RabbitMQ pass database connection failed: {error}");
        }
    });
    client
}

async fn isolated() -> Pool {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock follows the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_rabbitmq_{nanos}_{serial}");
    let admin = connect(&base).await;
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated RabbitMQ pass schema");
    drop(admin);
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let mut scoped = PgConfig::from_str(&url).expect("parse the scoped database URL");
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
        .expect("build the RabbitMQ pass pool");
    let client = pool.get().await.expect("borrow the migration client");
    store::migrate(&client)
        .await
        .expect("migrate the RabbitMQ pass store");
    drop(client);
    pool
}

fn options() -> PassOptions {
    PassOptions {
        refusal_limit: 20,
        rescan: false,
        dry_run: false,
    }
}

fn message(
    id: &'static str,
    redelivered: bool,
    settlement: Arc<SettlementProbe>,
) -> ScriptedMessage {
    message_body(
        id,
        redelivered,
        br#"{"id":"a","answers":{"age":"045","private":"not-persisted"}}"#,
        settlement,
    )
}

fn message_body(
    id: &'static str,
    redelivered: bool,
    body: &'static [u8],
    settlement: Arc<SettlementProbe>,
) -> ScriptedMessage {
    ScriptedMessage {
        id,
        redelivered,
        body,
        settlement,
    }
}

fn compile_with(
    source: Arc<ScriptedSource>,
    fixture: &RabbitJobFixture,
) -> registry_adapter_engine::job::JobProgram {
    let mut program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the RabbitMQ job compiles through the ordinary engine");
    program
        .register_rabbitmq_source("broker-in", source)
        .expect("the fixture source registers");
    program
}

#[tokio::test]
async fn durable_acknowledgement_settles_and_redelivery_skips_the_destination() {
    let fixture = RabbitJobFixture::start();
    let first = SettlementProbe::successful();
    let redelivery = SettlementProbe::successful();
    let source = ScriptedSource::new(vec![
        message("message-1", false, Arc::clone(&first)),
        message("message-1", true, Arc::clone(&redelivery)),
    ]);
    let program = compile_with(Arc::clone(&source), &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![HandOffOutcome::Acknowledged {
        run_id: Some("destination-run".to_owned()),
    }]);

    let accepted = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(accepted.stopped, None);
    assert_eq!(accepted.items_acknowledged, 1);
    assert_eq!(first.accepts.load(Ordering::Relaxed), 1);

    let repeated = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(repeated.stopped, None);
    assert_eq!(repeated.items_skipped, 1);
    assert_eq!(redelivery.accepts.load(Ordering::Relaxed), 1);
    assert_eq!(destination.delivered.lock().expect("deliveries").len(), 1);

    let key = rabbitmq_item_key("institution-a", "message-1");
    let client = pool.get().await.expect("the inspect client");
    let row = store::inspect_item(&client, "case-daily", &key)
        .await
        .expect("the item read")
        .expect("the item row");
    assert_eq!(row.status, ItemStatus::Acknowledged);
}

#[tokio::test]
async fn refusal_is_durable_before_source_rejection_and_held_never_settles() {
    let fixture = RabbitJobFixture::start();
    let refused = SettlementProbe::successful();
    let held = SettlementProbe::successful();
    let held_redelivery = SettlementProbe::successful();
    let source = ScriptedSource::new(vec![
        message("refused-1", false, Arc::clone(&refused)),
        message("held-1", false, Arc::clone(&held)),
        message("held-1", true, Arc::clone(&held_redelivery)),
    ]);
    let program = compile_with(source, &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![
        HandOffOutcome::Refused {
            code: "destination.invalid".to_owned(),
        },
        HandOffOutcome::Held {
            code: "destination.uncertain".to_owned(),
            run_id: Some("operator-case".to_owned()),
        },
    ]);

    let refusal = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(refusal.stopped, None);
    assert_eq!(refused.refuses.load(Ordering::Relaxed), 1);

    let first_hold = run_pass(&pool, &program, &destination, options()).await;
    assert!(matches!(
        first_hold.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_HELD
    ));
    assert_eq!(held.accepts.load(Ordering::Relaxed), 0);
    assert_eq!(held.refuses.load(Ordering::Relaxed), 0);

    let repeated_hold = run_pass(&pool, &program, &destination, options()).await;
    assert!(matches!(
        repeated_hold.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_HELD
    ));
    assert_eq!(held_redelivery.accepts.load(Ordering::Relaxed), 0);
    assert_eq!(held_redelivery.refuses.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn uncertain_acknowledgement_keeps_position_safe_and_recovers_without_duplicate_effect() {
    let fixture = RabbitJobFixture::start();
    let uncertain = SettlementProbe::uncertain_accept();
    let recovered = SettlementProbe::successful();
    let source = ScriptedSource::new(vec![
        message("uncertain-1", false, Arc::clone(&uncertain)),
        message("uncertain-1", true, Arc::clone(&recovered)),
    ]);
    let program = compile_with(source, &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![HandOffOutcome::Acknowledged {
        run_id: Some("one-effect".to_owned()),
    }]);

    let first = run_pass(&pool, &program, &destination, options()).await;
    assert!(matches!(
        first.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_SETTLEMENT_UNCERTAIN
    ));
    assert_eq!(uncertain.accepts.load(Ordering::Relaxed), 1);

    let second = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(second.stopped, None);
    assert_eq!(second.items_skipped, 1);
    assert_eq!(recovered.accepts.load(Ordering::Relaxed), 1);
    assert_eq!(destination.delivered.lock().expect("deliveries").len(), 1);
}

#[tokio::test]
async fn pending_source_settlement_is_finitely_uncertain() {
    let fixture = RabbitJobFixture::start();
    let pending = SettlementProbe::pending_accept();
    let source = ScriptedSource::new(vec![message(
        "pending-settlement-1",
        false,
        Arc::clone(&pending),
    )]);
    let program = compile_with(source, &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![HandOffOutcome::Acknowledged {
        run_id: Some("effect-before-pending-settlement".to_owned()),
    }]);

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        run_pass(&pool, &program, &destination, options()),
    )
    .await
    .expect("source settlement has a finite host-owned deadline");
    assert!(matches!(
        result.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_SETTLEMENT_UNCERTAIN
    ));
    assert_eq!(result.items_acknowledged, 1);
    assert_eq!(pending.accepts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rabbitmq_json_refuses_strings_and_keys_over_the_profile_field_bound() {
    let fixture = RabbitJobFixture::start_with_rabbit_field_bound(8);
    let exact = SettlementProbe::successful();
    let oversized_string = SettlementProbe::successful();
    let oversized_key = SettlementProbe::successful();
    let source = ScriptedSource::new(vec![
        message_body(
            "field-exact-1",
            false,
            br#"{"id":"a","answers":{"age":"12345678"}}"#,
            Arc::clone(&exact),
        ),
        message_body(
            "field-string-1",
            false,
            br#"{"id":"a","answers":{"age":"123456789"}}"#,
            Arc::clone(&oversized_string),
        ),
        message_body(
            "field-key-1",
            false,
            br#"{"id":"a","answers":{"123456789":"x"}}"#,
            Arc::clone(&oversized_key),
        ),
    ]);
    let program = compile_with(source, &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![HandOffOutcome::Acknowledged {
        run_id: Some("exact-bound-effect".to_owned()),
    }]);

    let exact_report = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(exact_report.items_acknowledged, 1);
    assert_eq!(exact.accepts.load(Ordering::Relaxed), 1);

    let string_report = run_pass(&pool, &program, &destination, options()).await;
    assert!(string_report.stopped.is_some());
    assert_eq!(oversized_string.refuses.load(Ordering::Relaxed), 1);
    assert_eq!(oversized_string.accepts.load(Ordering::Relaxed), 0);

    let key_report = run_pass(&pool, &program, &destination, options()).await;
    assert!(key_report.stopped.is_some());
    assert_eq!(oversized_key.refuses.load(Ordering::Relaxed), 1);
    assert_eq!(oversized_key.accepts.load(Ordering::Relaxed), 0);
    assert_eq!(destination.delivered.lock().expect("deliveries").len(), 1);
}

#[tokio::test]
async fn contradictory_and_multi_item_pages_leave_the_delivery_unsettled() {
    const CONTRADICTORY_KEY: &str = r#"fn normalize(exchange) {
    let page = exchange.body;
    page.items[0].key = "contradictory";
    page
}
"#;
    const MULTI_ITEM: &str = r#"fn normalize(exchange) {
    let page = exchange.body;
    let duplicate = page.items[0];
    page.items.push(duplicate);
    page
}
"#;

    for (id, script) in [
        ("contradictory-page-1", CONTRADICTORY_KEY),
        ("multi-page-1", MULTI_ITEM),
    ] {
        let fixture = RabbitJobFixture::start_with_rabbit_route_script(script);
        let settlement = SettlementProbe::successful();
        let source = ScriptedSource::new(vec![message(id, false, Arc::clone(&settlement))]);
        let program = compile_with(source, &fixture);
        let pool = isolated().await;
        let destination = ScriptedDestination::default();

        let report = run_pass(&pool, &program, &destination, options()).await;
        assert!(matches!(
            report.stopped,
            Some(StopReason::PageFault { ref code, .. }) if code == "adapter.job.rabbitmq-page-shape"
        ));
        assert_eq!(settlement.accepts.load(Ordering::Relaxed), 0);
        assert_eq!(settlement.refuses.load(Ordering::Relaxed), 0);
        assert!(destination.delivered.lock().expect("deliveries").is_empty());
    }
}

#[tokio::test]
async fn reviewed_normalization_change_under_one_raw_revision_is_not_skipped() {
    let plain_fixture = RabbitJobFixture::start();
    let normalized_fixture = RabbitJobFixture::start_with_reviewed_normalization();
    let first_settlement = SettlementProbe::successful();
    let revised_settlement = SettlementProbe::successful();
    let first_source = ScriptedSource::new(vec![message(
        "projection-change-1",
        false,
        Arc::clone(&first_settlement),
    )]);
    let revised_source = ScriptedSource::new(vec![message(
        "projection-change-1",
        true,
        Arc::clone(&revised_settlement),
    )]);
    let first_program = compile_with(first_source, &plain_fixture);
    let revised_program = compile_with(revised_source, &normalized_fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![
        HandOffOutcome::Acknowledged {
            run_id: Some("effect-before-normalization".to_owned()),
        },
        HandOffOutcome::Acknowledged {
            run_id: Some("effect-after-normalization".to_owned()),
        },
    ]);

    let first = run_pass(&pool, &first_program, &destination, options()).await;
    assert_eq!(first.items_acknowledged, 1);
    let revised = run_pass(&pool, &revised_program, &destination, options()).await;

    assert_eq!(
        revised.items_changed, 1,
        "the queue digest must cover the reviewed normalized projection as well as raw identity"
    );
    assert_eq!(revised.items_held, 1);
    assert!(matches!(
        revised.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_HELD
    ));
    assert_eq!(destination.delivered.lock().expect("deliveries").len(), 1);
    assert_eq!(revised_settlement.accepts.load(Ordering::Relaxed), 0);
    assert_eq!(revised_settlement.refuses.load(Ordering::Relaxed), 0);

    let key = rabbitmq_item_key("institution-a", "projection-change-1");
    let client = pool.get().await.expect("the normalization inspect client");
    let row = store::inspect_item(&client, "case-daily", &key)
        .await
        .expect("the normalized item read")
        .expect("the normalized item row");
    assert_eq!(row.status, ItemStatus::Held);
    assert_eq!(
        row.code.as_deref(),
        Some("adapter.job.rabbitmq-event-changed")
    );
}

#[tokio::test]
async fn changed_raw_body_under_one_message_identity_is_held_without_another_effect() {
    let fixture = RabbitJobFixture::start();
    let first_settlement = SettlementProbe::successful();
    let changed_settlement = SettlementProbe::successful();
    let source = ScriptedSource::new(vec![
        message("raw-change-1", false, Arc::clone(&first_settlement)),
        message_body(
            "raw-change-1",
            true,
            br#"{"id":"a","answers":{"age":"046","private":"not-persisted"}}"#,
            Arc::clone(&changed_settlement),
        ),
    ]);
    let program = compile_with(source, &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![HandOffOutcome::Acknowledged {
        run_id: Some("immutable-event-effect".to_owned()),
    }]);

    let first = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(first.items_acknowledged, 1);
    let changed = run_pass(&pool, &program, &destination, options()).await;

    assert_eq!(changed.items_changed, 1);
    assert_eq!(changed.items_held, 1);
    assert!(matches!(
        changed.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_HELD
    ));
    assert_eq!(destination.delivered.lock().expect("deliveries").len(), 1);
    assert_eq!(changed_settlement.accepts.load(Ordering::Relaxed), 0);
    assert_eq!(changed_settlement.refuses.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn queue_dry_run_refuses_before_broker_acquisition() {
    let fixture = RabbitJobFixture::start();
    let source = ScriptedSource::new(Vec::new());
    let program = compile_with(Arc::clone(&source), &fixture);
    let pool = isolated().await;
    let destination = ScriptedDestination::default();

    let report = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            dry_run: true,
            ..options()
        },
    )
    .await;

    assert!(matches!(
        report.stopped,
        Some(StopReason::PageFault { ref code, .. }) if code == RABBITMQ_DRY_RUN_REFUSED
    ));
    assert_eq!(source.reads.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_broker_and_postgres_pass_acknowledge_only_after_durable_acceptance() {
    let broker = BrokerFixture::start();
    let names = TopologyNames::new();
    drop(
        fixture_connection(&broker)
            .await
            .expect("the synthetic broker becomes ready"),
    );
    let fixture = RabbitJobFixture::start_for_broker_with_field_bound(
        broker.port,
        &names.queue,
        &names.dead_letter_exchange,
        &names.dead_letter_queue,
        &names.dead_letter_routing_key,
        8,
    );
    let mut program = compile_job(&fixture.pack, &fixture.job, &fixture.runtime)
        .expect("the real-broker RabbitMQ job compiles");
    std::env::set_var(FIXTURE_PASSWORD_ENV, FIXTURE_PASSWORD);
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment-only fixture resolver starts");
    activate_rabbitmq_sources(&mut program, &resolver)
        .expect("the host activates the compiled broker binding");
    std::env::remove_var(FIXTURE_PASSWORD_ENV);

    let pool = isolated().await;
    let destination = ScriptedDestination::new(vec![HandOffOutcome::Acknowledged {
        run_id: Some("real-broker-effect".to_owned()),
    }]);

    let idle = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(idle.stopped, None, "the first bounded empty poll is idle");
    assert_eq!(idle.items_read, 0);
    let repeated_idle = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(
        repeated_idle.stopped, None,
        "an empty poll does not permanently complete an ongoing queue source"
    );
    assert_eq!(repeated_idle.items_read, 0);

    publish(
        &broker,
        &names.queue,
        Some("real-pass-1"),
        br#"{"id":"real","answers":{"age":"051"}}"#,
    )
    .await
    .expect("the broker confirms the durable fixture publish");
    let accepted = run_pass(&pool, &program, &destination, options()).await;
    assert_eq!(accepted.stopped, None);
    assert_eq!(accepted.items_acknowledged, 1);

    let key = rabbitmq_item_key("institution-a", "real-pass-1");
    let client = pool.get().await.expect("the durable item inspect client");
    let row = store::inspect_item(&client, "case-daily", &key)
        .await
        .expect("the accepted item read")
        .expect("the accepted item row");
    assert_eq!(row.status, ItemStatus::Acknowledged);
    drop(client);

    let connection = fixture_connection(&broker)
        .await
        .expect("the broker inspection connection opens");
    let channel = connection
        .create_channel()
        .await
        .expect("the broker inspection channel opens");
    assert!(
        channel
            .basic_get(
                names.queue.clone().into(),
                lapin::options::BasicGetOptions { no_ack: true },
            )
            .await
            .expect("the source queue can be inspected")
            .is_none(),
        "the source-owned receipt acknowledged the durable accepted row"
    );
    assert_eq!(
        broker.messages_unacknowledged(&names.queue),
        0,
        "the owned broker fixture retains no unsettled delivery"
    );

    publish(
        &broker,
        &names.queue,
        Some("real-field-bound-1"),
        br#"{"id":"real","answers":{"age":"123456789"}}"#,
    )
    .await
    .expect("the broker confirms the over-field-bound fixture publish");
    let refused = run_pass(&pool, &program, &destination, options()).await;
    assert!(refused.stopped.is_some());
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(|value| value.as_str()),
        Some("real-field-bound-1")
    );

    publish_nonpersistent(
        &broker,
        &names.queue,
        "real-nonpersistent-1",
        br#"{"id":"unreliable","answers":{"age":"052"}}"#,
    )
    .await
    .expect("the broker confirms the nonpersistent fixture publish");
    let nonpersistent = run_pass(&pool, &program, &destination, options()).await;
    assert!(matches!(
        nonpersistent.stopped,
        Some(StopReason::PageFault { ref code, .. })
            if code == "adapter.job.rabbitmq-delivery-mode"
    ));
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(|value| value.as_str()),
        Some("real-nonpersistent-1")
    );
}
