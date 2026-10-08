// SPDX-License-Identifier: Apache-2.0

//! Database-backed dispatch tests: the worker sends each accepted message
//! through the transport its provider is registered with, under the policy
//! captured at acceptance, and an operator settles what it could not.
//!
//! The transport is scripted in process: it answers accepted, transient
//! with or without a pause hint, permanent, maybe-sent, or hangs, and counts
//! every send by message. Provider kinds prove their own wire behaviour in
//! their own suites.
//!
//! Every test runs in its own schema inside the database named by
//! `MESSAGING_TEST_DATABASE_URL`. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

mod support;

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use registry_messaging::dispatch::{
    dispatcher, MessageDispatcher, MessageSender, MessageTransport, OutboundMessage, Transports,
    PROVIDER_UNCONFIGURED,
};
use registry_messaging::messages::{OperatorAction, SettleOutcome};
use registry_messaging::runtime::{assemble, Listeners};
use registry_messaging_core::{Channel, MessageStatus};
use registry_platform_dispatch::postgres::{DispatchOutcome, DispatchWorker, WorkerConfig};
use registry_platform_dispatch::{FailureCode, ReceiverReference, SendOutcome, Sent};
use serde_json::Value;
use support::{email_submission, sms_submission, Harness, NAME, RECIPIENT};
use tokio::sync::watch;
use uuid::Uuid;

/// What the scripted transport answers.
#[derive(Clone, Copy, Debug)]
enum Script {
    Accepted,
    Transient(Option<Duration>),
    Permanent,
    MaybeSent,
    Hang,
}

/// A transport that answers its script and records every send.
struct Scripted {
    script: Mutex<Script>,
    timeout: Duration,
    sends: Mutex<BTreeMap<Uuid, usize>>,
    delay: Duration,
    seen: Mutex<Vec<OutboundMessage>>,
    rate: Option<u32>,
    started: Mutex<Vec<std::time::Instant>>,
    /// The provider's in-flight bound, and the slots a send waits for
    /// before it leaves, as an HTTP provider's `maximumConcurrentRequests`
    /// does.
    limit: Option<NonZeroUsize>,
    slots: Option<tokio::sync::Semaphore>,
    /// How long the first send takes, on top of `delay`.
    first_delay: Duration,
}

impl Scripted {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script),
            timeout: Duration::from_secs(30),
            sends: Mutex::new(BTreeMap::new()),
            delay: Duration::ZERO,
            seen: Mutex::new(Vec::new()),
            rate: None,
            started: Mutex::new(Vec::new()),
            limit: None,
            slots: None,
            first_delay: Duration::ZERO,
        })
    }

    /// Accepts every send, declaring the provider's rate.
    fn paced(rate: u32) -> Arc<Self> {
        Arc::new(Self {
            rate: Some(rate),
            ..Arc::into_inner(Self::new(Script::Accepted)).unwrap()
        })
    }

    fn with_timeout(script: Script, timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            timeout,
            ..Arc::into_inner(Self::new(script)).unwrap()
        })
    }

    fn slow(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            delay,
            ..Arc::into_inner(Self::new(Script::Accepted)).unwrap()
        })
    }

    fn answer(&self, script: Script) {
        *self.script.lock().unwrap() = script;
    }

    fn sends(&self, message_id: Uuid) -> usize {
        self.sends
            .lock()
            .unwrap()
            .get(&message_id)
            .copied()
            .unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.sends.lock().unwrap().values().sum()
    }
}

#[async_trait]
impl MessageTransport for Scripted {
    fn attempt_timeout(&self) -> Duration {
        self.timeout
    }

    fn rate_per_second(&self) -> Option<u32> {
        self.rate
    }

    fn concurrency_limit(&self) -> Option<NonZeroUsize> {
        self.limit
    }

    async fn send(&self, message: &OutboundMessage) -> SendOutcome {
        let _slot = match &self.slots {
            Some(slots) => Some(slots.acquire().await.unwrap()),
            None => None,
        };
        let first = {
            let mut started = self.started.lock().unwrap();
            started.push(std::time::Instant::now());
            started.len() == 1
        };
        *self
            .sends
            .lock()
            .unwrap()
            .entry(message.message_id)
            .or_default() += 1;
        self.seen.lock().unwrap().push(message.clone());
        if first && !self.first_delay.is_zero() {
            tokio::time::sleep(self.first_delay).await;
        }
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let script = *self.script.lock().unwrap();
        match script {
            Script::Accepted => SendOutcome::Accepted {
                receiver_reference: Some(ReceiverReference::new("provider-ref-1").unwrap()),
            },
            Script::Transient(retry_after) => SendOutcome::Transient { retry_after },
            Script::Permanent => SendOutcome::Permanent {
                code: FailureCode::new("recipient-refused").unwrap(),
            },
            Script::MaybeSent => SendOutcome::MaybeSent,
            Script::Hang => std::future::pending().await,
        }
    }
}

/// The dispatcher over the harness's schema with `transport` registered for
/// the email provider only, and the sender the worker drives through it.
fn worker_over(harness: &Harness, transport: Arc<Scripted>) -> (MessageDispatcher, MessageSender) {
    worker_for(harness, "mail-relay", transport)
}

/// The dispatcher and sender with `transport` registered for `provider`
/// only.
fn worker_for(
    harness: &Harness,
    provider: &str,
    transport: Arc<Scripted>,
) -> (MessageDispatcher, MessageSender) {
    let mut transports = Transports::new();
    transports.insert(provider, transport).unwrap();
    let transports = Arc::new(transports);
    let dispatcher = dispatcher(
        harness.store.clone(),
        &harness.isolated.schema,
        Arc::clone(&transports),
        Arc::clone(&harness.audit),
    )
    .unwrap();
    let sender = MessageSender::new(dispatcher.clone(), transports, Arc::clone(&harness.metrics));
    (dispatcher, sender)
}

async fn status(harness: &Harness, id: Uuid) -> MessageStatus {
    harness
        .service
        .messages()
        .read(id)
        .await
        .unwrap()
        .unwrap()
        .view
        .status
}

/// Make a waiting retry due now.
async fn make_due(harness: &Harness, id: Uuid) {
    harness
        .execute(
            "UPDATE messaging_dispatch_jobs SET next_attempt_at = now() WHERE message_id = $1",
            &[&id],
        )
        .await;
}

/// How long the job waits before its next attempt, in seconds.
async fn wait_seconds(harness: &Harness, id: Uuid) -> f64 {
    harness
        .isolated
        .admin
        .query_one(
            "SELECT extract(epoch FROM next_attempt_at - updated_at)::float8 \
               FROM messaging_dispatch_jobs WHERE message_id = $1 AND state = 'pending'",
            &[&id],
        )
        .await
        .unwrap()
        .get(0)
}

/// Move the live lease of `id` into the past, the way a worker that died
/// mid-send leaves it once its lease lapses.
async fn lapse_lease(harness: &Harness, id: Uuid) {
    let changed = harness
        .execute(
            "UPDATE messaging_dispatch_jobs \
                SET attempt_started_at = now() - interval '2 minutes', \
                    lease_expires_at = now() - interval '1 minute' \
              WHERE message_id = $1 AND state = 'leased'",
            &[&id],
        )
        .await;
    assert_eq!(changed, 1);
}

async fn attempt_outcomes(harness: &Harness, id: Uuid) -> Vec<(i64, i16, String, Option<String>)> {
    harness
        .isolated
        .admin
        .query(
            "SELECT generation, attempt, outcome, failure_code FROM messaging_attempts \
              WHERE message_id = $1 ORDER BY generation, attempt",
            &[&id],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

#[tokio::test]
async fn an_accepted_send_carries_the_rendered_parts_and_leaves_the_message_submitted() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(status(&harness, id).await, MessageStatus::Submitted);
    let seen = transport.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let message = &seen[0];
    assert_eq!(message.message_id, id);
    assert_eq!((message.generation, message.attempt), (1, 1));
    assert_eq!(message.channel, Channel::Email);
    assert_eq!(message.sender, "notices@example.org");
    assert_eq!(message.recipient, RECIPIENT);
    assert!(message.parts.text.contains(NAME));
    assert!(message.idempotency_key.starts_with("sha256:"));
    assert!(message.budget <= Duration::from_secs(30));
    // The debug form names the message and the attempt only.
    let debug = format!("{message:?}");
    assert!(
        !debug.contains(RECIPIENT) && !debug.contains(NAME),
        "{debug}"
    );
    assert_eq!(
        attempt_outcomes(&harness, id).await,
        vec![(1, 1, "accepted".to_owned(), None)]
    );
    let view = harness
        .service
        .messages()
        .read(id)
        .await
        .unwrap()
        .unwrap()
        .view;
    assert_eq!(view.attempts.len(), 1);
    assert!(view.attempts[0].provider_reference);
}

#[tokio::test]
async fn accepted_idempotency_capability_is_loaded_after_worker_reconstruction() {
    let harness = Harness::start_with(Value::Null, |package| {
        let path = package.join("messaging.yaml");
        let source = std::fs::read_to_string(&path).unwrap();
        let mut manifest: Value = serde_norway::from_str(&source).unwrap();
        manifest["senderProfiles"][1]["onUncertain"] = Value::String("retry".to_owned());
        std::fs::write(path, serde_norway::to_string(&manifest).unwrap()).unwrap();
    })
    .await;
    let id = harness.accepted(&sms_submission()).await;
    let stored: bool = harness
        .isolated
        .admin
        .query_one(
            "SELECT provider_idempotent_submit FROM messaging_messages WHERE message_id = $1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(stored);

    // Build a new worker over the persisted message, as a restarted runtime
    // does. Its outbound contract still carries the acceptance-time flag.
    let transport = Scripted::new(Script::Accepted);
    let mut transports = Transports::new();
    transports.insert("sms-gateway", transport.clone()).unwrap();
    let transports = Arc::new(transports);
    let dispatcher = dispatcher(
        harness.store.clone(),
        &harness.isolated.schema,
        Arc::clone(&transports),
        Arc::clone(&harness.audit),
    )
    .unwrap();
    let sender = MessageSender::new(dispatcher.clone(), transports, Arc::clone(&harness.metrics));
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].provider_idempotent_submit);
}

/// Two workers draining one table never send one message twice.
#[tokio::test]
async fn two_workers_never_send_one_message_twice() {
    let harness = Harness::start().await;
    let transport = Scripted::slow(Duration::from_millis(20));
    let mut ids = Vec::new();
    for _ in 0..24 {
        ids.push(harness.accepted(&email_submission()).await);
    }
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
            DispatchWorker::new(
                dispatcher,
                Arc::new(sender),
                WorkerConfig {
                    concurrency: NonZeroUsize::new(4).unwrap(),
                    idle_poll: Duration::from_millis(50),
                },
            )
        })
        .collect();
    let (_stop, shutdown) = watch::channel(false);
    let (first, second) = tokio::join!(workers[0].drain(&shutdown), workers[1].drain(&shutdown));
    assert_eq!(first + second, ids.len());
    for id in &ids {
        assert_eq!(transport.sends(*id), 1, "{id}");
        assert_eq!(harness.state(*id).await, "delivered");
    }
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_attempts")
            .await,
        i64::try_from(ids.len()).unwrap()
    );
}

/// A provider's `ratePerSecond` paces the sends of concurrent attempts: one
/// starts every interval, and every message is still delivered once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paced_provider_starts_one_send_per_interval() {
    let harness = Harness::start().await;
    let transport = Scripted::paced(10);
    let mut ids = Vec::new();
    for _ in 0..6 {
        ids.push(harness.accepted(&email_submission()).await);
    }
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let worker = DispatchWorker::new(
        dispatcher,
        Arc::new(sender),
        WorkerConfig {
            concurrency: NonZeroUsize::new(4).unwrap(),
            idle_poll: Duration::from_millis(50),
        },
    );
    let (_stop, shutdown) = watch::channel(false);
    assert_eq!(worker.drain(&shutdown).await, ids.len());
    for id in &ids {
        assert_eq!(transport.sends(*id), 1, "{id}");
        assert_eq!(harness.state(*id).await, "delivered");
    }
    let mut started = transport.started.lock().unwrap().clone();
    started.sort();
    // Six sends at ten a second: the first slot is free, and each of the
    // next five opens 100 ms after the one before.
    for pair in started.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(gap >= Duration::from_millis(90), "{gap:?}");
    }
    assert!(started[5].duration_since(started[0]) >= Duration::from_millis(490));
    // Pacing is not an attempt: each message was attempted once.
    assert_eq!(
        harness
            .count("SELECT count(*) FROM messaging_attempts")
            .await,
        6
    );
}

/// A provider whose `concurrencyLimit` is below the worker's concurrency
/// still has its sends leave one interval apart: an attempt takes its turn
/// at the rate only once it holds one of the provider's slots, so attempts
/// queued behind a slow send do not leave back to back when it ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paced_provider_below_the_worker_concurrency_still_sends_one_per_interval() {
    let harness = Harness::start().await;
    let transport = Arc::new(Scripted {
        limit: NonZeroUsize::new(1),
        slots: Some(tokio::sync::Semaphore::new(1)),
        first_delay: Duration::from_millis(500),
        ..Arc::into_inner(Scripted::paced(10)).unwrap()
    });
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(harness.accepted(&email_submission()).await);
    }
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let worker = DispatchWorker::new(
        dispatcher,
        Arc::new(sender),
        WorkerConfig {
            concurrency: NonZeroUsize::new(4).unwrap(),
            idle_poll: Duration::from_millis(50),
        },
    );
    let (_stop, shutdown) = watch::channel(false);
    assert_eq!(worker.drain(&shutdown).await, ids.len());
    for id in &ids {
        assert_eq!(transport.sends(*id), 1, "{id}");
        assert_eq!(harness.state(*id).await, "delivered");
    }
    let mut started = transport.started.lock().unwrap().clone();
    started.sort();
    // The first send holds the only slot for 500 ms; the three queued
    // behind it still leave 100 ms apart once it ends.
    for pair in started.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(gap >= Duration::from_millis(90), "{gap:?}");
    }
    assert_eq!(
        harness
            .sample("messaging_limit_refusals_total{limit=\"pacing\"}")
            .await,
        Some(0)
    );
}

/// A message whose `expiresAt` passes while it would wait for its
/// provider's next send slot is never handed to the transport: the wait is
/// bounded by the expiry, and the message expires unsent.
#[tokio::test]
async fn a_message_that_expires_before_its_pacing_slot_expires_unsent() {
    let harness = Harness::start().await;
    let transport = Scripted::paced(1);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let first = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    let second = harness.accepted(&email_submission()).await;
    // The provider's next slot opens a second after the first send, well
    // after this message's expiry.
    harness
        .execute(
            "UPDATE messaging_messages \
                SET expires_at = now() + interval '300 milliseconds' \
              WHERE message_id = $1",
            &[&second],
        )
        .await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Expired
    );
    assert_eq!(status(&harness, second).await, MessageStatus::Expired);
    assert_eq!(transport.sends(first), 1);
    assert_eq!(transport.sends(second), 0);
}

/// A worker that dies mid-send leaves the message unknown under the
/// default `hold` policy: it is never sent again on its own.
#[tokio::test]
async fn a_killed_worker_leaves_its_message_unknown_and_unsent_again() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&email_submission()).await;
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    assert_eq!(leased.key.id(), id);
    drop(leased);
    lapse_lease(&harness, id).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);
    assert_eq!(transport.total(), 0);
    assert_eq!(
        attempt_outcomes(&harness, id).await,
        vec![(1, 1, "interrupted".to_owned(), None)]
    );
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(transport.total(), 0);
}

/// SEC-05: a finish carrying a stale lease matches no row, so a worker that
/// lost its lease cannot overwrite the generation that replaced it.
#[tokio::test]
async fn a_stale_fence_cannot_finish_a_requeued_message() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&email_submission()).await;
    let stale = dispatcher.claim().await.unwrap().leased().unwrap();
    lapse_lease(&harness, id).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);

    let report = harness
        .service
        .messages()
        .operate(id, OperatorAction::Settle(SettleOutcome::NotSent), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.next_generation, Some(2));
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    assert_eq!(transport.sends(id), 1);

    for sent in [
        SendOutcome::Accepted {
            receiver_reference: None,
        },
        SendOutcome::Permanent {
            code: FailureCode::new("recipient-refused").unwrap(),
        },
    ] {
        assert!(dispatcher
            .finish(
                &stale,
                Sent {
                    outcome: sent,
                    detail: ()
                }
            )
            .await
            .is_err());
    }
    assert_eq!(harness.state(id).await, "delivered");
    assert_eq!(
        attempt_outcomes(&harness, id).await,
        vec![
            (1, 1, "interrupted".to_owned(), None),
            (2, 1, "accepted".to_owned(), None)
        ]
    );
}

/// SEC-06: an attempt is bounded by its transport's timeout; a send cut off
/// mid-flight may have reached the provider, so it is held as unknown.
#[tokio::test]
async fn a_hanging_send_is_cut_off_and_held_as_unknown() {
    let harness = Harness::start().await;
    let transport = Scripted::with_timeout(Script::Hang, Duration::from_secs(1));
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&email_submission()).await;
    let started = std::time::Instant::now();
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Unknown
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(transport.sends(id), 1);
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);
    assert_eq!(
        attempt_outcomes(&harness, id).await,
        vec![(1, 1, "maybe-sent".to_owned(), None)]
    );

    transport.answer(Script::MaybeSent);
    let answered = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Unknown
    );
    assert_eq!(status(&harness, answered).await, MessageStatus::Unknown);
}

/// The metrics listener samples the queue from the store on every scrape
/// and counts every attempt by the outcome its history records.
#[tokio::test]
async fn the_metrics_sample_the_queue_and_count_attempts_by_outcome() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    for _ in 0..3 {
        harness.accepted(&email_submission()).await;
    }
    let jobs = |state: &str| format!("messaging_dispatch_jobs{{state=\"{state}\"}}");
    let attempts =
        |outcome: &str| format!("messaging_provider_attempts_total{{outcome=\"{outcome}\"}}");
    assert_eq!(harness.sample(&jobs("pending")).await, Some(3));
    assert_eq!(harness.sample(&jobs("leased")).await, Some(0));
    assert_eq!(harness.sample(&jobs("unknown")).await, Some(0));
    assert_eq!(harness.sample(&attempts("accepted")).await, Some(0));

    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    assert_eq!(harness.sample(&jobs("pending")).await, Some(1));
    assert_eq!(harness.sample(&jobs("leased")).await, Some(1));
    drop(leased);
    transport.answer(Script::MaybeSent);
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Unknown
    );
    assert_eq!(harness.sample(&jobs("unknown")).await, Some(1));
    assert_eq!(harness.sample(&attempts("accepted")).await, Some(1));
    assert_eq!(harness.sample(&attempts("maybe-sent")).await, Some(1));
    assert_eq!(harness.sample(&attempts("transient")).await, Some(0));
    let scraped = harness.scrape().await;
    assert!(!scraped.contains("mail-relay"), "{scraped}");
    assert!(!scraped.contains(RECIPIENT), "{scraped}");
}

/// A provider whose send timeout fills the whole attempt timeout leaves
/// pacing no allowance: an attempt that finds no send slot is counted as a
/// pacing refusal and waits to be retried, without a send.
#[tokio::test]
async fn an_attempt_with_no_pacing_slot_in_its_allowance_is_counted_and_retried() {
    let harness = Harness::start().await;
    let transport = Arc::new(Scripted {
        rate: Some(1),
        ..Arc::into_inner(Scripted::with_timeout(
            Script::Accepted,
            Duration::from_secs(60),
        ))
        .unwrap()
    });
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let first = harness.accepted(&email_submission()).await;
    let second = harness.accepted(&email_submission()).await;
    dispatcher.dispatch_once(&sender).await.unwrap();
    dispatcher.dispatch_once(&sender).await.unwrap();
    assert_eq!(transport.total(), 1);
    let mut states = vec![harness.state(first).await, harness.state(second).await];
    states.sort();
    assert_eq!(states, ["delivered", "pending"]);
    assert_eq!(
        harness
            .sample("messaging_limit_refusals_total{limit=\"pacing\"}")
            .await,
        Some(1)
    );
    assert_eq!(
        harness
            .sample("messaging_provider_attempts_total{outcome=\"transient\"}")
            .await,
        Some(1)
    );
}

#[test]
fn a_transport_timeout_outside_one_to_sixty_seconds_is_refused() {
    for timeout in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_secs(61),
    ] {
        let mut transports = Transports::new();
        assert!(transports
            .insert(
                "mail-relay",
                Scripted::with_timeout(Script::Accepted, timeout)
            )
            .is_err());
    }
    let mut transports = Transports::new();
    transports
        .insert("mail-relay", Scripted::new(Script::Accepted))
        .unwrap();
    assert!(transports
        .insert("mail-relay", Scripted::new(Script::Accepted))
        .is_err());
}

/// A transient failure waits an equal-jittered backoff, a provider's pause
/// hint when it is longer, and never more than the maximum delay.
#[tokio::test]
async fn a_transient_failure_waits_a_jittered_backoff_or_the_providers_hint() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Transient(None));
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&email_submission()).await;

    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    let first = wait_seconds(&harness, id).await;
    assert!((15.0..=30.0).contains(&first), "{first}");
    assert_eq!(status(&harness, id).await, MessageStatus::Queued);
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );

    make_due(&harness, id).await;
    transport.answer(Script::Transient(Some(Duration::from_secs(120))));
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    let hinted = wait_seconds(&harness, id).await;
    assert!((119.9..=120.1).contains(&hinted), "{hinted}");

    make_due(&harness, id).await;
    transport.answer(Script::Transient(Some(Duration::from_secs(36_000))));
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    let capped = wait_seconds(&harness, id).await;
    assert!((3599.9..=3600.1).contains(&capped), "{capped}");
    assert_eq!(transport.sends(id), 3);

    // The fifth attempt is the last the starter's policy allows.
    make_due(&harness, id).await;
    transport.answer(Script::Transient(None));
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    make_due(&harness, id).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );
    assert_eq!(transport.sends(id), 5);
    assert_eq!(status(&harness, id).await, MessageStatus::Failed);
}

#[tokio::test]
async fn a_permanent_failure_stops_after_one_send() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Permanent);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(transport.sends(id), 1);
    assert_eq!(status(&harness, id).await, MessageStatus::Failed);
    assert_eq!(
        attempt_outcomes(&harness, id).await,
        vec![(
            1,
            1,
            "permanent".to_owned(),
            Some("recipient-refused".to_owned())
        )]
    );
}

/// A message past its `expiresAt` is expired unsent, whether it was still
/// queued or waiting for a retry.
#[tokio::test]
async fn a_message_past_its_expiry_is_expired_queued_or_waiting() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Transient(None));
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let waiting = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    let queued = harness.accepted(&email_submission()).await;
    for id in [waiting, queued] {
        harness
            .execute(
                "UPDATE messaging_messages \
                    SET accepted_at = now() - interval '2 hours', \
                        expires_at = now() - interval '1 hour' \
                  WHERE message_id = $1",
                &[&id],
            )
            .await;
    }
    make_due(&harness, waiting).await;
    for _ in 0..3 {
        let _ = dispatcher.dispatch_once(&sender).await.unwrap();
    }
    for id in [waiting, queued] {
        assert_eq!(status(&harness, id).await, MessageStatus::Expired, "{id}");
    }
    assert_eq!(transport.sends(waiting), 1);
    assert_eq!(transport.sends(queued), 0);
}

/// A row the claim cannot lease is quarantined out of the claim set, and
/// the healthy row behind it still sends.
#[tokio::test]
async fn a_poisoned_row_is_quarantined_while_a_healthy_one_sends() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let poisoned = harness.accepted(&email_submission()).await;
    let healthy = harness.accepted(&email_submission()).await;
    harness
        .execute(
            "UPDATE messaging_dispatch_jobs \
                SET attempt = 5, next_attempt_at = now() - interval '1 minute' \
              WHERE message_id = $1",
            &[&poisoned],
        )
        .await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(transport.sends(healthy), 1);
    assert_eq!(transport.sends(poisoned), 0);
    assert_eq!(status(&harness, poisoned).await, MessageStatus::Failed);
    let quarantined: Vec<Value> = harness
        .audit_responses()
        .await
        .into_iter()
        .filter(|record| record["event"] == "messaging.message.quarantined")
        .collect();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0]["messageId"], poisoned.to_string());
    assert_eq!(quarantined[0]["disposition"], "dead_lettered");
}

/// Start with the SMS sender profile, whose provider declares idempotent
/// submission, set to `onUncertain: retry`.
async fn retrying_sms_harness() -> Harness {
    Harness::start_with(Value::Null, |package| {
        let path = package.join("messaging.yaml");
        let source = std::fs::read_to_string(&path).unwrap();
        let mut manifest: Value = serde_norway::from_str(&source).unwrap();
        manifest["senderProfiles"][1]["onUncertain"] = Value::String("retry".to_owned());
        std::fs::write(path, serde_norway::to_string(&manifest).unwrap()).unwrap();
    })
    .await
}

/// The dispositions of every quarantine response recorded for `id`.
async fn quarantine_dispositions(harness: &Harness, id: Uuid) -> Vec<Value> {
    harness
        .audit_responses()
        .await
        .into_iter()
        .filter(|record| {
            record["event"] == "messaging.message.quarantined"
                && record["messageId"] == id.to_string()
        })
        .map(|record| record["disposition"].clone())
        .collect()
}

/// A leased row whose lapsed-lease recovery the database refuses may have
/// reached its provider, so it is quarantined unknown, never failed.
#[tokio::test]
async fn a_lapsed_lease_that_cannot_be_recovered_is_quarantined_unknown() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let poisoned = harness.accepted(&sms_submission()).await;
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    assert_eq!(leased.key.id(), poisoned);
    drop(leased);
    lapse_lease(&harness, poisoned).await;
    harness
        .execute(
            "CREATE FUNCTION refuse_lapsed_requeue() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF OLD.state = 'leased' AND NEW.state = 'pending' THEN \
                 RAISE EXCEPTION 'refused lapsed requeue'; \
               END IF; \
               RETURN NEW; \
             END $$",
            &[],
        )
        .await;
    harness
        .execute(
            "CREATE TRIGGER refuse_lapsed_requeue BEFORE UPDATE ON messaging_dispatch_jobs \
             FOR EACH ROW EXECUTE FUNCTION refuse_lapsed_requeue()",
            &[],
        )
        .await;
    let healthy = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    assert_eq!(transport.sends(healthy), 1);
    assert_eq!(transport.sends(poisoned), 0);
    assert_eq!(status(&harness, poisoned).await, MessageStatus::Unknown);
    assert_eq!(
        attempt_outcomes(&harness, poisoned).await,
        vec![(1, 1, "interrupted".to_owned(), None)]
    );
    assert_eq!(
        quarantine_dispositions(&harness, poisoned).await,
        vec![Value::from("unknown")]
    );
}

/// A pending row whose earlier attempt ended maybe-sent may have reached
/// its provider, so a claim that cannot lease it quarantines it unknown,
/// never failed.
#[tokio::test]
async fn a_poisoned_retry_after_a_maybe_sent_attempt_is_quarantined_unknown() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::MaybeSent);
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let poisoned = harness.accepted(&sms_submission()).await;
    dispatcher.dispatch_once(&sender).await.unwrap();
    assert_eq!(harness.state(poisoned).await, "pending");
    transport.answer(Script::Accepted);
    let healthy = harness.accepted(&sms_submission()).await;
    harness
        .execute(
            "UPDATE messaging_dispatch_jobs \
                SET attempt = 5, next_attempt_at = now() - interval '1 minute' \
              WHERE message_id = $1",
            &[&poisoned],
        )
        .await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    assert_eq!(transport.sends(healthy), 1);
    assert_eq!(transport.sends(poisoned), 1);
    assert_eq!(status(&harness, poisoned).await, MessageStatus::Unknown);
    assert_eq!(
        quarantine_dispositions(&harness, poisoned).await,
        vec![Value::from("unknown")]
    );
}

/// MESSAGING-SEC-06: under `onUncertain: retry` a message whose every
/// attempt ended maybe-sent retries until its attempts are spent, then stops
/// unknown for an operator to settle, never failed.
#[tokio::test]
async fn a_retrying_message_that_spends_its_attempts_maybe_sent_ends_unknown() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::MaybeSent);
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let id = harness.accepted(&sms_submission()).await;
    let mut attempts = 0;
    while harness.state(id).await == "pending" {
        assert!(attempts < 10, "the retries never stopped");
        make_due(&harness, id).await;
        dispatcher.dispatch_once(&sender).await.unwrap();
        attempts += 1;
    }
    assert!(attempts > 1, "the maybe-sent answer was retried");
    assert_eq!(transport.sends(id), attempts);
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);
    let outcomes = attempt_outcomes(&harness, id).await;
    assert_eq!(outcomes.len(), attempts);
    assert!(outcomes
        .iter()
        .all(|(_, _, outcome, _)| outcome == "maybe-sent"));
}

/// Dispatch `id` on its retrying profile until it leaves `pending`, and
/// return how many attempts it used.
async fn dispatch_until_settled(
    harness: &Harness,
    dispatcher: &MessageDispatcher,
    sender: &MessageSender,
    id: Uuid,
) -> usize {
    let mut attempts = 0;
    while harness.state(id).await == "pending" {
        assert!(attempts < 10, "the retries never stopped");
        make_due(harness, id).await;
        dispatcher.dispatch_once(sender).await.unwrap();
        attempts += 1;
    }
    attempts
}

/// MESSAGING-SEC-06: under `onUncertain: retry` a message whose first
/// attempt ended maybe-sent and whose later attempts failed transiently
/// until its attempts are spent stops unknown, never failed, since the
/// later failures do not prove the first attempt did not land.
#[tokio::test]
async fn a_retrying_message_spent_by_transient_failures_after_a_maybe_sent_attempt_ends_unknown() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::MaybeSent);
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let id = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    transport.answer(Script::Transient(None));
    let attempts = 1 + dispatch_until_settled(&harness, &dispatcher, &sender, id).await;
    assert!(attempts > 2, "the transient failures were retried");
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);
    let outcomes = attempt_outcomes(&harness, id).await;
    assert_eq!(outcomes.len(), attempts);
    assert_eq!(outcomes[0].2, "maybe-sent");
    assert!(outcomes[1..]
        .iter()
        .all(|(_, _, outcome, _)| outcome == "transient"));
}

/// MESSAGING-SEC-06: under `onUncertain: retry` a permanent refusal after an
/// attempt that ended maybe-sent stops the message unknown, never failed.
#[tokio::test]
async fn a_retrying_message_refused_permanently_after_a_maybe_sent_attempt_ends_unknown() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::MaybeSent);
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let id = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    transport.answer(Script::Permanent);
    make_due(&harness, id).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Unknown
    );
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);
    assert_eq!(
        attempt_outcomes(&harness, id)
            .await
            .into_iter()
            .map(|(_, _, outcome, _)| outcome)
            .collect::<Vec<_>>(),
        vec!["maybe-sent".to_owned(), "permanent".to_owned()]
    );
}

/// On the same retrying profile, a message whose every attempt failed
/// transiently until its attempts are spent still fails, as does one
/// refused permanently on its first attempt.
#[tokio::test]
async fn a_retrying_message_without_a_maybe_sent_attempt_still_fails() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::Transient(None));
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let spent = harness.accepted(&sms_submission()).await;
    let attempts = dispatch_until_settled(&harness, &dispatcher, &sender, spent).await;
    assert!(attempts > 1, "the transient failures were retried");
    assert_eq!(status(&harness, spent).await, MessageStatus::Failed);
    transport.answer(Script::Permanent);
    let refused = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );
    assert_eq!(status(&harness, refused).await, MessageStatus::Failed);
}

/// Moves a message's `expiresAt` into the past and its pending retry, if
/// any, to now, as a worker that fell behind would find it.
async fn lapse_expiry(harness: &Harness, id: Uuid) {
    harness
        .execute(
            "UPDATE messaging_messages \
                SET accepted_at = now() - interval '2 hours', \
                    expires_at = now() - interval '1 hour' \
              WHERE message_id = $1",
            &[&id],
        )
        .await;
    make_due(harness, id).await;
}

/// A retrying message whose retry reaches its expiry after an attempt that
/// may have been sent ends unknown for an operator to settle, never
/// expired, and is not sent again.
#[tokio::test]
async fn a_retrying_message_past_its_expiry_after_a_maybe_sent_attempt_ends_unknown() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::MaybeSent);
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let id = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    lapse_expiry(&harness, id).await;
    transport.answer(Script::Accepted);
    for _ in 0..3 {
        dispatcher.dispatch_once(&sender).await.unwrap();
    }
    assert_eq!(status(&harness, id).await, MessageStatus::Unknown);
    assert_eq!(transport.sends(id), 1);
    assert_eq!(
        attempt_outcomes(&harness, id)
            .await
            .into_iter()
            .map(|(_, _, outcome, _)| outcome)
            .collect::<Vec<_>>(),
        vec!["maybe-sent".to_owned()]
    );
}

/// On the same retrying profile, a message never attempted and one whose
/// attempts all failed transiently still expire unsent at their expiry.
#[tokio::test]
async fn a_retrying_message_past_its_expiry_without_a_maybe_sent_attempt_expires() {
    let harness = retrying_sms_harness().await;
    let transport = Scripted::new(Script::Transient(None));
    let (dispatcher, sender) = worker_for(&harness, "sms-gateway", Arc::clone(&transport));
    let transient = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    let queued = harness.accepted(&sms_submission()).await;
    for id in [transient, queued] {
        lapse_expiry(&harness, id).await;
    }
    for _ in 0..3 {
        dispatcher.dispatch_once(&sender).await.unwrap();
    }
    for id in [transient, queued] {
        assert_eq!(status(&harness, id).await, MessageStatus::Expired, "{id}");
    }
    assert_eq!(transport.sends(transient), 1);
    assert_eq!(transport.sends(queued), 0);
}

/// A provider with no registered transport fails the message permanently
/// without sending it anywhere.
#[tokio::test]
async fn a_message_for_an_unconfigured_provider_fails_without_a_send() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Accepted);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let id = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );
    assert_eq!(transport.total(), 0);
    assert_eq!(
        attempt_outcomes(&harness, id).await,
        vec![(
            1,
            1,
            "permanent".to_owned(),
            Some(PROVIDER_UNCONFIGURED.to_owned())
        )]
    );
}

/// An operator previews by default and acts only with `apply`: a failed
/// message is requeued under a new generation, an unknown outcome is
/// settled as sent or not sent, and a queued message is cancelled.
#[tokio::test]
async fn operator_actions_preview_by_default_and_apply_on_request() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Permanent);
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let messages = harness.service.messages();

    let failed = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );
    let preview = messages
        .operate(failed, OperatorAction::Retry, false)
        .await
        .unwrap()
        .unwrap();
    assert!(preview.eligible && !preview.applied);
    assert_eq!(preview.next_status, Some(MessageStatus::Queued));
    assert_eq!(status(&harness, failed).await, MessageStatus::Failed);
    let settle = messages
        .operate(failed, OperatorAction::Settle(SettleOutcome::Sent), true)
        .await
        .unwrap()
        .unwrap();
    assert!(!settle.eligible && !settle.applied);
    let retried = messages
        .operate(failed, OperatorAction::Retry, true)
        .await
        .unwrap()
        .unwrap();
    assert!(retried.applied);
    assert_eq!(retried.next_generation, Some(2));
    transport.answer(Script::Accepted);
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    assert_eq!(status(&harness, failed).await, MessageStatus::Submitted);
    assert_eq!(transport.sends(failed), 2);

    transport.answer(Script::MaybeSent);
    let uncertain = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Unknown
    );
    let sent = messages
        .operate(uncertain, OperatorAction::Settle(SettleOutcome::Sent), true)
        .await
        .unwrap()
        .unwrap();
    assert!(sent.applied);
    assert_eq!(sent.next_status, Some(MessageStatus::Submitted));
    assert_eq!(status(&harness, uncertain).await, MessageStatus::Submitted);
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    assert_eq!(transport.sends(uncertain), 1);

    let queued = harness.accepted(&email_submission()).await;
    let cancel = messages
        .operate(queued, OperatorAction::Cancel, false)
        .await
        .unwrap()
        .unwrap();
    assert!(cancel.eligible && !cancel.applied);
    assert_eq!(status(&harness, queued).await, MessageStatus::Queued);
    let cancel = messages
        .operate(queued, OperatorAction::Cancel, true)
        .await
        .unwrap()
        .unwrap();
    assert!(cancel.applied);
    assert_eq!(status(&harness, queued).await, MessageStatus::Cancelled);
    assert!(messages
        .operate(Uuid::new_v4(), OperatorAction::Cancel, true)
        .await
        .unwrap()
        .is_none());

    harness.publish().await;
    let action_ids = [
        failed.to_string(),
        uncertain.to_string(),
        queued.to_string(),
    ];
    let operator_entries: Vec<Value> = harness
        .journal()
        .into_iter()
        .filter(|entry| entry["record"]["actor"]["kind"] == "operator-tool")
        .filter(|entry| {
            action_ids
                .iter()
                .any(|id| entry["record"]["messageId"] == id.as_str())
        })
        .collect();
    // Each applied action has exactly one request and one established
    // response. The previews above produced no entries.
    assert_eq!(operator_entries.len(), 6, "{operator_entries:?}");
    for id in action_ids {
        let entries: Vec<&Value> = operator_entries
            .iter()
            .filter(|entry| entry["record"]["messageId"] == id)
            .collect();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    }
    assert!(operator_entries.iter().any(|entry| {
        entry["record"]["event"] == "messaging.message.settled" && entry["phase"] == "response"
    }));
}

/// Attempts, transitions, quarantines, and settlements journal
/// identifiers, classes, and dispositions only.
#[tokio::test]
async fn no_contact_content_data_or_credential_reaches_the_dispatch_journal_or_log() {
    let harness = Harness::start().await;
    let transport = Scripted::new(Script::Transient(None));
    let (dispatcher, sender) = worker_over(&harness, Arc::clone(&transport));
    let retried = harness.accepted(&email_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::RetryScheduled
    );
    make_due(&harness, retried).await;
    transport.answer(Script::Accepted);
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Delivered
    );
    let unconfigured = harness.accepted(&sms_submission()).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::DeadLettered
    );
    let lapsed = harness.accepted(&email_submission()).await;
    let _lease = dispatcher.claim().await.unwrap().leased().unwrap();
    lapse_lease(&harness, lapsed).await;
    assert_eq!(
        dispatcher.dispatch_once(&sender).await.unwrap(),
        DispatchOutcome::Idle
    );
    harness
        .service
        .messages()
        .operate(lapsed, OperatorAction::Settle(SettleOutcome::NotSent), true)
        .await
        .unwrap()
        .unwrap();
    harness
        .service
        .messages()
        .operate(unconfigured, OperatorAction::Retry, true)
        .await
        .unwrap()
        .unwrap();
    harness.publish().await;

    let journal = harness.journal();
    let events: Vec<&str> = journal
        .iter()
        .filter_map(|entry| entry["record"]["event"].as_str())
        .collect();
    for expected in [
        "messaging.attempt.started",
        "messaging.attempt.finished",
        "messaging.dispatch.transition",
    ] {
        assert!(
            events.contains(&expected),
            "{expected} missing from {events:?}"
        );
    }
    support::assert_absent("the journal", &Value::Array(journal));
    support::assert_absent(
        "the audit responses",
        &Value::Array(harness.audit_responses().await),
    );
    assert!(
        !serde_json::to_string(&harness.audit_responses().await)
            .unwrap()
            .contains("provider-ref-1"),
        "the provider reference is kept for receipts, never journaled"
    );
    // The unconfigured provider was reported, by its failure code only.
    assert!(support::captured_logs().contains(PROVIDER_UNCONFIGURED));
    support::assert_logs_clean();
}

#[tokio::test]
async fn a_shutdown_finishes_the_send_in_flight_and_claims_nothing_more() {
    let harness = Harness::start().await;
    let transport = Scripted::slow(Duration::from_millis(500));
    let mut transports = Transports::new();
    transports.insert("mail-relay", transport.clone()).unwrap();
    let in_flight = harness.accepted(&email_submission()).await;
    // The served runtime writes its own journal beside the harness's.
    let journal = tempfile::tempdir().unwrap();
    let mut config = harness.config.clone();
    config.audit.path = Some(journal.path().join("audit.jsonl"));
    let listeners = Listeners::bind(&config).await.unwrap();
    let app = assemble(&config, transports).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(listeners.serve_until(app, async {
        stopped.await.expect("the test requests the shutdown");
    }));
    tokio::time::timeout(Duration::from_secs(10), async {
        while transport.started.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the worker starts the send");

    stop.send(()).unwrap();
    let after = harness.accepted(&email_submission()).await;
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the runtime stops once the send in flight finishes")
        .unwrap()
        .expect("a requested shutdown is a clean stop");
    assert_eq!(transport.sends(in_flight), 1);
    assert_eq!(harness.state(in_flight).await, "delivered");
    assert_eq!(transport.sends(after), 0);
    assert_eq!(harness.state(after).await, "pending");
}
