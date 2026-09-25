// SPDX-License-Identifier: Apache-2.0

//! Database-backed dispatch tests: a test consumer that owns its job table,
//! its message table, and its audit table, driven through the dispatch core
//! against a real PostgreSQL server.
//!
//! The consumer stands in for a product that is not the hook worker: its
//! jobs carry a backoff profile with optional jitter, an uncertain-outcome
//! policy, and an expiry, and its transport answers with every
//! [`SendOutcome`]. Every test runs in its own schema inside the database
//! named by `DISPATCH_TEST_DATABASE_URL`. A test binary that passes because
//! its database URL is absent is not database verification, so the variable
//! is required: without it every test in this file fails on the spot.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_platform_dispatch::postgres::{
    enqueue, AttemptAudit, CancelOutcome, Claim, ClaimRefusal, Columns, Decoded, DispatchConfig,
    DispatchConnection, DispatchEvent, DispatchOutcome, DispatchSql, DispatchStore,
    DispatchTransport, DispatchWorker, Dispatcher, ExpirySql, JobKey, JobState, JobTable,
    LeasedJob, Quarantine, QuarantineDisposition, QuarantineReason, SelectSql, TargetAction,
    TransitionAudit, TransitionCode, WorkerConfig,
};
use registry_platform_dispatch::{
    idempotency_key, AttemptTimeoutBound, Backoff, DispatchError, FailureCode, Jitter, JobPolicy,
    ReceiverReference, RetrySchedule, SendOutcome, Sent, UncertainOutcome,
};
use tokio::sync::watch;
use tokio_postgres::{NoTls, Row, Transaction};
use uuid::Uuid;

const JOB_TABLE: &str = "test_message_jobs";
const RECIPIENT: &str = "recipient-1";

const MESSAGE_JOIN: &str =
    "JOIN {schema}.test_messages AS message ON message.message_id = state.message_id";
const POLICY_COLUMNS: &str = "message.attempt_timeout_ms, message.maximum_attempts,
     message.initial_backoff_ms, message.maximum_backoff_ms, message.jitter,
     message.on_uncertain, message.expires_at";
const CLAIM_COLUMNS: &str = "message.attempt_timeout_ms, message.maximum_attempts,
     message.initial_backoff_ms, message.maximum_backoff_ms, message.jitter,
     message.on_uncertain, message.expires_at, message.body";

fn database_url() -> String {
    std::env::var("DISPATCH_TEST_DATABASE_URL")
        .expect("DISPATCH_TEST_DATABASE_URL names a disposable PostgreSQL test server")
}

async fn connect(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("the test database accepts a connection");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("test database connection failed: {error}");
        }
    });
    client
}

/// One isolated schema holding the consumer's three tables.
struct Harness {
    url: String,
    schema: String,
    table: JobTable,
    admin: tokio_postgres::Client,
    events: Arc<Mutex<Vec<DispatchEvent>>>,
}

async fn harness() -> Harness {
    let url = database_url();
    let schema = format!("dispatch_{}", Uuid::new_v4().simple());
    let admin = connect(&url).await;
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema};
             CREATE TABLE {schema}.test_messages (
                 message_id uuid PRIMARY KEY,
                 body text NOT NULL,
                 attempt_timeout_ms bigint NOT NULL,
                 maximum_attempts smallint NOT NULL,
                 initial_backoff_ms bigint NOT NULL,
                 maximum_backoff_ms bigint NOT NULL,
                 jitter boolean NOT NULL,
                 on_uncertain text NOT NULL CHECK (on_uncertain IN ('hold', 'retry')),
                 expires_at timestamptz NOT NULL
             );
             CREATE TABLE {schema}.test_audit (
                 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                 message_id uuid NOT NULL,
                 recipient text NOT NULL,
                 generation bigint NOT NULL,
                 attempt smallint NOT NULL,
                 point text NOT NULL,
                 disposition text NOT NULL
             );"
        ))
        .await
        .expect("the consumer tables install");
    let table = JobTable::new(&schema, JOB_TABLE, "message_id", "recipient")
        .expect("the consumer names a valid job table");
    for statement in table.create_statements() {
        admin
            .batch_execute(&statement)
            .await
            .expect("the job table installs");
    }
    admin
        .batch_execute(&format!(
            "ALTER TABLE {schema}.{JOB_TABLE}
                 ADD COLUMN provider_reference text,
                 ADD COLUMN failure_code text,
                 ADD FOREIGN KEY (message_id) REFERENCES {schema}.test_messages (message_id)"
        ))
        .await
        .expect("the consumer extends its job table with its own columns");
    Harness {
        url,
        schema,
        table,
        admin,
        events: Arc::new(Mutex::new(Vec::new())),
    }
}

#[derive(Clone)]
struct TestStore {
    url: String,
    schema: String,
    events: Arc<Mutex<Vec<DispatchEvent>>>,
    quarantine: QuarantineMode,
}

/// Whether and how the test consumer quarantines a row the core cannot
/// take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuarantineMode {
    /// The consumer keeps the default: the core never quarantines.
    Unsupported,
    /// The consumer moves the row to a terminal state and audits it.
    Terminal,
    /// The consumer reports a quarantine but leaves the row claimable.
    Claimable,
}

struct TestJob {
    body: String,
}

fn decode_policy(row: &Row, first: usize) -> Result<JobPolicy, DispatchError> {
    let timeout_ms = row.try_get::<_, i64>(first)?;
    let maximum_attempts = row.try_get::<_, i16>(first + 1)?;
    let initial_ms = row.try_get::<_, i64>(first + 2)?;
    let maximum_ms = row.try_get::<_, i64>(first + 3)?;
    let jitter = row.try_get::<_, bool>(first + 4)?;
    let on_uncertain = row.try_get::<_, String>(first + 5)?;
    let expires_at = row.try_get::<_, SystemTime>(first + 6)?;
    let millis = |value: i64| {
        u64::try_from(value)
            .map(Duration::from_millis)
            .map_err(|_| DispatchError::Unavailable)
    };
    Ok(JobPolicy {
        attempt_timeout: millis(timeout_ms)?,
        maximum_attempts,
        retry: RetrySchedule::Backoff(Backoff {
            initial: millis(initial_ms)?,
            maximum: millis(maximum_ms)?,
            multiplier: 2,
            jitter: if jitter { Jitter::Equal } else { Jitter::None },
        }),
        on_uncertain: match on_uncertain.as_str() {
            "hold" => UncertainOutcome::Hold,
            "retry" => UncertainOutcome::Retry,
            _ => return Err(DispatchError::Unavailable),
        },
        expires_at: Some(expires_at),
    })
}

#[async_trait]
impl DispatchStore for TestStore {
    type Job = TestJob;
    type Record = ();
    type Detail = ();

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls).await?;
        tokio::spawn(async move {
            // A dropped connection surfaces as the next query's error.
            let _closed = connection.await;
        });
        Ok(Box::new(Box::new(client)))
    }

    async fn verify_transaction(
        &self,
        _transaction: &Transaction<'_>,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    fn claim_record(&self, _job: &TestJob) {}

    fn decode_claim(&self, row: &Row, first: usize) -> Result<Decoded<TestJob>, ClaimRefusal> {
        let policy = decode_policy(row, first).map_err(|_| ClaimRefusal::Unavailable)?;
        let body = row
            .try_get::<_, String>(first + 7)
            .map_err(|_| ClaimRefusal::Unavailable)?;
        Ok(Decoded {
            policy,
            job: TestJob { body },
        })
    }

    fn decode_lapsed(&self, row: &Row, first: usize) -> Result<Decoded<()>, DispatchError> {
        Ok(Decoded {
            policy: decode_policy(row, first)?,
            job: (),
        })
    }

    fn decode_expired(&self, _row: &Row, _first: usize) -> Result<(), DispatchError> {
        Ok(())
    }

    fn decode_target(
        &self,
        _row: &Row,
        _first: usize,
        _key: &JobKey,
        _action: TargetAction,
    ) -> Result<Option<()>, DispatchError> {
        Ok(Some(()))
    }

    async fn record_attempt_audit(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<TestJob>,
        audit: AttemptAudit<'_, ()>,
    ) -> Result<(), DispatchError> {
        let (point, disposition) = match audit {
            AttemptAudit::Started => ("attempt_started", "leased"),
            AttemptAudit::Finished { disposition, .. } => {
                ("attempt_finished", disposition.as_str())
            }
        };
        self.audit(
            transaction,
            &job.key,
            job.generation,
            job.attempt,
            point,
            disposition,
        )
        .await
    }

    async fn record_transition_audit(
        &self,
        transaction: &Transaction<'_>,
        audit: TransitionAudit<'_, ()>,
    ) -> Result<(), DispatchError> {
        self.audit(
            transaction,
            audit.key,
            audit.generation,
            audit.attempt,
            audit.transition.as_str(),
            audit.transition.disposition().as_str(),
        )
        .await
    }

    fn operational_event(&self, event: DispatchEvent) {
        self.events.lock().expect("events lock").push(event);
    }

    fn finished_columns(
        &self,
        _job: &LeasedJob<TestJob>,
        sent: &Sent<()>,
        _disposition: registry_platform_dispatch::postgres::Disposition,
    ) -> Result<Columns, DispatchError> {
        Ok(match &sent.outcome {
            SendOutcome::Accepted {
                receiver_reference: Some(reference),
            } => Columns::new().set("provider_reference", reference.as_str().to_owned()),
            SendOutcome::Permanent { code } => {
                Columns::new().set("failure_code", code.as_str().to_owned())
            }
            _ => Columns::new(),
        })
    }

    fn quarantines(&self) -> bool {
        self.quarantine != QuarantineMode::Unsupported
    }

    async fn quarantine(
        &self,
        transaction: &Transaction<'_>,
        quarantine: Quarantine<'_>,
    ) -> Result<QuarantineDisposition, DispatchError> {
        let (state, stamp) = if quarantine.attempt > 0 {
            (JobState::DeadLettered, "dead_lettered_at")
        } else {
            (JobState::Expired, "expired_at")
        };
        match self.quarantine {
            QuarantineMode::Unsupported => return Ok(QuarantineDisposition::Unsupported),
            QuarantineMode::Claimable => {}
            QuarantineMode::Terminal => {
                let changed = transaction
                    .execute(
                        &format!(
                            "UPDATE {}.{JOB_TABLE}
                                SET state = $4,
                                    next_attempt_at = NULL,
                                    attempt_started_at = NULL,
                                    lease_expires_at = NULL,
                                    lease_token = NULL,
                                    {stamp} = transaction_timestamp(),
                                    updated_at = transaction_timestamp()
                              WHERE message_id = $1 AND recipient = $2 AND generation = $3",
                            self.schema
                        ),
                        &[
                            &quarantine.key.id(),
                            &quarantine.key.part(),
                            &quarantine.generation,
                            &state.as_str(),
                        ],
                    )
                    .await?;
                if changed != 1 {
                    return Err(DispatchError::Unavailable);
                }
            }
        }
        self.audit(
            transaction,
            quarantine.key,
            quarantine.generation,
            quarantine.attempt,
            "quarantined",
            state.as_str(),
        )
        .await?;
        Ok(QuarantineDisposition::Quarantined(state))
    }
}

impl TestStore {
    async fn audit(
        &self,
        transaction: &Transaction<'_>,
        key: &JobKey,
        generation: i64,
        attempt: i16,
        point: &str,
        disposition: &str,
    ) -> Result<(), DispatchError> {
        transaction
            .execute(
                &format!(
                    "INSERT INTO {}.test_audit
                         (message_id, recipient, generation, attempt, point, disposition)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    self.schema
                ),
                &[
                    &key.id(),
                    &key.part(),
                    &generation,
                    &attempt,
                    &point,
                    &disposition,
                ],
            )
            .await?;
        Ok(())
    }
}

fn dispatch_sql() -> DispatchSql {
    DispatchSql {
        claim: SelectSql {
            columns: CLAIM_COLUMNS,
            joins: MESSAGE_JOIN,
            predicate: "message.expires_at > transaction_timestamp()",
        },
        lapsed: SelectSql {
            columns: POLICY_COLUMNS,
            joins: MESSAGE_JOIN,
            predicate: "TRUE",
        },
        expiry: Some(ExpirySql {
            states: &[JobState::Pending],
            select: SelectSql {
                columns: "",
                joins: MESSAGE_JOIN,
                predicate: "message.expires_at <= transaction_timestamp()",
            },
            order_by: "message.expires_at",
            lock_of: "state",
        }),
        target: SelectSql {
            columns: "",
            joins: "",
            predicate: "TRUE",
        },
    }
}

fn dispatcher(harness: &Harness) -> Dispatcher<TestStore> {
    quarantining_dispatcher(harness, QuarantineMode::Unsupported)
}

fn quarantining_dispatcher(harness: &Harness, quarantine: QuarantineMode) -> Dispatcher<TestStore> {
    Dispatcher::new(
        TestStore {
            url: harness.url.clone(),
            schema: harness.schema.clone(),
            events: Arc::clone(&harness.events),
            quarantine,
        },
        DispatchConfig {
            table: harness.table.clone(),
            sql: dispatch_sql(),
            attempt_timeout: AttemptTimeoutBound::new(
                Duration::from_millis(100),
                Duration::from_secs(60),
            )
            .expect("the consumer's bound is within the core ceiling"),
            replayable: &[JobState::DeadLettered, JobState::Unknown],
        },
    )
    .expect("the consumer's configuration is valid")
}

/// The captured policy and timing of one test message.
struct Message {
    attempt_timeout_ms: i64,
    maximum_attempts: i16,
    initial_backoff_ms: i64,
    maximum_backoff_ms: i64,
    jitter: bool,
    on_uncertain: &'static str,
    expires_in_ms: i64,
    not_before: Option<Duration>,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            attempt_timeout_ms: 5_000,
            maximum_attempts: 3,
            initial_backoff_ms: 1_000,
            maximum_backoff_ms: 4_000,
            jitter: false,
            on_uncertain: "hold",
            expires_in_ms: 3_600_000,
            not_before: None,
        }
    }
}

async fn enqueue_message(harness: &Harness, message: &Message) -> JobKey {
    let mut client = connect(&harness.url).await;
    let transaction = client.transaction().await.expect("transaction");
    let id = Uuid::new_v4();
    transaction
        .execute(
            &format!(
                "INSERT INTO {}.test_messages
                     (message_id, body, attempt_timeout_ms, maximum_attempts,
                      initial_backoff_ms, maximum_backoff_ms, jitter, on_uncertain,
                      expires_at)
                 VALUES ($1, 'hello', $2, $3, $4, $5, $6, $7,
                         transaction_timestamp() + $8::bigint * interval '1 millisecond')",
                harness.schema
            ),
            &[
                &id,
                &message.attempt_timeout_ms,
                &message.maximum_attempts,
                &message.initial_backoff_ms,
                &message.maximum_backoff_ms,
                &message.jitter,
                &message.on_uncertain,
                &message.expires_in_ms,
            ],
        )
        .await
        .expect("the message inserts");
    let key = JobKey::new(id, RECIPIENT).expect("a bounded key");
    let not_before = message.not_before.map(|delay| SystemTime::now() + delay);
    enqueue(&transaction, &harness.table, &key, not_before)
        .await
        .expect("the job enqueues");
    transaction.commit().await.expect("commit");
    key
}

struct StateRow {
    state: String,
    generation: i64,
    attempt: i16,
    lease_token: Option<Uuid>,
    provider_reference: Option<String>,
    failure_code: Option<String>,
}

async fn state_row(harness: &Harness, key: &JobKey) -> StateRow {
    let row = harness
        .admin
        .query_one(
            &format!(
                "SELECT state, generation, attempt, lease_token, provider_reference,
                        failure_code
                   FROM {}.{JOB_TABLE}
                  WHERE message_id = $1 AND recipient = $2",
                harness.schema
            ),
            &[&key.id(), &key.part()],
        )
        .await
        .expect("the job row exists");
    StateRow {
        state: row.get(0),
        generation: row.get(1),
        attempt: row.get(2),
        lease_token: row.get(3),
        provider_reference: row.get(4),
        failure_code: row.get(5),
    }
}

async fn audit_trail(harness: &Harness, key: &JobKey) -> Vec<String> {
    harness
        .admin
        .query(
            &format!(
                "SELECT point, disposition, generation, attempt
                   FROM {}.test_audit
                  WHERE message_id = $1 AND recipient = $2
                  ORDER BY sequence",
                harness.schema
            ),
            &[&key.id(), &key.part()],
        )
        .await
        .expect("the audit trail reads")
        .iter()
        .map(|row| {
            format!(
                "{}:{}:g{}:a{}",
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, i64>(2),
                row.get::<_, i16>(3)
            )
        })
        .collect()
}

/// The retry delay the last transition scheduled, in milliseconds.
async fn scheduled_delay_ms(harness: &Harness, key: &JobKey) -> i64 {
    harness
        .admin
        .query_one(
            &format!(
                "SELECT (extract(epoch FROM next_attempt_at - updated_at) * 1000)::bigint
                   FROM {}.{JOB_TABLE}
                  WHERE message_id = $1 AND recipient = $2 AND state = 'pending'",
                harness.schema
            ),
            &[&key.id(), &key.part()],
        )
        .await
        .expect("the job is pending a retry")
        .get(0)
}

/// Move a live lease into the past, as if the worker holding it stalled.
async fn lapse_lease(harness: &Harness, key: &JobKey) {
    let changed = harness
        .admin
        .execute(
            &format!(
                "UPDATE {}.{JOB_TABLE}
                    SET attempt_started_at = transaction_timestamp() - interval '10 seconds',
                        lease_expires_at = transaction_timestamp() - interval '1 second'
                  WHERE message_id = $1 AND recipient = $2 AND state = 'leased'",
                harness.schema
            ),
            &[&key.id(), &key.part()],
        )
        .await
        .expect("the lease moves");
    assert_eq!(changed, 1, "exactly one live lease lapses");
}

/// Make a scheduled retry due now.
async fn make_due(harness: &Harness, key: &JobKey) {
    let changed = harness
        .admin
        .execute(
            &format!(
                "UPDATE {}.{JOB_TABLE}
                    SET next_attempt_at = transaction_timestamp() - interval '1 millisecond'
                  WHERE message_id = $1 AND recipient = $2 AND state = 'pending'",
                harness.schema
            ),
            &[&key.id(), &key.part()],
        )
        .await
        .expect("the retry moves");
    assert_eq!(changed, 1, "exactly one pending retry becomes due");
}

type Script = Box<dyn Fn(&LeasedJob<TestJob>) -> SendOutcome + Send + Sync>;

/// A transport that answers from a script and records what it sent.
struct ScriptedTransport {
    script: Script,
    pause: Duration,
    sends: Mutex<Vec<(JobKey, i64, i16)>>,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

impl ScriptedTransport {
    fn new(script: impl Fn(&LeasedJob<TestJob>) -> SendOutcome + Send + Sync + 'static) -> Self {
        Self {
            script: Box::new(script),
            pause: Duration::ZERO,
            sends: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    fn pausing(mut self, pause: Duration) -> Self {
        self.pause = pause;
        self
    }

    fn sends(&self) -> Vec<(JobKey, i64, i16)> {
        self.sends.lock().expect("sends lock").clone()
    }
}

#[async_trait]
impl DispatchTransport for ScriptedTransport {
    type Job = TestJob;
    type Detail = ();

    async fn send(&self, job: &LeasedJob<TestJob>) -> Result<Sent<()>, DispatchError> {
        assert_eq!(
            job.job.body, "hello",
            "the claim decoded the consumer's job"
        );
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.sends
            .lock()
            .expect("sends lock")
            .push((job.key.clone(), job.generation, job.attempt));
        if !self.pause.is_zero() {
            tokio::time::sleep(self.pause).await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(Sent {
            outcome: (self.script)(job),
            detail: (),
        })
    }
}

fn accepted() -> SendOutcome {
    SendOutcome::Accepted {
        receiver_reference: None,
    }
}

fn transient() -> SendOutcome {
    SendOutcome::Transient { retry_after: None }
}

#[tokio::test]
async fn the_attempt_is_committed_and_audited_before_egress() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);

    let job = dispatcher
        .claim()
        .await
        .expect("the claim succeeds")
        .leased()
        .expect("one job is due");
    // Another connection sees the lease and the attempt audit before any
    // send happens: both committed with the claim.
    let observed = state_row(&harness, &key).await;
    assert_eq!(observed.state, "leased");
    assert_eq!(observed.lease_token, Some(job.lease_token));
    assert_eq!(observed.attempt, 1);
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec!["attempt_started:leased:g1:a1"]
    );

    let outcome = dispatcher
        .finish(
            &job,
            Sent {
                outcome: SendOutcome::Accepted {
                    receiver_reference: Some(
                        ReceiverReference::new("SM0123abcd").expect("bounded reference"),
                    ),
                },
                detail: (),
            },
        )
        .await
        .expect("the finish commits");
    assert_eq!(outcome, DispatchOutcome::Delivered);
    let finished = state_row(&harness, &key).await;
    assert_eq!(finished.state, "delivered");
    assert_eq!(finished.provider_reference.as_deref(), Some("SM0123abcd"));
    assert_eq!(finished.lease_token, None);
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec![
            "attempt_started:leased:g1:a1",
            "attempt_finished:delivered:g1:a1"
        ]
    );
}

#[tokio::test]
async fn a_lapsed_lease_on_a_hold_job_is_unknown_and_never_retried() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);

    let _stalled = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("one job is due");
    lapse_lease(&harness, &key).await;
    // The next claim reaps the lapsed lease. The provider may have accepted
    // the send, so the job is held as unknown rather than sent again.
    assert!(matches!(
        dispatcher.claim().await.expect("claim"),
        Claim::Idle
    ));
    let reaped = state_row(&harness, &key).await;
    assert_eq!(reaped.state, "unknown");
    assert_eq!(reaped.attempt, 1);
    assert_eq!(reaped.lease_token, None);
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec!["attempt_started:leased:g1:a1", "lease_lapsed:unknown:g1:a1"]
    );

    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher
            .dispatch_once(&transport)
            .await
            .expect("dispatch"),
        DispatchOutcome::Idle
    );
    assert!(
        transport.sends().is_empty(),
        "an unknown job is never sent again"
    );
}

#[tokio::test]
async fn a_lapsed_lease_on_a_retry_job_is_rescheduled() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            on_uncertain: "retry",
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);

    let _stalled = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    lapse_lease(&harness, &key).await;
    assert!(matches!(
        dispatcher.claim().await.expect("claim"),
        Claim::Idle
    ));
    let reaped = state_row(&harness, &key).await;
    assert_eq!(reaped.state, "pending");
    assert_eq!(scheduled_delay_ms(&harness, &key).await, 1_000);
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec![
            "attempt_started:leased:g1:a1",
            "lease_lapsed:retry_pending:g1:a1"
        ]
    );
}

#[tokio::test]
async fn equal_jitter_keeps_every_retry_inside_its_bounds() {
    let harness = harness().await;
    let mut keys = Vec::new();
    for _ in 0..24 {
        keys.push(
            enqueue_message(
                &harness,
                &Message {
                    jitter: true,
                    initial_backoff_ms: 1_000,
                    maximum_backoff_ms: 10_000,
                    ..Message::default()
                },
            )
            .await,
        );
    }
    let steady = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| transient());
    for _ in 0..25 {
        assert_eq!(
            dispatcher
                .dispatch_once(&transport)
                .await
                .expect("dispatch"),
            DispatchOutcome::RetryScheduled
        );
    }

    let mut delays = BTreeSet::new();
    for key in &keys {
        let delay = scheduled_delay_ms(&harness, key).await;
        assert!(
            (500..=1_000).contains(&delay),
            "equal jitter stays within half to all of the base delay, got {delay}"
        );
        delays.insert(delay);
    }
    assert!(delays.len() > 1, "jitter spreads the retries");
    assert_eq!(
        scheduled_delay_ms(&harness, &steady).await,
        1_000,
        "a job without jitter keeps the exact base delay"
    );

    // The second failure doubles the base. The jittered retries fall due
    // within a second, so they are parked to leave the steady job first.
    harness
        .admin
        .execute(
            &format!(
                "UPDATE {}.{JOB_TABLE}
                    SET next_attempt_at = transaction_timestamp() + interval '1 hour'
                  WHERE message_id <> $1 AND state = 'pending'",
                harness.schema
            ),
            &[&steady.id()],
        )
        .await
        .expect("the jittered retries are parked");
    make_due(&harness, &steady).await;
    let second = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("the steady job is due again");
    assert_eq!(second.key, steady);
    assert_eq!(
        dispatcher
            .finish(
                &second,
                Sent {
                    outcome: transient(),
                    detail: ()
                }
            )
            .await
            .expect("finish"),
        DispatchOutcome::RetryScheduled
    );
    assert_eq!(scheduled_delay_ms(&harness, &steady).await, 2_000);
}

#[tokio::test]
async fn retry_after_is_honoured_up_to_the_maximum_backoff() {
    let harness = harness().await;
    let far = enqueue_message(&harness, &Message::default()).await;
    let near = enqueue_message(&harness, &Message::default()).await;
    let short = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let hints = BTreeMap::from([
        (far.clone(), Duration::from_secs(60)),
        (near.clone(), Duration::from_millis(2_500)),
        (short.clone(), Duration::from_millis(200)),
    ]);
    let transport = ScriptedTransport::new(move |job| SendOutcome::Transient {
        retry_after: Some(hints[&job.key]),
    });
    for _ in 0..3 {
        assert_eq!(
            dispatcher
                .dispatch_once(&transport)
                .await
                .expect("dispatch"),
            DispatchOutcome::RetryScheduled
        );
    }
    assert_eq!(
        scheduled_delay_ms(&harness, &far).await,
        4_000,
        "a hint past the maximum backoff is capped at the maximum"
    );
    assert_eq!(
        scheduled_delay_ms(&harness, &near).await,
        2_500,
        "a hint inside the maximum is honoured"
    );
    assert_eq!(
        scheduled_delay_ms(&harness, &short).await,
        1_000,
        "a hint shorter than the backoff never shortens it"
    );
}

#[tokio::test]
async fn a_retry_that_would_land_after_expiry_expires_the_job() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            expires_in_ms: 3_000,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| SendOutcome::Transient {
        retry_after: Some(Duration::from_secs(60)),
    });
    assert_eq!(
        dispatcher
            .dispatch_once(&transport)
            .await
            .expect("dispatch"),
        DispatchOutcome::Expired
    );
    assert_eq!(state_row(&harness, &key).await.state, "expired");
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec![
            "attempt_started:leased:g1:a1",
            "attempt_finished:expired:g1:a1"
        ]
    );
}

#[tokio::test]
async fn a_permanent_failure_stops_without_a_retry() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            maximum_attempts: 5,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| SendOutcome::Permanent {
        code: FailureCode::new("recipient.rejected").expect("bounded code"),
    });
    assert_eq!(
        dispatcher
            .dispatch_once(&transport)
            .await
            .expect("dispatch"),
        DispatchOutcome::DeadLettered
    );
    assert_eq!(
        dispatcher
            .dispatch_once(&transport)
            .await
            .expect("dispatch"),
        DispatchOutcome::Idle
    );
    assert_eq!(
        transport.sends().len(),
        1,
        "four attempts remain and none is used"
    );
    let row = state_row(&harness, &key).await;
    assert_eq!(row.state, "dead_lettered");
    assert_eq!(row.failure_code.as_deref(), Some("recipient.rejected"));
}

#[tokio::test]
async fn a_maybe_sent_outcome_follows_the_job_policy() {
    let harness = harness().await;
    let held = enqueue_message(&harness, &Message::default()).await;
    let retried = enqueue_message(
        &harness,
        &Message {
            on_uncertain: "retry",
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| SendOutcome::MaybeSent);
    let mut outcomes = BTreeSet::new();
    for _ in 0..2 {
        outcomes.insert(format!(
            "{:?}",
            dispatcher
                .dispatch_once(&transport)
                .await
                .expect("dispatch")
        ));
    }
    assert_eq!(
        outcomes,
        BTreeSet::from(["RetryScheduled".to_owned(), "Unknown".to_owned()])
    );
    assert_eq!(state_row(&harness, &held).await.state, "unknown");
    assert_eq!(state_row(&harness, &retried).await.state, "pending");
}

#[tokio::test]
async fn an_exhausted_transient_failure_dead_letters() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            maximum_attempts: 2,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| transient());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await.expect("first"),
        DispatchOutcome::RetryScheduled
    );
    make_due(&harness, &key).await;
    assert_eq!(
        dispatcher.dispatch_once(&transport).await.expect("second"),
        DispatchOutcome::DeadLettered
    );
    let row = state_row(&harness, &key).await;
    assert_eq!(row.state, "dead_lettered");
    assert_eq!(row.attempt, 2);
}

#[tokio::test]
async fn cancel_first_wins_over_a_later_claim() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    assert_eq!(
        dispatcher.cancel(&key).await.expect("cancel"),
        CancelOutcome::Cancelled
    );
    assert!(matches!(
        dispatcher.claim().await.expect("claim"),
        Claim::Idle
    ));
    assert_eq!(state_row(&harness, &key).await.state, "cancelled");
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec!["cancelled:cancelled:g1:a0"]
    );
}

#[tokio::test]
async fn a_claimed_job_can_no_longer_be_cancelled() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let job = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    assert_eq!(
        dispatcher.cancel(&key).await.expect("cancel"),
        CancelOutcome::NotCancellable(JobState::Leased)
    );
    assert_eq!(
        dispatcher
            .finish(
                &job,
                Sent {
                    outcome: accepted(),
                    detail: ()
                }
            )
            .await
            .expect("finish"),
        DispatchOutcome::Delivered
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_racing_a_claim_never_lets_both_win() {
    let harness = harness().await;
    let dispatcher = dispatcher(&harness);
    for _ in 0..20 {
        let key = enqueue_message(&harness, &Message::default()).await;
        let claimer = dispatcher.clone();
        let canceller = dispatcher.clone();
        let cancel_key = key.clone();
        let (claimed, cancelled) = tokio::join!(
            tokio::spawn(async move { claimer.claim().await }),
            tokio::spawn(async move { canceller.cancel(&cancel_key).await }),
        );
        let claimed = claimed.expect("claim task").expect("claim").leased();
        let cancelled = cancelled.expect("cancel task").expect("cancel");
        match (claimed, cancelled) {
            (Some(job), CancelOutcome::NotCancellable(JobState::Leased)) => {
                assert_eq!(job.key, key);
                dispatcher
                    .finish(
                        &job,
                        Sent {
                            outcome: accepted(),
                            detail: (),
                        },
                    )
                    .await
                    .expect("finish");
                assert_eq!(state_row(&harness, &key).await.state, "delivered");
            }
            (None, CancelOutcome::Cancelled) => {
                assert_eq!(state_row(&harness, &key).await.state, "cancelled");
            }
            (claimed, cancelled) => panic!(
                "exactly one side wins: claimed {:?}, cancel {cancelled:?}",
                claimed.map(|job| job.key)
            ),
        }
    }
}

#[tokio::test]
async fn a_job_is_not_claimed_before_its_not_before_instant() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            not_before: Some(Duration::from_millis(1_500)),
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    assert!(matches!(
        dispatcher.claim().await.expect("claim"),
        Claim::Idle
    ));
    assert_eq!(state_row(&harness, &key).await.state, "pending");
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    let job = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("the job is due once its instant passes");
    assert_eq!(job.key, key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_concurrent_workers_never_send_one_job_twice() {
    let harness = harness().await;
    let mut keys = BTreeSet::new();
    for _ in 0..40 {
        keys.insert(enqueue_message(&harness, &Message::default()).await);
    }
    let transport =
        Arc::new(ScriptedTransport::new(|_| accepted()).pausing(Duration::from_millis(5)));
    let config = WorkerConfig {
        concurrency: NonZeroUsize::new(4).expect("nonzero"),
        idle_poll: Duration::from_millis(50),
    };
    // Two dispatchers over separate stores stand in for two processes.
    let first = DispatchWorker::new(dispatcher(&harness), Arc::clone(&transport), config);
    let second = DispatchWorker::new(dispatcher(&harness), Arc::clone(&transport), config);
    let (_shutdown_tx, shutdown) = watch::channel(false);
    let (one, two) = tokio::join!(first.drain(&shutdown), second.drain(&shutdown));
    assert_eq!(one + two, 40, "every job is dispatched exactly once");

    let mut sent = BTreeMap::<JobKey, usize>::new();
    for (key, generation, attempt) in transport.sends() {
        assert_eq!((generation, attempt), (1, 1));
        *sent.entry(key).or_default() += 1;
    }
    assert_eq!(sent.keys().cloned().collect::<BTreeSet<_>>(), keys);
    assert!(
        sent.values().all(|count| *count == 1),
        "no job is sent twice"
    );
    for key in &keys {
        assert_eq!(state_row(&harness, key).await.state, "delivered");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_drains_a_batch_under_bounded_concurrency() {
    let harness = harness().await;
    for _ in 0..12 {
        enqueue_message(&harness, &Message::default()).await;
    }
    let transport =
        Arc::new(ScriptedTransport::new(|_| accepted()).pausing(Duration::from_millis(100)));
    let worker = DispatchWorker::new(
        dispatcher(&harness),
        Arc::clone(&transport),
        WorkerConfig {
            concurrency: NonZeroUsize::new(3).expect("nonzero"),
            idle_poll: Duration::from_millis(50),
        },
    );
    let (_shutdown_tx, shutdown) = watch::channel(false);
    assert_eq!(worker.drain(&shutdown).await, 12);
    let peak = transport.peak.load(Ordering::SeqCst);
    assert!(peak <= 3, "at most three sends run at once, saw {peak}");
    assert!(peak >= 2, "the lanes send in parallel, saw {peak}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_runs_until_shutdown() {
    let harness = harness().await;
    let mut keys = Vec::new();
    for _ in 0..5 {
        keys.push(enqueue_message(&harness, &Message::default()).await);
    }
    let transport = Arc::new(ScriptedTransport::new(|_| accepted()));
    let worker = DispatchWorker::new(
        dispatcher(&harness),
        Arc::clone(&transport),
        WorkerConfig {
            concurrency: NonZeroUsize::new(2).expect("nonzero"),
            idle_poll: Duration::from_millis(50),
        },
    );
    let (shutdown_tx, shutdown) = watch::channel(false);
    let handle = tokio::spawn(worker.run(shutdown));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while transport.sends().len() < keys.len() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker dispatches every due job"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    shutdown_tx.send(true).expect("the worker is listening");
    handle.await.expect("the worker stops on shutdown");
    for key in &keys {
        assert_eq!(state_row(&harness, key).await.state, "delivered");
    }
}

#[tokio::test]
async fn a_stale_fence_cannot_write_after_the_lease_is_reclaimed() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            on_uncertain: "retry",
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    let stale = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    lapse_lease(&harness, &key).await;
    assert!(matches!(
        dispatcher.claim().await.expect("reap"),
        Claim::Idle
    ));
    make_due(&harness, &key).await;
    let current = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due again");
    assert_eq!(current.attempt, 2);
    assert_ne!(current.lease_token, stale.lease_token);

    assert_eq!(
        dispatcher
            .finish(
                &stale,
                Sent {
                    outcome: accepted(),
                    detail: ()
                }
            )
            .await,
        Err(DispatchError::Unavailable),
        "the stalled worker's write is refused"
    );
    let row = state_row(&harness, &key).await;
    assert_eq!(row.state, "leased");
    assert_eq!(row.lease_token, Some(current.lease_token));
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec![
            "attempt_started:leased:g1:a1",
            "lease_lapsed:retry_pending:g1:a1",
            "attempt_started:leased:g1:a2"
        ],
        "the refused write left no audit behind"
    );
    assert_eq!(
        dispatcher
            .finish(
                &current,
                Sent {
                    outcome: accepted(),
                    detail: ()
                }
            )
            .await,
        Ok(DispatchOutcome::Delivered)
    );
}

#[tokio::test]
async fn a_stale_fence_cannot_write_over_an_unknown_job() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let stale = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    lapse_lease(&harness, &key).await;
    assert!(matches!(
        dispatcher.claim().await.expect("reap"),
        Claim::Idle
    ));
    assert_eq!(
        dispatcher
            .finish(
                &stale,
                Sent {
                    outcome: accepted(),
                    detail: ()
                }
            )
            .await,
        Err(DispatchError::Unavailable)
    );
    assert_eq!(state_row(&harness, &key).await.state, "unknown");
}

#[tokio::test]
async fn operator_replay_bumps_the_generation_and_refuses_a_stale_replay() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| SendOutcome::Permanent {
        code: FailureCode::new("recipient.rejected").expect("bounded code"),
    });
    let first = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    let first_key = idempotency_key(
        b"dispatch-test-v1",
        &[
            first.key.id().to_string().as_bytes(),
            first.key.part().as_bytes(),
            first.generation.to_string().as_bytes(),
        ],
    );
    let permanent = transport.send(&first).await.expect("send");
    assert_eq!(
        dispatcher.finish(&first, permanent).await,
        Ok(DispatchOutcome::DeadLettered)
    );

    assert_eq!(dispatcher.replay(&key, 1).await, Ok(2));
    assert_eq!(
        dispatcher.replay(&key, 1).await,
        Err(DispatchError::Unavailable),
        "a replay against a superseded generation is refused"
    );
    let row = state_row(&harness, &key).await;
    assert_eq!(
        (row.state.as_str(), row.generation, row.attempt),
        ("pending", 2, 0)
    );

    let second = dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    assert_eq!((second.generation, second.attempt), (2, 1));
    let second_key = idempotency_key(
        b"dispatch-test-v1",
        &[
            second.key.id().to_string().as_bytes(),
            second.key.part().as_bytes(),
            second.generation.to_string().as_bytes(),
        ],
    );
    assert_ne!(
        first_key, second_key,
        "a replay changes the idempotency key"
    );
    assert_eq!(
        dispatcher
            .finish(
                &second,
                Sent {
                    outcome: accepted(),
                    detail: ()
                }
            )
            .await,
        Ok(DispatchOutcome::Delivered)
    );
    assert_eq!(
        dispatcher.replay(&key, 2).await,
        Err(DispatchError::Unavailable),
        "a delivered job is not replayable"
    );
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec![
            "attempt_started:leased:g1:a1",
            "attempt_finished:dead_lettered:g1:a1",
            "replayed:replay_pending:g2:a0",
            "attempt_started:leased:g2:a1",
            "attempt_finished:delivered:g2:a1"
        ]
    );
}

#[tokio::test]
async fn an_unknown_job_is_replayable() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| SendOutcome::MaybeSent);
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Unknown)
    );
    assert_eq!(dispatcher.replay(&key, 1).await, Ok(2));
    assert_eq!(state_row(&harness, &key).await.state, "pending");
}

#[tokio::test]
async fn an_undispatched_job_expires_without_being_sent() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            expires_in_ms: -1_000,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Idle)
    );
    assert!(transport.sends().is_empty());
    assert_eq!(state_row(&harness, &key).await.state, "expired");
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec!["expired:expired:g1:a0"]
    );
    assert_eq!(expiry_events(&harness), 1);
}

/// A consumer whose claim selection has no expiry predicate and which runs
/// no expiry sweep: only the captured policy says when a job expires.
fn unguarded_dispatcher(harness: &Harness) -> Dispatcher<TestStore> {
    Dispatcher::new(
        TestStore {
            url: harness.url.clone(),
            schema: harness.schema.clone(),
            events: Arc::clone(&harness.events),
            quarantine: QuarantineMode::Unsupported,
        },
        DispatchConfig {
            table: harness.table.clone(),
            sql: DispatchSql {
                claim: SelectSql {
                    columns: CLAIM_COLUMNS,
                    joins: MESSAGE_JOIN,
                    predicate: "TRUE",
                },
                expiry: None,
                ..dispatch_sql()
            },
            attempt_timeout: AttemptTimeoutBound::new(
                Duration::from_millis(100),
                Duration::from_secs(60),
            )
            .expect("the consumer's bound is within the core ceiling"),
            replayable: &[JobState::DeadLettered, JobState::Unknown],
        },
    )
    .expect("the consumer's configuration is valid")
}

fn expiry_events(harness: &Harness) -> usize {
    harness
        .events
        .lock()
        .expect("events lock")
        .iter()
        .filter(|event| **event == DispatchEvent::JobExpired)
        .count()
}

#[tokio::test]
async fn a_job_past_its_policy_expiry_is_expired_at_claim_and_never_sent() {
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            expires_in_ms: -1_000,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = unguarded_dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Expired),
        "the core expires the job its consumer's selection let through"
    );
    assert!(transport.sends().is_empty());
    let row = state_row(&harness, &key).await;
    assert_eq!((row.state.as_str(), row.attempt), ("expired", 0));
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec!["expired:expired:g1:a0"]
    );
    assert_eq!(expiry_events(&harness), 1);
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Idle)
    );
    assert!(transport.sends().is_empty());
}

#[tokio::test]
async fn a_scheduled_retry_past_its_policy_expiry_is_expired_at_claim() {
    let harness = harness().await;
    let key = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = unguarded_dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| transient());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::RetryScheduled)
    );
    harness
        .admin
        .execute(
            &format!(
                "UPDATE {}.test_messages
                    SET expires_at = transaction_timestamp() - interval '1 second'
                  WHERE message_id = $1",
                harness.schema
            ),
            &[&key.id()],
        )
        .await
        .expect("the message expires");
    make_due(&harness, &key).await;
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Expired)
    );
    assert_eq!(
        transport.sends().len(),
        1,
        "only the first attempt was sent"
    );
    let row = state_row(&harness, &key).await;
    assert_eq!((row.state.as_str(), row.attempt), ("expired", 1));
    assert_eq!(
        audit_trail(&harness, &key).await,
        vec![
            "attempt_started:leased:g1:a1",
            "attempt_finished:retry_pending:g1:a1",
            "expired:expired:g1:a1"
        ]
    );
}

#[tokio::test]
async fn an_attempt_timeout_outside_the_bound_is_refused() {
    assert_eq!(
        AttemptTimeoutBound::new(Duration::from_millis(100), Duration::from_secs(70)),
        Err(registry_platform_dispatch::ConfigError::AttemptTimeoutBound),
        "no consumer may bound an attempt above sixty seconds"
    );
    let harness = harness().await;
    let key = enqueue_message(
        &harness,
        &Message {
            attempt_timeout_ms: 61_000,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = dispatcher(&harness);
    assert!(dispatcher.claim().await.is_err());
    assert!(harness.events.lock().expect("events lock").contains(
        &DispatchEvent::TransitionFailed(TransitionCode::ClaimPolicyRefused)
    ));
    let row = state_row(&harness, &key).await;
    assert_eq!((row.state.as_str(), row.attempt), ("pending", 0));
    assert!(audit_trail(&harness, &key).await.is_empty());
}

#[tokio::test]
async fn sixty_seconds_is_an_accepted_attempt_timeout() {
    let harness = harness().await;
    enqueue_message(
        &harness,
        &Message {
            attempt_timeout_ms: 60_000,
            ..Message::default()
        },
    )
    .await;
    let job = dispatcher(&harness)
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    assert_eq!(job.policy.attempt_timeout, Duration::from_secs(60));
    let lease = harness
        .admin
        .query_one(
            &format!(
                "SELECT (extract(epoch FROM lease_expires_at - attempt_started_at) * 1000)::bigint
                   FROM {}.{JOB_TABLE}",
                harness.schema
            ),
            &[],
        )
        .await
        .expect("lease")
        .get::<_, i64>(0);
    assert_eq!(
        lease, 65_000,
        "the lease is the attempt timeout plus five seconds"
    );
}

fn quarantine_events(harness: &Harness) -> Vec<QuarantineReason> {
    harness
        .events
        .lock()
        .expect("events lock")
        .iter()
        .filter_map(|event| match event {
            DispatchEvent::JobQuarantined(reason) => Some(*reason),
            _ => None,
        })
        .collect()
}

/// Poison the captured policy of one message so no decoder accepts it.
async fn poison_policy(harness: &Harness, key: &JobKey) {
    let changed = harness
        .admin
        .execute(
            &format!(
                "UPDATE {}.test_messages SET attempt_timeout_ms = -1 WHERE message_id = $1",
                harness.schema
            ),
            &[&key.id()],
        )
        .await
        .expect("the policy is poisoned");
    assert_eq!(changed, 1, "exactly one message is poisoned");
}

#[tokio::test]
async fn a_quarantining_store_sets_a_refused_row_aside_and_delivers_the_next() {
    let harness = harness().await;
    let poisoned = enqueue_message(
        &harness,
        &Message {
            attempt_timeout_ms: 61_000,
            ..Message::default()
        },
    )
    .await;
    let healthy = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = quarantining_dispatcher(&harness, QuarantineMode::Terminal);
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Delivered),
        "the refused row no longer stalls the claim"
    );
    assert_eq!(transport.sends(), vec![(healthy.clone(), 1, 1)]);
    let row = state_row(&harness, &poisoned).await;
    assert_eq!((row.state.as_str(), row.attempt), ("expired", 0));
    assert_eq!(
        audit_trail(&harness, &poisoned).await,
        vec!["quarantined:expired:g1:a0"]
    );
    assert_eq!(state_row(&harness, &healthy).await.state, "delivered");
    assert_eq!(
        quarantine_events(&harness),
        vec![QuarantineReason::PolicyRefused]
    );
    assert!(!harness.events.lock().expect("events lock").contains(
        &DispatchEvent::TransitionFailed(TransitionCode::ClaimPolicyRefused)
    ));
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Idle),
        "a quarantined row is never claimed again"
    );
}

#[tokio::test]
async fn a_quarantining_store_sets_an_unrecoverable_lapsed_lease_aside_and_delivers_the_next() {
    let harness = harness().await;
    let poisoned = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = quarantining_dispatcher(&harness, QuarantineMode::Terminal);
    dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    lapse_lease(&harness, &poisoned).await;
    poison_policy(&harness, &poisoned).await;
    let healthy = enqueue_message(&harness, &Message::default()).await;
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Delivered),
        "the unrecoverable lease no longer stalls the claim"
    );
    assert_eq!(transport.sends(), vec![(healthy.clone(), 1, 1)]);
    let row = state_row(&harness, &poisoned).await;
    assert_eq!(
        (row.state.as_str(), row.attempt, row.lease_token),
        ("dead_lettered", 1, None)
    );
    assert_eq!(
        audit_trail(&harness, &poisoned).await,
        vec![
            "attempt_started:leased:g1:a1",
            "quarantined:dead_lettered:g1:a1"
        ]
    );
    assert_eq!(state_row(&harness, &healthy).await.state, "delivered");
    assert_eq!(
        quarantine_events(&harness),
        vec![QuarantineReason::RecoveryFailed]
    );
    assert!(!harness.events.lock().expect("events lock").contains(
        &DispatchEvent::TransitionFailed(TransitionCode::ClaimRecoveryFailed)
    ));
    assert_eq!(
        dispatcher.replay(&poisoned, 1).await,
        Ok(2),
        "the consumer's replayable set decides whether a quarantined row replays"
    );
}

/// Have the database refuse one audit point for one job, so the step that
/// writes it fails inside PostgreSQL and aborts its statement.
async fn refuse_audit(harness: &Harness, key: &JobKey, point: &str) {
    harness
        .admin
        .batch_execute(&format!(
            "ALTER TABLE {}.test_audit
                 ADD CONSTRAINT refuse_{point}
                 CHECK (message_id <> '{}' OR point <> '{point}')",
            harness.schema,
            key.id()
        ))
        .await
        .expect("the audit refusal installs");
}

#[tokio::test]
async fn a_lapsed_lease_the_database_refuses_is_rolled_back_to_its_savepoint_and_quarantined() {
    let harness = harness().await;
    let poisoned = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = quarantining_dispatcher(&harness, QuarantineMode::Terminal);
    dispatcher
        .claim()
        .await
        .expect("claim")
        .leased()
        .expect("due");
    lapse_lease(&harness, &poisoned).await;
    refuse_audit(&harness, &poisoned, "lease_lapsed").await;
    let healthy = enqueue_message(&harness, &Message::default()).await;
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Delivered)
    );
    assert_eq!(transport.sends(), vec![(healthy.clone(), 1, 1)]);
    let row = state_row(&harness, &poisoned).await;
    assert_eq!((row.state.as_str(), row.attempt), ("dead_lettered", 1));
    assert_eq!(
        audit_trail(&harness, &poisoned).await,
        vec![
            "attempt_started:leased:g1:a1",
            "quarantined:dead_lettered:g1:a1"
        ]
    );
    assert_eq!(
        quarantine_events(&harness),
        vec![QuarantineReason::RecoveryFailed]
    );
}

#[tokio::test]
async fn an_expiry_the_database_refuses_is_rolled_back_to_its_savepoint_and_quarantined() {
    let harness = harness().await;
    let poisoned = enqueue_message(
        &harness,
        &Message {
            expires_in_ms: -1_000,
            ..Message::default()
        },
    )
    .await;
    refuse_audit(&harness, &poisoned, "expired").await;
    let healthy = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = quarantining_dispatcher(&harness, QuarantineMode::Terminal);
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Ok(DispatchOutcome::Delivered)
    );
    assert_eq!(transport.sends(), vec![(healthy.clone(), 1, 1)]);
    let row = state_row(&harness, &poisoned).await;
    assert_eq!((row.state.as_str(), row.attempt), ("expired", 0));
    assert_eq!(
        audit_trail(&harness, &poisoned).await,
        vec!["quarantined:expired:g1:a0"]
    );
    assert_eq!(
        quarantine_events(&harness),
        vec![QuarantineReason::ExpiryFailed]
    );
    assert_eq!(expiry_events(&harness), 0);
}

#[tokio::test]
async fn without_quarantine_a_refused_row_still_stalls_the_claim() {
    let harness = harness().await;
    let poisoned = enqueue_message(
        &harness,
        &Message {
            attempt_timeout_ms: 61_000,
            ..Message::default()
        },
    )
    .await;
    let healthy = enqueue_message(&harness, &Message::default()).await;
    let dispatcher = dispatcher(&harness);
    let transport = ScriptedTransport::new(|_| accepted());
    assert_eq!(
        dispatcher.dispatch_once(&transport).await,
        Err(DispatchError::Unavailable)
    );
    assert!(transport.sends().is_empty());
    assert!(harness.events.lock().expect("events lock").contains(
        &DispatchEvent::TransitionFailed(TransitionCode::ClaimPolicyRefused)
    ));
    assert!(quarantine_events(&harness).is_empty());
    for key in [&poisoned, &healthy] {
        let row = state_row(&harness, key).await;
        assert_eq!((row.state.as_str(), row.attempt), ("pending", 0));
        assert!(audit_trail(&harness, key).await.is_empty());
    }
}

#[tokio::test]
async fn a_quarantine_that_leaves_the_row_claimable_is_refused() {
    let harness = harness().await;
    let poisoned = enqueue_message(
        &harness,
        &Message {
            attempt_timeout_ms: 61_000,
            ..Message::default()
        },
    )
    .await;
    let dispatcher = quarantining_dispatcher(&harness, QuarantineMode::Claimable);
    assert!(dispatcher.claim().await.is_err());
    assert!(harness.events.lock().expect("events lock").contains(
        &DispatchEvent::TransitionFailed(TransitionCode::ClaimPolicyRefused)
    ));
    assert!(quarantine_events(&harness).is_empty());
    let row = state_row(&harness, &poisoned).await;
    assert_eq!((row.state.as_str(), row.attempt), ("pending", 0));
    assert!(
        audit_trail(&harness, &poisoned).await.is_empty(),
        "the refused quarantine's audit rolls back with it"
    );
}
