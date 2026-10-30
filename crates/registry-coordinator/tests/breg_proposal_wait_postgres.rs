// SPDX-License-Identifier: Apache-2.0
//! A wait-for step follows a BReg Proposal. Each answered read keeps what the
//! Proposal showed on the wait, and inspection shows it with the "Open the
//! request" link. The observation ends with the wait. Isolated synthetic
//! PostgreSQL proof. Missing database configuration fails.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use registry_coordinator::{
    authoring,
    definition::{CompletionDefinition, Definition},
    protocol::{
        AdapterSet, CallOutcome, CallRequest, CompletionObservation, Operation, ProposalObservation,
    },
    runtime::RuntimeConfig,
    store::{Actor, ProposalTurn, RunListFilter, Store},
    worker::Worker,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

const ACTION: &str = "correct-address";
const REVISION: &str = "sha256:1e2b7f1e425c009616e0ffd8123583f9a8c3f95ebb8a001679dd96c7521c6120";
const PROPOSAL: &str = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml");

/// A run that reads one Proposal, follows it, and finishes with the outcome
/// it observes, or with `late` when the wait times out.
fn project() -> Value {
    let mut steps = json!({
        "call": {"type": "call", "operation": "follow", "input": {"type": "input"}, "next": "await"},
        "await": {"type": "wait-for", "completion": {"step": "call", "name": "proposal"},
            "timeoutSeconds": 86400, "next": "decide", "onTimeout": "late"},
        "decide": {"type": "choose", "choose": {"type": "step", "step": "await", "path": "/outcome"},
            "cases": {}},
        "late": {"type": "finish", "outcome": "late"}
    });
    let mut outcomes = json!({"late": {"type": "null"}});
    for case in ["applied", "rejected", "cancelled"] {
        steps["decide"]["cases"][case] = json!(case);
        steps[case] = json!({"type": "finish", "outcome": case});
        outcomes[case] = json!({"type": "null"});
    }
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id": "proposal-wait", "version": "1"},
        "contracts": {"facilities": {"type": "breg", "source": "facilities.json"}},
        "operations": {"follow": {"uses": "breg.read-proposal/v1", "connection": "applications",
            "action": {"contract": "facilities", "id": ACTION}}},
        "workflow": {"input": {"operationInput": "follow"}, "deadlineSeconds": 2_592_000,
            "start": "call", "steps": steps, "outcomes": outcomes}
    })
}

fn receipt_for(proposal: &str) -> Value {
    json!({"proposalId": proposal, "actionId": ACTION, "actionRevision": REVISION,
        "submissionVersion": 1, "state": "submitted"})
}

fn seen(state: &str, turn: &str, refusal: Option<&str>) -> ProposalObservation {
    ProposalObservation {
        state: state.into(),
        turn: Some(turn.into()),
        submission_version: 1,
        handoff_refusal: refusal.map(Into::into),
    }
}

fn followed(proposal: ProposalObservation, read: CompletionObservation) -> CompletionObservation {
    CompletionObservation::Followed {
        proposal,
        read: Box::new(read),
    }
}

fn waiting(turn: &str) -> CompletionObservation {
    followed(
        seen("submitted", turn, None),
        CompletionObservation::Pending { retry_after: None },
    )
}

fn applied() -> CompletionObservation {
    followed(
        seen("applied", "nobody", None),
        CompletionObservation::Settled(json!({"outcome": "applied", "proposalId": PROPOSAL,
            "submissionVersion": 1, "actionRevision": REVISION, "input": {}})),
    )
}

struct Fake {
    reads: Mutex<VecDeque<CompletionObservation>>,
    read_count: AtomicUsize,
}

impl Fake {
    fn new(reads: Vec<CompletionObservation>) -> Arc<Self> {
        Arc::new(Self {
            reads: Mutex::new(reads.into()),
            read_count: AtomicUsize::new(0),
        })
    }

    fn reads(&self) -> usize {
        self.read_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl AdapterSet for Fake {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        assert_eq!(request.operation, Operation::ReadProposal);
        CallOutcome::Success(receipt_for(
            request.input["proposalId"].as_str().expect("a Proposal id"),
        ))
    }

    async fn observe_completion(
        &self,
        request: &CallRequest,
        accepted: &Value,
        _completion: &CompletionDefinition,
    ) -> CompletionObservation {
        assert_eq!(request.connection, "applications");
        assert_eq!(
            accepted,
            &receipt_for(accepted["proposalId"].as_str().expect("a Proposal id"))
        );
        self.read_count.fetch_add(1, Ordering::SeqCst);
        self.reads
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| waiting("official"))
    }
}

struct Harness {
    url: String,
    namespace: String,
    store: Arc<Store>,
    definition: Definition,
    project: tempfile::TempDir,
}

async fn harness() -> Harness {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect(
        "COORDINATOR_TEST_DATABASE_URL must name a disposable synthetic PostgreSQL 17+ database",
    );
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let store = Arc::new(
        Store::connect(&url, &namespace)
            .await
            .expect("local disposable connection"),
    );
    store.migrate().await.expect("isolated migration");
    let project = tempfile::tempdir().expect("project");
    std::fs::write(project.path().join("workflow.yaml"), project_text()).expect("workflow");
    std::fs::write(
        project.path().join("facilities.json"),
        include_str!("fixtures/breg-contracts/facilities.contract.json"),
    )
    .expect("contract");
    let definition = Definition::load(project.path()).expect("valid synthetic definition");
    Harness {
        url,
        namespace,
        store,
        definition,
        project,
    }
}

fn project_text() -> String {
    project().to_string()
}

fn operator() -> Actor {
    Actor {
        issuer: "https://issuer.example.invalid".into(),
        subject: "synthetic-operator".into(),
        client_id: "synthetic-operator-client".into(),
        operator: true,
    }
}

/// The observation a wait keeps, as the database holds it.
struct Kept {
    observation: Option<Value>,
    observed_at: Option<DateTime<Utc>>,
    state_since: Option<DateTime<Utc>>,
}

impl Harness {
    async fn admit(&self) -> Uuid {
        self.admit_following(PROPOSAL).await
    }

    async fn admit_following(&self, proposal: &str) -> Uuid {
        self.store
            .admit(
                &self.definition,
                json!({"proposalId": proposal}),
                "synthetic-producer",
                &Uuid::new_v4().to_string(),
                "binding-a",
            )
            .await
            .expect("admit")
    }

    async fn client(&self) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .expect("test connection");
        tokio::spawn(async move {
            connection.await.expect("test connection finishes");
        });
        client
    }

    /// Make the waiting step due now, as an early read would.
    async fn make_due(&self, run: Uuid) {
        self.client().await.execute(&format!("UPDATE {}.completion_waits SET not_before=clock_timestamp()-interval '1 second' WHERE run_id=$1",self.namespace),&[&run]).await.unwrap();
        let changed = self
            .client()
            .await
            .execute(
                &format!("UPDATE {}.jobs SET next_attempt_at=clock_timestamp() WHERE run_id=$1 AND step='await' AND state='pending'", self.namespace),
                &[&run],
            )
            .await
            .unwrap();
        assert_eq!(changed, 1, "the waiting step is pending");
    }

    async fn sql(&self, sql: &str, run: Uuid) {
        self.client()
            .await
            .execute(&sql.replace("{schema}", &self.namespace), &[&run])
            .await
            .expect("synthetic test transition");
    }

    async fn kept(&self, run: Uuid) -> Option<Kept> {
        self.client()
            .await
            .query_opt(
                &format!("SELECT last_observation,observed_at,state_since FROM {}.completion_waits WHERE run_id=$1", self.namespace),
                &[&run],
            )
            .await
            .unwrap()
            .map(|row| Kept {
                observation: row.get(0),
                observed_at: row.get(1),
                state_since: row.get(2),
            })
    }

    async fn status(&self, run: Uuid) -> (String, Option<String>, Option<String>) {
        let status = self.store.status(run).await.expect("status");
        (status.state, status.outcome, status.failure_code)
    }

    async fn wait_view(&self, run: Uuid) -> Value {
        let inspection = self.store.inspect(run, "binding-a").await.expect("inspect");
        let waits = serde_json::to_value(&inspection.waits).unwrap();
        assert_eq!(waits.as_array().unwrap().len(), 1, "{waits}");
        waits[0].clone()
    }

    /// Run the worker until it has nothing due.
    async fn drain(&self, worker: &Worker) {
        for _ in 0..16 {
            if !worker.tick().await.expect("worker progress") {
                return;
            }
        }
        panic!("the worker kept finding due work");
    }
}

#[tokio::test]
async fn each_read_keeps_the_latest_observation_and_when_its_state_and_turn_began() {
    let h = harness().await;
    let fake = Fake::new(vec![
        waiting("official"),
        waiting("official"),
        waiting("nobody"),
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 1, "read at wait start");
    let first = h.kept(run).await.expect("the wait keeps its row");
    assert_eq!(
        first.observation,
        Some(json!({"state": "submitted", "turn": "official", "submissionVersion": 1}))
    );
    let first_seen = first.observed_at.expect("observed");
    assert_eq!(first.state_since, Some(first_seen));

    h.make_due(run).await;
    h.drain(&worker).await;
    let same = h.kept(run).await.unwrap();
    assert!(same.observed_at.unwrap() > first_seen, "a later read");
    assert_eq!(
        same.state_since,
        Some(first_seen),
        "the same state and turn keep the time they were first seen"
    );

    h.make_due(run).await;
    h.drain(&worker).await;
    let moved = h.kept(run).await.unwrap();
    assert_eq!(moved.observation.unwrap()["turn"], "nobody");
    assert_eq!(
        moved.state_since, moved.observed_at,
        "a new turn starts its own time"
    );
    let view = h.wait_view(run).await;
    assert_eq!(
        view["lastObservation"],
        json!({"state": "submitted", "turn": "nobody", "submissionVersion": 1,
            "observedAt": view["lastObservation"]["observedAt"],
            "stateSince": view["lastObservation"]["stateSince"]})
    );
    assert!(view["lastObservation"]["observedAt"].is_string(), "{view}");
    assert!(
        view.get("requestLink").is_none(),
        "no link without a runtime"
    );
    assert_eq!(
        h.status(run).await,
        ("running".into(), None, None),
        "the run keeps waiting"
    );
}

#[tokio::test]
async fn a_handoff_refusal_on_a_followed_request_keeps_waiting_and_shows_its_code() {
    let h = harness().await;
    let fake = Fake::new(vec![followed(
        seen("submitted", "official", Some("review.initiator-required")),
        CompletionObservation::Pending { retry_after: None },
    )]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(h.status(run).await, ("running".into(), None, None));
    assert_eq!(
        h.wait_view(run).await["lastObservation"]["handoffRefusal"],
        "review.initiator-required"
    );
}

#[tokio::test]
async fn a_held_read_keeps_the_observation_that_explains_it() {
    let h = harness().await;
    let fake = Fake::new(vec![followed(
        seen("submitted", "official", Some("review.refused")),
        CompletionObservation::Hold {
            code: "proposal-handoff-refused".into(),
        },
    )]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(
        h.status(run).await,
        (
            "attention".into(),
            None,
            Some("proposal-handoff-refused".into())
        )
    );
    assert_eq!(
        h.kept(run)
            .await
            .expect("a held wait keeps its row")
            .observation,
        Some(
            json!({"state": "submitted", "turn": "official", "submissionVersion": 1,
            "handoffRefusal": "review.refused"})
        )
    );
}

#[tokio::test]
async fn a_read_without_an_answer_keeps_the_last_observation() {
    let h = harness().await;
    let fake = Fake::new(vec![
        waiting("official"),
        CompletionObservation::Retryable {
            code: "remote-unavailable".into(),
            retry_after: None,
        },
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    let before = h.kept(run).await.unwrap();
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 2);
    let after = h.kept(run).await.unwrap();
    assert_eq!(after.observation, before.observation);
    assert_eq!(after.observed_at, before.observed_at);
}

#[tokio::test]
async fn the_observation_ends_with_the_wait() {
    let h = harness().await;
    let fake = Fake::new(vec![waiting("official"), applied()]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert!(h.kept(run).await.unwrap().observation.is_some());
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(
        h.status(run).await,
        ("finished".into(), Some("applied".into()), None)
    );
    assert!(
        h.kept(run).await.is_none(),
        "the wait and its observation end"
    );
}

#[tokio::test]
async fn inspection_offers_the_configured_request_link() {
    let h = harness().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    let path = h
        .project
        .path()
        .canonicalize()
        .unwrap()
        .join("runtime.yaml");
    std::fs::write(
        &path,
        RUNTIME.replace(
            "    profile: follow-up-reader\n",
            "    profile: follow-up-reader\n    requestLink: https://staff.example.test/proposals/{proposalId}\n",
        ),
    )
    .unwrap();
    let runtime = RuntimeConfig::load(&path).unwrap();
    let inspection = h
        .store
        .inspect_runtime_owned(run, &runtime, &operator())
        .await
        .expect("inspect");
    let waits = serde_json::to_value(&inspection.waits).unwrap();
    assert_eq!(
        waits[0]["requestLink"],
        format!("https://staff.example.test/proposals/{PROPOSAL}")
    );
    assert_eq!(waits[0]["lastObservation"]["turn"], "official");
}

/// Early reads spend the read budget. A wait whose budget is spent still
/// reaches its timeout route when the timeout comes, rather than holding.
#[tokio::test]
async fn a_wait_read_early_many_times_still_reaches_its_timeout_route() {
    let h = harness().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    // Ninety seconds at the thirty-second floor allow four reads.
    h.sql(
        "UPDATE {schema}.completion_waits SET started_at=timeout_at-interval '90 seconds' WHERE run_id=$1",
        run,
    )
    .await;
    for _ in 0..3 {
        h.make_due(run).await;
        h.drain(&worker).await;
    }
    assert_eq!(fake.reads(), 4);
    assert_eq!(h.wait_view(run).await["observations"], 4);
    h.sql(
        "UPDATE {schema}.completion_waits SET timeout_at=clock_timestamp()-interval '1 second',started_at=clock_timestamp()-interval '91 seconds' WHERE run_id=$1",
        run,
    )
    .await;
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 4, "no read past the budget");
    assert_eq!(
        h.status(run).await,
        ("finished".into(), Some("late".into()), None)
    );
    assert!(h.kept(run).await.is_none());
}

const OTHER_PROPOSAL: &str = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9";

impl Harness {
    async fn listed(&self, filter: RunListFilter) -> Vec<Uuid> {
        self.page(100, None, filter)
            .await
            .expect("list")
            .runs
            .iter()
            .map(|run| run.run_id)
            .collect()
    }

    async fn page(
        &self,
        limit: u32,
        cursor: Option<&str>,
        filter: RunListFilter,
    ) -> registry_coordinator::Result<registry_coordinator::store::RunListPage> {
        self.store
            .list_owned_page(
                limit,
                cursor,
                filter,
                &operator(),
                &["proposal-wait".to_owned()],
            )
            .await
    }
}

fn following(proposal: &str) -> RunListFilter {
    RunListFilter {
        proposal: Some(Uuid::parse_str(proposal).unwrap()),
        ..RunListFilter::default()
    }
}

fn on_turn(turn: ProposalTurn) -> RunListFilter {
    RunListFilter {
        turn: Some(turn),
        ..RunListFilter::default()
    }
}

#[tokio::test]
async fn runs_are_listed_by_the_proposal_they_follow_and_its_last_turn() {
    let h = harness().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let first = h.admit().await;
    h.drain(&worker).await;
    fake.reads.lock().unwrap().push_back(waiting("party"));
    let other = h.admit_following(OTHER_PROPOSAL).await;
    h.drain(&worker).await;
    fake.reads.lock().unwrap().push_back(waiting("official"));
    let second = h.admit().await;
    h.drain(&worker).await;

    assert_eq!(h.listed(following(PROPOSAL)).await, [second, first]);
    assert_eq!(h.listed(following(OTHER_PROPOSAL)).await, [other]);
    assert!(h
        .listed(following("6b7c8d9e-0f1a-4b2c-8d3e-4f5a6b7c8d9e"))
        .await
        .is_empty());
    assert_eq!(
        h.listed(on_turn(ProposalTurn::Official)).await,
        [second, first]
    );
    assert_eq!(h.listed(on_turn(ProposalTurn::Party)).await, [other]);
    assert!(h.listed(on_turn(ProposalTurn::Nobody)).await.is_empty());

    // A run whose wait ended is no longer waiting on the Proposal.
    fake.reads.lock().unwrap().push_back(applied());
    h.make_due(first).await;
    h.drain(&worker).await;
    assert_eq!(h.listed(following(PROPOSAL)).await, [second]);
}

#[tokio::test]
async fn a_list_cursor_carries_the_proposal_and_turn_filters() {
    let h = harness().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let first = h.admit().await;
    let second = h.admit().await;
    h.drain(&worker).await;

    let filter = RunListFilter {
        proposal: Some(Uuid::parse_str(PROPOSAL).unwrap()),
        turn: Some(ProposalTurn::Official),
        ..RunListFilter::default()
    };
    let page = h.page(1, None, filter).await.unwrap();
    assert_eq!(page.runs[0].run_id, second);
    let cursor = page.next_cursor.expect("another page");
    assert!(
        !cursor.contains(PROPOSAL) && !cursor.contains(&PROPOSAL.replace('-', "")),
        "the cursor names no Proposal in clear"
    );
    let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(&cursor).unwrap()).unwrap();
    assert!(!decoded.contains(PROPOSAL), "{decoded}");
    let next = h.page(1, Some(&cursor), filter).await.unwrap();
    assert_eq!(next.runs[0].run_id, first);

    for changed in [
        following(PROPOSAL),
        on_turn(ProposalTurn::Official),
        RunListFilter {
            proposal: Some(Uuid::parse_str(OTHER_PROPOSAL).unwrap()),
            ..filter
        },
        RunListFilter {
            turn: Some(ProposalTurn::Party),
            ..filter
        },
    ] {
        assert_eq!(
            h.page(1, Some(&cursor), changed).await.unwrap_err().code,
            "request.invalid"
        );
    }

    // A cursor from the earlier version is refused.
    let mut earlier: Value = serde_json::from_str(&decoded).unwrap();
    earlier["version"] = json!(1);
    let earlier = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&earlier).unwrap());
    assert_eq!(
        h.page(1, Some(&earlier), filter).await.unwrap_err().code,
        "request.invalid"
    );
}

#[tokio::test]
async fn doctor_counts_proposal_waits_by_their_last_turn_without_reading_breg() {
    let h = harness().await;
    let fake = Fake::new(vec![
        waiting("official"),
        waiting("party"),
        waiting("party"),
        CompletionObservation::Retryable {
            code: "remote-unavailable".into(),
            retry_after: None,
        },
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    for _ in 0..4 {
        h.admit().await;
        h.drain(&worker).await;
    }
    let reads = fake.reads();
    let doctor = serde_json::to_value(h.store.doctor().await.unwrap()).unwrap();
    assert_eq!(fake.reads(), reads, "doctor reads no Proposal");
    assert_eq!(
        doctor["proposalWaitsByTurn"],
        json!({"party": 2, "official": 1, "nobody": 0, "unobserved": 1})
    );
}
