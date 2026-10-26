// SPDX-License-Identifier: Apache-2.0

//! Event records written by immediate Actions against a real PostgreSQL
//! database: atomic success and refusal, replay, source event uniqueness,
//! competing writers, decision and effective dates, and correction links.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[path = "support/event_record_registry.rs"]
mod event_record_registry;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    PostgresSnapshotReadService, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const INSTANCE_ID: &str = "event-record-examples-instance";
const DATABASE_ID: &str = "event-record-examples-database";

struct Fixture {
    database: TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    app: axum::Router,
}

struct Reply {
    status: StatusCode,
    body: Value,
}

impl Fixture {
    async fn start() -> Self {
        let database = TestDatabase::create(10).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = Arc::new(event_record_registry::compiled());
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("migration installs the event record registry schema");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: event_record_registry::PACKAGE_ID,
                database_id: DATABASE_ID,
                label: "package-event-record-1",
            },
        )
        .await
        .expect("migration initializes registry identity");
        drop(migration);
        migration_task.abort();

        let pool = database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        let profile = database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x42; 32].into())
                .expect("test owns a keyed audit profile"),
        );
        let lock_key =
            RegistryLockKey::derive(event_record_registry::PACKAGE_ID).expect("lock key derives");
        let cursors = Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300))
                .expect("test cursor key is valid"),
        );
        let records = Arc::new(PostgresRecordReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            profile.clone(),
            cursors.clone(),
        ));
        let revisions = Arc::new(PostgresRevisionReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            profile.clone(),
        ));
        let snapshots = Arc::new(PostgresSnapshotReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            profile.clone(),
            cursors.clone(),
        ));
        let read_identity = ReadRuntimeIdentity {
            package_revision: identity.activation_id.clone(),
            schema_fingerprint: identity.schema_fingerprint.clone(),
        };
        let mutations = PostgresRecordMutationService::new(
            pool,
            registry.clone(),
            identity,
            INSTANCE_ID,
            lock_key,
            Duration::from_secs(2),
            profile,
        );
        let app = router(Arc::new(
            HttpService::new(
                registry.clone(),
                read_identity,
                records,
                Arc::new(AlwaysReady),
                cursors,
            )
            .with_postgres_revisions(revisions)
            .with_snapshots(snapshots)
            .with_postgres_mutations(Arc::new(mutations)),
        ));
        Self {
            database,
            registry,
            app,
        }
    }

    async fn send(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body))
            .expect("request builds");
        for (name, value) in headers {
            request.headers_mut().append(
                HeaderName::from_bytes(name.as_bytes()).expect("header name is valid"),
                HeaderValue::from_str(value).expect("header value is valid"),
            );
        }
        request.extensions_mut().insert(claims());
        let mut app = self.app.clone();
        let response = app.call(request).await.expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .expect("response body");
        Reply {
            status,
            body: serde_json::from_slice(&bytes).expect("response is JSON"),
        }
    }

    async fn get(&self, uri: &str) -> Reply {
        self.send(Method::GET, uri, &[], Vec::new()).await
    }

    /// The write precondition tokens of the Action's conditioned targets,
    /// named by their public input names.
    async fn conditions(&self, action: &str, input: &Value, targets: &[&str]) -> Value {
        let target_input: serde_json::Map<String, Value> = targets
            .iter()
            .map(|name| ((*name).to_owned(), input[*name].clone()))
            .collect();
        let reply = self
            .send(
                Method::POST,
                &format!("/v1/actions/{action}/target-conditions"),
                &[("content-type", "application/json")],
                serde_json::to_vec(&json!({ "input": target_input })).expect("body serializes"),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.body["preconditions"].clone()
    }

    async fn invoke_with(
        &self,
        action: &str,
        key: &str,
        input: &Value,
        preconditions: Option<&Value>,
    ) -> Reply {
        let mut body = json!({ "input": input });
        if let Some(preconditions) = preconditions {
            body["preconditions"] = preconditions.clone();
        }
        self.send(
            Method::POST,
            &format!("/v1/actions/{action}"),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&body).expect("body serializes"),
        )
        .await
    }

    /// Invokes an Action whose targets carry no write precondition.
    async fn invoke(&self, action: &str, key: &str, input: Value) -> Reply {
        self.invoke_with(action, key, &input, None).await
    }

    /// Invokes an Action after acquiring the conditions of its patched targets.
    async fn invoke_conditioned(
        &self,
        action: &str,
        key: &str,
        targets: &[&str],
        input: Value,
    ) -> Reply {
        let preconditions = self.conditions(action, &input, targets).await;
        self.invoke_with(action, key, &input, Some(&preconditions))
            .await
    }

    async fn open(&self, action: &str, key: &str, input: Value) -> String {
        let reply = self.invoke(action, key, input).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.body["results"]["opened"]["recordId"]
            .as_str()
            .expect("create result names the record")
            .to_owned()
    }

    async fn row_count(&self, entity: &str) -> i64 {
        let table = &self.registry.entities()[entity].physical_table;
        self.database
            .admin
            .query_one(
                &format!("SELECT count(*) FROM registry_data.\"{table}\""),
                &[],
            )
            .await
            .expect("row count query runs")
            .get(0)
    }

    async fn revisions(&self, route: &str, id: &str) -> Reply {
        self.get(&format!(
            "/v1/records/{route}/{id}/revisions?accessProfile=event-record-history"
        ))
        .await
    }
}

async fn finish(fixture: Fixture) {
    fixture.database.cleanup().await;
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar-principal",
        BTreeSet::new(),
        None,
        BTreeMap::<String, VerifiedClaimValue>::new(),
    )
    .expect("authenticated claims are valid")
}

#[derive(Clone)]
struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn atomic_success_and_refusal() {
    let fixture = Fixture::start().await;
    let grant = fixture
        .open("open-grant", "open-grant-1", json!({"grantNumber": "G-1"}))
        .await;

    let paused = fixture
        .invoke_conditioned(
            "pause-grant",
            "pause-1",
            &["grantId"],
            json!({"grantId": grant, "decidedOn": "2026-10-20", "effectiveFrom": "2026-11-01"}),
        )
        .await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.body);
    assert_eq!(
        paused.body["results"]["status-change"]["recordId"],
        json!(grant)
    );
    let decision = paused.body["results"]["decision"]["recordId"]
        .as_str()
        .expect("decision result names the record")
        .to_owned();

    let stored_grant = fixture.get(&format!("/v1/records/grants/{grant}")).await;
    assert_eq!(stored_grant.status, StatusCode::OK, "{}", stored_grant.body);
    assert_eq!(
        stored_grant.body["data"]["domainData"]["status"], "paused",
        "{}",
        stored_grant.body
    );
    let stored_decision = fixture
        .get(&format!("/v1/records/grant-pause-decisions/{decision}"))
        .await;
    assert_eq!(
        stored_decision.status,
        StatusCode::OK,
        "{}",
        stored_decision.body
    );
    assert_eq!(
        stored_decision.body["data"]["domainData"]["grant"],
        json!(grant)
    );
    assert_eq!(fixture.row_count("grant-pause-decision").await, 1);

    // A second pause fails the guard on the grant's status. Nothing is
    // written: no decision row and no second status revision.
    let refused = fixture
        .invoke_conditioned(
            "pause-grant",
            "pause-2",
            &["grantId"],
            json!({"grantId": grant, "decidedOn": "2026-10-21", "effectiveFrom": "2026-11-02"}),
        )
        .await;
    assert_eq!(
        refused.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        refused.body
    );
    assert_eq!(refused.body["code"], "action.guard_failed");
    assert_eq!(refused.body["guardReason"], "grant-not-active");
    assert_eq!(fixture.row_count("grant-pause-decision").await, 1);

    // A uniqueness refusal on the event record rolls back the sibling effects.
    let item = fixture
        .open("open-item", "open-item-1", json!({"itemNumber": "I-1"}))
        .await;
    let custody = fixture
        .open(
            "open-custody",
            "open-custody-1",
            json!({"holderReference": "holder-a"}),
        )
        .await;
    let other_custody = fixture
        .open(
            "open-custody",
            "open-custody-2",
            json!({"holderReference": "holder-b"}),
        )
        .await;
    let handover = |previous: &str, deed: &str| {
        json!({
            "itemId": item,
            "previousCustodyId": previous,
            "newHolder": "holder-c",
            "deedReference": deed,
            "effectiveAt": "2026-10-20T09:00:00+02:00"
        })
    };
    let first = fixture
        .invoke_conditioned(
            "hand-over-custody",
            "handover-1",
            &["previousCustodyId"],
            handover(&custody, "deed-1"),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let custody_rows = fixture.row_count("custody-record").await;
    let handover_rows = fixture.row_count("custody-handover").await;
    let duplicate = fixture
        .invoke_conditioned(
            "hand-over-custody",
            "handover-2",
            &["previousCustodyId"],
            handover(&other_custody, "deed-1"),
        )
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT, "{}", duplicate.body);
    assert_eq!(duplicate.body["code"], "mutation.conflict");
    assert_eq!(fixture.row_count("custody-record").await, custody_rows);
    assert_eq!(fixture.row_count("custody-handover").await, handover_rows);
    let untouched = fixture
        .get(&format!("/v1/records/custody-records/{other_custody}"))
        .await;
    assert_eq!(
        untouched.body["data"]["domainData"]["status"], "held",
        "{}",
        untouched.body
    );

    finish(fixture).await;
}

fn handover_input(item: &str, previous: &str, deed: &str) -> Value {
    json!({
        "itemId": item,
        "previousCustodyId": previous,
        "newHolder": "holder-next",
        "deedReference": deed,
        "effectiveAt": "2026-10-20T09:00:00+02:00"
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_and_source_event_uniqueness() {
    let fixture = Fixture::start().await;
    let item = fixture
        .open("open-item", "open-item-1", json!({"itemNumber": "I-1"}))
        .await;
    let mut custodies = Vec::new();
    for (index, holder) in ["holder-a", "holder-b", "holder-c"].iter().enumerate() {
        custodies.push(
            fixture
                .open(
                    "open-custody",
                    &format!("open-custody-{index}"),
                    json!({"holderReference": holder}),
                )
                .await,
        );
    }

    let input = handover_input(&item, &custodies[0], "deed-1");
    let preconditions = fixture
        .conditions("hand-over-custody", &input, &["previousCustodyId"])
        .await;
    let first = fixture
        .invoke_with(
            "hand-over-custody",
            "handover-1",
            &input,
            Some(&preconditions),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let custody_rows = fixture.row_count("custody-record").await;
    assert_eq!(fixture.row_count("custody-handover").await, 1);

    // The same key and body replays the receipt without a second write.
    let replay = fixture
        .invoke_with(
            "hand-over-custody",
            "handover-1",
            &input,
            Some(&preconditions),
        )
        .await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.body);
    assert_eq!(replay.body["results"], first.body["results"]);
    assert_eq!(fixture.row_count("custody-handover").await, 1);
    assert_eq!(fixture.row_count("custody-record").await, custody_rows);

    // The same key with another body is a key conflict, not a second write.
    let changed = handover_input(&item, &custodies[0], "deed-changed");
    let key_conflict = fixture
        .invoke_with(
            "hand-over-custody",
            "handover-1",
            &changed,
            Some(&preconditions),
        )
        .await;
    assert_eq!(
        key_conflict.status,
        StatusCode::CONFLICT,
        "{}",
        key_conflict.body
    );
    assert_eq!(fixture.row_count("custody-handover").await, 1);

    // A new key does not make the same source event a second event record.
    let duplicate = fixture
        .invoke_conditioned(
            "hand-over-custody",
            "handover-2",
            &["previousCustodyId"],
            handover_input(&item, &custodies[1], "deed-1"),
        )
        .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT, "{}", duplicate.body);
    assert_eq!(duplicate.body["code"], "mutation.conflict");
    assert_eq!(fixture.row_count("custody-handover").await, 1);

    // A different source event is a second event record.
    let second = fixture
        .invoke_conditioned(
            "hand-over-custody",
            "handover-3",
            &["previousCustodyId"],
            handover_input(&item, &custodies[1], "deed-2"),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_eq!(fixture.row_count("custody-handover").await, 2);

    finish(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn competing_changes_single_winner() {
    let fixture = Fixture::start().await;
    let grant = fixture
        .open("open-grant", "open-grant-1", json!({"grantNumber": "G-1"}))
        .await;
    let input = json!({"grantId": grant, "decidedOn": "2026-10-20", "effectiveFrom": "2026-11-01"});
    let preconditions = fixture
        .conditions("pause-grant", &input, &["grantId"])
        .await;
    let (left, right) = tokio::join!(
        fixture.invoke_with("pause-grant", "pause-left", &input, Some(&preconditions)),
        fixture.invoke_with("pause-grant", "pause-right", &input, Some(&preconditions)),
    );
    let mut statuses = [left.status, right.status];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::PRECONDITION_FAILED],
        "{} / {}",
        left.body,
        right.body
    );
    assert_eq!(fixture.row_count("grant-pause-decision").await, 1);

    // Two writers racing the same source event leave one event record.
    let item = fixture
        .open("open-item", "open-item-1", json!({"itemNumber": "I-1"}))
        .await;
    let first = fixture
        .open(
            "open-custody",
            "open-custody-1",
            json!({"holderReference": "holder-a"}),
        )
        .await;
    let second = fixture
        .open(
            "open-custody",
            "open-custody-2",
            json!({"holderReference": "holder-b"}),
        )
        .await;
    let first_input = handover_input(&item, &first, "deed-race");
    let second_input = handover_input(&item, &second, "deed-race");
    let first_conditions = fixture
        .conditions("hand-over-custody", &first_input, &["previousCustodyId"])
        .await;
    let second_conditions = fixture
        .conditions("hand-over-custody", &second_input, &["previousCustodyId"])
        .await;
    let (left, right) = tokio::join!(
        fixture.invoke_with(
            "hand-over-custody",
            "race-left",
            &first_input,
            Some(&first_conditions)
        ),
        fixture.invoke_with(
            "hand-over-custody",
            "race-right",
            &second_input,
            Some(&second_conditions)
        ),
    );
    let mut statuses = [left.status, right.status];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::CONFLICT],
        "{} / {}",
        left.body,
        right.body
    );
    assert_eq!(fixture.row_count("custody-handover").await, 1);

    finish(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decision_recorded_now_with_future_effect() {
    let fixture = Fixture::start().await;
    let grant = fixture
        .open("open-grant", "open-grant-1", json!({"grantNumber": "G-1"}))
        .await;
    let recorded = fixture
        .invoke(
            "record-grant-pause",
            "record-1",
            json!({
                "grantId": grant,
                "decidedOn": "2030-01-10",
                "effectiveFrom": "2030-02-01",
                "effectiveUntil": "2030-12-31"
            }),
        )
        .await;
    assert_eq!(recorded.status, StatusCode::OK, "{}", recorded.body);
    let decision = recorded.body["results"]["decision"]["recordId"]
        .as_str()
        .expect("decision result names the record")
        .to_owned();

    // Recording the decision does not change the grant: the effect starts
    // later and is the decision's own fact, not a state change.
    let stored_grant = fixture.get(&format!("/v1/records/grants/{grant}")).await;
    assert_eq!(stored_grant.body["data"]["domainData"]["status"], "active");
    assert_eq!(stored_grant.body["data"]["revisionIdentifier"], "1");

    let stored = fixture
        .get(&format!("/v1/records/grant-pause-decisions/{decision}"))
        .await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.body);
    let data = &stored.body["data"]["domainData"];
    assert_eq!(data["decidedOn"], "2030-01-10");
    assert_eq!(data["effectiveFrom"], "2030-02-01");
    assert_eq!(data["effectiveUntil"], "2030-12-31");

    // The recording instant is the system's own clock, not an authored date.
    let revisions = fixture.revisions("grant-pause-decisions", &decision).await;
    assert_eq!(revisions.status, StatusCode::OK, "{}", revisions.body);
    let created_at = revisions.body["items"][0]["createdAt"]
        .as_str()
        .expect("revision carries its recording instant");
    let created_at =
        time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339)
            .expect("recording instant is RFC 3339");
    let elapsed = time::OffsetDateTime::now_utc() - created_at;
    assert!(
        elapsed >= time::Duration::ZERO && elapsed < time::Duration::minutes(5),
        "recording instant {created_at} is not near now"
    );
    assert!(
        created_at.year() < 2030,
        "recording instant is not the authored decision date"
    );

    // An effective window that ends before it starts is refused whole.
    let inverted = fixture
        .invoke(
            "record-grant-pause",
            "record-2",
            json!({
                "grantId": grant,
                "decidedOn": "2030-01-10",
                "effectiveFrom": "2030-06-01",
                "effectiveUntil": "2030-05-01"
            }),
        )
        .await;
    assert!(
        inverted.status.is_client_error(),
        "{} {}",
        inverted.status,
        inverted.body
    );
    assert_eq!(fixture.row_count("grant-pause-decision").await, 1);

    finish(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_recording_keeps_dates_distinct() {
    let fixture = Fixture::start().await;
    let grant = fixture
        .open("open-grant", "open-grant-1", json!({"grantNumber": "G-1"}))
        .await;
    let recorded = fixture
        .invoke(
            "record-grant-pause",
            "record-late",
            json!({
                "grantId": grant,
                "decidedOn": "2020-03-01",
                "effectiveFrom": "2020-04-01"
            }),
        )
        .await;
    assert_eq!(recorded.status, StatusCode::OK, "{}", recorded.body);
    let decision = recorded.body["results"]["decision"]["recordId"]
        .as_str()
        .expect("decision result names the record")
        .to_owned();

    let stored = fixture
        .get(&format!("/v1/records/grant-pause-decisions/{decision}"))
        .await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.body);
    let data = &stored.body["data"]["domainData"];
    assert_eq!(data["decidedOn"], "2020-03-01");
    assert_eq!(data["effectiveFrom"], "2020-04-01");

    // Optional members the caller never supplied are present as null in
    // both the current record and its revision, so a reader can tell
    // "not stated" from a missing member of the shape.
    assert!(data["effectiveUntil"].is_null(), "{data}");
    assert!(
        data.as_object()
            .expect("domainData is an object")
            .contains_key("effectiveUntil"),
        "{data}"
    );

    let revisions = fixture.revisions("grant-pause-decisions", &decision).await;
    assert_eq!(revisions.status, StatusCode::OK, "{}", revisions.body);
    let revision = &revisions.body["items"][0];
    assert_eq!(revision["domainData"]["decidedOn"], "2020-03-01");
    assert!(revision["domainData"]["effectiveUntil"].is_null());
    assert!(
        revision["domainData"]
            .as_object()
            .expect("revision domainData is an object")
            .contains_key("effectiveUntil"),
        "{revision}"
    );
    let created_at = revision["createdAt"]
        .as_str()
        .expect("revision carries its recording instant");
    assert!(
        !created_at.starts_with("2020"),
        "the recording instant is the system clock, not the decision date: {created_at}"
    );

    finish(fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn correction_links_original() {
    let fixture = Fixture::start().await;
    let grant = fixture
        .open("open-grant", "open-grant-1", json!({"grantNumber": "G-1"}))
        .await;
    let other_grant = fixture
        .open("open-grant", "open-grant-2", json!({"grantNumber": "G-2"}))
        .await;
    let paused = fixture
        .invoke_conditioned(
            "pause-grant",
            "pause-1",
            &["grantId"],
            json!({"grantId": grant, "decidedOn": "2026-10-20", "effectiveFrom": "2026-11-01"}),
        )
        .await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.body);
    let original = paused.body["results"]["decision"]["recordId"]
        .as_str()
        .expect("decision result names the record")
        .to_owned();

    let correction_input = |grant: &str| {
        json!({
            "grantId": grant,
            "originalDecisionId": original,
            "decidedOn": "2026-10-22",
            "effectiveFrom": "2026-11-15"
        })
    };

    // A correction that names a decision of another grant is refused.
    let wrong = fixture
        .invoke(
            "correct-grant-pause",
            "correct-wrong",
            correction_input(&other_grant),
        )
        .await;
    assert_eq!(
        wrong.status,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        wrong.body
    );
    assert_eq!(wrong.body["guardReason"], "wrong-grant");
    assert_eq!(fixture.row_count("grant-pause-decision").await, 1);

    let corrected = fixture
        .invoke("correct-grant-pause", "correct-1", correction_input(&grant))
        .await;
    assert_eq!(corrected.status, StatusCode::OK, "{}", corrected.body);
    let correction = corrected.body["results"]["correction"]["recordId"]
        .as_str()
        .expect("correction result names the record")
        .to_owned();
    assert_ne!(correction, original);

    let stored = fixture
        .get(&format!("/v1/records/grant-pause-decisions/{correction}"))
        .await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.body);
    assert_eq!(
        stored.body["data"]["domainData"]["corrects"],
        json!(original)
    );

    // The original keeps its content and its single revision.
    let unchanged = fixture
        .get(&format!("/v1/records/grant-pause-decisions/{original}"))
        .await;
    assert_eq!(unchanged.status, StatusCode::OK, "{}", unchanged.body);
    assert_eq!(unchanged.body["data"]["revisionIdentifier"], "1");
    assert_eq!(
        unchanged.body["data"]["domainData"]["decidedOn"],
        "2026-10-20"
    );
    assert_eq!(
        unchanged.body["data"]["domainData"]["effectiveFrom"],
        "2026-11-01"
    );
    assert!(unchanged.body["data"]["domainData"]["corrects"].is_null());
    assert_eq!(fixture.row_count("grant-pause-decision").await, 2);

    finish(fixture).await;
}
