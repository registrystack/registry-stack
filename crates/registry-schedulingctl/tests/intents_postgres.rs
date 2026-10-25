// SPDX-License-Identifier: Apache-2.0

//! `intents` against a real PostgreSQL, on a disposable schema.
//!
//! The test proves the read path end to end: a pending intent the dispatcher
//! is still carrying, a delivered one, a superseded reminder and a reminder
//! cancelled before any attempt are never listed, a `local` intent (set aside because no destination is declared)
//! and a `failed` one (every attempt refused) both are, oldest due first, and
//! a `--limit` narrower than the qualifying rows keeps only the earliest of
//! them. Every field the command reports is pinned
//! against what was seeded, so nothing beyond what the test asserts on is
//! carried through.

use chrono::{DateTime, Duration, SubsecRound, Utc};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::{PostgresStore, StoreError};
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

/// A minimal exact-time policy that passes its checks, in the vocabulary of
/// the standalone starter project. `RuntimeConfig::check` reads and
/// validates the authored policy at `package.root`, so a deployment
/// configuration this test can load needs one, even though `intents` itself
/// never reads it.
const POLICY: &str = r#"apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project:
  id: registry-updates
  version: "1"
services:
  - id: registry-update
    label: Registry record update
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: bangkok-counter
    because: A 30-minute registry update at an interchangeable counter station.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: update-stations
      startIncrementMinutes: 30
      maximumRecipients: 1
    cancellationCutoffMinutes: 240
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry offices.
openings:
  - id: bangkok-counter-hours
    location: bangkok-counter
    holidaySet: office-holidays
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:30"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: Counter opening hours reviewed by the office manager.
channels: [public, assisted]
holdPolicy:
  ttlMinutes: 5
  maximumPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

fn scoped_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

/// `intents` builds its own single-threaded runtime, so the call runs on a
/// plain thread: it cannot nest inside this test's runtime.
fn undelivered(config: &Path, limit: i64) -> Value {
    let config = config.to_path_buf();
    std::thread::spawn(move || registry_schedulingctl::intents::undelivered(&config, limit))
        .join()
        .expect("intents does not panic")
        .expect("intents succeeds")
}

async fn seed_claim(client: &tokio_postgres::Client, claim_id: Uuid) {
    client
        .batch_execute("SET registry_scheduling.allocation_writer = 'v2'")
        .await
        .expect("the fixture uses the current allocation writer contract");
    client
        .execute(
            "INSERT INTO scheduling_claims(claim_id, kind, state, offering, supply_id, \
             displayed_start, displayed_end, occupied_start, occupied_end, units, \
             revision, policy_revision, actor, operational_service, operational_location, operational_mode) \
             VALUES($1,'booking','active','registry-update-30','station-1', \
             now(), now(), now(), now(), 1, 1, 1, 'actor-pseudonym', 'registry-update', 'main-office', 'exact-time')",
            &[&claim_id],
        )
        .await
        .expect("a claim seeds cleanly");
}

#[allow(clippy::too_many_arguments)]
async fn seed_outbox(
    client: &tokio_postgres::Client,
    outbox_id: Uuid,
    purpose: &str,
    claim_id: Uuid,
    appointment_revision: i64,
    due_at: DateTime<Utc>,
    delivery_state: &str,
    attempts: i16,
    payload: &Value,
) {
    // The command reports the dispatch core's terminal states in the
    // store's own terms; seed each in the core's vocabulary.
    let (state, class) = match delivery_state {
        "local" => ("dead-lettered", Some("destination_unconfigured")),
        "failed" => ("dead-lettered", Some("delivery_failed")),
        "superseded" => ("dead-lettered", Some("superseded")),
        other => (other, None),
    };
    client
        .execute(
            "INSERT INTO scheduling_outbox(outbox_id, purpose, generation, state, attempt, \
             next_attempt_at, delivered_at, dead_lettered_at, claim_id, \
             appointment_revision, due_at, payload, last_failure_class) \
             VALUES($1,$2,1,$6,$7, \
                    CASE WHEN $6='pending' THEN $5::timestamptz END, \
                    CASE WHEN $6='delivered' THEN $5::timestamptz END, \
                    CASE WHEN $6='dead-lettered' THEN $5::timestamptz END, \
                    $3,$4,$5,$8,$9)",
            &[
                &outbox_id,
                &purpose,
                &claim_id,
                &appointment_revision,
                &due_at,
                &state,
                &attempts,
                payload,
                &class,
            ],
        )
        .await
        .expect("an outbox row seeds cleanly");
}

#[tokio::test]
async fn intents_lists_local_and_failed_oldest_due_first_and_respects_limit() {
    let base = std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("intents_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("the test server accepts an administrative connection");
    tokio::spawn(async move {
        connection
            .await
            .expect("the administrative connection stays up")
    });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("a disposable schema is created");

    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("scheduling.yaml"), POLICY).unwrap();
    registry_platform_config::package::write_sum_file(
        &project,
        None,
        &registry_scheduling::config::package_limits(),
        registry_scheduling::config::PACKAGE_COMMAND,
    )
    .expect("the package is sealed");
    std::fs::write(
        root.path().join("runtime.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8106\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             identity:\n  databaseId: scheduling-ctl-test\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   allowedClients: [scheduling-test-client]\n\
             database:\n  runtimeUrlRef: secret:env/SCHEDULING_INTENTS_TEST_DATABASE\n\
             \x20 migrationUrlRef: secret:env/SCHEDULING_INTENTS_TEST_DATABASE\n\
             \x20 testOnlyPlaintext: true\n\
             taskGrantStatus: unchecked-final-fifteen-minutes\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/SCHEDULING_INTENTS_TEST_AUDIT\n\
             retention:\n  receiptRetentionDays: 2\n",
            project = project.display(),
            audit = root.path().join("audit.ndjson").display(),
        ),
    )
    .unwrap();
    let config_path = root.path().join("runtime.yaml");
    std::env::set_var(
        "SCHEDULING_INTENTS_TEST_DATABASE",
        scoped_url(&base, &schema),
    );
    std::env::set_var(
        "SCHEDULING_INTENTS_TEST_AUDIT",
        "0123456789abcdef0123456789abcdef",
    );

    let config = RuntimeConfig::load(&config_path).expect("the runtime configuration loads");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment secret provider configures");
    let store = PostgresStore::connect_migration(&config.database, &resolver).unwrap();
    store.migrate().await.expect("the schema migrates");

    let seed = tokio_postgres::connect(&scoped_url(&base, &schema), tokio_postgres::NoTls)
        .await
        .expect("a seeding connection scoped to the schema connects");
    tokio::spawn(async move { seed.1.await.expect("the seeding connection stays up") });
    let seed = seed.0;

    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();
    seed_claim(&seed, claim_a).await;
    seed_claim(&seed, claim_b).await;

    // PostgreSQL `timestamptz` holds microseconds, so the nanosecond tail of a
    // clock reading does not survive the round trip through `due_at`. Truncating
    // at the source keeps the seeded instant and the `dueAt` the command reports
    // comparable as strings on any clock.
    let base_time = Utc::now().trunc_subsecs(6);
    let pending_id = Uuid::new_v4();
    let local_first_id = Uuid::new_v4();
    let failed_id = Uuid::new_v4();
    let delivered_id = Uuid::new_v4();
    let local_second_id = Uuid::new_v4();
    let cancelled_id = Uuid::new_v4();

    let local_first_payload =
        json!({"appointmentId": claim_a, "revision": 1, "offering": "registry-update-30"});
    let failed_payload =
        json!({"appointmentId": claim_b, "revision": 2, "offering": "registry-update-30"});
    let local_second_payload =
        json!({"appointmentId": claim_a, "revision": 3, "offering": "registry-update-30"});

    // Still carried by the dispatcher: never listed.
    seed_outbox(
        &seed,
        pending_id,
        "reminder",
        claim_a,
        1,
        base_time,
        "pending",
        0,
        &json!({"appointmentId": claim_a, "revision": 1, "offering": "registry-update-30"}),
    )
    .await;
    // No destination declared: listed.
    seed_outbox(
        &seed,
        local_first_id,
        "reminder",
        claim_a,
        1,
        base_time + Duration::seconds(60),
        "local",
        1,
        &local_first_payload,
    )
    .await;
    // Every attempt refused: listed.
    seed_outbox(
        &seed,
        failed_id,
        "confirmation",
        claim_b,
        2,
        base_time + Duration::seconds(120),
        "failed",
        8,
        &failed_payload,
    )
    .await;
    // Delivered: never listed.
    seed_outbox(
        &seed,
        delivered_id,
        "reminder",
        claim_b,
        2,
        base_time + Duration::seconds(180),
        "delivered",
        1,
        &json!({"appointmentId": claim_b, "revision": 2, "offering": "registry-update-30"}),
    )
    .await;
    // Superseded by a later revision: retained as accounting, never listed.
    seed_outbox(
        &seed,
        Uuid::new_v4(),
        "reminder",
        claim_b,
        1,
        base_time + Duration::seconds(200),
        "superseded",
        1,
        &json!({"appointmentId": claim_b, "revision": 1, "offering": "registry-update-30"}),
    )
    .await;
    // Cancelled by its appointment's cancellation before any attempt:
    // never sent and never listed.
    seed_outbox(
        &seed,
        cancelled_id,
        "reminder",
        claim_b,
        1,
        base_time + Duration::seconds(220),
        "cancelled",
        0,
        &json!({"appointmentId": claim_b, "revision": 1, "offering": "registry-update-30"}),
    )
    .await;
    // A second, later local intent: listed last.
    seed_outbox(
        &seed,
        local_second_id,
        "reminder",
        claim_a,
        3,
        base_time + Duration::seconds(240),
        "local",
        1,
        &local_second_payload,
    )
    .await;

    let report = undelivered(&config_path, 10);
    assert_eq!(report["command"], "intents");
    let intents = report["intents"].as_array().expect("intents is an array");
    assert_eq!(intents.len(), 3, "{intents:?}");

    assert_eq!(intents[0]["outboxId"], local_first_id.to_string());
    assert_eq!(intents[0]["purpose"], "reminder");
    assert_eq!(intents[0]["claimId"], claim_a.to_string());
    assert_eq!(intents[0]["appointmentRevision"], 1);
    assert_eq!(
        intents[0]["dueAt"],
        (base_time + Duration::seconds(60)).to_rfc3339()
    );
    assert_eq!(intents[0]["deliveryState"], "local");
    assert_eq!(intents[0]["attempts"], 1);
    assert_eq!(intents[0]["payload"], local_first_payload);

    assert_eq!(intents[1]["outboxId"], failed_id.to_string());
    assert_eq!(intents[1]["purpose"], "confirmation");
    assert_eq!(intents[1]["claimId"], claim_b.to_string());
    assert_eq!(intents[1]["appointmentRevision"], 2);
    assert_eq!(
        intents[1]["dueAt"],
        (base_time + Duration::seconds(120)).to_rfc3339()
    );
    assert_eq!(intents[1]["deliveryState"], "failed");
    assert_eq!(intents[1]["attempts"], 8);
    assert_eq!(intents[1]["payload"], failed_payload);

    assert_eq!(intents[2]["outboxId"], local_second_id.to_string());
    assert_eq!(intents[2]["deliveryState"], "local");
    assert_eq!(intents[2]["payload"], local_second_payload);

    // A pending intent the dispatcher still carries, a delivered one, a
    // superseded reminder and a cancelled one are never listed, regardless
    // of the limit.
    let outbox_ids: Vec<&str> = intents
        .iter()
        .map(|intent| intent["outboxId"].as_str().unwrap())
        .collect();
    assert!(!outbox_ids.contains(&pending_id.to_string().as_str()));
    assert!(!outbox_ids.contains(&delivered_id.to_string().as_str()));
    assert!(!outbox_ids.contains(&cancelled_id.to_string().as_str()));

    // A limit narrower than the qualifying rows keeps only the earliest due.
    let limited = undelivered(&config_path, 2);
    let limited_intents = limited["intents"].as_array().expect("intents is an array");
    assert_eq!(limited_intents.len(), 2);
    assert_eq!(limited_intents[0]["outboxId"], local_first_id.to_string());
    assert_eq!(limited_intents[1]["outboxId"], failed_id.to_string());

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("the disposable schema is dropped");

    // The store owns the same bound as the CLI. These values are refused
    // before PostgreSQL is queried, which the already-dropped schema proves.
    for limit in [0, -1, 201, i64::MAX] {
        assert!(
            matches!(
                store.undelivered_intents(limit).await,
                Err(StoreError::InvalidUndeliveredIntentsLimit)
            ),
            "{limit} must be refused before SQL"
        );
    }
}
