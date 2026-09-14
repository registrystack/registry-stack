// SPDX-License-Identifier: Apache-2.0

//! `records apply` against a real PostgreSQL, on a disposable schema.
//!
//! The test proves the one attributable operator write end to end: the schema
//! migration runs, the first document lands whole (locations, pools, members,
//! and the typed exception columns), a second document replaces the first
//! rather than appending to it, and every apply leaves its audit row in the
//! outbox carrying the operator's allowed reason.

use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::PostgresStore;
use registry_schedulingctl::records;
use serde_json::json;
use std::path::Path;
use uuid::Uuid;

/// A minimal exact-time policy that passes its checks, in the vocabulary of
/// the standalone starter project.
const POLICY: &str = r#"apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: registry-updates
  version: 1
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
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry offices.
    dates: []
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
windows: []
holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

const FIRST_RECORDS: &str = r#"locations:
  - id: bangkok-counter
    timezone: Asia/Bangkok
pools:
  - id: update-stations
    members:
      - resourceId: station-1
        capabilities: []
        available: true
      - resourceId: station-2
        capabilities: []
        available: true
exceptions:
  - id: staff-training
    location: bangkok-counter
    kind: closure
    date: "2026-10-07"
    startTime: "09:00"
    endTime: "12:30"
"#;

const SECOND_RECORDS: &str = r#"locations:
  - id: bangkok-counter
    timezone: Asia/Bangkok
  - id: chiang-mai-counter
    timezone: Asia/Bangkok
pools:
  - id: update-stations
    members:
      - resourceId: station-1
        capabilities: []
        available: true
"#;

fn scoped_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

/// `records apply` builds its own single-threaded runtime, so the call runs
/// on a plain thread: it cannot nest inside this test's runtime.
fn apply(config: &Path, records_path: &Path) -> serde_json::Value {
    let config = config.to_path_buf();
    let records_path = records_path.to_path_buf();
    std::thread::spawn(move || records::apply(&config, &records_path))
        .join()
        .expect("records apply does not panic")
        .expect("records apply succeeds")
}

#[tokio::test]
async fn records_apply_replaces_facts_wholesale_and_audits_each_write() {
    let base = std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("records_apply_{}", Uuid::new_v4().simple());
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

    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("scheduling.yaml"), POLICY).unwrap();
    std::fs::write(root.path().join("first.yaml"), FIRST_RECORDS).unwrap();
    std::fs::write(root.path().join("second.yaml"), SECOND_RECORDS).unwrap();
    std::fs::write(
        root.path().join("runtime.yaml"),
        format!(
            "apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             database:\n  runtimeUrlRef: secret:env/SCHEDULING_RECORDS_TEST_DATABASE\n\
             \x20 migrationUrlRef: secret:env/SCHEDULING_RECORDS_TEST_DATABASE\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/SCHEDULING_RECORDS_TEST_AUDIT\n\
             retention:\n  attemptReceiptDays: 2\n",
            project = project.display(),
            audit = root.path().join("audit.ndjson").display(),
        ),
    )
    .unwrap();
    let config_path = root.path().join("runtime.yaml");
    std::env::set_var(
        "SCHEDULING_RECORDS_TEST_DATABASE",
        scoped_url(&base, &schema),
    );
    std::env::set_var(
        "SCHEDULING_RECORDS_TEST_AUDIT",
        "0123456789abcdef0123456789abcdef",
    );

    let report = apply(&config_path, &root.path().join("first.yaml"));
    assert_eq!(report["command"], "records-apply");
    assert_eq!(
        report["applied"],
        json!({"locations": 1, "pools": 1, "members": 2, "exceptions": 1})
    );

    let config = RuntimeConfig::load(&config_path).expect("the runtime configuration loads");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment secret provider configures");
    let store = PostgresStore::connect_runtime(&config.database, &resolver).unwrap();

    let facts = store.facts().await.unwrap();
    assert_eq!(facts.locations.len(), 1);
    assert_eq!(facts.locations[0].id, "bangkok-counter");
    assert_eq!(facts.locations[0].timezone, "Asia/Bangkok");
    assert_eq!(facts.pools.len(), 1);
    assert_eq!(facts.pools[0].id, "update-stations");
    let member_ids: Vec<&str> = facts.pools[0]
        .members
        .iter()
        .map(|member| member.resource_id.as_str())
        .collect();
    assert_eq!(member_ids, vec!["station-1", "station-2"]);
    assert_eq!(facts.exceptions.len(), 1);
    assert_eq!(facts.exceptions[0].id, "staff-training");
    assert_eq!(facts.exceptions[0].date, "2026-10-07");

    let audit = store.pending_audit(10).await.unwrap();
    let applies: Vec<_> = audit
        .iter()
        .filter(|(_, record)| record["operation"] == "records.apply")
        .collect();
    assert_eq!(applies.len(), 1, "{audit:?}");
    assert_eq!(applies[0].1["outcome"], "allowed");
    assert_eq!(applies[0].1["reason"], "authorization.allowed");
    assert_eq!(applies[0].1["counts"]["exceptions"], 1);

    // The second document replaces the first: the second location lands, the
    // retired station is gone, and the closure does not survive.
    let report = apply(&config_path, &root.path().join("second.yaml"));
    assert_eq!(
        report["applied"],
        json!({"locations": 2, "pools": 1, "members": 1, "exceptions": 0})
    );
    let facts = store.facts().await.unwrap();
    assert_eq!(facts.locations.len(), 2);
    let retired_station = facts
        .pools
        .iter()
        .flat_map(|pool| pool.members.iter())
        .any(|member| member.resource_id == "station-2");
    assert!(!retired_station, "a replace is not an append");
    assert!(facts.exceptions.is_empty(), "the closure did not survive");

    let audit = store.pending_audit(10).await.unwrap();
    let applies: Vec<_> = audit
        .iter()
        .filter(|(_, record)| record["operation"] == "records.apply")
        .collect();
    assert_eq!(applies.len(), 2, "{audit:?}");
    assert!(applies
        .iter()
        .all(|(_, record)| record["reason"] == "authorization.allowed"));

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("the disposable schema is dropped");
}
