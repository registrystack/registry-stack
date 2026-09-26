// SPDX-License-Identifier: Apache-2.0

//! `records apply` against a real PostgreSQL, on a disposable schema.
//!
//! The test proves the one attributable operator write end to end: the schema
//! migration runs, the first document lands whole (locations, pools, members,
//! and the typed exception columns), a second document replaces the first
//! rather than appending to it, and every apply writes a `request` audit
//! entry before its transaction and a `response` entry carrying the
//! operator's allowed reason after it commits, to the `schedulingctl` sibling
//! of the runtime's audit file.

use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::PostgresStore;
use registry_schedulingctl::records;
use serde_json::{json, Value};
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
  - id: registry-arrivals
    service: registry-update
    label: Counter arrivals
    mode: arrival-window
    location: bangkok-counter
    because: Arrivals join an operator-published window.
    arrival:
      window: morning-arrivals
      leadTimeMinutes: 60
      horizonDays: 45
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
windows:
  - id: morning-arrivals
    revision: 1
    offering: registry-arrivals
    location: bangkok-counter
    start: 2026-10-08T02:00:00Z
    end: 2026-10-08T04:00:00Z
    units: 10
    unitsPolicy: {kind: fixed, units: 1, because: Each arrival consumes one unit.}
    subquotas: []
    because: The operator published the morning arrival block.
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
windows:
  - id: morning-arrivals
    revision: 2
    offering: registry-arrivals
    location: bangkok-counter
    start: 2026-10-08T03:00:00Z
    end: 2026-10-08T05:00:00Z
    units: 8
    unitsPolicy: {kind: fixed, units: 1, because: Each arrival consumes one unit.}
    subquotas: []
    because: The operator republished the arrival block.
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

fn apply_error(config: &Path, records_path: &Path) -> String {
    let config = config.to_path_buf();
    let records_path = records_path.to_path_buf();
    std::thread::spawn(move || {
        let error = records::apply(&config, &records_path).expect_err("records apply refuses");
        format!("{error:#}")
    })
    .join()
    .expect("records apply does not panic")
}

/// Every entry the audit file at `path` holds, in write order.
fn audit_entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("an audit entry is JSON"))
        .collect()
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
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
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

    let config = RuntimeConfig::load(&config_path).expect("the runtime configuration loads");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment secret provider configures");
    let store = PostgresStore::connect_migration(&config.database, &resolver).unwrap();
    store.migrate().await.expect("the schema migrates");
    store
        .adopt("registry-updates")
        .await
        .expect("the policy identity adopts the database");

    let report = apply(&config_path, &root.path().join("first.yaml"));
    assert_eq!(report["command"], "records-apply");
    assert_eq!(
        report["applied"],
        json!({"locations": 1, "pools": 1, "members": 2, "windows": 1, "exceptions": 1})
    );

    let (facts, _) = store.facts().await.unwrap();
    assert_eq!(facts.locations.len(), 1);
    assert_eq!(facts.locations[0].id, "bangkok-counter");
    assert_eq!(facts.locations[0].timezone, "Asia/Bangkok");
    assert_eq!(facts.pools.len(), 1);
    assert_eq!(facts.pools[0].id, "update-stations");
    assert_eq!(facts.windows.len(), 1);
    assert_eq!(facts.windows[0].id, "morning-arrivals");
    assert_eq!(facts.windows[0].revision, 1);
    let member_ids: Vec<&str> = facts.pools[0]
        .members
        .iter()
        .map(|member| member.resource_id.as_str())
        .collect();
    assert_eq!(member_ids, vec!["station-1", "station-2"]);
    assert_eq!(facts.exceptions.len(), 1);
    assert_eq!(facts.exceptions[0].id, "staff-training");
    assert_eq!(facts.exceptions[0].date, "2026-10-07");

    // The command writes beside the runtime's audit file, never into it.
    let audit_path = root.path().join("audit.schedulingctl.ndjson");
    assert!(!root.path().join("audit.ndjson").exists());
    let audit = audit_entries(&audit_path);
    assert_eq!(audit.len(), 2, "{audit:?}");
    let (request, response) = (&audit[0], &audit[1]);
    assert_eq!(request["schema"], "registry-scheduling-audit/v1");
    assert_eq!(request["phase"], "request");
    assert_eq!(response["phase"], "response");
    assert_eq!(request["correlation"], response["correlation"]);
    assert_eq!(request["record"]["operation"], "records.apply");
    assert_eq!(request["record"]["actorKind"], "operator");
    assert!(request["record"]["outcome"].is_null());
    assert_eq!(response["record"]["outcome"], "allowed");
    assert_eq!(response["record"]["reason"], "authorization.allowed");
    assert_eq!(response["record"]["eventId"], response["correlation"]);
    assert_eq!(response["record"]["counts"]["exceptions"], 1);
    assert_eq!(response["record"]["counts"]["windows"], 1);

    // The second document replaces the first: the second location lands, the
    // retired station is gone, and the closure does not survive.
    let report = apply(&config_path, &root.path().join("second.yaml"));
    assert_eq!(
        report["applied"],
        json!({"locations": 2, "pools": 1, "members": 1, "windows": 1, "exceptions": 0})
    );
    let (facts, _) = store.facts().await.unwrap();
    assert_eq!(facts.locations.len(), 2);
    let retired_station = facts
        .pools
        .iter()
        .flat_map(|pool| pool.members.iter())
        .any(|member| member.resource_id == "station-2");
    assert!(!retired_station, "a replace is not an append");
    assert!(facts.exceptions.is_empty(), "the closure did not survive");
    assert_eq!(facts.windows.len(), 1);
    assert_eq!(facts.windows[0].revision, 2, "the window was replaced");

    let audit = audit_entries(&audit_path);
    assert_eq!(audit.len(), 4, "{audit:?}");
    assert!(audit
        .iter()
        .filter(|entry| entry["phase"] == "response")
        .all(|entry| entry["record"]["reason"] == "authorization.allowed"));

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("the disposable schema is dropped");
}

#[tokio::test]
async fn records_apply_rejects_a_different_deployment_identity_without_writing() {
    let base = std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("records_identity_{}", Uuid::new_v4().simple());
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
    let adopted_project = root.path().join("adopted-project");
    let other_project = root.path().join("other-project");
    std::fs::create_dir_all(&adopted_project).unwrap();
    std::fs::create_dir_all(&other_project).unwrap();
    std::fs::write(adopted_project.join("scheduling.yaml"), POLICY).unwrap();
    std::fs::write(
        other_project.join("scheduling.yaml"),
        POLICY.replacen("  id: registry-updates\n", "  id: permit-renewals\n", 1),
    )
    .unwrap();
    std::fs::write(root.path().join("first.yaml"), FIRST_RECORDS).unwrap();
    std::fs::write(root.path().join("second.yaml"), SECOND_RECORDS).unwrap();

    let runtime = |project: &Path, audit: &Path| {
        format!(
            "apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             database:\n  runtimeUrlRef: secret:env/SCHEDULING_RECORDS_IDENTITY_DATABASE\n\
             \x20 migrationUrlRef: secret:env/SCHEDULING_RECORDS_IDENTITY_DATABASE\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/SCHEDULING_RECORDS_IDENTITY_AUDIT\n\
             retention:\n  attemptReceiptDays: 2\n",
            project = project.display(),
            audit = audit.display(),
        )
    };
    let adopted_config = root.path().join("adopted-runtime.yaml");
    let other_config = root.path().join("other-runtime.yaml");
    std::fs::write(
        &adopted_config,
        runtime(&adopted_project, &root.path().join("adopted-audit.ndjson")),
    )
    .unwrap();
    std::fs::write(
        &other_config,
        runtime(&other_project, &root.path().join("other-audit.ndjson")),
    )
    .unwrap();
    std::env::set_var(
        "SCHEDULING_RECORDS_IDENTITY_DATABASE",
        scoped_url(&base, &schema),
    );
    std::env::set_var(
        "SCHEDULING_RECORDS_IDENTITY_AUDIT",
        "0123456789abcdef0123456789abcdef",
    );

    let config =
        RuntimeConfig::load(&adopted_config).expect("the adopted runtime configuration loads");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment secret provider configures");
    let store = PostgresStore::connect_migration(&config.database, &resolver).unwrap();
    store.migrate().await.expect("the schema migrates");
    store
        .adopt("registry-updates")
        .await
        .expect("the first policy identity adopts the database");
    apply(&adopted_config, &root.path().join("first.yaml"));
    let (before, _) = store.facts().await.expect("the first records landed");

    let error = apply_error(&other_config, &root.path().join("second.yaml"));
    assert_eq!(
        error,
        "replacing the environment records: the Scheduling database belongs to another deployment"
    );
    let (after, _) = store
        .facts()
        .await
        .expect("the existing records remain readable");
    assert_eq!(
        after, before,
        "the refused apply changed the existing facts"
    );
    // The request entry was written before the transaction the store
    // refused; the refusal still writes a paired response so the request is
    // never left orphaned.
    let refused = audit_entries(&root.path().join("other-audit.schedulingctl.ndjson"));
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(refused[0]["phase"], "request");
    assert_eq!(refused[1]["phase"], "response");
    assert_eq!(refused[0]["correlation"], refused[1]["correlation"]);
    assert_eq!(refused[1]["record"]["outcome"], "refused");
    assert_eq!(refused[1]["record"]["reason"], "records.replace-failed");
    assert_eq!(refused[1]["record"]["eventId"], refused[1]["correlation"]);
    assert!(
        refused[1]["record"]["detail"]
            .as_str()
            .unwrap()
            .contains("the Scheduling database belongs to another deployment"),
        "{refused:?}"
    );

    // An audit destination that cannot be opened refuses the apply before
    // the database is written.
    let blocked_config = root.path().join("blocked-runtime.yaml");
    std::fs::write(
        &blocked_config,
        runtime(&adopted_project, &root.path().join("blocked-audit.ndjson")),
    )
    .unwrap();
    std::fs::create_dir(root.path().join("blocked-audit.schedulingctl.ndjson")).unwrap();
    let error = apply_error(&blocked_config, &root.path().join("second.yaml"));
    assert!(
        error.starts_with("opening the schedulingctl audit destination"),
        "{error}"
    );
    let (unchanged, _) = store
        .facts()
        .await
        .expect("the existing records remain readable");
    assert_eq!(
        unchanged, before,
        "an unaudited apply changed the existing facts"
    );

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("the disposable schema is dropped");
}
