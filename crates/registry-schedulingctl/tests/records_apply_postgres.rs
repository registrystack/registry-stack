// SPDX-License-Identifier: Apache-2.0

//! `records apply` against a real PostgreSQL, on a disposable schema.
//!
//! The test proves the one attributable operator write end to end: the
//! package is activated, the first document lands whole (locations, pools, members,
//! and the typed exception columns), a second document replaces the first
//! rather than appending to it, and every apply writes a `request` audit
//! entry before its transaction and a `response` entry carrying the
//! operator's allowed reason after it commits, to the `schedulingctl` sibling
//! of the runtime's audit file.

use registry_platform_config::{SecretProvider, SecretResolver};
use registry_scheduling::config::RuntimeConfig;
use registry_scheduling::store::PostgresStore;
use registry_schedulingctl::{activation, records};
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

/// A minimal exact-time policy that passes its checks, in the vocabulary of
/// the standalone starter project.
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

const FIRST_RECORDS: &str = r#"apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1
kind: SchedulingRecords
locations:
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
    unitsPolicy: {type: fixed, units: 1, because: Each arrival consumes one unit.}
    because: The operator published the morning arrival block.
exceptions:
  - id: staff-training
    location: bangkok-counter
    kind: closure
    date: "2026-10-07"
    startTime: "09:00"
    endTime: "12:30"
"#;

const SECOND_RECORDS: &str = r#"apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1
kind: SchedulingRecords
locations:
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
    unitsPolicy: {type: fixed, units: 1, because: Each arrival consumes one unit.}
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

/// Activate the package `config` names, the way an operator does before
/// the first records apply.
fn activate(config: &Path) {
    let config = config.to_path_buf();
    std::thread::spawn(move || activation::apply(&config, None, &[]))
        .join()
        .expect("apply does not panic")
        .expect("the package activates");
}

/// Every `records apply` entry the audit file at `path` holds, in write
/// order; the activation entries beside them carry their own schema.
fn audit_entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("an audit entry is JSON"))
        .filter(|entry| entry["schema"] == "registry-scheduling-audit/v1")
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
    std::fs::write(root.path().join("first.yaml"), FIRST_RECORDS).unwrap();
    std::fs::write(root.path().join("second.yaml"), SECOND_RECORDS).unwrap();
    std::fs::write(
        root.path().join("runtime.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             identity:\n  databaseId: scheduling-ctl-test\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   allowedClients: [scheduling-test-client]\n\
             database:\n  runtimeUrlRef: secret:env/SCHEDULING_RECORDS_TEST_DATABASE\n\
             \x20 migrationUrlRef: secret:env/SCHEDULING_RECORDS_TEST_DATABASE\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/SCHEDULING_RECORDS_TEST_AUDIT\n\
             retention:\n  attemptReceiptRetentionDays: 2\n",
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
    activate(&config_path);

    let report = apply(&config_path, &root.path().join("first.yaml"));
    assert_eq!(report["command"], "records apply");
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

    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
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
    registry_platform_config::package::write_sum_file(
        &adopted_project,
        None,
        &registry_scheduling::config::package_limits(),
        registry_scheduling::config::PACKAGE_COMMAND,
    )
    .expect("the package is sealed");
    registry_platform_config::package::write_sum_file(
        &other_project,
        None,
        &registry_scheduling::config::package_limits(),
        registry_scheduling::config::PACKAGE_COMMAND,
    )
    .expect("the package is sealed");
    std::fs::write(root.path().join("first.yaml"), FIRST_RECORDS).unwrap();
    std::fs::write(root.path().join("second.yaml"), SECOND_RECORDS).unwrap();

    let runtime = |project: &Path, audit: &Path| {
        format!(
            "apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             identity:\n  databaseId: scheduling-ctl-test\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   allowedClients: [scheduling-test-client]\n\
             database:\n  runtimeUrlRef: secret:env/SCHEDULING_RECORDS_IDENTITY_DATABASE\n\
             \x20 migrationUrlRef: secret:env/SCHEDULING_RECORDS_IDENTITY_DATABASE\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/SCHEDULING_RECORDS_IDENTITY_AUDIT\n\
             retention:\n  attemptReceiptRetentionDays: 2\n",
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
    activate(&adopted_config);
    apply(&adopted_config, &root.path().join("first.yaml"));
    let (before, _) = store.facts().await.expect("the first records landed");

    // Another deployment's package is not the one the ledger names, so it
    // is refused before its audit opens or the database is written.
    let error = apply_error(&other_config, &root.path().join("second.yaml"));
    assert!(error.contains("is not the active package"), "{error}");
    let (after, _) = store
        .facts()
        .await
        .expect("the existing records remain readable");
    assert_eq!(after, before, "the refused package changed the facts");
    assert!(
        audit_entries(&root.path().join("other-audit.schedulingctl.ndjson")).is_empty(),
        "the refused package wrote an audit entry"
    );

    // A deployment row naming another scheduling id under the active
    // package is refused inside the replacement transaction.
    admin
        .batch_execute(&format!(
            "UPDATE {schema}.scheduling_meta SET scheduling_id = 'permit-renewals'"
        ))
        .await
        .expect("the deployment row is rebound");
    let error = apply_error(&adopted_config, &root.path().join("second.yaml"));
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
    let entries = audit_entries(&root.path().join("adopted-audit.schedulingctl.ndjson"));
    assert_eq!(entries.len(), 4, "{entries:?}");
    let refused = &entries[2..];
    assert_eq!(refused[0]["phase"], "request");
    assert_eq!(refused[1]["phase"], "response");
    assert_eq!(refused[0]["correlation"], refused[1]["correlation"]);
    assert_eq!(refused[1]["record"]["outcome"], "refused");
    assert_eq!(refused[1]["record"]["reason"], "records.replace-failed");
    assert_eq!(refused[1]["record"]["eventId"], refused[1]["correlation"]);
    // The store's refusal can name records and carry driver diagnostics, so
    // it reaches the command's error, never the closed audit record.
    let mut keys: Vec<&str> = refused[1]["record"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "actorKind",
            "counts",
            "eventId",
            "operation",
            "outcome",
            "reason"
        ]
    );
    let text =
        std::fs::read_to_string(root.path().join("adopted-audit.schedulingctl.ndjson")).unwrap();
    assert!(
        !text.contains("belongs to another deployment"),
        "the store's refusal leaked into the audit stream: {text}"
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

/// A database no package was ever activated on, or one where another
/// package is active, refuses the records, naming the commands that activate
/// this one, and neither the database nor the audit stream is written.
#[tokio::test]
async fn records_apply_refuses_a_database_where_this_package_is_not_active() {
    let base = std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("records_inactive_{}", Uuid::new_v4().simple());
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
    std::fs::write(root.path().join("first.yaml"), FIRST_RECORDS).unwrap();
    let runtime_text = format!(
        "apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             identity:\n  databaseId: scheduling-ctl-test\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   allowedClients: [scheduling-test-client]\n\
             database:\n  runtimeUrlRef: secret:env/SCHEDULING_RECORDS_INACTIVE_DATABASE\n\
             \x20 migrationUrlRef: secret:env/SCHEDULING_RECORDS_INACTIVE_DATABASE\n\
             \x20 testOnlyPlaintext: true\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/SCHEDULING_RECORDS_INACTIVE_AUDIT\n\
             retention:\n  attemptReceiptRetentionDays: 2\n",
        project = project.display(),
        audit = root.path().join("audit.ndjson").display(),
    );
    std::fs::write(root.path().join("runtime.yaml"), &runtime_text).unwrap();
    let config_path = root.path().join("runtime.yaml");
    std::env::set_var(
        "SCHEDULING_RECORDS_INACTIVE_DATABASE",
        scoped_url(&base, &schema),
    );
    std::env::set_var(
        "SCHEDULING_RECORDS_INACTIVE_AUDIT",
        "0123456789abcdef0123456789abcdef",
    );
    let config = RuntimeConfig::load(&config_path).expect("the runtime configuration loads");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment secret provider configures");
    let store = PostgresStore::connect_migration(&config.database, &resolver).unwrap();
    // The schema is current, so only the missing activation stands between
    // the records and the database.
    store.migrate().await.expect("the schema migrates");

    let error = apply_error(&config_path, &root.path().join("first.yaml"));
    assert_eq!(
        error,
        "no Scheduling package has been applied to this database; run \
         `schedulingctl plan --runtime-config FILE` then \
         `schedulingctl apply --runtime-config FILE`"
    );
    let (facts, _) = store.facts().await.expect("the empty records are readable");
    assert!(
        facts.locations.is_empty(),
        "the refused apply wrote records"
    );
    assert!(
        !root.path().join("audit.schedulingctl.ndjson").exists(),
        "the refused apply opened the audit stream"
    );

    // Another package is active than the one this configuration verifies.
    activate(&config_path);
    let successor = root.path().join("successor");
    std::fs::create_dir_all(&successor).unwrap();
    std::fs::write(
        successor.join("scheduling.yaml"),
        POLICY.replacen(
            "label: Registry record update",
            "label: Registry record visit",
            1,
        ),
    )
    .unwrap();
    registry_platform_config::package::write_sum_file(
        &successor,
        None,
        &registry_scheduling::config::package_limits(),
        registry_scheduling::config::PACKAGE_COMMAND,
    )
    .expect("the successor package is sealed");
    let successor_config = root.path().join("successor.yaml");
    std::fs::write(
        &successor_config,
        runtime_text.replace(
            &format!("root: {}\n", project.display()),
            &format!("root: {}\n", successor.display()),
        ),
    )
    .unwrap();
    let error = apply_error(&successor_config, &root.path().join("first.yaml"));
    assert!(
        error.contains("is not the active package")
            && error.ends_with(
                "run `schedulingctl plan --runtime-config FILE` then \
                 `schedulingctl apply --runtime-config FILE`"
            ),
        "{error}"
    );
    let (facts, _) = store.facts().await.expect("the records are readable");
    assert!(
        facts.locations.is_empty(),
        "the refused apply wrote records"
    );
    assert!(
        audit_entries(&root.path().join("audit.schedulingctl.ndjson")).is_empty(),
        "the refused apply audited a records write"
    );

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("the disposable schema is dropped");
}
