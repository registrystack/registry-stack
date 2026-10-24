// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

//! The operator records writer must use the same configured busy-source
//! coverage requirements as the serving runtime.

use chrono::{Duration, SecondsFormat, Utc};
use registry_schedulingctl::{activation, records};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const POLICY: &str = r#"apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project: {id: busy-records-test, version: "1"}
services: [{id: registry-update, label: Registry update}]
channels: [public]
holidaySets: [{id: none, revision: 1, because: test}]
openings:
  - id: all-day
    location: north-counter
    holidaySet: none
    weekdays: [mon, tue, wed, thu, fri, sat, sun]
    startTime: "00:00"
    endTime: "23:59"
    effectiveFrom: "2026-01-01"
    effectiveUntil: "2030-12-31"
    because: test
offerings:
  - id: room-30
    service: registry-update
    label: Room
    mode: exact-time
    location: north-counter
    because: test
    cancellationCutoffMinutes: 60
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 1
      horizonDays: 3650
      pool: rooms
      startIncrementMinutes: 1
      maximumRecipients: 1
      partyCounts: optional
  - id: registry-sessions
    service: registry-update
    label: Registry sessions
    mode: arrival-window
    location: north-counter
    because: test
    cancellationCutoffMinutes: 60
    arrival: {leadTimeMinutes: 1, horizonDays: 3650}
holdPolicy: {ttlMinutes: 5, maximumPerCaller: 2, because: test}
"#;

fn scoped_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

fn activate(config: &Path) {
    let config = config.to_path_buf();
    std::thread::spawn(move || activation::apply(&config, None, &[]))
        .join()
        .expect("activation does not panic")
        .expect("the package activates");
}

fn apply_error(config: &Path, records_path: &Path) -> String {
    let config = config.to_path_buf();
    let records_path = records_path.to_path_buf();
    std::thread::spawn(move || {
        let error = records::apply(&config, &records_path)
            .expect_err("missing configured busy-source coverage refuses records");
        format!("{error:#}")
    })
    .join()
    .expect("records apply does not panic")
}

fn write_runtime(
    root: &Path,
    project: &Path,
    database_secret: &str,
    audit_secret: &str,
) -> PathBuf {
    let path = root.join("runtime.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1\n\
             kind: SchedulingRuntimeConfig\n\
             package:\n  root: {project}\n\
             listener:\n  bind: 127.0.0.1:8105\n  tlsTermination: development-loopback\n\
             secretProviders:\n  environment: {{}}\n\
             identity:\n  databaseId: busy-records-test\n\
             authentication:\n  oidc:\n    issuer: https://identity.example.test\n\
             \x20   audience: urn:example:scheduling\n\
             \x20   allowedClients: [scheduling-test-client]\n\
             \x20   busyImportProfiles:\n\
             \x20     staff-calendar:\n\
             \x20       scope: scheduling-busy-write\n\
             \x20       sourceId: staff-calendar\n\
             \x20       resources: [room-1]\n\
             \x20       maximumPastDays: 7\n\
             \x20       maximumFutureDays: 3650\n\
             \x20       maximumSpanDays: 31\n\
             \x20       maximumFreshnessMinutes: 240\n\
             \x20       impactProjection: count-only\n\
             database:\n  runtimeUrlRef: secret:env/{database_secret}\n\
             \x20 migrationUrlRef: secret:env/{database_secret}\n\
             \x20 testOnlyPlaintext: true\n\
             taskGrantStatus: unchecked-final-fifteen-minutes\n\
             audit:\n  path: {audit}\n  hashKeyRef: secret:env/{audit_secret}\n\
             retention:\n  receiptRetentionDays: 2\n",
            project = project.display(),
            audit = root.join("audit.ndjson").display(),
        ),
    )
    .expect("write runtime configuration");
    path
}

#[tokio::test]
async fn records_apply_requires_fresh_coverage_from_configured_busy_sources() {
    let base = std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("records_busy_{}", Uuid::new_v4().simple());
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

    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .expect("create test workspace");
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).expect("create package directory");
    std::fs::write(project.join("scheduling.yaml"), POLICY).expect("write policy");
    registry_platform_config::package::write_sum_file(
        &project,
        None,
        &registry_scheduling::config::package_limits(),
        registry_scheduling::config::PACKAGE_COMMAND,
    )
    .expect("seal package");

    let start = (Utc::now() + Duration::days(2))
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .expect("midday window")
        .and_utc();
    let end = start + Duration::minutes(30);
    let records_path = root.path().join("records.yaml");
    std::fs::write(
        &records_path,
        format!(
            "apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1\n\
             kind: SchedulingRecords\n\
             locations:\n  - id: north-counter\n    timezone: UTC\n\
             pools:\n  - id: rooms\n    members:\n      - resourceId: room-1\n        capabilities: []\n        available: true\n\
             windows:\n  - id: midday-session\n    revision: 1\n\
             \x20   offering: registry-sessions\n    location: north-counter\n\
             \x20   start: {}\n    end: {}\n    units: 5\n\
             \x20   unitsPolicy: {{type: fixed, units: 1, because: test}}\n\
             \x20   resources:\n      - requirement: room\n        offering: room-30\n        resource: room-1\n        units: 1\n\
             \x20   because: test\n",
            start.to_rfc3339_opts(SecondsFormat::Secs, true),
            end.to_rfc3339_opts(SecondsFormat::Secs, true),
        ),
    )
    .expect("write window records");

    let suffix = Uuid::new_v4().simple().to_string().to_ascii_uppercase();
    let database_secret = format!("SCHEDULING_BUSY_RECORDS_DATABASE_{suffix}");
    let audit_secret = format!("SCHEDULING_BUSY_RECORDS_AUDIT_{suffix}");
    std::env::set_var(&database_secret, scoped_url(&base, &schema));
    std::env::set_var(&audit_secret, "a".repeat(32));
    let config_path = write_runtime(root.path(), &project, &database_secret, &audit_secret);
    activate(&config_path);

    let error = apply_error(&config_path, &records_path);
    assert!(error.contains("physical allocation refused"), "{error}");
}
