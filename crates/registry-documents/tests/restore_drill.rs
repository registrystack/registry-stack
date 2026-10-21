// SPDX-License-Identifier: Apache-2.0

//! One rehearsal of the restore drill in `products/documents/README.md`
//! against the database `DOCUMENTS_TEST_DATABASE_URL` names, with
//! `pg_dump` and `pg_restore` from `PATH`.
//!
//! The drill is a rehearsal an operator runs before relying on a restore,
//! not verification, so it is ignored and never part of a test run. It
//! takes a backup of its own schema, changes the store after the backup,
//! pauses erasure, restores the backup over the changed schema, and walks
//! the drill's steps, asserting what the README says happens at each and
//! printing one JSON line describing the restored state. The audit file is
//! deliberately not restored, as when the database backup and the audit
//! journal are kept apart, so step 4 has something to compare against.
//!
//! The connection's password reaches `pg_dump` and `pg_restore` through
//! their environment, never their command line.

mod support;

use std::process::Command;
use std::str::FromStr;

use axum::body::Body;
use chrono::{DateTime, Utc};
use registry_documents::runtime::{prepare_with_verifier, Prepared};
use registry_documents_core::ProblemCode;
use support::{
    database_url, pdf, reservation, Api, Deployment, FakeVerifier, APP, APPROVE, CITIZEN,
    DATABASE_STORAGE, DISABLED_VERIFIER, READER,
};

const PDF: &str = "application/pdf";

/// A libpq command for `program` connected to the test database through
/// its environment.
fn libpq(program: &str) -> Command {
    let config = tokio_postgres::Config::from_str(&database_url())
        .expect("DOCUMENTS_TEST_DATABASE_URL is a PostgreSQL connection string");
    let mut command = Command::new(program);
    command.env_remove("PGPASSFILE");
    if let Some(tokio_postgres::config::Host::Tcp(host)) = config.get_hosts().first() {
        command.env("PGHOST", host);
    }
    if let Some(port) = config.get_ports().first() {
        command.env("PGPORT", port.to_string());
    }
    if let Some(user) = config.get_user() {
        command.env("PGUSER", user);
    }
    if let Some(password) = config.get_password() {
        command.env("PGPASSWORD", String::from_utf8_lossy(password).as_ref());
    }
    if let Some(database) = config.get_dbname() {
        command.env("PGDATABASE", database);
    }
    command
}

fn succeed(command: &mut Command, what: &str) {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{what} starts: {error}"));
    assert!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn start(deployment: &Deployment) -> (Prepared, Api) {
    let verifier = FakeVerifier::new("restore-drill", APPROVE);
    let prepared = prepare_with_verifier(&deployment.runtime, verifier)
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    (prepared, api)
}

/// Reserve, upload, and verify `content` into the citizen's custody.
async fn ready(prepared: &Prepared, api: &Api, content: &[u8]) -> (String, String) {
    let reserved = api
        .reserve(APP, "citizen-delivery", CITIZEN.subject, content, PDF)
        .await;
    let (document, version, path) = reservation(&reserved);
    let put = api.put(APP, &path, PDF, Body::from(content.to_vec())).await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    assert_eq!(prepared.verify_due().await, 1);
    (document, version)
}

fn status(answer: &support::Answer) -> String {
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    answer.json()["version"]["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn grant_state(api: &Api, document: &str) -> String {
    let grants = api.get(APP, &format!("/documents/{document}/grants")).await;
    assert_eq!(grants.status, 200);
    grants.json()["items"][0]["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn events(deployment: &Deployment, event: &str) -> usize {
    deployment
        .audit_entries()
        .iter()
        .filter(|entry| entry["record"]["event"] == event)
        .count()
}

async fn held(deployment: &Deployment, version: &str) -> bool {
    deployment
        .scalar::<i64>(&format!(
            "SELECT count(*) FROM documents_contents WHERE version_id = '{version}'"
        ))
        .await
        == 1
}

async fn due(deployment: &Deployment, version: &str) -> Option<DateTime<Utc>> {
    deployment
        .scalar(&format!(
            "SELECT erasure_due_at FROM documents_versions WHERE version_id = '{version}'"
        ))
        .await
}

#[tokio::test]
#[ignore = "drill: rehearses the README restore drill with pg_dump and pg_restore on demand"]
async fn rehearse_the_restore_drill_against_a_disposable_database() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let backup = deployment.path().join("backup.dump");

    // Before the backup: three documents in custody, one shared, one with
    // its removal already requested.
    let (prepared, api) = start(&deployment).await;
    let kept = pdf(2048, 1);
    let removed_later = pdf(2048, 2);
    let (shared, shared_version) = ready(&prepared, &api, &kept).await;
    let (later, later_version) = ready(&prepared, &api, &removed_later).await;
    let (pending, pending_version) = ready(&prepared, &api, &pdf(2048, 3)).await;
    let grant = api
        .grant(APP, &shared, &shared_version, READER.subject, None)
        .await;
    assert_eq!(grant.status, 201);
    let grant = grant.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(
        status(&api.erase(CITIZEN, &pending).await),
        "erasure-pending"
    );
    let pending_due = due(&deployment, &pending_version).await;

    let backup_taken: DateTime<Utc> = deployment.scalar("SELECT now()").await;
    succeed(
        libpq("pg_dump")
            .args(["--format=custom", "--no-owner", "--no-privileges"])
            .arg(format!("--schema={}", deployment.schema))
            .arg("--file")
            .arg(&backup),
        "pg_dump",
    );

    // After the backup: the grant is revoked, the second document is
    // removed and erased, and a fourth document arrives.
    assert_eq!(api.revoke(APP, &grant).await.status, 200);
    assert_eq!(status(&api.erase(CITIZEN, &later).await), "erasure-pending");
    deployment
        .execute(&format!(
            "UPDATE documents_versions
                SET erasure_requested_at = erasure_requested_at - interval '2 days',
                    erasure_due_at = now() - interval '1 second'
              WHERE version_id = '{later_version}'"
        ))
        .await;
    prepared.sweep_due().await;
    assert!(
        !held(&deployment, &later_version).await,
        "erased after the backup"
    );
    let (arrived, _) = ready(&prepared, &api, &pdf(2048, 4)).await;
    let revocations = events(&deployment, "documents.grant-revoke");
    let requests = events(&deployment, "documents.erasure-request");
    let erasures = events(&deployment, "documents.erasure");

    // Step 1: pause erasure and stop serving.
    drop(api);
    drop(prepared);
    deployment.set_erasure("paused");

    // Step 2: restore the database backup; the audit file is not restored.
    deployment
        .execute(&format!("DROP SCHEMA {} CASCADE", deployment.schema))
        .await;
    succeed(
        libpq("pg_restore")
            .args(["--no-owner", "--no-privileges", "--exit-on-error"])
            .arg("--dbname")
            .arg(
                tokio_postgres::Config::from_str(&database_url())
                    .unwrap()
                    .get_dbname()
                    .expect("DOCUMENTS_TEST_DATABASE_URL names a database"),
            )
            .arg(&backup),
        "pg_restore",
    );

    // Step 3: start paused. The sweep erases nothing, even a version that
    // is due.
    let (prepared, api) = start(&deployment).await;
    deployment
        .execute(&format!(
            "UPDATE documents_versions
                SET erasure_requested_at = erasure_requested_at - interval '2 days',
                    erasure_due_at = now() - interval '1 second'
              WHERE version_id = '{pending_version}'"
        ))
        .await;
    let paused_pass = prepared.sweep_due().await;
    assert!(
        held(&deployment, &pending_version).await,
        "paused erases nothing"
    );
    assert_eq!(
        status(&api.read(CITIZEN, &pending).await),
        "erasure-pending"
    );

    // Step 4: what the restored database no longer knows. The revoked grant
    // is active again, the removed document is back in custody with its
    // bytes, and the document that arrived after the backup is unknown.
    assert_eq!(grant_state(&api, &shared).await, "active");
    assert_eq!(
        api.download(READER, &shared, &shared_version).await.body,
        kept
    );
    assert_eq!(status(&api.read(CITIZEN, &later).await), "ready");
    assert_eq!(
        api.download(CITIZEN, &later, &later_version).await.body,
        removed_later
    );
    api.read(CITIZEN, &arrived)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    // The audit file still holds them.
    assert_eq!(events(&deployment, "documents.grant-revoke"), revocations);
    assert_eq!(events(&deployment, "documents.erasure-request"), requests);
    assert_eq!(events(&deployment, "documents.erasure"), erasures);

    // Repeat them from the audit file. The repeated removal gets a fresh
    // due time: a full grace after the repeat, not after the original
    // request.
    let repeated_at: DateTime<Utc> = deployment.scalar("SELECT now()").await;
    assert_eq!(api.revoke(APP, &grant).await.status, 200);
    api.download(READER, &shared, &shared_version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    assert_eq!(status(&api.erase(CITIZEN, &later).await), "erasure-pending");
    let later_due = due(&deployment, &later_version)
        .await
        .expect("the repeated removal is due");
    let grace = later_due - repeated_at;
    assert!(
        grace > chrono::Duration::hours(23) && grace <= chrono::Duration::hours(25),
        "a fresh grace of the policy's cleanupGraceHours, not {grace}"
    );

    // Step 5 is for S3 storage; database storage restores bytes and rows
    // together, so nothing is left that no row names.

    // Step 6: set erasure active and restart. The version that became due
    // is erased; the repeated removal waits for its fresh grace.
    drop(api);
    drop(prepared);
    deployment.set_erasure("active");
    let (prepared, api) = start(&deployment).await;
    let active_pass = prepared.sweep_due().await;
    assert!(!held(&deployment, &pending_version).await, "due and active");
    assert_eq!(status(&api.read(CITIZEN, &pending).await), "erased");
    assert!(
        held(&deployment, &later_version).await,
        "within its fresh grace"
    );
    assert!(held(&deployment, &shared_version).await);

    println!(
        "{}",
        serde_json::json!({
            "backupTaken": backup_taken,
            "pendingDueAtBackup": pending_due,
            "pausedPassArmedErasures": paused_pass.armed_erasures,
            "revokedGrantAfterRestore": "active",
            "removedDocumentAfterRestore": "ready, bytes back",
            "documentArrivedAfterBackup": "unknown (404)",
            "auditEntriesKept": {
                "grantRevoke": revocations,
                "erasureRequest": requests,
                "erasure": erasures,
            },
            "repeatedRemovalAt": repeated_at,
            "repeatedRemovalDueAt": later_due,
            "repeatedRemovalGraceHours": grace.num_minutes() as f64 / 60.0,
            "activePassArmedErasures": active_pass.armed_erasures,
        })
    );
}
