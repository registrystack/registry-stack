// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]
mod support;

use registry_coordinator::{
    adapters::HttpAdapters,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
};
use support::{config, issuer, messaging::Messaging, submission};

fn postgres_tool(program: &str, url: &str) -> std::process::Command {
    let config: tokio_postgres::Config = url.parse().expect("disposable PostgreSQL URL");
    let mut command = std::process::Command::new(program);
    let host = match config.get_hosts().first().expect("explicit local host") {
        tokio_postgres::config::Host::Tcp(host) => std::ffi::OsString::from(host),
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(path) => path.as_os_str().to_owned(),
    };
    command
        .env("PGHOST", host)
        .env(
            "PGPORT",
            config
                .get_ports()
                .first()
                .copied()
                .unwrap_or(5432)
                .to_string(),
        )
        .env(
            "PGDATABASE",
            config.get_dbname().expect("explicit disposable database"),
        )
        .env("PGUSER", config.get_user().expect("explicit test role"))
        .env("PGCONNECT_TIMEOUT", "5");
    if let Some(password) = config.get_password() {
        command.env(
            "PGPASSWORD",
            std::str::from_utf8(password).expect("UTF-8 test password"),
        );
    }
    command
}

/// This also tests PostgreSQL's backup tooling, so it is run explicitly with a
/// client matching the disposable server, using scripts/test-restore.sh.
#[tokio::test]
#[ignore = "requires matching pg_dump and psql; run products/coordinator/scripts/test-restore.sh"]
async fn restoring_an_older_backup_cannot_repeat_a_real_accepted_message() {
    use registry_coordinator::{
        definition::Definition,
        store::{Actor, Store},
        worker::Worker,
    };
    use std::sync::Arc;

    let url =
        std::env::var("COORDINATOR_TEST_DATABASE_URL").expect("disposable Coordinator database");
    let dump_tool = std::env::var("COORDINATOR_PG_DUMP").unwrap_or_else(|_| "pg_dump".into());
    let psql_tool = std::env::var("COORDINATOR_PSQL").unwrap_or_else(|_| "psql".into());
    let issuer = issuer().await;
    let messaging = Messaging::start(&issuer).await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let config = config(
        root.path(),
        &issuer,
        "http://127.0.0.1:1",
        &messaging.base_url,
    );
    std::fs::write(
        root.path().join("workflow.yaml"),
        r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project:
  id: restore-proof
  version: v1
input: {type: object}
connections: {notices: messaging}
functionsFile: functions.rhai
deadlineSeconds: 3600
start: send
steps:
  send:
    type: call
    connection: notices
    operation: submit-message
    input: {function: request, arguments: [{type: input}]}
    next: done
  done: {type: finish, outcome: accepted}
outcomes: {accepted: {type: 'null'}}
"#,
    )
    .unwrap();
    std::fs::write(
        root.path().join("functions.rhai"),
        "fn request(input) { input }",
    )
    .unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let adapters = Arc::new(HttpAdapters::new(&config).unwrap());
    let binding = adapters.binding_digest_for(&definition.workflow);
    let store = Arc::new(Store::connect(&url, &config.namespace).await.unwrap());
    store.migrate().await.unwrap();
    let owner = Actor {
        issuer: "https://institution.example.invalid".into(),
        subject: "producer".into(),
        client_id: "producer-client".into(),
        operator: false,
    };
    let operator = Actor {
        operator: true,
        ..owner.clone()
    };
    let run = store
        .admit_owned(
            &definition,
            submission(),
            &owner,
            "original-start",
            &binding,
        )
        .await
        .unwrap();
    let backup = root.path().join("before-send.sql");
    let dump = postgres_tool(&dump_tool, &url)
        .args([
            "--no-password",
            "--no-owner",
            "--no-acl",
            "--schema",
            &config.namespace,
            "--file",
        ])
        .arg(&backup)
        .output()
        .expect("start matching pg_dump");
    assert!(dump.status.success(), "isolated namespace backup failed");
    let worker = Worker::new(store.clone(), adapters.clone());
    for _ in 0..3 {
        worker.tick().await.unwrap();
    }
    assert_eq!(
        store.status_owned(run, &owner).await.unwrap().state,
        "finished"
    );
    assert_eq!(messaging.count().await, 1);

    // This is the externally enforced fence in this test: the only old worker
    // is stopped and discarded before the Coordinator namespace is replaced.
    drop(worker);
    drop(store);
    let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", config.namespace))
        .await
        .unwrap();
    let restore = postgres_tool(&psql_tool, &url)
        .args([
            "--no-password",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "--file",
        ])
        .arg(&backup)
        .output()
        .expect("start matching psql");
    assert!(
        restore.status.success(),
        "isolated namespace restore failed"
    );
    let restored = Arc::new(Store::connect(&url, &config.namespace).await.unwrap());
    restored
        .set_restore_hold(&operator, "older-backup-old-worker-fenced")
        .await
        .unwrap();
    let worker = Worker::new(restored.clone(), adapters.clone());
    assert!(!worker.tick().await.unwrap());
    assert_eq!(messaging.count().await, 1);
    let status = restored.status_owned(run, &owner).await.unwrap();
    assert!(status.restore_review_required);
    assert!(restored
        .reconcile_owned(
            run,
            &binding,
            &operator,
            "missing-frozen-command",
            adapters.as_ref()
        )
        .await
        .is_err());
    assert_eq!(
        restored
            .release_restore_hold(&operator, "fence-without-history")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.restore-unresolved"
    );
    assert!(restored
        .admit_owned(&definition, submission(), &owner, "unknown-start", &binding)
        .await
        .is_err());
    assert!(restored.doctor().await.unwrap().admissions_hold);
    assert_eq!(
        messaging.count().await,
        1,
        "older backup cannot turn missing command history into a second effect"
    );
    drop(worker);
    drop(restored);
    admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", config.namespace))
        .await
        .unwrap();
    messaging.stop().await;
    issuer.stop().await;
}

#[tokio::test]
async fn maintained_client_replays_one_real_messaging_postgres_submission() {
    std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("disposable coordinator database is required");
    let issuer = issuer().await;
    let messaging = Messaging::start(&issuer).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let invalid = client
        .post(format!("{}/v1/messages", messaging.base_url))
        .bearer_auth("invalid-signature-canary")
        .header("idempotency-key", "refused")
        .json(&submission())
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), reqwest::StatusCode::UNAUTHORIZED);
    let expires = chrono::Utc::now().timestamp() + 300;
    let signed = issuer.issue_access_token(
        "case-system",
        "workflow-sender",
        "urn:example:messaging",
        "messaging:send",
        expires,
    );
    let (input, signature) = signed.rsplit_once('.').unwrap();
    let altered = format!(
        "{input}.{}{}",
        if signature.starts_with('A') { "B" } else { "A" },
        &signature[1..]
    );
    for (token, expected) in [
        (altered, reqwest::StatusCode::UNAUTHORIZED),
        (
            issuer.issue_access_token(
                "case-system",
                "workflow-sender",
                "urn:example:applications",
                "messaging:send",
                expires,
            ),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            issuer.issue_access_token(
                "application-reader",
                "workflow-reader",
                "urn:example:messaging",
                "messaging:send",
                expires,
            ),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            issuer.issue_access_token(
                "case-system",
                "workflow-sender",
                "urn:example:messaging",
                "other:scope",
                expires,
            ),
            reqwest::StatusCode::FORBIDDEN,
        ),
    ] {
        let refused = client
            .post(format!("{}/v1/messages", messaging.base_url))
            .bearer_auth(token)
            .header("idempotency-key", "refused")
            .json(&submission())
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), expected);
    }
    assert_eq!(
        messaging.count().await,
        0,
        "signature, audience, client and scope refusals create no message"
    );
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let config = config(
        root.path(),
        &issuer,
        "http://127.0.0.1:1",
        &messaging.base_url,
    );
    let request = CallRequest {
        connection: "notices".into(),
        operation: Operation::SubmitMessage,
        input: submission(),
        idempotency_key: Some("real-messaging-same-command".into()),
    };
    let first = HttpAdapters::new(&config).unwrap().call(&request).await;
    let CallOutcome::Success(receipt) = first else {
        panic!("real Messaging must accept authorized synthetic submission");
    };
    let replay = HttpAdapters::new(&config).unwrap().call(&request).await;
    assert!(matches!(replay, CallOutcome::Success(value) if value["id"] == receipt["id"]));
    assert_eq!(messaging.count().await, 1);
    messaging.stop().await;
    issuer.stop().await;
}
