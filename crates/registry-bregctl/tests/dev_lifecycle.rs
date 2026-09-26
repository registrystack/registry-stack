// SPDX-License-Identifier: Apache-2.0
//! Installed-binary proof. Opt in after building breg and bregctl; Docker
//! must be available. This creates and removes only its own synthetic database.
//! The refusal and help tests at the end need only the built bregctl: they
//! stop before any prerequisite is resolved or any service is started.

use base64::Engine as _;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

struct Session {
    project: PathBuf,
    path: std::ffi::OsString,
    docker: PathBuf,
}
impl Session {
    fn ctl(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_bregctl"))
            .env("PATH", &self.path)
            .env("SSL_CERT_FILE", self.project.join(".breg/dev/tls/ca.pem"))
            .args(["--format", "json"])
            .args(args)
            .output()
            .expect("native ctl command launches")
    }
    /// Run one `dev` invocation against this session's project. Docker is
    /// always named explicitly and never reachable through `PATH`, so every
    /// supervised phase, including the rehearsal and `dev stop`, has to use
    /// the resolved binary the caller chose.
    fn dev(&self, args: &[&str]) -> std::process::Output {
        let docker = self.docker.to_str().unwrap();
        let mut invocation = vec!["dev"];
        invocation.extend_from_slice(args);
        invocation.extend([self.project.to_str().unwrap(), "--docker-bin", docker]);
        self.ctl(&invocation)
    }
    #[track_caller]
    fn report(&self, output: std::process::Output) -> Value {
        if !output.status.success() {
            write(
                &self.project.parent().unwrap().join("native-failure.json"),
                &output.stdout,
            );
        }
        assert!(
            output.status.success(),
            "native lifecycle failed; retained private workspace {}",
            self.project.display()
        );
        serde_json::from_slice(&output.stdout).expect("native JSON report")
    }
    #[track_caller]
    fn success(&self, args: &[&str]) -> Value {
        self.report(self.ctl(args))
    }
    #[track_caller]
    fn start(&self) -> Value {
        self.report(self.dev(&[]))
    }
    #[track_caller]
    fn stop(&self) {
        self.report(self.dev(&["stop"]));
    }
    #[track_caller]
    fn remove(&self) {
        self.report(self.dev(&["stop", "--remove"]));
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        // Every exit, including a panicking assertion, reclaims the container
        // and the data volume this test created. A failed reclaim is reported
        // rather than dropped, unless the test is already unwinding.
        let output = self.dev(&["stop", "--remove"]);
        if !output.status.success() && !std::thread::panicking() {
            panic!(
                "dev stop --remove failed during cleanup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

/// The one installed command this test resolves through the ambient `PATH`.
/// The session's own `PATH` holds only the built binaries under test.
fn installed(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} must be installed to run the retained lifecycle test"))
}

/// Three distinct loopback ports nothing is listening on, taken the way the
/// supervisor probes one: bind `127.0.0.1:0`, let the kernel name the port,
/// and release all three together so this test's own ports stay distinct.
/// Fixed ports would make two concurrent runs collide.
fn free_ports() -> [u16; 3] {
    let held: Vec<std::net::TcpListener> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port is available"))
        .collect();
    let ports: Vec<u16> = held
        .iter()
        .map(|listener| listener.local_addr().expect("the bound port").port())
        .collect();
    drop(held);
    ports.try_into().expect("three ports")
}

fn docker_line(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("docker command launches");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("docker output is UTF-8")
        .trim()
        .to_owned()
}

/// The most recent modification time of one retained record, following a
/// directory to the newest file it holds.
fn newest(path: &Path) -> std::time::SystemTime {
    let metadata = fs::symlink_metadata(path).expect("the retained record exists");
    if !metadata.is_dir() {
        return metadata.modified().expect("a modification time");
    }
    fs::read_dir(path)
        .expect("retained directory")
        .map(|entry| newest(&entry.expect("retained entry").path()))
        .max()
        .unwrap_or_else(|| metadata.modified().expect("a modification time"))
}

/// The newest owner-only log one supervised phase wrote. Command logs carry a
/// random suffix, so a phase is named by its prefix.
fn newest_log(root: &Path, prefix: &str) -> std::time::SystemTime {
    fs::read_dir(root.join("logs"))
        .expect("private log directory")
        .map(|entry| entry.expect("log entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .map(|path| newest(&path))
        .max()
        .unwrap_or_else(|| panic!("the {prefix} phase left no private record"))
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn poll_report(mut read: impl FnMut() -> Value, ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let report = read();
        if ready(&report) {
            return report;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "local event lifecycle did not reach the expected state"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[test]
#[ignore = "requires matching installed breg/bregctl binaries and Docker; runs a retained local database"]
fn installed_dev_receives_retries_replays_and_retains_authored_events() {
    let binary = Path::new(env!("CARGO_BIN_EXE_bregctl"));
    // The issuer bind-mounts this workspace into Docker. Keep the synthetic
    // state beside the built binary instead of the host's possibly unshared
    // platform TMPDIR (for example macOS /private/var/folders).
    let temporary = tempfile::Builder::new()
        .prefix("breg-native-events-test-")
        .tempdir_in(binary.parent().unwrap())
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = fs::canonicalize(temporary.keep()).unwrap();
    let project = parent.join("registry");
    let session = Session {
        project: project.clone(),
        path: std::env::join_paths([binary.parent().unwrap()]).unwrap(),
        docker: installed("docker"),
    };
    session.success(&["init", project.to_str().unwrap()]);
    let mut registry: Value =
        serde_norway::from_slice(&fs::read(project.join("registry.yaml")).unwrap()).unwrap();
    let record = registry["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "record")
        .unwrap();
    record["hooks"] = json!([
        {"phase":"after","id":"record-created-a", "trigger":"created", "projection":["status"],
         "handler":{"kind":"url","destinationId":"receiver-a"}},
        {"phase":"after","id":"record-created-b", "trigger":"created", "projection":["status"],
         "handler":{"kind":"url","destinationId":"receiver-b"}}
    ]);
    write(
        &project.join("registry.yaml"),
        serde_norway::to_string(&registry).unwrap().as_bytes(),
    );
    let clients = parent.join("clients.yaml");
    write(
        &clients,
        br#"version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: reader
    accessProfiles: [record-reader]
    scopes: [registry:generic:read]
    claims:
      registry_principal: generic-registry-reader
      registry_purpose: registry-reporting
      registry_record_status: active
  - id: source
    accessProfiles: [evidence-source]
    scopes: [registry:evidence:lookup]
    claims:
      registry_principal: generic-registry-source
      registry_purpose: evidence-source-read
seed:
  - id: event-seed
    client: operator
    entity: record
    accessProfile: operator
    data: {code: synthetic-event-seed, label: Synthetic event seed, status: active}
"#,
    );
    let [database_port, breg_port, issuer_port] = free_ports();
    let first = session.report(session.dev(&[
        "start",
        "--clients-file",
        clients.to_str().unwrap(),
        "--database-port",
        &database_port.to_string(),
        "--breg-port",
        &breg_port.to_string(),
        "--issuer-port",
        &issuer_port.to_string(),
    ]));
    assert_eq!(first["status"], "ready");
    let dev = project.join(".breg/dev");
    let state_file = dev.join("state.json");
    let state: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    let webhook_port = u16::try_from(state["webhookPort"].as_u64().unwrap()).unwrap();
    assert_ne!(webhook_port, 0);
    assert!(![database_port, breg_port, issuer_port].contains(&webhook_port));
    let receiver_address = std::net::SocketAddr::from(([127, 0, 0, 1], webhook_port));
    assert!(std::net::TcpStream::connect(receiver_address).is_ok());
    let runtime_file = dev.join("runtime.yaml");
    let configuration: Value = serde_norway::from_slice(&fs::read(&runtime_file).unwrap()).unwrap();
    let destinations = configuration["eventDestinations"].as_object().unwrap();
    assert_eq!(destinations.len(), 2);
    for destination in ["receiver-a", "receiver-b"] {
        assert_eq!(
            destinations[destination]["origin"],
            format!("http://127.0.0.1:{webhook_port}")
        );
    }
    let events = || session.success(&["dev", "events", project.to_str().unwrap()]);
    let pending = || {
        session.success(&[
            "webhook",
            "list",
            "--runtime-config",
            runtime_file.to_str().unwrap(),
        ])
    };
    let delivered = || {
        let output = Command::new(&session.docker)
            .args([
                "exec",
                state["containerId"].as_str().unwrap(),
                "psql",
                "-X",
                "-A",
                "-t",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                "breg_dev",
                "-c",
                "SELECT count(*) FROM registry_internal.registry_webhook_delivery_state WHERE state = 'delivered'",
            ])
            .output()
            .expect("owned database state query launches");
        assert!(
            output.status.success(),
            "owned database state query succeeds"
        );
        json!(String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap())
    };
    let received = poll_report(events, |report| {
        report["deliveries"].as_array().unwrap().len() == 2
    });
    let encoded = serde_json::to_string(&received).unwrap();
    for absent in [
        "payload",
        "active",
        "synthetic-event-seed",
        "Synthetic event seed",
        "recordId",
    ] {
        assert!(
            !encoded.contains(absent),
            "default receipt disclosed {absent}"
        );
    }
    for receipt in received["deliveries"].as_array().unwrap() {
        uuid::Uuid::parse_str(receipt["eventId"].as_str().unwrap()).unwrap();
        let event_type = receipt["eventType"].as_str().unwrap();
        let destination = match event_type {
            "record-created-a" => "receiver-a",
            "record-created-b" => "receiver-b",
            _ => panic!("receipt did not name an authored event"),
        };
        assert_eq!(receipt["entity"], "record");
        assert_eq!(receipt["trigger"], "created");
        assert_eq!(
            receipt["deliveryId"],
            format!("events.record.{event_type}.webhook")
        );
        assert_eq!(receipt["destinationId"], destination);
        assert_eq!(receipt["status"], "received");
        assert!(receipt["generation"].as_u64().unwrap() > 0);
        assert_eq!(receipt["attempt"], 1);
    }
    let payloads = session.success(&[
        "dev",
        "events",
        project.to_str().unwrap(),
        "--include-payload",
    ]);
    for receipt in payloads["deliveries"].as_array().unwrap() {
        assert_eq!(receipt["payload"], json!({"status":"active"}));
    }
    poll_report(delivered, |count| count.as_u64() == Some(2));
    poll_report(pending, |report| {
        report["deliveries"].as_array().unwrap().is_empty()
    });

    // A receipt must be persisted privately before acknowledgement. Refusing
    // unsafe inbox permissions gives the real worker a retryable 503 response.
    let inbox = dev.join("events.jsonl");
    fs::set_permissions(&inbox, fs::Permissions::from_mode(0o644)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let origin = format!("http://127.0.0.1:{breg_port}");
    runtime.block_on(async {
        let token = fs::read_to_string(dev.join("secrets/operator-token")).unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .post(format!(
                "{origin}/v1/records/records?accessProfile=operator"
            ))
            .bearer_auth(&token)
            .header("Idempotency-Key", "synthetic-event-retry")
            .json(&json!({"data":{
                "code":"synthetic-event-retry", "label":"Synthetic retry record", "status":"retired"
            }}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
    });
    let retrying = poll_report(pending, |report| {
        let deliveries = report["deliveries"].as_array().unwrap();
        deliveries.len() == 2
            && deliveries.iter().all(|delivery| {
                delivery["state"] == "pending" && delivery["attempt"].as_u64().unwrap() >= 2
            })
    });
    let dead = poll_report(pending, |report| {
        let deliveries = report["deliveries"].as_array().unwrap();
        deliveries.len() == 2
            && deliveries
                .iter()
                .all(|delivery| delivery["state"] == "dead_lettered")
    });
    fs::set_permissions(&inbox, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        events(),
        received,
        "failed appends must not create receipts"
    );
    for delivery in dead["deliveries"].as_array().unwrap() {
        assert_eq!(delivery["attempt"], 5);
        assert_eq!(delivery["replayEligible"], true);
        assert_eq!(delivery["payloadAvailable"], true);
        assert!(retrying["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|earlier| {
                earlier["eventId"] == delivery["eventId"]
                    && earlier["deliveryId"] == delivery["deliveryId"]
                    && earlier["generation"] == delivery["generation"]
            }));
        let replay = session.success(&[
            "webhook",
            "replay",
            "--runtime-config",
            runtime_file.to_str().unwrap(),
            "--event-id",
            delivery["eventId"].as_str().unwrap(),
            "--delivery-id",
            delivery["deliveryId"].as_str().unwrap(),
            "--expected-generation",
            &delivery["generation"].to_string(),
        ]);
        assert_eq!(replay["eventId"], delivery["eventId"]);
        assert_eq!(
            replay["generation"].as_u64().unwrap(),
            delivery["generation"].as_u64().unwrap() + 1
        );
    }
    let recovered = poll_report(events, |report| {
        report["deliveries"].as_array().unwrap().len() == 4
    });
    for delivery in dead["deliveries"].as_array().unwrap() {
        let receipt = recovered["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["eventId"] == delivery["eventId"]
                    && receipt["deliveryId"] == delivery["deliveryId"]
            })
            .expect("replay has an authenticated receipt for the same event");
        assert_eq!(
            receipt["generation"].as_u64().unwrap(),
            delivery["generation"].as_u64().unwrap() + 1
        );
        assert_eq!(receipt["attempt"], 1);
        assert_eq!(receipt["status"], "received");
    }
    // The operator queue also omits leased attempts. Check the durable terminal
    // state directly before asserting that both recovered deliveries leave it.
    poll_report(delivered, |count| count.as_u64() == Some(4));
    poll_report(pending, |report| {
        report["deliveries"].as_array().unwrap().is_empty()
    });
    let receipts_before = fs::read(&inbox).unwrap();
    let webhook_key = fs::read(dev.join("secrets/webhook-key")).unwrap();
    let assertion_key = fs::read(dev.join("credentials/operator/assertion-key.jwk")).unwrap();
    session.stop();
    assert!(std::net::TcpStream::connect(receiver_address).is_err());
    assert_eq!(events(), recovered, "stopped inbox remains inspectable");
    let restarted = session.start();
    assert_eq!(restarted["packageRevision"], first["packageRevision"]);
    let retained: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    for field in ["owner", "containerId", "webhookPort", "seeded"] {
        assert_eq!(retained[field], state[field]);
    }
    assert!(std::net::TcpStream::connect(receiver_address).is_ok());
    assert!(fs::read(dev.join("secrets/webhook-key")).unwrap() == webhook_key);
    assert!(fs::read(dev.join("credentials/operator/assertion-key.jwk")).unwrap() == assertion_key);
    assert_eq!(fs::read(&inbox).unwrap(), receipts_before);
    assert_eq!(events(), recovered);
    runtime.block_on(async {
        let token = fs::read_to_string(dev.join("secrets/operator-token")).unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .get(format!(
                "{origin}/v1/records/records?accessProfile=operator"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let records: Value = response.json().await.unwrap();
        assert_eq!(
            records["items"].as_array().unwrap().len(),
            2,
            "restart must not reseed"
        );
    });
    fs::set_permissions(&inbox, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!session.dev(&["stop", "--remove"]).status.success());
    let incomplete: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(incomplete["containerId"], retained["containerId"]);
    fs::set_permissions(&inbox, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !session.dev(&[]).status.success(),
        "incomplete receipt reclamation must prevent a fresh database"
    );
    session.remove();
    assert!(std::net::TcpStream::connect(receiver_address).is_err());
    assert_eq!(events()["deliveries"], json!([]));
    assert!(!inbox.exists(), "removal erases captured event payloads");
    session.remove();
    assert_eq!(events()["deliveries"], json!([]));
    session.start();
    let fresh = poll_report(events, |report| {
        report["deliveries"].as_array().unwrap().len() == 2
    });
    for receipt in fresh["deliveries"].as_array().unwrap() {
        assert!(
            recovered["deliveries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|previous| previous["eventId"] != receipt["eventId"]),
            "fresh database receipts must not contain removed record events"
        );
    }
    session.remove();
    std::mem::forget(session);
    fs::remove_dir_all(parent).unwrap();
}

#[test]
#[ignore = "requires matching installed breg/bregctl binaries and Docker; runs a retained local database"]
fn installed_dev_preserves_edits_and_recovers_failed_start_without_reseeding() {
    let binary = Path::new(env!("CARGO_BIN_EXE_bregctl"));
    let temporary = tempfile::Builder::new()
        .prefix("breg-native-dev-test-")
        .tempdir_in(binary.parent().unwrap())
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = fs::canonicalize(temporary.keep()).unwrap();
    let project = parent.join("registry");
    // Only the binaries built beside bregctl serve this session: an installed
    // breg from an earlier package format must not be reachable, and
    // Docker must be named explicitly rather than found.
    let session = Session {
        project: project.clone(),
        path: std::env::join_paths([binary.parent().unwrap()]).unwrap(),
        docker: installed("docker"),
    };
    session.success(&["init", project.to_str().unwrap()]);
    let mut registry: Value =
        serde_norway::from_slice(&fs::read(project.join("registry.yaml")).unwrap()).unwrap();
    registry["package"]["environment"] = json!("local");
    write(
        &project.join("registry.yaml"),
        serde_norway::to_string(&registry).unwrap().as_bytes(),
    );
    let clients = parent.join("clients.yaml");
    write(
        &clients,
        br#"version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: reader
    accessProfiles: [record-reader]
    scopes: [registry:generic:read]
    claims:
      registry_principal: generic-registry-reader
      registry_purpose: registry-reporting
      registry_record_status: active
  - id: source
    accessProfiles: [evidence-source]
    scopes: [registry:evidence:lookup]
    claims:
      registry_principal: generic-registry-source
      registry_purpose: evidence-source-read
seed:
  - id: first-record
    client: operator
    entity: record
    accessProfile: operator
    data: {code: synthetic-dev-record, label: Synthetic local record, status: active}
"#,
    );
    // A service that exits before readiness causes owned child/container
    // cleanup. The same persisted keys and database can then start normally.
    let [database_port, breg_port, issuer_port] = free_ports();
    let origin = format!("http://127.0.0.1:{breg_port}");
    let failed = session.dev(&[
        "start",
        "--clients-file",
        clients.to_str().unwrap(),
        "--database-port",
        &database_port.to_string(),
        "--breg-port",
        &breg_port.to_string(),
        "--issuer-port",
        &issuer_port.to_string(),
        "--breg-bin",
        "/usr/bin/false",
    ]);
    assert!(!failed.status.success());
    // The supervisor is detached with both streams in a private log, so the
    // terminal that asked for the start only learns the cause if the start
    // reports what the supervisor recorded.
    let refused: Value =
        serde_json::from_slice(&failed.stdout).expect("a refused start reports machine-readable");
    let refusal = refused["diagnostics"][0]["message"]
        .as_str()
        .expect("the refusal carries a message");
    assert!(refusal.contains("local start failed:"), "{refusal}");
    assert!(refusal.contains("exited before readiness"), "{refusal}");
    let state_file = project.join(".breg/dev/state.json");
    let failed_state: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(failed_state["status"], "failed");

    // A breg from another release is refused by name before the session
    // starts, rather than failing later as a package or database the reader
    // has no reason to suspect.
    let shim = parent.join("breg-from-another-release");
    write(&shim, b"#!/bin/sh\necho 'breg 0.26.1'\n");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
    let mismatched = session.dev(&[
        "start",
        "--clients-file",
        clients.to_str().unwrap(),
        "--database-port",
        &database_port.to_string(),
        "--breg-port",
        &breg_port.to_string(),
        "--issuer-port",
        &issuer_port.to_string(),
        "--breg-bin",
        shim.to_str().unwrap(),
    ]);
    assert!(!mismatched.status.success());
    let refused: Value = serde_json::from_slice(&mismatched.stdout)
        .expect("a refused prerequisite reports machine-readable");
    let named = refused["diagnostics"][0]["message"]
        .as_str()
        .expect("the refusal carries a message");
    assert!(named.contains("0.26.1"), "{named}");
    assert!(named.contains("same release"), "{named}");

    let key_before =
        fs::read(project.join(".breg/dev/credentials/operator/assertion-key.jwk")).unwrap();
    let first = session.start();
    assert_eq!(first["status"], "ready");
    assert_eq!(first["bregUrl"], origin);
    // Public source handoff copies only the selected private pair and reports
    // the exact OAuth request parameters a separate Evidence process needs.
    let handoff = parent.join("source-credentials");
    fs::create_dir(&handoff).unwrap();
    fs::set_permissions(&handoff, fs::Permissions::from_mode(0o700)).unwrap();
    let client_id = handoff.join("client-id");
    let assertion_key = handoff.join("assertion-key.jwk");
    let exported_client = session.success(&[
        "dev",
        "export-client",
        project.to_str().unwrap(),
        "--client",
        "source",
        "--client-id-file",
        client_id.to_str().unwrap(),
        "--assertion-key-file",
        assertion_key.to_str().unwrap(),
    ]);
    assert_eq!(
        exported_client["issuer"],
        format!("http://127.0.0.1:{issuer_port}")
    );
    assert_eq!(exported_client["tokenEndpoint"], first["tokenEndpoint"]);
    assert_eq!(
        exported_client["clientAssertionAudience"],
        exported_client["issuer"]
    );
    assert_eq!(exported_client["resource"], first["audience"]);
    assert_eq!(
        exported_client["scopes"],
        json!(["registry:evidence:lookup"])
    );
    assert_eq!(fs::read(&client_id).unwrap(), b"source");
    assert_eq!(
        fs::read(&assertion_key).unwrap(),
        fs::read(project.join(".breg/dev/credentials/source/assertion-key.jwk")).unwrap()
    );
    assert_eq!(
        fs::metadata(&assertion_key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!serde_json::to_string(&exported_client)
        .unwrap()
        .contains("\"d\":"));
    // A client token lives 300 seconds, less than the worst case a first
    // start may spend on its child and readiness deadlines before it seeds.
    // Every token must therefore be minted after the rehearsal, the built
    // package and the activation, immediately before the seed.
    let dev = project.join(".breg/dev");
    let prepared = [
        newest(&dev.join("build")),
        newest(&dev.join("schema-test-receipt.json")),
        newest(&dev.join("runtime.yaml")),
        newest_log(&dev, "apply-"),
        newest_log(&dev, "verify-"),
    ]
    .into_iter()
    .max()
    .expect("the first start left its package and activation records");
    for client in ["operator", "reader", "source"] {
        let token = dev.join("secrets").join(format!("{client}-token"));
        assert!(
            newest(&token) >= prepared,
            "the {client} token was minted before the package and activation records"
        );
    }
    let again = session.start();
    assert_eq!(again["packageRevision"], first["packageRevision"]);
    let state: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(state["containerId"], failed_state["containerId"]);
    // Records live in a named volume derived from the ownership identifier,
    // not in an anonymous volume no command can name afterwards.
    let owned = format!("breg-dev-{}", state["owner"].as_str().unwrap());
    assert_eq!(
        docker_line(&[
            "volume",
            "ls",
            "--filter",
            &format!("name=^{owned}$"),
            "--format",
            "{{.Name}}"
        ]),
        owned
    );
    // A runtime credential must not authenticate as the migration or admin
    // role merely by replacing its username. Password bytes stay in a private
    // PostgreSQL password file, never command arguments or diagnostic output.
    let runtime_url = reqwest::Url::parse(
        &fs::read_to_string(project.join(".breg/dev/secrets/runtime-database-url")).unwrap(),
    )
    .unwrap();
    let password = runtime_url.password().unwrap();
    let password_file = parent.join("cross-role.pgpass");
    write(&password_file, format!("127.0.0.1:5432:breg_dev:breg_dev_migration:{password}\n127.0.0.1:5432:breg_dev:postgres:{password}\n").as_bytes());
    let container = state["containerId"].as_str().unwrap();
    assert!(Command::new("docker")
        .args([
            "cp",
            password_file.to_str().unwrap(),
            &format!("{container}:/tmp/cross-role.pgpass")
        ])
        .output()
        .unwrap()
        .status
        .success());
    for role in ["breg_dev_migration", "postgres"] {
        assert!(!Command::new("docker")
            .args([
                "exec",
                "--env",
                "PGPASSFILE=/tmp/cross-role.pgpass",
                container,
                "psql",
                "-X",
                "-w",
                "-h",
                "127.0.0.1",
                "-U",
                role,
                "-d",
                "breg_dev",
                "-c",
                "SELECT 1"
            ])
            .output()
            .unwrap()
            .status
            .success());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (record, revision) = runtime.block_on(async {
        let token = fs::read_to_string(project.join(".breg/dev/secrets/operator-token")).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let list: Value = client
            .get(format!(
                "{origin}/v1/records/records?accessProfile=operator"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let records = list["items"].as_array().expect("list records");
        assert_eq!(records.len(), 1, "first seed is executed once");
        let record = records[0]["recordIdentifier"].as_str().unwrap().to_owned();
        let url = format!("{origin}/v1/records/records/{record}?accessProfile=operator");
        let response = client.get(&url).bearer_auth(&token).send().await.unwrap();
        let etag = response
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let response = client
            .patch(&url)
            .bearer_auth(&token)
            .header("If-Match", etag)
            .header("Idempotency-Key", "native-dev-reader-edit")
            .header("Content-Type", "application/json-patch+json")
            .json(&json!([{"op":"replace","path":"/data/status","value":"retired"}]))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let revision = response
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        (record, revision)
    });
    // The exported Evidence source contract must describe the running
    // registry: its route and access profile answer the seeded identity, and
    // an unresolved lookup answers exactly the declared problem.
    let exports = parent.join("evidence-export");
    session.success(&[
        "generate",
        "evidence-source",
        project.to_str().unwrap(),
        "--access-profile",
        "evidence-source",
        "--entity",
        "record",
        "--selector",
        "by-code",
        "--fields",
        "status",
        "--source-id",
        "registry-status",
        "--connection",
        "registry",
        "--output",
        exports.to_str().unwrap(),
    ]);
    let exported: Value =
        serde_norway::from_slice(&fs::read(exports.join("sources/registry-status.yaml")).unwrap())
            .unwrap();
    let schema: Value = serde_norway::from_slice(
        &fs::read(exports.join("schemas/registry-status-response.yaml")).unwrap(),
    )
    .unwrap();
    let manifest: Value =
        serde_json::from_slice(&fs::read(exports.join("source-export.json")).unwrap()).unwrap();
    let unresolved = exported["unresolvedProblem"].clone();
    let request = exported["request"].clone();
    assert_eq!(request["method"], "POST");
    // `code` names both the authored selector field and its HTTP property in
    // this model, so the export's identity name addresses the response too.
    let identity = request["selectorInputs"][0]["alternatives"][0]["fields"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let declared = schema["properties"]["data"]["properties"]["domainData"]["properties"]
        [&identity]["type"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .find(|name| *name != "null")
        .expect("the export declares a scalar type for the identity field")
        .to_owned();
    let select = request["projection"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pointer| pointer.as_str().unwrap().rsplit('/').next().unwrap())
        .collect::<Vec<_>>()
        .join(",");
    runtime.block_on(async {
        let token = fs::read_to_string(project.join(".breg/dev/secrets/source-token")).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let lookup = |value: &str| {
            let mut sent = client
                .post(format!("{origin}{}", request["path"].as_str().unwrap()))
                .bearer_auth(&token)
                .query(&[
                    (
                        "accessProfile",
                        manifest["provenance"]["accessProfile"].as_str().unwrap(),
                    ),
                    ("$select", select.as_str()),
                ])
                .json(&json!({"selector": "by-code", "values": {&identity: value}}));
            for header in request["fixedHeaders"].as_array().unwrap() {
                sent = sent.header(
                    header["name"].as_str().unwrap().to_owned(),
                    header["value"].as_str().unwrap().to_owned(),
                );
            }
            sent.send()
        };
        let response = lookup("synthetic-dev-record").await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let found: Value = response.json().await.unwrap();
        let echoed = &found["data"]["domainData"][&identity];
        assert_eq!(echoed, "synthetic-dev-record");
        assert_eq!(
            match echoed {
                Value::String(_) => "string",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "integer",
                other => panic!("the identity field is not a scalar: {other}"),
            },
            declared
        );
        let response = lookup("absent-synthetic-dev-record").await.unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            unresolved["status"].as_u64().unwrap()
        );
        let problem: Value = response.json().await.unwrap();
        assert_eq!(problem["type"], unresolved["type"]);
        assert_eq!(problem["code"], unresolved["code"]);
    });
    session.stop();
    session.stop();
    let stopped: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(stopped["status"], "stopped");
    // Simulate a crash after the HTTP seed committed but before its local
    // checkpoint was flushed. The permanent BReg idempotency reservation
    // replays its result without replacing the subsequently edited record.
    let mut lost_checkpoint = stopped.clone();
    lost_checkpoint["seeded"] = json!([]);
    write(&state_file, &serde_json::to_vec(&lost_checkpoint).unwrap());
    let started = session.start();
    assert_eq!(started["packageRevision"], first["packageRevision"]);
    runtime.block_on(async {
        let token = fs::read_to_string(project.join(".breg/dev/secrets/operator-token")).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client
            .get(format!(
                "{origin}/v1/records/records/{record}?accessProfile=operator"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("etag").unwrap().to_str().unwrap(),
            revision
        );
        let value: Value = response.json().await.unwrap();
        assert_eq!(value["data"]["domainData"]["status"], "retired");
    });
    assert!(
        fs::read(project.join(".breg/dev/credentials/operator/assertion-key.jwk")).unwrap()
            == key_before
    );
    session.stop();
    let original = fs::read(project.join("registry.yaml")).unwrap();
    let mut changed = original.clone();
    changed.extend_from_slice(b"\n# reviewed authored edit\n");
    write(&project.join("registry.yaml"), &changed);
    assert!(!session.dev(&[]).status.success());
    assert_eq!(fs::read(project.join("registry.yaml")).unwrap(), changed);
    write(&project.join("registry.yaml"), &original);
    session.start();
    session.stop();
    let container = state["containerId"].as_str().unwrap();
    let owner = state["owner"].as_str().unwrap();
    let inspected = Command::new("docker")
        .args(["inspect", container])
        .output()
        .unwrap();
    let inventory: Vec<Value> = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(
        inventory[0]["Config"]["Labels"]["org.registrystack.bregctl.dev-owner"],
        owner
    );

    assert!(Command::new("docker")
        .args(["start", container])
        .output()
        .unwrap()
        .status
        .success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !Command::new("docker")
        .args(["exec", container, "pg_isready", "-U", "postgres"])
        .output()
        .unwrap()
        .status
        .success()
    {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // The audit log the restarted runtime wrote is intact JSONL.
    let runtime_file = project.join(".breg/dev/runtime.yaml");
    let configuration: Value = serde_norway::from_slice(&fs::read(&runtime_file).unwrap()).unwrap();
    let audit_path = runtime_file
        .parent()
        .unwrap()
        .join(configuration["audit"]["path"].as_str().unwrap());
    let audit = fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.is_empty());
    for line in audit.lines() {
        assert!(serde_json::from_str::<Value>(line).unwrap().is_object());
    }
    session.remove();
    assert_eq!(
        docker_line(&[
            "ps",
            "--all",
            "--filter",
            &format!("name=^/{owned}$"),
            "--format",
            "{{.ID}}"
        ]),
        ""
    );
    assert_eq!(
        docker_line(&[
            "volume",
            "ls",
            "--filter",
            &format!("name=^{owned}$"),
            "--format",
            "{{.Name}}"
        ]),
        ""
    );
    // Recreate the database, stop it normally (the container is left stopped,
    // not removed), then take the container away by hand. Only then does the
    // documented recovery path in `reclaim` (tolerating a manual removal) get
    // exercised: `dev stop --remove` must reclaim the remaining volume instead
    // of refusing on the now-absent container.
    let recreated = session.start();
    assert_eq!(recreated["status"], "ready");
    session.stop();
    assert!(Command::new("docker")
        .args(["rm", "--force", &owned])
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        docker_line(&[
            "volume",
            "ls",
            "--filter",
            &format!("name=^{owned}$"),
            "--format",
            "{{.Name}}"
        ]),
        owned
    );
    // Plain `dev stop` still refuses a retained container that vanished
    // without `--remove`; that refusal protects retained data.
    let refused = session.dev(&["stop"]);
    assert!(!refused.status.success());
    let refusal: Value = serde_json::from_slice(&refused.stdout).expect("refusal JSON");
    assert!(refusal["diagnostics"][0]["message"]
        .as_str()
        .unwrap()
        .contains("retained database container is missing"));
    session.remove();
    assert_eq!(
        docker_line(&[
            "volume",
            "ls",
            "--filter",
            &format!("name=^{owned}$"),
            "--format",
            "{{.Name}}"
        ]),
        ""
    );
    let reclaimed_state: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert!(reclaimed_state["containerId"].is_null());
    // Reclaiming again tolerates the container and volume already taken.
    session.remove();
    // The test owns this synthetic workspace and removes it only after all
    // checks and exact container-ownership verification succeeded.
    std::mem::forget(session);
    fs::remove_dir_all(parent).unwrap();
}

#[test]
#[ignore = "requires matching installed breg/bregctl binaries and Docker; runs a retained local database"]
fn installed_dev_prepares_a_native_source_successor_with_retained_records() {
    let binary = Path::new(env!("CARGO_BIN_EXE_bregctl"));
    let temporary = tempfile::Builder::new()
        .prefix("breg-native-source-test-")
        .tempdir_in(binary.parent().unwrap())
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = fs::canonicalize(temporary.keep()).unwrap();
    let project = parent.join("registry");
    let session = Session {
        project: project.clone(),
        path: std::env::join_paths([binary.parent().unwrap()]).unwrap(),
        docker: installed("docker"),
    };
    session.success(&["init", project.to_str().unwrap()]);
    let client_file = project.join("dev-clients.yaml");
    let mut clients = fs::read(&client_file).unwrap();
    clients.extend_from_slice(
        br#"
seed:
  - id: source-successor-seed
    client: operator
    entity: record
    accessProfile: operator
    data: {code: synthetic-source-successor, label: Synthetic source successor, status: active}
"#,
    );
    write(&client_file, &clients);
    let [database_port, breg_port, issuer_port] = free_ports();
    let first = session.report(session.dev(&[
        "start",
        "--database-port",
        &database_port.to_string(),
        "--breg-port",
        &breg_port.to_string(),
        "--issuer-port",
        &issuer_port.to_string(),
    ]));
    assert_eq!(first["status"], "ready");
    assert_eq!(first["packageSequence"], 1);
    session.stop();

    let source_args = [
        "dev",
        "prepare-source",
        project.to_str().unwrap(),
        "--entity",
        "record",
        "--selector-field",
        "code",
        "--readable-fields",
        "status",
        "--all-records",
        "--client",
        "source-reader",
        "--access-profile",
        "source-reader",
        "--selector-profile",
        "by-code-source-reader",
    ];
    let preview = session.success(&source_args);
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["packageSequence"], 2);
    let mut apply = source_args.to_vec();
    apply.push("--apply");
    let prepared = session.success(&apply);
    assert_eq!(prepared["status"], "prepared");
    let restarted = session.start();
    assert_eq!(restarted["status"], "ready");
    assert_eq!(restarted["packageSequence"], 2);
    assert_ne!(restarted["packageRevision"], first["packageRevision"]);

    let token = fs::read_to_string(project.join(".breg/dev/secrets/source-reader-token")).unwrap();
    let payload = token.split('.').nth(1).expect("issued JWT payload");
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["scope"], "registry:source-reader:lookup");
    assert_eq!(claims["registry_principal"], "source-reader");

    let export = parent.join("source-export");
    session.success(&[
        "generate",
        "evidence-source",
        project.to_str().unwrap(),
        "--access-profile",
        "source-reader",
        "--entity",
        "record",
        "--selector",
        "by-code-source-reader",
        "--fields",
        "status",
        "--source-id",
        "source-reader",
        "--connection",
        "registry",
        "--output",
        export.to_str().unwrap(),
    ]);
    let source: Value =
        serde_norway::from_slice(&fs::read(export.join("sources/source-reader.yaml")).unwrap())
            .unwrap();
    let request = &source["request"];
    let select = request["projection"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pointer| pointer.as_str().unwrap().rsplit('/').next().unwrap())
        .collect::<Vec<_>>()
        .join(",");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut request_builder = client
            .post(format!("http://127.0.0.1:{breg_port}{}", request["path"].as_str().unwrap()))
            .bearer_auth(&token)
            .query(&[("accessProfile", "source-reader"), ("$select", select.as_str())])
            .json(&json!({"selector":"by-code-source-reader","values":{"code":"synthetic-source-successor"}}));
        for header in request["fixedHeaders"].as_array().unwrap() {
            request_builder = request_builder.header(
                header["name"].as_str().unwrap(),
                header["value"].as_str().unwrap(),
            );
        }
        let response = request_builder.send().await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let found: Value = response.json().await.unwrap();
        assert_eq!(found["data"]["domainData"]["code"], "synthetic-source-successor");
        assert_eq!(found["data"]["domainData"]["status"], "active");
    });
    session.stop();
    std::mem::forget(session);
    fs::remove_dir_all(parent).unwrap();
}

/// One `bregctl` invocation against a freshly initialized project. The port
/// refusals this exercises happen before Docker or `breg` is resolved and
/// before any service starts, so the built bregctl is the only prerequisite.
fn plain_bregctl(binary: &Path, json: bool, args: &[&str]) -> std::process::Output {
    let mut invocation = Command::new(binary);
    if json {
        invocation.arg("--format").arg("json");
    }
    invocation.args(args);
    invocation.output().expect("bregctl starts")
}

#[test]
fn dev_start_port_refusals_name_the_port_flag_and_role_in_both_formats() {
    let binary = Path::new(env!("CARGO_BIN_EXE_bregctl"));
    let temporary = tempfile::tempdir().expect("a temporary directory");
    // `init` refuses a destination behind a symbolic link, and a platform's
    // temporary root often is one.
    let parent = fs::canonicalize(temporary.path()).expect("a canonical directory");
    let project = parent.join("registry");
    let initialized = plain_bregctl(binary, false, &["init", project.to_str().unwrap()]);
    assert!(
        initialized.status.success(),
        "{}{}",
        String::from_utf8_lossy(&initialized.stdout),
        String::from_utf8_lossy(&initialized.stderr)
    );
    // The start probes BReg, then the database, then the owned issuer, so
    // each case names the port it occupies and leaves the earlier ports free.
    let [breg, database, _] = free_ports();
    let occupant = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("an occupiable port");
    let occupied = occupant.local_addr().expect("the occupied port").port();
    for (case, occupied_flag, role) in [
        (vec![], "--breg-port", "BReg registry"),
        (
            vec![("--breg-port", breg)],
            "--database-port",
            "PostgreSQL database",
        ),
        (
            vec![("--breg-port", breg), ("--database-port", database)],
            "--issuer-port",
            "issuer",
        ),
    ] {
        let mut arguments: Vec<String> = vec![
            "dev".into(),
            "start".into(),
            occupied_flag.into(),
            occupied.to_string(),
        ];
        for (flag, port) in &case {
            arguments.push((*flag).to_owned());
            arguments.push(port.to_string());
        }
        arguments.push(project.to_str().unwrap().to_owned());
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        // The machine-readable refusal carries the same named facts as the
        // human one, because both render the refusal's own message.
        let json = plain_bregctl(binary, true, &borrowed);
        assert!(!json.status.success(), "{case:?} refused nothing");
        let report: Value = serde_json::from_slice(&json.stdout).expect("a JSON refusal");
        assert_eq!(report["ok"], false, "{report}");
        assert_eq!(report["command"], "dev", "{report}");
        let message = report["diagnostics"][0]["message"]
            .as_str()
            .expect("message");
        for fact in [
            occupied.to_string(),
            occupied_flag.to_owned(),
            role.to_owned(),
            "127.0.0.1".to_owned(),
        ] {
            assert!(message.contains(&fact), "{message} lacks {fact}");
        }
        assert!(!message.contains(".breg"), "{message}");
        let human = plain_bregctl(binary, false, &borrowed);
        assert!(!human.status.success(), "{case:?} refused nothing");
        let rendered = String::from_utf8_lossy(&human.stderr);
        for fact in [
            occupied.to_string(),
            occupied_flag.to_owned(),
            role.to_owned(),
        ] {
            assert!(rendered.contains(&fact), "{rendered} lacks {fact}");
        }
        assert!(
            String::from_utf8_lossy(&human.stdout).trim().is_empty(),
            "a human refusal stays off stdout"
        );
    }
}

#[test]
fn dev_help_names_the_owning_document_and_both_record_options() {
    let binary = Path::new(env!("CARGO_BIN_EXE_bregctl"));
    let start = plain_bregctl(binary, false, &["dev", "start", "--help"]);
    assert!(start.status.success(), "{start:?}");
    let start = String::from_utf8(start.stdout).expect("help is UTF-8");
    for fact in [
        "products/breg/DEV.md",
        "'Native local BReg lifecycle'",
        "'Retained state and recovery'",
        "uncatchable outside kill",
        ".breg/dev/logs",
    ] {
        assert!(start.contains(fact), "dev start --help omits {fact}");
    }
    let stop = plain_bregctl(binary, false, &["dev", "stop", "--help"]);
    assert!(stop.status.success(), "{stop:?}");
    let stop = String::from_utf8(stop.stdout).expect("help is UTF-8");
    for fact in [
        "--remove",
        "discarding records",
        "copy the authored files to a new project directory",
        "products/breg/DEV.md",
        "'Retained state and recovery'",
    ] {
        assert!(stop.contains(fact), "dev stop --help omits {fact}");
    }
}
