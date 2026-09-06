// SPDX-License-Identifier: Apache-2.0
//! Installed-binary proof. Opt in after building breg, mint and bregctl; Docker
//! must be available. This creates and removes only its own synthetic database.

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
    fn success(&self, args: &[&str]) -> Value {
        let output = self.ctl(args);
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
    fn start(&self) -> Value {
        self.success(&[
            "dev",
            "--detach",
            "--project",
            self.project.to_str().unwrap(),
        ])
    }
    fn stop(&self) {
        self.success(&["dev", "stop", "--project", self.project.to_str().unwrap()]);
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.ctl(&["dev", "stop", "--project", self.project.to_str().unwrap()]);
    }
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
#[ignore = "requires matching installed breg/mint binaries and Docker; runs a retained local database"]
fn installed_dev_preserves_edits_and_recovers_failed_start_without_reseeding() {
    let temporary = tempfile::Builder::new()
        .prefix("breg-native-dev-test-")
        .tempdir()
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = fs::canonicalize(temporary.keep()).unwrap();
    let project = parent.join("registry");
    let binary = Path::new(env!("CARGO_BIN_EXE_bregctl"));
    let mut paths = vec![binary.parent().unwrap().to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let session = Session {
        project: project.clone(),
        path: std::env::join_paths(paths).unwrap(),
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
    let failed = session.ctl(&[
        "dev",
        "start",
        "--project",
        project.to_str().unwrap(),
        "--clients-file",
        clients.to_str().unwrap(),
        "--database-port",
        "55448",
        "--breg-port",
        "8094",
        "--mint-port",
        "8095",
        "--mint-bin",
        "/usr/bin/false",
    ]);
    assert!(!failed.status.success());
    let state_file = project.join(".breg/dev/state.json");
    let failed_state: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(failed_state["status"], "failed");
    let key_before =
        fs::read(project.join(".breg/dev/credentials/operator/assertion-key.jwk")).unwrap();
    let first = session.start();
    assert_eq!(first["status"], "ready");
    let again = session.start();
    assert_eq!(again["packageRevision"], first["packageRevision"]);
    let state: Value = serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    assert_eq!(state["containerId"], failed_state["containerId"]);
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
            .get("http://127.0.0.1:8094/v1/records/records?accessProfile=operator")
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
        let url =
            format!("http://127.0.0.1:8094/v1/records/records/{record}?accessProfile=operator");
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
                "http://127.0.0.1:8094/v1/records/records/{record}?accessProfile=operator"
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
    assert!(!session
        .ctl(&["dev", "--project", project.to_str().unwrap()])
        .status
        .success());
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
    session.success(&[
        "audit",
        "verify",
        "--runtime-config",
        project.join(".breg/dev/runtime.yaml").to_str().unwrap(),
    ]);
    assert!(Command::new("mint")
        .env("PATH", &session.path)
        .args(["verify-audit", "--config"])
        .arg(project.join(".breg/dev/mint/mint.yaml"))
        .output()
        .unwrap()
        .status
        .success());
    assert!(Command::new("docker")
        .args(["stop", "--time", "30", container])
        .output()
        .unwrap()
        .status
        .success());
    assert!(Command::new("docker")
        .args(["rm", "--volumes", container])
        .output()
        .unwrap()
        .status
        .success());
    // The test owns this synthetic workspace and removes it only after all
    // checks and exact container-ownership verification succeeded.
    std::mem::forget(session);
    fs::remove_dir_all(parent).unwrap();
}
