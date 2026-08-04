//! Real first-tutorial lifecycle proof.
//!
//! The test is ignored in the ordinary package suite because it owns the
//! fixed tutorial ports. The grouped lifecycle gate builds the sibling Mint
//! and Evidence binaries, supplies their paths, and runs this test exactly.

use std::{
    ffi::OsStr,
    fs,
    net::TcpListener,
    os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    thread,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

const OPENAPI: &str = r#"openapi: 3.1.0
info: {title: Tutorial registry, version: 1.0.0}
servers: [{url: 'http://127.0.0.1:8000'}]
paths:
  /people/{person_id}:
    get:
      operationId: getPerson
      parameters:
        - name: person_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: A person
          content:
            application/json:
              schema:
                type: object
                required: [person_id, date_of_birth]
                properties:
                  person_id: {type: string}
                  date_of_birth: {type: string, format: date}
"#;

const QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts: [date_of_birth]
answer:
  concept: is_adult
  type: boolean
  derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

const DERIVATION: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    compare_dates(context.legal_local_date, add_calendar_years(born, 18)) >= 0
}
"#;

#[test]
#[ignore = "exact gate: owns fixed 127.0.0.1:8080 and :8081 tutorial ports"]
fn real_detached_lifecycle_is_ready_private_and_stops_only_owned_children() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new();
    fixture.generate_evidence_keys();

    let mut unrelated = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("start unrelated process");

    let started = fixture.dev_start(&evidence, &mint);
    assert_success(&started, "dev --detach");
    let stdout = String::from_utf8_lossy(&started.stdout);
    assert_eq!(
        stdout,
        "Evidence ready at http://127.0.0.1:8080\nMint ready at http://127.0.0.1:8081\n"
    );
    assert!(ready(
        "http://127.0.0.1:8080/ready",
        json!({"status":"ready"})
    ));
    assert!(jwks_ready());

    let duplicate = fixture.dev_start(&evidence, &mint);
    assert!(!duplicate.status.success(), "duplicate start must fail");
    assert!(ready(
        "http://127.0.0.1:8080/ready",
        json!({"status":"ready"})
    ));

    let dev = fixture.root.join(".evidence/dev");
    assert_mode(&fixture.root.join(".evidence"), 0o700);
    assert_mode(&dev, 0o700);
    for path in [
        "state.json",
        "generated/mint.yaml",
        "generated/clients/caller.yaml",
        "generated/keys/mint-private.jwk",
        "generated/keys/mint-public.jwk.json",
        "generated/keys/caller-private.jwk",
        "generated/keys/caller-public.jwk.json",
        "logs/supervisor.log",
        "logs/mint.log",
        "logs/evidence.log",
    ] {
        assert_mode(&dev.join(path), 0o600);
    }

    let state: Value = serde_json::from_slice(&fs::read(dev.join("state.json")).expect("state"))
        .expect("state JSON");
    assert_eq!(state["schema"], "registry.evidencectl.dev-state/v1");
    assert_eq!(state["status"], "ready");
    assert_eq!(state["accessTokenAudience"], "registry-evidence-local");
    assert_eq!(state["caller"]["requesterTag"], "local-caller");
    assert_eq!(state["question"]["alias"], "adult-status");
    assert_eq!(
        state["question"]["requirementUri"],
        "urn:registrystack:evidence:local:requirement:adult-status"
    );
    let encoded_state = serde_json::to_string(&state).expect("state encodes");
    for prohibited in [
        "access_token",
        "\"d\"",
        "generations",
        "receipt",
        "template",
    ] {
        assert!(
            !encoded_state.contains(prohibited),
            "state contains {prohibited}"
        );
    }

    assert_success(
        &Command::new(&mint)
            .args(["check", "--config"])
            .arg(dev.join("generated/mint.yaml"))
            .output()
            .expect("mint check"),
        "mint check",
    );
    assert_success(
        &Command::new(&evidence)
            .arg("--runtime")
            .arg(dev.join("runtime.yaml"))
            .arg("check")
            .output()
            .expect("evidence check"),
        "evidence check",
    );

    let stopped = fixture.dev_stop();
    assert_success(&stopped, "dev stop");
    assert_eq!(
        String::from_utf8_lossy(&stopped.stdout),
        "Local Evidence stopped\n"
    );
    wait_unavailable("127.0.0.1:8080");
    wait_unavailable("127.0.0.1:8081");
    assert!(unrelated.try_wait().expect("unrelated status").is_none());
    stop_child(&mut unrelated);

    let entries = sorted_names(&dev);
    assert_eq!(entries, ["audit", "bundle", "runtime.yaml", "state.json"]);
    let stopped_state: Value =
        serde_json::from_slice(&fs::read(dev.join("state.json")).expect("stopped state"))
            .expect("stopped state JSON");
    assert_eq!(stopped_state["status"], "stopped");
    assert!(stopped_state["caller"].is_null());
    assert!(dev.join("audit/evidence.jsonl").is_file());
    assert!(dev.join("runtime.yaml").is_file());
}

#[test]
#[ignore = "exact gate: owns fixed 127.0.0.1:8081 tutorial port"]
fn mint_port_conflict_fails_without_starting_evidence_or_disturbing_the_listener() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let conflict = TcpListener::bind("127.0.0.1:8081").expect("reserve Mint port");

    let output = fixture.dev_start(&evidence, &mint);
    assert!(!output.status.success(), "port conflict must fail");
    assert!(conflict.local_addr().is_ok(), "unrelated listener survives");
    assert!(
        TcpListener::bind("127.0.0.1:8080").is_ok(),
        "Evidence was not orphaned"
    );
    assert!(
        !fixture.root.join(".evidence/dev").exists(),
        "failed fresh state cleaned"
    );
}

#[test]
#[ignore = "exact gate: starts real Mint on fixed 127.0.0.1:8081"]
fn evidence_child_failure_stops_mint_and_cleans_the_fresh_session() {
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let evidence = fixture.root.join("evidence-fails-on-serve");
    fs::write(
        &evidence,
        "#!/bin/sh\nif [ \"$3\" = check ]; then exit 0; fi\nexit 1\n",
    )
    .expect("write Evidence test binary");
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)).expect("test binary mode");

    let output = fixture.dev_start(&evidence, &mint);
    assert!(
        !output.status.success(),
        "Evidence child failure must fail start"
    );
    wait_unavailable("127.0.0.1:8080");
    wait_unavailable("127.0.0.1:8081");
    assert!(
        !fixture.root.join(".evidence/dev").exists(),
        "failed state cleaned"
    );
}

#[test]
#[ignore = "exact gate: starts real services on fixed tutorial ports"]
fn ready_state_publication_failure_stops_children_and_allows_a_fresh_start() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new();
    fixture.generate_evidence_keys();

    let failed = fixture.dev_start_with_env(
        &evidence,
        &mint,
        "EVIDENCECTL_TEST_SUPERVISOR_FAIL_STAGE",
        OsStr::new("before-ready-state"),
    );
    assert!(
        !failed.status.success(),
        "state publication fault must fail"
    );
    wait_unavailable("127.0.0.1:8080");
    wait_unavailable("127.0.0.1:8081");
    assert!(
        !fixture.root.join(".evidence/dev").exists(),
        "failed fresh state cleaned"
    );

    let restarted = fixture.dev_start(&evidence, &mint);
    assert_success(&restarted, "fresh start after rollback");
    assert_success(&fixture.dev_stop(), "stop fresh start");
}

#[test]
#[ignore = "exact gate: starts real services on fixed tutorial ports"]
fn catchable_supervisor_signals_stop_owned_children_and_publish_terminal_state() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let mut unrelated = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("start unrelated process");

    for signal in [
        rustix::process::Signal::TERM,
        rustix::process::Signal::HUP,
        rustix::process::Signal::INT,
    ] {
        let fixture = Project::new();
        fixture.generate_evidence_keys();
        let pid_file = fixture.root.join("supervisor.pid");
        let started = fixture.dev_start_with_env(
            &evidence,
            &mint,
            "EVIDENCECTL_TEST_SUPERVISOR_PID_FILE",
            pid_file.as_os_str(),
        );
        assert_success(&started, "dev --detach before supervisor signal");

        let pid: i32 = fs::read_to_string(&pid_file)
            .expect("supervisor pid file")
            .trim()
            .parse()
            .expect("supervisor pid");
        let pid = rustix::process::Pid::from_raw(pid).expect("positive supervisor pid");
        rustix::process::kill_process(pid, signal).expect("signal supervisor");

        let dev = fixture.root.join(".evidence/dev");
        wait_for_failed_state(&dev);
        wait_unavailable("127.0.0.1:8080");
        wait_unavailable("127.0.0.1:8081");
        assert!(!dev.join("control.sock").exists());
        assert!(unrelated.try_wait().expect("unrelated status").is_none());
    }
    stop_child(&mut unrelated);
}

#[test]
fn every_pre_socket_supervisor_failure_rolls_back_without_wedging_the_project() {
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let check_only = fixture.root.join("check-only-tool");
    fs::write(
        &check_only,
        "#!/bin/sh\ncase \"$*\" in *check*) exit 0;; *) exit 1;; esac\n",
    )
    .expect("write check-only tool");
    fs::set_permissions(&check_only, fs::Permissions::from_mode(0o700)).expect("tool mode");

    let missing_supervisor = fixture.root.join("missing-supervisor");
    let failed = fixture.dev_start_with_env(
        &check_only,
        &check_only,
        "EVIDENCECTL_TEST_SUPERVISOR_BIN",
        missing_supervisor.as_os_str(),
    );
    assert!(!failed.status.success(), "supervisor spawn fault must fail");
    assert!(!fixture.root.join(".evidence/dev").exists());

    for stage in ["before-setsid", "before-socket", "after-socket"] {
        let failed = fixture.dev_start_with_env(
            &check_only,
            &check_only,
            "EVIDENCECTL_TEST_SUPERVISOR_FAIL_STAGE",
            OsStr::new(stage),
        );
        assert!(!failed.status.success(), "{stage} fault must fail");
        assert!(
            !fixture.root.join(".evidence/dev").exists(),
            "{stage} rollback must permit the next fresh start"
        );
    }
}

#[test]
fn public_symlink_and_stale_state_fail_before_binary_or_process_access() {
    let public = Project::new();
    fs::create_dir(public.root.join(".evidence")).expect("generated root");
    fs::set_permissions(
        public.root.join(".evidence"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("public mode");
    let output = evidencectl()
        .args(["dev", "--detach", "--project"])
        .arg(&public.root)
        .output()
        .expect("public-state start");
    assert!(!output.status.success());

    let linked = Project::new();
    let target = linked.root.join("private-target");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("target mode");
    symlink(&target, linked.root.join(".evidence")).expect("generated symlink");
    let output = evidencectl()
        .args(["dev", "--detach", "--project"])
        .arg(&linked.root)
        .output()
        .expect("symlink-state start");
    assert!(!output.status.success());

    let stale = Project::new();
    fs::create_dir(stale.root.join(".evidence")).expect("generated root");
    fs::set_permissions(
        stale.root.join(".evidence"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("generated mode");
    fs::create_dir(stale.root.join(".evidence/dev")).expect("stale dev");
    fs::set_permissions(
        stale.root.join(".evidence/dev"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("stale mode");
    fs::write(stale.root.join(".evidence/dev/unknown"), b"do not remove").expect("stale entry");
    let mut unrelated = Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .expect("unrelated process");
    let output = evidencectl()
        .args(["dev", "--detach", "--project"])
        .arg(&stale.root)
        .output()
        .expect("stale-state start");
    assert!(!output.status.success());
    assert!(stale.root.join(".evidence/dev/unknown").is_file());
    assert!(unrelated.try_wait().expect("unrelated status").is_none());
    stop_child(&mut unrelated);
}

struct Project {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl Project {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join("tutorial");
        fs::create_dir(&root).expect("project");
        fs::create_dir(root.join("questions")).expect("questions");
        fs::create_dir(root.join("derivations")).expect("derivations");
        fs::write(root.join("source.openapi.yaml"), OPENAPI).expect("OpenAPI");
        fs::write(root.join("questions/adult-status.yaml"), QUESTION).expect("question");
        fs::write(root.join("derivations/adult-status.rhai"), DERIVATION).expect("derivation");
        Self {
            _temporary: temporary,
            root,
        }
    }

    fn generate_evidence_keys(&self) {
        let secrets = self.root.join("secrets");
        assert_success(
            &evidencectl()
                .args(["keygen", "signing", "--out-dir"])
                .arg(&secrets)
                .args(["--kid", "local-signing-key-1"])
                .output()
                .expect("signing key"),
            "signing key",
        );
        for name in ["audit-hmac-key", "subject-binding-hmac-key"] {
            assert_success(
                &evidencectl()
                    .args(["keygen", "secret", "--out"])
                    .arg(secrets.join(name))
                    .output()
                    .expect("HMAC key"),
                "HMAC key",
            );
        }
    }

    fn dev_start(&self, evidence: &Path, mint: &Path) -> Output {
        self.dev_start_command(evidence, mint)
            .output()
            .expect("dev --detach")
    }

    fn dev_start_with_env(
        &self,
        evidence: &Path,
        mint: &Path,
        name: &str,
        value: &OsStr,
    ) -> Output {
        self.dev_start_command(evidence, mint)
            .env(name, value)
            .output()
            .expect("dev --detach with test fault")
    }

    fn dev_start_command(&self, evidence: &Path, mint: &Path) -> Command {
        let mut command = evidencectl();
        command
            .args(["dev", "--detach", "--project"])
            .arg(&self.root)
            .arg("--evidence-bin")
            .arg(evidence)
            .arg("--mint-bin")
            .arg(mint)
            .arg("--ready-timeout-seconds")
            .arg("20");
        command
    }

    fn dev_stop(&self) -> Output {
        evidencectl()
            .args(["dev", "stop", "--project"])
            .arg(&self.root)
            .output()
            .expect("dev stop")
    }
}

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn required_binary(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("set {name} for the exact lifecycle gate"))
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ready(url: &str, expected: Value) -> bool {
    ureq::get(url)
        .call()
        .ok()
        .and_then(|response| serde_json::from_reader::<_, Value>(response.into_reader()).ok())
        == Some(expected)
}

fn jwks_ready() -> bool {
    ureq::get("http://127.0.0.1:8081/.well-known/jwks.json")
        .call()
        .ok()
        .and_then(|response| serde_json::from_reader::<_, Value>(response.into_reader()).ok())
        .and_then(|value| value["keys"].as_array().cloned())
        .is_some_and(|keys| {
            keys.iter()
                .any(|key| key["kid"] == "local-mint-signing-key-1")
        })
}

fn assert_mode(path: &Path, expected: u32) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()));
    assert_eq!(
        metadata.mode() & 0o777,
        expected,
        "mode of {}",
        path.display()
    );
    assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
}

fn sorted_names(root: &Path) -> Vec<String> {
    let mut names = fs::read_dir(root)
        .expect("directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn wait_unavailable(address: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpListener::bind(address).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("{address} remained occupied");
}

fn wait_for_failed_state(dev: &Path) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        if let Ok(bytes) = fs::read(dev.join("state.json")) {
            if let Ok(state) = serde_json::from_slice::<Value>(&bytes) {
                if state["status"] == "failed" && state["failure"] == "supervisor-signal" {
                    return;
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("supervisor did not publish terminal failed state");
}

fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
