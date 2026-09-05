//! Real first-tutorial lifecycle proof.
//!
//! The test is ignored in the ordinary package suite because it owns the
//! fixed tutorial ports. The grouped lifecycle gate builds the sibling Mint
//! and Evidence binaries, supplies their paths, and runs this test exactly.

use std::{
    ffi::OsStr,
    fs,
    net::TcpListener,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{symlink, MetadataExt as _, PermissionsExt as _},
    },
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
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

const DERIVATION: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    #{is_adult: compare_dates(context.legal_local_date, add_calendar_years(born, 18)) >= 0}
}
"#;

const AGE_BRACKET_QUESTION: &str = r#"id: age-bracket
question: Which age bracket does this person belong to?
purpose: service-path-selection
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: age_bracket
    type: controlled-category
    values: [under-18, 18-to-24, 25-to-64, 65-or-older]
derivation: derivations/age-bracket.rhai
disclosure:
  allow: [age_bracket]
"#;

const AGE_BRACKET_DERIVATION: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    if compare_dates(context.legal_local_date, add_calendar_years(born, 18)) < 0 {
        #{age_bracket: "under-18"}
    } else if compare_dates(context.legal_local_date, add_calendar_years(born, 25)) < 0 {
        #{age_bracket: "18-to-24"}
    } else if compare_dates(context.legal_local_date, add_calendar_years(born, 65)) < 0 {
        #{age_bracket: "25-to-64"}
    } else {
        #{age_bracket: "65-or-older"}
    }
}
"#;

#[test]
#[ignore = "exact gate: owns fixed 127.0.0.1:8080 and :8081 tutorial ports"]
fn real_detached_lifecycle_is_ready_private_and_stops_only_owned_children() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new_long_path();
    assert!(
        fixture
            .root
            .join(".evidence/dev/control.sock")
            .as_os_str()
            .as_bytes()
            .len()
            > 104,
        "test path must exceed the common sockaddr_un.sun_path limit"
    );
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
    assert_mode(&dev.join("generated/audit"), 0o700);
    for path in [
        "state.json",
        "generated/mint.yaml",
        "generated/clients/caller.yaml",
        "generated/audit/mint.jsonl",
        "generated/keys/mint-audit-hmac-key",
        "generated/keys/mint-private.jwk",
        "generated/keys/holder-private.jwk",
        "generated/keys/holder-public.jwk.json",
        "generated/keys/caller-private.jwk",
        "generated/keys/caller-public.jwk.json",
        "logs/supervisor.log",
        "logs/mint.log",
        "logs/evidence.log",
    ] {
        assert_mode(&dev.join(path), 0o600);
    }
    let mint_private_path = dev.join("generated/keys/mint-private.jwk");
    let mint_private: Value =
        serde_json::from_slice(&fs::read(&mint_private_path).expect("generated Mint private JWK"))
            .expect("generated Mint private JWK parses");
    let mint_kid = mint_private["kid"]
        .as_str()
        .expect("generated Mint private JWK has a kid");
    let mint_public_path = dev.join(format!("generated/keys/{mint_kid}.jwk.json"));
    assert_mode(&mint_public_path, 0o600);
    for name in ["mint", "caller", "holder"] {
        let private_path = dev.join(format!("generated/keys/{name}-private.jwk"));
        let private: Value = if name == "mint" {
            mint_private.clone()
        } else {
            serde_json::from_slice(&fs::read(private_path).expect("generated private JWK"))
                .expect("generated private JWK parses")
        };
        let public_path = if name == "mint" {
            mint_public_path.clone()
        } else {
            dev.join(format!("generated/keys/{name}-public.jwk.json"))
        };
        let public: Value =
            serde_json::from_slice(&fs::read(public_path).expect("generated public JWK"))
                .expect("generated public JWK parses");
        assert_eq!(private["kty"], "EC");
        assert_eq!(private["crv"], "P-256");
        assert_eq!(private["alg"], "ES256");
        assert_eq!(public["kty"], "EC");
        assert_eq!(public["crv"], "P-256");
        assert_eq!(public["alg"], "ES256");
        assert_eq!(private["kid"], public["kid"]);
    }

    let state: Value = serde_json::from_slice(&fs::read(dev.join("state.json")).expect("state"))
        .expect("state JSON");
    assert_eq!(state["schema"], "registry.evidencectl.dev-state/v5");
    assert_eq!(state["status"], "ready");
    assert_eq!(state["accessTokenAudience"], "registry-evidence-local");
    assert_eq!(state["caller"]["requesterTag"], "local-caller");
    assert_eq!(state["accessPolicies"], json!([]));
    assert_eq!(state["questions"][0]["alias"], "adult-status");
    assert_eq!(
        state["questions"][0]["requirementUri"],
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
    assert_success(&fixture.dev_clean(), "dev clean");
    assert!(!dev.exists(), "clean removes the sealed stopped generation");
}

#[test]
#[ignore = "exact gate: starts real local Mint and Evidence services"]
fn configurable_ports_drive_every_generated_url_and_listener() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let (evidence_port, mint_port) = unused_port_pair();

    let started = fixture.dev_start_on_ports(&evidence, &mint, evidence_port, mint_port);
    assert_success(&started, "dev --detach on configured ports");
    assert_eq!(
        String::from_utf8_lossy(&started.stdout),
        format!(
            "Evidence ready at http://127.0.0.1:{evidence_port}\nMint ready at http://127.0.0.1:{mint_port}\n"
        )
    );
    assert!(ready(
        &format!("http://127.0.0.1:{evidence_port}/ready"),
        json!({"status":"ready"})
    ));
    assert!(jwks_ready_at(mint_port));

    let dev = fixture.root.join(".evidence/dev");
    let state: Value = serde_json::from_slice(&fs::read(dev.join("state.json")).unwrap()).unwrap();
    assert_eq!(
        state["evidenceOrigin"],
        format!("http://127.0.0.1:{evidence_port}")
    );
    assert_eq!(
        state["tokenUrl"],
        format!("http://127.0.0.1:{mint_port}/token")
    );
    let runtime: Value = serde_norway::from_slice(&fs::read(dev.join("runtime.yaml")).unwrap())
        .expect("runtime YAML");
    let mint_config: Value =
        serde_norway::from_slice(&fs::read(dev.join("generated/mint.yaml")).unwrap())
            .expect("Mint YAML");
    assert_eq!(runtime["listener"]["port"], evidence_port);
    assert_eq!(mint_config["listener"]["port"], mint_port);
    assert_eq!(mint_config["audit"]["path"], "audit/mint.jsonl");
    assert_eq!(mint_config["audit"]["hashKeyVersion"], 1);
    assert_eq!(
        mint_config["clientAssertion"]["audience"],
        format!("http://127.0.0.1:{mint_port}/token")
    );

    assert_success(&fixture.dev_stop(), "stop configured ports");
    wait_unavailable(&format!("127.0.0.1:{evidence_port}"));
    wait_unavailable(&format!("127.0.0.1:{mint_port}"));
    assert_success(&fixture.dev_clean(), "clean configured ports");
}

#[test]
#[ignore = "exact gate: starts real Mint and Evidence services"]
fn explicit_access_clients_reload_mint_without_restarting_services() {
    let evidence = required_binary("EVIDENCE_BIN");
    let mint = required_binary("MINT_BIN");
    let fixture = Project::new();
    let source_probe = TcpListener::bind("127.0.0.1:0").expect("source call probe");
    source_probe
        .set_nonblocking(true)
        .expect("nonblocking source call probe");
    fixture.point_source_at(
        source_probe
            .local_addr()
            .expect("source probe address")
            .port(),
    );
    fixture.add_age_bracket_question();
    fixture.generate_evidence_keys();
    assert_success(
        &evidencectl()
            .args([
                "access",
                "policy",
                "add",
                "age-checks",
                "--question",
                "adult-status",
                "--project",
            ])
            .arg(&fixture.root)
            .output()
            .expect("add policy"),
        "add policy",
    );
    assert_success(
        &evidencectl()
            .args([
                "access",
                "policy",
                "add",
                "service-routing",
                "--question",
                "age-bracket",
                "--project",
            ])
            .arg(&fixture.root)
            .output()
            .expect("add unassigned policy"),
        "add policy for the ungranted question",
    );
    assert_success(
        &add_local_client(&fixture.root, "client-a", "age-checks"),
        "add client A",
    );
    let client_a_key = fixture.root.join(".evidence/clients/client-a/private.jwk");
    assert_mode(&client_a_key, 0o600);
    let external_client_a_key = fixture
        ._temporary
        .path()
        .join("external-client-a-private.jwk");
    fs::copy(&client_a_key, &external_client_a_key).expect("retain external client A key");
    fs::remove_dir_all(client_a_key.parent().unwrap())
        .expect("remove local-only client A key as in a fresh clone");
    assert!(
        !client_a_key.exists(),
        "the cloned project has only client A's public registration"
    );

    let pid_directory = fixture.root.join("service-pids");
    fs::create_dir(&pid_directory).expect("PID directory");
    fs::set_permissions(&pid_directory, fs::Permissions::from_mode(0o700))
        .expect("PID directory mode");
    let (evidence_port, mint_port) = unused_port_pair();
    let started = fixture
        .dev_start_command(&evidence, &mint)
        .args(["--evidence-port", &evidence_port.to_string()])
        .args(["--mint-port", &mint_port.to_string()])
        .env("EVIDENCECTL_TEST_SERVICE_PID_DIRECTORY", &pid_directory)
        .output()
        .expect("start explicit access generation");
    assert_success(&started, "start explicit access generation");
    let evidence_pid = read_pid(&pid_directory.join("evidence.pid"));
    let mint_pid = read_pid(&pid_directory.join("mint.pid"));
    let generated_clients = fixture.root.join(".evidence/dev/generated/clients");
    assert_mode(&fixture.root.join(".evidence/dev/generated/audit"), 0o700);
    assert_mode(
        &fixture
            .root
            .join(".evidence/dev/generated/keys/mint-audit-hmac-key"),
        0o600,
    );
    assert_mode(
        &fixture
            .root
            .join(".evidence/dev/generated/audit/mint.jsonl"),
        0o600,
    );
    assert_eq!(sorted_names(&generated_clients), ["client-a.yaml"]);

    let added = add_local_client(&fixture.root, "client-b", "age-checks");
    assert_success(&added, "live add client B");
    assert!(String::from_utf8_lossy(&added.stdout).contains("Registry Mint reload requested."));
    assert_eq!(
        sorted_names(&generated_clients),
        ["client-a.yaml", "client-b.yaml"]
    );
    assert_eq!(read_pid(&pid_directory.join("evidence.pid")), evidence_pid);
    assert_eq!(read_pid(&pid_directory.join("mint.pid")), mint_pid);
    assert!(process_is_alive(evidence_pid));
    assert!(process_is_alive(mint_pid));

    let prepared = retry_until_success("newly added client B token request", || {
        evidencectl()
            .args([
                "request",
                "prepare",
                "adult-status",
                "--purpose",
                "age-check",
                "--subject",
                "person_id=person-123",
                "--client",
                "client-b",
                "--name",
                "client-b-live",
                "--project",
            ])
            .arg(&fixture.root)
            .output()
            .expect("prepare as client B")
    });
    assert_success(&prepared, "newly added client B token request");

    let client_b_key = fixture.root.join(".evidence/clients/client-b/private.jwk");
    let token = direct_mint_token(&mint, mint_port, "client-b", &client_b_key);
    assert_success(&token, "direct token for client B");
    let token = String::from_utf8(token.stdout)
        .expect("Mint token is UTF-8")
        .trim()
        .to_owned();
    let status = post_evidence(
        evidence_port,
        &token,
        "urn:registrystack:evidence:local:requirement:age-bracket",
        "service-path-selection",
        "local-subject-age-bracket-v1",
    );
    assert_eq!(status, 403, "an ungranted authored question is forbidden");
    assert_source_not_called(&source_probe);

    let revoked = evidencectl()
        .args(["access", "client", "revoke", "client-a", "--project"])
        .arg(&fixture.root)
        .output()
        .expect("revoke client A");
    assert_success(&revoked, "live revoke client A");
    assert!(String::from_utf8_lossy(&revoked.stdout).contains("Registry Mint reload requested."));
    assert_eq!(sorted_names(&generated_clients), ["client-b.yaml"]);
    assert_eq!(read_pid(&pid_directory.join("evidence.pid")), evidence_pid);
    assert_eq!(read_pid(&pid_directory.join("mint.pid")), mint_pid);
    assert!(process_is_alive(evidence_pid));
    assert!(process_is_alive(mint_pid));
    assert!(
        !client_a_key.exists(),
        "revocation does not require or recreate client A's local key"
    );

    let direct_refusal = retry_until_mint_refuses(|| {
        direct_mint_token(&mint, mint_port, "client-a", &external_client_a_key)
    });
    assert!(direct_refusal.stdout.is_empty());

    let refused = evidencectl()
        .args([
            "request",
            "prepare",
            "adult-status",
            "--purpose",
            "age-check",
            "--subject",
            "person_id=person-123",
            "--client",
            "client-a",
            "--name",
            "client-a-revoked",
            "--project",
        ])
        .arg(&fixture.root)
        .output()
        .expect("prepare as revoked client A");
    assert!(
        !refused.status.success(),
        "revoked client A must be refused"
    );
    assert!(String::from_utf8_lossy(&refused.stderr)
        .contains("unknown or revoked active client client-a"));
    assert!(!fixture
        .root
        .join(".evidence/requests/client-a-revoked")
        .exists());

    let last_revoked = evidencectl()
        .args(["access", "client", "revoke", "client-b", "--project"])
        .arg(&fixture.root)
        .output()
        .expect("revoke last client B");
    assert_success(&last_revoked, "live revoke last client B");
    assert!(
        String::from_utf8_lossy(&last_revoked.stdout).contains("Registry Mint reload requested.")
    );
    assert!(sorted_names(&generated_clients).is_empty());
    wait_mint_without_clients(mint_port);
    assert!(process_is_alive(evidence_pid));
    assert!(process_is_alive(mint_pid));

    assert_success(&fixture.dev_stop(), "stop explicit access generation");
    wait_unavailable(&format!("127.0.0.1:{evidence_port}"));
    wait_unavailable(&format!("127.0.0.1:{mint_port}"));
    assert_success(&fixture.dev_clean(), "clean explicit access generation");
}

#[test]
fn equal_local_ports_fail_before_creating_private_state() {
    let fixture = Project::new();
    let output = evidencectl()
        .args([
            "dev",
            "--detach",
            "--evidence-port",
            "18080",
            "--mint-port",
            "18080",
            "--project",
        ])
        .arg(&fixture.root)
        .output()
        .expect("equal-port start");
    assert!(!output.status.success());
    assert!(!fixture.root.join(".evidence").exists());
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
    let check_only = fixture.tool_that_never_serves();

    let missing_supervisor = fixture.root.join("missing-supervisor");
    let failed = fixture.dev_start_on_free_ports_with_env(
        &check_only,
        &check_only,
        "EVIDENCECTL_TEST_SUPERVISOR_BIN",
        missing_supervisor.as_os_str(),
    );
    assert!(!failed.status.success(), "supervisor spawn fault must fail");
    assert!(!fixture.root.join(".evidence/dev").exists());

    for stage in ["before-setsid", "before-socket", "after-socket"] {
        let failed = fixture.dev_start_on_free_ports_with_env(
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

/// A port another process already holds is the first thing a newcomer hits,
/// and it surfaces as a readiness timeout several seconds later that names
/// neither the port nor a way out. The refusal has to name the port, say what
/// is wrong with it, and give the flag that moves the session elsewhere.
#[test]
fn a_busy_local_port_is_refused_by_name_with_the_flag_that_moves_it() {
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let tool = fixture.tool_that_never_serves();
    let (free_evidence, free_mint) = unused_port_pair();
    let busy = TcpListener::bind("127.0.0.1:0").expect("hold a local port");
    let busy_port = busy.local_addr().expect("busy address").port();

    let output = fixture.dev_start_on_ports(&tool, &tool, busy_port, free_mint);
    assert!(!output.status.success(), "a busy Evidence port must fail");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains(&busy_port.to_string()), "{stderr}");
    assert!(stderr.contains("already in use"), "{stderr}");
    assert!(stderr.contains("--evidence-port"), "{stderr}");
    assert!(
        !fixture.root.join(".evidence/dev").exists(),
        "a refused port must leave no session behind"
    );

    let output = fixture.dev_start_on_ports(&tool, &tool, free_evidence, busy_port);
    assert!(!output.status.success(), "a busy Mint port must fail");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains(&busy_port.to_string()), "{stderr}");
    assert!(stderr.contains("already in use"), "{stderr}");
    assert!(
        stderr.contains("--mint-port"),
        "each port names its own flag: {stderr}"
    );
    assert!(
        busy.local_addr().is_ok(),
        "the unrelated listener must survive"
    );
}

/// The rollback that keeps the next start fresh also removed the only record
/// of why this one failed. The logs move up beside the session instead, and
/// the failure says where they are.
#[test]
fn a_failed_start_keeps_its_startup_logs_and_names_where_they_are() {
    let fixture = Project::new();
    fixture.generate_evidence_keys();
    let tool = fixture.tool_that_never_serves();

    let failed = fixture.dev_start_on_free_ports_with_env(
        &tool,
        &tool,
        "EVIDENCECTL_TEST_SUPERVISOR_FAIL_STAGE",
        OsStr::new("before-socket"),
    );
    assert!(!failed.status.success(), "the injected fault must fail");
    let stderr = String::from_utf8_lossy(&failed.stderr).into_owned();
    let kept = fixture.root.join(".evidence/failed-start");
    assert!(
        stderr.contains(&kept.to_string_lossy().into_owned()),
        "the failure must name where its logs are: {stderr}"
    );
    assert!(
        !stderr.contains("Some("),
        "a recorded program value is not a diagnostic: {stderr}"
    );
    assert!(
        !fixture.root.join(".evidence/dev").exists(),
        "the incomplete session is still rolled back"
    );

    assert_mode(&kept, 0o700);
    let supervisor_log = kept.join("supervisor.log");
    assert_mode(&supervisor_log, 0o600);
    assert!(
        !fs::read_to_string(&supervisor_log)
            .expect("kept supervisor log")
            .trim()
            .is_empty(),
        "the kept log must carry the supervisor's own diagnostic"
    );

    // One record, of the last failed start: an attempt per directory would
    // grow without bound and leave the reader choosing between them.
    let failed = fixture.dev_start_on_free_ports_with_env(
        &tool,
        &tool,
        "EVIDENCECTL_TEST_SUPERVISOR_FAIL_STAGE",
        OsStr::new("before-setsid"),
    );
    assert!(!failed.status.success(), "the second fault must fail");
    assert_eq!(sorted_names(&kept), vec!["supervisor.log".to_owned()]);

    // Keeping the logs must not wedge the project the way an incomplete
    // session would.
    assert!(!fixture.root.join(".evidence/dev").exists());
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
    assert!(!public.dev_clean().status.success());

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
    assert!(!linked.dev_clean().status.success());
    assert!(linked.root.join(".evidence").is_symlink());

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
    assert!(!stale.dev_clean().status.success());
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
        Self::at_relative_path(Path::new("tutorial"))
    }

    fn new_long_path() -> Self {
        Self::at_relative_path(Path::new(
            "first-evidence-assertion-with-a-deliberately-long-project-directory/adult-status-with-a-long-adopter-project-name",
        ))
    }

    fn at_relative_path(relative: &Path) -> Self {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join(relative);
        fs::create_dir_all(&root).expect("project");
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

    /// A stand-in for both service binaries that answers every compile and
    /// check step and refuses only to serve, so a start reaches the
    /// supervisor without ever binding a port.
    fn tool_that_never_serves(&self) -> PathBuf {
        let path = self.root.join("never-serves-tool");
        fs::write(
            &path,
            "#!/bin/sh\ncase \"$*\" in\n  render-discovery-description*) printf '{}\\n';;\n  *serve*) exit 1;;\nesac\n",
        )
        .expect("write the never-serving tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("tool mode");
        path
    }

    fn generate_evidence_keys(&self) {
        let secrets = self.root.join("secrets");
        assert_success(
            &evidencectl()
                .args(["keygen", "signing", "--out-dir"])
                .arg(&secrets)
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

    fn point_source_at(&self, port: u16) {
        fs::write(
            self.root.join("source.openapi.yaml"),
            OPENAPI.replace("http://127.0.0.1:8000", &format!("http://127.0.0.1:{port}")),
        )
        .expect("update source origin");
    }

    fn add_age_bracket_question(&self) {
        fs::write(
            self.root.join("questions/age-bracket.yaml"),
            AGE_BRACKET_QUESTION,
        )
        .expect("age-bracket question");
        fs::write(
            self.root.join("derivations/age-bracket.rhai"),
            AGE_BRACKET_DERIVATION,
        )
        .expect("age-bracket derivation");
    }

    fn dev_start(&self, evidence: &Path, mint: &Path) -> Output {
        self.dev_start_command(evidence, mint)
            .output()
            .expect("dev --detach")
    }

    fn dev_start_on_ports(
        &self,
        evidence: &Path,
        mint: &Path,
        evidence_port: u16,
        mint_port: u16,
    ) -> Output {
        self.dev_start_command(evidence, mint)
            .args(["--evidence-port", &evidence_port.to_string()])
            .args(["--mint-port", &mint_port.to_string()])
            .output()
            .expect("dev --detach on configured ports")
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

    /// The fixed tutorial ports are an exact gate of their own, so a fault
    /// that never reaches a listener asks for ports nobody else owns.
    fn dev_start_on_free_ports_with_env(
        &self,
        evidence: &Path,
        mint: &Path,
        name: &str,
        value: &OsStr,
    ) -> Output {
        let (evidence_port, mint_port) = unused_port_pair();
        self.dev_start_command(evidence, mint)
            .args(["--evidence-port", &evidence_port.to_string()])
            .args(["--mint-port", &mint_port.to_string()])
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

    fn dev_clean(&self) -> Output {
        evidencectl()
            .args(["dev", "clean", "--project"])
            .arg(&self.root)
            .output()
            .expect("dev clean")
    }
}

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn add_local_client(project: &Path, client: &str, policy: &str) -> Output {
    evidencectl()
        .args([
            "access",
            "client",
            "add",
            client,
            "--policy",
            policy,
            "--generate-local-key",
            "--project",
        ])
        .arg(project)
        .output()
        .expect("add local client")
}

fn direct_mint_token(mint: &Path, port: u16, client: &str, key: &Path) -> Output {
    let token_url = format!("http://127.0.0.1:{port}/token");
    Command::new(mint)
        .arg("token")
        .arg("--url")
        .arg(&token_url)
        .arg("--audience")
        .arg(&token_url)
        .arg("--client-id")
        .arg(client)
        .arg("--key")
        .arg(key)
        .output()
        .expect("invoke Mint token client")
}

fn post_evidence(
    port: u16,
    token: &str,
    requirement: &str,
    purpose: &str,
    selector_profile: &str,
) -> u16 {
    let body = json!({
        "requestNonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "requirement": requirement,
        "purpose": purpose,
        "subjects": [{
            "role": "person",
            "selector": {
                "profile": selector_profile,
                "values": {"person_id": "person-123"},
            },
        }],
    });
    let body = body.to_string();
    match ureq::post(&format!("http://127.0.0.1:{port}/v1/evidence"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/jose+json")
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(status, _)) => status,
        Err(error) => panic!("Evidence request failed before an HTTP response: {error}"),
    }
}

fn assert_source_not_called(source_probe: &TcpListener) {
    match source_probe.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("Evidence contacted the source for an ungranted question"),
        Err(error) => panic!("source call probe failed: {error}"),
    }
}

fn retry_until_success(label: &str, mut operation: impl FnMut() -> Output) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = operation();
        if output.status.success() {
            return output;
        }
        if Instant::now() >= deadline {
            panic!(
                "{label} did not succeed after Mint reload\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn retry_until_mint_refuses(mut operation: impl FnMut() -> Output) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = operation();
        let refused = !output.status.success()
            && output.stdout.is_empty()
            && String::from_utf8_lossy(&output.stderr).contains("invalid_client");
        if refused {
            return output;
        }
        if Instant::now() >= deadline {
            panic!(
                "Mint did not refuse revoked client A after reload\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .trim()
        .parse()
        .expect("numeric PID")
}

fn process_is_alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
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
    jwks_ready_at(8081)
}

fn jwks_ready_at(port: u16) -> bool {
    ureq::get(&format!("http://127.0.0.1:{port}/.well-known/jwks.json"))
        .call()
        .ok()
        .and_then(|response| serde_json::from_reader::<_, Value>(response.into_reader()).ok())
        .and_then(|value| value["keys"].as_array().cloned())
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                key["kty"] == "EC"
                    && key["crv"] == "P-256"
                    && key["alg"] == "ES256"
                    && key["kid"].as_str().is_some_and(|kid| kid.len() == 43)
            })
        })
}

fn unused_port_pair() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").expect("reserve first port");
    let second = TcpListener::bind("127.0.0.1:0").expect("reserve second port");
    let ports = (
        first.local_addr().expect("first address").port(),
        second.local_addr().expect("second address").port(),
    );
    drop((first, second));
    ports
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

fn wait_mint_without_clients(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if matches!(
            ureq::get(&format!("http://127.0.0.1:{port}/ready")).call(),
            Err(ureq::Error::Status(503, _))
        ) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("Mint did not publish its empty-registry readiness state");
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
